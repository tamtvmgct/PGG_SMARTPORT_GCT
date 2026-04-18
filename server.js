import express from "express";
import cors from "cors";
import http from "http";
import { WebSocketServer } from "ws";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

// ── APP SETUP ──────────────────────────────────────────────
const app = express();
app.use(express.static(__dirname));
// Dòng này bảo Server: "Nếu ai vào trang chủ, hãy đưa họ đến file index.html"
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});
const ALLOWED_ORIGINS = String(process.env.PGG_ALLOWED_ORIGINS || "")
  .split(",").map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.length === 0) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error("CORS blocked"), false);
  },
  credentials: true
}));
app.use(express.json({ limit: "2mb" }));
app.use(helmet({ contentSecurityPolicy: false }));

// Serve frontend files from parent directory
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, "..")));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
const eventLimiter = rateLimit({ windowMs: 10 * 1000, max: 200, standardHeaders: true, legacyHeaders: false });

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// ── IN-MEMORY STATE ────────────────────────────────────────
const clients            = new Map();   // ws → {app, deviceId, plate, role, userId}
const jobsByPlate        = new Map();   // plate → job payload
const stateByPlate       = new Map();   // plate → {status, ...}
const complianceByPlate  = new Map();   // plate → compliance snapshot
const processedEvents    = new Map();   // eventId → ts
const containerRegistry  = new Map();   // containerId → container object
const yardSlots          = new Map();   // "A-26-01-04" → { containerId, placedAt, ... }
const bypassRequests     = new Map();   // requestId → request
const auditLogs          = [];          // in-memory audit log (max 5000)
const sessions           = new Map();   // token → session
const failedLoginByKey   = new Map();   // key → {count, firstAttemptAt, lockedUntil}

// ── PERSISTENCE ────────────────────────────────────────────
const DATA_DIR   = path.join(__dirname, "data");
const STORE_FILE = path.join(DATA_DIR, "pgg-store.json");
let lastPersistAt = null;

// ── CONFIG ─────────────────────────────────────────────────
const LOGIN_WINDOW_MS  = 15 * 60 * 1000;
const LOGIN_LOCK_MS    = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 5;

// ── EVENT FLOW FSM ─────────────────────────────────────────
const EVENT_FLOW = [
  "JOB_CREATED",
  "PIMS_DONE",
  "GXT_CONFIRMED",
  "GXT_ARRIVED",
  "GNT_CONFIRMED",
  "GNT_DONE",
  "GXT_FINISH",
  "GXT_CHECKOUT"
];

// ── YARD CONFIGURATION (Configurable per port) ─────────────
const YARD_CONFIG = {
  blocks: {
    A: { name: "Block A — Hàng Xuất (Export)", maxBay: 40, maxRow: 6, maxTier: 5, allowedTypes: ["EXPORT"] },
    B: { name: "Block B — Hàng Nhập (Import)", maxBay: 30, maxRow: 6, maxTier: 5, allowedTypes: ["IMPORT"] },
    C: { name: "Block C — Container Rỗng", maxBay: 20, maxRow: 6, maxTier: 6, allowedTypes: ["EMPTY_RETURN", "EMPTY_PICKUP"] },
    D: { name: "Block D — Cont Hư hỏng / Sửa chữa", maxBay: 10, maxRow: 4, maxTier: 3, allowedTypes: ["DAMAGED"] },
  }
};

// ── DEFAULT USERS ──────────────────────────────────────────
const DEFAULT_USERS = [
  { userId: "pims.op",       username: "pims",       password: "pims123",  role: "PIMS",       name: "PIMS Operator" },
  { userId: "supervisor.1",  username: "supervisor", password: "super123", role: "SUPERVISOR",  name: "Duty Supervisor" },
  { userId: "admin.1",       username: "admin",      password: "admin123", role: "ADMIN",       name: "Port Admin" },
  { userId: "gxt.1",         username: "gxt",        password: "gxt123",   role: "GXT",         name: "GXT User" },
  { userId: "gnt.1",         username: "gnt",        password: "gnt123",   role: "GNT",         name: "GNT Operator" },
  { userId: "dispatch.1",    username: "dispatch",   password: "disp123",  role: "DISPATCHER",  name: "Yard Dispatcher" },
];
const USERS = [];

// ── UTIL ───────────────────────────────────────────────────
function safeJsonParse(s) { try { return JSON.parse(s); } catch { return null; } }

function getClientIp(req) {
  const xff = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return xff || req.socket?.remoteAddress || "unknown";
}

function randomId(prefix = "id") {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

function now() { return Date.now(); }

function padNum(n, len = 2) { return String(n).padStart(len, "0"); }

// ── PASSWORD ───────────────────────────────────────────────
function hashPassword(plain, saltHex = null) {
  const salt = saltHex ? Buffer.from(saltHex, "hex") : crypto.randomBytes(16);
  const digest = crypto.pbkdf2Sync(String(plain), salt, 100000, 32, "sha256");
  return { passwordHash: digest.toString("hex"), passwordSalt: salt.toString("hex"), passwordAlgo: "pbkdf2_sha256_100000" };
}

function verifyPassword(plain, userRecord) {
  if (!userRecord?.passwordHash || !userRecord?.passwordSalt) return false;
  const next = hashPassword(plain, userRecord.passwordSalt);
  const a = Buffer.from(next.passwordHash, "hex");
  const b = Buffer.from(userRecord.passwordHash, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ── USERS ──────────────────────────────────────────────────
function initUsers() {
  USERS.length = 0;
  for (const u of DEFAULT_USERS) {
    const hp = hashPassword(u.password);
    USERS.push({ userId: u.userId, username: u.username, role: u.role, name: u.name, ...hp });
  }
}

function findUser(username) { return USERS.find(u => u.username === username); }

function loginKey(username, ip) { return `${username}::${ip}`; }

function isLoginLocked(key) {
  const row = failedLoginByKey.get(key);
  if (!row) return { locked: false };
  if (row.lockedUntil && row.lockedUntil > now()) return { locked: true, retryAfterMs: row.lockedUntil - now() };
  if (row.lockedUntil && row.lockedUntil <= now()) { failedLoginByKey.delete(key); return { locked: false }; }
  return { locked: false };
}

function recordLoginFailure(key) {
  const n = now();
  const prev = failedLoginByKey.get(key) || { count: 0, firstAttemptAt: n, lockedUntil: null };
  if (n - prev.firstAttemptAt > LOGIN_WINDOW_MS) { failedLoginByKey.set(key, { count: 1, firstAttemptAt: n, lockedUntil: null }); return; }
  const next = { ...prev, count: prev.count + 1 };
  if (next.count >= LOGIN_MAX_ATTEMPTS) next.lockedUntil = n + LOGIN_LOCK_MS;
  failedLoginByKey.set(key, next);
}

function clearLoginFailures(key) { failedLoginByKey.delete(key); }

// ── SESSION / AUTH MIDDLEWARE ───────────────────────────────
function parseToken(req) {
  const h = String(req.headers.authorization || "");
  if (!h.startsWith("Bearer ")) return null;
  return h.slice(7).trim();
}

function getSessionFromReq(req) {
  const token = parseToken(req);
  if (!token) return null;
  const sess = sessions.get(token);
  if (!sess) return null;
  if (sess.expiresAt < now()) { sessions.delete(token); return null; }
  return sess;
}

function authRequired(req, res, next) {
  const sess = getSessionFromReq(req);
  if (!sess) return res.status(401).json({ ok: false, error: "Unauthorized" });
  req.session = sess;
  return next();
}

function roleRequired(roles) {
  return (req, res, next) => {
    if (!req.session) return res.status(401).json({ ok: false, error: "Unauthorized" });
    if (!roles.includes(req.session.role)) return res.status(403).json({ ok: false, error: "Forbidden" });
    return next();
  };
}

// ── AUDIT ──────────────────────────────────────────────────
function pushAudit(kind, payload = {}) {
  auditLogs.push({ id: randomId("audit"), kind, at: now(), ...payload });
  if (auditLogs.length > 5000) auditLogs.shift();
  schedulePersist();
}

// ── BROADCAST ──────────────────────────────────────────────
function broadcast(event, { plate } = {}) {
  const msg = JSON.stringify(event);
  for (const [ws, meta] of clients.entries()) {
    if (ws.readyState !== ws.OPEN) continue;
    if (plate && meta?.plate && meta.plate !== plate) continue;
    ws.send(msg);
  }
}

function broadcastYardUpdate() {
  const summary = getYardSummary();
  const msg = JSON.stringify({ type: "YARD_UPDATE", yard: summary, serverTime: now() });
  for (const [ws] of clients.entries()) {
    if (ws.readyState !== ws.OPEN) continue;
    ws.send(msg);
  }
}

// ── ISO 6346 VALIDATION ───────────────────────────────────
function isValidISO6346(id) {
  if (!id || typeof id !== "string") return false;
  const s = id.replace(/[\s\-]/g, "").toUpperCase();
  if (s.length !== 11) return false;
  if (!/^[A-Z]{4}\d{7}$/.test(s)) return false;
  const vals = "0123456789A BCDEFGHIJK LMNOPQRSTU VWXYZ".replace(/ /g, "");
  let sum = 0;
  for (let i = 0; i < 10; i++) {
    const c = s[i];
    let v = vals.indexOf(c);
    if (v < 0) return false;
    if (v >= 11) v++; // skip multiples of 11
    sum += v * Math.pow(2, i);
  }
  const check = sum % 11 % 10;
  return check === parseInt(s[10], 10);
}

// ═══════════════════════════════════════════════════════════
//  YARD MANAGEMENT — Block/Bay/Row/Tier
// ═══════════════════════════════════════════════════════════

function slotKey(block, bay, row, tier) {
  return `${block}-${padNum(bay)}-${padNum(row)}-${padNum(tier)}`;
}

function parseSlotKey(key) {
  const parts = key.split("-");
  if (parts.length !== 4) return null;
  return { block: parts[0], bay: parseInt(parts[1]), row: parseInt(parts[2]), tier: parseInt(parts[3]) };
}

function getBlockConfig(blockId) {
  return YARD_CONFIG.blocks[blockId.toUpperCase()] || null;
}

function isBayFull(blockId, bayNum) {
  const cfg = getBlockConfig(blockId);
  if (!cfg) return true;
  for (let r = 1; r <= cfg.maxRow; r++) {
    for (let t = 1; t <= cfg.maxTier; t++) {
      const key = slotKey(blockId, bayNum, r, t);
      if (!yardSlots.has(key)) return false;
    }
  }
  return true;
}

function getBayOccupancy(blockId, bayNum) {
  const cfg = getBlockConfig(blockId);
  if (!cfg) return { total: 0, used: 0, pct: 100 };
  const total = cfg.maxRow * cfg.maxTier;
  let used = 0;
  for (let r = 1; r <= cfg.maxRow; r++) {
    for (let t = 1; t <= cfg.maxTier; t++) {
      if (yardSlots.has(slotKey(blockId, bayNum, r, t))) used++;
    }
  }
  return { total, used, pct: Math.round((used / total) * 100) };
}

function getBlockOccupancy(blockId) {
  const cfg = getBlockConfig(blockId);
  if (!cfg) return { total: 0, used: 0, pct: 100 };
  const total = cfg.maxBay * cfg.maxRow * cfg.maxTier;
  let used = 0;
  for (let b = 1; b <= cfg.maxBay; b++) {
    for (let r = 1; r <= cfg.maxRow; r++) {
      for (let t = 1; t <= cfg.maxTier; t++) {
        if (yardSlots.has(slotKey(blockId, b, r, t))) used++;
      }
    }
  }
  return { total, used, pct: Math.round((used / total) * 100) };
}

function getYardSummary() {
  const blocks = {};
  for (const [blockId, cfg] of Object.entries(YARD_CONFIG.blocks)) {
    const occ = getBlockOccupancy(blockId);
    // Per-bay overview
    const bays = [];
    for (let b = 1; b <= cfg.maxBay; b++) {
      const bo = getBayOccupancy(blockId, b);
      bays.push({ bay: b, ...bo });
    }
    blocks[blockId] = { name: cfg.name, ...occ, allowedTypes: cfg.allowedTypes, maxBay: cfg.maxBay, maxRow: cfg.maxRow, maxTier: cfg.maxTier, bays };
  }
  return { blocks, totalContainers: yardSlots.size, updatedAt: now() };
}

// Find best available slot following stacking rules
function autoAssignSlot(blockId, container) {
  const cfg = getBlockConfig(blockId);
  if (!cfg) return null;

  const currentWeight = container.grossWeight || 0;

  // Strategy: find bay with containers from same vessel/carrier, then nearest slot
  let bestSlots = []; // collect possible slots across all bays
  
  for (let b = 1; b <= cfg.maxBay; b++) {
    if (isBayFull(blockId, b)) continue;

    let score = 10; // base score for empty bay

    // Prefer bays that already have containers from the same vessel/voyage
    for (let r = 1; r <= cfg.maxRow; r++) {
      for (let t = 1; t <= cfg.maxTier; t++) {
        const existing = yardSlots.get(slotKey(blockId, b, r, t));
        if (!existing) continue;
        const existCont = containerRegistry.get(existing.containerId);
        if (!existCont) continue;
        
        if (container.vesselName && existCont.vesselName === container.vesselName) {
          score += 20;
          if (container.voyageNo && existCont.voyageNo === container.voyageNo) {
            score += 20; // Plus 20 for same voyage
          }
        }
        if (container.carrier && existCont.carrier === container.carrier) {
          score += 10;
        }
      }
    }

    // Prefer lower bays (closer to gate for pickup priority)
    score += (cfg.maxBay - b);

    // Find the first valid slot in this bay considering weight rules
    let firstValidSlot = null;
    for (let r = 1; r <= cfg.maxRow; r++) {
      for (let t = 1; t <= cfg.maxTier; t++) {
        const key = slotKey(blockId, b, r, t);
        if (yardSlots.has(key)) continue; // Occupied, try next tier up

        if (t > 1) {
          const belowKey = slotKey(blockId, b, r, t - 1);
          if (!yardSlots.has(belowKey)) {
             break; // Cannot stack in thin air. Move to next row.
          }
          const belowSlot = yardSlots.get(belowKey);
          const belowCont = containerRegistry.get(belowSlot.containerId);
          if (belowCont) {
             const belowWeight = belowCont.grossWeight || 0;
             if (currentWeight > belowWeight) {
                // HEAVY ON LIGHT RULE: Invalid stack!
                break; // Move to next row
             }
          }
        }
        
        firstValidSlot = { block: blockId, bay: b, row: r, tier: t, key };
        break; // Found lowest free valid tier in this row
      }
      if (firstValidSlot) break; // Found a valid slot in this bay, no need to check other rows for the bay
    }

    if (firstValidSlot) {
      bestSlots.push({ slot: firstValidSlot, score });
    }
  }

  if (bestSlots.length === 0) return null;

  // Sort by score descending to get the best slot
  bestSlots.sort((a, b) => b.score - a.score);
  return bestSlots[0].slot;
}

function determineBlock(operationType) {
  for (const [blockId, cfg] of Object.entries(YARD_CONFIG.blocks)) {
    if (cfg.allowedTypes.includes(operationType)) return blockId;
  }
  return "A"; // fallback
}

function placeContainer(slotInfo, containerId) {
  yardSlots.set(slotInfo.key, { containerId, placedAt: now() });
  schedulePersist();
}

function removeContainer(slotKey) {
  yardSlots.delete(slotKey);
  schedulePersist();
}

// ═══════════════════════════════════════════════════════════
//  CONTAINER REGISTRY
// ═══════════════════════════════════════════════════════════

function registerContainer(data) {
  const id = String(data.containerId || "").replace(/[\s\-]/g, "").toUpperCase();
  if (!id) return { ok: false, error: "Missing containerId" };

  const container = {
    containerId: id,
    isoValid: isValidISO6346(id),
    size: String(data.size || "20GP").toUpperCase(),
    grossWeight: parseFloat(data.grossWeight) || 0,
    maxGrossWeight: parseFloat(data.maxGrossWeight) || 30.48,
    vgmVerified: !!data.vgmVerified,
    fullEmpty: String(data.fullEmpty || "F").toUpperCase()[0] === "F" ? "FULL" : "EMPTY",
    condition: String(data.condition || "A").toUpperCase(),

    vesselName: String(data.vesselName || "").toUpperCase(),
    voyageNo: String(data.voyageNo || ""),
    carrier: String(data.carrier || ""),
    etb: data.etb || null,
    etd: data.etd || null,
    cot: data.cot || null,

    bookingNo: String(data.bookingNo || ""),
    blNo: String(data.blNo || ""),
    customsDecNo: String(data.customsDecNo || ""),
    deliveryOrderNo: String(data.deliveryOrderNo || ""),

    operationType: String(data.operationType || "EXPORT").toUpperCase(),
    consignee: String(data.consignee || ""),
    portOfDischarge: String(data.portOfDischarge || ""),
    portOfDestination: String(data.portOfDestination || ""),

    truckPlate: String(data.truckPlate || "").toUpperCase(),
    romoocNo: String(data.romoocNo || ""),
    driverName: String(data.driverName || ""),

    yardPosition: null,
    status: "REGISTERED",
    registeredAt: now(),
    updatedAt: now()
  };

  containerRegistry.set(id, container);
  schedulePersist();
  return { ok: true, container };
}

// ═══════════════════════════════════════════════════════════
//  COMPLIANCE
// ═══════════════════════════════════════════════════════════

function defaultCompliance(plate) {
  return {
    plate, points: {
      bookingDO: "PENDING", customs: "PENDING", vgm: "PENDING",
      portFee: "PENDING", seal: "PENDING", gateBarcode: "PENDING"
    }, score: 0, approved: false, policy: "SMART_AUTO", updatedAt: now()
  };
}

function scoreCompliance(points) {
  const arr = Object.values(points);
  const pass = arr.filter(x => x === "PASS").length;
  return Math.round((pass * 100) / (arr.length || 1));
}

function mapBoolToState(v) {
  if (v === true) return "PASS";
  if (v === false) return "FAIL";
  return "PENDING";
}

// ═══════════════════════════════════════════════════════════
//  EVENT FLOW ENGINE
// ═══════════════════════════════════════════════════════════

function eventIndex(type) { return EVENT_FLOW.indexOf(type); }

function isTransitionAllowed(currentStatus, incomingType) {
  if (incomingType === "JOB_CREATED") return true;
  if (!currentStatus) return false;
  if (currentStatus === incomingType) return true;
  const from = eventIndex(currentStatus);
  const to = eventIndex(incomingType);
  return from >= 0 && to === from + 1;
}

function upsertPlateState(plate, patch) {
  const prev = stateByPlate.get(plate) || {};
  const next = { ...prev, ...patch, updatedAt: now() };
  stateByPlate.set(plate, next);
  schedulePersist();
  return next;
}

function actorFromSession(session, app) {
  if (session) return { userId: session.userId, role: session.role, app: app || "API" };
  return { userId: `${app || "SYSTEM"}_anon`, role: "UNKNOWN", app: app || "UNKNOWN" };
}

function processEvent(rawEvent, actor) {
  const plate = String(rawEvent.plate || "").toUpperCase();
  const type = String(rawEvent.type || "");
  const eventId = String(rawEvent.eventId || randomId("evt"));
  if (!plate || !type) return { ok: false, code: 400, error: "Missing plate/type" };

  if (processedEvents.has(eventId)) {
    return { ok: true, duplicate: true, eventId };
  }

  const current = stateByPlate.get(plate)?.status || null;
  if (!isTransitionAllowed(current, type)) {
    pushAudit("EVENT_REJECTED", { plate, type, reason: "INVALID_TRANSITION", current, actor });
    return { ok: false, code: 409, error: `Invalid transition ${current || "NONE"} → ${type}` };
  }

  if (type === "PIMS_DONE") {
    const comp = complianceByPlate.get(plate) || defaultCompliance(plate);
    if (!comp.approved) {
      pushAudit("EVENT_REJECTED", { plate, type, reason: "COMPLIANCE_NOT_MET", actor });
      return { ok: false, code: 423, error: "Compliance not at 100% or approved bypass" };
    }
  }

  const enriched = { ...rawEvent, plate, type, eventId, serverTime: now(), actor };

  if (type === "JOB_CREATED" && rawEvent.job) {
    jobsByPlate.set(plate, { ...rawEvent.job, plate });
    if (!complianceByPlate.has(plate)) complianceByPlate.set(plate, defaultCompliance(plate));
    schedulePersist();
  }

  // Auto assign yard position when GNT_CONFIRMED
  if (type === "GNT_CONFIRMED") {
    const job = jobsByPlate.get(plate);
    if (job?.containerId) {
      const cont = containerRegistry.get(job.containerId);
      if (cont && !cont.yardPosition) {
        const blockId = determineBlock(cont.operationType);
        const slot = autoAssignSlot(blockId, cont);
        if (slot) {
          placeContainer(slot, cont.containerId);
          cont.yardPosition = { block: slot.block, bay: slot.bay, row: slot.row, tier: slot.tier };
          cont.updatedAt = now();
          containerRegistry.set(cont.containerId, cont);
          enriched.yardPosition = cont.yardPosition;
          enriched.yardSlotKey = slot.key;
          broadcastYardUpdate();
          pushAudit("YARD_POSITION_ASSIGNED", { plate, containerId: cont.containerId, position: slot.key, actor });
        }
      }
    }
  }

  upsertPlateState(plate, { status: type, lastEventId: eventId });
  processedEvents.set(eventId, now());
  broadcast({ type: "EVENT", event: enriched }, { plate });
  pushAudit("EVENT_ACCEPTED", { plate, type, eventId, actor });
  return { ok: true, enriched };
}

// ═══════════════════════════════════════════════════════════
//  PERSISTENCE (File-based)
// ═══════════════════════════════════════════════════════════

function serializeMap(m) { return [...m.entries()]; }
function hydrateMap(m, rows) {
  m.clear();
  if (!Array.isArray(rows)) return;
  for (const row of rows) { if (Array.isArray(row) && row.length === 2) m.set(row[0], row[1]); }
}

function ensureDataDir() { if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true }); }

function loadStore() {
  try {
    ensureDataDir();
    if (!fs.existsSync(STORE_FILE)) return;
    const data = safeJsonParse(fs.readFileSync(STORE_FILE, "utf8"));
    if (!data || typeof data !== "object") return;
    if (Array.isArray(data.users) && data.users.length) {
      USERS.length = 0;
      for (const u of data.users) {
        if (!u?.username || !u?.userId || !u?.role || !u?.passwordHash) continue;
        USERS.push({ userId: u.userId, username: u.username, role: u.role, name: u.name || u.username, passwordHash: u.passwordHash, passwordSalt: u.passwordSalt, passwordAlgo: u.passwordAlgo || "pbkdf2_sha256_100000" });
      }
    }
    hydrateMap(jobsByPlate, data.jobsByPlate);
    hydrateMap(stateByPlate, data.stateByPlate);
    hydrateMap(complianceByPlate, data.complianceByPlate);
    hydrateMap(processedEvents, data.processedEvents);
    hydrateMap(containerRegistry, data.containerRegistry);
    hydrateMap(yardSlots, data.yardSlots);
    hydrateMap(bypassRequests, data.bypassRequests);
    if (Array.isArray(data.auditLogs)) { auditLogs.length = 0; auditLogs.push(...data.auditLogs.slice(-5000)); }
    lastPersistAt = data.persistedAt || null;
  } catch { /* continue with clean state */ }
}

function persistStore() {
  try {
    ensureDataDir();
    const snapshot = {
      version: 2, persistedAt: now(),
      jobsByPlate: serializeMap(jobsByPlate),
      stateByPlate: serializeMap(stateByPlate),
      complianceByPlate: serializeMap(complianceByPlate),
      processedEvents: serializeMap(processedEvents),
      containerRegistry: serializeMap(containerRegistry),
      yardSlots: serializeMap(yardSlots),
      bypassRequests: serializeMap(bypassRequests),
      auditLogs: auditLogs.slice(-5000),
      users: USERS.map(u => ({ userId: u.userId, username: u.username, role: u.role, name: u.name, passwordHash: u.passwordHash, passwordSalt: u.passwordSalt, passwordAlgo: u.passwordAlgo }))
    };
    fs.writeFileSync(STORE_FILE, JSON.stringify(snapshot, null, 2), "utf8");
    lastPersistAt = snapshot.persistedAt;
  } catch { /* swallow */ }
}

let persistTimer = null;
function schedulePersist() {
  if (persistTimer) return;
  persistTimer = setTimeout(() => { persistTimer = null; persistStore(); }, 500);
}

// ═══════════════════════════════════════════════════════════
//  CLEANUP TIMER
// ═══════════════════════════════════════════════════════════
setInterval(() => {
  const n = now();
  for (const [id, ts] of processedEvents.entries()) { if (n - ts > 24 * 3600 * 1000) processedEvents.delete(id); }
  for (const [token, sess] of sessions.entries()) { if (sess.expiresAt < n) sessions.delete(token); }
  for (const [key, row] of failedLoginByKey.entries()) {
    if (n - (row.firstAttemptAt || n) > LOGIN_WINDOW_MS * 2) failedLoginByKey.delete(key);
    else if (row.lockedUntil && row.lockedUntil <= n) failedLoginByKey.delete(key);
  }
  schedulePersist();
}, 60 * 1000);

// ═══════════════════════════════════════════════════════════
//  HTTP ROUTES
// ═══════════════════════════════════════════════════════════

// ── Health ──
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, version: "PGG V6.0", now: now(), clients: clients.size, plates: stateByPlate.size, containers: containerRegistry.size, yardSlots: yardSlots.size, sessions: sessions.size });
});

// ── Auth ──
app.post("/api/auth/login", authLimiter, (req, res) => {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  const ip = getClientIp(req);
  const key = loginKey(username || "unknown", ip);
  const lock = isLoginLocked(key);
  if (lock.locked) return res.status(429).json({ ok: false, error: "Tài khoản tạm khóa", retryAfterMs: lock.retryAfterMs });

  const user = findUser(username);
  if (!user || !verifyPassword(password, user)) {
    recordLoginFailure(key);
    pushAudit("LOGIN_FAILED", { username, ip });
    return res.status(401).json({ ok: false, error: "Sai tài khoản hoặc mật khẩu" });
  }

  clearLoginFailures(key);
  const token = randomId("tok");
  const session = { token, userId: user.userId, role: user.role, name: user.name, username: user.username, issuedAt: now(), expiresAt: now() + 8 * 3600 * 1000 };
  sessions.set(token, session);
  pushAudit("LOGIN_SUCCESS", { userId: user.userId, role: user.role, ip });
  return res.json({ ok: true, token, session });
});

app.get("/api/auth/me", authRequired, (req, res) => res.json({ ok: true, session: req.session }));

app.post("/api/auth/logout", authRequired, (req, res) => {
  sessions.delete(req.session.token);
  pushAudit("LOGOUT", { userId: req.session.userId });
  return res.json({ ok: true });
});

// ── State ──
app.get("/api/state/:plate", (req, res) => {
  const plate = String(req.params.plate).toUpperCase();
  res.json({ plate, job: jobsByPlate.get(plate) || null, state: stateByPlate.get(plate) || null, compliance: complianceByPlate.get(plate) || null });
});

// ── Containers ──
app.post("/api/containers", authRequired, roleRequired(["GXT", "PIMS", "ADMIN"]), (req, res) => {
  const result = registerContainer(req.body);
  if (!result.ok) return res.status(400).json(result);
  pushAudit("CONTAINER_REGISTERED", { containerId: result.container.containerId, by: req.session.userId });
  broadcast({ type: "CONTAINER_REGISTERED", container: result.container, serverTime: now() });
  return res.json(result);
});

app.get("/api/containers/:id", (req, res) => {
  const id = String(req.params.id).replace(/[\s\-]/g, "").toUpperCase();
  const cont = containerRegistry.get(id);
  if (!cont) return res.status(404).json({ ok: false, error: "Container not found" });
  return res.json({ ok: true, container: cont });
});

app.get("/api/containers", authRequired, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const all = [...containerRegistry.values()].sort((a, b) => (b.registeredAt || 0) - (a.registeredAt || 0)).slice(0, limit);
  return res.json({ ok: true, containers: all, total: containerRegistry.size });
});

// ── Yard ──
app.get("/api/yard/status", (req, res) => {
  return res.json({ ok: true, yard: getYardSummary() });
});

app.get("/api/yard/block/:blockId", (req, res) => {
  const blockId = String(req.params.blockId).toUpperCase();
  const cfg = getBlockConfig(blockId);
  if (!cfg) return res.status(404).json({ ok: false, error: "Block not found" });

  const bays = [];
  for (let b = 1; b <= cfg.maxBay; b++) {
    const rows = [];
    for (let r = 1; r <= cfg.maxRow; r++) {
      const tiers = [];
      for (let t = 1; t <= cfg.maxTier; t++) {
        const key = slotKey(blockId, b, r, t);
        const slot = yardSlots.get(key);
        tiers.push({ tier: t, occupied: !!slot, containerId: slot?.containerId || null });
      }
      rows.push({ row: r, tiers });
    }
    bays.push({ bay: b, rows, ...getBayOccupancy(blockId, b) });
  }

  return res.json({ ok: true, block: { id: blockId, ...cfg, bays } });
});

app.post("/api/yard/assign", authRequired, roleRequired(["PIMS", "DISPATCHER", "ADMIN"]), (req, res) => {
  const containerId = String(req.body?.containerId || "").replace(/[\s\-]/g, "").toUpperCase();
  const cont = containerRegistry.get(containerId);
  if (!cont) return res.status(404).json({ ok: false, error: "Container not found in registry" });

  // Manual or auto assign
  if (req.body?.block && req.body?.bay && req.body?.row && req.body?.tier) {
    const key = slotKey(req.body.block, req.body.bay, req.body.row, req.body.tier);
    if (yardSlots.has(key)) return res.status(409).json({ ok: false, error: "Slot already occupied" });
    const slot = { block: req.body.block, bay: req.body.bay, row: req.body.row, tier: req.body.tier, key };
    placeContainer(slot, containerId);
    cont.yardPosition = { block: slot.block, bay: slot.bay, row: slot.row, tier: slot.tier };
    cont.updatedAt = now();
    containerRegistry.set(containerId, cont);
    broadcastYardUpdate();
    pushAudit("YARD_MANUAL_ASSIGN", { containerId, position: key, by: req.session.userId });
    return res.json({ ok: true, position: slot });
  }

  // Auto
  const blockId = determineBlock(cont.operationType);
  const slot = autoAssignSlot(blockId, cont);
  if (!slot) return res.status(503).json({ ok: false, error: `No available slot in Block ${blockId}` });
  placeContainer(slot, containerId);
  cont.yardPosition = { block: slot.block, bay: slot.bay, row: slot.row, tier: slot.tier };
  cont.updatedAt = now();
  containerRegistry.set(containerId, cont);
  broadcastYardUpdate();
  pushAudit("YARD_AUTO_ASSIGN", { containerId, position: slot.key, by: req.session.userId });
  return res.json({ ok: true, position: slot });
});

app.post("/api/yard/report-full", authRequired, roleRequired(["GNT", "DISPATCHER", "ADMIN"]), (req, res) => {
  const blockId = String(req.body?.block || "").toUpperCase();
  const bayNum = parseInt(req.body?.bay);
  if (!blockId || !bayNum) return res.status(400).json({ ok: false, error: "Missing block/bay" });

  const occ = getBayOccupancy(blockId, bayNum);
  pushAudit("YARD_BAY_FULL_REPORT", { block: blockId, bay: bayNum, occupancy: occ, by: req.session.userId });
  broadcast({ type: "YARD_BAY_FULL", block: blockId, bay: bayNum, occupancy: occ, reportedBy: req.session.userId, serverTime: now() });
  return res.json({ ok: true, block: blockId, bay: bayNum, occupancy: occ });
});

app.post("/api/yard/relocate", authRequired, roleRequired(["DISPATCHER", "PIMS", "ADMIN"]), (req, res) => {
  const containerId = String(req.body?.containerId || "").replace(/[\s\-]/g, "").toUpperCase();
  const cont = containerRegistry.get(containerId);
  if (!cont) return res.status(404).json({ ok: false, error: "Container not found" });

  // Remove from old slot
  const oldPos = cont.yardPosition;
  if (oldPos) {
    const oldKey = slotKey(oldPos.block, oldPos.bay, oldPos.row, oldPos.tier);
    removeContainer(oldKey);
  }

  // New position: manual or auto
  let slot;
  if (req.body?.newBlock && req.body?.newBay && req.body?.newRow && req.body?.newTier) {
    const key = slotKey(req.body.newBlock, req.body.newBay, req.body.newRow, req.body.newTier);
    if (yardSlots.has(key)) return res.status(409).json({ ok: false, error: "New slot already occupied" });
    slot = { block: req.body.newBlock, bay: req.body.newBay, row: req.body.newRow, tier: req.body.newTier, key };
  } else {
    const blockId = req.body?.newBlock || determineBlock(cont.operationType);
    slot = autoAssignSlot(blockId, cont);
    if (!slot) return res.status(503).json({ ok: false, error: "No available slot" });
  }

  placeContainer(slot, containerId);
  cont.yardPosition = { block: slot.block, bay: slot.bay, row: slot.row, tier: slot.tier };
  cont.updatedAt = now();
  containerRegistry.set(containerId, cont);
  broadcastYardUpdate();

  const relocateOrder = { type: "YARD_RELOCATE_ORDER", containerId, oldPosition: oldPos, newPosition: cont.yardPosition, newSlotKey: slot.key, orderedBy: req.session.userId, serverTime: now() };
  broadcast(relocateOrder);
  pushAudit("YARD_RELOCATED", { containerId, from: oldPos, to: cont.yardPosition, by: req.session.userId });
  return res.json({ ok: true, oldPosition: oldPos, newPosition: cont.yardPosition });
});

// ── Compliance ──
app.post("/api/compliance/evaluate", authRequired, roleRequired(["PIMS", "SUPERVISOR", "ADMIN"]), (req, res) => {
  const plate = String(req.body?.plate || "").toUpperCase();
  if (!plate) return res.status(400).json({ ok: false, error: "Missing plate" });
  const points = {
    bookingDO: mapBoolToState(req.body?.bookingMatched), customs: mapBoolToState(req.body?.customsCleared),
    vgm: mapBoolToState(req.body?.vgmValid), portFee: mapBoolToState(req.body?.portFeePaid),
    seal: mapBoolToState(req.body?.sealMatched), gateBarcode: mapBoolToState(req.body?.gateBarcodeIssued)
  };
  const score = scoreCompliance(points);
  const prev = complianceByPlate.get(plate) || defaultCompliance(plate);
  const next = { ...prev, plate, points, score, approved: score === 100 || prev.policy === "BYPASS_APPROVED", updatedAt: now(), updatedBy: req.session.userId };
  complianceByPlate.set(plate, next);
  pushAudit("COMPLIANCE_EVALUATED", { plate, score, by: req.session.userId });
  schedulePersist();
  return res.json({ ok: true, compliance: next });
});

app.get("/api/compliance/:plate", authRequired, (req, res) => {
  const plate = String(req.params.plate).toUpperCase();
  return res.json({ ok: true, compliance: complianceByPlate.get(plate) || defaultCompliance(plate) });
});

// ── Bypass ──
app.post("/api/bypass/request", authRequired, roleRequired(["PIMS", "SUPERVISOR", "ADMIN"]), (req, res) => {
  const plate = String(req.body?.plate || "").toUpperCase();
  const reason = String(req.body?.reason || "").trim();
  if (!plate || !reason) return res.status(400).json({ ok: false, error: "Missing plate/reason" });
  const requestId = randomId("bypass");
  const obj = { requestId, plate, reason, status: "PENDING", createdAt: now(), requestedBy: req.session.userId, approvals: [] };
  bypassRequests.set(requestId, obj);
  pushAudit("BYPASS_REQUESTED", { plate, requestId, by: req.session.userId });
  schedulePersist();
  return res.json({ ok: true, request: obj });
});

app.post("/api/bypass/approve/:requestId", authRequired, roleRequired(["SUPERVISOR", "ADMIN"]), (req, res) => {
  const requestId = String(req.params.requestId);
  const obj = bypassRequests.get(requestId);
  if (!obj) return res.status(404).json({ ok: false, error: "Not found" });
  if (obj.status !== "PENDING") return res.status(400).json({ ok: false, error: "Not pending" });
  if (obj.approvals.some(a => a.userId === req.session.userId)) return res.status(409).json({ ok: false, error: "Already approved" });

  obj.approvals.push({ userId: req.session.userId, role: req.session.role, at: now() });
  const hasAdmin = obj.approvals.some(a => a.role === "ADMIN");
  if (obj.approvals.length >= 2 && hasAdmin) {
    obj.status = "APPROVED"; obj.closedAt = now();
    const prev = complianceByPlate.get(obj.plate) || defaultCompliance(obj.plate);
    complianceByPlate.set(obj.plate, { ...prev, plate: obj.plate, approved: true, policy: "BYPASS_APPROVED", bypassRequestId: requestId, updatedAt: now() });
    pushAudit("BYPASS_APPROVED", { plate: obj.plate, requestId, by: req.session.userId });
  } else {
    pushAudit("BYPASS_LEVEL1_APPROVED", { plate: obj.plate, requestId, by: req.session.userId });
  }
  bypassRequests.set(requestId, obj);
  schedulePersist();
  return res.json({ ok: true, request: obj });
});

// ── Events ──
app.post("/api/event", eventLimiter, (req, res) => {
  const event = req.body;
  if (!event || typeof event !== "object") return res.status(400).json({ ok: false, error: "Invalid JSON" });
  const session = getSessionFromReq(req);
  const actor = actorFromSession(session, "API");
  const result = processEvent(event, actor);
  if (!result.ok) return res.status(result.code || 400).json(result);
  return res.json({ ok: true, duplicate: !!result.duplicate, event: result.enriched || null });
});

// ── Audit ──
app.get("/api/audit", authRequired, roleRequired(["SUPERVISOR", "ADMIN"]), (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 500, 2000);
  return res.json({ ok: true, items: auditLogs.slice(-limit) });
});

// ── Yard Block Details (V6.1 Drill-down) ──
app.get("/api/yard/block/:id", authRequired, (req, res) => {
  const blockId = String(req.params.id).toUpperCase();
  const items = [];
  yardSlots.forEach((slot, key) => {
    if (slot.block === blockId) {
      const cont = containerRegistry.get(slot.containerId);
      items.push({
        position: key,
        containerId: slot.containerId,
        vesselName: cont?.vesselName || "—",
        grossWeight: cont?.grossWeight || 0,
        status: cont?.status || "IN_YARD"
      });
    }
  });
  return res.json({ ok: true, items });
});

// ── Yard Config (read-only, for frontend rendering) ──
app.get("/api/yard/config", (req, res) => {
  return res.json({ ok: true, config: YARD_CONFIG });
});

// ═══════════════════════════════════════════════════════════
//  WEBSOCKET
// ═══════════════════════════════════════════════════════════
wss.on("connection", (ws) => {
  ws.send(JSON.stringify({ type: "WELCOME", version: "PGG V6.0", serverTime: now() }));

  ws.on("message", (data) => {
    const msg = safeJsonParse(String(data));
    if (!msg || typeof msg !== "object") return;

    if (msg.type === "HELLO") {
      const token = msg.token ? String(msg.token) : "";
      const session = token ? sessions.get(token) : null;
      const meta = {
        app: String(msg.app || "UNKNOWN"),
        deviceId: String(msg.deviceId || "unknown"),
        plate: msg.plate ? String(msg.plate).toUpperCase() : null,
        role: session?.role || "UNKNOWN",
        userId: session?.userId || `${String(msg.app || "unknown").toLowerCase()}_ws`
      };
      clients.set(ws, meta);
      ws.send(JSON.stringify({ type: "HELLO_ACK", meta, serverTime: now() }));

      // Immediately push yard + plate state
      if (meta.plate) {
        ws.send(JSON.stringify({ type: "SYNC", plate: meta.plate, job: jobsByPlate.get(meta.plate) || null, state: stateByPlate.get(meta.plate) || null, compliance: complianceByPlate.get(meta.plate) || null, serverTime: now() }));
      }
      ws.send(JSON.stringify({ type: "YARD_UPDATE", yard: getYardSummary(), serverTime: now() }));
      return;
    }

    if (msg.type === "EVENT" && msg.event) {
      const meta = clients.get(ws) || { app: "UNKNOWN", role: "UNKNOWN", userId: "unknown_ws" };
      const actor = actorFromSession({ userId: meta.userId, role: meta.role }, meta.app);
      const result = processEvent(msg.event, actor);
      if (!result.ok) {
        ws.send(JSON.stringify({ type: "ERROR", code: result.code || 400, error: result.error }));
      }
      return;
    }

    if (msg.type === "YARD_BAY_FULL") {
      const meta = clients.get(ws) || {};
      const blockId = String(msg.block || "").toUpperCase();
      const bayNum = parseInt(msg.bay);
      if (blockId && bayNum) {
        const occ = getBayOccupancy(blockId, bayNum);
        pushAudit("YARD_BAY_FULL_REPORT", { block: blockId, bay: bayNum, occupancy: occ, by: meta.userId || "unknown" });
        broadcast({ type: "YARD_BAY_FULL", block: blockId, bay: bayNum, occupancy: occ, reportedBy: meta.userId, serverTime: now() });
      }
      return;
    }
  });

  ws.on("close", () => { clients.delete(ws); });
});

// ═══════════════════════════════════════════════════════════
//  START
// ═══════════════════════════════════════════════════════════
const PORT = Number(process.env.PORT || 3000);
initUsers();
loadStore();

server.listen(PORT, () => {
  console.log(`\n  ╔══════════════════════════════════════════╗`);
  console.log(`  ║   PGG Server V6.0 — Port Gate & Ground   ║`);
  console.log(`  ║   Listening on http://localhost:${PORT}     ║`);
  console.log(`  ║   WebSocket on ws://localhost:${PORT}       ║`);
  console.log(`  ╠══════════════════════════════════════════╣`);
  console.log(`  ║   Users: ${USERS.length} | Containers: ${containerRegistry.size}       ║`);
  console.log(`  ║   Yard Slots: ${yardSlots.size} | Audit: ${auditLogs.length}          ║`);
  console.log(`  ╚══════════════════════════════════════════╝\n`);
});

process.on("SIGINT", () => { persistStore(); process.exit(0); });
process.on("SIGTERM", () => { persistStore(); process.exit(0); });
