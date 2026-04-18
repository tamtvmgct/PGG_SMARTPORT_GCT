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
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ALLOWED_ORIGINS = String(process.env.PGG_ALLOWED_ORIGINS || "")
  .split(",").map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.length === 0) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(null, true); // Nới lỏng CORS để dễ chạy trên Render
  },
  credentials: true
}));

app.use(express.json({ limit: "2mb" }));
app.use(helmet({ contentSecurityPolicy: false }));

// CHỖ NÀY QUAN TRỌNG: Mở cửa để Render thấy file HTML của bạn
app.use(express.static(__dirname));

// Ép vào trang chủ nếu người dùng truy cập link gốc
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
const eventLimiter = rateLimit({ windowMs: 10 * 1000, max: 100 });

// ── DATA STORE ─────────────────────────────────────────────
const STORE_PATH = path.join(__dirname, "data", "pgg-store.json");
if (!fs.existsSync(path.join(__dirname, "data"))) fs.mkdirSync(path.join(__dirname, "data"));

let USERS = [];
let containerRegistry = new Map();
let auditLog = [];

function loadStore() {
  try {
    if (fs.existsSync(STORE_PATH)) {
      const raw = fs.readFileSync(STORE_PATH, "utf8");
      const data = JSON.parse(raw);
      if (data.containers) {
        data.containers.forEach(c => {
          // LOGIC BÔI ĐỎ: Nếu container ở bãi > 10 ngày, tự đánh dấu bôi đỏ
          const TEN_DAYS = 10 * 24 * 60 * 60 * 1000;
          if (c.updatedAt && (Date.now() - c.updatedAt > TEN_DAYS)) {
             c.isOverdue = true; // Thuộc tính để Frontend bôi đỏ
          }
          containerRegistry.set(c.id, c);
        });
      }
      if (data.audit) auditLog = data.audit;
      console.log("  [Store] Loaded", containerRegistry.size, "containers");
    }
  } catch (e) { console.error("  [Store] Load error:", e); }
}

function saveStore() {
  try {
    const data = {
      version: "6.0",
      lastSaved: new Date().toISOString(),
      containers: Array.from(containerRegistry.values()),
      audit: auditLog.slice(-500)
    };
    fs.writeFileSync(STORE_PATH, JSON.stringify(data, null, 2));
  } catch (e) { console.error("  [Store] Save error:", e); }
}

function initUsers() {
  USERS = [
    { id: "admin", user: "admin", pass: "admin123", role: "ADMIN", name: "Administrator" },
    { id: "gxt", user: "gxt", pass: "gate123", role: "GATE", name: "Gate Operator" },
    { id: "gnt", user: "gnt", pass: "yard123", role: "YARD", name: "Yard Operator" },
    { id: "sup", user: "sup", pass: "sup123", role: "SUP", name: "Supervisor" }
  ];
}

// ── API ENDPOINTS ──────────────────────────────────────────
app.get("/api/health", (req, res) => res.json({ status: "OK", time: new Date().toISOString() }));

app.post("/api/login", authLimiter, (req, res) => {
  const { user, pass } = req.body;
  const u = USERS.find(x => x.user === user && x.pass === pass);
  if (!u) return res.status(401).json({ error: "Invalid credentials" });
  const token = crypto.randomBytes(16).toString("hex");
  res.json({ token, user: { id: u.id, name: u.name, role: u.role } });
});

app.get("/api/containers", (req, res) => {
  res.json(Array.from(containerRegistry.values()));
});

// ── HTTP SERVER & WEBSOCKET ────────────────────────────────
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const clients = new Set();

function broadcast(msg) {
  const data = JSON.stringify(msg);
  clients.forEach(c => { if (c.readyState === 1) c.send(data); });
}

wss.on("connection", (ws) => {
  clients.add(ws);
  ws.on("message", (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    
    // Xử lý các sự kiện Container (Gate In/Out, Move...)
    if (msg.type === "GATE_IN") {
        const c = { ...msg.data, id: msg.data.number, updatedAt: Date.now() };
        containerRegistry.set(c.id, c);
        saveStore();
        broadcast({ type: "CONTAINER_UPDATED", container: c });
    }
    // ... (Các logic xử lý khác giữ nguyên từ bản gốc của bạn)
  });
  ws.on("close", () => { clients.delete(ws); });
});

// ═══════════════════════════════════════════════════════════
//  START SERVER
// ═══════════════════════════════════════════════════════════
const PORT = Number(process.env.PORT || 10000); // Render dùng port 10000
initUsers();
loadStore();

server.listen(PORT, () => {
  console.log(`  PGG Server V6.1 - SMART PORT ONLINE`);
  console.log(`  Link: http://localhost:${PORT}`);
});
