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

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(helmet({ contentSecurityPolicy: false }));

// 1. CHỖ NÀY ĐỂ MỞ CỬA GIAO DIỆN (Sửa lỗi Cannot GET)
app.use(express.static(__dirname));

// 2. TỰ ĐỘNG VÀO TRANG CHỦ
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── DATA STORE ─────────────────────────────────────────────
const STORE_PATH = path.join(__dirname, "data", "pgg-store.json");
if (!fs.existsSync(path.join(__dirname, "data"))) fs.mkdirSync(path.join(__dirname, "data"));

let USERS = [];
let containerRegistry = new Map();

function loadStore() {
  try {
    if (fs.existsSync(STORE_PATH)) {
      const data = JSON.parse(fs.readFileSync(STORE_PATH, "utf8"));
      if (data.containers) {
        data.containers.forEach(c => {
          // LOGIC BÔI ĐỎ 10 NGÀY CHO CHÚ SƠN
          const TEN_DAYS = 10 * 24 * 60 * 60 * 1000;
          if (c.updatedAt && (Date.now() - c.updatedAt > TEN_DAYS)) {
             c.status = "OVERDUE_RED"; 
          }
          containerRegistry.set(c.id, c);
        });
      }
    }
  } catch (e) { console.error(e); }
}

function initUsers() {
  USERS = [
    { id: "admin", user: "admin", pass: "admin123", role: "ADMIN", name: "Admin" },
    { id: "sup", user: "sup", pass: "sup123", role: "SUP", name: "Supervisor" }
  ];
}

// ── API ───────────────────────────────────────────────────
app.get("/api/health", (req, res) => res.json({ status: "OK" }));
app.get("/api/containers", (req, res) => res.json(Array.from(containerRegistry.values())));
app.post("/api/login", (req, res) => {
  const { user, pass } = req.body;
  const u = USERS.find(x => x.user === user && x.pass === pass);
  if (!u) return res.status(401).json({ error: "Sai tài khoản" });
  res.json({ token: "pgg-token", user: { id: u.id, name: u.name, role: u.role } });
});

const server = http.createServer(app);
const PORT = process.env.PORT || 10000;
initUsers();
loadStore();

server.listen(PORT, () => {
  console.log(`Server chạy tại port ${PORT}`);
});
