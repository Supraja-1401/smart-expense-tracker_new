import initSqlJs from "sql.js";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dbFilePath = path.join(__dirname, "expenses.sqlite");

let dbInstance = null;

// Helper to save DB buffer to disk
export function saveDatabase() {
  if (!dbInstance) return;
  try {
    const data = dbInstance.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(dbFilePath, buffer);
  } catch (err) {
    console.error("Error saving SQLite database to disk:", err);
  }
}

// Convert params for sql.js prepared statements
function sanitizeParams(params) {
  if (!params) return [];
  if (Array.isArray(params)) {
    return params.map((p) => (p === undefined ? null : p));
  }
  return params;
}

export async function initDatabase() {
  if (dbInstance) return dbInstance;

  const SQL = await initSqlJs();

  if (fs.existsSync(dbFilePath)) {
    try {
      const fileBuffer = fs.readFileSync(dbFilePath);
      if (fileBuffer.length === 0) {
        dbInstance = new SQL.Database();
      } else {
        dbInstance = new SQL.Database(fileBuffer);
        // Test basic query to ensure file integrity
        dbInstance.exec("SELECT 1;");
      }
      console.log("Loaded existing SQLite database from:", dbFilePath);
    } catch (err) {
      console.warn("⚠️ Existing SQLite database file was corrupted or incompatible. Recreating clean database...", err.message);
      try {
        if (fs.existsSync(dbFilePath)) {
          fs.unlinkSync(dbFilePath);
        }
      } catch (unlinkErr) {}
      dbInstance = new SQL.Database();
    }
  } else {
    dbInstance = new SQL.Database();
    console.log("Created fresh SQLite database instance.");
  }

  // Schema Definitions
  dbInstance.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  dbInstance.run(`
    CREATE TABLE IF NOT EXISTS user_settings (
      user_id INTEGER PRIMARY KEY,
      available_money REAL DEFAULT 0,
      currency TEXT DEFAULT '₹',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  dbInstance.run(`
    CREATE TABLE IF NOT EXISTS expenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      expense_name TEXT NOT NULL,
      amount REAL NOT NULL,
      category TEXT NOT NULL,
      date TEXT NOT NULL,
      description TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  dbInstance.run(`
    CREATE TABLE IF NOT EXISTS budgets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      category TEXT NOT NULL,
      monthly_limit REAL NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, category)
    );
  `);

  dbInstance.run(`
    CREATE TABLE IF NOT EXISTS otps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      otp TEXT NOT NULL,
      purpose TEXT NOT NULL,
      payload TEXT,
      expires_at INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  dbInstance.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at INTEGER NOT NULL
    );
  `);

  dbInstance.run(`
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      type TEXT DEFAULT 'info',
      is_read INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Indexes for fast lookup
  dbInstance.run(`CREATE INDEX IF NOT EXISTS idx_expenses_user_date ON expenses(user_id, date);`);
  dbInstance.run(`CREATE INDEX IF NOT EXISTS idx_expenses_user_cat ON expenses(user_id, category);`);
  dbInstance.run(`CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, is_read);`);
  dbInstance.run(`CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);`);

  saveDatabase();
  console.log("SQLite (WASM) schema initialized successfully.");
  return dbInstance;
}

// Promise-based SQL helpers
export async function dbRun(sql, params = []) {
  if (!dbInstance) await initDatabase();

  const cleanParams = sanitizeParams(params);
  const stmt = dbInstance.prepare(sql);
  stmt.run(cleanParams);
  stmt.free();

  const lastIDRes = dbInstance.exec("SELECT last_insert_rowid() as id;");
  const lastID = lastIDRes?.[0]?.values?.[0]?.[0] || 0;
  const changesRes = dbInstance.exec("SELECT changes() as count;");
  const changes = changesRes?.[0]?.values?.[0]?.[0] || 0;

  saveDatabase();
  return { lastID, changes };
}

export async function dbGet(sql, params = []) {
  if (!dbInstance) await initDatabase();

  const cleanParams = sanitizeParams(params);
  const stmt = dbInstance.prepare(sql);
  stmt.bind(cleanParams);

  let row = null;
  if (stmt.step()) {
    row = stmt.getAsObject();
  }
  stmt.free();
  return row;
}

export async function dbAll(sql, params = []) {
  if (!dbInstance) await initDatabase();

  const cleanParams = sanitizeParams(params);
  const stmt = dbInstance.prepare(sql);
  stmt.bind(cleanParams);

  const rows = [];
  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }
  stmt.free();
  return rows;
}

import crypto from "crypto";

export async function createSessionToken(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + 1000 * 60 * 60 * 24 * 14; // 14 days
  await dbRun("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)", [
    token,
    userId,
    expiresAt,
  ]);
  return token;
}

export async function getUserBySessionToken(token) {
  if (!token) return null;
  const now = Date.now();
  const sessionRow = await dbGet(
    "SELECT user_id, expires_at FROM sessions WHERE token = ?",
    [token]
  );
  if (!sessionRow) return null;
  if (now > sessionRow.expires_at) {
    await dbRun("DELETE FROM sessions WHERE token = ?", [token]);
    return null;
  }
  const user = await dbGet("SELECT id, name, email FROM users WHERE id = ?", [
    sessionRow.user_id,
  ]);
  return user;
}

export async function removeSessionToken(token) {
  if (!token) return;
  await dbRun("DELETE FROM sessions WHERE token = ?", [token]);
}

export default {
  initDatabase,
  dbRun,
  dbGet,
  dbAll,
  createSessionToken,
  getUserBySessionToken,
  removeSessionToken,
  saveDatabase,
};
