'use strict';
/*
 * BACE Sunday Register server.
 * Uses only what is built into Node 22: no packages to install.
 */
const http = require('http');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, 'register.db'));
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL COLLATE NOCASE,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','coordinator','viewer')),
  pass_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS entries(
  key TEXT PRIMARY KEY,
  date TEXT NOT NULL,
  sid TEXT NOT NULL,
  data TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  updated_by INTEGER
);
`);

/* ---------- passwords and sessions ---------- */
function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(pw, salt, 64);
  return salt.toString('hex') + ':' + h.toString('hex');
}
function checkPw(pw, stored) {
  const [s, h] = String(stored).split(':');
  const hh = crypto.scryptSync(pw, Buffer.from(s, 'hex'), 64);
  return crypto.timingSafeEqual(hh, Buffer.from(h, 'hex'));
}
const DUMMY_HASH = hashPw('not-a-real-password');
const sha = (t) => crypto.createHash('sha256').update(t).digest('hex');
const SESSION_MS = 30 * 24 * 60 * 60 * 1000;

function getCookie(req, name) {
  const h = req.headers.cookie || '';
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) {
      try { return decodeURIComponent(part.slice(i + 1).trim()); } catch (e) { return null; }
    }
  }
  return null;
}
function isHttps(req) {
  return !!req.socket.encrypted || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
}
function clientIp(req) {
  const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xf || req.socket.remoteAddress || '';
}

/* ---------- first run: create the admin account ---------- */
if (db.prepare('SELECT COUNT(*) AS n FROM users').get().n === 0) {
  const username = (process.env.ADMIN_USERNAME || 'admin').trim();
  let password = process.env.ADMIN_PASSWORD;
  let generated = false;
  if (!password || password.length < 8) {
    password = crypto.randomBytes(9).toString('base64url');
    generated = true;
  }
  db.prepare('INSERT INTO users(username,full_name,role,pass_hash,active,created_at) VALUES(?,?,?,?,1,?)')
    .run(username, 'Administrator', 'admin', hashPw(password), Date.now());
  console.log('\n=== First run: administrator account created ===');
  console.log('Username: ' + username);
  if (generated) console.log('Password: ' + password + '   (change it after you sign in)');
  else console.log('Password: the ADMIN_PASSWORD you set');
  console.log('================================================\n');
}
const purge = () => db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());
purge();
setInterval(purge, 6 * 60 * 60 * 1000).unref();

/* ---------- helpers ---------- */
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'same-origin',
  'Content-Security-Policy':
    "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
};
function send(res, status, obj, extra) {
  const body = JSON.stringify(obj);
  res.writeHead(status, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, SECURITY_HEADERS, extra || {}));
  res.end(body);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > 50 * 1024) { reject(Object.assign(new Error('too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { const v = JSON.parse(Buffer.concat(chunks).toString('utf8')); resolve(v && typeof v === 'object' ? v : {}); }
      catch (e) { reject(Object.assign(new Error('bad json'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}
function authenticate(req) {
  const t = getCookie(req, 'bace_sid');
  if (!t) return null;
  return db.prepare(
    `SELECT u.id, u.username, u.full_name AS fullName, u.role
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > ? AND u.active = 1`
  ).get(sha(t), Date.now()) || null;
}
const plain = (row) => (row ? JSON.parse(JSON.stringify(row)) : row);
const ROLES = ['admin', 'coordinator', 'viewer'];
const activeAdmins = () => db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND active=1").get().n;

/* ---------- entries ---------- */
const KEY_RE = /^(\d{4})-(\d{2})-(\d{2})__(day|[A-Za-z0-9]{1,20})$/;
const STR = { speaker: 200, topic: 300, notes: 2000, menu: 3000, sponsor: 200, facilitator: 200, actualStart: 5, actualEnd: 5 };
const NUM = ['online', 'offline', 'attendees', 'served'];
function clean(b, key) {
  const [date, sid] = key.split('__');
  const o = { date, sid };
  for (const f of Object.keys(STR)) {
    if (typeof b[f] === 'string' && b[f]) {
      const v = b[f].slice(0, STR[f]);
      if ((f === 'actualStart' || f === 'actualEnd') && !/^([01]\d|2[0-3]):[0-5]\d$/.test(v)) continue;
      o[f] = v;
    }
  }
  for (const f of NUM) if (Number.isFinite(b[f])) o[f] = Math.min(100000, Math.max(0, Math.trunc(b[f])));
  if (typeof b.held === 'boolean') o.held = b.held;
  if (typeof b.testDay === 'boolean') o.testDay = b.testDay;
  if (Array.isArray(b.servers)) {
    o.servers = b.servers.filter((x) => typeof x === 'string' && x.trim()).slice(0, 300).map((x) => x.trim().slice(0, 100));
  }
  return o;
}

/* ---------- live updates ---------- */
const clients = new Set();
setInterval(() => clients.forEach((c) => c.write(': ping\n\n')), 25000).unref();
function broadcast(msg) {
  const s = 'data: ' + JSON.stringify(msg) + '\n\n';
  clients.forEach((c) => c.write(s));
}

/* ---------- login rate limit ---------- */
const fails = new Map();

/* ---------- API ---------- */
async function api(req, res, url) {
  const p = url.pathname;
  const m = req.method;

  // Changing requests must carry this header. Other websites cannot add it from a browser.
  if (m !== 'GET' && req.headers['x-requested-with'] !== 'bace') return send(res, 403, { error: 'Request blocked' });

  if (p === '/api/login' && m === 'POST') {
    const { username, password } = await readJson(req);
    if (typeof username !== 'string' || typeof password !== 'string' || !username || !password)
      return send(res, 400, { error: 'Enter your username and password' });
    const k = clientIp(req) + '|' + username.trim().toLowerCase();
    const f = fails.get(k);
    if (f && f.until > Date.now()) return send(res, 429, { error: 'Too many wrong attempts. Try again in 15 minutes.' });
    const u = db.prepare('SELECT * FROM users WHERE username = ? AND active = 1').get(username.trim());
    const ok = checkPw(password, u ? u.pass_hash : DUMMY_HASH) && !!u;
    if (!ok) {
      const n = (f ? f.count : 0) + 1;
      fails.set(k, { count: n, until: n >= 8 ? Date.now() + 15 * 60 * 1000 : 0 });
      return send(res, 401, { error: 'Wrong username or password' });
    }
    fails.delete(k);
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(sha(token), u.id, Date.now() + SESSION_MS);
    const cookie = `bace_sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_MS / 1000)}${isHttps(req) ? '; Secure' : ''}`;
    return send(res, 200, { id: u.id, username: u.username, fullName: u.full_name, role: u.role }, { 'Set-Cookie': cookie });
  }

  if (p === '/api/logout' && m === 'POST') {
    const t = getCookie(req, 'bace_sid');
    if (t) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha(t));
    return send(res, 200, { ok: true }, { 'Set-Cookie': 'bace_sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' });
  }

  // everything below needs a signed-in person
  const user = authenticate(req);
  if (!user) return send(res, 401, { error: 'Please sign in' });
  const canEnter = user.role === 'admin' || user.role === 'coordinator';

  if (p === '/api/me' && m === 'GET') return send(res, 200, plain(user));

  if (p === '/api/me/password' && m === 'POST') {
    const { current, next } = await readJson(req);
    if (typeof current !== 'string' || typeof next !== 'string') return send(res, 400, { error: 'Fill in both passwords' });
    if (next.length < 8) return send(res, 400, { error: 'The new password needs at least 8 characters' });
    const u = db.prepare('SELECT pass_hash FROM users WHERE id = ?').get(user.id);
    if (!checkPw(current, u.pass_hash)) return send(res, 400, { error: 'Your current password is wrong' });
    db.prepare('UPDATE users SET pass_hash = ? WHERE id = ?').run(hashPw(next), user.id);
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?').run(user.id, sha(getCookie(req, 'bace_sid')));
    return send(res, 200, { ok: true });
  }

  if (p === '/api/entries' && m === 'GET') {
    const rows = db.prepare(
      `SELECT e.key, e.data, e.updated_at AS updatedAt, u.full_name AS byName
         FROM entries e LEFT JOIN users u ON u.id = e.updated_by`
    ).all();
    const out = {};
    for (const r of rows) {
      let d;
      try { d = JSON.parse(r.data); } catch (e) { continue; }
      d.updatedAt = r.updatedAt;
      if (r.byName) d.byName = r.byName;
      out[r.key] = d;
    }
    return send(res, 200, out);
  }

  const em = /^\/api\/entries\/([^/]+)$/.exec(p);
  if (em && m === 'PUT') {
    if (!canEnter) return send(res, 403, { error: 'Only coordinators can enter reports' });
    const key = decodeURIComponent(em[1]);
    const km = KEY_RE.exec(key);
    if (!km) return send(res, 400, { error: 'Bad entry' });
    const d = new Date(Number(km[1]), Number(km[2]) - 1, Number(km[3]));
    if (d.getMonth() !== Number(km[2]) - 1) return send(res, 400, { error: 'Bad date' });
    const data = clean(await readJson(req), key);
    const now = Date.now();
    db.prepare(
      `INSERT INTO entries(key,date,sid,data,updated_at,updated_by) VALUES(?,?,?,?,?,?)
       ON CONFLICT(key) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at, updated_by=excluded.updated_by`
    ).run(key, data.date, data.sid, JSON.stringify(data), now, user.id);
    broadcast({ type: 'entry', key });
    return send(res, 200, { ok: true, updatedAt: now });
  }

  if (p === '/api/events' && m === 'GET') {
    res.writeHead(200, Object.assign({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' }, SECURITY_HEADERS));
    res.write('retry: 3000\n\n');
    clients.add(res);
    req.on('close', () => clients.delete(res));
    return;
  }

  // people: administrators only
  if (p === '/api/users' || p.startsWith('/api/users/')) {
    if (user.role !== 'admin') return send(res, 403, { error: 'Only administrators can manage people' });

    if (p === '/api/users' && m === 'GET') {
      const rows = db.prepare('SELECT id, username, full_name AS fullName, role, active FROM users ORDER BY full_name COLLATE NOCASE').all();
      return send(res, 200, rows);
    }
    if (p === '/api/users' && m === 'POST') {
      const { username, fullName, role, password } = await readJson(req);
      if (typeof username !== 'string' || !/^[A-Za-z0-9._-]{3,32}$/.test(username.trim()))
        return send(res, 400, { error: 'Username must be 3 to 32 letters, numbers, dots, dashes or underscores' });
      if (typeof fullName !== 'string' || !fullName.trim() || fullName.length > 80) return send(res, 400, { error: "Enter the person's name" });
      if (!ROLES.includes(role)) return send(res, 400, { error: 'Choose a role' });
      if (typeof password !== 'string' || password.length < 8) return send(res, 400, { error: 'The password needs at least 8 characters' });
      try {
        const r = db.prepare('INSERT INTO users(username,full_name,role,pass_hash,active,created_at) VALUES(?,?,?,?,1,?)')
          .run(username.trim(), fullName.trim(), role, hashPw(password), Date.now());
        return send(res, 200, { id: Number(r.lastInsertRowid) });
      } catch (e) {
        if (String(e.message).includes('UNIQUE')) return send(res, 400, { error: 'That username is already taken' });
        throw e;
      }
    }
    const um = /^\/api\/users\/(\d+)$/.exec(p);
    if (um && m === 'PATCH') {
      const id = Number(um[1]);
      const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
      if (!u) return send(res, 404, { error: 'Person not found' });
      const b = await readJson(req);
      const role = b.role !== undefined ? b.role : u.role;
      const active = b.active !== undefined ? (b.active ? 1 : 0) : u.active;
      if (!ROLES.includes(role)) return send(res, 400, { error: 'Choose a role' });
      if (u.role === 'admin' && u.active && (role !== 'admin' || !active) && activeAdmins() <= 1)
        return send(res, 400, { error: 'There must always be at least one active administrator' });
      if (b.fullName !== undefined && (typeof b.fullName !== 'string' || !b.fullName.trim() || b.fullName.length > 80))
        return send(res, 400, { error: "Enter the person's name" });
      if (b.password !== undefined && (typeof b.password !== 'string' || b.password.length < 8))
        return send(res, 400, { error: 'The password needs at least 8 characters' });
      db.prepare('UPDATE users SET role=?, active=?, full_name=? WHERE id=?')
        .run(role, active, b.fullName !== undefined ? b.fullName.trim() : u.full_name, id);
      if (b.password !== undefined) {
        db.prepare('UPDATE users SET pass_hash=? WHERE id=?').run(hashPw(b.password), id);
        db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);
      }
      if (!active || role !== u.role) db.prepare('DELETE FROM sessions WHERE user_id=?').run(id === user.id ? -1 : id);
      return send(res, 200, { ok: true });
    }
  }

  return send(res, 404, { error: 'Not found' });
}

/* ---------- static files ---------- */
const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
function serveStatic(req, res, url) {
  let rel = decodeURIComponent(url.pathname);
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, SECURITY_HEADERS); return res.end('Not found'); }
    res.writeHead(200, Object.assign({ 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' }, SECURITY_HEADERS));
    res.end(buf);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/healthz') { res.writeHead(200); return res.end('ok'); }
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
    return serveStatic(req, res, url);
  } catch (e) {
    if (e && e.status) return send(res, e.status, { error: e.status === 413 ? 'That request is too large' : 'Bad request' });
    console.error(e);
    if (!res.headersSent) send(res, 500, { error: 'Something went wrong on the server' });
  }
});
server.listen(PORT, () => console.log('BACE Sunday Register running on port ' + PORT));
