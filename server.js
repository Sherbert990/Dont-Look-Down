const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function loadUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch { return {}; }
}
function saveUsers(u) { fs.writeFileSync(USERS_FILE, JSON.stringify(u, null, 2)); }

const sessions = new Map(); // token -> user key (lowercase username)

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function verifyPassword(password, user) {
  const h = Buffer.from(hashPassword(password, user.salt), 'hex');
  const stored = Buffer.from(user.hash, 'hex');
  return h.length === stored.length && crypto.timingSafeEqual(h, stored);
}
function makeToken() { return crypto.randomBytes(24).toString('hex'); }

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function sessionCookie(token, maxAge) {
  return `sid=${token}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Lax`;
}
function sendJson(res, status, obj, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
  });
}

function cleanUsername(name) {
  return typeof name === 'string' ? name.trim() : '';
}
function validUsername(name) {
  return /^[A-Za-z0-9_ ]{1,20}$/.test(name);
}
function cleanAvatar(a) {
  const n = parseInt(a, 10);
  return Number.isInteger(n) && n >= 0 && n <= 9 ? n : 0;
}

function currentUser(req) {
  const token = parseCookies(req).sid;
  if (!token) return null;
  const key = sessions.get(token);
  if (!key) return null;
  const users = loadUsers();
  const u = users[key];
  if (!u) return null;
  return { token, key, username: u.username, avatar: u.avatar };
}

async function handleApi(req, res, urlPath) {
  if (urlPath === '/api/register' && req.method === 'POST') {
    const body = await readBody(req);
    const username = cleanUsername(body.username);
    const password = typeof body.password === 'string' ? body.password : '';
    if (!validUsername(username)) return sendJson(res, 400, { error: 'Username must be 1-20 letters, numbers, spaces or underscores.' });
    if (password.length < 4) return sendJson(res, 400, { error: 'Password must be at least 4 characters.' });
    const key = username.toLowerCase();
    const users = loadUsers();
    if (users[key]) return sendJson(res, 409, { error: 'That username is taken.' });
    const salt = crypto.randomBytes(16).toString('hex');
    const avatar = cleanAvatar(body.avatar);
    users[key] = { username, hash: hashPassword(password, salt), salt, avatar };
    saveUsers(users);
    const token = makeToken();
    sessions.set(token, key);
    return sendJson(res, 200, { username, avatar }, { 'Set-Cookie': sessionCookie(token, 60 * 60 * 24 * 30) });
  }

  if (urlPath === '/api/login' && req.method === 'POST') {
    const body = await readBody(req);
    const username = cleanUsername(body.username);
    const password = typeof body.password === 'string' ? body.password : '';
    const key = username.toLowerCase();
    const users = loadUsers();
    const u = users[key];
    if (!u || !verifyPassword(password, u)) return sendJson(res, 401, { error: 'Wrong username or password.' });
    const token = makeToken();
    sessions.set(token, key);
    return sendJson(res, 200, { username: u.username, avatar: u.avatar }, { 'Set-Cookie': sessionCookie(token, 60 * 60 * 24 * 30) });
  }

  if (urlPath === '/api/logout' && req.method === 'POST') {
    const token = parseCookies(req).sid;
    if (token) sessions.delete(token);
    return sendJson(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie('', 0) });
  }

  if (urlPath === '/api/me' && req.method === 'GET') {
    const me = currentUser(req);
    if (!me) return sendJson(res, 401, { error: 'Not signed in.' });
    return sendJson(res, 200, { username: me.username, avatar: me.avatar });
  }

  if (urlPath === '/api/profile' && req.method === 'POST') {
    const me = currentUser(req);
    if (!me) return sendJson(res, 401, { error: 'Not signed in.' });
    const body = await readBody(req);
    const username = cleanUsername(body.username);
    if (!validUsername(username)) return sendJson(res, 400, { error: 'Username must be 1-20 letters, numbers, spaces or underscores.' });
    const avatar = cleanAvatar(body.avatar);
    const newKey = username.toLowerCase();
    const users = loadUsers();
    if (newKey !== me.key && users[newKey]) return sendJson(res, 409, { error: 'That username is taken.' });
    const record = users[me.key];
    record.username = username;
    record.avatar = avatar;
    if (newKey !== me.key) {
      delete users[me.key];
      users[newKey] = record;
      for (const [tok, k] of sessions) if (k === me.key) sessions.set(tok, newKey);
    }
    saveUsers(users);
    return sendJson(res, 200, { username, avatar });
  }

  return sendJson(res, 404, { error: 'Unknown endpoint.' });
}

const server = http.createServer((req, res) => {
  let urlPath = decodeURIComponent(req.url.split('?')[0]);

  if (urlPath.startsWith('/api/')) {
    handleApi(req, res, urlPath).catch(() => sendJson(res, 500, { error: 'Server error.' }));
    return;
  }

  if (urlPath === '/') urlPath = '/dont_look_down.html';
  const filePath = path.join(ROOT, path.normalize(urlPath));
  if (!filePath.startsWith(ROOT) || filePath === USERS_FILE || filePath.startsWith(DATA_DIR + path.sep)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(filePath)] || 'application/octet-stream' });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log(`Don't Look Down running on port ${PORT}`);
});
