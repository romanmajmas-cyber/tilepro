const express = require('express');
const bcrypt  = require('bcryptjs');
const crypto  = require('crypto');
const path    = require('path');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_DAYS = 30;
const BCRYPT_ROUNDS = 10;

const db = new Database(path.join(__dirname, 'tilepro.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    created_at    TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS requests (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    name        TEXT NOT NULL,
    phone       TEXT NOT NULL,
    email       TEXT,
    service     TEXT NOT NULL,
    area        TEXT,
    address     TEXT,
    comment     TEXT,
    status      TEXT NOT NULL DEFAULT 'new',
    admin_note  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_requests_user   ON requests(user_id);
  CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);
  CREATE INDEX IF NOT EXISTS idx_sessions_user   ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_exp    ON sessions(expires_at);
`);

{
  const admin = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@tile.ru');
  if (!admin) {
    const hash = bcrypt.hashSync('admin', BCRYPT_ROUNDS);
    db.prepare('INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?,?,?,?,?)')
      .run('Администратор', 'admin@tile.ru', hash, 'admin', new Date().toISOString());
    console.log('✅ Создан администратор: admin@tile.ru / admin');
  }
}

function cleanupSessions() {
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(new Date().toISOString());
}
cleanupSessions();
setInterval(cleanupSessions, 60 * 60 * 1000);

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)')
    .run(token, userId, now.toISOString(), expires.toISOString());
  return token;
}

function getTokenFromReq(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : null;
}

function authMiddleware(req, res, next) {
  const token = getTokenFromReq(req);
  if (!token) return res.status(401).json({ error: 'Не авторизован' });
  const s = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!s) return res.status(401).json({ error: 'Сессия не найдена' });
  if (new Date(s.expires_at) < new Date()) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return res.status(401).json({ error: 'Сессия истекла' });
  }
  const user = db.prepare('SELECT id, name, email, role, created_at FROM users WHERE id = ?').get(s.user_id);
  if (!user) return res.status(401).json({ error: 'Пользователь не найден' });
  req.user = user;
  req.token = token;
  next();
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Доступ запрещён' });
  next();
}

function mapRequest(r) {
  return {
    id: r.id, userId: r.user_id, name: r.name, phone: r.phone,
    email: r.email || '', service: r.service, area: r.area || '',
    address: r.address || '', comment: r.comment || '',
    status: r.status, adminNote: r.admin_note || '', createdAt: r.created_at,
    client: r.client_name ? { name: r.client_name, email: r.client_email } : null
  };
}

app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Заполните все поля' });
  if (String(password).length < 4) return res.status(400).json({ error: 'Пароль минимум 4 символа' });
  const em = String(email).trim().toLowerCase();
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(em);
  if (exists) return res.status(409).json({ error: 'Email уже занят' });
  const hash = bcrypt.hashSync(String(password), BCRYPT_ROUNDS);
  const info = db.prepare('INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?,?,?,?,?)')
    .run(String(name).trim(), em, hash, 'user', new Date().toISOString());
  const token = createSession(info.lastInsertRowid);
  const user = db.prepare('SELECT id, name, email, role FROM users WHERE id = ?').get(info.lastInsertRowid);
  res.json({ token, user });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Заполните все поля' });
  const em = String(email).trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(em);
  if (!user || !bcrypt.compareSync(String(password), user.password_hash)) {
    return res.status(401).json({ error: 'Неверный email или пароль' });
  }
  const token = createSession(user.id);
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.post('/api/logout', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(req.token);
  res.json({ ok: true });
});

app.get('/api/me', authMiddleware, (req, res) => res.json({ user: req.user }));

app.get('/api/requests', authMiddleware, (req, res) => {
  let rows;
  if (req.user.role === 'admin') {
    rows = db.prepare(`SELECT r.*, u.name AS client_name, u.email AS client_email
      FROM requests r LEFT JOIN users u ON u.id = r.user_id ORDER BY r.id DESC`).all();
  } else {
    rows = db.prepare('SELECT * FROM requests WHERE user_id = ? ORDER BY id DESC').all(req.user.id);
  }
  res.json(rows.map(mapRequest));
});

app.post('/api/requests', (req, res) => {
  const b = req.body || {};
  if (!b.name || !b.phone || !b.service) return res.status(400).json({ error: 'Заполните обязательные поля' });
  let userId = null;
  const token = getTokenFromReq(req);
  if (token) {
    const s = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
    if (s && new Date(s.expires_at) > new Date()) userId = s.user_id;
  }
  const info = db.prepare(`INSERT INTO requests
    (user_id, name, phone, email, service, area, address, comment, status, admin_note, created_at)
    VALUES (?,?,?,?,?,?,?,?, 'new', '', ?)`)
    .run(userId, String(b.name).trim(), String(b.phone).trim(),
         b.email ? String(b.email).trim() : '', String(b.service),
         b.area ? String(b.area) : '', b.address ? String(b.address).trim() : '',
         b.comment ? String(b.comment).trim() : '', new Date().toISOString());
  const row = db.prepare('SELECT * FROM requests WHERE id = ?').get(info.lastInsertRowid);
  res.json(mapRequest(row));
});

app.patch('/api/requests/:id', authMiddleware, (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare('SELECT * FROM requests WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ error: 'Заявка не найдена' });
  const isAdmin = req.user.role === 'admin';
  const isOwner = row.user_id === req.user.id;
  if (!isAdmin) {
    if (!isOwner) return res.status(403).json({ error: 'Нет доступа' });
    if (req.body.status && req.body.status !== 'cancelled')
      return res.status(403).json({ error: 'Можно только отменить свою заявку' });
  }
  const newStatus = req.body.status ?? row.status;
  const allowed = ['new', 'progress', 'done', 'cancelled'];
  if (!allowed.includes(newStatus)) return res.status(400).json({ error: 'Недопустимый статус' });
  const newNote = isAdmin && req.body.adminNote !== undefined ? String(req.body.adminNote) : row.admin_note;
  db.prepare('UPDATE requests SET status = ?, admin_note = ? WHERE id = ?').run(newStatus, newNote, id);
  const updated = db.prepare('SELECT * FROM requests WHERE id = ?').get(id);
  res.json(mapRequest(updated));
});

app.delete('/api/requests/:id', authMiddleware, adminOnly, (req, res) => {
  const id = Number(req.params.id);
  const info = db.prepare('DELETE FROM requests WHERE id = ?').run(id);
  if (info.changes === 0) return res.status(404).json({ error: 'Заявка не найдена' });
  res.json({ ok: true });
});

app.get('/api/users/count', authMiddleware, adminOnly, (req, res) => {
  const row = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role != 'admin'").get();
  res.json({ count: row.c });
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`🚀 ПлиткаПро запущен: http://localhost:${PORT}`));
