// Atelier shop to-do board. Zero dependencies: Node 22+ (built-in node:sqlite).
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------- secrets ----------
// SESSION_SECRET signs login cookies. If not provided, one is generated and kept on the data disk.
function loadSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  const f = path.join(DATA_DIR, '.session_secret');
  if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8');
  const s = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(f, s, { mode: 0o600 });
  return s;
}
const SECRET = loadSecret();
// The TV board URL is /tv?key=TV_KEY so a stranger who finds the site can't see the shop board.
function loadTvKey() {
  if (process.env.TV_KEY) return process.env.TV_KEY;
  const f = path.join(DATA_DIR, '.tv_key');
  if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8');
  const k = crypto.randomBytes(6).toString('hex');
  fs.writeFileSync(f, k, { mode: 0o600 });
  return k;
}
const TV_KEY = loadTvKey();

// ---------- db ----------
const db = new DatabaseSync(path.join(DATA_DIR, 'todo.db'));
db.exec(`
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  pin_salt TEXT NOT NULL,
  pin_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  hide_from_board INTEGER NOT NULL DEFAULT 0,  -- whole list is private: no column on TV/board
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  urgent INTEGER NOT NULL DEFAULT 0,
  private INTEGER NOT NULL DEFAULT 0,          -- single task hidden from the board
  done INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  done_at INTEGER
);
CREATE INDEX IF NOT EXISTS tasks_owner ON tasks(owner_id, done);
`);

// Migration: priority (0 low, 1 normal, 2 high, 3 urgent) and attention flags replace the old urgent yes/no.
{
  const cols = db.prepare('PRAGMA table_info(tasks)').all().map((c) => c.name);
  if (!cols.includes('priority')) {
    db.exec('ALTER TABLE tasks ADD COLUMN priority INTEGER NOT NULL DEFAULT 1');
    db.exec('UPDATE tasks SET priority=3 WHERE urgent=1');
  }
  if (!cols.includes('details')) {
    db.exec("ALTER TABLE tasks ADD COLUMN details TEXT NOT NULL DEFAULT ''");   // long text: cut lists etc., never on the TV
    db.exec("UPDATE tasks SET details=note, note=''");                           // earlier notes were private; keep them that way
  }
  if (!cols.includes('flag')) {
    db.exec("ALTER TABLE tasks ADD COLUMN flag TEXT NOT NULL DEFAULT ''");        // '', info, material, manager
    db.exec("ALTER TABLE tasks ADD COLUMN flag_text TEXT NOT NULL DEFAULT ''");   // what exactly is needed
  }
}
if (!db.prepare('PRAGMA table_info(users)').all().some((c) => c.name === 'is_manager')) {
  db.exec('ALTER TABLE users ADD COLUMN is_manager INTEGER NOT NULL DEFAULT 0'); // can resolve attention flags
}
const FLAGS = ['', 'info', 'material', 'manager'];
const prio = (v) => { const n = Number(v); return Number.isInteger(n) && n >= 0 && n <= 3 ? n : 1; };
const flagOf = (v) => (FLAGS.includes(v) ? v : '');

function hashPin(pin, salt) {
  return crypto.scryptSync(String(pin), salt, 32).toString('hex');
}
function createUser(name, pin, { admin = 0, hide = 0 } = {}) {
  const salt = crypto.randomBytes(16).toString('hex');
  return db.prepare('INSERT INTO users (name, pin_salt, pin_hash, is_admin, hide_from_board) VALUES (?,?,?,?,?)')
    .run(name, salt, hashPin(pin, salt), admin, hide).lastInsertRowid;
}
// First run: create the owner account. Change this PIN right after signing in (Settings).
if (db.prepare('SELECT COUNT(*) c FROM users').get().c === 0) {
  createUser(process.env.ADMIN_NAME || 'Chris', process.env.ADMIN_PIN || '1234', { admin: 1, hide: 1 });
  console.log('Created first user. Sign in with the admin name and PIN (default 1234) and change it.');
}

// ---------- sessions ----------
const sign = (v) => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
function makeCookie(userId) {
  const exp = Date.now() + 90 * 24 * 3600 * 1000;
  const v = `${userId}.${exp}`;
  return `${v}.${sign(v)}`;
}
function readSession(req) {
  const m = /(?:^|;\s*)sess=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const [id, exp, sig] = m[1].split('.');
  if (!id || !exp || !sig) return null;
  const good = sign(`${id}.${exp}`);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  if (Number(exp) < Date.now()) return null;
  return db.prepare('SELECT * FROM users WHERE id=? AND active=1').get(Number(id)) || null;
}
const cookieFlags = () => `Path=/; HttpOnly; SameSite=Lax; Max-Age=${90 * 24 * 3600}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`;

// ---------- login throttling (PINs are short, so lock out guessing) ----------
const fails = new Map(); // key -> {n, until}
function throttled(key) {
  const f = fails.get(key);
  return f && f.until > Date.now();
}
function noteFail(key) {
  const f = fails.get(key) || { n: 0, until: 0 };
  f.n += 1;
  if (f.n >= 5) { f.until = Date.now() + 5 * 60 * 1000; f.n = 0; }
  fails.set(key, f);
}

// ---------- helpers ----------
const json = (res, code, obj) => {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
};
const readBody = (req) => new Promise((resolve, reject) => {
  let b = '';
  req.on('data', (c) => { b += c; if (b.length > 50_000) { reject(new Error('too big')); req.destroy(); } });
  req.on('end', () => { try { resolve(b ? JSON.parse(b) : {}); } catch (e) { reject(e); } });
});
const clean = (s, n) => String(s ?? '').trim().slice(0, n);
const publicUser = (u) => ({ id: u.id, name: u.name, is_admin: !!u.is_admin, is_manager: !!(u.is_manager || u.is_admin), hide_from_board: !!u.hide_from_board });

// The ONE place that decides what the shared board shows.
// Hidden people get no column. Private tasks are never sent, only counted.
function boardData() {
  const people = db.prepare('SELECT id, name FROM users WHERE active=1 AND hide_from_board=0 ORDER BY name').all();
  const open = db.prepare("SELECT id, owner_id, title, note, (details!='') AS has_details, priority, flag, flag_text, private FROM tasks WHERE done=0 ORDER BY (flag!='') DESC, priority DESC, id").all();
  const doneToday = db.prepare('SELECT owner_id, COUNT(*) c FROM tasks WHERE done=1 AND done_at >= ? GROUP BY owner_id')
    .all(startOfToday());
  const doneMap = Object.fromEntries(doneToday.map((r) => [r.owner_id, r.c]));
  return {
    people: people.map((p) => {
      const mine = open.filter((t) => t.owner_id === p.id);
      const visible = mine.filter((t) => !t.private)
        // Short note goes on the board/TV. The long details text is never included here, only whether it exists.
        .map((t) => ({ id: t.id, title: t.title, note: t.note, has_details: !!t.has_details, priority: t.priority, flag: t.flag, flag_text: t.flag_text }));
      return { id: p.id, name: p.name, tasks: visible, private_count: mine.length - visible.length, done_today: doneMap[p.id] || 0 };
    }),
    attention: open.filter((t) => !t.private && t.flag && people.some((p) => p.id === t.owner_id)).length,
    updated: Date.now(),
  };
}
function startOfToday() {
  const d = new Date(); d.setHours(0, 0, 0, 0); return d.getTime();
}
const taskRow = (t) => ({ id: t.id, title: t.title, note: t.note, details: t.details, priority: t.priority, flag: t.flag, flag_text: t.flag_text, private: !!t.private, done: !!t.done });

// ---------- static ----------
const PUB = path.join(__dirname, 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png' };
function serveStatic(res, file) {
  const p = path.join(PUB, file);
  if (!p.startsWith(PUB) || !fs.existsSync(p)) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(p)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
  fs.createReadStream(p).pipe(res);
}

// ---------- routes ----------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const route = `${req.method} ${url.pathname}`;
  try {
    // pages
    if (route === 'GET /') return serveStatic(res, 'app.html');
    if (route === 'GET /tv') {
      if (url.searchParams.get('key') !== TV_KEY) { res.writeHead(403); return res.end('TV key required: /tv?key=...'); }
      return serveStatic(res, 'tv.html');
    }
    if (req.method === 'GET' && /^\/[\w.-]+\.(css|js|svg|png|json)$/.test(url.pathname)) return serveStatic(res, url.pathname.slice(1));

    // TV board data (needs the TV key; contains no private info)
    if (route === 'GET /api/tv') {
      if (url.searchParams.get('key') !== TV_KEY) return json(res, 403, { error: 'key' });
      return json(res, 200, boardData());
    }

    // login screen needs names only
    if (route === 'GET /api/people') {
      return json(res, 200, db.prepare('SELECT id, name FROM users WHERE active=1 ORDER BY name').all());
    }
    if (route === 'POST /api/login') {
      const { user_id, pin } = await readBody(req);
      const key = `${req.socket.remoteAddress}|${user_id}`;
      if (throttled(key)) return json(res, 429, { error: 'Too many tries. Wait 5 minutes.' });
      const u = db.prepare('SELECT * FROM users WHERE id=? AND active=1').get(Number(user_id));
      const ok = u && crypto.timingSafeEqual(Buffer.from(hashPin(pin ?? '', u.pin_salt)), Buffer.from(u.pin_hash));
      if (!ok) { noteFail(key); return json(res, 401, { error: 'Wrong PIN' }); }
      res.setHeader('Set-Cookie', `sess=${makeCookie(u.id)}; ${cookieFlags()}`);
      return json(res, 200, publicUser(u));
    }
    if (route === 'POST /api/logout') {
      res.setHeader('Set-Cookie', 'sess=; Path=/; Max-Age=0');
      return json(res, 200, {});
    }

    // everything below needs a signed-in person
    const me = readSession(req);
    if (!me) return json(res, 401, { error: 'login' });

    if (route === 'GET /api/me') return json(res, 200, publicUser(me));

    // shop board: same data as the TV, plus nothing private
    if (route === 'GET /api/board') return json(res, 200, boardData());

    // long details (cut lists etc.): the owner, or any signed-in coworker when the task is shared. Never on the TV.
    {
      const dm = /^\/api\/tasks\/(\d+)\/details$/.exec(url.pathname);
      if (dm && req.method === 'GET') {
        const t = db.prepare('SELECT t.details, t.owner_id, t.private, u.hide_from_board h FROM tasks t JOIN users u ON u.id=t.owner_id WHERE t.id=?').get(Number(dm[1]));
        if (!t || (t.owner_id !== me.id && (t.private || t.h))) return json(res, 404, { error: 'Not found' });
        return json(res, 200, { details: t.details });
      }
    }

    // my list
    if (route === 'GET /api/tasks') {
      const rows = db.prepare('SELECT * FROM tasks WHERE owner_id=? AND (done=0 OR done_at >= ?) ORDER BY done, (flag!=\'\') DESC, priority DESC, id')
        .all(me.id, Date.now() - 24 * 3600 * 1000);
      return json(res, 200, rows.map(taskRow));
    }
    if (route === 'POST /api/tasks') {
      const b = await readBody(req);
      const title = clean(b.title, 200);
      if (!title) return json(res, 400, { error: 'Title required' });
      const priv = me.hide_from_board ? 1 : (me.is_admin && b.private ? 1 : 0);
      const flag = flagOf(b.flag);
      const id = db.prepare('INSERT INTO tasks (owner_id, title, note, details, priority, flag, flag_text, private, created_at) VALUES (?,?,?,?,?,?,?,?,?)')
        .run(me.id, title, clean(b.note, 120), clean(b.details, 5000), b.priority === undefined ? 1 : prio(b.priority), flag, flag ? clean(b.flag_text, 200) : '', priv, Date.now()).lastInsertRowid;
      return json(res, 200, taskRow(db.prepare('SELECT * FROM tasks WHERE id=?').get(id)));
    }
    let m;
    if ((m = /^\/api\/tasks\/(\d+)$/.exec(url.pathname))) {
      const t = db.prepare('SELECT * FROM tasks WHERE id=? AND owner_id=?').get(Number(m[1]), me.id);
      if (!t) return json(res, 404, { error: 'Not found' }); // not yours = does not exist
      if (req.method === 'PATCH') {
        const b = await readBody(req);
        const next = {
          title: b.title !== undefined ? clean(b.title, 200) || t.title : t.title,
          note: b.note !== undefined ? clean(b.note, 120) : t.note,
          details: b.details !== undefined ? clean(b.details, 5000) : t.details,
          priority: b.priority !== undefined ? prio(b.priority) : t.priority,
          flag: b.flag !== undefined ? flagOf(b.flag) : t.flag,
          flag_text: b.flag_text !== undefined ? clean(b.flag_text, 200) : t.flag_text,
          private: me.hide_from_board ? 1 : (me.is_admin && b.private !== undefined ? (b.private ? 1 : 0) : (me.is_admin ? t.private : 0)),
          done: b.done !== undefined ? (b.done ? 1 : 0) : t.done,
        };
        if (next.done) next.flag = '';          // finishing a task clears its flag
        if (!next.flag) next.flag_text = '';
        const doneAt = next.done ? (t.done ? t.done_at : Date.now()) : null;
        db.prepare('UPDATE tasks SET title=?, note=?, details=?, priority=?, flag=?, flag_text=?, private=?, done=?, done_at=? WHERE id=?')
          .run(next.title, next.note, next.details, next.priority, next.flag, next.flag_text, next.private, next.done, doneAt, t.id);
        return json(res, 200, taskRow(db.prepare('SELECT * FROM tasks WHERE id=?').get(t.id)));
      }
      if (req.method === 'DELETE') {
        db.prepare('DELETE FROM tasks WHERE id=?').run(t.id);
        return json(res, 200, {});
      }
    }

    // my settings
    if (route === 'POST /api/me/pin') {
      const { pin } = await readBody(req);
      if (!/^\d{4,8}$/.test(String(pin))) return json(res, 400, { error: 'PIN must be 4-8 digits' });
      const salt = crypto.randomBytes(16).toString('hex');
      db.prepare('UPDATE users SET pin_salt=?, pin_hash=? WHERE id=?').run(salt, hashPin(pin, salt), me.id);
      return json(res, 200, {});
    }
    if (route === 'POST /api/me/hide') {
      if (!me.is_admin) return json(res, 403, { error: 'Only the owner account can hide a list' });
      const { hide } = await readBody(req);
      db.prepare('UPDATE users SET hide_from_board=? WHERE id=?').run(hide ? 1 : 0, me.id);
      if (hide) db.prepare('UPDATE tasks SET private=1 WHERE owner_id=?').run(me.id);
      return json(res, 200, {});
    }

    // managers (and the admin) clear attention flags on tasks that are visible on the board, never on private ones
    {
      const rm = /^\/api\/tasks\/(\d+)\/resolve$/.exec(url.pathname);
      if (rm && req.method === 'POST') {
        if (!(me.is_manager || me.is_admin)) return json(res, 403, { error: 'Managers only' });
        const r = db.prepare("UPDATE tasks SET flag='', flag_text='' WHERE id=? AND private=0").run(Number(rm[1]));
        return json(res, r.changes ? 200 : 404, r.changes ? {} : { error: 'Not found' });
      }
    }

    // admin: manage people
    if (url.pathname.startsWith('/api/admin/')) {
      if (!me.is_admin) return json(res, 403, { error: 'Admin only' });
      if (route === 'GET /api/admin/users') {
        return json(res, 200, db.prepare('SELECT id, name, is_admin, is_manager, hide_from_board, active FROM users ORDER BY name').all());
      }
      if (route === 'POST /api/admin/users') {
        const b = await readBody(req);
        const name = clean(b.name, 40);
        if (!name || !/^\d{4,8}$/.test(String(b.pin))) return json(res, 400, { error: 'Name and a 4-8 digit PIN required' });
        try { createUser(name, b.pin); } catch { return json(res, 409, { error: 'That name is taken' }); }
        return json(res, 200, {});
      }
      if ((m = /^\/api\/admin\/users\/(\d+)$/.exec(url.pathname)) && req.method === 'PATCH') {
        const b = await readBody(req);
        const id = Number(m[1]);
        if (b.pin !== undefined) {
          if (!/^\d{4,8}$/.test(String(b.pin))) return json(res, 400, { error: 'PIN must be 4-8 digits' });
          const salt = crypto.randomBytes(16).toString('hex');
          db.prepare('UPDATE users SET pin_salt=?, pin_hash=? WHERE id=?').run(salt, hashPin(b.pin, salt), id);
        }
        if (b.manager !== undefined) db.prepare('UPDATE users SET is_manager=? WHERE id=?').run(b.manager ? 1 : 0, id);
        if (b.active !== undefined && id !== me.id) db.prepare('UPDATE users SET active=? WHERE id=?').run(b.active ? 1 : 0, id);
        return json(res, 200, {});
      }
    }

    json(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error(e);
    json(res, 500, { error: 'Server error' });
  }
});

server.listen(PORT, () => {
  console.log(`Shop to-do running on :${PORT}`);
  console.log(`TV board address: /tv?key=${TV_KEY}`);
});
