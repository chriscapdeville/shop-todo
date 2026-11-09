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
  if (!cols.includes('assigned_by')) db.exec("ALTER TABLE tasks ADD COLUMN assigned_by TEXT NOT NULL DEFAULT ''"); // who gave it, when not the owner
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
const taskRow = (t) => ({ id: t.id, title: t.title, assigned_by: t.assigned_by, note: t.note, details: t.details, priority: t.priority, flag: t.flag, flag_text: t.flag_text, private: !!t.private, done: !!t.done });

// ---------- static ----------
// Logo images are embedded so there are no extra files to upload.
const IMG_LOGO = Buffer.from('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', 'base64');
const IMG_MARK = Buffer.from('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', 'base64');
const IMG_ICON = Buffer.from('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5s0B4MaNG19++aWmaU888cSuXbvq1PGVZbuzygrqDQD/clFpQRAYP/bs2d2wYUNJkqdOndalS9f9+/dznMD2DSiKUsamVkYIQghrIWU0mjVNjY/f75ANYWFhe/fubdCgoaoqTqwpqJPj76w8McaEyB06dDx06GD//hEAcODAgWef7f7SSy/Fx+/TNCoIBoxFhFiBW5VRgRCiqqqqapRSnhcwFgXBkJ+fu2rVdx06dJg8eYogCISQcePG7dixw9PT0+k5+noDwL/vGSNErl279qZNm9esWTVjxqcXL15inXtat27dq1ev7t27+/s38/T0ut8D1m7cuHby5OmYmJjdu3enpKSUctXTp556CiEkSZLBIOhFaquw/GAV4l59dVBYWFh09LcrVqw8f/58QkJCQkLCtGnT6tb1bdiwUb16dWvU8LZYLISoRUWF16/fyMjISElJzsrKcezEf+aZziNHjnj//QlpaWlHjx4dOHAgz/MAyLmVB3RylIMVoiiSh4fHu+++N2LE8N2792zZsuXQoUNXr6ZlZFzLyLhWRnWGoKDAHj169OvXr337DgD0gw8+AABVZY4TzelKXydHufRqxJqmqapisVgjIvpHRPTPz889e/bc6dOnkpNT0tPTs7OzS0pKeJ63WMzVq3s3aFA/MDCoVauWAQEBrNGCpql2u91icavk0JpOjkqSHyy4f68Fh0fHjiEdO4Y8cCVLiMy+azZbvLy8AMBisejkeGwNVUqpphFKqapqCIGjW5TDGeroCsVagvxZlzGdHFB1HWKOdl3sYTu62v5WllCHm8uxJCl9pmvSQifH3+94zXEcayD6J+YB/V2jLZ4X/hBPIWz3RunuXa624Usnx0M1dmQPkucFh9OCEDkjIyMtLT09PSM19cqdO5l372bm5uZKkuRodSAIgtVqdXNz8/T0rFGjZt26vo0bN65bt27dunWNRpODWKxXIc8jVwtI6eQoixmKoiAEgmBkD/Lu3Ttnz55NSEg4fjzhwoXz165dLygo/KvDWiwWHx+f5s2bBwcHt2/ftmXLVrVr+zDKMRHyKFUedHJAJRT0YR5uUeQB4NKli3v37omNjTt27Jijky38mgQkeHpWq127trd3DU9Pz2rVPKxWq9lsZqYIIUp+fn5eXt7du1l37969ffvWnTuZRUVFly9fvnz58tatWwHA29v7qaeefO6553v06MEMEY5DqqpWfjFrnRxliwogRAEAQTAwOfHDD9s2bdp06NDhwsJCRymEBg0atmrVqlWrVkFBQU2b+vn4+Nhstj9aFX80MgoLC2/cuJGcnHLhwoVTp04mJZ1JTk7JzMyMidkdE7PbbDazkpuSJLP2lKyfnBOLEujk+E3GDaNFUlJidHT01q1b09Mz2KceHh7t27fv3r17aGhIQIC/1fq7JKZf165/3A9XqmA+b7N52Gwe/v6BvXr1BoDi4sKLFy8eOnR47969x48fu3XrTnFxMcdx69atLy4uGTx4MHOTMIepczxjldCMx9V66tyv+dKvPWwOHjwwYECkowaGwSD26PHs4sWLr15NLXWjGmucQ4jM+nD9WZed3/0KO1lRJFmWFEVicRmGGzeuf/ttdFhYGGvTxERU7969Y2J+dMytqiqPYacmlyWHphFJKmYXf/JkwosvDsD4V+1Qr169CRMmJCUlOu6OPdcyGi79jV9nYzL1wXDx4i8ffzzN39/f8fY+//xz+/b92ibMbi8mRNbJUQnMUNhTuXHj+rhxb5nNJvYwmjVrOnful3fu3HbclCSVlH5rK4imiiLJcgn70Zyc7CVLFj/xxBMOKfLqq/9KTr5MKZVliRCZEJ0cFdyqjVIaHb2ybt1fy6E0bNhg3ry5ubk57CNZtrPXurxExQP/VFUhRHb0iispKVq6dHFgYAC7PG/v6nPnzmGELi4u1MlR/n/3Zp+mpV3t1y/8nu/B/N5772ZmMmmhKYpUaYQoQ5AwIzcvL3f69I89PX/tX9y1a5czZ5KYS37evHmPcQNAcEYLBBAEw9atmzt27Lh16w8A0Llzp3379s2dO8/Ly0tRJE1TnV7Sjm3A1zRNkkrc3KxTpkw7fPgIa0r600/7OnXqtHTpYo6r8AaJ3D+HFrIs8zzmeTxp0sTIyAHXrl23WMyzZ38RFxfXunUbZuJhLJQOdoCzN/iz7GJC5GbNmm3dunXJksXe3tVzc/NGjhz9/vvvFxUVVeil4op2HrDsWqdPtKIoJpMlMzNz+PDh27ZtA4DmzZtHRUWFhITY7cWKIgsC1jQNIY1SQMglYmDsuVMKCCFFsWsaHTFiZEhIyPDhww8fPjJ37lwPDw+Oq8hKaxVqc0RFRVGXQUpKMisvbzQaR4wYQasypk6d5ubmxjQL84/t37+/3G0OXHGcQwgdPHjQzc1Nlp1ZYZJF2AsLi778cnZqairGuEWLFl26dFm1apVrNqN8YMoAz+MWLYJZG14WLoZyraFb4ZLDaR7fMmEwGDDGf6NhCrhkyhlLKWIv3ubNm+8tDF1YcrA3FWPs3KDRH7JvkKOVmKZpgiCwcvRVtzaEqqocx3Ecupd2xFUBg1TTNE3TZFl2/TXtY7EKAwACAJIklb9FXI7FyClVEeKysrKOHTtWXFysKIrFYhFFkdn/Tg/Hl74GV7ikR74dJElScXERz2NClE6dOvn6+lKqIcS7IjkANH3/rVNRzvNfvuTQ8VhBf8t16OTQoZNDh04OHTo5dOjk0KGTQ4dODh06OXTo5NChk0OHDp0cOnRy6NDJoUMnhw6dHDp0cujQyaFDJ4cOnRw6dHLo0KGTQ4dODh06OXTo5NChk0OHa+D/A9kdOx53hKLSAAAAAElFTkSuQmCC', 'base64');

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
    if (req.method === 'GET' && ['/logo.png', '/mark.png', '/icon.png'].includes(url.pathname)) {
      res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=86400' });
      return res.end({ '/logo.png': IMG_LOGO, '/mark.png': IMG_MARK, '/icon.png': IMG_ICON }[url.pathname]);
    }
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
      // "Everyone": one copy of the task on every active person's list (managers and the admin only).
      if (b.owner_id === 'all') {
        if (!(me.is_manager || me.is_admin)) return json(res, 403, { error: 'Only managers can add tasks for others' });
        const people = db.prepare('SELECT * FROM users WHERE active=1').all();
        const ins = db.prepare('INSERT INTO tasks (owner_id, title, note, details, priority, flag, flag_text, private, assigned_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)');
        const fl = flagOf(b.flag), now = Date.now();
        for (const u of people) {
          ins.run(u.id, title, clean(b.note, 120), clean(b.details, 5000), b.priority === undefined ? 1 : prio(b.priority), fl, fl ? clean(b.flag_text, 200) : '', u.hide_from_board ? 1 : 0, u.id === me.id ? '' : me.name, now);
        }
        return json(res, 200, { count: people.length });
      }
      // Managers and the admin can put a task on anyone's list; everyone else only their own.
      let owner = me;
      if (b.owner_id !== undefined && Number(b.owner_id) !== me.id) {
        if (!(me.is_manager || me.is_admin)) return json(res, 403, { error: 'Only managers can add tasks for others' });
        owner = db.prepare('SELECT * FROM users WHERE id=? AND active=1').get(Number(b.owner_id));
        if (!owner) return json(res, 404, { error: 'Person not found' });
      }
      const forSelf = owner.id === me.id;
      const priv = owner.hide_from_board ? 1 : (forSelf && me.is_admin && b.private ? 1 : 0);
      const flag = flagOf(b.flag);
      const id = db.prepare('INSERT INTO tasks (owner_id, title, note, details, priority, flag, flag_text, private, assigned_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)')
        .run(owner.id, title, clean(b.note, 120), clean(b.details, 5000), b.priority === undefined ? 1 : prio(b.priority), flag, flag ? clean(b.flag_text, 200) : '', priv, forSelf ? '' : me.name, Date.now()).lastInsertRowid;
      return json(res, 200, taskRow(db.prepare('SELECT * FROM tasks WHERE id=?').get(id)));
    }
    // tasks I (a manager) put on other people's lists that are still open
    if (route === 'GET /api/assigned') {
      if (!(me.is_manager || me.is_admin)) return json(res, 403, { error: 'Managers only' });
      const rows = db.prepare('SELECT t.*, u.name AS owner_name FROM tasks t JOIN users u ON u.id=t.owner_id WHERE t.assigned_by=? AND t.owner_id != ? AND t.done=0 ORDER BY u.name, t.id').all(me.name, me.id);
      return json(res, 200, rows.map((r) => ({ ...taskRow(r), owner_name: r.owner_name })));
    }
    let m;
    if ((m = /^\/api\/tasks\/(\d+)$/.exec(url.pathname))) {
      // The owner can always edit/delete. A manager can also edit/delete tasks they assigned to someone else.
      const canManage = (me.is_manager || me.is_admin) ? 1 : 0;
      const t = db.prepare("SELECT * FROM tasks WHERE id=? AND (owner_id=? OR (? = 1 AND assigned_by != '' AND assigned_by=?))").get(Number(m[1]), me.id, canManage, me.name);
      if (!t) return json(res, 404, { error: 'Not found' }); // not yours = does not exist
      if (req.method === 'PATCH') {
        const b = await readBody(req);
        // Privacy follows the task's OWNER: a hidden person's tasks stay private; only the owner account can toggle its own tasks.
        const ownerRow = db.prepare('SELECT hide_from_board FROM users WHERE id=?').get(t.owner_id);
        let privNext = t.private;
        if (ownerRow.hide_from_board) privNext = 1;
        else if (t.owner_id === me.id) privNext = me.is_admin && b.private !== undefined ? (b.private ? 1 : 0) : (me.is_admin ? t.private : 0);
        const next = {
          title: b.title !== undefined ? clean(b.title, 200) || t.title : t.title,
          note: b.note !== undefined ? clean(b.note, 120) : t.note,
          details: b.details !== undefined ? clean(b.details, 5000) : t.details,
          priority: b.priority !== undefined ? prio(b.priority) : t.priority,
          flag: b.flag !== undefined ? flagOf(b.flag) : t.flag,
          flag_text: b.flag_text !== undefined ? clean(b.flag_text, 200) : t.flag_text,
          private: privNext,
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
      // Managers and the admin can manage people. Managers can only touch regular accounts, never other managers or the owner.
      if (!(me.is_admin || me.is_manager)) return json(res, 403, { error: 'Managers only' });
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
        const target = db.prepare('SELECT is_admin, is_manager FROM users WHERE id=?').get(id);
        if (!target) return json(res, 404, { error: 'Not found' });
        if (!me.is_admin && (target.is_admin || target.is_manager || id === me.id)) return json(res, 403, { error: 'Only the owner can change a manager account' });
        if (b.manager !== undefined && !me.is_admin) return json(res, 403, { error: 'Only the owner can make or remove managers' });
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
