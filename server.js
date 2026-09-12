const express = require('express');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'prc165.db');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let db;

function saveDB() {
  try {
    const data = db.export();
    fs.writeFileSync(DB_FILE, Buffer.from(data));
  } catch (e) {}
}

function run(sql, params) {
  params = params || [];
  db.run(sql, params);
  saveDB();
}

function get(sql, params) {
  params = params || [];
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

function all(sql, params) {
  params = params || [];
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function lastInsertId() {
  const r = get('SELECT last_insert_rowid() as id');
  return r ? r.id : null;
}

async function initDB() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_FILE)) {
    const buf = fs.readFileSync(DB_FILE);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'player',
      balance INTEGER DEFAULT 50000,
      wallet_balance INTEGER DEFAULT 0,
      total_bet INTEGER DEFAULT 0,
      total_win INTEGER DEFAULT 0,
      total_withdraw INTEGER DEFAULT 0,
      last_claim INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      game TEXT,
      win INTEGER,
      mult REAL,
      jackpot INTEGER DEFAULT 0,
      time TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS wallet_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT,
      amount INTEGER,
      desc TEXT,
      time TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      type TEXT,
      amount INTEGER,
      details TEXT,
      time TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS global_state (
      key TEXT PRIMARY KEY,
      value TEXT
    );
  `);

  saveDB();

  const jp = get("SELECT value FROM global_state WHERE key = 'jackpot'");
  if (!jp) run("INSERT INTO global_state (key, value) VALUES ('jackpot', '10000000')");

  const admin = get("SELECT id FROM users WHERE username = 'prc165'");
  if (!admin) {
    const hash = bcrypt.hashSync('prc165', 10);
    run("INSERT INTO users (username, password, role, balance) VALUES ('prc165', ?, 'bandar', 999999999)", [hash]);
  }

  console.log('[DB] Database siap');
}

function generateToken() {
  return 'tk_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
}

function getUserByToken(token) {
  return get("SELECT u.* FROM users u JOIN sessions s ON u.id = s.user_id WHERE s.token = ?", [token]);
}

function authMiddleware(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'No token' });
  const user = getUserByToken(token);
  if (!user) return res.status(401).json({ error: 'Invalid token' });
  req.user = user;
  next();
}

function addLog(userId, username, type, amount, details) {
  run("INSERT INTO logs (user_id, username, type, amount, details) VALUES (?, ?, ?, ?, ?)", [userId, username, type, amount, details]);
}

app.post('/api/register', (req, res) => {
  const body = req.body;
  const username = body.username;
  const password = body.password;
  const referral = body.referral;
  if (!username || !password) return res.status(400).json({ error: 'Isi semua field' });
  if (password.length < 3) return res.status(400).json({ error: 'Password min 3 karakter' });
  if (username.length < 3) return res.status(400).json({ error: 'Username min 3 karakter' });

  const existing = get("SELECT id FROM users WHERE username = ?", [username]);
  if (existing) return res.status(400).json({ error: 'Username sudah dipakai' });

  const hash = bcrypt.hashSync(password, 10);
  const bonus = referral ? 60000 : 50000;

  run("INSERT INTO users (username, password, balance) VALUES (?, ?, ?)", [username, hash, bonus]);
  const userId = lastInsertId();
  const token = generateToken();
  run("INSERT INTO sessions (token, user_id) VALUES (?, ?)", [token, userId]);
  addLog(userId, username, 'REGISTER', bonus, 'Registrasi baru');

  const user = get("SELECT id, username, role, balance, wallet_balance, total_bet, total_win, total_withdraw, last_claim FROM users WHERE id = ?", [userId]);
  res.json({ token, user });
});

app.post('/api/login', (req, res) => {
  const body = req.body;
  const username = body.username;
  const password = body.password;
  if (!username || !password) return res.status(400).json({ error: 'Isi semua field' });

  const user = get("SELECT * FROM users WHERE username = ?", [username]);
  if (!user) return res.status(400).json({ error: 'Akun tidak ditemukan' });
  if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: 'Password salah' });

  const token = generateToken();
  run("INSERT INTO sessions (token, user_id) VALUES (?, ?)", [token, user.id]);
  addLog(user.id, user.username, 'LOGIN', 0, 'Login');

  delete user.password;
  res.json({ token, user });
});

app.post('/api/logout', authMiddleware, (req, res) => {
  const token = req.headers['authorization'];
  run("DELETE FROM sessions WHERE token = ?", [token]);
  res.json({ success: true });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const u = req.user;
  delete u.password;
  res.json({ user: u });
});

app.get('/api/history', authMiddleware, (req, res) => {
  const history = all("SELECT * FROM history WHERE user_id = ? ORDER BY id DESC LIMIT 50", [req.user.id]);
  res.json({ history });
});

app.get('/api/wallet-history', authMiddleware, (req, res) => {
  const history = all("SELECT * FROM wallet_history WHERE user_id = ? ORDER BY id DESC LIMIT 50", [req.user.id]);
  res.json({ history });
});

app.post('/api/game/space/bet', authMiddleware, (req, res) => {
  const bet = req.body.bet;
  const u = req.user;
  if (!bet || bet < 2000) return res.status(400).json({ error: 'Min bet 2000' });
  if (bet > u.balance) return res.status(400).json({ error: 'Saldo tidak cukup' });

  const r = Math.random();
  let crashPoint;
  if (r < 0.55) crashPoint = 1.60 + Math.random() * 0.80;
  else if (r < 0.85) crashPoint = 2.40 + Math.random() * 2.00;
  else if (r < 0.96) crashPoint = 4.40 + Math.random() * 5.00;
  else crashPoint = 9 + Math.random() * 20;

  run("UPDATE users SET balance = balance - ?, total_bet = total_bet + ? WHERE id = ?", [bet, bet, u.id]);
  addLog(u.id, u.username, 'BET', -bet, 'Space bet');

  const row = get("SELECT balance FROM users WHERE id = ?", [u.id]);
  res.json({ balance: row.balance, crashPoint });
});

app.post('/api/game/space/cashout', authMiddleware, (req, res) => {
  const bet = req.body.bet;
  const mult = req.body.mult;
  const u = req.user;
  if (!bet || !mult) return res.status(400).json({ error: 'Invalid' });

  const win = Math.floor(bet * mult);
  const walletShare = Math.floor(win * 0.1 / 1000);

  run("UPDATE users SET balance = balance + ?, wallet_balance = wallet_balance + ?, total_win = total_win + ? WHERE id = ?", [win, walletShare, win, u.id]);
  run("INSERT INTO history (user_id, game, win, mult, jackpot) VALUES (?, 'Space', ?, ?, 0)", [u.id, win, mult]);
  if (walletShare > 0) {
    run("INSERT INTO wallet_history (user_id, type, amount, desc) VALUES (?, 'bonus', ?, 'Auto-convert 10% win')", [u.id, walletShare]);
  }
  addLog(u.id, u.username, 'CASHOUT', win, 'Space x' + mult.toFixed(2));

  const row = get("SELECT balance, wallet_balance FROM users WHERE id = ?", [u.id]);
  res.json({ balance: row.balance, wallet_balance: row.wallet_balance, win, walletShare });
});

app.post('/api/wallet/convert', authMiddleware, (req, res) => {
  const amount = req.body.amount;
  const u = req.user;
  if (!amount || amount < 1000) return res.status(400).json({ error: 'Min 1000' });
  if (amount > u.balance) return res.status(400).json({ error: 'Saldo tidak cukup' });

  const walletGain = Math.floor(amount / 1000);
  run("UPDATE users SET balance = balance - ?, wallet_balance = wallet_balance + ? WHERE id = ?", [amount, walletGain, u.id]);
  run("INSERT INTO wallet_history (user_id, type, amount, desc) VALUES (?, 'convert', ?, ?)", [u.id, walletGain, 'Konversi ' + amount + ' coin']);
  addLog(u.id, u.username, 'CONVERT', -amount, 'Ke ' + walletGain + ' WC');

  const row = get("SELECT balance, wallet_balance FROM users WHERE id = ?", [u.id]);
  res.json({ balance: row.balance, wallet_balance: row.wallet_balance, walletGain });
});

app.post('/api/wallet/withdraw', authMiddleware, (req, res) => {
  const amount = req.body.amount;
  const u = req.user;
  if (!amount || amount < 10) return res.status(400).json({ error: 'Min 10 WC' });
  if (amount > u.wallet_balance) return res.status(400).json({ error: 'Wallet tidak cukup' });

  run("UPDATE users SET wallet_balance = wallet_balance - ?, total_withdraw = total_withdraw + ? WHERE id = ?", [amount, amount, u.id]);
  run("INSERT INTO wallet_history (user_id, type, amount, desc) VALUES (?, 'withdraw', ?, ?)", [u.id, -amount, 'Withdraw ' + amount + ' WC']);
  addLog(u.id, u.username, 'WITHDRAW', -amount, 'Tarik ' + amount + ' WC');

  const row = get("SELECT balance, wallet_balance, total_withdraw FROM users WHERE id = ?", [u.id]);
  res.json(row);
});

app.post('/api/wallet/topup', authMiddleware, (req, res) => {
  const amount = req.body.amount;
  const u = req.user;
  if (!amount || amount < 10000) return res.status(400).json({ error: 'Min 10000' });

  const bonus = amount >= 100000 ? 0.1 : amount >= 50000 ? 0.05 : 0;
  const total = Math.floor(amount * (1 + bonus));

  run("UPDATE users SET balance = balance + ? WHERE id = ?", [total, u.id]);
  run("INSERT INTO wallet_history (user_id, type, amount, desc) VALUES (?, 'topup', ?, ?)", [u.id, total, 'Top up ' + amount]);
  addLog(u.id, u.username, 'TOPUP', total, 'Top up ' + amount);

  const row = get("SELECT balance, wallet_balance FROM users WHERE id = ?", [u.id]);
  res.json({ balance: row.balance, wallet_balance: row.wallet_balance, totalTopup: total, bonus });
});

app.get('/api/leaderboard', (req, res) => {
  const leaderboard = all("SELECT username, balance FROM users WHERE role = 'player' ORDER BY balance DESC LIMIT 20");
  res.json({ leaderboard });
});

app.get('/api/jackpot', (req, res) => {
  const row = get("SELECT value FROM global_state WHERE key = 'jackpot'");
  res.json({ jackpot: parseInt(row && row.value ? row.value : '10000000') });
});

app.post('/api/claim-bonus', authMiddleware, (req, res) => {
  const u = req.user;
  const now = Date.now();
  const last = u.last_claim || 0;
  if (now - last < 6 * 60 * 60 * 1000) {
    const sisa = Math.ceil((6 * 60 * 60 * 1000 - (now - last)) / 60000);
    return res.status(400).json({ error: 'Tunggu ' + sisa + ' menit lagi' });
  }

  run("UPDATE users SET balance = balance + 5000, last_claim = ? WHERE id = ?", [now, u.id]);
  addLog(u.id, u.username, 'BONUS', 5000, 'Bonus harian');

  const row = get("SELECT balance FROM users WHERE id = ?", [u.id]);
  res.json({ balance: row.balance, bonus: 5000 });
});

app.get('/api/admin/users', authMiddleware, (req, res) => {
  if (req.user.role !== 'bandar') return res.status(403).json({ error: 'Admin only' });
  const users = all("SELECT id, username, balance, wallet_balance, total_bet, total_win, role FROM users ORDER BY id DESC");
  res.json({ users });
});

app.post('/api/admin/topup', authMiddleware, (req, res) => {
  if (req.user.role !== 'bandar') return res.status(403).json({ error: 'Admin only' });
  const username = req.body.username;
  const amount = req.body.amount;
  if (!username || !amount) return res.status(400).json({ error: 'Invalid' });

  const user = get("SELECT id FROM users WHERE username = ?", [username]);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });

  run("UPDATE users SET balance = balance + ? WHERE username = ?", [amount, username]);
  addLog(req.user.id, username, 'ADMIN_TOPUP', amount, 'Admin top up');
  res.json({ success: true });
});

app.post('/api/admin/reset', authMiddleware, (req, res) => {
  if (req.user.role !== 'bandar') return res.status(403).json({ error: 'Admin only' });
  const username = req.body.username;
  run("UPDATE users SET balance = 50000 WHERE username = ?", [username]);
  res.json({ success: true });
});

app.post('/api/admin/delete', authMiddleware, (req, res) => {
  if (req.user.role !== 'bandar') return res.status(403).json({ error: 'Admin only' });
  const username = req.body.username;
  run("DELETE FROM users WHERE username = ?", [username]);
  res.json({ success: true });
});

app.get('/api/admin/logs', authMiddleware, (req, res) => {
  if (req.user.role !== 'bandar') return res.status(403).json({ error: 'Admin only' });
  const logs = all("SELECT * FROM logs ORDER BY id DESC LIMIT 100");
  res.json({ logs });
});

initDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log('=================================');
    console.log('  PRC165 SERVER RUNNING');
    console.log('=================================');
    console.log('  Port  : ' + PORT);
    console.log('  Admin : prc165 / prc165');
    console.log('=================================');
  });
}).catch(err => {
  console.error('DB Init error:', err);
  process.exit(1);
});
