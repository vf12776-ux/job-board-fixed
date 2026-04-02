const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'supersecretkey';

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./database.db');

// ==================== ИНИЦИАЛИЗАЦИЯ БД (расширенная) ====================
db.serialize(() => {
  // Таблица пользователей (добавлен город)
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'candidate',
    city TEXT DEFAULT ''
  )`);

  // Таблица заявок (добавлена категория)
  db.run(`CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    description TEXT,
    category TEXT DEFAULT 'other',
    city TEXT DEFAULT '',
    employerId INTEGER,
    createdAt TEXT,
    status TEXT DEFAULT 'open'   -- open, taken, completed
  )`);

  // Таблица откликов (новая)
  db.run(`CREATE TABLE IF NOT EXISTS responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    jobId INTEGER,
    candidateId INTEGER,
    createdAt TEXT,
    status TEXT DEFAULT 'pending'   -- pending, accepted, rejected
  )`);

  // Таблица чатов (для будущего этапа, пока заглушка)
  db.run(`CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    responseId INTEGER,
    senderId INTEGER,
    message TEXT,
    createdAt TEXT
  )`);

  // Чёрный список (пока просто таблица)
  db.run(`CREATE TABLE IF NOT EXISTS blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    reason TEXT,
    bannedAt TEXT
  )`);

  // Создание админа (без города)
  const adminEmail = 'admin@example.com';
  const adminPass = 'admin123';
  db.get('SELECT * FROM users WHERE email = ?', [adminEmail], (err, row) => {
    if (!row) {
      const hashed = bcrypt.hashSync(adminPass, 10);
      db.run('INSERT INTO users (email, password, role, city) VALUES (?, ?, ?, ?)', [adminEmail, hashed, 'admin', '']);
      console.log('Admin created: admin@example.com / admin123');
    }
  });
});

// ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ==================== API ПОЛЬЗОВАТЕЛЕЙ ====================
app.post('/api/register', (req, res) => {
  const { email, password, role, city } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const hashed = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users (email, password, role, city) VALUES (?, ?, ?, ?)', 
    [email, hashed, role || 'candidate', city || ''], function(err) {
    if (err) return res.status(400).json({ error: 'User already exists' });
    res.json({ id: this.lastID, email, role: role || 'candidate', city: city || '' });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET);
    res.json({ token, user: { id: user.id, email: user.email, role: user.role, city: user.city } });
  });
});

// Получить всех пользователей (для админа)
app.get('/api/users', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  db.all('SELECT id, email, role, city FROM users', (err, rows) => {
    res.json(rows);
  });
});

// Обновить роль (админ)
app.put('/api/users/:id/role', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const { role } = req.body;
  db.run('UPDATE users SET role = ? WHERE id = ?', [role, req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ updated: req.params.id, role });
  });
});

// ==================== API ЗАЯВОК ====================
// Создать заявку (employer или admin)
app.post('/api/jobs', auth, (req, res) => {
  if (req.user.role !== 'employer' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { title, description, category, city } = req.body;
  db.run(`INSERT INTO jobs (title, description, category, city, employerId, createdAt, status) 
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [title, description, category || 'other', city || '', req.user.id, new Date().toISOString(), 'open'], 
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, title, description, category, city });
    });
});

// Получить все заявки (с возможностью фильтра по городу)
app.get('/api/jobs', (req, res) => {
  const { city } = req.query;
  let sql = 'SELECT * FROM jobs ORDER BY createdAt DESC';
  let params = [];
  if (city && city !== 'all') {
    sql = 'SELECT * FROM jobs WHERE city = ? ORDER BY createdAt DESC';
    params = [city];
  }
  db.all(sql, params, (err, rows) => {
    res.json(rows);
  });
});

// Получить заявки текущего пользователя (для "Мои заявки")
app.get('/api/my-jobs', auth, (req, res) => {
  db.all('SELECT * FROM jobs WHERE employerId = ? ORDER BY createdAt DESC', [req.user.id], (err, rows) => {
    res.json(rows);
  });
});

// Удалить заявку (только админ или владелец)
app.delete('/api/jobs/:id', auth, (req, res) => {
  db.get('SELECT employerId FROM jobs WHERE id = ?', [req.params.id], (err, job) => {
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (req.user.role !== 'admin' && job.employerId !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    db.run('DELETE FROM jobs WHERE id = ?', req.params.id, function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ deleted: req.params.id });
    });
  });
});

// ==================== API ОТКЛИКОВ ====================
// Откликнуться на заявку (только кандидат)
app.post('/api/responses', auth, (req, res) => {
  if (req.user.role !== 'candidate') return res.status(403).json({ error: 'Only candidates can respond' });
  const { jobId } = req.body;
  // Проверяем, не откликался ли уже
  db.get('SELECT * FROM responses WHERE jobId = ? AND candidateId = ?', [jobId, req.user.id], (err, existing) => {
    if (existing) return res.status(400).json({ error: 'Already responded' });
    db.run('INSERT INTO responses (jobId, candidateId, createdAt, status) VALUES (?, ?, ?, ?)',
      [jobId, req.user.id, new Date().toISOString(), 'pending'], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, jobId, candidateId: req.user.id });
      });
  });
});

// Получить отклики для заявок текущего работодателя (или для админа)
app.get('/api/responses/for-employer', auth, (req, res) => {
  if (req.user.role !== 'employer' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  let sql = `
    SELECT r.*, j.title as jobTitle, u.email as candidateEmail 
    FROM responses r
    JOIN jobs j ON r.jobId = j.id
    JOIN users u ON r.candidateId = u.id
    WHERE j.employerId = ?
    ORDER BY r.createdAt DESC
  `;
  let params = [req.user.id];
  if (req.user.role === 'admin') {
    sql = `
      SELECT r.*, j.title as jobTitle, u.email as candidateEmail 
      FROM responses r
      JOIN jobs j ON r.jobId = j.id
      JOIN users u ON r.candidateId = u.id
      ORDER BY r.createdAt DESC
    `;
    params = [];
  }
  db.all(sql, params, (err, rows) => {
    res.json(rows);
  });
});

// Получить отклики текущего кандидата
app.get('/api/my-responses', auth, (req, res) => {
  if (req.user.role !== 'candidate') return res.status(403).json({ error: 'Forbidden' });
  db.all(`
    SELECT r.*, j.title as jobTitle, j.description, j.city 
    FROM responses r
    JOIN jobs j ON r.jobId = j.id
    WHERE r.candidateId = ?
    ORDER BY r.createdAt DESC
  `, [req.user.id], (err, rows) => {
    res.json(rows);
  });
});

// ==================== ОБНОВЛЕНИЕ СТАТУСА ЗАЯВКИ (взять в работу) ====================
app.put('/api/jobs/:id/take', auth, (req, res) => {
  if (req.user.role !== 'candidate') return res.status(403).json({ error: 'Only candidates can take jobs' });
  // Проверяем, есть ли отклик
  db.get('SELECT * FROM responses WHERE jobId = ? AND candidateId = ?', [req.params.id, req.user.id], (err, response) => {
    if (!response) return res.status(400).json({ error: 'You must respond first' });
    db.run('UPDATE jobs SET status = ? WHERE id = ?', ['taken', req.params.id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ taken: req.params.id });
    });
  });
});

// ==================== СТАТИКА ====================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});
app.use(express.static(__dirname));

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});