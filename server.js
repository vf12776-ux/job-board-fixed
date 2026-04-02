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

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'candidate'
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    description TEXT,
    employerId INTEGER,
    createdAt TEXT
  )`);

  const adminEmail = 'admin@example.com';
  const adminPass = 'admin123';
  db.get('SELECT * FROM users WHERE email = ?', [adminEmail], (err, row) => {
    if (!row) {
      const hashed = bcrypt.hashSync(adminPass, 10);
      db.run('INSERT INTO users (email, password, role) VALUES (?, ?, ?)', [adminEmail, hashed, 'admin']);
      console.log('Admin created: admin@example.com / admin123');
    }
  });
});

app.post('/api/register', (req, res) => {
  const { email, password, role } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const hashed = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users (email, password, role) VALUES (?, ?, ?)', [email, hashed, role || 'candidate'], function(err) {
    if (err) return res.status(400).json({ error: 'User already exists' });
    res.json({ id: this.lastID, email, role: role || 'candidate' });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET);
    res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
  });
});

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

app.post('/api/jobs', auth, (req, res) => {
  if (req.user.role !== 'employer' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { title, description } = req.body;
  db.run('INSERT INTO jobs (title, description, employerId, createdAt) VALUES (?, ?, ?, ?)',
    [title, description, req.user.id, new Date().toISOString()], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID, title, description });
  });
});

app.get('/api/jobs', (req, res) => {
  db.all('SELECT * FROM jobs ORDER BY createdAt DESC', (err, rows) => {
    res.json(rows);
  });
});

app.delete('/api/jobs/:id', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  db.run('DELETE FROM jobs WHERE id = ?', req.params.id, function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: req.params.id });
  });
});

app.get('/api/users', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  db.all('SELECT id, email, role FROM users', (err, rows) => {
    res.json(rows);
  });
});

app.put('/api/users/:id/role', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const { role } = req.body;
  db.run('UPDATE users SET role = ? WHERE id = ?', [role, req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ updated: req.params.id, role });
  });
});

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