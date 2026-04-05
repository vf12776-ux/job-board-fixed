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

// ========== ИНИЦИАЛИЗАЦИЯ ТАБЛИЦ ==========
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'candidate',
    city TEXT DEFAULT '',
    phone TEXT DEFAULT ''
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    description TEXT,
    category TEXT DEFAULT 'other',
    city TEXT DEFAULT '',
    employerId INTEGER,
    createdAt TEXT,
    status TEXT DEFAULT 'open',
    assignedTo INTEGER,
    price INTEGER DEFAULT 0,
    paymentStatus TEXT DEFAULT 'pending'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    jobId INTEGER,
    candidateId INTEGER,
    createdAt TEXT,
    status TEXT DEFAULT 'pending'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    jobId INTEGER,
    senderId INTEGER,
    message TEXT,
    createdAt TEXT,
    isRead INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER UNIQUE,
    reason TEXT,
    bannedAt TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS general_chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    message TEXT,
    createdAt TEXT
  )`);

  // Миграции для существующих БД
  db.run("ALTER TABLE jobs ADD COLUMN assignedTo INTEGER", (err) => {
    if (err && !err.message.includes('duplicate column name')) console.log(err);
  });
  db.run("ALTER TABLE jobs ADD COLUMN price INTEGER DEFAULT 0", (err) => {
    if (err && !err.message.includes('duplicate column name')) console.log(err);
  });
  db.run("ALTER TABLE jobs ADD COLUMN paymentStatus TEXT DEFAULT 'pending'", (err) => {
    if (err && !err.message.includes('duplicate column name')) console.log(err);
  });
  db.run("ALTER TABLE users ADD COLUMN phone TEXT DEFAULT ''", (err) => {
    if (err && !err.message.includes('duplicate column name')) console.log(err);
  });
  db.run("ALTER TABLE users ADD COLUMN name TEXT DEFAULT ''", (err) => {
  if (err && !err.message.includes('duplicate column name')) console.log(err);
});

  // Создание админа
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

// ========== MIDDLEWARE ==========
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

const checkBanned = (req, res, next) => {
  if (!req.user) return next();
  db.get('SELECT * FROM blacklist WHERE userId = ?', [req.user.id], (err, banned) => {
    if (banned) return res.status(403).json({ error: 'You are banned. Contact admin.' });
    next();
  });
};

// ========== ПОЛЬЗОВАТЕЛИ ==========
app.post('/api/register', (req, res) => {
  const { email, password, role, city, phone } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Требуются email и пароль' });
  const hashed = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users (email, password, role, city, phone) VALUES (?, ?, ?, ?, ?)',
    [email, hashed, role || 'candidate', city || '', phone || ''], function(err) {
      if (err) return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
      res.json({ id: this.lastID, email, role: role || 'candidate', city: city || '', phone: phone || '' });
    });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET);
    res.json({ token, user: { id: user.id, email: user.email, role: user.role, city: user.city, phone: user.phone } });
  });
});

app.get('/api/me', auth, (req, res) => {
  db.get('SELECT id, email, role, city, phone FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'Пользователь не найден' });
    db.get('SELECT * FROM blacklist WHERE userId = ?', [user.id], (err, banned) => {
      res.json({
        id: user.id,
        email: user.email,
        role: user.role,
        city: user.city,
        phone: user.phone,
        banned: !!banned
      });
    });
  });
});

app.get('/api/users', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Доступ запрещён' });
  db.all('SELECT id, email, role, city, phone FROM users', (err, rows) => {
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

// ========== ЗАЯВКИ ==========
app.post('/api/jobs', auth, checkBanned, (req, res) => {
  if (req.user.role !== 'employer' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { title, description, category, city, price } = req.body;
  const jobPrice = parseInt(price) || 0;
  db.run(`INSERT INTO jobs (title, description, category, city, employerId, createdAt, status, price, paymentStatus) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [title, description, category || 'other', city || '', req.user.id, new Date().toISOString(), 'open', jobPrice, 'pending'], 
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, title, description, category, city, price: jobPrice, paymentStatus: 'pending' });
    });
});

app.get('/api/jobs', (req, res) => {
  const { city, all } = req.query;
  const token = req.headers.authorization?.split(' ')[1];
  let userId = null;
  let userRole = null;
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      userId = decoded.id;
      userRole = decoded.role;
    } catch(e) {}
  }

  // Если работодатель и нет флага all=true – показываем только его заявки
  if (userRole === 'employer' && all !== 'true') {
    let sql = 'SELECT * FROM jobs WHERE employerId = ?';
    let params = [userId];
    // Дополнительный фильтр по городу, если передан
    if (city && city !== 'all') {
      sql += ' AND city = ?';
      params.push(city);
    }
    sql += ' ORDER BY createdAt DESC';
    db.all(sql, params, (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
    return;
  }

  // Для кандидатов и админов (или если all=true) – логика с городом по умолчанию
  function buildQuery(cityParam, userCity) {
    let sql = 'SELECT * FROM jobs';
    let params = [];
    let conditions = [];

    if (cityParam && cityParam !== 'all') {
      conditions.push('city = ?');
      params.push(cityParam);
    } else if (!cityParam && userCity && userRole !== 'employer') {
      // Для кандидатов и админов – по умолчанию заявки из их города
      conditions.push('city = ?');
      params.push(userCity);
    }
    // Если cityParam === 'all' – не добавляем фильтр

    if (conditions.length) {
      sql += ' WHERE ' + conditions.join(' AND ');
    }
    sql += ' ORDER BY createdAt DESC';
    db.all(sql, params, (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  }

  if (userId) {
    db.get('SELECT city FROM users WHERE id = ?', [userId], (err, user) => {
      if (err) return res.status(500).json({ error: err.message });
      const userCity = user ? user.city : null;
      buildQuery(city, userCity);
    });
  } else {
    buildQuery(city, null);
  }
});

  function buildQuery(cityParam, userCity) {
    let sql = 'SELECT * FROM jobs';
    let params = [];
    let conditions = [];

    if (cityParam && cityParam !== 'all') {
      // Если передан конкретный город — фильтруем по нему
      conditions.push('city = ?');
      params.push(cityParam);
    } else if (!cityParam && userCity) {
      // Если параметр city не передан и пользователь авторизован — фильтруем по его городу
      conditions.push('city = ?');
      params.push(userCity);
    }
    // Если cityParam === 'all' — не добавляем фильтр (показываем все города)

    if (conditions.length) {
      sql += ' WHERE ' + conditions.join(' AND ');
    }
    sql += ' ORDER BY createdAt DESC';

    db.all(sql, params, (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  }

app.get('/api/my-jobs', auth, (req, res) => {
  db.all('SELECT * FROM jobs WHERE employerId = ? ORDER BY createdAt DESC', [req.user.id], (err, rows) => {
    res.json(rows);
  });
});

app.delete('/api/jobs/:id', auth, (req, res) => {
  db.get('SELECT employerId FROM jobs WHERE id = ?', [req.params.id], (err, job) => {
    if (!job) return res.status(404).json({ error: 'Заявка не найдена' });
    if (req.user.role !== 'admin' && job.employerId !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    db.run('DELETE FROM jobs WHERE id = ?', req.params.id, function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ deleted: req.params.id });
    });
  });
});

app.put('/api/jobs/:jobId/assign', auth, (req, res) => {
  const { candidateId } = req.body;
  const jobId = req.params.jobId;
  db.get('SELECT employerId, status FROM jobs WHERE id = ?', [jobId], (err, job) => {
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.employerId !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (job.status !== 'open') return res.status(400).json({ error: 'Заявка уже взята в работу или завершена' });
    db.run('UPDATE jobs SET assignedTo = ?, status = ? WHERE id = ?', [candidateId, 'taken', jobId], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    });
  });
});

// ========== ОТКЛИКИ ==========
app.post('/api/responses', auth, checkBanned, (req, res) => {
  if (req.user.role !== 'candidate') {
    return res.status(403).json({ error: 'Только исполнители могут откликаться' });
  }
  const { jobId } = req.body;
  if (!jobId) return res.status(400).json({ error: 'Требуется идентификатор заявки' });

  db.serialize(() => {
    db.run('BEGIN IMMEDIATE');

    db.get('SELECT * FROM jobs WHERE id = ?', [jobId], (err, job) => {
      if (err || !job) {
        db.run('ROLLBACK');
        return res.status(404).json({ error: 'Заявка не найдена' });
      }
      if (job.employerId === req.user.id) {
        db.run('ROLLBACK');
        return res.status(400).json({ error: 'Нельзя откликаться на свою заявку' });
      }
      if (job.status !== 'open') {
        db.run('ROLLBACK');
        return res.status(400).json({ error: 'Заявка уже взята в работу или завершена' });
      }

      db.get('SELECT id FROM responses WHERE jobId = ? AND candidateId = ?', [jobId, req.user.id], (err, existing) => {
        if (existing) {
          db.run('ROLLBACK');
          return res.status(400).json({ error: 'Вы уже откликались на эту заявку. Хорош!' });
        }

        db.get('SELECT COUNT(*) as count FROM responses WHERE jobId = ?', [jobId], (err, countResult) => {
          const isFirst = (countResult.count === 0);

          db.run('INSERT INTO responses (jobId, candidateId, createdAt, status) VALUES (?, ?, ?, ?)',
            [jobId, req.user.id, new Date().toISOString(), 'pending'],
            function(err) {
              if (err) {
                db.run('ROLLBACK');
                return res.status(500).json({ error: err.message });
              }

              if (isFirst) {
                db.run('UPDATE jobs SET status = ?, assignedTo = ? WHERE id = ?',
                  ['taken', req.user.id, jobId],
                  (err) => {
                    if (err) {
                      db.run('ROLLBACK');
                      return res.status(500).json({ error: err.message });
                    }
                    db.run('COMMIT');
                    res.json({
                      id: this.lastID,
                      jobId,
                      candidateId: req.user.id,
                      autoAssigned: true,
                      message: 'Вы первый откликнувшийся! Заявка закреплена за вами.'
                    });
                  });
              } else {
                db.run('COMMIT');
                res.json({
                  id: this.lastID,
                  jobId,
                  candidateId: req.user.id,
                  autoAssigned: false,
                  message: 'Отклик отправлен, но заявка уже в работе. Вы в списке ожидания.'
                });
              }
            });
        });
      });
    });
  });
});

app.get('/api/responses/by-job/:jobId', auth, (req, res) => {
  const jobId = req.params.jobId;
  db.get('SELECT employerId FROM jobs WHERE id = ?', [jobId], (err, job) => {
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (req.user.role !== 'admin' && job.employerId !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    db.all(`
      SELECT r.*, u.email as candidateEmail 
      FROM responses r
      JOIN users u ON r.candidateId = u.id
      WHERE r.jobId = ?
      ORDER BY r.createdAt ASC
    `, [jobId], (err, rows) => {
      res.json(rows);
    });
  });
});

app.get('/api/my-responses', auth, (req, res) => {
  if (req.user.role !== 'candidate') return res.status(403).json({ error: 'Forbidden' });
  db.all(`
    SELECT r.*, j.title as jobTitle, j.description, j.city, j.status, j.assignedTo, j.employerId, j.id as jobId
    FROM responses r
    JOIN jobs j ON r.jobId = j.id
    WHERE r.candidateId = ?
    ORDER BY r.createdAt DESC
  `, [req.user.id], (err, rows) => {
    res.json(rows);
  });
});

// ========== ЧАТ ==========
app.get('/api/messages/:jobId', auth, (req, res) => {
  const jobId = req.params.jobId;
  db.get('SELECT employerId, assignedTo FROM jobs WHERE id = ?', [jobId], (err, job) => {
    if (!job) return res.status(404).json({ error: 'Заявка не найдена' });
    const isParticipant = (req.user.id === job.employerId || req.user.id === job.assignedTo);
    if (!isParticipant && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Доступ запрещен' });
    }
    db.all('SELECT * FROM messages WHERE jobId = ? ORDER BY createdAt ASC', [jobId], (err, rows) => {
      res.json(rows);
    });
  });
});

app.post('/api/messages', auth, (req, res) => {
  const { jobId, message } = req.body;
  if (!message || !jobId) return res.status(400).json({ error: 'Missing fields' });
  db.get('SELECT employerId, assignedTo FROM jobs WHERE id = ?', [jobId], (err, job) => {
    if (!job) return res.status(404).json({ error: 'Job not found' });
    const isParticipant = (req.user.id === job.employerId || req.user.id === job.assignedTo);
    if (!isParticipant && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    db.run('INSERT INTO messages (jobId, senderId, message, createdAt) VALUES (?, ?, ?, ?)',
      [jobId, req.user.id, message, new Date().toISOString()], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, jobId, senderId: req.user.id, message, createdAt: new Date().toISOString() });
    });
  });
});

// ========== ОБЩИЙ ЧАТ ИСПОЛНИТЕЛЕЙ (пункт 4) ==========
app.get('/api/general-chat/messages', auth, (req, res) => {
  db.all('SELECT * FROM general_chat_messages ORDER BY createdAt ASC', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/general-chat/messages', auth, (req, res) => {
  if (req.user.role !== 'candidate' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Только исполнители могут писать в общий чат' });
  }
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });
  db.run('INSERT INTO general_chat_messages (userId, message, createdAt) VALUES (?, ?, ?)',
    [req.user.id, message, new Date().toISOString()], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, userId: req.user.id, message, createdAt: new Date().toISOString() });
    });
});

// ========== ЧЁРНЫЙ СПИСОК ==========
app.get('/api/blacklist', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Доступ запрещен' });
  db.all(`
    SELECT b.userId, u.email, u.role, b.reason, b.bannedAt
    FROM blacklist b
    JOIN users u ON b.userId = u.id
  `, (err, rows) => {
    res.json(rows);
  });
});

app.post('/api/blacklist', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Доступ запрещен' });
  const { userId, reason } = req.body;
  db.run('INSERT OR REPLACE INTO blacklist (userId, reason, bannedAt) VALUES (?, ?, ?)',
    [userId, reason || 'No reason', new Date().toISOString()], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, userId });
    });
});

app.delete('/api/blacklist/:userId', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Доступ запрещен' });
  db.run('DELETE FROM blacklist WHERE userId = ?', [req.params.userId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ========== СИМУЛЯЦИЯ ОПЛАТЫ ==========
app.post('/api/pay/:jobId', auth, (req, res) => {
  const jobId = req.params.jobId;
  db.get('SELECT employerId, paymentStatus, price FROM jobs WHERE id = ?', [jobId], (err, job) => {
    if (!job) return res.status(404).json({ error: 'Заявка не найдена' });
    if (job.employerId !== req.user.id) return res.status(403).json({ error: 'Не твоя заявка' });
    if (job.paymentStatus !== 'pending') return res.status(400).json({ error: 'Уже оплачено' });
    if (job.price <= 0) return res.status(400).json({ error: 'Неверная цена' });
    
    db.run('UPDATE jobs SET paymentStatus = ? WHERE id = ?', ['paid', jobId], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, message: 'Оплата прошла успешно (симуляция)', jobId });
    });
  });
});
app.put('/api/users/profile', auth, (req, res) => {
  const { name, phone, city } = req.body;
  const userId = req.user.id;
  db.run('UPDATE users SET name = ?, phone = ?, city = ? WHERE id = ?',
    [name || '', phone || '', city || '', userId],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, user: { id: userId, name, phone, city } });
    });
});

// ========== СТАТИЧЕСКИЕ ФАЙЛЫ ==========
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});
app.use(express.static(__dirname));

// ========== ЗАПУСК ==========
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});