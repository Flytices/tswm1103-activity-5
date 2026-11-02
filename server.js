const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'pcu-campus-secret-key-2026';

app.use(cors());
app.use(express.json({ limit: '10kb' })); // Security: Prevent large payload attacks

// SECURITY CONTROL 1: Basic HTTP Security Headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// SECURITY CONTROL 2: Server-Side XSS Sanitization Helper
function sanitizeInput(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>]/g, '').trim();
}

const db = new sqlite3.Database('./campus.db', (err) => {
  if (err) console.error('Database connection error:', err.message);
  else console.log('Connected to SQLite database (campus.db).');
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student TEXT NOT NULL,
    department TEXT NOT NULL,
    date TEXT NOT NULL,
    status TEXT DEFAULT 'Pending',
    created_by TEXT
  )`);

  // PERFORMANCE OPTIMIZATION 1: Database Index on status and date columns
  db.run(`CREATE INDEX IF NOT EXISTS idx_appointments_status_date ON appointments(status, date)`);

  db.get(`SELECT COUNT(*) as count FROM users`, async (err, row) => {
    if (row && row.count === 0) {
      const adminHash = await bcrypt.hash('password123', 10);
      const studentHash = await bcrypt.hash('password123', 10);
      db.run(`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`, ['admin', adminHash, 'Admin']);
      db.run(`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`, ['student', studentHash, 'Student']);
    }
  });
});

// Request Logger with Execution Timer (Performance Measurement)
app.use((req, res, next) => {
  const start = process.hrtime();
  res.on('finish', () => {
    const diff = process.hrtime(start);
    const timeInMs = (diff[0] * 1e3 + diff[1] * 1e-6).toFixed(2);
    console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.url} - ${res.statusCode} (${timeInMs} ms)`);
  });
  next();
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ success: false, error: 'Authentication Required (401): Please sign in first.' });
  }
  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err) return res.status(403).json({ success: false, error: 'Invalid or Expired Token (403).' });
    req.user = decodedUser;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({
      success: false,
      error: `Authorization Denied (403): Role '${req.user.role}' cannot modify or delete records.`
    });
  }
  next();
}

// POST /api/auth/login (Parameterized Query prevents SQL Injection)
app.post('/api/auth/login', (req, res) => {
  const username = sanitizeInput(req.body.username);
  const password = req.body.password;

  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Username and password are required.' });
  }

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err) return res.status(500).json({ success: false, error: 'Database error occurred.' });
    if (!user) return res.status(401).json({ success: false, error: 'Invalid username or password.' });

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ success: false, error: 'Invalid username or password.' });

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '2h' });
    res.status(200).json({
      success: true,
      message: `Signed in as ${user.username} (${user.role})`,
      token,
      user: { username: user.username, role: user.role }
    });
  });
});

// PERFORMANCE OPTIMIZATION 2: Bounded Query with LIMIT & Indexed Filtering
app.get('/api/appointments', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  db.all(`SELECT id, student, department, date, status FROM appointments ORDER BY id DESC LIMIT ?`, [limit], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: 'Failed to retrieve appointments.' });
    res.status(200).json({ success: true, count: rows.length, data: rows });
  });
});

// POST /api/appointments (Sanitizes XSS tags + Parameterized SQL Insert)
app.post('/api/appointments', authenticateToken, (req, res) => {
  const cleanStudent = sanitizeInput(req.body.student);
  const cleanDepartment = sanitizeInput(req.body.department);
  const cleanDate = sanitizeInput(req.body.date);

  if (!cleanStudent || cleanStudent.length < 3 || !cleanDepartment || !cleanDate) {
    return res.status(400).json({
      success: false,
      error: 'Validation Error: Valid student name (min 3 chars), department, and date are required.'
    });
  }

  const sql = `INSERT INTO appointments (student, department, date, status, created_by) VALUES (?, ?, ?, 'Pending', ?)`;
  db.run(sql, [cleanStudent, cleanDepartment, cleanDate, req.user.username], function (err) {
    if (err) return res.status(500).json({ success: false, error: 'Database insert failed.' });

    db.get(`SELECT id, student, department, date, status FROM appointments WHERE id = ?`, [this.lastID], (err, newRecord) => {
      res.status(201).json({
        success: true,
        message: 'Appointment saved securely.',
        data: newRecord
      });
    });
  });
});

app.patch('/api/appointments/:id/status', authenticateToken, requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  db.get(`SELECT * FROM appointments WHERE id = ?`, [id], (err, appointment) => {
    if (!appointment) return res.status(404).json({ success: false, error: 'Appointment not found.' });

    const newStatus = appointment.status === 'Pending' ? 'Confirmed' : 'Pending';
    db.run(`UPDATE appointments SET status = ? WHERE id = ?`, [newStatus, id], (err) => {
      if (err) return res.status(500).json({ success: false, error: 'Database update failed.' });
      res.status(200).json({
        success: true,
        message: `Status updated to ${newStatus}.`,
        data: { ...appointment, status: newStatus }
      });
    });
  });
});

app.delete('/api/appointments/:id', authenticateToken, requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  db.run(`DELETE FROM appointments WHERE id = ?`, [id], function (err) {
    if (err) return res.status(500).json({ success: false, error: 'Database delete failed.' });
    if (this.changes === 0) return res.status(404).json({ success: false, error: 'Appointment not found.' });
    res.status(200).json({ success: true, message: 'Appointment deleted.' });
  });
});

// DEPLOYMENT SMOKE TEST ENDPOINT (Module 12 & 14 Requirement)
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'UP',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});