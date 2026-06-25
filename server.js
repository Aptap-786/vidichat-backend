const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

app.use(cors());
app.use(express.json());

// Rate Limiter for Security
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', apiLimiter);

// Database Pool
const dbPool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const JWT_SECRET = process.env.JWT_SECRET;

// --- AUTHENTICATION ---
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Please enter all fields.' });
  }
  try {
    const [existing] = await dbPool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'User with this email already exists.' });
    }
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const userId = require('crypto').randomUUID();

    await dbPool.query(
      'INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)',
      [userId, name, email, passwordHash]
    );

    const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id: userId, name, email } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Please enter all fields.' });
  }
  try {
    const [users] = await dbPool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(400).json({ error: 'User does not exist.' });
    }
    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials.' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const verifyToken = (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) return res.status(401).json({ error: 'No token, authorization denied.' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).json({ error: 'Token is not valid.' });
  }
};

// --- VIDEOS ---
app.get('/api/videos', async (req, res) => {
  try {
    const [rows] = await dbPool.query(
      `SELECT v.*, u.name as creator_name, u.avatar_url as creator_avatar 
       FROM videos v 
       JOIN users u ON v.creator_id = u.id 
       ORDER BY v.created_at DESC`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/videos', verifyToken, async (req, res) => {
  const { title, description, video_url, thumbnail_url, category } = req.body;
  if (!title || !video_url || !thumbnail_url) {
    return res.status(400).json({ error: 'Required fields are missing.' });
  }
  try {
    const videoId = require('crypto').randomUUID();
    await dbPool.query(
      `INSERT INTO videos (id, title, description, video_url, thumbnail_url, creator_id, category) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [videoId, title, description, video_url, thumbnail_url, req.user.id, category || 'All']
    );
    res.status(201).json({ id: videoId, title });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- CHATS ---
app.get('/api/chats', verifyToken, async (req, res) => {
  try {
    const [threads] = await dbPool.query(
      `SELECT t.*, 
       (SELECT m.message_text FROM chat_messages m WHERE m.thread_id = t.id ORDER BY m.created_at DESC LIMIT 1) as last_message,
       (SELECT m.created_at FROM chat_messages m WHERE m.thread_id = t.id ORDER BY m.created_at DESC LIMIT 1) as last_message_time
       FROM chat_threads t
       JOIN chat_participants p ON t.id = p.thread_id
       WHERE p.user_id = ?
       ORDER BY last_message_time DESC`,
      [req.user.id]
    );
    res.json(threads);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- SOCKETS ---
io.on('connection', (socket) => {
  socket.on('join', ({ userId }) => {
    socket.join(userId);
  });
  
  socket.on('send_message', async ({ threadId, senderId, text }) => {
    try {
      await dbPool.query(
        'INSERT INTO chat_messages (thread_id, sender_id, message_text) VALUES (?, ?, ?)',
        [threadId, senderId, text]
      );
      io.to(threadId).emit('receive_message', { threadId, senderId, messageText: text });
    } catch (err) {
      console.error(err);
    }
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
