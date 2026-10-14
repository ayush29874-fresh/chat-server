require('dotenv').config();
const express = require('express');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { Server } = require('socket.io');

const User = require('./models/User');
const Message = require('./models/Message');
const auth = require('./middleware/auth');

const { PORT = 3000, MONGO_URI, JWT_SECRET, CLIENT_ORIGIN } = process.env;
if (!MONGO_URI || !JWT_SECRET || !CLIENT_ORIGIN) {
  console.error('Missing env vars: MONGO_URI, JWT_SECRET, CLIENT_ORIGIN');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({ origin: CLIENT_ORIGIN }));
app.use(express.json({ limit: '10kb' }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
const makeToken = (username) => jwt.sign({ username }, JWT_SECRET, { expiresIn: '7d' });

// ---------- Auth ----------
app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!/^[a-z0-9_]{3,20}$/.test(username) || password.length < 8)
      return res.status(400).json({ error: 'Username: 3-20 letters/numbers/_ . Password: min 8 chars.' });

    const passwordHash = await bcrypt.hash(password, 12);
    await User.create({ username, passwordHash });
    res.json({ username, token: makeToken(username) });
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Username already taken' });
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const user = await User.findOne({ username });
    const ok = user && await bcrypt.compare(String(req.body.password || ''), user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Wrong username or password' });
    res.json({ username, token: makeToken(username) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Users ----------
app.get('/api/users/:username', auth, async (req, res) => {
  const name = req.params.username.toLowerCase();
  const exists = await User.exists({ username: name });
  if (!exists) return res.status(404).json({ error: 'User not found' });
  res.json({ username: name });
});

// ---------- Messages ----------
app.get('/api/messages/:other', auth, async (req, res) => {
  const id = Message.convoId(req.user.username, req.params.other.toLowerCase());
  const history = await Message.find({ conversationId: id })
    .sort({ createdAt: -1 }).limit(100).lean();
  res.json(history.reverse().map(m => ({
    from: m.from, to: m.to, text: m.text, time: new Date(m.createdAt).getTime(),
  })));
});

app.get('/api/conversations', auth, async (req, res) => {
  const me = req.user.username;
  const rows = await Message.aggregate([
    { $match: { $or: [{ from: me }, { to: me }] } },
    { $sort: { createdAt: -1 } },
    { $group: { _id: '$conversationId', last: { $first: '$$ROOT' } } },
    { $sort: { 'last.createdAt': -1 } },
    { $limit: 50 },
  ]);
  res.json(rows.map(r => ({
    username: r.last.from === me ? r.last.to : r.last.from,
    lastMessage: r.last.text,
    time: new Date(r.last.createdAt).getTime(),
  })));
});

app.get('/health', (_, res) => res.send('ok'));

// ---------- Socket.IO ----------
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: CLIENT_ORIGIN } });

io.use((socket, next) => {
  try {
    socket.data.username = jwt.verify(socket.handshake.auth.token, JWT_SECRET).username;
    next();
  } catch {
    next(new Error('Unauthorized'));
  }
});

io.on('connection', (socket) => {
  const me = socket.data.username;
  socket.join(me);

  let count = 0;
  const timer = setInterval(() => (count = 0), 5000);
  socket.on('disconnect', () => clearInterval(timer));

  socket.on('private-message', async ({ to, text } = {}) => {
    try {
      if (++count > 10) return;
      to = String(to || '').toLowerCase();
      text = String(text || '').trim().slice(0, 1000);
      if (!text || to === me) return;
      if (!(await User.exists({ username: to }))) return;

      const doc = await Message.create({
        from: me, to, text, conversationId: Message.convoId(me, to),
      });
      io.to(to).to(me).emit('private-message', {
        from: me, to, text, time: doc.createdAt.getTime(),
      });
    } catch (e) {
      console.error(e);
    }
  });
});

mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('MongoDB connected');
    server.listen(PORT, () => console.log(`Server on port ${PORT}`));
  })
  .catch(err => { console.error('Mongo error', err); process.exit(1); });