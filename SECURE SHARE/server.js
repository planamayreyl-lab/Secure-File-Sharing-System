const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const multer = require('multer');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

const PORT = 3000;
const JWT_SECRET = 'secureshare_jwt_secret_2025';
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const KEYS_DIR = path.join(__dirname, 'keys');
const USERS_FILE = path.join(__dirname, 'users.json'); // ← persistent storage

// ─── Create required directories ──────────────────────────────────────────────
[UPLOADS_DIR, KEYS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ─── Persistent User Storage ──────────────────────────────────────────────────
// Users are stored in users.json so accounts survive server restarts.

function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const raw = fs.readFileSync(USERS_FILE, 'utf8');
      return JSON.parse(raw);
    }
  } catch (e) {
    console.error('Failed to load users.json, starting fresh:', e.message);
  }
  return {};
}

function saveUsers(users) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
  } catch (e) {
    console.error('Failed to save users.json:', e.message);
  }
}

// Load users at startup
const users = loadUsers();
console.log(`   Loaded ${Object.keys(users).length} existing user(s) from storage.`);

// ─── In-memory session state ───────────────────────────────────────────────────
// connectedUsers: socketId → { username }
const connectedUsers = {};

// pendingTransfers: requestId → transfer object
const pendingTransfers = {};

// ─── RSA Key Generation ────────────────────────────────────────────────────────
function generateRSAKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

// ─── AES Encryption ────────────────────────────────────────────────────────────
function encryptFileAES(fileBuffer) {
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
  const encryptedFile = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
  return { encryptedFile, aesKey, iv };
}

function decryptFileAES(encryptedBuffer, aesKey, iv) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
  return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
}

// ─── RSA Key Wrapping ──────────────────────────────────────────────────────────
function encryptAESKeyWithRSA(aesKey, publicKeyPem) {
  return crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    aesKey
  );
}

function decryptAESKeyWithRSA(encryptedAESKey, privateKeyPem) {
  return crypto.privateDecrypt(
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    encryptedAESKey
  );
}

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(__dirname));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 } // 50 MB max
});

// ─── Helper: resolve username from username OR email ───────────────────────────
function resolveUsername(identifier) {
  // Direct username match
  if (users[identifier]) return identifier;
  // Email match
  const found = Object.entries(users).find(([, u]) => u.email === identifier);
  return found ? found[0] : null;
}

// ─── Auth Routes ───────────────────────────────────────────────────────────────

// Register
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'A valid email address is required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  // Check username uniqueness
  if (users[username]) {
    return res.status(409).json({ error: 'Username already taken' });
  }

  // Check email uniqueness
  const emailTaken = Object.values(users).some(u => u.email === email);
  if (emailTaken) {
    return res.status(409).json({ error: 'Email address already registered' });
  }

  const hashedPassword = await bcrypt.hash(password, 12);
  const { publicKey, privateKey } = generateRSAKeyPair();

  // Save to persistent storage
  users[username] = {
    hashedPassword,
    email,
    publicKey,
    privateKey,
    createdAt: new Date().toISOString()
  };
  saveUsers(users);

  // Also save key files (optional, for reference)
  fs.writeFileSync(path.join(KEYS_DIR, `${username}_private.pem`), privateKey);
  fs.writeFileSync(path.join(KEYS_DIR, `${username}_public.pem`), publicKey);

  console.log(`✅ New user registered: ${username} (${email})`);
  res.json({ success: true, message: 'Account created successfully' });
});

// Login (accepts username or email)
app.post('/login', async (req, res) => {
  const { username: identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ error: 'Credentials are required' });
  }

  const username = resolveUsername(identifier);
  if (!username) {
    return res.status(401).json({ error: 'Invalid username/email or password' });
  }

  const user = users[username];
  const valid = await bcrypt.compare(password, user.hashedPassword);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid username/email or password' });
  }

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
  console.log(`  Login: ${username}`);

  res.json({
    success: true,
    token,
    username,
    email: user.email,
    publicKey: user.publicKey
  });
});

// ─── File Transfer ──────────────────────────────────────────────────────────────

app.post('/send-file', upload.single('file'), (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  let decoded;
  try { decoded = jwt.verify(token, JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Invalid or expired token' }); }

  const { targetUsername } = req.body;
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'No file uploaded' });

  // Find target socket
  const targetEntry = Object.entries(connectedUsers).find(([, u]) => u.username === targetUsername);
  if (!targetEntry) return res.status(404).json({ error: 'Target user is not currently online' });

  const [targetSocketId] = targetEntry;
  const senderEntry = Object.entries(connectedUsers).find(([, u]) => u.username === decoded.username);
  const senderSocketId = senderEntry ? senderEntry[0] : null;

  const receiverPublicKey = users[targetUsername]?.publicKey;
  if (!receiverPublicKey) return res.status(404).json({ error: 'Receiver public key not found' });

  // Encrypt file
  const { encryptedFile, aesKey, iv } = encryptFileAES(file.buffer);
  const encryptedAESKey = encryptAESKeyWithRSA(aesKey, receiverPublicKey);

  const requestId = crypto.randomBytes(8).toString('hex');
  pendingTransfers[requestId] = {
    fromSocket: senderSocketId,
    toSocket: targetSocketId,
    fromUsername: decoded.username,
    filename: file.originalname,
    mimetype: file.mimetype,
    encryptedFile: encryptedFile.toString('base64'),
    encryptedAESKey: encryptedAESKey.toString('base64'),
    iv: iv.toString('hex'),
    fileSize: file.size,
    requestedAt: new Date().toISOString()
  };

  // Notify recipient via socket
  io.to(targetSocketId).emit('file-request', {
    requestId,
    fromUsername: decoded.username,
    filename: file.originalname,
    fileSize: file.size
  });

  console.log(`📤 Transfer request: ${decoded.username} → ${targetUsername} [${file.originalname}]`);
  res.json({ success: true, requestId, message: 'Transfer request sent to recipient' });
});

// Download + Decrypt
app.get('/download/:requestId', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  let decoded;
  try { decoded = jwt.verify(token, JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Invalid or expired token' }); }

  const transfer = pendingTransfers[req.params.requestId];
  if (!transfer) return res.status(404).json({ error: 'Transfer not found or already completed' });

  const receiverPrivateKey = users[decoded.username]?.privateKey;
  if (!receiverPrivateKey) return res.status(404).json({ error: 'Private key not found' });

  try {
    const encryptedAESKey = Buffer.from(transfer.encryptedAESKey, 'base64');
    const encryptedFile = Buffer.from(transfer.encryptedFile, 'base64');
    const iv = Buffer.from(transfer.iv, 'hex');

    const aesKey = decryptAESKeyWithRSA(encryptedAESKey, receiverPrivateKey);
    const decryptedFile = decryptFileAES(encryptedFile, aesKey, iv);

    res.setHeader('Content-Disposition', `attachment; filename="${transfer.filename}"`);
    res.setHeader('Content-Type', transfer.mimetype || 'application/octet-stream');
    res.send(decryptedFile);

    console.log(`✅ File delivered: ${transfer.filename} → ${decoded.username}`);
    delete pendingTransfers[req.params.requestId];
  } catch (err) {
    console.error('Decryption error:', err.message);
    res.status(500).json({ error: 'Decryption failed: ' + err.message });
  }
});

// ─── Socket.IO ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log(`  Socket connected: ${socket.id}`);

  socket.on('register-socket', ({ token }) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      connectedUsers[socket.id] = { username: decoded.username };
      console.log(`  ${decoded.username} is now online`);
      broadcastOnlineUsers();
    } catch {
      socket.emit('error', 'Invalid token — please log in again');
    }
  });

  socket.on('accept-transfer', ({ requestId }) => {
    const transfer = pendingTransfers[requestId];
    if (!transfer) return;
    if (transfer.fromSocket) {
      io.to(transfer.fromSocket).emit('transfer-accepted', { requestId, filename: transfer.filename });
    }
    socket.emit('start-download', { requestId, filename: transfer.filename });
  });

  socket.on('reject-transfer', ({ requestId }) => {
    const transfer = pendingTransfers[requestId];
    if (!transfer) return;
    if (transfer.fromSocket) {
      io.to(transfer.fromSocket).emit('transfer-rejected', { requestId, filename: transfer.filename });
    }
    delete pendingTransfers[requestId];
  });

  socket.on('disconnect', () => {
    const user = connectedUsers[socket.id];
    if (user) {
      console.log(`👋 ${user.username} went offline`);
      delete connectedUsers[socket.id];
      broadcastOnlineUsers();
    }
  });
});

function broadcastOnlineUsers() {
  const list = Object.values(connectedUsers).map(u => u.username);
  io.emit('online-users', list);
}

// ─── Start Server ──────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
  const interfaces = require('os').networkInterfaces();
  let localIP = 'localhost';
  Object.values(interfaces).forEach(iface => {
    iface.forEach(addr => {
      if (addr.family === 'IPv4' && !addr.internal) localIP = addr.address;
    });
  });

  console.log(`\n   SecureShare Server running!`);
  console.log(`   Local:   http://localhost:${PORT}`);
  console.log(`   Network: http://${localIP}:${PORT}  ← open this on other devices`);
  console.log(`   Users stored in: ${USERS_FILE}`);
  console.log(`   Registered accounts: ${Object.keys(users).length}\n`);
});
