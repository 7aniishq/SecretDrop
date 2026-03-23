const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// Multer config — store files in memory
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB max
});

// In-memory store
const secrets = new Map();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// ── Create Secret ──────────────────────────────────────────────
app.post('/api/secrets', upload.single('file'), async (req, res) => {
  try {
    const { secret, expiresIn, maxViews, password } = req.body;
    const file = req.file;

    if ((!secret || secret.trim().length === 0) && !file) {
      return res.status(400).json({ error: 'A secret message or file is required.' });
    }

    const id = crypto.randomBytes(16).toString('hex');
    const expirationHours = parseInt(expiresIn) || 24;
    const expirationMs = expirationHours * 60 * 60 * 1000;
    const viewLimit = parseInt(maxViews) || 1;

    // Hash password if provided
    let passwordHash = null;
    if (password && password.trim().length > 0) {
      passwordHash = await bcrypt.hash(password.trim(), 10);
    }

    const entry = {
      secret: secret || null,
      file: file ? {
        buffer: file.buffer,
        originalName: file.originalname,
        mimetype: file.mimetype,
        size: file.size
      } : null,
      createdAt: Date.now(),
      expiresAt: Date.now() + expirationMs,
      maxViews: viewLimit,
      viewCount: 0,
      passwordHash
    };

    secrets.set(id, entry);

    // Auto-cleanup on expiry
    setTimeout(() => secrets.delete(id), expirationMs);

    const link = `${req.protocol}://${req.get('host')}/#/view/${id}`;
    res.json({
      id,
      link,
      expiresIn: expirationHours,
      maxViews: viewLimit,
      hasPassword: !!passwordHash,
      hasFile: !!file,
      fileName: file ? file.originalname : null,
      fileSize: file ? file.size : null
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ── Get Secret Metadata (without revealing content) ────────────
app.get('/api/secrets/:id/meta', (req, res) => {
  const entry = secrets.get(req.params.id);
  if (!entry) {
    return res.status(404).json({ error: 'Secret not found or already destroyed.' });
  }
  if (Date.now() > entry.expiresAt) {
    secrets.delete(req.params.id);
    return res.status(410).json({ error: 'Secret has expired.' });
  }
  res.json({
    hasPassword: !!entry.passwordHash,
    hasFile: !!entry.file,
    hasText: !!entry.secret,
    fileName: entry.file ? entry.file.originalName : null,
    fileSize: entry.file ? entry.file.size : null,
    remainingViews: entry.maxViews - entry.viewCount,
    maxViews: entry.maxViews,
    expiresAt: entry.expiresAt
  });
});

// ── View/Reveal Secret ─────────────────────────────────────────
app.post('/api/secrets/:id/reveal', async (req, res) => {
  const entry = secrets.get(req.params.id);
  if (!entry) {
    return res.status(404).json({ error: 'Secret not found or already destroyed.' });
  }
  if (Date.now() > entry.expiresAt) {
    secrets.delete(req.params.id);
    return res.status(410).json({ error: 'Secret has expired.' });
  }

  // Password check
  if (entry.passwordHash) {
    const { password } = req.body || {};
    if (!password) {
      return res.status(401).json({ error: 'Password required.' });
    }
    const match = await bcrypt.compare(password, entry.passwordHash);
    if (!match) {
      return res.status(403).json({ error: 'Incorrect password.' });
    }
  }

  // Increment view count
  entry.viewCount++;

  const response = {
    secret: entry.secret,
    hasFile: !!entry.file,
    fileName: entry.file ? entry.file.originalName : null,
    fileSize: entry.file ? entry.file.size : null,
    fileMimetype: entry.file ? entry.file.mimetype : null,
    remainingViews: entry.maxViews - entry.viewCount,
    destroyed: entry.viewCount >= entry.maxViews
  };

  // If file exists, send base64
  if (entry.file) {
    response.fileData = entry.file.buffer.toString('base64');
  }

  // Destroy if view limit reached
  if (entry.viewCount >= entry.maxViews) {
    secrets.delete(req.params.id);
  }

  res.json(response);
});

// ── Serve frontend ─────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`SecretDrop server running on port ${PORT}`);
});
