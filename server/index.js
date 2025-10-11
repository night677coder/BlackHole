// Minimal backend for non-expiring encrypted share links (mode B)
// Node 18+ required

import express from 'express';
import cors from 'cors';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { randomBytes } from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
// Enable CORS for all origins and common methods/headers
app.use(cors({
  origin: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept'],
}));
// Handle CORS preflight explicitly (helps when serving UI from file://)
app.options('*', cors());

// Serve static files from the root directory
app.use(express.static(path.join(__dirname, '..')));

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const id = generateId();
    cb(null, id);
  }
});

const upload = multer({ storage });

function generateId(len = 32) {
  // URL-safe base64 id
  const bytes = randomBytes(len);
  const b64 = Buffer.from(bytes).toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

// Upload encrypted blob
app.post('/api/upload', upload.single('file'), (req, res) => {
  try {
    const id = path.basename(req.file.filename);
    const baseUrl = 'https://blackhole-jkby.onrender.com';
    const url = `${baseUrl}/d/${id}`;
    res.json({ id, url });
  } catch (e) {
    console.error('Upload failed:', e);
    res.status(500).json({ error: 'upload_failed' });
  }
});

// Basic health check
app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// Simple homepage
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>BLACKHOLE Share Server</title>
      <style>
        body {
          font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
          text-align: center;
          padding: 50px;
          margin: 0;
          background: linear-gradient(135deg, #000000 0%, #141414 100%);
          color: #ffffff;
          min-height: 100vh;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
        }
        h1 {
          color: #e50914;
          font-size: 3em;
          margin-bottom: 20px;
          font-weight: bold;
          text-shadow: 0 0 20px rgba(229, 9, 20, 0.5);
        }
        p {
          color: #cccccc;
          font-size: 1.2em;
          margin: 15px 0;
          max-width: 600px;
          line-height: 1.6;
        }
        a {
          color: #e50914;
          text-decoration: none;
          background: #e50914;
          color: #ffffff;
          padding: 12px 24px;
          border-radius: 4px;
          font-weight: bold;
          transition: all 0.3s ease;
          display: inline-block;
          margin-top: 20px;
          text-transform: uppercase;
          letter-spacing: 1px;
        }
        a:hover {
          background: #f40612;
          box-shadow: 0 0 20px rgba(229, 9, 20, 0.5);
        }
      </style>
    </head>
    <body>
      <h1>BLACKHOLE Share Server</h1>
      <p>The server is running and ready to handle file sharing requests.</p>
      <p>Use the main BLACKHOLE application (index.html) for uploading and managing files.</p>
      <p><a href="/api/health">Check server health</a></p>
    </body>
    </html>
  `);
});

// Download/stream the stored encrypted blob
app.get('/d/:id', (req, res) => {
  const id = req.params.id;
  const filePath = path.join(uploadsDir, id);
  if (!fs.existsSync(filePath)) {
    return res.status(404).send('Not found');
  }

  try {
    const stat = fs.statSync(filePath);
    const fileSize = stat.size;
    const range = req.headers.range;
    res.setHeader('Accept-Ranges', 'bytes');

    if (range) {
      // Example: bytes=start-end
      const match = /^bytes=(\d*)-(\d*)$/.exec(range);
      if (!match) {
        return res.status(416).set({ 'Content-Range': `bytes */${fileSize}` }).end();
      }

      let start = match[1] ? parseInt(match[1], 10) : 0;
      let end = match[2] ? parseInt(match[2], 10) : fileSize - 1;

      // Normalize invalid ranges
      if (isNaN(start) && !isNaN(end)) {
        // suffix range: bytes=-N
        const suffixLen = end;
        start = Math.max(fileSize - suffixLen, 0);
        end = fileSize - 1;
      }

      if (isNaN(start) || isNaN(end) || start > end || start >= fileSize) {
        return res.status(416).set({ 'Content-Range': `bytes */${fileSize}` }).end();
      }

      end = Math.min(end, fileSize - 1);
      const chunkSize = end - start + 1;

      res.status(206);
      res.setHeader('Content-Range', `bytes ${start}-${end}/${fileSize}`);
      res.setHeader('Content-Length', String(chunkSize));
      res.setHeader('Content-Type', 'application/octet-stream');

      const stream = fs.createReadStream(filePath, { start, end });
      stream.on('open', () => stream.pipe(res));
      stream.on('error', (err) => {
        console.error('Stream error:', err);
        res.destroy(err);
      });
    } else {
      // No range header: stream whole file
      res.status(200);
      res.setHeader('Content-Length', String(fileSize));
      res.setHeader('Content-Type', 'application/octet-stream');
      const stream = fs.createReadStream(filePath);
      stream.on('open', () => stream.pipe(res));
      stream.on('error', (err) => {
        console.error('Stream error:', err);
        res.destroy(err);
      });
    }
  } catch (e) {
    console.error('Failed to serve file:', e);
    res.status(500).send('Server error');
  }
});

// Decrypt viewer (static)
app.get('/view/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'viewer.html'));
});

// Static for any assets if needed
app.use('/static', express.static(path.join(__dirname, 'static')));

// Chunked upload API for very large payloads
// 1) POST /api/upload/init -> { id }
app.post('/api/upload/init', (req, res) => {
  try {
    const id = generateId();
    const tmp = path.join(uploadsDir, id + '.tmp');
    fs.writeFileSync(tmp, ''); // create/truncate
    res.json({ id });
  } catch (e) {
    console.error('init failed:', e);
    res.status(500).json({ error: 'init_failed' });
  }
});

// 2) POST /api/upload/chunk/:id/:index  (raw binary body)
app.post('/api/upload/chunk/:id/:index', (req, res) => {
  const { id, index } = req.params;
  const tmp = path.join(uploadsDir, id + '.tmp');
  try {
    const flags = Number(index) === 0 ? 'w' : 'a';
    const ws = fs.createWriteStream(tmp, { flags });
    req.on('error', (err) => {
      console.error('chunk req error:', err);
      try { ws.destroy(); } catch {}
      res.destroy(err);
    });
    ws.on('error', (err) => {
      console.error('chunk write error:', err);
      res.status(500).json({ error: 'chunk_write_failed' });
    });
    ws.on('finish', () => res.json({ ok: true }));
    req.pipe(ws);
  } catch (e) {
    console.error('chunk failed:', e);
    res.status(500).json({ error: 'chunk_failed' });
  }
});

// 3) POST /api/upload/complete/:id -> finalize file
app.post('/api/upload/complete/:id', (req, res) => {
  const { id } = req.params;
  const tmp = path.join(uploadsDir, id + '.tmp');
  const finalPath = path.join(uploadsDir, id);
  try {
    if (!fs.existsSync(tmp)) return res.status(404).json({ error: 'no_tmp' });
    fs.renameSync(tmp, finalPath);
    const baseUrl = 'https://blackhole-jkby.onrender.com';
    const url = `${baseUrl}/d/${id}`;
    res.json({ id, url });
  } catch (e) {
    console.error('complete failed:', e);
    res.status(500).json({ error: 'complete_failed' });
  }
});

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`Share server listening on http://127.0.0.1:${PORT}`);
});
// Disable request timeout for large uploads and be generous with headers/keepalive
try {
  server.setTimeout(0); // no socket inactivity timeout
  server.headersTimeout = 0;
  server.keepAliveTimeout = 120000;
} catch {}
