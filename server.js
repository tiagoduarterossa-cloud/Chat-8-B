'use strict';
// Servidor de retransmissão: só guarda e reencaminha texto cifrado.
// Não conhece palavras-passe, nomes nem conteúdo das mensagens.
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const selfsigned = require('selfsigned');

const PORT = Number(process.env.PORT) || 8443;
const DATA_DIR = path.join(__dirname, 'data');
const HISTORY_FILE = path.join(DATA_DIR, 'history.json');
const KEY_FILE = path.join(DATA_DIR, 'key.pem');
const CERT_FILE = path.join(DATA_DIR, 'cert.pem');
const FILES_DIR = path.join(DATA_DIR, 'files');
const MAX_PER_ROOM = 500;
const MAX_BODY = 64 * 1024;
const MAX_FILE = 25 * 1024 * 1024 + 28; // 25 MB + IV e tag do AES-GCM
const MAX_ROOM_FILES = 1024 * 1024 * 1024; // 1 GB por sala; apagam-se os mais antigos
const FILE_RE = /^[a-f0-9]{32}$/;
const ROOM_RE = /^[a-f0-9]{64}$/;
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

fs.mkdirSync(FILES_DIR, { recursive: true });

let rooms = {};
try { rooms = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8')); } catch {}

let saveTimer = null;
function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    fs.writeFile(HISTORY_FILE + '.tmp', JSON.stringify(rooms), err => {
      if (!err) fs.rename(HISTORY_FILE + '.tmp', HISTORY_FILE, () => {});
    });
  }, 500);
}

const listeners = new Map(); // sala -> Set(res)

function lanAddresses() {
  return Object.values(os.networkInterfaces()).flat()
    .filter(a => a && a.family === 'IPv4' && !a.internal)
    .map(a => a.address);
}

// O browser só permite WebCrypto em HTTPS (ou localhost), por isso geramos
// um certificado autoassinado na primeira execução.
async function loadCert() {
  if (!fs.existsSync(KEY_FILE) || !fs.existsSync(CERT_FILE)) {
    const altNames = [
      { type: 2, value: 'localhost' },
      { type: 7, ip: '127.0.0.1' },
      ...lanAddresses().map(ip => ({ type: 7, ip })),
    ];
    const notAfterDate = new Date();
    notAfterDate.setFullYear(notAfterDate.getFullYear() + 10);
    const pems = await selfsigned.generate([{ name: 'commonName', value: 'chat-news' }], {
      keySize: 2048,
      algorithm: 'sha256',
      notAfterDate,
      extensions: [{ name: 'subjectAltName', altNames }],
    });
    fs.writeFileSync(KEY_FILE, pems.private, { mode: 0o600 });
    fs.writeFileSync(CERT_FILE, pems.cert);
  }
  return { key: fs.readFileSync(KEY_FILE), cert: fs.readFileSync(CERT_FILE) };
}

function send(res, status, body, type = 'application/json') {
  res.writeHead(status, {
    'Content-Type': type,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

function sse(res, msg) {
  res.write(`id: ${msg.id}\ndata: ${JSON.stringify(msg)}\n\n`);
}

function handleEvents(req, res, url) {
  const room = url.searchParams.get('room') || '';
  if (!ROOM_RE.test(room)) return send(res, 400, { error: 'sala inválida' });
  const since = Number(req.headers['last-event-id'] || url.searchParams.get('since') || 0);

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-store',
    'Connection': 'keep-alive',
  });
  res.write('retry: 2000\n\n');
  for (const msg of (rooms[room]?.msgs || [])) if (msg.id > since) sse(res, msg);

  if (!listeners.has(room)) listeners.set(room, new Set());
  listeners.get(room).add(res);
  const ping = setInterval(() => res.write(': ping\n\n'), 25000);
  req.on('close', () => {
    clearInterval(ping);
    listeners.get(room)?.delete(res);
  });
}

function handleSend(req, res) {
  let body = '';
  req.setEncoding('utf8');
  req.on('data', chunk => {
    body += chunk;
    if (body.length > MAX_BODY) { send(res, 413, { error: 'mensagem demasiado grande' }); req.destroy(); }
  });
  req.on('end', () => {
    let data;
    try { data = JSON.parse(body); } catch { return send(res, 400, { error: 'JSON inválido' }); }
    const { room, iv, ct } = data || {};
    if (!ROOM_RE.test(room || '') || !B64_RE.test(iv || '') || !B64_RE.test(ct || '') || iv.length !== 16) {
      return send(res, 400, { error: 'pedido inválido' });
    }
    const r = rooms[room] || (rooms[room] = { seq: 0, msgs: [] });
    const msg = { id: ++r.seq, iv, ct };
    r.msgs.push(msg);
    if (r.msgs.length > MAX_PER_ROOM) r.msgs.splice(0, r.msgs.length - MAX_PER_ROOM);
    save();
    for (const l of listeners.get(room) || []) sse(l, msg);
    send(res, 200, { id: msg.id });
  });
}

// Os ficheiros chegam já cifrados pelo browser; aqui só se guardam os bytes.
function handleUpload(req, res, url) {
  const room = url.searchParams.get('room') || '';
  const id = url.searchParams.get('id') || '';
  if (!ROOM_RE.test(room) || !FILE_RE.test(id)) return send(res, 400, { error: 'pedido inválido' });
  const len = Number(req.headers['content-length']);
  if (!(len > 28)) return send(res, 400, { error: 'ficheiro vazio' });
  if (len > MAX_FILE) { send(res, 413, { error: 'ficheiro demasiado grande' }); return req.destroy(); }

  const dir = path.join(FILES_DIR, room);
  const dest = path.join(dir, id);
  fs.mkdirSync(dir, { recursive: true });
  if (fs.existsSync(dest)) { req.resume(); return send(res, 200, { ok: true }); }

  const tmp = dest + '.part';
  const out = fs.createWriteStream(tmp);
  let size = 0;
  let failed = false;
  const fail = (status, error) => {
    if (failed) return;
    failed = true;
    out.destroy();
    fs.rm(tmp, { force: true }, () => {});
    if (!res.headersSent) send(res, status, { error });
  };
  req.on('data', chunk => {
    size += chunk.length;
    if (size > len) { fail(413, 'ficheiro demasiado grande'); req.destroy(); }
  });
  req.on('aborted', () => fail(400, 'envio interrompido'));
  out.on('error', () => fail(500, 'erro ao gravar'));
  out.on('finish', () => {
    if (failed) return;
    if (size !== len) return fail(400, 'envio incompleto');
    fs.rename(tmp, dest, err => {
      if (err) return fail(500, 'erro ao gravar');
      pruneFiles(dir);
      send(res, 200, { ok: true });
    });
  });
  req.pipe(out);
}

function pruneFiles(dir) {
  const files = fs.readdirSync(dir)
    .filter(f => FILE_RE.test(f))
    .map(f => ({ f, ...fs.statSync(path.join(dir, f)) }))
    .sort((a, b) => a.mtimeMs - b.mtimeMs);
  let total = files.reduce((n, x) => n + x.size, 0);
  for (const x of files) {
    if (total <= MAX_ROOM_FILES) break;
    fs.rmSync(path.join(dir, x.f), { force: true });
    total -= x.size;
  }
}

function handleFile(res, url) {
  const room = url.searchParams.get('room') || '';
  const id = url.searchParams.get('id') || '';
  if (!ROOM_RE.test(room) || !FILE_RE.test(id)) return send(res, 400, { error: 'pedido inválido' });
  const file = path.join(FILES_DIR, room, id);
  fs.stat(file, (err, st) => {
    if (err) return send(res, 404, { error: 'ficheiro já não existe' });
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': st.size,
      'Cache-Control': 'private, max-age=31536000, immutable',
      'X-Content-Type-Options': 'nosniff',
    });
    fs.createReadStream(file).pipe(res);
  });
}

const indexHtml = path.join(__dirname, 'public', 'index.html');

function handler(req, res) {
  const url = new URL(req.url, 'http://x');
  if (req.method === 'GET' && url.pathname === '/') {
    return send(res, 200, fs.readFileSync(indexHtml), 'text/html; charset=utf-8');
  }
  if (req.method === 'GET' && url.pathname === '/events') return handleEvents(req, res, url);
  if (req.method === 'POST' && url.pathname === '/send') return handleSend(req, res);
  if (req.method === 'POST' && url.pathname === '/upload') return handleUpload(req, res, url);
  if (req.method === 'GET' && url.pathname === '/file') return handleFile(res, url);
  send(res, 404, { error: 'não encontrado' });
}

(async () => {
  const tls = process.env.NO_TLS ? null : await loadCert();
  const server = tls ? https.createServer(tls, handler) : http.createServer(handler);
  const proto = tls ? 'https' : 'http';

  server.on('error', err => {
    if (err.code === 'EADDRINUSE') console.error(`A porta ${PORT} já está em uso. O chat já está aberto noutra janela?`);
    else console.error(err.message);
    process.exit(1);
  });

  server.listen(PORT, '0.0.0.0', () => {
    console.log('Chat News a correr. Abre num browser da mesma rede:');
    console.log(`  ${proto}://localhost:${PORT}   (neste computador)`);
    for (const ip of lanAddresses()) console.log(`  ${proto}://${ip}:${PORT}   (telemóveis e outros aparelhos)`);
    console.log('Para desligar: Ctrl+C');
  });
})();
