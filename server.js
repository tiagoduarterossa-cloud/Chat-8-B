'use strict';
// Servidor de retransmissão: só guarda e reencaminha texto cifrado.
// Não conhece palavras-passe, nomes nem conteúdo das mensagens.
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const PORT = Number(process.env.PORT) || 8443;
const DATA_DIR = path.join(__dirname, 'data');
const HISTORY_FILE = path.join(DATA_DIR, 'history.json');
const KEY_FILE = path.join(DATA_DIR, 'key.pem');
const CERT_FILE = path.join(DATA_DIR, 'cert.pem');
const MAX_PER_ROOM = 500;
const MAX_BODY = 64 * 1024;
const ROOM_RE = /^[a-f0-9]{64}$/;
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

fs.mkdirSync(DATA_DIR, { recursive: true });

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
function loadCert() {
  if (!fs.existsSync(KEY_FILE) || !fs.existsSync(CERT_FILE)) {
    const san = ['DNS:localhost', 'IP:127.0.0.1', ...lanAddresses().map(ip => 'IP:' + ip)].join(',');
    try {
      execFileSync('openssl', [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
        '-keyout', KEY_FILE, '-out', CERT_FILE,
        '-subj', '/CN=chat-8-b', '-addext', 'subjectAltName=' + san,
      ], { stdio: 'ignore' });
    } catch {
      return null;
    }
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

const indexHtml = path.join(__dirname, 'public', 'index.html');

function handler(req, res) {
  const url = new URL(req.url, 'http://x');
  if (req.method === 'GET' && url.pathname === '/') {
    return send(res, 200, fs.readFileSync(indexHtml), 'text/html; charset=utf-8');
  }
  if (req.method === 'GET' && url.pathname === '/events') return handleEvents(req, res, url);
  if (req.method === 'POST' && url.pathname === '/send') return handleSend(req, res);
  send(res, 404, { error: 'não encontrado' });
}

const tls = process.env.NO_TLS ? null : loadCert();
const server = tls ? https.createServer(tls, handler) : http.createServer(handler);
const proto = tls ? 'https' : 'http';

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Chat a correr. Abre num browser da mesma rede:`);
  console.log(`  ${proto}://localhost:${PORT}`);
  for (const ip of lanAddresses()) console.log(`  ${proto}://${ip}:${PORT}`);
  if (!tls) console.log('Aviso: sem HTTPS a cifra só funciona em localhost. Instala o openssl.');
});
