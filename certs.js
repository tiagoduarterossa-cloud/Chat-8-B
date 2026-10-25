'use strict';
// Autoridade de certificação (CA) local do Chat News.
//
// Os telemóveis instalam o ca.crt uma vez; a partir daí deixam de ver o aviso
// de segurança e o browser permite notificações. A CA está limitada (Name
// Constraints) a endereços de rede local e a "localhost", por isso não serve
// para assinar certificados de sites da internet.
const fs = require('fs');
const path = require('path');
const { webcrypto } = require('crypto');
const x509 = require('@peculiar/x509');

x509.cryptoProvider.set(webcrypto);

const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
const LEAF_DAYS = 397; // o iOS recusa certificados de servidor muito longos

const PRIVATE_NETS = [
  [[10, 0, 0, 0], [255, 0, 0, 0]],
  [[172, 16, 0, 0], [255, 240, 0, 0]],
  [[192, 168, 0, 0], [255, 255, 0, 0]],
  [[127, 0, 0, 0], [255, 0, 0, 0]],
  [[169, 254, 0, 0], [255, 255, 0, 0]],
];

function der(tag, content) {
  const len = content.length;
  const head = len < 128 ? [len] : len < 256 ? [0x81, len] : [0x82, len >> 8, len & 255];
  return Buffer.concat([Buffer.from([tag, ...head]), content]);
}

// NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees }
function nameConstraints() {
  const subtrees = [
    ...PRIVATE_NETS.map(([ip, mask]) => der(0x30, der(0x87, Buffer.from([...ip, ...mask])))),
    der(0x30, der(0x82, Buffer.from('localhost'))),
  ];
  return der(0x30, der(0xa0, Buffer.concat(subtrees)));
}

async function exportKey(key) {
  return x509.PemConverter.encode(await webcrypto.subtle.exportKey('pkcs8', key), 'PRIVATE KEY');
}

async function importKey(pem) {
  const raw = x509.PemConverter.decode(pem)[0];
  return webcrypto.subtle.importKey('pkcs8', raw, ALG, true, ['sign']);
}

function serial() {
  return webcrypto.getRandomValues(new Uint8Array(16)).reduce((s, b) => s + b.toString(16).padStart(2, '0'), '7');
}

async function createCA() {
  const keys = await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const notBefore = new Date(Date.now() - 24 * 3600e3);
  const notAfter = new Date(notBefore);
  notAfter.setFullYear(notAfter.getFullYear() + 10);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serial(),
    name: 'CN=Chat News (rede local), O=Chat News',
    notBefore,
    notAfter,
    keys,
    signingAlgorithm: ALG,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      new x509.Extension('2.5.29.30', true, nameConstraints()),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
    ],
  });
  return { cert: cert.toString('pem'), key: await exportKey(keys.privateKey) };
}

async function createLeaf(caPem, caKeyPem, ips) {
  const ca = new x509.X509Certificate(caPem);
  const caKey = await importKey(caKeyPem);
  const keys = await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const notBefore = new Date(Date.now() - 24 * 3600e3);
  const notAfter = new Date(notBefore.getTime() + LEAF_DAYS * 24 * 3600e3);
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serial(),
    subject: 'CN=Chat News',
    issuer: ca.subject,
    notBefore,
    notAfter,
    publicKey: keys.publicKey,
    signingKey: caKey,
    signingAlgorithm: ALG,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
      new x509.SubjectAlternativeNameExtension([
        { type: 'dns', value: 'localhost' },
        { type: 'ip', value: '127.0.0.1' },
        ...ips.map(ip => ({ type: 'ip', value: ip })),
      ]),
      await x509.AuthorityKeyIdentifierExtension.create(ca),
    ],
  });
  return { cert: cert.toString('pem') + '\n' + ca.toString('pem') + '\n', key: await exportKey(keys.privateKey), notAfter };
}

function isPrivateIp(ip) {
  const p = ip.split('.').map(Number);
  return PRIVATE_NETS.some(([net, mask]) => p.every((b, i) => (b & mask[i]) === net[i]));
}

// Gera o que faltar: a CA só uma vez; o certificado do servidor sempre que o
// IP do computador muda (por exemplo, ao trocar de Wi-Fi para hotspot).
async function ensureCerts(dir, lanIps) {
  const f = name => path.join(dir, name);
  const ips = lanIps.filter(isPrivateIp);
  let createdCA = false;
  if (!fs.existsSync(f('ca.pem')) || !fs.existsSync(f('ca-key.pem'))) {
    const ca = await createCA();
    fs.writeFileSync(f('ca-key.pem'), ca.key, { mode: 0o600 });
    fs.writeFileSync(f('ca.pem'), ca.cert);
    createdCA = true;
  }
  let meta = null;
  try { meta = JSON.parse(fs.readFileSync(f('cert-meta.json'), 'utf8')); } catch {}
  const stale = createdCA || !meta || !fs.existsSync(f('key.pem')) || !fs.existsSync(f('cert.pem'))
    || new Date(meta.notAfter) - Date.now() < 30 * 24 * 3600e3
    || ips.some(ip => !meta.ips.includes(ip));
  if (stale) {
    const all = [...new Set([...(meta && !createdCA ? meta.ips : []), ...ips])].slice(-16);
    const leaf = await createLeaf(fs.readFileSync(f('ca.pem'), 'utf8'), fs.readFileSync(f('ca-key.pem'), 'utf8'), all);
    fs.writeFileSync(f('key.pem'), leaf.key, { mode: 0o600 });
    fs.writeFileSync(f('cert.pem'), leaf.cert);
    fs.writeFileSync(f('cert-meta.json'), JSON.stringify({ ips: all, notAfter: leaf.notAfter }));
  }
  const caCert = new x509.X509Certificate(fs.readFileSync(f('ca.pem'), 'utf8'));
  return {
    key: fs.readFileSync(f('key.pem')),
    cert: fs.readFileSync(f('cert.pem')),
    caDer: Buffer.from(caCert.rawData),
    caFingerprint: Buffer.from(await caCert.getThumbprint('SHA-256')).toString('hex').toUpperCase().match(/../g).join(':'),
  };
}

module.exports = { ensureCerts };
