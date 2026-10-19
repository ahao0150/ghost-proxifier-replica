// Local Shadowsocks AEAD test server (aes-256-gcm by default).
// TCP targets are mapped to the local HTTP target (or fake DNS for port 53);
// UDP targets are mapped to the local UDP echo server.
const net = require('net');
const dgram = require('dgram');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const METHOD = process.env.SS_METHOD || 'aes-256-gcm';
const PASSWORD = process.env.SS_PASSWORD || 'test-password';
const TCP_PORT = parseInt(process.env.SS_PORT || '18388', 10);
const UDP_PORT = parseInt(process.env.SS_UDP_PORT || '18388', 10);
const LOG = path.join(__dirname, 'ss-server.log');
function log(s) { const l = `[${new Date().toISOString()}] ${s}\n`; fs.appendFileSync(LOG, l); process.stdout.write(l); }

function params(method) {
  if (method === 'aes-128-gcm') return { alg: 'aes-128-gcm', keyLen: 16, saltLen: 16 };
  if (method === 'aes-256-gcm') return { alg: 'aes-256-gcm', keyLen: 32, saltLen: 32 };
  if (method === 'chacha20-ietf-poly1305' || method === 'chacha20-poly1305') return { alg: 'chacha20-poly1305', keyLen: 32, saltLen: 32 };
  throw new Error('bad method');
}
const P = params(METHOD);

function evp(password, keyLen) {
  const chunks = []; let prev = Buffer.alloc(0); let total = 0;
  while (total < keyLen) {
    const md = crypto.createHash('md5').update(Buffer.concat([prev, Buffer.from(password)])).digest();
    chunks.push(md); prev = md; total += md.length;
  }
  return Buffer.concat(chunks).subarray(0, keyLen);
}
const MASTER = evp(PASSWORD, P.keyLen);
function subkey(salt) { return Buffer.from(crypto.hkdfSync('sha1', MASTER, salt, Buffer.from('ss-subkey'), P.keyLen)); }
function nonce(n) { const b = Buffer.alloc(12); b.writeBigUInt64LE(BigInt(n), 0); return b; }

function encryptChunks(key, data, startNonce = 0) {
  const out = []; let n = startNonce;
  for (let off = 0; off < data.length; off += 0x3FFF) {
    const chunk = data.subarray(off, Math.min(off + 0x3FFF, data.length));
    for (const part of [Buffer.from([(chunk.length >> 8) & 0xff, chunk.length & 0xff]), chunk]) {
      const c = crypto.createCipheriv(P.alg, key, nonce(n++), { authTagLength: 16 });
      out.push(c.update(part), c.final(), c.getAuthTag());
    }
  }
  return Buffer.concat(out);
}

function aeadEncryptOne(key, data) {
  const c = crypto.createCipheriv(P.alg, key, nonce(0), { authTagLength: 16 });
  return Buffer.concat([c.update(data), c.final(), c.getAuthTag()]);
}

function decryptOne(key, nonceBuf, input) {
  if (input.length < 16) return null;
  const cipherLen = input.length - 16;
  const d = crypto.createDecipheriv(P.alg, key, nonceBuf, { authTagLength: 16 });
  d.setAuthTag(input.subarray(cipherLen));
  return Buffer.concat([d.update(input.subarray(0, cipherLen)), d.final()]);
}

function parseAddr(buf, off) {
  const atyp = buf[off++];
  let host = '';
  if (atyp === 1) { host = [...buf.subarray(off, off + 4)].join('.'); off += 4; }
  else if (atyp === 3) { const l = buf[off++]; host = buf.subarray(off, off + l).toString(); off += l; }
  else if (atyp === 4) { host = 'ipv6'; off += 16; }
  else throw new Error('bad atyp ' + atyp);
  const port = buf.readUInt16BE(off); off += 2;
  return { host, port, off };
}
function addrHeader(host, port) {
  const h = Buffer.from(host);
  const b = Buffer.alloc(1 + 1 + h.length + 2);
  b[0] = 3; b[1] = h.length; h.copy(b, 2); b.writeUInt16BE(port, 2 + h.length);
  return b;
}

// ---------------- TCP ----------------
net.createServer((sock) => {
  let salt = null;
  let key = null;
  let nRecv = 0;
  let buf = Buffer.alloc(0);
  let target = null;
  let targetSock = null;
  let saltSent = false;
  let sendKey = null;
  let nSend = 0;

  function sendPlain(data) {
    if (!data.length) return;
    if (!saltSent) {
      const salt2 = crypto.randomBytes(P.saltLen);
      sendKey = subkey(salt2);
      sock.write(salt2);
      saltSent = true;
    }
    sock.write(encryptChunks(sendKey, data, nSend));
    nSend += Math.ceil(data.length / 0x3FFF) * 2;
  }

  function processBuf() {
    while (true) {
      if (!salt) {
        if (buf.length < P.saltLen) return;
        salt = buf.subarray(0, P.saltLen);
        buf = buf.subarray(P.saltLen);
        key = subkey(salt);
        log(`TCP client salt received (${salt.length}b)`);
      }
      if (buf.length < 2 + 16) return;
      let lenPlain;
      try { lenPlain = decryptOne(key, nonce(nRecv++), buf.subarray(0, 2 + 16)); } catch (e) { sock.destroy(); return; }
      if (!lenPlain || lenPlain.length !== 2) { sock.destroy(); return; }
      const len = lenPlain.readUInt16BE(0);
      if (buf.length < 2 + 16 + len + 16) return;
      let payload;
      try { payload = decryptOne(key, nonce(nRecv++), buf.subarray(2 + 16, 2 + 16 + len + 16)); } catch (e) { sock.destroy(); return; }
      buf = buf.subarray(2 + 16 + len + 16);
      if (!target) {
        const a = parseAddr(payload, 0);
        target = a;
        const initial = payload.subarray(a.off);
        const destPort = a.port === 53 || a.port === 18053 ? 18053 : 18080;
        log(`TCP target ${a.host}:${a.port} -> 127.0.0.1:${destPort} initial=${initial.length}b`);
        targetSock = net.connect(destPort, '127.0.0.1', () => {
          if (initial.length) targetSock.write(initial);
        });
        targetSock.on('data', (d) => sendPlain(d));
        targetSock.on('error', () => sock.destroy());
        targetSock.on('close', () => { try { sock.end(); } catch {} });
      } else {
        if (targetSock) targetSock.write(payload);
      }
    }
  }

  sock.on('data', (d) => { buf = Buffer.concat([buf, d]); processBuf(); });
  sock.on('error', () => {});
  sock.on('close', () => { if (targetSock) targetSock.destroy(); });
}).listen(TCP_PORT, '127.0.0.1', () => log(`SS TCP listening 127.0.0.1:${TCP_PORT} method=${METHOD}`));

// ---------------- UDP ----------------
const echo = dgram.createSocket('udp4');
const udp = dgram.createSocket('udp4');
udp.on('message', (msg, rinfo) => {
  if (msg.length <= P.saltLen + 16) return;
  const salt = msg.subarray(0, P.saltLen);
  const key = subkey(salt);
  let plain;
  try { plain = decryptOne(key, nonce(0), msg.subarray(P.saltLen)); } catch (e) { return; }
  if (!plain) return;
  const a = parseAddr(plain, 0);
  const payload = plain.subarray(a.off);
  log(`UDP target ${a.host}:${a.port} ${payload.length}b -> local echo`);
  const fwd = dgram.createSocket('udp4');
  fwd.on('message', (resp) => {
    log(`UDP echo back ${resp.length}b -> encrypt/send`);
    const plainResp = Buffer.concat([addrHeader(a.host, a.port), resp]);
    const salt2 = crypto.randomBytes(P.saltLen);
    const key2 = subkey(salt2);
    const enc = aeadEncryptOne(key2, plainResp);
    udp.send(Buffer.concat([salt2, enc]), rinfo.port, rinfo.address);
    fwd.close();
  });
  fwd.on('error', () => fwd.close());
  fwd.send(payload, 18054, '127.0.0.1');
  setTimeout(() => { try { fwd.close(); } catch {} }, 4000);
});
udp.bind(UDP_PORT, '127.0.0.1', () => log(`SS UDP listening 127.0.0.1:${UDP_PORT}`));
