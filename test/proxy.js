// Test harness: HTTP CONNECT proxy + SOCKS5 proxy + fake DNS-over-TCP + target.
// Everything stays on localhost so the test can run without internet access.
const net = require('net');
const http = require('http');
const https = require('https');
const dgram = require('dgram');
const fs = require('fs');
const path = require('path');

const LOG = path.join(__dirname, 'proxy.log');
function log(line) {
  const s = `[${new Date().toISOString()}] ${line}\n`;
  fs.appendFileSync(LOG, s);
  process.stdout.write(s);
}

// ---------- target HTTP server ----------
const target = http.createServer((req, res) => {
  log(`TARGET ${req.method} ${req.url} host=${req.headers.host}`);
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('HELLO_FROM_PROXY_TARGET\n');
});
target.listen(18080, '127.0.0.1', () => log('target listening 127.0.0.1:18080'));

// ---------- local TLS target (for URL health tests) ----------
try {
  const tlsServer = https.createServer({
    key: fs.readFileSync(path.join(__dirname, 'key.pem')),
    cert: fs.readFileSync(path.join(__dirname, 'cert.pem')),
  }, (req, res) => {
    log(`TLS TARGET ${req.method} ${req.url}`);
    res.writeHead(204, { 'content-type': 'text/plain' });
    res.end();
  });
  tlsServer.listen(18443, '127.0.0.1', () => log('TLS target listening 127.0.0.1:18443'));
} catch (e) {
  log('TLS target disabled: ' + e.message);
}

// ---------- fake DNS-over-TCP server ----------
const FAKE_DNS_IP = Buffer.from([203, 0, 113, 10]);
const dnsServer = net.createServer((sock) => {
  let buf = Buffer.alloc(0);
  sock.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 2) {
      const len = buf.readUInt16BE(0);
      if (buf.length < 2 + len) break;
      const query = buf.subarray(2, 2 + len);
      buf = buf.subarray(2 + len);
      log(`DNS query ${len} bytes`);
      // Parse the first question name and its end offset.
      let off = 12;
      const labels = [];
      while (off < query.length && query[off] !== 0) {
        const l = query[off++];
        labels.push(query.subarray(off, off + l).toString());
        off += l;
      }
      off++; // zero
      const qtype = query.readUInt16BE(off);
      const qclass = query.readUInt16BE(off + 2);
      const questionEnd = off + 4;
      log(`DNS name=${labels.join('.')} type=${qtype} class=${qclass}`);

      const header = Buffer.alloc(12);
      query.copy(header, 0, 0, 2); // id
      header.writeUInt16BE(0x8180, 2); // response, RD+RA
      header.writeUInt16BE(1, 4); // qd
      header.writeUInt16BE(qtype === 1 ? 1 : 0, 6); // an
      header.writeUInt16BE(0, 8);
      header.writeUInt16BE(0, 10);
      const question = query.subarray(12, questionEnd);
      let answer = Buffer.alloc(0);
      if (qtype === 1) {
        answer = Buffer.alloc(16);
        answer.writeUInt16BE(0xc00c, 0); // pointer to name
        answer.writeUInt16BE(1, 2); // A
        answer.writeUInt16BE(1, 4); // IN
        answer.writeUInt32BE(60, 6); // TTL
        answer.writeUInt16BE(4, 10);
        FAKE_DNS_IP.copy(answer, 12);
      }
      const resp = Buffer.concat([header, question, answer]);
      const out = Buffer.alloc(2);
      out.writeUInt16BE(resp.length, 0);
      sock.write(Buffer.concat([out, resp]));
    }
  });
  sock.on('error', () => {});
});
dnsServer.listen(18053, '127.0.0.1', () => log('fake DNS listening 127.0.0.1:18053'));

// ---------- UDP echo target ----------
const udpEcho = dgram.createSocket('udp4');
udpEcho.on('message', (msg, rinfo) => {
  log(`UDP ECHO ${rinfo.address}:${rinfo.port} ${msg.length}b`);
  udpEcho.send(Buffer.concat([Buffer.from('ECHO:'), msg]), rinfo.port, rinfo.address);
});
udpEcho.bind(18054, '127.0.0.1', () => log('UDP echo listening 127.0.0.1:18054'));

function connectDestination(host, port, cb) {
  // Deliver every proxied TCP connection to the local test target.
  if ((host === '8.8.8.8' || host === '1.1.1.1') && port === 53) {
    return cb(null, net.connect(18053, '127.0.0.1'));
  }
  if (host === 'www.gstatic.com' && port === 443) {
    return cb(null, net.connect(18443, '127.0.0.1'));
  }
  cb(null, net.connect(18080, '127.0.0.1'));
}

// ---------- HTTP CONNECT proxy ----------
const httpProxy = http.createServer((req, res) => {
  log(`HTTP proxy plain request ${req.method} ${req.url}`);
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('HTTP_PROXY_PLAIN\n');
});
httpProxy.on('connect', (req, clientSock, head) => {
  log(`HTTP CONNECT ${req.url} (head ${head.length}b)`);
  const [host, portStr] = req.url.split(':');
  const port = parseInt(portStr, 10);
  connectDestination(host, port, (err, upstream) => {
    if (err) { clientSock.destroy(); return; }
    clientSock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length) upstream.write(head);
    clientSock.pipe(upstream);
    upstream.pipe(clientSock);
    upstream.on('error', () => clientSock.destroy());
    clientSock.on('error', () => upstream.destroy());
  });
});
httpProxy.listen(18081, '127.0.0.1', () => log('HTTP proxy listening 127.0.0.1:18081'));

// ---------- SOCKS5 proxy ----------
const socks = net.createServer((sock) => {
  let stage = 0;
  let buf = Buffer.alloc(0);
  sock.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    if (stage === 0) {
      if (buf.length < 2) return;
      const nm = buf[1];
      if (buf.length < 2 + nm) return;
      const methods = [...buf.subarray(2, 2 + nm)];
      buf = buf.subarray(2 + nm);
      log(`SOCKS5 greeting methods=${methods.join(',')}`);
      sock.write(Buffer.from([5, 0])); // no auth
      stage = 1;
    }
    if (stage === 1) {
      if (buf.length < 4) return;
      const cmd = buf[1];
      const atyp = buf[3];
      let need = 4;
      let host = '';
      if (atyp === 1) {
        need += 4 + 2;
        if (buf.length < need) return;
        host = [...buf.subarray(4, 8)].join('.');
      } else if (atyp === 3) {
        need += 1 + buf[4] + 2;
        if (buf.length < need) return;
        host = buf.subarray(5, 5 + buf[4]).toString();
      } else {
        sock.destroy();
        return;
      }
      const port = buf.readUInt16BE(need - 2);
      buf = buf.subarray(need);
      log(`SOCKS5 cmd=${cmd} CONNECT ${host}:${port} atyp=${atyp}`);
      if (cmd === 3) {
        // UDP ASSOCIATE: reply with a local relay endpoint, keep TCP open.
        const relay = dgram.createSocket('udp4');
        relay.on('error', () => {});
        relay.on('message', (msg, rinfo) => {
          // RSV(2) FRAG(1) ATYP(1) ADDR PORT DATA
          let off = 3;
          const a = msg[off++];
          let dst = '';
          if (a === 1) {
            dst = [...msg.subarray(off, off + 4)].join('.');
            off += 4;
          } else if (a === 3) {
            const l = msg[off++];
            dst = msg.subarray(off, off + l).toString();
            off += l;
          } else {
            return;
          }
          const dport = msg.readUInt16BE(off);
          off += 2;
          const payload = msg.subarray(off);
          log(`UDP RELAY ${dst}:${dport} ${payload.length}b -> local echo`);
          const fwd = dgram.createSocket('udp4');
          fwd.on('message', (resp) => {
            const head = Buffer.concat([
              Buffer.from([0, 0, 0, 1, 127, 0, 0, 1]),
              Buffer.from([(dport >> 8) & 0xff, dport & 0xff]),
            ]);
            relay.send(Buffer.concat([head, resp]), rinfo.port, rinfo.address);
            fwd.close();
          });
          fwd.on('error', () => fwd.close());
          fwd.send(payload, 18054, '127.0.0.1');
          setTimeout(() => { try { fwd.close(); } catch {} }, 4000);
        });
        relay.bind(0, '127.0.0.1', () => {
          const rp = relay.address().port;
          log(`UDP ASSOCIATE relay 127.0.0.1:${rp}`);
          sock.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, (rp >> 8) & 0xff, rp & 0xff]));
        });
        sock.on('close', () => { try { relay.close(); } catch {} });
        stage = 2;
        return;
      }
      connectDestination(host, port, (err, upstream) => {
        if (err) { sock.destroy(); return; }
        sock.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
        if (buf.length) upstream.write(buf);
        sock.pipe(upstream);
        upstream.pipe(sock);
        upstream.on('error', () => sock.destroy());
        sock.on('error', () => upstream.destroy());
      });
      stage = 2;
    }
  });
  sock.on('error', () => {});
});
socks.listen(18082, '127.0.0.1', () => log('SOCKS5 listening 127.0.0.1:18082'));
