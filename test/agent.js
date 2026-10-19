// Injected test agent. Usage: node agent.js <ip|dns|doh|quic>
const http = require('http');
const dns = require('dns');
const dgram = require('dgram');
const fs = require('fs');
const path = require('path');

const mode = process.argv[2] || 'ip';
const waitArg = process.argv.find((a) => a.startsWith('--wait='));
const waitMs = waitArg ? parseInt(waitArg.split('=')[1], 10) : 0;
const out = path.join(__dirname, `result-${mode}.txt`);
fs.writeFileSync(path.join(__dirname, 'pid.txt'), String(process.pid));

function done(text) {
  fs.writeFileSync(out, text);
  console.log(text);
}

function httpGet(host, port, cb) {
  const req = http.get({ host, port, path: '/', timeout: 8000 }, (res) => {
    let body = '';
    res.on('data', (d) => (body += d));
    res.on('end', () => cb(null, res.statusCode, body));
  });
  req.on('timeout', () => { req.destroy(new Error('timeout')); });
  req.on('error', (e) => cb(e));
}

if (mode === 'ip') {
  setTimeout(() => httpGet('1.1.1.1', 8080, (err, status, body) => {
    done(err ? `ERROR ${err.message}` : `OK ${status} ${body.trim()}`);
  }), waitMs);
} else if (mode === 'dns') {
  setTimeout(() => dns.lookup('test.local', { family: 4 }, (err, address) => {
    if (err) return done(`DNS_ERROR ${err.message}`);
    httpGet(address, 8080, (e, status, body) => {
      done(e ? `DNS_OK ${address} HTTP_ERROR ${e.message}` : `DNS_OK ${address} HTTP_OK ${status} ${body.trim()}`);
    });
  }), waitMs);
} else if (mode === 'doh') {
  setTimeout(() => httpGet('8.8.8.8', 443, (err) => {
    done(err ? `BLOCKED ${err.code || err.message}` : 'NOT_BLOCKED');
  }), waitMs);
} else if (mode === 'quic') {
  setTimeout(() => {
    const s = dgram.createSocket('udp4');
    s.send(Buffer.from('ping'), 443, '8.8.8.8', (err) => {
      done(err ? `BLOCKED ${err.code || err.message}` : 'SENT_UNEXPECTED');
      s.close();
    });
    s.on('error', (e) => done(`BLOCKED ${e.code || e.message}`));
  }, waitMs);
}
