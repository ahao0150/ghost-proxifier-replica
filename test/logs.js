const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const out = path.join(__dirname, 'logs.txt');
const s = dgram.createSocket('udp4');
s.on('message', (m) => {
  const line = m.toString('utf8');
  fs.appendFileSync(out, line + '\n');
  process.stdout.write(line + '\n');
});
s.bind(45001, '127.0.0.1');
const stats = dgram.createSocket('udp4');
stats.on('message', (m) => {
  fs.appendFileSync(path.join(__dirname, 'stats.txt'), m.toString('utf8') + '\n');
});
stats.bind(45002, '127.0.0.1');
