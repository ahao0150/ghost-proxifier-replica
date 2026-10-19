const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const mode = process.argv[2] || 'sendto';
const s = dgram.createSocket('udp4');
const out = path.join(__dirname, `udp-node-${mode}.txt`);
let done = false;
function finish(t) { if (done) return; done = true; fs.writeFileSync(out, t); console.log(t); try { s.close(); } catch {} }
s.on('message', (msg, rinfo) => finish(`OK ${msg.toString()} from ${rinfo.address}:${rinfo.port}`));
s.on('error', (e) => finish(`ERR ${e.code || e.message}`));
if (mode === 'connected') {
  s.connect(9999, '1.1.1.1', () => s.send('node-connected-udp'));
} else {
  s.send('node-sendto-udp', 9999, '1.1.1.1');
}
setTimeout(() => finish('TIMEOUT'), 6000);
