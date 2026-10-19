// Long-running injected workload: repeatedly resolves a fake domain through
// the proxy DNS and fetches the test target. Used to exercise stats/DNS UI.
const http = require('http');
const dns = require('dns');

let seq = 0;
function one() {
  dns.lookup('test.local', { family: 4 }, (err, address) => {
    if (err) return;
    for (let i = 0; i < 4; i++) {
      const req = http.get({ host: address, port: 8080, path: '/work?i=' + (++seq), timeout: 5000 }, (res) => {
        let n = 0;
        res.on('data', (d) => (n += d.length));
        res.on('end', () => {});
      });
      req.on('timeout', () => req.destroy());
      req.on('error', () => {});
    }
  });
}
setInterval(one, 1200);
one();
setTimeout(() => process.exit(0), 10 * 60 * 1000);
