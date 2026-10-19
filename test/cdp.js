// Minimal CDP helper for the Electron app.
// usage: node cdp.js shot <out.png>
//        node cdp.js eval "<js expression>"
//        node cdp.js click "<selector>"
const http = require('http');
const fs = require('fs');

function getJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch (e) { reject(e); } });
    }).on('error', reject);
  });
}

async function main() {
  const [cmd, arg] = process.argv.slice(2);
  const targets = await getJson('http://127.0.0.1:' + (process.env.CDP_PORT || 9222) + '/json');
  const page = targets.find((t) => t.type === 'page');
  if (!page) throw new Error('no page target');
  if (typeof WebSocket === 'undefined') throw new Error('global WebSocket missing');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let seq = 0;
  const pending = new Map();
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(JSON.stringify(msg.error)));
      else resolve(msg.result);
    }
  };
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++seq;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
  await send('Page.enable');
  await send('Runtime.enable');

  if (cmd === 'shot') {
    const r = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
    fs.writeFileSync(arg || 'shot.png', Buffer.from(r.data, 'base64'));
    console.log('saved', arg || 'shot.png');
  } else if (cmd === 'eval') {
    const r = await send('Runtime.evaluate', { expression: arg, awaitPromise: true, returnByValue: true });
    console.log(JSON.stringify(r.result?.value ?? r.result, null, 2));
  } else if (cmd === 'click') {
    const expr = `(() => { const el = document.querySelector(${JSON.stringify(arg)}); if (!el) return 'not found'; el.click(); return 'ok'; })()`;
    const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    console.log(r.result?.value);
  } else {
    console.log('unknown command');
  }
  ws.close();
}

main().catch((e) => { console.error(e); process.exit(1); });
