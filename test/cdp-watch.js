// Watch renderer console/errors across a reload.
const http = require('http');
function getJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => { let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => resolve(JSON.parse(d))); }).on('error', reject);
  });
}
(async () => {
  const targets = await getJson('http://127.0.0.1:9222/json');
  const page = targets.find((t) => t.type === 'page');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let seq = 0;
  const pending = new Map();
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); return; }
    if (m.method === 'Runtime.exceptionThrown') {
      const d = m.params.exceptionDetails;
      console.log('EXCEPTION:', d.text, d.exception?.description || '', d.url || '', d.lineNumber);
    } else if (m.method === 'Runtime.consoleAPICalled') {
      console.log('CONSOLE', m.params.type + ':', m.params.args.map((a) => a.value ?? a.description).join(' '));
    } else if (m.method === 'Log.entryAdded') {
      const e = m.params.entry;
      console.log('LOG', e.level + ':', e.text, e.url || '', e.lineNumber || '');
    }
  };
  await new Promise((res) => (ws.onopen = res));
  const send = (method, params = {}) => new Promise((resolve) => {
    const id = ++seq; pending.set(id, resolve); ws.send(JSON.stringify({ id, method, params }));
  });
  await send('Runtime.enable');
  await send('Log.enable');
  await send('Page.enable');
  await send('Page.reload', { ignoreCache: true });
  await new Promise((r) => setTimeout(r, 4000));
  const r = await send('Runtime.evaluate', { expression: 'typeof bootstrap + "|" + typeof state + "|" + document.readyState', returnByValue: true });
  console.log('STATE:', JSON.stringify(r.result?.result?.value ?? r.result));
  ws.close();
})();
