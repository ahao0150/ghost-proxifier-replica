'use strict';

const { app, BrowserWindow, ipcMain, dialog, shell, Tray, Menu, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const dgram = require('dgram');
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const os = require('os');
const { execFile, spawn } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const ROOT = path.join(__dirname, '..');
const IS_PACKAGED = app.isPackaged;
const NATIVE_DIR = IS_PACKAGED
  ? path.join(process.resourcesPath, 'native')
  : path.join(ROOT, 'native', 'bin');
const CTL = path.join(NATIVE_DIR, 'gppctl.exe');
const DLL_PATH = path.join(NATIVE_DIR, 'gpp_core_x64.dll');
const INI_PATH = path.join(NATIVE_DIR, 'gpp_config.ini');
const ICON_PATH = path.join(__dirname, 'assets', 'app_icon.ico');
const CONFIG_PATH = path.join(app.getPath('userData'), 'config.json');
const UPDATE_ROOT_PUB = (() => {
  try { return fs.readFileSync(path.join(__dirname, 'update-root.pub.pem'), 'utf8'); }
  catch { return ''; }
})();

const LOG_PORT = 45001;
const STATS_PORT = 45002;

const ACCENTS = ['#a78bfa', '#38bdf8', '#34d399', '#f472b6', '#fbbf24', '#22d3ee', '#fb7185'];

let win = null;
let tray = null;
let quitting = false;
let uwpNativeDir = null;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

function defaultConfig() {
  return {
    version: 1,
    language: 'zh',
    upstreams: [
      { id: 'nekobox', name: 'NekoBox', type: 'http', host: '127.0.0.1', port: 2080, username: '', password: '' },
      { id: 'clash-verge', name: 'Clash Verge Rev', type: 'http', host: '127.0.0.1', port: 7897, username: '', password: '' },
      { id: 'v2rayn', name: 'v2rayN', type: 'http', host: '127.0.0.1', port: 10807, username: '', password: '' },
      { id: 'cfw', name: 'Clash for Windows', type: 'http', host: '127.0.0.1', port: 7890, username: '', password: '' },
    ],
    activeUpstreamId: 'nekobox',
    dns: { server: '8.8.8.8', port: 53, mode: 'proxy', dohBlock: true, quicBlock: true },
    general: { closeToTray: true, autoTrackChildren: true, udpProxy: true, watchdog: true, language: 'zh', autoCheckUpdates: true, updateUrl: '', updateSku: 'personal', revokedCerts: [] },
  };
}

function mergeConfig(base, patch) {
  if (!patch || typeof patch !== 'object') return base;
  for (const [k, v] of Object.entries(patch)) {
    if (v && typeof v === 'object' && !Array.isArray(v) && base[k] && typeof base[k] === 'object' && !Array.isArray(base[k])) {
      mergeConfig(base[k], v);
    } else {
      base[k] = v;
    }
  }
  return base;
}

let cfg = defaultConfig();

function loadConfig() {
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    const d = defaultConfig();
    mergeConfig(d, raw);
    if (!Array.isArray(d.upstreams) || d.upstreams.length === 0) d.upstreams = defaultConfig().upstreams;
    if (!d.upstreams.find((u) => u.id === d.activeUpstreamId)) d.activeUpstreamId = d.upstreams[0].id;
    cfg = d;
  } catch {
    cfg = defaultConfig();
  }
}

function saveConfig() {
  try {
    fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), 'utf8');
  } catch (e) {
    console.error('saveConfig failed', e);
  }
}

function activeUpstream() {
  return cfg.upstreams.find((u) => u.id === cfg.activeUpstreamId) || cfg.upstreams[0] || null;
}

async function resolveHost(host) {
  if (!host) return '127.0.0.1';
  if (net.isIP(host)) return host;
  try {
    const r = await require('dns').promises.lookup(host, { family: 4 });
    return r.address;
  } catch {
    return host;
  }
}

async function buildIniContent() {
  const up = activeUpstream();
  let host = '127.0.0.1';
  let port = 2080;
  let type = 'http';
  let user = '';
  let pass = '';
  let node = '未配置';
  if (up) {
    host = await resolveHost(up.host);
    port = Number(up.port) || 0;
    type = up.type === 'socks5' ? 'socks5' : (up.type === 'shadowsocks' ? 'shadowsocks' : 'http');
    user = up.type === 'shadowsocks' ? '' : (up.username || '');
    pass = up.password || '';
    node = up.name || '上游节点';
  }
  const ssMethod = (up && up.method) || 'aes-256-gcm';
  return [
    `proxy=${host}`,
    `port=${port}`,
    `proxy_type=${type}`,
    `username=${String(user).replace(/[\r\n=]/g, '')}`,
    `password=${String(type === 'shadowsocks' ? '' : pass).replace(/[\r\n]/g, '')}`,
    `ss_method=${String(ssMethod).replace(/[\r\n=]/g, '')}`,
    `ss_password=${String(pass).replace(/[\r\n]/g, '')}`,
    `dns=${cfg.dns.server || '8.8.8.8'}`,
    `dns_port=${Number(cfg.dns.port) || 53}`,
    `dns_mode=${cfg.dns.mode === 'proxy' ? 'dot' : 'system'}`,
    `node=${String(node).replace(/[\r\n=]/g, '')}`,
    'sync=0',
    `doh_block=${cfg.dns.dohBlock ? 1 : 0}`,
    `quic_block=${cfg.dns.quicBlock ? 1 : 0}`,
    `udp_proxy=${up && (up.type === 'socks5' || up.type === 'shadowsocks') && cfg.general.udpProxy !== false ? 1 : 0}`,
    `log_port=${LOG_PORT}`,
  ].join('\n') + '\n';
}

function writeIniTo(dir, content) {
  try {
    fs.mkdirSync(dir, { recursive: true });
    const target = path.join(dir, 'gpp_config.ini');
    const tmp = target + '.tmp';
    fs.writeFileSync(tmp, content, 'utf8');
    fs.renameSync(tmp, target);
  } catch (e) {
    console.error('writeIniTo failed', dir, e);
  }
}

async function writeIni() {
  const content = await buildIniContent();
  writeIniTo(NATIVE_DIR, content);
  if (uwpNativeDir) writeIniTo(uwpNativeDir, content);
}

// ---------------------------------------------------------------------------
// Native helper
// ---------------------------------------------------------------------------

async function ctl(args, timeout = 10000) {
  const { stdout } = await execFileAsync(CTL, args, {
    windowsHide: true,
    timeout,
    maxBuffer: 16 * 1024 * 1024,
    encoding: 'utf8',
  });
  return JSON.parse(stdout);
}

async function ctlSafe(args, timeout) {
  try {
    return await ctl(args, timeout);
  } catch (e) {
    // execFile rejects on a non-zero exit even when the helper printed a
    // structured JSON error. Preserve it instead of the raw command string.
    try {
      if (e && e.stdout) {
        const parsed = JSON.parse(e.stdout);
        if (parsed && typeof parsed === 'object') return parsed;
      }
    } catch {}
    return { ok: false, error: e.message };
  }
}

// ---------------------------------------------------------------------------
// Runtime state
// ---------------------------------------------------------------------------

const procSnap = new Map(); // pid -> {pid, ppid, name, path}
const managed = new Map(); // rootPid -> root record
const pidToRoot = new Map(); // pid -> rootPid
const statsByPid = new Map(); // pid -> stats
const iconCache = new Map(); // path -> data url
const injectPending = new Set();
const injectFailedAt = new Map();
let treeBusy = false;

let logs = [];
let dnsRecords = [];
let dnsBlockedTotal = 0;
let history = new Array(60).fill(0);
let lastTotalBytes = 0;
let lastSampleAt = Date.now();
let tcpStats = { outSegs: 0, retransSegs: 0, retransRate: 0 };
let health = {
  availability: [],
  results: {}, // upstream id -> {ok, latency, error, at}
  activeLatency: null,
  lastTestAt: null,
};
let lastStateSentAt = 0;
let statsSock = null;
let logSock = null;

const SYSTEM_NAMES = new Set([
  'system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
  'lsass.exe', 'winlogon.exe', 'fontdrvhost.exe', 'dwm.exe', 'svchost.exe',
  'spoolsv.exe', 'audiodg.exe', 'conhost.exe', 'runtimebroker.exe',
  'sihost.exe', 'taskhostw.exe', 'ctfmon.exe', 'explorer.exe', 'searchhost.exe',
  'shellexperiencehost.exe', 'startmenuexperiencehost.exe', 'textinputhost.exe',
  'securityhealthsystray.exe', 'securityhealthservice.exe', 'msmpeng.exe',
  'nissrv.exe', 'searchindexer.exe', 'wmiprvse.exe', 'dllhost.exe',
  'wudfhost.exe', 'werfault.exe', 'crashpad_handler.exe', 'crashreporter.exe',
  'gppctl.exe', 'electron.exe', 'ghost-proxifier.exe',
]);

const CHILD_SKIP = new Set([
  'conhost.exe', 'werfault.exe', 'crashpad_handler.exe', 'crashreporter.exe',
  'msedgewebview2.exe', 'gppctl.exe',
]);

function accentFor(name) {
  let h = 0;
  for (const c of String(name || '')) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return ACCENTS[h % ACCENTS.length];
}

async function iconFor(p) {
  if (!p) return null;
  if (iconCache.has(p)) return iconCache.get(p);
  try {
    const img = await app.getFileIcon(p, { size: 'large' });
    const url = img.toDataURL();
    if (iconCache.size > 500) iconCache.clear();
    iconCache.set(p, url);
    return url;
  } catch {
    return null;
  }
}

function procInfo(pid) {
  const p = procSnap.get(pid);
  return p || { pid, name: `PID ${pid}`, path: '' };
}

function rootOf(pid) {
  return pidToRoot.get(pid) || null;
}

function membersOf(root) {
  return [root.pid, ...root.injectedPids].filter((v, i, a) => a.indexOf(v) === i);
}

function aggregate(root) {
  let up = 0;
  let down = 0;
  let conns = 0;
  let latency = null;
  for (const pid of membersOf(root)) {
    const s = statsByPid.get(pid);
    if (!s) continue;
    up += s.up || 0;
    down += s.down || 0;
    conns += s.conns || 0;
    if (s.lat >= 0) latency = s.lat;
  }
  return { up, down, conns, latency };
}

function addManaged(pid, opts = {}) {
  const info = procInfo(pid);
  if (managed.has(pid)) return managed.get(pid);
  let name = opts.name || info.name || `PID ${pid}`;
  let p = opts.path || info.path || '';
  if (!p && info.name) {
    // The snapshot may have been taken before the process fully started.
    p = info.path || '';
  }
  const root = {
    pid,
    name,
    path: p,
    icon: null,
    accent: accentFor(name),
    terminal: !!opts.terminal,
    dllPath: opts.dllPath || null,
    startedAt: Date.now(),
    injectedPids: new Set([pid]),
    children: new Set(),
  };
  managed.set(pid, root);
  pidToRoot.set(pid, pid);
  iconFor(p).then((url) => {
    if (url) {
      root.icon = url;
      sendState(true);
    }
  });
  return root;
}

function removeManaged(rootPid) {
  const root = managed.get(rootPid);
  if (!root) return;
  for (const pid of membersOf(root)) {
    pidToRoot.delete(pid);
    statsByPid.delete(pid);
  }
  managed.delete(rootPid);
  persistManaged();
}

function flattenManaged() {
  const roots = [];
  for (const root of managed.values()) {
    roots.push(root);
    for (const pid of root.injectedPids) {
      if (pid !== root.pid) roots.push({ pid, isChild: true, rootPid: root.pid });
    }
  }
  return roots;
}

// ---------------------------------------------------------------------------
// UDP listeners
// ---------------------------------------------------------------------------

function parseStatsLine(line) {
  if (!line.startsWith('[stats]')) return null;
  const out = {};
  const body = line.slice(7);
  for (const part of body.split('|')) {
    const idx = part.indexOf(':');
    if (idx < 0) continue;
    out[part.slice(0, idx)] = part.slice(idx + 1);
  }
  const pid = parseInt(out.pid, 10);
  if (!pid) return null;
  const s = {
    pid,
    ppid: parseInt(out.ppid, 10) || 0,
    up: parseInt(out.up, 10) || 0,
    down: parseInt(out.down, 10) || 0,
    lat: parseInt(out.lat, 10),
    conns: parseInt(out.conns, 10) || 0,
    node: out.node || '',
    dns: out.dns || '',
    blocked: parseInt(out.blocked, 10) || 0,
    type: out.type || '',
    at: Date.now(),
  };
  const prev = statsByPid.get(pid);
  if (prev && (s.up < prev.up || s.down < prev.down)) {
    s.up = s.up;
    s.down = s.down;
  }
  statsByPid.set(pid, s);
  return s;
}

function startUdpListeners() {
  logSock = dgram.createSocket('udp4');
  logSock.on('message', (msg) => {
    const line = msg.toString('utf8');
    if (line.startsWith('[stats]')) {
      parseStatsLine(line);
      return;
    }
    handleLogLine(line);
  });
  logSock.bind(LOG_PORT, '127.0.0.1');

  statsSock = dgram.createSocket('udp4');
  statsSock.on('message', (msg) => {
    parseStatsLine(msg.toString('utf8'));
  });
  statsSock.bind(STATS_PORT, '127.0.0.1');
}

function handleLogLine(line) {
  const m = line.match(/^\[(\d+)\.(\d+)\] \[(\d+):(\d+)\] (.*)$/);
  let pid = 0;
  let rest = line;
  let rel = '';
  if (m) {
    rel = `${m[1]}.${m[2]}`;
    pid = parseInt(m[3], 10);
    rest = m[5];
  }
  let tag = 'log';
  let text = rest;
  const tm = rest.match(/^\[([^\]]+)\]\s*(.*)$/);
  if (tm) {
    tag = tm[1];
    text = tm[2];
  }
  const entry = { ts: Date.now(), pid, tag, text, rel };
  logs.push(entry);
  if (logs.length > 1200) logs = logs.slice(-900);

  parseDnsRecord(entry);

  if (win && !win.isDestroyed()) {
    win.webContents.send('log', entry);
  }
}

function stripDot(d) {
  return d.endsWith('.') ? d.slice(0, -1) : d;
}

function pushDnsRecord(rec) {
  const last = dnsRecords[0];
  if (last && last.domain === rec.domain && last.pid === rec.pid &&
      last.status === rec.status && rec.ts - last.ts < 1500) {
    return;
  }
  const info = procInfo(rec.pid);
  rec.proc = info.name;
  rec.rootPid = pidToRoot.get(rec.pid) || rec.pid;
  delete rec.icon;
  dnsRecords.unshift(rec);
  if (dnsRecords.length > 300) dnsRecords = dnsRecords.slice(0, 250);
  if (rec.status === '已拦截') dnsBlockedTotal++;
  if (win && !win.isDestroyed()) win.webContents.send('dns', rec);
}

function parseDnsRecord(e) {
  const ts = e.ts;
  if (e.tag === 'DNS-Proxy') {
    const m = e.text.match(/resolved:\s*(\S+)\s*->\s*\[([^\]]*)\]/);
    if (m) {
      pushDnsRecord({ ts, pid: e.pid, domain: stripDot(m[1]), ips: m[2], status: '重定向' });
    }
    return;
  }
  if (e.tag === 'DNS') {
    const q = e.text.match(/Query:\s*(\S+)\s*->\s*A:\s*\[([^\]]*)\]/);
    if (q) {
      pushDnsRecord({ ts, pid: e.pid, domain: stripDot(q[1]), ips: q[2], status: '重定向' });
      return;
    }
    const b = e.text.match(/Blocking DoH server\s+(\S+)/);
    if (b) {
      pushDnsRecord({ ts, pid: e.pid, domain: `DoH ${b[1]}`, ips: b[1].replace(/:\d+$/, ''), status: '已拦截' });
    }
    return;
  }
  if (e.tag === 'QUIC') {
    const q = e.text.match(/(?:Blocking UDP 443 to|Closing QUIC socket[^ ]* to|Closing QUIC socket \(.*?\) to)\s*([^\s,]+)/);
    if (q) {
      const target = q[1].replace(/\.$/, '');
      pushDnsRecord({ ts, pid: e.pid, domain: `QUIC ${target}`, ips: target.replace(/:\d+$/, ''), status: '已拦截' });
    }
  }
}

// ---------------------------------------------------------------------------
// Process discovery / injection
// ---------------------------------------------------------------------------

async function refreshSnapshot() {
  const list = await ctlSafe(['list'], 8000);
  if (!Array.isArray(list)) return;
  procSnap.clear();
  for (const p of list) {
    procSnap.set(p.pid, p);
  }
  for (const root of [...managed.values()]) {
    if (!procSnap.has(root.pid)) {
      removeManaged(root.pid);
      continue;
    }
    const info = procSnap.get(root.pid);
    if (info.path && info.path !== root.path) {
      root.path = info.path;
      iconFor(info.path).then((url) => { if (url) root.icon = url; });
    }
    if (info.name) root.name = root.name || info.name;
  }
}

async function refreshTrees() {
  if (treeBusy) return;
  treeBusy = true;
  try {
    for (const root of [...managed.values()]) {
      if (!procSnap.has(root.pid)) continue;
      const tree = await ctlSafe(['tree', String(root.pid)], 5000);
      if (!Array.isArray(tree)) continue;
      for (const pid of [...root.children]) {
        if (!procSnap.has(pid)) root.children.delete(pid);
      }
      const toInject = [];
      for (const pid of tree) {
        const info = procSnap.get(pid);
        if (!info) continue;
        root.children.add(pid);
        if (CHILD_SKIP.has(String(info.name).toLowerCase())) continue;
        if (root.injectedPids.has(pid) || injectPending.has(pid)) continue;
        if (!cfg.general.autoTrackChildren) continue;
        const failedAt = injectFailedAt.get(pid);
        if (failedAt && Date.now() - failedAt < 60000) continue;
        toInject.push(pid);
      }
      // Inject a bounded batch in parallel. Sequential 15s timeouts were
      // enough to stall the UI on browsers with dozens of children.
      const batch = toInject.slice(0, 12);
      for (let i = 0; i < batch.length; i += 4) {
        await Promise.all(batch.slice(i, i + 4).map(async (pid) => {
          injectPending.add(pid);
          const res = await ctlSafe(['inject', String(pid)], 8000);
          injectPending.delete(pid);
          if (res && res.ok) {
            root.injectedPids.add(pid);
            pidToRoot.set(pid, root.pid);
            injectFailedAt.delete(pid);
          } else {
            injectFailedAt.set(pid, Date.now());
          }
        }));
      }
      // Drop dead child PIDs.
      for (const pid of [...root.injectedPids]) {
        if (pid !== root.pid && !procSnap.has(pid)) {
          root.injectedPids.delete(pid);
          pidToRoot.delete(pid);
          statsByPid.delete(pid);
          root.children.delete(pid);
        }
      }
    }
  } finally {
    treeBusy = false;
  }
}

async function injectPid(pid, opts = {}) {
  if (!procSnap.size) await refreshSnapshot();
  if (managed.has(pid)) return { ok: true, already: true };
  const res = await ctlSafe(['inject', String(pid)], 20000);
  if (res && res.ok) {
    addManaged(pid, opts);
    sendState(true);
    return { ok: true };
  }
  return { ok: false, error: (res && res.error) || '注入失败' };
}

// Windows command line splitter for shortcuts.
function splitWinArgs(s) {
  const out = [];
  let cur = '';
  let inQ = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '"') { inQ = !inQ; continue; }
    if (c === ' ' && !inQ) {
      if (cur) { out.push(cur); cur = ''; }
      continue;
    }
    cur += c;
  }
  if (cur) out.push(cur);
  return out;
}

async function resolveTarget(p) {
  const ext = path.extname(p).toLowerCase();
  if (ext === '.lnk') {
    try {
      const s = shell.readShortcutLink(p);
      if (!s.target || !fs.existsSync(s.target)) return { ok: false, error: '快捷方式目标不存在' };
      return {
        ok: true,
        target: s.target,
        args: splitWinArgs(s.args || ''),
        cwd: s.cwd || path.dirname(s.target),
        name: path.basename(s.target),
      };
    } catch (e) {
      return { ok: false, error: '无法读取快捷方式: ' + e.message };
    }
  }
  if (ext === '.bat' || ext === '.cmd') {
    const cmd = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'cmd.exe');
    return { ok: true, target: cmd, args: ['/c', p], cwd: path.dirname(p), name: path.basename(p), console: true };
  }
  if (ext === '.exe') {
    return { ok: true, target: p, args: [], cwd: path.dirname(p), name: path.basename(p) };
  }
  return { ok: false, error: '仅支持 .exe / .lnk / .bat / .cmd' };
}

async function findRunningByPath(p) {
  const norm = (x) => String(x || '').toLowerCase().replace(/\//g, '\\');
  for (const proc of procSnap.values()) {
    if (proc.path && norm(proc.path) === norm(p)) return proc.pid;
  }
  return null;
}

const SCRIPT_HOSTS = new Set([
  'node.exe', 'python.exe', 'pythonw.exe', 'java.exe', 'javaw.exe',
  'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe',
  'conhost.exe', 'bash.exe', 'wsl.exe',
]);
const BROWSERS = new Set(['msedge.exe', 'chrome.exe', 'firefox.exe', 'brave.exe', 'opera.exe', 'vivaldi.exe']);

function samePath(a, b) {
  return String(a || '').toLowerCase().replace(/\//g, '\\') ===
         String(b || '').toLowerCase().replace(/\//g, '\\');
}

function findExistingMain(path) {
  const same = [...procSnap.values()].filter((p) => p.path && samePath(p.path, path));
  if (!same.length) return null;
  const pids = new Set(same.map((p) => p.pid));
  // The browser/app main process is the one whose parent is not another
  // process with the same executable (renderers/utility processes are).
  const root = same.find((p) => !pids.has(p.ppid));
  return root ? root.pid : same[0].pid;
}

async function addPaths(paths) {
  const results = [];
  for (const p of paths) {
    const r = await resolveTarget(p);
    if (!r.ok) { results.push({ path: p, ok: false, error: r.error }); continue; }

    const base = path.basename(r.target).toLowerCase();
    const noArgs = !(r.args && r.args.length);
    // A running singleton app (Edge/Chrome/WeChat…) hands a freshly launched
    // process off to the existing instance, which then exits before the DLL
    // can be injected. Let the user choose: close it and relaunch, or inject
    // the existing process.
    const existing = findExistingMain(r.target);
    const runningPids = [...procSnap.values()]
      .filter((p) => p.path && samePath(p.path, r.target) && p.pid !== process.pid)
      .map((p) => p.pid);
    const shouldPrompt = existing && !SCRIPT_HOSTS.has(base) && (noArgs || BROWSERS.has(base));
    if (shouldPrompt) {
      results.push({
        path: p, ok: false, needsChoice: true,
        name: r.name, target: r.target, args: r.args || [], cwd: r.cwd || '',
        console: !!r.console, existingPid: existing, pids: runningPids,
      });
      continue;
    }

    const args = ['run', r.target, ...(r.args || []), `--cwd=${r.cwd || path.dirname(r.target)}`];
    if (r.console) args.push('--console');
    const res = await ctlSafe(args, 30000);
    if (res && res.ok) {
      addManaged(res.pid, { name: r.name, path: r.target, terminal: !!r.console });
      sendState(true);
      results.push({ path: p, ok: true, pid: res.pid });
    } else {
      let err = (res && res.error) || '启动注入失败';
      if (/exited during injection|LoadLibraryW failed|not observed/i.test(err)) {
        err = `${r.name} 已在运行或启动后立即退出。请先完全退出该程序再拖入，或使用「智能探测」接管现有进程。`;
      }
      results.push({ path: p, ok: false, error: err });
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Upstream tests
// ---------------------------------------------------------------------------

function readBytes(sock, n) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= n) {
        cleanup();
        resolve(buf.subarray(0, n));
      }
    };
    const onErr = (e) => { cleanup(); reject(e); };
    const onClose = () => { cleanup(); reject(new Error('closed')); };
    function cleanup() {
      sock.removeListener('data', onData);
      sock.removeListener('error', onErr);
      sock.removeListener('close', onClose);
    }
    sock.on('data', onData);
    sock.on('error', onErr);
    sock.on('close', onClose);
  });
}

async function socks5Handshake(sock, node) {
  const useAuth = !!(node.username || node.password);
  const greeting = useAuth ? Buffer.from([5, 2, 0, 2]) : Buffer.from([5, 1, 0]);
  sock.write(greeting);
  const method = await readBytes(sock, 2);
  if (method[0] !== 5) throw new Error('SOCKS5 版本错误');
  if (method[1] === 2) {
    const u = Buffer.from(node.username || '');
    const p = Buffer.from(node.password || '');
    const auth = Buffer.concat([Buffer.from([1, u.length]), u, Buffer.from([p.length]), p]);
    sock.write(auth);
    const resp = await readBytes(sock, 2);
    if (resp[1] !== 0) throw new Error('SOCKS5 认证失败');
  } else if (method[1] !== 0) {
    throw new Error('SOCKS5 不支持的认证方式');
  }
  const host = 'www.gstatic.com';
  const req = Buffer.concat([
    Buffer.from([5, 1, 0, 3, Buffer.byteLength(host)]),
    Buffer.from(host),
    Buffer.from([(443 >> 8) & 0xff, 443 & 0xff]),
  ]);
  sock.write(req);
  const head = await readBytes(sock, 4);
  if (head[0] !== 5 || head[1] !== 0) throw new Error(`SOCKS5 CONNECT 失败 (${head[1]})`);
  let addrLen = 0;
  if (head[3] === 1) addrLen = 4;
  else if (head[3] === 4) addrLen = 16;
  else if (head[3] === 3) addrLen = (await readBytes(sock, 1))[0];
  else throw new Error('SOCKS5 地址类型错误');
  await readBytes(sock, addrLen + 2);
}

function ssParams(method) {
  if (method === 'aes-128-gcm') return { alg: 'aes-128-gcm', keyLen: 16, saltLen: 16 };
  if (method === 'aes-256-gcm') return { alg: 'aes-256-gcm', keyLen: 32, saltLen: 32 };
  if (method === 'chacha20-ietf-poly1305' || method === 'chacha20-poly1305') {
    return { alg: 'chacha20-poly1305', keyLen: 32, saltLen: 32 };
  }
  return null;
}

function evpBytesToKey(password, keyLen) {
  const chunks = [];
  let prev = Buffer.alloc(0);
  let total = 0;
  while (total < keyLen) {
    const md = crypto.createHash('md5').update(Buffer.concat([prev, Buffer.from(password, 'utf8')])).digest();
    chunks.push(md);
    prev = md;
    total += md.length;
  }
  return Buffer.concat(chunks).subarray(0, keyLen);
}

function ssSubkey(master, salt, keyLen) {
  return Buffer.from(crypto.hkdfSync('sha1', master, salt, Buffer.from('ss-subkey'), keyLen));
}

function ssNonce(n) {
  const b = Buffer.alloc(12);
  b.writeBigUInt64LE(BigInt(n), 0);
  return b;
}

function ssEncryptChunks(method, key, data) {
  const out = [];
  let nonce = 0;
  for (let off = 0; off < data.length; off += 0x3FFF) {
    const chunk = data.subarray(off, Math.min(off + 0x3FFF, data.length));
    for (const part of [Buffer.from([(chunk.length >> 8) & 0xff, chunk.length & 0xff]), chunk]) {
      const c = crypto.createCipheriv(method, key, ssNonce(nonce++), { authTagLength: 16 });
      out.push(c.update(part), c.final(), c.getAuthTag());
    }
  }
  return Buffer.concat(out);
}

function ssAddr(host, port) {
  const h = Buffer.from(host, 'utf8');
  const b = Buffer.alloc(1 + 1 + h.length + 2);
  b[0] = 0x03;
  b[1] = h.length;
  h.copy(b, 2);
  b.writeUInt16BE(port, 2 + h.length);
  return b;
}

function testShadowsocks(node, timeout = 7000) {
  return new Promise((resolve) => {
    const p = ssParams(node.method || 'aes-256-gcm');
    if (!p) return resolve({ ok: false, error: '不支持的 Shadowsocks 加密方式', at: Date.now() });
    if (!node.password) return resolve({ ok: false, error: 'Shadowsocks 密码为空', at: Date.now() });
    const master = evpBytesToKey(node.password, p.keyLen);
    const start = Date.now();
    let settled = false;
    let sock;
    const finish = (ok, error) => {
      if (settled) return;
      settled = true;
      try { sock && sock.destroy(); } catch {}
      resolve({ ok, error: error || null, latency: ok ? Date.now() - start : null, at: Date.now() });
    };
    try {
      sock = net.connect({ host: node.host, port: Number(node.port) || 0 });
    } catch (e) {
      return finish(false, e.message);
    }
    sock.setTimeout(timeout, () => finish(false, 'Timeout'));
    sock.on('error', (e) => finish(false, e.code || e.message));
    sock.on('connect', () => {
      try {
        const salt = crypto.randomBytes(p.saltLen);
        const sub = ssSubkey(master, salt, p.keyLen);
        const request = Buffer.concat([
          ssAddr('www.gstatic.com', 80),
          Buffer.from('GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n'),
        ]);
        sock.write(Buffer.concat([salt, ssEncryptChunks(p.alg, sub, request)]));
      } catch (e) {
        finish(false, e.message);
      }
    });
    let received = 0;
    sock.on('data', (d) => {
      received += d.length;
      if (received > p.saltLen + 18) finish(true, null);
    });
  });
}

function testUpstream(node, timeout = 7000) {
  return new Promise((resolve) => {
    if (!node) return resolve({ ok: false, error: '未配置上游' });
    if (node.type === 'shadowsocks') return resolve(testShadowsocks(node, timeout));
    const start = Date.now();
    let settled = false;
    let sock;
    const finish = (ok, error, latency) => {
      if (settled) return;
      settled = true;
      try { sock && sock.destroy(); } catch {}
      resolve({ ok, error: error || null, latency: ok ? (latency || Date.now() - start) : null, at: Date.now() });
    };
    try {
      sock = net.connect({ host: node.host, port: Number(node.port) || 0 });
    } catch (e) {
      return finish(false, e.message);
    }
    sock.setTimeout(timeout, () => finish(false, 'Timeout'));
    sock.on('error', (e) => finish(false, e.code || e.message));
    sock.on('connect', async () => {
      try {
        if (node.type === 'socks5') {
          await socks5Handshake(sock, node);
        } else {
          sock.write(`CONNECT www.gstatic.com:443 HTTP/1.1\r\nHost: www.gstatic.com:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
          let buf = '';
          sock.setEncoding('latin1');
          const readHead = () => new Promise((res, rej) => {
            const onData = (d) => {
              buf += d;
              const idx = buf.indexOf('\r\n\r\n');
              if (idx >= 0) {
                sock.removeListener('data', onData);
                res(buf.slice(0, idx));
              }
            };
            const onErr = (e) => { sock.removeListener('data', onData); rej(e); };
            sock.on('data', onData);
            sock.on('error', onErr);
          });
          const head = await readHead();
          if (!/ 200 /.test(head)) throw new Error(head.split('\r\n')[0] || 'CONNECT 失败');
        }
        const t = tls.connect({ socket: sock, servername: 'www.gstatic.com', rejectUnauthorized: false });
        t.setTimeout(timeout, () => finish(false, 'TLS timeout'));
        t.on('error', (e) => finish(false, e.code || e.message));
        t.on('secureConnect', () => {
          t.write('GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n');
        });
        t.on('data', (d) => {
          if (d.toString('latin1').includes('HTTP/1.')) finish(true, null, Date.now() - start);
        });
      } catch (e) {
        finish(false, e.code || e.message);
      }
    });
  });
}

async function testActiveUpstream(silent = false) {
  const node = activeUpstream();
  if (!node) return;
  const r = await testUpstream(node);
  health.results[node.id] = r;
  health.lastTestAt = r.at;
  if (r.ok) health.activeLatency = r.latency;
  health.availability.push(!!r.ok);
  if (health.availability.length > 20) health.availability.shift();
  if (!silent) sendState(true);
  return r;
}

// ---------------------------------------------------------------------------
// State / IPC helpers
// ---------------------------------------------------------------------------

function publicConfig() {
  const { managed, ...rest } = cfg;
  return rest;
}

let lastManagedSignature = '';
function persistManaged() {
  const list = [...managed.values()].map((r) => ({
    pid: r.pid, path: r.path, name: r.name, terminal: r.terminal,
    dllPath: r.dllPath || null, startedAt: r.startedAt,
  }));
  const sig = list.map((m) => `${m.pid}|${m.path}|${m.terminal}`).join(';');
  if (sig === lastManagedSignature) return;
  lastManagedSignature = sig;
  cfg.managed = list;
  saveConfig();
}

async function restoreManaged() {
  const list = Array.isArray(cfg.managed) ? cfg.managed : [];
  if (!list.length) return;
  await refreshSnapshot();
  for (const m of list) {
    if (!m || !m.pid || !procSnap.has(m.pid)) continue;
    const r = await ctlSafe(['isinjected', String(m.pid)], 5000);
    if (r && r.injected) {
      addManaged(m.pid, { name: m.name, path: m.path, terminal: m.terminal, dllPath: m.dllPath || null });
    }
  }
  persistManaged();
  sendState(true);
}

function terminalInfo() {
  let procs = 0;
  let terms = 0;
  let conns = 0;
  for (const root of managed.values()) {
    const isTerm = root.terminal || /^(cmd|powershell|pwsh|windowsterminal|wt)\.exe$/i.test(path.basename(root.path || root.name || ''));
    if (!isTerm) continue;
    procs++;
    terms += membersOf(root).length;
    conns += aggregate(root).conns;
  }
  return { procs, terms, conns };
}

function buildState(extra = {}) {
  const roots = [];
  let totalUp = 0;
  let totalDown = 0;
  let totalConns = 0;
  for (const root of managed.values()) {
    const agg = aggregate(root);
    totalUp += agg.up;
    totalDown += agg.down;
    totalConns += agg.conns;
    roots.push({
      pid: root.pid,
      name: root.name,
      path: root.path,
      icon: root.icon,
      accent: root.accent,
      terminal: root.terminal,
      up: agg.up,
      down: agg.down,
      conns: agg.conns,
      latency: agg.latency,
      children: Math.max(0, membersOf(root).length - 1),
      members: membersOf(root).length,
      alive: procSnap.has(root.pid),
      startedAt: root.startedAt,
    });
  }
  roots.sort((a, b) => a.startedAt - b.startedAt);

  const availability = health.availability.length
    ? (health.availability.filter(Boolean).length / health.availability.length) * 100
    : null;

  return {
    config: publicConfig(),
    processes: roots,
    terminals: terminalInfo(),
    totals: {
      up: totalUp,
      down: totalDown,
      conns: totalConns,
      dnsBlocked: dnsBlockedTotal,
    },
    history: history.slice(),
    dnsRecords: dnsRecords.slice(0, 60).map((r) => ({
      ts: r.ts, pid: r.pid, rootPid: r.rootPid, domain: r.domain,
      ips: r.ips, status: r.status, proc: r.proc,
    })),
    health: {
      results: health.results,
      activeLatency: health.activeLatency,
      availability,
      lastTestAt: health.lastTestAt,
      samples: health.availability.length,
    },
    tcp: tcpStats,
    stats: {
      nativeReady: fs.existsSync(CTL) && fs.existsSync(DLL_PATH),
      activeNode: activeUpstream(),
    },
    now: Date.now(),
    ...extra,
  };
}

function sendState(force = false) {
  const now = Date.now();
  if (!force && now - lastStateSentAt < 700) return;
  lastStateSentAt = now;
  if (win && !win.isDestroyed()) win.webContents.send('state', buildState());
}

function toast(message, type = 'info') {
  if (win && !win.isDestroyed()) win.webContents.send('toast', { message, type });
}

function sampleHistory() {
  let total = 0;
  for (const root of managed.values()) {
    const agg = aggregate(root);
    total += agg.up + agg.down;
  }
  const now = Date.now();
  const dt = Math.max(0.2, (now - lastSampleAt) / 1000);
  let rate = 0;
  if (lastTotalBytes > 0 && total >= lastTotalBytes) {
    rate = (total - lastTotalBytes) / dt;
  }
  lastTotalBytes = total;
  lastSampleAt = now;
  history.push(rate);
  if (history.length > 60) history.shift();
}

// ---------------------------------------------------------------------------
// Signed updates
// ---------------------------------------------------------------------------

let updateCache = null;

function semverGt(a, b) {
  const pa = String(a || '0').split('.').map((x) => parseInt(x, 10) || 0);
  const pb = String(b || '0').split('.').map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x !== y) return x > y;
  }
  return false;
}

async function fetchBuffer(url, limit = 64 * 1024 * 1024, redirects = 0) {
  if (!url) throw new Error('空的更新地址');
  let localPath = null;
  if (url.startsWith('file://')) {
    localPath = decodeURIComponent(url.slice(7));
    if (/^\/[A-Za-z]:[\\/]/.test(localPath)) localPath = localPath.slice(1);
  } else if (path.isAbsolute(url)) {
    localPath = url;
  }
  if (localPath) return fsp.readFile(localPath);

  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https:') ? https : http;
    const req = mod.get(url, {
      timeout: 20000,
      headers: { 'user-agent': 'GhostProxifier-Replica-Updater' },
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects < 5) {
        res.resume();
        const next = new URL(res.headers.location, url).toString();
        fetchBuffer(next, limit, redirects + 1).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`更新服务器返回 HTTP ${res.statusCode}`));
        return;
      }
      const chunks = [];
      let total = 0;
      res.on('data', (c) => {
        total += c.length;
        if (total > limit) {
          req.destroy(new Error('更新文件过大'));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('更新服务器超时')));
    req.on('error', reject);
  });
}

function verifySignedManifest(manifestBytes, sigBytes) {
  if (!UPDATE_ROOT_PUB) throw new Error('缺少内置更新根公钥');
  let sig;
  try { sig = JSON.parse(sigBytes.toString('utf8')); }
  catch { throw new Error('签名文件不是有效 JSON'); }
  if (!sig.cert || !sig.certSig || !sig.sig) throw new Error('签名文件字段缺失');

  const certDer = Buffer.from(sig.cert, 'base64');
  const certSig = Buffer.from(sig.certSig, 'base64');
  const manifestSig = Buffer.from(sig.sig, 'base64');

  if (!crypto.verify('sha256', certDer, UPDATE_ROOT_PUB, certSig)) {
    throw new Error('更新证书签名无效');
  }
  let cert;
  try { cert = new crypto.X509Certificate(certDer); }
  catch { throw new Error('更新证书格式无效'); }

  const now = Date.now();
  if (now < Date.parse(cert.validFrom) || now > Date.parse(cert.validTo)) {
    throw new Error('更新证书不在有效期内');
  }
  const revoked = (Array.isArray(cfg.general.revokedCerts) ? cfg.general.revokedCerts : [])
    .map((x) => String(x).toLowerCase());
  if (revoked.includes(String(cert.fingerprint256).toLowerCase())) {
    throw new Error('更新证书已被吊销');
  }
  if (!crypto.verify('sha256', manifestBytes, cert.publicKey, manifestSig)) {
    throw new Error('更新清单签名无效');
  }
  let manifest;
  try { manifest = JSON.parse(manifestBytes.toString('utf8')); }
  catch { throw new Error('更新清单不是有效 JSON'); }
  return { cert, manifest };
}

function isLocalUpdateUrl(url) {
  return /^(file:|[A-Za-z]:[\\/]|\/)/.test(String(url || ''));
}

function validateManifest(m, manifestUrl) {
  if (!m || typeof m !== 'object') throw new Error('更新清单格式错误');
  if (String(m.sku || '') !== String(cfg.general.updateSku || 'personal')) {
    throw new Error('更新 SKU 与本机不匹配');
  }
  if (!/^\d+\.\d+\.\d+$/.test(String(m.version || ''))) {
    throw new Error('更新版本号格式错误');
  }
  const size = Number(m.size);
  if (!Number.isInteger(size) || size <= 0 || size > 500 * 1024 * 1024) {
    throw new Error('更新包大小不合法');
  }
  if (!/^[a-f0-9]{64}$/.test(String(m.sha256 || ''))) {
    throw new Error('更新包 SHA-256 不合法');
  }
  if (m.notesUrl && !/^https?:\/\//.test(String(m.notesUrl))) {
    throw new Error('更新说明地址不合法');
  }
  if (!m.url) throw new Error('更新包地址为空');

  if (isLocalUpdateUrl(manifestUrl)) {
    if (!isLocalUpdateUrl(m.url) && !/^https?:\/\//.test(String(m.url))) {
      throw new Error('本地更新清单指向了无效的更新包地址');
    }
  } else {
    if (!/^https:\/\//.test(String(m.url))) {
      throw new Error('更新包必须使用 HTTPS');
    }
    const allowed = Array.isArray(cfg.general.updateAllowedPrefixes) &&
      cfg.general.updateAllowedPrefixes.length
      ? cfg.general.updateAllowedPrefixes
      : ['https://github.com/'];
    if (!allowed.some((p) => String(m.url).startsWith(p))) {
      throw new Error('更新包地址不在允许的前缀内');
    }
  }
}

async function checkUpdate(manual = false) {
  const url = String(cfg.general.updateUrl || '').trim();
  if (!url) {
    if (manual) throw new Error('尚未配置更新地址');
    return { ok: true, available: false, reason: 'no-url', current: app.getVersion() };
  }
  const manifestBytes = await fetchBuffer(url, 2 * 1024 * 1024);
  const sigBytes = await fetchBuffer(url + '.sig', 128 * 1024);
  const { manifest } = verifySignedManifest(manifestBytes, sigBytes);
  validateManifest(manifest, url);

  const current = app.getVersion();
  const available = semverGt(manifest.version, current);
  updateCache = { manifest, url, fetchedAt: Date.now(), available };
  return {
    ok: true,
    available,
    current,
    version: manifest.version,
    notesUrl: manifest.notesUrl || '',
    size: manifest.size,
    sha256: manifest.sha256,
    url: manifest.url,
    sku: manifest.sku,
  };
}

async function downloadVerifiedPackage(m) {
  const buf = await fetchBuffer(m.url, Math.min(Number(m.size) + 1024, 500 * 1024 * 1024));
  if (buf.length !== Number(m.size)) throw new Error('更新包大小与清单不一致');
  const hash = crypto.createHash('sha256').update(buf).digest('hex');
  if (hash !== String(m.sha256)) throw new Error('更新包 SHA-256 与清单不一致');
  return buf;
}

async function installUpdate() {
  if (!app.isPackaged && process.env.GPP_ALLOW_DEV_UPDATE !== '1') {
    throw new Error('开发模式不执行自更新；请用打包版或设置 GPP_ALLOW_DEV_UPDATE=1');
  }
  let info = updateCache;
  if (!info || !info.available) {
    info = await checkUpdate();
    if (!info.available) throw new Error('当前已是最新版本');
  }
  const m = info.manifest;
  const buf = await downloadVerifiedPackage(m);
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'gpp-update-'));
  const lower = String(m.url).toLowerCase();

  if (lower.endsWith('.zip')) {
    const zip = path.join(tmpDir, 'update.zip');
    await fsp.writeFile(zip, buf);
    const appRoot = path.dirname(process.execPath);
    const exe = process.execPath;
    const ps1 = path.join(tmpDir, 'apply.ps1');
    const q = (s) => String(s).replace(/'/g, "''");
    const script = [
      "$ErrorActionPreference = 'Stop'",
      `Wait-Process -Id ${process.pid} -Timeout 60 -ErrorAction SilentlyContinue`,
      'Start-Sleep -Milliseconds 1000',
      `Expand-Archive -Path '${q(zip)}' -DestinationPath '${q(appRoot)}' -Force`,
      `Start-Process -FilePath '${q(exe)}'`,
    ].join('\r\n');
    await fsp.writeFile(ps1, script, 'utf8');
    const child = spawn('powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ps1],
      { detached: true, stdio: 'ignore', windowsHide: true });
    child.unref();
    setTimeout(() => { quitting = true; app.quit(); }, 600);
    return { ok: true, installing: true, version: m.version };
  }

  if (lower.endsWith('.msi')) {
    const msi = path.join(tmpDir, 'update.msi');
    await fsp.writeFile(msi, buf);
    const child = spawn('msiexec.exe', ['/i', msi, '/passive', '/norestart'],
      { detached: true, stdio: 'ignore', windowsHide: true });
    child.unref();
    setTimeout(() => { quitting = true; app.quit(); }, 600);
    return { ok: true, installing: true, version: m.version };
  }

  throw new Error('不支持的更新包格式（仅 .zip / .msi）');
}

// ---------------------------------------------------------------------------
// WinStore / UWP
// ---------------------------------------------------------------------------

let uwpAppsCache = null;
let uwpAppsCacheAt = 0;

async function prepareUwpNative() {
  if (!fs.existsSync(DLL_PATH)) return null;
  const candidates = [
    path.join(process.env.ProgramData || 'C:\\ProgramData', 'GhostProxifier'),
    path.join(process.env.PUBLIC || 'C:\\Users\\Public', 'GhostProxifier'),
    path.join(app.getPath('userData'), 'uwp-native'),
  ];
  const srcSize = fs.statSync(DLL_PATH).size;
  for (const dir of candidates) {
    try {
      fs.mkdirSync(dir, { recursive: true });
      const dst = path.join(dir, 'gpp_core_x64.dll');
      let needCopy = true;
      try { needCopy = fs.statSync(dst).size !== srcSize; } catch {}
      if (needCopy) fs.copyFileSync(DLL_PATH, dst);
      // ALL APPLICATION PACKAGES needs read/execute so an AppContainer can
      // load the DLL. Non-elevated accounts may fail on ProgramData; the
      // next candidate is tried.
      try {
        await execFileAsync('icacls.exe', [
          dir, '/grant', '*S-1-15-2-1:(OI)(CI)(RX)', '/T', '/Q',
        ], { windowsHide: true, timeout: 15000 });
      } catch {}
      uwpNativeDir = dir;
      await writeIni();
      return dir;
    } catch (e) {
      console.error('prepareUwpNative candidate failed', dir, e.message);
    }
  }
  return null;
}

async function listUwpApps() {
  if (uwpAppsCache && Date.now() - uwpAppsCacheAt < 60000) return uwpAppsCache;
  const tmp = path.join(os.tmpdir(), `gpp-uwp-apps-${process.pid}.json`);
  try {
    // Write the JSON with .NET's UTF-8 encoder. Reading PowerShell stdout
    // through a pipe depends on the console code page and garbles Chinese
    // display names on non-UTF-8 systems.
    const q = tmp.replace(/'/g, "''");
    const ps = [
      "$apps = Get-StartApps | Where-Object { $_.AppID -like '*!*' } | Select-Object Name,AppID",
      `[IO.File]::WriteAllText('${q}', (ConvertTo-Json $apps -Compress), (New-Object System.Text.UTF8Encoding $false))`,
    ].join('; ');
    await execFileAsync('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', ps],
      { windowsHide: true, timeout: 20000 });
    const raw = await fsp.readFile(tmp, 'utf8');
    let arr = JSON.parse(raw || '[]');
    if (!Array.isArray(arr)) arr = [arr];
    const seen = new Set();
    const apps = [];
    for (const a of arr) {
      if (!a || !a.AppID || !a.Name) continue;
      const id = String(a.AppID);
      const key = id + '|' + a.Name;
      if (seen.has(key)) continue;
      seen.add(key);
      apps.push({ name: String(a.Name), appId: id });
    }
    apps.sort((a, b) => a.name.localeCompare(b.name));
    uwpAppsCache = apps;
    uwpAppsCacheAt = Date.now();
    return apps;
  } catch (e) {
    console.error('listUwpApps failed:', e.message);
    return [];
  } finally {
    fsp.rm(tmp, { force: true }).catch(() => {});
  }
}

function findUwpPid(appId) {
  const family = String(appId).split('!')[0];
  const pkg = family.split('_')[0].toLowerCase();
  const candidates = [...procSnap.values()].filter((p) =>
    p.path && /\\windowsapps\\/i.test(p.path) && p.path.toLowerCase().includes(pkg));
  if (!candidates.length) return null;
  const pids = new Set(candidates.map((p) => p.pid));
  const root = candidates.find((p) => !pids.has(p.ppid));
  return root ? root.pid : candidates[0].pid;
}

async function launchUwp(appId, name) {
  if (!appId) return { ok: false, error: '缺少 AppID' };
  const dir = await prepareUwpNative();
  if (!dir) return { ok: false, error: '无法准备 AppContainer 可读的原生组件目录' };
  const dll = path.join(dir, 'gpp_core_x64.dll');

  const act = await ctlSafe(['uwp', appId], 20000);
  let pid = act && act.pid ? Number(act.pid) : 0;
  if (!pid) {
    await new Promise((r) => setTimeout(r, 1200));
    await refreshSnapshot();
    pid = findUwpPid(appId) || 0;
  }
  if (!pid) {
    return { ok: false, error: (act && act.error) || '应用已启动，但未找到进程 PID' };
  }

  let injected = null;
  for (let i = 0; i < 6; i++) {
    await new Promise((r) => setTimeout(r, i === 0 ? 400 : 700));
    const ins = await ctlSafe(['inject', String(pid), '--dll', dll], 20000);
    if (ins && ins.ok) { injected = ins; break; }
    await refreshSnapshot();
    const p2 = findUwpPid(appId);
    if (p2 && p2 !== pid) pid = p2;
  }
  if (!injected) {
    return {
      ok: false,
      error: 'UWP 进程注入失败（AppContainer/ACG 保护或权限不足）。请以管理员身份运行本程序后重试。',
    };
  }
  addManaged(pid, { name: name || appId, path: '', terminal: false, dllPath: dll });
  sendState(true);
  return { ok: true, pid, uwpDir: dir };
}

// ---------------------------------------------------------------------------
// IPC handlers
// ---------------------------------------------------------------------------

function registerIpc() {
  ipcMain.handle('get-bootstrap', () => ({
    ...buildState(),
    logs: logs.slice(-200),
    version: app.getVersion(),
    platform: process.platform,
    nativeDir: NATIVE_DIR,
    configPath: CONFIG_PATH,
  }));

  ipcMain.handle('refresh', async () => {
    await refreshSnapshot();
    sendState(true);
    return buildState();
  });

  ipcMain.handle('add-paths', async (e, paths) => {
    const list = (Array.isArray(paths) ? paths : [paths]).filter((p) => typeof p === 'string');
    const r = await addPaths(list);
    for (const x of r) {
      if (x.needsChoice) {
        if (win && !win.isDestroyed()) win.webContents.send('needs-choice', x);
      } else if (!x.ok) toast(`${path.basename(x.path)}：${x.error}`, 'error');
      else toast(`${path.basename(x.path)} 已接管`, 'success');
    }
    return r;
  });

  ipcMain.on('paths-dropped', async (e, paths) => {
    const list = (Array.isArray(paths) ? paths : []).filter((p) => typeof p === 'string');
    if (!list.length) return;
    const r = await addPaths(list);
    for (const x of r) {
      if (x.needsChoice) {
        if (win && !win.isDestroyed()) win.webContents.send('needs-choice', x);
      } else if (!x.ok) toast(`${path.basename(x.path)}：${x.error}`, 'error');
      else toast(`${path.basename(x.path)} 已接管`, 'success');
    }
  });

  ipcMain.handle('close-and-relaunch', async (e, req) => {
    const target = String(req?.target || '');
    if (!target) return { ok: false, error: '无效路径' };
    await refreshSnapshot();
    const requested = Array.isArray(req.pids) ? req.pids : [];
    const toKill = requested.filter((pid) => {
      const p = procSnap.get(pid);
      return p && samePath(p.path, target);
    });
    for (const pid of toKill) {
      try {
        await execFileAsync('taskkill.exe', ['/PID', String(pid), '/T', '/F'], { windowsHide: true, timeout: 6000 });
      } catch {}
    }
    // Wait for the singleton processes to really go away.
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline) {
      await new Promise((r2) => setTimeout(r2, 400));
      await refreshSnapshot();
      const still = [...procSnap.values()].some((p) => p.path && samePath(p.path, target));
      if (!still) break;
    }
    const still = [...procSnap.values()].some((p) => p.path && samePath(p.path, target));
    if (still) return { ok: false, error: '部分进程尚未退出，请稍后重试或手动关闭' };

    const args = ['run', target, ...(req.args || []), `--cwd=${req.cwd || path.dirname(target)}`];
    if (req.console) args.push('--console');
    const res = await ctlSafe(args, 30000);
    if (res && res.ok) {
      addManaged(res.pid, { name: req.name || path.basename(target), path: target, terminal: !!req.console });
      sendState(true);
      return { ok: true, pid: res.pid };
    }
    return { ok: false, error: (res && res.error) || '重新启动注入失败' };
  });

  ipcMain.handle('pick-executable', async () => {
    const r = await dialog.showOpenDialog(win, {
      title: '选择要代理的程序',
      properties: ['openFile'],
      filters: [
        { name: '程序或快捷方式', extensions: ['exe', 'lnk', 'bat', 'cmd'] },
        { name: '所有文件', extensions: ['*'] },
      ],
    });
    if (r.canceled || !r.filePaths.length) return null;
    return addPaths(r.filePaths);
  });

  ipcMain.handle('check-update', async () => {
    try { return await checkUpdate(true); }
    catch (e) { return { ok: false, error: e.message }; }
  });

  ipcMain.handle('install-update', async () => {
    try { return await installUpdate(); }
    catch (e) { return { ok: false, error: e.message }; }
  });

  ipcMain.handle('uwp-apps', async () => ({ ok: true, apps: await listUwpApps() }));

  ipcMain.handle('launch-uwp', async (e, appId, name) => {
    const r = await launchUwp(String(appId || ''), String(name || ''));
    if (r.ok) toast(`${name || 'WinStore 应用'} 已接管`, 'success');
    else toast(r.error || 'WinStore 注入失败', 'error');
    return r;
  });

  ipcMain.handle('smart-scan', async () => {
    await refreshSnapshot();
    const items = [];
    const managedPids = new Set();
    for (const root of managed.values()) for (const p of membersOf(root)) managedPids.add(p);
    const list = [...procSnap.values()].filter((p) => p.path && p.pid !== process.pid && !managedPids.has(p.pid));
    const groups = new Map();
    for (const p of list) {
      const lower = String(p.name).toLowerCase();
      if (SYSTEM_NAMES.has(lower)) continue;
      if (!p.path) continue;
      if (/\\windows\\(system32|syswow64|systemapps|servicing|winsxs)\\/i.test(p.path)) continue;
      if (/\\windowsapps\\/i.test(p.path)) continue;
      const key = lower + '|' + p.path.toLowerCase();
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(p);
    }
    // One entry per running instance: keep only the tree root for each exe.
    for (const group of groups.values()) {
      const pids = new Set(group.map((p) => p.pid));
      let roots = group.filter((p) => !pids.has(p.ppid));
      if (!roots.length) roots = [group[0]];
      for (const root of roots) {
        items.push({ pid: root.pid, name: root.name, path: root.path, injected: false, procs: group.length });
        if (items.length >= 60) break;
      }
      if (items.length >= 60) break;
    }
    items.sort((a, b) => a.name.localeCompare(b.name));
    // Generate icons concurrently; sequential getFileIcon calls made the
    // smart-scan modal take seconds to populate.
    await Promise.all(items.slice(0, 40).map(async (it) => {
      it.icon = await iconFor(it.path);
    }));
    return items;
  });

  ipcMain.handle('inject', async (e, pid) => {
    const r = await injectPid(Number(pid));
    toast(r.ok ? '注入成功' : (r.error || '注入失败'), r.ok ? 'success' : 'error');
    return r;
  });

  ipcMain.handle('launch', async (e, target, opts = {}) => {
    if (typeof target !== 'string') return { ok: false, error: '无效路径' };
    const r = await resolveTarget(target);
    if (!r.ok) { toast(r.error, 'error'); return r; }
    const args = ['run', r.target, ...(r.args || []), `--cwd=${r.cwd || path.dirname(r.target)}`];
    if (opts.console || r.console) args.push('--console');
    const res = await ctlSafe(args, 30000);
    if (res && res.ok) {
      addManaged(res.pid, { name: r.name, path: r.target, terminal: !!(opts.console || r.console) });
      sendState(true);
      toast(`${r.name} 已接管`, 'success');
      return { ok: true, pid: res.pid };
    }
    const err = (res && res.error) || '启动注入失败';
    toast(err, 'error');
    return { ok: false, error: err };
  });

  ipcMain.handle('launch-terminal', async (e, kind) => {
    const sys = process.env.SystemRoot || 'C:\\Windows';
    const isPs = kind === 'powershell';
    const target = isPs
      ? path.join(sys, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
      : path.join(sys, 'System32', 'cmd.exe');
    const res = await ctlSafe(['run', target, '--console', '--cwd=' + os.homedir()], 30000);
    if (res && res.ok) {
      addManaged(res.pid, { name: isPs ? 'PowerShell' : 'CMD', path: target, terminal: true });
      sendState(true);
      toast(`${isPs ? 'PowerShell' : 'CMD'} 终端已接管`, 'success');
      return { ok: true, pid: res.pid };
    }
    const err = (res && res.error) || '终端启动失败';
    toast(err, 'error');
    return { ok: false, error: err };
  });

  ipcMain.handle('stop-managing', async (e, pid) => {
    removeManaged(Number(pid));
    sendState(true);
    return { ok: true };
  });

  ipcMain.handle('settings-save', async (e, patch) => {
    mergeConfig(cfg, patch || {});
    cfg.general.language = cfg.language || cfg.general.language || 'zh';
    saveConfig();
    await writeIni();
    sendState(true);
    toast('设置已保存', 'success');
    return { ok: true, config: cfg };
  });

  ipcMain.handle('language-set', async (e, lang) => {
    cfg.language = lang === 'en' ? 'en' : 'zh';
    saveConfig();
    sendState(true);
    return { ok: true };
  });

  ipcMain.handle('upstream-add', async (e, node) => {
    const id = 'u' + Date.now().toString(36);
    const item = {
      id,
      name: String(node.name || '新节点').trim() || '新节点',
      type: ['socks5', 'shadowsocks'].includes(node.type) ? node.type : 'http',
      host: String(node.host || '127.0.0.1').trim(),
      port: Number(node.port) || 2080,
      username: String(node.username || ''),
      password: String(node.password || ''),
      method: String(node.method || 'aes-256-gcm'),
    };
    cfg.upstreams.push(item);
    if (node.activate) cfg.activeUpstreamId = id;
    saveConfig();
    await writeIni();
    sendState(true);
    testUpstream(item).then((r) => {
      health.results[id] = r;
      if (node.activate) {
        health.activeLatency = r.ok ? r.latency : null;
        health.availability = [!!r.ok];
      }
      sendState(true);
    });
    return { ok: true, node: item };
  });

  ipcMain.handle('upstream-update', async (e, id, patch) => {
    const node = cfg.upstreams.find((u) => u.id === id);
    if (!node) return { ok: false, error: '节点不存在' };
    Object.assign(node, {
      name: String(patch.name ?? node.name).trim() || node.name,
      type: ['socks5', 'shadowsocks'].includes(patch.type) ? patch.type : (patch.type === 'http' ? 'http' : node.type),
      host: String(patch.host ?? node.host).trim(),
      port: Number(patch.port ?? node.port) || node.port,
      username: String(patch.username ?? node.username),
      password: String(patch.password ?? node.password),
      method: String(patch.method ?? node.method ?? 'aes-256-gcm'),
    });
    if (patch.activate) cfg.activeUpstreamId = id;
    saveConfig();
    await writeIni();
    sendState(true);
    return { ok: true, node };
  });

  ipcMain.handle('upstream-remove', async (e, id) => {
    const idx = cfg.upstreams.findIndex((u) => u.id === id);
    if (idx < 0) return { ok: false, error: '节点不存在' };
    if (cfg.upstreams.length <= 1) return { ok: false, error: '至少保留一个节点' };
    cfg.upstreams.splice(idx, 1);
    if (cfg.activeUpstreamId === id) cfg.activeUpstreamId = cfg.upstreams[0].id;
    saveConfig();
    await writeIni();
    sendState(true);
    return { ok: true };
  });

  ipcMain.handle('upstream-activate', async (e, id) => {
    if (!cfg.upstreams.find((u) => u.id === id)) return { ok: false, error: '节点不存在' };
    cfg.activeUpstreamId = id;
    saveConfig();
    await writeIni();
    health.availability = [];
    health.activeLatency = null;
    sendState(true);
    toast(`已切换到 ${cfg.upstreams.find((u) => u.id === id).name}`, 'success');
    testActiveUpstream(true).then(() => sendState(true));
    return { ok: true };
  });

  ipcMain.handle('upstream-test', async (e, id) => {
    const node = cfg.upstreams.find((u) => u.id === id);
    if (!node) return { ok: false, error: '节点不存在' };
    const r = await testUpstream(node);
    health.results[id] = r;
    if (id === cfg.activeUpstreamId) {
      health.activeLatency = r.ok ? r.latency : null;
      health.availability.push(!!r.ok);
      if (health.availability.length > 20) health.availability.shift();
      health.lastTestAt = r.at;
    }
    sendState(true);
    return r;
  });

  ipcMain.handle('upstream-test-all', async () => {
    const list = cfg.upstreams.slice();
    const results = {};
    await Promise.all(list.map(async (n) => {
      results[n.id] = await testUpstream(n);
    }));
    for (const [id, r] of Object.entries(results)) health.results[id] = r;
    const active = activeUpstream();
    if (active && results[active.id]) {
      health.activeLatency = results[active.id].ok ? results[active.id].latency : null;
      health.availability.push(!!results[active.id].ok);
      if (health.availability.length > 20) health.availability.shift();
      health.lastTestAt = results[active.id].at;
    }
    sendState(true);
    return results;
  });

  ipcMain.handle('dns-set', async (e, server, port) => {
    const s = String(server || '').trim();
    if (!s) return { ok: false, error: '请输入 DNS 服务器' };
    cfg.dns.server = s;
    cfg.dns.port = Number(port) || 53;
    saveConfig();
    await writeIni();
    sendState(true);
    toast('DNS 配置已更新', 'success');
    return { ok: true };
  });

  ipcMain.handle('dns-proxy-toggle', async (e, enabled) => {
    cfg.dns.mode = enabled ? 'proxy' : 'system';
    saveConfig();
    await writeIni();
    sendState(true);
    return { ok: true };
  });

  ipcMain.handle('export-report', async () => {
    const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
    const r = await dialog.showSaveDialog(win, {
      title: '导出流量报表',
      defaultPath: path.join(app.getPath('downloads'), `ghost-traffic-${stamp}.csv`),
      filters: [{ name: 'CSV', extensions: ['csv'] }],
    });
    if (r.canceled || !r.filePath) return { ok: false };
    const rows = [['进程', 'PID', '下载(字节)', '上传(字节)', '连接数', '延迟(ms)']];
    let up = 0, down = 0, conns = 0;
    for (const root of managed.values()) {
      const a = aggregate(root);
      up += a.up; down += a.down; conns += a.conns;
      rows.push([root.name, root.pid, a.up, a.down, a.conns, a.latency == null ? '' : a.latency]);
    }
    rows.push([]);
    rows.push(['总计', '', down, up, conns, '']);
    rows.push(['DNS 拦截', dnsBlockedTotal, '', '', '', '']);
    const csv = '\uFEFF' + rows.map((r2) => r2.map((x) => `"${String(x ?? '').replace(/"/g, '""')}"`).join(',')).join('\r\n');
    await fsp.writeFile(r.filePath, csv, 'utf8');
    shell.showItemInFolder(r.filePath);
    toast('报表已导出', 'success');
    return { ok: true, path: r.filePath };
  });

  ipcMain.handle('export-diagnostics', async () => {
    const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
    const dir = path.join(app.getPath('temp'), `ghost-diag-${stamp}`);
    await fsp.mkdir(dir, { recursive: true });
    const redacted = JSON.parse(JSON.stringify(cfg));
    for (const u of redacted.upstreams) u.password = u.password ? '***' : '';
    const safe = (o) => JSON.stringify(o, null, 2);
    await fsp.writeFile(path.join(dir, 'config.json'), safe(redacted), 'utf8');
    await fsp.writeFile(path.join(dir, 'logs.txt'), logs.map((l) => `[${new Date(l.ts).toISOString()}] [${l.pid}] [${l.tag}] ${l.text}`).join('\n'), 'utf8');
    await fsp.writeFile(path.join(dir, 'processes.json'), safe([...managed.values()].map((r) => ({
      pid: r.pid, name: r.name, path: r.path, terminal: r.terminal,
      members: membersOf(r), stats: aggregate(r),
    }))), 'utf8');
    await fsp.writeFile(path.join(dir, 'system-info.txt'), [
      `app: Ghost Proxifier replica ${app.getVersion()}`,
      `electron: ${process.versions.electron}`,
      `chrome: ${process.versions.chrome}`,
      `node: ${process.versions.node}`,
      `os: ${os.type()} ${os.release()} ${os.arch()}`,
      `userData: ${app.getPath('userData')}`,
      `native: ${NATIVE_DIR}`,
      `nativeReady: ${fs.existsSync(CTL) && fs.existsSync(DLL_PATH)}`,
      `time: ${new Date().toISOString()}`,
    ].join('\n'), 'utf8');
    const zipPath = path.join(app.getPath('downloads'), `ghost-diagnostics-${stamp}.zip`);
    try {
      await fsp.rm(zipPath, { force: true });
      const ps = `Compress-Archive -Path '${dir.replace(/'/g, "''")}\\*' -DestinationPath '${zipPath.replace(/'/g, "''")}' -Force`;
      await execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], { windowsHide: true, timeout: 30000 });
      shell.showItemInFolder(zipPath);
      toast('排障包已导出', 'success');
      return { ok: true, path: zipPath };
    } catch (e) {
      return { ok: true, path: dir, warning: '压缩失败，已保留文件夹：' + e.message };
    }
  });

  ipcMain.handle('run-diagnostics', async () => {
    const node = activeUpstream();
    const up = node ? await testUpstream(node) : { ok: false, error: '未配置上游' };
    const tcp = await ctlSafe(['tcpstats'], 5000);
    const checks = [
      { name: '原生组件', ok: fs.existsSync(CTL) && fs.existsSync(DLL_PATH), detail: NATIVE_DIR },
      { name: '上游节点', ok: !!up.ok, detail: up.ok ? `${up.latency} ms` : (up.error || '失败') },
      { name: 'DNS 代理', ok: cfg.dns.mode === 'proxy', detail: `${cfg.dns.server}:${cfg.dns.port}` },
      { name: '托管进程', ok: managed.size > 0, detail: `${managed.size} 个` },
      { name: 'TCP 重传率', ok: tcp.ok !== false, detail: tcp.ok ? `${(tcp.retransRate || 0).toFixed(2)}%` : '读取失败' },
    ];
    return { ok: checks.every((c) => c.ok || c.name === '托管进程'), checks, upstream: up, tcp };
  });

  ipcMain.handle('open-path', async (e, p) => {
    if (typeof p !== 'string' || !p) return { ok: false };
    if (fs.existsSync(p)) {
      const stat = fs.statSync(p);
      if (stat.isDirectory()) await shell.openPath(p);
      else shell.showItemInFolder(p);
    }
    return { ok: true };
  });

  ipcMain.handle('open-external', async (e, url) => {
    if (typeof url === 'string' && /^https?:\/\//.test(url)) await shell.openExternal(url);
    return { ok: true };
  });

  ipcMain.handle('get-licenses', () => {
    const base = IS_PACKAGED ? path.join(process.resourcesPath, 'licenses') : path.join(ROOT, 'native');
    const read = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } };
    return {
      ghost: read(IS_PACKAGED
        ? path.join(base, 'LICENSE.ghost-proxifier')
        : path.join(base, 'core', 'LICENSE.ghost-proxifier')),
      minhook: read(IS_PACKAGED
        ? path.join(base, 'LICENSE.minhook')
        : path.join(base, 'minhook', 'LICENSE.txt')),
    };
  });
}

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------

async function tick() {
  sampleHistory();
  sendState();
}

async function slowTick() {
  await refreshSnapshot();
  await refreshTrees();
  persistManaged();
  sendState(true);
}

async function tcpTick() {
  const r = await ctlSafe(['tcpstats'], 4000);
  if (r && r.ok) tcpStats = { outSegs: r.outSegs, retransSegs: r.retransSegs, retransRate: r.retransRate };
}

let watchdogBusy = false;
const watchdogRetryAt = new Map();
let lastWatchdogProxyOk = null;

function watchdogLog(text) {
  const entry = { ts: Date.now(), pid: 0, tag: 'Watchdog', text, rel: '' };
  logs.push(entry);
  if (logs.length > 1200) logs = logs.slice(-900);
  if (win && !win.isDestroyed()) win.webContents.send('log', entry);
}

async function watchdogTick() {
  if (watchdogBusy || cfg.general.watchdog === false) return;
  watchdogBusy = true;
  try {
    const node = activeUpstream();
    const h = node ? health.results[node.id] : null;
    const ok = h ? !!h.ok : null;
    if (ok !== null && lastWatchdogProxyOk !== null && ok !== lastWatchdogProxyOk) {
      watchdogLog(ok
        ? `上游 ${node.name} 已恢复`
        : `上游 ${node.name} 不可用：${h.error || ''}`);
    }
    lastWatchdogProxyOk = ok;

    for (const root of [...managed.values()]) {
      if (!procSnap.has(root.pid)) continue;
      const retryAt = watchdogRetryAt.get(root.pid) || 0;
      if (Date.now() < retryAt) continue;
      const s = statsByPid.get(root.pid);
      if (s && Date.now() - s.at < 20000) continue;
      const inj = await ctlSafe(['isinjected', String(root.pid)], 6000);
      if (inj && inj.injected) continue;
      const args = ['inject', String(root.pid)];
      if (root.dllPath) args.push('--dll', root.dllPath);
      const res = await ctlSafe(args, 20000);
      if (res && res.ok) {
        root.injectedPids.add(root.pid);
        pidToRoot.set(root.pid, root.pid);
        watchdogLog(`已重新注入 ${root.name} (PID ${root.pid})`);
      } else {
        watchdogRetryAt.set(root.pid, Date.now() + 60000);
        watchdogLog(`Watchdog 重新注入 ${root.name} 失败：${(res && res.error) || ''}`);
      }
    }
  } finally {
    watchdogBusy = false;
  }
}

function createWindow() {
  win = new BrowserWindow({
    width: 1592,
    height: 895,
    minWidth: 1180,
    minHeight: 720,
    title: 'Ghost Proxifier',
    backgroundColor: '#080b0c',
    icon: ICON_PATH,
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });
  win.setMenuBarVisibility(false);
  win.loadFile(path.join(__dirname, 'src', 'index.html'));
  win.once('ready-to-show', () => win.show());
  win.on('close', (e) => {
    if (!quitting && cfg.general.closeToTray) {
      e.preventDefault();
      win.hide();
    }
  });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
}

function createTray() {
  try {
    const img = nativeImage.createFromPath(ICON_PATH);
    tray = new Tray(img.isEmpty() ? nativeImage.createEmpty() : img);
    tray.setToolTip('Ghost Proxifier');
    const rebuild = () => {
      tray.setContextMenu(Menu.buildFromTemplate([
        { label: '显示主界面', click: () => { win.show(); win.focus(); } },
        { type: 'separator' },
        { label: '退出', click: () => { quitting = true; app.quit(); } },
      ]));
    };
    rebuild();
    tray.on('double-click', () => { win.show(); win.focus(); });
  } catch (e) {
    console.error('tray failed', e);
  }
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (win) { win.show(); win.focus(); }
  });

  app.whenReady().then(async () => {
    loadConfig();
    saveConfig();
    await writeIni();
    registerIpc();
    startUdpListeners();
    createWindow();
    createTray();

    setTimeout(() => { slowTick(); }, 500);
    setTimeout(() => { restoreManaged(); }, 900);
    setTimeout(() => { testActiveUpstream(true); }, 1500);
    setTimeout(async () => {
      if (cfg.general.autoCheckUpdates === false) return;
      if (!String(cfg.general.updateUrl || '').trim()) return;
      try {
        const r = await checkUpdate(false);
        if (r.available) {
          toast(`发现新版本 ${r.version}`, 'info');
          if (win && !win.isDestroyed()) win.webContents.send('update-available', r);
        }
      } catch (e) {
        console.error('auto update check failed:', e.message);
      }
    }, 12000);
    setInterval(tick, 1000);
    setInterval(slowTick, 2400);
    setInterval(tcpTick, 5000);
    setInterval(watchdogTick, 5000);
    setInterval(() => testActiveUpstream(true), 30000);

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
      else win.show();
    });
  });

  app.on('window-all-closed', (e) => {
    // Keep running in the tray; quit only via tray menu or when closeToTray is off.
    if (!cfg.general.closeToTray) app.quit();
  });

  app.on('before-quit', () => {
    quitting = true;
    try { statsSock && statsSock.close(); } catch {}
    try { logSock && logSock.close(); } catch {}
    try { tray && tray.destroy(); } catch {}
  });
}
