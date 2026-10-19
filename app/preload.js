'use strict';

const { contextBridge, ipcRenderer, webUtils } = require('electron');

const invoke = (channel, ...args) => ipcRenderer.invoke(channel, ...args);

// Drag & drop: resolve real paths in the preload (File.path is gone in
// recent Electron), then let the main process launch/inject them.
window.addEventListener('drop', (event) => {
  try {
    const files = [...(event.dataTransfer?.files || [])];
    const paths = files.map((f) => {
      try { return webUtils.getPathForFile(f); } catch { return f.path || ''; }
    }).filter(Boolean);
    if (paths.length) ipcRenderer.send('paths-dropped', paths);
  } catch {}
}, true);
window.addEventListener('dragover', (e) => e.preventDefault(), true);

contextBridge.exposeInMainWorld('gpp', {
  getBootstrap: () => invoke('get-bootstrap'),
  refresh: () => invoke('refresh'),
  addPaths: (paths) => invoke('add-paths', paths),
  closeAndRelaunch: (req) => invoke('close-and-relaunch', req),
  pickExecutable: () => invoke('pick-executable'),
  smartScan: () => invoke('smart-scan'),
  uwpApps: () => invoke('uwp-apps'),
  launchUwp: (appId, name) => invoke('launch-uwp', appId, name),
  inject: (pid) => invoke('inject', pid),
  launch: (target, opts) => invoke('launch', target, opts),
  launchTerminal: (kind) => invoke('launch-terminal', kind),
  stopManaging: (pid) => invoke('stop-managing', pid),
  saveSettings: (patch) => invoke('settings-save', patch),
  setLanguage: (lang) => invoke('language-set', lang),
  upstream: {
    add: (node) => invoke('upstream-add', node),
    update: (id, patch) => invoke('upstream-update', id, patch),
    remove: (id) => invoke('upstream-remove', id),
    activate: (id) => invoke('upstream-activate', id),
    test: (id) => invoke('upstream-test', id),
    testAll: () => invoke('upstream-test-all'),
  },
  dns: {
    set: (server, port) => invoke('dns-set', server, port),
    setProxyEnabled: (on) => invoke('dns-proxy-toggle', on),
  },
  exportReport: () => invoke('export-report'),
  exportDiagnostics: () => invoke('export-diagnostics'),
  runDiagnostics: () => invoke('run-diagnostics'),
  checkUpdate: () => invoke('check-update'),
  installUpdate: () => invoke('install-update'),
  openPath: (p) => invoke('open-path', p),
  openExternal: (url) => invoke('open-external', url),
  getLicenses: () => invoke('get-licenses'),
  onState: (cb) => { const h = (_e, s) => cb(s); ipcRenderer.on('state', h); return () => ipcRenderer.removeListener('state', h); },
  onLog: (cb) => { const h = (_e, l) => cb(l); ipcRenderer.on('log', h); return () => ipcRenderer.removeListener('log', h); },
  onDns: (cb) => { const h = (_e, r) => cb(r); ipcRenderer.on('dns', h); return () => ipcRenderer.removeListener('dns', h); },
  onToast: (cb) => { const h = (_e, t) => cb(t); ipcRenderer.on('toast', h); return () => ipcRenderer.removeListener('toast', h); },
  onNeedsChoice: (cb) => { const h = (_e, r) => cb(r); ipcRenderer.on('needs-choice', h); return () => ipcRenderer.removeListener('needs-choice', h); },
  onUpdateAvailable: (cb) => { const h = (_e, r) => cb(r); ipcRenderer.on('update-available', h); return () => ipcRenderer.removeListener('update-available', h); },
});
