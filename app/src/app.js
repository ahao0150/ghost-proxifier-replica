'use strict';

(() => {

/* =========================================================================
 * Ghost Proxifier replica — renderer
 * ========================================================================= */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const gpp = window.gpp;

const I18N = {
  zh: {
    nav_process: '进程管理', nav_dns: 'DNS 安全', nav_upstream: '上游节点',
    nav_stats: '流量统计', nav_license: '授权许可',
    upstream_status: '上游状态', process_sub: '只有被注入的进程才会通过代理隧道',
    go_settings: '去设置', smart_detect: '智能探测', smart_detect_sub: '拖入或点击',
    manual_select: '手动选择', manual_select_sub: '浏览并启动',
    cmd_term: 'CMD 终端', cmd_term_sub: '打开已注入的命令提示符',
    ps_term: 'PowerShell 终端', ps_term_sub: '打开已注入的 PowerShell',
    managed_procs: '已托管进程', empty_process: '将程序或快捷方式拖入窗口，立即开始接管',
    proxy_terminals: '代理终端', stats_title: '流量与性能统计',
    stats_sub: '实时监控隧道流量和各个进程的网络占用情况',
    export_report: '导出报表', total_down: '总下载', total_up: '总上传',
    active_conns: '活动连接数', dns_blocked: 'DNS 拦截数',
    realtime_throughput: '实时吞吐量（过去 60 秒）', peak: '当前峰值',
    traffic_ranking: '流量排行', col_process: '进程', col_down: '下载', col_up: '上传',
    col_conns: '连接数', dns_title: 'DNS 安全配置',
    dns_sub: '管理 DNS 解析配置，增强隐私保护并防止域名污染',
    primary_resolver: '主解析服务器', dns_edit_hint: '双击卡片内容以进行深度配置',
    block_local_dns: '拦截并代理本地 DNS',
    block_local_dns_sub: '将所有进程的 DNS 请求重定向至上游代理，防止 DNS 污染与泄露',
    recent_dns: '最近拦截记录', col_time: '时间', col_domain: '域名',
    col_resolved: '解析 IP（修正）', col_status: '状态',
    upstream_title: '上游代理节点',
    upstream_sub: '管理所有流量的最终出口，支持 SOCKS5 / HTTP / Shadowsocks 等协议',
    test_all: '检测全部延迟', add_node: '添加节点', license_title: '授权许可',
    license_sub: '本复刻版用于学习与研究，完全免费', view_licenses: '查看开源许可',
    check_update: '检查更新',
    proxy_on: '代理已开启', proxy_off: '未配置上游', proxy_fail: '上游连接失败',
    connected: '已连接', not_connected: '未连接', untested: '未检测',
    current: '当前使用', available: '可用', failed: '连接失败', timeout: 'Timeout',
    no_records: '暂无记录', no_managed: '暂无托管进程', no_results: '没有匹配的进程',
    settings: '设置', save: '保存', cancel: '取消', close: '关闭', delete: '删除',
    general: '通用', proxy: '代理', dns: 'DNS', diagnostics: '诊断', about: '关于',
    close_to_tray: '关闭窗口时最小化到托盘', close_to_tray_sub: '后台保持隧道运行',
    auto_track: '自动追踪子进程', auto_track_sub: '注入目标进程创建的所有子进程',
    watchdog: 'Watchdog 自动重注入', watchdog_sub: '托管进程的注入丢失时自动恢复，并记录上游可用性变化',
    udp_proxy: 'UDP 转发（SOCKS5 / Shadowsocks）', udp_proxy_sub: '通过本地 UDP 中继转发连接型/非连接型 UDP（含 overlapped I/O）；HTTP 上游不支持 UDP',
    language: '界面语言', theme: '主题', theme_dark: '暗色',
    active_node: '当前上游节点', add_or_manage: '添加或管理节点',
    dns_server: 'DNS 服务器', dns_port: '端口',
    export_diag: '导出排障包', export_diag_sub: '脱敏收集配置、日志与进程信息',
    run_diag: '运行诊断工具', open_config: '打开配置目录',
    version: '版本', native_dir: '原生组件目录', config_path: '配置文件',
    licenses: '开源许可', close_btn: '关闭',
    smart_scan_title: '智能探测', smart_scan_sub: '选择正在运行的程序，立即接管其网络流量',
    tab_running: '运行中的程序', tab_uwp: 'WinStore 应用',
    launch_uwp: '启动并接管',
    uwp_hint: '通过 Windows 应用激活接口启动 WinStore 应用，并把 AppContainer 可读的 DLL 注入其进程。',
    uwp_empty: '没有找到 WinStore 应用。',
    search_placeholder: '搜索进程或路径…', take_over: '接管', taken: '已接管',
    smart_scan_empty: '没有找到可接管的应用。请先启动目标程序，或使用「手动选择」。',
    add_node_title: '添加上游节点', edit_node_title: '编辑上游节点',
    node_name: '节点名称', node_type: '协议类型', node_host: '地址', node_port: '端口',
    node_method: '加密方式',
    node_user: '用户名（可选）', node_pass: '密码（可选）', set_active: '设为当前节点',
    socks5_hint: 'HTTP CONNECT、SOCKS5（含认证）与 Shadowsocks AEAD（aes-256-gcm / aes-128-gcm / chacha20-ietf-poly1305）均受支持。',
    dns_edit_title: 'DNS 深度配置', dns_edit_sub: '所有 DNS 查询将通过上游代理以 TCP 方式发送',
    process_detail: '进程详情', pid_label: '进程 ID', path_label: '路径',
    members_label: '注入进程数', children_label: '子进程数',
    down_label: '下载', up_label: '上传', conns_label: '连接数', latency_label: '延迟',
    open_location: '打开所在位置', stop_manage: '停止管理',
    terminal_title: '代理终端', terminal_sub: '终端进程同样通过代理隧道',
    launch_cmd: '启动 CMD 终端', launch_ps: '启动 PowerShell 终端',
    terminal_empty: '还没有终端进程。点击上方按钮启动一个已注入的终端。',
    diagnostics_title: '网络诊断', running: '检测中…', check_native: '原生组件',
    check_upstream: '上游节点', check_dns: 'DNS 代理', check_managed: '托管进程',
    check_tcp: 'TCP 重传率', avg_latency: '平均延迟 (HTTP)',
    retrans_rate: 'TCP 重传率', run_diagnostics: '运行诊断工具',
    realtime_logs: '实时监听日志', log_hint: '提示：您可以在本地添加 Hosts 规则来覆盖特定域名的解析。',
    node_status: '节点状态', availability: '当前节点可用性',
    health_check: '上游健康检测', url_test: 'URL Test',
    health_note: 'Ghost Engine 会尝试通过该代理节点完整加载 Google 204 页面，以验证其是否具备访问国际互联网的能力。',
    health_note2: '状态：已由 TCP Ping 升级为端到端 URL 测试，数据更真实。',
    backend_sync: '后端同步时间', url_mode: '（URL测试模式）',
    export_ok: '报表已导出', settings_saved: '设置已保存', dns_saved: 'DNS 配置已更新',
    node_saved: '节点已保存', node_deleted: '节点已删除', activated: '已切换节点',
    testing: '检测中', all_tested: '检测完成', copied: '已复制',
    license_free: '无需注册或激活，所有功能已解锁',
    update_latest: '当前已是最新版本',
    update_title: '软件更新',
    update_available: '发现新版本',
    update_current: '当前版本',
    update_latest_version: '最新版本',
    update_size: '更新包大小',
    update_notes: '更新说明',
    download_install: '下载并安装',
    installing: '正在退出并安装…',
    update_url: '更新清单 URL',
    auto_check_update: '自动检查更新',
    update_signature_hint: '更新清单使用 ECDSA P-256 签名校验；大小和 SHA-256 必须与清单一致。',
    license_note_title: '复刻说明',
    drag_title: '松开以接管此程序',
    drag_sub: '支持 .exe / .lnk / .bat / .cmd，子进程将自动追踪',
    redirect: '重定向', blocked: '已拦截',
    running_title: '程序已在运行',
    running_body: '检测到 {name} 正在运行（共 {count} 个进程）。新启动的实例会被现有进程接管并立即退出，导致注入失败。',
    running_warn: '关闭进程可能丢失未保存的数据，请先保存工作。',
    close_relaunch: '关闭进程并重启',
    inject_existing: '直接接管现有进程',
    existing_note: '直接接管只注入现有主进程；浏览器等应用的沙箱子进程可能无法全部接管，建议关闭后重启以获得完整代理。',
    restarted: '已重启并接管',
    terminal_count: '进程 ·', terminal_count2: '终端',
    add_node_btn: '添加节点',
  },
  en: {
    nav_process: 'Processes', nav_dns: 'DNS Security', nav_upstream: 'Upstream',
    nav_stats: 'Traffic', nav_license: 'License',
    upstream_status: 'Upstream status', process_sub: 'Only injected processes are routed through the tunnel',
    go_settings: 'Settings', smart_detect: 'Smart detect', smart_detect_sub: 'Drop or click',
    manual_select: 'Choose manually', manual_select_sub: 'Browse and launch',
    cmd_term: 'CMD terminal', cmd_term_sub: 'Open an injected command prompt',
    ps_term: 'PowerShell terminal', ps_term_sub: 'Open an injected PowerShell',
    managed_procs: 'Managed processes', empty_process: 'Drop an app or shortcut here to start proxying',
    proxy_terminals: 'Proxy terminals', stats_title: 'Traffic & performance',
    stats_sub: 'Live tunnel throughput and per-process network usage',
    export_report: 'Export report', total_down: 'Total download', total_up: 'Total upload',
    active_conns: 'Active connections', dns_blocked: 'DNS blocks',
    realtime_throughput: 'Live throughput (last 60s)', peak: 'Peak',
    traffic_ranking: 'Traffic ranking', col_process: 'Process', col_down: 'Download', col_up: 'Upload',
    col_conns: 'Connections', dns_title: 'DNS security',
    dns_sub: 'Manage DNS resolution, protect privacy and prevent poisoning',
    primary_resolver: 'Primary resolver', dns_edit_hint: 'Double-click to configure',
    block_local_dns: 'Intercept and proxy local DNS',
    block_local_dns_sub: 'Redirect every process DNS query through the upstream proxy to prevent leaks',
    recent_dns: 'Recent interceptions', col_time: 'Time', col_domain: 'Domain',
    col_resolved: 'Resolved IP (corrected)', col_status: 'Status',
    upstream_title: 'Upstream nodes',
    upstream_sub: 'Manage the final egress for all traffic. HTTP / SOCKS5 / Shadowsocks are supported.',
    test_all: 'Test all latency', add_node: 'Add node', license_title: 'License',
    license_sub: 'This replica is free for learning and research', view_licenses: 'Open-source licenses',
    check_update: 'Check for updates',
    proxy_on: 'Proxy enabled', proxy_off: 'No upstream', proxy_fail: 'Upstream unreachable',
    connected: 'Connected', not_connected: 'Disconnected', untested: 'Untested',
    current: 'In use', available: 'Available', failed: 'Failed', timeout: 'Timeout',
    no_records: 'No records yet', no_managed: 'No managed processes', no_results: 'No matching processes',
    settings: 'Settings', save: 'Save', cancel: 'Cancel', close: 'Close', delete: 'Delete',
    general: 'General', proxy: 'Proxy', dns: 'DNS', diagnostics: 'Diagnostics', about: 'About',
    close_to_tray: 'Minimize to tray when closed', close_to_tray_sub: 'Keep the tunnel running in background',
    auto_track: 'Track child processes', auto_track_sub: 'Inject every child process created by the target',
    watchdog: 'Watchdog re-injection', watchdog_sub: 'Restore lost injections and log upstream availability changes',
    udp_proxy: 'UDP forwarding (SOCKS5 / Shadowsocks)', udp_proxy_sub: 'Local UDP relay for connected and unconnected UDP (including overlapped I/O); HTTP upstreams do not support UDP',
    language: 'Language', theme: 'Theme', theme_dark: 'Dark',
    active_node: 'Active upstream', add_or_manage: 'Add or manage nodes',
    dns_server: 'DNS server', dns_port: 'Port',
    export_diag: 'Export diagnostics', export_diag_sub: 'Redacted config, logs and process info',
    run_diag: 'Run diagnostics', open_config: 'Open config folder',
    version: 'Version', native_dir: 'Native directory', config_path: 'Config file',
    licenses: 'Licenses', close_btn: 'Close',
    smart_scan_title: 'Smart detect', smart_scan_sub: 'Pick a running app and take over its traffic',
    tab_running: 'Running apps', tab_uwp: 'WinStore apps',
    launch_uwp: 'Launch & inject',
    uwp_hint: 'Launches a WinStore app through the Windows activation manager and injects an AppContainer-readable DLL.',
    uwp_empty: 'No WinStore apps found.',
    search_placeholder: 'Search process or path…', take_over: 'Take over', taken: 'Managed',
    smart_scan_empty: 'No eligible apps found. Start the target first or use Choose manually.',
    add_node_title: 'Add upstream node', edit_node_title: 'Edit upstream node',
    node_name: 'Name', node_type: 'Protocol', node_host: 'Host', node_port: 'Port',
    node_method: 'Cipher',
    node_user: 'Username (optional)', node_pass: 'Password (optional)', set_active: 'Set as active',
    socks5_hint: 'HTTP CONNECT, SOCKS5 (with auth) and Shadowsocks AEAD (aes-256-gcm / aes-128-gcm / chacha20-ietf-poly1305) are supported.',
    dns_edit_title: 'DNS configuration', dns_edit_sub: 'DNS queries are sent through the upstream proxy over TCP',
    process_detail: 'Process details', pid_label: 'PID', path_label: 'Path',
    members_label: 'Injected processes', children_label: 'Children',
    down_label: 'Download', up_label: 'Upload', conns_label: 'Connections', latency_label: 'Latency',
    open_location: 'Open location', stop_manage: 'Stop managing',
    terminal_title: 'Proxy terminals', terminal_sub: 'Terminal processes also use the tunnel',
    launch_cmd: 'Launch CMD', launch_ps: 'Launch PowerShell',
    terminal_empty: 'No terminal yet. Launch an injected terminal above.',
    diagnostics_title: 'Network diagnostics', running: 'Running…', check_native: 'Native components',
    check_upstream: 'Upstream', check_dns: 'DNS proxy', check_managed: 'Managed processes',
    check_tcp: 'TCP retransmissions', avg_latency: 'Average latency (HTTP)',
    retrans_rate: 'TCP retransmission', run_diagnostics: 'Run diagnostics',
    realtime_logs: 'Live logs', log_hint: 'Tip: add a local Hosts entry to override resolution for a specific domain.',
    node_status: 'Node status', availability: 'Current availability',
    health_check: 'Upstream health check', url_test: 'URL Test',
    health_note: 'Ghost Engine loads a Google 204 page through the node to verify real internet reachability.',
    health_note2: 'Status is measured end-to-end with an URL test instead of a TCP ping.',
    backend_sync: 'Backend sync', url_mode: ' (URL test)',
    export_ok: 'Report exported', settings_saved: 'Settings saved', dns_saved: 'DNS updated',
    node_saved: 'Node saved', node_deleted: 'Node deleted', activated: 'Node switched',
    testing: 'Testing', all_tested: 'Testing complete', copied: 'Copied',
    license_free: 'No registration or activation. All features unlocked.',
    update_latest: 'You are on the latest version',
    update_title: 'Software update',
    update_available: 'Update available',
    update_current: 'Current version',
    update_latest_version: 'Latest version',
    update_size: 'Package size',
    update_notes: 'Release notes',
    download_install: 'Download & install',
    installing: 'Quitting and installing…',
    update_url: 'Update manifest URL',
    auto_check_update: 'Check for updates automatically',
    update_signature_hint: 'The manifest is verified with an ECDSA P-256 signature; size and SHA-256 must match.',
    license_note_title: 'About this replica',
    drag_title: 'Drop to take over this app',
    drag_sub: '.exe / .lnk / .bat / .cmd supported. Child processes are tracked automatically.',
    redirect: 'Redirected', blocked: 'Blocked',
    running_title: 'Application is already running',
    running_body: '{name} is already running ({count} processes). A newly launched instance is handed off to the existing one and exits before injection.',
    running_warn: 'Closing processes may lose unsaved data. Save your work first.',
    close_relaunch: 'Close and relaunch',
    inject_existing: 'Inject existing process',
    existing_note: 'Injecting the existing process only covers its main process. Sandboxed browser children may not all be injected; closing and relaunching gives the fullest coverage.',
    restarted: 'Relaunched and proxied',
    terminal_count: 'processes ·', terminal_count2: 'terminals',
    add_node_btn: 'Add node',
  },
};

let lang = 'zh';
function t(key) {
  return (I18N[lang] && I18N[lang][key]) || I18N.zh[key] || key;
}

const state = {
  config: null,
  processes: [],
  terminals: { procs: 0, terms: 0, conns: 0 },
  totals: { up: 0, down: 0, conns: 0, dnsBlocked: 0 },
  history: new Array(60).fill(0),
  dnsRecords: [],
  health: { results: {}, activeLatency: null, availability: null, lastTestAt: null, samples: 0 },
  tcp: { retransRate: 0 },
  stats: {},
  version: '1.0.0',
  nativeDir: '',
  configPath: '',
};

let logBuf = [];
let currentPage = 'process';
let currentSettingsTab = 'general';
let modalClose = null;
let cardEls = new Map();
let chartDrawn = false;

/* ============================== helpers ============================== */

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function fmtBytes(bytes) {
  const b = Number(bytes) || 0;
  if (b < 1024) return b.toFixed(0) + ' B';
  if (b < 1024 * 1024) return (b / 1024).toFixed(2) + ' KB';
  if (b < 1024 * 1024 * 1024) return (b / 1024 / 1024).toFixed(2) + ' MB';
  return (b / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}

function fmtMB(bytes) {
  return ((Number(bytes) || 0) / 1024 / 1024).toFixed(2);
}

function fmtRate(bps) {
  const b = Number(bps) || 0;
  if (b < 1024) return b.toFixed(0) + ' B/s';
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' K/s';
  if (b < 1024 * 1024 * 1024) return (b / 1024 / 1024).toFixed(1) + ' M/s';
  return (b / 1024 / 1024 / 1024).toFixed(2) + ' G/s';
}

function fmtTime(ts) {
  const d = new Date(ts || Date.now());
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
}

function basename(p) {
  return String(p || '').split(/[\\/]/).filter(Boolean).pop() || '';
}

function activeNode() {
  const c = state.config;
  if (!c) return null;
  return (c.upstreams || []).find((u) => u.id === c.activeUpstreamId) || (c.upstreams || [])[0] || null;
}

function activeHealth() {
  const n = activeNode();
  return n ? state.health.results[n.id] : null;
}

function isProxyOk() {
  const h = activeHealth();
  if (!navigator.onLine) return false;
  return !h || h.ok;
}

function svgGear() {
  return `<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="3.2" stroke="currentColor" stroke-width="1.6"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06A1.7 1.7 0 0 0 15 19.36a1.7 1.7 0 0 0-1 1.55V21a2 2 0 1 1-4 0v-.09A1.7 1.7 0 0 0 9 19.36a1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.7 1.7 0 0 0 4.64 15a1.7 1.7 0 0 0-1.55-1H3a2 2 0 1 1 0-4h.09A1.7 1.7 0 0 0 4.64 9a1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.7 1.7 0 0 0 9 4.64h.09a1.7 1.7 0 0 0 1-1.55V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1 1.55 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.7 1.7 0 0 0 19.36 9v.09a1.7 1.7 0 0 0 1.55 1H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.51 1Z" stroke="currentColor" stroke-width="1.3"/></svg>`;
}
function svgX() {
  return `<svg viewBox="0 0 24 24" fill="none"><path d="m6 6 12 12M18 6 6 18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`;
}
function svgInfo() {
  return `<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.6"/><path d="M12 11v5M12 8h.01" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`;
}

function processIcon(p, cls = 'process-icon') {
  if (p && p.icon) return `<img class="${cls}" src="${p.icon}" alt="">`;
  const letter = (p && p.name ? p.name[0] : '?').toUpperCase();
  return `<span class="${cls} letter" style="--accent:${p && p.accent || '#2b6d6a'}">${esc(letter)}</span>`;
}

function toast(message, type = 'info') {
  const stack = $('#toast-stack');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span class="ti"></span><span>${esc(message)}</span>`;
  stack.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(4px)';
    setTimeout(() => el.remove(), 220);
  }, 3200);
}

/* ============================== navigation ============================== */

function setPage(page) {
  currentPage = page;
  $$('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.page === page));
  $$('.page').forEach((p) => p.classList.toggle('active', p.id === 'page-' + page));
  const wrap = $('#page-wrap');
  if (wrap) wrap.scrollTop = 0;
  renderRightPanel();
  renderPage();
}

function applyI18n() {
  $$('[data-i18n]').forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.documentElement.lang = lang === 'en' ? 'en' : 'zh-CN';
}

/* ============================== sidebar / pill ============================== */

function renderChrome() {
  const node = activeNode();
  const h = activeHealth();
  const ok = isProxyOk();
  const sideDot = $('#side-dot');
  const sideText = $('#side-status-text');
  const sideAddr = $('#side-addr');
  if (node) {
    sideAddr.textContent = `${node.host}:${node.port} (${node.name})`;
  } else {
    sideAddr.textContent = '—';
  }
  if (!node) {
    sideDot.className = 'dot idle';
    sideText.textContent = t('proxy_off');
  } else if (h && !h.ok) {
    sideDot.className = 'dot warn';
    sideText.textContent = t('proxy_fail');
  } else {
    sideDot.className = 'dot ok';
    sideText.textContent = t('connected');
  }

  const pillDot = $('#pill-dot');
  const pillStatus = $('#pill-status');
  const pillNode = $('#pill-node');
  if (!node) {
    pillDot.className = 'dot idle';
    pillStatus.textContent = t('proxy_off');
  } else if (h && !h.ok) {
    pillDot.className = 'dot warn';
    pillStatus.textContent = t('proxy_fail');
  } else {
    pillDot.className = 'dot ok';
    pillStatus.textContent = t('proxy_on');
  }
  pillNode.textContent = node ? node.name : '—';
}

/* ============================== process page ============================== */

function renderProcesses() {
  const grid = $('#process-grid');
  const empty = $('#process-empty');
  const procs = (state.processes || []).filter((p) => !p.terminal);
  empty.classList.toggle('hidden', procs.length > 0);
  $('#managed-count').textContent = '';

  const seen = new Set();
  for (const p of procs) {
    seen.add(p.pid);
    let el = cardEls.get(p.pid);
    if (!el) {
      el = document.createElement('button');
      el.className = 'process-card';
      el.dataset.pid = p.pid;
      el.innerHTML = `
        <span class="process-dot"></span>
        ${processIcon(p)}
        <span class="process-name"></span>
        <span class="process-badge"></span>`;
      grid.appendChild(el);
      cardEls.set(p.pid, el);
    } else if (el.parentElement !== grid) {
      grid.appendChild(el);
    }
    el.style.setProperty('--accent', p.accent || '#35e57a');
    el.querySelector('.process-name').textContent = p.name;
    const img = el.querySelector('img.process-icon');
    if (p.icon && !img) {
      el.querySelector('.process-icon')?.remove();
      el.insertAdjacentHTML('afterbegin', processIcon(p));
    } else if (p.icon && img && img.src !== p.icon) {
      img.src = p.icon;
    }
    const dot = el.querySelector('.process-dot');
    dot.className = 'process-dot ' + (p.conns > 0 ? 'on' : 'off');
    const badge = el.querySelector('.process-badge');
    const n = p.conns || 0;
    badge.textContent = n > 0 ? n : '';
    badge.style.display = n > 0 ? 'grid' : 'none';
    badge.className = 'process-badge';
  }
  for (const [pid, el] of [...cardEls.entries()]) {
    if (!seen.has(pid)) {
      el.remove();
      cardEls.delete(pid);
    }
  }

  renderTerminals();
}

function renderTerminals() {
  const info = state.terminals || { procs: 0, terms: 0, conns: 0 };
  const section = $('#terminals-section');
  const grid = $('#terminal-grid');
  if (!info.procs) {
    section.style.display = 'none';
    return;
  }
  section.style.display = '';
  const spans = [];
  for (let i = 0; i < 9; i++) {
    const cls = i === 4 ? 'psb' : (i === 3 || i === 5 ? 'ps' : '');
    spans.push(`<span class="${cls}"></span>`);
  }
  grid.innerHTML = `
    <button class="terminal-card" id="terminal-group-card">
      <div class="terminal-grid-ico">${spans.join('')}</div>
      <div>
        <div class="terminal-info">${esc(t('proxy_terminals'))}</div>
        <div class="terminal-sub">${info.procs} ${esc(t('terminal_count'))} ${info.terms} ${esc(t('terminal_count2'))}</div>
      </div>
      <span class="terminal-badge" style="${info.terms > 0 ? '' : 'display:none'}">${info.terms || ''}</span>
    </button>`;
  $('#terminal-group-card').addEventListener('click', openTerminalModal);
}

/* ============================== stats page ============================== */

function renderStats() {
  $('#stat-down').textContent = fmtMB(state.totals.down);
  $('#stat-up').textContent = fmtMB(state.totals.up);
  $('#stat-conns').textContent = state.totals.conns || 0;
  $('#stat-blocked').textContent = state.totals.dnsBlocked || 0;

  const hist = state.history && state.history.length ? state.history : new Array(60).fill(0);
  const peak = Math.max(...hist, 0);
  $('#chart-peak').textContent = fmtRate(peak);
  drawChart(hist);

  const body = $('#ranking-body');
  const procs = (state.processes || []).slice().sort((a, b) => (b.down + b.up) - (a.down + a.up));
  if (!procs.length) {
    body.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--muted-2);padding:26px 0">${esc(t('no_managed'))}</td></tr>`;
    return;
  }
  body.innerHTML = procs.map((p) => `
    <tr>
      <td><div class="td-proc">${p.icon ? `<img src="${p.icon}" alt="">` : `<span class="letter">${esc((p.name || '?')[0].toUpperCase())}</span>`}<span>${esc(p.name)}</span></div></td>
      <td class="num">${fmtBytes(p.down)}</td>
      <td class="num">${fmtBytes(p.up)}</td>
      <td class="num">${p.conns || 0}</td>
    </tr>`).join('');
}

function niceMax(v) {
  const x = Math.max(v, 1);
  const pow = Math.pow(1024, Math.floor(Math.log(x) / Math.log(1024)));
  const n = x / pow;
  let m;
  if (n <= 1) m = 1;
  else if (n <= 2) m = 2;
  else if (n <= 4) m = 4;
  else if (n <= 8) m = 8;
  else m = 16;
  return m * pow;
}

function drawChart(hist) {
  const canvas = $('#traffic-chart');
  if (!canvas) return;
  const cssW = canvas.clientWidth || 800;
  const cssH = 250;
  const dpr = window.devicePixelRatio || 1;
  if (canvas.width !== Math.round(cssW * dpr) || canvas.height !== Math.round(cssH * dpr)) {
    canvas.width = Math.round(cssW * dpr);
    canvas.height = Math.round(cssH * dpr);
  }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssW, cssH);

  const left = 52;
  const right = 10;
  const top = 14;
  const bottom = 22;
  const w = cssW - left - right;
  const h = cssH - top - bottom;
  const peak = Math.max(...hist, 0);
  const max = niceMax(peak * 1.15 || 1024);

  ctx.font = '10px "Segoe UI", "Microsoft YaHei", sans-serif';
  ctx.textBaseline = 'middle';
  for (let i = 0; i <= 4; i++) {
    const y = top + h - (h * i) / 4;
    ctx.strokeStyle = i === 0 ? 'rgba(42,58,59,.75)' : 'rgba(30,42,43,.55)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(left, y + .5);
    ctx.lineTo(left + w, y + .5);
    ctx.stroke();
    ctx.fillStyle = '#5f6f6e';
    ctx.textAlign = 'right';
    ctx.fillText(fmtRate((max * i) / 4), left - 9, y);
  }

  const n = hist.length || 60;
  const step = w / n;
  const barW = Math.max(3, Math.min(11, step * 0.62));
  for (let i = 0; i < n; i++) {
    const v = Math.max(0, hist[i] || 0);
    const bh = Math.max(v > 0 ? 2 : 0, (v / max) * h);
    const x = left + i * step + (step - barW) / 2;
    const y = top + h - bh;
    if (bh <= 0) continue;
    const grad = ctx.createLinearGradient(0, y, 0, top + h);
    if (v === peak && peak > 0) {
      grad.addColorStop(0, '#7dffb0');
      grad.addColorStop(.45, '#35e57a');
      grad.addColorStop(1, '#0b7a3f');
    } else {
      grad.addColorStop(0, '#4ef08d');
      grad.addColorStop(.55, '#22c55e');
      grad.addColorStop(1, '#0a6b38');
    }
    ctx.save();
    ctx.shadowColor = 'rgba(53,229,122,.55)';
    ctx.shadowBlur = v === peak && peak > 0 ? 14 : 7;
    ctx.fillStyle = grad;
    const r = Math.min(2.5, barW / 2, bh);
    ctx.beginPath();
    if (ctx.roundRect) {
      ctx.roundRect(x, y, barW, bh, [r, r, 0, 0]);
    } else {
      ctx.rect(x, y, barW, bh);
    }
    ctx.fill();
    ctx.restore();
  }
}

/* ============================== DNS page ============================== */

function renderDns() {
  const d = state.config?.dns || { server: '8.8.8.8', port: 53, mode: 'proxy' };
  $('#dns-server').textContent = d.server || '8.8.8.8';
  $('#dns-port').textContent = d.port || 53;
  $('#dns-proxy-toggle').checked = d.mode === 'proxy';
  const badge = $('#dns-badge');
  badge.textContent = d.mode === 'proxy' ? '正在使用自定义解析' : '使用系统默认解析';

  const body = $('#dns-body');
  const rows = state.dnsRecords || [];
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--muted-2);padding:26px 0">${esc(t('no_records'))}</td></tr>`;
    return;
  }
  body.innerHTML = rows.slice(0, 40).map((r) => {
    const proc = state.processes.find((p) => p.pid === (r.rootPid || r.pid));
    const icon = proc && proc.icon;
    return `<tr>
      <td class="mono">${fmtTime(r.ts)}</td>
      <td class="td-ip" style="font-family:var(--font);font-size:11.5px;color:#d3dddc">${esc(r.domain)}</td>
      <td class="td-ip">${esc(r.ips || '—')}</td>
      <td><div class="td-proc">${icon ? `<img src="${icon}" alt="">` : `<span class="letter">${esc((r.proc || '?')[0].toUpperCase())}</span>`}<span>${esc(r.proc || 'PID ' + r.pid)}</span></div></td>
      <td class="right"><span class="badge ${r.status === '已拦截' ? 'blocked' : 'redirect'}">${esc(r.status)}</span></td>
    </tr>`;
  }).join('');
}

/* ============================== upstream page ============================== */

function nodeColors(name) {
  const palettes = [
    ['#ffb347', '#7a4a12'], ['#c084fc', '#4c1d95'], ['#38bdf8', '#0c4a6e'],
    ['#34d399', '#065f46'], ['#f472b6', '#831843'], ['#facc15', '#713f12'],
  ];
  let h = 0;
  for (const c of String(name || '')) h = (h * 33 + c.charCodeAt(0)) >>> 0;
  return palettes[h % palettes.length];
}

function renderUpstreams() {
  const list = $('#upstream-list');
  const c = state.config;
  if (!c) return;
  const nodes = c.upstreams || [];
  list.innerHTML = nodes.map((n) => {
    const active = n.id === c.activeUpstreamId;
    const r = state.health.results[n.id];
    const [c1, c2] = nodeColors(n.name);
    let status = `<span style="color:var(--muted-2)">${esc(t('untested'))}</span>`;
    if (r && r.ok) status = `<span class="lat">${r.latency}ms</span> <span class="dot ok"></span> <span style="color:#9fbcae">${esc(t('available'))}</span>`;
    else if (r && !r.ok) status = `<span class="fail">${esc(r.error || t('failed'))} · ${esc(t('failed'))}</span> <span class="dot bad"></span>`;
    return `<div class="upstream-card ${active ? 'active' : ''}" data-id="${esc(n.id)}">
      <div class="node-icon" style="--c1:${c1};--c2:${c2}">${esc((n.name || '?')[0].toUpperCase())}</div>
      <div class="node-main">
        <div class="node-name">${esc(n.name)}</div>
        <div class="node-addr">${n.type === 'socks5' ? 'SOCKS5' : (n.type === 'shadowsocks' ? `SS · ${esc(n.method || 'aes-256-gcm')}` : 'Mixed')} · ${esc(n.host)}:${esc(n.port)}</div>
      </div>
      <div class="node-side">
        <div style="text-align:right">
          ${active ? `<div class="current">${esc(t('current'))}</div>` : ''}
          <div class="node-state">${status}</div>
        </div>
        <button class="icon-btn" data-edit="${esc(n.id)}" title="Edit">${svgGear()}</button>
      </div>
    </div>`;
  }).join('');

  const last = state.health.lastTestAt;
  const sync = $('#upstream-sync');
  sync.textContent = `${t('backend_sync')}: ${last ? fmtTime(last) : '--:--:--'}${t('url_mode')}`;
}

/* ============================== right panel ============================== */

function renderRightPanel() {
  const panel = $('#right-panel');
  const content = $('#right-panel-content');
  if (currentPage === 'dns') {
    panel.classList.add('visible');
    content.innerHTML = `
      <div class="right-title">${esc(t('realtime_logs'))}</div>
      <div class="log-console" id="log-console"></div>
      <div class="log-hint">${svgInfo()}<span>${esc(t('log_hint'))}</span></div>`;
    renderLogs(true);
    return;
  }
  if (currentPage === 'upstream') {
    panel.classList.add('visible');
    const h = activeHealth();
    const avail = state.health.availability;
    const pct = avail == null ? 0 : avail;
    content.innerHTML = `
      <div class="right-title">${esc(t('node_status'))}</div>
      <div class="side-card">
        <div class="kv-row"><span class="k">${esc(t('availability'))}</span><span class="v green">${avail == null ? '—' : pct.toFixed(1) + '%'}</span></div>
        <div class="side-progress"><i style="width:${avail == null ? 0 : Math.max(2, pct)}%"></i></div>
        <div class="kv-row"><span class="k">${esc(t('health_check'))}</span><span class="v">${esc(t('url_test'))} ${h ? (h.ok ? `(${h.latency}ms)` : `(${esc(h.error || '')})`) : ''}</span></div>
        <div class="divider"></div>
        <div class="side-note">
          ${esc(t('health_note'))}<br><br>
          <b>*${esc(t('health_note2'))}</b>
        </div>
      </div>`;
    return;
  }
  if (currentPage === 'stats') {
    panel.classList.add('visible');
    const lat = state.health.activeLatency;
    const retr = (state.tcp && state.tcp.retransRate) || 0;
    content.innerHTML = `
      <div class="right-title">${esc(t('diagnostics_title'))}</div>
      <div class="side-card">
        <div class="kv-row"><span class="k">${esc(t('avg_latency'))}</span><span class="v">${lat == null ? '—' : lat + ' ms'}</span></div>
        <div class="kv-row"><span class="k">${esc(t('retrans_rate'))}</span><span class="v">${retr.toFixed(2)}%</span></div>
        <div class="divider"></div>
        <button class="btn btn-block" id="btn-run-diag">${esc(t('run_diagnostics'))}</button>
      </div>`;
    $('#btn-run-diag').addEventListener('click', openDiagnosticsModal);
    return;
  }
  panel.classList.remove('visible');
}

function renderLogs(force = false) {
  const consoleEl = $('#log-console');
  if (!consoleEl) return;
  const lines = logBuf.slice(-350);
  consoleEl.innerHTML = lines.map((l) => {
    const tag = String(l.tag || 'log').replace(/[^A-Za-z0-9-]/g, '');
    return `<div class="log-line"><span class="log-time">${fmtTime(l.ts)}</span><span class="log-pid">[${l.pid || '-'}]</span><span class="log-tag tag-${tag}">[${esc(l.tag)}]</span> ${esc(l.text)}</div>`;
  }).join('');
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function appendLog(l) {
  logBuf.push(l);
  if (logBuf.length > 1500) logBuf = logBuf.slice(-1200);
  const consoleEl = $('#log-console');
  if (!consoleEl) return;
  const atBottom = consoleEl.scrollHeight - consoleEl.scrollTop - consoleEl.clientHeight < 50;
  const tag = String(l.tag || 'log').replace(/[^A-Za-z0-9-]/g, '');
  const div = document.createElement('div');
  div.className = 'log-line';
  div.innerHTML = `<span class="log-time">${fmtTime(l.ts)}</span><span class="log-pid">[${l.pid || '-'}]</span><span class="log-tag tag-${tag}">[${esc(l.tag)}]</span> ${esc(l.text)}`;
  consoleEl.appendChild(div);
  while (consoleEl.children.length > 400) consoleEl.firstChild.remove();
  if (atBottom) consoleEl.scrollTop = consoleEl.scrollHeight;
}

/* ============================== page dispatcher ============================== */

function renderPage() {
  renderChrome();
  if (currentPage === 'process') renderProcesses();
  else if (currentPage === 'stats') renderStats();
  else if (currentPage === 'dns') renderDns();
  else if (currentPage === 'upstream') renderUpstreams();
}

function renderAll() {
  renderChrome();
  renderPage();
  renderRightPanel();
}

/* ============================== modals ============================== */

function closeModal() {
  const root = $('#modal-root');
  root.innerHTML = '';
  modalClose = null;
}

function openModal({ title, body, foot = '', wide = false, narrow = false, onMount }) {
  closeModal();
  const root = $('#modal-root');
  root.innerHTML = `
    <div class="modal-overlay">
      <div class="modal ${wide ? 'wide' : ''} ${narrow ? 'narrow' : ''}">
        <div class="modal-head">
          <h3>${esc(title)}</h3>
          <button class="modal-close" data-close>${svgX()}</button>
        </div>
        <div class="modal-body">${body}</div>
        ${foot ? `<div class="modal-foot">${foot}</div>` : ''}
      </div>
    </div>`;
  const overlay = root.querySelector('.modal-overlay');
  overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) closeModal(); });
  root.querySelector('[data-close]').addEventListener('click', closeModal);
  modalClose = closeModal;
  if (onMount) onMount(root);
  return root;
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && modalClose) modalClose();
});

/* ---------- smart scan ---------- */
async function openSmartScan() {
  const root = openModal({
    title: t('smart_scan_title'),
    wide: true,
    body: `
      <div class="seg" id="scan-tabs" style="margin:-2px 0 10px">
        <button data-tab="running" class="active">${esc(t('tab_running'))}</button>
        <button data-tab="uwp">${esc(t('tab_uwp'))}</button>
      </div>
      <div class="hint" id="scan-hint" style="margin:0 0 10px">${esc(t('smart_scan_sub'))}</div>
      <input class="scan-search" id="scan-search" placeholder="${esc(t('search_placeholder'))}">
      <div class="scan-list" id="scan-list"><div class="hint" style="padding:16px 0">${esc(t('running'))}</div></div>`,
    foot: `<button class="btn" data-close>${esc(t('close_btn'))}</button>`,
  });
  root.querySelector('.modal-foot [data-close]')?.addEventListener('click', closeModal);

  let activeTab = 'running';
  let runningItems = null;
  let uwpItems = null;
  const list = $('#scan-list', root);
  const hint = $('#scan-hint', root);
  const search = $('#scan-search', root);
  const loading = `<div class="hint" style="padding:16px 0">${esc(t('running'))}</div>`;

  const render = () => {
    const q = search.value.trim().toLowerCase();
    if (activeTab === 'running') {
      if (!runningItems) { list.innerHTML = loading; return; }
      const filtered = runningItems.filter((i) =>
        !q || i.name.toLowerCase().includes(q) || (i.path || '').toLowerCase().includes(q));
      if (!filtered.length) {
        list.innerHTML = `<div class="hint" style="padding:16px 0;text-align:center">${esc(t('smart_scan_empty'))}</div>`;
        return;
      }
      list.innerHTML = filtered.map((i) => `
        <div class="scan-item">
          ${i.icon ? `<img src="${i.icon}" alt="">` : `<span class="letter">${esc(i.name[0].toUpperCase())}</span>`}
          <div class="info"><div class="name">${esc(i.name)}</div><div class="path">${esc(i.path)} · PID ${i.pid}${i.procs > 1 ? ` · ${i.procs} ${lang === 'en' ? 'processes' : '进程'}` : ''}</div></div>
          <button class="btn btn-green" data-inject="${i.pid}">${esc(t('take_over'))}</button>
        </div>`).join('');
      list.querySelectorAll('[data-inject]').forEach((b) => {
        b.addEventListener('click', async () => {
          b.disabled = true;
          b.textContent = '…';
          const r = await gpp.inject(Number(b.dataset.inject));
          if (r && r.ok) {
            b.textContent = t('taken');
            b.classList.remove('btn-green');
            b.classList.add('btn');
          } else {
            b.disabled = false;
            b.textContent = t('take_over');
            toast((r && r.error) || '注入失败', 'error');
          }
        });
      });
      return;
    }

    if (!uwpItems) { list.innerHTML = loading; return; }
    const filtered = uwpItems.filter((i) =>
      !q || i.name.toLowerCase().includes(q) || i.appId.toLowerCase().includes(q));
    if (!filtered.length) {
      list.innerHTML = `<div class="hint" style="padding:16px 0;text-align:center">${esc(t('uwp_empty'))}</div>`;
      return;
    }
    list.innerHTML = filtered.map((a, idx) => `
      <div class="scan-item">
        <span class="letter">${esc((a.name || '?')[0].toUpperCase())}</span>
        <div class="info"><div class="name">${esc(a.name)}</div><div class="path">${esc(a.appId)}</div></div>
        <button class="btn btn-green" data-uwp="${idx}">${esc(t('launch_uwp'))}</button>
      </div>`).join('');
    list.querySelectorAll('[data-uwp]').forEach((b) => {
      b.addEventListener('click', async () => {
        const app = filtered[Number(b.dataset.uwp)];
        if (!app) return;
        b.disabled = true;
        b.textContent = '…';
        const r = await gpp.launchUwp(app.appId, app.name);
        if (r && r.ok) {
          b.textContent = t('taken');
          b.classList.remove('btn-green');
          b.classList.add('btn');
        } else {
          b.disabled = false;
          b.textContent = t('launch_uwp');
          toast((r && r.error) || '启动失败', 'error');
        }
      });
    });
  };

  const setTab = async (tab) => {
    activeTab = tab;
    root.querySelectorAll('#scan-tabs [data-tab]').forEach((x) =>
      x.classList.toggle('active', x.dataset.tab === tab));
    hint.textContent = tab === 'running' ? t('smart_scan_sub') : t('uwp_hint');
    search.value = '';
    if (tab === 'uwp' && !uwpItems) {
      list.innerHTML = loading;
      try {
        const res = await gpp.uwpApps();
        uwpItems = Array.isArray(res) ? res : (res && res.apps) || [];
      } catch {
        uwpItems = [];
      }
    }
    render();
  };

  root.querySelectorAll('#scan-tabs [data-tab]').forEach((b) =>
    b.addEventListener('click', () => setTab(b.dataset.tab)));
  search.addEventListener('input', render);

  gpp.smartScan().then((items) => {
    runningItems = Array.isArray(items) ? items : [];
    if (activeTab === 'running') render();
  }).catch(() => {
    runningItems = [];
    if (activeTab === 'running') render();
  });
}

/* ---------- already-running app prompt ---------- */
function handleAddResults(results) {
  if (!Array.isArray(results)) return;
  for (const r of results) {
    if (r.needsChoice) { openRunningPrompt(r); continue; }
    if (r.ok) toast(`${basename(r.path)} 已接管`, 'success');
    else toast(`${basename(r.path)}：${r.error}`, 'error');
  }
}

function openRunningPrompt(req) {
  const name = req.name || basename(req.target);
  const count = (req.pids || []).length || 1;
  const bodyText = t('running_body').replace('{name}', name).replace('{count}', String(count));
  const root = openModal({
    title: t('running_title'),
    narrow: true,
    body: `
      <div class="hint" style="margin:-2px 0 12px;line-height:1.75">${esc(bodyText)}</div>
      <div class="diag-item" style="margin-bottom:10px">
        <span class="ok">!</span>
        <span class="name">${esc(name)}</span>
        <span class="detail">PID ${req.existingPid} · ${count} ${lang === 'en' ? 'processes' : '进程'}</span>
      </div>
      <div class="hint" style="color:#f5a524;line-height:1.7">${esc(t('running_warn'))}</div>
      <div class="hint" style="margin-top:8px;line-height:1.7">${esc(t('existing_note'))}</div>`,
    foot: `<button class="btn" data-close>${esc(t('cancel'))}</button>
      <button class="btn" id="run-inject">${esc(t('inject_existing'))}</button>
      <button class="btn btn-danger" id="run-close">${esc(t('close_relaunch'))}</button>`,
    onMount: (r) => {
      r.querySelector('.modal-foot [data-close]').addEventListener('click', closeModal);
      $('#run-inject', r).addEventListener('click', async (ev) => {
        const b = ev.currentTarget;
        b.disabled = true;
        const res = await gpp.inject(req.existingPid);
        if (res && res.ok) {
          closeModal();
          setPage('process');
          toast(`${name} 已接管`, 'success');
        } else {
          b.disabled = false;
          toast((res && res.error) || '注入失败', 'error');
        }
      });
      $('#run-close', r).addEventListener('click', async (ev) => {
        const b = ev.currentTarget;
        b.disabled = true;
        b.textContent = t('running');
        const res = await gpp.closeAndRelaunch({
          target: req.target, args: req.args, cwd: req.cwd,
          console: req.console, name: req.name, pids: req.pids,
        });
        if (res && res.ok) {
          closeModal();
          setPage('process');
          toast(`${name} ${t('restarted')}`, 'success');
        } else {
          b.disabled = false;
          b.textContent = t('close_relaunch');
          toast((res && res.error) || '重启失败', 'error');
        }
      });
    },
  });
}

/* ---------- settings ---------- */
function openSettings(tab = 'general') {
  currentSettingsTab = tab;
  const c = state.config || {};
  const node = activeNode();
  const body = `
    <div class="settings-layout">
      <div class="settings-nav">
        ${['general', 'proxy', 'dns', 'diagnostics', 'about'].map((k) => `<button data-tab="${k}" class="${tab === k ? 'active' : ''}">${esc(t(k))}</button>`).join('')}
      </div>
      <div class="settings-content">
        <div class="settings-section ${tab === 'general' ? 'active' : ''}" data-sec="general">
          <div class="settings-row"><div><div class="label">${esc(t('close_to_tray'))}</div><div class="sub">${esc(t('close_to_tray_sub'))}</div></div>
            <label class="switch"><input type="checkbox" id="set-tray" ${c.general?.closeToTray ? 'checked' : ''}><span></span></label></div>
          <div class="settings-row"><div><div class="label">${esc(t('auto_track'))}</div><div class="sub">${esc(t('auto_track_sub'))}</div></div>
            <label class="switch"><input type="checkbox" id="set-track" ${c.general?.autoTrackChildren ? 'checked' : ''}><span></span></label></div>
          <div class="settings-row"><div><div class="label">${esc(t('watchdog'))}</div><div class="sub">${esc(t('watchdog_sub'))}</div></div>
            <label class="switch"><input type="checkbox" id="set-watchdog" ${c.general?.watchdog !== false ? 'checked' : ''}><span></span></label></div>
          <div class="settings-row"><div><div class="label">${esc(t('udp_proxy'))}</div><div class="sub">${esc(t('udp_proxy_sub'))}</div></div>
            <label class="switch"><input type="checkbox" id="set-udp" ${c.general?.udpProxy !== false ? 'checked' : ''}><span></span></label></div>
          <div class="settings-row"><div class="label">${esc(t('language'))}</div>
            <div class="seg"><button data-lang="zh" class="${(c.language || 'zh') === 'zh' ? 'active' : ''}">中文</button><button data-lang="en" class="${c.language === 'en' ? 'active' : ''}">English</button></div></div>
          <div class="settings-row"><div class="label">${esc(t('theme'))}</div><span class="hint">${esc(t('theme_dark'))}</span></div>
        </div>
        <div class="settings-section ${tab === 'proxy' ? 'active' : ''}" data-sec="proxy">
          <div class="settings-row"><div><div class="label">${esc(t('active_node'))}</div><div class="sub">${node ? `${esc(node.name)} · ${esc(node.host)}:${esc(node.port)}` : '—'}</div></div>
            <button class="btn" id="set-goto-upstream">${esc(t('add_or_manage'))}</button></div>
          <div class="hint" style="margin-top:12px">${esc(t('socks5_hint'))}</div>
        </div>
        <div class="settings-section ${tab === 'dns' ? 'active' : ''}" data-sec="dns">
          <div class="field"><label>${esc(t('dns_server'))}</label><input id="set-dns-server" value="${esc(c.dns?.server || '8.8.8.8')}"></div>
          <div class="field"><label>${esc(t('dns_port'))}</label><input id="set-dns-port" type="number" value="${esc(c.dns?.port || 53)}"></div>
          <div class="settings-row"><div><div class="label">${esc(t('block_local_dns'))}</div><div class="sub">${esc(t('block_local_dns_sub'))}</div></div>
            <label class="switch"><input type="checkbox" id="set-dns-proxy" ${c.dns?.mode === 'proxy' ? 'checked' : ''}><span></span></label></div>
          <div class="settings-row"><div class="label">DoH Block</div>
            <label class="switch"><input type="checkbox" id="set-doh" ${c.dns?.dohBlock ? 'checked' : ''}><span></span></label></div>
          <div class="settings-row"><div class="label">QUIC Block</div>
            <label class="switch"><input type="checkbox" id="set-quic" ${c.dns?.quicBlock ? 'checked' : ''}><span></span></label></div>
        </div>
        <div class="settings-section ${tab === 'diagnostics' ? 'active' : ''}" data-sec="diagnostics">
          <div class="settings-row"><div><div class="label">${esc(t('export_diag'))}</div><div class="sub">${esc(t('export_diag_sub'))}</div></div>
            <button class="btn" id="set-export-diag">${esc(t('export_diag'))}</button></div>
          <div class="settings-row"><div class="label">${esc(t('run_diag'))}</div>
            <button class="btn" id="set-run-diag">${esc(t('run_diag'))}</button></div>
          <div class="settings-row"><div class="label">${esc(t('open_config'))}</div>
            <button class="btn" id="set-open-config">${esc(t('open_config'))}</button></div>
        </div>
        <div class="settings-section ${tab === 'about' ? 'active' : ''}" data-sec="about">
          <div class="kv-row"><span class="k">${esc(t('version'))}</span><span class="v">v${esc(state.version)}</span></div>
          <div class="kv-row"><span class="k">${esc(t('native_dir'))}</span><span class="v" style="font-size:10px">${esc(state.nativeDir)}</span></div>
          <div class="kv-row"><span class="k">${esc(t('config_path'))}</span><span class="v" style="font-size:10px">${esc(state.configPath)}</span></div>
          <div class="divider"></div>
          <div class="field"><label>${esc(t('update_url'))}</label>
            <input id="set-update-url" value="${esc(c.general?.updateUrl || '')}" placeholder="https://…/personal.json"></div>
          <div class="settings-row"><div><div class="label">${esc(t('auto_check_update'))}</div><div class="sub">${esc(t('update_signature_hint'))}</div></div>
            <label class="switch"><input type="checkbox" id="set-auto-update" ${c.general?.autoCheckUpdates !== false ? 'checked' : ''}><span></span></label></div>
          <div class="divider"></div>
          <button class="btn" id="set-licenses">${esc(t('view_licenses'))}</button>
        </div>
      </div>
    </div>`;
  const root = openModal({
    title: t('settings'),
    wide: true,
    body,
    foot: `<button class="btn" data-close>${esc(t('cancel'))}</button><button class="btn btn-primary" id="set-save">${esc(t('save'))}</button>`,
  });

  let chosenLang = state.config?.language || 'zh';
  root.querySelectorAll('.settings-nav [data-tab]').forEach((b) => {
    b.addEventListener('click', () => {
      currentSettingsTab = b.dataset.tab;
      root.querySelectorAll('.settings-nav [data-tab]').forEach((x) => x.classList.toggle('active', x === b));
      root.querySelectorAll('.settings-section').forEach((s) => s.classList.toggle('active', s.dataset.sec === b.dataset.tab));
    });
  });
  root.querySelectorAll('[data-lang]').forEach((b) => {
    b.addEventListener('click', () => {
      chosenLang = b.dataset.lang;
      root.querySelectorAll('[data-lang]').forEach((x) => x.classList.toggle('active', x === b));
    });
  });
  $('#set-goto-upstream', root).addEventListener('click', () => { closeModal(); setPage('upstream'); });
  $('#set-export-diag', root).addEventListener('click', () => gpp.exportDiagnostics().then((r) => toast(r?.path ? t('export_ok') : '导出失败', r?.ok ? 'success' : 'error')));
  $('#set-run-diag', root).addEventListener('click', () => { closeModal(); openDiagnosticsModal(); });
  $('#set-open-config', root).addEventListener('click', () => gpp.openPath(state.configPath));
  $('#set-licenses', root).addEventListener('click', openLicensesModal);
  root.querySelector('.modal-foot [data-close]').addEventListener('click', closeModal);

  $('#set-save', root).addEventListener('click', async () => {
    const patch = {
      language: chosenLang,
      general: {
        closeToTray: $('#set-tray', root).checked,
        autoTrackChildren: $('#set-track', root).checked,
        watchdog: $('#set-watchdog', root).checked,
        udpProxy: $('#set-udp', root).checked,
        updateUrl: $('#set-update-url', root).value.trim(),
        autoCheckUpdates: $('#set-auto-update', root).checked,
      },
      dns: {
        ...(state.config?.dns || {}),
        server: $('#set-dns-server', root).value.trim() || '8.8.8.8',
        port: Number($('#set-dns-port', root).value) || 53,
        mode: $('#set-dns-proxy', root).checked ? 'proxy' : 'system',
        dohBlock: $('#set-doh', root).checked,
        quicBlock: $('#set-quic', root).checked,
      },
    };
    await gpp.saveSettings(patch);
    state.config = { ...state.config, ...patch, general: { ...(state.config?.general || {}), ...patch.general }, dns: { ...(state.config?.dns || {}), ...patch.dns } };
    if (chosenLang !== lang) {
      lang = chosenLang;
      applyI18n();
      renderAll();
    }
    closeModal();
    toast(t('settings_saved'), 'success');
    renderAll();
  });
}

/* ---------- upstream editor ---------- */
function openUpstreamModal(node = null) {
  const isEdit = !!node;
  const body = `
    <div class="field"><label>${esc(t('node_name'))}</label><input id="up-name" value="${esc(node?.name || '')}" placeholder="NekoBox"></div>
    <div class="field-row">
      <div class="field"><label>${esc(t('node_type'))}</label>
        <select id="up-type">
          <option value="http" ${node?.type !== 'socks5' && node?.type !== 'shadowsocks' ? 'selected' : ''}>HTTP / Mixed</option>
          <option value="socks5" ${node?.type === 'socks5' ? 'selected' : ''}>SOCKS5</option>
          <option value="shadowsocks" ${node?.type === 'shadowsocks' ? 'selected' : ''}>Shadowsocks</option>
        </select>
      </div>
      <div class="field"><label>${esc(t('node_port'))}</label><input id="up-port" type="number" value="${esc(node?.port ?? 2080)}"></div>
    </div>
    <div class="field" id="up-method-row" style="${node?.type === 'shadowsocks' ? '' : 'display:none'}">
      <label>${esc(t('node_method'))}</label>
      <select id="up-method">
        <option value="aes-256-gcm" ${(node?.method || 'aes-256-gcm') === 'aes-256-gcm' ? 'selected' : ''}>aes-256-gcm</option>
        <option value="aes-128-gcm" ${node?.method === 'aes-128-gcm' ? 'selected' : ''}>aes-128-gcm</option>
        <option value="chacha20-ietf-poly1305" ${node?.method === 'chacha20-ietf-poly1305' ? 'selected' : ''}>chacha20-ietf-poly1305</option>
      </select>
    </div>
    <div class="field"><label>${esc(t('node_host'))}</label><input id="up-host" value="${esc(node?.host || '127.0.0.1')}"></div>
    <div class="field-row">
      <div class="field"><label>${esc(t('node_user'))}</label><input id="up-user" value="${esc(node?.username || '')}" autocomplete="off"></div>
      <div class="field"><label>${esc(t('node_pass'))}</label><input id="up-pass" type="password" value="${esc(node?.password || '')}" autocomplete="off"></div>
    </div>
    <div class="settings-row" style="border:0;padding-top:4px">
      <div class="label">${esc(t('set_active'))}</div>
      <label class="switch"><input type="checkbox" id="up-active" ${isEdit ? (state.config?.activeUpstreamId === node.id ? 'checked' : '') : 'checked'}><span></span></label>
    </div>
    <div class="hint">${esc(t('socks5_hint'))}</div>`;
  const foot = `${isEdit ? `<button class="btn btn-danger" id="up-delete">${esc(t('delete'))}</button>` : ''}
    <span style="flex:1"></span>
    <button class="btn" data-close>${esc(t('cancel'))}</button>
    <button class="btn btn-primary" id="up-save">${esc(t('save'))}</button>`;
  const root = openModal({
    title: isEdit ? t('edit_node_title') : t('add_node_title'),
    narrow: true,
    body,
    foot,
    onMount: (r) => {
      r.querySelector('.modal-foot [data-close]').addEventListener('click', closeModal);
      const typeSel = $('#up-type', r);
      const methodRow = $('#up-method-row', r);
      const syncType = () => { methodRow.style.display = typeSel.value === 'shadowsocks' ? '' : 'none'; };
      typeSel.addEventListener('change', syncType);
      syncType();
      const save = async () => {
        const data = {
          name: $('#up-name', r).value.trim() || '上游节点',
          type: typeSel.value,
          host: $('#up-host', r).value.trim() || '127.0.0.1',
          port: Number($('#up-port', r).value) || 2080,
          username: $('#up-user', r).value,
          password: $('#up-pass', r).value,
          method: $('#up-method', r).value,
          activate: $('#up-active', r).checked,
        };
        if (isEdit) await gpp.upstream.update(node.id, data);
        else await gpp.upstream.add(data);
        toast(t('node_saved'), 'success');
        closeModal();
      };
      $('#up-save', r).addEventListener('click', save);
      $('#up-delete', r)?.addEventListener('click', async () => {
        const res = await gpp.upstream.remove(node.id);
        if (res && res.ok) { toast(t('node_deleted'), 'success'); closeModal(); }
        else toast((res && res.error) || '删除失败', 'error');
      });
    },
  });
}

/* ---------- DNS editor ---------- */
function openDnsModal() {
  const d = state.config?.dns || {};
  const root = openModal({
    title: t('dns_edit_title'),
    narrow: true,
    body: `
      <div class="hint" style="margin:-2px 0 14px">${esc(t('dns_edit_sub'))}</div>
      <div class="field"><label>${esc(t('dns_server'))}</label><input id="dns-server-input" value="${esc(d.server || '8.8.8.8')}"></div>
      <div class="field"><label>${esc(t('dns_port'))}</label><input id="dns-port-input" type="number" value="${esc(d.port || 53)}"></div>`,
    foot: `<button class="btn" data-close>${esc(t('cancel'))}</button><button class="btn btn-primary" id="dns-save">${esc(t('save'))}</button>`,
    onMount: (r) => {
      r.querySelector('.modal-foot [data-close]').addEventListener('click', closeModal);
      $('#dns-save', r).addEventListener('click', async () => {
        const res = await gpp.dns.set($('#dns-server-input', r).value.trim(), Number($('#dns-port-input', r).value) || 53);
        if (res && res.ok) { toast(t('dns_saved'), 'success'); closeModal(); }
        else toast((res && res.error) || '保存失败', 'error');
      });
    },
  });
}

/* ---------- process details ---------- */
function openProcessModal(pid) {
  const p = (state.processes || []).find((x) => x.pid === pid);
  if (!p) return;
  const root = openModal({
    title: t('process_detail'),
    narrow: true,
    body: `
      <div class="kv-row"><span class="k">${esc(t('pid_label'))}</span><span class="v">${p.pid}</span></div>
      <div class="kv-row"><span class="k">${esc(t('path_label'))}</span><span class="v" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:10px">${esc(p.path)}</span></div>
      <div class="kv-row"><span class="k">${esc(t('members_label'))}</span><span class="v">${p.members || 1}</span></div>
      <div class="kv-row"><span class="k">${esc(t('children_label'))}</span><span class="v">${p.children || 0}</span></div>
      <div class="divider"></div>
      <div class="kv-row"><span class="k">${esc(t('down_label'))}</span><span class="v">${fmtBytes(p.down)}</span></div>
      <div class="kv-row"><span class="k">${esc(t('up_label'))}</span><span class="v">${fmtBytes(p.up)}</span></div>
      <div class="kv-row"><span class="k">${esc(t('conns_label'))}</span><span class="v">${p.conns || 0}</span></div>
      <div class="kv-row"><span class="k">${esc(t('latency_label'))}</span><span class="v">${p.latency == null ? '—' : p.latency + ' ms'}</span></div>`,
    foot: `<button class="btn" id="proc-open">${esc(t('open_location'))}</button>
      <span style="flex:1"></span>
      <button class="btn" data-close>${esc(t('close'))}</button>
      <button class="btn btn-danger" id="proc-stop">${esc(t('stop_manage'))}</button>`,
    onMount: (r) => {
      r.querySelector('.modal-foot [data-close]').addEventListener('click', closeModal);
      $('#proc-open', r).addEventListener('click', () => gpp.openPath(p.path));
      $('#proc-stop', r).addEventListener('click', async () => {
        await gpp.stopManaging(p.pid);
        closeModal();
        toast(`${p.name} 已停止管理`, 'info');
      });
    },
  });
}

/* ---------- terminal modal ---------- */
function openTerminalModal() {
  const terms = (state.processes || []).filter((p) => p.terminal || /^(cmd|powershell|pwsh|windowsterminal|wt)\.exe$/i.test(basename(p.path || p.name)));
  const root = openModal({
    title: t('terminal_title'),
    body: `
      <div class="hint" style="margin:-2px 0 12px">${esc(t('terminal_sub'))}</div>
      <div class="terminal-launch-grid">
        <button class="terminal-launch" id="launch-cmd"><span class="big">&gt;_</span><span><span class="t">${esc(t('launch_cmd'))}</span><br><span class="s">cmd.exe · CREATE_NEW_CONSOLE</span></span></button>
        <button class="terminal-launch" id="launch-ps"><span class="big" style="color:#38bdf8">&gt;_</span><span><span class="t">${esc(t('launch_ps'))}</span><br><span class="s">powershell.exe · CREATE_NEW_CONSOLE</span></span></button>
      </div>
      <div class="term-list" id="term-list">
        ${terms.length ? terms.map((p) => `<div class="term-row">${processIcon(p, 'process-icon')}<span>${esc(p.name)}</span><span class="pid">PID ${p.pid} · ${p.conns || 0} conns</span></div>`).join('') : `<div class="hint" style="padding:12px 0">${esc(t('terminal_empty'))}</div>`}
      </div>`,
    foot: `<button class="btn" data-close>${esc(t('close'))}</button>`,
    onMount: (r) => {
      r.querySelector('.modal-foot [data-close]').addEventListener('click', closeModal);
      $('#launch-cmd', r).addEventListener('click', () => gpp.launchTerminal('cmd'));
      $('#launch-ps', r).addEventListener('click', () => gpp.launchTerminal('powershell'));
    },
  });
}

/* ---------- diagnostics ---------- */
async function openDiagnosticsModal() {
  const root = openModal({
    title: t('diagnostics_title'),
    narrow: true,
    body: `<div id="diag-body" class="diag-list"><div class="hint" style="padding:14px 0">${esc(t('running'))}</div></div>`,
    foot: `<button class="btn" data-close>${esc(t('close'))}</button>`,
    onMount: (r) => r.querySelector('.modal-foot [data-close]').addEventListener('click', closeModal),
  });
  let res;
  try { res = await gpp.runDiagnostics(); } catch (e) { res = { checks: [], error: e.message }; }
  const names = {
    '原生组件': t('check_native'), '上游节点': t('check_upstream'), 'DNS 代理': t('check_dns'),
    '托管进程': t('check_managed'), 'TCP 重传率': t('check_tcp'),
  };
  $('#diag-body', root).innerHTML = (res.checks || []).map((c) => `
    <div class="diag-item">
      <span class="${c.ok ? 'ok' : 'bad'}">${c.ok ? '✓' : '!'}</span>
      <span class="name">${esc(names[c.name] || c.name)}</span>
      <span class="detail">${esc(c.detail || '')}</span>
    </div>`).join('') || `<div class="hint">${esc(res.error || '—')}</div>`;
}

/* ---------- signed update ---------- */
function openUpdateModal(info, auto = false) {
  const sizeMb = (Number(info.size || 0) / 1024 / 1024).toFixed(2);
  const root = openModal({
    title: auto ? t('update_available') : t('update_title'),
    narrow: true,
    body: `
      <div class="diag-item" style="margin-bottom:12px">
        <span class="ok">↑</span>
        <span class="name">v${esc(info.version)}</span>
        <span class="detail">${esc(sizeMb)} MB</span>
      </div>
      <div class="kv-row"><span class="k">${esc(t('update_current'))}</span><span class="v">v${esc(info.current || state.version)}</span></div>
      <div class="kv-row"><span class="k">${esc(t('update_latest_version'))}</span><span class="v green">v${esc(info.version)}</span></div>
      <div class="kv-row"><span class="k">${esc(t('update_size'))}</span><span class="v">${esc(sizeMb)} MB</span></div>
      ${info.notesUrl ? `<div class="kv-row"><span class="k">${esc(t('update_notes'))}</span><span class="v"><a href="#" id="update-notes" style="color:#5b9bff">GitHub</a></span></div>` : ''}
      <div class="hint" style="margin-top:12px">${esc(t('update_signature_hint'))}</div>`,
    foot: `<button class="btn" data-close>${esc(t('cancel'))}</button>
      <button class="btn btn-primary" id="update-install">${esc(t('download_install'))}</button>`,
    onMount: (r) => {
      r.querySelector('.modal-foot [data-close]').addEventListener('click', closeModal);
      if (info.notesUrl) {
        $('#update-notes', r)?.addEventListener('click', (e) => { e.preventDefault(); gpp.openExternal(info.notesUrl); });
      }
      $('#update-install', r).addEventListener('click', async (ev) => {
        const b = ev.currentTarget;
        b.disabled = true;
        b.textContent = t('installing');
        const res = await gpp.installUpdate();
        if (res && res.ok) {
          toast(t('installing'), 'success');
          closeModal();
        } else {
          b.disabled = false;
          b.textContent = t('download_install');
          toast((res && res.error) || '安装失败', 'error');
        }
      });
    },
  });
}

/* ---------- licenses ---------- */
async function openLicensesModal() {
  let lic = { ghost: '', minhook: '' };
  try { lic = await gpp.getLicenses(); } catch {}
  const root = openModal({
    title: t('licenses'),
    wide: true,
    body: `
      <div class="table-head" style="padding:0 0 8px"><h2>Ghost Proxifier (MIT)</h2></div>
      <pre class="license-text">${esc(lic.ghost || '—')}</pre>
      <div class="table-head" style="padding:14px 0 8px"><h2>MinHook (BSD 2-Clause)</h2></div>
      <pre class="license-text">${esc(lic.minhook || '—')}</pre>`,
    foot: `<button class="btn" data-close>${esc(t('close'))}</button>`,
    onMount: (r) => r.querySelector('.modal-foot [data-close]').addEventListener('click', closeModal),
  });
}

/* ============================== events ============================== */

function bindEvents() {
  $('#nav').addEventListener('click', (e) => {
    const b = e.target.closest('.nav-item');
    if (b) setPage(b.dataset.page);
  });
  $('#collapse-btn').addEventListener('click', () => {
    $('#sidebar').classList.toggle('collapsed');
  });
  $('#btn-go-settings').addEventListener('click', () => openSettings('proxy'));
  $('#act-smart').addEventListener('click', openSmartScan);
  $('#act-manual').addEventListener('click', async () => {
    const r = await gpp.pickExecutable();
    handleAddResults(r);
  });
  $('#act-cmd').addEventListener('click', () => gpp.launchTerminal('cmd'));
  $('#act-ps').addEventListener('click', () => gpp.launchTerminal('powershell'));
  $('#btn-export').addEventListener('click', () => gpp.exportReport().then((r) => { if (r?.ok) toast(t('export_ok'), 'success'); }));
  $('#btn-test-all').addEventListener('click', async () => {
    toast(t('testing'), 'info');
    await gpp.upstream.testAll();
    toast(t('all_tested'), 'success');
  });
  $('#btn-add-node').addEventListener('click', () => openUpstreamModal(null));
  $('#dns-hero').addEventListener('dblclick', openDnsModal);
  $('#dns-proxy-toggle').addEventListener('change', (e) => gpp.dns.setProxyEnabled(e.target.checked));
  $('#upstream-list').addEventListener('click', (e) => {
    const edit = e.target.closest('[data-edit]');
    if (edit) {
      const n = (state.config?.upstreams || []).find((x) => x.id === edit.dataset.edit);
      if (n) openUpstreamModal(n);
      return;
    }
    const card = e.target.closest('.upstream-card');
    if (card && card.dataset.id && card.dataset.id !== state.config?.activeUpstreamId) {
      gpp.upstream.activate(card.dataset.id);
    }
  });
  $('#process-grid').addEventListener('click', (e) => {
    const card = e.target.closest('.process-card');
    if (card) openProcessModal(Number(card.dataset.pid));
  });
  $('#btn-licenses').addEventListener('click', openLicensesModal);
  $('#btn-check-update').addEventListener('click', async () => {
    const r = await gpp.checkUpdate();
    if (!r || !r.ok) {
      toast((r && r.error) || '检查更新失败', 'error');
    } else if (!r.available) {
      toast(`${t('update_latest')} (v${state.version})`, 'success');
    } else {
      openUpdateModal(r, false);
    }
  });

  // drag & drop overlay (paths handled in preload/main)
  let dragDepth = 0;
  window.addEventListener('dragenter', (e) => {
    e.preventDefault();
    dragDepth++;
    $('#drag-overlay').classList.add('visible');
  });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('dragleave', (e) => {
    e.preventDefault();
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) $('#drag-overlay').classList.remove('visible');
  });
  window.addEventListener('drop', (e) => {
    e.preventDefault();
    dragDepth = 0;
    $('#drag-overlay').classList.remove('visible');
  });

  window.addEventListener('resize', () => {
    if (currentPage === 'stats') renderStats();
  });
}

/* ============================== bootstrap ============================== */

async function bootstrap() {
  let boot;
  try {
    boot = await gpp.getBootstrap();
  } catch (e) {
    document.body.innerHTML = `<div style="padding:40px;color:#ff8a8a;font-family:sans-serif">Bootstrap failed: ${esc(e.message)}</div>`;
    return;
  }
  Object.assign(state, boot);
  lang = boot.config?.language || 'zh';
  logBuf = boot.logs || [];
  applyI18n();
  bindEvents();
  setPage('process');
  renderAll();
  renderLogs(true);
  if (state.stats && state.stats.nativeReady === false) {
    setTimeout(() => toast('原生组件未找到：请先编译 native/bin/gpp_core_x64.dll 与 gppctl.exe', 'error'), 600);
  }

  gpp.onState((s) => {
    const logs = logBuf;
    Object.assign(state, s);
    if (s.config?.language && s.config.language !== lang) {
      lang = s.config.language;
      applyI18n();
    }
    renderAll();
  });
  gpp.onLog((l) => appendLog(l));
  gpp.onDns((r) => {
    if (state.dnsRecords[0] && state.dnsRecords[0].domain === r.domain && state.dnsRecords[0].pid === r.pid && state.dnsRecords[0].status === r.status) return;
    state.dnsRecords.unshift(r);
    if (state.dnsRecords.length > 60) state.dnsRecords.pop();
    if (currentPage === 'dns') renderDns();
  });
  gpp.onToast((tmsg) => toast(tmsg.message, tmsg.type));
  gpp.onNeedsChoice((req) => openRunningPrompt(req));
  gpp.onUpdateAvailable((info) => openUpdateModal(info, true));
  setInterval(() => { if (currentPage === 'stats') drawChart(state.history || []); }, 1000);
}

// Debug/automation handle (used by the local CDP test harness).
window.__gppDebug = {
  get state() { return state; },
  setPage, renderAll, openSettings, openSmartScan, openDnsModal, openProcessModal,
  openTerminalModal, openDiagnosticsModal, toast,
};

bootstrap();

})();
