# Ghost Proxifier 实现原理分析

本文基于两个公开仓库：

- `liliBestCoder/ghost-proxifier-pro`：只有官网、README、截图、更新清单，**没有客户端源码**。
- `liliBestCoder/ghost-proxifier`：作者提供的 **MIT 开源命令行前身**，Pro 版的核心注入/Hook 机制与其一脉相承。

因此“实现原理”的结论来自：Pro 版 README 的架构描述与截图 + 开源版约 5500 行 C++ 源码的逐文件分析。复刻版在此基础上重新实现并扩展（SOCKS5、UDP、GUI、统计、子进程管理），不是对闭源 Pro 二进制做逆向。

---

## 1. 总体架构

```
目标进程 (Chrome / Edge / Cursor / Claude / ...)
┌──────────────────────────────────────────────────────────────┐
│ getaddrinfo / GetAddrInfoW / DnsQuery_*  ->  代理 DNS 解析    │
│ connect / WSAConnect / ConnectEx         ->  重定向到代理     │
│ send / WSASend (首次)                    ->  HTTP CONNECT     │
│ sendto / WSASendTo                       ->  DNS / QUIC / UDP │
│ recvfrom / WSARecvFrom                   ->  改写来源地址     │
│                                                              │
│            gpp_core_x64.dll（注入到目标进程）                 │
└──────────────────────────┬───────────────────────────────────┘
                           │ TCP / UDP
                 ┌─────────┴──────────┐
                 │ 上游 HTTP / SOCKS5 │  Clash / NekoBox / v2rayN
                 │ 127.0.0.1:xxxx     │
                 └────────────────────┘
                           ▲
              UDP 45001 日志 / 45002 统计
                           │
                 Electron 主进程 / 界面
```

关键点：**代理决策发生在目标进程内部**，因此不需要内核驱动、TUN 网卡或路由表；只影响被注入的进程树。代价是需要处理 Winsock 的各种 API、异步 IO 与进程注入兼容性。

---

## 2. 注入：EntryDetour 与 CreateRemoteThread

### 2.1 为什么不能直接 `CreateRemoteThread(LoadLibrary)`

对**挂起启动**的进程，`CreateRemoteThread` 可能在 `LdrInitializeThunk` 完成 DLL 初始化之前执行。此时 `ws2_32.dll` 可能尚未加载，`GetProcAddress(ws2_32, "connect")` 返回 NULL，Hook 装不上；目标随后正常初始化，所有流量直连。

### 2.2 EntryDetour（x64）

开源版 `core/shellcode.cpp` + `core/injector.cpp`：

1. `CreateProcess(..., CREATE_SUSPENDED)` 创建目标进程。
2. 读取主线程 `CONTEXT`，此时 `RIP = LdrInitializeThunk`，`RCX = EXE 入口点`。
3. 在目标进程分配 `PAGE_EXECUTE_READWRITE` 内存，写入一段位置无关 shellcode 和数据：

```
偏移 0x00  shellcode（0x57 字节）
偏移 0x58  原 EXE 入口点（保存的 RCX）
偏移 0x60  LoadLibraryW
偏移 0x68  GetProcAddress
偏移 0x70  WaitForSingleObject
偏移 0x78  hEvent（复刻版传 NULL）
偏移 0x80  "GhostInit\0"
偏移 0x8A  DLL 路径（UTF-16）
```

4. 把 `CONTEXT.Rcx` 改为 shellcode 地址，`SetThreadContext`，再 `ResumeThread`。
5. `LdrInitializeThunk` 先完成所有 DLL 初始化，然后按约定跳到 `RCX` 指向的 shellcode。
6. shellcode：`LoadLibraryW(dll)` → `GetProcAddress(h, "GhostInit")` → `GhostInit()` → `WaitForSingleObject(hEvent, 5000)` → 恢复寄存器 → `jmp 原入口`。

这样 `GhostInit` 运行在**第一个线程**且所有 DLL 已就绪。对 Cygwin/MSYS2 程序尤其重要：`cygtls` 只对收到 `DLL_PROCESS_ATTACH` 的线程正确初始化，换线程启用 MinHook 会导致 `SIGSEGV`。

### 2.3 回退路径

- x86 目标：开源版没有 x86 shellcode，直接回退 `CreateRemoteThread(LoadLibraryA)`。
- 跨架构：由 `ghost_launcher_x86.exe` / `ghost_launcher_x64.exe` 代注入。
- 权限不足：启用 `SeDebugPrivilege` 后重试；仍失败则提示管理员运行。

### 2.4 初始化时机与线程安全

- `DllMain(DLL_PROCESS_ATTACH)` 也调用 `GhostInit`，用 `g_Initialized` 防止 shellcode 和 DllMain 双初始化。
- `SetupThreadInternal`：
  1. 从环境变量 `GHOST_*` 或 `ghost_config.ini` 读取代理/DNS 配置；
  2. `MH_Initialize`；
  3. 解析 `ws2_32` 全部函数指针；
  4. **提前 Hook `ConnectEx`**（应用可能已通过 `WSAIoctl` 缓存指针）；
  5. 加载 `dnsapi.dll` 并解析 `DnsQuery_*`；
  6. 安装 socket/DNS Hook，`MH_EnableHook(MH_ALL_HOOKS)`；
  7. 启动本地 DNS 网关线程与统计线程；
  8. 把配置写回环境变量，子进程继承。

---

## 3. Winsock Hook 与延迟握手

### 3.1 Hook 列表

| API | 作用 |
| --- | --- |
| `connect` / `WSAConnect` / `ConnectEx` | 目标改为代理地址，保存目标信息到 `PendingMap` |
| `send` / `WSASend` | 首次发送前完成 HTTP CONNECT / SOCKS5；关闭绕过代理的旧 socket |
| `recv` / `WSARecv` | 同样处理 pending；强制旧连接重连 |
| `sendto` / `WSASendTo` | UDP 53 重定向到本地 DNS 网关；UDP 443 阻断；SOCKS5 UDP 封装 |
| `recvfrom` / `WSARecvFrom` | DNS 响应来源地址伪装；SOCKS5 UDP 头剥离 |
| `getaddrinfo` / `GetAddrInfoW` / `gethostbyname` | 域名解析改走代理 DNS |
| `GetAddrInfoExW` / `DnsQuery_W/A` / `DnsQueryEx` | Windows 8+ / Chromium / Cygwin 使用的异步 DNS |
| `closesocket` | 清理 PendingMap、代理完成集合、UDP ASSOCIATE |
| `WSAIoctl` | 延迟 Hook `ConnectEx`（兜底已缓存指针的进程） |

### 3.2 延迟握手

同步握手会阻塞 `connect()`，Chrome/Node 的非阻塞 IO 线程会认为进程卡死。开源版的做法：

1. `connect(s, 目标)`：
   - 把目标 IP/端口/域名写入 `g_PendingProxySockets[s]`；
   - 用 `real_connect(s, 代理地址)` 把 socket 连到代理；
   - 立即返回（非阻塞 socket 返回 `WSAEWOULDBLOCK`，由应用照常等待可写）。
2. 首次 `send`/`WSASend`：
   - `select` 等待代理连接可写（5 秒超时）；
   - 发送 `CONNECT host:port HTTP/1.1`（HTTP）或 SOCKS5 握手；
   - 成功后把 socket 加入 `g_ProxyCompletedSockets`，后续 send/recv 走快路径。
3. `close` 时清理。

`ConnectEx` 还要处理 `lpSendBuffer`：应用可能把首包直接交给 ConnectEx；Hook 暂存它，等握手完成后再补发。

### 3.3 域名优先

`connect()` 拿到的是 IP。DNS Hook 在解析时把每个结果写入 `IP→域名` 映射；`connect` 时反查域名，CONNECT 优先用域名：

```
CONNECT www.google.com:443
```

而不是 `CONNECT 142.251.45.10:443`。这样上游代理可以按域名规则精确分流；只有反查不到时才退回 IP + GeoIP。

### 3.4 防绕过

- 注入前已存在的 TCP socket：`send`/`recv` 中发现它是外部 TCP 且不在代理完成集合，直接 `closesocket` 并返回 `WSAECONNRESET`，迫使应用重连 → 新连接被接管。
- 非阻塞/重叠 IO：Hook 必须保持原 socket 的阻塞模式与 overlapped 语义；不能把应用 socket 改成阻塞。
- `WSAIoctl` Hook 确保后来才取 `ConnectEx` 指针的进程也走 Hook。

---

## 4. DNS 子系统

### 4.1 同步/异步 DNS API

`getaddrinfo` / `GetAddrInfoW` / `gethostbyname` / `GetAddrInfoExW` / `DnsQuery_W` / `DnsQuery_A` / `DnsQueryEx` 在 `DnsMode == "dot"` 时调用 `ProxyDnsResolve(domain)`：

1. 查跨进程共享内存缓存（256 条，FNV-1a 哈希，20 分钟 TTL）；
2. 查进程内缓存；
3. 缓存未命中：构造 DNS A 查询（12 字节头 + QNAME + QTYPE/QCLASS），通过上游代理打开 `DNS_IP:53` 的 TCP 隧道，发送 2 字节长度前缀 + 报文，读回并解析 A 记录；
4. 把结果写回两级缓存，并记录 `IP→域名`；
5. 把第一个 IP 转成字符串，调用真实 `getaddrinfo("1.2.3.4", ...)`，让系统构造合法的 `ADDRINFO` 结构（避免手工分配出错）；
6. `DnsQuery_*` 则用 `LocalAlloc` 构造 `DNS_RECORD`，`DnsFree` 可正常释放；AAAA 查询降级为 A。

DNS 连接池（最多 16 条）复用 TCP 隧道，减少握手开销。

### 4.2 本地 UDP DNS 网关

有些程序不走 `getaddrinfo`，直接 `sendto(8.8.8.8:53)`。`DnsProxyThread` 在 `127.0.0.1:随机端口` 绑定 UDP socket：

- `sendto` Hook 把目标为 UDP 53 的报文改发到本地网关；
- 网关把 UDP 报文转成 TCP，经代理隧道发往配置的 DNS 服务器；
- 响应通过 `recvfrom` Hook 把来源地址从 `127.0.0.1:网关端口` 伪装回 `DNS_IP:53`，应用无感。

### 4.3 DoH 阻断

Chrome/Edge 会尝试 DoH。`IsKnownDoHServer` 识别 `8.8.8.8`、`8.8.4.4`、`1.1.1.1`、`1.0.0.1` 及对应 IPv6 地址；命中且端口为 443 时，`connect` 直接返回 `WSAECONNREFUSED`。浏览器回退标准 DNS，被 UDP DNS 网关接管。

> 复刻版修复了参考实现的一个细节：原 `IsKnownDoHServer` 忽略端口，会把 `1.1.1.1:8080` 这类同 IP 的非 DoH 服务也拒绝。复刻版只在 443 时阻断。

### 4.4 QUIC 阻断

UDP 443 被阻断（返回 `WSAENETUNREACH` 并关闭 socket），浏览器回退 TCP/HTTP2。这样 UDP 443 不会绕过代理，也不需要实现完整的 UDP-over-proxy 才能保证网页流量不泄漏。

---

## 5. 上游协议

### 5.1 HTTP CONNECT

```
CONNECT host:port HTTP/1.1
Host: host:port
Proxy-Connection: Keep-Alive
User-Agent: GhostProxifier/1.0
```

读取响应直到 `\r\n\r\n`，状态行含 ` 200 ` 即成功。逐字节读取是为了不吞掉紧随其后的应用数据（例如 SSH banner）。

### 5.2 SOCKS5

复刻版新增：

- greeting：`05 01 00`（无认证）或 `05 02 00 02`（用户名/密码）
- 认证：`01 ULEN USER PLEN PASS`，检查 `01 00`
- CONNECT：`05 01 00 ATYP ADDR PORT`，域名优先（ATYP=3），否则 IPv4/IPv6
- 回复：检查 `REP=0`，跳过 BND.ADDR/BND.PORT

SOCKS5 UDP ASSOCIATE：

- 控制连接：greeting/auth 后发 `05 03 00 01 00 00 00 00 00 00`
- 响应给出 relay 地址；复刻版把 `0.0.0.0` 替换为代理 IP
- 数据报格式：`RSV(2) FRAG(1) ATYP ADDR PORT DATA`
- 当前实现覆盖**同步、未连接**的 `sendto`/`recvfrom`；`recvfrom` Hook 负责剥掉头并把来源改回目标地址

---

## 6. 统计与日志

注入进程每 2 秒通过 UDP 向 `127.0.0.1:45002` 发送：

```
[stats] guid:<...>|pid:1234|ppid:1|up:123|down:456|lat:35|conns:4|node:Clash|dns:dot|blocked:2|type:http
```

日志通过 `127.0.0.1:45001` 发送：

```
[003.125] [1234:5678] [Proxy] Handshake OK: www.google.com:443 | ... (latency 35ms)
```

UI 主进程：

- 用 PID/PPID 构建进程树；
- 把每个注入进程的累计字节聚合到根进程；
- 每秒计算总字节增量 → 60 秒吞吐量柱状图；
- 从日志解析 DNS 记录（`resolved:` / `Query:` / `Blocking DoH` / `Blocking UDP 443`）；
- `GetTcpStatistics` 提供系统级 TCP 重传率。

---

## 7. Pro 版界面拆解（截图）

| 页面 | 推断的功能与数据来源 |
| --- | --- |
| 活动进程 | 托管根进程卡、连接数徽标、子进程计数、快捷启动 CMD/PowerShell、代理终端分组 |
| 流量统计 | 总下载/上传、活动连接、DNS 拦截、60 秒实时图、进程流量排行、导出报表、网络诊断 |
| DNS 安全 | 主解析服务器、端口、拦截并代理本地 DNS、最近重定向记录（域名、修正 IP、进程、状态）、实时日志 |
| 上游节点 | HTTP/SOCKS5/Shadowsocks 节点列表、当前使用、URL Test 延迟、可用性、添加上游、检测全部 |
| 授权许可 | FREE & UNLOCKED、¥0.00、功能列表、更新检查 |
| 右侧栏 | 按页面切换：网络诊断 / 实时日志 / 节点状态 |
| 托盘/设置 | 关闭最小化、语言、排障包、自动更新（签名清单） |

复刻版按截图 1:1 还原了布局、配色、卡片、字体层级、图表、日志面板与弹窗交互；设置页因原版未提供截图，按相同设计语言补全。

---

## 8. 复刻版与开源前身的差异

| 能力 | 开源版 | 复刻版 |
| --- | --- | --- |
| 上游 | HTTP CONNECT | HTTP + SOCKS5（含认证）+ Shadowsocks AEAD |
| UDP | 仅 DNS / QUIC 处理 | 完整 UDP 本地中继（SOCKS5 / Shadowsocks，含 connected 与 overlapped 发送） |
| WinStore/UWP | 无 | COM 激活 + AppContainer 可读 DLL + 注入 |
| 更新 | 无 | ECDSA P-256 签名清单 + 下载校验 + ZIP/MSI 安装 |
| Watchdog | 无 | 注入丢失自动恢复 + 上游可用性事件 |
| 配置 | 环境变量 / INI | INI + 主进程热加载 |
| 界面 | CLI | Electron 完整 GUI |
| 进程管理 | 单 PID / --tree 轮询 | 根进程 + 子进程树自动注入、重启恢复 |
| 统计 | UDP `[stats]` 文本 | 实时聚合、图表、排行、导出 |
| 卸载 | eject | GhostShutdown + FreeLibrary 安全卸载 |
| 注入 | EntryDetour + 回退 | 沿用并增加已注入幂等判断 |

---

## 9. 关键源码索引

- 注入：`native/core/ghost_core.cpp`、`native/ctl/main.cpp`（EntryDetour shellcode + SetThreadContext）
- TCP Hook：`native/core/hooks_socket.cpp`
- DNS Hook：`native/core/hooks_dns.cpp`、`native/core/dns.cpp`
- 代理握手：`native/core/proxy.cpp`
- UDP 中继：`native/core/udp.cpp`
- Shadowsocks AEAD：`native/core/ss.cpp`
- UWP 激活：`native/ctl/main.cpp`（`CmdUwp`）
- 签名更新：`app/main.js`（`verifySignedManifest` / `checkUpdate` / `installUpdate`）、`tools/sign-update.js`
- Watchdog：`app/main.js`（`watchdogTick`）
- 配置热加载：`native/core/config.cpp`
- 统计/日志：`native/core/utils.cpp`
- UI 主进程：`app/main.js`
- 渲染：`app/src/app.js`、`app/src/styles.css`

---

## 10. 验证记录

本地测试使用回环代理 `test/proxy.js`（HTTP CONNECT / SOCKS5 / 假 DNS / TLS 204 / UDP echo），不依赖外网：

```
HTTP CONNECT:  OK 200 HELLO_FROM_PROXY_TARGET
SOCKS5 TCP:    OK 200 HELLO_FROM_PROXY_TARGET
DNS over TCP:  DNS_OK 203.0.113.10 HTTP_OK 200 ...
DoH block:     BLOCKED ECONNREFUSED
QUIC block:    BLOCKED ENETUNREACH
UDP sendto:    SENDTO_OK ECHO:sendto-udp ('1.1.1.1', 9999)
UDP connected: CONNECTED_OK ECHO:connected-udp peer=('1.1.1.1', 9999)
UDP overlapped: OK ECHO:node-sendto-udp from 1.1.1.1:9999
SS TCP+DNS:    DNS_OK 203.0.113.10 HTTP_OK 200 (aes-128/256, chacha)
SS UDP:        OK ECHO:node-sendto-udp from 1.1.1.1:9999 (aes-128/256, chacha)
Edge fresh:    members=4, proxy log: CONNECT www.bing.com:443
UWP:           ActivateApplication -> pid; inject --dll -> isinjected:true
Update:        v1.0.0 -> 1.0.1 available; tampered manifest rejected
Watchdog:      eject -> injected:false; 32s later injected:true
Eject:         isinjected: true -> false, target alive
Packaged app:  v1.1.0, nativeReady=true, UWP names UTF-8, Clash URL Test OK
```

> 注：测试中的 Edge 报 `ERR_SSL_PROTOCOL_ERROR` 是因为回环假代理对 HTTPS CONNECT 返回了普通 HTTP，并非产品缺陷；切换到真实的 Clash Verge 节点后浏览恢复正常。

---

## 11. 完整 UDP 中继（复刻版新增）

早期的 `sendto` 头封装方案无法覆盖 overlapped `WSASendTo`，也无法处理 connected UDP。复刻版改为**本地端点中继**：

1. 对每个 (应用 socket, 目标) 在 `127.0.0.1` 绑定一个 UDP 端点，并创建一个到上游的 SOCKS5 UDP ASSOCIATE 或 Shadowsocks UDP 加密通道。
2. 应用的 `sendto` / `WSASendTo` 只把目标地址改成本地端点；**应用缓冲区完全不变**，因此 overlapped/IOCP 发送由 I/O 管理器正常完成。
3. 应用的 `connect()` 对 UDP 重定向到本地端点；`getpeername` Hook 返回真实目标，应用认为自己仍连着目标。
4. 中继线程负责把数据报封装/加密后发往上游，并把响应解封装后回送给应用的源地址。
5. 同步 `recvfrom` Hook 用“本地端口 → 目标”映射把来源地址伪装回真实目标；overlapped `WSARecvFrom` 的来源地址由 I/O 管理器填写，仍是本地端点（数据正确）。

这使 Node/libuv、游戏客户端等使用 overlapped UDP 的程序也能代理，而无需伪造 IOCP 完成。

## 12. Shadowsocks AEAD

- 经典 AEAD 方法：aes-128-gcm、aes-256-gcm、chacha20-ietf-poly1305。
- 主密钥：EVP_BytesToKey（MD5）；会话子密钥：HKDF-SHA1，info=`ss-subkey`。
- TCP：客户端发送随机 salt，之后每个 chunk 用递增 nonce 分别加密 2 字节长度和载荷；目标地址（域名/IPv4/IPv6 + 端口）作为第一段明文。
- UDP：每个数据报随机 salt + 整包 AEAD，明文为地址头 + 载荷；响应由服务器用自己的 salt 重新加密。
- TCP 通过本地 loopback 监听器接入应用连接；应用仍然使用普通 socket/overlapped I/O，中继线程负责 AEAD 分帧与双向泵送。
- DNS 也复用同一条 SS TCP 中继：`SsCreateDnsSocket` 返回一个已连接到本地中继的 socket，原 DNS-over-TCP 代码无需改动。

## 13. WinStore / UWP 注入

1. `gppctl uwp <AUMID>` 调用 `CoCreateInstance(CLSID_ApplicationActivationManager)` 和 `ActivateApplication`，返回应用 PID。
2. DLL 先复制到 `C:\ProgramData\GhostProxifier`（失败则 Public/userData），并 `icacls` 授予 `ALL APPLICATION PACKAGES` 读取/执行权限。
3. 该目录同时写入 `gpp_config.ini`，保证 AppContainer 内的 DLL 能读到代理配置。
4. `gppctl inject <pid> --dll <uwp path>` 注入；若 PID 是启动 broker 或已退出，则按包名在 `WindowsApps` 路径下重新查找根进程并重试。
5. 计算器、ChatGPT 已验证注入成功；Claude 等应用可能因更严格的 AppContainer/ACG 策略失败，界面会提示管理员运行。

## 14. 签名自动更新

- 根公钥编译进应用（`app/update-root.pub.pem`）。
- `personal.json.sig` 包含应用证书 DER、根私钥对证书的签名、应用私钥对清单原始字节的签名。
- 验证顺序：根公钥验证书 → 有效期/吊销 → 证书验清单 → SKU/版本/URL 前缀/大小/SHA-256 → 下载后再验大小/哈希。
- ZIP 安装由 PowerShell 脚本完成：等待当前进程退出 → `Expand-Archive -Force` → 重启 exe；MSI 使用 `msiexec /passive`。
- 演示密钥在 `update/`；正式发布必须替换并保护私钥。

## 15. Watchdog

每 5 秒执行一次：

- 若托管根进程的统计数据超过 20 秒未更新，检查 `gppctl isinjected`；DLL 不在则重新注入。
- 失败后 60 秒退避，避免对受保护进程反复尝试。
- 记录上游健康状态从可用→失败/失败→可用的变化到日志面板。
- 不重启已经退出的应用；子进程注入仍由 2.4 秒的进程树刷新负责。
