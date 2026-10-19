#include <memory>
#include "globals.h"

// ============================================================================
// SOCKS5 UDP relay
//
// The app socket never sees SOCKS5 framing.  Each target gets a loopback UDP
// endpoint; the app sends/recv's to it with ordinary Winsock calls (including
// overlapped I/O), and a worker thread encapsulates/decapsulates the datagrams
// toward the upstream proxy's UDP ASSOCIATE relay.  This is what makes
// connected UDP and overlapped WSASendTo work without touching the app's
// buffers or IOCP completion path.
// ============================================================================

struct UdpRelay {
    SOCKET appSock = INVALID_SOCKET;
    SOCKET localSock = INVALID_SOCKET;
    SOCKET proxySock = INVALID_SOCKET;
    SOCKET control = INVALID_SOCKET;
    sockaddr_storage target = {};
    int targetLen = 0;
    sockaddr_storage localAddr = {};
    int localLen = 0;
    sockaddr_storage relayEndpoint = {};
    int relayLen = 0;
    sockaddr_storage proxyEndpoint = {};
    int proxyLen = 0;
    sockaddr_storage appAddr = {};
    int appAddrLen = 0;
    bool connected = false;
    bool ss = false;
    std::atomic<bool> stop{ false };
};

namespace {

std::mutex g_RelayMutex;
std::unordered_map<SOCKET, std::shared_ptr<UdpRelay>> g_ConnectedRelays;
std::unordered_map<SOCKET, std::vector<std::shared_ptr<UdpRelay>>> g_UnconnectedRelays;

struct TargetInfo {
    sockaddr_storage target;
    int targetLen;
};
std::unordered_map<DWORD, TargetInfo> g_LocalSources;

DWORD LocalKey(int family, unsigned short port) {
    return ((family == AF_INET6) ? 0x10000u : 0u) | (DWORD)port;
}

bool SameTarget(const sockaddr* a, const sockaddr* b) {
    if (!a || !b || a->sa_family != b->sa_family) return false;
    if (a->sa_family == AF_INET) {
        const sockaddr_in* x = (const sockaddr_in*)a;
        const sockaddr_in* y = (const sockaddr_in*)b;
        return x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
    if (a->sa_family == AF_INET6) {
        const sockaddr_in6* x = (const sockaddr_in6*)a;
        const sockaddr_in6* y = (const sockaddr_in6*)b;
        return x->sin6_port == y->sin6_port &&
               memcmp(&x->sin6_addr, &y->sin6_addr, 16) == 0 &&
               x->sin6_scope_id == y->sin6_scope_id;
    }
    return false;
}

bool IsLoopback(const sockaddr* a) {
    if (!a) return false;
    if (a->sa_family == AF_INET) {
        return (((sockaddr_in*)a)->sin_addr.s_addr == inet_addr("127.0.0.1"));
    }
    if (a->sa_family == AF_INET6) {
        return IN6_IS_ADDR_LOOPBACK(&((sockaddr_in6*)a)->sin6_addr) != 0;
    }
    return false;
}

unsigned short SockPort(const sockaddr* a) {
    if (!a) return 0;
    if (a->sa_family == AF_INET) return ntohs(((sockaddr_in*)a)->sin_port);
    if (a->sa_family == AF_INET6) return ntohs(((sockaddr_in6*)a)->sin6_port);
    return 0;
}

void AddLocalSourceLocked(const std::shared_ptr<UdpRelay>& r) {
    if (r->localAddr.ss_family == AF_INET) {
        unsigned short port = ntohs(((sockaddr_in*)&r->localAddr)->sin_port);
        g_LocalSources[LocalKey(AF_INET, port)] = { r->target, r->targetLen };
    } else if (r->localAddr.ss_family == AF_INET6) {
        unsigned short port = ntohs(((sockaddr_in6*)&r->localAddr)->sin6_port);
        g_LocalSources[LocalKey(AF_INET6, port)] = { r->target, r->targetLen };
    }
}

void RemoveLocalSourceLocked(const std::shared_ptr<UdpRelay>& r) {
    if (r->localAddr.ss_family == AF_INET) {
        unsigned short port = ntohs(((sockaddr_in*)&r->localAddr)->sin_port);
        g_LocalSources.erase(LocalKey(AF_INET, port));
    } else if (r->localAddr.ss_family == AF_INET6) {
        unsigned short port = ntohs(((sockaddr_in6*)&r->localAddr)->sin6_port);
        g_LocalSources.erase(LocalKey(AF_INET6, port));
    }
}

bool Socks5UdpNegotiate(SOCKET tcp, sockaddr_storage& relay, int& relayLen) {
    std::string user, pass, proxyIP;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        user = g_Config.ProxyUser;
        pass = g_Config.ProxyPass;
        proxyIP = g_Config.ProxyIP;
    }

    bool useAuth = !user.empty() || !pass.empty();
    unsigned char greeting[4] = { 0x05, (unsigned char)(useAuth ? 2 : 1), 0x00, 0x02 };
    if (!SyncSend(tcp, (const char*)greeting, useAuth ? 4 : 3)) return false;

    unsigned char method[2] = { 0 };
    if (!SyncRecvExact(tcp, method, 2) || method[0] != 0x05) return false;
    if (method[1] == 0x02) {
        if (user.size() > 255) user.resize(255);
        if (pass.size() > 255) pass.resize(255);
        unsigned char auth[513];
        int n = 0;
        auth[n++] = 0x01;
        auth[n++] = (unsigned char)user.size();
        memcpy(auth + n, user.data(), user.size()); n += (int)user.size();
        auth[n++] = (unsigned char)pass.size();
        memcpy(auth + n, pass.data(), pass.size()); n += (int)pass.size();
        if (!SyncSend(tcp, (const char*)auth, n)) return false;
        unsigned char resp[2] = { 0 };
        if (!SyncRecvExact(tcp, resp, 2) || resp[1] != 0x00) return false;
    }
    else if (method[1] != 0x00) {
        return false;
    }

    const unsigned char req[10] = { 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    if (!SyncSend(tcp, (const char*)req, sizeof(req))) return false;

    unsigned char head[4] = { 0 };
    if (!SyncRecvExact(tcp, head, 4) || head[0] != 0x05 || head[1] != 0x00) {
        NetLog("[UDP] ASSOCIATE rejected (rep=%d)", head[1]);
        return false;
    }

    int addrLen = 0;
    int family = AF_UNSPEC;
    if (head[3] == 0x01) { addrLen = 4; family = AF_INET; }
    else if (head[3] == 0x04) { addrLen = 16; family = AF_INET6; }
    else if (head[3] == 0x03) {
        unsigned char l = 0;
        if (!SyncRecvExact(tcp, &l, 1)) return false;
        addrLen = l;
    }
    else {
        return false;
    }

    std::vector<unsigned char> addr(addrLen);
    if (addrLen > 0 && !SyncRecvExact(tcp, addr.data(), addrLen)) return false;
    unsigned char portBytes[2] = { 0 };
    if (!SyncRecvExact(tcp, portBytes, 2)) return false;
    int port = (portBytes[0] << 8) | portBytes[1];

    memset(&relay, 0, sizeof(relay));
    if (family == AF_INET) {
        sockaddr_in* a = (sockaddr_in*)&relay;
        a->sin_family = AF_INET;
        a->sin_port = htons((u_short)port);
        memcpy(&a->sin_addr, addr.data(), 4);
        if (a->sin_addr.s_addr == 0) a->sin_addr.s_addr = inet_addr(proxyIP.c_str());
        relayLen = sizeof(sockaddr_in);
    }
    else if (family == AF_INET6) {
        sockaddr_in6* a = (sockaddr_in6*)&relay;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons((u_short)port);
        memcpy(&a->sin6_addr, addr.data(), 16);
        bool any = true;
        for (int i = 0; i < 16; i++) if (a->sin6_addr.u.Byte[i]) { any = false; break; }
        if (any) {
            memset(&relay, 0, sizeof(relay));
            sockaddr_in* a4 = (sockaddr_in*)&relay;
            a4->sin_family = AF_INET;
            a4->sin_port = htons((u_short)port);
            a4->sin_addr.s_addr = inet_addr(proxyIP.c_str());
            relayLen = sizeof(sockaddr_in);
        }
        else {
            relayLen = sizeof(sockaddr_in6);
        }
    }
    else {
        sockaddr_in* a = (sockaddr_in*)&relay;
        a->sin_family = AF_INET;
        a->sin_port = htons((u_short)port);
        a->sin_addr.s_addr = inet_addr(proxyIP.c_str());
        relayLen = sizeof(sockaddr_in);
    }
    return true;
}

bool Socks5UdpWrap(const sockaddr* to, const char* buf, int len, std::vector<char>& out) {
    if (!to || len < 0) return false;
    out.clear();
    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(0x00);

    if (to->sa_family == AF_INET) {
        const sockaddr_in* a = (const sockaddr_in*)to;
        out.push_back(0x01);
        const unsigned char* ip = (const unsigned char*)&a->sin_addr;
        out.insert(out.end(), ip, ip + 4);
        out.push_back((char)((ntohs(a->sin_port) >> 8) & 0xFF));
        out.push_back((char)(ntohs(a->sin_port) & 0xFF));
    }
    else if (to->sa_family == AF_INET6) {
        const sockaddr_in6* a = (const sockaddr_in6*)to;
        out.push_back(0x04);
        const unsigned char* ip = (const unsigned char*)&a->sin6_addr;
        out.insert(out.end(), ip, ip + 16);
        out.push_back((char)((ntohs(a->sin6_port) >> 8) & 0xFF));
        out.push_back((char)(ntohs(a->sin6_port) & 0xFF));
    }
    else {
        return false;
    }

    int maxPayload = 65507 - (int)out.size();
    if (len > maxPayload) len = maxPayload;
    out.insert(out.end(), buf, buf + len);
    return true;
}

bool Socks5UdpUnwrap(const char* buf, int len, char* out, int outCap,
                     sockaddr_storage& from, int& fromLen, int& payloadLen) {
    if (len < 4) return false;
    if ((unsigned char)buf[2] != 0x00) return false; // fragmented datagrams unsupported

    int off = 3;
    int atyp = (unsigned char)buf[off++];
    memset(&from, 0, sizeof(from));

    if (atyp == 0x01) {
        if (off + 4 + 2 > len) return false;
        sockaddr_in* a = (sockaddr_in*)&from;
        a->sin_family = AF_INET;
        memcpy(&a->sin_addr, buf + off, 4);
        off += 4;
        a->sin_port = htons((unsigned short)(((unsigned char)buf[off] << 8) | (unsigned char)buf[off + 1]));
        off += 2;
        fromLen = sizeof(sockaddr_in);
    }
    else if (atyp == 0x04) {
        if (off + 16 + 2 > len) return false;
        sockaddr_in6* a = (sockaddr_in6*)&from;
        a->sin6_family = AF_INET6;
        memcpy(&a->sin6_addr, buf + off, 16);
        off += 16;
        a->sin6_port = htons((unsigned short)(((unsigned char)buf[off] << 8) | (unsigned char)buf[off + 1]));
        off += 2;
        fromLen = sizeof(sockaddr_in6);
    }
    else {
        return false;
    }

    payloadLen = len - off;
    if (payloadLen > outCap) payloadLen = outCap;
    if (payloadLen > 0) memcpy(out, buf + off, payloadLen);
    return true;
}

std::shared_ptr<UdpRelay> CreateRelay(SOCKET appSock, const sockaddr* target,
                                      int targetLen, bool connected,
                                      std::string& err) {
    if (!target || targetLen <= 0) { err = "invalid target"; return nullptr; }
    if (!real_connect || !real_sendto || !real_recvfrom) { err = "Winsock not ready"; return nullptr; }

    int family = target->sa_family;
    if (connected) {
        sockaddr_storage bound = {};
        int blen = sizeof(bound);
        if (getsockname(appSock, (sockaddr*)&bound, &blen) == 0 && bound.ss_family != AF_UNSPEC) {
            family = bound.ss_family;
        }
    }
    if (family != AF_INET && family != AF_INET6) { err = "unsupported family"; return nullptr; }

    auto r = std::make_shared<UdpRelay>();
    r->appSock = appSock;
    memcpy(&r->target, target, targetLen);
    r->targetLen = targetLen;
    r->connected = connected;

    r->localSock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (r->localSock == INVALID_SOCKET) { err = "local socket failed"; return nullptr; }

    sockaddr_storage local = {};
    int localLen = 0;
    if (family == AF_INET) {
        sockaddr_in* a = (sockaddr_in*)&local;
        a->sin_family = AF_INET;
        a->sin_addr.s_addr = inet_addr("127.0.0.1");
        a->sin_port = 0;
        localLen = sizeof(sockaddr_in);
    }
    else {
        sockaddr_in6* a = (sockaddr_in6*)&local;
        a->sin6_family = AF_INET6;
        a->sin6_addr = in6addr_loopback;
        a->sin6_port = 0;
        localLen = sizeof(sockaddr_in6);
    }
    if (bind(r->localSock, (sockaddr*)&local, localLen) != 0) {
        err = "local bind failed";
        closesocket(r->localSock); r->localSock = INVALID_SOCKET;
        return nullptr;
    }
    int llen = sizeof(r->localAddr);
    if (getsockname(r->localSock, (sockaddr*)&r->localAddr, &llen) != 0) {
        err = "getsockname failed";
        closesocket(r->localSock); r->localSock = INVALID_SOCKET;
        return nullptr;
    }
    r->localLen = llen;

    r->proxySock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (r->proxySock == INVALID_SOCKET) {
        err = "proxy UDP socket failed";
        closesocket(r->localSock); r->localSock = INVALID_SOCKET;
        return nullptr;
    }

    std::string proxyIP;
    int proxyPort;
    std::string proxyType;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        proxyIP = g_Config.ProxyIP;
        proxyPort = g_Config.ProxyPort;
        proxyType = g_Config.ProxyType;
    }
    r->ss = SsIsEnabledProxy(proxyType);

    if (r->ss) {
        if (!SsInitUdpCrypto()) {
            err = "Shadowsocks crypto unavailable";
            closesocket(r->proxySock);
            closesocket(r->localSock);
            return nullptr;
        }
        sockaddr_in* a = (sockaddr_in*)&r->proxyEndpoint;
        a->sin_family = AF_INET;
        a->sin_port = htons((u_short)proxyPort);
        a->sin_addr.s_addr = inet_addr(proxyIP.c_str());
        r->proxyLen = sizeof(sockaddr_in);
    }
    else {
        r->control = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in p = {};
        p.sin_family = AF_INET;
        p.sin_port = htons((u_short)proxyPort);
        p.sin_addr.s_addr = inet_addr(proxyIP.c_str());
        if (r->control == INVALID_SOCKET || real_connect(r->control, (sockaddr*)&p, sizeof(p)) != 0) {
            err = "proxy control connect failed";
            if (r->control != INVALID_SOCKET) closesocket(r->control);
            closesocket(r->proxySock);
            closesocket(r->localSock);
            return nullptr;
        }
        int opt = 1;
        setsockopt(r->control, SOL_SOCKET, SO_KEEPALIVE, (char*)&opt, sizeof(opt));
        if (!Socks5UdpNegotiate(r->control, r->relayEndpoint, r->relayLen)) {
            err = "UDP ASSOCIATE failed";
            closesocket(r->control);
            closesocket(r->proxySock);
            closesocket(r->localSock);
            return nullptr;
        }
    }

    NetLog("[UDP] relay ready for %s:%d (local port %d)", connected ? "connected" : "sendto",
        (int)SockPort(target), (int)SockPort((sockaddr*)&r->localAddr));
    return r;
}

DWORD WINAPI RelayThread(LPVOID param) {
    std::shared_ptr<UdpRelay> r = *(std::shared_ptr<UdpRelay>*)param;
    delete (std::shared_ptr<UdpRelay>*)param;
    WorkerGuard worker;

    char buf[65535];
    while (!r->stop && !g_ShuttingDown) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(r->localSock, &rfds);
        FD_SET(r->proxySock, &rfds);
        if (r->control != INVALID_SOCKET) FD_SET(r->control, &rfds);
        timeval tv = { 1, 0 };
        int sel = select(0, &rfds, NULL, NULL, &tv);
        if (sel <= 0) continue;

        if (r->control != INVALID_SOCKET && FD_ISSET(r->control, &rfds)) {
            char tmp;
            int n = real_recv(r->control, &tmp, 1, 0);
            if (n <= 0) break;
        }

        if (FD_ISSET(r->localSock, &rfds)) {
            sockaddr_storage from = {};
            int flen = sizeof(from);
            int n = real_recvfrom(r->localSock, buf, sizeof(buf), 0, (sockaddr*)&from, &flen);
            if (n > 0) {
                r->appAddr = from;
                r->appAddrLen = flen;
                g_sentBytes += n;
                if (r->ss) {
                    std::vector<char> out;
                    if (SsUdpEncryptDatagram((sockaddr*)&r->target, buf, n, out)) {
                        real_sendto(r->proxySock, out.data(), (int)out.size(), 0,
                            (sockaddr*)&r->proxyEndpoint, r->proxyLen);
                    }
                    else {
                        NetLog("[SS] UDP encrypt failed (%d bytes)", n);
                    }
                }
                else {
                    std::vector<char> out;
                    if (Socks5UdpWrap((sockaddr*)&r->target, buf, n, out)) {
                        real_sendto(r->proxySock, out.data(), (int)out.size(), 0,
                            (sockaddr*)&r->relayEndpoint, r->relayLen);
                    }
                }
            }
        }

        if (FD_ISSET(r->proxySock, &rfds)) {
            sockaddr_storage from = {};
            int flen = sizeof(from);
            int n = real_recvfrom(r->proxySock, buf, sizeof(buf), 0, (sockaddr*)&from, &flen);
            if (n > 0 && r->appAddrLen > 0) {
                if (r->ss) {
                    std::vector<char> payload;
                    sockaddr_storage src = {};
                    int slen = 0;
                    if (SsUdpDecryptDatagram(buf, n, payload, src, slen) && !payload.empty()) {
                        NetLog("[SS] UDP response %d bytes -> app", (int)payload.size());
                        real_sendto(r->localSock, payload.data(), (int)payload.size(), 0,
                            (sockaddr*)&r->appAddr, r->appAddrLen);
                        g_recvBytes += payload.size();
                    }
                    else {
                        NetLog("[SS] UDP decrypt failed (%d bytes)", n);
                    }
                }
                else {
                    sockaddr_storage src = {};
                    int slen = 0;
                    int payload = 0;
                    std::vector<char> out(n);
                    if (Socks5UdpUnwrap(buf, n, out.data(), n, src, slen, payload)) {
                        if (payload > 0) {
                            real_sendto(r->localSock, out.data(), payload, 0,
                                (sockaddr*)&r->appAddr, r->appAddrLen);
                            g_recvBytes += payload;
                        }
                    }
                }
            }
        }
    }

    if (r->localSock != INVALID_SOCKET) closesocket(r->localSock);
    if (r->proxySock != INVALID_SOCKET) closesocket(r->proxySock);
    if (r->control != INVALID_SOCKET) closesocket(r->control);
    r->localSock = r->proxySock = r->control = INVALID_SOCKET;
    return 0;
}

bool StartRelay(const std::shared_ptr<UdpRelay>& r) {
    auto* p = new std::shared_ptr<UdpRelay>(r);
    HANDLE h = CreateThread(NULL, 0, RelayThread, p, 0, NULL);
    if (!h) {
        delete p;
        return false;
    }
    CloseHandle(h);
    return true;
}

} // namespace

bool EnsureUdpRelayForConnect(SOCKET appSock, const sockaddr* target, int targetLen,
                              sockaddr_storage& localAddr, int& localLen) {
    {
        std::lock_guard<std::mutex> lock(g_RelayMutex);
        auto it = g_ConnectedRelays.find(appSock);
        if (it != g_ConnectedRelays.end() && SameTarget((sockaddr*)&it->second->target, target)) {
            localAddr = it->second->localAddr;
            localLen = it->second->localLen;
            return true;
        }
    }

    std::string err;
    auto r = CreateRelay(appSock, target, targetLen, true, err);
    if (!r) {
        NetLog("[UDP] connected relay failed: %s", err.c_str());
        return false;
    }
    if (!StartRelay(r)) {
        closesocket(r->localSock);
        closesocket(r->proxySock);
        closesocket(r->control);
        return false;
    }

    std::lock_guard<std::mutex> lock(g_RelayMutex);
    auto old = g_ConnectedRelays.find(appSock);
    if (old != g_ConnectedRelays.end()) {
        old->second->stop = true;
        RemoveLocalSourceLocked(old->second);
    }
    g_ConnectedRelays[appSock] = r;
    AddLocalSourceLocked(r);
    localAddr = r->localAddr;
    localLen = r->localLen;
    return true;
}

bool EnsureUdpRelayForSend(SOCKET appSock, const sockaddr* target, int targetLen,
                           sockaddr_storage& localAddr, int& localLen) {
    {
        std::lock_guard<std::mutex> lock(g_RelayMutex);
        auto it = g_ConnectedRelays.find(appSock);
        if (it != g_ConnectedRelays.end()) {
            localAddr = it->second->localAddr;
            localLen = it->second->localLen;
            return true;
        }
        auto vit = g_UnconnectedRelays.find(appSock);
        if (vit != g_UnconnectedRelays.end()) {
            for (auto& r : vit->second) {
                if (SameTarget((sockaddr*)&r->target, target)) {
                    localAddr = r->localAddr;
                    localLen = r->localLen;
                    return true;
                }
            }
        }
    }

    std::string err;
    auto r = CreateRelay(appSock, target, targetLen, false, err);
    if (!r) {
        NetLog("[UDP] sendto relay failed: %s", err.c_str());
        return false;
    }
    if (!StartRelay(r)) {
        closesocket(r->localSock);
        closesocket(r->proxySock);
        closesocket(r->control);
        return false;
    }

    std::lock_guard<std::mutex> lock(g_RelayMutex);
    auto& vec = g_UnconnectedRelays[appSock];
    if (vec.size() >= 64) {
        vec.front()->stop = true;
        RemoveLocalSourceLocked(vec.front());
        vec.erase(vec.begin());
    }
    vec.push_back(r);
    AddLocalSourceLocked(r);
    localAddr = r->localAddr;
    localLen = r->localLen;
    return true;
}

bool SpoofUdpSource(SOCKET appSock, sockaddr* from, int* fromLen) {
    (void)appSock;
    if (!from || !fromLen || *fromLen < (int)sizeof(sockaddr_in)) return false;
    if (!IsLoopback(from)) return false;

    DWORD key = LocalKey(from->sa_family, SockPort(from));
    std::lock_guard<std::mutex> lock(g_RelayMutex);
    auto it = g_LocalSources.find(key);
    if (it == g_LocalSources.end()) return false;
    if (*fromLen < it->second.targetLen) return false;
    memcpy(from, &it->second.target, it->second.targetLen);
    *fromLen = it->second.targetLen;
    return true;
}

bool GetUdpPeerOverride(SOCKET appSock, sockaddr* name, int* nameLen) {
    if (!name || !nameLen) return false;
    std::lock_guard<std::mutex> lock(g_RelayMutex);
    auto it = g_ConnectedRelays.find(appSock);
    if (it == g_ConnectedRelays.end()) return false;
    if (*nameLen < it->second->targetLen) return false;
    memcpy(name, &it->second->target, it->second->targetLen);
    *nameLen = it->second->targetLen;
    return true;
}

void CloseUdpRelays(SOCKET appSock) {
    std::lock_guard<std::mutex> lock(g_RelayMutex);
    auto it = g_ConnectedRelays.find(appSock);
    if (it != g_ConnectedRelays.end()) {
        it->second->stop = true;
        RemoveLocalSourceLocked(it->second);
        g_ConnectedRelays.erase(it);
    }
    auto vit = g_UnconnectedRelays.find(appSock);
    if (vit != g_UnconnectedRelays.end()) {
        for (auto& r : vit->second) {
            r->stop = true;
            RemoveLocalSourceLocked(r);
        }
        g_UnconnectedRelays.erase(vit);
    }
}

void CloseAllUdpAssocs() {
    std::lock_guard<std::mutex> lock(g_RelayMutex);
    for (auto& kv : g_ConnectedRelays) {
        kv.second->stop = true;
        RemoveLocalSourceLocked(kv.second);
    }
    g_ConnectedRelays.clear();
    for (auto& kv : g_UnconnectedRelays) {
        for (auto& r : kv.second) {
            r->stop = true;
            RemoveLocalSourceLocked(r);
        }
    }
    g_UnconnectedRelays.clear();
    g_LocalSources.clear();
}
