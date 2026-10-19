#include "globals.h"

// --- Pending Proxy globals ---
std::unordered_map<SOCKET, PendingProxy> g_PendingProxySockets;
std::mutex g_PendingMutex;

// --- Proxy-Completed Sockets ---
std::unordered_set<SOCKET> g_ProxyCompletedSockets;
std::mutex g_ProxyCompletedMutex;

// --- PerformHttpConnect: HTTP CONNECT tunnel through proxy ---
bool PerformHttpConnect(SOCKET s, const char* ip_str, int port, int family, const std::string& domain) {
    char request[512];
    int req_len = 0;

    std::string proxyIP;
    int proxyPort;
    std::string dnsIP;
    int dnsPort;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        proxyIP = g_Config.ProxyIP;
        proxyPort = g_Config.ProxyPort;
        dnsIP = g_Config.DnsIP;
        dnsPort = g_Config.DnsPort;
    }

    const char* final_host = (!domain.empty()) ? domain.c_str() : ((port == 53 || port == dnsPort) ? dnsIP.c_str() : ip_str);

    // Auto-detect if brackets are needed (IPv6 literals only)
    bool use_brackets = (strchr(final_host, ':') != NULL);

    if (use_brackets) {
        req_len = sprintf_s(
            request, sizeof(request),
            "CONNECT [%s]:%d HTTP/1.1\x0d\x0aHost: [%s]:%d\x0d\x0aProxy-Connection: Keep-Alive\x0d\x0aUser-Agent: GhostProxifier/1.0\x0d\x0a\x0d\x0a",
            final_host, port, final_host, port);
    }
    else {
        req_len = sprintf_s(
            request, sizeof(request),
            "CONNECT %s:%d HTTP/1.1\x0d\x0aHost: %s:%d\x0d\x0aProxy-Connection: Keep-Alive\x0d\x0aUser-Agent: GhostProxifier/1.0\x0d\x0a\x0d\x0a",
            final_host, port, final_host, port);
    }

    NetLog("[Proxy] Handshake Request: %s:%d (via %s:%d http)", final_host, port, proxyIP.c_str(), proxyPort);

    NetLog("[Proxy] Sending CONNECT %s:%d", final_host, port);
    if (!SyncSend(s, request, req_len)) {
        NetLog("[Proxy] Failed to send CONNECT request to proxy (%d)", WSAGetLastError());
        return false;
    }

    std::string response;
    if (!SyncRecvResponse(s, response)) {
        NetLog("[Proxy] Failed to receive CONNECT response from proxy");
        return false;
    }

    if (response.find(" 200 ") != std::string::npos) {
        return true;
    }

    std::string err_line = response.substr(0, response.find("\r\n"));
    NetLog("[Proxy] CONNECT failed: %s", err_line.c_str());
    return false;
}

// --- PerformSocks5Connect: SOCKS5 CONNECT tunnel (optional username/password auth) ---
bool PerformSocks5Connect(SOCKET s, const char* ip_str, int port, int family, const std::string& domain) {
    std::string proxyIP, user, pass;
    int proxyPort;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        proxyIP = g_Config.ProxyIP;
        proxyPort = g_Config.ProxyPort;
        user = g_Config.ProxyUser;
        pass = g_Config.ProxyPass;
    }

    bool useAuth = !user.empty() || !pass.empty();
    unsigned char greeting[4] = { 0x05, (unsigned char)(useAuth ? 2 : 1), 0x00, 0x02 };
    if (!SyncSend(s, (const char*)greeting, useAuth ? 4 : 3)) {
        NetLog("[Proxy] SOCKS5: failed to send greeting (%d)", WSAGetLastError());
        return false;
    }
    unsigned char method[2] = { 0 };
    if (!SyncRecvExact(s, method, 2)) {
        NetLog("[Proxy] SOCKS5: failed to read method");
        return false;
    }
    if (method[0] != 0x05) {
        NetLog("[Proxy] SOCKS5: bad version %d", method[0]);
        return false;
    }
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
        if (!SyncSend(s, (const char*)auth, n)) {
            NetLog("[Proxy] SOCKS5: failed to send auth");
            return false;
        }
        unsigned char authResp[2] = { 0 };
        if (!SyncRecvExact(s, authResp, 2) || authResp[1] != 0x00) {
            NetLog("[Proxy] SOCKS5: authentication failed (%d)", authResp[1]);
            return false;
        }
    }
    else if (method[1] != 0x00) {
        NetLog("[Proxy] SOCKS5: unsupported auth method %d", method[1]);
        return false;
    }

    std::vector<unsigned char> req;
    req.push_back(0x05); // version
    req.push_back(0x01); // CONNECT
    req.push_back(0x00); // reserved

    const char* host = (!domain.empty()) ? domain.c_str() : ip_str;
    bool isIpv4 = (domain.empty() && family == AF_INET);
    bool isIpv6 = (domain.empty() && family == AF_INET6 && strchr(host, ':') != NULL);

    if (!domain.empty()) {
        size_t len = domain.size();
        if (len > 255) len = 255;
        req.push_back(0x03);
        req.push_back((unsigned char)len);
        req.insert(req.end(), host, host + len);
    }
    else if (isIpv6) {
        req.push_back(0x04);
        unsigned char bin[16] = { 0 };
        inet_pton(AF_INET6, host, bin);
        req.insert(req.end(), bin, bin + 16);
    }
    else {
        req.push_back(0x01);
        unsigned char bin[4] = { 0 };
        inet_pton(AF_INET, host, bin);
        req.insert(req.end(), bin, bin + 4);
    }
    req.push_back((unsigned char)((port >> 8) & 0xFF));
    req.push_back((unsigned char)(port & 0xFF));

    NetLog("[Proxy] SOCKS5 CONNECT %s:%d (via %s:%d socks5)", host, port, proxyIP.c_str(), proxyPort);
    if (!SyncSend(s, (const char*)req.data(), (int)req.size())) {
        NetLog("[Proxy] SOCKS5: failed to send request");
        return false;
    }

    unsigned char head[4] = { 0 };
    if (!SyncRecvExact(s, head, 4) || head[0] != 0x05) {
        NetLog("[Proxy] SOCKS5: bad reply header");
        return false;
    }
    if (head[1] != 0x00) {
        NetLog("[Proxy] SOCKS5: CONNECT rejected (rep=%d)", head[1]);
        return false;
    }
    int addrLen = 0;
    if (head[3] == 0x01) addrLen = 4;
    else if (head[3] == 0x04) addrLen = 16;
    else if (head[3] == 0x03) {
        unsigned char l = 0;
        if (!SyncRecvExact(s, &l, 1)) return false;
        addrLen = l;
    }
    else {
        NetLog("[Proxy] SOCKS5: bad address type %d", head[3]);
        return false;
    }
    std::vector<unsigned char> skip(addrLen + 2);
    if (!SyncRecvExact(s, skip.data(), (int)skip.size())) return false;
    return true;
}

// --- PerformProxyHandshake: dispatch on configured upstream protocol ---
bool PerformProxyHandshake(SOCKET s, const char* ip_str, int port, int family, const std::string& domain) {
    std::string type;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        type = g_Config.ProxyType;
    }
    if (type == "socks5" || type == "socks") {
        return PerformSocks5Connect(s, ip_str, port, family, domain);
    }
    return PerformHttpConnect(s, ip_str, port, family, domain);
}

// --- CompletePendingHandshake: finish deferred handshake before first data send ---
bool CompletePendingHandshake(SOCKET s) {
    PendingProxy pp;
    {
        std::lock_guard<std::mutex> lock(g_PendingMutex);
        auto it = g_PendingProxySockets.find(s);
        if (it == g_PendingProxySockets.end()) return true; // no pending
        pp = std::move(it->second);
        g_PendingProxySockets.erase(it);
    }

    // Ensure the connection to the proxy initiated in hook_connect/hook_ConnectEx is finished
    fd_set wfds, efds;
    FD_ZERO(&wfds); FD_ZERO(&efds);
    FD_SET(s, &wfds); FD_SET(s, &efds);
    timeval tv = { 5, 0 }; // 5s timeout
    GlobalConfig cfg;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        cfg = g_Config;
    }

    int sel = select(0, NULL, &wfds, &efds, &tv);
    if (sel <= 0) {
        NetLog("[Proxy] Wait for proxy connection timeout/fail (sel=%d): %s:%d", sel, pp.target_ip.c_str(), pp.target_port);
        return false;
    }
    if (FD_ISSET(s, &efds)) {
        int err = 0; int len = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        NetLog("[Proxy] Proxy connection error: %d on %s:%d (Target: %s:%d)", err, cfg.ProxyIP.c_str(), cfg.ProxyPort, pp.target_ip.c_str(), pp.target_port);
        return false;
    }

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*)&opt, sizeof(opt));

    DWORD t0 = GetTickCount();
    bool ok = PerformProxyHandshake(s, pp.target_ip.c_str(), pp.target_port, pp.target_family, pp.domain);

    // Send any initial data from ConnectEx
    if (ok && !pp.initial_data.empty()) {
        if (!SyncSend(s, pp.initial_data.data(), (int)pp.initial_data.size())) {
            ok = false;
        }
    }

    if (ok) {
        int lat = (int)(GetTickCount() - t0);
        g_lastLatency = lat;
        g_activeConns++;
        NetLog("[Proxy] Handshake OK: %s:%d | %s (latency %dms)", pp.target_ip.c_str(), pp.target_port, pp.domain.c_str(), lat);
        std::lock_guard<std::mutex> lock(g_ProxyCompletedMutex);
        g_ProxyCompletedSockets.insert(s);
    }
    else {
        NetLog("[Proxy] Handshake FAILED: %s:%d | %s", pp.target_ip.c_str(), pp.target_port, pp.domain.c_str());
        // Put it back to avoid accidental direct connection bypass in next retry if app doesn't close socket
        std::lock_guard<std::mutex> lock(g_PendingMutex);
        g_PendingProxySockets[s] = std::move(pp);
    }
    return ok;
}
