#include "globals.h"
#include <bcrypt.h>
#include <memory>

// ============================================================================
// Shadowsocks classic AEAD (aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305)
//
// TCP: each app connection is redirected to a loopback listener. A relay
// thread accepts it, connects to the SS server and pumps AEAD-framed data.
// UDP: the UDP relay encrypts each datagram with a fresh salt; the SS server
// returns an independently salted datagram.
// ============================================================================

namespace {

std::mutex g_SsCacheMutex;
std::string g_SsCachedMethod;
std::string g_SsCachedPassword;
struct SsParams;
std::shared_ptr<SsParams> g_SsCachedParams;

struct SsParams {
    std::string method;
    int keyLen = 32;
    int saltLen = 32;
    int tagLen = 16;
    bool chacha = false;
    std::vector<unsigned char> masterKey;
};

bool Md5(const unsigned char* data, int len, unsigned char out[16]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_MD5_ALGORITHM, NULL, 0) < 0) return false;
    bool ok = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0) >= 0 &&
              BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0) >= 0 &&
              BCryptFinishHash(hash, out, 16, 0) >= 0;
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

bool HmacSha1(const unsigned char* key, int keyLen, const unsigned char* data, int len,
              unsigned char out[20]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, NULL,
            BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0) return false;
    bool ok = BCryptCreateHash(alg, &hash, NULL, 0, (PUCHAR)key, (ULONG)keyLen, 0) >= 0 &&
              BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0) >= 0 &&
              BCryptFinishHash(hash, out, 20, 0) >= 0;
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

bool EvpBytesToKey(const std::string& password, int keyLen, std::vector<unsigned char>& key) {
    key.clear();
    std::vector<unsigned char> prev;
    while ((int)key.size() < keyLen) {
        std::vector<unsigned char> data = prev;
        data.insert(data.end(), password.begin(), password.end());
        unsigned char md[16];
        if (!Md5(data.data(), (int)data.size(), md)) return false;
        key.insert(key.end(), md, md + 16);
        prev.assign(md, md + 16);
    }
    key.resize(keyLen);
    return true;
}

bool HkdfSha1(const std::vector<unsigned char>& master,
              const unsigned char* salt, int saltLen,
              std::vector<unsigned char>& out, int keyLen) {
    unsigned char prk[20];
    if (!HmacSha1(salt, saltLen, master.data(), (int)master.size(), prk)) return false;
    static const char info[] = "ss-subkey";
    std::vector<unsigned char> t;
    out.clear();
    for (unsigned char i = 1; (int)out.size() < keyLen; i++) {
        std::vector<unsigned char> data;
        data.insert(data.end(), t.begin(), t.end());
        data.insert(data.end(), info, info + sizeof(info) - 1);
        data.push_back(i);
        unsigned char block[20];
        if (!HmacSha1(prk, 20, data.data(), (int)data.size(), block)) return false;
        t.assign(block, block + 20);
        out.insert(out.end(), block, block + 20);
        if (i == 255) break;
    }
    out.resize(keyLen);
    return true;
}

bool MakeParams(const std::string& method, const std::string& password,
                std::shared_ptr<SsParams>& out) {
    auto p = std::make_shared<SsParams>();
    p->method = method;
    if (method == "aes-128-gcm") {
        p->keyLen = 16; p->saltLen = 16; p->tagLen = 16; p->chacha = false;
    }
    else if (method == "aes-256-gcm") {
        p->keyLen = 32; p->saltLen = 32; p->tagLen = 16; p->chacha = false;
    }
    else if (method == "chacha20-ietf-poly1305" || method == "chacha20-poly1305") {
        p->keyLen = 32; p->saltLen = 32; p->tagLen = 16; p->chacha = true;
    }
    else {
        return false;
    }
    if (!EvpBytesToKey(password, p->keyLen, p->masterKey)) return false;
    out = p;
    return true;
}

bool GetParams(std::shared_ptr<SsParams>& out) {
    std::string method, password;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        method = g_Config.SsMethod;
        password = g_Config.SsPassword;
    }
    std::lock_guard<std::mutex> lock(g_SsCacheMutex);
    if (g_SsCachedParams && g_SsCachedMethod == method && g_SsCachedPassword == password) {
        out = g_SsCachedParams;
        return true;
    }
    std::shared_ptr<SsParams> p;
    if (!MakeParams(method, password, p)) return false;
    g_SsCachedMethod = method;
    g_SsCachedPassword = password;
    g_SsCachedParams = p;
    out = p;
    return true;
}

struct AeadCtx {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    bool chacha = false;
};

void AeadFree(AeadCtx& a) {
    if (a.key) BCryptDestroyKey(a.key);
    if (a.alg) BCryptCloseAlgorithmProvider(a.alg, 0);
    a.key = NULL;
    a.alg = NULL;
}

bool AeadInit(const std::shared_ptr<SsParams>& p,
              const std::vector<unsigned char>& subkey, AeadCtx& ctx) {
    AeadFree(ctx);
    ctx.chacha = p->chacha;
    const wchar_t* algName = p->chacha ? L"CHACHA20_POLY1305" : BCRYPT_AES_ALGORITHM;
    if (BCryptOpenAlgorithmProvider(&ctx.alg, algName, NULL, 0) < 0) {
        NetLog("[SS] algorithm unavailable: %s", p->method.c_str());
        return false;
    }
    if (!p->chacha) {
        if (BCryptSetProperty(ctx.alg, BCRYPT_CHAINING_MODE,
                (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) {
            AeadFree(ctx);
            return false;
        }
    }
    if (BCryptGenerateSymmetricKey(ctx.alg, &ctx.key, NULL, 0,
            (PUCHAR)subkey.data(), (ULONG)subkey.size(), 0) < 0) {
        AeadFree(ctx);
        return false;
    }
    return true;
}

void MakeNonce(uint64_t n, unsigned char nonce[12]) {
    memset(nonce, 0, 12);
    for (int i = 0; i < 8; i++) nonce[i] = (unsigned char)((n >> (8 * i)) & 0xFF);
}

bool AeadEncrypt(AeadCtx& ctx, uint64_t nonce, const unsigned char* in, int len,
                 std::vector<unsigned char>& out) {
    unsigned char nonceBuf[12];
    MakeNonce(nonce, nonceBuf);
    unsigned char tag[16] = { 0 };
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = nonceBuf;
    auth.cbNonce = 12;
    auth.pbTag = tag;
    auth.cbTag = 16;

    std::vector<unsigned char> cipher(len ? len : 1);
    ULONG produced = 0;
    NTSTATUS st = BCryptEncrypt(ctx.key, (PUCHAR)in, (ULONG)len, &auth,
        NULL, 0, cipher.data(), (ULONG)cipher.size(), &produced, 0);
    if (st < 0 || produced != (ULONG)len) return false;
    out.assign(cipher.begin(), cipher.begin() + len);
    out.insert(out.end(), tag, tag + 16);
    return true;
}

bool AeadDecrypt(AeadCtx& ctx, uint64_t nonce, const unsigned char* in, int len,
                 std::vector<unsigned char>& out) {
    if (len < 16) return false;
    int cipherLen = len - 16;
    unsigned char nonceBuf[12];
    MakeNonce(nonce, nonceBuf);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = nonceBuf;
    auth.cbNonce = 12;
    auth.pbTag = (PUCHAR)(in + cipherLen);
    auth.cbTag = 16;

    std::vector<unsigned char> plain(cipherLen ? cipherLen : 1);
    ULONG produced = 0;
    NTSTATUS st = BCryptDecrypt(ctx.key, (PUCHAR)in, (ULONG)cipherLen, &auth,
        NULL, 0, plain.data(), (ULONG)plain.size(), &produced, 0);
    if (st < 0 || produced != (ULONG)cipherLen) return false;
    out.assign(plain.begin(), plain.begin() + cipherLen);
    return true;
}

bool RandomBytes(unsigned char* buf, int len) {
    return BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
}

bool AppendAddress(std::vector<unsigned char>& out, const sockaddr* target,
                   const std::string& domain) {
    if (!domain.empty() && domain.size() <= 255) {
        out.push_back(0x03);
        out.push_back((unsigned char)domain.size());
        out.insert(out.end(), domain.begin(), domain.end());
    }
    else if (target && target->sa_family == AF_INET) {
        sockaddr_in* a = (sockaddr_in*)target;
        out.push_back(0x01);
        const unsigned char* ip = (const unsigned char*)&a->sin_addr;
        out.insert(out.end(), ip, ip + 4);
    }
    else if (target && target->sa_family == AF_INET6) {
        sockaddr_in6* a = (sockaddr_in6*)target;
        out.push_back(0x04);
        const unsigned char* ip = (const unsigned char*)&a->sin6_addr;
        out.insert(out.end(), ip, ip + 16);
    }
    else {
        return false;
    }
    int port = 0;
    if (target->sa_family == AF_INET) port = ntohs(((sockaddr_in*)target)->sin_port);
    else port = ntohs(((sockaddr_in6*)target)->sin6_port);
    out.push_back((unsigned char)((port >> 8) & 0xFF));
    out.push_back((unsigned char)(port & 0xFF));
    return true;
}

bool ParseAddress(const unsigned char* buf, int len, int& off,
                  sockaddr_storage& target, int& targetLen) {
    if (off >= len) return false;
    int atyp = buf[off++];
    memset(&target, 0, sizeof(target));
    if (atyp == 0x01) {
        if (off + 6 > len) return false;
        sockaddr_in* a = (sockaddr_in*)&target;
        a->sin_family = AF_INET;
        memcpy(&a->sin_addr, buf + off, 4); off += 4;
        a->sin_port = htons((unsigned short)((buf[off] << 8) | buf[off + 1])); off += 2;
        targetLen = sizeof(sockaddr_in);
    }
    else if (atyp == 0x04) {
        if (off + 18 > len) return false;
        sockaddr_in6* a = (sockaddr_in6*)&target;
        a->sin6_family = AF_INET6;
        memcpy(&a->sin6_addr, buf + off, 16); off += 16;
        a->sin6_port = htons((unsigned short)((buf[off] << 8) | buf[off + 1])); off += 2;
        targetLen = sizeof(sockaddr_in6);
    }
    else if (atyp == 0x03) {
        if (off >= len) return false;
        int l = buf[off++];
        if (off + l + 2 > len) return false;
        // A domain in a response is unusual for our use; leave the stored
        // target as IPv4 any.  The relay already knows the original target.
        off += l;
        off += 2;
        targetLen = 0;
    }
    else {
        return false;
    }
    return true;
}

bool RecvExact(SOCKET s, void* buf, int len, int timeoutSec = 0) {
    int done = 0;
    char* p = (char*)buf;
    while (done < len) {
        int n = real_recv(s, p + done, len - done, 0);
        if (n > 0) {
            done += n;
        }
        else if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set rfds; FD_ZERO(&rfds); FD_SET(s, &rfds);
            timeval tv = { timeoutSec, 0 };
            if (select(0, &rfds, NULL, NULL, &tv) <= 0) return false;
        }
        else {
            return false;
        }
    }
    return true;
}

bool SendAll(SOCKET s, const unsigned char* buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = real_send(s, (const char*)buf + sent, len - sent, 0);
        if (n > 0) {
            sent += n;
        }
        else if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set wfds; FD_ZERO(&wfds); FD_SET(s, &wfds);
            timeval tv = { 10, 0 };
            if (select(0, NULL, &wfds, NULL, &tv) <= 0) return false;
        }
        else {
            return false;
        }
    }
    return true;
}

bool ConnectWithTimeout(SOCKET s, const sockaddr* addr, int addrLen, int timeoutSec) {
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    int rc = real_connect(s, addr, addrLen);
    if (rc == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) return false;
        fd_set wfds, efds;
        FD_ZERO(&wfds); FD_ZERO(&efds);
        FD_SET(s, &wfds); FD_SET(s, &efds);
        timeval tv = { timeoutSec, 0 };
        if (select(0, NULL, &wfds, &efds, &tv) <= 0) return false;
        if (FD_ISSET(s, &efds)) return false;
        int soErr = 0; int slen = sizeof(soErr);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soErr, &slen);
        if (soErr != 0) return false;
    }
    u_long blocking = 0;
    ioctlsocket(s, FIONBIO, &blocking);
    return true;
}

struct SsRelay {
    SOCKET appSock = INVALID_SOCKET;
    SOCKET listenSock = INVALID_SOCKET;
    SOCKET appConn = INVALID_SOCKET;
    SOCKET serverSock = INVALID_SOCKET;
    sockaddr_storage target = {};
    int targetLen = 0;
    std::string domain;
    std::vector<char> initial;
    std::shared_ptr<SsParams> params;
    std::vector<unsigned char> sendKey;
    std::vector<unsigned char> recvKey;
    AeadCtx sendCtx;
    AeadCtx recvCtx;
    uint64_t sendNonce = 0;
    uint64_t recvNonce = 0;
    std::atomic<bool> stop{ false };
};

std::mutex g_SsRelayMutex;
std::unordered_map<SOCKET, std::vector<std::shared_ptr<SsRelay>>> g_SsRelays;

void RegisterRelay(SOCKET appSock, const std::shared_ptr<SsRelay>& r) {
    std::lock_guard<std::mutex> lock(g_SsRelayMutex);
    g_SsRelays[appSock].push_back(r);
}

void UnregisterRelay(SOCKET appSock, SsRelay* r) {
    std::lock_guard<std::mutex> lock(g_SsRelayMutex);
    auto it = g_SsRelays.find(appSock);
    if (it == g_SsRelays.end()) return;
    auto& vec = it->second;
    for (auto vit = vec.begin(); vit != vec.end(); ++vit) {
        if (vit->get() == r) { vec.erase(vit); break; }
    }
    if (vec.empty()) g_SsRelays.erase(it);
}

bool SendChunk(const std::shared_ptr<SsRelay>& r, const unsigned char* data, int len) {
    if (len <= 0) return true;
    if (len > 0x3FFF) len = 0x3FFF;
    unsigned char prefix[2] = { (unsigned char)((len >> 8) & 0xFF), (unsigned char)(len & 0xFF) };
    std::vector<unsigned char> enc;
    if (!AeadEncrypt(r->sendCtx, r->sendNonce++, prefix, 2, enc)) return false;
    if (!SendAll(r->serverSock, enc.data(), (int)enc.size())) return false;
    if (!AeadEncrypt(r->sendCtx, r->sendNonce++, data, len, enc)) return false;
    if (!SendAll(r->serverSock, enc.data(), (int)enc.size())) return false;
    g_sentBytes += len;
    return true;
}

bool RecvChunk(const std::shared_ptr<SsRelay>& r, std::vector<unsigned char>& out) {
    unsigned char prefixEnc[2 + 16];
    if (!RecvExact(r->serverSock, prefixEnc, sizeof(prefixEnc), 60)) return false;
    std::vector<unsigned char> prefix;
    if (!AeadDecrypt(r->recvCtx, r->recvNonce++, prefixEnc, sizeof(prefixEnc), prefix)) return false;
    if (prefix.size() != 2) return false;
    int len = (prefix[0] << 8) | prefix[1];
    if (len < 0 || len > 0x3FFF) return false;
    std::vector<unsigned char> payloadEnc(len + 16);
    if (!RecvExact(r->serverSock, payloadEnc.data(), len + 16, 60)) return false;
    if (!AeadDecrypt(r->recvCtx, r->recvNonce++, payloadEnc.data(), len + 16, out)) return false;
    g_recvBytes += out.size();
    return true;
}

DWORD WINAPI SsUpstreamPump(LPVOID param) {
    std::shared_ptr<SsRelay> r = *(std::shared_ptr<SsRelay>*)param;
    delete (std::shared_ptr<SsRelay>*)param;
    WorkerGuard worker;

    std::vector<char> buf(32768);
    while (!r->stop && !g_ShuttingDown) {
        int n = real_recv(r->appConn, buf.data(), (int)buf.size(), 0);
        if (n <= 0) break;
        if (!SendChunk(r, (const unsigned char*)buf.data(), n)) break;
    }
    r->stop = true;
    if (r->serverSock != INVALID_SOCKET) shutdown(r->serverSock, SD_SEND);
    if (r->appConn != INVALID_SOCKET) shutdown(r->appConn, SD_RECEIVE);
    return 0;
}

DWORD WINAPI SsDownstreamPump(LPVOID param) {
    std::shared_ptr<SsRelay> r = *(std::shared_ptr<SsRelay>*)param;
    delete (std::shared_ptr<SsRelay>*)param;
    WorkerGuard worker;

    std::vector<unsigned char> salt(r->params->saltLen);
    if (!RecvExact(r->serverSock, salt.data(), (int)salt.size(), 60)) {
        r->stop = true;
        return 0;
    }
    if (!HkdfSha1(r->params->masterKey, salt.data(), (int)salt.size(),
            r->recvKey, r->params->keyLen) ||
        !AeadInit(r->params, r->recvKey, r->recvCtx)) {
        r->stop = true;
        return 0;
    }

    std::vector<unsigned char> payload;
    while (!r->stop && !g_ShuttingDown) {
        if (!RecvChunk(r, payload)) break;
        int sent = 0;
        while (sent < (int)payload.size()) {
            int n = real_send(r->appConn, (const char*)payload.data() + sent,
                (int)payload.size() - sent, 0);
            if (n <= 0) { r->stop = true; break; }
            sent += n;
        }
        if (r->stop) break;
    }
    r->stop = true;
    if (r->appConn != INVALID_SOCKET) shutdown(r->appConn, SD_SEND);
    if (r->serverSock != INVALID_SOCKET) shutdown(r->serverSock, SD_RECEIVE);
    return 0;
}

DWORD WINAPI SsRelayThread(LPVOID param) {
    std::shared_ptr<SsRelay> r = *(std::shared_ptr<SsRelay>*)param;
    delete (std::shared_ptr<SsRelay>*)param;
    WorkerGuard worker;

    fd_set rfds; FD_ZERO(&rfds); FD_SET(r->listenSock, &rfds);
    timeval tv = { 15, 0 };
    if (select(0, &rfds, NULL, NULL, &tv) <= 0 || r->stop) {
        closesocket(r->listenSock);
        UnregisterRelay(r->appSock, r.get());
        return 0;
    }
    r->appConn = accept(r->listenSock, NULL, NULL);
    closesocket(r->listenSock);
    r->listenSock = INVALID_SOCKET;
    if (r->appConn == INVALID_SOCKET) {
        UnregisterRelay(r->appSock, r.get());
        return 0;
    }

    std::string proxyIP;
    int proxyPort;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        proxyIP = g_Config.ProxyIP;
        proxyPort = g_Config.ProxyPort;
    }
    r->serverSock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server = {};
    server.sin_family = AF_INET;
    server.sin_port = htons((u_short)proxyPort);
    server.sin_addr.s_addr = inet_addr(proxyIP.c_str());
    if (r->serverSock == INVALID_SOCKET ||
        !ConnectWithTimeout(r->serverSock, (sockaddr*)&server, sizeof(server), 10)) {
        NetLog("[SS] server connect failed");
        if (r->serverSock != INVALID_SOCKET) closesocket(r->serverSock);
        closesocket(r->appConn);
        UnregisterRelay(r->appSock, r.get());
        return 0;
    }

    if (!r->params) {
        closesocket(r->serverSock);
        closesocket(r->appConn);
        UnregisterRelay(r->appSock, r.get());
        return 0;
    }

    std::vector<unsigned char> salt(r->params->saltLen);
    if (!RandomBytes(salt.data(), (int)salt.size()) ||
        !SendAll(r->serverSock, salt.data(), (int)salt.size()) ||
        !HkdfSha1(r->params->masterKey, salt.data(), (int)salt.size(),
            r->sendKey, r->params->keyLen) ||
        !AeadInit(r->params, r->sendKey, r->sendCtx)) {
        closesocket(r->serverSock);
        closesocket(r->appConn);
        UnregisterRelay(r->appSock, r.get());
        return 0;
    }

    std::vector<unsigned char> header;
    if (!AppendAddress(header, (sockaddr*)&r->target, r->domain)) {
        closesocket(r->serverSock);
        closesocket(r->appConn);
        UnregisterRelay(r->appSock, r.get());
        return 0;
    }
    if (!r->initial.empty()) header.insert(header.end(), r->initial.begin(), r->initial.end());
    for (size_t off = 0; off < header.size(); off += 0x3FFF) {
        int chunk = (int)std::min<size_t>(0x3FFF, header.size() - off);
        if (!SendChunk(r, header.data() + off, chunk)) {
            closesocket(r->serverSock);
            closesocket(r->appConn);
            UnregisterRelay(r->appSock, r.get());
            return 0;
        }
    }

    auto up = new std::shared_ptr<SsRelay>(r);
    auto down = new std::shared_ptr<SsRelay>(r);
    HANDLE h1 = CreateThread(NULL, 0, SsUpstreamPump, up, 0, NULL);
    HANDLE h2 = CreateThread(NULL, 0, SsDownstreamPump, down, 0, NULL);
    if (!h1) delete up;
    else CloseHandle(h1);
    if (!h2) delete down;
    else CloseHandle(h2);
    if (!h1 || !h2) {
        r->stop = true;
        if (r->serverSock != INVALID_SOCKET) closesocket(r->serverSock);
        if (r->appConn != INVALID_SOCKET) closesocket(r->appConn);
        UnregisterRelay(r->appSock, r.get());
    }
    return 0;
}

bool CreateTcpRelay(SOCKET appSock, const sockaddr* target, int targetLen,
                    const std::string& domain, const std::vector<char>& initial,
                    sockaddr_storage& localAddr, int& localLen) {
    std::shared_ptr<SsParams> params;
    if (!GetParams(params)) {
        NetLog("[SS] unsupported method or empty password");
        return false;
    }
    if (!target || target->sa_family != AF_INET) {
        // The TCP target can be IPv4 or a domain mapped to IPv4; the SS
        // address header supports IPv6 as well, but the relay's server
        // connection is IPv4.
        if (!target) return false;
    }

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock == INVALID_SOCKET) return false;
    sockaddr_in bindAddr = {};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    bindAddr.sin_port = 0;
    if (bind(listenSock, (sockaddr*)&bindAddr, sizeof(bindAddr)) != 0 ||
        listen(listenSock, 1) != 0) {
        closesocket(listenSock);
        return false;
    }
    int llen = sizeof(localAddr);
    if (getsockname(listenSock, (sockaddr*)&localAddr, &llen) != 0) {
        closesocket(listenSock);
        return false;
    }
    localLen = llen;

    auto r = std::make_shared<SsRelay>();
    r->appSock = appSock;
    r->listenSock = listenSock;
    memcpy(&r->target, target, std::min<int>(targetLen, sizeof(r->target)));
    r->targetLen = targetLen;
    r->domain = domain;
    r->initial = initial;
    r->params = params;
    RegisterRelay(appSock, r);

    auto* p = new std::shared_ptr<SsRelay>(r);
    HANDLE h = CreateThread(NULL, 0, SsRelayThread, p, 0, NULL);
    if (!h) {
        delete p;
        closesocket(listenSock);
        UnregisterRelay(appSock, r.get());
        return false;
    }
    CloseHandle(h);
    NetLog("[SS] TCP relay ready for %s:%d (local port %d)",
        domain.empty() ? "target" : domain.c_str(),
        (int)ntohs(((sockaddr_in*)target)->sin_port),
        (int)ntohs(((sockaddr_in*)&localAddr)->sin_port));
    return true;
}

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool SsIsEnabledProxy(const std::string& type) {
    return type == "shadowsocks" || type == "ss";
}

bool SsCreateTcpRelay(SOCKET appSock, const sockaddr* target, int targetLen,
                      const std::string& domain,
                      const std::vector<char>& initialData,
                      sockaddr_storage& localAddr, int& localLen) {
    return CreateTcpRelay(appSock, target, targetLen, domain, initialData, localAddr, localLen);
}

SOCKET SsCreateDnsSocket(const char* dnsIp, int dnsPort) {
    SOCKET client = socket(AF_INET, SOCK_STREAM, 0);
    if (client == INVALID_SOCKET) return INVALID_SOCKET;

    sockaddr_in target = {};
    target.sin_family = AF_INET;
    target.sin_port = htons((u_short)dnsPort);
    target.sin_addr.s_addr = inet_addr(dnsIp);

    sockaddr_storage localAddr = {};
    int localLen = 0;
    if (!CreateTcpRelay(client, (sockaddr*)&target, sizeof(target), std::string(),
            std::vector<char>(), localAddr, localLen)) {
        closesocket(client);
        return INVALID_SOCKET;
    }
    if (real_connect(client, (sockaddr*)&localAddr, localLen) != 0) {
        closesocket(client);
        return INVALID_SOCKET;
    }
    return client;
}

void SsCloseTcpRelays(SOCKET appSock) {
    std::vector<std::shared_ptr<SsRelay>> copy;
    {
        std::lock_guard<std::mutex> lock(g_SsRelayMutex);
        auto it = g_SsRelays.find(appSock);
        if (it == g_SsRelays.end()) return;
        copy = it->second;
        g_SsRelays.erase(it);
    }
    for (auto& r : copy) {
        r->stop = true;
        if (r->listenSock != INVALID_SOCKET) closesocket(r->listenSock);
        if (r->appConn != INVALID_SOCKET) shutdown(r->appConn, SD_BOTH);
        if (r->serverSock != INVALID_SOCKET) shutdown(r->serverSock, SD_BOTH);
    }
}

void SsCloseAllTcpRelays() {
    std::vector<std::shared_ptr<SsRelay>> all;
    {
        std::lock_guard<std::mutex> lock(g_SsRelayMutex);
        for (auto& kv : g_SsRelays)
            for (auto& r : kv.second) all.push_back(r);
        g_SsRelays.clear();
    }
    for (auto& r : all) {
        r->stop = true;
        if (r->listenSock != INVALID_SOCKET) closesocket(r->listenSock);
        if (r->appConn != INVALID_SOCKET) shutdown(r->appConn, SD_BOTH);
        if (r->serverSock != INVALID_SOCKET) shutdown(r->serverSock, SD_BOTH);
    }
}

bool SsInitUdpCrypto() {
    std::shared_ptr<SsParams> p;
    return GetParams(p);
}

bool SsUdpEncryptDatagram(const sockaddr* target, const char* payload, int len,
                          std::vector<char>& out) {
    std::shared_ptr<SsParams> p;
    if (!GetParams(p)) return false;
    std::vector<unsigned char> salt(p->saltLen);
    if (!RandomBytes(salt.data(), (int)salt.size())) return false;
    std::vector<unsigned char> subkey;
    if (!HkdfSha1(p->masterKey, salt.data(), (int)salt.size(), subkey, p->keyLen)) return false;

    std::vector<unsigned char> plain;
    if (!AppendAddress(plain, target, std::string())) return false;
    plain.insert(plain.end(), (const unsigned char*)payload, (const unsigned char*)payload + len);

    AeadCtx ctx;
    if (!AeadInit(p, subkey, ctx)) return false;
    std::vector<unsigned char> encrypted;
    bool ok = AeadEncrypt(ctx, 0, plain.data(), (int)plain.size(), encrypted);
    AeadFree(ctx);
    if (!ok) return false;

    out.clear();
    out.insert(out.end(), salt.begin(), salt.end());
    out.insert(out.end(), encrypted.begin(), encrypted.end());
    return true;
}

bool SsUdpDecryptDatagram(const char* packet, int len, std::vector<char>& payload,
                          sockaddr_storage& source, int& sourceLen) {
    std::shared_ptr<SsParams> p;
    if (!GetParams(p)) return false;
    if (len <= p->saltLen + p->tagLen) return false;

    const unsigned char* salt = (const unsigned char*)packet;
    std::vector<unsigned char> subkey;
    if (!HkdfSha1(p->masterKey, salt, p->saltLen, subkey, p->keyLen)) return false;
    AeadCtx ctx;
    if (!AeadInit(p, subkey, ctx)) return false;
    std::vector<unsigned char> plain;
    bool ok = AeadDecrypt(ctx, 0, salt + p->saltLen, len - p->saltLen, plain);
    AeadFree(ctx);
    if (!ok) return false;

    int off = 0;
    sockaddr_storage target = {};
    int targetLen = 0;
    if (!ParseAddress(plain.data(), (int)plain.size(), off, target, targetLen)) return false;
    source = target;
    sourceLen = targetLen;
    payload.assign(plain.begin() + off, plain.end());
    return true;
}
