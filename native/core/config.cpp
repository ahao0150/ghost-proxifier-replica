#include "globals.h"

// --- Global variable definitions (config module) ---
GlobalConfig g_Config;
std::mutex g_ConfigMutex;
char g_CurrentGuid[64] = "";
time_t g_InjectTime = 0;
std::atomic<bool> g_Initialized{ false };
std::atomic<bool> g_ProxyEngineInitialized{ false };
std::atomic<bool> g_ShuttingDown{ false };
std::atomic<int> g_WorkerThreads{ 0 };
std::mutex g_EngineInitMutex;
std::atomic<int> g_DnsProxyPort{ 0 };

static DWORD s_LastConfigWrite = 0;
static std::string s_ConfigPath;

// --- PerformLazyInitializationInternal: background engine setup ---
void PerformLazyInitializationInternal() {
    // DNS proxy thread is already started in SetupThreadInternal.
    // This function exists as a gate target — no additional init needed.
}

// --- PerformLazyInitialization: thread-safe lazy init gate ---
void PerformLazyInitialization() {
    if (g_ProxyEngineInitialized) return;

    // Separate scope for lock_guard to avoid C2712
    {
        std::lock_guard<std::mutex> lock(g_EngineInitMutex);
        if (g_ProxyEngineInitialized) return;
        g_ProxyEngineInitialized = true;
    }

    PerformLazyInitializationInternal();
}

// --- DelayedInitThread: 2-second delayed background init ---
DWORD WINAPI DelayedInitThread(LPVOID) {
    Sleep(2000);
    PerformLazyInitialization();
    return 0;
}

// --- GetDllDir: directory that contains this injected DLL ---
static std::string GetDllDir() {
    char dllPath[MAX_PATH] = "";
    if (g_hDllModule) GetModuleFileNameA(g_hDllModule, dllPath, MAX_PATH);
    char* lastSlash = strrchr(dllPath, '\\');
    if (lastSlash) {
        *(lastSlash + 1) = 0;
        return std::string(dllPath);
    }
    return std::string(".\\");
}

static DWORD GetFileWriteTick(const std::string& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &fad)) return 0;
    ULARGE_INTEGER t;
    t.LowPart = fad.ftLastWriteTime.dwLowDateTime;
    t.HighPart = fad.ftLastWriteTime.dwHighDateTime;
    return (DWORD)(t.QuadPart / 10000ULL);
}

// --- ParseGppConfig: read gpp_config.ini (all keys optional) ---
static bool ReadIniFile(const std::string& path, GlobalConfig& cfg, int& logPort) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        if (key == "proxy")            cfg.ProxyIP = val;
        else if (key == "port")        cfg.ProxyPort = atoi(val.c_str());
        else if (key == "proxy_type")  cfg.ProxyType = val;
        else if (key == "username")    cfg.ProxyUser = val;
        else if (key == "password")    cfg.ProxyPass = val;
        else if (key == "ss_method")   cfg.SsMethod = val;
        else if (key == "ss_password") cfg.SsPassword = val;
        else if (key == "dns")         cfg.DnsIP = val;
        else if (key == "dns_port")    cfg.DnsPort = atoi(val.c_str());
        else if (key == "dns_mode")    cfg.DnsMode = val;
        else if (key == "node")        cfg.NodeName = val;
        else if (key == "sync")        cfg.SyncHandshake = (val == "1");
        else if (key == "doh_block")   cfg.DohBlock = (val != "0");
        else if (key == "quic_block")  cfg.QuicBlock = (val != "0");
        else if (key == "udp_proxy")   cfg.UdpProxy = (val == "1");
        else if (key == "log_port")    logPort = atoi(val.c_str());
    }
    return true;
}

static void LoadFromEnv(GlobalConfig& cfg, int& logPort) {
    char buf[256];
    if (GetEnvironmentVariableA("GHOST_PROXY", buf, sizeof(buf))) cfg.ProxyIP = buf;
    if (GetEnvironmentVariableA("GHOST_PROXY_PORT", buf, sizeof(buf))) cfg.ProxyPort = atoi(buf);
    if (GetEnvironmentVariableA("GHOST_PROXY_TYPE", buf, sizeof(buf))) cfg.ProxyType = buf;
    if (GetEnvironmentVariableA("GHOST_PROXY_USER", buf, sizeof(buf))) cfg.ProxyUser = buf;
    if (GetEnvironmentVariableA("GHOST_PROXY_PASS", buf, sizeof(buf))) cfg.ProxyPass = buf;
    if (GetEnvironmentVariableA("GHOST_SS_METHOD", buf, sizeof(buf))) cfg.SsMethod = buf;
    if (GetEnvironmentVariableA("GHOST_SS_PASSWORD", buf, sizeof(buf))) cfg.SsPassword = buf;
    if (GetEnvironmentVariableA("GHOST_DNS", buf, sizeof(buf))) cfg.DnsIP = buf;
    if (GetEnvironmentVariableA("GHOST_DNS_SERVER_PORT", buf, sizeof(buf))) cfg.DnsPort = atoi(buf);
    if (GetEnvironmentVariableA("GHOST_DNS_MODE", buf, sizeof(buf))) cfg.DnsMode = buf;
    if (GetEnvironmentVariableA("GHOST_NODE", buf, sizeof(buf))) cfg.NodeName = buf;
    if (GetEnvironmentVariableA("GHOST_SYNC", buf, sizeof(buf))) cfg.SyncHandshake = (atoi(buf) != 0);
    if (GetEnvironmentVariableA("GHOST_DOH_BLOCK", buf, sizeof(buf))) cfg.DohBlock = (atoi(buf) != 0);
    if (GetEnvironmentVariableA("GHOST_QUIC_BLOCK", buf, sizeof(buf))) cfg.QuicBlock = (atoi(buf) != 0);
    if (GetEnvironmentVariableA("GHOST_UDP_PROXY", buf, sizeof(buf))) cfg.UdpProxy = (atoi(buf) != 0);
    if (GetEnvironmentVariableA("GHOST_LOG_PORT", buf, sizeof(buf))) logPort = atoi(buf);
}

// --- LoadConfigFromEnv: file first, environment fallback ---
void LoadConfigFromEnv() {
    GlobalConfig cfg;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        cfg.DnsProxyPort = g_Config.DnsProxyPort; // preserve runtime value
    }
    cfg.ConfigPath = GetDllDir() + "gpp_config.ini";

    int logPort = 0;
    bool gotFile = ReadIniFile(cfg.ConfigPath, cfg, logPort);
    if (!gotFile) {
        // Legacy filename support
        cfg.ConfigPath = GetDllDir() + "ghost_config.ini";
        gotFile = ReadIniFile(cfg.ConfigPath, cfg, logPort);
    }
    if (!gotFile) {
        LoadFromEnv(cfg, logPort);
        cfg.ConfigPath = GetDllDir() + "gpp_config.ini";
    }
    s_ConfigPath = cfg.ConfigPath;
    s_LastConfigWrite = GetFileWriteTick(s_ConfigPath);

    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        cfg.DnsProxyPort = g_Config.DnsProxyPort;
        g_Config = cfg;
    }
    if (logPort > 0) g_LogPort = logPort;
}

// --- ReloadConfigIfChanged: hot-reload when the UI rewrites gpp_config.ini ---
void ReloadConfigIfChanged() {
    if (s_ConfigPath.empty()) return;
    DWORD wt = GetFileWriteTick(s_ConfigPath);
    if (wt == 0 || wt == s_LastConfigWrite) return;
    s_LastConfigWrite = wt;

    GlobalConfig oldCfg;
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        oldCfg = g_Config;
    }

    GlobalConfig cfg = oldCfg;
    int logPort = g_LogPort;
    if (!ReadIniFile(s_ConfigPath, cfg, logPort)) return;

    bool proxyChanged = (cfg.ProxyIP != oldCfg.ProxyIP) ||
                        (cfg.ProxyPort != oldCfg.ProxyPort) ||
                        (cfg.ProxyType != oldCfg.ProxyType) ||
                        (cfg.ProxyUser != oldCfg.ProxyUser) ||
                        (cfg.ProxyPass != oldCfg.ProxyPass);
    bool dnsChanged = (cfg.DnsIP != oldCfg.DnsIP) ||
                      (cfg.DnsPort != oldCfg.DnsPort) ||
                      (cfg.DnsMode != oldCfg.DnsMode);

    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        cfg.DnsProxyPort = g_Config.DnsProxyPort;
        g_Config = cfg;
    }

    if (proxyChanged) FlushDnsPool();
    if (dnsChanged) {
        FlushDnsPool();
        ClearPerProcessDnsCache();
        ClearSharedDnsCache();
    }
    if (logPort > 0) g_LogPort = logPort;

    NetLog("[Config] reloaded (proxy=%s:%d %s, node=%s, dns=%s:%d/%s)",
        cfg.ProxyIP.c_str(), cfg.ProxyPort, cfg.ProxyType.c_str(),
        cfg.NodeName.c_str(), cfg.DnsIP.c_str(), cfg.DnsPort, cfg.DnsMode.c_str());
}

// --- EnvInjectFromConfig: writes current config to GHOST_* env vars ---
void EnvInjectFromConfig() {
    std::lock_guard<std::mutex> lock(g_ConfigMutex);
    char buf[64];
    SetEnvironmentVariableA("GHOST_PROXY", g_Config.ProxyIP.c_str());
    snprintf(buf, sizeof(buf), "%d", g_Config.ProxyPort);
    SetEnvironmentVariableA("GHOST_PROXY_PORT", buf);
    SetEnvironmentVariableA("GHOST_PROXY_TYPE", g_Config.ProxyType.c_str());
    SetEnvironmentVariableA("GHOST_PROXY_USER", g_Config.ProxyUser.c_str());
    SetEnvironmentVariableA("GHOST_PROXY_PASS", g_Config.ProxyPass.c_str());
    SetEnvironmentVariableA("GHOST_SS_METHOD", g_Config.SsMethod.c_str());
    SetEnvironmentVariableA("GHOST_SS_PASSWORD", g_Config.SsPassword.c_str());
    SetEnvironmentVariableA("GHOST_DNS", g_Config.DnsIP.c_str());
    snprintf(buf, sizeof(buf), "%d", g_Config.DnsPort);
    SetEnvironmentVariableA("GHOST_DNS_SERVER_PORT", buf);
    SetEnvironmentVariableA("GHOST_DNS_MODE", g_Config.DnsMode.c_str());
    SetEnvironmentVariableA("GHOST_NODE", g_Config.NodeName.c_str());
    SetEnvironmentVariableA("GHOST_SYNC", g_Config.SyncHandshake ? "1" : "0");
    SetEnvironmentVariableA("GHOST_DOH_BLOCK", g_Config.DohBlock ? "1" : "0");
    SetEnvironmentVariableA("GHOST_QUIC_BLOCK", g_Config.QuicBlock ? "1" : "0");
    SetEnvironmentVariableA("GHOST_UDP_PROXY", g_Config.UdpProxy ? "1" : "0");
    snprintf(buf, sizeof(buf), "%d", g_LogPort);
    SetEnvironmentVariableA("GHOST_LOG_PORT", buf);
    SetEnvironmentVariableA("GHOST_STATS_PORT", "45002");
}
