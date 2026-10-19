// gppctl — native helper for Ghost Proxifier replica.
// Commands:
//   list                         JSON list of processes
//   tree <pid>                   JSON list of descendant PIDs
//   inject <pid>                 inject core DLL into an existing process
//   isinjected <pid>             JSON {injected:bool}
//   run <exe> [args...] [--console] [--cwd=DIR]
//                                launch suspended, inject, resume (JSON {pid})
//   eject <pid>                  best-effort FreeLibrary of the core DLL
//   tcpstats                     JSON TCP segment/retransmission counters
//   version
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000000
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shobjidl.h>
#include <objbase.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdio>
#include <cstdint>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")

// EntryDetour shellcode (x64), same technique as the MIT reference core:
// LdrInitializeThunk runs first and initialises every DLL, then calls RCX.
// We point RCX at this blob, which loads the core DLL, calls GhostInit and
// finally jumps to the real EXE entry point.
static const unsigned char kEntryDetourX64[] = {
    0x48, 0x8B, 0x0D, 0x51, 0x00, 0x00, 0x00, // mov rcx, [rip+0x51]
    0x51,                                     // push rcx
    0x52,                                     // push rdx
    0x41, 0x50,                               // push r8
    0x41, 0x51,                               // push r9
    0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 0x28
    0x48, 0x8D, 0x0D, 0x72, 0x00, 0x00, 0x00, // lea rcx, [rip+0x72]
    0x48, 0x8B, 0x05, 0x41, 0x00, 0x00, 0x00, // mov rax, [rip+0x41]
    0xFF, 0xD0,                               // call rax (LoadLibraryW)
    0x48, 0x89, 0xC1,                         // mov rcx, rax
    0x48, 0x8D, 0x15, 0x55, 0x00, 0x00, 0x00, // lea rdx, [rip+0x55]
    0x48, 0x8B, 0x05, 0x36, 0x00, 0x00, 0x00, // mov rax, [rip+0x36]
    0xFF, 0xD0,                               // call rax (GetProcAddress)
    0xFF, 0xD0,                               // call rax (GhostInit)
    0x48, 0x8B, 0x0D, 0x3B, 0x00, 0x00, 0x00, // mov rcx, [rip+0x3B]
    0xBA, 0x88, 0x13, 0x00, 0x00,             // mov edx, 5000
    0x48, 0x8B, 0x05, 0x27, 0x00, 0x00, 0x00, // mov rax, [rip+0x27]
    0xFF, 0xD0,                               // call rax (WaitForSingleObject)
    0x48, 0x83, 0xC4, 0x28,                   // add rsp, 0x28
    0x41, 0x59,                               // pop r9
    0x41, 0x58,                               // pop r8
    0x5A,                                     // pop rdx
    0x59,                                     // pop rcx
    0xFF, 0xE1,                               // jmp rcx
};
#define ED_CODE_SIZE      0x57
#define ED_OFF_ORIGENTRY  0x58
#define ED_OFF_LLW        0x60
#define ED_OFF_GPA        0x68
#define ED_OFF_WFSO       0x70
#define ED_OFF_HEVENT     0x78
#define ED_OFF_GHOSTINIT  0x80
#define ED_OFF_DLLPATH    0x8A

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, NULL, NULL);
    return s;
}

static std::string JsonEscape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) {
                    char b[8];
                    snprintf(b, sizeof(b), "\\u%04x", c);
                    o += b;
                } else {
                    o += (char)c;
                }
        }
    }
    return o;
}

static void WriteOut(const std::string& s) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    WriteFile(h, s.data(), (DWORD)s.size(), &written, NULL);
}

static void EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(hToken);
}

static std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH];
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    std::wstring dir(buf);
    size_t pos = dir.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? dir.substr(0, pos + 1) : L".\\";
}

static bool IsProcess64Bit(DWORD pid, bool& ok) {
    ok = false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return true;
    BOOL wow64 = FALSE;
    if (!IsWow64Process(h, &wow64)) {
        CloseHandle(h);
        return true;
    }
    CloseHandle(h);
    ok = true;
    return !wow64;
}

static bool IsModuleLoaded(DWORD pid, const wchar_t* needle) {
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return false;
    HMODULE mods[1024];
    DWORD needed = 0;
    bool found = false;
    if (EnumProcessModulesEx(h, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            wchar_t name[MAX_PATH];
            if (GetModuleFileNameExW(h, mods[i], name, MAX_PATH)) {
                std::wstring lower(name);
                for (auto& ch : lower) ch = towlower(ch);
                std::wstring n(needle);
                for (auto& ch : n) ch = towlower(ch);
                if (lower.find(n) != std::wstring::npos) {
                    found = true;
                    break;
                }
            }
        }
    }
    CloseHandle(h);
    return found;
}

static bool g_DllOverrideSet = false;
static std::wstring g_DllOverride;

static bool InjectPid(DWORD pid, std::string& err) {
    EnableDebugPrivilege();

    // Idempotent: loading a DLL twice returns the existing module, but the
    // injector should report success without a second hook setup.
    if (IsModuleLoaded(pid, L"gpp_core_x64.dll")) {
        return true;
    }

    bool ok = false;
    bool target64 = IsProcess64Bit(pid, ok);
    if (ok && !target64) {
        err = "32-bit target process is not supported by this build";
        return false;
    }

    std::wstring dllPath = g_DllOverrideSet ? g_DllOverride : (GetExeDir() + L"gpp_core_x64.dll");
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        err = "gpp_core_x64.dll not found next to gppctl.exe";
        return false;
    }

    HANDLE h = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!h) {
        char b[128];
        snprintf(b, sizeof(b), "OpenProcess failed (error %lu)", GetLastError());
        err = b;
        return false;
    }

    void* loadLibraryW = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
    if (!loadLibraryW) {
        err = "LoadLibraryW not found";
        CloseHandle(h);
        return false;
    }

    size_t bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(h, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        err = "VirtualAllocEx failed";
        CloseHandle(h);
        return false;
    }
    if (!WriteProcessMemory(h, remote, dllPath.c_str(), bytes, NULL)) {
        err = "WriteProcessMemory failed";
        VirtualFreeEx(h, remote, 0, MEM_RELEASE);
        CloseHandle(h);
        return false;
    }

    HANDLE thread = CreateRemoteThread(h, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLibraryW, remote, 0, NULL);
    if (!thread) {
        err = "CreateRemoteThread failed";
        VirtualFreeEx(h, remote, 0, MEM_RELEASE);
        CloseHandle(h);
        return false;
    }

    DWORD wait = WaitForSingleObject(thread, 10000);
    DWORD exitCode = 0;
    bool threadOk = (wait == WAIT_OBJECT_0) && GetExitCodeThread(thread, &exitCode) && exitCode != 0;
    CloseHandle(thread);
    VirtualFreeEx(h, remote, 0, MEM_RELEASE);
    CloseHandle(h);

    if (!threadOk) {
        err = "LoadLibraryW failed in target process";
        return false;
    }
    if (!IsModuleLoaded(pid, L"gpp_core_x64.dll")) {
        // The loader returned success but the module check can fail under
        // protected processes; only treat it as an error if we could query.
        HANDLE probe = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (probe) {
            CloseHandle(probe);
            err = "core DLL was not observed in target module list";
            return false;
        }
    }
    return true;
}

static std::wstring QuoteArg(const std::wstring& a) {
    if (a.find_first_of(L" \t\"") == std::wstring::npos) return a;
    std::wstring out = L"\"";
    for (wchar_t c : a) {
        if (c == L'"') out += L'\\';
        out += c;
    }
    out += L"\"";
    return out;
}

static bool InjectEntryDetour(HANDLE hProcess, HANDLE hThread,
                              const std::wstring& dllPath, std::string& err) {
#ifdef _WIN64
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        err = "GetThreadContext failed";
        return false;
    }
    DWORD64 origEntry = ctx.Rcx;

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    void* loadLibraryW = (void*)GetProcAddress(k32, "LoadLibraryW");
    void* getProcAddress = (void*)GetProcAddress(k32, "GetProcAddress");
    void* waitForSingleObject = (void*)GetProcAddress(k32, "WaitForSingleObject");
    if (!loadLibraryW || !getProcAddress || !waitForSingleObject) {
        err = "kernel32 exports not found";
        return false;
    }

    size_t pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    size_t totalSize = ED_OFF_DLLPATH + pathBytes;
    void* remote = VirtualAllocEx(hProcess, NULL, totalSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        err = "VirtualAllocEx failed";
        return false;
    }

    std::vector<unsigned char> buf(totalSize, 0);
    memcpy(buf.data(), kEntryDetourX64, ED_CODE_SIZE);
    memcpy(buf.data() + ED_OFF_ORIGENTRY, &origEntry, 8);
    memcpy(buf.data() + ED_OFF_LLW, &loadLibraryW, 8);
    memcpy(buf.data() + ED_OFF_GPA, &getProcAddress, 8);
    memcpy(buf.data() + ED_OFF_WFSO, &waitForSingleObject, 8);
    HANDLE noEvent = NULL;
    memcpy(buf.data() + ED_OFF_HEVENT, &noEvent, 8);
    memcpy(buf.data() + ED_OFF_GHOSTINIT, "GhostInit", 10);
    memcpy(buf.data() + ED_OFF_DLLPATH, dllPath.c_str(), pathBytes);

    if (!WriteProcessMemory(hProcess, remote, buf.data(), totalSize, NULL)) {
        err = "WriteProcessMemory failed";
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return false;
    }

    ctx.Rcx = (DWORD64)(uintptr_t)remote;
    if (!SetThreadContext(hThread, &ctx)) {
        err = "SetThreadContext failed";
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return false;
    }
    return true;
#else
    (void)hProcess; (void)hThread; (void)dllPath;
    err = "EntryDetour is x64-only";
    return false;
#endif
}

static bool RunAndInject(const std::wstring& exe, const std::vector<std::wstring>& args,
                         const std::wstring& cwd, bool console, DWORD& outPid,
                         std::string& err) {
    std::wstring cmdline = QuoteArg(exe);
    for (auto& a : args) {
        cmdline += L" ";
        cmdline += QuoteArg(a);
    }
    std::vector<wchar_t> cmd(cmdline.begin(), cmdline.end());
    cmd.push_back(0);

    DWORD flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
    if (console) flags |= CREATE_NEW_CONSOLE;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(exe.c_str(), cmd.data(), NULL, NULL, FALSE, flags, NULL,
                        cwd.empty() ? NULL : cwd.c_str(), &si, &pi)) {
        char b[160];
        snprintf(b, sizeof(b), "CreateProcess failed (error %lu)", GetLastError());
        err = b;
        return false;
    }

    bool archOk = false;
    bool target64 = IsProcess64Bit(pi.dwProcessId, archOk);
    if (archOk && !target64) {
        err = "32-bit target process is not supported by this build";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    std::wstring dllPath = GetExeDir() + L"gpp_core_x64.dll";
    bool detoured = InjectEntryDetour(pi.hProcess, pi.hThread, dllPath, err);
    if (!detoured) {
        // Fallback: let the process initialise, then inject from a worker thread.
        ResumeThread(pi.hThread);
        Sleep(800);
        std::string directErr;
        if (!InjectPid(pi.dwProcessId, directErr)) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            err = directErr;
            return false;
        }
    } else {
        ResumeThread(pi.hThread);
    }

    // Wait for the core DLL to appear in the target module list.
    bool loaded = false;
    for (int i = 0; i < 40; i++) {
        if (IsModuleLoaded(pi.dwProcessId, L"gpp_core_x64.dll")) {
            loaded = true;
            break;
        }
        if (WaitForSingleObject(pi.hProcess, 0) != WAIT_TIMEOUT) break;
        Sleep(150);
    }
    if (!loaded && WaitForSingleObject(pi.hProcess, 0) != WAIT_TIMEOUT) {
        err = "target process exited during injection";
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    outPid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

static uintptr_t RemoteExportAddress(HANDLE hProcess, HMODULE base, const char* wanted) {
    IMAGE_DOS_HEADER dos = {};
    if (!ReadProcessMemory(hProcess, base, &dos, sizeof(dos), NULL)) return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS nt = {};
    if (!ReadProcessMemory(hProcess, (BYTE*)base + dos.e_lfanew, &nt, sizeof(nt), NULL)) return 0;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;

    auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return 0;

    IMAGE_EXPORT_DIRECTORY ed = {};
    if (!ReadProcessMemory(hProcess, (BYTE*)base + dir.VirtualAddress, &ed, sizeof(ed), NULL)) return 0;

    std::vector<DWORD> names(ed.NumberOfNames);
    std::vector<WORD> ords(ed.NumberOfNames);
    std::vector<DWORD> funcs(ed.NumberOfFunctions);
    if (ed.NumberOfNames) {
        if (!ReadProcessMemory(hProcess, (BYTE*)base + ed.AddressOfNames,
                names.data(), names.size() * sizeof(DWORD), NULL)) return 0;
        if (!ReadProcessMemory(hProcess, (BYTE*)base + ed.AddressOfNameOrdinals,
                ords.data(), ords.size() * sizeof(WORD), NULL)) return 0;
    }
    if (ed.NumberOfFunctions) {
        if (!ReadProcessMemory(hProcess, (BYTE*)base + ed.AddressOfFunctions,
                funcs.data(), funcs.size() * sizeof(DWORD), NULL)) return 0;
    }

    for (DWORD i = 0; i < ed.NumberOfNames; i++) {
        char name[128] = { 0 };
        if (!ReadProcessMemory(hProcess, (BYTE*)base + names[i], name, sizeof(name) - 1, NULL)) continue;
        if (strcmp(name, wanted) == 0) {
            WORD ord = ords[i];
            if (ord < ed.NumberOfFunctions) {
                return (uintptr_t)base + funcs[ord];
            }
        }
    }
    return 0;
}

static bool EjectPid(DWORD pid, std::string& err) {
    EnableDebugPrivilege();
    HANDLE h = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_READ,
        FALSE, pid);
    if (!h) {
        err = "OpenProcess failed";
        return false;
    }

    HMODULE mods[1024];
    DWORD needed = 0;
    HMODULE target = NULL;
    if (EnumProcessModulesEx(h, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            wchar_t name[MAX_PATH];
            if (GetModuleFileNameExW(h, mods[i], name, MAX_PATH)) {
                std::wstring lower(name);
                for (auto& ch : lower) ch = towlower(ch);
                if (lower.find(L"gpp_core_x64.dll") != std::wstring::npos) {
                    target = mods[i];
                    break;
                }
            }
        }
    }
    if (!target) {
        err = "core DLL is not loaded in target";
        CloseHandle(h);
        return false;
    }

    uintptr_t shutdownFn = RemoteExportAddress(h, target, "GhostShutdown");
    if (!shutdownFn) {
        err = "core DLL does not export GhostShutdown; reload the DLL before ejecting";
        CloseHandle(h);
        return false;
    }

    HANDLE t1 = CreateRemoteThread(h, NULL, 0,
        (LPTHREAD_START_ROUTINE)shutdownFn, NULL, 0, NULL);
    if (!t1) {
        err = "CreateRemoteThread(GhostShutdown) failed";
        CloseHandle(h);
        return false;
    }
    WaitForSingleObject(t1, 8000);
    CloseHandle(t1);

    void* freeLibrary = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary");
    HANDLE t2 = CreateRemoteThread(h, NULL, 0,
        (LPTHREAD_START_ROUTINE)freeLibrary, target, 0, NULL);
    if (!t2) {
        err = "CreateRemoteThread(FreeLibrary) failed";
        CloseHandle(h);
        return false;
    }
    WaitForSingleObject(t2, 5000);
    CloseHandle(t2);
    CloseHandle(h);
    return true;
}

struct ProcInfo {
    DWORD pid;
    DWORD ppid;
    std::wstring name;
    std::wstring path;
};

static std::vector<ProcInfo> SnapshotProcesses() {
    std::vector<ProcInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcInfo p;
            p.pid = pe.th32ProcessID;
            p.ppid = pe.th32ParentProcessID;
            p.name = pe.szExeFile;
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
            if (h) {
                wchar_t buf[32768];
                DWORD size = 32768;
                if (QueryFullProcessImageNameW(h, 0, buf, &size)) {
                    p.path.assign(buf, size);
                }
                CloseHandle(h);
            }
            out.push_back(p);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

static std::vector<DWORD> Descendants(DWORD root) {
    auto procs = SnapshotProcesses();
    std::map<DWORD, std::vector<DWORD>> children;
    for (auto& p : procs) children[p.ppid].push_back(p.pid);
    std::vector<DWORD> result;
    std::vector<DWORD> queue = children[root];
    std::set<DWORD> seen;
    while (!queue.empty()) {
        DWORD pid = queue.back();
        queue.pop_back();
        if (pid == root || seen.count(pid)) continue;
        seen.insert(pid);
        result.push_back(pid);
        for (DWORD c : children[pid]) queue.push_back(c);
    }
    return result;
}

static int CmdList() {
    auto procs = SnapshotProcesses();
    std::string json = "[";
    bool first = true;
    for (auto& p : procs) {
        if (!first) json += ",";
        first = false;
        json += "{\"pid\":" + std::to_string(p.pid) +
                ",\"ppid\":" + std::to_string(p.ppid) +
                ",\"name\":\"" + JsonEscape(WideToUtf8(p.name)) +
                "\",\"path\":\"" + JsonEscape(WideToUtf8(p.path)) + "\"}";
    }
    json += "]";
    WriteOut(json);
    return 0;
}

static int CmdTree(DWORD pid) {
    auto list = Descendants(pid);
    std::string json = "[";
    for (size_t i = 0; i < list.size(); i++) {
        if (i) json += ",";
        json += std::to_string(list[i]);
    }
    json += "]";
    WriteOut(json);
    return 0;
}

static int CmdInject(DWORD pid) {
    std::string err;
    bool ok = InjectPid(pid, err);
    WriteOut(std::string("{\"ok\":") + (ok ? "true" : "false") +
             ",\"pid\":" + std::to_string(pid) +
             ",\"error\":\"" + JsonEscape(err) + "\"}");
    return ok ? 0 : 1;
}

static int CmdIsInjected(DWORD pid) {
    bool injected = IsModuleLoaded(pid, L"gpp_core_x64.dll");
    WriteOut(std::string("{\"injected\":") + (injected ? "true" : "false") + "}");
    return 0;
}

static int CmdEject(DWORD pid) {
    std::string err;
    bool ok = EjectPid(pid, err);
    WriteOut(std::string("{\"ok\":") + (ok ? "true" : "false") +
             ",\"pid\":" + std::to_string(pid) +
             ",\"error\":\"" + JsonEscape(err) + "\"}");
    return ok ? 0 : 1;
}

static int CmdTcpStats() {
    MIB_TCPSTATS stats = {};
    if (GetTcpStatistics(&stats) != NO_ERROR) {
        WriteOut("{\"ok\":false}");
        return 1;
    }
    double rate = stats.dwOutSegs ? (100.0 * stats.dwRetransSegs / stats.dwOutSegs) : 0.0;
    char buf[256];
    snprintf(buf, sizeof(buf),
        "{\"ok\":true,\"outSegs\":%lu,\"retransSegs\":%lu,\"retransRate\":%.4f}",
        (unsigned long)stats.dwOutSegs, (unsigned long)stats.dwRetransSegs, rate);
    WriteOut(buf);
    return 0;
}

static int CmdUwp(const std::wstring& aumid) {
    HRESULT hrInit = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    IApplicationActivationManager* mgr = NULL;
    HRESULT hr = CoCreateInstance(CLSID_ApplicationActivationManager, NULL,
        CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&mgr));
    DWORD pid = 0;
    if (SUCCEEDED(hr) && mgr) {
        hr = mgr->ActivateApplication(aumid.c_str(), L"", AO_NONE, &pid);
        mgr->Release();
    }
    if (SUCCEEDED(hrInit)) CoUninitialize();

    bool ok = SUCCEEDED(hr);
    char errBuf[128] = { 0 };
    if (!ok) snprintf(errBuf, sizeof(errBuf), "ActivateApplication failed (0x%08lx)", (unsigned long)hr);
    WriteOut(std::string("{\"ok\":") + (ok ? "true" : "false") +
             ",\"pid\":" + std::to_string(pid) +
             ",\"error\":\"" + JsonEscape(errBuf) + "\"}");
    return ok ? 0 : 1;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        WriteOut("{\"ok\":false,\"error\":\"missing command\"}");
        return 1;
    }
    std::wstring cmd = argv[1];

    if (cmd == L"list") return CmdList();
    if (cmd == L"tree" && argc >= 3) return CmdTree((DWORD)wcstoul(argv[2], NULL, 10));
    if (cmd == L"uwp" && argc >= 3) return CmdUwp(argv[2]);
    if (cmd == L"inject" && argc >= 3) {
        for (int i = 3; i + 1 < argc; i++) {
            if (std::wstring(argv[i]) == L"--dll") {
                g_DllOverride = argv[i + 1];
                g_DllOverrideSet = true;
            }
        }
        return CmdInject((DWORD)wcstoul(argv[2], NULL, 10));
    }
    if (cmd == L"isinjected" && argc >= 3) return CmdIsInjected((DWORD)wcstoul(argv[2], NULL, 10));
    if (cmd == L"eject" && argc >= 3) return CmdEject((DWORD)wcstoul(argv[2], NULL, 10));
    if (cmd == L"tcpstats") return CmdTcpStats();
    if (cmd == L"version") {
        WriteOut("{\"ok\":true,\"version\":\"1.0.0-replica\"}");
        return 0;
    }

    if (cmd == L"run" && argc >= 3) {
        std::wstring exe = argv[2];
        std::vector<std::wstring> args;
        std::wstring cwd;
        bool console = false;
        for (int i = 3; i < argc; i++) {
            std::wstring a = argv[i];
            if (a == L"--console") console = true;
            else if (a.rfind(L"--cwd=", 0) == 0) cwd = a.substr(6);
            else args.push_back(a);
        }
        DWORD pid = 0;
        std::string err;
        bool ok = RunAndInject(exe, args, cwd, console, pid, err);
        WriteOut(std::string("{\"ok\":") + (ok ? "true" : "false") +
                 ",\"pid\":" + std::to_string(pid) +
                 ",\"error\":\"" + JsonEscape(err) + "\"}");
        return ok ? 0 : 1;
    }

    WriteOut("{\"ok\":false,\"error\":\"unknown command\"}");
    return 1;
}
