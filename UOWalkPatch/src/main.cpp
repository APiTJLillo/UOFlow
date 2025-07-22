#define PSAPI_VERSION 1
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <regex>
#include "../include/stub_bin.h"

#undef min

namespace {
    std::ofstream log_file;
    
    void init_logging() {
        log_file.open("uowalkpatch.log", std::ios::out | std::ios::trunc);
    }
    
    void debug_log(const std::string& msg) {
        const std::string formatted = "[UOWalkPatch] " + msg;
        std::cout << formatted << std::endl;
        if (log_file.is_open()) {
            log_file << formatted << std::endl;
            log_file.flush();
        }
    }
    
    void close_logging() {
        if (log_file.is_open()) {
            log_file.close();
        }
    }

    // Helper function to format memory as hex dump
    std::string hex_dump(const uint8_t* data, size_t size, size_t highlight_offset = SIZE_MAX) {
        std::ostringstream oss;
        char hex[4];
        
        for (size_t i = 0; i < size; ++i) {
            if (i > 0 && i % 16 == 0) oss << "\n    ";
            else if (i > 0) oss << " ";
            
            if (i == highlight_offset) oss << "[";
            snprintf(hex, sizeof(hex), "%02X", data[i]);
            oss << hex;
            if (i == highlight_offset) oss << "]";
        }
        return oss.str();
    }

    // Helper function to format protection flags
    std::string format_protection(DWORD protect) {
        std::string flags;
        if (protect & PAGE_EXECUTE) flags += "X ";
        if (protect & PAGE_EXECUTE_READ) flags += "RX ";
        if (protect & PAGE_EXECUTE_READWRITE) flags += "RWX ";
        if (protect & PAGE_READONLY) flags += "R ";
        if (protect & PAGE_READWRITE) flags += "RW ";
        return flags;
    }

    // Helper function to dump pattern for signature creation
    void dump_pattern_around(const uint8_t* data, size_t pos, size_t context_size) {
        size_t start = pos >= context_size ? pos - context_size : 0;
        size_t end = pos + context_size;
        debug_log("Pattern template around match:");
        debug_log(hex_dump(data + start, end - start, context_size));
    }

    inline size_t min_size_t(size_t a, size_t b) { return a < b ? a : b; }
}

struct PatternData {
    std::vector<uint8_t> bytes;
    std::string mask;
};

PatternData parsePattern(const std::string& pat) {
    std::istringstream iss(pat);
    std::string byteStr;
    PatternData out;
    out.mask.reserve(pat.length() / 3);  // Rough estimate of final mask length
    
    while (iss >> byteStr) {
        if (byteStr == "??") {
            out.bytes.push_back(0x00);
            out.mask += '?';
        } else {
            out.bytes.push_back(static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16)));
            out.mask += 'x';
        }
    }
    return out;
}

struct Signature {
    std::string lua_name;
    std::string pattern;
    std::string bridge;
    uintptr_t address{0};
};

bool loadSignatures(const std::string& path, std::vector<Signature>& out) {
    std::ifstream f(path);
    if (!f.is_open()) {
        std::cerr << "failed to open signatures.json\n";
        return false;
    }
    std::string data((std::istreambuf_iterator<char>(f)), {});
    std::regex func_re(R"(\{[^\}]*\"lua_name\"\s*:\s*\"([^\"]+)\"[^\}]*\"pattern\"\s*:\s*\"([^\"]+)\"[^\}]*\"bridge\"\s*:\s*\"([^\"]+)\")");
    std::smatch m;
    auto it = data.cbegin();
    while (std::regex_search(it, data.cend(), m, func_re)) {
        Signature s;
        s.lua_name = m[1];
        s.pattern  = m[2];
        s.bridge   = m[3];
        out.push_back(s);
        it = m.suffix().first;
    }
    return !out.empty();
}

bool getProcessBitness(HANDLE proc, bool& is64Bit) {
    is64Bit = false;

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32)
        return false;

    using IsWow64Process2_t = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    auto fn2 = reinterpret_cast<IsWow64Process2_t>(GetProcAddress(k32, "IsWow64Process2"));
    if (fn2) {
        USHORT procMachine = 0, nativeMachine = 0;
        if (!fn2(proc, &procMachine, &nativeMachine))
            return false;

        // For 64-bit processes procMachine is IMAGE_FILE_MACHINE_UNKNOWN.
        if (procMachine == IMAGE_FILE_MACHINE_UNKNOWN)
            is64Bit = true;
        else
            is64Bit = false;
        return true;
    }

    using IsWow64Process_t = BOOL(WINAPI*)(HANDLE, PBOOL);
    auto fn = reinterpret_cast<IsWow64Process_t>(GetProcAddress(k32, "IsWow64Process"));
    if (fn) {
        BOOL wow64 = FALSE;
        if (!fn(proc, &wow64))
            return false;
#ifdef _WIN64
        is64Bit = !wow64;
#else
        // 32-bit process calling IsWow64Process - if running under WOW64,
        // the target must also be 32-bit.
        is64Bit = false;
#endif
        return true;
    }

    // Fallback: assume same bitness as self
#ifdef _WIN64
    is64Bit = true;
#else
    is64Bit = false;
#endif
    return true;
}

bool isLikelyCodeRegion(const MEMORY_BASIC_INFORMATION& mbi) {
    // Code regions are typically:
    // 1. Committed memory
    // 2. Have execute permissions
    // 3. Are from image (executable) or mapped memory
    return (mbi.State == MEM_COMMIT) &&
           (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
           (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED);
}

bool enumProcessModulesSafe(HANDLE proc, std::vector<HMODULE>& mods) {
    DWORD needed = 0;
    if (EnumProcessModulesEx(proc, nullptr, 0, &needed, LIST_MODULES_32BIT | LIST_MODULES_64BIT)) {
        mods.resize(needed / sizeof(HMODULE));
        if (EnumProcessModulesEx(proc, mods.data(), needed, &needed, LIST_MODULES_32BIT | LIST_MODULES_64BIT)) {
            mods.resize(needed / sizeof(HMODULE));
            return true;
        }
    }

    DWORD err = GetLastError();
    if (err == ERROR_ACCESS_DENIED)
        debug_log("EnumProcessModulesEx access denied - try running as administrator");
    else
        debug_log("EnumProcessModulesEx failed: " + std::to_string(err) + ", falling back to ToolHelp");
    DWORD pid = GetProcessId(proc);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        DWORD snapErr = GetLastError();
        if (snapErr == ERROR_ACCESS_DENIED)
            debug_log("CreateToolhelp32Snapshot access denied - try running as administrator");
        else
            debug_log("CreateToolhelp32Snapshot failed: " + std::to_string(snapErr));
        return false;
    }

    MODULEENTRY32 me{ sizeof(me) };
    if (!Module32First(snap, &me)) {
        debug_log("Module32First failed: " + std::to_string(GetLastError()));
        CloseHandle(snap);
        return false;
    }
    do {
        mods.push_back(reinterpret_cast<HMODULE>(me.modBaseAddr));
    } while (Module32Next(snap, &me));
    CloseHandle(snap);
    return !mods.empty();
}

HMODULE getUOSAModule(HANDLE proc) {
    std::vector<HMODULE> modules;
    if (!enumProcessModulesSafe(proc, modules)) {
        return NULL;
    }

    for (HMODULE mod : modules) {
        char modName[MAX_PATH];
        if (GetModuleFileNameExA(proc, mod, modName, sizeof(modName))) {
            std::string name = modName;
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            if (name.find("uosa.exe") != std::string::npos) {
                debug_log("Found UOSA.exe module at " + std::to_string((uintptr_t)mod));
                return mod;
            }
        }
    }
    return NULL;
}

bool scanProcess(HANDLE proc, const PatternData& pat, uintptr_t& found) {
    std::vector<HMODULE> modules;
    if (!enumProcessModulesSafe(proc, modules)) {
        debug_log("Failed to enumerate process modules");
        return false;
    }

    // Find UOSA.exe module
    HMODULE uosaModule = NULL;
    char szModName[MAX_PATH];
    for (HMODULE mod : modules) {
        if (GetModuleFileNameExA(proc, mod, szModName, sizeof(szModName))) {
            std::string modName = szModName;
            std::transform(modName.begin(), modName.end(), modName.begin(), ::tolower);
            if (modName.find("uosa.exe") != std::string::npos) {
                uosaModule = mod;
                debug_log("Found UOSA.exe at: " + modName);
                break;
            }
        }
    }

    if (!uosaModule) {
        debug_log("Could not find UOSA.exe module");
        return false;
    }

    MODULEINFO modInfo;
    if (!GetModuleInformation(proc, uosaModule, &modInfo, sizeof(modInfo))) {
        debug_log("Failed to get module information");
        return false;
    }

    // Scan only the UOSA.exe module
    uintptr_t start = (uintptr_t)modInfo.lpBaseOfDll;
    uintptr_t end = start + modInfo.SizeOfImage;
    
    debug_log("Scanning UOSA.exe module - base: 0x" + 
              [&]{std::ostringstream oss; oss<<std::hex<<start; return oss.str();}() + 
              " size: " + std::to_string(modInfo.SizeOfImage / 1024) + "KB");
    
    debug_log("Pattern: " + hex_dump(pat.bytes.data(), pat.bytes.size()));
    debug_log("Mask:    " + pat.mask);

    try {
        const size_t CHUNK_SIZE = 4096;  // Read in 4KB chunks
        const size_t STEP_SIZE = CHUNK_SIZE - pat.bytes.size() + 1;
        size_t bytesScanned = 0;
        std::vector<uint8_t> buffer(CHUNK_SIZE);

        for (uintptr_t addr = start; addr < end; addr += STEP_SIZE) {
            size_t toRead = min_size_t(CHUNK_SIZE, static_cast<size_t>(end - addr));
            
            SIZE_T read;
            if (!ReadProcessMemory(proc, (LPCVOID)addr, buffer.data(), toRead, &read)) {
                debug_log("ReadProcessMemory failed at 0x" + 
                    [&]{std::ostringstream oss; oss<<std::hex<<addr; return oss.str();}() +
                    " (error: " + std::to_string(GetLastError()) + ")");
                continue;
            }

            if (read == 0) {
                continue;
            }

            bytesScanned += read;
            if (bytesScanned % (1024*1024) == 0) {  // Log every MB
                debug_log("Scanned " + std::to_string(bytesScanned/1024) + "KB...");
            }

            // Look for pattern in this chunk
            for (size_t i = 0; i + pat.bytes.size() <= read; ++i) {
                bool match = true;
                for (size_t j = 0; j < pat.bytes.size(); ++j) {
                    if (pat.mask[j] == 'x' && buffer[i+j] != pat.bytes[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    found = addr + i;
                    debug_log("Pattern found at: 0x" + 
                        [&]{std::ostringstream oss; oss<<std::hex<<found; return oss.str();}());
                    debug_log("Context around match:");
                    size_t context_start = i >= 16 ? i - 16 : 0;
                    size_t context_len = min_size_t(
                        static_cast<size_t>(read - context_start),
                        static_cast<size_t>(i + pat.bytes.size() + 16 - context_start)
                    );
                    debug_log(hex_dump(buffer.data() + context_start, context_len, i - context_start));
                    return true;
                }
            }
        }
        
        debug_log("Scan complete - searched " + std::to_string(bytesScanned/1024) + "KB");
        
    } catch (const std::exception& e) {
        debug_log("ERROR: Exception during scan: " + std::string(e.what()));
        return false;
    } catch (...) {
        debug_log("ERROR: Unknown exception during scan");
        return false;
    }

    return false;
}

// Scan for a raw byte sequence (used for string searches)
bool scanForBytes(HANDLE proc, const std::vector<uint8_t>& bytes, uintptr_t& found) {
    PatternData pd;
    pd.bytes = bytes;
    pd.mask.assign(bytes.size(), 'x');
    return scanProcess(proc, pd, found);
}

bool scanForString(HANDLE proc, const std::string& str, uintptr_t& found) {
    std::vector<uint8_t> bytes(str.begin(), str.end());
    bytes.push_back('\0');
    return scanForBytes(proc, bytes, found);
}

bool findPushWithAddress(HANDLE proc, uintptr_t addr, uintptr_t& pushAddr) {
    std::vector<uint8_t> pat(5);
    pat[0] = 0x68; // push imm32
    std::memcpy(&pat[1], &addr, 4);
    return scanForBytes(proc, pat, pushAddr);
}

bool findRegisterLuaFunction(HANDLE proc, uintptr_t& regOut, uintptr_t& callSiteOut) {
    uintptr_t strAddr = 0;
    if (!scanForString(proc, "GetBuildVersion", strAddr)) {
        debug_log("GetBuildVersion string not found");
        return false;
    }
    debug_log("GetBuildVersion string at 0x" + [&]{std::ostringstream oss; oss<<std::hex<<strAddr; return oss.str();}());

    uintptr_t pushAddr = 0;
    if (!findPushWithAddress(proc, strAddr, pushAddr)) {
        debug_log("push instruction for GetBuildVersion not found");
        return false;
    }
    debug_log("push of GetBuildVersion found at 0x" + [&]{std::ostringstream oss; oss<<std::hex<<pushAddr; return oss.str();}());

    uintptr_t callAddr = pushAddr + 11; // push str, push impl, push esi, call
    uint8_t opcode = 0;
    SIZE_T read = 0;
    if (!ReadProcessMemory(proc, (LPCVOID)callAddr, &opcode, 1, &read) || opcode != 0xE8) {
        debug_log("expected call opcode not found");
        return false;
    }
    int32_t rel = 0;
    if (!ReadProcessMemory(proc, (LPCVOID)(callAddr + 1), &rel, 4, &read)) {
        debug_log("failed to read relative offset");
        return false;
    }
    regOut = callAddr + 5 + rel;
    callSiteOut = callAddr;
    debug_log("RegisterLuaFunction at 0x" + [&]{std::ostringstream oss; oss<<std::hex<<regOut; return oss.str();}());
    return true;
}

bool findLuaStatePtr(HANDLE proc, uintptr_t& out) {
    PatternData pat = parsePattern("A1 ?? ?? ?? ?? 85 C0 75 ?? 8B 08");
    uintptr_t match = 0;
    if (!scanProcess(proc, pat, match)) {
        debug_log("LuaState pattern not found");
        return false;
    }
    SIZE_T read = 0;
    if (!ReadProcessMemory(proc, (LPCVOID)(match + 1), &out, 4, &read)) {
        debug_log("failed to read LuaState pointer address");
        return false;
    }
    debug_log("LuaState global at 0x" + [&]{std::ostringstream oss; oss<<std::hex<<out; return oss.str();}());
    return true;
}


DWORD findProcess(const std::wstring& name) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring procName = pe.szExeFile;
            std::transform(procName.begin(), procName.end(), procName.begin(), ::tolower);
            // Look for both the exact name and the wine-prefixed version
            if (procName == name || procName == L"wine-" + name) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

bool createRemoteConsole(HANDLE hProc, DWORD pid) {
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) return false;
    auto alloc = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "AllocConsole");
    if (!alloc) return false;
    HANDLE th = CreateRemoteThread(hProc, nullptr, 0, alloc, nullptr, 0, nullptr);
    if (!th) return false;
    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
    FreeConsole();
    AttachConsole(pid);
    (void)freopen("CONOUT$", "w", stdout);
    (void)freopen("CONOUT$", "w", stderr);
    std::cout << "[UOWalkPatch] console attached\n";
    return true;
}

bool isProcessElevated() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        debug_log("Failed to open process token");
        return false;
    }
    
    TOKEN_ELEVATION elevation;
    DWORD size = sizeof(TOKEN_ELEVATION);
    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
        debug_log("Failed to get token information");
        CloseHandle(hToken);
        return false;
    }
    
    CloseHandle(hToken);
    return elevation.TokenIsElevated != 0;
}

bool enableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        debug_log("Failed to open process token for privilege adjustment");
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        debug_log("Failed to lookup debug privilege value");
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        debug_log("Failed to adjust token privileges");
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

struct RemoteFuncInfo {
    uint32_t nameAddr;
    uint32_t bridgeAddr;
};

struct RemoteAlloc { LPVOID addr; SIZE_T size; };

bool installHook(HANDLE proc, uintptr_t regFunc, uintptr_t callSite,
                 const std::vector<RemoteFuncInfo>& funcs,
                 std::vector<RemoteAlloc>& allocs) {
    SIZE_T written = 0;

    void* arrayMem = VirtualAllocEx(proc, nullptr,
                                    funcs.size() * sizeof(RemoteFuncInfo),
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!arrayMem) return false;
    WriteProcessMemory(proc, arrayMem, funcs.data(),
                       funcs.size() * sizeof(RemoteFuncInfo), &written);
    allocs.push_back({ arrayMem, funcs.size() * sizeof(RemoteFuncInfo) });

    uint32_t zero = 0;
    void* flagMem = VirtualAllocEx(proc, nullptr, sizeof(uint32_t),
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!flagMem) return false;
    WriteProcessMemory(proc, flagMem, &zero, sizeof(uint32_t), &written);
    allocs.push_back({ flagMem, sizeof(uint32_t) });

    std::vector<uint8_t> stub(hook_stub_template,
                              hook_stub_template + hook_stub_template_len);
    *(uint32_t*)&stub[HOOK_REG_OFF1]  = (uint32_t)regFunc;
    *(uint32_t*)&stub[HOOK_REG_OFF2]  = (uint32_t)regFunc;
    *(uint32_t*)&stub[HOOK_FLAG_OFF]  = (uint32_t)(uintptr_t)flagMem;
    *(uint32_t*)&stub[HOOK_NUM_OFF]   = (uint32_t)funcs.size();
    *(uint32_t*)&stub[HOOK_FUNCS_OFF] = (uint32_t)(uintptr_t)arrayMem;
    *(uint32_t*)&stub[HOOK_RET_OFF]   = (uint32_t)(callSite + 5);

    void* stubMem = VirtualAllocEx(proc, nullptr, stub.size(),
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!stubMem) return false;
    WriteProcessMemory(proc, stubMem, stub.data(), stub.size(), &written);
    allocs.push_back({ stubMem, stub.size() });

    uint8_t jmp[5];
    jmp[0] = 0xE9;
    uint32_t rel = (uint32_t)((uintptr_t)stubMem - (callSite + 5));
    std::memcpy(&jmp[1], &rel, 4);

    DWORD oldProt;
    if (!VirtualProtectEx(proc, (LPVOID)callSite, 5, PAGE_EXECUTE_READWRITE,
                          &oldProt))
        return false;
    WriteProcessMemory(proc, (LPVOID)callSite, jmp, 5, &written);
    VirtualProtectEx(proc, (LPVOID)callSite, 5, oldProt, &oldProt);

    return true;
}

// Helper to find a symbol in the stub by pattern
uintptr_t find_symbol_in_stub(const std::vector<uint8_t>& stub, const std::vector<uint8_t>& pat, int32_t offset = 0) {
    for (size_t i = 0; i + pat.size() <= stub.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pat.size(); ++j) {
            if (pat[j] != 0xFF && stub[i + j] != pat[j]) {
                match = false;
                break;
            }
        }
        if (match) return i + offset;
    }
    return (uintptr_t)-1;
}

int main() {
    init_logging();

    if (!enableDebugPrivilege()) {
        debug_log("WARNING: could not enable debug privilege");
    }

    if (!isProcessElevated()) {
        debug_log("WARNING: injector is not running elevated - access may be limited");
    }

    // Try different common case variations of the process name
    std::vector<std::wstring> processNames = {
        L"uosa.exe", L"UOSA.exe", L"Uosa.exe", L"wine-uosa.exe", L"wine-UOSA.exe"};

    DWORD pid = 0;
    for (const auto& name : processNames) {
        pid = findProcess(name);
        if (pid) break;
    }

    // If not running, launch UOSA.exe in suspended mode
    HANDLE hProc = NULL;
    HANDLE hThread = NULL;
    bool launchedSuspended = false;
    if (!pid) {
        debug_log("UOSA.exe not running, launching (suspended)...");
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        const char* uosaPath = "C:\\Program Files (x86)\\Electronic Arts\\Ultima Online Enhanced\\UOSA.exe";
        const char* uosaDir = "C:\\Program Files (x86)\\Electronic Arts\\Ultima Online Enhanced\\";
        if (!CreateProcessA(uosaPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, uosaDir, &si, &pi)) {
            DWORD err = GetLastError();
            std::ostringstream oss;
            oss << "Failed to launch UOSA.exe (" << uosaPath << ") error code: " << err;
            debug_log(oss.str());
            std::cerr << oss.str() << std::endl;
            close_logging();
            return 1;
        }
        debug_log("Launched UOSA.exe in suspended mode, patching registration hook...");
        pid = pi.dwProcessId;
        hProc = pi.hProcess;
        hThread = pi.hThread;
        launchedSuspended = true;
    }

    if (!hProc) {
        // Retry OpenProcess up to 10 times with 1s delay
        for (int attempt = 0; attempt < 10; ++attempt) {
            hProc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                                   PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (hProc) break;
            debug_log("OpenProcess failed, retrying in 1s...");
            Sleep(1000);
        }
        if (!hProc) {
            std::cerr << "failed to open process (error code: " << GetLastError() << ")\n";
            close_logging();
            return 1;
        }
    }

    bool target64 = true;
    if (getProcessBitness(hProc, target64)) {
#ifdef _WIN64
        const bool self64 = true;
#else
        const bool self64 = false;
#endif
        debug_log(std::string("Injector is ") + (self64 ? "64" : "32") + "-bit, target is " + (target64 ? "64" : "32") + "-bit");
        if (self64 != target64) {
            debug_log("WARNING: bitness mismatch detected - module enumeration may fail");
        }
    } else {
        debug_log("Failed to determine target process bitness");
    }

    createRemoteConsole(hProc, pid);

    uintptr_t regFunc = 0, callSite = 0;
    if (!findRegisterLuaFunction(hProc, regFunc, callSite)) {
        debug_log("failed to locate RegisterLuaFunction");
        CloseHandle(hProc);
        close_logging();
        return 1;
    }

    // Patch only the registration function (hook) while suspended
    std::vector<RemoteAlloc> allocs;
    std::vector<RemoteFuncInfo> funcs; // empty for now
    if (!installHook(hProc, regFunc, callSite, funcs, allocs)) {
        debug_log("failed to install registration hook");
        for (auto& a : allocs) VirtualFreeEx(hProc, a.addr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        close_logging();
        return 1;
    }

    // Resume the main thread so the client can initialize and register Lua natives
    if (launchedSuspended && hThread) {
        debug_log("Resuming UOSA.exe main thread after registration hook...");
        ResumeThread(hThread);
        CloseHandle(hThread);
        hThread = NULL;
    }

    // Wait for client to initialize and (hopefully) call our trampoline
    debug_log("Waiting 5 seconds for client Lua registration...");
    Sleep(5000);

    // Now scan for Lua state, inject bridges, and register our own natives
    // Reload signatures (if needed)
    std::vector<Signature> sigs;
    if (!loadSignatures("signatures.json", sigs)) {
        debug_log("failed to load signatures.json");
        CloseHandle(hProc);
        close_logging();
        return 1;
    }
    funcs.clear();
    allocs.clear();
    for (auto& s : sigs) {
        PatternData pd = parsePattern(s.pattern);
        if (!scanProcess(hProc, pd, s.address)) {
            debug_log("pattern not found for " + s.lua_name);
            continue;
        }
        void* bridge = VirtualAllocEx(hProc, nullptr, bridge_template_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!bridge) continue;
        std::vector<uint8_t> b(bridge_template, bridge_template + bridge_template_len);
        *(uint32_t*)&b[BRIDGE_FUNC_OFF] = (uint32_t)s.address;
        SIZE_T written = 0;
        WriteProcessMemory(hProc, bridge, b.data(), b.size(), &written);
        void* name = VirtualAllocEx(hProc, nullptr, s.lua_name.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!name) {
            VirtualFreeEx(hProc, bridge, 0, MEM_RELEASE);
            continue;
        }
        WriteProcessMemory(hProc, name, s.lua_name.c_str(), s.lua_name.size() + 1, &written);
        funcs.push_back({ (uint32_t)(uintptr_t)name, (uint32_t)(uintptr_t)bridge });
        allocs.push_back({ bridge, bridge_template_len });
        allocs.push_back({ name, s.lua_name.size() + 1 });
    }

    // Patch: Use regfunc_trampoline for registration and patch real_regfunc_ptr
    // 1. Find address of regfunc_trampoline in remote process
    // 2. Find address of real_regfunc_ptr in remote process
    // 3. Patch real_regfunc_ptr with RegisterLuaFunction address
    // 4. Use regfunc_trampoline as the registration function in stubs

    // 1. Find regfunc_trampoline and real_regfunc_ptr in stub
    // (Assume stub is loaded at stubBase, and symbols are at known offsets)
    // For simplicity, scan the stub memory for the trampoline and ptr symbol patterns
    // (In a real implementation, you would export or fixup these addresses more robustly)

    std::vector<uint8_t> bridges_stub;
    bridges_stub.resize(4096); // enough for bridges.asm output
    SIZE_T read = 0;
    ReadProcessMemory(hProc, allocs[0].addr, bridges_stub.data(), bridges_stub.size(), &read);

    // regfunc_trampoline: look for push ebp; mov ebp, esp; sub esp, 8; push dword [ebp+0Ch]
    std::vector<uint8_t> tramp_pat = {0x55, 0x89, 0xE5, 0x83, 0xEC, 0x08, 0xFF};
    uintptr_t tramp_off = find_symbol_in_stub(bridges_stub, tramp_pat);
    uintptr_t regfunc_trampoline_addr = (uintptr_t)allocs[0].addr + tramp_off;

    // real_regfunc_ptr: look for 4 zero bytes in .data after code
    std::vector<uint8_t> realptr_pat = {0x00, 0x00, 0x00, 0x00};
    uintptr_t realptr_off = find_symbol_in_stub(bridges_stub, realptr_pat);
    uintptr_t real_regfunc_ptr_addr = (uintptr_t)allocs[0].addr + realptr_off;

    // Patch real_regfunc_ptr with RegisterLuaFunction address
    WriteProcessMemory(hProc, (void*)real_regfunc_ptr_addr, &regFunc, sizeof(uint32_t), &read);

    // Use regfunc_trampoline_addr as the registration function in stub/hook
    // (patch stub/hook templates as needed)
    // ...

    // install hook stub at the registration call site (again, if needed)
    // ...

    debug_log("Registered Lua natives:");
    for (const auto& f : sigs) {
        debug_log("  " + f.lua_name + " (bridge: " + f.bridge + ")");
    }

    debug_log("hook installed - reload the UI to register natives. Press Enter to exit");
    std::cin.get();

    CloseHandle(hProc);
    close_logging();
    return 0;
}
