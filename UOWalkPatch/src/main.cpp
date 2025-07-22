#define PSAPI_VERSION 1
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include "stub_bin.h"
#include <cstdint>
#include <cstring>
#include <sstream>
#include <regex>

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

bool isLikelyCodeRegion(const MEMORY_BASIC_INFORMATION& mbi) {
    // Code regions are typically:
    // 1. Committed memory
    // 2. Have execute permissions
    // 3. Are from image (executable) or mapped memory
    return (mbi.State == MEM_COMMIT) &&
           (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
           (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED);
}

HMODULE getUOSAModule(HANDLE proc) {
    HMODULE modules[1024];
    DWORD needed;
    if (!EnumProcessModules(proc, modules, sizeof(modules), &needed)) {
        debug_log("Failed to enumerate process modules");
        return NULL;
    }

    for (DWORD i = 0; i < (needed / sizeof(HMODULE)); i++) {
        char modName[MAX_PATH];
        if (GetModuleFileNameExA(proc, modules[i], modName, sizeof(modName))) {
            std::string name = modName;
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            if (name.find("uosa.exe") != std::string::npos) {
                debug_log("Found UOSA.exe module at " + std::to_string((uintptr_t)modules[i]));
                return modules[i];
            }
        }
    }
    return NULL;
}

bool scanProcess(HANDLE proc, const PatternData& pat, uintptr_t& found) {
    HMODULE modules[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(proc, modules, sizeof(modules), &cbNeeded)) {
        debug_log("Failed to enumerate process modules");
        return false;
    }

    // Find UOSA.exe module
    HMODULE uosaModule = NULL;
    char szModName[MAX_PATH];
    for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        if (GetModuleFileNameExA(proc, modules[i], szModName, sizeof(szModName))) {
            std::string modName = szModName;
            std::transform(modName.begin(), modName.end(), modName.begin(), ::tolower);
            if (modName.find("uosa.exe") != std::string::npos) {
                uosaModule = modules[i];
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
            size_t toRead = std::min<size_t>(CHUNK_SIZE, end - addr);
            
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
                    size_t context_len = std::min(read - context_start, i + pat.bytes.size() + 16 - context_start);
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
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
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

int main() {
    init_logging();

    if (!enableDebugPrivilege()) {
        debug_log("WARNING: could not enable debug privilege");
    }

    const wchar_t* exePath = L"C:\\program files (x86)\\electronic arts\\ultima online enhanced\\uosa.exe";
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exePath, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        std::cerr << "failed to launch UOSA.exe\n";
        close_logging();
        return 1;
    }
    HANDLE hProc = pi.hProcess;
    debug_log("process launched suspended");

    uintptr_t registerAddr = 0, callSite = 0;
    if (!findRegisterLuaFunction(hProc, registerAddr, callSite)) {
        debug_log("failed to locate RegisterLuaFunction");
        TerminateProcess(hProc, 1);
        CloseHandle(pi.hThread);
        CloseHandle(hProc);
        close_logging();
        return 1;
    }

    std::vector<Signature> sigs;
    if (!loadSignatures("signatures.json", sigs)) {
        debug_log("failed to load signatures.json");
        TerminateProcess(hProc, 1);
        CloseHandle(pi.hThread);
        CloseHandle(hProc);
        close_logging();
        return 1;
    }

    struct FuncEntry { uint32_t name; uint32_t bridge; };
    std::vector<FuncEntry> entries;
    SIZE_T totalSize = hook_stub_template_len + sizeof(uint32_t); // stub + flag
    for (auto& s : sigs) {
        totalSize += s.lua_name.size() + 1;
        totalSize += bridge_stub_len;
        totalSize += sizeof(FuncEntry);
    }

    void* remote = VirtualAllocEx(hProc, nullptr, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        debug_log("remote allocation failed");
        TerminateProcess(hProc, 1);
        CloseHandle(pi.hThread);
        CloseHandle(hProc);
        close_logging();
        return 1;
    }

    uintptr_t stubAddr = (uintptr_t)remote;
    uintptr_t flagAddr = stubAddr + hook_stub_template_len;
    uintptr_t cursor = flagAddr + 4;

    for (auto& s : sigs) {
        SIZE_T nameLen = s.lua_name.size() + 1;
        uintptr_t nameAddr = cursor;
        SIZE_T written = 0;
        WriteProcessMemory(hProc, (LPVOID)nameAddr, s.lua_name.c_str(), nameLen, &written);
        cursor += nameLen;

        uintptr_t bridgeAddr = cursor;
        WriteProcessMemory(hProc, (LPVOID)bridgeAddr, bridge_stub, bridge_stub_len, &written);
        cursor += bridge_stub_len;

        entries.push_back({ (uint32_t)nameAddr, (uint32_t)bridgeAddr });
    }

    uintptr_t entryAddr = cursor;
    if (!entries.empty()) {
        SIZE_T written = 0;
        WriteProcessMemory(hProc, (LPVOID)entryAddr, entries.data(), entries.size()*sizeof(FuncEntry), &written);
        cursor += entries.size()*sizeof(FuncEntry);
    }

    std::vector<uint8_t> stub(hook_stub_template, hook_stub_template + hook_stub_template_len);
    *(uint32_t*)&stub[HOOK_REG_OFF1]  = (uint32_t)registerAddr;
    *(uint32_t*)&stub[HOOK_FLAG_OFF]  = (uint32_t)flagAddr;
    *(uint32_t*)&stub[HOOK_NUM_OFF]   = (uint32_t)entries.size();
    *(uint32_t*)&stub[HOOK_FUNCS_OFF] = (uint32_t)entryAddr;
    *(uint32_t*)&stub[HOOK_REG_OFF2]  = (uint32_t)registerAddr;
    *(uint32_t*)&stub[HOOK_RET_OFF]   = (uint32_t)(callSite + 5);

    SIZE_T written = 0;
    WriteProcessMemory(hProc, (LPVOID)stubAddr, stub.data(), stub.size(), &written);
    uint32_t zero = 0;
    WriteProcessMemory(hProc, (LPVOID)flagAddr, &zero, sizeof(uint32_t), &written);

    uint8_t patch[5];
    patch[0] = 0xE9;
    *(int32_t*)&patch[1] = (int32_t)(stubAddr - (callSite + 5));
    DWORD oldProt;
    VirtualProtectEx(hProc, (LPVOID)callSite, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    WriteProcessMemory(hProc, (LPVOID)callSite, patch, 5, &written);
    VirtualProtectEx(hProc, (LPVOID)callSite, 5, oldProt, &oldProt);

    ResumeThread(pi.hThread);
    debug_log("process resumed; hook installed");

    CloseHandle(pi.hThread);
    CloseHandle(hProc);
    close_logging();
    return 0;
}
