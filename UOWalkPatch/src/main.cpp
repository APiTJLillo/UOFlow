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
#include <nlohmann/json.hpp>
#include <sstream>

using json = nlohmann::json;

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

struct Signature {
    std::string lua_name;
    std::string pattern;
    std::string bridge;
    uintptr_t address{0};
};

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
        size_t bytesScanned = 0;
        std::vector<uint8_t> buffer(CHUNK_SIZE);

        for (uintptr_t addr = start; addr < end; addr += CHUNK_SIZE) {
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

bool loadSignatures(const std::string& path, std::vector<Signature>& out) {
    std::ifstream f(path);
    if (!f.is_open()) {
        std::cerr << "failed to open signatures.json\n";
        return false;
    }
    json j; f >> j;
    for (const auto& item : j["functions"]) {
        Signature s;
        s.lua_name = item["lua_name"].get<std::string>();
        s.pattern = item["pattern"].get<std::string>();
        s.bridge = item["bridge"].get<std::string>();
        out.push_back(s);
    }
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
    
    // Check if we're running with elevated privileges
    if (!isProcessElevated()) {
        debug_log("WARNING: Process is not running with elevated privileges");
        debug_log("This may prevent access to protected processes");
    } else {
        debug_log("Process is running with elevated privileges");
    }

    // Try to enable debug privileges
    if (enableDebugPrivilege()) {
        debug_log("Successfully enabled debug privileges");
    } else {
        debug_log("WARNING: Failed to enable debug privileges");
        debug_log("This may prevent access to protected processes");
    }
    
    std::vector<Signature> sigs;
    if (!loadSignatures("signatures.json", sigs)) {
        close_logging();
        return 1;
    }
    debug_log("loaded signatures" );

    // Try different common case variations of the process name
    std::vector<std::wstring> processNames = {
        L"uosa.exe",
        L"UOSA.exe",
        L"Uosa.exe",
        L"wine-uosa.exe",
        L"wine-UOSA.exe"
    };
    
    DWORD pid = 0;
    for (const auto& name : processNames) {
        pid = findProcess(name);
        if (pid) break;
    }
    
    if (!pid) {
        std::cerr << "UOSA.exe not running (checked various case combinations)\n";
        close_logging();
        return 1;
    }
    debug_log("found UO process with PID " + std::to_string(pid));

    // Try with full debug permissions first
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        debug_log("failed to open process with full permissions, trying reduced permissions...");
        hProc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc) {
            debug_log("failed to open process with reduced permissions, trying minimal permissions...");
            hProc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (!hProc) {
                std::cerr << "failed to open process (error code: " << GetLastError() << ")\n";
                close_logging();
                return 1;
            }
        }
    }
    debug_log("attached to process");

    // Skip console creation in Wine environment
    // createRemoteConsole(hProc, pid);

    // Give more time for the process to fully load
    debug_log("waiting for process to initialize (5 seconds)...");
    Sleep(5000);

    bool anyPatternFound = false;
    
    // Wait a bit longer for the process to initialize
    debug_log("performing module enumeration check...");
    DWORD needed;
    HMODULE modules[1024];
    if (!EnumProcessModules(hProc, modules, sizeof(modules), &needed)) {
        debug_log("warning: EnumProcessModules failed, process might not be fully initialized");
        Sleep(2000); // Wait a bit longer
    }
    
    for (auto& s : sigs) {
        PatternData pd = parsePattern(s.pattern);
        uintptr_t addr = 0;
        
        debug_log("scanning for " + s.lua_name + " pattern");
        debug_log("pattern size: " + std::to_string(pd.bytes.size()) + " bytes");
        debug_log("mask: " + pd.mask);

        // Try scanning up to 3 times with delays
        for (int attempt = 1; attempt <= 3; attempt++) {
            if (scanProcess(hProc, pd, addr)) {
                s.address = addr;
                debug_log("found " + s.lua_name + " at 0x" + [&]{std::ostringstream oss; oss<<std::hex<<addr; return oss.str();}());
                anyPatternFound = true;
                break;
            }
            
            if (attempt < 3) {
                debug_log("attempt " + std::to_string(attempt) + " failed, waiting before retry...");
                Sleep(1000);
            } else {
                debug_log("failed to find pattern for " + s.lua_name + " after " + std::to_string(attempt) + " attempts");
            }
        }
    }

    if (!anyPatternFound) {
        debug_log("warning: no patterns were found, process memory might not be accessible");
        // Don't try to inject if we couldn't find any patterns
        CloseHandle(hProc);
        close_logging();
        return 1;
    }

    // Allocate space for stub + patch info
    // First try to verify we can read the process memory
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(hProc, (LPCVOID)0x400000, &mbi, sizeof(mbi))) {
        debug_log("warning: VirtualQueryEx failed, process might not be fully loaded");
        Sleep(1000); // Wait a bit and try again
        if (!VirtualQueryEx(hProc, (LPCVOID)0x400000, &mbi, sizeof(mbi))) {
            std::cerr << "cannot query process memory (error: " << GetLastError() << ")\n";
            CloseHandle(hProc);
            close_logging();
            return 1;
        }
    }

    // Allocate memory with more restrictive permissions first
    SIZE_T totalSize = stub_bin_len;
    void* remote = VirtualAllocEx(hProc, nullptr, totalSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        std::cerr << "memory allocation failed (error: " << GetLastError() << ")\n";
        CloseHandle(hProc);
        close_logging();
        return 1;
    }
    debug_log("allocated remote memory");

    // Write the stub
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remote, stub_bin, stub_bin_len, &written) || written != stub_bin_len) {
        std::cerr << "failed to write memory (error: " << GetLastError() << ")\n";
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }
    debug_log("wrote stub to remote process");

    // Change permissions to allow execution
    DWORD oldProtect;
    if (!VirtualProtectEx(hProc, remote, totalSize, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "failed to set memory permissions (error: " << GetLastError() << ")\n";
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    // Create the remote thread with proper error handling
    HANDLE thread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)remote, nullptr, 0, nullptr);
    if (thread) {
        debug_log("stub injected, waiting for completion");
        if (WaitForSingleObject(thread, 5000) == WAIT_TIMEOUT) { // 5 second timeout
            debug_log("warning: thread execution timed out");
            TerminateThread(thread, 1);
        }
        CloseHandle(thread);
    } else {
        std::cerr << "CreateRemoteThread failed (error: " << GetLastError() << ")\n";
    }

    // Cleanup
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    CloseHandle(hProc);
    debug_log("done");
    close_logging();
    return 0;
}
