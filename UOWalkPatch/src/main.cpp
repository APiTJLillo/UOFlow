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
#include <thread>
#include <iomanip>
#include "../include/stub_bin.h"

#undef min

struct RemoteFuncInfo {
    uint32_t nameAddr;
    uint32_t bridgeAddr;
};

struct RemoteAlloc {
    void* addr;
    SIZE_T size;
};

// Logging functions
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

namespace {
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

struct HookData {
    void* stubMem;
    void* luaStateMem;
    void* debugCounterMem;  // Add debug counter memory
    uintptr_t callSite;               // address of patched call site
    uint8_t originalBytes[5];         // original bytes at call site
    std::vector<uint8_t> stub;
};

bool installHook(HANDLE proc, uintptr_t regFunc, uintptr_t callSite,
    const std::vector<RemoteFuncInfo>& funcs,
    std::vector<RemoteAlloc>& allocs,
    HookData& hookData) {
    SIZE_T written = 0;

    debug_log("Hook installation details:");
    debug_log("  RegisterLuaFunction: 0x" + [&] {std::ostringstream oss; oss << std::hex << regFunc; return oss.str(); }());
    debug_log("  Call site: 0x" + [&] {std::ostringstream oss; oss << std::hex << callSite; return oss.str(); }());

    // Verify target memory is accessible
    MEMORY_BASIC_INFORMATION mbiTarget;
    if (!VirtualQueryEx(proc, (LPCVOID)callSite, &mbiTarget, sizeof(mbiTarget))) {
        debug_log("Failed to query hook target memory");
        return false;
    }
    debug_log("  Target memory protection: " + format_protection(mbiTarget.Protect));

    // Allocate memory with proper order and alignment
    // First allocate the state tracking memory (4KB aligned)
    constexpr SIZE_T PAGE_SIZE = 4096;
    SIZE_T alignedSize = (sizeof(uint32_t) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    void* luaStateMem = VirtualAllocEx(proc, nullptr, alignedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void* debugCounterMem = VirtualAllocEx(proc, nullptr, alignedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!luaStateMem || !debugCounterMem) {
        debug_log("Failed to allocate state tracking memory");
        return false;
    }

    debug_log("  Lua state memory: 0x" + [&] {std::ostringstream oss; oss << std::hex << (uintptr_t)luaStateMem; return oss.str(); }());
    debug_log("  Debug counter: 0x" + [&] {std::ostringstream oss; oss << std::hex << (uintptr_t)debugCounterMem; return oss.str(); }());

    // Initialize memory with zeros
    uint32_t zero = 0;
    WriteProcessMemory(proc, luaStateMem, &zero, sizeof(uintptr_t), nullptr);
    WriteProcessMemory(proc, debugCounterMem, &zero, sizeof(zero), nullptr);

    // Allocate array memory last
    size_t arraySize = funcs.empty() ? sizeof(RemoteFuncInfo) : funcs.size() * sizeof(RemoteFuncInfo);
    void* arrayMem = VirtualAllocEx(proc, nullptr, arraySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!arrayMem) {
        debug_log("Failed to allocate array memory");
        return false;
    }

    // Allocate stub with proper alignment
    void* stubMemory = VirtualAllocEx(proc, nullptr, hook_stub_template_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stubMemory) {
        debug_log("Failed to allocate stub memory");
        return false;
    }

    debug_log("  Stub memory: 0x" + [&] {std::ostringstream oss; oss << std::hex << (uintptr_t)stubMemory; return oss.str(); }());

    // Create stub with proper addresses
    std::vector<uint8_t> stub(hook_stub_template, hook_stub_template + hook_stub_template_len);

    // Log original stub contents
    debug_log("Original stub contents:");
    debug_log(hex_dump(hook_stub_template, hook_stub_template_len));

    // Patch addresses into stub
    *(uint32_t*)&stub[HOOK_DEBUG_OFF + 1] = (uint32_t)(uintptr_t)debugCounterMem;      // After mov eax,
    *(uint32_t*)&stub[HOOK_LUASTATE_OFF + 1] = (uint32_t)(uintptr_t)luaStateMem;       // After mov eax,
    *(uint32_t*)&stub[HOOK_REG_OFF1 + 1] = (uint32_t)regFunc;                          // After mov eax,

    // Log patched stub contents 
    debug_log("Patched stub contents:");
    debug_log(hex_dump(stub.data(), stub.size()));

    // Verify every patched address
    debug_log("Verifying patched addresses:");
    debug_log("  Debug counter addr:   0x" + [&] {std::ostringstream oss; 
        oss << std::hex << *(uint32_t*)&stub[HOOK_DEBUG_OFF + 1]; return oss.str(); }());
    debug_log("  Lua state addr:       0x" + [&] {std::ostringstream oss; 
        oss << std::hex << *(uint32_t*)&stub[HOOK_LUASTATE_OFF + 1]; return oss.str(); }());
    debug_log("  RegisterLuaFunc addr: 0x" + [&] {std::ostringstream oss; 
        oss << std::hex << *(uint32_t*)&stub[HOOK_REG_OFF1 + 1]; return oss.str(); }());


    // Write the stub
    if (!WriteProcessMemory(proc, stubMemory, stub.data(), stub.size(), &written)) {
        debug_log("Failed to write stub");
        return false;
    }

    // Verify the written stub
    std::vector<uint8_t> verifyBuf(stub.size());
    if (!ReadProcessMemory(proc, stubMemory, verifyBuf.data(), stub.size(), &written)) {
        debug_log("Failed to verify stub memory");
        return false;
    }
    debug_log("Verified stub in memory:");
    debug_log(hex_dump(verifyBuf.data(), verifyBuf.size()));

    // Store hook data
    hookData.stubMem = stubMemory;
    hookData.luaStateMem = luaStateMem;
    hookData.debugCounterMem = debugCounterMem;
    hookData.stub = stub;
    hookData.callSite = callSite;

    SIZE_T read = 0;
    if (!ReadProcessMemory(proc, (LPCVOID)callSite, hookData.originalBytes,
                           sizeof(hookData.originalBytes), &read)) {
        debug_log("Failed to read original bytes at call site");
        return false;
    }

    // Track allocations
    allocs.push_back({ arrayMem, arraySize });
    allocs.push_back({ debugCounterMem, alignedSize });
    allocs.push_back({ luaStateMem, alignedSize });
    allocs.push_back({ stubMemory, stub.size() });

    // Install call to stub
    uint8_t callPatch[5] = { 0xE8 }; // CALL rel32
    *(uint32_t*)&callPatch[1] = (uint32_t)((uintptr_t)stubMemory - (callSite + 5));

    debug_log("Installing call to stub:");
    debug_log("  From: 0x" + [&] {std::ostringstream oss; oss << std::hex << callSite; return oss.str(); }());
    debug_log("  To: 0x" + [&] {std::ostringstream oss; oss << std::hex << (uintptr_t)stubMemory; return oss.str(); }());
    debug_log("  Relative offset: 0x" + [&] {std::ostringstream oss; oss << std::hex << *(uint32_t*)&callPatch[1]; return oss.str(); }());

    DWORD oldProtect;
    if (!VirtualProtectEx(proc, (LPVOID)callSite, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        debug_log("Failed to change page protection");
        return false;
    }

    if (!WriteProcessMemory(proc, (LPVOID)callSite, callPatch, 5, &written)) {
        debug_log("Failed to write call patch");
        VirtualProtectEx(proc, (LPVOID)callSite, 5, oldProtect, nullptr);
        return false;
    }

    VirtualProtectEx(proc, (LPVOID)callSite, 5, oldProtect, nullptr);
    return true;
}

bool removeHook(HANDLE proc, const HookData& hookData) {
    if (!hookData.callSite) return true;

    DWORD oldProtect;
    if (!VirtualProtectEx(proc, (LPVOID)hookData.callSite, sizeof(hookData.originalBytes),
                          PAGE_EXECUTE_READWRITE, &oldProtect)) {
        debug_log("Failed to change page protection to restore bytes");
        return false;
    }

    SIZE_T written;
    if (!WriteProcessMemory(proc, (LPVOID)hookData.callSite, hookData.originalBytes,
                            sizeof(hookData.originalBytes), &written)) {
        debug_log("Failed to restore original bytes at call site");
        VirtualProtectEx(proc, (LPVOID)hookData.callSite, sizeof(hookData.originalBytes), oldProtect, nullptr);
        return false;
    }

    VirtualProtectEx(proc, (LPVOID)hookData.callSite, sizeof(hookData.originalBytes), oldProtect, nullptr);
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

// Add helper to wait for module load
bool waitForModule(HANDLE proc, const char* moduleName, HMODULE& outModule, int timeout_ms = 5000) {
    DWORD start = GetTickCount();
    while (GetTickCount() - start < (DWORD)timeout_ms) {
        std::vector<HMODULE> modules;
        if (!enumProcessModulesSafe(proc, modules)) {
            Sleep(100);
            continue;
        }
        
        for (HMODULE mod : modules) {
            char modPath[MAX_PATH];
            if (GetModuleFileNameExA(proc, mod, modPath, sizeof(modPath))) {
                std::string path = modPath;
                std::transform(path.begin(), path.end(), path.begin(), ::tolower);
                if (path.find(moduleName) != std::string::npos) {
                    outModule = mod;
                    return true;
                }
            }
        }
        Sleep(100);
    }
    return false;
}

// Add helper to check if process is ready
bool isProcessReady(HANDLE proc) {
    DWORD exitCode = 0;
    if (!GetExitCodeProcess(proc, &exitCode) || exitCode != STILL_ACTIVE) {
        return false;
    }

    char modPath[MAX_PATH] = {0};
    if (GetModuleFileNameExA(proc, NULL, modPath, MAX_PATH)) {
        return true; // If we can get the main module path, process is ready
    }
    return false;
}

// Add helper function to verify memory permissions
bool verifyMemoryAccess(HANDLE proc, uintptr_t addr, size_t size, const char* description) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(proc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        debug_log("Failed to query memory at " + std::string(description) + ": " + std::to_string(GetLastError()));
        return false;
    }

    std::ostringstream oss;
    oss << "Memory at " << description << " (0x" << std::hex << addr << "): ";
    oss << "Base=" << mbi.BaseAddress << " Size=" << std::dec << mbi.RegionSize;
    oss << " Protection=" << format_protection(mbi.Protect);
    debug_log(oss.str());

    return true;
}

bool enableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        debug_log("Failed to open process token for privilege adjustment");
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME, &luid)) {
        debug_log("Failed to lookup debug privilege value");
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        debug_log("Failed to adjust token privileges");
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
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

DWORD findProcess(const std::wstring& name) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe{ sizeof(pe) };
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

    auto allocConsole = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "AllocConsole");
    if (!allocConsole) return false;

    HANDLE thread = CreateRemoteThread(hProc, nullptr, 0, allocConsole, nullptr, 0, nullptr);
    if (!thread) return false;

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    // Detach from our console and attach to target's
    FreeConsole();
    if (!AttachConsole(pid)) return false;

    // Reopen stdout/stderr
    FILE* dummy;
    freopen_s(&dummy, "CONOUT$", "w", stdout);
    freopen_s(&dummy, "CONOUT$", "w", stderr);

    std::cout << "[UOWalkPatch] console attached\n";
    return true;
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

    HANDLE hProc = NULL;
    HANDLE hThread = NULL;
    bool isDebugging = false;
    
    if (!pid) {
        debug_log("UOSA.exe not running, launching (suspended)...");
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        const char* uosaPath = "C:\\Program Files (x86)\\Electronic Arts\\Ultima Online Enhanced\\UOSA.exe";
        const char* uosaDir = "C:\\Program Files (x86)\\Electronic Arts\\Ultima Online Enhanced\\";
        
        // Create process suspended without debug flags
        DWORD createFlags = CREATE_SUSPENDED;
        
        if (!CreateProcessA(uosaPath, NULL, NULL, NULL, FALSE, createFlags, NULL, uosaDir, &si, &pi)) {
            DWORD err = GetLastError();
            std::ostringstream oss;
            oss << "Failed to launch UOSA.exe (" << uosaPath << ") error code: " << err;
            debug_log(oss.str());
            std::cerr << oss.str() << std::endl;
            close_logging();
            return 1;
        }
        
        pid = pi.dwProcessId;
        hProc = pi.hProcess;
        hThread = pi.hThread;
        
        debug_log("Launched UOSA.exe suspended, PID: " + std::to_string(pid));
        debug_log("Waiting for debugger attachment... Press Enter to continue");
        
        // Initialize hook data BEFORE creating debug thread
        HookData debugHookData = {};
        bool processExited = false;
        bool debuggerAttached = false;
        
        std::cin.get(); // Wait for user input
        
        debug_log("Continuing initialization...");
        
        // Initialize debug counter to 0
        uint32_t zero = 0;
        if (debugHookData.debugCounterMem) {
            WriteProcessMemory(hProc, debugHookData.debugCounterMem, &zero, sizeof(zero), nullptr);
        }
        
        // Resume the main thread
        debug_log("Resuming UOSA.exe main thread...");
        ResumeThread(hThread);
        CloseHandle(hThread);
        hThread = NULL;
    } else {
        // Open existing process
        for (int attempt = 0; attempt < 10; ++attempt) {
            hProc = OpenProcess(
                PROCESS_CREATE_THREAD | 
                PROCESS_VM_OPERATION | 
                PROCESS_VM_READ | 
                PROCESS_VM_WRITE |
                PROCESS_QUERY_INFORMATION |
                PROCESS_QUERY_LIMITED_INFORMATION, 
                FALSE, 
                pid);
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

    bool target64 = false;
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
    HookData hookData = {};
    std::vector<RemoteAlloc> allocs;
    std::vector<RemoteFuncInfo> funcs;
    funcs.reserve(1);

    debug_log("Initial hook installation with empty function array");
    if (!installHook(hProc, regFunc, callSite, funcs, allocs, hookData)) {
        debug_log("failed to install registration hook");
        for (auto& a : allocs) VirtualFreeEx(hProc, a.addr, a.size, MEM_RELEASE);
        CloseHandle(hProc);
        close_logging();
        return 1;
    }

    // Initialize hook state tracking memory


    // Monitor hook execution
    debug_log("Monitoring hook execution...");
    bool hookExecuted = false;
    int retries = 300; // 30 seconds total
    uintptr_t capturedLuaState = 0;
    uint32_t lastCounter = 0;

    while (retries-- > 0) {
        uint32_t flagValue = 0;
        uint32_t debugCounter = 0;
        uintptr_t luaState = 0;
        SIZE_T read;
        
        if (hookData.debugCounterMem) {
            if (ReadProcessMemory(hProc, hookData.debugCounterMem, &debugCounter, sizeof(debugCounter), &read)) {
                if (debugCounter != lastCounter) {
                    debug_log("Hook entered " + std::to_string(debugCounter) + " times");
                    lastCounter = debugCounter;
                }
            }
        }
        
        if (hookData.luaStateMem &&
            ReadProcessMemory(hProc, hookData.luaStateMem, &luaState, sizeof(luaState), &read)) {
            if (debugCounter > 0 && luaState != 0) {
                debug_log("Hook was called! Debug count: " + std::to_string(debugCounter));
                debug_log("Captured Lua state: 0x" +
                    [&]{std::ostringstream oss; oss<<std::hex<<luaState; return oss.str();}());
                hookExecuted = true;
                capturedLuaState = luaState;
                break;
            }
        }
        Sleep(100);
    }

    if (!hookExecuted) {
        debug_log("WARNING: Hook did not execute within timeout");
    } else {
        debug_log("Hook executed successfully");
    }

    // Clean up
    debug_log("Cleaning up...");
    removeHook(hProc, hookData);
    for (auto& a : allocs) {
        VirtualFreeEx(hProc, a.addr, a.size, MEM_RELEASE);
    }

    if (hProc) {
        CloseHandle(hProc);
    }

    // Keep console open for logging
    debug_log("Press Enter to exit...");
    std::cout.flush();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();

    close_logging();
    return 0;
}
