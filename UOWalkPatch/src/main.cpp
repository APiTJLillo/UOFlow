#include <windows.h>
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

struct Signature {
    std::string lua_name;
    std::string pattern;
    std::string mask;
    std::string bridge;
    uintptr_t address{0};
};

struct PatternData {
    std::vector<uint8_t> bytes;
    std::string mask;
};

PatternData parsePattern(const std::string& pat, const std::string& maskStr) {
    std::istringstream iss(pat);
    std::string byteStr;
    PatternData out;
    while (iss >> byteStr) {
        if (byteStr == "??") {
            out.bytes.push_back(0x00);
        } else {
            out.bytes.push_back(static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16)));
        }
    }
    out.mask = maskStr;
    return out;
}

bool scanProcess(HANDLE proc, const PatternData& pat, uintptr_t& found) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t start = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t end   = (uintptr_t)si.lpMaximumApplicationAddress;

    for (uintptr_t addr = start; addr < end; addr += mbi.RegionSize) {
        if (!VirtualQueryEx(proc, (LPCVOID)addr, &mbi, sizeof(mbi)))
            continue;
        if (mbi.State != MEM_COMMIT)
            continue;
        std::vector<uint8_t> buffer(mbi.RegionSize);
        SIZE_T read = 0;
        if (!ReadProcessMemory(proc, (LPCVOID)addr, buffer.data(), mbi.RegionSize, &read))
            continue;
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
                return true;
            }
        }
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
        s.mask = item["mask"].get<std::string>();
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
            if (name == pe.szExeFile) {
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

void log(const std::string& msg) {
    std::cout << "[UOWalkPatch] " << msg << std::endl;
}

int main() {
    std::vector<Signature> sigs;
    if (!loadSignatures("signatures.json", sigs)) {
        return 1;
    }
    log("loaded signatures" );

    DWORD pid = findProcess(L"uosa.exe");
    if (!pid) {
        std::cerr << "uosa.exe not running\n";
        return 1;
    }
    log("found uosa.exe with PID " + std::to_string(pid));

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        std::cerr << "failed to open process\n";
        return 1;
    }
    log("attached to process");

    createRemoteConsole(hProc, pid);

    for (auto& s : sigs) {
        PatternData pd = parsePattern(s.pattern, s.mask);
        uintptr_t addr = 0;
        log("scanning for " + s.lua_name + " pattern");
        if (scanProcess(hProc, pd, addr)) {
            s.address = addr;
            log("found " + s.lua_name + " at 0x" + [&]{std::ostringstream oss; oss<<std::hex<<addr; return oss.str();}());
        } else {
            log("failed to find pattern for " + s.lua_name);
        }
    }

    // Allocate space for stub + patch info
    SIZE_T totalSize = stub_bin_len;
    void* remote = VirtualAllocEx(hProc, nullptr, totalSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        std::cerr << "alloc failed\n";
        CloseHandle(hProc);
        return 1;
    }
    log("allocated remote memory");

    SIZE_T written = 0;
    WriteProcessMemory(hProc, remote, stub_bin, stub_bin_len, &written);
    log("wrote stub to remote process");

    HANDLE thread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)remote, nullptr, 0, nullptr);
    if (thread) {
        log("stub injected, waiting for completion");
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
    } else {
        std::cerr << "CreateRemoteThread failed\n";
    }

    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    CloseHandle(hProc);
    log("done");
    return 0;
}
