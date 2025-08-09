#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>

static void GetLastErrorString(std::wstring& error);

static bool ensureDependencies(const std::filesystem::path& binDir) {
    const std::filesystem::path luaplus = binDir / "luaplus_1100.dll";
    const std::filesystem::path sigs    = binDir / "signatures.json";
    const std::filesystem::path cmds    = binDir / "command_list.json";

    // Check LuaPlus DLL; if it's missing, copy from the source tree
    if (!std::filesystem::exists(luaplus)) {
        std::filesystem::path src = std::filesystem::current_path() / ".." / "external" / "luaplus" / "luaplus_1100.dll";
        if (!std::filesystem::exists(src)) {
            std::wcerr << L"Missing luaplus_1100.dll and no copy was found." << std::endl;
            return false;
        }
        std::filesystem::copy_file(src, luaplus);
        std::wcout << L"Copied luaplus_1100.dll to " << luaplus.wstring() << std::endl;
    }

    // Check signatures.json; copy from source if needed
    if (!std::filesystem::exists(sigs)) {
        std::filesystem::path src = std::filesystem::current_path() / ".." / "UOWalkPatch" / "signatures.json";
        if (!std::filesystem::exists(src)) {
            std::wcerr << L"Missing signatures.json and no copy was found." << std::endl;
            return false;
        }
        std::filesystem::copy_file(src, sigs);
        std::wcout << L"Copied signatures.json to " << sigs.wstring() << std::endl;
    }

    // Check command_list.json; copy from source if needed
    if (!std::filesystem::exists(cmds)) {
        std::filesystem::path src = std::filesystem::current_path() / ".." / "UOWalkPatch" / "command_list.json";
        if (std::filesystem::exists(src))
            std::filesystem::copy_file(src, cmds);
    }
    return true;
}

static bool checkRuntimeLibraries() {
    HMODULE msvcr = LoadLibraryW(L"msvcr100.dll");
    if (!msvcr) {
        std::wcerr << L"LuaPlus depends on the VC++ 2010 runtime (msvcr100.dll) which is missing. Please install the Microsoft Visual C++ 2010 Redistributable x86." << std::endl;
        return false;
    }
    FreeLibrary(msvcr);
    return true;
}

// Add function to check if we have admin rights
static bool IsElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        
        CloseHandle(hToken);
    }
    
    return isElevated != FALSE;
}

static void GetLastErrorString(std::wstring& error) {
    DWORD errorCode = GetLastError();
    if (errorCode == 0) return;

    LPWSTR messageBuffer = nullptr;
    size_t size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&messageBuffer,
        0,
        NULL
    );

    if (size) {
        error = messageBuffer;
        LocalFree(messageBuffer);
    } else {
        error = L"Unknown error";
    }
}

static DWORD FindProcess(const std::wstring& name) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to create process snapshot: " << GetLastError() << std::endl;
        return 0;
    }
    
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) { 
                pid = pe.th32ProcessID; 
                break; 
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static void LogModules(HANDLE hProcess) {
    std::wcout << L"Loaded modules:" << std::endl;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName)/sizeof(wchar_t))) {
                std::wcout << L"  " << std::filesystem::path(szModName).filename().wstring() << std::endl;
            }
        }
    }
}

static bool ValidateProcess(HANDLE hProcess) {
    // Check if the process is still alive
    DWORD exitCode = 0;
    if (!GetExitCodeProcess(hProcess, &exitCode)) {
        std::wstring error;
        GetLastErrorString(error);
        std::wcerr << L"GetExitCodeProcess failed: " << error << std::endl;
        return false;
    }
    
    if (exitCode != STILL_ACTIVE) {
        std::wcerr << L"Process is not active (exit code: " << exitCode << L")" << std::endl;
        return false;
    }

    // Try to get basic process information
    HMODULE hMod;
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
        std::wstring error;
        GetLastErrorString(error);
        std::wcerr << L"EnumProcessModules failed: " << error << std::endl;
        return false;
    }

    // Get the executable path
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameExW(hProcess, hMod, exePath, sizeof(exePath)/sizeof(wchar_t))) {
        std::wstring error;
        GetLastErrorString(error);
        std::wcerr << L"GetModuleFileNameExW failed: " << error << std::endl;
        return false;
    }

    std::wcout << L"Process executable: " << exePath << std::endl;

    // Check basic memory access
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(hProcess, (LPCVOID)hMod, &mbi, sizeof(mbi))) {
        std::wstring error;
        GetLastErrorString(error);
        std::wcerr << L"VirtualQueryEx failed: " << error << std::endl;
        return false;
    }

    std::wcout << L"Base address: " << std::hex << mbi.BaseAddress << 
                  L", Size: " << mbi.RegionSize << 
                  L", Protection: " << mbi.Protect << std::dec << std::endl;

    // Just verify we can read something from the process
    BYTE buffer[4];
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, hMod, buffer, sizeof(buffer), &bytesRead)) {
        std::wstring error;
        GetLastErrorString(error);
        std::wcerr << L"ReadProcessMemory failed: " << error << std::endl;
        return false;
    }

    // Check if it's a valid PE file (has MZ signature)
    if (buffer[0] != 'M' || buffer[1] != 'Z') {
        std::wcerr << L"Invalid PE file signature" << std::endl;
        return false;
    }

    std::wcout << L"Process validation successful" << std::endl;
    return true;
}

static bool WaitForModules(HANDLE hProcess,
                           const std::vector<std::wstring>& modules,
                           DWORD timeoutMs = 20000) {
    DWORD elapsed = 0;
    const DWORD interval = 500;
    HMODULE hMods[1024];
    DWORD cbNeeded;

    while (elapsed < timeoutMs) {
        if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            Sleep(interval);
            elapsed += interval;
            continue;
        }

        bool allFound = true;
        for (const auto& mod : modules) {
            bool found = false;
            for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); ++i) {
                wchar_t name[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], name, MAX_PATH)) {
                    std::wstring base = std::filesystem::path(name).filename().wstring();
                    if (_wcsicmp(base.c_str(), mod.c_str()) == 0) {
                        found = true;
                        break;
                    }
                }
            }
            if (!found) {
                allFound = false;
                break;
            }
        }

        if (allFound)
            return true;

        Sleep(interval);
        elapsed += interval;
    }
    return false;
}

static bool InjectHandle(HANDLE hProc, const std::wstring& dllPath) {
    std::wcout << L"Validating process..." << std::endl;
    // Give the process a bit more time to initialize
    if (!ValidateProcess(hProc)) {
        std::wcerr << L"Process validation failed" << std::endl;
        return false;
    }

    // Verify signatures.json exists next to the DLL
    std::filesystem::path sigPath = std::filesystem::path(dllPath).parent_path() / L"signatures.json";
    if (!std::filesystem::exists(sigPath)) {
        std::wcerr << L"signatures.json not found: " << sigPath.wstring() << std::endl;
        std::wcerr << L"Make sure this file is located next to the DLL" << std::endl;
        return false;
    }

    // Log loaded modules before injection
    std::wcout << L"Modules before injection:" << std::endl;
    LogModules(hProc);

    // Allocate memory for DLL path
    std::wcout << L"Allocating memory for DLL path..." << std::endl;
    SIZE_T size = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID mem = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        std::wstring error;
        GetLastErrorString(error);
        std::wcerr << L"VirtualAllocEx failed: " << error << std::endl;
        return false;
    }

    // Write DLL path
    if (!WriteProcessMemory(hProc, mem, dllPath.c_str(), size, nullptr)) {
        std::wstring error;
        GetLastErrorString(error);
        std::wcerr << L"WriteProcessMemory failed: " << error << std::endl;
        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
        return false;
    }

    // Get kernel32 module in target process
    HMODULE hKernel32Remote = nullptr;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameExW(hProc, hMods[i], szModName, sizeof(szModName)/sizeof(wchar_t))) {
                std::wstring modName = std::filesystem::path(szModName).filename().wstring();
                if (_wcsicmp(modName.c_str(), L"KERNEL32.DLL") == 0 || 
                    _wcsicmp(modName.c_str(), L"kernel32.dll") == 0) {
                    hKernel32Remote = hMods[i];
                    std::wcout << L"Found kernel32.dll at: " << std::hex << (void*)hMods[i] << std::dec << std::endl;
                    break;
                }
            }
        }
    }

    if (!hKernel32Remote) {
        std::wcerr << L"Failed to find kernel32.dll in target process" << std::endl;
        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
        return false;
    }

    // Get LoadLibraryW address in our process
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        std::wstring error;
        GetLastErrorString(error);
        std::wcerr << L"Failed to get kernel32.dll handle: " << error << std::endl;
        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
        return false;
    }

    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW) {
        std::wstring error;
        GetLastErrorString(error);
        std::wcerr << L"Failed to get LoadLibraryW address: " << error << std::endl;
        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
        return false;
    }

    // Calculate LoadLibraryW address in target process
    LPTHREAD_START_ROUTINE pLoadLibraryWRemote = 
        (LPTHREAD_START_ROUTINE)((DWORD_PTR)pLoadLibraryW - (DWORD_PTR)hKernel32 + (DWORD_PTR)hKernel32Remote);

    std::wcout << L"Creating remote thread..." << std::endl;
    std::wcout << L"LoadLibraryW address in target process: " << std::hex << pLoadLibraryWRemote << std::dec << std::endl;
    std::wcout << L"DLL path: " << dllPath << std::endl;
    std::wcout << L"Memory allocated at: " << std::hex << mem << std::dec << std::endl;

    // Verify memory was written correctly
    std::vector<wchar_t> verifyBuffer(dllPath.size() + 1);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProc, mem, verifyBuffer.data(), size, &bytesRead)) {
        std::wstring error;
        GetLastErrorString(error);
        std::wcerr << L"Failed to verify memory write: " << error << std::endl;
        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
        return false;
    }

    if (wcscmp(verifyBuffer.data(), dllPath.c_str()) != 0) {
        std::wcerr << L"Memory verification failed - path was not written correctly" << std::endl;
        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
        return false;
    }

    // Create remote thread with extra error handling
    DWORD threadId = 0;
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE hThread = CreateRemoteThread(
        hProc,
        &sa,
        0,
        pLoadLibraryWRemote,
        mem,
        0,
        &threadId
    );

    if (!hThread) {
        std::wstring error;
        GetLastErrorString(error);
        std::wcerr << L"CreateRemoteThread failed: " << error << std::endl;
        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
        return false;
    }

    std::wcout << L"Remote thread created with ID: " << threadId << std::endl;

    // Wait for injection to complete with increased timeout
    std::wcout << L"Waiting for DLL load..." << std::endl;
    DWORD waitResult = WaitForSingleObject(hThread, 30000); // 30 second timeout
    if (waitResult != WAIT_OBJECT_0) {
        std::wstring error;
        GetLastErrorString(error);
        std::wcerr << L"DLL injection thread did not complete in time: " << error << std::endl;
        CloseHandle(hThread);
        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
        return false;
    }

    // Get injection result
    DWORD threadExitCode;
    if (!GetExitCodeThread(hThread, &threadExitCode)) {
        std::wstring error;
        GetLastErrorString(error);
        std::wcerr << L"Failed to get thread exit code: " << error << std::endl;
        CloseHandle(hThread);
        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
        return false;
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);

    if (threadExitCode == 0) {
        // Try to get the last error from the target process
        DWORD lastError = 0;
        if (ReadProcessMemory(hProc, (LPCVOID)0x7FFE0000, &lastError, sizeof(lastError), nullptr)) {
            std::wcerr << L"LoadLibrary failed in target process with error: 0x" << std::hex << lastError << std::dec << std::endl;
        }
        std::wcerr << L"LoadLibrary returned NULL in target process (0x" << std::hex << threadExitCode << L")" << std::dec << std::endl;
        return false;
    }

    if (threadExitCode == 0xC0000005) {
        std::wcerr << L"Access violation occurred while loading DLL" << std::endl;
        return false;
    }

    std::wcout << L"LoadLibrary returned: " << std::hex << threadExitCode << std::dec << std::endl;

    // Give the DLL more time to initialize
    Sleep(5000);

    // Verify DLL was loaded and check modules after injection
    std::wcout << L"Modules after injection:" << std::endl;
    LogModules(hProc);

    // Now check specifically for our DLL
    bool found = false;
    if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameExW(hProc, hMods[i], szModName, sizeof(szModName)/sizeof(wchar_t))) {
                if (wcsstr(szModName, L"UOWalkPatchDLL.dll")) {
                    found = true;
                    std::wcout << L"Found DLL loaded at: " << std::hex << (void*)hMods[i] << std::dec << std::endl;
                    break;
                }
            }
        }
    }

    if (!found) {
        std::wcerr << L"DLL not found in process modules" << std::endl;
        return false;
    }

    std::wcout << L"DLL successfully loaded" << std::endl;
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    // Check for admin rights
    if (!IsElevated()) {
        std::wcerr << L"This program requires administrative privileges to run properly." << std::endl;
        std::wcerr << L"Please run as administrator." << std::endl;
        return 1;
    }

    // Get the full path of the current executable's directory
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) {
        std::wcerr << L"Failed to get module path" << std::endl;
        return 1;
    }

    std::filesystem::path dllPath = std::filesystem::path(exePath).parent_path() / L"UOWalkPatchDLL.dll";
    if (argc > 1) {
        dllPath = argv[1];
    }

    if (!std::filesystem::exists(dllPath)) {
        std::wcerr << L"DLL not found: " << dllPath.wstring() << std::endl;
        return 1;
    }

    std::wcout << L"Using DLL: " << dllPath.wstring() << std::endl;

    // Ensure required files exist next to the DLL
    if (!ensureDependencies(dllPath.parent_path())) {
        return 1;
    }

    // Verify required runtime libraries are present
    if (!checkRuntimeLibraries()) {
        return 1;
    }

    DWORD pid = FindProcess(L"UOSA.exe");
    HANDLE hProc = nullptr;
    HANDLE hThread = nullptr;
    bool launched = false;

    if (!pid) {
        const wchar_t* uosaPath = L"C:\\Program Files (x86)\\Electronic Arts\\Ultima Online Enhanced\\UOSA.exe";
        if (!std::filesystem::exists(uosaPath)) {
            std::wcerr << L"UOSA.exe not found at: " << uosaPath << std::endl;
            return 1;
        }

        std::wstring workingDir = std::filesystem::path(uosaPath).parent_path().wstring();
        
        std::wcout << L"Launching UOSA.exe..." << std::endl;

        STARTUPINFOW si{};
        si.cb = sizeof(STARTUPINFOW);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOWNORMAL;

        PROCESS_INFORMATION pi{};

        // Launch normally; we'll poll for modules before injecting
        DWORD flags = NORMAL_PRIORITY_CLASS;
        
        if (!CreateProcessW(
            uosaPath,             // Application path
            nullptr,              // Command line
            nullptr,              // Process security attributes
            nullptr,              // Thread security attributes
            FALSE,               // Don't inherit handles
            flags,                // Creation flags
            nullptr,              // Use parent's environment
            workingDir.c_str(),   // Working directory
            &si,                  // Startup info
            &pi                   // Process information
        )) {
            std::wstring error;
            GetLastErrorString(error);
            std::wcerr << L"Failed to launch UOSA.exe: " << error << std::endl;
            return 1;
        }

        pid = pi.dwProcessId;
        hProc = pi.hProcess;
        hThread = pi.hThread;
        launched = true;

        std::wcout << L"UOSA.exe launched with PID: " << pid << std::endl;

        // Resume the process
        std::wcout << L"Resuming UOSA.exe..." << std::endl;
        DWORD resumeResult = ResumeThread(hThread);
        if (resumeResult == (DWORD)-1) {
            std::wstring error;
            GetLastErrorString(error);
            std::wcerr << L"Failed to resume process: " << error << std::endl;
            CloseHandle(hThread);
            CloseHandle(hProc);
            return 1;
        }
        std::wcout << L"Process resumed successfully. Resume count: " << resumeResult << std::endl;

        // Wait longer for process to stabilize
        std::wcout << L"Waiting for process startup..." << std::endl;
        Sleep(2000);

        // Verify process is still running and responsive
        DWORD exitCode = 0;
        if (!GetExitCodeProcess(hProc, &exitCode)) {
            std::wstring error;
            GetLastErrorString(error);
            std::wcerr << L"Failed to get process exit code: " << error << std::endl;
            CloseHandle(hThread);
            CloseHandle(hProc);
            return 1;
        }

        if (exitCode != STILL_ACTIVE) {
            std::wcerr << L"Process terminated during startup with exit code: 0x" << std::hex << exitCode << std::dec << std::endl;
            
            // Print more detailed error info
            if (exitCode == 0xC0000005) {
                std::wcerr << L"Access violation occurred (0xC0000005)" << std::endl;
            }
            
            CloseHandle(hThread);
            CloseHandle(hProc);
            return 1;
        }

        // Additional verification step
        if (!ValidateProcess(hProc)) {
            std::wcerr << L"Process validation failed after startup" << std::endl;
            CloseHandle(hThread);
            CloseHandle(hProc);
            return 1;
        }

        CloseHandle(hThread);
        hThread = nullptr;
    } else {
        std::wcout << L"Found existing UOSA.exe process with PID: " << pid << std::endl;
        DWORD desiredAccess = PROCESS_CREATE_THREAD |
                             PROCESS_QUERY_INFORMATION |
                             PROCESS_VM_OPERATION |
                             PROCESS_VM_WRITE |
                             PROCESS_VM_READ;
        hProc = OpenProcess(desiredAccess, FALSE, pid);
        if (!hProc) {
            std::wstring error;
            GetLastErrorString(error);
            std::wcerr << L"Failed to open UOSA.exe: " << error << std::endl;
            return 1;
        }

        // Existing process should already have kernel32 loaded
        std::vector<std::wstring> mods{L"kernel32.dll"};
        if (!WaitForModules(hProc, mods)) {
            std::wcerr << L"Timed out waiting for modules" << std::endl;
            CloseHandle(hProc);
            return 1;
        }
    }

    bool ok = InjectHandle(hProc, dllPath.wstring());

    CloseHandle(hProc);

    if (!ok) {
        std::wcerr << L"Injection failed" << std::endl;
        return 1;
    }

    std::wcout << L"Process should now be running with DLL loaded" << std::endl;
    return 0;
}
