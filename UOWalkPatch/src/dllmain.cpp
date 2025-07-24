#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

// Global state
static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static char   g_logPath[MAX_PATH] = "";
static BOOL   g_logAnnounced = FALSE;
static BOOL   g_initialized = FALSE;
static HMODULE g_hModule = NULL;

// The client uses __stdcall for RegisterLuaFunction, so our hook and
// trampoline must match that convention to avoid stack imbalance.
// Parameter order in the client is (luaState, functionPtr, name)
typedef void (__stdcall* RegisterLuaFunction_t)(void* luaState, void* func, const char* name);
static RegisterLuaFunction_t g_regLua = NULL;
static void* g_luaState = NULL;
static HANDLE g_pollThread = NULL;
static volatile LONG g_stopPolling = 0;

typedef int (__cdecl* LuaCallback_t)(void*);

// Simple logging helper used throughout the DLL
static void WriteRawLog(const char* message);

static int __cdecl DummyFunction(void* L) {
    WriteRawLog("DummyFunction invoked");
    return 0;
}

// Write to debug output and file without any fancy formatting
static void WriteRawLog(const char* message) {
    if (!message) return;

    // Write to debug output
    OutputDebugStringA(message);
    OutputDebugStringA("\n");

    // Try to open log in executable directory first
    if (g_logFile == INVALID_HANDLE_VALUE && g_hModule != NULL) {
        GetModuleFileNameA(g_hModule, g_logPath, MAX_PATH);
        char* lastSlash = strrchr(g_logPath, '\\');
        if (lastSlash) {
            strcpy_s(lastSlash + 1, MAX_PATH - (lastSlash - g_logPath), "uowalkpatch_debug.log");
            g_logFile = CreateFileA(
                g_logPath,
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
        }
    }

    // Fallback to Windows directory
    if (g_logFile == INVALID_HANDLE_VALUE) {
        char winDir[MAX_PATH];
        if (GetWindowsDirectoryA(winDir, MAX_PATH)) {
            sprintf_s(g_logPath, MAX_PATH, "%s\\Temp\\uowalkpatch_debug.log", winDir);
            g_logFile = CreateFileA(
                g_logPath,
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
        }
    }

    if (g_logFile != INVALID_HANDLE_VALUE) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buffer[4096];
        int len = sprintf_s(buffer, sizeof(buffer),
            "[%02d:%02d:%02d.%03d] [%lu] %s\r\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            GetCurrentThreadId(),
            message
        );
        if (len > 0) {
            DWORD written;
            WriteFile(g_logFile, buffer, len, &written, NULL);
            FlushFileBuffers(g_logFile);

            if (!g_logAnnounced) {
                g_logAnnounced = TRUE;
                char pathMsg[MAX_PATH + 32];
                sprintf_s(pathMsg, sizeof(pathMsg), "Log file: %s\r\n", g_logPath);
                OutputDebugStringA(pathMsg);
                DWORD wrote;
                WriteFile(g_logFile, pathMsg, (DWORD)strlen(pathMsg), &wrote, NULL);
                FlushFileBuffers(g_logFile);
            }
        }
    }
}

static void LogLastError(const char* prefix) {
    if (!prefix) return;
    
    DWORD error = GetLastError();
    char buffer[1024];
    char errorMsg[512] = "";
    
    FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        errorMsg,
        sizeof(errorMsg),
        NULL
    );

    // Clean up error message
    for (char* p = errorMsg; *p; p++) {
        if (*p == '\r' || *p == '\n') *p = ' ';
    }

    sprintf_s(buffer, sizeof(buffer), "%s failed with 0x%08X: %s", prefix, error, errorMsg);
    WriteRawLog(buffer);
}

static void LogLoadedModules() {
    WriteRawLog("Enumerating loaded modules:");
    
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hMods[1024];
    DWORD needed;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &needed)) {
        for (DWORD i = 0; i < (needed / sizeof(HMODULE)); i++) {
            char path[MAX_PATH] = "";
            char buffer[MAX_PATH + 64] = "";
            
            if (GetModuleFileNameExA(hProcess, hMods[i], path, MAX_PATH)) {
                MODULEINFO mi = { 0 };
                if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
                    sprintf_s(buffer, sizeof(buffer), "  %p - %p: %s", 
                        mi.lpBaseOfDll,
                        (char*)mi.lpBaseOfDll + mi.SizeOfImage,
                        path);
                } else {
                    sprintf_s(buffer, sizeof(buffer), "  %p: %s", hMods[i], path);
                }
                WriteRawLog(buffer);
            }
        }
    } else {
        LogLastError("EnumProcessModules");
    }
}

static void SetupConsole() {
    if (!GetConsoleWindow()) {
        if (AllocConsole()) {
            FILE* dummy;
            freopen_s(&dummy, "CONOUT$", "w", stdout);
            freopen_s(&dummy, "CONOUT$", "w", stderr);
            SetConsoleTitleA("UOWalkPatch console");
        }
    }
}

// Simple memory search helper
static BYTE* FindBytes(BYTE* start, SIZE_T size, const BYTE* pattern, SIZE_T patSize) {
    for (SIZE_T i = 0; i + patSize <= size; ++i) {
        if (memcmp(start + i, pattern, patSize) == 0)
            return start + i;
    }
    return nullptr;
}

// Retrieve the .text section range for the current executable
static bool GetTextSection(BYTE*& start, SIZE_T& size) {
    HMODULE hExe = GetModuleHandleA(nullptr);
    if (!hExe) return false;

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hExe);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)hExe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            start = (BYTE*)hExe + sec->VirtualAddress;
            size = sec->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

// Locate RegisterLuaFunction inside UOSA.exe using the GetBuildVersion string heuristic
static LPVOID FindRegisterLuaFunction() {
    HMODULE hExe = GetModuleHandleA(nullptr); // UOSA.exe
    if (!hExe) return nullptr;

    BYTE* base = nullptr;
    SIZE_T size = 0;
    if (!GetTextSection(base, size))
        return nullptr;

    const char target[] = "GetBuildVersion";
    BYTE* strLoc = FindBytes(base, size, (const BYTE*)target, sizeof(target));
    if (!strLoc) return nullptr;

    BYTE pat[5];
    pat[0] = 0x68; // push imm32
    *(DWORD*)(pat + 1) = (DWORD)(uintptr_t)strLoc;

    BYTE* pushLoc = FindBytes(base, size, pat, sizeof(pat));
    if (!pushLoc) return nullptr;

    BYTE* callAddr = pushLoc + 11; // push string; push impl; push esi; call rel32
    if (*callAddr != 0xE8) return nullptr;

    int32_t rel = *(int32_t*)(callAddr + 1);
    BYTE* regAddr = callAddr + 5 + rel;
    return regAddr;
}

// Scan executable memory for the globalStateInfo reference and return its address
static LPVOID FindGlobalStateInfo() {
    HMODULE hExe = GetModuleHandleA(nullptr);
    if (!hExe) return nullptr;

    BYTE* base = nullptr;
    SIZE_T size = 0;
    if (!GetTextSection(base, size))
        return nullptr;

    const BYTE pattern[] = { 0x8B, 0x0D, 0,0,0,0, 0x8B, 0x41, 0x0C };
    const char mask[] = "xx????xxx";

    for (SIZE_T i = 0; i + sizeof(pattern) <= size; ++i) {
        bool match = true;
        for (SIZE_T j = 0; j < sizeof(pattern); ++j) {
            if (mask[j] != '?' && pattern[j] != base[i + j]) {
                match = false;
                break;
            }
        }
        if (match)
            return base + i;
    }
    return nullptr;
}

// Read the lua_State* from globalStateInfo + 0xC
static void* GetLuaState() {
    BYTE* addr = (BYTE*)FindGlobalStateInfo();
    if (!addr) return nullptr;

    DWORD absAddr = *(DWORD*)(addr + 2);
    void** statePtr = (void**)(absAddr + 0xC);
    return *statePtr;
}

static bool RegisterFunction(const char* name, LuaCallback_t cb) {
    if (!g_regLua || !g_luaState) return false;
    g_regLua(g_luaState, (void*)cb, name);
    char buf[128];
    sprintf_s(buf, sizeof(buf), "Registered %s at %p (L=%p)", name, cb, g_luaState);
    WriteRawLog(buf);
    return true;
}

static DWORD WINAPI LuaStatePollThread(LPVOID) {
    WriteRawLog("Lua state polling thread started");
    void* last = g_luaState;
    while (!g_stopPolling) {
        void* cur = GetLuaState();
        if (cur && cur != last) {
            char buf[128];
            sprintf_s(buf, sizeof(buf), "lua_State changed %p -> %p", last, cur);
            WriteRawLog(buf);
            g_luaState = cur;
            RegisterFunction("dummy", DummyFunction);
            last = cur;
        }
        Sleep(2000);
    }
    WriteRawLog("Lua state polling thread exiting");
    return 0;
}



static BOOL InitializeDLLSafe(HMODULE hModule) {
    WriteRawLog("DLL initialization starting...");
    
    __try {
        // Store module handle for later use
        g_hModule = hModule;

        // Log process info
        char processPath[MAX_PATH] = "";
        GetModuleFileNameA(NULL, processPath, MAX_PATH);
        char buffer[MAX_PATH + 64];
        sprintf_s(buffer, sizeof(buffer), "Process path: %s", processPath);
        WriteRawLog(buffer);
        
        sprintf_s(buffer, sizeof(buffer), "Process ID: %lu, Thread ID: %lu", 
                 GetCurrentProcessId(), GetCurrentThreadId());
        WriteRawLog(buffer);

        // Get DLL path
        char dllPath[MAX_PATH] = "";
        if (GetModuleFileNameA(hModule, dllPath, MAX_PATH)) {
            sprintf_s(buffer, sizeof(buffer), "DLL loaded at: %s", dllPath);
            WriteRawLog(buffer);
        } else {
            LogLastError("GetModuleFileName for DLL");
        }

        // Log loaded modules to check dependencies
        LogLoadedModules();


        // Locate RegisterLuaFunction and lua_State
        g_regLua = (RegisterLuaFunction_t)FindRegisterLuaFunction();
        if (g_regLua) {
            sprintf_s(buffer, sizeof(buffer), "RegisterLuaFunction at %p", g_regLua);
            WriteRawLog(buffer);
        } else {
            WriteRawLog("Failed to locate RegisterLuaFunction");
        }

        g_luaState = GetLuaState();
        if (g_luaState) {
            sprintf_s(buffer, sizeof(buffer), "lua_State at %p", g_luaState);
            WriteRawLog(buffer);
        } else {
            WriteRawLog("lua_State pointer not found");
        }

        // Look for signatures.json
        char sigPath[MAX_PATH];
        GetModuleFileNameA(hModule, sigPath, MAX_PATH);
        char* lastSlash = strrchr(sigPath, '\\');
        if (lastSlash) {
            // `strcpy_s` requires the destination buffer size starting from the
            // provided pointer. The previous calculation overshot by one and
            // corrupted the stack when the path was at the end of the buffer.
            size_t remaining = MAX_PATH - static_cast<size_t>(lastSlash - sigPath) - 1;
            strcpy_s(lastSlash + 1, remaining, "signatures.json");
            
            WriteRawLog("Looking for signatures.json...");
            sprintf_s(buffer, sizeof(buffer), "Checking: %s", sigPath);
            WriteRawLog(buffer);

            HANDLE hFile = CreateFileA(
                sigPath,
                GENERIC_READ,
                FILE_SHARE_READ,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );

            if (hFile != INVALID_HANDLE_VALUE) {
                sprintf_s(buffer, sizeof(buffer), "Found signatures at: %s", sigPath);
                WriteRawLog(buffer);
                CloseHandle(hFile);
                
                g_initialized = TRUE;
                WriteRawLog("DLL initialization successful");
                SetupConsole();
                RegisterFunction("dummy", DummyFunction);

                g_stopPolling = 0;
                g_pollThread = CreateThread(NULL, 0, LuaStatePollThread, NULL, 0, NULL);
                if (!g_pollThread)
                    LogLastError("CreateThread poll");
                return TRUE;
            } else {
                LogLastError("CreateFile for signatures.json");
            }
        }

        WriteRawLog("Failed to initialize - signatures.json not found");
        return FALSE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        char buffer[64];
        sprintf_s(buffer, sizeof(buffer), "Exception in initialization: 0x%08X", GetExceptionCode());
        WriteRawLog(buffer);
        return FALSE;
    }
}

static void CleanupDLL() {
    WriteRawLog("Starting cleanup...");

    if (g_initialized) {
        g_initialized = FALSE;
    }

    InterlockedExchange(&g_stopPolling, 1);
    if (g_pollThread) {
        WaitForSingleObject(g_pollThread, 3000);
        CloseHandle(g_pollThread);
        g_pollThread = NULL;
    }
    
    if (g_logFile != INVALID_HANDLE_VALUE) {
        WriteRawLog("Closing log file");
        CloseHandle(g_logFile);
        g_logFile = INVALID_HANDLE_VALUE;
    }

    g_hModule = NULL;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    char buffer[64];
    sprintf_s(buffer, sizeof(buffer), "DllMain entry - reason: %lu", reason);
    WriteRawLog(buffer);
    
    __try {
        switch (reason) {
            case DLL_PROCESS_ATTACH: {
                // Prevent the DLL from being unloaded by the system
                HMODULE hSelf;
                GetModuleHandleExA(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | 
                    GET_MODULE_HANDLE_EX_FLAG_PIN,
                    (LPCSTR)hModule,
                    &hSelf
                );

                if (!InitializeDLLSafe(hModule)) {
                    WriteRawLog("Initialization failed - cleaning up");
                    CleanupDLL();
                    return FALSE;
                }
                return TRUE;
            }
            case DLL_PROCESS_DETACH:
                WriteRawLog("DLL_PROCESS_DETACH");
                CleanupDLL();
                break;
            case DLL_THREAD_ATTACH:
                WriteRawLog("DLL_THREAD_ATTACH");
                break;
            case DLL_THREAD_DETACH:
                WriteRawLog("DLL_THREAD_DETACH");
                break;
        }
        return TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("Exception in DllMain");
        return FALSE;
    }
}
