#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include "minhook.h"

// Global state structure based on the memory layout observed
struct GlobalStateInfo {
    void* luaState;             // 0x00  - Lua state pointer
    void* databaseManager;      // 0x04  - Database manager
    bool initialized;           // 0x08  - Init flag 
    void* resourceManager;      // 0x0C  - Resource manager 
    void* resourceHandler1;     // 0x10
    void* networkConfig;        // 0x14
    void* engineContext;        // 0x18  - Points to engine context, not self
    void* globalFacetCache;     // 0x1C
    bool shutdownInitiated;     // 0x20
    void* resourceNodePtr;      // 0x24
    void* coreResourceMgr;      // 0x28
    // ... more fields we haven't identified yet
};

// Global state 
static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static char   g_logPath[MAX_PATH] = "";
static BOOL   g_logAnnounced = FALSE;
static BOOL   g_initialized = FALSE;
static HMODULE g_hModule = NULL;
static GlobalStateInfo* g_globalStateInfo = nullptr;
static void* g_luaState = NULL;
static HANDLE g_scanThread = NULL;

// The client uses __stdcall for RegisterLuaFunction 
typedef bool(__stdcall* RegisterLuaFunction_t)(void* luaState, void* func, const char* name);
static RegisterLuaFunction_t g_origRegLua = NULL;
static void* g_firstLuaState = NULL;

// Add global flag for hook success
static bool g_hookFoundLua = false;

// Add at top with other globals
static volatile LONG g_stopScan = 0;   // 0 = keep running, 1 = quit

// Forward declarations
static void WriteRawLog(const char* message);
static void LogLastError(const char* prefix);
static void LogLoadedModules();
static void SetupConsole();
static BYTE* FindBytes(BYTE* start, SIZE_T size, const BYTE* pattern, SIZE_T patSize);
static BYTE* FindPattern(BYTE* base, SIZE_T size, const BYTE* pat, SIZE_T patLen);
static void DumpMemory(const char* desc, void* addr, size_t len);
static void* FindGlobalStateInfo();
static void* FindOwnerOfLuaState(void* lua);
static DWORD WINAPI WaitForLua(LPVOID param);
static LPVOID FindRegisterLuaFunction();

// Simple memory search helper
static BYTE* FindBytes(BYTE* start, SIZE_T size, const BYTE* pattern, SIZE_T patSize) {
    for (SIZE_T i = 0; i + patSize <= size; ++i) {
        if (memcmp(start + i, pattern, patSize) == 0)
            return start + i;
    }
    return nullptr;
}

// Better pattern matching helper - handles wildcards and both UTF-16/ANSI
static BYTE* FindPattern(BYTE* base, SIZE_T size, const BYTE* pat, SIZE_T patLen) {
    for (SIZE_T i = 0; i + patLen <= size; ++i) {
        SIZE_T k = 0;
        while (k < patLen && (pat[k] == '?' || base[i + k] == pat[k]))
            ++k;
        if (k == patLen)
            return base + i;
    }
    return nullptr;
}

// Helper function to dump memory region as hex
static void DumpMemory(const char* desc, void* addr, size_t len) {
    if (!addr || !len) return;
    
    char buffer[1024];
    sprintf_s(buffer, sizeof(buffer), "Memory dump %s at %p:", desc, addr);
    WriteRawLog(buffer);

    BYTE* bytes = (BYTE*)addr;
    char hex[128];
    char ascii[17];
    ascii[16] = 0;

    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) {
            if (i > 0) {
                sprintf_s(buffer, sizeof(buffer), "  %p: %s  %s", bytes + i - 16, hex, ascii);
                WriteRawLog(buffer);
            }
            memset(hex, ' ', sizeof(hex));
            memset(ascii, '.', 16);
        }
        sprintf_s(hex + (i % 16) * 3, 4, "%02X ", bytes[i]);
        ascii[i % 16] = (bytes[i] >= 32 && bytes[i] <= 126) ? bytes[i] : '.';
    }

    // Print remaining bytes
    size_t remain = len % 16;
    if (remain > 0) {
        sprintf_s(buffer, sizeof(buffer), "  %p: %-48s  %s", 
            bytes + len - remain, hex, ascii);
        WriteRawLog(buffer);
    }
}

static void* FindGlobalStateInfo() {
    HMODULE hExe = GetModuleHandleA(nullptr);
    if (!hExe) return nullptr;

    BYTE* base = (BYTE*)hExe;
    
    // Get PE headers
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    
    // Multiple patterns to try
    static const struct {
        const wchar_t* w;   // UTF-16 literal (may be null)
        const char* a;      // ANSI literal (may be null) 
        int zeros;          // Expected consecutive zero DWORDs
    } needles[] = {
        {L"Text is cut off in Label", nullptr, 4},
        {L"UOSetWaypointMapFacet", nullptr, 4},
        {L"ProfessionDescriptionWindowText", nullptr, 4},
        {nullptr, "UOSetWaypointMapFacet", 4}, // ANSI fallback
    };

    static bool bannerShown = false; // Add static flag to reduce spam
    char buffer[256];
    bool foundAny = false;

    // Scan data sections but only once
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections && !foundAny; ++i, ++sec) {
        if ((sec->Characteristics & IMAGE_SCN_MEM_READ) &&
            (sec->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)) 
        {
            BYTE* sectionStart = base + sec->VirtualAddress;
            size_t sectionSize = sec->Misc.VirtualSize;

            // Try each pattern
            for (const auto& needle : needles) {
                BYTE* hit = nullptr;
                if (needle.w) {
                    // UTF-16 pattern
                    size_t len = (wcslen(needle.w) + 1) * 2;
                    hit = FindPattern(sectionStart, sectionSize, (const BYTE*)needle.w, len);
                }
                else if (needle.a) {
                    // ANSI pattern
                    size_t len = strlen(needle.a) + 1;
                    hit = FindPattern(sectionStart, sectionSize, (const BYTE*)needle.a, len);
                }

                if (hit) {
                    foundAny = true;
                    if (!bannerShown) {
                        if (needle.w) {
                            // Convert wide string to UTF-8 for logging
                            char utf8buf[128];
                            int conv = WideCharToMultiByte(CP_UTF8, 0, needle.w, -1, utf8buf, sizeof(utf8buf), NULL, NULL);
                            sprintf_s(buffer, sizeof(buffer),
                                "Found pattern '%s' at %p (zeros: %d)",
                                conv > 0 ? utf8buf : "<wchar_t conversion failed>", hit, needle.zeros);
                        }
                        else if (needle.a) {
                            sprintf_s(buffer, sizeof(buffer),
                                "Found pattern '%s' at %p (zeros: %d)",
                                needle.a, hit, needle.zeros);
                        }
                        WriteRawLog(buffer);
                        bannerShown = true;
                    }

                    // Walk back looking for zero block
                    DWORD* p = (DWORD*)hit;
                    for (int step = 0; step < 0x200; step += 4, --p) {
                        bool allZero = true;
                        for (int z = 0; z < needle.zeros && allZero; z++) {
                            if (p[z] != 0) allZero = false;
                        }

                        if (allZero) {
                            // Address of pointer variable following padding
                            DWORD* addrOfPtr = p + needle.zeros;
                            
                            // Defensive check - ensure we're still in module
                            if (addrOfPtr < (DWORD*)base || addrOfPtr > (DWORD*)(base + nt->OptionalHeader.SizeOfImage - 4))
                                continue;

                            GlobalStateInfo* info = *(GlobalStateInfo**)addrOfPtr;
                            if (!info) continue;

                            __try {
                                if (info->luaState && info->databaseManager) {
                                    sprintf_s(buffer, sizeof(buffer), 
                                        "Found GlobalStateInfo at %p:\n"
                                        "  Lua State: %p\n"
                                        "  DB Manager: %p\n"
                                        "  Resource Mgr: %p",
                                        info, info->luaState,
                                        info->databaseManager,
                                        info->resourceManager);
                                    WriteRawLog(buffer);
                                    return info;
                                }
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER) {
                                WriteRawLog("Access violation checking candidate");
                            }
                        }
                    }
                }
            }
        }
    }

    return nullptr;
}

// More robust function finder
static LPVOID FindRegisterLuaFunction() {
    HMODULE hExe = GetModuleHandleA(nullptr);
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), hExe, &mi, sizeof(mi)))
        return nullptr;

    BYTE* base = (BYTE*)mi.lpBaseOfDll;
    SIZE_T size = mi.SizeOfImage;

    static const char anchor[] = "GetBuildVersion";
    BYTE* str = FindBytes(base, size, (const BYTE*)anchor, sizeof(anchor));
    if (!str) return nullptr;

    char buffer[128];
    sprintf_s(buffer, sizeof(buffer), "Found GetBuildVersion string at %p", str);
    WriteRawLog(buffer);

    // Look for any push/lea that loads the string, then next near call
    for (BYTE* p = base; p < base + size - 5; ++p) {
        // push offset xxx  OR   lea eax, [xxx]
        bool hits = 
            (p[0] == 0x68 && *(DWORD*)(p + 1) == (DWORD)(uintptr_t)str) ||      // push imm32
            (p[0] == 0x8D && (p[1] & 0xC7) == 0x05 &&                           // lea eax, [addr]
             *(DWORD*)(p + 2) == (DWORD)(uintptr_t)str);

        if (!hits) continue;

        sprintf_s(buffer, sizeof(buffer), "Found string reference at %p", p);
        WriteRawLog(buffer);

        // Walk forward max 32 bytes to find near call (E8 xx xx xx xx) or indirect call (FF 15 xx xx xx xx)
        for (BYTE* q = p; q < p + 32; ++q) {
            if (*q == 0xE8) {  // near call
                INT32 rel = *(INT32*)(q + 1);
                BYTE* callee = q + 5 + rel;
                sprintf_s(buffer, sizeof(buffer), "Found direct call instruction at %p targeting %p", q, callee);
                WriteRawLog(buffer);
                return callee;
            }
            if (q[0] == 0xFF && q[1] == 0x15) {  // FF 15 [disp32] → call [absolute]
                DWORD disp = *(DWORD*)(q + 2);
                BYTE** abs = (BYTE**)(q + 6 + disp);  // RIP-relative
                BYTE* callee = *abs;  // Contents of IAT entry
                sprintf_s(buffer, sizeof(buffer), "Found indirect call instruction at %p targeting %p", q, callee);
                WriteRawLog(buffer);
                return callee;
            }
        }
    }

    WriteRawLog("Could not find RegisterLuaFunction reference");
    return nullptr;
}

static void* FindOwnerOfLuaState(void* lua) {
    if (!lua) return nullptr;

    char buffer[256];
    sprintf_s(buffer, sizeof(buffer), "Searching for owner of Lua state %p...", lua);
    WriteRawLog(buffer);

    HMODULE hExe = GetModuleHandleA(nullptr);
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hExe;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)hExe + dos->e_lfanew);

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) ||
            !(sec->Characteristics & IMAGE_SCN_MEM_READ))
            continue;  // Only interested in readable data sections

        BYTE* begin = (BYTE*)hExe + sec->VirtualAddress;
        BYTE* end = begin + sec->Misc.VirtualSize;

        for (BYTE* p = begin; p + sizeof(void*) <= end; p += sizeof(void*)) {
            if (*(void**)p != lua) continue;

            sprintf_s(buffer, sizeof(buffer), "Found Lua state reference at %p", p);
            WriteRawLog(buffer);

            // Walk backwards max 0x40 bytes for zero padding
            DWORD* d = (DWORD*)p;
            for (int back = 0; back < 0x10; ++back, --d) {
                if (!d[0] && !d[1] && !d[2] && !d[3]) {
                    GlobalStateInfo* info = *(GlobalStateInfo**)(d + 4);
                    sprintf_s(buffer, sizeof(buffer), 
                        "Found zero block at %p, checking candidate at %p", d, info);
                    WriteRawLog(buffer);

                    __try {
                        if (info && info->luaState == lua && info->databaseManager) {
                            sprintf_s(buffer, sizeof(buffer),
                                "Validated GlobalStateInfo at %p:\n"
                                "  Lua State: %p\n"
                                "  DB Manager: %p\n"
                                "  Resource Mgr: %p",
                                info, info->luaState,
                                info->databaseManager,
                                info->resourceManager);
                            WriteRawLog(buffer);
                            return info;
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER) {
                        WriteRawLog("Access violation checking candidate");
                    }
                }
            }
        }
    }

    WriteRawLog("Owner of Lua state not found in data sections");
    return nullptr;
}

// Background thread to wait for Lua state
static DWORD WINAPI WaitForLua(LPVOID) {
    WriteRawLog("Starting Lua state scan thread...");
    
    GlobalStateInfo* info = nullptr;
    int attempts = 0;
    
    while (!g_hookFoundLua && !g_stopScan && attempts++ < 50) {
        info = (GlobalStateInfo*)FindGlobalStateInfo();
        if (info && info->luaState) {
            g_globalStateInfo = info;
            g_luaState = info->luaState;
            
            char buffer[128];
            sprintf_s(buffer, sizeof(buffer), "Scanner found Lua State @ %p", g_luaState);
            WriteRawLog(buffer);
            
            return 0;
        }
        Sleep(200);
    }
    
    WriteRawLog(g_hookFoundLua ? "Hook found Lua state first" : "Failed to find Lua state after timeout");
    return 1;
}

// Hook function for RegisterLuaFunction
static bool __stdcall Hook_Register(void* L, void* func, const char* name) {
    char buffer[256];
    
    // First capture the Lua state
    if (!g_luaState) {
        g_luaState = L;
        g_hookFoundLua = true;
        sprintf_s(buffer, sizeof(buffer), "Captured first Lua state @ %p", L);
        WriteRawLog(buffer);

        // Now find its owner structure
        g_globalStateInfo = (GlobalStateInfo*)FindOwnerOfLuaState(L);
        if (g_globalStateInfo) {
            DumpMemory("GlobalStateInfo", g_globalStateInfo, 0x40);
            
            // Signal scanner thread to stop and wait for it to exit cleanly
            if (g_scanThread) {
                InterlockedExchange(&g_stopScan, 1);  // Tell scanner to stop
                WaitForSingleObject(g_scanThread, INFINITE);
                CloseHandle(g_scanThread);
                g_scanThread = NULL;
            }
        }
    }

    sprintf_s(buffer, sizeof(buffer),
        "RegisterLuaFunction called:\n"
        "  Lua State: %p\n"
        "  Function: %p\n"
        "  Name: %s\n"
        "  Global State Info: %p",
        L, func, name ? name : "<null>", g_globalStateInfo);
    WriteRawLog(buffer);

    bool ok = false;
    if (g_origRegLua) {
        WriteRawLog("Calling original RegisterLuaFunction...");
        ok = g_origRegLua(L, func, name);
        sprintf_s(buffer, sizeof(buffer), "Original RegisterLuaFunction returned %s", 
            ok ? "true" : "false");
        WriteRawLog(buffer);
    }

    return ok;
}

static bool InstallRegisterHook() {
    LPVOID target = FindRegisterLuaFunction();
    if (!target) {
        WriteRawLog("RegisterLuaFunction not found");
        return false;
    }

    char buffer[64];
    sprintf_s(buffer, sizeof(buffer), "RegisterLuaFunction at %p", target);
    WriteRawLog(buffer);

    if (MH_CreateHook(target, &Hook_Register, reinterpret_cast<LPVOID*>(&g_origRegLua)) != MH_OK)
    {
        WriteRawLog("MH_CreateHook failed");
        return false;
    }

    if (MH_EnableHook(target) != MH_OK) {
        WriteRawLog("MH_EnableHook failed");
        return false;
    }

    WriteRawLog("RegisterLuaFunction hook installed");
    return true;
}

static BOOL InitializeDLLSafe(HMODULE hModule) {
    WriteRawLog("DLL initialization starting...");

    __try {
        // Store module handle for later use
        g_hModule = hModule;

        // Log process info and loaded modules
        LogLoadedModules();

        // Initialize MinHook
        WriteRawLog("Initializing MinHook...");
        MH_STATUS status = MH_Initialize();
        if (status != MH_OK) {
            char buffer[64];
            sprintf_s(buffer, sizeof(buffer), "MinHook initialization failed: %d", status);
            WriteRawLog(buffer);
            return FALSE;
        }
        WriteRawLog("MinHook initialized successfully");

        // Start background thread to scan for Lua state
        g_scanThread = CreateThread(nullptr, 0, WaitForLua, nullptr, 0, nullptr);
        if (!g_scanThread) {
            WriteRawLog("Failed to create scanner thread");
            return FALSE;
        }

        // Note: RegisterLuaFunction hook is now optional since we can get 
        // lua_State directly. Only needed if you want to monitor registrations.
        if (!InstallRegisterHook()) {
            WriteRawLog("Warning: RegisterLuaFunction hook not installed");
        }

        g_initialized = TRUE;
        WriteRawLog("DLL initialization successful");
        SetupConsole();
        return TRUE;
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

    if (g_scanThread) {
        WaitForSingleObject(g_scanThread, 1000);
        CloseHandle(g_scanThread);
        g_scanThread = NULL;
    }

    if (g_initialized) {
        if (g_origRegLua) {
            MH_DisableHook(MH_ALL_HOOKS);
            g_origRegLua = NULL;
        }

        MH_STATUS status = MH_Uninitialize();
        if (status != MH_OK) {
            char buffer[64];
            sprintf_s(buffer, sizeof(buffer), "MinHook cleanup failed: %d", status);
            WriteRawLog(buffer);
        }
        g_initialized = FALSE;
    }

    if (g_logFile != INVALID_HANDLE_VALUE) {
        WriteRawLog("Closing log file");
        CloseHandle(g_logFile);
        g_logFile = INVALID_HANDLE_VALUE;
    }

    g_hModule = NULL;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    // Initialize globals first
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = NULL;
        g_logFile = INVALID_HANDLE_VALUE;
        g_logPath[0] = '\0';
        g_logAnnounced = FALSE;
        g_initialized = FALSE;
        g_globalStateInfo = nullptr;
        g_luaState = nullptr;  // Important: initialize before creating threads
        g_scanThread = NULL;
        g_origRegLua = NULL;
        g_firstLuaState = NULL;
    }

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
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("Exception in DllMain");
        return FALSE;
    }
}

// Write to debug output and file without any fancy formatting
static void WriteRawLog(const char* message) {
    if (!message) return;

    // Write to debug output
    OutputDebugStringA(message);
    OutputDebugStringA("\n");

    // Write to console if available
    if (GetConsoleWindow()) {
        printf("[%lu] %s\n", GetCurrentThreadId(), message);
        fflush(stdout); // Ensure immediate output
    }

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
            
            // Log creation error if any
            if (g_logFile == INVALID_HANDLE_VALUE) {
                LogLastError("CreateFile for log");
            }
        }
    }

    // Write to log file
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
            if (!WriteFile(g_logFile, buffer, len, &written, NULL)) {
                LogLastError("WriteFile to log");
            }
            else {
                FlushFileBuffers(g_logFile);

                if (!g_logAnnounced) {
                    g_logAnnounced = TRUE;
                    char pathMsg[MAX_PATH + 32];
                    sprintf_s(pathMsg, sizeof(pathMsg), "Log file: %s", g_logPath);
                    WriteRawLog(pathMsg); // Use WriteRawLog to avoid recursion
                }
            }
        }
    }
}

// Helper to log last error with Win32 message
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

// Log all loaded modules for debugging
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
                }
                else {
                    sprintf_s(buffer, sizeof(buffer), "  %p: %s", hMods[i], path);
                }
                WriteRawLog(buffer);
            }
        }
    }
    else {
        LogLastError("EnumProcessModules");
    }
}

// Setup console window for debug output
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