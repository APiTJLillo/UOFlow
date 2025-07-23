#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include "minhook.h"

// Global state
static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static BOOL g_initialized = FALSE;
static HMODULE g_hModule = NULL;

// Write to debug output and file without any fancy formatting
static void WriteRawLog(const char* message) {
    if (!message) return;

    // Write to debug output
    OutputDebugStringA(message);
    OutputDebugStringA("\n");

    // Try to open log in executable directory first
    if (g_logFile == INVALID_HANDLE_VALUE && g_hModule != NULL) {
        char logPath[MAX_PATH];
        GetModuleFileNameA(g_hModule, logPath, MAX_PATH);
        char* lastSlash = strrchr(logPath, '\\');
        if (lastSlash) {
            strcpy_s(lastSlash + 1, MAX_PATH - (lastSlash - logPath), "uowalkpatch_debug.log");
            g_logFile = CreateFileA(
                logPath,
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
            char logPath[MAX_PATH];
            sprintf_s(logPath, MAX_PATH, "%s\\Temp\\uowalkpatch_debug.log", winDir);
            g_logFile = CreateFileA(
                logPath,
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

        // Initialize MinHook
        WriteRawLog("Initializing MinHook...");
        MH_STATUS status = MH_Initialize();
        if (status != MH_OK) {
            sprintf_s(buffer, sizeof(buffer), "MinHook initialization failed: %d", status);
            WriteRawLog(buffer);
            return FALSE;
        }
        WriteRawLog("MinHook initialized successfully");

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
