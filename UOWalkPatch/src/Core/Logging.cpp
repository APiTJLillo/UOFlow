#include "Core/Logging.hpp"
#include <psapi.h>
#include <cstdio>
#include <cstdarg>

namespace Log {
namespace {
    HANDLE g_logFile = INVALID_HANDLE_VALUE;
    char   g_logPath[MAX_PATH];
    BOOL   g_logAnnounced = FALSE;
    HMODULE g_hModule = NULL;
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

void Init(HMODULE self) {
    g_hModule = self;
    g_logFile = INVALID_HANDLE_VALUE;
    g_logPath[0] = '\0';
    g_logAnnounced = FALSE;

    char dllPath[MAX_PATH] = {};
    DWORD len = GetModuleFileNameA(self, dllPath, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        char* lastSlash = strrchr(dllPath, '\\');
        if (lastSlash && lastSlash + 1 < dllPath + MAX_PATH) {
            size_t destIndex = static_cast<size_t>((lastSlash + 1) - dllPath);
            size_t remaining = MAX_PATH - destIndex;
            if (remaining > 1 &&
                strcpy_s(lastSlash + 1, remaining, "uowalkpatch_debug.log") == 0) {
                g_logFile = CreateFileA(
                    dllPath,
                    GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL,
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL
                );
                if (g_logFile != INVALID_HANDLE_VALUE) {
                    strcpy_s(g_logPath, MAX_PATH, dllPath);
                }
            }
        }
    }
    SetupConsole();
}

void Shutdown() {
    if (g_logFile != INVALID_HANDLE_VALUE) {
        WriteRawLog("Closing log file");
        CloseHandle(g_logFile);
        g_logFile = INVALID_HANDLE_VALUE;
    }
    g_hModule = NULL;
}

void WriteRawLog(const char* message) {
    if (!message) return;

    OutputDebugStringA(message);
    OutputDebugStringA("\n");

    if (GetConsoleWindow()) {
        printf("[%lu] %s\n", GetCurrentThreadId(), message);
        fflush(stdout);
    }

    if (g_logFile == INVALID_HANDLE_VALUE && g_hModule != NULL) {
        if (GetModuleFileNameA(g_hModule, g_logPath, MAX_PATH) > 0) {
            char* lastSlash = strrchr(g_logPath, '\\');
            if (lastSlash && lastSlash + 1 < g_logPath + MAX_PATH) {
                size_t destIndex = static_cast<size_t>((lastSlash + 1) - g_logPath);
                size_t remaining = MAX_PATH - destIndex;
                if (remaining > 1 &&
                    strcpy_s(lastSlash + 1, remaining, "uowalkpatch_debug.log") == 0) {
                    g_logFile = CreateFileA(
                        g_logPath,
                        GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL
                    );
                    if (g_logFile == INVALID_HANDLE_VALUE) {
                        LogLastError("CreateFile for log");
                    }
                }
            }
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
            if (!WriteFile(g_logFile, buffer, len, &written, NULL)) {
                LogLastError("WriteFile to log");
            } else {
                FlushFileBuffers(g_logFile);
                if (!g_logAnnounced) {
                    g_logAnnounced = TRUE;
                    char pathMsg[MAX_PATH + 32];
                    sprintf_s(pathMsg, sizeof(pathMsg), "Log file: %s", g_logPath);
                    WriteRawLog(pathMsg);
                }
            }
        }
    }
}

void LogLastError(const char* prefix) {
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
    for (char* p = errorMsg; *p; p++) {
        if (*p == '\r' || *p == '\n') *p = ' ';
    }
    sprintf_s(buffer, sizeof(buffer), "%s failed with 0x%08X: %s", prefix, error, errorMsg);
    WriteRawLog(buffer);
}

void LogLoadedModules() {
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

void Logf(const char* fmt, ...) {
    char buf[256];
    va_list args;
    va_start(args, fmt);
    vsprintf_s(buf, sizeof(buf), fmt, args);
    va_end(args);
    WriteRawLog(buf);
}

} // namespace Log
