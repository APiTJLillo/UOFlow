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
    char   g_dllDirectory[MAX_PATH];
}

static bool BuildPath(char* outPath,
                      size_t outPathSize,
                      const char* directory,
                      const char* fileName) {
    if (!outPath || outPathSize == 0 || !directory || !*directory || !fileName || !*fileName) {
        return false;
    }

    return sprintf_s(outPath, outPathSize, "%s\\%s", directory, fileName) > 0;
}

static bool ResetFileToEmpty(const char* fullPath, const char* tag) {
    if (!fullPath || !*fullPath) {
        return false;
    }

    HANDLE hFile = CreateFileA(
        fullPath,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        char errBuf[MAX_PATH + 96];
        sprintf_s(errBuf,
                  sizeof(errBuf),
                  "[Init] failed to reset %s: %s",
                  tag ? tag : "file",
                  fullPath);
        WriteRawLog(errBuf);
        LogLastError("CreateFileA(reset file)");
        return false;
    }

    CloseHandle(hFile);

    char msg[MAX_PATH + 96];
    sprintf_s(msg,
              sizeof(msg),
              "[Init] reset %s: %s",
              tag ? tag : "file",
              fullPath);
    WriteRawLog(msg);
    return true;
}

static void LinkClientTextLogToDllFile(const char* logsDir,
                                       const char* clientFileName,
                                       const char* dllFileName,
                                       const char* linkTag) {
    if (!logsDir || !*logsDir || !clientFileName || !*clientFileName ||
        !dllFileName || !*dllFileName || !g_dllDirectory[0]) {
        return;
    }

    char dllTargetPath[MAX_PATH] = {};
    char clientLinkPath[MAX_PATH] = {};
    if (!BuildPath(dllTargetPath, sizeof(dllTargetPath), g_dllDirectory, dllFileName) ||
        !BuildPath(clientLinkPath, sizeof(clientLinkPath), logsDir, clientFileName)) {
        return;
    }

    if (!ResetFileToEmpty(dllTargetPath, linkTag)) {
        return;
    }

    DWORD attrs = GetFileAttributesA(clientLinkPath);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        if (!DeleteFileA(clientLinkPath)) {
            char errBuf[MAX_PATH + 96];
            sprintf_s(errBuf,
                      sizeof(errBuf),
                      "[Init] failed to remove existing client text log alias: %s",
                      clientLinkPath);
            WriteRawLog(errBuf);
            LogLastError("DeleteFileA(client text log alias)");
            return;
        }
    }

    if (!CreateHardLinkA(clientLinkPath, dllTargetPath, NULL)) {
        char errBuf[MAX_PATH + 96];
        sprintf_s(errBuf,
                  sizeof(errBuf),
                  "[Init] failed to link client text log to DLL directory: %s -> %s",
                  clientLinkPath,
                  dllTargetPath);
        WriteRawLog(errBuf);
        LogLastError("CreateHardLinkA(client text log)");

        // Fall back to the original client-local file if hard links are unavailable.
        ResetFileToEmpty(clientLinkPath, linkTag);
        return;
    }

    char msg[MAX_PATH + 96];
    sprintf_s(msg,
              sizeof(msg),
              "[Init] linked client text log: %s -> %s",
              clientLinkPath,
              dllTargetPath);
    WriteRawLog(msg);
}

static void PrepareClientTextLogsInDllDirectory() {
    char exePath[MAX_PATH] = {};
    DWORD len = GetModuleFileNameA(NULL, exePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        WriteRawLog("[Init] unable to resolve client executable path for text logs");
        return;
    }

    char* lastSlash = strrchr(exePath, '\\');
    if (!lastSlash) {
        WriteRawLog("[Init] unable to resolve client log directory");
        return;
    }
    *lastSlash = '\0';

    char logsDir[MAX_PATH] = {};
    if (sprintf_s(logsDir, sizeof(logsDir), "%s\\logs", exePath) <= 0) {
        WriteRawLog("[Init] unable to build client log directory path");
        return;
    }

    if (!CreateDirectoryA(logsDir, NULL)) {
        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) {
            char errBuf[MAX_PATH + 96];
            sprintf_s(errBuf,
                      sizeof(errBuf),
                      "[Init] failed to create client log directory: %s",
                      logsDir);
            WriteRawLog(errBuf);
            SetLastError(error);
            LogLastError("CreateDirectoryA(client logs)");
            return;
        }
    }

    LinkClientTextLogToDllFile(logsDir, "ingame_console.log", "ingame_console.log", "client ui log");
    LinkClientTextLogToDllFile(logsDir, "Debug.Print.log", "Debug.Print.log", "client debug print log");
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
    g_dllDirectory[0] = '\0';
    g_logAnnounced = FALSE;

    char dllPath[MAX_PATH] = {};
    DWORD len = GetModuleFileNameA(self, dllPath, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        char* lastSlash = strrchr(dllPath, '\\');
        if (lastSlash && lastSlash + 1 < dllPath + MAX_PATH) {
            *lastSlash = '\0';
            strcpy_s(g_dllDirectory, MAX_PATH, dllPath);
            *lastSlash = '\\';
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
    PrepareClientTextLogsInDllDirectory();
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
