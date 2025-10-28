#include "Core/CrashHandler.hpp"
#include "Core/Logging.hpp"

#include <dbghelp.h>
#include <cstdio>
#include <cstring>

namespace Core::CrashHandler {
namespace {
    LPTOP_LEVEL_EXCEPTION_FILTER g_prevFilter = nullptr;
    HMODULE g_module = nullptr;
    char g_dumpPath[MAX_PATH] = {};
    bool g_pathReady = false;

    void BuildDumpPath()
    {
        g_pathReady = false;
        if (!g_module)
            return;

        char modulePath[MAX_PATH] = {};
        if (!GetModuleFileNameA(g_module, modulePath, MAX_PATH))
            return;

        char* lastSlash = strrchr(modulePath, '\\');
        if (!lastSlash)
            return;

        size_t dirLen = static_cast<size_t>(lastSlash - modulePath + 1);
        if (dirLen >= MAX_PATH)
            return;

        memcpy(g_dumpPath, modulePath, dirLen);
        g_dumpPath[dirLen] = '\0';

        SYSTEMTIME st{};
        GetLocalTime(&st);
        char fileName[80] = {};
        sprintf_s(fileName, sizeof(fileName),
                  "uowalkpatch_crash_%04u%02u%02u_%02u%02u%02u.dmp",
                  st.wYear,
                  st.wMonth,
                  st.wDay,
                  st.wHour,
                  st.wMinute,
                  st.wSecond);

        if (strlen(g_dumpPath) + strlen(fileName) + 1 >= MAX_PATH)
            return;

        strcat_s(g_dumpPath, MAX_PATH, fileName);
        g_pathReady = true;
    }

    LONG WINAPI HandleUnhandledException(EXCEPTION_POINTERS* info)
    {
        const EXCEPTION_RECORD* record = info ? info->ExceptionRecord : nullptr;
        char buf[256];
        if (record) {
            sprintf_s(buf,
                      sizeof(buf),
                      "Unhandled exception code=0x%08lX flags=0x%08lX addr=%p",
                      record->ExceptionCode,
                      record->ExceptionFlags,
                      record->ExceptionAddress);
        } else {
            strcpy_s(buf, sizeof(buf), "Unhandled exception (no record)");
        }
        WriteRawLog(buf);

        if (g_pathReady) {
            HANDLE file = CreateFileA(
                g_dumpPath,
                GENERIC_WRITE,
                FILE_SHARE_READ,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (file != INVALID_HANDLE_VALUE) {
                MINIDUMP_EXCEPTION_INFORMATION dumpInfo{};
                dumpInfo.ThreadId = GetCurrentThreadId();
                dumpInfo.ExceptionPointers = info;
                dumpInfo.ClientPointers = FALSE;

                BOOL wrote = MiniDumpWriteDump(
                    GetCurrentProcess(),
                    GetCurrentProcessId(),
                    file,
                    MiniDumpWithFullMemory,
                    info ? &dumpInfo : nullptr,
                    nullptr,
                    nullptr);

                CloseHandle(file);

                if (wrote) {
                    char dumpMsg[256];
                    sprintf_s(dumpMsg,
                              sizeof(dumpMsg),
                              "Wrote crash dump to %s",
                              g_dumpPath);
                    WriteRawLog(dumpMsg);
                } else {
                    LogLastError("MiniDumpWriteDump");
                }
            } else {
                LogLastError("CreateFile crash dump");
            }
        } else {
            WriteRawLog("Crash dump path was not initialized; skipping dump");
        }

        if (g_prevFilter)
            return g_prevFilter(info);
        return EXCEPTION_EXECUTE_HANDLER;
    }
}

void Init(HMODULE self)
{
    g_module = self;
    BuildDumpPath();
    g_prevFilter = SetUnhandledExceptionFilter(&HandleUnhandledException);
}

void Shutdown()
{
    SetUnhandledExceptionFilter(g_prevFilter);
    g_prevFilter = nullptr;
    g_module = nullptr;
    g_dumpPath[0] = '\0';
    g_pathReady = false;
}

} // namespace Core::CrashHandler
