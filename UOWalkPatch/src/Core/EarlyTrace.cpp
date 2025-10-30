#include "Core/EarlyTrace.hpp"

#include <windows.h>
#include <cstring>

namespace Core::EarlyTrace {

namespace {

CRITICAL_SECTION g_lock;
bool g_lockInitialized = false;
HMODULE g_module = nullptr;
char g_logPath[MAX_PATH] = {};

void EnsureLockInitialized()
{
    if (!g_lockInitialized) {
        InitializeCriticalSection(&g_lock);
        g_lockInitialized = true;
    }
}

const char* ResolvePath()
{
    if (g_logPath[0] != '\0')
        return g_logPath;
    if (!g_module)
        return nullptr;

    char modulePath[MAX_PATH] = {};
    if (!GetModuleFileNameA(g_module, modulePath, ARRAYSIZE(modulePath)))
        return nullptr;

    char* lastSlash = strrchr(modulePath, '\\');
    if (!lastSlash)
        return nullptr;
    *(lastSlash + 1) = '\0';
    strcpy_s(modulePath + strlen(modulePath), MAX_PATH - strlen(modulePath), "uowalkpatch_boot.log");
    strcpy_s(g_logPath, modulePath);
    return g_logPath;
}

} // namespace

void Initialize(HMODULE module)
{
    g_module = module;
    g_logPath[0] = '\0';
    EnsureLockInitialized();
    const char* path = ResolvePath();
    if (path)
    {
        HANDLE file = CreateFileA(path,
                                  GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  nullptr,
                                  CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL,
                                  nullptr);
        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }
    }
}

void Write(const char* message)
{
    EnsureLockInitialized();
    const char* path = ResolvePath();
    if (!path || !message || message[0] == '\0')
        return;

    EnterCriticalSection(&g_lock);
    HANDLE file = CreateFileA(path,
                              FILE_APPEND_DATA,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr,
                              OPEN_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (file != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        WriteFile(file, message, static_cast<DWORD>(strlen(message)), &written, nullptr);
        WriteFile(file, "\r\n", 2, &written, nullptr);
        CloseHandle(file);
    }
    LeaveCriticalSection(&g_lock);
}

} // namespace Core::EarlyTrace
