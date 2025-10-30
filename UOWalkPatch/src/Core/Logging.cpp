#include "Core/Logging.hpp"
#include "Core/Config.hpp"

#include <psapi.h>
#include <cstdio>
#include <cstdarg>
#include <cctype>
#include <vector>
#include <string>
#include <cstring>
#include <atomic>
#include <algorithm>

namespace Log {
namespace {

HANDLE g_logFile = INVALID_HANDLE_VALUE;
char   g_logPath[MAX_PATH] = {};
BOOL   g_logAnnounced = FALSE;
HMODULE g_hModule = NULL;
std::atomic<int> g_minLevel{static_cast<int>(Level::Info)};

const char* LevelToString(Level level) {
    switch (level) {
        case Level::Trace: return "TRACE";
        case Level::Debug: return "DEBUG";
        case Level::Info:  return "INFO";
        case Level::Warn:  return "WARN";
        case Level::Error: return "ERROR";
        default:           return "INFO";
    }
}

const char* CategoryToString(Category category) {
    switch (category) {
        case Category::Core:     return "CORE";
        case Category::LuaGuard: return "LUAGUARD";
        case Category::FastWalk: return "FW";
        case Category::Movement: return "MOVE";
        case Category::Walk:     return "WALK";
        case Category::Hooks:    return "HOOKS";
        case Category::Memory:   return "MEM";
        default:                 return "CORE";
    }
}

std::string Trim(const std::string& text) {
    size_t begin = 0;
    size_t end = text.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(text[begin])))
        ++begin;
    while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1])))
        --end;
    return text.substr(begin, end - begin);
}

bool IsAbsolutePath(const std::string& path) {
    if (path.empty())
        return false;
    if (path.size() >= 2 && path[1] == ':')
        return true;
    if (path.size() >= 2 && path[0] == '\\' && path[1] == '\\')
        return true;
    if (path[0] == '\\' || path[0] == '/')
        return true;
    return false;
}

std::string JoinPath(const std::string& baseDir, const std::string& relative) {
    if (baseDir.empty())
        return relative;
    if (baseDir.back() == '\\' || baseDir.back() == '/')
        return baseDir + relative;
    return baseDir + "\\" + relative;
}

Level ParseLevelString(const std::string& raw, Level fallback) {
    if (raw.empty())
        return fallback;
    std::string value = Trim(raw);
    if (value.rfind("--log-level=", 0) == 0)
        value = value.substr(12);
    std::string lowered;
    lowered.reserve(value.size());
    for (char ch : value)
        lowered.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    if (lowered == "trace")
        return Level::Trace;
    if (lowered == "debug")
        return Level::Debug;
    if (lowered == "warn" || lowered == "warning")
        return Level::Warn;
    if (lowered == "error" || lowered == "err")
        return Level::Error;
    if (lowered == "info" || lowered == "information")
        return Level::Info;
    return fallback;
}

bool OpenLogFileInternal(const std::string& path) {
    if (path.empty())
        return false;

    HANDLE file = CreateFileA(
        path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (file == INVALID_HANDLE_VALUE)
        return false;

    g_logFile = file;
    strncpy_s(g_logPath, path.c_str(), MAX_PATH - 1);
    g_logAnnounced = FALSE;
    return true;
}

void ConfigureLogging(HMODULE self) {
    char modulePath[MAX_PATH] = "";
    std::string baseDir;
    DWORD len = GetModuleFileNameA(self, modulePath, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        baseDir.assign(modulePath, modulePath + len);
        size_t slash = baseDir.find_last_of("\\/");
        if (slash != std::string::npos)
            baseDir.resize(slash + 1);
        else
            baseDir.clear();
    }

    Level level = Level::Info;
    if (auto envLevel = Core::Config::TryGetEnv("UOWALK_LOG_LEVEL"))
        level = ParseLevelString(*envLevel, level);
    else if (auto cfgLevel = Core::Config::TryGetValue("LOG_LEVEL"))
        level = ParseLevelString(*cfgLevel, level);
    SetMinLevel(level);

    std::string requestedPath;
    if (auto envPath = Core::Config::TryGetEnv("UOWALK_LOG_FILE"))
        requestedPath = Trim(*envPath);
    else if (auto cfgPath = Core::Config::TryGetValue("LOG_FILE"))
        requestedPath = Trim(*cfgPath);

    std::string defaultPath = baseDir.empty()
        ? std::string("uowalkpatch_debug.log")
        : JoinPath(baseDir, "uowalkpatch_debug.log");

    std::string resolvedPath;
    if (!requestedPath.empty()) {
        if (IsAbsolutePath(requestedPath))
            resolvedPath = requestedPath;
        else
            resolvedPath = JoinPath(baseDir, requestedPath);
    } else {
        resolvedPath = defaultPath;
    }

    if (!OpenLogFileInternal(resolvedPath) && resolvedPath != defaultPath)
        OpenLogFileInternal(defaultPath);

    if (g_logFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(g_logFile, 0, nullptr, FILE_END);
    }
}

void SetupConsole() {
    if (!GetConsoleWindow()) {
        if (AllocConsole()) {
            FILE* dummy;
            freopen_s(&dummy, "CONOUT$", "w", stdout);
            freopen_s(&dummy, "CONOUT$", "w", stderr);
            SetConsoleTitleA("UOWalkPatch console");
        }
    }
}

bool ShouldWrite(Level level) {
    return static_cast<int>(level) >= g_minLevel.load(std::memory_order_acquire);
}

} // namespace

void Init(HMODULE self) {
    g_hModule = self;
    g_logFile = INVALID_HANDLE_VALUE;
    g_logPath[0] = '\0';
    g_logAnnounced = FALSE;
    ConfigureLogging(self);
    SetupConsole();
    LogMessage(Level::Info, Category::Core, "logging initialized");
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
    if (!message)
        return;

    OutputDebugStringA(message);
    OutputDebugStringA("\n");

    if (GetConsoleWindow()) {
        printf("[%lu] %s\n", GetCurrentThreadId(), message);
        fflush(stdout);
    }

    if (g_logFile == INVALID_HANDLE_VALUE && g_logPath[0] != '\0')
        OpenLogFileInternal(g_logPath);

    if (g_logFile != INVALID_HANDLE_VALUE) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buffer[4096];
        int len = sprintf_s(buffer, sizeof(buffer),
            "[%02d:%02d:%02d.%03d] [%lu] %s\r\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            GetCurrentThreadId(),
            message);
        if (len > 0) {
            DWORD written;
            if (!WriteFile(g_logFile, buffer, len, &written, NULL)) {
                LogLastError("WriteFile to log");
            } else {
                FlushFileBuffers(g_logFile);
                if (!g_logAnnounced) {
                    g_logAnnounced = TRUE;
                    char announce[MAX_PATH + 64] = {};
                    sprintf_s(announce, sizeof(announce), "Log file: %s", g_logPath);
                    OutputDebugStringA(announce);
                    OutputDebugStringA("\n");
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
    for (char* p = errorMsg; *p; ++p) {
        if (*p == '\r' || *p == '\n') *p = ' ';
    }
    sprintf_s(buffer, sizeof(buffer), "%s failed with 0x%08X: %s", prefix, error, errorMsg);
    WriteRawLog(buffer);
}

void LogLoadedModules() {
    LogMessage(Level::Info, Category::Core, "Enumerating loaded modules");
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hMods[1024];
    DWORD needed;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &needed)) {
        for (DWORD i = 0; i < (needed / sizeof(HMODULE)); i++) {
            char path[MAX_PATH] = "";
            char buffer[MAX_PATH + 96] = "";
            if (GetModuleFileNameExA(hProcess, hMods[i], path, MAX_PATH)) {
                MODULEINFO mi = { 0 };
                if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
                    sprintf_s(buffer, sizeof(buffer), "module %p - %p: %s",
                              mi.lpBaseOfDll,
                              static_cast<const void*>(static_cast<const unsigned char*>(mi.lpBaseOfDll) + mi.SizeOfImage),
                              path);
                } else {
                    sprintf_s(buffer, sizeof(buffer), "module %p: %s", hMods[i], path);
                }
                WriteRawLog(buffer);
            }
        }
    } else {
        LogLastError("EnumProcessModules");
    }
}

void SetMinLevel(Level level) {
    g_minLevel.store(static_cast<int>(level), std::memory_order_release);
}

Level GetMinLevel() {
    return static_cast<Level>(g_minLevel.load(std::memory_order_acquire));
}

bool IsEnabled(Level level) {
    return ShouldWrite(level);
}

bool IsEnabled(Category, Level level) {
    return ShouldWrite(level);
}

void LogMessage(Level level, Category category, const char* message) {
    if (!message || !ShouldWrite(level))
        return;
    std::string formatted;
    formatted.reserve(strlen(message) + 32);
    formatted.append("[");
    formatted.append(LevelToString(level));
    formatted.append("][");
    formatted.append(CategoryToString(category));
    formatted.append("] ");
    formatted.append(message);
    WriteRawLog(formatted.c_str());
}

void LogMessage(Level level, const char* message) {
    LogMessage(level, Category::Core, message);
}

void Logf(Level level, Category category, const char* fmt, ...) {
    if (!fmt || !ShouldWrite(level))
        return;

    va_list args;
    va_start(args, fmt);
    int needed = _vscprintf(fmt, args);
    va_end(args);
    if (needed < 0)
        return;

    std::vector<char> buffer(static_cast<size_t>(needed) + 1, '\0');
    va_start(args, fmt);
    int written = vsnprintf_s(buffer.data(), buffer.size(), _TRUNCATE, fmt, args);
    va_end(args);
    if (written < 0)
        buffer.back() = '\0';

    LogMessage(level, category, buffer.data());
}

void Logf(Level level, const char* fmt, ...) {
    if (!fmt || !ShouldWrite(level))
        return;
    va_list args;
    va_start(args, fmt);
    int needed = _vscprintf(fmt, args);
    va_end(args);
    if (needed < 0)
        return;

    std::vector<char> buffer(static_cast<size_t>(needed) + 1, '\0');
    va_start(args, fmt);
    int written = vsnprintf_s(buffer.data(), buffer.size(), _TRUNCATE, fmt, args);
    va_end(args);
    if (written < 0)
        buffer.back() = '\0';

    LogMessage(level, Category::Core, buffer.data());
}

void Logf(Category category, const char* fmt, ...) {
    if (!fmt || !ShouldWrite(Level::Info))
        return;
    va_list args;
    va_start(args, fmt);
    int needed = _vscprintf(fmt, args);
    va_end(args);
    if (needed < 0)
        return;

    std::vector<char> buffer(static_cast<size_t>(needed) + 1, '\0');
    va_start(args, fmt);
    int written = vsnprintf_s(buffer.data(), buffer.size(), _TRUNCATE, fmt, args);
    va_end(args);
    if (written < 0)
        buffer.back() = '\0';

    LogMessage(Level::Info, category, buffer.data());
}

void Logf(const char* fmt, ...) {
    if (!fmt || !ShouldWrite(Level::Info))
        return;
    va_list args;
    va_start(args, fmt);
    int needed = _vscprintf(fmt, args);
    va_end(args);
    if (needed < 0)
        return;

    std::vector<char> buffer(static_cast<size_t>(needed) + 1, '\0');
    va_start(args, fmt);
    int written = vsnprintf_s(buffer.data(), buffer.size(), _TRUNCATE, fmt, args);
    va_end(args);
    if (written < 0)
        buffer.back() = '\0';

    LogMessage(Level::Info, Category::Core, buffer.data());
}

} // namespace Log
