#include "Core/Logging.hpp"
#include "Core/Config.hpp"
#include "Core/EarlyTrace.hpp"

#include <psapi.h>
#include <cstdio>
#include <cstdarg>
#include <cctype>
#include <vector>
#include <string>
#include <cstring>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <algorithm>
#include <cstdlib>
#include <exception>
#include <typeinfo>
#include <corecrt_startup.h>
#include <crtdbg.h>

#ifndef STATUS_STACK_BUFFER_OVERRUN
#define STATUS_STACK_BUFFER_OVERRUN static_cast<DWORD>(0xC0000409u)
#endif
#ifndef STATUS_FAIL_FAST_EXCEPTION
#define STATUS_FAIL_FAST_EXCEPTION static_cast<DWORD>(0xC0000602u)
#endif

namespace Log {
namespace {

HANDLE g_logFile = INVALID_HANDLE_VALUE;
char   g_logPath[MAX_PATH] = {};
BOOL   g_logAnnounced = FALSE;
std::atomic<std::uint32_t> g_categoryMask{0xFFFFFFFFu};
HMODULE g_hModule = NULL;
std::atomic<int> g_minLevel{static_cast<int>(Level::Info)};
PVOID g_securityHandlerHandle = nullptr;
std::terminate_handler g_prevTerminate = nullptr;

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
    Core::EarlyTrace::Write("ConfigureLogging begin");
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
    Core::EarlyTrace::Write("ConfigureLogging after path resolve");
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
    Core::EarlyTrace::Write("ConfigureLogging end");
}

void SetupConsole() {
    if (!GetConsoleWindow()) {
        if (AllocConsole()) {
            SetConsoleTitleA("UOWalkPatch console");
        }
    }
}

void __cdecl LogInvalidParameterHandler(const wchar_t* expression,
                                        const wchar_t* function,
                                        const wchar_t* file,
                                        unsigned int line,
                                        uintptr_t) {
    char buffer[512];
    const wchar_t* expr = expression ? expression : L"(null)";
    const wchar_t* func = function ? function : L"(null)";
    const wchar_t* filename = file ? file : L"(null)";
    int written = _snprintf_s(buffer,
                              sizeof(buffer),
                              _TRUNCATE,
                              "[CRT][invalid_parameter] expr=%S function=%S file=%S line=%u",
                              expr,
                              func,
                              filename,
                              line);
    if (written > 0)
        WriteRawLog(buffer);
}

LONG CALLBACK VectoredSecurityHandler(PEXCEPTION_POINTERS info) {
    if (!info || !info->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    const DWORD code = info->ExceptionRecord->ExceptionCode;
    if (code != STATUS_STACK_BUFFER_OVERRUN && code != STATUS_FAIL_FAST_EXCEPTION)
        return EXCEPTION_CONTINUE_SEARCH;

    char header[160];
    sprintf_s(header,
              sizeof(header),
              "[CRT][security_exception] code=0x%08lX flags=0x%08lX addr=%p thread=%lu",
              static_cast<unsigned long>(code),
              static_cast<unsigned long>(info->ExceptionRecord->ExceptionFlags),
              info->ExceptionRecord->ExceptionAddress,
              GetCurrentThreadId());
    WriteRawLog(header);

    ULONG_PTR paramCount = info->ExceptionRecord->NumberParameters;
    if (paramCount > 0) {
        char details[256];
        ULONG_PTR first = paramCount > 0 ? info->ExceptionRecord->ExceptionInformation[0] : 0;
        ULONG_PTR second = paramCount > 1 ? info->ExceptionRecord->ExceptionInformation[1] : 0;
        sprintf_s(details,
                  sizeof(details),
                  "  params={0x%p, 0x%p} count=%lu",
                  reinterpret_cast<void*>(first),
                  reinterpret_cast<void*>(second),
                  static_cast<unsigned long>(paramCount));
        WriteRawLog(details);
    }

    void* frames[32] = {};
    USHORT captured = CaptureStackBackTrace(0, static_cast<USHORT>(_countof(frames)), frames, nullptr);
    for (USHORT i = 0; i < captured; ++i) {
        char lineBuf[96];
        sprintf_s(lineBuf, sizeof(lineBuf), "  frame[%02u]=%p", i, frames[i]);
        WriteRawLog(lineBuf);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

void LogCurrentException(const char* context) {
    if (!context)
        context = "[CRT]";
    auto ex = std::current_exception();
    if (!ex) {
        char msg[192];
        sprintf_s(msg, sizeof(msg), "%s: terminate invoked without active exception", context);
        WriteRawLog(msg);
        return;
    }
    try {
        std::rethrow_exception(ex);
    } catch (const std::exception& e) {
        const char* typeName = typeid(e).name();
        const char* whatText = e.what() ? e.what() : "";
        char msg[320];
        sprintf_s(msg,
                  sizeof(msg),
                  "%s: uncaught std::exception type=%s what=\"%s\"",
                  context,
                  typeName ? typeName : "<unknown>",
                  whatText);
        WriteRawLog(msg);
    } catch (...) {
        char msg[192];
        sprintf_s(msg, sizeof(msg), "%s: uncaught non-std exception", context);
        WriteRawLog(msg);
    }
}

[[noreturn]] void TerminateHandler() {
    LogCurrentException("[CRT][terminate]");
    auto prev = g_prevTerminate;
    g_prevTerminate = nullptr;
    if (prev) {
        prev();
    } else {
        abort();
    }
    abort(); // Fallback; should not reach.
}

bool ShouldWrite(Level level) {
    return static_cast<int>(level) >= g_minLevel.load(std::memory_order_acquire);
}

} // namespace

void Init(HMODULE self) {
    Core::EarlyTrace::Write("Log::Init start");
    g_hModule = self;
    g_logFile = INVALID_HANDLE_VALUE;
    g_logPath[0] = '\0';
    g_logAnnounced = FALSE;
    Core::EarlyTrace::Write("Log::Init before ConfigureLogging");
    ConfigureLogging(self);
    Core::EarlyTrace::Write("Log::Init after ConfigureLogging");
    SetupConsole();
    Core::EarlyTrace::Write("Log::Init after SetupConsole");
    _set_invalid_parameter_handler(LogInvalidParameterHandler);
    _set_thread_local_invalid_parameter_handler(LogInvalidParameterHandler);
    g_prevTerminate = std::set_terminate(TerminateHandler);

    if (!g_securityHandlerHandle)
        g_securityHandlerHandle = AddVectoredExceptionHandler(1, VectoredSecurityHandler);
    LogMessage(Level::Info, Category::Core, "logging initialized");
}

void Shutdown() {
    if (g_prevTerminate) {
        std::set_terminate(g_prevTerminate);
        g_prevTerminate = nullptr;
    }
    if (g_securityHandlerHandle) {
        RemoveVectoredExceptionHandler(g_securityHandlerHandle);
        g_securityHandlerHandle = nullptr;
    }
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
        HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
        if (console && console != INVALID_HANDLE_VALUE) {
            char consoleBuffer[4096];
            int len = sprintf_s(consoleBuffer, sizeof(consoleBuffer),
                                "[%lu] %s\r\n",
                                GetCurrentThreadId(),
                                message);
            if (len > 0) {
                DWORD written = 0;
                WriteConsoleA(console, consoleBuffer, static_cast<DWORD>(len), &written, nullptr);
            }
        }
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

bool IsEnabled(Category category, Level level) {
    if (!ShouldWrite(level))
        return false;
    const auto mask = g_categoryMask.load(std::memory_order_acquire);
    const auto bit = 1u << static_cast<unsigned>(category);
    return (mask & bit) != 0;
}

void SetCategoryMask(std::uint32_t mask)
{
    g_categoryMask.store(mask, std::memory_order_release);
}

std::uint32_t GetCategoryMask()
{
    return g_categoryMask.load(std::memory_order_acquire);
}

bool ShouldWriteDebounced(const char* key, std::uint32_t intervalMs)
{
    if (!key || !*key)
        return true;
    static std::mutex s_mutex;
    static std::unordered_map<std::string, DWORD> s_lastEmit;
    DWORD now = GetTickCount();
    std::lock_guard<std::mutex> lock(s_mutex);
    DWORD& last = s_lastEmit[key];
    if (last == 0 || now - last >= intervalMs) {
        last = now;
        return true;
    }
    return false;
}

void EnableQuietProfile()
{
    constexpr std::uint32_t mask =
        (1u << static_cast<unsigned>(Category::Core)) |
        (1u << static_cast<unsigned>(Category::Hooks)) |
        (1u << static_cast<unsigned>(Category::Walk));
    SetMinLevel(Level::Info);
    SetCategoryMask(mask);
}

void EnableDevVerbose()
{
    SetMinLevel(Level::Debug);
    SetCategoryMask(0xFFFFFFFFu);
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



