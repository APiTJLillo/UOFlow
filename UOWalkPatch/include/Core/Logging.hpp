#pragma once
#include <windows.h>

namespace Log {
    enum class Level : int {
        Trace = 0,
        Debug = 1,
        Info  = 2,
        Warn  = 3,
        Error = 4
    };

    enum class Category : int {
        Core = 0,
        LuaGuard,
        FastWalk,
        Movement,
        Walk,
        Hooks,
        Memory
    };

    void Init(HMODULE self);
    void Shutdown();
    void WriteRawLog(const char* message);
    void LogLastError(const char* prefix);
    void LogLoadedModules();

    void SetMinLevel(Level level);
    Level GetMinLevel();
    bool IsEnabled(Level level);
    bool IsEnabled(Category category, Level level);

    void Logf(Level level, Category category, const char* fmt, ...);
    void Logf(Level level, const char* fmt, ...);
    void Logf(Category category, const char* fmt, ...);
    void Logf(const char* fmt, ...);

    void LogMessage(Level level, Category category, const char* message);
    void LogMessage(Level level, const char* message);
}

using Log::WriteRawLog;
using Log::LogLastError;
using Log::LogLoadedModules;
using Log::Logf;
