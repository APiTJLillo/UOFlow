#pragma once
#include <windows.h>

namespace Log {
    void Init(HMODULE self);
    void Shutdown();
    void WriteRawLog(const char* message);
    void LogLastError(const char* prefix);
    void LogLoadedModules();
    void Logf(const char* fmt, ...);
}

using Log::WriteRawLog;
using Log::LogLastError;
using Log::LogLoadedModules;
using Log::Logf;
