#pragma once

#include <windows.h>

namespace Core::CrashHandler {
    void Init(HMODULE self);
    void Shutdown();
}

