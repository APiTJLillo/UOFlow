#include "Core/ActionTrace.hpp"
#include <cstring>

namespace Trace {

namespace {
    CRITICAL_SECTION g_cs;
    bool g_csInit = false;
    LastAction g_last{};
    uint32_t g_windowMs = 300; // default correlation window

    void EnsureInit() {
        if (!g_csInit) {
            InitializeCriticalSection(&g_cs);
            g_csInit = true;
        }
    }
}

void MarkAction(const char* name) {
    if (!name || !name[0]) return;
    EnsureInit();
    EnterCriticalSection(&g_cs);
    g_last.tick = GetTickCount();
    g_last.tid = GetCurrentThreadId();
    std::strncpy(g_last.name, name, sizeof(g_last.name) - 1);
    g_last.name[sizeof(g_last.name) - 1] = '\0';
    LeaveCriticalSection(&g_cs);
}

bool GetLastAction(LastAction& out) {
    EnsureInit();
    EnterCriticalSection(&g_cs);
    out = g_last;
    LeaveCriticalSection(&g_cs);
    return out.name[0] != '\0' && out.tick != 0;
}

void SetWindowMs(uint32_t ms) {
    g_windowMs = ms;
}

uint32_t GetWindowMs() {
    return g_windowMs;
}

} // namespace Trace

