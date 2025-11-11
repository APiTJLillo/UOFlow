#include "TargetCorrelator.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>

#include "Core/Config.hpp"
#include "Core/Logging.hpp"
#include "SpellProbe.h"

namespace {

struct TargetState {
    bool armed = false;
    DWORD startTick = 0;
    uint32_t seq = 0;
    char reason[64];
};

CRITICAL_SECTION g_lock;
bool g_lockInit = false;
TargetState g_state{};
bool g_enabled = false;
DWORD g_windowMs = 400;
uintptr_t g_hint = 0;
bool g_hintAnnounced = false;
uintptr_t g_moduleBase = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));

bool DebugProfileEnabled() {
    if (auto cfg = Core::Config::TryGetBool("UOW_DEBUG_ENABLE"))
        return *cfg;
    if (auto env = Core::Config::TryGetEnvBool("UOW_DEBUG_ENABLE"))
        return *env;
    return false;
}

void EnsureLock() {
    if (!g_lockInit) {
        InitializeCriticalSection(&g_lock);
        g_lockInit = true;
    }
}

DWORD NowMs() {
    return GetTickCount();
}

uintptr_t EnsureModuleBase() {
    if (!g_moduleBase) {
        HMODULE mod = GetModuleHandleA(nullptr);
        g_moduleBase = reinterpret_cast<uintptr_t>(mod);
    }
    return g_moduleBase;
}

uintptr_t FirstClientFrame(const void* const* frames, unsigned short count) {
    if (!frames || count == 0)
        return 0;
    uintptr_t base = EnsureModuleBase();
    if (!base)
        return 0;
    for (unsigned short i = 0; i < count; ++i) {
        auto ptr = reinterpret_cast<uintptr_t>(frames[i]);
        if (!ptr)
            continue;
        HMODULE mod = nullptr;
        if (!GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(frames[i]),
                &mod))
            continue;
        if (reinterpret_cast<uintptr_t>(mod) == base)
            return ptr;
    }
    return 0;
}

void LogHint(uintptr_t frame) {
    uintptr_t base = EnsureModuleBase();
    if (!base || !frame)
        return;
    char buf[192];
    sprintf_s(buf,
              sizeof(buf),
              "[TargetCorrelator] dispatch frame set to UOSA.exe+0x%lX",
              static_cast<unsigned long>(frame - base));
    WriteRawLog(buf);
}

void ArmInternal(const char* reason, bool forceLog) {
    if (!g_enabled)
        return;
    EnsureLock();
    DWORD now = NowMs();
    bool shouldLog = forceLog;
    TargetState snapshot{};
    {
        EnterCriticalSection(&g_lock);
        snapshot = g_state;
        char previous[64];
        strncpy_s(previous, g_state.reason, _TRUNCATE);
        g_state.armed = true;
        g_state.startTick = now;
        if (!snapshot.armed)
            ++g_state.seq;
        if (reason)
            strncpy_s(g_state.reason, reason, _TRUNCATE);
        else
            g_state.reason[0] = '\0';
        bool reasonChanged = false;
        if (reason) {
            reasonChanged = _stricmp(previous, reason) != 0;
        } else {
            reasonChanged = previous[0] != '\0';
        }
        shouldLog = shouldLog || !snapshot.armed || reasonChanged;
        snapshot = g_state;
        LeaveCriticalSection(&g_lock);
    }
    if (shouldLog) {
        char buf[224];
        sprintf_s(buf,
                  sizeof(buf),
                  "[TargetCorrelator] armed seq=%u reason=%s window=%lu ms",
                  snapshot.seq,
                  (reason && reason[0]) ? reason : (snapshot.reason[0] ? snapshot.reason : "unknown"),
                  static_cast<unsigned long>(g_windowMs));
        WriteRawLog(buf);
    }
}

void DisarmInternal(const char* reason, bool logReason) {
    if (!g_lockInit)
        return;
    bool wasArmed = false;
    {
        EnterCriticalSection(&g_lock);
        wasArmed = g_state.armed;
        g_state.armed = false;
        LeaveCriticalSection(&g_lock);
    }
    if (wasArmed && logReason) {
        char buf[192];
        sprintf_s(buf,
                  sizeof(buf),
                  "[TargetCorrelator] disarmed reason=%s",
                  reason ? reason : "unspecified");
        WriteRawLog(buf);
    }
}

bool SnapshotState(TargetState& out) {
    if (!g_lockInit)
        return false;
    EnterCriticalSection(&g_lock);
    out = g_state;
    LeaveCriticalSection(&g_lock);
    return out.armed;
}

void HandleExpiry(const TargetState& snapshot) {
    DWORD now = NowMs();
    if (!snapshot.armed)
        return;
    DWORD age = now - snapshot.startTick;
    if (age > g_windowMs) {
        DisarmInternal("expired", true);
    }
}

} // namespace

namespace TargetCorrelator {

void Init() {
    EnsureLock();
    g_enabled = false;
    g_hintAnnounced = false;
    g_hint = 0;
    g_state = TargetState{};
    if (!DebugProfileEnabled())
        return;

    bool enable = false;
    if (auto cfg = Core::Config::TryGetBool("TARGET_CORR_ENABLE"))
        enable = *cfg;
    else if (auto env = Core::Config::TryGetEnvBool("TARGET_CORR_ENABLE"))
        enable = *env;
    if (!enable)
        return;

    g_windowMs = 400;
    if (auto cfgWindow = Core::Config::TryGetMilliseconds("TARGET_CORR_WINDOW_MS"))
        g_windowMs = std::clamp(*cfgWindow, 50u, 2000u);

    std::optional<std::string> targetAddr;
    if (auto cfg = Core::Config::TryGetValue("TARGET_SENDER_ADDR"))
        targetAddr = *cfg;
    else if (auto env = Core::Config::TryGetEnv("TARGET_SENDER_ADDR"))
        targetAddr = *env;
    if (targetAddr && !targetAddr->empty()) {
        uintptr_t hint = ResolveModulePlusOffset(targetAddr->c_str());
        if (hint) {
            g_hint = hint;
            LogHint(hint);
        } else {
            char warn[192];
            sprintf_s(warn,
                      sizeof(warn),
                      "[TargetCorrelator] TARGET_SENDER_ADDR invalid: %s",
                      targetAddr->c_str());
            WriteRawLog(warn);
        }
    }

    g_enabled = true;
    char buf[160];
    sprintf_s(buf,
              sizeof(buf),
              "[TargetCorrelator] enabled window=%lu ms",
              static_cast<unsigned long>(g_windowMs));
    WriteRawLog(buf);
}

void Shutdown() {
    g_enabled = false;
    DisarmInternal("shutdown", false);
}

bool IsEnabled() {
    return g_enabled;
}

void OnRequestTarget() {
    ArmInternal("RequestTargetInfo", false);
}

void OnCursorShown() {
    ArmInternal("HS_ShowTargetingCursor", true);
}

void OnCursorHidden() {
    DisarmInternal("HS_HideTargetingCursor", true);
}

bool ShouldCaptureStack(unsigned char packetId) {
    if (!g_enabled)
        return false;
    if (packetId != 0x2E)
        return false;
    TargetState snapshot{};
    if (!SnapshotState(snapshot))
        return false;
    DWORD now = NowMs();
    if (now - snapshot.startTick > g_windowMs)
        return false;
    return true;
}

void OnSendEvent(const CastCorrelator::SendEvent& ev) {
    if (!g_enabled)
        return;
    if (ev.packetId != 0x2E)
        return;
    if (ev.frameCount == 0)
        return;

    TargetState snapshot{};
    if (!SnapshotState(snapshot))
        return;

    DWORD now = ev.tick ? ev.tick : NowMs();
    DWORD age = now - snapshot.startTick;
    if (age > g_windowMs) {
        DisarmInternal("expired", true);
        return;
    }

    uintptr_t frame = FirstClientFrame(ev.frames, ev.frameCount);
    if (!frame)
        return;

    if (!g_hint) {
        g_hint = frame;
        LogHint(frame);
    } else if (g_hint != frame) {
        return;
    }

    uintptr_t base = EnsureModuleBase();
    char buf[256];
    sprintf_s(buf,
              sizeof(buf),
              "[TargetCorrelator] send t=+%lu ms id=%02X len=%d top=UOSA.exe+0x%lX -> TARGET COMMIT",
              static_cast<unsigned long>(age),
              ev.packetId,
              ev.length,
              base ? static_cast<unsigned long>(frame - base) : 0ul);
    WriteRawLog(buf);
    g_hintAnnounced = true;
    DisarmInternal("commit", false);
}

} // namespace TargetCorrelator
