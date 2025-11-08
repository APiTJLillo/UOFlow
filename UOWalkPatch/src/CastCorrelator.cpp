#include "CastCorrelator.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <optional>

#include "Core/Config.hpp"
#include "Core/Logging.hpp"
#include "SpellProbe.h"
#include "SpellSenderDetour.h"

namespace {

struct CastWindow {
    bool active = false;
    DWORD startTick = 0;
    uint32_t spellId = 0;
};

constexpr size_t kMaxWindows = 2;

CastWindow g_windows[kMaxWindows]{};
CRITICAL_SECTION g_lock;
bool g_lockInit = false;

bool g_enabled = false;
DWORD g_windowMs = 400;
int g_lenHint = 9;
std::atomic<LONG> g_activeWindows{0};
std::atomic<uintptr_t> g_targetFrame{0};
bool g_announcedTarget = false;
uintptr_t g_moduleBase = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
SpellSenderOptions g_senderOpts{};
bool g_senderDetourEnabled = true;

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

void CloseWindowLocked(CastWindow& win) {
    if (win.active) {
        win.active = false;
        g_activeWindows.fetch_sub(1, std::memory_order_acq_rel);
    }
}

void CleanupExpiredLocked(DWORD now) {
    for (size_t i = 0; i < kMaxWindows; ++i) {
        auto& win = g_windows[i];
        if (win.active && (now - win.startTick) > g_windowMs) {
            CloseWindowLocked(win);
        }
    }
}

uintptr_t FirstClientFrame(const void* const* frames, unsigned short count) {
    if (!frames || count == 0 || !g_moduleBase)
        return 0;
    for (unsigned short i = 0; i < count; ++i) {
        auto ptr = reinterpret_cast<uintptr_t>(frames[i]);
        if (!ptr)
            continue;
        HMODULE mod = nullptr;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCSTR>(frames[i]), &mod))
            continue;
        if (reinterpret_cast<uintptr_t>(mod) == g_moduleBase)
            return ptr;
    }
    return 0;
}

size_t CollectClientFrames(const void* const* frames, unsigned short count, uintptr_t* out, size_t maxOut) {
    size_t collected = 0;
    if (!frames || !g_moduleBase)
        return 0;
    for (unsigned short i = 0; i < count && collected < maxOut; ++i) {
        if (!frames[i])
            continue;
        HMODULE mod = nullptr;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCSTR>(frames[i]), &mod))
            continue;
        if (reinterpret_cast<uintptr_t>(mod) == g_moduleBase)
            out[collected++] = reinterpret_cast<uintptr_t>(frames[i]);
    }
    return collected;
}

void LogCandidateStack(const void* const* frames, unsigned short count) {
    uintptr_t list[5]{};
    size_t n = CollectClientFrames(frames, count, list, ARRAYSIZE(list));
    if (n == 0)
        return;
    char buf[512];
    size_t offset = sprintf_s(buf, sizeof(buf), "[CastCorrelator] stack:");
    for (size_t i = 0; i < n && offset + 32 < sizeof(buf); ++i) {
        offset += sprintf_s(buf + offset,
                            sizeof(buf) - offset,
                            " #%zu UOSA.exe+0x%lX",
                            i,
                            static_cast<unsigned long>(list[i] - g_moduleBase));
    }
    WriteRawLog(buf);
}

void LogWindowOpen(uint32_t spellId, DWORD startTick) {
    char buf[160];
    sprintf_s(buf,
              sizeof(buf),
              "[CastCorrelator] open window spell=%u t0=%lu window=%lu ms",
              spellId,
              static_cast<unsigned long>(startTick),
              static_cast<unsigned long>(g_windowMs));
    WriteRawLog(buf);
}

void LogTargetFrame(uintptr_t frame) {
    if (!frame || !g_moduleBase)
        return;
    char buf[160];
    sprintf_s(buf,
              sizeof(buf),
              "[CastCorrelator] target sender frame set to UOSA.exe+0x%lX",
              static_cast<unsigned long>(frame - g_moduleBase));
    WriteRawLog(buf);
}

} // namespace

namespace CastCorrelator {

void Init() {
    EnsureLock();
    if (!DebugProfileEnabled()) {
        g_enabled = false;
        return;
    }

    bool enable = false;
    if (auto cfg = Core::Config::TryGetBool("CAST_CORR_ENABLE"))
        enable = *cfg;
    if (!enable) {
        g_enabled = false;
        return;
    }

    g_windowMs = 400;
    if (auto cfgWindow = Core::Config::TryGetMilliseconds("CAST_CORR_WINDOW_MS"))
        g_windowMs = *cfgWindow ? *cfgWindow : g_windowMs;
    if (g_windowMs < 100)
        g_windowMs = 100;
    if (g_windowMs > 2000)
        g_windowMs = 2000;

    g_lenHint = 9;
    if (auto cfgLen = Core::Config::TryGetInt("CAST_CORR_LEN_HINT"))
        g_lenHint = *cfgLen;
    if (g_lenHint < 0)
        g_lenHint = 0;

    g_senderOpts = SpellSenderOptions{};
    if (auto cfg = Core::Config::TryGetBool("CAST_SENDER_DETOUR_ENABLE"))
        g_senderOpts.enable = *cfg;
    if (auto cfgCtx = Core::Config::TryGetBool("CAST_SENDER_LOG_CTX"))
        g_senderOpts.logCtx = *cfgCtx;
    if (auto cfgDump = Core::Config::TryGetInt("CAST_SENDER_DUMP_BYTES"))
        g_senderOpts.dumpBytes = *cfgDump;
    if (auto cfgHits = Core::Config::TryGetInt("CAST_SENDER_MAX_HITS"))
        g_senderOpts.maxHits = *cfgHits;
    if (auto cfgDebounce = Core::Config::TryGetInt("CAST_SENDER_DEBOUNCE_MS"))
        g_senderOpts.debounceMs = *cfgDebounce;
    g_senderOpts.dumpBytes = std::clamp(g_senderOpts.dumpBytes, 0, 64);
    if (g_senderOpts.maxHits < 0)
        g_senderOpts.maxHits = 0;
    if (g_senderOpts.debounceMs < 0)
        g_senderOpts.debounceMs = 0;
    SpellSenderDetour_Configure(g_senderOpts);
    g_senderDetourEnabled = g_senderOpts.enable;

    if (g_senderOpts.enable) {
        std::optional<std::string> senderAddr;
        if (auto cfgAddr = Core::Config::TryGetValue("CAST_SENDER_ADDR"))
            senderAddr = *cfgAddr;
        else if (auto envAddr = Core::Config::TryGetEnv("CAST_SENDER_ADDR"))
            senderAddr = *envAddr;
        if (senderAddr && !senderAddr->empty()) {
            uintptr_t manual = ResolveModulePlusOffset(senderAddr->c_str());
            if (manual)
                SpellSenderDetour_EnsureArmed(manual);
            else {
                char warn[192];
                sprintf_s(warn,
                          sizeof(warn),
                          "[CastCorrelator] CAST_SENDER_ADDR invalid: %s",
                          senderAddr->c_str());
                WriteRawLog(warn);
            }
        }
    }

    std::optional<std::string> targetAddr;
    if (auto cfgTarget = Core::Config::TryGetValue("TARGET_SENDER_ADDR"))
        targetAddr = *cfgTarget;
    else if (auto envTarget = Core::Config::TryGetEnv("TARGET_SENDER_ADDR"))
        targetAddr = *envTarget;
    if (targetAddr && !targetAddr->empty()) {
        uintptr_t resolvedTarget = ResolveModulePlusOffset(targetAddr->c_str());
        if (resolvedTarget) {
            g_targetFrame.store(resolvedTarget, std::memory_order_release);
            LogTargetFrame(resolvedTarget);
            g_announcedTarget = true;
        } else {
            char warn[192];
            sprintf_s(warn,
                      sizeof(warn),
                      "[CastCorrelator] TARGET_SENDER_ADDR invalid: %s",
                      targetAddr->c_str());
            WriteRawLog(warn);
        }
    }

    EnterCriticalSection(&g_lock);
    for (auto& win : g_windows)
        CloseWindowLocked(win);
    LeaveCriticalSection(&g_lock);

    g_activeWindows.store(0, std::memory_order_release);
    g_targetFrame.store(0, std::memory_order_release);
    g_announcedTarget = false;
    g_enabled = true;
    WriteRawLog("[CastCorrelator] enabled");
}

void Shutdown() {
    if (!g_lockInit)
        return;
    SpellSenderDetour_Disarm();
    EnterCriticalSection(&g_lock);
    for (auto& win : g_windows)
        CloseWindowLocked(win);
    LeaveCriticalSection(&g_lock);
    g_activeWindows.store(0, std::memory_order_release);
    g_targetFrame.store(0, std::memory_order_release);
    g_announcedTarget = false;
    g_enabled = false;
}

bool IsEnabled() {
    return g_enabled;
}

bool ShouldCaptureStack(unsigned char packetId) {
    if (!g_enabled)
        return false;
    if (packetId == 0x2E)
        return true;
    return g_activeWindows.load(std::memory_order_acquire) > 0;
}

void OnCastAttempt(uint32_t spellId) {
    if (!g_enabled)
        return;
    EnsureLock();
    DWORD now = NowMs();
    EnterCriticalSection(&g_lock);
    CleanupExpiredLocked(now);

    CastWindow* slot = nullptr;
    for (auto& win : g_windows) {
        if (!win.active) {
            slot = &win;
            break;
        }
    }
    if (!slot) {
        slot = &g_windows[0];
        CloseWindowLocked(*slot);
    }

    slot->active = true;
    slot->startTick = now;
    slot->spellId = spellId;
    g_activeWindows.fetch_add(1, std::memory_order_acq_rel);
    LeaveCriticalSection(&g_lock);

    LogWindowOpen(spellId, now);
}

void OnSendEvent(const SendEvent& ev) {
    if (!g_enabled)
        return;
    if (ev.frameCount == 0)
        return;

    uintptr_t clientFrame = FirstClientFrame(ev.frames, ev.frameCount);
    if (clientFrame && ev.packetId == 0x2E && ev.targetFilterArmed) {
        uintptr_t prev = g_targetFrame.exchange(clientFrame, std::memory_order_acq_rel);
        if (prev != clientFrame || !g_announcedTarget) {
            LogTargetFrame(clientFrame);
            g_announcedTarget = true;
        }
    }

    if (g_activeWindows.load(std::memory_order_acquire) == 0)
        return;

    if (!clientFrame || !g_moduleBase)
        return;

    DWORD now = ev.tick ? ev.tick : NowMs();

    CastWindow chosen{};
    int chosenIndex = -1;

    EnterCriticalSection(&g_lock);
    CleanupExpiredLocked(now);
    for (size_t i = 0; i < kMaxWindows; ++i) {
        auto& win = g_windows[i];
        if (!win.active)
            continue;
        DWORD age = now - win.startTick;
        if (age <= g_windowMs) {
            chosen = win;
            chosenIndex = static_cast<int>(i);
            break;
        }
    }
    LeaveCriticalSection(&g_lock);

    if (chosenIndex < 0)
        return;
    if (g_lenHint > 0 && ev.length != g_lenHint)
        return;

    uintptr_t targetFrame = g_targetFrame.load(std::memory_order_acquire);
    if (targetFrame && clientFrame == targetFrame)
        return;

    DWORD delta = now - chosen.startTick;
    char buf[256];
    sprintf_s(buf,
              sizeof(buf),
              "[CastCorrelator] send t=+%lu ms id=%02X len=%d top=UOSA.exe+0x%lX -> CAST CANDIDATE",
              static_cast<unsigned long>(delta),
              ev.packetId,
              ev.length,
              static_cast<unsigned long>(clientFrame - g_moduleBase));
    WriteRawLog(buf);
    LogCandidateStack(ev.frames, ev.frameCount);

    EnterCriticalSection(&g_lock);
    if (chosenIndex >= 0)
        CloseWindowLocked(g_windows[chosenIndex]);
    LeaveCriticalSection(&g_lock);

    if (g_senderDetourEnabled)
        SpellSenderDetour_EnsureArmed(clientFrame);
}

} // namespace CastCorrelator
