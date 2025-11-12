#include "TargetCorrelator.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>

#include "Core/Config.hpp"
#include "Core/Logging.hpp"
#include "SpellProbe.h"

namespace {

CRITICAL_SECTION g_targetCorrLock;
bool g_targetCorrLockInit = false;

void EnsureLock()
{
    if (!g_targetCorrLockInit) {
        InitializeCriticalSection(&g_targetCorrLock);
        g_targetCorrLockInit = true;
    }
}

uint64_t NowMs()
{
    return GetTickCount64();
}

uintptr_t ModuleBase()
{
    static uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    if (!base) {
        HMODULE mod = GetModuleHandleA(nullptr);
        base = reinterpret_cast<uintptr_t>(mod);
    }
    return base;
}

bool DebugProfileEnabled()
{
    if (auto cfg = Core::Config::TryGetBool("UOW_DEBUG_ENABLE"))
        return *cfg;
    if (auto env = Core::Config::TryGetEnvBool("UOW_DEBUG_ENABLE"))
        return *env;
    return false;
}

bool ReadBool(const char* key, const char* envKey, bool defaultValue = false)
{
    if (key) {
        if (auto cfg = Core::Config::TryGetBool(key))
            return *cfg;
    }
    if (envKey) {
        if (auto env = Core::Config::TryGetEnvBool(envKey))
            return *env;
    }
    return defaultValue;
}

uint32_t ReadWindowMs()
{
    uint32_t window = 1200;
    if (auto cfg = Core::Config::TryGetMilliseconds("uow.debug.target_window_ms"))
        window = *cfg;
    else if (auto env = Core::Config::TryGetEnv("UOW_DEBUG_TARGET_WINDOW_MS"))
        window = static_cast<uint32_t>(std::strtoul(env->c_str(), nullptr, 10));
    else if (auto legacy = Core::Config::TryGetMilliseconds("TARGET_CORR_WINDOW_MS"))
        window = *legacy;
    else if (auto legacyEnv = Core::Config::TryGetEnv("TARGET_CORR_WINDOW_MS"))
        window = static_cast<uint32_t>(std::strtoul(legacyEnv->c_str(), nullptr, 10));
    return std::clamp(window, 200u, 4000u);
}

uintptr_t ReadFrameHint()
{
    std::optional<std::string> hintText;
    if (auto cfg = Core::Config::TryGetValue("TARGET_SENDER_ADDR"))
        hintText = *cfg;
    else if (auto env = Core::Config::TryGetEnv("TARGET_SENDER_ADDR"))
        hintText = *env;
    if (!hintText || hintText->empty())
        return 0;
    uintptr_t resolved = ResolveModulePlusOffset(hintText->c_str());
    if (!resolved) {
        char warn[192];
        sprintf_s(warn,
                  sizeof(warn),
                  "[TargetCorrelator] TARGET_SENDER_ADDR invalid: %s",
                  hintText->c_str());
        WriteRawLog(warn);
    }
    return resolved;
}

void LogHint(uintptr_t frame)
{
    uintptr_t base = ModuleBase();
    if (!frame || !base)
        return;
    char buf[192];
    sprintf_s(buf,
              sizeof(buf),
              "[TargetCorrelator] dispatch frame set to UOSA.exe+0x%lX",
              static_cast<unsigned long>(frame - base));
    WriteRawLog(buf);
}

} // namespace

TargetCorrelator g_targetCorr;

void TargetCorrelator::Arm(const char* why)
{
    if (!enabled)
        return;
    EnsureLock();
    EnterCriticalSection(&g_targetCorrLock);
    armed = true;
    t0 = NowMs();
    ++seq;
    if (why && *why)
        strncpy_s(reason, why, _TRUNCATE);
    else
        reason[0] = '\0';
    LeaveCriticalSection(&g_targetCorrLock);
    if (verbose) {
        char buf[256];
        sprintf_s(buf,
                  sizeof(buf),
                  "[TargetCorrelator] armed seq=%u reason=%s window=%u ms",
                  seq,
                  (why && *why) ? why : "unspecified",
                  windowMs);
        WriteRawLog(buf);
    }
}

void TargetCorrelator::Disarm(const char* why)
{
    if (!enabled)
        return;
    bool wasArmed = false;
    char previous[64];
    EnsureLock();
    EnterCriticalSection(&g_targetCorrLock);
    wasArmed = armed;
    armed = false;
    strncpy_s(previous, reason, _TRUNCATE);
    reason[0] = '\0';
    LeaveCriticalSection(&g_targetCorrLock);
    if (wasArmed && verbose) {
        const char* msg = (why && *why) ? why : (previous[0] ? previous : "unspecified");
        char buf[192];
        sprintf_s(buf, sizeof(buf), "[TargetCorrelator] disarmed reason=%s", msg);
        WriteRawLog(buf);
    }
}

bool TargetCorrelator::ShouldCaptureStack(std::uint8_t packetId) const
{
    return enabled && armed && packetId == 0x2E;
}

std::optional<uint64_t> TargetCorrelator::TagIfWithin(std::uint8_t packetId,
                                                      std::size_t /*len*/,
                                                      void* topFrame)
{
    if (!enabled || packetId != 0x2E)
        return std::nullopt;

    uint64_t elapsed = 0;
    bool fire = false;
    {
        EnsureLock();
        EnterCriticalSection(&g_targetCorrLock);
        if (armed) {
            elapsed = NowMs() - t0;
            if (elapsed <= windowMs) {
                fire = true;
                armed = false;
            } else if (verbose) {
                char buf[192];
                sprintf_s(buf,
                          sizeof(buf),
                          "[TargetCorrelator] expired seq=%u after %llu ms",
                          seq,
                          static_cast<unsigned long long>(elapsed));
                WriteRawLog(buf);
                armed = false;
            } else {
                armed = false;
            }
        }
        LeaveCriticalSection(&g_targetCorrLock);
    }

    if (!fire)
        return std::nullopt;

    uintptr_t frame = reinterpret_cast<uintptr_t>(topFrame);
    if (!frameHint && frame) {
        frameHint = frame;
        hintAnnounced = false;
    }

    if (frameHint && frame) {
        if (!hintAnnounced && frameHint == frame) {
            LogHint(frameHint);
            hintAnnounced = true;
        } else if (frameHint != frame) {
            return std::nullopt;
        }
    }
    return elapsed;
}

void TargetCorrelatorInit()
{
    EnsureLock();
    g_targetCorr.armed = false;
    g_targetCorr.t0 = 0;
    g_targetCorr.seq = 0;
    g_targetCorr.reason[0] = '\0';
    g_targetCorr.windowMs = ReadWindowMs();
    g_targetCorr.frameHint = 0;
    g_targetCorr.hintAnnounced = false;

    bool enable = ReadBool("uow.debug.target", "UOW_DEBUG_TARGET");
    if (!enable && DebugProfileEnabled())
        enable = ReadBool("TARGET_CORR_ENABLE", "TARGET_CORR_ENABLE");
    g_targetCorr.enabled = enable;
    g_targetCorr.verbose = enable;

    uintptr_t manualHint = ReadFrameHint();
    if (manualHint) {
        g_targetCorr.frameHint = manualHint;
        g_targetCorr.hintAnnounced = false;
        LogHint(manualHint);
    }

    if (g_targetCorr.enabled) {
        char buf[160];
        sprintf_s(buf,
                  sizeof(buf),
                  "[TargetCorrelator] enabled window=%u ms",
                  g_targetCorr.windowMs);
        WriteRawLog(buf);
    } else {
        WriteRawLog("[TargetCorrelator] disabled (set TARGET_CORR_ENABLE=1 or uow.debug.target=1)");
    }
}

void TargetCorrelatorShutdown()
{
    if (g_targetCorr.enabled)
        g_targetCorr.Disarm("shutdown");
    g_targetCorr.enabled = false;
    if (g_targetCorrLockInit) {
        DeleteCriticalSection(&g_targetCorrLock);
        g_targetCorrLockInit = false;
    }
}

bool TargetCorrelatorEnabled()
{
    return g_targetCorr.enabled;
}
