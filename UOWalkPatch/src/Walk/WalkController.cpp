#include "Walk/WalkController.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <mutex>
#include <system_error>
#include <cstring>
#include <string>

#include "Core/Config.hpp"
#include "Core/EarlyTrace.hpp"
#include "Core/Logging.hpp"
#include "Net/SendBuilder.hpp"
#include "Engine/Movement.hpp"
#include "uow/WalkController.hpp"

namespace Walk::Controller {
namespace {

struct ControllerConfig {
    bool enabled = true;
    bool debug = false;
    std::uint32_t maxInflight = 1;
    std::uint32_t stepDelayMs = 350;
    std::uint32_t stepDelayFloor = 320;
    std::uint32_t stepDelayCeil = 480;
    std::uint32_t timeoutMs = 400;
};

struct ControllerState {
    bool active = false;
    bool run = false;
    float targetX = 0.0f;
    float targetY = 0.0f;
    float targetZ = 0.0f;
    float currentX = 0.0f;
    float currentZ = 0.0f;
    std::uint32_t inflight = 0;
    std::uint32_t lastHead = 0;
    std::uint32_t lastStepTick = 0;
    std::uint32_t lastProgressTick = 0;
    std::uint32_t lastLogTick = 0;
};

constexpr float kArrivalThreshold = 0.4f;
constexpr std::uint32_t kLogCooldownMs = 1500;
constexpr std::uint32_t kMaxInflightCap = 4;
ControllerConfig g_config{};
std::once_flag g_configOnce;
std::mutex g_stateMutex;
ControllerState g_state{};
std::atomic<std::uint32_t> g_inflightOverride{0};
std::atomic<std::uint32_t> g_inflightOverrideBudget{0};
std::atomic<std::uint32_t> g_runtimeMaxInflight{1};
std::uint32_t g_tunedStepDelayMs = 350;
std::uint32_t g_stepDelayFloor = 320;
std::uint32_t g_stepDelayCeil = 480;
std::uint32_t g_lastDelayTick = 0;
std::uint32_t g_lastDecayTick = 0;
std::uint32_t g_nominalStepDelayFloor = 320;
std::uint32_t g_nominalStepDelayCeil = 480;
std::uint32_t g_nominalMaxInflight = 2;
bool g_preAttachDefaultsActive = false;
bool g_builderWasAttached = false;
std::uint32_t g_attachStableStartTick = 0;
std::uint32_t g_attachBaselineAckDrops = 0;
std::uint32_t g_consecutiveAckOk = 0;
uow::WalkController g_pacingModel{};

std::uint32_t GetTickMs() {
    return GetTickCount();
}

void PacingAckNudge(std::uint64_t /*nowMs*/) {
    Net::SoftNudgeBuilder(320, 480);
}

void UpdateStepDelay(std::uint32_t newValue, const char* reason) {
    newValue = std::clamp(newValue, g_stepDelayFloor, g_stepDelayCeil);
    if (newValue == g_tunedStepDelayMs)
        return;
    std::uint32_t oldValue = g_tunedStepDelayMs;
    g_tunedStepDelayMs = newValue;
    Log::Logf(Log::Level::Info,
              Log::Category::Walk,
              "[WALK] tune stepDelayMs %u -> %u reason=%s",
              oldValue,
              g_tunedStepDelayMs,
              reason ? reason : "unknown");
}

void ApplyPreAttachDefaultsLocked() {
    if (g_preAttachDefaultsActive)
        return;
    g_stepDelayFloor = 320;
    g_stepDelayCeil = 480;
    g_preAttachDefaultsActive = true;
    g_consecutiveAckOk = 0;
    g_runtimeMaxInflight.store(1u, std::memory_order_release);
    std::uint64_t nowMs = GetTickCount64();
    g_pacingModel.init(nowMs);
    g_pacingModel.reevaluate(nowMs);
    g_pacingModel.set_ack_nudge_callback(&PacingAckNudge);
    UpdateStepDelay(static_cast<std::uint32_t>(g_pacingModel.stepDelayMs()), "pre-attach");
    Log::Logf(Log::Level::Info,
              Log::Category::Walk,
              "[WALK] pacing pre-attach floor=%u ceil=%u inflight=%u",
              g_stepDelayFloor,
              g_stepDelayCeil,
              g_runtimeMaxInflight.load(std::memory_order_relaxed));
}

void RestoreNominalPacingLocked(const char* reason) {
    if (!g_preAttachDefaultsActive)
        return;
    g_stepDelayFloor = g_nominalStepDelayFloor;
    g_stepDelayCeil = g_nominalStepDelayCeil;
    g_preAttachDefaultsActive = false;
    g_consecutiveAckOk = 0;
    g_runtimeMaxInflight.store(g_nominalMaxInflight, std::memory_order_release);
    std::uint64_t nowMs = GetTickCount64();
    g_pacingModel.init(nowMs);
    g_pacingModel.reevaluate(nowMs);
    g_pacingModel.set_ack_nudge_callback(&PacingAckNudge);
    UpdateStepDelay(static_cast<std::uint32_t>(g_pacingModel.stepDelayMs()),
                    reason ? reason : "attach-stable");
    Log::Logf(Log::Level::Info,
              Log::Category::Walk,
              "[WALK] pacing restored floor=%u ceil=%u inflight=%u",
              g_stepDelayFloor,
              g_stepDelayCeil,
              g_nominalMaxInflight);
}

void UpdatePacingLocked(std::uint32_t tickNow) {
    bool builderAttached = Net::IsSendBuilderAttached();
    if (!builderAttached) {
        g_builderWasAttached = false;
        g_attachStableStartTick = 0;
        g_attachBaselineAckDrops = Engine::GetAckDropCount();
        ApplyPreAttachDefaultsLocked();
        return;
    }

    if (!g_builderWasAttached) {
        g_builderWasAttached = true;
        g_attachBaselineAckDrops = Engine::GetAckDropCount();
        g_attachStableStartTick = tickNow;
    }

    if (g_preAttachDefaultsActive) {
        uint32_t currentDrops = Engine::GetAckDropCount();
        if (currentDrops != g_attachBaselineAckDrops) {
            g_attachBaselineAckDrops = currentDrops;
            g_attachStableStartTick = tickNow;
        } else {
            if (g_attachStableStartTick == 0)
                g_attachStableStartTick = tickNow;

            uint32_t elapsed = tickNow - g_attachStableStartTick;
            if (elapsed >= 5000) {
                RestoreNominalPacingLocked("sendbuilder-attached");
            }
        }
    }

    std::uint64_t nowMs = GetTickCount64();
    g_pacingModel.reevaluate(nowMs);
    std::uint32_t newDelay = static_cast<std::uint32_t>(g_pacingModel.stepDelayMs());
    if (newDelay != g_tunedStepDelayMs)
        UpdateStepDelay(newDelay, "reevaluate");
    g_runtimeMaxInflight.store(static_cast<std::uint32_t>(g_pacingModel.maxInflight()),
                               std::memory_order_release);
}


void LoadConfig() {
    ControllerConfig cfg{};

    auto readBool = [](const char* envName, const char* cfgKey, bool& outValue) {
        if (auto envValue = Core::Config::TryGetEnvBool(envName)) {
            outValue = *envValue;
            return true;
        }
        if (auto cfgValue = Core::Config::TryGetBool(cfgKey)) {
            outValue = *cfgValue;
            return true;
        }
        return false;
    };

    auto readUint = [](const char* envName, const char* cfgKey, std::uint32_t& outValue) {
        if (auto envValue = Core::Config::TryGetEnv(envName)) {
            try {
                outValue = static_cast<std::uint32_t>(std::stoul(*envValue));
                return true;
            } catch (...) {
                return false;
            }
        }
        if (auto cfgValue = Core::Config::TryGetUInt(cfgKey)) {
            outValue = *cfgValue;
            return true;
        }
        return false;
    };

    readBool("WALK_ENABLE", "walk.enable", cfg.enabled);
    readBool("WALK_DEBUG", "walk.debug", cfg.debug);

    std::uint32_t value = cfg.maxInflight;
    if (readUint("WALK_MAX_INFLIGHT", "walk.maxInflight", value))
        cfg.maxInflight = value;

    value = cfg.stepDelayMs;
    if (readUint("WALK_STEP_DELAY_MS", "walk.stepDelayMs", value))
        cfg.stepDelayMs = value;

    value = cfg.stepDelayFloor;
    if (readUint("WALK_STEP_DELAY_FLOOR", "walk.stepDelayFloor", value))
        cfg.stepDelayFloor = value;

    value = cfg.stepDelayCeil;
    if (readUint("WALK_STEP_DELAY_CEIL", "walk.stepDelayCeil", value))
        cfg.stepDelayCeil = value;

    value = cfg.timeoutMs;
    if (readUint("WALK_TIMEOUT_MS", "walk.timeoutMs", value))
        cfg.timeoutMs = value;

    cfg.maxInflight = std::clamp<std::uint32_t>(cfg.maxInflight, 1u, kMaxInflightCap);
    cfg.stepDelayFloor = std::clamp<std::uint32_t>(cfg.stepDelayFloor, 150u, 1000u);
    cfg.stepDelayCeil = std::clamp<std::uint32_t>(cfg.stepDelayCeil, cfg.stepDelayFloor, 1000u);
    cfg.stepDelayMs = std::clamp<std::uint32_t>(cfg.stepDelayMs, cfg.stepDelayFloor, cfg.stepDelayCeil);
    cfg.timeoutMs = std::clamp<std::uint32_t>(cfg.timeoutMs, 200u, 2000u);

    g_config = cfg;
    g_stepDelayFloor = cfg.stepDelayFloor;
    g_stepDelayCeil = cfg.stepDelayCeil;
    g_nominalStepDelayFloor = cfg.stepDelayFloor;
    g_nominalStepDelayCeil = cfg.stepDelayCeil;
    g_nominalMaxInflight = cfg.maxInflight;
    g_runtimeMaxInflight.store(cfg.maxInflight, std::memory_order_release);
    g_tunedStepDelayMs = cfg.stepDelayMs;
    g_lastDelayTick = 0;
    g_lastDecayTick = GetTickMs();

    Log::Logf(Log::Level::Info,
              Log::Category::Walk,
              "enable=%d maxInflight=%u stepDelayMs=%u floor=%u ceil=%u timeoutMs=%u debug=%d",
              cfg.enabled ? 1 : 0,
              cfg.maxInflight,
              cfg.stepDelayMs,
              cfg.stepDelayFloor,
              cfg.stepDelayCeil,
              cfg.timeoutMs,
              cfg.debug ? 1 : 0);
}

void EnsureConfigLoaded() {
    Core::EarlyTrace::Write("Walk::EnsureConfigLoaded call_once begin");
    try {
        std::call_once(g_configOnce, LoadConfig);
        Core::EarlyTrace::Write("Walk::EnsureConfigLoaded call_once success");
    } catch (const std::system_error& e) {
        char buf[256];
        sprintf_s(buf,
                  sizeof(buf),
                  "Walk::Controller::EnsureConfigLoaded call_once threw code=%d category=%s what=%s",
                  e.code().value(),
                  e.code().category().name(),
                  e.what());
        Core::EarlyTrace::Write(buf);
        throw;
    }
}

bool HasArrived(float currentX, float currentZ, float targetX, float targetZ) {
    return std::fabs(currentX - targetX) < kArrivalThreshold &&
           std::fabs(currentZ - targetZ) < kArrivalThreshold;
}

int DetermineDirection(float currentX, float currentZ, float targetX, float targetZ) {
    constexpr int kDirCount = 8;
    constexpr int kStepDx[kDirCount] = {0, 1, 1, 1, 0, -1, -1, -1};
    constexpr int kStepDz[kDirCount] = {-1, -1, 0, 1, 1, 1, 0, -1};

    const float dx = targetX - currentX;
    const float dz = targetZ - currentZ;
    const float threshold = kArrivalThreshold;

    int stepX = 0;
    if (dx > threshold)
        stepX = 1;
    else if (dx < -threshold)
        stepX = -1;

    int stepZ = 0;
    if (dz > threshold)
        stepZ = 1;
    else if (dz < -threshold)
        stepZ = -1;

    if (stepX == 0 && stepZ == 0)
        return -1;

    for (int dir = 0; dir < kDirCount; ++dir) {
        if (kStepDx[dir] == stepX && kStepDz[dir] == stepZ)
            return dir;
    }

    if (std::fabs(dx) >= std::fabs(dz))
        return (dx > 0) ? 2 : 6;
    return (dz > 0) ? 4 : 0;
}

} // namespace

void Reset() {
    EnsureConfigLoaded();
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_state = ControllerState{};
    g_inflightOverride.store(0, std::memory_order_release);
    g_inflightOverrideBudget.store(0, std::memory_order_release);
    g_consecutiveAckOk = 0;
    g_lastDelayTick = 0;
    std::uint64_t nowMs = GetTickCount64();
    g_lastDecayTick = static_cast<std::uint32_t>(nowMs);
    g_pacingModel.set_ack_nudge_callback(&PacingAckNudge);
    g_pacingModel.init(nowMs);
    g_pacingModel.reevaluate(nowMs);
    g_tunedStepDelayMs = static_cast<std::uint32_t>(g_pacingModel.stepDelayMs());
    g_runtimeMaxInflight.store(static_cast<std::uint32_t>(g_pacingModel.maxInflight()),
                               std::memory_order_release);
    UpdatePacingLocked(static_cast<std::uint32_t>(nowMs));
}

bool IsEnabled() {
    EnsureConfigLoaded();
    return g_config.enabled;
}

Settings GetSettings() {
    EnsureConfigLoaded();
    Settings settings{};
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        UpdatePacingLocked(GetTickMs());
        settings.enabled = g_config.enabled;
        settings.maxInflight = g_runtimeMaxInflight.load(std::memory_order_relaxed);
        settings.stepDelayMs = g_tunedStepDelayMs;
        settings.timeoutMs = g_config.timeoutMs;
        settings.debug = g_config.debug;
    }
    return settings;
}

bool DebugEnabled() {
    EnsureConfigLoaded();
    return g_config.debug;
}

bool RequestTarget(float x, float y, float z, bool run) {
    if (!IsEnabled())
        return false;
    if (!Engine::MovementReady())
        return false;

    std::lock_guard<std::mutex> lock(g_stateMutex);
    std::uint32_t now = GetTickMs();
    UpdatePacingLocked(now);
    g_state = ControllerState{};
    g_state.active = true;
    g_state.run = run;
    g_state.targetX = x;
    g_state.targetY = y;
    g_state.targetZ = z;
    g_state.lastProgressTick = now;

    Engine::MovementSnapshot snapshot{};
    if (Engine::GetLastMovementSnapshot(snapshot)) {
        g_state.currentX = snapshot.posX;
        g_state.currentZ = snapshot.posZ;
        g_state.lastHead = snapshot.head;
    }

    Log::Logf(Log::Level::Info,
              Log::Category::Walk,
              "walk-controller start target=(%.2f,%.2f,%.2f) run=%d",
              x,
              y,
              z,
              run ? 1 : 0);
    return true;
}

void Cancel() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    if (!g_state.active)
        return;
    g_state.active = false;
    g_state.inflight = 0;
    g_consecutiveAckOk = 0;
}

void OnMovementSnapshot(const Engine::MovementSnapshot& snapshot,
                        bool headChanged,
                        std::uint32_t tickMs) {
    if (!IsEnabled()) {
        Reset();
        return;
    }

    std::lock_guard<std::mutex> lock(g_stateMutex);
    if (!g_state.active)
        return;
    UpdatePacingLocked(tickMs);

    g_state.currentX = snapshot.posX;
    g_state.currentZ = snapshot.posZ;

    if (headChanged) {
        if (g_state.inflight > 0)
            --g_state.inflight;
        g_state.lastHead = snapshot.head;
        g_state.lastProgressTick = tickMs;
    }

    if (HasArrived(g_state.currentX, g_state.currentZ, g_state.targetX, g_state.targetZ)) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Walk,
                  "walk-controller arrived pos=(%.2f,%.2f)",
                  g_state.currentX,
                  g_state.currentZ);
        g_state = ControllerState{};
        return;
    }

    if (g_state.inflight > 0) {
        const std::uint32_t elapsed = tickMs - g_state.lastProgressTick;
        if (elapsed > g_config.timeoutMs) {
            if (tickMs - g_state.lastLogTick > kLogCooldownMs) {
                g_state.lastLogTick = tickMs;
                Log::Logf(Log::Level::Warn,
                          Log::Category::Walk,
                          "walk-controller timeout inflight=%u head=%u pos=(%.2f,%.2f) target=(%.2f,%.2f)",
                          g_state.inflight,
                          snapshot.head,
                          g_state.currentX,
                          g_state.currentZ,
                          g_state.targetX,
                          g_state.targetZ);
            }
            g_state.inflight = 0;
            g_state.lastProgressTick = tickMs;
        }
    }

    std::uint32_t effectiveMaxInflight = g_runtimeMaxInflight.load(std::memory_order_relaxed);
    std::uint32_t override = g_inflightOverride.load(std::memory_order_relaxed);
    if (override > 0) {
        std::uint32_t budget = g_inflightOverrideBudget.load(std::memory_order_relaxed);
        if (budget > 0) {
            if (override < effectiveMaxInflight)
                effectiveMaxInflight = override;
            std::uint32_t prev = g_inflightOverrideBudget.fetch_sub(1, std::memory_order_acq_rel);
            if (prev <= 1) {
                g_inflightOverrideBudget.store(0, std::memory_order_release);
                g_inflightOverride.store(0, std::memory_order_release);
            }
        } else {
            g_inflightOverride.store(0, std::memory_order_release);
        }
    }
    if (effectiveMaxInflight == 0)
        effectiveMaxInflight = 1;

    if (g_state.inflight >= effectiveMaxInflight)
        return;

    if (tickMs - g_state.lastStepTick < g_tunedStepDelayMs)
        return;

    if (!Engine::MovementReady())
        return;

    int dir = DetermineDirection(g_state.currentX, g_state.currentZ, g_state.targetX, g_state.targetZ);
    if (dir < 0) {
        g_state.active = false;
        g_state.inflight = 0;
        return;
    }

    bool sent = false;
    if (::Engine::Movement::IsReady()) {
        sent = ::Engine::Movement::EnqueueMove(static_cast<::Engine::Movement::Dir>(dir & 0x7),
                                               g_state.run);
    }
    if (!sent) {
        sent = SendWalk(dir, g_state.run ? 1 : 0);
    }
    g_state.lastStepTick = tickMs;
    if (sent) {
        ++g_state.inflight;
        g_state.lastProgressTick = tickMs;
        if (DebugEnabled() && Log::IsEnabled(Log::Category::Walk, Log::Level::Debug)) {
            Log::Logf(Log::Level::Debug,
                      Log::Category::Walk,
                      "walk-controller step dir=%d run=%d inflight=%u pos=(%.2f,%.2f) target=(%.2f,%.2f)",
                      dir,
                      g_state.run ? 1 : 0,
                      g_state.inflight,
                      g_state.currentX,
                      g_state.currentZ,
                      g_state.targetX,
                      g_state.targetZ);
        }
    } else if (tickMs - g_state.lastLogTick > kLogCooldownMs && DebugEnabled()) {
        g_state.lastLogTick = tickMs;
        Log::Logf(Log::Level::Debug,
                  Log::Category::Walk,
                  "walk-controller step-failed dir=%d run=%d",
                  dir,
                  g_state.run ? 1 : 0);
    }
}

std::uint32_t GetInflightCount() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    return g_state.inflight;
}

void NotifyAckOk() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    if (!g_state.active)
        return;
    if (g_state.inflight > 0)
        --g_state.inflight;
    std::uint64_t nowMs = GetTickCount64();
    g_state.lastProgressTick = static_cast<std::uint32_t>(nowMs);
    g_lastDecayTick = static_cast<std::uint32_t>(nowMs);
    g_consecutiveAckOk = 0;
    g_pacingModel.onAck(0, true, nowMs);
    g_pacingModel.reevaluate(nowMs);
    std::uint32_t target = static_cast<std::uint32_t>(g_pacingModel.stepDelayMs());
    if (target != g_tunedStepDelayMs)
        UpdateStepDelay(target, "ack");
    g_runtimeMaxInflight.store(static_cast<std::uint32_t>(g_pacingModel.maxInflight()),
                               std::memory_order_release);
}

void NotifyAckSoftFail() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_state.inflight = 0;
    g_consecutiveAckOk = 0;
    std::uint64_t nowMs = GetTickCount64();
    g_pacingModel.onAck(0, false, nowMs);
    g_pacingModel.reevaluate(nowMs);
    std::uint32_t target = static_cast<std::uint32_t>(g_pacingModel.stepDelayMs());
    if (target != g_tunedStepDelayMs)
        UpdateStepDelay(target, "ack-fail");
    g_runtimeMaxInflight.store(static_cast<std::uint32_t>(g_pacingModel.maxInflight()),
                               std::memory_order_release);
}

void NotifyResync(const char* reason) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    std::uint64_t nowMs = GetTickCount64();
    g_lastDelayTick = static_cast<std::uint32_t>(nowMs);
    g_lastDecayTick = static_cast<std::uint32_t>(nowMs);
    g_consecutiveAckOk = 0;
    g_pacingModel.onAck(0, false, nowMs);
    g_pacingModel.reevaluate(nowMs);
    std::uint32_t target = static_cast<std::uint32_t>(g_pacingModel.stepDelayMs());
    const char* label = (reason && *reason) ? reason : "resync";
    if (target != g_tunedStepDelayMs)
        UpdateStepDelay(target, label);
    g_runtimeMaxInflight.store(static_cast<std::uint32_t>(g_pacingModel.maxInflight()),
                               std::memory_order_release);
}

std::uint32_t GetStepDelayMs() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    return g_tunedStepDelayMs;
}

void SetStepDelayMs(std::uint32_t ms) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    std::uint32_t clamped = std::clamp(ms, g_stepDelayFloor, g_stepDelayCeil);
    g_pacingModel.force_step_delay(static_cast<int>(clamped));
    UpdateStepDelay(clamped, "manual");
}

void SetMaxInflight(std::uint32_t count) {
    if (count == 0)
        count = 1;
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_pacingModel.force_max_inflight(static_cast<int>(count));
    g_runtimeMaxInflight.store(count, std::memory_order_release);
    Log::Logf(Log::Level::Info, Log::Category::Walk, "[WALK] manual maxInflight=%u", count);
}

void ApplyInflightOverride(std::uint32_t maxInflight, std::uint32_t cycleBudget) {
    if (maxInflight == 0 || cycleBudget == 0) {
        g_inflightOverride.store(0, std::memory_order_release);
        g_inflightOverrideBudget.store(0, std::memory_order_release);
        return;
    }
    std::uint32_t clamped = std::max<std::uint32_t>(1u, maxInflight);
    g_inflightOverride.store(clamped, std::memory_order_release);
    g_inflightOverrideBudget.store(cycleBudget, std::memory_order_release);
    Log::Logf(Log::Level::Info,
              Log::Category::Walk,
              "[WALK] inflight override=%u cycles=%u",
              clamped,
              cycleBudget);
}

} // namespace Walk::Controller
