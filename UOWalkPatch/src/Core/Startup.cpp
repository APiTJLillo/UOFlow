#include "Core/Startup.hpp"

#include <atomic>
#include <sstream>
#include <chrono>
#include <thread>

#include "Core/Config.hpp"
#include "Engine/GlobalState.hpp"
#include "Net/SendBuilder.hpp"

#include "Core/Logging.hpp"
#include "Engine/LuaBridge.hpp"
#include "Walk/WalkController.hpp"

namespace {
struct SummaryState {
    std::atomic<int> movementHooks{0};
    std::atomic<int> packetTrace{0};
    std::atomic<int> sendBuilder{0};
    std::atomic<int> luaBridge{0};

    std::atomic<bool> bootstrapReady{false};
    std::atomic<bool> helpersReady{false};
    std::atomic<bool> engineReady{false};
    std::atomic<bool> luaHeartbeat{false};
    std::atomic<bool> summaryEmitted{false};
    std::atomic<bool> attachSummaryEmitted{false};
    std::atomic<bool> selfTestEmitted{false};
    std::atomic<bool> selfTestRequested{false};
    std::atomic<uint64_t> attachStartTick{0};
};

SummaryState g_state;

constexpr uint64_t kAttachSummaryGraceMs = 2000;

uint64_t NowMs() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

void RunSelfTest();
void MaybeEmitAttachSummary();

void MaybeEmitSummary() {
    if (!g_state.bootstrapReady.load(std::memory_order_acquire))
        return;
    if (!g_state.helpersReady.load(std::memory_order_acquire))
        return;
    if (!g_state.engineReady.load(std::memory_order_acquire))
        return;
    if (!g_state.luaHeartbeat.load(std::memory_order_acquire))
        return;

    bool expected = false;
    if (!g_state.summaryEmitted.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    Engine::Lua::StartupStatus luaStatus{};
    Engine::Lua::GetStartupStatus(luaStatus);
    Walk::Controller::Settings walkSettings = Walk::Controller::GetSettings();

    std::ostringstream summary;
    summary << "startup summary hooks.movement=" << g_state.movementHooks.load(std::memory_order_acquire)
            << " hooks.net=" << g_state.packetTrace.load(std::memory_order_acquire)
            << " hooks.send=" << g_state.sendBuilder.load(std::memory_order_acquire)
            << " lua.bridge=" << g_state.luaBridge.load(std::memory_order_acquire)
            << " engine.ctx=" << (luaStatus.engineContextDiscovered ? 1 : 0)
            << " lua.state=" << (luaStatus.luaStateDiscovered ? 1 : 0)
            << " helpers=" << (luaStatus.helpersInstalled ? 1 : 0)
            << " walk.enable=" << (walkSettings.enabled ? 1 : 0)
            << " maxInflight=" << walkSettings.maxInflight
            << " stepDelayMs=" << walkSettings.stepDelayMs
            << " timeoutMs=" << walkSettings.timeoutMs
            << " debug=" << (walkSettings.debug ? 1 : 0)
            << " helperOwnerTid=" << luaStatus.ownerThreadId;

    auto message = summary.str();
    Log::LogMessage(Log::Level::Info, Log::Category::Core, message.c_str());
    MaybeEmitAttachSummary();
}

void RunSelfTest() {
    using namespace std::chrono;
    constexpr auto kTimeout = seconds(5);
    constexpr auto kPollInterval = milliseconds(100);

    auto start = steady_clock::now();
    Engine::Lua::StartupStatus status{};
    bool helpersOk = false;
    bool builderOk = false;

    do {
        Engine::Lua::GetStartupStatus(status);
        helpersOk = status.helpersInstalled;
        builderOk = Net::IsSendBuilderAttached();
        if (helpersOk && builderOk)
            break;
        std::this_thread::sleep_for(kPollInterval);
    } while (steady_clock::now() - start < kTimeout);

    const char* helperStage = Engine::Lua::GetHelperStageSummary();
    const char* builderState = builderOk ? "attached" : "pending";

    if (!helpersOk) {
        Log::Logf(Log::Level::Warn,
                  Log::Category::Core,
                  "selftest: helpers not installed stage=%s",
                  helperStage ? helperStage : "unknown");
    }
    if (!builderOk) {
        Log::Logf(Log::Level::Warn,
                  Log::Category::Core,
                  "selftest: SendBuilder not attached state=%s",
                  builderState);
    }

    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "selftest: helpers=%s builder=%s",
              helperStage ? helperStage : "unknown",
              builderState);
}

void MaybeEmitAttachSummary() {
    if (!g_state.bootstrapReady.load(std::memory_order_acquire))
        return;
    if (!g_state.engineReady.load(std::memory_order_acquire))
        return;

    uint64_t nowMs = NowMs();
    bool builderAttached = Net::IsSendBuilderAttached();
    uint64_t start = g_state.attachStartTick.load(std::memory_order_acquire);
    if (start == 0) {
        uint64_t expected = 0;
        if (g_state.attachStartTick.compare_exchange_strong(expected, nowMs, std::memory_order_acq_rel)) {
            start = nowMs;
            if (!builderAttached) {
                std::thread([]() {
                    std::this_thread::sleep_for(std::chrono::milliseconds(kAttachSummaryGraceMs));
                    MaybeEmitAttachSummary();
                }).detach();
            }
        } else {
            start = expected;
        }
    }

    if (!builderAttached && nowMs - start < kAttachSummaryGraceMs)
        return;

    bool expected = false;
    if (!g_state.attachSummaryEmitted.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    const GlobalStateInfo* info = Engine::Info();
    void* ctx = info ? info->engineContext : nullptr;
    const char* helperStage = Engine::Lua::GetHelperStageSummary();
    Walk::Controller::Settings walkSettings = Walk::Controller::GetSettings();

    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "attach summary ctx=%p helpers=%s builder=%s walk.enable=%d stepDelayMs=%u",
              ctx,
              helperStage ? helperStage : "unknown",
              builderAttached ? "attached" : "pending",
              walkSettings.enabled ? 1 : 0,
              walkSettings.stepDelayMs);

    if (g_state.selfTestRequested.load(std::memory_order_acquire) &&
        !g_state.selfTestEmitted.exchange(true, std::memory_order_acq_rel)) {
        std::thread(RunSelfTest).detach();
    }
}

} // namespace

namespace Core::StartupSummary {
void Initialize(bool movementHooksOk,
                bool packetTraceOk,
                bool sendBuilderOk,
                bool luaBridgeOk) {
    g_state.movementHooks.store(movementHooksOk ? 1 : 0, std::memory_order_release);
    g_state.packetTrace.store(packetTraceOk ? 1 : 0, std::memory_order_release);
    g_state.sendBuilder.store(sendBuilderOk ? 1 : 0, std::memory_order_release);
    g_state.luaBridge.store(luaBridgeOk ? 1 : 0, std::memory_order_release);
    g_state.summaryEmitted.store(false, std::memory_order_release);
    g_state.attachSummaryEmitted.store(false, std::memory_order_release);
    g_state.selfTestEmitted.store(false, std::memory_order_release);
    g_state.attachStartTick.store(0, std::memory_order_release);
    g_state.bootstrapReady.store(true, std::memory_order_release);

    bool selfTest = false;
    if (auto flag = Core::Config::TryGetEnvBool("UOWALK_SELFTEST"))
        selfTest = *flag;
    g_state.selfTestRequested.store(selfTest, std::memory_order_release);

    Engine::Lua::StartupStatus luaStatus{};
    Engine::Lua::GetStartupStatus(luaStatus);
    if (luaStatus.helpersInstalled)
        NotifyHelpersReady();
    if (luaStatus.engineContextDiscovered)
        NotifyEngineContextReady();

    MaybeEmitSummary();
    MaybeEmitAttachSummary();
}

void NotifyHelpersReady() {
    bool wasReady = g_state.helpersReady.exchange(true, std::memory_order_acq_rel);
    if (!wasReady) {
        MaybeEmitSummary();
        MaybeEmitAttachSummary();
    }
}

void NotifyEngineContextReady() {
    bool wasReady = g_state.engineReady.exchange(true, std::memory_order_acq_rel);
    if (!wasReady) {
        MaybeEmitSummary();
        MaybeEmitAttachSummary();
    }
}

void NotifyLuaHeartbeat() {
    bool wasReady = g_state.luaHeartbeat.exchange(true, std::memory_order_acq_rel);
    if (!wasReady) {
        MaybeEmitSummary();
        MaybeEmitAttachSummary();
    }
}

void NotifySendBuilderReady() {
    g_state.sendBuilder.store(1, std::memory_order_release);
    MaybeEmitAttachSummary();
}

} // namespace Core::StartupSummary
