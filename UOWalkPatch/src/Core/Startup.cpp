#include "Core/Startup.hpp"

#include <atomic>
#include <sstream>

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
};

SummaryState g_state;

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
    g_state.bootstrapReady.store(true, std::memory_order_release);

    Engine::Lua::StartupStatus luaStatus{};
    Engine::Lua::GetStartupStatus(luaStatus);
    if (luaStatus.helpersInstalled)
        NotifyHelpersReady();
    if (luaStatus.engineContextDiscovered)
        NotifyEngineContextReady();

    MaybeEmitSummary();
}

void NotifyHelpersReady() {
    bool wasReady = g_state.helpersReady.exchange(true, std::memory_order_acq_rel);
    if (!wasReady)
        MaybeEmitSummary();
}

void NotifyEngineContextReady() {
    bool wasReady = g_state.engineReady.exchange(true, std::memory_order_acq_rel);
    if (!wasReady)
        MaybeEmitSummary();
}

void NotifyLuaHeartbeat() {
    bool wasReady = g_state.luaHeartbeat.exchange(true, std::memory_order_acq_rel);
    if (!wasReady)
        MaybeEmitSummary();
}
} // namespace Core::StartupSummary
