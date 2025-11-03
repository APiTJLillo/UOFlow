#pragma once

#include <cstdint>

#include "Engine/Movement.hpp"

namespace Walk::Controller {
    struct Settings {
        bool enabled = false;
        std::uint32_t maxInflight = 0;
        std::uint32_t stepDelayMs = 0;
        std::uint32_t timeoutMs = 0;
        bool debug = false;
    };

    void Reset();
    bool IsEnabled();
    Settings GetSettings();
    bool DebugEnabled();
    bool RequestTarget(float x, float y, float z, bool run);
    void Cancel();
    void OnMovementSnapshot(const Engine::MovementSnapshot& snapshot,
                            bool headChanged,
                            std::uint32_t tickMs);
    void ApplyInflightOverride(std::uint32_t maxInflight, std::uint32_t cycleBudget);
    std::uint32_t GetInflightCount();
    void NotifyAckOk();
    void NotifyAckSoftFail();
    void NotifyResync(const char* reason);
    std::uint32_t GetStepDelayMs();
    void SetStepDelayMs(std::uint32_t ms);
    void SetMaxInflight(std::uint32_t count);
}
