#pragma once

#include <cstdint>

#include "Engine/Movement.hpp"

namespace Walk::Controller {
    void Reset();
    bool IsEnabled();
    bool RequestTarget(float x, float y, float z, bool run);
    void Cancel();
    void OnMovementSnapshot(const Engine::MovementSnapshot& snapshot,
                            bool headChanged,
                            std::uint32_t tickMs);
}
