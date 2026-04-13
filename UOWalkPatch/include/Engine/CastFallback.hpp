#pragma once

#include <cstdint>

namespace Engine::CastFallback {

struct ExpectedCastResult {
    bool buildMatched = false;
    bool enqueueMatched = false;
    bool hooksActive = false;
    std::uintptr_t buildAction = 0;
    std::uintptr_t enqueueAction = 0;
    std::uint32_t spellId = 0;
    std::uint32_t targetType = 0;
    std::uint32_t targetId = 0;
    std::uint8_t flag18 = 0;
    std::uintptr_t queueSlot0Before = 0;
    std::uintptr_t queueSlot1Before = 0;
    std::uintptr_t queueSlot0After = 0;
    std::uintptr_t queueSlot1After = 0;
};

void Init();
void Shutdown();
bool IsNativeHookActive();
void ArmExpectedCast(std::uint32_t token,
                     std::uint32_t spellId,
                     std::uint32_t targetType,
                     std::uint32_t targetId,
                     bool onId);
ExpectedCastResult ConsumeExpectedCast(std::uint32_t token);

}
