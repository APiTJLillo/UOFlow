#pragma once
#include <stdint.h>

namespace Engine {
    bool InitMovementHooks();
    void ShutdownMovementHooks();

    void PushFastWalkKey(uint32_t key);
    uint32_t PopFastWalkKey();

    bool MovementReady();
    void RequestWalkRegistration();
}

extern "C" __declspec(dllexport) void __stdcall SendWalk(int dir, int run);

