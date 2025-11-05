#pragma once
#include <stdint.h>
#include <windows.h>

// Declare g_needWalkReg so it's accessible to other translation units
extern volatile LONG g_needWalkReg;

namespace Engine {
    bool InitMovementHooks();
    void ShutdownMovementHooks();

    void PushFastWalkKey(uint32_t key);
    uint32_t PopFastWalkKey();

    bool MovementReady();
    void RequestWalkRegistration();
}

extern "C" __declspec(dllexport) bool __stdcall SendWalk(int dir, int run);
