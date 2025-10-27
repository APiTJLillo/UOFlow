#pragma once
#include <stdint.h>
#include <windows.h>

// Declare g_needWalkReg so it's accessible to other translation units
extern volatile LONG g_needWalkReg;

namespace Engine {
    bool InitMovementHooks();
    void ShutdownMovementHooks();

    struct MovementDebugStatus {
        bool ready;
        bool updateHookInstalled;
        bool movementComponentCaptured;
        bool movementCandidatePending;
        bool pendingMoveActive;
        uint32_t pendingAgeMs;
        int pendingDir;
        bool pendingRun;
        void* movementComponentPtr;
        void* movementCandidatePtr;
        void* destinationPtr;
        int fastWalkDepth;
    };

    void PushFastWalkKey(uint32_t key);
    uint32_t PopFastWalkKey();
    uint32_t PeekFastWalkKey();
    int FastWalkQueueDepth();
    void RecordObservedFastWalkKey(uint32_t key);

    bool MovementReady();
    bool MovementReadyWithReason(const char** reasonOut);
    void GetMovementDebugStatus(MovementDebugStatus& out);
    void RequestWalkRegistration();
}

extern "C" __declspec(dllexport) bool __stdcall SendWalk(int dir, int run);
