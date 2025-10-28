#pragma once
#include <stdint.h>
#include <winsock2.h>
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

    void PushFastWalkKey(SOCKET socket, uint32_t key);
    uint32_t PopFastWalkKey();
    uint32_t PopFastWalkKey(SOCKET socket);
    uint32_t PeekFastWalkKey();
    uint32_t PeekFastWalkKey(SOCKET socket);
    int FastWalkQueueDepth();
    int FastWalkQueueDepth(SOCKET socket);
    SOCKET GetActiveFastWalkSocket();
    void SetActiveFastWalkSocket(SOCKET socket);
    void OnSocketClosed(SOCKET socket);
    void RecordObservedFastWalkKey(uint32_t key);
    void RecordMovementSent(uint8_t seq);
    void RecordMovementAck(uint8_t seq, uint8_t status);
    void RecordMovementReject(uint8_t seq);

    bool MovementReady();
    bool MovementReadyWithReason(const char** reasonOut);
    void GetMovementDebugStatus(MovementDebugStatus& out);
    void RequestWalkRegistration();
}

extern "C" __declspec(dllexport) bool __stdcall SendWalk(int dir, int run);
