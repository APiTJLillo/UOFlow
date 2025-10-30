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

    struct MovementSnapshot {
        uint32_t head = 0;
        uint32_t tail = 0;
        uint32_t stateFlags = 0;
        float posX = 0.0f;
        float posZ = 0.0f;
    };

    struct FastWalkCounters {
        uint64_t keysInbound = 0;
        uint64_t keysOutbound = 0;
        uint32_t depth = 0;
        uint64_t resyncs = 0;
        uint64_t misses = 0;
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
    // Track inbound FastWalk keys for reconciliation with movement snapshots and timeout checks.
    void RecordInboundFastWalkKey(SOCKET socket, uint32_t key, int depthBefore, int depthAfter, uint64_t tickMs);
    SOCKET ResolveFastWalkSocket(SOCKET socket);
    void ResyncFastWalk(SOCKET socket, const char* reason, uint32_t maxInflightOverride = 0);
    void RecordMovementSent(uint8_t seq);
    void RecordMovementAck(uint8_t seq, uint8_t status);
    void RecordMovementReject(uint8_t seq, uint8_t status);
    enum class MovementAckAction : uint8_t { Ignore = 0, Ok, Drop, Resync };

    struct MovementAckResult {
        MovementAckAction action = MovementAckAction::Ignore;
        uint8_t expected = 0;
        uint32_t dropped = 0;
    };

    MovementAckResult ProcessMovementAck(SOCKET socket, uint8_t seq, uint8_t status);

    void TrackMovementTx(uint8_t seq, int dir, bool run, SOCKET socket, uint32_t key, const char* sender);
    bool IsScriptedMovementSendInProgress();
    bool HaveSentSequence();
    bool HaveAckSequence();
    uint8_t GetLastSentSequence();
    uint8_t GetLastAckSequence();
    void NotifyClientMovementSent();
    void ArmMovementSendWatchdog();
    bool DisarmAndCheckMovementSend(uint32_t timeoutMs = 100);
    void GetFastWalkCounters(FastWalkCounters& out);
    uint64_t GetWalkStepsSent();

    bool MovementReady();
    bool MovementReadyWithReason(const char** reasonOut);
    void GetMovementDebugStatus(MovementDebugStatus& out);
    bool GetLastMovementSnapshot(MovementSnapshot& outSnapshot);
    void RequestWalkRegistration();
}

extern "C" __declspec(dllexport) bool __stdcall SendWalk(int dir, int run);
