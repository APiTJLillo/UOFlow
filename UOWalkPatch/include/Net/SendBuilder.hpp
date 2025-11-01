#pragma once
#include <cstdint>
#include <winsock2.h>
#include "Net/ScannerStage3.hpp"
#include "../include/Engine/GlobalState.hpp"

namespace Net {
    enum class WakeReason : std::uint8_t {
        LoginTransition = 0,
        NetCfgSettled,
        AckNudge,
        OwnerPumpClear,
        Manual,
        Count
    };

    enum class Stage3ScanState : std::uint8_t {
        Idle = 0,
        Running,
        Backoff
    };

    struct Stage3ScanConfig {
        std::uint32_t vtbl_scan_slots = 0;
        std::uint32_t depth = 0;
        std::uint32_t window = 0;
    };

    struct Stage3ScanStats {
        std::uint32_t candidates = 0;
        std::uint32_t accepted = 0;
        std::uint32_t rejected = 0;
        std::uint32_t ttfs_ms = 0;
        void* firstCandidate = nullptr;
        void* firstExecutable = nullptr;
    };

    bool InitSendBuilder(GlobalStateInfo* state);
    void ShutdownSendBuilder();
    bool SendPacketRaw(const void* bytes, int len, SOCKET socketHint = INVALID_SOCKET);
    bool IsSendReady();
    bool IsSendBuilderAttached();
    void PollSendBuilder();
    void GetSendBuilderProbeStats(uint32_t& attempted, uint32_t& succeeded, uint32_t& skipped);
    void ForceScan(WakeReason reason);
    void SoftNudgeBuilder(std::uint32_t minDelayMs, std::uint32_t maxDelayMs);
    struct SendBuilderStatus {
        bool hooked = false;
        bool probing = false;
        void* sendPacket = nullptr;
        void* netMgr = nullptr;
    };
    SendBuilderStatus GetSendBuilderStatus();
    Scanner::ScanPassTelemetry DumpLastPassTelemetry();
    Stage3ScanStats GetStage3ScanStats();
    Stage3ScanConfig GetStage3ScanConfig();
    Stage3ScanState GetStage3ScanState();
    void OnEngineReady();
    void NotifyCanonicalManagerDiscovered();
    void NotifyGlobalStateManager(void* netMgr);
    void SubmitSendSample(void* endpoint, void** frames, USHORT captured, std::uint64_t nowMs);
    bool IsSendSamplingEnabled();
}
