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
    void OnEngineReady();
    void NotifyCanonicalManagerDiscovered();
    void NotifyGlobalStateManager(void* netMgr);
    void SubmitSendSample(void* endpoint, void** frames, USHORT captured, std::uint64_t nowMs);
    bool IsSendSamplingEnabled();
}
