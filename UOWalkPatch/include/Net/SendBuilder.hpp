#pragma once
#include <cstdint>
#include <winsock2.h>
#include "Net/ScannerStage3.hpp"
#include "../include/Engine/GlobalState.hpp"

namespace Net {
    bool InitSendBuilder(GlobalStateInfo* state);
    void ShutdownSendBuilder();
    bool SendPacketRaw(const void* bytes, int len, SOCKET socketHint = INVALID_SOCKET);
    bool IsSendReady();
    bool IsSendBuilderAttached();
    void PollSendBuilder();
    void GetSendBuilderProbeStats(uint32_t& attempted, uint32_t& succeeded, uint32_t& skipped);
    struct SendBuilderStatus {
        bool hooked = false;
        bool probing = false;
        void* sendPacket = nullptr;
    };
    SendBuilderStatus GetSendBuilderStatus();
    Scanner::ScanPassTelemetry DumpLastPassTelemetry();
}
