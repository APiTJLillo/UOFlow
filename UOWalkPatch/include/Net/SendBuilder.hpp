#pragma once
#include <cstdint>
#include <winsock2.h>
#include "../include/Engine/GlobalState.hpp"

namespace Net {
    bool InitSendBuilder(GlobalStateInfo* state);
    void ShutdownSendBuilder();
    bool SendPacketRaw(const void* bytes, int len, SOCKET socketHint = INVALID_SOCKET);
    bool IsSendReady();
    bool IsSendBuilderAttached();
    void PollSendBuilder();
}
