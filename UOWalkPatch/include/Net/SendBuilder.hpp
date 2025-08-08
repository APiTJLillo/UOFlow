#pragma once
#include <cstdint>
#include "../include/Engine/GlobalState.hpp"

namespace Net {
    bool InitSendBuilder(GlobalStateInfo* state);
    void ShutdownSendBuilder();
    bool SendPacketRaw(const void* bytes, int len);
    bool IsSendReady();
}

