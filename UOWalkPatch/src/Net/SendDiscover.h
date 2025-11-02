#pragma once

#include <windows.h>

namespace uow::net {
    // Returns discovered SendPacket pointer (or nullptr if not yet found)
    void* DiscoverSendPacketFromWsasendReturnAddress(void* returnAddress);

    // Globally accessible once discovered
    void* GetSendPacket();
} // namespace uow::net

// Provide a helper you can call once to attempt install detour on SendPacket
bool Uow_AttemptInstallSendPacketHook(void* sendPacketAddr);

