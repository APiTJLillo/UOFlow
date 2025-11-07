#pragma once

namespace Net {
    bool InitPacketTrace();
    void ShutdownPacketTrace();
    // Monotonic counter of outbound send-family calls (send/WSASend/etc.).
    // Useful for correlating whether a user action resulted in a packet.
    unsigned GetSendCounter();
    void IncrementSendCounter();
}
