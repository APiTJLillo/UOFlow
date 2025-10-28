#pragma once

#include <winsock2.h>

namespace Net {
    bool InitPacketTrace();
    void ShutdownPacketTrace();
    SOCKET GetLastSocket();
    SOCKET GetPreferredSocket();
    void InvalidateLastSocket();
    void SetPreferredSocket(SOCKET socket);
}


