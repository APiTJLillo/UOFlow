#pragma once

#include <winsock2.h>

namespace Net {
    bool InitPacketTrace();
    void ShutdownPacketTrace();
    SOCKET GetLastSocket();
    void InvalidateLastSocket();
}


