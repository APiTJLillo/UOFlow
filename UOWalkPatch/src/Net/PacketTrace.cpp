#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <minhook.h>
#include <cstdio>
#include <cstdint>
#include <atomic>

#include "Core/Logging.hpp"
#include "Core/Utils.hpp"
#include "Net/PacketTrace.hpp"
#include "Net/SendBuilder.hpp"
#include "Engine/Movement.hpp"

namespace {

static int (WSAAPI* g_real_send)(SOCKET, const char*, int, int) = nullptr;
static int (WSAAPI* g_real_WSASend)(SOCKET, const WSABUF*, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) = nullptr;
static int (WSAAPI* g_real_WSASendTo)(SOCKET, const WSABUF*, DWORD, LPDWORD, DWORD, const sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) = nullptr;
static int (WSAAPI* g_real_sendto)(SOCKET, const char*, int, int, const sockaddr*, int) = nullptr;
static int (WSAAPI* g_real_recv)(SOCKET, char*, int, int) = nullptr;
static int (WSAAPI* g_real_WSARecv)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) = nullptr;
static int (WSAAPI* g_real_WSARecvFrom)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) = nullptr;
static int (WSAAPI* g_real_recvfrom)(SOCKET, char*, int, int, sockaddr*, int*) = nullptr;
static int (WSAAPI* g_real_closesocket)(SOCKET) = nullptr;
static bool shouldLogTraces = true;
static volatile LONG g_fastWalkScanMissBudget = 8;
static SOCKET g_lastSocket = INVALID_SOCKET;
static SOCKET g_lastLoggedSocket = INVALID_SOCKET;
static std::atomic<SOCKET> g_preferredSocket{INVALID_SOCKET};

static constexpr int kFastWalkReserveDepth = 2;

static bool EvaluateFastWalkGate(const char* buf, int len, bool& suppressOut, int& depthOut)
{
    suppressOut = false;
    depthOut = 0;

    if (!buf || len <= 0)
        return false;

    if (static_cast<unsigned char>(buf[0]) != 0x2E)
        return false;

    depthOut = Engine::FastWalkQueueDepth();
    suppressOut = depthOut >= kFastWalkReserveDepth;
    return true;
}

static void LogFastWalkGateDecision(const char* action, SOCKET s, int depth)
{
    static volatile LONG budget = 16;
    if (budget > 0 && InterlockedDecrement(&budget) >= 0) {
        Logf("FastWalk gate %s opcode=0x2E socket=%p depth=%d reserve=%d",
             action,
             reinterpret_cast<void*>(static_cast<uintptr_t>(s)),
             depth,
             kFastWalkReserveDepth);
        char buf[160];
        sprintf_s(buf, sizeof(buf),
                  "FastWalk gate %s: opcode=0x2E socket=%p depth=%d reserve=%d",
                  action,
                  reinterpret_cast<void*>(static_cast<uintptr_t>(s)),
                  depth,
                  kFastWalkReserveDepth);
        WriteRawLog(buf);
    }
}

static void LogInboundFastWalkKey(const char* source, SOCKET socket, uint32_t key, int depthBefore)
{
    static volatile LONG budget = 48;
    if (budget > 0 && InterlockedDecrement(&budget) >= 0) {
        int depthAfter = Engine::FastWalkQueueDepth(socket);
        Logf("FastWalk inbound %s socket=%p key=%08X depth=%d->%d",
             source,
             reinterpret_cast<void*>(static_cast<uintptr_t>(socket)),
             key,
             depthBefore,
             depthAfter);
        char buf[192];
        sprintf_s(buf, sizeof(buf),
                  "FastWalk inbound %s socket=%p key=%08X depth=%d->%d",
                  source,
                  reinterpret_cast<void*>(static_cast<uintptr_t>(socket)),
                  key,
                  depthBefore,
                  depthAfter);
        WriteRawLog(buf);
    }
}

static void NoteSocketActivity(SOCKET s)
{
    if (s == INVALID_SOCKET)
        return;
    g_lastSocket = s;
    SOCKET expected = INVALID_SOCKET;
    g_preferredSocket.compare_exchange_strong(expected, s);
}

static void UpdatePreferredSocket(SOCKET s)
{
    if (s == INVALID_SOCKET) {
        g_preferredSocket.store(INVALID_SOCKET);
        return;
    }
    g_preferredSocket.store(s);
    g_lastSocket = s;
}

static void HandleSocketInvalidated(SOCKET s)
{
    if (s == INVALID_SOCKET)
        return;
    SOCKET expected = s;
    g_preferredSocket.compare_exchange_strong(expected, INVALID_SOCKET);
    if (g_lastSocket == s)
        g_lastSocket = INVALID_SOCKET;
    Engine::OnSocketClosed(s);
}

static uint32_t ExtractFastWalkKey0x2E(const char* buf, int len)
{
    if (!buf || len < 7)
        return 0;
    uint32_t b3 = static_cast<uint8_t>(buf[3]);
    uint32_t b4 = static_cast<uint8_t>(buf[4]);
    uint32_t b5 = static_cast<uint8_t>(buf[5]);
    uint32_t b6 = static_cast<uint8_t>(buf[6]);
    return (b3 << 24) | (b4 << 16) | (b5 << 8) | b6;
}

static void LogFastWalkReceipt(SOCKET socket, const char* source, uint32_t key)
{
    static volatile LONG s_budget = 32;
    if (!source)
        source = "?";
    if (s_budget > 0 && InterlockedDecrement(&s_budget) >= 0) {
        Logf("FastWalk key received via %s socket=%p key=%08X depth=%d",
             source,
             reinterpret_cast<void*>(static_cast<uintptr_t>(socket)),
             key,
             Engine::FastWalkQueueDepth(socket));
    }
}

static bool HandleFastWalkKey(SOCKET socket, uint32_t key, const char* source)
{
    if (!key)
        return false;

    Engine::RecordObservedFastWalkKey(key);

    if (Engine::PeekFastWalkKey(socket) == key)
        return false;

    Engine::PushFastWalkKey(socket, key);
    LogFastWalkReceipt(socket, source, key);

    char msg[128];
    sprintf_s(msg, sizeof(msg), "FastWalk(%s) socket=%p key=%08X depth=%d",
              source ? source : "?",
              reinterpret_cast<void*>(static_cast<uintptr_t>(socket)),
              key,
              Engine::FastWalkQueueDepth(socket));
    WriteRawLog(msg);
    return true;
}

static bool ScanFastWalkPayload(SOCKET socket, const char* source, const uint8_t* data, size_t len)
{
    if (!data || len < 4)
        return false;

    // Pattern 1: embedded movement packet (0x02 [flags] [seq] key)
    for (size_t i = 0; i + 7 <= len; ++i) {
        if (data[i] == 0x02 && (data[i + 1] & 0x80)) {
            uint32_t key = (static_cast<uint32_t>(data[i + 3]) << 24) |
                           (static_cast<uint32_t>(data[i + 4]) << 16) |
                           (static_cast<uint32_t>(data[i + 5]) << 8) |
                           static_cast<uint32_t>(data[i + 6]);
            if (HandleFastWalkKey(socket, key, source))
                return true;
        }
    }

    // Pattern 2: big-endian key scan (high byte 0x01)
    for (size_t i = 0; i + 4 <= len; ++i) {
        uint32_t key = (static_cast<uint32_t>(data[i]) << 24) |
                       (static_cast<uint32_t>(data[i + 1]) << 16) |
                       (static_cast<uint32_t>(data[i + 2]) << 8) |
                       static_cast<uint32_t>(data[i + 3]);
        if ((key & 0xFF000000u) == 0x01000000u && HandleFastWalkKey(socket, key, source))
            return true;

        // Pattern 3: little-endian scan
        uint32_t keyLe = static_cast<uint32_t>(data[i]) |
                         (static_cast<uint32_t>(data[i + 1]) << 8) |
                         (static_cast<uint32_t>(data[i + 2]) << 16) |
                         (static_cast<uint32_t>(data[i + 3]) << 24);
        if ((keyLe & 0xFF000000u) == 0x01000000u && HandleFastWalkKey(socket, keyLe, source))
            return true;
    }

    LONG remaining = InterlockedCompareExchange(&g_fastWalkScanMissBudget, 0, 0);
    if (remaining > 0 && InterlockedDecrement(&g_fastWalkScanMissBudget) >= 0) {
        Logf("FastWalk scan miss (%s) len=%zu", source ? source : "?", static_cast<size_t>(len));
        size_t dumpLen = len < 32 ? len : 32;
        if (dumpLen)
            DumpMemory("FastWalk scan sample", const_cast<uint8_t*>(data), static_cast<int>(dumpLen));
    }

    return false;
}

static SOCKET SelectFastWalkSocket(SOCKET fallback)
{
    SOCKET active = Engine::GetActiveFastWalkSocket();
    if (active != INVALID_SOCKET)
        return active;

    SOCKET preferred = Net::GetPreferredSocket();
    if (preferred != INVALID_SOCKET)
        return preferred;

    return fallback;
}

static void TraceOutbound(SOCKET& s, const char* buf, int len)
{
    unsigned char opcode = (len > 0) ? static_cast<unsigned char>(buf[0]) : 0;

    if (opcode == 0x02) {
        s = SelectFastWalkSocket(s);
        if (len >= 7) {
            uint32_t key = ExtractFastWalkKey0x2E(buf, len);
            if (key) {
                char txBuf[160];
                sprintf_s(txBuf, sizeof(txBuf),
                          "FastWalk TX 0x02 via socket=%p key=%08X",
                          reinterpret_cast<void*>(static_cast<uintptr_t>(s)),
                          key);
                WriteRawLog(txBuf);
                Engine::RecordObservedFastWalkKey(key);
            }
        }
    }

    NoteSocketActivity(s);
    if (s != INVALID_SOCKET && s != g_lastLoggedSocket) {
        g_lastLoggedSocket = s;
        char msg[128];
        sprintf_s(msg, sizeof(msg), "TraceOutbound: socket=%p", reinterpret_cast<void*>(static_cast<uintptr_t>(s)));
        WriteRawLog(msg);
    }
    if(shouldLogTraces)
        Logf("send-family len=%d id=%02X", len, opcode);
    int dumpLen = len > 64 ? 64 : len;
    if (dumpLen > 0 && shouldLogTraces)
        DumpMemory("Outbound packet", (void*)buf, dumpLen);

    if (opcode == 0x3C) {
        Engine::SetActiveFastWalkSocket(s);
        Net::SetPreferredSocket(s);
    }

    Net::PollSendBuilder();
}

static void TraceInbound(SOCKET s, const char* buf, int len)
{
    unsigned char opcode = (len > 0) ? static_cast<unsigned char>(buf[0]) : 0;

    NoteSocketActivity(s);
    if(shouldLogTraces)
        Logf("recv-family len=%d id=%02X", len, opcode);
    int dumpLen = len > 64 ? 64 : len;
    if (dumpLen > 0 && shouldLogTraces)
        DumpMemory("Inbound packet", (void*)buf, dumpLen);

    if (opcode == 0x2E && len >= 7) {
        uint32_t key = ExtractFastWalkKey0x2E(buf, len);
        int depthBefore = Engine::FastWalkQueueDepth(s);
        bool accepted = HandleFastWalkKey(s, key, "0x2E");
        if (accepted) {
            LogInboundFastWalkKey("0x2E", s, key, depthBefore);
        } else if (shouldLogTraces) {
            if (key == 0) {
                Logf("FastWalk 0x2E packet ignored len=%d", len);
            } else {
                Logf("FastWalk 0x2E duplicate key=%08X len=%d", key, len);
            }
        }
    } else if ((opcode == 0x7B || opcode == 0x73) && len > 1) {
        const uint8_t* payload = reinterpret_cast<const uint8_t*>(buf + 1);
        size_t payloadLen = static_cast<size_t>(len - 1);
        ScanFastWalkPayload(s, opcode == 0x7B ? "0x7B" : "0x73", payload, payloadLen);
    }

    Net::PollSendBuilder();

    if (opcode == 0x22 && len >= 3) {
        uint8_t seq = static_cast<uint8_t>(buf[1]);
        uint8_t status = static_cast<uint8_t>(buf[2]);
        char ackBuf[128];
        sprintf_s(ackBuf, sizeof(ackBuf),
                  "MovementAck socket=%p seq=%u status=%u",
                  reinterpret_cast<void*>(static_cast<uintptr_t>(s)),
                  static_cast<unsigned>(seq),
                  static_cast<unsigned>(status));
        WriteRawLog(ackBuf);
        Engine::RecordMovementAck(seq, status);
        Engine::SetActiveFastWalkSocket(s);
        Net::SetPreferredSocket(s);
    } else if (opcode == 0x21 && len >= 2) {
        uint8_t seq = static_cast<uint8_t>(buf[1]);
        char rejBuf[128];
        sprintf_s(rejBuf, sizeof(rejBuf),
                  "MovementReject socket=%p seq=%u",
                  reinterpret_cast<void*>(static_cast<uintptr_t>(s)),
                  static_cast<unsigned>(seq));
        WriteRawLog(rejBuf);
        Engine::RecordMovementReject(seq);
        Net::SetPreferredSocket(s);
    }

    if (opcode == 0xB8)
    {
        uint32_t key = 0;
        if (len >= 5) {
            key = ntohl(*(const uint32_t*)(buf + 1));
        } else if (len >= 3) {
            key = ntohs(*(const uint16_t*)(buf + 1));
        }
        int depthBefore = Engine::FastWalkQueueDepth(s);
        bool accepted = HandleFastWalkKey(s, key, "0xB8");
        if (accepted) {
            LogInboundFastWalkKey("0xB8", s, key, depthBefore);
        } else if (shouldLogTraces) {
            if (key == 0) {
                Logf("FastWalk 0xB8 packet ignored len=%d", len);
            } else {
                Logf("FastWalk 0xB8 duplicate key=%08X", key);
            }
        }
    }
    else if (opcode == 0xBF && len >= 6)
    {
        uint16_t sub = ((unsigned char)buf[3] << 8) | (unsigned char)buf[4];
        const uint8_t* payload = (const uint8_t*)buf + 5;
        if (sub == 0x01 && len >= 5 + 1)
        {
            uint8_t count = payload[0];
            const uint8_t* p = payload + 1;
            for (uint8_t i = 0; i < count && (p + 4 <= (const uint8_t*)buf + len); ++i)
            {
                uint32_t key = ntohl(*(uint32_t*)p);
                int depthBefore = Engine::FastWalkQueueDepth(s);
                if (HandleFastWalkKey(s, key, "0xBF:01"))
                    LogInboundFastWalkKey("0xBF:01", s, key, depthBefore);
                p += 4;
            }
        }
        else if (sub == 0x02 && len >= 5 + 1 + 4)
        {
            uint32_t key = ntohl(*(uint32_t*)(payload + 1));
            int depthBefore = Engine::FastWalkQueueDepth(s);
            if (HandleFastWalkKey(s, key, "0xBF:02"))
                LogInboundFastWalkKey("0xBF:02", s, key, depthBefore);
        }
    }
}

static int WSAAPI H_Send(SOCKET s, const char* buf, int len, int flags)
{
    bool suppress = false;
    int depth = 0;
    if (EvaluateFastWalkGate(buf, len, suppress, depth)) {
        if (suppress) {
            LogFastWalkGateDecision("suppressing", s, depth);
            return len;
        }
        LogFastWalkGateDecision("forwarding", s, depth);
    }

    TraceOutbound(s, buf, len);
    return g_real_send ? g_real_send(s, buf, len, flags) : 0;
}

static int WSAAPI H_WSASend(
    SOCKET s,
    const WSABUF* wsa,
    DWORD cnt,
    LPDWORD sent,
    DWORD flags,
    LPWSAOVERLAPPED ov,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    if (cnt) {
        bool suppress = false;
        int depth = 0;
        if (EvaluateFastWalkGate(wsa[0].buf, static_cast<int>(wsa[0].len), suppress, depth)) {
            if (suppress) {
                LogFastWalkGateDecision("suppressing", s, depth);
                if (sent)
                    *sent = wsa[0].len;
                return 0;
            }
            LogFastWalkGateDecision("forwarding", s, depth);
        }
        TraceOutbound(s, wsa[0].buf, (int)wsa[0].len);
    }
    return g_real_WSASend ? g_real_WSASend(s, wsa, cnt, sent, flags, ov, cr) : 0;
}

static int WSAAPI H_WSASendTo(
    SOCKET s,
    const WSABUF* wsa,
    DWORD cnt,
    LPDWORD sent,
    DWORD flags,
    const sockaddr* dst,
    int dstlen,
    LPWSAOVERLAPPED ov,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    if (cnt) {
        bool suppress = false;
        int depth = 0;
        if (EvaluateFastWalkGate(wsa[0].buf, static_cast<int>(wsa[0].len), suppress, depth)) {
            if (suppress) {
                LogFastWalkGateDecision("suppressing", s, depth);
                if (sent)
                    *sent = wsa[0].len;
                return 0;
            }
            LogFastWalkGateDecision("forwarding", s, depth);
        }
        TraceOutbound(s, wsa[0].buf, (int)wsa[0].len);
    }
    return g_real_WSASendTo ? g_real_WSASendTo(s, wsa, cnt, sent, flags, dst, dstlen, ov, cr) : 0;
}

static int WSAAPI H_SendTo(
    SOCKET s,
    const char* buf,
    int len,
    int flags,
    const sockaddr* to,
    int tolen)
{
    bool suppress = false;
    int depth = 0;
    if (EvaluateFastWalkGate(buf, len, suppress, depth)) {
        if (suppress) {
            LogFastWalkGateDecision("suppressing", s, depth);
            return len;
        }
        LogFastWalkGateDecision("forwarding", s, depth);
    }

    TraceOutbound(s, buf, len);
    return g_real_sendto ? g_real_sendto(s, buf, len, flags, to, tolen) : 0;
}

static int WSAAPI H_Recv(
    SOCKET s,
    char* buf,
    int len,
    int flags)
{
    int rc = g_real_recv ? g_real_recv(s, buf, len, flags) : 0;
    if (rc > 0)
        TraceInbound(s, buf, rc);
    return rc;
}

static int WSAAPI H_WSARecv(
    SOCKET s,
    LPWSABUF wsa,
    DWORD cnt,
    LPDWORD recvd,
    LPDWORD flags,
    LPWSAOVERLAPPED ov,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    int rc = g_real_WSARecv ? g_real_WSARecv(s, wsa, cnt, recvd, flags, ov, cr) : 0;
    if (rc == 0 && cnt && recvd && *recvd)
        TraceInbound(s, wsa[0].buf, (int)*recvd);
    return rc;
}

static int WSAAPI H_WSARecvFrom(
    SOCKET s,
    LPWSABUF wsa,
    DWORD cnt,
    LPDWORD recvd,
    LPDWORD flags,
    sockaddr* from,
    LPINT fromlen,
    LPWSAOVERLAPPED ov,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    int rc = g_real_WSARecvFrom ? g_real_WSARecvFrom(s, wsa, cnt, recvd, flags, from, fromlen, ov, cr) : 0;
    if (rc == 0 && cnt && recvd && *recvd)
        TraceInbound(s, wsa[0].buf, (int)*recvd);
    return rc;
}

static int WSAAPI H_RecvFrom(
    SOCKET s,
    char* buf,
    int len,
    int flags,
    sockaddr* from,
    int* fromlen)
{
    int rc = g_real_recvfrom ? g_real_recvfrom(s, buf, len, flags, from, fromlen) : 0;
    if (rc > 0)
        TraceInbound(s, buf, rc);
    return rc;
}

static int WSAAPI H_CloseSocket(SOCKET s)
{
    int rc = g_real_closesocket ? g_real_closesocket(s) : 0;
    if (rc == 0)
        HandleSocketInvalidated(s);
    return rc;
}

static void InstallSendHooks()
{
    HMODULE ws = GetModuleHandleA("ws2_32.dll");
    if (!ws) ws = LoadLibraryA("ws2_32.dll");
    if (!ws) return;
    struct HookDef { const char* name; void* hook; void** tramp; };
    HookDef tbl[] = {
        {"send",        (void*)H_Send,        (void**)&g_real_send},
        {"WSASend",     (void*)H_WSASend,     (void**)&g_real_WSASend},
        {"WSASendTo",   (void*)H_WSASendTo,   (void**)&g_real_WSASendTo},
        {"sendto",      (void*)H_SendTo,      (void**)&g_real_sendto},
        {"closesocket", (void*)H_CloseSocket, (void**)&g_real_closesocket},
    };
    for (auto& e : tbl)
    {
        void* target = GetProcAddress(ws, e.name);
        if (target && MH_CreateHook(target, e.hook, e.tramp) == MH_OK && MH_EnableHook(target) == MH_OK)
            Logf("%s hook installed", e.name);
    }
}

static void InstallRecvHooks()
{
    HMODULE ws = GetModuleHandleA("ws2_32.dll");
    if (!ws) ws = LoadLibraryA("ws2_32.dll");
    if (!ws) return;
    struct HookDef { const char* name; void* hook; void** tramp; };
    HookDef tbl[] = {
        {"recv",       (void*)H_Recv,       (void**)&g_real_recv},
        {"WSARecv",    (void*)H_WSARecv,    (void**)&g_real_WSARecv},
        {"WSARecvFrom",(void*)H_WSARecvFrom,(void**)&g_real_WSARecvFrom},
        {"recvfrom",   (void*)H_RecvFrom,   (void**)&g_real_recvfrom},
    };
    for (auto& e : tbl)
    {
        void* target = GetProcAddress(ws, e.name);
        if (target && MH_CreateHook(target, e.hook, e.tramp) == MH_OK && MH_EnableHook(target) == MH_OK)
            Logf("%s hook installed", e.name);
    }
}

static void RemoveHooks()
{
    HMODULE ws = GetModuleHandleA("ws2_32.dll");
    if (!ws) return;
    const char* names[] = {
        "send", "WSASend", "WSASendTo", "sendto",
        "recv", "WSARecv", "WSARecvFrom", "recvfrom",
        "closesocket"
    };
    for (const char* name : names)
    {
        void* target = GetProcAddress(ws, name);
        if (target)
            MH_RemoveHook(target);
    }
}

} // anonymous namespace

namespace Net {

bool InitPacketTrace()
{
    InstallSendHooks();
    InstallRecvHooks();
    return true;
}

void ShutdownPacketTrace()
{
    RemoveHooks();
}

SOCKET GetLastSocket()
{
    SOCKET preferred = g_preferredSocket.load();
    if (preferred != INVALID_SOCKET)
        return preferred;
    return g_lastSocket;
}

SOCKET GetPreferredSocket()
{
    return g_preferredSocket.load();
}

void InvalidateLastSocket()
{
    SOCKET last = g_lastSocket;
    HandleSocketInvalidated(last);
}

void SetPreferredSocket(SOCKET s)
{
    UpdatePreferredSocket(s);
}


} // namespace Net
