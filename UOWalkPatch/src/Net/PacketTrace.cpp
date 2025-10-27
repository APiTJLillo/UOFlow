#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <minhook.h>
#include <cstdint>

#include "Core/Logging.hpp"
#include "Core/Utils.hpp"
#include "Net/PacketTrace.hpp"
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
static bool shouldLogTraces = false;

static void TraceOutbound(const char* buf, int len)
{
    Logf("send-family len=%d id=%02X", len, (unsigned char)buf[0]);
    int dumpLen = len > 64 ? 64 : len;
    if (dumpLen > 0 && shouldLogTraces)
        DumpMemory("Outbound packet", (void*)buf, dumpLen);
}

static void TraceInbound(const char* buf, int len)
{
    Logf("recv-family len=%d id=%02X", len, (unsigned char)buf[0]);
    int dumpLen = len > 64 ? 64 : len;
    if (dumpLen > 0 && shouldLogTraces)
        DumpMemory("Inbound packet", (void*)buf, dumpLen);
    if ((unsigned char)buf[0] == 0xB8 && len >= 5)
    {
        uint32_t key = ntohl(*(uint32_t*)(buf + 1));
        Engine::PushFastWalkKey(key);
    }
    else if (len >= 6 && (unsigned char)buf[0] == 0xBF)
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
                Engine::PushFastWalkKey(key);
                p += 4;
            }
        }
        else if (sub == 0x02 && len >= 5 + 1 + 4)
        {
            uint32_t key = ntohl(*(uint32_t*)(payload + 1));
            Engine::PushFastWalkKey(key);
        }
    }
}

static int WSAAPI H_Send(SOCKET s, const char* buf, int len, int flags)
{
    TraceOutbound(buf, len);
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
    if (cnt)
        TraceOutbound(wsa[0].buf, (int)wsa[0].len);
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
    if (cnt)
        TraceOutbound(wsa[0].buf, (int)wsa[0].len);
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
    TraceOutbound(buf, len);
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
        TraceInbound(buf, rc);
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
        TraceInbound(wsa[0].buf, (int)*recvd);
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
        TraceInbound(wsa[0].buf, (int)*recvd);
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
        TraceInbound(buf, rc);
    return rc;
}

static void InstallSendHooks()
{
    HMODULE ws = GetModuleHandleA("ws2_32.dll");
    if (!ws) ws = LoadLibraryA("ws2_32.dll");
    if (!ws) return;
    struct HookDef { const char* name; void* hook; void** tramp; };
    HookDef tbl[] = {
        {"send",      (void*)H_Send,      (void**)&g_real_send},
        {"WSASend",   (void*)H_WSASend,   (void**)&g_real_WSASend},
        {"WSASendTo", (void*)H_WSASendTo, (void**)&g_real_WSASendTo},
        {"sendto",    (void*)H_SendTo,    (void**)&g_real_sendto},
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
        "recv", "WSARecv", "WSARecvFrom", "recvfrom"
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

} // namespace Net

