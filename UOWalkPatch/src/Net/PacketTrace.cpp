#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <minhook.h>
#include <psapi.h>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <optional>

#include "Core/Logging.hpp"
#include "Core/Utils.hpp"
#include "Core/Config.hpp"
#include "Net/PacketTrace.hpp"
#include "Engine/Movement.hpp"
#include "Engine/LuaBridge.hpp"
#include "Net/SendBuilder.hpp"
#include "CastCorrelator.h"

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
static volatile LONG g_sendCounter = 0;
static bool g_captureWinsockStacks = false;
static volatile LONG g_winsockStackBudget = 0;
static bool g_packetIdFilterEnabled = false;
static unsigned g_packetIdFilter = 0;

static void LogWinsockStack(const char* apiTag)
{
    void* frames[16]{};
    // Skip hook+TraceOutbound frames (approx. 2)
    USHORT captured = RtlCaptureStackBackTrace(2, 16, frames, nullptr);
    char header[96];
    sprintf_s(header, sizeof(header), "[PacketTrace] %s call stack:", apiTag ? apiTag : "winsock");
    WriteRawLog(header);
    for (USHORT i = 0; i < captured; ++i) {
        if (!frames[i])
            continue;
        HMODULE mod = nullptr;
        char modName[MAX_PATH] = {};
        DWORD_PTR base = 0;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCSTR>(frames[i]), &mod)) {
            MODULEINFO mi{};
            if (GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
                base = reinterpret_cast<DWORD_PTR>(mi.lpBaseOfDll);
            GetModuleBaseNameA(GetCurrentProcess(), mod, modName, ARRAYSIZE(modName));
        }
        char line[160];
        if (modName[0])
            sprintf_s(line, sizeof(line), "[PacketTrace]    #%u %s+0x%llX (%p)",
                static_cast<unsigned>(i),
                modName,
                static_cast<unsigned long long>(reinterpret_cast<DWORD_PTR>(frames[i]) - base),
                frames[i]);
        else
            sprintf_s(line, sizeof(line), "[PacketTrace]    #%u %p", static_cast<unsigned>(i), frames[i]);
        WriteRawLog(line);
    }
}

static bool ShouldCaptureWinsockStack(unsigned char packetId)
{
    if (!g_captureWinsockStacks)
        return false;
    if (g_packetIdFilterEnabled && packetId != g_packetIdFilter)
        return false;
    if (InterlockedCompareExchange(&g_winsockStackBudget, 0, 0) <= 0)
        return false;
    return InterlockedDecrement(&g_winsockStackBudget) >= 0;
}

static bool TryParsePacketId(const std::string& text, unsigned& out)
{
    if (text.empty())
        return false;
    char* end = nullptr;
    unsigned long value = std::strtoul(text.c_str(), &end, 0);
    if (!end || *end != '\0' || value > 0xFF)
        return false;
    out = static_cast<unsigned>(value);
    return true;
}

static void TraceOutbound(const char* apiTag, const char* buf, int len)
{
    InterlockedIncrement(&g_sendCounter);
    unsigned char packetId = buf ? static_cast<unsigned char>(buf[0]) : 0;
    DWORD now = GetTickCount();

    bool needCorrStack = CastCorrelator::ShouldCaptureStack(packetId);
    CastCorrelator::SendEvent corrEvent{};
    if (needCorrStack) {
        corrEvent.apiTag = apiTag;
        corrEvent.buffer = buf;
        corrEvent.length = len;
        corrEvent.packetId = packetId;
        corrEvent.tick = static_cast<uint32_t>(now);
        corrEvent.targetFilterArmed = (g_packetIdFilterEnabled && g_packetIdFilter == 0x2E);
        corrEvent.frameCount = RtlCaptureStackBackTrace(
            2,
            CastCorrelator::kMaxRecordedFrames,
            corrEvent.frames,
            nullptr);
    }

    if(shouldLogTraces)
        Logf("%s len=%d id=%02X", apiTag ? apiTag : "send-family", len, packetId);
    int dumpLen = len > 64 ? 64 : len;
    if (dumpLen > 0 && shouldLogTraces)
        DumpMemory("Outbound packet", (void*)buf, dumpLen);
    if (!Net::IsInSendPacketHook()) {
        unsigned counter = Net::GetSendCounter();
        Engine::Lua::NotifySendPacket(counter, buf, len);
    }
    if (needCorrStack && corrEvent.frameCount > 0)
        CastCorrelator::OnSendEvent(corrEvent);
    if (ShouldCaptureWinsockStack(packetId)) {
        LogWinsockStack(apiTag ? apiTag : "winsock");
    }
}

static void TraceInbound(const char* buf, int len)
{
    if(shouldLogTraces)
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
    TraceOutbound("send", buf, len);
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
        TraceOutbound("WSASend", wsa[0].buf, (int)wsa[0].len);
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
        TraceOutbound("WSASendTo", wsa[0].buf, (int)wsa[0].len);
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
    TraceOutbound("sendto", buf, len);
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
    if (auto tracePackets = Core::Config::TryGetBool("TRACE_NETWORK_PACKETS"))
        shouldLogTraces = *tracePackets;
    else if (const char* envTrace = std::getenv("TRACE_NETWORK_PACKETS"))
        shouldLogTraces = (envTrace[0] == '1' || envTrace[0] == 'y' || envTrace[0] == 'Y' || envTrace[0] == 't' || envTrace[0] == 'T');
    if (shouldLogTraces)
        WriteRawLog("TRACE_NETWORK_PACKETS enabled (Winsock send/recv logging)");
    if (auto v = Core::Config::TryGetBool("TRACE_PACKET_STACKS"))
        g_captureWinsockStacks = *v;
    else if (const char* envStacks = std::getenv("TRACE_PACKET_STACKS"))
        g_captureWinsockStacks = (envStacks[0] == '1' || envStacks[0] == 'y' || envStacks[0] == 'Y' || envStacks[0] == 't' || envStacks[0] == 'T');
    int stackLimit = 0;
    if (auto limit = Core::Config::TryGetInt("TRACE_PACKET_STACKS_LIMIT"))
        stackLimit = *limit;
    else if (const char* envStackLimit = std::getenv("TRACE_PACKET_STACKS_LIMIT"))
        stackLimit = std::atoi(envStackLimit);
    if (stackLimit < 0)
        stackLimit = 0;
    InterlockedExchange(&g_winsockStackBudget, stackLimit);
    if (g_captureWinsockStacks) {
        char msg[160];
        sprintf_s(msg, sizeof(msg), "TRACE_PACKET_STACKS enabled (limit=%d)", stackLimit);
        WriteRawLog(msg);
    }
    std::optional<std::string> packetFilterText;
    if (auto cfgFilter = Core::Config::TryGetValue("TRACE_PACKET_ID_FILTER"))
        packetFilterText = *cfgFilter;
    else if (const char* envFilter = std::getenv("TRACE_PACKET_ID_FILTER"))
        packetFilterText = std::string(envFilter);
    if (packetFilterText) {
        unsigned parsed = 0;
        if (TryParsePacketId(*packetFilterText, parsed)) {
            g_packetIdFilterEnabled = true;
            g_packetIdFilter = parsed;
            char buf[96];
            sprintf_s(buf, sizeof(buf), "TRACE_PACKET_ID_FILTER set to 0x%02X", g_packetIdFilter);
            WriteRawLog(buf);
        } else {
            char warn[192];
            sprintf_s(warn, sizeof(warn),
                "TRACE_PACKET_ID_FILTER could not parse \"%s\" (expected 0-255 or 0xNN)",
                packetFilterText->c_str());
            WriteRawLog(warn);
        }
    }
    return true;
}

void ShutdownPacketTrace()
{
    RemoveHooks();
}

unsigned GetSendCounter()
{
    return static_cast<unsigned>(InterlockedCompareExchange(&g_sendCounter, 0, 0));
}

void IncrementSendCounter()
{
    InterlockedIncrement(&g_sendCounter);
}

} // namespace Net
