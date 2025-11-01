#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <minhook.h>
#include <cstdio>
#include <cstdint>
#include <atomic>
#include <cstring>

#include "Core/Logging.hpp"
#include "Core/Utils.hpp"
#include "Net/PacketTrace.hpp"
#include "Net/SendBuilder.hpp"
#include "Net/SendSampleStore.hpp"
#include "Engine/Movement.hpp"
#include "Walk/WalkController.hpp"

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
static volatile LONG g_fastWalkScanMissBudget = 8;
static SOCKET g_lastSocket = INVALID_SOCKET;
static SOCKET g_lastLoggedSocket = INVALID_SOCKET;
static std::atomic<SOCKET> g_preferredSocket{INVALID_SOCKET};
static std::atomic<uint64_t> g_fastWalkLastMissLogTick{0};

static constexpr int kFastWalkReserveDepth = 2;
static volatile LONG g_ackPayloadLogBudget = 4;
static std::atomic<std::uint32_t> g_wsasendWarmupRemaining{64};

struct WalkAckStatusInfo {
    uint8_t code;
    const char* label;
    bool ok;
};

static constexpr WalkAckStatusInfo kWalkAckStatusTable[] = {
    {0x00, "OK", true},
    {0x01, "BUSY", false},
    {0x02, "RETRY", false},
    {0x03, "RESYNC", false},
};

static const WalkAckStatusInfo* LookupWalkAckStatus(uint8_t code)
{
    for (const auto& entry : kWalkAckStatusTable) {
        if (entry.code == code)
            return &entry;
    }
    return nullptr;
}

static void LogAckPayloadBytes(const char* context, const char* buf, int len, bool traceEnabled)
{
    if (!traceEnabled || !buf || len <= 0)
        return;
    LONG remaining = InterlockedDecrement(&g_ackPayloadLogBudget);
    if (remaining < 0)
        return;

    char payloadBuf[192];
    int offset = sprintf_s(payloadBuf, sizeof(payloadBuf), "%s:", context ? context : "WalkACK");
    int dumpLen = (len < 8) ? len : 8;
    for (int i = 0; i < dumpLen && offset > 0; ++i) {
        offset += sprintf_s(payloadBuf + offset,
                            sizeof(payloadBuf) - offset,
                            " %02X",
                            static_cast<unsigned>(static_cast<unsigned char>(buf[i])));
    }
    if (offset > 0)
        Log::Logf(Log::Level::Debug, Log::Category::Walk, "%s", payloadBuf);
}

static bool HandleWalkAckMessage(SOCKET sock,
                                 SOCKET effectiveSocket,
                                 uint8_t opcode,
                                 const char* buf,
                                 int len,
                                 bool traceEnabled)
{
    if (opcode != 0x22 && opcode != 0x21)
        return false;

    if (!buf || len < 2) {
        LogAckPayloadBytes("[WALK] ack malformed", buf, len, traceEnabled);
        return true;
    }

    const uint8_t seq = static_cast<uint8_t>(buf[1]);
    const uint8_t rawStatus = (len >= 3) ? static_cast<uint8_t>(buf[2]) : 0;
    uint8_t statusForTracker = rawStatus;
    if (opcode == 0x21 && statusForTracker == 0)
        statusForTracker = 1;

    const WalkAckStatusInfo* statusInfo = LookupWalkAckStatus(rawStatus);
    char statusBuf[16];
    const char* statusLabel = nullptr;
    if (statusInfo) {
        statusLabel = statusInfo->label;
    } else {
        if (sprintf_s(statusBuf, sizeof(statusBuf), "0x%02X", static_cast<unsigned>(rawStatus)) > 0)
            statusLabel = statusBuf;
        else
            statusLabel = "UNKNOWN";
    }

    bool statusOk = statusInfo ? statusInfo->ok : (rawStatus == 0);
    if (opcode == 0x21) {
        statusOk = false;
        if (!statusInfo || statusInfo->ok) {
            strcpy_s(statusBuf, sizeof(statusBuf), "FAIL");
            statusLabel = statusBuf;
        }
    }

    if (!statusInfo && rawStatus != 0)
        LogAckPayloadBytes("[WALK] ack raw", buf, len, traceEnabled);

    Engine::MovementAckResult ackResult =
        Engine::ProcessMovementAck(effectiveSocket, seq, statusForTracker);

    const bool forcedFailure = (opcode == 0x21) || !statusOk;
    if (forcedFailure &&
        ackResult.action != Engine::MovementAckAction::Drop &&
        ackResult.action != Engine::MovementAckAction::Resync) {
        Engine::NoteAckDrop();
        ackResult.action = Engine::MovementAckAction::Drop;
    }

    const char* actionStr = "ignore";
    switch (ackResult.action) {
    case Engine::MovementAckAction::Ok:
        Walk::Controller::NotifyAckOk();
        actionStr = "ok";
        break;
    case Engine::MovementAckAction::Drop:
        Walk::Controller::ApplyInflightOverride(1, 4);
        Walk::Controller::NotifyAckSoftFail();
        Walk::Controller::NotifyResync("ack");
        Engine::ResyncFastWalk(effectiveSocket, "ack_drop", 1);
        actionStr = "drop";
        break;
    case Engine::MovementAckAction::Resync:
        Walk::Controller::ApplyInflightOverride(1, 4);
        Walk::Controller::NotifyAckSoftFail();
        Walk::Controller::NotifyResync("ack");
        Engine::ResyncFastWalk(effectiveSocket, "ack_mismatch", 1);
        actionStr = "resync";
        break;
    default:
        actionStr = "ignore";
        break;
    }

    if (opcode == 0x22) {
        Engine::RecordMovementAck(seq, rawStatus);
        Engine::SetActiveFastWalkSocket(effectiveSocket);
    } else {
        Engine::RecordMovementReject(seq, rawStatus);
    }
    Net::SetPreferredSocket(sock);

    const uint32_t inflightCount = Walk::Controller::GetInflightCount();
    const uint32_t stepDelayMs = Walk::Controller::GetStepDelayMs();
    const uint8_t expectedSeq = ackResult.expected
                                    ? ackResult.expected
                                    : static_cast<uint8_t>(seq + 1);

    Log::Logf(Log::Level::Info,
              Log::Category::Walk,
              "[WALK] ack seq=0x%02X status=%s inflight=%u stepDelay=%ums expected=0x%02X action=%s op=0x%02X",
              static_cast<unsigned>(seq),
              statusLabel,
              inflightCount,
              stepDelayMs,
              static_cast<unsigned>(expectedSeq),
              actionStr,
              opcode);

    return true;
}

static bool ShouldTracePackets()
{
    return Walk::Controller::DebugEnabled() || Log::IsEnabled(Log::Category::Walk, Log::Level::Debug);
}

static bool ShouldSampleWsasend(std::uint64_t nowMs)
{
    if (!Net::IsSendSamplingEnabled())
        return false;
    if (Net::Scanner::Sampler::shouldSample(nowMs))
        return true;

    std::uint32_t remaining = g_wsasendWarmupRemaining.load(std::memory_order_relaxed);
    while (remaining > 0) {
        if (g_wsasendWarmupRemaining.compare_exchange_weak(remaining,
                                                           remaining - 1,
                                                           std::memory_order_acq_rel,
                                                           std::memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

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
    if (!Walk::Controller::DebugEnabled())
        return;

    static volatile LONG budget = 16;
    if (budget > 0 && InterlockedDecrement(&budget) >= 0) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::FastWalk,
                  "FastWalk gate %s opcode=0x2E socket=%p depth=%d reserve=%d",
                  action,
                  reinterpret_cast<void*>(static_cast<uintptr_t>(s)),
                  depth,
                  kFastWalkReserveDepth);
    }
}

static void LogInboundFastWalkKey(const char* source, SOCKET socket, uint32_t key, int depthBefore, int depthAfter, uint64_t tickMs)
{
    Engine::RecordInboundFastWalkKey(socket, key, depthBefore, depthAfter, tickMs);

    if (!Walk::Controller::DebugEnabled())
        return;

    static volatile LONG budget = 48;
    if (budget > 0 && InterlockedDecrement(&budget) >= 0) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::FastWalk,
                  "FastWalk inbound %s socket=%p key=%08X depth=%d->%d",
                  source,
                  reinterpret_cast<void*>(static_cast<uintptr_t>(socket)),
                  key,
                  depthBefore,
                  depthAfter);
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
    if (!Walk::Controller::DebugEnabled())
        return;

    static volatile LONG s_budget = 32;
    if (!source)
        source = "?";
    if (s_budget > 0 && InterlockedDecrement(&s_budget) >= 0) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::FastWalk,
                  "FastWalk key received via %s socket=%p key=%08X depth=%d",
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

    SOCKET canonical = Engine::ResolveFastWalkSocket(socket);
    socket = canonical;

    Engine::RecordObservedFastWalkKey(key);

    if (Engine::PeekFastWalkKey(socket) == key)
        return false;

    Engine::PushFastWalkKey(socket, key);
    LogFastWalkReceipt(socket, source, key);

    if (Walk::Controller::DebugEnabled()) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::FastWalk,
                  "FastWalk(%s) socket=%p key=%08X depth=%d",
                  source ? source : "?",
                  reinterpret_cast<void*>(static_cast<uintptr_t>(socket)),
                  key,
                  Engine::FastWalkQueueDepth(socket));
    }
    return true;
}

static bool ScanFastWalkPayload(SOCKET socket, const char* source, const uint8_t* data, size_t len)
{
    if (!data || len < 4)
        return false;

    auto recordInbound = [&](uint32_t key) -> bool {
        if (!key)
            return false;
        int depthBefore = Engine::FastWalkQueueDepth(socket);
        if (!HandleFastWalkKey(socket, key, source))
            return false;
        uint64_t tickNow = GetTickCount64();
        int depthAfter = Engine::FastWalkQueueDepth(socket);
        LogInboundFastWalkKey(source, socket, key, depthBefore, depthAfter, tickNow);
        return true;
    };

    if (source && (_stricmp(source, "0x73") == 0 || _stricmp(source, "0x7B") == 0)) {
        // Observed layout: optional header byte(s) followed by 32-bit key.
        // Probe offsets 0, 2, and 4 in both big- and little-endian order.
        const size_t probeOffsets[] = {0, 2, 4};
        bool parsed = false;
        for (size_t offset : probeOffsets) {
            if (offset + 4 > len)
                continue;
            uint32_t keyBe = (static_cast<uint32_t>(data[offset]) << 24) |
                             (static_cast<uint32_t>(data[offset + 1]) << 16) |
                             (static_cast<uint32_t>(data[offset + 2]) << 8) |
                             static_cast<uint32_t>(data[offset + 3]);
            if (recordInbound(keyBe)) {
                parsed = true;
                Log::Logf(Log::Level::Debug,
                          Log::Category::FastWalk,
                          "[FW] parser %s offset=%zu key=0x%08X (big-endian)",
                          source,
                          offset,
                          keyBe);
                break;
            }

            uint32_t keyLe = static_cast<uint32_t>(data[offset]) |
                             (static_cast<uint32_t>(data[offset + 1]) << 8) |
                             (static_cast<uint32_t>(data[offset + 2]) << 16) |
                             (static_cast<uint32_t>(data[offset + 3]) << 24);
            if (recordInbound(keyLe)) {
                parsed = true;
                Log::Logf(Log::Level::Debug,
                          Log::Category::FastWalk,
                          "[FW] parser %s offset=%zu key=0x%08X (little-endian)",
                          source,
                          offset,
                          keyLe);
                break;
            }
        }
        if (parsed)
            return true;
    }

    // Pattern 1: embedded movement packet (0x02 [flags] [seq] key)
    for (size_t i = 0; i + 7 <= len; ++i) {
        if (data[i] == 0x02 && (data[i + 1] & 0x80)) {
            uint32_t key = (static_cast<uint32_t>(data[i + 3]) << 24) |
                           (static_cast<uint32_t>(data[i + 4]) << 16) |
                           (static_cast<uint32_t>(data[i + 5]) << 8) |
                           static_cast<uint32_t>(data[i + 6]);
            if (recordInbound(key))
                return true;
        }
    }

    // Pattern 2: big-endian key scan (high byte 0x01)
    for (size_t i = 0; i + 4 <= len; ++i) {
        uint32_t keyBe = (static_cast<uint32_t>(data[i]) << 24) |
                         (static_cast<uint32_t>(data[i + 1]) << 16) |
                         (static_cast<uint32_t>(data[i + 2]) << 8) |
                         static_cast<uint32_t>(data[i + 3]);
        if ((keyBe & 0xFF000000u) == 0x01000000u && recordInbound(keyBe))
            return true;

        // Pattern 3: little-endian scan
        uint32_t keyLe = static_cast<uint32_t>(data[i]) |
                         (static_cast<uint32_t>(data[i + 1]) << 8) |
                         (static_cast<uint32_t>(data[i + 2]) << 16) |
                         (static_cast<uint32_t>(data[i + 3]) << 24);
        if ((keyLe & 0xFF000000u) == 0x01000000u && recordInbound(keyLe))
            return true;
    }

    LONG remaining = InterlockedCompareExchange(&g_fastWalkScanMissBudget, 0, 0);
    if (remaining > 0 && InterlockedDecrement(&g_fastWalkScanMissBudget) >= 0) {
        uint64_t nowTick = GetTickCount64();
        uint64_t last = g_fastWalkLastMissLogTick.load(std::memory_order_relaxed);
        if (nowTick >= last && nowTick - last >= 250) {
            g_fastWalkLastMissLogTick.store(nowTick, std::memory_order_relaxed);
            Logf("FastWalk scan miss (%s) len=%zu", source ? source : "?", static_cast<size_t>(len));
            size_t dumpLen = len < 32 ? len : 32;
            if (dumpLen)
                DumpMemory("FastWalk scan sample", const_cast<uint8_t*>(data), static_cast<int>(dumpLen));
        }
    }

    return false;
}

static SOCKET SelectFastWalkSocket(SOCKET fallback)
{
    SOCKET active = Engine::GetActiveFastWalkSocket();
    if (active != INVALID_SOCKET)
        return active;

    SOCKET preferred = Net::GetPreferredSocket();
    if (preferred != INVALID_SOCKET) {
        SOCKET resolved = Engine::ResolveFastWalkSocket(preferred);
        return resolved != INVALID_SOCKET ? resolved : preferred;
    }

    SOCKET resolvedFallback = Engine::ResolveFastWalkSocket(fallback);
    return resolvedFallback != INVALID_SOCKET ? resolvedFallback : fallback;
}

static void TraceOutbound(SOCKET& s, const char* buf, int len)
{
    unsigned char opcode = (len > 0) ? static_cast<unsigned char>(buf[0]) : 0;

    if (opcode == 0x02) {
        s = SelectFastWalkSocket(s);
        bool scripted = Engine::IsScriptedMovementSendInProgress();
        int dir = 0;
        bool runFlag = false;
        if (len >= 2) {
            runFlag = (buf[1] & 0x80) != 0;
            dir = buf[1] & 0x07;
        }
        uint8_t seq = (len >= 3) ? static_cast<uint8_t>(buf[2]) : 0;
        uint32_t key = (len >= 7) ? ExtractFastWalkKey0x2E(buf, len) : 0;

        if (!scripted && seq != 0) {
            Engine::RecordMovementSent(seq);
            Engine::NotifyClientMovementSent();
        }
        if (key) {
            Engine::RecordObservedFastWalkKey(key);
        }
        if (!scripted && seq != 0) {
            Engine::TrackMovementTx(seq, dir, runFlag, s, key, "client");
        }
    }

    NoteSocketActivity(s);
    const bool traceEnabled = ShouldTracePackets();
    if (!traceEnabled) {
        g_lastLoggedSocket = INVALID_SOCKET;
    } else if (s != INVALID_SOCKET && s != g_lastLoggedSocket) {
        g_lastLoggedSocket = s;
        Log::Logf(Log::Level::Debug,
                  Log::Category::Walk,
                  "TraceOutbound socket=%p",
                  reinterpret_cast<void*>(static_cast<uintptr_t>(s)));
    }
    if (traceEnabled) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Walk,
                  "send-family len=%d id=%02X",
                  len,
                  opcode);
        int dumpLen = len > 64 ? 64 : len;
        if (dumpLen > 0)
            DumpMemory("Outbound packet", (void*)buf, dumpLen);
    }

    if (opcode == 0x3C) {
        Engine::SetActiveFastWalkSocket(s);
        Net::SetPreferredSocket(s);
    }

    Net::PollSendBuilder();
}

static void TraceInbound(SOCKET s, const char* buf, int len)
{
    unsigned char opcode = (len > 0) ? static_cast<unsigned char>(buf[0]) : 0;
    SOCKET canonical = Engine::ResolveFastWalkSocket(s);
    SOCKET effectiveSocket = (canonical != INVALID_SOCKET) ? canonical : s;

    NoteSocketActivity(s);
    const bool traceEnabled = ShouldTracePackets();
    if (traceEnabled) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Walk,
                  "recv-family len=%d id=%02X",
                  len,
                  opcode);
        int dumpLen = len > 64 ? 64 : len;
        if (dumpLen > 0)
            DumpMemory("Inbound packet", (void*)buf, dumpLen);
    }

    if (opcode == 0x2E && len >= 7) {
        uint32_t key = ExtractFastWalkKey0x2E(buf, len);
        int depthBefore = Engine::FastWalkQueueDepth(effectiveSocket);
        bool accepted = HandleFastWalkKey(effectiveSocket, key, "0x2E");
        if (accepted) {
            uint64_t tickNow = GetTickCount64();
            int depthAfter = Engine::FastWalkQueueDepth(effectiveSocket);
            LogInboundFastWalkKey("0x2E", effectiveSocket, key, depthBefore, depthAfter, tickNow);
        } else if (traceEnabled) {
            if (key == 0) {
                Logf("FastWalk 0x2E packet ignored len=%d", len);
            } else {
                Logf("FastWalk 0x2E duplicate key=%08X len=%d", key, len);
            }
        }
    } else if ((opcode == 0x7B || opcode == 0x73) && len > 1) {
        const uint8_t* payload = reinterpret_cast<const uint8_t*>(buf + 1);
        size_t payloadLen = static_cast<size_t>(len - 1);
        ScanFastWalkPayload(effectiveSocket, opcode == 0x7B ? "0x7B" : "0x73", payload, payloadLen);
    }

    Net::PollSendBuilder();

    HandleWalkAckMessage(s, effectiveSocket, opcode, buf, len, traceEnabled);

    if (opcode == 0xB8)
    {
        uint32_t key = 0;
        if (len >= 5) {
            key = ntohl(*(const uint32_t*)(buf + 1));
        } else if (len >= 3) {
            key = ntohs(*(const uint16_t*)(buf + 1));
        }
        int depthBefore = Engine::FastWalkQueueDepth(effectiveSocket);
        bool accepted = HandleFastWalkKey(effectiveSocket, key, "0xB8");
        if (accepted) {
            uint64_t tickNowB8 = GetTickCount64();
            int depthAfterB8 = Engine::FastWalkQueueDepth(effectiveSocket);
            LogInboundFastWalkKey("0xB8", effectiveSocket, key, depthBefore, depthAfterB8, tickNowB8);
        } else if (traceEnabled) {
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
                int depthBefore = Engine::FastWalkQueueDepth(effectiveSocket);
                if (HandleFastWalkKey(effectiveSocket, key, "0xBF:01")) {
                    uint64_t tickNowBF01 = GetTickCount64();
                    int depthAfterBF01 = Engine::FastWalkQueueDepth(effectiveSocket);
                    LogInboundFastWalkKey("0xBF:01", effectiveSocket, key, depthBefore, depthAfterBF01, tickNowBF01);
                }
                p += 4;
            }
        }
        else if (sub == 0x02 && len >= 5 + 1 + 4)
        {
            uint32_t key = ntohl(*(uint32_t*)(payload + 1));
            int depthBefore = Engine::FastWalkQueueDepth(effectiveSocket);
            if (HandleFastWalkKey(effectiveSocket, key, "0xBF:02")) {
                uint64_t tickNowBF02 = GetTickCount64();
                int depthAfterBF02 = Engine::FastWalkQueueDepth(effectiveSocket);
                LogInboundFastWalkKey("0xBF:02", effectiveSocket, key, depthBefore, depthAfterBF02, tickNowBF02);
            }
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
    if (cnt && wsa && wsa[0].buf && wsa[0].len) {
        const std::uint64_t nowMs = GetTickCount64();
        if (ShouldSampleWsasend(nowMs)) {
            void* frames[Net::SendSampleStore::kMaxFrames] = {};
            USHORT captured = RtlCaptureStackBackTrace(0,
                                                       static_cast<ULONG>(Net::SendSampleStore::kMaxFrames),
                                                       frames,
                                                       nullptr);
            if (captured > 0)
                Net::SubmitSendSample(nullptr, frames, captured, nowMs);
        }
    }

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
