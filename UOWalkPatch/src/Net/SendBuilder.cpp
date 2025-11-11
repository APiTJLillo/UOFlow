#include <windows.h>
#include <dbghelp.h>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <minhook.h>
#include "Core/Logging.hpp"
#include "Core/Config.hpp"
#include "Core/PatternScan.hpp"
#include "Core/Utils.hpp"
#include "Net/SendBuilder.hpp"
#include "Net/PacketTrace.hpp"
#include "Engine/GlobalState.hpp"
#include "Core/ActionTrace.hpp"
#include "Engine/LuaBridge.hpp"
#include "TargetCorrelator.h"

// Define the global variable that was previously only declared as extern
volatile LONG g_needWalkReg = 0;

namespace Net {

using SendPacket_t = void(__thiscall*)(void* netMgr, const void* pkt, int len);
using SendBuilder_t = void* (__thiscall*)(void* thisPtr, void* builder);

static GlobalStateInfo* g_state = nullptr;
static SendPacket_t g_sendPacket = nullptr;
static void* g_sendPacketTarget = nullptr;
static bool g_sendPacketHooked = false;
static void* g_netMgr = nullptr;
static SendBuilder_t fpSendBuilder = nullptr;
static bool g_sendBuilderHooked = false;
static bool g_builderScanned = false;
static bool g_captureSendStacks = false;
static volatile LONG g_sendStackBudget = 0;
static bool g_logSendPackets = false;
static thread_local bool g_inSendPacketHook = false;

struct BuilderProbeInfo {
    SendBuilder_t original;
    void* target;
};

static BuilderProbeInfo g_builderProbes[32] = {};

template<int Index>
static void* __fastcall Probe_SendBuilder(void* thisPtr, void* builder)
{
    uint8_t* plain = *(uint8_t**)builder;
    int len = *(int*)((uint8_t*)builder + 4);
    uint8_t first = plain ? plain[0] : 0;
    Logf("Builder? index=%02X len=%d first=%02X", Index, len, first);
    auto orig = g_builderProbes[Index].original;
    return orig ? orig(thisPtr, builder) : nullptr;
}

using ProbeFn = void* (__fastcall*)(void*, void*);
#define PROBE_ENTRY(n) Probe_SendBuilder<n>
static ProbeFn g_probeFns[32] = {
    PROBE_ENTRY(0),  PROBE_ENTRY(1),  PROBE_ENTRY(2),  PROBE_ENTRY(3),
    PROBE_ENTRY(4),  PROBE_ENTRY(5),  PROBE_ENTRY(6),  PROBE_ENTRY(7),
    PROBE_ENTRY(8),  PROBE_ENTRY(9),  PROBE_ENTRY(10), PROBE_ENTRY(11),
    PROBE_ENTRY(12), PROBE_ENTRY(13), PROBE_ENTRY(14), PROBE_ENTRY(15),
    PROBE_ENTRY(16), PROBE_ENTRY(17), PROBE_ENTRY(18), PROBE_ENTRY(19),
    PROBE_ENTRY(20), PROBE_ENTRY(21), PROBE_ENTRY(22), PROBE_ENTRY(23),
    PROBE_ENTRY(24), PROBE_ENTRY(25), PROBE_ENTRY(26), PROBE_ENTRY(27),
    PROBE_ENTRY(28), PROBE_ENTRY(29), PROBE_ENTRY(30), PROBE_ENTRY(31)
};
#undef PROBE_ENTRY

static void DumpCallstack(const char* tag, void* thisPtr, void* builder)
{
    void* frames[16]{};
    USHORT captured = RtlCaptureStackBackTrace(2, 16, frames, nullptr);

    for (USHORT i = 0; i < captured; ++i)
    {
        DWORD64 addr = (DWORD64)frames[i];
        DWORD64 disp = 0;
        char symbolBuffer[sizeof(SYMBOL_INFO) + 64] = {};
        auto* sym = (SYMBOL_INFO*)symbolBuffer;
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen = 63;

        if (SymFromAddr(GetCurrentProcess(), addr, &disp, sym))
            Logf("[%s] %2u: %s+%llx", tag, i, sym->Name, disp);
        else
            Logf("[%s] %2u: %p", tag, i, frames[i]);
    }

    Logf("[%s] this=%p builder=%p", tag, thisPtr, builder);
}

static void* __fastcall Hook_SendBuilder(void* thisPtr, void* builder)
{
    uint8_t* plain = *(uint8_t**)builder;
    int len = *(int*)((uint8_t*)builder + 4);
    DumpMemory("PLAINTEXT SendBuilder", plain, len);
    return fpSendBuilder(thisPtr, builder);
}

static void ScanEndpointVTable(void* endpoint)
{
    void** vtbl = *reinterpret_cast<void***>(endpoint);
    for (int i = 0; i < 32; ++i)
    {
        void* fn = vtbl[i];
        Logf("endpoint vtbl[%02X] = %p", i, fn);
        if (fn && MH_CreateHook(fn, g_probeFns[i], reinterpret_cast<LPVOID*>(&g_builderProbes[i].original)) == MH_OK)
        {
            if (MH_EnableHook(fn) == MH_OK)
                g_builderProbes[i].target = fn;
        }
    }
}

static void TryHookSendBuilder(void* endpoint)
{
    if (g_builderScanned || !endpoint)
        return;

    g_builderScanned = true;
    ScanEndpointVTable(endpoint);
}

static void HookSendBuilderFromNetMgr()
{
    if (g_builderScanned || !g_state)
        return;

    void** netMgr = reinterpret_cast<void**>(g_state->networkConfig);

    MEMORY_BASIC_INFORMATION mbi{};
    if (!netMgr ||
        !VirtualQuery(netMgr, &mbi, sizeof(mbi)) ||
        mbi.State != MEM_COMMIT)
        return;

    void* endpoint = netMgr[0];
    TryHookSendBuilder(endpoint);
}

static void __fastcall H_SendPacket(void* thisPtr, void*, const void* pkt, int len)
{
    g_inSendPacketHook = true;
    IncrementSendCounter();
    unsigned counterSnapshot = Net::GetSendCounter();
    unsigned char packetId = 0;
    if (pkt && len > 0) {
        __try {
            packetId = *static_cast<const unsigned char*>(pkt);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            packetId = 0;
        }
    }
    // Annotate proximity to last high-level action (e.g., CastSpell) for correlation
    Trace::LastAction last{};
    if (Trace::GetLastAction(last)) {
        DWORD now = GetTickCount();
        DWORD dt = now - last.tick;
        if (dt <= Trace::GetWindowMs()) {
            char info[160];
            sprintf_s(info, sizeof(info), "SendPacket near %s dt=%lu ms", last.name, static_cast<unsigned long>(dt));
            WriteRawLog(info);
        }
    }
    if (g_captureSendStacks && InterlockedCompareExchange(&g_sendStackBudget, 0, 0) > 0) {
        LONG left = InterlockedDecrement(&g_sendStackBudget);
        if (left >= 0) {
            void* frames[32] = {};
            USHORT captured = RtlCaptureStackBackTrace(0, 32, frames, nullptr);
            WriteRawLog("[SendStack] capturing call stack for SendPacket");
            for (USHORT i = 0; i < captured; ++i) {
                if (!frames[i])
                    continue;
                char line[128];
                sprintf_s(line, sizeof(line), "[SendStack] #%u: %p", static_cast<unsigned>(i), frames[i]);
                WriteRawLog(line);
            }
        }
    }
    DumpMemory("PLAIN-SendPacket", const_cast<void*>(pkt), len);
    if (g_logSendPackets) {
        char msg[192];
        sprintf_s(msg, sizeof(msg),
            "[SendPacket] counter=%u len=%d id=%02X this=%p",
            counterSnapshot, len, packetId, thisPtr);
        WriteRawLog(msg);
    }
    Engine::Lua::NotifySendPacket(counterSnapshot, pkt, len);
    g_targetCorr.TagIfWithin(packetId, static_cast<std::size_t>(len), nullptr);

    if (!g_netMgr)
        g_netMgr = thisPtr;
    if (!g_builderScanned)
        HookSendBuilderFromNetMgr();
    LONG previous = InterlockedExchange(&g_needWalkReg, 0);
    if (previous != 0)
        Engine::Lua::ScheduleWalkBinding();
    // Use network activity as a safe-ish place to poll late Lua installs (throttled internally).
    Engine::Lua::PollLateInstalls();
    g_sendPacket(thisPtr, pkt, len);
    g_inSendPacketHook = false;
}

static void FindSendPacket()
{
    const char* kSig = "51 53 55 56 57 8B F1";
    BYTE* hit = FindPatternText(kSig);
    if (hit)
    {
        g_sendPacketTarget = hit;
        char buf[64];
        sprintf_s(buf, sizeof(buf), "Found SendPacket at %p", hit);
        WriteRawLog(buf);
    }
    else
    {
        WriteRawLog("SendPacket signature not found");
    }
}

static void HookSendPacket()
{
    if (!g_sendPacketHooked && g_sendPacketTarget)
    {
        if (MH_CreateHook(g_sendPacketTarget, H_SendPacket, reinterpret_cast<LPVOID*>(&g_sendPacket)) == MH_OK &&
            MH_EnableHook(g_sendPacketTarget) == MH_OK)
        {
            g_sendPacketHooked = true;
            WriteRawLog("SendPacket hook installed");
        }
    }
}

bool InitSendBuilder(GlobalStateInfo* state)
{
    g_state = state;
    FindSendPacket();
    HookSendPacket();
    if (auto flag = Core::Config::TryGetBool("LOG_SEND_STACKS"))
        g_captureSendStacks = *flag;
    else if (const char* env = std::getenv("LOG_SEND_STACKS"))
        g_captureSendStacks = (env[0] == '1' || env[0] == 'y' || env[0] == 'Y' || env[0] == 't' || env[0] == 'T');
    int stackLimit = 4;
    if (auto limit = Core::Config::TryGetInt("LOG_SEND_STACKS_LIMIT"))
        stackLimit = *limit;
    else if (const char* envLimit = std::getenv("LOG_SEND_STACKS_LIMIT"))
        stackLimit = std::atoi(envLimit);
    if (stackLimit < 0)
        stackLimit = 0;
    InterlockedExchange(&g_sendStackBudget, stackLimit);
    if (auto logPackets = Core::Config::TryGetBool("LOG_SEND_PACKET_EVENTS"))
        g_logSendPackets = *logPackets;
    else if (const char* envLogPackets = std::getenv("LOG_SEND_PACKET_EVENTS"))
        g_logSendPackets = (envLogPackets[0] == '1' || envLogPackets[0] == 'y' || envLogPackets[0] == 'Y' || envLogPackets[0] == 't' || envLogPackets[0] == 'T');
    if (g_logSendPackets)
        WriteRawLog("LOG_SEND_PACKET_EVENTS enabled");
    return true;
}

void ShutdownSendBuilder()
{
    if (g_sendPacketHooked && g_sendPacketTarget)
    {
        MH_DisableHook(g_sendPacketTarget);
        MH_RemoveHook(g_sendPacketTarget);
        g_sendPacketHooked = false;
    }
    for (auto& p : g_builderProbes)
    {
        if (p.target)
        {
            MH_DisableHook(p.target);
            MH_RemoveHook(p.target);
            p.target = nullptr;
            p.original = nullptr;
        }
    }
    g_netMgr = nullptr;
    g_state = nullptr;
    fpSendBuilder = nullptr;
}

bool SendPacketRaw(const void* bytes, int len)
{
    if (len > 0 && g_sendPacket && g_netMgr)
    {
        g_sendPacket(g_netMgr, bytes, len);
        return true;
    }
    return false;
}

bool IsSendReady()
{
    return g_sendPacket && g_netMgr;
}

bool IsInSendPacketHook()
{
    return g_inSendPacketHook;
}

} // namespace Net
