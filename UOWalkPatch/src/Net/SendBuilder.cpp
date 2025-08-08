#include <windows.h>
#include <dbghelp.h>
#include <cstdio>
#include <minhook.h>
#include "Core/Logging.hpp"
#include "Core/PatternScan.hpp"
#include "Core/Utils.hpp"
#include "Net/SendBuilder.hpp"
#include "Engine/GlobalState.hpp"

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
    DumpMemory("PLAIN-SendPacket", const_cast<void*>(pkt), len);

    if (!g_netMgr)
        g_netMgr = thisPtr;
    if (!g_builderScanned)
        HookSendBuilderFromNetMgr();
    if (g_sendBuilderHooked || g_builderScanned)
        InterlockedExchange(&g_needWalkReg, 1);
    g_sendPacket(thisPtr, pkt, len);
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

} // namespace Net

