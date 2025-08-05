#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <psapi.h>
#include <dbghelp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <atomic>
#include <minhook.h>

// Global state structure based on the memory layout observed
struct GlobalStateInfo {
    void* luaState;             // 0x00  - Lua state pointer
    void* databaseManager;      // 0x04  - Database manager
    bool initialized;           // 0x08  - Init flag 
    void* resourceManager;      // 0x0C  - Resource manager 
    void* resourceHandler1;     // 0x10
    void* networkConfig;        // 0x14
    void* engineContext;        // 0x18  - Points to engine context, not self
    void* globalFacetCache;     // 0x1C
    bool shutdownInitiated;     // 0x20
    void* resourceNodePtr;      // 0x24
    void* coreResourceMgr;      // 0x28
    // ... more fields we haven't identified yet
};

// Global state
static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static char   g_logPath[MAX_PATH];
static BOOL   g_logAnnounced;
static BOOL   g_initialized;
static HMODULE g_hModule;
static GlobalStateInfo* g_globalStateInfo;
static void* g_luaState;
static HANDLE g_scanThread;

// The client uses __stdcall for RegisterLuaFunction 
typedef bool(__stdcall* RegisterLuaFunction_t)(void* luaState, void* func, const char* name);
static RegisterLuaFunction_t g_origRegLua;

// Add global flag for hook success
static bool g_luaStateCaptured = false;

//Add global flag that determines whether we hook the RegisterLuaFunction
static bool UOWP_HOOK_REGISTER = true; // Set to false to disable hook

// Add at top with other globals
static volatile LONG g_stopScan = 0;   // 0 = keep running, 1 = quit
static DWORD* g_globalStateSlot = nullptr;  // Location of static pointer

// VEH globals
static LONG   g_once = 0;
static PVOID  g_vehHandle = nullptr;

// Forward declarations
static void WriteRawLog(const char* message);
static void LogLastError(const char* prefix);
static void LogLoadedModules();
static void SetupConsole();
static BYTE* FindBytes(BYTE* start, SIZE_T size, const BYTE* pattern, SIZE_T patSize);
static BYTE* FindPattern(BYTE* base, SIZE_T size, const BYTE* pat, SIZE_T patLen);
static void DumpMemory(const char* desc, void* addr, size_t len);
static void* FindGlobalStateInfo();
static void* FindOwnerOfLuaState(void* lua);
static DWORD WINAPI WaitForLua(LPVOID param);
static LPVOID FindRegisterLuaFunction();
static void InstallWriteWatch();
static int  __cdecl Lua_DummyPrint(void* L);           // our Lua C‑function
static void RegisterOurLuaFunctions();                  // one‑shot registrar
static bool CallClientRegister(void* L, void* func, const char* name);
static DWORD WINAPI RegisterThread(LPVOID);             // worker for deferred registration
static void* g_moveComp = nullptr; // movement component instance
static int  __cdecl Lua_Walk(void* L);
static void FindMoveComponent();
static void InstallSendHooks();
static void TraceOutbound(const char* buf, int len);
static void FindSendPacket();
static int WSAAPI H_Send(SOCKET s, const char* buf, int len, int flags);
static int WSAAPI H_WSASend(
    SOCKET s,
    const WSABUF* wsa,
    DWORD cnt,
    LPDWORD sent,
    DWORD flags,
    LPWSAOVERLAPPED ov,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE cr);
static int WSAAPI H_WSASendTo(
    SOCKET s,
    const WSABUF* wsa,
    DWORD cnt,
    LPDWORD sent,
    DWORD flags,
    const sockaddr* dst,
    int dstlen,
    LPWSAOVERLAPPED ov,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE cr);
static int WSAAPI H_SendTo(
    SOCKET s,
    const char* buf,
    int len,
    int flags,
    const sockaddr* to,
    int tolen);
extern "C" __declspec(dllexport) void __stdcall SendRaw(const void* bytes, int len);
extern "C" __declspec(dllexport) void __stdcall SendWalk(int dir, int run);

static void DumpCallstack(const char* tag, void* thisPtr, void* builder);
static void TryHookSendBuilder(void* endpoint);
static void HookSendBuilderFromNetMgr();
static void HookSendPacket();
static void __fastcall H_SendPacket(void* thisPtr, void* _unused, const void* pkt, int len);

using SendBuilder_t = void* (__thiscall*)(void* thisPtr, void* builder);
static SendBuilder_t fpSendBuilder = nullptr;
static bool g_sendBuilderHooked = false;
static bool g_builderScanned = false;
static void* __fastcall Hook_SendBuilder(void* thisPtr, void* builder);

// Data for probing endpoint vtable entries
struct BuilderProbeInfo {
    SendBuilder_t original;
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

static void ScanEndpointVTable(void* endpoint);

// Deferred Lua registration state
static volatile LONG g_needWalkReg = 0;  // 0 = no, 1 = register when safe

// New updateDataStructureState hook
using UpdateState_t =
uint32_t(__thiscall*)(void* thisPtr,
    void* destPtr,   // <- first on stack
    uint32_t dir,     // <- second
    int     runFlag); // <- third

static UpdateState_t g_updateState = nullptr;
static UpdateState_t g_origUpdate = nullptr;
static void InstallUpdateHook();
static volatile LONG g_haveMoveComp = 0;
static long g_updateLogCount = 0;  // Log up to ~200 calls for telemetry
static thread_local int g_updateDepth = 0;  // re-entrancy guard
static std::atomic_flag g_regBusy = ATOMIC_FLAG_INIT;
static HANDLE g_regThread = nullptr;
static std::atomic<int> g_pendingDir{-1};
static std::atomic<int> g_pendingRun{1};
static uint32_t __fastcall H_Update(void* thisPtr,  // ECX
    void* _unused,  // EDX
    void* destPtr,
    uint32_t dir,
    int     runFlag);
static void* g_dest;
using SendPacket_t = void(__thiscall*)(void* netMgr, const void* pkt, int len);
static SendPacket_t g_sendPacket = nullptr; // trampoline after hook
static void* g_sendPacketTarget = nullptr;  // real SendPacket function
static bool g_sendPacketHooked = false;
static void* g_netMgr = nullptr;
static uint32_t g_fastWalkKeys[32]{};
static int      g_fwTop = 0;
static int (WSAAPI* g_real_send)(SOCKET, const char*, int, int) = nullptr;
static int (WSAAPI* g_real_WSASend)(SOCKET, const WSABUF*, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) = nullptr;
static int (WSAAPI* g_real_WSASendTo)(SOCKET, const WSABUF*, DWORD, LPDWORD, DWORD, const sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) = nullptr;
static int (WSAAPI* g_real_sendto)(SOCKET, const char*, int, int, const sockaddr*, int) = nullptr;

// Helper with printf-style formatting
static void Logf(const char* fmt, ...)
{
    char buf[256];
    va_list args;
    va_start(args, fmt);
    vsprintf_s(buf, sizeof(buf), fmt, args);
    va_end(args);
    WriteRawLog(buf);
}

static void PushFastWalkKey(uint32_t key)
{
    if (g_fwTop < (int)(sizeof(g_fastWalkKeys) / sizeof(g_fastWalkKeys[0])))
        g_fastWalkKeys[g_fwTop++] = key;
}

static uint32_t PopFastWalkKey()
{
    return g_fwTop > 0 ? g_fastWalkKeys[--g_fwTop] : 0;
}

static int __cdecl Lua_DummyPrint(void* L)
{
    WriteRawLog("[Lua] DummyPrint() was invoked!");
    return 0;   // no Lua return values
}

// Check if an address resides within the current thread's stack range
static bool IsOnCurrentStack(void* p)
{
    NT_TIB* tib = reinterpret_cast<NT_TIB*>(NtCurrentTeb());
    return p >= tib->StackLimit && p < tib->StackBase;
}

// Simple memory search helper
static BYTE* FindBytes(BYTE* start, SIZE_T size, const BYTE* pattern, SIZE_T patSize) {
    if (!start || !pattern || !patSize || size < patSize)
        return nullptr;

    for (SIZE_T i = 0; i + patSize <= size; ++i) {
        if (memcmp(start + i, pattern, patSize) == 0)
            return start + i;
    }
    return nullptr;
}

// Better pattern matching helper - handles wildcards and both UTF-16/ANSI
static BYTE* FindPattern(BYTE* base, SIZE_T size, const BYTE* pat, SIZE_T patLen) {
    for (SIZE_T i = 0; i + patLen <= size; ++i) {
        SIZE_T k = 0;
        while (k < patLen && (pat[k] == '?' || base[i + k] == pat[k]))
            ++k;
        if (k == patLen)
            return base + i;
    }
    return nullptr;
}

// Helper function to dump memory region as hex
static void DumpMemory(const char* desc, void* addr, size_t len) {
    if (!addr || !len) return;

    char buffer[1024];
    sprintf_s(buffer, sizeof(buffer), "Memory dump %s at %p:", desc, addr);
    WriteRawLog(buffer);

    BYTE* bytes = (BYTE*)addr;
    char hex[128];
    char ascii[17];
    ascii[16] = 0;

    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) {
            if (i > 0) {
                sprintf_s(buffer, sizeof(buffer), "  %p: %s  %s", bytes + i - 16, hex, ascii);
                WriteRawLog(buffer);
            }
            memset(hex, ' ', sizeof(hex));
            memset(ascii, '.', 16);
        }
        sprintf_s(hex + (i % 16) * 3, 4, "%02X ", bytes[i]);
        ascii[i % 16] = (bytes[i] >= 32 && bytes[i] <= 126) ? bytes[i] : '.';
    }

    // Print remaining bytes
    size_t remain = len % 16;
    if (remain > 0) {
        sprintf_s(buffer, sizeof(buffer), "  %p: %-48s  %s",
            bytes + len - remain, hex, ascii);
        WriteRawLog(buffer);
    }
}

// Simple masked pattern finder
// Parse textual signature with "??" wildcards into byte and mask arrays
struct Pattern {
    size_t      len;
    uint8_t     raw[128];
    uint8_t     mask[128];
};

static size_t ParsePattern(const char* sig, Pattern& out)
{
    size_t i = 0;
    while (*sig && i < sizeof(out.raw)) {
        if (*sig == ' ') { ++sig; continue; }
        if (sig[0] == '?' && sig[1] == '?') {
            out.mask[i] = 0; out.raw[i++] = 0; sig += 2;
        }
        else {
            unsigned v; sscanf_s(sig, "%02x", &v);
            out.mask[i] = 1; out.raw[i++] = (uint8_t)v; sig += 2;
        }
    }
    out.len = i;
    return i;
}

static BYTE* FindPatternText(const char* sig)
{
    Pattern p{}; ParsePattern(sig, p);

    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(nullptr), &mi, sizeof(mi)))
        return nullptr;

    uint8_t* base = (uint8_t*)mi.lpBaseOfDll;
    uint8_t* end = base + mi.SizeOfImage;

    for (uint8_t* cur = base; cur + p.len <= end; ++cur) {
        size_t k = 0;
        while (k < p.len && (!p.mask[k] || cur[k] == p.raw[k]))
            ++k;
        if (k == p.len)
            return cur;
    }
    return nullptr;
}

// Scan for the movement component using the updateState vtable entry
static void FindMoveComponent()
{
    if (!g_updateState)
        return;

    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(nullptr), &mi, sizeof(mi)))
        return;

    BYTE* base = (BYTE*)mi.lpBaseOfDll;
    BYTE* end = base + mi.SizeOfImage;

    BYTE* vtable = nullptr;
    for (BYTE* p = base; p + 0x44 <= end; p += 4) {
        if (*(DWORD*)(p + 0x40) == (DWORD)(uintptr_t)g_updateState) {
            vtable = p;
            break;
        }
    }

    if (!vtable) {
        WriteRawLog("Move component vtable not found");
        return;
    }

    char buf[64];
    sprintf_s(buf, sizeof(buf), "MoveComp vtable at %p", vtable);
    WriteRawLog(buf);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = 0;
    while (addr < (BYTE*)si.lpMaximumApplicationAddress) {
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ)) &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
        {
            BYTE* b = (BYTE*)mbi.BaseAddress;
            BYTE* e = b + mbi.RegionSize;
            for (BYTE* p = b; p + sizeof(void*) <= e; p += sizeof(void*)) {
                if (*(void**)p == (void*)vtable) {
                    MEMORY_BASIC_INFORMATION mbi2;
                    if (VirtualQuery(p, &mbi2, sizeof(mbi2)) &&
                        (mbi2.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                        g_moveComp = p;
                        sprintf_s(buf, sizeof(buf), "MoveComp candidate %p", p);
                        WriteRawLog(buf);
                        return;
                    }
                }
            }
        }
        addr += mbi.RegionSize;
    }
    WriteRawLog("Move component not found via scan");
}

typedef uint32_t(__stdcall* UpdateState_stdcall)(uint32_t moveComp,
    uint32_t dir,
    int runFlag,
    void* dest);

static int __cdecl Lua_Walk(void* /*L*/)
{
    // Instead of queuing a direction for the update hook, build and
    // transmit a movement packet directly. This bypasses the game's
    // internal movement component and relies on our network hook.

    SendWalk(4, 1); // run east
    return 0;
}

extern "C" __declspec(dllexport) void __stdcall SendRaw(const void* bytes, int len)
{
    if (len > 0 && g_sendPacket && g_netMgr)
    {
        g_sendPacket(g_netMgr, bytes, len);
    }
    else
    {
        WriteRawLog("SendRaw called before prerequisites were ready");
    }
}

extern "C" __declspec(dllexport) void __stdcall SendWalk(int dir, int run)
{
    if (!g_sendPacket || !g_netMgr)
    {
        WriteRawLog("SendWalk prerequisites missing");
        return;
    }
    uint8_t pkt[7]{};
    pkt[0] = 0x02;                                 // Move request opcode
    pkt[1] = uint8_t(dir & 7) | (run ? 0x80 : 0);  // Direction + run flag
    static uint8_t seq = 0;
    if (++seq == 0)
        seq = 1;                                   // Sequence wraps to 1
    pkt[2] = seq;
    *reinterpret_cast<uint32_t*>(pkt + 3) = PopFastWalkKey();
    g_sendPacket(g_netMgr, pkt, sizeof(pkt));
}


static uint32_t __fastcall H_Update(void* thisPtr,  // ECX
    void* _unused,  // EDX
    void* destPtr,
    uint32_t dir,
    int     runFlag)
{
    if (!g_moveComp && InterlockedCompareExchange(&g_haveMoveComp, 1, 0) == 0)
    {
        g_moveComp = thisPtr;
        Logf("Captured moveComp = %p (thread %lu)", g_moveComp,
            GetCurrentThreadId());
        InterlockedExchange(&g_needWalkReg, 1);
    }

    if (g_updateDepth++ == 0 && g_updateLogCount < 200)
    {
        Logf("updateState(this=%p, dest=%p, dir=%u, run=%d)",
            thisPtr, destPtr, dir, runFlag);
        ++g_updateLogCount;
    }

    g_dest = destPtr;                 // save the real dest for Lua walk()
    uint32_t rc = g_origUpdate(thisPtr, destPtr, dir, runFlag);

    int pend = g_pendingDir.exchange(-1, std::memory_order_relaxed);
    if (pend >= 0 && g_origUpdate)
    {
        struct Vec3 { int16_t x, y; int8_t z; };
        Vec3 tmp = *reinterpret_cast<Vec3*>(destPtr);
        static const int dx[8] = {0,1,1,1,0,-1,-1,-1};
        static const int dy[8] = {-1,-1,0,1,1,1,0,-1};
        tmp.x += dx[pend];
        tmp.y += dy[pend];
        int run = g_pendingRun.load(std::memory_order_relaxed);
        g_origUpdate(thisPtr, &tmp, (uint32_t)pend, run);
    }

    --g_updateDepth;
    if (g_updateDepth == 0) {
        if (InterlockedExchange(&g_needWalkReg, 0) &&
            !g_regBusy.test_and_set(std::memory_order_acquire))
        {
            g_regThread = CreateThread(nullptr, 0, RegisterThread, nullptr, 0, nullptr);
        }
    }
    return rc;
}

// ---------------------------------------------------------------------------
// Winsock send-family hooks
// ---------------------------------------------------------------------------

static void TraceOutbound(const char* buf, int len)
{
    Logf("send-family len=%d id=%02X", len, (unsigned char)buf[0]);
    int dumpLen = len > 64 ? 64 : len;
    if (dumpLen > 0)
        DumpMemory("Outbound packet", (void*)buf, dumpLen);
    if (!g_sendBuilderHooked)
        HookSendBuilderFromNetMgr();
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

// ---------------------------------------------------------------------------
// SendBuilder detours
// ---------------------------------------------------------------------------

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
            MH_EnableHook(fn);
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
    if (g_builderScanned || !g_globalStateInfo)
        return;

    void** netMgr = reinterpret_cast<void**>(g_globalStateInfo->networkConfig);
    if (!netMgr)
        return;

    void* endpoint = netMgr[0];
    TryHookSendBuilder(endpoint);
}

static void __fastcall H_SendPacket(void* thisPtr, void* _unused, const void* pkt, int len)
{
    // Log the plaintext packet before the client encrypts it
    DumpMemory("PLAIN-SendPacket", const_cast<void*>(pkt), len);

    if (!g_netMgr)
        g_netMgr = thisPtr;
    if (!g_builderScanned)
        HookSendBuilderFromNetMgr();
    if (g_sendBuilderHooked || g_builderScanned)
        InterlockedExchange(&g_needWalkReg, 1);
    g_sendPacket(thisPtr, pkt, len);
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

// ---------------------------------------------------------------------------
// updateDataStructureState hook
// ---------------------------------------------------------------------------

static void InstallUpdateHook()
{
    const char* kUpdateSig =
        "83 EC 58 53 55 8B 6C 24 64 80 7D 79 00 56 57 0F 85 ?? ?? ?? 00"
        "80 7D 7A 00 0F 85 ?? ?? ?? 00";

    BYTE* hit = FindPatternText(kUpdateSig);
    if (hit) {
        g_updateState = reinterpret_cast<UpdateState_t>(hit);
        char buf[64];
        sprintf_s(buf, sizeof(buf), "Found updateDataStructureState at %p", hit);
        WriteRawLog(buf);
        if (MH_CreateHook(g_updateState, &H_Update, reinterpret_cast<LPVOID*>(&g_origUpdate)) == MH_OK &&
            MH_EnableHook(g_updateState) == MH_OK)
        {
            WriteRawLog("updateDataStructureState hook installed");
        }
        else {
            WriteRawLog("updateDataStructureState hook failed; falling back to scan");
            g_origUpdate = g_updateState;
            FindMoveComponent();
        }
    }
    else {
        WriteRawLog("updateDataStructureState not found");
    }
}


static void* FindGlobalStateInfo() {
    HMODULE hExe = GetModuleHandleA(nullptr);
    if (!hExe) return nullptr;

    BYTE* base = (BYTE*)hExe;

    // Get PE headers
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

    // Multiple patterns to try
    static const struct {
        const wchar_t* w;   // UTF-16 literal (may be null)
        const char* a;      // ANSI literal (may be null) 
        int zeros;          // Expected consecutive zero DWORDs
    } needles[] = {
        {L"Text is cut off in Label", nullptr, 4},
        {L"UOSetWaypointMapFacet", nullptr, 4},
        {L"ProfessionDescriptionWindowText", nullptr, 4},
        {nullptr, "UOSetWaypointMapFacet", 4}, // ANSI fallback
    };

    static bool bannerShown = false; // Add static flag to reduce spam
    char buffer[256];
    bool foundAny = false;

    // Scan data sections but only once
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections && !foundAny; ++i, ++sec) {
        if ((sec->Characteristics & IMAGE_SCN_MEM_READ) &&
            (sec->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA))
        {
            BYTE* sectionStart = base + sec->VirtualAddress;
            size_t sectionSize = sec->Misc.VirtualSize;

            // Try each pattern
            for (const auto& needle : needles) {
                BYTE* hit = nullptr;
                if (needle.w) {
                    // UTF-16 pattern
                    size_t len = (wcslen(needle.w) + 1) * 2;
                    hit = FindPattern(sectionStart, sectionSize, (const BYTE*)needle.w, len);
                }
                else if (needle.a) {
                    // ANSI pattern
                    size_t len = strlen(needle.a) + 1;
                    hit = FindPattern(sectionStart, sectionSize, (const BYTE*)needle.a, len);
                }

                if (hit) {
                    foundAny = true;
                    if (!bannerShown) {
                        if (needle.w) {
                            // Convert wide string to UTF-8 for logging
                            char utf8buf[128];
                            int conv = WideCharToMultiByte(CP_UTF8, 0, needle.w, -1, utf8buf, sizeof(utf8buf), NULL, NULL);
                            sprintf_s(buffer, sizeof(buffer),
                                "Found pattern '%s' at %p (zeros: %d)",
                                conv > 0 ? utf8buf : "<wchar_t conversion failed>", hit, needle.zeros);
                        }
                        else if (needle.a) {
                            sprintf_s(buffer, sizeof(buffer),
                                "Found pattern '%s' at %p (zeros: %d)",
                                needle.a, hit, needle.zeros);
                        }
                        WriteRawLog(buffer);
                        bannerShown = true;
                    }

                    // Walk back looking for zero block
                    DWORD* p = (DWORD*)hit;
                    for (int step = 0; step < 0x200; step += 4, --p) {
                        bool allZero = true;
                        for (int z = 0; z < needle.zeros && allZero; z++) {
                            if (p[z] != 0) allZero = false;
                        }

                        if (allZero) {
                            // Address of pointer variable following padding
                            DWORD* addrOfPtr = p + needle.zeros;

                            // Defensive check - ensure we're still in module
                            if (addrOfPtr < (DWORD*)base || addrOfPtr >(DWORD*)(base + nt->OptionalHeader.SizeOfImage - 4))
                                continue;

                            GlobalStateInfo* info = *(GlobalStateInfo**)addrOfPtr;

                            // addrOfPtr = &staticGlobalStatePtr
                            g_globalStateSlot = (DWORD*)addrOfPtr;
                            if (g_globalStateSlot)
                                InstallWriteWatch();        // arm guard page immediately

                            if (!info)              // pointer not initialised yet
                            {
                                WriteRawLog("GlobalState pointer slot found but still NULL");
                                return nullptr;      // let caller know we did not get the struct yet
                            }

                            __try {
                                if (info->luaState && info->databaseManager) {
                                    sprintf_s(buffer, sizeof(buffer),
                                        "Found GlobalStateInfo at %p:\n"
                                        "  Lua State: %p\n"
                                        "  DB Manager: %p\n"
                                        "  Resource Mgr: %p",
                                        info, info->luaState,
                                        info->databaseManager,
                                        info->resourceManager);
                                    WriteRawLog(buffer);
                                    return info;
                                }
                            }
                            __except (EXCEPTION_EXECUTE_HANDLER) {
                                WriteRawLog("Access violation checking candidate");
                            }
                        }
                    }
                }
            }
        }
    }

    return nullptr;
}

// More robust function finder with write detection
static LPVOID FindRegisterLuaFunction() {
    HMODULE hExe = GetModuleHandleA(nullptr);
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), hExe, &mi, sizeof(mi)))
        return nullptr;

    BYTE* base = (BYTE*)mi.lpBaseOfDll;
    SIZE_T size = mi.SizeOfImage;

    static const char anchor[] = "GetBuildVersion";
    BYTE* str = FindBytes(base, size, (const BYTE*)anchor, sizeof(anchor));
    if (!str) return nullptr;

    char buffer[128];
    sprintf_s(buffer, sizeof(buffer), "Found GetBuildVersion string at %p", str);
    WriteRawLog(buffer);

    // Look for any push/lea that loads the string, then next near call
    for (BYTE* p = base; p < base + size - 5; ++p) {
        // push offset xxx  OR   lea eax, [xxx]
        bool hits =
            (p[0] == 0x68 && *(DWORD*)(p + 1) == (DWORD)(uintptr_t)str) ||      // push imm32
            (p[0] == 0x8D && (p[1] & 0xC7) == 0x05 &&                           // lea eax, [addr]
                *(DWORD*)(p + 2) == (DWORD)(uintptr_t)str);

        if (!hits) continue;

        sprintf_s(buffer, sizeof(buffer), "Found string reference at %p", p);
        WriteRawLog(buffer);

        // Walk forward max 32 bytes to find near call (E8 xx xx xx xx) or indirect call (FF 15 xx xx xx xx)
        for (BYTE* q = p; q < p + 32; ++q) {
            LPVOID target = nullptr;

            if (*q == 0xE8) {  // near call
                INT32 rel = *(INT32*)(q + 1);
                BYTE* callee = q + 5 + rel;
                sprintf_s(buffer, sizeof(buffer), "Found direct call instruction at %p targeting %p", q, callee);
                WriteRawLog(buffer);
                target = callee;

                // Look both forward and backward for mov [abs32], reg (A3 xx xx xx xx OR 89 /r)
                for (BYTE* k = q - 64; k < q + 64; ++k) {
                    if (k[0] == 0xA3) {  // mov [abs32], eax
                        g_globalStateSlot = (DWORD*)(*(DWORD*)(k + 1));
                        sprintf_s(buffer, sizeof(buffer), "Found global state write (A3) at %p targeting slot %p",
                            k, g_globalStateSlot);
                        WriteRawLog(buffer);
                        break;
                    }
                    // 89 /r xx xx xx xx: mov [abs32], r32 (rm == 101b for disp32)
                    if (k[0] == 0x89 && (k[1] & 0x07) == 0x05) {  // Bottom 3 bits = 101b
                        g_globalStateSlot = (DWORD*)(*(DWORD*)(k + 2));
                        sprintf_s(buffer, sizeof(buffer), "Found global state write (89 %02X) at %p targeting slot %p",
                            k[1], k, g_globalStateSlot);
                        WriteRawLog(buffer);
                        break;
                    }
                }
            }
            else if (q[0] == 0xFF && q[1] == 0x15) {  // FF 15 [disp32] → call [absolute]
                DWORD disp = *(DWORD*)(q + 2);
                BYTE** abs = (BYTE**)(q + 6 + disp);  // RIP-relative
                BYTE* callee = *abs;  // Contents of IAT entry
                sprintf_s(buffer, sizeof(buffer), "Found indirect call instruction at %p targeting %p", q, callee);
                WriteRawLog(buffer);
                target = callee;

                // Same expanded pattern search for mov [abs32], reg
                for (BYTE* k = q - 64; k < q + 64; ++k) {
                    if (k[0] == 0xA3) {
                        g_globalStateSlot = (DWORD*)(*(DWORD*)(k + 1));
                        sprintf_s(buffer, sizeof(buffer), "Found global state write (A3) at %p targeting slot %p",
                            k, g_globalStateSlot);
                        WriteRawLog(buffer);
                        break;
                    }
                    if (k[0] == 0x89 && (k[1] & 0x07) == 0x05) {  // Bottom 3 bits = 101b
                        g_globalStateSlot = (DWORD*)(*(DWORD*)(k + 2));
                        sprintf_s(buffer, sizeof(buffer), "Found global state write (89 %02X) at %p targeting slot %p",
                            k[1], k, g_globalStateSlot);
                        WriteRawLog(buffer);
                        break;
                    }
                }
            }

            if (target) return target;
        }
    }

    WriteRawLog("Could not find RegisterLuaFunction reference");
    return nullptr;
}

static void* FindOwnerOfLuaState(void* lua) {
    if (!lua) return nullptr;
    char buf[128];

    HMODULE hExe = GetModuleHandleA(nullptr);
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hExe;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)hExe + dos->e_lfanew);

    // First try data sections
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_READ) ||
            !(sec->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA))
            continue;  // .data / .rdata only

        BYTE* beg = (BYTE*)hExe + sec->VirtualAddress;
        BYTE* end = beg + sec->Misc.VirtualSize;

        for (BYTE* p = beg; p + sizeof(void*) <= end; p += sizeof(void*)) {
            if (*(void**)p != lua) continue;  // not our pointer

            // ─────────────────────────────────────────────────────────────
            // 1) assume p *is* the struct base (lua at offset 0)
            // ─────────────────────────────────────────────────────────────
            {
                GlobalStateInfo* g = (GlobalStateInfo*)p;
                if (IsOnCurrentStack(g)) {
                    WriteRawLog("Rejecting candidate: on current stack");
                }
                else {
                    __try {
                        if (g->luaState == lua && g->databaseManager) {
                            sprintf_s(buf, sizeof(buf),
                                "Validated GlobalStateInfo (no padding) @ %p", g);
                            WriteRawLog(buf);
                            return g;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
            }

            // ─────────────────────────────────────────────────────────────
            // 2) older pattern: four zero DWORDs immediately *before* ptr
            // ─────────────────────────────────────────────────────────────
            DWORD* d = (DWORD*)p - 4;
            __try {
                if (!d[0] && !d[1] && !d[2] && !d[3]) {
                    GlobalStateInfo* g = *(GlobalStateInfo**)(d + 4);
                    if (g) {
                        if (IsOnCurrentStack(g)) {
                            WriteRawLog("Rejecting candidate: on current stack");
                        }
                        else if (g->luaState == lua && g->databaseManager) {
                            sprintf_s(buf, sizeof(buf),
                                "Validated GlobalStateInfo (zero-block) @ %p", g);
                            WriteRawLog(buf);
                            return g;
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }

    // --------------------------------------------------------------------
    // 3) final fall-back - search the CRT heap once: walk low address space
    // --------------------------------------------------------------------
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    BYTE* addr = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (addr < (BYTE*)si.lpMaximumApplicationAddress) {
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) break;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ)) &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
        {
            BYTE* b = (BYTE*)mbi.BaseAddress;
            BYTE* e = b + mbi.RegionSize;

            for (BYTE* p = b; p + sizeof(void*) <= e; p += sizeof(void*)) {
                if (*(void**)p != lua) continue;

                GlobalStateInfo* g = (GlobalStateInfo*)p;
                if (IsOnCurrentStack(g)) {
                    WriteRawLog("Rejecting candidate: on current stack");
                }
                else {
                    __try {
                        if (g->luaState == lua && g->databaseManager) {
                            sprintf_s(buf, sizeof(buf),
                                "Validated GlobalStateInfo (heap) @ %p", g);
                            WriteRawLog(buf);
                            return g;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
            }
        }
        addr += mbi.RegionSize;
    }

    WriteRawLog("Owner of Lua state not found");
    return nullptr;
}

// Background thread to wait for Lua state
static DWORD WINAPI WaitForLua(LPVOID) {
    WriteRawLog("Starting Lua state scan thread...");

    while (!g_luaStateCaptured && !g_stopScan) {
        GlobalStateInfo* info = (GlobalStateInfo*)FindGlobalStateInfo();
        if (info && info->luaState) {
            g_globalStateInfo = info;
            g_luaState = info->luaState;

            char buffer[128];
            sprintf_s(buffer, sizeof(buffer), "Scanner found Lua State @ %p", g_luaState);
            WriteRawLog(buffer);

            return 0;
        }
        Sleep(200);  // ~5µs CPU per pass
    }

    WriteRawLog(g_luaStateCaptured ? "Hook found Lua state first" : "Scanner stopped");
    return 1;
}

// Worker thread to register our Lua functions outside of client update
static DWORD WINAPI RegisterThread(LPVOID) {
    RegisterOurLuaFunctions();
    g_regBusy.clear(std::memory_order_release);
    return 0;
}

// Safely invoke the client's RegisterLuaFunction
static bool CallClientRegister(void* L, void* func, const char* name)
{
    if (!g_origRegLua) {
        WriteRawLog("Original RegisterLuaFunction pointer not set!");
        return false;
    }
    __try {
        return g_origRegLua(L, func, name);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        char buf[64];
        sprintf_s(buf, sizeof(buf), "RegisterLuaFunction threw exception 0x%08X", code);
        WriteRawLog(buf);
        return false;
    }
}

static void RegisterOurLuaFunctions()
{
    static bool dummyReg = false;
    static bool walkReg = false;
    static bool sendReg = false;
    if (!g_luaState || !g_origRegLua)
        return;

    // Client hook should already be installed

    if (!dummyReg) {
        const char* luaName = "DummyPrint";
        WriteRawLog("Registering DummyPrint Lua function...");
        if (CallClientRegister(g_luaState,
            reinterpret_cast<void*>(Lua_DummyPrint),
            luaName))
        {
            char buf[128];
            sprintf_s(buf, sizeof(buf),
                "Successfully registered Lua function '%s' (%p)",
                luaName, Lua_DummyPrint);
            WriteRawLog(buf);
            dummyReg = true;
        }
        else
        {
            WriteRawLog("!! Failed to register DummyPrint");
        }
    }

    if (g_updateState && g_moveComp && !walkReg) {
        const char* walkName = "walk";
        WriteRawLog("Registering walk Lua function...");
        bool ok = CallClientRegister(g_luaState,
            reinterpret_cast<void*>(Lua_Walk), walkName);
        WriteRawLog(ok ? "Successfully registered walk()" :
            "!! Register walk() failed");
        if (ok) {
            walkReg = true;
        }
    }
    else if (!g_moveComp && !walkReg) {
        WriteRawLog("walk function prerequisites missing");
    }
    WriteRawLog("RegisterOurLuaFunctions completed");
}

// Hook function for RegisterLuaFunction
static bool __stdcall Hook_Register(void* L, void* func, const char* name) {
    // Short-circuit if we already have everything we need
    if (g_globalStateInfo) {
        return CallClientRegister(L, func, name);
    }

    char buffer[256];

    // First capture the Lua state
    if (!g_luaState) {
        g_luaState = L;
        g_luaStateCaptured = true;  // This alone will stop the scanner thread
        sprintf_s(buffer, sizeof(buffer), "Captured first Lua state @ %p", L);
        WriteRawLog(buffer);

        // Now find its owner structure
        g_globalStateInfo = (GlobalStateInfo*)FindOwnerOfLuaState(L);
        if (g_globalStateInfo) {
            DumpMemory("GlobalStateInfo", g_globalStateInfo, 0x40);

            // Scanner thread will exit on its own due to g_luaStateCaptured
            if (g_scanThread) {
                WaitForSingleObject(g_scanThread, INFINITE);
                CloseHandle(g_scanThread);
                g_scanThread = NULL;
            }

            WriteRawLog("DLL is now fully initialized - enjoy!");
            WriteRawLog("Registering our Lua functions...");
            // Defer actual Lua‑function registration to the next safe‑point
            InterlockedExchange(&g_needWalkReg, 1);
            HookSendBuilderFromNetMgr();
        }
    }

    sprintf_s(buffer, sizeof(buffer),
        "RegisterLuaFunction called:\n"
        "  Lua State: %p\n"
        "  Function: %p\n"
        "  Name: %s\n"
        "  Global State Info: %p",
        L, func, name ? name : "<null>", g_globalStateInfo);
    WriteRawLog(buffer);

    WriteRawLog("Calling original RegisterLuaFunction...");
    bool ok = CallClientRegister(L, func, name);
    WriteRawLog(ok ? "Original RegisterLuaFunction returned true"
        : "Original RegisterLuaFunction returned false");

    return ok;
}

// Validator function prototype 
static GlobalStateInfo* ValidateGlobalState(GlobalStateInfo* candidate) {
    if (!candidate) return nullptr;

    // Never accept pointers that sit on the caller's stack
    if (IsOnCurrentStack(candidate)) {
        WriteRawLog("Rejecting candidate: on current stack");
        return nullptr;
    }

    __try {
        if (candidate->luaState && candidate->databaseManager) {
            char buffer[256];
            sprintf_s(buffer, sizeof(buffer),
                "Write hook validated GlobalStateInfo @ %p:\n"
                "  Lua State: %p\n"
                "  DB Manager: %p\n"
                "  Resource Mgr: %p",
                candidate, candidate->luaState,
                candidate->databaseManager,
                candidate->resourceManager);
            WriteRawLog(buffer);

            // Store globally so RegisterLuaFunction hook can use it
            g_globalStateInfo = candidate;
            g_luaState = candidate->luaState;

            // Tell scanner thread we found it
            g_luaStateCaptured = true;

            return candidate;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("Access violation in write hook validation");
    }
    return candidate;  // Pass through even if validation fails
}

// Add to InstallRegisterHook
static bool InstallRegisterHook() {
    LPVOID target = FindRegisterLuaFunction();
    if (!target) {
        WriteRawLog("RegisterLuaFunction not found");
        return false;
    }

    char buffer[64];
    sprintf_s(buffer, sizeof(buffer), "RegisterLuaFunction at %p", target);
    WriteRawLog(buffer);

    // Install main hook for RegisterLuaFunction
    if (MH_CreateHook(target, &Hook_Register, reinterpret_cast<LPVOID*>(&g_origRegLua)) != MH_OK) {
        WriteRawLog("MH_CreateHook failed for RegisterLuaFunction");
        return false;
    }

    // Enable MinHook hooks
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        WriteRawLog("MH_EnableHook failed");
        return false;
    }

    WriteRawLog("Hooks installed successfully");
    return true;
}

static BOOL InitializeDLLSafe(HMODULE hModule) {
    WriteRawLog("DLL initialization starting...");

    __try {
        // Store module handle for later use
        g_hModule = hModule;

        // Log process info and loaded modules
        LogLoadedModules();

        // Initialize MinHook
        WriteRawLog("Initializing MinHook...");
        MH_STATUS status = MH_Initialize();
        if (status != MH_OK) {
            char buffer[64];
            sprintf_s(buffer, sizeof(buffer), "MinHook initialization failed: %d", status);
            WriteRawLog(buffer);
            return FALSE;
        }
        WriteRawLog("MinHook initialized successfully");

        // Initialize symbol handler for stack traces
        SymInitialize(GetCurrentProcess(), NULL, TRUE);

        // Install hooks
        InstallUpdateHook();
        InstallSendHooks();
        FindSendPacket();
        HookSendPacket();

        // Start background thread to scan for Lua state
        g_scanThread = CreateThread(nullptr, 0, WaitForLua, nullptr, 0, nullptr);
        if (!g_scanThread) {
            WriteRawLog("Failed to create scanner thread");
            return FALSE;
        }

        // RegisterLuaFunction hook is optional
        char env[2];
        bool enableHook = UOWP_HOOK_REGISTER || false;
        if (enableHook) {
            if (!InstallRegisterHook()) {
                WriteRawLog("Warning: RegisterLuaFunction hook not installed");
            }
        }
        else {
            WriteRawLog("RegisterLuaFunction hook disabled");
        }

        g_initialized = TRUE;
        WriteRawLog("DLL initialization successful");
        SetupConsole();
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        char buffer[64];
        sprintf_s(buffer, sizeof(buffer), "Exception in initialization: 0x%08X", GetExceptionCode());
        WriteRawLog(buffer);
        return FALSE;
    }
}

static void CleanupDLL() {
    WriteRawLog("Starting cleanup...");

    if (g_scanThread) {
        g_stopScan = 1;  // Signal scanner to stop
        WaitForSingleObject(g_scanThread, 1000);
        CloseHandle(g_scanThread);
        g_scanThread = NULL;
    }

    if (g_vehHandle) {
        RemoveVectoredExceptionHandler(g_vehHandle);
        g_vehHandle = nullptr;
    }

    if (g_initialized) {
        if (g_origRegLua) {
            MH_DisableHook(MH_ALL_HOOKS);
            g_origRegLua = NULL;
        }

        MH_STATUS status = MH_Uninitialize();
        if (status != MH_OK) {
            char buffer[64];
            sprintf_s(buffer, sizeof(buffer), "MinHook cleanup failed: %d", status);
            WriteRawLog(buffer);
        }
        g_initialized = FALSE;
    }

    SymCleanup(GetCurrentProcess());

    if (g_logFile != INVALID_HANDLE_VALUE) {
        WriteRawLog("Closing log file");
        CloseHandle(g_logFile);
        g_logFile = INVALID_HANDLE_VALUE;
    }

    g_hModule = NULL;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    // Initialize globals first - this needs to work even if we can't open log file
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = NULL;
        g_logFile = INVALID_HANDLE_VALUE;
        g_logPath[0] = '\0';
        g_logAnnounced = FALSE;
        g_initialized = FALSE;
        g_globalStateInfo = nullptr;
        g_luaState = nullptr;  // Important: initialize before creating threads
        g_scanThread = NULL;
        g_origRegLua = NULL;

        // Create a log file in the DLL's directory before anything else
        char dllPath[MAX_PATH];
        if (GetModuleFileNameA(hModule, dllPath, MAX_PATH)) {
            char* lastSlash = strrchr(dllPath, '\\');
            if (lastSlash) {
                strcpy_s(lastSlash + 1, MAX_PATH - (lastSlash - dllPath), "uowalkpatch_debug.log");
                g_logFile = CreateFileA(
                    dllPath,
                    GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL,
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL
                );
            }
        }
    }

    char buffer[128];
    sprintf_s(buffer, sizeof(buffer), "DllMain entry - reason: %lu", reason);
    WriteRawLog(buffer);

    __try {
        switch (reason) {
        case DLL_PROCESS_ATTACH: {
            // Log our load address 
            sprintf_s(buffer, sizeof(buffer), "DLL loaded at address: %p", hModule);
            WriteRawLog(buffer);

            // Prevent the DLL from being unloaded by the system
            HMODULE hSelf;
            if (!GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_PIN,
                (LPCSTR)hModule,
                &hSelf)) {
                sprintf_s(buffer, sizeof(buffer), "GetModuleHandleExA failed to pin DLL: %lu", GetLastError());
                WriteRawLog(buffer);
            }

            // Log process and module info before we try to initialize
            LogLoadedModules();

            if (!InitializeDLLSafe(hModule)) {
                WriteRawLog("Initialization failed - cleaning up");
                CleanupDLL();
                return FALSE;
            }
            return TRUE;
        }
        case DLL_PROCESS_DETACH:
            WriteRawLog("DLL_PROCESS_DETACH");
            CleanupDLL();
            break;
        case DLL_THREAD_ATTACH:
            WriteRawLog("DLL_THREAD_ATTACH");
            break;
        case DLL_THREAD_DETACH:
            WriteRawLog("DLL_THREAD_DETACH");
            break;
        }
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        sprintf_s(buffer, sizeof(buffer), "Exception in DllMain: 0x%08X", code);
        WriteRawLog(buffer);
        return FALSE;
    }
}

// Write to debug output and file without any fancy formatting
static void WriteRawLog(const char* message) {
    if (!message) return;

    // Write to debug output
    OutputDebugStringA(message);
    OutputDebugStringA("\n");

    // Write to console if available
    if (GetConsoleWindow()) {
        printf("[%lu] %s\n", GetCurrentThreadId(), message);
        fflush(stdout); // Ensure immediate output
    }

    // Try to open log in executable directory first
    if (g_logFile == INVALID_HANDLE_VALUE && g_hModule != NULL) {
        GetModuleFileNameA(g_hModule, g_logPath, MAX_PATH);
        char* lastSlash = strrchr(g_logPath, '\\');
        if (lastSlash) {
            strcpy_s(lastSlash + 1, MAX_PATH - (lastSlash - g_logPath), "uowalkpatch_debug.log");
            g_logFile = CreateFileA(
                g_logPath,
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );

            // Log creation error if any
            if (g_logFile == INVALID_HANDLE_VALUE) {
                LogLastError("CreateFile for log");
            }
        }
    }

    // Write to log file
    if (g_logFile != INVALID_HANDLE_VALUE) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buffer[4096];
        int len = sprintf_s(buffer, sizeof(buffer),
            "[%02d:%02d:%02d.%03d] [%lu] %s\r\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            GetCurrentThreadId(),
            message
        );
        if (len > 0) {
            DWORD written;
            if (!WriteFile(g_logFile, buffer, len, &written, NULL)) {
                LogLastError("WriteFile to log");
            }
            else {
                FlushFileBuffers(g_logFile);

                if (!g_logAnnounced) {
                    g_logAnnounced = TRUE;
                    char pathMsg[MAX_PATH + 32];
                    sprintf_s(pathMsg, sizeof(pathMsg), "Log file: %s", g_logPath);
                    WriteRawLog(pathMsg); // Use WriteRawLog to avoid recursion
                }
            }
        }
    }
}

// Helper to log last error with Win32 message
static void LogLastError(const char* prefix) {
    if (!prefix) return;

    DWORD error = GetLastError();
    char buffer[1024];
    char errorMsg[512] = "";

    FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        errorMsg,
        sizeof(errorMsg),
        NULL
    );

    // Clean up error message
    for (char* p = errorMsg; *p; p++) {
        if (*p == '\r' || *p == '\n') *p = ' ';
    }

    sprintf_s(buffer, sizeof(buffer), "%s failed with 0x%08X: %s", prefix, error, errorMsg);
    WriteRawLog(buffer);
}

// Log all loaded modules for debugging
static void LogLoadedModules() {
    WriteRawLog("Enumerating loaded modules:");

    HANDLE hProcess = GetCurrentProcess();
    HMODULE hMods[1024];
    DWORD needed;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &needed)) {
        for (DWORD i = 0; i < (needed / sizeof(HMODULE)); i++) {
            char path[MAX_PATH] = "";
            char buffer[MAX_PATH + 64] = "";

            if (GetModuleFileNameExA(hProcess, hMods[i], path, MAX_PATH)) {
                MODULEINFO mi = { 0 };
                if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
                    sprintf_s(buffer, sizeof(buffer), "  %p - %p: %s",
                        mi.lpBaseOfDll,
                        (char*)mi.lpBaseOfDll + mi.SizeOfImage,
                        path);
                }
                else {
                    sprintf_s(buffer, sizeof(buffer), "  %p: %s", hMods[i], path);
                }
                WriteRawLog(buffer);
            }
        }
    }
    else {
        LogLastError("EnumProcessModules");
    }
}

// Setup console window for debug output
static void SetupConsole() {
    if (!GetConsoleWindow()) {
        if (AllocConsole()) {
            FILE* dummy;
            freopen_s(&dummy, "CONOUT$", "w", stdout);
            freopen_s(&dummy, "CONOUT$", "w", stderr);
            SetConsoleTitleA("UOWalkPatch console");
        }
    }
}

// VEH handler to catch write to global state pointer via guard page
static LONG CALLBACK VehHandler(EXCEPTION_POINTERS* x)
{
    if (x->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION &&
        x->ExceptionRecord->NumberParameters >= 2 &&
        (void*)x->ExceptionRecord->ExceptionInformation[1] == g_globalStateSlot)
    {
        // Remove guard and validate the newly written pointer
        DWORD oldProtect;
        VirtualProtect(g_globalStateSlot, sizeof(void*), PAGE_READWRITE, &oldProtect);

        GlobalStateInfo* info = *(GlobalStateInfo**)g_globalStateSlot;
        ValidateGlobalState(info);

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Install guard page to watch global state pointer write
static void InstallWriteWatch()
{
    if (!g_globalStateSlot) return;

    if (InterlockedExchange(&g_once, 1) == 0) {
        char buffer[128];
        sprintf_s(buffer, sizeof(buffer), "Installing write watch on slot %p", g_globalStateSlot);
        WriteRawLog(buffer);

        // Calculate page address containing the slot
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        BYTE* page = (BYTE*)g_globalStateSlot - ((uintptr_t)g_globalStateSlot & (si.dwPageSize - 1));

        // Install guard page
        DWORD oldProtect;
        if (VirtualProtect(page, si.dwPageSize, PAGE_READWRITE | PAGE_GUARD, &oldProtect)) {
            g_vehHandle = AddVectoredExceptionHandler(1, VehHandler);
            WriteRawLog("Guard-page write watch installed successfully");
        }
        else {
            sprintf_s(buffer, sizeof(buffer), "Failed to set guard page at %p: error %lu",
                page, GetLastError());
            WriteRawLog(buffer);
        }
    }
}