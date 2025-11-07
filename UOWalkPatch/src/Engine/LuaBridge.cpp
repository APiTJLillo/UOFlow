#include <windows.h>
#include <cstdio>
#include <cctype>
#include <cstring>
#include <minhook.h>
#include <psapi.h>
#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstddef>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <optional>

#include "Core/Logging.hpp"
#include "Core/PatternScan.hpp"
#include "Core/Config.hpp"
#include "Net/PacketTrace.hpp"
#include "Core/ActionTrace.hpp"
#include "Net/SendBuilder.hpp"
#include "Engine/GlobalState.hpp"
#include "Engine/Movement.hpp"
#include "Engine/LuaBridge.hpp"
#include "Util/OwnerPump.hpp"
#include "Core/Utils.hpp"
#include "LuaPlus.h"
#include "CastCorrelator.h"

// LuaPlus.h intentionally exposes only a subset of the Lua C API.
// Declare the few additional APIs we need for stack manipulation + pcall usage.
extern "C" {
    LUA_API void lua_insert(lua_State* L, int idx);
    LUA_API void lua_pushvalue(lua_State* L, int idx);
    LUA_API const char* lua_tolstring(lua_State* L, int idx, size_t* len);
    LUA_API lua_Number lua_tonumber(lua_State* L, int idx);
    LUA_API const char* lua_getupvalue(lua_State* L, int funcIndex, int n);
    LUA_API void lua_getfenv(lua_State* L, int idx);
    LUA_API void lua_replace(lua_State* L, int idx);
}
#ifndef LUA_MULTRET
#define LUA_MULTRET (-1)
#endif

#ifndef LUA_REGISTRYINDEX
#define LUA_REGISTRYINDEX (-10000)
#endif


namespace {
    using ClientRegisterFn = int(__stdcall*)(void*, void*, const char*);
    using LuaFn = int(__cdecl*)(lua_State*);

    ClientRegisterFn g_clientRegister = nullptr;
    ClientRegisterFn g_origRegister = nullptr;
    bool g_registerResolved = false;
    void* g_registerTarget = nullptr;
    void* g_engineContext = nullptr;
    void* g_clientContext = nullptr;
    std::atomic<void*> g_ownerScriptContext{nullptr};
    std::atomic<std::uint32_t> g_ownerThreadId{0};

    struct ObservedContext {
        void* ctx;
        unsigned flags;
    };

    static constexpr size_t kMaxObservedContexts = 8;
static ObservedContext g_observedContexts[kMaxObservedContexts]{};

enum ContextLogBits : unsigned {
    kLogWalk = 1u << 0,
    kLogBindWalk = 1u << 1,
};

    static volatile LONG g_pendingRegistration = 0;
    static thread_local bool g_inScriptRegistration = false;

    // Late-install control for action wrappers
    static volatile LONG g_actionWrappersInstalled = 0;
    static volatile LONG g_targetApiSeen = 0;
    static DWORD g_targetApiTimestamp = 0;

    // Captured originals for key client Lua C functions we want to trace.
    static LuaFn g_origUserActionCastSpell = nullptr;
    static LuaFn g_origUserActionCastSpellOnId = nullptr;
    static LuaFn g_origUserActionUseSkill = nullptr;
    static LuaFn g_origUserActionIsTargetModeCompat = nullptr;
    static LuaFn g_origUserActionIsActionTypeTargetModeCompat = nullptr;
    static LuaFn g_origRequestTargetInfo = nullptr;
    static LuaFn g_origClearCurrentTarget = nullptr;
    // Additional originals for gating and ability paths
    static LuaFn g_origUserActionIsSkillAvalible = nullptr; // name spelled as in client
    static LuaFn g_origHS_ShowTargetingCursor = nullptr;
    static LuaFn g_origHS_HideTargetingCursor = nullptr;
    static LuaFn g_origUserActionUseWeaponAbility = nullptr;
    static LuaFn g_origUserActionUsePrimaryAbility = nullptr;

    static volatile LONG g_directActionHooksInstalled = 0;

    // Cast spell tracing helpers
    static std::atomic<int> g_castSpellCurSpell{-1};
    static std::atomic<DWORD> g_lastSuccessfulCastTick{0};
    static std::atomic<DWORD> g_lastCastAttemptTick{0};
    static std::atomic<uint32_t> g_castSpellTokenSeed{0};
    static std::atomic<uint32_t> g_lastCastToken{0};
    static volatile LONG g_castSpellCalleeDumps = 0;

    struct CastSpellFrameBuffer {
        USHORT count = 0;
        void* frames[16]{};
    };

    static thread_local CastSpellFrameBuffer g_castSpellLastRAs;
    static thread_local uint32_t g_tlsCurrentCastToken = 0;

    static std::mutex g_castSpellCalleeMutex;
    static std::unordered_set<void*> g_castSpellSeenCallees;
    static std::mutex g_castSpellPathMutex;
    static std::unordered_map<uint32_t, unsigned> g_castSpellPathIds;
    static std::unordered_map<uint32_t, unsigned> g_castSpellPathCounts;
    static unsigned g_castSpellNextPathId = 1;

    struct CastPacketWatch {
        uint32_t token = 0;
        int spellId = 0;
        DWORD startTick = 0;
        unsigned baselineCounter = 0;
        bool awaiting = false;
    };

    static constexpr size_t kMaxCastPacketWatches = 16;
    static CastPacketWatch g_castPacketWatches[kMaxCastPacketWatches]{};
    static std::mutex g_castPacketMutex;
    static bool g_castPacketTrackingEnabled = true;
    static DWORD g_castPacketTimeoutMs = 4000;

   struct GateCallProbe {
       uint8_t* callSite = nullptr;
       void* target = nullptr;
       void* trampoline = nullptr;
       uint8_t* stub = nullptr;
       uint32_t id = 0;
       std::atomic<uint32_t> hits{0};
       std::atomic<uint32_t> zeroHits{0};
       uint16_t retImm = 0;
       std::vector<uint8_t*> callSites;
       const char* name = nullptr;
   };

    static std::mutex g_gateProbeMutex;
    static std::unordered_map<void*, std::unique_ptr<GateCallProbe>> g_gateProbes;
    static std::unordered_map<void*, GateCallProbe*> g_gateStubProbes;
    static std::atomic<uint32_t> g_gateProbeSeed{1};

    static volatile LONG g_logBudgetTarget = 96;
    static volatile LONG g_logBudgetActionType = 96;
    static volatile LONG g_castSpellCalleeBudget = 64;
    static bool g_logBudgetTargetUnlimited = false;
    static bool g_logBudgetActionTypeUnlimited = false;
    static bool g_castSpellCalleeUnlimited = false;
    static bool g_enableCastGateProbes = true;
    static bool g_logCastSpellCallLists = false;
    static volatile LONG g_gateReturnLogBudget = 8;
    static volatile LONG g_gateReturnDumpBudget = 4;
    static bool g_gateReturnLogUnlimited = false;
    static bool g_gateReturnDumpUnlimited = false;

    struct GateInvokeTls {
        GateCallProbe* probe = nullptr;
        uintptr_t ecx = 0;
        uintptr_t edx = 0;
        uintptr_t args[4]{};
    };

    static thread_local GateInvokeTls g_gateInvokeTls;

    static std::atomic<DWORD> g_gateOwnerThread{0};
    static std::atomic<DWORD> g_gateArmExpiry{0};
    static std::atomic<int> g_gateArmDepth{0};
    static std::atomic<bool> g_gateArmedFlag{false};
    static std::atomic<bool> g_gatePanicAbort{false};
    static volatile LONG g_gatePreInvokeLogBudget = 16;
    static volatile LONG g_gatePreInvokeOkBudget = 8;
    static volatile LONG g_gateInvokeEntryBudget = 16;
    static volatile LONG g_gateStoreEntryBudget = 16;

    struct GateLogEvent {
        uint32_t id = 0;
        uint32_t tid = 0;
        uint32_t tick = 0;
    uintptr_t ret = 0;
    uintptr_t ecx = 0;
    uintptr_t arg0 = 0;
    const char* name = nullptr;
};

    static constexpr size_t kGateLogCapacity = 128;
    static GateLogEvent g_gateLogRing[kGateLogCapacity];
    static std::atomic<uint32_t> g_gateLogWrite{0};
    static uint32_t g_gateLogRead = 0;
    static std::atomic<bool> g_gateLogOverflow{false};
    static std::atomic<uint32_t> g_gateReturnLogCount{0};
    static std::atomic<uint32_t> g_gateReturnZeroCount{0};

    static constexpr uintptr_t kGateTargets[] = {
        0x00AA3350, // candidate #1
        0x00A9A000, // candidate #2
        0x00AA2D70, // candidate #3
        0x00AA3660  // candidate #4
    };
    static constexpr const char* kGateTargetNames[] = {
        "00AA3350",
        "00A9A000",
        "00AA2D70",
        "00AA3660"
    };
    static constexpr size_t kGateTargetCount = sizeof(kGateTargets) / sizeof(kGateTargets[0]);

    static uintptr_t g_gateSelectedTarget = kGateTargets[0];
    static const char* g_gateSelectedName = kGateTargetNames[0];
    static char g_gateOverrideName[32] = {};
}

static int __stdcall Hook_Register(void* ctx, void* func, const char* name);
static int __cdecl Lua_Walk(lua_State* L);
static int __cdecl Lua_BindWalk(lua_State* L);
static int __cdecl Lua_UserActionCastSpell_W(lua_State* L);
static int __cdecl Lua_UserActionCastSpellOnId_W(lua_State* L);
static int __cdecl Lua_UserActionUseSkill_W(lua_State* L);
static int __cdecl Lua_UserActionIsTargetModeCompat_W(lua_State* L);
static int __cdecl Lua_UserActionIsActionTypeTargetModeCompat_W(lua_State* L);
static int __cdecl Lua_RequestTargetInfo_W(lua_State* L);
static int __cdecl Lua_ClearCurrentTarget_W(lua_State* L);
static int __cdecl Lua_UserActionIsTargetModeCompat_W(lua_State* L);
static int __cdecl Lua_UserActionIsActionTypeTargetModeCompat_W(lua_State* L);
static int __cdecl Lua_RequestTargetInfo_W(lua_State* L);
static int __cdecl Lua_ClearCurrentTarget_W(lua_State* L);
// Prototypes for additional wrappers
static int __cdecl Lua_UserActionIsSkillAvalible_W(lua_State* L);
static int __cdecl Lua_HS_ShowTargetingCursor_W(lua_State* L);
static int __cdecl Lua_HS_HideTargetingCursor_W(lua_State* L);
static int __cdecl Lua_UserActionUseWeaponAbility_W(lua_State* L);
static int __cdecl Lua_UserActionUsePrimaryAbility_W(lua_State* L);

// Forward declarations for logging helpers
static void LogLuaArgs(lua_State* L, const char* func, int maxArgs = 3);
static void LogLuaReturns(lua_State* L, const char* func, int nret);
static void LogLuaErrorTop(lua_State* L, const char* context, int maxSlots = 6);
static void LogLuaClosureUpvalues(lua_State* L, int funcIndex, const char* context, int maxUpvalues = 4);
static void LogSavedOriginalUpvalues(lua_State* L, const char* savedName, const char* globalName, const char* context, volatile LONG* gate, int maxUpvalues = 4);
static void LogLuaTopTypes(lua_State* L, const char* context, int maxSlots = 6);
static int CallSavedOriginal(lua_State* L, const char* savedName);
static void MaybeUpdateOwnerContext(void* ctx);
static void* CurrentScriptContext();
static void* CanonicalOwnerContext();
static uint32_t NextCastToken();
static uint32_t CurrentCastToken();
static void UowTracePushSpell(int spell);
static void UowTraceCollectRAs();
static void* ResolveCalleeFromRA(void* ret);
static void DumpCastSpellCallees(const CastSpellFrameBuffer& frames, unsigned pathId, uint32_t token, bool packetSent);
static unsigned LogCastSpellPath(uint32_t token, const CastSpellFrameBuffer& frames, bool isOwnerPath);
static uint16_t DetectRetImm(void* target);
static void GateInvokeShared();
static void GateRecordEvent(GateCallProbe* probe, uintptr_t retValue);
static void GateFlushEvents(const char* reason);
static bool GateArmForCast();
static void GateDisarmForCast(const char* reason);
static void GateMaybeLogInvokeEntry(GateCallProbe* probe);

struct ValueProbe {
    bool pathValid = false;
    int type = LUA_TNONE;
    std::string summary;
};

struct CastSpellSnapshot {
    ValueProbe systemQueue;
    ValueProbe settingsQueue;
    ValueProbe settingsEnableQueue;
    ValueProbe cursorTargeting;
    ValueProbe actionQueueEnabled;
    ValueProbe actionQueueActive;
};

static ValueProbe ProbeValue(lua_State* L, const char* const* path, size_t length);
static CastSpellSnapshot CaptureCastSpellSnapshot(lua_State* L);
static void LogCastSpellSnapshot(const char* phase, uint32_t token, int spellId, const CastSpellSnapshot& snap);
static int InvokeClientLuaFn(LuaFn fn, const char* tag, lua_State* L);
static bool ProbeValueUnsafe(lua_State* L, const char* const* path, size_t length, ValueProbe& probe);
static void InstallGateProbeForCallSite(uint8_t* callSite);
static uint8_t* AllocateGateStub(GateCallProbe* probe);
static void GateInvokeShared();
static void __stdcall GateLogReturn(GateCallProbe* probe, uintptr_t retValue);
static void __stdcall GateStorePreInvoke(GateCallProbe* probe, uintptr_t ecx, uintptr_t edx, uintptr_t* argBase);
static void LogGateHelperSelected(GateCallProbe* probe, uintptr_t retValue);

// Configurable verbosity for Lua arg/ret logging
static bool g_traceLuaVerbose = false;

static std::vector<const void*> g_loggedCallScanTargets;
static void LogCallersForTarget(const char* name, const void* target);
static void NoteCapturedActionTarget(const char* name, const void* target);
static bool IsInMainModule(const void* address);

// (no-op helper removed)

// No special table manipulation needed; the client RegisterLuaFunction
// can accept dotted names and route them appropriately.

static void LogWalkBindingState(lua_State* L, const char* stage)
{
    if (!L)
        return;

    int walkType = LUA_TNONE;
    const void* walkPtr = nullptr;
    int moveType = LUA_TNONE;
    const void* movePtr = nullptr;
    int bindType = LUA_TNONE;
    const void* bindPtr = nullptr;

    __try {
        int top = lua_gettop(L);
        lua_getglobal(L, "walk");
        walkType = lua_type(L, -1);
        if (walkType == LUA_TFUNCTION) {
            walkPtr = lua_topointer(L, -1);
        }
        lua_pop(L, 1);

        // Try direct global lookup by dotted name if the client treats it specially
        lua_getglobal(L, "UOFlow.Walk.move");
        moveType = lua_type(L, -1);
        if (moveType == LUA_TFUNCTION) {
            movePtr = lua_topointer(L, -1);
        }
        lua_pop(L, 1);

        lua_getglobal(L, "bindWalk");
        bindType = lua_type(L, -1);
        if (bindType == LUA_TFUNCTION) {
            bindPtr = lua_topointer(L, -1);
        }
        lua_pop(L, 1);
        lua_settop(L, top);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("LogWalkBindingState: exception while inspecting globals");
    }

    char buf[256];
    sprintf_s(buf, sizeof(buf), "%s: walk=%s%p nsMove=%s%p bindWalk=%s%p",
        stage ? stage : "WalkBindingState",
        (walkType == LUA_TFUNCTION) ? "fn@" : lua_typename(L, walkType),
        walkPtr,
        (moveType == LUA_TFUNCTION) ? "fn@" : lua_typename(L, moveType),
        movePtr,
        (bindType == LUA_TFUNCTION) ? "fn@" : lua_typename(L, bindType),
        bindPtr);
    WriteRawLog(buf);
}

static bool RegisterFunctionSafe(lua_State* L, lua_CFunction fn, const char* name)
{
    __try {
        lua_pushcfunction(L, fn);
        lua_setglobal(L, name);
        char buf[160];
        sprintf_s(buf, sizeof(buf), "RegisterFunctionSafe: set global '%s' to %p", name ? name : "<null>", reinterpret_cast<void*>(fn));
        WriteRawLog(buf);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        char buf[128];
        sprintf_s(buf, sizeof(buf), "Exception registering Lua function '%s'", name ? name : "<null>");
        WriteRawLog(buf);
        return false;
    }
}

static void MaybeUpdateOwnerContext(void* ctx)
{
    if (!ctx)
        return;

    void* expected = nullptr;
    if (g_ownerScriptContext.compare_exchange_strong(expected, ctx, std::memory_order_acq_rel)) {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "Owner script context established: %p (tid=%u)", ctx, GetCurrentThreadId());
        WriteRawLog(buf);
    }

    const std::uint32_t currentTid = GetCurrentThreadId();
    std::uint32_t recorded = g_ownerThreadId.load(std::memory_order_acquire);
    if (recorded == 0 || recorded != currentTid) {
        g_ownerThreadId.store(currentTid, std::memory_order_release);
        char buf[160];
        sprintf_s(buf, sizeof(buf), "OwnerPump owner thread set: %u (ctx=%p)", currentTid, ctx);
        WriteRawLog(buf);
    }
}

static void* CurrentScriptContext()
{
    if (g_clientContext)
        return g_clientContext;
    if (const auto* info = Engine::Info()) {
        if (info->scriptContext)
            return info->scriptContext;
    }
    return nullptr;
}

static void* CanonicalOwnerContext()
{
    void* owner = g_ownerScriptContext.load(std::memory_order_acquire);
    if (!owner) {
        if (const auto* info = Engine::Info()) {
            owner = info->scriptContext;
        }
    }
    return owner;
}

static uint32_t NextCastToken()
{
    return g_castSpellTokenSeed.fetch_add(1, std::memory_order_relaxed) + 1u;
}

static uint32_t CurrentCastToken()
{
    uint32_t tok = g_tlsCurrentCastToken;
    if (tok == 0)
        tok = g_lastCastToken.load(std::memory_order_acquire);
    return tok;
}

static void UowTracePushSpell(int spell)
{
    g_castSpellCurSpell.store(spell, std::memory_order_relaxed);
}

static void UowTraceCollectRAs()
{
    g_castSpellLastRAs.count = 0;
    void* frames[16]{};
    USHORT captured = RtlCaptureStackBackTrace(1, 16, frames, nullptr);
    USHORT out = 0;
    for (USHORT i = 0; i < captured && out < 16; ++i) {
        if (!frames[i])
            continue;
        g_castSpellLastRAs.frames[out++] = frames[i];
    }
    g_castSpellLastRAs.count = out;
}

static void* ResolveCalleeFromRA(void* ret)
{
    if (!ret)
        return nullptr;
    __try {
        auto* ret8 = reinterpret_cast<uint8_t*>(ret);
        auto* callsite = ret8 - 5;
        if (*callsite != 0xE8)
            return nullptr;
        int32_t rel = *reinterpret_cast<int32_t*>(callsite + 1);
        return ret8 + rel;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }

    return nullptr;
}

static void* NormalizeGateCallee(void* callee)
{
    if (!callee)
        return nullptr;
    std::lock_guard<std::mutex> lock(g_gateProbeMutex);
    auto it = g_gateStubProbes.find(callee);
    if (it != g_gateStubProbes.end() && it->second)
        return it->second->target;
    return callee;
}

static std::optional<uintptr_t> ParseConfigAddress(const std::string& text)
{
    const char* ptr = text.c_str();
    while (*ptr && std::isspace(static_cast<unsigned char>(*ptr)))
        ++ptr;
    if (!*ptr)
        return std::nullopt;
    if (ptr[0] == '0' && (ptr[1] == 'x' || ptr[1] == 'X'))
        ptr += 2;
    char* end = nullptr;
    unsigned long long value = std::strtoull(ptr, &end, 16);
    if (ptr == end)
        return std::nullopt;
    return static_cast<uintptr_t>(value);
}

static void DumpCastSpellCallees(const CastSpellFrameBuffer& frames, unsigned pathId, uint32_t token, bool packetSent)
{
    if (frames.count == 0)
        return;

    std::unordered_set<void*> unique;
    for (USHORT i = 0; i < frames.count; ++i) {
        void* ra = frames.frames[i];
        if (!ra)
            continue;
        auto* callSite = reinterpret_cast<uint8_t*>(ra) - 5;
        if (g_enableCastGateProbes)
            InstallGateProbeForCallSite(callSite);
        void* callee = ResolveCalleeFromRA(ra);
        callee = NormalizeGateCallee(callee);
        if (!callee)
            continue;
        unique.insert(callee);
    }
    if (unique.empty())
        return;

    std::lock_guard<std::mutex> lock(g_castSpellCalleeMutex);
    for (void* fn : unique) {
        bool firstSeen = g_castSpellSeenCallees.insert(fn).second;
        if (!firstSeen && !g_logCastSpellCallLists)
            continue;
        char buf[224];
        sprintf_s(buf, sizeof(buf),
            "[CastSpell] candidate callee: %p path=%u tok=%u packet=%s%s",
            fn,
            pathId,
            token,
            packetSent ? "yes" : "no",
            firstSeen ? " (new)" : "");
        WriteRawLog(buf);
    }
}

static uint32_t HashCallPath(const CastSpellFrameBuffer& frames)
{
    const uint32_t fnvOffset = 2166136261u;
    const uint32_t fnvPrime = 16777619u;
    uint32_t hash = fnvOffset;
    for (USHORT i = 0; i < frames.count; ++i) {
        void* frame = frames.frames[i];
        uintptr_t value = reinterpret_cast<uintptr_t>(frame);
        for (int i = 0; i < static_cast<int>(sizeof(value)); ++i) {
            hash ^= static_cast<uint32_t>((value >> (i * 8)) & 0xFFu);
            hash *= fnvPrime;
        }
    }
    if (hash == 0)
        hash = fnvPrime;
    return hash;
}

static unsigned LogCastSpellPath(uint32_t token, const CastSpellFrameBuffer& frames, bool isOwnerPath)
{
    if (frames.count == 0)
        return 0;

    uint32_t hash = HashCallPath(frames);
    unsigned pathId = 0;
    unsigned count = 0;
    {
        std::lock_guard<std::mutex> lock(g_castSpellPathMutex);
        auto it = g_castSpellPathIds.find(hash);
        if (it == g_castSpellPathIds.end()) {
            pathId = g_castSpellNextPathId++;
            g_castSpellPathIds.emplace(hash, pathId);
            g_castSpellPathCounts.emplace(hash, 0);
        } else {
            pathId = it->second;
        }
        count = ++g_castSpellPathCounts[hash];
    }

    if (count <= 8 || g_logCastSpellCallLists) {
        char buf[192];
        sprintf_s(buf, sizeof(buf), "[Lua] CastSpell path tok=%u pathId=%u hash=%08X owner=%s depth=%u count=%u",
                  token, pathId, hash, isOwnerPath ? "yes" : "no", frames.count, count);
        WriteRawLog(buf);
    }
    return pathId;
}

static uint16_t DetectRetImm(void* target)
{
    if (!target)
        return 0;
    uint8_t* code = static_cast<uint8_t*>(target);
    __try {
        for (size_t i = 0; i < 256; ++i) {
            uint8_t op = code[i];
            if (op == 0xC3)
                return 0;
            if (op == 0xC2) {
                if (i + 2 >= 256)
                    break;
                return *reinterpret_cast<uint16_t*>(code + i + 1);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return 0;
}

static bool GateArmForCast()
{
    if (!g_enableCastGateProbes)
        return false;

    DWORD tid = GetCurrentThreadId();
    DWORD expected = 0;
    if (!g_gateOwnerThread.compare_exchange_strong(expected, tid, std::memory_order_acq_rel)) {
        if (expected != tid)
            return false;
    }

    int depth = g_gateArmDepth.fetch_add(1, std::memory_order_acq_rel);
    if (depth == 0) {
        g_gateLogWrite.store(0, std::memory_order_release);
        g_gateLogRead = 0;
        g_gateLogOverflow.store(false, std::memory_order_release);
        g_gatePanicAbort.store(false, std::memory_order_release);
    }

    g_gateArmExpiry.store(GetTickCount() + 500u, std::memory_order_release);
    g_gateArmedFlag.store(true, std::memory_order_release);

    char buf[160];
    sprintf_s(buf, sizeof(buf),
        "[Gate3350] armed tid=%u depth=%d tok=%u target=%s",
        tid,
        depth + 1,
        g_lastCastToken.load(std::memory_order_acquire),
        g_gateSelectedName ? g_gateSelectedName : "unknown");
    WriteRawLog(buf);
    if (depth == 0) {
        InterlockedExchange(&g_gatePreInvokeLogBudget, 16);
        InterlockedExchange(&g_gatePreInvokeOkBudget, 8);
        InterlockedExchange(&g_gateInvokeEntryBudget, 16);
        InterlockedExchange(&g_gateStoreEntryBudget, 16);
        char detail[160];
        sprintf_s(detail, sizeof(detail),
            "[Gate3350] owner set tid=%u", tid);
        WriteRawLog(detail);
    }
    return true;
}

static void GateFlushEvents(const char* reason)
{
    if (!reason)
        reason = "unspecified";

    uint32_t write = g_gateLogWrite.load(std::memory_order_acquire);
    uint32_t read = g_gateLogRead;
    bool overflow = g_gateLogOverflow.load(std::memory_order_acquire);
    bool panic = g_gatePanicAbort.load(std::memory_order_acquire);
    uint32_t available = (write >= read) ? (write - read) : 0;

    uint32_t start = write;
    if (available > kGateLogCapacity)
        start = write - static_cast<uint32_t>(kGateLogCapacity);
    else
        start = read;

    if (start < read)
        start = read;

    char header[192];
    sprintf_s(header, sizeof(header),
        "[Gate3350] flush reason=%s count=%u overflow=%s panic=%s target=%s",
        reason,
        static_cast<unsigned>(write - start),
        overflow ? "yes" : "no",
        panic ? "yes" : "no",
        g_gateSelectedName ? g_gateSelectedName : "unknown");
    WriteRawLog(header);

    for (uint32_t idx = start; idx < write; ++idx) {
        const GateLogEvent& evt = g_gateLogRing[idx & (kGateLogCapacity - 1)];
        char line[256];
        sprintf_s(line, sizeof(line),
            "[Gate3350] idx=%u id=%u tid=%u tick=%u ret=0x%08IX ecx=%p arg0=%p target=%s",
            idx,
            evt.id,
            evt.tid,
            evt.tick,
            static_cast<unsigned int>(evt.ret),
            reinterpret_cast<void*>(evt.ecx),
            reinterpret_cast<void*>(evt.arg0),
            evt.name ? evt.name : (g_gateSelectedName ? g_gateSelectedName : "unknown"));
        WriteRawLog(line);
    }

    g_gateLogRead = write;
    g_gateLogWrite.store(write, std::memory_order_release);
    g_gateLogOverflow.store(false, std::memory_order_release);
    g_gatePanicAbort.store(false, std::memory_order_release);
}

static void GateDisarmForCast(const char* reason)
{
    if (!g_enableCastGateProbes)
        return;

    DWORD tid = GetCurrentThreadId();
    if (g_gateOwnerThread.load(std::memory_order_acquire) != tid)
        return;

    int depth = g_gateArmDepth.fetch_sub(1, std::memory_order_acq_rel) - 1;
    bool last = (depth <= 0);
    if (last) {
        GateFlushEvents(reason ? reason : "disarm");
        g_gateArmedFlag.store(false, std::memory_order_release);
        g_gateOwnerThread.store(0, std::memory_order_release);
        char msg[160];
        sprintf_s(msg, sizeof(msg),
            "[Gate3350] disarmed tid=%u target=%s",
            tid,
            g_gateSelectedName ? g_gateSelectedName : "unknown");
        WriteRawLog(msg);
    }
}

static void GateRecordEvent(GateCallProbe* probe, uintptr_t retValue)
{
    if (!probe)
        return;
    if (!g_gateArmedFlag.load(std::memory_order_acquire)) {
        DWORD tid = GetCurrentThreadId();
        if (InterlockedCompareExchange(&g_gatePreInvokeLogBudget, 0, 0) > 0) {
            LONG left = InterlockedDecrement(&g_gatePreInvokeLogBudget);
            if (left >= 0) {
                char buf[160];
                sprintf_s(buf, sizeof(buf),
                    "[Gate3350] pre-invoke unarmed probe=%p tid=%u",
                    probe, tid);
                WriteRawLog(buf);
            }
        }
        return;
    }

    DWORD owner = g_gateOwnerThread.load(std::memory_order_acquire);
    if (owner == 0 || owner != GetCurrentThreadId())
        return;

    uint32_t slot = g_gateLogWrite.fetch_add(1, std::memory_order_acq_rel);
    if ((slot - g_gateLogRead) >= kGateLogCapacity)
        g_gateLogOverflow.store(true, std::memory_order_release);

    GateLogEvent evt{};
    evt.id = probe->id;
    evt.tid = owner;
    evt.tick = GetTickCount();
    evt.ret = retValue;
    evt.ecx = g_gateInvokeTls.ecx;
    evt.arg0 = g_gateInvokeTls.args[0];
    evt.name = probe->name;
    g_gateLogRing[slot & (kGateLogCapacity - 1)] = evt;
}

static void GateMaybeLogInvokeEntry(GateCallProbe* probe)
{
    if (!probe)
        return;
    LONG current = InterlockedCompareExchange(&g_gateInvokeEntryBudget, 0, 0);
    if (current <= 0)
        return;
    LONG left = InterlockedDecrement(&g_gateInvokeEntryBudget);
    if (left < 0)
        return;
    DWORD tid = GetCurrentThreadId();
    char buf[192];
    sprintf_s(buf, sizeof(buf),
        "[Gate3350] invoke entry probe=%p tid=%u target=%s",
        probe,
        tid,
        probe->name ? probe->name : (g_gateSelectedName ? g_gateSelectedName : "unknown"));
    WriteRawLog(buf);
}

static uint8_t* AllocateGateStub(GateCallProbe* probe)
{
    if (!probe)
        return nullptr;
    uint8_t* stub = static_cast<uint8_t*>(VirtualAlloc(nullptr, 32, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!stub)
        return nullptr;
    uintptr_t probePtr = reinterpret_cast<uintptr_t>(probe);
    stub[0] = 0x68; // push imm32 (probe pointer)
    *reinterpret_cast<uint32_t*>(stub + 1) = static_cast<uint32_t>(probePtr);
    stub[5] = 0xE8; // call rel32 GateInvokeShared
    intptr_t rel = reinterpret_cast<intptr_t>(&GateInvokeShared) - reinterpret_cast<intptr_t>(stub + 9);
    *reinterpret_cast<int32_t*>(stub + 6) = static_cast<int32_t>(rel);
    size_t flush = 11;
    if (probe->retImm == 0) {
        stub[10] = 0xC3; // ret
        flush = 11;
    } else {
        stub[10] = 0xC2; // ret imm16
        *reinterpret_cast<uint16_t*>(stub + 11) = probe->retImm;
        flush = 13;
    }
    FlushInstructionCache(GetCurrentProcess(), stub, flush);
    return stub;
}

static void __stdcall GateStorePreInvoke(GateCallProbe* probe, uintptr_t ecx, uintptr_t edx, uintptr_t* argBase)
{
    g_gateInvokeTls = GateInvokeTls{};

    if (InterlockedCompareExchange(&g_gateStoreEntryBudget, 0, 0) > 0) {
        LONG left = InterlockedDecrement(&g_gateStoreEntryBudget);
        if (left >= 0) {
            DWORD tid = GetCurrentThreadId();
            DWORD owner = g_gateOwnerThread.load(std::memory_order_acquire);
            char buf[192];
            sprintf_s(buf, sizeof(buf),
                "[Gate3350] pre-invoke entry probe=%p tid=%u owner=%u armed=%d",
                probe,
                tid,
                owner,
                g_gateArmedFlag.load(std::memory_order_acquire) ? 1 : 0);
            WriteRawLog(buf);
        }
    }

    if (!probe || !g_enableCastGateProbes) {
        if (InterlockedCompareExchange(&g_gatePreInvokeLogBudget, 0, 0) > 0) {
            LONG left = InterlockedDecrement(&g_gatePreInvokeLogBudget);
            if (left >= 0) {
                char buf[160];
                sprintf_s(buf, sizeof(buf),
                    "[Gate3350] pre-invoke skipped (probe=%p enabled=%d)",
                    probe, g_enableCastGateProbes ? 1 : 0);
                WriteRawLog(buf);
            }
        }
        return;
    }

    if (!g_gateArmedFlag.load(std::memory_order_acquire))
        return;

    DWORD owner = g_gateOwnerThread.load(std::memory_order_acquire);
    DWORD tid = GetCurrentThreadId();
    if (owner == 0 || owner != tid) {
        if (InterlockedCompareExchange(&g_gatePreInvokeLogBudget, 0, 0) > 0) {
            LONG left = InterlockedDecrement(&g_gatePreInvokeLogBudget);
            if (left >= 0) {
                char buf[160];
                sprintf_s(buf, sizeof(buf),
                    "[Gate3350] pre-invoke owner mismatch probe=%p tid=%u owner=%u",
                    probe, tid, owner);
                WriteRawLog(buf);
            }
        }
        return;
    }

    DWORD now = GetTickCount();
    DWORD expiry = g_gateArmExpiry.load(std::memory_order_acquire);
    if (now > expiry) {
        g_gatePanicAbort.store(true, std::memory_order_release);
        g_gateArmedFlag.store(false, std::memory_order_release);
        char panicMsg[160];
        sprintf_s(panicMsg, sizeof(panicMsg),
            "[Gate3350] panic: TTL expired while probe armed target=%s",
            probe->name ? probe->name : (g_gateSelectedName ? g_gateSelectedName : "unknown"));
        WriteRawLog(panicMsg);
        if (InterlockedCompareExchange(&g_gatePreInvokeLogBudget, 0, 0) > 0) {
            LONG left = InterlockedDecrement(&g_gatePreInvokeLogBudget);
            if (left >= 0) {
                char buf[160];
                sprintf_s(buf, sizeof(buf),
                    "[Gate3350] pre-invoke aborted due to expiry probe=%p now=%u expiry=%u",
                    probe, now, expiry);
                WriteRawLog(buf);
            }
        }
        return;
    }
    g_gateArmExpiry.store(now + 500u, std::memory_order_release);

    g_gateInvokeTls.probe = probe;
    g_gateInvokeTls.ecx = ecx;
    g_gateInvokeTls.edx = edx;
    for (size_t i = 0; i < 4; ++i)
        g_gateInvokeTls.args[i] = 0;

    if (InterlockedCompareExchange(&g_gatePreInvokeOkBudget, 0, 0) > 0) {
        LONG left = InterlockedDecrement(&g_gatePreInvokeOkBudget);
        if (left >= 0) {
            char buf[192];
            sprintf_s(buf, sizeof(buf),
                "[Gate3350] pre-invoke ok probe=%p ecx=%p edx=%p tid=%u",
                probe,
                reinterpret_cast<void*>(ecx),
                reinterpret_cast<void*>(edx),
                tid);
            WriteRawLog(buf);
        }
    }

    if (!argBase)
        return;

    __try {
        for (size_t i = 0; i < 4; ++i)
            g_gateInvokeTls.args[i] = argBase[i];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        for (size_t i = 0; i < 4; ++i)
            g_gateInvokeTls.args[i] = 0;
    }
}

static bool GateConsumeBudget(volatile LONG& budget, bool unlimited)
{
    if (unlimited)
        return true;
    if (InterlockedCompareExchange(&budget, 0, 0) <= 0)
        return false;
    LONG left = InterlockedDecrement(&budget);
    return (left >= 0);
}

static void DumpGateMemorySafe(const char* label, uintptr_t address, size_t length)
{
    if (!address || !length)
        return;
    __try {
        Core::Utils::DumpMemory(label, reinterpret_cast<void*>(address), length);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "[Gate3350] failed to dump %s at %p", label, reinterpret_cast<void*>(address));
        WriteRawLog(buf);
    }
}

static void LogGateHelperSelected(GateCallProbe* probe, uintptr_t retValue)
{
    if (!probe)
        return;
    if (g_gateInvokeTls.probe != probe)
        return;

    if (!GateConsumeBudget(g_gateReturnLogBudget, g_gateReturnLogUnlimited))
        return;

    GateInvokeTls snap = g_gateInvokeTls;
    uint32_t seq = g_gateReturnLogCount.fetch_add(1, std::memory_order_relaxed) + 1;
    bool isZero = (retValue == 0);
    uint32_t zeroSeq = isZero ? (g_gateReturnZeroCount.fetch_add(1, std::memory_order_relaxed) + 1)
                              : g_gateReturnZeroCount.load(std::memory_order_relaxed);

    char buf[320];
    sprintf_s(buf, sizeof(buf),
        "[Gate3350] ret=0x%08IX zero=%s seq=%u zeroSeq=%u ecx=%p edx=%p args={%p,%p,%p,%p} tok=%u spell=%d target=%s",
        static_cast<unsigned int>(retValue),
        isZero ? "yes" : "no",
        seq,
        isZero ? zeroSeq : 0u,
        reinterpret_cast<void*>(snap.ecx),
        reinterpret_cast<void*>(snap.edx),
        reinterpret_cast<void*>(snap.args[0]),
        reinterpret_cast<void*>(snap.args[1]),
        reinterpret_cast<void*>(snap.args[2]),
        reinterpret_cast<void*>(snap.args[3]),
        g_lastCastToken.load(std::memory_order_acquire),
        g_castSpellCurSpell.load(std::memory_order_relaxed),
        probe->name ? probe->name : "unknown");
    WriteRawLog(buf);

    if (isZero && GateConsumeBudget(g_gateReturnDumpBudget, g_gateReturnDumpUnlimited)) {
        DumpGateMemorySafe("Gate3350.ecx", snap.ecx, 64);
        DumpGateMemorySafe("Gate3350.arg0", snap.args[0], 64);
    }
}

static void __stdcall GateLogReturn(GateCallProbe* probe, uintptr_t retValue)
{
    if (!probe) {
        g_gateInvokeTls = GateInvokeTls{};
        return;
    }

    uint32_t total = probe->hits.fetch_add(1, std::memory_order_relaxed) + 1;
    uint32_t zeroTotal = (retValue == 0)
        ? (probe->zeroHits.fetch_add(1, std::memory_order_relaxed) + 1)
        : probe->zeroHits.load(std::memory_order_relaxed);

    GateRecordEvent(probe, retValue);

    if (reinterpret_cast<uintptr_t>(probe->target) == g_gateSelectedTarget)
        LogGateHelperSelected(probe, retValue);
    g_gateInvokeTls = GateInvokeTls{};
}

static void __declspec(naked) GateInvokeShared()
{
    __asm {
        push ebp
        mov ebp, esp
        sub esp, 12
        push ebx
        push esi
        push edi

        mov esi, [ebp + 8]                  // probe pointer
        push esi
        call GateMaybeLogInvokeEntry
        add esp, 4
        mov esi, [ebp + 8]
        mov [ebp - 4], ecx                  // save original ECX
        mov [ebp - 8], edx                  // save original EDX

        lea ebx, [ebp + 12]                 // pointer to first argument on stack
        mov eax, [ebp - 4]
        mov edx, [ebp - 8]
        push ebx                            // arg4: argument base pointer
        push edx                            // arg3: original EDX
        push eax                            // arg2: original ECX
        push esi                            // arg1: probe pointer
        call GateStorePreInvoke

        mov ecx, [ebp - 4]
        mov edx, [ebp - 8]
        mov eax, [esi + 8]                  // trampoline pointer
        call eax

        mov [ebp - 12], eax                 // stash return value
        push dword ptr [ebp - 12]
        push esi
        call GateLogReturn

        mov eax, [ebp - 12]

        pop edi
        pop esi
        pop ebx
        mov esp, ebp
        pop ebp
        ret 4
    }
}

static void InstallGateProbeForCallSite(uint8_t* callSite)
{
    if (!g_enableCastGateProbes)
        return;
    if (!callSite)
        return;
    if (callSite[0] != 0xE8)
        return;
    if (!IsInMainModule(callSite))
        return;

    int32_t rel = *reinterpret_cast<int32_t*>(callSite + 1);
    void* target = callSite + 5 + rel;
    if (!target)
        return;
    if (reinterpret_cast<uintptr_t>(target) != g_gateSelectedTarget)
        return;

    std::lock_guard<std::mutex> lock(g_gateProbeMutex);
    auto it = g_gateProbes.find(target);
    GateCallProbe* probe = nullptr;
    if (it == g_gateProbes.end()) {
        auto fresh = std::make_unique<GateCallProbe>();
        probe = fresh.get();
        probe->target = target;
        probe->callSite = callSite;
        probe->id = g_gateProbeSeed.fetch_add(1, std::memory_order_relaxed);
        probe->retImm = DetectRetImm(target);
        probe->name = g_gateSelectedName;
        probe->stub = AllocateGateStub(probe);
        if (!probe->stub) {
            WriteRawLog("[CastSpellGate] failed to allocate stub for gate detour");
            return;
        }

        MH_STATUS init = MH_Initialize();
        (void)init; // allow already-initialized
        MH_STATUS createRc = MH_CreateHook(target, probe->stub, reinterpret_cast<void**>(&probe->trampoline));
        if (createRc != MH_OK) {
            char buf[256];
            sprintf_s(buf, sizeof(buf),
                "[CastSpellGate] MH_CreateHook failed target=%p rc=%d", target, static_cast<int>(createRc));
            WriteRawLog(buf);
            VirtualFree(probe->stub, 0, MEM_RELEASE);
            return;
        }
        MH_STATUS enableRc = MH_EnableHook(target);
        if (enableRc != MH_OK) {
            char buf[256];
            sprintf_s(buf, sizeof(buf),
                "[CastSpellGate] MH_EnableHook failed target=%p rc=%d", target, static_cast<int>(enableRc));
            WriteRawLog(buf);
            MH_RemoveHook(target);
            VirtualFree(probe->stub, 0, MEM_RELEASE);
            return;
        }

        char buf[256];
        sprintf_s(buf, sizeof(buf),
            "[CastSpellGate] probe installed id=%u target=%p (%s) stub@%p tramp=%p retImm=%u",
            probe->id, probe->target, probe->name ? probe->name : "unknown", probe->stub, probe->trampoline, static_cast<unsigned>(probe->retImm));
        WriteRawLog(buf);
        probe->callSites.push_back(callSite);
        g_gateStubProbes[probe->stub] = probe;
        g_gateProbes.emplace(target, std::move(fresh));
    } else {
        probe = it->second.get();
        probe->name = g_gateSelectedName;
        probe->callSites.push_back(callSite);
        if (probe->stub)
            g_gateStubProbes[probe->stub] = probe;
        char buf[192];
        sprintf_s(buf, sizeof(buf),
            "[CastSpellGate] callsite %p linked to existing probe id=%u target=%p (%s) retImm=%u",
            callSite, probe->id, probe->target, probe->name ? probe->name : "unknown", static_cast<unsigned>(probe->retImm));
        WriteRawLog(buf);
    }
}

static int InvokeClientLuaFn(LuaFn fn, const char* tag, lua_State* L)
{
    if (!fn)
        return 0;
    int out = 0;
    __try {
        out = fn(L);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "[Lua] %s original threw", tag ? tag : "fn");
        WriteRawLog(buf);
        out = 0;
    }
    return out;
}

static bool ProbeValueUnsafe(lua_State* L, const char* const* path, size_t length, ValueProbe& probe)
{
    bool ok = true;
    __try {
        for (size_t i = 0; i < length; ++i) {
            const char* key = path[i];
            if (i == 0) {
                lua_getglobal(L, key);
            } else {
                if (lua_type(L, -1) != LUA_TTABLE) {
                    ok = false;
                    break;
                }
                lua_getfield(L, -1, key);
                lua_replace(L, -2);
            }
        }
        if (!ok) {
            probe.summary = "not-table";
            return true;
        }
        int t = lua_type(L, -1);
        probe.type = t;
        switch (t) {
        case LUA_TBOOLEAN:
            probe.pathValid = true;
            probe.summary = lua_toboolean(L, -1) ? "bool:true" : "bool:false";
            break;
        case LUA_TNUMBER:
        {
            probe.pathValid = true;
            char tmp[64];
            sprintf_s(tmp, sizeof(tmp), "number:%.3f", static_cast<double>(lua_tonumber(L, -1)));
            probe.summary = tmp;
            break;
        }
        case LUA_TSTRING:
        {
            probe.pathValid = true;
            size_t len = 0;
            const char* s = lua_tolstring(L, -1, &len);
            if (!s) {
                probe.summary = "string:<null>";
            } else {
                if (len > 48)
                    len = 48;
                probe.summary.assign("string:");
                probe.summary.append(s, len);
            }
            break;
        }
        case LUA_TTABLE:
        case LUA_TFUNCTION:
        case LUA_TLIGHTUSERDATA:
        case LUA_TUSERDATA:
        {
            probe.pathValid = true;
            char tmp[64];
            sprintf_s(tmp, sizeof(tmp), "ptr:%p", lua_topointer(L, -1));
            probe.summary = tmp;
            break;
        }
        case LUA_TNIL:
            probe.summary = "nil";
            break;
        default:
            probe.summary = lua_typename(L, t);
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

static ValueProbe ProbeValue(lua_State* L, const char* const* path, size_t length)
{
    ValueProbe probe;
    if (!L || !path || length == 0) {
        probe.summary = "invalid";
        return probe;
    }

    int top = lua_gettop(L);
    bool ok = ProbeValueUnsafe(L, path, length, probe);
    lua_settop(L, top);
    if (!ok) {
        probe.summary = "fault";
    } else if (probe.summary.empty()) {
        probe.summary = "missing";
    }
    return probe;
}

static CastSpellSnapshot CaptureCastSpellSnapshot(lua_State* L)
{
    CastSpellSnapshot snap;
    {
        const char* path[] = {"SystemData", "SpellQueueEnabled"};
        snap.systemQueue = ProbeValue(L, path, ARRAYSIZE(path));
    }
    {
        const char* path[] = {"SystemData", "Settings", "SpellQueueEnabled"};
        snap.settingsQueue = ProbeValue(L, path, ARRAYSIZE(path));
    }
    {
        const char* path[] = {"SystemData", "Settings", "EnableSpellQueue"};
        snap.settingsEnableQueue = ProbeValue(L, path, ARRAYSIZE(path));
    }
    {
        const char* path[] = {"Cursor", "Targeting"};
        snap.cursorTargeting = ProbeValue(L, path, ARRAYSIZE(path));
    }
    {
        const char* path[] = {"ActionQueueWindow", "QueueEnabled"};
        snap.actionQueueEnabled = ProbeValue(L, path, ARRAYSIZE(path));
    }
    {
        const char* path[] = {"ActionQueueWindow", "QueueActive"};
        snap.actionQueueActive = ProbeValue(L, path, ARRAYSIZE(path));
    }
    return snap;
}

static void LogCastSpellSnapshot(const char* phase, uint32_t token, int spellId, const CastSpellSnapshot& snap)
{
    char buf[512];
    sprintf_s(buf, sizeof(buf),
        "[Lua] CastSpell snapshot %s tok=%u spell=%d sysQueue=%s settingsQueue=%s settingsEnable=%s cursor=%s queueEnabled=%s queueActive=%s",
        phase ? phase : "?", token, spellId,
        snap.systemQueue.summary.c_str(),
        snap.settingsQueue.summary.c_str(),
        snap.settingsEnableQueue.summary.c_str(),
        snap.cursorTargeting.summary.c_str(),
        snap.actionQueueEnabled.summary.c_str(),
        snap.actionQueueActive.summary.c_str());
    WriteRawLog(buf);
}

static void LogLuaTopTypes(lua_State* L, const char* context, int maxSlots)
{
    if (!L || maxSlots <= 0)
        return;
    int top = lua_gettop(L);
    char buf[512];
    int written = sprintf_s(buf, sizeof(buf), "[Lua] %s stack top:", context ? context : "stack");
    if (top == 0) {
        sprintf_s(buf + written, sizeof(buf) - written, " <empty>");
        WriteRawLog(buf);
        return;
    }
    int limit = std::min(top, maxSlots);
    for (int i = 0; i < limit; ++i) {
        int idx = top - i;
        int type = lua_type(L, idx);
        const char* tn = lua_typename(L, type);
        if (written < static_cast<int>(sizeof(buf) - 16)) {
            written += sprintf_s(buf + written, sizeof(buf) - written, " #%d=%s", idx, tn ? tn : "?");
        }
    }
    WriteRawLog(buf);
}
// Save _G[name] as _G[name__orig] and replace it with our wrapper using only the Lua API.
static bool SaveAndReplace(lua_State* L, const char* name, lua_CFunction wrapper)
{
    if (!L || !name || !wrapper) return false;
    int top = lua_gettop(L);
    lua_getglobal(L, name);
    if (lua_type(L, -1) != LUA_TFUNCTION) {
        lua_settop(L, top);
        return false;
    }
    // Save original as name__orig (lua_setfield pops the value)
    std::string saved = std::string(name) + "__orig";
    lua_setfield(L, LUA_GLOBALSINDEX, saved.c_str());
    // Set wrapper
    lua_pushcfunction(L, wrapper);
    lua_setglobal(L, name);
    char buf[192];
    sprintf_s(buf, sizeof(buf), "SaveAndReplace: wrapped %s with %p (saved as %s)", name,
              reinterpret_cast<void*>(wrapper), saved.c_str());
    WriteRawLog(buf);
    lua_settop(L, top);
    return true;
}

static bool IsInMainModule(const void* address)
{
    if (!address)
        return false;

    HMODULE module = GetModuleHandleA(nullptr);
    if (!module)
        return false;

    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), module, &mi, sizeof(mi)))
        return false;

    auto base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
    auto size = static_cast<uintptr_t>(mi.SizeOfImage);
    auto value = reinterpret_cast<uintptr_t>(address);
    return value >= base && value < base + size;
}

static void LogCallersForTarget(const char* name, const void* target)
{
    if (!target)
        return;

    if (std::find(g_loggedCallScanTargets.begin(), g_loggedCallScanTargets.end(), target) != g_loggedCallScanTargets.end())
        return;

    g_loggedCallScanTargets.push_back(target);

    HMODULE module = GetModuleHandleA(nullptr);
    if (!module)
        return;

    const auto* base = reinterpret_cast<const BYTE*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
        return;

    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    std::vector<const void*> callers;

    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        const BYTE* secBase = base + section->VirtualAddress;
        DWORD secSize = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
        if (secSize < 5)
            continue;

        for (DWORD offset = 0; offset + 5 <= secSize; ++offset)
        {
            if (secBase[offset] != 0xE8)
                continue;

            INT32 rel = *reinterpret_cast<const INT32*>(secBase + offset + 1);
            const BYTE* dest = secBase + offset + 5 + rel;
            if (dest == target)
            {
                callers.push_back(secBase + offset);
            }
        }
    }

    if (callers.empty())
    {
        char buf[192];
        sprintf_s(buf, sizeof(buf), "CallScan: no callers found for %s @ %p", name ? name : "<unknown>", target);
        WriteRawLog(buf);
        return;
    }

    std::sort(callers.begin(), callers.end());
    callers.erase(std::unique(callers.begin(), callers.end()), callers.end());

    char buf[192];
    sprintf_s(buf, sizeof(buf), "CallScan: %zu callers for %s @ %p", callers.size(),
        name ? name : "<unknown>", target);
    WriteRawLog(buf);

    for (size_t i = 0; i < callers.size(); ++i)
    {
        const void* callSite = callers[i];
        char modName[MAX_PATH] = { 0 };
        HMODULE callerModule = nullptr;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(callSite), &callerModule))
        {
            GetModuleBaseNameA(GetCurrentProcess(), callerModule, modName, ARRAYSIZE(modName));
        }

        MODULEINFO mi{};
        uintptr_t modBase = 0;
        if (callerModule && GetModuleInformation(GetCurrentProcess(), callerModule, &mi, sizeof(mi)))
        {
            modBase = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        }

        uintptr_t addr = reinterpret_cast<uintptr_t>(callSite);
        unsigned long long offset = (modBase && addr >= modBase) ?
            static_cast<unsigned long long>(addr - modBase) :
            static_cast<unsigned long long>(addr);

        if (modName[0])
        {
            sprintf_s(buf, sizeof(buf), "  caller #%zu: %s+0x%llX (%p)", i, modName, offset, callSite);
        }
        else
        {
            sprintf_s(buf, sizeof(buf), "  caller #%zu: %p", i, callSite);
        }
        WriteRawLog(buf);
    }
}

static void NoteCapturedActionTarget(const char* name, const void* target)
{
    if (!name || !target)
        return;

    if (!IsInMainModule(target))
        return;

    bool shouldLog = false;
    if (_stricmp(name, "UserActionIsTargetModeCompat") == 0 ||
        _stricmp(name, "UserActionIsActionTypeTargetModeCompat") == 0 ||
        _stricmp(name, "UserActionCastSpell") == 0 ||
        _stricmp(name, "UserActionCastSpellOnId") == 0)
    {
        shouldLog = true;
    }

    if (shouldLog)
        LogCallersForTarget(name, target);
}

// Attempt action wrapper install after target APIs appear and a small delay has passed.
static void TryInstallActionWrappers()
{
    if (InterlockedCompareExchange(&g_actionWrappersInstalled, 0, 0) != 0)
        return;
    auto L = static_cast<lua_State*>(Engine::LuaState());
    if (!L) return;

    __try {
        // Gated logging to avoid spam while waiting for globals to exist
        static DWORD s_nextMissingLogMs = 0;
        DWORD now = GetTickCount();
        auto tryWrap = [&](const char* n, lua_CFunction w) -> bool {
            int t0 = lua_gettop(L);
            lua_getglobal(L, n);
            bool present = (lua_type(L, -1) == LUA_TFUNCTION);
            lua_pop(L, 1);
            if (!present) {
                if (now >= s_nextMissingLogMs) {
                    char b[160];
                    sprintf_s(b, sizeof(b), "TryInstallActionWrappers: '%s' not found; will retry", n);
                    WriteRawLog(b);
                }
                return false;
            }
            return SaveAndReplace(L, n, w);
        };

        bool any = false;
        any |= tryWrap("UserActionCastSpell", &Lua_UserActionCastSpell_W);
        any |= tryWrap("UserActionCastSpellOnId", &Lua_UserActionCastSpellOnId_W);
        any |= tryWrap("UserActionUseSkill", &Lua_UserActionUseSkill_W);
        any |= tryWrap("UserActionUsePrimaryAbility", &Lua_UserActionUsePrimaryAbility_W);
        any |= tryWrap("UserActionUseWeaponAbility", &Lua_UserActionUseWeaponAbility_W);
        any |= tryWrap("UserActionIsTargetModeCompat", &Lua_UserActionIsTargetModeCompat_W);
        any |= tryWrap("UserActionIsActionTypeTargetModeCompat", &Lua_UserActionIsActionTypeTargetModeCompat_W);
        any |= tryWrap("RequestTargetInfo", &Lua_RequestTargetInfo_W);
        any |= tryWrap("ClearCurrentTarget", &Lua_ClearCurrentTarget_W);
        any |= tryWrap("UserActionIsSkillAvalible", &Lua_UserActionIsSkillAvalible_W);
        any |= tryWrap("HS_ShowTargetingCursor", &Lua_HS_ShowTargetingCursor_W);
        any |= tryWrap("HS_HideTargetingCursor", &Lua_HS_HideTargetingCursor_W);
        if (any) {
            InterlockedExchange(&g_actionWrappersInstalled, 1);
            WriteRawLog("TryInstallActionWrappers: installed action wrappers via Lua API");
        }
        if (now >= s_nextMissingLogMs) {
            s_nextMissingLogMs = now + 1000;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        static DWORD s_nextExceptionLogMs = 0;
        DWORD now = GetTickCount();
        if (g_traceLuaVerbose || now >= s_nextExceptionLogMs) {
            WriteRawLog("TryInstallActionWrappers: exception while probing Lua globals; will retry later");
            if (!g_traceLuaVerbose) {
                s_nextExceptionLogMs = now + 5000;
            }
        }
    }
}

// Find and hook action C functions directly by scanning for registration sites:
//   push "UserActionCastSpell"; push <fn>; push <ctx>; call RegisterLuaFunction
static BYTE* FindActionFuncByName(const char* actionName)
{
    if (!actionName || !g_registerTarget)
        return nullptr;

    HMODULE hExe = GetModuleHandleA(nullptr);
    if (!hExe) return nullptr;
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), hExe, &mi, sizeof(mi)))
        return nullptr;

    // Locate the ASCII string in the image
    BYTE* base = static_cast<BYTE*>(mi.lpBaseOfDll);
    SIZE_T size = mi.SizeOfImage;
    SIZE_T nameLen = strlen(actionName) + 1; // include NUL
    BYTE* strAddr = FindBytes(base, size, reinterpret_cast<const BYTE*>(actionName), nameLen);
    if (!strAddr)
        return nullptr;

    // Search for code sequence: 68 <strAddr> 68 <fnAddr> 5? E8 <rel32 to g_registerTarget>
    // Scan the entire image; verify the E8 target matches g_registerTarget
    for (BYTE* p = base; p + 16 < base + size; ++p)
    {
        if (p[0] != 0x68) continue; // push imm32
        DWORD imm = *reinterpret_cast<DWORD*>(p + 1);
        if (imm != reinterpret_cast<DWORD>(strAddr))
            continue;

        BYTE* q = p + 5;
        if (q[0] != 0x68) // push imm32 (fn)
            continue;
        DWORD fnImm = *reinterpret_cast<DWORD*>(q + 1);
        BYTE* r = q + 5;
        if (!(r[0] >= 0x50 && r[0] <= 0x57)) // push r32 (context)
            continue;
        BYTE* callSite = r + 1;
        if (callSite[0] != 0xE8)
            continue;
        INT32 rel = *reinterpret_cast<INT32*>(callSite + 1);
        BYTE* callee = callSite + 5 + rel;
        if (reinterpret_cast<void*>(callee) != g_registerTarget)
            continue;
        return reinterpret_cast<BYTE*>(fnImm);
    }
    return nullptr;
}

static void TryInstallDirectActionHooks()
{
    if (InterlockedCompareExchange(&g_directActionHooksInstalled, 0, 0) != 0)
        return;

    HMODULE hExe = GetModuleHandleA(nullptr);
    if (!hExe) return;

    MH_STATUS init = MH_Initialize();
    (void)init; // ignore already-initialized status

    bool any = false;
    auto hookOne = [&](const char* name, LuaFn& orig, lua_CFunction wrapper) {
        if (orig) return; // already captured via register hook
        BYTE* target = FindActionFuncByName(name);
        if (!target)
            return;
        if (MH_CreateHook(reinterpret_cast<void*>(target), wrapper, reinterpret_cast<void**>(&orig)) == MH_OK &&
            MH_EnableHook(reinterpret_cast<void*>(target)) == MH_OK)
        {
            char buf[192];
            sprintf_s(buf, sizeof(buf), "DirectHook: hooked %s at %p (orig=%p)", name, target, reinterpret_cast<void*>(orig));
            WriteRawLog(buf);
            NoteCapturedActionTarget(name, reinterpret_cast<void*>(orig));
            any = true;
        }
    };

    hookOne("UserActionCastSpell", g_origUserActionCastSpell, &Lua_UserActionCastSpell_W);
    hookOne("UserActionCastSpellOnId", g_origUserActionCastSpellOnId, &Lua_UserActionCastSpellOnId_W);
    hookOne("UserActionUseSkill", g_origUserActionUseSkill, &Lua_UserActionUseSkill_W);
    hookOne("UserActionUsePrimaryAbility", g_origUserActionUsePrimaryAbility, &Lua_UserActionUsePrimaryAbility_W);
    hookOne("UserActionUseWeaponAbility", g_origUserActionUseWeaponAbility, &Lua_UserActionUseWeaponAbility_W);
    hookOne("UserActionIsTargetModeCompat", g_origUserActionIsTargetModeCompat, &Lua_UserActionIsTargetModeCompat_W);
    hookOne("UserActionIsActionTypeTargetModeCompat", g_origUserActionIsActionTypeTargetModeCompat, &Lua_UserActionIsActionTypeTargetModeCompat_W);
    hookOne("RequestTargetInfo", g_origRequestTargetInfo, &Lua_RequestTargetInfo_W);
    hookOne("ClearCurrentTarget", g_origClearCurrentTarget, &Lua_ClearCurrentTarget_W);
    hookOne("UserActionIsSkillAvalible", g_origUserActionIsSkillAvalible, &Lua_UserActionIsSkillAvalible_W);
    hookOne("HS_ShowTargetingCursor", g_origHS_ShowTargetingCursor, &Lua_HS_ShowTargetingCursor_W);
    hookOne("HS_HideTargetingCursor", g_origHS_HideTargetingCursor, &Lua_HS_HideTargetingCursor_W);

    if (any) {
        InterlockedExchange(&g_directActionHooksInstalled, 1);
    }
}

static bool RegisterViaClient(lua_State* L, lua_CFunction fn, const char* name)
{
    if (!fn || !name)
        return false;

    if (!g_clientRegister && !g_origRegister)
        return false;

    void* context = g_clientContext;
    const GlobalStateInfo* info = Engine::Info();
    void* candidateCtx = info ? info->scriptContext : nullptr;
    if ((!context || (candidateCtx && context != candidateCtx))) {
        context = candidateCtx;
        g_clientContext = context;
        if (context) {
            char buf[128];
            sprintf_s(buf, sizeof(buf), "RegisterViaClient: refreshed script context %p", context);
            WriteRawLog(buf);
        }
    }

    if (!context) {
        WriteRawLog("RegisterViaClient: script context unavailable");
        return false;
    }

    ClientRegisterFn target = g_origRegister ? g_origRegister : g_clientRegister;
    if (!target)
        return false;

    bool success = false;
    __try {
        int rc = target(context, reinterpret_cast<void*>(fn), name);
        success = (rc != 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "Client register threw for '%s'", name ? name : "<null>");
        WriteRawLog(buf);
        success = false;
    }

    char buf[200];
    sprintf_s(buf, sizeof(buf), "RegisterViaClient('%s') ctx=%p fn=%p => %s (Lua_Walk=%p)",
        name ? name : "<null>", context, fn, success ? "ok" : "fail", reinterpret_cast<void*>(&Lua_Walk));
    WriteRawLog(buf);

    if (!success && L) {
        WriteRawLog("RegisterViaClient: client helper failed, using direct Lua registration");
        success = RegisterFunctionSafe(L, fn, name);
    }

    return success;
}

static void ForceWalkBinding(lua_State* L, const char* reason)
{
    if (!L)
        return;

    InterlockedExchange(&g_pendingRegistration, 0);

    const void* desiredPtr = reinterpret_cast<const void*>(Lua_Walk);
    const char* tag = reason ? reason : "EnsureWalkBinding";

    char stateBuf[160];
    sprintf_s(stateBuf, sizeof(stateBuf), "%s pre-bind", tag);
    LogWalkBindingState(L, stateBuf);

    char buf[224];
    sprintf_s(buf, sizeof(buf), "%s: ensuring UOFlow.Walk.move binding via client helper (Lua_Walk=%p ctx=%p)",
        tag,
        desiredPtr,
        g_clientContext);
    WriteRawLog(buf);

    bool helperOk = RegisterViaClient(L, Lua_Walk, "UOFlow.Walk.move");
    if (helperOk) {
        WriteRawLog("ForceWalkBinding: client helper ensured UOFlow.Walk.move successfully");
    } else {
        WriteRawLog("ForceWalkBinding: client helper failed for UOFlow.Walk.move");
    }

    sprintf_s(stateBuf, sizeof(stateBuf), "%s post-bind", tag);
    LogWalkBindingState(L, stateBuf);
}

static bool ResolveRegisterFunction()
{
    if (g_registerResolved && g_origRegister)
        return true;

    void* addr = Engine::FindRegisterLuaFunction();
    if (!addr) {
        WriteRawLog("ResolveRegisterFunction: unable to find client register helper");
        return false;
    }

    g_registerTarget = addr;
    char buf[128];
    sprintf_s(buf, sizeof(buf), "ResolveRegisterFunction: register helper = %p", addr);
    WriteRawLog(buf);

    if (!g_origRegister) {
        MH_STATUS init = MH_Initialize();
        if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED) {
            WriteRawLog("ResolveRegisterFunction: MH_Initialize failed; hook disabled");
            return false;
        }
        if (MH_CreateHook(addr, &Hook_Register, reinterpret_cast<LPVOID*>(&g_origRegister)) != MH_OK ||
            MH_EnableHook(addr) != MH_OK) {
            g_origRegister = nullptr;
            WriteRawLog("ResolveRegisterFunction: MH_CreateHook/MH_EnableHook failed; hook disabled");
            return false;
        }
        WriteRawLog("ResolveRegisterFunction: register hook installed for context capture");
    }

    g_clientRegister = g_origRegister;
    g_registerResolved = true;
    return true;
}

static int __stdcall Hook_Register(void* ctx, void* func, const char* name)
{
    auto ensureContextSlot = [](void* context, bool* isNew) -> ObservedContext* {
        if (!context) {
            if (isNew) {
                *isNew = false;
            }
            return nullptr;
        }
        for (size_t i = 0; i < kMaxObservedContexts; ++i) {
            if (g_observedContexts[i].ctx == context) {
                if (isNew) {
                    *isNew = false;
                }
                return &g_observedContexts[i];
            }
        }
        for (size_t i = 0; i < kMaxObservedContexts; ++i) {
            if (!g_observedContexts[i].ctx) {
                g_observedContexts[i].ctx = context;
                g_observedContexts[i].flags = 0;
                if (isNew) {
                    *isNew = true;
                }
                return &g_observedContexts[i];
            }
        }
        if (isNew) {
            *isNew = false;
        }
        return nullptr;
    };

    auto containsWalk = [](const char* str) -> bool {
        if (!str) {
            return false;
        }
        const char* p = str;
        while (*p) {
            if (std::tolower(static_cast<unsigned char>(*p)) == 'w') {
                if (std::tolower(static_cast<unsigned char>(p[1])) == 'a' &&
                    std::tolower(static_cast<unsigned char>(p[2])) == 'l' &&
                    std::tolower(static_cast<unsigned char>(p[3])) == 'k') {
                    return true;
                }
            }
            ++p;
        }
        return false;
    };

    char buf[192];
    sprintf_s(buf, sizeof(buf), "Hook_Register ctx=%p func=%p name=%s", ctx, func, name ? name : "<null>");
    WriteRawLog(buf);

    if (ctx && ctx != g_clientContext) {
        g_clientContext = ctx;
        Engine::RequestWalkRegistration();
        InterlockedExchange(&g_pendingRegistration, 1);
    }

    if (ctx) {
        MaybeUpdateOwnerContext(ctx);
    }

    bool isNewCtx = false;
    ObservedContext* slot = ensureContextSlot(ctx, &isNewCtx);
    if (isNewCtx) {
        char info[160];
        sprintf_s(info, sizeof(info), "Observed new script context %p (name=%s func=%p)",
            ctx, name ? name : "<null>", func);
        WriteRawLog(info);
        Engine::RequestWalkRegistration();
        InterlockedExchange(&g_pendingRegistration, 1);
        MaybeUpdateOwnerContext(ctx);
    }

    unsigned flag = 0;
    if (name) {
        if (_stricmp(name, "walk") == 0 || containsWalk(name)) {
            flag |= kLogWalk;
        } else if (_stricmp(name, "bindWalk") == 0) {
            flag |= kLogBindWalk;
        }
    }

    if (slot && flag) {
        slot->flags |= flag;
        char info[256];
        sprintf_s(info, sizeof(info), "Context %p registering %s -> func=%p (flags=0x%X)",
            ctx, name ? name : "<null>", func, slot->flags);
        WriteRawLog(info);
        Engine::RequestWalkRegistration();
        InterlockedExchange(&g_pendingRegistration, 1);
    }

    // Optionally replace certain client Lua C functions with wrappers
    void* outFunc = func;
    if (name && func)
    {
        if (_stricmp(name, "UserActionCastSpell") == 0)
        {
            if (!g_origUserActionCastSpell)
            {
                g_origUserActionCastSpell = reinterpret_cast<LuaFn>(func);
                NoteCapturedActionTarget(name, func);
                outFunc = reinterpret_cast<void*>(&Lua_UserActionCastSpell_W);
                WriteRawLog("Hook_Register: wrapped UserActionCastSpell");
            }
        }
        else if (_stricmp(name, "UserActionCastSpellOnId") == 0)
        {
            if (!g_origUserActionCastSpellOnId)
            {
                g_origUserActionCastSpellOnId = reinterpret_cast<LuaFn>(func);
                NoteCapturedActionTarget(name, func);
                outFunc = reinterpret_cast<void*>(&Lua_UserActionCastSpellOnId_W);
                WriteRawLog("Hook_Register: wrapped UserActionCastSpellOnId");
            }
        }
        else if (_stricmp(name, "UserActionUseSkill") == 0 || _stricmp(name, "UserActionUsePrimaryAbility") == 0)
        {
            if (!g_origUserActionUseSkill)
            {
                g_origUserActionUseSkill = reinterpret_cast<LuaFn>(func);
                NoteCapturedActionTarget(name, func);
                outFunc = reinterpret_cast<void*>(&Lua_UserActionUseSkill_W);
                WriteRawLog("Hook_Register: wrapped UserActionUseSkill");
            }
        }
        else if (_stricmp(name, "UserActionIsTargetModeCompat") == 0)
        {
            if (!g_origUserActionIsTargetModeCompat)
            {
                g_origUserActionIsTargetModeCompat = reinterpret_cast<LuaFn>(func);
                NoteCapturedActionTarget(name, func);
                outFunc = reinterpret_cast<void*>(&Lua_UserActionIsTargetModeCompat_W);
                WriteRawLog("Hook_Register: wrapped UserActionIsTargetModeCompat");
            }
            else
            {
                NoteCapturedActionTarget(name, func);
            }
        }
        else if (_stricmp(name, "UserActionIsActionTypeTargetModeCompat") == 0)
        {
            if (!g_origUserActionIsActionTypeTargetModeCompat)
            {
                g_origUserActionIsActionTypeTargetModeCompat = reinterpret_cast<LuaFn>(func);
                NoteCapturedActionTarget(name, func);
                outFunc = reinterpret_cast<void*>(&Lua_UserActionIsActionTypeTargetModeCompat_W);
                WriteRawLog("Hook_Register: wrapped UserActionIsActionTypeTargetModeCompat");
            }
            else
            {
                NoteCapturedActionTarget(name, func);
            }
        }
        else if (_stricmp(name, "RequestTargetInfo") == 0)
        {
            if (!g_origRequestTargetInfo)
            {
                g_origRequestTargetInfo = reinterpret_cast<LuaFn>(func);
                NoteCapturedActionTarget(name, func);
                outFunc = reinterpret_cast<void*>(&Lua_RequestTargetInfo_W);
                WriteRawLog("Hook_Register: wrapped RequestTargetInfo");
            }
            else
            {
                NoteCapturedActionTarget(name, func);
            }
            g_targetApiTimestamp = GetTickCount();
            InterlockedExchange(&g_targetApiSeen, 1);
        }
        else if (_stricmp(name, "ClearCurrentTarget") == 0)
        {
            if (!g_origClearCurrentTarget)
            {
                g_origClearCurrentTarget = reinterpret_cast<LuaFn>(func);
                NoteCapturedActionTarget(name, func);
                outFunc = reinterpret_cast<void*>(&Lua_ClearCurrentTarget_W);
                WriteRawLog("Hook_Register: wrapped ClearCurrentTarget");
            }
            else
            {
                NoteCapturedActionTarget(name, func);
            }
            g_targetApiTimestamp = GetTickCount();
            InterlockedExchange(&g_targetApiSeen, 1);
        }
        else if (_stricmp(name, "UserActionIsSkillAvalible") == 0)
        {
            if (!g_origUserActionIsSkillAvalible)
            {
                g_origUserActionIsSkillAvalible = reinterpret_cast<LuaFn>(func);
                NoteCapturedActionTarget(name, func);
                outFunc = reinterpret_cast<void*>(&Lua_UserActionIsSkillAvalible_W);
                WriteRawLog("Hook_Register: wrapped UserActionIsSkillAvalible");
            }
        }
        else if (_stricmp(name, "HS_ShowTargetingCursor") == 0)
        {
            if (!g_origHS_ShowTargetingCursor)
            {
                g_origHS_ShowTargetingCursor = reinterpret_cast<LuaFn>(func);
                NoteCapturedActionTarget(name, func);
                outFunc = reinterpret_cast<void*>(&Lua_HS_ShowTargetingCursor_W);
                WriteRawLog("Hook_Register: wrapped HS_ShowTargetingCursor");
            }
        }
        else if (_stricmp(name, "HS_HideTargetingCursor") == 0)
        {
            if (!g_origHS_HideTargetingCursor)
            {
                g_origHS_HideTargetingCursor = reinterpret_cast<LuaFn>(func);
                NoteCapturedActionTarget(name, func);
                outFunc = reinterpret_cast<void*>(&Lua_HS_HideTargetingCursor_W);
                WriteRawLog("Hook_Register: wrapped HS_HideTargetingCursor");
            }
        }
        else if (_stricmp(name, "UserActionUseWeaponAbility") == 0)
        {
            if (!g_origUserActionUseWeaponAbility)
            {
                g_origUserActionUseWeaponAbility = reinterpret_cast<LuaFn>(func);
                NoteCapturedActionTarget(name, func);
                outFunc = reinterpret_cast<void*>(&Lua_UserActionUseWeaponAbility_W);
                WriteRawLog("Hook_Register: wrapped UserActionUseWeaponAbility");
            }
        }
        else if (_stricmp(name, "UserActionUsePrimaryAbility") == 0)
        {
            if (!g_origUserActionUsePrimaryAbility)
            {
                g_origUserActionUsePrimaryAbility = reinterpret_cast<LuaFn>(func);
                NoteCapturedActionTarget(name, func);
                outFunc = reinterpret_cast<void*>(&Lua_UserActionUsePrimaryAbility_W);
                WriteRawLog("Hook_Register: wrapped UserActionUsePrimaryAbility");
            }
        }
    }

    int rc = g_clientRegister ? g_clientRegister(ctx, outFunc, name) : 0;

    // If targeting APIs have been registered, attempt late wrapper install now
    if (name && ( _stricmp(name, "RequestTargetInfo") == 0 || _stricmp(name, "ClearCurrentTarget") == 0)) {
        g_targetApiTimestamp = GetTickCount();
        InterlockedExchange(&g_targetApiSeen, 1);
        TryInstallActionWrappers();
    }

    uintptr_t walkInt = reinterpret_cast<uintptr_t>(&Lua_Walk);
    uintptr_t bindInt = reinterpret_cast<uintptr_t>(&Lua_BindWalk);
    void* walkPtr = reinterpret_cast<void*>(walkInt);
    void* bindPtr = reinterpret_cast<void*>(bindInt);
    if (name && ctx) {
        if (_stricmp(name, "UOFlow.Walk.move") == 0 && func == walkPtr) {
            if (auto L2 = static_cast<lua_State*>(Engine::LuaState())) {
                LogWalkBindingState(L2, "Hook_Register post-UOFlow.Walk.move");
            }
        } else if (_stricmp(name, "bindWalk") == 0 && func == bindPtr) {
            if (auto L2 = static_cast<lua_State*>(Engine::LuaState())) {
                LogWalkBindingState(L2, "Hook_Register post-bindWalk");
            }
        }
    }

    // Avoid calling back into broader Lua registration from within the client's
    // RegisterLuaFunction path to minimize risk during world load.
    // Previously this invoked RegisterOurLuaFunctions() here; that proved risky.

    // Attempt late install of action wrappers once target APIs are present
    TryInstallActionWrappers();
    return rc;
}

static int __cdecl Lua_DummyPrint(lua_State*)
{
    WriteRawLog("[Lua] DummyPrint() was invoked!");
    return 0;
}

static int __cdecl Lua_Walk(lua_State* L)
{
    int dir = 0;
    int run = 0;
    if (L) {
        int top = lua_gettop(L);
        if (top >= 1)
            dir = static_cast<int>(lua_tointeger(L, 1));
        if (top >= 2)
            run = lua_toboolean(L, 2) ? 1 : 0;
    }
    char buf[128];
    sprintf_s(buf, sizeof(buf), "Lua_Walk invoked dir=%d run=%d", dir, run);
    WriteRawLog(buf);

    bool ok = SendWalk(dir, run);
    WriteRawLog(ok ? "Lua_Walk -> walk enqueued" : "Lua_Walk -> walk failed");
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

// Helpers to dump a small callstack for correlation between first and second cast
static void DumpStackTag(const char* tag)
{
    void* frames[8]{};
    USHORT captured = RtlCaptureStackBackTrace(2, 8, frames, nullptr);
    for (USHORT i = 0; i < captured; ++i)
    {
        HMODULE mod = nullptr;
        char modName[MAX_PATH] = {0};
        DWORD modBase = 0;
        DWORD addr = reinterpret_cast<DWORD>(frames[i]);
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCSTR>(frames[i]), &mod))
        {
            MODULEINFO mi{};
            if (GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
            {
                modBase = reinterpret_cast<DWORD>(mi.lpBaseOfDll);
            }
            GetModuleBaseNameA(GetCurrentProcess(), mod, modName, ARRAYSIZE(modName));
        }
        char buf[160];
        if (modName[0])
            sprintf_s(buf, sizeof(buf), "[%s] #%u: %s+0x%X (%p)", tag ? tag : "LuaWrap", i, modName, addr - modBase, frames[i]);
        else
            sprintf_s(buf, sizeof(buf), "[%s] #%u: %p", tag ? tag : "LuaWrap", i, frames[i]);
        WriteRawLog(buf);
    }
}

static void ResetCastPacketWatch(CastPacketWatch& watch)
{
    watch.token = 0;
    watch.spellId = 0;
    watch.startTick = 0;
    watch.baselineCounter = 0;
    watch.awaiting = false;
}

static void SweepCastPacketTimeoutsLocked(DWORD now)
{
    if (!g_castPacketTrackingEnabled)
        return;
    if (g_castPacketTimeoutMs == 0)
        return;
    for (auto& watch : g_castPacketWatches) {
        if (watch.token != 0 && watch.awaiting) {
            DWORD age = now - watch.startTick;
            if (age > g_castPacketTimeoutMs) {
                char buf[256];
                sprintf_s(buf, sizeof(buf),
                    "[CastSpell] tok=%u spell=%d no SendPacket observed within %lu ms",
                    watch.token, watch.spellId, static_cast<unsigned long>(age));
                WriteRawLog(buf);
                ResetCastPacketWatch(watch);
            }
        }
    }
}

static void TrackCastPacket(uint32_t token, int spellId, unsigned counter)
{
    if (!g_castPacketTrackingEnabled || token == 0)
        return;
    std::lock_guard<std::mutex> lock(g_castPacketMutex);
    DWORD now = GetTickCount();
    SweepCastPacketTimeoutsLocked(now);
    CastPacketWatch* slot = nullptr;
    CastPacketWatch* oldest = nullptr;
    for (auto& watch : g_castPacketWatches) {
        if (watch.token == token) {
            slot = &watch;
            break;
        }
        if (!slot && watch.token == 0)
            slot = &watch;
        if (watch.token != 0 && (!oldest || watch.startTick < oldest->startTick))
            oldest = &watch;
    }
    if (!slot && oldest) {
        char buf[256];
        sprintf_s(buf, sizeof(buf),
            "[CastSpell] reusing packet tracker slot tok=%u spell=%d for tok=%u spell=%d",
            oldest->token, oldest->spellId, token, spellId);
        WriteRawLog(buf);
        slot = oldest;
    }
    if (!slot)
        return;
    slot->token = token;
    slot->spellId = spellId;
    slot->startTick = now;
    slot->baselineCounter = counter;
    slot->awaiting = false;
}

static void ReleaseCastPacket(uint32_t token)
{
    if (!g_castPacketTrackingEnabled || token == 0)
        return;
    std::lock_guard<std::mutex> lock(g_castPacketMutex);
    for (auto& watch : g_castPacketWatches) {
        if (watch.token == token) {
            ResetCastPacketWatch(watch);
            break;
        }
    }
}

static bool ArmCastPacketWatch(uint32_t token, unsigned counter)
{
    if (!g_castPacketTrackingEnabled || token == 0)
        return false;
    std::lock_guard<std::mutex> lock(g_castPacketMutex);
    DWORD now = GetTickCount();
    SweepCastPacketTimeoutsLocked(now);
    for (auto& watch : g_castPacketWatches) {
        if (watch.token == token) {
            watch.awaiting = true;
            watch.startTick = now;
            watch.baselineCounter = counter;
            return true;
        }
    }
    return false;
}

static void HandleCastPacketSend(unsigned counter, const void* pkt, int len)
{
    if (!g_castPacketTrackingEnabled || counter == 0)
        return;
    std::lock_guard<std::mutex> lock(g_castPacketMutex);
    DWORD now = GetTickCount();
    SweepCastPacketTimeoutsLocked(now);
    CastPacketWatch* match = nullptr;
    for (auto& watch : g_castPacketWatches) {
        if (watch.token != 0 && watch.awaiting && counter > watch.baselineCounter) {
            if (!match || watch.startTick < match->startTick)
                match = &watch;
        }
    }
    if (!match)
        return;
    unsigned char id = 0;
    if (pkt && len > 0)
        id = *reinterpret_cast<const unsigned char*>(pkt);
    DWORD dt = now - match->startTick;
    char buf[256];
    sprintf_s(buf, sizeof(buf),
        "[CastSpell] tok=%u spell=%d observed SendPacket id=%02X len=%d after %lu ms (counter %u->%u)",
        match->token, match->spellId, id, len,
        static_cast<unsigned long>(dt), match->baselineCounter, counter);
    WriteRawLog(buf);
    ResetCastPacketWatch(*match);
}

static int __cdecl Lua_UserActionCastSpell_W(lua_State* L)
{
    const uint32_t previousTok = g_tlsCurrentCastToken;
    const uint32_t token = NextCastToken();
    g_tlsCurrentCastToken = token;
    g_lastCastToken.store(token, std::memory_order_release);

    DWORD now = GetTickCount();
    DWORD prevAttempt = g_lastCastAttemptTick.exchange(now, std::memory_order_acq_rel);
    DWORD sincePrevAttempt = prevAttempt ? (now - prevAttempt) : 0;
    DWORD lastSuccess = g_lastSuccessfulCastTick.load(std::memory_order_acquire);
    DWORD sinceLastSuccess = lastSuccess ? (now - lastSuccess) : 0;

    int spellId = 0;
    if (L && lua_gettop(L) >= 1 && lua_type(L, 1) == LUA_TNUMBER) {
        spellId = static_cast<int>(lua_tointeger(L, 1));
    }
    UowTracePushSpell(spellId);
    CastCorrelator::OnCastAttempt(static_cast<uint32_t>(spellId < 0 ? 0 : spellId));

    CastSpellSnapshot snapshotBefore = CaptureCastSpellSnapshot(L);
    LogCastSpellSnapshot("pre", token, spellId, snapshotBefore);

    void* scriptCtx = CurrentScriptContext();
    void* ownerCtx = CanonicalOwnerContext();
    DWORD ownerTid = g_ownerThreadId.load(std::memory_order_acquire);
    DWORD tid = GetCurrentThreadId();
    const bool ownerMatch = (scriptCtx != nullptr && ownerCtx != nullptr && scriptCtx == ownerCtx);

    char intro[256];
    sprintf_s(intro, sizeof(intro),
        "[Lua] UserActionCastSpell() wrapper invoked tok=%u spell=%d ctx=%p owner=%p tid=%u ownerTid=%u sincePrev=%u sinceLastSuccess=%u ownerMatch=%s",
        token, spellId, scriptCtx, ownerCtx, tid, ownerTid,
        sincePrevAttempt, sinceLastSuccess, ownerMatch ? "yes" : "no");
    WriteRawLog(intro);

    Trace::MarkAction("CastSpell");
    DumpStackTag("CastSpell");
    static volatile LONG s_noPacketLogs = 0;
    static volatile LONG s_upvalueLogs = 0;
    if (g_traceLuaVerbose) {
        LogLuaArgs(L, "UserActionCastSpell");
    }

    unsigned sentBefore = Net::GetSendCounter();
    TrackCastPacket(token, spellId, sentBefore);
    bool gateArmed = GateArmForCast();

    bool usedSaved = false;
    int savedCount = -1;
    bool usedDirect = false;
    int directValue = 0;

    int rc = CallSavedOriginal(L, "UserActionCastSpell__orig");
    if (rc >= 0) {
        usedSaved = true;
        savedCount = rc;
        if (g_traceLuaVerbose && savedCount > 0) {
            LogLuaReturns(L, "UserActionCastSpell", savedCount);
        }
    } else if (g_origUserActionCastSpell) {
        directValue = InvokeClientLuaFn(g_origUserActionCastSpell, "UserActionCastSpell", L);
        usedDirect = true;
        if (g_traceLuaVerbose && directValue > 0) {
            LogLuaReturns(L, "UserActionCastSpell", directValue);
        }
    } else {
        WriteRawLog("[Lua] UserActionCastSpell original missing (saved and ptr)");
        UowTraceCollectRAs();
        unsigned missPathId = LogCastSpellPath(token, g_castSpellLastRAs, ownerMatch);
        if (g_logCastSpellCallLists)
            DumpCastSpellCallees(g_castSpellLastRAs, missPathId, token, false);
        if (gateArmed)
            GateDisarmForCast("UserActionCastSpell:missing_orig");
        ReleaseCastPacket(token);
        g_tlsCurrentCastToken = previousTok;
        return 0;
    }

    unsigned sentAfter = Net::GetSendCounter();
    unsigned delta = sentAfter - sentBefore;
    const bool packetSent = (delta > 0);
    if (packetSent) {
        g_lastSuccessfulCastTick.store(now, std::memory_order_release);
    }

    UowTraceCollectRAs();
    unsigned pathId = LogCastSpellPath(token, g_castSpellLastRAs, ownerMatch);
    if (g_castSpellCalleeUnlimited) {
        DumpCastSpellCallees(g_castSpellLastRAs, pathId, token, packetSent);
    } else if (InterlockedCompareExchange(&g_castSpellCalleeBudget, 0, 0) > 0) {
        LONG left = InterlockedDecrement(&g_castSpellCalleeBudget);
        if (left >= 0)
            DumpCastSpellCallees(g_castSpellLastRAs, pathId, token, packetSent);
    } else if (g_logCastSpellCallLists) {
        DumpCastSpellCallees(g_castSpellLastRAs, pathId, token, packetSent);
    }

    char detail[320];
    const char* callKind = usedSaved ? "saved" : "direct";
    const int returnValue = usedSaved ? savedCount : directValue;
    sprintf_s(detail, sizeof(detail),
        "[Lua] UserActionCastSpell rc=%d packets(before=%u after=%u delta=%u) tok=%u call=%s spell=%d attemptDelta=%u sinceSuccess=%u",
        returnValue, sentBefore, sentAfter, delta, token, callKind, spellId,
        sincePrevAttempt, sinceLastSuccess);
    WriteRawLog(detail);

    if (packetSent) {
        ReleaseCastPacket(token);
        WriteRawLog("[Lua] CastSpell -> packet observed");
    } else {
        bool tracking = ArmCastPacketWatch(token, sentAfter);
        if (tracking)
            WriteRawLog("[Lua] CastSpell -> no packet observed yet (tracking pending send)");
        else
            WriteRawLog("[Lua] CastSpell -> no packet sent");
        LONG order = InterlockedIncrement(&s_noPacketLogs);
        if (order <= 8) {
            LogLuaErrorTop(L, "UserActionCastSpell/noPacket");
            LogSavedOriginalUpvalues(L, "UserActionCastSpell__orig", "UserActionCastSpell", "UserActionCastSpell/upvalues", &s_upvalueLogs);
        }
        CastSpellSnapshot snapshotAfter = CaptureCastSpellSnapshot(L);
        LogCastSpellSnapshot("post", token, spellId, snapshotAfter);
    }

    if (gateArmed)
        GateDisarmForCast(packetSent ? "UserActionCastSpell:packet" : "UserActionCastSpell:no_packet");

    g_tlsCurrentCastToken = previousTok;
    return returnValue;
}

static int __cdecl Lua_UserActionCastSpellOnId_W(lua_State* L)
{
    int spellId = 0;
    int targetId = 0;
    if (L) {
        int top = lua_gettop(L);
        if (top >= 1 && lua_type(L, 1) == LUA_TNUMBER)
            spellId = static_cast<int>(lua_tointeger(L, 1));
        if (top >= 2 && lua_type(L, 2) == LUA_TNUMBER)
            targetId = static_cast<int>(lua_tointeger(L, 2));
    }
    UowTracePushSpell(spellId);
    CastCorrelator::OnCastAttempt(static_cast<uint32_t>(spellId < 0 ? 0 : spellId));
    uint32_t tok = CurrentCastToken();
    char intro[192];
    sprintf_s(intro, sizeof(intro), "[Lua] UserActionCastSpellOnId() wrapper invoked tok=%u spell=%d target=%d", tok, spellId, targetId);
    WriteRawLog(intro);
    Trace::MarkAction("CastSpellOnId");
    DumpStackTag("CastSpellOnId");
    static volatile LONG s_noPacketLogs = 0;
    static volatile LONG s_upvalueLogs = 0;
    if (g_traceLuaVerbose) {
        LogLuaArgs(L, "UserActionCastSpellOnId");
    }
    unsigned sentBefore = Net::GetSendCounter();
    int rc = CallSavedOriginal(L, "UserActionCastSpellOnId__orig");
    if (rc >= 0) {
        char exitBuf[160];
        sprintf_s(exitBuf, sizeof(exitBuf), "[Lua] UserActionCastSpellOnId() wrapper exit (saved) tok=%u", tok);
        WriteRawLog(exitBuf);
        if (g_traceLuaVerbose && rc > 0)
            LogLuaReturns(L, "UserActionCastSpellOnId", rc);
        unsigned sentAfter = Net::GetSendCounter();
        unsigned delta = sentAfter - sentBefore;
        char detail[192];
        sprintf_s(detail, sizeof(detail),
            "[Lua] UserActionCastSpellOnId rc=%d packets(before=%u after=%u delta=%u) tok=%u",
            rc, sentBefore, sentAfter, delta, tok);
        WriteRawLog(detail);
        if (delta > 0) WriteRawLog("[Lua] CastSpellOnId -> packet observed");
        else {
            WriteRawLog("[Lua] CastSpellOnId -> no packet sent");
            LONG order = InterlockedIncrement(&s_noPacketLogs);
            if (order <= 8) {
                LogLuaErrorTop(L, "UserActionCastSpellOnId/noPacket");
                LogSavedOriginalUpvalues(L, "UserActionCastSpellOnId__orig", "UserActionCastSpellOnId", "UserActionCastSpellOnId/upvalues", &s_upvalueLogs);
            }
        }
        return rc;
    }
    if (g_origUserActionCastSpellOnId) {
        int out = InvokeClientLuaFn(g_origUserActionCastSpellOnId, "UserActionCastSpellOnId", L);
        char exitBuf[160];
        sprintf_s(exitBuf, sizeof(exitBuf), "[Lua] UserActionCastSpellOnId() wrapper exit (orig ptr) tok=%u", tok);
        WriteRawLog(exitBuf);
        if (g_traceLuaVerbose && out > 0)
            LogLuaReturns(L, "UserActionCastSpellOnId", out);
        unsigned sentAfter = Net::GetSendCounter();
        unsigned delta = sentAfter - sentBefore;
        char detail[192];
        sprintf_s(detail, sizeof(detail),
            "[Lua] UserActionCastSpellOnId rc=%d packets(before=%u after=%u delta=%u) tok=%u",
            out, sentBefore, sentAfter, delta, tok);
        WriteRawLog(detail);
        if (delta > 0) WriteRawLog("[Lua] CastSpellOnId -> packet observed");
        else {
            WriteRawLog("[Lua] CastSpellOnId -> no packet sent");
            LONG order = InterlockedIncrement(&s_noPacketLogs);
            if (order <= 8) {
                LogLuaErrorTop(L, "UserActionCastSpellOnId/noPacket");
                LogSavedOriginalUpvalues(L, "UserActionCastSpellOnId__orig", "UserActionCastSpellOnId", "UserActionCastSpellOnId/upvalues", &s_upvalueLogs);
            }
        }
        return out;
    }
    WriteRawLog("[Lua] UserActionCastSpellOnId original missing (saved and ptr)");
    return 0;
}

static int __cdecl Lua_UserActionUseSkill_W(lua_State* L)
{
    WriteRawLog("[Lua] UserActionUseSkill() wrapper invoked");
    Trace::MarkAction("UseSkill");
    DumpStackTag("UseSkill");
    static volatile LONG s_noPacketLogs = 0;
    static volatile LONG s_upvalueLogs = 0;
    unsigned sentBefore = Net::GetSendCounter();
    int rc = CallSavedOriginal(L, "UserActionUseSkill__orig");
    if (rc >= 0) {
        WriteRawLog("[Lua] UserActionUseSkill() wrapper exit (saved)");
        if (g_traceLuaVerbose && rc > 0)
            LogLuaReturns(L, "UserActionUseSkill", rc);
        unsigned sentAfter = Net::GetSendCounter();
        if (sentAfter > sentBefore) WriteRawLog("[Lua] UseSkill -> packet observed");
        else {
            WriteRawLog("[Lua] UseSkill -> no packet sent");
            LONG order = InterlockedIncrement(&s_noPacketLogs);
            if (order <= 8) {
                LogLuaErrorTop(L, "UserActionUseSkill/noPacket");
                LogSavedOriginalUpvalues(L, "UserActionUseSkill__orig", "UserActionUseSkill", "UserActionUseSkill/upvalues", &s_upvalueLogs);
            }
        }
        return rc;
    }
    if (g_origUserActionUseSkill) {
        int out = 0;
        __try { out = g_origUserActionUseSkill(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] UserActionUseSkill original threw"); }
        WriteRawLog("[Lua] UserActionUseSkill() wrapper exit (orig ptr)");
        if (g_traceLuaVerbose && out > 0)
            LogLuaReturns(L, "UserActionUseSkill", out);
        unsigned sentAfter = Net::GetSendCounter();
        if (sentAfter > sentBefore) WriteRawLog("[Lua] UseSkill -> packet observed");
        else {
            WriteRawLog("[Lua] UseSkill -> no packet sent");
            LONG order = InterlockedIncrement(&s_noPacketLogs);
            if (order <= 8) {
                LogLuaErrorTop(L, "UserActionUseSkill/noPacket");
                LogSavedOriginalUpvalues(L, "UserActionUseSkill__orig", "UserActionUseSkill", "UserActionUseSkill/upvalues", &s_upvalueLogs);
            }
        }
        return out;
    }
    WriteRawLog("[Lua] UserActionUseSkill original missing (saved and ptr)");
    return 0;
}

// Additional wrappers to trace gating/abilities and targeting cursor
static int __cdecl Lua_UserActionIsSkillAvalible_W(lua_State* L)
{
    WriteRawLog("[Lua] UserActionIsSkillAvalible() wrapper invoked");
    Trace::MarkAction("IsSkillAvalible");
    LogLuaArgs(L, "UserActionIsSkillAvalible");
    int rc = 0;
    if (g_origUserActionIsSkillAvalible) {
        __try { rc = g_origUserActionIsSkillAvalible(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] UserActionIsSkillAvalible original threw"); }
    }
    LogLuaReturns(L, "UserActionIsSkillAvalible", rc);
    return rc;
}

static int __cdecl Lua_HS_ShowTargetingCursor_W(lua_State* L)
{
    uint32_t tok = CurrentCastToken();
    char intro[160];
    sprintf_s(intro, sizeof(intro), "[Lua] HS_ShowTargetingCursor() wrapper invoked tok=%u", tok);
    WriteRawLog(intro);
    Trace::MarkAction("HS_ShowTargetingCursor");
    LogLuaArgs(L, "HS_ShowTargetingCursor");
    int rc = 0;
    if (g_origHS_ShowTargetingCursor) {
        __try { rc = g_origHS_ShowTargetingCursor(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] HS_ShowTargetingCursor original threw"); }
    }
    LogLuaReturns(L, "HS_ShowTargetingCursor", rc);
    char detail[160];
    sprintf_s(detail, sizeof(detail), "[Lua] HS_ShowTargetingCursor rc=%d tok=%u", rc, tok);
    WriteRawLog(detail);
    return rc;
}

static int __cdecl Lua_HS_HideTargetingCursor_W(lua_State* L)
{
    uint32_t tok = CurrentCastToken();
    char intro[160];
    sprintf_s(intro, sizeof(intro), "[Lua] HS_HideTargetingCursor() wrapper invoked tok=%u", tok);
    WriteRawLog(intro);
    Trace::MarkAction("HS_HideTargetingCursor");
    LogLuaArgs(L, "HS_HideTargetingCursor");
    int rc = 0;
    if (g_origHS_HideTargetingCursor) {
        __try { rc = g_origHS_HideTargetingCursor(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] HS_HideTargetingCursor original threw"); }
    }
    LogLuaReturns(L, "HS_HideTargetingCursor", rc);
    char detail[160];
    sprintf_s(detail, sizeof(detail), "[Lua] HS_HideTargetingCursor rc=%d tok=%u", rc, tok);
    WriteRawLog(detail);
    return rc;
}

static int __cdecl Lua_UserActionUseWeaponAbility_W(lua_State* L)
{
    WriteRawLog("[Lua] UserActionUseWeaponAbility() wrapper invoked");
    Trace::MarkAction("UseWeaponAbility");
    DumpStackTag("UseWeaponAbility");
    static volatile LONG s_noPacketLogs = 0;
    static volatile LONG s_upvalueLogs = 0;
    unsigned sentBefore = Net::GetSendCounter();
    int rc = CallSavedOriginal(L, "UserActionUseWeaponAbility__orig");
    if (rc >= 0) {
        WriteRawLog("[Lua] UserActionUseWeaponAbility() wrapper exit (saved)");
        if (g_traceLuaVerbose && rc > 0)
            LogLuaReturns(L, "UserActionUseWeaponAbility", rc);
        unsigned sentAfter = Net::GetSendCounter();
        if (sentAfter > sentBefore) WriteRawLog("[Lua] UseWeaponAbility -> packet observed");
        else {
            WriteRawLog("[Lua] UseWeaponAbility -> no packet sent");
            LONG order = InterlockedIncrement(&s_noPacketLogs);
            if (order <= 8) {
                LogLuaErrorTop(L, "UserActionUseWeaponAbility/noPacket");
                LogSavedOriginalUpvalues(L, "UserActionUseWeaponAbility__orig", "UserActionUseWeaponAbility", "UserActionUseWeaponAbility/upvalues", &s_upvalueLogs);
            }
        }
        return rc;
    }
    if (g_origUserActionUseWeaponAbility) {
        int out = 0;
        __try { out = g_origUserActionUseWeaponAbility(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] UserActionUseWeaponAbility original threw"); }
        WriteRawLog("[Lua] UserActionUseWeaponAbility() wrapper exit (orig ptr)");
        if (g_traceLuaVerbose && out > 0)
            LogLuaReturns(L, "UserActionUseWeaponAbility", out);
        unsigned sentAfter = Net::GetSendCounter();
        if (sentAfter > sentBefore) WriteRawLog("[Lua] UseWeaponAbility -> packet observed");
        else {
            WriteRawLog("[Lua] UseWeaponAbility -> no packet sent");
            LONG order = InterlockedIncrement(&s_noPacketLogs);
            if (order <= 8) {
                LogLuaErrorTop(L, "UserActionUseWeaponAbility/noPacket");
                LogSavedOriginalUpvalues(L, "UserActionUseWeaponAbility__orig", "UserActionUseWeaponAbility", "UserActionUseWeaponAbility/upvalues", &s_upvalueLogs);
            }
        }
        return out;
    }
    WriteRawLog("[Lua] UserActionUseWeaponAbility original missing (saved and ptr)");
    return 0;
}

static int __cdecl Lua_UserActionUsePrimaryAbility_W(lua_State* L)
{
    WriteRawLog("[Lua] UserActionUsePrimaryAbility() wrapper invoked");
    Trace::MarkAction("UsePrimaryAbility");
    DumpStackTag("UsePrimaryAbility");
    static volatile LONG s_noPacketLogs = 0;
    static volatile LONG s_upvalueLogs = 0;
    unsigned sentBefore = Net::GetSendCounter();
    int rc = CallSavedOriginal(L, "UserActionUsePrimaryAbility__orig");
    if (rc >= 0) {
        WriteRawLog("[Lua] UserActionUsePrimaryAbility() wrapper exit (saved)");
        if (g_traceLuaVerbose && rc > 0)
            LogLuaReturns(L, "UserActionUsePrimaryAbility", rc);
        unsigned sentAfter = Net::GetSendCounter();
        if (sentAfter > sentBefore) WriteRawLog("[Lua] UsePrimaryAbility -> packet observed");
        else {
            WriteRawLog("[Lua] UsePrimaryAbility -> no packet sent");
            LONG order = InterlockedIncrement(&s_noPacketLogs);
            if (order <= 8) {
                LogLuaErrorTop(L, "UserActionUsePrimaryAbility/noPacket");
                LogSavedOriginalUpvalues(L, "UserActionUsePrimaryAbility__orig", "UserActionUsePrimaryAbility", "UserActionUsePrimaryAbility/upvalues", &s_upvalueLogs);
            }
        }
        return rc;
    }
    if (g_origUserActionUsePrimaryAbility) {
        int out = 0;
        __try { out = g_origUserActionUsePrimaryAbility(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] UserActionUsePrimaryAbility original threw"); }
        WriteRawLog("[Lua] UserActionUsePrimaryAbility() wrapper exit (orig ptr)");
        if (g_traceLuaVerbose && out > 0)
            LogLuaReturns(L, "UserActionUsePrimaryAbility", out);
        unsigned sentAfter = Net::GetSendCounter();
        if (sentAfter > sentBefore) WriteRawLog("[Lua] UsePrimaryAbility -> packet observed");
        else {
            WriteRawLog("[Lua] UsePrimaryAbility -> no packet sent");
            LONG order = InterlockedIncrement(&s_noPacketLogs);
            if (order <= 8) {
                LogLuaErrorTop(L, "UserActionUsePrimaryAbility/noPacket");
                LogSavedOriginalUpvalues(L, "UserActionUsePrimaryAbility__orig", "UserActionUsePrimaryAbility", "UserActionUsePrimaryAbility/upvalues", &s_upvalueLogs);
            }
        }
        return out;
    }
    WriteRawLog("[Lua] UserActionUsePrimaryAbility original missing (saved and ptr)");
    return 0;
}

// Generic Lua arg/ret logging helpers for gating insight
static void LogLuaArgs(lua_State* L, const char* func, int maxArgs)
{
    if (!L || !g_traceLuaVerbose) return;
    int top = lua_gettop(L);
    char buf[256];
    sprintf_s(buf, sizeof(buf), "[Lua] %s args: top=%d", func ? func : "<fn>", top);
    WriteRawLog(buf);
    int n = top < maxArgs ? top : maxArgs;
    for (int i = 1; i <= n; ++i) {
        int t = lua_type(L, i);
        const char* tn = lua_typename(L, t);
        switch (t) {
        case LUA_TNUMBER:
        {
            int v = lua_tointeger(L, i);
            sprintf_s(buf, sizeof(buf), "  arg%d (%s) = %d", i, tn, v);
            break;
        }
        case LUA_TBOOLEAN:
        {
            int v = lua_toboolean(L, i);
            sprintf_s(buf, sizeof(buf), "  arg%d (%s) = %s", i, tn, v ? "true" : "false");
            break;
        }
        case LUA_TSTRING:
        {
            const char* s = lua_tolstring(L, i, nullptr);
            sprintf_s(buf, sizeof(buf), "  arg%d (%s) = %s", i, tn, s ? s : "<null>");
            break;
        }
        default:
            sprintf_s(buf, sizeof(buf), "  arg%d (%s)", i, tn ? tn : "?");
            break;
        }
        WriteRawLog(buf);
    }
}

static void LogLuaReturns(lua_State* L, const char* func, int nret)
{
    if (!L || nret <= 0 || !g_traceLuaVerbose) return;
    int topAfter = lua_gettop(L);
    char buf[256];
    sprintf_s(buf, sizeof(buf), "[Lua] %s returns: nret=%d", func ? func : "<fn>", nret);
    WriteRawLog(buf);
    int start = topAfter - nret + 1;
    if (start < 1) start = 1;
    for (int i = start; i <= topAfter; ++i) {
        int t = lua_type(L, i);
        const char* tn = lua_typename(L, t);
        switch (t) {
        case LUA_TNUMBER:
        {
            int v = lua_tointeger(L, i);
            sprintf_s(buf, sizeof(buf), "  ret%d (%s) = %d", i - start + 1, tn, v);
            break;
        }
        case LUA_TBOOLEAN:
        {
            int v = lua_toboolean(L, i);
            sprintf_s(buf, sizeof(buf), "  ret%d (%s) = %s", i - start + 1, tn, v ? "true" : "false");
            break;
        }
        case LUA_TSTRING:
        {
            const char* s = lua_tolstring(L, i, nullptr);
            sprintf_s(buf, sizeof(buf), "  ret%d (%s) = %s", i - start + 1, tn, s ? s : "<null>");
            break;
        }
        default:
            sprintf_s(buf, sizeof(buf), "  ret%d (%s)", i - start + 1, tn ? tn : "?");
            break;
        }
        WriteRawLog(buf);
    }
}

static int LuaAbsIndex(lua_State* L, int idx)
{
    if (!L)
        return idx;
    if (idx > 0 || idx <= LUA_REGISTRYINDEX)
        return idx;
    return lua_gettop(L) + idx + 1;
}

static void LogLuaClosureUpvalues(lua_State* L, int funcIndex, const char* context, int maxUpvalues)
{
    if (!L || maxUpvalues <= 0)
        return;

    int absIdx = LuaAbsIndex(L, funcIndex);
    int topBefore = lua_gettop(L);
    const void* fnPtr = lua_topointer(L, absIdx);

    char header[256];
    sprintf_s(header, sizeof(header), "[Lua] %s closure=%p upvalues", context ? context : "closure", fnPtr);
    WriteRawLog(header);
    LogLuaTopTypes(L, context ? context : "closure", 6);

    lua_pushvalue(L, absIdx);
    lua_getfenv(L, -1);
    int envType = lua_type(L, -1);
    const void* envPtr = nullptr;
    if (envType == LUA_TFUNCTION || envType == LUA_TTABLE || envType == LUA_TLIGHTUSERDATA || envType == LUA_TUSERDATA)
        envPtr = lua_topointer(L, -1);
    char envLine[256];
    sprintf_s(envLine, sizeof(envLine), "  env(%s) type=%s ptr=%p",
        context ? context : "closure", lua_typename(L, envType), envPtr);
    WriteRawLog(envLine);
    lua_pop(L, 2);

    bool any = false;
    for (int i = 1; i <= maxUpvalues; ++i) {
        const char* name = lua_getupvalue(L, absIdx, i);
        if (!name)
            break;
        any = true;
        int t = lua_type(L, -1);
        const char* tn = lua_typename(L, t);
        char line[256];
        switch (t) {
        case LUA_TNUMBER:
        {
            lua_Number v = lua_tonumber(L, -1);
            sprintf_s(line, sizeof(line), "  upvalue#%d (%s) = %.3f", i, tn ? tn : "number", static_cast<double>(v));
            break;
        }
        case LUA_TBOOLEAN:
        {
            int v = lua_toboolean(L, -1);
            sprintf_s(line, sizeof(line), "  upvalue#%d (%s) = %s", i, tn ? tn : "boolean", v ? "true" : "false");
            break;
        }
        case LUA_TSTRING:
        {
            size_t len = 0;
            const char* s = lua_tolstring(L, -1, &len);
            if (s && len > 96) len = 96;
            sprintf_s(line, sizeof(line), "  upvalue#%d (%s) = %.*s", i, tn ? tn : "string", static_cast<int>(len), s ? s : "");
            break;
        }
        case LUA_TLIGHTUSERDATA:
        case LUA_TUSERDATA:
        case LUA_TFUNCTION:
        case LUA_TTABLE:
        case LUA_TTHREAD:
        {
            const void* ptr = lua_topointer(L, -1);
            sprintf_s(line, sizeof(line), "  upvalue#%d (%s) = %p", i, tn ? tn : "ptr", ptr);
            break;
        }
        case LUA_TNIL:
            sprintf_s(line, sizeof(line), "  upvalue#%d (%s) = nil", i, tn ? tn : "nil");
            break;
        default:
        {
            sprintf_s(line, sizeof(line), "  upvalue#%d (%s)", i, tn ? tn : "?");
            break;
        }
        }
        WriteRawLog(line);
        lua_pop(L, 1);
    }

    if (!any) {
        WriteRawLog("  <no upvalues>");
    }

    lua_settop(L, topBefore);
}

static void LogSavedOriginalUpvalues(lua_State* L, const char* savedName, const char* globalName, const char* context, volatile LONG* gate, int maxUpvalues)
{
    if (!L || !savedName || maxUpvalues <= 0)
        return;
    LONG order = gate ? InterlockedIncrement(gate) : 1;
    if (gate && order > 3)
        return;

    int top = lua_gettop(L);
    lua_getglobal(L, savedName);
    int savedType = lua_type(L, -1);
    if (savedType == LUA_TFUNCTION) {
        LogLuaClosureUpvalues(L, -1, context ? context : savedName, maxUpvalues);
        lua_settop(L, top);
        return;
    } else {
        lua_pop(L, 1);
        if (globalName && *globalName) {
            lua_getglobal(L, globalName);
            if (lua_type(L, -1) == LUA_TFUNCTION) {
                char buf[192];
                sprintf_s(buf, sizeof(buf), "[Lua] %s saved original missing; inspecting global '%s' instead", context ? context : globalName, globalName);
                WriteRawLog(buf);
                LogLuaClosureUpvalues(L, -1, context ? context : globalName, maxUpvalues);
                lua_settop(L, top);
                return;
            }
            lua_pop(L, 1);
        }
        char buf[192];
        sprintf_s(buf, sizeof(buf), "[Lua] %s missing saved original '%s' (type=%s)", context ? context : "closure", savedName, lua_typename(L, savedType));
        WriteRawLog(buf);
    }
    lua_settop(L, top);
}

static void LogLuaErrorTop(lua_State* L, const char* context, int maxSlots)
{
    if (!L) return;
    __try {
        int top = lua_gettop(L);
        char buf[256];
        sprintf_s(buf, sizeof(buf), "[Lua] %s stack snapshot: top=%d", context ? context : "LuaStack", top);
        WriteRawLog(buf);
        if (top <= 0)
            return;
        int start = top - maxSlots + 1;
        if (start < 1)
            start = 1;
        for (int idx = start; idx <= top; ++idx) {
            int t = lua_type(L, idx);
            const char* tn = lua_typename(L, t);
            switch (t) {
            case LUA_TNUMBER:
            {
                lua_Number v = lua_tonumber(L, idx);
                sprintf_s(buf, sizeof(buf), "  slot%d (%s) = %.3f", idx, tn ? tn : "number", static_cast<double>(v));
                break;
            }
            case LUA_TBOOLEAN:
            {
                int v = lua_toboolean(L, idx);
                sprintf_s(buf, sizeof(buf), "  slot%d (%s) = %s", idx, tn ? tn : "boolean", v ? "true" : "false");
                break;
            }
            case LUA_TSTRING:
            {
                size_t len = 0;
                const char* s = lua_tolstring(L, idx, &len);
                if (s && len > 96) len = 96;
                sprintf_s(buf, sizeof(buf), "  slot%d (%s) = %.*s", idx, tn ? tn : "string", static_cast<int>(len), s ? s : "");
                break;
            }
            case LUA_TNIL:
            {
                sprintf_s(buf, sizeof(buf), "  slot%d (%s) = nil", idx, tn ? tn : "nil");
                break;
            }
            case LUA_TFUNCTION:
            case LUA_TTABLE:
            case LUA_TUSERDATA:
            case LUA_TLIGHTUSERDATA:
            {
                const void* ptr = lua_topointer(L, idx);
                sprintf_s(buf, sizeof(buf), "  slot%d (%s) = %p", idx, tn ? tn : "ptr", ptr);
                break;
            }
            default:
                sprintf_s(buf, sizeof(buf), "  slot%d (%s)", idx, tn ? tn : "?");
                break;
            }
            WriteRawLog(buf);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("[Lua] LogLuaErrorTop: exception while inspecting stack");
    }
}

static int __cdecl Lua_UserActionIsTargetModeCompat_W(lua_State* L)
{
    bool verbose = true;
    if (!g_logBudgetTargetUnlimited) {
        LONG remaining = InterlockedDecrement(&g_logBudgetTarget);
        verbose = (remaining >= 0);
    }
    if (verbose) {
        WriteRawLog("[Lua] UserActionIsTargetModeCompat() wrapper invoked");
        LogLuaArgs(L, "UserActionIsTargetModeCompat");
    }
    Trace::MarkAction("IsTargetModeCompat");
    static volatile LONG s_dumpCount1 = 0;
    if (verbose && InterlockedIncrement(&s_dumpCount1) <= 6)
        DumpStackTag("IsTargetModeCompat");
    int rc = 0;
    if (g_origUserActionIsTargetModeCompat) {
        __try { rc = g_origUserActionIsTargetModeCompat(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] UserActionIsTargetModeCompat original threw"); }
    }
    if (verbose)
        LogLuaReturns(L, "UserActionIsTargetModeCompat", rc);
    return rc;
}

static int __cdecl Lua_UserActionIsActionTypeTargetModeCompat_W(lua_State* L)
{
    bool verbose = true;
    if (!g_logBudgetActionTypeUnlimited) {
        LONG remaining = InterlockedDecrement(&g_logBudgetActionType);
        verbose = (remaining >= 0);
    }
    if (verbose) {
        WriteRawLog("[Lua] UserActionIsActionTypeTargetModeCompat() wrapper invoked");
        LogLuaArgs(L, "UserActionIsActionTypeTargetModeCompat");
    }
    Trace::MarkAction("IsActionTypeTargetModeCompat");
    static volatile LONG s_dumpCount2 = 0;
    if (verbose && InterlockedIncrement(&s_dumpCount2) <= 6)
        DumpStackTag("IsActionTypeTargetModeCompat");
    int rc = 0;
    if (g_origUserActionIsActionTypeTargetModeCompat) {
        __try { rc = g_origUserActionIsActionTypeTargetModeCompat(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] UserActionIsActionTypeTargetModeCompat original threw"); }
    }
    if (verbose)
        LogLuaReturns(L, "UserActionIsActionTypeTargetModeCompat", rc);
    return rc;
}

static int __cdecl Lua_RequestTargetInfo_W(lua_State* L)
{
    uint32_t tok = CurrentCastToken();
    char intro[128];
    sprintf_s(intro, sizeof(intro), "[Lua] RequestTargetInfo() wrapper invoked tok=%u", tok);
    WriteRawLog(intro);
    Trace::MarkAction("RequestTargetInfo");
    LogLuaArgs(L, "RequestTargetInfo");
    static volatile LONG s_dumpCountRTI = 0;
    if (InterlockedIncrement(&s_dumpCountRTI) <= 4)
        DumpStackTag("RequestTargetInfo");
    int rc = 0;
    if (g_origRequestTargetInfo) {
        __try { rc = g_origRequestTargetInfo(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] RequestTargetInfo original threw"); }
    }
    LogLuaReturns(L, "RequestTargetInfo", rc);
    char detail[128];
    sprintf_s(detail, sizeof(detail), "[Lua] RequestTargetInfo rc=%d tok=%u", rc, tok);
    WriteRawLog(detail);
    return rc;
}

static int __cdecl Lua_ClearCurrentTarget_W(lua_State* L)
{
    uint32_t tok = CurrentCastToken();
    char intro[128];
    sprintf_s(intro, sizeof(intro), "[Lua] ClearCurrentTarget() wrapper invoked tok=%u", tok);
    WriteRawLog(intro);
    Trace::MarkAction("ClearCurrentTarget");
    LogLuaArgs(L, "ClearCurrentTarget");
    static volatile LONG s_dumpCountCCT = 0;
    if (InterlockedIncrement(&s_dumpCountCCT) <= 4)
        DumpStackTag("ClearCurrentTarget");
    int rc = 0;
    if (g_origClearCurrentTarget) {
        __try { rc = g_origClearCurrentTarget(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] ClearCurrentTarget original threw"); }
    }
    LogLuaReturns(L, "ClearCurrentTarget", rc);
    char detail[128];
    sprintf_s(detail, sizeof(detail), "[Lua] ClearCurrentTarget rc=%d tok=%u", rc, tok);
    WriteRawLog(detail);
    return rc;
}
static int CallSavedOriginal(lua_State* L, const char* savedName)
{
    if (!L || !savedName)
        return -1;
    int nargs = lua_gettop(L);
    // Fetch saved original function
    lua_getglobal(L, savedName);
    if (lua_type(L, -1) != LUA_TFUNCTION) {
        lua_pop(L, 1);
        return -1;
    }
    // Move function below the existing arguments and call
    lua_insert(L, 1);
    int status = lua_pcall(L, nargs, LUA_MULTRET, 0);
    if (status != 0) {
        WriteRawLog("CallSavedOriginal: lua_pcall error invoking saved original");
        // On error, Lua left error message on the stack; clear it
        lua_settop(L, 0);
        return 0;
    }
    // Return all results left on the stack
    return lua_gettop(L);
}

static int __cdecl Lua_BindWalk(lua_State* L)
{
    WriteRawLog("Lua_BindWalk requested");
    Engine::Lua::EnsureWalkBinding("Lua.BindWalk");
    return 0;
}

namespace Engine::Lua {

void RegisterOurLuaFunctions()
{
    // Keep hook resolution but avoid registering Lua functions or forcing bindings at boot.
    ResolveRegisterFunction();

    if (Engine::RefreshLuaStateFromSlot()) {
        WriteRawLog("Lua state refreshed from global slot");
    }

    // Perform safe late wrapper install once target APIs exist
    TryInstallActionWrappers();

    WriteRawLog("RegisterOurLuaFunctions no-op (late wrappers only)");
}

void UpdateEngineContext(void* context)
{
    g_engineContext = context;
    if (context) {
        char buf[128];
        sprintf_s(buf, sizeof(buf), "LuaBridge engine context updated: %p", context);
        WriteRawLog(buf);
    } else {
        WriteRawLog("LuaBridge engine context cleared");
    }
    Engine::RequestWalkRegistration();
}

void EnsureWalkBinding(const char* reason)
{
    if (auto L = static_cast<lua_State*>(Engine::LuaState())) {
        ForceWalkBinding(L, reason ? reason : "EnsureWalkBinding");
    }
}

void ScheduleWalkBinding()
{
    InterlockedExchange(&g_pendingRegistration, 1);
}

void NotifySendPacket(unsigned counter, const void* bytes, int len)
{
    HandleCastPacketSend(counter, bytes, len);
}

bool InitLuaBridge()
{
    // Prefer configuration file, fall back to environment variable for compatibility.
    bool enableHook = false;
    if (auto v = Core::Config::TryGetBool("UOWP_ENABLE_LUA_REGISTER_HOOK"))
        enableHook = *v;
    else if (const char* env = std::getenv("UOWP_ENABLE_LUA_REGISTER_HOOK"))
        enableHook = (env[0] == '1' || env[0] == 'y' || env[0] == 'Y' || env[0] == 't' || env[0] == 'T');

    // Trace verbosity (optional): TRACE_LUA_VERBOSE or trace.lua.verbose
    if (auto v = Core::Config::TryGetBool("TRACE_LUA_VERBOSE"))
        g_traceLuaVerbose = *v;
    else if (auto v2 = Core::Config::TryGetBool("trace.lua.verbose"))
        g_traceLuaVerbose = *v2;

    auto applyBudget = [](volatile LONG& budget, bool& unlimited, int value) {
        if (value <= 0) {
            unlimited = true;
            budget = 0;
        } else {
            unlimited = false;
            budget = static_cast<LONG>(value);
        }
    };
    if (auto v = Core::Config::TryGetInt("TRACE_LUA_COMPAT_LIMIT")) {
        applyBudget(g_logBudgetTarget, g_logBudgetTargetUnlimited, *v);
        applyBudget(g_logBudgetActionType, g_logBudgetActionTypeUnlimited, *v);
    }
    if (auto v = Core::Config::TryGetInt("TRACE_LUA_TARGET_COMPAT_LIMIT"))
        applyBudget(g_logBudgetTarget, g_logBudgetTargetUnlimited, *v);
    if (auto v = Core::Config::TryGetInt("TRACE_LUA_ACTIONTYPE_COMPAT_LIMIT"))
        applyBudget(g_logBudgetActionType, g_logBudgetActionTypeUnlimited, *v);
    if (auto v = Core::Config::TryGetInt("CAST_SPELL_CALLEE_LIMIT"))
        applyBudget(g_castSpellCalleeBudget, g_castSpellCalleeUnlimited, *v);
    else if (const char* envCallee = std::getenv("CAST_SPELL_CALLEE_LIMIT"))
        applyBudget(g_castSpellCalleeBudget, g_castSpellCalleeUnlimited, std::atoi(envCallee));
    if (auto v = Core::Config::TryGetInt("CAST_SPELL_GATE_RET_LIMIT"))
        applyBudget(g_gateReturnLogBudget, g_gateReturnLogUnlimited, *v);
    else if (const char* envGateRet = std::getenv("CAST_SPELL_GATE_RET_LIMIT"))
        applyBudget(g_gateReturnLogBudget, g_gateReturnLogUnlimited, std::atoi(envGateRet));
    if (auto v = Core::Config::TryGetInt("CAST_SPELL_GATE_DUMP_LIMIT"))
        applyBudget(g_gateReturnDumpBudget, g_gateReturnDumpUnlimited, *v);
    else if (const char* envGateDump = std::getenv("CAST_SPELL_GATE_DUMP_LIMIT"))
        applyBudget(g_gateReturnDumpBudget, g_gateReturnDumpUnlimited, std::atoi(envGateDump));
    if (auto v = Core::Config::TryGetBool("CAST_SPELL_LOG_CALLEES"))
        g_logCastSpellCallLists = *v;
    else if (const char* envLogCallees = std::getenv("CAST_SPELL_LOG_CALLEES"))
        g_logCastSpellCallLists = (envLogCallees[0] == '1' || envLogCallees[0] == 'y' || envLogCallees[0] == 'Y' || envLogCallees[0] == 't' || envLogCallees[0] == 'T');
    if (auto v = Core::Config::TryGetBool("CAST_SPELL_GATE_PROBES"))
        g_enableCastGateProbes = *v;
    else if (const char* envProbe = std::getenv("CAST_SPELL_GATE_PROBES"))
        g_enableCastGateProbes = (envProbe[0] == '1' || envProbe[0] == 'y' || envProbe[0] == 'Y' || envProbe[0] == 't' || envProbe[0] == 'T');
    if (auto v = Core::Config::TryGetBool("CAST_SPELL_PACKET_TRACKING"))
        g_castPacketTrackingEnabled = *v;
    else if (const char* envPacketTrack = std::getenv("CAST_SPELL_PACKET_TRACKING"))
        g_castPacketTrackingEnabled = (envPacketTrack[0] == '1' || envPacketTrack[0] == 'y' || envPacketTrack[0] == 'Y' || envPacketTrack[0] == 't' || envPacketTrack[0] == 'T');
    auto applyPacketTimeout = [](uint32_t value) -> uint32_t {
        constexpr uint32_t kMinTimeoutMs = 100;
        return (value < kMinTimeoutMs) ? kMinTimeoutMs : value;
    };
    if (auto v = Core::Config::TryGetMilliseconds("CAST_SPELL_PACKET_TIMEOUT_MS")) {
        if (*v == 0)
            g_castPacketTrackingEnabled = false;
        else
            g_castPacketTimeoutMs = applyPacketTimeout(*v);
    } else if (const char* envPacketTimeout = std::getenv("CAST_SPELL_PACKET_TIMEOUT_MS")) {
        uint32_t envValue = static_cast<uint32_t>(std::strtoul(envPacketTimeout, nullptr, 10));
        if (envValue == 0)
            g_castPacketTrackingEnabled = false;
        else
            g_castPacketTimeoutMs = applyPacketTimeout(envValue);
    }
    if (!g_castPacketTrackingEnabled)
        WriteRawLog("InitLuaBridge: CastSpell packet tracking disabled");
    int gateIndex = 0;
    if (auto v = Core::Config::TryGetInt("CAST_SPELL_GATE_TARGET_INDEX"))
        gateIndex = *v;
    else if (const char* envGate = std::getenv("CAST_SPELL_GATE_TARGET_INDEX"))
        gateIndex = std::atoi(envGate);
    if (gateIndex < 0 || static_cast<size_t>(gateIndex) >= kGateTargetCount) {
        char warn[160];
        sprintf_s(warn, sizeof(warn),
            "InitLuaBridge: CAST_SPELL_GATE_TARGET_INDEX=%d out of range (0-%zu); defaulting to 0",
            gateIndex, kGateTargetCount ? (kGateTargetCount - 1) : 0);
        WriteRawLog(warn);
        gateIndex = 0;
    }
    std::optional<std::string> gateOverrideText;
    if (auto cfgOverride = Core::Config::TryGetValue("CAST_SPELL_GATE_TARGET_ADDR"))
        gateOverrideText = *cfgOverride;
    else if (const char* envGateAddr = std::getenv("CAST_SPELL_GATE_TARGET_ADDR"))
        gateOverrideText = std::string(envGateAddr);

    std::optional<uintptr_t> gateOverrideAddr;
    if (gateOverrideText && !gateOverrideText->empty()) {
        if (auto parsed = ParseConfigAddress(*gateOverrideText))
            gateOverrideAddr = parsed;
        else {
            char warn[256];
            sprintf_s(warn, sizeof(warn),
                "InitLuaBridge: could not parse CAST_SPELL_GATE_TARGET_ADDR=\"%s\"",
                gateOverrideText->c_str());
            WriteRawLog(warn);
        }
    }

    g_gateSelectedTarget = kGateTargets[gateIndex];
    g_gateSelectedName = kGateTargetNames[gateIndex];
    bool gateOverrideActive = false;
    if (gateOverrideAddr) {
        g_gateSelectedTarget = *gateOverrideAddr;
        sprintf_s(g_gateOverrideName, sizeof(g_gateOverrideName), "%p", reinterpret_cast<void*>(*gateOverrideAddr));
        g_gateSelectedName = g_gateOverrideName;
        gateOverrideActive = true;
    }
    if (g_enableCastGateProbes) {
        char cfgMsg[192];
        sprintf_s(cfgMsg, sizeof(cfgMsg),
            "InitLuaBridge: cast gate probes enabled target=%s (index=%d override=%s)",
            g_gateSelectedName ? g_gateSelectedName : "unknown",
            gateIndex,
            gateOverrideActive ? "yes" : "no");
        WriteRawLog(cfgMsg);
    }
    if (!g_enableCastGateProbes)
        WriteRawLog("InitLuaBridge: cast gate probes disabled via config/env");

    if (enableHook) {
        WriteRawLog("InitLuaBridge: enabling RegisterLuaFunction hook (cfg/env)");
        ResolveRegisterFunction();
    } else {
        WriteRawLog("InitLuaBridge: RegisterLuaFunction hook disabled (set UOWP_ENABLE_LUA_REGISTER_HOOK=1 in uowalkpatch.cfg)");
    }
    // Also try direct signature-based hooks for action functions (works even if client registered them before our hook)
    TryInstallDirectActionHooks();
    Engine::RequestWalkRegistration();
    return true;
}

// Lightweight polling entry-point to retry late installs from a game-thread context
void PollLateInstalls()
{
    static DWORD s_lastTryTick = 0;
    DWORD now = GetTickCount();
    if (now - s_lastTryTick < 500)
        return;
    s_lastTryTick = now;
    // Optionally enable the RegisterLuaFunction hook late (via cfg/env)
    if (!g_registerResolved) {
        bool late = false;
        if (auto v = Core::Config::TryGetBool("UOWP_ENABLE_LUA_REGISTER_HOOK_LATE"))
            late = *v;
        else if (const char* lateEnv = std::getenv("UOWP_ENABLE_LUA_REGISTER_HOOK_LATE"))
            late = (lateEnv[0] == '1' || lateEnv[0] == 'y' || lateEnv[0] == 'Y' || lateEnv[0] == 't' || lateEnv[0] == 'T');
        if (late) {
            ResolveRegisterFunction();
        }
    }
    TryInstallActionWrappers();
    TryInstallDirectActionHooks();
}

void ShutdownLuaBridge()
{
    if (g_registerTarget) {
        MH_DisableHook(g_registerTarget);
        MH_RemoveHook(g_registerTarget);
    }
    g_origRegister = nullptr;
    g_clientRegister = nullptr;
    g_registerResolved = false;
    g_registerTarget = nullptr;
    g_clientContext = nullptr;
}

} // namespace Engine::Lua
