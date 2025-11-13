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
#include <cmath>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <optional>
#include <functional>

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
#include "TargetCorrelator.h"

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
    LUA_API void lua_pushinteger(lua_State* L, lua_Integer n);
    LUA_API void lua_createtable(lua_State* L, int narr, int nrec);
    LUA_API int lua_iscfunction(lua_State* L, int idx);
    LUA_API void lua_pushlightuserdata(lua_State* L, void* p);
    LUA_API void* lua_touserdata(lua_State* L, int idx);
    LUA_API int luaL_ref(lua_State* L, int t);
    LUA_API void luaL_unref(lua_State* L, int t, int ref);
}
#ifndef LUA_NOREF
#define LUA_NOREF (-2)
#endif
#ifndef LUA_REFNIL
#define LUA_REFNIL (-1)
#endif
#ifndef LUA_MULTRET
#define LUA_MULTRET (-1)
#endif

#ifndef LUA_REGISTRYINDEX
#define LUA_REGISTRYINDEX (-10000)
#endif


namespace {
    using ClientRegisterFn = int(__stdcall*)(void*, void*, const char*);
    using LuaFn = int(__cdecl*)(lua_State*);
    using UserActionCastSpell_t = int(__cdecl*)(lua_State*);
    using UserActionCastSpellOnId_t = int(__cdecl*)(lua_State*);

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
    static UserActionCastSpell_t g_origCastSpell = nullptr;
    static UserActionCastSpellOnId_t g_origCastSpellOnId = nullptr;
    static bool g_allowDirectCastFallback = false;
    static bool g_castSpellOrigLogged = false;
    static bool g_castSpellOnIdOrigLogged = false;
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
    static LuaFn g_origHandleSingleLeftClkTarget = nullptr;
    static LuaFn g_origUserActionSpeechSetText = nullptr;
    static LuaFn g_origTextLogAddEntry = nullptr;
    static LuaFn g_origPrintWStringToChatWindow = nullptr;
    static LuaFn g_origPrintTidToChatWindow = nullptr;
    static LuaFn g_origTextLogAddSingleByteEntry = nullptr;

    static volatile LONG g_directActionHooksInstalled = 0;
    static bool g_traceTargetPath = false;

    static bool g_directHookConfigLoaded = false;
    static bool g_directHookEnableCastSpell = true;
    static bool g_directHookEnableCastSpellOnId = true;
    static bool g_directHookEnableUseSkill = true;
    static bool g_directHookEnableUseWeaponAbility = true;
    static bool g_directHookEnableRequestTargetInfo = true;
    static bool g_directHookEnableHsShowCursor = true;
    static bool g_directHookEnableHsHideCursor = true;
    static bool g_safeCastingMode = false;
    static bool g_debugWords = false;
    static std::atomic<uint32_t> g_wordsPendingToken{0};
    static std::atomic<uint32_t> g_wordsLoggedToken{0};
    static std::atomic<bool> g_replayHelperInstalled{false};
    static std::atomic<uint32_t> g_targetCompatLastArmToken{0};
    static bool g_warnNativeCastOnId = false;
    static bool g_warnNativeRequestTarget = false;
    static bool g_warnNativeHsCursor = false;
    static bool g_enableTapTargetWrap = false;
    static bool g_clickTapStateLogged = false;
    static std::atomic<bool> g_clickTapWrapInstalled{false};
    static DWORD g_clickTapNextMissingLog = 0;
    static int g_castSpellRegistryRef = LUA_NOREF;
    static int g_castSpellOnIdRegistryRef = LUA_NOREF;
    static const void* const kCastWrapperSentinel = reinterpret_cast<void*>(static_cast<intptr_t>(0xC457C0DE));

    static volatile LONG g_targetCompatBannerLogged = 0;
    static volatile LONG g_actionTypeCompatBannerLogged = 0;
    static volatile LONG g_castSpellReturnBannerLogged = 0;
    static volatile LONG g_castSpellOnIdReturnBannerLogged = 0;
    static volatile LONG g_requestTargetReturnBannerLogged = 0;
    static volatile LONG g_hsShowReturnBannerLogged = 0;
    static volatile LONG g_hsHideReturnBannerLogged = 0;

    static DWORD g_actionWrapperNextLogTick = 0;
    static bool g_actionWrapperReadyLogged = false;
    static volatile LONG g_actionWrapperInstallPending = 0;
    enum ActionWrapperBits : uint32_t {
        kWrapperCastSpell = 1u << 0,
        kWrapperCastSpellOnId = 1u << 1,
        kWrapperUseSkill = 1u << 2,
        kWrapperUsePrimaryAbility = 1u << 3,
        kWrapperUseWeaponAbility = 1u << 4,
        kWrapperTargetCompat = 1u << 5,
        kWrapperActionTypeCompat = 1u << 6,
        kWrapperRequestTargetInfo = 1u << 7,
        kWrapperClearCurrentTarget = 1u << 8,
        kWrapperSkillAvailable = 1u << 9,
        kWrapperHsShowCursor = 1u << 10,
        kWrapperHsHideCursor = 1u << 11,
        kWrapperHandleLeftClick = 1u << 12,
        kWrapperSpeechSetText = 1u << 13,
        kWrapperTextLogAddEntry = 1u << 14,
        kWrapperPrintWString = 1u << 15,
        kWrapperPrintTid = 1u << 16,
        kWrapperTextLogAddSingleByte = 1u << 17
    };
    static constexpr uint32_t kAllActionWrappers =
        kWrapperCastSpell | kWrapperCastSpellOnId | kWrapperUseSkill | kWrapperUsePrimaryAbility |
        kWrapperUseWeaponAbility | kWrapperTargetCompat | kWrapperActionTypeCompat | kWrapperRequestTargetInfo |
        kWrapperClearCurrentTarget | kWrapperSkillAvailable | kWrapperHsShowCursor | kWrapperHsHideCursor |
        kWrapperHandleLeftClick | kWrapperSpeechSetText | kWrapperTextLogAddEntry |
        kWrapperPrintWString | kWrapperPrintTid | kWrapperTextLogAddSingleByte;
    static constexpr uint32_t kWordWrapperMask =
        kWrapperSpeechSetText | kWrapperTextLogAddEntry | kWrapperPrintWString |
        kWrapperPrintTid | kWrapperTextLogAddSingleByte;
    static std::atomic<uint32_t> g_actionWrapperMask{0};

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

    static constexpr size_t kGateInvokeDefaultReserve = 32;
    static constexpr size_t kGateInvokeMaxDepth = 256;
    static thread_local std::vector<GateInvokeTls> g_gateInvokeStack;
    static thread_local bool g_gateInvokeOverflowLogged = false;

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
    static std::atomic<uint32_t> g_gatePendingToken{0};
    static std::atomic<int> g_gatePendingSpell{0};

    struct SpellGateReplayContext {
        GateCallProbe* probe = nullptr;
        uintptr_t ecx = 0;
        uintptr_t edx = 0;
        uintptr_t args[4]{};
        DWORD captureTick = 0;
        uint32_t token = 0;
        uintptr_t lastRet = 0;
    };

static std::mutex g_spellReplayMutex;
static std::unordered_map<int, SpellGateReplayContext> g_spellReplayCache;
static std::atomic<bool> g_spellBindingReady{false};
static bool HasAnyGateReplayContext()
{
    std::lock_guard<std::mutex> lock(g_spellReplayMutex);
    return !g_spellReplayCache.empty();
}

static bool HasGateReplayContext(int spellId)
{
    std::lock_guard<std::mutex> lock(g_spellReplayMutex);
    return g_spellReplayCache.find(spellId) != g_spellReplayCache.end();
}

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
    static char g_gateResolvedName[32] = {};

    static uintptr_t g_gateSelectedTarget = kGateTargets[0];
    static const char* g_gateSelectedName = kGateTargetNames[0];
    static char g_gateOverrideName[32] = {};

    enum class TargetCommitKind : std::uint8_t {
        Object,
        Ground,
        Self,
        Cancel,
    };

    struct NoClickCastState {
        bool active = false;
        bool busyLogged = false;
        bool openLogged = false;
        int spellId = 0;
        DWORD startTick = 0;
        TargetCommitKind openKind = TargetCommitKind::Object;
        uint8_t firstSendId = 0;
        bool sendLogged = false;
        DWORD powerWordsDeadline = 0;
        bool powerWordsLogged = false;
        bool powerWordsObserved = false;
        int powerWordsTid = 0;
        bool targetRequestObserved = false;
        DWORD targetRequestTick = 0;
    };

    static NoClickCastState g_noClickState{};
    static bool g_noClickDiagnostics = false;
    static bool g_consoleBound = false;
    static constexpr DWORD kTargetFallbackWindowMs = 1200;
    static constexpr DWORD kTargetFallbackSendWaitMs = 100;
    struct TargetRequestTuple {
        int action = 1;
        int sub = 1;
        int extra = 0;
        bool learned = false;
    };
    static TargetRequestTuple g_targetRequestTuple{1, 1, 0, false};
}

static void NoteNoClickSendPacket(uint8_t id, int len, unsigned counter);
static void MaybeLogPowerWordsTimeout(const char* stage);
static void NotePowerWordsTid(int tid);
static bool IsTargetCursorActive();
static void ResetNoClickState(const char* reason);
static bool EnsureNoClickActive(const char* action);
static bool EnsureWithinTargetWindow(const char* action);
static void LogTargetOpen(TargetCommitKind kind);
static uint32_t ResolveTargetWindowMs();
static bool MapSpellIdForClient(int spellId, int& mappedId);
static void LogCastPath(const char* path, uint32_t tok, const char* status, const char* reason = nullptr);
static bool ActivateManualCastToken(uint32_t& previousTok, const char* reason);
static void RestoreManualCastToken(uint32_t previousTok, bool manualAssigned);
static void LogSpellCastFailure(const char* branch, const char* reason, int spellId, uint32_t tok);
static void LogImmediateSpellFailure(int spellId, const char* branch, const char* reason);
static void ReportActiveSpellFailure(const char* branch, const char* reason);
static bool CastWrapperReady();
static bool CastOnIdWrapperReady();
static bool InstallUOFlowConsoleBindingsIfNeeded(void* ownerCtx, const char* reason = nullptr);
static void ForceLateCastWrapInstall(lua_State* L, const char* reason);
static void LogUOFlowStatus(const char* tag);
static bool OpenTargetForSpell_Fallback(const char* reason);
static void MaybeCaptureSpellTargetTuple(lua_State* L);
static bool TargetFallbackReady();
static void LogTargetFallbackError(const char* reason);
static bool WaitForSendLogged(DWORD timeoutMs);
static void MarkTargetRequestObserved();

static int __stdcall Hook_Register(void* ctx, void* func, const char* name);
static int __cdecl Lua_Walk(lua_State* L);
static int __cdecl Lua_BindWalk(lua_State* L);
static int __cdecl Lua_UOW_Spell_Cast(lua_State* L);
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
static int __cdecl Lua_HandleSingleLeftClkTarget_W(lua_State* L);
static int __cdecl Lua_UserActionSpeechSetText_W(lua_State* L);
static int __cdecl Lua_TextLogAddEntry_W(lua_State* L);
static int __cdecl Lua_PrintWStringToChatWindow_W(lua_State* L);
static int __cdecl Lua_PrintTidToChatWindow_W(lua_State* L);
static int __cdecl Lua_TextLogAddSingleByteEntry_W(lua_State* L);
static int __cdecl Lua_uow_cast_spell_and_target(lua_State* L);
static int __cdecl Lua_UOFlow_Spell_cast(lua_State* L);
static int __cdecl Lua_UOFlow_Spell_cast_on_id(lua_State* L);
static int __cdecl Lua_UOFlow_Target_commit_obj(lua_State* L);
static int __cdecl Lua_UOFlow_Target_commit_ground(lua_State* L);
static int __cdecl Lua_UOFlow_Target_cancel(lua_State* L);
static int __cdecl Lua_UOFlow_Target_force_open(lua_State* L);
static int __cdecl Lua_UOFlow_bootstrap(lua_State* L);
static int __cdecl Lua_UOFlow_status(lua_State* L);

struct LateWrapTarget {
    const char* name;
    lua_CFunction wrapper;
    uint32_t bit;
    bool installed;
    DWORD nextDeferredLog;
    const char* lastGuardReason;
    bool guardLogged;
};

static constexpr DWORD kLateWrapIntervalMs = 500;
static constexpr DWORD kLateWrapWindowMs = 10000;
static LateWrapTarget g_lateCastTargets[] = {
    {"UserActionCastSpell", &Lua_UserActionCastSpell_W, kWrapperCastSpell, false, 0, nullptr, false},
    {"UserActionCastSpellOnId", &Lua_UserActionCastSpellOnId_W, kWrapperCastSpellOnId, false, 0, nullptr, false}
};
static std::mutex g_lateWrapMutex;
static bool g_lateWrapActive = false;
static DWORD g_lateWrapStartTick = 0;
static DWORD g_lateWrapNextTick = 0;
static std::atomic<bool> g_lateWrapGuardDisabled{false};
static constexpr const char* kLateWrapGuardDisabledReason = "disabled_exception";


// Forward declarations for logging helpers
static void LogLuaArgs(lua_State* L, const char* func, int maxArgs = 3);
static void LogLuaReturns(lua_State* L, const char* func, int nret);
static void LogLuaErrorTop(lua_State* L, const char* context, int maxSlots = 6);
static void LogLuaClosureUpvalues(lua_State* L, int funcIndex, const char* context, int maxUpvalues = 4);
static void LogSavedOriginalUpvalues(lua_State* L, const char* savedName, const char* globalName, const char* context, volatile LONG* gate, int maxUpvalues = 4);
static void LogLuaTopTypes(lua_State* L, const char* context, int maxSlots = 6);
static bool SaveAndReplace(lua_State* L, const char* name, lua_CFunction wrapper);
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
static void* ResolveGateJumpTarget(void* target, int& depthOut);
static void GateInvokeShared();
static void GateResetInvokeStack();
static GateInvokeTls* GatePushInvokeFrame(GateCallProbe* probe);
static bool GatePopInvokeFrame(GateCallProbe* probe, GateInvokeTls& outSnap);
static void GateRecordEvent(GateCallProbe* probe, uintptr_t retValue, const GateInvokeTls* snap);
static void GateFlushEvents(const char* reason);
static void RequestLateCastWrapLoop(const char* reason);
static void ProcessLateCastWrapLoop(lua_State* L);
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
static void LogGateHelperSelected(GateCallProbe* probe, const GateInvokeTls* snap, uintptr_t retValue);
static void MaybeLearnSpellGateContext(GateCallProbe* probe, const GateInvokeTls& snap, uintptr_t retValue);
static bool SpellContextsEqual(const SpellGateReplayContext& a, const SpellGateReplayContext& b);
static bool InvokeSpellGateDirect(const SpellGateReplayContext& ctx);
static void ForceSpellBinding(lua_State* L, const char* reason);

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

static bool IsRegistryWrapper(lua_State* L, const char* name)
{
    if (!L || !name)
        return false;
    int top = lua_gettop(L);
    lua_getglobal(L, name);
    bool wrapped = false;
    if (lua_iscfunction(L, -1)) {
        if (lua_getupvalue(L, -1, 2) != nullptr) {
            const void* marker = lua_touserdata(L, -1);
            wrapped = (marker == kCastWrapperSentinel);
            lua_pop(L, 1);
        }
    }
    lua_settop(L, top);
    return wrapped;
}

    static bool InstallRegistryWrapper(lua_State* L,
                                       const char* name,
                                       lua_CFunction wrapper,
                                       int& registryRef)
{
    if (!L || !name || !wrapper)
        return false;
    if (IsRegistryWrapper(L, name))
        return true;
    int top = lua_gettop(L);
    lua_getglobal(L, name);
    if (lua_type(L, -1) != LUA_TFUNCTION) {
        lua_settop(L, top);
        return false;
    }
    std::string saved = std::string(name) + "__orig";
    lua_pushvalue(L, -1);
    lua_setfield(L, LUA_GLOBALSINDEX, saved.c_str());
    if (registryRef != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, registryRef);
        registryRef = LUA_NOREF;
    }
    registryRef = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_pushlightuserdata(L, reinterpret_cast<void*>(static_cast<intptr_t>(registryRef)));
    lua_pushlightuserdata(L, const_cast<void*>(kCastWrapperSentinel));
    lua_pushcclosure(L, wrapper, 2);
    lua_setglobal(L, name);
    lua_settop(L, top);
    char buf[192];
    sprintf_s(buf, sizeof(buf), "Wrap %s: saved original via registry ref=%d", name, registryRef);
    WriteRawLog(buf);
    if (_stricmp(name, "HandleSingleLeftClkTarget") == 0) {
        bool first = !g_clickTapWrapInstalled.exchange(true, std::memory_order_release);
        if (first) {
            char clickBuf[160];
            sprintf_s(clickBuf,
                      sizeof(clickBuf),
                      "[ClickTap] HandleSingleLeftClkTarget wrapper installed (ref=%d)",
                      registryRef);
            WriteRawLog(clickBuf);
        }
    }
    return true;
}

static int CallRegistryOriginal(lua_State* L, const char* name, int registryRef)
{
    if (!L || registryRef == LUA_NOREF)
        return -1;
    int nargs = lua_gettop(L);
    lua_rawgeti(L, LUA_REGISTRYINDEX, registryRef);
    if (lua_type(L, -1) != LUA_TFUNCTION) {
        lua_pop(L, 1);
        return -1;
    }
    lua_insert(L, 1);
    int status = lua_pcall(L, nargs, LUA_MULTRET, 0);
    if (status != 0) {
        const char* err = lua_tolstring(L, -1, nullptr);
        char buf[256];
        sprintf_s(buf,
                  sizeof(buf),
                  "[Wrap] %s registry call error: %s",
                  name ? name : "<fn>",
                  err ? err : "<nil>");
        WriteRawLog(buf);
        lua_settop(L, 0);
        return -1;
    }
    int nret = lua_gettop(L);
    char buf[192];
    sprintf_s(buf,
              sizeof(buf),
              "[Wrap] %s forwarded returns=%d",
              name ? name : "<fn>",
              nret);
    WriteRawLog(buf);
    return nret;
}

static bool RefreshLateCastTargetsLocked(uint32_t mask, bool resetLogs)
{
    bool pending = false;
    for (auto& target : g_lateCastTargets) {
        target.installed = ((mask & target.bit) != 0);
        if (!target.installed)
            pending = true;
        if (resetLogs) {
            target.nextDeferredLog = 0;
            target.guardLogged = false;
            target.lastGuardReason = nullptr;
        } else if (target.installed) {
            target.guardLogged = false;
            target.lastGuardReason = nullptr;
        }
    }
    return pending;
}

static const char* EvaluateCastWrapGuard(const LateWrapTarget& target)
{
    if (!g_consoleBound)
        return "console_unbound";
    if (!CanonicalOwnerContext())
        return "owner_unset";
    if (_stricmp(target.name, "UserActionCastSpell") == 0) {
        if (!g_origCastSpell)
            return "unresolved";
    } else if (_stricmp(target.name, "UserActionCastSpellOnId") == 0) {
        if (!g_origCastSpellOnId)
            return "unresolved";
    }
    return nullptr;
}

static bool WrapLuaGlobal(lua_State* L, LateWrapTarget& target, DWORD now)
{
    if (g_lateWrapGuardDisabled.load(std::memory_order_acquire)) {
        if (!target.guardLogged || target.lastGuardReason != kLateWrapGuardDisabledReason) {
            char buf[192];
            sprintf_s(buf,
                      sizeof(buf),
                      "Wrap %s: guard disabled (exception_once)",
                      target.name);
            WriteRawLog(buf);
            target.guardLogged = true;
            target.lastGuardReason = kLateWrapGuardDisabledReason;
        }
        return false;
    }
    const char* guardReason = EvaluateCastWrapGuard(target);
    if (guardReason) {
        if (!target.guardLogged || target.lastGuardReason != guardReason) {
            char buf[192];
            sprintf_s(buf,
                      sizeof(buf),
                      "Wrap %s: guard tripped (%s)",
                      target.name,
                      guardReason);
            WriteRawLog(buf);
            target.guardLogged = true;
            target.lastGuardReason = guardReason;
        }
        return false;
    }
    target.guardLogged = false;
    target.lastGuardReason = nullptr;

    bool wrapped = false;
    __try {
        wrapped = SaveAndReplace(L, target.name, target.wrapper);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        (void)code;
        bool alreadyDisabled = g_lateWrapGuardDisabled.exchange(true, std::memory_order_acq_rel);
        if (!alreadyDisabled || target.lastGuardReason != kLateWrapGuardDisabledReason) {
            char buf[256];
            sprintf_s(buf,
                      sizeof(buf),
                      "Wrap %s: guard disabled (exception_once)",
                      target.name);
            WriteRawLog(buf);
        }
        target.nextDeferredLog = now + 1000;
        target.guardLogged = true;
        target.lastGuardReason = kLateWrapGuardDisabledReason;
        g_lateWrapActive = false;
        return false;
    }

    if (wrapped) {
        char msg[192];
        sprintf_s(msg, sizeof(msg), "Wrap %s: installed via late wrap", target.name);
        WriteRawLog(msg);
        char hookMsg[192];
        sprintf_s(hookMsg, sizeof(hookMsg), "Hook_Register: wrapped %s (late)", target.name);
        WriteRawLog(hookMsg);
        target.installed = true;
        target.nextDeferredLog = 0;
        target.guardLogged = false;
        target.lastGuardReason = nullptr;
        return true;
    }

    if (now >= target.nextDeferredLog) {
        char buf[192];
        sprintf_s(buf, sizeof(buf), "Wrap %s: deferred (global missing)", target.name);
        WriteRawLog(buf);
        target.nextDeferredLog = now + 1000;
    }
    return false;
}

static void RequestLateCastWrapLoop(const char* reason)
{
    DWORD now = GetTickCount();
    std::lock_guard<std::mutex> lock(g_lateWrapMutex);
    uint32_t mask = g_actionWrapperMask.load(std::memory_order_acquire);
    bool restart = !g_lateWrapActive || (now - g_lateWrapStartTick) >= kLateWrapWindowMs;
    bool pending = RefreshLateCastTargetsLocked(mask, restart);
    if (!pending) {
        g_lateWrapActive = false;
        return;
    }

    g_lateWrapActive = true;
    if (restart)
        g_lateWrapStartTick = now;
    g_lateWrapNextTick = 0;
    if (restart) {
        char buf[192];
        sprintf_s(buf,
                  sizeof(buf),
                  "LateWrap: scheduled cast wrapper scan (%s)",
                  reason && *reason ? reason : "unspecified");
        WriteRawLog(buf);
    }
}

static void ProcessLateCastWrapLoop(lua_State* L)
{
    if (!L)
        return;
    std::lock_guard<std::mutex> lock(g_lateWrapMutex);
    if (!g_lateWrapActive)
        return;

    DWORD now = GetTickCount();
    if (g_lateWrapNextTick && now < g_lateWrapNextTick)
        return;

    uint32_t mask = g_actionWrapperMask.load(std::memory_order_acquire);
    RefreshLateCastTargetsLocked(mask, false);

    for (auto& target : g_lateCastTargets) {
        if (target.installed)
            continue;
        if (!WrapLuaGlobal(L, target, now))
            continue;
        uint32_t expected = mask;
        while (true) {
            uint32_t desired = expected | target.bit;
            if (g_actionWrapperMask.compare_exchange_weak(expected,
                                                          desired,
                                                          std::memory_order_acq_rel,
                                                          std::memory_order_acquire)) {
                mask = desired;
                if (desired == kAllActionWrappers)
                    InterlockedExchange(&g_actionWrappersInstalled, 1);
                break;
            }
        }
    }

    bool pendingLeft = false;
    for (const auto& target : g_lateCastTargets) {
        if (!target.installed) {
            pendingLeft = true;
            break;
        }
    }

    if (!pendingLeft) {
        g_lateWrapActive = false;
        WriteRawLog("LateWrap: cast wrapper loop complete");
        return;
    }

    if (now - g_lateWrapStartTick >= kLateWrapWindowMs) {
        g_lateWrapActive = false;
        WriteRawLog("LateWrap: cast wrapper window expired");
        return;
    }

    g_lateWrapNextTick = now + kLateWrapIntervalMs;
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
        Util::OwnerPump::SetOwnerThreadId(currentTid);
        char buf[160];
        sprintf_s(buf, sizeof(buf), "OwnerPump owner thread set: %u (ctx=%p)", currentTid, ctx);
        WriteRawLog(buf);
        InstallUOFlowConsoleBindingsIfNeeded(ctx, "owner_context");
        if (auto* L = static_cast<lua_State*>(Engine::LuaState())) {
            ForceLateCastWrapInstall(L, "owner_context");
        }
    }

    Engine::Lua::ScheduleCastWrapRetry("owner context");
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

static std::optional<bool> ReadBoolOption(const char* cfgKey, const char* envKey)
{
    if (cfgKey) {
        if (auto cfg = Core::Config::TryGetBool(cfgKey))
            return cfg;
    }
    if (envKey) {
        if (auto env = Core::Config::TryGetEnvBool(envKey))
            return env;
    }
    return std::nullopt;
}

static bool ReadHookToggle(const char* cfgKey, const char* envKey, bool defaultValue)
{
    if (auto opt = ReadBoolOption(cfgKey, envKey))
        return *opt;
    return defaultValue;
}

static bool ReadHookToggleWithFallback(const char* primaryCfg,
                                       const char* primaryEnv,
                                       const char* legacyCfg,
                                       const char* legacyEnv,
                                       bool defaultValue)
{
    if (auto opt = ReadBoolOption(primaryCfg, primaryEnv))
        return *opt;
    if (auto legacy = ReadBoolOption(legacyCfg, legacyEnv))
        return *legacy;
    return defaultValue;
}

static void LoadDirectHookPreferences()
{
    if (g_directHookConfigLoaded)
        return;
    g_directHookEnableCastSpell = ReadHookToggle("HOOK_ENABLE_USERACTION_CAST_SPELL", "HOOK_ENABLE_USERACTION_CAST_SPELL", true);
    g_directHookEnableCastSpellOnId = ReadHookToggleWithFallback(
        "HOOK_ENABLE_CPP_CAST_ON_ID",
        "HOOK_ENABLE_CPP_CAST_ON_ID",
        "HOOK_ENABLE_USERACTION_CAST_SPELL_ON_ID",
        "HOOK_ENABLE_USERACTION_CAST_SPELL_ON_ID",
        false);
    g_directHookEnableUseSkill = ReadHookToggle("HOOK_ENABLE_USERACTION_USE_SKILL", "HOOK_ENABLE_USERACTION_USE_SKILL", true);
    g_directHookEnableUseWeaponAbility = ReadHookToggle("HOOK_ENABLE_USERACTION_USE_WEAPON_ABILITY", "HOOK_ENABLE_USERACTION_USE_WEAPON_ABILITY", true);
    g_directHookEnableRequestTargetInfo = ReadHookToggleWithFallback(
        "HOOK_ENABLE_CPP_REQUEST_TARGET_INFO",
        "HOOK_ENABLE_CPP_REQUEST_TARGET_INFO",
        "HOOK_ENABLE_REQUEST_TARGET_INFO",
        "HOOK_ENABLE_REQUEST_TARGET_INFO",
        false);
    bool cursorHook = ReadHookToggleWithFallback(
        "HOOK_ENABLE_CPP_HS_CURSOR",
        "HOOK_ENABLE_CPP_HS_CURSOR",
        "HOOK_ENABLE_HS_SHOW_TARGETING_CURSOR",
        "HOOK_ENABLE_HS_SHOW_TARGETING_CURSOR",
        false);
    g_directHookEnableHsShowCursor = cursorHook;
    g_directHookEnableHsHideCursor = cursorHook;

    // Directly detouring UserActionCastSpell interferes with the spellbook flow because the game
    // bypasses the Lua trampoline until targeting APIs are live. We now rely solely on the Lua-level
    // wrapper for this action and force the direct hook off even if requested in the config/env.
    if (g_directHookEnableCastSpell) {
        g_directHookEnableCastSpell = false;
        WriteRawLog("DirectHook: UserActionCastSpell forced disabled (spellbook cast path must run via Lua wrapper)");
    }

    if (g_safeCastingMode) {
        g_directHookEnableCastSpellOnId = false;
        g_directHookEnableRequestTargetInfo = false;
        g_directHookEnableHsShowCursor = false;
        g_directHookEnableHsHideCursor = false;
        WriteRawLog("SafeCasting: native target-path hooks disabled");
    }

    auto warnNative = [](const char* name, bool enabled, bool& warnedFlag) {
        if (enabled && !warnedFlag) {
            warnedFlag = true;
            char buf[192];
            sprintf_s(buf, sizeof(buf), "[WARN] Native %s hook enabled (dev only). Proceeding in pass-through.", name);
            WriteRawLog(buf);
        }
    };
    warnNative("UserActionCastSpellOnId", g_directHookEnableCastSpellOnId, g_warnNativeCastOnId);
    warnNative("RequestTargetInfo", g_directHookEnableRequestTargetInfo, g_warnNativeRequestTarget);
    warnNative("HS_TargetingCursor", g_directHookEnableHsShowCursor || g_directHookEnableHsHideCursor, g_warnNativeHsCursor);

    g_directHookConfigLoaded = true;
}

static bool EvaluateHasReceivedServerFeatures(lua_State* L, bool& outReady)
{
    outReady = false;
    if (!L)
        return false;
    int top = lua_gettop(L);
    lua_getglobal(L, "HasReceivedServerFeatures");
    int type = lua_type(L, -1);
    if (type != LUA_TFUNCTION) {
        lua_settop(L, top);
        return false;
    }
    if (lua_pcall(L, 0, 1, 0) != 0) {
        LogLuaErrorTop(L, "HasReceivedServerFeatures", 6);
        lua_settop(L, top);
        return false;
    }
    outReady = lua_toboolean(L, -1) != 0;
    lua_settop(L, top);
    return true;
}

static bool ActionWrappersReady(lua_State* L)
{
    if (!L)
        return false;
    DWORD now = GetTickCount();
    bool featuresReady = false;
    if (!EvaluateHasReceivedServerFeatures(L, featuresReady) || !featuresReady) {
        if (now >= g_actionWrapperNextLogTick) {
            WriteRawLog("TryInstallActionWrappers: waiting for HasReceivedServerFeatures()");
            g_actionWrapperNextLogTick = now + 2000;
        }
        return false;
    }
    if (!g_actionWrapperReadyLogged) {
        WriteRawLog("TryInstallActionWrappers: feature gate ready; installing wrappers");
        g_actionWrapperReadyLogged = true;
    }
    return true;
}

static void LogCompatReturnBanner(lua_State* L, const char* name, int results)
{
    if (!L || !name)
        return;
    char buf[256];
    if (results <= 0) {
        sprintf_s(buf, sizeof(buf), "[Lua] %s returned no values", name);
        WriteRawLog(buf);
        return;
    }
    int idx = lua_gettop(L);
    int type = lua_type(L, idx);
    const char* tn = lua_typename(L, type);
    switch (type) {
    case LUA_TNUMBER:
    {
        int value = lua_tointeger(L, idx);
        sprintf_s(buf, sizeof(buf), "[Lua] %s return type=%s value=%d", name, tn ? tn : "number", value);
        break;
    }
    case LUA_TBOOLEAN:
    {
        int value = lua_toboolean(L, idx);
        sprintf_s(buf, sizeof(buf), "[Lua] %s return type=%s value=%s", name, tn ? tn : "boolean", value ? "true" : "false");
        break;
    }
    case LUA_TNIL:
        sprintf_s(buf, sizeof(buf), "[Lua] %s return type=nil", name);
        break;
    default:
        sprintf_s(buf, sizeof(buf), "[Lua] %s return type=%s", name, tn ? tn : "?");
        break;
    }
    WriteRawLog(buf);
}

struct LuaReturnInfo {
    int type = LUA_TNONE;
    double numberValue = 0.0;
    bool boolValue = false;
    bool hasValue = false;
};

static LuaReturnInfo CaptureLuaReturn(lua_State* L, int resultCount)
{
    LuaReturnInfo info;
    if (!L || resultCount <= 0)
        return info;
    int idx = lua_gettop(L) - resultCount + 1;
    if (idx < 1)
        idx = 1;
    info.type = lua_type(L, idx);
    info.hasValue = true;
    switch (info.type) {
    case LUA_TBOOLEAN:
        info.boolValue = (lua_toboolean(L, idx) != 0);
        break;
    case LUA_TNUMBER:
        info.numberValue = lua_tonumber(L, idx);
        break;
    case LUA_TNIL:
        break;
    default:
        break;
    }
    return info;
}

static void FormatLuaNumber(double value, char* out, size_t len)
{
    if (!out || len == 0)
        return;
    double rounded = std::round(value);
    if (std::fabs(value - rounded) < 0.0001)
        sprintf_s(out, len, "%.0f", rounded);
    else
        sprintf_s(out, len, "%.3f", value);
}

static void DescribeLuaReturn(lua_State* L, const LuaReturnInfo& info, char* typeBuf, size_t typeLen, char* valueBuf, size_t valueLen)
{
    if (typeBuf && typeLen)
        typeBuf[0] = '\0';
    if (valueBuf && valueLen)
        valueBuf[0] = '\0';
    if (!info.hasValue || !L)
        return;
    const char* tn = lua_typename(L, info.type);
    if (typeBuf && typeLen && tn)
        strncpy_s(typeBuf, typeLen, tn, _TRUNCATE);
    switch (info.type) {
    case LUA_TBOOLEAN:
        if (valueBuf && valueLen)
            strncpy_s(valueBuf, valueLen, info.boolValue ? "true" : "false", _TRUNCATE);
        break;
    case LUA_TNUMBER:
        if (valueBuf && valueLen)
            FormatLuaNumber(info.numberValue, valueBuf, valueLen);
        break;
    case LUA_TNIL:
        if (valueBuf && valueLen)
            strncpy_s(valueBuf, valueLen, "nil", _TRUNCATE);
        break;
    default:
        if (valueBuf && valueLen)
            strncpy_s(valueBuf, valueLen, "<complex>", _TRUNCATE);
        break;
    }
}

static void LogReturnBanner(lua_State* L, const char* name, const LuaReturnInfo& info, volatile LONG& guard)
{
    if (!info.hasValue)
        return;
    if (InterlockedCompareExchange(&guard, 1, 0) != 0)
        return;
    char typeBuf[32];
    char valueBuf[64];
    DescribeLuaReturn(L, info, typeBuf, sizeof(typeBuf), valueBuf, sizeof(valueBuf));
    if (info.type == LUA_TNIL || valueBuf[0] == '\0') {
        char buf[192];
        sprintf_s(buf, sizeof(buf), "[Lua] %s return type=%s", name ? name : "<fn>", typeBuf[0] ? typeBuf : "nil");
        WriteRawLog(buf);
    } else {
        char buf[224];
        sprintf_s(buf, sizeof(buf), "[Lua] %s return type=%s value=%s",
                  name ? name : "<fn>",
                  typeBuf[0] ? typeBuf : "unknown",
                  valueBuf);
        WriteRawLog(buf);
    }
}

static void LogCastUiReturn(lua_State* L, const char* tag, const LuaReturnInfo& info)
{
    if (!info.hasValue)
        return;
    char typeBuf[32];
    char valueBuf[64];
    DescribeLuaReturn(L, info, typeBuf, sizeof(typeBuf), valueBuf, sizeof(valueBuf));
    if (valueBuf[0] == '\0')
        strncpy_s(valueBuf, sizeof(valueBuf), "nil", _TRUNCATE);
    if (typeBuf[0] == '\0')
        strncpy_s(typeBuf, sizeof(typeBuf), "nil", _TRUNCATE);
    char buf[224];
    sprintf_s(buf, sizeof(buf), "[CastUI] %s rc=%s (type=%s)", tag ? tag : "Cast", valueBuf, typeBuf);
    WriteRawLog(buf);
}

static void ArmWordsLogWindow(uint32_t token)
{
    if (!g_debugWords || token == 0)
        return;
    g_wordsPendingToken.store(token, std::memory_order_release);
    g_wordsLoggedToken.store(0, std::memory_order_release);
}

static bool PrepareWordsLog(uint32_t& token)
{
    if (!g_debugWords)
        return false;
    token = g_wordsPendingToken.load(std::memory_order_acquire);
    if (token == 0)
        return false;
    if (g_wordsLoggedToken.load(std::memory_order_acquire) == token)
        return false;
    return true;
}

static void EmitWordsLog(uint32_t token, const char* label, const char* payload)
{
    if (!payload || !*payload)
        return;
    if (g_wordsLoggedToken.exchange(token, std::memory_order_acq_rel) == token)
        return;
    char buf[512];
    sprintf_s(buf,
              sizeof(buf),
              "[CastUI] Words(%s)=\"%s\" tok=%u",
              label ? label : "text",
              payload,
              token);
    WriteRawLog(buf);
}

static void MaybeLogWordsText(lua_State* L, const char* apiName, int argIndex, const char* label = nullptr)
{
    if (!L)
        return;
    uint32_t token = 0;
    if (!PrepareWordsLog(token))
        return;
    int top = lua_gettop(L);
    if (argIndex <= 0 || argIndex > top)
        return;
    const char* text = lua_tolstring(L, argIndex, nullptr);
    if (!text || !*text)
        return;
    char tag[64];
    if (label && *label)
        strncpy_s(tag, sizeof(tag), label, _TRUNCATE);
    else if (apiName)
        strncpy_s(tag, sizeof(tag), apiName, _TRUNCATE);
    else
        strncpy_s(tag, sizeof(tag), "text", _TRUNCATE);
    EmitWordsLog(token, tag, text);
}

static void MaybeLogWordsTid(lua_State* L, const char* apiName, int argIndex)
{
    uint32_t token = 0;
    if (!PrepareWordsLog(token) || !L)
        return;
    int top = lua_gettop(L);
    if (argIndex <= 0 || argIndex > top)
        return;
    if (lua_type(L, argIndex) != LUA_TNUMBER)
        return;
    int tid = static_cast<int>(lua_tointeger(L, argIndex));
    if (g_wordsLoggedToken.exchange(token, std::memory_order_acq_rel) == token)
        return;
    char buf[256];
    sprintf_s(buf,
              sizeof(buf),
              "[CastUI] Words(TID=%d) tok=%u via %s",
              tid,
              token,
              apiName ? apiName : "PrintTidToChatWindow");
    WriteRawLog(buf);
    NotePowerWordsTid(tid);
}

static void GuardLuaStack(lua_State* L, const char* tag, int topBefore, int returns)
{
    if (!L)
        return;
    if (returns < 0)
        returns = 0;
    int topAfter = lua_gettop(L);
    if (topAfter == returns)
        return;
    char buf[256];
    sprintf_s(buf,
              sizeof(buf),
              "[Lua] %s stack drift top_in=%d top_out=%d returns=%d",
              tag ? tag : "<fn>",
              topBefore,
              topAfter,
              returns);
    WriteRawLog(buf);
    lua_settop(L, returns);
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

static bool ActivateManualCastToken(uint32_t& previousTok, const char* reason)
{
    previousTok = g_tlsCurrentCastToken;
    if (previousTok != 0)
        return false;
    const uint32_t token = NextCastToken();
    g_tlsCurrentCastToken = token;
    g_lastCastToken.store(token, std::memory_order_release);
    ArmWordsLogWindow(token);
    char buf[192];
    sprintf_s(buf,
              sizeof(buf),
              "[NoClick] manual cast token tok=%u reason=%s",
              token,
              reason ? reason : "fallback");
    WriteRawLog(buf);
    return true;
}

static void RestoreManualCastToken(uint32_t previousTok, bool manualAssigned)
{
    if (!manualAssigned)
        return;
    g_tlsCurrentCastToken = previousTok;
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

static void* ResolveGateJumpTarget(void* target, int& depthOut)
{
    depthOut = 0;
    if (!target)
        return nullptr;

    uint8_t* current = static_cast<uint8_t*>(target);
    constexpr int kMaxDepth = 8;

    for (int depth = 0; depth < kMaxDepth; ++depth) {
        uint8_t opcode = 0;
        __try {
            opcode = current[0];
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }

        if (opcode == 0xE9) {
            int32_t rel = 0;
            __try {
                rel = *reinterpret_cast<int32_t*>(current + 1);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                break;
            }
            current = current + 5 + rel;
            ++depthOut;
            continue;
        }

        if (opcode == 0xEB) {
            int8_t rel8 = 0;
            __try {
                rel8 = *reinterpret_cast<int8_t*>(current + 1);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                break;
            }
            current = current + 2 + rel8;
            ++depthOut;
            continue;
        }

        if (opcode == 0xFF) {
            uint8_t modrm = 0;
            __try {
                modrm = current[1];
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                break;
            }

            if (modrm == 0x25) { // JMP [disp32]
                uint32_t disp = 0;
                __try {
                    disp = *reinterpret_cast<uint32_t*>(current + 2);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    break;
                }
                uint8_t** slot = reinterpret_cast<uint8_t**>(disp);
                uint8_t* next = nullptr;
                __try {
                    next = *slot;
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    break;
                }
                if (!next)
                    break;
                current = next;
                ++depthOut;
                continue;
            }
        }

        break;
    }

    return current;
}

static bool GateArmForCast()
{
    if (!g_enableCastGateProbes)
        return false;

    if (g_gatePendingToken.load(std::memory_order_acquire) != 0) {
        GateDisarmForCast("GateArm:pending_flush");
        g_gatePendingToken.store(0, std::memory_order_release);
        g_gatePendingSpell.store(0, std::memory_order_release);
    }

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
        GateResetInvokeStack();
    }

    g_gatePendingToken.store(0, std::memory_order_release);
    g_gatePendingSpell.store(0, std::memory_order_release);
}

static void GateResetInvokeStack()
{
    g_gateInvokeOverflowLogged = false;
    g_gateInvokeStack.clear();
}

static GateInvokeTls* GatePushInvokeFrame(GateCallProbe* probe)
{
    if (!probe)
        return nullptr;

    if (g_gateInvokeStack.capacity() == 0)
        g_gateInvokeStack.reserve(kGateInvokeDefaultReserve);

    if (g_gateInvokeStack.size() >= kGateInvokeMaxDepth) {
        if (!g_gateInvokeOverflowLogged) {
            g_gateInvokeOverflowLogged = true;
            char buf[192];
            sprintf_s(buf, sizeof(buf),
                "[Gate3350] invoke stack overflow (max=%zu) probe=%p",
                kGateInvokeMaxDepth,
                probe);
            WriteRawLog(buf);
        }
        return nullptr;
    }
    g_gateInvokeStack.emplace_back();
    GateInvokeTls& slot = g_gateInvokeStack.back();
    slot = GateInvokeTls{};
    slot.probe = probe;
    return &slot;
}

static bool GatePopInvokeFrame(GateCallProbe* probe, GateInvokeTls& outSnap)
{
    if (g_gateInvokeStack.empty())
        return false;

    GateInvokeTls slot = g_gateInvokeStack.back();
    g_gateInvokeStack.pop_back();
    if (probe && slot.probe != probe) {
        if (InterlockedCompareExchange(&g_gatePreInvokeLogBudget, 0, 0) > 0) {
            LONG left = InterlockedDecrement(&g_gatePreInvokeLogBudget);
            if (left >= 0) {
                char buf[192];
                sprintf_s(buf, sizeof(buf),
                    "[Gate3350] invoke stack mismatch probe=%p top=%p depth=%zu",
                    probe,
                    slot.probe,
                    g_gateInvokeStack.size());
                WriteRawLog(buf);
            }
        }
        if (g_gateInvokeStack.empty())
            g_gateInvokeOverflowLogged = false;
        return false;
    }

    outSnap = slot;
    if (g_gateInvokeStack.empty())
        g_gateInvokeOverflowLogged = false;
    return true;
}

static void GateRecordEvent(GateCallProbe* probe, uintptr_t retValue, const GateInvokeTls* snap)
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
    evt.ecx = snap ? snap->ecx : 0;
    evt.arg0 = snap ? snap->args[0] : 0;
    evt.name = probe->name;
    g_gateLogRing[slot & (kGateLogCapacity - 1)] = evt;
}

static bool GateLogActive()
{
    if (!g_enableCastGateProbes)
        return false;
    if (!g_gateArmedFlag.load(std::memory_order_acquire))
        return false;
    return g_gateOwnerThread.load(std::memory_order_acquire) != 0;
}

static void GateMaybeLogInvokeEntry(GateCallProbe* probe)
{
    if (!probe)
        return;
    if (!GateLogActive())
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
    if (!probe) {
        GateResetInvokeStack();
        return;
    }

    if (InterlockedCompareExchange(&g_gateStoreEntryBudget, 0, 0) > 0) {
        LONG left = InterlockedDecrement(&g_gateStoreEntryBudget);
        if (left >= 0 && GateLogActive()) {
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

    if (!g_enableCastGateProbes) {
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
            if (left >= 0 && GateLogActive()) {
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

    GateInvokeTls* slot = GatePushInvokeFrame(probe);
    if (!slot)
        return;
    slot->ecx = ecx;
    slot->edx = edx;
    for (size_t i = 0; i < 4; ++i)
        slot->args[i] = 0;

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
            slot->args[i] = argBase[i];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        for (size_t i = 0; i < 4; ++i)
            slot->args[i] = 0;
    }

    // If we're waiting to capture a spell context and the helper is firing,
    // treat the pre-invoke snapshot as sufficient (some helpers never return).
    uint32_t pendingTok = g_gatePendingToken.load(std::memory_order_acquire);
    if (pendingTok != 0) {
        int pendingSpell = g_gatePendingSpell.load(std::memory_order_acquire);
        int currentSpell = g_castSpellCurSpell.load(std::memory_order_relaxed);
        if (pendingSpell > 0 && currentSpell == pendingSpell) {
            MaybeLearnSpellGateContext(probe, *slot, /*retValue*/0);
        }
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

static bool SpellContextsEqual(const SpellGateReplayContext& a, const SpellGateReplayContext& b)
{
    if (a.probe != b.probe || a.ecx != b.ecx || a.edx != b.edx)
        return false;
    for (size_t i = 0; i < _countof(a.args); ++i) {
        if (a.args[i] != b.args[i])
            return false;
    }
    return true;
}

#if defined(_M_IX86)
static bool InvokeSpellGateDirect(const SpellGateReplayContext& ctx)
{
    if (!ctx.probe || !ctx.probe->trampoline)
        return false;

    uintptr_t arg0 = ctx.args[0];
    uintptr_t arg1 = ctx.args[1];
    uintptr_t arg2 = ctx.args[2];
    uintptr_t arg3 = ctx.args[3];
    uintptr_t result = 0;
    void* target = ctx.probe->trampoline;
    uintptr_t ecxVal = ctx.ecx;
    uintptr_t edxVal = ctx.edx;

    __asm {
        push arg3
        push arg2
        push arg1
        push arg0
        mov ecx, ecxVal
        mov edx, edxVal
        mov eax, target
        call eax
        mov result, eax
        add esp, 16
    }

    return (result != 0);
}
#else
static bool InvokeSpellGateDirect(const SpellGateReplayContext&)
{
    WriteRawLog("[SpellReplay] CastSpellNative unsupported on this architecture");
    return false;
}
#endif

static void MaybeLearnSpellGateContext(GateCallProbe* probe, const GateInvokeTls& snap, uintptr_t retValue)
{
    if (!probe)
        return;

    int spellId = g_castSpellCurSpell.load(std::memory_order_relaxed);
    if (spellId <= 0)
        return;

    SpellGateReplayContext ctx{};
    ctx.probe = probe;
    ctx.ecx = snap.ecx;
    ctx.edx = snap.edx;
    for (size_t i = 0; i < _countof(ctx.args); ++i)
        ctx.args[i] = snap.args[i];
    ctx.captureTick = GetTickCount();
    ctx.token = g_lastCastToken.load(std::memory_order_acquire);
    ctx.lastRet = retValue;

    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(g_spellReplayMutex);
        auto it = g_spellReplayCache.find(spellId);
        if (it == g_spellReplayCache.end()) {
            g_spellReplayCache.emplace(spellId, ctx);
            changed = true;
        } else if (!SpellContextsEqual(it->second, ctx)) {
            it->second = ctx;
            changed = true;
        }
    }

    if (changed) {
        char buf[256];
        sprintf_s(buf, sizeof(buf),
            "[SpellReplay] captured native context spell=%d probe=%s ecx=%p arg0=%p token=%u",
            spellId,
            probe->name ? probe->name : "unknown",
            reinterpret_cast<void*>(ctx.ecx),
            reinterpret_cast<void*>(ctx.args[0]),
            ctx.token);
        WriteRawLog(buf);
    }

    uint32_t pendingTok = g_gatePendingToken.load(std::memory_order_acquire);
    if (pendingTok != 0 && pendingTok == ctx.token) {
        g_gatePendingToken.store(0, std::memory_order_release);
        g_gatePendingSpell.store(0, std::memory_order_release);
        GateDisarmForCast("GateLogReturn:capture");
    }
}

static void LogGateHelperSelected(GateCallProbe* probe, const GateInvokeTls* snap, uintptr_t retValue)
{
    if (!probe || !snap)
        return;

    MaybeLearnSpellGateContext(probe, *snap, retValue);

    if (!GateConsumeBudget(g_gateReturnLogBudget, g_gateReturnLogUnlimited))
        return;

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
        reinterpret_cast<void*>(snap->ecx),
        reinterpret_cast<void*>(snap->edx),
        reinterpret_cast<void*>(snap->args[0]),
        reinterpret_cast<void*>(snap->args[1]),
        reinterpret_cast<void*>(snap->args[2]),
        reinterpret_cast<void*>(snap->args[3]),
        g_lastCastToken.load(std::memory_order_acquire),
        g_castSpellCurSpell.load(std::memory_order_relaxed),
        probe->name ? probe->name : "unknown");
    WriteRawLog(buf);
    MaybeLearnSpellGateContext(probe, *snap, retValue);

    if (isZero && GateConsumeBudget(g_gateReturnDumpBudget, g_gateReturnDumpUnlimited)) {
        DumpGateMemorySafe("Gate3350.ecx", snap->ecx, 64);
        DumpGateMemorySafe("Gate3350.arg0", snap->args[0], 64);
    }
}

static void __stdcall GateLogReturn(GateCallProbe* probe, uintptr_t retValue)
{
    if (!probe) {
        GateResetInvokeStack();
        return;
    }

    GateInvokeTls snap{};
    const GateInvokeTls* snapPtr = nullptr;
    if (GatePopInvokeFrame(probe, snap))
        snapPtr = &snap;

    uint32_t total = probe->hits.fetch_add(1, std::memory_order_relaxed) + 1;
    uint32_t zeroTotal = (retValue == 0)
        ? (probe->zeroHits.fetch_add(1, std::memory_order_relaxed) + 1)
        : probe->zeroHits.load(std::memory_order_relaxed);

    GateRecordEvent(probe, retValue, snapPtr);

    if (snapPtr && reinterpret_cast<uintptr_t>(probe->target) == g_gateSelectedTarget)
        LogGateHelperSelected(probe, snapPtr, retValue);
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

static void RequestActionWrapperInstall()
{
    InterlockedExchange(&g_actionWrapperInstallPending, 1);
}

// Attempt action wrapper install after target APIs appear and a small delay has passed.
static void TryInstallActionWrappers()
{
    if (InterlockedCompareExchange(&g_actionWrappersInstalled, 0, 0) != 0)
        return;
    auto L = static_cast<lua_State*>(Engine::LuaState());
    if (!L) return;
    if (!ActionWrappersReady(L))
        return;

    __try {
        struct ActionWrapperEntry {
            const char* name;
            lua_CFunction wrapper;
            uint32_t bit;
        };
        static const ActionWrapperEntry kEntries[] = {
            {"UserActionCastSpell", &Lua_UserActionCastSpell_W, kWrapperCastSpell},
            {"UserActionCastSpellOnId", &Lua_UserActionCastSpellOnId_W, kWrapperCastSpellOnId},
            {"UserActionUseSkill", &Lua_UserActionUseSkill_W, kWrapperUseSkill},
            {"UserActionUsePrimaryAbility", &Lua_UserActionUsePrimaryAbility_W, kWrapperUsePrimaryAbility},
            {"UserActionUseWeaponAbility", &Lua_UserActionUseWeaponAbility_W, kWrapperUseWeaponAbility},
            {"UserActionIsTargetModeCompat", &Lua_UserActionIsTargetModeCompat_W, kWrapperTargetCompat},
            {"UserActionIsActionTypeTargetModeCompat", &Lua_UserActionIsActionTypeTargetModeCompat_W, kWrapperActionTypeCompat},
            {"RequestTargetInfo", &Lua_RequestTargetInfo_W, kWrapperRequestTargetInfo},
            {"ClearCurrentTarget", &Lua_ClearCurrentTarget_W, kWrapperClearCurrentTarget},
            {"UserActionIsSkillAvalible", &Lua_UserActionIsSkillAvalible_W, kWrapperSkillAvailable},
            {"HS_ShowTargetingCursor", &Lua_HS_ShowTargetingCursor_W, kWrapperHsShowCursor},
            {"HS_HideTargetingCursor", &Lua_HS_HideTargetingCursor_W, kWrapperHsHideCursor},
            {"HandleSingleLeftClkTarget", &Lua_HandleSingleLeftClkTarget_W, kWrapperHandleLeftClick},
            {"UserActionSpeechSetText", &Lua_UserActionSpeechSetText_W, kWrapperSpeechSetText},
            {"TextLogAddEntry", &Lua_TextLogAddEntry_W, kWrapperTextLogAddEntry},
            {"PrintWStringToChatWindow", &Lua_PrintWStringToChatWindow_W, kWrapperPrintWString},
            {"PrintTidToChatWindow", &Lua_PrintTidToChatWindow_W, kWrapperPrintTid},
            {"TextLogAddSingleByteEntry", &Lua_TextLogAddSingleByteEntry_W, kWrapperTextLogAddSingleByte}
        };

        static DWORD s_nextMissingLogMs = 0;
        DWORD now = GetTickCount();
        uint32_t mask = g_actionWrapperMask.load(std::memory_order_acquire);
        bool installedAny = false;
        auto tryWrap = [&](const ActionWrapperEntry& entry) {
            if (mask & entry.bit)
                return;
            if ((entry.bit == kWrapperHandleLeftClick && !g_enableTapTargetWrap) ||
                (!g_debugWords && (entry.bit == kWrapperPrintWString || entry.bit == kWrapperPrintTid || entry.bit == kWrapperTextLogAddSingleByte || entry.bit == kWrapperSpeechSetText || entry.bit == kWrapperTextLogAddEntry)))
                return;
            bool wrapped = false;
            if (entry.bit == kWrapperCastSpell) {
                wrapped = InstallRegistryWrapper(L, entry.name, entry.wrapper, g_castSpellRegistryRef);
            } else if (entry.bit == kWrapperCastSpellOnId) {
                wrapped = InstallRegistryWrapper(L, entry.name, entry.wrapper, g_castSpellOnIdRegistryRef);
            } else {
                lua_getglobal(L, entry.name);
                bool present = (lua_type(L, -1) == LUA_TFUNCTION);
                lua_pop(L, 1);
                if (!present) {
                    if (entry.bit == kWrapperHandleLeftClick && g_enableTapTargetWrap) {
                        DWORD tick = GetTickCount();
                        if (tick >= g_clickTapNextMissingLog) {
                            WriteRawLog("[ClickTap] HandleSingleLeftClkTarget not yet registered; will retry");
                            g_clickTapNextMissingLog = tick + 1000;
                        }
                    }
                    if (now >= s_nextMissingLogMs) {
                        char msg[192];
                        sprintf_s(msg, sizeof(msg), "TryInstallActionWrappers: '%s' not found; will retry", entry.name);
                        WriteRawLog(msg);
                    }
                    return;
                }
                wrapped = SaveAndReplace(L, entry.name, entry.wrapper);
            }
            if (wrapped) {
                mask |= entry.bit;
                installedAny = true;
            }
        };

        for (const auto& entry : kEntries)
            tryWrap(entry);

        if (installedAny) {
            g_actionWrapperMask.store(mask, std::memory_order_release);
            char buf[160];
            sprintf_s(buf, sizeof(buf), "TryInstallActionWrappers: updated mask=0x%X", mask);
            WriteRawLog(buf);
            if (mask == kAllActionWrappers) {
                InterlockedExchange(&g_actionWrappersInstalled, 1);
                WriteRawLog("TryInstallActionWrappers: installed action wrappers via Lua API");
            }
            if (g_enableTapTargetWrap) {
                char clickBuf[128];
                sprintf_s(clickBuf,
                          sizeof(clickBuf),
                          "[ClickTap] install status: %s",
                          g_clickTapWrapInstalled.load(std::memory_order_acquire) ? "OK" : "PENDING");
                WriteRawLog(clickBuf);
            }
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

static void EnsureRegisterHelperAddress()
{
    if (g_registerTarget)
        return;
    void* addr = Engine::FindRegisterLuaFunction();
    if (!addr)
        return;
    g_registerTarget = addr;
    static bool s_logged = false;
    if (!s_logged) {
        char buf[160];
        sprintf_s(buf,
                  sizeof(buf),
                  "EnsureRegisterHelperAddress: register helper resolved at %p",
                  addr);
        WriteRawLog(buf);
        s_logged = true;
    }
}

static void LogCastOriginalAddress(const char* label, const void* addr, bool& loggedFlag)
{
    if (loggedFlag || !label || !addr)
        return;
    HMODULE hExe = GetModuleHandleA(nullptr);
    if (!hExe)
        return;
    auto base = reinterpret_cast<uintptr_t>(hExe);
    auto offset = reinterpret_cast<uintptr_t>(addr) - base;
    char buf[192];
    sprintf_s(buf,
              sizeof(buf),
              "[CastOrig] %s=UOSA.exe+0x%08lX",
              label,
              static_cast<unsigned long>(offset));
    WriteRawLog(buf);
    loggedFlag = true;
}

template <typename FnPtr>
static BYTE* ResolveCastOriginalAddress(const char* name, FnPtr& storage, bool& loggedFlag)
{
    if (storage)
        return reinterpret_cast<BYTE*>(storage);
    BYTE* target = FindActionFuncByName(name);
    if (!target)
        return nullptr;
    storage = reinterpret_cast<FnPtr>(target);
    LogCastOriginalAddress(name, reinterpret_cast<void*>(storage), loggedFlag);
    return target;
}

static void TryInstallDirectActionHooks()
{
    if (InterlockedCompareExchange(&g_directActionHooksInstalled, 0, 0) != 0)
        return;
    EnsureRegisterHelperAddress();
    LoadDirectHookPreferences();

    HMODULE hExe = GetModuleHandleA(nullptr);
    if (!hExe) return;

    MH_STATUS init = MH_Initialize();
    (void)init; // ignore already-initialized status

    BYTE* castSpellTarget = ResolveCastOriginalAddress("UserActionCastSpell", g_origCastSpell, g_castSpellOrigLogged);
    BYTE* castOnIdTarget = ResolveCastOriginalAddress("UserActionCastSpellOnId", g_origCastSpellOnId, g_castSpellOnIdOrigLogged);

    bool any = false;
    auto hookOne = [&](const char* name, LuaFn& orig, lua_CFunction wrapper, bool enabled, BYTE* targetHint = nullptr) {
        if (!enabled) {
            if (name) {
                char msg[192];
                sprintf_s(msg, sizeof(msg), "DirectHook: %s disabled via config/env", name);
                WriteRawLog(msg);
            }
            return;
        }
        if (orig) return; // already captured via register hook
        BYTE* target = targetHint ? targetHint : FindActionFuncByName(name);
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

    hookOne("UserActionCastSpell", g_origUserActionCastSpell, &Lua_UserActionCastSpell_W, g_directHookEnableCastSpell, castSpellTarget);
    hookOne("UserActionCastSpellOnId", g_origUserActionCastSpellOnId, &Lua_UserActionCastSpellOnId_W, g_directHookEnableCastSpellOnId, castOnIdTarget);
    hookOne("UserActionUseSkill", g_origUserActionUseSkill, &Lua_UserActionUseSkill_W, g_directHookEnableUseSkill);
    hookOne("UserActionUsePrimaryAbility", g_origUserActionUsePrimaryAbility, &Lua_UserActionUsePrimaryAbility_W, true);
    hookOne("UserActionUseWeaponAbility", g_origUserActionUseWeaponAbility, &Lua_UserActionUseWeaponAbility_W, g_directHookEnableUseWeaponAbility);
    hookOne("UserActionIsTargetModeCompat", g_origUserActionIsTargetModeCompat, &Lua_UserActionIsTargetModeCompat_W, true);
    hookOne("UserActionIsActionTypeTargetModeCompat", g_origUserActionIsActionTypeTargetModeCompat, &Lua_UserActionIsActionTypeTargetModeCompat_W, true);
    hookOne("RequestTargetInfo", g_origRequestTargetInfo, &Lua_RequestTargetInfo_W, g_directHookEnableRequestTargetInfo);
    hookOne("ClearCurrentTarget", g_origClearCurrentTarget, &Lua_ClearCurrentTarget_W, true);
    hookOne("UserActionIsSkillAvalible", g_origUserActionIsSkillAvalible, &Lua_UserActionIsSkillAvalible_W, true);
    hookOne("HS_ShowTargetingCursor", g_origHS_ShowTargetingCursor, &Lua_HS_ShowTargetingCursor_W, g_directHookEnableHsShowCursor);
    hookOne("HS_HideTargetingCursor", g_origHS_HideTargetingCursor, &Lua_HS_HideTargetingCursor_W, g_directHookEnableHsHideCursor);

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

    InstallUOFlowConsoleBindingsIfNeeded(CanonicalOwnerContext(), nullptr);

    sprintf_s(stateBuf, sizeof(stateBuf), "%s post-bind", tag);
    LogWalkBindingState(L, stateBuf);
}

static void ForceSpellBinding(lua_State* L, const char* reason)
{
    if (!L)
        return;
    if (!g_clientContext)
        return;
    if (g_spellBindingReady.load(std::memory_order_acquire))
        return;

    const char* tag = reason ? reason : "EnsureSpellBinding";
    char buf[224];
    sprintf_s(buf, sizeof(buf), "%s: ensuring UOW.Spell.cast binding (ctx=%p)", tag, g_clientContext);
    WriteRawLog(buf);

    bool primary = RegisterViaClient(L, Lua_UOW_Spell_Cast, "UOW.Spell.cast");
    bool alias = RegisterViaClient(L, Lua_UOW_Spell_Cast, "UOFlow.Spell.cast");
    if (primary || alias) {
        g_spellBindingReady.store(true, std::memory_order_release);
        char okBuf[192];
        sprintf_s(okBuf, sizeof(okBuf),
            "%s: spell helper installed (alias=%s)",
            tag,
            alias ? "yes" : "no");
        WriteRawLog(okBuf);
    }
}

static void EnsureReplayHelper(lua_State* L)
{
    if (!L)
        return;
    if (g_replayHelperInstalled.load(std::memory_order_acquire))
        return;
    bool ok = RegisterViaClient(L, Lua_uow_cast_spell_and_target, "uow_cast_spell_and_target");
    if (!ok)
        ok = RegisterFunctionSafe(L, Lua_uow_cast_spell_and_target, "uow_cast_spell_and_target");
    if (ok) {
        g_replayHelperInstalled.store(true, std::memory_order_release);
        WriteRawLog("EnsureReplayHelper: registered uow_cast_spell_and_target");
    }
    InstallUOFlowConsoleBindingsIfNeeded(CanonicalOwnerContext(), "replay_helper");
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
                WriteRawLog("Hook_Register: wrapped UserActionCastSpell");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = reinterpret_cast<void*>(&Lua_UserActionCastSpell_W);
        }
        else if (_stricmp(name, "UserActionCastSpellOnId") == 0)
        {
            if (!g_origUserActionCastSpellOnId)
            {
                g_origUserActionCastSpellOnId = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped UserActionCastSpellOnId");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = reinterpret_cast<void*>(&Lua_UserActionCastSpellOnId_W);
        }
        else if (_stricmp(name, "UserActionUseSkill") == 0 || _stricmp(name, "UserActionUsePrimaryAbility") == 0)
        {
            if (!g_origUserActionUseSkill)
            {
                g_origUserActionUseSkill = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped UserActionUseSkill");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = reinterpret_cast<void*>(&Lua_UserActionUseSkill_W);
        }
        else if (_stricmp(name, "UserActionIsTargetModeCompat") == 0)
        {
            if (!g_origUserActionIsTargetModeCompat)
            {
                g_origUserActionIsTargetModeCompat = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped UserActionIsTargetModeCompat");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = reinterpret_cast<void*>(&Lua_UserActionIsTargetModeCompat_W);
        }
        else if (_stricmp(name, "UserActionIsActionTypeTargetModeCompat") == 0)
        {
            if (!g_origUserActionIsActionTypeTargetModeCompat)
            {
                g_origUserActionIsActionTypeTargetModeCompat = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped UserActionIsActionTypeTargetModeCompat");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = reinterpret_cast<void*>(&Lua_UserActionIsActionTypeTargetModeCompat_W);
        }
        else if (_stricmp(name, "RequestTargetInfo") == 0)
        {
            if (!g_origRequestTargetInfo)
            {
                g_origRequestTargetInfo = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped RequestTargetInfo");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = reinterpret_cast<void*>(&Lua_RequestTargetInfo_W);
            g_targetApiTimestamp = GetTickCount();
            InterlockedExchange(&g_targetApiSeen, 1);
        }
        else if (_stricmp(name, "ClearCurrentTarget") == 0)
        {
            if (!g_origClearCurrentTarget)
            {
                g_origClearCurrentTarget = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped ClearCurrentTarget");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = reinterpret_cast<void*>(&Lua_ClearCurrentTarget_W);
            g_targetApiTimestamp = GetTickCount();
            InterlockedExchange(&g_targetApiSeen, 1);
        }
        else if (_stricmp(name, "UserActionIsSkillAvalible") == 0)
        {
            if (!g_origUserActionIsSkillAvalible)
            {
                g_origUserActionIsSkillAvalible = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped UserActionIsSkillAvalible");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = reinterpret_cast<void*>(&Lua_UserActionIsSkillAvalible_W);
        }
        else if (_stricmp(name, "HS_ShowTargetingCursor") == 0)
        {
            if (!g_origHS_ShowTargetingCursor)
            {
                g_origHS_ShowTargetingCursor = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped HS_ShowTargetingCursor");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = reinterpret_cast<void*>(&Lua_HS_ShowTargetingCursor_W);
        }
        else if (_stricmp(name, "HS_HideTargetingCursor") == 0)
        {
            if (!g_origHS_HideTargetingCursor)
            {
                g_origHS_HideTargetingCursor = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped HS_HideTargetingCursor");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = reinterpret_cast<void*>(&Lua_HS_HideTargetingCursor_W);
        }
        else if (_stricmp(name, "UserActionUseWeaponAbility") == 0)
        {
            if (!g_origUserActionUseWeaponAbility)
            {
                g_origUserActionUseWeaponAbility = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped UserActionUseWeaponAbility");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = reinterpret_cast<void*>(&Lua_UserActionUseWeaponAbility_W);
        }
        else if (_stricmp(name, "UserActionUsePrimaryAbility") == 0)
        {
            if (!g_origUserActionUsePrimaryAbility)
            {
                g_origUserActionUsePrimaryAbility = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped UserActionUsePrimaryAbility");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = reinterpret_cast<void*>(&Lua_UserActionUsePrimaryAbility_W);
        }
        else if (_stricmp(name, "HandleSingleLeftClkTarget") == 0)
        {
            if (!g_clickTapStateLogged) {
                WriteRawLog(g_enableTapTargetWrap ? "[ClickTap] wrapper ENABLED" : "[ClickTap] wrapper DISABLED");
                g_clickTapStateLogged = true;
            }
            if (!g_enableTapTargetWrap) {
                outFunc = func;
            } else {
                if (!g_origHandleSingleLeftClkTarget)
                {
                    g_origHandleSingleLeftClkTarget = reinterpret_cast<LuaFn>(func);
                    WriteRawLog("Hook_Register: wrapped HandleSingleLeftClkTarget");
                }
                NoteCapturedActionTarget(name, func);
                outFunc = reinterpret_cast<void*>(&Lua_HandleSingleLeftClkTarget_W);
                if (!g_clickTapWrapInstalled.exchange(true, std::memory_order_acq_rel)) {
                    char clickBuf[160];
                    sprintf_s(clickBuf,
                              sizeof(clickBuf),
                              "[ClickTap] HandleSingleLeftClkTarget wrapper installed (ref=direct)");
                    WriteRawLog(clickBuf);
                }
            }
        }
        else if (_stricmp(name, "UserActionSpeechSetText") == 0)
        {
            if (!g_origUserActionSpeechSetText)
            {
                g_origUserActionSpeechSetText = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped UserActionSpeechSetText");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = g_debugWords ? reinterpret_cast<void*>(&Lua_UserActionSpeechSetText_W) : func;
        }
        else if (_stricmp(name, "TextLogAddEntry") == 0)
        {
            if (!g_origTextLogAddEntry)
            {
                g_origTextLogAddEntry = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped TextLogAddEntry");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = g_debugWords ? reinterpret_cast<void*>(&Lua_TextLogAddEntry_W) : func;
        }
        else if (_stricmp(name, "PrintWStringToChatWindow") == 0)
        {
            if (!g_origPrintWStringToChatWindow)
            {
                g_origPrintWStringToChatWindow = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped PrintWStringToChatWindow");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = g_debugWords ? reinterpret_cast<void*>(&Lua_PrintWStringToChatWindow_W) : func;
        }
        else if (_stricmp(name, "PrintTidToChatWindow") == 0)
        {
            if (!g_origPrintTidToChatWindow)
            {
                g_origPrintTidToChatWindow = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped PrintTidToChatWindow");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = g_debugWords ? reinterpret_cast<void*>(&Lua_PrintTidToChatWindow_W) : func;
        }
        else if (_stricmp(name, "TextLogAddSingleByteEntry") == 0)
        {
            if (!g_origTextLogAddSingleByteEntry)
            {
                g_origTextLogAddSingleByteEntry = reinterpret_cast<LuaFn>(func);
                WriteRawLog("Hook_Register: wrapped TextLogAddSingleByteEntry");
            }
            NoteCapturedActionTarget(name, func);
            outFunc = g_debugWords ? reinterpret_cast<void*>(&Lua_TextLogAddSingleByteEntry_W) : func;
        }
    }

    int rc = g_clientRegister ? g_clientRegister(ctx, outFunc, name) : 0;

    // If targeting APIs have been registered, attempt late wrapper install now
    if (name && ( _stricmp(name, "RequestTargetInfo") == 0 || _stricmp(name, "ClearCurrentTarget") == 0)) {
        g_targetApiTimestamp = GetTickCount();
        InterlockedExchange(&g_targetApiSeen, 1);
        RequestActionWrapperInstall();
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
            InstallUOFlowConsoleBindingsIfNeeded(ctx, "register_hook");
        } else if (_stricmp(name, "bindWalk") == 0 && func == bindPtr) {
            if (auto L2 = static_cast<lua_State*>(Engine::LuaState())) {
                LogWalkBindingState(L2, "Hook_Register post-bindWalk");
            }
        }
    }

    // Avoid calling back into broader Lua registration from within the client's
    // RegisterLuaFunction path to minimize risk during world load.
    // Previously this invoked RegisterOurLuaFunctions() here; that proved risky.

    // Request late install of action wrappers once target APIs are present
    RequestActionWrapperInstall();
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

static int __cdecl Lua_UOW_Spell_Cast(lua_State* L)
{
    int spellId = 0;
    if (L && lua_gettop(L) >= 1 && lua_type(L, 1) == LUA_TNUMBER) {
        spellId = static_cast<int>(lua_tointeger(L, 1));
    }
    char buf[128];
    sprintf_s(buf, sizeof(buf), "[Lua] UOW.Spell.cast invoked spell=%d", spellId);
    WriteRawLog(buf);
    bool ok = Engine::Lua::CastSpellNative(spellId);
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

static int __cdecl Lua_uow_cast_spell_and_target(lua_State* L)
{
    int spellId = 0;
    int targetId = 0;
    int top = lua_gettop(L);
    if (top >= 1 && lua_type(L, 1) == LUA_TNUMBER)
        spellId = static_cast<int>(lua_tointeger(L, 1));
    if (top >= 2 && lua_type(L, 2) == LUA_TNUMBER)
        targetId = static_cast<int>(lua_tointeger(L, 2));
    char intro[256];
    sprintf_s(intro,
              sizeof(intro),
              "[Replay] uow_cast_spell_and_target spell=%d target=%d",
              spellId,
              targetId);
    WriteRawLog(intro);

    auto invokeGlobal = [&](const char* name,
                            int nargs,
                            const std::function<void()>& pushArgs,
                            bool keepResults,
                            LuaReturnInfo* outInfo = nullptr) -> int {
        int baseTop = lua_gettop(L);
        lua_getglobal(L, name);
        if (lua_type(L, -1) != LUA_TFUNCTION) {
            lua_settop(L, baseTop);
            char warn[192];
            sprintf_s(warn, sizeof(warn), "[Replay] global '%s' missing", name ? name : "<fn>");
            WriteRawLog(warn);
            return -1;
        }
        if (pushArgs)
            pushArgs();
        if (lua_pcall(L, nargs, keepResults ? LUA_MULTRET : 0, 0) != 0) {
            const char* err = lua_tolstring(L, -1, nullptr);
            char warn[256];
            sprintf_s(warn,
                      sizeof(warn),
                      "[Replay] %s failed: %s",
                      name ? name : "<fn>",
                      err ? err : "<unknown>");
            WriteRawLog(warn);
            lua_settop(L, baseTop);
            return -1;
        }
        if (!keepResults) {
            lua_settop(L, baseTop);
            return 0;
        }
        int results = lua_gettop(L) - baseTop;
        if (outInfo)
            *outInfo = CaptureLuaReturn(L, results);
        return results;
    };

    if (invokeGlobal("UserActionCastSpell",
                     1,
                     [&]() { lua_pushinteger(L, spellId); },
                     false) < 0) {
        lua_pushboolean(L, 0);
        return 1;
    }

    LuaReturnInfo retInfo{};
    int results = invokeGlobal(
        "UserActionCastSpellOnId",
        2,
        [&]() {
            lua_pushinteger(L, spellId);
            lua_pushinteger(L, targetId);
        },
        true,
        &retInfo);
    if (results < 0) {
        lua_pushboolean(L, 0);
        return 1;
    }

    char typeBuf[32];
    char valueBuf[64];
    DescribeLuaReturn(L, retInfo, typeBuf, sizeof(typeBuf), valueBuf, sizeof(valueBuf));
    if (typeBuf[0] == '\0')
        strncpy_s(typeBuf, sizeof(typeBuf), retInfo.hasValue ? "unknown" : "nil", _TRUNCATE);
    if (valueBuf[0] == '\0')
        strncpy_s(valueBuf, sizeof(valueBuf), retInfo.hasValue ? "<complex>" : "nil", _TRUNCATE);
    char exitBuf[256];
    sprintf_s(exitBuf,
              sizeof(exitBuf),
              "[Replay] uow_cast_spell_and_target -> rc=%s (type=%s)",
              valueBuf,
              typeBuf);
    WriteRawLog(exitBuf);
    LogCastUiReturn(L, "Replay", retInfo);
    return results;
}

static const char* TargetKindName(TargetCommitKind kind)
{
    switch (kind) {
    case TargetCommitKind::Object:
        return "object";
    case TargetCommitKind::Ground:
        return "ground";
    case TargetCommitKind::Self:
        return "self";
    case TargetCommitKind::Cancel:
        return "cancel";
    default:
        return "object";
    }
}

static uint32_t EncodeGroundTarget(int x, int y)
{
    const uint32_t ux = static_cast<uint32_t>(x) & 0xFFFFu;
    const uint32_t uy = static_cast<uint32_t>(y) & 0xFFFFu;
    return 0x40000000u | (uy << 16) | ux;
}

static constexpr DWORD kPowerWordsWindowMs = 200;

static void NotePowerWordsTid(int tid)
{
    if (!g_noClickState.active)
        return;
    g_noClickState.powerWordsTid = tid;
    g_noClickState.powerWordsObserved = true;
    if (g_noClickState.powerWordsLogged)
        return;
    DWORD elapsed = GetTickCount() - g_noClickState.startTick;
    char buf[192];
    sprintf_s(buf,
              sizeof(buf),
              "[SpellUI] power-words: OK tid=%d elapsed=%lu ms",
              tid,
              static_cast<unsigned long>(elapsed));
    WriteRawLog(buf);
    g_noClickState.powerWordsLogged = true;
}

static void MaybeLogPowerWordsTimeout(const char* stage)
{
    if (!g_noClickState.active)
        return;
    if (g_noClickState.powerWordsLogged)
        return;
    if (g_noClickState.powerWordsDeadline == 0)
        return;
    DWORD now = GetTickCount();
    if (now < g_noClickState.powerWordsDeadline)
        return;
    char buf[224];
    sprintf_s(buf,
              sizeof(buf),
              "[SpellUI] power-words: TIMEOUT stage=%s elapsed=%lu ms",
              stage ? stage : "unknown",
              static_cast<unsigned long>(now - g_noClickState.startTick));
    WriteRawLog(buf);
    g_noClickState.powerWordsLogged = true;
}

static bool IsTargetCursorActive()
{
    auto* L = static_cast<lua_State*>(Engine::LuaState());
    if (!L || !g_origUserActionIsTargetModeCompat)
        return false;
    int topBefore = lua_gettop(L);
    int rc = InvokeClientLuaFn(g_origUserActionIsTargetModeCompat, "UserActionIsTargetModeCompat", L);
    bool compat = false;
    if (rc > 0) {
        int topAfter = lua_gettop(L);
        if (topAfter > 0)
            compat = lua_toboolean(L, -1) != 0;
    }
    lua_settop(L, topBefore);
    return compat;
}

static void MarkTargetRequestObserved()
{
    if (!g_noClickState.active)
        return;
    g_noClickState.targetRequestObserved = true;
    g_noClickState.targetRequestTick = GetTickCount();
}

static bool TargetFallbackReady()
{
    if (!g_origRequestTargetInfo)
        return false;
    if (!CanonicalOwnerContext())
        return false;
    return Util::OwnerPump::GetOwnerThreadId() != 0;
}

static void LogTargetFallbackError(const char* reason)
{
    void* ctx = CanonicalOwnerContext();
    char buf[256];
    sprintf_s(buf,
              sizeof(buf),
              "tag=UOFlow.Spell.target_fallback_error reason=%s ctx=%p clear=%p request=%p",
              reason ? reason : "unknown",
              ctx,
              reinterpret_cast<void*>(g_origClearCurrentTarget),
              reinterpret_cast<void*>(g_origRequestTargetInfo));
    WriteRawLog(buf);
}

static bool WaitForSendLogged(DWORD timeoutMs)
{
    if (g_noClickState.sendLogged)
        return true;
    DWORD start = GetTickCount();
    while (!g_noClickState.sendLogged) {
        if (GetTickCount() - start >= timeoutMs)
            return false;
        Sleep(0);
    }
    return true;
}

static bool OpenTargetForSpell_Fallback(const char* reason)
{
    if (!TargetFallbackReady()) {
        LogTargetFallbackError("prereq_missing");
        return false;
    }
    static constexpr int kFallbackAction = 1;
    static constexpr int kFallbackSub = 1;
    static constexpr int kFallbackExtra = 0;
    TargetRequestTuple tuple{};
    tuple.action = kFallbackAction;
    tuple.sub = kFallbackSub;
    tuple.extra = kFallbackExtra;
    tuple.learned = true;
    g_targetRequestTuple = tuple;
    char buf[256];
    sprintf_s(buf,
              sizeof(buf),
              "[TargetFallback] RequestTargetInfo(action=%d, sub=%d, extra=%d reason=%s)",
              kFallbackAction,
              kFallbackSub,
              kFallbackExtra,
              reason ? reason : "fallback");
    WriteRawLog(buf);
    auto success = std::make_shared<std::atomic<bool>>(false);
    auto task = [success]() {
        auto* L = static_cast<lua_State*>(Engine::LuaState());
        if (!L) {
            LogTargetFallbackError("lua_state_missing");
            return;
        }
        if (g_origClearCurrentTarget) {
            int topClear = lua_gettop(L);
            int rcClear = InvokeClientLuaFn(g_origClearCurrentTarget, "ClearCurrentTarget", L);
            lua_settop(L, topClear);
            if (rcClear < 0) {
                LogTargetFallbackError("clear_call_failed");
                return;
            }
        } else {
            WriteRawLog("[TargetFallback] ClearCurrentTarget unavailable");
        }
        g_targetCorr.Arm("UOW_RequestTargetInfo");
        WriteRawLog("[Target] open requested via RequestTargetInfo (fallback)");
        int top = lua_gettop(L);
        lua_pushinteger(L, kFallbackAction);
        lua_pushinteger(L, kFallbackSub);
        lua_pushinteger(L, kFallbackExtra);
        int rc = InvokeClientLuaFn(g_origRequestTargetInfo, "RequestTargetInfo", L);
        lua_settop(L, top);
        if (rc < 0) {
            LogTargetFallbackError("request_call_failed");
            return;
        }
        MarkTargetRequestObserved();
        if (g_noClickState.active)
            LogTargetOpen(TargetCommitKind::Object);
        success->store(true, std::memory_order_release);
    };
    bool ranInline = Util::OwnerPump::Invoke("target_fallback", std::move(task));
    if (!ranInline)
        return true;
    return success->load(std::memory_order_acquire);
}

static bool InstallUOFlowConsoleBindingsIfNeeded(void* ownerCtx, const char* reason)
{
    (void)reason;
    static DWORD s_nextOwnerCtxLog = 0;
    if (g_consoleBound)
        return true;

    auto* L = static_cast<lua_State*>(Engine::LuaState());
    if (!L) {
        static DWORD s_nextLuaLog = 0;
        DWORD now = GetTickCount();
        if (now >= s_nextLuaLog) {
            WriteRawLog("InstallUOFlowConsoleBindingsIfNeeded: lua state unavailable");
            s_nextLuaLog = now + 1000;
        }
        return false;
    }

    if (!ownerCtx)
        ownerCtx = CanonicalOwnerContext();
    if (!ownerCtx)
        ownerCtx = g_clientContext;
    if (!ownerCtx) {
        DWORD now = GetTickCount();
        if (now >= s_nextOwnerCtxLog) {
            WriteRawLog("InstallUOFlowConsoleBindingsIfNeeded: owner context unavailable");
            s_nextOwnerCtxLog = now + 1000;
        }
        return false;
    }

    struct ConsoleBinding {
        lua_CFunction fn;
        const char* name;
    };

    static const ConsoleBinding kRequired[] = {
        {Lua_UOFlow_status, "UOFlow.status"},
        {Lua_UOFlow_Spell_cast, "UOFlow.Spell.cast"},
        {Lua_UOFlow_Spell_cast_on_id, "UOFlow.Spell.cast_on_id"},
        {Lua_UOFlow_Target_commit_obj, "UOFlow.Target.commit_obj"},
        {Lua_UOFlow_Target_commit_ground, "UOFlow.Target.commit_ground"},
        {Lua_UOFlow_Target_cancel, "UOFlow.Target.cancel"},
        {Lua_UOFlow_Target_force_open, "UOFlow.Target.force_open"},
    };

    for (const auto& binding : kRequired) {
        if (!RegisterViaClient(L, binding.fn, binding.name)) {
            char buf[256];
            sprintf_s(buf,
                      sizeof(buf),
                      "InstallUOFlowConsoleBindingsIfNeeded: register failed for '%s'",
                      binding.name);
            WriteRawLog(buf);
            return false;
        }
    }

    static const ConsoleBinding kCompat[] = {
        {Lua_UOFlow_bootstrap, "uow.bootstrap"},
        {Lua_UOFlow_Spell_cast, "uow.cmd.cast"},
        {Lua_UOFlow_Spell_cast_on_id, "uow.cmd.cast_on_id"},
        {Lua_UOFlow_Target_commit_obj, "uow.cmd.commit_obj"},
        {Lua_UOFlow_Target_commit_ground, "uow.cmd.commit_ground"},
        {Lua_UOFlow_Target_cancel, "uow.cmd.cancel_target"},
        {Lua_UOFlow_Target_force_open, "uow.cmd.force_open"},
        {Lua_UOFlow_status, "uow.cmd.status"},
    };

    for (const auto& binding : kCompat) {
        if (!RegisterViaClient(L, binding.fn, binding.name)) {
            char buf[256];
            sprintf_s(buf,
                      sizeof(buf),
                      "InstallUOFlowConsoleBindingsIfNeeded: compat register failed for '%s'",
                      binding.name);
            WriteRawLog(buf);
        }
    }

    g_consoleBound = true;
    Util::OwnerPump::SetDrainAllowed(true);

    char buf[256];
    sprintf_s(buf,
              sizeof(buf),
              "[LuaConsole] UOFlow.* console bindings installed (owner_context ctx=%p)",
              ownerCtx);
    WriteRawLog(buf);
    return true;
}

static void ForceLateCastWrapInstall(lua_State* L, const char* reason)
{
    if (!L)
        return;
    DWORD now = GetTickCount();
    std::lock_guard<std::mutex> lock(g_lateWrapMutex);
    for (auto& target : g_lateCastTargets) {
        if (target.installed)
            continue;
        if (!WrapLuaGlobal(L, target, now))
            continue;
        target.installed = true;
        target.nextDeferredLog = 0;
        uint32_t previous = g_actionWrapperMask.fetch_or(target.bit, std::memory_order_acq_rel);
        uint32_t updated = previous | target.bit;
        if (updated == kAllActionWrappers)
            InterlockedExchange(&g_actionWrappersInstalled, 1);
        char buf[192];
        sprintf_s(buf,
                  sizeof(buf),
                  "[LateWrap] wrapped %s (%s)",
                  target.name,
                  reason ? reason : "manual");
        WriteRawLog(buf);
    }
}

static void NoteNoClickSendPacket(uint8_t id, int len, unsigned counter)
{
    if (!g_noClickState.active)
        return;
    if (g_noClickState.sendLogged)
        return;
    if (id == 0)
        return;
    g_noClickState.firstSendId = id;
    g_noClickState.sendLogged = true;
    char buf[256];
    sprintf_s(buf,
              sizeof(buf),
              "[NoClick] cast send observed id=%02X len=%d counter=%u",
              id,
              len,
              counter);
    WriteRawLog(buf);
}

static void ResetNoClickState(const char* reason)
{
    if (g_noClickState.active && reason && *reason) {
        char buf[256];
        sprintf_s(buf,
                  sizeof(buf),
                  "[NoClick] reset spell=%d reason=%s",
                  g_noClickState.spellId,
                  reason);
        WriteRawLog(buf);
    }
    g_noClickState = {};
}

static void LogUOFlowStatus(const char* tag)
{
    bool haveOrig = (g_origCastSpell != nullptr);
    bool haveGate = HasAnyGateReplayContext();
    bool wrapperReady = CastWrapperReady();
    uint32_t ownerTid = g_ownerThreadId.load(std::memory_order_acquire);
    char ownerBuf[32] = {};
    const char* ownerLabel = "none";
    if (ownerTid != 0) {
        sprintf_s(ownerBuf, sizeof(ownerBuf), "%u", ownerTid);
        ownerLabel = ownerBuf;
    }
    const char* consoleLabel = g_consoleBound ? "bound" : "unbound";
    const char* fallbackLabel = TargetFallbackReady() ? "open" : "blocked";
    const char* wrapperLabel = wrapperReady ? "yes" : "no";
    auto formatPtr = [](uintptr_t value, char* out, size_t len) {
        if (!out || len == 0)
            return;
        if (!value) {
            strcpy_s(out, len, "none");
            return;
        }
        sprintf_s(out, len, "0x%llX", static_cast<unsigned long long>(value));
    };
    char gateBuf[32];
    char origBuf[32];
    char origOnIdBuf[32];
    formatPtr(g_gateSelectedTarget, gateBuf, sizeof(gateBuf));
    formatPtr(reinterpret_cast<uintptr_t>(g_origCastSpell), origBuf, sizeof(origBuf));
    formatPtr(reinterpret_cast<uintptr_t>(g_origCastSpellOnId), origOnIdBuf, sizeof(origOnIdBuf));
    TargetRequestTuple tuple = g_targetRequestTuple;
    char tupleBuf[32];
    const char* tupleLabel = "none";
    if (tuple.learned) {
        sprintf_s(tupleBuf, sizeof(tupleBuf), "(%d,%d,%d)", tuple.action, tuple.sub, tuple.extra);
        tupleLabel = tupleBuf;
    }
    char buf[352];
    sprintf_s(buf,
              sizeof(buf),
              "tag=%s orig=(%s/%s) gate_ctx=(%s/%s) owner=%s console=%s wrapper_ready=%s direct_toggle=%d fallback_target=%s rt_req_last=%s orig_on_id=%s",
              tag ? tag : "UOFlow.status",
              origBuf,
              haveOrig ? "ok" : "missing",
              gateBuf,
              haveGate ? "ok" : "missing",
              ownerLabel,
              consoleLabel,
              wrapperLabel,
              g_allowDirectCastFallback ? 1 : 0,
              fallbackLabel,
              tupleLabel,
              origOnIdBuf);
    WriteRawLog(buf);
}

static uint32_t ResolveTargetWindowMs()
{
    uint32_t window = TargetCorrelatorGetWindow();
    if (window == 0)
        window = kTargetFallbackWindowMs;
    return window;
}

static bool MapSpellIdForClient(int spellId, int& mappedId)
{
    static constexpr int kMinSpellId = 1;
    static constexpr int kMaxSpellId = 1024;
    if (spellId < kMinSpellId || spellId > kMaxSpellId)
        return false;
    mappedId = spellId;
    return true;
}

static void LogCastPath(const char* path, uint32_t tok, const char* status, const char* reason)
{
    char buf[256];
    sprintf_s(buf,
              sizeof(buf),
              "[NoClick] cast path: %s tok=%u status=%s%s%s",
              path ? path : "unknown",
              tok,
              status ? status : "unknown",
              reason ? " reason=" : "",
              reason ? reason : "");
    WriteRawLog(buf);
}

static void LogSpellCastFailure(const char* branch, const char* reason, int spellId, uint32_t tok)
{
    char buf[320];
    sprintf_s(buf,
              sizeof(buf),
              "tag=UOFlow.Spell.cast_fail branch=%s reason=%s spell=%d tok=%u",
              branch ? branch : "unknown",
              reason ? reason : "unknown",
              spellId,
              tok);
    WriteRawLog(buf);
}

static void LogImmediateSpellFailure(int spellId, const char* branch, const char* reason)
{
    uint32_t tok = CurrentCastToken();
    char buf[256];
    sprintf_s(buf,
              sizeof(buf),
              "[Spell] fail spell=%d reason=%s branch=%s tok=%u",
              spellId,
              reason ? reason : "unknown",
              branch ? branch : "unknown",
              tok);
    WriteRawLog(buf);
    LogSpellCastFailure(branch, reason, spellId, tok);
}

static void ReportActiveSpellFailure(const char* branch, const char* reason)
{
    if (!g_noClickState.active)
        return;
    uint32_t tok = CurrentCastToken();
    char buf[256];
    sprintf_s(buf,
              sizeof(buf),
              "[Spell] fail spell=%d reason=%s branch=%s tok=%u",
              g_noClickState.spellId,
              reason ? reason : "unknown",
              branch ? branch : "unknown",
              tok);
    WriteRawLog(buf);
    LogSpellCastFailure(branch, reason, g_noClickState.spellId, tok);
    ResetNoClickState(reason ? reason : branch);
}

static bool EnsureNoClickActive(const char* action)
{
    if (g_noClickState.active)
        return true;
    char buf[256];
    sprintf_s(buf,
              sizeof(buf),
              "[NoClick] %s rejected: no active spell",
              action ? action : "commit");
    WriteRawLog(buf);
    return false;
}

static bool EnsureWithinTargetWindow(const char* action)
{
    const uint32_t window = ResolveTargetWindowMs();
    const DWORD now = GetTickCount();
    const DWORD elapsed = now - g_noClickState.startTick;
    if (window > 0 && elapsed > window) {
        char buf[256];
        sprintf_s(buf,
                  sizeof(buf),
                  "[NoClick] %s exceeded target window spell=%d elapsed=%lu window=%u",
                  action ? action : "commit",
                  g_noClickState.spellId,
                  static_cast<unsigned long>(elapsed),
                  window);
        WriteRawLog(buf);
        ReportActiveSpellFailure("target_window", "window_expired");
        return false;
    }
    MaybeLogPowerWordsTimeout(action ? action : "window_check");
    return true;
}

static void LogTargetOpen(TargetCommitKind kind)
{
    if (g_noClickState.openLogged)
        return;
    DWORD now = GetTickCount();
    DWORD dt = now - g_noClickState.startTick;
    char buf[256];
    sprintf_s(buf,
              sizeof(buf),
              "[Target] open t0=%lu mode=%s",
              static_cast<unsigned long>(dt),
              TargetKindName(kind));
    WriteRawLog(buf);
    g_noClickState.openLogged = true;
    g_noClickState.openKind = kind;
}

static void LogTargetCommit(TargetCommitKind kind, uint32_t objectId, int x, int y, int facet, const char* via = nullptr)
{
    char buf[256];
    switch (kind) {
    case TargetCommitKind::Ground:
        sprintf_s(buf,
                  sizeof(buf),
                  "[Target] commit kind=%s obj=%u xy=<%d,%d> facet=%d via=%s",
                  TargetKindName(kind),
                  objectId,
                  x,
                  y,
                  facet,
                  via ? via : "<unknown>");
        break;
    case TargetCommitKind::Cancel:
        sprintf_s(buf,
                  sizeof(buf),
                  "[Target] commit kind=%s via=%s",
                  TargetKindName(kind),
                  via ? via : "<unknown>");
        break;
    default:
        sprintf_s(buf,
                  sizeof(buf),
                  "[Target] commit kind=%s obj=%u via=%s",
                  TargetKindName(kind),
                  objectId,
                  via ? via : "<unknown>");
        break;
    }
    WriteRawLog(buf);
}

static void CompleteNoClickSpell()
{
    MaybeLogPowerWordsTimeout("complete");
    DWORD elapsed = GetTickCount() - g_noClickState.startTick;
    char buf[256];
    sprintf_s(buf,
              sizeof(buf),
              "[Spell] done spell=%d elapsed=%lu ms",
              g_noClickState.spellId,
              static_cast<unsigned long>(elapsed));
    WriteRawLog(buf);
    ResetNoClickState(nullptr);
}

static bool DispatchNoClickCommand(const char* name, std::function<bool()> fn)
{
    if (!fn)
        return false;
    auto result = std::make_shared<bool>(false);
    auto task = [fn = std::move(fn), result]() mutable {
        *result = fn();
    };
    if (Util::OwnerPump::Invoke(name, std::move(task)))
        return *result;
    return true;
}

static bool CastWrapperReady()
{
    return (g_castSpellRegistryRef != LUA_NOREF) || (g_origUserActionCastSpell != nullptr);
}

static bool CastOnIdWrapperReady()
{
    return (g_castSpellOnIdRegistryRef != LUA_NOREF) || (g_origUserActionCastSpellOnId != nullptr);
}

static bool InvokeCastWrapper(lua_State* L, int spellId)
{
    if (!L)
        return false;
    int top = lua_gettop(L);
    lua_pushinteger(L, spellId);
    int rc = InvokeClientLuaFn(reinterpret_cast<LuaFn>(&Lua_UserActionCastSpell_W), "UserActionCastSpell_W", L);
    lua_settop(L, top);
    return rc >= 0;
}

static bool InvokeCastOnIdWrapper(lua_State* L, int spellId, uint32_t objectId)
{
    if (!L || objectId == 0)
        return false;
    int top = lua_gettop(L);
    lua_pushinteger(L, spellId);
    lua_pushinteger(L, static_cast<lua_Integer>(objectId));
    int rc = InvokeClientLuaFn(reinterpret_cast<LuaFn>(&Lua_UserActionCastSpellOnId_W), "UserActionCastSpellOnId_W", L);
    lua_settop(L, top);
    return rc >= 0;
}

static bool InvokeCastOriginal(lua_State* L, int mappedSpellId, int displaySpellId)
{
    if (!g_allowDirectCastFallback || !g_origCastSpell || !L)
        return false;
    bool ok = false;
    bool ranInline = Util::OwnerPump::Invoke("UOFlow.cast.orig", [L, mappedSpellId, &ok]() {
        int top = lua_gettop(L);
        lua_pushinteger(L, mappedSpellId);
        int rc = InvokeClientLuaFn(reinterpret_cast<LuaFn>(g_origCastSpell), "UserActionCastSpell", L);
        lua_settop(L, top);
        ok = (rc >= 0);
    });
    if (!ranInline) {
        WriteRawLog("[NoClick] cast orig path deferred; owner thread unavailable");
        return false;
    }
    if (ok) {
        char msg[128];
        sprintf_s(msg, sizeof(msg), "[NoClick] cast via orig path spell=%u", static_cast<unsigned>(displaySpellId));
        WriteRawLog(msg);
    }
    return ok;
}

static bool InvokeCastOnIdOriginal(lua_State* L, int mappedSpellId, uint32_t objectId, int displaySpellId)
{
    if (!g_allowDirectCastFallback || !g_origCastSpellOnId || !L || objectId == 0)
        return false;
    bool ok = false;
    bool ranInline = Util::OwnerPump::Invoke("UOFlow.cast_on_id.orig", [L, mappedSpellId, objectId, &ok]() {
        int top = lua_gettop(L);
        lua_pushinteger(L, mappedSpellId);
        lua_pushinteger(L, static_cast<lua_Integer>(objectId));
        int rc = InvokeClientLuaFn(reinterpret_cast<LuaFn>(g_origCastSpellOnId), "UserActionCastSpellOnId", L);
        lua_settop(L, top);
        ok = (rc >= 0);
    });
    if (!ranInline) {
        WriteRawLog("[NoClick] cast_on_id orig path deferred; owner thread unavailable");
        return false;
    }
    if (ok) {
        char generic[128];
        sprintf_s(generic, sizeof(generic), "[NoClick] cast via orig path spell=%u", static_cast<unsigned>(displaySpellId));
        WriteRawLog(generic);
        char msg[160];
        sprintf_s(msg,
                  sizeof(msg),
                  "[NoClick] cast_on_id via orig path spell=%u target=%u",
                  static_cast<unsigned>(displaySpellId),
                  objectId);
        WriteRawLog(msg);
    }
    return ok;
}

// Casting decision tree:
// 1) Invoke the client's Lua wrapper when it is registered.
// 2) Optionally call the original native entry point (guarded by config + id mapping).
// 3) Reuse cached gate contexts when both wrapper/direct are unavailable.
// 4) If no cursor opens (or we relied on direct/gate ctx), explicitly raise targeting via Clear/Request.
static bool NoClickCastSpell_Internal(int spellId)
{
    if (spellId <= 0) {
        WriteRawLog("[NoClick] cast rejected: spell id must be positive");
        LogImmediateSpellFailure(spellId, "guard", "invalid_spell");
        return false;
    }
    auto* L = static_cast<lua_State*>(Engine::LuaState());
    if (!L) {
        WriteRawLog("[NoClick] cast rejected: no Lua state available");
        LogImmediateSpellFailure(spellId, "guard", "no_lua_state");
        return false;
    }

    DWORD now = GetTickCount();
    const uint32_t window = ResolveTargetWindowMs();
    if (g_noClickState.active) {
        DWORD elapsed = now - g_noClickState.startTick;
        if (window == 0 || elapsed <= window) {
            if (!g_noClickState.busyLogged) {
                char buf[256];
                sprintf_s(buf,
                          sizeof(buf),
                          "[NoClick] reset spell=%d reason=busy",
                          g_noClickState.spellId);
                WriteRawLog(buf);
                g_noClickState.busyLogged = true;
            }
            LogImmediateSpellFailure(spellId, "guard", "busy");
            return false;
        }
        ResetNoClickState("timeout");
    }

    g_noClickState = {};
    g_noClickState.active = true;
    g_noClickState.spellId = spellId;
    g_noClickState.startTick = now;
    g_noClickState.openKind = TargetCommitKind::Object;
    g_noClickState.powerWordsDeadline = now + kPowerWordsWindowMs;

    char buf[256];
    sprintf_s(buf,
              sizeof(buf),
              "[Cast] spell=%d dispatched owner=%u",
              spellId,
              GetCurrentThreadId());
    WriteRawLog(buf);

    const bool wrapperReady = CastWrapperReady();
    const bool directEligible = g_allowDirectCastFallback && g_origCastSpell;
    bool manualTokenAssigned = false;
    uint32_t manualTokenPrevious = 0;
    if (!wrapperReady && !directEligible)
        manualTokenAssigned = ActivateManualCastToken(manualTokenPrevious, "wrapper_not_ready");
    uint32_t tok = CurrentCastToken();
    char diag[256];
    sprintf_s(diag,
              sizeof(diag),
              "[NoClick] cast start: path=%s tok=%u spell=%d send_id_seen=none",
              g_gateSelectedName ? g_gateSelectedName : "unknown",
              tok,
              spellId);
    WriteRawLog(diag);
    bool wrapperOk = false;
    if (wrapperReady) {
        wrapperOk = InvokeCastWrapper(L, spellId);
        LogCastPath("wrapper", tok, wrapperOk ? "ok" : "fail", wrapperOk ? nullptr : "invoke_failed");
    } else {
        LogCastPath("wrapper", tok, "skipped", "not_ready");
    }

    bool directOk = false;
    if (!wrapperOk) {
        if (directEligible) {
            int mappedId = 0;
            if (MapSpellIdForClient(spellId, mappedId)) {
                directOk = InvokeCastOriginal(L, mappedId, spellId);
                LogCastPath("direct", tok, directOk ? "ok" : "fail", directOk ? nullptr : "invoke_failed");
            } else {
                LogCastPath("direct", tok, "skipped", "map_failed");
            }
        } else {
            LogCastPath("direct", tok, "skipped", g_allowDirectCastFallback ? "orig_missing" : "toggle_off");
        }
    } else {
        LogCastPath("direct", tok, "skipped", "wrapper_ok");
    }

    if (!wrapperReady && !directEligible) {
        bool fallbackOk = OpenTargetForSpell_Fallback("wrapper_not_ready");
        LogCastPath("fallback", tok, fallbackOk ? "ok" : "fail", fallbackOk ? "wrapper_not_ready" : "request_failed");
        LogUOFlowStatus("UOFlow.Spell.cast_prereq");
        RestoreManualCastToken(manualTokenPrevious, manualTokenAssigned);
        if (!fallbackOk) {
            ReportActiveSpellFailure("fallback", "request_failed");
            return false;
        }
        return true;
    }
    bool gateCtxOk = false;
    bool gateCtxAvailable = HasGateReplayContext(spellId) || HasAnyGateReplayContext();
    if (!wrapperOk && !directOk) {
        if (gateCtxAvailable) {
            gateCtxOk = Engine::Lua::CastSpellNative(spellId);
            LogCastPath("gate_ctx", tok, gateCtxOk ? "ok" : "fail", gateCtxOk ? nullptr : "native_failed");
            if (gateCtxOk) {
                char bufFallback[192];
                sprintf_s(bufFallback,
                          sizeof(bufFallback),
                          "[NoClick] cast used cached gate context for spell=%d",
                          spellId);
                WriteRawLog(bufFallback);
            }
        } else {
            LogCastPath("gate_ctx", tok, "skipped", "ctx_missing");
        }
    } else {
        LogCastPath("gate_ctx", tok, "skipped", "not_needed");
    }

    bool castOk = wrapperOk || directOk || gateCtxOk;
    if (!castOk) {
        char bufPrereq[256];
        sprintf_s(bufPrereq,
                  sizeof(bufPrereq),
                  "[NoClick] prerequisites missing: orig=%s gate_ctx=%s",
                  g_origCastSpell ? "yes" : "no",
                  gateCtxAvailable ? "yes" : "no");
        WriteRawLog(bufPrereq);
        bool fallbackOk = OpenTargetForSpell_Fallback("pipeline_exhausted");
        LogCastPath("fallback", tok, fallbackOk ? "ok" : "fail", fallbackOk ? "pipeline_exhausted" : "request_failed");
        LogUOFlowStatus("UOFlow.Spell.cast_prereq");
        if (!fallbackOk) {
            ReportActiveSpellFailure("pipeline", "fallback_failed");
            return false;
        }
        return true;
    }

    bool sendObserved = WaitForSendLogged(kTargetFallbackSendWaitMs);
    bool fallbackForDirectOnly = directOk && !wrapperReady && !gateCtxAvailable;
    bool fallbackForGateCtx = gateCtxOk;
    bool needTargetFallback = !sendObserved || fallbackForDirectOnly || fallbackForGateCtx;
    const char* gateReason = "not_needed";
    if (!sendObserved)
        gateReason = "send_missing";
    else if (fallbackForGateCtx)
        gateReason = "gate_ctx";
    else if (fallbackForDirectOnly)
        gateReason = "direct_orig";
    if (needTargetFallback) {
        bool fallbackOk = OpenTargetForSpell_Fallback(gateReason);
        LogCastPath("fallback", tok, fallbackOk ? "ok" : "fail", fallbackOk ? gateReason : "open_failed");
        if (!fallbackOk) {
            ReportActiveSpellFailure("gate", "fallback_failed");
            return false;
        }
    } else {
        LogCastPath("fallback", tok, "skipped", gateReason);
    }

    return true;
}

static bool CommitTargetObject_Internal(uint32_t objectId, TargetCommitKind kind)
{
    if (!EnsureNoClickActive("commit_obj"))
        return false;
    if (!EnsureWithinTargetWindow("commit_obj"))
        return false;
    auto* L = static_cast<lua_State*>(Engine::LuaState());
    if (!L) {
        WriteRawLog("[NoClick] commit rejected: no Lua state");
        ReportActiveSpellFailure("commit_obj", "lua_state_missing");
        return false;
    }
    if (!g_origHandleSingleLeftClkTarget) {
        WriteRawLog("[NoClick] commit rejected: HandleSingleLeftClkTarget original missing");
        ReportActiveSpellFailure("commit_obj", "handler_missing");
        return false;
    }

    g_targetCorr.Arm("UOW_HandleSingleLeftClkTarget");
    LogTargetOpen(kind);

    int top = lua_gettop(L);
    lua_pushinteger(L, static_cast<lua_Integer>(objectId));
    int rc = InvokeClientLuaFn(g_origHandleSingleLeftClkTarget, "HandleSingleLeftClkTarget", L);
    lua_settop(L, top);
    if (rc < 0) {
        ReportActiveSpellFailure("commit_obj", "invoke_failed");
        return false;
    }

    LogTargetCommit(kind, objectId, 0, 0, 0, "HandleSingleLeftClkTarget");
    CompleteNoClickSpell();
    return true;
}

static bool CommitTargetGround_Internal(int x, int y, int facet)
{
    if (!EnsureNoClickActive("commit_ground"))
        return false;
    if (!EnsureWithinTargetWindow("commit_ground"))
        return false;
    auto* L = static_cast<lua_State*>(Engine::LuaState());
    if (!L) {
        WriteRawLog("[NoClick] ground commit rejected: no Lua state");
        ReportActiveSpellFailure("commit_ground", "lua_state_missing");
        return false;
    }
    if (!g_origHandleSingleLeftClkTarget) {
        WriteRawLog("[NoClick] ground commit rejected: HandleSingleLeftClkTarget original missing");
        ReportActiveSpellFailure("commit_ground", "handler_missing");
        return false;
    }

    uint32_t encoded = EncodeGroundTarget(x, y);
    g_targetCorr.Arm("UOW_HandleSingleLeftClkTarget");
    LogTargetOpen(TargetCommitKind::Ground);

    int top = lua_gettop(L);
    lua_pushinteger(L, static_cast<lua_Integer>(encoded));
    int rc = InvokeClientLuaFn(g_origHandleSingleLeftClkTarget, "HandleSingleLeftClkTarget", L);
    lua_settop(L, top);
    if (rc < 0) {
        ReportActiveSpellFailure("commit_ground", "invoke_failed");
        return false;
    }

    LogTargetCommit(TargetCommitKind::Ground, encoded, x, y, facet, "HandleSingleLeftClkTarget");
    CompleteNoClickSpell();
    return true;
}

static bool CancelTarget_Internal()
{
    if (!EnsureNoClickActive("cancel_target"))
        return false;
    auto* L = static_cast<lua_State*>(Engine::LuaState());
    if (!L) {
        WriteRawLog("[NoClick] cancel rejected: no Lua state");
        ReportActiveSpellFailure("cancel", "lua_state_missing");
        return false;
    }

    bool usedClear = false;
    int top = lua_gettop(L);
    if (g_origClearCurrentTarget) {
        g_targetCorr.Arm("UOW_ClearCurrentTarget");
        LogTargetOpen(TargetCommitKind::Cancel);
        int rc = InvokeClientLuaFn(g_origClearCurrentTarget, "ClearCurrentTarget", L);
        lua_settop(L, top);
        if (rc < 0) {
            ReportActiveSpellFailure("cancel", "invoke_failed");
            return false;
        }
        usedClear = true;
    } else if (g_origHandleSingleLeftClkTarget) {
        g_targetCorr.Arm("UOW_HandleSingleLeftClkTarget");
        LogTargetOpen(TargetCommitKind::Cancel);
        lua_pushinteger(L, 0);
        int rc = InvokeClientLuaFn(g_origHandleSingleLeftClkTarget, "HandleSingleLeftClkTarget", L);
        lua_settop(L, top);
        if (rc < 0) {
            ReportActiveSpellFailure("cancel", "invoke_failed");
            return false;
        }
        usedClear = true;
    }

    if (!usedClear) {
        WriteRawLog("[NoClick] cancel rejected: no clear/handle function available");
        ReportActiveSpellFailure("cancel", "handler_missing");
        return false;
    }

    const char* via = g_origClearCurrentTarget ? "ClearCurrentTarget" : "HandleSingleLeftClkTarget";
    LogTargetCommit(TargetCommitKind::Cancel, 0, 0, 0, 0, via);
    CompleteNoClickSpell();
    return true;
}

static bool TryCastSpellOnIdViaClient(lua_State* L, int spellId, uint32_t objectId)
{
    if (!L || objectId == 0)
        return false;
    if (CastOnIdWrapperReady() && InvokeCastOnIdWrapper(L, spellId, objectId))
        return true;
    if (!g_allowDirectCastFallback || !g_origCastSpellOnId)
        return false;
    int mappedId = 0;
    if (!MapSpellIdForClient(spellId, mappedId))
        return false;
    return InvokeCastOnIdOriginal(L, mappedId, objectId, spellId);
}

static bool NoClickCastSpellOnId_Internal(int spellId, uint32_t objectId)
{
    auto* L = static_cast<lua_State*>(Engine::LuaState());
    if (TryCastSpellOnIdViaClient(L, spellId, objectId))
        return true;
    if (!NoClickCastSpell_Internal(spellId))
        return false;
    return CommitTargetObject_Internal(objectId, TargetCommitKind::Object);
}

static int __cdecl Lua_UOFlow_Spell_cast(lua_State* L)
{
    int spellId = 0;
    if (L && lua_gettop(L) >= 1 && lua_type(L, 1) == LUA_TNUMBER)
        spellId = static_cast<int>(lua_tointeger(L, 1));
    if (spellId <= 0) {
        WriteRawLog("[Lua] UOFlow.Spell.cast rejected: invalid spell id");
        lua_pushboolean(L, 0);
        return 1;
    }
    bool ok = DispatchNoClickCommand("UOFlow.Spell.cast", [spellId]() { return NoClickCastSpell_Internal(spellId); });
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

static int __cdecl Lua_UOFlow_Spell_cast_on_id(lua_State* L)
{
    int spellId = 0;
    uint32_t objectId = 0;
    if (L && lua_gettop(L) >= 1 && lua_type(L, 1) == LUA_TNUMBER)
        spellId = static_cast<int>(lua_tointeger(L, 1));
    if (L && lua_gettop(L) >= 2 && lua_type(L, 2) == LUA_TNUMBER)
        objectId = static_cast<uint32_t>(lua_tointeger(L, 2));
    if (spellId <= 0 || objectId == 0) {
        WriteRawLog("[Lua] UOFlow.Spell.cast_on_id rejected: invalid spell or object id");
        lua_pushboolean(L, 0);
        return 1;
    }
    bool ok = DispatchNoClickCommand("UOFlow.Spell.cast_on_id", [spellId, objectId]() {
        return NoClickCastSpellOnId_Internal(spellId, objectId);
    });
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

static int __cdecl Lua_UOFlow_Target_commit_obj(lua_State* L)
{
    uint32_t objectId = 0;
    if (L && lua_gettop(L) >= 1 && lua_type(L, 1) == LUA_TNUMBER)
        objectId = static_cast<uint32_t>(lua_tointeger(L, 1));
    if (objectId == 0) {
        WriteRawLog("[Lua] UOFlow.Target.commit_obj rejected: invalid object id");
        lua_pushboolean(L, 0);
        return 1;
    }
    bool ok = DispatchNoClickCommand("UOFlow.Target.commit_obj", [objectId]() {
        return CommitTargetObject_Internal(objectId, TargetCommitKind::Object);
    });
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

static int __cdecl Lua_UOFlow_Target_commit_ground(lua_State* L)
{
    int x = 0;
    int y = 0;
    int facet = 0;
    if (L && lua_gettop(L) >= 1 && lua_type(L, 1) == LUA_TNUMBER)
        x = static_cast<int>(lua_tointeger(L, 1));
    if (L && lua_gettop(L) >= 2 && lua_type(L, 2) == LUA_TNUMBER)
        y = static_cast<int>(lua_tointeger(L, 2));
    if (L && lua_gettop(L) >= 3 && lua_type(L, 3) == LUA_TNUMBER)
        facet = static_cast<int>(lua_tointeger(L, 3));
    bool ok = DispatchNoClickCommand("UOFlow.Target.commit_ground", [x, y, facet]() {
        return CommitTargetGround_Internal(x, y, facet);
    });
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

static int __cdecl Lua_UOFlow_Target_cancel(lua_State* L)
{
    bool ok = DispatchNoClickCommand("UOFlow.Target.cancel", []() { return CancelTarget_Internal(); });
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

static int __cdecl Lua_UOFlow_Target_force_open(lua_State* L)
{
    bool ok = DispatchNoClickCommand("UOFlow.Target.force_open", []() { return OpenTargetForSpell_Fallback("force_open"); });
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

static int __cdecl Lua_UOFlow_bootstrap(lua_State* L)
{
    InstallUOFlowConsoleBindingsIfNeeded(CanonicalOwnerContext(), "manual");
    if (auto* state = static_cast<lua_State*>(Engine::LuaState()))
        ForceLateCastWrapInstall(state, "manual");
    LogUOFlowStatus("UOFlow.bootstrap");
    lua_pushboolean(L, g_consoleBound ? 1 : 0);
    return 1;
}

static int __cdecl Lua_UOFlow_status(lua_State* L)
{
    LogUOFlowStatus("UOFlow.status");
    lua_pushboolean(L, g_consoleBound ? 1 : 0);
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
    InstallUOFlowConsoleBindingsIfNeeded(CanonicalOwnerContext(), "UserActionCastSpell_W");
    int topBefore = lua_gettop(L);
    const uint32_t previousTok = g_tlsCurrentCastToken;
    const uint32_t token = NextCastToken();
    g_tlsCurrentCastToken = token;
    g_lastCastToken.store(token, std::memory_order_release);
    ArmWordsLogWindow(token);

    DWORD now = GetTickCount();
    DWORD prevAttempt = g_lastCastAttemptTick.exchange(now, std::memory_order_acq_rel);
    DWORD sincePrevAttempt = prevAttempt ? (now - prevAttempt) : 0;
    DWORD lastSuccess = g_lastSuccessfulCastTick.load(std::memory_order_acquire);
    DWORD sinceLastSuccess = lastSuccess ? (now - lastSuccess) : 0;

    int spellId = 0;
    if (L && lua_gettop(L) >= 1 && lua_type(L, 1) == LUA_TNUMBER) {
        spellId = static_cast<int>(lua_tointeger(L, 1));
    }
    char castUiMsg[160];
    sprintf_s(castUiMsg, sizeof(castUiMsg), "[CastUI] CastSpell invoked (spell=%d)", spellId);
    WriteRawLog(castUiMsg);
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
    LuaReturnInfo retInfo{};

    bool usedSaved = false;
    int savedCount = -1;
    bool usedDirect = false;
    int directValue = 0;
    bool usedRegistry = false;

    int rc = CallRegistryOriginal(L, "UserActionCastSpell", g_castSpellRegistryRef);
    if (rc >= 0) {
        usedRegistry = true;
        savedCount = rc;
        retInfo = CaptureLuaReturn(L, savedCount);
        if (g_traceLuaVerbose && savedCount > 0)
            LogLuaReturns(L, "UserActionCastSpell", savedCount);
    } else {
        rc = CallSavedOriginal(L, "UserActionCastSpell__orig");
        if (rc >= 0) {
            usedSaved = true;
            savedCount = rc;
            retInfo = CaptureLuaReturn(L, savedCount);
            if (g_traceLuaVerbose && savedCount > 0)
                LogLuaReturns(L, "UserActionCastSpell", savedCount);
        } else if (g_origUserActionCastSpell) {
            directValue = InvokeClientLuaFn(g_origUserActionCastSpell, "UserActionCastSpell", L);
            usedDirect = true;
            retInfo = CaptureLuaReturn(L, directValue);
            if (g_traceLuaVerbose && directValue > 0)
                LogLuaReturns(L, "UserActionCastSpell", directValue);
        } else {
            WriteRawLog("[Lua] UserActionCastSpell original missing (saved and ptr)");
            UowTraceCollectRAs();
            unsigned missPathId = LogCastSpellPath(token, g_castSpellLastRAs, ownerMatch);
            if (g_logCastSpellCallLists)
                DumpCastSpellCallees(g_castSpellLastRAs, missPathId, token, false);
            if (gateArmed)
                GateDisarmForCast("UserActionCastSpell:missing_orig");
            ReleaseCastPacket(token);
            GuardLuaStack(L, "UserActionCastSpell", topBefore, 0);
            g_tlsCurrentCastToken = previousTok;
            return 0;
        }
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
    const char* callKind = usedRegistry ? "registry" : (usedSaved ? "saved" : "direct");
    const int returnValue = (usedRegistry || usedSaved) ? savedCount : directValue;
    sprintf_s(detail, sizeof(detail),
        "[Lua] UserActionCastSpell rc=%d packets(before=%u after=%u delta=%u) tok=%u call=%s spell=%d attemptDelta=%u sinceSuccess=%u",
        returnValue, sentBefore, sentAfter, delta, token, callKind, spellId,
        sincePrevAttempt, sinceLastSuccess);
    WriteRawLog(detail);
    LogReturnBanner(L, "UserActionCastSpell", retInfo, g_castSpellReturnBannerLogged);
    LogCastUiReturn(L, "CastSpell", retInfo);

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

    if (gateArmed) {
        if (!packetSent && g_enableCastGateProbes) {
            g_gatePendingToken.store(token, std::memory_order_release);
            g_gatePendingSpell.store(spellId, std::memory_order_release);
            char buf[192];
            sprintf_s(buf, sizeof(buf),
                "[Gate3350] pending capture tok=%u spell=%d (awaiting helper)",
                token,
                spellId);
            WriteRawLog(buf);
        } else {
            GateDisarmForCast(packetSent ? "UserActionCastSpell:packet" : "UserActionCastSpell:no_packet");
        }
    }

    GuardLuaStack(L, "UserActionCastSpell", topBefore, returnValue);
    g_tlsCurrentCastToken = previousTok;
    return returnValue;
}

static int __cdecl Lua_UserActionCastSpellOnId_W(lua_State* L)
{
    InstallUOFlowConsoleBindingsIfNeeded(CanonicalOwnerContext(), "UserActionCastSpellOnId_W");
    int topBefore = lua_gettop(L);
    int spellId = 0;
    int targetId = 0;
    if (L) {
        int top = lua_gettop(L);
        if (top >= 1 && lua_type(L, 1) == LUA_TNUMBER)
            spellId = static_cast<int>(lua_tointeger(L, 1));
        if (top >= 2 && lua_type(L, 2) == LUA_TNUMBER)
            targetId = static_cast<int>(lua_tointeger(L, 2));
    }
    char castUiMsg[192];
    sprintf_s(castUiMsg,
              sizeof(castUiMsg),
              "[CastUI] CastSpellOnId invoked (spell=%d, target=%d)",
              spellId,
              targetId);
    WriteRawLog(castUiMsg);
    UowTracePushSpell(spellId);
    CastCorrelator::OnCastAttempt(static_cast<uint32_t>(spellId < 0 ? 0 : spellId));
    uint32_t tok = CurrentCastToken();
    if (g_traceTargetPath) {
        char buf[224];
        sprintf_s(buf,
                  sizeof(buf),
                  "[TargetPath] Enter UserActionCastSpellOnId spell=%d target=%d tok=%u",
                  spellId,
                  targetId,
                  tok);
        WriteRawLog(buf);
    }
    char intro[192];
    sprintf_s(intro, sizeof(intro), "[Lua] UserActionCastSpellOnId() wrapper invoked tok=%u spell=%d target=%d", tok, spellId, targetId);
    WriteRawLog(intro);
    Trace::MarkAction("CastSpellOnId");
    DumpStackTag("CastSpellOnId");
    static volatile LONG s_noPacketLogs = 0;
    static volatile LONG s_upvalueLogs = 0;
    LuaReturnInfo retInfo{};
    if (g_traceLuaVerbose)
        LogLuaArgs(L, "UserActionCastSpellOnId");

    unsigned sentBefore = Net::GetSendCounter();
    bool usedRegistry = false;
    bool usedSaved = false;
    bool usedDirect = false;
    int savedCount = -1;
    int directValue = 0;

    int rc = CallRegistryOriginal(L, "UserActionCastSpellOnId", g_castSpellOnIdRegistryRef);
    if (rc >= 0) {
        usedRegistry = true;
        savedCount = rc;
        retInfo = CaptureLuaReturn(L, savedCount);
        if (g_traceLuaVerbose && savedCount > 0)
            LogLuaReturns(L, "UserActionCastSpellOnId", savedCount);
    } else {
        rc = CallSavedOriginal(L, "UserActionCastSpellOnId__orig");
        if (rc >= 0) {
            usedSaved = true;
            savedCount = rc;
            retInfo = CaptureLuaReturn(L, rc);
            if (g_traceLuaVerbose && rc > 0)
                LogLuaReturns(L, "UserActionCastSpellOnId", rc);
        } else if (g_origUserActionCastSpellOnId) {
            directValue = InvokeClientLuaFn(g_origUserActionCastSpellOnId, "UserActionCastSpellOnId", L);
            usedDirect = true;
            retInfo = CaptureLuaReturn(L, directValue);
            if (g_traceLuaVerbose && directValue > 0)
                LogLuaReturns(L, "UserActionCastSpellOnId", directValue);
        } else {
            WriteRawLog("[Lua] UserActionCastSpellOnId original missing (saved and ptr)");
            if (g_traceTargetPath) {
                char buf[128];
                sprintf_s(buf, sizeof(buf), "[TargetPath] Leave UserActionCastSpellOnId rc=0 tok=%u (missing)", tok);
                WriteRawLog(buf);
            }
            GuardLuaStack(L, "UserActionCastSpellOnId", topBefore, 0);
            return 0;
        }
    }

    if (usedRegistry)
        rc = savedCount;
    else if (usedSaved)
        rc = savedCount;
    else if (usedDirect)
        rc = directValue;

    if (usedRegistry) {
        char exitBuf[160];
        sprintf_s(exitBuf, sizeof(exitBuf), "[Lua] UserActionCastSpellOnId() wrapper exit (registry) tok=%u", tok);
        WriteRawLog(exitBuf);
    } else if (usedSaved) {
        char exitBuf[160];
        sprintf_s(exitBuf, sizeof(exitBuf), "[Lua] UserActionCastSpellOnId() wrapper exit (saved) tok=%u", tok);
        WriteRawLog(exitBuf);
    } else if (usedDirect) {
        char exitBuf[160];
        sprintf_s(exitBuf, sizeof(exitBuf), "[Lua] UserActionCastSpellOnId() wrapper exit (orig ptr) tok=%u", tok);
        WriteRawLog(exitBuf);
    }

    unsigned sentAfter = Net::GetSendCounter();
    unsigned delta = sentAfter - sentBefore;
    char detail[192];
    sprintf_s(detail, sizeof(detail),
        "[Lua] UserActionCastSpellOnId rc=%d packets(before=%u after=%u delta=%u) tok=%u",
        rc, sentBefore, sentAfter, delta, tok);
    WriteRawLog(detail);
    LogReturnBanner(L, "UserActionCastSpellOnId", retInfo, g_castSpellOnIdReturnBannerLogged);
    if (delta > 0) WriteRawLog("[Lua] CastSpellOnId -> packet observed");
    else {
        WriteRawLog("[Lua] CastSpellOnId -> no packet sent");
        LONG order = InterlockedIncrement(&s_noPacketLogs);
        if (order <= 8) {
            LogLuaErrorTop(L, "UserActionCastSpellOnId/noPacket");
            LogSavedOriginalUpvalues(L, "UserActionCastSpellOnId__orig", "UserActionCastSpellOnId", "UserActionCastSpellOnId/upvalues", &s_upvalueLogs);
        }
    }
    if (g_traceTargetPath) {
        char buf[160];
        sprintf_s(buf,
                  sizeof(buf),
                  "[TargetPath] Leave UserActionCastSpellOnId rc=%d tok=%u",
                  rc,
                  tok);
        WriteRawLog(buf);
    }
    GuardLuaStack(L, "UserActionCastSpellOnId", topBefore, rc);
    return rc;
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
    int topBefore = lua_gettop(L);
    uint32_t tok = CurrentCastToken();
    char intro[160];
    sprintf_s(intro, sizeof(intro), "[Lua] HS_ShowTargetingCursor() wrapper invoked tok=%u", tok);
    WriteRawLog(intro);
    char uiIntro[160];
    sprintf_s(uiIntro, sizeof(uiIntro), "[TargetUI] ShowCursor enter tok=%u", tok);
    WriteRawLog(uiIntro);
    if (g_traceTargetPath) {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "[TargetPath] Enter HS_ShowTargetingCursor tok=%u", tok);
        WriteRawLog(buf);
    }
    Trace::MarkAction("HS_ShowTargetingCursor");
    LogLuaArgs(L, "HS_ShowTargetingCursor");
    LuaReturnInfo retInfo{};
    int rc = 0;
    if (g_origHS_ShowTargetingCursor) {
        __try { rc = g_origHS_ShowTargetingCursor(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] HS_ShowTargetingCursor original threw"); }
        retInfo = CaptureLuaReturn(L, rc);
    }
    LogLuaReturns(L, "HS_ShowTargetingCursor", rc);
    char detail[160];
    sprintf_s(detail, sizeof(detail), "[Lua] HS_ShowTargetingCursor rc=%d tok=%u", rc, tok);
    WriteRawLog(detail);
    g_targetCorr.Arm("HS_ShowTargetingCursor");
    LogReturnBanner(L, "HS_ShowTargetingCursor", retInfo, g_hsShowReturnBannerLogged);
    if (g_traceTargetPath) {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "[TargetPath] Leave HS_ShowTargetingCursor rc=%d tok=%u", rc, tok);
        WriteRawLog(buf);
    }
    char uiExit[160];
    sprintf_s(uiExit, sizeof(uiExit), "[TargetUI] ShowCursor exit rc=%d tok=%u", rc, tok);
    WriteRawLog(uiExit);
    GuardLuaStack(L, "HS_ShowTargetingCursor", topBefore, rc);
    return rc;
}

static int __cdecl Lua_HS_HideTargetingCursor_W(lua_State* L)
{
    int topBefore = lua_gettop(L);
    uint32_t tok = CurrentCastToken();
    char intro[160];
    sprintf_s(intro, sizeof(intro), "[Lua] HS_HideTargetingCursor() wrapper invoked tok=%u", tok);
    WriteRawLog(intro);
    char uiIntro[160];
    sprintf_s(uiIntro, sizeof(uiIntro), "[TargetUI] HideCursor enter tok=%u", tok);
    WriteRawLog(uiIntro);
    if (g_traceTargetPath) {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "[TargetPath] Enter HS_HideTargetingCursor tok=%u", tok);
        WriteRawLog(buf);
    }
    Trace::MarkAction("HS_HideTargetingCursor");
    LogLuaArgs(L, "HS_HideTargetingCursor");
    LuaReturnInfo retInfo{};
    int rc = 0;
    if (g_origHS_HideTargetingCursor) {
        __try { rc = g_origHS_HideTargetingCursor(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] HS_HideTargetingCursor original threw"); }
        retInfo = CaptureLuaReturn(L, rc);
    }
    LogLuaReturns(L, "HS_HideTargetingCursor", rc);
    char detail[160];
    sprintf_s(detail, sizeof(detail), "[Lua] HS_HideTargetingCursor rc=%d tok=%u", rc, tok);
    WriteRawLog(detail);
    g_targetCorr.Disarm("HS_HideTargetingCursor");
    LogReturnBanner(L, "HS_HideTargetingCursor", retInfo, g_hsHideReturnBannerLogged);
    if (g_traceTargetPath) {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "[TargetPath] Leave HS_HideTargetingCursor rc=%d tok=%u", rc, tok);
        WriteRawLog(buf);
    }
    char uiExit[160];
    sprintf_s(uiExit, sizeof(uiExit), "[TargetUI] HideCursor exit rc=%d tok=%u", rc, tok);
    WriteRawLog(uiExit);
    GuardLuaStack(L, "HS_HideTargetingCursor", topBefore, rc);
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

static int __cdecl Lua_HandleSingleLeftClkTarget_W(lua_State* L)
{
    if (!g_enableTapTargetWrap) {
        if (g_origHandleSingleLeftClkTarget)
            return g_origHandleSingleLeftClkTarget(L);
        return CallSavedOriginal(L, "HandleSingleLeftClkTarget__orig");
    }
    int topBefore = lua_gettop(L);
    uint32_t tok = CurrentCastToken();
    int targetId = 0;
    if (L && lua_gettop(L) >= 1 && lua_type(L, 1) == LUA_TNUMBER)
        targetId = static_cast<int>(lua_tointeger(L, 1));
    char intro[192];
    sprintf_s(intro,
              sizeof(intro),
              "[Lua] HandleSingleLeftClkTarget() wrapper invoked tok=%u target=%d",
              tok,
              targetId);
    WriteRawLog(intro);
    char clickBuf[192];
    sprintf_s(clickBuf,
              sizeof(clickBuf),
              "[ClickTap] click observed tok=%u target=%d",
              tok,
              targetId);
    WriteRawLog(clickBuf);
    if (g_traceTargetPath) {
        char buf[192];
        sprintf_s(buf,
                  sizeof(buf),
                  "[TargetPath] Enter HandleSingleLeftClkTarget target=%d tok=%u",
                  targetId,
                  tok);
        WriteRawLog(buf);
    }
    Trace::MarkAction("HandleSingleLeftClkTarget");
    LogLuaArgs(L, "HandleSingleLeftClkTarget", 2);
    g_targetCorr.Arm("HandleSingleLeftClkTarget");
    int rc = CallSavedOriginal(L, "HandleSingleLeftClkTarget__orig");
    if (rc < 0 && g_origHandleSingleLeftClkTarget) {
        rc = InvokeClientLuaFn(g_origHandleSingleLeftClkTarget, "HandleSingleLeftClkTarget", L);
    }
    int topAfter = lua_gettop(L);
    char stateBuf[256];
    sprintf_s(stateBuf,
              sizeof(stateBuf),
              "[ClickTap] HandleSingleLeftClkTarget invoked nret=%d top_in=%d top_out=%d target=%d tok=%u",
              rc,
              topBefore,
              topAfter,
              targetId,
              tok);
    WriteRawLog(stateBuf);
    if (g_traceLuaVerbose && rc > 0)
        LogLuaReturns(L, "HandleSingleLeftClkTarget", rc);
    if (g_traceTargetPath) {
        char buf[192];
        sprintf_s(buf,
                  sizeof(buf),
                  "[TargetPath] Leave HandleSingleLeftClkTarget rc=%d tok=%u",
                  rc,
                  tok);
        WriteRawLog(buf);
    }
    GuardLuaStack(L, "HandleSingleLeftClkTarget", topBefore, rc);
    return (rc >= 0) ? rc : 0;
}

static int __cdecl Lua_UserActionSpeechSetText_W(lua_State* L)
{
    int topBefore = lua_gettop(L);
    if (g_traceLuaVerbose)
        LogLuaArgs(L, "UserActionSpeechSetText", 4);
    MaybeLogWordsText(L, "UserActionSpeechSetText", 4, "Speech");
    int rc = CallSavedOriginal(L, "UserActionSpeechSetText__orig");
    if (rc < 0 && g_origUserActionSpeechSetText) {
        rc = InvokeClientLuaFn(g_origUserActionSpeechSetText, "UserActionSpeechSetText", L);
    }
    if (g_traceLuaVerbose && rc > 0)
        LogLuaReturns(L, "UserActionSpeechSetText", rc);
    GuardLuaStack(L, "UserActionSpeechSetText", topBefore, rc);
    return (rc >= 0) ? rc : 0;
}

static int __cdecl Lua_TextLogAddEntry_W(lua_State* L)
{
    int topBefore = lua_gettop(L);
    if (g_traceLuaVerbose)
        LogLuaArgs(L, "TextLogAddEntry", 3);
    const char* logName = nullptr;
    if (L && lua_gettop(L) >= 1 && lua_type(L, 1) == LUA_TSTRING)
        logName = lua_tolstring(L, 1, nullptr);
    MaybeLogWordsText(L, "TextLogAddEntry", 3, logName);
    int rc = CallSavedOriginal(L, "TextLogAddEntry__orig");
    if (rc < 0 && g_origTextLogAddEntry) {
        rc = InvokeClientLuaFn(g_origTextLogAddEntry, "TextLogAddEntry", L);
    }
    if (g_traceLuaVerbose && rc > 0)
        LogLuaReturns(L, "TextLogAddEntry", rc);
    GuardLuaStack(L, "TextLogAddEntry", topBefore, rc);
    return (rc >= 0) ? rc : 0;
}

static int __cdecl Lua_TextLogAddSingleByteEntry_W(lua_State* L)
{
    int topBefore = lua_gettop(L);
    if (g_traceLuaVerbose)
        LogLuaArgs(L, "TextLogAddSingleByteEntry", 3);
    const char* logName = nullptr;
    if (L && lua_gettop(L) >= 1 && lua_type(L, 1) == LUA_TSTRING)
        logName = lua_tolstring(L, 1, nullptr);
    MaybeLogWordsText(L, "TextLogAddSingleByteEntry", 3, logName);
    int rc = CallSavedOriginal(L, "TextLogAddSingleByteEntry__orig");
    if (rc < 0 && g_origTextLogAddSingleByteEntry) {
        rc = InvokeClientLuaFn(g_origTextLogAddSingleByteEntry, "TextLogAddSingleByteEntry", L);
    }
    if (g_traceLuaVerbose && rc > 0)
        LogLuaReturns(L, "TextLogAddSingleByteEntry", rc);
    GuardLuaStack(L, "TextLogAddSingleByteEntry", topBefore, rc);
    return (rc >= 0) ? rc : 0;
}

static int __cdecl Lua_PrintWStringToChatWindow_W(lua_State* L)
{
    int topBefore = lua_gettop(L);
    if (g_traceLuaVerbose)
        LogLuaArgs(L, "PrintWStringToChatWindow", 2);
    MaybeLogWordsText(L, "PrintWStringToChatWindow", 1, "WS");
    int rc = CallSavedOriginal(L, "PrintWStringToChatWindow__orig");
    if (rc < 0 && g_origPrintWStringToChatWindow) {
        rc = InvokeClientLuaFn(g_origPrintWStringToChatWindow, "PrintWStringToChatWindow", L);
    }
    if (g_traceLuaVerbose && rc > 0)
        LogLuaReturns(L, "PrintWStringToChatWindow", rc);
    GuardLuaStack(L, "PrintWStringToChatWindow", topBefore, rc);
    return (rc >= 0) ? rc : 0;
}

static int __cdecl Lua_PrintTidToChatWindow_W(lua_State* L)
{
    int topBefore = lua_gettop(L);
    if (g_traceLuaVerbose)
        LogLuaArgs(L, "PrintTidToChatWindow", 3);
    MaybeLogWordsTid(L, "PrintTidToChatWindow", 1);
    int rc = CallSavedOriginal(L, "PrintTidToChatWindow__orig");
    if (rc < 0 && g_origPrintTidToChatWindow) {
        rc = InvokeClientLuaFn(g_origPrintTidToChatWindow, "PrintTidToChatWindow", L);
    }
    if (g_traceLuaVerbose && rc > 0)
        LogLuaReturns(L, "PrintTidToChatWindow", rc);
    GuardLuaStack(L, "PrintTidToChatWindow", topBefore, rc);
    return (rc >= 0) ? rc : 0;
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
    uint32_t tok = CurrentCastToken();
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
    if (InterlockedCompareExchange(&g_targetCompatBannerLogged, 1, 0) == 0)
        LogCompatReturnBanner(L, "UserActionIsTargetModeCompat", rc);

    if (rc > 0 && tok != 0) {
        int top = lua_gettop(L);
        bool compat = (lua_toboolean(L, top) != 0);
        if (compat) {
            uint32_t expected = g_targetCompatLastArmToken.load(std::memory_order_acquire);
            if (expected != tok &&
                g_targetCompatLastArmToken.compare_exchange_strong(expected,
                                                                    tok,
                                                                    std::memory_order_acq_rel,
                                                                    std::memory_order_acquire)) {
                g_targetCorr.Arm("UserActionIsTargetModeCompat");
            }
        }
    }
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
    if (InterlockedCompareExchange(&g_actionTypeCompatBannerLogged, 1, 0) == 0)
        LogCompatReturnBanner(L, "UserActionIsActionTypeTargetModeCompat", rc);
    return rc;
}

static void MaybeCaptureSpellTargetTuple(lua_State* L)
{
    if (!L)
        return;
    int argc = lua_gettop(L);
    if (argc < 3)
        return;
    if (lua_type(L, 1) != LUA_TNUMBER || lua_type(L, 2) != LUA_TNUMBER || lua_type(L, 3) != LUA_TNUMBER)
        return;
    TargetRequestTuple tuple{};
    tuple.action = static_cast<int>(lua_tointeger(L, 1));
    tuple.sub = static_cast<int>(lua_tointeger(L, 2));
    tuple.extra = static_cast<int>(lua_tointeger(L, 3));
    tuple.learned = true;
    bool changed = !g_targetRequestTuple.learned ||
                   g_targetRequestTuple.action != tuple.action ||
                   g_targetRequestTuple.sub != tuple.sub ||
                   g_targetRequestTuple.extra != tuple.extra;
    g_targetRequestTuple = tuple;
    if (changed) {
        char buf[192];
        sprintf_s(buf,
                  sizeof(buf),
                  "[TargetFallback] learned RequestTargetInfo tuple action=%d sub=%d extra=%d",
                  tuple.action,
                  tuple.sub,
                  tuple.extra);
        WriteRawLog(buf);
    }
}

static int __cdecl Lua_RequestTargetInfo_W(lua_State* L)
{
    InstallUOFlowConsoleBindingsIfNeeded(CanonicalOwnerContext(), "RequestTargetInfo_W");
    int topBefore = lua_gettop(L);
    uint32_t tok = CurrentCastToken();
    char intro[128];
    sprintf_s(intro, sizeof(intro), "[Lua] RequestTargetInfo() wrapper invoked tok=%u", tok);
    WriteRawLog(intro);
    char uiIntro[160];
    sprintf_s(uiIntro, sizeof(uiIntro), "[TargetUI] RequestTargetInfo enter tok=%u", tok);
    WriteRawLog(uiIntro);
    if (g_traceTargetPath) {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "[TargetPath] Enter RequestTargetInfo tok=%u", tok);
        WriteRawLog(buf);
    }
    Trace::MarkAction("RequestTargetInfo");
    g_targetCorr.Arm("RequestTargetInfo");
    LuaReturnInfo retInfo{};
    LogLuaArgs(L, "RequestTargetInfo");
    MaybeCaptureSpellTargetTuple(L);
    static volatile LONG s_dumpCountRTI = 0;
    if (InterlockedIncrement(&s_dumpCountRTI) <= 4)
        DumpStackTag("RequestTargetInfo");
    int rc = 0;
    if (g_origRequestTargetInfo) {
        __try { rc = g_origRequestTargetInfo(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] RequestTargetInfo original threw"); }
        retInfo = CaptureLuaReturn(L, rc);
    }
    if (rc >= 0)
        MarkTargetRequestObserved();
    LogLuaReturns(L, "RequestTargetInfo", rc);
    char detail[128];
    sprintf_s(detail, sizeof(detail), "[Lua] RequestTargetInfo rc=%d tok=%u", rc, tok);
    WriteRawLog(detail);
    LogReturnBanner(L, "RequestTargetInfo", retInfo, g_requestTargetReturnBannerLogged);
    if (g_traceTargetPath) {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "[TargetPath] Leave RequestTargetInfo rc=%d tok=%u", rc, tok);
        WriteRawLog(buf);
    }
    char uiExit[160];
    sprintf_s(uiExit, sizeof(uiExit), "[TargetUI] RequestTargetInfo exit rc=%d tok=%u", rc, tok);
    WriteRawLog(uiExit);
    GuardLuaStack(L, "RequestTargetInfo", topBefore, rc);
    return rc;
}

static int __cdecl Lua_ClearCurrentTarget_W(lua_State* L)
{
    InstallUOFlowConsoleBindingsIfNeeded(CanonicalOwnerContext(), "ClearCurrentTarget_W");
    int topBefore = lua_gettop(L);
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
    g_targetCorr.Arm("ClearCurrentTarget");
    GuardLuaStack(L, "ClearCurrentTarget", topBefore, rc);
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
    ForceSpellBinding(L, "Lua.BindWalk");
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
    RequestActionWrapperInstall();
    if (auto L = static_cast<lua_State*>(Engine::LuaState())) {
        EnsureReplayHelper(L);
    }

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

void ScheduleCastWrapRetry(const char* reason)
{
    RequestLateCastWrapLoop(reason);
}

void NotifySendPacket(unsigned counter, const void* bytes, int len)
{
    HandleCastPacketSend(counter, bytes, len);
    uint8_t packetId = 0;
    if (bytes && len > 0) {
        __try {
            packetId = *static_cast<const uint8_t*>(bytes);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            packetId = 0;
        }
    }
    if (packetId != 0)
        NoteNoClickSendPacket(packetId, len, counter);
}

bool UseHotbarSlot(int hotbarId, int slot)
{
    if (hotbarId <= 0 || slot <= 0) {
        WriteRawLog("[Hotbar] UseHotbarSlot requires positive hotbar and slot ids");
        return false;
    }

    DWORD ownerTid = g_ownerThreadId.load(std::memory_order_acquire);
    DWORD tid = GetCurrentThreadId();
    if (ownerTid != 0 && ownerTid != tid) {
        char buf[160];
        sprintf_s(buf,
                  sizeof(buf),
                  "[Hotbar] UseHotbarSlot rejected: owner thread=%u caller=%u",
                  ownerTid,
                  tid);
        WriteRawLog(buf);
        return false;
    }

    auto* L = static_cast<lua_State*>(Engine::LuaState());
    if (!L) {
        WriteRawLog("[Hotbar] UseHotbarSlot no Lua state available");
        return false;
    }

    int top = lua_gettop(L);
    lua_getglobal(L, "Hotbar");
    if (lua_type(L, -1) != LUA_TTABLE) {
        WriteRawLog("[Hotbar] UseHotbarSlot missing global 'Hotbar'");
        lua_settop(L, top);
        return false;
    }

    lua_getfield(L, -1, "UseSlot");
    lua_replace(L, -2); // drop table, leave function on stack
    if (lua_type(L, -1) != LUA_TFUNCTION) {
        WriteRawLog("[Hotbar] UseHotbarSlot missing Hotbar.UseSlot function");
        lua_settop(L, top);
        return false;
    }

    lua_pushinteger(L, hotbarId);
    lua_pushinteger(L, slot);
    if (lua_pcall(L, 2, 0, 0) != 0) {
        const char* err = lua_tolstring(L, -1, nullptr);
        char buf[256];
        sprintf_s(buf,
                  sizeof(buf),
                  "[Hotbar] UseHotbarSlot failed: %s",
                  err ? err : "<unknown>");
        WriteRawLog(buf);
        lua_settop(L, top);
        return false;
    }

    lua_settop(L, top);
    return true;
}

bool CastSpellNative(int spellId)
{
    if (spellId <= 0) {
        WriteRawLog("[SpellReplay] CastSpellNative requires a positive spell id");
        return false;
    }

    DWORD ownerTid = g_ownerThreadId.load(std::memory_order_acquire);
    DWORD tid = GetCurrentThreadId();
    if (ownerTid != 0 && ownerTid != tid) {
        char buf[192];
        sprintf_s(buf, sizeof(buf),
                  "[SpellReplay] CastSpellNative rejected: owner thread=%u caller=%u",
                  ownerTid,
                  tid);
        WriteRawLog(buf);
        return false;
    }

    SpellGateReplayContext ctx{};
    bool haveCtx = false;
    {
        std::lock_guard<std::mutex> lock(g_spellReplayMutex);
        auto it = g_spellReplayCache.find(spellId);
        if (it != g_spellReplayCache.end()) {
            ctx = it->second;
            haveCtx = true;
        }
    }

    if (!haveCtx) {
        char buf[256];
        sprintf_s(buf, sizeof(buf),
                  "[SpellReplay] no native context for spell=%d (cast via UI once to learn)",
                  spellId);
        WriteRawLog(buf);
        return false;
    }

    if (!ctx.probe || !ctx.probe->trampoline) {
        char buf[192];
        sprintf_s(buf, sizeof(buf),
                  "[SpellReplay] stored context invalid for spell=%d probe=%p",
                  spellId,
                  ctx.probe);
        WriteRawLog(buf);
        return false;
    }

    bool ok = InvokeSpellGateDirect(ctx);
    char buf[256];
    sprintf_s(buf, sizeof(buf),
              "[SpellReplay] CastSpellNative spell=%d -> %s token=%u",
              spellId,
              ok ? "success" : "failure",
              ctx.token);
    WriteRawLog(buf);
    return ok;
}

bool InitLuaBridge()
{
    // Prefer configuration file, fall back to environment variable for compatibility.
    bool enableHook = false;
    if (auto v = Core::Config::TryGetBool("UOWP_ENABLE_LUA_REGISTER_HOOK"))
        enableHook = *v;
    else if (const char* env = std::getenv("UOWP_ENABLE_LUA_REGISTER_HOOK"))
        enableHook = (env[0] == '1' || env[0] == 'y' || env[0] == 'Y' || env[0] == 't' || env[0] == 'T');

    if (auto opt = ReadBoolOption("uow.safe_casting", "UOW_SAFE_CASTING"))
        g_safeCastingMode = *opt;
    else
        g_safeCastingMode = false;
    if (auto opt = ReadBoolOption("uow.debug.words", "UOW_DEBUG_WORDS"))
        g_debugWords = *opt;
    else
        g_debugWords = true;
    if (auto opt = ReadBoolOption("uow.debug.taptarget", "UOW_DEBUG_TAPTARGET"))
        g_enableTapTargetWrap = *opt;
    else
        g_enableTapTargetWrap = false;
    if (auto opt = ReadBoolOption("uow.debug.noclick", "UOW_DEBUG_NOCLICK"))
        g_noClickDiagnostics = *opt;
    else
        g_noClickDiagnostics = false;
    if (g_noClickDiagnostics)
        WriteRawLog("[NoClick] diagnostics enabled");
    if (auto opt = ReadBoolOption("uoflow.cast.use_direct_orig", "UOFLOW_CAST_USE_DIRECT_ORIG"))
        g_allowDirectCastFallback = *opt;
    else
        g_allowDirectCastFallback = false;
    WriteRawLog(g_allowDirectCastFallback ? "[NoClick] direct-orig path ENABLED" : "[NoClick] direct-orig path DISABLED");
    g_clickTapWrapInstalled.store(false, std::memory_order_release);
    g_clickTapNextMissingLog = 0;
    if (!g_enableTapTargetWrap)
        g_actionWrapperMask.fetch_or(kWrapperHandleLeftClick, std::memory_order_acq_rel);
    if (!g_debugWords)
        g_actionWrapperMask.fetch_or(kWordWrapperMask, std::memory_order_acq_rel);
    WriteRawLog(g_enableTapTargetWrap ? "[ClickTap] wrapper ENABLED" : "[ClickTap] wrapper DISABLED");
    g_clickTapStateLogged = true;
    if (g_safeCastingMode)
        RequestActionWrapperInstall();

    // Trace verbosity (optional): TRACE_LUA_VERBOSE or trace.lua.verbose
    if (auto v = Core::Config::TryGetBool("TRACE_LUA_VERBOSE"))
        g_traceLuaVerbose = *v;
    else if (auto v2 = Core::Config::TryGetBool("trace.lua.verbose"))
        g_traceLuaVerbose = *v2;
    if (auto traceTarget = Core::Config::TryGetBool("TRACE_TARGET_PATH"))
        g_traceTargetPath = *traceTarget;
    else if (const char* traceTargetEnv = std::getenv("TRACE_TARGET_PATH"))
        g_traceTargetPath = (traceTargetEnv[0] == '1' || traceTargetEnv[0] == 'y' || traceTargetEnv[0] == 'Y' || traceTargetEnv[0] == 't' || traceTargetEnv[0] == 'T');

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

    int gateResolveDepth = 0;
    void* resolvedTarget = ResolveGateJumpTarget(reinterpret_cast<void*>(g_gateSelectedTarget), gateResolveDepth);
    if (resolvedTarget && reinterpret_cast<uintptr_t>(resolvedTarget) != g_gateSelectedTarget) {
        g_gateSelectedTarget = reinterpret_cast<uintptr_t>(resolvedTarget);
        sprintf_s(g_gateResolvedName, sizeof(g_gateResolvedName), "%p", resolvedTarget);
        g_gateSelectedName = g_gateResolvedName;
        char resolveMsg[256];
        sprintf_s(resolveMsg, sizeof(resolveMsg),
            "InitLuaBridge: gate target resolved via %d jump(s) -> %s",
            gateResolveDepth,
            g_gateResolvedName);
        WriteRawLog(resolveMsg);
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
    RequestActionWrapperInstall();
    uint32_t targetWindowMs = TargetCorrelatorGetWindow();
    char flagBuf[160];
    sprintf_s(flagBuf,
              sizeof(flagBuf),
              "[Init] flags: taptarget=%s words=%s target_window_ms=%u",
              g_enableTapTargetWrap ? "on" : "off",
              g_debugWords ? "on" : "off",
              targetWindowMs);
    WriteRawLog(flagBuf);
    return true;
}

// Lightweight polling entry-point to retry late installs from a game-thread context
void PollLateInstalls()
{
    Util::OwnerPump::DrainOnOwnerThread();
    static DWORD s_lastTryTick = 0;
    DWORD now = GetTickCount();
    if (now - s_lastTryTick < 500)
        return;
    s_lastTryTick = now;
    if (auto L = static_cast<lua_State*>(Engine::LuaState()))
        ProcessLateCastWrapLoop(L);
    InstallUOFlowConsoleBindingsIfNeeded(CanonicalOwnerContext(), "poller");
    if (auto L = static_cast<lua_State*>(Engine::LuaState())) {
        ForceLateCastWrapInstall(L, "poller");
    }
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
    bool wantActionWrappers = (InterlockedCompareExchange(&g_actionWrapperInstallPending, 0, 0) != 0);
    if (wantActionWrappers && InterlockedCompareExchange(&g_actionWrappersInstalled, 0, 0) == 0) {
        static DWORD s_nextWrapperLog = 0;
        DWORD now = GetTickCount();
        if (now >= s_nextWrapperLog) {
            WriteRawLog("PollLateInstalls: attempting action wrapper install");
            s_nextWrapperLog = now + 1000;
        }
        TryInstallActionWrappers();
        if (InterlockedCompareExchange(&g_actionWrappersInstalled, 0, 0) != 0)
            InterlockedExchange(&g_actionWrapperInstallPending, 0);
        else if (now >= s_nextWrapperLog) {
            WriteRawLog("PollLateInstalls: action wrapper install deferred (prereqs missing)");
            s_nextWrapperLog = now + 1000;
        }
    }
    TryInstallDirectActionHooks();
    if (!g_spellBindingReady.load(std::memory_order_acquire)) {
        if (auto L = static_cast<lua_State*>(Engine::LuaState())) {
            ForceSpellBinding(L, "PollLateInstalls");
        }
    }
    if (!g_replayHelperInstalled.load(std::memory_order_acquire)) {
        if (auto L = static_cast<lua_State*>(Engine::LuaState())) {
            EnsureReplayHelper(L);
        }
    }
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

extern "C" __declspec(dllexport) bool __stdcall UseHotbarSlot(int hotbarId, int slot)
{
    return Engine::Lua::UseHotbarSlot(hotbarId, slot);
}

extern "C" __declspec(dllexport) bool __stdcall CastSpellNative(int spellId)
{
    return Engine::Lua::CastSpellNative(spellId);
}
