#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cctype>
#include <atomic>
#include <string>
#include <deque>
#include <mutex>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <vector>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdarg>
#include <climits>
#include <charconv>
#include <sstream>
#include <fstream>
#include <intrin.h>
#include <thread>
#include <system_error>
#include <limits>

#include <minhook.h>

#include "Core/Config.hpp"
#include "Core/CoreFlags.hpp"
#include "Core/EarlyTrace.hpp"
#include "Core/Bind.hpp"
#include "Core/Logging.hpp"
#include "Core/Startup.hpp"
#include "Engine/GlobalState.hpp"
#include "Engine/LuaBridge.hpp"
#include "Engine/LuaStateRegistry.hpp"
#include "Engine/Movement.hpp"
#include "Util/OwnerPump.hpp"
#include "Walk/WalkController.hpp"
#include "Net/SendBuilder.hpp"
#include "Engine/lua_safe.h"
#include "Win32/SafeProbe.h"

#include "LuaPlus.h"

#ifndef LUA_NOREF
#define LUA_NOREF (-2)
#endif

#ifndef LUA_REFNIL
#define LUA_REFNIL (-1)
#endif

#ifndef LUA_HOOKCALL
#define LUA_HOOKCALL 0
#define LUA_HOOKRET 1
#define LUA_HOOKLINE 2
#define LUA_HOOKCOUNT 3
#define LUA_HOOKTAILRET 4
#endif

#ifndef LUA_MASKCALL
#define LUA_MASKCALL (1 << LUA_HOOKCALL)
#define LUA_MASKRET (1 << LUA_HOOKRET)
#define LUA_MASKLINE (1 << LUA_HOOKLINE)
#define LUA_MASKCOUNT (1 << LUA_HOOKCOUNT)
#endif

#ifndef LUA_IDSIZE
#define LUA_IDSIZE 60
#endif

#ifndef LUA_MULTRET
#define LUA_MULTRET (-1)
#endif

#ifndef lua_newtable
#define lua_newtable(L) lua_createtable(L, 0, 0)
#endif

typedef struct lua_Debug {
    int event;
    const char* name;
    const char* namewhat;
    const char* what;
    const char* source;
    int currentline;
    int nups;
    int linedefined;
    int lastlinedefined;
    char short_src[LUA_IDSIZE];
    int i_ci;
} lua_Debug;

extern "C" {
    LUA_API int lua_gettop(lua_State* L);
    LUA_API void lua_settop(lua_State* L, int idx);
    LUA_API int lua_checkstack(lua_State* L, int extra);
    LUA_API void lua_pushvalue(lua_State* L, int idx);
    LUA_API void lua_pushnil(lua_State* L);
    LUA_API void lua_pushstring(lua_State* L, const char* s);
    LUA_API void lua_pushcclosure(lua_State* L, lua_CFunction fn, int n);
    LUA_API void lua_pushboolean(lua_State* L, int b);
    LUA_API void lua_pushinteger(lua_State* L, lua_Integer n);
    LUA_API void lua_pushlightuserdata(lua_State* L, void* p);
    LUA_API int lua_isnumber(lua_State* L, int idx);
    LUA_API int lua_isstring(lua_State* L, int idx);
    LUA_API int lua_istable(lua_State* L, int idx);
    LUA_API int lua_iscfunction(lua_State* L, int idx);
    LUA_API int lua_isuserdata(lua_State* L, int idx);
    LUA_API lua_CFunction lua_tocfunction(lua_State* L, int idx);
    LUA_API lua_Integer lua_tointeger(lua_State* L, int idx);
    LUA_API lua_Number lua_tonumber(lua_State* L, int idx);
    LUA_API void* lua_touserdata(lua_State* L, int idx);
    LUA_API const char* lua_tolstring(lua_State* L, int idx, size_t* len);
    LUA_API const char* lua_tostring(lua_State* L, int idx);
    LUA_API const char* lua_getupvalue(lua_State* L, int funcindex, int n);
    LUA_API int lua_next(lua_State* L, int idx);
    LUA_API int luaL_ref(lua_State* L, int t);
    LUA_API void luaL_unref(lua_State* L, int t, int ref);
    LUA_API const char* lua_typename(lua_State* L, int tp);
    LUA_API int lua_type(lua_State* L, int idx);
    LUA_API lua_CFunction lua_atpanic(lua_State* L, lua_CFunction panicf);
    LUA_API int lua_getstack(lua_State* L, int level, lua_Debug* ar);
    LUA_API int lua_getinfo(lua_State* L, const char* what, lua_Debug* ar);
    typedef void(__cdecl* lua_Hook)(lua_State*, lua_Debug*);
    LUA_API void lua_setfield(lua_State* L, int idx, const char* k);
    LUA_API void lua_insert(lua_State* L, int idx);
    LUA_API void lua_createtable(lua_State* L, int narr, int nrec);
    LUA_API void lua_sethook(lua_State* L, lua_Hook func, int mask, int count);
    LUA_API lua_Hook lua_gethook(lua_State* L);
    LUA_API int lua_gethookmask(lua_State* L);
    LUA_API int lua_gethookcount(lua_State* L);
    LUA_API void lua_rawget(lua_State* L, int idx);
    LUA_API void lua_rawset(lua_State* L, int idx);
    LUA_API void* lua_newuserdata(lua_State* L, size_t size);
    LUA_API int lua_setmetatable(lua_State* L, int objindex);
    LUA_API int luaL_newmetatable(lua_State* L, const char* tname);
    LUA_API void luaL_getmetatable(lua_State* L, const char* tname);
    LUA_API void lua_settable(lua_State* L, int idx);
    LUA_API int luaL_loadstring(lua_State* L, const char* str);
    LUA_API void lua_call(lua_State* L, int nargs, int nresults);
    LUA_API int lua_pcall(lua_State* L, int nargs, int nresults, int errfunc);
}

extern "C" IMAGE_DOS_HEADER __ImageBase;

#ifndef LUA_RIDX_GLOBALS
#define LUA_RIDX_GLOBALS 2
#endif

#ifndef LUA_REGISTRYINDEX
#define LUA_REGISTRYINDEX (-10000)
#endif

namespace {

using HCTX = void*;

using ClientRegisterFn = int(__stdcall*)(void*, void*, const char*);
using LuaStateGetCStateFn = lua_State* (__thiscall*)(void*);
using LuaStateAtPanicFn = lua_CFunction(__thiscall*)(void*, lua_CFunction);

using Engine::Lua::LuaStateInfo;
using Engine::Lua::LuaStateRegistry;
using namespace Engine::Lua;

constexpr DWORD kQueueDrainLogCooldownMs = 1000;
constexpr DWORD kMaintenanceIntervalMs = 5000;
constexpr DWORD kProbeInitialBackoffMs = 1000;
constexpr DWORD kProbeMaxBackoffMs = 8000;
constexpr DWORD kRegisterSettleWindowMs = 250;
constexpr DWORD kBindSummaryIntervalMs = 2000;
constexpr DWORD kBindLogCooldownMs = 800;
constexpr const char* kSettlePromoteReason = "settle-promote";
constexpr uint32_t kMaxHelperRebindAttempts = 3;

struct LuaTask {
    std::string name;
    lua_State* target = nullptr;
    std::function<void(lua_State*)> fn;
};

struct ModuleBounds {
    uintptr_t base = 0;
    size_t size = 0;
    bool valid = false;
};

static ClientRegisterFn g_origRegister = nullptr;
static ClientRegisterFn g_clientRegister = nullptr;
static void* g_registerTarget = nullptr;
static std::atomic<bool> g_registerResolved{false};
static std::atomic<void*> g_engineContext{nullptr};
static std::atomic<void*> g_latestScriptCtx{nullptr};
static std::atomic<void*> g_loggedEngineContext{nullptr};
static std::atomic<bool> g_engineVtableLogged{false};

static std::atomic<DWORD> g_scriptThreadId{0};
static std::atomic<lua_State*> g_mainLuaState{nullptr};
static std::atomic<void*> g_mainLuaPlusState{nullptr};
static std::atomic<lua_State*> g_canonicalState{nullptr};

static LuaStateRegistry g_stateRegistry;
static std::atomic<uint64_t> g_generation{1};
static std::atomic<uint64_t> g_lastMaintenanceTick{0};
static std::atomic<uint64_t> g_lastHelperSummaryTick{0};
static std::atomic<uint32_t> g_helperScheduledCount{0};
static std::atomic<uint32_t> g_helperInstalledCount{0};
static std::atomic<uint32_t> g_helperDeferredCount{0};
static std::atomic<uint32_t> g_helperProbeAttempted{0};
static std::atomic<uint32_t> g_helperProbeSuccess{0};
static std::atomic<uint32_t> g_helperProbeSkipped{0};
static std::atomic<bool> g_helpersInstalledAny{false};
static std::atomic<int> g_helperInstallInFlight{0};

enum class CtxValidationResult {
    Ok = 0,
    Null,
    QueryFailed,
    NotCommitted,
    NoAccess,
    Guarded
};

static const char* DescribeCtxValidation(CtxValidationResult result)
{
    switch (result) {
    case CtxValidationResult::Ok:
        return "ok";
    case CtxValidationResult::Null:
        return "null";
    case CtxValidationResult::QueryFailed:
        return "query-failed";
    case CtxValidationResult::NotCommitted:
        return "not-committed";
    case CtxValidationResult::NoAccess:
        return "no-access";
    case CtxValidationResult::Guarded:
        return "guard-page";
    default:
        return "unknown";
    }
}

static CtxValidationResult ValidateCtxLoose(const void* ctx) noexcept
{
    if (!ctx)
        return CtxValidationResult::Null;

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(ctx, &mbi, sizeof(mbi)))
        return CtxValidationResult::QueryFailed;

    if (mbi.State != MEM_COMMIT)
        return CtxValidationResult::NotCommitted;

    if (mbi.Protect & PAGE_NOACCESS)
        return CtxValidationResult::NoAccess;

    if (mbi.Protect & PAGE_GUARD)
        return CtxValidationResult::Guarded;

    return CtxValidationResult::Ok;
}

static std::atomic<uint64_t> g_ownerPumpUnstickLoggedGen{0};
static std::atomic<DWORD> g_lastHelperOwnerThread{0};
static std::atomic<uint64_t> g_lastHelperRetryScanTick{0};
static std::atomic<uint64_t> g_lastHeartbeatTick{0};
static constexpr size_t kLuaTraceRingSize = 64 * 1024;
static std::array<char, kLuaTraceRingSize> g_luaTraceRing{};
static std::atomic<uint32_t> g_luaTraceHead{0};
static std::atomic<uint32_t> g_luaTraceTail{0};

struct HelperRetryPolicy {
    uint32_t retryMax = 3;
    uint32_t retryWindowMs = 1500;
    uint32_t stableWindowMs = 250;
    uint32_t retryBackoffMs = 150;
    uint32_t ownerConfirmMs = 1000;
    uint32_t minSettleMs = 500;
    uint32_t debounceMs = 100;
    uint32_t maxRetries = 10;
    std::array<uint32_t, 8> retrySchedule{};
};

static HelperRetryPolicy g_helperRetryPolicy{};
static std::once_flag g_helperRetryPolicyOnce;

static std::mutex g_taskMutex;
static std::deque<LuaTask> g_taskQueue;
static thread_local bool g_processingLuaQueue = false;
static std::atomic<bool> g_queueLoggedDuringInit{false};
static std::atomic<DWORD> g_lastQueueLogTick{0};

static thread_local bool g_helperInstallActive = false;

static bool TryEnterHelperInstall() noexcept {
    if (g_helperInstallActive)
        return false;
    g_helperInstallActive = true;
    return true;
}

static void LeaveHelperInstall(bool engaged) noexcept {
    if (engaged)
        g_helperInstallActive = false;
}

static std::atomic<bool> g_helperPumpStop{false};
static std::atomic<bool> g_helperPumpRunning{false};
static std::thread g_helperPumpThread;

struct HelpersRuntimeState {
    std::atomic<uint64_t> settle_start_ms{0};
    std::atomic<HCTX> canonical_ctx{nullptr};
    std::atomic<DWORD> owner_tid{0};
    std::atomic<bool> rebind_pending{false};

    void SetCanonicalCtx(HCTX ctx, DWORD owner) noexcept {
        if (!ctx)
            return;

        HCTX current = canonical_ctx.load(std::memory_order_acquire);
        HCTX engineCtx = g_engineContext.load(std::memory_order_acquire);
        if (current == ctx) {
            if (owner) {
                owner_tid.store(owner, std::memory_order_release);
                g_lastHelperOwnerThread.store(owner, std::memory_order_relaxed);
            }
            return;
        }

        bool currentValid = ValidateCtxLoose(current) == CtxValidationResult::Ok;
        bool preferNew = (current == nullptr) || !currentValid || current == engineCtx;

        if (preferNew) {
            canonical_ctx.store(ctx, std::memory_order_release);
            if (owner) {
                owner_tid.store(owner, std::memory_order_release);
                g_lastHelperOwnerThread.store(owner, std::memory_order_relaxed);
            }
            return;
        }

        if (owner) {
            DWORD currentOwner = owner_tid.load(std::memory_order_acquire);
            if (currentOwner != owner) {
                owner_tid.store(owner, std::memory_order_release);
                g_lastHelperOwnerThread.store(owner, std::memory_order_relaxed);
            }
        }
    }

    HCTX GetCanonicalCtx() const noexcept {
        return canonical_ctx.load(std::memory_order_acquire);
    }

    DWORD GetOwnerTid() const noexcept {
        return owner_tid.load(std::memory_order_acquire);
    }

    void MarkRebindPending() noexcept {
        rebind_pending.store(true, std::memory_order_release);
    }

    bool ConsumeRebindPending() noexcept {
        return rebind_pending.exchange(false, std::memory_order_acq_rel);
    }
};

static HelpersRuntimeState g_helpers{};

struct HelperInstallMetrics {
    uint64_t startTick = 0;
    uint64_t endTick = 0;
    uint32_t hookSuccess = 0;
    uint32_t hookFailure = 0;
};

static inline bool HelperSingleFlightTryAcquire()
{
    int expected = 0;
    return g_helperInstallInFlight.compare_exchange_strong(expected,
                                                           1,
                                                           std::memory_order_acq_rel,
                                                           std::memory_order_acquire);
}

static inline void HelperSingleFlightRelease()
{
    g_helperInstallInFlight.store(0, std::memory_order_release);
}

static void SetCanonicalHelperCtx(HCTX ctx, DWORD ownerTid) noexcept {
    g_helpers.SetCanonicalCtx(ctx, ownerTid);
    if (ownerTid)
        Util::OwnerPump::SetOwnerThreadId(ownerTid);
    if (ctx)
        Net::NotifyCanonicalManagerDiscovered();
}

static HCTX GetCanonicalHelperCtx() noexcept {
    return g_helpers.GetCanonicalCtx();
}

static DWORD GetCanonicalHelperOwnerTid() noexcept {
    return g_helpers.GetOwnerTid();
}

static void StartHelperPumpThread();
static void StopHelperPumpThread();
static void MaybePumpLuaQueueFromScriptThread(const char* reason);
static bool IsPlausibleContextPointer(const void* ctx);
static bool IsValidCtx(HCTX ctx);
static void PostBindToOwnerThread(lua_State* L, DWORD ownerTid, uint64_t generation, bool force, const char* reason);

static void SafeRefreshLuaStateFromSlot() noexcept {
    __try {
        Engine::RefreshLuaStateFromSlot();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // no-op
    }
}

static HelperInstallStage DetermineHelperStage(const LuaStateInfo& state, bool canonicalReadyFlag);
static HelperInstallStage CurrentHelperStage(const LuaStateInfo& state);
static void UpdateHelperStage(LuaStateInfo& state, HelperInstallStage nextStage, uint64_t now, const char* reason);

static void PostOwnerPumpUnstick(lua_State* L, uint64_t generation)
{
    if (!L || generation == 0)
        return;

    uint64_t logged = g_ownerPumpUnstickLoggedGen.load(std::memory_order_acquire);
    while (generation > logged) {
        if (g_ownerPumpUnstickLoggedGen.compare_exchange_weak(logged, generation, std::memory_order_acq_rel))
            break;
    }
    if (generation <= logged)
        return;

    Log::Logf(Log::Level::Info,
              Log::Category::Hooks,
              "[HOOKS] helpers owner-pump unstick gen=%llu",
              static_cast<unsigned long long>(generation));

    Util::OwnerPump::RunOnOwner([L, generation]() {
        g_stateRegistry.UpdateByPointer(L, [generation](LuaStateInfo& state) {
            if (state.gen != generation)
                return;
            if ((state.flags & STATE_FLAG_HELPERS_INSTALLED) != 0)
                return;
            uint64_t now = GetTickCount64();
            bool canonicalReady = (state.flags & STATE_FLAG_CANON_READY) != 0;
            HelperInstallStage desired = DetermineHelperStage(state, canonicalReady);
            if (desired != HelperInstallStage::ReadyToInstall)
                return;
            HelperInstallStage current = CurrentHelperStage(state);
            if (current == HelperInstallStage::ReadyToInstall || current == HelperInstallStage::Installed)
                return;
            UpdateHelperStage(state, HelperInstallStage::ReadyToInstall, now, "owner-unstick");
        });
    });
}

static bool IsValidCtx(HCTX ctx) {
    return ValidateCtxLoose(ctx) == CtxValidationResult::Ok;
}

static void* ResolveCanonicalEngineContext() noexcept {
    void* ctx = GetCanonicalHelperCtx();
    if (IsValidCtx(ctx))
        return ctx;

    ctx = nullptr;
    __try {
        const GlobalStateInfo* globalInfo = ::Engine::Info();
        if (globalInfo && globalInfo->engineContext)
            ctx = globalInfo->engineContext;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ctx = nullptr;
    }
    if (ctx && !IsPlausibleContextPointer(ctx))
        ctx = nullptr;

    if (!ctx) {
        ctx = g_engineContext.load(std::memory_order_acquire);
        if (ctx && !IsPlausibleContextPointer(ctx))
            ctx = nullptr;
    }

    if (!ctx) {
        void* logged = g_loggedEngineContext.load(std::memory_order_acquire);
        if (logged && IsPlausibleContextPointer(logged))
            ctx = logged;
    }

    return ctx;
}

static LuaStateGetCStateFn g_luaStateGetCState = nullptr;
static LuaStateAtPanicFn g_luaStateAtPanic = nullptr;

static thread_local char g_cppExceptionDetail[192];

static void TrackHelperEvent(std::atomic<uint32_t>& counter) {
    counter.fetch_add(1u, std::memory_order_relaxed);
}

static bool ParseUint32(const std::string& text, uint32_t& outValue) {
    if (text.empty())
        return false;

    const char* begin = text.data();
    const char* end = begin + text.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(*begin)))
        ++begin;
    while (end > begin && std::isspace(static_cast<unsigned char>(*(end - 1))))
        --end;
    if (begin >= end)
        return false;

    uint64_t value = 0;
    auto result = std::from_chars(begin, end, value, 10);
    if (result.ec != std::errc() || result.ptr != end)
        return false;
    if (value > std::numeric_limits<uint32_t>::max())
        return false;
    outValue = static_cast<uint32_t>(value);
    return true;
}

static void LoadHelperRetryPolicy() {
    HelperRetryPolicy policy{};
    policy.retrySchedule = {500u, 1000u, 2000u, 3000u, 5000u, 8000u, 13000u, 21000u};

    uint32_t value = 0;

    if (auto envMax = Core::Config::TryGetEnv("WALK_HELPERS_MAX_RETRIES")) {
        if (ParseUint32(*envMax, value))
            policy.maxRetries = value;
    } else if (auto cfgMax = Core::Config::TryGetUInt("walk.helpers.maxRetries")) {
        policy.maxRetries = *cfgMax;
    } else if (auto legacyEnvMax = Core::Config::TryGetEnv("LUA_HELPERS_RETRYMAX")) {
        if (ParseUint32(*legacyEnvMax, value))
            policy.maxRetries = value;
    } else if (auto legacyCfgMax = Core::Config::TryGetUInt("lua.helpers.retryMax")) {
        policy.maxRetries = *legacyCfgMax;
    }

    if (auto envWindow = Core::Config::TryGetEnv("LUA_HELPERS_RETRYWINDOWMS")) {
        if (ParseUint32(*envWindow, value))
            policy.retryWindowMs = value;
    } else if (auto cfgWindow = Core::Config::TryGetUInt("lua.helpers.retryWindowMs")) {
        policy.retryWindowMs = *cfgWindow;
    }

    if (auto envOwner = Core::Config::TryGetEnv("LUA_HELPERS_OWNERCONFIRMMS")) {
        if (ParseUint32(*envOwner, value))
            policy.ownerConfirmMs = value;
    } else if (auto cfgOwner = Core::Config::TryGetUInt("lua.helpers.ownerConfirmMs")) {
        policy.ownerConfirmMs = *cfgOwner;
    }

    if (auto envSettle = Core::Config::TryGetEnv("WALK_HELPERS_MIN_SETTLE_MS")) {
        if (ParseUint32(*envSettle, value))
            policy.minSettleMs = value;
    } else if (auto cfgSettle = Core::Config::TryGetMilliseconds("walk.helpers.minSettleMs")) {
        policy.minSettleMs = *cfgSettle;
    }

    if (auto envDebounce = Core::Config::TryGetEnv("WALK_HELPERS_DEBOUNCE_MS")) {
        if (ParseUint32(*envDebounce, value))
            policy.debounceMs = value;
    } else if (auto cfgDebounce = Core::Config::TryGetMilliseconds("walk.helpers.debounceMs")) {
        policy.debounceMs = *cfgDebounce;
    }

    policy.maxRetries = std::clamp<uint32_t>(policy.maxRetries, 1u, 32u);
    policy.retryMax = policy.maxRetries;
    policy.retryWindowMs = std::clamp<uint32_t>(policy.retryWindowMs, 250u, 8000u);

    const uint32_t derivedStable = std::clamp<uint32_t>(policy.retryWindowMs / 4u, 150u, 1000u);
    const uint32_t retryDivisor = std::max<uint32_t>(policy.retryMax, 1u);
    const uint32_t derivedBackoff = std::clamp<uint32_t>(policy.retryWindowMs / retryDivisor, 50u, 500u);

    policy.stableWindowMs = derivedStable;
    policy.retryBackoffMs = derivedBackoff;
    policy.ownerConfirmMs = std::clamp<uint32_t>(policy.ownerConfirmMs, 250u, 5000u);
    policy.minSettleMs = std::clamp<uint32_t>(policy.minSettleMs, 100u, 5000u);
    policy.debounceMs = std::clamp<uint32_t>(policy.debounceMs, 50u, 2000u);

    g_helperRetryPolicy = policy;

    Log::Logf(Log::Level::Debug,
              Log::Category::Hooks,
              "helper-retry policy retryMax=%u retryWindowMs=%u stableWindowMs=%u retryBackoffMs=%u ownerConfirmMs=%u minSettleMs=%u debounceMs=%u maxRetries=%u",
              policy.retryMax,
              policy.retryWindowMs,
              policy.stableWindowMs,
              policy.retryBackoffMs,
              policy.ownerConfirmMs,
              policy.minSettleMs,
              policy.debounceMs,
              policy.maxRetries);
}


static uint32_t HelperRetryDelay(const HelperRetryPolicy& policy, uint32_t attemptIndex) {
    if (attemptIndex == 0)
        return 0;
    if (policy.retrySchedule.empty())
        return policy.retryBackoffMs;
    size_t idx = static_cast<size_t>(attemptIndex - 1u);
    if (idx < policy.retrySchedule.size() && policy.retrySchedule[idx] != 0)
        return policy.retrySchedule[idx];
    uint32_t fallback = policy.retrySchedule.back();
    return fallback != 0 ? fallback : policy.retryBackoffMs;
}

static uint32_t HelperJitterMs(const HelperRetryPolicy& policy, const void* token, uint64_t now) {
    uint32_t window = std::max<uint32_t>(policy.debounceMs, 25u);
    uint64_t raw = (now << 21) ^ (now >> 7) ^ reinterpret_cast<std::uintptr_t>(token);
    return static_cast<uint32_t>(raw % (static_cast<uint64_t>(window) + 1u));
}

static uint32_t HelperRandomWindow(const void* token, uint64_t now, uint32_t window) noexcept {
    window = std::max<uint32_t>(window, 1u);
    uint64_t seed = (now << 19) ^ (now >> 13) ^ reinterpret_cast<std::uintptr_t>(token) ^ 0x4C11DB7u;
    seed ^= (seed >> 17);
    seed ^= (seed << 31);
    return static_cast<uint32_t>(seed % (static_cast<uint64_t>(window) + 1u));
}

static uint32_t HelperBudgetBackoffMs(const void* token, uint64_t now) noexcept {
    const uint32_t base = 450u + HelperRandomWindow(token, now ^ 0xA5A5A5A5u, 250u);
    const void* jitterToken = reinterpret_cast<const void*>(reinterpret_cast<std::uintptr_t>(token) ^ 0x5A5A5A5Au);
    int32_t jitter = static_cast<int32_t>(HelperRandomWindow(jitterToken, now ^ 0x3C3C3C3Cu, 200u)) - 100;
    int32_t total = static_cast<int32_t>(base) + jitter;
    if (total < 250)
        total = 250;
    if (total > 900)
        total = 900;
    return static_cast<uint32_t>(total);
}

static bool DebugRingTryWrite(const char* fmt, ...) noexcept {
    if (!fmt)
        return false;

    char temp[256];
    va_list args;
    va_start(args, fmt);
    va_list argsCopy;
    va_copy(argsCopy, args);
    int required = _vscprintf(fmt, argsCopy);
    va_end(argsCopy);
    if (required <= 0) {
        va_end(args);
        return false;
    }
    int written = _vsnprintf_s(temp, sizeof(temp), _TRUNCATE, fmt, args);
    va_end(args);
    if (written < 0)
        written = static_cast<int>(std::strlen(temp));
    if (written <= 0)
        return false;

    size_t msgLen = static_cast<size_t>(written);
    if (msgLen > 0xFFFF)
        msgLen = 0xFFFF;
    size_t total = msgLen + sizeof(uint16_t);
    if (total == 0 || total >= kLuaTraceRingSize)
        return false;

    uint32_t head = g_luaTraceHead.load(std::memory_order_relaxed);
    uint32_t tail = g_luaTraceTail.load(std::memory_order_acquire);
    uint32_t used = head - tail;
    if (used >= kLuaTraceRingSize)
        return false;
    size_t freeSpace = kLuaTraceRingSize - static_cast<size_t>(used);
    if (freeSpace <= total)
        return false;

    uint32_t writePos = head;
    auto storeByte = [&](uint8_t byte) {
        g_luaTraceRing[writePos % kLuaTraceRingSize] = static_cast<char>(byte);
        ++writePos;
    };

    uint16_t storedLen = static_cast<uint16_t>(msgLen);
    storeByte(static_cast<uint8_t>(storedLen & 0xFFu));
    storeByte(static_cast<uint8_t>((storedLen >> 8) & 0xFFu));
    for (size_t i = 0; i < msgLen; ++i)
        storeByte(static_cast<uint8_t>(temp[i]));

    g_luaTraceHead.store(writePos, std::memory_order_release);
    return true;
}

static void DebugRingFlush() noexcept {
    uint32_t tail = g_luaTraceTail.load(std::memory_order_relaxed);
    uint32_t head = g_luaTraceHead.load(std::memory_order_acquire);
    if (tail == head)
        return;

    char message[512];
    while (tail < head) {
        uint32_t available = head - tail;
        if (available < 2)
            break;
        uint32_t readPos = tail % kLuaTraceRingSize;
        uint8_t low = static_cast<uint8_t>(g_luaTraceRing[readPos]);
        uint8_t high = static_cast<uint8_t>(g_luaTraceRing[(readPos + 1u) % kLuaTraceRingSize]);
        uint16_t storedLen = static_cast<uint16_t>(low | (static_cast<uint16_t>(high) << 8));
        if (storedLen == 0 || storedLen > kLuaTraceRingSize - 2) {
            tail = head;
            break;
        }
        if (available < static_cast<uint32_t>(storedLen) + 2)
            break;

        tail += 2;
        size_t copyLen = std::min<size_t>(storedLen, sizeof(message) - 1);
        for (size_t i = 0; i < copyLen; ++i)
            message[i] = g_luaTraceRing[(tail + static_cast<uint32_t>(i)) % kLuaTraceRingSize];
        message[copyLen] = '\0';
        if (storedLen > copyLen && sizeof(message) > 2)
            message[sizeof(message) - 2] = '\0';
        WriteRawLog(message);
        tail += storedLen;
    }
    g_luaTraceTail.store(tail, std::memory_order_release);
}

static bool DescribeAddressForLog(const void* address, char* moduleBuf, size_t moduleBufLen, void** moduleBaseOut, DWORD* protectOut) {
    if (moduleBuf && moduleBufLen)
        moduleBuf[0] = '\0';
    if (moduleBaseOut)
        *moduleBaseOut = nullptr;
    if (protectOut)
        *protectOut = 0;

    if (!address)
        return false;

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(address, &mbi, sizeof(mbi)))
        return false;

    if (moduleBaseOut)
        *moduleBaseOut = mbi.AllocationBase;
    if (protectOut)
        *protectOut = mbi.Protect;

    if (moduleBuf && moduleBufLen) {
        moduleBuf[0] = '\0';
        HMODULE module = static_cast<HMODULE>(mbi.AllocationBase);
        if (module) {
            char fullPath[MAX_PATH] = {};
            DWORD len = GetModuleFileNameA(module, fullPath, ARRAYSIZE(fullPath));
            if (len != 0) {
                const char* name = fullPath;
                for (const char* it = fullPath; *it; ++it) {
                    if (*it == '\\' || *it == '/')
                        name = it + 1;
                }
                strncpy_s(moduleBuf, moduleBufLen, name, _TRUNCATE);
            } else {
                strncpy_s(moduleBuf, moduleBufLen, "<unknown>", _TRUNCATE);
            }
        } else {
            strncpy_s(moduleBuf, moduleBufLen, "<anon>", _TRUNCATE);
        }
    }

    return true;
}

static bool IsPlausibleContextPointer(const void* ctx) {
    return ValidateCtxLoose(ctx) == CtxValidationResult::Ok;
}

static const HelperRetryPolicy& GetHelperRetryPolicy() {
    Core::EarlyTrace::Write("LuaBridge::GetHelperRetryPolicy call_once begin");
    try {
        std::call_once(g_helperRetryPolicyOnce, LoadHelperRetryPolicy);
        Core::EarlyTrace::Write("LuaBridge::GetHelperRetryPolicy call_once success");
    } catch (const std::system_error& e) {
        char buf[256];
        sprintf_s(buf,
                  sizeof(buf),
                  "LuaBridge::GetHelperRetryPolicy call_once threw code=%d category=%s what=%s",
                  e.code().value(),
                  e.code().category().name(),
                  e.what());
        Core::EarlyTrace::Write(buf);
        throw;
    }
    return g_helperRetryPolicy;
}

static lua_State* HelperStagePointer(const LuaStateInfo& state) {
    if (state.L_canonical)
        return state.L_canonical;
    if (state.L_reported)
        return state.L_reported;
    if (state.ctx_reported)
        return reinterpret_cast<lua_State*>(state.ctx_reported);
    return nullptr;
}

static const char* HelperStageName(HelperInstallStage stage) {
    switch (stage) {
    case HelperInstallStage::WaitingForGlobalState:
        return "waiting_for_global_state";
    case HelperInstallStage::WaitingForOwnerThread:
        return "waiting_for_owner_thread";
    case HelperInstallStage::ReadyToInstall:
        return "ready_to_install";
    case HelperInstallStage::Installing:
        return "installing";
    case HelperInstallStage::Installed:
        return "installed";
    default:
        return "unknown";
    }
}

static HelperInstallStage CurrentHelperStage(const LuaStateInfo& state) {
    return static_cast<HelperInstallStage>(state.helper_state);
}

static HelperInstallStage DetermineHelperStage(const LuaStateInfo& state, bool canonicalReadyFlag) {
    if ((state.flags & STATE_FLAG_HELPERS_INSTALLED) != 0)
        return HelperInstallStage::Installed;
    if ((state.flags & STATE_FLAG_HELPERS_PENDING) != 0 && state.helper_pending_generation == state.gen)
        return HelperInstallStage::Installing;
    if ((state.flags & STATE_FLAG_SLOT_READY) == 0 || !state.L_canonical || (state.flags & STATE_FLAG_REG_STABLE) == 0 || !canonicalReadyFlag)
        return HelperInstallStage::WaitingForGlobalState;
    if ((state.flags & STATE_FLAG_OWNER_READY) == 0 || state.owner_tid == 0)
        return HelperInstallStage::WaitingForOwnerThread;
    return HelperInstallStage::ReadyToInstall;
}

static void UpdateHelperStage(LuaStateInfo& state, HelperInstallStage nextStage, uint64_t now, const char* reason) {
    HelperInstallStage previous = CurrentHelperStage(state);
    if (previous == nextStage) {
        if (state.helper_state_since_ms == 0)
            state.helper_state_since_ms = now;
        return;
    }
    lua_State* logPtr = HelperStagePointer(state);
    uint64_t age = state.helper_state_since_ms ? (now - state.helper_state_since_ms) : 0;
    state.helper_state = static_cast<uint8_t>(nextStage);
    state.helper_state_since_ms = now;
    const char* prevName = HelperStageName(previous);
    const char* nextName = HelperStageName(nextStage);
    Log::Logf(Log::Level::Info,
              Log::Category::Hooks,
              "helpers stage L=%p %s->%s ageMs=%llu reason=%s",
              logPtr,
              prevName,
              nextName,
              static_cast<unsigned long long>(age),
              reason ? reason : "unknown");
    if (previous == HelperInstallStage::Installing && nextStage == HelperInstallStage::Installed) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "helpers stage L=%p installing->installed gen=%llu owner=%lu",
                  logPtr,
                  static_cast<unsigned long long>(state.gen),
                  static_cast<unsigned long>(state.owner_tid));
    }
}

static lua_CFunction g_origWindowRegisterEventHandler = nullptr;
static lua_CFunction g_origWindowUnregisterEventHandler = nullptr;
static lua_CFunction g_origRegisterEventHandler = nullptr;
static lua_CFunction g_origUnregisterEventHandler = nullptr;
static lua_CFunction g_origBroadcastEvent = nullptr;
static lua_CFunction g_origTryLogin = nullptr;
static lua_CFunction g_origSelectShard = nullptr;
static lua_CFunction g_origSelectCharacter = nullptr;
static lua_CFunction g_origRequestTargetInfo = nullptr;
static lua_CFunction g_origAcceptCriminalNotification = nullptr;
static lua_CFunction g_origCreateWaypoint = nullptr;
static lua_CFunction g_origDeleteWaypoint = nullptr;
static lua_CFunction g_origEditWaypoint = nullptr;
static lua_CFunction g_origSetWaypointFacet = nullptr;
static lua_CFunction g_origResetWaypointFacet = nullptr;
static lua_CFunction g_origSetWaypointDisplayMode = nullptr;
static lua_CFunction g_origSetWaypointTypeInfo = nullptr;

struct WaypointFacetLogState {
    uint64_t lastLogMs = 0;
    uint64_t lastSuppressMs = 0;
};
static std::mutex g_waypointFacetMutex;
static std::unordered_map<int, WaypointFacetLogState> g_waypointFacetLogState;
static constexpr uint64_t kWaypointFacetDebounceMs = 1500;

static thread_local bool g_pumpingLuaQueueFromScript = false;
static std::atomic<bool> g_queueNeedsPump{false};

static void MaybePumpLuaQueueFromScriptThread(const char* /*reason*/) {
    if (!g_queueNeedsPump.load(std::memory_order_acquire))
        return;
    DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
    DWORD current = GetCurrentThreadId();
    if (scriptTid == 0 || scriptTid != current)
        return;
    if (g_pumpingLuaQueueFromScript)
        return;
    g_pumpingLuaQueueFromScript = true;
    Engine::Lua::ProcessLuaQueue();
    g_pumpingLuaQueueFromScript = false;
}

static std::string DescribeLuaArgs(lua_State* L, int startIndex = 1, bool redactStrings = false) {
    int top = lua_gettop(L);
    std::string out;
    for (int i = startIndex; i <= top; ++i) {
        if (!out.empty())
            out.append(" ");
        char indexBuf[16];
        sprintf_s(indexBuf, sizeof(indexBuf), "#%d=", i);
        out.append(indexBuf);
        int type = lua_type(L, i);
        switch (type) {
        case LUA_TSTRING: {
            out.push_back('"');
            if (redactStrings) {
                out.append("<redacted>");
            } else {
                const char* str = lua_tolstring(L, i, nullptr);
                out.append(str ? str : "<null>");
            }
            out.push_back('"');
            break;
        }
        case LUA_TNUMBER: {
            lua_Number num = lua_tonumber(L, i);
            lua_Integer asInt = lua_tointeger(L, i);
            double diff = num - static_cast<lua_Number>(asInt);
            char numBuf[64];
            if (diff == 0.0) {
                sprintf_s(numBuf, sizeof(numBuf), "%lld", static_cast<long long>(asInt));
            } else {
                sprintf_s(numBuf, sizeof(numBuf), "%.4f", static_cast<double>(num));
            }
            out.append(numBuf);
            break;
        }
        case LUA_TBOOLEAN:
            out.append(lua_toboolean(L, i) ? "true" : "false");
            break;
        case LUA_TNIL:
            out.append("nil");
            break;
        case LUA_TTABLE:
        case LUA_TFUNCTION:
        case LUA_TUSERDATA:
        case LUA_TLIGHTUSERDATA: {
            out.append(lua_typename(L, type));
            void* ptr = const_cast<void*>(lua_topointer(L, i));
            if (ptr) {
                char ptrBuf[32];
                sprintf_s(ptrBuf, sizeof(ptrBuf), "@%p", ptr);
                out.append(ptrBuf);
            }
            break;
        }
        default:
            out.append(lua_typename(L, type));
            break;
        }
    }
    if (out.empty())
        out.assign("<none>");
    return out;
}

static bool SafeLuaProbeStack(lua_State* L, int* outTop, DWORD* outSeh) noexcept;
static bool SafeLuaProbeStack(lua_State* L, const LuaStateInfo& info, int* outTop, DWORD* outSeh) noexcept;
static bool SafeLuaSetTop(lua_State* L, int idx, DWORD* outSeh) noexcept;
static bool SafeLuaSetTop(lua_State* L, const LuaStateInfo& info, int idx, DWORD* outSeh) noexcept;
static bool SafeLuaGetTop(lua_State* L, int* outTop, DWORD* outSeh = nullptr) noexcept;
static bool SafeLuaGetTop(lua_State* L, const LuaStateInfo& info, int* outTop, DWORD* outSeh = nullptr) noexcept;
static bool SafeLuaGetStack(lua_State* L, int level, lua_Debug* ar, DWORD* outSeh = nullptr) noexcept;
static bool SafeLuaGetInfo(lua_State* L, const char* what, lua_Debug* ar, DWORD* outSeh = nullptr) noexcept;
static bool SafeLuaGetGlobalType(lua_State* L, const char* name, int* outType, const char** outTypeName, DWORD* outSeh) noexcept;
static bool TryInstallPanicHook(lua_State* L, lua_CFunction* outPrev, DWORD* outSeh = nullptr) noexcept;
static bool ClearHookSentinel(lua_State* L, DWORD* outSeh) noexcept;

class LuaStackGuard {
public:
    explicit LuaStackGuard(lua_State* L, const LuaStateInfo* info = nullptr) noexcept
        : L_(L), top_(0), valid_(false), legacy_(false), haveInfo_(false) {
        if (!L_)
            return;
        if (info) {
            info_ = *info;
            haveInfo_ = true;
        } else {
            LuaStateInfo fetched{};
            if (g_stateRegistry.GetByPointer(L_, fetched) && (fetched.flags & STATE_FLAG_VALID) && fetched.L_canonical) {
                info_ = fetched;
                haveInfo_ = true;
            }
        }
        if (haveInfo_) {
            if (SafeLuaGetTop(L_, info_, &top_, nullptr)) {
                valid_ = true;
            }
            return;
        }
        legacy_ = true;
        __try {
            top_ = lua_gettop(L_);
            valid_ = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            valid_ = false;
        }
    }

    ~LuaStackGuard() {
        if (!L_ || !valid_)
            return;
        if (legacy_) {
            __try {
                lua_settop(L_, top_);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
            }
            return;
        }
        SafeLuaSetTop(L_, info_, top_, nullptr);
    }

private:
    lua_State* L_;
    LuaStateInfo info_{};
    int top_;
    bool valid_;
    bool legacy_;
    bool haveInfo_;
};

static int __cdecl Hook_WindowRegisterEventHandler(lua_State* L) {
    LuaStackGuard guard(L);
    const char* window = lua_isstring(L, 1) ? lua_tolstring(L, 1, nullptr) : nullptr;
    lua_Integer eventId = lua_isnumber(L, 2) ? lua_tointeger(L, 2) : 0;
    const char* callback = lua_isstring(L, 3) ? lua_tolstring(L, 3, nullptr) : nullptr;
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][EVT] register window=%s event=0x%llX cb=%s",
              window ? window : "<nil>",
              static_cast<unsigned long long>(static_cast<std::uint64_t>(eventId)),
              callback ? callback : "<nil>");
    Net::ForceScan(Net::WakeReason::LoginTransition);
    return g_origWindowRegisterEventHandler ? g_origWindowRegisterEventHandler(L) : 0;
}

static int __cdecl Hook_WindowUnregisterEventHandler(lua_State* L) {
    LuaStackGuard guard(L);
    const char* window = lua_isstring(L, 1) ? lua_tolstring(L, 1, nullptr) : nullptr;
    lua_Integer eventId = lua_isnumber(L, 2) ? lua_tointeger(L, 2) : 0;
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][EVT] unregister window=%s event=0x%llX",
              window ? window : "<nil>",
              static_cast<unsigned long long>(static_cast<std::uint64_t>(eventId)));
    return g_origWindowUnregisterEventHandler ? g_origWindowUnregisterEventHandler(L) : 0;
}

static int __cdecl Hook_RegisterEventHandler(lua_State* L) {
    LuaStackGuard guard(L);
    std::string args = DescribeLuaArgs(L);
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][EVT] register_global args=%s",
              args.c_str());
    Net::ForceScan(Net::WakeReason::LoginTransition);
    return g_origRegisterEventHandler ? g_origRegisterEventHandler(L) : 0;
}

static int __cdecl Hook_UnregisterEventHandler(lua_State* L) {
    LuaStackGuard guard(L);
    std::string args = DescribeLuaArgs(L);
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][EVT] unregister_global args=%s",
              args.c_str());
    return g_origUnregisterEventHandler ? g_origUnregisterEventHandler(L) : 0;
}

static int __cdecl Hook_BroadcastEvent(lua_State* L) {
    LuaStackGuard guard(L);
    int top = lua_gettop(L);
    lua_Integer eventId = (top >= 1 && lua_isnumber(L, 1)) ? lua_tointeger(L, 1) : 0;
    std::string payload = (top >= 2) ? DescribeLuaArgs(L, 2) : "<none>";
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][EVT] broadcast event=0x%llX argc=%d payload=%s",
              static_cast<unsigned long long>(static_cast<std::uint64_t>(eventId)),
              top,
              payload.c_str());
    int rc = g_origBroadcastEvent ? g_origBroadcastEvent(L) : 0;
    MaybePumpLuaQueueFromScriptThread("broadcast");
    return rc;
}

static int __cdecl Hook_TryLogin(lua_State* L) {
    LuaStackGuard guard(L);
    std::string args = DescribeLuaArgs(L, 1, true);
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][LOGIN] TryLogin args=%s",
              args.c_str());
    Net::ForceScan(Net::WakeReason::LoginTransition);
    return g_origTryLogin ? g_origTryLogin(L) : 0;
}

static int __cdecl Hook_SelectShard(lua_State* L) {
    LuaStackGuard guard(L);
    std::string args = DescribeLuaArgs(L);
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][LOGIN] SelectShard args=%s",
              args.c_str());
    Net::ForceScan(Net::WakeReason::LoginTransition);
    return g_origSelectShard ? g_origSelectShard(L) : 0;
}

static int __cdecl Hook_SelectCharacter(lua_State* L) {
    LuaStackGuard guard(L);
    std::string args = DescribeLuaArgs(L);
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][LOGIN] SelectCharacter args=%s",
              args.c_str());
    Net::ForceScan(Net::WakeReason::LoginTransition);
    return g_origSelectCharacter ? g_origSelectCharacter(L) : 0;
}

static int __cdecl Hook_RequestTargetInfo(lua_State* L) {
    LuaStackGuard guard(L);
    std::string args = DescribeLuaArgs(L);
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][TARGET] RequestTargetInfo args=%s",
              args.c_str());
    return g_origRequestTargetInfo ? g_origRequestTargetInfo(L) : 0;
}

static int __cdecl Hook_AcceptCriminalNotification(lua_State* L) {
    LuaStackGuard guard(L);
    std::string args = DescribeLuaArgs(L);
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][TARGET] AcceptCriminalNotification args=%s",
              args.c_str());
    return g_origAcceptCriminalNotification ? g_origAcceptCriminalNotification(L) : 0;
}

static int __cdecl Hook_CreateWaypoint(lua_State* L) {
    LuaStackGuard guard(L);
    std::string args = DescribeLuaArgs(L);
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][MAP] UOCreateUserWaypoint args=%s",
              args.c_str());
    int rc = g_origCreateWaypoint ? g_origCreateWaypoint(L) : 0;
    MaybePumpLuaQueueFromScriptThread("waypoint-create");
    return rc;
}

static int __cdecl Hook_DeleteWaypoint(lua_State* L) {
    LuaStackGuard guard(L);
    std::string args = DescribeLuaArgs(L);
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][MAP] UODeleteUserWaypoint args=%s",
              args.c_str());
    int rc = g_origDeleteWaypoint ? g_origDeleteWaypoint(L) : 0;
    MaybePumpLuaQueueFromScriptThread("waypoint-delete");
    return rc;
}

static int __cdecl Hook_EditWaypoint(lua_State* L) {
    LuaStackGuard guard(L);
    std::string args = DescribeLuaArgs(L);
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][MAP] UOEditUserWaypoint args=%s",
              args.c_str());
    int rc = g_origEditWaypoint ? g_origEditWaypoint(L) : 0;
    MaybePumpLuaQueueFromScriptThread("waypoint-edit");
    return rc;
}

static int __cdecl Hook_SetWaypointFacet(lua_State* L) {
    LuaStackGuard guard(L);
    int facetValue = std::numeric_limits<int>::min();
    if (lua_gettop(L) >= 1) {
        if (lua_isnumber(L, 1)) {
            facetValue = static_cast<int>(lua_tointeger(L, 1));
        } else if (lua_isstring(L, 1)) {
            size_t facetLen = 0;
            const char* facetStr = lua_tolstring(L, 1, &facetLen);
            if (facetStr) {
                try {
                    facetValue = std::stoi(facetStr);
                } catch (...) {
                    facetValue = std::numeric_limits<int>::min();
                }
            }
        }
    }

    uint64_t now = GetTickCount64();
    bool suppress = false;
    bool logSuppression = false;
    {
        std::lock_guard<std::mutex> lock(g_waypointFacetMutex);
        WaypointFacetLogState& state = g_waypointFacetLogState[facetValue];
        if (state.lastLogMs && now - state.lastLogMs < kWaypointFacetDebounceMs) {
            if (!state.lastSuppressMs || now - state.lastSuppressMs >= kWaypointFacetDebounceMs) {
                state.lastSuppressMs = now;
                logSuppression = true;
            }
            suppress = true;
        } else {
            state.lastLogMs = now;
            state.lastSuppressMs = 0;
        }
    }

    if (suppress) {
        if (logSuppression) {
            Log::Logf(Log::Level::Info,
                      Log::Category::LuaGuard,
                      "UOSetWaypointMapFacet logging suppressed (debounce) facet=%d",
                      facetValue);
        }
    } else {
        std::string args = DescribeLuaArgs(L);
        Log::Logf(Log::Level::Info,
                  Log::Category::LuaGuard,
                  "[LUA][MAP] UOSetWaypointMapFacet args=%s",
                  args.c_str());
    }
    int rc = g_origSetWaypointFacet ? g_origSetWaypointFacet(L) : 0;
    MaybePumpLuaQueueFromScriptThread("facet");
    return rc;
}


static int __cdecl Hook_ResetWaypointFacet(lua_State* L) {
    LuaStackGuard guard(L);
    std::string args = DescribeLuaArgs(L);
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][MAP] UOResetWaypointMapFacet args=%s",
              args.c_str());
    int rc = g_origResetWaypointFacet ? g_origResetWaypointFacet(L) : 0;
    MaybePumpLuaQueueFromScriptThread("facet-reset");
    return rc;
}

static int __cdecl Hook_SetWaypointDisplayMode(lua_State* L) {
    LuaStackGuard guard(L);
    std::string args = DescribeLuaArgs(L);
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][MAP] UOSetWaypointDisplayMode args=%s",
              args.c_str());
    int rc = g_origSetWaypointDisplayMode ? g_origSetWaypointDisplayMode(L) : 0;
    MaybePumpLuaQueueFromScriptThread("facet-display");
    return rc;
}

static int __cdecl Hook_SetWaypointTypeInfo(lua_State* L) {
    LuaStackGuard guard(L);
    std::string args = DescribeLuaArgs(L);
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][MAP] UOSetWaypointTypeDisplayInfo args=%s",
              args.c_str());
    int rc = g_origSetWaypointTypeInfo ? g_origSetWaypointTypeInfo(L) : 0;
    MaybePumpLuaQueueFromScriptThread("facet-type");
    return rc;
}

static lua_CFunction MaybeWrapLuaFunction(const char* name, lua_CFunction func) {
    if (!name || !func)
        return func;

    if (_stricmp(name, "WindowRegisterEventHandler") == 0) {
        if (func != Hook_WindowRegisterEventHandler) {
            g_origWindowRegisterEventHandler = func;
            return &Hook_WindowRegisterEventHandler;
        }
        return func;
    }
    if (_stricmp(name, "WindowUnregisterEventHandler") == 0) {
        if (func != Hook_WindowUnregisterEventHandler) {
            g_origWindowUnregisterEventHandler = func;
            return &Hook_WindowUnregisterEventHandler;
        }
        return func;
    }
    if (_stricmp(name, "RegisterEventHandler") == 0) {
        if (func != Hook_RegisterEventHandler) {
            g_origRegisterEventHandler = func;
            return &Hook_RegisterEventHandler;
        }
        return func;
    }
    if (_stricmp(name, "UnregisterEventHandler") == 0) {
        if (func != Hook_UnregisterEventHandler) {
            g_origUnregisterEventHandler = func;
            return &Hook_UnregisterEventHandler;
        }
        return func;
    }
    if (_stricmp(name, "BroadcastEvent") == 0) {
        if (func != Hook_BroadcastEvent) {
            g_origBroadcastEvent = func;
            return &Hook_BroadcastEvent;
        }
        return func;
    }
    if (_stricmp(name, "TryLogin") == 0) {
        if (func != Hook_TryLogin) {
            g_origTryLogin = func;
            return &Hook_TryLogin;
        }
        return func;
    }
    if (_stricmp(name, "SelectShard") == 0) {
        if (func != Hook_SelectShard) {
            g_origSelectShard = func;
            return &Hook_SelectShard;
        }
        return func;
    }
    if (_stricmp(name, "SelectCharacter") == 0) {
        if (func != Hook_SelectCharacter) {
            g_origSelectCharacter = func;
            return &Hook_SelectCharacter;
        }
        return func;
    }
    if (_stricmp(name, "RequestTargetInfo") == 0) {
        if (func != Hook_RequestTargetInfo) {
            g_origRequestTargetInfo = func;
            return &Hook_RequestTargetInfo;
        }
        return func;
    }
    if (_stricmp(name, "AcceptCriminalNotification") == 0) {
        if (func != Hook_AcceptCriminalNotification) {
            g_origAcceptCriminalNotification = func;
            return &Hook_AcceptCriminalNotification;
        }
        return func;
    }
    if (_stricmp(name, "UOCreateUserWaypoint") == 0) {
        if (func != Hook_CreateWaypoint) {
            g_origCreateWaypoint = func;
            return &Hook_CreateWaypoint;
        }
        return func;
    }
    if (_stricmp(name, "UODeleteUserWaypoint") == 0) {
        if (func != Hook_DeleteWaypoint) {
            g_origDeleteWaypoint = func;
            return &Hook_DeleteWaypoint;
        }
        return func;
    }
    if (_stricmp(name, "UOEditUserWaypoint") == 0) {
        if (func != Hook_EditWaypoint) {
            g_origEditWaypoint = func;
            return &Hook_EditWaypoint;
        }
        return func;
    }
    if (_stricmp(name, "UOSetWaypointMapFacet") == 0) {
        if (func != Hook_SetWaypointFacet) {
            g_origSetWaypointFacet = func;
            return &Hook_SetWaypointFacet;
        }
        return func;
    }
    if (_stricmp(name, "UOResetWaypointMapFacet") == 0) {
        if (func != Hook_ResetWaypointFacet) {
            g_origResetWaypointFacet = func;
            return &Hook_ResetWaypointFacet;
        }
        return func;
    }
    if (_stricmp(name, "UOSetWaypointDisplayMode") == 0) {
        if (func != Hook_SetWaypointDisplayMode) {
            g_origSetWaypointDisplayMode = func;
            return &Hook_SetWaypointDisplayMode;
        }
        return func;
    }
    if (_stricmp(name, "UOSetWaypointTypeDisplayInfo") == 0) {
        if (func != Hook_SetWaypointTypeInfo) {
            g_origSetWaypointTypeInfo = func;
            return &Hook_SetWaypointTypeInfo;
        }
        return func;
    }

    return func;
}

static void ClearHelperPending(lua_State* L, uint64_t generation, LuaStateInfo* infoOut = nullptr) {
    if (!L)
        return;
    bool scheduleWake = false;
    bool scheduleOwnerPump = false;
    g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
        if (generation == 0 || state.helper_pending_generation == generation) {
            bool wasPending = (state.flags & STATE_FLAG_HELPERS_PENDING) != 0;
            HelperInstallStage previousStage = CurrentHelperStage(state);
            state.flags &= ~STATE_FLAG_HELPERS_PENDING;
            state.helper_pending_generation = 0;
            state.helper_pending_tick_ms = 0;
            state.helper_flags &= ~HELPER_FLAG_SETTLE_ARMED;
            if ((state.flags & STATE_FLAG_HELPERS_INSTALLED) == 0) {
                uint64_t now = GetTickCount64();
                bool canonicalReady = (state.flags & STATE_FLAG_CANON_READY) != 0;
                HelperInstallStage nextStage = DetermineHelperStage(state, canonicalReady);
                if (nextStage == HelperInstallStage::ReadyToInstall && canonicalReady) {
                    if (state.helper_rebind_attempts != 0 && state.helper_rebind_attempts <= 3)
                        nextStage = HelperInstallStage::Installing;
                }
                UpdateHelperStage(state, nextStage, now, "clear-pending");
                HelperInstallStage currentStage = CurrentHelperStage(state);
                if (wasPending && currentStage == HelperInstallStage::ReadyToInstall)
                {
                    scheduleWake = true;
                    scheduleOwnerPump = true;
                }
            }
            else if (wasPending) {
                scheduleWake = true;
            }
        }
    }, infoOut);
    if (scheduleOwnerPump)
        PostOwnerPumpUnstick(L, generation);
    if (scheduleWake)
        Net::ForceScan(Net::WakeReason::OwnerPumpClear);
}

static void MaybeEmitHelperSummary(uint64_t now, bool force = false) {
    if (!force) {
        uint64_t last = g_lastHelperSummaryTick.load(std::memory_order_relaxed);
        if (now - last < kBindSummaryIntervalMs)
            return;
        if (!g_lastHelperSummaryTick.compare_exchange_strong(last, now, std::memory_order_acq_rel))
            return;
    } else {
        g_lastHelperSummaryTick.store(now, std::memory_order_release);
    }

    uint32_t scheduled = g_helperScheduledCount.exchange(0u, std::memory_order_acq_rel);
    uint32_t installed = g_helperInstalledCount.exchange(0u, std::memory_order_acq_rel);
    uint32_t deferred = g_helperDeferredCount.exchange(0u, std::memory_order_acq_rel);
    DWORD ownerTid = g_lastHelperOwnerThread.load(std::memory_order_relaxed);
    DWORD canonicalOwnerTid = GetCanonicalHelperOwnerTid();
    if (scheduled || installed || deferred || canonicalOwnerTid || force) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "helpers summary scheduled=%u installed=%u deferred=%u ownerTid=%lu helperOwnerTid=%lu",
                  scheduled,
                  installed,
                  deferred,
                  static_cast<unsigned long>(ownerTid),
                  static_cast<unsigned long>(canonicalOwnerTid));
    }
}

static constexpr const char* kHelperWalkName = "uow_walk";
static constexpr const char* kHelperWalkMoveName = "WalkMove";
static constexpr const char* kHelperGetPacingName = "GetPacing";
static constexpr const char* kHelperSetPacingName = "uow_set_pacing";
static constexpr const char* kHelperSetInflightName = "uow_set_inflight";
static constexpr const char* kHelperGetWalkMetricsName = "GetWalkMetrics";
static constexpr const char* kHelperStatusFlagsName = "UOW_StatusFlags";
static constexpr const char* kHelperStatusFlagsAliasName = "UOW_StatusFlagsEx";
static constexpr const char* kHelperTestRetName = "UOW_TestRet";
static constexpr const char* kHelperDumpName = "uow_dump_walk_env";
static constexpr const char* kHelperInspectName = "uow_lua_inspect";
static constexpr const char* kHelperRebindName = "uow_lua_rebind_all";
static constexpr const char* kHelperSelfTestName = "uow_selftest";
static constexpr const char* kHelperDebugName = "uow_debug";
static constexpr const char* kHelperDebugStatusName = "uow_debug_status";
static constexpr const char* kHelperDebugPingName = "uow_debug_ping";
static char g_hookSentinelKey = 0;
static char kUOW_StatusFlagsKey = 0;
static char kUOW_StatusFlagsExKey = 0;
static constexpr uint32_t kVerifyStatusFlagsBit = 1u << 0;
static constexpr uint32_t kVerifyStatusFlagsExBit = 1u << 1;
static std::atomic<int> g_statusShimWatchdogBudget{0};
static std::atomic<uint32_t> g_statusShimVerifyMask{0};

static void LogLuaBind(const char* fmt, ...);
static void LogLuaState(const char* fmt, ...);
static bool DebugInstrumentationEnabled();

static int top(lua_State* L) {
    return lua_gettop(L);
}

static void log_top(lua_State* L, const char* tag) {
    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[UOW][statusflags] %s: top=%d",
              tag ? tag : "<null>",
              top(L));
}

static std::atomic<uint64_t> g_lastContextMutationTick{0};
static std::atomic<uint64_t> g_lastDestabilizedTick{0};
static std::atomic<uint64_t> g_lastCanonicalReadyTick{0};
static std::atomic<uint64_t> g_lastLuaHeartbeatTick{0};
static std::atomic<uint64_t> g_lastWaypointFacetTick{0};
static std::atomic<uint32_t> g_sehTrapCount{0};
static std::atomic<uint64_t> g_lastDebugDeferLogTick{0};
static std::atomic<uint64_t> g_lastDebugStableLogTick{0};
static std::atomic<uint64_t> g_lastSentinelStackLogTick{0};
static std::atomic<uint32_t> g_guardFailCanon{0};
static std::atomic<uint32_t> g_guardFailOwner{0};
static std::atomic<uint32_t> g_guardFailRead{0};
static std::atomic<uint32_t> g_guardFailSeh{0};
static std::atomic<uint32_t> g_guardFailPlausible{0};
static std::atomic<uint64_t> g_guardFailLastLogTick{0};
static std::mutex g_debugInstallMutex;
static std::unordered_set<lua_State*> g_debugInstallInFlight;
struct DebugInstallRetryInfo {
    uint64_t dueTick = 0;
    uint64_t generation = 0;
};
static std::unordered_map<lua_State*, DebugInstallRetryInfo> g_debugInstallRetry;
static constexpr DWORD kDebugInstallStableWindowMs = 500;
static constexpr int kMaxReasonableLuaTop = 1'000'000;
static constexpr DWORD kLuaStatusImplausibleTop = 0xE0001001; // custom status for implausible lua_gettop result
static constexpr DWORD kLuaStatusGuardCanon = 0xE0002001;
static constexpr DWORD kLuaStatusGuardOwner = 0xE0002002;
static constexpr DWORD kLuaStatusGuardRead = 0xE0002003;
static constexpr DWORD kLuaStatusGuardSeh = 0xE0002004;
static constexpr DWORD kLuaStatusGuardGeneration = 0xE0002005;

static uint64_t GetDebugTickNow() {
    return GetTickCount64();
}

static bool IsLuaStackTopPlausible(int top) noexcept {
    return top >= 0 && top <= kMaxReasonableLuaTop;
}

static DWORD MapGuardFailureToStatus(Engine::Lua::LuaGuardFailure reason) noexcept {
    using Engine::Lua::LuaGuardFailure;
    switch (reason) {
    case LuaGuardFailure::None:
        return 0;
    case LuaGuardFailure::CanonMismatch:
        return kLuaStatusGuardCanon;
    case LuaGuardFailure::GenerationMismatch:
        return kLuaStatusGuardGeneration;
    case LuaGuardFailure::OwnerMismatch:
        return kLuaStatusGuardOwner;
    case LuaGuardFailure::ReadCheckFailed:
        return kLuaStatusGuardRead;
    case LuaGuardFailure::Seh:
        return kLuaStatusGuardSeh;
    case LuaGuardFailure::ImplausibleTop:
        return kLuaStatusImplausibleTop;
    default:
        return kLuaStatusGuardSeh;
    }
}

static const char* DescribeGuardFailure(Engine::Lua::LuaGuardFailure reason) noexcept {
    using Engine::Lua::LuaGuardFailure;
    switch (reason) {
    case LuaGuardFailure::None:
        return "none";
    case LuaGuardFailure::CanonMismatch:
        return "canon_mismatch";
    case LuaGuardFailure::GenerationMismatch:
        return "generation_mismatch";
    case LuaGuardFailure::OwnerMismatch:
        return "owner_mismatch";
    case LuaGuardFailure::ReadCheckFailed:
        return "read_check_failed";
    case LuaGuardFailure::Seh:
        return "seh";
    case LuaGuardFailure::ImplausibleTop:
        return "implausible_top";
    default:
        return "unknown";
    }
}

static void NoteGuardFailure(Engine::Lua::LuaGuardFailure reason) {
    using Engine::Lua::LuaGuardFailure;
    if (reason == LuaGuardFailure::None)
        return;

    switch (reason) {
    case LuaGuardFailure::CanonMismatch:
    case LuaGuardFailure::GenerationMismatch:
        g_guardFailCanon.fetch_add(1, std::memory_order_relaxed);
        break;
    case LuaGuardFailure::OwnerMismatch:
        g_guardFailOwner.fetch_add(1, std::memory_order_relaxed);
        break;
    case LuaGuardFailure::ReadCheckFailed:
        g_guardFailRead.fetch_add(1, std::memory_order_relaxed);
        break;
    case LuaGuardFailure::Seh:
        g_guardFailSeh.fetch_add(1, std::memory_order_relaxed);
        break;
    case LuaGuardFailure::ImplausibleTop:
        g_guardFailPlausible.fetch_add(1, std::memory_order_relaxed);
        break;
    default:
        break;
    }

    uint64_t now = GetTickCount64();
    uint64_t last = g_guardFailLastLogTick.load(std::memory_order_acquire);
    if (now - last < 5000)
        return;
    if (!g_guardFailLastLogTick.compare_exchange_strong(last, now, std::memory_order_acq_rel, std::memory_order_acquire))
        return;

    uint32_t canon = g_guardFailCanon.exchange(0, std::memory_order_acq_rel);
    uint32_t owner = g_guardFailOwner.exchange(0, std::memory_order_acq_rel);
    uint32_t read = g_guardFailRead.exchange(0, std::memory_order_acq_rel);
    uint32_t seh = g_guardFailSeh.exchange(0, std::memory_order_acq_rel);
    uint32_t plaus = g_guardFailPlausible.exchange(0, std::memory_order_acq_rel);

    if (canon || owner || read || seh || plaus) {
        LogLuaBind("lua-guard summary canon=%u owner=%u read=%u seh=%u plausible=%u",
                   canon,
                   owner,
                   read,
                   seh,
                   plaus);
    }
}

static void LogLuaStateSnapshot(lua_State* L) {
    if (!L)
        return;

    LuaStateInfo snapshot{};
    if (!g_stateRegistry.GetByPointer(L, snapshot))
        return;
    if (!Engine::Lua::ValidateLuaStateShallow(L, snapshot.expected_global))
        return;

    __try {
        constexpr size_t kWordCount = 8;
        uintptr_t words[kWordCount]{};
        const uintptr_t* wordPtr = reinterpret_cast<const uintptr_t*>(L);
        for (size_t i = 0; i < kWordCount; ++i)
            words[i] = wordPtr[i];

        constexpr size_t kByteCount = 64;
        unsigned char bytes[kByteCount]{};
        const unsigned char* bytePtr = reinterpret_cast<const unsigned char*>(L);
        for (size_t i = 0; i < kByteCount; ++i)
            bytes[i] = bytePtr[i];

        char wordsBuf[256];
        size_t wordOffset = 0;
        for (size_t i = 0; i < kWordCount && wordOffset < sizeof(wordsBuf); ++i) {
            int written = _snprintf_s(wordsBuf + wordOffset,
                                      sizeof(wordsBuf) - wordOffset,
                                      _TRUNCATE,
                                      (i == 0) ? "0x%p" : " 0x%p",
                                      reinterpret_cast<void*>(words[i]));
            if (written <= 0)
                break;
            wordOffset += static_cast<size_t>(written);
        }
        if (wordOffset >= sizeof(wordsBuf))
            wordsBuf[sizeof(wordsBuf) - 1] = '\0';

        char bytesBuf[kByteCount * 3 + 1];
        size_t byteOffset = 0;
        for (size_t i = 0; i < kByteCount && byteOffset + 3 < sizeof(bytesBuf); ++i) {
            int written = _snprintf_s(bytesBuf + byteOffset,
                                      sizeof(bytesBuf) - byteOffset,
                                      _TRUNCATE,
                                      "%02X",
                                      static_cast<unsigned int>(bytes[i]));
            if (written <= 0)
                break;
            byteOffset += static_cast<size_t>(written);
            if (i + 1 < kByteCount && byteOffset + 1 < sizeof(bytesBuf))
                bytesBuf[byteOffset++] = (i % 16 == 15) ? '|' : ' ';
        }
        if (byteOffset >= sizeof(bytesBuf))
            bytesBuf[sizeof(bytesBuf) - 1] = '\0';
        else
            bytesBuf[byteOffset] = '\0';

        LogLuaBind("lua-state snapshot L=%p words[0..7]=%s", L, wordsBuf);
        LogLuaBind("lua-state bytes L=%p head64=%s", L, bytesBuf);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        LogLuaBind("lua-state snapshot-seh L=%p code=0x%08lX", L, code);
    }
}

static void NoteDestabilization(uint64_t tick, const char* reason = nullptr, const char* detail = nullptr) {
    uint64_t previous = g_lastDestabilizedTick.exchange(tick, std::memory_order_acq_rel);
    if (DebugInstrumentationEnabled()) {
        lua_State* canonical = g_canonicalState.load(std::memory_order_acquire);
        uint64_t readyTick = g_lastCanonicalReadyTick.load(std::memory_order_acquire);
        const uint64_t window = static_cast<uint64_t>(kDebugInstallStableWindowMs);
        uint64_t stableDuration = (previous && tick >= previous) ? (tick - previous) : 0;
        uint64_t readyAge = (readyTick && tick >= readyTick) ? (tick - readyTick) : 0;
        LogLuaState("canonical-destabilized Lc=%p reason=%s context=%s tick=%llu prev=%llu stable=%llu ready=%llu ready-age=%llu window=%llu",
                    canonical,
                    reason ? reason : "unknown",
                    detail ? detail : "n/a",
                    static_cast<unsigned long long>(tick),
                    static_cast<unsigned long long>(previous),
                    static_cast<unsigned long long>(stableDuration),
                    static_cast<unsigned long long>(readyTick),
                    static_cast<unsigned long long>(readyAge),
                    static_cast<unsigned long long>(window));
    }
}

static void NoteDestabilization(const char* reason = nullptr, const char* detail = nullptr) {
    NoteDestabilization(GetDebugTickNow(), reason, detail);
}

static void NoteContextMutation() {
    uint64_t now = GetDebugTickNow();
    g_lastContextMutationTick.store(now, std::memory_order_release);
    NoteDestabilization(now, "context-mutation");
}

static bool TryGetConfigValue(const char* key, std::string* outValue) {
    if (!key)
        return false;
    auto value = Core::Config::TryGetValue(key);
    if (!value)
        return false;
    if (outValue)
        *outValue = *value;
    return true;
}

static bool TryReadConfigBool(const char* key, bool* outValue) {
    if (!key || !outValue)
        return false;
    auto value = Core::Config::TryGetBool(key);
    if (!value)
        return false;
    *outValue = *value;
    return true;
}

static bool TryReadEnvBool(const char* name, bool* outValue) {
    if (!name || !outValue)
        return false;
    auto value = Core::Config::TryGetEnvBool(name);
    if (!value)
        return false;
    *outValue = *value;
    return true;
}

static bool DebugInstallEnvEnabled() {
#if defined(_DEBUG)
    return true;
#else
    static int cached = -1;
    static bool enabled = false;
    if (cached < 0) {
        bool value = false;
        if (TryReadEnvBool("UOW_DEBUG_INSTALL", &value)) {
            enabled = value;
        } else if (TryReadConfigBool("UOW_DEBUG_INSTALL", &value)) {
            enabled = value;
        } else {
            enabled = false;
        }
        cached = 1;
    }
    return enabled;
#endif
}

static int Lua_UOWStatusFlags(lua_State* L);

static void LogGlobalFn(lua_State* L, const char* name) {
    if (!L || !name)
        return;
    DWORD seh = 0;
    bool ok = sp::seh_probe([&]() {
        int top = lua_gettop(L);
        lua_getglobal(L, name);
        int type = lua_type(L, -1);
        const char* typeName = lua_typename(L, type);
        int isCFunc = (type == LUA_TFUNCTION) ? lua_iscfunction(L, -1) : 0;
        const void* ptr = lua_topointer(L, -1);
        const char* src = "";
        if (type == LUA_TFUNCTION) {
            lua_Debug ar{};
            lua_pushvalue(L, -1);
            if (lua_getinfo(L, ">S", &ar) != 0)
                src = ar.short_src;
            lua_pop(L, 1);
        }
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[UOW][verify] %s type=%s iscfunc=%d ptr=%p src=%s",
                  name ? name : "<null>",
                  typeName ? typeName : "<unknown>",
                  isCFunc,
                  ptr,
                  src ? src : "");
        lua_settop(L, top);
    }, &seh);
    if (!ok) {
        Log::Logf(Log::Level::Warn,
                  Log::Category::Core,
                  "[UOW][verify] %s probe-seh=0x%08lX",
                  name ? name : "<null>",
                  static_cast<unsigned long>(seh));
    }
}

static void StoreRegistryCFunction(lua_State* L, void* key, lua_CFunction fn) {
    if (!L || !key || !fn)
        return;
    int top = lua_gettop(L);
    lua_pushlightuserdata(L, key);
    lua_pushcfunction(L, fn);
    lua_rawset(L, LUA_REGISTRYINDEX);
    lua_settop(L, top);
}

static void RequestStatusVerify(uint32_t bits) {
    if (bits == 0)
        return;
    g_statusShimVerifyMask.fetch_or(bits, std::memory_order_relaxed);
}

static void StoreRealStatusFlags(lua_State* L) {
    StoreRegistryCFunction(L, &kUOW_StatusFlagsKey, Lua_UOWStatusFlags);
    RequestStatusVerify(kVerifyStatusFlagsBit);
}

static void StoreRealStatusFlagsEx(lua_State* L) {
    StoreRegistryCFunction(L, &kUOW_StatusFlagsExKey, Lua_UOWStatusFlags);
    RequestStatusVerify(kVerifyStatusFlagsBit | kVerifyStatusFlagsExBit);
}

static int ForwardRegistryCall(lua_State* L, void* key, lua_CFunction fallback, const char* name) {
    if (!L)
        return 0;
    lua_pushlightuserdata(L, key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    int type = lua_type(L, -1);
    bool isCFunc = (type == LUA_TFUNCTION) && lua_iscfunction(L, -1);
    if (!isCFunc) {
        lua_pop(L, 1);
        Log::Logf(Log::Level::Warn,
                  Log::Category::Core,
                  "[UOW][shim] %s missing registry target (fallback to real)",
                  name ? name : "<unknown>");
        return fallback ? fallback(L) : 0;
    }
    lua_insert(L, 1);
    int nargs = lua_gettop(L) - 1;
    lua_call(L, nargs, LUA_MULTRET);
    int results = lua_gettop(L);
    return results;
}

static int Lua_UOW_StatusFlagsShim(lua_State* L) {
    return ForwardRegistryCall(L, &kUOW_StatusFlagsKey, Lua_UOWStatusFlags, kHelperStatusFlagsName);
}

static int Lua_UOW_StatusFlagsExShim(lua_State* L) {
    return ForwardRegistryCall(L, &kUOW_StatusFlagsExKey, Lua_UOWStatusFlags, kHelperStatusFlagsAliasName);
}

static uint32_t VerifyBitsForName(const char* name) {
    if (!name)
        return 0;
    if (_stricmp(name, kHelperStatusFlagsName) == 0)
        return kVerifyStatusFlagsBit;
    if (_stricmp(name, kHelperStatusFlagsAliasName) == 0)
        return kVerifyStatusFlagsExBit;
    return 0;
}

static void ReassertBinding(lua_State* L, const char* name, lua_CFunction shim, bool logIfStable = false) {
    if (!L || !name || !shim)
        return;
    DWORD seh = 0;
    bool probeOk = sp::seh_probe([&]() {
        int top = lua_gettop(L);
        lua_getglobal(L, name);
        bool ok = (lua_type(L, -1) == LUA_TFUNCTION) && lua_iscfunction(L, -1) && (lua_tocfunction(L, -1) == shim);
        lua_pop(L, 1);
        if (!ok) {
            Log::Logf(Log::Level::Info,
                      Log::Category::Core,
                      "[UOW] Rebinding global %s to shim",
                      name);
            lua_pushcfunction(L, shim);
            lua_setglobal(L, name);
            RequestStatusVerify(VerifyBitsForName(name));
        } else if (logIfStable) {
            RequestStatusVerify(VerifyBitsForName(name));
        }
        lua_settop(L, top);
    }, &seh);
    if (!probeOk) {
        Log::Logf(Log::Level::Warn,
                  Log::Category::Core,
                  "[UOW] ReassertBinding seh name=%s code=0x%08lX",
                  name ? name : "<null>",
                  static_cast<unsigned long>(seh));
        RequestStatusVerify(VerifyBitsForName(name));
    }
}

static bool IsOverwriteLoggerEnabled() {
    static std::once_flag onceFlag;
    static bool enabled = false;
    std::call_once(onceFlag, []() {
        if (auto value = Core::Config::TryGetEnvBool("UOW_TRACE_OVERWRITES"))
            enabled = *value;
    });
    return enabled;
}

static int GlobalNewIndexLogger(lua_State* L) {
    const char* key = lua_tolstring(L, 2, nullptr);
    if (key && (!std::strcmp(key, kHelperStatusFlagsName) || !std::strcmp(key, kHelperStatusFlagsAliasName))) {
        bool isCF = lua_iscfunction(L, 3);
        const void* ptr = lua_topointer(L, 3);
        const char* src = "";
        lua_Debug ar{};
        if (lua_type(L, 3) == LUA_TFUNCTION && !isCF) {
            lua_pushvalue(L, 3);
            if (lua_getinfo(L, ">S", &ar) != 0)
                src = ar.short_src;
            lua_pop(L, 1);
        }
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[UOW][overwrite] _G.%s = (%s) ptr=%p src=%s",
                  key,
                  isCF ? "cfunction" : lua_typename(L, lua_type(L, 3)),
                  ptr,
                  src ? src : "");
    }
    lua_rawset(L, 1);
    return 0;
}

static void InstallGlobalOverwriteLogger(lua_State* L) {
    if (!L || !IsOverwriteLoggerEnabled())
        return;
    DWORD seh = 0;
    bool probeOk = sp::seh_probe([&]() {
        int top = lua_gettop(L);
        lua_getglobal(L, "_G");
        if (lua_type(L, -1) == LUA_TTABLE) {
            int hasMeta = lua_getmetatable(L, -1);
            if (hasMeta == 0)
                lua_newtable(L);
            lua_pushstring(L, "__newindex");
            lua_pushcfunction(L, GlobalNewIndexLogger);
            lua_rawset(L, -3);
            lua_setmetatable(L, -2);
        }
        lua_pop(L, 1);
        lua_settop(L, top);
    }, &seh);
    if (!probeOk) {
        Log::Logf(Log::Level::Warn,
                  Log::Category::Core,
                  "[UOW] InstallGlobalOverwriteLogger seh code=0x%08lX",
                  static_cast<unsigned long>(seh));
    }
}

static void MaybeLogInstallDefer(lua_State* L, const char* reason) {
    uint64_t now = GetDebugTickNow();
    uint64_t last = g_lastDebugDeferLogTick.load(std::memory_order_acquire);
    if (now - last < 250)
        return;
    if (g_lastDebugDeferLogTick.compare_exchange_strong(last, now, std::memory_order_acq_rel, std::memory_order_acquire)) {
        uint64_t readyTick = g_lastCanonicalReadyTick.load(std::memory_order_acquire);
        uint64_t destabilized = g_lastDestabilizedTick.load(std::memory_order_acquire);
        uint64_t readyAge = (readyTick && now >= readyTick) ? (now - readyTick) : 0;
        uint64_t stableDuration = (destabilized && now >= destabilized) ? (now - destabilized) : 0;
        const uint64_t window = static_cast<uint64_t>(kDebugInstallStableWindowMs);
        const uint64_t remaining = (stableDuration < window) ? (window - stableDuration) : 0;
        const uint64_t extendedWindow = window * 4u;
        const uint64_t extendedRemaining = (stableDuration < extendedWindow) ? (extendedWindow - stableDuration) : 0;
        const bool movementReady = Engine::MovementReady();
        DWORD ownerTid = 0;
        uint64_t generation = 0;
        if (L) {
            LuaStateInfo snapshot{};
            if (g_stateRegistry.GetByPointer(L, snapshot)) {
                ownerTid = snapshot.owner_tid;
                generation = snapshot.gen;
            }
        }
        LogLuaBind("hooks-install deferred Lc=%p reason=%s now=%llu ready=%llu dest=%llu stable=%llu remain=%llu window=%llu extRemain=%llu movement=%d ready-age=%llu delta=%llu owner=%lu gen=%llu",
                   L,
                   reason ? reason : "unknown",
                   static_cast<unsigned long long>(now),
                   static_cast<unsigned long long>(readyTick),
                   static_cast<unsigned long long>(destabilized),
                    static_cast<unsigned long long>(stableDuration),
                    static_cast<unsigned long long>(remaining),
                    static_cast<unsigned long long>(window),
                    static_cast<unsigned long long>(extendedRemaining),
                    movementReady ? 1 : 0,
                    static_cast<unsigned long long>(readyAge),
                    static_cast<unsigned long long>((readyTick > destabilized) ? (readyTick - destabilized) : 0),
                    static_cast<unsigned long>(ownerTid),
                    static_cast<unsigned long long>(generation));
    }
}

static void MaybeLogInstallStable(lua_State* L) {
    uint64_t now = GetDebugTickNow();
    uint64_t last = g_lastDebugStableLogTick.load(std::memory_order_acquire);
    if (now - last < 250)
        return;
    if (g_lastDebugStableLogTick.compare_exchange_strong(last, now, std::memory_order_acq_rel, std::memory_order_acquire)) {
        uint64_t readyTick = g_lastCanonicalReadyTick.load(std::memory_order_acquire);
        uint64_t destabilized = g_lastDestabilizedTick.load(std::memory_order_acquire);
        uint64_t readyAge = (readyTick && now >= readyTick) ? (now - readyTick) : 0;
        uint64_t stableDuration = (destabilized && now >= destabilized) ? (now - destabilized) : 0;
        const uint64_t window = static_cast<uint64_t>(kDebugInstallStableWindowMs);
        DWORD ownerTid = 0;
        uint64_t generation = 0;
        if (L) {
            LuaStateInfo snapshot{};
            if (g_stateRegistry.GetByPointer(L, snapshot)) {
                ownerTid = snapshot.owner_tid;
                generation = snapshot.gen;
            }
        }
        const bool movementReady = Engine::MovementReady();
        LogLuaBind("hooks-install stable-ok Lc=%p now=%llu ready=%llu dest=%llu stable=%llu window=%llu ready-age=%llu movement=%d owner=%lu gen=%llu",
                   L,
                   static_cast<unsigned long long>(now),
                   static_cast<unsigned long long>(readyTick),
                   static_cast<unsigned long long>(destabilized),
                   static_cast<unsigned long long>(stableDuration),
                   static_cast<unsigned long long>(window),
                   static_cast<unsigned long long>(readyAge),
                   movementReady ? 1 : 0,
                   static_cast<unsigned long>(ownerTid),
                   static_cast<unsigned long long>(generation));
    }
}

class DebugInstallGuard {
public:
    explicit DebugInstallGuard(lua_State* state) : state_(state), acquired_(false) {
        if (!state_)
            return;
        std::lock_guard<std::mutex> lock(g_debugInstallMutex);
        auto inserted = g_debugInstallInFlight.insert(state_);
        acquired_ = inserted.second;
    }

    ~DebugInstallGuard() {
        if (!acquired_ || !state_)
            return;
        std::lock_guard<std::mutex> lock(g_debugInstallMutex);
        g_debugInstallInFlight.erase(state_);
    }

    bool acquired() const noexcept { return acquired_; }

private:
    lua_State* state_;
    bool acquired_;
};

static void InstallPanicAndDebug(lua_State* L, LuaStateInfo& info);
static void PostToOwnerWithTask(lua_State* L, const char* taskName, std::function<void()> fn);
static bool IsDebugInstallRetryPending(lua_State* L, uint64_t now, DebugInstallRetryInfo* outInfo = nullptr);

static void ScheduleDebugInstallRetry(lua_State* L, uint32_t delayMs = kDebugInstallStableWindowMs) {
    if (!L)
        return;

    LuaStateInfo info{};
    uint64_t generation = 0;
    if (g_stateRegistry.GetByPointer(L, info))
        generation = info.gen;

    uint64_t now = GetDebugTickNow();
    DebugInstallRetryInfo pendingInfo{};
    if (IsDebugInstallRetryPending(L, now, &pendingInfo) && pendingInfo.generation == generation) {
        uint64_t remaining = (pendingInfo.dueTick > now) ? (pendingInfo.dueTick - now) : 0;
        LogLuaBind("hooks-install retry-pending Lc=%p remaining=%llu gen=%llu",
                   L,
                   static_cast<unsigned long long>(remaining),
                   static_cast<unsigned long long>(pendingInfo.generation));
        return;
    }

    uint64_t target = now + delayMs;
    bool scheduled = false;
    {
        std::lock_guard<std::mutex> lock(g_debugInstallMutex);
        auto it = g_debugInstallRetry.find(L);
        if (it != g_debugInstallRetry.end()) {
            DebugInstallRetryInfo& entry = it->second;
            entry.dueTick = target;
            entry.generation = generation;
            scheduled = true;
        } else {
            g_debugInstallRetry.emplace(L, DebugInstallRetryInfo{target, generation});
            scheduled = true;
        }
    }

    if (!scheduled)
        return;

    LogLuaBind("hooks-install retry-scheduled Lc=%p delay=%u gen=%llu",
               L,
               delayMs,
               static_cast<unsigned long long>(generation));

    std::thread([state = L, delayMs]() {
        LogLuaBind("hooks-install retry-waker Lc=%p delay=%u start", state, delayMs);
        std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        LogLuaBind("hooks-install retry-waker Lc=%p delay=%u wake", state, delayMs);
        PostToOwnerWithTask(state, "panic&debug-retry", [state]() {
            LuaStateInfo refreshed{};
            if (g_stateRegistry.GetByPointer(state, refreshed)) {
                LogLuaBind("hooks-install retry-run Lc=%p gen=%llu flags=0x%08X",
                           state,
                           static_cast<unsigned long long>(refreshed.gen),
                           refreshed.flags);
                InstallPanicAndDebug(state, refreshed);
            } else {
                LogLuaBind("hooks-install retry-run Lc=%p state-missing", state);
            }
        });
    }).detach();
}

static void ClearDebugInstallRetry(lua_State* L) {
    if (!L)
        return;
    std::lock_guard<std::mutex> lock(g_debugInstallMutex);
    g_debugInstallRetry.erase(L);
}

static void ClearAllDebugInstallRetry() {
    std::lock_guard<std::mutex> lock(g_debugInstallMutex);
    g_debugInstallRetry.clear();
}

static bool IsDebugInstallRetryPending(lua_State* L, uint64_t now, DebugInstallRetryInfo* outInfo) {
    if (!L)
        return false;
    std::lock_guard<std::mutex> lock(g_debugInstallMutex);
    auto it = g_debugInstallRetry.find(L);
    if (it == g_debugInstallRetry.end())
        return false;
    if (outInfo)
        *outInfo = it->second;
    return it->second.dueTick > now;
}

static bool IsStateStableForInstall(const LuaStateInfo& info, lua_State* L, const char** outReason = nullptr) {
    if (!L || !(info.flags & STATE_FLAG_VALID) || !info.L_canonical) {
        if (outReason)
            *outReason = "no-canonical";
        return false;
    }
    lua_State* canonical = g_canonicalState.load(std::memory_order_acquire);
    if (!canonical || canonical != info.L_canonical) {
        if (outReason)
            *outReason = "canonical-mismatch";
        return false;
    }
    uint64_t readyTick = g_lastCanonicalReadyTick.load(std::memory_order_acquire);
    if (!readyTick) {
        if (outReason)
            *outReason = "no-ready-tick";
        return false;
    }
    uint64_t destabilized = g_lastDestabilizedTick.load(std::memory_order_acquire);
    uint64_t now = GetDebugTickNow();
    const uint64_t stableDuration = now > destabilized ? (now - destabilized) : 0;
    if (readyTick < destabilized) {
        if (outReason)
            *outReason = "destabilized";
        return false;
    }
    if (now - destabilized < kDebugInstallStableWindowMs) {
        if (outReason)
            *outReason = "grace";
        return false;
    }
    if (!Engine::MovementReady()) {
        const uint64_t kExtendedGraceMs = static_cast<uint64_t>(kDebugInstallStableWindowMs) * 4u;
        if (stableDuration < kExtendedGraceMs) {
            if (outReason)
                *outReason = "movement-pending";
            return false;
        }
    }
    if (outReason)
        *outReason = nullptr;
    return true;
}

static bool DebugInstrumentationEnabled() {
#if defined(_DEBUG)
    return true;
#else
    static int cached = -1;
    static bool enabled = false;
    if (cached < 0) {
        bool value = false;
        if (TryReadEnvBool("UOW_DEBUG_ENABLE", &value)) {
            enabled = value;
        } else if (TryReadConfigBool("UOW_DEBUG_ENABLE", &value)) {
            enabled = value;
        } else {
            enabled = false;
        }
        cached = 1;
    }
    return enabled;
#endif
}

// Forward declarations
static void ProcessPendingLuaTasks(lua_State* L);
static void PostToLuaThread(lua_State* L, const char* name, std::function<void(lua_State*)> fn);
static void MaybeAdoptOwnerThread(lua_State* L, LuaStateInfo& info);
static void MaybeRunMaintenance();
static void RequestBindForState(const LuaStateInfo& info, const char* reason, bool force);
static void BindHelpersTask(lua_State* L, uint64_t generation, bool force, const char* reason);
static bool BindHelpersOnThread(lua_State* L,
                                const LuaStateInfo& info,
                                uint64_t generation,
                                bool force,
                                HelperInstallMetrics* metrics,
                                const char* installTag,
                                bool sbReadyNow,
                                bool sbPivotNow,
                                bool sbFallbackNow);
static bool BindHelpersWithSeh(lua_State* L,
                               const LuaStateInfo& info,
                               uint64_t generation,
                               bool force,
                               bool& attemptedOut,
                               DWORD& sehCodeOut,
                               HelperInstallMetrics* metrics,
                               const char* installTag,
                               bool sbReadyNow,
                               bool sbPivotNow,
                               bool sbFallbackNow) noexcept;
static void MaybeProcessHelperRetryQueue();
static void InstallPanicAndDebug(lua_State* L, LuaStateInfo& info);
static bool RegisterHelper(lua_State* L, const LuaStateInfo& info, const char* name, lua_CFunction fn, uint64_t generation);
static void DumpWalkEnv(lua_State* L, const char* reason);
static int Lua_UOWalk(lua_State* L);
static int Lua_UOWDump(lua_State* L);
static int Lua_WalkMove(lua_State* L);
static int Lua_GetPacing(lua_State* L);
static int Lua_SetPacing(lua_State* L);
static int Lua_SetInflight(lua_State* L);
static int Lua_GetWalkMetrics(lua_State* L);
static int Lua_UOWStatusFlags(lua_State* L);
static int Lua_UOWTestRet(lua_State* L);
static int Lua_UOWInspect(lua_State* L);
static int Lua_UOWSelfTest(lua_State* L);
static int Lua_UOWRebindAll(lua_State* L);
static int Lua_UOWDebug(lua_State* L);
static int Lua_UOWDebugStatus(lua_State* L);
static int Lua_UOWDebugPing(lua_State* L);
static int __cdecl HookSentinelGC(lua_State* L);
static void ForceRebindAll(const char* reason);
static bool ResolveRegisterFunction();
static int __stdcall RegisterHookImpl(void* ctx, void* func, const char* name);
static int __stdcall RegLua_detour(void* ctx, void* func, const char* name);
static bool ProbeLua(lua_State* L);
static lua_State* NormalizeLuaStatePointer(lua_State* candidate);
static bool IsOwnerThread(const LuaStateInfo& info);
static bool IsOwnerThread(lua_State* L);
static void PostToOwnerWithTask(lua_State* L, const char* taskName, std::function<void()> fn);
static bool PushSentinelTable(lua_State* L, const LuaStateInfo& info, bool create, bool* outCreated, DWORD* outSeh) noexcept;
static bool EnsureHookSentinel(lua_State* L, LuaStateInfo& info, bool* created, DWORD* outSeh, bool* outSoftFail = nullptr) noexcept;
static bool EnsureHookSentinelGuarded(lua_State* L, LuaStateInfo& info, bool* created, DWORD* outSeh, bool* outSoftFail = nullptr) noexcept;
static bool ClearHookSentinel(lua_State* L, DWORD* outSeh) noexcept;

static void AppendPointer(std::string& dest, const void* ptr) {
    char buffer[32];
    sprintf_s(buffer, sizeof(buffer), "%p", ptr);
    dest.append(buffer);
}

static std::string JoinStrings(const std::vector<std::string>& chunks, const char* separator = ",") {
    std::string out;
    if (chunks.empty())
        return out;
    size_t total = 0;
    for (const auto& chunk : chunks)
        total += chunk.size();
    total += (chunks.size() - 1) * std::strlen(separator);
    out.reserve(total);
    for (size_t i = 0; i < chunks.size(); ++i) {
        if (i)
            out.append(separator);
        out.append(chunks[i]);
    }
    return out;
}

static void SanitizeIntoBuffer(const char* data, size_t len, char* dest, size_t destSize, size_t maxLen = 48) {
    if (!dest || destSize == 0)
        return;
    if (!data) {
        strncpy_s(dest, destSize, "<null>", _TRUNCATE);
        return;
    }
    size_t writeLimit = destSize > 0 ? destSize - 1 : 0;
    if (writeLimit == 0)
        return;
    size_t limit = std::min(len, std::min(maxLen, writeLimit));
    size_t i = 0;
    for (; i < limit; ++i) {
        unsigned char ch = static_cast<unsigned char>(data[i]);
        dest[i] = (ch < 0x20 || ch >= 0x7Fu) ? '?' : static_cast<char>(ch);
    }
    if (len > limit && (writeLimit - i) >= 3) {
        dest[i++] = '.';
        dest[i++] = '.';
        dest[i++] = '.';
    }
    dest[i] = '\0';
}

struct PackageLoadedSnapshot {
    bool packageValid = false;
    bool loadedValid = false;
    char packageType[16]{};
    char loadedType[16]{};
    size_t keyCount = 0;
    bool truncated = false;
    char keys[16][49]{};
};

static bool SafeSnapshotPackageLoaded(lua_State* L, const LuaStateInfo& info, PackageLoadedSnapshot& out, DWORD* outSeh) noexcept {
    if (!L)
        return false;
    std::memset(&out, 0, sizeof(out));
    int top = 0;
    DWORD topSeh = 0;
    if (!SafeLuaGetTop(L, info, &top, &topSeh)) {
        if (outSeh)
            *outSeh = topSeh;
        return false;
    }
    __try {
        lua_getglobal(L, "package");
        int packageType = lua_type(L, -1);
        const char* packageTypeName = lua_typename(L, packageType);
        strncpy_s(out.packageType, packageTypeName ? packageTypeName : "<unknown>", _TRUNCATE);
        out.packageValid = (packageType != LUA_TNONE);
        if (packageType == LUA_TTABLE) {
            lua_getfield(L, -1, "loaded");
            int loadedType = lua_type(L, -1);
            const char* loadedTypeName = lua_typename(L, loadedType);
            strncpy_s(out.loadedType, loadedTypeName ? loadedTypeName : "<unknown>", _TRUNCATE);
            out.loadedValid = (loadedType == LUA_TTABLE);
            if (out.loadedValid) {
                const size_t kLimit = 16;
                lua_pushnil(L);
                while (lua_next(L, -2) != 0) {
                    if (out.keyCount < kLimit) {
                        int keyType = lua_type(L, -2);
                        if (keyType == LUA_TSTRING) {
                            size_t textLen = 0;
                            const char* keyStr = lua_tolstring(L, -2, &textLen);
                            SanitizeIntoBuffer(keyStr, textLen, out.keys[out.keyCount], sizeof(out.keys[out.keyCount]));
                        } else {
                            const char* keyTypeName = lua_typename(L, keyType);
                            strncpy_s(out.keys[out.keyCount], keyTypeName ? keyTypeName : "<unknown>", _TRUNCATE);
                        }
                        ++out.keyCount;
                        lua_pop(L, 1);
                    } else {
                        out.truncated = true;
                        lua_pop(L, 1); // pop value
                        lua_pop(L, 1); // pop key
                        break;
                    }
                }
            }
            lua_pop(L, 1); // loaded
        }
        lua_pop(L, 1); // package
        DWORD restoreSeh = 0;
        if (!SafeLuaSetTop(L, info, top, &restoreSeh)) {
            if (outSeh)
                *outSeh = restoreSeh;
            return false;
        }
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeHasDebugTraceback(lua_State* L, const LuaStateInfo& info, bool& outIsTable, bool& outHasTraceback, DWORD* outSeh) noexcept {
    if (!L)
        return false;
    int top = 0;
    DWORD topSeh = 0;
    if (!SafeLuaGetTop(L, info, &top, &topSeh)) {
        if (outSeh)
            *outSeh = topSeh;
        return false;
    }
    __try {
        lua_getglobal(L, "debug");
        int debugType = lua_type(L, -1);
        outIsTable = (debugType == LUA_TTABLE);
        outHasTraceback = false;
        if (outIsTable) {
            lua_getfield(L, -1, "traceback");
            outHasTraceback = (lua_type(L, -1) == LUA_TFUNCTION);
            lua_pop(L, 1);
        }
        DWORD restoreSeh = 0;
        if (!SafeLuaSetTop(L, info, top, &restoreSeh)) {
            if (outSeh)
                *outSeh = restoreSeh;
            return false;
        }
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static void LogLuaFormatted(Log::Level level, Log::Category category, const char* tag, const char* fmt, va_list args) {
    if (!fmt || !Log::IsEnabled(category, level))
        return;

    va_list argsCopy;
    va_copy(argsCopy, args);
    int needed = _vscprintf(fmt, argsCopy);
    va_end(argsCopy);
    if (needed < 0)
        return;

    std::vector<char> buffer(static_cast<size_t>(needed) + 1, '\0');
    va_copy(argsCopy, args);
    vsnprintf_s(buffer.data(), buffer.size(), _TRUNCATE, fmt, argsCopy);
    va_end(argsCopy);

    if (tag && *tag)
        Log::Logf(level, category, "[%s] %s", tag, buffer.data());
    else
        Log::Logf(level, category, "%s", buffer.data());
}

static void LogLuaQ(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    LogLuaFormatted(Log::Level::Debug, Log::Category::LuaGuard, "LuaQ", fmt, args);
    va_end(args);
}

static void LogLuaState(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    LogLuaFormatted(Log::Level::Debug, Log::Category::LuaGuard, "LuaState", fmt, args);
    va_end(args);
}

static void LogLuaBind(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    LogLuaFormatted(Log::Level::Debug, Log::Category::Hooks, "LuaBind", fmt, args);
    va_end(args);
}

static void LogLuaProbe(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    LogLuaFormatted(Log::Level::Debug, Log::Category::LuaGuard, "LuaProbe", fmt, args);
    va_end(args);
}

static void LogLuaPanic(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    LogLuaFormatted(Log::Level::Warn, Log::Category::LuaGuard, "LuaPanic", fmt, args);
    va_end(args);
}

static void LogLuaDbg(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    LogLuaFormatted(Log::Level::Debug, Log::Category::LuaGuard, "LuaDbg", fmt, args);
    va_end(args);
}

enum : uint32_t {
    DEBUG_MODE_OFF = 0,
    DEBUG_MODE_CALLS = 1,
    DEBUG_MODE_TRACE = 2,
    DEBUG_MODE_CUSTOM = 3,
};

struct DebugConfigRequest {
    uint32_t mode = DEBUG_MODE_OFF;
    uint32_t mask = 0;
    uint32_t count = 0;
    bool explicitMask = false;
    bool explicitCount = false;
};

struct DebugConfigResult {
    bool applied = false;
    bool enabled = false;
    uint32_t mode = DEBUG_MODE_OFF;
    uint32_t mask = 0;
    uint32_t count = 0;
    DWORD seh = 0;
    std::string error;
};

struct HookSentinel {
    lua_State* state = nullptr;
};

struct TokenBucket {
    double tokens = 0.0;
    uint64_t lastTickMs = 0;
};

static constexpr double kDebugTokenRatePerSec = 200.0;
static constexpr double kDebugTokenCapacity = 200.0;

static std::mutex g_debugBucketMutex;
static std::unordered_map<DWORD, TokenBucket> g_debugBuckets;

static const char* DebugModeToString(uint32_t mode) {
    switch (mode) {
    case DEBUG_MODE_CALLS:
        return "calls";
    case DEBUG_MODE_TRACE:
        return "trace";
    case DEBUG_MODE_CUSTOM:
        return "on";
    case DEBUG_MODE_OFF:
    default:
        return "off";
    }
}

static uint32_t DebugModeFromString(const char* modeStr) {
    if (!modeStr)
        return DEBUG_MODE_OFF;
    if (_stricmp(modeStr, "off") == 0)
        return DEBUG_MODE_OFF;
    if (_stricmp(modeStr, "calls") == 0)
        return DEBUG_MODE_CALLS;
    if (_stricmp(modeStr, "trace") == 0)
        return DEBUG_MODE_TRACE;
    if (_stricmp(modeStr, "on") == 0)
        return DEBUG_MODE_CUSTOM;
    if (_stricmp(modeStr, "enable") == 0)
        return DEBUG_MODE_CUSTOM;
    return DEBUG_MODE_OFF;
}

static bool ConsumeDebugToken() {
    DWORD tid = GetCurrentThreadId();
    uint64_t now = GetTickCount64();
    std::lock_guard<std::mutex> lock(g_debugBucketMutex);
    TokenBucket& bucket = g_debugBuckets[tid];
    if (bucket.lastTickMs == 0)
        bucket.lastTickMs = now;
    double elapsedSec = static_cast<double>(now - bucket.lastTickMs) / 1000.0;
    if (elapsedSec < 0.0)
        elapsedSec = 0.0;
    bucket.tokens = std::min(kDebugTokenCapacity, bucket.tokens + elapsedSec * kDebugTokenRatePerSec);
    bucket.lastTickMs = now;
    if (bucket.tokens >= 1.0) {
        bucket.tokens -= 1.0;
        return true;
    }
    return false;
}

static const char* FormatCppExceptionDetail(const char* tag, const char* value) {
    if (!value || !*value)
        value = "unknown";
    if (tag && *tag)
        sprintf_s(g_cppExceptionDetail, sizeof(g_cppExceptionDetail), "%s=%s", tag, value);
    else
        sprintf_s(g_cppExceptionDetail, sizeof(g_cppExceptionDetail), "%s", value);
    return g_cppExceptionDetail;
}

static std::string DescribeFlags(uint32_t flags) {
    std::vector<std::string> parts;
    if (flags & STATE_FLAG_PANIC_OK) {
        parts.emplace_back("PANIC_OK");
    } else if (flags & STATE_FLAG_PANIC_MISS) {
        parts.emplace_back("PANIC_MISS");
    } else {
        parts.emplace_back("PANIC_UNKNOWN");
    }

    if (flags & STATE_FLAG_DEBUG_OK) {
        parts.emplace_back("DEBUG_OK");
    } else if (flags & STATE_FLAG_DEBUG_MISS) {
        parts.emplace_back("DEBUG_MISS");
    } else {
        parts.emplace_back("DEBUG_UNKNOWN");
    }

    if (flags & STATE_FLAG_VALID)
        parts.emplace_back("VALID");
    else
        parts.emplace_back("NO_CANON");

    if (flags & STATE_FLAG_QUARANTINED)
        parts.emplace_back("QUAR");

    if (flags & STATE_FLAG_HELPERS)
        parts.emplace_back("HELPERS_SEEN");

    if (flags & STATE_FLAG_HELPERS_BOUND)
        parts.emplace_back("BOUND");
    else
        parts.emplace_back("UNBOUND");

    if (flags & STATE_FLAG_HELPERS_INSTALLED)
        parts.emplace_back("INSTALLED");

    if (flags & STATE_FLAG_SLOT_READY)
        parts.emplace_back("SLOT");
    if (flags & STATE_FLAG_OWNER_READY)
        parts.emplace_back("OWNER");
    if (flags & STATE_FLAG_REG_STABLE)
        parts.emplace_back("REG");
    if (flags & STATE_FLAG_CANON_READY)
        parts.emplace_back("CANON_READY");
    else
        parts.emplace_back("CANON_WAIT");
    if (flags & STATE_FLAG_HELPERS_PENDING)
        parts.emplace_back("HELPERS_PENDING");

    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i)
            out.push_back('|');
        out += parts[i];
    }
    return out;
}

static void RefreshCanonicalReadiness(LuaStateInfo& state, uint64_t now) {
    if (state.slot_ready_tick_ms)
        state.flags |= STATE_FLAG_SLOT_READY;
    if (state.owner_tid != 0) {
        if (!(state.flags & STATE_FLAG_OWNER_READY) || state.owner_ready_tick_ms == 0)
            state.owner_ready_tick_ms = now;
        state.flags |= STATE_FLAG_OWNER_READY;
    }
    if (!(state.flags & STATE_FLAG_REG_STABLE)) {
        if (state.register_last_tick_ms == 0 || now - state.register_last_tick_ms >= kRegisterSettleWindowMs) {
            state.flags |= STATE_FLAG_REG_STABLE;
            if (!state.register_quiet_tick_ms)
                state.register_quiet_tick_ms = now;
        }
    }
}

static bool HasCanonicalGating(const LuaStateInfo& state) {
    constexpr uint32_t kRequired = STATE_FLAG_SLOT_READY | STATE_FLAG_OWNER_READY | STATE_FLAG_REG_STABLE;
    return state.L_canonical != nullptr && (state.flags & kRequired) == kRequired;
}

static bool PromoteCanonicalState(LuaStateInfo& state, uint64_t now, const char* tag) {
    if (!HasCanonicalGating(state))
        return false;

    state.flags |= STATE_FLAG_VALID | STATE_FLAG_CANON_READY;
    state.flags &= ~STATE_FLAG_QUARANTINED;
    state.probe_failures = 0;
    state.next_probe_ms = now;
    if (!state.canonical_ready_tick_ms)
        state.canonical_ready_tick_ms = now;

    uint64_t previousReady = g_lastCanonicalReadyTick.load(std::memory_order_acquire);
    g_lastCanonicalReadyTick.store(now, std::memory_order_release);
    uint64_t destabilized = g_lastDestabilizedTick.load(std::memory_order_acquire);

    const int slotReady = (state.flags & STATE_FLAG_SLOT_READY) ? 1 : 0;
    const int ownerReady = (state.flags & STATE_FLAG_OWNER_READY) ? 1 : 0;
    const int regReady = (state.flags & STATE_FLAG_REG_STABLE) ? 1 : 0;

    if (!previousReady || previousReady <= destabilized) {
        LogLuaState("canonical-ready Lc=%p source=%s tick=%llu dest=%llu prev=%llu gates={slot:%d owner:%d reg:%d}",
                    state.L_canonical,
                    tag ? tag : "unknown",
                    static_cast<unsigned long long>(now),
                    static_cast<unsigned long long>(destabilized),
                    static_cast<unsigned long long>(previousReady),
                    slotReady,
                    ownerReady,
                    regReady);
    } else {
        uint64_t delta = previousReady > destabilized ? previousReady - destabilized : 0;
        LogLuaState("canonical-hold Lc=%p source=%s tick=%llu dest=%llu ready=%llu delta=%llu gates={slot:%d owner:%d reg:%d}",
                    state.L_canonical,
                    tag ? tag : "unknown",
                    static_cast<unsigned long long>(now),
                    static_cast<unsigned long long>(destabilized),
                    static_cast<unsigned long long>(previousReady),
                    static_cast<unsigned long long>(delta),
                    slotReady,
                    ownerReady,
                    regReady);
    }

    state.last_bind_log_tick_ms = now;
    return true;
}

static bool EnsureCanonicalLocked(LuaStateInfo& state, uint64_t now, const char* sourceTag) {
    const char* tag = (sourceTag && *sourceTag) ? sourceTag : "unknown";

    RefreshCanonicalReadiness(state, now);
    if (PromoteCanonicalState(state, now, tag))
        return true;

    state.flags &= ~(STATE_FLAG_VALID | STATE_FLAG_CANON_READY);
    if (state.L_canonical && !HasCanonicalGating(state)) {
        if (now - state.last_bind_log_tick_ms >= kBindLogCooldownMs) {
            state.last_bind_log_tick_ms = now;
            LogLuaState("canonical-gate-wait Lc=%p source=%s slot=%d owner=%d reg=%d",
                        state.L_canonical,
                        tag,
                        (state.flags & STATE_FLAG_SLOT_READY) ? 1 : 0,
                        (state.flags & STATE_FLAG_OWNER_READY) ? 1 : 0,
                        (state.flags & STATE_FLAG_REG_STABLE) ? 1 : 0);
        }
    }

    if (state.next_probe_ms && now < state.next_probe_ms) {
        uint64_t remaining = state.next_probe_ms - now;
        uint64_t readyTick = g_lastCanonicalReadyTick.load(std::memory_order_acquire);
        uint64_t destabilized = g_lastDestabilizedTick.load(std::memory_order_acquire);
        LogLuaState("probe-wait L=%p ctx=%p wait=%llu next=%llu ready=%llu dest=%llu now=%llu source=%s",
                    state.L_reported,
                    state.ctx_reported,
                    static_cast<unsigned long long>(remaining),
                    static_cast<unsigned long long>(state.next_probe_ms),
                    static_cast<unsigned long long>(readyTick),
                    static_cast<unsigned long long>(destabilized),
                    static_cast<unsigned long long>(now),
                    tag);
        NoteDestabilization(now, "probe-wait", tag);
        return false;
    }

    auto markSuccess = [&](lua_State* canonical, const char* mode) {
        state.L_canonical = canonical;
        state.flags &= ~STATE_FLAG_QUARANTINED;
        state.probe_failures = 0;
        state.next_probe_ms = now;
        LogLuaState("probe-ok %s Lc=%p ctx=%p tid=%lu source=%s gen=%llu",
                    mode ? mode : "direct",
                    canonical,
                    state.ctx_reported,
                    state.owner_tid,
                    tag,
                    static_cast<unsigned long long>(state.gen));
        if (mode)
            LogLuaState("probe-ok %s Lc=%p source=%s", mode, canonical, tag);
        else
            LogLuaState("probe-ok Lc=%p source=%s", canonical, tag);
        RefreshCanonicalReadiness(state, now);
        bool ready = PromoteCanonicalState(state, now, tag);
        if (!ready && now - state.last_bind_log_tick_ms >= kBindLogCooldownMs) {
            state.last_bind_log_tick_ms = now;
            LogLuaState("probe-ok gate-wait Lc=%p source=%s mode=%s slot=%d owner=%d reg=%d",
                        canonical,
                        tag,
                        mode ? mode : "direct",
                        (state.flags & STATE_FLAG_SLOT_READY) ? 1 : 0,
                        (state.flags & STATE_FLAG_OWNER_READY) ? 1 : 0,
                        (state.flags & STATE_FLAG_REG_STABLE) ? 1 : 0);
        }
        return ready;
    };

    if (state.L_reported) {
        if (ProbeLua(state.L_reported))
            return markSuccess(state.L_reported, "reported");

        if (state.ctx_reported) {
            LogLuaState("probe-failed L=%p source=%s -> trying ctx=%p", state.L_reported, tag, state.ctx_reported);
        } else {
            LogLuaState("probe-failed L=%p source=%s", state.L_reported, tag);
        }
    }

    if (state.ctx_reported) {
        lua_State* ctxCandidate = reinterpret_cast<lua_State*>(state.ctx_reported);
        if (ProbeLua(ctxCandidate))
            return markSuccess(ctxCandidate, "ctx-as-canonical");
        LogLuaState("probe-failed ctx=%p source=%s", state.ctx_reported, tag);
    }

    state.flags &= ~STATE_FLAG_VALID;
    state.flags |= STATE_FLAG_QUARANTINED;
    state.probe_failures = std::min<uint32_t>(state.probe_failures + 1, 4u);
    const uint32_t exponent = state.probe_failures ? state.probe_failures - 1 : 0;
    uint32_t backoff = kProbeInitialBackoffMs << exponent;
    if (backoff > kProbeMaxBackoffMs)
        backoff = kProbeMaxBackoffMs;
    state.next_probe_ms = now + backoff;
    uint64_t readyTick = g_lastCanonicalReadyTick.load(std::memory_order_acquire);
    uint64_t destabilized = g_lastDestabilizedTick.load(std::memory_order_acquire);
    LogLuaState("probe-backoff L=%p ctx=%p retries=%u next=%llu ready=%llu dest=%llu now=%llu source=%s",
                state.L_reported,
                state.ctx_reported,
                state.probe_failures,
                static_cast<unsigned long long>(state.next_probe_ms),
                static_cast<unsigned long long>(readyTick),
                static_cast<unsigned long long>(destabilized),
                static_cast<unsigned long long>(now),
                tag);
    NoteDestabilization(now, "probe-backoff", tag);
    return false;
}

static LuaStateInfo RefreshCanonical(lua_State* lookupPtr, const char* sourceTag, bool fromHelper, bool* outReady, bool* outCoalesced) {
    LuaStateInfo snapshot{};
    bool ready = false;
    const uint64_t now = GetTickCount64();

    bool updated = g_stateRegistry.UpdateByPointer(lookupPtr, [&](LuaStateInfo& state) {
        if (fromHelper)
            state.flags |= STATE_FLAG_HELPERS;
        ready = EnsureCanonicalLocked(state, now, sourceTag);
        snapshot = state;
    }, &snapshot);

    bool coalesced = false;
    if (updated && snapshot.L_canonical) {
        auto merge = g_stateRegistry.MergeByCanonical(snapshot.L_reported, snapshot.ctx_reported, snapshot.L_canonical);
        coalesced = merge.merged;
        snapshot = merge.info;
    }

    if (outReady)
        *outReady = updated && snapshot.L_canonical != nullptr && ready;
    if (outCoalesced)
        *outCoalesced = coalesced;
    if (snapshot.L_canonical)
        g_canonicalState.store(snapshot.L_canonical, std::memory_order_release);
    return snapshot;
}

static LuaStateInfo ObserveReportedState(lua_State* reported, void* ctx, DWORD tid, uint64_t gen, const char* sourceTag, bool* outIsNew, bool* outReady, bool* outCoalesced) {
    if (!reported)
        return {};

    if (ctx)
        SetCanonicalHelperCtx(ctx, tid);

    auto result = g_stateRegistry.AddOrUpdate(reported, ctx, tid, gen);
    if (outIsNew)
        *outIsNew = result.second;
    return RefreshCanonical(reported, sourceTag, false, outReady, outCoalesced);
}

static lua_State* LookupPointerFor(const LuaStateInfo& info) {
    if (info.L_canonical)
        return info.L_canonical;
    if (info.L_reported)
        return info.L_reported;
    if (info.ctx_reported)
        return reinterpret_cast<lua_State*>(info.ctx_reported);
    return nullptr;
}

static LuaStateInfo EnsureHelperState(lua_State* L, const char* helperName, bool* outReady, bool* outCoalesced, bool* outIsNew) {
    if (outReady)
        *outReady = false;
    if (outCoalesced)
        *outCoalesced = false;
    if (outIsNew)
        *outIsNew = false;
    if (!L)
        return {};

    if (lua_State* normalized = NormalizeLuaStatePointer(L)) {
        L = normalized;
    }

    DWORD tid = GetCurrentThreadId();
    uint64_t gen = g_generation.load(std::memory_order_acquire);
    bool isNew = false;
    LuaStateInfo info = g_stateRegistry.EnsureForPointer(L, nullptr, tid, gen, isNew);
    const uint64_t now = GetTickCount64();
    g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
        state.flags |= STATE_FLAG_HELPERS;
        state.last_tid = tid;
        state.last_seen_ms = now;
        state.gen = std::max(state.gen, gen);
        if (state.owner_tid == 0)
            state.owner_tid = tid;
        if (!(state.flags & STATE_FLAG_OWNER_READY) || state.owner_ready_tick_ms == 0)
            state.owner_ready_tick_ms = now;
        state.flags |= STATE_FLAG_OWNER_READY;
    }, &info);

    if (isNew) {
        LogLuaState("observed L=%p ctx=<unknown> tid=%lu gen=%llu source=helper helper=%s",
                    L,
                    tid,
                    static_cast<unsigned long long>(gen),
                    helperName ? helperName : "<unknown>");
    }

    bool ready = false;
    bool coalesced = false;
    info = RefreshCanonical(L, helperName, true, &ready, &coalesced);

    if (coalesced && info.L_canonical) {
        LogLuaState("coalesced under canonical Lc=%p source=helper helper=%s",
                    info.L_canonical,
                    helperName ? helperName : "<unknown>");
    }

    if (outReady)
        *outReady = ready;
    if (outCoalesced)
        *outCoalesced = coalesced;
    if (outIsNew)
        *outIsNew = isNew;
    return info;
}

static bool TryBuildInspectSummary(lua_State* target, const LuaStateInfo& info, std::string& outSummary, DWORD* outSeh) {
    if (!target)
        return false;

    outSummary.clear();

    int originalTop = 0;
    DWORD probeSeh = 0;
    if (!SafeLuaProbeStack(target, info, &originalTop, &probeSeh)) {
        if (outSeh)
            *outSeh = probeSeh;
        return false;
    }

    DWORD firstSeh = 0;
    bool ok = true;
    std::vector<std::string> helperEntries;
    helperEntries.reserve(5);

    const char* helpers[] = {
        kHelperWalkName,
        kHelperWalkMoveName,
        kHelperGetPacingName,
        kHelperSetPacingName,
        kHelperSetInflightName,
        kHelperGetWalkMetricsName,
        kHelperDumpName,
        kHelperInspectName,
        kHelperRebindName,
        kHelperSelfTestName
    };
    constexpr size_t helperCount = sizeof(helpers) / sizeof(helpers[0]);
    for (size_t i = 0; i < helperCount; ++i) {
        int type = LUA_TNONE;
        const char* typeName = nullptr;
        DWORD helperSeh = 0;
        if (SafeLuaGetGlobalType(target, helpers[i], &type, &typeName, &helperSeh)) {
            std::string entry(helpers[i]);
            entry.push_back(':');
            entry.append(typeName ? typeName : "<unknown>");
            helperEntries.emplace_back(std::move(entry));
        } else {
            if (firstSeh == 0)
                firstSeh = helperSeh;
            ok = false;
            break;
        }
    }

    int debugType = LUA_TNONE;
    const char* debugTypeName = nullptr;
    bool debugHasTraceback = false;
    if (ok) {
        DWORD debugSeh = 0;
        if (SafeLuaGetGlobalType(target, "debug", &debugType, &debugTypeName, &debugSeh)) {
            if (debugType == LUA_TTABLE) {
                bool isTable = false;
                DWORD tracebackSeh = 0;
                if (!SafeHasDebugTraceback(target, info, isTable, debugHasTraceback, &tracebackSeh)) {
                    if (firstSeh == 0)
                        firstSeh = tracebackSeh;
                    ok = false;
                }
            }
        } else {
            if (firstSeh == 0)
                firstSeh = debugSeh;
            ok = false;
        }
    }

    PackageLoadedSnapshot pkg{};
    if (ok) {
        DWORD pkgSeh = 0;
        if (!SafeSnapshotPackageLoaded(target, info, pkg, &pkgSeh)) {
            if (firstSeh == 0)
                firstSeh = pkgSeh;
            ok = false;
        }
    }

    if (!ok) {
        if (outSeh)
            *outSeh = firstSeh ? firstSeh : probeSeh;
        return false;
    }

    std::string debugInfo = "debug=";
    debugInfo.append(debugTypeName ? debugTypeName : "<unknown>");
    if (debugType == LUA_TTABLE)
        debugInfo.append(debugHasTraceback ? "(traceback)" : "(no-traceback)");

    std::string packageInfo = "package=";
    packageInfo.append(pkg.packageType[0] ? pkg.packageType : "<unknown>");
    packageInfo.append(" loaded=");
    packageInfo.append(pkg.loadedType[0] ? pkg.loadedType : "<unknown>");
    if (pkg.loadedValid) {
        std::vector<std::string> keys;
        keys.reserve(pkg.keyCount);
        for (size_t i = 0; i < pkg.keyCount; ++i) {
            keys.emplace_back(pkg.keys[i][0] ? pkg.keys[i] : "<unknown>");
        }
        packageInfo.append(" keys=[");
        if (!keys.empty())
            packageInfo.append(JoinStrings(keys, ", "));
        if (pkg.truncated) {
            if (!keys.empty())
                packageInfo.append(", ");
            packageInfo.append("...");
        }
        packageInfo.push_back(']');
    }

    std::string summary;
    summary.reserve(256);
    lua_State* canonical = info.L_canonical ? info.L_canonical : target;
    summary.append("Lc=");
    AppendPointer(summary, canonical);
    summary.append(" (Lr=");
    AppendPointer(summary, info.L_reported);
    summary.append(" ctx=");
    AppendPointer(summary, info.ctx_reported);
    summary.push_back(')');
    summary.append(" owner=");
    summary.append(std::to_string(info.owner_tid));
    summary.append(" last=");
    summary.append(std::to_string(info.last_tid));
    summary.append(" gen=");
    summary.append(std::to_string(info.gen));
    summary.append(" flags=");
    summary.append(DescribeFlags(info.flags));
    summary.append(" counters=");
    summary.append(std::to_string(info.hook_call_count));
    summary.push_back('/');
    summary.append(std::to_string(info.hook_ret_count));
    summary.push_back('/');
    summary.append(std::to_string(info.hook_line_count));
    if (info.flags & STATE_FLAG_QUARANTINED) {
        uint64_t now = GetTickCount64();
        uint64_t wait = (info.next_probe_ms > now) ? (info.next_probe_ms - now) : 0;
        summary.append(" backoff=");
        summary.append(std::to_string(wait));
        summary.append("ms");
    }
    summary.append(" top=");
    summary.append(std::to_string(originalTop));

    summary.append(" helpers=");
    if (!helperEntries.empty())
        summary.append(JoinStrings(helperEntries, ", "));
    else
        summary.append("<none>");

    summary.push_back(' ');
    summary.append(debugInfo);
    summary.push_back(' ');
    summary.append(packageInfo);

    outSummary = std::move(summary);
    if (outSeh)
        *outSeh = 0;
    return true;
}

extern "C" int __cdecl UOW_PanicThunk(lua_State* L) {
    DWORD tid = GetCurrentThreadId();
    LuaStateInfo info{};
    g_stateRegistry.GetByPointer(L, info);
    DWORD owner = info.owner_tid ? info.owner_tid : g_scriptThreadId.load(std::memory_order_acquire);
    uint32_t gen = static_cast<uint32_t>(info.gen & 0xFFFFFFFFu);

    int top = 0;
    char errBuf[128]{};
    __try {
        top = lua_gettop(L);
        if (top > 0) {
            size_t errLen = 0;
            const char* err = lua_tolstring(L, -1, &errLen);
            SanitizeIntoBuffer(err, errLen, errBuf, sizeof(errBuf));
        } else {
            strncpy_s(errBuf, "<empty>", _TRUNCATE);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        strncpy_s(errBuf, "<seh>", _TRUNCATE);
    }

    char frameSummary[512]{};
    for (int level = 0; level < 8; ++level) {
        lua_Debug ar{};
        if (!SafeLuaGetStack(L, level, &ar, nullptr))
            break;
        if (!SafeLuaGetInfo(L, "Sln", &ar, nullptr))
            break;
        const char* funcName = ar.name ? ar.name : (ar.what ? ar.what : "?");
        char srcBuf[96]{};
        size_t srcLen = ar.short_src ? strnlen_s(ar.short_src, sizeof(ar.short_src)) : 0;
        SanitizeIntoBuffer(ar.short_src, srcLen, srcBuf, sizeof(srcBuf));
        char funcBuf[96]{};
        size_t funcLen = funcName ? strnlen_s(funcName, 256) : 0;
        SanitizeIntoBuffer(funcName, funcLen, funcBuf, sizeof(funcBuf));
        char frameBuf[192];
        sprintf_s(frameBuf, sizeof(frameBuf), "%s:%d %s",
                  srcBuf,
                  ar.currentline,
                  funcBuf);
        if (frameSummary[0] != '\0') {
            strncat_s(frameSummary, sizeof(frameSummary), "; ", _TRUNCATE);
        }
        strncat_s(frameSummary, sizeof(frameSummary), frameBuf, _TRUNCATE);
    }

    if (frameSummary[0] == '\0') {
        strncpy_s(frameSummary, "<no-stack>", _TRUNCATE);
    }
    LogLuaPanic("Lc=%p err=%s top=%d tid=%lu owner=%lu gen=%u frames=%s",
                L,
                errBuf,
                top,
                tid,
                owner,
                gen,
                frameSummary);

    lua_CFunction prev = info.panic_prev;
    if (prev && prev != UOW_PanicThunk) {
        int result = 0;
        bool prevOk = false;
        __try {
            result = prev(L);
            prevOk = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            LogLuaPanic("prev-handler-seh Lc=%p seh=0x%08lX", L, GetExceptionCode());
        }
        if (prevOk)
            return result;
    }
    return 0;
}

extern "C" void __cdecl UOW_DebugHook(lua_State* L, lua_Debug* ar) {
    if (!L || !ar)
        return;

    const char* eventName = "UNKNOWN";
    switch (ar->event) {
    case LUA_HOOKCALL:
        eventName = "CALL";
        g_stateRegistry.IncrementHookCounters(L, 1u, 0u, 0u);
        break;
    case LUA_HOOKRET:
        eventName = "RET";
        g_stateRegistry.IncrementHookCounters(L, 0u, 1u, 0u);
        break;
    case LUA_HOOKTAILRET:
        eventName = "TAILRET";
        g_stateRegistry.IncrementHookCounters(L, 0u, 1u, 0u);
        break;
    case LUA_HOOKLINE:
        eventName = "LINE";
        g_stateRegistry.IncrementHookCounters(L, 0u, 0u, 1u);
        break;
    default:
        break;
    }

    if (!ConsumeDebugToken())
        return;

    lua_Debug detail = *ar;
    SafeLuaGetInfo(L, "Sln", &detail, nullptr);
    const char* funcName = detail.name ? detail.name : (detail.what ? detail.what : "[anon]");
    char srcBuf[96]{};
    SanitizeIntoBuffer(detail.short_src, std::strlen(detail.short_src), srcBuf, sizeof(srcBuf));
    char funcBuf[96]{};
    SanitizeIntoBuffer(funcName, std::strlen(funcName), funcBuf, sizeof(funcBuf));

    LogLuaDbg("ev=%s src=%s:%d func=%s",
              eventName,
              srcBuf,
              detail.currentline,
              funcBuf);
}

static bool SafeLuaProbeStack(lua_State* L, const LuaStateInfo& info, int* outTop, DWORD* outSeh) noexcept {
    if (!L)
        return false;
    auto topRes = Engine::Lua::safe_lua_gettop(L, info);
    if (!topRes.ok) {
        if (outTop)
            *outTop = topRes.top;
        Engine::Lua::LuaGuardFailure fail = Engine::Lua::GetLastLuaGuardFailure();
        NoteGuardFailure(fail);
        if (outSeh)
            *outSeh = MapGuardFailureToStatus(fail);
        return false;
    }
    if (outTop)
        *outTop = topRes.top;
    if (!Engine::Lua::safe_lua_settop(L, info, topRes.top)) {
        Engine::Lua::LuaGuardFailure fail = Engine::Lua::GetLastLuaGuardFailure();
        NoteGuardFailure(fail);
        if (outSeh)
            *outSeh = MapGuardFailureToStatus(fail);
        return false;
    }
    if (outSeh)
        *outSeh = 0;
    return true;
}

static bool SafeLuaProbeStack(lua_State* L, int* outTop, DWORD* outSeh) noexcept {
    if (!L)
        return false;
    LuaStateInfo info{};
    if (g_stateRegistry.GetByPointer(L, info) && (info.flags & STATE_FLAG_VALID) && info.L_canonical) {
        return SafeLuaProbeStack(L, info, outTop, outSeh);
    }
    DWORD localSeh = 0;
    int top = 0;
    if (!SafeLuaGetTop(L, &top, &localSeh)) {
        if (outTop)
            *outTop = top;
        if (outSeh)
            *outSeh = localSeh ? localSeh : kLuaStatusImplausibleTop;
        return false;
    }
    if (outTop)
        *outTop = top;
    if (!SafeLuaSetTop(L, top, &localSeh)) {
        if (outSeh)
            *outSeh = localSeh ? localSeh : kLuaStatusImplausibleTop;
        return false;
    }
    if (outSeh)
        *outSeh = 0;
    return true;
}

static bool SafeLuaSetTop(lua_State* L, const LuaStateInfo& info, int idx, DWORD* outSeh) noexcept {
    if (!L)
        return false;
    if (idx >= 0 && !IsLuaStackTopPlausible(idx)) {
        NoteGuardFailure(Engine::Lua::LuaGuardFailure::ImplausibleTop);
        if (outSeh)
            *outSeh = kLuaStatusImplausibleTop;
        return false;
    }
    if (!Engine::Lua::safe_lua_settop(L, info, idx)) {
        Engine::Lua::LuaGuardFailure fail = Engine::Lua::GetLastLuaGuardFailure();
        NoteGuardFailure(fail);
        if (outSeh)
            *outSeh = MapGuardFailureToStatus(fail);
        return false;
    }
    if (outSeh)
        *outSeh = 0;
    return true;
}

static bool SafeLuaSetTop(lua_State* L, int idx, DWORD* outSeh) noexcept {
    if (!L)
        return false;
    LuaStateInfo info{};
    if (g_stateRegistry.GetByPointer(L, info) && (info.flags & STATE_FLAG_VALID) && info.L_canonical) {
        return SafeLuaSetTop(L, info, idx, outSeh);
    }
    if (idx >= 0 && !IsLuaStackTopPlausible(idx)) {
        NoteGuardFailure(Engine::Lua::LuaGuardFailure::ImplausibleTop);
        if (outSeh)
            *outSeh = kLuaStatusImplausibleTop;
        return false;
    }
    __try {
        lua_settop(L, idx);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        NoteGuardFailure(Engine::Lua::LuaGuardFailure::Seh);
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaPushString(lua_State* L, const char* str, DWORD* outSeh = nullptr) noexcept {
    if (!L || !str)
        return false;
    __try {
        lua_pushstring(L, str);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaPushNil(lua_State* L, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_pushnil(L);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaPushCClosure(lua_State* L, lua_CFunction fn, int n, DWORD* outSeh = nullptr) noexcept {
    if (!L || !fn)
        return false;
    __try {
        lua_pushcclosure(L, fn, n);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaPushLightUserdata(lua_State* L, const void* ptr, DWORD* outSeh = nullptr) noexcept {
    if (!L || !ptr)
        return false;
    __try {
        lua_pushlightuserdata(L, const_cast<void*>(ptr));
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaPushInteger(lua_State* L, lua_Integer value, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_pushinteger(L, value);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaPushBoolean(lua_State* L, int value, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_pushboolean(L, value ? 1 : 0);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaCreateTable(lua_State* L, int narr, int nrec, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_createtable(L, narr, nrec);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaSetTable(lua_State* L, int idx, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_settable(L, idx);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaPushValue(lua_State* L, int idx, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_pushvalue(L, idx);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaInsert(lua_State* L, int idx, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_insert(L, idx);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaRawGet(lua_State* L, int idx, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_rawget(L, idx);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaRawSet(lua_State* L, int idx, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_rawset(L, idx);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaRawGetP(lua_State* L, int idx, const void* key, DWORD* outSeh = nullptr) noexcept {
    if (!L || !key)
        return false;
    if (!SafeLuaPushLightUserdata(L, key, outSeh))
        return false;
    if (!SafeLuaRawGet(L, idx, outSeh))
        return false;
    if (outSeh)
        *outSeh = 0;
    return true;
}

static bool SafeLuaRawSetP(lua_State* L, int idx, const void* key, DWORD* outSeh = nullptr) noexcept {
    if (!L || !key)
        return false;
    if (!SafeLuaPushLightUserdata(L, key, outSeh))
        return false;
    if (!SafeLuaInsert(L, -2, outSeh))
        return false;
    if (!SafeLuaRawSet(L, idx, outSeh))
        return false;
    if (outSeh)
        *outSeh = 0;
    return true;
}

static bool SafeLuaNewUserdata(lua_State* L, size_t size, void** outPtr, DWORD* outSeh = nullptr) noexcept {
    if (!L || size == 0)
        return false;
    __try {
        void* ptr = lua_newuserdata(L, size);
        if (outPtr)
            *outPtr = ptr;
        if (outSeh)
            *outSeh = 0;
        return ptr != nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outPtr)
            *outPtr = nullptr;
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaSetMetatable(lua_State* L, int idx, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_setmetatable(L, idx);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaType(lua_State* L, int idx, int* outType, DWORD* outSeh = nullptr) noexcept {
    if (!L || !outType)
        return false;
    __try {
        *outType = lua_type(L, idx);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *outType = LUA_TNONE;
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaToUserdata(lua_State* L, int idx, void** outPtr, DWORD* outSeh = nullptr) noexcept {
    if (!L || !outPtr)
        return false;
    __try {
        *outPtr = lua_touserdata(L, idx);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *outPtr = nullptr;
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaToInteger(lua_State* L, int idx, lua_Integer* outValue, DWORD* outSeh = nullptr) noexcept {
    if (!L || !outValue)
        return false;
    __try {
        *outValue = lua_tointeger(L, idx);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *outValue = 0;
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaCheckStack(lua_State* L, int extra, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        int ok = lua_checkstack(L, extra);
        if (!ok)
            return false;
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaGetTop(lua_State* L, const LuaStateInfo& info, int* outTop, DWORD* outSeh) noexcept {
    if (!L || !outTop)
        return false;
    auto res = Engine::Lua::safe_lua_gettop(L, info);
    if (!res.ok) {
        Engine::Lua::LuaGuardFailure fail = Engine::Lua::GetLastLuaGuardFailure();
        NoteGuardFailure(fail);
        *outTop = res.top;
        if (outSeh)
            *outSeh = MapGuardFailureToStatus(fail);
        return false;
    }
    *outTop = res.top;
    if (outSeh)
        *outSeh = 0;
    return true;
}

static bool SafeLuaGetTop(lua_State* L, int* outTop, DWORD* outSeh) noexcept {
    if (!L || !outTop)
        return false;
    LuaStateInfo info{};
    if (g_stateRegistry.GetByPointer(L, info) && (info.flags & STATE_FLAG_VALID) && info.L_canonical) {
        return SafeLuaGetTop(L, info, outTop, outSeh);
    }
    int top = 0;
    __try {
        top = lua_gettop(L);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *outTop = 0;
        NoteGuardFailure(Engine::Lua::LuaGuardFailure::Seh);
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
    *outTop = top;
    if (!IsLuaStackTopPlausible(top)) {
        NoteGuardFailure(Engine::Lua::LuaGuardFailure::ImplausibleTop);
        if (outSeh)
            *outSeh = kLuaStatusImplausibleTop;
        return false;
    }
    if (outSeh)
        *outSeh = 0;
    return true;
}

static bool SafeLuaLNewMetatable(lua_State* L, const char* tname, int* outCreated, DWORD* outSeh = nullptr) noexcept {
    if (!L || !tname)
        return false;
    __try {
        int created = luaL_newmetatable(L, tname);
        if (outCreated)
            *outCreated = created;
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outCreated)
            *outCreated = 0;
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaAtPanic(lua_State* L, lua_CFunction fn, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_atpanic(L, fn);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaQueryPanic(lua_State* L, lua_CFunction* outPrev, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_CFunction prev = lua_atpanic(L, nullptr);
        if (outPrev)
            *outPrev = prev;
        lua_atpanic(L, prev);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outPrev)
            *outPrev = nullptr;
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaSetHook(lua_State* L, lua_Hook hook, int mask, int count, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_sethook(L, hook, mask, count);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool TryInstallPanicHook(lua_State* L, lua_CFunction* outPrev, DWORD* outSeh) noexcept {
    if (!L)
        return false;
    __try {
        lua_CFunction previous = lua_atpanic(L, UOW_PanicThunk);
        if (outPrev)
            *outPrev = previous;
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outPrev)
            *outPrev = nullptr;
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaGetStack(lua_State* L, int level, lua_Debug* ar, DWORD* outSeh) noexcept {
    if (!L || !ar)
        return false;
    __try {
        int rc = lua_getstack(L, level, ar);
        if (outSeh)
            *outSeh = 0;
        return rc != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaGetInfo(lua_State* L, const char* what, lua_Debug* ar, DWORD* outSeh) noexcept {
    if (!L || !ar || !what)
        return false;
    __try {
        int rc = lua_getinfo(L, what, ar);
        if (outSeh)
            *outSeh = 0;
        return rc != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaGetGlobalType(lua_State* L, const char* name, int* outType, const char** outTypeName, DWORD* outSeh) noexcept {
    if (!L || !name)
        return false;
    __try {
        lua_getglobal(L, name);
        int type = lua_type(L, -1);
        if (outType)
            *outType = type;
        if (outTypeName)
            *outTypeName = lua_typename(L, type);
        lua_pop(L, 1);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaGetHook(lua_State* L, lua_Hook* outHook, int* outMask, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        if (outHook)
            *outHook = lua_gethook(L);
        if (outMask)
            *outMask = lua_gethookmask(L);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outHook)
            *outHook = nullptr;
        if (outMask)
            *outMask = 0;
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaDoString(lua_State* L, const char* chunk, DWORD* outSeh = nullptr) noexcept {
    if (!L || !chunk)
        return false;
    __try {
        int rc = luaL_loadstring(L, chunk);
        if (rc == 0)
            rc = lua_pcall(L, 0, LUA_MULTRET, 0);
        if (outSeh)
            *outSeh = 0;
        return rc == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool PushSentinelTable(lua_State* L, const LuaStateInfo& info, bool create, bool* outCreated, DWORD* outSeh) noexcept {
    DWORD seh = 0;
    if (!SafeLuaRawGetP(L, LUA_REGISTRYINDEX, &g_hookSentinelKey, &seh)) {
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    int type = LUA_TNONE;
    if (!SafeLuaType(L, -1, &type, &seh)) {
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    if (type == LUA_TTABLE) {
        if (outCreated)
            *outCreated = false;
        if (outSeh)
            *outSeh = 0;
        return true;
    }

    if (!SafeLuaSetTop(L, info, -2, &seh)) {
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    if (!create) {
        if (outCreated)
            *outCreated = false;
        if (outSeh)
            *outSeh = 0;
        return false;
    }

    if (!SafeLuaCreateTable(L, 0, 4, &seh)) {
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    if (!SafeLuaRawSetP(L, LUA_REGISTRYINDEX, &g_hookSentinelKey, &seh)) {
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    if (!SafeLuaRawGetP(L, LUA_REGISTRYINDEX, &g_hookSentinelKey, &seh)) {
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    if (outCreated)
        *outCreated = true;
    if (outSeh)
        *outSeh = 0;
    return true;
}

static bool ProbeLua(lua_State* L) {
    if (!L)
        return false;

    DWORD probeSeh = 0;
    return SafeLuaProbeStack(L, nullptr, &probeSeh);
}

static void LogSentinelStackFailure(lua_State* L, const LuaStateInfo& info, int initialTop, DWORD stackSeh) {
    if (!L)
        return;

    uint64_t now = GetDebugTickNow();
    uint64_t last = g_lastSentinelStackLogTick.load(std::memory_order_acquire);
    if (now - last < 250)
        return;
    g_lastSentinelStackLogTick.store(now, std::memory_order_release);

    LuaStateInfo detail = info;
    g_stateRegistry.GetByPointer(L, detail);

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&ctx);

    LogLuaBind("sentinel stack-fail detail L=%p ctx=%p canonical=%p owner=%lu flags=0x%08X gen=%llu top=%d (0x%08X) seh=0x%08lX sentinelRef=%d sentinelGen=%llu "
               "eip=0x%08lX esp=0x%08lX ebp=0x%08lX eax=0x%08lX ebx=0x%08lX ecx=0x%08lX edx=0x%08lX esi=0x%08lX edi=0x%08lX",
               L,
               detail.ctx_reported,
               detail.L_canonical,
               static_cast<unsigned long>(detail.owner_tid),
               detail.flags,
               static_cast<unsigned long long>(detail.gen),
               initialTop,
               static_cast<unsigned int>(initialTop),
               stackSeh,
               detail.gc_sentinel_ref,
               static_cast<unsigned long long>(detail.gc_sentinel_gen),
               ctx.Eip,
               ctx.Esp,
               ctx.Ebp,
               ctx.Eax,
               ctx.Ebx,
               ctx.Ecx,
               ctx.Edx,
               ctx.Esi,
               ctx.Edi);

    for (int level = 0; level < 3; ++level) {
        lua_Debug ar{};
        DWORD debugSeh = 0;
        if (!SafeLuaGetStack(L, level, &ar, &debugSeh)) {
            if (debugSeh) {
                LogLuaBind("sentinel stack-fail lua_getstack level=%d seh=0x%08lX", level, debugSeh);
            }
            break;
        }

        if (SafeLuaGetInfo(L, "Sln", &ar, &debugSeh)) {
            const char* functionName = (ar.name && *ar.name) ? ar.name : "unknown";
            const char* source = ar.short_src[0] ? ar.short_src : (ar.source ? ar.source : "unknown");
            LogLuaBind("sentinel stack-fail frame level=%d name=%s line=%d source=%s",
                       level,
                       functionName,
                       ar.currentline,
                       source);
        } else if (debugSeh) {
            LogLuaBind("sentinel stack-fail lua_getinfo level=%d seh=0x%08lX", level, debugSeh);
        }
    }
}

static bool EnsureHookSentinel(lua_State* L, LuaStateInfo& info, bool* created, DWORD* outSeh, bool* outSoftFail) noexcept {
    if (created)
        *created = false;
    if (outSoftFail)
        *outSoftFail = false;
    if (!L)
        return false;

    int initialTop = 0;
    DWORD topSeh = 0;
    if (!SafeLuaGetTop(L, info, &initialTop, &topSeh)) {
        LogSentinelStackFailure(L, info, initialTop, topSeh);
        LogLuaBind("sentinel-fail stage=get-top L=%p top=%d (0x%08X) seh=0x%08lX",
                   L,
                   initialTop,
                   static_cast<unsigned int>(initialTop),
                   topSeh);
        if (outSoftFail && topSeh == kLuaStatusImplausibleTop)
            *outSoftFail = true;
        if (outSeh)
            *outSeh = topSeh;
        return false;
    }

    constexpr int kStackCandidates[] = {32, 24, 20, 16, 12, 10, 8, 6, 4};
    constexpr int kMinStackReserve = 6;
    DWORD stackSeh = 0;
    int grantedReserve = 0;
    for (int candidate : kStackCandidates) {
        if (SafeLuaCheckStack(L, candidate, &stackSeh)) {
            grantedReserve = candidate;
            break;
        }
    }
    if (grantedReserve < kMinStackReserve) {
        LogSentinelStackFailure(L, info, initialTop, stackSeh);
        LogLuaBind("sentinel-fail stage=check-stack L=%p top=%d (0x%08X) min=%d seh=0x%08lX",
                   L,
                   initialTop,
                   static_cast<unsigned int>(initialTop),
                   kMinStackReserve,
                   stackSeh);
        if (outSoftFail)
            *outSoftFail = true;
        if (outSeh)
            *outSeh = stackSeh;
        return false;
    }
    if (grantedReserve != kStackCandidates[0]) {
        LogLuaBind("sentinel stack-reserve L=%p top=%d (0x%08X) granted=%d",
                   L,
                   initialTop,
                   static_cast<unsigned int>(initialTop),
                   grantedReserve);
    }

    LuaStackGuard stackGuard(L, &info);

    DWORD seh = 0;
    if (!PushSentinelTable(L, info, true, nullptr, &seh)) {
        LogLuaBind("sentinel-fail stage=rawget-check L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    int tableIndex = 0;
    if (!SafeLuaGetTop(L, info, &tableIndex, &seh)) {
        LogLuaBind("sentinel-fail stage=table-top L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    bool hasUd = false;
    lua_Integer storedGen = 0;
    bool hasGen = false;

    if (!SafeLuaPushString(L, "ud", &seh) || !SafeLuaRawGet(L, tableIndex, &seh)) {
        LogLuaBind("sentinel-fail stage=table-inspect L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }
    int valueType = LUA_TNONE;
    if (SafeLuaType(L, -1, &valueType, &seh) && valueType == LUA_TUSERDATA) {
        void* ptr = nullptr;
        if (SafeLuaToUserdata(L, -1, &ptr, &seh) && ptr)
            hasUd = true;
    }
    if (!SafeLuaSetTop(L, info, tableIndex, &seh)) {
        LogLuaBind("sentinel-fail stage=restore-check-stack L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    if (!SafeLuaPushString(L, "gen", &seh) || !SafeLuaRawGet(L, tableIndex, &seh)) {
        LogLuaBind("sentinel-fail stage=table-inspect L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }
    valueType = LUA_TNONE;
    if (SafeLuaType(L, -1, &valueType, &seh) && valueType == LUA_TNUMBER) {
        if (SafeLuaToInteger(L, -1, &storedGen, &seh))
            hasGen = true;
    }
    if (!SafeLuaSetTop(L, info, tableIndex, &seh)) {
        LogLuaBind("sentinel-fail stage=restore-check-stack L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    bool needsInstall = !hasUd || !hasGen || storedGen != static_cast<lua_Integer>(info.gen);

    if (!needsInstall) {
        if (outSeh)
            *outSeh = 0;
        return true;
    }

    if (!SafeLuaPushString(L, "ud", &seh) || !SafeLuaPushNil(L, &seh) || !SafeLuaSetTable(L, tableIndex, &seh)) {
        LogLuaBind("sentinel-fail stage=table-reset L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }
    if (!SafeLuaPushString(L, "installed", &seh) || !SafeLuaPushNil(L, &seh) || !SafeLuaSetTable(L, tableIndex, &seh)) {
        LogLuaBind("sentinel-fail stage=table-reset L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    void* payloadPtr = nullptr;
    if (!SafeLuaNewUserdata(L, sizeof(HookSentinel), &payloadPtr, &seh)) {
        LogLuaBind("sentinel-fail stage=newuserdata L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }
    HookSentinel* payload = reinterpret_cast<HookSentinel*>(payloadPtr);
    if (payload)
        payload->state = L;

    if (!SafeLuaCreateTable(L, 0, 1, &seh)) {
        LogLuaBind("sentinel-fail stage=create-mt L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }
    if (!SafeLuaPushString(L, "__gc", &seh)) {
        LogLuaBind("sentinel-fail stage=push-gc-key L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }
    if (!SafeLuaPushCClosure(L, HookSentinelGC, 0, &seh)) {
        LogLuaBind("sentinel-fail stage=push-gc-func L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }
    if (!SafeLuaRawSet(L, -3, &seh)) {
        LogLuaBind("sentinel-fail stage=set-gc-entry L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }
    if (!SafeLuaSetMetatable(L, -2, &seh)) {
        LogLuaBind("sentinel-fail stage=set-metatable L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    if (!SafeLuaPushString(L, "ud", &seh) || !SafeLuaPushValue(L, -2, &seh) || !SafeLuaSetTable(L, tableIndex, &seh)) {
        LogLuaBind("sentinel-fail stage=store-ud L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }
    if (!SafeLuaPushString(L, "state", &seh) || !SafeLuaPushLightUserdata(L, L, &seh) || !SafeLuaSetTable(L, tableIndex, &seh)) {
        LogLuaBind("sentinel-fail stage=store-state L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }
    if (!SafeLuaPushString(L, "gen", &seh) || !SafeLuaPushInteger(L, static_cast<lua_Integer>(info.gen), &seh) || !SafeLuaSetTable(L, tableIndex, &seh)) {
        LogLuaBind("sentinel-fail stage=store-gen L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }
    if (!SafeLuaPushString(L, "installed", &seh) || !SafeLuaPushBoolean(L, 1, &seh) || !SafeLuaSetTable(L, tableIndex, &seh)) {
        LogLuaBind("sentinel-fail stage=store-flag L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    if (!SafeLuaSetTop(L, info, tableIndex, &seh)) {
        LogLuaBind("sentinel-fail stage=restore-final L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    if (created)
        *created = true;
    if (outSeh)
        *outSeh = 0;
    return true;
}

static bool EnsureHookSentinelGuarded(lua_State* L, LuaStateInfo& info, bool* created, DWORD* outSeh, bool* outSoftFail) noexcept {
    DWORD localSeh = 0;
#if defined(_MSC_VER)
    __try {
        bool ok = EnsureHookSentinel(L, info, created, &localSeh, outSoftFail);
        if (outSeh)
            *outSeh = localSeh;
        return ok;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        if (created)
            *created = false;
        if (outSoftFail)
            *outSoftFail = false;
        if (outSeh)
            *outSeh = code;
        LogLuaBind("sentinel-fail stage=seh-handler L=%p seh=0x%08lX", L, code);
        return false;
    }
#else
    bool ok = EnsureHookSentinel(L, info, created, &localSeh, outSoftFail);
    if (outSeh)
        *outSeh = localSeh;
    return ok;
#endif
}

static bool ClearHookSentinel(lua_State* L, DWORD* outSeh) noexcept {
    if (!L)
        return false;

    LuaStateInfo info{};
    bool haveInfo = g_stateRegistry.GetByPointer(L, info) && (info.flags & STATE_FLAG_VALID) && info.L_canonical;

    LuaStackGuard stackGuard(L, haveInfo ? &info : nullptr);
    DWORD seh = 0;
    if (!SafeLuaRawGetP(L, LUA_REGISTRYINDEX, &g_hookSentinelKey, &seh)) {
        LogLuaBind("sentinel-fail stage=clear-rawget L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    int type = LUA_TNONE;
    if (!SafeLuaType(L, -1, &type, &seh)) {
        LogLuaBind("sentinel-fail stage=clear-type L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }
    bool exists = (type == LUA_TTABLE);
    bool restoreOk = haveInfo ? SafeLuaSetTop(L, info, -2, &seh) : SafeLuaSetTop(L, -2, &seh);
    if (!restoreOk) {
        LogLuaBind("sentinel-fail stage=clear-restore-check L=%p seh=0x%08lX", L, seh);
        if (outSeh)
            *outSeh = seh;
        return false;
    }

    if (exists) {
        if (!SafeLuaPushNil(L, &seh)) {
            LogLuaBind("sentinel-fail stage=clear-push-nil L=%p seh=0x%08lX", L, seh);
            if (outSeh)
                *outSeh = seh;
            return false;
        }
        if (!SafeLuaRawSetP(L, LUA_REGISTRYINDEX, &g_hookSentinelKey, &seh)) {
            LogLuaBind("sentinel-fail stage=clear-rawsetp L=%p seh=0x%08lX", L, seh);
            if (outSeh)
                *outSeh = seh;
            return false;
        }
    }

    if (outSeh)
        *outSeh = 0;
    return true;
}

static bool EnsurePanicHookOnOwner(lua_State* L, LuaStateInfo& info, bool* changed, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;

    bool needInstall = (info.panic_status != 1);
    lua_CFunction current = nullptr;
    DWORD querySeh = 0;
    if (!needInstall) {
        if (SafeLuaQueryPanic(L, &current, &querySeh)) {
            needInstall = (current != UOW_PanicThunk);
        } else if (querySeh != 0) {
            needInstall = true;
        }
    }

    if (!needInstall) {
        if (changed)
            *changed = false;
        if (outSeh)
            *outSeh = 0;
        return true;
    }

    DWORD panicSeh = 0;
    lua_CFunction previous = nullptr;
    bool installed = TryInstallPanicHook(L, &previous, &panicSeh);

    if (!installed) {
        g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
            state.panic_status = 0;
            state.panic_status_gen = state.gen;
            state.panic_prev = nullptr;
            state.flags |= STATE_FLAG_PANIC_MISS;
            state.flags &= ~STATE_FLAG_PANIC_OK;
        }, &info);
        if (changed)
            *changed = false;
        if (outSeh)
            *outSeh = panicSeh;
        return false;
    }

    g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
        state.panic_prev = previous;
        state.panic_status = 1;
        state.panic_status_gen = state.gen;
        state.flags |= STATE_FLAG_PANIC_OK;
        state.flags &= ~STATE_FLAG_PANIC_MISS;
    }, &info);

    if (changed)
        *changed = true;
    if (outSeh)
        *outSeh = 0;
    return true;
}

static void CleanupHooksOnOwner(lua_State* L, const char* reason, bool releaseEntry) {
    if (!L)
        return;

    LuaStackGuard stackGuard(L);

    LuaStateInfo info{};

    bool haveInfo = g_stateRegistry.GetByPointer(L, info);

    if (haveInfo && info.debug_status == 1) {
        lua_Hook restore = info.debug_prev_valid ? info.debug_prev : nullptr;
        int restoreMask = info.debug_prev_valid ? info.debug_prev_mask : 0;
        int restoreCount = info.debug_prev_valid ? info.debug_prev_count : 0;
        SafeLuaSetHook(L, restore, restoreMask, restoreCount, nullptr);
    } else {
        SafeLuaSetHook(L, nullptr, 0, 0, nullptr);
    }

    if (haveInfo && info.panic_status == 1) {
        lua_CFunction restorePanic = info.panic_prev;
        SafeLuaAtPanic(L, restorePanic, nullptr);
    }

    ClearHookSentinel(L, nullptr);
    ClearDebugInstallRetry(L);

    if (haveInfo) {
        g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
            state.debug_status = 0;
            state.debug_status_gen = state.gen;
            state.debug_mode = DEBUG_MODE_OFF;
            state.debug_mode_gen = state.gen;
            state.debug_mask = 0;
            state.debug_count = 0;
            state.debug_prev = nullptr;
            state.debug_prev_mask = 0;
            state.debug_prev_count = 0;
            state.debug_prev_valid = 0;
            state.panic_status = 0;
            state.panic_status_gen = state.gen;
            state.panic_prev = nullptr;
            state.flags &= ~STATE_FLAG_PANIC_OK;
            state.flags &= ~STATE_FLAG_DEBUG_OK;
            state.gc_sentinel_ref = -1;
            state.gc_sentinel_gen = state.gen;
        }, &info);
    }

    LogLuaBind("hooks-uninstall Lc=%p reason=%s", L, reason ? reason : "unknown");

    if (releaseEntry)
        g_stateRegistry.RemoveByPointer(L, nullptr);
}

static void CleanupHooks(lua_State* L, const char* reason, bool releaseEntry) {
    if (!L)
        return;

    LuaStateInfo info{};
    bool haveInfo = g_stateRegistry.GetByPointer(L, info);
    if (haveInfo)
        MaybeAdoptOwnerThread(L, info);
    if (haveInfo && !IsOwnerThread(info)) {
        std::string reasonCopy = reason ? reason : "cleanup";
        PostToOwnerWithTask(L, "hooks-cleanup", [state = L, reasonCopy = std::move(reasonCopy), releaseEntry]() {
            CleanupHooksOnOwner(state, reasonCopy.c_str(), releaseEntry);
        });
        return;
    }

    CleanupHooksOnOwner(L, reason, releaseEntry);
}

static int __cdecl HookSentinelGC(lua_State* L) {
    return 0;
}

static bool ApplyDebugConfigOnOwner(lua_State* L, LuaStateInfo& info, const DebugConfigRequest& req, DebugConfigResult& result) {
    if (!L)
        return false;

    MaybeAdoptOwnerThread(L, info);

    if (!(info.flags & STATE_FLAG_VALID)) {
        result.error = "state-invalid";
        result.enabled = (info.debug_status == 1);
        return false;
    }

    uint32_t mode = req.mode;
    uint32_t mask = req.mask;
    uint32_t count = req.count;

    switch (mode) {
    case DEBUG_MODE_CALLS:
        mask = LUA_MASKCALL | LUA_MASKRET;
        count = 0;
        break;
    case DEBUG_MODE_TRACE:
        mask = LUA_MASKCALL | LUA_MASKRET | LUA_MASKLINE;
        count = 0;
        break;
    case DEBUG_MODE_CUSTOM:
        if (!req.explicitMask) {
            mask = info.debug_mask ? info.debug_mask : (LUA_MASKCALL | LUA_MASKRET);
        }
        if (!req.explicitCount) {
            count = info.debug_count;
        }
        break;
    case DEBUG_MODE_OFF:
    default:
        mask = 0;
        count = 0;
        mode = DEBUG_MODE_OFF;
        break;
    }

    int hookMask = static_cast<int>(mask);
    int hookCount = 0;
    if (count > 0) {
        hookCount = static_cast<int>(std::min<uint32_t>(count, static_cast<uint32_t>(INT_MAX)));
        hookMask |= LUA_MASKCOUNT;
    }

    bool enabling = (hookMask != 0);
    bool currentlyEnabled = (info.debug_status == 1);
    bool configChanged = currentlyEnabled != enabling ||
                         info.debug_mask != static_cast<uint32_t>(hookMask) ||
                         info.debug_count != static_cast<uint32_t>(hookCount) ||
                         info.debug_mode != mode;
    result.enabled = currentlyEnabled;

    if (!configChanged) {
        result.applied = false;
        result.mode = info.debug_mode;
        result.mask = info.debug_mask;
        result.count = info.debug_count;
        return true;
    }

    if (enabling) {
        InstallPanicAndDebug(L, info);
        lua_Hook prevHook = nullptr;
        int prevMask = 0;
        int prevCount = 0;
        if (info.debug_status != 1) {
            SafeLuaGetHook(L, &prevHook, &prevMask, nullptr);
            prevCount = lua_gethookcount(L);
        } else {
            prevHook = info.debug_prev;
            prevMask = info.debug_prev_mask;
            prevCount = info.debug_prev_count;
        }

        DWORD setSeh = 0;
        if (!SafeLuaSetHook(L, UOW_DebugHook, hookMask, hookCount, &setSeh)) {
            result.error = "sethook-failed";
            result.seh = setSeh;
            return false;
        }

        g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
            if (state.debug_status != 1) {
                state.debug_prev = prevHook;
                state.debug_prev_mask = prevMask;
                state.debug_prev_count = prevCount;
                state.debug_prev_valid = 1;
            }
            state.debug_status = 1;
            state.debug_status_gen = state.gen;
            state.debug_mode = mode;
            state.debug_mode_gen = state.gen;
            state.debug_mask = static_cast<uint32_t>(hookMask);
            state.debug_count = static_cast<uint32_t>(hookCount);
            state.flags |= STATE_FLAG_DEBUG_OK;
            state.flags &= ~STATE_FLAG_DEBUG_MISS;
        }, &info);

        result.applied = true;
        result.enabled = true;
        result.mode = mode;
        result.mask = static_cast<uint32_t>(hookMask);
        result.count = static_cast<uint32_t>(hookCount);
        return true;
    }

    lua_Hook restoreHook = nullptr;
    int restoreMask = 0;
    int restoreCount = 0;
    if (info.debug_prev_valid) {
        restoreHook = info.debug_prev;
        restoreMask = info.debug_prev_mask;
        restoreCount = info.debug_prev_count;
    }

    DWORD setSeh = 0;
    if (!SafeLuaSetHook(L, restoreHook, restoreMask, restoreCount, &setSeh)) {
        result.error = "restore-failed";
        result.seh = setSeh;
        return false;
    }

    g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
        state.debug_status = 0;
        state.debug_status_gen = state.gen;
        state.debug_mode = DEBUG_MODE_OFF;
        state.debug_mode_gen = state.gen;
        state.debug_mask = 0;
        state.debug_count = 0;
        state.flags &= ~STATE_FLAG_DEBUG_OK;
    }, &info);

    result.applied = currentlyEnabled;
    result.enabled = false;
    result.mode = DEBUG_MODE_OFF;
    result.mask = 0;
    result.count = 0;
    return true;
}

static void PushDebugResultTable(lua_State* L,
                                 const char* status,
                                 bool enabled,
                                 uint32_t mode,
                                 uint32_t mask,
                                 uint32_t count,
                                 bool applied,
                                 bool scheduled) {
    lua_newtable(L);

    lua_pushstring(L, "status");
    lua_pushstring(L, status ? status : (enabled ? "on" : "off"));
    lua_settable(L, -3);

    lua_pushstring(L, "enabled");
    lua_pushboolean(L, enabled ? 1 : 0);
    lua_settable(L, -3);

    lua_pushstring(L, "mode");
    lua_pushstring(L, DebugModeToString(mode));
    lua_settable(L, -3);

    lua_pushstring(L, "mask");
    lua_pushinteger(L, static_cast<lua_Integer>(mask));
    lua_settable(L, -3);

    lua_pushstring(L, "count");
    lua_pushinteger(L, static_cast<lua_Integer>(count));
    lua_settable(L, -3);

    lua_pushstring(L, "applied");
    lua_pushboolean(L, applied ? 1 : 0);
    lua_settable(L, -3);

    lua_pushstring(L, "scheduled");
    lua_pushboolean(L, scheduled ? 1 : 0);
    lua_settable(L, -3);
}

static ModuleBounds GetLuaPlusModuleBounds() {
    static ModuleBounds cached{};
    static bool cachedReady = false;
    if (cachedReady)
        return cached;

    HMODULE mod = GetModuleHandleA("luaplus_1100.dll");
    if (!mod)
        return ModuleBounds{};

    MODULEINFO info{};
    if (!GetModuleInformation(GetCurrentProcess(), mod, &info, sizeof(info)))
        return ModuleBounds{};

    cached.base = reinterpret_cast<uintptr_t>(info.lpBaseOfDll);
    cached.size = info.SizeOfImage;
    cached.valid = true;
    cachedReady = true;
    return cached;
}

static bool LooksLikeLuaPlusState(void* candidate) {
    if (!candidate)
        return false;
    ModuleBounds bounds = GetLuaPlusModuleBounds();
    if (!bounds.valid)
        return false;

    uintptr_t vtbl = 0;
    __try {
        vtbl = *reinterpret_cast<uintptr_t*>(candidate);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return vtbl >= bounds.base && vtbl < (bounds.base + bounds.size);
}

static LuaStateGetCStateFn ResolveLuaPlusGetCState() {
    if (!g_luaStateGetCState) {
        HMODULE mod = GetModuleHandleA("luaplus_1100.dll");
        if (mod) {
            g_luaStateGetCState = reinterpret_cast<LuaStateGetCStateFn>(
                GetProcAddress(mod, "?GetCState@LuaState@LuaPlus@@QAEPAUlua_State@@XZ"));
        }
    }
    return g_luaStateGetCState;
}

static LuaStateAtPanicFn ResolveLuaPlusAtPanic() {
    if (!g_luaStateAtPanic) {
        HMODULE mod = GetModuleHandleA("luaplus_1100.dll");
        if (mod) {
            g_luaStateAtPanic = reinterpret_cast<LuaStateAtPanicFn>(
                GetProcAddress(mod, "?AtPanic@LuaState@LuaPlus@@QAEP6AHPAUlua_State@@@ZP6AH0@Z@Z"));
        }
    }
    return g_luaStateAtPanic;
}

static lua_State* NormalizeLuaStatePointer(lua_State* candidate) {
    if (!candidate)
        return nullptr;
    void* raw = reinterpret_cast<void*>(candidate);

    auto getCState = ResolveLuaPlusGetCState();
    auto tryGetCState = [&](void* ptr) -> lua_State* {
        if (!ptr || !getCState)
            return nullptr;
        lua_State* actual = nullptr;
        __try {
            actual = getCState(ptr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            actual = nullptr;
        }
        return actual;
    };

    lua_State* actual = nullptr;
    if (LooksLikeLuaPlusState(raw)) {
        actual = tryGetCState(raw);
    } else {
        actual = tryGetCState(raw);
    }

    if (actual && ProbeLua(actual)) {
        g_mainLuaPlusState.store(raw, std::memory_order_release);
        if (actual != candidate) {
            LogLuaProbe("normalized lua state raw=%p c=%p", raw, actual);
        }
        return actual;
    }

    if (ProbeLua(candidate))
        return candidate;

    return nullptr;
}

static void LogLuaQueueDrain(lua_State* L, DWORD tid, const char* outcome, const char* detail = nullptr) {
    LogLuaQ("drain outcome=%s tid=%lu L=%p%s%s",
            outcome ? outcome : "?",
            tid,
            L,
            detail ? " detail=" : "",
            detail ? detail : "");
}

static void MaybeLogQueueDrain(lua_State* L, DWORD tid, const char* detail) {
    DWORD now = GetTickCount();
    DWORD last = g_lastQueueLogTick.load(std::memory_order_relaxed);
    if (now - last < kQueueDrainLogCooldownMs)
        return;
    if (g_lastQueueLogTick.compare_exchange_strong(last, now, std::memory_order_acq_rel)) {
        LogLuaQueueDrain(L, tid, "idle", detail);
    }
}

static void EnsureScriptThread(DWORD tid, lua_State* L) {
    if (!tid)
        return;

    lua_State* normalized = NormalizeLuaStatePointer(L);
    if (normalized)
        L = normalized;

    DWORD expected = 0;
    bool scriptThreadDiscovered = false;
    if (g_scriptThreadId.compare_exchange_strong(expected, tid)) {
        Log::Logf(Log::Level::Info,
                  Log::Category::LuaGuard,
                  "[LuaQ] script-thread-discovered tid=%lu L=%p",
                  static_cast<unsigned long>(tid),
                  L);
        scriptThreadDiscovered = true;
    }

    if (!scriptThreadDiscovered) {
        DWORD current = g_scriptThreadId.load(std::memory_order_acquire);
        if (current != tid && L) {
            lua_State* canonical = g_canonicalState.load(std::memory_order_acquire);
            lua_State* mainState = g_mainLuaState.load(std::memory_order_acquire);
            if ((canonical && L == canonical) || (mainState && L == mainState)) {
                if (g_scriptThreadId.compare_exchange_strong(current, tid)) {
                    Log::Logf(Log::Level::Info,
                              Log::Category::LuaGuard,
                              "[LuaQ] script-thread-updated tid=%lu prev=%lu L=%p",
                              static_cast<unsigned long>(tid),
                              static_cast<unsigned long>(current),
                              L);
                    scriptThreadDiscovered = true;
                }
            } else {
                Log::Logf(Log::Level::Info,
                          Log::Category::LuaGuard,
                          "[LuaQ] script-thread-await tid=%lu prev=%lu L=%p canonical=%p main=%p",
                          static_cast<unsigned long>(tid),
                          static_cast<unsigned long>(current),
                          L,
                          canonical,
                          mainState);
            }
        }
    }

    if (g_scriptThreadId.load(std::memory_order_acquire) == tid && L) {
        lua_State* prev = g_mainLuaState.exchange(L, std::memory_order_acq_rel);
        bool stateChanged = (prev != L);
        if (stateChanged) {
            LogLuaQ("tid=%lu main-state-updated L=%p (prev=%p)", tid, L, prev);

            void* ctxHint = nullptr;
            if (prev) {
                LuaStateInfo prevInfo{};
                if (g_stateRegistry.GetByPointer(prev, prevInfo) && prevInfo.ctx_reported)
                    ctxHint = prevInfo.ctx_reported;
            }
            if (!ctxHint)
                ctxHint = g_latestScriptCtx.load(std::memory_order_acquire);
            if (!ctxHint)
                ctxHint = GetCanonicalHelperCtx();

            bool isNew = false;
            bool ready = false;
            bool coalesced = false;
            uint64_t gen = g_generation.load(std::memory_order_acquire);
            ObserveReportedState(L, ctxHint, tid, gen, "main-state", &isNew, &ready, &coalesced);

            if (prev) {
                ForceRebindAll("main-state-updated");
            }
        }
        if (!g_processingLuaQueue) {
            bool hasPending = false;
            {
                std::lock_guard<std::mutex> lock(g_taskMutex);
                hasPending = !g_taskQueue.empty();
            }
            if (hasPending)
                ProcessPendingLuaTasks(L);
        }
        if (scriptThreadDiscovered || stateChanged) {
            ScheduleWalkBinding();
        }
    }
}

static lua_State* ResolveLuaState() {
    if (auto* state = g_mainLuaState.load(std::memory_order_acquire))
        return state;

    void* raw = Engine::LuaState();
    if (!raw)
        return nullptr;

    if (LooksLikeLuaPlusState(raw)) {
        g_mainLuaPlusState.store(raw, std::memory_order_release);
    }

    lua_State* normalized = NormalizeLuaStatePointer(static_cast<lua_State*>(raw));
    if (!normalized)
        normalized = static_cast<lua_State*>(raw);

    g_mainLuaState.store(normalized, std::memory_order_release);
    return normalized;
}

static bool RunLuaTaskWithGuards(lua_State* L, std::function<void(lua_State*)>& fn, const char** outDetail) noexcept {
    struct Runner {
        static bool Execute(lua_State* state, std::function<void(lua_State*)>* func, const char** outDetail) noexcept {
            bool ok = false;
            const char* localDetail = nullptr;
            __try {
                (*func)(state);
                ok = true;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                DWORD code = GetExceptionCode();
                static thread_local char sehDetail[64];
                sprintf_s(sehDetail, sizeof(sehDetail), "seh=0x%08lX", code);
                localDetail = sehDetail;
            }

            if (!ok && outDetail)
                *outDetail = localDetail;
            return ok;
        }
    };

    bool success = false;
    const char* detail = nullptr;
    try {
        success = Runner::Execute(L, &fn, &detail);
    } catch (const std::exception& ex) {
        detail = FormatCppExceptionDetail("cxx", ex.what());
        success = false;
    } catch (...) {
        detail = FormatCppExceptionDetail("cxx", "unknown");
        success = false;
    }

    if (!success && outDetail)
        *outDetail = detail;
    return success;
}

static void ProcessPendingLuaTasks(lua_State* L) {
    DWORD tid = GetCurrentThreadId();
    DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
    if (!scriptTid || tid != scriptTid) {
        MaybeLogQueueDrain(L, tid, "non-script-thread");
        return;
    }

    if (g_processingLuaQueue)
        return;

    std::deque<LuaTask> local;
    size_t queuedCount = 0;
    {
        std::lock_guard<std::mutex> lock(g_taskMutex);
        queuedCount = g_taskQueue.size();
        if (queuedCount == 0) {
            MaybeLogQueueDrain(L, tid, "empty");
        } else {
            local.swap(g_taskQueue);
        }
    }
    if (queuedCount == 0) {
        g_queueNeedsPump.store(false, std::memory_order_release);
    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][HB] tid=%lu queued=0 processed=0",
              static_cast<unsigned long>(tid));
    g_lastLuaHeartbeatTick.store(GetTickCount64(), std::memory_order_release);
    Core::StartupSummary::NotifyLuaHeartbeat();
    return;
    }

    g_processingLuaQueue = true;

    if (!g_queueLoggedDuringInit.exchange(true, std::memory_order_acq_rel)) {
        LogLuaQueueDrain(L, tid, "start");
    }

    size_t processedCount = 0;

    for (auto& task : local) {
        LogLuaQ("run fn=%s on=tid=%lu start", task.name.c_str(), tid);
        if (!L) {
            LogLuaQ("run fn=%s on=tid=%lu err=lua_state-null", task.name.c_str(), tid);
            continue;
        }

        auto fn = std::move(task.fn);
        bool success = false;
        const char* detail = nullptr;
        success = RunLuaTaskWithGuards(L, fn, &detail);
        if (success) {
            LogLuaQ("run fn=%s on=tid=%lu ok", task.name.c_str(), tid);
        } else {
            LogLuaQ("run fn=%s on=tid=%lu err=%s", task.name.c_str(), tid, detail ? detail : "unknown");
            PostToLuaThread(task.target ? task.target : L, task.name.c_str(), std::move(fn));
        }
        ++processedCount;
    }

    g_processingLuaQueue = false;
    MaybeLogQueueDrain(L, tid, "processed");

    size_t queuedAfter = 0;
    {
        std::lock_guard<std::mutex> lock(g_taskMutex);
        queuedAfter = g_taskQueue.size();
    }

    Log::Logf(Log::Level::Info,
              Log::Category::LuaGuard,
              "[LUA][HB] tid=%lu queued=%zu processed=%zu",
              static_cast<unsigned long>(tid),
              queuedAfter,
              processedCount);
    if (queuedAfter == 0)
        g_queueNeedsPump.store(false, std::memory_order_release);
    g_lastLuaHeartbeatTick.store(GetTickCount64(), std::memory_order_release);
    Core::StartupSummary::NotifyLuaHeartbeat();
}

static void PostToLuaThread(lua_State* L, const char* name, std::function<void(lua_State*)> fn) {
    DWORD fromTid = GetCurrentThreadId();
    {
        std::lock_guard<std::mutex> lock(g_taskMutex);
        g_taskQueue.push_back(LuaTask{ name ? name : "<lambda>", L, std::move(fn) });
    }
    g_queueNeedsPump.store(true, std::memory_order_release);
    LogLuaQ("post fn=%s L=%p from=tid=%lu", name ? name : "<lambda>", L, fromTid);

    DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
    if (scriptTid != 0 && scriptTid == fromTid && L && !g_processingLuaQueue) {
        ProcessPendingLuaTasks(L);
    }
}

static void MaybeAdoptOwnerThread(lua_State* L, LuaStateInfo& info) {
    DWORD canonicalOwner = GetCanonicalHelperOwnerTid();
    if (canonicalOwner) {
        if (info.owner_tid == canonicalOwner)
            return;
        uint64_t now = GetTickCount64();

        auto assignCanonical = [&](lua_State* pointer, const char* source) -> bool {
            if (!pointer)
                return false;
            DWORD previous = info.owner_tid;
            bool updated = g_stateRegistry.UpdateByPointer(pointer, [&](LuaStateInfo& state) {
                state.owner_tid = canonicalOwner;
                state.last_tid = canonicalOwner;
                if (!(state.flags & STATE_FLAG_OWNER_READY) || state.owner_ready_tick_ms == 0) {
                    state.owner_ready_tick_ms = now;
                    state.flags |= STATE_FLAG_OWNER_READY;
                }
            }, &info);
            if (updated) {
                info.owner_tid = canonicalOwner;
                if (previous != canonicalOwner) {
                    LogLuaState("owner-adopt L=%p old=%lu new=%lu source=%s",
                                pointer,
                                previous,
                                canonicalOwner,
                                source ? source : "canonical");
                }
            }
            return updated;
        };

        if (assignCanonical(info.L_canonical, "canonical"))
            return;
        if (assignCanonical(L, "direct"))
            return;
        assignCanonical(info.L_reported, "reported");
        return;
    }

    DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
    if (!scriptTid)
        return;
    if (info.owner_tid == scriptTid)
        return;
    uint64_t now = GetTickCount64();

    auto tryUpdate = [&](lua_State* pointer, const char* source) -> bool {
        if (!pointer)
            return false;
        DWORD previous = info.owner_tid;
        bool updated = g_stateRegistry.UpdateByPointer(pointer, [&](LuaStateInfo& state) {
            state.owner_tid = scriptTid;
            state.last_tid = scriptTid;
            if (!(state.flags & STATE_FLAG_OWNER_READY) || state.owner_ready_tick_ms == 0) {
                state.owner_ready_tick_ms = now;
                state.flags |= STATE_FLAG_OWNER_READY;
            }
        }, &info);
        if (updated && previous != info.owner_tid) {
            LogLuaState("owner-adopt L=%p old=%lu new=%lu source=%s",
                        pointer,
                        previous,
                        info.owner_tid,
                        source ? source : "unknown");
        }
        return updated;
    };

    if (tryUpdate(info.L_canonical, "canonical"))
        return;
    if (tryUpdate(L, "direct"))
        return;
    tryUpdate(info.L_reported, "reported");
}

static bool IsOwnerThread(const LuaStateInfo& info) {
    if (Core::Bind::IsCurrentDispatchTag("helpers"))
        return true;
    DWORD current = GetCurrentThreadId();
    if (info.owner_tid != 0 && info.owner_tid == current)
        return true;
    DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
    return scriptTid != 0 && scriptTid == current;
}

static bool IsOwnerThread(lua_State* L) {
    if (!L)
        return false;
    LuaStateInfo info{};
    if (!g_stateRegistry.GetByPointer(L, info))
        return false;
    return IsOwnerThread(info);
}

static void PostToOwnerWithTask(lua_State* L, const char* taskName, std::function<void()> fn) {
    if (!L || !fn)
        return;

    LuaStateInfo info{};
    bool haveInfo = g_stateRegistry.GetByPointer(L, info);
    if (haveInfo)
        MaybeAdoptOwnerThread(L, info);

    DWORD owner = 0;
    DWORD canonicalOwner = GetCanonicalHelperOwnerTid();
    if (canonicalOwner) {
        owner = canonicalOwner;
        if (haveInfo && info.owner_tid != canonicalOwner) {
            uint64_t now = GetTickCount64();
            g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
                state.owner_tid = canonicalOwner;
                state.last_tid = canonicalOwner;
                if (!(state.flags & STATE_FLAG_OWNER_READY) || state.owner_ready_tick_ms == 0) {
                    state.owner_ready_tick_ms = now;
                    state.flags |= STATE_FLAG_OWNER_READY;
                }
            }, &info);
            info.owner_tid = canonicalOwner;
        }
    } else if (haveInfo) {
        owner = info.owner_tid ? info.owner_tid : g_scriptThreadId.load(std::memory_order_acquire);
    } else {
        owner = g_scriptThreadId.load(std::memory_order_acquire);
    }

    DWORD from = GetCurrentThreadId();
    const char* name = taskName ? taskName : "<owner>";

    std::string taskLabel = name;
    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[CORE][Bind] posted-to-owner L=%p from=%lu -> owner=%lu task=%s",
              L,
              from,
              owner,
              taskLabel.c_str());

    std::function<void()> taskWrapper = [fn = std::move(fn), taskLabel, owner, L]() mutable {
        DWORD runner = GetCurrentThreadId();
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[CORE][Bind] owner-run L=%p owner=%lu runner=%lu task=%s",
                  L,
                  owner,
                  runner,
                  taskLabel.c_str());
        fn();
    };

    bool dispatched = false;
    if (taskLabel == "helpers") {
        dispatched = Core::Bind::DispatchWithFallback(owner, std::move(taskWrapper), taskLabel.c_str());
    } else {
        dispatched = Core::Bind::PostToOwner(owner, std::move(taskWrapper), taskLabel.c_str());
    }

    if (!dispatched) {
        Log::Logf(Log::Level::Warn,
                  Log::Category::Core,
                  "[CORE][Bind] dispatch incomplete L=%p owner=%lu task=%s",
                  L,
                  owner,
                  taskLabel.c_str());
    }
}

static void PostToOwner(lua_State* L, std::function<void()> fn) {
    PostToOwnerWithTask(L, "<owner>", std::move(fn));
}

static void PostBindToOwnerThread(lua_State* L,
                                  DWORD ownerTid,
                                  uint64_t generation,
                                  bool force,
                                  const char* reason) {
    if (!L)
        return;

    DWORD canonicalOwner = GetCanonicalHelperOwnerTid();
    if (canonicalOwner != 0)
        ownerTid = canonicalOwner;

    if (ownerTid == 0)
        return;

    if (Core::Bind::IsCurrentDispatchTag("helpers") || GetCurrentThreadId() == ownerTid) {
        BindHelpersTask(L, generation, force, reason ? reason : "ctx-rebind");
        return;
    }

    std::string reasonCopy = reason ? reason : "ctx-rebind";
    PostToOwnerWithTask(L, "helpers", [L, generation, force, reasonCopy]() {
        BindHelpersTask(L, generation, force, reasonCopy.c_str());
    });
}

static void MaybeRunMaintenance() {
    uint64_t now = GetTickCount64();
    uint64_t last = g_lastMaintenanceTick.load(std::memory_order_relaxed);
    if (now - last < kMaintenanceIntervalMs)
        return;
    if (!g_lastMaintenanceTick.compare_exchange_strong(last, now, std::memory_order_acq_rel))
        return;

    auto snapshot = g_stateRegistry.Snapshot();
    uint64_t generation = g_generation.load(std::memory_order_acquire);
    for (const auto& info : snapshot) {
        if (!(info.flags & STATE_FLAG_HELPERS_BOUND) || info.gen != generation) {
            RequestBindForState(info, "maintenance", false);
        }
    }
}

static void MaybeProcessHelperRetryQueue() {
    uint64_t now = GetTickCount64();
    uint64_t last = g_lastHelperRetryScanTick.load(std::memory_order_relaxed);
    if (now - last < 50)
        return;
    if (!g_lastHelperRetryScanTick.compare_exchange_strong(last, now, std::memory_order_acq_rel, std::memory_order_acquire))
        return;

    auto snapshot = g_stateRegistry.Snapshot();
    if (snapshot.empty())
        return;

    uint64_t generation = g_generation.load(std::memory_order_acquire);
    uint64_t heartbeatTick = g_lastLuaHeartbeatTick.load(std::memory_order_acquire);
    uint64_t facetTick = g_lastWaypointFacetTick.load(std::memory_order_acquire);
    uint64_t mutationTick = g_lastContextMutationTick.load(std::memory_order_acquire);
    uint64_t globalSignalTick = std::max<uint64_t>({heartbeatTick, facetTick, mutationTick});

    for (auto info : snapshot) {
        bool installed = (info.flags & STATE_FLAG_HELPERS_INSTALLED) && info.gen == generation;
        if (installed)
            continue;
        if (info.flags & STATE_FLAG_HELPERS_PENDING)
            continue;

        bool scheduleDue = (info.helper_next_retry_ms != 0) && now >= info.helper_next_retry_ms;
        bool passiveEligible = false;
        uint64_t consumedSignal = 0;

        if (!scheduleDue && info.helper_passive_since_ms != 0) {
            if (globalSignalTick != 0 && globalSignalTick > info.helper_last_signal_ms) {
                passiveEligible = true;
                consumedSignal = globalSignalTick;
            }
        }

        if (!scheduleDue && !passiveEligible)
            continue;

        lua_State* key = info.L_canonical ? info.L_canonical : info.L_reported;
        if (key && passiveEligible && consumedSignal != 0) {
            g_stateRegistry.UpdateByPointer(key, [&](LuaStateInfo& state) {
                if (consumedSignal > state.helper_last_signal_ms)
                    state.helper_last_signal_ms = consumedSignal;
                if (state.helper_next_retry_ms == 0 || state.helper_next_retry_ms > now)
                    state.helper_next_retry_ms = now;
            }, &info);
        }

        uint64_t nextTick = info.helper_next_retry_ms;
        if (passiveEligible && consumedSignal != 0)
            nextTick = now;

        uint64_t firstTick = info.helper_first_attempt_ms;
        uint64_t elapsedMs = (firstTick && now >= firstTick) ? (now - firstTick) : 0;

        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "helpers retry scheduling L=%p owner=%lu retries=%u next=%llu elapsed=%llu reason=%s",
                  key,
                  static_cast<unsigned long>(info.owner_tid),
                  static_cast<unsigned>(info.helper_retry_count),
                  static_cast<unsigned long long>(nextTick),
                  static_cast<unsigned long long>(elapsedMs),
                  scheduleDue ? "timer" : "signal");

        RequestBindForState(info, scheduleDue ? "retry" : "signal", false);
    }
}

static void MaybeEmitHeartbeat() {
    uint64_t now = GetTickCount64();
    uint64_t last = g_lastHeartbeatTick.load(std::memory_order_relaxed);
    if (now - last < 2000)
        return;
    if (!g_lastHeartbeatTick.compare_exchange_strong(last, now, std::memory_order_acq_rel))
        return;

    lua_State* canonical = g_canonicalState.load(std::memory_order_acquire);
    LuaStateInfo info{};
    bool haveInfo = canonical && g_stateRegistry.GetByPointer(canonical, info);
    HelperInstallStage stage = haveInfo ? static_cast<HelperInstallStage>(info.helper_state)
                                        : HelperInstallStage::WaitingForGlobalState;
    const char* helperLabel = "waiting_for_global_state";
    switch (stage) {
    case HelperInstallStage::Installed:
        helperLabel = "installed";
        break;
    case HelperInstallStage::Installing:
    case HelperInstallStage::ReadyToInstall:
        helperLabel = "installing";
        break;
    case HelperInstallStage::WaitingForGlobalState:
    case HelperInstallStage::WaitingForOwnerThread:
    default:
        helperLabel = "waiting_for_global_state";
        break;
    }
    uint64_t ageMs = (haveInfo && info.helper_state_since_ms && now >= info.helper_state_since_ms)
                         ? (now - info.helper_state_since_ms)
                         : 0;

    LONG slotSeen = InterlockedCompareExchange(&g_flags.lua_slot_seen, 0, 0);
    LONG tracerAttached = InterlockedCompareExchange(&g_flags.lua_tracer_attached, 0, 0);
    LONG regSeen = InterlockedCompareExchange(&g_flags.lua_reg_seen, 0, 0);
    bool luaOK = ((slotSeen | tracerAttached | regSeen) != 0);
    const char* luaLabel = luaOK ? "OK" : "MISS";
    void* engineCtx = g_engineContext.load(std::memory_order_acquire);
    const bool ctxOK = engineCtx != nullptr;
    const char* ctxLabel = ctxOK ? "OK" : "MISS";
    Net::SendBuilderStatus sbStatus = Net::GetSendBuilderStatus();
    char sbLabelBuf[32]{};
    const char* sbLabel = "pending";
    if (sbStatus.hooked) {
        sbLabel = "attached";
    } else if (sbStatus.ready) {
        const char* modeStr = "scan";
        switch (sbStatus.readyMode) {
        case Net::ReadyMode::Callsite:
            modeStr = "callsite";
            break;
        case Net::ReadyMode::DbMgr:
            modeStr = "dbmgr";
            break;
        default:
            break;
        }
        _snprintf_s(sbLabelBuf, sizeof(sbLabelBuf), _TRUNCATE, "ready(mode=%s)", modeStr);
        sbLabel = sbLabelBuf;
    } else if (sbStatus.probing) {
        sbLabel = "probing";
    }

    if (ctxOK && luaOK) {
        uint64_t expected = 0;
        g_helpers.settle_start_ms.compare_exchange_strong(expected, now, std::memory_order_acq_rel);
    }

    static bool s_lastLuaOk = false;
    static bool s_loggedLuaOk = false;
    if (luaOK && !s_lastLuaOk && !s_loggedLuaOk) {
        const char* parts[3]{};
        size_t partCount = 0;
        if (tracerAttached)
            parts[partCount++] = "tracer";
        if (slotSeen)
            parts[partCount++] = "slot";
        if (regSeen)
            parts[partCount++] = "regs";

        char sourceBuf[32] = {};
        if (partCount == 0) {
            strcpy_s(sourceBuf, sizeof(sourceBuf), "unknown");
        } else {
            size_t offset = 0;
            for (size_t i = 0; i < partCount && offset < sizeof(sourceBuf); ++i) {
                if (i != 0 && offset + 1 < sizeof(sourceBuf)) {
                    sourceBuf[offset++] = '/';
                }
                const char* part = parts[i];
                if (!part)
                    continue;
                int written = _snprintf_s(sourceBuf + offset,
                                          sizeof(sourceBuf) - offset,
                                          _TRUNCATE,
                                          "%s",
                                          part);
                if (written > 0)
                    offset += static_cast<size_t>(written);
            }
        }

        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[HB] lua status source=%s (ok)",
                  sourceBuf);
        s_loggedLuaOk = true;
    }
    s_lastLuaOk = luaOK;

    Walk::Controller::Settings walkSettings = Walk::Controller::GetSettings();
    uint32_t inflight = Walk::Controller::GetInflightCount();
    uint32_t maxInflight = walkSettings.maxInflight ? walkSettings.maxInflight : 1;
    uint32_t stepDelay = walkSettings.stepDelayMs;
    uint32_t ackOk = Engine::GetAckOkCount();
    uint32_t ackDrop = Engine::GetAckDropCount();

    unsigned long ageLog = ageMs > std::numeric_limits<unsigned long>::max()
                               ? std::numeric_limits<unsigned long>::max()
                               : static_cast<unsigned long>(ageMs);

    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[HB] lua=%s ctx=%s helpers=%s (age=%lums) sb=%s send=%p inflight=%u/%u stepDelay=%ums ack.ok=%u ack.drop=%u",
              luaLabel,
              ctxLabel,
              helperLabel ? helperLabel : "unknown",
              ageLog,
              sbLabel,
              sbStatus.sendPacket,
              static_cast<unsigned>(inflight),
              static_cast<unsigned>(maxInflight),
              static_cast<unsigned>(stepDelay),
              static_cast<unsigned>(ackOk),
              static_cast<unsigned>(ackDrop));
}

static void HelperPumpThreadMain() {
    while (!g_helperPumpStop.load(std::memory_order_acquire)) {
        MaybeProcessHelperRetryQueue();
        Net::PollSendBuilder();
        MaybeEmitHeartbeat();
        DebugRingFlush();
        for (int i = 0; i < 5; ++i) {
            if (g_helperPumpStop.load(std::memory_order_acquire))
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    DebugRingFlush();
    g_helperPumpRunning.store(false, std::memory_order_release);
}

static void StartHelperPumpThread() {
    bool expected = false;
    if (!g_helperPumpRunning.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    g_helperPumpStop.store(false, std::memory_order_release);
    try {
        g_helperPumpThread = std::thread([]() {
            HelperPumpThreadMain();
        });
    } catch (...) {
        g_helperPumpStop.store(true, std::memory_order_release);
        g_helperPumpRunning.store(false, std::memory_order_release);
        throw;
    }
}

static void StopHelperPumpThread() {
    g_helperPumpStop.store(true, std::memory_order_release);
    if (g_helperPumpThread.joinable()) {
        try {
            g_helperPumpThread.join();
        } catch (...) {
            // Suppress exceptions during shutdown.
        }
    }
    g_helperPumpRunning.store(false, std::memory_order_release);
}

static void RequestBindForState(const LuaStateInfo& info, const char* reason, bool force) {
    const char* action = reason ? reason : "unspecified";
    LuaStateInfo current = info;

    lua_State* lookupPtr = LookupPointerFor(current);
    if (!lookupPtr) {
        LogLuaState("bind-skip Lr=%p ctx=%p reason=no-pointer action=%s",
                    current.L_reported,
                    current.ctx_reported,
                    action);
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "helpers skip Lr=%p ctx=%p reason=no-pointer action=%s",
                  current.L_reported,
                  current.ctx_reported,
                  action);
        return;
    }

    if (reason && _stricmp(reason, "script-thread-wait") == 0) {
        DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
        lua_State* scriptL = g_mainLuaState.load(std::memory_order_acquire);
        if (scriptTid == 0 || !scriptL) {
            uint64_t now = GetTickCount64();
            const HelperRetryPolicy& retryPolicy = GetHelperRetryPolicy();
            uint64_t retryDelay = retryPolicy.debounceMs ? retryPolicy.debounceMs : 50u;
            uint64_t nextRetry = now + retryDelay;
            g_stateRegistry.UpdateByPointer(lookupPtr, [&](LuaStateInfo& state) {
                state.helper_next_retry_ms = nextRetry;
                state.helper_passive_since_ms = 0;
                UpdateHelperStage(state, HelperInstallStage::WaitingForGlobalState, now, "script-thread-wait");
            }, &current);

            Log::Logf(Log::Level::Info,
                      Log::Category::Hooks,
                      "helpers bind deferral L=%p reason=%s scriptTid=%lu scriptState=%p nextRetry=%llu",
                      lookupPtr,
                      action,
                      static_cast<unsigned long>(scriptTid),
                      scriptL,
                      static_cast<unsigned long long>(nextRetry));
            return;
        }
    }

    uint64_t now = GetTickCount64();
    const HelperRetryPolicy& retry = GetHelperRetryPolicy();

    bool haveCanonical = current.L_canonical != nullptr;
    bool canonicalReadyFlag = (current.flags & STATE_FLAG_CANON_READY) != 0;
    if (!haveCanonical || !canonicalReadyFlag) {
        bool ready = false;
        bool coalesced = false;
        current = RefreshCanonical(lookupPtr, action, false, &ready, &coalesced);
        haveCanonical = current.L_canonical != nullptr;
        canonicalReadyFlag = ready && haveCanonical && ((current.flags & STATE_FLAG_CANON_READY) != 0);
    }

    if (!haveCanonical || !current.L_canonical) {
        now = GetTickCount64();
        uint64_t waitMs = (current.next_probe_ms > now) ? (current.next_probe_ms - now) : 0;
        if (now - current.last_bind_log_tick_ms >= kBindLogCooldownMs) {
            current.last_bind_log_tick_ms = now;
            LogLuaState("bind-skip Lr=%p ctx=%p reason=no-canonical wait=%llu action=%s",
                        current.L_reported,
                        current.ctx_reported,
                        static_cast<unsigned long long>(waitMs),
                        action);
            lua_State* logTarget = current.L_canonical ? current.L_canonical : lookupPtr;
            if (logTarget) {
                g_stateRegistry.UpdateByPointer(logTarget, [&](LuaStateInfo& state) {
                    state.last_bind_log_tick_ms = now;
                }, &current);
            }
        }
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "helpers skip Lr=%p ctx=%p reason=no-canonical waitMs=%llu action=%s",
                  current.L_reported,
                  current.ctx_reported,
                  static_cast<unsigned long long>(waitMs),
                  action);
        lua_State* stageTarget = current.L_canonical ? current.L_canonical : lookupPtr;
        if (stageTarget) {
            g_stateRegistry.UpdateByPointer(stageTarget, [&](LuaStateInfo& state) {
                UpdateHelperStage(state, HelperInstallStage::WaitingForGlobalState, now, action);
                if (!state.helper_first_attempt_ms)
                    state.helper_first_attempt_ms = now;
                uint64_t minNext = now + retry.retryBackoffMs;
                if (state.helper_next_retry_ms == 0 || state.helper_next_retry_ms < minNext)
                    state.helper_next_retry_ms = minNext;
            }, &current);
        }
        TrackHelperEvent(g_helperDeferredCount);
        MaybeEmitHelperSummary(now);
        return;
    }

    lua_State* target = current.L_canonical;
    Net::SendBuilderStatus sbStatus = Net::GetSendBuilderStatus();
    const bool sbReadyNow = sbStatus.ready;
    const bool sbPivotNow = sbStatus.pivotReady;
    const bool sbFallbackNow = Net::HasFallbackPivot();
    const bool sbDbMgrMode = sbStatus.ready && sbStatus.readyMode == Net::ReadyMode::DbMgr;
    HelperInstallStage stage = DetermineHelperStage(current, canonicalReadyFlag);
    void* engineCtxSnapshot = g_engineContext.load(std::memory_order_acquire);
    if (engineCtxSnapshot && current.helper_settle_start_ms == 0) {
        lua_State* settlePtr = target ? target : lookupPtr;
        if (settlePtr) {
            g_stateRegistry.UpdateByPointer(settlePtr, [&](LuaStateInfo& state) {
                if (state.helper_settle_start_ms == 0)
                    state.helper_settle_start_ms = now;
            }, &current);
        }
    }
    if (target) {
        g_stateRegistry.UpdateByPointer(target, [&](LuaStateInfo& state) {
            UpdateHelperStage(state, stage, now, action);
            if (stage == HelperInstallStage::WaitingForOwnerThread && state.helper_owner_deadline_ms == 0)
                state.helper_owner_deadline_ms = now + retry.ownerConfirmMs;
        }, &current);
        stage = CurrentHelperStage(current);
        now = GetTickCount64();
    }
    if (!force && stage == HelperInstallStage::WaitingForOwnerThread) {
        bool ownerReady = (current.flags & STATE_FLAG_OWNER_READY) != 0 && current.owner_tid != 0;
        if (!ownerReady) {
            g_stateRegistry.UpdateByPointer(target, [&](LuaStateInfo& state) {
                if (state.helper_owner_deadline_ms == 0)
                    state.helper_owner_deadline_ms = now + retry.ownerConfirmMs;
            }, &current);
            ownerReady = (current.flags & STATE_FLAG_OWNER_READY) != 0 && current.owner_tid != 0;
        }

        uint64_t deadline = current.helper_owner_deadline_ms;
        if (!ownerReady && deadline && now >= deadline) {
            DWORD previousOwner = current.owner_tid;
            DWORD fallbackTid = previousOwner ? previousOwner : g_scriptThreadId.load(std::memory_order_acquire);
            if (!fallbackTid)
                fallbackTid = GetCurrentThreadId();
            if (fallbackTid) {
                uint64_t waitedMs = current.helper_state_since_ms ? (now - current.helper_state_since_ms) : 0;
                g_stateRegistry.UpdateByPointer(target, [&](LuaStateInfo& state) {
                    if (state.owner_tid == 0)
                        state.owner_tid = fallbackTid;
                    state.flags |= STATE_FLAG_OWNER_READY;
                    state.owner_ready_tick_ms = now;
                    state.helper_owner_deadline_ms = 0;
                    if (state.helper_failover_count < std::numeric_limits<uint8_t>::max())
                        ++state.helper_failover_count;
                    UpdateHelperStage(state, HelperInstallStage::ReadyToInstall, now, "owner-promoted");
                }, &current);
                Log::Logf(Log::Level::Warn,
                          Log::Category::Hooks,
                          "helpers owner promotion L=%p prev=%lu new=%lu waitedMs=%llu action=%s",
                          target,
                          static_cast<unsigned long>(previousOwner),
                          static_cast<unsigned long>(current.owner_tid),
                          static_cast<unsigned long long>(waitedMs),
                          action);
                bool ready = false;
                bool coalesced = false;
                current = RefreshCanonical(target, action, false, &ready, &coalesced);
                canonicalReadyFlag = ready && ((current.flags & STATE_FLAG_CANON_READY) != 0);
                stage = DetermineHelperStage(current, canonicalReadyFlag);
                g_stateRegistry.UpdateByPointer(target, [&](LuaStateInfo& state) {
                    UpdateHelperStage(state, stage, now, "owner-promoted-refresh");
                }, &current);
                now = GetTickCount64();
            }
        }

        ownerReady = (current.flags & STATE_FLAG_OWNER_READY) != 0 && current.owner_tid != 0;
        if (!ownerReady && !force) {
            TrackHelperEvent(g_helperDeferredCount);
            MaybeEmitHelperSummary(now);
            uint64_t remaining = (current.helper_owner_deadline_ms > now)
                                     ? (current.helper_owner_deadline_ms - now)
                                     : 0;
            Log::Logf(Log::Level::Info,
                      Log::Category::Hooks,
                      "helpers skip Lc=%p reason=owner-wait remainingMs=%llu action=%s",
                      target,
                      static_cast<unsigned long long>(remaining),
                      action);
            return;
        }
        stage = DetermineHelperStage(current, canonicalReadyFlag);
        g_stateRegistry.UpdateByPointer(target, [&](LuaStateInfo& state) {
            UpdateHelperStage(state, stage, now, "owner-ready");
        }, &current);
    }

    uint64_t generation = g_generation.load(std::memory_order_acquire);
    now = GetTickCount64();
    uint64_t globalSettleStart = g_helpers.settle_start_ms.load(std::memory_order_acquire);
    uint64_t settleElapsed = (globalSettleStart && now >= globalSettleStart) ? (now - globalSettleStart) : 0;
    uint64_t attemptElapsed = (current.helper_first_attempt_ms && now >= current.helper_first_attempt_ms)
                                  ? (now - current.helper_first_attempt_ms)
                                  : 0;
    const void* jitterToken = target ? target : lookupPtr;
    bool promotionTriggered = false;
    uint64_t promotionElapsed = 0;
    if (!force) {
        if ((current.flags & STATE_FLAG_HELPERS_BOUND) && current.gen == generation) {
            if (now - current.last_bind_log_tick_ms >= kBindLogCooldownMs) {
                current.last_bind_log_tick_ms = now;
                LogLuaState("bind-skip Lc=%p reason=already-bound action=%s",
                            target,
                            action);
                g_stateRegistry.UpdateByPointer(target, [&](LuaStateInfo& state) {
                    state.last_bind_log_tick_ms = now;
                }, &current);
            }
            return;
        }
    }
    if (current.flags & STATE_FLAG_HELPERS_INSTALLED) {
        if (now - current.last_bind_log_tick_ms >= kBindLogCooldownMs) {
            current.last_bind_log_tick_ms = now;
            LogLuaState("bind-skip Lc=%p reason=installed action=%s",
                        target,
                        action);
            g_stateRegistry.UpdateByPointer(target, [&](LuaStateInfo& state) {
                state.last_bind_log_tick_ms = now;
            }, &current);
        }
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "helpers skip Lc=%p reason=installed action=%s",
                  target,
                  action);
        return;
    }
    bool skipDueToPending = false;

    if (!force) {
        g_stateRegistry.UpdateByPointer(target, [&](LuaStateInfo& state) {
            if ((state.flags & STATE_FLAG_HELPERS_PENDING) && state.helper_pending_generation == generation) {
                skipDueToPending = true;
                UpdateHelperStage(state, HelperInstallStage::Installing, now, "pending");
                if (now - state.helper_pending_tick_ms >= kBindLogCooldownMs)
                    state.helper_pending_tick_ms = now;
            }
        }, &current);

        if (skipDueToPending) {
            if (now - current.helper_pending_tick_ms >= kBindLogCooldownMs) {
                LogLuaState("bind-skip Lc=%p reason=pending action=%s gen=%llu",
                            target,
                            action,
                            static_cast<unsigned long long>(generation));
            }
            Log::Logf(Log::Level::Info,
                      Log::Category::Hooks,
                      "helpers skip Lc=%p reason=pending gen=%llu action=%s",
                      target,
                      static_cast<unsigned long long>(generation),
                      action);
            TrackHelperEvent(g_helperDeferredCount);
            MaybeEmitHelperSummary(now);
            return;
        }
    } else {
        ClearHelperPending(target, generation, &current);
    }

    const uint64_t mutationTick = g_lastContextMutationTick.load(std::memory_order_acquire);
    const uint64_t heartbeatTick = g_lastLuaHeartbeatTick.load(std::memory_order_acquire);
    const uint64_t facetTick = g_lastWaypointFacetTick.load(std::memory_order_acquire);
    const uint64_t latestSignalTick = std::max<uint64_t>({heartbeatTick, facetTick, mutationTick});
    const uint32_t autopLimit = retry.retrySchedule.empty()
                                    ? 0u
                                    : std::min<uint32_t>(retry.maxRetries, static_cast<uint32_t>(retry.retrySchedule.size()));

    uint32_t attemptsSoFar = current.helper_retry_count;
    uint32_t nextAttemptIndex = attemptsSoFar + 1;
    bool allowNow = force;
    bool passiveMode = false;
    bool signalConsumed = false;
    bool logOverride = false;
    const char* overrideReason = nullptr;
    const char* gateReason = nullptr;
    uint64_t desiredNextMs = 0;

    if (!force) {
        bool canonicalReady = (current.flags & STATE_FLAG_CANON_READY) != 0;
        uint64_t canonicalTick = current.canonical_ready_tick_ms;
        uint64_t settleBase = canonicalTick;
        if (current.helper_last_mutation_tick_ms > settleBase)
            settleBase = current.helper_last_mutation_tick_ms;
        if (mutationTick > settleBase)
            settleBase = mutationTick;

        if (!canonicalReady || canonicalTick == 0) {
            allowNow = false;
            gateReason = "canon";
        } else {
            uint64_t settleDeadline = settleBase ? (settleBase + retry.minSettleMs) : 0;
            if (settleDeadline && now < settleDeadline) {
                allowNow = false;
                gateReason = "settle";
                desiredNextMs = settleDeadline;
            }
        }

        uint64_t activityTick = std::max<uint64_t>(heartbeatTick, facetTick);
        if (allowNow) {
            if (activityTick == 0 || (settleBase && activityTick < settleBase)) {
                allowNow = false;
                gateReason = "signal";
                desiredNextMs = std::max<uint64_t>(desiredNextMs, now + std::max<uint32_t>(retry.debounceMs, 100u));
            }
        }

        if (allowNow) {
            bool autopStageAvailable = autopLimit > 0;
            bool beyondAutop = !autopStageAvailable || attemptsSoFar >= autopLimit;
            bool hasNewSignal = latestSignalTick != 0 && latestSignalTick > current.helper_last_signal_ms;

            if (attemptsSoFar >= retry.maxRetries) {
                allowNow = false;
                gateReason = "retry-max";
                passiveMode = true;
            } else if (beyondAutop) {
                passiveMode = true;
                if (hasNewSignal) {
                    allowNow = true;
                    signalConsumed = true;
                    logOverride = true;
                    overrideReason = "retry-max";
                } else {
                    allowNow = false;
                    gateReason = "passive";
                }
            } else if (hasNewSignal) {
                signalConsumed = true;
            }
        }

        if (!allowNow) {
            bool stageEligible = (stage == HelperInstallStage::WaitingForGlobalState ||
                                  stage == HelperInstallStage::ReadyToInstall);
            if (stageEligible && settleElapsed >= 2000 && engineCtxSnapshot && jitterToken) {
                if ((current.helper_flags & HELPER_FLAG_SETTLE_PROMOTED) == 0) {
                    allowNow = true;
                    passiveMode = false;
                    gateReason = nullptr;
                    logOverride = true;
                    overrideReason = "settle-budget";
                    promotionTriggered = true;
                    promotionElapsed = settleElapsed;
                }
            }
        }
    }

    if (allowNow && !(sbReadyNow || sbPivotNow || sbFallbackNow)) {
        allowNow = false;
        gateReason = "sendbuilder";
        desiredNextMs = std::max<uint64_t>(desiredNextMs, now + retry.retryBackoffMs);
    }

    if (sbDbMgrMode) {
        allowNow = true;
        passiveMode = false;
        gateReason = nullptr;
        desiredNextMs = 0;
        logOverride = true;
        overrideReason = "sb-ready";
    } else if (!allowNow && Core::Config::HelpersIgnoreGlobalSettleIfSbReady() && (sbReadyNow || sbPivotNow || sbFallbackNow)) {
        allowNow = true;
        passiveMode = false;
        gateReason = nullptr;
        logOverride = true;
        overrideReason = "sb-ready";
        const char* readyModeLabel = Net::ReadyModeString();
        if (!readyModeLabel || readyModeLabel[0] == '\0')
            readyModeLabel = sbPivotNow ? "pivot" : "scan";
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "[HOOKS] helpers forcing proceed: sb=ready(%s)",
                  readyModeLabel);
    }

    if (!allowNow) {
        g_helperProbeSkipped.fetch_add(1u, std::memory_order_relaxed);
        uint64_t backoff = HelperRetryDelay(retry, nextAttemptIndex);
        if (!passiveMode) {
            uint32_t delayMs = 0;
            if (attemptElapsed >= 2000) {
                delayMs = HelperBudgetBackoffMs(jitterToken ? jitterToken : target, now);
            } else {
                if (backoff == 0)
                    backoff = retry.debounceMs;
                delayMs = static_cast<uint32_t>(backoff);
                delayMs += HelperJitterMs(retry, target, now);
            }
            desiredNextMs = std::max<uint64_t>(desiredNextMs, now + delayMs);
        }

        bool shouldLogSkip = false;
        g_stateRegistry.UpdateByPointer(target, [&](LuaStateInfo& state) {
            if (!state.helper_first_attempt_ms)
                state.helper_first_attempt_ms = now;
            if (mutationTick > state.helper_last_mutation_tick_ms) {
                state.helper_last_mutation_tick_ms = mutationTick;
                state.helper_retry_count = 0;
                state.helper_first_attempt_ms = now;
            }
            if (passiveMode) {
                if (state.helper_passive_since_ms == 0)
                    state.helper_passive_since_ms = now;
            } else {
                state.helper_passive_since_ms = 0;
            }
            if (desiredNextMs != 0) {
                if (state.helper_next_retry_ms == 0 || state.helper_next_retry_ms < desiredNextMs)
                    state.helper_next_retry_ms = desiredNextMs;
            } else {
                state.helper_next_retry_ms = 0;
            }
            bool allowLog = (state.helper_next_skip_log_ms == 0) || now >= state.helper_next_skip_log_ms;
            if (allowLog) {
                uint32_t skipJitter = HelperRandomWindow(jitterToken ? jitterToken : target, now, 250u);
                state.helper_next_skip_log_ms = now + 1000u + skipJitter;
            }
            shouldLogSkip = allowLog;
            UpdateHelperStage(state,
                              HelperInstallStage::WaitingForGlobalState,
                              now,
                              gateReason ? gateReason : "not-ready");
        }, &current);
        ClearHelperPending(target, generation, &current);
        TrackHelperEvent(g_helperDeferredCount);
        MaybeEmitHelperSummary(now);

        if (logOverride && overrideReason) {
            Log::Logf(Log::Level::Info,
                      Log::Category::Hooks,
                      "helpers gating override L=%p reason=%s retries=%u action=%s",
                      target,
                      overrideReason,
                      static_cast<unsigned>(current.helper_retry_count),
                      action);
        }

        if (shouldLogSkip) {
            Log::Logf(Log::Level::Info,
                      Log::Category::Hooks,
                      "helpers skip L=%p reason=%s retries=%u next=%llu action=%s",
                      target,
                      gateReason ? gateReason : "not-ready",
                      static_cast<unsigned>(current.helper_retry_count),
                      static_cast<unsigned long long>(desiredNextMs),
                      action);
        }
        return;
    }

    const bool luaOk = (target != nullptr);
    const bool ctxOk = (current.ctx_reported != nullptr);
    if (!force && !(luaOk && ctxOk)) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "[HOOKS] helpers install-defer lua=%d ctx=%d",
                  luaOk ? 1 : 0,
                  ctxOk ? 1 : 0);
        TrackHelperEvent(g_helperDeferredCount);
        MaybeEmitHelperSummary(now);
        ClearHelperPending(target, generation, &current);
        return;
    }

    if (logOverride && overrideReason) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "helpers gating override L=%p reason=%s retries=%u action=%s",
                  target,
                  overrideReason,
                  static_cast<unsigned>(current.helper_retry_count),
                  action);
    }

    g_stateRegistry.UpdateByPointer(target, [&](LuaStateInfo& state) {
        state.flags |= STATE_FLAG_HELPERS_PENDING;
        state.helper_pending_generation = generation;
        state.helper_pending_tick_ms = now;
        if (!state.helper_first_attempt_ms)
            state.helper_first_attempt_ms = now;
        uint64_t localAttemptElapsed = (state.helper_first_attempt_ms && now >= state.helper_first_attempt_ms)
                                           ? (now - state.helper_first_attempt_ms)
                                           : 0;
        state.helper_last_attempt_ms = now;
        if (mutationTick > state.helper_last_mutation_tick_ms)
            state.helper_last_mutation_tick_ms = mutationTick;
        if (latestSignalTick != 0)
            state.helper_last_signal_ms = latestSignalTick;
        if (state.helper_retry_count < std::numeric_limits<uint32_t>::max())
            ++state.helper_retry_count;
        uint64_t backoff = HelperRetryDelay(retry, state.helper_retry_count);
        if (!passiveMode) {
            uint32_t delayMs = 0;
            if (promotionTriggered || localAttemptElapsed >= 2000) {
                delayMs = HelperBudgetBackoffMs(jitterToken ? jitterToken : target, now);
            } else {
                if (backoff == 0)
                    backoff = retry.debounceMs;
                delayMs = static_cast<uint32_t>(backoff);
                delayMs += HelperJitterMs(retry, target, now);
            }
            state.helper_next_retry_ms = now + delayMs;
            state.helper_passive_since_ms = 0;
        } else {
            state.helper_next_retry_ms = 0;
        }
        if (promotionTriggered) {
            state.helper_flags |= (HELPER_FLAG_SETTLE_PROMOTED | HELPER_FLAG_SETTLE_ARMED);
        } else {
            state.helper_flags &= ~HELPER_FLAG_SETTLE_ARMED;
        }
        UpdateHelperStage(state, HelperInstallStage::Installing, now, "schedule");
    }, &current);

    TrackHelperEvent(g_helperScheduledCount);
    MaybeEmitHelperSummary(now);

    if (promotionTriggered) {
        TrackHelperEvent(g_helperDeferredCount);
        MaybeEmitHelperSummary(now);
        RequestBindForState(current, "script-thread-wait", false);
    }

    const char* bindReason = promotionTriggered ? kSettlePromoteReason : action;
    DWORD owner = current.owner_tid ? current.owner_tid : g_scriptThreadId.load(std::memory_order_acquire);

    if (owner && owner == GetCurrentThreadId()) {
        BindHelpersTask(target, generation, force, bindReason);
    } else {
        std::string reasonCopy = bindReason;
        PostToOwnerWithTask(target, "helpers", [target, generation, force, reasonCopy]() {
            BindHelpersTask(target, generation, force, reasonCopy.c_str());
        });
    }
}

static bool CallLuaDebugPreference(lua_State* L, bool& resultOut, bool& successOut) {
    bool result = true;
    bool success = false;
    int status = 0;
    __try {
        status = lua_pcall(L, 0, 1, 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogLuaBind("debug-pref call seh=0x%08lX", GetExceptionCode());
        return false;
    }

    if (status == 0) {
        result = lua_toboolean(L, -1) != 0;
        success = true;
    } else {
        const char* err = lua_tolstring(L, -1, nullptr);
        LogLuaBind("debug-pref call error err=%s", err ? err : "<unknown>");
    }

    resultOut = result;
    successOut = success;
    return true;
}

static bool QueryClientDebugPreference(lua_State* L, LuaStateInfo& info, bool* outAllowed) {
    if (!L || !outAllowed)
        return false;
    LuaStackGuard guard(L, &info);
    int top = 0;
    DWORD topSeh = 0;
    if (!SafeLuaGetTop(L, info, &top, &topSeh))
        return false;

    int type = LUA_TNONE;
    const char* typeName = nullptr;
    DWORD funcSeh = 0;
    if (!SafeLuaGetGlobalType(L, "GetLoadLuaDebugLibrary", &type, &typeName, &funcSeh))
        return false;
    if (type != LUA_TFUNCTION)
        return false;

    bool result = true;
    bool success = false;
    if (!CallLuaDebugPreference(L, result, success))
        return false;

    if (success)
        *outAllowed = result;
    return success;
}

static void InstallPanicAndDebug(lua_State* L, LuaStateInfo& info) {
    if (!L)
        return;

    LuaStackGuard stackGuard(L, &info);
    g_stateRegistry.UpdateByPointer(L, [](LuaStateInfo&) {}, &info);

    if (!(info.flags & STATE_FLAG_VALID))
        return;

    MaybeAdoptOwnerThread(L, info);

    if (!IsOwnerThread(info)) {
        uint64_t now = GetTickCount64();
        if (now - info.last_bind_log_tick_ms >= kBindLogCooldownMs) {
            info.last_bind_log_tick_ms = now;
            LogLuaBind("bind-redirect Lc=%p owner=%lu current=%lu action=panic&debug",
                       L,
                       info.owner_tid,
                       static_cast<unsigned long>(GetCurrentThreadId()));
            g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
                state.last_bind_log_tick_ms = now;
            }, &info);
        }
        PostToOwnerWithTask(L, "panic&debug", [L]() {
            LuaStateInfo refreshed{};
            if (g_stateRegistry.GetByPointer(L, refreshed))
                InstallPanicAndDebug(L, refreshed);
        });
        return;
    }

    const bool debugEnabled = DebugInstrumentationEnabled();
    const bool installEnv = DebugInstallEnvEnabled();
    bool clientAllowsDebug = true;
    bool clientPrefKnown = true;
    if (debugEnabled && installEnv)
        clientPrefKnown = QueryClientDebugPreference(L, info, &clientAllowsDebug);
    const bool allowDebug = debugEnabled && installEnv && clientAllowsDebug;

    LogLuaBind("hooks-install begin Lc=%p allowDebug=%d debugEnv=%d installEnv=%d clientPref=%d sentinelRef=%d flags=0x%08X",
               L,
               allowDebug ? 1 : 0,
               debugEnabled ? 1 : 0,
               installEnv ? 1 : 0,
               clientAllowsDebug ? 1 : 0,
               info.gc_sentinel_ref,
               info.flags);

    if (!allowDebug) {
        if (debugEnabled && installEnv && clientPrefKnown && !clientAllowsDebug)
            LogLuaBind("hooks-install skip-client-pref Lc=%p", L);
        ClearDebugInstallRetry(L);
        g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
            state.debug_status = 0;
            state.debug_status_gen = state.gen;
            state.flags &= ~STATE_FLAG_DEBUG_OK;
            state.flags |= STATE_FLAG_DEBUG_MISS;
        }, &info);
        return;
    }

    const char* stabilityReason = nullptr;
    if (!IsStateStableForInstall(info, L, &stabilityReason)) {
        MaybeLogInstallDefer(L, stabilityReason);
        LogLuaBind("hooks-install skip-unstable Lc=%p reason=%s",
                   L,
                   stabilityReason ? stabilityReason : "unknown");
        ScheduleDebugInstallRetry(L);
        return;
    }
    MaybeLogInstallStable(L);
    LogLuaBind("hooks-install proceed Lc=%p tid=%lu gen=%llu flags=0x%08X",
               L,
               static_cast<unsigned long>(GetCurrentThreadId()),
               static_cast<unsigned long long>(info.gen),
               info.flags);

    if (!safe_probe_stack_roundtrip(L, info)) {
        NoteGuardFailure(Engine::Lua::GetLastLuaGuardFailure());
        LogLuaBind("hooks-install skip-unstable Lc=%p reason=probe-failed", L);
        ScheduleDebugInstallRetry(L);
        return;
    }

    auto topRes = safe_lua_gettop(L, info);
    if (!topRes.ok) {
        NoteGuardFailure(Engine::Lua::GetLastLuaGuardFailure());
        LogLuaBind("hooks-install skip-unstable Lc=%p reason=top-unavailable", L);
        ScheduleDebugInstallRetry(L);
        return;
    }
    LogLuaBind("lua-top op=gettop top=%d", topRes.top);

    DWORD panicSeh = 0;
    bool panicChanged = false;
    Log::Logf(Log::Level::Info,
              Log::Category::Hooks,
              "[HOOKS][step] name=panic_hook phase=pre");
    bool panicOk = EnsurePanicHookOnOwner(L, info, &panicChanged, &panicSeh);
    Log::Logf(Log::Level::Info,
              Log::Category::Hooks,
              "[HOOKS][step] name=panic_hook phase=post ok=%d",
              panicOk ? 1 : 0);

    bool sentinelCreated = false;
    DWORD sentinelSeh = 0;
    bool sentinelOk = true;
    bool sentinelAttempted = false;
    bool sentinelSkip = false;
    bool sentinelMarkedFailed = false;
    const char* sentinelSkipReason = nullptr;
    bool sentinelSoftFail = false;
    const char* sentinelFailureReason = nullptr;
    const uint64_t nowTick = GetDebugTickNow();
    DebugInstallRetryInfo pendingRetry{};
    Log::Logf(Log::Level::Info,
              Log::Category::Hooks,
              "[HOOKS][step] name=sentinel phase=pre");
    bool sentinelRetryPending = false;
    uint64_t retryRemaining = 0;
    if (IsDebugInstallRetryPending(L, nowTick, &pendingRetry) && pendingRetry.generation == info.gen) {
        sentinelRetryPending = true;
        if (pendingRetry.dueTick > nowTick)
            retryRemaining = pendingRetry.dueTick - nowTick;
    }

    const bool sentinelPrevFailed = (info.gc_sentinel_ref == -2 && info.gc_sentinel_gen == info.gen);
    const bool sentinelInstalled = (info.gc_sentinel_ref == 1 && info.gc_sentinel_gen == info.gen);
    lua_State* canonical = g_canonicalState.load(std::memory_order_acquire);

    if (sentinelInstalled) {
        sentinelOk = true;
    } else if (sentinelPrevFailed) {
        sentinelSkip = true;
        sentinelOk = false;
        sentinelSkipReason = "prev-failed";
    } else if (sentinelRetryPending) {
        sentinelSkip = true;
        sentinelSkipReason = "retry-pending";
    } else if (!(info.L_canonical && info.L_canonical == L)) {
        sentinelSkip = true;
        sentinelSkipReason = "non-canonical";
    } else if (!(canonical && canonical == L)) {
        sentinelSkip = true;
        sentinelSkipReason = "canonical-mismatch";
    } else {
        DebugInstallGuard guard(L);
        LogLuaBind("hooks-install guard-check Lc=%p tid=%lu acquired=%d flags=0x%08X",
                   L,
                   static_cast<unsigned long>(GetCurrentThreadId()),
                   guard.acquired() ? 1 : 0,
                   info.flags);
        if (!guard.acquired()) {
            sentinelSkip = true;
            sentinelSkipReason = "install-inflight";
            LogLuaBind("hooks-install sentinel-guard-skip Lc=%p tid=%lu reason=%s",
                       L,
                       static_cast<unsigned long>(GetCurrentThreadId()),
                       sentinelSkipReason);
        } else {
            sentinelAttempted = true;
            sentinelOk = EnsureHookSentinelGuarded(L, info, &sentinelCreated, &sentinelSeh, &sentinelSoftFail);
            if (sentinelOk) {
                g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
                    state.gc_sentinel_ref = 1;
                    state.gc_sentinel_gen = state.gen;
                }, &info);
            } else if (sentinelSoftFail) {
                sentinelFailureReason = "check-stack";
                ScheduleDebugInstallRetry(L);
            } else {
                g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
                    state.gc_sentinel_ref = -2;
                    state.gc_sentinel_gen = state.gen;
                }, &info);
                sentinelMarkedFailed = true;
                sentinelFailureReason = "install-failed";
            }
        }
    }

    if (!sentinelAttempted && sentinelSkip && !sentinelInstalled && !sentinelPrevFailed) {
        if (sentinelRetryPending) {
            LogLuaBind("hooks-install sentinel-defer Lc=%p reason=%s remaining=%llu",
                       L,
                       sentinelSkipReason ? sentinelSkipReason : "unknown",
                       static_cast<unsigned long long>(retryRemaining));
        } else {
            LogLuaBind("hooks-install sentinel-defer Lc=%p reason=%s",
                       L,
                       sentinelSkipReason ? sentinelSkipReason : "unknown");
            ScheduleDebugInstallRetry(L);
        }
    }

    int sentinelPhaseOk = 0;
    if (sentinelAttempted)
        sentinelPhaseOk = sentinelOk ? 1 : 0;
    else if (sentinelInstalled)
        sentinelPhaseOk = 1;
    Log::Logf(Log::Level::Info,
              Log::Category::Hooks,
              "[HOOKS][step] name=sentinel phase=post ok=%d",
              sentinelPhaseOk);

    const bool sentinelSatisfied = sentinelInstalled ||
                                   (sentinelAttempted && sentinelOk) ||
                                   sentinelPrevFailed ||
                                   sentinelMarkedFailed;
    if (sentinelSatisfied) {
        ClearDebugInstallRetry(L);
    }

    bool shouldLog = sentinelCreated || panicChanged;
    if (!panicOk && panicSeh != 0)
        shouldLog = true;
    if (sentinelAttempted && !sentinelOk)
        shouldLog = true;
    if (sentinelSkip && debugEnabled)
        shouldLog = true;

    if (shouldLog) {
        LuaStateInfo latest{};
        if (!g_stateRegistry.GetByPointer(L, latest))
            latest = info;
        const char* debugState = (latest.debug_status == 1) ? "on" : "off";
        if (!sentinelAttempted) {
            if (sentinelSkip) {
                if (sentinelRetryPending) {
                    LogLuaBind("hooks-install Lc=%p panic=%s debug=%s sentinel=skip reason=%s remaining=%llu",
                               L,
                               panicOk ? "ok" : "fail",
                               debugState,
                               sentinelSkipReason ? sentinelSkipReason : "unknown",
                               static_cast<unsigned long long>(retryRemaining));
                } else {
                    LogLuaBind("hooks-install Lc=%p panic=%s debug=%s sentinel=skip reason=%s",
                               L,
                               panicOk ? "ok" : "fail",
                               debugState,
                               sentinelSkipReason ? sentinelSkipReason : "unknown");
                }
            } else {
                LogLuaBind("hooks-install Lc=%p panic=%s debug=%s sentinel=present",
                           L,
                           panicOk ? "ok" : "fail",
                           debugState);
            }
        } else if (!sentinelOk && sentinelSoftFail) {
            LogLuaBind("hooks-install Lc=%p panic=%s debug=%s sentinel=soft-fail reason=%s",
                       L,
                       panicOk ? "ok" : "fail",
                       debugState,
                       sentinelFailureReason ? sentinelFailureReason : "unknown");
        } else if (!sentinelOk && sentinelSeh) {
            LogLuaBind("hooks-install Lc=%p panic=%s debug=%s sentinel=fail seh=0x%08lX",
                       L,
                       panicOk ? "ok" : "fail",
                       debugState,
                       sentinelSeh);
        } else if (!sentinelOk) {
            LogLuaBind("hooks-install Lc=%p panic=%s debug=%s sentinel=fail",
                       L,
                       panicOk ? "ok" : "fail",
                       debugState);
        } else if (!panicOk && panicSeh) {
            LogLuaBind("hooks-install Lc=%p panic=fail debug=%s seh=0x%08lX",
                       L,
                       debugState,
                       panicSeh);
        } else {
            LogLuaBind("hooks-install Lc=%p panic=%s debug=%s",
                       L,
                       panicOk ? "ok" : "fail",
                       debugState);
        }
    }
}

static int CallClientRegister(void* ctx, lua_CFunction fn, const char* safeName, DWORD* outSeh) noexcept {
    if (!g_clientRegister || !fn || !safeName || !ctx) {
        if (outSeh)
            *outSeh = 0;
        return 0;
    }
    DWORD seh = 0;
    int rc = 0;
    __try {
        rc = g_clientRegister(ctx, reinterpret_cast<void*>(fn), safeName);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        seh = GetExceptionCode();
        rc = 0;
    }
    if (outSeh)
        *outSeh = seh;
    return rc;
}

static bool TryLuaSetGlobal(lua_State* L, lua_CFunction fn, const char* name, DWORD* outSeh) noexcept {
    if (!L || !fn || !name || name[0] == '\0')
        return false;
    const DWORD tid = GetCurrentThreadId();
    int topBefore = 0;
    DWORD topSeh = 0;
    bool topOk = SafeLuaGetTop(L, &topBefore, &topSeh);
    DWORD pushSeh = 0;
    DWORD setSeh = 0;
    bool pushOk = false;
    bool setOk = false;
    __try {
        lua_pushcfunction(L, fn);
        pushOk = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        pushSeh = GetExceptionCode();
        pushOk = false;
    }
    if (pushOk) {
        __try {
            lua_setglobal(L, name);
            setOk = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            setSeh = GetExceptionCode();
            setOk = false;
        }
    }
    if (!(pushOk && setOk)) {
        char fnModule[64] = {};
        void* fnModuleBase = nullptr;
        DWORD fnProtect = 0;
        DescribeAddressForLog(reinterpret_cast<const void*>(fn), fnModule, ARRAYSIZE(fnModule), &fnModuleBase, &fnProtect);
        char stateModule[64] = {};
        void* stateModuleBase = nullptr;
        DWORD stateProtect = 0;
        DescribeAddressForLog(L, stateModule, ARRAYSIZE(stateModule), &stateModuleBase, &stateProtect);
        Log::Logf(Log::Level::Warn,
                  Log::Category::Hooks,
                  "[HOOKS] helper-register lua_setglobal failed name=%s tid=%lu L=%p Lmod=%s Lprot=0x%08lX fn=%p fnMod=%s fnProt=0x%08lX okTop=%d top=%d topSeh=0x%08lX pushOk=%d pushSeh=0x%08lX setOk=%d setSeh=0x%08lX",
                  name,
                  static_cast<unsigned long>(tid),
                  L,
                  stateModule[0] ? stateModule : "<unk>",
                  static_cast<unsigned long>(stateProtect),
                  reinterpret_cast<void*>(fn),
                  fnModule[0] ? fnModule : "<unk>",
                  static_cast<unsigned long>(fnProtect),
                  topOk ? 1 : 0,
                  topBefore,
                  static_cast<unsigned long>(topSeh),
                  pushOk ? 1 : 0,
                  static_cast<unsigned long>(pushSeh),
                  setOk ? 1 : 0,
                  static_cast<unsigned long>(setSeh));
    }
    if (outSeh)
        *outSeh = pushOk ? setSeh : pushSeh;
    return pushOk && setOk;
}

static WORD HelperFlagForName(const char* name) {
    if (!name)
        return 0;
    if (_stricmp(name, kHelperWalkName) == 0)
        return HELPER_FLAG_WALK;
    if (_stricmp(name, kHelperWalkMoveName) == 0)
        return HELPER_FLAG_WALK_MOVE;
    if (_stricmp(name, kHelperGetPacingName) == 0)
        return HELPER_FLAG_GET_PACING;
    if (_stricmp(name, kHelperSetPacingName) == 0)
        return HELPER_FLAG_SET_PACING;
    if (_stricmp(name, kHelperSetInflightName) == 0)
        return HELPER_FLAG_SET_INFLIGHT;
    if (_stricmp(name, kHelperGetWalkMetricsName) == 0)
        return HELPER_FLAG_GET_METRICS;
    if (_stricmp(name, kHelperStatusFlagsName) == 0 || _stricmp(name, kHelperStatusFlagsAliasName) == 0)
        return HELPER_FLAG_STATUS_FLAGS;
    if (_stricmp(name, kHelperTestRetName) == 0)
        return HELPER_FLAG_STATUS_FLAGS;
    if (_stricmp(name, kHelperDumpName) == 0)
        return HELPER_FLAG_DUMP;
    if (_stricmp(name, kHelperInspectName) == 0)
        return HELPER_FLAG_INSPECT;
    if (_stricmp(name, kHelperRebindName) == 0)
        return HELPER_FLAG_REBIND;
    if (_stricmp(name, kHelperSelfTestName) == 0)
        return HELPER_FLAG_SELFTEST;
    if (_stricmp(name, kHelperDebugName) == 0)
        return HELPER_FLAG_DEBUG;
    if (_stricmp(name, kHelperDebugStatusName) == 0)
        return HELPER_FLAG_DEBUG_STATUS;
    if (_stricmp(name, kHelperDebugPingName) == 0)
        return HELPER_FLAG_DEBUG_PING;
    return 0;
}

static int WaitForDispatchResult(std::atomic<int>& outcome, DWORD timeoutMs) {
    if (timeoutMs == 0)
        timeoutMs = 100;
    const DWORD deadline = GetTickCount() + timeoutMs;
    for (;;) {
        int value = outcome.load(std::memory_order_acquire);
        if (value != 0)
            return value;
        if (static_cast<LONG>(deadline - GetTickCount()) <= 0)
            break;
        Sleep(1);
    }
    return outcome.load(std::memory_order_acquire);
}

static bool DoRegisterHelperOnScriptThread(lua_State* ownerState,
                                           lua_State* target,
                                           LuaStateInfo info,
                                           const char* name,
                                           lua_CFunction fn,
                                           uint64_t generation,
                                           bool allowForeignThread = false) {
    const char* safeName = (name && name[0] != '\0') ? name : "<null>";
    lua_State* state = target ? target : ownerState;
    if (!state || !fn) {
        Log::Logf(Log::Level::Warn,
                  Log::Category::Hooks,
                  "[HOOKS] helper-register abort name=%s reason=state-or-fn-null state=%p",
                  safeName,
                  state);
        return false;
    }

    const DWORD currentTid = GetCurrentThreadId();
    if (!allowForeignThread) {
        EnsureScriptThread(currentTid, state);
    } else {
        DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
        if (scriptTid == 0 || scriptTid == currentTid) {
            EnsureScriptThread(currentTid, state);
        } else {
            Log::Logf(Log::Level::Info,
                      Log::Category::Hooks,
                      "[HOOKS] helper-register foreign-thread name=%s tid=%lu scriptTid=%lu (skip-ensure) L=%p",
                      safeName,
                      static_cast<unsigned long>(currentTid),
                      static_cast<unsigned long>(scriptTid),
                      state);
        }
    }

    LuaStateInfo latest = info;
    if (!g_stateRegistry.GetByPointer(state, latest)) {
        if (target && target != state)
            g_stateRegistry.GetByPointer(target, latest);
    }

    WORD flag = HelperFlagForName(name);
    if (flag == 0) {
        Log::Logf(Log::Level::Warn,
                  Log::Category::Hooks,
                  "[HOOKS] helper-register abort name=%s reason=unknown-helper",
                  safeName);
        return false;
    }

    const GlobalStateInfo* globalInfo = Engine::Info();
    void* ctx = nullptr;
    if (globalInfo && globalInfo->scriptContext) {
        ctx = globalInfo->scriptContext;
    }

    auto validateCtx = [&](void*& candidate, const char* source) {
        if (candidate && !IsValidCtx(static_cast<HCTX>(candidate))) {
            Log::Logf(Log::Level::Info,
                      Log::Category::Hooks,
                      "[HOOKS] helper-register ctx-invalid source=%s ptr=%p",
                      source ? source : "?",
                      candidate);
            candidate = nullptr;
        }
    };
    validateCtx(ctx, "global-script");
    if (!ctx) {
        ctx = g_latestScriptCtx.load(std::memory_order_acquire);
        validateCtx(ctx, "latest-script");
    }
    if (!ctx) {
        ctx = latest.ctx_reported;
        validateCtx(ctx, "reported");
    }
    if (!ctx) {
        ctx = GetCanonicalHelperCtx();
        validateCtx(ctx, "canonical");
    }
    if (!ctx) {
        ctx = ResolveCanonicalEngineContext();
        validateCtx(ctx, "resolved");
    }

    if (ctx && latest.ctx_reported != ctx) {
        g_stateRegistry.UpdateByPointer(state, [&](LuaStateInfo& stateRef) {
            stateRef.ctx_reported = ctx;
        }, &latest);
    }

    DWORD ownerTid = latest.owner_tid ? latest.owner_tid : GetCurrentThreadId();
    void* clientFn = reinterpret_cast<void*>(g_clientRegister);

    Log::Logf(Log::Level::Info,
              Log::Category::Hooks,
              "[HOOKS] helper-register begin name=%s L=%p ctx=%p owner=%lu gen=%llu clientFn=%p",
              safeName,
              state,
              ctx,
              static_cast<unsigned long>(ownerTid),
              static_cast<unsigned long long>(generation),
              clientFn);

    bool clientAttempted = false;
    bool clientOk = false;
    int clientRc = 0;
    DWORD clientSeh = 0;

    if (g_clientRegister && ctx) {
        clientAttempted = true;
        clientRc = CallClientRegister(ctx, fn, safeName, &clientSeh);
        clientOk = (clientRc != 0);
        Log::Logf(clientOk ? Log::Level::Info : Log::Level::Warn,
                  Log::Category::Hooks,
                  "[HOOKS] helper-register client name=%s ok=%d rc=%d seh=0x%08lX",
                  safeName,
                  clientOk ? 1 : 0,
                  clientRc,
                  static_cast<unsigned long>(clientSeh));
    } else {
        const char* reason = g_clientRegister ? "ctx-null" : "client-missing";
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "[HOOKS] helper-register client-skip name=%s reason=%s",
                  safeName,
                  reason);
    }

    bool fallbackOk = false;
    DWORD fallbackSeh = 0;
    if (!clientOk) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "[HOOKS] helper-register fallback name=%s",
                  safeName);

        int topBefore = 0;
        bool topCaptured = SafeLuaGetTop(state, latest, &topBefore, &fallbackSeh);
        if (!topCaptured) {
            Log::Logf(Log::Level::Warn,
                      Log::Category::Hooks,
                      "[HOOKS] helper-register fallback-abort name=%s reason=gettop-failed seh=0x%08lX",
                      safeName,
                      static_cast<unsigned long>(fallbackSeh));
        } else if (!name || name[0] == '\0') {
            Log::Logf(Log::Level::Warn,
                      Log::Category::Hooks,
                      "[HOOKS] helper-register fallback-abort name=%s reason=name-empty",
                      safeName);
        } else {
            fallbackOk = TryLuaSetGlobal(state, fn, name, &fallbackSeh);
        }

        if (topCaptured) {
            DWORD restoreSeh = 0;
            if (!SafeLuaSetTop(state, latest, topBefore, &restoreSeh)) {
                Log::Logf(Log::Level::Warn,
                          Log::Category::Hooks,
                          "[HOOKS] helper-register fallback-restore name=%s seh=0x%08lX",
                          safeName,
                          static_cast<unsigned long>(restoreSeh));
            }
        }

        Log::Logf(fallbackOk ? Log::Level::Info : Log::Level::Warn,
                  Log::Category::Hooks,
                  "[HOOKS] helper-register fallback-result name=%s ok=%d seh=0x%08lX",
                  safeName,
                  fallbackOk ? 1 : 0,
                  static_cast<unsigned long>(fallbackSeh));
    }

    bool success = clientOk || fallbackOk;
    if (success) {
        uint64_t now = GetTickCount64();
        auto updater = [&](LuaStateInfo& stateRef) {
            stateRef.helper_flags |= flag;
            stateRef.gen = generation;
            stateRef.helper_last_attempt_ms = now;
            stateRef.helper_last_mutation_tick_ms = g_lastContextMutationTick.load(std::memory_order_acquire);
            if (!stateRef.ctx_reported && ctx)
                stateRef.ctx_reported = ctx;
        };
        if (!g_stateRegistry.UpdateByPointer(state, updater, &latest) && ownerState && ownerState != state) {
            g_stateRegistry.UpdateByPointer(ownerState, updater, &latest);
        }
    }

    Log::Logf(success ? Log::Level::Info : Log::Level::Warn,
              Log::Category::Hooks,
              "[HOOKS] helper-register %s name=%s client=%d fallback=%d flags=0x%04X",
              success ? "done" : "failed",
              safeName,
              clientOk ? 1 : 0,
              fallbackOk ? 1 : 0,
              latest.helper_flags);

    if (success && name) {
        if (_stricmp(name, kHelperStatusFlagsName) == 0) {
            StoreRealStatusFlags(state);
            lua_pushcfunction(state, Lua_UOW_StatusFlagsShim);
            lua_setglobal(state, kHelperStatusFlagsName);
            LogGlobalFn(state, kHelperStatusFlagsName);
        } else if (_stricmp(name, kHelperStatusFlagsAliasName) == 0) {
            StoreRealStatusFlagsEx(state);
            lua_pushcfunction(state, Lua_UOW_StatusFlagsExShim);
            lua_setglobal(state, kHelperStatusFlagsAliasName);
            LogGlobalFn(state, kHelperStatusFlagsAliasName);
            LogGlobalFn(state, kHelperStatusFlagsName);
        } else if (_stricmp(name, kHelperTestRetName) == 0) {
            LogGlobalFn(state, kHelperTestRetName);
        }
    }

    return success;
}

static bool ScriptThreadRegisterHelper(lua_State* ownerState,
                                       lua_State* target,
                                       LuaStateInfo info,
                                       const char* name,
                                       lua_CFunction fn,
                                       uint64_t generation) {
    DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
    if (scriptTid == 0)
        return false;

    lua_State* scriptState = ownerState ? ownerState : g_mainLuaState.load(std::memory_order_acquire);
    if (!scriptState)
        scriptState = target;
    if (!scriptState)
        return false;

    if (GetCurrentThreadId() == scriptTid)
        return DoRegisterHelperOnScriptThread(scriptState, target, info, name, fn, generation);

    std::string dispatchTag = "helper-register";
    if (name && name[0] != '\0') {
        dispatchTag.push_back(':');
        dispatchTag.append(name);
    }

    std::string nameCopy = (name && name[0] != '\0') ? name : "";
    constexpr std::size_t kMaxDispatchAttempts = 6;

    for (std::size_t attempt = 0; attempt < kMaxDispatchAttempts; ++attempt) {
        std::atomic<int> outcome{0};
        bool dispatched = Core::Bind::DispatchWithFallback(
            scriptTid,
            [scriptTid, scriptState, target, info, nameCopy, fn, generation, &outcome]() mutable {
                DWORD currentTid = GetCurrentThreadId();
                if (currentTid != scriptTid) {
                    outcome.store(2, std::memory_order_release);
                    return;
                }

                const char* runName = nameCopy.empty() ? nullptr : nameCopy.c_str();
                bool ok = DoRegisterHelperOnScriptThread(scriptState,
                                                         target,
                                                         info,
                                                         runName,
                                                         fn,
                                                         generation,
                                                         false);
                outcome.store(ok ? 1 : -1, std::memory_order_release);
            },
            dispatchTag.c_str());

        if (!dispatched) {
            Log::Logf(Log::Level::Warn,
                      Log::Category::Hooks,
                      "[HOOKS] helper-register dispatch-failed name=%s scriptTid=%u",
                      name ? name : "<null>",
                      static_cast<unsigned>(scriptTid));
            return false;
        }

        int result = WaitForDispatchResult(outcome, 200);
        if (result == 1)
            return true;
        if (result == -1)
            return false;

        Sleep(10 + static_cast<DWORD>((attempt + 1) * 7));
    }

    Log::Logf(Log::Level::Warn,
              Log::Category::Hooks,
              "[HOOKS] helper-register dispatch exhausted name=%s scriptTid=%u",
              name ? name : "<null>",
              static_cast<unsigned>(scriptTid));
    return false;
}

static bool RegisterHelper(lua_State* L, const LuaStateInfo& info, const char* name, lua_CFunction fn, uint64_t generation) {
    const char* safeName = name ? name : "<null>";
    const bool allowFlagless = (name && _stricmp(name, kHelperTestRetName) == 0);
    WORD flag = HelperFlagForName(name);
    if (flag == 0 && !allowFlagless) {
        Log::Logf(Log::Level::Warn,
                  Log::Category::Hooks,
                  "[HOOKS] helper-register abort name=%s reason=unknown-helper",
                  safeName);
        return false;
    }

    lua_State* scriptState = g_mainLuaState.load(std::memory_order_acquire);
    DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
    if (!scriptState || scriptTid == 0) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "[HOOKS] helper-register defer name=%s reason=script-thread-missing L=%p ctx=%p scriptTid=%lu scriptState=%p",
                  safeName,
                  L,
                  info.ctx_reported,
                  static_cast<unsigned long>(scriptTid),
                  scriptState);
        return false;
    }

    lua_State* ownerState = scriptState ? scriptState : L;
    (void)ScriptThreadRegisterHelper(ownerState, L, info, name, fn, generation);

    ProcessPendingLuaTasks(scriptState);

    LuaStateInfo latest{};
    bool haveLatest = g_stateRegistry.GetByPointer(L, latest);
   if (!haveLatest && scriptState && scriptState != L)
       haveLatest = g_stateRegistry.GetByPointer(scriptState, latest);
   if (!haveLatest)
       latest = info;

    bool installed = allowFlagless ? false : ((latest.helper_flags & flag) != 0);

    if (!installed) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "[HOOKS] helper-register pending name=%s; attempting inline fallback",
                  safeName);
        if (DoRegisterHelperOnScriptThread(scriptState,
                                           L,
                                           info,
                                           name,
                                           fn,
                                           generation,
                                           /*allowForeignThread*/ true)) {
            LuaStateInfo refreshed{};
            if (g_stateRegistry.GetByPointer(L, refreshed) ||
                (scriptState != L && g_stateRegistry.GetByPointer(scriptState, refreshed)))
                latest = refreshed;
            installed = allowFlagless ? true : ((latest.helper_flags & flag) != 0);
            Log::Logf(installed ? Log::Level::Info : Log::Level::Warn,
                      Log::Category::Hooks,
                      "[HOOKS] helper-register inline-fallback name=%s ok=%d flags=0x%04X",
                      safeName,
                      installed ? 1 : 0,
                      latest.helper_flags);
        } else {
            Log::Logf(Log::Level::Warn,
                      Log::Category::Hooks,
                      "[HOOKS] helper-register inline-fallback failed name=%s",
                      safeName);
        }
    }

    Log::Logf(installed ? Log::Level::Info : Log::Level::Warn,
              Log::Category::Hooks,
              "[HOOKS] helper-register %s name=%s flags=0x%04X",
              installed ? "ok" : "pending",
              safeName,
              latest.helper_flags);
    return installed;
}

static bool BindHelpersOnThread(lua_State* L,
                                const LuaStateInfo& originalInfo,
                                uint64_t generation,
                                bool force,
                                HelperInstallMetrics* metrics,
                                const char* installTag,
                                bool sbReadyNow,
                                bool sbPivotNow,
                                bool sbFallbackNow) {
    if (!L)
        return false;

    LuaStateInfo info = originalInfo;

    const char* tagLabel = (installTag && installTag[0] != '\0') ? installTag : "unknown";
    const bool luaOk = (info.L_canonical != nullptr);
    const bool ctxOk = (info.ctx_reported != nullptr);
    const bool sbReady = sbReadyNow;
    const bool sbPivot = sbPivotNow;
    const bool sbFallback = sbFallbackNow;

    Log::Logf(Log::Level::Info,
              Log::Category::Hooks,
              "[HOOKS] helpers install-begin tag=%s mode=%s tid=%u lua=%d ctx=%d sb_ready=%d sb_pivot=%d sb_fallback=%d",
              tagLabel,
              Net::ReadyModeString(),
              static_cast<unsigned>(GetCurrentThreadId()),
              luaOk ? 1 : 0,
              ctxOk ? 1 : 0,
              sbReady ? 1 : 0,
              sbPivot ? 1 : 0,
              sbFallback ? 1 : 0);

    MaybeAdoptOwnerThread(L, info);

    DWORD scriptThreadId = g_scriptThreadId.load(std::memory_order_acquire);
    DWORD desiredOwner = info.owner_tid;
    if (scriptThreadId != 0)
        desiredOwner = scriptThreadId;
    if (desiredOwner == 0)
        desiredOwner = GetCurrentThreadId();
    if (info.owner_tid != desiredOwner) {
        uint64_t adoptTick = GetTickCount64();
        g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
            state.owner_tid = desiredOwner;
            state.last_tid = desiredOwner;
            if ((state.flags & STATE_FLAG_OWNER_READY) == 0 || state.owner_ready_tick_ms == 0)
                state.owner_ready_tick_ms = adoptTick;
            state.flags |= STATE_FLAG_OWNER_READY;
        }, &info);
        info.owner_tid = desiredOwner;
    }

    DWORD currentScriptTid = g_scriptThreadId.load(std::memory_order_acquire);
    lua_State* currentScriptState = g_mainLuaState.load(std::memory_order_acquire);
    if (currentScriptTid == 0 || !currentScriptState) {
        uint64_t nowTick = GetTickCount64();
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "[HOOKS] helpers defer L=%p reason=script-thread-wait owner=%lu scriptTid=%lu scriptState=%p",
                  L,
                  static_cast<unsigned long>(info.owner_tid),
                  static_cast<unsigned long>(currentScriptTid),
                  currentScriptState);
        TrackHelperEvent(g_helperDeferredCount);
        MaybeEmitHelperSummary(nowTick);
        ClearHelperPending(L, generation, &info);
        RequestBindForState(info, "script-thread-wait", false);
        return false;
    }

    Net::SendBuilderStatus bindStatusSnapshot = Net::GetSendBuilderStatus();
    Net::ReadyMode helperReadyMode = bindStatusSnapshot.ready ? bindStatusSnapshot.readyMode : Net::ReadyMode::None;
    const GlobalStateInfo* globalInfo = Engine::Info();
    void* scriptCtx = globalInfo ? globalInfo->scriptContext : nullptr;
    void* engineCtx = globalInfo ? globalInfo->engineContext : nullptr;
    void* dbMgrCtx = globalInfo ? globalInfo->databaseManager : nullptr;

    void* bindCtx = info.ctx_reported;
    const char* bindTargetLabel = "reported";

    if (helperReadyMode == Net::ReadyMode::DbMgr && dbMgrCtx) {
        bindCtx = dbMgrCtx;
        bindTargetLabel = "dbmgr";
    } else if (scriptCtx) {
        bindCtx = scriptCtx;
        bindTargetLabel = "script";
    } else if (engineCtx) {
        bindCtx = engineCtx;
        bindTargetLabel = "engine";
    } else if (!bindCtx) {
        bindTargetLabel = "none";
    }

    if (bindCtx && info.ctx_reported != bindCtx) {
        g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
            state.ctx_reported = bindCtx;
        }, &info);
        info.ctx_reported = bindCtx;
    }

    DWORD ownerHint = info.owner_tid ? info.owner_tid : GetCurrentThreadId();
    if (bindCtx) {
        SetCanonicalHelperCtx(bindCtx, ownerHint);
    }

    CtxValidationResult bindCtxStatus = ValidateCtxLoose(bindCtx);
    void* bindVtable = nullptr;
    if (bindCtx && bindCtxStatus == CtxValidationResult::Ok && sp::is_readable(bindCtx, sizeof(void*))) {
        std::memcpy(&bindVtable, bindCtx, sizeof(void*));
    }

    Log::Logf(Log::Level::Info,
              Log::Category::Hooks,
              "[HOOKS] helpers bind target=%s ctx=%p vtbl=%p status=%s",
              bindTargetLabel,
              bindCtx,
              bindVtable,
              DescribeCtxValidation(bindCtxStatus));

    HCTX canonicalCtx = nullptr;
    DWORD canonicalOwner = 0;
    bool canonicalValid = false;
    CtxValidationResult canonicalStatus = CtxValidationResult::Null;
    auto refreshCanonical = [&]() {
        canonicalCtx = GetCanonicalHelperCtx();
        canonicalOwner = GetCanonicalHelperOwnerTid();
        canonicalStatus = ValidateCtxLoose(canonicalCtx);
        canonicalValid = (canonicalStatus == CtxValidationResult::Ok);
    };
    refreshCanonical();

    static void* s_lastRebindCtx = nullptr;

    CtxValidationResult reportedCtxStatus = ValidateCtxLoose(info.ctx_reported);
    if (info.ctx_reported && reportedCtxStatus != CtxValidationResult::Ok) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "[HOOKS] ctx validation result=%s ctx=%p L=%p owner=%lu",
                  DescribeCtxValidation(reportedCtxStatus),
                  info.ctx_reported,
                  L,
                  static_cast<unsigned long>(info.owner_tid));
    }

    if (!canonicalValid && reportedCtxStatus == CtxValidationResult::Ok && info.ctx_reported) {
        SetCanonicalHelperCtx(info.ctx_reported, info.owner_tid);
        refreshCanonical();
        canonicalStatus = ValidateCtxLoose(canonicalCtx);
        canonicalValid = (canonicalStatus == CtxValidationResult::Ok);
    }

    if (canonicalCtx && canonicalStatus != CtxValidationResult::Ok) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "[HOOKS] canonical ctx pending validation=%s ctx=%p owner=%lu",
                  DescribeCtxValidation(canonicalStatus),
                  canonicalCtx,
                  static_cast<unsigned long>(canonicalOwner));
    }

    auto rebindToCanonical = [&](HCTX previousCtx, const char* reason) {
        refreshCanonical();

        if (!canonicalCtx)
            return;

        bool ctxChanged = (canonicalCtx != previousCtx);
        if (!ctxChanged && canonicalCtx == s_lastRebindCtx)
            return;

        uint64_t nowTick = GetTickCount64();
        g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
            state.ctx_reported = canonicalCtx;
            state.helper_passive_since_ms = 0;
            state.helper_rebind_attempts = 0;
            if (canonicalValid) {
                state.flags |= STATE_FLAG_CANON_READY;
                UpdateHelperStage(state, HelperInstallStage::Installing, nowTick, reason ? reason : "ctx-rebind");
            }
            if (canonicalOwner) {
                state.owner_tid = canonicalOwner;
                state.last_tid = canonicalOwner;
                state.flags |= STATE_FLAG_OWNER_READY;
                if (state.owner_ready_tick_ms == 0)
                    state.owner_ready_tick_ms = nowTick;
            }
        }, &info);
        info.ctx_reported = canonicalCtx;
        info.helper_rebind_attempts = 0;
        if (canonicalOwner)
            info.owner_tid = canonicalOwner;
        if (canonicalOwner)
            SetCanonicalHelperCtx(canonicalCtx, canonicalOwner);

        if (ctxChanged && s_lastRebindCtx != canonicalCtx) {
            Log::Logf(Log::Level::Info,
                      Log::Category::Hooks,
                      "[HOOKS] helpers rebind ctx old=%p new=%p owner=%u reason=%s",
                      previousCtx,
                      canonicalCtx,
                      static_cast<unsigned>(canonicalOwner),
                      reason ? reason : "unknown");
        }
        s_lastRebindCtx = canonicalCtx;
    };

    if (!IsOwnerThread(info)) {
        DWORD targetOwner = info.owner_tid ? info.owner_tid : scriptThreadId;
        if (targetOwner && targetOwner != GetCurrentThreadId()) {
            Log::Logf(Log::Level::Info,
                      Log::Category::Hooks,
                      "[HOOKS] helpers defer to owner tid=%u current=%u ctx=%p",
                      static_cast<unsigned>(targetOwner),
                      static_cast<unsigned>(GetCurrentThreadId()),
                      info.ctx_reported);
            PostBindToOwnerThread(L, targetOwner, generation, force, "wrong-thread");
        } else {
            Log::Logf(Log::Level::Info,
                      Log::Category::Hooks,
                      "[HOOKS] helpers cannot resolve owner current=%u ctx=%p",
                      static_cast<unsigned>(GetCurrentThreadId()),
                      info.ctx_reported);
        }
        return false;
    }

    Log::Logf(Log::Level::Info,
              Log::Category::Hooks,
              "[HOOKS] helpers owner-run ctx=%p canonical=%p owner=%lu canonicalOwner=%lu thread=%lu",
              info.ctx_reported,
              canonicalCtx,
              static_cast<unsigned long>(info.owner_tid),
              static_cast<unsigned long>(canonicalOwner),
              static_cast<unsigned long>(GetCurrentThreadId()));

    if (canonicalValid && canonicalOwner && canonicalOwner != GetCurrentThreadId()) {
        rebindToCanonical(info.ctx_reported, "owner-mismatch");
        refreshCanonical();
        reportedCtxStatus = ValidateCtxLoose(info.ctx_reported);
    }

    if (canonicalValid && info.ctx_reported != canonicalCtx) {
        if (reportedCtxStatus != CtxValidationResult::Ok || !info.ctx_reported) {
            rebindToCanonical(info.ctx_reported, "ctx-mismatch");
            refreshCanonical();
            reportedCtxStatus = ValidateCtxLoose(info.ctx_reported);
        }
    }

    Log::Logf(Log::Level::Info,
              Log::Category::Hooks,
              "helpers bind begin L=%p owner=%lu gen=%llu thread=%lu flags=0x%08X retries=%u",
              L,
              static_cast<unsigned long>(info.owner_tid),
              static_cast<unsigned long long>(generation),
              static_cast<unsigned long>(GetCurrentThreadId()),
              info.flags,
              static_cast<unsigned>(info.helper_retry_count));

    if (g_clientRegister && !sp::is_plausible_vtbl_entry(reinterpret_cast<const void*>(g_clientRegister))) {
        Log::Logf(Log::Level::Warn,
                  Log::Category::Hooks,
                  "helpers bind abort L=%p reason=register-invalid target=%p",
                  L,
                  reinterpret_cast<void*>(g_clientRegister));
        return false;
    }

    reportedCtxStatus = ValidateCtxLoose(info.ctx_reported);
    if (info.ctx_reported && reportedCtxStatus != CtxValidationResult::Ok) {
        HCTX attemptedCtx = info.ctx_reported;
        SafeRefreshLuaStateFromSlot();
        refreshCanonical();
        if (canonicalValid && canonicalCtx && canonicalCtx != attemptedCtx) {
            rebindToCanonical(attemptedCtx, "ctx-invalid");
            refreshCanonical();
            reportedCtxStatus = ValidateCtxLoose(info.ctx_reported);
        }
    }

    if (info.ctx_reported && reportedCtxStatus != CtxValidationResult::Ok) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "[HOOKS] ctx dropped ctx=%p reason=%s L=%p",
                  info.ctx_reported,
                  DescribeCtxValidation(reportedCtxStatus),
                  L);
        g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
            state.ctx_reported = nullptr;
        }, &info);
        info.ctx_reported = nullptr;
        reportedCtxStatus = CtxValidationResult::Null;
    }

    if (!info.ctx_reported) {
        refreshCanonical();
        if (canonicalValid && canonicalCtx) {
            rebindToCanonical(nullptr, "ctx-missing");
            refreshCanonical();
            reportedCtxStatus = ValidateCtxLoose(info.ctx_reported);
        }
    }

    g_stateRegistry.GetByPointer(L, info);

    bool ok = true;
    bool helpersBound = (info.flags & STATE_FLAG_HELPERS_BOUND) && info.gen == generation;
    if (force || !helpersBound) {
        if (metrics) {
            metrics->startTick = GetTickCount64();
        }
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "[HOOKS] helpers install-begin mode=%s tid=%u",
                  Net::ReadyModeString(),
                  static_cast<unsigned>(GetCurrentThreadId()));

        const bool wantsDebugPack = DebugInstrumentationEnabled() && DebugInstallEnvEnabled();

        auto logStep = [&](const char* name, auto&& fn) -> bool {
            Log::Logf(Log::Level::Info,
                      Log::Category::Hooks,
                      "[HOOKS][step] name=%s phase=pre",
                      name);
            bool stepOk = fn();
            Log::Logf(Log::Level::Info,
                      Log::Category::Hooks,
                      "[HOOKS][step] name=%s phase=post ok=%d",
                      name,
                      stepOk ? 1 : 0);
            return stepOk;
        };

        bool walkOk = logStep(kHelperWalkName, [&]() { return RegisterHelper(L, info, kHelperWalkName, Lua_UOWalk, generation); });
        bool walkMoveOk = logStep(kHelperWalkMoveName, [&]() { return RegisterHelper(L, info, kHelperWalkMoveName, Lua_WalkMove, generation); });
        bool pacingOk = logStep(kHelperGetPacingName, [&]() { return RegisterHelper(L, info, kHelperGetPacingName, Lua_GetPacing, generation); });
        bool setPacingOk = logStep(kHelperSetPacingName, [&]() { return RegisterHelper(L, info, kHelperSetPacingName, Lua_SetPacing, generation); });
        bool setInflightOk = logStep(kHelperSetInflightName, [&]() { return RegisterHelper(L, info, kHelperSetInflightName, Lua_SetInflight, generation); });
        bool metricsOk = logStep(kHelperGetWalkMetricsName, [&]() { return RegisterHelper(L, info, kHelperGetWalkMetricsName, Lua_GetWalkMetrics, generation); });
        bool statusFlagsOk = logStep(kHelperStatusFlagsName, [&]() { return RegisterHelper(L, info, kHelperStatusFlagsName, Lua_UOWStatusFlags, generation); });
        bool statusFlagsExOk = logStep(kHelperStatusFlagsAliasName, [&]() { return RegisterHelper(L, info, kHelperStatusFlagsAliasName, Lua_UOWStatusFlags, generation); });
        bool testRetOk = logStep(kHelperTestRetName, [&]() { return RegisterHelper(L, info, kHelperTestRetName, Lua_UOWTestRet, generation); });
        bool testRetAttempted = true;

        bool dumpOk = true;
        bool inspectOk = true;
        bool rebindOk = true;
        bool selfTestOk = true;
        bool debugCfgOk = true;
        bool debugStatusOk = true;
        bool debugPingOk = true;
        bool dumpAttempted = false;
        bool inspectAttempted = false;
        bool rebindAttempted = false;
        bool selfTestAttempted = false;
        bool debugCfgAttempted = false;
        bool debugStatusAttempted = false;
        bool debugPingAttempted = false;

        if (wantsDebugPack) {
            dumpOk = logStep(kHelperDumpName, [&]() { return RegisterHelper(L, info, kHelperDumpName, Lua_UOWDump, generation); });
            inspectOk = logStep(kHelperInspectName, [&]() { return RegisterHelper(L, info, kHelperInspectName, Lua_UOWInspect, generation); });
            rebindOk = logStep(kHelperRebindName, [&]() { return RegisterHelper(L, info, kHelperRebindName, Lua_UOWRebindAll, generation); });
            selfTestOk = logStep(kHelperSelfTestName, [&]() { return RegisterHelper(L, info, kHelperSelfTestName, Lua_UOWSelfTest, generation); });
            debugCfgOk = logStep(kHelperDebugName, [&]() { return RegisterHelper(L, info, kHelperDebugName, Lua_UOWDebug, generation); });
            debugStatusOk = logStep(kHelperDebugStatusName, [&]() { return RegisterHelper(L, info, kHelperDebugStatusName, Lua_UOWDebugStatus, generation); });
            debugPingOk = logStep(kHelperDebugPingName, [&]() { return RegisterHelper(L, info, kHelperDebugPingName, Lua_UOWDebugPing, generation); });
            dumpAttempted = true;
            inspectAttempted = true;
            rebindAttempted = true;
            selfTestAttempted = true;
            debugCfgAttempted = true;
            debugStatusAttempted = true;
            debugPingAttempted = true;
        }

        if (metrics) {
            uint32_t successCount = 0;
            uint32_t failureCount = 0;
            auto recordMetric = [&](bool attempted, bool ok) {
                if (!attempted)
                    return;
                if (ok)
                    ++successCount;
                else
                    ++failureCount;
            };
            recordMetric(true, walkOk);
            recordMetric(true, walkMoveOk);
            recordMetric(true, pacingOk);
            recordMetric(true, setPacingOk);
            recordMetric(true, setInflightOk);
            recordMetric(true, metricsOk);
            recordMetric(true, statusFlagsOk);
            recordMetric(true, statusFlagsExOk);
            recordMetric(testRetAttempted, testRetOk);
            recordMetric(dumpAttempted, dumpOk);
            recordMetric(inspectAttempted, inspectOk);
            recordMetric(rebindAttempted, rebindOk);
            recordMetric(selfTestAttempted, selfTestOk);
            recordMetric(debugCfgAttempted, debugCfgOk);
            recordMetric(debugStatusAttempted, debugStatusOk);
            recordMetric(debugPingAttempted, debugPingOk);
            metrics->hookSuccess = successCount;
            metrics->hookFailure = failureCount;
        }

        bool coreOk = walkOk && walkMoveOk && pacingOk && setPacingOk && setInflightOk && metricsOk && statusFlagsOk && statusFlagsExOk && testRetOk;
        bool debugPackOk = !wantsDebugPack || (dumpOk && inspectOk && rebindOk && selfTestOk && debugCfgOk && debugStatusOk && debugPingOk);
        bool allOk = coreOk && debugPackOk;
        if (allOk) {
            uint64_t installTick = GetTickCount64();
            g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
                state.flags |= STATE_FLAG_HELPERS_BOUND;
                state.flags |= STATE_FLAG_HELPERS_INSTALLED;
                state.gen = generation;
                state.helper_installed_tick_ms = installTick;
                state.helper_retry_count = 0;
                state.helper_first_attempt_ms = 0;
                state.helper_next_retry_ms = 0;
                state.helper_last_attempt_ms = installTick;
                state.helper_last_mutation_tick_ms = g_lastContextMutationTick.load(std::memory_order_acquire);
                UpdateHelperStage(state, HelperInstallStage::Installed, installTick, "success");
            }, &info);
            Log::Logf(Log::Level::Info,
                      Log::Category::Hooks,
                      "[HOOKS] helpers install-success tag=%s L=%p owner=%lu gen=%llu thread=%lu",
                      tagLabel,
                      L,
                      static_cast<unsigned long>(info.owner_tid),
                      static_cast<unsigned long long>(generation),
                      static_cast<unsigned long>(GetCurrentThreadId()));
            InstallGlobalOverwriteLogger(L);
            ReassertBinding(L, kHelperStatusFlagsName, Lua_UOW_StatusFlagsShim, true);
            ReassertBinding(L, kHelperStatusFlagsAliasName, Lua_UOW_StatusFlagsExShim, true);
            g_statusShimWatchdogBudget.store(3, std::memory_order_relaxed);
            g_helpersInstalledAny.store(true, std::memory_order_release);
            g_lastHelperOwnerThread.store(static_cast<DWORD>(info.owner_tid), std::memory_order_relaxed);
            Core::StartupSummary::NotifyHelpersReady();
        } else {
            ok = false;
            std::string missing;
            auto appendMissing = [&](bool attempted, bool valueOk, const char* name) {
                if (!attempted || valueOk)
                    return;
                if (!missing.empty())
                    missing.append(",");
                missing.append(name);
            };
            appendMissing(true, walkOk, kHelperWalkName);
            appendMissing(true, walkMoveOk, kHelperWalkMoveName);
            appendMissing(true, pacingOk, kHelperGetPacingName);
            appendMissing(true, setPacingOk, kHelperSetPacingName);
            appendMissing(true, setInflightOk, kHelperSetInflightName);
            appendMissing(true, metricsOk, kHelperGetWalkMetricsName);
            appendMissing(true, statusFlagsOk, kHelperStatusFlagsName);
            appendMissing(true, statusFlagsExOk, kHelperStatusFlagsAliasName);
            appendMissing(testRetAttempted, testRetOk, kHelperTestRetName);
            appendMissing(dumpAttempted, dumpOk, kHelperDumpName);
            appendMissing(inspectAttempted, inspectOk, kHelperInspectName);
            appendMissing(rebindAttempted, rebindOk, kHelperRebindName);
            appendMissing(selfTestAttempted, selfTestOk, kHelperSelfTestName);
            appendMissing(debugCfgAttempted, debugCfgOk, kHelperDebugName);
            appendMissing(debugStatusAttempted, debugStatusOk, kHelperDebugStatusName);
            appendMissing(debugPingAttempted, debugPingOk, kHelperDebugPingName);
            Log::Logf(Log::Level::Warn,
                      Log::Category::Hooks,
                      "helpers install failed L=%p owner=%lu gen=%llu missing=[%s]",
                      L,
                      static_cast<unsigned long>(info.owner_tid),
                      static_cast<unsigned long long>(generation),
                      missing.empty() ? "unknown" : missing.c_str());
        }
        if (metrics && metrics->endTick == 0)
            metrics->endTick = GetTickCount64();
    }

    InstallPanicAndDebug(L, info);
    if (metrics && metrics->endTick == 0)
        metrics->endTick = GetTickCount64();
    return ok;
}

static bool BindHelpersWithSeh(lua_State* L,
                               const LuaStateInfo& info,
                               uint64_t generation,
                               bool force,
                               bool& attemptedOut,
                               DWORD& sehCodeOut,
                               HelperInstallMetrics* metrics,
                               const char* installTag,
                               bool sbReadyNow,
                               bool sbPivotNow,
                               bool sbFallbackNow) noexcept {
    bool ok = false;
    bool attempted = false;
    DWORD sehCode = 0;
    attempted = true;
    HelperInstallMetrics localMetrics{};
    HelperInstallMetrics* metricsPtr = metrics ? metrics : &localMetrics;
    bool probeOk = sp::seh_probe([&]() {
        ok = BindHelpersOnThread(L,
                                 info,
                                 generation,
                                 force,
                                 metricsPtr,
                                 installTag,
                                 sbReadyNow,
                                 sbPivotNow,
                                 sbFallbackNow);
    }, &sehCode);
    if (!probeOk)
        ok = false;
    attemptedOut = attempted;
    sehCodeOut = sehCode;
    return ok;
}

static void BindHelpersTask(lua_State* L, uint64_t generation, bool force, const char* reason) {
    if (!L)
        return;

    LuaStateInfo info{};
    if (!g_stateRegistry.GetByPointer(L, info)) {
        LogLuaState("bind-skip Lc=%p reason=state-missing action=%s", L, reason ? reason : "unknown");
        ClearHelperPending(L, generation);
        return;
    }

    MaybeAdoptOwnerThread(L, info);

    const bool dispatchHelpers = Core::Bind::IsCurrentDispatchTag("helpers");
    const bool ownerThreadNow = IsOwnerThread(info);
    const char* installTag = "queued";
    if (dispatchHelpers)
        installTag = ownerThreadNow ? "owner" : "fallback";
    else if (ownerThreadNow)
        installTag = "owner-direct";

    Net::SendBuilderStatus sbStatus = Net::GetSendBuilderStatus();
    const bool sbReadyNow = sbStatus.ready;
    const bool sbPivotNow = sbStatus.pivotReady;
    const bool sbFallbackNow = Net::HasFallbackPivot();
    const bool sbDbMgrMode = sbStatus.ready && sbStatus.readyMode == Net::ReadyMode::DbMgr;

    if (!dispatchHelpers && !ownerThreadNow) {
        uint64_t now = GetTickCount64();
        if (now - info.last_bind_log_tick_ms >= kBindLogCooldownMs) {
            info.last_bind_log_tick_ms = now;
            LogLuaBind("bind-redirect Lc=%p owner=%lu current=%lu action=%s",
                       L,
                       info.owner_tid,
                       static_cast<unsigned long>(GetCurrentThreadId()),
                       reason ? reason : "unknown");
            g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
                state.last_bind_log_tick_ms = now;
            }, &info);
        }
        std::string reasonCopy = reason ? reason : "unknown";
        PostToOwnerWithTask(L, "helpers", [L, generation, force, reasonCopy]() {
            BindHelpersTask(L, generation, force, reasonCopy.c_str());
        });
        return;
    }

    uint64_t now = GetTickCount64();
    if ((info.flags & STATE_FLAG_QUARANTINED) && info.next_probe_ms && now < info.next_probe_ms) {
        LogLuaState("bind-skip Lc=%p reason=quarantined wait=%llu", L,
                    static_cast<unsigned long long>(info.next_probe_ms - now));
        TrackHelperEvent(g_helperDeferredCount);
        MaybeEmitHelperSummary(now);
        ClearHelperPending(L, generation, &info);
        return;
    }

    if (!force && (info.flags & STATE_FLAG_HELPERS_BOUND) && info.gen == generation) {
        InstallPanicAndDebug(L, info);
        ClearHelperPending(L, generation, &info);
        return;
    }

    Log::Logf(Log::Level::Info,
              Log::Category::Hooks,
              "helpers attempt L=%p owner=%lu flags=0x%08X retries=%u pendingGen=%llu nextRetry=%llu reason=%s",
              L,
              static_cast<unsigned long>(info.owner_tid),
              info.flags,
              static_cast<unsigned>(info.helper_retry_count),
              static_cast<unsigned long long>(info.helper_pending_generation),
              static_cast<unsigned long long>(info.helper_next_retry_ms),
              reason ? reason : "unknown");

    if (!IsOwnerThread(info)) {
        if (dispatchHelpers) {
            DWORD currentTid = GetCurrentThreadId();
            uint64_t nowTick = GetTickCount64();
            g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
                state.owner_tid = currentTid;
                state.last_tid = currentTid;
                if (state.owner_ready_tick_ms == 0)
                    state.owner_ready_tick_ms = nowTick;
                state.flags |= STATE_FLAG_OWNER_READY;
            }, &info);
            info.owner_tid = currentTid;
        } else {
            DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
            DWORD targetOwner = info.owner_tid ? info.owner_tid : scriptTid;
            if (targetOwner && targetOwner != GetCurrentThreadId()) {
                PostBindToOwnerThread(L, targetOwner, generation, force, "owner-redirect");
                ClearHelperPending(L, generation, &info);
                return;
            }
        }
    }

    if (!HelperSingleFlightTryAcquire()) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "[HOOKS] helpers in-progress skip tag=%s reason=single-flight tid=%u",
                  installTag,
                  static_cast<unsigned>(GetCurrentThreadId()));
        ClearHelperPending(L, generation, &info);
        return;
    }

    struct HelperSingleFlightGuard {
        ~HelperSingleFlightGuard() { HelperSingleFlightRelease(); }
    } singleFlightGuard;

    Log::Logf(Log::Level::Info,
              Log::Category::Hooks,
              "[HOOKS][step] install-flight-acquired tag=%s tid=%u",
              installTag,
              static_cast<unsigned>(GetCurrentThreadId()));

    LogLuaState("bind-start Lc=%p (Lr=%p ctx=%p) tid=%lu gen=%llu reason=%s",
                L,
                info.L_reported,
                info.ctx_reported,
                info.owner_tid,
                static_cast<unsigned long long>(generation),
                reason ? reason : "unknown");

    bool ok = false;
    bool attempted = false;
    DWORD sehCode = 0;
    bool reentrancyBlocked = false;
    bool guardEngaged = TryEnterHelperInstall();
    HelperInstallMetrics metrics{};

    if (!guardEngaged) {
        reentrancyBlocked = true;
        Log::Logf(Log::Level::Warn,
                  Log::Category::Hooks,
                  "helpers install reentrancy blocked L=%p owner=%lu",
                  L,
                  static_cast<unsigned long>(info.owner_tid));
    } else {
        g_helperProbeAttempted.fetch_add(1u, std::memory_order_relaxed);
                ok = BindHelpersWithSeh(L, info, generation, force, attempted, sehCode, &metrics, installTag, sbReadyNow, sbPivotNow, sbFallbackNow);
    }
    LeaveHelperInstall(guardEngaged);

    if (attempted) {
        uint64_t endTick = metrics.endTick ? metrics.endTick : GetTickCount64();
        uint64_t startTick = metrics.startTick;
        unsigned long tookMs = 0;
        if (startTick != 0 && endTick >= startTick)
            tookMs = static_cast<unsigned long>(endTick - startTick);
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "[HOOKS] helpers install-end tag=%s ok=%d hooks_ok=%u hooks_fail=%u took=%lums",
                  installTag,
                  ok ? 1 : 0,
                  static_cast<unsigned>(metrics.hookSuccess),
                  static_cast<unsigned>(metrics.hookFailure),
                  tookMs);
    }

    uint64_t summaryTick = GetTickCount64();
    if (ok) {
        ClearHelperPending(L, generation, &info);
        g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
            state.helper_rebind_attempts = 0;
        }, &info);
        g_helperProbeSuccess.fetch_add(1u, std::memory_order_relaxed);
        TrackHelperEvent(g_helperInstalledCount);
        MaybeEmitHelperSummary(summaryTick, true);
    } else {
        ClearHelperPending(L, generation, &info);
        TrackHelperEvent(g_helperDeferredCount);
        const HelperRetryPolicy& retry = GetHelperRetryPolicy();
        g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
            if (state.helper_passive_since_ms != 0) {
                state.helper_next_retry_ms = 0;
                return;
            }
            uint64_t delay = HelperRetryDelay(retry, state.helper_retry_count);
            if (delay == 0)
                delay = retry.debounceMs;
            uint64_t firstTick = state.helper_first_attempt_ms;
            uint64_t elapsed = (firstTick && summaryTick >= firstTick) ? (summaryTick - firstTick) : 0;
            uint32_t delayMs = 0;
            if (elapsed >= 2000) {
                delayMs = HelperBudgetBackoffMs(L, summaryTick);
            } else {
                delayMs = static_cast<uint32_t>(delay);
                delayMs += HelperJitterMs(retry, L, summaryTick);
            }
            uint64_t next = summaryTick + delayMs;
            if (state.helper_next_retry_ms == 0 || state.helper_next_retry_ms < next)
                state.helper_next_retry_ms = next;
        });
        MaybeEmitHelperSummary(summaryTick);

        LuaStateInfo after{};
        if (!g_stateRegistry.GetByPointer(L, after))
            after = info;
        const char* stageName = HelperStageName(static_cast<HelperInstallStage>(after.helper_state));
        DWORD codeToLog = (reentrancyBlocked || !attempted) ? 0 : sehCode;
        uint64_t elapsedMs = (after.helper_first_attempt_ms && summaryTick >= after.helper_first_attempt_ms)
                                 ? (summaryTick - after.helper_first_attempt_ms)
                                 : 0;
        uint64_t nextRetry = after.helper_next_retry_ms;
        Log::Logf(Log::Level::Warn,
                  Log::Category::Hooks,
                  "helpers install failed (will retry) code=0x%08lX stage=%s retries=%u elapsed=%llu next=%llu",
                  static_cast<unsigned long>(codeToLog),
                  stageName ? stageName : "unknown",
                  static_cast<unsigned>(after.helper_retry_count),
                  static_cast<unsigned long long>(elapsedMs),
                  static_cast<unsigned long long>(nextRetry));
        if (sehCode != 0 && reason && _stricmp(reason, kSettlePromoteReason) == 0) {
            Log::Logf(Log::Level::Warn,
                      Log::Category::Hooks,
                      "helpers promotion failed (seh) \xE2\x80\x94 will defer and retry later");
        }
        if (sehCode != 0) {
            g_sehTrapCount.fetch_add(1u, std::memory_order_relaxed);
            char moduleName[MAX_PATH] = {};
            void* moduleBase = nullptr;
            DWORD protect = 0;
            DescribeAddressForLog(L, moduleName, ARRAYSIZE(moduleName), &moduleBase, &protect);
            Log::Logf(Log::Level::Warn,
                      Log::Category::Hooks,
                      "[HOOKS][SAFE] probe AV: target=%p module=%s base=%p prot=0x%08lX exc=0x%08lX stage=%s",
                      L,
                      moduleName,
                      moduleBase,
                      static_cast<unsigned long>(protect),
                      static_cast<unsigned long>(sehCode),
                      stageName ? stageName : "unknown");
            LogLuaState("bind-fail Lc=%p ctx=%p gen=%llu seh=0x%08lX module=%s",
                        L,
                        info.ctx_reported,
                        static_cast<unsigned long long>(generation),
                        sehCode,
                        moduleName);
        } else {
            LogLuaState("bind-fail Lc=%p ctx=%p gen=%llu",
                        L,
                        info.ctx_reported,
                        static_cast<unsigned long long>(generation));
        }
    }

    if (ok) {
        LogLuaState("bind-done Lc=%p ctx=%p gen=%llu", L, info.ctx_reported, static_cast<unsigned long long>(generation));
    }
}


static void ForceRebindAll(const char* reason) {
    uint64_t newGen = g_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    LogLuaState("force-rebind gen=%llu reason=%s", newGen, reason ? reason : "manual");
    ClearAllDebugInstallRetry();
    g_stateRegistry.ClearFlagsAll(STATE_FLAG_HELPERS_BOUND | STATE_FLAG_HELPERS_INSTALLED);
    auto snapshot = g_stateRegistry.Snapshot();
    for (const auto& info : snapshot) {
        RequestBindForState(info, reason ? reason : "force", true);
    }
}

static void DumpWalkEnv(lua_State* L, const char* reason) {
    if (!L)
        return;
    const char* names[] = { "walk", "bindWalk" };
    for (const char* name : names) {
        lua_getglobal(L, name);
        int type = lua_type(L, -1);
        const char* typeName = lua_typename(L, type);
        const void* ptr = lua_topointer(L, -1);
        int upCount = 0;
        if (type == LUA_TFUNCTION && !lua_iscfunction(L, -1)) {
            int funcIndex = lua_gettop(L);
            while (lua_getupvalue(L, funcIndex, upCount + 1) != nullptr) {
                ++upCount;
                lua_pop(L, 1);
            }
        }
        LogLuaProbe("%s env type=%s ptr=%p upvalues=%d reason=%s",
                    name,
                    typeName ? typeName : "?",
                    ptr,
                    upCount,
                    reason ? reason : "manual");
        lua_pop(L, 1);
    }
}

static int Lua_UOWDump(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    EnsureHelperState(L, kHelperDumpName, &ready, &coalesced, nullptr);
    DumpWalkEnv(L, "uow_dump_walk_env");
    return 0;
}

static int Lua_WalkMove(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    EnsureHelperState(L, kHelperWalkMoveName, &ready, &coalesced, nullptr);
    int argc = lua_gettop(L);
    if (argc < 1 || !lua_isnumber(L, 1)) {
        lua_pushboolean(L, 0);
        return 1;
    }
    int dir = static_cast<int>(lua_tointeger(L, 1));
    bool run = false;
    if (argc >= 2)
        run = lua_toboolean(L, 2) != 0;
    bool ok = false;
    if (::Engine::Movement::IsReady()) {
        ok = ::Engine::Movement::EnqueueMove(static_cast<::Engine::Movement::Dir>(dir & 0x7), run);
    }
    if (!ok) {
        ok = SendWalk(dir & 0x7, run ? 1 : 0);
    }
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

static int Lua_GetPacing(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    EnsureHelperState(L, kHelperGetPacingName, &ready, &coalesced, nullptr);
    lua_pushinteger(L, static_cast<lua_Integer>(Walk::Controller::GetStepDelayMs()));
    return 1;
}

static int Lua_SetPacing(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    EnsureHelperState(L, kHelperSetPacingName, &ready, &coalesced, nullptr);

    if (lua_gettop(L) < 1 || !lua_isnumber(L, 1)) {
        LogLuaProbe("uow_set_pacing invalid parameter");
        lua_pushboolean(L, 0);
        return 1;
    }

    int ms = static_cast<int>(lua_tointeger(L, 1));
    if (ms < 0)
        ms = 0;
    Walk::Controller::SetStepDelayMs(static_cast<std::uint32_t>(ms));
    LogLuaProbe("uow_set_pacing ms=%d", ms);
    lua_pushboolean(L, 1);
    return 1;
}

static int Lua_SetInflight(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    EnsureHelperState(L, kHelperSetInflightName, &ready, &coalesced, nullptr);

    if (lua_gettop(L) < 1 || !lua_isnumber(L, 1)) {
        LogLuaProbe("uow_set_inflight invalid parameter");
        lua_pushboolean(L, 0);
        return 1;
    }

    int count = static_cast<int>(lua_tointeger(L, 1));
    if (count < 1)
        count = 1;
    Walk::Controller::SetMaxInflight(static_cast<std::uint32_t>(count));
    LogLuaProbe("uow_set_inflight count=%d", count);
    lua_pushboolean(L, 1);
    return 1;
}

static int Lua_GetWalkMetrics(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    EnsureHelperState(L, kHelperGetWalkMetricsName, &ready, &coalesced, nullptr);
    Engine::AckStats ack{};
    Engine::GetAckStats(ack);
    lua_newtable(L);
    lua_pushinteger(L, static_cast<lua_Integer>(Walk::Controller::GetStepDelayMs()));
    lua_setfield(L, -2, "stepDelay");
    lua_pushinteger(L, static_cast<lua_Integer>(Walk::Controller::GetInflightCount()));
    lua_setfield(L, -2, "inflight");
    lua_pushinteger(L, static_cast<lua_Integer>(::Engine::Movement::QueueDepth()));
    lua_setfield(L, -2, "queueDepth");
    lua_pushinteger(L, static_cast<lua_Integer>(ack.lastSeq));
    lua_setfield(L, -2, "lastAckSeq");
    lua_pushinteger(L, static_cast<lua_Integer>(ack.okCount));
    lua_setfield(L, -2, "acksOk");
    lua_pushinteger(L, static_cast<lua_Integer>(ack.dropCount));
    lua_setfield(L, -2, "acksDrop");
    return 1;
}

static int Lua_UOWStatusFlags(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    EnsureHelperState(L, kHelperStatusFlagsName, &ready, &coalesced, nullptr);

    const bool helpersReady = g_helpersInstalledAny.load(std::memory_order_acquire);
    const bool engineReady = g_engineContext.load(std::memory_order_acquire) != nullptr;
    const bool sendReady = Net::IsSendReady();
    const bool movementReady = Engine::MovementReady();
    const bool sendPivotReady = Net::IsPivotReady();
    const bool sendFallback = Net::HasFallbackPivot();
    const int fwDepth = Engine::Movement::QueueDepth();
    const int stepDelayMs = static_cast<int>(Walk::Controller::GetStepDelayMs());
    const int inflight = static_cast<int>(Walk::Controller::GetInflightCount());
    Engine::AckStats ack{};
    Engine::GetAckStats(ack);

    int baseTop = lua_gettop(L);
    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[UOW][statusflags] begin top=%d L=%p",
              baseTop,
              L);

    log_top(L, "enter");

    const char* rawKey = nullptr;
    size_t rawKeyLen = 0;
    if (lua_gettop(L) >= 1 && lua_isstring(L, 1)) {
        rawKey = lua_tolstring(L, 1, &rawKeyLen);
    }

    int argCount = lua_gettop(L);
    int argType = (argCount >= 1) ? lua_type(L, 1) : LUA_TNONE;

    std::string keyStr;
    if (rawKey && rawKeyLen > 0) {
        keyStr.assign(rawKey, rawKeyLen);
        auto trim = [](std::string& s) {
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
                s.erase(s.begin());
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
                s.pop_back();
        };
        trim(keyStr);
    }

    std::string keyLower = keyStr;
    std::transform(keyLower.begin(), keyLower.end(), keyLower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    const char* safeKey = !keyStr.empty() ? keyStr.c_str() : "<table>";
    LogLuaProbe("uow_statusflags call key=%s type=%d argc=%d ready=%d coalesced=%d helpers=%d engine=%d send=%d pivot=%d fallback=%d movement=%d fwDepth=%d stepDelay=%d inflight=%d ackOk=%u ackDrop=%u",
                safeKey,
                argType,
                argCount,
                ready ? 1 : 0,
                coalesced ? 1 : 0,
                helpersReady ? 1 : 0,
                engineReady ? 1 : 0,
                sendReady ? 1 : 0,
                sendPivotReady ? 1 : 0,
                sendFallback ? 1 : 0,
                movementReady ? 1 : 0,
                fwDepth,
                stepDelayMs,
                inflight,
                static_cast<unsigned int>(ack.okCount),
                static_cast<unsigned int>(ack.dropCount));
    DebugRingTryWrite("[UOW][statusflags] key=%s type=%d argc=%d helpers=%d engine=%d send=%d pivot=%d fallback=%d movement=%d fw=%d step=%d inflight=%d ackOk=%u ackDrop=%u",
                      safeKey,
                      argType,
                      argCount,
                      helpersReady ? 1 : 0,
                      engineReady ? 1 : 0,
                      sendReady ? 1 : 0,
                      sendPivotReady ? 1 : 0,
                      sendFallback ? 1 : 0,
                      movementReady ? 1 : 0,
                      fwDepth,
                      stepDelayMs,
                      inflight,
                      static_cast<unsigned int>(ack.okCount),
                      static_cast<unsigned int>(ack.dropCount));

    auto calcReturnCount = [&](const char* tag) -> int {
        int topNow = lua_gettop(L);
        log_top(L, tag);
        int nret = topNow - baseTop;
        return (nret < 0) ? 0 : nret;
    };

    auto pushTable = [&]() -> int {
        LogLuaProbe("uow_statusflags return table key=%s", safeKey);
        DebugRingTryWrite("[UOW][statusflags] return table key=%s", safeKey);
        lua_createtable(L, 0, 20);

        lua_pushboolean(L, helpersReady ? 1 : 0);
        lua_setfield(L, -2, "helpers");
        lua_pushboolean(L, helpersReady ? 1 : 0);
        lua_setfield(L, -2, "helpersReady");

        lua_pushboolean(L, engineReady ? 1 : 0);
        lua_setfield(L, -2, "engineCtx");
        lua_pushboolean(L, engineReady ? 1 : 0);
        lua_setfield(L, -2, "engine");

        lua_pushboolean(L, sendReady ? 1 : 0);
        lua_setfield(L, -2, "sendReady");
        lua_pushboolean(L, sendReady ? 1 : 0);
        lua_setfield(L, -2, "send");

        lua_pushboolean(L, sendPivotReady ? 1 : 0);
        lua_setfield(L, -2, "sendPivot");
        lua_pushboolean(L, sendFallback ? 1 : 0);
        lua_setfield(L, -2, "sendFallback");
        lua_pushboolean(L, movementReady ? 1 : 0);
        lua_setfield(L, -2, "movementReady");

        lua_pushinteger(L, static_cast<lua_Integer>(fwDepth));
        lua_setfield(L, -2, "fwDepth");
        lua_pushinteger(L, static_cast<lua_Integer>(fwDepth));
        lua_setfield(L, -2, "fw");
        lua_pushinteger(L, static_cast<lua_Integer>(fwDepth));
        lua_setfield(L, -2, "queueDepth");

        lua_pushinteger(L, static_cast<lua_Integer>(stepDelayMs));
        lua_setfield(L, -2, "stepDelay");
        lua_pushinteger(L, static_cast<lua_Integer>(stepDelayMs));
        lua_setfield(L, -2, "stepDelayMs");
        lua_pushinteger(L, static_cast<lua_Integer>(stepDelayMs));
        lua_setfield(L, -2, "pace");

        lua_pushinteger(L, static_cast<lua_Integer>(inflight));
        lua_setfield(L, -2, "inflight");

        lua_pushinteger(L, static_cast<lua_Integer>(ack.okCount));
        lua_setfield(L, -2, "acksOk");
        lua_pushinteger(L, static_cast<lua_Integer>(ack.dropCount));
        lua_setfield(L, -2, "acksDrop");
        lua_pushinteger(L, static_cast<lua_Integer>(ack.okCount));
        lua_setfield(L, -2, "ack_ok");
        lua_pushinteger(L, static_cast<lua_Integer>(ack.dropCount));
        lua_setfield(L, -2, "ack_drop");

        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[UOW][statusflags] built-table top=%d",
                  lua_gettop(L));
        return calcReturnCount("ret-table");
    };

    if (keyLower.empty()) {
        LogLuaProbe("uow_statusflags missing key, returning table");
        return pushTable();
    }

    if (keyLower == "helpers") {
        int value = helpersReady ? 1 : 0;
        LogLuaProbe("uow_statusflags return bool key=%s value=%d", safeKey, value);
        DebugRingTryWrite("[UOW][statusflags] return bool key=%s value=%d", safeKey, value);
        lua_pushboolean(L, value);
        return calcReturnCount("ret-helpers");
    }
    if (keyLower == "engine" || keyLower == "enginctx" || keyLower == "enginectx") {
        int value = engineReady ? 1 : 0;
        LogLuaProbe("uow_statusflags return bool key=%s value=%d", safeKey, value);
        DebugRingTryWrite("[UOW][statusflags] return bool key=%s value=%d", safeKey, value);
        lua_pushboolean(L, value);
        return calcReturnCount("ret-engine");
    }
    if (keyLower == "send" || keyLower == "sendready") {
        int value = sendReady ? 1 : 0;
        LogLuaProbe("uow_statusflags return bool key=%s value=%d", safeKey, value);
        DebugRingTryWrite("[UOW][statusflags] return bool key=%s value=%d", safeKey, value);
        lua_pushboolean(L, value);
        return calcReturnCount("ret-send");
    }
    if (keyLower == "sendpivot" || keyLower == "pivot") {
        int value = sendPivotReady ? 1 : 0;
        LogLuaProbe("uow_statusflags return bool key=%s value=%d", safeKey, value);
        DebugRingTryWrite("[UOW][statusflags] return bool key=%s value=%d", safeKey, value);
        lua_pushboolean(L, value);
        return calcReturnCount("ret-sendpivot");
    }
    if (keyLower == "sendfallback" || keyLower == "fallback") {
        int value = sendFallback ? 1 : 0;
        LogLuaProbe("uow_statusflags return bool key=%s value=%d", safeKey, value);
        DebugRingTryWrite("[UOW][statusflags] return bool key=%s value=%d", safeKey, value);
        lua_pushboolean(L, value);
        return calcReturnCount("ret-sendfallback");
    }
    if (keyLower == "movement" || keyLower == "movementready") {
        int value = movementReady ? 1 : 0;
        LogLuaProbe("uow_statusflags return bool key=%s value=%d", safeKey, value);
        DebugRingTryWrite("[UOW][statusflags] return bool key=%s value=%d", safeKey, value);
        lua_pushboolean(L, value);
        return calcReturnCount("ret-movement");
    }
    if (keyLower == "fw" || keyLower == "fwdepth" || keyLower == "queuedepth") {
        LogLuaProbe("uow_statusflags return int key=%s value=%d", safeKey, fwDepth);
        DebugRingTryWrite("[UOW][statusflags] return int key=%s value=%d", safeKey, fwDepth);
        lua_pushinteger(L, static_cast<lua_Integer>(fwDepth));
        return calcReturnCount("ret-fw");
    }
    if (keyLower == "pace" || keyLower == "stepdelay" || keyLower == "stepdelayms") {
        LogLuaProbe("uow_statusflags return int key=%s value=%d", safeKey, stepDelayMs);
        DebugRingTryWrite("[UOW][statusflags] return int key=%s value=%d", safeKey, stepDelayMs);
        lua_pushinteger(L, static_cast<lua_Integer>(stepDelayMs));
        return calcReturnCount("ret-pace");
    }
    if (keyLower == "inflight") {
        LogLuaProbe("uow_statusflags return int key=%s value=%d", safeKey, inflight);
        DebugRingTryWrite("[UOW][statusflags] return int key=%s value=%d", safeKey, inflight);
        lua_pushinteger(L, static_cast<lua_Integer>(inflight));
        return calcReturnCount("ret-inflight");
    }
    if (keyLower == "ack" || keyLower == "acks") {
        lua_newtable(L);
        lua_pushinteger(L, static_cast<lua_Integer>(ack.okCount));
        lua_setfield(L, -2, "ok");
        lua_pushinteger(L, static_cast<lua_Integer>(ack.dropCount));
        lua_setfield(L, -2, "drop");
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[UOW][statusflags] returning ack-table top=%d",
                  lua_gettop(L));
        LogLuaProbe("uow_statusflags return ack-table key=%s ok=%u drop=%u",
                    safeKey,
                    static_cast<unsigned int>(ack.okCount),
                    static_cast<unsigned int>(ack.dropCount));
        DebugRingTryWrite("[UOW][statusflags] return ack-table key=%s ok=%u drop=%u",
                          safeKey,
                          static_cast<unsigned int>(ack.okCount),
                          static_cast<unsigned int>(ack.dropCount));
        return calcReturnCount("ret-ack-table");
    }
    if (keyLower == "ackok" || keyLower == "acksok" || keyLower == "ack_ok") {
        LogLuaProbe("uow_statusflags return int key=%s value=%u", safeKey, static_cast<unsigned int>(ack.okCount));
        DebugRingTryWrite("[UOW][statusflags] return int key=%s value=%u", safeKey, static_cast<unsigned int>(ack.okCount));
        lua_pushinteger(L, static_cast<lua_Integer>(ack.okCount));
        return calcReturnCount("ret-ackok");
    }
    if (keyLower == "ackdrop" || keyLower == "acksdrop" || keyLower == "ack_drop") {
        LogLuaProbe("uow_statusflags return int key=%s value=%u", safeKey, static_cast<unsigned int>(ack.dropCount));
        DebugRingTryWrite("[UOW][statusflags] return int key=%s value=%u", safeKey, static_cast<unsigned int>(ack.dropCount));
        lua_pushinteger(L, static_cast<lua_Integer>(ack.dropCount));
        return calcReturnCount("ret-ackdrop");
    }
    if (keyLower == "version") {
        constexpr int kStatusFlagsVersion = 20251103;
        LogLuaProbe("uow_statusflags return int key=%s value=%d", safeKey, kStatusFlagsVersion);
        DebugRingTryWrite("[UOW][statusflags] return int key=%s value=%d", safeKey, kStatusFlagsVersion);
        lua_pushinteger(L, static_cast<lua_Integer>(kStatusFlagsVersion));
        return calcReturnCount("ret-version");
    }

    LogLuaProbe("uow_statusflags unknown key=%s (len=%zu)", safeKey, keyStr.size());
    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[UOW][statusflags] unknown-key returning table top=%d",
              lua_gettop(L));
    return pushTable();
}

static int Lua_UOWTestRet(lua_State* L) {
    int baseTop = lua_gettop(L);
    lua_pushboolean(L, 1);
    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[UOW][testret] enterTop=%d exitTop=%d",
              baseTop,
              lua_gettop(L));
    return std::max(0, lua_gettop(L) - baseTop);
}

static int Lua_UOWalk(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    EnsureHelperState(L, kHelperWalkName, &ready, &coalesced, nullptr);
    int argc = lua_gettop(L);
    if (argc >= 1 && lua_type(L, 1) == LUA_TTABLE) {
        if (!Walk::Controller::IsEnabled()) {
            LogLuaProbe("uow_walk controller disabled");
            lua_pushboolean(L, 0);
            return 1;
        }

        auto readNumberField = [&](const char* name, int index, double& outValue, bool& outHasValue) {
            lua_getfield(L, index, name);
            if (lua_isnumber(L, -1)) {
                outValue = lua_tonumber(L, -1);
                outHasValue = true;
            }
            lua_pop(L, 1);
        };

        auto readArrayEntry = [&](int index, int arrayIndex, double& outValue, bool& outHasValue) {
            lua_rawgeti(L, index, arrayIndex);
            if (lua_isnumber(L, -1)) {
                outValue = lua_tonumber(L, -1);
                outHasValue = true;
            }
            lua_pop(L, 1);
        };

        double x = 0.0;
        double yVal = 0.0;
        double z = 0.0;
        bool hasX = false;
        bool hasY = false;
        bool hasZ = false;

        readNumberField("x", 1, x, hasX);
        readNumberField("y", 1, yVal, hasY);
        readNumberField("z", 1, z, hasZ);

        if (!hasX)
            readArrayEntry(1, 1, x, hasX);
        if (!hasY)
            readArrayEntry(1, 2, yVal, hasY);
        if (!hasZ)
            readArrayEntry(1, 3, z, hasZ);

        bool runFlag = false;
        lua_getfield(L, 1, "run");
        int runFieldType = lua_type(L, -1);
        if (runFieldType == LUA_TBOOLEAN) {
            runFlag = lua_toboolean(L, -1) != 0;
        } else if (runFieldType == LUA_TNUMBER) {
            runFlag = lua_tointeger(L, -1) != 0;
        }
        lua_pop(L, 1);

        if (argc >= 2) {
            int arg2Type = lua_type(L, 2);
            if (arg2Type == LUA_TBOOLEAN) {
                runFlag = lua_toboolean(L, 2) != 0;
            } else if (arg2Type == LUA_TNUMBER) {
                runFlag = lua_tointeger(L, 2) != 0;
            }
        }

        if (!hasX || !hasZ) {
            LogLuaProbe("uow_walk controller missing x/z target");
            lua_pushboolean(L, 0);
            return 1;
        }

        if (!hasY)
            yVal = 0.0;

        bool ok = Walk::Controller::RequestTarget(static_cast<float>(x),
                                                  static_cast<float>(yVal),
                                                  static_cast<float>(z),
                                                  runFlag);
        lua_pushboolean(L, ok ? 1 : 0);
        return 1;
    }

    if (argc < 1 || !lua_isnumber(L, 1)) {
        LogLuaProbe("uow_walk invalid dir parameter");
        lua_pushboolean(L, 0);
        return 1;
    }

    int dir = static_cast<int>(lua_tointeger(L, 1));
    int run = 0;
    if (argc >= 2) {
        if (lua_isnumber(L, 2)) {
            run = lua_tointeger(L, 2) != 0 ? 1 : 0;
        } else {
            int type = lua_type(L, 2);
            if (type == LUA_TBOOLEAN) {
                run = lua_toboolean(L, 2) ? 1 : 0;
            } else {
                LogLuaProbe("uow_walk run parameter ignored (unsupported type)");
                run = 0;
            }
        }
    }
    bool ok = SendWalk(dir, run);
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

static int Lua_UOWInspect(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    LuaStateInfo info = EnsureHelperState(L, kHelperInspectName, &ready, &coalesced, nullptr);

    lua_State* targetState = info.L_canonical ? info.L_canonical : L;
    int callerTop = 0;
    bool callerTopValid = SafeLuaProbeStack(targetState, info, &callerTop, nullptr);

    auto finalize = [&](bool ok) -> int {
        if (callerTopValid) {
            DWORD restoreSeh = 0;
            if (!SafeLuaSetTop(targetState, info, callerTop, &restoreSeh)) {
                LogLuaState("inspect restore-seh L=%p code=0x%08lX", L, restoreSeh);
                ok = false;
            }
        }
        lua_pushboolean(L, ok ? 1 : 0);
        return 1;
    };

    if (!ready || !info.L_canonical) {
        LogLuaState("inspect abort L=%p reason=no-canonical ready=%d flags=0x%08X",
                    L,
                    ready ? 1 : 0,
                    info.flags);
        return finalize(false);
    }

    std::string summary;
    DWORD seh = 0;
    bool summaryOk = TryBuildInspectSummary(targetState, info, summary, &seh);

    if (!summaryOk) {
        LogLuaState("inspect-seh Lc=%p code=0x%08lX", targetState, seh);
        return finalize(false);
    }

    LogLuaState("inspect %s", summary.c_str());

    uint64_t now = GetTickCount64();
    auto snapshot = g_stateRegistry.Snapshot();
    for (const auto& entry : snapshot) {
        uint64_t wait = (entry.flags & STATE_FLAG_QUARANTINED) && entry.next_probe_ms > now
                            ? (entry.next_probe_ms - now)
                            : 0;
        std::string extra = wait ? (" backoff=" + std::to_string(wait) + "ms") : std::string();
        LogLuaState("entry Lc=%p (Lr=%p ctx=%p) owner=%lu last=%lu gen=%llu flags=%s counters=%u/%u/%u%s",
                    entry.L_canonical,
                    entry.L_reported,
                    entry.ctx_reported,
                    entry.owner_tid,
                    entry.last_tid,
                    static_cast<unsigned long long>(entry.gen),
                    DescribeFlags(entry.flags).c_str(),
                    entry.hook_call_count,
                    entry.hook_ret_count,
                    entry.hook_line_count,
                    extra.c_str());
    }

    return finalize(true);
}

static bool IsValidDebugModeString(const char* mode) {
    if (!mode)
        return false;
    return _stricmp(mode, "off") == 0 ||
           _stricmp(mode, "on") == 0 ||
           _stricmp(mode, "trace") == 0 ||
           _stricmp(mode, "calls") == 0;
}

static int Lua_UOWDebug(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    LuaStateInfo info = EnsureHelperState(L, kHelperDebugName, &ready, &coalesced, nullptr);

    int argc = lua_gettop(L);
    if (argc < 1 || !lua_isstring(L, 1)) {
        lua_pushstring(L, "invalid-mode");
        return 1;
    }

    size_t modeLen = 0;
    const char* modeText = lua_tolstring(L, 1, &modeLen);
    if (!IsValidDebugModeString(modeText)) {
        lua_pushstring(L, "invalid-mode");
        return 1;
    }

    DebugConfigRequest req{};
    req.mode = DebugModeFromString(modeText);

    if (argc >= 2 && lua_type(L, 2) != LUA_TNIL) {
        if (!lua_isnumber(L, 2)) {
            lua_pushstring(L, "invalid-mask");
            return 1;
        }
        lua_Integer maskVal = lua_tointeger(L, 2);
        if (maskVal < 0)
            maskVal = 0;
        req.mask = static_cast<uint32_t>(maskVal);
        req.explicitMask = true;
    }

    if (argc >= 3 && lua_type(L, 3) != LUA_TNIL) {
        if (!lua_isnumber(L, 3)) {
            lua_pushstring(L, "invalid-count");
            return 1;
        }
        lua_Integer countVal = lua_tointeger(L, 3);
        if (countVal < 0)
            countVal = 0;
        req.count = static_cast<uint32_t>(std::min<lua_Integer>(countVal, static_cast<lua_Integer>(INT_MAX)));
        req.explicitCount = true;
    }

    lua_State* target = info.L_canonical ? info.L_canonical : L;
    LuaStateInfo targetInfo{};
    if (!g_stateRegistry.GetByPointer(target, targetInfo))
        targetInfo = info;

    if (!(targetInfo.flags & STATE_FLAG_VALID)) {
        PushDebugResultTable(L,
                             "invalid",
                             targetInfo.debug_status == 1,
                             targetInfo.debug_mode,
                             targetInfo.debug_mask,
                             targetInfo.debug_count,
                             false,
                             false);
        return 1;
    }

    MaybeAdoptOwnerThread(target, targetInfo);

    if (!IsOwnerThread(targetInfo)) {
        DebugConfigRequest taskReq = req;
        PostToOwnerWithTask(target, "debug-config", [target, taskReq]() {
            LuaStateInfo current{};
            if (!g_stateRegistry.GetByPointer(target, current))
                return;
            DebugConfigResult taskResult{};
            if (ApplyDebugConfigOnOwner(target, current, taskReq, taskResult)) {
                if (taskResult.applied) {
                    if (taskResult.enabled) {
                        LogLuaDbg("enabled Lc=%p mask=0x%x count=%u mode=%s",
                                  target,
                                  taskResult.mask,
                                  taskResult.count,
                                  DebugModeToString(taskResult.mode));
                    } else {
                        LogLuaDbg("disabled Lc=%p", target);
                    }
                }
            } else if (!taskResult.error.empty()) {
                if (taskResult.seh) {
                    LogLuaDbg("enable-failed Lc=%p err=%s seh=0x%08lX",
                              target,
                              taskResult.error.c_str(),
                              taskResult.seh);
                } else {
                    LogLuaDbg("enable-failed Lc=%p err=%s",
                              target,
                              taskResult.error.c_str());
                }
            }
        });
        PushDebugResultTable(L,
                             "scheduled",
                             targetInfo.debug_status == 1,
                             targetInfo.debug_mode,
                             targetInfo.debug_mask,
                             targetInfo.debug_count,
                             false,
                             true);
        return 1;
    }

    DebugConfigResult result{};
    if (!ApplyDebugConfigOnOwner(target, targetInfo, req, result)) {
        std::string message = result.error.empty() ? "error" : result.error;
        if (result.seh) {
            char buf[16];
            sprintf_s(buf, sizeof(buf), "0x%08lX", result.seh);
            message.append(" seh=");
            message.append(buf);
        }
        lua_pushstring(L, message.c_str());
        return 1;
    }

    if (result.applied) {
        if (result.enabled) {
            LogLuaDbg("enabled Lc=%p mask=0x%x count=%u mode=%s",
                      target,
                      result.mask,
                      result.count,
                      DebugModeToString(result.mode));
        } else {
            LogLuaDbg("disabled Lc=%p", target);
        }
    }

    PushDebugResultTable(L,
                         result.enabled ? "on" : "off",
                         result.enabled,
                         result.mode,
                         result.mask,
                         result.count,
                         result.applied,
                         false);
    return 1;
}

static int Lua_UOWDebugStatus(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    LuaStateInfo info = EnsureHelperState(L, kHelperDebugStatusName, &ready, &coalesced, nullptr);

    LuaStateInfo targetInfo{};
    if (!g_stateRegistry.GetByPointer(info.L_canonical ? info.L_canonical : L, targetInfo))
        targetInfo = info;

    bool enabled = DebugInstrumentationEnabled() && (targetInfo.gc_sentinel_ref == 1);
    lua_pushboolean(L, enabled ? 1 : 0);
    return 1;
}

static bool RunSmokeSelfTest(std::string& reason) {
    const GlobalStateInfo* gs = Engine::Info();
    if (!gs) {
        reason = "global-missing";
        return false;
    }
    if (!gs->luaState || !gs->databaseManager || !gs->resourceManager) {
        reason = "global-incomplete";
        return false;
    }

    Engine::MovementDebugStatus status{};
    Engine::GetMovementDebugStatus(status);
    if (!status.ready || !Engine::MovementReady()) {
        reason = "movement-not-ready";
        return false;
    }

    void* movementComponent = status.movementComponentPtr;
    if (!movementComponent) {
        reason = "movement-component-null";
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    bool vtableOk = VirtualQuery(movementComponent, &mbi, sizeof(mbi)) == sizeof(mbi) &&
                    mbi.State == MEM_COMMIT &&
                    (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
                    !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS));

    if (!vtableOk) {
        reason = "movement-vtable-unreadable";
        return false;
    }

    Engine::MovementSnapshot snapshot{};
    if (!Engine::GetLastMovementSnapshot(snapshot)) {
        reason = "movement-snapshot-missing";
        return false;
    }

    reason.clear();
    return true;
}

static int Lua_UOWDebugPing(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    LuaStateInfo info = EnsureHelperState(L, kHelperDebugName, &ready, &coalesced, nullptr);
    LuaStackGuard guard(L, &info);

    const GlobalStateInfo* gs = Engine::Info();
    const bool helpersInstalled = (info.flags & STATE_FLAG_HELPERS_INSTALLED) != 0;
    const bool helpersPending = (info.flags & STATE_FLAG_HELPERS_PENDING) != 0;
    const bool helpersBound = (info.flags & STATE_FLAG_HELPERS_BOUND) != 0;

    Engine::MovementDebugStatus moveStatus{};
    Engine::GetMovementDebugStatus(moveStatus);
    Engine::MovementSnapshot snapshot{};
    bool haveSnapshot = Engine::GetLastMovementSnapshot(snapshot);
    bool movementReady = Engine::MovementReady();

    LogLuaState("ping ready=%d bound=%d installed=%d pending=%d Lc=%p ctx=%p global=%p db=%p resource=%p core=%p cookie=%u moveReady=%d head=%u tail=%u pos=(%.2f,%.2f)",
                ready ? 1 : 0,
                helpersBound ? 1 : 0,
                helpersInstalled ? 1 : 0,
                helpersPending ? 1 : 0,
                info.L_canonical,
                info.ctx_reported,
                gs,
                gs ? gs->databaseManager : nullptr,
                gs ? gs->resourceManager : nullptr,
                gs ? gs->coreResourceMgr : nullptr,
                Engine::GlobalStateCookie(),
                movementReady ? 1 : 0,
                haveSnapshot ? snapshot.head : 0u,
                haveSnapshot ? snapshot.tail : 0u,
                haveSnapshot ? snapshot.posX : 0.0f,
                haveSnapshot ? snapshot.posZ : 0.0f);

    std::string flagSummary = DescribeFlags(info.flags);

    auto pushBool = [&](const char* key, bool value) {
        lua_pushstring(L, key);
        lua_pushboolean(L, value ? 1 : 0);
        lua_settable(L, -3);
    };

    auto pushPtr = [&](const char* key, const void* ptr) {
        lua_pushstring(L, key);
        if (ptr) {
            lua_pushlightuserdata(L, const_cast<void*>(ptr));
        } else {
            lua_pushnil(L);
        }
        lua_settable(L, -3);
    };

    lua_newtable(L);
    pushBool("ready", ready);
    pushBool("helpersBound", helpersBound);
    pushBool("helpersInstalled", helpersInstalled);
    pushBool("helpersPending", helpersPending);
    pushBool("movementReady", movementReady);

    lua_pushstring(L, "flags");
    lua_pushstring(L, flagSummary.c_str());
    lua_settable(L, -3);

    pushPtr("canonical", info.L_canonical);
    pushPtr("reported", info.L_reported);
    pushPtr("context", info.ctx_reported);
    pushPtr("globalState", gs);
    pushPtr("databaseManager", gs ? gs->databaseManager : nullptr);
    pushPtr("resourceManager", gs ? gs->resourceManager : nullptr);
    pushPtr("coreResourceManager", gs ? gs->coreResourceMgr : nullptr);
    pushPtr("movementComponent", moveStatus.movementComponentPtr);
    pushPtr("movementCandidate", moveStatus.movementCandidatePtr);
    pushPtr("movementDestination", moveStatus.destinationPtr);

    if (haveSnapshot) {
        lua_pushstring(L, "movementHead");
        lua_pushinteger(L, static_cast<lua_Integer>(snapshot.head));
        lua_settable(L, -3);

        lua_pushstring(L, "movementTail");
        lua_pushinteger(L, static_cast<lua_Integer>(snapshot.tail));
        lua_settable(L, -3);

        lua_pushstring(L, "movementPosX");
        lua_pushnumber(L, snapshot.posX);
        lua_settable(L, -3);

        lua_pushstring(L, "movementPosZ");
        lua_pushnumber(L, snapshot.posZ);
        lua_settable(L, -3);
    }

    std::string smokeReason;
    bool smokeOk = RunSmokeSelfTest(smokeReason);
    pushBool("smokeOk", smokeOk);
    if (!smokeOk && !smokeReason.empty()) {
        lua_pushstring(L, "smokeReason");
        lua_pushstring(L, smokeReason.c_str());
        lua_settable(L, -3);
        LogLuaState("ping smoke-fail reason=%s", smokeReason.c_str());
    }

    lua_pushstring(L, "cookie");
    lua_pushinteger(L, static_cast<lua_Integer>(Engine::GlobalStateCookie()));
    lua_settable(L, -3);

    return 1;
}

static int Lua_UOWSelfTest(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    LuaStateInfo info = EnsureHelperState(L, kHelperSelfTestName, &ready, &coalesced, nullptr);

    if (!info.L_canonical)
        info.L_canonical = L;

    lua_State* canonical = info.L_canonical ? info.L_canonical : L;

    LuaStateInfo stateInfo{};
    if (!g_stateRegistry.GetByPointer(canonical, stateInfo))
        stateInfo = info;

    MaybeAdoptOwnerThread(canonical, stateInfo);

    bool panicOk = false;
    bool debugOk = false;
    bool eventsOk = false;
    std::string failure;

    if (!IsOwnerThread(stateInfo)) {
        failure = "wrong-thread";
        LogLuaState("selftest abort wrong-thread L=%p owner=%lu current=%lu",
                    canonical,
                    stateInfo.owner_tid,
                    GetCurrentThreadId());
    } else if (!ProbeLua(L)) {
        failure = "probe-failed";
        LogLuaState("selftest abort probe-failed L=%p", canonical);
    } else {
        InstallPanicAndDebug(canonical, stateInfo);
        g_stateRegistry.GetByPointer(canonical, stateInfo);

        DWORD panicSeh = 0;
        lua_CFunction panicPtr = nullptr;
        if (SafeLuaQueryPanic(L, &panicPtr, &panicSeh)) {
            panicOk = (panicPtr == UOW_PanicThunk);
            if (!panicOk) {
                if (failure.empty())
                    failure = "panic-mismatch";
                LogLuaState("selftest panic mismatch L=%p got=%p expected=%p",
                            canonical,
                            panicPtr,
                            UOW_PanicThunk);
            }
        } else {
            if (failure.empty())
                failure = "panic-query-failed";
            LogLuaState("selftest panic query failed L=%p seh=0x%08lX", canonical, panicSeh);
        }

        bool prevEnabled = (stateInfo.debug_status == 1);
        uint32_t prevMode = stateInfo.debug_mode;
        uint32_t prevMask = stateInfo.debug_mask;
        uint32_t prevCount = stateInfo.debug_count;

        auto restoreConfig = [&]() {
            LuaStateInfo restoreInfo{};
            if (!g_stateRegistry.GetByPointer(canonical, restoreInfo))
                restoreInfo = stateInfo;
            DebugConfigRequest restoreReq{};
            if (prevEnabled) {
                restoreReq.mode = DEBUG_MODE_CUSTOM;
                restoreReq.mask = prevMask;
                restoreReq.count = prevCount;
                restoreReq.explicitMask = true;
                restoreReq.explicitCount = true;
            } else {
                restoreReq.mode = DEBUG_MODE_OFF;
            }
            DebugConfigResult restoreRes{};
            ApplyDebugConfigOnOwner(canonical, restoreInfo, restoreReq, restoreRes);
        };

        DebugConfigRequest enableReq{};
        enableReq.mode = DEBUG_MODE_CALLS;
        DebugConfigResult enableRes{};
        if (ApplyDebugConfigOnOwner(canonical, stateInfo, enableReq, enableRes)) {
            debugOk = (stateInfo.debug_status == 1);
            if (!debugOk && failure.empty())
                failure = "debug-enable-failed";
            if (!debugOk) {
                LogLuaState("selftest debug hook inactive L=%p", canonical);
            }
        } else {
            if (failure.empty())
                failure = enableRes.error.empty() ? "debug-enable-failed" : enableRes.error;
            LogLuaState("selftest debug enable failed L=%p err=%s seh=0x%08lX",
                        canonical,
                        enableRes.error.empty() ? "<unknown>" : enableRes.error.c_str(),
                        enableRes.seh);
        }

        uint64_t beforeEvents = stateInfo.hook_call_count +
                                stateInfo.hook_ret_count +
                                stateInfo.hook_line_count;

        int topBefore = 0;
        DWORD topBeforeSeh = 0;
        bool topCaptured = SafeLuaGetTop(canonical, stateInfo, &topBefore, &topBeforeSeh);
        if (!topCaptured) {
            if (failure.empty())
                failure = "gettop-failed";
            LogLuaState("selftest gettop failed L=%p seh=0x%08lX", canonical, topBeforeSeh);
        } else {
            DWORD runSeh = 0;
            if (!SafeLuaDoString(canonical, "local function f() return 1 end; return f()", &runSeh)) {
                if (failure.empty())
                    failure = "chunk-failed";
                LogLuaState("selftest chunk failed L=%p seh=0x%08lX", canonical, runSeh);
            } else {
                int newTop = 0;
                DWORD newTopSeh = 0;
                if (!SafeLuaGetTop(canonical, stateInfo, &newTop, &newTopSeh)) {
                    if (failure.empty())
                        failure = "post-gettop-failed";
                    LogLuaState("selftest post-gettop failed L=%p seh=0x%08lX", canonical, newTopSeh);
                } else if (!(newTop > topBefore && lua_isnumber(canonical, -1) && lua_tointeger(canonical, -1) == 1)) {
                    if (failure.empty())
                        failure = "chunk-result-invalid";
                    LogLuaState("selftest chunk result invalid L=%p", canonical);
                }
            }
            SafeLuaSetTop(canonical, stateInfo, topBefore, nullptr);
        }

        LuaStateInfo afterRun{};
        if (!g_stateRegistry.GetByPointer(canonical, afterRun))
            afterRun = stateInfo;
        uint64_t afterEvents = afterRun.hook_call_count +
                               afterRun.hook_ret_count +
                               afterRun.hook_line_count;
        eventsOk = (afterEvents > beforeEvents);
        if (!eventsOk) {
            LogLuaState("selftest no debug events L=%p before=%llu after=%llu",
                        canonical,
                        static_cast<unsigned long long>(beforeEvents),
                        static_cast<unsigned long long>(afterEvents));
            if (failure.empty())
                failure = "no-events";
        }

        restoreConfig();
    }

    lua_newtable(L);
    lua_pushstring(L, "panic");
    lua_pushboolean(L, panicOk ? 1 : 0);
    lua_settable(L, -3);
    lua_pushstring(L, "debug_installed");
    lua_pushboolean(L, debugOk ? 1 : 0);
    lua_settable(L, -3);
    lua_pushstring(L, "events_emitted");
    lua_pushboolean(L, eventsOk ? 1 : 0);
    lua_settable(L, -3);
    if (!failure.empty()) {
        lua_pushstring(L, "error");
        lua_pushstring(L, failure.c_str());
        lua_settable(L, -3);
    }
    return 1;
}

static int Lua_UOWRebindAll(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    EnsureHelperState(L, kHelperRebindName, &ready, &coalesced, nullptr);
    ForceRebindAll("lua-command");
    lua_pushboolean(L, 1);
    return 1;
}

static bool ResolveRegisterFunction() {
    if (g_registerResolved.load(std::memory_order_acquire))
        return true;

    void* addr = Engine::FindRegisterLuaFunction();
    if (!addr) {
        LogLuaProbe("resolve-register failed");
        return false;
    }

    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        LogLuaProbe("MH_Initialize failed");
        return false;
    }

    if (MH_CreateHook(addr, &RegLua_detour, reinterpret_cast<LPVOID*>(&g_origRegister)) != MH_OK ||
        MH_EnableHook(addr) != MH_OK) {
        LogLuaProbe("hook installation failed");
        g_origRegister = nullptr;
        return false;
    }

    g_registerTarget = addr;
    g_clientRegister = g_origRegister;
    InterlockedExchange(&g_flags.lua_tracer_attached, 1);
    g_registerResolved.store(true, std::memory_order_release);
    char tracerMsg[128];
    sprintf_s(tracerMsg, sizeof(tracerMsg), "[INFO][LUA] RegisterLuaFunction tracer attached at %p", addr);
    WriteRawLog(tracerMsg);
    LogLuaProbe("register-hook-installed target=%p", addr);
    return true;
}

// Game client exports RegisterLuaFunction with stdcall; keep the hook matched so the stack remains balanced.
static int __stdcall RegLua_detour(void* ctx, void* func, const char* name) {
    __try {
        const char* label = name ? name : "<null>";
        DebugRingTryWrite("[LUA][REG] name=\"%s\" fn=%p", label, func);
        InterlockedExchange(&g_flags.lua_reg_seen, 1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return RegisterHookImpl(ctx, func, name);
    }
    return RegisterHookImpl(ctx, func, name);
}

static int __stdcall RegisterHookImpl(void* ctx, void* func, const char* name) {
    if (func) {
        lua_CFunction original = reinterpret_cast<lua_CFunction>(func);
        lua_CFunction wrapped = MaybeWrapLuaFunction(name, original);
        if (wrapped != original)
            func = reinterpret_cast<void*>(wrapped);
    }

    DWORD tid = GetCurrentThreadId();
    lua_State* fromCtx = nullptr;
    lua_State* resolved = ResolveLuaState();
    if (ctx) {
        fromCtx = NormalizeLuaStatePointer(reinterpret_cast<lua_State*>(ctx));
        if (!ProbeLua(fromCtx))
            fromCtx = nullptr;
    }
    if (!ProbeLua(resolved))
        resolved = nullptr;

    lua_State* L = resolved ? resolved : fromCtx;
    if (!L)
        L = fromCtx;

    EnsureScriptThread(tid, L);

    LogLuaProbe("register name=%s fn=%p ctx=%p tid=%lu", name ? name : "<null>", func, ctx, tid);

    if (ctx && ctx != g_engineContext.load(std::memory_order_acquire)) {
        g_engineContext.store(ctx, std::memory_order_release);
        NoteContextMutation();
        void* previousCtx = g_loggedEngineContext.exchange(ctx, std::memory_order_acq_rel);
        if (ctx != previousCtx) {
            Log::Logf(Log::Level::Info,
                      Log::Category::Core,
                      "engine context discovered ctx=%p thread=%lu",
                      ctx,
                      static_cast<unsigned long>(tid));
        }
    }
    if (ctx)
        g_latestScriptCtx.store(ctx, std::memory_order_release);

    if (L) {
        uint64_t gen = g_generation.load(std::memory_order_acquire);
        bool isNew = false;
        bool ready = false;
        bool coalesced = false;
        LuaStateInfo snapshot = ObserveReportedState(L, ctx, tid, gen, name ? name : "register", &isNew, &ready, &coalesced);
        if (isNew) {
            LogLuaState("observed L=%p ctx=%p tid=%lu gen=%llu source=register", snapshot.L_reported, ctx, tid, gen);
            Log::Logf(Log::Level::Info,
                      Log::Category::Core,
                      "lua state discovered Lc=%p Lr=%p ctx=%p owner=%lu gen=%llu",
                      snapshot.L_canonical,
                      snapshot.L_reported,
                      ctx,
                      static_cast<unsigned long>(tid),
                      static_cast<unsigned long long>(gen));
        }
        uint64_t registerTick = GetTickCount64();
        lua_State* registerPtr = snapshot.L_canonical ? snapshot.L_canonical : L;
        if (registerPtr) {
            g_stateRegistry.UpdateByPointer(registerPtr, [&](LuaStateInfo& state) {
                state.register_last_tick_ms = registerTick;
                state.register_quiet_tick_ms = 0;
                state.flags &= ~(STATE_FLAG_REG_STABLE | STATE_FLAG_CANON_READY | STATE_FLAG_VALID);
            }, &snapshot);
        }
        if (!name || _stricmp(name, kHelperWalkName) != 0) {
            RequestBindForState(snapshot, name ? name : "register", false);
        }
    }

    if (L) {
        ProcessPendingLuaTasks(L);
        MaybeProcessHelperRetryQueue();
    }

    int rc = g_clientRegister ? g_clientRegister(ctx, func, name) : 0;
    return rc;
}

} // namespace

namespace Engine::Lua {

lua_State* GetCanonicalStateRelaxed() noexcept {
    return g_canonicalState.load(std::memory_order_acquire);
}

DWORD GetScriptThreadIdHint() noexcept {
    return g_scriptThreadId.load(std::memory_order_acquire);
}

void OnGlobalStateValidated(const GlobalStateInfo* info, std::uint32_t cookie) {
    if (!info || !info->luaState || cookie == 0)
        return;

    lua_State* raw = static_cast<lua_State*>(info->luaState);
    lua_State* canonical = NormalizeLuaStatePointer(raw);
    if (!canonical)
        canonical = raw;
    if (!canonical)
        return;

    uint64_t gen = g_generation.load(std::memory_order_acquire);
    uint64_t now = GetTickCount64();
    auto updater = [&](LuaStateInfo& state) {
        state.expected_global = reinterpret_cast<uintptr_t>(info);
        state.gc_gen = cookie;
        if (!state.slot_ready_tick_ms)
            state.slot_ready_tick_ms = now;
        state.flags |= STATE_FLAG_SLOT_READY;
        if (!state.L_canonical)
            state.L_canonical = canonical;
    };

    auto ensureAndUpdate = [&](lua_State* target) {
        if (!target)
            return;
        if (!g_stateRegistry.UpdateByPointer(target, updater)) {
            bool isNew = false;
            g_stateRegistry.EnsureForPointer(target, info->scriptContext, 0, gen, isNew);
            g_stateRegistry.UpdateByPointer(target, updater);
        }
    };

    ensureAndUpdate(canonical);
    if (raw != canonical)
        ensureAndUpdate(raw);

    g_canonicalState.store(canonical, std::memory_order_release);

    if (info->engineContext && canonical) {
        DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
        LuaStateInfo snapshot{};
        if (g_stateRegistry.GetByPointer(canonical, snapshot)) {
            DWORD canonicalOwner = GetCanonicalHelperOwnerTid();
            bool ownerAssigned = false;
            if (canonicalOwner) {
                g_stateRegistry.UpdateByPointer(canonical, [&](LuaStateInfo& state) {
                    if (state.owner_tid != canonicalOwner) {
                        state.owner_tid = canonicalOwner;
                        state.last_tid = canonicalOwner;
                    }
                    if ((state.flags & STATE_FLAG_OWNER_READY) == 0 || state.owner_ready_tick_ms == 0)
                        state.owner_ready_tick_ms = now;
                    state.flags |= (STATE_FLAG_OWNER_READY | STATE_FLAG_CANON_READY);
                    if (info->engineContext && state.ctx_reported != info->engineContext)
                        state.ctx_reported = info->engineContext;
                }, &snapshot);
                snapshot.owner_tid = canonicalOwner;
                snapshot.last_tid = canonicalOwner;
                if ((snapshot.flags & STATE_FLAG_OWNER_READY) == 0 || snapshot.owner_ready_tick_ms == 0)
                    snapshot.owner_ready_tick_ms = now;
                snapshot.flags |= (STATE_FLAG_OWNER_READY | STATE_FLAG_CANON_READY);
                if (info->engineContext && snapshot.ctx_reported != info->engineContext)
                    snapshot.ctx_reported = info->engineContext;
                ownerAssigned = true;
            }
            if (!ownerAssigned && scriptTid) {
                g_stateRegistry.UpdateByPointer(canonical, [&](LuaStateInfo& state) {
                    if (state.owner_tid == 0) {
                        state.owner_tid = scriptTid;
                        state.flags |= STATE_FLAG_OWNER_READY;
                        state.owner_ready_tick_ms = now;
                    }
                }, &snapshot);
                if (snapshot.owner_tid == 0) {
                    snapshot.owner_tid = scriptTid;
                    snapshot.flags |= STATE_FLAG_OWNER_READY;
                    snapshot.owner_ready_tick_ms = now;
                }
            }
            RequestBindForState(snapshot, "global-ready", false);
        }
    }
}


bool InitLuaBridge() {
    g_stateRegistry.Reset();
    g_generation.store(1, std::memory_order_release);
    g_lastMaintenanceTick.store(GetTickCount64(), std::memory_order_release);
    g_lastHelperSummaryTick.store(0, std::memory_order_release);
    g_helperScheduledCount.store(0, std::memory_order_release);
    g_helperInstalledCount.store(0, std::memory_order_release);
    g_helperDeferredCount.store(0, std::memory_order_release);
    g_helpersInstalledAny.store(false, std::memory_order_release);
    g_lastHelperOwnerThread.store(0, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lock(g_taskMutex);
        g_taskQueue.clear();
    }
    {
        std::lock_guard<std::mutex> lock(g_debugInstallMutex);
        g_debugInstallRetry.clear();
        g_debugInstallInFlight.clear();
    }
    g_queueLoggedDuringInit.store(false, std::memory_order_release);
    LogLuaState("registry-init ok cap=32");
    if (!ResolveRegisterFunction())
        return false;
    ScheduleWalkBinding();
    StartHelperPumpThread();
    return true;
}

void ShutdownLuaBridge() {
    StopHelperPumpThread();
    DebugRingFlush();
    if (g_registerTarget) {
        MH_DisableHook(g_registerTarget);
        MH_RemoveHook(g_registerTarget);
        g_registerTarget = nullptr;
    }
    g_origRegister = nullptr;
    g_clientRegister = nullptr;
    g_registerResolved.store(false, std::memory_order_release);

    {
        std::lock_guard<std::mutex> lock(g_taskMutex);
        g_taskQueue.clear();
    }
    {
        std::lock_guard<std::mutex> lock(g_debugInstallMutex);
        g_debugInstallRetry.clear();
        g_debugInstallInFlight.clear();
    }

    g_stateRegistry.Reset();
    g_mainLuaState.store(nullptr, std::memory_order_release);
    g_mainLuaPlusState.store(nullptr, std::memory_order_release);
    g_scriptThreadId.store(0, std::memory_order_release);
    Util::OwnerPump::Reset();
    g_engineContext.store(nullptr, std::memory_order_release);
    g_latestScriptCtx.store(nullptr, std::memory_order_release);
    NoteContextMutation();
}

void RegisterOurLuaFunctions() {
    ScheduleWalkBinding();
}

void GetStartupStatus(StartupStatus& out) {
    out.engineContextDiscovered = g_engineContext.load(std::memory_order_acquire) != nullptr;
    out.luaStateDiscovered = g_canonicalState.load(std::memory_order_acquire) != nullptr;
    out.helpersInstalled = g_helpersInstalledAny.load(std::memory_order_acquire);
    DWORD owner = g_lastHelperOwnerThread.load(std::memory_order_relaxed);
    if (owner == 0)
        owner = GetCanonicalHelperOwnerTid();
    out.ownerThreadId = owner;
}
const char* GetHelperStageSummary() {
    lua_State* canonical = g_canonicalState.load(std::memory_order_acquire);
    if (canonical) {
        LuaStateInfo info{};
        if (g_stateRegistry.GetByPointer(canonical, info))
            return HelperStageName(static_cast<HelperInstallStage>(info.helper_state));
    }
    if (g_helpersInstalledAny.load(std::memory_order_acquire))
        return "installed";
    return "waiting_for_global_state";
}


void UpdateEngineContext(void* context) {
    g_engineContext.store(context, std::memory_order_release);
    NoteContextMutation();
    DWORD threadId = GetCurrentThreadId();
    void* previous = g_loggedEngineContext.exchange(context, std::memory_order_acq_rel);
    if (context && context != previous) {
        void* priorCanonical = GetCanonicalHelperCtx();
        DWORD priorOwner = GetCanonicalHelperOwnerTid();
        SetCanonicalHelperCtx(context, threadId);
        void* canonical = GetCanonicalHelperCtx();
        DWORD canonicalOwner = GetCanonicalHelperOwnerTid();
        bool canonicalMatch = canonical && context == canonical;
        bool canonicalNew = (!priorCanonical && canonicalMatch);
        bool ownerPromoted = (canonicalMatch && priorOwner == 0 && canonicalOwner != 0);

        if (canonicalNew) {
            Log::Logf(Log::Level::Info,
                      Log::Category::Core,
                      "[ENGINE][CTX] canonical ctx=%p owner=%lu",
                      canonical,
                      static_cast<unsigned long>(canonicalOwner));
            Log::Logf(Log::Level::Info,
                      Log::Category::Core,
                      "engine context discovered ctx=%p owner=%lu thread=%lu (canonical)",
                      context,
                      static_cast<unsigned long>(canonicalOwner),
                      static_cast<unsigned long>(threadId));
        } else if (canonicalMatch) {
            Log::Logf(Log::Level::Info,
                      Log::Category::Core,
                      "engine context discovered ctx=%p owner=%lu thread=%lu (canonical)",
                      context,
                      static_cast<unsigned long>(canonicalOwner),
                      static_cast<unsigned long>(threadId));
        } else if (canonical && context != canonical) {
            Log::Logf(Log::Level::Info,
                      Log::Category::Core,
                      "[ENGINE][CTX_ALT] ctx=%p owner=%lu (canonical=%p/%lu)",
                      context,
                      static_cast<unsigned long>(threadId),
                      canonical,
                      static_cast<unsigned long>(canonicalOwner));
        } else {
            Log::Logf(Log::Level::Info,
                      Log::Category::Core,
                      "engine context discovered ctx=%p thread=%lu",
                      context,
                      static_cast<unsigned long>(threadId));
        }

        if (ownerPromoted && !canonicalNew) {
            Log::Logf(Log::Level::Info,
                      Log::Category::Core,
                      "[ENGINE][CTX] canonical owner assigned ctx=%p owner=%lu",
                      canonical,
                      static_cast<unsigned long>(canonicalOwner));
        }

        if (canonicalMatch) {
            Core::StartupSummary::NotifyEngineContextReady();
            Net::OnEngineReady();
            bool expected = false;
            if (g_engineVtableLogged.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                __try {
                    void** vtable = context ? *reinterpret_cast<void***>(context) : nullptr;
                    void* entry0 = (vtable && vtable[0]) ? vtable[0] : nullptr;
                    void* entry1 = (vtable && vtable[1]) ? vtable[1] : nullptr;
                    void* entry2 = (vtable && vtable[2]) ? vtable[2] : nullptr;
                    void* entry3 = (vtable && vtable[3]) ? vtable[3] : nullptr;
                    Log::Logf(Log::Level::Info,
                              Log::Category::Core,
                              "[ENGINE][CTX] ctx=%p vtable=%p entry0=%p entry1=%p entry2=%p entry3=%p",
                              context,
                              vtable,
                              entry0,
                              entry1,
                              entry2,
                              entry3);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    Log::Logf(Log::Level::Warn,
                              Log::Category::Core,
                              "[ENGINE][CTX] ctx=%p vtable-inspect-failed seh=0x%08lX",
                              context,
                              GetExceptionCode());
                    g_engineVtableLogged.store(false, std::memory_order_release);
                }
            }
        }
    }
    LogLuaProbe("engine-context=%p", context);
    ScheduleWalkBinding();
}

void EnsureWalkBinding(const char* /*reason*/) {
    ScheduleWalkBinding();
}

void ScheduleWalkBinding() {
    auto snapshot = g_stateRegistry.Snapshot();
    if (snapshot.empty()) {
        lua_State* existing = ResolveLuaState();
        if (existing) {
            uint64_t gen = g_generation.load(std::memory_order_acquire);
            DWORD tid = g_scriptThreadId.load(std::memory_order_acquire);
            void* ctx = g_latestScriptCtx.load(std::memory_order_acquire);
            if (ctx)
                SetCanonicalHelperCtx(ctx, tid);
            bool isNew = false;
            bool ready = false;
            bool coalesced = false;
            LuaStateInfo info = ObserveReportedState(existing, ctx, tid, gen, "schedule", &isNew, &ready, &coalesced);
            snapshot.push_back(info);
        }
    }

    for (const auto& info : snapshot) {
        RequestBindForState(info, "schedule", false);
    }
}

void ProcessLuaQueue() {
    lua_State* L = ResolveLuaState();
    EnsureScriptThread(GetCurrentThreadId(), L);
    if (L) {
        int remaining = g_statusShimWatchdogBudget.load(std::memory_order_relaxed);
        while (remaining > 0) {
            if (g_statusShimWatchdogBudget.compare_exchange_weak(remaining,
                                                                 remaining - 1,
                                                                 std::memory_order_acq_rel,
                                                                 std::memory_order_relaxed)) {
                ReassertBinding(L, kHelperStatusFlagsName, Lua_UOW_StatusFlagsShim);
                ReassertBinding(L, kHelperStatusFlagsAliasName, Lua_UOW_StatusFlagsExShim);
                break;
            }
        }
        uint32_t verifyMask = g_statusShimVerifyMask.exchange(0u, std::memory_order_acq_rel);
        if (verifyMask & kVerifyStatusFlagsBit)
            LogGlobalFn(L, kHelperStatusFlagsName);
        if (verifyMask & kVerifyStatusFlagsExBit)
            LogGlobalFn(L, kHelperStatusFlagsAliasName);
    }
    ProcessPendingLuaTasks(L);
    MaybeProcessHelperRetryQueue();
    MaybeRunMaintenance();
}

void OnStateObserved(lua_State* L, void* scriptCtx, std::uint32_t ownerTid, bool adoptThread) {
    if (!L)
        return;
    uint64_t gen = g_generation.load(std::memory_order_acquire);
    DWORD tid = ownerTid ? ownerTid : GetCurrentThreadId();
    if (adoptThread)
        EnsureScriptThread(tid, L);
    if (scriptCtx)
        g_latestScriptCtx.store(scriptCtx, std::memory_order_release);
    if (scriptCtx)
        SetCanonicalHelperCtx(scriptCtx, tid);

    bool isNew = false;
    bool ready = false;
    bool coalesced = false;
    LuaStateInfo snapshot = ObserveReportedState(L, scriptCtx, tid, gen, "external", &isNew, &ready, &coalesced);
    if (isNew) {
        LogLuaState("observed L=%p ctx=%p tid=%lu gen=%llu source=external", snapshot.L_reported, scriptCtx, tid, gen);
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "lua state discovered Lc=%p Lr=%p ctx=%p owner=%lu gen=%llu",
                  snapshot.L_canonical,
                  snapshot.L_reported,
                  scriptCtx,
                  static_cast<unsigned long>(tid),
                  static_cast<unsigned long long>(gen));
    }
    RequestBindForState(snapshot, "state-observed", false);
}

void OnStateRemoved(lua_State* L, const char* reason) {
    if (!L)
        return;
    LuaStateInfo info{};
    if (g_stateRegistry.RemoveByPointer(L, &info)) {
        LogLuaState("removed Lc=%p (Lr=%p ctx=%p) tid=%lu reason=%s",
                    info.L_canonical ? info.L_canonical : L,
                    info.L_reported,
                    info.ctx_reported,
                    info.owner_tid,
                    reason ? reason : "unknown");
        lua_State* canonical = g_canonicalState.load(std::memory_order_acquire);
        if (canonical && (canonical == info.L_canonical || canonical == L))
            g_canonicalState.store(nullptr, std::memory_order_release);
        NoteDestabilization("state-removed", reason);
    }
}

void GetHelperProbeStats(uint32_t& attempted, uint32_t& succeeded, uint32_t& skipped) {
    attempted = g_helperProbeAttempted.load(std::memory_order_acquire);
    succeeded = g_helperProbeSuccess.load(std::memory_order_acquire);
    skipped = g_helperProbeSkipped.load(std::memory_order_acquire);
}

uint32_t GetSehTrapCount() {
    return g_sehTrapCount.load(std::memory_order_acquire);
}



} // namespace Engine::Lua

















