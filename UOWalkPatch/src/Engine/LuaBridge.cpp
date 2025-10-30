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
#include <limits>

#include <minhook.h>

#include "Core/Config.hpp"
#include "Core/Logging.hpp"
#include "Engine/GlobalState.hpp"
#include "Engine/LuaBridge.hpp"
#include "Engine/LuaStateRegistry.hpp"
#include "Engine/Movement.hpp"
#include "Walk/WalkController.hpp"
#include "Engine/lua_safe.h"

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
static std::atomic<bool> g_helpersInstalledAny{false};
static std::atomic<DWORD> g_lastHelperOwnerThread{0};
static std::atomic<uint64_t> g_lastHelperRetryScanTick{0};

struct HelperRetryPolicy {
    uint32_t retryMax = 3;
    uint32_t retryWindowMs = 1500;
    uint32_t stableWindowMs = 250;
    uint32_t retryBackoffMs = 150;
};

static HelperRetryPolicy g_helperRetryPolicy{};
static std::once_flag g_helperRetryPolicyOnce;

static std::mutex g_taskMutex;
static std::deque<LuaTask> g_taskQueue;
static thread_local bool g_processingLuaQueue = false;
static std::atomic<bool> g_queueLoggedDuringInit{false};
static std::atomic<DWORD> g_lastQueueLogTick{0};

static std::mutex g_bindingMutex;
static std::unordered_set<lua_State*> g_bindingInFlight;

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

    uint32_t value = 0;
    if (auto envMax = Core::Config::TryGetEnv("LUA_HELPERS_RETRYMAX")) {
        if (ParseUint32(*envMax, value))
            policy.retryMax = value;
    } else if (auto cfgMax = Core::Config::TryGetUInt("lua.helpers.retryMax")) {
        policy.retryMax = *cfgMax;
    }

    if (auto envWindow = Core::Config::TryGetEnv("LUA_HELPERS_RETRYWINDOWMS")) {
        if (ParseUint32(*envWindow, value))
            policy.retryWindowMs = value;
    } else if (auto cfgWindow = Core::Config::TryGetUInt("lua.helpers.retryWindowMs")) {
        policy.retryWindowMs = *cfgWindow;
    }

    policy.retryMax = std::clamp<uint32_t>(policy.retryMax, 1u, 16u);
    policy.retryWindowMs = std::clamp<uint32_t>(policy.retryWindowMs, 250u, 8000u);

    const uint32_t derivedStable = std::clamp<uint32_t>(policy.retryWindowMs / 4u, 150u, 1000u);
    const uint32_t retryDivisor = std::max(policy.retryMax, static_cast<uint32_t>(1));
    const uint32_t derivedBackoff = std::clamp<uint32_t>(policy.retryWindowMs / retryDivisor, 50u, 500u);

    policy.stableWindowMs = derivedStable;
    policy.retryBackoffMs = derivedBackoff;

    g_helperRetryPolicy = policy;

    Log::Logf(Log::Level::Debug,
              Log::Category::Hooks,
              "helper-retry policy retryMax=%u retryWindowMs=%u stableWindowMs=%u retryBackoffMs=%u",
              policy.retryMax,
              policy.retryWindowMs,
              policy.stableWindowMs,
              policy.retryBackoffMs);
}

static const HelperRetryPolicy& GetHelperRetryPolicy() {
    std::call_once(g_helperRetryPolicyOnce, LoadHelperRetryPolicy);
    return g_helperRetryPolicy;
}

static void ClearHelperPending(lua_State* L, uint64_t generation, LuaStateInfo* infoOut = nullptr) {
    if (!L)
        return;
    g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
        if (generation == 0 || state.helper_pending_generation == generation) {
            state.flags &= ~STATE_FLAG_HELPERS_PENDING;
            state.helper_pending_generation = 0;
            state.helper_pending_tick_ms = 0;
        }
    }, infoOut);
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
    if (scheduled || installed || deferred) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "helpers summary scheduled=%u installed=%u deferred=%u",
                  scheduled,
                  installed,
                  deferred);
    }
}

static constexpr const char* kHelperWalkName = "uow_walk";
static constexpr const char* kHelperDumpName = "uow_dump_walk_env";
static constexpr const char* kHelperInspectName = "uow_lua_inspect";
static constexpr const char* kHelperRebindName = "uow_lua_rebind_all";
static constexpr const char* kHelperSelfTestName = "uow_selftest";
static constexpr const char* kHelperDebugName = "uow_debug";
static constexpr const char* kHelperDebugStatusName = "uow_debug_status";
static constexpr const char* kHelperDebugPingName = "uow_debug_ping";
static char g_hookSentinelKey = 0;

static void LogLuaBind(const char* fmt, ...);
static void LogLuaState(const char* fmt, ...);
static bool DebugInstrumentationEnabled();

static std::atomic<uint64_t> g_lastContextMutationTick{0};
static std::atomic<uint64_t> g_lastDestabilizedTick{0};
static std::atomic<uint64_t> g_lastCanonicalReadyTick{0};
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
static bool BindHelpersOnThread(lua_State* L, const LuaStateInfo& info, uint64_t generation, bool force);
static void MaybeProcessHelperRetryQueue();
static void InstallPanicAndDebug(lua_State* L, LuaStateInfo& info);
static bool RegisterHelper(lua_State* L, const LuaStateInfo& info, const char* name, lua_CFunction fn, uint64_t generation);
static void DumpWalkEnv(lua_State* L, const char* reason);
static int Lua_UOWalk(lua_State* L);
static int Lua_UOWDump(lua_State* L);
static int Lua_UOWInspect(lua_State* L);
static int Lua_UOWSelfTest(lua_State* L);
static int Lua_UOWRebindAll(lua_State* L);
static int Lua_UOWDebug(lua_State* L);
static int Lua_UOWDebugStatus(lua_State* L);
static int Lua_UOWDebugPing(lua_State* L);
static int __cdecl HookSentinelGC(lua_State* L);
static void ForceRebindAll(const char* reason);
static bool ResolveRegisterFunction();
static int __stdcall Hook_Register(void* ctx, void* func, const char* name);
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

    const char* helpers[] = { kHelperWalkName, kHelperDumpName, kHelperInspectName, kHelperRebindName, kHelperSelfTestName };
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

static bool AcquireBindingSlot(lua_State* L) {
    std::lock_guard<std::mutex> lock(g_bindingMutex);
    return g_bindingInFlight.insert(L).second;
}

static void ReleaseBindingSlot(lua_State* L) {
    std::lock_guard<std::mutex> lock(g_bindingMutex);
    g_bindingInFlight.erase(L);
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
    if (g_scriptThreadId.compare_exchange_strong(expected, tid)) {
        LogLuaQ("tid=%lu script-thread-discovered L=%p", tid, L);
    }

    if (g_scriptThreadId.load(std::memory_order_acquire) == tid && L) {
        lua_State* prev = g_mainLuaState.exchange(L, std::memory_order_acq_rel);
        if (prev != L) {
            LogLuaQ("tid=%lu main-state-updated L=%p (prev=%p)", tid, L, prev);
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
    {
        std::lock_guard<std::mutex> lock(g_taskMutex);
        if (g_taskQueue.empty()) {
            MaybeLogQueueDrain(L, tid, "empty");
            return;
        }
        local.swap(g_taskQueue);
    }

    g_processingLuaQueue = true;

    if (!g_queueLoggedDuringInit.exchange(true, std::memory_order_acq_rel)) {
        LogLuaQueueDrain(L, tid, "start");
    }

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
    }

    g_processingLuaQueue = false;
    MaybeLogQueueDrain(L, tid, "processed");
}

static void PostToLuaThread(lua_State* L, const char* name, std::function<void(lua_State*)> fn) {
    DWORD fromTid = GetCurrentThreadId();
    {
        std::lock_guard<std::mutex> lock(g_taskMutex);
        g_taskQueue.push_back(LuaTask{ name ? name : "<lambda>", L, std::move(fn) });
    }
    LogLuaQ("post fn=%s L=%p from=tid=%lu", name ? name : "<lambda>", L, fromTid);

    DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
    if (scriptTid != 0 && scriptTid == fromTid && L && !g_processingLuaQueue) {
        ProcessPendingLuaTasks(L);
    }
}

static void MaybeAdoptOwnerThread(lua_State* L, LuaStateInfo& info) {
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
    if (haveInfo) {
        owner = info.owner_tid ? info.owner_tid : g_scriptThreadId.load(std::memory_order_acquire);
    } else {
        owner = g_scriptThreadId.load(std::memory_order_acquire);
    }

    DWORD from = GetCurrentThreadId();
    const char* name = taskName ? taskName : "<owner>";

    if (owner && owner == from && haveInfo) {
        Log::Logf("[Bind] owner-inline L=%p owner=%lu task=%s", L, owner, name);
        fn();
        return;
    }

    std::string taskLabel = name;
    Log::Logf("[Bind] posted-to-owner L=%p from=%lu -> owner=%lu task=%s", L, from, owner, taskLabel.c_str());
    PostToLuaThread(L, name, [fn = std::move(fn), taskLabel = std::move(taskLabel), owner, L](lua_State*) mutable {
        Log::Logf("[Bind] owner-run L=%p owner=%lu runner=%lu task=%s",
                  L,
                  owner,
                  GetCurrentThreadId(),
                  taskLabel.c_str());
        fn();
    });
}

static void PostToOwner(lua_State* L, std::function<void()> fn) {
    PostToOwnerWithTask(L, "<owner>", std::move(fn));
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
    for (const auto& info : snapshot) {
        bool installed = (info.flags & STATE_FLAG_HELPERS_INSTALLED) && info.gen == generation;
        if (installed)
            continue;
        if (info.flags & STATE_FLAG_HELPERS_PENDING)
            continue;
        if (info.helper_next_retry_ms == 0)
            continue;
        if (now < info.helper_next_retry_ms)
            continue;
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "helpers retry scheduling L=%p owner=%lu retries=%u next=%llu now=%llu",
                  info.L_canonical ? info.L_canonical : info.L_reported,
                  static_cast<unsigned long>(info.owner_tid),
                  static_cast<unsigned>(info.helper_retry_count),
                  static_cast<unsigned long long>(info.helper_next_retry_ms),
                  static_cast<unsigned long long>(now));
        RequestBindForState(info, "retry", false);
    }
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
        uint64_t now = GetTickCount64();
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
        TrackHelperEvent(g_helperDeferredCount);
        MaybeEmitHelperSummary(now);
        return;
    }

    lua_State* target = current.L_canonical;
    uint64_t generation = g_generation.load(std::memory_order_acquire);
    uint64_t now = GetTickCount64();
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
}
    bool skipDueToPending = false;

    if (!force) {
        g_stateRegistry.UpdateByPointer(target, [&](LuaStateInfo& state) {
            if ((state.flags & STATE_FLAG_HELPERS_PENDING) && state.helper_pending_generation == generation) {
                skipDueToPending = true;
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

    const HelperRetryPolicy& retry = GetHelperRetryPolicy();
    const uint64_t mutationTick = g_lastContextMutationTick.load(std::memory_order_acquire);

    bool allowNow = force;
    if (!force) {
        bool canonicalStable = canonicalReadyFlag;
        uint64_t readyTick = current.canonical_ready_tick_ms;
        if (!canonicalStable && readyTick && now >= readyTick) {
            uint64_t readyAge = now - readyTick;
            if (readyAge >= retry.stableWindowMs)
                canonicalStable = true;
        }

        uint64_t sinceFirst = current.helper_first_attempt_ms
                                  ? (now - current.helper_first_attempt_ms)
                                  : 0;
        bool attemptsExceeded = retry.retryMax > 0 && current.helper_retry_count >= retry.retryMax;
        bool windowExceeded = current.helper_first_attempt_ms != 0 && sinceFirst >= retry.retryWindowMs;
        bool forcedByRetry = false;
        if (!canonicalStable && (attemptsExceeded || windowExceeded)) {
            canonicalStable = true;
            forcedByRetry = true;
        }

        allowNow = canonicalStable;
        if (allowNow) {
            if (!forcedByRetry && current.helper_next_retry_ms && now < current.helper_next_retry_ms)
                allowNow = false;
        }

        if (allowNow && (attemptsExceeded || windowExceeded)) {
            bool logOverride = false;
            const char* overrideReason = nullptr;
            if (attemptsExceeded && retry.retryMax > 0 && current.helper_retry_count == retry.retryMax) {
                logOverride = true;
                overrideReason = "retry-max";
            } else if (windowExceeded && sinceFirst >= retry.retryWindowMs) {
                uint64_t windowDelta = sinceFirst - retry.retryWindowMs;
                if (windowDelta < retry.retryBackoffMs) {
                    logOverride = true;
                    overrideReason = "retry-window";
                }
            }
            if (logOverride) {
                Log::Logf(Log::Level::Info,
                          Log::Category::Hooks,
                          "helpers gating override L=%p reason=%s retries=%u ageMs=%llu action=%s",
                          target,
                          overrideReason ? overrideReason : "unknown",
                          static_cast<unsigned>(current.helper_retry_count),
                          static_cast<unsigned long long>(sinceFirst),
                          action);
            }
        }

        if (!allowNow && mutationTick > current.helper_last_mutation_tick_ms)
            allowNow = true;
    }

    if (!allowNow) {
        g_stateRegistry.UpdateByPointer(target, [&](LuaStateInfo& state) {
            if (!state.helper_first_attempt_ms)
                state.helper_first_attempt_ms = now;
            if (mutationTick > state.helper_last_mutation_tick_ms) {
                state.helper_last_mutation_tick_ms = mutationTick;
                state.helper_retry_count = 0;
                state.helper_first_attempt_ms = now;
            }
            uint64_t minNext = now + retry.retryBackoffMs;
            if (state.helper_next_retry_ms == 0 || state.helper_next_retry_ms < minNext)
                state.helper_next_retry_ms = minNext;
        }, &current);
        ClearHelperPending(target, generation, &current);
        TrackHelperEvent(g_helperDeferredCount);
        MaybeEmitHelperSummary(now);
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "helpers skip Lc=%p reason=not-ready nextRetry=%llu gen=%llu action=%s",
                  target,
                  static_cast<unsigned long long>(current.helper_next_retry_ms),
                  static_cast<unsigned long long>(generation),
                  action);
        return;
    }

    g_stateRegistry.UpdateByPointer(target, [&](LuaStateInfo& state) {
        state.flags |= STATE_FLAG_HELPERS_PENDING;
        state.helper_pending_generation = generation;
        state.helper_pending_tick_ms = now;
        if (!state.helper_first_attempt_ms)
            state.helper_first_attempt_ms = now;
        state.helper_last_attempt_ms = now;
        state.helper_next_retry_ms = now + retry.retryBackoffMs;
        if (state.helper_retry_count < std::numeric_limits<uint32_t>::max())
            ++state.helper_retry_count;
        if (mutationTick > state.helper_last_mutation_tick_ms)
            state.helper_last_mutation_tick_ms = mutationTick;
    }, &current);

    TrackHelperEvent(g_helperScheduledCount);
    MaybeEmitHelperSummary(now);

    DWORD owner = current.owner_tid ? current.owner_tid : g_scriptThreadId.load(std::memory_order_acquire);

    if (owner && owner == GetCurrentThreadId()) {
        BindHelpersTask(target, generation, force, action);
    } else {
        std::string reasonCopy = action;
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
    bool panicOk = EnsurePanicHookOnOwner(L, info, &panicChanged, &panicSeh);

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

static bool RegisterHelper(lua_State* L, const LuaStateInfo& info, const char* name, lua_CFunction fn, uint64_t generation) {
    bool registered = false;
    DWORD seh = 0;

    if (g_clientRegister && info.ctx_reported) {
        __try {
            g_clientRegister(info.ctx_reported, reinterpret_cast<void*>(fn), name);
            registered = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            seh = GetExceptionCode();
            registered = false;
            LogLuaBind("fail name=%s L=%p reason=register-call-exception seh=0x%08lX ctx=%p", name, L, seh, info.ctx_reported);
        }
    }

    if (!registered) {
        __try {
            lua_pushcfunction(L, fn);
            lua_setglobal(L, name);
            registered = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            seh = GetExceptionCode();
            registered = false;
            LogLuaBind("fail name=%s L=%p reason=fallback-exception seh=0x%08lX", name, L, seh);
        }
    }

    if (registered) {
        LogLuaBind("ok name=%s L=%p ctx=%p tid=%lu gen=%llu", name, L, info.ctx_reported, info.owner_tid, generation);
    }
    return registered;
}

static bool BindHelpersOnThread(lua_State* L, const LuaStateInfo& originalInfo, uint64_t generation, bool force) {
    if (!L)
        return false;

    LuaStateInfo info = originalInfo;

    MaybeAdoptOwnerThread(L, info);

    if (!IsOwnerThread(info)) {
        LogLuaBind("bind-helpers wrong-thread L=%p owner=%lu current=%lu",
                   L,
                   info.owner_tid,
                   static_cast<unsigned long>(GetCurrentThreadId()));
        return false;
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

    const bool probeOk = ProbeLua(L);
    g_stateRegistry.GetByPointer(L, info);

    bool ok = probeOk;
    if (!probeOk) {
        LogLuaBind("bind-helpers probe-failed L=%p", L);
        Log::Logf(Log::Level::Warn,
                  Log::Category::Hooks,
                  "helpers install probe failed L=%p owner=%lu gen=%llu",
                  L,
                  static_cast<unsigned long>(info.owner_tid),
                  static_cast<unsigned long long>(generation));
    }
    if (probeOk) {
        bool helpersBound = (info.flags & STATE_FLAG_HELPERS_BOUND) && info.gen == generation;
        if (force || !helpersBound) {
            bool walkOk = RegisterHelper(L, info, kHelperWalkName, Lua_UOWalk, generation);
            bool dumpOk = RegisterHelper(L, info, kHelperDumpName, Lua_UOWDump, generation);
            bool inspectOk = RegisterHelper(L, info, kHelperInspectName, Lua_UOWInspect, generation);
            bool rebindOk = RegisterHelper(L, info, kHelperRebindName, Lua_UOWRebindAll, generation);
            bool selfTestOk = RegisterHelper(L, info, kHelperSelfTestName, Lua_UOWSelfTest, generation);
            bool debugCfgOk = RegisterHelper(L, info, kHelperDebugName, Lua_UOWDebug, generation);
            bool debugStatusOk = RegisterHelper(L, info, kHelperDebugStatusName, Lua_UOWDebugStatus, generation);
            bool debugPingOk = RegisterHelper(L, info, kHelperDebugPingName, Lua_UOWDebugPing, generation);
            bool allOk = walkOk && dumpOk && inspectOk && rebindOk && selfTestOk && debugCfgOk && debugStatusOk && debugPingOk;
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
                }, &info);
                Log::Logf(Log::Level::Info,
                          Log::Category::Hooks,
                          "helpers installed L=%p owner=%lu gen=%llu thread=%lu",
                          L,
                          static_cast<unsigned long>(info.owner_tid),
                          static_cast<unsigned long long>(generation),
                          static_cast<unsigned long>(GetCurrentThreadId()));
                g_helpersInstalledAny.store(true, std::memory_order_release);
                g_lastHelperOwnerThread.store(static_cast<DWORD>(info.owner_tid), std::memory_order_relaxed);
            } else {
                ok = false;
                std::string missing;
                auto appendMissing = [&](bool valueOk, const char* name) {
                    if (valueOk)
                        return;
                    if (!missing.empty())
                        missing.append(",");
                    missing.append(name);
                };
                appendMissing(walkOk, kHelperWalkName);
                appendMissing(dumpOk, kHelperDumpName);
                appendMissing(inspectOk, kHelperInspectName);
                appendMissing(rebindOk, kHelperRebindName);
                appendMissing(selfTestOk, kHelperSelfTestName);
                appendMissing(debugCfgOk, kHelperDebugName);
                appendMissing(debugStatusOk, kHelperDebugStatusName);
                appendMissing(debugPingOk, kHelperDebugPingName);
                Log::Logf(Log::Level::Warn,
                          Log::Category::Hooks,
                          "helpers install failed L=%p owner=%lu gen=%llu missing=[%s]",
                          L,
                          static_cast<unsigned long>(info.owner_tid),
                          static_cast<unsigned long long>(generation),
                          missing.empty() ? "unknown" : missing.c_str());
            }
        }
    }

    InstallPanicAndDebug(L, info);
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

    if (!IsOwnerThread(info)) {
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

    if (!AcquireBindingSlot(L)) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Hooks,
                  "helpers in-progress skip L=%p owner=%lu",
                  L,
                  static_cast<unsigned long>(info.owner_tid));
        ClearHelperPending(L, generation, &info);
        return;
    }

    LogLuaState("bind-start Lc=%p (Lr=%p ctx=%p) tid=%lu gen=%llu reason=%s",
                L,
                info.L_reported,
                info.ctx_reported,
                info.owner_tid,
                static_cast<unsigned long long>(generation),
                reason ? reason : "unknown");

    bool ok = BindHelpersOnThread(L, info, generation, force);
    ReleaseBindingSlot(L);
    ClearHelperPending(L, generation, &info);
    uint64_t summaryTick = GetTickCount64();
    if (ok) {
        TrackHelperEvent(g_helperInstalledCount);
        MaybeEmitHelperSummary(summaryTick, true);
    } else {
        TrackHelperEvent(g_helperDeferredCount);
        const HelperRetryPolicy& retry = GetHelperRetryPolicy();
        g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
            uint64_t next = summaryTick + retry.retryBackoffMs;
            if (state.helper_next_retry_ms == 0 || state.helper_next_retry_ms < next)
                state.helper_next_retry_ms = next;
        });
        MaybeEmitHelperSummary(summaryTick);
    }
    if (!ok) {
        LogLuaState("bind-fail Lc=%p ctx=%p gen=%llu", L, info.ctx_reported, static_cast<unsigned long long>(generation));
    } else {
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

    if (MH_CreateHook(addr, &Hook_Register, reinterpret_cast<LPVOID*>(&g_origRegister)) != MH_OK ||
        MH_EnableHook(addr) != MH_OK) {
        LogLuaProbe("hook installation failed");
        g_origRegister = nullptr;
        return false;
    }

    g_registerTarget = addr;
    g_clientRegister = g_origRegister;
    g_registerResolved.store(true, std::memory_order_release);
    LogLuaProbe("register-hook-installed target=%p", addr);
    return true;
}

// Game client exports RegisterLuaFunction with stdcall; keep the hook matched so the stack remains balanced.
static int __stdcall Hook_Register(void* ctx, void* func, const char* name) {
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
    g_bindingInFlight.clear();
    LogLuaState("registry-init ok cap=32");
    if (!ResolveRegisterFunction())
        return false;
    ScheduleWalkBinding();
    return true;
}

void ShutdownLuaBridge() {
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

    g_bindingInFlight.clear();
    g_stateRegistry.Reset();
    g_mainLuaState.store(nullptr, std::memory_order_release);
    g_mainLuaPlusState.store(nullptr, std::memory_order_release);
    g_scriptThreadId.store(0, std::memory_order_release);
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
    out.ownerThreadId = g_lastHelperOwnerThread.load(std::memory_order_relaxed);
}

void UpdateEngineContext(void* context) {
    g_engineContext.store(context, std::memory_order_release);
    NoteContextMutation();
    void* previous = g_loggedEngineContext.exchange(context, std::memory_order_acq_rel);
    if (context && context != previous) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "engine context discovered ctx=%p thread=%lu",
                  context,
                  static_cast<unsigned long>(GetCurrentThreadId()));
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
    ProcessPendingLuaTasks(L);
    MaybeProcessHelperRetryQueue();
    MaybeRunMaintenance();
}

void OnStateObserved(lua_State* L, void* scriptCtx, std::uint32_t ownerTid) {
    if (!L)
        return;
    uint64_t gen = g_generation.load(std::memory_order_acquire);
    DWORD tid = ownerTid ? ownerTid : GetCurrentThreadId();
    EnsureScriptThread(tid, L);
    if (scriptCtx)
        g_latestScriptCtx.store(scriptCtx, std::memory_order_release);

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



} // namespace Engine::Lua






