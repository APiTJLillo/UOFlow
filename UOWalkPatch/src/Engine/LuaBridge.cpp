#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cctype>
#include <atomic>
#include <string>
#include <deque>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <vector>
#include <array>
#include <chrono>
#include <cstdarg>
#include <sstream>

#include <minhook.h>

#include "Core/Logging.hpp"
#include "Engine/GlobalState.hpp"
#include "Engine/LuaBridge.hpp"
#include "Engine/Movement.hpp"

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
    LUA_API void lua_pushvalue(lua_State* L, int idx);
    LUA_API int lua_isnumber(lua_State* L, int idx);
    LUA_API int lua_isboolean(lua_State* L, int idx);
    LUA_API int lua_iscfunction(lua_State* L, int idx);
    LUA_API lua_CFunction lua_tocfunction(lua_State* L, int idx);
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
    LUA_API void lua_sethook(lua_State* L, lua_Hook func, int mask, int count);
    LUA_API lua_Hook lua_gethook(lua_State* L);
    LUA_API int lua_gethookmask(lua_State* L);
    LUA_API int luaL_loadstring(lua_State* L, const char* str);
    LUA_API int lua_pcall(lua_State* L, int nargs, int nresults, int errfunc);
}

#ifndef LUA_RIDX_GLOBALS
#define LUA_RIDX_GLOBALS 2
#endif

namespace {

using ClientRegisterFn = int(__stdcall*)(void*, void*, const char*);
using LuaStateGetCStateFn = lua_State* (__thiscall*)(void*);
using LuaStateAtPanicFn = lua_CFunction(__thiscall*)(void*, lua_CFunction);

constexpr DWORD kQueueDrainLogCooldownMs = 1000;
constexpr DWORD kMaintenanceIntervalMs = 5000;
constexpr DWORD kProbeThrottleMs = 1000;

enum : uint32_t {
    STATE_FLAG_PANIC_OK      = 1u << 0,
    STATE_FLAG_PANIC_MISS    = 1u << 1,
    STATE_FLAG_DEBUG_OK      = 1u << 2,
    STATE_FLAG_DEBUG_MISS    = 1u << 3,
    STATE_FLAG_QUARANTINED   = 1u << 4,
    STATE_FLAG_HELPERS_BOUND = 1u << 5,
};

struct LuaStateInfo {
    lua_State* L = nullptr;
    uint64_t gen = 0;
    uint32_t flags = 0;
    DWORD owner_tid = 0;
    DWORD last_seen_tid = 0;
    void* script_ctx = nullptr;
    uint64_t last_seen_ts = 0;
    uint64_t quarantine_until = 0;
    bool probe_quarantine_logged = false;
    uint64_t panic_log_gen = 0;
    int panic_log_status = -1;
    uint64_t debug_log_gen = 0;
    int debug_log_status = -1;
    uint32_t hook_call_count = 0;
    uint32_t hook_ret_count = 0;
    uint32_t hook_line_count = 0;
};

static void PopulateHookCounters(LuaStateInfo& info);
static void ResetHookStats();

struct HookStatsEntry {
    std::atomic<lua_State*> state{ nullptr };
    std::atomic<uint32_t> call{ 0 };
    std::atomic<uint32_t> ret{ 0 };
    std::atomic<uint32_t> line{ 0 };
};

static std::array<HookStatsEntry, 32> g_hookStats{};

static HookStatsEntry* LookupHookStats(lua_State* L) {
    if (!L)
        return nullptr;
    for (auto& entry : g_hookStats) {
        if (entry.state.load(std::memory_order_acquire) == L)
            return &entry;
    }
    return nullptr;
}

static HookStatsEntry* AcquireHookStats(lua_State* L) {
    if (!L)
        return nullptr;
    if (auto* existing = LookupHookStats(L))
        return existing;
    for (auto& entry : g_hookStats) {
        lua_State* expected = nullptr;
        if (entry.state.compare_exchange_strong(expected, L, std::memory_order_acq_rel)) {
            entry.call.store(0, std::memory_order_relaxed);
            entry.ret.store(0, std::memory_order_relaxed);
            entry.line.store(0, std::memory_order_relaxed);
            return &entry;
        }
    }
    return nullptr;
}

static void ReleaseHookStats(lua_State* L) {
    if (!L)
        return;
    if (auto* entry = LookupHookStats(L)) {
        entry->state.store(nullptr, std::memory_order_release);
        entry->call.store(0, std::memory_order_relaxed);
        entry->ret.store(0, std::memory_order_relaxed);
        entry->line.store(0, std::memory_order_relaxed);
    }
}

static void PopulateHookCounters(LuaStateInfo& info) {
    if (!info.L)
        return;
    if (auto* entry = LookupHookStats(info.L)) {
        info.hook_call_count = entry->call.load(std::memory_order_relaxed);
        info.hook_ret_count = entry->ret.load(std::memory_order_relaxed);
        info.hook_line_count = entry->line.load(std::memory_order_relaxed);
    } else {
        info.hook_call_count = 0;
        info.hook_ret_count = 0;
        info.hook_line_count = 0;
    }
}

static void ResetHookStats() {
    for (auto& entry : g_hookStats) {
        entry.state.store(nullptr, std::memory_order_release);
        entry.call.store(0, std::memory_order_relaxed);
        entry.ret.store(0, std::memory_order_relaxed);
        entry.line.store(0, std::memory_order_relaxed);
    }
}

class LuaStateRegistry {
public:
    LuaStateRegistry() {
        states_.reserve(32);
    }

    bool AddOrUpdate(lua_State* L, void* scriptCtx, DWORD tid, uint64_t generation, LuaStateInfo* outInfo = nullptr) {
        if (!L)
            return false;
        const uint64_t now = GetTickCount64();
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = states_.find(L);
        bool isNew = (it == states_.end());
        if (isNew) {
            LuaStateInfo info{};
            info.L = L;
            info.gen = generation;
            info.script_ctx = scriptCtx;
            info.owner_tid = tid;
            info.last_seen_tid = tid;
            info.flags = 0;
            info.last_seen_ts = now;
            it = states_.emplace(L, info).first;
        } else {
            LuaStateInfo& info = it->second;
            if (scriptCtx)
                info.script_ctx = scriptCtx;
            if (tid) {
                if (info.owner_tid == 0)
                    info.owner_tid = tid;
                info.last_seen_tid = tid;
            }
            info.last_seen_ts = now;
        }
        if (outInfo) {
            *outInfo = it->second;
            PopulateHookCounters(*outInfo);
        }
        return isNew;
    }

    bool Remove(lua_State* L, LuaStateInfo* outInfo = nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = states_.find(L);
        if (it == states_.end())
            return false;
        if (outInfo)
            *outInfo = it->second;
        ReleaseHookStats(L);
        states_.erase(it);
        return true;
    }

    bool Contains(lua_State* L) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return states_.find(L) != states_.end();
    }

    bool GetInfo(lua_State* L, LuaStateInfo& outInfo) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = states_.find(L);
        if (it == states_.end())
            return false;
        outInfo = it->second;
        PopulateHookCounters(outInfo);
        return true;
    }

    bool Update(lua_State* L, const std::function<void(LuaStateInfo&)>& fn, LuaStateInfo* outInfo = nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = states_.find(L);
        if (it == states_.end())
            return false;
        fn(it->second);
        if (outInfo) {
            *outInfo = it->second;
            PopulateHookCounters(*outInfo);
        }
        return true;
    }

    std::vector<LuaStateInfo> Snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<LuaStateInfo> out;
        out.reserve(states_.size());
        for (const auto& kv : states_) {
            LuaStateInfo info = kv.second;
            PopulateHookCounters(info);
            out.push_back(info);
        }
        return out;
    }

    bool MarkFlags(lua_State* L, uint32_t setMask, uint32_t clearMask, uint64_t generation, bool updateGeneration) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = states_.find(L);
        if (it == states_.end())
            return false;
        it->second.flags &= ~clearMask;
        it->second.flags |= setMask;
        if (updateGeneration)
            it->second.gen = generation;
        it->second.last_seen_ts = GetTickCount64();
        return true;
    }

    void ClearFlagsAll(uint32_t mask) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& kv : states_)
            kv.second.flags &= ~mask;
    }

    void Reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        states_.clear();
        ResetHookStats();
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<lua_State*, LuaStateInfo> states_;
};

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

static std::atomic<DWORD> g_scriptThreadId{0};
static std::atomic<lua_State*> g_mainLuaState{nullptr};
static std::atomic<void*> g_mainLuaPlusState{nullptr};

static LuaStateRegistry g_stateRegistry;
static std::atomic<uint64_t> g_generation{1};
static std::atomic<uint64_t> g_lastMaintenanceTick{0};

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

static constexpr const char* kHelperWalkName = "uow_walk";
static constexpr const char* kHelperDumpName = "uow_dump_walk_env";
static constexpr const char* kHelperInspectName = "uow_lua_inspect";
static constexpr const char* kHelperRebindName = "uow_lua_rebind_all";
static constexpr const char* kHelperSelfTestName = "uow_selftest";

// Forward declarations
static void ProcessPendingLuaTasks(lua_State* L);
static void PostToLuaThread(lua_State* L, const char* name, std::function<void(lua_State*)> fn);
static void MaybeRunMaintenance();
static void RequestBindForState(const LuaStateInfo& info, const char* reason, bool force);
static void BindHelpersTask(lua_State* L, uint64_t generation, bool force, const char* reason);
static bool BindHelpersOnThread(lua_State* L, const LuaStateInfo& info, uint64_t generation, bool force);
static void InstallPanicAndDebug(lua_State* L, LuaStateInfo& info);
static bool RegisterHelper(lua_State* L, const LuaStateInfo& info, const char* name, lua_CFunction fn, uint64_t generation);
static void DumpWalkEnv(lua_State* L, const char* reason);
static int Lua_UOWalk(lua_State* L);
static int Lua_UOWDump(lua_State* L);
static int Lua_UOWInspect(lua_State* L);
static int Lua_UOWSelfTest(lua_State* L);
static int Lua_UOWRebindAll(lua_State* L);
static void ForceRebindAll(const char* reason);
static bool ResolveRegisterFunction();
static int __stdcall Hook_Register(void* ctx, void* func, const char* name);

static void LogLuaQ(const char* fmt, ...) {
    char payload[512];
    va_list args;
    va_start(args, fmt);
    vsprintf_s(payload, sizeof(payload), fmt, args);
    va_end(args);
    Log::Logf("[LuaQ] %s", payload);
}

static void LogLuaState(const char* fmt, ...) {
    char payload[512];
    va_list args;
    va_start(args, fmt);
    vsprintf_s(payload, sizeof(payload), fmt, args);
    va_end(args);
    Log::Logf("[LuaState] %s", payload);
}

static void LogLuaBind(const char* fmt, ...) {
    char payload[512];
    va_list args;
    va_start(args, fmt);
    vsprintf_s(payload, sizeof(payload), fmt, args);
    va_end(args);
    Log::Logf("[LuaBind] %s", payload);
}

static void LogLuaProbe(const char* fmt, ...) {
    char payload[512];
    va_list args;
    va_start(args, fmt);
    vsprintf_s(payload, sizeof(payload), fmt, args);
    va_end(args);
    Log::Logf("[LuaProbe] %s", payload);
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

    if (flags & STATE_FLAG_QUARANTINED)
        parts.emplace_back("QUARANTINED");

    if (flags & STATE_FLAG_HELPERS_BOUND) {
        parts.emplace_back("HELPERS");
    } else {
        parts.emplace_back("HELPERS_MISS");
    }

    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i)
            out.push_back('|');
        out += parts[i];
    }
    return out;
}

extern "C" int __cdecl UOW_PanicThunk(lua_State* L) {
    const char* topType = "<unset>";
    __try {
        int top = lua_gettop(L);
        if (top > 0) {
            int type = lua_type(L, -1);
            const char* name = lua_typename(L, type);
            topType = name ? name : "<null>";
        } else {
            topType = "<empty>";
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        topType = "<seh>";
    }
    LogLuaBind("panic-handler-fired L=%p top_type=%s", L, topType);
    return 0;
}

extern "C" void __cdecl UOW_DebugHook(lua_State* L, lua_Debug* ar) {
    if (!L || !ar)
        return;
    HookStatsEntry* entry = LookupHookStats(L);
    if (!entry)
        entry = AcquireHookStats(L);
    if (!entry)
        return;

    switch (ar->event) {
    case LUA_HOOKCALL:
        entry->call.fetch_add(1, std::memory_order_relaxed);
        break;
    case LUA_HOOKRET:
    case LUA_HOOKTAILRET:
        entry->ret.fetch_add(1, std::memory_order_relaxed);
        break;
    case LUA_HOOKLINE:
        entry->line.fetch_add(1, std::memory_order_relaxed);
        break;
    default:
        break;
    }
}

static bool SafeLuaProbeStack(lua_State* L, int* outTop = nullptr, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        int top = lua_gettop(L);
        if (outTop)
            *outTop = top;
        lua_settop(L, top);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaSetTop(lua_State* L, int idx, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_settop(L, idx);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
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

static bool ProbeLua(lua_State* L) {
    if (!L)
        return false;

    const uint64_t now = GetTickCount64();
    LuaStateInfo info{};
    bool haveInfo = g_stateRegistry.GetInfo(L, info);

    if (haveInfo && (info.flags & STATE_FLAG_QUARANTINED)) {
        if (now < info.quarantine_until) {
            return false;
        }
        g_stateRegistry.Update(L, [&](LuaStateInfo& state) {
            state.flags &= ~STATE_FLAG_QUARANTINED;
            state.quarantine_until = 0;
            state.probe_quarantine_logged = false;
        }, &info);
    }

    DWORD probeSeh = 0;
    bool ok = SafeLuaProbeStack(L, nullptr, &probeSeh);

    if (ok) {
        if (haveInfo && (info.flags & STATE_FLAG_QUARANTINED)) {
            g_stateRegistry.Update(L, [&](LuaStateInfo& state) {
                state.flags &= ~STATE_FLAG_QUARANTINED;
                state.quarantine_until = 0;
                state.probe_quarantine_logged = false;
            });
        }
        return true;
    }

    if (haveInfo) {
        bool shouldLog = false;
        g_stateRegistry.Update(L, [&](LuaStateInfo& state) {
            state.flags |= STATE_FLAG_QUARANTINED;
            state.quarantine_until = now + kProbeThrottleMs;
            if (!state.probe_quarantine_logged) {
                state.probe_quarantine_logged = true;
                shouldLog = true;
            }
        });
        if (shouldLog) {
            LogLuaState("probe-failed L=%p tid=%lu quarantined", L, GetCurrentThreadId());
        }
    } else {
        LogLuaState("probe-failed L=%p tid=%lu quarantined", L, GetCurrentThreadId());
    }

    return false;
}

static bool AcquireBindingSlot(lua_State* L) {
    std::lock_guard<std::mutex> lock(g_bindingMutex);
    return g_bindingInFlight.insert(L).second;
}

static void ReleaseBindingSlot(lua_State* L) {
    std::lock_guard<std::mutex> lock(g_bindingMutex);
    g_bindingInFlight.erase(L);
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

static bool IsOwnerThread(const LuaStateInfo& info) {
    if (!info.L)
        return false;
    DWORD owner = info.owner_tid ? info.owner_tid : g_scriptThreadId.load(std::memory_order_acquire);
    if (!owner)
        return false;
    return owner == GetCurrentThreadId();
}

static bool IsOwnerThread(lua_State* L) {
    if (!L)
        return false;
    LuaStateInfo info{};
    if (!g_stateRegistry.GetInfo(L, info))
        return false;
    return IsOwnerThread(info);
}

static void PostToOwnerWithTask(lua_State* L, const char* taskName, std::function<void()> fn) {
    if (!L || !fn)
        return;

    LuaStateInfo info{};
    bool haveInfo = g_stateRegistry.GetInfo(L, info);
    DWORD owner = 0;
    if (haveInfo) {
        owner = info.owner_tid ? info.owner_tid : g_scriptThreadId.load(std::memory_order_acquire);
    } else {
        owner = g_scriptThreadId.load(std::memory_order_acquire);
    }

    DWORD from = GetCurrentThreadId();
    const char* name = taskName ? taskName : "<owner>";

    if (owner && owner == from && haveInfo) {
        fn();
        return;
    }

    Log::Logf("[Bind] posted-to-owner L=%p from=%lu -> owner=%lu task=%s", L, from, owner, name);
    PostToLuaThread(L, name, [fn = std::move(fn)](lua_State*) {
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

static void RequestBindForState(const LuaStateInfo& info, const char* reason, bool force) {
    if (!info.L)
        return;
    uint64_t generation = g_generation.load(std::memory_order_acquire);
    DWORD owner = info.owner_tid ? info.owner_tid : g_scriptThreadId.load(std::memory_order_acquire);
    if (owner && owner == GetCurrentThreadId()) {
        BindHelpersTask(info.L, generation, force, reason ? reason : "immediate");
    } else {
        std::string reasonCopy = reason ? reason : "queue";
        PostToOwnerWithTask(info.L, "helpers", [target = info.L, generation, force, reasonCopy]() {
            BindHelpersTask(target, generation, force, reasonCopy.c_str());
        });
    }
}

static void InstallPanicAndDebug(lua_State* L, LuaStateInfo& info) {
    if (!L)
        return;

    if (!IsOwnerThread(info)) {
        PostToOwnerWithTask(L, "panic&debug", [L]() {
            LuaStateInfo refreshed{};
            if (g_stateRegistry.GetInfo(L, refreshed))
                InstallPanicAndDebug(L, refreshed);
        });
        return;
    }

    lua_State* mainState = g_mainLuaState.load(std::memory_order_acquire);
    if (mainState && mainState != L)
        return;

    if ((info.flags & STATE_FLAG_PANIC_OK) && (info.flags & STATE_FLAG_DEBUG_OK) &&
        info.panic_log_gen == info.gen && info.debug_log_gen == info.gen) {
        return;
    }

    if (!ProbeLua(L))
        return;

    DWORD panicSeh = 0;
    bool panicOk = SafeLuaAtPanic(L, UOW_PanicThunk, &panicSeh);

    DWORD debugSeh = 0;
    bool debugOk = SafeLuaSetHook(L, UOW_DebugHook, LUA_MASKCALL | LUA_MASKRET | LUA_MASKLINE, 0, &debugSeh);

    if (debugOk)
        AcquireHookStats(L);
    else
        ReleaseHookStats(L);

    bool logPanic = false;
    bool logDebug = false;
    g_stateRegistry.Update(L, [&](LuaStateInfo& state) {
        if (panicOk) {
            state.flags |= STATE_FLAG_PANIC_OK;
            state.flags &= ~STATE_FLAG_PANIC_MISS;
        } else {
            state.flags |= STATE_FLAG_PANIC_MISS;
            state.flags &= ~STATE_FLAG_PANIC_OK;
        }

        if (debugOk) {
            state.flags |= STATE_FLAG_DEBUG_OK;
            state.flags &= ~STATE_FLAG_DEBUG_MISS;
        } else {
            state.flags |= STATE_FLAG_DEBUG_MISS;
            state.flags &= ~STATE_FLAG_DEBUG_OK;
        }

        if (state.panic_log_gen != state.gen || state.panic_log_status != (panicOk ? 1 : 0)) {
            state.panic_log_gen = state.gen;
            state.panic_log_status = panicOk ? 1 : 0;
            logPanic = true;
        }
        if (state.debug_log_gen != state.gen || state.debug_log_status != (debugOk ? 1 : 0)) {
            state.debug_log_gen = state.gen;
            state.debug_log_status = debugOk ? 1 : 0;
            logDebug = true;
        }
    }, &info);

    if (logPanic) {
        if (panicOk) {
            LogLuaBind("ok name=panic-handler L=%p", L);
        } else {
            LogLuaBind("fail name=panic-handler L=%p reason=seh=0x%08lX", L, panicSeh);
        }
    }

    if (logDebug) {
        if (debugOk) {
            LogLuaBind("ok name=debug-hook L=%p", L);
        } else {
            LogLuaBind("fail name=debug-hook L=%p reason=seh=0x%08lX", L, debugSeh);
        }
    }
}

static bool RegisterHelper(lua_State* L, const LuaStateInfo& info, const char* name, lua_CFunction fn, uint64_t generation) {
    bool registered = false;
    DWORD seh = 0;

    if (g_clientRegister && info.script_ctx) {
        __try {
            g_clientRegister(info.script_ctx, reinterpret_cast<void*>(fn), name);
            registered = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            seh = GetExceptionCode();
            registered = false;
            LogLuaBind("fail name=%s L=%p reason=register-call-exception seh=0x%08lX ctx=%p", name, L, seh, info.script_ctx);
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
        LogLuaBind("ok name=%s L=%p ctx=%p tid=%lu gen=%llu", name, L, info.script_ctx, info.owner_tid, generation);
    }
    return registered;
}

static bool BindHelpersOnThread(lua_State* L, const LuaStateInfo& originalInfo, uint64_t generation, bool force) {
    if (!L)
        return false;

    LuaStateInfo info = originalInfo;

    if (!IsOwnerThread(info))
        return false;

    if (!ProbeLua(L))
        return false;

    g_stateRegistry.GetInfo(L, info);

    bool ok = true;
    bool helpersBound = (info.flags & STATE_FLAG_HELPERS_BOUND) && info.gen == generation;
    if (force || !helpersBound) {
        bool walkOk = RegisterHelper(L, info, kHelperWalkName, Lua_UOWalk, generation);
        bool dumpOk = RegisterHelper(L, info, kHelperDumpName, Lua_UOWDump, generation);
        bool inspectOk = RegisterHelper(L, info, kHelperInspectName, Lua_UOWInspect, generation);
        bool rebindOk = RegisterHelper(L, info, kHelperRebindName, Lua_UOWRebindAll, generation);
        bool selfTestOk = RegisterHelper(L, info, kHelperSelfTestName, Lua_UOWSelfTest, generation);
        bool allOk = walkOk && dumpOk && inspectOk && rebindOk && selfTestOk;
        if (allOk) {
            g_stateRegistry.MarkFlags(L, STATE_FLAG_HELPERS_BOUND, 0, generation, true);
        } else {
            ok = false;
        }
        g_stateRegistry.GetInfo(L, info);
    }

    InstallPanicAndDebug(L, info);
    return ok;
}

static void BindHelpersTask(lua_State* L, uint64_t generation, bool force, const char* reason) {
    if (!L)
        return;

    LuaStateInfo info{};
    if (!g_stateRegistry.GetInfo(L, info)) {
        LogLuaState("bind-skip L=%p reason=state-missing action=%s", L, reason ? reason : "unknown");
        return;
    }

    if (!IsOwnerThread(info)) {
        std::string reasonCopy = reason ? reason : "unknown";
        PostToOwnerWithTask(L, "helpers", [L, generation, force, reasonCopy]() {
            BindHelpersTask(L, generation, force, reasonCopy.c_str());
        });
        return;
    }

    uint64_t now = GetTickCount64();
    if ((info.flags & STATE_FLAG_QUARANTINED) && now < info.quarantine_until) {
        LogLuaState("bind-skip L=%p reason=quarantined", L);
        return;
    }

    if (!force && (info.flags & STATE_FLAG_HELPERS_BOUND) && info.gen == generation) {
        InstallPanicAndDebug(L, info);
        return;
    }

    if (!AcquireBindingSlot(L)) {
        LogLuaState("bind-skip L=%p reason=in-progress", L);
        return;
    }

    LogLuaState("bind-start L=%p ctx=%p tid=%lu gen=%llu reason=%s", L, info.script_ctx, info.owner_tid, generation, reason ? reason : "unknown");
    bool ok = BindHelpersOnThread(L, info, generation, force);
    ReleaseBindingSlot(L);
    if (!ok) {
        LogLuaState("bind-fail L=%p ctx=%p gen=%llu", L, info.script_ctx, generation);
    } else {
        LogLuaState("bind-done L=%p ctx=%p gen=%llu", L, info.script_ctx, generation);
    }
}

static void ForceRebindAll(const char* reason) {
    uint64_t newGen = g_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    LogLuaState("force-rebind gen=%llu reason=%s", newGen, reason ? reason : "manual");
    g_stateRegistry.ClearFlagsAll(STATE_FLAG_HELPERS_BOUND);
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
    DumpWalkEnv(L, "uow_dump_walk_env");
    return 0;
}

static int Lua_UOWalk(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    int argc = lua_gettop(L);
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
    LuaStateInfo info{};
    bool have = g_stateRegistry.GetInfo(L, info);
    std::ostringstream oss;
    oss << "L=" << L;
    if (have) {
        oss << " ctx=" << info.script_ctx
            << " owner=" << info.owner_tid
            << " last_tid=" << info.last_seen_tid
            << " gen=" << info.gen
            << " flags=" << DescribeFlags(info.flags)
            << " counters=call:" << info.hook_call_count
            << "|ret:" << info.hook_ret_count
            << "|line:" << info.hook_line_count;
    } else {
        oss << " ctx=<unknown>";
    }

    const char* helpers[] = { kHelperWalkName, kHelperDumpName, kHelperInspectName, kHelperRebindName, kHelperSelfTestName };
    constexpr size_t helperCount = sizeof(helpers) / sizeof(helpers[0]);
    oss << " helpers=";
    for (size_t i = 0; i < helperCount; ++i) {
        if (i)
            oss << ',';
        lua_getglobal(L, helpers[i]);
        int type = lua_type(L, -1);
        oss << helpers[i] << ':' << lua_typename(L, type);
        lua_pop(L, 1);
    }

    std::string summary = oss.str();
    LogLuaState("inspect %s", summary.c_str());

    auto snapshot = g_stateRegistry.Snapshot();
    for (const auto& entry : snapshot) {
        LogLuaState("entry L=%p ctx=%p owner=%lu last_tid=%lu gen=%llu flags=%s last_seen=%llu counters=%u/%u/%u",
                    entry.L,
                    entry.script_ctx,
                    entry.owner_tid,
                    entry.last_seen_tid,
                    entry.gen,
                    DescribeFlags(entry.flags).c_str(),
                    entry.last_seen_ts,
                    entry.hook_call_count,
                    entry.hook_ret_count,
                    entry.hook_line_count);
    }

    lua_pushstring(L, summary.c_str());
    return 1;
}

static int Lua_UOWSelfTest(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);

    LuaStateInfo info{};
    if (!g_stateRegistry.GetInfo(L, info)) {
        lua_pushstring(L, "state-missing");
        return 1;
    }

    if (!IsOwnerThread(info)) {
        lua_pushstring(L, "wrong-thread");
        return 1;
    }

    if (!ProbeLua(L)) {
        lua_pushstring(L, "probe-failed");
        return 1;
    }

    bool panicOk = false;
    bool debugOk = false;
    bool runOk = false;
    DWORD panicSeh = 0;
    DWORD debugSeh = 0;
    DWORD runSeh = 0;

    lua_CFunction prevPanic = nullptr;
    if (SafeLuaQueryPanic(L, &prevPanic, &panicSeh)) {
        panicOk = (prevPanic == UOW_PanicThunk);
    } else {
        panicOk = false;
    }

    lua_Hook hook = nullptr;
    int hookMask = 0;
    if (SafeLuaGetHook(L, &hook, &hookMask, &debugSeh)) {
        debugOk = (hook == UOW_DebugHook) &&
                  ((hookMask & (LUA_MASKCALL | LUA_MASKRET | LUA_MASKLINE)) == (LUA_MASKCALL | LUA_MASKRET | LUA_MASKLINE));
    } else {
        debugOk = false;
    }

    int top = 0;
    SafeLuaProbeStack(L, &top, nullptr);
    DWORD dostringSeh = 0;
    if (SafeLuaDoString(L, "return 1+1", &dostringSeh)) {
        int newTop = lua_gettop(L);
        if (newTop > top && lua_isnumber(L, -1) && lua_tointeger(L, -1) == 2) {
            runOk = true;
        }
    } else if (dostringSeh) {
        runSeh = dostringSeh;
    }
    DWORD restoreSeh = 0;
    if (!SafeLuaSetTop(L, top, &restoreSeh) && restoreSeh && !runSeh)
        runSeh = restoreSeh;

    Log::Logf("[SelfTest] L=%p panic=%s debug=%s run=%s",
              L,
              panicOk ? "ok" : "fail",
              debugOk ? "ok" : "fail",
              runOk ? "ok" : "fail");

    std::ostringstream oss;
    oss << "panic=" << (panicOk ? "ok" : "fail");
    if (!panicOk && panicSeh) {
        char buf[16];
        sprintf_s(buf, sizeof(buf), "0x%08lX", panicSeh);
        oss << "(seh=" << buf << ")";
    }
    oss << " debug=" << (debugOk ? "ok" : "fail");
    if (!debugOk && debugSeh) {
        char buf[16];
        sprintf_s(buf, sizeof(buf), "0x%08lX", debugSeh);
        oss << "(seh=" << buf << ")";
    }
    oss << " run=" << (runOk ? "ok" : "fail");
    if (!runOk && runSeh) {
        char buf[16];
        sprintf_s(buf, sizeof(buf), "0x%08lX", runSeh);
        oss << "(seh=" << buf << ")";
    }

    std::string summary = oss.str();
    lua_pushstring(L, summary.c_str());
    return 1;
}

static int Lua_UOWRebindAll(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
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
    }
    if (ctx)
        g_latestScriptCtx.store(ctx, std::memory_order_release);

    if (L) {
        LuaStateInfo snapshot{};
        uint64_t gen = g_generation.load(std::memory_order_acquire);
        bool isNew = g_stateRegistry.AddOrUpdate(L, ctx, tid, gen, &snapshot);
        if (isNew) {
            LogLuaState("observed L=%p ctx=%p tid=%lu gen=%llu source=register", L, ctx, tid, gen);
        }
        if (!name || _stricmp(name, kHelperWalkName) != 0) {
            RequestBindForState(snapshot, name ? name : "register", false);
        }
    }

    int rc = g_clientRegister ? g_clientRegister(ctx, func, name) : 0;
    return rc;
}

} // namespace

namespace Engine::Lua {

bool InitLuaBridge() {
    g_stateRegistry.Reset();
    g_generation.store(1, std::memory_order_release);
    g_lastMaintenanceTick.store(GetTickCount64(), std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(g_taskMutex);
        g_taskQueue.clear();
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

    g_bindingInFlight.clear();
    g_stateRegistry.Reset();
    g_mainLuaState.store(nullptr, std::memory_order_release);
    g_mainLuaPlusState.store(nullptr, std::memory_order_release);
    g_scriptThreadId.store(0, std::memory_order_release);
    g_engineContext.store(nullptr, std::memory_order_release);
    g_latestScriptCtx.store(nullptr, std::memory_order_release);
}

void RegisterOurLuaFunctions() {
    ScheduleWalkBinding();
}

void UpdateEngineContext(void* context) {
    g_engineContext.store(context, std::memory_order_release);
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
            LuaStateInfo info{};
            g_stateRegistry.AddOrUpdate(existing, g_latestScriptCtx.load(std::memory_order_acquire),
                                        g_scriptThreadId.load(std::memory_order_acquire),
                                        g_generation.load(std::memory_order_acquire),
                                        &info);
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
    MaybeRunMaintenance();
}

void OnStateObserved(lua_State* L, void* scriptCtx, std::uint32_t ownerTid) {
    if (!L)
        return;
    uint64_t gen = g_generation.load(std::memory_order_acquire);
    LuaStateInfo snapshot{};
    DWORD tid = ownerTid ? ownerTid : GetCurrentThreadId();
    bool isNew = g_stateRegistry.AddOrUpdate(L, scriptCtx, tid, gen, &snapshot);
    EnsureScriptThread(tid, L);
    if (scriptCtx)
        g_latestScriptCtx.store(scriptCtx, std::memory_order_release);
    if (isNew) {
        LogLuaState("observed L=%p ctx=%p tid=%lu gen=%llu source=external", L, scriptCtx, tid, gen);
    }
    RequestBindForState(snapshot, "state-observed", false);
}

void OnStateRemoved(lua_State* L, const char* reason) {
    if (!L)
        return;
    LuaStateInfo info{};
    if (g_stateRegistry.Remove(L, &info)) {
        LogLuaState("removed L=%p ctx=%p tid=%lu reason=%s", L, info.script_ctx, info.owner_tid, reason ? reason : "unknown");
    }
}



} // namespace Engine::Lua
