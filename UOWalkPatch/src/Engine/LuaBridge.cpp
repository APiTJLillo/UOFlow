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
#endif

#ifndef LUA_IDSIZE
#define LUA_IDSIZE 60
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
    LUA_API lua_CFunction lua_atpanic(lua_State* L, lua_CFunction panicf);
    LUA_API int lua_getstack(lua_State* L, int level, lua_Debug* ar);
    LUA_API int lua_getinfo(lua_State* L, const char* what, lua_Debug* ar);
    typedef void(__cdecl* lua_Hook)(lua_State*, lua_Debug*);
    LUA_API void lua_sethook(lua_State* L, lua_Hook func, int mask, int count);
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

enum : uint32_t {
    STATE_FLAG_PANIC_OK      = 1u << 0,
    STATE_FLAG_DEBUGHOOK_OK  = 1u << 1,
    STATE_FLAG_HELPERS_BOUND = 1u << 2,
};

struct LuaStateInfo {
    lua_State* L = nullptr;
    uint64_t gen = 0;
    uint32_t flags = 0;
    DWORD owner_tid = 0;
    void* script_ctx = nullptr;
    uint64_t last_seen_ts = 0;
};

class LuaStateRegistry {
public:
    LuaStateRegistry() {
        states_.reserve(32);
    }

    bool AddOrUpdate(lua_State* L, void* scriptCtx, DWORD ownerTid, uint64_t generation, LuaStateInfo* outInfo = nullptr) {
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
            info.owner_tid = ownerTid;
            info.flags = 0;
            info.last_seen_ts = now;
            it = states_.emplace(L, info).first;
        } else {
            LuaStateInfo& info = it->second;
            if (scriptCtx)
                info.script_ctx = scriptCtx;
            if (ownerTid)
                info.owner_tid = ownerTid;
            info.last_seen_ts = now;
        }
        if (outInfo)
            *outInfo = it->second;
        return isNew;
    }

    bool Remove(lua_State* L, LuaStateInfo* outInfo = nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = states_.find(L);
        if (it == states_.end())
            return false;
        if (outInfo)
            *outInfo = it->second;
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
        return true;
    }

    std::vector<LuaStateInfo> Snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<LuaStateInfo> out;
        out.reserve(states_.size());
        for (const auto& kv : states_)
            out.push_back(kv.second);
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

// Forward declarations
static void ProcessPendingLuaTasks(lua_State* L);
static void PostToLuaThread(lua_State* L, const char* name, std::function<void(lua_State*)> fn);
static void MaybeRunMaintenance();
static void RequestBindForState(const LuaStateInfo& info, const char* reason, bool force);
static void BindHelpersTask(lua_State* L, uint64_t generation, bool force, const char* reason);
static bool BindHelpersOnThread(lua_State* L, const LuaStateInfo& info, uint64_t generation, bool force);
static bool EnsurePanicHandler(lua_State* L, const LuaStateInfo& info, uint64_t generation);
static void InstallDebugHook(lua_State* L);
static bool RegisterHelper(lua_State* L, const LuaStateInfo& info, const char* name, lua_CFunction fn, uint64_t generation);
static void DumpWalkEnv(lua_State* L, const char* reason);
static int Lua_UOWalk(lua_State* L);
static int Lua_UOWDump(lua_State* L);
static int Lua_UOWInspect(lua_State* L);
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
    std::string out;
    if (flags & STATE_FLAG_PANIC_OK)
        out += "PANIC_OK";
    else
        out += "PANIC_MISS";
    out += '|';
    if (flags & STATE_FLAG_DEBUGHOOK_OK)
        out += "DEBUG_OK";
    else
        out += "DEBUG_MISS";
    out += '|';
    if (flags & STATE_FLAG_HELPERS_BOUND)
        out += "HELPERS";
    else
        out += "HELPERS_MISS";
    return out;
}

static bool ProbeLuaState(lua_State* L) {
    if (!L)
        return false;
    bool ok = false;
    __try {
        lua_gettop(L);
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    return ok;
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

    if (actual && ProbeLuaState(actual)) {
        g_mainLuaPlusState.store(raw, std::memory_order_release);
        if (actual != candidate) {
            LogLuaProbe("normalized lua state raw=%p c=%p", raw, actual);
        }
        return actual;
    }

    if (ProbeLuaState(candidate))
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
    std::string name = std::string("BindHelpers:") + (reason ? reason : "unknown");
    if (owner && owner == GetCurrentThreadId()) {
        BindHelpersTask(info.L, generation, force, reason ? reason : "immediate");
    } else {
        PostToLuaThread(info.L, name.c_str(), [generation, force, reasonStr = std::string(reason ? reason : "queue")](lua_State* state) {
            BindHelpersTask(state, generation, force, reasonStr.c_str());
        });
    }
}

static bool EnsurePanicHandler(lua_State* L, const LuaStateInfo& info, uint64_t generation) {
    if (!L)
        return false;

    lua_CFunction prev = nullptr;
    DWORD sehCode = 0;
    bool ok = false;

    auto atPanic = ResolveLuaPlusAtPanic();
    if (info.script_ctx && LooksLikeLuaPlusState(info.script_ctx) && atPanic) {
        __try {
            prev = atPanic(info.script_ctx, Lua_UOWDump);
            ok = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            sehCode = GetExceptionCode();
            ok = false;
        }
    }

    if (!ok) {
        __try {
            prev = lua_atpanic(L, Lua_UOWDump);
            ok = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            sehCode = GetExceptionCode();
            ok = false;
        }
    }

    if (ok) {
        LogLuaBind("ok name=panic-handler L=%p ctx=%p prev=%p gen=%llu", L, info.script_ctx, prev, generation);
        g_stateRegistry.MarkFlags(L, STATE_FLAG_PANIC_OK, 0, generation, false);
    } else {
        LogLuaBind("fail name=panic-handler L=%p ctx=%p reason=seh=0x%08lX", L, info.script_ctx, sehCode);
    }
    return ok;
}

static void InstallDebugHook(lua_State* L) {
    if (!L)
        return;

    auto debugHook = [](lua_State* Lstate, lua_Debug* ar) {
        if (!Lstate || !ar)
            return;
        int infoOk = 0;
        DWORD seh = 0;
        __try {
            infoOk = lua_getinfo(Lstate, "Sn", ar);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            seh = GetExceptionCode();
            infoOk = 0;
        }
        if (infoOk == 0)
            return;
        const char* src = ar->short_src ? ar->short_src : "?";
        int line = ar->currentline;
        const char* name = ar->name ? ar->name : "?";
        bool isC = ar->what && ar->what[0] == 'C';
        DWORD tid = GetCurrentThreadId();
        if (ar->event == LUA_HOOKCALL) {
            LogLuaProbe("tid=%lu CALL src=%s:%d name=%s%s", tid, src, line, name, isC ? "(C)" : "");
        } else if (ar->event == LUA_HOOKRET || ar->event == LUA_HOOKTAILRET) {
            LogLuaProbe("tid=%lu RET src=%s:%d name=%s%s", tid, src, line, name, isC ? "(C)" : "");
        }
    };

    bool installed = false;
    DWORD seh = 0;
    __try {
        lua_sethook(L, debugHook, LUA_MASKCALL | LUA_MASKRET, 0);
        installed = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        seh = GetExceptionCode();
        installed = false;
    }

    if (installed) {
        LogLuaBind("ok name=debug-hook L=%p", L);
    } else {
        LogLuaBind("fail name=debug-hook L=%p reason=seh=0x%08lX", L, seh);
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

static bool BindHelpersOnThread(lua_State* L, const LuaStateInfo& info, uint64_t generation, bool force) {
    if (!L)
        return false;

    bool ok = true;

    if (force || !(info.flags & STATE_FLAG_PANIC_OK)) {
        if (!EnsurePanicHandler(L, info, generation))
            ok = false;
    }

    if (force || !(info.flags & STATE_FLAG_DEBUGHOOK_OK)) {
        InstallDebugHook(L);
        g_stateRegistry.MarkFlags(L, STATE_FLAG_DEBUGHOOK_OK, 0, generation, false);
    }

    bool helpersBound = (info.flags & STATE_FLAG_HELPERS_BOUND) && info.gen == generation;
    if (force || !helpersBound) {
        bool walkOk = RegisterHelper(L, info, kHelperWalkName, Lua_UOWalk, generation);
        bool dumpOk = RegisterHelper(L, info, kHelperDumpName, Lua_UOWDump, generation);
        bool inspectOk = RegisterHelper(L, info, kHelperInspectName, Lua_UOWInspect, generation);
        bool rebindOk = RegisterHelper(L, info, kHelperRebindName, Lua_UOWRebindAll, generation);
        bool allOk = walkOk && dumpOk && inspectOk && rebindOk;
        if (allOk)
            g_stateRegistry.MarkFlags(L, STATE_FLAG_HELPERS_BOUND, 0, generation, true);
        else
            ok = false;
    }

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

    if (!force && (info.flags & STATE_FLAG_HELPERS_BOUND) && info.gen == generation)
        return;

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
            << " gen=" << info.gen
            << " flags=" << DescribeFlags(info.flags);
    } else {
        oss << " ctx=<unknown>";
    }

    const char* helpers[] = { kHelperWalkName, kHelperDumpName, kHelperInspectName, kHelperRebindName };
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
        LogLuaState("entry L=%p ctx=%p tid=%lu gen=%llu flags=%s last_seen=%llu",
                    entry.L,
                    entry.script_ctx,
                    entry.owner_tid,
                    entry.gen,
                    DescribeFlags(entry.flags).c_str(),
                    entry.last_seen_ts);
    }

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
        if (!ProbeLuaState(fromCtx))
            fromCtx = nullptr;
    }
    if (!ProbeLuaState(resolved))
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
