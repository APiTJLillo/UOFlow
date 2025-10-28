#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cctype>
#include <atomic>
#include <string>
#include <deque>
#include <mutex>
#include <unordered_map>
#include <functional>
#include <exception>

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
    LUA_API int lua_iscfunction(lua_State* L, int idx);
    LUA_API lua_CFunction lua_tocfunction(lua_State* L, int idx);
    LUA_API const char* lua_tolstring(lua_State* L, int idx, size_t* len);
    LUA_API const char* lua_getupvalue(lua_State* L, int funcindex, int n);
    LUA_API int lua_next(lua_State* L, int idx);
    LUA_API int luaL_ref(lua_State* L, int t);
    LUA_API void luaL_unref(lua_State* L, int t, int ref);
    LUA_API lua_CFunction lua_atpanic(lua_State* L, lua_CFunction panicf);
    typedef void(__cdecl* lua_Hook)(lua_State*, lua_Debug*);
    LUA_API void lua_sethook(lua_State* L, lua_Hook func, int mask, int count);
    LUA_API int lua_getstack(lua_State* L, int level, lua_Debug* ar);
    LUA_API int lua_getinfo(lua_State* L, const char* what, lua_Debug* ar);
}

#ifndef lua_newtable
#define lua_newtable(L) lua_createtable(L, 0, 0)
#endif

#ifndef LUA_REGISTRYINDEX
#define LUA_REGISTRYINDEX (-10000)
#endif

#ifndef LUA_RIDX_GLOBALS
#define LUA_RIDX_GLOBALS 2
#endif

namespace {

using ClientRegisterFn = int(__stdcall*)(void*, void*, const char*);
using LuaStateGetCStateFn = lua_State* (__thiscall*)(void*);
using LuaStateAtPanicFn = lua_CFunction(__thiscall*)(void*, lua_CFunction);

static ClientRegisterFn g_origRegister = nullptr;
static ClientRegisterFn g_clientRegister = nullptr;
static void* g_registerTarget = nullptr;
static std::atomic<bool> g_registerResolved{false};
static std::atomic<DWORD> g_scriptThreadId{0};
static std::atomic<lua_State*> g_mainLuaState{nullptr};
static std::atomic<void*> g_mainLuaPlusState{nullptr};
static void* g_engineContext = nullptr;

struct LuaTask {
    std::string name;
    std::function<void(lua_State*)> fn;
};

static std::mutex g_taskMutex;
static std::deque<LuaTask> g_taskQueue;
static std::atomic<bool> g_registrationQueued{false};
static thread_local bool g_processingLuaQueue = false;
static thread_local char g_cppExceptionDetail[192];

struct HandlerBinding {
    lua_CFunction cfunc = nullptr;
    int luaRef = LUA_NOREF;
    std::string type;
    int upvalueCount = 0;
    const void* pointer = nullptr;
};

static std::mutex g_bindingMutex;
static std::unordered_map<std::string, HandlerBinding> g_bindings;
static int g_bindingRegistryRef = LUA_NOREF;
static bool g_debugHookInstalled = false;
static bool g_globalsDumped = false;
static std::atomic<bool> g_queueLoggedDuringInit{false};
static std::atomic<DWORD> g_lastQueueLogTick{0};
static std::atomic<bool> g_panicInstalled{false};
static std::atomic<bool> g_debugHookFailed{false};
static std::atomic<bool> g_debugHookInfoFailed{false};

static constexpr const char* kHelperWalkName = "uow_walk";
static constexpr const char* kHelperDumpName = "uow_dump_walk_env";
static constexpr const char* kBindingRegistryName = "_uowalk_binding_refs";
static constexpr DWORD kQueueDrainLogCooldownMs = 1000;

struct ModuleBounds {
    uintptr_t base = 0;
    size_t size = 0;
    bool valid = false;
};

static std::atomic<bool> g_loggedStateNormalization{false};
static LuaStateGetCStateFn g_luaStateGetCState = nullptr;
static LuaStateAtPanicFn g_luaStateAtPanic = nullptr;

static void EnsureScriptThread(DWORD tid, lua_State* L);
static void ProcessPendingLuaTasks(lua_State* L);
static void ScheduleLuaTask(const char* name, std::function<void(lua_State*)> fn);
static bool ResolveRegisterFunction();
static int __stdcall Hook_Register(void* ctx, void* func, const char* name);
static void InstallInstrumentation(lua_State* L);
static void InstallDebugHook(lua_State* L);
static void DumpGlobalsOnce(lua_State* L);
static void CaptureBinding(const std::string& name, lua_State* L);
static void ScheduleBindingCapture(const std::string& name);
static int EnsureBindingRegistry(lua_State* L);
static void ReleaseExistingBinding(lua_State* L, HandlerBinding& binding);
static void LogLuaQueuePost(const char* name, lua_State* L, DWORD fromTid);
static void LogLuaQueueDrain(lua_State* L, DWORD tid, const char* outcome, const char* detail = nullptr);
static void LogLuaRunResult(const char* name, DWORD tid, const char* status, const char* detail = nullptr);
static bool ShouldTrackBinding(const char* name);
static lua_State* ResolveLuaState();
static ModuleBounds GetLuaPlusModuleBounds();
static bool LooksLikeLuaPlusState(void* candidate);
static LuaStateGetCStateFn ResolveLuaPlusGetCState();
static LuaStateAtPanicFn ResolveLuaPlusAtPanic();
static lua_State* NormalizeLuaStatePointer(lua_State* candidate);
static void EnsurePanicHandler(lua_State* L);
static int LuaPanicHandler(lua_State* L);
static void DumpWalkEnv(lua_State* L, const char* reason);
static int Lua_UOWalk(lua_State* L);
static int Lua_UOWDump(lua_State* L);
static void CaptureTrackedBindings(lua_State* L);
static void LogProbeBinding(const std::string& name, const HandlerBinding& binding);
static void PushGlobalTable(lua_State* L);
static void MaybeLogQueueDrain(lua_State* L, DWORD tid, const char* detail);
static bool RunLuaTaskWithGuards(lua_State* L, std::function<void(lua_State*)>& fn, const char** outDetail) noexcept;
static const char* FormatCppExceptionDetail(const char* tag, const char* value);

} // namespace

namespace Engine::Lua {

bool InitLuaBridge() {
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

    std::lock_guard<std::mutex> lock(g_bindingMutex);
    g_bindings.clear();
    g_bindingRegistryRef = LUA_NOREF;
    g_debugHookInstalled = false;
    g_globalsDumped = false;
    g_mainLuaState.store(nullptr, std::memory_order_release);
    g_mainLuaPlusState.store(nullptr, std::memory_order_release);
    g_panicInstalled.store(false, std::memory_order_release);
    g_loggedStateNormalization.store(false, std::memory_order_release);
    g_luaStateGetCState = nullptr;
    g_luaStateAtPanic = nullptr;
    g_debugHookFailed.store(false, std::memory_order_release);
    g_debugHookInfoFailed.store(false, std::memory_order_release);
}

void RegisterOurLuaFunctions() {
    ScheduleWalkBinding();
}

void UpdateEngineContext(void* context) {
    g_engineContext = context;
    char buf[160];
    sprintf_s(buf, sizeof(buf), "[LuaProbe] engine-context=%p", context);
    WriteRawLog(buf);
    ScheduleWalkBinding();
}

void EnsureWalkBinding(const char* /*reason*/) {
    ScheduleWalkBinding();
}

void ScheduleWalkBinding() {
    bool expected = false;
    if (!g_registrationQueued.compare_exchange_strong(expected, true))
        return;

    ScheduleLuaTask("InstallInstrumentation", [](lua_State* L) {
        g_registrationQueued.store(false, std::memory_order_release);
        InstallInstrumentation(L);
    });
}

void ProcessLuaQueue() {
    lua_State* L = ResolveLuaState();
    EnsureScriptThread(GetCurrentThreadId(), L);
    ProcessPendingLuaTasks(L);
}

} // namespace Engine::Lua

namespace {

void EnsureScriptThread(DWORD tid, lua_State* L) {
    if (!tid)
        return;

    void* plusCandidate = reinterpret_cast<void*>(L);
    if (plusCandidate && LooksLikeLuaPlusState(plusCandidate)) {
        g_mainLuaPlusState.store(plusCandidate, std::memory_order_release);
    }

    if (auto* normalized = NormalizeLuaStatePointer(L)) {
        L = normalized;
    }

    DWORD expected = 0;
    if (g_scriptThreadId.compare_exchange_strong(expected, tid)) {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "[LuaQ] tid=%lu script-thread-discovered L=%p", tid, L);
        WriteRawLog(buf);
    }

    if (g_scriptThreadId.load(std::memory_order_acquire) == tid && L) {
        lua_State* prev = g_mainLuaState.exchange(L, std::memory_order_acq_rel);
        if (prev != L) {
            char buf[160];
            sprintf_s(buf, sizeof(buf), "[LuaQ] tid=%lu main-state-updated L=%p (prev=%p)", tid, L, prev);
            WriteRawLog(buf);
        }
        if (!g_processingLuaQueue) {
            bool hasPending = false;
            {
                std::lock_guard<std::mutex> lock(g_taskMutex);
                hasPending = !g_taskQueue.empty();
            }
            if (hasPending) {
                ProcessPendingLuaTasks(L);
            }
        }
    }
}

lua_State* ResolveLuaState() {
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

ModuleBounds GetLuaPlusModuleBounds() {
    static ModuleBounds cached{};
    static bool cachedReady = false;

    if (cachedReady && cached.valid)
        return cached;

    HMODULE mod = GetModuleHandleA("luaplus_1100.dll");
    if (!mod) {
        return ModuleBounds{};
    }

    MODULEINFO info{};
    if (!GetModuleInformation(GetCurrentProcess(), mod, &info, sizeof(info))) {
        return ModuleBounds{};
    }

    cached.base = reinterpret_cast<uintptr_t>(info.lpBaseOfDll);
    cached.size = info.SizeOfImage;
    cached.valid = true;
    cachedReady = true;
    return cached;
}

bool LooksLikeLuaPlusState(void* candidate) {
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

LuaStateGetCStateFn ResolveLuaPlusGetCState() {
    if (!g_luaStateGetCState) {
        HMODULE mod = GetModuleHandleA("luaplus_1100.dll");
        if (mod) {
            g_luaStateGetCState = reinterpret_cast<LuaStateGetCStateFn>(
                GetProcAddress(mod, "?GetCState@LuaState@LuaPlus@@QAEPAUlua_State@@XZ"));
        }
    }
    return g_luaStateGetCState;
}

LuaStateAtPanicFn ResolveLuaPlusAtPanic() {
    if (!g_luaStateAtPanic) {
        HMODULE mod = GetModuleHandleA("luaplus_1100.dll");
        if (mod) {
            g_luaStateAtPanic = reinterpret_cast<LuaStateAtPanicFn>(
                GetProcAddress(mod, "?AtPanic@LuaState@LuaPlus@@QAEP6AHPAUlua_State@@@ZP6AH0@Z@Z"));
        }
    }
    return g_luaStateAtPanic;
}

lua_State* NormalizeLuaStatePointer(lua_State* candidate) {
    if (!candidate)
        return nullptr;

    void* raw = reinterpret_cast<void*>(candidate);
    if (!LooksLikeLuaPlusState(raw))
        return candidate;

    auto getCState = ResolveLuaPlusGetCState();
    if (!getCState)
        return candidate;

    lua_State* actual = nullptr;
    __try {
        actual = getCState(raw);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        actual = nullptr;
    }

    if (actual && actual != candidate) {
        bool expected = false;
        if (g_loggedStateNormalization.compare_exchange_strong(expected, true)) {
            char buf[196];
            sprintf_s(buf, sizeof(buf),
                      "[LuaProbe] normalized lua state raw=%p c=%p",
                      raw,
                      actual);
            WriteRawLog(buf);
        }
        return actual;
    }

    return actual ? actual : candidate;
}

void LogLuaQueuePost(const char* name, lua_State* L, DWORD fromTid) {
    char buf[192];
    sprintf_s(buf, sizeof(buf),
              "[LuaQ] post fn=%s L=%p from=tid=%lu",
              name ? name : "<null>", L, fromTid);
    WriteRawLog(buf);
}

void LogLuaQueueDrain(lua_State* L, DWORD tid, const char* outcome, const char* detail) {
    char buf[208];
    sprintf_s(buf, sizeof(buf),
              "[LuaQ] drain outcome=%s tid=%lu L=%p%s%s",
              outcome ? outcome : "?",
              tid,
              L,
              detail ? " detail=" : "",
              detail ? detail : "");
    WriteRawLog(buf);
}

void LogLuaRunResult(const char* name, DWORD tid, const char* status, const char* detail) {
    char buf[256];
    sprintf_s(buf, sizeof(buf),
              "[LuaQ] run fn=%s on=tid=%lu %s%s%s",
              name ? name : "<null>",
              tid,
              status ? status : "?",
              detail ? "=" : "",
              detail ? detail : "");
    WriteRawLog(buf);
}

void MaybeLogQueueDrain(lua_State* L, DWORD tid, const char* detail) {
    DWORD now = GetTickCount();
    DWORD last = g_lastQueueLogTick.load(std::memory_order_relaxed);
    if (now - last < kQueueDrainLogCooldownMs)
        return;
    if (g_lastQueueLogTick.compare_exchange_strong(last, now, std::memory_order_acq_rel)) {
        LogLuaQueueDrain(L, tid, "idle", detail);
    }
}

const char* FormatCppExceptionDetail(const char* tag, const char* value) {
    if (!value || !*value)
        value = "unknown";

    if (tag && *tag) {
        sprintf_s(g_cppExceptionDetail, sizeof(g_cppExceptionDetail), "%s=%s", tag, value);
    } else {
        sprintf_s(g_cppExceptionDetail, sizeof(g_cppExceptionDetail), "%s", value);
    }

    return g_cppExceptionDetail;
}

bool RunLuaTaskWithGuards(lua_State* L, std::function<void(lua_State*)>& fn, const char** outDetail) noexcept {
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

            if (!ok && outDetail) {
                *outDetail = localDetail;
            }
            return ok;
        }
    };

    return Runner::Execute(L, &fn, outDetail);
}

void ProcessPendingLuaTasks(lua_State* L) {
    DWORD tid = GetCurrentThreadId();
    DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
    if (!scriptTid || tid != scriptTid) {
        MaybeLogQueueDrain(L, tid, "non-script-thread");
        return;
    }

    if (!L)
        L = ResolveLuaState();

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
        LogLuaRunResult(task.name.c_str(), tid, "start");
        if (!L) {
            LogLuaRunResult(task.name.c_str(), tid, "err", "lua_state=null");
            continue;
        }

        auto fn = std::move(task.fn);
        bool success = false;
        const char* detail = nullptr;
        try {
            success = RunLuaTaskWithGuards(L, fn, &detail);
        } catch (const std::exception& ex) {
            detail = FormatCppExceptionDetail("cxx", ex.what());
            success = false;
        } catch (...) {
            detail = FormatCppExceptionDetail("cxx", "unknown");
            success = false;
        }

        if (success) {
            LogLuaRunResult(task.name.c_str(), tid, "ok");
        } else {
            if (!detail) {
                detail = "unknown";
            }
            LogLuaRunResult(task.name.c_str(), tid, "err", detail);
            // Requeue the task for a later attempt.
            ScheduleLuaTask(task.name.c_str(), std::move(fn));
        }
    }

    g_processingLuaQueue = false;
}

void ScheduleLuaTask(const char* name, std::function<void(lua_State*)> fn) {
    DWORD fromTid = GetCurrentThreadId();
    lua_State* target = ResolveLuaState();
    {
        std::lock_guard<std::mutex> lock(g_taskMutex);
        g_taskQueue.push_back(LuaTask{ name ? name : "<lambda>", std::move(fn) });
    }
    LogLuaQueuePost(name ? name : "<lambda>", target, fromTid);

    DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
    if (scriptTid != 0 && scriptTid == fromTid && target && !g_processingLuaQueue) {
        ProcessPendingLuaTasks(target);
    }
}

bool ShouldTrackBinding(const char* name) {
    if (!name)
        return false;
    if (_stricmp(name, "walk") == 0)
        return true;
    if (_stricmp(name, "bindWalk") == 0)
        return true;
    if (_stricmp(name, "fastWalkInfo") == 0)
        return true;
    if (_stricmp(name, "movementInfo") == 0)
        return true;
    return false;
}

void ScheduleBindingCapture(const std::string& name) {
    ScheduleLuaTask("CaptureBinding", [name](lua_State* L) {
        CaptureBinding(name, L);
    });
}

void CaptureTrackedBindings(lua_State* L) {
    static const char* kTracked[] = { "walk", "bindWalk", "fastWalkInfo", "movementInfo" };
    for (const char* name : kTracked) {
        CaptureBinding(name, L);
    }
}

void EnsurePanicHandler(lua_State* L) {
    if (!L)
        return;

    if (g_panicInstalled.load(std::memory_order_acquire))
        return;

    bool panicOk = false;
    bool viaLuaPlus = false;
    DWORD sehCode = 0;

    void* plusState = g_mainLuaPlusState.load(std::memory_order_acquire);
    auto atPanic = ResolveLuaPlusAtPanic();
    if (plusState && atPanic) {
        __try {
            atPanic(plusState, LuaPanicHandler);
            panicOk = true;
            viaLuaPlus = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            sehCode = GetExceptionCode();
            panicOk = false;
        }
    }

    if (!panicOk) {
        __try {
            lua_atpanic(L, LuaPanicHandler);
            panicOk = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            sehCode = GetExceptionCode();
            panicOk = false;
        }
    }

    if (panicOk) {
        g_panicInstalled.store(true, std::memory_order_release);
        char buf[160];
        sprintf_s(buf, sizeof(buf),
                  "[LuaProbe] panic-installed via=%s",
                  viaLuaPlus ? "LuaPlus::AtPanic" : "lua_atpanic");
        WriteRawLog(buf);
    } else {
        char buf[160];
        sprintf_s(buf, sizeof(buf),
                  "[LuaProbe] panic-install-failed seh=0x%08lX",
                  sehCode);
        WriteRawLog(buf);
    }
}

int LuaPanicHandler(lua_State* L) {
    const char* msg = nullptr;
    if (lua_gettop(L) > 0) {
        msg = lua_tolstring(L, -1, nullptr);
    }
    char buf[256];
    sprintf_s(buf, sizeof(buf),
              "[LuaProbe] panic msg=%s",
              msg ? msg : "<null>");
    WriteRawLog(buf);
    return 0;
}

void InstallInstrumentation(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    if (!L) {
        LogLuaRunResult("InstallInstrumentation", GetCurrentThreadId(), "err", "lua_state=null");
        return;
    }

    auto logStep = [](const char* stage) {
        char buf[192];
        sprintf_s(buf, sizeof(buf), "[LuaProbe] install step=%s", stage ? stage : "<null>");
        WriteRawLog(buf);
    };

    logStep("ensure-panic");
    EnsurePanicHandler(L);
    logStep("ensure-panic-done");

    logStep("debug-hook");
    InstallDebugHook(L);
    logStep("debug-hook-done");

    logStep("dump-globals");
    DumpGlobalsOnce(L);
    logStep("dump-globals-done");

    static bool helpersInstalled = false;
    if (!helpersInstalled) {
        logStep("register-helpers");
        lua_pushcfunction(L, Lua_UOWalk);
        lua_setglobal(L, kHelperWalkName);
        lua_pushcfunction(L, Lua_UOWDump);
        lua_setglobal(L, kHelperDumpName);
        char buf[160];
        sprintf_s(buf, sizeof(buf),
                  "[LuaProbe] helpers-registered walk=%s dump=%s",
                  kHelperWalkName,
                  kHelperDumpName);
        WriteRawLog(buf);
        helpersInstalled = true;
        logStep("register-helpers-done");
    }

    logStep("capture-bindings");
    CaptureTrackedBindings(L);
    logStep("capture-bindings-done");
}

void InstallDebugHook(lua_State* L) {
    if (!L || g_debugHookInstalled)
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
        if (infoOk == 0) {
            if (!g_debugHookInfoFailed.exchange(true, std::memory_order_acq_rel)) {
                char buf[160];
                sprintf_s(buf, sizeof(buf),
                          "[LuaProbe] debug-hook-getinfo-failed seh=0x%08lX",
                          seh);
                WriteRawLog(buf);
            }
            return;
        }
        const char* src = ar->short_src ? ar->short_src : "?";
        int line = ar->currentline;
        const char* name = ar->name ? ar->name : "?";
        bool isC = ar->what && ar->what[0] == 'C';
        char buf[256];
        DWORD tid = GetCurrentThreadId();
        if (ar->event == LUA_HOOKCALL) {
            sprintf_s(buf, sizeof(buf),
                      "[LUA] tid=%lu CALL src=%s:%d name=%s%s",
                      tid, src, line, name, isC ? "(C)" : "");
            WriteRawLog(buf);
        } else if (ar->event == LUA_HOOKRET || ar->event == LUA_HOOKTAILRET) {
            sprintf_s(buf, sizeof(buf),
                      "[LUA] tid=%lu RET src=%s:%d name=%s%s",
                      tid, src, line, name, isC ? "(C)" : "");
            WriteRawLog(buf);
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

    if (!installed) {
        if (!g_debugHookFailed.exchange(true, std::memory_order_acq_rel)) {
            char buf[160];
            sprintf_s(buf, sizeof(buf),
                      "[LuaProbe] debug-hook-install-failed seh=0x%08lX",
                      seh);
            WriteRawLog(buf);
        }
        return;
    }

    g_debugHookInstalled = true;
    g_debugHookFailed.store(false, std::memory_order_release);
    g_debugHookInfoFailed.store(false, std::memory_order_release);
    char buf[128];
    sprintf_s(buf, sizeof(buf), "[LuaProbe] debug-hook-installed L=%p", L);
    WriteRawLog(buf);
}

void PushGlobalTable(lua_State* L) {
#if defined(LUA_RIDX_GLOBALS)
    lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS);
#else
    lua_pushvalue(L, LUA_GLOBALSINDEX);
#endif
}

void DumpGlobalsOnce(lua_State* L) {
    if (g_globalsDumped || !L)
        return;

    g_globalsDumped = true;
    int top = lua_gettop(L);
    PushGlobalTable(L);
    int tableIndex = lua_gettop(L);
    lua_pushnil(L);

    int emitted = 0;
    std::string line;
    while (lua_next(L, tableIndex) != 0 && emitted < 64) {
        const char* key = lua_tolstring(L, -2, nullptr);
        int type = lua_type(L, -1);
        const char* typeName = lua_typename(L, type);
        if (line.size() > 0)
            line.append(", ");
        if (key) {
            line.append(key);
        } else {
            line.append("<non-string-key>");
        }
        line.push_back(':');
        line.append(typeName ? typeName : "?");
        lua_pop(L, 1);
        ++emitted;
        if (line.size() > 120) {
            char buf[200];
            sprintf_s(buf, sizeof(buf),
                      "[LuaProbe] globals snapshot chunk=%s",
                      line.c_str());
            WriteRawLog(buf);
            line.clear();
        }
    }
    if (!line.empty()) {
        char buf[200];
        sprintf_s(buf, sizeof(buf),
                  "[LuaProbe] globals snapshot chunk=%s",
                  line.c_str());
        WriteRawLog(buf);
    }
    lua_settop(L, top);
}

int EnsureBindingRegistry(lua_State* L) {
    if (g_bindingRegistryRef != LUA_NOREF)
        return g_bindingRegistryRef;

    lua_newtable(L);
    g_bindingRegistryRef = luaL_ref(L, LUA_REGISTRYINDEX);
    char buf[128];
    sprintf_s(buf, sizeof(buf),
              "[LuaProbe] registry-table-created ref=%d",
              g_bindingRegistryRef);
    WriteRawLog(buf);
    return g_bindingRegistryRef;
}

void ReleaseExistingBinding(lua_State* L, HandlerBinding& binding) {
    if (!L)
        return;
    if (binding.luaRef != LUA_NOREF && g_bindingRegistryRef != LUA_NOREF) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, g_bindingRegistryRef);
        luaL_unref(L, -1, binding.luaRef);
        lua_pop(L, 1);
        binding.luaRef = LUA_NOREF;
    }
    binding.cfunc = nullptr;
    binding.type.clear();
    binding.pointer = nullptr;
    binding.upvalueCount = 0;
}

void LogProbeBinding(const std::string& name, const HandlerBinding& binding) {
    char buf[256];
    if (binding.type == "Lua") {
        sprintf_s(buf, sizeof(buf),
                  "[LuaProbe] %s: type=Lua ptr=%p ref=%d upvalues=%d",
                  name.c_str(),
                  binding.pointer,
                  binding.luaRef,
                  binding.upvalueCount);
    } else if (binding.type == "CFunction") {
        sprintf_s(buf, sizeof(buf),
                  "[LuaProbe] %s: type=CFunction ptr=%p",
                  name.c_str(),
                  reinterpret_cast<void*>(binding.cfunc));
    } else {
        sprintf_s(buf, sizeof(buf),
                  "[LuaProbe] %s: type=%s",
                  name.c_str(),
                  binding.type.c_str());
    }
    WriteRawLog(buf);
}

void CaptureBinding(const std::string& name, lua_State* L) {
    if (!L) {
        LogLuaRunResult("CaptureBinding", GetCurrentThreadId(), "err", "lua_state=null");
        return;
    }

    lua_getglobal(L, name.c_str());
    int type = lua_type(L, -1);
    HandlerBinding newBinding;
    newBinding.type = lua_typename(L, type);
    newBinding.pointer = lua_topointer(L, -1);

    if (type == LUA_TFUNCTION) {
        if (lua_iscfunction(L, -1)) {
            newBinding.type = "CFunction";
            newBinding.cfunc = lua_tocfunction(L, -1);
        } else {
            newBinding.type = "Lua";
            newBinding.upvalueCount = 0;
            int funcIndex = lua_gettop(L);
            while (lua_getupvalue(L, funcIndex, newBinding.upvalueCount + 1) != nullptr) {
                ++newBinding.upvalueCount;
                lua_pop(L, 1);
            }
            int tableRef = EnsureBindingRegistry(L);
            lua_rawgeti(L, LUA_REGISTRYINDEX, tableRef);
            lua_pushvalue(L, funcIndex);
            newBinding.luaRef = luaL_ref(L, -2);
            lua_pop(L, 1); // pop registry table
        }
    } else if (type == LUA_TNIL) {
        newBinding.type = "nil";
    }

    {
        std::lock_guard<std::mutex> lock(g_bindingMutex);
        HandlerBinding& slot = g_bindings[name];
        ReleaseExistingBinding(L, slot);
        slot = newBinding;
    }

    LogProbeBinding(name, newBinding);
    lua_pop(L, 1);
}

void DumpWalkEnv(lua_State* L, const char* reason) {
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
        char buf[256];
        sprintf_s(buf, sizeof(buf),
                  "[LuaProbe] %s env type=%s ptr=%p upvalues=%d reason=%s",
                  name,
                  typeName ? typeName : "?",
                  ptr,
                  upCount,
                  reason ? reason : "manual");
        WriteRawLog(buf);
        lua_pop(L, 1);
    }
}

int Lua_UOWDump(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    DumpWalkEnv(L, "uow_dump_walk_env");
    return 0;
}

int Lua_UOWalk(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    int argc = lua_gettop(L);
    if (argc < 1 || !lua_isnumber(L, 1)) {
        WriteRawLog("[LuaProbe] uow_walk invalid dir parameter");
        lua_pushboolean(L, 0);
        return 1;
    }

    int dir = static_cast<int>(lua_tointeger(L, 1));
    int run = 0;
    if (argc >= 2) {
        if (lua_isnumber(L, 2)) {
            run = lua_tointeger(L, 2) != 0 ? 1 : 0;
        } else if (lua_type(L, 2) == LUA_TBOOLEAN) {
            run = lua_toboolean(L, 2) ? 1 : 0;
        } else {
            WriteRawLog("[LuaProbe] uow_walk run parameter ignored (unsupported type)");
            run = 0;
        }
    }
    bool ok = SendWalk(dir, run);
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

bool ResolveRegisterFunction() {
    if (g_registerResolved.load(std::memory_order_acquire))
        return true;

    void* addr = Engine::FindRegisterLuaFunction();
    if (!addr) {
        WriteRawLog("ResolveRegisterFunction: register helper not found");
        return false;
    }

    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        WriteRawLog("ResolveRegisterFunction: MH_Initialize failed");
        return false;
    }

    if (MH_CreateHook(addr, &Hook_Register, reinterpret_cast<LPVOID*>(&g_origRegister)) != MH_OK ||
        MH_EnableHook(addr) != MH_OK) {
        WriteRawLog("ResolveRegisterFunction: hook installation failed");
        g_origRegister = nullptr;
        return false;
    }

    g_registerTarget = addr;
    g_clientRegister = g_origRegister;
    g_registerResolved.store(true, std::memory_order_release);

    char buf[160];
    sprintf_s(buf, sizeof(buf),
              "[LuaProbe] register-hook-installed target=%p",
              addr);
    WriteRawLog(buf);
    return true;
}

int __stdcall Hook_Register(void* ctx, void* func, const char* name) {
    DWORD tid = GetCurrentThreadId();
    lua_State* L = ResolveLuaState();
    EnsureScriptThread(tid, L);

    char buf[224];
    sprintf_s(buf, sizeof(buf),
              "[LuaReg] name=%s fn=%p ctx=%p on tid=%lu",
              name ? name : "<null>",
              func,
              ctx,
              tid);
    WriteRawLog(buf);

    if (ctx && ctx != g_engineContext) {
        g_engineContext = ctx;
    }

    if (name && ShouldTrackBinding(name)) {
        ScheduleBindingCapture(name);
    }

    int rc = g_clientRegister ? g_clientRegister(ctx, func, name) : 0;

    if (name && ShouldTrackBinding(name)) {
        ScheduleBindingCapture(name);
    }

    return rc;
}

} // namespace
