#include <windows.h>
#include <cstdio>
#include <cctype>
#include <cstring>
#include <atomic>
#include <minhook.h>

#include "Core/Logging.hpp"
#include "Net/SendBuilder.hpp"
#include "Engine/GlobalState.hpp"
#include "Engine/Movement.hpp"
#include "Engine/LuaBridge.hpp"
#include "LuaPlus.h"

extern "C" LUA_API void lua_pushlightuserdata(lua_State* L, void* p);
extern "C" LUA_API void lua_pushvalue(lua_State* L, int idx);
extern "C" LUA_API void lua_pushnumber(lua_State* L, lua_Number n);
extern "C" LUA_API int lua_pcall(lua_State* L, int nargs, int nresults, int errfunc);
extern "C" LUA_API void lua_remove(lua_State* L, int idx);
extern "C" LUA_API const char* lua_tolstring(lua_State* L, int idx, size_t* len);
extern "C" LUA_API void lua_pushboolean(lua_State* L, int b);
extern "C" LUA_API void lua_pushcclosure(lua_State* L, lua_CFunction fn, int n);
extern "C" LUA_API lua_CFunction lua_tocfunction(lua_State* L, int idx);

#ifndef LUA_MULTRET
#define LUA_MULTRET (-1)
#endif

#ifndef LUA_OK
#define LUA_OK 0
#endif


namespace {
    using ClientRegisterFn = int(__stdcall*)(void*, void*, const char*);

    ClientRegisterFn g_clientRegister = nullptr;
    ClientRegisterFn g_origRegister = nullptr;
    bool g_registerResolved = false;
    void* g_registerTarget = nullptr;
    void* g_engineContext = nullptr;
    void* g_clientContext = nullptr;

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
static std::atomic<bool> g_registrationInProgress{false};

static void FlushPendingRegistration()
{
    if (InterlockedCompareExchange(&g_pendingRegistration, 0, 0) == 0)
        return;

    bool expected = false;
    if (!g_registrationInProgress.compare_exchange_strong(expected, true))
        return;

    __try {
        Engine::Lua::RegisterOurLuaFunctions();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("FlushPendingRegistration: exception during RegisterOurLuaFunctions");
    }

    g_registrationInProgress.store(false, std::memory_order_release);
    InterlockedExchange(&g_pendingRegistration, 0);
}
}

static int __stdcall Hook_Register(void* ctx, void* func, const char* name);
static int __cdecl Lua_Walk(lua_State* L);
static int __cdecl Lua_BindWalk(lua_State* L);
static int __cdecl Lua_FastWalkInfo(lua_State* L);
static int __cdecl Lua_MovementInfo(lua_State* L);

static lua_CFunction g_clientWalkFn = nullptr;
static bool g_clientWalkClosureValid = false;
static constexpr const char* kClientWalkClosureGlobal = "_uoWalk_clientClosure";

static void ClearClientWalkClosure(lua_State* L)
{
    g_clientWalkClosureValid = false;
    if (!L)
        return;

    __try {
        lua_pushnil(L);
        lua_setglobal(L, kClientWalkClosureGlobal);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("ClearClientWalkClosure: exception while clearing closure global");
    }
}

static void LogWalkBindingState(lua_State* L, const char* stage)
{
    if (!L)
        return;

    int walkType = LUA_TNONE;
    const void* walkPtr = nullptr;
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
    sprintf_s(buf, sizeof(buf), "%s: walk=%s%p bindWalk=%s%p",
        stage ? stage : "WalkBindingState",
        (walkType == LUA_TFUNCTION) ? "fn@" : lua_typename(L, walkType),
        walkPtr,
        (bindType == LUA_TFUNCTION) ? "fn@" : lua_typename(L, bindType),
        bindPtr);
    WriteRawLog(buf);
}

static void CaptureClientWalkBinding(lua_State* L, const char* reason)
{
    if (!L)
        return;

    if (g_clientWalkFn || g_clientWalkClosureValid)
        return;

    int topBefore = 0;
    __try {
        topBefore = lua_gettop(L);
        lua_getglobal(L, "walk");
        if (lua_type(L, -1) == LUA_TFUNCTION) {
            const void* walkPtr = lua_topointer(L, -1);
            lua_CFunction cfn = lua_tocfunction(L, -1);
            if (cfn && cfn != reinterpret_cast<lua_CFunction>(&Lua_Walk)) {
                g_clientWalkFn = cfn;
                ClearClientWalkClosure(L);
                char info[224];
                sprintf_s(info, sizeof(info),
                    "CaptureClientWalkBinding(%s): captured C handler ptr=%p",
                    reason ? reason : "<null>",
                    reinterpret_cast<void*>(cfn));
                WriteRawLog(info);
            } else if (!cfn) {
                ClearClientWalkClosure(L);
                lua_pushvalue(L, -1);
                lua_setglobal(L, kClientWalkClosureGlobal);
                g_clientWalkClosureValid = true;
                char info[256];
                sprintf_s(info, sizeof(info),
                    "CaptureClientWalkBinding(%s): captured Lua closure ptr=%p",
                    reason ? reason : "<null>",
                    walkPtr);
                WriteRawLog(info);
            } else {
                WriteRawLog("CaptureClientWalkBinding: walk global already bound to helper");
            }
        } else {
            char info[160];
            sprintf_s(info, sizeof(info),
                "CaptureClientWalkBinding(%s): global walk missing or type=%s",
                reason ? reason : "<null>",
                lua_typename(L, lua_type(L, -1)));
            WriteRawLog(info);
            lua_pop(L, 1);
        }
        lua_settop(L, topBefore);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("CaptureClientWalkBinding: exception during inspection");
        __try {
            if (L)
                lua_settop(L, topBefore);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
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
    sprintf_s(buf, sizeof(buf),
        "%s: skipping walk rebinding (Lua_Walk=%p ctx=%p)",
        tag,
        desiredPtr,
        g_clientContext);
    WriteRawLog(buf);

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

    bool isNewCtx = false;
    ObservedContext* slot = ensureContextSlot(ctx, &isNewCtx);
    if (isNewCtx) {
        char info[160];
        sprintf_s(info, sizeof(info), "Observed new script context %p (name=%s func=%p)",
            ctx, name ? name : "<null>", func);
        WriteRawLog(info);
        Engine::RequestWalkRegistration();
        InterlockedExchange(&g_pendingRegistration, 1);
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

    uintptr_t walkInt = reinterpret_cast<uintptr_t>(&Lua_Walk);
    void* walkPtr = reinterpret_cast<void*>(walkInt);
    if (name && _stricmp(name, "walk") == 0 && func && func != walkPtr) {
        g_clientWalkFn = reinterpret_cast<lua_CFunction>(func);
        ClearClientWalkClosure(static_cast<lua_State*>(Engine::LuaState()));
        char info[160];
        sprintf_s(info, sizeof(info), "Captured client walk function %p", func);
        WriteRawLog(info);
    }

    int rc = g_clientRegister ? g_clientRegister(ctx, func, name) : 0;

    uintptr_t bindInt = reinterpret_cast<uintptr_t>(&Lua_BindWalk);
    void* bindPtr = reinterpret_cast<void*>(bindInt);
    if (name && ctx) {
        if (_stricmp(name, "walk") == 0 && func == walkPtr) {
            if (auto L = static_cast<lua_State*>(Engine::LuaState())) {
                if (RegisterFunctionSafe(L, Lua_Walk, "walk")) {
                    LogWalkBindingState(L, "Hook_Register post-walk");
                }
            }
        } else if (_stricmp(name, "bindWalk") == 0 && func == bindPtr) {
            if (auto L = static_cast<lua_State*>(Engine::LuaState())) {
                if (RegisterFunctionSafe(L, Lua_BindWalk, "bindWalk")) {
                    LogWalkBindingState(L, "Hook_Register post-bindWalk");
                }
            }
        }
    }

    FlushPendingRegistration();

    return rc;
}

static int __cdecl Lua_DummyPrint(lua_State*)
{
    WriteRawLog("[Lua] DummyPrint() was invoked!");
    return 0;
}

struct ClientWalkCallResult {
    bool invoked = false;
    bool callSucceeded = false;
    bool truthy = false;
    bool sendObserved = false;
};

static ClientWalkCallResult InvokeClientWalk(lua_State* L, lua_CFunction fn, int dir, int runValue, bool includeRun, const char* label)
{
    ClientWalkCallResult result{};
    if (!L || !fn)
        return result;

    int topBefore = 0;
    __try {
        topBefore = lua_gettop(L);
        lua_pushcclosure(L, fn, 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("Lua_Walk: exception while pushing client walk handler");
        __try {
            if (L)
                lua_settop(L, topBefore);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        return result;
    }

    result.invoked = true;

    const void* pushedPtr = lua_topointer(L, -1);
    if (pushedPtr == reinterpret_cast<const void*>(Lua_Walk)) {
        WriteRawLog("Lua_Walk: client handler pointer resolved to helper; refusing recursion");
        lua_settop(L, topBefore);
        return result;
    }

    lua_pushnumber(L, dir);
    if (includeRun)
        lua_pushnumber(L, runValue);
    int nargs = includeRun ? 2 : 1;

    Engine::ArmMovementSendWatchdog();
    int rc = lua_pcall(L, nargs, LUA_MULTRET, 0);
    bool sendObserved = Engine::DisarmAndCheckMovementSend();
    result.sendObserved = sendObserved;

    if (rc != LUA_OK) {
        const char* err = lua_tolstring(L, -1, nullptr);
        char buf[256];
        sprintf_s(buf, sizeof(buf),
                  "Lua_Walk: client handler '%s' threw (%s)",
                  label,
                  err ? err : "<unknown>");
        WriteRawLog(buf);
        lua_pop(L, 1);
        lua_settop(L, topBefore);
        return result;
    }

    result.callSucceeded = true;

    int topAfter = lua_gettop(L);
    int resultCount = topAfter - topBefore;
    bool truthy = true;
    if (resultCount > 0) {
        truthy = (lua_toboolean(L, topBefore + 1) != 0);
    }
    result.truthy = truthy;

    char buf[256];
    sprintf_s(buf, sizeof(buf),
              "Lua_Walk -> client handler '%s' completed (results=%d truthy=%d sendObserved=%d)",
              label,
              resultCount,
              truthy ? 1 : 0,
              sendObserved ? 1 : 0);
    WriteRawLog(buf);

    lua_settop(L, topBefore);
    return result;
}

static ClientWalkCallResult InvokeClientWalkClosure(lua_State* L, int dir, int runValue, bool includeRun, const char* label)
{
    ClientWalkCallResult result{};
    if (!L || !g_clientWalkClosureValid)
        return result;

    int topBefore = 0;
    __try {
        topBefore = lua_gettop(L);
        lua_getglobal(L, kClientWalkClosureGlobal);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("Lua_Walk: exception while pushing walk closure");
        return result;
    }

    if (lua_type(L, -1) != LUA_TFUNCTION) {
        char buf[224];
        sprintf_s(buf, sizeof(buf),
            "Lua_Walk: stored walk closure missing (type=%s); clearing cache",
            lua_typename(L, lua_type(L, -1)));
        WriteRawLog(buf);
        ClearClientWalkClosure(L);
        lua_settop(L, topBefore);
        return result;
    }

    result.invoked = true;

    if (!includeRun)
        lua_pushnumber(L, dir);
    else {
        lua_pushnumber(L, dir);
        lua_pushnumber(L, runValue);
    }

    int nargs = includeRun ? 2 : 1;

    Engine::ArmMovementSendWatchdog();
    int rc = lua_pcall(L, nargs, LUA_MULTRET, 0);
    bool sendObserved = Engine::DisarmAndCheckMovementSend();
    result.sendObserved = sendObserved;

    if (rc != LUA_OK) {
        const char* err = lua_tolstring(L, -1, nullptr);
        char buf[256];
        sprintf_s(buf, sizeof(buf),
                  "Lua_Walk: walk closure '%s' threw (%s)",
                  label,
                  err ? err : "<unknown>");
        WriteRawLog(buf);
        lua_pop(L, 1);
        lua_settop(L, topBefore);
        return result;
    }

    result.callSucceeded = true;

    int topAfter = lua_gettop(L);
    int resultCount = topAfter - topBefore;
    bool truthy = true;
    if (resultCount > 0) {
        truthy = (lua_toboolean(L, topBefore + 1) != 0);
    }
    result.truthy = truthy;

    char buf[256];
    sprintf_s(buf, sizeof(buf),
              "Lua_Walk -> walk closure '%s' completed (results=%d truthy=%d sendObserved=%d)",
              label,
              resultCount,
              truthy ? 1 : 0,
              sendObserved ? 1 : 0);
    WriteRawLog(buf);

    lua_settop(L, topBefore);
    return result;
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
    int runValue = run;
    if (L && lua_gettop(L) >= 2) {
        if (lua_type(L, 2) == LUA_TNUMBER)
            runValue = static_cast<int>(lua_tointeger(L, 2));
        else
            runValue = lua_toboolean(L, 2) ? 1 : 0;
    }
    run = runValue != 0;

    SOCKET activeSocket = Engine::GetActiveFastWalkSocket();
   int fastWalkDepth = Engine::FastWalkQueueDepth(activeSocket);

    char buf[192];
    sprintf_s(buf, sizeof(buf),
              "Lua_Walk invoked dir=%d run=%d activeSocket=%p fastWalkDepth=%d clientFn=%p closureValid=%d",
              dir,
              runValue,
              reinterpret_cast<void*>(static_cast<uintptr_t>(activeSocket)),
              fastWalkDepth,
              reinterpret_cast<void*>(g_clientWalkFn),
              g_clientWalkClosureValid ? 1 : 0);
    WriteRawLog(buf);

    bool clientAttempted = false;
    bool clientHandled = false;
    bool missingSend = false;

    if (L && g_clientWalkFn) {
        auto attempt = [&](bool includeRun, const char* label) {
            ClientWalkCallResult res = InvokeClientWalk(L, g_clientWalkFn, dir, runValue, includeRun, label);
            if (!res.invoked)
                return;
            clientAttempted = true;
            if (!res.callSucceeded || !res.truthy)
                return;
            if (res.sendObserved) {
                clientHandled = true;
                WriteRawLog("Lua_Walk -> client handler accepted request");
                return;
            }
            missingSend = true;
        };

        attempt(false, "dir-only");
        if (!clientHandled)
            attempt(true, "dir+run");

        if (clientHandled) {
            lua_pushboolean(L, 1);
            return 1;
        }
    } else if (L && !g_clientWalkFn) {
        if (g_clientWalkClosureValid)
            WriteRawLog("Lua_Walk: no captured client walk C function; will try Lua closure");
        else
            WriteRawLog("Lua_Walk: no captured client walk handler; will use internal sender");
    }

    if (L && !clientHandled && g_clientWalkClosureValid) {
        auto attemptClosure = [&](bool includeRun, const char* label) {
            ClientWalkCallResult res = InvokeClientWalkClosure(L, dir, runValue, includeRun, label);
            if (!res.invoked)
                return;
            clientAttempted = true;
            if (!res.callSucceeded || !res.truthy)
                return;
            if (res.sendObserved) {
                clientHandled = true;
                WriteRawLog("Lua_Walk -> walk closure accepted request");
                return;
            }
            missingSend = true;
        };

        attemptClosure(false, "dir-only");
        if (!clientHandled)
            attemptClosure(true, "dir+run");

        if (clientHandled) {
            lua_pushboolean(L, 1);
            return 1;
        }
    }

    if (missingSend) {
        WriteRawLog("Lua_Walk: client handler returned, but no client 0x02 observed; falling back");
    } else if (clientAttempted) {
        WriteRawLog("Lua_Walk: client handler attempts failed; falling back to internal sender");
    }

    WriteRawLog("Lua_Walk using internal sender");
    bool ok = SendWalk(dir, run);
    WriteRawLog(ok ? "Lua_Walk -> internal sender succeeded" : "Lua_Walk -> internal sender failed");
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

static int __cdecl Lua_BindWalk(lua_State* L)
{
    WriteRawLog("Lua_BindWalk requested");
    Engine::Lua::EnsureWalkBinding("Lua.BindWalk");
    return 0;
}

static int __cdecl Lua_FastWalkInfo(lua_State* L)
{
    uint32_t key = Engine::PeekFastWalkKey();
    int depth = Engine::FastWalkQueueDepth();

    char buf[160];
    sprintf_s(buf, sizeof(buf), "Lua_FastWalkInfo depth=%d nextKey=%08X", depth, key);
    WriteRawLog(buf);

    lua_pushnumber(L, static_cast<lua_Number>(depth));
    if (key != 0) {
        lua_pushnumber(L, static_cast<lua_Number>(key));
    } else {
        lua_pushnil(L);
    }
    return 2;
}

static int __cdecl Lua_MovementInfo(lua_State* L)
{
    Engine::MovementDebugStatus status{};
    const char* reason = nullptr;
    bool ready = false;

    __try {
        Engine::GetMovementDebugStatus(status);
        ready = Engine::MovementReadyWithReason(&reason);
        status.ready = ready;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("Lua_MovementInfo: exception while capturing status");
        lua_pushnil(L);
        return 1;
    }

    char buf[256];
    sprintf_s(buf, sizeof(buf),
              "Lua_MovementInfo ready=%d updateHook=%d moveComp=%p candidate=%p pending=%d age=%u dir=%d run=%d depth=%d",
              status.ready ? 1 : 0,
              status.updateHookInstalled ? 1 : 0,
              status.movementComponentPtr,
              status.movementCandidatePtr,
              status.pendingMoveActive ? 1 : 0,
              status.pendingAgeMs,
              status.pendingDir,
              status.pendingRun ? 1 : 0,
              status.fastWalkDepth);
    WriteRawLog(buf);

    lua_createtable(L, 0, 12);

    lua_pushboolean(L, status.ready);
    lua_setfield(L, -2, "ready");

    lua_pushboolean(L, status.updateHookInstalled);
    lua_setfield(L, -2, "updateHookInstalled");

    lua_pushboolean(L, status.movementComponentCaptured);
    lua_setfield(L, -2, "movementComponentCaptured");

    lua_pushboolean(L, status.movementCandidatePending);
    lua_setfield(L, -2, "movementCandidatePending");

    lua_pushboolean(L, status.pendingMoveActive);
    lua_setfield(L, -2, "pendingMoveActive");

    lua_pushnumber(L, static_cast<lua_Number>(status.pendingAgeMs));
    lua_setfield(L, -2, "pendingAgeMs");

    lua_pushnumber(L, static_cast<lua_Number>(status.pendingDir));
    lua_setfield(L, -2, "pendingDir");

    lua_pushboolean(L, status.pendingRun);
    lua_setfield(L, -2, "pendingRun");

    lua_pushnumber(L, static_cast<lua_Number>(status.fastWalkDepth));
    lua_setfield(L, -2, "fastWalkDepth");

    auto pushPointerFields = [&](const char* userdataField, const char* stringField, void* ptr) {
        if (ptr) {
            lua_pushlightuserdata(L, ptr);
            lua_setfield(L, -2, userdataField);

            char ptrBuf[32];
            sprintf_s(ptrBuf, sizeof(ptrBuf), "0x%p", ptr);
            lua_pushstring(L, ptrBuf);
            lua_setfield(L, -2, stringField);
        } else {
            lua_pushnil(L);
            lua_setfield(L, -2, userdataField);
            lua_pushnil(L);
            lua_setfield(L, -2, stringField);
        }
    };

    pushPointerFields("movementComponentPtr", "movementComponentPtrStr", status.movementComponentPtr);
    pushPointerFields("movementCandidatePtr", "movementCandidatePtrStr", status.movementCandidatePtr);
    pushPointerFields("destinationPtr", "destinationPtrStr", status.destinationPtr);

    if (reason && reason[0] != '\0') {
        lua_pushstring(L, reason);
        lua_setfield(L, -2, "reason");
    }

    return 1;
}

namespace Engine::Lua {

void RegisterOurLuaFunctions()
{
    static bool dummyReg = false;
   static bool walkReg = false;
    static bool fastInfoReg = false;
    static bool movementInfoReg = false;
    static lua_State* lastState = nullptr;
    static bool lastMovementReady = false;

    ResolveRegisterFunction();

    if (Engine::RefreshLuaStateFromSlot()) {
        WriteRawLog("Lua state refreshed from global slot; pending re-registration");
    }

    auto L = static_cast<lua_State*>(Engine::LuaState());
    if (!L) {
        char buf[160];
        auto slotAddr = Engine::GlobalStateSlotAddress();
        auto slotValue = Engine::GlobalStateSlotValue();
        sprintf_s(buf, sizeof(buf),
            "Lua state not available yet (slot=%p value=%p)",
            reinterpret_cast<void*>(slotAddr),
            slotValue);
        WriteRawLog(buf);
        return;
    }

    bool movementReady = Engine::MovementReady();

    if (L != lastState || movementReady != lastMovementReady) {
        dummyReg = false;
        walkReg = false;
        fastInfoReg = false;
        movementInfoReg = false;
        lastState = L;
        lastMovementReady = movementReady;
        ClearClientWalkClosure(L);
        g_clientWalkFn = nullptr;
        WriteRawLog("Lua or movement state changed; reset registration flags");
    }

    if (!dummyReg) {
        WriteRawLog("Registering DummyPrint Lua function...");
        bool registered = RegisterViaClient(L, Lua_DummyPrint, "DummyPrint");
        if (!registered) {
            char buf[128];
            sprintf_s(buf, sizeof(buf), "DummyPrint registration using lua_State=%p", static_cast<void*>(L));
            WriteRawLog(buf);
            if (RegisterFunctionSafe(L, Lua_DummyPrint, "DummyPrint")) {
                registered = true;
            } else {
                WriteRawLog("Failed to register DummyPrint; postponing remaining registrations");
                return;
            }
        }
        if (registered) {
            WriteRawLog("Successfully registered DummyPrint");
            dummyReg = true;
        }
    }

    if (!fastInfoReg) {
        WriteRawLog("Registering fastWalkInfo Lua function...");
        if (RegisterViaClient(L, Lua_FastWalkInfo, "fastWalkInfo") ||
            RegisterFunctionSafe(L, Lua_FastWalkInfo, "fastWalkInfo")) {
            WriteRawLog("Successfully registered fastWalkInfo");
            fastInfoReg = true;
        } else {
            WriteRawLog("Failed to register fastWalkInfo (will retry)");
            return;
        }
    }

    if (!movementInfoReg) {
        WriteRawLog("Registering movementInfo Lua function...");
        if (RegisterViaClient(L, Lua_MovementInfo, "movementInfo") ||
            RegisterFunctionSafe(L, Lua_MovementInfo, "movementInfo")) {
            WriteRawLog("Successfully registered movementInfo");
            movementInfoReg = true;
        } else {
            WriteRawLog("Failed to register movementInfo (will retry)");
            return;
        }
    }

    if (!walkReg) {
        WriteRawLog("Registering walk Lua function...");
        CaptureClientWalkBinding(L, "pre-register");
        bool registered = RegisterViaClient(L, Lua_Walk, "walk");
        if (!registered) {
            char buf[128];
            sprintf_s(buf, sizeof(buf), "walk registration using lua_State=%p", static_cast<void*>(L));
            WriteRawLog(buf);
            if (RegisterFunctionSafe(L, Lua_Walk, "walk")) {
                registered = true;
            } else {
                WriteRawLog("Failed to register walk; will retry");
                return;
            }
        }
        if (registered) {
            WriteRawLog("Successfully registered walk");
            char buf[160];
            sprintf_s(buf, sizeof(buf), "walk registration used fn=%p (Lua_Walk=%p)",
                reinterpret_cast<void*>(Lua_Walk), reinterpret_cast<void*>(&Lua_Walk));
            WriteRawLog(buf);
            walkReg = true;
        }
    }

    WriteRawLog("Ensuring walk binding via helper registration");
    ForceWalkBinding(L, "post-register");

    static bool bindReg = false;
    if (!bindReg) {
        WriteRawLog("Registering bindWalk Lua function...");
        if (RegisterViaClient(L, Lua_BindWalk, "bindWalk") || RegisterFunctionSafe(L, Lua_BindWalk, "bindWalk")) {
            WriteRawLog("Successfully registered bindWalk");
            bindReg = true;
        } else {
            WriteRawLog("Failed to register bindWalk (will retry) ");
        }
    }

    WriteRawLog("RegisterOurLuaFunctions completed");
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
    FlushPendingRegistration();
}

bool InitLuaBridge()
{
    ResolveRegisterFunction();
    Engine::RequestWalkRegistration();
    return true;
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
