#include <windows.h>
#include <cstdio>
#include <cctype>
#include <cstring>
#include <minhook.h>

#include "Core/Logging.hpp"
#include "Net/SendBuilder.hpp"
#include "Engine/GlobalState.hpp"
#include "Engine/Movement.hpp"
#include "Engine/LuaBridge.hpp"
#include "LuaPlus.h"


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
static thread_local bool g_inScriptRegistration = false;
}

static int __stdcall Hook_Register(void* ctx, void* func, const char* name);
static int __cdecl Lua_Walk(lua_State* L);
static int __cdecl Lua_BindWalk(lua_State* L);

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

    int rc = g_clientRegister ? g_clientRegister(ctx, func, name) : 0;

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

    if (!g_inScriptRegistration) {
        if (InterlockedExchange(&g_pendingRegistration, 0)) {
            g_inScriptRegistration = true;
            Engine::Lua::RegisterOurLuaFunctions();
            g_inScriptRegistration = false;
        }
    }

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

static int __cdecl Lua_BindWalk(lua_State* L)
{
    WriteRawLog("Lua_BindWalk requested");
    Engine::Lua::EnsureWalkBinding("Lua.BindWalk");
    return 0;
}

namespace Engine::Lua {

void RegisterOurLuaFunctions()
{
    static bool dummyReg = false;
    static bool walkReg = false;
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
        lastState = L;
        lastMovementReady = movementReady;
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

    if (movementReady && !walkReg) {
        WriteRawLog("Registering UOFlow.Walk.move function via client helper...");
        if (RegisterViaClient(L, Lua_Walk, "UOFlow.Walk.move")) {
            char buf[160];
            sprintf_s(buf, sizeof(buf), "UOFlow.Walk.move registration used fn=%p (Lua_Walk=%p)",
                reinterpret_cast<void*>(Lua_Walk), reinterpret_cast<void*>(&Lua_Walk));
            WriteRawLog(buf);
            walkReg = true;
        } else {
            WriteRawLog("Failed to register UOFlow.Walk.move; will retry");
            return;
        }
    }
    else if (!movementReady && !walkReg) {
        WriteRawLog("UOFlow.Walk.move prerequisites missing");
    }

    WriteRawLog("Ensuring UOFlow.Walk.move binding via helper registration");
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
