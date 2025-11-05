#include <windows.h>
#include <cstdio>
#include <cctype>
#include <cstring>
#include <minhook.h>
#include <psapi.h>
#include <string>
#include <cstdlib>
#include <string>

#include "Core/Logging.hpp"
#include "Core/PatternScan.hpp"
#include "Core/Config.hpp"
#include "Net/SendBuilder.hpp"
#include "Engine/GlobalState.hpp"
#include "Engine/Movement.hpp"
#include "Engine/LuaBridge.hpp"
#include "LuaPlus.h"

// LuaPlus.h intentionally exposes only a subset of the Lua C API.
// Declare the few additional APIs we need for stack manipulation + pcall usage.
extern "C" {
    LUA_API void lua_insert(lua_State* L, int idx);
    LUA_API void lua_pushvalue(lua_State* L, int idx);
}
#ifndef LUA_MULTRET
#define LUA_MULTRET (-1)
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

    static volatile LONG g_directActionHooksInstalled = 0;
}

static int __stdcall Hook_Register(void* ctx, void* func, const char* name);
static int __cdecl Lua_Walk(lua_State* L);
static int __cdecl Lua_BindWalk(lua_State* L);
static int __cdecl Lua_UserActionCastSpell_W(lua_State* L);
static int __cdecl Lua_UserActionCastSpellOnId_W(lua_State* L);
static int __cdecl Lua_UserActionUseSkill_W(lua_State* L);
static int CallSavedOriginal(lua_State* L, const char* savedName);

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
        if (any) {
            InterlockedExchange(&g_actionWrappersInstalled, 1);
            WriteRawLog("TryInstallActionWrappers: installed action wrappers via Lua API");
        }
        if (now >= s_nextMissingLogMs) {
            s_nextMissingLogMs = now + 1000;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("TryInstallActionWrappers: exception while probing Lua globals; will retry later");
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
            any = true;
        }
    };

    hookOne("UserActionCastSpell", g_origUserActionCastSpell, &Lua_UserActionCastSpell_W);
    hookOne("UserActionCastSpellOnId", g_origUserActionCastSpellOnId, &Lua_UserActionCastSpellOnId_W);
    hookOne("UserActionUseSkill", g_origUserActionUseSkill, &Lua_UserActionUseSkill_W);

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

    // Optionally replace certain client Lua C functions with wrappers
    void* outFunc = func;
    if (name && func)
    {
        if (_stricmp(name, "UserActionCastSpell") == 0)
        {
            if (!g_origUserActionCastSpell)
            {
                g_origUserActionCastSpell = reinterpret_cast<LuaFn>(func);
                outFunc = reinterpret_cast<void*>(&Lua_UserActionCastSpell_W);
                WriteRawLog("Hook_Register: wrapped UserActionCastSpell");
            }
        }
        else if (_stricmp(name, "UserActionCastSpellOnId") == 0)
        {
            if (!g_origUserActionCastSpellOnId)
            {
                g_origUserActionCastSpellOnId = reinterpret_cast<LuaFn>(func);
                outFunc = reinterpret_cast<void*>(&Lua_UserActionCastSpellOnId_W);
                WriteRawLog("Hook_Register: wrapped UserActionCastSpellOnId");
            }
        }
        else if (_stricmp(name, "UserActionUseSkill") == 0 || _stricmp(name, "UserActionUsePrimaryAbility") == 0)
        {
            if (!g_origUserActionUseSkill)
            {
                g_origUserActionUseSkill = reinterpret_cast<LuaFn>(func);
                outFunc = reinterpret_cast<void*>(&Lua_UserActionUseSkill_W);
                WriteRawLog("Hook_Register: wrapped UserActionUseSkill");
            }
        }
        else if (_stricmp(name, "RequestTargetInfo") == 0)
        {
            g_targetApiTimestamp = GetTickCount();
            InterlockedExchange(&g_targetApiSeen, 1);
        }
        else if (_stricmp(name, "ClearCurrentTarget") == 0)
        {
            g_targetApiTimestamp = GetTickCount();
            InterlockedExchange(&g_targetApiSeen, 1);
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
        char buf[96];
        sprintf_s(buf, sizeof(buf), "[%s] #%u: %p", tag ? tag : "LuaWrap", i, frames[i]);
        WriteRawLog(buf);
    }
}

static int __cdecl Lua_UserActionCastSpell_W(lua_State* L)
{
    WriteRawLog("[Lua] UserActionCastSpell() wrapper invoked");
    DumpStackTag("CastSpell");
    // Prefer saved original in Lua state; fall back to captured pointer.
    int rc = CallSavedOriginal(L, "UserActionCastSpell__orig");
    if (rc >= 0) {
        WriteRawLog("[Lua] UserActionCastSpell() wrapper exit (saved)");
        return rc;
    }
    if (g_origUserActionCastSpell) {
        int out = 0;
        __try { out = g_origUserActionCastSpell(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] UserActionCastSpell original threw"); }
        WriteRawLog("[Lua] UserActionCastSpell() wrapper exit (orig ptr)");
        return out;
    }
    WriteRawLog("[Lua] UserActionCastSpell original missing (saved and ptr)");
    return 0;
}

static int __cdecl Lua_UserActionCastSpellOnId_W(lua_State* L)
{
    WriteRawLog("[Lua] UserActionCastSpellOnId() wrapper invoked");
    DumpStackTag("CastSpellOnId");
    int rc = CallSavedOriginal(L, "UserActionCastSpellOnId__orig");
    if (rc >= 0) {
        WriteRawLog("[Lua] UserActionCastSpellOnId() wrapper exit (saved)");
        return rc;
    }
    if (g_origUserActionCastSpellOnId) {
        int out = 0;
        __try { out = g_origUserActionCastSpellOnId(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] UserActionCastSpellOnId original threw"); }
        WriteRawLog("[Lua] UserActionCastSpellOnId() wrapper exit (orig ptr)");
        return out;
    }
    WriteRawLog("[Lua] UserActionCastSpellOnId original missing (saved and ptr)");
    return 0;
}

static int __cdecl Lua_UserActionUseSkill_W(lua_State* L)
{
    WriteRawLog("[Lua] UserActionUseSkill() wrapper invoked");
    DumpStackTag("UseSkill");
    int rc = CallSavedOriginal(L, "UserActionUseSkill__orig");
    if (rc >= 0) {
        WriteRawLog("[Lua] UserActionUseSkill() wrapper exit (saved)");
        return rc;
    }
    if (g_origUserActionUseSkill) {
        int out = 0;
        __try { out = g_origUserActionUseSkill(L); }
        __except (EXCEPTION_EXECUTE_HANDLER) { WriteRawLog("[Lua] UserActionUseSkill original threw"); }
        WriteRawLog("[Lua] UserActionUseSkill() wrapper exit (orig ptr)");
        return out;
    }
    WriteRawLog("[Lua] UserActionUseSkill original missing (saved and ptr)");
    return 0;
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

bool InitLuaBridge()
{
    // Prefer configuration file, fall back to environment variable for compatibility.
    bool enableHook = false;
    if (auto v = Core::Config::TryGetBool("UOWP_ENABLE_LUA_REGISTER_HOOK"))
        enableHook = *v;
    else if (const char* env = std::getenv("UOWP_ENABLE_LUA_REGISTER_HOOK"))
        enableHook = (env[0] == '1' || env[0] == 'y' || env[0] == 'Y' || env[0] == 't' || env[0] == 'T');

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
