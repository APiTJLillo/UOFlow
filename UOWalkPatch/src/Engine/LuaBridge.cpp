#include <windows.h>
#include <cstdio>
#include <minhook.h>

#include "Core/Logging.hpp"
#include "Net/SendBuilder.hpp"
#include "Engine/GlobalState.hpp"
#include "Engine/Movement.hpp"
#include "Engine/LuaBridge.hpp"
#include "LuaPlus.h"

namespace {
    static RegisterLuaFunction_t g_origRegLua = nullptr;
    static void* g_registerTarget = nullptr;
    static bool  g_hookInstalled = false;
    static bool  g_hookRegister = true;
}

static bool CallClientRegister(lua_State* L, void* func, const char* name);
static int  __cdecl Lua_DummyPrint(lua_State* L);
static int  __cdecl Lua_Walk(lua_State* L);
static bool __stdcall Hook_Register(lua_State* L, void* func, const char* name);
static bool InstallRegisterHook();

extern "C" __declspec(dllexport) void __stdcall SendRaw(const void* bytes, int len)
{
    if (!Net::SendPacketRaw(bytes, len))
        WriteRawLog("SendRaw called before prerequisites were ready");
}

static int __cdecl Lua_DummyPrint(lua_State* L)
{
    WriteRawLog("[Lua] DummyPrint() was invoked!");
    return 0;
}

static int __cdecl Lua_Walk(lua_State* L)
{
    int dir = 0;
    int run = 0;
    if (L)
    {
        int top = lua_gettop(L);
        if (top >= 1)
            dir = (int)(lua_tointeger(L, 1)) & 7;
        if (top >= 2)
            run = lua_toboolean(L, 2) ? 1 : 0;
    }
    SendWalk(dir, run);
    return 0;
}

static bool CallClientRegister(lua_State* L, void* func, const char* name)
{
    if (!g_origRegLua) {
        WriteRawLog("Original RegisterLuaFunction pointer not set!");
        return false;
    }
    __try {
        return g_origRegLua(static_cast<lua_State*>(L), func, name);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        char buf[64];
        sprintf_s(buf, sizeof(buf), "RegisterLuaFunction threw exception 0x%08X", code);
        WriteRawLog(buf);
        return false;
    }
}

namespace Engine::Lua {

void RegisterOurLuaFunctions()
{
    static bool dummyReg = false;
    static bool walkReg = false;
    auto L = static_cast<lua_State*>(Engine::LuaState());
    if (!L || !g_origRegLua)
        return;

    if (!dummyReg) {
        const char* luaName = "DummyPrint";
        WriteRawLog("Registering DummyPrint Lua function...");
        if (CallClientRegister(L, reinterpret_cast<void*>(Lua_DummyPrint), luaName))
        {
            char buf[128];
            sprintf_s(buf, sizeof(buf),
                "Successfully registered Lua function '%s' (%p)",
                luaName, Lua_DummyPrint);
            WriteRawLog(buf);
            dummyReg = true;
        }
        else
        {
            WriteRawLog("!! Failed to register DummyPrint");
        }
    }

    if (Engine::MovementReady() && !walkReg) {
        const char* walkName = "walk";
        WriteRawLog("Registering walk Lua function...");
        bool ok = CallClientRegister(L, reinterpret_cast<void*>(Lua_Walk), walkName);
        WriteRawLog(ok ? "Successfully registered walk()" :
            "!! Register walk() failed");
        if (ok) {
            walkReg = true;
        }
    }
    else if (!Engine::MovementReady() && !walkReg) {
        WriteRawLog("walk function prerequisites missing");
    }
    WriteRawLog("RegisterOurLuaFunctions completed");
}

bool InitLuaBridge()
{
    if (!g_hookRegister)
        return true;
    if (!InstallRegisterHook()) {
        WriteRawLog("Warning: RegisterLuaFunction hook not installed");
        return false;
    }
    return true;
}

void ShutdownLuaBridge()
{
    if (g_hookInstalled && g_registerTarget) {
        MH_DisableHook(g_registerTarget);
        MH_RemoveHook(g_registerTarget);
        g_registerTarget = nullptr;
        g_origRegLua = nullptr;
        g_hookInstalled = false;
    }
}

} // namespace Engine::Lua

static bool __stdcall Hook_Register(lua_State* L, void* func, const char* name)
{
    if (Engine::Info()) {
        return CallClientRegister(L, func, name);
    }

    auto currentState = static_cast<lua_State*>(Engine::LuaState());
    if (!currentState) {
        Engine::ReportLuaState(L);
        if (Engine::Info()) {
            WriteRawLog("DLL is now fully initialized - enjoy!");
            WriteRawLog("Registering our Lua functions...");
            Engine::RequestWalkRegistration();
        }
    }

    char buffer[256];
    sprintf_s(buffer, sizeof(buffer),
        "RegisterLuaFunction called:\n"
        "  Lua State: %p\n"
        "  Function: %p\n"
        "  Name: %s\n"
        "  Global State Info: %p",
        L, func, name ? name : "<null>", Engine::Info());
    WriteRawLog(buffer);

    WriteRawLog("Calling original RegisterLuaFunction...");
    bool ok = CallClientRegister(L, func, name);
    WriteRawLog(ok ? "Original RegisterLuaFunction returned true" :
        "Original RegisterLuaFunction returned false");

    return ok;
}

static bool InstallRegisterHook()
{
    LPVOID target = Engine::FindRegisterLuaFunction();
    if (!target) {
        WriteRawLog("RegisterLuaFunction not found");
        return false;
    }

    char buffer[64];
    sprintf_s(buffer, sizeof(buffer), "RegisterLuaFunction at %p", target);
    WriteRawLog(buffer);

    if (MH_CreateHook(target, &Hook_Register, reinterpret_cast<LPVOID*>(&g_origRegLua)) != MH_OK) {
        WriteRawLog("MH_CreateHook failed for RegisterLuaFunction");
        return false;
    }

    if (MH_EnableHook(target) != MH_OK) {
        WriteRawLog("MH_EnableHook failed");
        return false;
    }

    WriteRawLog("Hooks installed successfully");
    g_registerTarget = target;
    g_hookInstalled = true;
    return true;
}
