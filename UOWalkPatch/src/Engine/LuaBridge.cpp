#include <windows.h>
#include <cstdio>

#include "Core/Logging.hpp"
#include "Net/SendBuilder.hpp"
#include "Engine/GlobalState.hpp"
#include "Engine/Movement.hpp"
#include "Engine/LuaBridge.hpp"
#include "LuaPlus.h"

static int __cdecl Lua_DummyPrint(lua_State* L);
static int __cdecl Lua_Walk(lua_State* L);

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

namespace Engine::Lua {

void RegisterOurLuaFunctions()
{
    static bool dummyReg = false;
    static bool walkReg = false;
    auto L = static_cast<lua_State*>(Engine::LuaState());
    if (!L)
        return;

    if (!dummyReg) {
        WriteRawLog("Registering DummyPrint Lua function...");
        lua_pushcfunction(L, Lua_DummyPrint);
        lua_setglobal(L, "DummyPrint");
        WriteRawLog("Successfully registered Lua function 'DummyPrint'");
        dummyReg = true;
    }

    if (Engine::MovementReady() && !walkReg) {
        WriteRawLog("Registering walk Lua function...");
        lua_pushcfunction(L, Lua_Walk);
        lua_setglobal(L, "walk");
        WriteRawLog("Successfully registered walk()");
        walkReg = true;
    }
    else if (!Engine::MovementReady() && !walkReg) {
        WriteRawLog("walk function prerequisites missing");
    }
    WriteRawLog("RegisterOurLuaFunctions completed");
}

bool InitLuaBridge()
{
    return true;
}

void ShutdownLuaBridge()
{
    // no-op
}

} // namespace Engine::Lua
