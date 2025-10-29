#pragma once
#include <cstdint>
#include "LuaPlus.h"

namespace Engine::Lua {
    bool InitLuaBridge();
    void ShutdownLuaBridge();
    void RegisterOurLuaFunctions();
    void UpdateEngineContext(void* context);
    void EnsureWalkBinding(const char* reason = nullptr);
    void ScheduleWalkBinding();
    void ProcessLuaQueue();
    void OnStateObserved(lua_State* L, void* scriptCtx, std::uint32_t ownerTid = 0);
    void OnStateRemoved(lua_State* L, const char* reason);
}

extern "C" __declspec(dllexport) void __stdcall SendRaw(const void* bytes, int len);
