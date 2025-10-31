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
    void OnStateObserved(lua_State* L, void* scriptCtx, std::uint32_t ownerTid = 0, bool adoptThread = true);
    void OnStateRemoved(lua_State* L, const char* reason);
    void GetHelperProbeStats(uint32_t& attempted, uint32_t& succeeded, uint32_t& skipped);
    uint32_t GetSehTrapCount();

    struct StartupStatus {
        bool engineContextDiscovered = false;
        bool luaStateDiscovered = false;
        bool helpersInstalled = false;
        std::uint32_t ownerThreadId = 0;
    };

    void GetStartupStatus(StartupStatus& out);
    const char* GetHelperStageSummary();
}

extern "C" __declspec(dllexport) void __stdcall SendRaw(const void* bytes, int len);
