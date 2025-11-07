#pragma once
#include "LuaPlus.h"

namespace Engine::Lua {
    bool InitLuaBridge();
    void ShutdownLuaBridge();
    void RegisterOurLuaFunctions();
    void UpdateEngineContext(void* context);
    void EnsureWalkBinding(const char* reason = nullptr);
    void ScheduleWalkBinding();
    // Called from safe, game-thread contexts (e.g., movement update) to retry wrapper installs
    void PollLateInstalls();
    // Notified whenever SendPacket executes (used to correlate delayed CastSpell packets).
    void NotifySendPacket(unsigned counter, const void* bytes, int len);
}

extern "C" __declspec(dllexport) void __stdcall SendRaw(const void* bytes, int len);
