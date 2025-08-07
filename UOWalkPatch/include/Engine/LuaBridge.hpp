#pragma once

namespace Engine::Lua {
    bool InitLuaBridge();
    void ShutdownLuaBridge();
    void RegisterOurLuaFunctions();
}

extern "C" __declspec(dllexport) void __stdcall SendRaw(const void* bytes, int len);
