#include <windows.h>
#include <minhook.h>
#include <cstdio>
#include <cwchar>
#include <string>

#include "../include/Core/Logging.hpp"
#include "../include/Core/MinHookHelpers.hpp"
#include "../include/Engine/GlobalState.hpp"
#include "../include/Engine/Movement.hpp"
#include "../include/Engine/LuaBridge.hpp"
#include "../include/Net/PacketTrace.hpp"
#include "../include/Net/SendBuilder.hpp"
#include "../include/Core/Config.hpp"
#include "../include/Core/ActionTrace.hpp"
#include "SpellProbe.h"
#include "CastCorrelator.h"
#include "TargetCorrelator.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);
        Log::Init(hModule);

        // Determine directory of this DLL
        WCHAR dllDir[MAX_PATH];
        GetModuleFileNameW(hModule, dllDir, MAX_PATH);
        WCHAR* lastSlash = wcsrchr(dllDir, L'\\');
        if (!lastSlash) {
            WriteRawLog("Failed to determine DLL directory");
            return FALSE;
        }
        *(lastSlash + 1) = L'\0';

        // Build absolute path to luaplus_1100.dll located next to this DLL
        WCHAR fullPath[MAX_PATH];
        wcscpy_s(fullPath, dllDir);
        wcscat_s(fullPath, MAX_PATH, L"luaplus_1100.dll");
        WriteRawLog("Loading luaplus_1100.dll from:");
        char dirLog[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, fullPath, -1, dirLog, MAX_PATH, NULL, NULL);
        WriteRawLog(dirLog);

        // Load LuaPlus and use its directory for dependency resolution
        HMODULE luaplus = LoadLibraryExW(fullPath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!luaplus) {
            char buf[256];
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof(buf), NULL);
            WriteRawLog("Failed to load luaplus_1100.dll");
            WriteRawLog(buf);
            return FALSE;
        }

        // Verify essential functions are available
        const char* requiredFuncs[] = {
            "lua_gettop", "lua_tointeger", "lua_toboolean",
            "lua_pushnumber", "lua_pushstring", "lua_pushboolean"
        };

        for (const char* funcName : requiredFuncs) {
            if (!GetProcAddress(luaplus, funcName)) {
                char buf[256];
                sprintf_s(buf, sizeof(buf), "Failed to find function %s in luaplus_1100.dll", funcName);
                WriteRawLog(buf);
                FreeLibrary(luaplus);
                return FALSE;
            }
        }

        // Keep LuaPlus loaded for subsequent delay-load calls
        Log::LogLoadedModules();
        if (!Core::MinHookHelpers::Init())
            return FALSE;

        // Optional: configure correlation window from cfg/env
        if (auto ms = Core::Config::TryGetMilliseconds("TRACE_WINDOW_MS"))
            Trace::SetWindowMs(*ms);
        else if (auto ms2 = Core::Config::TryGetMilliseconds("trace.windowMs"))
            Trace::SetWindowMs(*ms2);

        if (!Engine::InitGlobalStateWatch())
            return FALSE;

        Engine::InitMovementHooks();
        Net::InitPacketTrace();
        Net::InitSendBuilder(const_cast<GlobalStateInfo*>(Engine::Info()));
        Engine::Lua::InitLuaBridge();
        CastCorrelator::Init();
        TargetCorrelatorInit();
        break;
    }
    case DLL_PROCESS_DETACH:
        TargetCorrelatorShutdown();
        CastCorrelator::Shutdown();
        SpellProbe_DisarmAll();
        Engine::Lua::ShutdownLuaBridge();
        Net::ShutdownSendBuilder();
        Net::ShutdownPacketTrace();
        Engine::ShutdownMovementHooks();
        Engine::ShutdownGlobalStateWatch();
        Core::MinHookHelpers::Shutdown();
        Log::Shutdown();
        break;
    }
    return TRUE;
}
