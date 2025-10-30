#include <windows.h>
#include <minhook.h>
#include <cstdio>
#include <cwchar>

#include "../include/Core/Logging.hpp"
#include "../include/Core/MinHookHelpers.hpp"
#include "../include/Core/CrashHandler.hpp"
#include "../include/Core/Startup.hpp"
#include "../include/Core/EarlyTrace.hpp"
#include "../include/Engine/GlobalState.hpp"
#include "../include/Engine/Movement.hpp"
#include "../include/Engine/LuaBridge.hpp"
#include "../include/Net/PacketTrace.hpp"
#include "../include/Net/SendBuilder.hpp"
#include "../include/Walk/WalkController.hpp"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        Core::EarlyTrace::Initialize(hModule);
        Core::EarlyTrace::Write("DllMain attach entry");
        DisableThreadLibraryCalls(hModule);
        Log::Init(hModule);
        Core::EarlyTrace::Write("Log::Init completed");
        Core::CrashHandler::Init(hModule);
        Core::EarlyTrace::Write("CrashHandler::Init completed");

        // Determine directory of this DLL
        WCHAR dllDir[MAX_PATH];
        GetModuleFileNameW(hModule, dllDir, MAX_PATH);
        WCHAR* lastSlash = wcsrchr(dllDir, L'\\');
        if (!lastSlash) {
            Core::EarlyTrace::Write("Failed to determine DLL directory");
            Log::Logf(Log::Level::Error, Log::Category::Core, "Failed to determine DLL directory");
            return FALSE;
        }
        *(lastSlash + 1) = L'\0';

        // Build absolute path to luaplus_1100.dll located next to this DLL
        WCHAR fullPath[MAX_PATH];
        wcscpy_s(fullPath, dllDir);
        wcscat_s(fullPath, MAX_PATH, L"luaplus_1100.dll");
        char dirLog[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, fullPath, -1, dirLog, MAX_PATH, NULL, NULL);
        Log::Logf(Log::Level::Info, Log::Category::Core, "Loading luaplus_1100.dll from: %s", dirLog);
        Core::EarlyTrace::Write("Attempting to load luaplus_1100.dll");

        // Load LuaPlus and use its directory for dependency resolution
        HMODULE luaplus = LoadLibraryExW(fullPath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!luaplus) {
            char buf[256];
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof(buf), NULL);
            Core::EarlyTrace::Write("Failed to load luaplus_1100.dll");
            Log::Logf(Log::Level::Error, Log::Category::Core, "Failed to load luaplus_1100.dll: %s", buf);
            return FALSE;
        }
        Core::EarlyTrace::Write("luaplus_1100.dll loaded");

        // Verify essential functions are available
        const char* requiredFuncs[] = {
            "lua_gettop", "lua_tointeger", "lua_toboolean",
            "lua_pushnumber", "lua_pushstring", "lua_pushboolean"
        };

        for (const char* funcName : requiredFuncs) {
            if (!GetProcAddress(luaplus, funcName)) {
                char buf[256];
                sprintf_s(buf, sizeof(buf), "Failed to find function %s in luaplus_1100.dll", funcName);
                Log::Logf(Log::Level::Error, Log::Category::Core, "%s", buf);
                FreeLibrary(luaplus);
                Core::EarlyTrace::Write("Missing LuaPlus export");
                return FALSE;
            }
        }
        Core::EarlyTrace::Write("LuaPlus exports validated");

        // Keep LuaPlus loaded for subsequent delay-load calls
        Log::LogLoadedModules();
        Core::EarlyTrace::Write("Logged loaded modules");
        if (!Core::MinHookHelpers::Init()) {
            Core::EarlyTrace::Write("MinHookHelpers::Init FAILED");
            return FALSE;
        }
        Core::EarlyTrace::Write("MinHookHelpers::Init succeeded");

        if (!Engine::InitGlobalStateWatch()) {
            Core::EarlyTrace::Write("InitGlobalStateWatch FAILED");
            return FALSE;
        }
        Core::EarlyTrace::Write("InitGlobalStateWatch succeeded");

        const bool movementHooksOk = Engine::InitMovementHooks();
        const bool packetTraceOk = Net::InitPacketTrace();
        const bool sendBuilderOk = Net::InitSendBuilder(const_cast<GlobalStateInfo*>(Engine::Info()));
        const bool luaBridgeOk = Engine::Lua::InitLuaBridge();
        Core::EarlyTrace::Write("Primary subsystem inits completed");

        if (!movementHooksOk) {
            Log::Logf(Log::Level::Warn, Log::Category::Core, "InitMovementHooks reported failure");
        }
        if (!packetTraceOk) {
            Log::Logf(Log::Level::Warn, Log::Category::Core, "InitPacketTrace reported failure");
        }
        if (!sendBuilderOk) {
            Log::Logf(Log::Level::Warn, Log::Category::Core, "InitSendBuilder reported failure");
        }
        if (!luaBridgeOk) {
            Log::Logf(Log::Level::Warn, Log::Category::Core, "InitLuaBridge reported failure");
        }

        Walk::Controller::Settings walkSettings = Walk::Controller::GetSettings();
        Engine::Lua::StartupStatus luaStatus{};
        Engine::Lua::GetStartupStatus(luaStatus);

        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "startup summary hooks.movement=%d hooks.net=%d hooks.send=%d lua.bridge=%d engine.ctx=%d lua.state=%d helpers=%d walk.enable=%d maxInflight=%u stepDelayMs=%u timeoutMs=%u debug=%d helperOwnerTid=%u",
                  movementHooksOk ? 1 : 0,
                  packetTraceOk ? 1 : 0,
                  sendBuilderOk ? 1 : 0,
                  luaBridgeOk ? 1 : 0,
                  luaStatus.engineContextDiscovered ? 1 : 0,
                  luaStatus.luaStateDiscovered ? 1 : 0,
                  luaStatus.helpersInstalled ? 1 : 0,
                  walkSettings.enabled ? 1 : 0,
                  walkSettings.maxInflight,
                  walkSettings.stepDelayMs,
                  walkSettings.timeoutMs,
                  walkSettings.debug ? 1 : 0,
                  luaStatus.ownerThreadId);
        Core::StartupSummary::Initialize(movementHooksOk, packetTraceOk, sendBuilderOk, luaBridgeOk);
        break;
    }
    case DLL_PROCESS_DETACH:
        Engine::Lua::ShutdownLuaBridge();
        Net::ShutdownSendBuilder();
        Net::ShutdownPacketTrace();
        Engine::ShutdownMovementHooks();
        Engine::ShutdownGlobalStateWatch();
        Core::MinHookHelpers::Shutdown();
        Core::CrashHandler::Shutdown();
        Log::Shutdown();
        break;
    }
    return TRUE;
}
