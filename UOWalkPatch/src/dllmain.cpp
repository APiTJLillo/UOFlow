#include <windows.h>
#include <minhook.h>
#include <cstdio>
#include <cwchar>

#include "../include/Core/Logging.hpp"
#include "../include/Core/MinHookHelpers.hpp"
#include "../include/Engine/GlobalState.hpp"
#include "../include/Engine/Movement.hpp"
#include "../include/Engine/LuaBridge.hpp"
#include "../include/Net/PacketTrace.hpp"
#include "../include/Net/SendBuilder.hpp"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);
        Log::Init(hModule);

        // Get current DLL directory
        WCHAR dllDir[MAX_PATH];
        GetModuleFileNameW(hModule, dllDir, MAX_PATH);
        WCHAR* lastSlash = wcsrchr(dllDir, L'\\');
        if (lastSlash) {
            *(lastSlash + 1) = L'\0';
            WriteRawLog("Setting DLL directory to:");
            char dirLog[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, dllDir, -1, dirLog, MAX_PATH, NULL, NULL);
            WriteRawLog(dirLog);
            
            // Add our directory to DLL search path
            if (!SetDllDirectoryW(dllDir)) {
                WriteRawLog("SetDllDirectoryW failed, trying AddDllDirectory...");
                AddDllDirectory(dllDir);
            }
        }

        // Try loading LuaPlus - first from search path
        HMODULE luaplus = LoadLibraryW(L"luaplus_1100.dll");
        
        // If that fails, try absolute path
        if (!luaplus && lastSlash) {
            WCHAR fullPath[MAX_PATH];
            wcscpy_s(fullPath, dllDir);
            wcscat_s(fullPath, MAX_PATH, L"luaplus_1100.dll");
            WriteRawLog("Trying absolute path...");
            luaplus = LoadLibraryW(fullPath);
        }

        if (!luaplus) {
            char buf[256];
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), 
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof(buf), NULL);
            WriteRawLog("Failed to load luaplus_1100.dll from both system path and DLL directory");
            WriteRawLog(buf);
            return FALSE;
        }

        // Restore default DLL directory
        SetDllDirectoryW(NULL);

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

        FreeLibrary(luaplus); // Let the normal DLL loading handle it
        Log::LogLoadedModules();
        if (!Core::MinHookHelpers::Init())
            return FALSE;
        Engine::InitGlobalStateWatch();
        Engine::InitMovementHooks();
        Net::InitPacketTrace();
        Net::InitSendBuilder(const_cast<GlobalStateInfo*>(Engine::Info()));
        Engine::Lua::InitLuaBridge();
        break;
    }
    case DLL_PROCESS_DETACH:
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
