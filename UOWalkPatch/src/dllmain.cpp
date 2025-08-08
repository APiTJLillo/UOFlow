#include <windows.h>
#include <minhook.h>

#include "Core/Logging.hpp"
#include "Core/MinHookHelpers.hpp"
#include "Engine/GlobalState.hpp"
#include "Engine/Movement.hpp"
#include "Engine/LuaBridge.hpp"
#include "Net/PacketTrace.hpp"
#include "Net/SendBuilder.hpp"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        Log::Init(hModule);
        Log::LogLoadedModules();
        if (!Core::MinHookHelpers::Init())
            return FALSE;
        Engine::InitGlobalStateWatch();
        Engine::InitMovementHooks();
        Net::InitPacketTrace();
        Net::InitSendBuilder(const_cast<GlobalStateInfo*>(Engine::Info()));
        Engine::Lua::InitLuaBridge();
        break;
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

