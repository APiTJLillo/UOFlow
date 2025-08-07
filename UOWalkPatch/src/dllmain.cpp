#include <windows.h>
#include <minhook.h>

#include "Core/Logging.hpp"
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
        LogLoadedModules();
        if (MH_Initialize() != MH_OK)
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
        MH_Uninitialize();
        Log::Shutdown();
        break;
    }
    return TRUE;
}

