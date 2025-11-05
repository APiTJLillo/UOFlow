#pragma once
#include <windows.h>
#include <cstdint>

struct GlobalStateInfo {
    void*    luaState;
    void*    databaseManager;
    void*    reserved0;
    void*    scriptContext;
    void*    resourceManager;
    uint32_t initFlags;
    void*    networkConfig;
    void*    engineContext;
    void*    globalFacetCache;
    bool     shutdownInitiated;
    void*    resourceNodePtr;
    void*    coreResourceMgr;
};

namespace Engine {
    bool InitGlobalStateWatch();
    void ShutdownGlobalStateWatch();
    void ReportLuaState(void* L);
    void* LuaState();
    const GlobalStateInfo* Info();
    uintptr_t GlobalStateSlotAddress();
    GlobalStateInfo* GlobalStateSlotValue();
    bool RefreshLuaStateFromSlot();
    void* FindRegisterLuaFunction();
}
