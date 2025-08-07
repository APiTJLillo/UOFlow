#pragma once
#include <windows.h>

struct GlobalStateInfo {
    void*    luaState;
    void*    databaseManager;
    uint8_t  reserved8[8];
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
    void* FindRegisterLuaFunction();
}

