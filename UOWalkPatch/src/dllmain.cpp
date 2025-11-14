#include <windows.h>
#include <minhook.h>
#include <cstdio>
#include <cwchar>
#include <string>
#include <cstdlib>

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
#include "../include/Engine/CastFallback.hpp"
#include "../include/Util/OwnerPump.hpp"

namespace {

bool TryReadEnvInt(const wchar_t* key, int& outValue, const char* tag)
{
    if (!key)
        return false;
    wchar_t bufW[64]{};
    DWORD copied = GetEnvironmentVariableW(key, bufW, _countof(bufW));
    if (copied == 0 || copied >= _countof(bufW))
        return false;
    int value = _wtoi(bufW);
    if (value == 0)
        return false;
    outValue = value;
    char logBuf[160];
    sprintf_s(logBuf,
              sizeof(logBuf),
              "[Init] env %s=%S",
              tag ? tag : "env",
              bufW);
    WriteRawLog(logBuf);
    return true;
}

bool TryReadEnvIntA(const char* key, int& outValue, const char* tag)
{
    if (!key)
        return false;
    char bufA[64]{};
    DWORD copied = GetEnvironmentVariableA(key, bufA, static_cast<DWORD>(sizeof(bufA)));
    if (copied == 0 || copied >= sizeof(bufA))
        return false;
    int value = std::atoi(bufA);
    if (value == 0)
        return false;
    outValue = value;
    char logBuf[160];
    sprintf_s(logBuf,
              sizeof(logBuf),
              "[Init] env %s=%s",
              tag ? tag : "env",
              bufA);
    WriteRawLog(logBuf);
    return true;
}

} // namespace

#ifndef UOW_COMMIT_HASH
#define UOW_COMMIT_HASH "unknown"
#endif

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);
        Util::OwnerPump::Reset();
        Log::Init(hModule);
        char buildBuf[256];
        sprintf_s(buildBuf,
                  sizeof(buildBuf),
                  "[Build] commit=%s built=%s %s",
                  UOW_COMMIT_HASH,
                  __DATE__,
                  __TIME__);
        WriteRawLog(buildBuf);

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

        uint32_t targetWindowOverride = 0;
        const char* targetWindowSource = nullptr;
        int envValue = 0;
        if (TryReadEnvInt(L"UOW_DEBUG_TARGET_WINDOW_MS", envValue, "UOW_DEBUG_TARGET_WINDOW_MS") ||
            TryReadEnvIntA("UOW_DEBUG_TARGET_WINDOW_MS", envValue, "UOW_DEBUG_TARGET_WINDOW_MS")) {
            targetWindowOverride = static_cast<uint32_t>(envValue);
            targetWindowSource = "env:UOW_DEBUG_TARGET_WINDOW_MS";
        } else if (auto cfg = Core::Config::TryGetMilliseconds("uow.debug.target_window_ms")) {
            targetWindowOverride = *cfg;
            targetWindowSource = "cfg:uow.debug.target_window_ms";
        } else if (auto legacy = Core::Config::TryGetMilliseconds("TARGET_CORR_WINDOW_MS")) {
            targetWindowOverride = *legacy;
            targetWindowSource = "cfg:TARGET_CORR_WINDOW_MS";
        } else if (auto legacyEnv = Core::Config::TryGetEnv("TARGET_CORR_WINDOW_MS")) {
            targetWindowOverride = static_cast<uint32_t>(std::strtoul(legacyEnv->c_str(), nullptr, 10));
            targetWindowSource = "env:TARGET_CORR_WINDOW_MS";
        }
        if (targetWindowOverride > 0) {
            TargetCorrelatorSetWindow(targetWindowOverride);
            char buf[192];
            sprintf_s(buf,
                      sizeof(buf),
                      "[Init] target_window_ms=%u source=%s",
                      TargetCorrelatorGetWindow(),
                      targetWindowSource ? targetWindowSource : "override");
            WriteRawLog(buf);
        } else {
            char buf[192];
            sprintf_s(buf,
                      sizeof(buf),
                      "[Init] target_window_ms=%u source=default",
                      TargetCorrelatorGetWindow());
            WriteRawLog(buf);
        }

        if (!Engine::InitGlobalStateWatch())
            return FALSE;

        Engine::InitMovementHooks();
        Net::InitPacketTrace();
        Net::InitSendBuilder(const_cast<GlobalStateInfo*>(Engine::Info()));
        Engine::Lua::InitLuaBridge();
        Engine::CastFallback::Init();
        CastCorrelator::Init();
        TargetCorrelatorInit();
        break;
    }
    case DLL_PROCESS_DETACH:
        Engine::CastFallback::Shutdown();
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
        Util::OwnerPump::Reset();
        break;
    }
    return TRUE;
}
