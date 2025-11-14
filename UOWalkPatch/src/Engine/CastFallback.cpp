#include "Engine/CastFallback.hpp"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <minhook.h>

#include "Core/Config.hpp"
#include "Core/Logging.hpp"
#include "CastCorrelator.h"
#include "Engine/Addresses.h"

namespace Engine::CastFallback {
namespace {

using BuildActionFn = void* (__thiscall*)(void*, void*, void*);

constexpr int kMaxNativeFaults = 3;

BuildActionFn g_origBuildAction = nullptr;
void* g_buildActionTarget = nullptr;
std::atomic<bool> g_nativeActive{false};
std::atomic<int> g_faultStreak{0};
uintptr_t g_moduleBase = 0;
uintptr_t g_expectedVtable = 0;

bool ShouldEnableFallback()
{
    auto readCastTrace = []() -> bool {
        if (auto cfgPrimary = Core::Config::TryGetBool("debug.casttrace"))
            return *cfgPrimary;
        if (auto cfgLegacy = Core::Config::TryGetBool("UOW_DEBUG_CASTTRACE"))
            return *cfgLegacy;
        if (auto envPrimary = Core::Config::TryGetEnvBool("debug.casttrace"))
            return *envPrimary;
        if (auto envLegacy = Core::Config::TryGetEnvBool("UOW_DEBUG_CASTTRACE"))
            return *envLegacy;
        return false;
    };
    bool enabled = readCastTrace();
    if (auto cfg = Core::Config::TryGetBool("debug.native_cast_fallback"))
        enabled = *cfg;
    else if (auto env = Core::Config::TryGetEnvBool("debug.native_cast_fallback"))
        enabled = *env;
    return enabled;
}

bool VerifyBuildActionSignature(uintptr_t address)
{
    BYTE expected[] = {0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8};
    BYTE bytes[ARRAYSIZE(expected)]{};
    __try {
        memcpy(bytes, reinterpret_cast<const void*>(address), sizeof(bytes));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return memcmp(bytes, expected, sizeof(bytes)) == 0;
}

void DisableNativeFallback(DWORD code)
{
    bool expected = true;
    if (!g_nativeActive.compare_exchange_strong(expected, false, std::memory_order_acq_rel))
        return;
    if (g_buildActionTarget)
        MH_DisableHook(g_buildActionTarget);
    char buf[160];
    sprintf_s(buf,
              sizeof(buf),
              "[CastUI/native] disabled after %d faults (code=0x%08X)",
              kMaxNativeFaults,
              code);
    WriteRawLog(buf);
}

void* __fastcall Hook_BuildAction(void* self, void*, void* a1, void* a2)
{
    if (!g_origBuildAction)
        return nullptr;
    if (!g_nativeActive.load(std::memory_order_acquire))
        return g_origBuildAction(self, a1, a2);

    bool faulted = false;
    DWORD faultCode = 0;

    __try {
        if (self) {
            auto vtbl = *reinterpret_cast<uintptr_t*>(self);
            if (vtbl == g_expectedVtable) {
                auto base = static_cast<std::uint8_t*>(self);
                uint32_t targetType = *reinterpret_cast<uint32_t*>(base + Engine::Addresses::CAST_OFS_TargetType);
                uint32_t spellId = *reinterpret_cast<uint32_t*>(base + Engine::Addresses::CAST_OFS_SpellId);
                uint32_t iconId = *reinterpret_cast<uint32_t*>(base + Engine::Addresses::CAST_OFS_IconId);
                uint32_t targetId = *reinterpret_cast<uint32_t*>(base + Engine::Addresses::CAST_OFS_TargetId);
                char buf[256];
                sprintf_s(buf,
                          sizeof(buf),
                          "[CastUI/native] self=%p vtbl=%p spellId=%u targetType=%u targetId=%08X iconId=%u",
                          self,
                          reinterpret_cast<void*>(vtbl),
                          spellId,
                          targetType,
                          targetId,
                          iconId);
                WriteRawLog(buf);
                CastCorrelator::OnCastAttempt(spellId);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        faulted = true;
        faultCode = GetExceptionCode();
    }

    if (faulted) {
        int streak = g_faultStreak.fetch_add(1, std::memory_order_acq_rel) + 1;
        if (streak >= kMaxNativeFaults)
            DisableNativeFallback(faultCode);
    } else {
        g_faultStreak.store(0, std::memory_order_release);
    }

    return g_origBuildAction(self, a1, a2);
}

} // namespace

void Init()
{
    if (!ShouldEnableFallback())
        return;
    if (g_buildActionTarget)
        return;
    g_moduleBase = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    char gateBuf[160];
    sprintf_s(gateBuf, sizeof(gateBuf), "[Gate] module base=%p", reinterpret_cast<void*>(g_moduleBase));
    WriteRawLog(gateBuf);
    uintptr_t buildAction = g_moduleBase + Engine::Addresses::RVA_BuildAction;
    bool prologueOk = VerifyBuildActionSignature(buildAction);
    char targetBuf[200];
    sprintf_s(targetBuf,
              sizeof(targetBuf),
              "[Gate] BuildAction at %p (rva=0x%08X) prologue_ok=%d",
              reinterpret_cast<void*>(buildAction),
              Engine::Addresses::RVA_BuildAction,
              prologueOk ? 1 : 0);
    WriteRawLog(targetBuf);
    if (!prologueOk) {
        WriteRawLog("[Gate] signature mismatch at 0x0053E630, native fallback disabled.");
        return;
    }
    g_expectedVtable = g_moduleBase + Engine::Addresses::RVA_Vtbl_CastSpell;
    g_buildActionTarget = reinterpret_cast<void*>(buildAction);
    if (MH_CreateHook(g_buildActionTarget,
                      reinterpret_cast<LPVOID>(Hook_BuildAction),
                      reinterpret_cast<LPVOID*>(&g_origBuildAction)) != MH_OK)
        return;
    if (MH_EnableHook(g_buildActionTarget) != MH_OK) {
        g_origBuildAction = nullptr;
        return;
    }
    g_nativeActive.store(true, std::memory_order_release);
    g_faultStreak.store(0, std::memory_order_release);
}

void Shutdown()
{
    g_nativeActive.store(false, std::memory_order_release);
    if (g_buildActionTarget) {
        MH_DisableHook(g_buildActionTarget);
        MH_RemoveHook(g_buildActionTarget);
        g_buildActionTarget = nullptr;
    }
    g_origBuildAction = nullptr;
}

} // namespace Engine::CastFallback
