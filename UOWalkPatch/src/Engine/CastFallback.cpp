#include "Engine/CastFallback.hpp"

#include <windows.h>
#include <Psapi.h>

#include <algorithm>
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

static const uint8_t kStdBuildActionPrologue[] = {0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8};
static const uint8_t kStdBuildActionMask[] = {1, 1, 1, 1, 1, 1};
static const uint8_t kHotpatchPrologue[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC};
static const uint8_t kHotpatchMask[] = {1, 1, 1, 1, 1};
static const uint8_t kTlsGuardStart[] = {0xA1, 0x00, 0x00, 0x00, 0x00, 0x33, 0xC5, 0x89, 0x45, 0xFC};
static const uint8_t kTlsGuardStartMask[] = {1, 0, 0, 0, 0, 1, 1, 1, 1, 1};
static const uint8_t kTlsGuardStd[] = {0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8};
static const uint8_t kTlsGuardStdMask[] = {1, 1, 1, 1, 1, 1};

struct ProloguePattern {
    const char* name;
    const uint8_t* bytes;
    const uint8_t* mask;
    size_t length;
};

struct PrologueMatch {
    bool ok = false;
    const char* variant = nullptr;
    int score = 0;
    int maxScore = 0;
};

struct GateCandidate {
    uintptr_t address = 0;
    const char* source = "RVA";
    PrologueMatch match;
};

static const ProloguePattern kProloguePatterns[] = {
    {"std", kStdBuildActionPrologue, kStdBuildActionMask, ARRAYSIZE(kStdBuildActionPrologue)},
    {"hotpatch", kHotpatchPrologue, kHotpatchMask, ARRAYSIZE(kHotpatchPrologue)},
    {"tls_guard_start", kTlsGuardStart, kTlsGuardStartMask, ARRAYSIZE(kTlsGuardStart)},
    {"tls_guard_std", kTlsGuardStd, kTlsGuardStdMask, ARRAYSIZE(kTlsGuardStd)}
};

static PrologueMatch MatchPattern(uintptr_t address, uintptr_t moduleBase, size_t moduleSize, const ProloguePattern& pattern)
{
    PrologueMatch match{};
    match.variant = pattern.name;
    int maxScore = 0;
    for (size_t i = 0; i < pattern.length; ++i) {
        if (pattern.mask[i])
            ++maxScore;
    }
    match.maxScore = maxScore;
    if (address < moduleBase || address + pattern.length > moduleBase + moduleSize)
        return match;
    const auto* bytes = reinterpret_cast<const uint8_t*>(address);
    int score = 0;
    for (size_t i = 0; i < pattern.length; ++i) {
        if (!pattern.mask[i])
            continue;
        if (bytes[i] != pattern.bytes[i]) {
            match.score = score;
            return match;
        }
        ++score;
    }
    match.score = score;
    match.ok = (score == maxScore);
    return match;
}

static PrologueMatch MatchPrologue(uintptr_t address, uintptr_t moduleBase, size_t moduleSize)
{
    PrologueMatch best{};
    for (const auto& pattern : kProloguePatterns) {
        auto match = MatchPattern(address, moduleBase, moduleSize, pattern);
        if (match.maxScore == 0)
            continue;
        if (!best.variant || match.score > best.score || (match.ok && !best.ok))
            best = match;
    }
    return best;
}

static uintptr_t FindFunctionStart(uintptr_t reference, uintptr_t moduleBase, size_t moduleSize)
{
    constexpr size_t kMaxBacktrack = 0x400;
    for (size_t back = 0; back < kMaxBacktrack && reference >= moduleBase + back + 1; ++back) {
        uintptr_t candidate = reference - back;
        auto match = MatchPrologue(candidate, moduleBase, moduleSize);
        if (match.maxScore > 0 && match.ok)
            return candidate;
    }
    return 0;
}

static GateCandidate EvaluateCandidate(uintptr_t address, const char* source, uintptr_t moduleBase, size_t moduleSize)
{
    GateCandidate candidate{};
    candidate.address = address;
    candidate.source = source;
    candidate.match = MatchPrologue(address, moduleBase, moduleSize);
    return candidate;
}

static GateCandidate ScanForBuildActionCandidate(uintptr_t moduleBase, size_t moduleSize)
{
    GateCandidate best{};
    best.match.score = -1;
    uintptr_t vtblAddr = moduleBase + Engine::Addresses::RVA_Vtbl_CastSpell;
    const auto* bytes = reinterpret_cast<const uint8_t*>(moduleBase);
    for (size_t offset = 0; offset + sizeof(uintptr_t) < moduleSize; ++offset) {
        uintptr_t value = *reinterpret_cast<const uintptr_t*>(bytes + offset);
        if (value != vtblAddr)
            continue;
        uintptr_t reference = moduleBase + offset;
        uintptr_t fnStart = FindFunctionStart(reference, moduleBase, moduleSize);
        if (!fnStart)
            continue;
        auto candidate = EvaluateCandidate(fnStart, "AOB", moduleBase, moduleSize);
        if (candidate.match.maxScore == 0)
            continue;
        if (candidate.match.score > best.match.score)
            best = candidate;
    }
    return best;
}

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
    MODULEINFO moduleInfo{};
    if (!GetModuleInformation(GetCurrentProcess(), reinterpret_cast<HMODULE>(g_moduleBase), &moduleInfo, sizeof(moduleInfo)))
        return;
    size_t moduleSize = moduleInfo.SizeOfImage;
    GateCandidate candidate = EvaluateCandidate(g_moduleBase + Engine::Addresses::RVA_BuildAction, "RVA", g_moduleBase, moduleSize);
    GateCandidate fallback = ScanForBuildActionCandidate(g_moduleBase, moduleSize);
    if (!candidate.match.ok && fallback.address != 0)
        candidate = fallback;
    else if (fallback.match.ok && fallback.address != 0 && fallback.match.score > candidate.match.score)
        candidate = fallback;
    char targetBuf[256];
    bool candidateValid = (candidate.address != 0);
    sprintf_s(targetBuf,
              sizeof(targetBuf),
              "[Gate] BuildAction @ %p found_by=%s score=%d/%d prologue_variant=%s gate_ok=%d",
              reinterpret_cast<void*>(candidate.address),
              candidate.source ? candidate.source : "unknown",
              candidate.match.score,
              candidate.match.maxScore,
              candidate.match.variant ? candidate.match.variant : "unknown",
              candidateValid ? 1 : 0);
    WriteRawLog(targetBuf);
    if (!candidateValid) {
        WriteRawLog("[Gate] signature mismatch at 0x0053E630, native fallback disabled.");
        return;
    }
    if (!candidate.match.ok) {
        WriteRawLog("[Gate] BuildAction signature heuristic failed; forcing fallback candidate");
    }
    g_expectedVtable = g_moduleBase + Engine::Addresses::RVA_Vtbl_CastSpell;
    g_buildActionTarget = reinterpret_cast<void*>(candidate.address);
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
