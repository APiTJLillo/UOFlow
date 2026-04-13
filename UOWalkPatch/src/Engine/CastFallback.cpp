#include "Engine/CastFallback.hpp"

#include <windows.h>
#include <Psapi.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>

#include <minhook.h>

#include "Core/Config.hpp"
#include "Core/Logging.hpp"
#include "CastCorrelator.h"
#include "Engine/Addresses.h"
#include "Engine/LuaBridge.hpp"

namespace Engine::CastFallback {
namespace {

using BuildActionFn = void* (__thiscall*)(void*, void*, void*);
using EnqueueActionFn = void(__thiscall*)(void*, void*);

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
EnqueueActionFn g_origEnqueueAction = nullptr;
void* g_buildActionTarget = nullptr;
void* g_enqueueActionTarget = nullptr;
std::atomic<bool> g_nativeActive{false};
std::atomic<int> g_faultStreak{0};
std::atomic<bool> g_castQueueSnapshotDisabled{false};
uintptr_t g_moduleBase = 0;
uintptr_t g_expectedVtable = 0;
std::atomic<int> g_logActionQueue{0};

struct ExpectedCastState {
    bool armed = false;
    std::uint32_t token = 0;
    std::uint32_t spellId = 0;
    std::uint32_t targetType = 0;
    std::uint32_t targetId = 0;
    bool onId = false;
    ExpectedCastResult result{};
};

std::mutex g_expectedCastMutex;
ExpectedCastState g_expectedCast{};

struct ActionSnapshot {
    uintptr_t vtbl = 0;
    uint32_t targetType = 0;
    uint32_t spellId = 0;
    uint32_t iconId = 0;
    uint32_t targetId = 0;
    uint8_t targetReady = 0;
    bool ok = false;
};

struct QueueSnapshot {
    uintptr_t slot0 = 0;
    uintptr_t slot1 = 0;
    bool ok = false;
};

static ActionSnapshot ReadActionSnapshot(void* action)
{
    ActionSnapshot snap{};
    if (!action)
        return snap;
    __try {
        auto base = static_cast<std::uint8_t*>(action);
        snap.vtbl = *reinterpret_cast<uintptr_t*>(base);
        snap.targetType = *reinterpret_cast<uint32_t*>(base + Engine::Addresses::CAST_OFS_TargetType);
        snap.spellId = *reinterpret_cast<uint32_t*>(base + Engine::Addresses::CAST_OFS_SpellId);
        snap.iconId = *reinterpret_cast<uint32_t*>(base + Engine::Addresses::CAST_OFS_IconId);
        snap.targetId = *reinterpret_cast<uint32_t*>(base + Engine::Addresses::CAST_OFS_TargetId);
        snap.targetReady = *reinterpret_cast<uint8_t*>(base + Engine::Addresses::CAST_OFS_TargetReadyFlag);
        snap.ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snap.ok = false;
    }
    return snap;
}

static QueueSnapshot ReadQueueSnapshot(void* queue)
{
    QueueSnapshot snap{};
    if (!queue)
        return snap;
    __try {
        auto base = static_cast<std::uint8_t*>(queue);
        snap.slot0 = *reinterpret_cast<uintptr_t*>(base + 0x00);
        snap.slot1 = *reinterpret_cast<uintptr_t*>(base + 0x08);
        snap.ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snap.ok = false;
    }
    return snap;
}

static bool LooksLikeSpellAction(const ActionSnapshot& snap)
{
    if (!snap.ok)
        return false;
    if (snap.spellId == 0 || snap.spellId > 1000)
        return false;
    if (snap.targetType > 8)
        return false;
    return true;
}

static bool MatchesExpectedAction(const ExpectedCastState& expected, const ActionSnapshot& snap)
{
    if (!expected.armed || !snap.ok)
        return false;
    if (snap.spellId != expected.spellId)
        return false;
    if (snap.targetType != expected.targetType)
        return false;
    if (expected.onId) {
        if (snap.targetId != expected.targetId)
            return false;
        if (snap.targetReady != 1)
            return false;
    }
    return true;
}

static void RecordBuildMatch(const ExpectedCastState& expected, const ActionSnapshot& snap, void* action)
{
    std::lock_guard<std::mutex> lock(g_expectedCastMutex);
    if (!g_expectedCast.armed || g_expectedCast.token != expected.token)
        return;
    g_expectedCast.result.hooksActive = true;
    g_expectedCast.result.buildMatched = true;
    g_expectedCast.result.buildAction = reinterpret_cast<std::uintptr_t>(action);
    g_expectedCast.result.spellId = snap.spellId;
    g_expectedCast.result.targetType = snap.targetType;
    g_expectedCast.result.targetId = snap.targetId;
    g_expectedCast.result.flag18 = snap.targetReady;
}

static void RecordEnqueueMatch(const ExpectedCastState& expected,
                               const ActionSnapshot& snap,
                               void* action,
                               const QueueSnapshot& beforeQueue,
                               const QueueSnapshot& afterQueue)
{
    std::lock_guard<std::mutex> lock(g_expectedCastMutex);
    if (!g_expectedCast.armed || g_expectedCast.token != expected.token)
        return;
    g_expectedCast.result.hooksActive = true;
    g_expectedCast.result.enqueueMatched = true;
    g_expectedCast.result.enqueueAction = reinterpret_cast<std::uintptr_t>(action);
    g_expectedCast.result.spellId = snap.spellId;
    g_expectedCast.result.targetType = snap.targetType;
    g_expectedCast.result.targetId = snap.targetId;
    g_expectedCast.result.flag18 = snap.targetReady;
    g_expectedCast.result.queueSlot0Before = beforeQueue.ok ? beforeQueue.slot0 : 0;
    g_expectedCast.result.queueSlot1Before = beforeQueue.ok ? beforeQueue.slot1 : 0;
    g_expectedCast.result.queueSlot0After = afterQueue.ok ? afterQueue.slot0 : 0;
    g_expectedCast.result.queueSlot1After = afterQueue.ok ? afterQueue.slot1 : 0;
}

static ExpectedCastState CopyExpectedCastState()
{
    std::lock_guard<std::mutex> lock(g_expectedCastMutex);
    return g_expectedCast;
}

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

bool ShouldLogActionQueue()
{
    int cached = g_logActionQueue.load(std::memory_order_acquire);
    if (cached != 0)
        return cached > 0;

    bool enabled = false;
    if (auto cfg = Core::Config::TryGetBool("debug.actionqueue"))
        enabled = *cfg;
    else if (auto env = Core::Config::TryGetEnvBool("debug.actionqueue"))
        enabled = *env;
    else if (auto legacyCfg = Core::Config::TryGetBool("UOW_DEBUG_ACTIONQUEUE"))
        enabled = *legacyCfg;
    else if (auto legacyEnv = Core::Config::TryGetEnvBool("UOW_DEBUG_ACTIONQUEUE"))
        enabled = *legacyEnv;

    g_logActionQueue.store(enabled ? 1 : -1, std::memory_order_release);
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

    if (self) {
        ActionSnapshot snap = ReadActionSnapshot(self);
        ExpectedCastState expected = CopyExpectedCastState();
        const bool exactMatch = snap.ok && (snap.vtbl == g_expectedVtable);
        const bool heuristicMatch = snap.ok && LooksLikeSpellAction(snap);
        const bool wrapperArmed = Engine::Lua::HasRecentCastAttempt();
        if (snap.ok && (exactMatch || (heuristicMatch && wrapperArmed))) {
            char buf[320];
            sprintf_s(buf,
                      sizeof(buf),
                      "[CastUI/native] self=%p vtbl=%p match=%s spellId=%u targetType=%u targetId=%08X iconId=%u flag18=%u",
                      self,
                      reinterpret_cast<void*>(snap.vtbl),
                      exactMatch ? "vtbl" : "heuristic",
                      snap.spellId,
                      snap.targetType,
                      snap.targetId,
                      snap.iconId,
                      static_cast<unsigned>(snap.targetReady));
            WriteRawLog(buf);
            CastCorrelator::OnCastAttempt(snap.spellId);
        }
        if (MatchesExpectedAction(expected, snap)) {
            RecordBuildMatch(expected, snap, self);
            char buf[224];
            sprintf_s(buf,
                      sizeof(buf),
                      "[CastExpect] build matched tok=%u spell=%u targetType=%u targetId=%08X flag18=%u",
                      expected.token,
                      snap.spellId,
                      snap.targetType,
                      snap.targetId,
                      static_cast<unsigned>(snap.targetReady));
            WriteRawLog(buf);
        }
    }

    g_faultStreak.store(0, std::memory_order_release);
    return g_origBuildAction(self, a1, a2);
}

void __fastcall Hook_EnqueueAction(void* self, void*, void* action)
{
    ActionSnapshot actionSnap = ReadActionSnapshot(action);
    ExpectedCastState expected = CopyExpectedCastState();
    const bool castScopedLog = actionSnap.ok && LooksLikeSpellAction(actionSnap) && Engine::Lua::HasRecentCastAttempt();
    const bool shouldLog = g_nativeActive.load(std::memory_order_acquire) && (ShouldLogActionQueue() || castScopedLog);

    const bool needQueueSnapshot = shouldLog || expected.armed;
    QueueSnapshot beforeQueue = needQueueSnapshot ? ReadQueueSnapshot(self) : QueueSnapshot{};

    if (g_origEnqueueAction)
        g_origEnqueueAction(self, action);

    QueueSnapshot afterQueue = needQueueSnapshot ? ReadQueueSnapshot(self) : QueueSnapshot{};
    if (MatchesExpectedAction(expected, actionSnap)) {
        RecordEnqueueMatch(expected, actionSnap, action, beforeQueue, afterQueue);
        char buf[288];
        sprintf_s(buf,
                  sizeof(buf),
                  "[CastExpect] enqueue matched tok=%u spell=%u targetType=%u targetId=%08X flag18=%u slots(before=%p,%p after=%p,%p)",
                  expected.token,
                  actionSnap.spellId,
                  actionSnap.targetType,
                  actionSnap.targetId,
                  static_cast<unsigned>(actionSnap.targetReady),
                  reinterpret_cast<void*>(beforeQueue.ok ? beforeQueue.slot0 : 0),
                  reinterpret_cast<void*>(beforeQueue.ok ? beforeQueue.slot1 : 0),
                  reinterpret_cast<void*>(afterQueue.ok ? afterQueue.slot0 : 0),
                  reinterpret_cast<void*>(afterQueue.ok ? afterQueue.slot1 : 0));
        WriteRawLog(buf);
    }

    if (shouldLog) {
        const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
        char retBuf[32];
        if (ret >= g_moduleBase) {
            sprintf_s(retBuf, sizeof(retBuf), "UOSA.exe+0x%X", static_cast<unsigned>(ret - g_moduleBase));
        } else {
            sprintf_s(retBuf, sizeof(retBuf), "0x%p", reinterpret_cast<void*>(ret));
        }

        char buf[352];
        sprintf_s(buf,
                  sizeof(buf),
                  "[ActionQueue] enqueue ret=%s queue=%p action=%p spellId=%u targetType=%u targetId=%08X flag18=%u slots(before=%p,%p after=%p,%p)",
                  retBuf,
                  self,
                  action,
                  actionSnap.spellId,
                  actionSnap.targetType,
                  actionSnap.targetId,
                  static_cast<unsigned>(actionSnap.targetReady),
                  reinterpret_cast<void*>(beforeQueue.ok ? beforeQueue.slot0 : 0),
                  reinterpret_cast<void*>(beforeQueue.ok ? beforeQueue.slot1 : 0),
                  reinterpret_cast<void*>(afterQueue.ok ? afterQueue.slot0 : 0),
                  reinterpret_cast<void*>(afterQueue.ok ? afterQueue.slot1 : 0));
        WriteRawLog(buf);
    }
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
        WriteRawLog("[Gate] signature mismatch at 0x0053E630, BuildAction hook skipped.");
    } else {
        if (!candidate.match.ok) {
            WriteRawLog("[Gate] BuildAction signature heuristic failed; forcing fallback candidate");
        }
        g_expectedVtable = g_moduleBase + Engine::Addresses::RVA_Vtbl_CastSpell;
        g_buildActionTarget = reinterpret_cast<void*>(candidate.address);
        if (MH_CreateHook(g_buildActionTarget,
                          reinterpret_cast<LPVOID>(Hook_BuildAction),
                          reinterpret_cast<LPVOID*>(&g_origBuildAction)) == MH_OK) {
            if (MH_EnableHook(g_buildActionTarget) != MH_OK) {
                g_origBuildAction = nullptr;
                g_buildActionTarget = nullptr;
            }
        } else {
            g_buildActionTarget = nullptr;
        }
    }
    auto enqueueAddr = g_moduleBase + Engine::Addresses::RVA_EnqueueAction;
    if (enqueueAddr >= g_moduleBase && enqueueAddr < g_moduleBase + moduleSize) {
        g_enqueueActionTarget = reinterpret_cast<void*>(enqueueAddr);
        if (MH_CreateHook(g_enqueueActionTarget,
                          reinterpret_cast<LPVOID>(Hook_EnqueueAction),
                          reinterpret_cast<LPVOID*>(&g_origEnqueueAction)) == MH_OK) {
            if (MH_EnableHook(g_enqueueActionTarget) != MH_OK) {
                g_origEnqueueAction = nullptr;
            } else {
                char buf[160];
                sprintf_s(buf, sizeof(buf), "[ActionQueue] hook armed at %p", g_enqueueActionTarget);
                WriteRawLog(buf);
            }
        }
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
    if (g_enqueueActionTarget) {
        MH_DisableHook(g_enqueueActionTarget);
        MH_RemoveHook(g_enqueueActionTarget);
        g_enqueueActionTarget = nullptr;
    }
    g_origBuildAction = nullptr;
    g_origEnqueueAction = nullptr;
}

bool IsNativeHookActive()
{
    return g_nativeActive.load(std::memory_order_acquire) &&
           g_buildActionTarget != nullptr &&
           g_enqueueActionTarget != nullptr;
}

void ArmExpectedCast(std::uint32_t token,
                     std::uint32_t spellId,
                     std::uint32_t targetType,
                     std::uint32_t targetId,
                     bool onId)
{
    std::lock_guard<std::mutex> lock(g_expectedCastMutex);
    g_expectedCast = {};
    g_expectedCast.armed = true;
    g_expectedCast.token = token;
    g_expectedCast.spellId = spellId;
    g_expectedCast.targetType = targetType;
    g_expectedCast.targetId = targetId;
    g_expectedCast.onId = onId;
    g_expectedCast.result.hooksActive = IsNativeHookActive();
}

ExpectedCastResult ConsumeExpectedCast(std::uint32_t token)
{
    std::lock_guard<std::mutex> lock(g_expectedCastMutex);
    ExpectedCastResult result{};
    result.hooksActive = IsNativeHookActive();
    if (g_expectedCast.armed && g_expectedCast.token == token)
        result = g_expectedCast.result;
    g_expectedCast = {};
    if (!result.hooksActive)
        result.hooksActive = IsNativeHookActive();
    return result;
}

} // namespace Engine::CastFallback
