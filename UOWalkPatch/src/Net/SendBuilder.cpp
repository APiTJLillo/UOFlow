#include <winsock2.h>
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <cstdio>
#include <cstring>
#include <limits>
#include <cstdint>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>
#include <atomic>
#include <array>
#include <string>
#include <optional>
#include <cstdlib>
#include <ws2tcpip.h>
#include <minhook.h>
#include <intrin.h>
#include "Core/Config.hpp"
#include "Core/Logging.hpp"
#include "Core/Startup.hpp"
#include "Core/PatternScan.hpp"
#include "Core/Utils.hpp"
#include "Core/SafeMem.h"
#include "Core/RejectCache.hpp"
#include "Core/TrustedEndpointCache.hpp"
#include "Core/SendRing.hpp"
#include "Win32/SafeProbe.h"
#include "Net/PacketTrace.hpp"
#include "Net/SendBuilder.hpp"
#include "Net/ScannerStage3.hpp"
#include "Net/SendSampleStore.hpp"
#include "Util/OwnerPump.hpp"
#include "Util/RegionWatch.hpp"
#include "Engine/GlobalState.hpp"
#include "Engine/LuaBridge.hpp"

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Define the global variable that was previously only declared as extern
extern "C" IMAGE_DOS_HEADER __ImageBase;
volatile LONG g_needWalkReg = 0;

namespace Net {

using SendPacket_t = void(__thiscall*)(void* netMgr, const void* pkt, int len);
using SendBuilder_t = void* (__thiscall*)(void* thisPtr, void* builder);

constexpr DWORD kEngineUnstableLogCooldownMs = 2000;
constexpr DWORD kManagerScanCooldownMs = 2500;
constexpr size_t kEndpointScanWindow = 0x800;
constexpr int kTailFollowMaxDepth = 4;
constexpr size_t kTailScanWindow = 0x100;
constexpr uintptr_t kCanonicalManagerVtbl = 0ull; // runtime-resolved via GlobalState when available
constexpr std::uint32_t kRingSnapshotAgeMs = 3000;
constexpr std::uint32_t kRingHitThreshold = 3;
constexpr std::uint32_t kRingMatchLeewayBytes = 32;
constexpr std::uint32_t kTrustedEndpointTtlMs = 15u * 60u * 1000u;
constexpr std::uint32_t kRejectCacheTtlMs = 5u * 60u * 1000u;
constexpr std::uint32_t SB_BACKOFF_MS_INITIAL = 250;
constexpr std::uint32_t SB_BACKOFF_MS_MAX = 4000;
constexpr double SB_BACKOFF_FACTOR = 2.0;
constexpr std::uint32_t SB_PASS_MAX_CANDIDATES = 64;
constexpr std::uint32_t SB_PASS_BASE_POLL_MS = 100;

static GlobalStateInfo* g_state = nullptr;
static SendPacket_t g_sendPacket = nullptr;
static void* g_sendPacketTarget = nullptr;
static bool g_sendPacketHooked = false;
static void* g_netMgr = nullptr;
static void* g_sendCtx = nullptr;
static SendBuilder_t fpSendBuilder = nullptr;
static bool g_sendBuilderHooked = false;
static void* g_sendBuilderTarget = nullptr;
static bool g_builderScanned = false;
static bool g_loggedNetScanFailure = false;
static bool g_initLogged = false;
static std::atomic<uint32_t> g_builderProbeAttempted{0};
static std::atomic<uint32_t> g_builderProbeSuccess{0};
static std::atomic<uint32_t> g_builderProbeSkipped{0};
static DWORD g_lastPollTick = 0;
static uintptr_t g_lastNetCfgSnapshot[4] = {};
static bool g_haveNetCfgSnapshot = false;
static void* g_lastLoggedManager = nullptr;
static void* g_lastLoggedEndpoint = nullptr;
static void* g_lastNetCfgPtr = nullptr;
static DWORD g_lastNetCfgState = 0xFFFFFFFF;
static DWORD g_lastNetCfgProtect = 0xFFFFFFFF;
static DWORD g_lastNetCfgType = 0xFFFFFFFF;
static void* g_lastNetCfgBase = nullptr;
static SIZE_T g_lastNetCfgRegionSize = 0;
static void* g_lastEngineCtxScanPtr = nullptr;
static DWORD g_lastEngineCtxScanTick = 0;
static bool g_loggedEngineUnstable = false;
static DWORD g_lastEngineUnstableLogTick = 0;
static DWORD g_lastBuilderScanTick = 0;
static DWORD g_helperWaitStartTick = 0;
static bool g_helperBypassWarningLogged = false;
static std::unordered_set<uint64_t> g_vtblSlotCache;
static std::unordered_set<void*> g_skipWarnedVtables;
static DWORD g_nextNetCfgProbeTick = 0;
static Scanner::SendSampleRing g_sendSampleRing{};
static Scanner::SampleDeduper g_sendSampleDeduper{};
static std::atomic<bool> g_sendSamplingEnabled{true};
static Scanner::TokenBucket g_sendSampleBucket(100, 200);
static constexpr std::uint32_t kSamplerWarmupSamples = 128;
static std::atomic<std::uint32_t> g_samplerWarmupRemaining{kSamplerWarmupSamples};
static std::atomic<bool> g_sbDebug{false};
static std::atomic<bool> g_sbDebugNudge{false};
static std::atomic<bool> g_debugNudgePending{false};
static std::atomic<bool> g_debugNudgeSent{false};
static std::atomic<DWORD> g_lastSampleDropLogTick{0};
static Scanner::EndpointTrustCache g_endpointTrust{};
static Scanner::RejectStore g_rejectStore{};
static Scanner::Tuner g_tuner{};
static Scanner::ScanPassTelemetry g_lastTelemetry{};
static std::mutex g_lastTelemetryMutex;
static std::atomic<std::uint64_t> g_passSeq{0};
static std::atomic<std::uint32_t> g_lastRingLoad{0};
static std::atomic<bool> g_requireSendSample{true};
static std::atomic<bool> g_sendRingDebug{false};
static std::atomic<DWORD> g_lastSendRingDebugTick{0};
static std::atomic<std::uint32_t> g_guardWarnBudget{0};

static bool IsExecutableCodeAddress(void* addr);
static std::atomic<std::uint64_t> g_guardWarnPass{0};
static std::atomic<std::uint64_t> g_asciiWarnLastPass{0};
static std::uint64_t g_initTickMs64 = 0;
static std::uint64_t g_firstScanTickMs64 = 0;
static std::unordered_map<void*, std::uint64_t> g_endpointCallsiteHints;
static std::mutex g_endpointCallsiteMutex;
static thread_local bool t_debugNudgeCall = false;
static thread_local std::uint32_t t_ringHitsForAttach = 0;
static Scanner::ModuleMap g_moduleMap;
static Net::SendSampleStore g_sendSampleStore;
static Core::SendRing& g_sendRing = Core::GetSendRing();

enum class Stage3State : std::uint8_t { Idle = 0, Running, Backoff };

enum class Stage3Pivot : std::uint8_t { None = 0, Engine, Database };

struct Stage3PassSummary {
    Stage3Pivot pivot = Stage3Pivot::None;
    bool executed = false;
    bool trustHit = false;
    bool accepted = false;
    bool deferred = false;
    std::uint32_t deferDelayMs = 0;
    std::uint64_t passId = 0;
    std::uint32_t ttfsMs = 0;
    std::uint32_t nextBackoffMs = 0;
    Scanner::ScanPassTelemetry telemetry{};
};

struct Stage3PivotResult {
    bool ready = false;
    bool deferred = false;
    std::uint32_t deferDelayMs = 0;
    bool trustHit = false;
    bool accepted = false;
    bool scanned = false;
    Scanner::ScanPassTelemetry telemetry{};
};

class Stage3Controller {
public:
    Stage3Controller()
    {
        reset();
    }

    void reset()
    {
        m_state = Stage3State::Running;
        m_pendingBackoffMs = SB_BACKOFF_MS_INITIAL;
        m_activeDelayMs = SB_PASS_BASE_POLL_MS;
        m_backoffStartTick = 0;
        m_passActive = false;
    }

    std::optional<std::uint64_t> beginPass(DWORD nowMs)
    {
        if (m_state == Stage3State::Idle)
            return std::nullopt;
        if (m_state == Stage3State::Backoff) {
            if (m_backoffStartTick != 0) {
                const DWORD elapsed = nowMs - m_backoffStartTick;
                if (elapsed < m_activeDelayMs)
                    return std::nullopt;
            }
            m_state = Stage3State::Running;
        }
        if (m_passActive)
            return std::nullopt;
        m_passActive = true;
        m_lastPassStartTick = nowMs;
        const std::uint64_t id = g_passSeq.fetch_add(1, std::memory_order_relaxed) + 1;
        return id;
    }

    std::uint32_t completePass(const Stage3PassSummary& summary, DWORD nowMs)
    {
        m_passActive = false;
        if (summary.accepted || summary.trustHit) {
            m_state = Stage3State::Idle;
            m_pendingBackoffMs = SB_BACKOFF_MS_INITIAL;
            m_activeDelayMs = SB_PASS_BASE_POLL_MS;
            m_backoffStartTick = nowMs;
            return 0;
        }

        m_state = Stage3State::Backoff;
        std::uint32_t applied = m_pendingBackoffMs;
        if (applied < SB_BACKOFF_MS_INITIAL)
            applied = SB_BACKOFF_MS_INITIAL;
        if (applied > SB_BACKOFF_MS_MAX)
            applied = SB_BACKOFF_MS_MAX;
        m_activeDelayMs = applied;
        m_backoffStartTick = nowMs;
        const double next = static_cast<double>(applied) * SB_BACKOFF_FACTOR;
        m_pendingBackoffMs = static_cast<std::uint32_t>(std::min<double>(next, SB_BACKOFF_MS_MAX));
        return applied;
    }

    void defer(DWORD nowMs, std::uint32_t delayMs, bool resetBackoff)
    {
        m_passActive = false;
        m_state = Stage3State::Backoff;
        m_activeDelayMs = delayMs;
        m_backoffStartTick = nowMs;
        if (resetBackoff)
            m_pendingBackoffMs = SB_BACKOFF_MS_INITIAL;
    }

    std::uint32_t currentDelayMs() const
    {
        if (m_state == Stage3State::Backoff)
            return m_activeDelayMs;
        return SB_PASS_BASE_POLL_MS;
    }

    Stage3State state() const { return m_state; }

private:
    Stage3State m_state = Stage3State::Running;
    bool m_passActive = false;
    DWORD m_backoffStartTick = 0;
    DWORD m_lastPassStartTick = 0;
    std::uint32_t m_activeDelayMs = SB_PASS_BASE_POLL_MS;
    std::uint32_t m_pendingBackoffMs = SB_BACKOFF_MS_INITIAL;
};

static Stage3Controller g_stage3Controller{};

struct RingHitStats {
    std::uint32_t hits = 0;
    std::uint32_t selfHits = 0;
    std::uint32_t offModuleHits = 0;
    std::uint32_t considered = 0;
};

struct TraceResult;

enum : std::uint8_t {
    kRejectReasonGeneric = 0,
    kRejectReasonNotExec = 1,
    kRejectReasonNonGame = 2,
    kRejectReasonNoChain = 3,
    kRejectReasonSelf = 4,
    kRejectReasonOffText = 5,
};

static const char* RejectReasonLabel(std::uint8_t reason) noexcept
{
    switch (reason) {
    case kRejectReasonNotExec:
        return "nonexec";
    case kRejectReasonNoChain:
        return "nochain";
    case kRejectReasonSelf:
        return "self";
    case kRejectReasonNonGame:
        return "offtext";
    case kRejectReasonOffText:
        return "offtext";
    default:
        return "generic";
    }
}

static void LogRejectTtl(uintptr_t vtbl, int slotIndex, std::uint8_t reason)
{
    if (vtbl == 0 || slotIndex < 0)
        return;
    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[SB][REJ] ttl vtbl=%p slot=%u reason=%s",
              reinterpret_cast<void*>(vtbl),
              static_cast<unsigned>(slotIndex),
              RejectReasonLabel(reason));
}

enum class ManagerKind : std::uint8_t {
    Engine,
    Database,
    ScriptCtx,
    Neighbor
};

struct ManagerTarget {
    ManagerKind kind = ManagerKind::Engine;
    uintptr_t vtbl = 0;
    uintptr_t owner = 0;
    std::uint32_t neighborIndex = std::numeric_limits<std::uint32_t>::max();
};

struct VtblSuppressEntry {
    uintptr_t vtbl = 0;
    std::uint64_t expiryMs = 0;
};

static ManagerTarget g_managerTarget{};
static bool g_managerTargetValid = false;
static bool g_allowDbProbe = false;
static size_t g_lastPassCandidateCount = 0;
static uint32_t g_lastPassSampleHits = 0;
static std::array<VtblSuppressEntry, 8> g_vtblSuppress{};
static size_t g_vtblSuppressIndex = 0;

struct EndpointBackoffState {
    DWORD nextTick = 0;
    DWORD delayMs = 0;
    uint32_t failures = 0;
};

static std::unordered_map<void*, EndpointBackoffState> g_endpointBackoff;
static std::mutex g_endpointBackoffMutex;

struct GuardLogState {
    std::uint64_t lastWarnPass = 0;
};

static std::unordered_map<void*, GuardLogState> g_managerGuardLog;
static std::mutex g_managerGuardLogMutex;

struct SectionRange {
    uintptr_t begin = 0;
    uintptr_t end = 0;
    bool Contains(uintptr_t addr) const {
        if (begin == 0 && end == 0)
            return false;
        if (end < begin)
            return addr >= begin;
        return addr >= begin && addr < end;
    }
};

static std::once_flag g_sectionRangeOnce;
static SectionRange g_dataSection{};
static SectionRange g_rdataSection{};
static uintptr_t g_managerRegionBase = 0;
static SIZE_T g_managerRegionSize = 0;

static bool ParseBoolFlag(const char* text, bool defaultValue) noexcept
{
    if (!text || !*text)
        return defaultValue;
    switch (text[0]) {
    case '0':
    case 'n':
    case 'N':
    case 'f':
    case 'F':
        return false;
    default:
        return true;
    }
}

static bool ResolveSendBuilderFlag(const char* envName, const char* cfgKey, bool fallback)
{
    bool value = fallback;
    if (auto cfg = Core::Config::TryGetBool(cfgKey))
        value = *cfg;
    if (const char* env = std::getenv(envName))
        value = ParseBoolFlag(env, value);
    return value;
}

static bool SafeCopy(void* dst, const void* src, size_t bytes);

static const char* ManagerKindName(ManagerKind kind) noexcept
{
    switch (kind) {
    case ManagerKind::Engine:
        return "engine";
    case ManagerKind::Database:
        return "db";
    case ManagerKind::ScriptCtx:
        return "script";
    case ManagerKind::Neighbor:
        return "neighbor";
    default:
        return "?";
    }
}

static std::uint32_t HashPointer(const void* ptr) noexcept
{
    if (!ptr)
        return 0;
    std::uintptr_t value = reinterpret_cast<std::uintptr_t>(ptr);
    std::uint32_t hash = 2166136261u;
    constexpr std::uint32_t kPrime = 16777619u;
    for (std::size_t i = 0; i < sizeof(value); ++i) {
        const std::uint8_t byte = static_cast<std::uint8_t>(value & 0xFFu);
        hash ^= byte;
        hash *= kPrime;
        value >>= 8;
    }
    return hash;
}

static bool IsInPrimaryText(const void* address)
{
    if (!address)
        return false;
    const auto* primary = g_moduleMap.primaryExecutable();
    if (!primary)
        return false;
    const std::uintptr_t addr = reinterpret_cast<std::uintptr_t>(address);
    if (primary->containsText(addr))
        return true;
    return false;
}

static bool IsInSelfModule(const void* address)
{
    if (!address)
        return false;
    const auto* module = g_moduleMap.findByAddress(address);
    if (!module)
        return false;
    return module->module == reinterpret_cast<HMODULE>(&__ImageBase);
}

static void FormatModuleOffset(const void* address, char* buffer, size_t bufferLen)
{
    if (!buffer || bufferLen == 0)
        return;
    if (!address) {
        std::snprintf(buffer, bufferLen, "null");
        return;
    }
    const auto* module = g_moduleMap.findByAddress(address);
    if (!module) {
        std::snprintf(buffer, bufferLen, "%p", address);
        return;
    }
    char moduleName[MAX_PATH] = {};
    if (GetModuleBaseNameA(GetCurrentProcess(),
                           module->module,
                           moduleName,
                           static_cast<DWORD>(sizeof(moduleName))) == 0) {
        std::snprintf(moduleName, sizeof(moduleName), "%p", module->module);
    }
    const std::uintptr_t offset = reinterpret_cast<std::uintptr_t>(address) - module->base;
    std::snprintf(buffer, bufferLen, "%s!0x%X", moduleName, static_cast<unsigned>(offset));
}

static RingHitStats EvaluateRingHits(const std::vector<Core::SendRing::Entry>& samples,
                                     void* candidateEntry,
                                     const TraceResult& trace);

static bool IsInModuleRdata(uintptr_t addr);

static bool IsReadableMemory(const void* address, SIZE_T minimum, MEMORY_BASIC_INFORMATION* outMbi = nullptr)
{
    if (!address)
        return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0)
        return false;
    if (outMbi)
        *outMbi = mbi;
    if (mbi.State != MEM_COMMIT)
        return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
        return false;
    constexpr DWORD kReadableMask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if ((mbi.Protect & kReadableMask) == 0)
        return false;
    SIZE_T span = mbi.RegionSize;
    const auto begin = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    const auto offset = reinterpret_cast<uintptr_t>(address) - begin;
    if (offset >= span)
        return false;
    span -= offset;
    return span >= minimum;
}

static void ResetVtblSuppressions() noexcept
{
    for (auto& entry : g_vtblSuppress) {
        entry.vtbl = 0;
        entry.expiryMs = 0;
    }
}

static bool IsVtblSuppressed(uintptr_t vtbl, std::uint64_t nowMs) noexcept
{
    if (vtbl == 0)
        return false;
    for (const auto& entry : g_vtblSuppress) {
        if (entry.vtbl == vtbl && entry.expiryMs != 0 && nowMs < entry.expiryMs)
            return true;
    }
    return false;
}

static void SuppressVtbl(uintptr_t vtbl, std::uint64_t nowMs) noexcept
{
    if (vtbl == 0)
        return;
    constexpr std::uint64_t kTtlMs = 5ull * 60ull * 1000ull;
    for (auto& entry : g_vtblSuppress) {
        if (entry.vtbl == vtbl) {
            entry.expiryMs = nowMs + kTtlMs;
            return;
        }
        if (entry.expiryMs == 0 || nowMs >= entry.expiryMs) {
            entry.vtbl = vtbl;
            entry.expiryMs = nowMs + kTtlMs;
            return;
        }
    }
    g_vtblSuppress[g_vtblSuppressIndex] = {vtbl, nowMs + kTtlMs};
    g_vtblSuppressIndex = (g_vtblSuppressIndex + 1) % g_vtblSuppress.size();
}

static void ClearVtblSuppression(uintptr_t vtbl) noexcept
{
    if (vtbl == 0)
        return;
    for (auto& entry : g_vtblSuppress) {
        if (entry.vtbl == vtbl) {
            entry.vtbl = 0;
            entry.expiryMs = 0;
        }
    }
}

static std::string BuildPreconditionsString(bool netReadable)
{
    std::string result = netReadable ? "netReadable" : "netPending";
    const char* helperStage = Engine::Lua::GetHelperStageSummary();
    if (helperStage && helperStage[0] != '\0') {
        std::string stage(helperStage);
        result += ";helpers=" + stage;
        if (_stricmp(helperStage, "installed") == 0)
            ResetVtblSuppressions();
    } else {
        result += ";helpers=unknown";
    }
    return result;
}

static bool BuildManagerTarget(ManagerKind kind, const GlobalStateInfo* state, ManagerTarget& out)
{
    if (!state)
        return false;

    void* owner = nullptr;
    uintptr_t vtblAddr = 0;

    switch (kind) {
    case ManagerKind::Engine:
        owner = state->engineContext;
        if (owner) {
            if (state->engineVtable)
                vtblAddr = reinterpret_cast<uintptr_t>(state->engineVtable);
            if (vtblAddr == 0) {
                void* vtblPtr = nullptr;
                if (SafeCopy(&vtblPtr, owner, sizeof(vtblPtr)) && vtblPtr)
                    vtblAddr = reinterpret_cast<uintptr_t>(vtblPtr);
            }
        }
        break;
    case ManagerKind::Database:
        owner = state->databaseManager;
        if (owner) {
            void* vtblPtr = nullptr;
            if (SafeCopy(&vtblPtr, owner, sizeof(vtblPtr)) && vtblPtr)
                vtblAddr = reinterpret_cast<uintptr_t>(vtblPtr);
        }
        break;
    case ManagerKind::ScriptCtx:
        owner = state->scriptContext;
        if (owner) {
            void* vtblPtr = nullptr;
            if (SafeCopy(&vtblPtr, owner, sizeof(vtblPtr)) && vtblPtr)
                vtblAddr = reinterpret_cast<uintptr_t>(vtblPtr);
        }
        break;
    default:
        break;
    }

    if (!owner || vtblAddr == 0)
        return false;
    if (!IsInModuleRdata(vtblAddr))
        return false;

    out.kind = kind;
    out.owner = reinterpret_cast<uintptr_t>(owner);
    out.vtbl = vtblAddr;
    return true;
}

static bool ValidateNeighborVtbl(void* vtblPtr)
{
    if (!vtblPtr)
        return false;

    const int kCheckSlots = 4;
    for (int i = 0; i < kCheckSlots; ++i) {
        void* entry = nullptr;
        if (!SafeCopy(&entry, reinterpret_cast<void* const*>(vtblPtr) + i, sizeof(entry)) || !entry)
            return false;
        if (!IsExecutableCodeAddress(entry))
            return false;
        if (!IsInPrimaryText(entry))
            return false;
    }
    return true;
}

static void BuildNeighborTargets(const ManagerTarget& engineTarget,
                                 std::vector<ManagerTarget>& out)
{
    if (engineTarget.vtbl == 0 || engineTarget.owner == 0)
        return;

    void* const* engineVtbl = reinterpret_cast<void* const*>(engineTarget.vtbl);
    std::unordered_set<std::uintptr_t> seen;

    for (int i = 0; i < 32; ++i) {
        void* candidate = nullptr;
        if (!SafeCopy(&candidate, engineVtbl + i, sizeof(candidate)) || !candidate)
            continue;
        if (candidate == reinterpret_cast<void*>(engineTarget.owner))
            continue;

        void* neighborVtbl = nullptr;
        if (!SafeCopy(&neighborVtbl, candidate, sizeof(neighborVtbl)) || !neighborVtbl)
            continue;

        const std::uintptr_t neighborVtblAddr = reinterpret_cast<std::uintptr_t>(neighborVtbl);
        if (!IsInModuleRdata(neighborVtblAddr))
            continue;
        if (!seen.insert(neighborVtblAddr).second)
            continue;
        if (!ValidateNeighborVtbl(neighborVtbl))
            continue;

        ManagerTarget neighbor{};
        neighbor.kind = ManagerKind::Neighbor;
        neighbor.vtbl = neighborVtblAddr;
        neighbor.owner = reinterpret_cast<std::uintptr_t>(candidate);
        neighbor.neighborIndex = static_cast<std::uint32_t>(i);
        out.push_back(neighbor);
    }
}

static void LogPivotAttempt(const ManagerTarget& target)
{
    if (target.kind == ManagerKind::Neighbor) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[SB][PIVOT] trying manager=neighbor@%u vtbl=%p",
                  target.neighborIndex,
                  reinterpret_cast<void*>(target.vtbl));
        return;
    }

    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[SB][PIVOT] trying manager=%s vtbl=%p",
              ManagerKindName(target.kind),
              reinterpret_cast<void*>(target.vtbl));
}

static bool EnsureManagerSelection(const GlobalStateInfo* state)
{
    // NOTE: Engine manager vtbl must be preferred. DB/ScriptCtx are fallbacks used only when
    // sb.allow_db_probe=1 and engine yields zero candidates. This reduces false positives.
    ManagerTarget candidate{};
    if (!BuildManagerTarget(ManagerKind::Engine, state, candidate)) {
        if (!BuildManagerTarget(ManagerKind::Database, state, candidate) &&
            !BuildManagerTarget(ManagerKind::ScriptCtx, state, candidate))
            return false;
    }

    if (!g_managerTargetValid ||
        g_managerTarget.owner != candidate.owner ||
        g_managerTarget.vtbl != candidate.vtbl ||
        g_managerTarget.kind != candidate.kind) {
        g_managerTarget = candidate;
        g_managerTargetValid = true;
        g_netMgr = reinterpret_cast<void*>(candidate.owner);
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[CORE][SB] manager_select kind=%s vtbl=%p owner=%p from GlobalState",
                  ManagerKindName(candidate.kind),
                  reinterpret_cast<void*>(candidate.vtbl),
                  reinterpret_cast<void*>(candidate.owner));
    }

    return true;
}




using VirtualProtect_t = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
static VirtualProtect_t g_origVirtualProtect = nullptr;
static LPVOID g_virtualProtectTarget = nullptr;
static bool g_virtualProtectHooked = false;

using VirtualProtectEx_t = BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
static VirtualProtectEx_t g_origVirtualProtectEx = nullptr;
static LPVOID g_virtualProtectExTarget = nullptr;
static bool g_virtualProtectExHooked = false;

using VirtualAlloc_t = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
static VirtualAlloc_t g_origVirtualAlloc = nullptr;
static LPVOID g_virtualAllocTarget = nullptr;
static bool g_virtualAllocHooked = false;

using VirtualAllocEx_t = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
static VirtualAllocEx_t g_origVirtualAllocEx = nullptr;
static LPVOID g_virtualAllocExTarget = nullptr;
static bool g_virtualAllocExHooked = false;

using MapViewOfFile_t = LPVOID(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
static MapViewOfFile_t g_origMapViewOfFile = nullptr;
static LPVOID g_mapViewOfFileTarget = nullptr;
static bool g_mapViewOfFileHooked = false;

using MapViewOfFileEx_t = LPVOID(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T, LPVOID);
static MapViewOfFileEx_t g_origMapViewOfFileEx = nullptr;
static LPVOID g_mapViewOfFileExTarget = nullptr;
static bool g_mapViewOfFileExHooked = false;

using NtProtectVirtualMemory_t = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
static NtProtectVirtualMemory_t g_origNtProtectVirtualMemory = nullptr;
static LPVOID g_ntProtectVirtualMemoryTarget = nullptr;
static bool g_ntProtectVirtualMemoryHooked = false;

using NtAllocateVirtualMemory_t = NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
static NtAllocateVirtualMemory_t g_origNtAllocateVirtualMemory = nullptr;
static LPVOID g_ntAllocateVirtualMemoryTarget = nullptr;
static bool g_ntAllocateVirtualMemoryHooked = false;

using NtMapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
static NtMapViewOfSection_t g_origNtMapViewOfSection = nullptr;
static LPVOID g_ntMapViewOfSectionTarget = nullptr;
static bool g_ntMapViewOfSectionHooked = false;

using NtUnmapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, PVOID);
static NtUnmapViewOfSection_t g_origNtUnmapViewOfSection = nullptr;
static LPVOID g_ntUnmapViewOfSectionTarget = nullptr;
static bool g_ntUnmapViewOfSectionHooked = false;

static void* g_lastManagerScanPtr = nullptr;
static DWORD g_lastManagerScanTick = 0;

static void* GetTrackedConfigPtr()
{
    if (g_state && g_state->networkConfig)
        return g_state->networkConfig;
    return g_lastNetCfgPtr;
}

static bool TickHasElapsed(DWORD now, DWORD target)
{
    return static_cast<int32_t>(now - target) >= 0;
}

static bool LooksLikeAsciiDword(uintptr_t value)
{
    std::uint32_t lower = static_cast<std::uint32_t>(value & 0xFFFFFFFFu);
    unsigned printable = 0;
    for (int i = 0; i < 4; ++i) {
        std::uint8_t ch = static_cast<std::uint8_t>(lower & 0xFFu);
        lower >>= 8;
        if (ch == 0)
            continue;
        if (ch < 0x20 || ch > 0x7Eu)
            return false;
        ++printable;
    }
    return printable >= 3;
}

static const Scanner::ModuleInfo* EnsurePrimaryModule()
{
    const Scanner::ModuleInfo* primary = g_moduleMap.primaryExecutable();
    if (!primary) {
        g_moduleMap.refresh(true);
        primary = g_moduleMap.primaryExecutable();
    }
    return primary;
}

static bool IsPrimaryModuleRdata(uintptr_t addr)
{
    const Scanner::ModuleInfo* primary = EnsurePrimaryModule();
    return primary && primary->containsRdata(addr);
}

static void* ResolveStateEngineVtablePtr()
{
    if (!g_state)
        return nullptr;

    void* vtbl = nullptr;
    if (g_state->engineVtable)
        vtbl = g_state->engineVtable;
    if ((!vtbl) && g_state->engineContext)
        SafeCopy(&vtbl, g_state->engineContext, sizeof(vtbl));
    return vtbl;
}

static void EnsureSectionRanges()
{
    std::call_once(g_sectionRangeOnce, []() {
        HMODULE module = GetModuleHandleW(nullptr);
        if (!module)
            return;
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
            return;
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(reinterpret_cast<const uint8_t*>(module) + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
            return;
        auto section = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
            char name[9] = {};
            memcpy(name, section->Name, sizeof(section->Name));
            name[8] = '\0';
            uintptr_t base = reinterpret_cast<uintptr_t>(module) + section->VirtualAddress;
            DWORD virtSize = section->Misc.VirtualSize;
            DWORD rawSize = section->SizeOfRawData;
            DWORD size = virtSize > rawSize ? virtSize : rawSize;
            if (size == 0)
                continue;
            uintptr_t end = base + size;
            SectionRange range{base, end};
            if (strncmp(name, ".data", 8) == 0)
                g_dataSection = range;
            else if (strncmp(name, ".rdata", 8) == 0)
                g_rdataSection = range;
        }
        if (const Scanner::ModuleInfo* primary = EnsurePrimaryModule()) {
            if (primary->rdataBegin != 0 && primary->rdataEnd > primary->rdataBegin) {
                g_rdataSection.begin = primary->rdataBegin;
                g_rdataSection.end = primary->rdataEnd;
            }
        }
    });
}

static uintptr_t ResolveCanonicalManagerVtbl()
{
    void* stateVtbl = ResolveStateEngineVtablePtr();
    if (stateVtbl) {
        uintptr_t candidate = reinterpret_cast<uintptr_t>(stateVtbl);
        if (IsPrimaryModuleRdata(candidate))
            return candidate;
    }

    uintptr_t fallback = static_cast<uintptr_t>(kCanonicalManagerVtbl);
    if (fallback != 0 && IsPrimaryModuleRdata(fallback))
        return fallback;
    return 0;
}

static void EnsureCanonicalVtblWhitelisted()
{
    uintptr_t canonical = ResolveCanonicalManagerVtbl();
    if (canonical == 0)
        return;
    EnsureSectionRanges();
    if (!IsPrimaryModuleRdata(canonical))
        return;
    if (!g_rdataSection.Contains(canonical)) {
        if (const Scanner::ModuleInfo* primary = EnsurePrimaryModule()) {
            g_rdataSection.begin = primary->rdataBegin;
            g_rdataSection.end = primary->rdataEnd;
        }
    }
}

static bool IsInModuleRdata(uintptr_t addr)
{
    return IsPrimaryModuleRdata(addr);
}

static bool IsInManagerRegion(uintptr_t addr)
{
    if (g_managerRegionBase == 0 || g_managerRegionSize == 0)
        return false;
    uintptr_t end = g_managerRegionBase + g_managerRegionSize;
    if (end < g_managerRegionBase)
        return addr >= g_managerRegionBase;
    return addr >= g_managerRegionBase && addr < end;
}

static void RememberManagerRegion(const MEMORY_BASIC_INFORMATION& mbi)
{
    g_managerRegionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    g_managerRegionSize = mbi.RegionSize;
}

static bool IsInImageSection(const SectionRange& range, uintptr_t addr)
{
    return range.Contains(addr);
}

static void LogGuardInvalidManager(void* manager)
{
    const std::uint64_t warnPass = g_guardWarnPass.load(std::memory_order_relaxed);
    bool warnThisPass = true;
    if (warnPass != 0) {
        std::lock_guard<std::mutex> lock(g_managerGuardLogMutex);
        GuardLogState& state = g_managerGuardLog[manager];
        if (state.lastWarnPass == warnPass) {
            warnThisPass = false;
        } else {
            state.lastWarnPass = warnPass;
        }
    }

    Log::Level level = warnThisPass ? Log::Level::Warn : Log::Level::Debug;
    if (warnThisPass) {
        uint32_t budget = g_guardWarnBudget.load(std::memory_order_relaxed);
        if (budget > 0) {
            g_guardWarnBudget.fetch_sub(1, std::memory_order_relaxed);
        } else {
            level = Log::Level::Debug;
        }
    }

    Log::Logf(level,
              Log::Category::Core,
              "[SB][GUARD] skipped invalid manager=%p",
              manager);
}

static bool ShouldDeferEndpointScan(void* endpoint, DWORD now, DWORD& waitMs)
{
    std::lock_guard<std::mutex> lock(g_endpointBackoffMutex);
    auto it = g_endpointBackoff.find(endpoint);
    if (it == g_endpointBackoff.end())
        return false;
    EndpointBackoffState& entry = it->second;
    if (entry.nextTick == 0)
        return false;
    if (!TickHasElapsed(now, entry.nextTick)) {
        int32_t delta = static_cast<int32_t>(entry.nextTick - now);
        waitMs = delta > 0 ? static_cast<DWORD>(delta) : 0;
        return true;
    }
    entry.nextTick = 0;
    entry.delayMs = 0;
    return false;
}

static void ClearEndpointBackoff(void* endpoint)
{
    std::lock_guard<std::mutex> lock(g_endpointBackoffMutex);
    g_endpointBackoff.erase(endpoint);
}

static void RegisterEndpointBackoff(void* endpoint, DWORD now)
{
    constexpr DWORD kBackoffTable[] = {500, 1000, 2000};
    constexpr size_t kBackoffCount = sizeof(kBackoffTable) / sizeof(kBackoffTable[0]);

    DWORD delay = kBackoffTable[0];
    uint32_t attempt = 1;
    {
        std::lock_guard<std::mutex> lock(g_endpointBackoffMutex);
        EndpointBackoffState& entry = g_endpointBackoff[endpoint];
        entry.failures = std::min(entry.failures + 1, static_cast<uint32_t>(kBackoffCount));
        attempt = entry.failures;
        delay = kBackoffTable[entry.failures - 1];
        entry.delayMs = delay;
        entry.nextTick = now + delay;
    }

    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[CORE][SB] no path to SendPacket; backoff=%u ms endpoint=%p attempt=%u",
              delay,
              endpoint,
              attempt);
}

static bool HasEndpointBackoff()
{
    std::lock_guard<std::mutex> lock(g_endpointBackoffMutex);
    return !g_endpointBackoff.empty();
}

static bool ValidateManagerPointer(void* manager, void** outVtbl)
{
    if (!manager)
        return false;

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(manager, &mbi, sizeof(mbi)) == 0)
        return false;

    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
        return false;

    const DWORD readableMask = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE;
    if ((mbi.Protect & readableMask) == 0)
        return false;

    if (!SafeMem::IsReadable(manager, sizeof(void*) * 2))
        return false;

    EnsureSectionRanges();
    uintptr_t managerAddr = reinterpret_cast<uintptr_t>(manager);
    if (mbi.Type == MEM_IMAGE) {
        if (!IsInImageSection(g_dataSection, managerAddr) && !IsInImageSection(g_rdataSection, managerAddr))
            return false;
    } else if (mbi.Type == MEM_PRIVATE) {
        if (!IsInManagerRegion(managerAddr))
            RememberManagerRegion(mbi);
    } else {
        if (!IsInImageSection(g_dataSection, managerAddr) && !IsInImageSection(g_rdataSection, managerAddr))
            return false;
    }

    if (!outVtbl)
        return true;

    void* vtbl = nullptr;
    if (!SafeCopy(&vtbl, manager, sizeof(vtbl)) || !vtbl)
        return false;

    EnsureCanonicalVtblWhitelisted();
    uintptr_t vtblAddr = reinterpret_cast<uintptr_t>(vtbl);
    if (!IsInModuleRdata(vtblAddr))
        return false;

    if (outVtbl)
        *outVtbl = vtbl;
    return true;
}

static bool IsTrackedConfigInRange(uintptr_t base, SIZE_T size)
{
    if (size == 0)
        return false;
    void* tracked = GetTrackedConfigPtr();
    if (!tracked)
        return false;
    uintptr_t cfg = reinterpret_cast<uintptr_t>(tracked);
    uintptr_t start = base;
    uintptr_t end = base + size;
    if (end < start)
        end = std::numeric_limits<uintptr_t>::max();
    return cfg >= start && cfg < end;
}

static void UpdateTrackedRegionCache(const MEMORY_BASIC_INFORMATION& mbi)
{
    void* tracked = GetTrackedConfigPtr();
    if (!tracked)
        return;
    if (reinterpret_cast<uintptr_t>(tracked) < reinterpret_cast<uintptr_t>(mbi.BaseAddress) ||
        reinterpret_cast<uintptr_t>(tracked) >= reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize)
        return;
    g_lastNetCfgState = mbi.State;
    g_lastNetCfgProtect = mbi.Protect;
    g_lastNetCfgType = mbi.Type;
    g_lastNetCfgBase = mbi.BaseAddress;
    g_lastNetCfgRegionSize = mbi.RegionSize;
}

static bool IsEngineStableForScanning()
{
    Engine::Lua::StartupStatus status{};
    Engine::Lua::GetStartupStatus(status);
    DWORD now = GetTickCount();

    if (!status.engineContextDiscovered || !status.luaStateDiscovered)
    {
        g_helperWaitStartTick = 0;
        g_helperBypassWarningLogged = false;
        if (!g_loggedEngineUnstable || (DWORD)(now - g_lastEngineUnstableLogTick) >= kEngineUnstableLogCooldownMs)
        {
            char buf[192];
            sprintf_s(buf, sizeof(buf),
                      "SendBuilder scan deferred: engineContext=%d luaState=%d helpers=%d",
                      status.engineContextDiscovered ? 1 : 0,
                      status.luaStateDiscovered ? 1 : 0,
                      status.helpersInstalled ? 1 : 0);
            WriteRawLog(buf);
            g_loggedEngineUnstable = true;
            g_lastEngineUnstableLogTick = now;
        }
        return false;
    }

    if (g_helperWaitStartTick == 0)
        g_helperWaitStartTick = now;

#if defined(UOWALK_NO_HELPERS)
    g_loggedEngineUnstable = false;
    return true;
#else
    if (status.helpersInstalled)
    {
        g_loggedEngineUnstable = false;
        g_helperBypassWarningLogged = false;
        return true;
    }

    DWORD elapsed = now - g_helperWaitStartTick;
    if (elapsed >= 2000)
    {
        if (!g_helperBypassWarningLogged)
        {
            Log::Logf(Log::Level::Warn,
                      Log::Category::Core,
                      "SendBuilder helper wait exceeded elapsedMs=%lu proceeding without helpers",
                      static_cast<unsigned long>(elapsed));
            g_helperBypassWarningLogged = true;
        }
        g_loggedEngineUnstable = false;
        return true;
    }

    if (!g_loggedEngineUnstable || (DWORD)(now - g_lastEngineUnstableLogTick) >= kEngineUnstableLogCooldownMs)
    {
        char buf[224];
        sprintf_s(buf, sizeof(buf),
                  "SendBuilder scan deferred: engineContext=1 luaState=1 helpers=0 waitMs=%lu",
                  static_cast<unsigned long>(2000 - elapsed));
        WriteRawLog(buf);
        g_loggedEngineUnstable = true;
        g_lastEngineUnstableLogTick = now;
    }
    return false;
#endif
}

static bool SafeCopy(void* dst, const void* src, size_t bytes)
{
    return SafeMem::SafeReadBytes(src, dst, bytes);
}

static HMODULE GetGameModule()
{
    static HMODULE module = GetModuleHandleW(nullptr);
    return module;
}

static bool IsExecutableCodeAddress(void* addr)
{
    return sp::is_executable_code_ptr(addr);
}

static bool IsGameVtableAddress(void* addr, bool* outInRdata = nullptr)
{
    if (!addr)
        return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(addr, &mbi, sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD))
        return false;
    const auto* primary = g_moduleMap.primaryExecutable();
    if (!primary)
        return false;
    if (mbi.AllocationBase != reinterpret_cast<void*>(primary->base))
        return false;

    std::uintptr_t address = reinterpret_cast<std::uintptr_t>(addr);
    bool inRdata = false;
    if (primary->rdataBegin != 0 && primary->rdataEnd > primary->rdataBegin)
        inRdata = address >= primary->rdataBegin && address < primary->rdataEnd;

    if (outInRdata)
        *outInRdata = inRdata;

    if (!inRdata)
        return false;

    DWORD protect = mbi.Protect & 0xFF;
    return protect == PAGE_READONLY ||
           protect == PAGE_READWRITE ||
           protect == PAGE_EXECUTE_READ ||
           protect == PAGE_EXECUTE_READWRITE;
}

struct SendPacketAttemptContext {
    void* sendCtx;
    void* vtbl;
    void* vtblFirstEntry;
    bool vtblEntryExecutable;
    const void* payload;
    int payloadLen;
    void* sendPacketFn;
    void* sendPacketTarget;
};

static thread_local SendPacketAttemptContext g_lastSendAttempt{};

static uint32_t SocketToId(SOCKET sock)
{
    if (sock == INVALID_SOCKET)
        return 0u;
    return static_cast<uint32_t>(static_cast<uintptr_t>(sock));
}

static bool TryCaptureSocketEndpoint(SOCKET sock, uint32_t& ipOut, uint16_t& portOut)
{
    ipOut = 0;
    portOut = 0;
    if (sock == INVALID_SOCKET)
        return false;

    sockaddr_in addr{};
    int len = sizeof(addr);
    if (getpeername(sock, reinterpret_cast<sockaddr*>(&addr), &len) != 0)
        return false;

    ipOut = ntohl(addr.sin_addr.s_addr);
    portOut = ntohs(addr.sin_port);
    return true;
}

static uint64_t PerfFrequency()
{
    static uint64_t s_freq = []() -> uint64_t {
        LARGE_INTEGER freq{};
        QueryPerformanceFrequency(&freq);
        return freq.QuadPart == 0 ? 1ull : static_cast<uint64_t>(freq.QuadPart);
    }();
    return s_freq;
}

struct CandidateRaw
{
    void* endpoint = nullptr;
    void* manager = nullptr;
    void* vtbl = nullptr;
    size_t offset = 0;
};

struct CandidateProcessOutcome
{
    bool accepted = false;
    bool attempted = false;
};

struct TraceResult;
struct TraceHop
{
    const char* pattern = nullptr;
    uint8_t* from = nullptr;
    uint8_t* to = nullptr;
    uint8_t* slot = nullptr;
    uint8_t* slotValue = nullptr;
};

struct TraceResult
{
    uint8_t* site = nullptr;
    uint32_t offset = 0;
    uint8_t* finalTarget = nullptr;
    size_t hopCount = 0;
    uint8_t slotIndex = 0xFF;
    void* vtable = nullptr;
    TraceHop hops[kTailFollowMaxDepth] = {};
};

static RingHitStats EvaluateRingHits(const std::vector<Core::SendRing::Entry>& samples,
                                     void* candidateEntry,
                                     const TraceResult& trace)
{
    RingHitStats stats{};
    if (samples.empty())
        return stats;

    std::vector<std::uintptr_t> addresses;
    addresses.reserve(16);

    auto pushAddress = [&addresses](const void* addr) {
        if (!addr)
            return;
        addresses.push_back(reinterpret_cast<std::uintptr_t>(addr));
    };

    pushAddress(candidateEntry);
    pushAddress(trace.finalTarget);
    pushAddress(trace.site);
    for (size_t i = 0; i < trace.hopCount; ++i) {
        pushAddress(trace.hops[i].from);
        pushAddress(trace.hops[i].to);
        pushAddress(trace.hops[i].slotValue);
    }

    const auto* primary = g_moduleMap.primaryExecutable();

    for (const auto& sample : samples) {
        if (!sample.func)
            continue;
        ++stats.considered;

        const std::uintptr_t pc = reinterpret_cast<std::uintptr_t>(sample.func);
        bool matched = false;
        for (const auto addr : addresses) {
            if (addr == 0)
                continue;
            const std::uintptr_t lower = (addr > kRingMatchLeewayBytes) ? (addr - kRingMatchLeewayBytes) : 0;
            const std::uintptr_t upper = addr + kRingMatchLeewayBytes;
            if (pc >= lower && pc <= upper) {
                matched = true;
                break;
            }
        }

        if (!matched)
            continue;

        if (IsInSelfModule(sample.func)) {
            ++stats.selfHits;
            continue;
        }

        if (!primary || !primary->containsText(pc)) {
            ++stats.offModuleHits;
            continue;
        }

        ++stats.hits;
    }

    return stats;
}

static void ResetTraceResult(TraceResult& trace);
static bool TraceSendPacketUse(uint8_t* fn, TraceResult& trace, uint8_t slotIndex, void* vtable);
static bool TraceSendPacketFrom(uint8_t* fn,
                                size_t window,
                                int depthRemaining,
                                TraceResult& trace,
                                uint8_t** visited,
                                size_t& visitedCount,
                                bool isRoot);
static void* __fastcall Hook_SendBuilder(void* thisPtr, void* /*unused*/, void* builder);

static void LogTraceHops(const TraceResult& trace, uint8_t slotLabel)
{
    for (size_t hop = 0; hop < trace.hopCount; ++hop) {
        const TraceHop& hopInfo = trace.hops[hop];
        const bool isRoot = (hop == 0);
        const char* pattern = hopInfo.pattern ? hopInfo.pattern : "?";
        if (isRoot) {
            if (hopInfo.slot && hopInfo.slotValue) {
                Log::Logf(Log::Level::Info,
                          Log::Category::Core,
                          "[CORE][SB] hop vtbl[%02X] @%p: %s -> [%08lX]=%p",
                          slotLabel,
                          hopInfo.from,
                          pattern,
                          static_cast<unsigned long>(reinterpret_cast<uintptr_t>(hopInfo.slot)),
                          hopInfo.slotValue);
            } else {
                Log::Logf(Log::Level::Info,
                          Log::Category::Core,
                          "[CORE][SB] hop vtbl[%02X] @%p: %s -> %p",
                          slotLabel,
                          hopInfo.from,
                          pattern,
                          hopInfo.to);
            }
        } else {
            if (hopInfo.slot && hopInfo.slotValue) {
                Log::Logf(Log::Level::Info,
                          Log::Category::Core,
                          "[CORE][SB] hop @%p: %s -> [%08lX]=%p",
                          hopInfo.from,
                          pattern,
                          static_cast<unsigned long>(reinterpret_cast<uintptr_t>(hopInfo.slot)),
                          hopInfo.slotValue);
            } else {
                Log::Logf(Log::Level::Info,
                          Log::Category::Core,
                          "[CORE][SB] hop @%p: %s -> %p",
                          hopInfo.from,
                          pattern,
                          hopInfo.to);
            }
        }
    }
}

static void FormatTraceChain(const TraceResult& trace, char* buffer, size_t length)
{
    if (!buffer || length == 0)
        return;

    buffer[0] = '\0';
    if (trace.hopCount == 0) {
        std::snprintf(buffer, length, "?");
        return;
    }

    size_t written = 0;
    for (size_t hop = 0; hop < trace.hopCount; ++hop) {
        if (hop > 0 && written + 2 < length) {
            int step = std::snprintf(buffer + written, length - written, "->");
            if (step < 0)
                break;
            if (static_cast<size_t>(step) >= length - written) {
                written = length - 1;
                break;
            }
            written += static_cast<size_t>(step);
        }
        const char* pattern = trace.hops[hop].pattern ? trace.hops[hop].pattern : "?";
        if (written < length) {
            int step = std::snprintf(buffer + written, length - written, "%s", pattern);
            if (step < 0)
                break;
            if (static_cast<size_t>(step) >= length - written) {
                written = length - 1;
                break;
            }
            written += static_cast<size_t>(step);
        }
        if (written >= length - 1)
            break;
    }
    if (written == 0)
        std::snprintf(buffer, length, "?");
}

static bool AttachSendBuilderFromTrace(void* matchedFn,
                                       uint8_t slotIndex,
                                       void* vtbl,
                                       const TraceResult* traceOpt,
                                       const char* fallbackLabel,
                                       const uint8_t* byteTargetOverride)
{
    if (!matchedFn)
        return false;

    const uint8_t* byteTarget = byteTargetOverride;
    char chain[128] = {};
    chain[0] = '\0';
    uint8_t displaySlot = slotIndex;

    if (traceOpt) {
        const TraceResult& trace = *traceOpt;
        const uint8_t slotLabel = (trace.slotIndex != 0xFF) ? trace.slotIndex : slotIndex;
        displaySlot = slotLabel;
        LogTraceHops(trace, slotLabel);
        FormatTraceChain(trace, chain, sizeof(chain));
        if (trace.site)
            byteTarget = trace.site;
        else if (!byteTarget)
            byteTarget = reinterpret_cast<const uint8_t*>(matchedFn) + trace.offset;
    } else {
        std::snprintf(chain, sizeof(chain), "%s", (fallbackLabel && fallbackLabel[0]) ? fallbackLabel : "direct");
        if (!byteTarget)
            byteTarget = reinterpret_cast<const uint8_t*>(matchedFn);
    }

    if (g_sendBuilderHooked)
        return true;

    if (MH_CreateHook(matchedFn, Hook_SendBuilder, reinterpret_cast<LPVOID*>(&fpSendBuilder)) == MH_OK &&
        MH_EnableHook(matchedFn) == MH_OK) {
        g_builderProbeSuccess.fetch_add(1u, std::memory_order_relaxed);
        g_sendBuilderHooked = true;
        g_sendBuilderTarget = matchedFn;
        uint8_t byteSample[4] = {0xFF, 0xFF, 0xFF, 0xFF};
        bool haveBytes = false;
        if (byteTarget)
            haveBytes = SafeMem::SafeReadBytes(byteTarget, byteSample, sizeof(byteSample));
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[CORE][SB] attaching vtbl[%02u]=%p bytes=%02X %02X %02X %02X",
                  static_cast<unsigned>(slotIndex),
                  matchedFn,
                  haveBytes ? byteSample[0] : 0xFF,
                  haveBytes ? byteSample[1] : 0xFF,
                  haveBytes ? byteSample[2] : 0xFF,
                  haveBytes ? byteSample[3] : 0xFF);
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[CORE][SB] matched vtbl[%02X]=%p via %s -> SendPacket (hits=%u) ATTACHED",
                  displaySlot,
                  matchedFn,
                  chain[0] ? chain : "?",
                  t_ringHitsForAttach);
        Core::StartupSummary::NotifySendBuilderReady();
        Core::StartupSummary::NotifySendBuilderReady();
        return true;
    }

    WriteRawLog("ScanEndpointVTable: failed to hook suspected builder");
    g_builderProbeSkipped.fetch_add(1u, std::memory_order_relaxed);
    return false;
}

static uint8_t* LocateFunctionStart(uint8_t* ret,
                                    const Scanner::ModuleInfo& module)
{
    if (!ret)
        return nullptr;

    constexpr std::size_t kMaxBack = 0x40;
    const std::uintptr_t moduleBegin = module.textBegin ? module.textBegin : module.base;
    const std::uintptr_t moduleEnd = module.textEnd ? module.textEnd : module.end;
    const std::uintptr_t retAddr = reinterpret_cast<std::uintptr_t>(ret);
    if (retAddr <= moduleBegin || retAddr >= moduleEnd)
        return nullptr;

    for (std::size_t back = 0; back <= kMaxBack; ++back) {
        if (retAddr <= moduleBegin + back + 4)
            break;
        uint8_t* candidate = ret - back;
        if (!candidate)
            break;
        if (reinterpret_cast<std::uintptr_t>(candidate) < moduleBegin)
            break;
        uint8_t bytes[6] = {};
        if (!SafeMem::SafeReadBytes(candidate, bytes, sizeof(bytes)))
            continue;

        if (bytes[0] == 0x55 && bytes[1] == 0x8B && (bytes[2] == 0xEC || bytes[2] == 0xE5))
            return candidate;
        if (bytes[0] == 0x53 && bytes[1] == 0x56)
            return candidate;
        if (bytes[0] == 0x53 && bytes[1] == 0x57)
            return candidate;
        if (bytes[0] == 0x56 && bytes[1] == 0x57)
            return candidate;
        if (bytes[0] == 0x57 && bytes[1] == 0x56)
            return candidate;
        if (bytes[0] == 0x8B && bytes[1] == 0xFF && bytes[2] == 0x55 && bytes[3] == 0x8B && (bytes[4] == 0xEC || bytes[4] == 0xE5))
            return candidate + 2;
        if (bytes[0] == 0xCC && back > 0)
            return candidate + 1;
    }

    return ret;
}

static uint8_t* NormalizeSampleStart(uint8_t* func,
                                     const Scanner::ModuleInfo& module)
{
    if (!func)
        return nullptr;

    uint8_t* normalized = LocateFunctionStart(func, module);
    if (normalized && func >= normalized && static_cast<std::size_t>(func - normalized) <= 0x40)
        return normalized;

    const std::uintptr_t moduleBegin = module.textBegin ? module.textBegin : module.base;
    if (func <= reinterpret_cast<uint8_t*>(moduleBegin))
        return func;

    uint8_t* cursor = func;
    std::size_t scanned = 0;
    while (cursor > reinterpret_cast<uint8_t*>(moduleBegin) && scanned < 0x40) {
        --cursor;
        ++scanned;
        uint8_t byte = 0;
        if (!SafeMem::SafeReadBytes(cursor, &byte, sizeof(byte)))
            continue;
        if (byte == 0xCC || byte == 0xC3 || byte == 0x90) {
            return cursor < func ? cursor : func;
        }
    }

    return normalized ? normalized : func;
}

static Scanner::EdgeType ClassifyEdgeFromReturn(uint8_t* ret)
{
    if (!ret)
        return Scanner::EdgeType::Unknown;

    const std::uintptr_t retAddr = reinterpret_cast<std::uintptr_t>(ret);

    auto readByte = [](const uint8_t* addr, uint8_t& value) -> bool {
        return SafeMem::SafeReadBytes(addr, &value, sizeof(value));
    };

    uint8_t opcode = 0;

    if (retAddr >= 5 && readByte(ret - 5, opcode) && opcode == 0xE8)
        return Scanner::EdgeType::Direct;

    if (retAddr >= 6) {
        uint8_t bytes[2] = {};
        if (SafeMem::SafeReadBytes(ret - 6, bytes, sizeof(bytes))) {
            if (bytes[0] == 0xFF && bytes[1] == 0x15)
                return Scanner::EdgeType::Direct;
        }
    }

    if (retAddr >= 2) {
        uint8_t bytes[2] = {};
        if (SafeMem::SafeReadBytes(ret - 2, bytes, sizeof(bytes))) {
            if (bytes[0] == 0xFF && (bytes[1] & 0xF8) == 0xD0)
                return Scanner::EdgeType::RegThunk;
        }
    }

    if (retAddr >= 3) {
        uint8_t bytes[3] = {};
        if (SafeMem::SafeReadBytes(ret - 3, bytes, sizeof(bytes))) {
            if (bytes[0] == 0xFF && (bytes[1] & 0xF8) == 0xE0)
                return Scanner::EdgeType::Tail;
        }
    }

    if (retAddr >= 7) {
        uint8_t bytes[7] = {};
        if (SafeMem::SafeReadBytes(ret - 7, bytes, sizeof(bytes))) {
            if (bytes[0] == 0x68 && bytes[5] == 0xE9)
                return Scanner::EdgeType::PushJmp;
            if (bytes[0] == 0x68 && bytes[5] == 0xFF && bytes[6] == 0x25)
                return Scanner::EdgeType::PushJmp;
        }
    }

    if (retAddr >= 5 && readByte(ret - 5, opcode) && opcode == 0xE9)
        return Scanner::EdgeType::Tail;

    return Scanner::EdgeType::Unknown;
}

static bool BuildSendSample(void* retPtr,
                            std::uint64_t nowMs,
                            Scanner::SendSample& outSample,
                            const Scanner::ModuleInfo** moduleOut)
{
    if (!retPtr)
        return false;

    const Scanner::ModuleInfo* module = g_moduleMap.findByAddress(retPtr);
    if (!module) {
        g_moduleMap.refresh(true);
        module = g_moduleMap.findByAddress(retPtr);
    }
    if (!module)
        return false;

    uint8_t* ret = reinterpret_cast<uint8_t*>(retPtr);
    uint8_t* funcStart = LocateFunctionStart(ret, *module);
    if (!funcStart)
        return false;

    const std::uintptr_t funcAddr = reinterpret_cast<std::uintptr_t>(funcStart);
    if (funcAddr < module->textBegin || funcAddr >= module->textEnd)
        return false;

    std::uint32_t rva = static_cast<std::uint32_t>(funcAddr - module->base);
    if (!g_sendSampleDeduper.accept(module->base, rva, nowMs))
        return false;

    outSample.ret = retPtr;
    outSample.func = funcStart;
    outSample.rva = rva;
    outSample.tick = nowMs;
    outSample.edge = ClassifyEdgeFromReturn(ret);
    outSample.moduleBase = module->base;
    if (moduleOut)
        *moduleOut = module;
    return true;
}

static constexpr USHORT kMaxFingerprintFrames =
    static_cast<USHORT>(Net::SendSampleStore::kMaxFrames);
static void FormatSampleLabel(const Scanner::ModuleInfo* module,
                              const Scanner::SendSample& sample,
                              char* buffer,
                              size_t bufferLen)
{
    if (!buffer || bufferLen == 0) {
        return;
    }

    buffer[0] = '\0';

    const Scanner::ModuleInfo* primary = g_moduleMap.primaryExecutable();
    if (module && primary && module->module == primary->module) {
        std::snprintf(buffer, bufferLen, "UOSA+0x%X", static_cast<unsigned>(sample.rva));
        return;
    }

    if (module && module->module) {
        char moduleName[MAX_PATH] = {};
        if (GetModuleBaseNameA(GetCurrentProcess(), module->module, moduleName, static_cast<DWORD>(sizeof(moduleName))) == 0) {
            std::snprintf(moduleName,
                          sizeof(moduleName),
                          "%p",
                          module->module);
        }
        std::snprintf(buffer, bufferLen, "%s!0x%X", moduleName, static_cast<unsigned>(sample.rva));
        return;
    }

    std::snprintf(buffer,
                  bufferLen,
                  "0x%llX!0x%X",
                  static_cast<unsigned long long>(sample.moduleBase),
                  static_cast<unsigned>(sample.rva));
}

namespace Scanner {
namespace Sampler {

bool shouldSample(std::uint64_t nowMs)
{
    std::uint32_t remaining = g_samplerWarmupRemaining.load(std::memory_order_relaxed);
    while (remaining > 0) {
        if (g_samplerWarmupRemaining.compare_exchange_weak(remaining,
                                                           remaining - 1,
                                                           std::memory_order_acq_rel,
                                                           std::memory_order_relaxed)) {
            return true;
        }
    }
    return g_sendSampleBucket.tryConsume(nowMs);
}

std::uint32_t enqueueFrames(void** frames,
                            USHORT frameCount,
                            std::uint64_t nowMs,
                            void* thisPtr,
                            SendSample* firstOut)
{
    if (!frames || frameCount == 0)
        return 0;

    const USHORT limit = frameCount > kMaxFingerprintFrames ? kMaxFingerprintFrames : frameCount;
    std::uint32_t produced = 0;
    SendSample firstSample{};

    for (USHORT i = 0; i < limit; ++i) {
        void* frame = frames[i];
        if (!frame)
            continue;

        const Scanner::ModuleInfo* moduleInfo = nullptr;
        SendSample sample{};
        if (!BuildSendSample(frame, nowMs, sample, &moduleInfo))
            continue;

        sample.thisPtr = thisPtr;

        if (!g_sendSampleRing.push(sample)) {
            DWORD nowTick = GetTickCount();
            DWORD prev = g_lastSampleDropLogTick.load(std::memory_order_relaxed);
            if ((nowTick - prev) > 1000 &&
                g_lastSampleDropLogTick.compare_exchange_strong(prev,
                                                                nowTick,
                                                                std::memory_order_acq_rel,
                                                                std::memory_order_relaxed)) {
                Log::Logf(Log::Level::Warn,
                          Log::Category::Core,
                          "[SEND_SAMPLE] ring full func=UOSA+0x%08X",
                          static_cast<unsigned>(sample.rva));
            }
            break;
        }

        if (produced == 0)
            firstSample = sample;

        ++produced;

        if (g_sbDebug.load(std::memory_order_relaxed) && sample.rva != 0) {
            char label[128];
            FormatSampleLabel(moduleInfo, sample, label, sizeof(label));
            Log::Logf(Log::Level::Info,
                      Log::Category::Core,
                      "[SEND_SAMPLE] func=%s",
                      label);
        }
    }

    if (produced > 0 && firstOut)
        *firstOut = firstSample;

    return produced;
}

void drain(std::vector<SendSample>& out, std::uint32_t max, std::uint32_t* ringLoadPctOut)
{
    out.clear();
    g_sendSampleRing.drain(out, max);
    const std::uint32_t load = g_sendSampleRing.loadPercent();
    if (ringLoadPctOut)
        *ringLoadPctOut = load;
    g_lastRingLoad.store(load, std::memory_order_relaxed);
}

std::vector<SendSample> drain(std::uint32_t max)
{
    std::vector<SendSample> result;
    drain(result, max, nullptr);
    return result;
}

std::uint32_t ringLoadPercent()
{
    return g_sendSampleRing.loadPercent();
}

void reset(std::uint64_t nowMs)
{
    g_sendSampleRing.reset();
    g_sendSampleDeduper.reset();
    g_samplerWarmupRemaining.store(kSamplerWarmupSamples, std::memory_order_relaxed);
    g_sendSampleBucket.reset(nowMs);
    g_lastRingLoad.store(0, std::memory_order_relaxed);
    g_lastSampleDropLogTick.store(0, std::memory_order_relaxed);
    g_sendSampleStore.Reset();
}

} // namespace Sampler
} // namespace Scanner

bool IsSendSamplingEnabled()
{
    return g_sendSamplingEnabled.load(std::memory_order_relaxed);
}

void SubmitSendSample(void* endpoint, void** frames, USHORT captured, std::uint64_t nowMs)
{
    if (!IsSendSamplingEnabled())
        return;
    if (!frames || captured == 0)
        return;

    const std::uint16_t count = static_cast<std::uint16_t>(captured);
    std::uint64_t fingerprint = Net::SendSampleStore::HashFrames(g_moduleMap,
                                                                 frames,
                                                                 count);
    if (endpoint && fingerprint != 0)
        g_sendSampleStore.Add(endpoint, fingerprint);

    Scanner::SendSample firstSample{};
    std::uint32_t produced = Scanner::Sampler::enqueueFrames(frames,
                                                             captured,
                                                             nowMs,
                                                             endpoint,
                                                             &firstSample);
    if (produced > 0 && endpoint) {
        std::lock_guard<std::mutex> lock(g_endpointCallsiteMutex);
        g_endpointCallsiteHints[endpoint] = firstSample.rva;
    }
}

static bool IsExecutableSendContext(void* candidate, void** outVtbl, void** outEntry0);
static bool ScanEndpointVTable(void* endpoint,
                               bool& outNoPath,
                               const std::vector<Core::SendRing::Entry>* ringSamples,
                               RingHitStats* ringStats,
                               TraceResult* outTrace = nullptr);
static void CaptureSendContext(void* candidate, const char* sourceTag);
static void MaybeSendDebugNudge();
static bool IsExecutablePtr(const void* p);
static void ApplySuccessfulAttach(void* endpoint, void* manager, const TraceResult& trace, std::uint64_t nowMs);
static bool ProcessSendSamplesFast(const std::vector<Scanner::SendSample>& samples,
                                   Scanner::ScanPassTelemetry& telemetry);
static std::optional<std::uint32_t> ResolveRva(void* addr);

static CandidateProcessOutcome ProcessScannerCandidate(const Scanner::CandidateDescriptor& descriptor,
                                                       const std::vector<Core::SendRing::Entry>& ringSamples,
                                                       Scanner::ScanPassTelemetry& telemetry,
                                                       uint64_t perfFreq);

static std::optional<std::uint32_t> ResolveRva(void* addr)
{
    if (!addr)
        return std::nullopt;
    const Scanner::ModuleInfo* module = g_moduleMap.findByAddress(addr);
    if (!module)
        return std::nullopt;
    const Scanner::ModuleInfo* primary = g_moduleMap.primaryExecutable();
    if (!primary || module->module != primary->module)
        return std::nullopt;
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(addr) - module->base);
}

static void ApplySuccessfulAttach(void* endpoint, void* manager, const TraceResult& trace, std::uint64_t nowMs)
{
    if (!endpoint)
        return;

    g_rejectStore.clear(reinterpret_cast<std::uintptr_t>(endpoint));

    void* trustManager = manager ? manager : endpoint;
    if (trace.vtable && trace.slotIndex != 0xFF) {
        Scanner::EndpointTrustCache::SlotKey slotKey{trustManager, trace.vtable, trace.slotIndex};
        g_endpointTrust.store(slotKey, true, nowMs, 30u * 60u * 1000u);
    }

    if (trace.site) {
        if (auto rva = ResolveRva(trace.site)) {
            Scanner::EndpointTrustCache::CodeKey codeKey{*rva};
            g_endpointTrust.store(codeKey, true, nowMs, 30u * 60u * 1000u);
            std::lock_guard<std::mutex> lock(g_endpointCallsiteMutex);
            g_endpointCallsiteHints[endpoint] = *rva;
        }
    }

    g_lastLoggedEndpoint = endpoint;
    ClearEndpointBackoff(endpoint);
    if (g_sendBuilderHooked)
        g_builderScanned = true;
}

static bool AttachSampleViaEndpoint(const Scanner::SendSample& sample, std::uint64_t nowMs)
{
    if (!sample.thisPtr)
        return false;

    bool noPath = false;
    TraceResult endpointTrace{};
    ResetTraceResult(endpointTrace);
    if (!ScanEndpointVTable(sample.thisPtr,
                           noPath,
                           nullptr,
                           nullptr,
                           &endpointTrace))
        return false;

    ApplySuccessfulAttach(sample.thisPtr, nullptr, endpointTrace, nowMs);
    if (sample.rva != 0) {
        std::lock_guard<std::mutex> lock(g_endpointCallsiteMutex);
        g_endpointCallsiteHints[sample.thisPtr] = sample.rva;
    }
    return true;
}

static bool AttachSampleViaCodesite(const Scanner::SendSample& sample,
                                    const TraceResult& trace,
                                    std::uint64_t nowMs)
{
    if (!sample.func || !IsExecutablePtr(sample.func))
        return false;

    if (!AttachSendBuilderFromTrace(sample.func, 0xFF, nullptr, &trace, "sample-trace", nullptr))
        return false;

    const Scanner::ModuleInfo* primary = g_moduleMap.primaryExecutable();
    if (primary && sample.moduleBase == primary->base && sample.rva != 0) {
        Scanner::EndpointTrustCache::CodeKey codeKey{sample.rva};
        g_endpointTrust.store(codeKey, true, nowMs, 600000);
    }

    if (sample.thisPtr && sample.rva != 0) {
        std::lock_guard<std::mutex> lock(g_endpointCallsiteMutex);
        g_endpointCallsiteHints[sample.thisPtr] = sample.rva;
    }

    if (sample.thisPtr)
        ClearEndpointBackoff(sample.thisPtr);
    g_builderScanned = g_sendBuilderHooked;
    return true;
}

static bool ProcessSendSamplesFast(const std::vector<Scanner::SendSample>& samples,
                                   Scanner::ScanPassTelemetry& telemetry)
{
    if (samples.empty())
        return false;

    const uint64_t nowMs = GetTickCount64();
    std::uint32_t examined = 0;
    std::unordered_set<void*> visitedEndpoints;
    visitedEndpoints.reserve(samples.size());

    const Scanner::ModuleInfo* primary = g_moduleMap.primaryExecutable();
    if (!primary)
        return false;
    const std::uintptr_t primaryBase = primary->base;

    for (const auto& sample : samples) {
        const bool hasPrimaryRva = (primaryBase != 0 && sample.moduleBase == primaryBase && sample.rva != 0);
        if (!hasPrimaryRva)
            continue;
        if (examined >= 16)
            break;
        ++examined;

        Scanner::EndpointTrustCache::CodeKey codeKey{};
        if (hasPrimaryRva)
            codeKey = {sample.rva};

        if (hasPrimaryRva && g_endpointTrust.shouldSkip(codeKey, nowMs)) {
            ++telemetry.sample_rejects;
            continue;
        }

        TraceResult trace{};
        ResetTraceResult(trace);
        uint8_t* visited[kTailFollowMaxDepth] = {};
        size_t visitedCount = 0;
        uint8_t* normalizedStart = NormalizeSampleStart(reinterpret_cast<uint8_t*>(sample.func), *primary);
        if (!normalizedStart)
            continue;
        bool matched = TraceSendPacketFrom(normalizedStart,
                                           kEndpointScanWindow,
                                           kTailFollowMaxDepth,
                                           trace,
                                           visited,
                                           visitedCount,
                                           true);
        if (!matched || !trace.finalTarget) {
            if (hasPrimaryRva)
                g_endpointTrust.store(codeKey, false, nowMs, 10000);
            ++telemetry.sample_rejects;
            continue;
        }

        ++telemetry.sample_hits;

        bool attached = false;
        if (sample.thisPtr) {
            if (visitedEndpoints.insert(sample.thisPtr).second) {
                attached = AttachSampleViaEndpoint(sample, nowMs);
            }
        }

        if (!attached) {
            attached = AttachSampleViaCodesite(sample, trace, nowMs);
        }

        if (attached) {
            if (hasPrimaryRva)
                g_endpointTrust.store(codeKey, true, nowMs, 600000);
            ++telemetry.accepted;
            return true;
        }

        if (hasPrimaryRva)
            g_endpointTrust.store(codeKey, false, nowMs, 30000);
        ++telemetry.sample_rejects;
    }

    return false;
}

static bool RunCandidatePass(const std::vector<CandidateRaw>& rawCandidates,
                             const std::vector<Scanner::SendSample>& stackSamples,
                             const std::vector<Core::SendRing::Entry>& ringSamples,
                             uint32_t ringSampleCount,
                             uint32_t ringLoadPct,
                             std::uint64_t passId,
                             Scanner::ScanPassTelemetry& telemetry,
                             const ManagerTarget& managerTarget,
                             const std::string& preconditions)
{
    const std::uint32_t preRejHits = telemetry.rej_cache_hits;
    const std::uint32_t preRejInserted = telemetry.rej_cache_inserted;
    telemetry = {};
    telemetry.rej_cache_hits = preRejHits;
    telemetry.rej_cache_inserted = preRejInserted;
    telemetry.id = passId;
    telemetry.send_samples = ringSampleCount;
    telemetry.ring_load_pct = ringLoadPct;
    const std::uint64_t passStartMs = GetTickCount64();

    if (g_firstScanTickMs64 == 0)
        g_firstScanTickMs64 = GetTickCount64();

    g_guardWarnPass.store(telemetry.id, std::memory_order_relaxed);
    g_guardWarnBudget.store(1, std::memory_order_relaxed);

    if (ProcessSendSamplesFast(stackSamples, telemetry)) {
        telemetry.rej_cache_size = static_cast<std::uint32_t>(Core::GetRejectCache().size());
        const std::uint64_t passElapsed = GetTickCount64() - passStartMs;
        telemetry.elapsed_ms = static_cast<std::uint32_t>(std::min<std::uint64_t>(passElapsed, std::numeric_limits<std::uint32_t>::max()));

        g_tuner.applyTelemetry(telemetry);

        return g_builderScanned;
    }

    if (rawCandidates.empty()) {
        telemetry.rej_cache_size = static_cast<std::uint32_t>(Core::GetRejectCache().size());
        const std::uint64_t passElapsed = GetTickCount64() - passStartMs;
        telemetry.elapsed_ms = static_cast<std::uint32_t>(std::min<std::uint64_t>(passElapsed, std::numeric_limits<std::uint32_t>::max()));
        g_tuner.applyTelemetry(telemetry);
        return false;
    }

    std::vector<Scanner::CandidateDescriptor> descriptors;
    descriptors.reserve(rawCandidates.size());
    uint32_t trustedCandidates = 0;

    const std::uint64_t descriptorNowMs = GetTickCount64();

    for (const auto& raw : rawCandidates) {
        if (!raw.endpoint)
            continue;

        Scanner::CandidateDescriptor descriptor{};
        descriptor.endpoint = raw.endpoint;
        descriptor.manager = raw.manager;
        descriptor.vtbl = raw.vtbl;
        descriptor.offset = raw.offset;

        std::uint64_t hintRva = 0;
        {
            std::lock_guard<std::mutex> lock(g_endpointCallsiteMutex);
            auto hint = g_endpointCallsiteHints.find(raw.endpoint);
            if (hint != g_endpointCallsiteHints.end())
                hintRva = hint->second;
        }

        void* trustManager = raw.manager ? raw.manager : raw.endpoint;
        if (auto managerTrust = g_endpointTrust.lookupByManager(trustManager, descriptorNowMs)) {
            if (managerTrust->accepted)
                descriptor.trusted = true;
        }

        Net::SendSampleStore::EndpointStats endpointStats{};
        if (g_sendSampleStore.TryGetStats(raw.endpoint, endpointStats) && endpointStats.total > 0) {
            descriptor.sampleReferenced = true;
            descriptor.sampleCount = endpointStats.total;
        }

        if (hintRva != 0) {
            Scanner::EndpointTrustCache::CodeKey codeKey{static_cast<std::uint32_t>(hintRva)};
            if (auto codeTrust = g_endpointTrust.lookup(codeKey, descriptorNowMs)) {
                if (codeTrust->accepted)
                    descriptor.trusted = true;
            }
        }

        if (descriptor.trusted)
            ++trustedCandidates;
        descriptors.push_back(descriptor);
    }

    if (descriptors.empty()) {
        telemetry.rej_cache_size = static_cast<std::uint32_t>(Core::GetRejectCache().size());
        const std::uint64_t passElapsed = GetTickCount64() - passStartMs;
        telemetry.elapsed_ms = static_cast<std::uint32_t>(std::min<std::uint64_t>(passElapsed, std::numeric_limits<std::uint32_t>::max()));
        g_tuner.applyTelemetry(telemetry);
        return false;
    }

    Scanner::PrioritizeCandidates(descriptors);

    const uint64_t freq = PerfFrequency();
    uint32_t attempted = 0;
    const uint32_t maxInflight = std::max(1u, g_tuner.maxInflight());

    for (const auto& descriptor : descriptors) {
        if (g_builderScanned)
            break;
        CandidateProcessOutcome outcome = ProcessScannerCandidate(descriptor,
                                        ringSamples,
                                        telemetry,
                                        freq);
        if (outcome.accepted)
            break;
        if (outcome.attempted) {
            ++attempted;
            if (attempted >= maxInflight)
                break;
        }
    }

    telemetry.rej_cache_size = static_cast<std::uint32_t>(Core::GetRejectCache().size());
    const std::uint64_t passElapsed = GetTickCount64() - passStartMs;
    telemetry.elapsed_ms = static_cast<std::uint32_t>(std::min<std::uint64_t>(passElapsed, std::numeric_limits<std::uint32_t>::max()));

    g_tuner.applyTelemetry(telemetry);

    Log::Logf(Log::Level::Debug,
              Log::Category::Core,
              "[SB] pass: candidates=%zu trusted=%u sendSamples=%u ringLoad=%u rejHits=%u rejIns=%u rejSkipped=%u",
              descriptors.size(),
              trustedCandidates,
              ringSampleCount,
              ringLoadPct,
              telemetry.rej_cache_hits,
              telemetry.rej_cache_inserted,
              telemetry.rejected_skipped);

    return g_builderScanned;
}

static CandidateProcessOutcome ProcessScannerCandidate(const Scanner::CandidateDescriptor& descriptor,
                                                       const std::vector<Core::SendRing::Entry>& ringSamples,
                                                       Scanner::ScanPassTelemetry& telemetry,
                                                       uint64_t perfFreq)
{
    CandidateProcessOutcome outcome{};
    if (!descriptor.endpoint)
        return outcome;

    const std::uintptr_t addr = reinterpret_cast<std::uintptr_t>(descriptor.endpoint);
    const int slotIndex = (descriptor.offset != std::numeric_limits<std::size_t>::max())
                              ? static_cast<int>(descriptor.offset / sizeof(void*))
                              : -1;
    const uint64_t nowMs = GetTickCount64();
    void* slotKey = nullptr;
    if (descriptor.vtbl && descriptor.offset != std::numeric_limits<std::size_t>::max())
        slotKey = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(descriptor.vtbl) + descriptor.offset);
    std::uint8_t rejectReason = kRejectReasonGeneric;

    if (g_rejectStore.isRejectedAndActive(addr, nowMs)) {
        ++telemetry.rejected_skipped;
        Log::Logf(Log::Level::Debug,
                  Log::Category::Core,
                  "[REJECT] skip addr=%p active=1",
                  descriptor.endpoint);
        return outcome;
    }

    void* trustManager = descriptor.manager ? descriptor.manager : descriptor.endpoint;
    if (trustManager) {
        if (auto cached = g_endpointTrust.lookupByManager(trustManager, nowMs)) {
            ++telemetry.rejected_skipped;
            Log::Logf(Log::Level::Debug,
                      Log::Category::Core,
                      "[SB] skip candidate manager=%p endpoint=%p reason=manager-cache accepted=%u",
                      trustManager,
                      descriptor.endpoint,
                      cached->accepted ? 1u : 0u);
            return outcome;
        }
    }

    if (slotIndex >= 0) {
        Scanner::EndpointTrustCache::SlotKey slotTrustKey{trustManager, descriptor.vtbl, slotIndex};
        if (g_endpointTrust.shouldSkip(slotTrustKey, nowMs)) {
            ++telemetry.rejected_skipped;
            Log::Logf(Log::Level::Debug,
                      Log::Category::Core,
                      "[SB] skip candidate manager=%p endpoint=%p reason=slot-cache slot=%d",
                      trustManager,
                      descriptor.endpoint,
                      slotIndex);
            return outcome;
        }
    }

    outcome.attempted = true;

    LARGE_INTEGER start{}, end{};
    QueryPerformanceCounter(&start);

    bool accepted = false;
    bool rejected = false;
    bool noPath = false;
    RingHitStats ringStats{};
    TraceResult trace{};
    ResetTraceResult(trace);

    if (ScanEndpointVTable(descriptor.endpoint,
                           noPath,
                           &ringSamples,
                           &ringStats,
                           &trace)) {
        accepted = true;
    } else {
        rejected = true;
        if (noPath)
            rejectReason = kRejectReasonNoChain;
        else if (ringStats.selfHits > 0 && ringStats.hits == 0)
            rejectReason = kRejectReasonSelf;
        else if (ringStats.offModuleHits > 0 && ringStats.hits == 0)
            rejectReason = kRejectReasonOffText;
    }

    telemetry.sample_hits += ringStats.hits;
    telemetry.sample_rejects += ringStats.selfHits + ringStats.offModuleHits;

    QueryPerformanceCounter(&end);
    const uint64_t elapsed = static_cast<uint64_t>(end.QuadPart - start.QuadPart);
    const uint64_t durationUs = (elapsed * 1000000ull) / (perfFreq ? perfFreq : 1ull);

    telemetry.recordCandidate(durationUs, accepted, rejected);

    if (accepted) {
        ApplySuccessfulAttach(descriptor.endpoint, descriptor.manager, trace, nowMs);
        outcome.accepted = true;
        return outcome;
    }

    if (rejected) {
        if (slotIndex >= 0 && descriptor.vtbl && rejectReason != kRejectReasonGeneric) {
            LogRejectTtl(reinterpret_cast<std::uintptr_t>(descriptor.vtbl), slotIndex, rejectReason);
        }
        Core::GetRejectCache().reject(slotKey ? slotKey : descriptor.endpoint, rejectReason);
        ++telemetry.rej_cache_inserted;
        auto rejectInfo = g_rejectStore.incrementReject(addr, nowMs);
        Log::Logf(Log::Level::Warn,
                  Log::Category::Core,
                  "[REJECT] endpoint=%p count=%u ttl=%us",
                  descriptor.endpoint,
                  rejectInfo.first,
                  rejectInfo.second);
        if (trace.site) {
            if (auto rva = ResolveRva(trace.site)) {
                Scanner::EndpointTrustCache::CodeKey codeKey{*rva};
                g_endpointTrust.store(codeKey, false, nowMs, 120000);
            }
        }
    }

    if (noPath) {
        RegisterEndpointBackoff(descriptor.endpoint, GetTickCount());
    } else {
        ClearEndpointBackoff(descriptor.endpoint);
    }

    return outcome;
}

static bool TrySendViaSocket(const void* bytes, int len, const char* tag, SOCKET preferredSocket)
{
    SOCKET sock = preferredSocket;
    if (sock == INVALID_SOCKET)
        sock = Net::GetLastSocket();
    if (sock == INVALID_SOCKET)
        return false;

    int rc = send(sock, reinterpret_cast<const char*>(bytes), len, 0);
    if (rc == len) {
        static volatile LONG s_socketSuccessLogBudget = 32;
        if (tag && s_socketSuccessLogBudget > 0 && InterlockedDecrement(&s_socketSuccessLogBudget) >= 0) {
            char status[200];
            sprintf_s(status, sizeof(status),
                      "%s succeeded len=%d socket=%p",
                      tag,
                      len,
                      reinterpret_cast<void*>(static_cast<uintptr_t>(sock)));
            WriteRawLog(status);
        }
        return true;
    }

    int err = WSAGetLastError();
    if (err == WSAENOTCONN || err == WSAENOTSOCK)
        Net::InvalidateLastSocket();

    char warn[200];
    sprintf_s(warn, sizeof(warn),
              "%s failed len=%d rc=%d err=%d socket=%p",
              tag ? tag : "SendPacketRaw socket fallback",
              len,
              rc,
              err,
              reinterpret_cast<void*>(static_cast<uintptr_t>(sock)));
    WriteRawLog(warn);
    return false;
}

static int SendPacketExceptionFilter(unsigned code, EXCEPTION_POINTERS* info)
{
    void* exceptionAddress = (info && info->ExceptionRecord) ? info->ExceptionRecord->ExceptionAddress : nullptr;
    char buf[256];
    sprintf_s(buf, sizeof(buf),
              "SendPacketRaw exception code=%08X addr=%p sendCtx=%p vtbl=%p entry=%p exec=%d sendFn=%p target=%p len=%d",
              code,
              exceptionAddress,
              g_lastSendAttempt.sendCtx,
              g_lastSendAttempt.vtbl,
              g_lastSendAttempt.vtblFirstEntry,
              g_lastSendAttempt.vtblEntryExecutable ? 1 : 0,
              g_lastSendAttempt.sendPacketFn,
              g_lastSendAttempt.sendPacketTarget,
              g_lastSendAttempt.payloadLen);
    WriteRawLog(buf);

    if (g_lastSendAttempt.payload && g_lastSendAttempt.payloadLen > 0) {
        const unsigned char* bytes = static_cast<const unsigned char*>(g_lastSendAttempt.payload);
        int dumpLen = g_lastSendAttempt.payloadLen < 16 ? g_lastSendAttempt.payloadLen : 16;
        char dump[3 * 16 + 1] = {};
        char* out = dump;
        for (int i = 0; i < dumpLen; ++i) {
            sprintf_s(out, 4, "%02X ", bytes[i]);
            out += 3;
        }
        char dumpMsg[128];
        sprintf_s(dumpMsg, sizeof(dumpMsg), "SendPacketRaw payload prefix: %s", dump);
        WriteRawLog(dumpMsg);
    }

    return EXCEPTION_EXECUTE_HANDLER;
}

static void TryHookSendBuilder(void* endpoint);
static bool TryAttachTrustedEndpoint(const ManagerTarget& target,
                                     void* manager,
                                     uintptr_t observedVtbl,
                                     std::uint64_t passId,
                                     Scanner::ScanPassTelemetry& telemetry)
{
    if (!manager || observedVtbl == 0 || g_sendBuilderHooked || g_builderScanned)
        return g_builderScanned;

    LARGE_INTEGER nowLi{};
    QueryPerformanceCounter(&nowLi);
    const std::uint64_t nowQpc = static_cast<std::uint64_t>(nowLi.QuadPart);

    auto& trustedCache = Core::GetTrustedEndpointCache();
    trustedCache.Purge(nowQpc);

    constexpr int kMaxTrustedSlots = 32;
    void* const* vtbl = reinterpret_cast<void* const*>(observedVtbl);

    Core::TrustedEndpoint cached{};
    if (!trustedCache.TryGetValid(observedVtbl, cached, nowQpc))
        return false;
    if (cached.slot >= static_cast<std::uint32_t>(kMaxTrustedSlots))
        return false;

    void* entry = nullptr;
    if (!SafeCopy(&entry, vtbl + cached.slot, sizeof(entry)) || !entry)
        return false;

    if (reinterpret_cast<std::uintptr_t>(entry) != cached.entry) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[SB][CACHE] miss vtbl=%p slot=%u entry=%p cached=%p",
                  reinterpret_cast<void*>(observedVtbl),
                  cached.slot,
                  entry,
                  reinterpret_cast<void*>(cached.entry));
        return false;
    }

    std::uint64_t ttlMs = 0;
    const std::uint64_t freq = Core::TrustedEndpointCache::QpcFrequency();
    if (cached.expires_qpc > nowQpc && freq != 0)
        ttlMs = ((cached.expires_qpc - nowQpc) * 1000ull) / freq;

    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[SB][CACHE] hit vtbl=%p slot=%u entry=%p hits=%u",
              reinterpret_cast<void*>(observedVtbl),
              cached.slot,
              entry,
              cached.hits);

    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[CORE][SB] using trusted endpoint vtbl=%p slot=%u entry=%p ttl=%llu ms",
              reinterpret_cast<void*>(observedVtbl),
              cached.slot,
              entry,
              static_cast<unsigned long long>(ttlMs));

    t_ringHitsForAttach = cached.hits;
    bool attached = AttachSendBuilderFromTrace(entry,
                                               static_cast<uint8_t>(cached.slot & 0xFF),
                                               reinterpret_cast<void*>(observedVtbl),
                                               nullptr,
                                               "trusted-cache",
                                               reinterpret_cast<const uint8_t*>(entry));
    t_ringHitsForAttach = 0;

    if (!attached)
        return false;

    const auto refreshed = trustedCache.InsertOrBump(observedVtbl,
                                                     cached.slot,
                                                     cached.entry,
                                                     kTrustedEndpointTtlMs);
    Log::Logf(Log::Level::Debug,
              Log::Category::Core,
              "[SB][CACHE] refresh vtbl=%p slot=%u hits=%u",
              reinterpret_cast<void*>(observedVtbl),
              refreshed.slot,
              refreshed.hits);

    g_builderScanned = g_sendBuilderHooked;
    telemetry = {};
    telemetry.id = passId;
    telemetry.candidates_considered = 1;
    telemetry.accepted = 1;
    telemetry.send_samples = 0;
    telemetry.ring_load_pct = g_lastRingLoad.load(std::memory_order_relaxed);
    telemetry.rej_cache_size = static_cast<std::uint32_t>(Core::GetRejectCache().size());

    return true;
}
static Stage3PivotResult TryDiscoverEndpointFromManager(const ManagerTarget& target,
                                                        const std::string& preconditions,
                                                        std::uint64_t passId);
static bool TryDiscoverFromEngineContext();

static void FormatDiscoverySlotInfo(char* dest,
                                    size_t destSize,
                                    size_t offsetValue,
                                    void* pointerValue,
                                    size_t invalidOffset)
{
    if (offsetValue == invalidOffset || !pointerValue)
        strcpy_s(dest, destSize, "n/a");
    else
        sprintf_s(dest, destSize, "%p@+0x%02zx", pointerValue, offsetValue);
}

static bool IsExecutableSendContext(void* candidate, void** outVtbl, void** outEntry0)
{
    if (!candidate)
        return false;

    void* vtbl = nullptr;
    if (!SafeCopy(&vtbl, candidate, sizeof(vtbl)) || !vtbl)
        return false;

    void* entry0 = nullptr;
    if (!SafeCopy(&entry0, vtbl, sizeof(entry0)))
        return false;

    if (outVtbl)
        *outVtbl = vtbl;
    if (outEntry0)
        *outEntry0 = entry0;
    return IsExecutableCodeAddress(entry0);
}

static void CaptureSendContext(void* candidate, const char* sourceTag)
{
    if (!candidate)
        return;
    if (!sourceTag)
        sourceTag = "?";

    void* vtbl = nullptr;
    void* entry0 = nullptr;
    bool exec = IsExecutableSendContext(candidate, &vtbl, &entry0);
    if (!exec) {
        static volatile LONG s_skipLogBudget = 16;
        if (s_skipLogBudget > 0 && InterlockedDecrement(&s_skipLogBudget) >= 0) {
            char warn[192];
            sprintf_s(warn, sizeof(warn),
                      "SendCtx skip via %s candidate=%p vtbl=%p entry0=%p",
                      sourceTag,
                      candidate,
                      vtbl,
                      entry0);
            WriteRawLog(warn);
        }
        return;
    }

    if (g_sendCtx == candidate)
        return;

    if (g_sendCtx) {
        void* existingVtbl = nullptr;
        void* existingEntry0 = nullptr;
        bool existingExec = IsExecutableSendContext(g_sendCtx, &existingVtbl, &existingEntry0);
        if (!existingExec) {
            g_sendCtx = nullptr;
        } else if (existingExec && existingVtbl == vtbl && existingEntry0 == entry0) {
            return;
        }
    }

    char buf[160];
    if (!g_sendCtx) {
        sprintf_s(buf, sizeof(buf), "SendCtx captured via %s = %p", sourceTag, candidate);
    } else {
        sprintf_s(buf, sizeof(buf), "SendCtx pointer updated via %s %p -> %p", sourceTag, g_sendCtx, candidate);
    }
    WriteRawLog(buf);
    g_sendCtx = candidate;
    MaybeSendDebugNudge();
}

static void MaybeSendDebugNudge()
{
    if (!g_sbDebugNudge.load(std::memory_order_acquire))
        return;
    if (g_debugNudgeSent.load(std::memory_order_acquire))
        return;
    if (!g_debugNudgePending.load(std::memory_order_acquire))
        return;
    if (!g_sendPacketHooked || !g_sendPacketTarget)
        return;

    void* ctx = g_sendCtx ? g_sendCtx : g_netMgr;
    if (!ctx)
        return;

    SendPacket_t target = reinterpret_cast<SendPacket_t>(g_sendPacketTarget);
    if (!target)
        return;

    if (t_debugNudgeCall)
        return;

    static const std::uint8_t kDebugNudgePacket[] = {0x73, 0x00, 0x00, 0x00};

    t_debugNudgeCall = true;
    bool success = false;
    __try {
        target(ctx, kDebugNudgePacket, static_cast<int>(sizeof(kDebugNudgePacket)));
        success = true;
    } __finally {
        t_debugNudgeCall = false;
    }

    if (success) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Core,
                  "[CORE][SB] debug nudge triggered");
        g_debugNudgeSent.store(true, std::memory_order_release);
        g_debugNudgePending.store(false, std::memory_order_release);
    }
}

static Stage3PivotResult TryDiscoverEndpointFromManager(const ManagerTarget& target,
                                                        const std::string& preconditions,
                                                        std::uint64_t passId)
{
    Stage3PivotResult result{};
    result.telemetry.id = passId;

    Scanner::ScanPassTelemetry telemetry{};
    telemetry.id = passId;
    g_lastPassCandidateCount = 0;
    g_lastPassSampleHits = 0;

    if (g_builderScanned)
        return result;
    if (target.owner == 0 || target.vtbl == 0)
        return result;

    void* manager = reinterpret_cast<void*>(target.owner);
    void* observedVtblPtr = nullptr;
    if (!ValidateManagerPointer(manager, &observedVtblPtr)) {
        LogGuardInvalidManager(manager);
        return result;
    }

    const uintptr_t observedVtbl = reinterpret_cast<uintptr_t>(observedVtblPtr);
    if (observedVtbl != target.vtbl) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Core,
                  "[CORE][SB] manager vtbl mismatch kind=%s expected=%p actual=%p owner=%p",
                  ManagerKindName(target.kind),
                  reinterpret_cast<void*>(target.vtbl),
                  observedVtblPtr,
                  manager);
        return result;
    }

    if (!IsInModuleRdata(observedVtbl))
        return result;

    if (!IsEngineStableForScanning())
        return result;

    result.ready = true;

    if (TryAttachTrustedEndpoint(target, manager, observedVtbl, passId, telemetry)) {
        if (g_firstScanTickMs64 == 0)
            g_firstScanTickMs64 = GetTickCount64();

        g_tuner.applyTelemetry(telemetry);

        result.ready = true;
        result.trustHit = true;
        result.accepted = true;
        result.telemetry = telemetry;
        return result;
    }

    if (g_requireSendSample.load(std::memory_order_relaxed)) {
        const std::uint32_t pendingSamples = static_cast<std::uint32_t>(g_sendRing.size());
        if (pendingSamples == 0) {
            const std::uint32_t baseDelay = std::max(1u, g_tuner.stepDelayMs());
            const std::uint32_t deferDelay = baseDelay * 10u;
            Log::Logf(Log::Level::Debug,
                      Log::Category::Core,
                      "[SB] no send samples, deferring scan delay=%ums",
                      deferDelay);
            result.deferred = true;
            result.deferDelayMs = deferDelay;
            result.telemetry = telemetry;
            return result;
        }
    }

    constexpr size_t kScanLimit = kEndpointScanWindow;
    DWORD now = GetTickCount();
    DWORD dynamicDelay = std::max<DWORD>(kManagerScanCooldownMs, g_tuner.stepDelayMs());
    if (g_lastBuilderScanTick != 0 &&
        (DWORD)(now - g_lastBuilderScanTick) < dynamicDelay)
        return result;

    if (manager == g_lastManagerScanPtr && (DWORD)(now - g_lastManagerScanTick) < 1000)
        return result;

    if (!SafeMem::IsReadable(manager, kScanLimit + sizeof(void*))) {
        LogGuardInvalidManager(manager);
        return result;
    }

    g_lastBuilderScanTick = now;
    g_lastManagerScanPtr = manager;
    g_lastManagerScanTick = now;

    const char* mgrName = ManagerKindName(target.kind);
    char startBuf[192];
    sprintf_s(startBuf, sizeof(startBuf),
              "DiscoverEndpoint: scan begin manager=%p kind=%s vtbl=%p (.rdata) window=0x%zx depth=%d",
              manager,
              mgrName,
              reinterpret_cast<void*>(observedVtbl),
              kScanLimit,
              kTailFollowMaxDepth);
    WriteRawLog(startBuf);
    auto& rejectCache = Core::GetRejectCache();
    LARGE_INTEGER cacheSweepLi{};
    QueryPerformanceCounter(&cacheSweepLi);
    rejectCache.sweep(static_cast<std::uint64_t>(cacheSweepLi.QuadPart));

    std::vector<Core::SendRing::Entry> ringSamples;
    const std::size_t ringOccupancy = g_sendRing.size();
    const std::size_t newRingSamples = g_sendRing.snapshot(ringSamples,
                                                           static_cast<std::uint64_t>(kRingSnapshotAgeMs) * 1000ull);
    const std::uint32_t ringLoadPct = g_sendRing.load_percent();
    g_lastRingLoad.store(ringLoadPct, std::memory_order_relaxed);

    if (Log::IsEnabled(Log::Level::Debug)) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Core,
                  "[SB][RING] snapshot count=%llu new=%llu age<=%ums load=%u%%",
                  static_cast<unsigned long long>(ringOccupancy),
                  static_cast<unsigned long long>(newRingSamples),
                  static_cast<unsigned>(kRingSnapshotAgeMs),
                  ringLoadPct);
    }

    auto stackSamples = Scanner::Sampler::drain();

    std::vector<CandidateRaw> rawCandidates;
    rawCandidates.reserve(SB_PASS_MAX_CANDIDATES);
    std::unordered_set<void*> seenCandidates;
    seenCandidates.reserve(SB_PASS_MAX_CANDIDATES);

    const size_t kInvalidOffset = std::numeric_limits<size_t>::max();
    size_t slotsExamined = 0;
    size_t firstCandidateOffset = kInvalidOffset;
    void* firstCandidateValue = nullptr;
    size_t firstCommittedOffset = kInvalidOffset;
    void* firstCommittedValue = nullptr;
    size_t firstGameOffset = kInvalidOffset;
    void* firstGameValue = nullptr;
    void* firstGameVtable = nullptr;
    size_t firstNonGameOffset = kInvalidOffset;
    void* firstNonGameValue = nullptr;
    void* firstNonGameVtable = nullptr;
    size_t firstExecOffset = kInvalidOffset;
    void* firstExecValue = nullptr;
    void* firstExecEntry = nullptr;
    size_t firstNonExecOffset = kInvalidOffset;
    void* firstNonExecValue = nullptr;
    void* firstNonExecEntry = nullptr;

    for (size_t offset = 0; offset <= kScanLimit; offset += sizeof(void*)) {
        ++slotsExamined;
        const int slotIndex = static_cast<int>(offset / sizeof(void*));
        void* slotPtr = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(manager) + offset);
        LARGE_INTEGER iterLi{};
        QueryPerformanceCounter(&iterLi);
        const std::uint64_t iterNowQpc = static_cast<std::uint64_t>(iterLi.QuadPart);
        if (rejectCache.is_hot(slotPtr, iterNowQpc)) {
            ++telemetry.rej_cache_hits;
            ++telemetry.rejected_skipped;
            continue;
        }
        void* candidate = nullptr;
        if (!SafeCopy(&candidate, reinterpret_cast<const uint8_t*>(manager) + offset, sizeof(candidate)))
            continue;
        if (!candidate || candidate == manager)
            continue;

        if (firstCandidateOffset == kInvalidOffset) {
            firstCandidateOffset = offset;
            firstCandidateValue = candidate;
        }

        MEMORY_BASIC_INFORMATION mbiCandidate{};
        if (!VirtualQuery(candidate, &mbiCandidate, sizeof(mbiCandidate)))
            continue;
        if (mbiCandidate.State != MEM_COMMIT || (mbiCandidate.Protect & PAGE_GUARD))
            continue;

        if (firstCommittedOffset == kInvalidOffset) {
            firstCommittedOffset = offset;
            firstCommittedValue = candidate;
        }

        void* vtbl = nullptr;
        if (!SafeCopy(&vtbl, candidate, sizeof(vtbl)) || !vtbl)
            continue;
        bool inRdata = false;
        if (!IsGameVtableAddress(vtbl, &inRdata)) {
            if (firstNonGameOffset == kInvalidOffset) {
                firstNonGameOffset = offset;
                firstNonGameValue = candidate;
                firstNonGameVtable = vtbl;
                if (!inRdata) {
                    Log::Logf(Log::Level::Debug,
                              Log::Category::Core,
                              "[CORE][SB] candidate=%p rejected reason=rdata-miss vtbl=%p offset=0x%zX",
                              candidate,
                              vtbl,
                              offset);
                }
            }
            LogRejectTtl(reinterpret_cast<std::uintptr_t>(vtbl), slotIndex, kRejectReasonNonGame);
            rejectCache.reject(slotPtr, kRejectReasonNonGame);
            ++telemetry.rej_cache_inserted;
            continue;
        }

        if (firstGameOffset == kInvalidOffset) {
            firstGameOffset = offset;
            firstGameValue = candidate;
            firstGameVtable = vtbl;
        }

        void* firstEntry = nullptr;
        if (!SafeCopy(&firstEntry, vtbl, sizeof(firstEntry)))
            continue;
        if (!IsExecutableCodeAddress(firstEntry)) {
            if (firstNonExecOffset == kInvalidOffset) {
                firstNonExecOffset = offset;
                firstNonExecValue = candidate;
                firstNonExecEntry = firstEntry;
            }
            LogRejectTtl(reinterpret_cast<std::uintptr_t>(vtbl), slotIndex, kRejectReasonNotExec);
            rejectCache.reject(slotPtr, kRejectReasonNotExec);
            ++telemetry.rej_cache_inserted;
            continue;
        }

        if (firstExecOffset == kInvalidOffset) {
            firstExecOffset = offset;
            firstExecValue = candidate;
            firstExecEntry = firstEntry;
        }

        if (seenCandidates.insert(candidate).second) {
            rawCandidates.push_back({candidate, manager, vtbl, offset});
            if (rawCandidates.size() >= SB_PASS_MAX_CANDIDATES)
                break;
        }
    }

    g_lastPassCandidateCount = rawCandidates.size();
    telemetry.rej_cache_size = static_cast<std::uint32_t>(rejectCache.size());

    char candidateInfo[64];
    char committedInfo[64];
    char gameInfo[64];
    char execInfo[64];
    char nonExecInfo[64];
    char nonGameInfo[64];
    FormatDiscoverySlotInfo(candidateInfo, sizeof(candidateInfo), firstCandidateOffset, firstCandidateValue, kInvalidOffset);
    FormatDiscoverySlotInfo(committedInfo, sizeof(committedInfo), firstCommittedOffset, firstCommittedValue, kInvalidOffset);
    FormatDiscoverySlotInfo(gameInfo, sizeof(gameInfo), firstGameOffset, firstGameValue, kInvalidOffset);
    FormatDiscoverySlotInfo(execInfo, sizeof(execInfo), firstExecOffset, firstExecValue, kInvalidOffset);
    FormatDiscoverySlotInfo(nonExecInfo, sizeof(nonExecInfo), firstNonExecOffset, firstNonExecValue, kInvalidOffset);
    FormatDiscoverySlotInfo(nonGameInfo, sizeof(nonGameInfo), firstNonGameOffset, firstNonGameValue, kInvalidOffset);

    char summary[360];
    sprintf_s(summary, sizeof(summary),
              "DiscoverEndpoint: scan complete manager=%p kind=%s slots=%zu candidates=%zu firstCandidate=%s firstCommitted=%s firstGame=%s(vtbl=%p) firstExecutable=%s(entry=%p) sendSamples=%u ringLoad=%u",
              manager,
              mgrName,
              slotsExamined,
              rawCandidates.size(),
              candidateInfo,
              committedInfo,
              gameInfo,
              firstGameVtable,
              execInfo,
              firstExecEntry,
              static_cast<unsigned>(newRingSamples),
              ringLoadPct);
    WriteRawLog(summary);

    bool attached = RunCandidatePass(rawCandidates,
                                     stackSamples,
                                     ringSamples,
                                     static_cast<std::uint32_t>(newRingSamples),
                                     ringLoadPct,
                                     passId,
                                     telemetry,
                                     target,
                                     preconditions);
    g_lastPassSampleHits = telemetry.sample_hits;

    result.scanned = true;
    result.telemetry = telemetry;
    result.accepted = attached || telemetry.accepted > 0;

    if (attached) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[CORE][SB] manager scan attached endpoint (candidates=%zu)",
                  rawCandidates.size());
        return result;
    }

    if (firstNonGameValue || firstNonExecValue) {
        char reason[256];
        sprintf_s(reason, sizeof(reason),
                  "DiscoverEndpoint: rejection details nonGame=%s vtbl=%p nonExec=%s entry=%p lastEndpoint=%p",
                  nonGameInfo,
                  firstNonGameVtable,
                  nonExecInfo,
                  firstNonExecEntry,
                  g_lastLoggedEndpoint);
        WriteRawLog(reason);
    }

    g_lastBuilderScanTick = GetTickCount();
    return result;
}

static void ExecuteManagerScanSequence()
{
    if (g_builderScanned)
        return;

    const GlobalStateInfo* state = g_state;
    if (!EnsureManagerSelection(state))
        return;

    DWORD nowTick = GetTickCount();
    auto passIdOpt = g_stage3Controller.beginPass(nowTick);
    if (!passIdOpt)
        return;

    Stage3PassSummary summary{};
    summary.passId = *passIdOpt;
    summary.telemetry.id = summary.passId;
    summary.pivot = Stage3Pivot::Engine;

    LARGE_INTEGER passStart{};
    QueryPerformanceCounter(&passStart);

    ManagerTarget primary = g_managerTarget;

    void* netCfgPtr = GetTrackedConfigPtr();
    MEMORY_BASIC_INFORMATION cfgInfo{};
    bool netReadable = netCfgPtr && IsReadableMemory(netCfgPtr, sizeof(void*), &cfgInfo);
    if (!netCfgPtr)
        cfgInfo = {};
    std::string preconditions = BuildPreconditionsString(netReadable);

    if (!netReadable) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[CORE][SB] networkConfig not-readable; deferring scan (state=0x%08lX protect=0x%08lX)",
                  static_cast<unsigned long>(cfgInfo.State),
                  static_cast<unsigned long>(cfgInfo.Protect));
        g_stage3Controller.defer(nowTick, SB_BACKOFF_MS_INITIAL, false);
        return;
    }

    std::uint64_t nowMs = GetTickCount64();
    if (IsVtblSuppressed(primary.vtbl, nowMs)) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[CORE][SB] vtbl unchanged: skipping redundant scan (ttl active)");
        g_stage3Controller.defer(nowTick, SB_BACKOFF_MS_INITIAL, false);
        return;
    }

    LogPivotAttempt(primary);

    Stage3PivotResult engineResult = TryDiscoverEndpointFromManager(primary, preconditions, summary.passId);
    if (engineResult.deferred) {
        g_stage3Controller.defer(nowTick, engineResult.deferDelayMs, false);
        return;
    }

    bool engineCandidatesZero = (g_lastPassCandidateCount == 0);
    bool engineSampleHit = (engineResult.telemetry.sample_hits > 0) || (engineResult.telemetry.accepted > 0);

    if (engineResult.accepted || engineResult.trustHit || engineSampleHit)
        ClearVtblSuppression(primary.vtbl);
    else if (engineResult.ready && engineCandidatesZero)
        SuppressVtbl(primary.vtbl, nowMs);

    Stage3PivotResult finalResult = engineResult;
    Stage3Pivot pivotUsed = Stage3Pivot::Engine;

    if (!engineResult.accepted && !engineResult.trustHit && g_allowDbProbe) {
        ManagerTarget dbTarget{};
        if (BuildManagerTarget(ManagerKind::Database, state, dbTarget) && dbTarget.vtbl != 0 && dbTarget.owner != 0) {
            Log::Logf(Log::Level::Info,
                      Log::Category::Core,
                      "[CORE][SB] fallback to dbMgr vtbl=%p (engine yielded no accept)",
                      reinterpret_cast<void*>(dbTarget.vtbl));
            if (!IsVtblSuppressed(dbTarget.vtbl, nowMs)) {
                LogPivotAttempt(dbTarget);
                Stage3PivotResult dbResult = TryDiscoverEndpointFromManager(dbTarget, preconditions, summary.passId);
                if (dbResult.deferred) {
                    g_stage3Controller.defer(nowTick, dbResult.deferDelayMs, false);
                    return;
                }
                if (dbResult.ready) {
                    pivotUsed = Stage3Pivot::Database;
                    finalResult = dbResult;
                    bool dbCandidatesZero = (g_lastPassCandidateCount == 0);
                    bool dbSampleHit = (dbResult.telemetry.sample_hits > 0) || (dbResult.telemetry.accepted > 0);

                    if (dbResult.accepted || dbResult.trustHit || dbSampleHit)
                        ClearVtblSuppression(dbTarget.vtbl);
                    else if (dbCandidatesZero)
                        SuppressVtbl(dbTarget.vtbl, nowMs);
                }
            } else {
                Log::Logf(Log::Level::Info,
                          Log::Category::Core,
                          "[CORE][SB] dbMgr vtbl suppressed; skipping pivot");
            }
        }
    }

    LARGE_INTEGER passEnd{};
    QueryPerformanceCounter(&passEnd);
    std::uint32_t ttfsMs = 0;
    const std::uint64_t freq = Core::TrustedEndpointCache::QpcFrequency();
    if (freq != 0) {
        const std::uint64_t delta = static_cast<std::uint64_t>(passEnd.QuadPart - passStart.QuadPart);
        ttfsMs = static_cast<std::uint32_t>((delta * 1000ull) / freq);
    }
    summary.ttfsMs = ttfsMs;
    summary.pivot = pivotUsed;
    summary.executed = finalResult.ready || finalResult.trustHit;
    summary.trustHit = finalResult.trustHit;
    summary.accepted = finalResult.accepted;
    summary.telemetry = finalResult.telemetry;
    summary.telemetry.id = summary.passId;
    if (!summary.executed)
        summary.pivot = Stage3Pivot::None;

    summary.nextBackoffMs = g_stage3Controller.completePass(summary, nowTick);
    summary.telemetry.backoff_ms = summary.nextBackoffMs;

    {
        std::lock_guard<std::mutex> lock(g_lastTelemetryMutex);
        g_lastTelemetry = summary.telemetry;
    }

    const char* pivotLabel = "none";
    switch (summary.pivot) {
    case Stage3Pivot::Engine:
        pivotLabel = "engine";
        break;
    case Stage3Pivot::Database:
        pivotLabel = "db";
        break;
    default:
        pivotLabel = "none";
        break;
    }

    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[CORE][SB][PASS] ttfs_ms=%u pivot=%s candidates=%u accepted=%u rejected=%u rej_cache_hits=%u send_samples=%u sample_hits=%u next_backoff_ms=%u",
              summary.ttfsMs,
              pivotLabel,
              summary.telemetry.candidates_considered,
              summary.telemetry.accepted,
              summary.telemetry.rejected,
              summary.telemetry.rej_cache_hits,
              summary.telemetry.send_samples,
              summary.telemetry.sample_hits,
              summary.nextBackoffMs);

    if (summary.trustHit) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[CORE][SB][PASS] trust: hit pivot=%s",
                  pivotLabel);
    }
}

static bool TryDiscoverFromEngineContext()
{
    if (g_builderScanned || !g_state)
        return false;

    void* engineCtx = g_state->engineContext;
    if (!engineCtx)
        return false;

    void* netCfgPtr = GetTrackedConfigPtr();
    MEMORY_BASIC_INFORMATION cfgInfo{};
    bool netReadable = netCfgPtr && IsReadableMemory(netCfgPtr, sizeof(void*), &cfgInfo);
    std::string preconditions = BuildPreconditionsString(netReadable);
    if (!netReadable)
        return false;

    DWORD now = GetTickCount();
    if (engineCtx == g_lastEngineCtxScanPtr && (DWORD)(now - g_lastEngineCtxScanTick) < 1000)
        return false;
    g_lastEngineCtxScanPtr = engineCtx;
    g_lastEngineCtxScanTick = now;

    const size_t kScanLimit = kEndpointScanWindow;
    char startBuf[160];
    sprintf_s(startBuf, sizeof(startBuf),
              "EngineCtx scan begin ctx=%p window=0x%zx depth=%d",
              engineCtx,
              kScanLimit,
              kTailFollowMaxDepth);
    WriteRawLog(startBuf);

    size_t scanned = 0;
    size_t attempted = 0;
    const uint8_t* base = reinterpret_cast<const uint8_t*>(engineCtx);
    for (size_t offset = 0; offset <= kScanLimit && !g_builderScanned; offset += sizeof(void*))
    {
        void* candidate = nullptr;
        if (!SafeCopy(&candidate, base + offset, sizeof(candidate)))
            continue;
        if (!candidate)
            continue;
        ++scanned;

        void* targetVtbl = nullptr;
        if (!SafeCopy(&targetVtbl, candidate, sizeof(targetVtbl)) || !targetVtbl)
            continue;
        uintptr_t vtblAddr = reinterpret_cast<uintptr_t>(targetVtbl);
        if (!IsInModuleRdata(vtblAddr))
            continue;

        ManagerTarget temp{};
        temp.kind = ManagerKind::Engine;
        temp.owner = reinterpret_cast<uintptr_t>(candidate);
        temp.vtbl = vtblAddr;

        Stage3PivotResult pivotResult = TryDiscoverEndpointFromManager(temp, preconditions, 0);
        if (pivotResult.accepted) {
            g_managerTarget = temp;
            g_managerTargetValid = true;
            g_netMgr = candidate;
            char successBuf[160];
            sprintf_s(successBuf, sizeof(successBuf),
                      "EngineCtx scan success manager=%p offset=0x%02zx",
                      candidate,
                      offset);
            WriteRawLog(successBuf);
            return true;
        }
        ++attempted;
    }

    char summary[160];
    sprintf_s(summary, sizeof(summary),
              "EngineCtx scan complete ctx=%p entries=%zu attempts=%zu builderScanned=%d",
              engineCtx,
              scanned,
              attempted,
              g_builderScanned ? 1 : 0);
    WriteRawLog(summary);
    return false;
}

static void CaptureNetManager(void* candidate, const char* sourceTag)
{
    if (!candidate)
        return;
    if (!sourceTag)
        sourceTag = "?";

    if (!g_netMgr) {
        g_netMgr = candidate;
        char buf[128];
        sprintf_s(buf, sizeof(buf), "NetMgr captured via %s = %p", sourceTag, g_netMgr);
        WriteRawLog(buf);
        g_lastManagerScanPtr = nullptr;
        g_lastManagerScanTick = 0;
        g_lastLoggedEndpoint = nullptr;
    } else if (g_netMgr != candidate) {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "NetMgr pointer updated via %s %p -> %p", sourceTag, g_netMgr, candidate);
        WriteRawLog(buf);
        g_netMgr = candidate;
        g_lastManagerScanPtr = nullptr;
        g_lastManagerScanTick = 0;
        g_lastLoggedEndpoint = nullptr;
    }

    EnsureManagerSelection(g_state);
    ExecuteManagerScanSequence();
}

static bool CallsSendPacket(uint8_t* fn, size_t maxScan, uintptr_t send, uint8_t* offsetOut) {
    if (!fn || !send || maxScan < 5)
        return false;

    __try {
        for (size_t i = 0; i + 5 <= maxScan; ++i) {
            uint8_t op = fn[i];
            if (op == 0xE8 || op == 0xE9) {
                int32_t rel = *reinterpret_cast<int32_t*>(fn + i + 1);
                uintptr_t tgt = reinterpret_cast<uintptr_t>(fn + i + 5) + rel;
                if (tgt == send) {
                    if (offsetOut)
                        *offsetOut = static_cast<uint8_t>(i);
                    return true;
                }
            }
            if (op == 0xFF && (i + 6) <= maxScan && fn[i + 1] == 0x25) {
                uintptr_t ptr = *reinterpret_cast<uintptr_t*>(fn + i + 2);
                uintptr_t tgt = *reinterpret_cast<uintptr_t*>(reinterpret_cast<void*>(ptr));
                if (tgt == send) {
                    if (offsetOut)
                        *offsetOut = static_cast<uint8_t>(i);
                    return true;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* ignore */
    }
    return false;
}

static bool CallsSendPacket(uint8_t* fn, size_t maxScan, uintptr_t send) {
    return CallsSendPacket(fn, maxScan, send, nullptr);
}

static bool FunctionCallsSendPacket(void* fn)
{
    return CallsSendPacket(reinterpret_cast<uint8_t*>(fn),
                           0x80,
                           reinterpret_cast<uintptr_t>(g_sendPacketTarget));
}

static bool IsExecutablePtr(const void* p)
{
    if (!p)
        return false;

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(p, &mbi, sizeof(mbi)))
        return false;

    if (mbi.State != MEM_COMMIT)
        return false;

    const DWORD execFlags = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if ((mbi.Protect & execFlags) == 0)
        return false;

    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
        return false;

    return true;
}

template<typename T>
static bool TryLoad(const void* p, T& out)
{
    if (!p)
        return false;

    __try
    {
        out = *reinterpret_cast<const T*>(p);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool TryResolveSendPacket(uint8_t* candidate, uint8_t*& resolved)
{
    resolved = nullptr;
    if (!candidate)
        return false;

    constexpr uintptr_t kExpectedSendPacketAddr = 0x0082FB60;
    uint8_t* expected = reinterpret_cast<uint8_t*>(kExpectedSendPacketAddr);

    uint8_t* target = reinterpret_cast<uint8_t*>(g_sendPacketTarget);
    uint8_t* original = reinterpret_cast<uint8_t*>(g_sendPacket);

    if (candidate == expected) {
        resolved = expected;
        return true;
    }
    if (target && candidate == target) {
        resolved = target;
        return true;
    }
    if (original && candidate == original) {
        resolved = original;
        return true;
    }

    uint8_t* deref = nullptr;
    if (TryLoad(candidate, deref) && deref) {
        if (deref == expected ||
            (target && deref == target) ||
            (original && deref == original))
        {
            resolved = deref;
            return true;
        }
    }

    return false;
}

static void ResetTraceResult(TraceResult& trace)
{
    trace.site = nullptr;
    trace.offset = 0;
    trace.finalTarget = nullptr;
    trace.hopCount = 0;
    trace.slotIndex = 0xFF;
    trace.vtable = nullptr;
    for (auto& hop : trace.hops) {
        hop.pattern = nullptr;
        hop.from = nullptr;
        hop.to = nullptr;
        hop.slot = nullptr;
        hop.slotValue = nullptr;
    }
}

static bool HasVisited(uint8_t* addr, uint8_t** visited, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        if (visited[i] == addr)
            return true;
    }
    return false;
}

static bool TraceSendPacketFrom(uint8_t* fn,
                                size_t window,
                                int depthRemaining,
                                TraceResult& trace,
                                uint8_t** visited,
                                size_t& visitedCount,
                                bool isRoot);

static bool TraceHandleHop(TraceResult& trace,
                           const char* pattern,
                           uint8_t* from,
                           uint8_t* dest,
                           bool isRoot,
                           uint32_t offset,
                           int depthRemaining,
                           uint8_t** visited,
                           size_t& visitedCount,
                           uint8_t* slot,
                           uint8_t* slotValue)
{
    if (!dest || trace.hopCount >= kTailFollowMaxDepth)
        return false;

    bool siteSet = false;
    if (isRoot && trace.site == nullptr) {
        trace.site = from;
        trace.offset = offset;
        siteSet = true;
    }

    trace.hops[trace.hopCount].pattern = pattern;
    trace.hops[trace.hopCount].from = from;
    trace.hops[trace.hopCount].to = dest;
    trace.hops[trace.hopCount].slot = slot;
    trace.hops[trace.hopCount].slotValue = slotValue;
    ++trace.hopCount;

    bool matched = false;
    uint8_t* resolved = nullptr;

    if (TryResolveSendPacket(dest, resolved)) {
        trace.finalTarget = resolved;
        matched = true;
    } else {
        bool destExecutable = IsExecutablePtr(dest);
        if (destExecutable && depthRemaining > 1 && !HasVisited(dest, visited, visitedCount)) {
            matched = TraceSendPacketFrom(dest,
                                          kTailScanWindow,
                                          depthRemaining - 1,
                                          trace,
                                          visited,
                                          visitedCount,
                                          false);
        }

        if (!matched) {
            uint8_t* chained = nullptr;
            if (!destExecutable && TryLoad(dest, chained) && chained && chained != dest) {
                trace.hops[trace.hopCount - 1].slot = dest;
                trace.hops[trace.hopCount - 1].slotValue = chained;
                if (TryResolveSendPacket(chained, resolved)) {
                    trace.finalTarget = resolved;
                    matched = true;
                } else if (depthRemaining > 1 && IsExecutablePtr(chained) && !HasVisited(chained, visited, visitedCount)) {
                    matched = TraceSendPacketFrom(chained,
                                                  kTailScanWindow,
                                                  depthRemaining - 1,
                                                  trace,
                                                  visited,
                                                  visitedCount,
                                                  false);
                }
            }
        }
    }

    if (!matched) {
        if (trace.hopCount > 0)
            --trace.hopCount;
        if (siteSet) {
            trace.site = nullptr;
            trace.offset = 0;
        }
    }

    return matched;
}

static bool TraceSendPacketFrom(uint8_t* fn,
                                size_t window,
                                int depthRemaining,
                                TraceResult& trace,
                                uint8_t** visited,
                                size_t& visitedCount,
                                bool isRoot)
{
    if (!fn || depthRemaining <= 0)
        return false;
    if (!IsExecutablePtr(fn))
        return false;
    if (visitedCount >= kTailFollowMaxDepth)
        return false;
    if (HasVisited(fn, visited, visitedCount))
        return false;

    const std::uint64_t nowMs = GetTickCount64();
    const std::uintptr_t codeAddr = reinterpret_cast<std::uintptr_t>(fn);
    if (g_rejectStore.isRejectedAndActive(codeAddr, nowMs)) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Core,
                  "[SB] skip trace addr=%p reason=reject-cache",
                  fn);
        return false;
    }
    if (auto rva = ResolveRva(fn)) {
        Scanner::EndpointTrustCache::CodeKey codeKey{*rva};
        if (g_endpointTrust.shouldSkip(codeKey, nowMs)) {
            Log::Logf(Log::Level::Debug,
                      Log::Category::Core,
                      "[SB] skip trace addr=%p reason=code-cache rva=0x%X",
                      fn,
                      *rva);
            return false;
        }
    }

    visited[visitedCount++] = fn;
    bool matched = false;

    for (size_t i = 0; i < window && !matched; ++i) {
        size_t remaining = window - i;
        uint8_t* p = fn + i;
        uint8_t opcode = 0;
        if (!TryLoad(p, opcode))
            continue;

        if (opcode == 0xE8 && remaining >= 5) {
            int32_t rel = 0;
            if (!TryLoad(p + 1, rel))
                continue;
            uint8_t* dest = p + 5 + rel;
            matched = TraceHandleHop(trace,
                                     "E8",
                                     p,
                                     dest,
                                     isRoot,
                                     static_cast<uint32_t>(i),
                                     depthRemaining,
                                     visited,
                                     visitedCount,
                                     nullptr,
                                     nullptr);
            continue;
        }

        if (opcode == 0xE9 && remaining >= 5) {
            int32_t rel = 0;
            if (!TryLoad(p + 1, rel))
                continue;
            uint8_t* dest = p + 5 + rel;
            matched = TraceHandleHop(trace,
                                     "E9",
                                     p,
                                     dest,
                                     isRoot,
                                     static_cast<uint32_t>(i),
                                     depthRemaining,
                                     visited,
                                     visitedCount,
                                     nullptr,
                                     nullptr);
            continue;
        }

        if (opcode == 0xFF && remaining >= 6) {
            uint8_t modrm = 0;
            if (!TryLoad(p + 1, modrm))
                continue;
#if defined(_M_X64)
            if (modrm == 0x15) {
                int32_t disp = 0;
                if (!TryLoad(p + 2, disp))
                    goto next_opcode;
                uint8_t* slotAddr = p + 6 + disp;
                void* slot = nullptr;
                if (!TryLoad(slotAddr, slot) || !slot)
                    goto next_opcode;
                void* target = nullptr;
                if (!TryLoad(slot, target) || !target)
                    goto next_opcode;
                uint8_t* dest = reinterpret_cast<uint8_t*>(target);
                matched = TraceHandleHop(trace,
                                         "FF15",
                                         p,
                                         dest,
                                         isRoot,
                                         static_cast<uint32_t>(i),
                                         depthRemaining,
                                         visited,
                                         visitedCount,
                                         slotAddr,
                                         reinterpret_cast<uint8_t*>(target));
                continue;
            }
#else
            if (modrm == 0x15) {
                uint32_t absMem = 0;
                if (!TryLoad(p + 2, absMem))
                    goto next_opcode;
                void* slotAddr = reinterpret_cast<void*>(static_cast<uintptr_t>(absMem));
                void* slot = nullptr;
                if (!TryLoad(slotAddr, slot) || !slot)
                    goto next_opcode;
                void* target = nullptr;
                if (!TryLoad(slot, target) || !target)
                    goto next_opcode;
                uint8_t* dest = reinterpret_cast<uint8_t*>(target);
                matched = TraceHandleHop(trace,
                                         "FF15",
                                         p,
                                         dest,
                                         isRoot,
                                         static_cast<uint32_t>(i),
                                         depthRemaining,
                                         visited,
                                         visitedCount,
                                         reinterpret_cast<uint8_t*>(slotAddr),
                                         reinterpret_cast<uint8_t*>(target));
                continue;
            }
#endif
            if ((modrm & 0xF8) == 0xD0) {
#if defined(_M_X64)
                if (i >= 10) {
                    uint8_t rex = 0;
                    uint8_t movOp = 0;
                    if (!TryLoad(p - 10, rex) || (rex & 0xF0) != 0x40)
                        goto next_opcode;
                    if (!TryLoad(p - 9, movOp) || (movOp & 0xF8) != 0xB8)
                        goto next_opcode;
                    uint64_t imm = 0;
                    if (!TryLoad(p - 8, imm))
                        goto next_opcode;
                    uint8_t* dest = reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(imm));
                    matched = TraceHandleHop(trace,
                                             "MOV/CALL",
                                             p - 10,
                                             dest,
                                             isRoot,
                                             static_cast<uint32_t>(i - 10),
                                             depthRemaining,
                                             visited,
                                             visitedCount,
                                             nullptr,
                                             nullptr);
                    continue;
                }
#else
                if (i >= 5) {
                    uint8_t movOp = 0;
                    if (!TryLoad(p - 5, movOp) || (movOp & 0xF8) != 0xB8)
                        goto next_opcode;
                    uintptr_t imm = 0;
                    if (!TryLoad(p - 4, imm))
                        goto next_opcode;
                    uint8_t* dest = reinterpret_cast<uint8_t*>(imm);
                    matched = TraceHandleHop(trace,
                                             "MOV/CALL",
                                             p - 5,
                                             dest,
                                             isRoot,
                                             static_cast<uint32_t>(i - 5),
                                             depthRemaining,
                                             visited,
                                             visitedCount,
                                             nullptr,
                                             nullptr);
                    continue;
                }
#endif
            }

            if ((modrm & 0xF8) == 0xE0) {
#if defined(_M_X64)
                if (i >= 10) {
                    uint8_t rex = 0;
                    uint8_t movOp = 0;
                    if (!TryLoad(p - 10, rex) || (rex & 0xF0) != 0x40)
                        goto next_opcode;
                    if (!TryLoad(p - 9, movOp) || (movOp & 0xF8) != 0xB8)
                        goto next_opcode;
                    uint64_t imm = 0;
                    if (!TryLoad(p - 8, imm))
                        goto next_opcode;
                    uint8_t* dest = reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(imm));
                    matched = TraceHandleHop(trace,
                                             "MOV/JMP",
                                             p - 10,
                                             dest,
                                             isRoot,
                                             static_cast<uint32_t>(i - 10),
                                             depthRemaining,
                                             visited,
                                             visitedCount,
                                             nullptr,
                                             nullptr);
                    continue;
                }
#else
                if (i >= 5) {
                    uint8_t movOp = 0;
                    if (!TryLoad(p - 5, movOp) || (movOp & 0xF8) != 0xB8)
                        goto next_opcode;
                    uintptr_t imm = 0;
                    if (!TryLoad(p - 4, imm))
                        goto next_opcode;
                    uint8_t* dest = reinterpret_cast<uint8_t*>(imm);
                    matched = TraceHandleHop(trace,
                                             "MOV/JMP",
                                             p - 5,
                                             dest,
                                             isRoot,
                                             static_cast<uint32_t>(i - 5),
                                             depthRemaining,
                                             visited,
                                             visitedCount,
                                             nullptr,
                                             nullptr);
                    continue;
                }
#endif
            }

#if defined(_M_X64)
            if (modrm == 0x25) {
                int32_t disp = 0;
                if (!TryLoad(p + 2, disp))
                    goto next_opcode;
                uint8_t* slotAddr = p + 6 + disp;
                void* target = nullptr;
                if (!TryLoad(slotAddr, target) || !target)
                    goto next_opcode;
                uint8_t* dest = reinterpret_cast<uint8_t*>(target);
                matched = TraceHandleHop(trace,
                                         "FF25",
                                         p,
                                         dest,
                                         isRoot,
                                         static_cast<uint32_t>(i),
                                         depthRemaining,
                                         visited,
                                         visitedCount,
                                         slotAddr,
                                         reinterpret_cast<uint8_t*>(target));
                continue;
            }
#else
            if (modrm == 0x25) {
                uint32_t absMem = 0;
                if (!TryLoad(p + 2, absMem))
                    goto next_opcode;
                void* slotAddr = reinterpret_cast<void*>(static_cast<uintptr_t>(absMem));
                void* target = nullptr;
                if (!TryLoad(slotAddr, target) || !target)
                    goto next_opcode;
                uint8_t* dest = reinterpret_cast<uint8_t*>(target);
                matched = TraceHandleHop(trace,
                                         "FF25",
                                         p,
                                         dest,
                                         isRoot,
                                         static_cast<uint32_t>(i),
                                         depthRemaining,
                                         visited,
                                         visitedCount,
                                         reinterpret_cast<uint8_t*>(slotAddr),
                                         reinterpret_cast<uint8_t*>(target));
                continue;
            }
#endif
        }

        if (opcode == 0x68 && remaining >= 10) {
            uint8_t nextOp = 0;
            if (!TryLoad(p + 5, nextOp) || nextOp != 0xE9)
                continue;
            int32_t rel = 0;
            if (!TryLoad(p + 6, rel))
                continue;
            uint8_t* dest = p + 10 + rel;
            matched = TraceHandleHop(trace,
                                     "PUSH/JMP",
                                     p,
                                     dest,
                                     isRoot,
                                     static_cast<uint32_t>(i),
                                     depthRemaining,
                                     visited,
                                     visitedCount,
                                     nullptr,
                                     nullptr);
            continue;
        }

next_opcode:
        (void)0;
    }

    if (visitedCount > 0)
        --visitedCount;
    return matched;
}

static bool TraceSendPacketUse(uint8_t* fn, TraceResult& trace, uint8_t slotIndex, void* vtable)
{
    if (!fn)
        return false;

    uint8_t* visited[kTailFollowMaxDepth] = {};
    size_t visitedCount = 0;
    trace = {};
    trace.slotIndex = slotIndex;
    trace.vtable = vtable;
    return TraceSendPacketFrom(fn,
                               kEndpointScanWindow,
                               kTailFollowMaxDepth,
                               trace,
                               visited,
                               visitedCount,
                               true);
}

// Note: second (__fastcall) parameter is required to consume the register slot when
// detouring a __thiscall target. Do not remove it or the caller stack will misalign.
static void* __fastcall Hook_SendBuilder(void* thisPtr, void* /*unused*/, void* builder)
{
    uint8_t* plainPtr = nullptr;
    int len = 0;
    if (!SafeCopy(&plainPtr, builder, sizeof(plainPtr)) ||
        !SafeCopy(&len, reinterpret_cast<uint8_t*>(builder) + 4, sizeof(len)) ||
        len < 0 || len > 0x1000)
    {
        WriteRawLog("Hook_SendBuilder: builder structure unreadable or length invalid");
        return fpSendBuilder ? fpSendBuilder(thisPtr, builder) : nullptr;
    }

    static volatile LONG s_structDumpBudget = 8;
    if (s_structDumpBudget > 0 && InterlockedDecrement(&s_structDumpBudget) >= 0) {
        DumpMemory("SendBuilder struct snapshot", builder, 0x20);
    }

    if (plainPtr && len > 0)
        DumpMemory("PLAINTEXT SendBuilder", plainPtr, len);
    else
        WriteRawLog("Hook_SendBuilder: empty payload");

    return fpSendBuilder ? fpSendBuilder(thisPtr, builder) : nullptr;
}

static bool ScanEndpointVTable(void* endpoint,
                               bool& outNoPath,
                               const std::vector<Core::SendRing::Entry>* ringSamples,
                               RingHitStats* ringStats,
                               TraceResult* outTrace)
{
    outNoPath = false;
    if (outTrace)
        ResetTraceResult(*outTrace);
    g_builderProbeAttempted.fetch_add(1u, std::memory_order_relaxed);
    void** vtbl = nullptr;
    if (!SafeMem::SafeRead(endpoint, vtbl) || !vtbl) {
        char msg[160];
        sprintf_s(msg, sizeof(msg), "ScanEndpointVTable: endpoint=%p vtbl unreadable", endpoint);
        WriteRawLog(msg);
        g_builderProbeSkipped.fetch_add(1u, std::memory_order_relaxed);
        return false;
    }

    bool vtblInRdata = false;
    if (!IsGameVtableAddress(vtbl, &vtblInRdata) || !vtblInRdata) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Core,
                  "[CORE][SB] endpoint=%p rejected reason=rdata-miss vtbl=%p",
                  endpoint,
                  vtbl);
        g_builderProbeSkipped.fetch_add(1u, std::memory_order_relaxed);
        return false;
    }


    uintptr_t vtblAddr = reinterpret_cast<uintptr_t>(vtbl);
    bool anyNewSlot = false;
    void* const* vtblEntries = vtbl;
    int firstEightCount = 0;
    int firstEightMisses = 0;
    int matchedIndex = -1;
    void* matchedFn = nullptr;
    void* slotFns[32]{};

    uint32_t scannedCount = 0;
    uint32_t execLikeCount = 0;
    TraceResult trace{};
    ResetTraceResult(trace);
    bool tracedMatched = false;
    bool asciiReject = false;
    std::uint32_t asciiValue = 0;
    int asciiSlot = -1;
    __try
    {
        for (int i = 0; i < 32; ++i)
        {
            uint64_t slotKey = (static_cast<uint64_t>(vtblAddr) << 8) ^ static_cast<uint64_t>(i & 0xFF);
            bool firstVisit = g_vtblSlotCache.insert(slotKey).second;
            if (firstVisit)
                anyNewSlot = true;

            void* fn = nullptr;
            bool readable = SafeMem::SafeRead(vtblEntries + i, fn);
            ++scannedCount;
            if (!readable)
            {
                Logf("endpoint vtbl[%02X] unreadable (vtbl=%p)", i, vtbl);
                if (i < 8)
                {
                    ++firstEightCount;
                    ++firstEightMisses;
                }
                continue;
            }

            Logf("endpoint vtbl[%02u] = %p", i, fn);
            if (fn && IsExecutablePtr(fn))
            {
                uint8_t b[8] = {};
                for (int k = 0; k < 8; ++k)
                {
                    if (!TryLoad(reinterpret_cast<uint8_t*>(fn) + k, b[k]))
                        b[k] = 0xFF;
                }
                Log::Logf(Log::Level::Info,
                          Log::Category::Core,
                          "[CORE] endpoint vtbl[%02u] = %p bytes=%02X %02X %02X %02X %02X %02X %02X %02X",
                          i,
                          fn,
                          b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
            }

            slotFns[i] = fn;

            bool execCandidate = fn && sp::is_executable_code_ptr(fn);
            if (execCandidate)
                ++execLikeCount;
            if (i < 8)
            {
                ++firstEightCount;
                if (!execCandidate)
                    ++firstEightMisses;
            }

            if (!execCandidate && fn) {
                uintptr_t candidate = reinterpret_cast<uintptr_t>(fn);
                bool inModule = false;
                if (const Scanner::ModuleInfo* primary = g_moduleMap.primaryExecutable()) {
                    inModule = (candidate >= primary->base && candidate < primary->end) ||
                               primary->containsRdata(candidate);
                }
                if (!inModule && LooksLikeAsciiDword(candidate)) {
                    asciiReject = true;
                    asciiValue = static_cast<std::uint32_t>(candidate & 0xFFFFFFFFu);
                    asciiSlot = i;
                    break;
                }
            }

            if (!execCandidate)
                continue;

            if (!matchedFn)
            {
                TraceResult candidate{};
                if (TraceSendPacketUse(reinterpret_cast<uint8_t*>(fn), candidate, static_cast<uint8_t>(i), vtbl)) {
                    matchedIndex = i;
                    matchedFn = fn;
                    trace = candidate;
                    tracedMatched = true;
                    break;
                }

                if (!g_sendBuilderHooked && FunctionCallsSendPacket(fn)) {
                    matchedIndex = i;
                    matchedFn = fn;
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        char msg[192];
        sprintf_s(msg, sizeof(msg),
                  "ScanEndpointVTable: exception code=%08lX endpoint=%p vtbl=%p",
                  GetExceptionCode(),
                  endpoint,
                  vtbl);
        WriteRawLog(msg);
        g_builderProbeSkipped.fetch_add(1u, std::memory_order_relaxed);
        return false;
    }

    if (asciiReject) {
        Log::Level asciiLevel = Log::Level::Warn;
        const std::uint64_t passId = g_guardWarnPass.load(std::memory_order_relaxed);
        if (passId != 0) {
            std::uint64_t last = g_asciiWarnLastPass.load(std::memory_order_relaxed);
            if (last == passId) {
                asciiLevel = Log::Level::Debug;
            } else {
                g_asciiWarnLastPass.store(passId, std::memory_order_relaxed);
            }
        }
        Log::Logf(asciiLevel,
                  Log::Category::Core,
                  "[CORE][SB] ascii vtbl endpoint=%p slot=%02d value=0x%08X",
                  endpoint,
                  asciiSlot,
                  asciiValue);
        g_builderProbeSkipped.fetch_add(1u, std::memory_order_relaxed);
        return false;
    }

    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[SB] endpoint candidates: scanned=%u exec_like=%u selected=%p entry=%p",
              scannedCount,
              execLikeCount,
              endpoint,
              matchedFn);

    if (!anyNewSlot && !matchedFn) {
        if (!g_sendBuilderHooked)
            g_builderProbeSkipped.fetch_add(1u, std::memory_order_relaxed);
        return g_sendBuilderHooked;
    }

    if (firstEightCount >= 8 && firstEightMisses >= 6)
    {
        char msg[192];
        sprintf_s(msg, sizeof(msg),
                  "ScanEndpointVTable: rejecting endpoint=%p vtbl=%p first8 misses=%d",
                  endpoint,
                  vtbl,
                  firstEightMisses);
        WriteRawLog(msg);
        g_builderProbeSkipped.fetch_add(1u, std::memory_order_relaxed);
        return false;
    }

    if (!matchedFn) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[CORE][SB] fallback scan window=0x%zX depth=%d",
                  kEndpointScanWindow,
                  kTailFollowMaxDepth);
        for (int i = 0; i < 32; ++i) {
            auto* fnBytes = reinterpret_cast<uint8_t*>(slotFns[i]);
            if (!fnBytes || !IsExecutablePtr(fnBytes))
                continue;
            TraceResult candidate{};
            if (TraceSendPacketUse(fnBytes, candidate, static_cast<uint8_t>(i), vtbl)) {
                matchedFn = slotFns[i];
                matchedIndex = i;
                trace = candidate;
                tracedMatched = true;
                break;
            }
        }
    }

    if (!tracedMatched && matchedFn) {
        TraceResult candidate{};
        if (TraceSendPacketUse(reinterpret_cast<uint8_t*>(matchedFn), candidate, static_cast<uint8_t>(matchedIndex & 0xFF), vtbl)) {
            trace = candidate;
            tracedMatched = true;
        }
    }

    if (!matchedFn) {
        bool firstWarn = g_skipWarnedVtables.insert(vtbl).second;
        if (firstWarn) {
            Log::Logf(Log::Level::Warn,
                      Log::Category::Core,
                      "[CORE][SB] no vtbl body referenced SendPacket; will retry (send=%p)",
                      g_sendPacketTarget);
        }
        g_builderProbeSkipped.fetch_add(1u, std::memory_order_relaxed);
        outNoPath = true;
        return false;
    }

    const TraceResult* tracePtr = tracedMatched ? &trace : nullptr;
    RingHitStats localRingStats{};
    if (ringStats)
        *ringStats = localRingStats;

    if (ringSamples && matchedFn) {
        localRingStats = EvaluateRingHits(*ringSamples, matchedFn, trace);
        if (ringStats)
            *ringStats = localRingStats;
        if (!ringSamples->empty()) {
            Log::Logf(Log::Level::Debug,
                      Log::Category::Core,
                      "[SB][RING] match hits=%u self=%u off=%u threshold=%u",
                      localRingStats.hits,
                      localRingStats.selfHits,
                      localRingStats.offModuleHits,
                      kRingHitThreshold);
            if (localRingStats.hits < kRingHitThreshold)
                return false;
        }
    } else if (ringStats) {
        *ringStats = {};
    }
    if (tracedMatched && outTrace)
        *outTrace = trace;

    t_ringHitsForAttach = localRingStats.hits;
    bool attached = AttachSendBuilderFromTrace(matchedFn,
                                               static_cast<uint8_t>(matchedIndex & 0xFF),
                                               vtbl,
                                               tracePtr,
                                               "direct",
                                               tracedMatched ? nullptr : reinterpret_cast<const uint8_t*>(matchedFn));
    t_ringHitsForAttach = 0;

    if (attached) {
        if (ringSamples && localRingStats.hits >= kRingHitThreshold) {
            auto trusted = Core::GetTrustedEndpointCache().InsertOrBump(reinterpret_cast<std::uintptr_t>(vtbl),
                                                                        static_cast<std::uint32_t>(matchedIndex & 0xFF),
                                                                        reinterpret_cast<std::uintptr_t>(matchedFn),
                                                                        kTrustedEndpointTtlMs);
            Log::Logf(Log::Level::Info,
                      Log::Category::Core,
                      "[SB][CACHE] insert vtbl=%p slot=%u entry=%p hits=%u",
                      vtbl,
                      matchedIndex,
                      matchedFn,
                      trusted.hits);
        }
        return true;
    }

    return g_sendBuilderHooked;
}

static void TryHookSendBuilder(void* endpoint)
{
    if (g_builderScanned || !endpoint)
        return;

    if (!IsEngineStableForScanning())
        return;

    DWORD now = GetTickCount();
    DWORD waitMs = 0;
    if (ShouldDeferEndpointScan(endpoint, now, waitMs))
        return;

    bool noPath = false;
    if (ScanEndpointVTable(endpoint,
                           noPath,
                           nullptr,
                           nullptr,
                           nullptr))
    {
        g_builderScanned = true;
        ClearEndpointBackoff(endpoint);
    }
    else
    {
        if (noPath)
            RegisterEndpointBackoff(endpoint, now);
        else
            ClearEndpointBackoff(endpoint);
    }
}

static BOOL WINAPI Hook_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    void* trackedCfg = GetTrackedConfigPtr();
    bool intersects = trackedCfg && IsTrackedConfigInRange(reinterpret_cast<uintptr_t>(lpAddress), dwSize);

    MEMORY_BASIC_INFORMATION before{};
    MEMORY_BASIC_INFORMATION after{};
    bool haveBefore = false;
    bool haveAfter = false;

    DWORD preservedLE = GetLastError();
    if (intersects)
        haveBefore = VirtualQuery(trackedCfg, &before, sizeof(before)) != 0;
    SetLastError(preservedLE);

    BOOL result = g_origVirtualProtect ? g_origVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
                                       : FALSE;
    DWORD callError = GetLastError();

    if (intersects)
    {
        haveAfter = VirtualQuery(trackedCfg, &after, sizeof(after)) != 0;
        DWORD beforeState = haveBefore ? before.State : 0xFFFFFFFF;
        DWORD beforeProtect = haveBefore ? before.Protect : 0xFFFFFFFF;
        DWORD beforeType = haveBefore ? before.Type : 0xFFFFFFFF;
        DWORD afterState = haveAfter ? after.State : 0xFFFFFFFF;
        DWORD afterProtect = haveAfter ? after.Protect : 0xFFFFFFFF;
        DWORD afterType = haveAfter ? after.Type : 0xFFFFFFFF;
        DWORD oldProtectValue = (lpflOldProtect && result) ? *lpflOldProtect : 0xFFFFFFFF;
        char buf[320];
        sprintf_s(buf, sizeof(buf),
                  "VirtualProtect intercept cfg=%p addr=%p size=0x%zx new=0x%08lX old=0x%08lX result=%ld err=%lu "
                  "before={state=0x%08lX protect=0x%08lX type=0x%08lX} "
                  "after={state=0x%08lX protect=0x%08lX type=0x%08lX}",
                  trackedCfg,
                  lpAddress,
                  dwSize,
                  static_cast<unsigned long>(flNewProtect),
                  static_cast<unsigned long>(oldProtectValue),
                  static_cast<long>(result),
                  static_cast<unsigned long>(callError),
                  static_cast<unsigned long>(beforeState),
                  static_cast<unsigned long>(beforeProtect),
                  static_cast<unsigned long>(beforeType),
                  static_cast<unsigned long>(afterState),
                  static_cast<unsigned long>(afterProtect),
                  static_cast<unsigned long>(afterType));
        WriteRawLog(buf);
        if (haveAfter)
            UpdateTrackedRegionCache(after);
    }

    SetLastError(callError);
    return result;
}

static BOOL WINAPI Hook_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    void* trackedCfg = GetTrackedConfigPtr();
    DWORD currentPid = GetCurrentProcessId();
    DWORD targetPid = 0;
    bool sameProcess = false;
    if (hProcess == nullptr || hProcess == GetCurrentProcess() || hProcess == INVALID_HANDLE_VALUE)
    {
        sameProcess = true;
        targetPid = currentPid;
    }
    else
    {
        DWORD pid = GetProcessId(hProcess);
        if (pid != 0)
        {
            targetPid = pid;
            if (pid == currentPid)
                sameProcess = true;
        }
    }

    bool intersects = trackedCfg && sameProcess && IsTrackedConfigInRange(reinterpret_cast<uintptr_t>(lpAddress), dwSize);

    MEMORY_BASIC_INFORMATION before{};
    MEMORY_BASIC_INFORMATION after{};
    bool haveBefore = false;
    bool haveAfter = false;

    DWORD preservedLE = GetLastError();
    if (intersects)
        haveBefore = VirtualQueryEx(hProcess, trackedCfg, &before, sizeof(before)) != 0;
    SetLastError(preservedLE);

    BOOL result = g_origVirtualProtectEx ? g_origVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect)
                                         : FALSE;
    DWORD callError = GetLastError();

    if (intersects)
    {
        haveAfter = VirtualQueryEx(hProcess, trackedCfg, &after, sizeof(after)) != 0;
        DWORD beforeState = haveBefore ? before.State : 0xFFFFFFFF;
        DWORD beforeProtect = haveBefore ? before.Protect : 0xFFFFFFFF;
        DWORD beforeType = haveBefore ? before.Type : 0xFFFFFFFF;
        DWORD afterState = haveAfter ? after.State : 0xFFFFFFFF;
        DWORD afterProtect = haveAfter ? after.Protect : 0xFFFFFFFF;
        DWORD afterType = haveAfter ? after.Type : 0xFFFFFFFF;
        DWORD oldProtectValue = (lpflOldProtect && result) ? *lpflOldProtect : 0xFFFFFFFF;
        char buf[352];
        sprintf_s(buf, sizeof(buf),
                  "VirtualProtectEx intercept pid=%lu cfg=%p addr=%p size=0x%zx new=0x%08lX old=0x%08lX result=%ld err=%lu "
                  "before={state=0x%08lX protect=0x%08lX type=0x%08lX} "
                  "after={state=0x%08lX protect=0x%08lX type=0x%08lX}",
                  static_cast<unsigned long>(targetPid),
                  trackedCfg,
                  lpAddress,
                  dwSize,
                  static_cast<unsigned long>(flNewProtect),
                  static_cast<unsigned long>(oldProtectValue),
                  static_cast<long>(result),
                  static_cast<unsigned long>(callError),
                  static_cast<unsigned long>(beforeState),
                  static_cast<unsigned long>(beforeProtect),
                  static_cast<unsigned long>(beforeType),
                  static_cast<unsigned long>(afterState),
                  static_cast<unsigned long>(afterProtect),
                  static_cast<unsigned long>(afterType));
        WriteRawLog(buf);
        if (haveAfter)
            UpdateTrackedRegionCache(after);
    }

    SetLastError(callError);
    return result;
}

static LPVOID WINAPI Hook_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    LPVOID result = g_origVirtualAlloc ? g_origVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect) : nullptr;
    DWORD callError = GetLastError();

    void* trackedCfg = GetTrackedConfigPtr();
    bool intersects = false;
    if (trackedCfg && dwSize)
    {
        if (result)
            intersects = IsTrackedConfigInRange(reinterpret_cast<uintptr_t>(result), dwSize);
        if (!intersects && lpAddress)
            intersects = IsTrackedConfigInRange(reinterpret_cast<uintptr_t>(lpAddress), dwSize);
    }

    if (intersects)
    {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(trackedCfg, &info, sizeof(info)))
        {
            UpdateTrackedRegionCache(info);
            char buf[352];
            sprintf_s(buf, sizeof(buf),
                      "VirtualAlloc intercept cfg=%p hint=%p size=0x%zx flags=0x%08lX protect=0x%08lX result=%p err=%lu "
                      "region={base=%p size=0x%zx state=0x%08lX protect=0x%08lX type=0x%08lX}",
                      trackedCfg,
                      lpAddress,
                      dwSize,
                      static_cast<unsigned long>(flAllocationType),
                      static_cast<unsigned long>(flProtect),
                      result,
                      static_cast<unsigned long>(callError),
                      info.BaseAddress,
                      info.RegionSize,
                      static_cast<unsigned long>(info.State),
                      static_cast<unsigned long>(info.Protect),
                      static_cast<unsigned long>(info.Type));
            WriteRawLog(buf);
        }
    }

    SetLastError(callError);
    return result;
}

static LPVOID WINAPI Hook_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    LPVOID result = g_origVirtualAllocEx ? g_origVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect) : nullptr;
    DWORD callError = GetLastError();

    void* trackedCfg = GetTrackedConfigPtr();
    DWORD currentPid = GetCurrentProcessId();
    DWORD targetPid = 0;
    bool sameProcess = false;
    if (hProcess == nullptr || hProcess == GetCurrentProcess() || hProcess == INVALID_HANDLE_VALUE)
    {
        sameProcess = true;
        targetPid = currentPid;
    }
    else
    {
        DWORD pid = GetProcessId(hProcess);
        if (pid != 0)
        {
            targetPid = pid;
            if (pid == currentPid)
                sameProcess = true;
        }
    }

    bool intersects = false;
    if (trackedCfg && sameProcess && dwSize)
    {
        if (result)
            intersects = IsTrackedConfigInRange(reinterpret_cast<uintptr_t>(result), dwSize);
        if (!intersects && lpAddress)
            intersects = IsTrackedConfigInRange(reinterpret_cast<uintptr_t>(lpAddress), dwSize);
    }

    if (intersects)
    {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQueryEx(hProcess, trackedCfg, &info, sizeof(info)))
        {
            UpdateTrackedRegionCache(info);
            char buf[368];
            sprintf_s(buf, sizeof(buf),
                      "VirtualAllocEx intercept pid=%lu cfg=%p hint=%p size=0x%zx flags=0x%08lX protect=0x%08lX result=%p err=%lu "
                      "region={base=%p size=0x%zx state=0x%08lX protect=0x%08lX type=0x%08lX}",
                      static_cast<unsigned long>(targetPid),
                      trackedCfg,
                      lpAddress,
                      dwSize,
                      static_cast<unsigned long>(flAllocationType),
                      static_cast<unsigned long>(flProtect),
                      result,
                      static_cast<unsigned long>(callError),
                      info.BaseAddress,
                      info.RegionSize,
                      static_cast<unsigned long>(info.State),
                      static_cast<unsigned long>(info.Protect),
                      static_cast<unsigned long>(info.Type));
            WriteRawLog(buf);
        }
    }

    SetLastError(callError);
    return result;
}

static LPVOID WINAPI Hook_MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
{
    LPVOID result = g_origMapViewOfFile ? g_origMapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap)
                                        : nullptr;
    DWORD callError = GetLastError();

    void* trackedCfg = GetTrackedConfigPtr();
    SIZE_T effectiveSize = dwNumberOfBytesToMap;
    if (trackedCfg && result)
    {
        if (effectiveSize == 0)
        {
            MEMORY_BASIC_INFORMATION tmp{};
            if (VirtualQuery(result, &tmp, sizeof(tmp)))
                effectiveSize = tmp.RegionSize;
        }
        if (effectiveSize && IsTrackedConfigInRange(reinterpret_cast<uintptr_t>(result), effectiveSize))
        {
            MEMORY_BASIC_INFORMATION info{};
            if (VirtualQuery(trackedCfg, &info, sizeof(info)))
            {
                UpdateTrackedRegionCache(info);
                char buf[368];
                sprintf_s(buf, sizeof(buf),
                          "MapViewOfFile intercept cfg=%p result=%p size=0x%zx access=0x%08lX err=%lu "
                          "region={base=%p size=0x%zx state=0x%08lX protect=0x%08lX type=0x%08lX}",
                          trackedCfg,
                          result,
                          effectiveSize,
                          static_cast<unsigned long>(dwDesiredAccess),
                          static_cast<unsigned long>(callError),
                          info.BaseAddress,
                          info.RegionSize,
                          static_cast<unsigned long>(info.State),
                          static_cast<unsigned long>(info.Protect),
                          static_cast<unsigned long>(info.Type));
                WriteRawLog(buf);
            }
        }
    }

    SetLastError(callError);
    return result;
}

static LPVOID WINAPI Hook_MapViewOfFileEx(HANDLE hFileMappingObject,
                                          DWORD dwDesiredAccess,
                                          DWORD dwFileOffsetHigh,
                                          DWORD dwFileOffsetLow,
                                          SIZE_T dwNumberOfBytesToMap,
                                          LPVOID lpBaseAddress)
{
    LPVOID result = g_origMapViewOfFileEx ? g_origMapViewOfFileEx(hFileMappingObject,
                                                                  dwDesiredAccess,
                                                                  dwFileOffsetHigh,
                                                                  dwFileOffsetLow,
                                                                  dwNumberOfBytesToMap,
                                                                  lpBaseAddress)
                                          : nullptr;
    DWORD callError = GetLastError();

    void* trackedCfg = GetTrackedConfigPtr();
    SIZE_T effectiveSize = dwNumberOfBytesToMap;
    if (trackedCfg && result)
    {
        if (effectiveSize == 0)
        {
            MEMORY_BASIC_INFORMATION tmp{};
            if (VirtualQuery(result, &tmp, sizeof(tmp)))
                effectiveSize = tmp.RegionSize;
        }
        if (effectiveSize && IsTrackedConfigInRange(reinterpret_cast<uintptr_t>(result), effectiveSize))
        {
            MEMORY_BASIC_INFORMATION info{};
            if (VirtualQuery(trackedCfg, &info, sizeof(info)))
            {
                UpdateTrackedRegionCache(info);
                char buf[384];
                sprintf_s(buf, sizeof(buf),
                          "MapViewOfFileEx intercept cfg=%p desiredBase=%p result=%p size=0x%zx access=0x%08lX err=%lu "
                          "region={base=%p size=0x%zx state=0x%08lX protect=0x%08lX type=0x%08lX}",
                          trackedCfg,
                          lpBaseAddress,
                          result,
                          effectiveSize,
                          static_cast<unsigned long>(dwDesiredAccess),
                          static_cast<unsigned long>(callError),
                          info.BaseAddress,
                          info.RegionSize,
                          static_cast<unsigned long>(info.State),
                          static_cast<unsigned long>(info.Protect),
                          static_cast<unsigned long>(info.Type));
                WriteRawLog(buf);
            }
        }
    }

    SetLastError(callError);
    return result;
}

static bool IsCurrentProcessHandle(HANDLE handle)
{
    return handle == nullptr || handle == GetCurrentProcess() || handle == reinterpret_cast<HANDLE>(-1);
}

static HANDLE EffectiveProcessHandle(HANDLE handle)
{
    return IsCurrentProcessHandle(handle) ? GetCurrentProcess() : handle;
}

static DWORD ResolveProcessIdentity(HANDLE processHandle, bool& sameProcess)
{
    DWORD currentPid = GetCurrentProcessId();
    sameProcess = IsCurrentProcessHandle(processHandle);
    if (sameProcess)
        return currentPid;

    DWORD pid = GetProcessId(processHandle);
    if (pid == 0)
        return currentPid;
    sameProcess = (pid == currentPid);
    return pid;
}

static NTSTATUS NTAPI Hook_NtProtectVirtualMemory(HANDLE processHandle,
                                                  PVOID* baseAddress,
                                                  PSIZE_T regionSize,
                                                  ULONG newProtect,
                                                  PULONG oldProtect)
{
    void* trackedCfg = GetTrackedConfigPtr();
    if (!trackedCfg)
        return g_origNtProtectVirtualMemory(processHandle, baseAddress, regionSize, newProtect, oldProtect);

    bool sameProcess = false;
    DWORD targetPid = ResolveProcessIdentity(processHandle, sameProcess);

    uintptr_t inputBase = (baseAddress && *baseAddress) ? reinterpret_cast<uintptr_t>(*baseAddress) : 0;
    SIZE_T inputSize = regionSize ? *regionSize : 0;
    bool intersectsBefore = sameProcess && baseAddress && regionSize && *regionSize &&
                            IsTrackedConfigInRange(inputBase, inputSize);

    MEMORY_BASIC_INFORMATION mbiBefore{};
    bool haveBefore = false;
    if (intersectsBefore)
    {
        DWORD saved = GetLastError();
        haveBefore = VirtualQueryEx(EffectiveProcessHandle(processHandle), trackedCfg, &mbiBefore, sizeof(mbiBefore)) != 0;
        SetLastError(saved);
    }

    NTSTATUS status = g_origNtProtectVirtualMemory(processHandle, baseAddress, regionSize, newProtect, oldProtect);

    uintptr_t outputBase = (baseAddress && *baseAddress) ? reinterpret_cast<uintptr_t>(*baseAddress) : inputBase;
    SIZE_T outputSize = regionSize ? *regionSize : inputSize;
    bool intersectsAfter = sameProcess && outputSize && IsTrackedConfigInRange(outputBase, outputSize);

    MEMORY_BASIC_INFORMATION mbiAfter{};
    bool haveAfter = false;
    if (sameProcess && (intersectsBefore || intersectsAfter))
    {
        DWORD saved = GetLastError();
        haveAfter = VirtualQueryEx(EffectiveProcessHandle(processHandle), trackedCfg, &mbiAfter, sizeof(mbiAfter)) != 0;
        SetLastError(saved);
        if (haveAfter)
            UpdateTrackedRegionCache(mbiAfter);
    }

    if (sameProcess && (intersectsBefore || intersectsAfter))
    {
        ULONG oldProtectValue = (oldProtect && NT_SUCCESS(status)) ? *oldProtect : 0xFFFFFFFF;
        char buf[416];
        sprintf_s(buf, sizeof(buf),
                  "NtProtectVirtualMemory intercept pid=%lu cfg=%p status=0x%08lX baseIn=%p sizeIn=0x%zx baseOut=%p sizeOut=0x%zx new=0x%08lX old=0x%08lX "
                  "before={state=0x%08lX protect=0x%08lX type=0x%08lX} "
                  "after={state=0x%08lX protect=0x%08lX type=0x%08lX}",
                  static_cast<unsigned long>(targetPid),
                  trackedCfg,
                  static_cast<unsigned long>(status),
                  reinterpret_cast<void*>(inputBase),
                  inputSize,
                  reinterpret_cast<void*>(outputBase),
                  outputSize,
                  static_cast<unsigned long>(newProtect),
                  static_cast<unsigned long>(oldProtectValue),
                  static_cast<unsigned long>(haveBefore ? mbiBefore.State : 0xFFFFFFFF),
                  static_cast<unsigned long>(haveBefore ? mbiBefore.Protect : 0xFFFFFFFF),
                  static_cast<unsigned long>(haveBefore ? mbiBefore.Type : 0xFFFFFFFF),
                  static_cast<unsigned long>(haveAfter ? mbiAfter.State : 0xFFFFFFFF),
                  static_cast<unsigned long>(haveAfter ? mbiAfter.Protect : 0xFFFFFFFF),
                  static_cast<unsigned long>(haveAfter ? mbiAfter.Type : 0xFFFFFFFF));
        WriteRawLog(buf);
        Util::RegionWatch::NotifyRange("NtProtectVirtualMemory",
                                       outputBase,
                                       outputSize,
                                       haveAfter ? &mbiAfter : nullptr);
    }

    return status;
}

static NTSTATUS NTAPI Hook_NtAllocateVirtualMemory(HANDLE processHandle,
                                                   PVOID* baseAddress,
                                                   ULONG_PTR zeroBits,
                                                   PSIZE_T regionSize,
                                                   ULONG allocationType,
                                                   ULONG protect)
{
    void* trackedCfg = GetTrackedConfigPtr();
    if (!trackedCfg)
        return g_origNtAllocateVirtualMemory(processHandle, baseAddress, zeroBits, regionSize, allocationType, protect);

    bool sameProcess = false;
    DWORD targetPid = ResolveProcessIdentity(processHandle, sameProcess);

    uintptr_t inputBase = (baseAddress && *baseAddress) ? reinterpret_cast<uintptr_t>(*baseAddress) : 0;
    SIZE_T inputSize = regionSize ? *regionSize : 0;
    bool intersectsBefore = sameProcess && inputSize && IsTrackedConfigInRange(inputBase, inputSize);

    MEMORY_BASIC_INFORMATION mbiBefore{};
    bool haveBefore = false;
    if (intersectsBefore)
    {
        DWORD saved = GetLastError();
        haveBefore = VirtualQueryEx(EffectiveProcessHandle(processHandle), trackedCfg, &mbiBefore, sizeof(mbiBefore)) != 0;
        SetLastError(saved);
    }

    NTSTATUS status = g_origNtAllocateVirtualMemory(processHandle, baseAddress, zeroBits, regionSize, allocationType, protect);

    uintptr_t outputBase = (baseAddress && *baseAddress) ? reinterpret_cast<uintptr_t>(*baseAddress) : inputBase;
    SIZE_T outputSize = regionSize ? *regionSize : inputSize;
    bool intersectsAfter = sameProcess && outputSize && IsTrackedConfigInRange(outputBase, outputSize);

    MEMORY_BASIC_INFORMATION mbiAfter{};
    bool haveAfter = false;
    if (intersectsAfter)
    {
        DWORD saved = GetLastError();
        haveAfter = VirtualQueryEx(EffectiveProcessHandle(processHandle), trackedCfg, &mbiAfter, sizeof(mbiAfter)) != 0;
        SetLastError(saved);
        if (haveAfter)
            UpdateTrackedRegionCache(mbiAfter);
    }

    if (sameProcess && (intersectsBefore || intersectsAfter))
    {
        char buf[400];
        sprintf_s(buf, sizeof(buf),
                  "NtAllocateVirtualMemory intercept pid=%lu cfg=%p status=0x%08lX baseIn=%p sizeIn=0x%zx baseOut=%p sizeOut=0x%zx flags=0x%08lX protect=0x%08lX "
                  "before={state=0x%08lX protect=0x%08lX type=0x%08lX} "
                  "after={state=0x%08lX protect=0x%08lX type=0x%08lX}",
                  static_cast<unsigned long>(targetPid),
                  trackedCfg,
                  static_cast<unsigned long>(status),
                  reinterpret_cast<void*>(inputBase),
                  inputSize,
                  reinterpret_cast<void*>(outputBase),
                  outputSize,
                  static_cast<unsigned long>(allocationType),
                  static_cast<unsigned long>(protect),
                  static_cast<unsigned long>(haveBefore ? mbiBefore.State : 0xFFFFFFFF),
                  static_cast<unsigned long>(haveBefore ? mbiBefore.Protect : 0xFFFFFFFF),
                  static_cast<unsigned long>(haveBefore ? mbiBefore.Type : 0xFFFFFFFF),
                  static_cast<unsigned long>(haveAfter ? mbiAfter.State : 0xFFFFFFFF),
                  static_cast<unsigned long>(haveAfter ? mbiAfter.Protect : 0xFFFFFFFF),
                  static_cast<unsigned long>(haveAfter ? mbiAfter.Type : 0xFFFFFFFF));
        WriteRawLog(buf);
        Util::RegionWatch::NotifyRange("NtAllocateVirtualMemory",
                                       outputBase,
                                       outputSize,
                                       haveAfter ? &mbiAfter : nullptr);
    }

    return status;
}

static NTSTATUS NTAPI Hook_NtMapViewOfSection(HANDLE sectionHandle,
                                              HANDLE processHandle,
                                              PVOID* baseAddress,
                                              ULONG zeroBits,
                                              SIZE_T commitSize,
                                              PLARGE_INTEGER sectionOffset,
                                              PSIZE_T viewSize,
                                              ULONG inheritDisposition,
                                              ULONG allocationType,
                                              ULONG win32Protect)
{
    void* trackedCfg = GetTrackedConfigPtr();
    bool sameProcess = false;
    DWORD targetPid = ResolveProcessIdentity(processHandle, sameProcess);

    SIZE_T requestedSize = viewSize ? *viewSize : 0;

    NTSTATUS status = g_origNtMapViewOfSection(sectionHandle,
                                               processHandle,
                                               baseAddress,
                                               zeroBits,
                                               commitSize,
                                               sectionOffset,
                                               viewSize,
                                               inheritDisposition,
                                               allocationType,
                                               win32Protect);

    uintptr_t mappedBase = (baseAddress && *baseAddress) ? reinterpret_cast<uintptr_t>(*baseAddress) : 0;
    SIZE_T actualSize = viewSize ? *viewSize : requestedSize;
    bool intersects = trackedCfg && sameProcess && actualSize && IsTrackedConfigInRange(mappedBase, actualSize);

    MEMORY_BASIC_INFORMATION info{};
    bool haveInfo = false;
    if (intersects)
    {
        DWORD saved = GetLastError();
        haveInfo = VirtualQueryEx(EffectiveProcessHandle(processHandle), trackedCfg, &info, sizeof(info)) != 0;
        SetLastError(saved);
        if (haveInfo)
            UpdateTrackedRegionCache(info);
    }

    if (intersects)
    {
        ULONGLONG offsetCombined = 0;
        if (sectionOffset)
        {
            offsetCombined = (static_cast<ULONGLONG>(static_cast<unsigned long>(sectionOffset->HighPart)) << 32) |
                             static_cast<ULONGLONG>(static_cast<unsigned long>(sectionOffset->LowPart));
        }

        char buf[448];
        sprintf_s(buf, sizeof(buf),
                  "NtMapViewOfSection intercept pid=%lu cfg=%p status=0x%08lX base=%p size=0x%zx offset=0x%016llX protect=0x%08lX alloc=0x%08lX "
                  "region={base=%p size=0x%zx state=0x%08lX protect=0x%08lX type=0x%08lX}",
                  static_cast<unsigned long>(targetPid),
                  trackedCfg,
                  static_cast<unsigned long>(status),
                  reinterpret_cast<void*>(mappedBase),
                  actualSize,
                  offsetCombined,
                  static_cast<unsigned long>(win32Protect),
                  static_cast<unsigned long>(allocationType),
                  haveInfo ? info.BaseAddress : nullptr,
                  haveInfo ? info.RegionSize : 0,
                  static_cast<unsigned long>(haveInfo ? info.State : 0xFFFFFFFF),
                  static_cast<unsigned long>(haveInfo ? info.Protect : 0xFFFFFFFF),
                  static_cast<unsigned long>(haveInfo ? info.Type : 0xFFFFFFFF));
        WriteRawLog(buf);
        Util::RegionWatch::NotifyRange("NtMapViewOfSection",
                                       mappedBase,
                                       actualSize,
                                       haveInfo ? &info : nullptr);
    }

    return status;
}

static NTSTATUS NTAPI Hook_NtUnmapViewOfSection(HANDLE processHandle, PVOID baseAddress)
{
    void* trackedCfg = GetTrackedConfigPtr();
    if (!trackedCfg)
        return g_origNtUnmapViewOfSection(processHandle, baseAddress);

    bool sameProcess = false;
    DWORD targetPid = ResolveProcessIdentity(processHandle, sameProcess);

    MEMORY_BASIC_INFORMATION infoBefore{};
    bool haveBefore = false;
    if (sameProcess)
    {
        DWORD saved = GetLastError();
        haveBefore = VirtualQueryEx(EffectiveProcessHandle(processHandle), trackedCfg, &infoBefore, sizeof(infoBefore)) != 0;
        SetLastError(saved);
    }

    bool affectsTracked = haveBefore && infoBefore.BaseAddress == baseAddress;

    NTSTATUS status = g_origNtUnmapViewOfSection(processHandle, baseAddress);

    if (sameProcess && affectsTracked)
    {
        char buf[320];
        sprintf_s(buf, sizeof(buf),
                  "NtUnmapViewOfSection intercept pid=%lu cfg=%p status=0x%08lX base=%p size=0x%zx state=0x%08lX protect=0x%08lX type=0x%08lX",
                  static_cast<unsigned long>(targetPid),
                  trackedCfg,
                  static_cast<unsigned long>(status),
                  infoBefore.BaseAddress,
                  infoBefore.RegionSize,
                  static_cast<unsigned long>(infoBefore.State),
                  static_cast<unsigned long>(infoBefore.Protect),
                  static_cast<unsigned long>(infoBefore.Type));
        WriteRawLog(buf);
        Util::RegionWatch::NotifyUnmap("NtUnmapViewOfSection", &infoBefore);

        if (NT_SUCCESS(status))
        {
            g_lastNetCfgState = 0xFFFFFFFF;
            g_lastNetCfgProtect = 0xFFFFFFFF;
            g_lastNetCfgType = 0xFFFFFFFF;
            g_lastNetCfgBase = nullptr;
            g_lastNetCfgRegionSize = 0;
            g_haveNetCfgSnapshot = false;
        }
    }

    return status;
}

static void InstallModuleHook(const wchar_t* moduleName,
                              const char* tag,
                              const char* procName,
                              LPVOID hookFn,
                              void** originalFn,
                              LPVOID* targetSlot,
                              bool* installedFlag)
{
    if (*installedFlag)
        return;

    if (!*targetSlot)
    {
        HMODULE module = GetModuleHandleW(moduleName);
        if (!module)
            return;
        *targetSlot = GetProcAddress(module, procName);
        if (!*targetSlot)
            return;
    }

    MH_STATUS createStatus = MH_CreateHook(*targetSlot, hookFn, originalFn);
    if (createStatus != MH_OK && createStatus != MH_ERROR_ALREADY_CREATED)
    {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "%s hook create failed status=%d", tag, static_cast<int>(createStatus));
        WriteRawLog(buf);
        return;
    }

    MH_STATUS enableStatus = MH_EnableHook(*targetSlot);
    if (enableStatus == MH_OK || enableStatus == MH_ERROR_ENABLED)
    {
        if (!*installedFlag)
        {
            char buf[128];
            sprintf_s(buf, sizeof(buf), "%s hook installed", tag);
            WriteRawLog(buf);
        }
        *installedFlag = true;
    }
    else
    {
        if (createStatus == MH_OK)
        {
            MH_RemoveHook(*targetSlot);
            *originalFn = nullptr;
            *targetSlot = nullptr;
        }
        char buf[160];
        sprintf_s(buf, sizeof(buf), "%s hook enable failed status=%d", tag, static_cast<int>(enableStatus));
        WriteRawLog(buf);
    }
}

static void InstallKernelHook(const char* tag,
                              const char* procName,
                              LPVOID hookFn,
                              void** originalFn,
                              LPVOID* targetSlot,
                              bool* installedFlag)
{
    InstallModuleHook(L"KERNEL32.DLL", tag, procName, hookFn, originalFn, targetSlot, installedFlag);
}

static void InstallNtdllHook(const char* tag,
                             const char* procName,
                             LPVOID hookFn,
                             void** originalFn,
                             LPVOID* targetSlot,
                             bool* installedFlag)
{
    InstallModuleHook(L"NTDLL.DLL", tag, procName, hookFn, originalFn, targetSlot, installedFlag);
}

static void RemoveKernelHook(const char* tag, LPVOID* targetSlot, bool* installedFlag, void** originalFn)
{
    if (!*installedFlag || !*targetSlot)
        return;

    MH_DisableHook(*targetSlot);
    MH_RemoveHook(*targetSlot);
    *installedFlag = false;
    *originalFn = nullptr;
    *targetSlot = nullptr;

    char buf[128];
    sprintf_s(buf, sizeof(buf), "%s hook removed", tag);
    WriteRawLog(buf);
}

static void EnsureMemoryHooks()
{
    InstallKernelHook("VirtualProtect",
                      "VirtualProtect",
                      reinterpret_cast<LPVOID>(Hook_VirtualProtect),
                      reinterpret_cast<void**>(&g_origVirtualProtect),
                      &g_virtualProtectTarget,
                      &g_virtualProtectHooked);
    InstallKernelHook("VirtualProtectEx",
                      "VirtualProtectEx",
                      reinterpret_cast<LPVOID>(Hook_VirtualProtectEx),
                      reinterpret_cast<void**>(&g_origVirtualProtectEx),
                      &g_virtualProtectExTarget,
                      &g_virtualProtectExHooked);
    InstallKernelHook("VirtualAlloc",
                      "VirtualAlloc",
                      reinterpret_cast<LPVOID>(Hook_VirtualAlloc),
                      reinterpret_cast<void**>(&g_origVirtualAlloc),
                      &g_virtualAllocTarget,
                      &g_virtualAllocHooked);
    InstallKernelHook("VirtualAllocEx",
                      "VirtualAllocEx",
                      reinterpret_cast<LPVOID>(Hook_VirtualAllocEx),
                      reinterpret_cast<void**>(&g_origVirtualAllocEx),
                      &g_virtualAllocExTarget,
                      &g_virtualAllocExHooked);
    InstallKernelHook("MapViewOfFile",
                      "MapViewOfFile",
                      reinterpret_cast<LPVOID>(Hook_MapViewOfFile),
                      reinterpret_cast<void**>(&g_origMapViewOfFile),
                      &g_mapViewOfFileTarget,
                      &g_mapViewOfFileHooked);
    InstallKernelHook("MapViewOfFileEx",
                      "MapViewOfFileEx",
                      reinterpret_cast<LPVOID>(Hook_MapViewOfFileEx),
                      reinterpret_cast<void**>(&g_origMapViewOfFileEx),
                      &g_mapViewOfFileExTarget,
                      &g_mapViewOfFileExHooked);
    InstallNtdllHook("NtProtectVirtualMemory",
                     "NtProtectVirtualMemory",
                     reinterpret_cast<LPVOID>(Hook_NtProtectVirtualMemory),
                     reinterpret_cast<void**>(&g_origNtProtectVirtualMemory),
                     &g_ntProtectVirtualMemoryTarget,
                     &g_ntProtectVirtualMemoryHooked);
    InstallNtdllHook("NtAllocateVirtualMemory",
                     "NtAllocateVirtualMemory",
                     reinterpret_cast<LPVOID>(Hook_NtAllocateVirtualMemory),
                     reinterpret_cast<void**>(&g_origNtAllocateVirtualMemory),
                     &g_ntAllocateVirtualMemoryTarget,
                     &g_ntAllocateVirtualMemoryHooked);
    InstallNtdllHook("NtMapViewOfSection",
                     "NtMapViewOfSection",
                     reinterpret_cast<LPVOID>(Hook_NtMapViewOfSection),
                     reinterpret_cast<void**>(&g_origNtMapViewOfSection),
                     &g_ntMapViewOfSectionTarget,
                     &g_ntMapViewOfSectionHooked);
    InstallNtdllHook("NtUnmapViewOfSection",
                     "NtUnmapViewOfSection",
                     reinterpret_cast<LPVOID>(Hook_NtUnmapViewOfSection),
                     reinterpret_cast<void**>(&g_origNtUnmapViewOfSection),
                     &g_ntUnmapViewOfSectionTarget,
                     &g_ntUnmapViewOfSectionHooked);
}

static void RemoveMemoryHooks()
{
    RemoveKernelHook("NtUnmapViewOfSection",
                     &g_ntUnmapViewOfSectionTarget,
                     &g_ntUnmapViewOfSectionHooked,
                     reinterpret_cast<void**>(&g_origNtUnmapViewOfSection));
    RemoveKernelHook("NtMapViewOfSection",
                     &g_ntMapViewOfSectionTarget,
                     &g_ntMapViewOfSectionHooked,
                     reinterpret_cast<void**>(&g_origNtMapViewOfSection));
    RemoveKernelHook("NtAllocateVirtualMemory",
                     &g_ntAllocateVirtualMemoryTarget,
                     &g_ntAllocateVirtualMemoryHooked,
                     reinterpret_cast<void**>(&g_origNtAllocateVirtualMemory));
    RemoveKernelHook("NtProtectVirtualMemory",
                     &g_ntProtectVirtualMemoryTarget,
                     &g_ntProtectVirtualMemoryHooked,
                     reinterpret_cast<void**>(&g_origNtProtectVirtualMemory));
    RemoveKernelHook("MapViewOfFileEx",
                     &g_mapViewOfFileExTarget,
                     &g_mapViewOfFileExHooked,
                     reinterpret_cast<void**>(&g_origMapViewOfFileEx));
    RemoveKernelHook("MapViewOfFile",
                     &g_mapViewOfFileTarget,
                     &g_mapViewOfFileHooked,
                     reinterpret_cast<void**>(&g_origMapViewOfFile));
    RemoveKernelHook("VirtualAllocEx",
                     &g_virtualAllocExTarget,
                     &g_virtualAllocExHooked,
                     reinterpret_cast<void**>(&g_origVirtualAllocEx));
    RemoveKernelHook("VirtualAlloc",
                     &g_virtualAllocTarget,
                     &g_virtualAllocHooked,
                     reinterpret_cast<void**>(&g_origVirtualAlloc));
    RemoveKernelHook("VirtualProtectEx",
                     &g_virtualProtectExTarget,
                     &g_virtualProtectExHooked,
                     reinterpret_cast<void**>(&g_origVirtualProtectEx));
    RemoveKernelHook("VirtualProtect",
                     &g_virtualProtectTarget,
                     &g_virtualProtectHooked,
                     reinterpret_cast<void**>(&g_origVirtualProtect));
}

static void HookSendBuilderFromNetMgr()
{
    if (g_builderScanned || !g_state)
        return;

    DWORD now = GetTickCount();
    if (g_nextNetCfgProbeTick != 0 && !TickHasElapsed(now, g_nextNetCfgProbeTick))
        return;
    g_nextNetCfgProbeTick = 0;

    void* rawCfg = g_state->networkConfig;
    if (!rawCfg) {
        if (!g_loggedNetScanFailure) {
            g_loggedNetScanFailure = true;
            WriteRawLog("HookSendBuilderFromNetMgr: networkConfig pointer is null");
        }
        Util::RegionWatch::ClearWatch();
        TryDiscoverFromEngineContext();
        return;
    }

    if (rawCfg != g_lastNetCfgPtr) {
        g_lastNetCfgPtr = rawCfg;
        g_lastNetCfgState = 0xFFFFFFFF;
        g_lastNetCfgProtect = 0xFFFFFFFF;
        g_lastNetCfgType = 0xFFFFFFFF;
        g_lastNetCfgBase = nullptr;
        g_lastNetCfgRegionSize = 0;
        g_haveNetCfgSnapshot = false;
        g_lastLoggedManager = nullptr;
        g_lastLoggedEndpoint = nullptr;
        Util::RegionWatch::SetWatchPointer(rawCfg);
        char buf[128];
        sprintf_s(buf, sizeof(buf), "HookSendBuilderFromNetMgr: networkConfig pointer changed -> %p", rawCfg);
        WriteRawLog(buf);
    }

    uintptr_t snapshot[4]{};
    if (!SafeCopy(snapshot, rawCfg, sizeof(snapshot))) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(rawCfg, &mbi, sizeof(mbi))) {
            if (!g_loggedNetScanFailure || g_lastNetCfgState != 0xFFFFFFFE) {
                char buf[200];
                sprintf_s(buf, sizeof(buf),
                          "HookSendBuilderFromNetMgr: VirtualQuery failed for %p (error %lu)",
                          rawCfg,
                          GetLastError());
                WriteRawLog(buf);
            }
            g_loggedNetScanFailure = true;
            g_lastNetCfgState = 0xFFFFFFFE;
            return;
        }

        bool stateChanged = (mbi.State != g_lastNetCfgState) ||
                            (mbi.Protect != g_lastNetCfgProtect) ||
                            (mbi.Type != g_lastNetCfgType) ||
                            (mbi.BaseAddress != g_lastNetCfgBase) ||
                            (mbi.RegionSize != g_lastNetCfgRegionSize);
        Util::RegionWatch::UpdateRegionInfo(mbi);
        if (stateChanged) {
            char buf[256];
            sprintf_s(buf, sizeof(buf),
                      "HookSendBuilderFromNetMgr: cfg=%p region base=%p size=0x%zx state=0x%08lX protect=0x%08lX type=0x%08lX",
                      rawCfg,
                      mbi.BaseAddress,
                      mbi.RegionSize,
                      mbi.State,
                      mbi.Protect,
                      mbi.Type);
            WriteRawLog(buf);
            g_lastNetCfgState = mbi.State;
            g_lastNetCfgProtect = mbi.Protect;
            g_lastNetCfgType = mbi.Type;
            g_lastNetCfgBase = mbi.BaseAddress;
            g_lastNetCfgRegionSize = mbi.RegionSize;
        }
        const DWORD readableMask = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE;
        bool readable = (mbi.State == MEM_COMMIT) && !(mbi.Protect & PAGE_GUARD) && (mbi.Protect & readableMask);
        if (!readable) {
            if (!g_loggedNetScanFailure) {
                Log::Logf(Log::Level::Info,
                          Log::Category::Core,
                          "[CORE][SB] networkConfig pending protect=0x%08lX state=0x%08lX; deferring scan",
                          static_cast<unsigned long>(mbi.Protect),
                          static_cast<unsigned long>(mbi.State));
            }
            g_loggedNetScanFailure = true;
            DWORD jitter = 50u + (now % 51u);
            g_nextNetCfgProbeTick = now + jitter;
            return;
        }

        // Region is committed but SafeCopy failed; try again below to capture exception info.
        if (!SafeCopy(snapshot, rawCfg, sizeof(snapshot))) {
            if (!g_loggedNetScanFailure) {
                Log::Logf(Log::Level::Info,
                          Log::Category::Core,
                          "[CORE][SB] networkConfig access fault; deferring scan");
            }
            g_loggedNetScanFailure = true;
            DWORD jitter = 50u + ((now >> 1) % 51u);
            g_nextNetCfgProbeTick = now + jitter;
            return;
        }
    }

    if (!g_haveNetCfgSnapshot || memcmp(g_lastNetCfgSnapshot, snapshot, sizeof(snapshot)) != 0) {
        char infoBuf[256];
        sprintf_s(infoBuf, sizeof(infoBuf),
                  "HookSendBuilderFromNetMgr snapshot cfg=%p slots={%p,%p,%p,%p}",
                  rawCfg,
                  reinterpret_cast<void*>(snapshot[0]),
                  reinterpret_cast<void*>(snapshot[1]),
                  reinterpret_cast<void*>(snapshot[2]),
                  reinterpret_cast<void*>(snapshot[3]));
        WriteRawLog(infoBuf);
        memcpy(g_lastNetCfgSnapshot, snapshot, sizeof(g_lastNetCfgSnapshot));
        g_haveNetCfgSnapshot = true;
    }
    g_loggedNetScanFailure = false;

    if (g_netMgr) {
        EnsureManagerSelection(g_state);
        ExecuteManagerScanSequence();
    }

    MEMORY_BASIC_INFORMATION mbiCurrent{};
    if (VirtualQuery(rawCfg, &mbiCurrent, sizeof(mbiCurrent))) {
        bool changed = (mbiCurrent.State != g_lastNetCfgState) ||
                       (mbiCurrent.Protect != g_lastNetCfgProtect) ||
                       (mbiCurrent.Type != g_lastNetCfgType) ||
                       (mbiCurrent.BaseAddress != g_lastNetCfgBase) ||
                       (mbiCurrent.RegionSize != g_lastNetCfgRegionSize);
        Util::RegionWatch::UpdateRegionInfo(mbiCurrent);
        if (changed) {
            char buf[256];
            sprintf_s(buf, sizeof(buf),
                      "HookSendBuilderFromNetMgr: cfg=%p region state=0x%08lX protect=0x%08lX type=0x%08lX base=%p size=0x%zx",
                      rawCfg,
                      mbiCurrent.State,
                      mbiCurrent.Protect,
                      mbiCurrent.Type,
                      mbiCurrent.BaseAddress,
                      mbiCurrent.RegionSize);
            WriteRawLog(buf);
            g_lastNetCfgState = mbiCurrent.State;
            g_lastNetCfgProtect = mbiCurrent.Protect;
            g_lastNetCfgType = mbiCurrent.Type;
            g_lastNetCfgBase = mbiCurrent.BaseAddress;
            g_lastNetCfgRegionSize = mbiCurrent.RegionSize;
        }
    }
    else if (g_lastNetCfgState != 0xFFFFFFFD) {
        char buf[200];
        sprintf_s(buf, sizeof(buf),
                  "HookSendBuilderFromNetMgr: VirtualQuery later failed for %p (error %lu)",
                  rawCfg,
                  GetLastError());
        WriteRawLog(buf);
        g_lastNetCfgState = 0xFFFFFFFD;
    }

    void* managerCandidate = reinterpret_cast<void*>(snapshot[0]);
    if (managerCandidate && managerCandidate != g_lastLoggedManager) {
        uintptr_t vtbl = 0;
        bool managerOk = ValidateManagerPointer(managerCandidate, nullptr);
        if (SafeCopy(&vtbl, managerCandidate, sizeof(vtbl)) && vtbl && managerOk) {
            char mgrBuf[160];
            sprintf_s(mgrBuf, sizeof(mgrBuf), "HookSendBuilderFromNetMgr: manager=%p vtbl=%p",
                      managerCandidate, reinterpret_cast<void*>(vtbl));
            WriteRawLog(mgrBuf);
            CaptureNetManager(managerCandidate, "networkConfig[0]");
            g_lastLoggedManager = managerCandidate;
            TryHookSendBuilder(managerCandidate);
        } else if (!managerOk) {
            LogGuardInvalidManager(managerCandidate);
        }
    }

    if (!g_builderScanned) {
        void* endpointCandidate = reinterpret_cast<void*>(snapshot[1]);
        if (endpointCandidate && endpointCandidate != g_lastLoggedEndpoint) {
            uintptr_t vtbl = 0;
            if (SafeCopy(&vtbl, endpointCandidate, sizeof(vtbl)) && vtbl) {
                char endpointBuf[160];
                sprintf_s(endpointBuf, sizeof(endpointBuf), "HookSendBuilderFromNetMgr: endpoint=%p vtbl=%p",
                          endpointCandidate, reinterpret_cast<void*>(vtbl));
                WriteRawLog(endpointBuf);
                g_lastLoggedEndpoint = endpointCandidate;
                CaptureSendContext(endpointCandidate, "networkConfig[1]");
                TryHookSendBuilder(endpointCandidate);
            }
        }
    }
}

static void ScanSendBuilder()
{
    HookSendBuilderFromNetMgr();
}

static void __fastcall H_SendPacket(void* thisPtr, void*, const void* pkt, int len)
{
    void* returnPc = _ReturnAddress();
    g_sendRing.push(returnPc, HashPointer(returnPc));
    if (Log::IsEnabled(Log::Level::Debug)) {
        char pcLabel[128];
        FormatModuleOffset(returnPc, pcLabel, sizeof(pcLabel));
        Log::Logf(Log::Level::Debug,
                  Log::Category::Core,
                  "[SB][RING] push tid=%lu pc=%s",
                  static_cast<unsigned long>(GetCurrentThreadId()),
                  pcLabel);
    }

    const bool isDebugNudge = t_debugNudgeCall;

    if (pkt && len > 0 && Net::IsSendSamplingEnabled()) {
        const std::uint64_t nowMs = static_cast<std::uint64_t>(GetTickCount64());
        if (Scanner::Sampler::shouldSample(nowMs)) {
            void* frames[kMaxFingerprintFrames] = {};
            USHORT captured = RtlCaptureStackBackTrace(0, kMaxFingerprintFrames, frames, nullptr);
            if (captured > 0)
                Net::SubmitSendSample(thisPtr, frames, captured, nowMs);
        }
    }

    constexpr const char* kSendTag = "H_SendPacket";
    CaptureSendContext(thisPtr, kSendTag);
    CaptureNetManager(thisPtr, kSendTag);
    if (!g_builderScanned)
        HookSendBuilderFromNetMgr();
    LONG previous = InterlockedExchange(&g_needWalkReg, 0);
    if (previous != 0)
        Engine::Lua::ScheduleWalkBinding();
    if (!isDebugNudge)
        g_sendPacket(thisPtr, pkt, len);
}

static void FindSendPacket()
{
    const char* kSig = "51 53 55 56 57 8B F1";
    BYTE* hit = FindPatternText(kSig);
    if (hit)
    {
        g_sendPacketTarget = hit;
        char buf[64];
        sprintf_s(buf, sizeof(buf), "Found SendPacket at %p", hit);
        WriteRawLog(buf);
    }
    else
    {
        WriteRawLog("SendPacket signature not found");
    }
}

static void HookSendPacket()
{
    if (!g_sendPacketHooked && g_sendPacketTarget)
    {
        if (MH_CreateHook(g_sendPacketTarget, H_SendPacket, reinterpret_cast<LPVOID*>(&g_sendPacket)) == MH_OK &&
            MH_EnableHook(g_sendPacketTarget) == MH_OK)
        {
            g_sendPacketHooked = true;
            Scanner::Sampler::reset(GetTickCount64());
            WriteRawLog("SendPacket hook installed");
            MaybeSendDebugNudge();
        }
    }
}

bool InitSendBuilder(GlobalStateInfo* state)
{
    bool stateChanged = state != g_state;
    if (stateChanged) {
        g_state = state;
        if (state) {
            g_netMgr = nullptr;
            g_sendCtx = nullptr;
            g_builderScanned = false;
            g_loggedNetScanFailure = false;
            g_haveNetCfgSnapshot = false;
            memset(g_lastNetCfgSnapshot, 0, sizeof(g_lastNetCfgSnapshot));
            g_lastLoggedManager = nullptr;
            g_lastLoggedEndpoint = nullptr;
            g_loggedEngineUnstable = false;
            g_lastEngineUnstableLogTick = 0;
            g_lastBuilderScanTick = 0;
            g_helperWaitStartTick = 0;
            g_helperBypassWarningLogged = false;
            g_vtblSlotCache.clear();
            g_skipWarnedVtables.clear();
            {
                std::lock_guard<std::mutex> lock(g_endpointBackoffMutex);
                g_endpointBackoff.clear();
            }
            {
                std::lock_guard<std::mutex> lock(g_managerGuardLogMutex);
                g_managerGuardLog.clear();
            }
            g_nextNetCfgProbeTick = 0;
            g_managerRegionBase = 0;
            g_managerRegionSize = 0;
            g_debugNudgePending.store(false, std::memory_order_relaxed);
            g_debugNudgeSent.store(false, std::memory_order_relaxed);
            g_initTickMs64 = GetTickCount64();
            g_firstScanTickMs64 = 0;
            g_managerTargetValid = false;
            ResetVtblSuppressions();
        }
        else {
            g_initTickMs64 = 0;
            g_firstScanTickMs64 = 0;
        }
        Scanner::Sampler::reset(GetTickCount64());
        g_sendRing.clear();
        g_lastRingLoad.store(0, std::memory_order_relaxed);
        g_sendSampleStore.Reset();

        g_lastPollTick = 0;
    }

    bool sbDebug = ResolveSendBuilderFlag("SB_DEBUG", "sb.debug", false);
    g_sbDebug.store(sbDebug, std::memory_order_relaxed);
    bool sendRingDebug = ResolveSendBuilderFlag("UOWP_SENDRING_DEBUG", "sb.sendRingDebug", false);
    g_sendRingDebug.store(sendRingDebug, std::memory_order_relaxed);
    if (!sendRingDebug)
        g_lastSendRingDebugTick.store(0, std::memory_order_relaxed);

    bool sbDebugNudge = ResolveSendBuilderFlag("SB_DEBUG_NUDGE", "sb.debug_nudge", false);
    g_sbDebugNudge.store(sbDebugNudge, std::memory_order_relaxed);
    if (!sbDebugNudge) {
        g_debugNudgePending.store(false, std::memory_order_relaxed);
    }

    bool regionWatchEnabled = ResolveSendBuilderFlag("SB_REGION_WATCH", "sb.regionWatch", true);
    Util::RegionWatch::SetEnabled(regionWatchEnabled);
    Util::RegionWatch::SetCallback([]() {
        ScanSendBuilder();
    });
    const void* defaultNetCfgPage = reinterpret_cast<void*>(0x310A0000);
    if (state && state->networkConfig) {
        Util::RegionWatch::SetWatchPointer(state->networkConfig);
    } else {
        Util::RegionWatch::SetWatchPointer(const_cast<void*>(defaultNetCfgPage));
    }

    bool samplingEnabled = ResolveSendBuilderFlag("SB_SEND_SAMPLING", "sb.sendSampling", true);
    g_sendSamplingEnabled.store(samplingEnabled, std::memory_order_relaxed);
    if (!samplingEnabled) {
        Scanner::Sampler::reset(GetTickCount64());
        g_sendRing.clear();
        g_lastRingLoad.store(0, std::memory_order_relaxed);
        g_sendSampleStore.Reset();
    }

    bool requireSamples = ResolveSendBuilderFlag("SB_REQUIRE_SAMPLE", "sb.requireSendSample", true);
    g_requireSendSample.store(requireSamples, std::memory_order_relaxed);
    g_allowDbProbe = ResolveSendBuilderFlag("SB_ALLOW_DB_PROBE", "sb.allow_db_probe", false);

    if (!g_initLogged || stateChanged) {
        char initBuf[160];
        sprintf_s(initBuf, sizeof(initBuf),
                  "InitSendBuilder invoked state=%p networkConfig=%p",
                  state,
                  state ? state->networkConfig : nullptr);
        WriteRawLog(initBuf);
        g_initLogged = true;
    }

    EnsureManagerSelection(g_state);

    EnsureMemoryHooks();

    if (!g_sendPacketTarget)
        FindSendPacket();
    HookSendPacket();
    HookSendBuilderFromNetMgr();
    g_stage3Controller.reset();
    return g_sendPacketHooked;
}

void PollSendBuilder()
{
    if (!g_state)
        return;

    DWORD now = GetTickCount();
    if (g_sendRingDebug.load(std::memory_order_relaxed)) {
        DWORD last = g_lastSendRingDebugTick.load(std::memory_order_relaxed);
        if (last == 0 || (now - last) >= 5000) {
            g_lastSendRingDebugTick.store(now, std::memory_order_relaxed);
            const std::uint32_t ringSize = static_cast<std::uint32_t>(g_sendRing.size());
            const std::uint64_t ageUs = g_sendRing.newest_age_us();
            Log::Logf(Log::Level::Debug,
                      Log::Category::Core,
                      "[CORE][SR] size=%u age_us=%llu",
                      ringSize,
                      static_cast<unsigned long long>(ageUs));
        }
    }
    // Stage-3: dynamic poll delay driven by pass controller.
    DWORD delay = g_stage3Controller.currentDelayMs();
    DWORD last = g_lastPollTick;
    if (last != 0 && (DWORD)(now - last) < delay)
        return;
    g_lastPollTick = now;

    if (g_netMgr && g_builderScanned)
        return;

    bool gatingActive = (g_nextNetCfgProbeTick != 0 && !TickHasElapsed(now, g_nextNetCfgProbeTick));

    if (!g_netMgr && !gatingActive)
        TryDiscoverFromEngineContext();

    if (g_netMgr && !g_builderScanned && !gatingActive) {
        EnsureManagerSelection(g_state);
        ExecuteManagerScanSequence();
    }

    if (!g_sendPacketTarget)
        FindSendPacket();
    HookSendPacket();
    HookSendBuilderFromNetMgr();
}

void GetSendBuilderProbeStats(uint32_t& attempted, uint32_t& succeeded, uint32_t& skipped)
{
    attempted = g_builderProbeAttempted.load(std::memory_order_acquire);
    succeeded = g_builderProbeSuccess.load(std::memory_order_acquire);
    skipped = g_builderProbeSkipped.load(std::memory_order_acquire);
}

void ShutdownSendBuilder()
{
    if (g_sendPacketHooked && g_sendPacketTarget)
    {
        MH_DisableHook(g_sendPacketTarget);
        MH_RemoveHook(g_sendPacketTarget);
        g_sendPacketHooked = false;
    }
    if (g_sendBuilderHooked && g_sendBuilderTarget)
    {
        MH_DisableHook(g_sendBuilderTarget);
        MH_RemoveHook(g_sendBuilderTarget);
    }
    g_sendBuilderHooked = false;
    g_sendBuilderTarget = nullptr;
    fpSendBuilder = nullptr;
    g_builderScanned = false;
    RemoveMemoryHooks();
    g_sendCtx = nullptr;
    g_netMgr = nullptr;
    g_state = nullptr;
    g_sendRingDebug.store(false, std::memory_order_relaxed);
    g_lastSendRingDebugTick.store(0, std::memory_order_relaxed);
    g_lastManagerScanPtr = nullptr;
    g_lastManagerScanTick = 0;
    g_loggedEngineUnstable = false;
    g_lastEngineUnstableLogTick = 0;
    g_lastBuilderScanTick = 0;
    g_helperWaitStartTick = 0;
    g_helperBypassWarningLogged = false;
    g_vtblSlotCache.clear();
    g_skipWarnedVtables.clear();
    {
        std::lock_guard<std::mutex> lock(g_endpointBackoffMutex);
        g_endpointBackoff.clear();
    }
    {
        std::lock_guard<std::mutex> lock(g_managerGuardLogMutex);
        g_managerGuardLog.clear();
    }
    g_nextNetCfgProbeTick = 0;
    g_managerRegionBase = 0;
    g_managerRegionSize = 0;

    g_lastPollTick = 0;
    Scanner::Sampler::reset(GetTickCount64());
    g_sendRing.clear();
    g_lastRingLoad.store(0, std::memory_order_relaxed);
    g_sendSampleStore.Reset();
    Util::RegionWatch::ClearWatch();
    g_stage3Controller.reset();
}

bool SendPacketRaw(const void* bytes, int len, SOCKET socketHint)
{
    if (len <= 0 || !bytes)
        return false;

    if (TrySendViaSocket(bytes, len, "SendPacketRaw via socket (preferred)", socketHint))
        return true;
    if (!g_sendPacket)
        return TrySendViaSocket(bytes, len, "SendPacketRaw via socket (no sendCtx)", socketHint);

    void* sendCtx = g_sendCtx ? g_sendCtx : g_netMgr;
    if (!sendCtx)
        return false;

    static volatile LONG s_attemptLogBudget = 64;
    if (s_attemptLogBudget > 0 && InterlockedDecrement(&s_attemptLogBudget) >= 0) {
        char status[200];
        sprintf_s(status, sizeof(status),
                  "SendPacketRaw attempt len=%d sendCtx=%p netMgr=%p sendTarget=%p",
                  len,
                  sendCtx,
                  g_netMgr,
                  g_sendPacketTarget);
        WriteRawLog(status);
    }

    void* vtbl = nullptr;
    if (!SafeCopy(&vtbl, sendCtx, sizeof(vtbl)) || !vtbl) {
        WriteRawLog("SendPacketRaw: send context pointer not readable");
        return false;
    }
    void* vtblEntry = nullptr;
    if (!SafeCopy(&vtblEntry, vtbl, sizeof(vtblEntry))) {
        WriteRawLog("SendPacketRaw: failed to read vtable[0]");
    }
    bool entryExecutable = IsExecutableCodeAddress(vtblEntry);
    if (!entryExecutable) {
        char warn[200];
        sprintf_s(warn, sizeof(warn),
                  "SendPacketRaw warning: vtable entry not executable vtbl=%p entry=%p",
                  vtbl,
                  vtblEntry);
        WriteRawLog(warn);
    }

    g_lastSendAttempt.sendCtx = sendCtx;
    g_lastSendAttempt.vtbl = vtbl;
    g_lastSendAttempt.vtblFirstEntry = vtblEntry;
    g_lastSendAttempt.vtblEntryExecutable = entryExecutable;
    g_lastSendAttempt.payload = bytes;
    g_lastSendAttempt.payloadLen = len;
    g_lastSendAttempt.sendPacketFn = reinterpret_cast<void*>(g_sendPacket);
    g_lastSendAttempt.sendPacketTarget = g_sendPacketTarget;

    bool sent = false;
    __try {
        g_sendPacket(sendCtx, bytes, len);
        sent = true;
    }
    __except (SendPacketExceptionFilter(GetExceptionCode(), GetExceptionInformation())) {
        sent = false;
    }
    if (sent) {
        static volatile LONG s_successLogBudget = 64;
        if (s_successLogBudget > 0 && InterlockedDecrement(&s_successLogBudget) >= 0) {
            char status[160];
            sprintf_s(status, sizeof(status),
                      "SendPacketRaw succeeded len=%d", len);
            WriteRawLog(status);
        }
    }
    else if (TrySendViaSocket(bytes, len, "SendPacketRaw via socket fallback", socketHint)) {
        return true;
    }
    return sent;
}

bool IsSendReady()
{
    return g_sendPacket && (g_sendCtx || g_netMgr);
}

SendBuilderStatus GetSendBuilderStatus()
{
    SendBuilderStatus status{};
    status.hooked = g_sendBuilderHooked;
    status.sendPacket = g_sendPacketTarget;
    bool haveManager = g_netMgr != nullptr || g_sendCtx != nullptr;
    bool activelyScanning = !g_builderScanned || HasEndpointBackoff() || g_nextNetCfgProbeTick != 0;
    status.probing = !status.hooked && (haveManager || activelyScanning);
    return status;
}

Scanner::ScanPassTelemetry DumpLastPassTelemetry()
{
    std::lock_guard<std::mutex> lock(g_lastTelemetryMutex);
    return g_lastTelemetry;
}


bool IsSendBuilderAttached()
{
    return g_sendBuilderHooked;
}

void OnEngineReady()
{
    if (!g_sbDebugNudge.load(std::memory_order_acquire))
        return;
    if (g_debugNudgeSent.load(std::memory_order_acquire))
        return;
    g_debugNudgePending.store(true, std::memory_order_release);
    MaybeSendDebugNudge();
}

void NotifyCanonicalManagerDiscovered()
{
    EnsureCanonicalVtblWhitelisted();
}


} // namespace Net\n
