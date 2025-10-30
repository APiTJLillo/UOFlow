#include <windows.h>
#include <winsock2.h>
#include <psapi.h>
#include <minhook.h>
#include <cstdint>
#include <cstdio>
#include <cstddef>
#include <cstring>
#include <deque>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <string>
#include <algorithm>
#include <vector>

#include "Core/Logging.hpp"
#include "Core/Config.hpp"
#include "Core/Utils.hpp"
#include "Core/PatternScan.hpp"
#include "Net/SendBuilder.hpp"
#include "Engine/Movement.hpp"
#include "Engine/LuaBridge.hpp"
#include "Walk/WalkController.hpp"

// Move variable definition to global scope
extern volatile LONG g_needWalkReg;

namespace {

struct Vec3 { int16_t x, y; int8_t z; };

static bool g_moveSafeDumpEnabled = false;
static uint32_t g_fastWalkAssocWindowMs = 250;
static std::once_flag g_movementConfigOnce;

static void* g_moveComp = nullptr; // movement component instance
static void* g_moveCandidate = nullptr;
static void* g_dest = nullptr;     // last destination vector
using UpdateState_t = uint32_t(__thiscall*)(void*, void*, uint32_t, int);
static UpdateState_t g_updateState = nullptr;
static UpdateState_t g_origUpdate = nullptr;
static volatile LONG g_haveMoveComp = 0;
static long g_updateLogCount = 0;
static thread_local int g_updateDepth = 0;
static constexpr size_t kFastWalkQueueCapacity = 16;
static constexpr size_t kFastWalkNominalDepth = 16;
static std::mutex g_fastWalkMutex;
static std::unordered_map<SOCKET, std::deque<uint32_t>> g_fastWalkQueues;
static std::unordered_map<SOCKET, int> g_fastWalkExpectedDepth;
struct FastWalkKeyRecord {
    uint32_t key = 0;
    uint64_t tickMs = 0;
    int depthBefore = 0;
    int depthAfter = 0;
    bool consumed = false;
    bool warned = false;
};
static std::unordered_map<SOCKET, std::deque<FastWalkKeyRecord>> g_fastWalkKeyHistory;
static std::unordered_map<SOCKET, SOCKET> g_socketAliases;
static constexpr uint32_t kFastWalkWarningWindowMs = 500;
static constexpr uint64_t kFastWalkHistoryTtlMs = 2000;
static constexpr size_t kFastWalkHistoryLimit = 32;
static SOCKET g_activeFastWalkSocket = INVALID_SOCKET;
static std::atomic<uint64_t> g_fwKeysInbound{0};
static std::atomic<uint64_t> g_fwKeysOutbound{0};
static std::atomic<uint64_t> g_fwResyncs{0};
static std::atomic<uint64_t> g_fwMisses{0};
static std::atomic<uint32_t> g_fwDepth{0};
static std::atomic<uint64_t> g_walkStepsSent{0};
static uint32_t g_lastIndexHead = 0;
static uint32_t g_lastIndexTail = 0;
static uint32_t g_lastProbeAttemptKey = 0;
static uint32_t g_lastLoggedCandidateKey = 0;
static volatile LONG g_fastWalkProbeBudget = 64;
static int g_fastWalkStorageOffset = -1;

static SOCKET ResolveSocketAliasLocked(SOCKET socket);
static SOCKET SelectNextActiveSocketLocked();

static void PruneOldFastWalkKeysLocked(SOCKET socket, uint64_t now) {
    auto it = g_fastWalkKeyHistory.find(socket);
    if (it == g_fastWalkKeyHistory.end())
        return;
    auto& history = it->second;
    while (!history.empty() && now - history.front().tickMs > kFastWalkHistoryTtlMs)
        history.pop_front();
    if (history.empty())
        g_fastWalkKeyHistory.erase(it);
}

static void RecordFastWalkKeyLocked(SOCKET socket, uint32_t key, int depthBefore, int depthAfter, uint64_t tickMs) {
    FastWalkKeyRecord record{};
    record.key = key;
    record.tickMs = tickMs;
    record.depthBefore = depthBefore;
    record.depthAfter = depthAfter;
    auto& history = g_fastWalkKeyHistory[socket];
    if (history.size() >= kFastWalkHistoryLimit)
        history.pop_front();
    history.push_back(record);
    PruneOldFastWalkKeysLocked(socket, tickMs);
}

static void ResyncFastWalkLocked(SOCKET socket,
                                 uint32_t headIndex,
                                 uint32_t tailIndex,
                                 uint64_t now,
                                 const char* reason) {
    size_t dropped = 0;
    if (socket != INVALID_SOCKET) {
        auto queueIt = g_fastWalkQueues.find(socket);
        if (queueIt != g_fastWalkQueues.end()) {
            dropped = queueIt->second.size();
            g_fastWalkQueues.erase(queueIt);
        }
        g_fastWalkKeyHistory.erase(socket);
        g_fastWalkExpectedDepth.erase(socket);
        for (auto it = g_socketAliases.begin(); it != g_socketAliases.end();) {
            if (it->first == socket || it->second == socket)
                it = g_socketAliases.erase(it);
            else
                ++it;
        }
    } else {
        for (const auto& entry : g_fastWalkQueues)
            dropped += entry.second.size();
        g_fastWalkQueues.clear();
        g_fastWalkKeyHistory.clear();
        g_fastWalkExpectedDepth.clear();
        g_socketAliases.clear();
    }

    g_activeFastWalkSocket = SelectNextActiveSocketLocked();
    g_fwDepth.store(0, std::memory_order_relaxed);
    g_fwResyncs.fetch_add(1, std::memory_order_relaxed);
    g_lastIndexHead = headIndex;
    g_lastIndexTail = tailIndex;
    InterlockedExchange(&g_fastWalkProbeBudget, 64);
    g_fastWalkStorageOffset = -1;
    g_lastProbeAttemptKey = 0;
    g_lastLoggedCandidateKey = 0;

    if (reason) {
        Log::Logf(Log::Level::Info,
                  Log::Category::FastWalk,
                  "FastWalk resync reason=%s socket=%p dropped=%zu head=%u tail=%u",
                  reason,
                  reinterpret_cast<void*>(static_cast<uintptr_t>(socket)),
                  dropped,
                  headIndex,
                  tailIndex);
    }
}

static void ResyncFastWalkForProbeMiss(uint32_t key) {
    std::lock_guard<std::mutex> lock(g_fastWalkMutex);
    SOCKET target = INVALID_SOCKET;
    for (const auto& entry : g_fastWalkKeyHistory) {
        for (const auto& record : entry.second) {
            if (record.key == key) {
                target = entry.first;
                break;
            }
        }
        if (target != INVALID_SOCKET)
            break;
    }
    ResyncFastWalkLocked(target, g_lastIndexHead, g_lastIndexTail, GetTickCount64(), "probe-miss");
    g_fwMisses.fetch_add(1, std::memory_order_relaxed);
}

static bool FetchRecentFastWalkKeyLocked(SOCKET socket, uint64_t now, uint32_t windowMs, FastWalkKeyRecord* outRecord) {
    auto it = g_fastWalkKeyHistory.find(socket);
    if (it == g_fastWalkKeyHistory.end())
        return false;
    const auto& history = it->second;
    for (auto rit = history.rbegin(); rit != history.rend(); ++rit) {
        if (rit->consumed)
            continue;
        if (now >= rit->tickMs && now - rit->tickMs <= windowMs) {
            if (outRecord)
                *outRecord = *rit;
            return true;
        }
        if (now > rit->tickMs && now - rit->tickMs > windowMs)
            break;
    }
    return false;
}

static void MarkFastWalkKeyConsumedLocked(SOCKET socket, uint32_t key, uint64_t now) {
    auto it = g_fastWalkKeyHistory.find(socket);
    if (it == g_fastWalkKeyHistory.end())
        return;
    auto& history = it->second;
    bool matched = false;
    if (key != 0) {
        for (auto rit = history.rbegin(); rit != history.rend(); ++rit) {
            if (rit->key == key) {
                if (!rit->consumed) {
                    rit->consumed = true;
                    rit->warned = false;
                }
                matched = true;
                break;
            }
        }
    }
    if (!matched) {
        for (auto& record : history) {
            if (!record.consumed) {
                record.consumed = true;
                record.warned = false;
                break;
            }
        }
    }
    PruneOldFastWalkKeysLocked(socket, now);
}

static void CheckFastWalkTimeoutsLocked(SOCKET socket, uint32_t headIndex, uint32_t tailIndex, uint64_t now) {
    auto it = g_fastWalkKeyHistory.find(socket);
    if (it == g_fastWalkKeyHistory.end())
        return;

    auto& history = it->second;
    bool emitted = false;
    uint64_t maxAge = 0;
    for (auto& record : history) {
        if (!record.consumed && !record.warned) {
            uint64_t age = (now >= record.tickMs) ? (now - record.tickMs) : 0;
            if (age > maxAge)
                maxAge = age;
            if (age > kFastWalkWarningWindowMs) {
                record.warned = true;
                emitted = true;
            }
        }
    }

    if (emitted) {
        char keyBuf[64] = {};
        int offset = 0;
        size_t count = 0;
        for (auto rit = history.rbegin(); rit != history.rend() && count < 3; ++rit, ++count) {
            offset += sprintf_s(keyBuf + offset,
                                sizeof(keyBuf) - offset,
                                "%s0x%08X",
                                count ? "," : "",
                                rit->key);
            if (offset < 0 || static_cast<size_t>(offset) >= sizeof(keyBuf))
                break;
        }
        Log::Logf(Log::Level::Warn,
                  Log::Category::FastWalk,
                  "FastWalk key delay socket=%p headIdx=%u tailIdx=%u latestAgeMs=%llu recentKeys=[%s]",
                  reinterpret_cast<void*>(static_cast<uintptr_t>(socket)),
                  headIndex,
                  tailIndex,
                  static_cast<unsigned long long>(maxAge),
                  (offset > 0) ? keyBuf : "<none>");
        g_fwMisses.fetch_add(1, std::memory_order_relaxed);
        ResyncFastWalkLocked(socket, headIndex, tailIndex, now, "delay");
    }

    PruneOldFastWalkKeysLocked(socket, now);
}

static void CheckFastWalkTimeoutsAllLocked(uint32_t headIndex, uint32_t tailIndex, uint64_t now) {
    if (g_fastWalkKeyHistory.empty())
        return;
    std::vector<SOCKET> sockets;
    sockets.reserve(g_fastWalkKeyHistory.size());
    for (const auto& entry : g_fastWalkKeyHistory)
        sockets.push_back(entry.first);
    for (SOCKET socket : sockets)
        CheckFastWalkTimeoutsLocked(socket, headIndex, tailIndex, now);
}

static bool TryAssociateFastWalkWithMovement(uint32_t headIndex,
                                             uint32_t tailIndex,
                                             uint64_t now,
                                             bool consumeKey,
                                             SOCKET* outSocket,
                                             FastWalkKeyRecord* outRecord) {
    std::lock_guard<std::mutex> lock(g_fastWalkMutex);
    SOCKET socket = ResolveSocketAliasLocked(g_activeFastWalkSocket);
    if (socket == INVALID_SOCKET)
        socket = SelectNextActiveSocketLocked();
    g_activeFastWalkSocket = socket;

    if (outSocket)
        *outSocket = socket;

    bool matched = false;
    if (socket != INVALID_SOCKET && consumeKey && outRecord) {
        matched = FetchRecentFastWalkKeyLocked(socket, now, g_fastWalkAssocWindowMs, outRecord);
        if (matched)
            MarkFastWalkKeyConsumedLocked(socket, outRecord->key, now);
    }

    CheckFastWalkTimeoutsAllLocked(headIndex, tailIndex, now);
    return matched;
}
static volatile LONG g_fwOverflowWarned = 0;
static Vec3 g_expectedDest{};
static volatile LONG g_expectValid = 0;
static volatile LONG g_pendingMoveActive = 0;
static volatile LONG g_pendingTick = 0;
static volatile LONG g_pendingDir = 0;
static volatile LONG g_pendingRunFlag = 0;
static volatile LONG g_lastObservedNetworkKey = 0;
static std::atomic<uint8_t> g_lastAckSeq{0};
static std::atomic<uint8_t> g_lastSentSeq{0};
static std::atomic<bool> g_haveAckSeq{false};
static std::atomic<bool> g_haveSentSeq{false};
static std::atomic<bool> g_clientMovementSendObserved{false};
static std::atomic<bool> g_movementWatchdogArmed{false};
static std::atomic<DWORD> g_movementWatchdogStartTick{0};
static thread_local bool g_scriptSendInProgress = false;
static std::atomic<uint32_t> g_lastMovementSendTickMs{0};
static constexpr DWORD kMovementAckThrottleMs = 800;
static volatile LONG g_sendThrottleLogBudget = 8;
static void* g_candidateDest = nullptr;
static volatile LONG g_localEnqueueFailBudget = 8;

static constexpr int kStepDx[8] = {0, 1, 1, 1, 0, -1, -1, -1};
static constexpr int kStepDy[8] = {-1, -1, 0, 1, 1, 1, 0, -1};
static constexpr DWORD kPendingWindowMs = 500;
static constexpr size_t kMaxTrackers = 96;
static constexpr size_t kDestCopySize = 0x200;
static constexpr int kPtrDiffLogLimit = 128;
static constexpr int kIndexSampleLimit = 32;
static constexpr size_t kQueueEntrySize = 0x10;
struct MovementTracker {
    void* instance;
    Vec3 lastDest;
    DWORD lastTick;
    bool hasDest;
};

static MovementTracker g_trackers[kMaxTrackers]{};
static size_t g_trackerCount = 0;
static int g_trackerLogBudget = 8;
static volatile LONG g_memDumpBudget = 4;
static uint8_t g_lastCompPtrSnapshot[kDestCopySize]{};
static bool g_haveCompPtrSnapshot = false;
static int g_ptrDiffLogBudget = kPtrDiffLogLimit;
static int g_savedIndexBudget = kIndexSampleLimit;
static uint8_t g_lastHeadEntry[kQueueEntrySize]{};
static uint8_t g_lastTailEntry[kQueueEntrySize]{};
static bool g_haveHeadEntry = false;
static bool g_haveTailEntry = false;
static void** g_loggedVtable = nullptr;

struct ECMoveCompSnapshot {
    uint32_t head = 0;
    uint32_t tail = 0;
    uint32_t stateFlags = 0;
    float posX = 0.0f;
    float posZ = 0.0f;
};

static ECMoveCompSnapshot g_lastMoveSnapshot{};
static bool g_moveSnapshotValid = false;
static DWORD g_lastMoveSnapshotTick = 0;
static std::atomic<DWORD> g_lastMoveReadErrorTick{0};
static constexpr DWORD kMoveSnapshotHeartbeatMs = 500;
static constexpr DWORD kMoveReadErrorCooldownMs = 5000;
static constexpr size_t kStateFlagsOffset = 0x30;

struct MoveTimelineEntry {
    DWORD tick = 0;
    int dir = 0;
    bool run = false;
    SOCKET socket = INVALID_SOCKET;
    uint32_t key = 0;
    std::string sender;
};

static std::mutex g_moveTimelineMutex;
static std::unordered_map<uint8_t, MoveTimelineEntry> g_moveTimeline;
static constexpr size_t kMaxTimelineEntries = 128;

static SOCKET ResolveSocketAliasLocked(SOCKET socket);
static void MaybeLogMoveSnapshot(void* component, const uint8_t* snapshot);
static bool ExtractMoveSnapshot(const uint8_t* snapshot, ECMoveCompSnapshot& out);
static void EmitMoveSnapshotLog(void* component, const ECMoveCompSnapshot& snapshot);
static void LogMoveSnapshotError(void* component, const char* reason);
static void TrackMovementTxInternal(uint8_t seq, int dir, bool run, SOCKET socket, uint32_t key, const char* sender);
static void EmitMovementResponse(const char* kind, uint8_t seq, uint8_t status);
static void PruneOldTimelineEntriesLocked();

static SOCKET SelectNextActiveSocketLocked()
{
    for (auto& entry : g_fastWalkQueues) {
        if (!entry.second.empty())
            return entry.first;
    }
    return INVALID_SOCKET;
}

static std::deque<uint32_t>* FindQueueLocked(SOCKET socket)
{
    socket = ResolveSocketAliasLocked(socket);
    if (socket == INVALID_SOCKET)
        return nullptr;
    auto it = g_fastWalkQueues.find(socket);
    if (it == g_fastWalkQueues.end())
        return nullptr;
    return &it->second;
}

static std::deque<uint32_t>& EnsureQueueLocked(SOCKET socket)
{
    socket = ResolveSocketAliasLocked(socket);
    return g_fastWalkQueues[socket];
}

static int GetQueueDepthLocked(SOCKET socket)
{
    socket = ResolveSocketAliasLocked(socket);
    auto* queue = FindQueueLocked(socket);
    return queue ? static_cast<int>(queue->size()) : 0;
}

static size_t MergeQueuesToSocketLocked(SOCKET socket)
{
    socket = ResolveSocketAliasLocked(socket);
    if (socket == INVALID_SOCKET)
        return 0;

    auto& targetQueue = EnsureQueueLocked(socket);
    size_t moved = 0;
    for (auto it = g_fastWalkQueues.begin(); it != g_fastWalkQueues.end();) {
        SOCKET key = it->first;
        if (key == socket) {
            ++it;
            continue;
        }
        if (!it->second.empty()) {
            moved += it->second.size();
            targetQueue.insert(targetQueue.end(), it->second.begin(), it->second.end());
        }
        g_socketAliases[key] = socket;
        it = g_fastWalkQueues.erase(it);
    }
    return moved;
}

static uintptr_t ReadPointerSafe(void* base, ptrdiff_t offset)
{
    if (!base)
        return 0;
    uintptr_t value = 0;
    __try {
        value = *reinterpret_cast<uintptr_t*>(static_cast<uint8_t*>(base) + offset);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        value = 0;
    }
    return value;
}

static uint32_t ReadUInt32Safe(void* base, ptrdiff_t offset)
{
    if (!base)
        return 0;
    uint32_t value = 0;
    __try {
        value = *reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(base) + offset);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        value = 0;
    }
    return value;
}

static void DumpMemorySafe(const char* label, void* addr, size_t len)
{
    if (!addr || len == 0)
        return;

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(addr, &mbi, sizeof(mbi)))
        return;

    if (mbi.State != MEM_COMMIT)
        return;

    DWORD prot = mbi.Protect;
    if (!(prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return;
    if (prot & (PAGE_GUARD | PAGE_NOACCESS))
        return;

    BYTE* base = static_cast<BYTE*>(mbi.BaseAddress);
    BYTE* end = base + mbi.RegionSize;
    BYTE* ptr = static_cast<BYTE*>(addr);
    if (ptr < base || ptr >= end)
        return;

    size_t maxLen = static_cast<size_t>(end - ptr);
    size_t dumpLen = len <= maxLen ? len : maxLen;

    __try {
        DumpMemory(label, ptr, dumpLen);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // ignore faults
    }
}

static float AsFloat(uint32_t v)
{
    float f;
    std::memcpy(&f, &v, sizeof(f));
    return f;
}

static void LogQueueEntry(const char* label, const uint8_t* data, size_t len = kQueueEntrySize)
{
    if (!data || !label)
        return;

    uint32_t vals[4]{};
    int16_t hiVals[4]{};
    int16_t loVals[4]{};
    size_t count = len / sizeof(uint32_t);
    if (count > 4)
        count = 4;
    for (size_t i = 0; i < count; ++i) {
        std::memcpy(&vals[i], data + i * sizeof(uint32_t), sizeof(uint32_t));
        hiVals[i] = static_cast<int16_t>((vals[i] >> 16) & 0xFFFF);
        loVals[i] = static_cast<int16_t>(vals[i] & 0xFFFF);
    }

    Logf("%s raw={0x%08X 0x%08X 0x%08X 0x%08X} int={%d %d %d %d} float={%.3f %.3f %.3f %.3f} s16={{%d,%d} {%d,%d} {%d,%d} {%d,%d}}",
         label,
         vals[0], vals[1], vals[2], vals[3],
         static_cast<int32_t>(vals[0]), static_cast<int32_t>(vals[1]), static_cast<int32_t>(vals[2]), static_cast<int32_t>(vals[3]),
         AsFloat(vals[0]), AsFloat(vals[1]), AsFloat(vals[2]), AsFloat(vals[3]),
         hiVals[0], loVals[0],
         hiVals[1], loVals[1],
         hiVals[2], loVals[2],
         hiVals[3], loVals[3]);
}

static void ProbeFastWalkStorage(const uint8_t* compPtrData);
static bool CopyMemorySafe(const void* src, void* dst, size_t len);

static bool IsReadableProtect(DWORD protect) {
    switch (protect & 0xFF) {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
    }
}

static bool IsExecutableProtect(DWORD protect) {
    switch (protect & 0xFF) {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
    }
}

static void LoadMovementConfig() {
    std::call_once(g_movementConfigOnce, []() {
        if (auto enabled = Core::Config::TryGetBool("MOVE_SAFE_DUMP"))
            g_moveSafeDumpEnabled = *enabled;
        if (auto windowMs = Core::Config::TryGetUInt("FW_ASSOC_WINDOW_MS"))
            g_fastWalkAssocWindowMs = std::clamp<uint32_t>(static_cast<uint32_t>(*windowMs), 50u, 1000u);
    });
}

static void LogMovementVtable(void* thisPtr)
{
    if (!thisPtr)
        return;
    LoadMovementConfig();
    if (!g_moveSafeDumpEnabled && !Log::IsEnabled(Log::Category::Movement, Log::Level::Debug))
        return;

    void** vt = nullptr;
    __try {
        vt = *reinterpret_cast<void***>(thisPtr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Movement,
                  "Movement vtable pointer unreadable (seh=0x%08lX)",
                  static_cast<unsigned long>(GetExceptionCode()));
        return;
    }

    if (!vt || vt == g_loggedVtable)
        return;

    MEMORY_BASIC_INFORMATION tableInfo{};
    if (VirtualQuery(vt, &tableInfo, sizeof(tableInfo)) != sizeof(tableInfo) || !IsReadableProtect(tableInfo.Protect)) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Movement,
                  "Movement vtable base unreadable vt=%p protect=0x%08lX",
                  vt,
                  static_cast<unsigned long>(tableInfo.Protect));
        return;
    }

    g_loggedVtable = vt;
    Log::Logf(Log::Level::Debug, Log::Category::Movement, "Movement component vtable snapshot (first 16 entries):");

    for (int i = 0; i < 16; ++i) {
        void* entry = nullptr;
        DWORD sehCode = 0;
        __try {
            entry = vt[i];
        }
        __except (sehCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
            entry = nullptr;
        }

        if (sehCode != 0) {
            Log::Logf(Log::Level::Debug,
                      Log::Category::Movement,
                      "  vtbl[%02d] = <unreadable> seh=0x%08lX",
                      i,
                      static_cast<unsigned long>(sehCode));
            continue;
        }

        MEMORY_BASIC_INFORMATION entryInfo{};
        if (!entry || VirtualQuery(entry, &entryInfo, sizeof(entryInfo)) != sizeof(entryInfo) || !IsExecutableProtect(entryInfo.Protect)) {
            Log::Logf(Log::Level::Debug,
                      Log::Category::Movement,
                      "  vtbl[%02d] = %p (skipped protect=0x%08lX)",
                      i,
                      entry,
                      entry ? static_cast<unsigned long>(entryInfo.Protect) : 0UL);
            continue;
        }

        Log::Logf(Log::Level::Debug, Log::Category::Movement, "  vtbl[%02d] = %p", i, entry);
    }
}

static void LogQueueState(const char* tag)
{
    if (!tag)
        tag = "Queue";

    if (!g_moveComp) {
        Logf("%s: queue log skipped (movement component unavailable)", tag);
        return;
    }

    uintptr_t queuePtr = ReadPointerSafe(g_moveComp, 0x08);
    if (!queuePtr) {
        Logf("%s: queue pointer unavailable (component=%p)", tag, g_moveComp);
        return;
    }

    uint8_t snapshot[kDestCopySize]{};
    if (!CopyMemorySafe(reinterpret_cast<void*>(queuePtr), snapshot, sizeof(snapshot))) {
        Logf("%s: failed to snapshot queue state @ %p", tag, reinterpret_cast<void*>(queuePtr));
        return;
    }

    uint32_t head = 0;
    uint32_t tail = 0;
    uint32_t count = 0;
    std::memcpy(&head, snapshot + 0x10, sizeof(head));
    std::memcpy(&tail, snapshot + 0x14, sizeof(tail));
    std::memcpy(&count, snapshot + 0x2C, sizeof(count));

    Logf("%s: queue=%p head=%u tail=%u count=%u", tag, reinterpret_cast<void*>(queuePtr), head, tail, count);

    if (0x20 + kQueueEntrySize <= kDestCopySize) {
        char label[96];
        sprintf_s(label, sizeof(label), "%s head entry", tag);
        LogQueueEntry(label, snapshot + 0x20);
    }

    if (0x30 + kQueueEntrySize <= kDestCopySize) {
        char label[96];
        sprintf_s(label, sizeof(label), "%s tail entry", tag);
        LogQueueEntry(label, snapshot + 0x30);
    }
}

static bool EnqueueViaUpdate(int dir, bool shouldRun, int stepScale)
{
    if (!g_moveComp || !g_origUpdate || !g_dest)
        return false;

    dir &= 7;

    uint8_t scratch[kDestCopySize]{};
    if (!CopyMemorySafe(g_dest, scratch, sizeof(scratch))) {
        Logf("EnqueueViaUpdate: failed to clone destination block (dest=%p)", g_dest);
        return false;
    }

    Vec3* vec = reinterpret_cast<Vec3*>(scratch);
    Vec3 before = *vec;

    vec->x = static_cast<int16_t>(before.x + static_cast<int16_t>(kStepDx[dir] * stepScale));
    vec->y = static_cast<int16_t>(before.y + static_cast<int16_t>(kStepDy[dir] * stepScale));
    vec->z = before.z;

    g_expectedDest = *vec;
    InterlockedExchange(&g_expectValid, 1);

    char beforeTag[64];
    sprintf_s(beforeTag, sizeof(beforeTag),
              "SendWalk before enqueue (dir=%d run=%d)", dir, shouldRun ? 1 : 0);
    LogQueueState(beforeTag);

    bool updateSucceeded = false;
    __try {
        g_origUpdate(g_moveComp, scratch, static_cast<uint32_t>(dir), shouldRun ? 1 : 0);
        updateSucceeded = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("EnqueueViaUpdate: exception invoking original update");
        updateSucceeded = false;
    }

    if (!updateSucceeded)
        return false;

    char afterTag[64];
    sprintf_s(afterTag, sizeof(afterTag),
              "SendWalk after enqueue (dir=%d run=%d)", dir, shouldRun ? 1 : 0);
    LogQueueState(afterTag);

    return true;
}

static bool EnqueueViaUpdateWithComponent(void* component, void* destPtr, int dir, bool shouldRun, int stepScale, const char* reasonTag)
{
    if (!component || !destPtr || !g_origUpdate)
        return false;

    void* savedComp = g_moveComp;
    void* savedDest = g_dest;

    g_moveComp = component;
    g_dest = destPtr;

    bool queued = EnqueueViaUpdate(dir, shouldRun, stepScale);

    if (!savedComp) {
        if (queued) {
            g_moveComp = component;
            g_dest = destPtr;
            g_candidateDest = destPtr;
            Logf("LocalStep: adopted movement component = %p (reason=%s)", component, reasonTag ? reasonTag : "candidate");
            Engine::RequestWalkRegistration();
        } else {
            g_moveComp = nullptr;
            g_dest = nullptr;
        }
    } else {
        g_moveComp = savedComp;
        g_dest = savedDest;
    }

    if (queued) {
        char buf[192];
        sprintf_s(buf, sizeof(buf),
                  "%s: enqueued predicted step dir=%d run=%d (comp=%p dest=%p)",
                  reasonTag ? reasonTag : "LocalStep",
                  dir,
                  shouldRun ? 1 : 0,
                  component,
                  destPtr);
        WriteRawLog(buf);
    } else if (reasonTag) {
        while (true) {
            LONG current = g_localEnqueueFailBudget;
            if (current <= 0)
                break;
            if (InterlockedCompareExchange(&g_localEnqueueFailBudget, current - 1, current) == current) {
                char buf[192];
                sprintf_s(buf, sizeof(buf),
                          "%s: local enqueue failed (comp=%p dest=%p)",
                          reasonTag,
                          component,
                          destPtr);
                WriteRawLog(buf);
                break;
            }
        }
    }

    return queued;
}

static bool TryQueueLocalStep(int dir, bool shouldRun, int stepScale)
{
    if (EnqueueViaUpdate(dir, shouldRun, stepScale))
        return true;

    void* candidateComp = g_moveCandidate ? g_moveCandidate : nullptr;
    void* candidateDest = g_candidateDest;

    if (candidateComp && candidateDest) {
        return EnqueueViaUpdateWithComponent(candidateComp, candidateDest, dir, shouldRun, stepScale, "LocalStep(cand)");
    }

    return false;
}

static void ProbeFastWalkStorage(const uint8_t* compPtrData)
{
    if (!compPtrData)
        return;

    LONG budget = InterlockedCompareExchange(&g_fastWalkProbeBudget, 0, 0);
    if (budget <= 0)
        return;

    uint32_t key = static_cast<uint32_t>(InterlockedCompareExchange(&g_lastObservedNetworkKey, 0, 0));
    if (key == 0)
        return;

    if (g_fastWalkStorageOffset >= 0 && g_lastProbeAttemptKey == key)
        return;
    if (g_fastWalkStorageOffset < 0 && g_lastProbeAttemptKey == key)
        return;

    g_lastProbeAttemptKey = key;

    size_t hitOffset = SIZE_MAX;
    for (size_t offset = 0; offset + sizeof(uint32_t) <= kDestCopySize; ++offset) {
        uint32_t value = 0;
        std::memcpy(&value, compPtrData + offset, sizeof(value));
        if (value == key) {
            hitOffset = offset;
            break;
        }
    }

    if (hitOffset != SIZE_MAX) {
        g_fastWalkStorageOffset = static_cast<int>(hitOffset);
        if (g_lastLoggedCandidateKey != key) {
            g_lastLoggedCandidateKey = key;
            Logf("FastWalk storage candidate: key=%08X offset=0x%X within movement snapshot", key, static_cast<unsigned>(hitOffset));
            char buf[160];
            sprintf_s(buf, sizeof(buf), "FastWalk storage candidate offset=0x%X key=%08X", static_cast<unsigned>(hitOffset), key);
            WriteRawLog(buf);
            if (hitOffset + 4 * sizeof(uint32_t) <= kDestCopySize) {
                uint32_t preview[4]{};
                std::memcpy(preview, compPtrData + hitOffset, sizeof(preview));
                Logf("FastWalk slot preview: {%08X %08X %08X %08X}", preview[0], preview[1], preview[2], preview[3]);
            }
        }
        InterlockedDecrement(&g_fastWalkProbeBudget);
    } else {
        if (InterlockedDecrement(&g_fastWalkProbeBudget) >= 0) {
            Logf("FastWalk probe miss for key=%08X (no match in movement snapshot)", key);
        }
    }
}

static bool CopyMemorySafe(const void* src, void* dst, size_t len)
{
    if (!src || !dst || len == 0)
        return false;

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(src, &mbi, sizeof(mbi)))
        return false;

    if (mbi.State != MEM_COMMIT)
        return false;

    DWORD prot = mbi.Protect;
    if (!(prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return false;
    if (prot & (PAGE_GUARD | PAGE_NOACCESS))
        return false;

    const BYTE* base = static_cast<const BYTE*>(mbi.BaseAddress);
    const BYTE* end = base + mbi.RegionSize;
    const BYTE* ptr = static_cast<const BYTE*>(src);
    if (ptr < base || ptr >= end)
        return false;

    size_t maxLen = static_cast<size_t>(end - ptr);
    size_t copyLen = len <= maxLen ? len : maxLen;

    bool success = false;
    __try {
        std::memcpy(dst, src, copyLen);
        success = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        success = false;
    }
    return success;
}

static bool ExtractMoveSnapshot(const uint8_t* snapshot, ECMoveCompSnapshot& out)
{
    if (!snapshot)
        return false;
    if (0x28 + sizeof(float) > kDestCopySize)
        return false;
    if (kStateFlagsOffset + sizeof(uint32_t) > kDestCopySize)
        return false;

    std::memcpy(&out.head, snapshot + 0x10, sizeof(out.head));
    std::memcpy(&out.tail, snapshot + 0x14, sizeof(out.tail));
    std::memcpy(&out.stateFlags, snapshot + kStateFlagsOffset, sizeof(out.stateFlags));
    std::memcpy(&out.posX, snapshot + 0x20, sizeof(out.posX));
    std::memcpy(&out.posZ, snapshot + 0x28, sizeof(out.posZ));
    return true;
}

static void EmitMoveSnapshotLog(void* component, const ECMoveCompSnapshot& snapshot)
{
    char buf[256];
    sprintf_s(buf, sizeof(buf),
              "[MoveComp] tid=%lu this=%p head=%u tail=%u flags=0x%08X pos=(%.3f,%.3f)",
              GetCurrentThreadId(),
              component,
              snapshot.head,
              snapshot.tail,
              snapshot.stateFlags,
              static_cast<double>(snapshot.posX),
              static_cast<double>(snapshot.posZ));
    WriteRawLog(buf);
}

static void LogMoveSnapshotError(void* component, const char* reason)
{
    DWORD now = GetTickCount();
    DWORD last = g_lastMoveReadErrorTick.load(std::memory_order_relaxed);
    if (now - last < kMoveReadErrorCooldownMs)
        return;
    if (!g_lastMoveReadErrorTick.compare_exchange_strong(last, now, std::memory_order_acq_rel))
        return;

    char buf[224];
    sprintf_s(buf, sizeof(buf),
              "[MoveComp] tid=%lu this=%p warn=%s",
              GetCurrentThreadId(),
              component,
              reason ? reason : "snapshot-failed");
    WriteRawLog(buf);
}

static void MaybeLogMoveSnapshot(void* component, const uint8_t* snapshot)
{
    if (!component || !snapshot)
        return;

    ECMoveCompSnapshot current{};
    if (!ExtractMoveSnapshot(snapshot, current)) {
        LogMoveSnapshotError(component, "extract-failed");
        return;
    }

    DWORD now = GetTickCount();
    bool shouldLog = !g_moveSnapshotValid;
    if (g_moveSnapshotValid) {
        if (current.head != g_lastMoveSnapshot.head ||
            current.tail != g_lastMoveSnapshot.tail ||
            current.stateFlags != g_lastMoveSnapshot.stateFlags) {
            shouldLog = true;
        } else if (now - g_lastMoveSnapshotTick >= kMoveSnapshotHeartbeatMs) {
            shouldLog = true;
        }
    }

    if (shouldLog) {
        EmitMoveSnapshotLog(component, current);
        g_lastMoveSnapshot = current;
        g_moveSnapshotValid = true;
        g_lastMoveSnapshotTick = now;
    }
}

static void PruneOldTimelineEntriesLocked()
{
    if (g_moveTimeline.size() <= kMaxTimelineEntries)
        return;
    while (g_moveTimeline.size() > kMaxTimelineEntries) {
        auto oldest = g_moveTimeline.begin();
        for (auto it = g_moveTimeline.begin(); it != g_moveTimeline.end(); ++it) {
            if (it->second.tick < oldest->second.tick)
                oldest = it;
        }
        if (oldest != g_moveTimeline.end())
            g_moveTimeline.erase(oldest);
        else
            break;
    }
}

static void TrackMovementTxInternal(uint8_t seq, int dir, bool run, SOCKET socket, uint32_t key, const char* sender)
{
    if (seq == 0)
        seq = 1;

    const bool detailedLog = Walk::Controller::DebugEnabled() || Log::IsEnabled(Log::Category::Walk, Log::Level::Debug);

    MoveTimelineEntry entry{};
    entry.tick = GetTickCount();
    entry.dir = dir;
    entry.run = run;
    entry.socket = socket;
    entry.key = key;
    if (sender)
        entry.sender = sender;
    else
        entry.sender = "unknown";

    {
        std::lock_guard<std::mutex> lock(g_moveTimelineMutex);
        g_moveTimeline[seq] = entry;
        if (g_moveTimeline.size() > kMaxTimelineEntries) {
            PruneOldTimelineEntriesLocked();
        }
    }

    if (detailedLog) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Walk,
                  "[Move] tid=%lu dir=%d run=%d TX seq=0x%02X key=0x%08X socket=%p sender=%s",
                  GetCurrentThreadId(),
                  dir,
                  run ? 1 : 0,
                  seq,
                  static_cast<unsigned>(key),
                  reinterpret_cast<void*>(static_cast<uintptr_t>(socket)),
                  entry.sender.c_str());
    }
}

static void EmitMovementResponse(const char* kind, uint8_t seq, uint8_t status)
{
    if (seq == 0)
        seq = 1;

    const bool detailedLog = Walk::Controller::DebugEnabled() || Log::IsEnabled(Log::Category::Walk, Log::Level::Debug);

    MoveTimelineEntry entry{};
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(g_moveTimelineMutex);
        auto it = g_moveTimeline.find(seq);
        if (it != g_moveTimeline.end()) {
            entry = it->second;
            g_moveTimeline.erase(it);
            found = true;
        }
    }

    DWORD now = GetTickCount();
    if (!detailedLog)
        return;

    if (found) {
        DWORD delta = now - entry.tick;
        Log::Logf(Log::Level::Debug,
                  Log::Category::Walk,
                  "[Move] tid=%lu %s seq=0x%02X status=0x%02X (+%u ms since TX) dir=%d run=%d sender=%s socket=%p",
                  GetCurrentThreadId(),
                  kind ? kind : "RESP",
                  seq,
                  static_cast<unsigned>(status),
                  delta,
                  entry.dir,
                  entry.run ? 1 : 0,
                  entry.sender.c_str(),
                  reinterpret_cast<void*>(static_cast<uintptr_t>(entry.socket)));
    } else {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Walk,
                  "[Move] tid=%lu %s seq=0x%02X status=0x%02X (+? since TX)",
                  GetCurrentThreadId(),
                  kind ? kind : "RESP",
                  seq,
                  static_cast<unsigned>(status));
    }
}

static void FindMoveComponent();
static uint32_t __fastcall H_Update(void* thisPtr, void* _unused, void* destPtr, uint32_t dir, int runFlag);
static void ResetMovementSequenceState();
static uint8_t NextMovementSequence();

static int NormalizeDirection(int dir)
{
    if (dir >= 0)
        return dir & 7;
    int normalized = dir % 8;
    if (normalized < 0)
        normalized += 8;
    return normalized & 7;
}

static void ResetMovementSequenceState()
{
    g_lastAckSeq.store(0, std::memory_order_relaxed);
    g_lastSentSeq.store(0, std::memory_order_relaxed);
    g_haveAckSeq.store(false, std::memory_order_relaxed);
    g_haveSentSeq.store(false, std::memory_order_relaxed);
    g_lastMovementSendTickMs.store(0, std::memory_order_relaxed);
}

static uint8_t NextMovementSequence()
{
    uint8_t base = 0;
    if (g_haveSentSeq.load(std::memory_order_acquire)) {
        base = g_lastSentSeq.load(std::memory_order_relaxed);
    } else if (g_haveAckSeq.load(std::memory_order_acquire)) {
        base = g_lastAckSeq.load(std::memory_order_relaxed);
    }
    uint8_t next = static_cast<uint8_t>(base + 1);
    if (next == 0)
        next = 1;
    return next;
}

static bool MovementAckPending()
{
    if (!g_haveSentSeq.load(std::memory_order_acquire))
        return false;
    if (!g_haveAckSeq.load(std::memory_order_acquire))
        return true;
    return g_lastSentSeq.load(std::memory_order_relaxed) != g_lastAckSeq.load(std::memory_order_relaxed);
}

static SOCKET ResolveSocketAliasLocked(SOCKET socket)
{
    if (socket == INVALID_SOCKET)
        return socket;

    SOCKET current = socket;
    for (int depth = 0; depth < 8; ++depth)
    {
        auto it = g_socketAliases.find(current);
        if (it == g_socketAliases.end())
            break;
        SOCKET next = it->second;
        if (next == INVALID_SOCKET || next == current)
            break;
        current = next;
    }
    return current;
}

} // namespace

namespace Engine {

void RecordInboundFastWalkKey(SOCKET socket, uint32_t key, int depthBefore, int depthAfter, uint64_t tickMs) {
    if (socket == INVALID_SOCKET || key == 0)
        return;

    g_fwKeysInbound.fetch_add(1, std::memory_order_relaxed);

    std::lock_guard<std::mutex> lock(g_fastWalkMutex);
    SOCKET canonical = ResolveSocketAliasLocked(socket);
    if (canonical == INVALID_SOCKET)
        canonical = socket;
    if (socket != canonical && canonical != INVALID_SOCKET)
        g_socketAliases[socket] = canonical;

    g_fastWalkExpectedDepth[canonical] = std::clamp(depthAfter, 0, static_cast<int>(kFastWalkQueueCapacity));

    RecordFastWalkKeyLocked(canonical, key, depthBefore, depthAfter, tickMs);
    CheckFastWalkTimeoutsAllLocked(g_lastIndexHead, g_lastIndexTail, tickMs);
}

static bool MovementReadyInternal(const char** reasonOut)
{
    if (!g_updateState) {
        if (reasonOut)
            *reasonOut = "movement hook not installed";
        return false;
    }
    if (!g_moveComp) {
        if (reasonOut) {
            *reasonOut = g_moveCandidate
                ? "movement component candidate pending"
                : "movement component not discovered";
        }
        return false;
    }
    if (reasonOut)
        *reasonOut = nullptr;
    return true;
}

void PushFastWalkKey(SOCKET socket, uint32_t key) {
    if (socket == INVALID_SOCKET || key == 0)
        return;

    const bool debugLog = Walk::Controller::DebugEnabled();

    std::lock_guard<std::mutex> lock(g_fastWalkMutex);
    SOCKET canonical = ResolveSocketAliasLocked(socket);
    if (canonical == INVALID_SOCKET)
        canonical = socket;
    if (socket != canonical && canonical != INVALID_SOCKET)
        g_socketAliases[socket] = canonical;

    socket = canonical;
    auto& queue = EnsureQueueLocked(socket);
    auto expectedIt = g_fastWalkExpectedDepth.find(socket);
    int expectedDepth = (expectedIt != g_fastWalkExpectedDepth.end() && expectedIt->second > 0)
                            ? expectedIt->second
                            : static_cast<int>(kFastWalkNominalDepth);

    queue.push_back(key);

    while (queue.size() > static_cast<size_t>(expectedDepth))
        queue.pop_front();

    if (queue.size() > kFastWalkQueueCapacity) {
        size_t before = queue.size();
        while (queue.size() > kFastWalkQueueCapacity)
            queue.pop_front();
        g_fwResyncs.fetch_add(1, std::memory_order_relaxed);
        if (debugLog) {
            Log::Logf(Log::Level::Debug,
                      Log::Category::FastWalk,
                      "FastWalk queue trimmed socket=%p trimmed=%zu",
                      reinterpret_cast<void*>(static_cast<uintptr_t>(socket)),
                      before - queue.size());
        }
    }

    g_activeFastWalkSocket = socket;
    g_fwDepth.store(static_cast<uint32_t>(queue.size()), std::memory_order_relaxed);
    g_fastWalkExpectedDepth[socket] = static_cast<int>(queue.size());

    if (debugLog) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::FastWalk,
                  "FastWalk enqueue key=0x%08X socket=%p depth=%zu",
                  key,
                  reinterpret_cast<void*>(static_cast<uintptr_t>(socket)),
                  queue.size());
    }
}

uint32_t PopFastWalkKey(SOCKET socket) {
    const bool debugLog = Walk::Controller::DebugEnabled();

    std::lock_guard<std::mutex> lock(g_fastWalkMutex);
    socket = ResolveSocketAliasLocked(socket);
    if (socket == INVALID_SOCKET)
        return 0;

    auto it = g_fastWalkQueues.find(socket);
    if (it == g_fastWalkQueues.end() || it->second.empty()) {
        if (debugLog) {
            Log::Logf(Log::Level::Debug,
                      Log::Category::FastWalk,
                      "FastWalk dequeue empty socket=%p",
                      reinterpret_cast<void*>(static_cast<uintptr_t>(socket)));
        }
        return 0;
    }

    uint32_t key = it->second.front();
    it->second.pop_front();
    g_fwKeysOutbound.fetch_add(1, std::memory_order_relaxed);
    g_fastWalkExpectedDepth[socket] = static_cast<int>(it->second.size());
    g_fwDepth.store(static_cast<uint32_t>(it->second.size()), std::memory_order_relaxed);

    if (debugLog) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::FastWalk,
                  "FastWalk dequeue key=0x%08X socket=%p depth=%zu",
                  key,
                  reinterpret_cast<void*>(static_cast<uintptr_t>(socket)),
                  it->second.size());
    }

    uint64_t now = GetTickCount64();
    MarkFastWalkKeyConsumedLocked(socket, key, now);
    CheckFastWalkTimeoutsLocked(socket, g_lastIndexHead, g_lastIndexTail, now);

    if (it->second.empty()) {
        g_fastWalkQueues.erase(it);
        g_fastWalkExpectedDepth.erase(socket);
        if (g_activeFastWalkSocket == socket)
            g_activeFastWalkSocket = SelectNextActiveSocketLocked();
    }

    return key;
}

uint32_t PopFastWalkKey() {
    return PopFastWalkKey(GetActiveFastWalkSocket());
}

uint32_t PeekFastWalkKey(SOCKET socket) {
    std::lock_guard<std::mutex> lock(g_fastWalkMutex);
    socket = ResolveSocketAliasLocked(socket);
    if (socket == INVALID_SOCKET)
        return 0;
    auto* queue = FindQueueLocked(socket);
    if (!queue || queue->empty())
        return 0;
    return queue->front();
}

uint32_t PeekFastWalkKey() {
    return PeekFastWalkKey(GetActiveFastWalkSocket());
}

int FastWalkQueueDepth(SOCKET socket) {
    std::lock_guard<std::mutex> lock(g_fastWalkMutex);
    socket = ResolveSocketAliasLocked(socket);
    if (socket == INVALID_SOCKET)
        return 0;
    return GetQueueDepthLocked(socket);
}

int FastWalkQueueDepth() {
    return FastWalkQueueDepth(GetActiveFastWalkSocket());
}

SOCKET GetActiveFastWalkSocket() {
    std::lock_guard<std::mutex> lock(g_fastWalkMutex);
    SOCKET resolved = ResolveSocketAliasLocked(g_activeFastWalkSocket);
    if (resolved == INVALID_SOCKET)
        resolved = SelectNextActiveSocketLocked();
    g_activeFastWalkSocket = resolved;
    return resolved;
}

void SetActiveFastWalkSocket(SOCKET socket) {
    const bool debugLog = Walk::Controller::DebugEnabled();
    std::lock_guard<std::mutex> lock(g_fastWalkMutex);
    SOCKET canonicalPrev = ResolveSocketAliasLocked(g_activeFastWalkSocket);
    SOCKET canonicalNew = ResolveSocketAliasLocked(socket);
    if (canonicalNew == INVALID_SOCKET)
        canonicalNew = socket;

    size_t moved = 0;
    if (canonicalNew != INVALID_SOCKET)
        moved = MergeQueuesToSocketLocked(canonicalNew);
    else
        g_socketAliases.clear();

    if (canonicalPrev != INVALID_SOCKET && canonicalPrev != canonicalNew)
        g_socketAliases[canonicalPrev] = canonicalNew;

    if (socket != INVALID_SOCKET && socket != canonicalNew)
        g_socketAliases[socket] = canonicalNew;

    if (canonicalNew != INVALID_SOCKET)
        g_socketAliases.erase(canonicalNew);

    for (auto it = g_socketAliases.begin(); it != g_socketAliases.end();) {
        if (it->first == it->second || it->second == INVALID_SOCKET)
            it = g_socketAliases.erase(it);
        else {
            SOCKET target = ResolveSocketAliasLocked(it->second);
            if (target != it->second)
                it->second = target;
            ++it;
        }
    }

    g_activeFastWalkSocket = canonicalNew;

    if (canonicalPrev != INVALID_SOCKET && canonicalPrev != canonicalNew)
        g_fastWalkExpectedDepth.erase(canonicalPrev);

    uint32_t currentDepth = 0;
    if (canonicalNew != INVALID_SOCKET) {
        auto queueIt = g_fastWalkQueues.find(canonicalNew);
        if (queueIt != g_fastWalkQueues.end()) {
            currentDepth = static_cast<uint32_t>(queueIt->second.size());
            g_fastWalkExpectedDepth[canonicalNew] = static_cast<int>(currentDepth);
        }
    }
    g_fwDepth.store(currentDepth, std::memory_order_relaxed);

    if (debugLog && (canonicalNew != canonicalPrev || moved > 0)) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::FastWalk,
                  "FastWalk active socket old=%p new=%p moved=%zu depth=%u",
                  reinterpret_cast<void*>(static_cast<uintptr_t>(canonicalPrev)),
                  reinterpret_cast<void*>(static_cast<uintptr_t>(canonicalNew)),
                  moved,
                  currentDepth);
    }
}

void OnSocketClosed(SOCKET socket) {
    if (socket == INVALID_SOCKET)
        return;
    std::lock_guard<std::mutex> lock(g_fastWalkMutex);
    g_fastWalkQueues.erase(socket);
    g_fastWalkExpectedDepth.erase(socket);
    g_socketAliases.erase(socket);
    for (auto it = g_socketAliases.begin(); it != g_socketAliases.end();) {
        if (it->second == socket)
            it = g_socketAliases.erase(it);
        else
            ++it;
    }
    if (ResolveSocketAliasLocked(g_activeFastWalkSocket) == socket)
        g_activeFastWalkSocket = SelectNextActiveSocketLocked();

    SOCKET active = ResolveSocketAliasLocked(g_activeFastWalkSocket);
    uint32_t currentDepth = 0;
    if (active != INVALID_SOCKET) {
        auto itActive = g_fastWalkQueues.find(active);
        if (itActive != g_fastWalkQueues.end())
            currentDepth = static_cast<uint32_t>(itActive->second.size());
    }
    g_fwDepth.store(currentDepth, std::memory_order_relaxed);
}

void RecordObservedFastWalkKey(uint32_t key) {
    InterlockedExchange(&g_lastObservedNetworkKey, static_cast<LONG>(key));
}

void RecordMovementSent(uint8_t seq)
{
    g_walkStepsSent.fetch_add(1, std::memory_order_relaxed);
    if (seq == 0)
        seq = 1;
    g_lastSentSeq.store(seq, std::memory_order_release);
    g_haveSentSeq.store(true, std::memory_order_release);
}

void RecordMovementAck(uint8_t seq, uint8_t status)
{
    if (seq == 0)
        seq = 1;
    g_lastAckSeq.store(seq, std::memory_order_release);
    g_haveAckSeq.store(true, std::memory_order_release);
    g_lastSentSeq.store(seq, std::memory_order_release);
    g_haveSentSeq.store(true, std::memory_order_release);
    EmitMovementResponse("ACK", seq, status);
}

void RecordMovementReject(uint8_t seq, uint8_t status)
{
    if (seq == 0)
        seq = 1;
    g_lastAckSeq.store(seq, std::memory_order_release);
    g_haveAckSeq.store(true, std::memory_order_release);
    g_lastSentSeq.store(seq, std::memory_order_release);
    g_haveSentSeq.store(true, std::memory_order_release);
    EmitMovementResponse("NACK", seq, status);
}

void TrackMovementTx(uint8_t seq, int dir, bool run, SOCKET socket, uint32_t key, const char* sender)
{
    TrackMovementTxInternal(seq, dir, run, socket, key, sender);
}

void GetFastWalkCounters(FastWalkCounters& out)
{
    out.keysInbound = g_fwKeysInbound.load(std::memory_order_relaxed);
    out.keysOutbound = g_fwKeysOutbound.load(std::memory_order_relaxed);
    out.depth = g_fwDepth.load(std::memory_order_relaxed);
    out.resyncs = g_fwResyncs.load(std::memory_order_relaxed);
    out.misses = g_fwMisses.load(std::memory_order_relaxed);
}

uint64_t GetWalkStepsSent()
{
    return g_walkStepsSent.load(std::memory_order_relaxed);
}

void NotifyClientMovementSent()
{
    g_clientMovementSendObserved.store(true, std::memory_order_release);
}

void ArmMovementSendWatchdog()
{
    g_clientMovementSendObserved.store(false, std::memory_order_release);
    g_movementWatchdogStartTick.store(GetTickCount(), std::memory_order_relaxed);
    g_movementWatchdogArmed.store(true, std::memory_order_release);
}

bool DisarmAndCheckMovementSend(uint32_t timeoutMs)
{
    bool armed = g_movementWatchdogArmed.exchange(false, std::memory_order_acq_rel);
    if (!armed) {
        return g_clientMovementSendObserved.exchange(false, std::memory_order_acq_rel);
    }

    if (timeoutMs == 0)
        timeoutMs = 100;

    DWORD start = g_movementWatchdogStartTick.load(std::memory_order_relaxed);
    if (start == 0)
        start = GetTickCount();

    while (!g_clientMovementSendObserved.load(std::memory_order_acquire)) {
        DWORD now = GetTickCount();
        if (now - start >= timeoutMs)
            break;
        Sleep(1);
    }

    bool observed = g_clientMovementSendObserved.exchange(false, std::memory_order_acq_rel);
    g_movementWatchdogStartTick.store(0, std::memory_order_relaxed);
    return observed;
}

bool IsScriptedMovementSendInProgress()
{
    return g_scriptSendInProgress;
}

bool HaveSentSequence()
{
    return g_haveSentSeq.load(std::memory_order_acquire);
}

bool HaveAckSequence()
{
    return g_haveAckSeq.load(std::memory_order_acquire);
}

uint8_t GetLastSentSequence()
{
    return g_lastSentSeq.load(std::memory_order_relaxed);
}

uint8_t GetLastAckSequence()
{
    return g_lastAckSeq.load(std::memory_order_relaxed);
}

bool MovementReady() {
    return MovementReadyInternal(nullptr);
}

bool MovementReadyWithReason(const char** reasonOut) {
    return MovementReadyInternal(reasonOut);
}

void GetMovementDebugStatus(MovementDebugStatus& out) {
    std::memset(&out, 0, sizeof(out));
    out.updateHookInstalled = g_updateState != nullptr;
    out.movementComponentCaptured = g_moveComp != nullptr;
    out.movementCandidatePending = g_moveCandidate != nullptr && g_moveComp == nullptr;
    out.movementComponentPtr = g_moveComp;
    out.movementCandidatePtr = g_moveCandidate;
    out.destinationPtr = g_dest;
    out.fastWalkDepth = FastWalkQueueDepth();
    out.ready = MovementReadyInternal(nullptr);

    out.pendingMoveActive = g_pendingMoveActive != 0;
    DWORD now = GetTickCount();
    DWORD pendingTick = static_cast<DWORD>(g_pendingTick);
    out.pendingAgeMs = out.pendingMoveActive ? (now - pendingTick) : 0;
    out.pendingDir = static_cast<int>(g_pendingDir);
    out.pendingRun = g_pendingRunFlag != 0;
}

bool GetLastMovementSnapshot(Engine::MovementSnapshot& outSnapshot) {
    if (!g_moveSnapshotValid)
        return false;
    outSnapshot.head = g_lastMoveSnapshot.head;
    outSnapshot.tail = g_lastMoveSnapshot.tail;
    outSnapshot.stateFlags = g_lastMoveSnapshot.stateFlags;
    outSnapshot.posX = g_lastMoveSnapshot.posX;
    outSnapshot.posZ = g_lastMoveSnapshot.posZ;
    return true;
}

void RequestWalkRegistration() {
    InterlockedExchange(&g_needWalkReg, 1);
    Engine::Lua::ScheduleWalkBinding();
}

SOCKET ResolveFastWalkSocket(SOCKET socket)
{
    std::lock_guard<std::mutex> lock(g_fastWalkMutex);
    SOCKET resolved = ResolveSocketAliasLocked(socket);
    return resolved == INVALID_SOCKET ? socket : resolved;
}

bool InitMovementHooks() {
    LoadMovementConfig();
    Walk::Controller::Reset();
    ResetMovementSequenceState();
    g_socketAliases.clear();

    const char* kUpdateSig =
        "83 EC 58 53 55 8B 6C 24 64 80 7D 79 00 56 57 0F 85 ?? ?? ?? 00"
        "80 7D 7A 00 0F 85 ?? ?? ?? 00";

    BYTE* hit = FindPatternText(kUpdateSig);
    if (hit) {
        g_updateState = reinterpret_cast<UpdateState_t>(hit);
        char buf[64];
        sprintf_s(buf, sizeof(buf), "Found updateDataStructureState at %p", hit);
        WriteRawLog(buf);
        if (MH_CreateHook(g_updateState, &H_Update, reinterpret_cast<LPVOID*>(&g_origUpdate)) == MH_OK &&
            MH_EnableHook(g_updateState) == MH_OK) {
            WriteRawLog("updateDataStructureState hook installed");
        } else {
            WriteRawLog("updateDataStructureState hook failed; falling back to scan");
            g_origUpdate = g_updateState;
            FindMoveComponent();
        }
        return true;
    }
    WriteRawLog("updateDataStructureState not found");
    return false;
}

void ShutdownMovementHooks() {
    if (g_updateState) {
        MH_DisableHook(g_updateState);
        MH_RemoveHook(g_updateState);
        g_updateState = nullptr;
        g_origUpdate = nullptr;
    }
    Walk::Controller::Reset();
    g_moveComp = nullptr;
   g_moveCandidate = nullptr;
   g_dest = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_fastWalkMutex);
        g_fastWalkQueues.clear();
        g_activeFastWalkSocket = INVALID_SOCKET;
    }
    InterlockedExchange(&g_fwOverflowWarned, 0);
    g_trackerCount = 0;
    g_trackerLogBudget = 8;
    g_haveCompPtrSnapshot = false;
    std::memset(g_lastCompPtrSnapshot, 0, sizeof(g_lastCompPtrSnapshot));
    g_ptrDiffLogBudget = kPtrDiffLogLimit;
    g_savedIndexBudget = kIndexSampleLimit;
    g_lastIndexHead = 0;
    g_lastIndexTail = 0;
    g_haveHeadEntry = false;
    g_haveTailEntry = false;
    std::memset(g_lastHeadEntry, 0, sizeof(g_lastHeadEntry));
    std::memset(g_lastTailEntry, 0, sizeof(g_lastTailEntry));
    g_loggedVtable = nullptr;
    g_moveSnapshotValid = false;
    g_lastMoveSnapshotTick = 0;
    g_lastMoveReadErrorTick.store(0, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> timelineLock(g_moveTimelineMutex);
        g_moveTimeline.clear();
    }
    InterlockedExchange(&g_memDumpBudget, 4);
    InterlockedExchange(&g_expectValid, 0);
    InterlockedExchange(&g_pendingMoveActive, 0);
    InterlockedExchange(&g_pendingTick, 0);
    InterlockedExchange(&g_pendingDir, 0);
    InterlockedExchange(&g_pendingRunFlag, 0);
    ResetMovementSequenceState();
}

} // namespace Engine

namespace {

static void FindMoveComponent() {
    if (!g_updateState)
        return;

    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(nullptr), &mi, sizeof(mi)))
        return;

    BYTE* base = (BYTE*)mi.lpBaseOfDll;
    BYTE* end = base + mi.SizeOfImage;

    BYTE* vtable = nullptr;
    for (BYTE* p = base; p + 0x44 <= end; p += 4) {
        if (*(DWORD*)(p + 0x40) == (DWORD)(uintptr_t)g_updateState) {
            vtable = p;
            break;
        }
    }

    if (!vtable) {
        WriteRawLog("Move component vtable not found");
        return;
    }

    char buf[64];
    sprintf_s(buf, sizeof(buf), "MoveComp vtable at %p", vtable);
    WriteRawLog(buf);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = 0;
    while (addr < (BYTE*)si.lpMaximumApplicationAddress) {
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ)) &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            BYTE* b = (BYTE*)mbi.BaseAddress;
            BYTE* e = b + mbi.RegionSize;
            for (BYTE* p = b; p + sizeof(void*) <= e; p += sizeof(void*)) {
                if (*(void**)p == (void*)vtable) {
                    MEMORY_BASIC_INFORMATION mbi2;
                    if (VirtualQuery(p, &mbi2, sizeof(mbi2)) &&
                        (mbi2.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                        g_moveCandidate = p;
                        g_moveComp = p;
                        sprintf_s(buf, sizeof(buf), "MoveComp candidate %p", p);
                        WriteRawLog(buf);
                        return;
                    }
                }
            }
        }
        addr += mbi.RegionSize;
    }
    WriteRawLog("Move component not found via scan");
}

static MovementTracker* GetTracker(void* instance)
{
    for (size_t i = 0; i < g_trackerCount; ++i) {
        if (g_trackers[i].instance == instance)
            return &g_trackers[i];
    }

    MovementTracker* slot = nullptr;
    if (g_trackerCount < kMaxTrackers) {
        slot = &g_trackers[g_trackerCount++];
    } else {
        MovementTracker* oldest = &g_trackers[0];
        for (size_t i = 1; i < kMaxTrackers; ++i) {
            if (g_trackers[i].lastTick < oldest->lastTick)
                oldest = &g_trackers[i];
        }
        slot = oldest;
    }

    *slot = {};
    slot->instance = instance;
    return slot;
}

static bool ReadVec3Safe(void* ptr, Vec3& out)
{
    if (!ptr)
        return false;
    bool success = false;
    __try {
        out = *reinterpret_cast<Vec3*>(ptr);
        success = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        success = false;
    }
    return success;
}

static uint32_t __fastcall H_Update(void* thisPtr, void* _unused, void* destPtr, uint32_t dir, int runFlag) {
    Engine::Lua::ProcessLuaQueue();
    if (!g_moveCandidate && InterlockedCompareExchange(&g_haveMoveComp, 1, 0) == 0) {
        g_moveCandidate = thisPtr;
        Logf("Captured movement candidate = %p (thread %lu)", g_moveCandidate, GetCurrentThreadId());
    }

    if (thisPtr == g_moveCandidate && destPtr) {
        g_candidateDest = destPtr;
    }

    DWORD now = GetTickCount();
    bool dumpReserved = false;
    if (destPtr && (!g_moveComp || g_pendingMoveActive)) {
        LONG current = g_memDumpBudget;
        while (current > 0) {
            LONG prev = current;
            current = InterlockedCompareExchange(&g_memDumpBudget, prev - 1, prev);
            if (current == prev) {
                dumpReserved = true;
                break;
            }
        }
    }

    Vec3 before{};
    Vec3 after{};
    bool haveBefore = ReadVec3Safe(destPtr, before);
    bool haveAfter = false;
    int dx = 0;
    int dy = 0;
    int dz = 0;

    MovementTracker* tracker = GetTracker(thisPtr);

    uint8_t compPtrData[kDestCopySize]{};
    bool haveCompPtrData = false;
    uintptr_t ptrA = ReadPointerSafe(thisPtr, 0x08);
    uint32_t rawPtrB = ReadUInt32Safe(thisPtr, 0x0C);
    uintptr_t ptrB = static_cast<uintptr_t>(rawPtrB);
    uintptr_t destPtrA = ReadPointerSafe(destPtr, 0x06);
    uintptr_t destPtrB = ReadPointerSafe(destPtr, 0x0A);
    if (ptrA) {
        haveCompPtrData = CopyMemorySafe(reinterpret_cast<void*>(ptrA), compPtrData, sizeof(compPtrData));
        if (!haveCompPtrData && thisPtr == g_moveComp && g_ptrDiffLogBudget > 0) {
            Logf("compPtr copy failed (ptrA=%p)", reinterpret_cast<void*>(ptrA));
            --g_ptrDiffLogBudget;
        }
    }

    uintptr_t thisBase = thisPtr ? reinterpret_cast<uintptr_t>(thisPtr) : 0;
    bool ptrALooksValid = ptrA && thisPtr && ptrA >= thisBase && ptrA < thisBase + 0x200;
    bool hasId = rawPtrB != 0;

    if (!g_moveComp && ptrALooksValid && hasId) {
        if (!g_moveCandidate || g_moveCandidate != thisPtr) {
            Logf("Player candidate matched heuristics: this=%p ptrA=%p (offset=0x%X) id=%u dest=%p",
                 thisPtr,
                 reinterpret_cast<void*>(ptrA),
                 static_cast<unsigned>(ptrA ? (ptrA - thisBase) : 0),
                 static_cast<unsigned>(rawPtrB),
                 destPtr);
        }
        g_moveCandidate = thisPtr;
        if (destPtr) {
            g_moveComp = thisPtr;
            g_dest = destPtr;
            g_candidateDest = destPtr;
            g_moveSnapshotValid = false;
            g_lastMoveSnapshotTick = 0;
            g_lastMoveReadErrorTick.store(0, std::memory_order_relaxed);
            Logf("Identified player movement component via ptr heuristic = %p (ptrA=%p offset=0x%X id=%u dest=%p)",
                 g_moveComp,
                 reinterpret_cast<void*>(ptrA),
                 static_cast<unsigned>(ptrA ? (ptrA - thisBase) : 0),
                 static_cast<unsigned>(rawPtrB),
                 destPtr);
            g_haveCompPtrSnapshot = false;
            g_ptrDiffLogBudget = kPtrDiffLogLimit;
            g_savedIndexBudget = kIndexSampleLimit;
            g_lastIndexHead = 0;
            g_lastIndexTail = 0;
            g_haveHeadEntry = false;
            g_haveTailEntry = false;
            std::memset(g_lastHeadEntry, 0, sizeof(g_lastHeadEntry));
            std::memset(g_lastTailEntry, 0, sizeof(g_lastTailEntry));
            LogMovementVtable(thisPtr);
            Engine::RequestWalkRegistration();
            InterlockedExchange(&g_pendingMoveActive, 0);
        }
    } else if (g_moveComp == thisPtr && destPtr) {
        g_dest = destPtr;
    }

    if (thisPtr == g_moveComp && haveCompPtrData) {
        MaybeLogMoveSnapshot(thisPtr, compPtrData);
        LogMovementVtable(thisPtr);
        ProbeFastWalkStorage(compPtrData);

        uint32_t head = 0;
        uint32_t tail = 0;
        std::memcpy(&head, compPtrData + 0x10, sizeof(head));
        std::memcpy(&tail, compPtrData + 0x14, sizeof(tail));
        bool hadSnapshot = g_haveCompPtrSnapshot;

        const uint8_t* headEntryPtr = (0x20 + kQueueEntrySize <= kDestCopySize) ? compPtrData + 0x20 : nullptr;
        const uint8_t* tailEntryPtr = (0x30 + kQueueEntrySize <= kDestCopySize) ? compPtrData + 0x30 : nullptr;

        bool headChanged = hadSnapshot && head != g_lastIndexHead;
        bool tailChanged = hadSnapshot && tail != g_lastIndexTail;
        uint64_t now64 = GetTickCount64();
        FastWalkKeyRecord assocRecord{};
        SOCKET assocSocket = INVALID_SOCKET;
        bool haveAssoc = TryAssociateFastWalkWithMovement(head, tail, now64, headChanged, &assocSocket, &assocRecord);

        if (!hadSnapshot) {
            if (g_savedIndexBudget > 0) {
                Logf("Queue indices initial: head=%u (0x%08X %.3f) tail=%u (0x%08X %.3f)",
                     head, head, static_cast<double>(AsFloat(head)),
                     tail, tail, static_cast<double>(AsFloat(tail)));
                --g_savedIndexBudget;
            }
            if (headEntryPtr && g_savedIndexBudget > 0) {
                LogQueueEntry("Queue head entry initial", headEntryPtr);
                --g_savedIndexBudget;
            }
            if (tailEntryPtr && g_savedIndexBudget > 0) {
                LogQueueEntry("Queue tail entry initial", tailEntryPtr);
                --g_savedIndexBudget;
            }
            g_lastIndexHead = head;
            g_lastIndexTail = tail;
            if (headEntryPtr) {
                std::memcpy(g_lastHeadEntry, headEntryPtr, kQueueEntrySize);
                g_haveHeadEntry = true;
            }
            if (tailEntryPtr) {
                std::memcpy(g_lastTailEntry, tailEntryPtr, kQueueEntrySize);
                g_haveTailEntry = true;
            }
        } else {
            if (headChanged && g_savedIndexBudget > 0) {
                if (haveAssoc && assocSocket != INVALID_SOCKET) {
                    uint64_t ageMs = (now64 >= assocRecord.tickMs) ? (now64 - assocRecord.tickMs) : 0;
                    Log::Logf(Log::Level::Debug,
                              Log::Category::Movement,
                              "Queue head changed: prev=%u (0x%08X %.3f) -> %u (0x%08X %.3f) [socket=%p fw.key=0x%08X depth=%d->%d age=%llu ms]",
                              g_lastIndexHead,
                              g_lastIndexHead,
                              static_cast<double>(AsFloat(g_lastIndexHead)),
                              head,
                              head,
                              static_cast<double>(AsFloat(head)),
                              reinterpret_cast<void*>(static_cast<uintptr_t>(assocSocket)),
                              assocRecord.key,
                              assocRecord.depthBefore,
                              assocRecord.depthAfter,
                              static_cast<unsigned long long>(ageMs));
                } else {
                    Log::Logf(Log::Level::Debug,
                              Log::Category::Movement,
                              "Queue head changed: prev=%u (0x%08X %.3f) -> %u (0x%08X %.3f) [socket=%p fw.key=<none> window=%u ms]",
                              g_lastIndexHead,
                              g_lastIndexHead,
                              static_cast<double>(AsFloat(g_lastIndexHead)),
                              head,
                              head,
                              static_cast<double>(AsFloat(head)),
                              reinterpret_cast<void*>(static_cast<uintptr_t>(assocSocket)),
                              static_cast<unsigned>(g_fastWalkAssocWindowMs));
                }
                --g_savedIndexBudget;
            }
            if (tailChanged && g_savedIndexBudget > 0) {
                Log::Logf(Log::Level::Debug,
                          Log::Category::Movement,
                          "Queue tail changed: prev=%u (0x%08X %.3f) -> %u (0x%08X %.3f)",
                          g_lastIndexTail,
                          g_lastIndexTail,
                          static_cast<double>(AsFloat(g_lastIndexTail)),
                          tail,
                          tail,
                          static_cast<double>(AsFloat(tail)));
                --g_savedIndexBudget;
            }
            if (headEntryPtr) {
                bool hadHeadEntry = g_haveHeadEntry;
                if (!g_haveHeadEntry) {
                    g_haveHeadEntry = true;
                }
                bool headEntryChanged = !hadHeadEntry ||
                    std::memcmp(g_lastHeadEntry, headEntryPtr, kQueueEntrySize) != 0;
                if (headEntryChanged) {
                    if (g_savedIndexBudget > 0) {
                        LogQueueEntry(hadHeadEntry ? "Queue head entry updated" : "Queue head entry", headEntryPtr);
                        --g_savedIndexBudget;
                    }
                    std::memcpy(g_lastHeadEntry, headEntryPtr, kQueueEntrySize);
                }
            }
            if (tailEntryPtr) {
                bool hadTailEntry = g_haveTailEntry;
                if (!g_haveTailEntry) {
                    g_haveTailEntry = true;
                }
                bool tailEntryChanged = !hadTailEntry ||
                    std::memcmp(g_lastTailEntry, tailEntryPtr, kQueueEntrySize) != 0;
                if (tailEntryChanged) {
                    if (g_savedIndexBudget > 0) {
                        LogQueueEntry(hadTailEntry ? "Queue tail entry updated" : "Queue tail entry", tailEntryPtr);
                        --g_savedIndexBudget;
                    }
                    std::memcpy(g_lastTailEntry, tailEntryPtr, kQueueEntrySize);
                }
            }
            g_lastIndexHead = head;
            g_lastIndexTail = tail;
        }

        if (g_haveCompPtrSnapshot && g_ptrDiffLogBudget > 0) {
            for (size_t offset = 0; offset < kDestCopySize && g_ptrDiffLogBudget > 0; offset += 4) {
                uint32_t prev = 0;
                uint32_t curr = 0;
                std::memcpy(&prev, g_lastCompPtrSnapshot + offset, sizeof(prev));
                std::memcpy(&curr, compPtrData + offset, sizeof(curr));
                if (prev != curr) {
                    Logf("compPtr delta off=0x%02X prev=0x%08X (%d %.3f) curr=0x%08X (%d %.3f)",
                         static_cast<unsigned>(offset),
                         prev, static_cast<int32_t>(prev), static_cast<double>(AsFloat(prev)),
                         curr, static_cast<int32_t>(curr), static_cast<double>(AsFloat(curr)));
                    --g_ptrDiffLogBudget;
                }
            }
        }
        std::memcpy(g_lastCompPtrSnapshot, compPtrData, kDestCopySize);
        g_haveCompPtrSnapshot = true;
        g_lastIndexHead = head;
        g_lastIndexTail = tail;

        Engine::MovementSnapshot controllerSnapshot{};
        if (Engine::GetLastMovementSnapshot(controllerSnapshot)) {
            Walk::Controller::OnMovementSnapshot(controllerSnapshot, headChanged, now);
        }
    }

    if (dumpReserved) {

        Logf("Dumping movement state for this=%p (pA=%p pB=%p) dest=%p (dA=%p dB=%p) dir=%u run=%d (pendingDir=%ld pendingRun=%ld)",
             thisPtr,
             reinterpret_cast<void*>(ptrA),
             reinterpret_cast<void*>(ptrB),
             destPtr,
             reinterpret_cast<void*>(destPtrA),
             reinterpret_cast<void*>(destPtrB),
             dir,
             runFlag,
             static_cast<long>(g_pendingDir),
             static_cast<long>(g_pendingRunFlag));
        if (haveBefore)
            DumpMemorySafe("Pre destVec", &before, sizeof(before));
        DumpMemorySafe("Pre destBlk", destPtr, 0x40);
        DumpMemorySafe("Pre compBlk", thisPtr, 0x140);
        if (ptrA)
            DumpMemorySafe("Pre compPtrA", reinterpret_cast<void*>(ptrA), 0x60);
        if (ptrB)
            DumpMemorySafe("Pre compPtrB", reinterpret_cast<void*>(ptrB), 0x60);
        if (destPtrA)
            DumpMemorySafe("Pre destPtrA", reinterpret_cast<void*>(destPtrA), 0x60);
        if (destPtrB)
            DumpMemorySafe("Pre destPtrB", reinterpret_cast<void*>(destPtrB), 0x60);
    }

    uint32_t rc = g_origUpdate ? g_origUpdate(thisPtr, destPtr, dir, runFlag) : 0;

    haveAfter = ReadVec3Safe(destPtr, after);
    if (!haveAfter && haveBefore)
        after = before;

    if (haveBefore && haveAfter) {
        dx = static_cast<int>(after.x) - static_cast<int>(before.x);
        dy = static_cast<int>(after.y) - static_cast<int>(before.y);
        dz = static_cast<int>(after.z) - static_cast<int>(before.z);
    } else {
        dx = dy = dz = 0;
    }

    if (tracker) {
        if (!tracker->hasDest && g_trackerLogBudget > 0) {
            Logf("Tracking movement candidate this=%p dest=(%d,%d,%d) dir=%u run=%d",
                 thisPtr,
                 static_cast<int>(after.x),
                 static_cast<int>(after.y),
                 static_cast<int>(after.z),
                 dir,
                 runFlag);
            --g_trackerLogBudget;
        }
        tracker->lastDest = after;
        tracker->lastTick = now;
        tracker->hasDest = haveAfter;
    }

    if (dumpReserved) {
        if (haveAfter)
            DumpMemorySafe("Post destVec", &after, sizeof(after));
        DumpMemorySafe("Post destBlk", destPtr, 0x40);
        DumpMemorySafe("Post compBlk", thisPtr, 0x140);
        if (ptrA)
            DumpMemorySafe("Post compPtrA", reinterpret_cast<void*>(ptrA), 0x60);
        if (ptrB)
            DumpMemorySafe("Post compPtrB", reinterpret_cast<void*>(ptrB), 0x60);
        if (destPtrA)
            DumpMemorySafe("Post destPtrA", reinterpret_cast<void*>(destPtrA), 0x60);
        if (destPtrB)
            DumpMemorySafe("Post destPtrB", reinterpret_cast<void*>(destPtrB), 0x60);
    }

    if (!g_moveComp) {
        if (g_pendingMoveActive) {
            DWORD pendingTick = static_cast<DWORD>(g_pendingTick);
            DWORD age = now - pendingTick;
            if (age <= kPendingWindowMs) {
                int expectedDir = static_cast<int>(g_pendingDir);
                int expectedRun = static_cast<int>(g_pendingRunFlag);
                if (expectedDir >= 0 && expectedDir < 8) {
                    int stepX = kStepDx[expectedDir];
                    int stepY = kStepDy[expectedDir];
                    bool matchesStep = (dx == stepX && dy == stepY);
                    if (!matchesStep && expectedRun != 0) {
                        matchesStep = (dx == stepX * 2 && dy == stepY * 2);
                    }
                    bool runMatches = (runFlag == expectedRun);
                    if (!runMatches) {
                        bool wantRun = (expectedRun != 0);
                        bool isRun = (runFlag > 1);
                        if (!isRun && runFlag == 0)
                            isRun = false;
                        runMatches = (wantRun == isRun);
                    }
                    if (matchesStep && runMatches) {
                        g_moveComp = thisPtr;
                        g_dest = destPtr;
                        g_moveSnapshotValid = false;
                        g_lastMoveSnapshotTick = 0;
                        g_lastMoveReadErrorTick.store(0, std::memory_order_relaxed);
                        Logf("Identified player movement component = %p (dir=%u run=%d)", g_moveComp, dir, runFlag);
                        Engine::RequestWalkRegistration();
                        InterlockedExchange(&g_pendingMoveActive, 0);
                    }
                }
            } else {
                InterlockedExchange(&g_pendingMoveActive, 0);
            }
        }
    } else if (thisPtr == g_moveComp) {
        g_dest = destPtr;
        if (destPtr)
            g_candidateDest = destPtr;
    }

    if (g_expectValid && haveAfter) {
        Vec3 expected = g_expectedDest;
        if (after.x == expected.x && after.y == expected.y && after.z == expected.z) {
            if (g_moveComp != thisPtr) {
                g_moveComp = thisPtr;
                g_dest = destPtr;
                g_candidateDest = destPtr;
                g_moveSnapshotValid = false;
                g_lastMoveSnapshotTick = 0;
                g_lastMoveReadErrorTick.store(0, std::memory_order_relaxed);
                Logf("Adjusted player movement component = %p", g_moveComp);
                Engine::RequestWalkRegistration();
            }
            InterlockedExchange(&g_expectValid, 0);
        }
    }

    bool logThisCall = false;
    if (!g_moveComp) {
        logThisCall = g_updateLogCount < 64;
    } else if (thisPtr == g_moveComp) {
        logThisCall = g_updateLogCount < 256;
    }

    if (g_updateDepth++ == 0 && logThisCall) {
        Logf("updateState(this=%p, dest=%p -> (%d,%d,%d), dir=%u, run=%d, dXYZ=(%d,%d,%d))",
             thisPtr,
             destPtr,
             static_cast<int>(after.x),
             static_cast<int>(after.y),
             static_cast<int>(after.z),
             dir,
             runFlag,
             dx,
             dy,
             dz);
        ++g_updateLogCount;
    }

    --g_updateDepth;
    if (g_updateDepth == 0 && InterlockedExchange(&g_needWalkReg, 0)) {
        Log::Logf(Log::Level::Debug, Log::Category::Hooks, "H_Update safe point - scheduling Lua helper registration");
        Engine::Lua::ScheduleWalkBinding();
    }

    return rc;
}

} // namespace

extern "C" __declspec(dllexport) bool __stdcall SendWalk(int dir, int run) {
    const bool debugLog = Walk::Controller::DebugEnabled();
    const bool detailedLog = debugLog || Log::IsEnabled(Log::Category::Walk, Log::Level::Debug);

    const char* movementReason = nullptr;
    const bool movementReady = Engine::MovementReadyWithReason(&movementReason);
    const bool netReady = Net::IsSendReady();
    const int fastWalkDepth = Engine::FastWalkQueueDepth();
    SOCKET movementSocket = Engine::GetActiveFastWalkSocket();

    if (detailedLog) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Walk,
                  "SendWalk prereq movement=%d net=%d fastWalkDepth=%d socket=%p",
                  movementReady ? 1 : 0,
                  netReady ? 1 : 0,
                  fastWalkDepth,
                  reinterpret_cast<void*>(static_cast<uintptr_t>(movementSocket)));
    }

    if (!netReady) {
        Log::Logf(Log::Level::Warn, Log::Category::Walk, "SendWalk aborted: network not ready");
        return false;
    }
    if (fastWalkDepth <= 0) {
        Log::Logf(Log::Level::Warn,
                  Log::Category::Walk,
                  "SendWalk aborted: fast-walk queue empty (depth=%d)",
                  fastWalkDepth);
        return false;
    }
    if (movementSocket == INVALID_SOCKET) {
        Log::Logf(Log::Level::Warn, Log::Category::Walk, "SendWalk aborted: no active fast-walk socket");
        return false;
    }

    DWORD now = GetTickCount();
    if (MovementAckPending()) {
        uint32_t lastTick = g_lastMovementSendTickMs.load(std::memory_order_relaxed);
        if (lastTick != 0) {
            DWORD delta = now - lastTick;
            if (delta < kMovementAckThrottleMs) {
                if (g_sendThrottleLogBudget > 0 && InterlockedDecrement(&g_sendThrottleLogBudget) >= 0) {
                    uint8_t lastSent = g_lastSentSeq.load(std::memory_order_relaxed);
                    uint8_t lastAck = g_haveAckSeq.load(std::memory_order_relaxed)
                        ? g_lastAckSeq.load(std::memory_order_relaxed)
                        : 0;
                    Log::Logf(Log::Level::Debug,
                              Log::Category::Walk,
                              "SendWalk throttled: awaiting ack lastSent=0x%02X lastAck=0x%02X age=%u ms",
                              static_cast<unsigned>(lastSent),
                              static_cast<unsigned>(lastAck),
                              static_cast<unsigned>(delta));
                }
                return false;
            }
        }
    }

    if (!movementReady && detailedLog) {
        if (movementReason && movementReason[0] != '\0') {
            Log::Logf(Log::Level::Debug,
                      Log::Category::Walk,
                      "SendWalk proceeding while movement state pending (%s)",
                      movementReason);
        } else {
            Log::Logf(Log::Level::Debug,
                      Log::Category::Walk,
                      "SendWalk proceeding while movement state pending");
        }
    }

    const int normalizedDir = NormalizeDirection(dir);
    const bool shouldRun = run != 0;
    const int stepScale = shouldRun ? 2 : 1;

    if (detailedLog) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Walk,
                  "SendWalk begin dir=%d run=%d normDir=%d socket=%p",
                  dir,
                  run,
                  normalizedDir,
                  reinterpret_cast<void*>(static_cast<uintptr_t>(movementSocket)));
    }

    uint8_t pkt[7]{};
    pkt[0] = 0x02;
    pkt[1] = static_cast<uint8_t>(normalizedDir) | (shouldRun ? 0x80 : 0);
    uint8_t nextSeq = NextMovementSequence();
    pkt[2] = nextSeq;

    uint32_t key = Engine::PeekFastWalkKey(movementSocket);
    if (!key) {
        Log::Logf(Log::Level::Warn,
                  Log::Category::Walk,
                  "SendWalk aborted: fast-walk queue underflow on peek socket=%p depth=%d",
                  reinterpret_cast<void*>(static_cast<uintptr_t>(movementSocket)),
                  fastWalkDepth);
        return false;
    }

    *reinterpret_cast<uint32_t*>(pkt + 3) = htonl(key);

    bool sendOk = false;
    g_scriptSendInProgress = true;
    __try {
        sendOk = Net::SendPacketRaw(pkt, sizeof(pkt), movementSocket);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Log::Logf(Log::Level::Error,
                  Log::Category::Walk,
                  "SendWalk exception during Net::SendPacketRaw seh=0x%08lX",
                  static_cast<unsigned long>(GetExceptionCode()));
        sendOk = false;
    }
    g_scriptSendInProgress = false;

    if (!sendOk) {
        Log::Logf(Log::Level::Error,
                  Log::Category::Walk,
                  "SendWalk send failed seq=0x%02X key=0x%08X socket=%p",
                  static_cast<unsigned>(nextSeq),
                  key,
                  reinterpret_cast<void*>(static_cast<uintptr_t>(movementSocket)));
        return false;
    }

    Engine::TrackMovementTx(nextSeq, normalizedDir, shouldRun, movementSocket, key, "internal");
    Engine::PopFastWalkKey(movementSocket);
    Engine::RecordMovementSent(nextSeq);
    g_lastMovementSendTickMs.store(GetTickCount(), std::memory_order_relaxed);
    if (detailedLog) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Walk,
                  "SendWalk send succeeded seq=0x%02X key=0x%08X socket=%p",
                  static_cast<unsigned>(nextSeq),
                  key,
                  reinterpret_cast<void*>(static_cast<uintptr_t>(movementSocket)));
    }

    InterlockedExchange(&g_pendingDir, normalizedDir);
    InterlockedExchange(&g_pendingRunFlag, shouldRun ? 2 : 1);
    InterlockedExchange(&g_pendingTick, static_cast<LONG>(GetTickCount()));
    InterlockedExchange(&g_pendingMoveActive, 1);

    bool queuedLocally = TryQueueLocalStep(normalizedDir, shouldRun, stepScale);

    if (!queuedLocally) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Walk,
                  "SendWalk local queue skipped comp=%p candidate=%p dest=%p candidateDest=%p orig=%d",
                  g_moveComp,
                  g_moveCandidate,
                  g_dest,
                  g_candidateDest,
                  g_origUpdate ? 1 : 0);
    }

    if (detailedLog) {
        Log::Logf(Log::Level::Debug,
                  Log::Category::Walk,
                  "SendWalk complete queuedLocal=%d",
                  queuedLocally ? 1 : 0);
    }
    return queuedLocally || sendOk;
}

