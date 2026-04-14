#include <windows.h>
#include <winsock2.h>
#include <psapi.h>
#include <minhook.h>
#include <cstdint>
#include <cstdio>
#include <cstddef>
#include <cstring>

#include "Core/Logging.hpp"
#include "Core/Utils.hpp"
#include "Core/PatternScan.hpp"
#include "Net/SendBuilder.hpp"
#include "Engine/Movement.hpp"
#include "Engine/LuaBridge.hpp"
#include "Util/OwnerPump.hpp"

// Move variable definition to global scope
extern volatile LONG g_needWalkReg;

namespace {

struct Vec3 { int16_t x, y; int8_t z; };

static void* g_moveComp = nullptr; // movement component instance
static void* g_moveCandidate = nullptr;
static void* g_dest = nullptr;     // last destination vector
using UpdateState_t = uint32_t(__stdcall*)(void*, uint32_t, int);
static UpdateState_t g_updateState = nullptr;
static UpdateState_t g_origUpdate = nullptr;
static volatile LONG g_haveMoveComp = 0;
static long g_updateLogCount = 0;
static thread_local int g_updateDepth = 0;
static uint32_t g_fastWalkKeys[32]{};
static int g_fwTop = 0;
static Vec3 g_expectedDest{};
static volatile LONG g_expectValid = 0;
static volatile LONG g_pendingMoveActive = 0;
static volatile LONG g_pendingTick = 0;
static volatile LONG g_pendingDir = 0;
static volatile LONG g_pendingRunFlag = 0;

static constexpr int kStepDx[8] = {0, 1, 1, 1, 0, -1, -1, -1};
static constexpr int kStepDy[8] = {-1, -1, 0, 1, 1, 1, 0, -1};
static constexpr DWORD kPendingWindowMs = 500;
static constexpr size_t kMaxTrackers = 96;
static constexpr size_t kDestCopySize = 0x40;
static constexpr int kPtrDiffLogLimit = 128;
static constexpr int kIndexSampleLimit = 32;
static constexpr size_t kQueueEntrySize = 0x10;
static constexpr uintptr_t kMoveControllerVtableRva = 0x008BA9DC;
static constexpr uintptr_t kMoveControllerVtableAltRva = 0x008BA9C0;
static constexpr uintptr_t kMoveControllerGlobalRva = 0x00A3D524;
static constexpr uintptr_t kGameplayRootRva = 0x00A1A17C;
static constexpr uintptr_t kResolveMoveHelperRva = 0x001C2230;
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
static uint32_t g_lastIndexHead = 0;
static uint32_t g_lastIndexTail = 0;
static uint8_t g_lastHeadEntry[kQueueEntrySize]{};
static uint8_t g_lastTailEntry[kQueueEntrySize]{};
static bool g_haveHeadEntry = false;
static bool g_haveTailEntry = false;
static void** g_loggedVtable = nullptr;

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

static uint8_t ReadUInt8Safe(void* base, ptrdiff_t offset)
{
    if (!base)
        return 0;
    uint8_t value = 0;
    __try {
        value = *reinterpret_cast<uint8_t*>(static_cast<uint8_t*>(base) + offset);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        value = 0;
    }
    return value;
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

static bool CopyMemorySafe(const void* src, void* dst, size_t len);
static uintptr_t ExpectedMoveControllerVtable()
{
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(nullptr), &mi, sizeof(mi)))
        return 0;
    return reinterpret_cast<uintptr_t>(mi.lpBaseOfDll) + kMoveControllerVtableRva;
}

static uintptr_t AlternateMoveControllerVtable()
{
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(nullptr), &mi, sizeof(mi)))
        return 0;
    return reinterpret_cast<uintptr_t>(mi.lpBaseOfDll) + kMoveControllerVtableAltRva;
}

static bool IsMovementComponentPlausible(void* component)
{
    if (!component)
        return false;

    const uintptr_t expectedVtable = ExpectedMoveControllerVtable();
    const uintptr_t alternateVtable = AlternateMoveControllerVtable();
    const uintptr_t actualVtable = ReadPointerSafe(component, 0x00);
    if (!expectedVtable ||
        (actualVtable != expectedVtable && actualVtable != alternateVtable))
        return false;

    const uint32_t dirNow = ReadUInt32Safe(component, 0x5C);
    const uint32_t dirPrev = ReadUInt32Safe(component, 0x60);
    const uint32_t desired = ReadUInt32Safe(component, 0x64);
    return dirNow <= 8 && dirPrev <= 8 && desired <= 8;
}

static int CaptureSehInfo(EXCEPTION_POINTERS* ep,
                          DWORD* outCode,
                          void** outAddress,
                          CONTEXT* outContext)
{
    if (outCode)
        *outCode = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionCode : 0;
    if (outAddress)
        *outAddress = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionAddress : nullptr;
    if (outContext && ep && ep->ContextRecord)
        *outContext = *ep->ContextRecord;
    return EXCEPTION_EXECUTE_HANDLER;
}

static void LogMovementVtable(void* thisPtr)
{
    if (!thisPtr)
        return;
    void** vt = *reinterpret_cast<void***>(thisPtr);
    if (!vt || vt == g_loggedVtable)
        return;

    g_loggedVtable = vt;
    Logf("Movement component vtable snapshot (first 16 entries):");
    __try {
        for (int i = 0; i < 16; ++i) {
            Logf("  vtbl[%02d] = %p", i, vt[i]);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("Movement component vtable logging aborted due to access violation");
    }
}

static void LogMovementState(const char* tag, void* component)
{
    if (!tag)
        tag = "MoveState";

    if (!component) {
        Logf("%s: component unavailable", tag);
        return;
    }

    Logf("%s: comp=%p vt=%p cur=%u prev=%u desired=%u mode=%u prevMode=%u flags={79:%u 7A:%u 7B:%u 9C:%u} pending={list:%u queued:%u} target=%u pos={%.3f %.3f}",
         tag,
         component,
         reinterpret_cast<void*>(ReadPointerSafe(component, 0x00)),
         ReadUInt32Safe(component, 0x5C),
         ReadUInt32Safe(component, 0x60),
         ReadUInt32Safe(component, 0x64),
         ReadUInt32Safe(component, 0x70),
         ReadUInt32Safe(component, 0x74),
         static_cast<unsigned>(ReadUInt8Safe(component, 0x79)),
         static_cast<unsigned>(ReadUInt8Safe(component, 0x7A)),
         static_cast<unsigned>(ReadUInt8Safe(component, 0x7B)),
         static_cast<unsigned>(ReadUInt8Safe(component, 0x9C)),
         ReadUInt32Safe(component, 0x1C),
         ReadUInt32Safe(component, 0x98),
         ReadUInt32Safe(component, 0xAC),
         AsFloat(ReadUInt32Safe(component, 0x68)),
         AsFloat(ReadUInt32Safe(component, 0x6C)));
}

static void LogQueueState(const char* tag)
{
    if (!tag)
        tag = "Queue";

    if (!g_moveComp) {
        Logf("%s: queue log skipped (movement component unavailable)", tag);
        return;
    }

    Logf("%s: queueFields primary={head:%u tail:%u cap:%u count:%u} secondary={head:%u tail:%u cap:%u count:%u}",
         tag,
         ReadUInt32Safe(g_moveComp, 0x10),
         ReadUInt32Safe(g_moveComp, 0x14),
         ReadUInt32Safe(g_moveComp, 0x18),
         ReadUInt32Safe(g_moveComp, 0x1C),
         ReadUInt32Safe(g_moveComp, 0x8C),
         ReadUInt32Safe(g_moveComp, 0x90),
         ReadUInt32Safe(g_moveComp, 0x94),
         ReadUInt32Safe(g_moveComp, 0x98));
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

    g_origUpdate(g_moveComp, static_cast<uint32_t>(dir), shouldRun ? 2 : 1);

    char afterTag[64];
    sprintf_s(afterTag, sizeof(afterTag),
              "SendWalk after enqueue (dir=%d run=%d)", dir, shouldRun ? 1 : 0);
    LogQueueState(afterTag);

    return true;
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

static void FindMoveComponent();
static uint32_t __stdcall H_Update(void* thisPtr, uint32_t dir, int runFlag);

static bool ResolveMoveComponentViaClientHelper(void** outComponent)
{
    if (outComponent)
        *outComponent = nullptr;

    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(nullptr), &mi, sizeof(mi)))
        return false;

    BYTE* base = static_cast<BYTE*>(mi.lpBaseOfDll);
    auto helper = reinterpret_cast<void(*)()>(base + kResolveMoveHelperRva);
    uintptr_t gameplayRootSlot = reinterpret_cast<uintptr_t>(base + kGameplayRootRva);
    uintptr_t gameplayRoot = 0;

    __try {
        gameplayRoot = *reinterpret_cast<uintptr_t*>(gameplayRootSlot);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        gameplayRoot = 0;
    }

    if (!gameplayRoot || !helper)
        return false;

    struct LookupPair {
        void* component;
        void* refToken;
    } pair{};

#if defined(_M_IX86)
    DWORD sehCode = 0;
    void* sehAddress = nullptr;
    CONTEXT sehContext{};
    __try {
        __asm {
            mov edi, gameplayRoot
            lea esi, pair
            mov eax, helper
            call eax
        }
    }
    __except (CaptureSehInfo(GetExceptionInformation(), &sehCode, &sehAddress, &sehContext)) {
        Logf("ResolveMoveComponentViaClientHelper exception code=0x%08lX addr=%p root=%p helper=%p eax=%08lX ecx=%08lX edx=%08lX esi=%08lX edi=%08lX",
             static_cast<unsigned long>(sehCode),
             sehAddress,
             reinterpret_cast<void*>(gameplayRoot),
             helper,
             static_cast<unsigned long>(sehContext.Eax),
             static_cast<unsigned long>(sehContext.Ecx),
             static_cast<unsigned long>(sehContext.Edx),
             static_cast<unsigned long>(sehContext.Esi),
             static_cast<unsigned long>(sehContext.Edi));
        return false;
    }
#else
    return false;
#endif

    if (!pair.component) {
        Logf("ResolveMoveComponentViaClientHelper returned null rootSlot=%p root=%p helper=%p root+0x0c=%p root+0x10=%p",
             reinterpret_cast<void*>(gameplayRootSlot),
             reinterpret_cast<void*>(gameplayRoot),
             reinterpret_cast<void*>(ReadPointerSafe(reinterpret_cast<void*>(gameplayRoot), 0x0C)),
             reinterpret_cast<void*>(ReadPointerSafe(reinterpret_cast<void*>(gameplayRoot), 0x0C)),
             reinterpret_cast<void*>(ReadPointerSafe(reinterpret_cast<void*>(gameplayRoot), 0x10)));
        return false;
    }

    Logf("ResolveMoveComponentViaClientHelper rootSlot=%p root=%p helper=%p comp=%p ref=%p",
         reinterpret_cast<void*>(gameplayRootSlot),
         reinterpret_cast<void*>(gameplayRoot),
         helper,
         pair.component,
         pair.refToken);
    if (outComponent)
        *outComponent = pair.component;
    return true;
}

static int NormalizeDirection(int dir)
{
    if (dir >= 0)
        return dir & 7;
    int normalized = dir % 8;
    if (normalized < 0)
        normalized += 8;
    return normalized & 7;
}

static void SetWalkFailure(std::string* outReason, const char* reason)
{
    if (!outReason)
        return;
    outReason->assign(reason ? reason : "walk_failed");
}

static void AdoptMovementComponent(void* component, const char* reason, uint32_t dir = 8, int mode = -1)
{
    if (!component)
        return;

    const bool changed = (g_moveComp != component);
    g_moveCandidate = component;
    g_moveComp = component;
    InterlockedExchange(&g_haveMoveComp, 1);

    if (!changed)
        return;

    char buf[224];
    sprintf_s(buf,
              sizeof(buf),
              "Movement component adopted = %p (reason=%s dir=%u mode=%d)",
              component,
              reason ? reason : "<none>",
              dir,
              mode);
    WriteRawLog(buf);
    LogMovementVtable(component);
    Engine::RequestWalkRegistration();
}

static bool EnsureMovementComponent(const char* reason)
{
    if (g_moveComp && IsMovementComponentPlausible(g_moveComp))
        return true;

    if (g_moveComp && !IsMovementComponentPlausible(g_moveComp)) {
        Logf("Movement component rejected as implausible: %p vt=%p reason=%s",
             g_moveComp,
             reinterpret_cast<void*>(ReadPointerSafe(g_moveComp, 0x00)),
             reason ? reason : "<none>");
        g_moveComp = nullptr;
        InterlockedExchange(&g_haveMoveComp, 0);
    }

    void* helperCandidate = nullptr;
    if (ResolveMoveComponentViaClientHelper(&helperCandidate) &&
        helperCandidate &&
        IsMovementComponentPlausible(helperCandidate)) {
        AdoptMovementComponent(helperCandidate,
                               reason ? reason : "client_helper_retry",
                               ReadUInt32Safe(helperCandidate, 0x5C),
                               static_cast<int>(ReadUInt32Safe(helperCandidate, 0x70)));
        return g_moveComp != nullptr;
    }

    if (g_moveCandidate && IsMovementComponentPlausible(g_moveCandidate)) {
        AdoptMovementComponent(g_moveCandidate, reason ? reason : "candidate");
        return g_moveComp != nullptr;
    }

    FindMoveComponent();
    return g_moveComp && IsMovementComponentPlausible(g_moveComp);
}

static bool SendWalkStepInternal(int dir, int run, std::string* outReason)
{
    if (dir < 0 || dir > 7) {
        SetWalkFailure(outReason, "invalid_direction");
        return false;
    }

    const uint32_t callerTid = GetCurrentThreadId();
    const uint32_t ownerTid = Util::OwnerPump::GetOwnerThreadId();
    if (ownerTid == 0 || callerTid != ownerTid) {
        SetWalkFailure(outReason, "wrong_thread");
        return false;
    }

    if (!g_origUpdate) {
        SetWalkFailure(outReason, "movement_not_ready");
        return false;
    }

    if (!EnsureMovementComponent("SendWalkStepInternal")) {
        SetWalkFailure(outReason, "movement_not_ready");
        return false;
    }

    const int normalizedDir = NormalizeDirection(dir);
    const bool shouldRun = run != 0;
    const int nativeMode = shouldRun ? 2 : 1;

    char introBuf[256];
    sprintf_s(introBuf,
              sizeof(introBuf),
              "SendWalk direct begin dir=%d run=%d mode=%d caller=%u owner=%u comp=%p",
              normalizedDir,
              shouldRun ? 1 : 0,
              nativeMode,
              callerTid,
              ownerTid,
              g_moveComp);
    WriteRawLog(introBuf);
    LogMovementState("SendWalk direct state", g_moveComp);

    char beforeTag[80];
    sprintf_s(beforeTag, sizeof(beforeTag),
              "SendWalk direct before (dir=%d mode=%d)", normalizedDir, nativeMode);
    LogQueueState(beforeTag);

    uint32_t rc = 0;
    DWORD sehCode = 0;
    void* sehAddress = nullptr;
    CONTEXT sehContext{};
    __try {
        rc = g_origUpdate(g_moveComp, static_cast<uint32_t>(normalizedDir), nativeMode);
    }
    __except (CaptureSehInfo(GetExceptionInformation(), &sehCode, &sehAddress, &sehContext)) {
        char faultBuf[352];
        sprintf_s(faultBuf,
                  sizeof(faultBuf),
                  "SendWalk direct exception code=0x%08lX addr=%p dir=%d mode=%d comp=%p eax=%08lX ebx=%08lX ecx=%08lX edx=%08lX esi=%08lX edi=%08lX ebp=%08lX",
                  static_cast<unsigned long>(sehCode),
                  sehAddress,
                  normalizedDir,
                  nativeMode,
                  g_moveComp,
                  static_cast<unsigned long>(sehContext.Eax),
                  static_cast<unsigned long>(sehContext.Ebx),
                  static_cast<unsigned long>(sehContext.Ecx),
                  static_cast<unsigned long>(sehContext.Edx),
                  static_cast<unsigned long>(sehContext.Esi),
                  static_cast<unsigned long>(sehContext.Edi),
                  static_cast<unsigned long>(sehContext.Ebp));
        WriteRawLog(faultBuf);
        SetWalkFailure(outReason, "movement_fault");
        return false;
    }

    char afterTag[80];
    sprintf_s(afterTag, sizeof(afterTag),
              "SendWalk direct after (dir=%d mode=%d)", normalizedDir, nativeMode);
    LogQueueState(afterTag);

    char outroBuf[192];
    sprintf_s(outroBuf,
              sizeof(outroBuf),
              "SendWalk direct completed rc=%u okByte=%u dir=%d mode=%d",
              rc,
              static_cast<unsigned>(rc & 0xFF),
              normalizedDir,
              nativeMode);
    WriteRawLog(outroBuf);

    const bool accepted = (rc & 0xFF) != 0;
    if (!accepted) {
        SetWalkFailure(outReason, "client_rejected");
        return false;
    }

    if (outReason)
        outReason->assign("queued");
    return true;
}

} // namespace

namespace Engine {

void PushFastWalkKey(uint32_t key) {
    if (g_fwTop < (int)(sizeof(g_fastWalkKeys) / sizeof(g_fastWalkKeys[0])))
        g_fastWalkKeys[g_fwTop++] = key;
}

uint32_t PopFastWalkKey() {
    return g_fwTop > 0 ? g_fastWalkKeys[--g_fwTop] : 0;
}

bool MovementReady() {
    if (g_updateState && !g_moveComp)
        FindMoveComponent();
    return g_updateState && g_moveComp;
}

void RequestWalkRegistration() {
    InterlockedExchange(&g_needWalkReg, 1);
    Engine::Lua::ScheduleWalkBinding();
}

bool SendWalkStep(int dir, int run, std::string* outReason) {
    return SendWalkStepInternal(dir, run, outReason);
}

bool InitMovementHooks() {
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
            FindMoveComponent();
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
    g_moveComp = nullptr;
    g_moveCandidate = nullptr;
    g_dest = nullptr;
    InterlockedExchange(&g_haveMoveComp, 0);
    g_fwTop = 0;
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
    InterlockedExchange(&g_memDumpBudget, 4);
    InterlockedExchange(&g_expectValid, 0);
    InterlockedExchange(&g_pendingMoveActive, 0);
    InterlockedExchange(&g_pendingTick, 0);
    InterlockedExchange(&g_pendingDir, 0);
    InterlockedExchange(&g_pendingRunFlag, 0);
}

} // namespace Engine

namespace {

static void FindMoveComponent() {
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(nullptr), &mi, sizeof(mi)))
        return;

    BYTE* base = (BYTE*)mi.lpBaseOfDll;
    BYTE* vtable = base + kMoveControllerVtableRva;
    void* globalCandidate = reinterpret_cast<void*>(base + kMoveControllerGlobalRva);

    MEMORY_BASIC_INFORMATION vtableMbi{};
    if (!VirtualQuery(vtable, &vtableMbi, sizeof(vtableMbi)) ||
        vtableMbi.State != MEM_COMMIT ||
        (vtableMbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
        WriteRawLog("Move component vtable unavailable");
        return;
    }

    char buf[64];
    sprintf_s(buf, sizeof(buf), "MoveComp vtable at %p", vtable);
    WriteRawLog(buf);

    if (globalCandidate) {
        const uint32_t dirNow = ReadUInt32Safe(globalCandidate, 0x5C);
        const uint32_t dirPrev = ReadUInt32Safe(globalCandidate, 0x60);
        const uint32_t desired = ReadUInt32Safe(globalCandidate, 0x64);
        const uint32_t mode = ReadUInt32Safe(globalCandidate, 0x70);
        const uintptr_t vt = ReadPointerSafe(globalCandidate, 0x00);
        char globalBuf[224];
        sprintf_s(globalBuf,
                  sizeof(globalBuf),
                  "MoveComp global candidate %p vt=%p dir=%u prev=%u desired=%u mode=%u",
                  globalCandidate,
                  reinterpret_cast<void*>(vt),
                  dirNow,
                  dirPrev,
                  desired,
                  mode);
        WriteRawLog(globalBuf);
        if (vt == reinterpret_cast<uintptr_t>(vtable)) {
            AdoptMovementComponent(globalCandidate, "global_object", dirNow, static_cast<int>(mode));
            return;
        }
    }

    void* helperCandidate = nullptr;
    if (ResolveMoveComponentViaClientHelper(&helperCandidate) && helperCandidate) {
        char helperBuf[192];
        sprintf_s(helperBuf,
                  sizeof(helperBuf),
                  "MoveComp helper candidate %p dir=%u prev=%u desired=%u vt=%p",
                  helperCandidate,
                  ReadUInt32Safe(helperCandidate, 0x5C),
                  ReadUInt32Safe(helperCandidate, 0x60),
                  ReadUInt32Safe(helperCandidate, 0x64),
                  reinterpret_cast<void*>(ReadPointerSafe(helperCandidate, 0x00)));
        WriteRawLog(helperBuf);
        if (ReadPointerSafe(helperCandidate, 0x00) == reinterpret_cast<uintptr_t>(vtable)) {
            AdoptMovementComponent(helperCandidate,
                                   "client_helper",
                                   ReadUInt32Safe(helperCandidate, 0x5C),
                                   static_cast<int>(ReadUInt32Safe(helperCandidate, 0x70)));
            return;
        }
    }

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
                    const uint32_t dirNow = ReadUInt32Safe(p, 0x5C);
                    const uint32_t dirPrev = ReadUInt32Safe(p, 0x60);
                    if (dirNow > 8 || dirPrev > 8)
                        continue;

                    MEMORY_BASIC_INFORMATION mbi2;
                    if (VirtualQuery(p, &mbi2, sizeof(mbi2)) &&
                        (mbi2.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                        g_moveCandidate = p;
                        sprintf_s(buf,
                                  sizeof(buf),
                                  "MoveComp candidate %p dir=%u prev=%u",
                                  p,
                                  dirNow,
                                  dirPrev);
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

static uint32_t __stdcall H_Update(void* thisPtr, uint32_t dir, int runFlag) {
    Util::OwnerPump::DrainOnOwnerThread();
    Engine::Lua::PollQueuedRawCasts();

    if (thisPtr) {
        if (!g_moveCandidate) {
            g_moveCandidate = thisPtr;
            Logf("Captured movement candidate = %p (thread %lu)", g_moveCandidate, GetCurrentThreadId());
        }

        if (!g_moveComp) {
            AdoptMovementComponent(thisPtr, "live_update", dir, runFlag);
        } else if (g_moveComp != thisPtr) {
            Logf("Movement update on alternate component this=%p active=%p dir=%u mode=%d",
                 thisPtr,
                 g_moveComp,
                 dir,
                 runFlag);
            AdoptMovementComponent(thisPtr, "live_update_override", dir, runFlag);
            ++g_updateLogCount;
        }
    }

    bool logThisCall = false;
    if (!g_moveComp) {
        logThisCall = g_updateLogCount < 64;
    } else if (thisPtr == g_moveComp) {
        logThisCall = g_updateLogCount < 256;
    }

    ++g_updateDepth;
    if (g_updateDepth == 1 && logThisCall) {
        Logf("updateState(this=%p, dir=%u, mode=%d)", thisPtr, dir, runFlag);
        ++g_updateLogCount;
    }

    uint32_t rc = g_origUpdate ? g_origUpdate(thisPtr, dir, runFlag) : 0;

    if (g_updateDepth == 1 && logThisCall) {
        Logf("updateState result rc=%u this=%p dir=%u mode=%d", rc, thisPtr, dir, runFlag);
    }

    --g_updateDepth;
    if (g_updateDepth == 0) {
        Engine::Lua::ScheduleCastWrapRetry("H_Update safe point");
        if (InterlockedExchange(&g_needWalkReg, 0)) {
            WriteRawLog("H_Update safe point - scheduling Lua helper registration");
            Engine::Lua::ScheduleWalkBinding();
        }
    }

    return rc;
}

} // namespace

extern "C" __declspec(dllexport) bool __stdcall SendWalk(int dir, int run) {
    std::string reason;
    bool ok = Engine::SendWalkStep(dir, run, &reason);
    if (!ok) {
        char buf[160];
        sprintf_s(buf,
                  sizeof(buf),
                  "SendWalk failed dir=%d run=%d reason=%s",
                  dir,
                  run,
                  reason.empty() ? "<none>" : reason.c_str());
        WriteRawLog(buf);
    }
    return ok;
}
