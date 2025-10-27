#include <windows.h>
#include <dbghelp.h>
#include <cstdio>
#include <cstring>
#include <limits>
#include <cstdint>
#include <minhook.h>
#include "Core/Logging.hpp"
#include "Core/PatternScan.hpp"
#include "Core/Utils.hpp"
#include "Net/SendBuilder.hpp"
#include "Engine/GlobalState.hpp"
#include "Engine/LuaBridge.hpp"

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Define the global variable that was previously only declared as extern
volatile LONG g_needWalkReg = 0;

namespace Net {

using SendPacket_t = void(__thiscall*)(void* netMgr, const void* pkt, int len);
using SendBuilder_t = void* (__thiscall*)(void* thisPtr, void* builder);

static GlobalStateInfo* g_state = nullptr;
static SendPacket_t g_sendPacket = nullptr;
static void* g_sendPacketTarget = nullptr;
static bool g_sendPacketHooked = false;
static void* g_netMgr = nullptr;
static SendBuilder_t fpSendBuilder = nullptr;
static bool g_sendBuilderHooked = false;
static void* g_sendBuilderTarget = nullptr;
static bool g_builderScanned = false;
static bool g_loggedNetScanFailure = false;
static bool g_initLogged = false;
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

static bool SafeCopy(void* dst, const void* src, size_t bytes)
{
    __try {
        memcpy(dst, src, bytes);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static HMODULE GetGameModule()
{
    static HMODULE module = GetModuleHandleW(nullptr);
    return module;
}

static bool IsExecutableCodeAddress(void* addr)
{
    if (!addr)
        return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(addr, &mbi, sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD))
        return false;
    DWORD protect = mbi.Protect & 0xFF;
    switch (protect)
    {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

static bool IsGameVtableAddress(void* addr)
{
    if (!addr)
        return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(addr, &mbi, sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD))
        return false;
    HMODULE gameModule = GetGameModule();
    if (!gameModule)
        return false;
    if (mbi.AllocationBase != gameModule)
        return false;
    DWORD protect = mbi.Protect & 0xFF;
    return protect == PAGE_READONLY ||
           protect == PAGE_READWRITE ||
           protect == PAGE_EXECUTE_READ ||
           protect == PAGE_EXECUTE_READWRITE;
}

static void TryHookSendBuilder(void* endpoint);
static bool TryDiscoverEndpointFromManager(void* manager);
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

static bool TryDiscoverEndpointFromManager(void* manager)
{
    if (!manager || g_builderScanned)
        return false;

    DWORD now = GetTickCount();
    if (manager == g_lastManagerScanPtr && (DWORD)(now - g_lastManagerScanTick) < 1000)
        return false;

    g_lastManagerScanPtr = manager;
    g_lastManagerScanTick = now;

    const size_t kScanLimit = 0x200;
    char startBuf[160];
    sprintf_s(startBuf, sizeof(startBuf),
              "DiscoverEndpoint: scan begin manager=%p window=0x%zx",
              manager,
              kScanLimit);
    WriteRawLog(startBuf);

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

    for (size_t offset = 0; offset <= kScanLimit; offset += sizeof(void*))
    {
        ++slotsExamined;
        void* candidate = nullptr;
        if (!SafeCopy(&candidate, reinterpret_cast<const uint8_t*>(manager) + offset, sizeof(candidate)))
            continue;
        if (!candidate || candidate == manager || candidate == g_lastLoggedEndpoint)
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
        if (!IsGameVtableAddress(vtbl)) {
            if (firstNonGameOffset == kInvalidOffset) {
                firstNonGameOffset = offset;
                firstNonGameValue = candidate;
                firstNonGameVtable = vtbl;
            }
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
            continue;
        }

        if (firstExecOffset == kInvalidOffset) {
            firstExecOffset = offset;
            firstExecValue = candidate;
            firstExecEntry = firstEntry;
        }

        TryHookSendBuilder(candidate);
        if (g_builderScanned)
        {
            g_lastLoggedEndpoint = candidate;
            char buf[256];
            sprintf_s(buf, sizeof(buf),
                      "DiscoverEndpoint: manager=%p offset=0x%02zx endpoint=%p vtbl=%p",
                      manager,
                      offset,
                      candidate,
                      vtbl);
            WriteRawLog(buf);
            WriteRawLog("DiscoverEndpoint: endpoint hook established via manager scan");
            return true;
        }
    }

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

    char summary[320];
    sprintf_s(summary, sizeof(summary),
              "DiscoverEndpoint: scan complete manager=%p slots=%zu firstCandidate=%s firstCommitted=%s firstGame=%s(vtbl=%p) firstExecutable=%s(entry=%p)",
              manager,
              slotsExamined,
              candidateInfo,
              committedInfo,
              gameInfo,
              firstGameVtable,
              execInfo,
              firstExecEntry);
    WriteRawLog(summary);

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

    return false;
}

static bool TryDiscoverFromEngineContext()
{
    if (g_builderScanned || !g_state)
        return false;

    void* engineCtx = g_state->engineContext;
    if (!engineCtx)
        return false;

    DWORD now = GetTickCount();
    if (engineCtx == g_lastEngineCtxScanPtr && (DWORD)(now - g_lastEngineCtxScanTick) < 1000)
        return false;
    g_lastEngineCtxScanPtr = engineCtx;
    g_lastEngineCtxScanTick = now;

    const size_t kScanLimit = 0x200;
    char startBuf[160];
    sprintf_s(startBuf, sizeof(startBuf),
              "EngineCtx scan begin ctx=%p window=0x%zx",
              engineCtx,
              kScanLimit);
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

        if (TryDiscoverEndpointFromManager(candidate))
        {
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

    TryDiscoverEndpointFromManager(g_netMgr);
}

static bool FunctionCallsSendPacket(void* fn)
{
    if (!fn || !g_sendPacketTarget)
        return false;

    uint8_t buffer[256]{};
    if (!SafeCopy(buffer, fn, sizeof(buffer)))
        return false;

    uintptr_t fnAddr = reinterpret_cast<uintptr_t>(fn);
    uintptr_t target = reinterpret_cast<uintptr_t>(g_sendPacketTarget);

    for (size_t i = 0; i + 5 <= sizeof(buffer); ++i)
    {
        if (buffer[i] != 0xE8) // CALL rel32
            continue;
        int32_t rel = 0;
        memcpy(&rel, buffer + i + 1, sizeof(rel));
        uintptr_t callTarget = fnAddr + i + 5 + static_cast<intptr_t>(rel);
        if (callTarget == target)
            return true;
    }

    return false;
}

static void* __fastcall Hook_SendBuilder(void* thisPtr, void* builder)
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

    if (plainPtr && len > 0)
        DumpMemory("PLAINTEXT SendBuilder", plainPtr, len);
    else
        WriteRawLog("Hook_SendBuilder: empty payload");

    return fpSendBuilder ? fpSendBuilder(thisPtr, builder) : nullptr;
}

static bool ScanEndpointVTable(void* endpoint)
{
    void** vtbl = nullptr;
    if (!SafeCopy(&vtbl, endpoint, sizeof(vtbl)) || !vtbl) {
        char msg[160];
        sprintf_s(msg, sizeof(msg), "ScanEndpointVTable: endpoint=%p vtbl unreadable", endpoint);
        WriteRawLog(msg);
        return false;
    }

    void* entries[32]{};
    if (!SafeCopy(entries, vtbl, sizeof(entries))) {
        char msg[160];
        sprintf_s(msg, sizeof(msg), "ScanEndpointVTable: vtbl=%p entries unreadable", vtbl);
        WriteRawLog(msg);
        return false;
    }

    int matchedIndex = -1;
    void* matchedFn = nullptr;
    int fallbackIndex = -1;
    void* fallbackFn = nullptr;

    for (int i = 0; i < 32; ++i)
    {
        void* fn = entries[i];
        Logf("endpoint vtbl[%02X] = %p", i, fn);
        if (!fn)
            continue;
        if (!IsExecutableCodeAddress(fn))
            continue;

        if (!g_sendBuilderHooked && FunctionCallsSendPacket(fn)) {
            matchedIndex = i;
            matchedFn = fn;
            break;
        }

        if (fallbackFn == nullptr)
        {
            fallbackIndex = i;
            fallbackFn = fn;
        }
    }

    if (!matchedFn)
    {
        matchedIndex = fallbackIndex;
        matchedFn = fallbackFn;
        if (matchedFn)
        {
            char info[160];
            sprintf_s(info, sizeof(info),
                      "ScanEndpointVTable: using fallback executable entry index=%d fn=%p",
                      matchedIndex,
                      matchedFn);
            WriteRawLog(info);
        }
    }

    if (matchedFn && !g_sendBuilderHooked)
    {
        if (MH_CreateHook(matchedFn, Hook_SendBuilder, reinterpret_cast<LPVOID*>(&fpSendBuilder)) == MH_OK &&
            MH_EnableHook(matchedFn) == MH_OK)
        {
            g_sendBuilderHooked = true;
            g_sendBuilderTarget = matchedFn;
            char buf[160];
            sprintf_s(buf, sizeof(buf),
                      "SendBuilder hook attached index=%d fn=%p via vtbl=%p",
                      matchedIndex,
                      matchedFn,
                      vtbl);
            WriteRawLog(buf);
            return true;
        }
        else
        {
            WriteRawLog("ScanEndpointVTable: failed to hook suspected builder");
        }
    }
    else if (!matchedFn && !g_sendBuilderHooked)
    {
        WriteRawLog("ScanEndpointVTable: no vtbl entry calling SendPacket");
    }

    return g_sendBuilderHooked;
}

static void TryHookSendBuilder(void* endpoint)
{
    if (g_builderScanned || !endpoint)
        return;

    if (ScanEndpointVTable(endpoint))
        g_builderScanned = true;
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

    if (g_netMgr)
        TryDiscoverEndpointFromManager(g_netMgr);

    void* rawCfg = g_state->networkConfig;
    if (!rawCfg) {
        if (!g_loggedNetScanFailure) {
            g_loggedNetScanFailure = true;
            WriteRawLog("HookSendBuilderFromNetMgr: networkConfig pointer is null");
        }
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
            TryDiscoverEndpointFromManager(g_netMgr);
            return;
        }

        bool stateChanged = (mbi.State != g_lastNetCfgState) ||
                            (mbi.Protect != g_lastNetCfgProtect) ||
                            (mbi.Type != g_lastNetCfgType) ||
                            (mbi.BaseAddress != g_lastNetCfgBase) ||
                            (mbi.RegionSize != g_lastNetCfgRegionSize);
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

        if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD)) {
            if (!g_loggedNetScanFailure) {
                WriteRawLog("HookSendBuilderFromNetMgr: networkConfig region not readable yet");
            }
            g_loggedNetScanFailure = true;
            TryDiscoverEndpointFromManager(g_netMgr);
            TryDiscoverFromEngineContext();
            return;
        }

        // Region is committed but SafeCopy failed; try again below to capture exception info.
        if (!SafeCopy(snapshot, rawCfg, sizeof(snapshot))) {
            if (!g_loggedNetScanFailure) {
                char buf[160];
                sprintf_s(buf, sizeof(buf), "HookSendBuilderFromNetMgr: networkConfig=%p access still failing post-commit", rawCfg);
                WriteRawLog(buf);
            }
            g_loggedNetScanFailure = true;
            TryDiscoverEndpointFromManager(g_netMgr);
            TryDiscoverFromEngineContext();
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

    MEMORY_BASIC_INFORMATION mbiCurrent{};
    if (VirtualQuery(rawCfg, &mbiCurrent, sizeof(mbiCurrent))) {
        bool changed = (mbiCurrent.State != g_lastNetCfgState) ||
                       (mbiCurrent.Protect != g_lastNetCfgProtect) ||
                       (mbiCurrent.Type != g_lastNetCfgType) ||
                       (mbiCurrent.BaseAddress != g_lastNetCfgBase) ||
                       (mbiCurrent.RegionSize != g_lastNetCfgRegionSize);
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
        if (SafeCopy(&vtbl, managerCandidate, sizeof(vtbl)) && vtbl) {
            char mgrBuf[160];
            sprintf_s(mgrBuf, sizeof(mgrBuf), "HookSendBuilderFromNetMgr: manager=%p vtbl=%p",
                      managerCandidate, reinterpret_cast<void*>(vtbl));
            WriteRawLog(mgrBuf);
            CaptureNetManager(managerCandidate, "networkConfig[0]");
            g_lastLoggedManager = managerCandidate;
            TryHookSendBuilder(managerCandidate);
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
                TryHookSendBuilder(endpointCandidate);
            }
        }
    }
}

static void __fastcall H_SendPacket(void* thisPtr, void*, const void* pkt, int len)
{
    char tagBuf[128];
    sprintf_s(tagBuf, sizeof(tagBuf), "H_SendPacket enter ctx=%p len=%d", thisPtr, len);
    WriteRawLog(tagBuf);
    DumpMemory("PLAIN-SendPacket", const_cast<void*>(pkt), len);

    if (pkt && len > 0) {
        uint8_t id = *(const uint8_t*)pkt;
        char tag[64];
        sprintf_s(tag, sizeof(tag), "H_SendPacket(pktLen=%d id=%02X)", len, id);
        CaptureNetManager(thisPtr, tag);
    } else {
        CaptureNetManager(thisPtr, "H_SendPacket");
    }
    if (!g_builderScanned)
        HookSendBuilderFromNetMgr();
    LONG previous = InterlockedExchange(&g_needWalkReg, 0);
    if (previous != 0)
        Engine::Lua::ScheduleWalkBinding();
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
            WriteRawLog("SendPacket hook installed");
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
            g_builderScanned = false;
            g_loggedNetScanFailure = false;
            g_haveNetCfgSnapshot = false;
            memset(g_lastNetCfgSnapshot, 0, sizeof(g_lastNetCfgSnapshot));
            g_lastLoggedManager = nullptr;
            g_lastLoggedEndpoint = nullptr;
        }
    }

    if (!g_initLogged || stateChanged) {
        char initBuf[160];
        sprintf_s(initBuf, sizeof(initBuf),
                  "InitSendBuilder invoked state=%p networkConfig=%p",
                  state,
                  state ? state->networkConfig : nullptr);
        WriteRawLog(initBuf);
        g_initLogged = true;
    }

    EnsureMemoryHooks();

    if (!g_sendPacketTarget)
        FindSendPacket();
    HookSendPacket();
    HookSendBuilderFromNetMgr();
    return g_sendPacketHooked;
}

void PollSendBuilder()
{
    if (!g_state)
        return;
    if (g_netMgr && g_builderScanned)
        return;

    if (!g_netMgr)
        TryDiscoverFromEngineContext();

    if (g_netMgr)
        TryDiscoverEndpointFromManager(g_netMgr);

    DWORD now = GetTickCount();
    DWORD last = g_lastPollTick;
    if (last != 0 && (DWORD)(now - last) < 100)
        return;
    g_lastPollTick = now;

    if (!g_sendPacketTarget)
        FindSendPacket();
    HookSendPacket();
    HookSendBuilderFromNetMgr();
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
    g_netMgr = nullptr;
    g_state = nullptr;
    g_lastManagerScanPtr = nullptr;
    g_lastManagerScanTick = 0;
}

bool SendPacketRaw(const void* bytes, int len)
{
    if (len <= 0 || !bytes)
        return false;

    if (!g_sendPacket || !g_netMgr)
        return false;

    void* vtbl = nullptr;
    if (!SafeCopy(&vtbl, g_netMgr, sizeof(vtbl)) || !vtbl) {
        WriteRawLog("SendPacketRaw: net manager pointer not readable");
        return false;
    }

    bool sent = false;
    __try {
        g_sendPacket(g_netMgr, bytes, len);
        sent = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("SendPacketRaw: exception while invoking client SendPacket");
        sent = false;
    }
    return sent;
}

bool IsSendReady()
{
    return g_sendPacket && g_netMgr;
}

} // namespace Net

