#include "SpellProbe.h"

#include <windows.h>

#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "Core/Logging.hpp"

namespace {

struct SpellProbeState {
    uintptr_t entry = 0;
    BYTE originalEntryByte = 0;
    bool installed = false;
    bool entryArmed = false;
    int argCount = 0;
    int maxHits = 0;
    int rateMs = 0;
    volatile LONG hitCount = 0;
    volatile LONG lastLogTick = 0;
    PVOID vehHandle = nullptr;
};

static SpellProbeState g_probe;

static INIT_ONCE g_lockOnce = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION g_lock;
static bool g_lockReady = false;

static BOOL CALLBACK InitLockOnce(PINIT_ONCE, PVOID, PVOID*) {
    InitializeCriticalSection(&g_lock);
    g_lockReady = true;
    return TRUE;
}

static void EnsureLock() {
    InitOnceExecuteOnce(&g_lockOnce, InitLockOnce, nullptr, nullptr);
}

static constexpr int kMaxReturnSlots = 16;

struct ReturnSlot {
    uintptr_t site = 0;
    BYTE original = 0;
    bool shouldLog = false;
};

static thread_local ReturnSlot g_returnSlots[kMaxReturnSlots];
static thread_local int g_returnDepth = 0;
static thread_local bool g_tlsEntryStepPending = false;

static void LogSpell(const char* fmt, ...) {
    char buffer[256];
    va_list args;
    va_start(args, fmt);
    vsprintf_s(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    WriteRawLog(buffer);
}

static bool PatchByteCapture(uintptr_t address, BYTE value, BYTE& outOriginal) {
    if (!address)
        return false;

    auto* ptr = reinterpret_cast<BYTE*>(address);
    BYTE previous = 0;
    __try {
        previous = *ptr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(ptr, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;
    outOriginal = previous;
    *ptr = value;
    FlushInstructionCache(GetCurrentProcess(), ptr, 1);
    DWORD dummy = 0;
    VirtualProtect(ptr, 1, oldProtect, &dummy);
    return true;
}

static bool PatchByteNoCapture(uintptr_t address, BYTE value) {
    if (!address)
        return false;
    auto* ptr = reinterpret_cast<BYTE*>(address);
    DWORD oldProtect = 0;
    if (!VirtualProtect(ptr, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;
    *ptr = value;
    FlushInstructionCache(GetCurrentProcess(), ptr, 1);
    DWORD dummy = 0;
    VirtualProtect(ptr, 1, oldProtect, &dummy);
    return true;
}

static bool ArmEntryBreakpoint() {
    if (!g_probe.entry)
        return false;
    if (!PatchByteCapture(g_probe.entry, 0xCC, g_probe.originalEntryByte))
        return false;
    g_probe.entryArmed = true;
    return true;
}

static bool RestoreEntryBreakpoint() {
    if (!g_probe.entry || !g_probe.entryArmed)
        return true;
    if (!PatchByteNoCapture(g_probe.entry, g_probe.originalEntryByte)) {
        LogSpell("[spell.probe] error: failed to restore entry byte");
        return false;
    }
    g_probe.entryArmed = false;
    return true;
}

static bool RearmEntryBreakpoint() {
    if (!g_probe.entry)
        return false;
    if (!PatchByteNoCapture(g_probe.entry, 0xCC)) {
        LogSpell("[spell.probe] error: failed to re-arm entry breakpoint");
        return false;
    }
    g_probe.entryArmed = true;
    return true;
}

static uint32_t ReadStackDword(uintptr_t address) {
    __try {
        return *reinterpret_cast<uint32_t*>(address);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

static bool ShouldEmitLog(DWORD now) {
    if (g_probe.maxHits > 0) {
        LONG hits = InterlockedCompareExchange(&g_probe.hitCount, 0, 0);
        if (hits >= g_probe.maxHits)
            return false;
    }
    DWORD last = static_cast<DWORD>(InterlockedCompareExchange(&g_probe.lastLogTick, 0, 0));
    if (g_probe.rateMs > 0 && last != 0) {
        DWORD delta = now - last;
        if (delta < static_cast<DWORD>(g_probe.rateMs))
            return false;
    }
    return true;
}

static void NoteLogEmission(DWORD now) {
    if (g_probe.maxHits > 0)
        InterlockedIncrement(&g_probe.hitCount);
    InterlockedExchange(&g_probe.lastLogTick, static_cast<LONG>(now));
}

static void LogEnter(const CONTEXT* ctx) {
    if (!ctx)
        return;
    char line[320];
    int offset = sprintf_s(line,
                           sizeof(line),
                           "[SpellProbe:ENTER] eip=%p ecx=%p esp=%p",
                           reinterpret_cast<void*>(g_probe.entry),
                           reinterpret_cast<void*>(ctx->Ecx),
                           reinterpret_cast<void*>(ctx->Esp));
    for (int i = 0; i < g_probe.argCount && i < 4; ++i) {
        uintptr_t argAddr = static_cast<uintptr_t>(ctx->Esp) + 4u + static_cast<uintptr_t>(i) * 4u;
        uint32_t value = ReadStackDword(argAddr);
        offset += sprintf_s(line + offset,
                            sizeof(line) - static_cast<size_t>(offset),
                            " arg%d=%08X",
                            i,
                            value);
        if (offset >= static_cast<int>(sizeof(line)))
            break;
    }
    WriteRawLog(line);
}

static void LogLeave(const ReturnSlot& slot, const CONTEXT* ctx) {
    if (!ctx)
        return;
    char line[160];
    sprintf_s(line,
              sizeof(line),
              "[SpellProbe:LEAVE] retSite=%p EAX=%08X",
              reinterpret_cast<void*>(slot.site),
              static_cast<unsigned int>(ctx->Eax));
    WriteRawLog(line);
}

static bool ArmReturnBreakpoint(uintptr_t retSite, bool shouldLog) {
    if (!shouldLog)
        return false;
    if (!retSite)
        return false;
    if (g_returnDepth >= kMaxReturnSlots)
        return false;
    BYTE original = 0;
    if (!PatchByteCapture(retSite, 0xCC, original))
        return false;
    g_returnSlots[g_returnDepth].site = retSite;
    g_returnSlots[g_returnDepth].original = original;
    g_returnSlots[g_returnDepth].shouldLog = shouldLog;
    ++g_returnDepth;
    return true;
}

static uintptr_t BreakpointAddressFromContext(const CONTEXT* ctx) {
    if (!ctx)
        return 0;
    uintptr_t eip = static_cast<uintptr_t>(ctx->Eip);
    if (eip == 0)
        return 0;
    return eip - 1;
}

static bool HandleReturnBreakpoint(CONTEXT* ctx) {
    if (g_returnDepth <= 0)
        return false;
    uintptr_t faultAfter = ctx ? static_cast<uintptr_t>(ctx->Eip) : 0;
    uintptr_t site = BreakpointAddressFromContext(ctx);
    if (!site)
        site = faultAfter;

    int index = -1;
    for (int i = g_returnDepth - 1; i >= 0; --i) {
        if (g_returnSlots[i].site == site || g_returnSlots[i].site == faultAfter) {
            index = i;
            break;
        }
    }
    if (index < 0)
        return false;

    ReturnSlot slot = g_returnSlots[index];
    for (int i = index + 1; i < g_returnDepth; ++i)
        g_returnSlots[i - 1] = g_returnSlots[i];
    --g_returnDepth;

    PatchByteNoCapture(slot.site, slot.original);
    ctx->Eip = static_cast<DWORD>(slot.site);
    if (slot.shouldLog)
        LogLeave(slot, ctx);
    return true;
}

static bool HandleEntryBreakpoint(CONTEXT* ctx) {
    if (!ctx)
        return false;
    if (!RestoreEntryBreakpoint())
        return false;
    ctx->Eip = static_cast<DWORD>(g_probe.entry);
    ctx->EFlags |= 0x100u;
    g_tlsEntryStepPending = true;

    DWORD now = GetTickCount();
    bool doLog = ShouldEmitLog(now);
    if (doLog) {
        NoteLogEmission(now);
        LogEnter(ctx);
        uintptr_t retSite = ReadStackDword(static_cast<uintptr_t>(ctx->Esp));
        if (!ArmReturnBreakpoint(retSite, true)) {
            LogSpell("[spell.probe] warn: failed to arm return breakpoint for %p", reinterpret_cast<void*>(retSite));
        }
    }
    return true;
}

static bool HandleSingleStep(CONTEXT* ctx) {
    if (!g_tlsEntryStepPending)
        return false;
    g_tlsEntryStepPending = false;
    if (ctx)
        ctx->EFlags &= ~0x100u;
    if (!RearmEntryBreakpoint()) {
        g_probe.installed = false;
        g_probe.entry = 0;
        g_probe.entryArmed = false;
    }
    return true;
}

static LONG CALLBACK SpellProbeVectored(EXCEPTION_POINTERS* info) {
    if (!g_probe.installed || !info || !info->ContextRecord || !info->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD code = info->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_BREAKPOINT) {
        uintptr_t site = BreakpointAddressFromContext(info->ContextRecord);
        uintptr_t eip = static_cast<uintptr_t>(info->ContextRecord->Eip);
        if (site == g_probe.entry || eip == g_probe.entry) {
            if (HandleEntryBreakpoint(info->ContextRecord))
                return EXCEPTION_CONTINUE_EXECUTION;
        } else if (HandleReturnBreakpoint(info->ContextRecord)) {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    } else if (code == EXCEPTION_SINGLE_STEP) {
        if (HandleSingleStep(info->ContextRecord))
            return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static void RemoveLocked(bool quiet) {
    if (!g_probe.installed)
        return;
    RestoreEntryBreakpoint();
    if (g_probe.vehHandle) {
        RemoveVectoredExceptionHandler(g_probe.vehHandle);
        g_probe.vehHandle = nullptr;
    }
    g_probe.entry = 0;
    g_probe.installed = false;
    g_probe.entryArmed = false;
    g_probe.hitCount = 0;
    g_probe.lastLogTick = 0;
    if (!quiet)
        LogSpell("[spell.probe] RET-probe disarmed");
}

static void TrimWhitespace(char* text) {
    if (!text)
        return;
    size_t len = strlen(text);
    while (len > 0 && std::isspace(static_cast<unsigned char>(text[len - 1]))) {
        text[len - 1] = '\0';
        --len;
    }
    char* start = text;
    while (*start && std::isspace(static_cast<unsigned char>(*start)))
        ++start;
    if (start != text) {
        size_t remaining = strlen(start);
        memmove(text, start, remaining + 1);
    }
}

static bool ParseUnsigned(const char* text, uintptr_t& out) {
    if (!text || !text[0])
        return false;
    char* end = nullptr;
    unsigned long long value = std::strtoull(text, &end, 0);
    if (text == end)
        return false;
    while (end && *end) {
        if (!std::isspace(static_cast<unsigned char>(*end)))
            return false;
        ++end;
    }
    out = static_cast<uintptr_t>(value);
    return true;
}

} // namespace

uintptr_t ResolveModulePlusOffset(const char* spec) {
    if (!spec)
        return 0;

    char buffer[260];
    buffer[0] = '\0';
    strncpy_s(buffer, spec, _TRUNCATE);
    TrimWhitespace(buffer);
    if (buffer[0] == '\0')
        return 0;

    char original[260];
    strncpy_s(original, buffer, _TRUNCATE);

    char* plus = std::strchr(buffer, '+');
    if (!plus)
    {
        uintptr_t absolute = 0;
        if (!ParseUnsigned(buffer, absolute))
            return 0;
        return absolute;
    }

    *plus = '\0';
    char* moduleName = buffer;
    char* offsetText = plus + 1;
    TrimWhitespace(moduleName);
    TrimWhitespace(offsetText);
    if (moduleName[0] == '\0' || offsetText[0] == '\0')
        return 0;

    uintptr_t offset = 0;
    if (!ParseUnsigned(offsetText, offset))
        return 0;
    HMODULE module = GetModuleHandleA(moduleName);
    if (!module)
    {
        LogSpell("[spell.probe] module '%s' not loaded for spec '%s'",
                 moduleName,
                 original);
        return 0;
    }
    return reinterpret_cast<uintptr_t>(module) + offset;
}

void SpellProbe_Install(uintptr_t entry, int nArgs, int maxHits, int rateMs) {
    EnsureLock();
    if (!g_lockReady)
        return;

    EnterCriticalSection(&g_lock);
    RemoveLocked(true);
    g_returnDepth = 0;
    g_tlsEntryStepPending = false;

    if (!entry) {
        LeaveCriticalSection(&g_lock);
        LogSpell("[spell.probe] install skipped: entry address missing");
        return;
    }

    g_probe.entry = entry;
    g_probe.argCount = (nArgs < 0) ? 0 : (nArgs > 4 ? 4 : nArgs);
    g_probe.maxHits = (maxHits <= 0) ? 0 : maxHits;
    g_probe.rateMs = (rateMs <= 0) ? 0 : rateMs;
    g_probe.hitCount = 0;
    g_probe.lastLogTick = 0;

    g_probe.vehHandle = AddVectoredExceptionHandler(1, SpellProbeVectored);
    if (!g_probe.vehHandle) {
        LeaveCriticalSection(&g_lock);
        LogSpell("[spell.probe] failed to register vectored handler");
        g_probe.entry = 0;
        return;
    }

    if (!ArmEntryBreakpoint()) {
        RemoveVectoredExceptionHandler(g_probe.vehHandle);
        g_probe.vehHandle = nullptr;
        g_probe.entry = 0;
        LeaveCriticalSection(&g_lock);
        LogSpell("[spell.probe] failed to arm entry breakpoint (VirtualProtect?)");
        return;
    }

    g_probe.installed = true;
    LeaveCriticalSection(&g_lock);

    LogSpell("[spell.probe] RET-probe armed entry=%p args=%d maxHits=%d rateMs=%d",
             reinterpret_cast<void*>(entry),
             g_probe.argCount,
             g_probe.maxHits,
             g_probe.rateMs);
}

void SpellProbe_Remove() {
    EnsureLock();
    if (!g_lockReady)
        return;
    EnterCriticalSection(&g_lock);
    bool wasInstalled = g_probe.installed;
    RemoveLocked(true);
    g_returnDepth = 0;
    g_tlsEntryStepPending = false;
    LeaveCriticalSection(&g_lock);
    if (wasInstalled)
        LogSpell("[spell.probe] RET-probe removed");
}
