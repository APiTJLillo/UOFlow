#include "SpellSenderDetour.h"

#include <windows.h>
#include <minhook.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>

#include "Core/Config.hpp"
#include "Core/Logging.hpp"

namespace {

struct SenderState {
    SpellSenderOptions opts{};
    uintptr_t entry = 0;
    void* trampoline = nullptr;
    bool armed = false;
};

SenderState g_state{};
std::mutex g_detourMutex;
std::atomic<int> g_hitCount{0};
std::atomic<uint32_t> g_lastTick{0};

constexpr size_t kReturnStackMax = 128;

struct SpellSenderTls {
    bool returnOverflowWarned = false;
    bool returnUnderflowWarned = false;
    bool logOverflowWarned = false;
    bool logUnderflowWarned = false;
    uint32_t returnDepth = 0;
    uintptr_t returnAddrs[kReturnStackMax]{};
    uint32_t logDepth = 0;
    uint8_t logFlags[kReturnStackMax]{};
};

thread_local SpellSenderTls g_tls{};

extern "C" void* g_SpellSender_Trampoline = nullptr;
extern "C" uintptr_t g_SpellSender_Target = 0;

extern "C" uint32_t __stdcall SpellSender_PushReturn(uintptr_t retAddr) {
    if (!retAddr)
        return 0;
    uint32_t slot = g_tls.returnDepth;
    if (slot < kReturnStackMax) {
        g_tls.returnAddrs[slot] = retAddr;
        g_tls.returnDepth = slot + 1;
        return 1;
    }
    if (!g_tls.returnOverflowWarned) {
        g_tls.returnOverflowWarned = true;
        WriteRawLog("[CastSender] return stack overflow; detour may misbehave");
    }
    return 0;
}

extern "C" uintptr_t __stdcall SpellSender_PopReturn() {
    if (g_tls.returnDepth == 0) {
        if (!g_tls.returnUnderflowWarned) {
            g_tls.returnUnderflowWarned = true;
            WriteRawLog("[CastSender] return stack underflow");
        }
        return 0;
    }
    uint32_t slot = --g_tls.returnDepth;
    uintptr_t addr = g_tls.returnAddrs[slot];
    g_tls.returnAddrs[slot] = 0;
    return addr;
}

bool DebugProfileEnabled() {
    if (auto cfg = Core::Config::TryGetBool("UOW_DEBUG_ENABLE"))
        return *cfg;
    if (auto env = Core::Config::TryGetEnvBool("UOW_DEBUG_ENABLE"))
        return *env;
    return false;
}

bool ReadDword(uintptr_t addr, uint32_t& out) {
    __try {
        out = *reinterpret_cast<uint32_t*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

size_t CopyBytes(uintptr_t addr, uint8_t* dst, size_t len) {
    __try {
        memcpy(dst, reinterpret_cast<const void*>(addr), len);
        return len;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

void LogDump(const uint8_t* data, size_t len) {
    if (!data || len == 0)
        return;
    char line[256];
    size_t offset = sprintf_s(line, sizeof(line), "[CastSender:DUMP]");
    for (size_t i = 0; i < len && offset + 3 < sizeof(line); ++i)
        offset += sprintf_s(line + offset, sizeof(line) - offset, " %02X", data[i]);
    WriteRawLog(line);
}

bool ShouldEmit(DWORD now) {
    if (!g_state.opts.enable)
        return false;
    if (!DebugProfileEnabled())
        return false;
    if (g_state.opts.maxHits > 0) {
        int hits = g_hitCount.load(std::memory_order_relaxed);
        if (hits >= g_state.opts.maxHits)
            return false;
    }
    if (g_state.opts.debounceMs > 0) {
        uint32_t last = g_lastTick.load(std::memory_order_acquire);
        if (last != 0 && (now - last) < static_cast<uint32_t>(g_state.opts.debounceMs))
            return false;
    }
    if (g_state.opts.maxHits > 0)
        g_hitCount.fetch_add(1, std::memory_order_acq_rel);
    g_lastTick.store(now, std::memory_order_release);
    return true;
}

void PushLogFlag(bool allowed) {
    uint32_t slot = g_tls.logDepth++;
    if (slot < kReturnStackMax) {
        g_tls.logFlags[slot] = allowed ? 1u : 0u;
        return;
    }
    if (!g_tls.logOverflowWarned) {
        g_tls.logOverflowWarned = true;
        WriteRawLog("[CastSender] log stack overflow; suppressing ENTER/LEAVE pairing");
    }
}

bool PopLogFlag() {
    if (g_tls.logDepth == 0) {
        if (!g_tls.logUnderflowWarned) {
            g_tls.logUnderflowWarned = true;
            WriteRawLog("[CastSender] log stack underflow; check detour balance");
        }
        return false;
    }
    uint32_t slot = --g_tls.logDepth;
    if (slot < kReturnStackMax)
        return g_tls.logFlags[slot] != 0;
    return false;
}

bool IsReadablePointer(uintptr_t ptr) {
    if (!ptr)
        return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<void*>(ptr), &mbi, sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
        return false;
    const DWORD kWritable =
        PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (mbi.Protect & kWritable) != 0;
}

extern "C" void __cdecl SpellSender_OnEnter(uintptr_t entry, uint32_t ecx, uint32_t edx, uintptr_t argBase) {
    DWORD now = GetTickCount();
    bool allowed = ShouldEmit(now);
    PushLogFlag(allowed);
    if (!allowed)
        return;

    constexpr int kLoggedArgs = 4;
    uint32_t args[kLoggedArgs]{};
    uintptr_t stackBase = argBase ? (argBase + 4u) : 0;
    for (int i = 0; i < kLoggedArgs; ++i) {
        uintptr_t addr = stackBase + static_cast<uintptr_t>(i) * 4u;
        if (!ReadDword(addr, args[i]))
            args[i] = 0;
    }
    const auto validLen = [](uint32_t value) {
        return value > 0 && value <= 0x10000;
    };
    const char* lenSrc = "a2";
    uint32_t len = args[2];
    if (!validLen(len)) {
        len = args[3];
        lenSrc = "a3";
    }
    if (!validLen(len))
        len = 0;
    size_t dumpLen = 0;
    uint8_t dumpBuf[64]{};
    uintptr_t ctxWords[4]{};
    bool haveCtxWords = false;
    bool logCtxDetails = g_state.opts.logCtx;
    if (logCtxDetails && args[0] &&
        CopyBytes(args[0], reinterpret_cast<uint8_t*>(ctxWords), sizeof(ctxWords)) == sizeof(ctxWords))
        haveCtxWords = true;

    char payloadSrc[32] = "n/a";
    uintptr_t payloadPtr = 0;
    uintptr_t ctxProbe = 0;
    if (edx && IsReadablePointer(edx)) {
        payloadPtr = edx;
        strcpy_s(payloadSrc, sizeof(payloadSrc), "edx");
    } else if (args[0] && IsReadablePointer(args[0])) {
        for (int i = 0; i < 6; ++i) {
            uint32_t word = 0;
            if (!ReadDword(args[0] + static_cast<uintptr_t>(i) * 4u, word))
                continue;
            uintptr_t candidate = word;
            if (!IsReadablePointer(candidate))
                continue;
            payloadPtr = candidate;
            ctxProbe = args[0] + static_cast<uintptr_t>(i) * 4u;
            sprintf_s(payloadSrc, sizeof(payloadSrc), "ctx+0x%X", i * 4);
            break;
        }
    }

    if (payloadPtr && g_state.opts.dumpBytes > 0) {
        size_t want = g_state.opts.dumpBytes;
        if (len > 0 && len < want)
            want = len;
        if (want > sizeof(dumpBuf))
            want = sizeof(dumpBuf);
        dumpLen = CopyBytes(payloadPtr, dumpBuf, want);
    }

    char line[256];
    sprintf_s(line,
              sizeof(line),
              "[CastSender:ENTER] addr=%p ecx=%08X edx=%p buf=%p(%s) len=%u(%s) a0=%08X a1=%08X a2=%08X a3=%08X",
              reinterpret_cast<void*>(entry),
              ecx,
              reinterpret_cast<void*>(edx),
              reinterpret_cast<void*>(payloadPtr),
              payloadSrc,
              len,
              lenSrc,
              args[0],
              args[1],
              args[2],
              args[3]);
    WriteRawLog(line);
    if (ctxProbe && logCtxDetails) {
        char ctxLine[160];
        sprintf_s(ctxLine,
                  sizeof(ctxLine),
                  "[CastSender] buf derived from ctx word @ %p",
                  reinterpret_cast<void*>(ctxProbe));
        WriteRawLog(ctxLine);
    }
    if (haveCtxWords && logCtxDetails) {
        char ctxDump[256];
        sprintf_s(ctxDump,
                  sizeof(ctxDump),
                  "[CastSender:CTX] base=%p w0=%08X w1=%08X w2=%08X w3=%08X",
                  reinterpret_cast<void*>(args[0]),
                  ctxWords[0],
                  ctxWords[1],
                  ctxWords[2],
                  ctxWords[3]);
        WriteRawLog(ctxDump);
    }
    if (dumpLen)
        LogDump(dumpBuf, dumpLen);
}

extern "C" void __cdecl SpellSender_OnLeave(uintptr_t entry, uint32_t eax) {
    if (!PopLogFlag())
        return;
    char buf[128];
    sprintf_s(buf,
              sizeof(buf),
              "[CastSender:LEAVE] addr=%p EAX=%08X",
              reinterpret_cast<void*>(entry),
              eax);
    WriteRawLog(buf);
}

extern "C" void SpellSender_Return();

extern "C" void SpellSender_Return();

extern "C" void __declspec(naked) SpellSender_Detour() {
    __asm {
        pushfd
        pushad
        mov eax, [esp + 36]                // original return address
        push eax
        call SpellSender_PushReturn
        mov esi, eax                       // success flag
        mov ebx, [esp + 24]                // original ECX
        mov ecx, [esp + 20]                // original EDX
        lea eax, [esp + 36]                // pointer to caller stack (return slot)
        push eax                           // arg4: argument base
        push ecx                           // arg3: original EDX
        push ebx                           // arg2: original ECX
        mov edx, g_SpellSender_Target
        push edx                           // arg1: entry address
        call SpellSender_OnEnter
        add esp, 16
        test esi, esi
        jz SpellSender_SkipPatch
        mov dword ptr [esp + 36], offset SpellSender_Return
SpellSender_SkipPatch:
        popad
        popfd
        test esi, esi
        jz SpellSender_FallbackCall
        jmp g_SpellSender_Trampoline

SpellSender_FallbackCall:
        call g_SpellSender_Trampoline
        ret
    }
}

extern "C" void __declspec(naked) SpellSender_Return() {
    __asm {
        push eax                           // save return value
        pushfd
        pushad
        mov edx, g_SpellSender_Target
        push dword ptr [esp + 36]          // arg2: saved return value
        push edx                           // arg1: entry address
        call SpellSender_OnLeave
        add esp, 8
        popad
        popfd
        pop eax                            // restore return value
        call SpellSender_PopReturn
        test eax, eax
        jz SpellSender_ReturnDirect
        jmp eax

SpellSender_ReturnDirect:
        ret
    }
}

void DisarmLocked() {
    if (!g_state.armed)
        return;
    MH_DisableHook(reinterpret_cast<void*>(g_state.entry));
    MH_RemoveHook(reinterpret_cast<void*>(g_state.entry));
    g_state.entry = 0;
    g_state.trampoline = nullptr;
    g_state.armed = false;
    g_SpellSender_Trampoline = nullptr;
    g_SpellSender_Target = 0;
    g_hitCount.store(0, std::memory_order_release);
    g_lastTick.store(0, std::memory_order_release);
    g_tls = SpellSenderTls{};
    WriteRawLog("[CastSender] detour disarmed");
}

} // namespace

void SpellSenderDetour_Configure(const SpellSenderOptions& opts) {
    std::lock_guard<std::mutex> lock(g_detourMutex);
    g_state.opts = opts;
    g_state.opts.dumpBytes = std::clamp(g_state.opts.dumpBytes, 0, 64);
    if (g_state.opts.maxHits < 0)
        g_state.opts.maxHits = 0;
    if (g_state.opts.debounceMs < 0)
        g_state.opts.debounceMs = 0;
    if (!g_state.opts.enable)
        DisarmLocked();
}

void SpellSenderDetour_Disarm() {
    std::lock_guard<std::mutex> lock(g_detourMutex);
    DisarmLocked();
}

void SpellSenderDetour_EnsureArmed(uintptr_t entryAddr) {
    if (!entryAddr)
        return;
    if (!DebugProfileEnabled())
        return;
    std::lock_guard<std::mutex> lock(g_detourMutex);
    if (!g_state.opts.enable)
        return;
    if (g_state.armed && g_state.entry == entryAddr)
        return;
    if (g_state.armed)
        DisarmLocked();

    void* trampoline = nullptr;
    if (MH_CreateHook(reinterpret_cast<void*>(entryAddr),
                      reinterpret_cast<LPVOID>(&SpellSender_Detour),
                      reinterpret_cast<LPVOID*>(&trampoline)) != MH_OK) {
        char buf[160];
        sprintf_s(buf,
                  sizeof(buf),
                  "[CastSender] failed to create detour at %p",
                  reinterpret_cast<void*>(entryAddr));
        WriteRawLog(buf);
        return;
    }
    if (MH_EnableHook(reinterpret_cast<void*>(entryAddr)) != MH_OK) {
        MH_RemoveHook(reinterpret_cast<void*>(entryAddr));
        WriteRawLog("[CastSender] failed to enable detour hook");
        return;
    }

    g_state.entry = entryAddr;
    g_state.armed = true;
    g_state.trampoline = trampoline;
    g_SpellSender_Trampoline = trampoline;
    g_SpellSender_Target = entryAddr;
    g_hitCount.store(0, std::memory_order_release);
    g_lastTick.store(0, std::memory_order_release);
    g_tls = SpellSenderTls{};

    char buf[160];
    sprintf_s(buf,
              sizeof(buf),
              "[CastSender] detour armed at %p",
              reinterpret_cast<void*>(entryAddr));
    WriteRawLog(buf);
}
