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
thread_local bool g_tlsLogActive = false;

extern "C" void* g_SpellSender_Trampoline = nullptr;
extern "C" uintptr_t g_SpellSender_Target = 0;

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

extern "C" void __cdecl SpellSender_OnEnter(uintptr_t entry, uint32_t ecx, uint32_t edx, uintptr_t esp) {
    DWORD now = GetTickCount();
    bool allowed = ShouldEmit(now);
    g_tlsLogActive = allowed;
    if (!allowed)
        return;

    uint32_t args[3]{};
    for (int i = 0; i < 3; ++i) {
        uintptr_t addr = esp + 4u + static_cast<uintptr_t>(i) * 4u;
        if (!ReadDword(addr, args[i]))
            args[i] = 0;
    }
    uint32_t len = args[2];
    size_t dumpLen = 0;
    uint8_t dumpBuf[64]{};
    if (edx && g_state.opts.dumpBytes > 0) {
        size_t want = g_state.opts.dumpBytes;
        if (len > 0 && len < want)
            want = len;
        if (want > sizeof(dumpBuf))
            want = sizeof(dumpBuf);
        dumpLen = CopyBytes(edx, dumpBuf, want);
    }

    char line[256];
    sprintf_s(line,
              sizeof(line),
              "[CastSender:ENTER] addr=%p ecx=%08X edx=%p len=%u a0=%08X a1=%08X a2=%08X",
              reinterpret_cast<void*>(entry),
              ecx,
              reinterpret_cast<void*>(edx),
              len,
              args[0],
              args[1],
              args[2]);
    WriteRawLog(line);
    if (dumpLen)
        LogDump(dumpBuf, dumpLen);
}

extern "C" void __cdecl SpellSender_OnLeave(uintptr_t entry, uint32_t eax) {
    if (!g_tlsLogActive)
        return;
    g_tlsLogActive = false;
    char buf[128];
    sprintf_s(buf,
              sizeof(buf),
              "[CastSender:LEAVE] addr=%p EAX=%08X",
              reinterpret_cast<void*>(entry),
              eax);
    WriteRawLog(buf);
}

extern "C" void __declspec(naked) SpellSender_Detour() {
    __asm {
        pushfd
        pushad
        mov ebx, [esp + 4]    // original ECX
        mov esi, [esp + 8]    // original EDX
        mov edi, [esp + 16]   // original ESP
        push edi
        push esi
        push ebx
        mov eax, g_SpellSender_Target
        push eax
        call SpellSender_OnEnter
        add esp, 16
        popad
        popfd
        push offset SpellSender_Post
        mov eax, g_SpellSender_Trampoline
        jmp eax
SpellSender_Post:
        push eax
        mov edx, g_SpellSender_Target
        push dword ptr [esp]
        push edx
        call SpellSender_OnLeave
        add esp, 8
        pop eax
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
    g_tlsLogActive = false;

    char buf[160];
    sprintf_s(buf,
              sizeof(buf),
              "[CastSender] detour armed at %p",
              reinterpret_cast<void*>(entryAddr));
    WriteRawLog(buf);
}
