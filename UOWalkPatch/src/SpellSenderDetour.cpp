#include "SpellSenderDetour.h"

#include <windows.h>
#include <intrin.h>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>

#include "Core/Config.hpp"
#include "Core/Logging.hpp"

namespace {

struct SenderState {
    SpellSenderOptions opts{};
    uintptr_t entry = 0;
    bool armed = false;
    void** vtableSlot = nullptr;
    using SendPacketFn = int(__thiscall*)(void*, void*, void*);
    SendPacketFn original = nullptr;
};

SenderState g_state{};
std::mutex g_detourMutex;
std::atomic<int> g_hitCount{0};
std::atomic<uint32_t> g_lastTick{0};

constexpr size_t kReturnStackMax = 128;

struct SpellSenderTls {
    bool logOverflowWarned = false;
    bool logUnderflowWarned = false;
    bool pendingRetValid = false;
    bool pendingLeaveLog = false;
    uint32_t logDepth = 0;
    uint8_t logFlags[kReturnStackMax]{};
    uintptr_t pendingRetAddr = 0;
};

thread_local SpellSenderTls g_tls{};

int __stdcall SpellSender_SendPacketHookImpl(void* self, void* packetCtx, void* refCtx, void* returnAddr);
extern "C" int __fastcall SpellSender_SendPacketHook(void* self, void* unused, void* packetCtx, void* refCtx);
extern "C" void __cdecl SpellSender_OnEnter(uintptr_t entry, uint32_t ecx, uint32_t edx, uintptr_t argBase);
extern "C" void __cdecl SpellSender_OnLeave(uintptr_t entry, uint32_t eax);
void** LocateVtableSlot(uintptr_t entryAddr);

void SpellSender_LogPopReturn(uintptr_t retAddr) {
    if (!g_tls.pendingLeaveLog)
        return;
    g_tls.pendingLeaveLog = false;
    char buf[192];
    sprintf_s(buf,
              sizeof(buf),
              "[CastSender:TRACE] popRA=%p thread=%lu",
              reinterpret_cast<void*>(retAddr),
              GetCurrentThreadId());
    WriteRawLog(buf);
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

bool LooksLikeStdPrologue(uintptr_t addr) {
    uint8_t bytes[3]{};
    if (CopyBytes(addr, bytes, sizeof(bytes)) != sizeof(bytes))
        return false;
    return bytes[0] == 0x55 && bytes[1] == 0x8B && bytes[2] == 0xEC;
}

bool LooksLikeHotpatchPrologue(uintptr_t addr) {
    uint8_t bytes[5]{};
    if (CopyBytes(addr, bytes, sizeof(bytes)) != sizeof(bytes))
        return false;
    return bytes[0] == 0x8B && bytes[1] == 0xFF && LooksLikeStdPrologue(addr + 2);
}

bool LooksLikeFpoPrologue(uintptr_t addr) {
    uint8_t bytes[8]{};
    size_t copied = CopyBytes(addr, bytes, sizeof(bytes));
    if (copied < 4)
        return false;
    size_t idx = 0;
    bool sawPush = false;
    while (idx < copied) {
        uint8_t op = bytes[idx];
        if (op == 0x53 || op == 0x56 || op == 0x57 || op == 0x51 || op == 0x52) {
            sawPush = true;
            ++idx;
            continue;
        }
        break;
    }
    if (!sawPush)
        return false;
    if (idx + 2 <= copied && bytes[idx] == 0x83 && bytes[idx + 1] == 0xEC)
        return true;
    if (idx + 5 <= copied && bytes[idx] == 0x81 && bytes[idx + 1] == 0xEC)
        return true;
    return false;
}

bool LooksLikeMultiPushPrologue(uintptr_t addr) {
    uint8_t bytes[16]{};
    size_t copied = CopyBytes(addr, bytes, sizeof(bytes));
    if (copied == 0)
        return false;
    size_t idx = 0;
    size_t pushCount = 0;
    while (idx < copied) {
        uint8_t op = bytes[idx];
        if (op >= 0x50 && op <= 0x57) {
            ++pushCount;
            ++idx;
            continue;
        }
        break;
    }
    return pushCount >= 3;
}

uintptr_t NormalizeEntryAddress(uintptr_t addr, const char** matchedKind = nullptr) {
    if (matchedKind)
        *matchedKind = nullptr;
    if (!addr)
        return 0;
    constexpr size_t kMaxScan = 0x200;
    uintptr_t bestMatch = 0;
    const char* bestKindLocal = nullptr;
    bool foundMatch = false;
    auto recordMatch = [&](uintptr_t candidate, const char* kind) {
        bestMatch = candidate;
        bestKindLocal = kind;
        foundMatch = true;
    };
    for (size_t delta = 0; delta <= kMaxScan; ++delta) {
        if (addr < delta)
            break;
        uintptr_t candidate = addr - delta;
        if (LooksLikeHotpatchPrologue(candidate)) {
            recordMatch(candidate, "hotpatch");
            continue;
        }
        if (LooksLikeStdPrologue(candidate)) {
            recordMatch(candidate, "std");
            continue;
        }
        if (LooksLikeFpoPrologue(candidate)) {
            recordMatch(candidate, "fpo");
            continue;
        }
        if (LooksLikeMultiPushPrologue(candidate)) {
            recordMatch(candidate, "push");
            continue;
        }
        uint8_t opcode = 0;
        if (CopyBytes(candidate, &opcode, sizeof(opcode)) != sizeof(opcode))
            continue;
        if (opcode == 0xC3 || opcode == 0xC2)
            break;
    }
    if (foundMatch) {
        if (matchedKind)
            *matchedKind = bestKindLocal;
        return bestMatch;
    }
    if (matchedKind)
        *matchedKind = "none";
    return addr;
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

enum class LogFlagPopResult {
    kUnderflow,
    kSuppressed,
    kAllowed,
};

LogFlagPopResult PopLogFlag() {
    if (g_tls.logDepth == 0) {
        if (!g_tls.logUnderflowWarned) {
            g_tls.logUnderflowWarned = true;
            WriteRawLog("[CastSender] log stack underflow; check detour balance");
        }
        return LogFlagPopResult::kUnderflow;
    }
    uint32_t slot = --g_tls.logDepth;
    if (slot >= kReturnStackMax)
        return LogFlagPopResult::kUnderflow;
    return g_tls.logFlags[slot] != 0 ? LogFlagPopResult::kAllowed : LogFlagPopResult::kSuppressed;
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

bool ReadStructField(uintptr_t base, uint32_t offset, uint32_t& out) {
    return ReadDword(base + offset, out);
}

uint32_t EstimatePayloadLength(uintptr_t ctx) {
    if (!ctx)
        return 0;
    uint32_t v28 = 0, v18 = 0, v1c = 0, v20 = 0, v14 = 0, v0c = 0;
    if (!ReadStructField(ctx, 0x28, v28) || !ReadStructField(ctx, 0x18, v18) ||
        !ReadStructField(ctx, 0x1C, v1c) || !ReadStructField(ctx, 0x20, v20) ||
        !ReadStructField(ctx, 0x14, v14) || !ReadStructField(ctx, 0x0C, v0c))
        return 0;
    int part1 = static_cast<int>(v28) - static_cast<int>(v18);
    part1 = (part1 >> 2) - 1;
    if (part1 < 0)
        part1 = 0;
    int part2 = (static_cast<int>(v1c) - static_cast<int>(v20)) >> 3;
    int part3 = (static_cast<int>(v14) - static_cast<int>(v0c)) >> 3;
    int total = (part1 << 5) + part2 + part3;
    if (total < 0)
        total = 0;
    return static_cast<uint32_t>(total);
}

uintptr_t FindPayloadPointer(uintptr_t ctx) {
    if (!ctx || !IsReadablePointer(ctx))
        return 0;
    for (int i = 0; i < 6; ++i) {
        uint32_t word = 0;
        if (!ReadDword(ctx + static_cast<uintptr_t>(i) * 4u, word))
            continue;
        uintptr_t candidate = static_cast<uintptr_t>(word);
        if (IsReadablePointer(candidate))
            return candidate;
    }
    return 0;
}

void** LocateVtableSlot(uintptr_t entryAddr) {
    HMODULE module = GetModuleHandleW(nullptr);
    if (!module)
        return nullptr;
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(module) + dos->e_lfanew);
    auto section = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const DWORD readableFlags = IMAGE_SCN_MEM_READ;
        if ((section[i].Characteristics & readableFlags) == 0)
            continue;
        uint8_t* start = reinterpret_cast<uint8_t*>(module) + section[i].VirtualAddress;
        size_t size = section[i].Misc.VirtualSize;
        size_t count = size / sizeof(uintptr_t);
        auto data = reinterpret_cast<uintptr_t*>(start);
        for (size_t j = 0; j < count; ++j) {
            if (data[j] == entryAddr)
                return reinterpret_cast<void**>(&data[j]);
        }
    }
    return nullptr;
}

int __stdcall SpellSender_SendPacketHookImpl(void* self, void* packetCtx, void* refCtx, void* returnAddr) {
    if (!g_state.original)
        return 0;
    uint32_t length = EstimatePayloadLength(reinterpret_cast<uintptr_t>(packetCtx));
    uintptr_t fakeArgs[4]{
        reinterpret_cast<uintptr_t>(packetCtx),
        reinterpret_cast<uintptr_t>(refCtx),
        length,
        length
    };
    uintptr_t argBase = reinterpret_cast<uintptr_t>(fakeArgs) - sizeof(uintptr_t);
    g_tls.pendingRetAddr = reinterpret_cast<uintptr_t>(returnAddr);
    g_tls.pendingRetValid = true;
    uintptr_t payloadPtr = FindPayloadPointer(reinterpret_cast<uintptr_t>(packetCtx));

    SpellSender_OnEnter(g_state.entry,
                        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(self)),
                        static_cast<uint32_t>(payloadPtr),
                        argBase);

    int result = g_state.original(self, packetCtx, refCtx);

    SpellSender_OnLeave(g_state.entry, static_cast<uint32_t>(result));
    g_tls.pendingRetValid = false;
    return result;
}

extern "C" int __fastcall SpellSender_SendPacketHook(void* self, void*, void* packetCtx, void* refCtx) {
    void* returnAddr = _ReturnAddress();
    return SpellSender_SendPacketHookImpl(self, packetCtx, refCtx, returnAddr);
}

extern "C" void __cdecl SpellSender_OnEnter(uintptr_t entry, uint32_t ecx, uint32_t edx, uintptr_t argBase) {
    DWORD now = GetTickCount();
    bool allowed = ShouldEmit(now);
    PushLogFlag(allowed);
    if (!allowed)
        return;
    if (g_tls.pendingRetValid) {
        char trace[192];
        sprintf_s(trace,
                  sizeof(trace),
                  "[CastSender:TRACE] savedRA=%p stub=%p thread=%lu",
                  reinterpret_cast<void*>(g_tls.pendingRetAddr),
                  reinterpret_cast<void*>(&SpellSender_SendPacketHook),
                  GetCurrentThreadId());
        WriteRawLog(trace);
        g_tls.pendingRetValid = false;
    }

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
    auto logResult = PopLogFlag();
    if (logResult != LogFlagPopResult::kAllowed)
        return;
    g_tls.pendingLeaveLog = true;
    char buf[128];
    sprintf_s(buf,
              sizeof(buf),
              "[CastSender:LEAVE] addr=%p EAX=%08X",
              reinterpret_cast<void*>(entry),
              eax);
    WriteRawLog(buf);
    SpellSender_LogPopReturn(g_tls.pendingRetAddr);
}

void DisarmLocked() {
    if (!g_state.armed)
        return;
    if (g_state.vtableSlot && g_state.original) {
        DWORD oldProtect = 0;
        VirtualProtect(g_state.vtableSlot, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect);
        *g_state.vtableSlot = reinterpret_cast<void*>(g_state.original);
        VirtualProtect(g_state.vtableSlot, sizeof(void*), oldProtect, &oldProtect);
    }
    g_state.entry = 0;
    g_state.original = nullptr;
    g_state.vtableSlot = nullptr;
    g_state.armed = false;
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

void SpellSenderDetour_EnsureArmed(uintptr_t frameAddr) {
    if (!frameAddr)
        return;
    if (!DebugProfileEnabled())
        return;
    const char* prologueKind = nullptr;
    uintptr_t normalized = NormalizeEntryAddress(frameAddr, &prologueKind);
    if (!normalized)
        return;
    std::lock_guard<std::mutex> lock(g_detourMutex);
    if (!g_state.opts.enable)
        return;
    if (g_state.armed)
        return;

    long long delta = static_cast<long long>(static_cast<intptr_t>(frameAddr) -
                                             static_cast<intptr_t>(normalized));
    char resolveBuf[256];
    sprintf_s(resolveBuf,
              sizeof(resolveBuf),
              "[CastSender] frame resolved frame=%p entry=%p kind=%s delta=%lld",
              reinterpret_cast<void*>(frameAddr),
              reinterpret_cast<void*>(normalized),
              prologueKind ? prologueKind : "n/a",
              delta);
    WriteRawLog(resolveBuf);

    void** slot = LocateVtableSlot(normalized);
    if (!slot) {
        char buf[160];
        sprintf_s(buf,
                  sizeof(buf),
                  "[CastSender] unable to locate vtable slot (frame=%p entry=%p)",
                  reinterpret_cast<void*>(frameAddr),
                  reinterpret_cast<void*>(normalized));
        WriteRawLog(buf);
        return;
    }
    DWORD oldProtect = 0;
    if (!VirtualProtect(slot, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        char protBuf[192];
        sprintf_s(protBuf,
                  sizeof(protBuf),
                  "[CastSender] failed to change protection on vtable slot (frame=%p entry=%p)",
                  reinterpret_cast<void*>(frameAddr),
                  reinterpret_cast<void*>(normalized));
        WriteRawLog(protBuf);
        return;
    }
    auto original = reinterpret_cast<SenderState::SendPacketFn>(*slot);
    *slot = reinterpret_cast<void*>(&SpellSender_SendPacketHook);
    VirtualProtect(slot, sizeof(void*), oldProtect, &oldProtect);
    g_state.entry = normalized;
    g_state.armed = true;
    g_state.original = original;
    g_state.vtableSlot = slot;
    g_hitCount.store(0, std::memory_order_release);
    g_lastTick.store(0, std::memory_order_release);
    g_tls = SpellSenderTls{};

    char buf[160];
    sprintf_s(buf,
              sizeof(buf),
              "[CastSender] detour armed at %p",
              reinterpret_cast<void*>(normalized));
    WriteRawLog(buf);
}
