#include "Net/SendDiscover.h"

#include <atomic>
#include <cstdint>

#include "Core/Logging.hpp"
#include "Net/SendBuilder.hpp"

namespace {

std::atomic<void*> g_SendPacket{nullptr};

bool IsInModuleRange(const void* p, HMODULE modBase) {
    if (!p || !modBase)
        return false;
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(modBase);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const std::uint8_t*>(modBase) + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
        return false;
    const auto size = static_cast<std::uintptr_t>(nt->OptionalHeader.SizeOfImage);
    const auto addr = reinterpret_cast<std::uintptr_t>(p);
    const auto base = reinterpret_cast<std::uintptr_t>(modBase);
    return addr >= base && addr < (base + size);
}

bool IsReadableByte(const void* p) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(p, &mbi, sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
        return false;
    constexpr DWORD kReadableMask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (mbi.Protect & kReadableMask) != 0;
}

void* FindFunctionStartBackward(void* ret, std::size_t scanBytes = 0x300) {
    if (!ret)
        return nullptr;

    HMODULE mod = GetModuleHandleW(L"UOSA.exe");
    if (!IsInModuleRange(ret, mod))
        return nullptr;

    auto* cursor = static_cast<std::uint8_t*>(ret);
    auto* lowerBound = reinterpret_cast<std::uint8_t*>(mod);

    std::size_t walked = 0;
    while (walked < scanBytes && cursor > lowerBound) {
        --cursor;
        ++walked;

        if (!IsReadableByte(cursor))
            return nullptr;

        __try {
            // Pattern: push ebp; mov ebp, esp
            if (cursor[0] == 0x55 && cursor[1] == 0x8B && cursor[2] == 0xEC)
                return cursor;
            // Pattern: mov edi, edi; push ebp; mov ebp, esp
            if (cursor[0] == 0x8B && cursor[1] == 0xFF && cursor[2] == 0x55 &&
                cursor[3] == 0x8B && cursor[4] == 0xEC)
                return cursor;
            // Pattern: push <imm8>; push ebp; mov ebp, esp (stdcall wrapper)
            if (cursor[0] == 0x6A && cursor[2] == 0x55 && cursor[3] == 0x8B && cursor[4] == 0xEC)
                return cursor + 2;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return nullptr;
        }
    }
    return nullptr;
}

void LogDiscovered(void* addr) {
    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[INFO][CORE] Found SendPacket at %p",
              addr);
}

} // namespace

namespace uow::net {

void* DiscoverSendPacketFromWsasendReturnAddress(void* returnAddress) {
    void* already = g_SendPacket.load(std::memory_order_acquire);
    if (already)
        return already;

    void* start = FindFunctionStartBackward(returnAddress);
    if (!start)
        return nullptr;

    HMODULE mod = GetModuleHandleW(L"UOSA.exe");
    if (!IsInModuleRange(start, mod))
        return nullptr;

    void* expected = nullptr;
    if (g_SendPacket.compare_exchange_strong(expected, start, std::memory_order_acq_rel)) {
        LogDiscovered(start);
    }
    return g_SendPacket.load(std::memory_order_acquire);
}

void* GetSendPacket() {
    return g_SendPacket.load(std::memory_order_acquire);
}

} // namespace uow::net

bool Uow_AttemptInstallSendPacketHook(void* sendPacketAddr) {
    if (!sendPacketAddr)
        return false;

    bool installed = Net::InstallSendPacketHook(sendPacketAddr);
    if (installed) {
        Log::Logf(Log::Level::Info, Log::Category::Core, "[INFO][CORE] SendPacket hook installed");
    } else {
        Log::Logf(Log::Level::Warn, Log::Category::Core, "[WARN][CORE] SendPacket hook install failed at %p", sendPacketAddr);
    }
    return installed;
}
