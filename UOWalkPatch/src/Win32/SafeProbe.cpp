#include "Win32/SafeProbe.h"

#include <psapi.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace sp {
namespace {

bool is_read_protect(DWORD protect) {
    protect &= 0xFF;
    switch (protect) {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
    }
}

bool is_exec_protect(DWORD protect) {
    protect &= 0xFF;
    switch (protect) {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
    }
}

bool query_region(const void* address, MEMORY_BASIC_INFORMATION& mbi) {
    std::memset(&mbi, 0, sizeof(mbi));
    if (!address)
        return false;
    if (!VirtualQuery(address, &mbi, sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    if (mbi.Protect == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD))
        return false;
    return true;
}

bool pointer_in_section(const void* address, HMODULE module, const IMAGE_SECTION_HEADER& section) {
    if (!module)
        return false;
    const auto base = reinterpret_cast<const std::uint8_t*>(module);
    const auto addr = reinterpret_cast<const std::uint8_t*>(address);
    if (section.VirtualAddress == 0)
        return false;

    std::uint32_t virtualSize = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
    if (virtualSize == 0)
        return false;

    const std::uint8_t* sectionBegin = base + section.VirtualAddress;
    const std::uint8_t* sectionEnd = sectionBegin + virtualSize;
    return addr >= sectionBegin && addr < sectionEnd;
}

std::optional<bool> module_contains_text(const void* address) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!query_region(address, mbi))
        return std::nullopt;

    auto module = static_cast<HMODULE>(mbi.AllocationBase);
    if (!module)
        return std::nullopt;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
        return std::nullopt;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const std::uint8_t*>(module) + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
        return std::nullopt;

    const auto* sections = IMAGE_FIRST_SECTION(nt);
    const auto& fileHeader = nt->FileHeader;
    bool sawExecutable = false;
    for (unsigned i = 0; i < fileHeader.NumberOfSections; ++i) {
        const IMAGE_SECTION_HEADER& section = sections[i];
        if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;
        sawExecutable = true;

        // Prefer explicit .text match but accept any executable section.
        if (pointer_in_section(address, module, section))
            return true;
    }

    if (!sawExecutable)
        return std::nullopt;

    return false;
}

} // namespace

bool is_readable(const void* address, std::size_t bytes) {
    if (!address || bytes == 0)
        return false;

    const auto* current = static_cast<const std::uint8_t*>(address);
    const auto* end = current + bytes;

    while (current < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!query_region(current, mbi))
            return false;
        if (!is_read_protect(mbi.Protect))
            return false;

        const auto regionStart = reinterpret_cast<const std::uint8_t*>(mbi.BaseAddress);
        const auto regionEnd = regionStart + mbi.RegionSize;
        if (regionEnd <= current)
            return false;

        const auto advance = std::min<std::size_t>(static_cast<std::size_t>(regionEnd - current),
                                                   static_cast<std::size_t>(end - current));
        current += advance;
    }

    return true;
}

bool is_executable_code_ptr(const void* address) {
    if (!address)
        return false;

    MEMORY_BASIC_INFORMATION mbi{};
    if (!query_region(address, mbi))
        return false;
    if (!is_exec_protect(mbi.Protect))
        return false;

    auto moduleOk = module_contains_text(address);
    if (moduleOk.has_value())
        return moduleOk.value();

    // Allow executable heap/JIT regions even if not part of a PE image.
    return true;
}

bool is_plausible_vtbl_entry(const void* address) {
    if (!address)
        return false;
    auto value = reinterpret_cast<std::uintptr_t>(address);
    if ((value & (sizeof(void*) - 1u)) != 0)
        return false;
    return is_executable_code_ptr(address);
}

} // namespace sp
