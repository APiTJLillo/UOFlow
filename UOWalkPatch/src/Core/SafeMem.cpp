#include "Core/SafeMem.h"

#include <windows.h>
#include <psapi.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

namespace {

std::mutex g_codeRangesMutex;
std::vector<SafeMem::CodeRange> g_codeRanges;
DWORD g_lastRefreshTick = 0;
bool g_rangesInitialized = false;

constexpr DWORD kRefreshIntervalMs = 3000;

bool IsReadableProtection(DWORD protect)
{
    protect &= 0xFF;
    switch (protect)
    {
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

bool IsExecutableProtection(DWORD protect)
{
    protect &= 0xFF;
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

void CollectModuleRanges(std::vector<SafeMem::CodeRange>& outRanges)
{
    HANDLE process = GetCurrentProcess();
    DWORD neededBytes = 0;
    std::vector<HMODULE> modules(64);

    for (;;)
    {
        DWORD capacityBytes = static_cast<DWORD>(modules.size() * sizeof(HMODULE));
        if (!EnumProcessModules(process, modules.data(), capacityBytes, &neededBytes))
            return;
        if (neededBytes <= capacityBytes)
        {
            modules.resize(neededBytes / sizeof(HMODULE));
            break;
        }
        modules.resize((neededBytes / sizeof(HMODULE)) + 8);
    }

    for (HMODULE module : modules)
    {
        if (!module)
            continue;

        auto* base = reinterpret_cast<const std::uint8_t*>(module);
        const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
            continue;

        const IMAGE_NT_HEADERS* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
            continue;

        const IMAGE_FILE_HEADER& fileHeader = nt->FileHeader;
        const IMAGE_OPTIONAL_HEADER& opt = nt->OptionalHeader;
        const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

        bool foundExecutableSection = false;
        for (unsigned i = 0; i < fileHeader.NumberOfSections; ++i)
        {
            const IMAGE_SECTION_HEADER& section = sections[i];
            if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            std::uintptr_t start = reinterpret_cast<std::uintptr_t>(base) + section.VirtualAddress;
            std::size_t size = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
            if (size == 0)
                continue;

            std::uintptr_t end = start + size;
            if (end <= start)
                continue;

            outRanges.push_back({ start, end });
            foundExecutableSection = true;
        }

        if (!foundExecutableSection && opt.SizeOfCode != 0)
        {
            std::uintptr_t start = reinterpret_cast<std::uintptr_t>(base) + opt.BaseOfCode;
            std::uintptr_t end = start + opt.SizeOfCode;
            if (end > start)
                outRanges.push_back({ start, end });
        }
    }

    std::sort(outRanges.begin(), outRanges.end(), [](const SafeMem::CodeRange& a, const SafeMem::CodeRange& b) {
        return a.start < b.start;
    });

    std::vector<SafeMem::CodeRange> merged;
    merged.reserve(outRanges.size());

    for (const SafeMem::CodeRange& range : outRanges)
    {
        if (range.start >= range.end)
            continue;

        if (merged.empty() || range.start > merged.back().end)
        {
            merged.push_back(range);
        }
        else if (range.end > merged.back().end)
        {
            merged.back().end = range.end;
        }
    }

    outRanges.swap(merged);
}

bool IsAddressInRangesUnlocked(std::uintptr_t value)
{
    for (const SafeMem::CodeRange& range : g_codeRanges)
    {
        if (value < range.start)
            return false;
        if (value < range.end)
            return true;
    }
    return false;
}

} // namespace

namespace SafeMem {

void RefreshModuleCodeRanges(bool force)
{
    DWORD now = GetTickCount();

    std::lock_guard<std::mutex> lock(g_codeRangesMutex);
    if (!force && g_rangesInitialized)
    {
        DWORD elapsed = now - g_lastRefreshTick;
        if (elapsed < kRefreshIntervalMs)
            return;
    }

    std::vector<CodeRange> newRanges;
    CollectModuleRanges(newRanges);
    g_codeRanges.swap(newRanges);
    g_lastRefreshTick = now;
    g_rangesInitialized = true;
}

bool IsReadable(const void* address, std::size_t size)
{
    if (size == 0 || !address)
        return false;

    const std::uint8_t* current = static_cast<const std::uint8_t*>(address);
    const std::uint8_t* end = current + size;

    while (current < end)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(current, &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD))
            return false;
        if (!IsReadableProtection(mbi.Protect))
            return false;

        std::uintptr_t regionStart = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        std::uintptr_t regionEnd = regionStart + mbi.RegionSize;
        std::uintptr_t currentAddr = reinterpret_cast<std::uintptr_t>(current);

        if (regionEnd <= currentAddr)
            return false;

        std::uintptr_t chunkEnd = regionEnd;
        std::uintptr_t requestedEnd = reinterpret_cast<std::uintptr_t>(end);
        if (chunkEnd > requestedEnd)
            chunkEnd = requestedEnd;

        if (chunkEnd <= currentAddr)
            return false;

        std::size_t advance = static_cast<std::size_t>(chunkEnd - currentAddr);
        current += advance;
    }

    return true;
}

bool SafeReadBytes(const void* address, void* outBuffer, std::size_t size)
{
    if (!outBuffer || size == 0)
        return false;
    if (!IsReadable(address, size))
        return false;

    __try
    {
        std::memcpy(outBuffer, address, size);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

bool IsProbablyCodePtr(const void* address)
{
    if (!address)
        return false;

    RefreshModuleCodeRanges(false);

    std::uintptr_t value = reinterpret_cast<std::uintptr_t>(address);
    bool inRange = false;

    {
        std::lock_guard<std::mutex> lock(g_codeRangesMutex);
        inRange = IsAddressInRangesUnlocked(value);
    }

    if (!inRange)
    {
        RefreshModuleCodeRanges(true);
        std::lock_guard<std::mutex> lock(g_codeRangesMutex);
        inRange = IsAddressInRangesUnlocked(value);
        if (!inRange)
            return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(address, &mbi, sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD))
        return false;

    return IsExecutableProtection(mbi.Protect);
}

} // namespace SafeMem
