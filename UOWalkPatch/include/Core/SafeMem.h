#pragma once

#include <cstddef>
#include <cstdint>

namespace SafeMem {

struct CodeRange {
    std::uintptr_t start;
    std::uintptr_t end;
};

void RefreshModuleCodeRanges(bool force = false);
bool IsReadable(const void* address, std::size_t size);
bool IsProbablyCodePtr(const void* address);
bool SafeReadBytes(const void* address, void* outBuffer, std::size_t size);

template <typename T>
bool SafeRead(const void* address, T& outValue)
{
    return SafeReadBytes(address, &outValue, sizeof(T));
}

} // namespace SafeMem

