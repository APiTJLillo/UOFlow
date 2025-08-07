#pragma once
#include <windows.h>
#include <stddef.h>

namespace Core {
namespace Utils {
    bool IsOnCurrentStack(void* p);
    void DumpMemory(const char* desc, void* addr, size_t len);
} // namespace Utils
} // namespace Core

using Core::Utils::IsOnCurrentStack;
using Core::Utils::DumpMemory;
