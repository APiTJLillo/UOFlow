#pragma once
#include <minhook.h>

namespace Core {
namespace MinHookHelpers {
    bool Init();
    void Shutdown();

    template<typename T>
    bool Hook(void* target, void* detour, T** original) {
        if (MH_CreateHook(target, detour, reinterpret_cast<void**>(original)) != MH_OK)
            return false;
        if (MH_EnableHook(target) != MH_OK)
            return false;
        return true;
    }

    inline bool Unhook(void* target) {
        if (MH_DisableHook(target) != MH_OK)
            return false;
        if (MH_RemoveHook(target) != MH_OK)
            return false;
        return true;
    }
} // namespace MinHookHelpers
} // namespace Core

using Core::MinHookHelpers::Hook;
using Core::MinHookHelpers::Unhook;
