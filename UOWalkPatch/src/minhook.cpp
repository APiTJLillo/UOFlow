#include "minhook.h"
#include <vector>
#include <cstring>

struct HookItem {
    LPVOID target;
    LPVOID detour;
    LPVOID trampoline;
    BYTE original[5];
    bool enabled;
};

static std::vector<HookItem> g_hooks;
static bool g_initialized = false;

MH_STATUS MH_Initialize(void) {
    if (g_initialized) return MH_ERROR_ALREADY_CREATED;
    g_hooks.clear();
    g_initialized = true;
    return MH_OK;
}

MH_STATUS MH_Uninitialize(void) {
    if (!g_initialized) return MH_ERROR_NOT_CREATED;
    
    // Disable and remove all hooks
    MH_STATUS status = MH_DisableHook(MH_ALL_HOOKS);
    
    // Free all trampolines
    for (auto& hook : g_hooks) {
        if (hook.trampoline) {
            VirtualFree(hook.trampoline, 0, MEM_RELEASE);
            hook.trampoline = nullptr;
        }
    }
    
    g_hooks.clear();
    g_initialized = false;
    return status;
}

static HookItem* findHook(LPVOID target) {
    for (auto& h : g_hooks) {
        if (h.target == target) return &h;
    }
    return nullptr;
}

MH_STATUS MH_CreateHook(LPVOID target, LPVOID detour, LPVOID* original) {
    if (!g_initialized) return MH_ERROR_NOT_CREATED;
    if (!target || !detour) return MH_ERROR_NOT_CREATED;
    if (findHook(target)) return MH_ERROR_ALREADY_CREATED;

    HookItem h{};
    h.target = target;
    h.detour = detour;
    h.enabled = false;

    // Allocate executable memory for trampoline
    h.trampoline = VirtualAlloc(nullptr, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!h.trampoline) return MH_ERROR_NOT_CREATED;

    // Save original bytes and create trampoline
    DWORD oldProtect;
    if (!VirtualProtect(target, 5, PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFree(h.trampoline, 0, MEM_RELEASE);
        return MH_ERROR_NOT_CREATED;
    }

    memcpy(h.original, target, 5);
    memcpy(h.trampoline, h.original, 5);

    BYTE jmp[5] = {0xE9};
    *(DWORD*)(jmp + 1) = (DWORD)((BYTE*)target + 5 - ((BYTE*)h.trampoline + 5));
    memcpy((BYTE*)h.trampoline + 5, jmp, 5);

    VirtualProtect(target, 5, oldProtect, &oldProtect);

    if (original) *original = h.trampoline;
    g_hooks.push_back(h);
    return MH_OK;
}

MH_STATUS MH_EnableHook(LPVOID target) {
    if (!g_initialized) return MH_ERROR_NOT_CREATED;
    
    if (target == MH_ALL_HOOKS) {
        MH_STATUS status = MH_OK;
        for (auto& h : g_hooks) {
            if (!h.enabled) {
                MH_STATUS result = MH_EnableHook(h.target);
                if (result != MH_OK) status = result;
            }
        }
        return status;
    }

    HookItem* h = findHook(target);
    if (!h) return MH_ERROR_NOT_CREATED;
    if (h->enabled) return MH_OK;

    DWORD oldProtect;
    if (!VirtualProtect(h->target, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return MH_ERROR_NOT_CREATED;
    }

    BYTE jmp[5] = {0xE9};
    *(DWORD*)(jmp + 1) = (DWORD)((BYTE*)h->detour - ((BYTE*)h->target + 5));
    memcpy(h->target, jmp, 5);
    
    VirtualProtect(h->target, 5, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), h->target, 5);

    h->enabled = true;
    return MH_OK;
}

MH_STATUS MH_DisableHook(LPVOID target) {
    if (!g_initialized) return MH_ERROR_NOT_CREATED;

    if (target == MH_ALL_HOOKS) {
        MH_STATUS status = MH_OK;
        for (auto& h : g_hooks) {
            if (h.enabled) {
                MH_STATUS result = MH_DisableHook(h.target);
                if (result != MH_OK) status = result;
            }
        }
        return status;
    }

    HookItem* h = findHook(target);
    if (!h) return MH_ERROR_NOT_CREATED;
    if (!h->enabled) return MH_OK;

    DWORD oldProtect;
    if (!VirtualProtect(h->target, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return MH_ERROR_NOT_CREATED;
    }

    memcpy(h->target, h->original, 5);
    VirtualProtect(h->target, 5, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), h->target, 5);

    h->enabled = false;
    return MH_OK;
}

MH_STATUS MH_RemoveHook(LPVOID target) {
    if (!g_initialized) return MH_ERROR_NOT_CREATED;

    for (auto it = g_hooks.begin(); it != g_hooks.end(); ++it) {
        if (it->target == target) {
            if (it->enabled) {
                MH_STATUS status = MH_DisableHook(target);
                if (status != MH_OK) return status;
            }
            if (it->trampoline) {
                VirtualFree(it->trampoline, 0, MEM_RELEASE);
                it->trampoline = nullptr;
            }
            g_hooks.erase(it);
            return MH_OK;
        }
    }
    return MH_ERROR_NOT_CREATED;
}
