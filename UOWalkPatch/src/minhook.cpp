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

MH_STATUS MH_Initialize(void) { return MH_OK; }
MH_STATUS MH_Uninitialize(void) { return MH_OK; }

static HookItem* findHook(LPVOID target) {
    for (auto& h : g_hooks) {
        if (h.target == target) return &h;
    }
    return nullptr;
}

MH_STATUS MH_CreateHook(LPVOID target, LPVOID detour, LPVOID* original) {
    if (findHook(target)) return MH_ERROR_ALREADY_CREATED;

    HookItem h{};
    h.target = target;
    h.detour = detour;
    h.enabled = false;

    h.trampoline = VirtualAlloc(nullptr, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!h.trampoline) return MH_ERROR_NOT_CREATED;

    memcpy(h.original, target, 5);
    memcpy(h.trampoline, h.original, 5);

    BYTE jmp[5] = {0xE9};
    *(DWORD*)(jmp + 1) = (DWORD)((BYTE*)target + 5 - ((BYTE*)h.trampoline + 5));
    memcpy((BYTE*)h.trampoline + 5, jmp, 5);

    if (original) *original = h.trampoline;
    g_hooks.push_back(h);
    return MH_OK;
}

MH_STATUS MH_EnableHook(LPVOID target) {
    HookItem* h = findHook(target);
    if (!h) return MH_ERROR_NOT_CREATED;
    if (h->enabled) return MH_OK;

    DWORD old;
    VirtualProtect(h->target, 5, PAGE_EXECUTE_READWRITE, &old);
    BYTE jmp[5] = {0xE9};
    *(DWORD*)(jmp + 1) = (DWORD)((BYTE*)h->detour - ((BYTE*)h->target + 5));
    memcpy(h->target, jmp, 5);
    VirtualProtect(h->target, 5, old, &old);

    h->enabled = true;
    return MH_OK;
}

MH_STATUS MH_DisableHook(LPVOID target) {
    HookItem* h = findHook(target);
    if (!h) return MH_ERROR_NOT_CREATED;
    if (!h->enabled) return MH_OK;

    DWORD old;
    VirtualProtect(h->target, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(h->target, h->original, 5);
    VirtualProtect(h->target, 5, old, &old);

    h->enabled = false;
    return MH_OK;
}

MH_STATUS MH_RemoveHook(LPVOID target) {
    for (auto it = g_hooks.begin(); it != g_hooks.end(); ++it) {
        if (it->target == target) {
            if (it->enabled) MH_DisableHook(target);
            VirtualFree(it->trampoline, 0, MEM_RELEASE);
            g_hooks.erase(it);
            return MH_OK;
        }
    }
    return MH_ERROR_NOT_CREATED;
}
