#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <vector>
#include <string>
#include <sstream>
#include "minhook.h"

static void* g_luaState = nullptr;

// Simple pattern parser "AA BB ?? CC"
struct Pattern {
    std::vector<unsigned char> bytes;
    std::string mask;
};

static Pattern parsePattern(const char* str) {
    Pattern p;
    std::istringstream iss(str);
    std::string s;
    while (iss >> s) {
        if (s == "??") {
            p.bytes.push_back(0);
            p.mask.push_back('?');
        } else {
            p.bytes.push_back((unsigned char)strtoul(s.c_str(), nullptr, 16));
            p.mask.push_back('x');
        }
    }
    return p;
}

static bool scanModule(const Pattern& pat, uintptr_t& out) {
    HMODULE hMod = GetModuleHandle(NULL);
    MODULEINFO info{};
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &info, sizeof(info)))
        return false;
    unsigned char* base = (unsigned char*)info.lpBaseOfDll;
    size_t size = info.SizeOfImage;
    for (size_t i = 0; i + pat.bytes.size() <= size; ++i) {
        bool match = true;
        for (size_t j = 0; j < pat.bytes.size(); ++j) {
            if (pat.mask[j] == 'x' && base[i+j] != pat.bytes[j]) { match = false; break; }
        }
        if (match) { out = (uintptr_t)(base + i); return true; }
    }
    return false;
}

static bool findString(const char* str, uintptr_t& out) {
    Pattern p; p.mask.assign(strlen(str)+1, 'x');
    p.bytes.assign((unsigned char*)str, (unsigned char*)str + strlen(str) + 1);
    return scanModule(p, out);
}

static bool findPushWithAddress(uintptr_t addr, uintptr_t& out) {
    Pattern p; p.bytes.resize(5); p.mask = "xxxxx";
    p.bytes[0] = 0x68;
    *(DWORD*)&p.bytes[1] = (DWORD)addr;
    return scanModule(p, out);
}

static bool findRegisterLuaFunction(uintptr_t& addr) {
    uintptr_t strAddr;
    if (!findString("GetBuildVersion", strAddr)) return false;
    uintptr_t pushAddr;
    if (!findPushWithAddress(strAddr, pushAddr)) return false;
    uintptr_t callAddr = pushAddr + 11;
    if (*(unsigned char*)callAddr != 0xE8) return false;
    int rel = *(int*)(callAddr + 1);
    addr = callAddr + 5 + rel;
    return true;
}

// placeholder for real walk function pointer
using WalkFunc = void (__stdcall*)(int,int);
static WalkFunc g_walk = nullptr;

extern "C" int __stdcall walk_bridge(void* L) {
    typedef int (__cdecl* lua_tointeger_t)(void*, int);
    static lua_tointeger_t lua_tointeger = nullptr;
    if (!lua_tointeger) {
        HMODULE lua = GetModuleHandleA("lua.dll");
        if (lua) lua_tointeger = (lua_tointeger_t)GetProcAddress(lua, "lua_tointeger");
    }
    if (!lua_tointeger || !g_walk) return 0;
    int dir = lua_tointeger(L, 1);
    int run = lua_tointeger(L, 2);
    g_walk(dir, run);
    return 0;
}

using RegFunc = int (__stdcall*)(void*, const char*, void*);
static RegFunc Real_RegFunc = nullptr;

static int __stdcall Hook_RegFunc(void* L, const char* name, void* func) {
    if (!g_luaState) {
        g_luaState = L;
        if (Real_RegFunc && g_walk) {
            Real_RegFunc(L, "walk_ex", (void*)walk_bridge);
        }
    }
    printf("[UOWalkPatch] RegisterLuaFunction: %s\n", name);
    return Real_RegFunc(L, name, func);
}

static DWORD WINAPI InitThread(LPVOID) {
    if (MH_Initialize() != MH_OK) return 0;
    uintptr_t regAddr;
    if (!findRegisterLuaFunction(regAddr)) return 0;
    uintptr_t walkAddr;
    Pattern walkPat = parsePattern("55 8B EC 83 E4 ?? 83 EC ?? F3 0F 10 45 08 53 56 8B F1 57");
    if (scanModule(walkPat, walkAddr)) g_walk = (WalkFunc)walkAddr;
    MH_CreateHook((LPVOID)regAddr, (LPVOID)Hook_RegFunc, (LPVOID*)&Real_RegFunc);
    MH_EnableHook((LPVOID)regAddr);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
