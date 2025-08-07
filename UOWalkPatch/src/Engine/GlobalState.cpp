#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <cstdint>
#include <cstdio>
#include "Core/Logging.hpp"
#include "Core/PatternScan.hpp"
#include "Core/Utils.hpp"
#include "Engine/GlobalState.hpp"

namespace Engine {

static GlobalStateInfo* g_globalStateInfo = nullptr;
static void* g_luaState = nullptr;
static HANDLE g_scanThread = nullptr;
static volatile LONG g_stopScan = 0;
static DWORD* g_globalStateSlot = nullptr;
static LONG g_once = 0;
static PVOID g_vehHandle = nullptr;
static bool g_luaStateCaptured = false;

// Forward declarations
static void* FindGlobalStateInfo();
static void* FindOwnerOfLuaState(void* lua);
static GlobalStateInfo* ValidateGlobalState(GlobalStateInfo* candidate);
static void InstallWriteWatch();
static DWORD WINAPI WaitForLua(LPVOID);
static LONG CALLBACK VehHandler(EXCEPTION_POINTERS* x);

void* FindRegisterLuaFunction() {
    HMODULE hExe = GetModuleHandleA(nullptr);
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), hExe, &mi, sizeof(mi)))
        return nullptr;

    BYTE* base = (BYTE*)mi.lpBaseOfDll;
    SIZE_T size = mi.SizeOfImage;

    static const char anchor[] = "GetBuildVersion";
    BYTE* str = FindBytes(base, size, (const BYTE*)anchor, sizeof(anchor));
    if (!str) return nullptr;

    char buffer[128];
    sprintf_s(buffer, sizeof(buffer), "Found GetBuildVersion string at %p", str);
    WriteRawLog(buffer);

    for (BYTE* p = base; p < base + size - 5; ++p) {
        bool hits =
            (p[0] == 0x68 && *(DWORD*)(p + 1) == (DWORD)(uintptr_t)str) ||
            (p[0] == 0x8D && (p[1] & 0xC7) == 0x05 &&
                *(DWORD*)(p + 2) == (DWORD)(uintptr_t)str);

        if (!hits) continue;

        sprintf_s(buffer, sizeof(buffer), "Found string reference at %p", p);
        WriteRawLog(buffer);

        for (BYTE* q = p; q < p + 32; ++q) {
            LPVOID target = nullptr;

            if (*q == 0xE8) {
                INT32 rel = *(INT32*)(q + 1);
                BYTE* callee = q + 5 + rel;
                sprintf_s(buffer, sizeof(buffer), "Found direct call instruction at %p targeting %p", q, callee);
                WriteRawLog(buffer);
                target = callee;

                for (BYTE* k = q - 64; k < q + 64; ++k) {
                    if (k[0] == 0xA3) {
                        g_globalStateSlot = (DWORD*)(*(DWORD*)(k + 1));
                        sprintf_s(buffer, sizeof(buffer), "Found global state write (A3) at %p targeting slot %p",
                            k, g_globalStateSlot);
                        WriteRawLog(buffer);
                        break;
                    }
                    if (k[0] == 0x89 && (k[1] & 0x07) == 0x05) {
                        g_globalStateSlot = (DWORD*)(*(DWORD*)(k + 2));
                        sprintf_s(buffer, sizeof(buffer), "Found global state write (89 %02X) at %p targeting slot %p",
                            k[1], k, g_globalStateSlot);
                        WriteRawLog(buffer);
                        break;
                    }
                }
            }
            else if (q[0] == 0xFF && q[1] == 0x15) {
                DWORD disp = *(DWORD*)(q + 2);
                BYTE** abs = (BYTE**)(q + 6 + disp);
                BYTE* callee = *abs;
                sprintf_s(buffer, sizeof(buffer), "Found indirect call instruction at %p targeting %p", q, callee);
                WriteRawLog(buffer);
                target = callee;

                for (BYTE* k = q - 64; k < q + 64; ++k) {
                    if (k[0] == 0xA3) {
                        g_globalStateSlot = (DWORD*)(*(DWORD*)(k + 1));
                        sprintf_s(buffer, sizeof(buffer), "Found global state write (A3) at %p targeting slot %p",
                            k, g_globalStateSlot);
                        WriteRawLog(buffer);
                        break;
                    }
                    if (k[0] == 0x89 && (k[1] & 0x07) == 0x05) {
                        g_globalStateSlot = (DWORD*)(*(DWORD*)(k + 2));
                        sprintf_s(buffer, sizeof(buffer), "Found global state write (89 %02X) at %p targeting slot %p",
                            k[1], k, g_globalStateSlot);
                        WriteRawLog(buffer);
                        break;
                    }
                }
            }

            if (target) return target;
        }
    }

    WriteRawLog("Could not find RegisterLuaFunction reference");
    return nullptr;
}

static void* FindOwnerOfLuaState(void* lua) {
    if (!lua) return nullptr;
    char buf[128];

    HMODULE hExe = GetModuleHandleA(nullptr);
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hExe;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)hExe + dos->e_lfanew);

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_READ) ||
            !(sec->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA))
            continue;

        BYTE* beg = (BYTE*)hExe + sec->VirtualAddress;
        BYTE* end = beg + sec->Misc.VirtualSize;

        for (BYTE* p = beg; p + sizeof(void*) <= end; p += sizeof(void*)) {
            if (*(void**)p != lua) continue;

            {
                GlobalStateInfo* g = (GlobalStateInfo*)p;
                if (IsOnCurrentStack(g)) {
                    WriteRawLog("Rejecting candidate: on current stack");
                }
                else {
                    __try {
                        if (g->luaState == lua && g->databaseManager) {
                            sprintf_s(buf, sizeof(buf),
                                "Validated GlobalStateInfo (no padding) @ %p", g);
                            WriteRawLog(buf);
                            return g;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
            }

            DWORD* d = (DWORD*)p - 4;
            __try {
                if (!d[0] && !d[1] && !d[2] && !d[3]) {
                    GlobalStateInfo* g = *(GlobalStateInfo**)(d + 4);
                    if (g) {
                        if (IsOnCurrentStack(g)) {
                            WriteRawLog("Rejecting candidate: on current stack");
                        }
                        else if (g->luaState == lua && g->databaseManager) {
                            sprintf_s(buf, sizeof(buf),
                                "Validated GlobalStateInfo (zero-block) @ %p", g);
                            WriteRawLog(buf);
                            return g;
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    BYTE* addr = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (addr < (BYTE*)si.lpMaximumApplicationAddress) {
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) break;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ)) &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
        {
            BYTE* b = (BYTE*)mbi.BaseAddress;
            BYTE* e = b + mbi.RegionSize;

            for (BYTE* p = b; p + sizeof(void*) <= e; p += sizeof(void*)) {
                if (*(void**)p != lua) continue;

                GlobalStateInfo* g = (GlobalStateInfo*)p;
                if (IsOnCurrentStack(g)) {
                    WriteRawLog("Rejecting candidate: on current stack");
                }
                else {
                    __try {
                        if (g->luaState == lua && g->databaseManager) {
                            sprintf_s(buf, sizeof(buf),
                                "Validated GlobalStateInfo (heap) @ %p", g);
                            WriteRawLog(buf);
                            return g;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
            }
        }
        addr += mbi.RegionSize;
    }

    WriteRawLog("Owner of Lua state not found");
    return nullptr;
}

static void* FindGlobalStateInfo() {
    HMODULE hExe = GetModuleHandleA(nullptr);
    if (!hExe) return nullptr;

    BYTE* base = (BYTE*)hExe;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

    static const struct {
        const wchar_t* w;
        const char* a;
        int zeros;
    } needles[] = {
        {L"Text is cut off in Label", nullptr, 4},
        {L"UOSetWaypointMapFacet", nullptr, 4},
        {L"ProfessionDescriptionWindowText", nullptr, 4},
        {nullptr, "UOSetWaypointMapFacet", 4},
    };

    static bool bannerShown = false;
    char buffer[256];
    bool foundAny = false;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections && !foundAny; ++i, ++sec) {
        if ((sec->Characteristics & IMAGE_SCN_MEM_READ) &&
            (sec->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA))
        {
            BYTE* sectionStart = base + sec->VirtualAddress;
            size_t sectionSize = sec->Misc.VirtualSize;

            for (const auto& needle : needles) {
                BYTE* hit = nullptr;
                if (needle.w) {
                    size_t len = (wcslen(needle.w) + 1) * 2;
                    hit = FindPattern(sectionStart, sectionSize, (const BYTE*)needle.w, len);
                }
                else if (needle.a) {
                    size_t len = strlen(needle.a) + 1;
                    hit = FindPattern(sectionStart, sectionSize, (const BYTE*)needle.a, len);
                }

                if (hit) {
                    foundAny = true;
                    if (!bannerShown) {
                        if (needle.w) {
                            char utf8buf[128];
                            int conv = WideCharToMultiByte(CP_UTF8, 0, needle.w, -1, utf8buf, sizeof(utf8buf), NULL, NULL);
                            sprintf_s(buffer, sizeof(buffer),
                                "Found pattern '%s' at %p (zeros: %d)",
                                conv > 0 ? utf8buf : "<wchar_t conversion failed>", hit, needle.zeros);
                        }
                        else if (needle.a) {
                            sprintf_s(buffer, sizeof(buffer),
                                "Found pattern '%s' at %p (zeros: %d)",
                                needle.a, hit, needle.zeros);
                        }
                        WriteRawLog(buffer);
                        bannerShown = true;
                    }

                    DWORD* p = (DWORD*)hit;
                    for (int step = 0; step < 0x200; step += 4, --p) {
                        bool allZero = true;
                        for (int z = 0; z < needle.zeros && allZero; z++) {
                            if (p[z] != 0) allZero = false;
                        }

                        if (allZero) {
                            DWORD* addrOfPtr = p + needle.zeros;
                            if (addrOfPtr < (DWORD*)base || addrOfPtr >(DWORD*)(base + nt->OptionalHeader.SizeOfImage - 4))
                                continue;

                            GlobalStateInfo* info = *(GlobalStateInfo**)addrOfPtr;

                            g_globalStateSlot = (DWORD*)addrOfPtr;
                            if (g_globalStateSlot)
                                InstallWriteWatch();

                            if (!info) {
                                WriteRawLog("GlobalState pointer slot found but still NULL");
                                return nullptr;
                            }

                            __try {
                                if (info->luaState && info->databaseManager) {
                                    sprintf_s(buffer, sizeof(buffer),
                                        "Found GlobalStateInfo at %p:\n"
                                        "  Lua State: %p\n"
                                        "  DB Manager: %p\n"
                                        "  Resource Mgr: %p",
                                        info, info->luaState,
                                        info->databaseManager,
                                        info->resourceManager);
                                    WriteRawLog(buffer);
                                    return info;
                                }
                            }
                            __except (EXCEPTION_EXECUTE_HANDLER) {
                                WriteRawLog("Access violation checking candidate");
                            }
                        }
                    }
                }
            }
        }
    }

    return nullptr;
}

static GlobalStateInfo* ValidateGlobalState(GlobalStateInfo* candidate) {
    if (!candidate) return nullptr;
    if (IsOnCurrentStack(candidate)) {
        WriteRawLog("Rejecting candidate: on current stack");
        return nullptr;
    }

    __try {
        if (candidate->luaState && candidate->databaseManager) {
            char buffer[256];
            sprintf_s(buffer, sizeof(buffer),
                "Write hook validated GlobalStateInfo @ %p:\n"
                "  Lua State: %p\n"
                "  DB Manager: %p\n"
                "  Resource Mgr: %p",
                candidate, candidate->luaState,
                candidate->databaseManager,
                candidate->resourceManager);
            WriteRawLog(buffer);

            g_globalStateInfo = candidate;
            g_luaState = candidate->luaState;
            g_luaStateCaptured = true;
            return candidate;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("Access violation in write hook validation");
    }
    return candidate;
}

static LONG CALLBACK VehHandler(EXCEPTION_POINTERS* x) {
    if (x->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION &&
        x->ExceptionRecord->NumberParameters >= 2 &&
        (void*)x->ExceptionRecord->ExceptionInformation[1] == g_globalStateSlot)
    {
        DWORD oldProtect;
        VirtualProtect(g_globalStateSlot, sizeof(void*), PAGE_READWRITE, &oldProtect);

        GlobalStateInfo* info = *(GlobalStateInfo**)g_globalStateSlot;
        ValidateGlobalState(info);

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void InstallWriteWatch() {
    if (!g_globalStateSlot) return;

    if (InterlockedExchange(&g_once, 1) == 0) {
        char buffer[128];
        sprintf_s(buffer, sizeof(buffer), "Installing write watch on slot %p", g_globalStateSlot);
        WriteRawLog(buffer);

        SYSTEM_INFO si;
        GetSystemInfo(&si);
        BYTE* page = (BYTE*)g_globalStateSlot - ((uintptr_t)g_globalStateSlot & (si.dwPageSize - 1));

        DWORD oldProtect;
        if (VirtualProtect(page, si.dwPageSize, PAGE_READWRITE | PAGE_GUARD, &oldProtect)) {
            g_vehHandle = AddVectoredExceptionHandler(1, VehHandler);
            WriteRawLog("Guard-page write watch installed successfully");
        }
        else {
            sprintf_s(buffer, sizeof(buffer), "Failed to set guard page at %p: error %lu",
                page, GetLastError());
            WriteRawLog(buffer);
        }
    }
}

static DWORD WINAPI WaitForLua(LPVOID) {
    WriteRawLog("Starting Lua state scan thread...");

    while (!g_luaStateCaptured && !g_stopScan) {
        GlobalStateInfo* info = (GlobalStateInfo*)FindGlobalStateInfo();
        if (info && info->luaState) {
            g_globalStateInfo = info;
            g_luaState = info->luaState;

            char buffer[128];
            sprintf_s(buffer, sizeof(buffer), "Scanner found Lua State @ %p", g_luaState);
            WriteRawLog(buffer);

            return 0;
        }
        Sleep(200);
    }

    WriteRawLog(g_luaStateCaptured ? "Hook found Lua state first" : "Scanner stopped");
    return 1;
}

bool InitGlobalStateWatch() {
    g_stopScan = 0;
    g_luaStateCaptured = false;
    g_scanThread = CreateThread(nullptr, 0, WaitForLua, nullptr, 0, nullptr);
    if (!g_scanThread) {
        WriteRawLog("Failed to create scanner thread");
        return false;
    }
    return true;
}

void ShutdownGlobalStateWatch() {
    g_stopScan = 1;
    if (g_scanThread) {
        WaitForSingleObject(g_scanThread, 1000);
        CloseHandle(g_scanThread);
        g_scanThread = nullptr;
    }
    if (g_vehHandle) {
        RemoveVectoredExceptionHandler(g_vehHandle);
        g_vehHandle = nullptr;
    }
}

void ReportLuaState(void* L) {
    if (g_luaState) return;

    g_luaState = L;
    g_luaStateCaptured = true;
    char buffer[128];
    sprintf_s(buffer, sizeof(buffer), "Captured first Lua state @ %p", L);
    WriteRawLog(buffer);

    g_globalStateInfo = (GlobalStateInfo*)FindOwnerOfLuaState(L);
    if (g_globalStateInfo) {
        DumpMemory("GlobalStateInfo", g_globalStateInfo, 0x40);
        if (g_scanThread) {
            WaitForSingleObject(g_scanThread, INFINITE);
            CloseHandle(g_scanThread);
            g_scanThread = nullptr;
        }
    }
}

void* LuaState() {
    return g_luaState;
}

const GlobalStateInfo* Info() {
    return g_globalStateInfo;
}

} // namespace Engine

