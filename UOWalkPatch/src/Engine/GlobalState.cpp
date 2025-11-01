#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "Core/CoreFlags.hpp"
#include "Core/Logging.hpp"
#include "Core/PatternScan.hpp"
#include "Core/Utils.hpp"
#include "Engine/GlobalState.hpp"
#include "Engine/LuaBridge.hpp"
#include "Engine/Movement.hpp"
#include "Net/SendBuilder.hpp"

namespace Engine {

static GlobalStateInfo* g_globalStateInfo = nullptr;
static void* g_luaState = nullptr;
static HANDLE g_scanThread = nullptr;
static volatile LONG g_stopScan = 0;
static DWORD* g_globalStateSlot = nullptr;
static LONG g_once = 0;
static PVOID g_vehHandle = nullptr;
static bool g_luaStateCaptured = false;
static GlobalStateInfo* g_lastValidatedInfo = nullptr;
static std::atomic<std::uint32_t> g_globalStateCookie{0};
static BYTE* g_guardPageBase = nullptr;
static SIZE_T g_guardPageSize = 0;
static HANDLE g_pollThread = nullptr;
static volatile LONG g_stopPoll = 0;
static std::atomic<bool> g_pollThreadStarted{false};

namespace Lua {
    void OnGlobalStateValidated(const GlobalStateInfo* info, std::uint32_t cookie);
}

// Forward declarations
static void* FindGlobalStateInfo();
static void* FindOwnerOfLuaState(void* lua);
static GlobalStateInfo* ValidateGlobalState(GlobalStateInfo* candidate);
static void InstallWriteWatch();
static void StartGlobalStatePoll();
static DWORD WINAPI WaitForLua(LPVOID);
static LONG CALLBACK VehHandler(EXCEPTION_POINTERS* x);
static GlobalStateInfo* ReadSlotUnsafe();
static DWORD WINAPI PollGlobalStateSlot(LPVOID);
static bool HelpersAwaitingGlobalState();

void* FindRegisterLuaFunction() {
    HMODULE hExe = GetModuleHandleA(nullptr);
    if (!hExe) {
        WriteRawLog("FindRegisterLuaFunction: no module handle");
        return nullptr;
    }

    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), hExe, &mi, sizeof(mi))) {
        WriteRawLog("FindRegisterLuaFunction: GetModuleInformation failed");
        return nullptr;
    }

    BYTE* base = static_cast<BYTE*>(mi.lpBaseOfDll);
    SIZE_T size = mi.SizeOfImage;

    static const char kAnchor[] = "GetBuildVersion";
    BYTE* anchor = FindBytes(base, size, reinterpret_cast<const BYTE*>(kAnchor), sizeof(kAnchor));
    if (!anchor) {
        WriteRawLog("FindRegisterLuaFunction: anchor string not found");
        return nullptr;
    }
    uintptr_t anchorAddr = reinterpret_cast<uintptr_t>(anchor);

    char buffer[160];
    sprintf_s(buffer, sizeof(buffer), "FindRegisterLuaFunction: anchor string at %p", anchor);
    WriteRawLog(buffer);

    auto tryRecordSlot = [&](BYTE* cursor) {
        for (BYTE* k = cursor - 0x80; k && k < cursor + 0x80; ++k) {
            if (k[0] == 0xA3) {
                g_globalStateSlot = reinterpret_cast<DWORD*>(*reinterpret_cast<DWORD*>(k + 1));
                sprintf_s(buffer, sizeof(buffer), "FindRegisterLuaFunction: slot via A3 at %p -> %p", k, g_globalStateSlot);
                WriteRawLog(buffer);
                return;
            }
            if (k[0] == 0x89 && (k[1] & 0x07) == 0x05) {
                g_globalStateSlot = reinterpret_cast<DWORD*>(*reinterpret_cast<DWORD*>(k + 2));
                sprintf_s(buffer, sizeof(buffer), "FindRegisterLuaFunction: slot via 89 %02X at %p -> %p", k[1], k, g_globalStateSlot);
                WriteRawLog(buffer);
                return;
            }
        }
    };

    for (BYTE* p = base; p < base + size - 5; ++p) {
        bool ref =
            (p[0] == 0x68 && *reinterpret_cast<DWORD*>(p + 1) == static_cast<DWORD>(anchorAddr)) ||
            (p[0] == 0x8D && (p[1] & 0xC7) == 0x05 && *reinterpret_cast<DWORD*>(p + 2) == static_cast<DWORD>(anchorAddr));
        if (!ref)
            continue;

        sprintf_s(buffer, sizeof(buffer), "FindRegisterLuaFunction: string ref at %p", p);
        WriteRawLog(buffer);

        for (BYTE* q = p; q < p + 0x40; ++q) {
            if (q[0] == 0xE8) {
                INT32 rel = *reinterpret_cast<INT32*>(q + 1);
                BYTE* callee = q + 5 + rel;
                sprintf_s(buffer, sizeof(buffer),
                    "FindRegisterLuaFunction: direct call at %p -> %p", q, callee);
                WriteRawLog(buffer);
                tryRecordSlot(q);
                return callee;
            }
            if (q[0] == 0xFF && q[1] == 0x15) {
                DWORD disp = *reinterpret_cast<DWORD*>(q + 2);
                BYTE** ind = reinterpret_cast<BYTE**>(q + 6 + disp);
                BYTE* callee = ind ? *ind : nullptr;
                sprintf_s(buffer, sizeof(buffer),
                    "FindRegisterLuaFunction: indirect call at %p -> %p", q, callee);
                WriteRawLog(buffer);
                tryRecordSlot(q);
                return callee;
            }
        }
    }

    WriteRawLog("FindRegisterLuaFunction: no callsite located");
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

    // Primary lookup: signature scan for mov ecx, [globalStateInfo]; mov eax, [ecx+0C]
    const char* kGlobalStateSig = "8B 0D ?? ?? ?? ?? 8B 41 0C";
    if (!g_globalStateSlot) {
        BYTE* hit = FindPatternText(kGlobalStateSig);
        if (hit) {
            DWORD slotAddr = *reinterpret_cast<DWORD*>(hit + 2);
            if (slotAddr) {
                auto slot = reinterpret_cast<GlobalStateInfo**>(slotAddr);
                char buffer[160];
                sprintf_s(buffer, sizeof(buffer),
                    "GlobalState signature hit at %p (slot %p)", hit, slot);
                WriteRawLog(buffer);

                g_globalStateSlot = reinterpret_cast<DWORD*>(slotAddr);
                InstallWriteWatch();

                __try {
                    GlobalStateInfo* info = slot ? *slot : nullptr;
                    if (info && info->luaState && info->databaseManager) {
                        sprintf_s(buffer, sizeof(buffer),
                            "Signature resolved GlobalStateInfo @ %p:\n"
                            "  Lua State: %p\n"
                            "  DB Manager: %p\n"
                            "  Resource Mgr: %p",
                            info, info->luaState, info->databaseManager, info->resourceManager);
                        WriteRawLog(buffer);
                        if (info->databaseManager)
                            Net::NotifyGlobalStateManager(info->databaseManager);
                        return info;
                    }
                    if (!info)
                        WriteRawLog("GlobalState slot currently NULL; waiting for guard page notification");
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    WriteRawLog("Access violation reading GlobalState slot from signature");
                }
            }
        }
    }

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

    if (candidate == g_lastValidatedInfo && candidate->luaState == g_luaState) {
        return candidate;
    }

    __try {
        if (candidate->luaState && candidate->databaseManager) {
            char buffer[256];
            sprintf_s(buffer, sizeof(buffer),
                "Write hook validated GlobalStateInfo @ %p:\n"
                "  Lua State: %p\n"
                "  DB Manager: %p\n"
                "  Script Ctx: %p\n"
                "  Resource Mgr: %p",
                candidate, candidate->luaState,
                candidate->databaseManager,
                candidate->scriptContext,
                candidate->resourceManager);
            WriteRawLog(buffer);
            if (candidate->databaseManager)
                Net::NotifyGlobalStateManager(candidate->databaseManager);
            InterlockedExchange(&g_flags.lua_slot_seen, 1);

            void* engineCtx = candidate->engineContext;
            void* networkCfg = candidate->networkConfig;
            if (engineCtx) {
                __try {
                    void** vtbl = *reinterpret_cast<void***>(engineCtx);
                    void* entries[8]{};
                    for (int i = 0; i < 8; ++i)
                        entries[i] = vtbl ? vtbl[i] : nullptr;
                    char extra[256];
                    sprintf_s(extra, sizeof(extra),
                        "  engineContext=%p vtbl=%p entries={%p,%p,%p,%p,%p,%p,%p,%p} networkConfig=%p",
                        engineCtx, vtbl,
                        entries[0], entries[1], entries[2], entries[3],
                        entries[4], entries[5], entries[6], entries[7],
                        networkCfg);
                    WriteRawLog(extra);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    char extra[160];
                    sprintf_s(extra, sizeof(extra),
                        "  engineContext=%p (vtbl read failed) networkConfig=%p",
                        engineCtx, networkCfg);
                    WriteRawLog(extra);
                }
                Engine::Lua::UpdateEngineContext(engineCtx);
            } else {
                char extra[160];
                sprintf_s(extra, sizeof(extra),
                    "  engineContext=%p networkConfig=%p",
                    engineCtx, networkCfg);
                WriteRawLog(extra);
                Engine::Lua::UpdateEngineContext(nullptr);
            }

            g_globalStateInfo = candidate;
            g_luaState = candidate->luaState;
            g_luaStateCaptured = true;
            g_lastValidatedInfo = candidate;
            std::uint32_t cookie = g_globalStateCookie.fetch_add(1, std::memory_order_acq_rel) + 1;
            Lua::OnGlobalStateValidated(candidate, cookie);

            Net::InitSendBuilder(candidate);

            // The Lua VM is now known; ensure helper registration runs
            RequestWalkRegistration();
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
        x->ExceptionRecord->NumberParameters >= 2)
    {
        void* faultAddr = reinterpret_cast<void*>(x->ExceptionRecord->ExceptionInformation[1]);

        bool onWatchedPage = false;
        if (g_guardPageBase && g_guardPageSize)
        {
            BYTE* addr = static_cast<BYTE*>(faultAddr);
            BYTE* base = g_guardPageBase;
            BYTE* end = base + g_guardPageSize;
            onWatchedPage = addr >= base && addr < end;
        }
        else if (faultAddr == g_globalStateSlot)
        {
            onWatchedPage = true;
        }

        if (!onWatchedPage)
            return EXCEPTION_CONTINUE_SEARCH;

        DWORD oldProtect;
        VirtualProtect(g_guardPageBase ? g_guardPageBase : reinterpret_cast<BYTE*>(g_globalStateSlot),
                       g_guardPageSize ? g_guardPageSize : sizeof(void*),
                       PAGE_READWRITE,
                       &oldProtect);

        GlobalStateInfo* info = ReadSlotUnsafe();
        ValidateGlobalState(info);

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void InstallWriteWatch() {
    if (!g_globalStateSlot) return;

    bool firstInstall = (InterlockedExchange(&g_once, 1) == 0);
    if (firstInstall) {
        char buffer[128];
        sprintf_s(buffer, sizeof(buffer), "Installing write watch on slot %p", g_globalStateSlot);
        WriteRawLog(buffer);

        SYSTEM_INFO si;
        GetSystemInfo(&si);
        BYTE* page = (BYTE*)g_globalStateSlot - ((uintptr_t)g_globalStateSlot & (si.dwPageSize - 1));

        DWORD oldProtect;
        if (VirtualProtect(page, si.dwPageSize, PAGE_READWRITE | PAGE_GUARD, &oldProtect)) {
            g_guardPageBase = page;
            g_guardPageSize = si.dwPageSize;
            g_vehHandle = AddVectoredExceptionHandler(1, VehHandler);
            WriteRawLog("Guard-page write watch installed successfully");
        }
        else {
            sprintf_s(buffer, sizeof(buffer), "Failed to set guard page at %p: error %lu",
                page, GetLastError());
            WriteRawLog(buffer);
        }
    }

    StartGlobalStatePoll();
}

static GlobalStateInfo* ReadSlotUnsafe()
{
    if (!g_globalStateSlot)
        return nullptr;
    GlobalStateInfo* value = nullptr;
    __try {
        value = *reinterpret_cast<GlobalStateInfo**>(g_globalStateSlot);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteRawLog("Exception reading GlobalState slot value");
        value = nullptr;
    }
    return value;
}

static bool HelpersAwaitingGlobalState()
{
    const char* stage = Engine::Lua::GetHelperStageSummary();
    if (!stage)
        return true;
    return std::strcmp(stage, "waiting_for_global_state") == 0;
}

static DWORD WINAPI PollGlobalStateSlot(LPVOID)
{
    constexpr DWORD kInitialDelayMs = 150;
    constexpr DWORD kPollIntervalMs = 500;
    constexpr DWORD kMaxAttempts = 10;

    Sleep(kInitialDelayMs);

    for (DWORD attempt = 0; attempt < kMaxAttempts; ++attempt) {
        if (InterlockedCompareExchange(&g_stopPoll, 0, 0) != 0)
            break;
        if (g_globalStateInfo && g_luaStateCaptured)
            break;
        if (!HelpersAwaitingGlobalState())
            break;

        GlobalStateInfo* slotVal = ReadSlotUnsafe();
        if (slotVal) {
            GlobalStateInfo* validated = ValidateGlobalState(slotVal);
            if (validated && validated == g_globalStateInfo &&
                g_globalStateInfo && g_globalStateInfo->luaState && g_globalStateInfo->databaseManager) {
                Log::Logf(Log::Level::Info,
                          Log::Category::Core,
                          "[CORE] GlobalState polled OK @ %p",
                          validated);
                InterlockedExchange(&g_stopPoll, 1);
                break;
            }
        }

        if (attempt + 1 < kMaxAttempts)
            Sleep(kPollIntervalMs);
    }

    g_pollThreadStarted.store(false, std::memory_order_release);
    InterlockedExchange(&g_stopPoll, 1);
    return 0;
}

static void StartGlobalStatePoll()
{
    if (!g_globalStateSlot)
        return;

    bool expected = false;
    if (!g_pollThreadStarted.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    InterlockedExchange(&g_stopPoll, 0);
    HANDLE thread = CreateThread(nullptr, 0, PollGlobalStateSlot, nullptr, 0, nullptr);
    if (!thread) {
        g_pollThreadStarted.store(false, std::memory_order_release);
        WriteRawLog("Failed to create GlobalState poll thread");
        g_pollThread = nullptr;
        return;
    }
    g_pollThread = thread;
}

static DWORD WINAPI WaitForLua(LPVOID) {
    WriteRawLog("Starting Lua state scan thread...");

    while (!g_luaStateCaptured && !g_stopScan) {
        GlobalStateInfo* info = (GlobalStateInfo*)FindGlobalStateInfo();
        if (info && info->luaState) {
            GlobalStateInfo* active = ValidateGlobalState(info);
            if (!active)
                active = info;

            g_globalStateInfo = active;
            g_luaState = active ? active->luaState : nullptr;
            if (g_luaState)
                g_luaStateCaptured = true;

            char buffer[128];
            sprintf_s(buffer, sizeof(buffer), "Scanner found Lua State @ %p", g_luaState);
            WriteRawLog(buffer);
            InterlockedExchange(&g_flags.lua_slot_seen, 1);

            // Queue Lua helper registration for the next safe point
            RequestWalkRegistration();
            Engine::Lua::OnStateObserved(static_cast<lua_State*>(g_luaState),
                                         active ? active->scriptContext : nullptr,
                                         0,
                                         false);
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
    InterlockedExchange(&g_stopPoll, 0);
    g_pollThreadStarted.store(false, std::memory_order_release);
    g_scanThread = CreateThread(nullptr, 0, WaitForLua, nullptr, 0, nullptr);
    if (!g_scanThread) {
        WriteRawLog("Failed to create scanner thread");
        return false;
    }
    return true;
}

void ShutdownGlobalStateWatch() {
    g_stopScan = 1;
    InterlockedExchange(&g_stopPoll, 1);
    if (g_scanThread) {
        WaitForSingleObject(g_scanThread, 1000);
        CloseHandle(g_scanThread);
        g_scanThread = nullptr;
    }
    if (g_vehHandle) {
        RemoveVectoredExceptionHandler(g_vehHandle);
        g_vehHandle = nullptr;
    }
    if (g_pollThread) {
        WaitForSingleObject(g_pollThread, 1000);
        CloseHandle(g_pollThread);
        g_pollThread = nullptr;
    }
    g_pollThreadStarted.store(false, std::memory_order_release);
    g_guardPageBase = nullptr;
    g_guardPageSize = 0;
}

void ReportLuaState(void* L) {
    if (!L || g_luaState == L)
        return;

    g_luaState = L;
    g_luaStateCaptured = true;
    char buffer[128];
    sprintf_s(buffer, sizeof(buffer), "Captured Lua state @ %p", L);
   WriteRawLog(buffer);

    g_globalStateInfo = (GlobalStateInfo*)FindOwnerOfLuaState(L);
    if (g_globalStateInfo) {
        GlobalStateInfo* validated = ValidateGlobalState(g_globalStateInfo);
        if (validated)
            g_globalStateInfo = validated;
        DumpMemory("GlobalStateInfo", g_globalStateInfo, 0x40);
        if (g_scanThread) {
            WaitForSingleObject(g_scanThread, INFINITE);
            CloseHandle(g_scanThread);
            g_scanThread = nullptr;
        }
    }

    // The Lua VM was recreated; request re-registration of helpers
    RequestWalkRegistration();
    Engine::Lua::OnStateObserved(static_cast<lua_State*>(L),
                                 g_globalStateInfo ? g_globalStateInfo->scriptContext : nullptr);
}

void* LuaState() {
    return g_luaState;
}

const GlobalStateInfo* Info() {
    return g_globalStateInfo;
}

uintptr_t GlobalStateSlotAddress() {
    return reinterpret_cast<uintptr_t>(g_globalStateSlot);
}

GlobalStateInfo* GlobalStateSlotValue() {
    return ReadSlotUnsafe();
}

bool RefreshLuaStateFromSlot()
{
    GlobalStateInfo* slotVal = ReadSlotUnsafe();
    if (!slotVal || !slotVal->luaState || !slotVal->databaseManager) {
        return false;
    }

    bool changed = (slotVal != g_lastValidatedInfo) || (slotVal->luaState != g_luaState);
    if (changed) {
        char buffer[160];
        sprintf_s(buffer, sizeof(buffer),
            "Refreshing Lua state from slot: info=%p lua=%p", slotVal, slotVal->luaState);
        WriteRawLog(buffer);
        ValidateGlobalState(slotVal);
        Engine::Lua::OnStateObserved(static_cast<lua_State*>(slotVal->luaState),
                                     slotVal->scriptContext);
    }
    return changed;
}

std::uint32_t GlobalStateCookie() {
    return g_globalStateCookie.load(std::memory_order_acquire);
}

} // namespace Engine
