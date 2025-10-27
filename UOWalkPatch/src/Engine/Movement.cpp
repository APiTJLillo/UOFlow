#include <windows.h>
#include <winsock2.h>
#include <psapi.h>
#include <minhook.h>
#include <cstdint>
#include <cstdio>

#include "Core/Logging.hpp"
#include "Core/PatternScan.hpp"
#include "Net/SendBuilder.hpp"
#include "Engine/Movement.hpp"
#include "Engine/LuaBridge.hpp"

// Move variable definition to global scope
extern volatile LONG g_needWalkReg;

namespace {

static void* g_moveComp = nullptr; // movement component instance
static void* g_dest = nullptr;     // last destination vector
using UpdateState_t = uint32_t(__thiscall*)(void*, void*, uint32_t, int);
static UpdateState_t g_updateState = nullptr;
static UpdateState_t g_origUpdate = nullptr;
static volatile LONG g_haveMoveComp = 0;
static long g_updateLogCount = 0;
static thread_local int g_updateDepth = 0;
static uint32_t g_fastWalkKeys[32]{};
static int g_fwTop = 0;

static constexpr int kStepDx[8] = {0, 1, 1, 1, 0, -1, -1, -1};
static constexpr int kStepDy[8] = {-1, -1, 0, 1, 1, 1, 0, -1};

static void FindMoveComponent();
static uint32_t __fastcall H_Update(void* thisPtr, void* _unused, void* destPtr, uint32_t dir, int runFlag);

static int NormalizeDirection(int dir)
{
    if (dir >= 0)
        return dir & 7;
    int normalized = dir % 8;
    if (normalized < 0)
        normalized += 8;
    return normalized & 7;
}

} // namespace

namespace Engine {

void PushFastWalkKey(uint32_t key) {
    if (g_fwTop < (int)(sizeof(g_fastWalkKeys) / sizeof(g_fastWalkKeys[0])))
        g_fastWalkKeys[g_fwTop++] = key;
}

uint32_t PopFastWalkKey() {
    return g_fwTop > 0 ? g_fastWalkKeys[--g_fwTop] : 0;
}

bool MovementReady() {
    return g_updateState && g_moveComp;
}

void RequestWalkRegistration() {
    InterlockedExchange(&g_needWalkReg, 1);
}

bool InitMovementHooks() {
    const char* kUpdateSig =
        "83 EC 58 53 55 8B 6C 24 64 80 7D 79 00 56 57 0F 85 ?? ?? ?? 00"
        "80 7D 7A 00 0F 85 ?? ?? ?? 00";

    BYTE* hit = FindPatternText(kUpdateSig);
    if (hit) {
        g_updateState = reinterpret_cast<UpdateState_t>(hit);
        char buf[64];
        sprintf_s(buf, sizeof(buf), "Found updateDataStructureState at %p", hit);
        WriteRawLog(buf);
        if (MH_CreateHook(g_updateState, &H_Update, reinterpret_cast<LPVOID*>(&g_origUpdate)) == MH_OK &&
            MH_EnableHook(g_updateState) == MH_OK) {
            WriteRawLog("updateDataStructureState hook installed");
        } else {
            WriteRawLog("updateDataStructureState hook failed; falling back to scan");
            g_origUpdate = g_updateState;
            FindMoveComponent();
        }
        return true;
    }
    WriteRawLog("updateDataStructureState not found");
    return false;
}

void ShutdownMovementHooks() {
    if (g_updateState) {
        MH_DisableHook(g_updateState);
        MH_RemoveHook(g_updateState);
        g_updateState = nullptr;
        g_origUpdate = nullptr;
    }
    g_moveComp = nullptr;
    g_dest = nullptr;
    g_fwTop = 0;
}

} // namespace Engine

namespace {

static void FindMoveComponent() {
    if (!g_updateState)
        return;

    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(nullptr), &mi, sizeof(mi)))
        return;

    BYTE* base = (BYTE*)mi.lpBaseOfDll;
    BYTE* end = base + mi.SizeOfImage;

    BYTE* vtable = nullptr;
    for (BYTE* p = base; p + 0x44 <= end; p += 4) {
        if (*(DWORD*)(p + 0x40) == (DWORD)(uintptr_t)g_updateState) {
            vtable = p;
            break;
        }
    }

    if (!vtable) {
        WriteRawLog("Move component vtable not found");
        return;
    }

    char buf[64];
    sprintf_s(buf, sizeof(buf), "MoveComp vtable at %p", vtable);
    WriteRawLog(buf);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = 0;
    while (addr < (BYTE*)si.lpMaximumApplicationAddress) {
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ)) &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            BYTE* b = (BYTE*)mbi.BaseAddress;
            BYTE* e = b + mbi.RegionSize;
            for (BYTE* p = b; p + sizeof(void*) <= e; p += sizeof(void*)) {
                if (*(void**)p == (void*)vtable) {
                    MEMORY_BASIC_INFORMATION mbi2;
                    if (VirtualQuery(p, &mbi2, sizeof(mbi2)) &&
                        (mbi2.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                        g_moveComp = p;
                        sprintf_s(buf, sizeof(buf), "MoveComp candidate %p", p);
                        WriteRawLog(buf);
                        return;
                    }
                }
            }
        }
        addr += mbi.RegionSize;
    }
    WriteRawLog("Move component not found via scan");
}

static uint32_t __fastcall H_Update(void* thisPtr, void* _unused, void* destPtr, uint32_t dir, int runFlag) {
    if (!g_moveComp && InterlockedCompareExchange(&g_haveMoveComp, 1, 0) == 0) {
        g_moveComp = thisPtr;
        Logf("Captured moveComp = %p (thread %lu)", g_moveComp, GetCurrentThreadId());
        Engine::RequestWalkRegistration();
    }

    if (g_updateDepth++ == 0 && g_updateLogCount < 200) {
        Logf("updateState(this=%p, dest=%p, dir=%u, run=%d)", thisPtr, destPtr, dir, runFlag);
        ++g_updateLogCount;
    }

    g_dest = destPtr;
    uint32_t rc = g_origUpdate ? g_origUpdate(thisPtr, destPtr, dir, runFlag) : 0;

    --g_updateDepth;
    if (g_updateDepth == 0 && InterlockedExchange(&g_needWalkReg, 0)) {
        WriteRawLog("H_Update safe point - registering Lua helpers");
        Engine::Lua::RegisterOurLuaFunctions();
    }
    return rc;
}

} // namespace

extern "C" __declspec(dllexport) bool __stdcall SendWalk(int dir, int run) {
    if (!Net::IsSendReady()) {
        WriteRawLog("SendWalk prerequisites missing");
        return false;
    }

    const int normalizedDir = NormalizeDirection(dir);
    const bool shouldRun = run != 0;

    uint8_t pkt[7]{};
    pkt[0] = 0x02;
    pkt[1] = static_cast<uint8_t>(normalizedDir) | (shouldRun ? 0x80 : 0);
    static uint8_t seq = 0;
    if (++seq == 0)
        seq = 1;
    pkt[2] = seq;

    uint32_t key = Engine::PopFastWalkKey();
    if (!key) {
        WriteRawLog("SendWalk no fast-walk key");
        return false;
    }

    *reinterpret_cast<uint32_t*>(pkt + 3) = htonl(key);
    if (!Net::SendPacketRaw(pkt, sizeof(pkt))) {
        WriteRawLog("SendWalk send failed");
        return false;
    }

    if (g_moveComp && g_origUpdate && g_dest) {
        struct Vec3 { int16_t x, y; int8_t z; };
        Vec3 tmp = *reinterpret_cast<Vec3*>(g_dest);
        tmp.x += kStepDx[normalizedDir];
        tmp.y += kStepDy[normalizedDir];
        g_origUpdate(g_moveComp, &tmp, static_cast<uint32_t>(normalizedDir), shouldRun ? 1 : 0);
    }

    return true;
}

