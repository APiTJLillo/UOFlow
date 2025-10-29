#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cctype>
#include <atomic>
#include <string>
#include <deque>
#include <mutex>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <vector>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdarg>
#include <sstream>

#include <minhook.h>

#include "Core/Logging.hpp"
#include "Engine/GlobalState.hpp"
#include "Engine/LuaBridge.hpp"
#include "Engine/LuaStateRegistry.hpp"
#include "Engine/Movement.hpp"

#include "LuaPlus.h"

#ifndef LUA_NOREF
#define LUA_NOREF (-2)
#endif

#ifndef LUA_REFNIL
#define LUA_REFNIL (-1)
#endif

#ifndef LUA_HOOKCALL
#define LUA_HOOKCALL 0
#define LUA_HOOKRET 1
#define LUA_HOOKLINE 2
#define LUA_HOOKCOUNT 3
#define LUA_HOOKTAILRET 4
#endif

#ifndef LUA_MASKCALL
#define LUA_MASKCALL (1 << LUA_HOOKCALL)
#define LUA_MASKRET (1 << LUA_HOOKRET)
#define LUA_MASKLINE (1 << LUA_HOOKLINE)
#define LUA_MASKCOUNT (1 << LUA_HOOKCOUNT)
#endif

#ifndef LUA_IDSIZE
#define LUA_IDSIZE 60
#endif

#ifndef LUA_MULTRET
#define LUA_MULTRET (-1)
#endif

#ifndef lua_newtable
#define lua_newtable(L) lua_createtable(L, 0, 0)
#endif

typedef struct lua_Debug {
    int event;
    const char* name;
    const char* namewhat;
    const char* what;
    const char* source;
    int currentline;
    int nups;
    int linedefined;
    int lastlinedefined;
    char short_src[LUA_IDSIZE];
    int i_ci;
} lua_Debug;

extern "C" {
    LUA_API int lua_gettop(lua_State* L);
    LUA_API void lua_settop(lua_State* L, int idx);
    LUA_API void lua_pushvalue(lua_State* L, int idx);
    LUA_API int lua_isnumber(lua_State* L, int idx);
    LUA_API int lua_isboolean(lua_State* L, int idx);
    LUA_API int lua_iscfunction(lua_State* L, int idx);
    LUA_API lua_CFunction lua_tocfunction(lua_State* L, int idx);
    LUA_API const char* lua_tolstring(lua_State* L, int idx, size_t* len);
    LUA_API const char* lua_tostring(lua_State* L, int idx);
    LUA_API const char* lua_getupvalue(lua_State* L, int funcindex, int n);
    LUA_API int lua_next(lua_State* L, int idx);
    LUA_API int luaL_ref(lua_State* L, int t);
    LUA_API void luaL_unref(lua_State* L, int t, int ref);
    LUA_API const char* lua_typename(lua_State* L, int tp);
    LUA_API int lua_type(lua_State* L, int idx);
    LUA_API lua_CFunction lua_atpanic(lua_State* L, lua_CFunction panicf);
    LUA_API int lua_getstack(lua_State* L, int level, lua_Debug* ar);
    LUA_API int lua_getinfo(lua_State* L, const char* what, lua_Debug* ar);
    typedef void(__cdecl* lua_Hook)(lua_State*, lua_Debug*);
    LUA_API void lua_sethook(lua_State* L, lua_Hook func, int mask, int count);
    LUA_API lua_Hook lua_gethook(lua_State* L);
    LUA_API int lua_gethookmask(lua_State* L);
    LUA_API int luaL_loadstring(lua_State* L, const char* str);
    LUA_API int lua_pcall(lua_State* L, int nargs, int nresults, int errfunc);
}

#ifndef LUA_RIDX_GLOBALS
#define LUA_RIDX_GLOBALS 2
#endif

namespace {

using ClientRegisterFn = int(__stdcall*)(void*, void*, const char*);
using LuaStateGetCStateFn = lua_State* (__thiscall*)(void*);
using LuaStateAtPanicFn = lua_CFunction(__thiscall*)(void*, lua_CFunction);

using Engine::Lua::LuaStateInfo;
using Engine::Lua::LuaStateRegistry;

constexpr DWORD kQueueDrainLogCooldownMs = 1000;
constexpr DWORD kMaintenanceIntervalMs = 5000;
constexpr DWORD kProbeInitialBackoffMs = 1000;
constexpr DWORD kProbeMaxBackoffMs = 8000;

enum : uint32_t {
    STATE_FLAG_HELPERS        = 1u << 0,
    STATE_FLAG_QUARANTINED    = 1u << 1,
    STATE_FLAG_VALID          = 1u << 2,
    STATE_FLAG_HELPERS_BOUND  = 1u << 3,
    STATE_FLAG_PANIC_OK       = 1u << 4,
    STATE_FLAG_PANIC_MISS     = 1u << 5,
    STATE_FLAG_DEBUG_OK       = 1u << 6,
    STATE_FLAG_DEBUG_MISS     = 1u << 7,
};

struct LuaTask {
    std::string name;
    lua_State* target = nullptr;
    std::function<void(lua_State*)> fn;
};

struct ModuleBounds {
    uintptr_t base = 0;
    size_t size = 0;
    bool valid = false;
};

static ClientRegisterFn g_origRegister = nullptr;
static ClientRegisterFn g_clientRegister = nullptr;
static void* g_registerTarget = nullptr;
static std::atomic<bool> g_registerResolved{false};
static std::atomic<void*> g_engineContext{nullptr};
static std::atomic<void*> g_latestScriptCtx{nullptr};

static std::atomic<DWORD> g_scriptThreadId{0};
static std::atomic<lua_State*> g_mainLuaState{nullptr};
static std::atomic<void*> g_mainLuaPlusState{nullptr};

static LuaStateRegistry g_stateRegistry;
static std::atomic<uint64_t> g_generation{1};
static std::atomic<uint64_t> g_lastMaintenanceTick{0};

static std::mutex g_taskMutex;
static std::deque<LuaTask> g_taskQueue;
static thread_local bool g_processingLuaQueue = false;
static std::atomic<bool> g_queueLoggedDuringInit{false};
static std::atomic<DWORD> g_lastQueueLogTick{0};

static std::mutex g_bindingMutex;
static std::unordered_set<lua_State*> g_bindingInFlight;

static LuaStateGetCStateFn g_luaStateGetCState = nullptr;
static LuaStateAtPanicFn g_luaStateAtPanic = nullptr;

static thread_local char g_cppExceptionDetail[192];

static constexpr const char* kHelperWalkName = "uow_walk";
static constexpr const char* kHelperDumpName = "uow_dump_walk_env";
static constexpr const char* kHelperInspectName = "uow_lua_inspect";
static constexpr const char* kHelperRebindName = "uow_lua_rebind_all";
static constexpr const char* kHelperSelfTestName = "uow_selftest";

// Forward declarations
static void ProcessPendingLuaTasks(lua_State* L);
static void PostToLuaThread(lua_State* L, const char* name, std::function<void(lua_State*)> fn);
static void MaybeRunMaintenance();
static void RequestBindForState(const LuaStateInfo& info, const char* reason, bool force);
static void BindHelpersTask(lua_State* L, uint64_t generation, bool force, const char* reason);
static bool BindHelpersOnThread(lua_State* L, const LuaStateInfo& info, uint64_t generation, bool force);
static void InstallPanicAndDebug(lua_State* L, LuaStateInfo& info);
static bool RegisterHelper(lua_State* L, const LuaStateInfo& info, const char* name, lua_CFunction fn, uint64_t generation);
static void DumpWalkEnv(lua_State* L, const char* reason);
static int Lua_UOWalk(lua_State* L);
static int Lua_UOWDump(lua_State* L);
static int Lua_UOWInspect(lua_State* L);
static int Lua_UOWSelfTest(lua_State* L);
static int Lua_UOWRebindAll(lua_State* L);
static void ForceRebindAll(const char* reason);
static bool ResolveRegisterFunction();
static int __stdcall Hook_Register(void* ctx, void* func, const char* name);
static bool ProbeLua(lua_State* L);
static lua_State* NormalizeLuaStatePointer(lua_State* candidate);

static void AppendPointer(std::string& dest, const void* ptr) {
    char buffer[32];
    sprintf_s(buffer, sizeof(buffer), "%p", ptr);
    dest.append(buffer);
}

static std::string JoinStrings(const std::vector<std::string>& chunks, const char* separator = ",") {
    std::string out;
    if (chunks.empty())
        return out;
    size_t total = 0;
    for (const auto& chunk : chunks)
        total += chunk.size();
    total += (chunks.size() - 1) * std::strlen(separator);
    out.reserve(total);
    for (size_t i = 0; i < chunks.size(); ++i) {
        if (i)
            out.append(separator);
        out.append(chunks[i]);
    }
    return out;
}

static bool SafeLuaProbeStack(lua_State* L, int* outTop, DWORD* outSeh) noexcept;
static bool SafeLuaSetTop(lua_State* L, int idx, DWORD* outSeh) noexcept;
static bool SafeLuaGetGlobalType(lua_State* L, const char* name, int* outType, const char** outTypeName, DWORD* outSeh) noexcept;

static void SanitizeIntoBuffer(const char* data, size_t len, char* dest, size_t destSize, size_t maxLen = 48) {
    if (!dest || destSize == 0)
        return;
    if (!data) {
        strncpy_s(dest, destSize, "<null>", _TRUNCATE);
        return;
    }
    size_t writeLimit = destSize > 0 ? destSize - 1 : 0;
    if (writeLimit == 0)
        return;
    size_t limit = std::min(len, std::min(maxLen, writeLimit));
    size_t i = 0;
    for (; i < limit; ++i) {
        unsigned char ch = static_cast<unsigned char>(data[i]);
        dest[i] = (ch < 0x20 || ch >= 0x7Fu) ? '?' : static_cast<char>(ch);
    }
    if (len > limit && (writeLimit - i) >= 3) {
        dest[i++] = '.';
        dest[i++] = '.';
        dest[i++] = '.';
    }
    dest[i] = '\0';
}

struct PackageLoadedSnapshot {
    bool packageValid = false;
    bool loadedValid = false;
    char packageType[16]{};
    char loadedType[16]{};
    size_t keyCount = 0;
    bool truncated = false;
    char keys[16][49]{};
};

static bool SafeSnapshotPackageLoaded(lua_State* L, PackageLoadedSnapshot& out, DWORD* outSeh) noexcept {
    if (!L)
        return false;
    std::memset(&out, 0, sizeof(out));
    __try {
        int top = lua_gettop(L);
        lua_getglobal(L, "package");
        int packageType = lua_type(L, -1);
        const char* packageTypeName = lua_typename(L, packageType);
        strncpy_s(out.packageType, packageTypeName ? packageTypeName : "<unknown>", _TRUNCATE);
        out.packageValid = (packageType != LUA_TNONE);
        if (packageType == LUA_TTABLE) {
            lua_getfield(L, -1, "loaded");
            int loadedType = lua_type(L, -1);
            const char* loadedTypeName = lua_typename(L, loadedType);
            strncpy_s(out.loadedType, loadedTypeName ? loadedTypeName : "<unknown>", _TRUNCATE);
            out.loadedValid = (loadedType == LUA_TTABLE);
            if (out.loadedValid) {
                const size_t kLimit = 16;
                lua_pushnil(L);
                while (lua_next(L, -2) != 0) {
                    if (out.keyCount < kLimit) {
                        int keyType = lua_type(L, -2);
                        if (keyType == LUA_TSTRING) {
                            size_t textLen = 0;
                            const char* keyStr = lua_tolstring(L, -2, &textLen);
                            SanitizeIntoBuffer(keyStr, textLen, out.keys[out.keyCount], sizeof(out.keys[out.keyCount]));
                        } else {
                            const char* keyTypeName = lua_typename(L, keyType);
                            strncpy_s(out.keys[out.keyCount], keyTypeName ? keyTypeName : "<unknown>", _TRUNCATE);
                        }
                        ++out.keyCount;
                        lua_pop(L, 1);
                    } else {
                        out.truncated = true;
                        lua_pop(L, 1); // pop value
                        lua_pop(L, 1); // pop key
                        break;
                    }
                }
            }
            lua_pop(L, 1); // loaded
        }
        lua_pop(L, 1); // package
        lua_settop(L, top);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeHasDebugTraceback(lua_State* L, bool& outIsTable, bool& outHasTraceback, DWORD* outSeh) noexcept {
    if (!L)
        return false;
    __try {
        int top = lua_gettop(L);
        lua_getglobal(L, "debug");
        int debugType = lua_type(L, -1);
        outIsTable = (debugType == LUA_TTABLE);
        outHasTraceback = false;
        if (outIsTable) {
            lua_getfield(L, -1, "traceback");
            outHasTraceback = (lua_type(L, -1) == LUA_TFUNCTION);
            lua_pop(L, 1);
        }
        lua_settop(L, top);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static void LogLuaQ(const char* fmt, ...) {
    char payload[512];
    va_list args;
    va_start(args, fmt);
    vsprintf_s(payload, sizeof(payload), fmt, args);
    va_end(args);
    Log::Logf("[LuaQ] %s", payload);
}

static void LogLuaState(const char* fmt, ...) {
    char payload[512];
    va_list args;
    va_start(args, fmt);
    vsprintf_s(payload, sizeof(payload), fmt, args);
    va_end(args);
    Log::Logf("[LuaState] %s", payload);
}

static void LogLuaBind(const char* fmt, ...) {
    char payload[512];
    va_list args;
    va_start(args, fmt);
    vsprintf_s(payload, sizeof(payload), fmt, args);
    va_end(args);
    Log::Logf("[LuaBind] %s", payload);
}

static void LogLuaProbe(const char* fmt, ...) {
    char payload[512];
    va_list args;
    va_start(args, fmt);
    vsprintf_s(payload, sizeof(payload), fmt, args);
    va_end(args);
    Log::Logf("[LuaProbe] %s", payload);
}

static const char* FormatCppExceptionDetail(const char* tag, const char* value) {
    if (!value || !*value)
        value = "unknown";
    if (tag && *tag)
        sprintf_s(g_cppExceptionDetail, sizeof(g_cppExceptionDetail), "%s=%s", tag, value);
    else
        sprintf_s(g_cppExceptionDetail, sizeof(g_cppExceptionDetail), "%s", value);
    return g_cppExceptionDetail;
}

static std::string DescribeFlags(uint32_t flags) {
    std::vector<std::string> parts;
    if (flags & STATE_FLAG_PANIC_OK) {
        parts.emplace_back("PANIC_OK");
    } else if (flags & STATE_FLAG_PANIC_MISS) {
        parts.emplace_back("PANIC_MISS");
    } else {
        parts.emplace_back("PANIC_UNKNOWN");
    }

    if (flags & STATE_FLAG_DEBUG_OK) {
        parts.emplace_back("DEBUG_OK");
    } else if (flags & STATE_FLAG_DEBUG_MISS) {
        parts.emplace_back("DEBUG_MISS");
    } else {
        parts.emplace_back("DEBUG_UNKNOWN");
    }

    if (flags & STATE_FLAG_VALID)
        parts.emplace_back("VALID");
    else
        parts.emplace_back("NO_CANON");

    if (flags & STATE_FLAG_QUARANTINED)
        parts.emplace_back("QUAR");

    if (flags & STATE_FLAG_HELPERS)
        parts.emplace_back("HELPERS_SEEN");

    if (flags & STATE_FLAG_HELPERS_BOUND)
        parts.emplace_back("BOUND");
    else
        parts.emplace_back("UNBOUND");

    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i)
            out.push_back('|');
        out += parts[i];
    }
    return out;
}

static bool EnsureCanonicalLocked(LuaStateInfo& state, uint64_t now, const char* sourceTag) {
    const char* tag = (sourceTag && *sourceTag) ? sourceTag : "unknown";

    if (state.L_canonical) {
        state.flags |= STATE_FLAG_VALID;
        state.flags &= ~STATE_FLAG_QUARANTINED;
        state.probe_failures = 0;
        state.next_probe_ms = now;
        return true;
    }

    if (state.next_probe_ms && now < state.next_probe_ms)
        return false;

    auto markSuccess = [&](lua_State* canonical, const char* mode) {
        state.L_canonical = canonical;
        state.flags |= STATE_FLAG_VALID;
        state.flags &= ~STATE_FLAG_QUARANTINED;
        state.probe_failures = 0;
        state.next_probe_ms = now;
        if (mode)
            LogLuaState("probe-ok %s Lc=%p source=%s", mode, canonical, tag);
        else
            LogLuaState("probe-ok Lc=%p source=%s", canonical, tag);
        return true;
    };

    if (state.L_reported) {
        if (ProbeLua(state.L_reported))
            return markSuccess(state.L_reported, "reported");

        if (state.ctx_reported) {
            LogLuaState("probe-failed L=%p source=%s -> trying ctx=%p", state.L_reported, tag, state.ctx_reported);
        } else {
            LogLuaState("probe-failed L=%p source=%s", state.L_reported, tag);
        }
    }

    if (state.ctx_reported) {
        lua_State* ctxCandidate = reinterpret_cast<lua_State*>(state.ctx_reported);
        if (ProbeLua(ctxCandidate))
            return markSuccess(ctxCandidate, "ctx-as-canonical");
        LogLuaState("probe-failed ctx=%p source=%s", state.ctx_reported, tag);
    }

    state.flags &= ~STATE_FLAG_VALID;
    state.flags |= STATE_FLAG_QUARANTINED;
    state.probe_failures = std::min<uint32_t>(state.probe_failures + 1, 4u);
    const uint32_t exponent = state.probe_failures ? state.probe_failures - 1 : 0;
    uint32_t backoff = kProbeInitialBackoffMs << exponent;
    if (backoff > kProbeMaxBackoffMs)
        backoff = kProbeMaxBackoffMs;
    state.next_probe_ms = now + backoff;
    return false;
}

static LuaStateInfo RefreshCanonical(lua_State* lookupPtr, const char* sourceTag, bool fromHelper, bool* outReady, bool* outCoalesced) {
    LuaStateInfo snapshot{};
    bool ready = false;
    const uint64_t now = GetTickCount64();

    bool updated = g_stateRegistry.UpdateByPointer(lookupPtr, [&](LuaStateInfo& state) {
        if (fromHelper)
            state.flags |= STATE_FLAG_HELPERS;
        ready = EnsureCanonicalLocked(state, now, sourceTag);
        snapshot = state;
    }, &snapshot);

    bool coalesced = false;
    if (updated && snapshot.L_canonical) {
        auto merge = g_stateRegistry.MergeByCanonical(snapshot.L_reported, snapshot.ctx_reported, snapshot.L_canonical);
        coalesced = merge.merged;
        snapshot = merge.info;
    }

    if (outReady)
        *outReady = updated && snapshot.L_canonical != nullptr && ready;
    if (outCoalesced)
        *outCoalesced = coalesced;
    return snapshot;
}

static LuaStateInfo ObserveReportedState(lua_State* reported, void* ctx, DWORD tid, uint64_t gen, const char* sourceTag, bool* outIsNew, bool* outReady, bool* outCoalesced) {
    if (!reported)
        return {};

    auto result = g_stateRegistry.AddOrUpdate(reported, ctx, tid, gen);
    if (outIsNew)
        *outIsNew = result.second;
    return RefreshCanonical(reported, sourceTag, false, outReady, outCoalesced);
}

static lua_State* LookupPointerFor(const LuaStateInfo& info) {
    if (info.L_canonical)
        return info.L_canonical;
    if (info.L_reported)
        return info.L_reported;
    if (info.ctx_reported)
        return reinterpret_cast<lua_State*>(info.ctx_reported);
    return nullptr;
}

static LuaStateInfo EnsureHelperState(lua_State* L, const char* helperName, bool* outReady, bool* outCoalesced, bool* outIsNew) {
    if (outReady)
        *outReady = false;
    if (outCoalesced)
        *outCoalesced = false;
    if (outIsNew)
        *outIsNew = false;
    if (!L)
        return {};

    if (lua_State* normalized = NormalizeLuaStatePointer(L)) {
        L = normalized;
    }

    DWORD tid = GetCurrentThreadId();
    uint64_t gen = g_generation.load(std::memory_order_acquire);
    bool isNew = false;
    LuaStateInfo info = g_stateRegistry.EnsureForPointer(L, nullptr, tid, gen, isNew);
    const uint64_t now = GetTickCount64();
    g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
        state.flags |= STATE_FLAG_HELPERS;
        state.last_tid = tid;
        state.last_seen_ms = now;
        state.gen = std::max(state.gen, gen);
        if (state.owner_tid == 0)
            state.owner_tid = tid;
    }, &info);

    if (isNew) {
        LogLuaState("observed L=%p ctx=<unknown> tid=%lu gen=%llu source=helper helper=%s",
                    L,
                    tid,
                    static_cast<unsigned long long>(gen),
                    helperName ? helperName : "<unknown>");
    }

    bool ready = false;
    bool coalesced = false;
    info = RefreshCanonical(L, helperName, true, &ready, &coalesced);

    if (coalesced && info.L_canonical) {
        LogLuaState("coalesced under canonical Lc=%p source=helper helper=%s",
                    info.L_canonical,
                    helperName ? helperName : "<unknown>");
    }

    if (outReady)
        *outReady = ready;
    if (outCoalesced)
        *outCoalesced = coalesced;
    if (outIsNew)
        *outIsNew = isNew;
    return info;
}

static bool TryBuildInspectSummary(lua_State* target, const LuaStateInfo& info, std::string& outSummary, DWORD* outSeh) {
    if (!target)
        return false;

    outSummary.clear();

    int originalTop = 0;
    DWORD probeSeh = 0;
    if (!SafeLuaProbeStack(target, &originalTop, &probeSeh)) {
        if (outSeh)
            *outSeh = probeSeh;
        return false;
    }

    DWORD firstSeh = 0;
    bool ok = true;
    std::vector<std::string> helperEntries;
    helperEntries.reserve(5);

    const char* helpers[] = { kHelperWalkName, kHelperDumpName, kHelperInspectName, kHelperRebindName, kHelperSelfTestName };
    constexpr size_t helperCount = sizeof(helpers) / sizeof(helpers[0]);
    for (size_t i = 0; i < helperCount; ++i) {
        int type = LUA_TNONE;
        const char* typeName = nullptr;
        DWORD helperSeh = 0;
        if (SafeLuaGetGlobalType(target, helpers[i], &type, &typeName, &helperSeh)) {
            std::string entry(helpers[i]);
            entry.push_back(':');
            entry.append(typeName ? typeName : "<unknown>");
            helperEntries.emplace_back(std::move(entry));
        } else {
            if (firstSeh == 0)
                firstSeh = helperSeh;
            ok = false;
            break;
        }
    }

    int debugType = LUA_TNONE;
    const char* debugTypeName = nullptr;
    bool debugHasTraceback = false;
    if (ok) {
        DWORD debugSeh = 0;
        if (SafeLuaGetGlobalType(target, "debug", &debugType, &debugTypeName, &debugSeh)) {
            if (debugType == LUA_TTABLE) {
                bool isTable = false;
                DWORD tracebackSeh = 0;
                if (!SafeHasDebugTraceback(target, isTable, debugHasTraceback, &tracebackSeh)) {
                    if (firstSeh == 0)
                        firstSeh = tracebackSeh;
                    ok = false;
                }
            }
        } else {
            if (firstSeh == 0)
                firstSeh = debugSeh;
            ok = false;
        }
    }

    PackageLoadedSnapshot pkg{};
    if (ok) {
        DWORD pkgSeh = 0;
        if (!SafeSnapshotPackageLoaded(target, pkg, &pkgSeh)) {
            if (firstSeh == 0)
                firstSeh = pkgSeh;
            ok = false;
        }
    }

    if (!ok) {
        if (outSeh)
            *outSeh = firstSeh ? firstSeh : probeSeh;
        return false;
    }

    std::string debugInfo = "debug=";
    debugInfo.append(debugTypeName ? debugTypeName : "<unknown>");
    if (debugType == LUA_TTABLE)
        debugInfo.append(debugHasTraceback ? "(traceback)" : "(no-traceback)");

    std::string packageInfo = "package=";
    packageInfo.append(pkg.packageType[0] ? pkg.packageType : "<unknown>");
    packageInfo.append(" loaded=");
    packageInfo.append(pkg.loadedType[0] ? pkg.loadedType : "<unknown>");
    if (pkg.loadedValid) {
        std::vector<std::string> keys;
        keys.reserve(pkg.keyCount);
        for (size_t i = 0; i < pkg.keyCount; ++i) {
            keys.emplace_back(pkg.keys[i][0] ? pkg.keys[i] : "<unknown>");
        }
        packageInfo.append(" keys=[");
        if (!keys.empty())
            packageInfo.append(JoinStrings(keys, ", "));
        if (pkg.truncated) {
            if (!keys.empty())
                packageInfo.append(", ");
            packageInfo.append("...");
        }
        packageInfo.push_back(']');
    }

    std::string summary;
    summary.reserve(256);
    lua_State* canonical = info.L_canonical ? info.L_canonical : target;
    summary.append("Lc=");
    AppendPointer(summary, canonical);
    summary.append(" (Lr=");
    AppendPointer(summary, info.L_reported);
    summary.append(" ctx=");
    AppendPointer(summary, info.ctx_reported);
    summary.push_back(')');
    summary.append(" owner=");
    summary.append(std::to_string(info.owner_tid));
    summary.append(" last=");
    summary.append(std::to_string(info.last_tid));
    summary.append(" gen=");
    summary.append(std::to_string(info.gen));
    summary.append(" flags=");
    summary.append(DescribeFlags(info.flags));
    summary.append(" counters=");
    summary.append(std::to_string(info.hook_call_count));
    summary.push_back('/');
    summary.append(std::to_string(info.hook_ret_count));
    summary.push_back('/');
    summary.append(std::to_string(info.hook_line_count));
    if (info.flags & STATE_FLAG_QUARANTINED) {
        uint64_t now = GetTickCount64();
        uint64_t wait = (info.next_probe_ms > now) ? (info.next_probe_ms - now) : 0;
        summary.append(" backoff=");
        summary.append(std::to_string(wait));
        summary.append("ms");
    }
    summary.append(" top=");
    summary.append(std::to_string(originalTop));

    summary.append(" helpers=");
    if (!helperEntries.empty())
        summary.append(JoinStrings(helperEntries, ", "));
    else
        summary.append("<none>");

    summary.push_back(' ');
    summary.append(debugInfo);
    summary.push_back(' ');
    summary.append(packageInfo);

    outSummary = std::move(summary);
    if (outSeh)
        *outSeh = 0;
    return true;
}

extern "C" int __cdecl UOW_PanicThunk(lua_State* L) {
    const char* topType = "<unset>";
    __try {
        int top = lua_gettop(L);
        if (top > 0) {
            int type = lua_type(L, -1);
            const char* name = lua_typename(L, type);
            topType = name ? name : "<null>";
        } else {
            topType = "<empty>";
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        topType = "<seh>";
    }
    LogLuaBind("panic-handler-fired L=%p top_type=%s", L, topType);
    return 0;
}

extern "C" void __cdecl UOW_DebugHook(lua_State* L, lua_Debug* ar) {
    if (!L || !ar)
        return;

    switch (ar->event) {
    case LUA_HOOKCALL:
        g_stateRegistry.IncrementHookCounters(L, 1u, 0u, 0u);
        break;
    case LUA_HOOKRET:
    case LUA_HOOKTAILRET:
        g_stateRegistry.IncrementHookCounters(L, 0u, 1u, 0u);
        break;
    case LUA_HOOKLINE:
        g_stateRegistry.IncrementHookCounters(L, 0u, 0u, 1u);
        break;
    default:
        break;
    }
}

static bool SafeLuaProbeStack(lua_State* L, int* outTop, DWORD* outSeh) noexcept {
    if (!L)
        return false;
    __try {
        int top = lua_gettop(L);
        if (outTop)
            *outTop = top;
        lua_settop(L, top);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaSetTop(lua_State* L, int idx, DWORD* outSeh) noexcept {
    if (!L)
        return false;
    __try {
        lua_settop(L, idx);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaAtPanic(lua_State* L, lua_CFunction fn, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_atpanic(L, fn);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaQueryPanic(lua_State* L, lua_CFunction* outPrev, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_CFunction prev = lua_atpanic(L, nullptr);
        if (outPrev)
            *outPrev = prev;
        lua_atpanic(L, prev);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outPrev)
            *outPrev = nullptr;
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaSetHook(lua_State* L, lua_Hook hook, int mask, int count, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        lua_sethook(L, hook, mask, count);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaGetGlobalType(lua_State* L, const char* name, int* outType, const char** outTypeName, DWORD* outSeh) noexcept {
    if (!L || !name)
        return false;
    __try {
        lua_getglobal(L, name);
        int type = lua_type(L, -1);
        if (outType)
            *outType = type;
        if (outTypeName)
            *outTypeName = lua_typename(L, type);
        lua_pop(L, 1);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaGetHook(lua_State* L, lua_Hook* outHook, int* outMask, DWORD* outSeh = nullptr) noexcept {
    if (!L)
        return false;
    __try {
        if (outHook)
            *outHook = lua_gethook(L);
        if (outMask)
            *outMask = lua_gethookmask(L);
        if (outSeh)
            *outSeh = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outHook)
            *outHook = nullptr;
        if (outMask)
            *outMask = 0;
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool SafeLuaDoString(lua_State* L, const char* chunk, DWORD* outSeh = nullptr) noexcept {
    if (!L || !chunk)
        return false;
    __try {
        int rc = luaL_loadstring(L, chunk);
        if (rc == 0)
            rc = lua_pcall(L, 0, LUA_MULTRET, 0);
        if (outSeh)
            *outSeh = 0;
        return rc == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outSeh)
            *outSeh = GetExceptionCode();
        return false;
    }
}

static bool ProbeLua(lua_State* L) {
    if (!L)
        return false;

    DWORD probeSeh = 0;
    return SafeLuaProbeStack(L, nullptr, &probeSeh);
}

static bool AcquireBindingSlot(lua_State* L) {
    std::lock_guard<std::mutex> lock(g_bindingMutex);
    return g_bindingInFlight.insert(L).second;
}

static void ReleaseBindingSlot(lua_State* L) {
    std::lock_guard<std::mutex> lock(g_bindingMutex);
    g_bindingInFlight.erase(L);
}

static ModuleBounds GetLuaPlusModuleBounds() {
    static ModuleBounds cached{};
    static bool cachedReady = false;
    if (cachedReady)
        return cached;

    HMODULE mod = GetModuleHandleA("luaplus_1100.dll");
    if (!mod)
        return ModuleBounds{};

    MODULEINFO info{};
    if (!GetModuleInformation(GetCurrentProcess(), mod, &info, sizeof(info)))
        return ModuleBounds{};

    cached.base = reinterpret_cast<uintptr_t>(info.lpBaseOfDll);
    cached.size = info.SizeOfImage;
    cached.valid = true;
    cachedReady = true;
    return cached;
}

static bool LooksLikeLuaPlusState(void* candidate) {
    if (!candidate)
        return false;
    ModuleBounds bounds = GetLuaPlusModuleBounds();
    if (!bounds.valid)
        return false;

    uintptr_t vtbl = 0;
    __try {
        vtbl = *reinterpret_cast<uintptr_t*>(candidate);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return vtbl >= bounds.base && vtbl < (bounds.base + bounds.size);
}

static LuaStateGetCStateFn ResolveLuaPlusGetCState() {
    if (!g_luaStateGetCState) {
        HMODULE mod = GetModuleHandleA("luaplus_1100.dll");
        if (mod) {
            g_luaStateGetCState = reinterpret_cast<LuaStateGetCStateFn>(
                GetProcAddress(mod, "?GetCState@LuaState@LuaPlus@@QAEPAUlua_State@@XZ"));
        }
    }
    return g_luaStateGetCState;
}

static LuaStateAtPanicFn ResolveLuaPlusAtPanic() {
    if (!g_luaStateAtPanic) {
        HMODULE mod = GetModuleHandleA("luaplus_1100.dll");
        if (mod) {
            g_luaStateAtPanic = reinterpret_cast<LuaStateAtPanicFn>(
                GetProcAddress(mod, "?AtPanic@LuaState@LuaPlus@@QAEP6AHPAUlua_State@@@ZP6AH0@Z@Z"));
        }
    }
    return g_luaStateAtPanic;
}

static lua_State* NormalizeLuaStatePointer(lua_State* candidate) {
    if (!candidate)
        return nullptr;
    void* raw = reinterpret_cast<void*>(candidate);

    auto getCState = ResolveLuaPlusGetCState();
    auto tryGetCState = [&](void* ptr) -> lua_State* {
        if (!ptr || !getCState)
            return nullptr;
        lua_State* actual = nullptr;
        __try {
            actual = getCState(ptr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            actual = nullptr;
        }
        return actual;
    };

    lua_State* actual = nullptr;
    if (LooksLikeLuaPlusState(raw)) {
        actual = tryGetCState(raw);
    } else {
        actual = tryGetCState(raw);
    }

    if (actual && ProbeLua(actual)) {
        g_mainLuaPlusState.store(raw, std::memory_order_release);
        if (actual != candidate) {
            LogLuaProbe("normalized lua state raw=%p c=%p", raw, actual);
        }
        return actual;
    }

    if (ProbeLua(candidate))
        return candidate;

    return nullptr;
}

static void LogLuaQueueDrain(lua_State* L, DWORD tid, const char* outcome, const char* detail = nullptr) {
    LogLuaQ("drain outcome=%s tid=%lu L=%p%s%s",
            outcome ? outcome : "?",
            tid,
            L,
            detail ? " detail=" : "",
            detail ? detail : "");
}

static void MaybeLogQueueDrain(lua_State* L, DWORD tid, const char* detail) {
    DWORD now = GetTickCount();
    DWORD last = g_lastQueueLogTick.load(std::memory_order_relaxed);
    if (now - last < kQueueDrainLogCooldownMs)
        return;
    if (g_lastQueueLogTick.compare_exchange_strong(last, now, std::memory_order_acq_rel)) {
        LogLuaQueueDrain(L, tid, "idle", detail);
    }
}

static void EnsureScriptThread(DWORD tid, lua_State* L) {
    if (!tid)
        return;

    lua_State* normalized = NormalizeLuaStatePointer(L);
    if (normalized)
        L = normalized;

    DWORD expected = 0;
    if (g_scriptThreadId.compare_exchange_strong(expected, tid)) {
        LogLuaQ("tid=%lu script-thread-discovered L=%p", tid, L);
    }

    if (g_scriptThreadId.load(std::memory_order_acquire) == tid && L) {
        lua_State* prev = g_mainLuaState.exchange(L, std::memory_order_acq_rel);
        if (prev != L) {
            LogLuaQ("tid=%lu main-state-updated L=%p (prev=%p)", tid, L, prev);
        }
        if (!g_processingLuaQueue) {
            bool hasPending = false;
            {
                std::lock_guard<std::mutex> lock(g_taskMutex);
                hasPending = !g_taskQueue.empty();
            }
            if (hasPending)
                ProcessPendingLuaTasks(L);
        }
    }
}

static lua_State* ResolveLuaState() {
    if (auto* state = g_mainLuaState.load(std::memory_order_acquire))
        return state;

    void* raw = Engine::LuaState();
    if (!raw)
        return nullptr;

    if (LooksLikeLuaPlusState(raw)) {
        g_mainLuaPlusState.store(raw, std::memory_order_release);
    }

    lua_State* normalized = NormalizeLuaStatePointer(static_cast<lua_State*>(raw));
    if (!normalized)
        normalized = static_cast<lua_State*>(raw);

    g_mainLuaState.store(normalized, std::memory_order_release);
    return normalized;
}

static bool RunLuaTaskWithGuards(lua_State* L, std::function<void(lua_State*)>& fn, const char** outDetail) noexcept {
    struct Runner {
        static bool Execute(lua_State* state, std::function<void(lua_State*)>* func, const char** outDetail) noexcept {
            bool ok = false;
            const char* localDetail = nullptr;
            __try {
                (*func)(state);
                ok = true;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                DWORD code = GetExceptionCode();
                static thread_local char sehDetail[64];
                sprintf_s(sehDetail, sizeof(sehDetail), "seh=0x%08lX", code);
                localDetail = sehDetail;
            }

            if (!ok && outDetail)
                *outDetail = localDetail;
            return ok;
        }
    };

    bool success = false;
    const char* detail = nullptr;
    try {
        success = Runner::Execute(L, &fn, &detail);
    } catch (const std::exception& ex) {
        detail = FormatCppExceptionDetail("cxx", ex.what());
        success = false;
    } catch (...) {
        detail = FormatCppExceptionDetail("cxx", "unknown");
        success = false;
    }

    if (!success && outDetail)
        *outDetail = detail;
    return success;
}

static void ProcessPendingLuaTasks(lua_State* L) {
    DWORD tid = GetCurrentThreadId();
    DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
    if (!scriptTid || tid != scriptTid) {
        MaybeLogQueueDrain(L, tid, "non-script-thread");
        return;
    }

    if (g_processingLuaQueue)
        return;

    std::deque<LuaTask> local;
    {
        std::lock_guard<std::mutex> lock(g_taskMutex);
        if (g_taskQueue.empty()) {
            MaybeLogQueueDrain(L, tid, "empty");
            return;
        }
        local.swap(g_taskQueue);
    }

    g_processingLuaQueue = true;

    if (!g_queueLoggedDuringInit.exchange(true, std::memory_order_acq_rel)) {
        LogLuaQueueDrain(L, tid, "start");
    }

    for (auto& task : local) {
        LogLuaQ("run fn=%s on=tid=%lu start", task.name.c_str(), tid);
        if (!L) {
            LogLuaQ("run fn=%s on=tid=%lu err=lua_state-null", task.name.c_str(), tid);
            continue;
        }

        auto fn = std::move(task.fn);
        bool success = false;
        const char* detail = nullptr;
        success = RunLuaTaskWithGuards(L, fn, &detail);
        if (success) {
            LogLuaQ("run fn=%s on=tid=%lu ok", task.name.c_str(), tid);
        } else {
            LogLuaQ("run fn=%s on=tid=%lu err=%s", task.name.c_str(), tid, detail ? detail : "unknown");
            PostToLuaThread(task.target ? task.target : L, task.name.c_str(), std::move(fn));
        }
    }

    g_processingLuaQueue = false;
    MaybeLogQueueDrain(L, tid, "processed");
}

static void PostToLuaThread(lua_State* L, const char* name, std::function<void(lua_State*)> fn) {
    DWORD fromTid = GetCurrentThreadId();
    {
        std::lock_guard<std::mutex> lock(g_taskMutex);
        g_taskQueue.push_back(LuaTask{ name ? name : "<lambda>", L, std::move(fn) });
    }
    LogLuaQ("post fn=%s L=%p from=tid=%lu", name ? name : "<lambda>", L, fromTid);

    DWORD scriptTid = g_scriptThreadId.load(std::memory_order_acquire);
    if (scriptTid != 0 && scriptTid == fromTid && L && !g_processingLuaQueue) {
        ProcessPendingLuaTasks(L);
    }
}

static bool IsOwnerThread(const LuaStateInfo& info) {
    DWORD owner = info.owner_tid ? info.owner_tid : g_scriptThreadId.load(std::memory_order_acquire);
    return owner != 0 && owner == GetCurrentThreadId();
}

static bool IsOwnerThread(lua_State* L) {
    if (!L)
        return false;
    LuaStateInfo info{};
    if (!g_stateRegistry.GetByPointer(L, info))
        return false;
    return IsOwnerThread(info);
}

static void PostToOwnerWithTask(lua_State* L, const char* taskName, std::function<void()> fn) {
    if (!L || !fn)
        return;

    LuaStateInfo info{};
    bool haveInfo = g_stateRegistry.GetByPointer(L, info);
    DWORD owner = 0;
    if (haveInfo) {
        owner = info.owner_tid ? info.owner_tid : g_scriptThreadId.load(std::memory_order_acquire);
    } else {
        owner = g_scriptThreadId.load(std::memory_order_acquire);
    }

    DWORD from = GetCurrentThreadId();
    const char* name = taskName ? taskName : "<owner>";

    if (owner && owner == from && haveInfo) {
        fn();
        return;
    }

    Log::Logf("[Bind] posted-to-owner L=%p from=%lu -> owner=%lu task=%s", L, from, owner, name);
    PostToLuaThread(L, name, [fn = std::move(fn)](lua_State*) {
        fn();
    });
}

static void PostToOwner(lua_State* L, std::function<void()> fn) {
    PostToOwnerWithTask(L, "<owner>", std::move(fn));
}

static void MaybeRunMaintenance() {
    uint64_t now = GetTickCount64();
    uint64_t last = g_lastMaintenanceTick.load(std::memory_order_relaxed);
    if (now - last < kMaintenanceIntervalMs)
        return;
    if (!g_lastMaintenanceTick.compare_exchange_strong(last, now, std::memory_order_acq_rel))
        return;

    auto snapshot = g_stateRegistry.Snapshot();
    uint64_t generation = g_generation.load(std::memory_order_acquire);
    for (const auto& info : snapshot) {
        if (!(info.flags & STATE_FLAG_HELPERS_BOUND) || info.gen != generation) {
            RequestBindForState(info, "maintenance", false);
        }
    }
}

static void RequestBindForState(const LuaStateInfo& info, const char* reason, bool force) {
    const char* action = reason ? reason : "unspecified";
    LuaStateInfo current = info;

    lua_State* lookupPtr = LookupPointerFor(current);
    if (!lookupPtr) {
        LogLuaState("bind-skip Lr=%p ctx=%p reason=no-pointer action=%s",
                    current.L_reported,
                    current.ctx_reported,
                    action);
        return;
    }

    bool canonicalReady = current.L_canonical != nullptr;
    if (!canonicalReady) {
        bool ready = false;
        bool coalesced = false;
        current = RefreshCanonical(lookupPtr, action, false, &ready, &coalesced);
        canonicalReady = ready && current.L_canonical != nullptr;
    }

    if (!canonicalReady || !current.L_canonical) {
        uint64_t now = GetTickCount64();
        uint64_t waitMs = (current.next_probe_ms > now) ? (current.next_probe_ms - now) : 0;
        LogLuaState("bind-skip Lr=%p ctx=%p reason=no-canonical wait=%llu action=%s",
                    current.L_reported,
                    current.ctx_reported,
                    static_cast<unsigned long long>(waitMs),
                    action);
        return;
    }

    lua_State* target = current.L_canonical;
    uint64_t generation = g_generation.load(std::memory_order_acquire);
    DWORD owner = current.owner_tid ? current.owner_tid : g_scriptThreadId.load(std::memory_order_acquire);

    if (owner && owner == GetCurrentThreadId()) {
        BindHelpersTask(target, generation, force, action);
    } else {
        std::string reasonCopy = action;
        PostToOwnerWithTask(target, "helpers", [target, generation, force, reasonCopy]() {
            BindHelpersTask(target, generation, force, reasonCopy.c_str());
        });
    }
}

static void InstallPanicAndDebug(lua_State* L, LuaStateInfo& info) {
    if (!L)
        return;

    if (!IsOwnerThread(info)) {
        PostToOwnerWithTask(L, "panic&debug", [L]() {
            LuaStateInfo refreshed{};
            if (g_stateRegistry.GetByPointer(L, refreshed))
                InstallPanicAndDebug(L, refreshed);
        });
        return;
    }

    lua_State* mainState = g_mainLuaState.load(std::memory_order_acquire);
    if (mainState && mainState != L)
        return;

    if (!ProbeLua(L))
        return;

    DWORD panicSeh = 0;
    bool panicOk = SafeLuaAtPanic(L, UOW_PanicThunk, &panicSeh);

    DWORD debugSeh = 0;
    bool debugOk = SafeLuaSetHook(L, UOW_DebugHook, LUA_MASKCALL | LUA_MASKRET | LUA_MASKLINE, 0, &debugSeh);

    bool logPanic = false;
    bool logDebug = false;
    g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
        if (panicOk) {
            state.flags |= STATE_FLAG_PANIC_OK;
            state.flags &= ~STATE_FLAG_PANIC_MISS;
        } else {
            state.flags |= STATE_FLAG_PANIC_MISS;
            state.flags &= ~STATE_FLAG_PANIC_OK;
        }

        if (debugOk) {
            state.flags |= STATE_FLAG_DEBUG_OK;
            state.flags &= ~STATE_FLAG_DEBUG_MISS;
        } else {
            state.flags |= STATE_FLAG_DEBUG_MISS;
            state.flags &= ~STATE_FLAG_DEBUG_OK;
        }

        int panicStatus = panicOk ? 1 : 0;
        if (state.panic_status_gen != state.gen || state.panic_status != panicStatus) {
            state.panic_status_gen = state.gen;
            state.panic_status = panicStatus;
            logPanic = true;
        }
        int debugStatus = debugOk ? 1 : 0;
        if (state.debug_status_gen != state.gen || state.debug_status != debugStatus) {
            state.debug_status_gen = state.gen;
            state.debug_status = debugStatus;
            logDebug = true;
        }
        info = state;
    }, &info);

    if (logPanic) {
        if (panicOk) {
            LogLuaBind("ok name=panic-handler L=%p", L);
        } else {
            LogLuaBind("fail name=panic-handler L=%p reason=seh=0x%08lX", L, panicSeh);
        }
    }

    if (logDebug) {
        if (debugOk) {
            LogLuaBind("ok name=debug-hook L=%p", L);
        } else {
            LogLuaBind("fail name=debug-hook L=%p reason=seh=0x%08lX", L, debugSeh);
        }
    }
}

static bool RegisterHelper(lua_State* L, const LuaStateInfo& info, const char* name, lua_CFunction fn, uint64_t generation) {
    bool registered = false;
    DWORD seh = 0;

    if (g_clientRegister && info.ctx_reported) {
        __try {
            g_clientRegister(info.ctx_reported, reinterpret_cast<void*>(fn), name);
            registered = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            seh = GetExceptionCode();
            registered = false;
            LogLuaBind("fail name=%s L=%p reason=register-call-exception seh=0x%08lX ctx=%p", name, L, seh, info.ctx_reported);
        }
    }

    if (!registered) {
        __try {
            lua_pushcfunction(L, fn);
            lua_setglobal(L, name);
            registered = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            seh = GetExceptionCode();
            registered = false;
            LogLuaBind("fail name=%s L=%p reason=fallback-exception seh=0x%08lX", name, L, seh);
        }
    }

    if (registered) {
        LogLuaBind("ok name=%s L=%p ctx=%p tid=%lu gen=%llu", name, L, info.ctx_reported, info.owner_tid, generation);
    }
    return registered;
}

static bool BindHelpersOnThread(lua_State* L, const LuaStateInfo& originalInfo, uint64_t generation, bool force) {
    if (!L)
        return false;

    LuaStateInfo info = originalInfo;

    if (!IsOwnerThread(info))
        return false;

    if (!ProbeLua(L))
        return false;

    g_stateRegistry.GetByPointer(L, info);

    bool ok = true;
    bool helpersBound = (info.flags & STATE_FLAG_HELPERS_BOUND) && info.gen == generation;
    if (force || !helpersBound) {
        bool walkOk = RegisterHelper(L, info, kHelperWalkName, Lua_UOWalk, generation);
        bool dumpOk = RegisterHelper(L, info, kHelperDumpName, Lua_UOWDump, generation);
        bool inspectOk = RegisterHelper(L, info, kHelperInspectName, Lua_UOWInspect, generation);
        bool rebindOk = RegisterHelper(L, info, kHelperRebindName, Lua_UOWRebindAll, generation);
        bool selfTestOk = RegisterHelper(L, info, kHelperSelfTestName, Lua_UOWSelfTest, generation);
        bool allOk = walkOk && dumpOk && inspectOk && rebindOk && selfTestOk;
        if (allOk) {
            g_stateRegistry.UpdateByPointer(L, [&](LuaStateInfo& state) {
                state.flags |= STATE_FLAG_HELPERS_BOUND;
                state.gen = generation;
            }, &info);
        } else {
            ok = false;
        }
    }

    InstallPanicAndDebug(L, info);
    return ok;
}

static void BindHelpersTask(lua_State* L, uint64_t generation, bool force, const char* reason) {
    if (!L)
        return;

    LuaStateInfo info{};
    if (!g_stateRegistry.GetByPointer(L, info)) {
        LogLuaState("bind-skip Lc=%p reason=state-missing action=%s", L, reason ? reason : "unknown");
        return;
    }

    if (!IsOwnerThread(info)) {
        std::string reasonCopy = reason ? reason : "unknown";
        PostToOwnerWithTask(L, "helpers", [L, generation, force, reasonCopy]() {
            BindHelpersTask(L, generation, force, reasonCopy.c_str());
        });
        return;
    }

    uint64_t now = GetTickCount64();
    if ((info.flags & STATE_FLAG_QUARANTINED) && info.next_probe_ms && now < info.next_probe_ms) {
        LogLuaState("bind-skip Lc=%p reason=quarantined wait=%llu", L,
                    static_cast<unsigned long long>(info.next_probe_ms - now));
        return;
    }

    if (!force && (info.flags & STATE_FLAG_HELPERS_BOUND) && info.gen == generation) {
        InstallPanicAndDebug(L, info);
        return;
    }

    if (!AcquireBindingSlot(L)) {
        LogLuaState("bind-skip Lc=%p reason=in-progress", L);
        return;
    }

    LogLuaState("bind-start Lc=%p (Lr=%p ctx=%p) tid=%lu gen=%llu reason=%s",
                L,
                info.L_reported,
                info.ctx_reported,
                info.owner_tid,
                static_cast<unsigned long long>(generation),
                reason ? reason : "unknown");

    bool ok = BindHelpersOnThread(L, info, generation, force);
    ReleaseBindingSlot(L);
    if (!ok) {
        LogLuaState("bind-fail Lc=%p ctx=%p gen=%llu", L, info.ctx_reported, static_cast<unsigned long long>(generation));
    } else {
        LogLuaState("bind-done Lc=%p ctx=%p gen=%llu", L, info.ctx_reported, static_cast<unsigned long long>(generation));
    }
}

static void ForceRebindAll(const char* reason) {
    uint64_t newGen = g_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    LogLuaState("force-rebind gen=%llu reason=%s", newGen, reason ? reason : "manual");
    g_stateRegistry.ClearFlagsAll(STATE_FLAG_HELPERS_BOUND);
    auto snapshot = g_stateRegistry.Snapshot();
    for (const auto& info : snapshot) {
        RequestBindForState(info, reason ? reason : "force", true);
    }
}

static void DumpWalkEnv(lua_State* L, const char* reason) {
    if (!L)
        return;
    const char* names[] = { "walk", "bindWalk" };
    for (const char* name : names) {
        lua_getglobal(L, name);
        int type = lua_type(L, -1);
        const char* typeName = lua_typename(L, type);
        const void* ptr = lua_topointer(L, -1);
        int upCount = 0;
        if (type == LUA_TFUNCTION && !lua_iscfunction(L, -1)) {
            int funcIndex = lua_gettop(L);
            while (lua_getupvalue(L, funcIndex, upCount + 1) != nullptr) {
                ++upCount;
                lua_pop(L, 1);
            }
        }
        LogLuaProbe("%s env type=%s ptr=%p upvalues=%d reason=%s",
                    name,
                    typeName ? typeName : "?",
                    ptr,
                    upCount,
                    reason ? reason : "manual");
        lua_pop(L, 1);
    }
}

static int Lua_UOWDump(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    EnsureHelperState(L, kHelperDumpName, &ready, &coalesced, nullptr);
    DumpWalkEnv(L, "uow_dump_walk_env");
    return 0;
}

static int Lua_UOWalk(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    EnsureHelperState(L, kHelperWalkName, &ready, &coalesced, nullptr);
    int argc = lua_gettop(L);
    if (argc < 1 || !lua_isnumber(L, 1)) {
        LogLuaProbe("uow_walk invalid dir parameter");
        lua_pushboolean(L, 0);
        return 1;
    }

    int dir = static_cast<int>(lua_tointeger(L, 1));
    int run = 0;
    if (argc >= 2) {
        if (lua_isnumber(L, 2)) {
            run = lua_tointeger(L, 2) != 0 ? 1 : 0;
        } else {
            int type = lua_type(L, 2);
            if (type == LUA_TBOOLEAN) {
                run = lua_toboolean(L, 2) ? 1 : 0;
            } else {
                LogLuaProbe("uow_walk run parameter ignored (unsupported type)");
                run = 0;
            }
        }
    }
    bool ok = SendWalk(dir, run);
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

static int Lua_UOWInspect(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    int callerTop = 0;
    bool callerTopValid = SafeLuaProbeStack(L, &callerTop, nullptr);
    bool ready = false;
    bool coalesced = false;
    LuaStateInfo info = EnsureHelperState(L, kHelperInspectName, &ready, &coalesced, nullptr);

    auto finalize = [&](bool ok) -> int {
        if (callerTopValid) {
            DWORD restoreSeh = 0;
            if (!SafeLuaSetTop(L, callerTop, &restoreSeh)) {
                LogLuaState("inspect restore-seh L=%p code=0x%08lX", L, restoreSeh);
                ok = false;
            }
        }
        lua_pushboolean(L, ok ? 1 : 0);
        return 1;
    };

    if (!ready || !info.L_canonical) {
        LogLuaState("inspect abort L=%p reason=no-canonical ready=%d flags=0x%08X",
                    L,
                    ready ? 1 : 0,
                    info.flags);
        return finalize(false);
    }

    lua_State* target = info.L_canonical ? info.L_canonical : L;
    std::string summary;
    DWORD seh = 0;
    bool summaryOk = TryBuildInspectSummary(target, info, summary, &seh);

    if (!summaryOk) {
        LogLuaState("inspect-seh Lc=%p code=0x%08lX", target, seh);
        return finalize(false);
    }

    LogLuaState("inspect %s", summary.c_str());

    uint64_t now = GetTickCount64();
    auto snapshot = g_stateRegistry.Snapshot();
    for (const auto& entry : snapshot) {
        uint64_t wait = (entry.flags & STATE_FLAG_QUARANTINED) && entry.next_probe_ms > now
                            ? (entry.next_probe_ms - now)
                            : 0;
        std::string extra = wait ? (" backoff=" + std::to_string(wait) + "ms") : std::string();
        LogLuaState("entry Lc=%p (Lr=%p ctx=%p) owner=%lu last=%lu gen=%llu flags=%s counters=%u/%u/%u%s",
                    entry.L_canonical,
                    entry.L_reported,
                    entry.ctx_reported,
                    entry.owner_tid,
                    entry.last_tid,
                    static_cast<unsigned long long>(entry.gen),
                    DescribeFlags(entry.flags).c_str(),
                    entry.hook_call_count,
                    entry.hook_ret_count,
                    entry.hook_line_count,
                    extra.c_str());
    }

    return finalize(true);
}

static int Lua_UOWSelfTest(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    EnsureHelperState(L, kHelperSelfTestName, &ready, &coalesced, nullptr);

    LuaStateInfo info{};
    if (!g_stateRegistry.GetByPointer(L, info)) {
        lua_pushstring(L, "state-missing");
        return 1;
    }

    if (!IsOwnerThread(info)) {
        lua_pushstring(L, "wrong-thread");
        return 1;
    }

    if (!ProbeLua(L)) {
        lua_pushstring(L, "probe-failed");
        return 1;
    }

    bool panicOk = false;
    bool debugOk = false;
    bool runOk = false;
    DWORD panicSeh = 0;
    DWORD debugSeh = 0;
    DWORD runSeh = 0;

    lua_CFunction prevPanic = nullptr;
    if (SafeLuaQueryPanic(L, &prevPanic, &panicSeh)) {
        panicOk = (prevPanic == UOW_PanicThunk);
    } else {
        panicOk = false;
    }

    lua_Hook hook = nullptr;
    int hookMask = 0;
    if (SafeLuaGetHook(L, &hook, &hookMask, &debugSeh)) {
        debugOk = (hook == UOW_DebugHook) &&
                  ((hookMask & (LUA_MASKCALL | LUA_MASKRET | LUA_MASKLINE)) == (LUA_MASKCALL | LUA_MASKRET | LUA_MASKLINE));
    } else {
        debugOk = false;
    }

    int top = 0;
    SafeLuaProbeStack(L, &top, nullptr);
    DWORD dostringSeh = 0;
    if (SafeLuaDoString(L, "return 1+1", &dostringSeh)) {
        int newTop = lua_gettop(L);
        if (newTop > top && lua_isnumber(L, -1) && lua_tointeger(L, -1) == 2) {
            runOk = true;
        }
    } else if (dostringSeh) {
        runSeh = dostringSeh;
    }
    DWORD restoreSeh = 0;
    if (!SafeLuaSetTop(L, top, &restoreSeh) && restoreSeh && !runSeh)
        runSeh = restoreSeh;

    Log::Logf("[SelfTest] L=%p panic=%s debug=%s run=%s",
              L,
              panicOk ? "ok" : "fail",
              debugOk ? "ok" : "fail",
              runOk ? "ok" : "fail");

    std::ostringstream oss;
    oss << "panic=" << (panicOk ? "ok" : "fail");
    if (!panicOk && panicSeh) {
        char buf[16];
        sprintf_s(buf, sizeof(buf), "0x%08lX", panicSeh);
        oss << "(seh=" << buf << ")";
    }
    oss << " debug=" << (debugOk ? "ok" : "fail");
    if (!debugOk && debugSeh) {
        char buf[16];
        sprintf_s(buf, sizeof(buf), "0x%08lX", debugSeh);
        oss << "(seh=" << buf << ")";
    }
    oss << " run=" << (runOk ? "ok" : "fail");
    if (!runOk && runSeh) {
        char buf[16];
        sprintf_s(buf, sizeof(buf), "0x%08lX", runSeh);
        oss << "(seh=" << buf << ")";
    }

    std::string summary = oss.str();
    lua_pushstring(L, summary.c_str());
    return 1;
}

static int Lua_UOWRebindAll(lua_State* L) {
    EnsureScriptThread(GetCurrentThreadId(), L);
    bool ready = false;
    bool coalesced = false;
    EnsureHelperState(L, kHelperRebindName, &ready, &coalesced, nullptr);
    ForceRebindAll("lua-command");
    lua_pushboolean(L, 1);
    return 1;
}

static bool ResolveRegisterFunction() {
    if (g_registerResolved.load(std::memory_order_acquire))
        return true;

    void* addr = Engine::FindRegisterLuaFunction();
    if (!addr) {
        LogLuaProbe("resolve-register failed");
        return false;
    }

    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        LogLuaProbe("MH_Initialize failed");
        return false;
    }

    if (MH_CreateHook(addr, &Hook_Register, reinterpret_cast<LPVOID*>(&g_origRegister)) != MH_OK ||
        MH_EnableHook(addr) != MH_OK) {
        LogLuaProbe("hook installation failed");
        g_origRegister = nullptr;
        return false;
    }

    g_registerTarget = addr;
    g_clientRegister = g_origRegister;
    g_registerResolved.store(true, std::memory_order_release);
    LogLuaProbe("register-hook-installed target=%p", addr);
    return true;
}

static int __stdcall Hook_Register(void* ctx, void* func, const char* name) {
    DWORD tid = GetCurrentThreadId();
    lua_State* fromCtx = nullptr;
    lua_State* resolved = ResolveLuaState();
    if (ctx) {
        fromCtx = NormalizeLuaStatePointer(reinterpret_cast<lua_State*>(ctx));
        if (!ProbeLua(fromCtx))
            fromCtx = nullptr;
    }
    if (!ProbeLua(resolved))
        resolved = nullptr;

    lua_State* L = resolved ? resolved : fromCtx;
    if (!L)
        L = fromCtx;

    EnsureScriptThread(tid, L);

    LogLuaProbe("register name=%s fn=%p ctx=%p tid=%lu", name ? name : "<null>", func, ctx, tid);

    if (ctx && ctx != g_engineContext.load(std::memory_order_acquire)) {
        g_engineContext.store(ctx, std::memory_order_release);
    }
    if (ctx)
        g_latestScriptCtx.store(ctx, std::memory_order_release);

    if (L) {
        uint64_t gen = g_generation.load(std::memory_order_acquire);
        bool isNew = false;
        bool ready = false;
        bool coalesced = false;
        LuaStateInfo snapshot = ObserveReportedState(L, ctx, tid, gen, name ? name : "register", &isNew, &ready, &coalesced);
        if (isNew) {
            LogLuaState("observed L=%p ctx=%p tid=%lu gen=%llu source=register", snapshot.L_reported, ctx, tid, gen);
        }
        if (!name || _stricmp(name, kHelperWalkName) != 0) {
            RequestBindForState(snapshot, name ? name : "register", false);
        }
    }

    int rc = g_clientRegister ? g_clientRegister(ctx, func, name) : 0;
    return rc;
}

} // namespace

namespace Engine::Lua {

bool InitLuaBridge() {
    g_stateRegistry.Reset();
    g_generation.store(1, std::memory_order_release);
    g_lastMaintenanceTick.store(GetTickCount64(), std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(g_taskMutex);
        g_taskQueue.clear();
    }
    g_queueLoggedDuringInit.store(false, std::memory_order_release);
    g_bindingInFlight.clear();
    LogLuaState("registry-init ok cap=32");
    if (!ResolveRegisterFunction())
        return false;
    ScheduleWalkBinding();
    return true;
}

void ShutdownLuaBridge() {
    if (g_registerTarget) {
        MH_DisableHook(g_registerTarget);
        MH_RemoveHook(g_registerTarget);
        g_registerTarget = nullptr;
    }
    g_origRegister = nullptr;
    g_clientRegister = nullptr;
    g_registerResolved.store(false, std::memory_order_release);

    {
        std::lock_guard<std::mutex> lock(g_taskMutex);
        g_taskQueue.clear();
    }

    g_bindingInFlight.clear();
    g_stateRegistry.Reset();
    g_mainLuaState.store(nullptr, std::memory_order_release);
    g_mainLuaPlusState.store(nullptr, std::memory_order_release);
    g_scriptThreadId.store(0, std::memory_order_release);
    g_engineContext.store(nullptr, std::memory_order_release);
    g_latestScriptCtx.store(nullptr, std::memory_order_release);
}

void RegisterOurLuaFunctions() {
    ScheduleWalkBinding();
}

void UpdateEngineContext(void* context) {
    g_engineContext.store(context, std::memory_order_release);
    LogLuaProbe("engine-context=%p", context);
    ScheduleWalkBinding();
}

void EnsureWalkBinding(const char* /*reason*/) {
    ScheduleWalkBinding();
}

void ScheduleWalkBinding() {
    auto snapshot = g_stateRegistry.Snapshot();
    if (snapshot.empty()) {
        lua_State* existing = ResolveLuaState();
        if (existing) {
            uint64_t gen = g_generation.load(std::memory_order_acquire);
            DWORD tid = g_scriptThreadId.load(std::memory_order_acquire);
            void* ctx = g_latestScriptCtx.load(std::memory_order_acquire);
            bool isNew = false;
            bool ready = false;
            bool coalesced = false;
            LuaStateInfo info = ObserveReportedState(existing, ctx, tid, gen, "schedule", &isNew, &ready, &coalesced);
            snapshot.push_back(info);
        }
    }

    for (const auto& info : snapshot) {
        RequestBindForState(info, "schedule", false);
    }
}

void ProcessLuaQueue() {
    lua_State* L = ResolveLuaState();
    EnsureScriptThread(GetCurrentThreadId(), L);
    ProcessPendingLuaTasks(L);
    MaybeRunMaintenance();
}

void OnStateObserved(lua_State* L, void* scriptCtx, std::uint32_t ownerTid) {
    if (!L)
        return;
    uint64_t gen = g_generation.load(std::memory_order_acquire);
    DWORD tid = ownerTid ? ownerTid : GetCurrentThreadId();
    EnsureScriptThread(tid, L);
    if (scriptCtx)
        g_latestScriptCtx.store(scriptCtx, std::memory_order_release);

    bool isNew = false;
    bool ready = false;
    bool coalesced = false;
    LuaStateInfo snapshot = ObserveReportedState(L, scriptCtx, tid, gen, "external", &isNew, &ready, &coalesced);
    if (isNew) {
        LogLuaState("observed L=%p ctx=%p tid=%lu gen=%llu source=external", snapshot.L_reported, scriptCtx, tid, gen);
    }
    RequestBindForState(snapshot, "state-observed", false);
}

void OnStateRemoved(lua_State* L, const char* reason) {
    if (!L)
        return;
    LuaStateInfo info{};
    if (g_stateRegistry.RemoveByPointer(L, &info)) {
        LogLuaState("removed Lc=%p (Lr=%p ctx=%p) tid=%lu reason=%s",
                    info.L_canonical ? info.L_canonical : L,
                    info.L_reported,
                    info.ctx_reported,
                    info.owner_tid,
                    reason ? reason : "unknown");
    }
}



} // namespace Engine::Lua




