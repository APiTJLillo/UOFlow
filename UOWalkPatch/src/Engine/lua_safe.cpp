#include "Engine/lua_safe.h"

#include <windows.h>

#include "Engine/GlobalState.hpp"
#include "Engine/LuaStateRegistry.hpp"

extern "C" {
    int lua_gettop(lua_State* L);
    void lua_settop(lua_State* L, int idx);
}

namespace Engine::Lua {

lua_State* GetCanonicalStateRelaxed() noexcept;
DWORD GetScriptThreadIdHint() noexcept;

namespace {

constexpr int kMaxReasonableLuaTop = 1'000'000;
constexpr uint32_t kStateFlagValid = 1u << 2;

thread_local LuaGuardFailure g_lastFailure = LuaGuardFailure::None;
thread_local DWORD g_lastSehCode = 0;

void SetFailure(LuaGuardFailure reason) noexcept {
    g_lastFailure = reason;
}

void ClearFailure() noexcept {
    g_lastFailure = LuaGuardFailure::None;
    g_lastSehCode = 0;
}

bool CheckThreadOwnership(const LuaStateInfo& info) noexcept {
    DWORD tid = GetCurrentThreadId();
    DWORD owner = info.owner_tid;
    DWORD script = GetScriptThreadIdHint();

    if (owner && owner == tid)
        return true;
    if (!owner && script == tid)
        return true;
    if (owner && owner != tid) {
        return script && script == tid;
    }
    return script && script == tid;
}

bool IsStackTopPlausible(int top) noexcept {
    return top >= 0 && top <= kMaxReasonableLuaTop;
}

} // namespace

LuaGuardFailure GetLastLuaGuardFailure() noexcept {
    return g_lastFailure;
}

DWORD GetLastLuaGuardSehCode() noexcept {
    return g_lastSehCode;
}

bool IsProbablyReadable(const void* p, size_t bytes) noexcept {
    if (!p || bytes == 0)
        return false;

    const volatile unsigned char* data = static_cast<const volatile unsigned char*>(p);
    volatile unsigned char guard = 0;
    size_t step = bytes / 8;
    if (step == 0)
        step = 1;

    __try {
        for (size_t i = 0; i < bytes; i += step)
            guard ^= data[i];
        guard ^= data[bytes - 1];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    (void)guard;
    return true;
}

bool ValidateLuaStateShallow(lua_State* L, uintptr_t expectedGlobal) noexcept {
    if (!L)
        return false;
    if (!IsProbablyReadable(L, sizeof(void*) * 8))
        return false;
    if (expectedGlobal) {
        const GlobalStateInfo* info = Engine::Info();
        if (!info || reinterpret_cast<uintptr_t>(info) != expectedGlobal)
            return false;
        if (info->luaState && info->luaState != L)
            return false;
    }
    return true;
}

bool IsOkToTouchVM(lua_State* L, const LuaStateInfo& info) noexcept {
    if (!L) {
        SetFailure(LuaGuardFailure::CanonMismatch);
        return false;
    }
    if (!(info.flags & kStateFlagValid)) {
        SetFailure(LuaGuardFailure::CanonMismatch);
        return false;
    }
    if (!info.L_canonical || info.L_canonical != L) {
        SetFailure(LuaGuardFailure::CanonMismatch);
        return false;
    }

    lua_State* canonical = GetCanonicalStateRelaxed();
    if (canonical && canonical != L) {
        SetFailure(LuaGuardFailure::CanonMismatch);
        return false;
    }

    uint32_t cookie = Engine::GlobalStateCookie();
    if (!cookie || info.gc_gen != cookie) {
        SetFailure(LuaGuardFailure::GenerationMismatch);
        return false;
    }

    if (!CheckThreadOwnership(info)) {
        SetFailure(LuaGuardFailure::OwnerMismatch);
        return false;
    }

    if (!ValidateLuaStateShallow(L, info.expected_global)) {
        SetFailure(LuaGuardFailure::ReadCheckFailed);
        return false;
    }

    ClearFailure();
    return true;
}

LuaTopRes safe_lua_gettop(lua_State* L, const LuaStateInfo& info) noexcept {
    LuaTopRes res{};
    if (!IsOkToTouchVM(L, info))
        return res;

    int top = 0;
    __try {
        top = lua_gettop(L);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_lastSehCode = GetExceptionCode();
        SetFailure(LuaGuardFailure::Seh);
        return res;
    }

    if (!IsStackTopPlausible(top)) {
        SetFailure(LuaGuardFailure::ImplausibleTop);
        return res;
    }

    res.ok = true;
    res.top = top;
    ClearFailure();
    return res;
}

bool safe_lua_settop(lua_State* L, const LuaStateInfo& info, int idx) noexcept {
    if (!IsOkToTouchVM(L, info))
        return false;

    if (idx >= 0 && !IsStackTopPlausible(idx)) {
        SetFailure(LuaGuardFailure::ImplausibleTop);
        return false;
    }

    __try {
        lua_settop(L, idx);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_lastSehCode = GetExceptionCode();
        SetFailure(LuaGuardFailure::Seh);
        return false;
    }

    ClearFailure();
    return true;
}

bool safe_probe_stack_roundtrip(lua_State* L, const LuaStateInfo& info) noexcept {
    LuaTopRes top = safe_lua_gettop(L, info);
    if (!top.ok)
        return false;
    if (!safe_lua_settop(L, info, top.top))
        return false;
    ClearFailure();
    return true;
}

} // namespace Engine::Lua
