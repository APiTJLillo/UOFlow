#pragma once

#include <cstddef>
#include <cstdint>

struct lua_State;

namespace Engine::Lua {

struct LuaStateInfo;

enum class LuaGuardFailure {
    None = 0,
    CanonMismatch,
    OwnerMismatch,
    ReadCheckFailed,
    Seh,
    ImplausibleTop,
    GenerationMismatch,
};

LuaGuardFailure GetLastLuaGuardFailure() noexcept;

bool IsProbablyReadable(const void* p, size_t bytes) noexcept;
bool ValidateLuaStateShallow(lua_State* L, uintptr_t expectedGlobal) noexcept;
bool IsOkToTouchVM(lua_State* L, const LuaStateInfo& info) noexcept;

struct LuaTopRes {
    bool ok = false;
    int top = 0;
};

LuaTopRes safe_lua_gettop(lua_State* L, const LuaStateInfo& info) noexcept;
bool safe_lua_settop(lua_State* L, const LuaStateInfo& info, int idx) noexcept;
bool safe_probe_stack_roundtrip(lua_State* L, const LuaStateInfo& info) noexcept;

} // namespace Engine::Lua

