#pragma once

#include <windows.h>

#include <cstdint>
#include <functional>
#include <list>
#include <mutex>
#include <utility>
#include <vector>

struct lua_State;
struct lua_Debug;

using lua_CFunction = int(__cdecl*)(lua_State*);
using lua_Hook = void(__cdecl*)(lua_State*, lua_Debug*);

namespace Engine::Lua {

struct LuaStateInfo {
    lua_State* L_reported = nullptr;
    void* ctx_reported = nullptr;
    lua_State* L_canonical = nullptr;
    uintptr_t expected_global = 0;
    DWORD owner_tid = 0;
    DWORD last_tid = 0;
    uint64_t gen = 0;
    uint32_t gc_gen = 0;
    uint32_t flags = 0;
    uint64_t next_probe_ms = 0;
    uint32_t probe_failures = 0;
    uint64_t last_seen_ms = 0;

    uint32_t hook_call_count = 0;
    uint32_t hook_ret_count = 0;
    uint32_t hook_line_count = 0;

    int panic_status = -1;
    uint64_t panic_status_gen = 0;
    lua_CFunction panic_prev = nullptr;

    int debug_status = -1;
    uint64_t debug_status_gen = 0;
    uint32_t debug_mode = 0;
    uint64_t debug_mode_gen = 0;
    uint32_t debug_mask = 0;
    uint32_t debug_count = 0;
    lua_Hook debug_prev = nullptr;
    int debug_prev_mask = 0;
    int debug_prev_count = 0;
    int debug_prev_valid = 0;

    int gc_sentinel_ref = -1;
    uint64_t gc_sentinel_gen = 0;
};

class LuaStateRegistry {
public:
    struct MergeResult {
        bool merged = false;
        LuaStateInfo info{};
    };

    LuaStateRegistry();

    std::pair<LuaStateInfo, bool> AddOrUpdate(lua_State* reported, void* ctx, DWORD tid, uint64_t gen);
    LuaStateInfo EnsureForPointer(lua_State* pointer, void* ctxHint, DWORD tid, uint64_t gen, bool& isNew);

    MergeResult MergeByCanonical(lua_State* reported, void* ctx, lua_State* canonical);

    bool GetByPointer(lua_State* pointer, LuaStateInfo& out) const;
    bool UpdateByPointer(lua_State* pointer, const std::function<void(LuaStateInfo&)>& fn, LuaStateInfo* outInfo = nullptr);
    bool RemoveByPointer(lua_State* pointer, LuaStateInfo* outInfo = nullptr);

    void IncrementHookCounters(lua_State* canonical, uint32_t callDelta, uint32_t retDelta, uint32_t lineDelta);

    void ClearFlagsAll(uint32_t mask);
    std::vector<LuaStateInfo> Snapshot() const;
    void Reset();

private:
    struct Entry {
        LuaStateInfo info;
        std::vector<lua_State*> aliases;
    };

    Entry* FindByPointer(lua_State* pointer);
    const Entry* FindByPointer(lua_State* pointer) const;
    Entry* FindByKey(lua_State* reported, void* ctx);
    static bool MatchesPointer(const Entry& entry, lua_State* pointer);
    static void AddAlias(Entry& entry, lua_State* pointer);
    static void CombineInfo(LuaStateInfo& into, const LuaStateInfo& from);

    std::pair<Entry*, bool> EnsureEntry(lua_State* reported, void* ctx, DWORD tid, uint64_t gen);

    mutable std::mutex mutex_;
    std::list<Entry> entries_;
};

} // namespace Engine::Lua
