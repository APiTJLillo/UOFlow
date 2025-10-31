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

constexpr uint32_t STATE_FLAG_HELPERS         = 1u << 0;
constexpr uint32_t STATE_FLAG_QUARANTINED     = 1u << 1;
constexpr uint32_t STATE_FLAG_VALID           = 1u << 2;
constexpr uint32_t STATE_FLAG_HELPERS_BOUND   = 1u << 3;
constexpr uint32_t STATE_FLAG_PANIC_OK        = 1u << 4;
constexpr uint32_t STATE_FLAG_PANIC_MISS      = 1u << 5;
constexpr uint32_t STATE_FLAG_DEBUG_OK        = 1u << 6;
constexpr uint32_t STATE_FLAG_DEBUG_MISS      = 1u << 7;
constexpr uint32_t STATE_FLAG_SLOT_READY      = 1u << 8;
constexpr uint32_t STATE_FLAG_REG_STABLE      = 1u << 9;
constexpr uint32_t STATE_FLAG_OWNER_READY     = 1u << 10;
constexpr uint32_t STATE_FLAG_CANON_READY     = 1u << 11;
constexpr uint32_t STATE_FLAG_HELPERS_PENDING = 1u << 12;
constexpr uint32_t STATE_FLAG_HELPERS_INSTALLED = 1u << 13;

constexpr uint16_t HELPER_FLAG_SETTLE_PROMOTED = 1u << 0;
constexpr uint16_t HELPER_FLAG_SETTLE_ARMED    = 1u << 1;

enum class HelperInstallStage : uint8_t {
    WaitingForGlobalState = 0,
    WaitingForOwnerThread = 1,
    ReadyToInstall        = 2,
    Installing            = 3,
    Installed             = 4,
};

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

    uint64_t slot_ready_tick_ms = 0;
    uint64_t register_last_tick_ms = 0;
    uint64_t register_quiet_tick_ms = 0;
    uint64_t owner_ready_tick_ms = 0;
    uint64_t canonical_ready_tick_ms = 0;
    uint64_t helper_pending_tick_ms = 0;
    uint64_t last_bind_log_tick_ms = 0;
    uint64_t helper_pending_generation = 0;
    uint64_t helper_installed_tick_ms = 0;
    uint32_t helper_retry_count = 0;
    uint32_t helper_rebind_attempts = 0;
    uint64_t helper_first_attempt_ms = 0;
    uint64_t helper_next_retry_ms = 0;
    uint64_t helper_last_attempt_ms = 0;
    uint64_t helper_last_mutation_tick_ms = 0;
    uint64_t helper_state_since_ms = 0;
    uint64_t helper_settle_start_ms = 0;
    uint64_t helper_next_skip_log_ms = 0;
    uint64_t helper_owner_deadline_ms = 0;
    uint64_t helper_passive_since_ms = 0;
    uint64_t helper_last_signal_ms = 0;
    uint8_t helper_state = static_cast<uint8_t>(HelperInstallStage::WaitingForGlobalState);
    uint8_t helper_failover_count = 0;
    uint16_t helper_flags = 0;
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

    mutable std::recursive_mutex mutex_;
    std::list<Entry> entries_;
};

} // namespace Engine::Lua
