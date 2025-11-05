#include "Engine/LuaStateRegistry.hpp"

#include <algorithm>
#include <windows.h>

namespace Engine::Lua {

LuaStateRegistry::LuaStateRegistry() = default;

std::pair<LuaStateInfo, bool> LuaStateRegistry::AddOrUpdate(lua_State* reported, void* ctx, DWORD tid, uint64_t gen) {
    if (!reported)
        return {LuaStateInfo{}, false};

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto [entry, inserted] = EnsureEntry(reported, ctx, tid, gen);
    return {entry ? entry->info : LuaStateInfo{}, inserted};
}

LuaStateInfo LuaStateRegistry::EnsureForPointer(lua_State* pointer, void* ctxHint, DWORD tid, uint64_t gen, bool& isNew) {
    isNew = false;
    if (!pointer)
        return {};

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    Entry* entry = FindByPointer(pointer);
    const uint64_t now = GetTickCount64();
    if (entry) {
        if (tid) {
            if (entry->info.owner_tid == 0)
                entry->info.owner_tid = tid;
            entry->info.last_tid = tid;
        }
        entry->info.gen = std::max(entry->info.gen, gen);
        entry->info.last_seen_ms = now;
        if (ctxHint && !entry->info.ctx_reported)
            entry->info.ctx_reported = ctxHint;
        AddAlias(*entry, pointer);
        if (ctxHint)
            AddAlias(*entry, reinterpret_cast<lua_State*>(ctxHint));
        return entry->info;
    }

    Entry newEntry{};
    newEntry.info.L_reported = pointer;
    newEntry.info.ctx_reported = ctxHint;
    newEntry.info.owner_tid = tid;
    newEntry.info.last_tid = tid;
    newEntry.info.gen = gen;
    newEntry.info.last_seen_ms = now;
    AddAlias(newEntry, pointer);
    if (ctxHint)
        AddAlias(newEntry, reinterpret_cast<lua_State*>(ctxHint));
    entries_.push_back(newEntry);
    isNew = true;
    return entries_.back().info;
}

LuaStateRegistry::MergeResult LuaStateRegistry::MergeByCanonical(lua_State* reported, void* ctx, lua_State* canonical) {
    MergeResult result{};
    if (!canonical)
        return result;

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    Entry* source = FindByKey(reported, ctx);
    if (!source)
        return result;

    source->info.L_canonical = canonical;
    AddAlias(*source, canonical);

    Entry* target = nullptr;
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        Entry* candidate = &(*it);
        if (candidate == source)
            continue;
        if (MatchesPointer(*candidate, canonical)) {
            target = candidate;
            break;
        }
    }

    if (!target) {
        result.info = source->info;
        return result;
    }

    CombineInfo(target->info, source->info);
    AddAlias(*target, source->info.L_reported);
    AddAlias(*target, reinterpret_cast<lua_State*>(source->info.ctx_reported));
    for (lua_State* alias : source->aliases)
        AddAlias(*target, alias);

    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (&(*it) == source) {
            entries_.erase(it);
            break;
        }
    }

    result.merged = true;
    result.info = target->info;
    return result;
}

bool LuaStateRegistry::GetByPointer(lua_State* pointer, LuaStateInfo& out) const {
    if (!pointer)
        return false;

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const Entry* entry = FindByPointer(pointer);
    if (!entry)
        return false;
    out = entry->info;
    return true;
}

bool LuaStateRegistry::UpdateByPointer(lua_State* pointer, const std::function<void(LuaStateInfo&)>& fn, LuaStateInfo* outInfo) {
    if (!pointer)
        return false;

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    Entry* entry = FindByPointer(pointer);
    if (!entry)
        return false;
    fn(entry->info);
    AddAlias(*entry, pointer);
    if (outInfo)
        *outInfo = entry->info;
    return true;
}

bool LuaStateRegistry::RemoveByPointer(lua_State* pointer, LuaStateInfo* outInfo) {
    if (!pointer)
        return false;

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (MatchesPointer(*it, pointer)) {
            if (outInfo)
                *outInfo = it->info;
            entries_.erase(it);
            return true;
        }
    }
    return false;
}

void LuaStateRegistry::IncrementHookCounters(lua_State* canonical, uint32_t callDelta, uint32_t retDelta, uint32_t lineDelta) {
    if (!canonical)
        return;

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    Entry* entry = FindByPointer(canonical);
    if (!entry)
        return;

    entry->info.hook_call_count += callDelta;
    entry->info.hook_ret_count += retDelta;
    entry->info.hook_line_count += lineDelta;
}

void LuaStateRegistry::ClearFlagsAll(uint32_t mask) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto& entry : entries_) {
        if (mask & STATE_FLAG_HELPERS_INSTALLED)
            entry.info.helper_installed_tick_ms = 0;
        entry.info.flags &= ~mask;
    }
}

std::vector<LuaStateInfo> LuaStateRegistry::Snapshot() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<LuaStateInfo> out;
    out.reserve(entries_.size());
    for (const auto& entry : entries_)
        out.push_back(entry.info);
    return out;
}

void LuaStateRegistry::Reset() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    entries_.clear();
}

LuaStateRegistry::Entry* LuaStateRegistry::FindByPointer(lua_State* pointer) {
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (MatchesPointer(*it, pointer))
            return &(*it);
    }
    return nullptr;
}

const LuaStateRegistry::Entry* LuaStateRegistry::FindByPointer(lua_State* pointer) const {
    for (auto it = entries_.cbegin(); it != entries_.cend(); ++it) {
        if (MatchesPointer(*it, pointer))
            return &(*it);
    }
    return nullptr;
}

LuaStateRegistry::Entry* LuaStateRegistry::FindByKey(lua_State* reported, void* ctx) {
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (it->info.L_reported == reported && it->info.ctx_reported == ctx)
            return &(*it);
    }
    return nullptr;
}

bool LuaStateRegistry::MatchesPointer(const Entry& entry, lua_State* pointer) {
    if (!pointer)
        return false;
    if (entry.info.L_canonical == pointer)
        return true;
    if (entry.info.L_reported == pointer)
        return true;
    if (entry.info.ctx_reported && reinterpret_cast<lua_State*>(entry.info.ctx_reported) == pointer)
        return true;
    return std::find(entry.aliases.begin(), entry.aliases.end(), pointer) != entry.aliases.end();
}

void LuaStateRegistry::AddAlias(Entry& entry, lua_State* pointer) {
    if (!pointer)
        return;
    if (entry.info.L_canonical == pointer || entry.info.L_reported == pointer ||
        (entry.info.ctx_reported && reinterpret_cast<lua_State*>(entry.info.ctx_reported) == pointer))
        return;
    if (std::find(entry.aliases.begin(), entry.aliases.end(), pointer) == entry.aliases.end())
        entry.aliases.push_back(pointer);
}

void LuaStateRegistry::CombineInfo(LuaStateInfo& into, const LuaStateInfo& from) {
    if (into.owner_tid == 0)
        into.owner_tid = from.owner_tid;
    if (from.last_tid)
        into.last_tid = from.last_tid;
    into.gen = std::max(into.gen, from.gen);
    if (!into.expected_global && from.expected_global)
        into.expected_global = from.expected_global;
    if (from.gc_gen > into.gc_gen)
        into.gc_gen = from.gc_gen;
    into.flags |= from.flags;

    if (into.next_probe_ms == 0 || (from.next_probe_ms != 0 && from.next_probe_ms < into.next_probe_ms))
        into.next_probe_ms = from.next_probe_ms;
    into.probe_failures = std::max(into.probe_failures, from.probe_failures);
    into.last_seen_ms = std::max(into.last_seen_ms, from.last_seen_ms);

    if (!into.L_canonical && from.L_canonical)
        into.L_canonical = from.L_canonical;
    if (!into.ctx_reported && from.ctx_reported)
        into.ctx_reported = from.ctx_reported;

    into.hook_call_count += from.hook_call_count;
    into.hook_ret_count += from.hook_ret_count;
    into.hook_line_count += from.hook_line_count;
    if (from.panic_status_gen > into.panic_status_gen) {
        into.panic_status_gen = from.panic_status_gen;
        into.panic_status = from.panic_status;
        into.panic_prev = from.panic_prev;
    }
    if (from.debug_status_gen > into.debug_status_gen) {
        into.debug_status_gen = from.debug_status_gen;
        into.debug_status = from.debug_status;
        into.debug_prev = from.debug_prev;
        into.debug_prev_mask = from.debug_prev_mask;
        into.debug_prev_count = from.debug_prev_count;
        into.debug_prev_valid = from.debug_prev_valid;
    }
    if (from.debug_mode_gen > into.debug_mode_gen) {
        into.debug_mode_gen = from.debug_mode_gen;
        into.debug_mode = from.debug_mode;
        into.debug_mask = from.debug_mask;
        into.debug_count = from.debug_count;
    }
    if (from.gc_sentinel_gen > into.gc_sentinel_gen) {
        into.gc_sentinel_gen = from.gc_sentinel_gen;
        into.gc_sentinel_ref = from.gc_sentinel_ref;
    }

    if (from.slot_ready_tick_ms && (!into.slot_ready_tick_ms || from.slot_ready_tick_ms < into.slot_ready_tick_ms))
        into.slot_ready_tick_ms = from.slot_ready_tick_ms;
    if (from.register_last_tick_ms > into.register_last_tick_ms)
        into.register_last_tick_ms = from.register_last_tick_ms;
    if (from.register_quiet_tick_ms > into.register_quiet_tick_ms)
        into.register_quiet_tick_ms = from.register_quiet_tick_ms;
    if (from.owner_ready_tick_ms && (!into.owner_ready_tick_ms || from.owner_ready_tick_ms < into.owner_ready_tick_ms))
        into.owner_ready_tick_ms = from.owner_ready_tick_ms;
    if (from.canonical_ready_tick_ms > into.canonical_ready_tick_ms)
        into.canonical_ready_tick_ms = from.canonical_ready_tick_ms;
    if (from.helper_pending_tick_ms > into.helper_pending_tick_ms)
        into.helper_pending_tick_ms = from.helper_pending_tick_ms;
    if (from.last_bind_log_tick_ms > into.last_bind_log_tick_ms)
        into.last_bind_log_tick_ms = from.last_bind_log_tick_ms;
    if (from.helper_pending_generation > into.helper_pending_generation)
        into.helper_pending_generation = from.helper_pending_generation;
    if (from.helper_installed_tick_ms > into.helper_installed_tick_ms)
        into.helper_installed_tick_ms = from.helper_installed_tick_ms;
    into.helper_retry_count = std::max(into.helper_retry_count, from.helper_retry_count);
    if (into.helper_first_attempt_ms == 0 || (from.helper_first_attempt_ms != 0 && from.helper_first_attempt_ms < into.helper_first_attempt_ms))
        into.helper_first_attempt_ms = from.helper_first_attempt_ms;
    if (into.helper_next_retry_ms == 0 || (from.helper_next_retry_ms != 0 && from.helper_next_retry_ms < into.helper_next_retry_ms))
        into.helper_next_retry_ms = from.helper_next_retry_ms;
    if (from.helper_last_attempt_ms > into.helper_last_attempt_ms)
        into.helper_last_attempt_ms = from.helper_last_attempt_ms;
    if (from.helper_last_mutation_tick_ms > into.helper_last_mutation_tick_ms)
        into.helper_last_mutation_tick_ms = from.helper_last_mutation_tick_ms;
}

std::pair<LuaStateRegistry::Entry*, bool> LuaStateRegistry::EnsureEntry(lua_State* reported, void* ctx, DWORD tid, uint64_t gen) {
    Entry* entry = FindByKey(reported, ctx);
    const uint64_t now = GetTickCount64();
    if (entry) {
        if (tid) {
            if (entry->info.owner_tid == 0)
                entry->info.owner_tid = tid;
            entry->info.last_tid = tid;
        }
        entry->info.gen = std::max(entry->info.gen, gen);
        entry->info.last_seen_ms = now;
        if (ctx && !entry->info.ctx_reported)
            entry->info.ctx_reported = ctx;
        AddAlias(*entry, reported);
        if (ctx)
            AddAlias(*entry, reinterpret_cast<lua_State*>(ctx));
        return {entry, false};
    }

    Entry newEntry{};
    newEntry.info.L_reported = reported;
    newEntry.info.ctx_reported = ctx;
    newEntry.info.owner_tid = tid;
    newEntry.info.last_tid = tid;
    newEntry.info.gen = gen;
    newEntry.info.last_seen_ms = now;
    AddAlias(newEntry, reported);
    if (ctx)
        AddAlias(newEntry, reinterpret_cast<lua_State*>(ctx));
    entries_.push_back(newEntry);
    return {&entries_.back(), true};
}

} // namespace Engine::Lua
