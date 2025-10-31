#pragma once

#include <windows.h>
#include <psapi.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Net::Scanner {

enum class EdgeType : std::uint8_t {
    Direct = 0,
    Tail = 1,
    PushJmp = 2,
    RegThunk = 3,
    Unknown = 4,
};

inline const char* ToString(EdgeType type) noexcept
{
    switch (type) {
    case EdgeType::Direct:
        return "direct";
    case EdgeType::Tail:
        return "tail";
    case EdgeType::PushJmp:
        return "push_jmp";
    case EdgeType::RegThunk:
        return "reg_thunk";
    default:
        return "unknown";
    }
}

struct SendSample {
    void* ret = nullptr;
    void* func = nullptr;
    EdgeType edge = EdgeType::Unknown;
    std::uint32_t rva = 0;
    std::uint64_t tick = 0;
};

class SendSampleRing {
public:
    static constexpr std::uint32_t kCapacity = 4096;

    SendSampleRing()
    {
        for (auto& flag : m_ready) {
            flag.store(0, std::memory_order_relaxed);
        }
    }

    bool push(const SendSample& sample)
    {
        std::uint32_t head = m_head.load(std::memory_order_relaxed);
        while (true) {
            const std::uint32_t tail = m_tail.load(std::memory_order_acquire);
            if (static_cast<std::uint32_t>(head - tail) >= kCapacity) {
                return false;
            }
            if (m_head.compare_exchange_weak(head,
                                             head + 1,
                                             std::memory_order_acq_rel,
                                             std::memory_order_relaxed)) {
                const std::size_t slot = head & (kCapacity - 1);
                m_buffer[slot] = sample;
                m_ready[slot].store(1, std::memory_order_release);
                return true;
            }
        }
    }

    void drain(std::vector<SendSample>& out, std::uint32_t max = 0)
    {
        out.clear();

        std::uint32_t tail = m_tail.load(std::memory_order_relaxed);
        const std::uint32_t head = m_head.load(std::memory_order_acquire);

        while (tail < head) {
            const std::size_t slot = tail & (kCapacity - 1);
            if (!m_ready[slot].load(std::memory_order_acquire)) {
                break;
            }
            out.push_back(m_buffer[slot]);
            m_ready[slot].store(0, std::memory_order_release);
            ++tail;
            if (max != 0 && out.size() >= max)
                break;
        }

        m_tail.store(tail, std::memory_order_release);
    }

    std::uint32_t loadPercent() const
    {
        const std::uint32_t currentSize = size();
        if (currentSize >= kCapacity) {
            return 100;
        }
        return static_cast<std::uint32_t>((static_cast<std::uint64_t>(currentSize) * 100u) / kCapacity);
    }

    std::uint32_t size() const
    {
        const std::uint32_t head = m_head.load(std::memory_order_acquire);
        const std::uint32_t tail = m_tail.load(std::memory_order_acquire);
        return static_cast<std::uint32_t>(head - tail);
    }

private:
    std::array<SendSample, kCapacity> m_buffer{};
    std::array<std::atomic<std::uint8_t>, kCapacity> m_ready{};
    std::atomic<std::uint32_t> m_head{0};
    std::atomic<std::uint32_t> m_tail{0};
};

class SampleDeduper {
public:
    bool accept(std::uintptr_t moduleBase, std::uint32_t rva, std::uint64_t nowMs)
    {
        constexpr std::uint64_t kWindowMs = 1200;
        std::lock_guard<std::mutex> lock(m_mutex);
        const std::uint64_t key = hashKey(moduleBase, rva);
        auto it = m_recent.find(key);
        if (it != m_recent.end()) {
            if (nowMs <= it->second || (nowMs - it->second) < kWindowMs) {
                return false;
            }
        }
        m_recent[key] = nowMs;
        if (m_recent.size() > kPruneThreshold) {
            prune(nowMs, kWindowMs);
        }
        return true;
    }

    void reset()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_recent.clear();
    }

private:
    static constexpr std::size_t kPruneThreshold = 256;

    static std::uint64_t hashKey(std::uintptr_t base, std::uint32_t rva) noexcept
    {
        const std::uint64_t hi = static_cast<std::uint64_t>(base);
        const std::uint64_t lo = static_cast<std::uint64_t>(rva);
        const std::uint64_t mixed = (hi << 32) ^ (hi >> 17) ^ (lo * 0x9E3779B97F4A7C15ull);
        return mixed ? mixed : 1ull;
    }

    void prune(std::uint64_t nowMs, std::uint64_t windowMs)
    {
        for (auto it = m_recent.begin(); it != m_recent.end();) {
            if (nowMs > it->second && (nowMs - it->second) > windowMs) {
                it = m_recent.erase(it);
            } else {
                ++it;
            }
        }
    }

    std::unordered_map<std::uint64_t, std::uint64_t> m_recent;
    std::mutex m_mutex;
};

struct ModuleInfo {
    HMODULE module = nullptr;
    std::uintptr_t base = 0;
    std::uintptr_t end = 0;
    std::uintptr_t textBegin = 0;
    std::uintptr_t textEnd = 0;

    [[nodiscard]] bool containsText(std::uintptr_t addr) const noexcept
    {
        return textBegin != 0 && textEnd > textBegin && addr >= textBegin && addr < textEnd;
    }
};

class ModuleMap {
public:
    ModuleMap() = default;

    const ModuleInfo* findByAddress(const void* address)
    {
        if (!address)
            return nullptr;
        refresh(false);
        const std::uintptr_t addr = reinterpret_cast<std::uintptr_t>(address);
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& info : m_entries) {
            if (info.containsText(addr))
                return &info;
        }
        return nullptr;
    }

    const ModuleInfo* primaryExecutable()
    {
        refresh(false);
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_primaryIndex < m_entries.size())
            return &m_entries[m_primaryIndex];
        return nullptr;
    }

    void refresh(bool force)
    {
        const std::uint64_t now = GetTickCount64();
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!force && !m_entries.empty()) {
                if ((now - m_lastRefreshMs) < kRefreshIntervalMs)
                    return;
            }
        }

        std::vector<HMODULE> modules(64);
        DWORD neededBytes = 0;
        HANDLE process = GetCurrentProcess();

        while (true) {
            DWORD capacityBytes = static_cast<DWORD>(modules.size() * sizeof(HMODULE));
            if (!EnumProcessModules(process, modules.data(), capacityBytes, &neededBytes))
                return;
            if (neededBytes <= capacityBytes) {
                modules.resize(neededBytes / sizeof(HMODULE));
                break;
            }
            modules.resize((neededBytes / sizeof(HMODULE)) + 8);
        }

        std::vector<ModuleInfo> fresh;
        fresh.reserve(modules.size());

        const HMODULE primary = GetModuleHandleW(nullptr);
        std::size_t primaryIndex = modules.size();

        for (HMODULE mod : modules) {
            if (!mod)
                continue;

            auto* base = reinterpret_cast<const std::uint8_t*>(mod);
            const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
                continue;
            const IMAGE_NT_HEADERS* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
                continue;

            ModuleInfo info{};
            info.module = mod;
            info.base = reinterpret_cast<std::uintptr_t>(mod);
            info.end = info.base + nt->OptionalHeader.SizeOfImage;

#if defined(_M_X64)
            const IMAGE_OPTIONAL_HEADER64& opt = nt->OptionalHeader;
#else
            const IMAGE_OPTIONAL_HEADER32& opt = nt->OptionalHeader;
#endif

            const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
                if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
                    continue;
                std::uint32_t size = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
                if (size == 0)
                    continue;
                std::uintptr_t begin = info.base + section->VirtualAddress;
                std::uintptr_t end = begin + size;
                if (end <= begin)
                    continue;
                if (section->Name[0] == '.' && section->Name[1] == 't' && section->Name[2] == 'e') {
                    info.textBegin = begin;
                    info.textEnd = end;
                    break;
                }
                if (info.textBegin == 0) {
                    info.textBegin = begin;
                    info.textEnd = end;
                }
            }

            if (info.textBegin == 0 && opt.SizeOfCode != 0) {
                info.textBegin = info.base + opt.BaseOfCode;
                info.textEnd = info.textBegin + opt.SizeOfCode;
            }

            if (info.textBegin != 0 && info.textEnd > info.textBegin) {
                if (mod == primary)
                    primaryIndex = fresh.size();
                fresh.push_back(info);
            }
        }

        std::lock_guard<std::mutex> lock(m_mutex);
        m_primaryIndex = primaryIndex < fresh.size() ? primaryIndex : fresh.size();
        m_entries.swap(fresh);
        m_lastRefreshMs = now;
    }

private:
    static constexpr std::uint64_t kRefreshIntervalMs = 2000;

    mutable std::mutex m_mutex;
    std::vector<ModuleInfo> m_entries;
    std::size_t m_primaryIndex = 0;
    std::uint64_t m_lastRefreshMs = 0;
};

struct EndpointTrust {
    enum class Kind : std::uint8_t { VtblSlot, CodeSite };

    Kind kind = Kind::VtblSlot;
    void* manager = nullptr;
    void* vtbl = nullptr;
    int slot = -1;
    std::uint32_t rva = 0;
    std::uint64_t ttlExpiryMs = 0;
    std::uint32_t gen = 0;
};

class EndpointTrustCache {
public:
    struct SlotKey {
        void* manager = nullptr;
        void* vtbl = nullptr;
        int slot = -1;
    };

    struct CodeKey {
        std::uint32_t rva = 0;
    };

    struct CacheResult {
        EndpointTrust trust;
        bool accepted = false;
    };

    EndpointTrustCache() = default;

    std::optional<CacheResult> lookup(const SlotKey& key, std::uint64_t nowMs) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_slots.find(key);
        if (it == m_slots.end())
            return std::nullopt;
        if (nowMs >= it->second.trust.ttlExpiryMs) {
            m_slots.erase(it);
            return std::nullopt;
        }
        return it->second;
    }

    std::optional<CacheResult> lookup(const CodeKey& key, std::uint64_t nowMs) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_codes.find(key);
        if (it == m_codes.end())
            return std::nullopt;
        if (nowMs >= it->second.trust.ttlExpiryMs) {
            m_codes.erase(it);
            return std::nullopt;
        }
        return it->second;
    }

    bool shouldSkip(const SlotKey& key, std::uint64_t nowMs) const
    {
        return lookup(key, nowMs).has_value();
    }

    bool shouldSkip(const CodeKey& key, std::uint64_t nowMs) const
    {
        return lookup(key, nowMs).has_value();
    }

    void store(const SlotKey& key, bool accepted, std::uint64_t nowMs, std::uint64_t ttlMs)
    {
        CacheResult entry{};
        entry.trust.kind = EndpointTrust::Kind::VtblSlot;
        entry.trust.manager = key.manager;
        entry.trust.vtbl = key.vtbl;
        entry.trust.slot = key.slot;
        entry.trust.ttlExpiryMs = nowMs + ttlMs;
        entry.trust.gen = nextGeneration();
        entry.accepted = accepted;

        std::lock_guard<std::mutex> lock(m_mutex);
        m_slots[key] = entry;
    }

    void store(const CodeKey& key, bool accepted, std::uint64_t nowMs, std::uint64_t ttlMs)
    {
        CacheResult entry{};
        entry.trust.kind = EndpointTrust::Kind::CodeSite;
        entry.trust.rva = key.rva;
        entry.trust.ttlExpiryMs = nowMs + ttlMs;
        entry.trust.gen = nextGeneration();
        entry.accepted = accepted;

        std::lock_guard<std::mutex> lock(m_mutex);
        m_codes[key] = entry;
    }

    void reset()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_slots.clear();
        m_codes.clear();
        m_generation = 0;
    }

private:
    struct SlotHasher {
        std::size_t operator()(const SlotKey& key) const noexcept
        {
            std::size_t h1 = std::hash<void*>{}(key.manager);
            std::size_t h2 = std::hash<void*>{}(key.vtbl);
            std::size_t h3 = std::hash<int>{}(key.slot);
            return (h1 ^ (h2 << 1)) ^ (h3 << 1);
        }
    };

    struct SlotEq {
        bool operator()(const SlotKey& a, const SlotKey& b) const noexcept
        {
            return a.manager == b.manager && a.vtbl == b.vtbl && a.slot == b.slot;
        }
    };

    struct CodeHasher {
        std::size_t operator()(const CodeKey& key) const noexcept
        {
            return std::hash<std::uint32_t>{}(key.rva);
        }
    };

    struct CodeEq {
        bool operator()(const CodeKey& a, const CodeKey& b) const noexcept
        {
            return a.rva == b.rva;
        }
    };

    std::uint32_t nextGeneration() const noexcept
    {
        return m_generation.fetch_add(1u, std::memory_order_relaxed) + 1u;
    }

    mutable std::mutex m_mutex;
    std::unordered_map<SlotKey, CacheResult, SlotHasher, SlotEq> m_slots;
    std::unordered_map<CodeKey, CacheResult, CodeHasher, CodeEq> m_codes;
    mutable std::atomic<std::uint32_t> m_generation{0};
};

class RejectStore {
public:
    RejectStore() = default;

    std::pair<std::uint32_t, std::uint32_t> incrementReject(std::uintptr_t addr, std::uint64_t nowMs)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        Entry& entry = m_entries[addr];
        ++entry.count;
        entry.lastMs = nowMs;
        entry.ttlSeconds = computeTtlSeconds(entry.count);
        return {entry.count, entry.ttlSeconds};
    }

    void clear(std::uintptr_t addr)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_entries.erase(addr);
    }

    bool isRejectedAndActive(std::uintptr_t addr, std::uint64_t nowMs)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_entries.find(addr);
        if (it == m_entries.end())
            return false;
        const Entry& entry = it->second;
        if (entry.ttlSeconds == 0)
            return false;
        const std::uint64_t ttlMs = static_cast<std::uint64_t>(entry.ttlSeconds) * 1000ull;
        if (nowMs <= entry.lastMs)
            return true;
        return (nowMs - entry.lastMs) < ttlMs;
    }

private:
    struct Entry {
        std::uint64_t lastMs = 0;
        std::uint32_t ttlSeconds = 0;
        std::uint32_t count = 0;
    };

    static std::uint32_t computeTtlSeconds(std::uint32_t count)
    {
        if (count == 0)
            return 0;
        if (count == 1)
            return 10;
        if (count == 2)
            return 60;
        if (count == 3)
            return 300;
        if (count >= 4 && count < 10)
            return 3600;
        return 86400;
    }

    mutable std::mutex m_mutex;
    std::unordered_map<std::uintptr_t, Entry> m_entries;
};

struct ScanPassTelemetry {
    std::uint64_t id = 0;
    std::uint32_t candidates_considered = 0;
    std::uint32_t accepted = 0;
    std::uint32_t rejected = 0;
    std::uint32_t skipped = 0;
    std::uint32_t send_samples = 0;
    std::uint32_t sample_hits = 0;
    std::uint32_t sample_rejects = 0;
    std::uint32_t ring_load_pct = 0;
    std::uint64_t total_candidate_us = 0;
    std::uint64_t max_candidate_us = 0;

    void recordCandidate(std::uint64_t duration_us, bool acceptedCandidate, bool rejectedCandidate)
    {
        ++candidates_considered;
        total_candidate_us += duration_us;
        if (duration_us > max_candidate_us)
            max_candidate_us = duration_us;
        if (acceptedCandidate)
            ++accepted;
        if (rejectedCandidate)
            ++rejected;
    }

    std::uint64_t avg_us() const
    {
        if (candidates_considered == 0)
            return 0;
        return total_candidate_us / candidates_considered;
    }
};

class Tuner {
public:
    void applyTelemetry(const ScanPassTelemetry& telemetry)
    {
        const std::uint32_t considered = telemetry.accepted + telemetry.rejected;
        const double rejectRate = considered > 0
                                      ? static_cast<double>(telemetry.rejected) / considered
                                      : 0.0;
        const std::uint64_t avgTime = telemetry.avg_us();

        bool deteriorated = false;
        if (rejectRate > 0.7) {
            if (m_stepDelayMs < kMaxStepDelayMs - 30)
                m_stepDelayMs += 30;
            else
                m_stepDelayMs = kMaxStepDelayMs;
            if (m_escalationLevel < UINT32_MAX)
                ++m_escalationLevel;
            deteriorated = true;
        }

        if (avgTime > 50000 && m_maxInflight > kMaxInflightMin) {
            --m_maxInflight;
        }

        if (telemetry.ring_load_pct > 80) {
            if (m_stepDelayMs < kMaxStepDelayMs - 50)
                m_stepDelayMs += 50;
            else
                m_stepDelayMs = kMaxStepDelayMs;
            deteriorated = true;
        }

        if (!deteriorated && rejectRate < 0.3 && avgTime < 40000 && telemetry.ring_load_pct < 70) {
            if (m_improvementStreak < UINT32_MAX)
                ++m_improvementStreak;
        } else {
            m_improvementStreak = 0;
            if (deteriorated && m_stepDelayMs < kMaxStepDelayMs && m_stepDelayMs < kMaxStepDelayMs - 10) {
                m_stepDelayMs += 10;
            }
        }

        if (m_improvementStreak >= 3 && m_stepDelayMs > kDefaultStepDelayMs) {
            const std::uint32_t newDelay =
                (m_stepDelayMs > 30) ? m_stepDelayMs - 30 : m_stepDelayMs;
            m_stepDelayMs = newDelay < kDefaultStepDelayMs ? kDefaultStepDelayMs : newDelay;
            if (m_escalationLevel > 0)
                --m_escalationLevel;
            m_improvementStreak = 0;
        }

        if (m_stepDelayMs < kMinStepDelayMs)
            m_stepDelayMs = kMinStepDelayMs;
    }

    std::uint32_t stepDelayMs() const { return m_stepDelayMs; }
    std::uint32_t maxInflight() const { return m_maxInflight; }
    std::uint32_t escalationLevel() const { return m_escalationLevel; }

private:
    static constexpr std::uint32_t kDefaultStepDelayMs = 120;
    static constexpr std::uint32_t kMinStepDelayMs = 30;
    static constexpr std::uint32_t kMaxStepDelayMs = 1000;
    static constexpr std::uint32_t kMaxInflightMin = 1;

    std::uint32_t m_stepDelayMs = kDefaultStepDelayMs;
    std::uint32_t m_maxInflight = 4;
    std::uint32_t m_escalationLevel = 0;
    std::uint32_t m_improvementStreak = 0;
};

struct CandidateDescriptor {
    void* endpoint = nullptr;
    std::size_t offset = 0;
    bool trusted = false;
    bool sampleReferenced = false;
    std::uint32_t sampleCount = 0;
};

inline void PrioritizeCandidates(std::vector<CandidateDescriptor>& candidates)
{
    std::stable_sort(candidates.begin(),
                     candidates.end(),
                     [](const CandidateDescriptor& a, const CandidateDescriptor& b) {
                         if (a.trusted != b.trusted)
                             return a.trusted && !b.trusted;
                         if (a.sampleReferenced != b.sampleReferenced)
                             return a.sampleReferenced && !b.sampleReferenced;
                         if (a.sampleCount != b.sampleCount)
                             return a.sampleCount > b.sampleCount;
                         return a.offset < b.offset;
                     });
}

class TokenBucket {
public:
    TokenBucket(std::uint32_t ratePerSec, std::uint32_t capacity)
        : m_rate(ratePerSec)
        , m_capacity(capacity)
        , m_state((static_cast<std::uint64_t>(capacity) << 32) |
                  static_cast<std::uint64_t>(GetTickCount())) {}

    bool tryConsume(std::uint64_t nowMs = 0)
    {
        const std::uint32_t nowTick = static_cast<std::uint32_t>((nowMs ? nowMs : GetTickCount()) & 0xFFFFFFFFu);
        std::uint64_t state = m_state.load(std::memory_order_relaxed);

        while (true) {
            std::uint32_t tokens = static_cast<std::uint32_t>(state >> 32);
            std::uint32_t lastTick = static_cast<std::uint32_t>(state & 0xFFFFFFFFu);

            const std::uint32_t elapsed = nowTick - lastTick;
            if (elapsed > 0) {
                const std::uint64_t add = (static_cast<std::uint64_t>(elapsed) * m_rate) / 1000ull;
                if (add > 0) {
                    const std::uint64_t newTokens = std::min<std::uint64_t>(m_capacity, tokens + add);
                    tokens = static_cast<std::uint32_t>(newTokens);
                    lastTick = nowTick;
                }
            }

            if (tokens == 0) {
                const std::uint64_t desired = (static_cast<std::uint64_t>(tokens) << 32) |
                                              static_cast<std::uint64_t>(lastTick);
                if (m_state.compare_exchange_weak(state,
                                                  desired,
                                                  std::memory_order_acq_rel,
                                                  std::memory_order_relaxed)) {
                    return false;
                }
                continue;
            }

            --tokens;
            const std::uint64_t desired = (static_cast<std::uint64_t>(tokens) << 32) |
                                          static_cast<std::uint64_t>(lastTick);
            if (m_state.compare_exchange_weak(state,
                                              desired,
                                              std::memory_order_acq_rel,
                                              std::memory_order_relaxed)) {
                return true;
            }
        }
    }

private:
    const std::uint32_t m_rate;
    const std::uint32_t m_capacity;
    std::atomic<std::uint64_t> m_state;
};

} // namespace Net::Scanner
