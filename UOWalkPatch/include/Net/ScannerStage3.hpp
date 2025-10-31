#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <iterator>
#include <list>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>
#include <windows.h>

namespace Net::Scanner {

struct SendSample {
    std::uint64_t ts_ms = 0;
    std::uint64_t callsite = 0;
    std::uint32_t ip = 0;
    std::uint16_t port = 0;
    std::uint32_t sock = 0;
};

class SendSampleRing {
public:
    static constexpr std::uint32_t kCapacity = 4096;

    SendSampleRing() {
        for (auto& flag : m_ready) {
            flag.store(0, std::memory_order_relaxed);
        }
    }

    bool push(const SendSample& sample) {
        std::uint32_t head = m_head.load(std::memory_order_relaxed);
        while (true) {
            const std::uint32_t tail = m_tail.load(std::memory_order_acquire);
            if (static_cast<std::uint32_t>(head - tail) >= kCapacity) {
                return false;
            }
            if (m_head.compare_exchange_weak(head, head + 1,
                                             std::memory_order_acq_rel,
                                             std::memory_order_relaxed)) {
                const std::size_t slot = head & (kCapacity - 1);
                m_buffer[slot] = sample;
                m_ready[slot].store(1, std::memory_order_release);
                return true;
            }
        }
    }

    void drain(std::vector<SendSample>& out) {
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
        }

        m_tail.store(tail, std::memory_order_release);
    }

    std::uint32_t loadPercent() const {
        const std::uint32_t currentSize = size();
        if (currentSize >= kCapacity) {
            return 100;
        }
        return static_cast<std::uint32_t>((static_cast<std::uint64_t>(currentSize) * 100u) / kCapacity);
    }

    std::uint32_t size() const {
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

struct SampleAggregate {
    std::uint64_t callsite = 0;
    std::uint32_t ip = 0;
    std::uint16_t port = 0;
    std::uint32_t sock = 0;
    std::uint32_t count = 0;
    std::uint64_t last_ts_ms = 0;
};

struct TrustedEndpoint {
    std::uint64_t callsite = 0;
    std::uint32_t ip = 0;
    std::uint16_t port = 0;
    std::uint32_t sock = 0;
    std::uintptr_t endpoint = 0;
    std::uint64_t last_seen_ms = 0;
    std::uint32_t accept_count = 0;
    std::uint32_t reject_count = 0;
};

class TrustedEndpointCache {
public:
    TrustedEndpointCache() = default;

    void addOrRefresh(std::uint64_t callsite,
                      std::uint32_t ip,
                      std::uint16_t port,
                      std::uint32_t sock = 0,
                      std::uintptr_t endpoint = 0,
                      bool accepted = true,
                      std::uint64_t now_ms = 0) {
        std::lock_guard<std::mutex> lock(m_mutex);

        const Key key{callsite, ip, port};
        const std::uint64_t now = now_ms ? now_ms : nowMsUnlocked();
        auto it = m_byKey.find(key);
        if (it != m_byKey.end()) {
            EntryList::iterator entry = it->second;
            entry->last_seen_ms = now;
            entry->sock = sock ? sock : entry->sock;
            entry->endpoint = endpoint ? endpoint : entry->endpoint;
            if (accepted) {
                ++entry->accept_count;
            } else if (entry->reject_count < UINT32_MAX) {
                ++entry->reject_count;
            }
            touchEntry(entry);
            return;
        }

        TrustedEndpoint fresh{};
        fresh.callsite = callsite;
        fresh.ip = ip;
        fresh.port = port;
        fresh.sock = sock;
        fresh.endpoint = endpoint;
        fresh.last_seen_ms = now;
        fresh.accept_count = accepted ? 1u : 0u;
        fresh.reject_count = accepted ? 0u : 1u;

        m_entries.push_front(fresh);
        m_byKey.emplace(key, m_entries.begin());
        if (endpoint) {
            m_byEndpoint[endpoint] = m_entries.begin();
        }
        trimIfNeeded();
    }

    std::optional<TrustedEndpoint> lookup(std::uint64_t callsite,
                                          std::uint32_t ip,
                                          std::uint16_t port) {
        std::lock_guard<std::mutex> lock(m_mutex);
        const Key key{callsite, ip, port};
        auto it = m_byKey.find(key);
        if (it == m_byKey.end()) {
            return std::nullopt;
        }
        touchEntry(it->second);
        return *(it->second);
    }

    std::optional<TrustedEndpoint> lookupByEndpoint(std::uintptr_t endpoint) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_byEndpoint.find(endpoint);
        if (it == m_byEndpoint.end()) {
            return std::nullopt;
        }
        touchEntry(it->second);
        return *(it->second);
    }

    void noteReject(std::uint64_t callsite,
                    std::uint32_t ip,
                    std::uint16_t port,
                    std::uint64_t now_ms = 0) {
        std::lock_guard<std::mutex> lock(m_mutex);
        const Key key{callsite, ip, port};
        auto it = m_byKey.find(key);
        if (it == m_byKey.end()) {
            return;
        }
        EntryList::iterator entry = it->second;
        entry->last_seen_ms = now_ms ? now_ms : nowMsUnlocked();
        if (entry->reject_count < UINT32_MAX) {
            ++entry->reject_count;
        }
        touchEntry(entry);
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_entries.size();
    }

private:
    struct Key {
        std::uint64_t callsite = 0;
        std::uint32_t ip = 0;
        std::uint16_t port = 0;

        bool operator==(const Key& rhs) const noexcept {
            return callsite == rhs.callsite && ip == rhs.ip && port == rhs.port;
        }
    };

    struct KeyHasher {
        std::size_t operator()(const Key& key) const noexcept;
    };

    using EntryList = std::list<TrustedEndpoint>;
    using MapByKey = std::unordered_map<Key, EntryList::iterator, KeyHasher>;
    using MapByEndpoint = std::unordered_map<std::uintptr_t, EntryList::iterator>;

    static constexpr std::size_t kMaxEntries = 2000;

    mutable std::mutex m_mutex;
    EntryList m_entries;
    MapByKey m_byKey;
    MapByEndpoint m_byEndpoint;

    std::uint64_t nowMsUnlocked() const {
        return static_cast<std::uint64_t>(GetTickCount64());
    }

    void touchEntry(EntryList::iterator it) {
        if (it == m_entries.begin())
            return;
        TrustedEndpoint entry = *it;
        m_entries.erase(it);
        m_entries.push_front(entry);
        const Key key{entry.callsite, entry.ip, entry.port};
        m_byKey[key] = m_entries.begin();
        if (entry.endpoint) {
            m_byEndpoint[entry.endpoint] = m_entries.begin();
        }
    }

    void trimIfNeeded() {
        while (m_entries.size() > kMaxEntries) {
            EntryList::iterator doomed = std::prev(m_entries.end());
            const Key key{doomed->callsite, doomed->ip, doomed->port};
            m_byKey.erase(key);
            if (doomed->endpoint) {
                m_byEndpoint.erase(doomed->endpoint);
            }
            m_entries.pop_back();
        }
    }
};

class RejectStore {
public:
    std::pair<std::uint32_t, std::uint32_t> incrementReject(std::uintptr_t addr,
                                                            std::uint64_t now_ms = 0) {
        std::lock_guard<std::mutex> lock(m_mutex);
        const std::uint64_t now = now_ms ? now_ms : static_cast<std::uint64_t>(GetTickCount64());
        Entry& entry = m_entries[addr];
        if (now >= entry.expiry_ms) {
            entry.count = 0;
        }
        if (entry.count < UINT32_MAX) {
            ++entry.count;
        }
        const std::uint32_t ttl = ttlForCount(entry.count);
        entry.expiry_ms = now + (static_cast<std::uint64_t>(ttl) * 1000ull);
        return {entry.count, ttl};
    }

    bool isRejectedAndActive(std::uintptr_t addr, std::uint64_t now_ms = 0) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_entries.find(addr);
        if (it == m_entries.end()) {
            return false;
        }
        const std::uint64_t now = now_ms ? now_ms : static_cast<std::uint64_t>(GetTickCount64());
        if (now >= it->second.expiry_ms) {
            m_entries.erase(it);
            return false;
        }
        return true;
    }

    void clear(std::uintptr_t addr) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_entries.erase(addr);
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_entries.size();
    }

private:
    struct Entry {
        std::uint32_t count = 0;
        std::uint64_t expiry_ms = 0;
    };

    static std::uint32_t ttlForCount(std::uint32_t count) {
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
    std::uint32_t ring_load_pct = 0;
    std::uint64_t total_candidate_us = 0;
    std::uint64_t max_candidate_us = 0;

    void recordCandidate(std::uint64_t duration_us, bool acceptedCandidate, bool rejectedCandidate) {
        ++candidates_considered;
        total_candidate_us += duration_us;
        if (duration_us > max_candidate_us)
            max_candidate_us = duration_us;
        if (acceptedCandidate)
            ++accepted;
        if (rejectedCandidate)
            ++rejected;
    }

    std::uint64_t avg_us() const {
        if (candidates_considered == 0)
            return 0;
        return total_candidate_us / candidates_considered;
    }
};

class Tuner {
public:
    void applyTelemetry(const ScanPassTelemetry& telemetry) {
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

inline void PrioritizeCandidates(std::vector<CandidateDescriptor>& candidates) {
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

inline std::size_t TrustedEndpointCache::KeyHasher::operator()(const Key& key) const noexcept {
    std::size_t h1 = std::hash<std::uint64_t>{}(key.callsite);
    std::size_t h2 = std::hash<std::uint32_t>{}(key.ip);
    std::size_t h3 = std::hash<std::uint16_t>{}(key.port);
    return h1 ^ (h2 << 1) ^ (h3 << 2);
}

class TokenBucket {
public:
    TokenBucket(std::uint32_t ratePerSec, std::uint32_t capacity)
        : m_rate(ratePerSec)
        , m_capacity(capacity)
        , m_state((static_cast<std::uint64_t>(capacity) << 32) |
                  static_cast<std::uint64_t>(GetTickCount())) {}

    bool tryConsume(std::uint64_t nowMs = 0) {
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
