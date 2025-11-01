#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <vector>

namespace Core {

struct TrustedEndpoint {
    std::uintptr_t vtbl = 0;
    std::uint32_t slot = 0;
    std::uintptr_t entry = 0;
    std::uint64_t expires_qpc = 0;
    std::uint32_t hits = 0;
};

class TrustedEndpointCache {
public:
    explicit TrustedEndpointCache(std::uint32_t default_ttl_ms = 900000, std::size_t max_entries = 16);

    bool TryGetValid(std::uintptr_t vtbl, TrustedEndpoint& out, std::uint64_t now_qpc = 0);
    TrustedEndpoint InsertOrBump(std::uintptr_t vtbl,
                                 std::uint32_t slot,
                                 std::uintptr_t entry,
                                 std::uint32_t ttl_ms = 0);
    void Purge(std::uint64_t now_qpc = 0);
    void Clear();

    std::size_t size() const;

    static std::uint64_t QpcFrequency();

private:
    static std::uint64_t ToQpcTicks(std::uint32_t ms);
    static std::uint64_t NowQpc();

    void PurgeLocked(std::uint64_t now_qpc);

    const std::uint32_t m_defaultTtlMs;
    const std::size_t m_maxEntries;
    mutable std::mutex m_mutex;
    std::vector<TrustedEndpoint> m_entries;
};

TrustedEndpointCache& GetTrustedEndpointCache();

} // namespace Core
