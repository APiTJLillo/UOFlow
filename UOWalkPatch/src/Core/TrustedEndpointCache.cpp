#include "Core/TrustedEndpointCache.hpp"

#include <algorithm>
#include <limits>
#include <windows.h>

namespace {

std::atomic<std::uint64_t> g_qpcFrequency{0};
Core::TrustedEndpointCache g_trustedEndpointCache;

} // namespace

namespace Core {

namespace {

std::uint64_t LoadFrequency()
{
    std::uint64_t freq = g_qpcFrequency.load(std::memory_order_acquire);
    if (freq != 0)
        return freq;

    LARGE_INTEGER li{};
    if (QueryPerformanceFrequency(&li) && li.QuadPart > 0) {
        const std::uint64_t value = static_cast<std::uint64_t>(li.QuadPart);
        g_qpcFrequency.compare_exchange_strong(freq,
                                               value,
                                               std::memory_order_release,
                                               std::memory_order_relaxed);
        return value;
    }
    return 0;
}

} // namespace

TrustedEndpointCache::TrustedEndpointCache(std::uint32_t default_ttl_ms, std::size_t max_entries)
    : m_defaultTtlMs(default_ttl_ms)
    , m_maxEntries(max_entries ? max_entries : 16)
{
    LoadFrequency();
}

bool TrustedEndpointCache::TryGetValid(std::uintptr_t vtbl, TrustedEndpoint& out, std::uint64_t now_qpc)
{
    const std::uint64_t now = now_qpc ? now_qpc : NowQpc();
    std::lock_guard<std::mutex> lock(m_mutex);
    PurgeLocked(now);

    TrustedEndpoint* best = nullptr;
    for (auto& entry : m_entries) {
        if (vtbl != 0 && entry.vtbl != vtbl)
            continue;
        if (entry.expires_qpc != 0 && entry.expires_qpc <= now)
            continue;
        if (!best || entry.hits > best->hits)
            best = &entry;
    }

    if (!best)
        return false;

    out = *best;
    return true;
}

TrustedEndpoint TrustedEndpointCache::InsertOrBump(std::uintptr_t vtbl,
                                                   std::uint32_t slot,
                                                   std::uintptr_t entry,
                                                   std::uint32_t ttl_ms)
{
    const std::uint64_t now = NowQpc();
    const std::uint64_t ttlTicks = ToQpcTicks(ttl_ms ? ttl_ms : m_defaultTtlMs);
    TrustedEndpoint result{};

    std::lock_guard<std::mutex> lock(m_mutex);
    PurgeLocked(now);

    for (auto& node : m_entries) {
        if (node.vtbl == vtbl && node.slot == slot) {
            node.entry = entry;
            node.expires_qpc = ttlTicks ? (now + ttlTicks) : 0;
            if (node.hits < std::numeric_limits<std::uint32_t>::max())
                ++node.hits;
            result = node;
            return result;
        }
    }

    TrustedEndpoint fresh{};
    fresh.vtbl = vtbl;
    fresh.slot = slot;
    fresh.entry = entry;
    fresh.expires_qpc = ttlTicks ? (now + ttlTicks) : 0;
    fresh.hits = 1;
    m_entries.push_back(fresh);

    if (m_entries.size() > m_maxEntries) {
        auto dropIt = std::min_element(m_entries.begin(),
                                       m_entries.end(),
                                       [](const TrustedEndpoint& a, const TrustedEndpoint& b) {
                                           if (a.hits != b.hits)
                                               return a.hits < b.hits;
                                           return a.expires_qpc < b.expires_qpc;
                                       });
        if (dropIt != m_entries.end() && dropIt->vtbl != vtbl) {
            m_entries.erase(dropIt);
        } else if (m_entries.size() > m_maxEntries) {
            m_entries.erase(m_entries.begin());
        }
    }

    result = fresh;
    return result;
}

void TrustedEndpointCache::Purge(std::uint64_t now_qpc)
{
    const std::uint64_t now = now_qpc ? now_qpc : NowQpc();
    std::lock_guard<std::mutex> lock(m_mutex);
    PurgeLocked(now);
}

void TrustedEndpointCache::Clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_entries.clear();
}

std::size_t TrustedEndpointCache::size() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_entries.size();
}

std::uint64_t TrustedEndpointCache::QpcFrequency()
{
    return LoadFrequency();
}

std::uint64_t TrustedEndpointCache::ToQpcTicks(std::uint32_t ms)
{
    if (ms == 0)
        return 0;
    const std::uint64_t freq = LoadFrequency();
    if (freq == 0)
        return 0;
    return (freq * static_cast<std::uint64_t>(ms)) / 1000ull;
}

std::uint64_t TrustedEndpointCache::NowQpc()
{
    LARGE_INTEGER li{};
    QueryPerformanceCounter(&li);
    return static_cast<std::uint64_t>(li.QuadPart);
}

void TrustedEndpointCache::PurgeLocked(std::uint64_t now_qpc)
{
    m_entries.erase(std::remove_if(m_entries.begin(),
                                   m_entries.end(),
                                   [now_qpc](const TrustedEndpoint& entry) {
                                       return entry.expires_qpc != 0 && entry.expires_qpc <= now_qpc;
                                   }),
                    m_entries.end());
}

TrustedEndpointCache& GetTrustedEndpointCache()
{
    return g_trustedEndpointCache;
}

} // namespace Core
