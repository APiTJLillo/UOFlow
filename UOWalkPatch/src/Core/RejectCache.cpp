#include "Core/RejectCache.hpp"

#include <windows.h>

namespace {

std::atomic<std::uint64_t> g_qpcFrequency{0};

} // namespace

namespace Core {

namespace {
RejectCache g_rejectCache;
}

static std::uint64_t LoadFrequency()
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

RejectCache::RejectCache(std::uint32_t ttl_ms)
    : m_ttl_ms(ttl_ms)
{
    LoadFrequency();
}

void RejectCache::reject(void* key, std::uint8_t reason)
{
    if (!key)
        return;

    const std::uint64_t now = NowQpc();
    std::lock_guard<std::mutex> lock(m_mutex);
    Node& node = m_entries[key];
    node.ts_qpc = now;
    node.reason = reason;
}

bool RejectCache::is_hot(void* key, std::uint64_t now_qpc, std::uint8_t* reason_out)
{
    if (reason_out)
        *reason_out = 0;

    if (!key)
        return false;

    const std::uint64_t freq = LoadFrequency();
    if (freq == 0)
        return false;

    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_entries.find(key);
    if (it == m_entries.end())
        return false;

    const std::uint64_t ttlTicks = QpcTicksForMs(m_ttl_ms);
    const Node& node = it->second;
    const std::uint64_t ageTicks = (now_qpc >= node.ts_qpc) ? (now_qpc - node.ts_qpc) : 0;
    if (ttlTicks != 0 && ageTicks > ttlTicks) {
        m_entries.erase(it);
        return false;
    }

    if (reason_out)
        *reason_out = node.reason;
    return true;
}

void RejectCache::sweep(std::uint64_t now_qpc)
{
    const std::uint64_t ttlTicks = QpcTicksForMs(m_ttl_ms);
    if (ttlTicks == 0)
        return;

    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_entries.begin(); it != m_entries.end();) {
        const Node& node = it->second;
        const std::uint64_t ageTicks = (now_qpc >= node.ts_qpc) ? (now_qpc - node.ts_qpc) : 0;
        if (ageTicks > ttlTicks)
            it = m_entries.erase(it);
        else
            ++it;
    }
}

std::size_t RejectCache::size() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_entries.size();
}

std::uint64_t RejectCache::QpcFrequency()
{
    return LoadFrequency();
}

std::uint64_t RejectCache::QpcTicksForMs(std::uint32_t ms)
{
    if (ms == 0)
        return 0;
    const std::uint64_t freq = LoadFrequency();
    if (freq == 0)
        return 0;
    return (freq * static_cast<std::uint64_t>(ms)) / 1000ull;
}

std::uint64_t RejectCache::NowQpc()
{
    LARGE_INTEGER li{};
    QueryPerformanceCounter(&li);
    return static_cast<std::uint64_t>(li.QuadPart);
}

RejectCache& GetRejectCache()
{
    return g_rejectCache;
}

} // namespace Core

