#include "Net/SendSampleStore.hpp"

#include "Net/ScannerStage3.hpp"

#include <algorithm>

namespace Net {

void SendSampleStore::Reset()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_ring.clear();
    m_endpoints.clear();
    m_fingerprintCounts.clear();
}

void SendSampleStore::Add(void* endpoint, std::uint64_t fingerprint)
{
    if (!endpoint || fingerprint == 0)
        return;

    std::lock_guard<std::mutex> lock(m_mutex);
    m_ring.push_back(Entry{ endpoint, fingerprint });

    auto& entry = m_endpoints[endpoint];
    entry.history.push_back(fingerprint);
    ++entry.counts[fingerprint];

    ++m_fingerprintCounts[fingerprint];
    EvictIfNeeded();
}

bool SendSampleStore::TryGetStats(void* endpoint, EndpointStats& out) const
{
    if (!endpoint)
        return false;

    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_endpoints.find(endpoint);
    if (it == m_endpoints.end())
        return false;

    const auto& entry = it->second;
    out.total = static_cast<std::uint32_t>(entry.history.size());
    out.unique = static_cast<std::uint32_t>(entry.counts.size());
    out.lastFingerprint = entry.history.empty() ? 0 : entry.history.back();
    return true;
}

std::uint32_t SendSampleStore::FingerprintCount(std::uint64_t fingerprint) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_fingerprintCounts.find(fingerprint);
    return it != m_fingerprintCounts.end() ? it->second : 0;
}

std::size_t SendSampleStore::Size() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_ring.size();
}

void SendSampleStore::EvictIfNeeded()
{
    while (m_ring.size() > kCapacity) {
        Entry old = m_ring.front();
        m_ring.pop_front();

        auto fit = m_fingerprintCounts.find(old.fingerprint);
        if (fit != m_fingerprintCounts.end()) {
            if (fit->second > 1)
                --fit->second;
            else
                m_fingerprintCounts.erase(fit);
        }

        auto eit = m_endpoints.find(old.endpoint);
        if (eit == m_endpoints.end())
            continue;

        auto& history = eit->second.history;
        if (!history.empty()) {
            if (history.front() == old.fingerprint) {
                history.pop_front();
            } else {
                auto it = std::find(history.begin(), history.end(), old.fingerprint);
                if (it != history.end())
                    history.erase(it);
            }
        }

        auto& counts = eit->second.counts;
        auto cit = counts.find(old.fingerprint);
        if (cit != counts.end()) {
            if (cit->second > 1)
                --cit->second;
            else
                counts.erase(cit);
        }

        if (history.empty())
            m_endpoints.erase(eit);
    }
}

} // namespace Net

