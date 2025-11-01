#pragma once

#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <deque>
#include <mutex>
#include <unordered_map>
#include "Net/ScannerStage3.hpp"

namespace Net {

class SendSampleStore {
public:
    static constexpr std::uint16_t kMaxFrames = 12;

    struct EndpointStats {
        std::uint64_t lastFingerprint = 0;
        std::uint32_t total = 0;
        std::uint32_t unique = 0;
    };

    void Reset();
    void Add(void* endpoint, std::uint64_t fingerprint);
    bool TryGetStats(void* endpoint, EndpointStats& out) const;
    std::uint32_t FingerprintCount(std::uint64_t fingerprint) const;
    std::size_t Size() const;
    static std::uint64_t HashFrames(Scanner::ModuleMap& moduleMap,
                                    void* const* frames,
                                    std::uint16_t captured)
    {
        if (!frames || captured == 0)
            return 0;

        const std::uint16_t limit = std::min<std::uint16_t>(captured, kMaxFrames);
        Scanner::ModuleMap& map = moduleMap;
        const auto* primary = map.primaryExecutable();
        if (!primary || !primary->module)
            return 0;

        std::uint64_t hash = 1469598103934665603ull;
        bool used = false;

        for (std::uint16_t i = 0; i < limit; ++i) {
            void* frame = frames[i];
            if (!frame)
                continue;

            const auto* module = map.findByAddress(frame);
            if (!module || module->module != primary->module)
                continue;

            used = true;
            const auto addr = reinterpret_cast<std::uintptr_t>(frame);
            const auto rva = static_cast<std::uint64_t>(addr - module->base);
            hash ^= (rva + 0x9E3779B97F4A7C15ull + (static_cast<std::uint64_t>(i) << 32));
            hash *= 1099511628211ull;
        }

        return used ? hash : 0;
    }

private:
    struct Entry {
        void* endpoint = nullptr;
        std::uint64_t fingerprint = 0;
    };

    struct EndpointEntry {
        std::deque<std::uint64_t> history;
        std::unordered_map<std::uint64_t, std::uint32_t> counts;
    };

    void EvictIfNeeded();

    mutable std::mutex m_mutex;
    std::deque<Entry> m_ring;
    std::unordered_map<void*, EndpointEntry> m_endpoints;
    std::unordered_map<std::uint64_t, std::uint32_t> m_fingerprintCounts;
    static constexpr std::size_t kCapacity = 256;
};

} // namespace Net
