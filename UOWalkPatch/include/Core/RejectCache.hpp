#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <unordered_map>

namespace Core {

class RejectCache {
public:
    explicit RejectCache(std::uint32_t ttl_ms = 300000);

    void reject(void* key, std::uint8_t reason);
    bool is_hot(void* key, std::uint64_t now_qpc, std::uint8_t* reason_out = nullptr);
    void sweep(std::uint64_t now_qpc);

    std::size_t size() const;

    static std::uint64_t QpcFrequency();

private:
    struct Node {
        std::uint64_t ts_qpc = 0;
        std::uint8_t reason = 0;
    };

    static std::uint64_t QpcTicksForMs(std::uint32_t ms);
    static std::uint64_t NowQpc();

    std::uint32_t m_ttl_ms;
    mutable std::mutex m_mutex;
    std::unordered_map<void*, Node> m_entries;
};

RejectCache& GetRejectCache();

} // namespace Core
