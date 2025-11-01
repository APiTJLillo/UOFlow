#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <vector>

namespace Core {

class SendRing {
public:
    struct Entry {
        std::uint32_t hash = 0;
        void* func = nullptr;
        std::uint32_t tid = 0;
        std::uint32_t flags = 0;
        std::uint64_t ts_qpc = 0;
    };

    SendRing();

    void push(void* func, std::uint32_t callsite_hash, std::uint32_t flags = 0);
    std::size_t snapshot(std::vector<Entry>& out, std::uint64_t max_age_us);
    void clear();

    std::uint32_t load_percent() const;
    std::size_t size() const;
    std::uint64_t newest_age_us() const;
    std::size_t capacity() const { return kCapacity; }

private:
    static constexpr std::size_t kCapacity = 128;
    static constexpr std::size_t kMask = kCapacity - 1;

    static std::uint64_t QueryFrequency();
    static std::uint64_t ToQpcTicks(std::uint64_t usec);
    static std::uint64_t NowQpc();

    std::array<Entry, kCapacity> m_entries{};
    std::array<std::atomic<std::uint64_t>, kCapacity> m_sequences{};
    std::atomic<std::uint64_t> m_writeSeq;
    std::atomic<std::uint64_t> m_lastSnapshotSeq;
};

SendRing& GetSendRing();

} // namespace Core
