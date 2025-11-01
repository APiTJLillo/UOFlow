#include "Core/SendRing.hpp"

#include <algorithm>
#include <utility>
#include <windows.h>

namespace {

std::atomic<std::uint64_t> g_qpcFrequency{0};
Core::SendRing g_globalSendRing;

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

SendRing::SendRing()
    : m_writeSeq(0)
    , m_lastSnapshotSeq(0)
{
    for (auto& seq : m_sequences)
        seq.store(0, std::memory_order_relaxed);
    LoadFrequency();
}

void SendRing::push(void* func, std::uint32_t callsite_hash, std::uint32_t flags)
{
    if (!func)
        return;

    Entry entry{};
    entry.func = func;
    entry.hash = callsite_hash;
    entry.flags = flags;
    entry.tid = GetCurrentThreadId();
    entry.ts_qpc = NowQpc();

    const std::uint64_t seq = m_writeSeq.fetch_add(1, std::memory_order_relaxed) + 1ull;
    const std::size_t slot = static_cast<std::size_t>(seq & kMask);

    m_sequences[slot].store(0, std::memory_order_relaxed);
    m_entries[slot] = entry;
    m_sequences[slot].store(seq, std::memory_order_release);
}

std::size_t SendRing::snapshot(std::vector<Entry>& out, std::uint64_t max_age_us)
{
    out.clear();

    const std::uint64_t now = NowQpc();
    const std::uint64_t maxAgeTicks = ToQpcTicks(max_age_us);
    const std::uint64_t head = m_writeSeq.load(std::memory_order_acquire);
    const std::uint64_t lastSnapshot = m_lastSnapshotSeq.load(std::memory_order_acquire);
    const std::uint64_t minSeq = (head > kCapacity) ? (head - kCapacity) : 0ull;
    const std::uint64_t lowerBound = (lastSnapshot > minSeq) ? lastSnapshot : minSeq;

    std::vector<std::pair<std::uint64_t, Entry>> collected;
    collected.reserve(kCapacity);

    for (std::size_t slot = 0; slot < kCapacity; ++slot) {
        std::uint64_t seqFirst = m_sequences[slot].load(std::memory_order_acquire);
        if (seqFirst == 0 || seqFirst <= lowerBound || seqFirst > head)
            continue;

        Entry entry = m_entries[slot];
        std::uint64_t seqSecond = m_sequences[slot].load(std::memory_order_acquire);
        if (seqFirst != seqSecond || seqSecond <= lowerBound || seqSecond > head)
            continue;

        if (maxAgeTicks != 0 && now > entry.ts_qpc) {
            const std::uint64_t ageTicks = now - entry.ts_qpc;
            if (ageTicks > maxAgeTicks)
                continue;
        }

        collected.emplace_back(seqSecond, entry);
    }

    if (collected.empty()) {
        m_lastSnapshotSeq.store(lowerBound, std::memory_order_release);
        return 0;
    }

    std::sort(collected.begin(),
              collected.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    std::uint64_t maxSeq = lowerBound;
    for (const auto& pair : collected) {
        out.push_back(pair.second);
        if (pair.first > maxSeq)
            maxSeq = pair.first;
    }

    m_lastSnapshotSeq.store(maxSeq, std::memory_order_release);
    return out.size();
}

void SendRing::clear()
{
    for (auto& seq : m_sequences)
        seq.store(0, std::memory_order_relaxed);
    m_writeSeq.store(0, std::memory_order_relaxed);
    m_lastSnapshotSeq.store(0, std::memory_order_relaxed);
}

std::uint32_t SendRing::load_percent() const
{
    const std::uint64_t head = m_writeSeq.load(std::memory_order_acquire);
    const std::uint64_t current = head > kCapacity ? kCapacity : head;
    if (current >= kCapacity)
        return 100u;
    return static_cast<std::uint32_t>((current * 100ull) / kCapacity);
}

std::size_t SendRing::size() const
{
    const std::uint64_t head = m_writeSeq.load(std::memory_order_acquire);
    return static_cast<std::size_t>(head > kCapacity ? kCapacity : head);
}

std::uint64_t SendRing::newest_age_us() const
{
    const std::uint64_t freq = QueryFrequency();
    if (freq == 0)
        return 0;

    const std::uint64_t head = m_writeSeq.load(std::memory_order_acquire);
    if (head == 0)
        return 0;

    const std::size_t index = static_cast<std::size_t>((head - 1) & kMask);
    std::uint64_t seq = m_sequences[index].load(std::memory_order_acquire);
    if (seq == 0)
        return 0;

    Entry entry = m_entries[index];
    const std::uint64_t seqVerify = m_sequences[index].load(std::memory_order_acquire);
    if (seq != seqVerify)
        return 0;

    const std::uint64_t now = NowQpc();
    if (now <= entry.ts_qpc)
        return 0;

    const std::uint64_t ageTicks = now - entry.ts_qpc;
    return (ageTicks * 1000000ull) / freq;
}

std::uint64_t SendRing::QueryFrequency()
{
    return LoadFrequency();
}

std::uint64_t SendRing::ToQpcTicks(std::uint64_t usec)
{
    const std::uint64_t freq = QueryFrequency();
    if (freq == 0 || usec == 0)
        return 0;
    const std::uint64_t numerator = freq * usec;
    return numerator / 1000000ull;
}

std::uint64_t SendRing::NowQpc()
{
    LARGE_INTEGER li{};
    QueryPerformanceCounter(&li);
    return static_cast<std::uint64_t>(li.QuadPart);
}

SendRing& GetSendRing()
{
    return g_globalSendRing;
}

} // namespace Core
