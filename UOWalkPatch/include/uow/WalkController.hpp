#pragma once

#include <windows.h>

#include <atomic>
#include <array>
#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <optional>

namespace uow {

struct SendEndpoint; // forward for future use if needed

struct AckSample {
    bool ok = true;
    std::uint32_t seq = 0;
    std::uint64_t t_ms = 0;
};

class AckHistory {
public:
    static constexpr std::size_t N = 32;

    void push(bool ok, std::uint32_t seq, std::uint64_t now_ms) {
        m_buf[m_head] = {ok, seq, now_ms};
        m_head = (m_head + 1) % N;
        if (m_count < N)
            ++m_count;
        if (!ok)
            m_lastFailMs = now_ms;
    }

    bool clean_since(std::uint64_t window_ms, std::uint64_t now_ms) const {
        if (m_count == 0)
            return false;
        return (now_ms - m_lastFailMs) >= window_ms;
    }

    void reset(std::uint64_t now_ms) {
        m_head = 0;
        m_count = 0;
        m_lastFailMs = now_ms;
        for (auto& entry : m_buf)
            entry = {};
    }

private:
    std::array<AckSample, N> m_buf{};
    std::size_t m_head = 0;
    std::size_t m_count = 0;
    std::uint64_t m_lastFailMs = 0;
};

class WalkController {
public:
    using AckNudgeCallback = void(*)(std::uint64_t);

    void init(std::uint64_t start_ms) {
        m_socketBirthMs = start_ms;
        m_stepDelayMs.store(kBaseDelay, std::memory_order_relaxed);
        m_maxInflight.store(1, std::memory_order_relaxed);
        m_lastTightenMs = start_ms;
        m_relaxTier = 0;
        m_hist.reset(start_ms);
    }

    void set_ack_nudge_callback(AckNudgeCallback cb) {
        m_ackNudge = cb;
    }

    void force_step_delay(int ms) {
        ms = std::clamp(ms, kBaseDelayTight, kMaxRelaxMs);
        m_stepDelayMs.store(ms, std::memory_order_relaxed);
    }

    void force_max_inflight(int n) {
        if (n < 1)
            n = 1;
        m_maxInflight.store(n, std::memory_order_relaxed);
    }

    void onAck(std::uint32_t seq, bool ok, std::uint64_t now_ms) {
        m_hist.push(ok, seq, now_ms);
        if (!ok) {
            // Immediate tighten & backoff
            m_stepDelayMs.store(kBaseDelayTight, std::memory_order_relaxed);
            m_maxInflight.store(1, std::memory_order_relaxed);
            m_lastTightenMs = now_ms;
            m_relaxTier = 0;
            schedule_ack_nudge(now_ms);
        }
    }

    void reevaluate(std::uint64_t now_ms) {
        if (now_ms - m_lastTightenMs < kMinTightenHoldMs)
            return;

        const bool link_old = (now_ms - m_socketBirthMs) >= kAgeForRelaxMs;
        const bool clean    = m_hist.clean_since(kCleanWindowMs, now_ms);

        if (link_old && clean) {
            int current = m_stepDelayMs.load(std::memory_order_relaxed);
            int target = std::min<int>(kBaseDelay + kRelaxStepMs * m_relaxTier, kMaxRelaxMs);
            if (current < target) {
                m_stepDelayMs.store(target, std::memory_order_relaxed);
            } else if (current == target && m_relaxTier < kRelaxTiers) {
                ++m_relaxTier;
                target = std::min<int>(kBaseDelay + kRelaxStepMs * m_relaxTier, kMaxRelaxMs);
                m_stepDelayMs.store(target, std::memory_order_relaxed);
            }

            if (m_maxInflight.load(std::memory_order_relaxed) == 1)
                m_maxInflight.store(2, std::memory_order_relaxed);
        } else {
            if (m_stepDelayMs.load(std::memory_order_relaxed) > kBaseDelay)
                m_stepDelayMs.store(kBaseDelay, std::memory_order_relaxed);
            m_relaxTier = 0;
            m_maxInflight.store(1, std::memory_order_relaxed);
        }
    }

    int stepDelayMs() const {
        return m_stepDelayMs.load(std::memory_order_relaxed);
    }

    int maxInflight() const {
        return m_maxInflight.load(std::memory_order_relaxed);
    }

private:
    void schedule_ack_nudge(std::uint64_t now_ms) {
        if (m_ackNudge)
            m_ackNudge(now_ms);
    }

    static constexpr int      kBaseDelay        = 350;
    static constexpr int      kBaseDelayTight   = 320;
    static constexpr std::uint64_t kMinTightenHoldMs = 3000;
    static constexpr std::uint64_t kAgeForRelaxMs    = 45'000;
    static constexpr std::uint64_t kCleanWindowMs    = 20'000;
    static constexpr int      kRelaxStepMs      = 20;
    static constexpr int      kMaxRelaxMs       = 480;
    static constexpr int      kRelaxTiers       = 4;

    std::atomic<int> m_stepDelayMs{ kBaseDelay };
    std::atomic<int> m_maxInflight{ 1 };
    std::uint64_t    m_socketBirthMs = 0;
    std::uint64_t    m_lastTightenMs = 0;
    int              m_relaxTier = 0;
    AckHistory       m_hist;
    AckNudgeCallback m_ackNudge = nullptr;
};

} // namespace uow
