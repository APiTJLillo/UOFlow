#include "Util/OwnerPump.hpp"

#include <windows.h>

#include <atomic>
#include <mutex>
#include <utility>
#include <vector>

namespace Util::OwnerPump {
namespace {
std::mutex g_queueMutex;
std::vector<std::function<void()>> g_queue;
std::atomic<std::uint32_t> g_ownerTid{0};
constexpr std::size_t kMaxDrainPerPass = 8;
constexpr std::size_t kMaxDrainIterations = 4;

void requeueRemaining(std::vector<std::function<void()>>& tasks, std::size_t index)
{
    if (index >= tasks.size())
        return;

    std::lock_guard<std::mutex> lock(g_queueMutex);
    for (std::size_t i = index; i < tasks.size(); ++i) {
        if (tasks[i])
            g_queue.emplace_back(std::move(tasks[i]));
    }
}
} // namespace

void RunOnOwner(std::function<void()> task)
{
    if (!task)
        return;

    std::lock_guard<std::mutex> lock(g_queueMutex);
    g_queue.emplace_back(std::move(task));
}

void SetOwnerThreadId(std::uint32_t tid) noexcept
{
    g_ownerTid.store(tid, std::memory_order_release);
}

std::uint32_t GetOwnerThreadId() noexcept
{
    return g_ownerTid.load(std::memory_order_acquire);
}

std::size_t DrainOnOwnerThread() noexcept
{
    const std::uint32_t ownerTid = g_ownerTid.load(std::memory_order_acquire);
    if (ownerTid == 0)
        return 0;

    const std::uint32_t currentTid = GetCurrentThreadId();
    if (currentTid != ownerTid)
        return 0;

    std::size_t ran = 0;

    for (std::size_t iteration = 0; iteration < kMaxDrainIterations; ++iteration) {
        std::vector<std::function<void()>> local;
        {
            std::lock_guard<std::mutex> lock(g_queueMutex);
            if (g_queue.empty())
                break;
            local.swap(g_queue);
        }

        std::size_t index = 0;
        for (; index < local.size(); ++index) {
            if (!local[index])
                continue;

            try {
                local[index]();
            } catch (...) {
                // Swallow exceptions to avoid destabilising the owner thread.
            }

            ++ran;
            if (ran >= kMaxDrainPerPass) {
                ++index;
                break;
            }
        }

        if (index < local.size()) {
            requeueRemaining(local, index);
            break;
        }

        if (ran >= kMaxDrainPerPass)
            break;
    }

    return ran;
}

void Reset() noexcept
{
    {
        std::lock_guard<std::mutex> lock(g_queueMutex);
        g_queue.clear();
    }
    g_ownerTid.store(0, std::memory_order_release);
}

} // namespace Util::OwnerPump
