#include "Util/OwnerPump.hpp"

#include <windows.h>

#include <atomic>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "Core/Logging.hpp"

namespace Util::OwnerPump {
namespace {
struct PendingTask {
    std::string name;
    std::function<void()> fn;
};

std::mutex g_queueMutex;
std::vector<PendingTask> g_queue;
std::atomic<std::uint32_t> g_ownerTid{0};
std::atomic<bool> g_allowDrain{false};
constexpr std::size_t kMaxDrainPerPass = 8;
constexpr std::size_t kMaxDrainIterations = 4;

void requeueRemaining(std::vector<PendingTask>& tasks, std::size_t index)
{
    if (index >= tasks.size())
        return;

    std::lock_guard<std::mutex> lock(g_queueMutex);
    for (std::size_t i = index; i < tasks.size(); ++i) {
        if (tasks[i].fn)
            g_queue.emplace_back(std::move(tasks[i]));
    }
}

const char* OpLabel(const char* name) {
    return (name && *name) ? name : "<unnamed>";
}

void LogQueued(const char* name, std::uint32_t fromTid, std::uint32_t ownerTid)
{
    char buf[192];
    sprintf_s(buf,
              sizeof(buf),
              "[OwnerPump] queued op=%s from=%u -> owner=%u",
              OpLabel(name),
              static_cast<unsigned>(fromTid),
              static_cast<unsigned>(ownerTid));
    WriteRawLog(buf);
}

void LogRunning(const char* name, std::uint32_t tid)
{
    char buf[192];
    sprintf_s(buf,
              sizeof(buf),
              "[OwnerPump] running op=%s on=%u",
              OpLabel(name),
              static_cast<unsigned>(tid));
    WriteRawLog(buf);
}
} // namespace

void RunOnOwner(std::function<void()> task)
{
    Post(nullptr, std::move(task));
}

void Post(const char* opName, std::function<void()> task)
{
    if (!task)
        return;

    const std::uint32_t owner = g_ownerTid.load(std::memory_order_acquire);
    const std::uint32_t current = GetCurrentThreadId();
    if (owner != 0 && current == owner) {
        LogRunning(opName, current);
        task();
        return;
    }

    PendingTask entry{};
    if (opName)
        entry.name = opName;
    entry.fn = std::move(task);

    std::lock_guard<std::mutex> lock(g_queueMutex);
    g_queue.emplace_back(std::move(entry));

    LogQueued(opName, current, owner);
}

bool Invoke(const char* opName, std::function<void()> task)
{
    if (!task)
        return false;
    const std::uint32_t owner = g_ownerTid.load(std::memory_order_acquire);
    const std::uint32_t current = GetCurrentThreadId();
    if (owner != 0 && current == owner) {
        LogRunning(opName, current);
        task();
        return true;
    }
    Post(opName, std::move(task));
    return false;
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
    if (!g_allowDrain.load(std::memory_order_acquire))
        return 0;

    const std::uint32_t ownerTid = g_ownerTid.load(std::memory_order_acquire);
    if (ownerTid == 0)
        return 0;

    const std::uint32_t currentTid = GetCurrentThreadId();
    if (currentTid != ownerTid)
        return 0;

    std::size_t ran = 0;

    for (std::size_t iteration = 0; iteration < kMaxDrainIterations; ++iteration) {
        std::vector<PendingTask> local;
        {
            std::lock_guard<std::mutex> lock(g_queueMutex);
            if (g_queue.empty())
                break;
            local.swap(g_queue);
        }

        std::size_t index = 0;
        for (; index < local.size(); ++index) {
            if (!local[index].fn)
                continue;

            try {
                LogRunning(local[index].name.c_str(), currentTid);
                local[index].fn();
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
    g_allowDrain.store(false, std::memory_order_release);
}

void SetDrainAllowed(bool enabled) noexcept
{
    g_allowDrain.store(enabled, std::memory_order_release);
}

} // namespace Util::OwnerPump
