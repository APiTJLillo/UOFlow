#include "Util/RegionWatch.hpp"

#include <limits>
#include <mutex>
#include <utility>

#include "Core/Logging.hpp"

namespace Util::RegionWatch {
namespace {
struct WatchState {
    uintptr_t target = 0;
    uintptr_t base = 0;
    SIZE_T span = 0;
    bool hasInfo = false;
    bool enabled = true;
};

std::mutex g_mutex;
WatchState g_state{};
Callback g_callback{};

constexpr uintptr_t kPageMask = 0xFFFF;

uintptr_t Align64k(uintptr_t value) noexcept
{
    return value & ~kPageMask;
}

bool Contains(uintptr_t base, SIZE_T span, uintptr_t address) noexcept
{
    if (span == 0)
        return false;
    uintptr_t end = base + span;
    if (end < base)
        end = std::numeric_limits<uintptr_t>::max();
    return address >= base && address < end;
}

bool Intersects(uintptr_t rangeBase, SIZE_T rangeSize, uintptr_t target, const MEMORY_BASIC_INFORMATION* after) noexcept
{
    if (target == 0)
        return false;
    if (rangeSize != 0 && Contains(rangeBase, rangeSize, target))
        return true;
    if (after && after->RegionSize != 0) {
        auto afterBase = reinterpret_cast<uintptr_t>(after->BaseAddress);
        if (Contains(afterBase, after->RegionSize, target))
            return true;
    }
    return false;
}

void UpdateFromAfter(const MEMORY_BASIC_INFORMATION& info, WatchState& state) noexcept
{
    uintptr_t base = reinterpret_cast<uintptr_t>(info.BaseAddress);
    if (base != 0) {
        state.base = Align64k(base);
    }
    if (info.RegionSize != 0)
        state.span = info.RegionSize;
    state.hasInfo = true;
}

} // namespace

void SetEnabled(bool enabled) noexcept
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_state.enabled = enabled;
}

bool IsEnabled() noexcept
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_state.enabled;
}

void SetWatchPointer(void* pointer) noexcept
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!pointer) {
        g_state = {};
        return;
    }

    uintptr_t addr = reinterpret_cast<uintptr_t>(pointer);
    g_state.target = addr;
    g_state.base = Align64k(addr);
    if (g_state.span == 0)
        g_state.span = 0x10000;
    g_state.hasInfo = false;
}

void ClearWatch() noexcept
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_state = {};
}

void SetCallback(Callback cb)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_callback = std::move(cb);
}

void UpdateRegionInfo(const MEMORY_BASIC_INFORMATION& info) noexcept
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_state.target == 0)
        return;
    if (!Contains(reinterpret_cast<uintptr_t>(info.BaseAddress), info.RegionSize, g_state.target))
        return;
    UpdateFromAfter(info, g_state);
}

void NotifyRange(const char* source,
                 uintptr_t rangeBase,
                 SIZE_T rangeSize,
                 const MEMORY_BASIC_INFORMATION* afterState) noexcept
{
    (void)source;
    Callback cb;
    uintptr_t baseForLog = 0;

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_state.enabled || g_state.target == 0)
            return;
        if (!Intersects(rangeBase, rangeSize, g_state.target, afterState))
            return;

        if (afterState) {
            UpdateFromAfter(*afterState, g_state);
            if (afterState->State == MEM_COMMIT && afterState->Protect == PAGE_READWRITE) {
                cb = g_callback;
                baseForLog = g_state.base ? g_state.base
                                          : Align64k(reinterpret_cast<uintptr_t>(afterState->BaseAddress));
            }
        }
    }

    if (!cb)
        return;

    if (baseForLog == 0)
        baseForLog = Align64k(rangeBase);

    Log::Logf(Log::Level::Info,
              Log::Category::Hooks,
              "[SB][WATCH] netcfg %p -> RW/COMMIT; scanning now.",
              reinterpret_cast<void*>(baseForLog));

    cb();
}

void NotifyUnmap(const char* /*source*/, const MEMORY_BASIC_INFORMATION* beforeState) noexcept
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (beforeState && Contains(reinterpret_cast<uintptr_t>(beforeState->BaseAddress),
                                beforeState->RegionSize,
                                g_state.target)) {
        g_state.hasInfo = false;
        g_state.span = 0;
    }
}

uintptr_t GetWatchBase() noexcept
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_state.base;
}

SIZE_T GetWatchSpan() noexcept
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_state.span;
}

bool HasWatch() noexcept
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_state.target != 0;
}

} // namespace Util::RegionWatch
