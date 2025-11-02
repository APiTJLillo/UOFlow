#pragma once

#include <cstdint>
#include <functional>

namespace Core::Bind {

using TaskFn = std::function<void()>;

// Schedule work to run on the supplied owner thread. Returns true when the
// primary posting mechanism succeeded.
bool PostToOwner(std::uint32_t ownerTid, TaskFn&& fn, const char* tag);

// Attempts PostToOwner, then applies configured fallbacks (APC / remote thread)
// if the owner does not acknowledge execution within the configured timeout.
bool DispatchWithFallback(std::uint32_t ownerTid, TaskFn&& fn, const char* tag);

} // namespace Core::Bind
