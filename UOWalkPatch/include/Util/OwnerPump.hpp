#pragma once

#include <cstdint>
#include <functional>
#include <cstddef>

namespace Util::OwnerPump {

// Schedule work to execute on the owner thread. If the caller is already on
// the owner thread (when known), the task runs inline.
void RunOnOwner(std::function<void()> task);

// Record or query the current owner thread identifier.
void SetOwnerThreadId(std::uint32_t tid) noexcept;
std::uint32_t GetOwnerThreadId() noexcept;

// Drain pending tasks. Only processes work when invoked by the canonical owner
// thread; other callers simply leave the queue untouched.
// Returns the number of tasks actually executed.
std::size_t DrainOnOwnerThread() noexcept;

// Clear queued work. Intended for shutdown paths.
void Reset() noexcept;

} // namespace Util::OwnerPump
