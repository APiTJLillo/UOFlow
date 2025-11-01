#pragma once

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <functional>

namespace Util::RegionWatch {

using Callback = std::function<void()>;

void SetEnabled(bool enabled) noexcept;
bool IsEnabled() noexcept;

// Target pointer is typically the networkConfig structure.
void SetWatchPointer(void* pointer) noexcept;
void ClearWatch() noexcept;

void SetCallback(Callback cb);

// Update cached region details from a fresh VirtualQuery sample.
void UpdateRegionInfo(const MEMORY_BASIC_INFORMATION& info) noexcept;

// Notify the watcher that a range was touched by a memory API and provide the
// resulting state if available. Range is specified by base/size pair taken
// from the API inputs or outputs.
void NotifyRange(const char* source,
                 uintptr_t rangeBase,
                 SIZE_T rangeSize,
                 const MEMORY_BASIC_INFORMATION* afterState) noexcept;

// Notify that a view was unmapped; used to clear cached region metadata.
void NotifyUnmap(const char* source,
                 const MEMORY_BASIC_INFORMATION* beforeState) noexcept;

uintptr_t GetWatchBase() noexcept;
SIZE_T GetWatchSpan() noexcept;
bool HasWatch() noexcept;

} // namespace Util::RegionWatch

