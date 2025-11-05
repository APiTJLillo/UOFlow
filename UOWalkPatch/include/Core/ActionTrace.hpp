#pragma once
#include <windows.h>
#include <cstdint>

namespace Trace {

struct LastAction {
    DWORD tick = 0;
    char  name[64]{};
    DWORD tid = 0;
};

// Record the most recent high-level action name and time.
void MarkAction(const char* name);

// Retrieve a snapshot of the most recent action.
bool GetLastAction(LastAction& out);

// Configure and query the correlation window (ms) used by helpers.
void SetWindowMs(uint32_t ms);
uint32_t GetWindowMs();

} // namespace Trace

