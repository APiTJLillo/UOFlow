#pragma once

#include <windows.h>

namespace Core::EarlyTrace {

void Initialize(HMODULE module);
void Write(const char* message);

} // namespace Core::EarlyTrace

