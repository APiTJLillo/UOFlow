#pragma once
#include <windows.h>
#include <psapi.h>
#include <stdint.h>

namespace Core {
namespace PatternScan {
    BYTE* FindBytes(BYTE* start, SIZE_T size, const BYTE* pattern, SIZE_T patSize);
    BYTE* FindPattern(BYTE* base, SIZE_T size, const BYTE* pat, SIZE_T patLen);
    struct Pattern {
        size_t  len;
        uint8_t raw[128];
        uint8_t mask[128];
    };
    size_t ParsePattern(const char* sig, Pattern& out);
    BYTE* FindPatternText(const char* sig);
} // namespace PatternScan
} // namespace Core

using Core::PatternScan::FindBytes;
using Core::PatternScan::FindPattern;
using Core::PatternScan::Pattern;
using Core::PatternScan::ParsePattern;
using Core::PatternScan::FindPatternText;
