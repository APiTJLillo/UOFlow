#include "Core/PatternScan.hpp"
#include <string.h>

namespace Core {
namespace PatternScan {

BYTE* FindBytes(BYTE* start, SIZE_T size, const BYTE* pattern, SIZE_T patSize) {
    if (!start || !pattern || !patSize || size < patSize)
        return nullptr;
    for (SIZE_T i = 0; i + patSize <= size; ++i) {
        if (memcmp(start + i, pattern, patSize) == 0)
            return start + i;
    }
    return nullptr;
}

BYTE* FindPattern(BYTE* base, SIZE_T size, const BYTE* pat, SIZE_T patLen) {
    for (SIZE_T i = 0; i + patLen <= size; ++i) {
        SIZE_T k = 0;
        while (k < patLen && (pat[k] == '?' || base[i + k] == pat[k]))
            ++k;
        if (k == patLen)
            return base + i;
    }
    return nullptr;
}

size_t ParsePattern(const char* sig, Pattern& out) {
    size_t i = 0;
    while (*sig && i < sizeof(out.raw)) {
        if (*sig == ' ') { ++sig; continue; }
        if (sig[0] == '?' && sig[1] == '?') {
            out.mask[i] = 0; out.raw[i++] = 0; sig += 2;
        } else {
            unsigned v; sscanf_s(sig, "%02x", &v);
            out.mask[i] = 1; out.raw[i++] = (uint8_t)v; sig += 2;
        }
    }
    out.len = i;
    return i;
}

BYTE* FindPatternText(const char* sig) {
    Pattern p{}; ParsePattern(sig, p);
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(nullptr), &mi, sizeof(mi)))
        return nullptr;
    uint8_t* base = (uint8_t*)mi.lpBaseOfDll;
    uint8_t* end = base + mi.SizeOfImage;
    for (uint8_t* cur = base; cur + p.len <= end; ++cur) {
        size_t k = 0;
        while (k < p.len && (!p.mask[k] || cur[k] == p.raw[k]))
            ++k;
        if (k == p.len)
            return cur;
    }
    return nullptr;
}

} // namespace PatternScan
} // namespace Core
