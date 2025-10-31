#pragma once

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <utility>

namespace sp {

bool is_readable(const void* address, std::size_t bytes);
bool is_executable_code_ptr(const void* address);
bool is_plausible_vtbl_entry(const void* address);

template <typename Fn>
bool seh_probe(Fn&& fn, DWORD* exceptionCodeOut = nullptr) noexcept {
    DWORD code = 0;
    bool ok = false;
    __try {
        std::forward<Fn>(fn)();
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        code = GetExceptionCode();
        ok = false;
    }

    if (exceptionCodeOut)
        *exceptionCodeOut = ok ? 0 : code;
    return ok;
}

} // namespace sp

