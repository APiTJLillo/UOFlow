#include "Core/Utils.hpp"
#include "Core/Logging.hpp"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

namespace Core {
namespace Utils {

bool IsOnCurrentStack(void* p) {
    NT_TIB* tib = reinterpret_cast<NT_TIB*>(NtCurrentTeb());
    return p >= tib->StackLimit && p < tib->StackBase;
}

void DumpMemory(const char* desc, void* addr, size_t len) {
    if (!addr || !len) return;
    char buffer[1024];
    sprintf_s(buffer, sizeof(buffer), "Memory dump %s at %p:", desc, addr);
    WriteRawLog(buffer);
    BYTE* bytes = (BYTE*)addr;
    char hex[128];
    char ascii[17];
    ascii[16] = 0;
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) {
            if (i > 0) {
                sprintf_s(buffer, sizeof(buffer), "  %p: %s  %s", bytes + i - 16, hex, ascii);
                WriteRawLog(buffer);
            }
            memset(hex, ' ', sizeof(hex));
            memset(ascii, '.', 16);
        }
        sprintf_s(hex + (i % 16) * 3, 4, "%02X ", bytes[i]);
        ascii[i % 16] = (bytes[i] >= 32 && bytes[i] <= 126) ? bytes[i] : '.';
    }
    size_t remain = len % 16;
    if (remain > 0) {
        sprintf_s(buffer, sizeof(buffer), "  %p: %-48s  %s", bytes + len - remain, hex, ascii);
        WriteRawLog(buffer);
    }
}

} // namespace Utils
} // namespace Core
