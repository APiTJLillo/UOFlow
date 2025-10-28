#include <windows.h>
#include <dbghelp.h>
#include <cstdio>
#include <cstdint>

namespace {
struct MappedFile {
    HANDLE file{INVALID_HANDLE_VALUE};
    HANDLE mapping{nullptr};
    void*  view{nullptr};

    ~MappedFile() {
        if (view) UnmapViewOfFile(view);
        if (mapping) CloseHandle(mapping);
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    }

    bool open(const char* path) {
        file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return false;
        mapping = CreateFileMappingA(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!mapping)
            return false;
        view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
        return view != nullptr;
    }
};

void DumpBytes(const char* label, const uint8_t* ptr, size_t len) {
    if (!ptr || !len)
        return;
    printf("%s @ %p\n", label, ptr);
    size_t rowLen = 16;
    for (size_t i = 0; i < len; i += rowLen) {
        printf("  %08llX  ", static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(ptr + i)));
        size_t remain = len - i;
        size_t count = remain < rowLen ? remain : rowLen;
        for (size_t j = 0; j < count; ++j) {
            printf("%02X ", ptr[i + j]);
        }
        printf("\n");
    }
}
} // anonymous namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: DumpAnalyzer <path-to-dmp>\n");
        return 1;
    }

    if (!SymInitialize(GetCurrentProcess(), nullptr, FALSE)) {
        printf("SymInitialize failed (%lu)\n", GetLastError());
        return 1;
    }

    MappedFile mf;
    if (!mf.open(argv[1])) {
        printf("Failed to open dump file (%lu)\n", GetLastError());
        return 1;
    }

    MINIDUMP_DIRECTORY* directory = nullptr;
    void* stream = nullptr;
    ULONG streamSize = 0;
    if (!MiniDumpReadDumpStream(mf.view, ExceptionStream, &directory, &stream, &streamSize)) {
        printf("MiniDumpReadDumpStream(ExceptionStream) failed (%lu)\n", GetLastError());
        return 1;
    }

    auto* exceptionStream = static_cast<MINIDUMP_EXCEPTION_STREAM*>(stream);
    const MINIDUMP_EXCEPTION& ex = exceptionStream->ExceptionRecord;
    const uint8_t* dumpBase = static_cast<const uint8_t*>(mf.view);
    const CONTEXT* ctxPtr = reinterpret_cast<const CONTEXT*>(dumpBase + exceptionStream->ThreadContext.Rva);
    if (!ctxPtr) {
        printf("Failed to locate CONTEXT block in dump\n");
        return 1;
    }
    const CONTEXT& ctx = *ctxPtr;

    printf("Exception code: 0x%08lX\n", ex.ExceptionCode);
    printf("Exception flags: 0x%08lX\n", ex.ExceptionFlags);
    uintptr_t exceptionAddr = static_cast<uintptr_t>(ex.ExceptionAddress);
    uintptr_t accessAddr = (ex.NumberParameters >= 2) ? static_cast<uintptr_t>(ex.ExceptionInformation[1]) : 0;
    printf("Exception address: 0x%p\n", reinterpret_cast<void*>(exceptionAddr));
    if (ex.NumberParameters >= 2) {
        printf("Access type: %llu\n", static_cast<unsigned long long>(ex.ExceptionInformation[0]));
        printf("Access address: 0x%p\n", reinterpret_cast<void*>(accessAddr));
    }

#if defined(_M_IX86) || defined(__i386__)
    printf("Registers:\n");
    printf(" EAX=%08lX  EBX=%08lX  ECX=%08lX  EDX=%08lX\n", ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx);
    printf(" ESI=%08lX  EDI=%08lX  EBP=%08lX  ESP=%08lX\n", ctx.Esi, ctx.Edi, ctx.Ebp, ctx.Esp);
    printf(" EIP=%08lX  EFlags=%08lX\n", ctx.Eip, ctx.EFlags);

    uintptr_t esp = static_cast<uintptr_t>(ctx.Esp);
    uintptr_t eip = static_cast<uintptr_t>(ctx.Eip);
#else
    printf("Registers (x86 context expected): tool compiled for different architecture.\n");
    uintptr_t esp = 0;
    uintptr_t eip = 0;
    accessAddr = 0;
#endif

    MINIDUMP_DIRECTORY* memDir = nullptr;
    void* memStream = nullptr;
    ULONG memStreamSize = 0;
    MINIDUMP_MEMORY64_LIST* mem64 = nullptr;
    if (MiniDumpReadDumpStream(mf.view, Memory64ListStream, &memDir, &memStream, &memStreamSize)) {
        mem64 = static_cast<MINIDUMP_MEMORY64_LIST*>(memStream);
    } else {
        printf("MiniDump lacks Memory64ListStream (%lu)\n", GetLastError());
    }

    auto readDumpMemory = [&](uintptr_t address, size_t length) -> const uint8_t* {
        if (!mem64)
            return nullptr;
        ULONG64 currentRva = mem64->BaseRva;
        for (ULONG64 i = 0; i < mem64->NumberOfMemoryRanges; ++i) {
            const auto& desc = mem64->MemoryRanges[i];
            ULONG64 start = desc.StartOfMemoryRange;
            ULONG64 end = start + desc.DataSize;
            if (address >= start && (address + length) <= end) {
                ULONG64 offset = currentRva + (address - start);
                return dumpBase + offset;
            }
            currentRva += desc.DataSize;
        }
        return nullptr;
    };

    if (eip) {
        if (const uint8_t* bytes = readDumpMemory(eip, 0x40)) {
            DumpBytes("Code bytes near EIP", bytes, 0x40);
        } else {
            printf("Unable to read code bytes near EIP\n");
        }
    }

    if (esp) {
        if (const uint8_t* bytes = readDumpMemory(esp, 0x40)) {
            DumpBytes("Stack (ESP)", bytes, 0x40);
        } else {
            printf("Unable to read stack at ESP\n");
        }
    }

    if (accessAddr) {
        if (const uint8_t* bytes = readDumpMemory(accessAddr, 0x20)) {
            DumpBytes("Memory at fault address", bytes, 0x20);
        } else {
            printf("Unable to read memory at fault address\n");
        }
    }

    if (ctx.Ebp) {
        uintptr_t builderArgAddr = static_cast<uintptr_t>(ctx.Ebp) + sizeof(uintptr_t) * 2;
        if (const uint8_t* argBytes = readDumpMemory(builderArgAddr, sizeof(uintptr_t))) {
            uintptr_t builderPtr = *reinterpret_cast<const uint32_t*>(argBytes);
            printf("Builder argument pointer: 0x%p\n", reinterpret_cast<void*>(builderPtr));
            if (builderPtr) {
                if (const uint8_t* builderBytes = readDumpMemory(builderPtr, 0x30)) {
                    DumpBytes("Builder struct", builderBytes, 0x30);
                } else {
                    printf("Unable to read builder struct at 0x%p\n", reinterpret_cast<void*>(builderPtr));
                }
            }
        }
    }

    if (mem64) {
        printf("EBP chain:\n");
        uintptr_t frame = static_cast<uintptr_t>(ctx.Ebp);
        for (int i = 0; i < 8 && frame; ++i) {
            const uint8_t* mem = readDumpMemory(frame, 8);
            if (!mem) {
                printf("  [0x%p] <unavailable>\n", reinterpret_cast<void*>(frame));
                break;
            }
            uintptr_t next = *reinterpret_cast<const uint32_t*>(mem);
            uintptr_t ret = *reinterpret_cast<const uint32_t*>(mem + 4);
            printf("  [0x%p] return=0x%p next=0x%p\n",
                   reinterpret_cast<void*>(frame),
                   reinterpret_cast<void*>(ret),
                   reinterpret_cast<void*>(next));
            if (next <= frame)
                break;
            frame = next;
        }
    }

    SymCleanup(GetCurrentProcess());
    return 0;
}
