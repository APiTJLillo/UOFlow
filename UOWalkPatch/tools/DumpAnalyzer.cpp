#include <windows.h>
#include <dbghelp.h>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

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
    MINIDUMP_DIRECTORY* moduleDir = nullptr;
    void* moduleStream = nullptr;
    ULONG moduleStreamSize = 0;
    MINIDUMP_MODULE_LIST* moduleList = nullptr;
    if (MiniDumpReadDumpStream(mf.view, ModuleListStream, &moduleDir, &moduleStream, &moduleStreamSize)) {
        moduleList = static_cast<MINIDUMP_MODULE_LIST*>(moduleStream);
    } else {
        printf("MiniDumpReadDumpStream(ModuleListStream) failed (%lu)\n", GetLastError());
    }
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
    MINIDUMP_MEMORY_LIST* mem32 = nullptr;
    if (MiniDumpReadDumpStream(mf.view, Memory64ListStream, &memDir, &memStream, &memStreamSize)) {
        mem64 = static_cast<MINIDUMP_MEMORY64_LIST*>(memStream);
    } else if (MiniDumpReadDumpStream(mf.view, MemoryListStream, &memDir, &memStream, &memStreamSize)) {
        mem32 = static_cast<MINIDUMP_MEMORY_LIST*>(memStream);
    } else {
        printf("MiniDump lacks Memory64ListStream/MemoryListStream (%lu)\n", GetLastError());
    }

    auto readDumpMemory = [&](uintptr_t address, size_t length) -> const uint8_t* {
        if (mem64) {
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
        } else if (mem32) {
            for (ULONG i = 0; i < mem32->NumberOfMemoryRanges; ++i) {
                const auto& desc = mem32->MemoryRanges[i];
                ULONG64 start = desc.StartOfMemoryRange;
                ULONG64 end = start + desc.Memory.DataSize;
                if (address >= start && (address + length) <= end) {
                    ULONG64 offset = desc.Memory.Rva + (address - start);
                    return dumpBase + offset;
                }
            }
        }
        return nullptr;
    };

    auto dumpRegionIfAvailable = [&](const char* label, uintptr_t address, size_t length) {
        if (!address)
            return;
        if (const uint8_t* bytes = readDumpMemory(address, length)) {
            DumpBytes(label, bytes, length);
        } else {
            printf("Unable to read %s at %p\n", label, reinterpret_cast<void*>(address));
        }
    };

    uintptr_t moduleBase = 0;
    ULONG64 moduleSize = 0;
    std::wstring modulePath;
    if (moduleList) {
        for (ULONG32 i = 0; i < moduleList->NumberOfModules; ++i) {
            const auto& mod = moduleList->Modules[i];
            ULONG64 start = mod.BaseOfImage;
            ULONG64 end = start + mod.SizeOfImage;
            if (exceptionAddr >= start && exceptionAddr < end) {
                moduleBase = static_cast<uintptr_t>(start);
                moduleSize = mod.SizeOfImage;
                auto* name = reinterpret_cast<MINIDUMP_STRING*>(const_cast<uint8_t*>(dumpBase) + mod.ModuleNameRva);
                modulePath.assign(name->Buffer, name->Length / sizeof(wchar_t));
                break;
            }
        }
    }

    if (moduleBase) {
        printf("Faulting module: base=0x%p size=0x%llX path=%S\n",
               reinterpret_cast<void*>(moduleBase),
               static_cast<unsigned long long>(moduleSize),
               modulePath.c_str());
        if (!modulePath.empty()) {
            SymLoadModuleExW(GetCurrentProcess(),
                             nullptr,
                             modulePath.c_str(),
                             nullptr,
                             static_cast<DWORD64>(moduleBase),
                             static_cast<DWORD>(moduleSize),
                             nullptr,
                             0);
        }
    }

    if (eip) {
        if (const uint8_t* bytes = readDumpMemory(eip, 0x80)) {
            DumpBytes("Code bytes near EIP", bytes, 0x80);
        } else {
            printf("Unable to read code bytes near EIP\n");
        }
    }

    if (esp) {
        constexpr size_t kStackDumpLen = 0x200;
        if (const uint8_t* bytes = readDumpMemory(esp, kStackDumpLen)) {
            DumpBytes("Stack (ESP)", bytes, kStackDumpLen);
            if (moduleBase && moduleSize) {
                printf("Stack pointers into faulting module:\n");
                std::vector<uintptr_t> seen;
                for (size_t offset = 0; offset + sizeof(uint32_t) <= kStackDumpLen; offset += sizeof(uint32_t)) {
                    uintptr_t value = *reinterpret_cast<const uint32_t*>(bytes + offset);
                    if (value >= moduleBase && value < moduleBase + moduleSize) {
                        DWORD64 displacement = 0;
                        char symbolBuffer[sizeof(SYMBOL_INFO) + 256] = {};
                        auto* symbol = reinterpret_cast<SYMBOL_INFO*>(symbolBuffer);
                        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
                        symbol->MaxNameLen = 255;
                        if (SymFromAddr(GetCurrentProcess(), value, &displacement, symbol)) {
                            printf("  [ESP+0x%02zX] %p -> %s + 0x%llX\n",
                                   offset,
                                   reinterpret_cast<void*>(value),
                                   symbol->Name,
                                   static_cast<unsigned long long>(displacement));
                        } else {
                            printf("  [ESP+0x%02zX] %p (symbol lookup failed %lu)\n",
                                   offset,
                                   reinterpret_cast<void*>(value),
                                   GetLastError());
                        }
                        seen.push_back(value);
                    }
                }
                if (!seen.empty()) {
                    printf("Approximate call stack (module frames):\n");
                    for (uintptr_t addr : seen) {
                        DWORD64 displacement = 0;
                        char symbolBuffer[sizeof(SYMBOL_INFO) + 256] = {};
                        auto* symbol = reinterpret_cast<SYMBOL_INFO*>(symbolBuffer);
                        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
                        symbol->MaxNameLen = 255;
                        if (SymFromAddr(GetCurrentProcess(), addr, &displacement, symbol)) {
                            printf("  %p -> %s + 0x%llX\n",
                                   reinterpret_cast<void*>(addr),
                                   symbol->Name,
                                   static_cast<unsigned long long>(displacement));
                        }
                    }
                }
            }
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

    dumpRegionIfAvailable("Object at EBX", static_cast<uintptr_t>(ctx.Ebx), 0x80);
    dumpRegionIfAvailable("Object at ESI", static_cast<uintptr_t>(ctx.Esi), 0x40);

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

    if (mem64 || mem32) {
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
