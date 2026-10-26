#pragma once

#include <Windows.h>

#include <cstdint>

#if !defined(_M_X64)
#error "cs2-manual-map must be compiled for native AMD64 (_M_X64)."
#endif

namespace mmap {

inline constexpr DWORD kContextMagic = 0x50414D4D; // "MMAP"
inline constexpr DWORD kContextVersion = 3;

enum class RemoteStatus : LONG {
    pending = 0,
    relocating = 1,
    resolving_imports = 2,
    applying_protections = 3,
    flushing_instruction_cache = 4,
    registering_exceptions = 5,
    running_tls = 6,
    calling_entry_point = 7,

    success = 100,
    invalid_context = -1,
    relocation_directory_missing = -10,
    relocation_block_malformed = -11,
    relocation_type_unsupported = -12,
    import_module_failed = -20,
    import_symbol_failed = -21,
    section_protection_failed = -24,
    instruction_cache_flush_failed = -25,
    exception_registration_failed = -30,
    entry_point_rejected = -40,
};

struct RemoteProtectionRun {
    DWORD rva;
    DWORD size;
    DWORD protection;
    DWORD reserved;
};

struct RemoteContext {
    DWORD magic;
    DWORD version;
    std::uint64_t image_base;
    std::uint64_t load_library_a;
    std::uint64_t get_proc_address;
    std::uint64_t rtl_add_function_table;
    std::uint64_t virtual_protect;
    std::uint64_t flush_instruction_cache;
    std::uint64_t protection_runs;
    DWORD protection_run_count;
    volatile LONG status;
    std::uint64_t detail;
};

static_assert(sizeof(RemoteProtectionRun) == 16);
static_assert(sizeof(RemoteContext) == 80);

extern "C" DWORD WINAPI RemoteLoader(RemoteContext* context);
extern "C" void RemoteLoaderEnd();

} // namespace mmap
