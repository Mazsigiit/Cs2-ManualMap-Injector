#include "remote_loader.hpp"

#include <winnt.h>

// The injector copies the bytes in the ordered .mmap section into the target.
// This translation unit is deliberately compiled without stack cookies, CFG,
// function-level linking, LTCG, or optimization. Keep RemoteLoader free of
// globals, literals, CRT calls, and helper-function calls.
#pragma runtime_checks("", off)
#pragma optimize("", off)
#pragma code_seg(push, ".mmap$m")

namespace mmap {

extern "C" __declspec(noinline) DWORD WINAPI RemoteLoader(RemoteContext* context) {
    using LoadLibraryAFn = HMODULE(WINAPI*)(LPCSTR);
    using GetProcAddressFn = FARPROC(WINAPI*)(HMODULE, LPCSTR);
    using RtlAddFunctionTableFn = BOOLEAN(NTAPI*)(PRUNTIME_FUNCTION, DWORD, DWORD64);
    using VirtualProtectFn = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
    using FlushInstructionCacheFn = BOOL(WINAPI*)(HANDLE, LPCVOID, SIZE_T);
    using DllEntryFn = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

    if (context == nullptr || context->magic != kContextMagic ||
        context->version != kContextVersion || context->image_base == 0 ||
        context->load_library_a == 0 || context->get_proc_address == 0 ||
        context->rtl_add_function_table == 0 ||
        context->virtual_protect == 0 || context->flush_instruction_cache == 0 ||
        context->protection_runs == 0 || context->protection_run_count == 0) {
        if (context != nullptr) {
            context->status = static_cast<LONG>(RemoteStatus::invalid_context);
        }
        return static_cast<DWORD>(RemoteStatus::invalid_context);
    }

    auto* const image = reinterpret_cast<unsigned char*>(context->image_base);
    auto* const dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
    auto* const nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    const auto load_library_a = reinterpret_cast<LoadLibraryAFn>(context->load_library_a);
    const auto get_proc_address = reinterpret_cast<GetProcAddressFn>(context->get_proc_address);
    const auto rtl_add_function_table =
        reinterpret_cast<RtlAddFunctionTableFn>(context->rtl_add_function_table);
    const auto virtual_protect =
        reinterpret_cast<VirtualProtectFn>(context->virtual_protect);
    const auto flush_instruction_cache =
        reinterpret_cast<FlushInstructionCacheFn>(context->flush_instruction_cache);
    auto* const protection_runs = reinterpret_cast<RemoteProtectionRun*>(
        context->protection_runs);

    context->status = static_cast<LONG>(RemoteStatus::relocating);
    const auto preferred_base = static_cast<std::uint64_t>(nt->OptionalHeader.ImageBase);
    const auto actual_base = reinterpret_cast<std::uint64_t>(image);
    const auto delta = static_cast<std::int64_t>(actual_base) -
                       static_cast<std::int64_t>(preferred_base);

    if (delta != 0) {
        const auto& reloc_directory =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_directory.VirtualAddress == 0 || reloc_directory.Size == 0) {
            context->status = static_cast<LONG>(RemoteStatus::relocation_directory_missing);
            return static_cast<DWORD>(RemoteStatus::relocation_directory_missing);
        }

        auto* cursor = image + reloc_directory.VirtualAddress;
        auto* const end = cursor + reloc_directory.Size;
        while (cursor < end) {
            auto* const block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(cursor);
            if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                cursor + block->SizeOfBlock > end ||
                ((block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(WORD)) != 0) {
                context->status = static_cast<LONG>(RemoteStatus::relocation_block_malformed);
                return static_cast<DWORD>(RemoteStatus::relocation_block_malformed);
            }

            auto* const entries = reinterpret_cast<WORD*>(
                cursor + sizeof(IMAGE_BASE_RELOCATION));
            const DWORD entry_count =
                (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

            for (DWORD index = 0; index < entry_count; ++index) {
                const WORD type = entries[index] >> 12;
                const WORD offset = entries[index] & 0x0FFF;
                if (type == IMAGE_REL_BASED_ABSOLUTE) {
                    continue;
                }
                if (type != IMAGE_REL_BASED_DIR64) {
                    context->detail = type;
                    context->status = static_cast<LONG>(RemoteStatus::relocation_type_unsupported);
                    return static_cast<DWORD>(RemoteStatus::relocation_type_unsupported);
                }

                auto* const patch = reinterpret_cast<std::uint64_t*>(
                    image + block->VirtualAddress + offset);
                *patch += static_cast<std::uint64_t>(delta);
            }
            cursor += block->SizeOfBlock;
        }
    }

    context->status = static_cast<LONG>(RemoteStatus::resolving_imports);
    const auto& import_directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_directory.VirtualAddress != 0 && import_directory.Size != 0) {
        auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            image + import_directory.VirtualAddress);
        for (; descriptor->Name != 0; ++descriptor) {
            const auto module_name = reinterpret_cast<LPCSTR>(image + descriptor->Name);
            const HMODULE module = load_library_a(module_name);
            if (module == nullptr) {
                context->detail = descriptor->Name;
                context->status = static_cast<LONG>(RemoteStatus::import_module_failed);
                return static_cast<DWORD>(RemoteStatus::import_module_failed);
            }

            auto* lookup = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                image + (descriptor->OriginalFirstThunk != 0
                             ? descriptor->OriginalFirstThunk
                             : descriptor->FirstThunk));
            auto* address = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                image + descriptor->FirstThunk);

            for (; lookup->u1.AddressOfData != 0; ++lookup, ++address) {
                FARPROC imported = nullptr;
                if (IMAGE_SNAP_BY_ORDINAL64(lookup->u1.Ordinal)) {
                    imported = get_proc_address(
                        module,
                        reinterpret_cast<LPCSTR>(
                            static_cast<ULONG_PTR>(IMAGE_ORDINAL64(lookup->u1.Ordinal))));
                    context->detail = lookup->u1.Ordinal;
                } else {
                    auto* const import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        image + lookup->u1.AddressOfData);
                    imported = get_proc_address(
                        module, reinterpret_cast<LPCSTR>(import_by_name->Name));
                    context->detail = lookup->u1.AddressOfData;
                }

                if (imported == nullptr) {
                    context->status = static_cast<LONG>(RemoteStatus::import_symbol_failed);
                    return static_cast<DWORD>(RemoteStatus::import_symbol_failed);
                }
                address->u1.Function = reinterpret_cast<ULONGLONG>(imported);
            }
        }
    }

    context->status = static_cast<LONG>(RemoteStatus::applying_protections);
    for (DWORD index = 0; index < context->protection_run_count; ++index) {
        DWORD old_protection = 0;
        if (!virtual_protect(
                image + protection_runs[index].rva,
                protection_runs[index].size,
                protection_runs[index].protection,
                &old_protection)) {
            context->detail = index;
            context->status =
                static_cast<LONG>(RemoteStatus::section_protection_failed);
            return static_cast<DWORD>(RemoteStatus::section_protection_failed);
        }
    }

    context->status = static_cast<LONG>(RemoteStatus::flushing_instruction_cache);
    if (!flush_instruction_cache(
            reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1)),
            image,
            nt->OptionalHeader.SizeOfImage)) {
        context->status =
            static_cast<LONG>(RemoteStatus::instruction_cache_flush_failed);
        return static_cast<DWORD>(RemoteStatus::instruction_cache_flush_failed);
    }

    context->status = static_cast<LONG>(RemoteStatus::registering_exceptions);
    const auto& exception_directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exception_directory.VirtualAddress != 0 && exception_directory.Size != 0) {
        auto* const runtime_functions = reinterpret_cast<PRUNTIME_FUNCTION>(
            image + exception_directory.VirtualAddress);
        const DWORD function_count = exception_directory.Size / sizeof(RUNTIME_FUNCTION);
        if (!rtl_add_function_table(runtime_functions, function_count, actual_base)) {
            context->detail = exception_directory.VirtualAddress;
            context->status =
                static_cast<LONG>(RemoteStatus::exception_registration_failed);
            return static_cast<DWORD>(RemoteStatus::exception_registration_failed);
        }
    }

    context->status = static_cast<LONG>(RemoteStatus::running_tls);
    const auto& tls_directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_directory.VirtualAddress != 0 && tls_directory.Size != 0) {
        auto* const tls = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(
            image + tls_directory.VirtualAddress);
        if (tls->AddressOfCallBacks != 0) {
            auto** callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(
                tls->AddressOfCallBacks);
            while (*callback != nullptr) {
                (*callback)(reinterpret_cast<PVOID>(image), DLL_PROCESS_ATTACH, nullptr);
                ++callback;
            }
        }
    }

    context->status = static_cast<LONG>(RemoteStatus::calling_entry_point);
    if (nt->OptionalHeader.AddressOfEntryPoint != 0) {
        const auto entry = reinterpret_cast<DllEntryFn>(
            image + nt->OptionalHeader.AddressOfEntryPoint);
        if (!entry(reinterpret_cast<HINSTANCE>(image), DLL_PROCESS_ATTACH, nullptr)) {
            context->status = static_cast<LONG>(RemoteStatus::entry_point_rejected);
            return static_cast<DWORD>(RemoteStatus::entry_point_rejected);
        }
    }

    context->detail = 0;
    context->status = static_cast<LONG>(RemoteStatus::success);
    return static_cast<DWORD>(RemoteStatus::success);
}

} // namespace mmap

#pragma code_seg(pop)

#pragma code_seg(push, ".mmap$z")

namespace mmap {

extern "C" __declspec(noinline) void RemoteLoaderEnd() {}

} // namespace mmap

#pragma code_seg(pop)
