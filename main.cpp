#include "remote_loader.hpp"

#include <TlHelp32.h>
#include <Windows.h>
#include <winnt.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

constexpr std::uint64_t kMaximumImageSize = 512ull * 1024ull * 1024ull;

[[noreturn]] void throw_last_error(const char* operation) {
    throw std::system_error(
        static_cast<int>(GetLastError()), std::system_category(), operation);
}

bool range_is_valid(
    const std::uint64_t offset,
    const std::uint64_t length,
    const std::uint64_t total) noexcept {
    return offset <= total && length <= total - offset;
}

class UniqueHandle {
public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE handle) noexcept : handle_(handle) {}
    ~UniqueHandle() { reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)) {}

    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }
    [[nodiscard]] explicit operator bool() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    void reset(HANDLE replacement = nullptr) noexcept {
        if (*this) {
            CloseHandle(handle_);
        }
        handle_ = replacement;
    }

private:
    HANDLE handle_ = nullptr;
};

class RemoteAllocation {
public:
    RemoteAllocation(HANDLE process, void* address) noexcept
        : process_(process), address_(address) {}

    ~RemoteAllocation() { reset(); }

    RemoteAllocation(const RemoteAllocation&) = delete;
    RemoteAllocation& operator=(const RemoteAllocation&) = delete;

    RemoteAllocation(RemoteAllocation&& other) noexcept
        : process_(std::exchange(other.process_, nullptr)),
          address_(std::exchange(other.address_, nullptr)) {}

    RemoteAllocation& operator=(RemoteAllocation&& other) noexcept {
        if (this != &other) {
            reset();
            process_ = std::exchange(other.process_, nullptr);
            address_ = std::exchange(other.address_, nullptr);
        }
        return *this;
    }

    [[nodiscard]] void* get() const noexcept { return address_; }

    void* release() noexcept { return std::exchange(address_, nullptr); }

    void reset() noexcept {
        if (process_ != nullptr && address_ != nullptr) {
            VirtualFreeEx(process_, address_, 0, MEM_RELEASE);
        }
        address_ = nullptr;
    }

private:
    HANDLE process_ = nullptr;
    void* address_ = nullptr;
};

std::vector<std::byte> read_binary_file(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) {
        throw std::runtime_error("Unable to open the DLL");
    }

    const auto end = stream.tellg();
    if (end <= std::streampos{0}) {
        throw std::runtime_error("The DLL is empty");
    }
    const auto file_size =
        static_cast<std::uint64_t>(static_cast<std::streamoff>(end));
    if (file_size > kMaximumImageSize) {
        throw std::runtime_error("The DLL exceeds the 512 MiB input limit");
    }

    std::vector<std::byte> result(static_cast<std::size_t>(file_size));
    stream.seekg(0, std::ios::beg);
    stream.read(reinterpret_cast<char*>(result.data()),
                static_cast<std::streamsize>(result.size()));
    if (!stream) {
        throw std::runtime_error("Unable to read the complete DLL");
    }
    return result;
}

class PeImage {
public:
    explicit PeImage(const std::filesystem::path& path) {
        const auto file = read_binary_file(path);
        parse_and_map(file);
        validate_relocations();
        validate_imports();
        validate_exception_directory();
        validate_tls_directory();

        const auto& delay =
            nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        if (delay.VirtualAddress != 0 || delay.Size != 0) {
            throw std::runtime_error("Delay-load imports are not supported");
        }

        const auto& clr =
            nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        if (clr.VirtualAddress != 0 || clr.Size != 0) {
            throw std::runtime_error("Managed/.NET DLLs are not supported");
        }
    }

    [[nodiscard]] const IMAGE_NT_HEADERS64* nt() const noexcept {
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mapped_.data());
        return reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            mapped_.data() + dos->e_lfanew);
    }

    [[nodiscard]] const IMAGE_SECTION_HEADER* sections() const noexcept {
        return IMAGE_FIRST_SECTION(nt());
    }

    [[nodiscard]] std::span<const std::byte> bytes() const noexcept {
        return {mapped_.data(), mapped_.size()};
    }

    [[nodiscard]] bool has_relocations() const noexcept {
        const auto& directory =
            nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        return directory.VirtualAddress != 0 && directory.Size != 0 &&
               (nt()->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) == 0;
    }

    [[nodiscard]] bool has_tls() const noexcept {
        const auto& directory =
            nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        return directory.VirtualAddress != 0 && directory.Size != 0;
    }

private:
    [[nodiscard]] bool image_range_is_valid(
        const std::uint64_t rva, const std::uint64_t size) const noexcept {
        return range_is_valid(rva, size, mapped_.size());
    }

    [[nodiscard]] bool has_terminated_string(const std::uint64_t rva) const noexcept {
        if (!image_range_is_valid(rva, 1)) {
            return false;
        }
        const auto* begin = reinterpret_cast<const char*>(mapped_.data() + rva);
        return std::memchr(begin, '\0', mapped_.size() - static_cast<std::size_t>(rva)) !=
               nullptr;
    }

    void parse_and_map(const std::vector<std::byte>& file) {
        if (!range_is_valid(0, sizeof(IMAGE_DOS_HEADER), file.size())) {
            throw std::runtime_error("File is too small for a DOS header");
        }

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) {
            throw std::runtime_error("Invalid DOS header");
        }

        const auto nt_offset = static_cast<std::uint64_t>(dos->e_lfanew);
        const auto fixed_nt_size = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (!range_is_valid(nt_offset, fixed_nt_size, file.size())) {
            throw std::runtime_error("Truncated NT headers");
        }

        const auto* signature = reinterpret_cast<const DWORD*>(file.data() + nt_offset);
        if (*signature != IMAGE_NT_SIGNATURE) {
            throw std::runtime_error("Invalid PE signature");
        }

        const auto* file_header = reinterpret_cast<const IMAGE_FILE_HEADER*>(
            file.data() + nt_offset + sizeof(DWORD));
        const auto optional_offset = nt_offset + fixed_nt_size;
        if (file_header->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
            !range_is_valid(optional_offset, file_header->SizeOfOptionalHeader, file.size())) {
            throw std::runtime_error("Truncated PE32+ optional header");
        }

        const auto* optional = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(
            file.data() + optional_offset);
        if (file_header->Machine != IMAGE_FILE_MACHINE_AMD64 ||
            optional->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            throw std::runtime_error("The payload must be a native AMD64/PE32+ DLL");
        }
        if ((file_header->Characteristics & IMAGE_FILE_DLL) == 0) {
            throw std::runtime_error("The PE image is not marked as a DLL");
        }
        if (file_header->NumberOfSections == 0 || file_header->NumberOfSections > 96) {
            throw std::runtime_error("Invalid PE section count");
        }
        if (optional->NumberOfRvaAndSizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
            throw std::runtime_error("The optional header has too few data directories");
        }
        if (optional->SectionAlignment == 0 || optional->FileAlignment == 0 ||
            optional->ImageBase == 0 || (optional->ImageBase & 0xFFFFull) != 0 ||
            optional->SizeOfImage == 0 || optional->SizeOfImage > kMaximumImageSize ||
            optional->SizeOfHeaders == 0 ||
            optional->SizeOfHeaders > optional->SizeOfImage ||
            optional->SizeOfHeaders > file.size()) {
            throw std::runtime_error("Invalid PE image/header sizes");
        }
        if (optional->AddressOfEntryPoint >= optional->SizeOfImage &&
            optional->AddressOfEntryPoint != 0) {
            throw std::runtime_error("Entry point is outside the image");
        }

        const auto section_table_offset =
            optional_offset + file_header->SizeOfOptionalHeader;
        const auto section_table_size =
            static_cast<std::uint64_t>(file_header->NumberOfSections) *
            sizeof(IMAGE_SECTION_HEADER);
        if (!range_is_valid(section_table_offset, section_table_size, file.size()) ||
            !range_is_valid(section_table_offset, section_table_size,
                            optional->SizeOfHeaders)) {
            throw std::runtime_error("Truncated PE section table");
        }

        const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            file.data() + section_table_offset);
        std::vector<std::pair<std::uint64_t, std::uint64_t>> virtual_ranges;
        virtual_ranges.reserve(file_header->NumberOfSections);

        for (WORD index = 0; index < file_header->NumberOfSections; ++index) {
            const auto& section = sections[index];
            if (section.SizeOfRawData != 0 &&
                !range_is_valid(section.PointerToRawData, section.SizeOfRawData,
                                file.size())) {
                throw std::runtime_error("A section's raw bytes are outside the file");
            }

            const auto virtual_size = static_cast<std::uint64_t>(
                std::max(section.Misc.VirtualSize, section.SizeOfRawData));
            if (virtual_size == 0) {
                continue;
            }
            if (section.VirtualAddress < optional->SizeOfHeaders ||
                !range_is_valid(section.VirtualAddress, virtual_size,
                                optional->SizeOfImage)) {
                throw std::runtime_error("A section's virtual range is invalid");
            }

            const std::pair<std::uint64_t, std::uint64_t> current{
                section.VirtualAddress, section.VirtualAddress + virtual_size};
            for (const auto& existing : virtual_ranges) {
                if (current.first < existing.second && existing.first < current.second) {
                    throw std::runtime_error("Overlapping virtual sections are unsupported");
                }
            }
            virtual_ranges.push_back(current);
        }

        for (std::size_t index = 0; index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++index) {
            if (index == IMAGE_DIRECTORY_ENTRY_SECURITY) {
                continue; // Security-directory offsets are file offsets, not RVAs.
            }
            const auto& directory = optional->DataDirectory[index];
            if ((directory.VirtualAddress == 0) != (directory.Size == 0)) {
                throw std::runtime_error("A PE data directory is only partially specified");
            }
            if (directory.VirtualAddress != 0 &&
                !range_is_valid(directory.VirtualAddress, directory.Size,
                                optional->SizeOfImage)) {
                throw std::runtime_error("A PE data directory is outside the image");
            }
        }

        mapped_.assign(optional->SizeOfImage, std::byte{0});
        std::memcpy(mapped_.data(), file.data(), optional->SizeOfHeaders);
        for (WORD index = 0; index < file_header->NumberOfSections; ++index) {
            const auto& section = sections[index];
            if (section.SizeOfRawData != 0) {
                std::memcpy(mapped_.data() + section.VirtualAddress,
                            file.data() + section.PointerToRawData,
                            section.SizeOfRawData);
            }
        }
    }

    void validate_relocations() const {
        const auto& directory =
            nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (directory.VirtualAddress == 0) {
            return;
        }

        std::uint64_t consumed = 0;
        while (consumed < directory.Size) {
            if (directory.Size - consumed < sizeof(IMAGE_BASE_RELOCATION)) {
                throw std::runtime_error("Truncated base-relocation block");
            }
            const auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
                mapped_.data() + directory.VirtualAddress + consumed);
            if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                block->SizeOfBlock > directory.Size - consumed ||
                ((block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(WORD)) != 0) {
                throw std::runtime_error("Malformed base-relocation block");
            }

            const auto* entries = reinterpret_cast<const WORD*>(
                reinterpret_cast<const std::byte*>(block) +
                sizeof(IMAGE_BASE_RELOCATION));
            const auto count =
                (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (DWORD index = 0; index < count; ++index) {
                const WORD type = entries[index] >> 12;
                const WORD offset = entries[index] & 0x0FFF;
                if (type != IMAGE_REL_BASED_ABSOLUTE && type != IMAGE_REL_BASED_DIR64) {
                    throw std::runtime_error("Unsupported AMD64 relocation type");
                }
                if (type == IMAGE_REL_BASED_DIR64 &&
                    !image_range_is_valid(
                        static_cast<std::uint64_t>(block->VirtualAddress) + offset,
                        sizeof(std::uint64_t))) {
                    throw std::runtime_error("A relocation target is outside the image");
                }
            }
            consumed += block->SizeOfBlock;
        }
    }

    void validate_imports() const {
        const auto& directory =
            nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (directory.VirtualAddress == 0) {
            return;
        }
        if (directory.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            throw std::runtime_error("Truncated import directory");
        }

        const auto descriptor_limit = directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        bool found_terminator = false;
        for (std::uint64_t descriptor_index = 0;
             descriptor_index < descriptor_limit;
             ++descriptor_index) {
            const auto descriptor_rva = directory.VirtualAddress +
                descriptor_index * sizeof(IMAGE_IMPORT_DESCRIPTOR);
            const auto* descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
                mapped_.data() + descriptor_rva);

            if (descriptor->Name == 0 && descriptor->FirstThunk == 0 &&
                descriptor->OriginalFirstThunk == 0) {
                found_terminator = true;
                break;
            }
            if (descriptor->Name == 0 || descriptor->FirstThunk == 0 ||
                !has_terminated_string(descriptor->Name)) {
                throw std::runtime_error("Malformed import descriptor");
            }

            const std::uint64_t lookup_rva = descriptor->OriginalFirstThunk != 0
                ? descriptor->OriginalFirstThunk
                : descriptor->FirstThunk;
            bool thunk_terminated = false;
            const auto maximum_thunks = mapped_.size() / sizeof(IMAGE_THUNK_DATA64);
            for (std::uint64_t thunk_index = 0;
                 thunk_index < maximum_thunks;
                 ++thunk_index) {
                const auto lookup_offset =
                    lookup_rva + thunk_index * sizeof(IMAGE_THUNK_DATA64);
                const auto address_offset = static_cast<std::uint64_t>(
                    descriptor->FirstThunk) +
                    thunk_index * sizeof(IMAGE_THUNK_DATA64);
                if (!image_range_is_valid(lookup_offset, sizeof(IMAGE_THUNK_DATA64)) ||
                    !image_range_is_valid(address_offset, sizeof(IMAGE_THUNK_DATA64))) {
                    throw std::runtime_error("An import thunk is outside the image");
                }

                const auto* lookup = reinterpret_cast<const IMAGE_THUNK_DATA64*>(
                    mapped_.data() + lookup_offset);
                if (lookup->u1.AddressOfData == 0) {
                    thunk_terminated = true;
                    break;
                }
                if (!IMAGE_SNAP_BY_ORDINAL64(lookup->u1.Ordinal)) {
                    const auto name_rva = lookup->u1.AddressOfData;
                    if (!image_range_is_valid(name_rva, sizeof(WORD) + 1) ||
                        !has_terminated_string(name_rva + sizeof(WORD))) {
                        throw std::runtime_error("An imported symbol name is outside the image");
                    }
                }
            }
            if (!thunk_terminated) {
                throw std::runtime_error("Unterminated import thunk table");
            }
        }
        if (!found_terminator) {
            throw std::runtime_error("Unterminated import descriptor table");
        }
    }

    void validate_exception_directory() const {
        const auto& directory =
            nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (directory.VirtualAddress == 0) {
            return;
        }
        if (directory.Size % sizeof(RUNTIME_FUNCTION) != 0) {
            throw std::runtime_error("Malformed x64 exception directory");
        }

        const auto* functions = reinterpret_cast<const RUNTIME_FUNCTION*>(
            mapped_.data() + directory.VirtualAddress);
        const auto count = directory.Size / sizeof(RUNTIME_FUNCTION);
        for (DWORD index = 0; index < count; ++index) {
            if (functions[index].BeginAddress >= functions[index].EndAddress ||
                functions[index].EndAddress > nt()->OptionalHeader.SizeOfImage ||
                !image_range_is_valid(
                    functions[index].UnwindData, sizeof(DWORD))) {
                throw std::runtime_error("An x64 runtime-function entry is invalid");
            }
        }
    }

    void validate_tls_directory() const {
        const auto& directory =
            nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (directory.VirtualAddress == 0) {
            return;
        }
        if (directory.Size < sizeof(IMAGE_TLS_DIRECTORY64)) {
            throw std::runtime_error("Truncated TLS directory");
        }

        const auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(
            mapped_.data() + directory.VirtualAddress);
        const std::uint64_t image_base = nt()->OptionalHeader.ImageBase;
        const std::uint64_t image_size = nt()->OptionalHeader.SizeOfImage;
        if (image_base > std::numeric_limits<std::uint64_t>::max() - image_size) {
            throw std::runtime_error("The preferred image range overflows");
        }
        const std::uint64_t image_end = image_base + image_size;

        const auto va_is_in_image = [&](const std::uint64_t va,
                                        const std::uint64_t size) noexcept {
            return va >= image_base && range_is_valid(va - image_base, size, image_size);
        };

        if ((tls->StartAddressOfRawData == 0) !=
            (tls->EndAddressOfRawData == 0)) {
            throw std::runtime_error("Partially specified TLS raw-data range");
        }
        if (tls->StartAddressOfRawData != 0 &&
            (tls->EndAddressOfRawData < tls->StartAddressOfRawData ||
             tls->StartAddressOfRawData < image_base ||
             tls->EndAddressOfRawData > image_end)) {
            throw std::runtime_error("TLS raw-data range is outside the image");
        }
        if (tls->AddressOfIndex != 0 &&
            !va_is_in_image(tls->AddressOfIndex, sizeof(DWORD))) {
            throw std::runtime_error("TLS index storage is outside the image");
        }
        if (tls->AddressOfCallBacks == 0) {
            return;
        }
        if (!va_is_in_image(tls->AddressOfCallBacks, sizeof(std::uint64_t))) {
            throw std::runtime_error("TLS callback array is outside the image");
        }

        const std::uint64_t callbacks_rva =
            tls->AddressOfCallBacks - image_base;
        bool found_terminator = false;
        for (std::uint64_t offset = callbacks_rva;
             image_range_is_valid(offset, sizeof(std::uint64_t));
             offset += sizeof(std::uint64_t)) {
            std::uint64_t callback_va = 0;
            std::memcpy(&callback_va, mapped_.data() + offset, sizeof(callback_va));
            if (callback_va == 0) {
                found_terminator = true;
                break;
            }
            if (!va_is_in_image(callback_va, 1)) {
                throw std::runtime_error("A TLS callback points outside the image");
            }
        }
        if (!found_terminator) {
            throw std::runtime_error("Unterminated TLS callback array");
        }
    }

    std::vector<std::byte> mapped_;
};

struct Options {
    std::filesystem::path dll_path;
    std::wstring process_name = L"cs2.exe";
    std::optional<DWORD> pid;
    DWORD timeout_ms = 15'000;
};

void print_usage() {
    std::wcout
        << L"CS2 Manual Map Injector (x64)\n\n"
        << L"Usage:\n"
        << L"  cs2-manual-map.exe <payload.dll> [--process cs2.exe] "
           L"[--pid N] [--timeout MS]\n\n"
        << L"Options:\n"
        << L"  --process NAME   Target image name (default: cs2.exe)\n"
        << L"  --pid N          Target an exact process ID\n"
        << L"  --timeout MS     Remote-loader timeout (default: 15000)\n"
        << L"  --help           Show this help\n";
}

DWORD parse_positive_dword(const wchar_t* value, const wchar_t* option_name) {
    if (value == nullptr || *value == L'\0') {
        throw std::runtime_error("Missing numeric option value");
    }
    errno = 0;
    wchar_t* end = nullptr;
    const unsigned long parsed = std::wcstoul(value, &end, 10);
    if (errno == ERANGE || end == value || *end != L'\0' || parsed == 0 ||
        parsed > std::numeric_limits<DWORD>::max()) {
        std::wcerr << L"Invalid value for " << option_name << L": " << value << L'\n';
        throw std::runtime_error("Invalid numeric option value");
    }
    return static_cast<DWORD>(parsed);
}

Options parse_options(const int argc, wchar_t** argv) {
    if (argc < 2) {
        print_usage();
        throw std::runtime_error("No payload DLL was provided");
    }

    if (std::wstring_view(argv[1]) == L"--help") {
        print_usage();
        std::exit(0);
    }

    Options options;
    options.dll_path = argv[1];
    for (int index = 2; index < argc; ++index) {
        const std::wstring_view argument = argv[index];
        if (argument == L"--help") {
            print_usage();
            std::exit(0);
        }
        if (argument == L"--process") {
            if (++index >= argc || argv[index][0] == L'\0') {
                throw std::runtime_error("--process requires a value");
            }
            options.process_name = argv[index];
            continue;
        }
        if (argument == L"--pid") {
            if (++index >= argc) {
                throw std::runtime_error("--pid requires a value");
            }
            options.pid = parse_positive_dword(argv[index], L"--pid");
            continue;
        }
        if (argument == L"--timeout") {
            if (++index >= argc) {
                throw std::runtime_error("--timeout requires a value");
            }
            options.timeout_ms = parse_positive_dword(argv[index], L"--timeout");
            if (options.timeout_ms > 300'000) {
                throw std::runtime_error("--timeout may not exceed 300000 ms");
            }
            continue;
        }
        std::wcerr << L"Unknown option: " << argument << L'\n';
        throw std::runtime_error("Unknown command-line option");
    }
    return options;
}

bool enable_debug_privilege() {
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(
            GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &raw_token)) {
        return false;
    }
    UniqueHandle token(raw_token);

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        return false;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    if (!AdjustTokenPrivileges(
            token.get(), FALSE, &privileges, sizeof(privileges), nullptr, nullptr)) {
        return false;
    }
    return GetLastError() == ERROR_SUCCESS;
}

std::vector<DWORD> find_process_ids(const std::wstring& process_name) {
    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        throw_last_error("CreateToolhelp32Snapshot(processes)");
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.get(), &entry)) {
        throw_last_error("Process32FirstW");
    }

    std::vector<DWORD> results;
    do {
        if (_wcsicmp(entry.szExeFile, process_name.c_str()) == 0) {
            results.push_back(entry.th32ProcessID);
        }
    } while (Process32NextW(snapshot.get(), &entry));

    if (GetLastError() != ERROR_NO_MORE_FILES) {
        throw_last_error("Process32NextW");
    }
    return results;
}

DWORD choose_process_id(const Options& options) {
    if (options.pid.has_value()) {
        return *options.pid;
    }

    const auto candidates = find_process_ids(options.process_name);
    if (candidates.empty()) {
        throw std::runtime_error("Target process was not found");
    }
    if (candidates.size() > 1) {
        std::wcerr << L"Multiple " << options.process_name
                   << L" processes were found. Select one with --pid:";
        for (const DWORD pid : candidates) {
            std::wcerr << L' ' << pid;
        }
        std::wcerr << L'\n';
        throw std::runtime_error("Target process is ambiguous");
    }
    return candidates.front();
}

void verify_native_amd64_process(HANDLE process) {
    using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    const auto is_wow64_process_2 = reinterpret_cast<IsWow64Process2Fn>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
    if (is_wow64_process_2 != nullptr) {
        USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        if (!is_wow64_process_2(process, &process_machine, &native_machine)) {
            throw_last_error("IsWow64Process2");
        }
        if (process_machine != IMAGE_FILE_MACHINE_UNKNOWN ||
            native_machine != IMAGE_FILE_MACHINE_AMD64) {
            throw std::runtime_error("The target is not a native AMD64 process");
        }
        return;
    }

    BOOL wow64 = FALSE;
    if (!IsWow64Process(process, &wow64)) {
        throw_last_error("IsWow64Process");
    }
    if (wow64) {
        throw std::runtime_error("The target is a 32-bit process");
    }
}

UniqueHandle create_module_snapshot(const DWORD pid) {
    for (int attempt = 0; attempt < 8; ++attempt) {
        UniqueHandle snapshot(CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
        if (snapshot) {
            return snapshot;
        }
        if (GetLastError() != ERROR_BAD_LENGTH) {
            throw_last_error("CreateToolhelp32Snapshot(modules)");
        }
        Sleep(1);
    }
    throw_last_error("CreateToolhelp32Snapshot(modules)");
}

std::uintptr_t find_remote_module_base(
    const DWORD pid, const std::wstring& module_name) {
    auto snapshot = create_module_snapshot(pid);
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot.get(), &entry)) {
        throw_last_error("Module32FirstW");
    }

    do {
        if (_wcsicmp(entry.szModule, module_name.c_str()) == 0) {
            return reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
        }
    } while (Module32NextW(snapshot.get(), &entry));

    if (GetLastError() != ERROR_NO_MORE_FILES) {
        throw_last_error("Module32NextW");
    }
    throw std::runtime_error("A required system module is absent from the target");
}

std::uintptr_t resolve_remote_function(
    const DWORD pid, const wchar_t* source_module, const char* export_name) {
    const HMODULE requested = GetModuleHandleW(source_module);
    if (requested == nullptr) {
        throw_last_error("GetModuleHandleW");
    }
    const FARPROC local_function = GetProcAddress(requested, export_name);
    if (local_function == nullptr) {
        throw_last_error("GetProcAddress");
    }

    MEMORY_BASIC_INFORMATION memory{};
    if (VirtualQuery(
            reinterpret_cast<const void*>(local_function), &memory, sizeof(memory)) == 0) {
        throw_last_error("VirtualQuery");
    }
    const auto owner = static_cast<HMODULE>(memory.AllocationBase);

    std::vector<wchar_t> owner_path(32'768);
    const DWORD path_length = GetModuleFileNameW(
        owner, owner_path.data(), static_cast<DWORD>(owner_path.size()));
    if (path_length == 0 || path_length >= owner_path.size()) {
        throw_last_error("GetModuleFileNameW");
    }
    const std::wstring owner_name =
        std::filesystem::path(std::wstring(owner_path.data(), path_length))
            .filename()
            .wstring();

    const auto local_base = reinterpret_cast<std::uintptr_t>(owner);
    const auto local_address = reinterpret_cast<std::uintptr_t>(local_function);
    const auto remote_base = find_remote_module_base(pid, owner_name);
    return remote_base + (local_address - local_base);
}

void write_remote_exact(
    HANDLE process, void* destination, const void* source, const SIZE_T size) {
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, destination, source, size, &written)) {
        throw_last_error("WriteProcessMemory");
    }
    if (written != size) {
        throw std::system_error(
            ERROR_PARTIAL_COPY, std::system_category(), "WriteProcessMemory");
    }
}

template <typename T>
T read_remote_exact(HANDLE process, const void* source) {
    T value{};
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, source, &value, sizeof(value), &read)) {
        throw_last_error("ReadProcessMemory");
    }
    if (read != sizeof(value)) {
        throw std::system_error(
            ERROR_PARTIAL_COPY, std::system_category(), "ReadProcessMemory");
    }
    return value;
}

DWORD protection_from_bits(const unsigned char bits) noexcept {
    constexpr unsigned char read = 1;
    constexpr unsigned char write = 2;
    constexpr unsigned char execute = 4;

    if ((bits & execute) != 0) {
        if ((bits & write) != 0) {
            return PAGE_EXECUTE_READWRITE;
        }
        if ((bits & read) != 0) {
            return PAGE_EXECUTE_READ;
        }
        return PAGE_EXECUTE;
    }
    if ((bits & write) != 0) {
        return PAGE_READWRITE;
    }
    if ((bits & read) != 0) {
        return PAGE_READONLY;
    }
    return PAGE_NOACCESS;
}

std::vector<mmap::RemoteProtectionRun> build_protection_runs(const PeImage& image) {
    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    const std::size_t page_size = system_info.dwPageSize;
    const std::size_t image_size = image.nt()->OptionalHeader.SizeOfImage;
    const std::size_t page_count = (image_size + page_size - 1) / page_size;
    std::vector<unsigned char> page_bits(page_count, 0);

    const auto mark_pages = [&](const std::uint64_t start,
                                const std::uint64_t length,
                                const unsigned char bits) {
        if (length == 0) {
            return;
        }
        const auto bounded_end = std::min<std::uint64_t>(
            image_size, start + length);
        if (start >= bounded_end) {
            return;
        }
        const auto first = static_cast<std::size_t>(start / page_size);
        const auto last = static_cast<std::size_t>((bounded_end - 1) / page_size);
        for (std::size_t page = first; page <= last; ++page) {
            page_bits[page] |= bits;
        }
    };

    mark_pages(0, image.nt()->OptionalHeader.SizeOfHeaders, 1);
    for (WORD index = 0; index < image.nt()->FileHeader.NumberOfSections; ++index) {
        const auto& section = image.sections()[index];
        unsigned char bits = 0;
        if ((section.Characteristics & IMAGE_SCN_MEM_READ) != 0) {
            bits |= 1;
        }
        if ((section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0) {
            bits |= 2;
        }
        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
            bits |= 4;
        }
        mark_pages(
            section.VirtualAddress,
            std::max(section.Misc.VirtualSize, section.SizeOfRawData),
            bits);
    }

    std::vector<mmap::RemoteProtectionRun> runs;
    std::size_t run_begin = 0;
    while (run_begin < page_count) {
        std::size_t run_end = run_begin + 1;
        while (run_end < page_count && page_bits[run_end] == page_bits[run_begin]) {
            ++run_end;
        }
        const auto byte_offset = run_begin * page_size;
        const auto byte_length = std::min(
            (run_end - run_begin) * page_size, image_size - byte_offset);
        runs.push_back(mmap::RemoteProtectionRun{
            static_cast<DWORD>(byte_offset),
            static_cast<DWORD>(byte_length),
            protection_from_bits(page_bits[run_begin]),
            0});
        run_begin = run_end;
    }
    return runs;
}

const wchar_t* remote_status_name(const mmap::RemoteStatus status) noexcept {
    using enum mmap::RemoteStatus;
    switch (status) {
    case pending: return L"pending";
    case relocating: return L"relocating";
    case resolving_imports: return L"resolving imports";
    case applying_protections: return L"applying section protections";
    case flushing_instruction_cache: return L"flushing the instruction cache";
    case registering_exceptions: return L"registering exception tables";
    case running_tls: return L"running TLS callbacks";
    case calling_entry_point: return L"calling DllMain";
    case success: return L"success";
    case invalid_context: return L"invalid loader context";
    case relocation_directory_missing: return L"missing relocation directory";
    case relocation_block_malformed: return L"malformed relocation block";
    case relocation_type_unsupported: return L"unsupported relocation type";
    case import_module_failed: return L"dependency load failure";
    case import_symbol_failed: return L"import lookup failure";
    case section_protection_failed: return L"section-protection failure";
    case instruction_cache_flush_failed: return L"instruction-cache flush failure";
    case exception_registration_failed: return L"unwind registration failure";
    case entry_point_rejected: return L"DllMain returned FALSE";
    }
    return L"unknown status";
}

void inject(const Options& options) {
    static_assert(sizeof(void*) == 8, "Build the injector for x64");

    PeImage image(options.dll_path);
    const auto protection_runs = build_protection_runs(image);
    if (image.has_tls()) {
        std::wcerr
            << L"Warning: TLS callbacks are invoked, but Windows static-TLS loader "
               L"bookkeeping is not emulated.\n";
    }

    const DWORD pid = choose_process_id(options);
    const bool debug_privilege = enable_debug_privilege();
    constexpr DWORD access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    UniqueHandle process(OpenProcess(access, FALSE, pid));
    if (!process) {
        if (!debug_privilege) {
            std::wcerr << L"Note: SeDebugPrivilege was unavailable.\n";
        }
        throw_last_error("OpenProcess");
    }
    verify_native_amd64_process(process.get());

    const auto preferred = reinterpret_cast<void*>(
        static_cast<std::uintptr_t>(image.nt()->OptionalHeader.ImageBase));
    void* remote_image = VirtualAllocEx(
        process.get(), preferred, image.bytes().size(),
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (remote_image == nullptr) {
        if (!image.has_relocations()) {
            throw std::runtime_error(
                "The preferred image base is occupied and the DLL has no relocations");
        }
        remote_image = VirtualAllocEx(
            process.get(), nullptr, image.bytes().size(),
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    if (remote_image == nullptr) {
        throw_last_error("VirtualAllocEx(image)");
    }
    if (remote_image != preferred && !image.has_relocations()) {
        VirtualFreeEx(process.get(), remote_image, 0, MEM_RELEASE);
        throw std::runtime_error(
            "The DLL was not allocated at its preferred base and has no relocations");
    }
    RemoteAllocation image_allocation(process.get(), remote_image);
    write_remote_exact(
        process.get(), remote_image, image.bytes().data(), image.bytes().size());

    const auto local_loader_begin =
        reinterpret_cast<std::uintptr_t>(&mmap::RemoteLoader);
    const auto local_loader_end =
        reinterpret_cast<std::uintptr_t>(&mmap::RemoteLoaderEnd);
    if (local_loader_end <= local_loader_begin ||
        local_loader_end - local_loader_begin > 64 * 1024) {
        throw std::runtime_error(
            "Remote loader section layout is invalid; inspect the Release build map");
    }
    const SIZE_T loader_size = local_loader_end - local_loader_begin;

    void* remote_loader = VirtualAllocEx(
        process.get(), nullptr, loader_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (remote_loader == nullptr) {
        throw_last_error("VirtualAllocEx(loader)");
    }
    RemoteAllocation loader_allocation(process.get(), remote_loader);
    write_remote_exact(
        process.get(), remote_loader,
        reinterpret_cast<const void*>(local_loader_begin), loader_size);
    DWORD old_loader_protection = 0;
    if (!VirtualProtectEx(
            process.get(), remote_loader, loader_size,
            PAGE_EXECUTE_READ, &old_loader_protection)) {
        throw_last_error("VirtualProtectEx(loader)");
    }

    mmap::RemoteContext context{};
    context.magic = mmap::kContextMagic;
    context.version = mmap::kContextVersion;
    context.image_base = reinterpret_cast<std::uint64_t>(remote_image);
    context.load_library_a = resolve_remote_function(
        pid, L"kernel32.dll", "LoadLibraryA");
    context.get_proc_address = resolve_remote_function(
        pid, L"kernel32.dll", "GetProcAddress");
    context.rtl_add_function_table = resolve_remote_function(
        pid, L"ntdll.dll", "RtlAddFunctionTable");
    context.virtual_protect = resolve_remote_function(
        pid, L"kernel32.dll", "VirtualProtect");
    context.flush_instruction_cache = resolve_remote_function(
        pid, L"kernel32.dll", "FlushInstructionCache");

    const SIZE_T protection_bytes =
        protection_runs.size() * sizeof(mmap::RemoteProtectionRun);
    void* remote_protection_runs = VirtualAllocEx(
        process.get(), nullptr, protection_bytes,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (remote_protection_runs == nullptr) {
        throw_last_error("VirtualAllocEx(protection runs)");
    }
    RemoteAllocation protection_allocation(process.get(), remote_protection_runs);
    write_remote_exact(
        process.get(), remote_protection_runs,
        protection_runs.data(), protection_bytes);
    context.protection_runs =
        reinterpret_cast<std::uint64_t>(remote_protection_runs);
    context.protection_run_count =
        static_cast<DWORD>(protection_runs.size());
    context.status = static_cast<LONG>(mmap::RemoteStatus::pending);

    void* remote_context = VirtualAllocEx(
        process.get(), nullptr, sizeof(context),
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (remote_context == nullptr) {
        throw_last_error("VirtualAllocEx(context)");
    }
    RemoteAllocation context_allocation(process.get(), remote_context);
    write_remote_exact(process.get(), remote_context, &context, sizeof(context));

    if (!FlushInstructionCache(process.get(), remote_loader, loader_size)) {
        throw_last_error("FlushInstructionCache(loader)");
    }
    UniqueHandle thread(CreateRemoteThread(
        process.get(), nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_loader),
        remote_context, 0, nullptr));
    if (!thread) {
        throw_last_error("CreateRemoteThread");
    }

    const DWORD wait_result = WaitForSingleObject(thread.get(), options.timeout_ms);
    if (wait_result == WAIT_TIMEOUT) {
        // The remote thread may still touch all staging allocations. Intentionally
        // retain them rather than creating a use-after-free in the target.
        image_allocation.release();
        loader_allocation.release();
        protection_allocation.release();
        context_allocation.release();
        throw std::runtime_error(
            "The remote loader timed out; its target allocations were retained");
    }
    if (wait_result != WAIT_OBJECT_0) {
        image_allocation.release();
        loader_allocation.release();
        protection_allocation.release();
        context_allocation.release();
        throw_last_error("WaitForSingleObject");
    }

    mmap::RemoteContext final_context{};
    try {
        final_context =
            read_remote_exact<mmap::RemoteContext>(process.get(), remote_context);
    } catch (...) {
        // The loader thread ended, but without its status the image's
        // initialization state is unknowable. Conservatively retain it.
        image_allocation.release();
        throw;
    }
    const auto final_status = static_cast<mmap::RemoteStatus>(final_context.status);
    if (final_status != mmap::RemoteStatus::success) {
        if (final_status == mmap::RemoteStatus::registering_exceptions ||
            final_status == mmap::RemoteStatus::running_tls ||
            final_status == mmap::RemoteStatus::calling_entry_point ||
            final_status == mmap::RemoteStatus::entry_point_rejected) {
            // Unwind registration, a TLS callback, or DllMain may have
            // published references. Retain the image to avoid dangling target
            // pointers when the precise remote exit path is unknown.
            image_allocation.release();
        }
        std::wcerr << L"Remote loader failed while " << remote_status_name(final_status)
                   << L" (status " << final_context.status << L", detail 0x"
                   << std::hex << final_context.detail << std::dec << L").\n";
        throw std::runtime_error("Manual mapping failed in the remote loader");
    }

    // From this point onward the payload has completed initialization and can
    // own threads, callbacks, and unwind records. Never roll its image back as
    // part of host-side cleanup.
    image_allocation.release();

    if (!FlushInstructionCache(
            process.get(), remote_image, image.bytes().size())) {
        std::wcerr
            << L"Warning: final FlushInstructionCache failed with Win32 error "
            << GetLastError() << L".\n";
    }

    std::wcout << L"Mapped " << options.dll_path.filename().wstring()
               << L" into PID " << pid << L" at 0x" << std::hex
               << reinterpret_cast<std::uintptr_t>(remote_image) << std::dec << L".\n";
}

} // namespace

int wmain(const int argc, wchar_t** argv) {
    try {
        inject(parse_options(argc, argv));
        return 0;
    } catch (const std::system_error& error) {
        std::cerr << "Error: " << error.what() << " (code "
                  << error.code().value() << ")\n";
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
    }
    return 1;
}
