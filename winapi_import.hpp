#pragma once
#include <functional>
#include <Windows.h>
#include <string_view>

namespace win_api {

using t_load_library = HMODULE(WINAPI *)(__in LPCSTR file_name);

struct unicode_string {
    USHORT length;
    USHORT maximum_length;
    PWSTR buffer;
};

struct ldr_module {
    LIST_ENTRY e[3];
    HMODULE base;
    void *entry;
    UINT size;
    unicode_string dll_path;
    unicode_string dll_name;
};

#define mmix(h, k)                                                                                                             \
    {                                                                                                                          \
        k *= m;                                                                                                                \
        k ^= k >> r;                                                                                                           \
        k *= m;                                                                                                                \
        h *= m;                                                                                                                \
        h ^= k;                                                                                                                \
    }

namespace detail {
[[nodiscard]] unsigned int murmur_hash2_a(const void *key, int len, unsigned int seed)
{
    constexpr unsigned int m = 0x5bd1e995;
    constexpr auto r = 24;
    const unsigned char *current_data = static_cast<const unsigned char *>(key);
    auto h = seed;
    auto remaining_len = len;

    while (remaining_len >= 4) {
        auto k = *reinterpret_cast<const unsigned int *>(current_data);
        k *= m;
        k ^= k >> r;
        k *= m;
        h *= m;
        h ^= k;
        current_data += 4;
        remaining_len -= 4;
    }

    unsigned int t = 0;
    switch (remaining_len) {
    case 3:
        t ^= static_cast<unsigned int>(current_data[2]) << 16;
    case 2:
        t ^= static_cast<unsigned int>(current_data[1]) << 8;
    case 1:
        t ^= static_cast<unsigned int>(current_data[0]);
    }

    auto result = h;
    result *= m;
    result ^= t;
    result *= m;
    result ^= static_cast<unsigned int>(len);
    result ^= result >> 13;
    result *= m;
    result ^= result >> 15;

    return result;
}

[[nodiscard]] LPVOID parse_export_table(HMODULE module, DWORD api_hash, int len, unsigned seed)
{
    if (!module)
        return nullptr;

    const auto img_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    const auto img_nt_header =
            reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(img_dos_header) + img_dos_header->e_lfanew);
    const auto in_export = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
            reinterpret_cast<DWORD_PTR>(img_dos_header)
            + img_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    const auto rva_name = reinterpret_cast<PDWORD>(reinterpret_cast<DWORD_PTR>(img_dos_header) + in_export->AddressOfNames);
    const auto rva_ordinal =
            reinterpret_cast<PWORD>(reinterpret_cast<DWORD_PTR>(img_dos_header) + in_export->AddressOfNameOrdinals);

    for (UINT i = 0; i < in_export->NumberOfNames - 1; ++i) {
        const auto api_name = reinterpret_cast<PCHAR>(reinterpret_cast<DWORD_PTR>(img_dos_header) + rva_name[i]);

        if (api_hash == murmur_hash2_a(api_name, len, seed)) {
            const auto func_addr =
                    reinterpret_cast<PDWORD>(reinterpret_cast<DWORD_PTR>(img_dos_header) + in_export->AddressOfFunctions);
            const auto ord = static_cast<UINT>(rva_ordinal[i]);

            if (ord > reinterpret_cast<unsigned>(func_addr))
                return nullptr;

            return reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(img_dos_header) + func_addr[ord]);
        }
    }
    return nullptr;
}
} // namespace detail

template<typename T>
class win_api_import {
public:
    struct function_holder final {
        HMODULE dll_handle;
        T *func_ptr;

        function_holder() : dll_handle(nullptr), func_ptr(nullptr) {}

        function_holder(HMODULE dll, T *func) : dll_handle(dll), func_ptr(func) {}

        function_holder(function_holder &&other) noexcept : dll_handle(other.dll_handle), func_ptr(other.func_ptr)
        {
            other.dll_handle = nullptr;
            other.func_ptr = nullptr;
        }

        function_holder &operator=(function_holder &&other) noexcept
        {
            if (this != &other) {
                cleanup();
                dll_handle = other.dll_handle;
                func_ptr = other.func_ptr;
                other.dll_handle = nullptr;
                other.func_ptr = nullptr;
            }
            return *this;
        }

        ~function_holder() { cleanup(); }

        template<typename... Args>
        auto operator()(Args &&...args) const
        {
            return func_ptr(std::forward<Args>(args)...);
        }

        explicit operator bool() const { return func_ptr != nullptr; }

    private:
        void cleanup()
        {
            if (dll_handle) {
                FreeLibrary(dll_handle);
                dll_handle = nullptr;
                func_ptr = nullptr;
            }
        }

        function_holder(const function_holder &) = delete;
        function_holder &operator=(const function_holder &) = delete;
    };

    win_api_import(std::string_view func_name, std::string_view module_name, unsigned seed = 0)
        : m_func_name(func_name)
        , m_module_name(module_name)
        , m_len(static_cast<int>(func_name.length()))
        , m_seed(seed == 0 ? m_len : seed)
    {
    }

    [[nodiscard]] function_holder get_function()
    {
        try {
            const auto [krnl32, hdll] = get_modules();
            const auto api_hash = detail::murmur_hash2_a(m_func_name.data(), m_len, m_seed);
            auto api_func = detail::parse_export_table(hdll, api_hash, m_len, m_seed);
            return function_holder(hdll, reinterpret_cast<T *>(api_func));
        } catch (...) {
            return function_holder();
        }
    }

private:
    const std::string_view m_func_name;
    const std::string_view m_module_name;
    const int m_len;
    const unsigned m_seed;

    struct module_pair {
        HMODULE kernel32;
        HMODULE dll;
    };

    [[nodiscard]] module_pair get_modules() const
    {
#ifdef _WIN64
        constexpr auto module_list = 0x18;
        constexpr auto module_list_flink = 0x18;
        constexpr auto kernel_base_addr = 0x10;
        const auto peb = __readgsqword(0x60);
#else
        constexpr auto module_list = 0x0C;
        constexpr auto module_list_flink = 0x10;
        constexpr auto kernel_base_addr = 0x10;
        const auto peb = __readfsdword(0x30);
#endif
        const auto mdllist = *reinterpret_cast<INT_PTR *>(peb + module_list);
        const auto mlink = *reinterpret_cast<INT_PTR *>(mdllist + module_list_flink);
        auto mdl = reinterpret_cast<ldr_module *>(mlink);
        HMODULE krnl32 = nullptr;

        do {
            mdl = reinterpret_cast<ldr_module *>(mdl->e[0].Flink);
            if (mdl->base && !lstrcmpiW(mdl->dll_name.buffer, L"kernel32.dll")) {
                krnl32 = mdl->base;
                break;
            }
        } while (mlink != reinterpret_cast<INT_PTR>(mdl));

        const auto api_hash_load_library = detail::murmur_hash2_a("LoadLibraryA", 12, 10);
        auto temp_load_library = static_cast<t_load_library>(detail::parse_export_table(krnl32, api_hash_load_library, 12, 10));
        auto hdll = temp_load_library(m_module_name.data());

        return {krnl32, hdll};
    }
};

template<typename T>
[[nodiscard]] typename win_api_import<T>::function_holder get(std::string_view func_name, std::string_view module_name,
                                                              unsigned seed = 0)
{
    win_api_import<T> importer(func_name, module_name, seed);
    return importer.get_function();
}

} // namespace win_api
