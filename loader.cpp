#define NOMINMAX

#pragma comment(lib, "psapi.lib")

#include "loader.h"
#include <vector>
#include <string>
#include <format>
#include <span>
#include <psapi.h>
#include <algorithm>
#include <cstdlib>
#include "Zydis.h"

// Configuration constants
constexpr SIZE_T SHARED_BUFFER_SIZE = 5 * 1024 * 1024;    // 5 MB chunk size for memory reading
constexpr SIZE_T DEFAULT_MODULE_SIZE = 25 * 1024 * 1024;  // Fallback module size (25 MB)
constexpr SIZE_T MAX_DECODE_BYTES = 256;                   // Max bytes to decode forward from any anchor
constexpr int MAX_ANCHOR_OFFSET = 64;                      // Max bytes to step back from target

static CE_EXPORTED_FUNCTIONS exports;
static CE_DISASSEMBLER_CONTEXT_INIT ctx_aob;
static CE_DISASSEMBLER_CONTEXT_INIT ctx_cpp;
static CE_DISASSEMBLER_CONTEXT_INIT ctx_addr;

struct PatternByte {
    uint8_t val;
    bool masked;
};

struct SignatureData {
    std::string ce_style;
    std::string cpp_pattern;
    std::string cpp_mask;
};

// Store only base address and size to optimize memory usage during scans
struct MemoryRegion {
    ULONG_PTR base = 0;
    SIZE_T size = 0;
};

// Retrieves module base address and size for a given memory address
[[nodiscard]] bool find_module_info(HANDLE handle, ULONG_PTR address, ULONG_PTR& out_base, SIZE_T& out_size, char* out_name = nullptr, size_t name_size = 0) {
    HMODULE hMods[1024];
    DWORD cbNeeded = 0;

    if (EnumProcessModules(handle, hMods, sizeof(hMods), &cbNeeded)) {
        const auto count = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < count; ++i) {
            MODULEINFO info{};
            if (GetModuleInformation(handle, hMods[i], &info, sizeof(info))) {
                auto base = reinterpret_cast<ULONG_PTR>(info.lpBaseOfDll);
                if (address >= base && address < base + info.SizeOfImage) {
                    out_base = base;
                    out_size = info.SizeOfImage;
                    if (out_name && name_size > 0) {
                        GetModuleBaseNameA(handle, hMods[i], out_name, static_cast<DWORD>(name_size));
                    }
                    return true;
                }
            }
        }
    }
    return false;
}

// Safely copies a given string to the Windows clipboard using RAII
void set_clipboard(const std::string& str) {
    if (!OpenClipboard(nullptr)) return;

    struct ClipboardScope {
        ~ClipboardScope() { CloseClipboard(); }
    } scope;

    EmptyClipboard();

    HGLOBAL buf = GlobalAlloc(GMEM_MOVEABLE, str.size() + 1);
    if (!buf) return; // Early exit if allocation fails

    if (void* locked_mem = GlobalLock(buf)) {
        std::memcpy(locked_mem, str.c_str(), str.size() + 1);
        GlobalUnlock(buf);
        SetClipboardData(CF_TEXT, buf);
    }
    else {
        GlobalFree(buf);
    }
}

// Scans for all committed, executable memory regions within the target module
[[nodiscard]] bool get_executable_regions(HANDLE handle, ULONG_PTR address, std::vector<MemoryRegion>& out_regions, ULONG_PTR& out_mod_base) {
    ULONG_PTR modBase = 0;
    SIZE_T modSize = 0;

    if (!find_module_info(handle, address, modBase, modSize)) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
            modBase = reinterpret_cast<ULONG_PTR>(mbi.AllocationBase);
            if (!modBase) modBase = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress);
            modSize = DEFAULT_MODULE_SIZE;
        }
        else {
            return false;
        }
    }

    out_mod_base = modBase;
    ULONG_PTR current_addr = modBase;

    while (current_addr < modBase + modSize) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(current_addr), &mbi, sizeof(mbi))) break;

        bool is_executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (mbi.State == MEM_COMMIT && is_executable) {
            MemoryRegion region;
            region.base = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress);

            ULONG_PTR offset = region.base - modBase;
            SIZE_T sizeToProcess = mbi.RegionSize;
            if (offset + sizeToProcess > modSize) sizeToProcess = modSize - offset;

            region.size = sizeToProcess;
            out_regions.push_back(region);
        }

        current_addr = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + mbi.RegionSize;
        if (current_addr < reinterpret_cast<ULONG_PTR>(mbi.BaseAddress)) break;
    }

    return !out_regions.empty();
}

// Evaluates how many times a pattern exists in the target memory.
// Returns 2 immediately if more than one match is found (early exit optimization).
[[nodiscard]] int count_pattern_matches(HANDLE handle, std::span<const MemoryRegion> regions, std::span<const PatternByte> pattern, std::vector<uint8_t>& chunk_buffer) {
    if (pattern.empty()) return 0;

    int total_matches = 0;
    const SIZE_T CHUNK_SIZE = chunk_buffer.size();

    uint8_t first_byte = pattern[0].val;
    bool first_masked = pattern[0].masked;

    for (const auto& region : regions) {
        SIZE_T offset = 0;

        while (offset < region.size) {
            SIZE_T read_size = (std::min)(CHUNK_SIZE, region.size - offset);
            SIZE_T bytes_read = 0;

            if (!ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(region.base + offset), chunk_buffer.data(), read_size, &bytes_read) || bytes_read == 0) {
                break;
            }

            if (bytes_read < pattern.size()) break;

            size_t search_limit = bytes_read - pattern.size();
            const uint8_t* data = chunk_buffer.data();

            for (size_t i = 0; i <= search_limit; ++i) {
                if (!first_masked && data[i] != first_byte) continue;

                bool match = true;
                for (size_t j = 1; j < pattern.size(); ++j) {
                    if (!pattern[j].masked && data[i + j] != pattern[j].val) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    total_matches++;
                    // Early exit: we only care if the signature is unique (1 match) or generic (2+ matches)
                    if (total_matches > 1) return 2;
                }
            }

            if (read_size <= pattern.size()) break;
            offset += read_size - (pattern.size() - 1); // Overlap to prevent missing cross-chunk matches
        }
    }
    return total_matches;
}

// Core function: Generates the shortest unique, update-proof signature using Zydis instruction decoding.
// Pattern length is determined dynamically — grows instruction by instruction until unique.
// Tries the exact target address first, only falls back to anchoring if necessary.
bool generate_dynamic_signature(HANDLE handle, ULONG_PTR address, SignatureData& out_sig) {
    std::vector<MemoryRegion> regions;
    ULONG_PTR modBase = 0;

    if (!get_executable_regions(handle, address, regions, modBase)) return false;

    static thread_local std::vector<uint8_t> shared_chunk_buffer(SHARED_BUFFER_SIZE);

    ZydisDecoder decoder;
    BOOL is_wow64 = FALSE;

    if (IsWow64Process(handle, &is_wow64) && is_wow64) {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
    }
    else {
        SYSTEM_INFO sys_info;
        GetNativeSystemInfo(&sys_info);
        if (sys_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
            ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        }
        else {
            ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
        }
    }

    // Pre-read the entire decode region in one call: anchor area + forward decode space
    const auto max_back = static_cast<ULONG_PTR>(MAX_ANCHOR_OFFSET);
    ULONG_PTR read_start = (address > max_back) ? (address - max_back) : 0;
    auto prefix = static_cast<SIZE_T>(address - read_start);
    SIZE_T read_len = prefix + MAX_DECODE_BYTES;

    std::vector<uint8_t> decode_region(read_len);
    SIZE_T total_read = 0;

    if (!ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(read_start), decode_region.data(), read_len, &total_read) || total_read <= prefix) {
        // Fallback: read only from the target address forward
        read_start = address;
        prefix = 0;
        read_len = MAX_DECODE_BYTES;
        decode_region.resize(read_len);
        if (!ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(read_start), decode_region.data(), read_len, &total_read) || total_read == 0) {
            out_sig.ce_style = "ERROR: Could not read process memory.";
            out_sig.cpp_pattern = out_sig.ce_style;
            out_sig.cpp_mask = "";
            return true;
        }
    }

    int best_offset = 0;
    std::vector<PatternByte> best_pattern;
    bool found = false;

    // Try exact address first (anchor_offset=0), then step back 1 byte at a time
    int max_anchor = -static_cast<int>(prefix);

    for (int anchor_offset = 0; anchor_offset >= max_anchor && !found; --anchor_offset) {
        SIZE_T buf_idx = prefix + anchor_offset;
        SIZE_T available = total_read - buf_idx;
        const uint8_t* buf = decode_region.data() + buf_idx;

        // Phase 0: update-proof — mask displacements + ALL immediates
        // Phase 1: strict     — mask displacements + relative immediates only
        // Displacements are ALWAYS masked (address-relative, break on recompile)
        for (int phase = 0; phase < 2 && !found; ++phase) {
            bool mask_abs_imm = (phase == 0);
            std::vector<PatternByte> pattern;
            pattern.reserve(64);
            size_t decode_offset = 0;

            // Dynamic length: decode instructions one by one, check uniqueness after each
            while (decode_offset < available) {
                ZydisDecodedInstruction instr;
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buf + decode_offset, available - decode_offset, &instr, operands))) {
                    break;
                }

                // NOTE: Zydis reports size fields in BITS, offset fields in BYTES
                const auto disp_bytes = instr.raw.disp.size / 8;
                const auto imm0_bytes = instr.raw.imm[0].size / 8;
                const auto imm1_bytes = instr.raw.imm[1].size / 8;

                for (uint8_t i = 0; i < instr.length; ++i) {
                    bool mask = false;

                    // Always mask displacements (RIP-relative, address-relative — change every build)
                    if (disp_bytes > 0 &&
                        i >= instr.raw.disp.offset &&
                        i < instr.raw.disp.offset + disp_bytes) {
                        mask = true;
                    }

                    // Mask immediates
                    const struct { ZyanU8 offset; ZyanU8 size_bytes; ZyanBool is_relative; } imm_info[2] = {
                        { instr.raw.imm[0].offset, imm0_bytes, instr.raw.imm[0].is_relative },
                        { instr.raw.imm[1].offset, imm1_bytes, instr.raw.imm[1].is_relative },
                    };

                    for (const auto& [off, sz, is_rel] : imm_info) {
                        if (sz > 0 && i >= off && i < off + sz) {
                            if (is_rel || mask_abs_imm) {
                                mask = true;
                            }
                        }
                    }

                    pattern.push_back({ buf[decode_offset + i], mask });
                }

                decode_offset += instr.length;

                // Trim trailing wildcards for uniqueness check
                auto trimmed_size = pattern.size();
                while (trimmed_size > 0 && pattern[trimmed_size - 1].masked) {
                    --trimmed_size;
                }

                if (trimmed_size == 0) continue;

                std::span<const PatternByte> view(pattern.data(), trimmed_size);
                int matches = count_pattern_matches(handle, regions, view, shared_chunk_buffer);

                if (matches == 1) {
                    pattern.resize(trimmed_size);
                    best_pattern = std::move(pattern);
                    best_offset = anchor_offset;
                    found = true;
                    break;
                }
            }
        }
    }

    if (!found) {
        out_sig.ce_style = "ERROR: Signature too generic. No unique pattern found within scan range.";
        out_sig.cpp_pattern = "ERROR: Try another location.";
        out_sig.cpp_mask = "";
        return true;
    }

    // Format the final output strings
    for (const auto& pb : best_pattern) {
        if (pb.masked) {
            out_sig.ce_style += "* ";
            out_sig.cpp_pattern += "\\x00";
            out_sig.cpp_mask += "?";
        }
        else {
            out_sig.ce_style += std::format("{:02X} ", pb.val);
            out_sig.cpp_pattern += std::format("\\x{:02X}", pb.val);
            out_sig.cpp_mask += "x";
        }
    }

    if (!out_sig.ce_style.empty()) {
        out_sig.ce_style.pop_back();
    }

    // Append offset info only if an anchor was needed (not at exact target)
    if (best_offset < 0) {
        std::string offset_info = std::format(" // OFFSET: +0x{:X} bytes to injection point", -best_offset);
        out_sig.ce_style += offset_info;
        out_sig.cpp_pattern += offset_info;
    }

    return true;
}

[[nodiscard]] bool get_module_info(HANDLE handle, ULONG_PTR address, std::string& modName, ULONG_PTR& offset) {
    ULONG_PTR modBase = 0;
    SIZE_T modSize = 0;
    char name[MAX_PATH] = {};

    if (find_module_info(handle, address, modBase, modSize, name, sizeof(name))) {
        modName = name;
        offset = address - modBase;
        return true;
    }

    modName = "Unknown.exe";
    offset = 0;
    return false;
}

// --- CHEAT ENGINE CONTEXT MENU CALLBACKS ---

BOOL CE_CONV on_copy_aob(uintptr_t* selected_address) {
    if (!selected_address || !exports.OpenedProcessHandle) return TRUE;
    SignatureData sig;
    if (generate_dynamic_signature(*exports.OpenedProcessHandle, *selected_address, sig)) {
        set_clipboard(sig.ce_style);
    }
    return TRUE;
}

BOOL CE_CONV on_copy_cpp(uintptr_t* selected_address) {
    if (!selected_address || !exports.OpenedProcessHandle) return TRUE;
    SignatureData sig;
    if (generate_dynamic_signature(*exports.OpenedProcessHandle, *selected_address, sig)) {
        set_clipboard(std::format("{}\n{}", sig.cpp_pattern, sig.cpp_mask));
    }
    return TRUE;
}

BOOL CE_CONV on_copy_addr(uintptr_t* selected_address) {
    if (!selected_address || !exports.OpenedProcessHandle) return TRUE;
    std::string modName;
    ULONG_PTR offset;
    if (get_module_info(*exports.OpenedProcessHandle, *selected_address, modName, offset)) {
        set_clipboard(std::format("{} + 0x{:08X} = 0x{:X}", modName, offset, *selected_address));
    }
    else {
        set_clipboard(std::format("0x{:X}", *selected_address));
    }
    return TRUE;
}

BOOL CE_CONV on_rightclick(uintptr_t selected_address, const char** name_address, BOOL* show) {
    return TRUE;
}

// --- CHEAT ENGINE PLUGIN EXPORTS ---
// Notice the 'extern "C" __declspec(dllexport)'. This completely removes the need for a .def file!

extern "C" __declspec(dllexport) BOOL CE_CONV CEPlugin_GetVersion(CE_PLUGIN_VERSION* version, int version_size) {
    version->plugin_name = "SigMaker Pro - Created by gmax17";
    version->version = 1;
    return sizeof(CE_PLUGIN_VERSION) == version_size;
}

extern "C" __declspec(dllexport) BOOL CE_CONV CEPlugin_InitializePlugin(CE_EXPORTED_FUNCTIONS* ef, int pluginid) {
    exports = *ef;

    ctx_aob.name = "Copy AOB Sig";
    ctx_aob.callback_routine = &on_copy_aob;
    ctx_aob.callback_routine_onpopup = &on_rightclick;
    exports.RegisterFunction(pluginid, CE_PLUGIN_TYPE_DISASSEMBLER_CONTEXT, &ctx_aob);

    ctx_cpp.name = "Copy C++ Pattern";
    ctx_cpp.callback_routine = &on_copy_cpp;
    ctx_cpp.callback_routine_onpopup = &on_rightclick;
    exports.RegisterFunction(pluginid, CE_PLUGIN_TYPE_DISASSEMBLER_CONTEXT, &ctx_cpp);

    ctx_addr.name = "Copy Address Info";
    ctx_addr.callback_routine = &on_copy_addr;
    ctx_addr.callback_routine_onpopup = &on_rightclick;
    exports.RegisterFunction(pluginid, CE_PLUGIN_TYPE_DISASSEMBLER_CONTEXT, &ctx_addr);

    return TRUE;
}

extern "C" __declspec(dllexport) BOOL CE_CONV CEPlugin_DisablePlugin() {
    return TRUE;
}
