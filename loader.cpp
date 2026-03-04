#define NOMINMAX

#pragma comment(lib, "psapi.lib")

#include "loader.h"
#include <vector>
#include <string>
#include <format>
#include <psapi.h>
#include <algorithm>
#include <cmath>
#include "Zydis.h"

// Configuration constants
constexpr SIZE_T SHARED_BUFFER_SIZE = 5 * 1024 * 1024;    // 5 MB chunk size for memory reading
constexpr SIZE_T DEFAULT_MODULE_SIZE = 25 * 1024 * 1024;  // Fallback module size (25 MB)
constexpr SIZE_T MAX_DECODE_BYTES = 128;
constexpr size_t MAX_PATTERN_LENGTH = 32;
constexpr int MAX_ANCHOR_OFFSET = 50;
constexpr int ANCHOR_STEP = 10;

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
bool find_module_info(HANDLE handle, ULONG_PTR address, ULONG_PTR& out_base, SIZE_T& out_size, char* out_name = nullptr, size_t name_size = 0) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(handle, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO info;
            if (GetModuleInformation(handle, hMods[i], &info, sizeof(info))) {
                ULONG_PTR base = reinterpret_cast<ULONG_PTR>(info.lpBaseOfDll);
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
bool get_executable_regions(HANDLE handle, ULONG_PTR address, std::vector<MemoryRegion>& out_regions, ULONG_PTR& out_mod_base) {
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

        bool is_executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));

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
int count_pattern_matches(HANDLE handle, const std::vector<MemoryRegion>& regions, const std::vector<PatternByte>& pattern, std::vector<uint8_t>& chunk_buffer) {
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

// Core function: Generates a unique, update-proof signature using Zydis instruction decoding
bool generate_dynamic_signature(HANDLE handle, ULONG_PTR address, SignatureData& out_sig) {
    std::vector<MemoryRegion> regions;
    ULONG_PTR modBase = 0;

    if (!get_executable_regions(handle, address, regions, modBase)) return false;

    // Use thread_local to allocate the 5MB buffer only once per thread, reusing it across clicks
    static thread_local std::vector<uint8_t> shared_chunk_buffer(SHARED_BUFFER_SIZE);

    ZydisDecoder decoder;
    BOOL is_wow64 = FALSE;

    // Initialize Zydis decoder based on process architecture
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

    int best_offset = 0;
    std::vector<PatternByte> best_pattern;
    int best_matches = 2;

    // Attempt to find a unique anchor by stepping backwards from the target address
    for (int anchor_offset = 0; anchor_offset >= -MAX_ANCHOR_OFFSET; anchor_offset -= ANCHOR_STEP) {
        ULONG_PTR current_scan_address = address + anchor_offset;

        std::vector<uint8_t> local_decode_buffer(MAX_DECODE_BYTES);
        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(current_scan_address), local_decode_buffer.data(), MAX_DECODE_BYTES, &bytes_read) || bytes_read == 0) {
            continue;
        }

        std::vector<PatternByte> final_pattern;
        int final_matches = 2;

        // Phase 0: Try update-proof (mask all disp/imm). Phase 1: Try strict matching if phase 0 is too generic.
        for (int phase = 0; phase < 2; ++phase) {
            bool phase_update_proof = (phase == 0);
            std::vector<PatternByte> pattern;
            size_t decode_offset = 0;
            int matches = 2;

            while (matches > 1 && decode_offset < MAX_PATTERN_LENGTH && decode_offset < bytes_read) {
                ZydisDecodedInstruction instruction;
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, local_decode_buffer.data() + decode_offset, bytes_read - decode_offset, &instruction, operands))) {
                    break;
                }

                // Masking logic based on Zydis decode data
                for (uint8_t i = 0; i < instruction.length; ++i) {
                    bool mask = false;

                    // Mask displacements
                    if (instruction.raw.disp.size > 0 &&
                        i >= instruction.raw.disp.offset &&
                        i < instruction.raw.disp.offset + instruction.raw.disp.size) {

                        if (phase_update_proof) mask = true;
                    }

                    // Mask immediates
                    for (int imm_idx = 0; imm_idx < 2; ++imm_idx) {
                        if (instruction.raw.imm[imm_idx].size > 0 &&
                            i >= instruction.raw.imm[imm_idx].offset &&
                            i < instruction.raw.imm[imm_idx].offset + instruction.raw.imm[imm_idx].size) {

                            if (instruction.raw.imm[imm_idx].is_relative) {
                                mask = true; // Always mask relative calls/jumps
                            }
                            else if (phase_update_proof) {
                                mask = true;
                            }
                        }
                    }

                    pattern.push_back({ local_decode_buffer[decode_offset + i], mask });
                }

                decode_offset += instruction.length;

                // Trim trailing masked bytes to optimize search length
                std::vector<PatternByte> temp_pattern = pattern;
                while (!temp_pattern.empty() && temp_pattern.back().masked) {
                    temp_pattern.pop_back();
                }

                matches = count_pattern_matches(handle, regions, temp_pattern, shared_chunk_buffer);

                if (matches == 1) {
                    pattern = temp_pattern;
                    break;
                }
            }

            final_matches = matches;
            final_pattern = pattern;

            if (final_matches == 1) break;
        }

        if (final_matches == 1) {
            best_pattern = final_pattern;
            best_offset = anchor_offset;
            best_matches = 1;
            break;
        }
    }

    if (best_matches > 1) {
        out_sig.ce_style = "ERROR: Signature too generic. Couldn't find a unique anchor within 50 bytes.";
        out_sig.cpp_pattern = "ERROR: Try another location.";
        out_sig.cpp_mask = "";
        return true;
    }

    // Final trailing trim just to be absolutely sure
    while (!best_pattern.empty() && best_pattern.back().masked) {
        best_pattern.pop_back();
    }

    // Format the final output strings
    for (const auto& pb : best_pattern) {
        if (pb.masked) {
            out_sig.ce_style += "?? ";
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
        out_sig.ce_style.pop_back(); // Remove the last trailing space
    }

    // Append offset information if an anchor was used
    if (best_offset < 0) {
        std::string offset_info = std::format(" // OFFSET: +0x{:X} bytes to the injection point!", std::abs(best_offset));
        out_sig.ce_style += offset_info;
        out_sig.cpp_pattern += offset_info;
    }

    return true;
}

bool get_module_info(HANDLE handle, ULONG_PTR address, std::string& modName, ULONG_PTR& offset) {
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
    version->plugin_name = const_cast<char*>("SigMaker Pro - Created by gmax17");
    version->version = 1;
    return sizeof(CE_PLUGIN_VERSION) == version_size;
}

extern "C" __declspec(dllexport) BOOL CE_CONV CEPlugin_InitializePlugin(CE_EXPORTED_FUNCTIONS* ef, int pluginid) {
    exports = *ef;

    ctx_aob.name = const_cast<char*>("Copy AOB Sig");
    ctx_aob.callback_routine = &on_copy_aob;
    ctx_aob.callback_routine_onpopup = &on_rightclick;
    exports.RegisterFunction(pluginid, CE_PLUGIN_TYPE_DISASSEMBLER_CONTEXT, &ctx_aob);

    ctx_cpp.name = const_cast<char*>("Copy C++ Pattern");
    ctx_cpp.callback_routine = &on_copy_cpp;
    ctx_cpp.callback_routine_onpopup = &on_rightclick;
    exports.RegisterFunction(pluginid, CE_PLUGIN_TYPE_DISASSEMBLER_CONTEXT, &ctx_cpp);

    ctx_addr.name = const_cast<char*>("Copy Address Info");
    ctx_addr.callback_routine = &on_copy_addr;
    ctx_addr.callback_routine_onpopup = &on_rightclick;
    exports.RegisterFunction(pluginid, CE_PLUGIN_TYPE_DISASSEMBLER_CONTEXT, &ctx_addr);

    return TRUE;
}

extern "C" __declspec(dllexport) BOOL CE_CONV CEPlugin_DisablePlugin() {
    return TRUE;
}
