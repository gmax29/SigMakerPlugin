#pragma comment(lib, "psapi.lib")

#include "loader.h"
#include <vector>
#include <string>
#include <format>
#include <psapi.h>
#include "Zydis.h"

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

struct MemoryRegion {
    ULONG_PTR base;
    SIZE_T size;
    std::vector<uint8_t> buffer;
};

void set_clipboard(const std::string& str) {
    if (!OpenClipboard(nullptr)) return;

    struct ClipboardScope {
        ~ClipboardScope() { CloseClipboard(); }
    } scope;

    EmptyClipboard();

    HGLOBAL buf = GlobalAlloc(GMEM_MOVEABLE, str.size() + 1);
    if (buf) {
        if (void* locked_mem = GlobalLock(buf)) {
            std::memcpy(locked_mem, str.c_str(), str.size() + 1);
            GlobalUnlock(buf);
            SetClipboardData(CF_TEXT, buf);
        }
        else {
            GlobalFree(buf);
        }
    }
}

bool get_executable_regions(HANDLE handle, ULONG_PTR address, std::vector<MemoryRegion>& out_regions, ULONG_PTR& out_mod_base) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    ULONG_PTR modBase = 0;
    SIZE_T modSize = 0;

    if (EnumProcessModules(handle, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO info;
            if (GetModuleInformation(handle, hMods[i], &info, sizeof(info))) {
                ULONG_PTR base = reinterpret_cast<ULONG_PTR>(info.lpBaseOfDll);
                if (address >= base && address < base + info.SizeOfImage) {
                    modBase = base;
                    modSize = info.SizeOfImage;
                    break;
                }
            }
        }
    }

    if (!modBase) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
            modBase = reinterpret_cast<ULONG_PTR>(mbi.AllocationBase);
            if (!modBase) modBase = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress);
            modSize = 25 * 1024 * 1024;
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
            SIZE_T sizeToRead = mbi.RegionSize;
            if (offset + sizeToRead > modSize) sizeToRead = modSize - offset;

            region.size = sizeToRead;
            region.buffer.resize(sizeToRead);

            SIZE_T read;
            if (ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(region.base), region.buffer.data(), sizeToRead, &read)) {
                out_regions.push_back(std::move(region));
            }
        }

        current_addr = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + mbi.RegionSize;
        if (current_addr < reinterpret_cast<ULONG_PTR>(mbi.BaseAddress)) break;
    }

    return !out_regions.empty();
}

int count_pattern_matches(const std::vector<MemoryRegion>& regions, const std::vector<PatternByte>& pattern) {
    if (pattern.empty()) return 0;

    int total_matches = 0;
    uint8_t first_byte = pattern[0].val;
    bool first_masked = pattern[0].masked;

    for (const auto& region : regions) {
        if (region.buffer.size() < pattern.size()) continue;

        size_t search_limit = region.buffer.size() - pattern.size();
        const uint8_t* data = region.buffer.data();

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
                if (total_matches > 1) return 2;
            }
        }
    }
    return total_matches;
}

bool generate_dynamic_signature(HANDLE handle, ULONG_PTR address, SignatureData& out_sig) {
    std::vector<MemoryRegion> regions;
    ULONG_PTR modBase = 0;

    if (!get_executable_regions(handle, address, regions, modBase)) return false;

    const MemoryRegion* target_region = nullptr;
    for (const auto& region : regions) {
        if (address >= region.base && address < region.base + region.size) {
            target_region = &region;
            break;
        }
    }
    if (!target_region) return false;

    size_t local_offset = address - target_region->base;

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

    std::vector<PatternByte> pattern;
    size_t decode_offset = 0;
    int matches = 2;

    while (matches > 1 && decode_offset < 128 && (local_offset + decode_offset) < target_region->size) {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, target_region->buffer.data() + local_offset + decode_offset, target_region->size - (local_offset + decode_offset), &instruction, operands))) {
            break;
        }

        for (uint8_t i = 0; i < instruction.length; ++i) {
            bool mask = false;

            if (instruction.raw.disp.size > 0 &&
                i >= instruction.raw.disp.offset &&
                i < instruction.raw.disp.offset + instruction.raw.disp.size) {
                mask = true;
            }

            for (int imm_idx = 0; imm_idx < 2; ++imm_idx) {
                if (instruction.raw.imm[imm_idx].size > 0 && instruction.raw.imm[imm_idx].is_relative &&
                    i >= instruction.raw.imm[imm_idx].offset &&
                    i < instruction.raw.imm[imm_idx].offset + instruction.raw.imm[imm_idx].size) {
                    mask = true;
                }
            }

            pattern.push_back({ target_region->buffer[local_offset + decode_offset + i], mask });
        }

        decode_offset += instruction.length;

        std::vector<PatternByte> temp_pattern = pattern;
        while (!temp_pattern.empty() && temp_pattern.back().masked) {
            temp_pattern.pop_back();
        }

        matches = count_pattern_matches(regions, temp_pattern);

        if (matches == 1) {
            pattern = temp_pattern;
            break;
        }
    }

    if (matches > 1) {
        out_sig.ce_style = "ERROR: Signature is NOT UNIQUE within the 128-byte limit.";
        out_sig.cpp_pattern = "ERROR: Function too generic / not unique.";
        out_sig.cpp_mask = "";
        return true;
    }

    while (!pattern.empty() && pattern.back().masked) {
        pattern.pop_back();
    }

    for (const auto& pb : pattern) {
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

    return true;
}

bool get_module_info(HANDLE handle, ULONG_PTR address, std::string& modName, ULONG_PTR& offset) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(handle, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO info;
            if (GetModuleInformation(handle, hMods[i], &info, sizeof(info))) {
                ULONG_PTR modBase = reinterpret_cast<ULONG_PTR>(info.lpBaseOfDll);
                if (address >= modBase && address < modBase + info.SizeOfImage) {
                    char name[MAX_PATH];
                    GetModuleBaseNameA(handle, hMods[i], name, sizeof(name));
                    modName = name;
                    offset = address - modBase;
                    return true;
                }
            }
        }
    }
    modName = "Unknown.exe";
    offset = 0;
    return false;
}

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

BOOL CE_CONV CEPlugin_GetVersion(CE_PLUGIN_VERSION* version, int version_size) {
    version->plugin_name = const_cast<char*>("SigMaker Pro - Created by gmax17");
    version->version = 1;
    return sizeof(CE_PLUGIN_VERSION) == version_size;
}

BOOL CE_CONV CEPlugin_InitializePlugin(CE_EXPORTED_FUNCTIONS* ef, int pluginid) {
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

BOOL CE_CONV CEPlugin_DisablePlugin() {
    return TRUE;
}
