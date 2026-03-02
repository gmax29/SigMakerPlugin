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

bool get_search_region(HANDLE handle, ULONG_PTR address, ULONG_PTR& out_base, SIZE_T& out_size) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;

    out_base = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress);
    out_size = mbi.RegionSize;
    return true;
}

int count_pattern_matches(const std::vector<uint8_t>& buffer, const std::vector<PatternByte>& pattern) {
    if (pattern.empty() || buffer.size() < pattern.size()) return 0;

    int matches = 0;
    for (size_t i = 0; i <= buffer.size() - pattern.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (!pattern[j].masked && buffer[i + j] != pattern[j].val) {
                match = false;
                break;
            }
        }
        if (match) {
            matches++;
            if (matches > 1) return 2;
        }
    }
    return matches;
}

bool generate_dynamic_signature(HANDLE handle, ULONG_PTR address, SignatureData& out_sig) {
    ULONG_PTR region_base = 0;
    SIZE_T region_size = 0;

    if (!get_search_region(handle, address, region_base, region_size) || region_size == 0) return false;

    std::vector<uint8_t> buffer(region_size);
    if (!ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(region_base), buffer.data(), region_size, nullptr)) return false;

    size_t local_offset = address - region_base;
    if (local_offset >= region_size) return false;

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

    while (matches > 1 && decode_offset < 128 && (local_offset + decode_offset) < region_size) {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buffer.data() + local_offset + decode_offset, region_size - (local_offset + decode_offset), &instruction, operands))) {
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

            pattern.push_back({ buffer[local_offset + decode_offset + i], mask });
        }

        decode_offset += instruction.length;
        matches = count_pattern_matches(buffer, pattern);
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

std::string get_address_string(HANDLE handle, ULONG_PTR address) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(handle, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO info;
            if (GetModuleInformation(handle, hMods[i], &info, sizeof(info))) {
                ULONG_PTR modBase = reinterpret_cast<ULONG_PTR>(info.lpBaseOfDll);
                if (address >= modBase && address < modBase + info.SizeOfImage) {
                    char modName[MAX_PATH];
                    GetModuleBaseNameA(handle, hMods[i], modName, sizeof(modName));
                    ULONG_PTR offset = address - modBase;
                    return std::format("{} + 0x{:08X} = 0x{:X}", modName, offset, address);
                }
            }
        }
    }
    return std::format("0x{:X}", address);
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
    set_clipboard(get_address_string(*exports.OpenedProcessHandle, *selected_address));
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