#define NOMINMAX

#include "loader.h"
#include "sigmaker.h"

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <format>

static CE_EXPORTED_FUNCTIONS exports;
static CE_DISASSEMBLER_CONTEXT_INIT ctx_aob;
static CE_DISASSEMBLER_CONTEXT_INIT ctx_cpp;
static CE_DISASSEMBLER_CONTEXT_INIT ctx_addr;
static CE_DISASSEMBLER_CONTEXT_INIT ctx_aa;

static bool is_all_hex(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

static void split_symbol(const std::string& in, std::string& base, ULONG_PTR& offset) {
    base = in;
    offset = 0;

    const auto plus = in.find_last_of('+');
    if (plus == std::string::npos || plus + 1 >= in.size()) return;

    const std::string tail = in.substr(plus + 1);
    for (char c : tail) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return;
    }

    base = in.substr(0, plus);
    offset = static_cast<ULONG_PTR>(std::strtoull(tail.c_str(), nullptr, 16));
}

static void set_clipboard(const std::string& str) {
    if (!OpenClipboard(nullptr)) return;

    struct ClipboardScope {
        ~ClipboardScope() { CloseClipboard(); }
    } scope;

    EmptyClipboard();

    HGLOBAL buf = GlobalAlloc(GMEM_MOVEABLE, str.size() + 1);
    if (!buf) return;

    void* locked = GlobalLock(buf);
    if (!locked) {
        GlobalFree(buf);
        return;
    }

    std::memcpy(locked, str.c_str(), str.size() + 1);
    GlobalUnlock(buf);

    if (!SetClipboardData(CF_TEXT, buf)) GlobalFree(buf);
}

static bool ce_name_at(ULONG_PTR address, std::string& out) {
    if (!exports.sym_addressToName) return false;

    char buf[512] = {};
    if (!exports.sym_addressToName(address, buf, static_cast<int>(sizeof(buf) - 1))) return false;

    buf[sizeof(buf) - 1] = 0;
    out = buf;
    return !out.empty();
}

static std::string describe_address(HANDLE handle, ULONG_PTR address) {
    std::string name;
    if (ce_name_at(address, name)) {
        std::string base;
        ULONG_PTR offset = 0;
        split_symbol(name, base, offset);
        if (!is_all_hex(base)) return name;
    }

    ULONG_PTR mod_base = 0;
    SIZE_T mod_size = 0;
    char mod_name[MAX_PATH] = {};

    if (find_module_info(handle, address, mod_base, mod_size, mod_name, sizeof(mod_name))) {
        return std::format("{}+{:X}", mod_name, address - mod_base);
    }
    return std::format("{:X}", address);
}

static std::string offset_note(HANDLE handle, ULONG_PTR address, int anchor_offset) {
    if (anchor_offset >= 0) return {};
    return std::format("// result + 0x{:X} = {}", -anchor_offset, describe_address(handle, address));
}

static bool prepare(HANDLE handle, ULONG_PTR address, ModuleSnapshot& snap, ZydisDecoder& decoder, SignatureResult& result) {
    if (address < 0x1000) {
        result.error = "ERROR: Invalid address.";
        return false;
    }
    if (!capture_snapshot(handle, address, snap)) {
        result.error = "ERROR: Could not read any executable memory of the module.";
        return false;
    }
    if (!snap.contains(address)) {
        result.error = "ERROR: Address is not inside a readable executable region of the module.";
        return false;
    }

    init_decoder(handle, decoder);
    return build_signature(snap, decoder, address, result);
}

BOOL CE_CONV on_copy_aob(uintptr_t* selected_address) {
    if (!selected_address || !exports.OpenedProcessHandle) return TRUE;

    const HANDLE handle = *exports.OpenedProcessHandle;
    const auto address = static_cast<ULONG_PTR>(*selected_address);

    ModuleSnapshot snap;
    ZydisDecoder decoder;
    SignatureResult sig;

    if (!prepare(handle, address, snap, decoder, sig)) {
        set_clipboard(sig.error);
        return TRUE;
    }

    const std::string note = offset_note(handle, address, sig.anchor_offset);
    set_clipboard(note.empty() ? sig.data.ce_style : std::format("{}\n{}", sig.data.ce_style, note));
    return TRUE;
}

BOOL CE_CONV on_copy_cpp(uintptr_t* selected_address) {
    if (!selected_address || !exports.OpenedProcessHandle) return TRUE;

    const HANDLE handle = *exports.OpenedProcessHandle;
    const auto address = static_cast<ULONG_PTR>(*selected_address);

    ModuleSnapshot snap;
    ZydisDecoder decoder;
    SignatureResult sig;

    if (!prepare(handle, address, snap, decoder, sig)) {
        set_clipboard(sig.error);
        return TRUE;
    }

    std::string out = std::format("{}\n{}", sig.data.cpp_pattern, sig.data.cpp_mask);
    if (const std::string note = offset_note(handle, address, sig.anchor_offset); !note.empty()) out += "\n" + note;

    set_clipboard(out);
    return TRUE;
}

BOOL CE_CONV on_copy_addr(uintptr_t* selected_address) {
    if (!selected_address || !exports.OpenedProcessHandle) return TRUE;

    set_clipboard(describe_address(*exports.OpenedProcessHandle, static_cast<ULONG_PTR>(*selected_address)));
    return TRUE;
}

BOOL CE_CONV on_aa_script(uintptr_t* selected_address) {
    if (!selected_address || !exports.OpenedProcessHandle) return TRUE;

    const HANDLE handle = *exports.OpenedProcessHandle;
    const auto address = static_cast<ULONG_PTR>(*selected_address);

    ModuleSnapshot snap;
    ZydisDecoder decoder;
    SignatureResult sig;

    if (!prepare(handle, address, snap, decoder, sig)) {
        set_clipboard(sig.error);
        return TRUE;
    }

    AaOptions opt;
    aa_load_settings(opt);

    std::string name;
    if (ce_name_at(address, name)) {
        std::string base;
        ULONG_PTR off = 0;
        split_symbol(name, base, off);
        if (!is_all_hex(base)) opt.base_name = sanitize_symbol(base);
    }
    if (opt.base_name.empty()) {
        std::string mod = snap.mod_name;
        if (const auto dot = mod.find_last_of('.'); dot != std::string::npos) mod.erase(dot);
        opt.base_name = sanitize_symbol(std::format("{}_{:X}", mod, address - snap.mod_base));
    }

    HWND parent = exports.GetMainWindowHandle ? static_cast<HWND>(exports.GetMainWindowHandle()) : nullptr;
    if (!aa_show_dialog(parent, opt)) return TRUE;

    std::vector<StolenInstr> stolen;
    SIZE_T stolen_len = 0;
    if (!collect_stolen(snap, decoder, address, static_cast<SIZE_T>(opt.min_bytes), stolen, stolen_len)) {
        set_clipboard("ERROR: Could not decode enough bytes at the injection point.");
        return TRUE;
    }

    aa_save_settings(opt);
    set_clipboard(aa_build_script(snap, decoder, address, sig, stolen, stolen_len, opt));
    return TRUE;
}

BOOL CE_CONV on_rightclick(uintptr_t selected_address, const char** name_address, BOOL* show) {
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL CE_CONV CEPlugin_GetVersion(CE_PLUGIN_VERSION* version, int version_size) {
    if (!version) return FALSE;

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

    ctx_aa.name = "Generate AA Script";
    ctx_aa.callback_routine = &on_aa_script;
    ctx_aa.callback_routine_onpopup = &on_rightclick;
    exports.RegisterFunction(pluginid, CE_PLUGIN_TYPE_DISASSEMBLER_CONTEXT, &ctx_aa);

    return TRUE;
}

extern "C" __declspec(dllexport) BOOL CE_CONV CEPlugin_DisablePlugin() {
    return TRUE;
}
