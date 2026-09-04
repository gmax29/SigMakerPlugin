#define NOMINMAX

#include "sigmaker.h"

#include <cstdlib>
#include <cstring>
#include <format>

static std::string plugin_dir() {
    HMODULE self = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(&plugin_dir), &self);

    char path[MAX_PATH] = {};
    if (!GetModuleFileNameA(self, path, sizeof(path))) return {};

    std::string s = path;
    const auto slash = s.find_last_of("\\/");
    return slash == std::string::npos ? std::string{} : s.substr(0, slash + 1);
}

static std::string ini_path() {
    const std::string dir = plugin_dir();
    return dir.empty() ? std::string{} : dir + "SigMaker.ini";
}

void aa_load_settings(AaOptions& opt) {
    const std::string ini = ini_path();
    if (ini.empty()) return;

    char buf[512] = {};
    GetPrivateProfileStringA("SigMaker", "Author", "", buf, sizeof(buf), ini.c_str());
    opt.author = buf;

    GetPrivateProfileStringA("SigMaker", "Description", "", buf, sizeof(buf), ini.c_str());
    opt.description = buf;

    GetPrivateProfileStringA("SigMaker", "Version", "", buf, sizeof(buf), ini.c_str());
    opt.version = buf;

    opt.min_bytes = GetPrivateProfileIntA("SigMaker", "MinBytes", 5, ini.c_str());
    opt.code_mode = GetPrivateProfileIntA("SigMaker", "CodeMode", 0, ini.c_str());
    opt.restore_mode = GetPrivateProfileIntA("SigMaker", "RestoreMode", 0, ini.c_str());
    opt.reg_newmem = GetPrivateProfileIntA("SigMaker", "RegNewmem", 0, ini.c_str()) != 0;
    opt.reg_code = GetPrivateProfileIntA("SigMaker", "RegCode", 0, ini.c_str()) != 0;
    opt.reg_return = GetPrivateProfileIntA("SigMaker", "RegReturn", 0, ini.c_str()) != 0;
}

void aa_save_settings(const AaOptions& opt) {
    const std::string ini = ini_path();
    if (ini.empty()) return;

    WritePrivateProfileStringA("SigMaker", "Author", opt.author.c_str(), ini.c_str());
    WritePrivateProfileStringA("SigMaker", "Description", opt.description.c_str(), ini.c_str());
    WritePrivateProfileStringA("SigMaker", "Version", opt.version.c_str(), ini.c_str());
    WritePrivateProfileStringA("SigMaker", "MinBytes", std::format("{}", opt.min_bytes).c_str(), ini.c_str());
    WritePrivateProfileStringA("SigMaker", "CodeMode", std::format("{}", opt.code_mode).c_str(), ini.c_str());
    WritePrivateProfileStringA("SigMaker", "RestoreMode", std::format("{}", opt.restore_mode).c_str(), ini.c_str());
    WritePrivateProfileStringA("SigMaker", "RegNewmem", opt.reg_newmem ? "1" : "0", ini.c_str());
    WritePrivateProfileStringA("SigMaker", "RegCode", opt.reg_code ? "1" : "0", ini.c_str());
    WritePrivateProfileStringA("SigMaker", "RegReturn", opt.reg_return ? "1" : "0", ini.c_str());
}

bool collect_stolen(const ModuleSnapshot& snap, const ZydisDecoder& decoder, ULONG_PTR address,
    SIZE_T min_bytes, std::vector<StolenInstr>& out, SIZE_T& total_len) {
    ZydisFormatter fmt;
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL))) return false;

    if (min_bytes < 5) min_bytes = 5;

    out.clear();
    total_len = 0;

    while (total_len < min_bytes) {
        const ULONG_PTR at = address + total_len;
        const SnapshotRegion* r = snap.region_of(at);
        if (!r) return false;

        const SIZE_T avail = r->base + r->size - at;
        const uint8_t* p = r->bytes.get() + (at - r->base);

        ZydisDecodedInstruction instr;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, p, avail, &instr, operands))) return false;

        StolenInstr si;
        si.addr = at;
        si.len = instr.length;
        si.position_dependent = (instr.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0;

        char text[256] = {};
        if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&fmt, &instr, operands, instr.operand_count_visible,
            text, sizeof(text), at, ZYAN_NULL))) {
            si.text = text;
        }

        out.push_back(std::move(si));
        total_len += instr.length;
    }
    return true;
}

std::string sanitize_symbol(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        out += ok ? c : '_';
    }
    if (out.empty() || (out[0] >= '0' && out[0] <= '9')) out.insert(out.begin(), '_');
    return out;
}

static std::string today() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    return std::format("{:04}-{:02}-{:02}", st.wYear, st.wMonth, st.wDay);
}

static std::string byte_list(const ModuleSnapshot& snap, ULONG_PTR address, SIZE_T len) {
    const uint8_t* p = snap.ptr(address, len);
    if (!p) return {};

    std::string s;
    for (SIZE_T i = 0; i < len; ++i) {
        if (i) s += ' ';
        s += std::format("{:02X}", p[i]);
    }
    return s;
}

std::string aa_build_script(const ModuleSnapshot& snap, const ZydisDecoder& decoder, ULONG_PTR address,
    const SignatureResult& sig, const std::vector<StolenInstr>& stolen, SIZE_T stolen_len, const AaOptions& opt) {
    const std::string sym = sanitize_symbol(opt.base_name);
    const std::string restore = sym + "_restore";
    const int inject_off = -sig.anchor_offset;
    const std::string inject = inject_off > 0 ? std::format("{}+{:X}", sym, inject_off) : sym;

    bool any_relative = false;
    for (const auto& s : stolen) any_relative |= s.position_dependent;

    std::string b;

    b += "{ Game   : " + snap.mod_name + "\n";
    b += "  Version: " + opt.version + "\n";
    b += "  Date   : " + today() + "\n";
    b += "  Author : " + opt.author + "\n\n";
    b += "  " + (opt.description.empty() ? std::string("This script does blah blah blah") : opt.description) + "\n";
    b += "}\n\n";

    b += "[ENABLE]\n";
    b += std::format("aobscanmodule({},{},{})\n", sym, snap.mod_name, sig.data.ce_style);
    b += std::format("alloc(newmem,$1000,{})\n\n", sym);

    b += "label(code)\n";
    b += "label(return)\n";
    if (opt.restore_mode == 1) b += std::format("label({})\n", restore);
    b += "\n";

    b += "newmem:\n";

    if (opt.code_mode == 0) {
        if (any_relative) {
            b += "  // relative operands below are resolved to absolute addresses\n";
        }
        for (const auto& s : stolen) {
            b += "  " + (s.text.empty() ? std::string("db 90") : s.text) + "\n";
        }
    }

    b += "code:\n";

    if (opt.code_mode == 0) {
        for (const auto& s : stolen) b += "  //" + s.text + "\n";
    }
    else {
        for (const auto& s : stolen) b += std::format("  // {:X}: {}\n", s.addr, s.text);
        if (any_relative) {
            b += "  // WARNING: a stolen instruction is position dependent, readmem copies its\n";
            b += "  // displacement verbatim and it will point elsewhere from newmem\n";
        }
        b += std::format("  readmem({},{})\n", inject, stolen_len);
    }

    b += "  jmp return\n\n";

    if (opt.restore_mode == 1) {
        b += restore + ":\n";
        b += std::format("  readmem({},{})\n\n", inject, stolen_len);
    }

    b += inject + ":\n";
    b += "  jmp newmem\n";
    if (stolen_len == 6) b += "  nop\n";
    else if (stolen_len > 6) b += std::format("  nop {}\n", stolen_len - 5);
    b += "return:\n";
    b += std::format("registersymbol({})\n", sym);
    if (opt.reg_newmem) b += "registersymbol(newmem)\n";
    if (opt.reg_code) b += "registersymbol(code)\n";
    if (opt.reg_return) b += "registersymbol(return)\n";
    if (opt.restore_mode == 1) b += std::format("registersymbol({})\n", restore);
    if (!opt.extra_symbols.empty()) b += std::format("registersymbol({})\n", opt.extra_symbols);
    b += "\n";

    b += "[DISABLE]\n";
    b += inject + ":\n";

    if (opt.restore_mode == 1) {
        b += std::format("  readmem({},{})\n", restore, stolen_len);
    }
    else {
        b += "  db " + byte_list(snap, address, stolen_len) + "\n";
    }

    b += "\nunregistersymbol(*)\n";
    b += "dealloc(*)\n\n";

    b += "{\n";
    b += "// ORIGINAL CODE - INJECTION POINT: " + snap.mod_name + std::format("+{:X}", address - snap.mod_base) + "\n\n";
    for (const auto& s : stolen) {
        b += std::format("{}+{:X}: {}\n", snap.mod_name, s.addr - snap.mod_base, s.text);
    }
    b += "}\n";

    return b;
}

namespace {

constexpr int ID_NAME = 101, ID_DESC = 102, ID_VER = 103, ID_AUTHOR = 104;
constexpr int ID_B5 = 110, ID_B14 = 111, ID_BCUSTOM = 112, ID_BVAL = 113;
constexpr int ID_CODE_ASM = 120, ID_CODE_MEM = 121;
constexpr int ID_RES_DB = 130, ID_RES_MEM = 131;
constexpr int ID_RN = 140, ID_RC = 141, ID_RR = 142, ID_EXTRA = 143;

struct DlgState {
    AaOptions* opt = nullptr;
    bool done = false;
};

HINSTANCE self_instance() {
    HMODULE self = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(&self_instance), &self);
    return reinterpret_cast<HINSTANCE>(self);
}

std::string text_of(HWND hwnd, int id) {
    char buf[1024] = {};
    GetDlgItemTextA(hwnd, id, buf, sizeof(buf));
    return buf;
}

LRESULT CALLBACK dlg_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* st = reinterpret_cast<DlgState*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));

    switch (msg) {
    case WM_CREATE: {
        auto* cs = reinterpret_cast<CREATESTRUCTA*>(lp);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        return 0;
    }
    case WM_COMMAND:
        if (!st) break;
        if (LOWORD(wp) == IDOK) {
            AaOptions& o = *st->opt;
            o.base_name = text_of(hwnd, ID_NAME);
            o.description = text_of(hwnd, ID_DESC);
            o.version = text_of(hwnd, ID_VER);
            o.author = text_of(hwnd, ID_AUTHOR);
            o.extra_symbols = text_of(hwnd, ID_EXTRA);

            if (IsDlgButtonChecked(hwnd, ID_B5) == BST_CHECKED) o.min_bytes = 5;
            else if (IsDlgButtonChecked(hwnd, ID_B14) == BST_CHECKED) o.min_bytes = 14;
            else {
                o.min_bytes = std::atoi(text_of(hwnd, ID_BVAL).c_str());
                if (o.min_bytes < 1) o.min_bytes = 5;
            }

            o.code_mode = IsDlgButtonChecked(hwnd, ID_CODE_MEM) == BST_CHECKED ? 1 : 0;
            o.restore_mode = IsDlgButtonChecked(hwnd, ID_RES_MEM) == BST_CHECKED ? 1 : 0;
            o.reg_newmem = IsDlgButtonChecked(hwnd, ID_RN) == BST_CHECKED;
            o.reg_code = IsDlgButtonChecked(hwnd, ID_RC) == BST_CHECKED;
            o.reg_return = IsDlgButtonChecked(hwnd, ID_RR) == BST_CHECKED;
            o.accepted = !o.base_name.empty();

            st->done = true;
            DestroyWindow(hwnd);
            return 0;
        }
        if (LOWORD(wp) == IDCANCEL) {
            st->done = true;
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_CLOSE:
        if (st) st->done = true;
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

HWND add(HWND parent, const char* cls, const char* text, DWORD style, int x, int y, int w, int h, int id,
    HINSTANCE inst, HFONT font) {
    HWND c = CreateWindowExA(0, cls, text, WS_CHILD | WS_VISIBLE | style, x, y, w, h,
        parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), inst, nullptr);
    if (c) SendMessageA(c, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    return c;
}

}

bool aa_show_dialog(HWND parent, AaOptions& opt) {
    const HINSTANCE inst = self_instance();

    static bool registered = false;
    if (!registered) {
        WNDCLASSEXA wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = dlg_proc;
        wc.hInstance = inst;
        wc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
        wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
        wc.lpszClassName = "SigMakerAaDialog";
        if (!RegisterClassExA(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return false;
        registered = true;
    }

    HFONT font = nullptr;
    NONCLIENTMETRICSA ncm{};
    ncm.cbSize = sizeof(ncm);
    if (SystemParametersInfoA(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) font = CreateFontIndirectA(&ncm.lfMessageFont);
    const bool own_font = font != nullptr;
    if (!font) font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

    DlgState st{ &opt, false };

    constexpr DWORD style = WS_POPUP | WS_CAPTION | WS_SYSMENU;
    RECT rc{ 0, 0, 460, 478 };
    AdjustWindowRect(&rc, style, FALSE);
    const int w = rc.right - rc.left, h = rc.bottom - rc.top;

    HWND hwnd = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, "SigMakerAaDialog",
        "Generate Auto Assembler Script", style,
        (GetSystemMetrics(SM_CXSCREEN) - w) / 2, (GetSystemMetrics(SM_CYSCREEN) - h) / 2,
        w, h, parent, nullptr, inst, &st);
    if (!hwnd) {
        if (own_font) DeleteObject(font);
        return false;
    }

    const DWORD ED = WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL;

    add(hwnd, "STATIC", "Symbol name", 0, 12, 10, 436, 16, -1, inst, font);
    add(hwnd, "EDIT", opt.base_name.c_str(), ED, 12, 28, 436, 22, ID_NAME, inst, font);

    add(hwnd, "STATIC", "Description", 0, 12, 58, 436, 16, -1, inst, font);
    add(hwnd, "EDIT", opt.description.c_str(), ED, 12, 76, 436, 22, ID_DESC, inst, font);

    add(hwnd, "STATIC", "Version", 0, 12, 106, 210, 16, -1, inst, font);
    add(hwnd, "STATIC", "Author", 0, 238, 106, 210, 16, -1, inst, font);
    add(hwnd, "EDIT", opt.version.c_str(), ED, 12, 124, 210, 22, ID_VER, inst, font);
    add(hwnd, "EDIT", opt.author.c_str(), ED, 238, 124, 210, 22, ID_AUTHOR, inst, font);

    add(hwnd, "BUTTON", "Bytes to steal", BS_GROUPBOX, 12, 158, 436, 62, -1, inst, font);
    add(hwnd, "BUTTON", "5  (jmp rel32)", WS_TABSTOP | WS_GROUP | BS_AUTORADIOBUTTON, 26, 182, 120, 20, ID_B5, inst, font);
    add(hwnd, "BUTTON", "14  (jmp far)", WS_TABSTOP | BS_AUTORADIOBUTTON, 156, 182, 120, 20, ID_B14, inst, font);
    add(hwnd, "BUTTON", "custom", WS_TABSTOP | BS_AUTORADIOBUTTON, 286, 182, 80, 20, ID_BCUSTOM, inst, font);
    add(hwnd, "EDIT", std::format("{}", opt.min_bytes).c_str(), ED | WS_GROUP, 372, 181, 62, 22, ID_BVAL, inst, font);

    add(hwnd, "BUTTON", "newmem code block", BS_GROUPBOX, 12, 230, 436, 56, -1, inst, font);
    add(hwnd, "BUTTON", "reassemble  (CE standard)", WS_TABSTOP | WS_GROUP | BS_AUTORADIOBUTTON, 26, 252, 200, 20, ID_CODE_ASM, inst, font);
    add(hwnd, "BUTTON", "readmem", WS_TABSTOP | BS_AUTORADIOBUTTON, 238, 252, 200, 20, ID_CODE_MEM, inst, font);

    add(hwnd, "BUTTON", "DISABLE restore", BS_GROUPBOX, 12, 296, 436, 56, -1, inst, font);
    add(hwnd, "BUTTON", "db bytes  (CE standard)", WS_TABSTOP | WS_GROUP | BS_AUTORADIOBUTTON, 26, 318, 200, 20, ID_RES_DB, inst, font);
    add(hwnd, "BUTTON", "readmem from copy", WS_TABSTOP | BS_AUTORADIOBUTTON, 238, 318, 200, 20, ID_RES_MEM, inst, font);

    add(hwnd, "BUTTON", "Register symbols", BS_GROUPBOX, 12, 362, 436, 78, -1, inst, font);
    add(hwnd, "BUTTON", "newmem", WS_TABSTOP | WS_GROUP | BS_AUTOCHECKBOX, 26, 384, 110, 20, ID_RN, inst, font);
    add(hwnd, "BUTTON", "code", WS_TABSTOP | BS_AUTOCHECKBOX, 146, 384, 90, 20, ID_RC, inst, font);
    add(hwnd, "BUTTON", "return", WS_TABSTOP | BS_AUTOCHECKBOX, 246, 384, 90, 20, ID_RR, inst, font);
    add(hwnd, "STATIC", "extra", 0, 26, 414, 40, 16, -1, inst, font);
    add(hwnd, "EDIT", opt.extra_symbols.c_str(), ED, 70, 411, 364, 22, ID_EXTRA, inst, font);

    add(hwnd, "BUTTON", "OK", WS_TABSTOP | BS_DEFPUSHBUTTON, 272, 448, 84, 26, IDOK, inst, font);
    add(hwnd, "BUTTON", "Cancel", WS_TABSTOP | BS_PUSHBUTTON, 364, 448, 84, 26, IDCANCEL, inst, font);

    const int byte_id = opt.min_bytes == 5 ? ID_B5 : (opt.min_bytes == 14 ? ID_B14 : ID_BCUSTOM);
    CheckRadioButton(hwnd, ID_B5, ID_BCUSTOM, byte_id);
    CheckRadioButton(hwnd, ID_CODE_ASM, ID_CODE_MEM, opt.code_mode == 1 ? ID_CODE_MEM : ID_CODE_ASM);
    CheckRadioButton(hwnd, ID_RES_DB, ID_RES_MEM, opt.restore_mode == 1 ? ID_RES_MEM : ID_RES_DB);
    CheckDlgButton(hwnd, ID_RN, opt.reg_newmem ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, ID_RC, opt.reg_code ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, ID_RR, opt.reg_return ? BST_CHECKED : BST_UNCHECKED);

    if (parent) EnableWindow(parent, FALSE);
    ShowWindow(hwnd, SW_SHOW);
    SetFocus(GetDlgItem(hwnd, ID_NAME));

    while (!st.done) {
        MSG msg;
        const BOOL r = GetMessageA(&msg, nullptr, 0, 0);
        if (r == -1) break;
        if (r == 0) {
            PostQuitMessage(static_cast<int>(msg.wParam));
            break;
        }

        if (msg.message == WM_KEYDOWN && (msg.hwnd == hwnd || IsChild(hwnd, msg.hwnd))) {
            if (msg.wParam == VK_RETURN) { SendMessageA(hwnd, WM_COMMAND, IDOK, 0); continue; }
            if (msg.wParam == VK_ESCAPE) { SendMessageA(hwnd, WM_COMMAND, IDCANCEL, 0); continue; }
        }

        if (!IsDialogMessageA(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }

    if (parent) {
        EnableWindow(parent, TRUE);
        SetForegroundWindow(parent);
    }
    if (own_font) DeleteObject(font);

    return opt.accepted;
}
