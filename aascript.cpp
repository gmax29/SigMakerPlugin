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
    const std::string sym = sanitize_symbol(opt.symbol);
    const std::string restore = sym + "_restore";
    const int inject_off = -sig.anchor_offset;
    const std::string inject = inject_off > 0 ? std::format("{}+{:X}", sym, inject_off) : sym;

    const SIZE_T jump_size = opt.min_bytes >= 14 ? 14 : 5;
    const bool far_jump = jump_size == 14;

    std::string b;

    b += "{ Game   : " + snap.mod_name + "\n";
    b += "  Version: " + opt.version + "\n";
    b += "  Date   : " + today() + "\n";
    b += "  Author : " + opt.author + "\n";
    b += "  Description : " + opt.description + "\n\n";
    b += "  <Optional info>\n";
    b += "}\n\n";

    b += "[ENABLE]\n\n";

    if (!opt.function_symbol.empty()) {
        b += std::format("aobscanfunction({},{},{})  // should be unique in this function\n",
            sym, opt.function_symbol, sig.data.ce_style);
    }
    else {
        b += std::format("aobscanmodule({},{},{})  // should be unique\n", sym, snap.mod_name, sig.data.ce_style);
    }

    if (far_jump) b += "alloc(newmem,$1000)\n\n";
    else b += std::format("alloc(newmem,$1000,{})\n\n", sym);

    b += "label(code)\n";
    b += "label(return)\n";
    if (opt.restore_mode == 1) b += std::format("label({})\n", restore);
    b += "\n";

    b += "newmem:\n\n";
    b += "code:\n";

    if (opt.code_mode == 0) {
        for (const auto& s : stolen) {
            const ULONG_PTR off = (s.addr - address) + static_cast<ULONG_PTR>(inject_off);
            b += off ? std::format("  reassemble({}+{:X})\n", sym, off)
                     : std::format("  reassemble({})\n", sym);
        }
    }
    else {
        for (const auto& s : stolen) b += std::format("  // {:X}: {}\n", s.addr, s.text);
        b += std::format("  readmem({},{})\n", inject, stolen_len);
    }

    b += "  jmp return\n\n";

    if (opt.restore_mode == 1) {
        b += restore + ":\n";
        b += std::format("  readmem({},{})\n\n", inject, stolen_len);
    }

    b += inject + ":\n";
    b += far_jump ? "  jmp far newmem\n" : "  jmp newmem\n";

    const SIZE_T pad = stolen_len > jump_size ? stolen_len - jump_size : 0;
    if (pad == 1) b += "  nop\n";
    else if (pad > 1) b += std::format("  nop {}\n", pad);

    b += "return:\n";
    b += std::format("registersymbol({})\n", sym);
    if (opt.restore_mode == 1) b += std::format("registersymbol({})\n", restore);
    b += "\n";

    b += "[DISABLE]\n\n";
    b += inject + ":\n";

    if (opt.restore_mode == 1) {
        b += std::format("  readmem({},{})\n\n", restore, stolen_len);
        b += "unregistersymbol(*)\n";
        b += "dealloc(*)\n";
    }
    else {
        b += "  db " + byte_list(snap, address, stolen_len) + "\n\n";
        b += std::format("unregistersymbol({})\n", sym);
        b += "dealloc(newmem)\n";
    }

    b += "\n{\n";
    b += "// ORIGINAL CODE - INJECTION POINT: " +
        (opt.address_text.empty() ? snap.mod_name + std::format("+{:X}", address - snap.mod_base) : opt.address_text) + "\n\n";
    b += "// ---------- INJECTING HERE ----------\n";
    for (const auto& s : stolen) {
        b += std::format("{}+{:X}: {}\n", snap.mod_name, s.addr - snap.mod_base, s.text);
    }
    b += "// ---------- DONE INJECTING  ----------\n";
    b += "}\n";

    return b;
}


namespace {

constexpr int ID_ADDR = 100, ID_SYM = 101, ID_DESC = 102, ID_VER = 103, ID_AUTHOR = 104;
constexpr int ID_B5 = 110, ID_B14 = 111, ID_BCUSTOM = 112, ID_BVAL = 113;
constexpr int ID_CODE_ASM = 120, ID_CODE_MEM = 121;
constexpr int ID_RES_DB = 130, ID_RES_MEM = 131;

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
            o.symbol = text_of(hwnd, ID_SYM);
            o.description = text_of(hwnd, ID_DESC);
            o.version = text_of(hwnd, ID_VER);
            o.author = text_of(hwnd, ID_AUTHOR);

            if (IsDlgButtonChecked(hwnd, ID_B5) == BST_CHECKED) o.min_bytes = 5;
            else if (IsDlgButtonChecked(hwnd, ID_B14) == BST_CHECKED) o.min_bytes = 14;
            else {
                o.min_bytes = std::atoi(text_of(hwnd, ID_BVAL).c_str());
                if (o.min_bytes < 1) o.min_bytes = 5;
            }

            o.code_mode = IsDlgButtonChecked(hwnd, ID_CODE_MEM) == BST_CHECKED ? 1 : 0;
            o.restore_mode = IsDlgButtonChecked(hwnd, ID_RES_MEM) == BST_CHECKED ? 1 : 0;
            o.accepted = !o.symbol.empty();

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
    RECT rc{ 0, 0, 470, 452 };
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

    add(hwnd, "STATIC", "Address", 0, 12, 10, 446, 16, -1, inst, font);
    add(hwnd, "EDIT", opt.address_text.c_str(), WS_BORDER | ES_AUTOHSCROLL | ES_READONLY, 12, 28, 446, 22, ID_ADDR, inst, font);

    add(hwnd, "STATIC", "Symbol", 0, 12, 58, 446, 16, -1, inst, font);
    add(hwnd, "EDIT", opt.symbol.c_str(), ED, 12, 76, 446, 22, ID_SYM, inst, font);

    add(hwnd, "STATIC", "Description", 0, 12, 106, 446, 16, -1, inst, font);
    add(hwnd, "EDIT", opt.description.c_str(), ED, 12, 124, 446, 22, ID_DESC, inst, font);

    add(hwnd, "STATIC", "Version", 0, 12, 154, 215, 16, -1, inst, font);
    add(hwnd, "STATIC", "Author", 0, 243, 154, 215, 16, -1, inst, font);
    add(hwnd, "EDIT", opt.version.c_str(), ED, 12, 172, 215, 22, ID_VER, inst, font);
    add(hwnd, "EDIT", opt.author.c_str(), ED, 243, 172, 215, 22, ID_AUTHOR, inst, font);

    add(hwnd, "BUTTON", "Bytes to steal", BS_GROUPBOX, 12, 206, 446, 62, -1, inst, font);
    add(hwnd, "BUTTON", "5  (jmp)", WS_TABSTOP | WS_GROUP | BS_AUTORADIOBUTTON, 26, 230, 110, 20, ID_B5, inst, font);
    add(hwnd, "BUTTON", "14  (jmp far)", WS_TABSTOP | BS_AUTORADIOBUTTON, 146, 230, 120, 20, ID_B14, inst, font);
    add(hwnd, "BUTTON", "custom", WS_TABSTOP | BS_AUTORADIOBUTTON, 276, 230, 80, 20, ID_BCUSTOM, inst, font);
    add(hwnd, "EDIT", std::format("{}", opt.min_bytes).c_str(), ED | WS_GROUP, 366, 229, 78, 22, ID_BVAL, inst, font);

    add(hwnd, "BUTTON", "newmem code block", BS_GROUPBOX, 12, 278, 446, 56, -1, inst, font);
    add(hwnd, "BUTTON", "reassemble", WS_TABSTOP | WS_GROUP | BS_AUTORADIOBUTTON, 26, 300, 200, 20, ID_CODE_ASM, inst, font);
    add(hwnd, "BUTTON", "readmem", WS_TABSTOP | BS_AUTORADIOBUTTON, 243, 300, 200, 20, ID_CODE_MEM, inst, font);

    add(hwnd, "BUTTON", "DISABLE restore", BS_GROUPBOX, 12, 344, 446, 56, -1, inst, font);
    add(hwnd, "BUTTON", "db bytes", WS_TABSTOP | WS_GROUP | BS_AUTORADIOBUTTON, 26, 366, 200, 20, ID_RES_DB, inst, font);
    add(hwnd, "BUTTON", "readmem from copy", WS_TABSTOP | BS_AUTORADIOBUTTON, 243, 366, 200, 20, ID_RES_MEM, inst, font);

    add(hwnd, "BUTTON", "OK", WS_TABSTOP | BS_DEFPUSHBUTTON, 282, 412, 84, 26, IDOK, inst, font);
    add(hwnd, "BUTTON", "Cancel", WS_TABSTOP | BS_PUSHBUTTON, 374, 412, 84, 26, IDCANCEL, inst, font);

    const int byte_id = opt.min_bytes == 5 ? ID_B5 : (opt.min_bytes == 14 ? ID_B14 : ID_BCUSTOM);
    CheckRadioButton(hwnd, ID_B5, ID_BCUSTOM, byte_id);
    CheckRadioButton(hwnd, ID_CODE_ASM, ID_CODE_MEM, opt.code_mode == 1 ? ID_CODE_MEM : ID_CODE_ASM);
    CheckRadioButton(hwnd, ID_RES_DB, ID_RES_MEM, opt.restore_mode == 1 ? ID_RES_MEM : ID_RES_DB);

    if (parent) EnableWindow(parent, FALSE);
    ShowWindow(hwnd, SW_SHOW);
    SetFocus(GetDlgItem(hwnd, ID_SYM));

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
