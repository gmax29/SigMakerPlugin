#define NOMINMAX

#pragma comment(lib, "psapi.lib")

#include "loader.h"
#include <vector>
#include <string>
#include <format>
#include <span>
#include <psapi.h>
#include <algorithm>
#include <cstring>
#include <thread>
#include <mutex>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include "Zydis.h"

constexpr SIZE_T DEFAULT_MODULE_SIZE = 25 * 1024 * 1024;
constexpr SIZE_T PAGE_GRANULARITY = 0x1000;
constexpr SIZE_T SCAN_CHUNK = 2 * 1024 * 1024;

constexpr ULONG_PTR MAX_ANCHOR_RANGE = 1024;
constexpr SIZE_T MAX_DECODE_BYTES = 4096;
constexpr size_t MAX_ANCHORS = 64;
constexpr size_t MAX_HITS = 1u << 20;

// Literal backslash for the C++ pattern output.
static const std::string CPP_ESCAPE(1, static_cast<char>(92));

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

// --- MODULE SNAPSHOT ---------------------------------------------------------

struct SnapshotRegion {
    ULONG_PTR base = 0;
    std::vector<uint8_t> bytes;
};

// Every byte held here was really read from the target, so scanning never has to
// guess whether a page was readable.
struct ModuleSnapshot {
    ULONG_PTR mod_base = 0;
    SIZE_T mod_size = 0;
    std::string mod_name;
    bool has_module = false;   // false for JIT or otherwise module-less code
    std::vector<SnapshotRegion> regions;

    [[nodiscard]] const SnapshotRegion* region_of(ULONG_PTR addr) const {
        auto it = std::upper_bound(regions.begin(), regions.end(), addr,
            [](ULONG_PTR a, const SnapshotRegion& r) { return a < r.base; });
        if (it == regions.begin()) return nullptr;
        --it;
        return (addr - it->base < it->bytes.size()) ? &*it : nullptr;
    }

    [[nodiscard]] const uint8_t* ptr(ULONG_PTR addr, SIZE_T need) const {
        const SnapshotRegion* r = region_of(addr);
        if (!r) return nullptr;
        const SIZE_T off = addr - r->base;
        if (need > r->bytes.size() - off) return nullptr;
        return r->bytes.data() + off;
    }

    [[nodiscard]] bool contains(ULONG_PTR addr) const { return ptr(addr, 1) != nullptr; }
};

// EnumProcessModules alone misses 32 bit modules when the host is 64 bit.
BOOL enum_modules(HANDLE handle, HMODULE* out, DWORD cb, DWORD* needed) {
    if (EnumProcessModulesEx(handle, out, cb, needed, LIST_MODULES_ALL)) return TRUE;
    return EnumProcessModules(handle, out, cb, needed);
}

[[nodiscard]] bool find_module_info(HANDLE handle, ULONG_PTR address, ULONG_PTR& out_base, SIZE_T& out_size, char* out_name = nullptr, size_t name_size = 0) {
    std::vector<HMODULE> mods(1024);
    DWORD cb_needed = 0;

    if (!enum_modules(handle, mods.data(), static_cast<DWORD>(mods.size() * sizeof(HMODULE)), &cb_needed)) return false;

    // cb_needed is the size required, which can exceed what was actually written.
    if (cb_needed > mods.size() * sizeof(HMODULE)) {
        mods.resize(cb_needed / sizeof(HMODULE));
        if (!enum_modules(handle, mods.data(), static_cast<DWORD>(mods.size() * sizeof(HMODULE)), &cb_needed)) return false;
    }

    const size_t count = std::min<size_t>(cb_needed / sizeof(HMODULE), mods.size());
    for (size_t i = 0; i < count; ++i) {
        MODULEINFO info{};
        if (!GetModuleInformation(handle, mods[i], &info, sizeof(info))) continue;

        const auto base = reinterpret_cast<ULONG_PTR>(info.lpBaseOfDll);
        if (address >= base && address < base + info.SizeOfImage) {
            out_base = base;
            out_size = info.SizeOfImage;
            if (out_name && name_size > 0) {
                GetModuleBaseNameA(handle, mods[i], out_name, static_cast<DWORD>(name_size));
            }
            return true;
        }
    }
    return false;
}

// Splits into maximal contiguous readable runs when the region cannot be read in one go.
void read_region_runs(HANDLE handle, ULONG_PTR base, SIZE_T size, std::vector<SnapshotRegion>& out) {
    if (size == 0) return;

    SnapshotRegion whole;
    whole.base = base;
    whole.bytes.resize(size);

    SIZE_T got = 0;
    if (ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(base), whole.bytes.data(), size, &got) && got == size) {
        out.push_back(std::move(whole));
        return;
    }
    whole.bytes.clear();
    whole.bytes.shrink_to_fit();

    std::vector<uint8_t> page(PAGE_GRANULARITY);
    SnapshotRegion run;
    bool in_run = false;

    for (SIZE_T off = 0; off < size; off += PAGE_GRANULARITY) {
        const SIZE_T len = std::min(PAGE_GRANULARITY, size - off);
        SIZE_T n = 0;
        const bool ok = ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(base + off), page.data(), len, &n) && n == len;

        if (ok) {
            if (!in_run) {
                run.base = base + off;
                run.bytes.clear();
                in_run = true;
            }
            run.bytes.insert(run.bytes.end(), page.begin(), page.begin() + len);
        }
        else if (in_run) {
            out.push_back(std::move(run));
            run = SnapshotRegion{};
            in_run = false;
        }
    }
    if (in_run) out.push_back(std::move(run));
}

[[nodiscard]] bool capture_snapshot(HANDLE handle, ULONG_PTR address, ModuleSnapshot& snap) {
    char name[MAX_PATH] = {};
    ULONG_PTR mod_base = 0;
    SIZE_T mod_size = 0;

    if (find_module_info(handle, address, mod_base, mod_size, name, sizeof(name))) {
        snap.mod_name = name;
        snap.has_module = true;
    }
    else {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) return false;
        mod_base = reinterpret_cast<ULONG_PTR>(mbi.AllocationBase);
        if (!mod_base) mod_base = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress);
        mod_size = DEFAULT_MODULE_SIZE;
        snap.mod_name = "Unknown.exe";
    }

    snap.mod_base = mod_base;
    snap.mod_size = mod_size;

    constexpr DWORD EXEC_MASK = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    ULONG_PTR cursor = mod_base;

    while (cursor < mod_base + mod_size) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi))) break;

        const auto region_base = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress);
        const bool usable = mbi.State == MEM_COMMIT && (mbi.Protect & EXEC_MASK) != 0 && (mbi.Protect & PAGE_GUARD) == 0;

        if (usable && region_base >= mod_base) {
            const ULONG_PTR offset = region_base - mod_base;
            SIZE_T len = mbi.RegionSize;
            if (offset < mod_size && offset + len > mod_size) len = mod_size - offset;
            read_region_runs(handle, region_base, len, snap.regions);
        }

        const ULONG_PTR next = region_base + mbi.RegionSize;
        if (next <= cursor) break;
        cursor = next;
    }

    std::sort(snap.regions.begin(), snap.regions.end(),
        [](const SnapshotRegion& a, const SnapshotRegion& b) { return a.base < b.base; });

    return !snap.regions.empty();
}

// --- SCANNING ----------------------------------------------------------------

// Fills out with match addresses (sorted). Returns false if max_hits was reached,
// in which case the result is incomplete and must not be treated as authoritative.
bool scan_snapshot(const ModuleSnapshot& snap, std::span<const PatternByte> pat, std::vector<ULONG_PTR>& out, size_t max_hits) {
    out.clear();
    if (pat.empty()) return false;

    size_t lead = 0;
    while (lead < pat.size() && pat[lead].masked) ++lead;
    if (lead == pat.size()) return false;
    const uint8_t lead_val = pat[lead].val;

    struct Chunk {
        const uint8_t* data;
        size_t len;
        ULONG_PTR base;
    };
    std::vector<Chunk> chunks;

    for (const auto& r : snap.regions) {
        if (r.bytes.size() < pat.size()) continue;
        size_t off = 0;
        while (off + pat.size() <= r.bytes.size()) {
            const size_t len = std::min(SCAN_CHUNK, r.bytes.size() - off);
            chunks.push_back({ r.bytes.data() + off, len, r.base + off });
            if (len < SCAN_CHUNK) break;
            off += len - (pat.size() - 1);
        }
    }
    if (chunks.empty()) return true;

    unsigned worker_count = std::thread::hardware_concurrency();
    if (worker_count == 0) worker_count = 4;
    worker_count = static_cast<unsigned>(std::min<size_t>(worker_count, chunks.size()));

    std::atomic<size_t> total{ 0 };
    std::atomic<bool> capped{ false };
    std::mutex mut;

    auto worker = [&](unsigned idx) {
        std::vector<ULONG_PTR> local;

        for (size_t c = idx; c < chunks.size(); c += worker_count) {
            if (capped.load(std::memory_order_relaxed)) break;

            const Chunk& ch = chunks[c];
            const uint8_t* p = ch.data + lead;
            const uint8_t* const stop = ch.data + (ch.len - pat.size()) + lead + 1;

            while (p < stop) {
                const auto* hit = static_cast<const uint8_t*>(std::memchr(p, lead_val, static_cast<size_t>(stop - p)));
                if (!hit) break;

                const size_t j = static_cast<size_t>(hit - ch.data) - lead;
                bool match = true;
                for (size_t k = 0; k < pat.size(); ++k) {
                    if (!pat[k].masked && ch.data[j + k] != pat[k].val) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    local.push_back(ch.base + j);
                    if (total.fetch_add(1, std::memory_order_relaxed) + 1 >= max_hits) {
                        capped.store(true, std::memory_order_relaxed);
                        break;
                    }
                }
                p = hit + 1;
            }
        }

        std::lock_guard<std::mutex> lock(mut);
        out.insert(out.end(), local.begin(), local.end());
        };

    std::vector<std::thread> pool;
    pool.reserve(worker_count);
    for (unsigned i = 0; i < worker_count; ++i) pool.emplace_back(worker, i);
    for (auto& t : pool) t.join();

    std::sort(out.begin(), out.end());
    return !capped.load();
}

void filter_candidates(const ModuleSnapshot& snap, std::vector<ULONG_PTR>& candidates, std::span<const PatternByte> pat) {
    std::vector<ULONG_PTR> next;
    next.reserve(candidates.size());

    for (ULONG_PTR addr : candidates) {
        const uint8_t* p = snap.ptr(addr, pat.size());
        if (!p) continue;

        bool match = true;
        for (size_t i = 0; i < pat.size(); ++i) {
            if (!pat[i].masked && p[i] != pat[i].val) {
                match = false;
                break;
            }
        }
        if (match) next.push_back(addr);
    }
    candidates = std::move(next);
}

// --- SIGNATURE GENERATION ----------------------------------------------------

struct SignatureResult {
    SignatureData data;
    int anchor_offset = 0;   // <= 0, distance from pattern start to the target address
    bool ok = false;
    std::string error;
};

void init_decoder(HANDLE handle, ZydisDecoder& decoder) {
    BOOL is_wow64 = FALSE;
    if (IsWow64Process(handle, &is_wow64) && is_wow64) {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
        return;
    }

    SYSTEM_INFO sys_info;
    GetNativeSystemInfo(&sys_info);
    if (sys_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    }
    else {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
    }
}

// Collects the offsets inside [window, window+prefix) whose decode chain lands exactly
// on prefix. Anything else decodes garbage and is worthless as an anchor.
void collect_anchors(const ZydisDecoder& decoder, const uint8_t* window, SIZE_T prefix, std::vector<SIZE_T>& out) {
    out.clear();
    out.push_back(prefix);
    if (prefix == 0) return;

    std::vector<bool> lands_on_target(prefix + 1, false);
    lands_on_target[prefix] = true;

    for (SIZE_T s = prefix; s-- > 0;) {
        ZydisDecodedInstruction instr;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, nullptr, window + s, prefix - s, &instr))) continue;

        const SIZE_T next = s + instr.length;
        if (next <= prefix && lands_on_target[next]) {
            lands_on_target[s] = true;
            if (out.size() < MAX_ANCHORS) out.push_back(s);
        }
    }
}

[[nodiscard]] bool build_signature(const ModuleSnapshot& snap, const ZydisDecoder& decoder, ULONG_PTR address, SignatureResult& out) {
    const SnapshotRegion* reg = snap.region_of(address);
    if (!reg) {
        out.error = "ERROR: Address is not inside a readable executable region of the module.";
        return false;
    }

    const ULONG_PTR region_end = reg->base + reg->bytes.size();
    const SIZE_T prefix = static_cast<SIZE_T>(std::min<ULONG_PTR>(MAX_ANCHOR_RANGE, address - reg->base));
    const SIZE_T forward = static_cast<SIZE_T>(std::min<ULONG_PTR>(MAX_DECODE_BYTES, region_end - address));
    const uint8_t* const window = reg->bytes.data() + (address - reg->base) - prefix;

    std::vector<SIZE_T> anchors;
    collect_anchors(decoder, window, prefix, anchors);

    std::vector<PatternByte> best_pattern;
    int best_offset = 0;
    bool found = false;

    for (SIZE_T anchor : anchors) {
        if (found) break;

        const int anchor_offset = -static_cast<int>(prefix - anchor);
        const ULONG_PTR anchor_addr = address + anchor_offset;
        const uint8_t* const buf = window + anchor;
        const SIZE_T available = (prefix - anchor) + forward;

        // Phase 0 masks every immediate (update proof), phase 1 only relative ones (strict).
        for (int phase = 0; phase < 2 && !found; ++phase) {
            const bool mask_abs_imm = (phase == 0);

            std::vector<PatternByte> pattern;
            pattern.reserve(64);
            std::vector<ULONG_PTR> candidates;
            bool have_candidates = false;
            SIZE_T decode_offset = 0;

            while (decode_offset < available) {
                ZydisDecodedInstruction instr;
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buf + decode_offset, available - decode_offset, &instr, operands))) break;

                const auto disp_bytes = static_cast<ZyanU8>(instr.raw.disp.size / 8);
                const auto imm0_bytes = static_cast<ZyanU8>(instr.raw.imm[0].size / 8);
                const auto imm1_bytes = static_cast<ZyanU8>(instr.raw.imm[1].size / 8);
                const bool is_nop = (instr.mnemonic == ZYDIS_MNEMONIC_NOP);

                for (uint8_t i = 0; i < instr.length; ++i) {
                    bool mask = is_nop;

                    if (!mask && disp_bytes > 0 && i >= instr.raw.disp.offset && i < instr.raw.disp.offset + disp_bytes) {
                        mask = true;
                    }

                    if (!mask) {
                        const struct { ZyanU8 offset; ZyanU8 size_bytes; ZyanBool is_relative; } imm_info[2] = {
                            { instr.raw.imm[0].offset, imm0_bytes, instr.raw.imm[0].is_relative },
                            { instr.raw.imm[1].offset, imm1_bytes, instr.raw.imm[1].is_relative },
                        };

                        for (const auto& [off, sz, is_rel] : imm_info) {
                            if (sz > 0 && i >= off && i < off + sz) {
                                if (is_rel || mask_abs_imm) mask = true;
                            }
                        }
                    }

                    pattern.push_back({ buf[decode_offset + i], mask });
                }

                decode_offset += instr.length;

                auto trimmed = pattern.size();
                while (trimmed > 0 && pattern[trimmed - 1].masked) --trimmed;
                if (trimmed == 0) continue;

                const std::span<const PatternByte> view(pattern.data(), trimmed);

                if (!have_candidates) {
                    // An incomplete result cannot prove uniqueness, so extend and retry.
                    if (!scan_snapshot(snap, view, candidates, MAX_HITS)) continue;
                    have_candidates = true;
                }
                else {
                    filter_candidates(snap, candidates, view);
                }

                if (!std::binary_search(candidates.begin(), candidates.end(), anchor_addr)) break;

                if (candidates.size() == 1) {
                    pattern.resize(trimmed);
                    best_pattern = std::move(pattern);
                    best_offset = anchor_offset;
                    found = true;
                    break;
                }
            }
        }
    }

    if (!found) {
        out.error = "ERROR: Signature too generic. No unique pattern found within scan range.";
        return false;
    }

    // The pattern was built incrementally; prove the final form on its own.
    std::vector<ULONG_PTR> verify;
    if (!scan_snapshot(snap, best_pattern, verify, MAX_HITS) || verify.size() != 1 || verify[0] != address + best_offset) {
        out.error = "ERROR: Final verification failed. Signature was not emitted.";
        return false;
    }

    for (const auto& pb : best_pattern) {
        if (pb.masked) {
            out.data.ce_style += "?? ";
            out.data.cpp_pattern += CPP_ESCAPE + "x00";
            out.data.cpp_mask += "?";
        }
        else {
            out.data.ce_style += std::format("{:02X} ", pb.val);
            out.data.cpp_pattern += CPP_ESCAPE + std::format("x{:02X}", pb.val);
            out.data.cpp_mask += "x";
        }
    }
    if (!out.data.ce_style.empty()) out.data.ce_style.pop_back();

    out.anchor_offset = best_offset;
    out.ok = true;
    return true;
}

// --- SYMBOL NAMES (via Cheat Engine) -----------------------------------------

bool is_all_hex(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

// Splits a name like "Menu_DevGame:UpdateDesignSettings+f5" into base and offset.
void split_symbol(const std::string& in, std::string& base, ULONG_PTR& offset) {
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

// --- HELPERS -----------------------------------------------------------------

void set_clipboard(const std::string& str) {
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

[[nodiscard]] bool get_module_info(HANDLE handle, ULONG_PTR address, std::string& mod_name, ULONG_PTR& offset) {
    ULONG_PTR mod_base = 0;
    SIZE_T mod_size = 0;
    char name[MAX_PATH] = {};

    if (find_module_info(handle, address, mod_base, mod_size, name, sizeof(name))) {
        mod_name = name;
        offset = address - mod_base;
        return true;
    }

    mod_name = "Unknown.exe";
    offset = 0;
    return false;
}

// Cheat Engine's own symbol resolver, which also knows Mono method names. Absent on
// older hosts.
bool ce_name_at(ULONG_PTR address, std::string& out) {
    if (!exports.sym_addressToName) return false;

    char buf[512] = {};
    if (!exports.sym_addressToName(address, buf, static_cast<int>(sizeof(buf) - 1))) return false;

    buf[sizeof(buf) - 1] = 0;
    out = buf;
    return !out.empty();
}

// Best expression Cheat Engine can give for an address: a Mono method or debug symbol
// when one is known, otherwise module plus offset, otherwise the bare address. The result
// is meant to be pasted straight back into Cheat Engine.
std::string describe_address(HANDLE handle, ULONG_PTR address) {
    std::string name;
    if (ce_name_at(address, name)) {
        std::string base;
        ULONG_PTR offset = 0;
        split_symbol(name, base, offset);
        if (!is_all_hex(base)) return name;
    }

    std::string mod_name;
    ULONG_PTR offset = 0;
    if (get_module_info(handle, address, mod_name, offset)) {
        return std::format("{}+{:X}", mod_name, offset);
    }
    return std::format("{:X}", address);
}

std::string offset_note(HANDLE handle, ULONG_PTR address, int anchor_offset) {
    if (anchor_offset >= 0) return {};
    return std::format("// result + 0x{:X} = {}", -anchor_offset, describe_address(handle, address));
}

// Captures the module and produces the signature. On failure the reason is in result.error.
bool prepare(HANDLE handle, ULONG_PTR address, ModuleSnapshot& snap, ZydisDecoder& decoder, SignatureResult& result) {
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

// --- CHEAT ENGINE CONTEXT MENU CALLBACKS ---

BOOL CE_CONV on_copy_aob(uintptr_t* selected_address) {
    if (!selected_address || !exports.OpenedProcessHandle) return TRUE;

    ModuleSnapshot snap;
    ZydisDecoder decoder;
    SignatureResult sig;

    if (!prepare(*exports.OpenedProcessHandle, static_cast<ULONG_PTR>(*selected_address), snap, decoder, sig)) {
        set_clipboard(sig.error);
        return TRUE;
    }

    const std::string note = offset_note(*exports.OpenedProcessHandle, static_cast<ULONG_PTR>(*selected_address), sig.anchor_offset);
    set_clipboard(note.empty() ? sig.data.ce_style : std::format("{}\n{}", sig.data.ce_style, note));
    return TRUE;
}

BOOL CE_CONV on_copy_cpp(uintptr_t* selected_address) {
    if (!selected_address || !exports.OpenedProcessHandle) return TRUE;

    ModuleSnapshot snap;
    ZydisDecoder decoder;
    SignatureResult sig;

    if (!prepare(*exports.OpenedProcessHandle, static_cast<ULONG_PTR>(*selected_address), snap, decoder, sig)) {
        set_clipboard(sig.error);
        return TRUE;
    }

    std::string out = std::format("{}\n{}", sig.data.cpp_pattern, sig.data.cpp_mask);
    if (const std::string note = offset_note(*exports.OpenedProcessHandle, static_cast<ULONG_PTR>(*selected_address), sig.anchor_offset); !note.empty()) out += "\n" + note;

    set_clipboard(out);
    return TRUE;
}

BOOL CE_CONV on_copy_addr(uintptr_t* selected_address) {
    if (!selected_address || !exports.OpenedProcessHandle) return TRUE;

    set_clipboard(describe_address(*exports.OpenedProcessHandle, static_cast<ULONG_PTR>(*selected_address)));
    return TRUE;
}

BOOL CE_CONV on_rightclick(uintptr_t selected_address, const char** name_address, BOOL* show) {
    return TRUE;
}

// --- CHEAT ENGINE PLUGIN EXPORTS ---

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
