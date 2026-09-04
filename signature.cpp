#define NOMINMAX

#include "sigmaker.h"

#include <format>

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

static void collect_anchors(const ZydisDecoder& decoder, const uint8_t* window, SIZE_T prefix, std::vector<SIZE_T>& out) {
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

bool build_signature(const ModuleSnapshot& snap, const ZydisDecoder& decoder, ULONG_PTR address, SignatureResult& out,
    ULONG_PTR lo, ULONG_PTR hi) {
    const SnapshotRegion* reg = snap.region_of(address);
    if (!reg) {
        out.error = "ERROR: Address is not inside a readable executable region of the module.";
        return false;
    }

    ULONG_PTR low = reg->base;
    ULONG_PTR high = reg->base + reg->size;
    if (lo && lo > low && lo <= address) low = lo;
    if (hi && hi < high && hi > address) high = hi;

    const SIZE_T prefix = static_cast<SIZE_T>(std::min<ULONG_PTR>(MAX_ANCHOR_RANGE, address - low));
    const SIZE_T forward = static_cast<SIZE_T>(std::min<ULONG_PTR>(MAX_DECODE_BYTES, high - address));

    auto in_range = [&](ULONG_PTR a) { return a >= low && a < high; };
    auto clip = [&](std::vector<ULONG_PTR>& v) {
        if (!lo && !hi) return;
        v.erase(std::remove_if(v.begin(), v.end(), [&](ULONG_PTR a) { return !in_range(a); }), v.end());
    };
    const uint8_t* const window = reg->bytes.get() + (address - reg->base) - prefix;

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
                if (instr.mnemonic == ZYDIS_MNEMONIC_INT3) break;

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

            if (!found && have_candidates && !pattern.empty()) {
                auto trimmed = pattern.size();
                while (trimmed > 0 && pattern[trimmed - 1].masked) --trimmed;

                std::vector<ULONG_PTR> scoped = candidates;
                clip(scoped);

                if (trimmed > 0 && scoped.size() == 1 && scoped[0] == anchor_addr) {
                    pattern.resize(trimmed);
                    best_pattern = std::move(pattern);
                    best_offset = anchor_offset;
                    found = true;
                }
            }
        }
    }

    if (!found) {
        out.error = "ERROR: Signature too generic. No unique pattern found within scan range.";
        return false;
    }

    std::vector<ULONG_PTR> verify;
    const bool complete = scan_snapshot(snap, best_pattern, verify, MAX_HITS);
    clip(verify);
    if (!complete || verify.size() != 1 || verify[0] != address + best_offset) {
        out.error = "ERROR: Final verification failed. Signature was not emitted.";
        return false;
    }

    const std::string esc(1, static_cast<char>(92));

    for (const auto& pb : best_pattern) {
        if (pb.masked) {
            out.data.ce_style += WILDCARD_CHAR;
            out.data.ce_style += ' ';
            out.data.cpp_pattern += esc + "x00";
            out.data.cpp_mask += "?";
        }
        else {
            out.data.ce_style += std::format("{:02X} ", pb.val);
            out.data.cpp_pattern += esc + std::format("x{:02X}", pb.val);
            out.data.cpp_mask += "x";
        }
    }
    if (!out.data.ce_style.empty()) out.data.ce_style.pop_back();

    out.anchor_offset = best_offset;
    out.ok = true;
    return true;
}
