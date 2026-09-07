#define NOMINMAX
#include <cstdio>
#include <cstring>
#include "sigmaker.h"
#include "snapshot.cpp"
#include "signature.cpp"
#include "aascript.cpp"

static int failures = 0;
static void check(bool ok, const char* what) {
    std::printf("%s  %s\n", ok ? "[ OK ]" : "[FAIL]", what);
    if (!ok) ++failures;
}

static constexpr ULONG_PTR BASE = 0x140000000ull;

static ModuleSnapshot make_snap(size_t size) {
    ModuleSnapshot s;
    s.mod_base = BASE; s.mod_size = size; s.mod_name = "test.exe"; s.has_module = true;
    SnapshotRegion r;
    r.base = BASE; r.size = size;
    r.bytes.reset(new uint8_t[size]);
    std::memset(r.bytes.get(), 0x90, size);
    s.regions.push_back(std::move(r));
    return s;
}

static void plant(ModuleSnapshot& s, size_t off, const uint8_t* b, size_t n) {
    std::memcpy(s.regions[0].bytes.get() + off, b, n);
}

// Six register-only instructions, nothing maskable, then ret and int 3 padding.
static const uint8_t FUNC[] = {
    0x48,0x89,0xC8, 0x48,0x01,0xD8, 0x48,0x31,0xC9,
    0x48,0x29,0xD0, 0x48,0x09,0xC1, 0x48,0x21,0xD9, 0xC3,
    0xCC,0xCC,0xCC,0xCC
};
static constexpr size_t FUNC_CODE = 19;

static ZydisDecoder DEC;

int main() {
    ZydisDecoderInit(&DEC, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    // ---- Defect 1: the pattern must reach as far as the patch ----
    {
        ModuleSnapshot s = make_snap(64 * 1024);
        plant(s, 0x1000, FUNC, sizeof(FUNC));
        const ULONG_PTR addr = BASE + 0x1000;

        SignatureResult a;
        check(build_signature(s, DEC, addr, a), "unconstrained signature builds");
        const ULONG_PTR a_end = addr + a.anchor_offset + a.data.cpp_mask.size();
        std::printf("       len=%zu anchor=%d reaches +%llu\n",
            a.data.cpp_mask.size(), a.anchor_offset, (unsigned long long)(a_end - addr));
        check(a_end - addr < 16, "unconstrained signature stops well short of 16 bytes");

        SignatureResult b;
        check(build_signature(s, DEC, addr, b, 0, 0, addr + 16), "constrained signature builds");
        const ULONG_PTR b_end = addr + b.anchor_offset + b.data.cpp_mask.size();
        std::printf("       len=%zu anchor=%d reaches +%llu\n",
            b.data.cpp_mask.size(), b.anchor_offset, (unsigned long long)(b_end - addr));
        check(b_end >= addr + 16, "constrained signature covers every patched byte");
        check(b.module_unique, "unique function is reported module wide");
    }

    // ---- The anchor must not be able to fake the span ----
    {
        ModuleSnapshot s = make_snap(64 * 1024);
        // The body repeats, so only the differing instruction in front can pin it down.
        const uint8_t lead_a[] = { 0x48,0x89,0xD1 };
        const uint8_t lead_b[] = { 0x48,0x31,0xDB };
        plant(s, 0x1000, lead_a, sizeof(lead_a));
        plant(s, 0x1003, FUNC, sizeof(FUNC));
        plant(s, 0x3000, lead_b, sizeof(lead_b));
        plant(s, 0x3003, FUNC, sizeof(FUNC));
        const ULONG_PTR addr = BASE + 0x1003;

        SignatureResult r;
        check(build_signature(s, DEC, addr, r, 0, 0, addr + 18), "signature builds with a leading instruction");
        const ULONG_PTR end = addr + r.anchor_offset + r.data.cpp_mask.size();
        std::printf("       len=%zu anchor=%d reaches +%lld\n",
            r.data.cpp_mask.size(), r.anchor_offset, (long long)(end - addr));
        check(r.anchor_offset < 0, "the pattern really did start before the address");
        check(end >= addr + 18, "span is measured from the address, not from the anchor");
    }

    // ---- Defect 2: the reported scope must match reality ----
    {
        ModuleSnapshot s = make_snap(64 * 1024);
        plant(s, 0x1000, FUNC, sizeof(FUNC));
        plant(s, 0x3000, FUNC, sizeof(FUNC));   // byte-identical twin elsewhere
        const ULONG_PTR addr = BASE + 0x1000;

        SignatureResult wide;
        check(!build_signature(s, DEC, addr, wide), "duplicated function has no module wide signature");

        SignatureResult scoped;
        const bool ok = build_signature(s, DEC, addr, scoped, addr, addr + FUNC_CODE);
        check(ok, "duplicated function still resolves inside its own range");
        if (ok) check(!scoped.module_unique, "scope is reported as function only, not module wide");
    }

    // ---- Scanner invariants ----
    {
        ModuleSnapshot s = make_snap(3 * 1024 * 1024);
        uint8_t needle[16];
        for (int i = 0; i < 16; ++i) needle[i] = static_cast<uint8_t>(0xA0 + i);

        const size_t straddle = SCAN_CHUNK - 8;   // half in each chunk
        plant(s, straddle, needle, sizeof(needle));

        std::vector<PatternByte> pat;
        for (uint8_t v : needle) pat.push_back({ v, false });

        std::vector<ULONG_PTR> hits;
        check(scan_snapshot(s, pat, hits, MAX_HITS), "scan completes");
        check(hits.size() == 1, "a match across the chunk boundary is found exactly once");
        if (hits.size() == 1) check(hits[0] == BASE + straddle, "and at the right address");

        std::vector<PatternByte> huge(SCAN_CHUNK + 1, { 0x90, false });
        std::vector<ULONG_PTR> none;
        check(!scan_snapshot(s, huge, none, MAX_HITS), "a pattern larger than a chunk is refused");
    }

    // ---- collect_stolen must not walk into the padding ----
    {
        ModuleSnapshot s = make_snap(64 * 1024);
        plant(s, 0x1000, FUNC, sizeof(FUNC));
        const ULONG_PTR addr = BASE + 0x1000;

        std::vector<StolenInstr> st;
        SIZE_T len = 0;
        check(collect_stolen(s, DEC, addr, 14, st, len) && len >= 14, "14 bytes are stolen inside the function");

        st.clear(); len = 0;
        const ULONG_PTR late = BASE + 0x1000 + 15;   // 4 bytes of code left, then int 3
        check(!collect_stolen(s, DEC, late, 14, st, len), "stealing past int 3 padding is refused");
    }

    std::printf("\n%s (%d failing)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures != 0;
}
