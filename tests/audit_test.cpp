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


// readmem copies bytes verbatim, so every instruction whose meaning depends on where it
// sits has to be recognised. A displacement alone does not make one position dependent,
// and neither does an absolute immediate, so both are covered as counter examples.
struct RelCase {
    const char* text;
    uint8_t bytes[16];
    size_t len;
    bool dependent;
};

static const RelCase REL64[] = {
    { "call rel32",              {0xE8,0,0,0,0}, 5, true },
    { "jmp rel32",               {0xE9,0,0,0,0}, 5, true },
    { "jmp rel8",                {0xEB,0x10}, 2, true },
    { "jz rel8",                 {0x74,0x10}, 2, true },
    { "jnz rel8",                {0x75,0x10}, 2, true },
    { "jz rel32",                {0x0F,0x84,0,0,0,0}, 6, true },
    { "jrcxz rel8",              {0xE3,0x10}, 2, true },
    { "loop rel8",               {0xE2,0x10}, 2, true },
    { "mov rax,[rip+d]",         {0x48,0x8B,0x05,0,0,0,0}, 7, true },
    { "lea rax,[rip+d]",         {0x48,0x8D,0x05,0,0,0,0}, 7, true },
    { "mov eax,[rip+d]",         {0x8B,0x05,0,0,0,0}, 6, true },
    { "call [rip+d]",            {0xFF,0x15,0,0,0,0}, 6, true },
    { "jmp [rip+d]",             {0xFF,0x25,0,0,0,0}, 6, true },
    { "cmp [rip+d],rax",         {0x48,0x39,0x05,0,0,0,0}, 7, true },
    { "cmp qword [rip+d],0",     {0x48,0x83,0x3D,0,0,0,0,0}, 8, true },
    { "mov dword [rip+d],2A",    {0xC7,0x05,0,0,0,0,0x2A,0,0,0}, 10, true },
    { "movss xmm0,[rip+d]",      {0xF3,0x0F,0x10,0x05,0,0,0,0}, 8, true },

    { "mov rax,rcx",             {0x48,0x89,0xC8}, 3, false },
    { "mov [rcx+8],rax",         {0x48,0x89,0x41,0x08}, 4, false },
    { "mov rax,[rsp]",           {0x48,0x8B,0x04,0x24}, 4, false },
    { "mov rax,[rsp+80]",        {0x48,0x8B,0x84,0x24,0x80,0,0,0}, 8, false },
    { "mov eax,[rbp-8]",         {0x8B,0x45,0xF8}, 3, false },
    { "call rax",                {0xFF,0xD0}, 2, false },
    { "jmp rax",                 {0xFF,0xE0}, 2, false },
    { "push rax",                {0x50}, 1, false },
    { "sub rsp,20",              {0x48,0x83,0xEC,0x20}, 4, false },
    { "mov rax,imm64",           {0x48,0xB8,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11}, 10, false },
    { "mov eax,imm32",           {0xB8,0x78,0x56,0x34,0x12}, 5, false },
    { "syscall",                 {0x0F,0x05}, 2, false },
    { "ret",                     {0xC3}, 1, false },
};

// 32 bit has no rip relative form, so an absolute memory operand must stay unflagged
// while a relative branch must still be caught.
static const RelCase REL32[] = {
    { "call rel32",              {0xE8,0,0,0,0}, 5, true },
    { "jmp rel8",                {0xEB,0x10}, 2, true },
    { "jz rel32",                {0x0F,0x84,0,0,0,0}, 6, true },
    { "mov eax,[abs32]",         {0x8B,0x05,0x78,0x56,0x34,0x12}, 6, false },
    { "mov eax,[12345678]",      {0xA1,0x78,0x56,0x34,0x12}, 5, false },
    { "mov eax,[ebp-8]",         {0x8B,0x45,0xF8}, 3, false },
    { "push eax",                {0x50}, 1, false },
};

static void run_rel_cases(const ZydisDecoder& dec, const RelCase* cases, size_t n, const char* label) {
    size_t wrong = 0;
    for (size_t i = 0; i < n; ++i) {
        const RelCase& c = cases[i];
        ZydisDecodedInstruction in;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, c.bytes, c.len, &in, ops))) {
            std::printf("       %-24s decode failed\n", c.text);
            ++wrong;
            continue;
        }
        if (in.length != c.len) {
            std::printf("       %-24s length %u, expected %zu\n", c.text, in.length, c.len);
            ++wrong;
            continue;
        }

        const bool got = (in.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0;
        if (got != c.dependent) {
            std::printf("       %-24s flagged %s, expected %s\n",
                c.text, got ? "yes" : "no", c.dependent ? "yes" : "no");
            ++wrong;
        }
    }
    char what[128];
    std::snprintf(what, sizeof(what), "%s: all %zu instruction forms classified correctly", label, n);
    check(wrong == 0, what);
}

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

    // ---- every position dependent form readmem could copy must be recognised ----
    {
        run_rel_cases(DEC, REL64, sizeof(REL64) / sizeof(REL64[0]), "64 bit");

        ZydisDecoder d32;
        ZydisDecoderInit(&d32, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
        run_rel_cases(d32, REL32, sizeof(REL32) / sizeof(REL32[0]), "32 bit");
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
