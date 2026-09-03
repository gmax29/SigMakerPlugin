#pragma once

#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "Zydis.h"

constexpr SIZE_T DEFAULT_MODULE_SIZE = 25 * 1024 * 1024;
constexpr SIZE_T PAGE_GRANULARITY = 0x1000;
constexpr SIZE_T SCAN_CHUNK = 2 * 1024 * 1024;
constexpr SIZE_T PARALLEL_THRESHOLD = 4 * 1024 * 1024;

constexpr ULONG_PTR MAX_ANCHOR_RANGE = 1024;
constexpr SIZE_T MAX_DECODE_BYTES = 4096;
constexpr size_t MAX_ANCHORS = 64;
constexpr size_t MAX_HITS = 1u << 16;

constexpr char WILDCARD_CHAR = '*';

struct PatternByte {
    uint8_t val;
    bool masked;
};

struct SignatureData {
    std::string ce_style;
    std::string cpp_pattern;
    std::string cpp_mask;
};

struct SignatureResult {
    SignatureData data;
    int anchor_offset = 0;
    bool ok = false;
    std::string error;
};

struct SnapshotRegion {
    ULONG_PTR base = 0;
    std::unique_ptr<uint8_t[]> bytes;
    size_t size = 0;
};

struct ModuleSnapshot {
    ULONG_PTR mod_base = 0;
    SIZE_T mod_size = 0;
    std::string mod_name;
    bool has_module = false;
    std::vector<SnapshotRegion> regions;

    [[nodiscard]] const SnapshotRegion* region_of(ULONG_PTR addr) const {
        auto it = std::upper_bound(regions.begin(), regions.end(), addr,
            [](ULONG_PTR a, const SnapshotRegion& r) { return a < r.base; });
        if (it == regions.begin()) return nullptr;
        --it;
        return (addr - it->base < it->size) ? &*it : nullptr;
    }

    [[nodiscard]] const uint8_t* ptr(ULONG_PTR addr, SIZE_T need) const {
        const SnapshotRegion* r = region_of(addr);
        if (!r) return nullptr;
        const SIZE_T off = addr - r->base;
        if (need > r->size - off) return nullptr;
        return r->bytes.get() + off;
    }

    [[nodiscard]] bool contains(ULONG_PTR addr) const { return ptr(addr, 1) != nullptr; }
};

[[nodiscard]] bool find_module_info(HANDLE handle, ULONG_PTR address, ULONG_PTR& out_base, SIZE_T& out_size,
    char* out_name = nullptr, size_t name_size = 0);

[[nodiscard]] bool capture_snapshot(HANDLE handle, ULONG_PTR address, ModuleSnapshot& snap);

bool scan_snapshot(const ModuleSnapshot& snap, std::span<const PatternByte> pat,
    std::vector<ULONG_PTR>& out, size_t max_hits);

void filter_candidates(const ModuleSnapshot& snap, std::vector<ULONG_PTR>& candidates,
    std::span<const PatternByte> pat);

void init_decoder(HANDLE handle, ZydisDecoder& decoder);

[[nodiscard]] bool build_signature(const ModuleSnapshot& snap, const ZydisDecoder& decoder,
    ULONG_PTR address, SignatureResult& out);
