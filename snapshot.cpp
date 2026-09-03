#define NOMINMAX

#pragma comment(lib, "psapi.lib")

#include "sigmaker.h"

#include <atomic>
#include <cstring>
#include <mutex>
#include <thread>

#include <psapi.h>

static BOOL enum_modules(HANDLE handle, HMODULE* out, DWORD cb, DWORD* needed) {
    if (EnumProcessModulesEx(handle, out, cb, needed, LIST_MODULES_ALL)) return TRUE;
    return EnumProcessModules(handle, out, cb, needed);
}

bool find_module_info(HANDLE handle, ULONG_PTR address, ULONG_PTR& out_base, SIZE_T& out_size, char* out_name, size_t name_size) {
    std::vector<HMODULE> mods(1024);
    DWORD cb_needed = 0;

    if (!enum_modules(handle, mods.data(), static_cast<DWORD>(mods.size() * sizeof(HMODULE)), &cb_needed)) return false;

    if (cb_needed > mods.size() * sizeof(HMODULE)) {
        std::vector<HMODULE> bigger(cb_needed / sizeof(HMODULE));
        DWORD bigger_needed = 0;

        if (enum_modules(handle, bigger.data(), static_cast<DWORD>(bigger.size() * sizeof(HMODULE)), &bigger_needed)) {
            mods = std::move(bigger);
            cb_needed = bigger_needed;
        }
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

static void read_region_runs(HANDLE handle, ULONG_PTR base, SIZE_T size, std::vector<SnapshotRegion>& out) {
    if (size == 0) return;

    std::unique_ptr<uint8_t[]> buffer(new (std::nothrow) uint8_t[size]);
    if (!buffer) return;

    SIZE_T got = 0;
    if (ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(base), buffer.get(), size, &got) && got == size) {
        SnapshotRegion whole;
        whole.base = base;
        whole.size = size;
        whole.bytes = std::move(buffer);
        out.push_back(std::move(whole));
        return;
    }

    struct Run { SIZE_T off; SIZE_T len; };
    std::vector<Run> runs;
    bool in_run = false;

    for (SIZE_T off = 0; off < size; off += PAGE_GRANULARITY) {
        const SIZE_T len = std::min(PAGE_GRANULARITY, size - off);
        SIZE_T n = 0;

        if (ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(base + off), buffer.get() + off, len, &n) && n == len) {
            if (in_run) runs.back().len += len;
            else {
                runs.push_back({ off, len });
                in_run = true;
            }
        }
        else {
            in_run = false;
        }
    }

    if (runs.empty()) return;

    if (runs.size() == 1 && runs[0].off == 0 && runs[0].len == size) {
        SnapshotRegion whole;
        whole.base = base;
        whole.size = size;
        whole.bytes = std::move(buffer);
        out.push_back(std::move(whole));
        return;
    }

    for (const Run& r : runs) {
        SnapshotRegion piece;
        piece.bytes.reset(new (std::nothrow) uint8_t[r.len]);
        if (!piece.bytes) continue;

        std::memcpy(piece.bytes.get(), buffer.get() + r.off, r.len);
        piece.base = base + r.off;
        piece.size = r.len;
        out.push_back(std::move(piece));
    }
}

bool capture_snapshot(HANDLE handle, ULONG_PTR address, ModuleSnapshot& snap) {
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
        if (r.size < pat.size()) continue;
        size_t off = 0;
        while (off + pat.size() <= r.size) {
            const size_t len = std::min(SCAN_CHUNK, r.size - off);
            chunks.push_back({ r.bytes.get() + off, len, r.base + off });
            if (len < SCAN_CHUNK) break;
            off += len - (pat.size() - 1);
        }
    }
    if (chunks.empty()) return true;

    size_t total_bytes = 0;
    for (const auto& c : chunks) total_bytes += c.len;

    unsigned worker_count = 1;
    if (chunks.size() > 1 && total_bytes >= PARALLEL_THRESHOLD) {
        worker_count = std::thread::hardware_concurrency();
        if (worker_count == 0) worker_count = 4;
        worker_count = static_cast<unsigned>(std::min<size_t>(worker_count, chunks.size()));
    }

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

    if (worker_count == 1) {
        worker(0);
    }
    else {
        std::vector<std::thread> pool;
        pool.reserve(worker_count);
        for (unsigned i = 0; i < worker_count; ++i) pool.emplace_back(worker, i);
        for (auto& t : pool) t.join();
    }

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
