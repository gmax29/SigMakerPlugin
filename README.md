# SigMaker Pro (2026 Edition)

**SigMaker Pro** is a high-performance, precision-focused Cheat Engine plugin designed to generate update-proof code signatures (AOBs) for both x86 and x64 applications.

Unlike traditional static signature makers, this plugin utilizes the **Zydis Disassembler Engine** and a fully dynamic memory scanner to produce the **shortest possible unique pattern** — automatically calculated, never hardcoded.

---

## Key Features

* **Dynamic Pattern Length** — No fixed byte limit. The engine grows the signature instruction-by-instruction and stops the moment it's unique. Result: the most compact signature possible.
* **Exact Injection Point** — Always tries the exact target address first. Anchor-based fallback steps back over real instruction boundaries (up to 1024 bytes) and is only used when absolutely necessary.
* **Update-Proof Masking** — Displacements (RIP-relative, address-relative) are **always** masked in both scan phases. Relative immediates (JMP/CALL targets) are always masked. Absolute immediates are masked in the first pass for maximum update resilience.
* **Two-Phase Scan Strategy**:
  * **Phase 0 (Update-Proof)**: Masks displacements + all immediates — survives recompilation.
  * **Phase 1 (Strict)**: Masks displacements + relative immediates only — shorter pattern when Phase 0 is too generic.
* **Architecture Auto-Detection** — Seamlessly handles 32-bit and 64-bit processes using native Windows APIs and WoW64 detection.
* **Module Snapshot Scanner** — The executable memory of the target module is read once per lookup; every uniqueness check then runs against that local copy instead of issuing fresh `ReadProcessMemory` calls. Large scans are spread across all CPU cores, small ones stay on one thread.
* **Symbol-Aware Addresses** — Address output goes through Cheat Engine's own resolver first, so Mono methods appear by name instead of as a raw pointer.
* **Multi-Format Output** — Three output formats via the Memory Viewer context menu.
* **C++20 Powered** — Built with `std::format`, `std::span`, `constexpr`, structured bindings, and `[[nodiscard]]`.

---

## How It Works

```
1. Snapshot the executable regions of the target module into local memory (once)
2. Collect anchor candidates: decode chains that land exactly on the target address
3. Start at the exact target address (offset = 0)
4. Decode one instruction at a time using Zydis
5. Mask displacement bytes + immediate bytes based on phase
6. After each instruction: trim trailing wildcards, scan the snapshot for matches
7. First check keeps every match address; later checks only re-test those candidates
8. If matches == 1 and it sits at the expected address → done
9. Otherwise try the next anchor, then Phase 1 (stricter masking, fewer wildcards)
10. Re-verify the finished pattern on its own before emitting it
```

---

## Installation

1. **Download**: Grab the latest `SigMaker.dll` from the [Releases](https://github.com/gmax29/SigMakerPlugin/tree/main/Releases) section.
2. **Move to Plugins**: Copy the DLL into your Cheat Engine `plugins` folder:
   * Example: `C:\Program Files\Cheat Engine\plugins`
3. **Enable**:
   * Open Cheat Engine.
   * Go to **Edit -> Settings -> Plugins**.
   * Click **"Add new"**, select your DLL, and ensure the checkbox is checked.
4. **Usage**: In the **Memory Viewer**, right-click any instruction and select one of the "Copy" options from the menu.

---

## Available Output Formats

### 1. Copy AOB Sig
Standard Cheat Engine AOB format with `*` wildcards. Trailing wildcards are trimmed, so
the pattern always ends on a fixed byte.
> `48 8B 8F * * * * 48 8B 97 * * * * E8`

When the signature had to be anchored before the selected instruction, a second line names
the target it points at.
> `// result + 0x7 = Game-Win64-Shipping.exe+1234AB`

### 2. Copy C++ Pattern
Ready-to-use byte array and mask for internal/external tools.
> `\x48\x8B\x8F\x00\x00\x00\x00\x48\x8B\x97\x00\x00\x00\x00\xE8`
> `xxx????xxx????x`

### 3. Copy Address Info
Whatever Cheat Engine can resolve for the address: a Mono method or debug symbol first,
then module plus offset, then the bare address.
> `Menu_DevGame:UpdateDesignSettings+f5`
> `Game-Win64-Shipping.exe+1234AB`

---

## Changelog (1.0.6 — Source Layout)

Housekeeping only. Generated signatures are byte for byte identical to 1.0.5, so there is
no reason to update if 1.0.5 already works for you.

### Changed
- **`loader.cpp` split into modules.** 743 lines in one file became four focused ones:
  `sigmaker.h` (types, constants, declarations), `snapshot.cpp` (module lookup, memory
  capture, scanning), `signature.cpp` (decoding, masking, pattern building) and
  `loader.cpp`, which now holds only the Cheat Engine plugin glue.
- **Comments trimmed** to the ones that explain a decision the code cannot show on its own,
  such as why scan chunks overlap or why the thread pool is tied to a size threshold.
  File-local helpers are `static` now.

---

## Changelog (1.0.5 — Memory & Output)

### Changed
- **Wildcards print as `*` again** in the AOB output. `Copy C++ Pattern` is unaffected and
  keeps `\x00` / `?`.
- **Snapshot buffers are no longer zero-filled.** The region was previously held in a
  `std::vector`, whose `resize()` fills the whole buffer with zeros before
  `ReadProcessMemory` overwrites it — a pointless memset of the entire `.text` section and
  a second pass over every page, on every lookup. It is now a raw array that `new[]` leaves
  uninitialised.
- **Exact allocations in the page-wise fallback.** When a region cannot be read in one go,
  the readable stretches were accumulated with `insert()`, which can leave the buffer
  holding roughly twice its content. The pages now go into one buffer and each stretch is
  cut to size afterwards.
- **Candidate limit lowered** from 1,048,576 to 65,536 addresses. On overflow the scan
  already reports itself incomplete and the caller extends the pattern instead, so the
  larger list was never needed — it only cost memory and sorting time.
- **The thread pool is only built when it pays off.** A fresh pool was spawned for every
  scan, including the very small ones that run dozens of times per signature. Scans below
  4 MB now run on the calling thread.

On a synthetic 48 MB section with 22,500 near-identical decoys, signature generation went
from about 12 ms to 4-6 ms.

---

## Changelog (1.0.5 — Snapshot Scanner & Zydis 5)

### Changed
- **Zydis updated 4.1 → 5.0.0.** Newer instruction tables and decoder fixes.
- **One-shot module snapshot.** All executable regions of the target module are read into
  local memory once per lookup; every uniqueness check and candidate filter then runs
  against that snapshot instead of issuing a fresh `ReadProcessMemory` call per attempt.
  This is what actually fixed the multi-minute freeze on generic signatures — the earlier
  candidate-list optimization still re-scanned the whole module per anchor.
- **Instruction-aligned anchors.** Fallback anchors are now real decode-chain boundaries
  (found by decoding forward once) instead of every byte offset, cutting anchor attempts
  from up to 1024 to a few dozen.
- **Full-module scan is multithreaded**, split into 2 MB chunks across all CPU cores, with
  a `memchr`-based prefilter on the first unmasked byte.
- **`Copy Address Info`** now asks Cheat Engine's own symbol resolver first, so Mono/IL2CPP
  methods print as `Menu_DevGame:UpdateDesignSettings+f5` instead of a bare hex address;
  falls back to `module+offset`, then the raw address.

### Fixed
- Uncovered/invalid addresses now fail immediately with a clear error instead of scanning
  the whole module empty-handed on every anchor attempt.
- `EnumProcessModules` buffer could be overrun on processes with >1024 modules.
- `ReadProcessMemory` partial reads (`STATUS_PARTIAL_COPY`) were discarded outright instead
  of being accepted where they still covered the needed range.
- A generated signature is now re-verified as a whole (exactly one hit, at the expected
  address) before being emitted; previously an incrementally-built pattern was trusted
  without a final check.
- `GlobalFree` leak in the clipboard helper when `SetClipboardData` failed.

---

## Credits
Developed by **gmax17**.
Special thanks to the **Zydis** team for their incredible disassembly library.

---
*Disclaimer: This tool is intended for educational purposes and reverse engineering only.*
