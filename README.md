# SigMaker Pro (2026 Edition)

**SigMaker Pro** is a high-performance, precision-focused Cheat Engine plugin designed to generate update-proof code signatures (AOBs) for both x86 and x64 applications.

Unlike traditional static signature makers, this plugin utilizes the **Zydis Disassembler Engine** and a fully dynamic memory scanner to produce the **shortest possible unique pattern** — automatically calculated, never hardcoded.

---

## Key Features

* **Dynamic Pattern Length** — No fixed byte limit. The engine grows the signature instruction-by-instruction and stops the moment it's unique. Result: the most compact signature possible.
* **Exact Injection Point** — Always tries the exact target address first. Anchor-based fallback (1-byte stepping, up to 64 bytes back) is only used when absolutely necessary.
* **Update-Proof Masking** — Displacements (RIP-relative, address-relative) are **always** masked in both scan phases. Relative immediates (JMP/CALL targets) are always masked. Absolute immediates are masked in the first pass for maximum update resilience.
* **Two-Phase Scan Strategy**:
  * **Phase 0 (Update-Proof)**: Masks displacements + all immediates — survives recompilation.
  * **Phase 1 (Strict)**: Masks displacements + relative immediates only — shorter pattern when Phase 0 is too generic.
* **Architecture Auto-Detection** — Seamlessly handles 32-bit and 64-bit processes using native Windows APIs and WoW64 detection.
* **Single-Read Optimization** — The entire decode region (anchor area + forward decode space) is read in one `ReadProcessMemory` call instead of dozens.
* **Multi-Format Output** — Three output formats via the Memory Viewer context menu.
* **C++20 Powered** — Built with `std::format`, `std::span`, `constexpr`, structured bindings, and `[[nodiscard]]`.

---

## How It Works

```
1. Read 320 bytes of memory (64 back + 256 forward) in a single call
2. Start at the exact target address (offset = 0)
3. Decode one instruction at a time using Zydis
4. Mask displacement bytes + immediate bytes based on phase
5. After each instruction: trim trailing wildcards, scan module for matches
6. If matches == 1 → done (shortest unique signature found)
7. If no unique sig at offset 0 → step back 1 byte, repeat (up to 64 bytes)
8. Phase 0 fails entirely → try Phase 1 (stricter masking, fewer wildcards)
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
Standard Cheat Engine format with `*` wildcards.
> `48 83 EC * E8 * * * * 48 83 C4 *`

### 2. Copy C++ Pattern
Ready-to-use byte array and mask for internal/external tools.
> `\x48\x83\xEC\x00\xE8\x00\x00\x00\x00\x48\x83\xC4\x00`
> `xxx?x????xxx?`

### 3. Copy Address Info
Module-relative offset for documentation and static analysis.
> `Game-Win64-Shipping.exe + 0x1234AB = 0x7FF65FD0FDF8`

---

## Changelog (v2 — Dynamic Engine Rewrite)

### Changed
- **Dynamic pattern length**: Removed the fixed `MAX_PATTERN_LENGTH = 32` limit. Signatures now grow dynamically until unique — no manual tuning needed.
- **Displacements always masked**: Both phases now mask displacements. Previously Phase 1 left them unmasked, which could break signatures after updates.
- **1-byte anchor stepping**: Changed from 10-byte steps to 1-byte steps for precise anchor placement when fallback is needed.
- **Single memory read**: The entire decode region (320 bytes) is pre-read in one `ReadProcessMemory` call instead of up to 64 separate calls.
- **Decode buffer increased**: From 128 to 256 bytes forward, allowing unique signatures for code in highly repetitive regions.
- **Anchor range increased**: From 50 to 64 bytes back, covering more potential anchor points.

### Removed
- `MAX_PATTERN_LENGTH` constant (replaced by dynamic growth)
- `ANCHOR_STEP` constant (replaced by 1-byte stepping)

### Fixed
- Phase 1 no longer leaves displacements unmasked — all signatures are now update-safe by default.
- Eliminated per-offset heap allocations in the anchor loop.

---

## Build Requirements

* **Visual Studio 2022** (or newer)
* **C++20 Standard** enabled
* **Zydis Disassembler Library** (Include & Lib)
* **Windows SDK** (for PSAPI and Memory APIs)

---

## Credits
Developed by **gmax17**.
Special thanks to the **Zydis** team for their incredible disassembly library.

---
*Disclaimer: This tool is intended for educational purposes and reverse engineering only.*
