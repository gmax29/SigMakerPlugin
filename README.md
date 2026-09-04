# 🚀 SigMaker Pro (2026 Edition)

**SigMaker Pro** is a high-performance, precision-focused Cheat Engine plugin designed to generate update-proof code signatures (AOBs) for both x86 and x64 applications.

Unlike traditional static signature makers, this plugin utilizes the 🧠 **Zydis Disassembler Engine** and a fully dynamic memory scanner to produce the **shortest possible unique pattern** — automatically calculated, never hardcoded.

---

## ✨ Key Features

* 📏 **Dynamic Pattern Length** — No fixed byte limit. The engine grows the signature instruction-by-instruction and stops the moment it's unique. *Result: the most compact signature possible.*
* 🎯 **Exact Injection Point** — Always tries the exact target address first. Anchor-based fallback steps back over real instruction boundaries (up to 1024 bytes) and is only used when absolutely necessary.
* 🛡️ **Update-Proof Masking** — Displacements (RIP-relative, address-relative) are **always** masked in both scan phases. Relative immediates (JMP/CALL targets) are always masked. Absolute immediates are masked in the first pass for maximum update resilience.
* 🔍 **Two-Phase Scan Strategy**:
* 🟢 **Phase 0 (Update-Proof)**: Masks displacements + all immediates — survives recompilation.
* 🟡 **Phase 1 (Strict)**: Masks displacements + relative immediates only — shorter pattern when Phase 0 is too generic.


* ⚙️ **Architecture Auto-Detection** — Seamlessly handles 32-bit and 64-bit processes using native Windows APIs and WoW64 detection.
* 📸 **Module Snapshot Scanner** — The executable memory of the target module is read *once* per lookup. Every uniqueness check runs against that local copy instead of issuing fresh `ReadProcessMemory` calls. Large scans spread across all CPU cores; small ones stay on one thread.
* 🧩 **Symbol-Aware Addresses** — Address output goes through Cheat Engine's own resolver first, so Mono methods appear by name instead of as a raw pointer.
* 💾 **Multi-Format Output** — Three flexible output formats via the Memory Viewer context menu.
* ⚡ **C++20 Powered** — Built with modern standards: `std::format`, `std::span`, `constexpr`, structured bindings, and `[[nodiscard]]`.

---

## 🛠️ How It Works

1. 📸 **Snapshot** the executable regions of the target module into local memory (once).
2. ⚓ **Collect anchors:** Find decode chains that land exactly on the target address.
3. 🏁 **Start** at the exact target address (offset = 0).
4. 🔎 **Decode** one instruction at a time using Zydis.
5. 🎭 **Mask** displacement bytes + immediate bytes based on the current phase.
6. ✂️ **Trim & Scan:** After each instruction, trim trailing wildcards and scan the snapshot for matches.
7. ♻️ **Filter:** The first check keeps every match address; later checks only re-test those candidates.
8. ✅ **Verify:** If matches == 1 and it sits at the expected address → done!
9. 🔄 **Fallback:** Otherwise, try the next anchor, then Phase 1 (stricter masking, fewer wildcards).
10. 🛡️ **Re-verify** the finished pattern on its own before emitting it.

---

## 📦 Installation

1. 📥 **Download**: Grab the latest `SigMaker.dll` from the [Releases](https://github.com/gmax29/SigMakerPlugin/tree/main/Releases) section.
2. 📂 **Move to Plugins**: Copy the DLL into your Cheat Engine `plugins` folder.
* *Example:* `C:\Program Files\Cheat Engine\plugins`


3. 🔌 **Enable**:
* Open Cheat Engine.
* Go to **Edit ➡️ Settings ➡️ Plugins**.
* Click **"Add new"**, select your DLL, and ensure the checkbox is checked ✅.


4. 🖱️ **Usage**: In the **Memory Viewer**, right-click any instruction and select one of the "Copy" options from the menu.

---

## 📋 Available Output Formats

### 1️⃣ Copy AOB Sig

Standard Cheat Engine AOB format with `*` wildcards. Trailing wildcards are trimmed, so the pattern always ends on a fixed byte.

> `48 8B 8F * * * * 48 8B 97 * * * * E8`

*If the signature had to be anchored before the selected instruction, a second line names the target it points at:*

> `// result + 0x7 = Game-Win64-Shipping.exe+1234AB`

### 2️⃣ Copy C++ Pattern

Ready-to-use byte array and mask for internal/external tools.

> `\x48\x8B\x8F\x00\x00\x00\x00\x48\x8B\x97\x00\x00\x00\x00\xE8`
> `xxx????xxx????x`

### 3️⃣ Copy Address Info

Whatever Cheat Engine can resolve for the address: a Mono method or debug symbol first, then module plus offset, then the bare address.

> `Menu_DevGame:UpdateDesignSettings+f5`
> `Game-Win64-Shipping.exe+1234AB`

---

## 🔄 Changelogs

### 🏷️ v1.0.9 — Dark Mode

* 🌙 **New:** a **Dark mode** checkbox in the generator dialog, switching live and
  remembered in `SigMaker.ini`. Covers the window background, all labels, the edit fields
  and the title bar.
* 🧹 **Changed:** the `readmem` warning comment about position dependent instructions
  was dropped from the generated script.

> Group box frames and the check marks inside radio buttons are drawn by the Windows theme
> engine, not by the plugin. They are pulled along with `SetWindowTheme`, which is
> undocumented and not equally complete on every Windows build, so a light detail may
> remain here and there.

---

### 🏷️ v1.0.8 — Auto Assembler Generator

*The generator from the 0.0.4 to 0.0.7 betas, tested in Cheat Engine and promoted to the
stable line. The signature engine is unchanged from 1.0.7.*

* 🧰 **New:** context menu entry **Generate AA Script** builds a complete injection
  script: header block, `aobscanfunction` against the enclosing function symbol, `alloc`,
  injection point, `[DISABLE]` restore and the ORIGINAL CODE comment block. It lands on the
  clipboard and is inserted into the cheat table as an auto assembler entry.
* 🎛️ **New:** dialog for the symbol, description, version, author, byte count, the
  newmem code block (`reassemble` or `readmem`) and the restore style (`db` bytes or
  `readmem`). Settings persist in `SigMaker.ini` next to the DLL.
* 📐 **New:** the byte count is a minimum and is rounded up to whole instructions, so an
  instruction is never cut in half. 5 uses `jmp` with an anchored `alloc`, 14 uses
  `jmp far` with a plain one, and the `nop` padding follows from the jump size.
* ✂️ **New:** the pattern stops growing at `int 3`, ending on the last real instruction
  instead of running into the `CC` padding and the next function. Uniqueness is still
  searched module-wide, so the signature stays update-resistant; if the room up to the
  padding is not enough, uniqueness inside the function is accepted, which is all
  `aobscanfunction` needs.
* 🔄 **New:** reassemble mode emits `reassemble(INJECT)` per stolen instruction, so Cheat
  Engine re-assembles them itself and RIP-relative operands are handled properly.

---

### 🧪 v0.0.7-beta — Stop at int3

* 🐛 **Fixed:** 0.0.6 restricted *two* things to the enclosing function, the pattern
  length and the uniqueness check. The second one was wrong: inside a single function three
  bytes are already unique, which is useless once the game updates. Uniqueness is searched
  module-wide again.
* ✂️ **Changed:** the pattern now stops growing when the decoder hits `int 3`, so it ends
  on the last real instruction instead of running into the `CC` padding and the next
  function. On the test module this yields 32 bytes ending on `E9`, where 0.0.5 ran to 37
  bytes past the boundary and 0.0.6 collapsed to 4.
* 🛟 **New:** if the room up to the padding is not enough for module-wide uniqueness, the
  pattern is accepted when it is at least unique inside the function, which is all
  `aobscanfunction` requires. Only when that fails too does it report an error.

---

### 🧪 v0.0.6-beta — Function Bounds & Reassemble

* 🐛 **Fixed:** the pattern grew past the end of the enclosing function, into the `CC`
  padding and on into the next one. Since `aobscanfunction` only searches inside the
  function, such a pattern can never be found there and the script refused to enable.
  The function range now comes from Cheat Engine’s symbol resolver: the pattern stops at
  the boundary and uniqueness is judged inside the function, which is all
  `aobscanfunction` needs. On a test module with 192 identical copies of the function this
  cuts the pattern from 37 bytes to 4.
* 🔄 **Changed:** the reassemble mode emits `reassemble(INJECT)` per stolen instruction
  instead of writing out the mnemonics. Cheat Engine re-assembles them itself, which also
  fixes RIP-relative operands properly rather than papering over them.

---

### 🧪 v0.0.5-beta — Far Jumps & Function Scans

* 🐛 **Fixed:** the 14 byte mode produced a broken script. The `nop` padding was always
  computed against a 5 byte jump, so stealing 18 bytes emitted `nop 13` instead of `nop 4`.
  The jump size now drives everything: 5 uses `jmp` with an anchored `alloc`, 14 uses
  `jmp far` with a plain `alloc`, and the padding follows.
* 🎯 **Changed:** the scan line is now `aobscanfunction` against the enclosing function
  symbol from Cheat Engine, falling back to `aobscanmodule` when no symbol is known.
* 🗃️ **New:** the finished script is inserted into the cheat table automatically,
  on top of landing on the clipboard.
* 🎛️ **Changed:** the dialog shows the resolved **Address** read-only and takes the
  **Symbol** separately, pre-filled with `INJECT`. The register symbol checkboxes are gone,
  the generator sets those itself.

---

### 🧪 v0.0.4-beta — Auto Assembler Generator

*Preview build, sitting beside the 1.0.x line rather than in it. The signature engine is
unchanged from 1.0.7 — this only adds the script generator on top.*

* 🧰 **New:** Context menu entry **Generate AA Script** builds a complete injection script:
  header block, `aobscanmodule`, `alloc`, injection point, `[DISABLE]` restore and the
  ORIGINAL CODE comment block. Lands on the clipboard, paste it into the Auto Assemble window.
* 🎛️ **New:** Dialog for symbol name, description, version, author, byte count,
  newmem code block (reassemble or `readmem`), restore style (`db` bytes or `readmem`) and
  which labels get a `registersymbol`.
* 📐 **New:** The byte count is a *minimum*. It is always rounded up to whole
  instructions, so an instruction is never cut in half: 3 becomes 6, 5 becomes 6, 14 becomes 16.
  Below 5 it is raised silently, otherwise the `jmp` would not fit.
* 💾 **New:** Settings persist in `SigMaker.ini` next to the DLL.
* ⚠️ **Untested in Cheat Engine.** Builds clean and the generator was verified against
  synthetic memory, but the dialog and the emitted script have not been run against a live
  game yet. Treat it as a beta.

---

### 🏷️ v1.0.7 — Cleanup & Hardening

*No behaviour change. Generated signatures are identical to 1.0.6.*

* 🧽 **Changed:** All comments stripped from the sources (26 across four files) — the code carries itself.
* 🛡️ **Fixed:** `CEPlugin_GetVersion` null-checks its `version` pointer before writing to it.
* 🧩 **Fixed:** `find_module_info` keeps its first module list when the retry pass fails, instead of giving up. Only reachable on processes with more than 1024 modules.
* 📦 **Fixed:** `<cstdint>` is included explicitly instead of arriving through `Windows.h`.

### 🏷️ v1.0.6 — Source Layout

*Housekeeping only. Generated signatures are byte-for-byte identical to 1.0.5.*

* 🧹 **Changed:** `loader.cpp` split into focused modules (`sigmaker.h`, `snapshot.cpp`, `signature.cpp`, `loader.cpp`).
* 📝 **Changed:** Comments trimmed to explain *why* (decisions) rather than *what* (code). File-local helpers are now `static`.

### 🏷️ v1.0.5 — Memory & Output

* 🎨 **Changed:** Wildcards print as `*` again in AOB output. (C++ Pattern keeps `\x00` / `?`).
* 🚀 **Changed:** Snapshot buffers are no longer zero-filled, saving memory overhead.
* 💾 **Changed:** Exact allocations in the page-wise fallback to prevent bloat.
* 📉 **Changed:** Candidate limit lowered (1,048,576 ➡️ 65,536 addresses) for better sorting times.
* 🧵 **Changed:** Thread pool is only built for scans >4 MB, drastically speeding up small scans (12ms ➡️ 4-6ms).

### 🏷️ v1.0.4 — Snapshot Scanner & Zydis 5

* ⬆️ **Changed:** Zydis updated (4.1 ➡️ 5.0.0).
* ⚡ **Changed:** One-shot module snapshot introduced.
* ⚓ **Changed:** Instruction-aligned anchors (cuts attempts from 1024 to a few dozen).
* 🔀 **Changed:** Full-module scan is now multithreaded (2 MB chunks).
* 🔍 **Changed:** `Copy Address Info` now uses CE's symbol resolver for Mono/IL2CPP.
* 🐛 **Fixed:** Uncovered/invalid addresses fail cleanly, buffer overruns on >1024 modules resolved, `STATUS_PARTIAL_COPY` reads accepted, full pattern re-verification added, and `GlobalFree` leak patched.

---

## 👏 Credits

👨‍💻 Developed by **gmax17**.
🙌 Special thanks to the **Zydis** team for their incredible disassembly library.

> ⚠️ **Disclaimer:** *This tool is intended for educational purposes and reverse engineering only.*
