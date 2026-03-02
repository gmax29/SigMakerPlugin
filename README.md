# SigMaker Pro (2026 Edition)

**SigMaker Pro** is a high-performance, precision-focused Cheat Engine plugin designed to generate update-proof code signatures (AOBs) for both x86 and x64 applications. 

Unlike traditional static signature makers, this plugin utilizes the **Zydis Disassembler Engine** and a dynamic memory scanner to ensure your patterns are as short as possible while remaining 100% unique within their memory region.

---

## 🚀 Key Features

* **Instruction-Aware Masking**: Automatically detects and masks displacements and relative offsets (like those in JMPs or CALLs) to ensure the signature survives game updates.
* **Dynamic Uniqueness Check**: Scans the current memory region in real-time to find the shortest possible unique signature.
* **Architecture Auto-Detection**: Seamlessly handles 32-bit and 64-bit processes using native Windows APIs.
* **Multi-Format Output**: Copies signatures in three different formats via the Memory Viewer context menu.
* **C++20 Powered**: Built with modern C++ standards for maximum efficiency and stability.

---

## 🛠 Installation

1.  **Download**: Grab the latest `SigMaker.dll` from the [Releases](link-to-your-release-here) section.
2.  **Move to Plugins**: Copy the DLL into your Cheat Engine `plugins` folder:
    * Example: `C:\Program Files\Cheat Engine\plugins`
3.  **Enable**: 
    * Open Cheat Engine.
    * Go to **Edit -> Settings -> Plugins**.
    * Click **"Add new"**, select your DLL, and ensure the checkbox is checked.
4.  **Usage**: In the **Memory Viewer**, right-click any instruction and select one of the "Copy" options from the menu.

---

## 📋 Available Output Formats

### 1. Copy AOB Sig
Standard Cheat Engine format with wildcards.
> `48 83 EC * E8 * * * * 48 83 C4 *`

### 2. Copy C++ Pattern
Ready-to-use array and mask for your internal/external hacks.
> `\x48\x83\xEC\x00\xE8\x00\x00\x00\x00\x48\x83\xC4\x00`
> `xxx?x????xxx?`

### 3. Copy Address Info
Helpful for documentation and static analysis.
> `Game-Win64-Shipping.exe + 0x1234AB = 0x7FF65FD0FDF8`

---

## 🏗 Build Requirements

If you want to compile the source yourself, you will need:
* **Visual Studio 2022** (or newer)
* **C++20 Standard** enabled
* **Zydis Disassembler Library** (Include & Lib)
* **Windows SDK** (for PSAPI and Memory APIs)

---

## 🛡 Credits
Developed by **gmax17**. 
Special thanks to the **Zydis** team for their incredible disassembly library.

---
*Disclaimer: This tool is intended for educational purposes and reverse engineering only.*
