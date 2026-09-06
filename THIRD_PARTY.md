# Third-party components

SigMaker Pro links the following component into `SigMakerPlugin.dll`. Its licence is
reproduced here so the requirement is met even when only the DLL is distributed, without
the source tree.

---

## Zydis — Zyan Disassembler Library

Original author: Florian Bernd. Distributed under the MIT licence. Zydis itself is not
tracked in this repository — see [CONTRIBUTING.md](CONTRIBUTING.md) for how to obtain it —
but it *is* compiled into `SigMakerPlugin.dll`, so its notice has to travel with the
binary. The full text as shipped in the amalgamated `Zydis.h` / `Zydis.c`:

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The complete header, including the copyright line, sits at the top of the amalgamated
`Zydis.h` and `Zydis.c` you supply when building.

---

## Cheat Engine plugin SDK

`sdk.h` is derived from the plugin SDK shipped with Cheat Engine. Cheat Engine itself is
not redistributed here; the plugin only builds against its interface.

---

**When publishing a release, include this file alongside the DLL** — the MIT licence
requires the notice to travel with binary distributions too.
