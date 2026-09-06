# Contributing

Thanks for taking a look. This is a small, focused plugin, so the bar is simple: changes
should be understandable a year from now and must not make signature generation slower or
less reliable.

## Building

Visual Studio 2022 or newer, C++20, Windows SDK.

```
msbuild SigMakerPlugin.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=x64
```

**Zydis is not in this repository and you have to supply it.** It is 17 MB of generated
code, so it is deliberately not tracked. Fetch the amalgamated distribution — the single
`Zydis.h` / `Zydis.c` pair — from [the Zydis project](https://github.com/zyantific/zydis)
and put it where the build expects it.

The project file compiles `..\..\zydis\amalgamated-dist\Zydis.c`, a path *outside* the
repository, and `#include "Zydis.h"` resolves next to the including source. The simplest
setup is to drop both files in the repository root and point the `ClCompile` entry in
`SigMakerPlugin.vcxproj` at the local `Zydis.c`; the root is then already on the include
path. Either way, `Zydis.c` must use `#include "Zydis.h"` with quotes, or the include
directory has to be added explicitly.

## Layout

| File | Responsibility |
|---|---|
| `sigmaker.h` | shared types, constants, declarations |
| `snapshot.cpp` | module lookup, memory capture, pattern scanning |
| `signature.cpp` | instruction decoding, masking, pattern building |
| `aascript.cpp` | Auto Assembler script generation and its dialog |
| `loader.cpp` | Cheat Engine plugin glue and the context menu entries |

## Style

Comments are deliberately sparse. Explain a decision the code cannot show on its own — why
scan chunks overlap, why the thread pool hangs off a size threshold — and leave everything
else to the code. File-local helpers are `static`. Identifiers and strings are English.

## Testing

There is no test project in the repository. Tests are written as standalone programs that
`#include` the `.cpp` files directly and run against synthetic memory, so no Cheat Engine
and no target process are needed:

```
cl /nologo /std:c++20 /EHsc /O2 /MD /I. your_test.cpp path\to\Zydis.obj ^
   /Fe:your_test.exe /link /SUBSYSTEM:CONSOLE user32.lib gdi32.lib psapi.lib
```

Build a `ModuleSnapshot` by hand, plant known bytes, and assert on the result. The
worthwhile properties to cover are the ones that are easy to break silently:

- a pattern must match exactly once, at the expected address
- no proper prefix of an emitted pattern may already be unique
- chunk boundaries must not produce duplicate or missing matches

If you change the scanner or the signature builder, please include a test that would have
caught the bug you fixed.

## What is hard to verify

Anything touching the Cheat Engine interface — the symbol resolver, the cheat table entry,
the dialog — cannot be tested without Cheat Engine running against a real process. Say so
in your pull request if you could not verify a change that way, rather than implying it was
tested.

## Releases

Tags follow `SigMaker-Pro-<version>`. Built DLLs live in `Releases/`. `THIRD_PARTY.md` has
to accompany the DLL wherever it is distributed on its own, because Zydis is compiled into
it and its licence requires the notice to travel with binaries.
