# Tests

Standalone programs. They `#include` the `.cpp` files directly and run against a synthetic
`ModuleSnapshot`, so neither Cheat Engine nor a target process is needed.

Build one against the `Zydis.obj` the normal build already produced:

```
cl /nologo /std:c++20 /EHsc /O2 /MD /DZYDIS_STATIC_BUILD /DZYCORE_STATIC_BUILD /I.. ^
   audit_test.cpp ..\SigMakerPlugin\x64\Release\Zydis.obj /Fe:audit_test.exe ^
   /link /SUBSYSTEM:CONSOLE user32.lib gdi32.lib psapi.lib dwmapi.lib uxtheme.lib
```

The executable prints one line per check and exits non-zero if any of them fail.

## audit_test.cpp

Covers the two defects fixed in 0.0.9-beta and the invariants that were easy to break
silently while fixing them:

- a signature must reach at least as far as the bytes the script overwrites, measured from
  the injection point and not from the anchor the pattern happens to start at
- `module_unique` must say which guarantee the pattern actually carries
- a match straddling a scan chunk boundary is found exactly once, at the right address
- a pattern larger than one chunk is refused instead of underflowing the length arithmetic
- `collect_stolen` refuses to steal across `int 3` padding into the next function
