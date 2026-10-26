# Cs2-ManualMap-Injector
It's up to date and working manual map injector

## Implemented PE handling

- Strict PE32+/AMD64/DLL validation and checked image bounds
- Preferred-base allocation with relocation-aware fallback
- `IMAGE_REL_BASED_DIR64` relocations
- Named and ordinal imports
- Target-relative resolution of `LoadLibraryA`, `GetProcAddress`, and
  `RtlAddFunctionTable` (no same-ASLR-base assumption)
- x64 exception/unwind registration before payload initialization
- TLS callback invocation
- `DllMain(base, DLL_PROCESS_ATTACH, nullptr)`
- Page-by-page protections, applied before payload code runs, that merge
  permissions for shared pages
- Remote phase/error reporting and bounded waits

## Limitations

- This is a user-mode mapper. It contains no kernel component, anti-cheat
  bypass, handle-access bypass, concealment, header wiping, or PEB unlinking.
- Delay-load imports and managed/.NET images are rejected.
- TLS callbacks are invoked, but Windows static-TLS slot/index bookkeeping is
  not emulated. Payloads using `__declspec(thread)` or some `thread_local`
  patterns can fail.
- The image is not inserted into the PEB loader lists, so APIs such as
  `GetModuleHandle` will not discover it normally.
- Activation contexts, CFG target registration, CET compatibility, bound-import
  metadata, and a complete unload path are not implemented.
- The mapped image is staged read/write for relocations and imports. The remote
  loader applies section-derived execute/read/write protections before any TLS
  callback or payload entry point runs; the image is not staged as RWX.
- A timeout intentionally leaves the target allocations intact because freeing
  memory under a still-running remote thread would create a use-after-free.

Keep `DllMain` small. Move complex initialization to payload-controlled worker
code, and avoid throwing exceptions across module boundaries.


If you have any questions dm to me on Discord:aloszam
