# Worker owned sealed stdin fixture

This offline Linux x86-64 qualification advances one boundary beyond the
memory-only Worker WQX3 library. The pinned HIA emitter packs an import-free
ELF with a fixed, hand-encoded Linux adapter (the same literal-machine
approach used by Bench) and the exact previously qualified WQX3 machine text.
There is no general syscall feature in Core and no GAS, runtime Python, Rust
shim, loader or linker in the fixture. Python transports byte inputs and
outputs only during build/qualification. The existing memory-only WQX3 and
its named library remain independent and unchanged.

The only supported launch is the private test launcher. It creates a fresh
anonymous memfd from an owned synthetic journal, applies all four immutable
seals, gives it to the child as fd 0 at offset zero, and retains the same open
file description for independent readback. The launcher supplies an anonymous
stdout pipe. The fixture does not accept a path, argv, environment settings,
inherited input descriptor numbers, or network endpoints. The test launcher
uses the sealed executable descriptor to start the fixture; it is not a
journal path. Original Rust test files and all retained captures are created
by the host qualifier under its private test directory, not by the fixture.

| ELF file offsets | Fixed adapter behavior |
|---|---|
| `0x0..0xaf` | ELF64 ET_EXEC with a single RX load and non-executable RW stack; no dynamic loader |
| `0xb0..0x170` | Require regular fd 0, all four seals, frozen stat size at most 64 KiB, and zero starting offset. Require fd 1 to be a FIFO (the launcher is what supplies an anonymous pipe). |
| `0x171..0x1a9` | Allocate anonymous RW memory: input `[0,0x10000)`, output `[0x10000,0x110000)`, scratch `[0x110000,0x129000)`. No executable mapping or file-backed mapping. |
| `0x1aa..0x20c` | Read from fd 0 in requests bounded by 8192 and remaining input-buffer space. Require positive progress within the request and the frozen extent. |
| `0x20d..0x27e` | Read one additional byte into separate stack storage and require zero (EOF). Check the fd 0 cursor equals the frozen extent without resetting it, close fd 0, and call the unmodified WQX3 entry exactly once. |
| `0x27f..0x2e3` | Reject a non-output return. Otherwise send the bounded WAO1 result to fd 1 only, with exact progress accounting. No input-refusal path sends a prefix. |
| `0x2e4..0x357` | Bound read/probe EINTR retries with a shared eight-retry counter; bound output retries separately. Distinct refusal exits and one success exit. |
| `0x358..` | Exact pinned WQX3 text at its entry, not patched or re-linked. |

The qualification retains the pinned source closures and compiler requests,
the complete ELF, a disassembly of the fixed syscall sites, genuine untouched
locked Rust export files, and actual pipe bytes. It compares JSONL, Markdown
and the Markdown sidecar from the same owned source bytes (also requiring the
original JSONL sidecar to match), with empty, mixed, and exact 64 KiB inputs.
The held descriptor confirms size, seals, unchanged bytes and the shared
kernel offset. Missing seals, nonzero offset, overflow and late typed refusal
are observed without stdout bytes. The EOF branch must pass before success;
there is no independent runtime syscall trace or observed EINTR claim.
Transport failures after a write can leave a partial pipe result; this is not
a file publication transaction.

This proves only the fixed synthetic descriptor path. Ordinary path lookup,
production filesystem custody/locking, publication, permissions, live files,
generic Serde acceptance, production dispatch and Rust retirement are not
qualified.
