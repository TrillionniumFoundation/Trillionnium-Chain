# Fixed native sealed streaming fixture

This uninstalled Linux x86-64 fixture emits a pinned static ELF using an
HIA packer. It is distinct from the earlier 64 KiB whole-frame adapter and
the private Rust streaming transport test; those bytes and caps are
unchanged. No executable locator, path, descriptor selector, argv,
environment, filesystem store, network, clocks, or production authority
is provided. The test parent creates a fresh sealed anonymous fd 0 and
anonymous fd 1 pipe. The executable is started from a separate sealed
executable memfd by the test launcher.

The HIA emitter packs reviewed fixed Linux x86-64 instruction constants
and appends the import-free pinned stock Selfhost windowed code without
relocating or modifying it. No assembler, linker, interpreter, Rust,
Python, C shim, or dynamic loader is used by the resulting executable.
Python runs the pinned build, disassembly checks and test fixture only.

The adapter checks a regular fd 0, all four seals, zero cursor, a FIFO
fd 1, and at most 4,259,840 total bytes. The immutable input is exactly
the original 20-byte request prefix, its declared TCM1 manifest (combined
prefix/manifest at most 65,536 bytes) and at most one 4,194,304-byte
synthetic row. All declared extents are checked before use. The adapter
maps a 208,896-byte anonymous RW arena with unchanged permissions:

| Relative range | Use |
|---|---|
| 0–65,543 | Eight-byte private tag and window up to 65,536 bytes |
| 69,632–135,183 | Stock bounded output loan, 65,552 bytes |
| 139,264–208,895 | Stock private workspace, 69,632 bytes |

Private HIA calls bind the manifest once, then receive each read window
in order. Progress must stay positive and inside the declared request;
interrupted reads and writes have separate eight-retry budgets. Read
requests are always at most 65,536 bytes. The adapter verifies actual
EOF with the fixed one-byte probe, then exact original device, inode,
extent, seals and shared cursor. It requires close success before calling
the HIA finish step. Only after finish accepts, and the returned count
is bounded, does it write the original header and selected bytes to
fd 1. Semantic failure gives no stdout. This fixed transport admits
a logical zero-size request or an at/after-EOF cursor only when no row
bytes trail the manifest. Unlike that transport restriction, the
original logical no-read operation would simply ignore a supplied row.
Trailing bytes on the synthetic zero/EOF controls therefore produce a
transport refusal, not a claim of original result equivalence.

Other than the static budget and ordering readback, this fixture does
not inject interrupted syscalls or close failures. It does not claim
atomic pipe delivery: a sink failure after a write can leave a prefix.

Independent disassembly binds the 13 fixed syscall sites and seven
closed calls, including the checked close before finish and output. The
test parent validates the same retained fd identity, extent, seals and
cursor with nonposition-changing readback; the exact bytes it observes
go to the locked original Rust held-reader oracle. The previous Rust
carrier is a separate physical comparator. This only qualifies the fixed
synthetic test on stock Selfhost for Linux x86-64. No general syscall ABI,
OS owner, real cache, model custody, ARM, production bridge or retirement
is claimed. The existing memory module has its separate dual-backend
qualification.
