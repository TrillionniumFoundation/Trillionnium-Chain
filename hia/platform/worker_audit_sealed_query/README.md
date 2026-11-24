# Static sealed Worker audit query candidate

`sealed-worker-task-query.elf` is a named, uninstalled Linux x86-64
test fixture. The pinned HIA emitter assembles its ELF and a fixed
machine-code query adapter from HIA constants, using the same approach
as the previous sealed-stdin Worker fixture. The old adapter instruction
bytes are identical (file offsets 176–855). It reads only its fixed
fd 0 and can emit only to fd 1: the private test driver supplies a
fresh immutable memfd and an anonymous pipe. No path, argv, environment
selector, extra descriptor authority, network, file creation, shell,
dynamic interpreter, or production routing is present in the ELF.

The runtime consists of the previously reviewed read/EOF/pipe adapter,
a new syscall-free fixed query thunk, and three byte-identical pinned
selfhost kernel texts. Each object must contain only resolved `f0` at
the beginning of executable text, no unresolved imports or relocations.
Direct raw object portability is **not** qualified: the direct
WER1 object imports `abort` and `memset`, and WID1 and WTQ2 import
`abort`; the direct objects also expose extra scalar entries. This build
never relaxes the gate, uses a dynamic library, or silently falls back.

## Held WQS1 input

The complete little-endian input, including the 24-byte prefix, remains
at most 65,536 bytes:

| Bytes | Meaning |
|---:|---|
| 0–3 | ASCII `WQS1` |
| 4–7 | Raw existing WID1 sidecar length |
| 8–11 | Raw existing WER1 compact export JSONL length |
| 12–15 | Reserved, must be zero |
| 16–23 | Unsigned task ID |
| 24 onward | Original sidecar followed by original JSONL, without gaps/trailing bytes |

A checked widened sum establishes the exact two raw slice bounds before
either decode. A zero-row input may point one byte past the used raw extent
as a zero-length slice and is never dereferenced. WID1 takes the unchanged
canonical generated subset (three policy maps empty); WER1 takes the
unchanged generated 18-field scope (private benign synthetic display and
strict null authority fields). Neither input is a policy/custody record.

## Bounded memory and sequencing

The unchanged earlier adapter mmaps the same 0x129000 bytes. Relative to
this anonymous base:

| Bytes | Lifetime |
|---|---|
| `[0,65536)` | Raw WQS1 while WID1 and WER1 run; after both return, used for the bounded WTQ2 frame |
| `[65536,131072)` | WER1 WAT1 output (at most 64 KiB) until its rows have been copied |
| `[131072,160808)` | WID1 WIX1 output (at most 29,736 bytes) until copied |
| `[65536,1114112)` | Only once the typed frame is complete, WTQ2 may use the entire original 1 MiB output |
| `[1114112,1216512)` | Same 102,400-byte scratch, borrowed once by each sequential call |

The carrier calls WID1, WER1 and WTQ2 at exact linked offsets. It checks
each decoder return range and marker. Before copying, WIX1 length plus
WAT1 length plus 12 must fit the unchanged 64 KiB typed request cap.
The thunk retains the scalar task before reusing the consumed raw buffer.
It copies the native index and typed rows in disjoint regions and sets only
the existing WTQ2 envelope fields. WAT1 count bytes are transported unchanged.
No stage is live in a region when the next use can overwrite it. Invalid
input, changed task-to-row correspondence, preexisting reader refusal, or
coverage failure yields no stdout. Successful bounded bytes are exactly the
old task query pretty stdout, including the LF. This is not a pipe-transport
atomicity claim if the recipient fails after a write.

## Qualification scope

An independent disassembly binds the earlier syscall inventory unchanged,
the three direct thunk calls, and the physical and typed bound checks.
Qualification runs the unchanged locked Rust CLI on private synthetic
generated inputs; the test driver adds only length/task framing to the two
untouched raw files, seals the fixture, and compares full original query
stdout. An actual generated pair reaches precisely 65,536 physical bytes.
Synthetic exact-cap split extremes, 65,537 bytes, missing seals, a nonzero
shared offset, mismatch between otherwise generated pairs, and a private
non-pipe sink exercise no-output controls. Original seal and cursor
readbacks are retained. The combined typed cap is separately explicit
in the thunk. Accepted canonical sidecars are at least 196 bytes longer
than their WIX1 wire (236 vs 40 base bytes, and each key/offset's raw
extension is no shorter than its typed extension). Accepted WAT1 is
no longer than raw JSONL plus its 8-byte batch header. Thus typed
composition is at least 200 bytes smaller than the same valid WQS1,
including both envelopes; no valid pair is claimed to force typed overflow. No runtime EINTR or independent syscall trace is claimed.

The build itself writes a private artifact/receipt only. In an already
owned private directory, a fresh child output can be built with
`python3 -B -m hia.platform.worker_audit_sealed_query.build --output NEW`. No live paths,
credentials, authority, service, or runtime replacement is authorized.
