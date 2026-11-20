# Bench report bytes

`report.hepta` renders the original ordered Bench output, complete profile,
adaptive decision fields, persistence metadata, and the two bounded replay
error messages. All production arithmetic, decimal/date formatting, line
construction, hashing-to-hex, and metadata convergence run in HIA native code.
This is a private report component. It does not parse argv, capture a clock,
open a directory, or write a file, and does not retire the original Bench.

## Private input

The fixed header is 848 bytes. Every integer/float-bit field is little-endian.

| Offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 8 | `BRPT0001` |
| 8 | 120 | 15 context u64 words, listed below |
| 128 | 136 | 17 original raw profile words, in `PROFILE.md` order |
| 264 | 408 | 51 derived profile words, in `PROFILE.md` method order |
| 672 | 80 | Ten original adaptive-decision words |
| 752 | 32 | Canonical workload SHA-256 bytes |
| 784 | 32 | Ordered group SHA-256 bytes |
| 816 | 32 | Persistence state, path byte count, basename byte count, error byte count |
| 848 | variable | UTF-8 displayed path, basename, and error, concatenated |

Context words are workload, strategy, requested tx count, requested keys,
requested read fanout, requested write interval, profile flag, persistence
flag, determinism repeats, replay match, captured epoch second, elapsed
milliseconds low word, elapsed milliseconds high word, group count, and
grouped transaction count. Workload codes 0..2 and strategy codes 0..6 have
the same order as `README.md`. Zero requested counts are normalized to one.
The elapsed pair is an unsigned 128-bit integer, without truncation.
All four flag fields are 0/1. The dominant-stage code is 0..4. Adaptive
reason codes 0..6 have the existing scheduler meaning; zero is the empty
unused decision and codes 1..6 render the original reason strings.

The derived words are supplied by the separately compiled native profile
component. The renderer does not replace that component with a host
calculation. The eventual owner must preserve this actual native data flow.
Synthetic component tests are distinct from an integrated original CLI run.

Persistence states are: 0, no persistence suffix; 1, directory creation
failure (error only); 2, successful path setup and candidate write; 3,
write failure (path and basename precede the error). A nonzero state requires
both profile and persistence flags. State 0 has no text payload; state 1 has
no path or basename; state 2 has no error. Each text segment must be valid
UTF-8. Display conversion of non-UTF-8 OS paths belongs to the future owner.
State 0 with both flags enabled is also the private pre-persistence report
used before the owner attempts directory setup.

## Output and buffers

Output starts with `BRPTOUT1`, then four u64 words: business exit code,
stdout byte count, stderr byte count, and candidate file byte count.
Those three complete streams follow in that order. Business exit 2 emits
the original bounded-repeat or replay-mismatch diagnostic and no stdout
or file bytes. Borrowed-entry return 0 means this outcome was rendered;
it is not a claim that the process itself succeeded.

For input length N, let B = 32768 + N - 848. Output must have at least
40 + 2B bytes; scratch must have at least 8192 + N + 2B bytes. The renderer
checks framing, field ranges, UTF-8, arithmetic extents, and both capacities
before changing mutable buffers. Refusal statuses are 1 framing, 2 magic,
3 fields, 4 UTF-8, and 100 capacity. Output after the returned streams and
scratch after the required capacity remain unchanged.

Scratch 0..4608 belongs to the existing finite formatter; 4608..4931 saves
the output's 323-byte temporary formatting window. This window is restored
before final publication. Each float call uses two distinct HIA borrowed
buffers. There is no aliased exclusive call. Metrics occupy 6000..6096 and
file counters 6200..6224. The input is copied at 8192; stdout staging begins
immediately after it, and file staging is another B bytes later. In-buffer
copies use one mutable capability and proved disjoint source/destination
ranges. Output publication reads these staged streams only after rendering.

All possible fixed lines and their maximal value lengths together need at
most 23,604 bytes, including the otherwise mutually exclusive optional
lines. A binary64 fixed-four field needs at most 315 bytes; u64/u128 need
20/39. Each payload segment is used at most once in either stream. Thus B
also bounds arbitrary accepted UTF-8 path/error payloads. Input-length
arithmetic is rejected before it could overflow u64.

## Arithmetic and persistence details

Estimated conflict is the original rounded binary64 ratio, clamped to one,
then subtracted from one with a single round-to-nearest-even operation.
Two integer limbs retain the exact subtraction before packing. It is not
replaced by an integer difference divided by tx count. Coverage, group
efficiency, and groups-per-thousand preserve the original operation order.

The normal output retains the original 16 base lines, 23 report context
lines, 17 raw fields, 51 derived fields, and optional ten adaptive fields.
Only the file gains `output_line_count` and `output_bytes`. Its byte count
is iterated to a fixed point. Line count counts actual LF bytes, including
LF characters inside displayed paths, as the original terminal-LF content's
`str::lines().count()` does. The write-failure diagnostic is appended to
stdout after the candidate file bytes were constructed and is excluded
from those bytes. A returned candidate is never described as an observed
successful OS write.

Literal dispatch is split into bounded HIA functions, preserving the pinned
compiler's original per-function SSA/block limits and global limits. The
first development source rejected by Core for aliased call arguments and
the next source refused by the native compiler are retained as failures;
neither is a native PASS observation.

Qualification executes the original unchanged `main` through an `include!`
adapter, with an explicitly recorded temporary `CARGO_MANIFEST_DIR` so
profile artifacts remain outside the checkout. Actual clocks are observed,
then supplied unchanged to the native renderer for byte comparison. The
original canonical Cargo CLI binary is separately retained. This does not
qualify a native argv/clock/filesystem owner, which remains OPEN.
