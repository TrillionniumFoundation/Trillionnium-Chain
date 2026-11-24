# M09 TMA1 declared tensor plan binding

This private byte entry mirrors the unchanged pure
[`CellTensorModelManifestV1::decode`](../../../trillionnium/crates/trnm-data-availability/src/cell/tensor.rs).
A single immutable raw TMA1 loan contains both original sections. The
outer entry guards the first extent, validates embedded TMR1 including
its actual TCD1 and router roster, guards the second extent, validates
embedded TMT1, and checks the exact suffix. Existing content/row/shape
helpers are reused with the section origins. The standalone TMR1 and TMT1
entries and their source bodies remain unchanged.

The declared model ID in TMT1 is compared with the freshly computed
TMR1 ID, then each declared tensor file index and declared integer
dtype/shape byte sum plus 10 are compared with that exact closure member.
Every Base or Adapter closure row must be included; other roles are
optional. This is an internal declaration relation: the Rust outer caller
supplies its own freshly computed contract ID, not a trusted external pin.
No approval flag, independently supplied digest, caller-evaluated validation,
or payload observation substitutes for either real section.

Success writes exactly 96 bytes: independently calculated domain SHA-256
IDs for TMA1, TMR1, and TMT1, in that order. No refusal writes a result.
The original 13,944-byte embedded workspace remains sufficient: the DFS
state range is reused as a member-coverage table only after its last read,
and the two nested IDs occupy no-longer-live DFS frame slots. There is no
new memory, format, or compiler limit. This does not open tensor files,
read headers, weights or payload, check owner or loader policies, grant
access, activate, select, fetch, or authorize adoption.

Original Rust methods and exact pure dependencies, with the locked SHA-256
graph, independently decode and re-encode accepted bytes. Both pinned HIA
emitters match their exact IDs and diagnostic order through an actual
1 MiB saturated canonical TMA1 input. The legacy generic native test
loan is at most 1 MiB; a valid original TMA1 record can exceed it with a
valid 1 MiB TMT1 section plus TMR1 and framing. Rust-only observations
include that accepted record and over-loan refusals. The HIA source uses the
original format maximum 2,097,717 bytes; native coverage above the old
generic loan cap remains unqualified pending a distinct reviewed route.
No generic test guard is relaxed.

## Opt-in stock ABI diagnostic

On Linux x86-64 with 4 KiB pages and the same pinned compiler and Rust
dependencies, explicitly run
`python3 -B -m hia.tests.qualify_cell_tensor_model_large` to reproduce the
source-bound diagnostic. It is not part of default discovery or a CI gate.
It accepts no caller data. The four synthetic records and both exact built
ELF images must match their fixed identities. The isolated child calls only
public `f0` with the actual loan extents, sealed input/image descriptors,
guarded read-only input, bounded private results and scratch, and fixed
process and IPC limits. It never retries through another ABI or code path.
A timeout, trap, changed input or out-of-scope image is not evidence.

The maximum constructible accepted record is 1,204,562 bytes:
TCD1 contributes 155,421 bytes (including 256 paths of 255 bytes and the
30,720 edges of 16 balanced longest-path ranks), TMR1 adds 553 bytes,
TMT1 contributes exactly 1 MiB, and TMA1 adds 12 framing bytes. The
original Rust and both stock TCD1 emitters independently accept that
maximum TCD1 record. The original TMA1 Rust decoder independently accepts
both 1,048,996 and 1,204,562 bytes and emits all three exact IDs.

For both accepted Rust records the stock Direct public wrapper returns
packed `0x0000000100000000` (`ABI_EXTENT` before Core), with untouched output.
The exact stock selfhost public wrapper returns zero and the same 96 bytes
as Rust. For the maximum record with a suffix byte and an input over the
declared 2,097,717-byte format limit, selfhost returns 93 and 90 with no
output; Direct still returns `ABI_EXTENT`. This is backend-specific
diagnostic evidence, not dual qualification above 1 MiB, a new generic
loan guarantee, or application activation.
