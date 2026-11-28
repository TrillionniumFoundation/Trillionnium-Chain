# Native exact raw binding owner

`raw_bindings_owner.hepta` implements the complete `RawBindings` method scope in
`trillionnium/crates/trnm-pon-node/src/store/mempool.rs`: `new`, `insert`,
`consume`, and `is_empty`. A private native arena retains all digest/body
bindings across calls. The artifact contains the storage, lookup, byte
comparison, removal, and erasure operations; no host map, replayed result table,
callback verdict, or Rust runtime implements those operations.

This component is invocation-local exact body ownership for Node M05 preview.
It does not validate signed envelopes, verify signatures, own pending nonces,
implement typed admission hooks, or replace the durable local pool. Those
surrounding migration boundaries remain open.

## Original behavior

Insertion first refuses an existing digest with `POOL_DUPLICATE_MEMBER`, then
refuses a full owner with `POOL_RECORD_LIMIT`. It never replaces an existing
body. All 32 digest bytes participate in identity; an all-zero digest and an
empty body are valid values.

Consumption of an unknown digest returns `POOL_TYPED_BINDING` without changing
other bindings. Consumption of a known digest removes that binding even when
the supplied body differs. A subsequent consume of the formerly known digest
therefore fails as unknown. The native implementation compares exact lengths
and every body byte, and physically wipes the complete removed slot on both
the matching and mismatching paths. In particular, a body longer than the
configured storage limit can still consume a known binding with a mismatch.

The original Rust borrows each inserted body. This native boundary copies the
body into its private arena so that no external allocation must outlive a
binding. It preserves the observable original method results. The `maximum`
parameter is an explicit native storage bound, not an original Rust limit.

## Entry and request

The only public foreign-buffer export is
`f0(input: readbuf, output: mutbuf, context: mutbuf) -> u32`. The private context
must remain allocated at one stable address through the entire operation
history. The test worker retains the actual allocation; it never reconstructs
an owner from snapshots between calls.

Every request starts with this 64-byte header. Integer fields are little-endian
unsigned 64-bit words.

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 8 | `NBRV0001` |
| 8 | 8 | operation |
| 16 | 8 | `a` |
| 24 | 8 | `b` |
| 32 | 32 | digest |
| 64 | remaining | body |

| Operation | Name | `a` | `b` | Digest/body |
| --- | --- | --- | --- | --- |
| 0 | NEW | record capacity | maximum stored body length | zero digest, no body |
| 1 | INSERT | exact body length | zero | complete digest and body |
| 2 | CONSUME | exact body length | zero | complete digest and body |
| 3 | IS_EMPTY | zero | zero | zero digest, no body |
| 4 | CLEAR | zero | zero | zero digest, no body |
| 5 | CLOSE | zero | zero | zero digest, no body |

NEW requires the first 128 context bytes to be zero. It clears the full owned
extent, including previously dirty slot bytes. Reinitializing a live owner
refuses. CLEAR wipes every slot and resets the count while preserving the live
configuration. CLOSE wipes the entire owned context, including its header.
After CLOSE, non-NEW operations refuse; another NEW may initialize the same
allocation. CLEAR and CLOSE correspond respectively to dropping and recreating
the original owner, and dropping it without recreation.

## Return status and reply

A zero return status produces a 40-byte reply. Bytes after offset 40 remain
unchanged. The reply consists of `NBRR0001`, the operation, an outcome, the
remaining record count, and an empty flag (`0` or `1`), each as an 8-byte field.

| Outcome | Meaning |
| --- | --- |
| 0 | Original operation succeeded, or control operation completed |
| 1 | `POOL_DUPLICATE_MEMBER` |
| 2 | `POOL_RECORD_LIMIT` |
| 3 | `POOL_TYPED_BINDING` |

These outcome codes identify the original three error strings. They do not
claim to implement Node's complete error taxonomy.

Nonzero ABI return statuses leave both output and the complete supplied
context unchanged:

| Status | Meaning |
| --- | --- |
| 1 | Malformed request, unknown operation, noncanonical fields, or body length mismatch |
| 2 | Output extent below 40 bytes |
| 3 | Context below 128 bytes, or NEW storage/stride extent cannot fit |
| 4 | Invalid lifecycle or malformed live private context shape |
| 5 | Fresh INSERT exceeds the owner's per-record body storage bound |

The complete request is validated before the output and context checks. For a
valid INSERT, original duplicate and full-owner outcomes have priority over
status 5. A status 5 refusal never consumes a capacity slot or changes a
previously stored body. Every arithmetic extent guard runs before its checked
addition or multiplication and before any mutation. Capacity zero is supported,
including `maximum = u64::MAX - 48`, because no slot extent is then accessed.

## Private physical storage

The owned extent is `128 + capacity * (48 + maximum)`. It must fit in the actual
supplied context; trailing bytes outside that extent remain untouched. All
integer fields below are little-endian `u64` values.

| Header offset | Field |
| --- | --- |
| 0 | `NBRC0001` |
| 8 | live marker `1` |
| 16 | complete owned extent |
| 24 | record capacity |
| 32 | maximum stored body length |
| 40 | slot stride `48 + maximum` |
| 48 | live record count |
| 56..127 | zero reserved bytes |

Each slot contains an explicit occupied word, a stored length word, a 32-byte
digest, then `maximum` body bytes. Unused body padding and every free slot are
zero. Empty bodies and zero digests are never used as occupancy sentinels.

Live operations validate the arena's extent, arithmetic, tags, reserved bytes,
slot occupancy, lengths, zero dead bytes, and observed count. Private contexts
are not a persisted format or a recovery protocol. These guards do not
authenticate caller-forged private bytes or promise reconstruction after memory
corruption. Only NEW constructs the supported live owner, and callers retain
exclusive ownership until CLOSE.

This implementation scans the physical arena and uses linear digest lookup.
The additional shape checks examine dead slot and body-padding bytes. Its
performance is not accepted as equivalent to Rust's `BTreeMap`; functional
qualification is not a performance or production release result.

## Qualification

`hia/tests/test_raw_bindings_owner.py` uses the unchanged test corpus recovered
from the independently stored original-Rust desktop bundle. It observes every
native output and the complete private allocation after each operation,
including output/context sentinels and erasure. Cases cover repeated histories,
all 32 digest-byte positions, all 256 body-byte positions, unknown and mismatched
consumption, duplicate/full priority, empty values, complete slot reuse, dirty
initial storage, close/reinitialize, integer overflow, and malformed private
shape. The worker executes the emitted ELF in an isolated process with no HIA
compiler modules loaded.

`hia/tests/rust_raw_bindings_reference.rs` is only a standard-library wire
adapter. Qualification inserts the exact original `RawBindings` block and the
exact original `ensure` function at its two markers, without rewriting their
source bytes. Rust itself executes the original owner methods. The Python model
is an independent test reference and is never loaded into the native worker.

The recovered HIA source is a new source version. Results obtained before the
temporary execution filesystem was lost do not qualify this version; it
requires a fresh native build and actual original-Rust comparison. Exact
source, compiler, artifact, corpus, and observed-output identities belong in
the corresponding qualification report and exact-head CI.
