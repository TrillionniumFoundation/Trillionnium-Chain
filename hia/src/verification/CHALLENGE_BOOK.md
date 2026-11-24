# Bounded immutable challenge book values

The HIA entry implements local value behavior of the
[original Rust `ChallengeBookV1::open` and `get_mut`](../../../trillionnium/crates/trnm-verification-profiles/src/lib.rs).
An opening inserts one new record and returns it with the updated
snapshot. Lookup returns the exact selected record with the snapshot
unchanged. Applying an action composes lookup with the actual
[per-record transition owner](CHALLENGE_RECORD.md) in one call over the
selected row. It publishes only the resulting immutable book and member
values, not a borrowed mutable pointer. There is no
live registry, actor authentication, external action, persistence,
production admission, or financial or reorganization authority.

The roster has up to **32** one-per-result records in ascending
lexicographic order of their raw 32-byte result keys, matching Rust's
`BTreeMap<[u8; 32], _>` byte ordering. Reusing a challenge ID for
different result IDs is allowed. Duplicate result IDs refuse before any
typed identifier/deadline checks on the new opening, as in Rust.
Lookup miss does not insert or change anything. The 32-entry bound only
applies to the private snapshot representation; the Rust map is not
limited to 32.

An existing row must have nonzero identifiers, bounded tags, literal
false authority fields, and the exact original record digest recomputed
in HIA from all original hash fields. A digest is not a signature or
proof of origin, historical reachability, authenticity, or custody.
This additional byte-level admission is for the private representation,
before treating it as an existing typed Rust book. The native code
shares the original record-domain hashing core at checked row offsets.

## Local fixture layout

Input begins with a 197-byte `VCX1` request, followed by `VCB1`,
a one-byte book operation (0 opening, 1 lookup, or 2 apply action),
one-byte row count, two zero reserved bytes, then exactly that many
173-byte records. Opening and lookup retain their operation-0 leading
record request with a 37-byte zero tail. Lookup uses only the result ID
at offset 56; other request values are irrelevant after framing checks.

Apply action uses a `VCX1` method (1–8), matching choice, height and
argument fields, and only the result ID at offset 56. All other bytes
in the 173-byte leading record region are zero. State always comes
from the exact selected snapshot row, never from a second member value
supplied by the caller. On success only that row changes; all other
bytes and the number and order of members are unchanged.

Successful output contains the row count, selected zero-based row
index, six zero bytes, the full sorted snapshot, then a copy of the
selected 173-byte record. No bytes after the declared output change.
Scratch is bounded to 1,472 bytes. Refusals publish no output or
changes to the input. Snapshot verification can use scratch before
rejecting a bad request or a missing result.

- 20 duplicate result and 21 missing result correspond to original outcomes.
- 1 zero identifier and 17 invalid phase, 18 missed deadline and 19 already
  used appeal remain original outcomes. Missing key precedes typed per-record
  transition checks, as in `get_mut` followed by the record call.
- 100 bad private frame, 101 noncanonical/unbound snapshot, 102 capacity,
  103 internal hash failure and 104 full private roster are local only.
  Capacity is checked before writing. Opening checks original typed
  fields before the local full-roster refusal.

The [differential test](../../tests/test_verification_challenge_book.py)
compiles unchanged original Rust book and record methods with pinned
rustc and a system SHA-256 seam. Its book persists for each original
test trajectory; both independently emitted HIA images carry their own
immutable prior snapshot across requests. Both native emitters now
perform the member transitions themselves and produce complete updated
snapshots for later lookup; no advanced state is imported from Rust.
Private truncation, exact capacity, untouched unselected rows, bad
ordering and corrupted row bytes are separately tested.
