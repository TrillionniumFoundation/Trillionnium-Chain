# M09 TCD1 declared dependency metadata

This private byte entry observes the canonical original Rust
[`CellReleaseClosureV1`](../../../trillionnium/crates/trnm-data-availability/src/cell/closure.rs).
It accepts one immutable borrowed TCD1 record and validates its embedded TCR1
through the same, offset-aware core used by the standalone TCR1 entry. No
caller-supplied digest, parse result, roster, path lookup, or approval substitutes
for the original checks. The Rust production callers are unchanged.

The original 1 MiB/256-row/16-depth bounds apply. Success writes exactly 72
bytes (TCD1 SHA-256 ID, embedded TCR1 SHA-256 ID, LE32 file count, LE32 member
count). Both digests include their original domain and complete canonical wire.
The result says only what the descriptor declares. It cannot authenticate
publishers, verify a referenced TCM1 or payload, discover omitted dependencies,
offer storage or custody, admit a loader, release anything, select a version,
or authorize adoption. Paths are strings checked lexically, never resolved.

The decoder follows the original read order, then generation/profile/roots,
canonical path order, case-fold aliases, each row's lexical path, file/directory
alias, payload identity fields, distinct manifest IDs and dependency list.
Matching both canonical sets uses one membership pass over at most 256 entries,
after duplicate refusal; dependency traversal preserves the original ordered
root/edge visits, depth-before-state check, memoized subtree heights and
reachability order. The original trailing-byte check plus exact accepted
re-encoding means the capped input is already the canonical hash preimage.

Private ABI: `f0(readbuf, mutbuf, mutbuf) -> u32`. The output remains unchanged
on refusal. Scratch is private to each invocation, not an observation:
0..1240 is streaming SHA work, 1240..1272 the saved first digest, 1272..11512
five 8-byte wire facts per file (path start/length, role offset, dependency count,
row end), 11512..13560 visitation state/height, 13560..13944 sixteen 24-byte DFS
frames. Derived offsets follow a complete, immutable first parse before this
workspace is accessed. The private size-check status is 102; 103 is a reserved
internal hash failure. Nested errors retain their own original reason range;
both nested and outer I/O truncation are the same status as in the Rust observer.

[`test_cell_dependency_closure.py`](../../tests/test_cell_dependency_closure.py)
uses both independently pinned emitters, the complete original Rust
`closure.rs` plus `manifest.rs` and verified Cargo-locked SHA-256 graph when
`HIA_M09_SHA2_RLIB` is configured. The original's success bytes must re-encode
unchanged before comparison. The original's input-over-1-MiB check is
observed only by Rust because the generic native test ABI caps all loans at
1 MiB. The native tests separately exercise the private capacity and fixed
no-output-on-refusal contract. The standalone TCR1 limit suite remains required.
