# Worker audit index construction from selected rows

`audit_index_group.hepta` owns the eight index maps and their complete
pretty JSON bytes in one native call. It consumes an ordered, already
selected snapshot of the [active Rust audit export
rows](../../../trillionnium/crates/trnm-worker-agent/src/audit.rs), not an
already-built index. The snapshot ordinarily comes from the Rust
conversion, whose file, metadata-policy and input-validation authority
are unchanged. This is a private, nonproduction candidate.

## WIG1 input and workspace

`f0(input: readbuf, output: mutbuf, scratch: mutbuf) -> u32` takes live,
disjoint buffers. The input stays immutable, scratch is caller-owned
and may be changed on either success or refusal. The call requires a
102,400-byte scratch prefix and never touches scratch beyond it. There is
no allocation and the existing 1 MiB direct borrowed-buffer ceiling
does not change.

- `WIG1` and a little-endian `u32` row count, at most 64.
- For each row in its final selection order, a little-endian `u64`
  task ID followed by six `u8` byte lengths: status, provider, model,
  agent protocol, compliance profile and provenance fingerprint.
- The six payloads follow the lengths in that order, with no padding or
  trailing bytes. Status is one of the four literal export statuses;
  optional length zero is absent. The five canonical optional strings
  are printable ASCII with byte ceilings 64, 128, 3, 64 and 64.
  This is shape validation, **not** protocol/compliance policy or
  fingerprint syntax or derivation. Supplying the genuine canonical
  values from export conversion is the caller's precondition. No
  credentials, request IDs, path or raw journal data are input.

For this exact export projection Rust's index normalization is already
identity on the optional strings: provider/model have been trimmed,
protocol is already `mcp` or `a2a`, compliance already uses canonical
hyphens, and the optional fingerprint is already lowercase hex. The
candidate neither reconstructs nor normalizes those fields. Rust
currently selects only `rejected`, `failed_adapter`,
`failed_submission` and `reveal_submitted`. HIA uses the existing
selected-status predicate, assigns `rejected` to `terminal`, and assigns
the other three to `active`. Out-of-projection statuses are refused,
not silently dropped. Record index is its zero-based position in this
selected batch, not its position in the original journal.

## Native grouping, bounds and atomic output

HIA converts task IDs to unsigned decimal, separates case-sensitive
keys, and repeatedly chooses the earliest lexical key still pending in
each map. The equal-key pass emits all matching zero-based positions in
ascending order, including row 63, and clears their bits. Absent fields
never create groups. Numeric-looking keys remain lexically sorted
(`10` before `2`); prefix keys are shorter-first. Work is bounded even
with a long common prefix: for N rows and eight maps, there are at most
`8 * N * (2N + 1)` row visits including the final empty scan, and each
lexical comparison reads at most 128 byte pairs.

Scratch has a 32,768-byte staging prefix plus eight maps of 64
136-byte key slots. The input bound is 22,664 bytes. The staged WIX1
frame needs at most 29,736 bytes: 40 fixed bytes, plus at most
`64 * (8 * 12 + 20 + 17 + 8 + 64 + 128 + 3 + 64 + 64)`.
Only the computed frame extent is lent read-only to the existing
[WIX1 serializer](audit_index_wire.md). The standalone WIX1 entry and
ABI are unchanged. WIG1 validates the entire input and has WIX1
measure the exact output before writing. Malformed input returns
`0xffffffff`; insufficient scratch or output returns `0xfffffffe`.
An invalid top-level header is rejected before scratch capacity is
checked. All refusals preserve the output; successful calls return the
byte count and preserve the output tail. JSON has no final newline.

## Original byte comparison

```sh
python3 -B -m unittest -v hia.tests.test_worker_audit_index_group hia.tests.test_worker_audit_index_wire
python3 -B -m hia.tests.test_worker_audit_index_group --output /private/new-proof \
  --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

The observation checks the unchanged locked Rust executable and all six
source/lock identities, runs its actual `export-audit` on local benign
records, and supplies only the original `.jsonl` rows as native typed
input. A separate original CLI invocation produces the untouched
`.md.index.json` byte oracle. Neither original index contributes
keys, groups or ordering to the native input. Both machine emitters
match the entire file, including all eight nonempty maps at 64
selected rows, duplicates, absent fields, escaping, long key prefixes,
and empty and all-excluded journals. Separate cases check late invalid
rows, count 65, short scratch/output, and the unchanged standalone WIX1.

This does not implement native journal ingestion or selection, provenance
policy, lookup, real export file ownership, public query or production
routing. It does not replace Rust's wider source limits or provide a
production fallback for them.
