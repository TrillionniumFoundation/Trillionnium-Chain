# Worker task-id query on a held typed audit snapshot

`audit_task_query.hepta` implements the bounded typed task-ID branch of
the active `trnm-worker-agent query-audit` in
[`audit.rs`](../../../trillionnium/crates/trnm-worker-agent/src/audit.rs).
It consumes the canonical shape produced by the original exporter, not
a generally accepted Rust/Serde sidecar. It does not parse JSON or access
paths, disk, identity, credentials, fingerprint policy, or networks.

## Private WTQ1 request and WTO1 result

The complete immutable input is at most 65,536 bytes, in this order:

1. One [WIX1](audit_index_wire.md) index frame of 40–29,736 bytes,
   preserving all eight original typed maps and their order. Its
   `total_records` must be identical to the row count below.
2. ASCII `WTQ1`, the little-endian `u64` task ID, and a little-endian
   `u32` count of 0–64 already-selected rows in export order. Each row
   occupies a little-endian `u32` length followed by precisely that
   many [WJL1](audit_jsonl_row.md) bytes.
3. A final little-endian `u32` WIX1 prefix length. This lets the
   existing WIX1 validator run against the exact logical extent of the
   original borrowed input; no copy or alteration of that validator is
   needed. No extra bytes are allowed.

The index format represents version 1 only. WTQ1 uses WIX1's full
read-only validation of all eight maps, including UTF-8 keys, strict
key and ordinal ordering, row count, and every offset range. Every
WJL1 row is measured with the original native row encoder and must
satisfy the already selected export status predicate. For the first
index map only, keys must also be canonical unsigned decimal with
overflow rejected. Every stored offset must point to a row with that
task ID, and every row must be represented exactly once. This is
stricter than the general Rust index validator, which only checks
version, count, and offset ranges; non-task maps are checked
structurally, not assigned authority or interpreted as query keys.

The successful output is ASCII `WTO1` and a little-endian `u32` hit
count. For each hit in original stored order it contains a little-endian
`u32` zero-based export ordinal, a little-endian `u32` row length, and
the complete compact original JSONL record including LF. No hit
succeeds with just the eight-byte header. Only after validation and
measurement does output start; the entire unused tail is preserved.
Invalid input returns `0xffffffff` and an undersized workspace or
output returns `0xfffffffe`, neither with output modification.
The existing 1 MiB borrowed output ceiling remains. The existing
102,400-byte scratch extent is required; at most its first 1,536
bytes store offset/mask/size tuples for the 64 rows.

## Actual original CLI comparison

The local qualifier uses the exact locked Rust Worker binary and all
six source/lock identities. It runs the actual unchanged
`export-audit` separately in JSONL and Markdown modes. It checks that
both sidecars match, then transports the full typed sidecar and all
typed rows without selecting, grouping, sorting or generating any
native expected query result. For each task it separately executes
the original `query-audit --task-id` and compares ordered hit offsets
and all 18 record fields; compact row bytes are independently compared
against the corresponding original JSONL record. Positive cases
include repeated tasks, an absent task, a full 64-row group, zero,
maximum `u64`, mixed selected/excluded statuses, empty and all-excluded
inputs. Negative controls cover a malformed final map or row, count
disagreement, wrong-task references, duplicate/missing offsets, and
the exact input/output/scratch boundaries.

Rust's pretty query stdout and its three query-only decorators
(`proof_type`, `settlement_status`, `timestamp_unix_ms`) are not emitted
by this candidate. Qualifications check those original fields
separately. File ownership/locking, generic index and record parsing,
fingerprint lookup, production dispatch, and existing ABIs retain their
previous scope.
