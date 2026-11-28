# Decode a canonical Worker audit sidecar

The private WID1 entry (`audit_index_decode.hepta`) takes raw bytes from one
already-held, ordinary, original Worker audit index. It does not accept a
path, open files, access credentials, or constitute an authority record. Its
output is the existing [WIX1 typed index](audit_index_wire.md); it introduces
no wire change to WIX1, [WTQ1](audit_task_query.md), or
[WTQ2](audit_task_query_pretty.md).

## Accepted profile

- At most 65,536 input bytes and 0–64 selected records. Only the exact
  version-1 canonical pretty layout from active
  [`audit.rs`](../../../trillionnium/crates/trnm-worker-agent/src/audit.rs):
  all eight named maps in declaration order, fixed indentation and punctuation,
  unsigned canonical decimals, and no trailing bytes or LF. Other top-level
  types, versions, whitespace spellings and unknown, missing or reordered
  fields are refused. This is not Rust/Serde's general parsing language.
- Task keys are canonical quoted `u64` decimals. Status keys are the four
  active export statuses; phase keys are `active` and `terminal`. Each of
  these three maps must cover every row once; every populated map rejects
  repeated or out-of-range row ordinals. An array has at least one value and
  preserves the original strict ascending ordinal order.
- Provider and model may carry ordinary already-generated opaque ASCII
  display labels, respectively up to 64 and 128 decoded bytes. Labels
  are nonempty and without outer spaces. The only accepted key escapes
  are the canonical JSON escapes for a quote and a backslash; other
  key bytes must be printable ASCII. No normalization or ownership is derived.
  The last three policy-bearing maps, agent protocol, compliance profile and
  provenance fingerprint, are required and must be empty.
- All eight WIX1 maps undergo the unchanged shared validator, including
  per-map budgets, decoded key lexical ordering, and all array extents.
  Cross-artifact task-to-row correspondence remains with WTQ2. WID1 does
  not claim to verify other cross-map or row correspondence.

Input is immutable. A 102,400-byte caller-owned disjoint scratch buffer
is required. The WIX1 frame stages at offset zero and never exceeds
29,736 bytes; the shared original JSON map-header writer uses a separate
token window beginning at 32,768. The staged frame is checked by
`wx_index(..., emit=false)` before output capacity is tested. Then the
exact typed prefix is copied and no output tail is changed. Malformed or
out-of-profile input returns `0xffffffff`, and insufficient scratch or
output returns `0xfffffffe`; neither modifies output. The existing
borrowed output ceiling is unchanged.

## Actual original file comparison

The qualification runs unchanged, source/lock-bound Rust exports in both
formats on private synthetic inputs. The native decoder receives only the
raw original sidecar bytes; the host does not parse, build, or sort any
map. The old WIX1 serializer takes the emitted WIX1 and reproduces the
complete original sidecar byte-for-byte. Through a separate physical
native call, existing WTQ2 receives those exact WIX1 bytes and the full
typed original export rows. The genuine independent original
`query-audit --task-id` stdout is the byte oracle. This covers empty,
excluded, mixed, repeated 64-hit, and escaped provider/model display
labels with no provenance schema. Both pinned emitter paths run and
the previous WIX1, WTQ1 and WTQ2 artifact hashes are checked unchanged.

The host still transports typed rows from the original JSONL and no
native JSONL row ingestion, generic sidecar acceptance, source identity,
OS/file custody, storage lock, or production query routing is implied.
