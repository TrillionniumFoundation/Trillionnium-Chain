# Canonical raw Worker export rows to WAT1/WJL1

`audit_export_row_decode.hepta` (WER1) consumes an immutable, already
held original Worker audit **export** JSONL, not an ingress journal,
snapshot of credentials, or generally accepted Serde document. It does
not accept a pathname or perform IO. The scope is the 18 active
[`EnterpriseAuditExportRecord`](../../../trillionnium/crates/trnm-worker-agent/src/audit.rs)
fields in exactly the compact exporter declaration order.

## Accepted generated subset

- 0–64 records and at most 65,536 raw bytes. Empty input represents
  the existing eight-byte empty WAT1 frame. Otherwise each JSON
  object closes with LF. Blank lines, CRLF, alternate whitespace,
  field names/order, unknown top-level types, extra bytes, and
  truncated rows are not accepted.
- Request ID is an opaque synthetic display string, task ID is a
  canonical full unsigned 64-bit decimal, and status is exactly one
  of the four already selected export statuses. Strings use the
  original compact spelling: strict UTF-8, native quote/backslash and
  short control escapes where required, and lowercase `\u00xx` for
  other ASCII controls. Equivalent alternate escapes and Unicode
  escapes for directly printed UTF-8 are not admitted.
- Provider and model are optional opaque printable ASCII display
  labels (64/128 decoded bytes, nonempty when present and no outer
  spaces). Adapter, provider request ID, provenance schema/fingerprint,
  agent protocol and compliance profile must be literal `null` in this
  profile. No fingerprint, protocol, credentials, provider identity or
  authority is computed or returned.
- The seven audit-only reputation fields are either all null or all
  present: a bounded printable label (23 bytes), three `i32` values,
  two `u8` values, and a `u16` weight. Signed values preserve two's
  complement in the existing WJL1 slots. This is shape and presence
  validation, not new reputation calculation or policy.

## Stage and return

The result is the existing [WAT1](audit_export_transaction.md) frame,
including the little-endian count and complete length-prefixed
[WJL1](audit_jsonl_row.md) rows. The exact original `wj_key` literals
are compared in a separate scratch window starting at 65,536.
The first 65,536 scratch bytes stage the typed rows. There are 354
fixed compact JSON bytes per row before any values versus 112 fixed
typed bytes (4 length + 108 WJL1 header). Decoded strings do not grow,
so accepted staged bytes fit the existing total bound, accounting
for the 8-byte typed header. Every native write is also explicitly
bounded. Required caller-owned disjoint scratch remains 102,400 bytes.

All rows are validated before output, with no writes on malformed
(`0xffffffff`) or inadequate output/scratch (`0xfffffffe`) returns.
Success copies only the exact measured stage and leaves the output
tail untouched. Existing WJL/WAT/WID/WTQ callable profiles are separate.

## Original byte qualification

Both pinned HIA emitters receive untouched actual locked Rust compact
JSONL bytes; WID1 separately receives actual original sidecar bytes.
Old WAT1 reconstructs all three selected export artifacts from WER1's
native typed frame and compares them byte-for-byte. For query, the
host copies only the full WAT1/WIX1 byte regions and their framing into
unchanged WTQ2. Combined WTQ2 input remains capped at 65,536 bytes,
even when each earlier decoder separately accepts its own input.
Actual untouched original `query-audit --task-id` stdout is the
independent full byte oracle, including the 64th ordinal and a genuine
original control-escape witness. No host JSON row or map parsing is
used for this new native path. The former WJL1, WAT1, WID1 and WTQ2
entries are independently rebuilt on the exact predecessor registry and
again with the candidate registry, using the same compiler. All effective
Core/compiler requests and resulting artifact bytes must match. Older
WJL1/WAT1 receipts from other source revisions are retained separately.

There is no general JSON/Serde, original path handling or file custody,
security-policy lookup, production dispatch, or retirement claim.
