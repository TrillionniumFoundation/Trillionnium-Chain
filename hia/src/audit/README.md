# Native AuditEvent values

`event.hepta` implements the complete value-operation scope of
`trillionnium/crates/trnm-audit-events/src/lib.rs`: `AuditEvent::new`, all six
builders (`with_actor`, `with_object_id`, `with_related_id`, `with_amount`,
`with_reason`, and `with_note`), Clone, and Eq/PartialEq. The native artifact
constructs, validates, copies, changes, and compares the complete event value.
The next operation can consume the actual bytes produced by the previous one.

An event has required `source` and `event_type` strings, optional `actor`,
`object_id`, `related_id`, `reason`, and `note` strings, and an optional `u128`
amount. A present empty string differs from an absent string. A present zero
amount differs from an absent amount. All 128 amount bits are retained.

These are descriptive values. Constructing an event does not authorize a
ledger change, validate an identity, provide a signature, commit state, publish
an event, or grant persistence authority. This component does not close event
collection, routing, storage, publication, or whole-project retirement gates.

## Foreign entry

The sole public foreign-buffer export is
`f0(input: readbuf, output: mutbuf, scratch: mutbuf) -> u32`.
The request and scratch bytes are unchanged. On success, the artifact writes
exactly the result extent and preserves any output suffix. On refusal, the
complete output remains unchanged. The caller owns the resulting serialized
value; no external-language implementation computes a native-path value.

Every request has a 32-byte header:

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 8 | `NAEB0001` |
| 8 | 8 | operation, little-endian `u64` |
| 16 | 8 | left argument byte length, little-endian `u64` |
| 24 | 8 | right argument byte length, little-endian `u64` |
| 32 | left length | complete left argument |
| following | right length | complete right argument |

The declared lengths must account for the entire input without overflow or
trailing bytes. Text arguments are UTF-8 bytes, not another envelope.

| Operation | Original operation | Left argument | Right argument | Result |
| --- | --- | --- | --- | --- |
| 0 | `new` | source string | event type string | complete event record |
| 1 | `with_actor` | event record | actor string | changed event record |
| 2 | `with_object_id` | event record | object ID string | changed event record |
| 3 | `with_related_id` | event record | related ID string | changed event record |
| 4 | `with_amount` | event record | exactly 16 little-endian amount bytes | changed event record |
| 5 | `with_reason` | event record | reason string | changed event record |
| 6 | `with_note` | event record | note string | changed event record |
| 7 | Clone | event record | empty | complete event record |
| 8 | Eq | left event record | right event record | one byte, `0` or `1` |

Each builder sets its corresponding option to Some, including when the supplied
string is empty or the amount is zero. Other fields are preserved exactly.
The original builder methods do not expose an operation that clears an option
back to None, and this ABI does not add one.

## Complete event record

Record magic is `NAER0001`. Its header is 96 bytes; all word fields are
little-endian unsigned 64-bit values.

| Offset | Field |
| --- | --- |
| 0 | 8-byte record magic |
| 8 | total record byte extent |
| 16 | optional-field presence mask |
| 24 | low 64 amount bits |
| 32 | high 64 amount bits |
| 40 | source byte length |
| 48 | event type byte length |
| 56 | actor byte length |
| 64 | object ID byte length |
| 72 | related ID byte length |
| 80 | reason byte length |
| 88 | note byte length |
| 96 onward | the seven strings concatenated in the same order |

Presence bits are actor `0`, object ID `1`, related ID `2`, amount `3`, reason
`4`, and note `5`. Other mask bits refuse. An absent optional string must have
zero length; an absent amount must have both amount words zero. Source and
event type are always present and may be empty. The total extent must equal
the header plus all seven string lengths and the actual supplied record
extent. There are no implicit terminators or padding bytes.

Every declared string must independently be valid UTF-8. A multibyte character
cannot straddle two field boundaries, even if the concatenated payload is
valid UTF-8. NUL, combining sequences, non-ASCII text, and the valid Unicode
boundary code points remain ordinary string contents. No normalization or
case folding is applied. There is no separate artificial per-string limit;
the actual supplied native buffer capacities still bound an invocation.

Eq validates both complete record operands before publishing any result,
including when their lengths or early bytes already differ. It compares all
required fields, option presence, optional string contents, and the complete
amount value. Clone produces an independent complete record in the caller's
output while preserving the input.

## Status codes

| Status | Meaning |
| --- | --- |
| 0 | Complete result published |
| 1 | Malformed request, unknown operation, invalid argument extents, or wrong fixed argument size |
| 2 | Malformed event record, presence mask, amount representation, or record/string extent |
| 3 | Invalid UTF-8 in an argument or declared record field |
| 4 | Insufficient output capacity for the complete result |

These refusal codes belong to this native byte ABI. Original Rust accepts typed
Rust strings and AuditEvent values and therefore has no corresponding malformed-byte
input path. Refusal tests qualify the native boundary separately from original
typed-value differential tests.

## Qualification boundary

`hia/tests/test_audit_event.py` contains the fixed 1849-case constructor,
builder, Clone, and Eq corpus. The original corpus constructors remain
unchanged after recovery. Native-only controls additionally cover returned
values used as subsequent inputs, absent versus present-empty values, exact
output capacities and sentinels, long strings, all amount bits, malformed
records, and UTF-8 failures.

Five additional native groups contain 498 calls: 112 field-boundary UTF-8
controls, 40 comparisons with malformed left or right operands, 18 overflowing
outer-word controls, 256 comparisons that change individual amount bits in
both directions, and 72 builder replacement/capacity controls. These include
empty replacements, growth to 4097 bytes, and preservation of every following
field. They do not alter the original-Rust corpus or manufacture Rust results.

`hia/tests/rust_audit_event_reference.rs` is a byte adapter linked against the
unchanged original `trnm-audit-events` crate. Qualification compiles that crate,
runs its original unit tests, then invokes its actual methods on the public
corpus. Python constructs requests and independent expected values; the native
worker executes only the emitted machine artifact, without compiler modules
or a Python value implementation loaded into it.

Recovery created a new HIA source version and a rebuilt set of boundary tests.
It requires fresh source-bound native qualification. Earlier artifact hashes
or successful runs do not certify this source version. Development reports and
actual original-Rust observations are evidence for their exact inputs; direct
comparison on the final committed source remains a required CI gate.
