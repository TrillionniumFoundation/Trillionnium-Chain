# Bounded ordinary Worker audit DTO from a raw line

`journal_audit_dto.hepta` consumes one raw retained journal line for a
deliberately narrow profile of the active Rust `MessageIngressRecord`.
It parses and type-checks the entire admitted object before returning a
[WJL1](audit_jsonl_row.md) audit row. This candidate is not a replacement
for Rust's complete Serde decoder or metadata handling.

## WJD1 private boundary

The `f0(input: readbuf, output: mutbuf, scratch: mutbuf) -> u32` entry
uses live, disjoint buffers. Input is one raw nonblank line, without a
wire prefix or its LF delimiter, at most 65,536 bytes. Scratch is unused.
Only these fields are admitted, in the exact declaration order of the
[active Rust struct](../../../trillionnium/crates/trnm-worker-agent/src/main.rs):

| Field | Required type |
|---|---|
| request_id | JSON string |
| task_id | unsigned integer, full u64 |
| channel | JSON string |
| user_id | JSON string |
| session_id | JSON string |
| text | JSON string |
| idempotency_key | JSON string |
| status | JSON string |
| created_at_unix_ms | unsigned integer, full u128 |

The object may end there, or continue with the complete exact ordered
thirteen-field suffix, with **all** values literally `null`:
`assigned_worker`, `assigned_at_unix_ms`, `model_output`,
`provider_request_id`, `provenance_schema_version`, `llm_provenance`,
`result_hash`, `verifier_status`, `resolution_code`, `commit_tx_hash`,
`reveal_tx_hash`, `adapter_error`, `reputation_delta`. This is the
declaration-order null shape used by the struct serializer; a
partial suffix is deliberately not part of this profile.

Property names are unescaped literal spellings. Space, tab and CR are
permitted at JSON punctuation boundaries (and before/after the object);
a physical LF is not part of a retained line. Strings accept valid raw
UTF-8 and ordinary JSON escapes through shared scalar/UTF-8 functions,
including decoded surrogate pairs. Both integer fields are minimal
unsigned ASCII decimal; no leading zero, sign, fraction, or exponent
is admitted. The task value is accumulated only after an overflow
check; the timestamp is bounded against its complete u128 decimal
ceiling and immediately discarded.

Every required value is checked even if not projected. WJL1 preserves
the decoded request ID, full numeric task ID and decoded original status
verbatim; all fifteen audit options are absent. No metadata is supplied
to, or derived by, this candidate. It neither selects records nor treats
a lexical status as sufficient admission.

Input and scratch stay unchanged. The first pass validates the entire
line and measures the two projected strings. Only after exact capacity
is checked does it write WJL1, preserving the unused output tail.
`0xffffffff` is an invalid or out-of-profile line; `0xfffffffe` is
the private byte limit or inadequate output capacity. Both refusals
leave output unchanged; the original wider limits are unaffected.

## Actual original comparison

```sh
python3 -B -m unittest -v hia.tests.test_worker_journal_audit_dto
python3 -B -m hia.tests.test_worker_journal_audit_dto --output /private/new-proof \
  --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

The test binds the unchanged locked Rust executable and original active
struct to their source and lock identities, then runs Rust on private
unchanged synthetic snapshots. The native chain passes raw bytes into
[WJF1](journal_line_frame.md), passes each untouched span into WJD1,
and passes only the native WJL1 byte frames into
[WAT2](audit_export_preselection.md) with their byte lengths. The test
host does not parse a record, select a status, or compute any artifact.
All three original Rust files are separate raw byte oracles; direct and
selfhost both compare the entire result for minimal and full null-suffix
journals, mixed selection, Unicode, integer extrema, and blank/empty.

Rust separately accepts fixtures with reordered properties, an unknown
field, an escaped property name, one explicit null, or a non-null
option; both WJD1 backends return out-of-profile with output unchanged.
These are expected coverage differences, not Rust errors. There is no
fallback or claim of full Rust JSON/typed parity. Opening/locking files,
authorization, any provenance or market policy, query, and production
routing remain with existing code.
