# Signed reputation in the private Worker journal audit DTO

WJD3 is a separate single-line memory candidate extending
[WJD2](journal_audit_dto_ordered_fields_v2.md) by precisely one raw value:
`reputation_delta` may be absent, literal null, or a signed JSON
integer fitting i32. All other optional types remain absent or null.
The typed range includes -2,147,483,648 through 2,147,483,647.
Float/exponent, `-0`, duplicate, overflow or quoted integer inputs
are refused. The full record is typed and bounded before any output,
whether or not the export would select its status. No provenance, display
metadata, credentials, market reputation or authorization changes.

The internal parser stores a full task u64, both raw quote offsets and
decoded lengths in one u64, and one tagged delta word. Each measured
string has a raw quote byte within the 65,536-byte line and at least
two quote bytes, so each offset and decoded length fit in 16 bits.
The numeric word carries a distinct presence bit even for 0; non-null
deltas use the low u32 two's-complement bits. All fields retain the
known-literal unduplicated WJD2 key policy and original shared value
helpers.

The external borrow signature, 65,536-byte raw cap, untouched scratch,
unchanged output suffix, and invalid/insufficient status are the WJD
family's existing contract. Output is still [WJL1](audit_jsonl_row.md).
The exact established [WJR1/WJB3 audit classifier](audit_reputation_projection.md)
maps 3, -1, -2 and -3 to the seven corresponding display fields, using
the same labels and integer arithmetic. These fields occupy existing WJL
presence bits 8–14, six numeric lanes and the final text lane. Other
admitted values and absent/null emit the original empty reputation lanes.
The at-most-23-byte label is included in the exact capacity check;
nothing is written until the whole projected record fits.

```sh
python3 -B -m unittest -v hia.tests.test_worker_journal_audit_dto_reputation_v3
python3 -B -m hia.tests.test_worker_journal_audit_dto_reputation_v3 --output /private/new-proof \
  --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

An unchanged lock-bound Rust CLI generates the full JSONL, Markdown
and index files. The two machine emitters independently execute
WJF1 → WJD3 → WAT2, with a test-only coordinator passing only raw spans
and WJL byte lengths. It performs no field interpretation or artifact
construction and dispatches no transaction after any refused row.
The index has no reputation grouping keys. This qualification does
not change WJD1, WJD2, WQX1, WQX2 or the existing named library; does
not claim a single expanded raw call, generic Serde, file operations,
or production routing.
