# Known-field Worker journal DTO, order-independent profile

WJD2 keeps the [WJD1](journal_audit_dto.md) borrowed single-line entry
shape, limits and WJL1 output. It is a separate source and is not
used by WQX1 or the current named Worker library.

- The same nine required fields can occur in any order. The same thirteen
  optional fields can be absent independently or present once with literal
  `null`, including between required fields.
- Only the exact 22 unescaped known property names are in scope. Unknown
  properties, escaped property names and non-null optional values remain
  explicitly out of profile, even when the original Rust accepts them.
- The shared literal matcher tries at most 22 finite keys per property.
  A bounded 22-bit mask rejects all duplicates; mask `0x1ff` must be present
  before the final closing delimiter and trailing allowed whitespace.
  There can be at most 22 accepted fields per line; a final extra property
  can only fail on the literal or duplicate check. There is no key cache,
  hashing, added scratch, or optional-value materialization.
- Every required value is still validated through the original shared
  string/UTF-8 and unsigned u64/u128 helpers. The same exact request,
  task and status projection is emitted only after whole-line validation
  and exact output-capacity measurement. Every WJL1 option stays absent.
  Error codes and unchanged output/source/scratch boundaries are the same
  as WJD1.

The byte-oracle qualification sends one immutable synthetic journal to the
unchanged locked Rust CLI and both native WJF1 → WJD2 → WAT2 chains.
The coordinator passes byte spans and frames, never interpreting a field
or constructing an artifact. It does not dispatch a transaction when any
line is refused. Both real CLI modes and all three artifact byte streams
are compared. Fixtures cover rotations, reversal, every independently-null
option, the full integer and Unicode scalar ranges, and a 64-candidate
journal retaining ordinal 63. Tests also compare both duplicate cases to
original Rust refusal, and late original-valid but non-null data to native
atomic line refusal and coordinators not publishing a WAT2 transaction.

```sh
python3 -B -m unittest -v hia.tests.test_worker_journal_audit_dto_v2
python3 -B -m hia.tests.test_worker_journal_audit_dto_v2 --output /private/new-proof \
  --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

This remains a staged private DTO candidate. No generic JSON/Serde coverage,
one-call expanded raw journal path, filesystem custody, authorization, or
production routing is claimed.
