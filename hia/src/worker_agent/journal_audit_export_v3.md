# One-call Worker journal audit reputation export

WQX3 takes one immutable bounded snapshot, a separate output and scratch,
and returns the same WAO1 packet as [WQX2](journal_audit_export_v2.md).
This separate in-memory ABI widens the admitted ordinary journal profile
only by the already qualified [WJD3](journal_audit_dto_reputation_v3.md)
optional signed reputation delta. The seven resulting audit display fields
use the same classifier and label bytes. Nothing else becomes an allowed
non-null optional value. There is no host parser or intermediate frame
producer and no change to the original named library or production route.

The raw limit stays 65,536 bytes with at most 64 candidates and final LF;
the typed equivalent transaction cap is still 65,536 bytes including an
8-byte header and each 4-byte row length. WAO1 is still at most 1 MiB.
Scratch still has its original 102,400-byte extent. Each raw span supplies
its bounded global origin and end to the WJD3 parser. Each 24-byte
descriptor holds task u64, the combined request/status geometry and the
tagged delta. The descriptor range is still [30768, 32304), separate
from the row and the index. Reputation never adds an index key.

Materialization measures 108 plus both decoded string lengths plus the
exact label length (at most 23). It tests 65,524 before any row write:
even one row beyond this size cannot fit the existing typed header/length
budget. An oversize return takes the old aggregate capacity path before
publishing output. The staged row begins at 32,768 and its end is
therefore at most 98,292, inside the old staged row range. This preserves
the original index/scratch reuse boundaries. The WJD3 emitter's fixed
mask, numeric and label-size lanes are shifted by the row offset; its
label payload is already absolute. Measurement and publication both
obtain mask 0 or 0x7f00 from the same materialization helper and pass it
to both original formatters. Whole refusal preserves every output byte.

The 64 KiB test reaches the raw cap, not the typed cap. A minimum
physically present ordinary line costs at least 138 bytes including LF,
but its typed overhead is 112 bytes. When a recognized delta is present,
the maximum label still leaves a margin of at least 25 bytes per row
between raw overhead and typed overhead, apart from the one 8-byte
typed header. Decoded string bytes never exceed their raw spelling.
The unreachable typed-bound edge in this admitted raw profile is checked
structurally in Core; a raw fixture is not presented as its execution.

## Reproducible source and observed parity

The fixed generated prefix takes two unchanged functions from WQX2, three
small adapters from WQX1, and two offset-adjusted WJD3 helpers. All other
shared checked functions are imported from their actual owners; the two
new bodies implement the measure handoff and bounded staging. Exact
projection and full shared Core graph checks run without modifying the
standard composer. The resulting graph has 86 functions and 2,797 ops.

```sh
python3 -B -m hia.tests.test_worker_journal_audit_export_v3 --print-projection
python3 -B -m unittest -v hia.tests.test_worker_journal_audit_export_v3
python3 -B -m hia.tests.test_worker_journal_audit_export_v3 --output /private/new-proof \
  --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

Both pinned backends receive the same entire raw synthetic journal in one
call. The independently run original Rust CLI supplies all three byte
oracles. Coverage includes all signed mappings, mixed selected/excluded
rows, an exact 65,536-byte snapshot with a 23-byte label, old ordinary
inputs, and late typed refusals. This is not generic Serde, a credential
or fingerprint feature, filesystem ownership, or a production cutover.
