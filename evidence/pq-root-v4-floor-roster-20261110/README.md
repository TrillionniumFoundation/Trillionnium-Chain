# PQ Root V4 ninth native test required-roster repair — HOLD

## Trigger and exact failure
The frozen #887 required-baseline protocol-contract job (link in validation.json) executed
`recovery_floor_v4_native` with exit code 0, but `run_pq_root_continuation_v4.py`
refused to recognize the 9-case Rust result: its immutable expected FLOOR tuple
still named only 8 cases after #878 added the joint rollback control.
This is **not** a protocol or deployment success.

## Change
Include the ninth test in the exact required roster (rather than reducing checks).
Require the Python runner control test to compare all Rust `#[test]` function
names with the exact expected FLOOR names; duplicate and missing cases fail.
Re-pin the two changed Python files in the cross-branch source corpus.

## Fresh local evidence / limits
`unit.stderr` is the raw four-case Python control execution on the isolated
#887 source snapshot. `diffcheck.stdout` and `diffcheck.stderr` are the
literal output of Git diff whitespace checks. The original native CI job
and artifact are preserved at the links in validation.json.
No native Rust suite was newly executed by this repair job.
No independent physical custody, external freshness, production authority,
effect, PQ migration, or quantum lifetime qualification is implied.

All five PQ Root qualification blockers remain **HOLD**.
