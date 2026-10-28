# Original e25 phase-startup refusal and scoped repair

Run [40615636719](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40615636719)
tested `e25ae09220661985ef578edae5a337caca94f832`, tree
`158add0b6740c5c395d125da77b609d1ac3cddd5`. Its original release build completed
successfully in 130.746756474 seconds. The retained 9,999,656-byte test ELF has
SHA-256 `1a630fe50e556075f7d9370c555aeb27028fa2cd80b24319a523f2d4da5845ec`
before and after execution. This is an actual build, not successful service
qualification.

All three predeclared runs failed, with elapsed times 3.167552877,
3.093457746 and 3.102579575 seconds. Each attempted all three phase launches.
All nine launchers refused `ORIGINAL_UNPRIVILEGED_CONTROLLER` before Host setup
or native phase measurements. The original condition combines repository cwd
and non-root UID; these logs do not identify which component failed. No claim
of observed root execution is made. Phase service requests, budget depletion
and fixed-Host conformance have no executed observation. Their initialization
flags are not evidence that a running service avoided depletion.

The complete original ZIP is GitHub artifact `12785445349`, 16,009,230 bytes,
SHA-256 `b5e5371a8913f52349d1afdf16ec332777831b689d8ec92d95303d4ac417b57b`.
All 167 manifest members were byte-count/SHA-256 verified; the archive has 168
members including the manifest. This directory retains the selected original
diagnostic bytes and their hashes in `readback.json`. It is not a substitute
for the complete archive, retained separately for the audit deliverable.

## Repair boundary

The Rust integration test starts the Python launcher without an explicit cwd,
while the launcher requires its canonical repository root. The candidate now
sets only that child process's cwd, derived from the canonical launcher path.
The overall native test/attacker controller cwd is not changed. Python still
requires the exact repository directory and a non-root controller; separate
error messages distinguish the two refusals. A new negative control exercises
both refusals before any provisioning command. The existing Host limits,
unit/hash checks, caller UID, exact binary, deadlines, denials and cleanup
remain required.

The first new control fixture placed output inside its mocked source directory
and correctly hit the earlier `OUTPUT_OUTSIDE_SOURCE` refusal. Its source/output
layout was corrected; no production check was relaxed. All 11 phase-host Python
controls then passed. These controls simulate input/permission conditions and
do not provision a local Host or run a native phase.

The outer campaign runner additionally retains explicit phase startup errors
before reading duration/attacker fields absent from failed startup reports.
Such a record remains failed; it never acquires an invented duration, request
count or acceptance result.

## Explicit reviewed pin transition

The separate recent-batch run `40615636663` stopped before tests because five
of its 16 literal source pins still referred to the earlier owners. The new
candidate replaces only those five reviewed literal blob IDs. The other 11
guards, exact source/merge checks, all original test selectors/counts and
budgets remain. `recent-batch-pin-transition.json` preserves every old/new
identity. This does not inherit any earlier native acceptance for the changed
detached-execution or reorganization code. New source-head and actual-merge
observations remain necessary.
