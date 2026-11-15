# R11: preserve the F0 resource counterexample and fail closed on missing group evidence

Scope: **source and Python/parser evidence only**. No Rust command, formatter,
compiler, native selector, Host service, cgroup mutation or remote action was
run for this change. Native qualification and an actual hosted F0 remain open.

## Actual old-reader counterexample

The [retained original readback](legacy-reader-counterexample.zip) contains the
exact old reader sources, synthetic fixture, invocation script, stdout/stderr
and machine-readable result. The [archive receipt](legacy-archive-receipt.json)
records full member readback. Its source was clean
`ca4fcb2564c9747a9bd81df4e67bffd1a210634a`.

The original actual `check_report` and `check_f0_placement_and_timing` functions
both returned `None` (accepted) for the same synthetic object while all
controller resource snapshots were absent and every one of 24 retained actor
RSS rows had unknown cost. The original `complete: false` and
`sum_rss_bytes: null` values were retained, not changed to zero. Neither reader
was mocked. The fixture starts with the original
`F0DenominatorControls.report` and adds internally consistent fields required
by the old readers. It is explicitly **not** a real workload, native proof,
resource observation, attack, Host or service success.

The exact 160,569-byte fixture has SHA-256
`d0494d73cd52eadc414290b01543ecb4cecbca686f4a0531f080a3f5aef04c6a`.
The 50,071-byte archive has SHA-256
`8144b42d985fab3d16c42e21fbc19dfe32961b1747a959cf0cb4296a8eaccaf8`.
The [identical regression fixture](../../scripts/ci/fixtures/fixed_root_f0_legacy_resource_counterexample.json)
is now rejected by both actual R11 readers. The original five native controls
and 61 Python controls did not cover this condition; their earlier outcomes
are not retroactively relabeled.

## Narrow source change

The new [native observation module](../../trillionnium/crates/trnm-pon-node/tests/support/multiprocess_root_phase_host_resources.rs)
adds three explicitly ordered observations per phase: before launching the
phase, after all actors are ready and before the original pressure epoch,
and after actual actor reaping and phase-process exit. It reobserves the
private controller's real boot ID, PID birth, executable, cgroup inode and
original ceiling on both sides of independent `cpu.stat`, `memory.current`
and `memory.peak` reads. All raw reads/errors remain in the report.

The readiness observation reobserves all actual 0 or 24 actor identities on
both sides of those reads. The reader joins them to the existing actual
Child-derived spawn manifest and reap results, not a declared count or
caller-supplied parent alone. Counter/clock rewind, missing or malformed
readings, inconsistent raw/parsed values and identity drift prevent total
success. Missing `memory.peak` is unknown and cannot fall back to RSS,
RUSAGE, a nominal ceiling, or a copied success boolean.

The scope is the entire original **controller cgroup and descendants**:
controller, broker, launchers and external producer processes. It excludes
the separately systemd-owned public phase. Its CPU delta brackets the whole
phase launch-to-reap interval; honest-miner preparation remains separately
reported outside that interval. Its memory peak is for the controller
service's lifetime, including earlier preparation and previous phases.
Current memory may decrease; the lifetime peak is never subtracted or
presented as per-actor RSS. Optional per-actor traffic/whole CPU and old RSS
diagnostics remain separately unqualified.

The old pressure-window sampler, null RSS observations, complete W1/M06,
public quota, paid CPU geometry, 30-second windows, four-second scheduled SLO,
6 confirmations and 42 business exposures remain. No honest receiver,
History, confirmation or sampler work moves to the controller. The new
boundary checks can consume the original outer runtime but cannot extend it.

The [strict reader](../../scripts/ci/fixed_root_f0_resources.py), both original
F0 reader entry functions and the independent finalizer recompute the resource
gate. New positive controls are synthetic parser inputs only; they do not
claim that these real kernel reads have executed on this new Rust source.

## Qualification boundary

The first static attempt passed the unchanged 11 launcher and 50 F0 controls
plus 16 new resource controls, 77 total. The final source draft adds one explicit
missing-group success-boolean regression: **78 Python controls passed**, the
unchanged 61 plus 17 resource controls. The source inventory, repository/link
checker, four changed Python ASTs, all eight workflow Bash blocks and four
embedded Python blocks also passed. These are parser/source observations;
exact committed-source readback is retained separately. The failed ad-hoc
assumption that the workflow had 11 steps is preserved; it has the unchanged
10 steps. All failed or partial artifacts are kept.

The preservation audit compares bytes against `ca4fcb`: the original main
phase file, old external phase module, RSS helper, three original control
files and three original launcher/ownership files are unchanged. The new F0
Rust changes are insertions only. All 16 existing whole-file workflow pins
still match. The original execution and preparation command bodies and all
workflow deadlines are unchanged.

The original five Rust selector names remain in order, with two additional
counter parser/rewind selectors. All seven, strict Clippy and formatting must
run under the parent-owned native slot on the final integrated source.
Source controls do not establish memory/resource availability, service SLO,
credit depletion, restart safety, independent operators, WAN or production
readiness. This fixes a source acceptance gap; real F0 remains unqualified.

## Exact committed-source static readback

The [static archive](static-controls-and-preservation.zip) and its
[full readback receipt](static-archive-receipt.json) bind the final checks to
source commit `be0437976c64ff548064e2b2136fdfd0afc532cf`, tree
`c9c6ac66cff590ea8101b57fb3d66087c2394beb`. The worktree was clean before and
after all six commands. The archive retains 56 payload members plus its
manifest, including the original failed assumptions, both draft attempts,
the exact-source audit script, final raw command logs, byte-preservation
results and the actual new-reader refusal of the identical old fixture.

The archive is 235,275 bytes with SHA-256
`bee0bb3eda6641f4cdc2d6d0eab002fba15bedfa41d5481ef1de001cbdbfb311`.
All member CRCs, sizes and SHA-256 values were read back and verified. The
78 controls and all source checks passed on that committed source. This
evidence-only follow-up does not modify the tested code or grant a native,
Host, cost, SLO or WAN qualification.
