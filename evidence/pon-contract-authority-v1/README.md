# Responsibility/applicability correction and fresh controlled cost evidence

Measured implementation: `dbb1c989342639c4c04366a0d12bc3ecb4760e04`.
Measured tree: `a38495fe234c4ae71aeae3c570d5d91acf847fee`.

This package records the five documentation corrections, their executable source/evidence
checks and a new run of the existing native cost example. It does not implement or qualify
a complete native node, arbitrary VM, independent model-evaluation system or public chain.
No historical v1/v3/v4/E3 artifact, consensus/runtime byte or genesis parameter was changed.
The publication commit adds this package and read-only CI/bootstrap integration; it does
not relabel that publication commit as another full native test or cost measurement.

## Executed qualification, including the failed first environment

The [original command matrix](qualification/report.json) and every raw log are unchanged.
Its `all_commands_passed` remains false: the first native run inherited a group-writable
0775 test TMPDIR and the unchanged journal ancestry guard correctly rejected it. Do not
count the first native job as passed. [The correction](setup/fixture-permission-correction.json)
changes ONLY this delivery's owned temporary directory to0700. No product assertion,
security check, lease deadline or filesystem durability assumption was weakened.

[The same-source supplement](supplement/report.json) reruns the COMPLETE native baseline,
including all-target/all-feature tests, documentation tests, Clippy and formatting. Actual
results: 1801 native tests passed, 0 failed;
15 documentation tests passed, 0 failed. The default-ignored
fixture helper was run separately by the original matrix; it is not production acceptance.
Nested child-process summaries are not counted again as top-level tests.

Repository-truth, protocol-contract, fuzz-smoke and external-evidence-contract all passed
in the original matrix. The new responsibility suite executed34 tests and the cost/receipt
suite31; these are observations, not required future test-count thresholds. The protocol
lane executes native work/command vectors, real reference reorg/expiry/replay behavior,
strict signatures, frozen evaluation, receipts and complete accepted blocks. Existing E3
semantics are recomputed by its checker; this is not a new independent learning experiment.

The public Python-package download stalled. The setup log is retained. The private venv
was completed by copying the host's existing numpy1.26.4/cryptography41.0.7 and compiled
cffi backend; the initial missing-backend preparation error is described in the recovery
record. System packages and another project's environment were not changed. Rust builds
used locked offline public dependencies and copied private Cargo caches; temporary data
was on the actual ext4-backed filesystem, not a claimed physical power-loss campaign.

## Fresh same-target native costs

[Raw samples](work-cost/native-work.json), [exact commands/source/binary](work-cost/execution.json)
and [derived summary](work-cost/summary.json) are distinct artifacts. The native example
was built and actually executed on the clean measured implementation. Each class has8
samples, with target `0x7fff...ffff` and assumed uniform-ticket p=1/2. Timing is measured
elapsed duration; no fastest-adversary lower bound or public admission rate is inferred.

| Input class | Samples | Winning honest work | Valid verification | Forged-ticket construction | Invalid rejection | Rejection / forgery medians |
|---|---:|---:|---:|---:|---:|---:|
| dense | 8 | 7.985550 ms | 4.296356 ms | 9.8650 us | 4.292832 ms | 435.158 |
| rank-one | 8 | 7.898588 ms | 4.276303 ms | 6.9500 us | 4.302840 ms | 619.114 |
| sparse | 8 | 10.402475 ms | 3.780529 ms | 7.3755 us | 3.837380 ms | 520.287 |
| zero | 8 | 5.797498 ms | 4.180919 ms | 6.9325 us | 4.188241 ms | 604.146 |

The new collector rejects mixed targets, duplicate samples, malformed counters, unbound
source inventories and rehashed summary/target substitutions. It never contacts a peer.
The ratio compares class medians at the same target, not a measured WAN attack and not a
claim that a forged transcript can become an accepted block. Mining attempts, accepted
work, useful AB results and adopted model improvement remain different quantities.

Reproduce into a NEW external output path from a clean checkout with private Cargo paths:

```bash
python3 scripts/pon_work_cost_report.py --run --out /new/owned-cost-run
python3 scripts/pon_work_cost_report.py --verify evidence/pon-contract-authority-v1/work-cost
python3 scripts/ci/report_module_evidence.py --module M08 --format markdown
```

The reporter does not rerun tests. Historical artifact integrity, narrow subject bytes,
complete recorded runtime and observed selectors are separate results. Empty ordinary
product entrypoints, no registered execution and changed dependencies remain visible.

## Remaining scope

All independent, public-network, future-window and production flags remain false. The
existing parallel worktree's uncommitted native-session/state/precheck implementation was
left untouched and is not delivered by this package. Public work/DoS qualification, one
ordinary native consensus/storage/client path, paged authenticated state and client proof,
authorized prospective independent learning, long-lived resource obligations, target-side
effect reconciliation and physical/public-network fault acceptance remain open in the
sole development plan. Dependency alerts were not dismissed by this documentation change.

Hosted PR/head and prospective-merge status must be read from GitHub. Successful local
jobs here do not establish that queued hosted checks completed, and no protected branch
rule or approval requirement was bypassed.
