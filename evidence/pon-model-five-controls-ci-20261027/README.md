# Fresh five-participant CI diagnostic: completed execution, zero benefit

Exact tested source: `678c9e00b97885b1af9fa2dcf3572f65a5ac3b45`.
Actual diagnostic [run40487735989](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40487735989),
job122133657558, completed successfully. All twelve original loader, training/control
and evaluation phases executed, exited0 and resolved their owned child cleanup.
This establishes execution of this fresh cohort. The original assessment reports
**`positive_vs_all_controls=false` and gain0/1 against the strongest control**.
Every authentication, independent/prospective acceptance, public reward and public
network flag remains false. No candidate is adopted or installed.

## Original quality result

The original metric is `equal-source-group-exact-output-bytes`. Fractions below
are that small fixed diagnostic's source-group score; they do not estimate broad
model capability. The assessment and every original prediction/receipt remain in
[raw-evidence.tar.gz](raw-evidence.tar.gz).

| Participant | Calibration | Evaluation | Actual training steps |
| --- | --- | --- | --- |
| Candidate | 1/2 | 1/2 | 10 |
| Fresh budget-matched LoRA | 1/2 | 1/2 | 10 |
| Budget-matched full tune | 1/2 | 1/2 | 10 |
| Current backbone | 0/1 | 0/1 | 0 |
| Randomized rank-matched LoRA | 0/1 | 0/1 | 0 |

All three trained arms used the original10 steps,526 tokens and40 supervised
tokens. The frozen experiment is
`7f321ce80c38f8ad86e501047ff2714074041a59d6f4678f34448b317fce21f9`.
Matching that schedule does not assert equal CPU, memory, FLOPs or useful work.
The original profiler counts only its supported operators.

This fresh candidate's artifact is
`eff04d147bc2194039c906371635b356b197dd38682033910bcc50e3a6bc4d4d`.
Its reported933,544-byte parameter file has SHA256
`77a33bfc034dd8637ec71ace227d3b1f1a332380552195d9b11181f934d423ca`.
It is separate from local V2 candidate `d3b3e79e`, its incomplete controls and
[Cell004/readback](../pon-cell004-model-readback-20261027/README.md).
The original local full-tune SIGKILL(-9), unknown cause and missing receipt remain
unchanged. Successful CI full-tune execution does not rewrite that failed cohort.

## Observed costs

| Original phase | Supervisor wall seconds | Child CPU seconds | wait4 peak RSS bytes |
| --- | ---: | ---: | ---: |
| Candidate training | 32.249228548 | 36.436106 | 3,100,110,848 |
| Fresh LoRA training | 32.420580901 | 36.587609 | 3,101,200,384 |
| Full-tune training | 39.758589990 | 47.807732 | 6,141,497,344 |
| Candidate evaluation | 14.785013405 | 25.149909 | 1,153,462,272 |

The twelve phase wall measurements sum to226.827036961s; owned-child CPU sums to
310.018861s. These totals exclude dependency installation, CI setup and the
supervisor's own CPU. Linux wait4 RSS is a maximum single-process high-water with
inherited waited-descendant accounting, not simultaneous process-tree RSS. The
separate50ms direct-child samples, exit-reconciliation observations and unchanged
600s/8GiB per-role budgets are retained. The CI job remains limited to15 minutes
with a10-minute outer model step. No limit was raised to obtain this outcome.

## Artifact verification and the checkpoint limitation

The downloaded compact ZIP is260,730 bytes, SHA256
`6c24a0ac300a23ff78c8047bea00153f9d712e23f728c36603dbf293451fbfb0`,
artifact12726390813. `raw-evidence.tar.gz` is its unchanged260,285-byte inner
archive, SHA256
`8580b8817bebf32792afb175f5ff4f9e022c6eab6f95b10759e3d349c72e5761`.
All81 non-checkpoint inventory entries were independently checked for size and
SHA256 after retrieval. Source observations before and after execution match.

Checkpoint artifact12726735299 is540,891,786 bytes. Its download was explicitly
refused by the536,870,912-byte tool limit; it has **not** been locally downloaded
or verified. The inventory's reported file hashes are preserved as CI reports,
not represented as local checkpoint verification. The single full-tune checkpoint
alone is538,090,376 bytes, so splitting only by participant would still exceed
the limit. Any later retrieval must reuse the original artifact and split fixed
byte ranges; it must not silently retrain or substitute another candidate.

## Actual four-matrix runtime material controls

Parent-evidence [run40487735846](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40487735846)
completed all four jobs. The original strict runtime roster was independently
reconstructed from each complete GitHub job log and rechecked against the
unchanged exact-source validator:13 named tests, each once, no skips, one OK.

| Job | Architecture | Source | Runtime material tests |
| --- | --- | --- | --- |
| 122133656851 | arm64 | Prospective merge `3fda4916` | 13PASS |
| 122133657300 | x86_64 | Prospective merge `3fda4916` | 13PASS |
| 122133657466 | x86_64 | Head `678c9e00` | 13PASS |
| 122133657631 | arm64 | Head `678c9e00` | 13PASS |

[matrix-controls.tar.gz](matrix-controls.tar.gz) retains the full original logs,
extracted suites, validation outcomes and per-file inventory. The earlier
[CI preparation failures](../pon-model-diagnostic-env-failure-20261027/README.md)
remain unchanged. These thirteen controls validate canonical original-wheel
extraction materials. Actual pip rewrites all31 installed RECORDs; this material
schema does not certify an installed or held Torch runtime. The four small-unit
matrix jobs are not four architecture replications of the135M training experiment.

## Newer Hepta source and remaining ordinary boundary

Hepta [PR4071](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4071),
inspected at `3b308ce2ca0c5117280c2820ca034ca5e5e0287f`, already adds a distinct
public-initial V2 ordinary CognitiveRanker route. It does not turn selected
initial material into an evaluated child or supply SystemLongitudinal product
qualification. This newer source supersedes any inference that ordinary initial
entry is wholly absent from the older inspected e153 cohort.

Its actual [run40488014123](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40488014123)
passed519 scoped Rust tests, with24 skipped. Public V2 materials and the CPU wheel
environment were built. The required ordinary model test then failed before
Agentd readiness with `Codex executable path is not configured`; proposal rounds
and descendants were skipped. This is an observed original-entry fixture wiring
failure, not a failed model-quality or FinalUse judgment. A separately reviewed
Hepta source slice supplies the first-party CLI path and propagates original
settled load/forward observations; its future CI must establish its own outcome.

The present Chain evidence does not close ordinary I10, held runtime closure,
beneficial installation, three installed upgrades, independent operators or WAN
acceptance. `task_complete=false`, `merge_ready=false`.

[observations.json](observations.json) contains exact identities, all twelve cost
rows and the original no-adoption assessment. [archive.json](archive.json) records
archive hashes and verification scope. No private keys or user credentials were
created; the retained files also passed the documented limited credential-pattern
scan. A local packaging harness initially rejected ordinary tar directory entries;
its preserved failed attempt changed no experimental result. The corrected reader
skips only safe directory entries and still refuses links and unsafe paths.
