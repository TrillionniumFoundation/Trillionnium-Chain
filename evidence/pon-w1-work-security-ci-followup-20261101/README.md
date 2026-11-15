# W1 first hosted observations and execution repairs — 2026-11-01

**The first hosted run fails.** This directory preserves that result, including
all six original artifact ZIP archives. It does not convert the earlier local
module captures into complete-workspace execution or claim a passing service.

Run: [41292410360](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41292410360).
PR: [675](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/675).
Head: `f2588fe1d5e02cf631334431570e3719e64109d7`.
Prospective merge: `c028445ac4388378e26751bf456dffc86618873a`, against integration
base `0e9eac5d2a8cdb0a6f0cc7920f84e290e0d5d0d0`.
These are the source identities of this run, not a later repaired candidate.

## Native component execution and cost-runner refusal

All four head/merge × x64/ARM64 jobs build the original locked dependency graph.
Each executes **98 W1 tests and 6 native fuzz semantic tests successfully** and
passes strict primitive Clippy. The workflow selects the entire current W1
module; its count check is a minimum of 98, not a claim that the guard requires
exact equality. These are component tests, not all workspace targets or a
proof of consensus security.

All four cost runners then refuse the inherited `CARGO_INCREMENTAL=0` override.
Their original manifests have `observations=[]`, no reader result, unchanged
before/after source identities, and the same explicit override error. **No native
false-trace cost campaign ran in these four jobs.** This is an invocation error,
not a measured performance failure or an omitted native success.

The follow-up calls the same runner with `env -u CARGO_INCREMENTAL`. The original
override guard, release configuration, source binding, compiler, architecture,
campaign and time limits remain. The concurrent integration base contains the
equivalent repair for its existing cost calls and is preserved as a merge parent.

The [cost artifact readback](initial-ci/cost-artifact-readback.json) records ZIP
sizes and hashes, original manifest hashes and the 98/6 counts read from each
archive's actual test logs. The complete archives are retained byte for byte:

| Source | x64 | ARM64 |
|---|---|---|
| Head | [Original ZIP](initial-ci/cost-x64-head.zip) | [Original ZIP](initial-ci/cost-arm64-head.zip) |
| Prospective merge | [Original ZIP](initial-ci/cost-x64-prospective-merge.zip) | [Original ZIP](initial-ci/cost-arm64-prospective-merge.zip) |

## Actual service failure under both traffic shapes

Both service jobs compile the original release target successfully and execute
the original repeated-packet test and the fresh-challenge successor under the
original Host, UID, CPU owner and resource limits. Host validation reports no
final Host errors. The actual business target nevertheless fails.

| Observed source / traffic | Baseline six-depth confirmation | Pressure confirmations | Last of seven honest submissions | Full `WORK:Transcript` refusals |
|---|---:|---:|---:|---:|
| Head / original | 3.395307114 s | 0 | 2.559799481 s | 194 |
| Head / fresh | 3.399360833 s | 0 | 2.753075509 s | 167 |
| Merge / original | 3.473539186 s | 0 | 2.356676925 s | 190 |
| Merge / fresh | 3.410195625 s | 0 | 2.683511116 s | 173 |

All seven honest submissions return `ok` in every pressure phase. The independent
client then fails History replay with `PUBLIC_REQUEST_DEADLINE`; accepting the
seven submissions does not establish its six-depth confirmation. The original
test exits zero while reporting `finite_target_met=false`, which the runner
correctly refuses. The fresh test saves its complete report and then exits 101
on its actual business assertion. Neither failure is waived.

The first network History response itself succeeds and carries one block; the
deadline occurs during the independent client's local import. A separate
[read-only SQLite check](initial-ci/durable-readback.json) of all four archived
pressure databases finds exactly the genesis block, so the first received
History block has not reached durable admission. The fixed Host retains
`cpu.max = 25000 100000` and zero burst: all participating threads share 0.25 CPU.
The measured scalar mutation-refusal count is zero, so this observation does
not establish exhaustion of that separate mutation-credit bucket. Per-stage
profiling is needed before attributing the replay cost to a particular guard,
matrix kernel or serialization step.

The fresh head and merge observations construct 183 and 189 unique challenges,
respectively, with no exhausted searches or reached per-worker attempt cap.
The four service observers report no dropped records or measurement failures.
This is a concrete finite Host service failure, not a public-WAN attack multiplier
or a proof about the cheapest adversary. An unchanged rejection verdict and
correct ledger invariants do not establish deadline service under pressure.

The [head archive](initial-ci/service-head.zip) and
[prospective-merge archive](initial-ci/service-prospective-merge.zip) preserve all
original reports, manifests, stdout/stderr, Host observations, actual native
binary and test databases. The [readback summary](initial-ci/service-summary.json)
is derived from those records and does not replace them. No post-window success,
extra worker allowance or different confirmation depth repairs these outcomes.

## Additional evidence-integrity repair

Independent synthetic owner review reproduced a separate flaw: modifying the
retained binary copy while leaving the executed binary unchanged could still
produce `PASS`. The actual runner now checks the retained copy against the
execution binary before and after the campaign, as well as preserving its
existing checks of the execution path. Two controls modify real temporary
receipt bytes at the two boundaries; the full runner-control suite now has
**28 passing tests**. These synthetic controls are not native cost measurements.

The generated distributed-source inventory is updated through its original
generator and selector: all 1,127 upstream entries remain, and the two new Rust
sources bring the count to 1,129. No source path or test is excluded to get a
passing inventory. The complete source retains all 346 existing PQ corpus pins
and its `HOLD_NO_GO` result; that source check is not PQ security acceptance.

Local follow-up controls and original failures are retained under `validation/`.
The initial corpus check fails because historical evidence files are absent
from the sparse local checkout. Restoring those exact Git-index blobs permits
the subsequent pinned-source check; the first failure is preserved. Full
tracked-worktree validation remains owned by the complete hosted checkout.

## Scope and next execution

`INDEX.json` hashes every retained file except itself, including the original ZIP
archives. ZIP hashes were compared with the GitHub artifact digest before copying.
The original local captures in the earlier evidence directory remain unchanged.
The repaired candidate requires its own run; this first run is never relabeled.

Work-cost hardness, fresh-identity fairness, public-WAN service, model utility,
whole-chain post-quantum security and production activation remain unaccepted.
No default verifier, work weight, ticket, cache activation, Host budget, four-second
window, sixteen-worker pressure or six-depth confirmation requirement changes.
