# Six-axis continuation: frozen-source readback, 2026-11-04

**Decision: HOLD.** Component correctness checks and finite growth observations
passed on the frozen source below. The original complete-service F0 and
three-run campaign failed. This evidence does not grant performance acceptance,
public-network readiness, production activation, or a passing result to later
runtime changes.

This is an evidence record under the existing
[performance contract](../../docs/protocol/pon-nakamoto-v1/details/PERFORMANCE_ACCEPTANCE.md)
and sole development plan, not a new plan.

## Source and provenance

| Item | Exact identity |
| --- | --- |
| Measured HEAD | `be0d5f978dc86008115524a6be85c38e03982b33` |
| Actual prospective merge | `d8c95604f6c73f0df5b8dfb23dc4061efa62f94b` |
| Base | `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0` |
| Both measured source trees | `0042b3212d0960d10e31fdbe8a92a57c50dedd90` |
| Archival reader workflow commit | `1a9e7a8a0d339a5b6124b60f3e6d9bf6e8017094` |
| Reader run / successful job | `41756337661 / 126333212375` |

The [archival reader job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41756337661/job/126333212375)
read existing artifacts, verified their complete ZIP size and SHA-256, checked
run/job/source identities, and read bounded JSON. It executed no archived code
and no native benchmark. Every emitted record retains
`source_tests_executed=false` and `acceptance_granted=false`.

[retained-throughput-readback.jsonl](retained-throughput-readback.jsonl)
normalizes the 17 JSONL records already emitted by that successful job without
changing their values. They include finalization, execution, all three campaign
attempts, all nine phases, and both archive-integrity receipts. They are the
complete **bounded readback**, not the complete ZIPs: each phase retains its
explicit omitted-field declaration, and complete receiver role splits remain
in the archived derivation. The reader artifact also contains the nine selected
JSON members. This copy does not invent missing, cancelled, or unentered spans.

| Original artifact | Bytes | Verified complete ZIP SHA-256 |
| --- | ---: | --- |
| F0 `13286673364`, run `41753071420`, job `126323929045` | 15,946,259 | `90a1834ddc7a083fc9103285c6f42f9c00d421b8c6d6206139f9db3e7f4da042` |
| Campaign `13288600275`, run `41753071468`, job `126326178742` | 59,518,668 | `06bd58d9fb7e10fea73e6f57f2e008295b6515e7be490532deea74711aa6d1be` |

The reader retained the original commands, windows, attackers, workload, profile,
confirmation policy, failures and planned denominators. It did not rerun the
campaign to obtain a different outcome. The two pre-existing diagnostic jobs
were unchanged when this archival job was added.

## Changes represented by this continuation

- [bbcb3804](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/bbcb3804576b9eb0b908eb3054bedccc189fb7ef)
  adds a checked-task negative discriminator to the bounded arithmetic-fact
  cache. A task match alone never establishes a hit: complete canonical A/B
  bytes, proof grammar/profile, current claims and target checks remain. The
  collision/alias control mutates the last A/B words, tests lookup and
  publication aliases, and preserves independent full arithmetic and bounded
  accounting. This stores no current authorization verdict.
- The same commit requires a stable network/parameters/genesis tuple across
  history cohorts at each fixed account count. Different account cohorts may
  have different identities. Two new reader methods accompany that rule.
- [be0d5f97](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/be0d5f978dc86008115524a6be85c38e03982b33)
  maintains the recent-suite exact gates after concurrent test additions:
  six History passes with three original ignored observations, and 91
  authenticated passes including five CurrentAccounts controls and 23
  post-write controls. Original invocations and budgets remain.
- [5a677aae](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/5a677aae598c4e90a08538ad39f5d183c4de12c1)
  adds the bounded archival readback. Its runtime bytes are the later c9
  runtime, while the archives it reads remain the earlier be0 measurements.
- Concurrent ordered State merging, immutable per-operation CurrentAccounts
  reuse, borrowed History response preparation, exact Submit encoding reuse,
  and bounded PQ key expansion reuse were preserved. Their finite observations
  do not establish end-to-end performance acceptance.

Subsequent `c9f4e9af` changes actual History completion deadlines and wire
admission preparation. Later `39839288` changes the independent Python storage
oracle. Neither receives be0 test/benchmark qualification by inheritance.

## Original complete-service outcome

| Original workload | Retained outcome |
| --- | --- |
| F0, six scheduled confirmation rounds | **1/6** confirmed inside the original 30-second windows |
| F0, original scheduled four-second SLO | **0/6** |
| F0, planned business-packet exposures | 42; 11 timely acknowledgements, which are not confirmations |
| F0 observed / unobserved rounds | 3 / 3 |
| Three-run campaign, nine phases | **3/27** confirmed; each run baseline 1/3, from-zero 0/3, late-product 0/3 |
| Campaign observed / unobserved rounds | 12 / 15 |
| Campaign client imports | 51 = 42 accepted + 9 deadline failures |
| All nine native phase criteria | false |

The [F0 native execution](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41753071420)
returned 101 after 76.348097047 seconds, below its unchanged 540-second outer cap.
It retained `NATIVE_F0_FAILED` and `BASELINE_MUST_PASS`. The first baseline
confirmation finished 28.097016122 seconds after its scheduled start; the next
round began 24.097030319 seconds late. Final service cleanup and all six
controller-resource boundary samples were complete. Cleanup success does not
turn the workload into a pass.

The [three original campaign executions](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41753071468)
returned 101 after 110.644588957, 110.457110726 and 110.244792280 seconds, each below
the original 600-second cap. Inputs remain 1,024 seed transfers, four seed blocks,
21 business blocks, three modes with 30 seconds each, and 0/24/24 attackers. The
state backend is authenticated-v1, profile is release, and public Host resources
are real and fixed. There were no startup, report-validation or finalization
failures that would explain away the native confirmation failure.

All nine receiver observers are complete without drops, counter overflow or
measurement failure. The nine failed client imports retain
`PUBLIC_REQUEST_DEADLINE`; their total wall time is 29.361911269 seconds. Across
all 51 import calls the retained wall total is 217.041621734 seconds and
caller-thread CPU total is 30.123065784 seconds. These are aggregate per-call
costs, not a throughput denominator or unique campaign elapsed time.

### Measured critical path

These are actual retained samples, not independently summed stage estimates:

| Client import sample | Whole import, s | Full W1, s | Admission preparation, s | Execution, s | Durable commit, s | Nested root commitment, s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Attempt 1, baseline, index 1 | 2.277189466 | 0.277232072 | 0.509318022 | 0.001536264 | 1.486379955 | 0.000594956 |
| Attempt 1, from-zero, index 1 | 5.905010883 | 0.695726540 | 1.400473379 | 0.001790577 | 3.802990255 | 0.000537710 |

The last successful baseline import at index 6 costs 8.283442065,
7.782848371 and 7.797583484 seconds across attempts 1/2/3. Its **measured
activation-call** span costs 6.001248119, 5.610801642 and 5.687383396 seconds.
The existing `SubmitResult` span wraps `activate_packet`, including its Host
checks, owner access and activation operation; it is not only the final
active-generation publication or SQLite COMMIT. Separate epoch close costs
only 0.289596, 0.306592 and 0.329706 milliseconds.

Each of those long calls records 29,928 Host checkpoints. Checkpoint time is
nested across the entire import and is not wholly assigned to activation.
Admission contains preparation/execution/commit; root commitment is nested
inside execution. **Do not add these inclusive/nested spans.**

The evidence supports prioritizing complete import, preparation, durable commit
and activation cost. It does not support treating millisecond execution/root
work or a sub-percent parsing change as sufficient to close the four-second
confirmation failure.

Direct inspection of the
[measured store source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/be0d5f978dc86008115524a6be85c38e03982b33/trillionnium/crates/trnm-pon-node/src/store.rs)
identifies remaining full-size work in the ordinary path. A straight-extension
activation scans and decodes the complete slot State after applying the delta;
the atomic pre-COMMIT guard reads that complete slot again and validates
persisted state. Before activation, `check_observed_history_with_progress`
walks the requested tip back to genesis through bounded header batches. Bounded
batches bound each allocation, not the total ancestry walk. These are
code-backed candidate contributors, not separately measured shares of the
activation span. The direct GrowthV2 curves below do not establish that this
ordinary authenticated path has eliminated those full scans. When the final
page advances more than one block beyond the old active tip, same-chain catch-up
also uses the existing multi-step reorganization path: complete slot copy,
durable intent, per-block attach transactions and readback, then final
publication. The retained import records do not expose an `active_before`
field, so no exact attach count or cost share is inferred from their cursor
alone.

## Fixed touched-set growth

[growth-readbacks.json](growth-readbacks.json) copies all four unchanged bounded
growth JSONs with their exact source and job identities. The
[growth run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41753071687)
completed successfully on x64 and ARM, both HEAD and actual merge. Every lane
contains nine cohorts, 72 measured native blocks, nine deliberate pre-commit
cancellations, nine cold opens, and the same three witness owners.

Each cohort contains eight samples. The interval below is the sorted fourth
and fifth admission sample, **not a confidence interval**. H is the warmup
history before eight measured blocks; cold open therefore retains 8/24/136 blocks.

| Accounts | Warmup H | x64 HEAD admission median interval, ms | ARM HEAD admission median interval, ms | x64 cold open, s | ARM cold open, s |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 | 0 | 9.540–10.061 | 14.521–15.186 | 0.0573 | 0.0942 |
| 64 | 16 | 16.647–17.009 | 25.756–26.573 | 0.1894 | 0.3135 |
| 64 | 128 | 17.249–17.281 | 26.756–26.832 | 1.2698 | 2.1436 |
| 1,024 | 0 | 9.721–10.675 | 15.118–15.596 | 0.1483 | 0.2738 |
| 1,024 | 16 | 17.214–17.799 | 25.826–26.791 | 0.2804 | 0.4931 |
| 1,024 | 128 | 17.856–18.474 | 27.701–27.802 | 1.3540 | 2.3535 |
| 16,384 | 0 | 9.817–10.350 | 15.698–16.333 | 1.5684 | 3.1408 |
| 16,384 | 16 | 17.088–17.738 | 26.418–27.666 | 1.7090 | 3.3579 |
| 16,384 | 128 | 18.641–18.714 | 29.401–29.410 | 2.7893 | 5.2400 |

A separate successor query records 16/30/37 point reads and 917/1,841/2,303
witness bytes at A=64/1,024/16,384, consistently across H and lanes. These are
**not total admission reads**. Copied nodes range 13–16, 23–30 and 27–37, so
fixed witness owners do not imply identical write work at different H.

These are direct GrowthV2 native Node observations with one worker, not ordinary
public TCP or client confirmation. Deliberate cancellation checks verify
unchanged SQL rows, active generation and nonce; cancellation itself and its
full-row comparison are outside admission timing. Cold-open timing is
`Node::open`, excluding the later independent journal/reference comparison.

The reader command succeeded. The exact test source registers 25 unittest
methods; its artifact-only `Ran 25 tests` line was not independently read.
Each lane ran 49 retained singleton native controls plus the growth selector:
50 invocations, not the full workspace suite. Full workspace/all-target/
all-feature compilation was retained. All p99 values remain null, and
throughput/public-network/activation qualification flags remain false.

## Actual correctness and component observations

| be0 validation | Observed scope and result |
| --- | --- |
| [W1 run 41753071470](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41753071470) | Four false-trace lanes succeed; complete pon_work 119/0/0, including all 21 arithmetic controls and the new alias test; strict primitive Clippy succeeds |
| [Recent run 41753071650](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41753071650) | All four lanes succeed; History 6 passed / 3 ignored, authenticated 91 passed / 0 ignored, original recovery/pipeline/public TCP controls and strict lint retained |
| [Branch run 41753071457](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41753071457) | All four exact-source lanes succeed, with original protocol/primitive/migration/CPU/public-service controls and strict lint |
| [Large-state CPU run 41753071734](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41753071734) | Four original singleton selectors in each of four lanes: 16 executions, not a full-workspace test pass |
| [PQ run 41753071537](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41753071537) | All four x64/ARM HEAD/actual-merge jobs complete successfully: each full Node suite 968 passed / 0 failed / 25 ignored; strict all-feature Clippy and both complete-cost observers pass |
| [Priority run 41753071579](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41753071579) | Original release from-zero service step fails in all four service-model lanes; subsequent independent registered controls pass. A control pass does not override that service failure |

The priority run's separate 4,105-block History and full-capacity state lanes
were still executing at the 02:10 UTC observation; no completion is inferred.

CurrentAccounts paired release observations use six samples per arm. The
per-operation parser reuse reduces parser calls from two to one and scans
from 2N to N, while keeping checkpoints unchanged. Median complete
`verify_state_with_cache` differences across lanes are only about 0.168–0.944%.
This is not a statistically qualified speedup and excludes Node opening,
admission, networking, contention, client confirmation and RSS.

The be0 x64 HEAD PQ component observation includes both helpful and adverse
cases: with 512 samples, warm one-key authentication is approximately
9.564 to 1.435 ms; eight warm keys and invalid-signature rejection show similar
component savings. Sixteen-key churn is approximately **9.554 to 9.591 ms** with
zero cache hits. Eight keys remain retained, every signature/message is still
verified, and unexpected results and unknown CPU are zero. This is a finite
debug-profile component observation, not PQ aggregation or complete-service
qualification.

## Later-source gate maintenance and open boundaries

The evidence commit also repairs only the W1 workflow's exact History summary:
25 passed / 1 ignored becomes **27 passed / 1 ignored** because c9 added two
ordinary deadline controls. It requires each new full selector to pass once in
the same original log. Original cargo commands, profile, source matrix,
timeouts, ignored crash fixture and all 384 PQ source pins are unchanged.

The new controls are:

- `ingress::history_import::tests::deadline_controls::final_resource_completion_preserves_error_priority_and_original_deadline`
- `ingress::history_import::tests::deadline_controls::final_resource_expiry_keeps_committed_history_and_settled_cpu`

This repairs an obsolete expected count, not a native failure. The completed
[5a x64 HEAD factorial log](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41756337914/job/126333730796)
directly records 27 passed / 0 failed / 1 ignored in 23.05 seconds, with both
new exact deadline names passing once. All six original native invocations
passed (6, 6, 1, 5, 27 and 11 ordinary tests). The subsequent Python reader
then failed with `history-import-tests: exact native controls did not execute`
because it still expected 25. The proposed two name assertions were checked
against that actual log. New-source native execution remains separate from
be0 benchmark evidence; the corrected workflow still needs its own run.

Concurrent commit 0b2 preserves a
[separate local execution manifest](../pon-final-resource-completion-20261104/final-source-validation.json)
for source `39839288`: 15 selected ordinary native controls pass, including both
new deadline controls and both new legacy/PQ wire-admission controls, with
before/after source guards. Its whole-registry flag remains false and its
qualification flags remain false. The readable manifest was checked; its
compressed command archive was not independently unpacked in this readback.
This is attributed local evidence, not a replacement for the still-running
hosted jobs or a transfer of be0 benchmark results. Concurrent documentation
commit 66e also retains a
[later source manifest](../pon-final-resource-completion-20261104/latest-source-validation.json)
for implementation `0b2e9839`, repeating the same 15 native passes with
before/after source guards, strict workspace lint and open qualification flags.
Its readable manifest was checked separately; its compressed archive was not
independently unpacked here.

The pre-maintenance 398 branch jobs had already completed their actual
`project-preflight.sh --audit` source step successfully before this maintenance:
jobs 126335136877, 126335137181 and 126335137245 in run 41756935828.
The implementation parent `0b2e9839` then completed the same actual audit-containing
step in ARM HEAD job 126340468411, run 41758563926, before this evidence commit.
No local preflight execution is claimed.

Parallel worker scaling, shared-sponsor/hot-key end-to-end cost, bounded batch
drain/retry/head-of-line acceptance, and complete weight-release/repair/
inference resource qualification remain distinct requirements. Existing
bounded controls were retained; this record does not close those requirements
with growth or cache measurements. Old nonce, liabilities, recovery, current
authorization checks, individual PQ verification and atomic generation
publication are not relaxed to improve a number.

No limits were raised, no planned failed/unobserved rounds were dropped, and
no production activation was performed. Draft PR #688 remains HOLD.
