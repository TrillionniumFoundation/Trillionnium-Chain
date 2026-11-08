# Exact int257 comparison on an owned Colab T4

Result: **arithmetic comparison completed; research HOLD**. The existing
`pon-routed-int257-grouped-research-v0` model and the first 16 retained consumer
inputs were replayed on an actual Tesla T4 through HeptaRuntime → ROG → the
installed Colab adapter. This is not a registered lottery, a new model adoption,
a demand receipt, a minimum-work bound, or permission to award chainwork.

## Evidence and source identity

- [Machine summary](summary.json) and [complete unedited result](result.json).
- [Frozen payload](payload.json): model `d6ac3f24a43045dda6af862344918688b5fbb047599d423e27c567cf670ccfc2`,
  source `9fedf7ecbbe07177069c030592b4e03dcffebb81`, evaluation bundle
  `485d1ddac3f10b859599297ede15c5703517952d3f507cdc3efea7f14214429e`.
  The existing source producer reproduced the whole consumer partition before
  the same `[0:16]` prefix was frozen. These are historical public-source tasks,
  not newly authenticated demand.
- [Final harness](../../../formal/pon-nakamoto-v1/experiments/grouped_gpu_legal_v0.py)
  SHA-256 `83c0e3162b8cdfe4936a6316560c9ea749af76b03c83fc5866c55e63ad81afdd`.
- [Executed standalone bytes](submitted-workload02.py) SHA-256
  `c00765a255c021cb2e59b9670736acbcbcfcd36aa4773ef5befc60921de6fdc4`;
  [successor freeze](frozen-request02.json) retains its predecessor and cause.
- Result: 256,484 bytes, SHA-256
  `b037da2e62f9d758beaeb977a710fcc01bdb93e761ac693658b45b993f4d8b37`.
  The cloud manifest, adapter-retained download, four version-bound chunks,
  local complete length and SHA-256 all agree.
- [Cloud lifecycle](cloud-lifecycle.json), [download chunks](download-chunks.ndjson),
  [verified stdout](successor.stdout.txt), [verified stderr](successor.stderr.txt).
  Public lifecycle copies replace the account email with the fixed account
  alias; original durable Hepta process logs remain on ROG. Credentials and
  session proxy tokens are not included.

## What was executed

The retained model has three classes, three experts and 257 features including
fixed bias 8. Every path computes the actual router, lowest-index argmax,
selected expert, complete logits and predictions. The grouped path performs
stable gather and scatters to the original input order. Direct selected paths
are lawful alternate producers for the same product and need not perform
unnecessary packed-group copies.

CPU controls use cached merged weights with NumPy signed int64 and FP64.
CUDA uses binary64 for direct original base plus selected delta, cached direct
selected weights, and cached grouped weights. Every observed product is compared
in full against independently summed original-coefficient Python integer
arithmetic, also cross-checked against the pre-existing reference in the payload.
The GPU did not receive a weaker floating tolerance: admitted integer operands,
products and absolute partial-sum bounds are strictly below `2^53`. The retained
batch's merged bound is 44,748; the generic profile bound is 134,737,904. FP32 and
TF32 substitution are disabled. The artifact retains actual runtime versions,
CUDA device, driver observation, dtype and bounds.

One separate deterministic rank-one synthetic model uses the same dimensions
and same historical vectors to compare legal factor execution. Its full
`up * down == delta` relation is checked before running. It is not a claim that
the retained trained model has those factors, or that a complete LLM is faster.
A zero-model tie control checks first-index ties and stable output ordering.

## Observed performance

All 480 first-call, warmup and warm attempts, plus 12 fresh-input samples, passed
full exact-product checks. All planned warm samples were retained: 30 per arm
for the real model and 42 per arm for the factor control. Fixed rotated and
reversed schedules give every arm the same position frequency. Timing repeats
reuse the same immutable inputs and are not independent demand or ticket queries.

Retained model, batch 16; milliseconds:

| Implementation | Warm compute median | Whole verified sample median |
| --- | ---: | ---: |
| CPU cached merged int64 | 0.140261 | 0.300196 |
| CPU cached merged exact FP64 | 0.161600 | 0.352024 |
| CUDA cached direct selected FP64 | 0.411432 | 0.837090 |
| CUDA original direct selected FP64 | 0.702305 | 1.118157 |
| CUDA cached grouped FP64 | 1.437210 | 1.845617 |

For these concrete implementations and this small profile, cached direct CUDA
was approximately 2.93 times as slow as the CPU int64 control; grouped CUDA was
approximately 10.25 times as slow in the warm compute clock. This measures the
Python/NumPy/PyTorch paths with synchronization; it is not a lower bound on a
future fused CUDA kernel. It also does not imply a speed comparison for larger
model families, shapes or different profiles.

The synthetic factor control likewise did not justify suppressing a normal
cached-merged baseline: CPU factor median 0.181567 ms versus cached merged
0.152657 ms; CUDA factor 1.764826 ms versus cached direct merged 0.434927 ms.
Router, base and lawful cached preparation all belong in a fair comparison.

Warm compute excludes host-result transfer/normalization and independent
comparison; both are separately recorded and included in whole-sample timing.
Fresh-input samples include new host conversion, optional H2D, computation,
D2H, a newly computed scalar reference and comparison. First calls share one
process and the recorded setup order, so they are not separate cold boots.

## Failures, resources and cleanup

The first actual cloud attempt, `c44f27ec-d560-443d-8b75-0bb0fb5534fe`, terminated
with exit 2 after 0.120032 seconds. The deployed runner uses `runpy` and retains
its `code.py` argument, which the original workload parser rejected before
reaching its computation. Its exact [171-byte stderr](first-attempt.stderr.txt),
[receipts](first-attempt-receipts.json), [source](submitted-workload.py) and
[initial freeze](frozen-request.json) remain. It was not relabelled successful.

Only after its authoritative `failed`, stopped-process-group receipt, a distinct
successor key admitted the corrected frozen no-CLI entrypoint. The successor
`433199d9-4ee8-43c2-8140-ff440735cfbb` had one dispatch and terminated `succeeded`,
exit 0, with `cloud_execution_stopped=true` and no live process group. The same
owned T4 assignment and dedicated kernel were used; no unknown task was replaced.
Runtime deployment files were not modified.

The successful cloud child ran 17.474959 seconds. The workload's own clock
records 14.246770 seconds before its last write, including 988 atomic progress
checkpoints taking 4.839262 seconds. The checkpoint overhead surrounds hot
sample clocks and remains in total process cost. Every in-progress sample has
an explicit started record; incomplete samples must remain incomplete.

Initial real-model CPU preparation was 0.949051 ms; first H2D material transfer
50.383106 ms; GPU merge preparation 64.042100 ms. Import, CUDA initialization,
reference verification, warmup, subsequent preparation and every sample are
retained in `result.json`, not discarded from the cost record.

The task-owned runtime had one allocation, one dedicated kernel and one release.
Manager `pon-legal-gpu-10a9-20261107-01` reached `released` at
2026-11-07T11:32:16.260372Z, after verified artifact retrieval. Its observed
allocation-to-release interval was 650.278609 seconds, including setup, idle,
observation and download. The release checks refused foreign or busy kernels.

The first post-release account snapshot has empty assignments but a consumption
counter of one assignment and a rate of 1.15 units/hour. That discrepancy is
preserved separately from the released original endpoint; lag is a hypothesis,
not a proved cause. A balance of zero is not evidence of zero accrued cost.
At the later 2026-11-07T11:37:44.131097Z observation, assignments remained empty
and the consumption counter and hourly rate both became zero. Both snapshots
remain in the lifecycle and summary. A per-job billed-unit invoice was unavailable,
so complete monetary cost and GPU energy are explicitly unknown.

The local `entrypoint-probe02/` is an intentional test of the exact deployed
`runpy` invocation in an environment without PyTorch. Its retained missing-torch
diagnostic proves the CLI mismatch was removed; it is not a GPU attempt or a
successful hardware test. Local CPU correctness and admission checks have their
own receipts and are not substituted for the Colab result.
