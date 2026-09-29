# Executed block-scoped native continuation

Measured implementation: `30b85c34d1be404dcccd9f415286bb43b00f64ea`.
Measured tree: `4ee1a9d265f09871b0f167d2a5be77ca4b9839c0`.
Preceding candidate/baseline: `209f742279044327ad8c763012b6fdda54e5e61e`.
This continues PR #202, without a second consensus engine, learning owner or deployment.
Root README remains blank. Old evidence/pon-v1 and evidence/pon-v3 are unchanged.

## Executed invariants

All18 module contracts retain claim, scope, atomic boundary, failure schedule and exact
selectors in [the invariant registry](../../config/pon/invariants-v2.json). The current
[qualification receipt](qualification/report.json) binds66 selectors to actual raw test
results. Counting headings or test classes does not establish behavior or acceptance.
The four audited capacity/initialization/revoke-entry/restart cases remain regressions.

The native M06 engine starts at most1/2/4/8 workers once per block and checks each main
signed envelope once, including on canonical state replay. Private verified envelopes
cannot be constructed from a Boolean. Shared prefix-capacity commands retain ordered
state transitions; consumer-use signatures still bind actual quota state. Tests cover
funding dependencies, error order, payload substitution and saturated deadline capacity.
All12 commands remain state/receipt/root equivalent at each worker count. No parent
mutation escapes rejection; no dependency version or consensus encoding changed.

## Clean-source qualification

Locked offline dependencies, pinned Rust, two compiler jobs and one test-harness thread
were used. Temporary files were on `/tmp` backed by ext4. This is filesystem/process
regression, not physical power-loss qualification. Results: 1,801 native tests,15 doc tests,
a separately executed ignored helper, and strict all-target/all-feature Clippy/fmt.
The18-test ledger suite also passed with the explicit native eight-worker backend.
[Commands and raw logs](qualification/report.json) bind exact sources, environment,
exits and binary hashes. Evidence mutation tests run separately when this package is
published; they are not added retrospectively to the measured runtime suite.

## Paired application cost, not public-chain TPS

The [comparison](comparison/report.json) contains216 samples: three64-transaction
workloads, four worker settings, two fixed binaries and nine samples per pair. One
warmup per binary/case is excluded. Fixed-seed randomized interleaving limits ordering
bias; full states, receipts and roots must match the same independent Python expectation.
Both executor-only and process-inclusive timings are retained. The original per-process
resource lines are consolidated without changing values in
[one table](comparison/process-resource-usage.tsv), rather than240 separate tiny files. The table below includes
full-state root construction. Regressions stay visible; no speedup threshold changes
correctness acceptance. Proof cost, inclusion, confirmation and VRAM remain unmeasured.

| Workload | Workers | Baseline median | Current median | Current / baseline |
|---|---:|---:|---:|---:|
| independent-senders-and-recipients | 1 | 40.358 ms | 40.754 ms | 1.0098 |
| independent-senders-and-recipients | 2 | 47.320 ms | 39.354 ms | 0.8317 |
| independent-senders-and-recipients | 4 | 42.559 ms | 37.586 ms | 0.8831 |
| independent-senders-and-recipients | 8 | 42.019 ms | 37.773 ms | 0.8989 |
| independent-senders-hot-recipient | 1 | 25.567 ms | 26.121 ms | 1.0217 |
| independent-senders-hot-recipient | 2 | 32.966 ms | 24.753 ms | 0.7509 |
| independent-senders-hot-recipient | 4 | 32.276 ms | 20.087 ms | 0.6223 |
| independent-senders-hot-recipient | 8 | 31.470 ms | 21.323 ms | 0.6776 |
| single-hot-sender-recipient | 1 | 24.911 ms | 25.703 ms | 1.0318 |
| single-hot-sender-recipient | 2 | 25.615 ms | 25.237 ms | 0.9852 |
| single-hot-sender-recipient | 4 | 25.444 ms | 22.630 ms | 0.8894 |
| single-hot-sender-recipient | 8 | 25.519 ms | 23.328 ms | 0.9141 |

## Current binary on three physical machines

The [host report](native-hosts/report.json) ran both exact binaries on ROG, Pocket4 and
X230:72 executions across three workloads and1/2/4/8 workers. State, receipt and root
parity all passed. Input/driver/binary hashes and platform/UTC observations are bound in
[the source manifest](native-hosts/source-manifest.json). All owned remote temporary
directories were removed. No live database, key, daemon, service or firewall was changed.
These machines share an administrator; they are not independent consensus operators.
No live-chain inclusion, WAN consensus or physical power-loss result is inferred.

## Historical campaigns and open boundaries

[The previous package](../pon-v3/README.md) remains bound to
`242906bae4f281c738c60adbd2c053d2ded1eae5`, not the current executor.
It records4,114 actual work-verified blocks, a shallow fork above4,096, controlled
three-machine delivery/recovery/reorg/disk-error tests, and three real learning attempts.
Those learning attempts correctly produced no public update and zero reward when the
strongest locked controls prevailed. They are not three improving future generations.
The current binary has not silently inherited those old performance measurements.

Historical consistency and current-runtime equality are separate checks. The previous
checker explicitly refuses to promote its old runtime to current; this package supplies
a new current-runtime receipt. Neither checker creates independent scientific truth.

Still unaccepted: work-cost hardness and public Sybil-safe proof admission; ordinary
Agentd/Hepta PoN destination with genuine export/withdrawal/resource owners; independent
evaluators/custodians; untouched future-task windows; physical power loss; long-term DA;
and sustained public-network capacity. A script cannot manufacture those authorities.
Production stays disabled. The setup cache failure is retained in [failures](failures/README.md).

## Reproduction

Use the measured implementation, build the recorded native examples and run the exact
qualification commands. Always choose NEW result paths. The paired comparison command is:

```bash
python3 formal/pon-nakamoto-v1/experiments/executor_comparison.py \
  --out /new/comparison --baseline /verified/baseline-pon-execute \
  --candidate /verified/current-pon-execute --samples 9
```

The owned-host driver is `experiments/native_host_parity.py`, with explicit host aliases.
It uses new private temporary directories and manifested public inputs only.
