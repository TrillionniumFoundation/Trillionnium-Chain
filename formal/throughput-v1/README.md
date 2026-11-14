# Four business throughput domains and their component observations

These tools account for four different product questions. They do not grant
production activation, an unconditional cryptographic security claim, a quantum
work lower bound, or qualified public throughput. The current result is
**HOLD_NO_GO**. The [retained execution report](../../evidence/pon-throughput-20261108/README.md)
distinguishes new execution from historical readback.

## Metric contracts

| Question | Useful numerator and interval | Evidence that is insufficient |
| --- | --- | --- |
| Independent transaction confirmation | Unique original transaction identities confirmed under the installed depth **and** cumulative-work rule, within the original common observation window; retain reorganization, failures, queues, late completion and risk obligations | SubmitACK, admission, History response, blocks, repeated fixtures, a depth-only snapshot, or incompatible local forks |
| Independently useful computation | Unique tasks accepted by the independent task owner within a complete common observation window; retain preparation, training, evaluation, unsuccessful attempts, proof, propagation and recovery costs | Work/seal IDs, receiver fanout, operation labels, training receipts or self-declared usefulness without independent acceptance |
| Complete weight-version access | Verified complete-release bytes per original acquisition interval, plus verification, decode, host/device transfer, load-to-first-response, failures and repair traffic; distinguish cold/hot caches and every planned attempt | Advertised bytes, one member, offline hash speed, a Ready or download-complete message, a model-load substage, or CPU-only work relabeled as GPU loading |
| Model computation and adoption | Actual decoder-generated tokens or separately named forward operations per their matching execution interval; retain training cost, quality, NoUpdate and original next-task adoption evidence | Single-action logits relabeled as generated tokens, transport success relabeled as adoption, or training-stage cost relabeled as total iteration cost |

The four numerators are not interchangeable. They are never summed into a
single TPS. The original readers' separate Cell-distribution and model-loading
projections remain separate components of weight-version access. Existing
historical reports are not rewritten by this grouping. Rates computed from
historical component observations remain descriptive observations of their
exact source, binary, fixture and resources.

## Implemented readers

| File | Scope |
| --- | --- |
| [Transaction reader](../pon-native-fullpath-v1/transaction_throughput.py) | Layers exact PNX1 transaction identities and the installed depth/work distinction over the existing complete-path reader; separately reuses the original Host confirmation reader |
| [Proof CPU reader](proof_cpu_metrics.py) | Recomputes the fixed eight-run #795 corpus from ten independently pinned original blobs, including GNU time user plus system CPU, wall time, failure diagnostics, planned denominator and repeated inputs |
| [Cell/model reader](cell_model_metrics.py) | Projects 44 pinned original records covering the complete eleven-member release, transfer/refusal commands, three training rounds and 32+32 actual action-scoring forwards |
| [Useful-task observation adapter](useful_task_metrics.py) | Imports the same pinned raw corpus, retains training and failed-command costs with source pointers, and explicitly withholds useful-task count/rate, full cost and net value when independent acceptance and a complete attempt census are missing |
| [Complete-block cost readback](whole_block_cost_metrics.py) | Requires all 84 original native records, fixed warmups and alternating paired order; compares full M06 call wall time while keeping per-arm CPU and confirmed business TPS unknown |
| [Host prerequisites](host_prerequisites.py) | Calls the unchanged original Host observer and validator; a prerequisite inspection never becomes an executed or qualified pressure campaign |
| [Report reproduction](reproduce_reports.py) | Reproduces the committed projections byte for byte, rechecks original raw native records and preserves all HOLD decisions |

The separate [command-receipt repair](../../scripts/run_smollm_cell_replica_research.py)
retains available stdout/stderr bytes, monotonic start/end, the unchanged timeout,
actual return status and incomplete output when a command times out or fails.
It rethrows the original timeout; it does not grant another budget. CPU, RSS and
process-family cleanup stay unknown unless independently observed. A normal
command return is not by itself a successfully completed negative control.

## Native execution continuation

The [execution profile](EXECUTION_PROFILE_V1.md) keeps the original four-second
service contract separate from the thirty-second 0/24/24 campaign. Its
[execution report](execution_report.py) preserves both planned denominators,
native error/owner times, queues and available CPU/I/O coverage. The independent
[SQLite syscall reader](sqlite_syscall_profile.py) retains instrumented WAL
write/sync attempts without claiming physical I/O or either throughput gate.

The [useful-task observation contract](USEFUL_TASK_OBSERVATIONS_V1.md) identifies
which original cost scopes are present and which are unknown. The
[component-cost contract](COMPONENT_COST_OBSERVATIONS_V1.md) separates complete
M06 execution and root encoding from the original Node business path. New
request-cancellation observations separately retain the first flag-write time
bracket, per-request worker return and all request-owner closure. Ordinary
connection cleanup, process exit and reconciliation of durable effects remain
different events; historical records without the extension stay unknown.

## Confirmation, forks and uncertainty

The native confirmation rule requires at least six successors and descendant
work of at least six times the included block's target-derived work. The original
Host boundary is strictly before four seconds. The reader preserves this strict
boundary rather than rounding a late observation into the window.

Exact packet identities are retrospective when the original collector did not
freeze signed transaction bytes before collection. They cannot repair a missing
transaction-offer census after the experiment. Duplicate submissions and the
same transaction included in several observations add at most one identity.
Empty blocks add no transactions.

An aggregate eligible numerator additionally needs a common retained canonical
cut: tip, height, chainwork and generation must agree across contributing
observations. Conflicting forks retain their individual observations, but their
aggregate count, rate and latency are unknown. Reorganization/absence remains
recorded even if the same transaction later returns.

Growth ancestry is not a native confirmation return. The development reader
therefore keeps independently confirmed transactions and qualified TPS null.
The Host adapter separately checks the original confirmation phases and refuses
to turn a contradictory zero summary plus an earlier native-positive receipt
into an observed zero rate. Legitimate confirmation after the original window
remains a late observation, with zero timely completion where the original
complete observation supports that conclusion.

Missing attempts, incomplete windows and unknown clocks do not become zeros.
Latency quantiles are descriptive, require their stated minimum sample counts
and never establish a tail or independent-trial confidence guarantee. Risk
ledger consistency, physical clock authentication, native origin, actual resource
enforcement and WAN qualification remain separate unresolved requirements.

## Resource and cohort boundaries

The unchanged original target is 0.25 CPU, 2 GiB, zero swap, 256 PIDs, four
seconds, sixteen hostile inputs and the original honest cohort. Both the parent
identity and original kernel limits must be observed before the actual owned
campaign. No detached JSON `verified` flag can provide that enforcement.

#795's tagged verifier used CPU affinity 0–7 and eight Rayon threads on a shared
host. Its pooled observed user+system CPU median is 2.36 CPU-seconds, while
0.25 CPU times four seconds is a nominal one-CPU-second service envelope. This
is evidence of a resource mismatch. Dividing those CPU observations by 0.25
would not establish a measured latency or a universal lower bound.

Scheduled-SHA and tagged-SHA3 observations remain separate. A combined backend
needs a fresh namespace and a resource-matched four-arm experiment with complete
prover and independent verifier costs. Historical speedup factors cannot be
multiplied, and an admitted fixture cache hit is not new transaction confirmation.

The historical SmolLM release contains 272,190,131 bytes and uses its recorded
180-second transfer cohort. It is distinct from the original failed
272,189,990-byte, 35-second cold-transfer cohort. The failed cohort stays failed;
the complete eleven-member readback and a later successful transfer do not
replace its missing original material or close its gate. Model scoring produced
16/32 for each arm and retained **NoUpdate**. Its 64 action-scoring forwards
are not decoder-generated tokens.

## Reproduction

From a complete checkout, all readers use only the Python standard library:

```sh
python3 -m unittest discover -s formal/pon-native-fullpath-v1 -p 'test_*.py' -v
python3 formal/throughput-v1/test_proof_cpu_metrics.py -v
python3 formal/throughput-v1/test_cell_model_metrics.py -v
python3 formal/throughput-v1/test_useful_task_metrics.py -v
python3 formal/throughput-v1/test_whole_block_cost_metrics.py -v
python3 formal/throughput-v1/test_reproduce_reports.py -v
python3 scripts/ci/test_smollm_command_receipts.py -v
python3 formal/throughput-v1/reproduce_reports.py --output /tmp/throughput-reproduction-new
```

The output directory must be absent and outside the checkout. The reproduction
command exits zero only when retained report bytes reproduce; its summary still
contains `qualification: HOLD_NO_GO` and null qualified throughput. Native
transaction readers return exit 1 for valid component/HOLD evidence and exit 2
for invalid evidence. The prerequisite helper also returns 1 because it cannot
qualify a campaign. These exit meanings must not be collapsed into a generic
success badge.

The [dedicated workflow](../../.github/workflows/pon-throughput-evidence.yml)
checks the exact published source before and after tests and reproduction. It
retains original project, source-inventory, PQ integration and resource guards.
Existing native full-path CI and original pressure acceptance remain separate.
