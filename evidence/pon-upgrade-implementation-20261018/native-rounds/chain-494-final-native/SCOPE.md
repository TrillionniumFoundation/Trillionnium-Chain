# Source494 final native observations

The authenticated public campaign **failed**. Its no-attacker baseline and both
hostile modes each confirmed **0 of 3 planned signed rounds**, completed no
Submit responses and remained at the initial seed tip. Source/format/lint checks
passed in their separately identified invocations. These are development results;
production activation, independent operators, WAN and work qualification remain
false.

Primary native source: `4940b7a8072761807c5da75b322eecb05a5f193f`, tree
`e336a673fa763ad117b4b4dc40677fb85ba0c00e`. The archive also retains an earlier
format failure at `a51a2eeab84e3c1ff59e4df1a1088e1c16dd5a13`, tree
`63b81f6874d4360db3bf70a9340ee82c2aa67397`. These native identities do not become
the identity of a later documentation or evidence commit.

## Retained original files

The original [compressed archive](observations.tar.gz) is **8,861,501 bytes**,
SHA-256 `aa5869a304be8dd4e3bb873df4e88a785642e65526160d7ef130b652e9524925`.
Its original [member manifest](MANIFEST.json) is **65,127 bytes**, SHA-256
`127d457b947d7463be1a236d2f70199a1756e36c761f3e31b6bfeb0c87033009`.
All **310 regular members, 33,198,520 uncompressed bytes**, were read in memory
and individually checked against their recorded sizes and SHA-256 values. All
members remain, including seven SQLite files, the original a51 candidate bundle,
failed executions and hostile actor records. This archival reader did not execute
SQLite integrity checks or native reexecution.

The archive is **not fully expanded**. Only the following five small JSON members
have byte-identical expanded copies for navigation; those copies do not add
observations to the 310-member cohort:

- [Authenticated campaign results](expanded-results/chain-494-authenticated-multiprocess/results.json)
- [Sequential comparison context](expanded-results/chain-494-authenticated-multiprocess/comparison-context.json)
- [Final static results, including both harness failures](expanded-results/chain-494-final-static/results.json)
- [Corrected source observer results](expanded-results/chain-494-correct-source-observers/results.json)
- [Earlier a51 format failure](expanded-results/chain-a51-auth-comparison-v2/results.json)

The [derived report](derived-observations.json) names exact archive members and
their hashes. Cross-device rename returned `EXDEV`; the authorized replacement
used a streaming copy, full destination and source size/SHA checks, then removal
of the original temporary transport file. No complete extraction or duplicate
transport copy is retained.

## Actual business and failure denominators

The original test used explicit `authenticated-v1` for its three original Node
openers. The default remains `legacy-v2`. Settings, 1,024 signed seed transfers,
21 prepared business blocks, three planned signed rounds, each 30-second pressure
window, 24 attacker processes in each hostile mode, and the original work and
resource budgets are unchanged. All actors use the controlled `main` host and
loopback. A requested 400-percent outer CPU quota is recorded as requested; this
reader does not independently establish its enforcement or control unrelated
host load.

| Phase | Successful honest Submit ACKs / offered attempts | Offered outcome cohort | Confirmed / planned signed rounds | Full-work accepted / failed | Completed service Submit / read |
| --- | ---: | --- | ---: | ---: | ---: |
| Baseline, no attackers | 0/25 | 12 CPU refusals; 12 I/O errors; 1 frame deadline | 0/3 | 1/0 | 0/0 |
| From-zero | 0/15 | 2 CPU refusals; 13 I/O errors | 0/3 | 0/2 | 0/0 |
| Late-product | 0/15 | 14 I/O errors; 1 frame deadline | 0/3 | 0/2 | 0/0 |

Every offered Submit in each phase retries `packet_index=0`, with one distinct
request-body digest per phase. The attempts do not represent 25 or 15 distinct
business transactions. Each phase starts only round0; the two unstarted planned
rounds remain in the planned denominator. Each cohort retains one response/error
return after its pressure window. No honest History call completed or started in
the recorded client sequence. No positive confirmation observation exists.

`receiver_client_state_equal=true` means both parties remain at their identical
initial seed tip. It is **not successful business progress**. Client timeout or
missing ACK also does not, by itself, prove absence of every durable side effect.
Tasks enqueued/dequeued (25/25, 143/143 and 171/171) and W1 acceptance are separate
internal observations, not confirmed transactions or successful user requests.

The failed campaign command returned 101 after **390.8495972949895 seconds**.
Compilation was separately recorded at **147.0886561240186 seconds**. The campaign
duration includes honest preparation, receiver/verifier setup, pressure windows
and shutdown; it is not a business-only latency denominator. There are zero
unique confirmations in each declared 30-second phase; that failed observation
does not establish sustainable capacity. No confirmation or model-install latency
quantile can be inferred from these zero completed confirmations.

## CPU: expensive remaining mutation work, exact cause unresolved

| Phase | Total metered mutation CPU | W1 CPU within that total | Remaining mutation dispatch/execution CPU | Final debt |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 9.468013452 s | 0.002855270 s | 9.465158182 s | 0.297783179 s |
| From-zero | 9.478595972 s | 0.007702385 s | 9.470893587 s | 0.109270318 s |
| Late-product | 9.730666435 s | 0.010037395 s | 9.720629040 s | 0.271948401 s |

The original shared budget remains a 2-second burst, 0.25 CPU seconds per wall
second refill, two workers and a 100 ms start reserve. The derived reader checks
`initial + credited_refill - paid_CPU - settlement_discard = remaining_credit`
for all 597/575/576 retained budget snapshots and each final flow. It also checks
the nested W1/remaining CPU sum and live-debit/residual settlement. Negative final
credit is retained as debt. Original retained body/output/grant/in-flight owners,
booked reservations and unsettled known live CPU are zero after shutdown.
Conservation and cleanup coexist with the complete business failure.

The no-attacker baseline localizes the dominant **measured bucket** to mutation
dispatch/execution outside W1. It does not attribute all of that bucket to SQL,
history, root hashing, State cloning or candidate archive writes. History is a
separate read lane outside this mutation CPU bucket. Reactor authentication,
response handling, queue waiting and separate attacker-process CPU also have
their own scopes and must not be added as though these nested counters were
disjoint.

## What existing timing can and cannot explain

The existing [request observer](../../../../trillionnium/crates/trnm-pon-node/src/ingress/public_v3/request_observation.rs)
records request identity, terminal phase, total dispatch thread CPU and full-work
thread CPU. The public metrics retain grant/queue wall waits, reservation/debt
accounting and the mutation split above. Continuous pipeline observations retain
separate inclusion/confirmation wall timings. Component root-hash timing probes
exist, but are not connected to these public request records. No retained
per-request profiler splits this run into full State materialization/clone, root
hashing, candidate archive, commit/readback and confirmation work.

The next narrow observation point is the original
[`dispatch_shared_with_execution_control`](../../../../trillionnium/crates/trnm-pon-node/src/ingress.rs):
record optional bounded CPU/wall intervals around
`check_admission_context_with_progress` / `begin_owner_work`, the existing work
verification interval, `attach_owner_work` / `admit_work_checked_with_control`,
and `submit_result`. Lock/queue wall waiting must remain separate from CPU. The
original [Node owner](../../../../trillionnium/crates/trnm-pon-node/src/store.rs)
already separates these calls; notably task eligibility/context work occurs
before the measured W1 callback. Only after locating the expensive owner phase
should its existing State/root/archive/commit boundaries receive finer timing.
Reuse the bounded optional observer and retain unknown clocks and failed/cancelled
outcomes. This is a proposed measurement, not an implemented profiler or new
acceptance gate. These data do not establish a need for a DAG or a broad
consensus rewrite.

## Legacy comparison and six-metric boundary

The earlier [source390 report](../CHAIN_390_SCOPE.md) remains unchanged, including
the successful slow pipeline, failed fast pipeline and all three failed original
legacy public phases. The recorded seed/business header, ID and transaction
fields match across the legacy and authenticated preparation files; the first
submitted body digest also matches in each corresponding phase.

Legacy preparation used **26.651623045 wall seconds / 22.228627897 CPU seconds**;
authenticated preparation used **189.327795105 / 180.563833662 seconds**.
Legacy completed 4/2/4 Submit calls across its phases; authenticated completed
0/0/0. Both completed 0/3 planned signed rounds per phase. These sequential
observations have different exact source identities and uncontrolled background
load. They show no demonstrated service improvement from selecting this backend
under the retained settings; they do not establish an isolated causal slowdown
ratio or compare sustainable capacities.

The derived JSON preserves all six development metrics. It reports the failed
unique-confirmation counts, actual proof outcomes/CPU and honest offered/success
cohorts. Isolated proof/state-commit capacity, candidate-to-install p50/p95/p99,
installed-and-subsequently-qualified updates, calibrated loss/reorg/restart/new-node
cost and WAN capacity remain null. The source390 finite 0.7597448140746955 TPS
success and 3.807633098281181 failed/censored value remain separate observations.

## Static results and preserved invocation failures

Source494 format and strict Clippy passed. The **one exact previously failing
applicability case** passed; this is not a new complete 29-case applicability run.
The corrected invocation passed 12 W1 reader controls, 33 source-integrity
controls, and `check_repository` with 948 links on its recorded clean source.
Negative-control FAIL receipts inside the 33-test log are expected observations;
the enclosing test command passed.

Both original root harness failures remain: the W1 reader invocation left its
required raw directory unset (`RAW_DIR=None`), failed `setUpClass` and ran zero
tests; the original source-check invocation named nonexistent
`scripts/check_repository.py`. The corrected commands and results have their
own original files. The earlier a51 format failure also remains; no business
campaign ran in that attempt. Resumed native command access and these successful
source checks do not erase the authenticated campaign's actual failure or add
independent-network evidence.
