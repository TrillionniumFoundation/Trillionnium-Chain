# P1 — measurable acceptance, comparison and remaining blockers

All performance reports must bind executed source/input hashes, compiler/interpreter,
hardware, filesystem, concurrency, workload and exact command. Do not merge benchmark
numbers from different code/profile contexts. Production activation stays separate.

The [current continuous pipeline and six acceptance gates](PUBLIC_READINESS.md) add
live native TCP/persistence/client observation campaigns. Logical smoke runs remain
explicitly distinct from paced wall-clock measurements. Transfer-only throughput,
correlated block samples, null mempool/GPU stages and confirmation-drain costs are
reported with their exact limits; no nominal configuration is promoted to measured TPS.

## P1.1 Reproducible campaign matrix

| Campaign | Actual executable | Measures | Does NOT establish |
|---|---|---|---|
| native work32 samples | trnm-crypto-primitives `pon_cost` release example | honest generation, valid/invalid verification, forged-ticket cost, certificate bytes | adversarial lower bound, succinctness, real network security |
| native/Python parity | test_interop.py plus two native examples | exact header/12command bytes, sparse root, work output and rejects | independent external review or formal completeness |
| process crash8 cuts | test_contracts.py DiskReorgTests | real SQLite intent/detach/attach/publish, restart and effect-history preservation | physical power-loss or coherent rollback of every independent anchor |
| three subprocess peers | experiments/local_network.py | signed blocks, full verification, loopback dissemination, hot/disjoint recipients, invalid frames/work, reorg | WAN TPS, native throughput, independent operators or permissionless deployment |
| public-code learning | experiments/model_loop.py | actual parameter optimization, fixed source/file partitions, baselines/ablations and useful matrix contraction | ordinary Hepta operation, unseen future data or general model optimality |
| release/reward/free use | experiments/settle_model.py | exact artifacts, signed attestations, work blocks,20-block maturity, replay rejection, author-path offline and sponsored request | market value, independent custodian diversity, sustainable free service |

The existing Rust executor is separately testable; the Python ledger's full snapshots and
hash recomputation are intentionally not sold as a native parallel performance result.
No throughput number is inferred from thread count, fixture count or recorded parameter size.

## P1.2 Threat-derived failure observations

The full-transcript relation has a cheap-forgery/expensive-rejection asymmetry. Report both
costs, the target used, and the ratio, not just valid proof speed. Do not mark a profile
public-network-ready until admission work and its Sybil model are independently qualified.

The first real learned composition failed its fixed score gate; preserve algorithm digest,
artifacts and metrics. A later feature/imbalance repair can improve observed scores, but
reusing the same evaluation partitions makes it exploratory. Keep best-single and simple
merge comparisons even when they beat routed composition. Zero reward on failure and a
finite reward only for an admitted measured increment are both required executable cases.

Disk-backed previous component tests had deadline/short-lease failures on the observed
host; tmpfs logical passes never replace those failures. New SQLite process-crash tests
name their filesystem. Full-node power cuts, WAN partitions, malicious independent peers,
long retention loss and model poisoning remain unexecuted acceptance work unless new raw
evidence exists. No missing campaign may be represented as an all-green row.

## P1.3 Performance accounting

Report generated work attempts, accepted blocks and client-confirmed transactions separately.
Count failed/stale attempts, proof generation, validation, storage, payload bandwidth,
model-load cold latency, resident memory, VRAM, free-request queuing and budget depletion.
One common-base allocation is counted once. A shared sponsor, nonce, release pointer or
reward pool can serialize otherwise independent tasks; histogram those key conflicts.

Production capacity must satisfy the minimum of propagation, proof verification,
execution, state access and persistence capacities under the SAME workload. Public model
traffic is separate from block-plane traffic. A million parameter bytes in one commitment
is not a million independently verified transactions. A JSON root does not compress the
work of checking each claim.

Low-conflict and single-hot-key workloads must produce the same deterministic roots with
1/2/4/8 execution workers before a speedup is credited. Per-object queueing, preallocated
quota partitions and bounded settlement batches are candidates, not measured gains in
this increment. Any such optimization must preserve escrow, nonce, fee and reorg semantics.

## P1.4 Independent acceptance package

A reviewer receives frozen configs, exact algorithms/byte offsets, vectors generated by a
separate implementation, native source, replay scripts, positive and negative results,
failed experiments and raw cost samples. They should implement a third verifier without
calling either supplied implementation and test hidden adversarial vectors.

External acceptance requires an identified authorized reviewer, exact source/binary/profile,
independent environment, executed command, outputs and signed scope. Two subprocesses or
languages authored by the same agent do not fulfill it. Production eligibility additionally
requires work-cost/security review, verified native integration, financial/DA responsibility,
ordinary Hepta request loop, future-window efficacy and deployed fault evidence. Those are
explicit separate axes; code presence or a hash-bound report is never an activation switch.

## P1.5 Current security and engineering decisions

The selected target stays Nakamoto-style PoN. Bitcoin-style target arithmetic does not
supply a work-cost theorem for a neural relation. Lessons from parallel public chains
are applied at the execution/conflict/resource boundary, not by restoring a discarded
voting core. The exact experimental genesis is useful for reproducibility, not a proposed
production token launch. Improving the failing primitive or observation requires a new
reviewed profile/context, not lowering assertions, erasing failures or adding a silent
hash-only/BFT fallback.

## P1.6 Recorded execution

[The evidence package](../../../../evidence/pon-v1/README.md) contains the clean-source
command exits,1794 native test results,18 executable-ledger tests,eight process-crash
cuts,seven cross-language suites,work-cost samples,first failed model experiment and
the later28-block release/reward/free-use run. Its source hashes are checked separately
from its scientific scope; none of these results grant independent acceptance.

## P2. Revision2 reporting contract

[Native execution](EXECUTION_PARALLEL.md), [local admission](ADMISSION_SECURITY.md),
[recovery](STATE_RECOVERY.md) and [Hepta handoff](HEPTA_HANDOFF.md) have distinct scopes.
Every current measurement must state block mix, exact encoded bytes, real shared key
conflicts, retries, workers, proof cost, host, filesystem and source. Record input accepted,
application executed, block included and client-confirmed counts separately. Unmeasured
inclusion/confirmation is null, not copied from executor success. Peak RSS is measured by
the executed process; absent GPU telemetry is null with an explanation, never zero usage.

Historical pon-v1 results remain tied to their original source. New reference/Python/
native tests do not silently inherit physical disk, WAN, independent-operator or future
model efficacy acceptance. The current network harness uses a fixed logical clock; it
cannot supply live-clock confirmation or public TPS. 256 slots/10-second target is a
nominal25.6 slot/s parameter budget, not measured throughput.

## Invariant continuation: stage boundaries and actual observations

[Historical revision3 evidence](../../../../evidence/pon-v3/README.md) records its measured runtime tests,
actual >4096 history, the 1/2/4/8 native-command comparisons, local proof-admission load,
three real learning attempts and same-operator ROG/Pocket4/X230 execution. Each report
names the source and its distinct clock/filesystem/trust conditions. Source-file equality
permits later documentation publication without calling it another runtime experiment.

Prepared transactions, application-executed transactions, included transactions and
policy-confirmed transactions remain separate counters. A missing stage is null, not zero
or estimated from another stage. Report encoded bytes, key conflicts, proof generation and
verification, root/persistence cost, peak RSS, actual GPU/VRAM use or explicit nonuse,
queue/Busy outcomes, state growth, active physical slots and recovery duration.

No throughput improvement is inferred from worker count. Samples in which extra workers
are slower stay in the report. No learning update is inferred from successful optimization:
all three measured candidates may remain unapplied with zero reward. File-disjoint source
windows are not independent future user experience. Physical hosts and actual UTC do not
establish different operators, public ingress fairness or proof-cost hardness.

## Current applicability and pipeline cost decomposition

The [responsibility reporter](../../../modules/README.md#responsibility-and-evidence)
derives current byte applicability; neither v3 nor v4 is globally labelled current merely
because a component file stayed unchanged. E3 records its model/consent experiment;
client and native-session receipts record later receiver/execution regressions. None
replays v4's physical-host performance or repeats E3 model efficacy by implication.
The module index links all these packages and the separately measured native-session
work costs. New tooling checks belong to their own source/PR observations. Never
overwrite an old manifest or change its measured SHA.

Current workloads use the closed command set selected by the committed profile: the
historical twelve-command core and explicitly gated signed-task, native evaluation and
lifecycle extensions. Each benchmark must name its profile and exercised tags; historical
twelve-command parity and transfer-only measurements retain their original scope.
For one source and one profile, split signature preparation, state speculation, canonical
replay, root construction, IPC encoding, process startup, durable commit, work validation,
propagation, inclusion and client confirmation. Record state size and shared sponsor,
provider, nonce, release-pointer and prefix conflicts. Ordinary append no longer copies
all KV rows; full root computation and the reference/native bridge still require scrutiny.

The [checked derived commitment adapter](DERIVED_STATE_COMMITMENT.md) specifies complete
actual-state validation, immutable staged roots, cache limits and explicit full-root
fallback. Its component controls do not establish a Node or network performance result.
Growth acceptance must cross the historical 8,192- and 16,384-key cache boundaries,
reach the current 65,536-key protocol boundary and separately verify overflow rejection
without changing the committed parent. Protocol overflow must not be accepted as a
successful cache fallback.
Record actual canonical payload, retained-cache/software-workspace
charges, selected method and complete-root fallback separately. The 8 MiB payload and
512 MiB workspace-charge ceilings govern the optional derived cache; a valid state
outside a cache budget still needs the complete root and must not become a consensus
refusal. The protocol state limit remains 65,536 keys. Report continuous owner-held operation windows against the public request work
deadline, including every failed Head, History and PoolStatus attempt. Successful
inclusion or a faster root component cannot waive honest request failures, final
confirmation or closed-store convergence in the same registered campaign.

Optimize the measured bottleneck rather than prescribing another worker pool. Candidate
work includes measurement and scaling of the implemented durable-owner root integration,
bounded native state residency, explicit
access/dependency scheduling and serial hotspot degradation while preserving the existing
single durable owner. A changed backend needs exact state/receipt/error/recovery parity
before its speed can count. A faster executor cannot expand the 256-slot/10-second nominal
budget or reduce probabilistic confirmation risk by itself.

Client-confirmed throughput requires independently checked work/inclusion/currentness,
not an RPC integer or a controller ACK. Public attack capacity additionally requires the
ordinary open ingress path. Missing network/native owner/independent observations remain
unmeasured, even when all local correctness and cost collectors complete successfully.

## Native session and receiver pipeline measurement scope

A new-source session qualification must rerun all native and reference regressions,
work prechecks, exact twelve-command session parity, and both single/batched client
confirmation with explicit native backends. Historical E3 and client packages are
validated against their original measured Git trees; they cannot qualify changed runtime.

Paired cache measurements advance nonces/roots; cache hits are excluded as actual samples.
Bootstrap, full-state serialization, incremental native commitment, Python root checking
and whole-map costs remain separately visible. The real-proof receiver campaign measures
all fill blocks and source/receiver verification through locally computed confirmation.
Its unpaced logical clock and same-controller transport forbid a public-chain TPS claim.
Do not derive tail percentiles from a handful of samples, omit slower cases, or infer
hostile-peer availability, independence, GPU consumption or physical durability.

## Native confirmation cost and bounded mixed ingress observations

Native `confirm-batch` shares one complete ancestry walk and one membership index per
distinct requested body. Reports expose those actual check counts and preserve every
individual work/depth/generation result. Complete state-root work, serialized Node access
and linear historical traversal remain costs; no constant-time or public TPS claim is
made. Cancellation discards the result rather than caching incomplete currentness.
Native socket tests with concurrent false transcripts and honest confirmation requests
exercise the real entry, but bounded same-host concurrency is not a sustained public
arrival process, Sybil churn, latency-tail qualification or independently operated load.

Qualification timeouts remain failed observations when process-group termination
prevents GNU time from writing its summary. Keep the actual exit and timeout, preserve
the raw log, and record missing peak RSS as null. Never infer completion from a partial
test count. SHA2-only test optimization retains debug assertions, overflow checks and
all boundary instances; compare performance only between the explicitly recorded build
profiles. That test setting does not change the release runtime or certify its capacity.

## Executable work-security cost and honest-service screening

Use the existing collector's native raw observations and the existing paired producer
example, rather than a second benchmark algorithm:

    python scripts/pon_work_cost_report.py \
      --input PATH/native-work.json --prepared PATH/prepared-cost.json \
      --expected-target 7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
      --require-local-acceptance

The command prints a complete JSON report and exits 2 if any local cost gate fails or
service evidence is missing/fails. Without the last option it remains a summarizer;
exit 0 then means parsing/reporting succeeded, NOT security acceptance. Inputs have
strict field/type/identity checks, all four task classes, exactly the existing 64 paired
producer observations, at least eight invalid-cost observations per class, setup
arithmetic, canonical targets, and positive denominators. Raw inputs are not rewritten.
Semantic input hashes and policy hash bind the calculation. Existing clean-source
receipt verifiers must separately verify source/binary/command identity and current
applicability: this summarizer explicitly does NOT authenticate those claims or create
fresh measurements. Historical evidence remains historical.

Optional `--service PATH/events.json` supplies schema `pon-work-service-events-v1`:
`target`, `window_ns`, `acceptance_profile_sha256`, `attacker_setup_cpu_ns`, `honest` and
`attacker` arrays, `scope: controlled-local`, and false `independent_accepted` and
`production_activation`. Each event contains a unique integer `id`, `offered_ns`,
`finished_ns` (null only for timeout/drop), and `outcome` (accepted/rejected/timeout/dropped).
All times are integer nanoseconds relative to the same observed window. Attacker events
add positive `construction_cpu_ns`, `encoded_bytes` and `rejection_cpu_ns`. CPU counters
are actual charged resource time, not elapsed latency; setup/precomputation is charged
once in the top-level setup field and never omitted or counted as free. A capture lacking
CPU accounting cannot be converted to zero-cost samples. This schema is an import
contract for actual observations, not an implemented public traffic generator or proof
that an operator included every event.

The versioned proposed diagnostic policy checks an observed >=60-second window and >=49-second offer
span for EACH population; a nominal long window around an instantaneous burst fails.
All >=100 offered honest requests form the denominator, including rejection, timeout,
drop and late success. No honest failures are allowed; nearest-rank p99 must be <=2s.
The attack must include >=100 offered requests, no accepted forged work, <=60 CPU-seconds
INCLUDING setup, and <=64MiB encoded traffic. These finite single-host screening budgets
are not preregistered/deployment acceptance or a sustained public adversary capacity claim.
The local service checker additionally refuses independently long but disjoint
honest/attacker offer spans. It requires their offered-time ranges to overlap by
at least half the configured minimum offer span, and requires co-offered traffic
in at least `max(1, floor(minimum_offer_span / (minimum_window / 10)) - 1)`
common time buckets (integer nanosecond division; bucket width at least 1ns).
The existing sixty-second and forty-nine-second screening values yield six-second
buckets and seven required joint buckets. These checks defeat delayed separate
campaigns and endpoint-only bursts in supplied ledgers; they do not authenticate
the ledger, establish CPU saturation, police false timestamps or imply public
admission security. Both raw populations, their failures and their independent
costs must still be retained.

This service gate checks only input-contract consistency: budget maxima and minimum
request counts cannot establish attack saturation, adversarial mix or sufficient hostile
intensity. An externally reviewed registered arrival/mix plan and observed execution
against it are still required; a weak attack within budget must never qualify public service. Deadline failures, uncompleted
requests, construction/setup CPU and defender rejection CPU remain separately visible.
A missing ledger yields `unmeasured`, never an inferred zero failure rate. No existing
network campaign is implicitly relabelled as this event ledger.

A local pass still leaves external acceptance unmeasured and all production/public/work
hardness flags false. Independently authored/reproduced algorithms, identified external
reviewers/operators, source-bound public ordinary-ingress measurements and an accepted
security argument remain separate prerequisites. The supplied Rust/Python implementations
share development authorship and cannot satisfy that external obligation themselves.


## Continuous pipeline failure ownership and stage observations

The existing `continuous_pipeline` example now retains pending confirmation items
until a complete contextual observation succeeds. A read refusal, malformed response
or later failed item does not discard earlier unconfirmed items or the unread tail.
The failure report records the remaining original record indices; a later successful
poll removes only its completed items and does not recount earlier completions.
This is in-memory campaign bookkeeping, not a second durable transaction journal or
an authorization to redispatch a packet after an uncertain remote outcome.

Final producer/validator readbacks are collected without returning before the original
server receives stop and is joined. Its actual failure is reported separately from the
primary campaign failure; a server error prevents a successful campaign result. Disk
failure may still prevent writing a report. No detached worker or new background service
is introduced, and no deadline, wire rule, work verification or state fence is relaxed.

Additive `stage_counts` distinguish fully constructed transaction batches, completed
execution-plus-work packets, local durable admission, local activation, remote ACK,
verified remote membership and policy confirmation. The standalone executor completion
count remains null because `make` couples execution with proof search; it cannot be
inferred for a failed search. ACK is neither membership nor confirmation. The existing
accepted/confirmed fields now count the actual verified query cardinalities, not the
number of latency samples multiplied by the configured batch size. Pending entries
cover membership-checked batches; earlier delivery uncertainty is visible as a stage
gap and campaign error, never reclassified as proof of non-execution.

Native controls reproduce the original drain-on-error loss, exercise every failure
position and successful retry, and join real successful, failed and panicked server
threads. Existing exact-head/actual-main-merge x64/ARM64 lanes run these controls and
both original legacy/protected TCP pipelines with actual mined, stored and confirmed
transactions. The tiny logical-clock runs check scope and count consistency only; they
are not saturated throughput, live-paced latency, public V3 fairness, independent WAN,
physical power-loss or long-term data-availability measurements. All original full
baseline, capacity/history, native owner and cross-repository gates remain required.


### Bounded cross-block confirmation polling

The existing continuous pipeline now groups whole pending block-query sets into
at most256 queries per ConfirmMany RPC. One native response still performs the
original complete State, ancestry, inclusion-body, clock and generation checks.
Only the caller's repeated acquisitions are coalesced; no backend history walk,
wire rule, confirmation threshold or state check is removed or cached across calls.

Each response is validated in full before any item in that batch is completed.
Incorrect cardinality, reordered identities, foreign chain context, mixed observed
tip/generation/time or malformed/authority-bearing flags preserve the whole failed
batch and unread tail. Successfully completed earlier batches remain completed;
deferred items keep original order. Empty/oversized query sets reject before any
RPC. No block's queries are split across responses. This is a read caller and
in-memory campaign owner, never a durable journal or redispatch authority.

`confirmation_poll_counts` counts actual started and fully validated RPCs, query
cardinalities and block-query sets, including failed starts. Initial membership
reads are outside this scope. Per-block confirmation records retain only their
own observations; scan counters and wall time are explicitly marked as shared
RPC measurements and must not be summed as independent per-block costs. The
source-bound two-block native smoke checks eight confirmation RPCs instead of
fourteen separate block polls, with all28 repeated transaction queries retained.
This is a deterministic call-count check, not a measured time speedup, saturated
TPS, independent WAN or a change to full-history asymptotic cost. All original
failure, native, capacity/history and two-repository baseline gates remain.
