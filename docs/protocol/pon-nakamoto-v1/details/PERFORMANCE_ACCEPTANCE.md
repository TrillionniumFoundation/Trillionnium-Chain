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

The optional public request observer uses
`public-v3-local-request-resource-observation-v3`. Its outer owner CPU covers the
r11 paid body decode, native dispatch and signed response envelope, also retained
by r12/r13. This observation schema does not identify the scheduling revision: new
original campaign reports bind their exact signed policy identifier in
`public_resource_policy`, checked against the independent r10/r11/r12/r13 vectors.
Historical missing policy metadata stays unknown, and r11 starvation remains
failed evidence. Historical v1/v2 totals retain their original scope; source/profile
identifiers must be preserved when comparing them. Each retained request has exactly
seven Submit slots: decode, context-owner wait, context, full work, admission-owner
wait, admission, and submit-result generation. Every entered slot records monotonic
wall time and, where available, the actual dispatcher thread's CPU time. Slots not
entered remain null; an abandoned or panicked slot retains its measured interval
with unknown outcome and `completed=false`. A completed error is `accepted=false`.
An exact durable duplicate does not manufacture work or admission measurements.
The existing first-record retention bound and nonblocking optional writes still
apply; capture contention marks the observation failed without changing admission,
cancellation, durable results, or CPU settlement.

These slots separate waiting from owner-held context/admission work. They are
nested within dispatch and must not be added to dispatch or full-work CPU a second
time. Their thread CPU excludes scoped M06 workers, reactor authentication and
response signing; missing clocks are unknown rather than zero. These diagnostic
fields add no service credit and do not extend any deadline. They locate the
remaining cost before attributing it to root reconstruction, history verification,
SQLite, or execution; they do not by themselves establish a restored baseline or
improved throughput. Historical Source494 records retain their original schema,
source and failed outcomes.

The ordinary unowned public V3 Submit preflight now checks bounded packet
identity, namespace, parent/header/target/time constraints and the cheap PNW1
task/ticket statement before full W1 replay. It defers complete parent-State
task lookup until the verified packet reacquires the durable owner. That final
admission still rechecks the current full task/State/clock and all persistence
fences. Local owner, continuous-owner and mining-owner policies keep their
task binding before work; private/generic dispatch keeps its earlier order.
Tests retain a ticket-valid false transcript, a valid retry, and a real external
SQLite mutation between full work and final admission. A passing W1 proof is
not a retained State or task authorization.

Native final-state and genesis-root comparisons reuse only arithmetic over
the exact complete State bytes and network/parameter/genesis context. The
existing three complete-commitment entries retain at most 4 MiB of encoded
input each; one separate root entry has the same bound, so repeated genesis
root calculations do not depend on parent/child entry eviction. Oversize
inputs or unavailable entries use the original full calculation. Failed root
calculations are never retained, and a root-only miss preserves the original
root grammar and error order. Every current SQL row, stored record, delta,
genesis snapshot and required account node is still read and checked. This
does not cache a database validity verdict or remove the full history walk;
history remains O(H) and complete State reads remain O(State). Actual original
budget multiprocess confirmation results are required before crediting a
baseline restoration or a throughput improvement.

After native execution and the final header state/receipt comparison, the
owner also offers the existing opaque successor tree to the existing historical
arithmetic cache. A task output that changes the final State first derives the
matching final tree. This cache keeps its original eight-entry, 2 MiB total
canonical-payload and 16 MiB retained-software-charge bounds. The subsequent
snapshot readback still reads all actual SQL State, encodes every key/value,
applies any differences to the immutable material and compares the resulting
root; it then checks the account graph and full history. A rollback can leave
only optional arithmetic, not a stored or admitted block. Cold rebuilds and
external snapshot mutations remain explicit test controls. No database version
token or cached validity result replaces those observations.

[`pon_public_v3_phase_read.py`](../../../../scripts/pon_public_v3_phase_read.py)
projects exact retained report bytes and checks their supplied SHA256. Native
refusals come from `response.value.error`, while earlier flat `response.error`
records remain readable; conflicting shapes are rejected and a missing cause
stays unknown. ACKs, late ACKs and the three scheduled confirmation rounds
remain separate. The reader never infers a successful confirmation from an
accepted socket reply or changes the original 30-second windows.

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

## Exact-input native history arithmetic and unchanged business gate

The 2026-10-19 native campaign on source
`d633cb17dedd45f1346968a764d92caaab466750` still failed the original business gate:
baseline acknowledged five unique packets (indices 0 through 4) in 54 calls, with
48 `PUBLIC_MUTATION_CPU_BUDGET` refusals, and confirmed zero of three rounds.
Both hostile phases acknowledged two packets and confirmed zero of three rounds.
The complete native test exited 101 after 129.24 seconds; it was not terminated
by its outer job deadline. Its raw `report.json` is 9,553,037 bytes with SHA-256
`0e17d701d2e11fc8e9c0a081469dd56e2e78c00f642f5b85ec8863d25996adcc`.
These observations remain failures and do not qualify the successor source.

The baseline's 54 entered admission intervals consumed 8,472,464,608 ns of
execution-thread CPU; the five entered submit-result intervals consumed
180,218,204 ns. Context consumed 94,504,438 ns. These intervals exclude scoped
worker CPU and must not be added again to their containing dispatch intervals.
The receiver's actual charged mutation CPU was 9,185,360,744 ns. An ACK is not
a confirmed signed round, and this offered load is not a saturated TPS result.

The next implementation keeps `verify_history_with_cache`'s complete original
tip-to-genesis traversal. It rereads every actual typed block, parent,
commitment-record and delta row. It may reuse a record's successful codec/hash
calculation only after the complete current BLOB and network/parameters/genesis/
block identity match. Packet codec/hash material additionally remains subject to
fresh actual block-column, parent-height and parent-chainwork checks. Delta leaf
material requires the current exact tuple at the same index, after all original
SQL type, length, order, NULL-versus-empty, before/after and canonical-JSON checks.
The original Merkle merge/padding, genesis snapshot/account-graph checks, error
order and progress/cancellation positions remain. No metadata root, generation,
mtime, data-version value or previously admitted fact supplies authority.

The three independent record/packet/delta pools each retain at most 64 entries
and 4 MiB of conservative software charge, including their owned input/result
capacities. Thus retained charge is at most 12 MiB per Node. An operation may
temporarily collect at most one additional 4 MiB delta-material capture. These
are software retention/workspace bounds, not process RSS or SQLite page-cache
bounds. Retained entries are immutable and are not evicted by a historical scan;
full pools or oversized input use the original calculation without retaining the
new material. This avoids self-eviction during long scans without claiming an
unbounded cache, an always-resident genesis prefix or constant-time validation.
SQL traversal and current-byte comparison remain O(H plus actual delta bytes).

`native_history_arithmetic_observation()` returns local cumulative diagnostics
with schema `pon-native-history-arithmetic-observation-v1`: current observed
bytes/rows, arithmetic hits/computations, pool charges, and fixed nested
native stages. Stage times are wall time and current-thread CPU, include error
and cancelled calls, exclude scoped worker CPU, and expose unavailable CPU
separately. They grant no work credit, eligibility, currentness or consensus
authority. The original multiprocess campaign adds before/after snapshots to
its raw report; its three 30-second windows, 0.25 CPU-second/second refill,
2 CPU-second burst, 21 business blocks, hostile load and confirmation/state
criteria are unchanged. The new source must rerun that gate at the original
resource limits; arithmetic regressions alone cannot close it.

Run the exact-input, mutation, cancellation, retention, rollback and reopen
regressions together with the original native suites:

    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::native_authenticated::history_arithmetic:: -- --test-threads=1
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::native_authenticated:: -- --test-threads=1
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::native_authenticated_tests:: -- --test-threads=1

## Complete-state root arithmetic after the failed 6bc campaign

The next original-budget campaign, on source
`6bc6f40a7d93602303cf7bb4724e4fee52ea9c48` / tree
`e76d41a2a3226e86e5dbee4ac1deb84f5a8ad216`, also exited 101 without an outer
timeout. Its 9,526,402-byte raw report has SHA-256
`a12cbc9cb516181bcb30f90ed0e5f5aa8efa1fe4b2f9af7e4f972a5f7d074b1c`.
The baseline acknowledged five packets in 55 calls, with 49 CPU-budget refusals
and one shutdown-interrupted call. From-zero and late-product acknowledged two
packets in 23 and 21 calls. Each phase still confirmed zero of three signed rounds.
Preparation consumed 13,112,593,855 ns of CPU; this is not a business-gate pass.

The new before/after owner observations show effective, unfilled history pools:
the baseline reused 1,339 record calculations, 673 packet calculations and
43,703 delta-leaf calculations, with only 6, 6 and 14 corresponding computations.
The largest pool had eleven entries; packet retained charge was 716,865 bytes.
No sequential-scan cache overflow was observed in this campaign. Complete
history verification consumed 165,757,213 ns, while complete-state verification
consumed 5,175,279,647 ns over 266 entered calls. Admission consumed
8,488,149,094 ns over 54 entered calls. These are nested current-thread intervals,
including rejected or cancelled work, and must not be summed. The snapshots
exclude setup and the final post-service verification reads.

The following source change targets a separate duplicate calculation: a new
native StateCommitment previously rebuilt the full sparse State root even when
M06 had just produced an opaque canonical map and derived StateTree for those
values. The native owner may now offer that opaque material from its existing
checked parent or derived successor. At the original root-calculation position,
the existing M06 algorithm re-encodes every actual State key/value, compares the
complete key set and applies every actual addition, change or removal. A stored
record, header digest, block identity or caller-supplied root is never an answer.
Network, parameter and genesis context must match before material can be used.
Missing, foreign or refused material uses the original full-root path; an error
from optional arithmetic re-enters the original grammar for its exact error.

The optional material retains at most one tree, 2 MiB of canonical payload and
16 MiB of conservative software charge, charging shared Arc material in full.
These are additional retention bounds, not process RSS bounds. M06's existing
temporary workspace and the other independent caches remain separate. The root
material has no row-set, freshness, admission, cancellation or consensus authority.
Rollback may leave mathematical material but cannot leave a successful verdict.

Account parsing still precedes State-root calculation. Every actual SQL account
node is still read and decoded, and its parent edge, path, digest, complete leaf
set, count and balance are checked. Actual complete KV reads, state/metadata
bindings, old-history checks, transaction fences and all original progress/error
positions remain. There is no new node-decoding cache or reduced history scan.

Three additional nested stages, `complete_commitment`, `complete_state_root` and
`account_graph`, separate actual commitment/cache work from the unchanged graph
checks. The additive `complete_root_arithmetic` object records offered/refused
material, exact-root hits, complete-cache hits, actual tree calculations and
changes, cold/error fallbacks and retention charge. Missing measurements remain
unknown. Its counters grant no CPU credit or success classification.

The same original three 30-second windows, 0.25 CPU-second/second refill,
2 CPU-second burst, 1,024 actual signed seed transfers and 21 business blocks
must be rerun on this successor source. Local exact-byte and mutation regressions
cannot predict or replace that original-budget result.

    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::native_authenticated::arithmetic_cache::root_arithmetic:: -- --test-threads=1

## Ordinary verifier material after the df6 two-of-three baseline

The original-budget campaign on source
`df6faa814f193c7c6645d53f140612bc3a156416` / tree
`80fbb9fa4b06b3da9784572634d6e15767ba2e08` exited 101 without an outer
timeout or cancellation. Its 11,997,334-byte raw report has SHA-256
`d584d047983daeb5f5ed24489d046a394e3392e533cc0529fb41245dc21dd002`.
The baseline acknowledged all 21 business blocks with no CPU-budget refusal,
and the independently importing client reached the receiver's final state/tip.
The first two depth-six confirmations completed at 11.859364293 and
22.604274663 seconds, inside the original 30-second window. The third actual
confirmation completed at 32.613441056 seconds and remains a failure of that
unchanged window. Baseline therefore improved to two of three; it is not a
complete passing campaign. Both hostile phases still confirmed zero of three,
with five and four acknowledged packets respectively.

The complete-root material was used in 21 baseline calculations, all through
checked apply with no cold fallback. Receiver account-graph verification still
consumed 2,997,489,777 ns out of 3,110,607,952 ns of complete-state verification.
These are nested current-thread CPU intervals, not independent additive costs.
The 21 History network calls consumed only 384,366,531 ns of aggregate wall time.
The gaps from each final History reply to its round's confirmation completion
were 4.297006385, 4.623609865 and 4.131588619 seconds. Each gap includes the last
local import, its original complete-page activation, confirmation and controller
overhead; the old raw report does not isolate confirmation alone.

The successor removes two measured-path opportunities for duplicate pure tree
calculation. Ordinary import may admit several inactive parents before activating
the final page tip. After the original active/slot reads and a fresh parent record
root read, execution may use the same Node's already bounded historical opaque
material. The original `check_and_bind` still canonically encodes every actual
State key/value and compares its calculated root. The block/root pair is only an
index, and does not replace current SQL, namespace, ancestry, eligibility or
actual-state checks. Missing, mismatched, unavailable or over-budget material
uses the original complete calculation. Both original parent-binding progress
points remain, and no activation is moved to an earlier page.

The root-only persisted-state check also uses the existing bounded opaque
arithmetic on an exact-byte-cache miss. It does not call complete account
validation before the original root grammar or alter its error precedence.
Actual KV and account graph reads, all parent edges, complete row/leaf sets,
reorganization steps and final transaction checks remain. In particular,
`resume_intent` retains its final independent full-root comparison before
publishing the target. There is no new cache or larger retention allowance;
the previous software charges still do not bound process RSS or remove O(H)
history reads and O(K) complete-State encoding.

Two appended native stages, `persisted_state_root` and
`execution_parent_binding`, and successful binding method/candidate counters
make the actual route observable. The original campaign additionally retains
client native before/after counters and per-History-row `client_import` and
`client_confirmation` timing. The import interval includes ordinary complete-page
activation; confirmation is timed separately. Timing uses monotonic wall time
and the calling thread's CPU, excludes scoped worker CPU, and records unavailable
CPU as null. Retention is bounded by the unchanged 64 History-call cap. The
before/after snapshots exclude setup and final post-service readback. None of
these observations changes budget credit, paging, readiness or acceptance.
The client calls remain synchronous at their original cancellation boundaries;
timing does not introduce an interruption mechanism. A late return still fails
the original final 30-second gate.

The original 1,024 signed seed transfers, four seed blocks, 21 business blocks,
three 30-second windows, 0/24/24 attackers, two workers, 2 CPU-second burst,
0.25 CPU-second/second refill and 100 ms start reservation must run again on the
exact successor. Local seven-page import, foreign SQL/root, cancellation,
rollback, reorganization and reopen controls qualify the implementation path;
they cannot supply the missing third timely confirmation or hostile liveness.

    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib native_inactive_ -- --test-threads=1

## PN1–PN5 frozen performance and product campaign

This is the measurement contract for the 2026-10-20
[sole-plan amendment](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
not a new run. PR #323 source `9bd8b20da68f0dc199aab78c27644ed004af7411`
still needs the original-budget campaign described above. Source494's 0/3
rounds and df6's 2/3 baseline and 0/3 hostile results remain failures of their
original gates. Source390's finite successful pipeline and its faster censored
work-budget failure are separate observations, not sustainable public capacity.

Freeze the following before each campaign; changing a value creates a new
experiment and cannot turn an old timeout into success:

| Campaign | Required independent variables | Exit measurement |
| --- | --- | --- |
| PN1 work/service | Exact target/task/source/hardware, setup horizon, failed attempts, cache state, shared CPU/worker/byte budgets, attacker and honest offered load | Full producer/invalid-verifier costs and effective-work assumptions separately from client-confirmed honest completion; original three-mode gate in the plan remains unchanged. |
| PN2 state/history | Permanent accounts A, all touched accounts W, working keys, mandatory/range/proof bytes, retained history, backend, disk/WAL budget | Signed admission beyond 65,536, declared packet/resource limits, fixed-W scaling, full-path confirmation and cold sync/recovery. Distinguish retained bytes from hot-path complexity. |
| PN3 Hepta learning | Actual parent/candidate/control bytes, independent source/time/exposure, sample/power rule, minimum gain/safety/retention and equal total budgets | Actual installed-model readback and untouched follow-up outcomes, with no-update and failed cycles retained; mechanical loop and learned benefit are separate verdicts. |
| PN3/PN5 Cell | Complete release closure, Cell/base sizes, active set, cold/warm cache, providers, bandwidth/loss, discovery/retry and loader budgets | Complete verified release-to-real-inference latency, peak SSD/RAM/device memory, all requested releases, unavailable/malformed outcomes and replica repair costs. Transfer rate alone is not loading capacity. |
| PN4 serving/storage | Actual sponsored resources/funding, offered service, storage byte-time, retention/repair duties and depletion policy | Authorized completed service / all offered authorized service, conservation, repair backlog and actual billed units. Token count is not GPU or disk capacity. |
| PN5 WAN/recovery | At least three independent operators, 72-hour minimum, frozen attack/fault schedule, load, confirmation and repair policy | Per-cohort thresholds including hostile completion, tails, stale/fork rate, state/model availability, restart/power loss and new-node/deep-reorg recovery. No aggregate masks a failed cohort. |

Retain the six distinct plan metrics: unique confirmed transaction TPS;
proof-verification/state-commit rates; candidate-to-install p50/p95/p99;
installed and subsequently qualified updates; honest completion during attack;
and loss/reorg/restart/new-node cost. Every report names its original attempt
population, counts/fraction of timeout, Busy, invalid, unknown, withdrawn and
reorged outcomes, observation interval, confirmation drain and tail sample
requirements. Failed candidates and repeat polls cannot vanish from denominators
or count as extra successful updates. A no-update decision may pass safe behavior
while contributing zero to the improvement count.

Measure an enclosing operation plus nested costs: decode/admission, work/task
acquisition, state reconstruction, account/range proof, execution, root/history
checks, lock/SQL wait, persistence, network, client import and confirmation.
Nested timings are not additive totals. Actual scoped worker CPU must be joined
or declared missing; thread CPU is not process CPU. Preserve mandatory cancellation
and final-root fences. Report true wall/CPU/RSS/disk separately from software
retention charges; a smaller arithmetic cache count is not a process-memory bound.

Concurrency and DAG experiments follow joint work/storage repair. Use the same
profile, state/history, workload, availability, hardware and total resource budget
for serial/concurrent/reference-DAG paths. Measure the complete confirmation and
recovery path, including unavailable data and stale work. The current reference
transport DAG does not implement GHAST/GHOSTDAG/Prism ordering or inherit their
security. Select a consensus successor only after a measured propagation/fork
bottleneck and an explicit new ordering/state/reward/reorg contract justify it.

### R13 replay/cancellation evidence is additional

R13 limits same-complete-packet priority reacquisition only within one live CPU
owner, using 4,096 monotonic exact identities with no eviction. Capacity full
disables extra promotion, not ordinary verification/recovery. An actual restart
begins a new zero-credit identity epoch; no permanent work-spent or general
valid-W1 fairness guarantee follows. The receiver reports this capacity, actual
marker/counter observations and epoch scope separately from its unchanged CPU
flow identity. Historical r12 phases retain their own resource digest and
derivation without synthetic r13 fields.

Focused controls must exercise a genuinely verified W1 packet with a failing
native root, concurrent claims, full-capacity ordinary admission, Unknown and
cancellation retention, plus cancellation after actual durable reorganization
progress and exact retry of signed transfer deltas. These do not replace the
original native campaign or close its throughput acceptance by themselves.
Every original attack count, two-second client deadline, CPU/RAM setting,
confirmation denominator and genuine depletion condition remains unchanged.
Deep roots and individual SQLite operations remain cooperative observation
intervals rather than hard CPU preemption; all observed overruns remain paid.
