# Current development entrypoints and public qualification gates

This is the acceptance contract for the six audit findings. The sole engineering
sequence remains the [development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
All public/production acceptance flags remain false. Implemented development controls
and controlled measurements are independently useful; they cannot substitute for the
missing work-security or real model-benefit claims. These gates govern acceptance;
the CLI can still run an explicitly selected public-development listener with
`--development` and `--public-development-network` at the operator's `--listen` address.
This document adds no automatic firewall or acceptance-gate listener prohibition.

## Applicable profiles and exact interfaces

| Interface | Explicit selection | Current behavior and limits |
|---|---|---|
| historical task registration | `--task-profile legacy-task-v1` (default) | twelve original PNX1 commands; tag12 records a nonzero task commitment; original golden bytes/roots remain applicable |
| signed task development context | `--task-profile signed-task-dev-v1` | distinct revision5 genesis/network/parameters; tag13 is652 signed payload bytes; rejects historical tag12 and implicit maintenance; finite16 genesis demand records and public development source key |
| renewable task development context | `--task-profile signed-task-lifecycle-dev-v2` | distinct revision7 namespace; tags18/19 open/renew344-byte leases, tag20 revokes144 bytes, tag21 registers684-byte statements;32 bounded slots, optimistic revision, monotonic generation and one-output meter preserved on renewal |
| atomic renewable task development context | `--task-profile signed-task-lifecycle-dev-v3` | distinct revision8 namespace; [atomic successor](QUALIFIED_TASK_LIFECYCLE_V3.md) tag22 couples requester renewal and exact source signature in1028 payload bytes; standalone tag19 refuses; legacy V2 is unchanged |
| overlap renewable task development context | `--task-profile signed-task-lifecycle-dev-v4` | distinct revision9 namespace; [V4 atomic22](QUALIFIED_TASK_LIFECYCLE_V4.md) retains1028 bytes and refuses19, permits a source-signed successor whose window has begun to be included while the old lease remains valid; no automatic renewal or source signing |
| checkpoint tile maintenance development context | effective `signed-checkpoint-tile-maintenance-dev-v1` task profile, installed only through `--actor-profile native-operator-checkpoint-tile-dev-v1` | [revision10 selector](CHECKPOINT_TILE_TASK_V1.md) commits the exact source/material policy in fresh N/P/G; Settings construction and every Node open replay complete checkpoint/activation/A/B materials; only Maintenance/output0, with original parent/source/renewal checks |
| consensus maintenance continuity development context | `--task-profile consensus-maintenance-continuity-dev-v1` | [revision12 continuity](CONTINUITY_V1.md) commits a separate immutable genesis maintenance record and the V4 optional-task policy; reserves mandatory state-key liabilities; maintenance has zero useful-output credit and requires explicit selection; task availability does not establish hardness or unlimited new-account admission |
| checkpoint tile operator context | `--actor-profile native-operator-checkpoint-tile-dev-v1` plus the deployment specification/bootstrap/model/input/checkpoint/activation options | [bound material deployment](CHECKPOINT_TILE_TASK_V1.md) requires exact offline source/requester approvals and explicit mining identity; old profiles and approvals refuse this context; no full-model forward, genuine demand or hardness acceptance |
| operator actor development context | `--actor-profile native-operator-actors-dev-v1` plus `--deployment-spec`, `--deployment-bootstrap`, `--deployment-model`, `--deployment-input` | [public descriptor and approvals](OPERATOR_ACTORS_V1.md) bind fresh N/P/G and role/material pins; runtime reads public inputs, actor mining requires explicit `--miner`, and genesis/profile overrides and implicit DEV task fixtures refuse; key possession does not establish independent governance or truthful demand |
| native evaluation development context | `--evaluation-policy native-public-evaluation-dev-v1` | tags14/15 commit/reveal,16 signed conflict evidence,17 bounded record-only appeal;128-height frozen rounds, mandatory close and positive conflict-free adoption guard |
| integer factor development family | `--model-profile linear-factor-witness-dev-v2` with native evaluation and legacy tasks | [revision11/tag23](NATIVE_INTEGER_FACTOR_CANDIDATE_V2.md): complete current ILM2 model, full bounded BA recomputation, cross-author same-parent/round/slot duplicate rejection and fresh N/P/G; historical tag6/model profiles refuse; no general function attribution, ML gain or public acceptance |
| native empirical evidence development family | `--model-profile linear-factor-evidence-dev-v3` with native evaluation and legacy or continuity tasks | [revision13 evidence](NATIVE_MODEL_EVIDENCE_V3.md): complete integer candidate/parent/four-control evaluation on25 public retrospective rows, reveal binding, known-source budgets and pre-adoption review hold; allocation membership does not derive the bundle or prove component causality |
| native composition development family | `--model-profile linear-factor-composition-dev-v4` with native evaluation and legacy or continuity tasks | [revision14 composition](NATIVE_MODEL_COMPOSITION_V4.md): exact2–4-component common-parent sum, zero-increment subset rejection, superiority to parent/controls/every component and positive recomputed leave-one-out weights; retains the25-row retrospective corpus, bounded ILF2 representation and funded claim/dust rules; no prospective efficacy or Shapley fairness acceptance |
| real small-model development family | `--model-profile smollm2-135m-cpu-dev-v1` with native evaluation | frozen135M decoder/tokenizer and rank4 adapter interface; distinct family/chain parameters and2MiB candidate limit; actual external CPU observations do not grant native authenticated ML execution or quality acceptance |
| full task material mining | `mine` / `make` with `--task-manifest`, `--task-model`, `--task-input` | exact source statement, independently pinned genesis demand context, model/input derivation, parent registration and signed height window; no self-registration by its own work block |
| explicit leased bootstrap | `mine` / `make --task-bootstrap` | exact signed development bootstrap statement/material; zero useful-output credit; the initial lease covers heights0..1000; renewable profiles require explicitly signed successor lease/source registration, with current parent material checked for mining |
| explicit consensus maintenance | `mine` / `make` / `mine-loop`, or public V3 `serve --mine`, with `--consensus-maintenance` and the continuity task profile | exact committed genesis materials need no lease or external source signature; all optional leases may expire or be revoked without removing this separate task; full PNW1 verification and ordinary parent/state/owner checks remain; no automatic switch from a rejected selected lease |
| manifest fixture generation | `task-fixture` plus model/input, demand index, purpose, source nonce and height window | reproducible public-key fixture; no genuine demand, exclusive custody, legal consent or production DA certificate |
| historical ingress | `--admission-profile legacy-development` (default) | unchanged development listener; no admission-work claim |
| public development ingress/client | `serve` / `push` / `head` / `history` / `sync --admission-profile public-protected-development-v2` | [separate versioned public intake](PUBLIC_INTAKE_V2.md); guest resource tickets for all operations, no allowlist or durable guest authority, independent full packet verification on sync; explicit `--public-development-network` required for serve |
| public development pool ingress/client | `serve` / `pool-push` / `pool-status-remote --admission-profile public-protected-development-v3` | [V3 transport/resource r9](PUBLIC_POOL_INTAKE_V3.md) retains Submit/Head/History and adds paid `pool_context`-bound PNX1 bundles1..16 plus read-only scalar pool status; `serve` requires `--public-development-network`, `--auth-secret` and fixed `--pool-policy`; its signed domains and pinned resource digest remain separate from V2; queue reservation is not inclusion/confirmation |
| local persistent pool | `pool-submit --transactions --pool-policy` / `pool-status` | [existing Node queue owner](LOCAL_MEMPOOL_LIFECYCLE.md) applies M05 typed checks and M06 prefix preview; [cache V2](LOCAL_MEMPOOL_CACHE_V2.md) bounds logical retained resources and evicts wholly expired/sequence-consumed groups on admission need, preserving explicit-removal tombstones; physical archive/WAL growth remains separate |
| finite continuous mining | `mine-loop --miner --pool-policy`, or public V3 `serve --mine --miner --pool-policy` | [wall-clock mining](CONTINUOUS_MINING_V1.md) selects exact queued groups and current parent task/source material under the same Node owner; attempts, runtime and block limits are finite; proof search releases the owner and rechecks parent/generation before native admission |
| operator-pinned peer following | public V3 `serve --peers`, optional `--peer-poll-ms` / `--peer-pages` | [bounded pinned polling](PINNED_PEER_POLLING.md) verifies the configured peer/context/history under the same owner; operator pins addresses and server keys, with no open discovery or independent-operator claim |
| protected ingress/client | `serve` / `push --admission-profile connection-work-v1` | hello/ready before Submit body, exact-wire challenge and single connection-local solution; strict clients refuse downgrade before exposing Submit; ordinary read-only requests retain their bounded path |
| complete finite evaluation observation | `evaluation-observe --candidate HEX --ancestry-blocks N` | [V1](EVALUATION_CONFIRMED_OBSERVATION_V1.md) checks the complete active ancestry to genesis, with N in1..4096; longer histories refuse rather than truncate |
| bounded evaluation round observation | `evaluation-round-observe --candidate HEX --round-blocks N` | [V2](EVALUATION_CONFIRMED_ROUND_OBSERVATION_V2.md) checks the actual round window, parent roots and index consistency at any chain height, with N in1..4096; its preceding base anchor and global confirmation/clock history are explicitly unevaluated |
| synchronized local evaluation observation | public V2/V3 `sync --evaluation-candidate HEX --evaluation-round-blocks N` | [same-owner observation](SYNC_EVALUATION_OBSERVATION_V1.md) runs only after complete native sync, with N in1..4096; partial sync has no phase result, and an observation refusal preserves the already completed sync fact |

The model13/14 selectors require `--evaluation-policy native-public-evaluation-dev-v1`
and accept only `legacy-task-v1` or `consensus-maintenance-continuity-dev-v1` as the
task selector. Combining continuity with either model retains both policies and
selects the higher consensus revision13 or14. These are fresh network, parameter,
genesis, model-family and evaluation-plan contexts. Existing PNH1/PNX1 framing,
transaction tags and `tx-sign` framing remain unchanged; the signed PNX1 network
field distinguishes the new context. Historical signatures and stores are not
reinterpreted. Continuity retains the exact V4 signed optional-task domains and
does not invent a signature or lease for its separate genesis maintenance record.
Model13 uses `model-evidence-v3:` / `model-source-v3:` state keys; model14 uses
`model-evidence-v4:` / `model-source-v4:` and fresh empirical, source/root-work and
composition record domains. The branch SQLite schema is unchanged; selecting a
successor is not an in-place store migration or an automatic profile upgrade.

Protected `serve` additionally accepts `--admission-bits`8..20 and
`--admission-ttl-ms`100..2000. Default16 bits/2000ms is a development experiment,
not an accepted public attacker budget. The client search cap and timeout can reject an
honest request at excessive difficulty; record that failure. Non-loopback legacy and connection-work-v1 development
listeners require signed allowlisted authentication. Explicit public-v2/v3 successors
accept unknown transport keys with per-operation resource tickets; their bounded
resources are not public service or work-hardness qualification. A puzzle changes neither the
work relation, block validity, chainwork, reward nor confirmation policy. Its parameters
are transport-profile committed, separately from the chain context.

The connection-work-v1 protected development listener has two proof-capable socket workers and one
reserved read-only worker. Initial frame and Hello/body reads share a100ms absolute
budget; the reserved worker transfers the exact proof Hello socket within an
at most2ms zero-capacity rendezvous opportunity and its original deadlines.
After such a refusal it yields for2ms to reduce accept competition with proof workers;
this bounded delay does not guarantee fair scheduling.
The client allows at most512 total Hello attempts and reconnects after Busy within one5-second deadline, and searches
at most1,048,576 puzzle nonces per challenge. These finite bounds and the retained
read-only service test do not guarantee public service under arbitrary occupancy.
Untrusted protected parse/auth/preface refusals have at most128 Unicode characters
and a100ms absolute response budget, also committed by the transport profile.

[Public V3 resource revision r9](PUBLIC_POOL_INTAKE_V3.md) independently reserves
read body/output/challenge budgets within its existing totals, limits paid grants
per operation lane, and cancels disconnected queued work between complete native
stages. Complete Hello and validated Solution requests wait in separate bounded
lane FIFOs before challenge/grant readiness, under their original deadlines;
waiting does not hold a grant or allocate the request body. The original connection,
worker, queue, byte and challenge limits remain unchanged. Its resource digest
changes explicitly, and historical resource revisions refuse. The retained 26/27 honest Submit
result in the short unpaid campaign belongs to `connection-work-v1`, not V3;
V3 component fixes do not close that separate observation or certify public service.
Revision r5 introduced the local mutation-thread CPU account retained by r9;
it reserves across caller identities and charges actual dispatch once. Debt/unavailable accounting prevents further
starts while already completed native outcomes are preserved. Two existing
nonpreemptive mutation calls may overshoot; read latency and physical host CPU
are not hard-bounded by this account.
Revision r8 includes actual scoped M06 worker intervals in the same request debit;
the dispatch observer remains its single outer-thread interval. Missing worker
clocks disable future mutation starts without rewriting durable results.

Revision r9 additionally debits same-thread owner and actual scoped-worker CPU
increments during those progress observations. Final settlement charges only the
remaining portion of the original O+C intervals; W stays nested in O. Local debt
cancels cooperative continuation, and unknown measurements disable future mutation
starts. The explicit controlled Pool path propagates cancellation through every
complete prefix without treating it as a Blocked relation; uncommitted rows roll
back and already committed reconciliation or native success remains true.
No accounting mutex spans native math, joins or SQLite. The reserve/refill/capacity
numbers are unchanged, and deep operations may overshoot before another checkpoint.
Current r9 source still requires its own actual captures and complete qualification.

Current r9 also observes the original deadline/cancellation during bounded M05
replay and M06 envelope/canonical-apply/precommit boundaries. Individual
signatures, deep State/root/history and SQLite calls remain nonpreemptive;
uncommitted changes roll back and committed native facts remain true. These are current source contracts, not a rerun or
relabeling of historical r5/r6/r7/r8 measurements or a public fairness qualification.

An already admitted local packet can use [bounded Submit recovery](PUBLIC_SUBMIT_RECOVERY_V1.md)
with `push --reliable-submit --store EXISTING_LOCAL_PRODUCER`. The opt-in client
clips every RPC and retry to one absolute deadline, restores only a bounded path
of actual local parents, and requires authenticated history plus a stable pinned
head and complete local State/root checks before reporting dependency readiness.
Every failed attempt and uncertain outcome remains recorded. Dependency readiness
does not establish confirmation depth or remote durable persistence. Default push
behavior remains unchanged, and recovery does not supply receiver fairness.

Authoritative implementations are `trnm-pon-node/src/main.rs`, `src/ingress.rs`,
`src/ingress/public_v2.rs`, `src/ingress/public_v3.rs`, `src/store.rs`,
`src/store/mempool.rs`, `src/mining.rs`, `src/peer_polling.rs`, `src/operator_deployment.rs`,
`trnm-mvcc-fee/src/pon_executor.rs`, `src/continuity_v1.rs`,
`src/model_evidence_v3.rs`, `src/model_composition_v4.rs` and the strict
[qualified-task codec and admission](QUALIFIED_WORK_TASK.md). The namespace owner
refuses a mismatched genesis/schema; no stored signature or historical state is reinterpreted.
PNH1 remains318 bytes and the work transcript remains49188 bytes. The source statement
does not by itself make a cost class scientifically qualified.
For signed tasks, validators independently bind the actual PNW1 operand bytes to
the signed model and input hashes before expensive transcript verification; this
requirement also applies to manually constructed packets that bypass the ordinary
mining entrypoint. Explicit consensus maintenance instead binds the immutable
genesis record and exact matrix task; full PNW1 verification still checks its
actual operand bytes and complete transcript.

Height1000 is the end of the initial bootstrap lease, not a universal chain lifetime.
In `signed-task-dev-v1`, unused fixed demand records can admit later windows, but a
used demand or the same matrix task cannot be renewed through tag13; its16-record
context remains finite. [V2](QUALIFIED_TASK_LIFECYCLE_V2.md) separately adds native
lease open/renew/revoke, retained source sequences and generation-safe slot recycling.
V2 standalone19 can invalidate the sole task statement before21 is included; a local
bundle does not guarantee consensus atomicity. [V3](QUALIFIED_TASK_LIFECYCLE_V3.md)
and [V4](QUALIFIED_TASK_LIFECYCLE_V4.md) use one requester-signed22 carrying the exact
source signature and refuse19. V3 requires its exact containing height; V4 permits
inclusion during the signed overlap. A valid successor must be included while the old
lease remains eligible, so it is parent state for subsequent work; source signatures,
material, sequences and the output meter remain checked. Actual Node tests cover signed
renewal, revoke, reopen and heavier-fork replacement. No profile automatically signs
renewal or creates new demand. Missing material or expiry/revocation leaves the
selected leased task ineligible. An unwilling signer prevents a new signed
successor; it does not invalidate an existing signed window. Without another
eligible task, the leased-only profiles cannot continue mining. Operator actor
approvals establish signed bootstrap possession and bindings, not genuine demand,
independent owners or an accepted work-cost class.

The separately selected [revision12 continuity task policy](CONTINUITY_V1.md),
including its combinations with model13/14, retains an immutable maintenance task
when all optional leases are ineligible. The operator must choose that exact task
explicitly; a failed leased-task selection remains a failure. Maintenance grants
zero useful-output credit and requires neither automatic renewal nor a new source
signature. Owner-side operation grants and withdrawal fences still apply. Its
capacity invariant preserves an existing-account empty successor with mandatory
rewards/refunds/archives; permanent accounts can still exhaust new-account capacity.
These are availability and state-liability rules, not computational qualification,
genuine useful demand or public network acceptance.

The [independent model composition comparison](NATIVE_MODEL_COMPOSITION_V4.md#independent-arithmetic-and-observed-state-comparison)
recomputes complete ILM2 arithmetic, parent-relative derivation, required zero
subsets, leave-one-out counts, complete empirical/composition record bytes,
allocation roots, source reservations, payouts and dust from actual native
observations. It requires a fresh run-bound set of thirteen observation files,
including42 named arithmetic boundaries; missing observations fail. It does not
independently establish M05 signatures, evaluator roster closure, the ILF2 factor
witness or every ledger transition. Independent implementation agreement on the
fixed25 public rows does not prove training causality, future efficacy, concealed
source independence or fair attribution. Current-source native execution and
external acceptance each still require their own evidence.

## Six gates and their evidence requirements

| Priority / gate | Executable progress | Required before public acceptance |
|---|---|---|
| P0 hostile public proof intake | versioned transport challenge; complete rejection remains; strict downgrade, replay, expiry and mixed real-socket tests; V2 r2 and V3 r9 retain resource reserves and cooperative disconnect fences; V3 r9 retains bounded pre-ready lane FIFOs, paid grant lifetime, bounded same-connection enqueue, actual owner/scoped-worker CPU debits and M05/M06 cancellation boundaries; protected original-deadline rendezvous; optional bounded Submit dependency recovery | calibrated adversarial CPU/GPU/hash budget; paid/unpaid attacks; identity rotation; bandwidth/connection exhaustion; realistic valid/invalid mixes; honest waiting time and service success under sustained attack; independent deployment; deep native stages remain nonpreemptive |
| P0 qualified neural tasks | exact material-bound source statement; native renewable/revocable leases; parent eligibility, retained sequences, generation-safe recycling and one-output meters; independent [full checkpoint to A/B replay](CHECKPOINT_TILE_MATERIAL_V1.md) and the fresh [revision10 source/material selector](CHECKPOINT_TILE_TASK_V1.md) restricted to Maintenance/output0; separate [revision12 genesis maintenance](CONTINUITY_V1.md) remains available without lease renewal and grants zero useful-output credit | genuinely admitted task owners; computationally qualified maintenance and leased tasks; sustained signer/renewal operation where leases are selected; DA/retention funding; cheapest valid instance and structural shortcuts; cross-challenge preprocessing/reuse analysis; independent cheapest-miner bound |
| P1 public evaluation/reward | frozen native commit/reveal rounds and all-eligible minimum; mandatory timeout abort; strict signed conflict evidence, next-round key exclusions, bounded archived appeals and funded release/claim gating; explicit revision13/14 native empirical reveal binding, source budgets and pre-adoption review hold; local typed [complete-history V1](EVALUATION_CONFIRMED_OBSERVATION_V1.md) and [bounded-round V2](EVALUATION_CONFIRMED_ROUND_OBSERVATION_V2.md) observers/CLI, with [same-owner public sync consumption](SYNC_EVALUATION_OBSERVATION_V1.md) | public roster governance and independent evaluator ownership; application durable operation IDs and external-effect reorg/retirement policy where confirmed observations are used; withheld/low-score/cartel incentives; objective ML fraud versus subjective quality disagreement; funded appeal adjudication and sanctions for past paid rewards |
| P1 target model attribution | exact bounded integer BA and revision11 full-parent admission; revision13 native empirical scoring and known-source budgets; revision14 exact composition and measured leave-one-out allocation, with the scoped independent arithmetic/record comparison above; separate pinned135M decoder/rank4 LoRA CPU observations with four strong controls; failed and zero-gain results remain retained | independent future tasks; prospective registration; reproducible positive efficacy; poisoning/backdoor/forgetting, functional-copy and concealed-controller handling; inference/memory costs; general model and allocation fairness remain unaccepted |
| P1 useful-work efficiency | arithmetic output meter counts fixed AB once; branch-relative adopted-output observer records explicitly supplied attempt and validator costs | real downstream use receipts; count duplicate, failed, stale/orphan work and every verifier; include training/load/retention/DA costs; report accepted unique benefit per aggregate resource budget |
| P1 sustained end-to-end capacity | durable TCP pipeline and [separate processes](DISTRIBUTED_PIPELINE.md); explicitly selected native pool/public V3 queue intake, finite wall-clock miner and pinned peer following share one Node owner | measured queued-transaction latency and saturation; long steady-state campaigns, state/history scaling, tail confidence, mixed commands/conflicts, attack availability, WAN independent nodes and measured deployment GPU/VRAM |

No table row grants a source an independent identity, proves neural work unavoidable,
or turns an empirical fixed-dataset optimum into a general model/circuit optimum.
The public reward owner and native evaluation lifecycle remain separate from
Nakamoto fork choice. Missing scores explicitly abort the bounded evaluation outcome
with no recommended adoption/reward; an appeal cannot rewrite a closed round.

## Attack budget and measurement contract

Every attack run must freeze source, binary, chain and transport profiles; CPU/GPU and
memory; network topology/bandwidth; connection count; attacker duration; hash trials and
measured hash rate; signing identities and rotation; paid/unpaid split; valid/invalid
proof ratio; parent age/target distribution; request size and honest arrival schedule.
Honest success uses all attempted requests as denominator, including Busy/timeouts;
latency reports include waits, retries and failures. A finite closed roster does not
bound the number of identities in a public network. A low-difficulty historical parent
does not automatically become an invalid block; transport costs must not silently
change consensus fork validity.

The proposed qualification matrix includes low/high invalid mixes, unpaid and paid
false transcripts, legitimate historical forks, connection occupancy, equivocation,
task expiry/revocation and recovery traffic while honest work continues. Numerical
service thresholds must be registered with a measured deployment and attacker budget
before the run. Choosing them after observing success is not acceptance. Monotonic
elapsed durations are not CPU cycles or a universal hardware lower bound.

## Continuous pipeline and reproducibility

`cargo run --offline --locked --release --manifest-path trillionnium/Cargo.toml
-p trnm-pon-node --example continuous_pipeline -- NEW_DIRECTORY BLOCKS TX_PER_BLOCK
PACE_MS hot|disjoint4|growth legacy|protected` uses two durable owners and a real TCP
listener. It records construction/signing, execution/mining, producer verification/store,
activation, socket admission/verification/store/activation, membership, confirmed
observation, bytes, state growth and final disk size. Work attempts and empty confirmation
drain blocks are retained. Queries independently check transaction membership and the
installed depth/work policy; they never claim finality or execution authority.
Ledger-only disk counters cover the two durable database directories. Separate whole-run
counters include raw packets and measurement files; they must not be called ledger growth.
The transfer builder reads each sender nonce once per block. Its eager lookup predecessor
reloaded the full authenticated state for every transfer; the retained observation documents
that caller bottleneck. Remaining full-state persistence and query costs still require scale tests.

The sustained socket measurement uses `transport-admission-sustained-cost-v2`.
`request_template_bytes` describes one fixed request body, while separate counters record
successfully written attacker bodies and writes whose outcome is unknown. These are
body-write observations, not total link bandwidth including handshake and responses.

The [finite saved V3 service campaign](PUBLIC_V3_SERVICE_CAMPAIGN.md) adds 130
actual mixed calls over two server/owner epochs, including paid false-transcript
W1 and malformed-packet load, a real persistent-owner reopen, complete
failed-call records and a recomputed honest Head completion gap that includes
restart downtime. The header-bound forged tickets reach actual full W1
transcript rejection, checked against signed responses and server work counts.
It uses the current V3 policy and records local development target outcomes
without granting public or independent acceptance.

The workload is exactly signed transfer tag1. Four funded senders are available; hot
uses one sender/receiver, disjoint4 uses four, and growth introduces new receiver keys.
These are explicit conflicts within a dedicated command chain, not general-contract TPS.
`PACE_MS<1000` uses historical logical timestamps and is labelled logical pacing. Public
qualification requires live wall-clock measurements. Percentiles describe observed block
samples: fewer than20 gives no p95, fewer than100 gives no p99. These are resolution floors,
not independent-sample or confidence guarantees; blocks on the same chain/host can be
correlated. Transactions in one block do not inflate the block sample count. The program has no transaction-only
RPC/mempool stage; that latency is null. No GPU is used by this CPU chain workload;
deployment model-inference GPU/VRAM qualification remains absent. The separate CPU
SmolLM2 pilot reloads actual frozen weights and all five candidate/control artifacts;
its tiny same-operator fixture produces no gain over the strongest control. Its native
bridge binds raw candidate bytes and the original external observation to a fresh chain
context and exercises zero-score closure, adoption/reward refusal and durable reopen.
It does not rebrand the original observation as authenticated native ML execution.

`scripts/run_public_readiness_qualification.py` prepares exact declared implementation
and corpus Git objects, verifies negative source/evidence tests, executes the full existing
native/reference regression and then the new attack, task, attribution/lifecycle and
live pipeline campaigns from clean committed source. Failures and raw logs are retained.
It hashes its source and binary, records actual tool/runtime versions and produces no
public acceptance. Earlier packages remain immutable and are checked against their
original source. Documentation publication alone never reruns a historical measurement.

The qualification owners record the actual child exit and timeout even when GNU time
does not emit a resource summary. Missing, empty, unreadable or malformed usage records
leave peak RSS null; an unavailable observation is never converted to zero or success.
The [runtime controls](../../../../scripts/test_qualification_runtime.py) exercise both
owners with actual successful, failing and process-group-terminated local children.
They do not replace the complete qualification or change its command matrix, timeouts
or rejection conditions. The [test-profile cost boundary](TEST_PROFILE_COST_BOUNDARY.md)
records the SHA2, protocol and MVCC test-package optimization settings, with debug
assertions and overflow checks explicitly enabled in
[Cargo profiles](../../../../trillionnium/Cargo.toml). Every original test instance and
assertion remains required. A test build setting supplies no production throughput,
work-hardness, model-quality or public availability evidence.

The development status remains a candidate. Independent reviewers, genuine prospective
tasks, deployment resources and cryptographic hardness evidence must be supplied by
their actual owners; source code and local subprocesses cannot fabricate those facts.
