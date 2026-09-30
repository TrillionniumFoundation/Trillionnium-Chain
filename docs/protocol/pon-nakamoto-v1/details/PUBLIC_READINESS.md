# Current development entrypoints and public qualification gates

This is the acceptance contract for the six audit findings. The sole engineering
sequence remains the [development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
All public/production acceptance flags remain false. Implemented development controls
and controlled measurements are independently useful; they cannot substitute for the
missing work-security or real model-benefit claims.

## Applicable profiles and exact interfaces

| Interface | Explicit selection | Current behavior and limits |
|---|---|---|
| historical task registration | `--task-profile legacy-task-v1` (default) | twelve original PNX1 commands; tag12 records a nonzero task commitment; original golden bytes/roots remain applicable |
| signed task development context | `--task-profile signed-task-dev-v1` | distinct revision5 genesis/network/parameters; tag13 is652 signed payload bytes; rejects historical tag12 and implicit maintenance; finite16 genesis demand records and public development source key |
| renewable task development context | `--task-profile signed-task-lifecycle-dev-v2` | distinct revision7 namespace; tags18/19 open/renew344-byte leases, tag20 revokes144 bytes, tag21 registers684-byte statements;32 bounded slots, optimistic revision, monotonic generation and one-output meter preserved on renewal |
| atomic renewable task development context | `--task-profile signed-task-lifecycle-dev-v3` | distinct revision8 namespace; [atomic successor](QUALIFIED_TASK_LIFECYCLE_V3.md) tag22 couples requester renewal and exact source signature in1028 payload bytes; standalone tag19 refuses; legacy V2 is unchanged |
| native evaluation development context | `--evaluation-policy native-public-evaluation-dev-v1` | tags14/15 commit/reveal,16 signed conflict evidence,17 bounded record-only appeal;128-height frozen rounds, mandatory close and positive conflict-free adoption guard |
| real small-model development family | `--model-profile smollm2-135m-cpu-dev-v1` with native evaluation | frozen135M decoder/tokenizer and rank4 adapter interface; distinct family/chain parameters and2MiB candidate limit; actual external CPU observations do not grant native authenticated ML execution or quality acceptance |
| full task material mining | `mine` / `make` with `--task-manifest`, `--task-model`, `--task-input` | exact source statement, independently pinned genesis demand context, model/input derivation, parent registration and signed height window; no self-registration by its own work block |
| explicit bootstrap | `mine` / `make --task-bootstrap` | exact genesis maintenance statement/material; zero useful-output credit; expires at height1000 |
| manifest fixture generation | `task-fixture` plus model/input, demand index, purpose, source nonce and height window | reproducible public-key fixture; no genuine demand, exclusive custody, legal consent or production DA certificate |
| historical ingress | `--admission-profile legacy-development` (default) | unchanged development listener; no admission-work claim |
| public development ingress/client | `serve` / `push` / `head` / `history` / `sync --admission-profile public-protected-development-v2` | [separate versioned public intake](PUBLIC_INTAKE_V2.md); guest resource tickets for all operations, no allowlist or durable guest authority, independent full packet verification on sync; explicit `--public-development-network` required for serve |
| protected ingress/client | `serve` / `push --admission-profile connection-work-v1` | hello/ready before Submit body, exact-wire challenge and single connection-local solution; strict clients refuse downgrade before exposing Submit; ordinary read-only requests retain their bounded path |

Protected `serve` additionally accepts `--admission-bits`8..20 and
`--admission-ttl-ms`100..2000. Default16 bits/2000ms is a development experiment,
not an accepted public attacker budget. The client search cap and timeout can reject an
honest request at excessive difficulty; record that failure. Non-loopback legacy and connection-work-v1 development
listeners require signed allowlisted authentication. The explicit public-v2 successor
accepts unknown transport keys with per-operation resource tickets; its bounded
resources are not public service or work-hardness qualification. A puzzle changes neither the
work relation, block validity, chainwork, reward nor confirmation policy. Its parameters
are transport-profile committed, separately from the chain context.

The connection-work-v1 protected development listener has two proof-capable socket workers and one
reserved read-only worker. Initial frame and Hello/body reads share a100ms absolute
budget; the reserved worker refuses proof Hello traffic before accepting a body.
After such a refusal it yields for2ms to reduce accept competition with proof workers;
this bounded delay does not guarantee fair scheduling.
The client allows at most256 Busy retries within one5-second deadline and searches
at most1,048,576 puzzle nonces per challenge. These finite bounds and the retained
read-only service test do not guarantee public service under arbitrary occupancy.
Untrusted protected parse/auth/preface refusals have at most128 Unicode characters
and a100ms absolute response budget, also committed by the transport profile.

Authoritative implementations are `trnm-pon-node/src/main.rs`, `src/ingress.rs`,
`src/ingress/public_v2.rs`, `src/store.rs`, `trnm-mvcc-fee/src/pon_executor.rs` and the strict
[qualified-task codec and admission](QUALIFIED_WORK_TASK.md). The namespace owner
refuses a mismatched genesis/schema; no stored signature or historical state is reinterpreted.
PNH1 remains318 bytes and the work transcript remains49188 bytes. The source statement
does not by itself make a cost class scientifically qualified.
Validators independently bind the actual PNW1 operand bytes to the signed model and
input hashes before expensive transcript verification; this requirement also applies
to manually constructed packets that bypass the ordinary mining entrypoint.

The bootstrap expires at height1000. A valid successor must already be registered in
parent state before that expiry. Unused fixed demand records can admit later windows,
but neither a used demand nor the same matrix task can be renewed through tag13.
The16-record testing context therefore has a finite lifecycle and cannot promise
indefinite production liveness. The explicit [lifecycle successor](QUALIFIED_TASK_LIFECYCLE_V2.md)
adds native lease open/renew/revoke, retained source sequences and generation-safe slot
recycling. V2 standalone renewal can invalidate the sole task statement and stop mining;
its paired local transactions do not guarantee consensus atomicity. The explicit
[atomic V3 successor](QUALIFIED_TASK_LIFECYCLE_V3.md) uses one tag22 and refuses
standalone tag19. Actual Node tests exercise renewal, revoke, reopen and heavier-fork replacement.
It still requires genuine authorized requesters, available materials, timely renewal and
an accepted work-cost class. Public development keys provide none of those owner attestations.

## Six gates and their evidence requirements

| Priority / gate | Executable progress | Required before public acceptance |
|---|---|---|
| P0 hostile public proof intake | versioned transport challenge; complete rejection remains; strict downgrade, replay, expiry and mixed real-socket tests | calibrated adversarial CPU/GPU/hash budget; paid/unpaid attacks; identity rotation; bandwidth/connection exhaustion; realistic valid/invalid mixes; honest waiting time and service success under sustained attack; independent deployment |
| P0 qualified neural tasks | exact material-bound source statement; native renewable/revocable leases; parent eligibility, retained sequences, generation-safe recycling and one-output meters | genuinely admitted task owners; sustainable maintenance/renewal policy; DA/retention funding; cheapest valid instance and structural shortcuts; cross-challenge preprocessing/reuse analysis; independent cheapest-miner bound |
| P1 public evaluation/reward | frozen native commit/reveal rounds and all-eligible minimum; mandatory timeout abort; strict signed conflict evidence, next-round key exclusions, bounded archived appeals and funded release/claim gating | public roster governance and independent evaluator ownership; confirmed-chain phase observation policy; withheld/low-score/cartel incentives; objective ML fraud versus subjective quality disagreement; funded appeal adjudication and sanctions for past paid rewards |
| P1 target model attribution | exact integer BA equivalence/common-root budgets; pinned135M decoder/rank4 LoRA CPU execution with all four strong controls; native zero-gain no-adoption/no-reward experiment | independent future tasks; prospective registration; reproducible positive efficacy; poisoning/backdoor/forgetting, functional-copy handling and inference/memory costs; no general circuit-optimum claim |
| P1 useful-work efficiency | arithmetic output meter counts fixed AB once; branch-relative adopted-output observer records explicitly supplied attempt and validator costs | real downstream use receipts; count duplicate, failed, stale/orphan work and every verifier; include training/load/retention/DA costs; report accepted unique benefit per aggregate resource budget |
| P1 sustained end-to-end capacity | continuous durable TCP pipeline plus [separate producer/validator/full-sync confirmer processes](DISTRIBUTED_PIPELINE.md), signed receipts and matching independently verified state | physical-host LAN measurements; long steady-state campaigns, state/history scaling, tail confidence, mixed commands/conflicts, queued transaction RPC/mempool, attack availability, WAN independent nodes and measured deployment GPU/VRAM |

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

The development status remains a candidate. Independent reviewers, genuine prospective
tasks, deployment resources and cryptographic hardness evidence must be supplied by
their actual owners; source code and local subprocesses cannot fabricate those facts.
