# Trillionnium Chain Development Plan — PoN / Hepta-PoH revision

Plan ID: `trnm-chain-development-plan-v2` (stable registry identity; content revision 3).
Effective: 2026-09-28; applicability clarification: 2026-09-29. Status: selected development direction; no runtime activation.
Canonical destination: `refs/heads/main`; continuation uses the current main lineage, not retired PR #194.
Current source/head/tree/base and prospective merge are derived at verification time.
Assessed legacy baseline: `c552c31c6d3c5ac47522a124e02c6b8bca4e23f2`, tree
`c37858e60146147eccf1a6fec6eff04d00a828a7`; this is provenance, not a live-head claim.

Machine implementation truth: [consensus-mainline.json](../../config/consensus-mainline.json).
Selected protocol and transition: [pon-nakamoto-v1.json](../../config/pon-nakamoto-v1.json).
Technical contract: [PoN specification](../protocol/pon-nakamoto-v1/README.md).
Module index: [M00-M17](../modules/README.md); [source registry](module-registry-v1.toml);
[source inventory](../../config/portability-inventory-v1.json); [release train](release-train-v1.toml);
[manifest](plan-manifest-v1.toml); [snapshot](CURRENT_SNAPSHOT_V1.json);
[applicability](../architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md).

## 0. One authority and explicit retirement

This is the one active engineering plan. It owns sequence, work boundaries and integration
policy; the protocol suite owns domain rules and the module guides own implementation
contracts. There is no parallel PoCO completion roadmap or separate Hepta blockchain.
Git history is the archive. The development directory retains one regular Markdown plan
and small machine-readable companions, not historical symlinks or dated parallel plans.

The user's revised consensus decision supersedes the earlier keep-BFT proposal:
PoCO-BFT is RETIRED AS DEVELOPMENT TARGET. PoN is a Nakamoto-style useful neural-work
chain: permissionless work competition, target/difficulty, independent block validation,
cumulative verified work, forks and probabilistic confirmations. Consumption-weighted
validators, stake/evaluator-vote fork choice, QC/TC locking, three-chain finality and
joint validator epochs do not belong in the new consensus profile.

Retired consensus code, binaries, protocol files, fixtures and legacy appendices are
now deleted from the active tree. Only explicitly inventoried portable components remain.
History is available from Git, not an active compatibility directory. No legacy runtime,
proof decoder or fallback remains in the workspace. Portable local monotonic stores do
not grant PoN branch/undo semantics. The later native development Node owns its own
explicit branch namespace and cannot silently import those portable stores.

No machine flag is promoted. The current implementation projection is:

    stage = invariant-driven-native-application-candidate
    production_candidate = false
    production_consensus_activation = false
    public_testnet_ready = false
    release_ready = false

New PoN implementation, work-profile qualification, cryptographic security, public-model
efficacy and activation are also false. Source work and documentation may proceed now;
release requires their own real evidence, not completion of the retired PoCO roadmap.

### Current native development contracts

The [checked applicability registry](../../config/pon/applicability-v1.json) and
[canonical procedure/profile table](../architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md#current-applicability-and-evidence-classes)
separate current source bindings from local execution, historical receipts, hosted-head
checks, prospective-merge checks and external acceptance. This plan records no current
PR pass: derive exact candidate/base/merge identities and retrieve their actual CI results.

#### Current four-priority development scope

These changes continue this plan and its existing module owners; no acceptance axis
is promoted by implementation or by adding a diagnostic checker.

1. **Applicability and evidence consistency:** the checked registry above joins all
   module documents, actual source owners, controlled entrypoints and test selectors.
   M05 explicit reconciliation and M06 native execution/deltas are mapped to the Node
   owner; the39 responsibilities also bind revision11 factor admission and public V3
   resource-r3 to their exact source/tests, without granting execution evidence.
   Historical receipts and exact current delivery checks remain separate.
2. **Work security diagnostics:** the [proposed local diagnostic profile](../../config/pon/work-security-acceptance-v1.json)
   and [work report contract](../protocol/pon-nakamoto-v1/details/WORK_PROFILE.md)
   bind cost classes, setup amortization, rejection amplification and scoped hostile
   service observations. Its thresholds are proposed screening policy, not
   preregistered scientific acceptance, consensus parameters or a hardness proof.
3. **Conservative execution/resource improvements:** the [local pool contract](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_LIFECYCLE.md)
   reuses one checked actual parent within a pool operation while preserving full
   growing-prefix execution, nonce/signature checks and operation-boundary rereads.
   [Derived commitment](../protocol/pon-nakamoto-v1/details/DERIVED_STATE_COMMITMENT.md)
   changes retain complete-root authority and bounded fallback. These changes do
   not claim incremental prefix execution, SQL isolation or measured endpoint TPS.
   The [sync evaluation fixture](../protocol/pon-nakamoto-v1/details/SYNC_EVALUATION_OBSERVATION_V1.md)
   now checks explicit64+64+64+49 page-budget resume over all241 retirement successors,
   with separate original120-second listeners and durable ancestry/cursor assertions.
   It preserves the prior single-transfer timeout, and does not certify uninterrupted
   delivery within one lease or inherit old fixture/CI execution results.
4. **Model and operations evidence:** the [reported-acceptance sidecar](../protocol/pon-nakamoto-v1/details/MODEL_OPERATIONS_ACCEPTANCE_V1.md)
   joins a pinned run plan, strongest-control gain, adversarial probes, reported
   consumer uses and material/retention obligations. Supplied-record consistency
   does not prove future-task custody, consent, independent operation, real serving
   or physical retention; those external obligations remain unaccepted.

[Source-bound local observation package](../../evidence/pon-four-priority-audit-v1/README.md)
retains the measured `3c63c836` work-cost diagnostic (expected exit 2) and scoped
M06 preview timings; it promotes no acceptance or end-to-end throughput claim.

New local checker results apply only to the source and environment actually tested.
Full Rust qualification, exact committed-head/prospective-merge CI, physical-host
measurements and independent model/security acceptance require their own retained
observations; this section declares none of them passed. Earlier failed campaigns
and their source identities remain unchanged.

The following contracts describe the current candidate under M05/M06/M15 ownership.
Older evidence and historical sections below retain their original source and profile.
Their presence does not make an earlier absence claim the current API specification.

| Boundary | Current explicit contract | Remaining acceptance boundary |
| --- | --- | --- |
| Retained signed transactions | [Local pool](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_LIFECYCLE.md), [cache V2](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_CACHE_V2.md) | Logical cache bounds do not bound physical chain/SQLite/WAL growth or operator tombstone lifetime. |
| Continuous native work | [Wall-clock mining](../protocol/pon-nakamoto-v1/details/CONTINUOUS_MINING_V1.md) | Preparation, one transcript, native commit and diagnostic sinks remain nonpreemptive. |
| Parent task and execution state | [Operation-local actual parent](../modules/M06_EXECUTION_TECHNICAL_SPEC_V1.md) | One operation can reuse its first checked full parent read; new operations and admission re-entry still read actual state. The checked derived cache may retain up to the existing 65,536-key protocol limit under 8 MiB payload/512 MiB workspace-charge ceilings, with complete-root fallback when a selected cache budget is exceeded. Protocol overflow still rejects. This adds no authority cache, SQL isolation guarantee, throughput claim or work qualification. |
| Guest transaction intake | [Public V3](../protocol/pon-nakamoto-v1/details/PUBLIC_POOL_INTAKE_V3.md) | Resource tickets and separate read queues do not certify hostile-load fairness. |
| Protected proof transport | [Admission security](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md) | A zero-capacity Hello handoff preserves original deadlines and three socket workers. Its new explicit transport digest requires same-profile peers. A finite regression does not prove public scheduling or availability. |
| Atomic task renewal | [V3 exact inclusion](../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V3.md), [fresh V4 overlap](../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V4.md) | Source/requester signatures and actual task availability remain required; no automatic qualification or indefinite lease. |
| Long retained history | [Native ancestry index](../protocol/pon-nakamoto-v1/details/NATIVE_ANCESTRY_INDEX.md) | Local derived index integrity is not a remote ancestry certificate; receivers still verify full packets. |
| Explicit neighbor following | [Pinned peer polling](../protocol/pon-nakamoto-v1/details/PINNED_PEER_POLLING.md) | Paid Head/History and fixed cursors do not supply discovery, gossip, independent operators or eclipse resistance. |

Same-administrator Tailscale campaigns and task-owned delayed/interrupted TCP
proxies are simulation evidence. Record actual direct/DERP routes, every failed
attempt, native inclusion and stopped-store verification; do not promote independent
operators, prospective model tasks, computational hardness or public readiness from them.

The immutable `fefe235bdb25bd18a8b48876c2114448da0a4a86` near-limit
normal-load attempt requested 262 blocks of 250 transfers, followed by six drain
blocks, at 10-second live pacing. It failed with
`ADMISSION_BUSY_READ_ONLY_RESERVED` on the next submission after 116 completed
blocks: 29,000 transactions were accepted and 27,500 confirmed. The producer had
29,277 state keys and the validator 29,027; their heads differed. This was an actual
service failure before budget exhaustion, not a passed maximum-state acceptance.
The failed source predates the bounded repeated Hello handoff opportunities described
in the current admission contract. Those opportunities and larger optional derived-cache budgets require a
fresh committed-source rerun of that unchanged load and independent complete
reference replay. The earlier passed 16,411-key case remains scoped to its original
source. Reaching 65,536 keys, rejecting 65,537 without changing parent state, large
payload/workspace cases and hostile availability remain separate obligations.

## 1. Product mission: shared intelligence from real work

Every Hepta node can learn compatible small-model parameters from authorized real tasks.
It can publish a bounded parameter update, obtain independent out-of-node validation,
contribute to a reproducible shared model, and receive rewards for measured adopted
value. The public model is available without a model-use fee under its accepted public
policy; funded network resources provide a bounded free hosted-inference tier.

    real tasks -> local adaptation -> public parameter contribution
       -> independent evaluation -> expert/router composition
       -> whole-model evaluation -> shared model release
       -> contribution reward + free basic consumption -> new authorized experience

This is not only an inference marketplace. Upload counts, trained parameters, issued
coins, hashes, self-evaluations and seven local processes are not closed-loop evidence.
A new independent consumer must benefit from the composed release in a future task
window and be able to feed its own authorized learning into the next generation.

## 2. Consensus and learning architecture

### 2.1 The PoW-like ledger

Use one native event/effect consensus core. It receives bounded verified inputs and
returns effects; it performs no network, database, private-key, unbounded proof generation
or model call. Replace the active decision rules with the PoN block/target/chainwork
state machine. Keep reusable codecs, strict crypto, bounded adapters, transaction
accounting and storage identity checks only where their meaning actually matches.

Fresh work binds the exact parent, complete header template, producer/payout and
neural-task context. A qualified expensive attempt produces a canonical output; a
threshold predicate determines a winning attempt. Proof randomness and cheap metadata
changes cannot produce extra lottery trials. A node chooses the fully valid branch
with maximum cumulative required work, not maximum height or maximum model accuracy.
The precise candidate arithmetic, target adjustment and time rules are in CONSENSUS.

An old fine-tuned model may earn a model-contribution reward. It is not fresh consensus
work. The target work primitive is challenge-bound verifiable linear algebra arising
from adapter/head/router training or evaluation. The exact experimental transcript primitive, numeric/byte registry and two-language
vectors are implemented in W1/L1. Anti-shortcut security, cheap-forgery admission,
public-network efficiency and independent verification remain unqualified. No
quality threshold, training log, TEE quote or proof-of-execution is silently substituted
for computational hardness. No pure-hash or old-BFT automatic fallback is authorized.

### 2.2 Executable application boundary

The mainline is a dedicated AI-work/model/service chain with twelve original closed
application commands and explicit profile-gated native extensions. Signed task13,
evaluation14..17, lifecycle18..21, and the revision8
[V3 atomic renewal22](../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V3.md)
and revision9 [V4 signed overlap](../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V4.md)
have distinct context and gate rules; V3/V4 refuse standalone19. V3 requires the exact
containing height; V4 permits delayed inclusion while both signed authority windows
remain valid. The explicit revision11
[integer factor candidate23](../protocol/pon-nakamoto-v1/details/NATIVE_INTEGER_FACTOR_CANDIDATE_V2.md)
adds `M10.SubmitFactorContribution`, bringing the current typed responsibility
inventory to39 across the same18 modules,25 packages and17 normal dependency edges.
It loads the actual complete ILM2 parent and reuses bounded integer BA computation;
old tag6/model/task contexts do not silently select this profile. Historical twelve-command
parity and transfer benchmarks retain their original scope. This is not an arbitrary user-contract VM. No EVM, Move or WASM backend is
selected. Fees and performance evidence apply to the named closed commands. A future
VM decision needs explicit bytecode safety, deterministic metering, ABI, storage,
upgrade/reorg semantics, tooling and module ownership; it cannot arrive through an
unknown transaction tag or model artifact. See the application-scope section of
[LEDGER_WIRE](../protocol/pon-nakamoto-v1/details/LEDGER_WIRE.md).

### 2.3 Shared model structure

Use a common immutable base, organ/domain adapters, Cell/expert deltas, learned router
and typed composition graph. Parameters carry exact compatibility-family identities.
Local optima are candidates, not automatic global optima. Train/calibrate routing and
connectors under a fixed budget, evaluate the complete composition, and periodically
distill into a cheaper public base. Keep sparse full releases and compact deployment
profiles distinct and reproducible. Count shared weights once.

Heterogeneous backbones/tokenizers cannot be merged by tensor position. They require
versioned ports or evaluated distillation. An arbitrary collection of remote APIs is
not called one parameterized large model unless its complete architecture, model bytes,
routing and output semantics can be reproduced. Cell depth is not transformer depth.

The global control plane remains advisory and outside ledger authority.

### 2.4 Local Hepta sovereignty

Hepta training/artifact/evaluation/plasticity owners remain authoritative for their
facts. Neuron/Intuition/inference execute admitted models; kernel.operations owns
intents/outboxes/reconciliation; memory.federation remains read-only. The chain adapter
submits idempotent business operations and verifies PoN inclusion/confirmation proofs.
It cannot mint a local final-use token, share private memories by default, become a
second trainer/store or override revocation. The four existing NDU subject levels are
unchanged; a mandatory fifth global optimizer is not introduced.

## 3. Eighteen long-lived modules, reused ownership

There remain 18 long-lived modules. Current crate ownership is preserved; changed
responsibilities are explicit targets, not evidence that existing crates implement them.

| Module | Selected PoN responsibility |
|---|---|
| M00 | New work/header/contribution/release codecs, parameters, registries and version dispatch |
| M01 | Work/statement verification, identity and capability crypto; no vote weights |
| M02 | Header validity, target, cumulative work, fork choice and branch transition decisions |
| M03 | Mining/effect identity, bounded work-attempt lifecycle, durable publication and local fencing |
| M04 | Open bounded header/body/proof/parameter gossip, retrieval and eclipse resistance |
| M05 | Reorg-aware mempool, nonce/reservation and contribution transaction admission |
| M06 | Deterministic branch execution, workload metering and reversible application deltas |
| M07 | Branch roots, undo/replay, model/escrow state and descriptor-bound storage |
| M08 | Confirmation policy, reorg coordination and effect-aware recovery |
| M09 | Public parameter/evidence availability, replication, repair and bounded retention |
| M10 | Parameter contribution, evaluation job, composition and model-release lifecycle |
| M11 | Objective verification, independent evaluation and typed challenge/adoption decisions |
| M12 | Mining maturity, marginal-contribution rewards, serving payments and free-use budgets |
| M13 | Work-verified sync/light clients, deep reorg replay and fresh-instance PoCO migration |
| M14 | Honest included/confirmed/reorged APIs, model discovery/download and free inference |
| M15 | One ordinary PoN node composition, Hepta adapter and versioned deployment |
| M16 | Advisory routing/resource/composition proposals; no fork or authority decisions |
| M17 | Work-security, model-efficacy, reorg, economic and independently retained evidence |

Dependencies remain primitives -> contracts -> pure cores -> bounded adapters -> node
composition. No new global supervisor, parallel task ledger, PoN-owned learning database,
second body registry or all-module runtime is introduced. Actual Cargo edges/SCCs remain
source facts; a target diagram is not permission to falsify current dependency evidence.

## 4. Interfaces, persistence and reorganization

Separate ParameterContribution, WorkCertificate, EvaluationReceipt, CompositionCandidate,
GlobalModelRelease, ContributionAllocation and PublicInferenceBudget. Each has one
schema owner, versioned meaning, exact parent/attempt/nonce/profile binding and bounded
codec. Public constructors, booleans and unsigned JSON cannot manufacture verified facts.

Maintain a Node Commit Ledger-style coordinator and PinnedSqliteNamespace protection,
but do not reuse monotonic BFT-finalized state as a reorg implementation. PoN requires
new branch/undo schemas: durable intent -> detach -> attach -> root/readback -> atomic
active-generation publish -> indexed remove/add acknowledgement. Deep valid reorgs
trigger verified replay when undo was pruned; a local retention threshold is not finality.

Chain-derived balances, nonces, task entitlement, model-release pointers and reward
maturity can roll back. Local effect entry, provider receipt and revocation/anti-rollback
frontier cannot. A vanished confirmed lease does not authorize executing the same real
API action again. Reconcile orphaned effects under explicit risk/compensation rules.
Model adoption uses fresh local generations and preserves which historical model made
each recorded decision. Never reexecute history using current weights.

## 5. Reward and free-use rules

Keep mining reward, model-contribution reward and serving/storage/evaluation compensation
separate. A finite release budget unlocks only under preregistered whole-model improvement
rules; zero credible improvement pays zero. Attribute within the locked budget using
bounded ablation/sampling, with uncertainty, duplicate lineage and complementary bundles
handled explicitly. Splitting a root contribution across cells/accounts cannot increase
its total budget. No automatic perpetual lineage royalty or validator weight is minted.

Hosted free inference is sponsored and rate/queue/quota bounded. Token issuance is not
GPU supply; report funding and resource units separately. Service permission, local
learning, parameter export and public redistribution are distinct permissions. Parameter
publication does not prove privacy and cannot promise recall of every downloaded copy.
Genesis economics, emission/maturity/fees and public-tier budgets require explicit
parameters and independent economic review before activation; no invented launch numbers.

## 6. One executable convergence sequence

### PN0 — Contract and source alignment

Update this plan, all module specifications, applicability and machine target together.
Retain current source ownership and remove all old protocol/operation references from the active tree. Register new objects/errors/bounds and independent vectors. Documentation
and reference-model tests prove only their stated scope. No parallel target or roadmap.

### PN1 — Qualify real neural work

Select and implement the exact challenge-bound useful-work primitive. Freeze arithmetic,
proof format, setup assumptions, task choice, cost class and no-workload behavior. Attack
precomputation, trivial instances, stolen/old models, unused-input/proof randomness grinding
and verification DoS. Quantify useful work vs proof overhead and independent reproduction.
A falsified primitive is repaired or replaced by a reviewed new work profile, not silently
substituted with old consensus. New model improvement is not needed for every block.

### PN2 — Native PoN chain and recovery

Implement M00/M01/M02 contracts, M03 attempts/publication, M04 ingress, M05 admission,
M06/M07 reversible execution and M08 reorg. Verify required work rather than reported
work, DAA boundaries, partitions and every crash cut. Port pure-core/durable-owner patterns,
not retired Vote/Timeout/QC/TC logic. Keep actual runtime activation false until qualified.

### PN3 — One real parameter-to-public-model product loop

Connect Hepta's existing owners, real compatible small models and public parameter DA.
A normal product task trains an update, independent peers evaluate it, a router/composition
candidate improves the whole model, and a new independent consumer uses the release.
Test author disappearance, poison/compatibility faults and consent/source substitutions.
No manual fixture assembly substitutes for the ordinary startup/request path.

### PN4 — Rewards, reorg liabilities and free service

Implement bounded emission/maturity, escrow, contribution attribution and PublicInferenceBudget.
Replay duplicate/reorged rewards, cancelled tasks, delayed observations and real external
effects. Reconcile exact identities after crashes; never reset the local effect log when
chain state moves backwards. Measure free-tier capacity, successful service and costs.

### PN5 — Independent system acceptance (the G5 release boundary)

Execute real independently operated mining/validation hosts, forks, eclipse/partition,
proof flood, workload starvation, restart/power loss and deep reorg. Separately measure
whole-model future-window benefit, cheap/public serving, data availability, resource
cost and adversarial economic incentives. Do not relabel old seven-validator epoch runs
as PoN security. Exact-head and applicable prospective-merge evidence are distinct.

### PN6 — Migration and governed deployment

Drain/reconcile legacy liabilities and export exact classified history. Use a fresh
PoN genesis, identities, key/store namespace and explicit import reconciliation. Verify
no old proof is promoted, no liability omitted and no false cross-network double-spend
claim. Only accepted release/activation material can change production flags. Source
merge, a green document checker and model registry publication are not activation.

## 7. Qualification and evidence commands

Run project preflight before edits/commit/push. On a committed, unchanged checkout:

```bash
bash scripts/project-preflight.sh --audit
python3 scripts/ci/check_repository.py
python3 scripts/ci/test_repository.py
python3 formal/pon-nakamoto-v1/test_reference.py
bash scripts/ci/check_canonical_development_plan.sh
cargo test --locked --workspace --all-targets --all-features --manifest-path trillionnium/Cargo.toml
```

The new reference tests are arithmetic/state examples, never a neural miner, work proof,
Rust node or deployment certificate. Retained component regression tests remain required and are not evidence of PoN completion.
Run the affected Rust package tests, strict Clippy/fmt and applicable build-closure,
security and supply-chain checks for actual implementation changes.

Preserve exact source/tree/base/binary/profile/configuration, raw failing and successful
logs, hardware, actual invocation path and independent review. Current candidate identity
comes from Git/CI, not branch prose. Derive source and document fingerprints from the actual checked-out tree, never evidence outcomes. No self-approval, unrelated protection change,
force push, deployment or performance/efficacy claims arise from this refactor.

## 8. Completion definition

The direction is complete only when a real local-task update becomes a verified useful
part of a reproducible shared model, a new user obtains funded free basic use, the
contributor receives exactly the allowed reward, and the new PoN chain safely handles
work competition and reorg under its qualified assumptions. This document does not
assert any of those experiments ran. Open work-profile and implementation obligations
remain named in the machine contract and domain acceptance specification.


## 9. Active-tree cleanup boundary

`config/portability-inventory-v1.json` is the actual retained-package/owner inventory.
All old protocol and runtime trees are absent; Git history is the archive. Deployed
state, keys and services were not touched. Portable domains and schemas are fresh-only.
Local monotonic application stores are NOT yet authoritative branch-aware chain storage.
Storage/evaluator thresholds are application trust contracts, not ledger voting power.

## 10. Current convergence, not a count of documents or tests

The authoritative invariants are `config/pon/invariants-v2.json`. Each names its claim,
owner/scope, atomic boundary, adversarial schedule, exact test selectors and remaining
assumptions. All eighteen module contracts refer to their own failure modes. A registry
checker proves that these bindings exist; a separate exact-source receipt proves which
selectors actually ran. Neither mechanism supplies independent scientific authority.

| Priority / workstream | Actual implemented boundary | Concrete next acceptance requirement |
|---|---|---|
| P0 work and public admission | Exact experimental transcript and full scalar verification; a mismatching final digest skips product corrections after the complete transcript replay, while matching digests still require exact product verification; native PreparedTask removes avoidable repeated product work; paired valid-producer costs and bounded development ingress retain open hostile-proof/Sybil qualification | Implement/reproduce adversarial shortcuts and same-target costs; join ordinary public ingress and demonstrate honest service under stated sustained attack. No queue count grants work hardness. |
| P0 one native node | Native development CLI owns work/target decisions, branch persistence/reorg, receiver sync/confirmation an allowlisted signed private-development ingress with durable inbound replay/client outbox, and explicit public-development-v2 resource-ticket intake with bounded Head/History and no durable guest authority; original M00/M01/M06 are reused | The explicitly enabled [local queued owner](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_LIFECYCLE.md) provides bounded durable groups, typed M05 checks/M06 preview and branch/restart reconciliation; its explicit wall-clock miner, fresh V4 signed-overlap renewal, paid V3 transaction intake and operator-pinned peer following share one native owner; qualify measured sustained operation, open public discovery/gossip plus confidentiality, interruptible native work and ordinary Hepta/resource/effect integration. Both transport profiles remain development candidates; public-v2 resource bounds and local conformance do not grant public-service or complete product acceptance. |
| P1 long-lived state and confirmation | Native branch/delta/checkpoint persistence, receiver verification and exact signed-request replay/outbox state coexist with the independent reference oracle; root maps/history scans still incur full-size costs | Persistent incremental authenticated roots and real WAN/open-peer integration; the controlled receiver is full-verifying, not succinct or globally fresh. Verify deep history without treating private authentication, transport budgets or retention as finality. |
| P1 independent model value | E3 seals actual parent/candidate/strong controls/calibration/partitions; explicit revision11 factor admission loads the complete current parent and rejects exact same-context BA copies; no-gain remains zero adoption and reward | Authorized new tasks, independent source/evaluation/withdrawal owners, untouched future windows and budget-matched strong controls. Retrospective splits or configured identities do not satisfy independence. |
| P1 real resources and failures | Closed service receipt, finite quota/reward conservation and same-admin process/host fault observations | Real storage/serving obligations and funding, target-side effect reconciliation, independent operators, physical power loss and hostile public network. No chain undo may repeat a physical action. |
| P2 end-to-end capacity | Source-bound worker/session comparisons plus real native CLI, process-cut and loopback socket regressions; no sustained public capacity claim | Same profile, source, state size and load through submission, inclusion and client-verified depth/work confirmation, with latency tails, hotspot degradation, resources and attack availability. Executor speed alone is not TPS. |

Existing capacity/initialization/revoke-entry/admit-before-activate counterexample fixes
remain regression obligations in the current owners; they are not new missing features.
P0 work research and native integration may proceed concurrently, but neither grants the
other's acceptance. The five documentation corrections are implemented through current
revision applicability, procedure-level maturity/evidence, exact M08 phase contracts and
explicit application scope; their completion is not completion of this table.

Do not repeat already accepted component work under a new parallel engine. The source
inventory remains the sole native package/owner list; proof, execution, chain state,
model quality, local permission and actual effect entry remain different facts. A
published Hepta learning artifact does not automatically authorize public redistribution:
its publication receipt carries DENY_ALL authority, and actual export/withdrawal and
final-use decisions belong to existing independently configured owners.

## 11. Current model and consent increment

The [E3 contract](../protocol/pon-nakamoto-v1/details/EVALUATION_BUNDLE.md) gives the
exact immutable evaluation object, limits, control materialization, source-group policy,
producer write boundary, evaluator replay and consumer expectations. Existing
`model_loop.py`, `learning_cycles.py` and `settle_model.py` consume it directly. No new
trainer, artifact registry, global optimizer or parallel economic ledger is added.

A reference file, task file or score report changed after sealing must fail under the
caller's admitted hash. Calibration chooses the strongest deployable control using the
same equal-group principle as evaluation. Both positive mean gain and the corrected
sign-direction test are required. The settlement producer recomputes the original
calibration and evaluation; rehashing both summary and evaluator files cannot grant
reward. Full service expectations include returned output, units and provider nonce.

Three actual optimization attempts must each start from the actually admitted public
artifact. No-update, weaker-than-control and zero-reward outcomes remain visible. The
current public-source corpus is retrospective; three disjoint file pools or a caller's
future flag are not three independently improving prospective generations. Public
parameters change only after current independently admitted evidence and owner approval,
not because the experiment was scheduled to run three times.

## 12. Evidence and remaining authority

[Procedure-level evidence navigation](../modules/README.md#responsibility-and-evidence)
reads immutable package identities and reports subject-byte equality, the complete
recorded runtime and exact observed/unobserved selectors separately. Reusable package
presence is not ordinary product integration. Empty entrypoints and unobserved campaigns
remain explicit; no mandatory paragraph length, heading total or test-count gate is added.


`evidence/pon-v1`, `pon-v3` and `pon-v4` retain their exact historical source, failures,
workload, filesystem and host scope. The historical verifier checks those bytes and
results without promoting them to a changed current binary. Current model execution
requires its own current-source receipt; source equality and empirical effectiveness
are separate checks. Runtime changes must never be hidden by repinning old reports.

New measurements report input composition and conflicts, submitted/executed/included/
client-confirmed stages separately, proof cost, wall time, RSS, model load and actual
resource use. Unmeasured VRAM/inclusion/confirmation remains null. Native component
throughput is not chain TPS, and same-administrator physical machines are not independent
consensus actors. Root README remains blank by owner decision.

Squash merges may leave measured source commits outside main's ancestry. The evidence
preparation tool fetches only declared exact objects from this repository, verifies
their trees and never moves a branch or grants acceptance. A missing source object is
an error, not permission to copy current results into historical evidence.

Still unaccepted: cost-hardness and public hostile-proof fairness; complete public native host, continuous miner/mempool lifecycle
and ordinary Hepta owner/resource integration; independent attestors/custodians;
untouched future tasks; sustained long-term DA/state growth; actual physical power loss
and public network security. Highest repository privilege does not manufacture those
facts. Continue their implementations and falsifiable experiments on this lineage;
production remains disabled until the corresponding evidence exists.

[The retained E3 model execution receipt](../../evidence/pon-evaluation-bundle-v1/README.md)
records its exact-source native and logical regressions, locked evaluation replay, three
no-update optimization attempts and nine same-input results on three owned hosts.
It does not cover the subsequently added client runtime or replace independently
administered future tasks and public work qualification.

[The receiver-verified client receipt](../../evidence/pon-client-confirmation-v1/README.md)
records new clean-source full regression and both reference and explicit native compute
client configurations, including complete-ancestry clock reobservation. The same
responsibility reporter resolves its measured source and exact selectors. No model
training/host campaign was rerun for that receipt. Its retained initial failure exposed
an omitted-source hole in historical component checking: the original measured runtime
inventory must come from the measured Git tree, not an editable receipt. Publication
checker tests are separate from runtime qualification; local callbacks inside a test
are not independent test cases. Original successful and failed logs remain immutable.

## 13. Native session, bounded confirmation and new-source qualification

Continue the same canonical PR #204 lineage. Existing five applicability/evidence/M08/
responsibility/application-scope corrections are preserved, not counted as new runtime.
Recovered local work is integrated only after source comparison and byte-preservation.

In the historical session path, M06 exposes an optional private native compute session
with a compressed in-memory incremental commitment. Within that path M07/M08 reference
SQLite remains the sole durable owner. The subsequent native CLI has its own fresh
M07/M08 namespace, not a second writer of the reference store. Strict predecessor bytes, sequence, delta, output,
backend selection and lost-reply handling prevent reuse of an unknown cache as authority.
Early work prechecks reject malformed input before branch-state reconstruction but do not
qualify cheap forged tickets or adversarial work hardness. The receiver can check a bounded
batch of distinct transaction confirmations with one complete-ancestry clock observation.

Qualify on a clean committed source, including all existing native tests, client/reference/
explicit-native/session backends, old evidence integrity and newly added counterexamples.
Run same-source paired execution costs and an actual work/persistence/receiver-confirmation
campaign into new paths. Report logical-clock/no-pacing and local-controller limitations;
no executor improvement becomes public TPS, independent consensus or full-node completion.
Historical E3/model/client reports retain their original source and outcomes. The new
current receipt must cover changed runtime; no old receipt is repinned or silently waived.

All six P0/P1/P2 tracks above retain their missing real boundaries: adversarial work/public
admission, ordinary native node, persistent state/WAN sync, authorized independent future
model efficacy, funded DA/effects/physical faults, and sustained public confirmed capacity.
No new VM, EVM, consensus fallback, learning owner, live service or production flag is added.

[The historical native-session and receiver receipt](../../evidence/pon-native-session-v1/README.md)
supplies its original exact-source regression and controlled pipeline observations.
Native-node changes require a new native-node receipt; old E3/client/session packages
are historical, not current-runtime coverage.
The retained selected-matrix pass is accompanied by the later actual expiry-receipt and
maximum-budget failures, their fixes and a complete clean-source rerun. An incremental
in-memory tree is not persistent native storage, and locally verified confirmation
under a logical clock is not public WAN throughput or deterministic finality.

The [historical session-source work-cost collection](../../evidence/pon-native-session-v1/work-cost/README.md)
was rebuilt and executed on its named clean source after the prior cost gate rejected
stale inputs. Current and historical verification remain separate required checks.
The [retained publication failures](../../evidence/pon-native-session-v1/publication-failures/README.md)
also record globally ignored raw logs; the delivery checker now requires actual Git
coverage for in-repository receipts. None of these repairs changes work qualification,
production flags, original model observations or the missing ordinary native host.


The same native development composition now supplies bounded ordinary CLI/socket batch
confirmation, cancellable read traversal and an explicit allowlisted signed private-
development transport. Inbound replay reservation and signed response retention survive
restart; the client commits one exact signed wire before I/O and retries only those bytes.
Opened-descriptor checks protect key/roster inputs and authentication options are confined
to network commands. These facts close a controlled request/replay gap, not confidentiality,
open peer discovery, Sybil fairness, independent administration or target-side physical
exactly-once effects. Fixed-dataset value and elementary accuracy upper-bound statements
are recomputed by the existing evaluation/settlement workers; they do not qualify
prospective learning or general circuit optimization. Record this changed source in a new
native-node receipt rather than repinning session evidence. Public P2P/work admission,
continuous mining/mempool scheduling, native persistent incremental state, revision3
evaluation-order economics and genuine Hepta/model/resource integration remain separate
unfinished implementation/acceptance work on these existing owners.

The current [native-node receipt](../../evidence/pon-native-node-v1/README.md) binds the clean runtime, actual native CLI replay, both work-cost targets and a separate recomputed model-value experiment. Hosted candidate/merge checks remain fresh delivery observations, not part of old runtime receipts.

## Complete-evaluator successor and alternative valid-work producer

Continue PR #204 and the same native M11/M06/M15 owners. The default revision3 and all
prior evidence remain unchanged. An explicitly selected fresh revision4 development
context binds `closed-round-all-eligible-min-v1`: every eligible genesis attestor except
the exact author must submit before the minimum score closes. Missing/zero evidence
cannot unlock adoption or reward; existing signed expiry bounds withheld candidates.
This removes prefix-arrival selection for this complete-set rule, not evaluator trust,
withholding, functional-copy attribution or the need for a public dispute profile.
Ordinary native CLI mining, reopen, heavier-fork removal and reexecution are exercised
with the same signed transactions and independently computed state. No old database is
migrated, production enabled or authenticated public ingress inferred.

The existing M01 PreparedTask producer now uses exact bounded field reduction,
transposition and batched transcript hashing. It must produce byte-identical work under
the unchanged verifier. Account preprocessing and same-target winners, full verification
and forged-ticket rejection separately. An observed cheaper valid miner tightens the
actual cost question; it does not qualify the work profile or supply a lower bound.

New runtime needs its own clean-source qualification and cost records. Old node/model/
host evidence remains historical. No new training, funded GPU serving, independently
administered future-task acceptance, continuous public miner or persistent authenticated
state is claimed by the closed-round or arithmetic changes. Their existing P0/P1/P2
workstreams remain implementation and external-acceptance obligations, not paper gates.


The [closed-round/producer receipt](../../evidence/pon-closed-round-v1/README.md)
retains the explicit revision4 selection, complete eligible-set aggregation, ordinary
native CLI/reorg tests, exact optimized producer, and new same-target cost collection.
It preserves revision3 defaults and all historical artifacts. Source qualification,
independent model value, public work safety and production activation remain separate;
the remaining work stays in the existing convergence table, not a new roadmap.

## Six-finding convergence continuation

The [current entrypoint and acceptance contract](../protocol/pon-nakamoto-v1/details/PUBLIC_READINESS.md)
maps the six audit findings onto executable development interfaces and remaining public
gates. This continuation stays on the existing native candidate; no acceptance flag is
promoted. The implemented additions are a negotiated connection-local proof-admission
challenge, explicit signed-task revision5 registration/material/parent eligibility,
branch-relative arithmetic-output counting, bounded integer-adapter attribution and
off-chain evaluation lifecycle, and a durable TCP/client-confirmation campaign. The
original work verifier, chainwork and revision3/default bytes remain unchanged.

The signed-task testing context has16 public fixture demands, a public source seed,
a fixed withdrawal frontier and1000-block bootstrap lifetime. It is intentionally not
an exclusive production source, real task marketplace, live revoke or indefinite
maintenance policy. The attribution profile establishes exact BA identity and finite
candidate-set objectives, not generic neuron equivalence, independent future efficacy
or global neural-circuit optimum. Public evaluator governance remains a separate owner responsibility. The explicit
native-public-evaluation-dev-v1 successor implements frozen commit/reveal phases,
mandatory deadline closure, signature-conflict evidence, bounded archive appeals and
existing funded release/reward gating. Its heights and branch state are native; its
development identities and signed scores remain unqualified for independent governance
and objective ML quality. Historical revision4 and default revision3 keep their bytes.
An actual complete-round counterexample exposed the previous single-value storage
limit: a late reveal conflict and the third appeal exceeded4096 bytes and rejected.
Storage revision2 separates bounded records, commits a fresh network/parameter context,
and tests all16 appeals, late conflicts, archive-only continuation, reopen and cleanup.
Preserve the failed candidate and its original execution record.

The explicit signed-task-lifecycle-dev-v2 revision7 adds native requester lease
open/renew/revoke and source registration under distinct signing/parameter domains.
Renewal keeps the admitted material and one-output meter; revoked parent state refuses
subsequent work. Generation-safe bounded slots retain source sequence and availability
windows. Actual Node tests cover signed transactions, valid PNW1 packets, durable reopen
and heavier-fork replacement. Development authorities and cost-class1 remain unqualified
for genuine demand, remote availability or cheapest-miner hardness.

The pinned SmolLM2-135M CPU/rank4 LoRA family has actual material loading, training and
all four required controls in an isolated LAN runtime. The tiny public same-operator
fixture gives zero gain against the strongest control. An explicit cross-context bridge
binds the raw artifact and original observation to native revision7, completes the native
commit/reveal round at score0 and refuses adoption/reward; it claims no native ML proof.
The separate distributed caller assigns producer, authenticated validator and full-sync
confirmer to three OS processes with three owners. Each verifies native work and state;
matching signed receipts do not attest physical placement or independent operation.

Priority remains P0 qualified cheapest-miner work cost and sustained hostile intake,
then P1 actual target-model efficacy/poisoning/deployment costs, independent evaluation
governance, useful-output efficiency and steady end-to-end state/history/network load.
Keep failed experiments and all attempt/validator costs. Live wall time and descriptive
latencies do not supply a hardness theorem, independent operators or public fairness.
The new clean-source qualification runner captures the full native/reference regression
and additional campaigns; historical receipts stay bound to their original source.

The [six-finding local qualification](../../evidence/pon-public-readiness-v1/README.md)
records clean implementation c2b1ca2 with cryptography50.0.2/OpenSSL4.0.3, all 15
qualification commands and the nested 48-command native/reference regression. Four live
transfer workloads confirm 20,480 transactions through two durable owners; protected
socket phases preserve reported high-level attempt outcomes and retry-inclusive elapsed
times, without individual reconnect attribution.
Actual transcript, signature, confirmation and closed SQLite replay passed. The 29
source-preparation and 20 evidence negative tests passed. First-run missing-corpus failure,
predecessor traffic-accounting/caller costs, the prior publication CI selector failure,
D publication historical-test setup failure and E launch/Python-path failure
are retained without relabelling their source or tool environment. This evidence does not
close the public gates above or qualify the later lifecycle, evaluation, model and
distributed additions. Each successor requires its own source-bound observations;
independent work-cost and model-benefit obligations remain open. Child Python is explicitly bound to the observer environment and its actual
executable/dependencies are checked against both qualification layers. Preserve the
measured Git source history when publishing or merging evidence.


The explicit [operator actors development profile](../protocol/pon-nakamoto-v1/details/OPERATOR_ACTORS_V1.md)
adds canonical public genesis actors/allocations and source/requester offline approvals
without implicit DEV signing in Node Settings. M05 still validates the native nonce/fee
and parent-admitted task; M06 commits the selected roster/material under a fresh N/P/G;
M15 composes public-only normal startup and explicit offline prepare/sign/finalize.
Actual local native/CLI regressions do not prove random keys, independent custody,
truthful demand, data retention, cheapest-miner hardness or public governance. All
acceptance flags remain false, and historical constructors/golden bytes stay unchanged.

The current convergence continues with [public V2](../protocol/pon-nakamoto-v1/details/PUBLIC_INTAKE_V2.md)
resource revision r2 and [V3](../protocol/pon-nakamoto-v1/details/PUBLIC_POOL_INTAKE_V3.md)
resource revision r3. V3 retains paid canonical requests within the same bounded
connection while its original worker channel is Full, attempting enqueue in
connection-ID order without increasing queues, grants or absolute deadlines.
The current V3 resource r5 additionally reserves local actual mutation-thread CPU
before native dispatch, charges its total once and records disjoint full-work and
remaining dispatch intervals. One service-epoch account spans caller identities;
measured debt stops new starts, and unavailable accounting disables future
mutation starts while preserving already completed native outcomes. Original
read reservations remain. Two nonpreemptive calls may exceed their reservations;
individual CPU, Node lock occupancy, honest fairness and Head SLA are not bounded
by this local account. It is a development resource policy, not ticket cost or
hardness calibration, host-global governance or public qualification.

Within the existing totals it reserves read-body and control-output capacity, separates
paid mutation/read grants and read challenge tokens, retains grants through native work
and output, and checks disconnect/expiry fences between complete stages. EOF, including
a write-half-close, cancels the request; clients keep both halves open until the reply.
New resource digests reject old cookies without fallback. These component controls do
not establish anonymous scheduling, remove full-verifier cost amplification or qualify
independent public hostile service. The separate connection-work-v1 transport now gives
its original socket/deadlines an at most2ms zero-capacity handoff opportunity and up to512
Busy attempts within its existing absolute5s budget, under a fresh profile digest.

The same [continuous miner](../protocol/pon-nakamoto-v1/details/CONTINUOUS_MINING_V1.md)
checks cooperative stop/deadline fences after owner/parent observation, actual pool
selection, miner binding and preparation, and before and after postsearch revalidation.
Selection already performs full M05/M06 under the uninterrupted owner; its immediately
duplicated presearch preview is removed only for the locally owned batch. Public mutable
batch validation, postsearch validation, native admission and durable activation remain
complete. Stage timing names and nonpreemptive overruns are specified explicitly.
Actual SQLite-blocked stopping and injected native failure controls retain state and
queue invariants; failed predecessor observations remain bound to their source.

The [M06 derived commitment](../protocol/pon-nakamoto-v1/details/DERIVED_STATE_COMMITMENT.md)
preflights ordered differences without cloning payloads, selects resource or excessive
delta fallback before building the public change vector, and computes the complete
original root before fallback materialization. Complete delta bytes and root authority
remain unchanged. The65536-key disjoint-state control has131072 changes; it is a finite
component resource/root equivalence control, not a native reachable workload or public
availability certificate. Cache budgets are separate from canonical-state limits and
do not bound all required canonical/delta allocations or allocator RSS.

The [V1 evaluation observer](../protocol/pon-nakamoto-v1/details/EVALUATION_CONFIRMED_OBSERVATION_V1.md)
and its CLI check actual candidate membership, frozen rounds, active generation and
installed confirmation policy through a complete ancestry bounded at4096 blocks.
The separate [V2 round observer](../protocol/pon-nakamoto-v1/details/EVALUATION_CONFIRMED_ROUND_OBSERVATION_V2.md)
checks a complete bounded round window at later chain heights, actual reverse deltas and
parent roots, and cross-checks the existing ancestry index. Its base anchor, earlier
global confirmation and earlier clock history are explicitly unevaluated. A private
typed local observation is neither a public session receipt nor adoption/reward
authority. Reorg invalidation, public operation consumption and independent evaluator
governance remain in the existing convergence requirements.

The independent [checkpoint tile material replay](../protocol/pon-nakamoto-v1/details/CHECKPOINT_TILE_MATERIAL_V1.md)
checks complete original checkpoint bytes, actual tensor coordinates, original input
bits and exact integer quantization against all derived A/B values, under a new
closed descriptor/policy domain. Its private checked result binds the unchanged
crypto source/context manifest; actual native parent slot eligibility, withdrawal,
replay and output consumption remain with the existing owner. The library alone adds no
task selector, State, ledger wire or signed source authority. The explicit revision10
[checkpoint tile task selector](../protocol/pon-nakamoto-v1/details/CHECKPOINT_TILE_TASK_V1.md)
commits a context-free policy and new operator specification before deriving fresh
N/P/G. Settings construction and every Node open replay complete original materials;
Config policy construction alone does not. Only the installed Maintenance/output0
relation is selected; original parent/source eligibility and native execution remain required.
Full-file membership and material density do not qualify cheapest-miner hardness,
true demand, full-model execution, marginal contribution or independent custody.

Public sync can explicitly request the [same-owner evaluation observation](../protocol/pon-nakamoto-v1/details/SYNC_EVALUATION_OBSERVATION_V1.md)
after its complete actual work/state sync succeeds. Partial sync cannot create a
phase result. Observation failures retain and report the already completed sync
fact; omission preserves the previous result fields. This composes existing owners
without new evaluation RPC, guest permission, durable schema or decoded observation
authority. Applications consuming observations still need their own durable effect
identity and reorg/retirement rules; native evaluation transactions continue to use
the actual roster, current State, branch heights and funded conditions.

The isolated public V3 r3 localhost successor completed three10s phases with
180/180 honest Submit/Head/History requests. Cached invalid800 attempts produced
792 duplicate-content refusals and8 Product rejections; distinct-fork800 produced
799 Product rejections and1 paid-grant client refusal. Queue refusals were0;
71 Full polls were not71 failed requests. Original independently coded scalar/State/
ordered-receipt replay checked the anchor,20 linear successors and one separate
valid fork template (22 packets). Each closed service store contains genesis and
21 linear packets, giving66 stored rows including3 genesis; the fork is not in
those stores. Its product-only mutation was refused as PRODUCT.
The original1c observation (9 of20 honest Submit accepted,7 queue refusals,788 duplicate-content
and6 Product rejections) remains a retained failure/saturation observation.
These component results do not qualify the newly combined source, WAN/SLA,
anonymous fairness, model efficacy, useful task demand, mining hardness or public
readiness. General functional-copy attribution and independent evaluation/source
budgets remain open; all six public acceptance gates remain false.
