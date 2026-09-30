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
proof decoder or fallback remains in the workspace. Current local monotonic stores are
not yet a PoN branch/undo implementation.

No machine flag is promoted. The current implementation projection is:

    stage = invariant-driven-native-application-candidate
    production_candidate = false
    production_consensus_activation = false
    public_testnet_ready = false
    release_ready = false

New PoN implementation, work-profile qualification, cryptographic security, public-model
efficacy and activation are also false. Source work and documentation may proceed now;
release requires their own real evidence, not completion of the retired PoCO roadmap.

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
have distinct context and gate rules; V3 refuses standalone19. Historical twelve-command
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
| P0 work and public admission | Exact experimental transcript and original verification; native PreparedTask removes avoidable repeated product work; paired valid-producer costs and bounded development ingress retain open hostile-proof/Sybil qualification | Implement/reproduce adversarial shortcuts and same-target costs; join ordinary public ingress and demonstrate honest service under stated sustained attack. No queue count grants work hardness. |
| P0 one native node | Native development CLI owns work/target decisions, branch persistence/reorg, receiver sync/confirmation an allowlisted signed private-development ingress with durable inbound replay/client outbox, and explicit public-development-v2 resource-ticket intake with bounded Head/History and no durable guest authority; original M00/M01/M06 are reused | Finish persistent mining/mempool scheduling, open public discovery/gossip plus confidentiality, interruptible long history and ordinary Hepta/resource/effect integration. Both transport profiles remain development candidates; public-v2 resource bounds and local conformance do not grant public-service or complete product acceptance. |
| P1 long-lived state and confirmation | Native branch/delta/checkpoint persistence, receiver verification and exact signed-request replay/outbox state coexist with the independent reference oracle; root maps/history scans still incur full-size costs | Persistent incremental authenticated roots and real WAN/open-peer integration; the controlled receiver is full-verifying, not succinct or globally fresh. Verify deep history without treating private authentication, transport budgets or retention as finality. |
| P1 independent model value | E3 seals actual parent/candidate/strong controls/calibration/partitions; no-gain remains zero adoption and reward | Authorized new tasks, independent source/evaluation/withdrawal owners, untouched future windows and budget-matched strong controls. Retrospective splits or configured identities do not satisfy independence. |
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
