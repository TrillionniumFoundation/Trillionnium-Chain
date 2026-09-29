# Trillionnium Chain Development Plan — PoN / Hepta-PoH revision

Plan ID: `trnm-chain-development-plan-v2` (stable registry identity; content revision 3).
Effective: 2026-09-28. Status: selected development direction; no runtime activation.
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

### 2.2 Shared model structure

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

### 2.3 Local Hepta sovereignty

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

## 10. Invariant-driven continuation, revision2

The authoritative failure contracts are `config/pon/invariants-v2.json`: scope,
atomic boundary, concrete fault schedule, expected result, exact test function,
source owner, resource bounds and honest remaining work. Module-count, heading length
and test-class names do not establish completion. The gate validates exact selectors;
only separate source-bound command receipts say whether those tests executed.

Implemented candidate scope: four reviewed counterexamples corrected; durable owned
initialization; entry/revoke serialization; best-known-tip recovery; active-only candidate
capacity; root-bound claims after retirement; bounded release expiry/refunds; incremental
normal append; local checkpoints beyond4096 without declaring finality; actual native
all-twelve-command application execution with fixed-order bounded speculation; explicit
native backend without success fallback; native local proof-capacity separation; strongest
calibration control and clustered evaluation; closed genesis-bound service receipts.

These are not all seven acceptance packages completed. Public proof hardness/hostile
admission fairness, full native consensus/persistence host, normal Hepta final-use/owner
integration, independent operators, untouched future learning windows, native paged sync,
complete historical compaction, WAN and physical power-loss remain unaccepted. The
three-generation signed ledger fixture is not three improving trained models.

Prioritized remaining work stays on this lineage: verify the new failure regressions;
qualify work and actual public ingress; finish bounded history/resource lifecycle; connect
native host and Hepta owners; then run genuinely independent multi-host and prospective
model acceptance. Do not reopen retired consensus or create a parallel global trainer.
The root README remains blank by owner decision.

## Current revision3 continuation

Continue the existing invariant candidate; do not create a parallel consensus or learning
owner. Revision3 adds signed contribution intake windows, per-lane proof identity,
bounded native process I/O, explicit native work bridging and spooled historical replay.
All18 modules now bind their specific invariant, failure schedule and executable tests.
Machine-count or section-count coverage is not semantic or independent acceptance.

Acceptance must keep four result classes separate: deterministic native/reference
regression; real long-chain storage with logical timestamps; same-operator physical-host
SSH conformance with real UTC; and actual controlled learning with possible zero reward.
The ordinary Hepta destination, independent attestors/operators, fresh future experience,
public work-cost security, long retention and physical power-loss campaigns remain named
work. No local experiment, preserved failure or admin privilege silently resolves them.

## Measured continuation and unresolved acceptance boundaries

The concrete regression/experiment package is `evidence/pon-v3/README.md`. It records
which exact implementation ran, source hashes, command output, filesystem and clock scope.
The checker verifies those records; it is not an authority that certifies usefulness,
consensus security, independent operators or production deployment.

The four audited counterexamples and native twelve-command parity have executable
regressions. Signed intake rounds, root-bound claims, bounded checkpoint caches and
spooled ancestry deepen long-lived behavior; they do not complete global state compaction.
Real >4096 proof history, local malicious-verification load and physical SSH peers are
separate workloads. Ordinary-node and Hepta owner integration remain distinct missing
implementation, not a permission that can be created from an admin token.

The three controlled learning attempts preserve strongest-baseline and clustered rules;
all no-update/zero-reward outcomes must remain visible. The actual public-model pointer
must change only on current admitted evidence. The desired three improving generations
requires prospective tasks and the real owner path; it is not met by three synthetic
score releases, three retrospectively trained candidates or three remote machines.
