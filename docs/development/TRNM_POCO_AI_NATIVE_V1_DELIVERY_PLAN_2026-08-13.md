# TRNM PoCO AI-native v1 delivery plan — 2026-08-13

Status: **active target plan; design-only; no gate is complete; v1 is not
implemented or activated**

This plan translates the native-mainline decision and the proposed v1
production contracts into an evidence-ordered engineering sequence. It does
not amend frozen PoCO-BFT v0 and does not claim a deployable node.

Authoritative inputs:

- [`../architecture/TRNM_POCO_BFT_MAINLINE_CUTOVER_2026-08-25.md`](../architecture/TRNM_POCO_BFT_MAINLINE_CUTOVER_2026-08-25.md)
- [`../architecture/TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md`](../architecture/TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md)
- [`../architecture/TRNM_POCO_AI_NATIVE_V1_PRODUCTION_CONTRACTS.md`](../architecture/TRNM_POCO_AI_NATIVE_V1_PRODUCTION_CONTRACTS.md)
- [`TRNM_POCO_BFT_DELIVERY_PLAN_2026-08-04.md`](TRNM_POCO_BFT_DELIVERY_PLAN_2026-08-04.md)

The v0 work in G1 is a minimal safety baseline. It must not absorb v1 DA,
digest ordering, Agent concurrency, or settlement semantics by stealth. V1 is
frozen and activated only through its own wire, domain, vectors, formal,
upgrade, light-client, and implementation gates.

## 1. Delivery rules

1. Machine truth leads narrative truth. A target stays false until its code,
   dependency graph, release closure, tests, and external evidence pass.
2. Safety precedes throughput. Persist-before-sign, lock recovery, whole-node
   monotonic checkpointing, durable-before-attest, and exact finalization apply
   cannot be weakened to improve a benchmark.
3. V0 and v1 have separate parsers, types, domains, state schemas, and
   conformance vectors. Cross-version behavior exists only in the upgrade
   verifier.
4. Order, DA, execution, AI verification, and settlement have separate metrics
   and fault domains. A slow or unavailable layer cannot fabricate a positive
   result in another layer.
5. Only committed goodput, p50/p95/p99 finality, recovery time, availability,
   correctness, and per-resource cost are reported. Ingress TPS is not a
   performance claim.
6. An Order safety-kernel change is evidence-driven. Protocol novelty alone is
   not a requirement.

## 2. Gate board

| Gate | Objective | Initial truth | Exit authority |
| --- | --- | --- | --- |
| G0 | Clean, reproducible, zero-Comet native boundary | Dependency graph closed: active workspace/all-features/lockfile and executable config/adapter authority are clean; reproducible commit/release evidence remains | Dependency/release/SBOM truth and clean-clone reproduction |
| G1 | Minimal frozen-v0 non-empty vertical safety path | In progress: complete deterministic ordinary-body execution and restart-readable durable P exist behind the native application boundary; Node/Core/Safety/CAS wiring remains absent | Crash-safe execution -> Vote -> finality -> apply evidence |
| G1.5 | Freeze v1 specification; measure only a minimal 4/7-node v0 baseline | In progress: foundation/order, per-entry Order crypto, activation, and bounded-formal candidate tranches | Normative schemas/vectors/formal review plus reproducible baseline |
| G2 | Implement v1 DA, Agent, task, verification, MVCC, fees and rollups | In progress: bounded local DA, Agent/Market, Verify/Challenge and object-MVCC/fee candidates only | End-to-end private alpha contracts and fault evidence |
| G3 | Profile 7/31/100 validators under WAN/fault workloads | Not started | Reproducible bottleneck report and Order decision record |
| G4 | Adversarial public-validation and release gates | Not started | Soak, audits, independent clients, operations and governance sign-off |

Parallel prototypes are allowed, but a later gate cannot inherit completion
from an earlier incomplete gate. No calendar estimate overrides an exit gate.

## 3. G0 — zero-Comet clean native baseline

### Scope

- Reduce the current dirty tranche to reviewable, reproducible commits; include
  every source file referenced by the build and eliminate staged/worktree
  ambiguity.
- Extract TRNM-owned application request/result, execution receipt, validator
  transition, snapshot, state proof, commit, recovery, and event types into a
  native boundary.
- Move reusable runtime, JMT/ICS23, storage, overlay, and PoCO state-machine
  logic behind that boundary.
- Remove the production node's normal dependency path through
  `trnm-consensus-app` and every unconditional Tendermint/ABCI dependency.
- Isolate any one-way legacy export tool outside the active build and release
  closure; it may emit a reviewed migration manifest but cannot import legacy
  WAL, lock state, finality, signer state, or local watermarks.
- Freeze the TRNM chain descriptor, genesis, network magic, node identity,
  validator keys, native data-directory marker, wire negotiation, release name,
  and rejection behavior for old Comet data directories.
- Generate a single machine-readable status/schema manifest from source and
  make CI compare it with Cargo metadata, dependency graphs, binaries,
  containers, SBOMs, runbooks, and documentation.
- Provide a clean offline build and test entry that any reviewer can reproduce
  without a private workspace or mutable external service.

### Exit gate

G0 is complete only when a clean clone builds the same native artifacts and:

- no production node/application/signer/sync/light-client normal or build
  dependency contains CometBFT, Tendermint, ABCI, ABCI++, or the legacy adapter;
- public native APIs, wire, storage, genesis, release, SBOM, and operator paths
  contain no ABCI-owned type or compatibility mode;
- the only production node family is TRNM native and it rejects legacy data;
- CI truth passes from worktree, staged index, clean clone, and pushed commit;
  and
- readiness and production-activation flags remain false.

### Current evidence tranche

The first G0 slice adds `trnm-native-application`, a dependency-free boundary
crate with checked native types for genesis, block execution/result, receipts,
events, commit, validator transition, proof, snapshot, and recovery. Its CI
gate proves the crate has no normal/build dependency and no Comet/Tendermint/
ABCI or legacy App/Node token. The PoCO node's direct development dependencies
and source references to the old transport crates have also been removed; its
legacy genesis fixture is now behind the migration-residue App test helper.
The Node default and all-features closures, complete active workspace graph,
and lockfile no longer include `trnm-consensus-app`, Tendermint, or ABCI. The
historical App and legacy-node crates are explicitly outside the workspace and
the remaining adapter/config markers carry no executable authority. This
closes the G0 dependency graph but does not by itself create production
readiness. The default Node now imports the
native contract and contains a private, non-cloneable, exact-binding,
fail-closed owner scaffold. Production can construct neither the raw owner nor
its separate finality permit; the owner has no native store/engine,
authenticated recovery, commit-uncertainty recovery, Core/effect-driver path,
or finalization reachability. Machine truth therefore separates
`default_node_boundary_owner=true` from
`node_application_engine_integration=false` and
`node_process_integration=false`. A separate native SQLite slice now owns the
complete bounded canonical bytes for one `NativeExecutedBlockV0` as durable P
and performs digest/checksum, strict decode, exact re-encode, full proposal
binding, and fresh-connection readback. It still has no native execution
engine, Core-D/Safety-C authority, restart capability takeover, committed-head
advance, Node/process wiring, whole-node CAS, or production status. The store's
terminal K row now retains request-bound, C-shaped readback provenance -- the
validation ID and Core-delivery digest, an exact Core/Safety revision mapping,
Safety-record digest, and vote-intent digest -- under the row checksum and
fresh/reopen audit. It also rejects a self-consistent C
substitution whose Core-delivery digest differs from the durable D row. This
closes loss of request-bound provenance inside the scaffold; the raw adapter
response is still untrusted and does not supply the real SafetyStore adapter
or make K a Core/Safety authority. Existing clean schema-v3 stores are
immutable-read-only preflighted before any WAL pragma/writable connection and
are never implicitly recreated or migrated; any WAL/SHM/rollback-journal
sidecar is fenced because recovery authority is absent. The D value likewise no
longer has an external constructor: until a Node-private Core acceptance
carrier exists, outside code cannot forge the missing authority.

The active workflow/release/operator surface is also retired from legacy
authority: every automatically triggered workflow is free of Comet/ABCI
execution, port `26657` probes, legacy-App Cargo execution, and legacy
package/release entrypoints; six historical workflows are manual inert
markers; local legacy release, operator-transition, Comet rehearsal,
persistent-scale, and emergency-drill entrypoints fail closed before effects.
Legacy App recovery/SIGKILL sources remain audit-only outside the active Cargo
graph. The dependency closure is complete, while clean pushed-commit evidence,
native release/SBOM, default-Node integration of the deterministic application,
and legacy-data rejection proof remain separate readiness/G1 obligations.

The default Node now additionally proves one private linear splice from a
genuine Core-issued ordinary non-empty Proposal through a Node-owned exact-
binding `NativeApplicationV0` test fixture to canonical durable P and exact
fresh/reopen readback. The fixture supplies synthetic expected roots and is not
a complete deterministic execution engine. The private carrier retains the
Core permit and P token; it cannot construct D, C, K, a Valid callback,
`RequestSignature`, signing, broadcast, or restart takeover. Advancing beyond P
requires a durable speculative-overlay manifest/write plan joined with the
issuing Core's affined application seal plus real Safety authority.

A separate active zero-Comet G1 tranche now implements the complete frozen-v0
ordinary-body state transition and `NativeApplicationV0` owner. It executes
runtime, validator-lifecycle, PoCO/cutoff, and mandatory system writes against
one authenticated parent snapshot; independently derives all four roots; and
atomically persists canonical P, the full target JMT snapshot/overlay, replay
sets, lifecycle bytes, store identity, and monotonic local sequence. Immutable
fresh/reopen validation recomputes the target root before `Valid`, and reopen
audits the complete P chain. Two ordered transactions prove in-block overlay
visibility; artifact, snapshot, store, sequence, root, replay, and missing-P
substitutions fail closed. This owner is not yet connected to the default Node
or a Core application seal. It has no real Safety-C, whole-node CAS, process
takeover, `RequestSignature`, signing, or broadcast authority, so G1 remains
open.

## 4. G1 — minimal frozen-v0 vertical safety

### Scope

Implement the narrowest real validator path that makes the existing v0 safety
kernel operational without expanding v0 into the v1 architecture:

```text
bounded ingress
  -> complete v0 payload dissemination
  -> exact decode and deterministic execution
  -> sealed BlockId overlay and roots
  -> durable SafetyState
  -> complete canonical Vote/Timeout SignIntent
  -> signer journal and external watermark
  -> QC/TC and three-chain finality
  -> ordered application apply and durable acknowledgement
```

Required work:

- build one process host/effect driver with generation-aware pacemaker,
  bounded queues, typed backpressure, metrics, tracing, and authenticated
  ingress;
- route both Vote and Timeout through one production SafetyRules owner;
- implement the independent Safety/Application/Signer whole-node checkpoint
  and compare-and-swap recovery protocol;
- complete arbitrary non-empty regular blocks, BlockId-keyed speculative
  overlays, ordered ancestor finalization, idempotent apply, overlay pruning,
  and general recovery rather than another special empty-height carrier;
- retain v0 complete-payload-before-vote and sequential reference semantics;
  v1 BatchRef/DA certificates and v1 Agent semantics are forbidden here;
- test every persist/sign/broadcast/validation/outbox/finalize/checkpoint cut
  under SIGKILL, commit success with response loss, disk full, I/O error,
  restart, database rollback, full namespace rollback, and signer/Safety/App
  skew; and
- add authenticated state replay sufficient for this single-node vertical
  path without claiming general state sync.

### Exit gate

- At least 100,000 arbitrary non-empty deterministic v0 blocks complete with
  zero double-sign, duplicate apply, lost obligation, skipped ancestor,
  receipt/root drift, or unsafe rollback.
- Vote and Timeout exact replay are idempotent; any mixed or stale local cut
  fails before a signature or application effect escapes.
- All durable-boundary crash cases converge to the exact source or target.
- The binary is still not called a production candidate, public testnet, or
  mainnet node.

## 5. G1.5 — freeze v1 and establish the minimal v0 baseline

G1.5 has two deliberately bounded lanes. The specification lane may run in
parallel with late G1 engineering. The measurement lane starts only after the
G1 vertical path is stable.

### 5.1 V1 specification freeze lane

The first machine tranche now closes only the listed CEV1 foundation and Order
kernel carriers (contexts, validator/parameter facts, ordered roots, header,
Vote/QC, Timeout/TC, and minimum activation/handoff anchors) with 27 positive,
one ordered-root derivation, and 24 negative vectors plus a standard-library
authoring checker. A separately authored standard-library-only parser now
strictly decodes, re-encodes, semantically validates, and reproduces every
listed digest; it also rejects the complete negative corpus and checker-owned
malformed-input mutants. This is independent parser evidence only for this
closed candidate tranche. It is explicitly
non-normative and closed only for its listed types; it provides no proposal,
DA, execution, settlement, state-sync, light-client, cryptographic interop, or
complete formal-model evidence. Three bounded Quint candidates separately
check the weighted-order kernel, timeout-lock discipline, and epoch
handoff/activation with 15 bounded invariants, three reachable legal witnesses,
and seven retained mutants that must produce counterexamples. These finite
models are not a complete proof. All global evidence and freeze flags remain
false.

A second candidate tranche now checks the bounded Order signature surface with
an independent standard-library strict-Ed25519 verifier: four deterministic
validators, one Vote statement, two distinct Timeout statement roots, four QC
signatures and four complete per-entry TC statement/signatures, checked
weighted quorum, and 18 retained negative controls. It reproduces the
validator-set digests, Vote/Timeout domain separation, and the foundation TC
context/justification projection, but does not prove complete QC/TC transition
semantics, provide a light client, or make global crypto-interoperability or
freeze claims. A third bounded candidate checks the v0-to-v1 activation kernel
with one positive and 31 negative cases, exact CEV0/CEV1 validator-set hash
reproduction, independent old/new weighted quorums, strict role-separated
Ed25519 signatures, NoFallback, and the empty first-v1 projection. It does not
verify complete v0 governance/finality authority, execute migration, implement
a light client, or complete the upgrade contract.

A fourth cumulative candidate closes one cross-version carrier ambiguity
without changing frozen v0: it exact-decodes raw CEV0 `UpgradePlanV0` field
12, requires frozen fields 13/14 absent on the v0-to-v1 route, and verifies a
separate CEV1 `V0ActivationFirst` proposal witness plus its direct three-chain
finality. Its corpus has one positive and 44 exact-error negatives; the
stdlib verifier checks one proposer and twelve QC signatures, and OpenSSL
cross-checks all 13 valid signatures plus a bad control. This does not prove
field-12 governance membership/finality, complete source-v0 authority,
deterministic migration, full `OrderProposalV1` admission, durability, or
upgrade freeze. Those remain G1.5 blockers.

A fifth bounded candidate now composes same-version Order trust across exact
0/1/2/3-hop paths. The first nonempty step is still the existing raw
FreshGenesis transition; later steps use the new versioned checkpoint-anchored
carrier, so no old anchor tag is reinterpreted. The stdlib-only checker
strict-decodes and re-encodes every path/step, consumes each prior certified
head QC, derives each intermediate trusted state, enforces strict epoch/height
progression, and verifies 88 QC plus 24 handoff signatures in the three-hop
case. It binds the global length-prefixed `DigestV1` construction and exact
one-item `V1HandoffFirst` sidecar root over the complete handoff wrapper and
both signature lists. The third hop also exercises one exact epoch-start TC at
`initial_new_view+1`, bound to the identical handoff safe parent, no lock, and
the latest finalized checkpoint. Its 63 exact-error mutants—including empty,
wrong, and different-wrapper sidecar-root controls plus 11 TC controls—and all
116 OpenSSL cross-checks pass. This
closes only a bounded composition proof: v0 activation, weak-subjectivity
selection, arbitrary-length trust advancement, other proof classes, complete
wire/crypto conformance, a second implementation, and normative freeze remain
G1.5 blockers.

A sixth bounded candidate derives a trusted state from the exact
FreshGenesis-to-Ordinary source proof and verifies two sequential same-epoch
Ordinary finality advances. Each advance has exactly three certified headers,
consumes the prior certified-head QC, and permits at most one skipped view
under a complete checkpoint-anchored TC. Four positive controls, 52
exact-error mutants, and 48 OpenSSL QC/TC cross-checks pass. This remains a
bounded continuation relation: payload execution, arbitrary history, epoch
transition, global light-client completion, a second implementation, and
normative freeze remain G1.5 blockers.

A seventh bounded candidate now verifies deterministic weak-subjectivity
checkpoint renewal over that exact three-hop path. The prior and renewed
anchors are derived from authenticated checkpoint objects, with exact
chain/genesis/protocol lineage, epoch, validator-set, parameters, application
root, and state-schema-root bindings. Positive epoch/block trusting windows,
strict epoch/height advancement, minimum advance, and same-height conflict
rejection are exercised by two positive controls and 45 exact-error mutants.
Operator/governance authentication, wall-clock policy, arbitrary checkpoint
selection, unbounded history, complete wire/crypto interoperability, global
light-client completion, and normative freeze remain G1.5 blockers.

Freeze, review, and publish:

- protocol scope, threat model, trust boundaries, status taxonomy, and version
  negotiation;
- one canonical binary codec, object-kind registry, exact domain registry, and
  limits; no JSON or transport bytes as signing authority;
- the complete object catalog for protocol manifests, Agent/capability/session
  authorization, nonce lanes, tasks/offers/leases/checkpoints/results,
  verification profiles and attestations, challenges/settlements, DA
  descriptors/votes/certificates/repair/withholding/retention, BatchRefs,
  blocks/QCs/TCs/finality, consumption rollups, epochs/upgrades and light-client
  proofs;
- separate transaction-batch DA and AI-artifact DA namespaces and policies;
- proof-carrying task lifecycle and dual order/result finality;
- deterministic MVCC serial semantics, explicit receipt outcome, multi-resource
  fees, fee-delta aggregation, escrow conservation, and rollup challenge rules;
- v0-to-v1 upgrade plan, deterministic migration, dual-quorum handoff, first
  v1 block, no-downgrade rule, and independent light-client verification; and
- canonical byte/hash/signature/ID/root vectors, cross-version and cross-domain
  negatives, limits, reference parsers, fuzz corpora, and implementation-
  independent conformance harnesses.

Required formal models and retained failing mutants cover at least:

- weighted QC/lock/TC/three-chain safety with v1 BatchRef bindings;
- DA persist-before-attest, retrievability, withholding, repair and retention
  GC;
- proposal AC validation and complete retrieval-before-vote;
- capability scope/revocation/budget/expiry and nonce-lane replay safety;
- deterministic MVCC serial equivalence and conflict replay;
- task/escrow conservation, dual finality and forward-only challenge effects;
- consumption-rollup uniqueness, cumulative monotonicity and one settlement;
- multi-resource fee conservation and checked arithmetic;
- atomic migration, both handoff quorums, one configuration per height, no
  downgrade, and deterministic migration root; and
- multi-hop light-client verification with a non-rolling weak-subjectivity
  anchor.

The freeze requires independent consensus, canonical-encoding, application,
DA, cryptography, economics, and light-client review. `design-only` becomes
`spec-frozen` only when all normative documents, registries, vectors, models,
mutants, and review findings agree. It does not become `implemented`.

### 5.2 Minimal v0 measurement lane

Measure only enough v0 to establish a trustworthy external baseline:

- four equal-weight validators and seven unequal-weight validators;
- at least three physical hosts and controlled LAN/WAN delay/loss/jitter;
- empty, 512-byte and near-limit transactions, several block sizes, and low/
  high state-conflict workloads;
- normal operation, leader loss, one-third-minus-one Byzantine/offline power,
  3–1 progress, 2–2 safe stall, heal, restart, catch-up, and shortened epoch
  handoff; and
- committed goodput, p50/p95/p99 finality, CPU, memory, disk/fsync, network,
  state growth, recovery time, and unit resource cost.

Do not productionize the v0 full-payload network, add 31/100-node campaigns, or
market the baseline as AI-native performance. Its purpose is to locate costs
and provide a reproducible control for v1.

### Exit gate

- V1 normative freeze and independent review are complete with zero open
  Critical or High specification finding. This plan uses one severity
  vocabulary throughout: Critical, High, Medium, Low.
- The 4/7-node v0 dataset and harness are reproducible and honestly labelled.
- V1 implementation and production flags remain false.

## 6. G2 — implement the PoCO AI-native v1 stack

Build in dependency order; do not begin with an alternative Order theorem.

### G2A — certified DA

Current bounded tranche: `trnm-poco-da-v1` implements a local, full-replication
`TransactionBatch` candidate with durable-before-attest, author/queue bounds,
strict weighted certificates, retrieval, repair, retention, and durable GC.
Its local schema-v2 attestation journal has a checksummed high-watermark and
immutable durable manifest. GC can be exercised only through a test-only
permit issuer; production byte deletion is unreachable until Node finality/CAS
owns the authority. It has no network, ArtifactEvidence namespace,
BatchRef/Order integration, whole-node CAS, Node reachability, or production
signer/GC authority; therefore G2A and G2 remain incomplete.

A bounded follow-on closes only the cryptographic **full-range** portion of
remote retrieval/repair. An out-of-band pinned requester signs an exact
certificate/range/window request; a committee member signs a response whose
canonical per-chunk paths reach the certified chunk root. The verifier rebuilds
the complete transaction batch and yields a non-copyable carrier bound to the
target scope/store/config/certificate. Repair still passes through the original
immutable durable manifest and ends with a fresh complete-byte/certificate
readback. This is transport-independent candidate evidence: generic ranges,
requester registry, responder signer journal, peer routing, non-response/
withholding adjudication, ArtifactEvidence, Node integration and global G2 all
remain false.

- Implement bounded multi-worker transaction-batch and artifact dissemination,
  canonical descriptors, durable store manifests, durable-before-attest
  journals, weighted availability certificates, quotas and backpressure.
- Implement complete retrieval/reconstruction, repair, withholding evidence,
  retention/GC, restart reconciliation, and DA whole-node checkpoint facts.
- Integrate exact BatchRef + certificate verification and complete retrieval-
  before-vote with the retained HotStuff Order kernel.

Exit: no attestation can escape without its promised durable bytes; every
certified test batch remains retrievable through its retention/challenge
window under the admitted fault model; missing data never produces a Vote.

### G2B — Agent and task market

Current bounded tranche: `trnm-poco-agent-market-v1` implements a local
candidate for root capability/session grants, explicit nonzero session lanes,
one shared capability budget, `Task + funded Escrow`, Bid, atomic requester
lease acceptance (Task/Bid/Escrow/Bond/Lease), and provider Offered-to-Active.
It now enforces every representable Task/model/tool/profile/privacy/exact-
resource scope; unsupported `CommittedSet` and uncarried market/endpoint scopes
fail closed, and provider acceptance resolves its Lease back to the Task. Its
SQLite schema-v2 journal separates immutable genesis trust from a per-call
Order-finalized height/block context, persists a monotonic expected-tip CAS,
checks durable state/journal roots on every verified open/read/write, provides
exact replay/read-only reopen preflight/sidecar/schema/tamper rejection, and
permanently fences an ambiguous third state. It is not the global
`AgentTransactionV1` wire, complete identity/key/capability or task lifecycle,
an authenticated state tree, whole-node CAS, or Node-backed Order-proof
authority; committed-set verification, Verify/Challenge/Settlement and
production authority also remain absent. G2B and G2 remain incomplete.

- Implement Agent identity, capability grants/revocation, session keys,
  budgets, model/tool/endpoint/rate/time scopes, nonce lanes, and bounded Agent
  batches.
- Implement task specs, offers, leases, funded escrow, deadlines,
  checkpoint/resume, migration/cancel/timeout/refund, artifact references, and
  immutable verification/settlement profiles.

Exit: capability escalation and cross-lane replay mutants fail; task lifecycle
and escrow conservation models, vectors, property tests, and crash tests agree.

### G2C — compute verification and challenge

Current bounded tranche: `trnm-poco-verify-challenge-v1` implements a local
candidate for one `StakeQuorum` profile. It admits an exact provider-signed
receipt, counts strictly unique verifier identities under checked weight,
requires every claim to bind the same deterministic
statement/evidence/sequence, persists the atomic virtual BeginEvaluation plus
decision pair, and supports one challenge through evidence, response and
Upheld/Rejected bond resolution. Duplicate trust keys and inconsistent
verifier-set/profile commitments fail closed; verifier membership is fixed to
four, all revision/bond arithmetic is checked, and evidence is capped at 64
entries. Its schema-v2 SQLite journal immutable-read-only preflights an existing
store before writable access, persists a monotonic per-call Order-finalized
height/block CAS and checks durable state/operation-tail roots on every verified
access. The Order context
is not a proof and has no Node authority; ArtifactEvidence DA, the other six
verification classes, expiry/withdraw/appeal, concurrent challenges,
Agent/Market/Settlement integration, whole-store CAS, global wire and
production authority remain absent. G2C and G2 remain incomplete.

- Keep AI compute off chain and implement the frozen verification profiles:
  deterministic re-execution, reproducible ML, ZK, TEE, stake quorum,
  optimistic challenge, and explicitly subjective evaluation as separate
  semantics.
- Implement proof/evaluator/repair/challenge/settlement durable outboxes,
  idempotent result ingestion, deadlines, compensation, slash, and appeal rules.
- Separate BFT order finality from AI result/settlement finality; challenge
  success is a forward transaction, never a block rollback.

Exit: every result and settlement is traceable through exact task, lease,
profile, artifact, DA, proof, challenge and outbox IDs; no ambiguous `Valid`
status crosses profiles.

### G2D — deterministic parallel execution and fees

Current bounded tranche: `trnm-poco-mvcc-fee-v1` implements one local
single-block typed-object candidate. Every transaction declares exact read and
write object IDs; speculative parent-snapshot versions are validated in
gap-free transaction-index order and mismatches re-execute deterministically
against the canonical prefix. Success, Reverted and OutOfResource receipts bind
read/write versions, roots, conflict/retry evidence, four resource classes and
checked fees. Per-transaction fee deltas debit only their payer; sorted
block-end reduction credits each destination once, avoiding a global collector
write hotspot. SQLite schema v1 atomically persists objects, receipts, resource
totals, fee deltas and journal roots with immutable existing-store preflight and
exact crash/full-journal replay. This is not global AgentTransaction authorization, real
parallelism, JMT/state proof, the complete resource schedule, Order/Node
authority, Settlement or G2 completion.

- Implement object-aware MVCC with canonical read/write/conflict commitments,
  deterministic replay and reference serial semantics.
- Add explicit outcome/status receipts, batched authenticated-state commits,
  nonce-lane advances, block-level fee deltas, and hot-key-free distribution.
- Implement multi-resource fees and checked conservation across order, state,
  transaction DA, artifact DA/retention, proof verification, priority,
  challenge bonds, escrow, rewards, refunds, burn, and treasury.

Exit: randomized conflict schedules reproduce serial state/receipt roots;
runtime timing does not change validity; all assets/resources conserve under
success, failure, retry and crash.

### G2E — consumption rollups and integrated private alpha

Current bounded tranche: `trnm-poco-consumption-settlement-v1` implements one
local provider/consumer, one asset, one final-valid result and one rollup.
Current-height bilateral Ed25519 signatures bind a gap-free receipt chain;
usage and cumulative charge are recomputed from a committed price table. One
atomic rollup assigns every receipt, sets a chain-derived challenge-close
height, and a later caller-amount-free trigger derives provider payment,
consumer refund and protocol fee while conserving the full escrow exactly
once. SQLite schema v2 provides immutable preflight, durable state/journal and
finalized-block roots, full deterministic replay, direct-successor empty-block
coverage, and exact source/target/fence crash outcomes.
All bootstrap identities, DA/result/order facts remain local trust inputs, so
this does not close G2E or integrated private alpha.

### G2F — cross-plane fresh-readback consistency

The first G2F candidate now joins all five local G2 kernels using two exact
fresh-reopen samples, typed lifecycle IDs, and each store identity, monotonic
position, state/metadata root, and journal tail. It deliberately has no write
path. The DA head and selected certificate share one SQLite read snapshot, and
each terminal receipt must match the sampled store identity, sequence/height,
Order head and state root. The Order-proof digest remains a trust input. A later
Node-owned whole-node CAS must consume these exact facts before cross-plane
authority or integrated private-alpha completion can move true.

A bounded follow-on candidate now demonstrates that consumption shape inside
the Node crate without activating it. It independently verifies one pinned raw
CEV1 FreshGenesis direct three-chain Order proof in Rust, consumes the G2F
carrier, reopens and rejoins the five sources, requires exact projection
stability, then advances a distinct predecessor-bound checkpoint with
successor-only CAS and mandatory fresh source/target confirmation. Existing
checkpoint files receive immutable read-only schema/metadata preflight,
sidecar rejection, and exact file-identity revalidation before mutable PRAGMAs
or transactions. The finalized Order header does not authenticate membership
of the five-plane projection in its `post_state_root`: the Order proof and
stable projection remain parallel local co-observations,
`order_finalized_cross_plane_authority=false`, and no proof-to-state
substitution boundary is closed. The source stores are not one atomic snapshot
or transaction; anti-whole-store rollback, Node process wiring,
Ordinary/TC/handoff trust progression and global G2 are still open.

An additional non-Node candidate now implements one bounded global pre-vote
runtime over those real local kernels. It requires a freshly authenticated
certificate and complete local DA retrieval, exactly one strictly decoded
bounded candidate item, and the exact same five-store parent cut before and
after Agent/Market, Verify/Challenge, MVCC/Fee and Consumption/Settlement
preview. It commits their candidate roots and receipts, the certified DA
obligation and retrieved bytes into a domain-separated **candidate composite
root**, then advances a separate validation sequence only through an exact
successor CAS with mandatory fresh source, target and prepared-row readback.
The resulting private carrier is non-cloneable and can exist only after the
target has been reauthenticated; reopen exercises the same generation,
checksum and prepared commitment.

A follow-on now also closes the bounded normal-build source-apply cut. An
independently verified Order-finality carrier naming the exact prepared
candidate drives exact-replayable finalized application through all five
planes. Checksummed direct-successor finalized-block journals cover empty
blocks and same-block multi-operation execution, and fresh terminal readback
must match the prepared roots before the private, non-cloneable finalization
owner can exist. That owner binds the exact prepared generation/checksum,
candidate composite tip, five plane terminal receipt/root commitments and a
candidate-local final execution root. The history successor, finalized
evidence row and metadata CAS
commit in one SQLite transaction; exact retry, pre/post-commit response loss,
stale/fork/root substitution, reopen, partial/torn rows and logical metadata
rollback are executable controls. This is
`whole_node_finalization_cas=true`,
`normal_build_finalization_owner_issuer=true`, and
`source_plane_finalization_apply=true` for this bounded path. It does not
detect rollback of an entire database file without external anti-rollback
authority.

T0-C/T0-D separately carry the manifest-bound v2 path into a private Node data
journal. The only owner ingress consumes the exact non-Clone
`G2CandidateLocalFinalizeJoinV2`;
the journal never accepts a preview, raw request, root list, decoded snapshot,
or pin as an authority substitute. An anchor and its sole persisted successor
form a complete predecessor-bound history. `BEGIN IMMEDIATE` metadata CAS,
immutable source/target readback, path-level file/content identity checks and
external trusted-prefix pin data resolve exact retry and pre/post-commit
response loss. Receipt count is bounded before serialization; allocation-free
Borsh length counting and a hard-limited writer enforce the fixed snapshot
budget. A reopened target remains inert until a freshly regenerated typed join
encodes to the exact durable bytes.

The T0-E foundation first added the two authority-preserving prerequisites for
a real process tranche. Canonical Order-state now seals the manifest-bound
G2 block through a normal-build method that accepts its own non-forgeable
`RecoveredCanonicalOrderApplicationParentV1`, fresh-audits the complete store
and exact head pin before and after, and proves the seal is the unique direct
successor without exposing `OrderApplicationParentV1`. Separately, the
non-Clone T0-D owner retains its live SQLite journal and can crate-privately
rederive the full snapshot from the retained typed join across two fresh exact
journal audits.

The smallest normal-build process tranche is now statically wired behind
explicit candidate-only `prepare-g2-manifest-bound-candidate-v2` and
`run-g2-manifest-bound-candidate-v2` commands. It opens all five source stores
and canonical Order state through existing-only audited APIs, traverses the
normal input/preview/recovered-parent/seal/exact-join chain, consumes only that
typed join at T0-D, and holds the live stores, canonical store, T0-D journal,
independent process-pin CAS file and exclusive OS lock in one non-Clone owner.
The process-pin anchor seals the exact-join commitment produced during prepare;
prepare retries under the exact stable lock rerun the full issuer and reconcile
only the ordered durable prefix through that anchor. The run path requires
external manifest/process-pin checksums, rejects a fresh issuer mismatch before
T0-D consumption, permits an old external anchor only for the byte-exact unique
target reconstructed from the same issuer and T0-D successor, and reconciles
only an exact temporary target. The target schema binds journal ID, process
scope, generation, predecessor and direct canonical height. `READY` follows a
second fresh issuer/revalidation pass, after which control-stdin EOF performs a
final audit and clean shutdown. A normal-build integration target plus private
schema/temp/lock/rollback tests are present as source. Its feature-gated
fixture builder constructs real DA plus all five source stores, a canonical
Order parent and exact manifest, while exposing no typed join/owner input to
the unchanged normal CLI. The feature integration target now passes all 7/7
tests. Its real normal-binary matrix observes a byte-stable PREPARED retry, P1
READY, duplicate-lock refusal before READY, P1 SIGKILL (signal 9), and a
different-PID P2 launched with the saved old anchor recovering the same unique
target before READY and clean stdin-EOF shutdown. Five dynamic negative
classes—DA mode drift, canonical Order mode drift, malformed temporary target,
process-pin rollback after an externally observed target, and T0-D journal
rollback—each fail before READY. The full feature suite (74 unit, 7 process,
7 doc tests), strict all-target Clippy, the global boundary and project
preflight (`errors=0`) also pass. Therefore only the candidate-local process
integration, external-pin process persistence, and external-pin-authenticated
process-owner facts are true; whole-Node, rollback, and G2 facts remain false.

These separate path/hash/rusqlite opens only narrow the replacement window.
They do not retain an `openat`/directory-descriptor identity, close a malicious
same-UID rename race, pin the namespace inode/effective-UID owner, or provide an
authenticated production anti-rollback root beyond the operator-retained
external checksum. The database-only rollback test therefore is not coherent
pin-plus-database rollback protection. This closes candidate-local normal Node
process reachability only, not whole-Node commissioning, vote eligibility,
whole-node rollback authority, or G2.

A further bounded path now closes the local Order-state membership binding.
The independent Order-state writer consumes the real non-Clone linear terminal
owner into an exact-parent create-once permit, proves the derived tag-50 key
absent, commits its immutable version-zero value, and freshly reconstructs the
successor receipt and canonical 256-sibling proof. A typed receipt projection
can issue the non-Clone positive carrier only when separately verified later
Order finality names that exact height/root and proves the encoded candidate as
a strict certified ancestor. The global refinement seam then checks context,
candidate height/block, composite root, and final execution root against the
retained owner. Public terminal commitments, raw CEV1 claims, cloneable create
material, and fabricated receipt projections remain non-authority. The global
crate itself still has `order_binding_positive_carrier_issuer=false`, while the
cross-crate local path makes `order_state_membership_binding=true`.

This is `candidate_runtime_implemented=true`, not G2 completion. The item is
not the normative `AgentTransactionV1` wire, the composite root is not the
application JMT root, and there is still no multi-level overlay, canonical Node
Order-state commissioning, coherent whole-store rollback authority, Node
process owner for the global runtime, state sync, signing or broadcast. The
manifest-bound candidate-local persistence tranche has
`node_process_integration=true`, while the global execution tranche and top
level retain `node_process_integration=false`; `g2_global_complete=false`
remains fail-closed.

- Implement bilateral/versioned consumption receipts, cumulative roots and
  totals, artifact/measurement DA references, sampling proofs, challenge
  windows, rollup resolution, settlement, relationship status and PoCO
  maturity eligibility.
- Integrate DA, Order, execution, task, verification, challenge and settlement
  into one native node while PoCO economic weight remains shadow-only.
- Complete v1 snapshot/state sync, cross-version transition proof, independent
  v1 light client/parser, remote signer/HSM interface, metrics and operator
  recovery tools.

Exit: a private alpha passes complete transaction/task/rollup lifecycles,
cross-crash recovery, deterministic state sync, and shortened v0-to-v1 upgrade
campaigns. It is not yet public-testnet ready.

## 7. G3 — 7/31/100-validator WAN profiling and Order decision

The authorized six-host `192.168.0.0/24` fleet first closes a distinct LAN
campaign. Its frozen 7/31/100 placement, read-only readiness probe,
content-addressed raw-evidence acceptor, and private ephemeral-key material
generator exist, but no validator run is yet complete. Every validator must be
one independently observed OS process using a run-unique Ed25519 key with a
verified proof of possession. A LAN pass may set only the LAN evidence bit;
`g3_geo_wan_evidence` remains false until the same signed candidate is run
across controlled geographic regions.

Run the same signed artifact, genesis, workload generator, fault schedule and
measurement contract at 7, 31 and 100 validators across controlled regions.
Matrices include:

- transaction and artifact size, batch size, worker count, conflict rate,
  read/write-set width, receipt/proof size and retention profile;
- normal, slow leader, leader crash, bandwidth-constrained leader, equivocation,
  selective omission/censorship, withholding, repair storms, DDoS, partition,
  heal, validator restart, state sync, epoch handoff and key rotation;
- committed goodput, finality tails, DA certify/retrieve/repair latency, MVCC
  abort/replay, proof/challenge/settlement latency, availability, state growth,
  recovery, CPU/GPU, memory, disk and network cost; and
- identical-hardware external baseline comparisons that do not enter the
  production dependency or release closure.

The profiler must attribute the dominant tail and resource bottleneck to DA,
Order, execution, state storage, signing, sync, proof verification, application
conflicts, or operations. A new Order mechanism is considered only if the
target hard requirement is formalized and DA/execution separation still leaves
Order as the measured blocker.

Decision routing:

- happy-path latency bottleneck: evaluate Jolteon/Fast-HotStuff style changes;
- long asynchronous/DDoS liveness bottleneck: evaluate a bounded fallback
  protocol;
- certified-DA leader censorship or residual bandwidth bottleneck: evaluate a
  multi-proposer DAG Order profile;
- formally prioritized tail-fork/MEV fault isolation: evaluate an explicitly
  specified tail-fork-resistant variant; and
- blob bandwidth/retention bottleneck: improve dissemination, erasure coding
  or sampling rather than changing BFT finality.

An Order replacement requires a new protocol version, safety model, liveness
model, negative mutants, independent proof review, two interoperable
implementations, migration/light-client rules, WAN fault evidence and an ADR.
Otherwise v1 retains weighted chained HotStuff.

### Exit gate

- The full dataset, harness, manifests, raw metrics and analysis are
  reproducible.
- No conflicting finality or state-root divergence occurs in the admitted
  fault model.
- The Order decision is an evidence-backed retain/amend/replace ADR, not a
  benchmark anecdote.
- Marketing claims are limited to achieved committed-goodput, latency,
  availability and cost evidence.

## 8. G4 — adversarial and public-validation gates

### Required campaigns

- 72-hour continuous chaos followed by 7-day and 30-day multi-region soak;
- repeated process and host power loss at every Safety, signer, DA, execution,
  outbox, finalization, sync, migration and whole-node checkpoint boundary;
- database, WAL, snapshot, namespace and full-machine rollback; disk full,
  corruption, fsync uncertainty, clock skew, key loss/rotation, HSM/KMS outage,
  network eclipse, DDoS, censorship, withholding, repair and GC pressure;
- unequal PoCO weight in shadow across many epochs, related-party/Sybil and
  correlated-penalty simulations, challenge and settlement adversaries;
- reproducible builds, signed artifacts, SBOM/provenance, dependency/license
  review, secret scanning, fuzzing, supply-chain and disaster-recovery drills;
  and
- independent full-node/parser interoperability, independent light client,
  external consensus/cryptography/DA/application/economics/security audits,
  and a public bug-bounty process.

### Public-testnet gate

A public testnet requires all prior gates, operational RPC/read APIs,
monitoring/alerts, incident replay, documented upgrades, backups/restores,
validator onboarding/key management, state-sync capacity, published limits,
and closure or explicit acceptance of every Critical/High audit finding. PoCO
economic influence remains capped or shadow until its separate economic gate
passes.

### Mainnet activation gate

Mainnet requires an explicitly finalized activation decision and
machine-verified release manifest after:

- all production contracts have implementation and crash evidence;
- two interoperable consensus/light-client implementations or an explicitly
  reviewed equivalent independence plan exist;
- public adversarial operation and multi-epoch upgrade evidence pass;
- the security council/governance, incident response, release signing,
  rollback/recovery and vulnerability-disclosure processes are operational;
- every Critical/High issue is closed and remaining risk is published; and
- `zero_comet_production_dependency_achieved`, `production_candidate`, and
  `production_consensus_activation` change only in the exact release that
  actually satisfies their gates.

## 9. Reporting cadence and stop conditions

Each gate publishes a signed evidence index containing source commit, protocol
manifest, toolchain, binaries, SBOM, topology, workload, fault schedule, raw
metrics, test/formal results, known gaps, and status flags. Weekly reports state
only changed evidence and blockers; they do not convert planned work into
percent-complete readiness.

Work stops and fails closed on conflicting finality, state-root divergence,
double-sign, lost durable obligation, unavailable certified data inside its
promise, nondeterministic migration or MVCC result, settlement/asset imbalance,
light-client acceptance of an unauthorized set, whole-node checkpoint
ambiguity, or a truth-manifest/release mismatch. The affected gate reopens
after root cause, retained regression mutant, remediation, and independent
review.
