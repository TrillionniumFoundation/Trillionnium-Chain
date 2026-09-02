# Trillionnium Chain Development Plan v2

Plan ID: `trnm-chain-development-plan-v2`  
Effective: **2026-09-02 (Asia/Singapore)**  
Status: **sole active engineering plan; candidate-non-normative until independently accepted and merged through protected `main`**  
Canonical destination: `refs/heads/main`  
Active integration candidate: Draft PR **#62**, `refs/heads/work/plan-v2-full-gap-closure-20260902`  
Assessed integration baseline: `work/plan-v2-full-gap-closure-20260902@af691ea5005e1f0262e90c4fc878ba0a70dbe7ea`  
Assessed tree: `af09e389b1a462b3839508b7ef305596c76384c6`  
Current PR head, source tree, prospective-merge commit, and prospective-merge tree are derived at verification time and may not be copied from this prose.

Machine truth: [`../../config/consensus-mainline.json`](../../config/consensus-mainline.json)  
Snapshot: [`CURRENT_SNAPSHOT_V1.json`](CURRENT_SNAPSHOT_V1.json)  
Module registry: [`module-registry-v1.toml`](module-registry-v1.toml)  
Module coverage: [`../../config/module-coverage-v1.toml`](../../config/module-coverage-v1.toml)  
Module technical reference: [`../modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md`](../modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md)  
Release train: [`release-train-v1.toml`](release-train-v1.toml)  
Manifest: [`plan-manifest-v1.toml`](plan-manifest-v1.toml)

---

## 0. Authority, truth hierarchy, and non-claims

This is the **one active engineering plan** for Trillionnium Chain. It alone defines development sequencing, module ownership, integration policy, gate order, and the next executable action. Machine truth, protocol specifications, schemas, vectors, formal models, architecture decisions, module technical references, runbooks, audits, benchmarks, and evidence records remain authorities only for their own domains; none is a second roadmap.

Current machine truth remains:

```text
stage = G1-native-host-incomplete
production_candidate = false
production_consensus_activation = false
public_testnet_ready = false
release_ready = false
```

**No machine flag is promoted by this plan.** A document edit, source commit, pull request, hosted check, self-hosted check, candidate fixture, simulation, benchmark, carrier workflow, local process run, or generated report cannot authorize production, public testnet, release, protocol activation, security certification, or a performance claim. PoCO AI-native v1 remains design/candidate work unless its own normative, implementation, external-evidence, governance, and activation gates close.

Truth precedence is:

1. signed activation or governance record bound to an accepted release;
2. machine truth and protected repository policy;
3. frozen normative protocol inputs and exact canonical registries;
4. this hash-bound plan;
5. module contracts, release projection, and runbooks;
6. exact-source evidence and independent review;
7. pull-request, issue, comment, or chat text.

Protected `main`, assessed baseline, current PR head, prospective merge, built artifact, evidence submission, accepted release, and activated network identities are distinct and may not be substituted.

### Documentation anti-pollution rule

Development history lives in Git history, closed pull requests, immutable evidence, and source-bound audits. Active content must satisfy:

- `docs/development/` has one regular Markdown file: this plan;
- the legacy evidence-contract path is only a symlink to this plan;
- no agent prompt fleet, package narrative, per-PR roadmap, sprint board, continuation note, dated delivery plan, or active archive may reappear;
- compact JSON/TOML beside the plan carries current source, module, release-train, and gate facts;
- stable technical material belongs under protocol, architecture, modules, runbooks, schemas, formal, or evidence surfaces and may not assign a competing work sequence;
- stale branches, people, dates, local absolute paths, and completion percentages are observations, never authority;
- CI rejects a second active plan, a retired historical tree, stale active references, orphan crates, duplicate module ownership, dependency cycles, and missing module contracts/SLO/testkit entries.

---

## 1. Current assessment and selected successor

Protected `main` was observed at `b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9`. It is the canonical destination but not the assessed implementation baseline for this plan.

Draft PR #62 is the sole selected integration successor. Its assessed baseline combines:

- the descriptor-bound A04/A19/A23 application/finality/replay source train;
- the Plan v2 single-development-truth structure;
- the Node Commit Ledger implementation;
- persistent deterministic 1/2/4/8-worker execution equivalence;
- exact-source and prospective-merge document validation;
- M00-M17 technical references and exact primary ownership for every active workspace crate and auxiliary package.

The assessed baseline is an ancestor of the current PR head. It is not release, production, activation, or independent-acceptance authority. Any later commit invalidates prior exact-head evidence and must rerun applicable checks.

### 1.1 Repository implementation retained

The selected source line contains repository implementations for the following previously open areas:

1. descriptor-bound SQLite database and sidecar identity around authoritative operations;
2. closed-world SQLite schema and pragma checking;
3. post-close/post-operation validation before trusted return;
4. a monotonic, hash-chained Node Commit Ledger and recovery coordinator;
5. persistent deterministic execution comparison at 1, 2, 4, and 8 workers;
6. one active engineering plan and fail-closed documentation-reference validation;
7. machine coverage for all eighteen modules, all active workspace crates, contracts, Web4, formal, fuzz, transport, and CI/evidence tooling.

These facts mean **implementation present**, not **accepted closed**. Closure additionally requires unchanged exact-head checks, prospective-merge checks, independent review, protected-main integration, post-merge replay, and any external evidence required by the affected gate.

### 1.2 Current promotion-critical gaps

The shortest honest path remains:

1. keep PR #62 as the sole successor and supersede overlapping PRs without losing immutable evidence;
2. complete all non-skipped exact-head and prospective-merge gates on the same source;
3. obtain independent module-owner, consumer, security, and release review;
4. enforce crate/module dependency and production-build closures;
5. decompose the node composition hotspot and finish the persistent validator host;
6. close authoritative networking, pacemaker, Vote/Timeout, finality, transaction lifecycle, state sync, and restart convergence;
7. complete migration rehearsal, reproducible release artifacts, custody, external audit, multi-host fault campaigns, power-loss evidence, and wall-clock soaks;
8. retain every production and activation flag as false until an authorized signed record changes machine truth through protected review.

---

## 2. Target architecture

Use a **deterministic modular monolith for the consensus hot path**, **selective process isolation**, and an **out-of-band global control plane**:

```text
Global control plane: registry -> telemetry -> constrained planner -> policy guard
                                      |
                              signed bounded plans
                                      v
authenticated ingress -> Order -> Execution -> State -> Finality
        |                  bounded in-process contracts                |
        +-------------- durable Node Commit Ledger -------------------+

isolated where useful: signer/HSM, DA workers, state-sync download,
RPC/indexer, proof generation, telemetry/evidence collection
```

Consensus, SafetyRules, deterministic scheduling, canonical state commit, finality, checkpointing, and recovery may not depend on synchronous remote control-plane RPC. Large models, nondeterministic inference, private datasets, long outputs, external tools, and subjective judgment remain off-chain. The chain orders and settles commitments, availability facts, proofs, challenges, declared verification profiles, and deterministic application transitions.

### Dependency law

```text
primitives -> contracts -> pure cores -> bounded adapters -> node composition
```

Contract crates depend only on primitives, canonical codecs, and approved cryptographic interfaces. Pure cores own no filesystem, socket, wall clock, thread pool, process, database connection, signer, environment variable, or remote service. Adapters do not leak storage or transport implementations into domain contracts. Composition wires implementations but contains no domain state machine.

Cross-module calls use versioned ports, immutable events, authenticated proofs, or consumed non-cloneable capabilities. Implementation-to-implementation horizontal edges, cycles, and production dependencies on lab, fixture, research, PoC, v1-candidate, or legacy consensus code are prohibited.

---

## 3. Eighteen long-lived modules

Crates are implementation units, not organizational boundaries. Every engineer has one primary module. Every active workspace crate and auxiliary package has exactly one primary module in `config/module-coverage-v1.toml`; secondary consumer relationships do not transfer authority.

| ID | Module | Responsibility | Placement | Staff |
|---|---|---|---|---:|
| M00 | Protocol / Schema / Codec | versioned types, domains, limits, codecs, vectors, error registry | library | 2 |
| M01 | Crypto / Identity / Capability | verification, identities, capability carriers, signer protocol | library / signer | 3 |
| M02 | Order / Consensus Kernel | PoCO-BFT state machine, QC/TC, epoch, pacemaker contract | hot path | 4 |
| M03 | Safety / Signer / Checkpoint | Safety authority, journal, watermark, checkpoint CAS | hot path / HSM | 4 |
| M04 | P2P / Session / Dissemination | authenticated sessions, leases, bounded ingress, gossip | I/O runtime | 3 |
| M05 | Tx Admission / Mempool | budgets, nonce/replay, WAL, handoff, tombstone/GC | in process | 2 |
| M06 | Execution / MVCC / Meter | speculation, conflicts, re-execution, multidimensional meter | hot path | 4 |
| M07 | State / JMT / Storage | state tree, proofs, pruning, namespace and schema ownership | hot path | 3 |
| M08 | Finality / Commit / Recovery | ordered finality, commit ledger, restart convergence | hot path | 3 |
| M09 | Data Availability | batch/artifact commitments, retrieval, repair, withholding evidence | workers | 2 |
| M10 | Agent / Task / Market | agent identity, capability, task/lease/escrow lifecycle | application | 2 |
| M11 | Verify / Challenge | profiles, result authority, challenge/appeal lifecycle | core / workers | 2 |
| M12 | Settlement / Economics | fees, escrow conservation, rewards, slash, refund | application | 2 |
| M13 | State Sync / Light Client / Proofs | checkpoints, sync, proof verification, weak subjectivity | verifier / downloader | 3 |
| M14 | RPC / Indexer / SDK / CLI | non-authoritative client and query surfaces | services | 2 |
| M15 | Node / Packaging / Release | wiring, lifecycle, build closures, binaries, reproducibility | composition | 2 |
| M16 | Global Control Plane | registry, observation, planning, rollout, rollback | out of band | 2 |
| M17 | Observability / Benchmark / Security / Evidence | metrics, fault/fuzz/formal/audit/evidence tooling | tooling | 3 |

Target allocation: 48 engineers.

### 3.1 Module documentation and coverage contract

Each module converges to:

```text
versioned contract
pure or explicitly non-authoritative core
bounded adapters
optional isolated service
testkit profile
SLO profile
evidence roots
two-maintainer minimum
machine dependency/capability descriptor
```

`docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md` defines stable scope, authority, interfaces, invariants, failure/recovery, security, verification, and SLO expectations. It is not a roadmap and does not establish implementation.

`config/module-coverage-v1.toml` maps:

- every active Rust workspace crate exactly once;
- every external-contract crate;
- Web4;
- formal models;
- fuzz workspace;
- transport schemas;
- CI and evidence tooling.

The coverage gate fails on an orphan or duplicate crate, missing path, invalid module ID, dependency cycle, missing technical section, missing SLO/testkit/contract entry, insufficient maintainers, production contamination policy drift, or control-plane authority drift.

A module is complete only when its source, contracts, tests, testkit, SLO, owners, capabilities, runbooks, and evidence are all source-bound and accepted. Documentation completeness is not implementation completeness.

---

## 4. Deterministic concurrency and canonical commit

Serial authorities are:

- consensus transition;
- SafetyRules and signer watermark;
- canonical order;
- canonical state-root commit;
- finality advancement;
- checkpoint replacement;
- Node Commit Ledger sequence;
- protocol activation.

Bounded parallel work includes sessions, decode/admission, batch signature verification, DA fetch/repair, prevalidation, immutable-parent MVCC speculation, proof/receipt construction, snapshot chunks, RPC/indexing, analytics, and evidence processing.

```text
authenticated ingress
 -> bounded decode/admission
 -> canonical order
 -> immutable parent snapshot
 -> parallel speculation
 -> deterministic conflict detection/re-execution
 -> serial canonical commit barrier
 -> Node Commit Ledger
 -> state/finality/checkpoint projections
```

Worker count, CPU topology, scheduling, retry timing, queue interleaving, and process placement must not change canonical roots, receipts, fees, events, proofs, or finality. Test at 1/2/4/8 workers across clean, conflict-heavy, crash/restart, and replay cases.

Every queue and operation has explicit byte, item, depth, allocation, signature-work, state-access, event, CPU, memory, network, and storage limits. `u32::MAX` is not an acceptable effective transaction-count bound.

---

## 5. Persistence and recovery

### 5.1 `PinnedSqliteNamespace`

All authoritative SQLite stores share one reviewed capability providing:

- canonical parent-directory descriptor ownership;
- no-follow and descriptor-relative opens where supported;
- database and WAL/SHM/journal/lock/anchor identity;
- closed-world `sqlite_schema` digest and pragma profile;
- chain, store, role, generation, and configuration binding;
- pre-open, post-open, pre-return, post-close, and reopen checks;
- distinct fresh-create, read-only, and read-write modes;
- fail-closed unsupported-platform behavior;
- retained path, link, mount, sidecar, schema, rollback, replacement, and partial-inventory mutants.

No authoritative operation may return trusted state before connection close and final namespace/schema revalidation. A coherent whole-store rollback plus rollback of its external trusted anchor remains outside a local SQLite store and must be prevented by the Node checkpoint/anchor design.

### 5.2 Node Commit Ledger

Use one append-only, hash-chained, monotonic node authority rather than cross-database hope or an unproved two-phase commit:

```text
Prepared -> ApplicationSealed -> SafetyPersisted -> SignIntentPersisted
 -> SignatureConfirmed -> FinalityApplied -> CheckpointConfirmed
 -> OutboundPublished
```

Each record binds node generation, chain/validator/application identity, height/view/block/parent, proposal and proof digests, pre/post roots, receipt/event roots, Safety revision, signer watermark, finality proof, checkpoint predecessor, previous record digest, and durable sequence.

Subordinate stores are idempotent projections or explicitly named independent authorities. Recovery reaches the exact durable source or exact durable target. Ambiguity fails closed with a machine-readable stop, rebuild, or independent-review action.

### 5.3 Required crash boundaries

The full fault matrix covers at least:

- before and after application seal;
- before and after Safety persistence;
- before and after sign-intent persistence;
- hardware signer applied but response lost;
- signature confirmed but publication response lost;
- before and after finality apply;
- checkpoint CAS applied but response lost;
- WAL/SHM/journal partial persistence;
- disk full, I/O error, fsync failure, and controller-cache loss;
- file, directory, mount, link, sidecar, schema, and generation replacement;
- process restart and independently controlled process takeover;
- physical power interruption and reboot.

Local SIGKILL and file-watermark tests do not replace physical durability or external monotonic-anchor evidence.

---

## 6. Persistent validator vertical path

The production candidate path is:

```text
Tx admission -> authenticated dissemination -> canonical order
 -> deterministic MVCC -> canonical JMT
 -> application seal -> Safety/Core -> sign intent
 -> hardware signature -> publication -> ordered finality
 -> durable apply -> checkpoint -> restart replay -> state sync
```

### 6.1 Order and Safety

M02 remains deterministic and I/O-free. M03 owns persist-before-sign state, signer intent, watermark, checkpoint, and custody adapters. A live host must provide persistent pacemaker, Vote/Timeout, QC/TC, epoch handoff, arbitrary proposal bodies, catch-up, and retained ancestry without allowing local overload or remote control-plane loss to alter deterministic validity.

### 6.2 Networking

M04 must deliver authenticated peer identity, chain/profile negotiation, bounded ingress, replay protection, backpressure, peer/global quotas, and Byzantine packet handling. Connection or queue failure may delay progress or return retryable local unavailability; it cannot fabricate deterministic invalidity.

### 6.3 Transaction lifecycle

M05 must close canonical decode, authorization, nonce/replay, fee/resource admission, WAL, replacement, proposal handoff, finalized readback, tombstone, and GC. GC requires finalized proof and replay-floor authority.

### 6.4 State sync and client proof

M13 must verify arbitrary-length finality/trust paths, weak-subjectivity anchors, epoch transitions, state-sync catalogs/chunks, closed-world schema, root closure, and non-destructive install. Network majority alone cannot choose a trust anchor.

The vertical path exits only when full candidate validator behavior survives crash cuts, Byzantine networking, restart/rejoin, state sync, and 1/2/4/8-worker invariance. Production flags remain false until later gates close.

---

## 7. PoCO AI-native v1 boundary

PoCO AI-native v1 remains a new protocol-version candidate, not a silent amendment to frozen v0. Its logical planes are:

1. Agent and capability;
2. Market, task, lease, and escrow;
3. Compute receipts, verification, and challenges;
4. certified transaction/artifact data availability;
5. coordination, deterministic execution, settlement, and Order.

Candidate kernels are useful implementation evidence but do not establish global wire freeze, interoperability, node reachability, state-tree inclusion, production authority, or activation.

Before G1.5/G2 closure, v1 requires:

- complete exact bounded parameters;
- closed machine schemas and registries;
- canonical positive/negative vectors;
- independent parser, re-encoder, crypto verification, and light client;
- formal obligations and retained unsafe mutants;
- all profile classes and application transitions;
- whole-node checkpoint and recovery integration;
- v0-to-v1 source verification, migration, target-root recomputation, and no-fallback activation;
- reproducible node/release artifacts and independent external review.

No v0 signature or object is re-encoded and treated as a v1 signature or object by inference.

---

## 8. Node, build, packaging, and migration closures

Decompose the `trnm-poco-node` hotspot into:

- kernel host;
- authority coordinator;
- I/O runtime;
- composition;
- CLI;
- lab/evidence fixtures.

The production composition layer performs wiring only.

Require separately checked closures:

```text
node-prod-v0
node-devnet-v0
ai-v1-candidate
lab-and-evidence
```

`node-prod-v0` contains no v1 candidate, lab, fixture, benchmark, mock authority, research, PoC, or legacy Comet runtime dependency. No Cargo feature combination may silently activate candidate authority.

**Repository implementation present; exact-head acceptance pending.** `config/build-closures-v1.toml` freezes all four closure roots and forbidden groups. `scripts/ci/check_build_closures_v1.py` recursively resolves local normal/build features, rejects production contamination, and can compare the result with Cargo's locked offline `cargo tree`. The default `trnm-poco-node` closure now resolves zero AI-v1 candidate packages; all eleven AI-v1 package edges and G2 commands/modules require the explicit `ai-v1-candidate` feature. Hosted and X230 gates must still compile both default and explicit-candidate forms on the unchanged source before this blocker is accepted.

Reproducible packaging binds source/tree, plan, protocol, module registry, coverage, configuration, compiler, dependency lock, feature closure, binaries, containers, SBOM, provenance, signatures, and operator handoff.

Migration uses a trusted finalized source verifier, exact export, target projection, root recomputation, and a fresh PoCO genesis. In-place DB/WAL rewriting and importing legacy validator signing state are prohibited. Removal of migration residue requires signed cutover evidence, cross-peer genesis/QC agreement, downgrade prohibition, and completed differential replay preservation.

---

## 9. Global control plane

M16 is observer-first and out of band. Each module publishes a versioned descriptor and a performance Pareto frontier: contract/implementation/dependency digests, capabilities, limits, tunables, invariants, workload validity region, committed goodput, p50/p95/p99 latency, CPU/memory/disk/network cost, queue pressure, error/drop rate, recovery cost, and evidence IDs.

The planner uses lexicographic constrained optimization:

```text
minimize safety violations, determinism violations, durability violations,
compatibility violations, p99 finality, resource/recovery cost,
and negative committed goodput — in that order
```

The first four must be zero.

A signed `OptimizationPlanV1` binds source graph, contracts, workload assumption, bounded resources, workers/queues/batches, placement, parameter class, activation boundary, expected effect, expiry, and rollback. `ActionReceiptV1` reports exact acceptance or rejection, generation, applied digest, resulting configuration, invariant results, and measured effect. A node-local independent guard is final acceptance authority.

Parameter classes are:

- **ConsensusCritical** — governance plus explicit epoch/height activation only;
- **DeterminismCritical** — only after root invariance and shadow replay;
- **OperationalLocal** — bounded automatic adjustment may be allowed.

M16 cannot sign, vote, finalize, create an authoritative root, modify SafetyRules, bypass admission, erase evidence, rewrite history, force incompatible startup, or activate production. On control-plane loss, nodes retain the last accepted safe plan; optimization stops, consensus does not.

---

## 10. Team, ownership, and merge train

Each critical module has at least two maintainers. CODEOWNERS migrates from personal fallback ownership to real module teams when those teams are provisioned. The author cannot provide independent acceptance.

Cross-module work normally uses:

```text
PR A: contract/version/limits/vectors/mutants
PR B: producer implementation
PR C: consumer adoption and aggregate replay
```

Limits:

- one active implementation PR per module;
- one successor per integration surface;
- at most five concurrent writers across consensus, Safety, state, finality, and recovery;
- no direct edits to another module implementation without its owner;
- base movement invalidates exact-head evidence;
- overlapping work declares one successor or closes.

Merge train:

```text
contract freeze -> module qualification -> consumer replay
 -> integration candidate -> exact PR-head checks
 -> prospective-merge checks -> independent review
 -> protected-main merge -> post-merge verification
```

Skipped, cancelled, queued, stale, synthetic, self-authored, or different-head runs are not acceptance. CI layers are:

- L0 module;
- L1 contract/conformance;
- L2 merge queue, recovery, root invariance, dependency closure;
- L3 independent multi-host, HSM, power-loss, audit, and soak evidence.

---

## 11. Ordered execution program

### D0 — single development truth

**Repository implementation present.** One active plan, compact machine companions, retired-tree prohibition, exact source/merge document binding, and active reference closure are implemented. Every new exact head must rerun the gate. Exit requires the same checks on protected-main merge and post-merge source.

### P0 — selected integration integrity

PR #62 is the sole selected successor. Preserve the descriptor-bound SQLite namespace/schema/post-check implementation, declare old overlapping PRs superseded, and obtain unchanged exact-head plus prospective-merge checks and independent acceptance. No gate is promoted merely because implementation is present.

### P1 — module and production boundaries

**Module coverage implementation present.** All active workspace crates and auxiliary packages map to M00-M17 with stable technical contracts, SLO/testkit profiles, owner policy, and an acyclic declared module graph.

**Production dependency-closure implementation present; acceptance pending.** The machine registry and recursive resolver now enforce separately named production, devnet, AI-v1-candidate, and lab/evidence closures; the default node has zero AI-v1 package edges. Remaining P1 work is exact-head and prospective-merge Cargo-tree/compiler acceptance, continued zero forbidden edges under future feature changes, real module-team ownership, and node decomposition. Exit: generated dependency/ownership views match Cargo's locked graph, composition contains wiring only, and `node-prod-v0` remains free of candidate/lab/legacy contamination.

### P2 — whole-node durability

**Node Commit Ledger implementation present; acceptance pending.** Complete integration across Safety, signer, application, finality, checkpoint, publication, and external recovery ownership. Prove every crash cut, disk/controller failure class, exact source-or-target convergence, and independently anchored rollback resistance.

### P3 — persistent validator

Complete persistent authenticated networking, pacemaker, arbitrary proposals, Vote/Timeout, epoch, receipts, catch-up, transaction lifecycle, production state sync, finality/readback, and restart/rejoin while preserving 1/2/4/8-worker canonical equivalence.

### P4 — selective isolation

Externalize signer/HSM, DA workers, state-sync downloader, RPC/indexer, proof generation, and telemetry/evidence only where security or scaling improves. Use versioned protocols, persistent intents, idempotent IDs, deadlines, backpressure, authenticated identity, and uncertainty recovery. Do not microservice the commit path.

### P5 — guarded control plane

Deliver registry and read-only observation first; then telemetry/workload classification, signed plan/receipt, offline planner, shadow evaluator, local guard, canary/rollback, bounded OperationalLocal tuning, and only later DeterminismCritical tuning after invariance evidence.

### P6 — migration and external promotion

Complete trusted source verification, exact export and root recomputation, multi-party cutover rehearsal, cross-peer agreement, downgrade prohibition, reproducible artifacts, independent audits, custody, fault campaigns, soaks, governance, and activation. G5 remains false until an explicit signed governance record updates machine truth through protected review.

---

## 12. Prioritized blocker ledger

| P | ID | Owner | Current state | Exit |
|---|---|---|---|---|
| P0 | DOC-TRUTH-001 | M15/M17 | implementation present | exact head, prospective merge, protected-main and post-merge document truth all pass |
| P0 | MODULE-COVERAGE-001 | M00-M17 | implementation present | every source unit remains uniquely mapped; technical/SLO/testkit/owner/dependency checks pass |
| P0 | INT-STACK-001 | M15/M17 | open | PR #62 sole successor; overlaps superseded; all required exact-head/merge checks and independent review pass |
| P0 | A19-NS-001 | M07/M08 | implementation present, acceptance pending | descriptor-bound DB and sidecar identity passes all replacement/rollback/reopen mutants |
| P0 | A19-SCHEMA-001 | M07 | implementation present, acceptance pending | closed-world schema/pragma digest passes exact-source qualification |
| P0 | A19-RETURN-001 | M07/M08 | implementation present, acceptance pending | no trusted return before close/post-check; crash/replay qualification passes |
| P1 | NODE-COMMIT-001 | M03/M07/M08 | implementation present, acceptance pending | monotonic ledger proves every exact crash-cut source/target convergence |
| P1 | EXEC-VERTICAL-001 | M02/M06/M07/M08 | persistent worker equivalence present | real MVCC/JMT/finality/recovery path preserves roots at 1/2/4/8 workers under faults |
| P1 | NODE-SPLIT-001 | M15 | open | composition performs wiring only; host/coordinator/I/O/CLI/lab boundaries are explicit |
| P1 | BUILD-CLOSURE-001 | M15/M17 | implementation present, exact-head acceptance pending | static and Cargo-resolved production graphs exclude candidate, lab, fixture, research, PoC, and legacy code; default/candidate compilation passes |
| P1 | CORE-LIVE-001 | M02/M03/M04 | open | persistent pacemaker, Vote/Timeout, epoch, network and catch-up path passes fault campaigns |
| P2 | TX-PROD-001 | M05/M15 | open | production admission, sign/broadcast, finalized readback, tombstone and GC lifecycle closes |
| P2 | SYNC-PROD-001 | M07/M13 | open | authenticated non-destructive production state sync and arbitrary trust path close |
| P2 | MIG-001 | M00/M07/M13/M15 | open | trusted finalized export and target-root recomputation accepted |
| P2 | MIG-014/016 | M02/M13/M15/M17 | open | signed cutover, cross-peer agreement, downgrade prohibition, safe residue cleanup |
| P2 | OWNERSHIP-001 | M15/M17 | open | real module teams, two-maintainer minimum, independent consumer/security review |
| P2 | CONTROL-001 | M16/M17 | open | observer-first, guarded, reversible, non-authoritative control plane demonstrated |

External blockers remain:

- `EXT-REVIEW-001`;
- `EXT-G1-CAMPAIGN-001`;
- `EXT-ANCHOR-HSM-001`;
- `EXT-POWERLOSS-001`;
- `EXT-AUDIT-001`;
- `EXT-SOAK-ACTIVATION-001`.

A blocker closes only through accepted exact-source evidence. Deleting prose, weakening a validator, changing a status label, shortening a wall-clock campaign, or substituting simulation does not close it.

---

## 13. Gates and evidence contract

| Gate | Exit meaning |
|---|---|
| G0 | one repository/protocol truth, protected controls, bounded canonical schemas/vectors, complete source/module coverage |
| G1 | persistent native validator, Safety/Core/finality/recovery/state sync and real network evidence |
| G1.5 | AI-native object/domain/error/limit registry, independent conformance, formal obligations; no activation |
| G2 | Agent/Market, DA, execution, verify/challenge, settlement and cross-plane proofs integrated |
| G3 | adversarial multi-host, resource/denial, observability and incident/DR qualification |
| G4 | reproducible artifacts, independent audits, custody, migration rehearsal and testnet approval |
| G5 | completed soaks, zero open Critical/High, governance authorization and activation bundle |

Every promotion-capable evidence envelope binds:

- evidence, gate, plan, module, and protocol IDs/hashes;
- source and prospective-merge identities;
- toolchain, dependency, feature, configuration, and validator-set digests;
- machine truth before and after;
- artifact, image, SBOM, provenance, and signature digests;
- exact commands, topology, workload, fault manifest, seeds, and time bounds;
- raw artifacts, positive controls, negative vectors, and retained mutants;
- crash/replay boundaries, known gaps, non-claims, and invalidation set;
- independent reviewers, custody identities, signatures, and immutable locations.

An enabled operation needs one vertical trace from schema/domain through admission/replay, batch/DA, proposal predicate, consensus/Safety, execution/meter, JMT/root, finality/checkpoint, result/challenge/settlement, and RPC/SDK/indexer/light-client view.

Benchmarks bind exact workload bytes, caps, profile, hardware/OS/toolchain/container, topology/RTT/faults, warm-up, repetitions, percentile denominator, confidence method, raw traces, cost normalization, and comparator digest. Report committed goodput and finality tails, not ingress TPS.

Any source, protocol, dependency, compiler, feature, configuration, validator set, key policy, state-root format, migration input, failed invariant, or reopened security finding invalidates affected evidence and transitive dependants. Failed evidence remains immutable but is not active guidance.

---

## 14. Immediate executable order

1. rerun canonical document/module coverage, repository truth, protocol contract, Rust baseline, fuzz smoke, Node Commit, 1/2/4/8-worker, recovery, replay-to-Core, candidate-node, Web4, and prospective-merge gates on the same current PR #62 head;
2. repair every exact log failure without weakening source identity, offline dependency, mutation, recovery, or non-promotion requirements;
3. mark PRs #54, #57, #58, #59, and #61 superseded only after their evidence and unique commits are preserved or proven absorbed;
4. obtain independent module-owner, consumer, security/evidence, and release acceptance on the unchanged head;
5. merge only through protected `main`, then run post-merge verification and regenerate source-bound release status;
6. retain and qualify the implemented Cargo dependency/feature closures for `node-prod-v0`, `node-devnet-v0`, `ai-v1-candidate`, and `lab-and-evidence` on the exact head and prospective merge;
7. decompose the node composition hotspot and finish the persistent network/pacemaker/Vote/Timeout/finality/recovery path;
8. complete transaction lifecycle, state sync, migration, packaging, SBOM/provenance, observability, denial/resource, and incident/DR closure;
9. ingest authentic independent multi-host, HSM/anchor, physical power-loss, audit/red-team, and wall-clock soak evidence;
10. retain G5 and every activation flag as false until governance signs the exact accepted bundle.

Minimum local replay:

```bash
bash scripts/ci/check_canonical_development_plan.sh
bash scripts/ci/check_agent_development_docs_v1.sh
python3 scripts/ci/check_module_coverage_v1.py
python3 scripts/ci/check_repository_truth_v1.py
python3 scripts/ci/check_blocker_execution_v1.py
python3 scripts/ci/check_build_closures_v1.py --verify-cargo-tree
python3 scripts/ci/check_required_protocol_contract_v1.py
python3 scripts/ci/generate_release_status_v1.py --check-deterministic
python3 scripts/ci/check_external_evidence_v1.py
cd trillionnium
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
```

The modular program is complete only when M00-M17 have accepted versioned contracts, team owners, two-maintainer minimums, dependency/capability policies, testkits, SLOs, runbooks, and evidence; forbidden edges and production contamination are zero; composition owns no domain logic; concurrency preserves roots; the Node Commit Ledger proves recovery; M16 is guarded and non-authoritative; every repository and external blocker closes; and G5 remains false until an explicit signed governance record updates machine truth through protected review.
