# Trillionnium Chain Development Plan v2

Plan ID: `trnm-chain-development-plan-v2`  
Effective: **2026-09-01 (Asia/Singapore)**  
Status: **sole active engineering plan; candidate-non-normative until independently accepted and merged through protected `main`**  
Canonical destination: `refs/heads/main`  
Documentation candidate: `refs/heads/docs/chain-development-plan-v2-20260901`  
Assessed source: `integration/native-poco-a04-a19-a23-qualified-v1-20260901@3c46293e78a125dec9504e51c355a20216341338`  
Assessed tree: `875a1e6366df7cd9da80de145e25584ae309cee8`

Machine truth: [`../../config/consensus-mainline.json`](../../config/consensus-mainline.json)  
Snapshot: [`CURRENT_SNAPSHOT_V1.json`](CURRENT_SNAPSHOT_V1.json)  
Module registry: [`module-registry-v1.toml`](module-registry-v1.toml)  
Release train: [`release-train-v1.toml`](release-train-v1.toml)  
Manifest: [`plan-manifest-v1.toml`](plan-manifest-v1.toml)

---

## 0. Authority and non-claims

This is the **one active engineering plan** for Trillionnium Chain. It alone may define development sequencing, module ownership, integration policy, gate order, and the next executable action. Machine truth, protocol specifications, schemas, vectors, formal models, architecture decisions, runbooks, audits, and evidence records remain authorities only for their own domains; none is a second roadmap.

Current truth remains:

```text
stage = G1-native-host-incomplete
production_candidate = false
production_consensus_activation = false
public_testnet_ready = false
release_ready = false
```

**No machine flag is promoted by this plan.** A document edit, PR, test, simulation, benchmark, carrier workflow, or local process run cannot authorize production, public testnet, release, protocol activation, security certification, or a performance claim. PoCO AI-native v1 remains design-only unless its own normative gates close.

Truth precedence is: signed activation/governance record; machine truth and repository policy; normative protocol inputs; this hash-bound plan; release projection/runbooks; exact-source evidence; PR/issue/comment/chat text. Protected-main, assessed source, PR head, prospective merge, artifact, evidence, and activated release identities are distinct and may not be substituted.

### Documentation anti-pollution rule

Development history lives in Git history, closed PRs, immutable evidence, and source-bound audits. Active content must satisfy:

- `docs/development/` has one regular Markdown file: this plan;
- the legacy evidence-contract path may only be a symlink to this plan;
- no `docs/development/agents/`, `docs/development/packages/`, prompt pack, per-PR narrative ledger, sprint board, continuation note, or dated delivery plan;
- no `docs/archive/`; Git is the archive;
- compact JSON/TOML beside the plan carries current source, module, and release-train facts;
- navigation points only here for development direction;
- stale branches, commits, dates, absolute worktree paths, people, and completion percentages are observations, never authority.

CI must reject a second active development plan or a recreated archive.

---

## 1. Current assessment

Protected `main` was observed at `b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9`. The latest assessed source is Draft PR #58:

```text
head_ref  = integration/native-poco-a04-a19-a23-qualified-v1-20260901
head      = 3c46293e78a125dec9504e51c355a20216341338
head_tree = 875a1e6366df7cd9da80de145e25584ae309cee8
base_ref  = feature/chain-p2-node-candidate-devnet-cli-v1-20260831
base      = fddc8e919a77f3be42b72ad4b8a7f8ff91d7abdc
```

PR #58 combines ordered application finalization, durable terminal finalization history, and a native finalized replay floor for bounded tombstone deletion. It is Draft, unaccepted, and has requested changes. Carrier qualification does not replace non-skipped exact PR-head and prospective-merge runs.

### P0 merge blockers

1. **Descriptor-bound namespace identity:** every authoritative SQLite open/read/append/audit/replay/reopen remains bound to the intended directory, database, and sidecars before and after use.
2. **Closed-world schema:** reject extra, missing, or changed tables, indexes, views, triggers, SQL definitions, and required pragmas.
3. **No early trusted return:** read and exact-replay paths close the connection and complete post-operation identity checks before returning.
4. **Fresh-connection revalidation:** every connection rechecks namespace, sidecars, schema digest, scope, generation, and durable head.
5. **One successor:** PR #58 is the selected A04/A19/A23 successor; overlapping PR #57 must be superseded before integration.
6. **Exact evidence:** unchanged PR head, prospective merge, independent review, and no skipped required jobs.

The codebase already has a deterministic I/O-free consensus core, capability-oriented SafetyRules, persist-before-sign ordering, bounded canonical decoders, host-neutral application contracts, deterministic parallel-execution candidates, and source-bound evidence concepts. The primary gaps are whole-node integration, durability, production closure, operational evidence, and fragmented historical guidance.

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

Consensus, SafetyRules, deterministic scheduling, canonical state commit, finality, checkpointing, and recovery may not depend on synchronous remote control-plane RPC. Large models, nondeterministic inference, private datasets, long outputs, external tools, and subjective judgment remain off-chain; the chain orders and settles commitments, availability facts, proofs, challenges, and declared verification profiles.

---

## 3. Eighteen long-lived modules

Crates are implementation units, not team boundaries. Every engineer has one primary module; cross-module work changes a versioned contract and requires producer/consumer acceptance.

| ID | Module | Responsibility | Placement | Staff |
|---|---|---|---|---:|
| M00 | Protocol / Schema / Codec | versioned types, domains, limits, codecs, vectors, error registry | library | 2 |
| M01 | Crypto / Identity / Capability | verification, identities, capability carriers, signer protocol | library / signer | 3 |
| M02 | Order / Consensus Kernel | PoCO-BFT state machine, QC/TC, epoch, pacemaker contract | hot path | 4 |
| M03 | Safety / Signer / Checkpoint | Safety authority, journal, watermark, checkpoint CAS | hot path / HSM | 4 |
| M04 | P2P / Session / Dissemination | authenticated sessions, leases, bounded ingress, gossip | I/O runtime | 3 |
| M05 | Tx Admission / Mempool | budgets, nonce/replay, WAL, handoff | in process | 2 |
| M06 | Execution / MVCC / Meter | speculation, conflicts, re-execution, multidimensional meter | hot path | 4 |
| M07 | State / JMT / Storage | state tree, proofs, pruning, storage and namespace ownership | hot path | 3 |
| M08 | Finality / Commit / Recovery | ordered finality, commit ledger, restart convergence | hot path | 3 |
| M09 | Data Availability | batch/artifact commitments, retrieval, repair, withholding evidence | workers | 2 |
| M10 | Agent / Task / Market | agent identity, task/lease/escrow lifecycle | application | 2 |
| M11 | Verify / Challenge | profiles, result authority, challenge/appeal lifecycle | core / workers | 2 |
| M12 | Settlement / Economics | fees, escrow conservation, rewards, slash, refund | application | 2 |
| M13 | State Sync / Light Client / Proofs | checkpoints, sync, proof verification, weak subjectivity | verifier / downloader | 3 |
| M14 | RPC / Indexer / SDK / CLI | non-authoritative client and query surfaces | services | 2 |
| M15 | Node / Packaging / Release | wiring, lifecycle, build closures, binaries, reproducibility | composition | 2 |
| M16 | Global Control Plane | registry, observation, planning, rollout, rollback | out of band | 2 |
| M17 | Observability / Benchmark / Security / Evidence | metrics, fault/fuzz/formal/audit/evidence tooling | tooling | 3 |

Target allocation: 48 engineers. Each module converges to `contract`, pure `core`, bounded `adapters`, optional `service`, and `testkit`, with a machine descriptor for owners, dependencies, SLOs, capabilities, and evidence.

### Dependency law

```text
primitives -> contracts -> pure cores -> adapters -> node composition
```

Contract crates depend only on primitives/codecs/approved crypto interfaces. Pure cores own no filesystem, socket, wall clock, thread pool, process, database connection, signer, or environment variable. Adapters do not leak storage/transport types into domain contracts. Composition wires implementations but contains no domain state machine. Cross-module calls use versioned ports, immutable events, or consumed capabilities. Implementation-to-implementation horizontal edges, cycles, and production dependencies on lab/fixture/research/v1-candidate/legacy code are prohibited. M16 cannot mint signing, voting, finality, state-root, Safety, or activation authority.

---

## 4. Concurrency and deterministic commit

Serial authorities: consensus transition, SafetyRules, signer watermark, canonical order, state-root commit, finality advancement, checkpoint replacement, and Node Commit Ledger sequence.

Bounded parallel work: sessions, decode/admission, batch signature verification, DA fetch/repair, prevalidation, immutable-parent MVCC speculation, proof/receipt construction, snapshot chunks, RPC/indexing, analytics, and evidence processing.

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

Worker count, CPU topology, scheduling, retry timing, and queue interleaving must not change canonical roots, receipts, fees, events, proofs, or finality. Test at 1/2/4/8 workers across clean, conflict-heavy, crash/restart, and replay cases. Every queue and operation has explicit byte, item, depth, allocation, signature-work, state-access, event, CPU, memory, network, and storage limits; `u32::MAX` is not an acceptable effective transaction-count bound.

---

## 5. Persistence and recovery

### `PinnedSqliteNamespace`

All authoritative SQLite stores share one reviewed capability providing canonical parent-directory descriptor ownership; no-follow/descriptor-relative opens where available; database and WAL/SHM/journal/lock/anchor identity; closed-world `sqlite_schema` digest and pragma profile; chain/store/generation binding; pre-open, post-open, pre-return, post-close, and reopen checks; separate fresh-create/read-only/read-write modes; fail-closed unsupported-platform behavior; and retained path, link, mount, sidecar, schema, rollback, and partial-inventory mutants.

### Node Commit Ledger

Use one append-only, hash-chained, monotonic node authority rather than cross-database hope or 2PC:

```text
Prepared -> ApplicationSealed -> SafetyPersisted -> SignIntentPersisted
 -> SignatureConfirmed -> FinalityApplied -> CheckpointConfirmed -> OutboundPublished
```

Each record binds node generation, chain/validator/application identity, height/round/block/parent, proposal/proof digests, pre/post roots, application/receipt roots, Safety revision, signer watermark, finality proof, checkpoint predecessor, prior record digest, and durable sequence. Stores are idempotent projections or explicitly bound authorities. Recovery reaches exact durable source or exact durable target; ambiguity fails closed with a machine-readable recovery action.

Split storage by authority: namespace, schema registry, proposal, application seal, safety commit, signer intent, finalization history, checkpoint, recovery, and audit.

---

## 6. Node and build closures

Decompose the `trnm-poco-node` hotspot into kernel host, authority coordinator, I/O runtime, composition, CLI, and lab boundaries. The production composition layer performs wiring only.

Require separately checked closures:

```text
node-prod-v0 | node-devnet-v0 | ai-v1-candidate | lab-and-evidence
```

`node-prod-v0` contains no v1 candidate, lab, fixture, benchmark, mock authority, research, PoC, or legacy Comet runtime dependency. No Cargo feature combination may silently activate candidate authority.

---

## 7. Global control plane

Each module publishes a versioned descriptor and a performance Pareto frontier: contract/implementation/dependency digests, capabilities, limits, tunables, invariants, workload validity region, committed goodput, p50/p95/p99 latency, CPU/memory/disk/network cost, queue pressure, error/drop rate, recovery cost, and evidence IDs.

The planner uses lexicographic constrained optimization:

```text
minimize safety violations, determinism violations, durability violations,
compatibility violations, p99 finality, resource/recovery cost,
and negative committed goodput — in that order.
```

The first four must be zero. Offline finite planning may report MILP/CP-SAT optimality gaps; online planning reports feasibility/regret and never claims universal optimality for unknown future workloads.

A signed `OptimizationPlanV1` binds source graph, contracts, workload assumption, bounded resources, workers/queues/batches, placement, activation boundary, expected delta, and rollback. `ActionReceiptV1` reports acceptance/rejection, generation, applied digest, resulting configuration, invariant results, and measured effect. A node-local independent guard verifies every plan; rollout is shadow, canary, staged, general, with rollback.

Parameter classes:

- **ConsensusCritical:** quorum, validator set, wire/domain/root rules; governance plus epoch/height activation only.
- **DeterminismCritical:** workers, partitioning, re-execution; only after root-invariance and shadow replay.
- **OperationalLocal:** cache, pools, RPC quotas, DA fetch concurrency, sampling; bounded automatic adjustment allowed.

M16 cannot sign, vote, finalize, create an authoritative root, modify SafetyRules, bypass admission, erase evidence, rewrite history, or force incompatible startup. On control-plane loss, nodes keep the last accepted safe plan; optimization stops, consensus does not.

---

## 8. Team, PR, and merge train

Each critical module has at least two maintainers. CODEOWNERS migrates from individuals to module teams after teams exist. The author cannot provide independent acceptance. Cross-module changes normally use:

```text
PR A: contract/version/limits/vectors/mutants
PR B: producer implementation
PR C: consumer adoption and aggregate replay
```

Limits: one active implementation PR per module; one successor per integration surface; at most five concurrent writers across consensus/Safety/state/finality/recovery; no direct edits to another module's implementation without its owner; base movement invalidates evidence; overlap declares successor or closes.

Merge train:

```text
contract freeze -> module qualification -> consumer replay -> integration candidate
 -> exact PR-head checks -> prospective-merge checks -> independent review
 -> protected-main merge -> post-merge verification
```

Skipped, cancelled, queued, stale, synthetic, self-authored, or different-head runs are not acceptance. CI layers are L0 module, L1 contract, L2 merge queue/recovery/root-invariance, and L3 independent multi-host/HSM/power-loss/audit/soak.

---

## 9. Ordered execution program

### D0 — single development truth

Replace all active development roadmaps with this plan; remove archive, agent prompts, package narratives, stale PR ledgers, and absolute worktree references; retain compact snapshot/manifest/module/release-train data; update navigation and CI. Exit: one plan, no active archive, valid links/data, passing documentation gate.

### P0 — latest-candidate integrity

Make PR #58 the sole A04/A19/A23 successor; supersede PR #57; implement pinned namespace and closed-world schema; remove pre-postcheck returns; add replacement/schema/sidecar/rollback/reopen mutants; run unchanged exact-head and prospective-merge checks. Exit: independent acceptance of the exact head; no Gate promotion.

### P1 — module and production boundaries

Map active crates to M00-M17; generate dependency/ownership views; split build closures; prohibit horizontal implementation edges; begin node decomposition. Exit: acyclic graph, zero forbidden edges, clean `node-prod-v0` closure.

### P2 — whole-node durability

Implement Node Commit Ledger; project Safety/signer/application/finality/checkpoint state; split storage by authority; prove every crash cut; provide external recovery/status ownership. Exit: deterministic exact source/target convergence or explicit fail-closed recovery.

### P3 — persistent validator vertical path

```text
Tx admission -> canonical order -> deterministic MVCC -> canonical JMT
 -> application seal -> Safety/Core -> signature/publication
 -> ordered finality -> durable apply -> restart replay
```

Add persistent authenticated networking, pacemaker, arbitrary proposals, receipts, catch-up, and production state sync while preserving 1/2/4/8-worker roots. Exit: full candidate validator path under faults; production flags remain false.

### P4 — selective isolation

Externalize signer/HSM, DA workers, state-sync downloader, RPC/indexer, proof generation, and telemetry/evidence only where security or scaling improves. Use versioned protocols, persistent intents, idempotent IDs, deadlines, backpressure, authenticated identity, and uncertainty recovery. Do not microservice the commit path.

### P5 — control plane

Deliver registry and read-only observation; telemetry/workload classification; signed plan/receipt; offline planner; shadow evaluator; local guard; canary/rollback; bounded OperationalLocal tuning; then DeterminismCritical tuning after invariance evidence.

### P6 — migration and external promotion

`MIG-001`: trusted finalized legacy source verifier, exact export, target projection, root recomputation, and fresh PoCO genesis. In-place DB/WAL conversion and import of legacy validator signing state are prohibited.

`MIG-014/016`: multi-party cutover rehearsal, cross-peer genesis/QC agreement, downgrade prohibition, and signed eligibility to remove legacy Comet packages/workflows/fixtures/scripts/active docs. Differential fixtures remain only when explicitly classified and excluded from production.

Complete G3-G5 independent campaigns, audits, governance, and activation only after repository-owned gates close.

---

## 10. Prioritized blocker ledger

| P | ID | Owner | Exit |
|---|---|---|---|
| P0 | DOC-TRUTH-001 | M15/M17 | one plan; no archive or stale agent/package docs |
| P0 | INT-STACK-001 | M15 | PR58 sole successor; overlap superseded; exact-head and merge checks pass |
| P0 | A19-NS-001 | M07/M08 | descriptor-bound DB/sidecar identity around every trusted operation |
| P0 | A19-SCHEMA-001 | M07 | closed-world schema and pragma digest |
| P0 | A19-RETURN-001 | M07/M08 | no trusted return before close/post-check |
| P1 | NODE-COMMIT-001 | M03/M07/M08 | monotonic ledger and exact crash convergence |
| P1 | NODE-SPLIT-001 | M15 | composition is wiring only |
| P1 | BUILD-CLOSURE-001 | M15/M17 | production excludes candidate/lab/legacy |
| P1 | EXEC-VERTICAL-001 | M02/M06/M07/M08 | real MVCC/JMT/finality path with root invariance |
| P1 | CORE-LIVE-001 | M02/M03/M04 | persistent pacemaker, Vote/Timeout, epoch and catch-up |
| P2 | TX-PROD-001 | M05/M15 | production admission/sign/broadcast/readback/GC lifecycle |
| P2 | SYNC-PROD-001 | M07/M13 | authenticated production state sync |
| P2 | MIG-001 | M00/M07/M13/M15 | trusted export and target root recomputation |
| P2 | MIG-014/016 | M02/M13/M15/M17 | signed cutover and safe legacy cleanup |
| P2 | OWNERSHIP-001 | M15/M17 | module teams and independent consumer review |
| P2 | CONTROL-001 | M16/M17 | observer-first, guarded, reversible control plane |

External blockers remain `EXT-REVIEW-001`, `EXT-G1-CAMPAIGN-001`, `EXT-ANCHOR-HSM-001`, `EXT-POWERLOSS-001`, `EXT-AUDIT-001`, and `EXT-SOAK-ACTIVATION-001`. A blocker closes only through accepted exact-source evidence, never by deleting prose.

---

## 11. Gates and evidence contract

| Gate | Exit meaning |
|---|---|
| G0 | one repository/protocol truth, protected controls, bounded canonical schemas/vectors |
| G1 | persistent native validator, Safety/Core/finality/recovery/state sync and real network evidence |
| G1.5 | AI-native object/domain/error/limit registry and independent conformance; no activation |
| G2 | Agent/Market, DA, execution, verify/challenge, settlement and cross-plane proofs integrated |
| G3 | adversarial multi-host, resource/denial, observability and incident/DR qualification |
| G4 | reproducible artifacts, independent audits, custody, migration rehearsal and testnet approval |
| G5 | completed soaks, zero open Critical/High, governance authorization and activation bundle |

Every promotion-capable evidence envelope binds: evidence/gate/plan IDs and hashes; source and prospective-merge identities; protocol/module/toolchain/dependency digests; machine truth before/after; artifact/image/SBOM/provenance digests; exact commands; scope/authority/classification; topology/workload/fault manifests; raw artifacts; positive vectors and retained mutants; crash/replay boundaries; known gaps/non-claims; invalidation set; independent reviewers/signatures; immutable locations.

An enabled operation needs one vertical trace from schema/domain through admission/replay, batch/DA, proposal/consensus predicate, execution/meter, JMT/root, finality/checkpoint, result/challenge/settlement, and RPC/SDK/indexer/light-client view. External objects require two independent parsers agreeing on canonical bytes, roots, bounds, and errors.

Benchmarks bind exact workload bytes, caps, profile, hardware/OS/toolchain/container, topology/RTT/faults, seed, warm-up, repetitions, percentile denominator, confidence method, raw traces, cost normalization, and comparator digest. Report committed goodput and finality tails, not ingress TPS.

Source, protocol, dependency, compiler, feature, configuration, validator set, key policy, root format, migration input, failed invariant, or reopened security finding invalidates affected evidence and transitive dependants. Failed evidence remains immutable but is not active guidance.

---

## 12. Documentation lifecycle and immediate actions

A semantic plan update atomically updates this file, plan manifest/hash, snapshot when source facts change, module registry when boundaries change, release train when successor/blocker facts change, navigation, and CI. Architecture, authority, gate, module, or promotion-rule changes require a new Plan ID. Git supplies history; no duplicate is retained “for reference.”

Immediate order:

1. land this cleanup only after one-plan, link, JSON/TOML, symlink, and no-archive checks pass;
2. repair PR #58 A19 namespace/schema/post-check blockers;
3. declare PR #58 sole successor and supersede PR #57;
4. run exact-head and prospective-merge checks with independent review;
5. integrate canonical Native PoCO truth through protected `main`, then rebase without restoring stale docs;
6. enforce crate-to-M00-M17 dependency policy and build closures;
7. implement pinned namespace and Node Commit Ledger before adding feature planes;
8. connect MVCC to real JMT/finality/recovery and build the persistent validator path;
9. introduce M16 as read-only observation first;
10. complete independent campaigns and audits before any G4/G5/activation claim.

Minimum replay:

```bash
bash scripts/ci/check_canonical_development_plan.sh
bash scripts/ci/check_agent_development_docs_v1.sh
python3 scripts/ci/check_repository_truth_v1.py
python3 scripts/ci/check_blocker_execution_v1.py
python3 scripts/ci/check_required_protocol_contract_v1.py
python3 scripts/ci/generate_release_status_v1.py --check-deterministic
python3 scripts/ci/check_external_evidence_v1.py
cd trillionnium
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
```

The modular program is complete only when M00-M17 have versioned contracts, team owners, two-maintainer minimums, dependency/capability policies, testkits, SLOs, and evidence; forbidden edges and production contamination are zero; composition owns no domain logic; concurrency preserves roots; the Node Commit Ledger proves recovery; M16 is guarded and non-authoritative; all repository and external blockers close; and G5 remains false until an explicit signed governance record updates machine truth through protected review.
