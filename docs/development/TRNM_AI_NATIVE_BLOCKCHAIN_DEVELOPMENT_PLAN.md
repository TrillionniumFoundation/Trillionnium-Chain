# Trillionnium Chain Development Plan v2

Plan ID: `trnm-chain-development-plan-v2`
Effective: **2026-09-15 (Asia/Singapore)**
Status observed: **2026-09-15 (candidate commit `a1225af2ecad9e849368ff6b3d28dedbd6cb2ee8`)**
Status: **sole active engineering plan; candidate-non-normative until independently accepted and merged through protected `main`**
Canonical destination: `refs/heads/main`

This plan owns execution order and acceptance sequencing. Detailed algorithms,
layouts, invariants and recovery contracts live in the technical references
below; they are not duplicated here. This condensation does not retire any
protocol rule, implementation blocker, independent review or release obligation.

## 0. Authority, truth hierarchy, and non-claims

Machine truth is [`config/consensus-mainline.json`](../../config/consensus-mainline.json).
The present stage is `G1-native-host-incomplete`; production candidate,
production activation, public-testnet readiness and release readiness remain
false. A document edit, interface, source commit, test fixture, green workflow or
self-authored report cannot promote any of those flags.

Authority precedence remains: signed activation/governance for an accepted
release; machine truth and protected policy; frozen protocol inputs; this plan;
module contracts/runbooks; source-bound evidence within its qualified scope;
PR or chat narrative. Protected main, assessed baseline, current PR head,
prospective merge, artifact, accepted release and activated network are distinct.

### Applicable technical version

[`docs/architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md`](../architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md)
resolves each operation's profile. `bft-v0` is the frozen implementation target;
`pcc1` imports that kernel as a candidate integration contract; `ai-v1` is a
separate draft profile. `legacy-ledger-observation` stage tags grant no signing,
publication or finality authority. A newer file or crate name cannot override
signing bytes, locks, validity, finality, parameter commitments or activation.

### Documentation anti-pollution rule

This is the one regular Markdown plan in `docs/development/`. Git history and
immutable evidence retain history; do not create per-PR roadmaps, prompt fleets,
active archives or competing sprint plans. Machine companions are inventories,
source bindings and projections, not alternate work queues. Stable technical
material belongs under protocol, architecture, modules, runbooks or evidence.
Do not treat staffing estimates, exact prose, directory names or private Git
forms as software-validity predicates. Source ownership, canonical imports,
finite limits, dependency boundaries and real acceptance remain checked.

## 1. Current assessment and selected successor

The source-only baseline observed on 2026-09-13 is
`435c0168558d75fc70aaa11980a179b9d5980f33`, tree
`1e3db388234eff27b7214cc7879aef6853214709`. It must be an ancestor of the actual
candidate. No successor PR number is pinned; derive head/base/merge identities
from Git and the event. Historical integration identities and their non-transfer
of acceptance are retained in the manifest and Git history, not a live queue.
The current documentation candidate is based on commit
`a1225af2ecad9e849368ff6b3d28dedbd6cb2ee8` (tree
`e9f2f0d85a1d49758e6f3b180ab0c6a011219cf7`); this observation does not alter the
assessed `main` baseline or confer acceptance.

### 1.1 Repository implementation retained

The baseline contains descriptor-bound SQLite validation, closed schema/pragma
checks, post-operation checks, Node Commit Ledger/recovery implementations,
1/2/4/8-worker deterministic execution comparison and M00-M17 ownership/technical
coverage. These are implementation-present facts, not accepted whole-node,
production or independent-review results.

Use [`CURRENT_SNAPSHOT_V1.json`](CURRENT_SNAPSHOT_V1.json),
[`plan-manifest-v1.toml`](plan-manifest-v1.toml) and
[`release-train-v1.toml`](release-train-v1.toml) for source observations and open
status. Generated input pins do not transfer evidence or close a blocker.

### 1.2 Current promotion-critical gaps

Execution order is section 11: real persistent node, two consecutive epoch
transitions, bounded state/recovery and measured goodput. Source integrity and
focused security tests apply continuously. Independent review and external
qualification block their acceptance gates, not unrelated local compilation.
Every open functional/external obligation stays visible in the blocker register.

## 2. Target architecture

Use a deterministic modular monolith for the consensus hot path, selective
process isolation where justified, and an out-of-band global control plane.

```text
primitives -> versioned contracts -> deterministic cores -> bounded adapters
 -> node composition

authenticated ingress -> Order -> Execution -> State -> Finality
                         durable Node Commit Ledger
```

### Dependency law

Pure cores own no sockets, wall clock, filesystem, process, database connection,
signer or model inference. Composition wires owners; it contains no domain
state machine. Cross-module contracts use typed ports, immutable events,
authenticated proofs or consumed non-cloneable capabilities. Consensus, Safety,
canonical commit and recovery must not depend on synchronous control-plane RPC.
Large models, private datasets, subjective evaluation and external tools remain
off-chain under explicit verification/availability profiles.

## 3. Eighteen long-lived modules

[`module-registry-v1.toml`](module-registry-v1.toml) and
[`module-coverage-v1.toml`](../../config/module-coverage-v1.toml) own exact package
membership. Crates are implementation units, not mandatory team boundaries.

| Module | Responsibility |
|---|---|
| M00 | Protocol, schema, canonical codecs and vectors |
| M01 | Cryptography, identity and capability verification |
| M02 | Order and deterministic consensus kernel |
| M03 | Safety, signer, watermark and checkpoint authority |
| M04 | P2P sessions, dissemination and backpressure |
| M05 | Transaction admission, mempool and replay lifecycle |
| M06 | Deterministic execution, MVCC and metering |
| M07 | State, JMT and authoritative storage |
| M08 | Finality, commit coordination and recovery |
| M09 | Data availability, retrieval and retention |
| M10 | Agent, task, market and lease lifecycle |
| M11 | Verification profiles, challenge and appeal |
| M12 | Settlement, conservation and economics |
| M13 | State sync, light-client and proof verification |
| M14 | RPC, indexer, SDK, CLI and Web4 |
| M15 | Node composition, packaging and release |
| M16 | Non-authoritative operational control plane |
| M17 | Observability, benchmark, security and evidence tooling |

### 3.1 Module documentation and coverage contract

[`Technical reference`](../modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md),
[`docs/modules/TRNM_MODULE_IMPLEMENTATION_GUIDE_V1.md`](../modules/TRNM_MODULE_IMPLEMENTATION_GUIDE_V1.md),
[`config/documentation-contracts-v1.json`](../../config/documentation-contracts-v1.json),
[`foundation operations`](../modules/TRNM_FOUNDATION_OPERATION_CONTRACTS_V1.md)
and [`operation catalog`](../../config/documentation-operations-v1.json) retain
scope, algorithms, failure/recovery, schemas, errors, test vectors and consumers.
Do not re-create them as plan prose. Structural navigation, independent semantic
acceptance and implementation/production acceptance are separate judgments.

Each active package/auxiliary unit has one primary module. Completion requires
its actual source, versioned contract, tests, testkit, measured SLO, qualified
owners, capability/dependency boundary, runbook and source-bound evidence.
Naming a profile or linking one representative test does not complete all
operations. New interfaces, wrappers and stage names are not delivery metrics.

## 4. Deterministic concurrency and canonical commit

Parallel work may include bounded ingress/decode, signature verification, DA,
immutable-parent speculation, proof construction, downloads and queries.
Consensus transition, Safety/watermark, canonical order, state-root commit,
finality, checkpoint CAS, ledger sequence and activation remain serial owners.

Worker count and scheduling cannot change roots, fees, receipts, events, errors
or finality. Preserve canonical dependency validation, ordered re-execution and
commit barriers. Test independent and hotspot/conflicting workloads at
1/2/4/8 workers with crash/replay; use the serial scheduler as a scheduling oracle,
not an independent implementation of shared semantics. Every public operation
and queue has finite byte/item/work/resource limits; full-history work and
transient cost must be measured rather than hidden behind a worker count.

## 5. Persistence and recovery

### 5.1 `PinnedSqliteNamespace`

M07/M03 retain descriptor/identity-bound namespace ownership, no-follow behavior,
closed-world schema/pragma checks, database/sidecar/generation binding and exact
pre/post-open, return, close and reopen validation. Fresh create and existing
open are distinct. Do not remove these safeguards to make a benchmark faster.
Concrete algorithms and known platform assumptions remain in the implementation
guide and storage specifications.

### 5.2 Node Commit Ledger

Signing (`Validated -> IntentDurable -> SignatureRecorded -> VotePublished`)
and finality publication (`FinalityVerified -> CommitIntentDurable ->
ApplicationApplied -> CommitRecorded -> CheckpointConfirmed -> ReceiptPublished`)
are separate lifecycles. A vote cannot wait for its own block's finality. A
stored historical stage is not proof that a domain owner executed the operation.
Recovery uses actual authoritative source/target receipts; uncertain completion
requires fresh readback, not a new intent or guessed acknowledgement.

### 5.3 Required crash boundaries

Retain all affected persist/sign/publish/CAS crash cuts, duplicate and lost reply,
rollback, clone, replacement, partial projection, disk-full and takeover cases.
Local file watermarks and process-kill tests cannot prove independent rollback
resistance, HSM custody or physical power-loss durability. Those external gates
remain separate. Incremental recovery is allowed only after its replacement
root/predecessor and crash-convergence invariants are accepted.

## 6. Persistent validator vertical path

### 6.1 Order and Safety

Connect the real deterministic Core, durable Safety and role-specific custody.
Retain weighted-quorum uniqueness, locks, certified-chain finality, authenticated
ancestry and epoch context. A compatible alternate TC is not automatically a
contradictory QC; TC-only failed-view progress cannot reset pacemaker backoff.
An epoch preparation row or observed old-role signature is not live new-epoch
authority. The detailed M02/M08 live-epoch gaps remain open.

### 6.2 Networking

Real peer identity, chain/profile negotiation, bounded admission, leases,
backpressure and replay protection must feed the same recovered Core owner.
Persist admission and recoverable payload before acknowledged consumption.
Caller-provided acknowledgements, repaired WAL heads and candidate socket
fixtures do not establish Core acceptance or whole-node atomicity. Local
availability failure is not deterministic Byzantine invalidity.

### 6.3 Transaction lifecycle

Close canonical decode, authorization, nonce/replay, admission budgets, WAL,
atomic replacement, ordering handoff, finalized readback and proof-gated
GC/tombstones. Uncertain replacement poisons participation until exact recovery;
expiration cannot erase replay protection. Test namespace-wide capacity and
real producer/consumer handoff, not only an in-memory contract fixture.

### 6.4 State sync and client proof

Authenticate checkpoints, arbitrary trust paths, epoch transitions, snapshot
catalog/chunks, schema and root before non-destructive install. Trust anchors
are explicit; network majority does not choose them. Preserve consensus versus
application coordinates, typed unavailable/invariant errors, retention and
historical proof semantics. M13/M14 must verify actual finalized responses.

## 7. PoCO AI-native v1 boundary

AI-v1 remains a separate candidate. Before G1.5/G2 acceptance, retain exact bounded
parameters, codecs, error/domain registries, independent vectors/verifiers,
formal obligations, actual state transitions, whole-node recovery and controlled
migration/activation. A local Agent/DA/Verify/Settlement kernel is not a deployed
service or proof of result correctness, independent consumption or economic
safety. Related-party/Sybil/collusion economics stay in shadow mode.

## 8. Node, build, packaging, and migration closures

[`build-closures-v1.toml`](../../config/build-closures-v1.toml) owns
`node-prod-v0`, `node-devnet-v0`, `ai-v1-candidate` and `lab-and-evidence` closures.
Production must not import candidate/lab/fixture/research/PoC or legacy consensus
runtime authority. Default and explicit-feature graphs need actual Cargo checks;
a crate or binary named production is not readiness.

Packaging binds source/tree, locked compiler/dependencies/features, configuration,
binary/container, SBOM, provenance and signatures. Migration verifies trusted
finalized export and recomputes the target root in a fresh namespace/genesis.
Do not import legacy signing state or rewrite an in-place validator database.
Rehearsal, multi-party cutover, cross-peer agreement and downgrade protection
remain release requirements.

## 9. Global control plane

M16 stays maintenance-only/read-only with fixed reviewed configuration and
manual tuning until section 11 base-chain predicates close. Defer new optimizer,
networked rollout and automatic tuning work; retain guard tests and security
fixes. Later plans remain bounded, signed, expiring, generation-bound and
reversible. ConsensusCritical changes need governance/activation;
DeterminismCritical changes need independent invariance evidence; only an
accepted OperationalLocal subset may be tuned locally.

The control plane cannot sign, vote, finalize, create authoritative roots,
change SafetyRules, erase evidence, bypass admission or activate production.
Its loss stops tuning, not consensus. Detailed descriptor/guard contracts remain
in the M16 technical specification, not duplicated here.

## 10. Team, ownership, and merge train

Critical modules retain at least two maintainers. Actual module owners, affected
consumers, qualified independent specialists and release/custody authorities
are distinct roles under [`docs/modules/TRNM_INDEPENDENT_REVIEW_V1.md`](../modules/TRNM_INDEPENDENT_REVIEW_V1.md).
A fallback account, second account, requested review or administrator permission
does not establish specialist competence or independence. Unfilled specialist
roles remain unaccepted, not invented. Authors cannot self-issue acceptance.

A compatible producer/consumer fix may be atomic in one PR. Split contract,
implementation and consumer PRs only when each is useful and safely testable.
Wire/signing/validity changes still need controlled version review and freeze
before activation. Sequence delivery as behavior/contract diff and tests,
exact-head checks, prospective merge, independent review, protected-main merge
and post-merge verification. Concurrency follows actual conflicting authority
ownership, not a fixed staffing count. Source movement invalidates affected
acceptance; unrelated diagnostics may still run and retain their own failures.

## 11. Ordered execution program

This section is the sole work ordering. Source/contract integrity is a continuous
constraint. Release acceptance dependencies are not permission to postpone
behavioral feedback until paperwork or a future audit finishes. Priorities below
are delivery priorities, not claims that a blocker is closed.

### P0.1 — persistent validator vertical path

Primary integration owner: M15; producers/consumers M02/M03/M04/M05/M06/M07/M08/M13/M14.
Connect actual authenticated ingress, persistent pacemaker, Core/Safety,
role-specific signer, transaction admission, execution, state commit, finality,
checkpoint, and proof-aware RPC readback. Keep the canonical hot path in process.
A retained stage label, permissive fixture, standalone interface or passing
source scan is not an implementation of its domain producer.

Exit predicate: real signed transactions traverse submission, dissemination,
ordering, execution, durable finality and client proof verification on actual
node processes. Exercise empty/low-load finalization, conflicting transactions,
partition/heal, lost replies, crash cuts, disk-full, restart, state sync and
rejoin. Every acknowledged effect must survive exact replay once, rejected
operations must leave the relevant durable state unchanged, and 1/2/4/8-worker
runs must agree on roots, receipts, events and fees. Start with bounded process
regressions; independent multi-host qualification remains required for G1.

### P0.2 — two continuous epoch transitions

Owners: M02/M03/M06/M07/M08/M13 with M15 integration. First settle the authenticated
consensus-height/application-version contract in the implementation guide's
M02/M08 boundaries. Then implement the actual checkpoint, two non-executing
seals, pre-certificate old/new role admission, separate persist-before-sign,
joint authorization, Core/Safety phases and first new executed block.

Exit predicate: two successive transitions using real producers, stores and
signers, including old-only/new-only/dual-role membership; view reset and skipped
views; interrupted persistence before each signature and cross-store commit;
lost acknowledgements; cold restart/rejoin and independent proof verification.
There is no dummy seal execution, removed epoch fence, caller-minted authority,
old-view/new-view numeric shortcut or silent reinterpretation of frozen cutoff
proofs. Unsupported live behavior stays disabled until this path is qualified.

### P0 acceptance checklist (all items required)

The P0.1 and P0.2 exits are conjunctive. A candidate remains
`candidate-non-normative` and all production/readiness flags remain false until
each item has source-bound, independently replayable evidence:

1. **Real 4-to-7-node campaign:** run the same persistent validator binary on
   independently operated hosts at four nodes and then seven nodes, including
   restart, partition/heal, lost replies and rejoin. Simulator, fixture and
   single-host process tests do not satisfy this item.
2. **Two epochs:** complete two successive authenticated epoch transitions with
   old-only, new-only and dual-role membership, first-new-block execution,
   interrupted persist-before-sign cuts, cold restart and proof verification.
3. **Coordinate binding:** every proposal, vote, QC/TC, checkpoint, finality and
   application receipt must bind and verify `(chain_id, epoch, height, view,
   block_id, parent_qc)`; mismatches and cross-epoch ancestry are rejected.
4. **Signer anchor:** signatures come from independently administered,
   device-backed custody with a monotonic anti-rollback anchor. The durable
   signer intent precedes custody, and anchor/store rollback or replacement tests
   fail closed. Local file watermarks are not a substitute.
5. **Committed goodput:** publish finalized, replay-verified successful business
   transactions per second with p50/p95/p99 finality, exact workload and
   durability profile, topology/fault manifest, raw traces and confidence bounds.
   Submitted or ingress TPS is not accepted as goodput.

### P1 — operation detail and state/recovery scalability

Complete contracts at the actual operation being delivered, not by adding equal
amounts of prose to all eighteen modules. Each critical operation records exact
clause/schema/domain/limits, authenticated input and pre-state, success effects,
errors and unchanged-on-rejection state, idempotency/crash recovery, independent
positive/negative bytes, implementation symbol/features and consumer replay.
Missing entries stay open; representative tests are not full operation coverage.

M07/M08 own reviewed incremental authenticated persistence, bounded checkpoint
replay and pruning. Separate foreground commit/recovery from scheduled full
history audit only after the replacement root, predecessor and crash-recovery
invariants are demonstrated. Do not delete verification for speed. Measure
state/history growth, snapshot cost, full-history work, bytes written per commit
and recovery duration. M06 then compares a bounded long-lived worker design with
the current scoped-thread path; preserve exact dependency checks and canonical
fallback. More workers or new caches alone are not a throughput result.

M17 measures finalized, replay-verified successful business goodput and
p50/p95/p99 finality, separately from submitted/admitted/executed counts. Bind
transaction bytes, disjoint/hotspot mix, state/history size, actual durability,
hardware, topology, measurement window and raw traces. Publish regressions and
confidence bounds, not simulator or ingress peaks as mainnet TPS.

### P1 — PoCO economic trust in shadow mode

M10/M11/M12 evaluate related-party demand, cross-identity Sybil, reciprocal
consumption, verifier collusion and challenge griefing. Receipt volume does not
prove independent demand. Keep shadow economics and activation fences unchanged;
reviewed parameters, objective evidence and independent economics acceptance are
prerequisites for enabling economic voting weight.

### P2 — selective services and control plane

After the persistent node, continuous epochs and large-state baseline are
accepted, extend AI services, DA workers, SDK and optional process isolation
against actual consumers. Isolate signer/HSM, downloads, queries or proof work
where evidence supports security/scaling benefit; do not microservice canonical
commit. M16 stays read-only first. Networked planning, automatic rollout and
automatic tuning are deferred. Existing guard tests and vulnerability fixes are
retained; an outage of optimization must never stop consensus.

### Release qualification — independent of edit-loop scheduling

Trusted migration, reproducible artifacts, custody, independent protocol/crypto/
economics review, real multi-host faults, physical power-loss and wall-clock
soaks remain mandatory for their gates. Independent reviewers can assess stable
boundaries in parallel, but evidence is accepted only for its actual source and
scope. G5 remains false until a signed governance record authorizes activation
through protected review. No default runtime, safety or release flag changes
because this plan is edited.

---

## 12. Prioritized blocker ledger

[`release-train-v1.toml`](release-train-v1.toml) retains the named blocker
inventory, owner modules, status and exit predicates; section 11 defines work
order. [`blocker-execution-v1.json`](../../config/blocker-execution-v1.json)
retains executable acceptance dependencies and evidence intake. An acceptance
dependency is not permission to defer developing an independently testable fix.

NODE-COMMIT-001, EXEC-VERTICAL-001, CORE-LIVE-001, TX-PROD-001 and SYNC-PROD-001
are P0 base-chain delivery work. Source/module/build hygiene continues alongside
it; namespace/schema/trusted-return invariants remain critical. No existing
blocker ID, status, external audit or rejection regression is deleted here.

The historical operation-sequence corpus is still a profile-migration/native
replay blocker. Private-kernel semantic replay is not current-owner signature,
durable P, full-event or restart acceptance. History reachability alone does not
prove branch-content absorption; validate actual replacements before integration.

External blockers EXT-REVIEW-001, EXT-G1-CAMPAIGN-001, EXT-ANCHOR-HSM-001,
EXT-POWERLOSS-001, EXT-AUDIT-001 and EXT-SOAK-ACTIVATION-001 stay open until genuine
qualified evidence closes them. Changing a label, shortening a campaign or
weakening a checker is not closure.

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

### Validation tiers and non-applicability

| Tier | Required behavior | What it does not establish |
|---|---|---|
| Local edit / PR | Cheap project/remote/dependency preflight; focused behavior and compiler tests; applicable exact-source repository/protocol/build checks | No release, independent audit or real-network acceptance |
| Integration | Real node transactions, finality, persistence, restart/rejoin, two epochs, root invariance and protected prospective-merge replay | No substitute for hardware/physical faults or completed wall-clock campaigns |
| Release / activation | Qualified independent review, multi-host faults, custody/anchors, physical durability, reproducible artifacts, soaks and authorized governance | No acceptance from generated statuses or missing evidence |

The five protected required job names remain unchanged. `rust-baseline` derives
applicability from exact Git base/head trees through
`scripts/ci/validation_scope_v1.py`, never an actor, label or claimed file list.
Only regular top-level overview/operator/security prose and Markdown runbooks
can be classified documentation-only. Protocol/module/development documents,
source, configuration, workflows, scripts, toolchains, locks, unknown paths,
symlinks and executable files require the full Rust suite. Main pushes and
manual runs always require it. Missing source, dirty checkout, ambiguous ancestry
or selector failure blocks the decision; it does not authorize a shortcut.

Documentation-only records **not applicable / not executed**, not successful
Rust tests. The other four required jobs still run, and the exact scope report
is retained and recomputed after the job. This exemption is a PR risk decision,
not evidence of compiler equivalence, integration qualification or reusable
release tests. Workflow/selector edits themselves run full validation. Source
hygiene checks are auxiliary; compiler negatives and observable state invariants
supply the corresponding API guarantees. Existing failure and cancellation
statuses are retained and may never be promoted to acceptance.

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

Use section 11 for priority and the existing blocker register for remaining
acceptance predicates. Do not maintain a second sequence in snapshots, PR forms
or task files. A useful PR supplies an executable producer/consumer behavior or
a demonstrated regression fix, not a count of crates, wrappers or stage labels.
Source-bound status and dependency views are generated; staffing estimates,
checkout basenames and Git-private task forms are not software validity rules.

For local work, run the cheap preflight and the affected behavior/compiler tests
first. After reviewing edits to pinned inputs, refresh derived pins once and
commit the related source together; this does not grant acceptance. Exact-source
and prospective-merge checks remain read-only and must bind clean source.
Independent diagnostics preserve each failure instead of stopping all unrelated
families at the first documentation failure. For example, on a clean candidate:

```bash
bash scripts/project-preflight.sh --dev
source scripts/ci/independent_gates_v1.sh
trnm_gate cargo test --manifest-path trillionnium/Cargo.toml -p trnm-poco-node-production-v0 --all-targets --locked
trnm_gate cargo test --manifest-path trillionnium/Cargo.toml -p trnm-poco-node-production-v0 --doc --locked
trnm_gate bash scripts/ci/check_canonical_development_plan.sh
trnm_gate python3 scripts/ci/check_repository_truth_v1.py
trnm_gate python3 scripts/ci/check_blocker_execution_v1.py
trnm_gate python3 scripts/ci/check_external_evidence_v1.py
trnm_gate_finish
```

The example targets the authority-session seam, not all runtime operations.
Select real affected packages and their consumers for each change. Commit/push
preflight still checks staged/head policy and the complete mixed-trust/offline
CI boundary; `--audit` runs that complete policy locally. No release gate is
removed, and no test is called passed merely because it was selected.

The modular program is complete only when M00-M17 have accepted versioned contracts, team owners, two-maintainer minimums, dependency/capability policies, testkits, SLOs, runbooks, and evidence; forbidden edges and production contamination are zero; composition owns no domain logic; concurrency preserves roots; the Node Commit Ledger proves recovery; M16 is guarded and non-authoritative; every repository and external blocker closes; and G5 remains false until an explicit signed governance record updates machine truth through protected review.
