# Trillionnium Chain Module Technical Reference v1

Status: **active technical reference; non-roadmap; non-activation authority**  
Plan: `docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`  
Registry: `docs/development/module-registry-v1.toml`

This document defines the stable engineering contract for modules M00–M17. It
is subordinate to machine truth and the canonical development plan. It does not
change gate order, assign a new delivery sequence, or promote any production,
public-testnet, release, or activation flag. Exact source ownership is carried
by the module registry; exact implementation claims require accepted evidence.

## Common module contract

Every module exposes versioned contracts, deterministic or explicitly
non-authoritative cores, bounded adapters, a test surface, and an evidence
surface. Cross-module calls use typed ports, immutable events, authenticated
proofs, or consumed non-cloneable capabilities. Raw database handles, transport
objects, clocks, filesystem paths, process handles, private keys, and mutable
implementation types may not cross a module contract unless the receiving
module is explicitly the authority owner for that resource.

The common failure rule is fail closed. Unknown schema, protocol, profile,
capability, root, proof, recovery state, or activation version is rejected.
Ambiguous durable acknowledgement is never guessed. A retry is permitted only
when the same idempotency identity can be revalidated against fresh durable
state. Every queue and public decode surface has finite byte, item, nesting,
signature-work, state-access, CPU, memory, disk, and network bounds.

### SLO profiles

| Profile | Applies to | Required measurements |
|---|---|---|
| `contract-library-v1` | codecs, types, crypto verifiers | decode/verify latency, allocation bound, rejection accuracy, compatibility |
| `authority-hot-path-v1` | order, Safety, state commit, finality | committed goodput, p50/p95/p99 finality, crash recovery, root invariance |
| `bounded-io-runtime-v1` | networking, mempool, storage adapters | queue pressure, admission latency, drop/retry rate, disk/network cost |
| `candidate-application-v1` | Agent, DA, Verify, Settlement candidates | transition latency, conservation, replay, storage growth, authority non-claims |
| `non-authoritative-service-v1` | RPC, indexer, CLI, control plane | freshness/lag, availability, rate limits, stale-read signalling, rollback |
| `evidence-tooling-v1` | benchmark, fuzz, formal, audit tooling | reproducibility, exact-source binding, false-pass resistance, artifact integrity |

A module does not satisfy its SLO merely by naming a profile. Evidence must bind
workload bytes, source/tree, configuration, hardware, repetitions, percentile
denominator, confidence method, raw traces, and invalidation conditions.

---

## M00 — Protocol / Schema / Canonical Codec

**Authority.** M00 owns protocol identities, canonical encodings, domains,
closed enums, resource limits, parameter objects, error registries, positive and
negative vectors, and compatibility rules. It does not own networking,
persistence, signing, ordering, execution, or activation.

**Primary code.** `trnm-consensus-types`, `trnm-types`, `trnm-protocol`, and
`trnm-poco-order-types-v1`. Protocol prose, schemas, vectors, manifests, and
protobuf projections are part of the contract surface.

**Contract.** A valid object has an exact version, context, domain-separated
identity, bounded length and nesting, canonical field order, checked arithmetic,
and one unambiguous byte representation. Decoders reject unknown fields where a
closed schema is required, duplicate map/member identities, non-minimal values,
unsorted canonical sets, invalid UTF-8, trailing bytes, and cross-domain hash
substitution. Encoding an invalid object is not normalization authority.

**Invariants and failure.** Two independent implementations must agree on bytes,
object IDs, roots, limits, and exact errors. A schema conflict blocks freeze;
code does not silently override normative input. Version migration is explicit
and never treats a re-encoded old signature as a signature over a new object.

**Verification.** Required evidence includes schema linting, independent parser
and re-encoder, positive/negative/mutation corpora, fuzzing of every public
boundary, compatibility matrices, and formal obligations for consensus-visible
objects. SLO profile: `contract-library-v1`.

---

## M01 — Cryptography / Identity / Capability

**Authority.** M01 owns cryptographic verification policy, typed key and signer
identities, capability carriers, delegation and revocation semantics, and the
remote-signer protocol. It cannot decide fork choice, application validity,
state roots, finality, or activation.

**Primary code.** `trnm-consensus-crypto` and
`trnm-consensus-remote-signer-protocol`; signer implementations remain M03
adapters consuming M01 contracts.

**Contract.** Every signature statement binds chain/genesis context, protocol and
schema version, role, validator or agent identity, epoch/height/view or nonce,
object digest, and anti-replay domain. Key IDs and public keys are unique within
an authority set. Capabilities are scoped, versioned, budgeted, expiring where
applicable, non-escalating, and revocable by an authenticated successor.

**Security.** Verification is strict and constant-time where supported. Unknown
algorithms, malformed keys, duplicate signer weight, role substitution,
cross-chain replay, stale capability generation, and ambiguous key rotation fail
closed. Private keys never enter deterministic cores. Production custody
requires device-backed non-exportable keys and an external monotonic anchor;
local file watermarks are candidate evidence only.

**Verification.** Cross-library vectors, malformed-signature mutants, key
rotation/revocation tests, HSM protocol fault injection, and independent crypto
review are required. SLO profile: `contract-library-v1`.

---

## M02 — Order / Consensus Kernel

**Authority.** M02 owns the deterministic PoCO-BFT order state machine: proposal
admission predicates, weighted quorum calculation, QC/TC processing, lock and
safe-vote rules, epoch transitions, pacemaker effects, and order-finality
selection. It does not own sockets, clocks, databases, direct signing, execution
state roots, or settlement correctness.

**Primary code.** `trnm-consensus-core`; protocol types are consumed from M00,
cryptographic verification from M01, and durable Safety authority from M03.

**State machine.** Inputs are authenticated typed events plus an immutable prior
state. Outputs are a new deterministic state and bounded effects. Weighted
quorums count unique validator identity once. Timeout certificates do not unlock
or finalize by themselves. Finality follows the frozen certified-chain rule and
must bind the exact application transition selected by the proposal.

**Failure and recovery.** Nondeterministic scheduling, wall-clock reads, I/O
errors, and remote control-plane availability cannot alter transition results.
On restart M02 is reconstructed only from authenticated finalized reference,
Safety state, retained ancestry, and Node Commit Ledger position. Missing or
conflicting ancestry halts voting.

**Verification.** Model checking, retained unsafe mutants, Byzantine proposal and
message-order tests, partition/heal campaigns, epoch handoff, long ancestry, and
1/2/4/8-worker downstream root invariance are required. SLO profile:
`authority-hot-path-v1`.

---

## M03 — Safety / Signer / Checkpoint Authority

**Authority.** M03 owns persist-before-sign SafetyRules, vote/timeout intents,
monotonic signer watermarks, signer journals, external checkpoint CAS, and
hardware-signer adapters. It cannot invent proposal validity, fork choice,
application roots, or control-plane overrides.

**Primary code.** `trnm-consensus-safety-rules`, `trnm-consensus-safety-store`,
`trnm-consensus-signer-journal`, `trnm-consensus-unix-remote-signer`,
`trnm-consensus-unix-fleet-signer`, `trnm-consensus-external-watermark`,
`trnm-consensus-external-node-checkpoint`,
`trnm-consensus-remote-signer-service`, `trnm-whole-node-checkpoint-types`, and
`trnm-durable-file-adapters-v0`. The durable-file package supplies bounded,
hash-chained, sync-before-return repository adapters; it does not substitute for
device-backed custody, an independent monotonic anchor, or physical durability
evidence.

**Durability contract.** Safety state is durably advanced before a signature can
escape. Sign intent, signer result, watermark, checkpoint predecessor, node
generation, and exact statement digest are idempotently bound. Lost responses
are resolved by fresh exact readback, never by reminting. A cloned or rolled-back
state directory cannot resume signing without the independent external anchor.

**Security.** Double-sign potential, watermark regression, identity mismatch,
ambiguous CAS, stale checkpoint, or unsupported custody platform is a stop event.
Production adapters use authenticated channels, bounded messages, explicit
timeouts, non-exportable keys, rotation/revocation, and multi-party custody.

**Verification.** Every persistence/signature crash cut, HSM timeout, response
loss, restart/takeover, rollback, clone, rotation, and revocation case must be
exercised. SLO profile: `authority-hot-path-v1`.

---

The candidate `CandidateAuthorityJournalV0` in `trnm-durable-file-adapters-v0`
owns the recovered flag, root checks, strict successor validation and durable
receipt validation. Recovery and uncertain append failure close its readiness
barrier. M15 may delegate to it only through `persistent-authority-candidate`;
the default CLI runtime closure excludes the adapter. This seam records inert
caller facts, not domain acceptance or signing/finality authority.

## M04 — P2P / Session / Dissemination

**Authority.** M04 owns authenticated peer sessions, leases, bounded ingress,
message dissemination, peer scoring inputs, routing, backpressure, and transport
lifecycle. It cannot sign, vote, finalize, commit state, or label a deterministic
protocol error from local overload.

**Primary code.** `trnm-consensus-peer-lease` plus the I/O adapters hosted by the
node composition.

**Contract.** Sessions bind peer identity, chain/protocol profile, negotiated
limits, expiry, and replay protection. Decode occurs behind byte and work
budgets. Duplicate, delayed, reordered, fragmented, and replayed messages are
handled idempotently or rejected. Queue saturation returns an explicit local
availability result and cannot fabricate consensus invalidity.

**Failure and security.** Connection loss, partial writes, address churn,
Byzantine flooding, slow readers, and route disagreement are isolated from the
deterministic kernel. Authentication downgrade, peer-identity rebinding,
unbounded decompression, amplification, and per-peer/global quota bypass fail
closed.

**Verification.** Multi-host packet fault injection, bandwidth/CPU exhaustion,
peer churn, partition/heal, certificate rotation, and bounded queue tests are
required. SLO profile: `bounded-io-runtime-v1`.

---

## M05 — Transaction Admission / Mempool

**Authority.** M05 owns transaction envelope preflight, replay and nonce policy,
fee/resource admission, per-principal and global budgets, mempool WAL, canonical
handoff to ordering, expiration, replacement, and finalized tombstone/GC policy.
It does not choose canonical order or mutate finalized application state.

**Primary code.** `trnm-mempool`, `trnm-application-tx-builder-v0`, and
`trnm-tx-lifecycle-v0`. The lifecycle crate freezes deterministic phase,
receipt, authorization, replacement, broadcast-intent, finality-readback,
tombstone, and replay-floor contracts without opening a socket or holding a
signer.

**Contract.** Admission verifies exact canonical bytes, authentication,
chain/profile, nonce lane, access declaration, gas/resource caps, size, expiry,
and fee affordability against an explicitly versioned view. Accepted entries
have stable identities and idempotent WAL records. Recheck at proposal time uses
the authoritative parent state; stale local acceptance is not block validity.

**Recovery.** WAL replay distinguishes accepted, handed-off, finalized,
rejected, expired, and tombstoned records. GC requires finalized proof and the
replay floor; a lost acknowledgement is resolved by exact durable readback.
Overload may reject or defer locally without changing deterministic execution.

**Verification.** Replay/gap/duplicate/overflow mutants, WAL crash cuts,
replacement races, finalization/GC, adversarial access lists, and full
admission→broadcast→finality→readback traces are required. SLO profile:
`bounded-io-runtime-v1`.

---

## M06 — Deterministic Execution / MVCC / Meter

**Authority.** M06 owns deterministic application execution, immutable-parent
speculation, conflict detection, canonical re-execution, multidimensional
metering, receipts, events, and execution-root production. It cannot choose
proposal order, bypass Safety, or directly publish finality.

**Primary code.** `trnm-native-application`, `trnm-native-execution-v0`,
`trnm-executor`, `trnm-poco-mvcc-fee-v1`,
`trnm-poco-global-execution-v1`, and `trnm-runtime`.

**Execution contract.** Canonical order and an authenticated parent snapshot are
inputs. Speculation may run in parallel, but conflict resolution and the commit
plan are deterministic. Worker count, CPU topology, interleaving, retries, and
queue timing cannot change writes, roots, fees, receipts, events, or errors.
All arithmetic is checked and all resource dimensions have hard bounds.

**Failure and recovery.** Speculative state is disposable. Only a sealed,
collision-checked write plan may reach M07 and M08. Partial execution, panic,
resource exhaustion, or adapter failure leaves the authoritative parent
unchanged. Re-execution from the same bytes and parent must reproduce the exact
artifact.

**Verification.** Clean and conflict-heavy workloads at 1/2/4/8 workers,
property tests, deterministic replay, crash/restart, meter overflow, hotspot and
abort-storm campaigns are required. SLO profile: `authority-hot-path-v1`.

---

## M07 — State / JMT / Authoritative Storage

**Authority.** M07 owns canonical key derivation, sparse/JMT state, membership and
non-membership proofs, pruning, snapshots, authoritative SQLite namespace and
schema ownership, and durable application/state projections. It cannot vote,
sign, choose forks, or infer finality from local writes.

**Primary code.** `trnm-state`, `trnm-native-application-sqlite`, and
`trnm-poco-order-state-v1`.

**Storage contract.** Every authoritative open is mediated by a
`PinnedSqliteNamespace`: descriptor-bound parent, no-follow and relative opens
where supported, database plus WAL/SHM/journal/lock/anchor identity, closed-world
schema and pragma digest, chain/store/generation binding, and pre-open,
post-open, pre-return, post-close, and reopen verification. Fresh-create,
read-only, and read-write modes are distinct.

**Recovery.** Committed and prepared states are explicit. Metadata-only,
state-only, replaced-file, partial sidecar, rollback, schema drift, or ambiguous
third states are fenced. Pruning preserves required proof and replay horizons;
snapshot installation validates exact schema, root closure, signer policy, and
lifecycle authorization before replacement.

**Verification.** Path/link/mount/sidecar/replacement mutants, closed-world schema
mutants, fsync and power-loss campaigns, million-object restart/prune/restore,
proof preservation, and exact replay are required. SLO profile:
`authority-hot-path-v1`.

---

## M08 — Finality / Node Commit / Recovery

**Authority.** M08 owns ordered application finalization, the append-only Node
Commit Ledger, projection coordination, restart convergence, recovery actions,
and publication eligibility. It cannot independently choose a fork or override
M02/M03 authority.

**Primary code.** `trnm-core-restart-v0` and
`trnm-poco-order-application-v1`; it coordinates M03, M06, M07, and M13
contracts.

**Ledger contract.** The monotonic hash-chained sequence is:
`Prepared → ApplicationSealed → SafetyPersisted → SignIntentPersisted →
SignatureConfirmed → FinalityApplied → CheckpointConfirmed →
OutboundPublished`. Every record binds generation, chain/validator/application
identity, height/view/block/parent, proposal and proof digests, pre/post roots,
receipt/event roots, Safety revision, signer watermark, finality proof,
checkpoint predecessor, prior digest, and durable sequence.

**Recovery.** Each subordinate store is an idempotent projection or a separately
named authority. Recovery reaches the exact durable source or exact durable
target. Ambiguity produces a machine-readable stop/rebuild/review action. A
signature cannot be reissued merely because publication acknowledgement was
lost.

**Verification.** Exhaustive crash cuts, lost replies, reordered projection,
rollback, duplicate replay, process takeover, disk-full, and root convergence
are required. SLO profile: `authority-hot-path-v1`.

---

## M09 — Certified Data Availability

**Authority.** M09 owns transaction-batch and artifact commitments, durable
store-before-attest, availability policies and committees, chunk proofs,
retrieval, repair, retention obligations, GC holds, and objective withholding or
equivocation evidence. DA attestations are not consensus votes.

**Primary code.** `trnm-poco-da-v1`.

**Contract.** Batch identity binds exact canonical bytes, author sequence,
namespace, chunking, committed policy, and durable manifest. Attestations escape
only after bytes and metadata are durable. Certificates count unique committee
identity once and satisfy the committed weighted policy. Retrieval proves every
chunk path and reconstructs the exact batch before repair.

**Recovery and security.** High-watermarks are checksummed and monotonic. Exact
replay is idempotent. Rollback, row deletion, sequence reuse, alternate bytes,
certificate rebinding, early GC, quota bypass, and duplicate signer weight fail
closed. Production deletion requires a finalized whole-node permit.

**Verification.** Durable-before-attest crash cuts, remote retrieval/repair,
retention expiry, withholding adjudication, quota/backpressure, multi-host
committee faults, and state-sync integration are required. SLO profile:
`candidate-application-v1` until Node authority is integrated.

---

## M10 — Agent / Task / Market

**Authority.** M10 owns agent identities as application objects, root/session
capability lifecycle, nonce lanes and budgets, task offers, bids, leases, escrow
reservation, deadlines, checkpoint/resume, migration, cancellation, timeout,
and refund state transitions. It cannot order blocks, sign consensus messages,
or treat external compute as deterministic without an M11 profile.

**Primary code.** `trnm-poco-agent-market-v1` and `trnm-worker-agent`.

**Contract.** Every delegated action binds controller/session key, capability and
session generation, exact lane/nonce/version, operation body, scope, budget, and
order-finalized execution context. Task and escrow creation are atomic. Lease
acceptance consumes the exact bid and task revision; provider acceptance cannot
retarget the task. Balances, bonds, and escrow are conserved.

**Recovery and security.** Replay returns the original receipt without duplicate
budget or nonce change. Stale generations, unavailable commitment carriers,
unsupported scopes, partial multi-object transitions, and ambiguous durable
state fail closed. Private prompts, data, weights, and outputs remain off-chain
unless committed through declared profiles.

**Verification.** Capability revocation/delegation, shared-budget concurrency,
all lifecycle terminal paths, crash recovery, conservation, wallet/RPC/SDK, and
Node proof integration are required. SLO profile: `candidate-application-v1`.

---

## M11 — Verification / Challenge

**Authority.** M11 owns verification-profile registries, compute receipt
statements, evidence binding, result authority, challenge and appeal lifecycle,
evaluator independence, and verifier decisions. It does not grant order
finality or move settlement funds directly.

**Primary code.** `trnm-poco-verify-challenge-v1` and `trnm-oracle`.

**Contract.** A profile fixes verifier class, statement, evidence, committee or
proof policy, deadlines, error semantics, privacy/retention obligations, and
result maturity. Unknown profiles and implicit fallback fail closed. Claims bind
one exact task/lease/attempt/result, required DA policy, sequence, and evidence.
Signer identities and weights are unique.

**State and recovery.** Evaluation history, result, challenge bond, evidence,
provider response, and adjudication are atomic or exact-replayable. Successful
challenge is a forward order-finalized transition; it never reorgs an
order-finalized block. Inconclusive and unavailable are distinct from invalid.

**Verification.** All declared profile classes, malformed proofs/attestations,
correlated evaluators, concurrent challenges, appeal windows, evidence
retention, privacy leakage, crash cuts, and independent verifier
interoperability are required. SLO profile: `candidate-application-v1`.

---

## M12 — Settlement / Economics

**Authority.** M12 owns fee and price application, escrow conservation,
consumption receipts and rollups, reward/refund/slash allocation, challenge
consequences, and settlement finality. It cannot establish result correctness,
order blocks, or use unprofiled evidence.

**Primary code.** `trnm-poco-consumption-settlement-v1` and the migration-named
`trnm-pouw`; the latter carries compatibility/provenance semantics and is not an
implicit work-unit payout authority.

**Contract.** Settlement consumes an order-finalized, profile-valid,
challenge-closed result plus exact escrow, price table, policy, and eligible
consumption. All assets, fees, bonds, rewards, refunds, and burns use checked
arithmetic and conservation identities. Rollups are gap-free, uniquely keyed,
and cannot count one consumption event twice.

**Recovery and security.** Exact replay is idempotent; third states are fenced.
Related-party, Sybil, meter manipulation, verifier collusion, griefing, and
challenge-evasion assumptions are explicit inputs to economic review. Policy
changes activate only through versioned governance boundaries.

**Verification.** Multi-asset conservation, overflow, partial settlement,
challenge outcomes, slash/refund matrices, rollup replay, economic simulations,
and independent economic/security review are required. SLO profile:
`candidate-application-v1`.

---

## M13 — State Sync / Light Client / Proofs

**Authority.** M13 owns finality receipt verification, checkpoint and weak-
subjectivity anchors, trust-path iteration, state-sync verification, proof
transport, snapshot download validation, client upgrade rules, and fresh-genesis
migration verification. It cannot sign, vote, trust an unverified checkpoint, or
rewrite an in-place validator database.

**Primary code.** `trnm-poco-cross-plane-readback-v1`,
`trnm-poco-order-finality-verifier-v1`, `trnm-finality-types`,
`trnm-finality-verifier`, `trnm-migration-v0`, and `trnm-state-sync-v0`.
The migration crate verifies finalized source exports and deterministic target
projection; the state-sync crate verifies bounded arbitrary trust paths and
non-destructive staged installation.

**Contract.** A verified path binds chain/profile, validator and parameter sets,
epoch transitions, certified ancestry, finality rule, application/state/schema
roots, and checkpoint predecessor. State-sync accepts only chunks whose catalog,
root closure, schema, lifecycle authorization, and exact final root are
validated. Trust anchors are explicit operator/governance inputs, never inferred
from network majority alone.

**Recovery and security.** Missing history, conflicting checkpoints, stale weak-
subjectivity windows, downgrade, alternate schema, unreachable nodes, and
partial install fail closed. Download and verification are isolated; the
existing store is not destroyed until the replacement is fully verified.
Migration targets a fresh namespace and fresh genesis; legacy WAL or signer state
is never imported as production authority.

**Verification.** Arbitrary-length trust paths, skipped views, epoch transitions,
hostile peers/chunks, checkpoint renewal, snapshot restart, independent parser,
and cross-version migration proofs are required. SLO profile:
`bounded-io-runtime-v1` for download and `contract-library-v1` for verification.

---

## M14 — RPC / Indexer / SDK / CLI

**Authority.** M14 owns non-authoritative query, index, transaction-building,
SDK, CLI, and Web4 client surfaces. It cannot create consensus, state-root, or
finality authority, and it must expose freshness and proof level rather than
silently presenting stale data as canonical.

**Primary code.** `trnm-rpc`, `trnm-cli`, and the `web4-frontend` package. Typed
builders consume M00 contracts and finality/proof views from M13.

**Contract.** APIs are versioned, bounded, authenticated where mutating, and
return stable error codes. Responses bind chain, protocol/schema version,
committed height, finality class, root/proof where available, and indexer lag.
Simulation shares execution gas/fee semantics but discards mutations. Mock mode
is explicit and visually/semantically isolated.

**Operations and security.** Rate limits, pagination, maximum response work,
timeouts, cancellation, cache policy, index replay, reorg/finality handling, and
credential boundaries are explicit. A write path cannot bypass M05 admission or
M01 authorization.

**Verification.** Contract tests, generated-client compatibility, real-node
transaction→finality→readback E2E, stale/lag/error paths, browser tests, and
index rebuild/replay are required. SLO profile: `non-authoritative-service-v1`.

---

## M15 — Node Composition / Packaging / Release

**Authority.** M15 owns process lifecycle, dependency closure, adapter wiring,
configuration loading, binaries, packaging, reproducible builds, SBOM and
provenance assembly, release manifests, and operator handoff. Composition owns
no domain state machine and cannot silently promote machine truth.

**Primary code.** `trnm-poco-node`, `trnm-poco-node-authority`,
`trnm-poco-node-io`, `trnm-poco-node-host`, `trnm-poco-node-cli`,
`trnm-bridge-poc`, `trnm-node-boundary-v0`,
`trnm-poco-node-production-v0`, and `trnm-release-bundle-v0`. The boundary crate
contains versioned ports only; the production crate performs wiring only; the
release crate validates exact-source artifact, SBOM, provenance, signature, and
handoff bindings. Legacy `trnm-consensus-app` and `trnm-node` remain excluded
migration residue.

**Composition contract.** Separate closures are maintained for `node-prod-v0`,
`node-devnet-v0`, `ai-v1-candidate`, and `lab-and-evidence`. Production closure
contains no fixture, mock authority, benchmark, research, PoC, v1 candidate, or
legacy consensus runtime. Feature combinations cannot activate authority.
Configuration is closed-world, versioned, source-bound, and validated before
side effects. A composition object may route typed requests and lifecycle
signals but may not decide validity, mint a state root, weaken SafetyRules, or
set an activation flag.

**Operations and recovery.** Startup reconstructs exact durable authority before
network participation. Shutdown drains or durably records intents. Packaging
binds source/tree, toolchain, lockfile, build features, artifacts, SBOM,
provenance, configuration, and signatures. Rollback never reuses unsafe signer
state.

**Verification.** Dependency-closure scans, reproducible builds, clean install,
startup/shutdown/crash, upgrade/downgrade, operator error, artifact tamper, and
release rehearsal are required. SLO profile: `evidence-tooling-v1` for builds
and `authority-hot-path-v1` for node lifecycle.

---

`trnm-poco-node-authority` is a wiring facade with no local journal or recovery
state machine. Its optional `persistent-authority-candidate` feature selects the
M03 owner; `trnm-poco-node-host` forwards that explicit feature. The default host
exposes no persistent constructor or stage mutation. Existing candidate tests
are retained behind the opt-in seam, with a separate default CLI/build closure.
See the candidate ownership contract in
`docs/architecture/TRNM_POCO_NODE_DECOMPOSITION_V1.md`; independent acceptance
and full persistent-validator implementation remain open.

## M16 — Global Control Plane

**Authority.** M16 is an out-of-band observer and bounded optimization planner.
It owns module descriptors, telemetry ingestion, workload classification,
offline planning, signed plan/receipt formats, staged rollout, and rollback. It
cannot sign, vote, finalize, create roots, alter SafetyRules, bypass admission,
erase evidence, rewrite history, or activate production.

**Primary code.** `trnm-control-plane-v0` is the commissioned
non-authoritative contract/core library. It validates module descriptors,
measurements, bounded OperationalLocal plans, node-local guard decisions, and
action receipts. No networked control-plane service, production rollout daemon,
or production activation authority is commissioned; absence of those adapters
cannot be hidden by a mock.

**Plan contract.** `OptimizationPlanV1` binds source graph and digests, workload
assumption and validity region, finite resource bounds, workers/queues/batches,
placement, parameter class, activation boundary, expected effect, expiry, and
rollback. `ActionReceiptV1` reports exact acceptance/rejection, generation,
applied digest, resulting configuration, invariant results, and measured effect.
A node-local independent guard is final authority for acceptance.

**Safety and availability.** Optimization is lexicographic: safety,
determinism, durability, and compatibility violations must remain zero before
latency, cost, or goodput objectives are considered. Loss of M16 freezes tuning
at the last accepted safe plan; consensus continues. Initial operation is
read-only observation, and only bounded OperationalLocal proposals may advance
to a separately guarded apply request.

**Verification.** Schema/mutant tests, forged/stale/over-broad plans, guard
independence, shadow/canary/rollback, telemetry poisoning, planner infeasibility,
and control-plane loss are required. SLO profile:
`non-authoritative-service-v1`.

---

## M17 — Observability / Benchmark / Security / Evidence

**Authority.** M17 owns metrics and trace contracts, benchmark methodology,
fault/fuzz/formal harnesses, security scanning, audit/evidence schemas, exact-
source artifact binding, and gate reporting. It observes and tests authority but
cannot become production signing, consensus, state, or self-acceptance
authority.

**Primary code.** `trnm-bench`, `trnm-consensus-sim`,
`trnm-research-protocol`, `trnm-poco-lab-validator`, and
`trnm-production-adapter-conformance-v0`, plus `scripts/ci`, `formal`, fuzz
targets, evidence schemas, and read-only campaign tooling. The conformance crate
is a testkit and is forbidden from the production dependency closure.

**Evidence contract.** Every result binds source and prospective-merge identity,
plan/protocol/module/toolchain/dependency/configuration digests, topology,
workload and fault manifests, exact commands, raw artifacts, positive controls,
retained mutants, crash/replay boundaries, known gaps, invalidation set,
reviewers, signatures, and immutable locations. Failed evidence is retained but
is not active guidance.

**Benchmark and security rules.** Report committed goodput and finality tails,
not ingress TPS. Short fuzz smoke is not a long campaign. Simulation is not
multi-host or physical durability evidence. Self-authored, skipped, stale,
queued, cancelled, synthetic, or different-head runs are not acceptance.
Critical/High findings remain blockers until independently resolved and replayed.

**Verification.** The tooling itself requires deterministic regeneration,
false-pass mutants, artifact-tamper tests, independent review, multi-host/HSM/
power-loss campaigns, red-team/audit, and wall-clock soaks. SLO profile:
`evidence-tooling-v1`.

---

## Module completion rule

A module is technically documented only when its registry row maps every primary
source unit, contract and technical reference, test roots, SLO profile,
maintainers, dependencies, capabilities, and evidence roots. Documentation does
not establish implementation completion. Implementation completion additionally
requires exact-source tests and accepted evidence; production and activation
remain governed solely by machine truth, protected review, external evidence,
and signed governance records.
