# Trillionnium Chain Module Technical Reference v1

## Selected PoN scope and retained-source boundary

The selected development profile is `pon-nakamoto-v1`; PoCO-BFT is retired as the target.
Each module below begins with its new work/fork/model-commons responsibility. The existing
source, API and regression paragraphs that follow are explicitly **legacy source traces**;
they do not claim an implemented PoN runtime or impose a second PoCO roadmap.
New module-specific algorithms and acceptance live in the [eighteen technical specs](README.md).
The [PoN suite](../protocol/pon-nakamoto-v1/README.md) defines the shared semantics.
Compatibility profiles retain their original byte and proof meanings. Trace integrity
is not cryptographic work qualification, model-efficacy evidence or deployment authority.


Status: **active technical reference; non-roadmap; non-activation authority**  
Plan: `docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`  
Registry: `docs/development/module-registry-v1.toml`

This document defines the stable engineering contract for modules M00–M17. It
is subordinate to machine truth and the canonical development plan. It does not
change gate order, assign a new delivery sequence, or promote any production,
public-testnet, release, or activation flag. Exact source ownership is carried
by the module registry; exact implementation claims require accepted evidence.

## Applicability, implementation detail and review

Resolve `docs/architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md` before selecting a rule. Frozen v0, candidate PCC1, draft AI-v1 and `legacy-ledger-observation` are distinct profiles, not interchangeable versions. The ordered algorithms, failure/recovery semantics and requirement IDs for all M00-M17 modules are in `docs/modules/TRNM_MODULE_IMPLEMENTATION_GUIDE_V1.md`; the machine trace index is `config/documentation-contracts-v1.json`.

These references complement, rather than replace, the exact normative layouts and existing error registries. Structural coverage does not assess semantic implementability. Every enabled operation requires exact clause/schema/limit, state transition, errors, positive/negative vectors, implementation symbol and source-bound consumer replay. Missing or undecided operation-level details remain explicit acceptance blockers.

Implementation maintainers, consumer reviewers and qualified independent specialists are separate roles under `docs/modules/TRNM_INDEPENDENT_REVIEW_V1.md`. Repository fallback accounts confer no specialist qualification or independent acceptance. No unverified person or team is appointed by this reference.

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

**Selected PoN responsibility.** Own the versioned PoN header/template, work statement, target/parameter, contribution, evaluation, release, confirmation and reorg-event schemas. The codec does not choose a branch, issue local capabilities or certify the neural primitive. Preserve historical CEV0/CEV1 decoders in explicit legacy dispatch; no new value reuses an old tag with stronger meaning.

**PoN transition and recovery.** Resolve installed genesis/chain/profile before decoding. Bound total bytes, lists, depth, tensors, proof and signature work before allocation. Canonicalize only valid objects; reject duplicates, unknown mandatory fields, trailing bytes and target/profile substitution. Encode every challenge-affecting field once. Derive a stable block id from template and canonical output, not proof randomness. Specify exact signedness, endian, dimensions and output uniqueness with an independent encoder. Codec owns no store. Persisted schemas are separate from public wire schemas; M07/M03 own migrations. A historical decode returns its original proof class. State/error/limit registry changes require explicit profile version and consumer requalification, never parser fallback.

**PoN acceptance and source migration.** Independent positive/negative codec vectors, every truncated prefix, appended bytes, maximum and maximum+1, target overflow, changed model/base/schema and old-QC-as-work rejection. Test every consensus-affecting field against the same challenge relation. Reuse bounded canonical-codec patterns and exact historical verification. New header/work/model byte domains need implementation; old type names and existing golden vectors do not establish it.

### Legacy source contract and trace — not the selected PoN target

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

**Selected PoN responsibility.** Own strict cryptographic verification and private context-bound verified work/identity carriers. Mining keys identify producer and payout; they do not define a validator set or voting weight. Evaluation attestation and local authorization are separate proof types.

**PoN transition and recovery.** Authenticate the installed work profile and expected template/challenge, then exact-decode and verify the complete relation. Bind model/input, miner, payout, parent, dimensions and canonical output. Charge failed cryptographic attempts to the local budget. Return work validity only; M02 derives target/chainwork and M11 evaluates usefulness. Proof-of-execution does not demonstrate an adversarial work-cost lower bound by itself. Keep verification stateless except bounded non-authoritative caches keyed by complete profile/statement/proof context. Cache hits cannot mint additional lottery outcomes. Key rotation preserves historical verification while fresh local grants require current authority.

**PoN acceptance and source migration.** Independent verification implementation; invalid proof/weak key/wrong context/payout/template mutations; proof-randomness replay; degree/range/field mismatch; verifier-flood resource bounds; research attacks from NEURAL_WORK. Keep strict signatures, identity/role separation and legacy finality verifiers as history only. Neither StrictFinalityProof nor an accept-all test verifier can authorize a PoN block.

### Legacy source contract and trace — not the selected PoN target

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

**Selected PoN responsibility.** Own the single deterministic PoN consensus state machine. Retire Vote, TimeoutVote, QC, TC, locked/high-QC and weighted validator scheduling from the target. No majority model score or application settlement can choose a fork.

**PoN transition and recovery.** Validate parent/height/profile, exact branch-derived DAA target and median-time rule. Join M01 work and M06 body/state validity, then derive work=floor(2^256/(target+1)) from required target, not lucky digest. Accumulate exact chainwork. Adopt only a fully validated strictly heavier branch; equal work retains the current valid tip. Header-only chains request missing dependencies and cannot publish application state. M08 receives a bound reorg decision, not an unsigned tip suggestion. M07 stores branch nodes/roots/work and M08 owns durable active-tip changes. On recovery recompute work/target from verified ancestry before preferred-tip publication. Missing deep history triggers resync. A consumer confirmation depth is not a permanent fork lock.

**PoN acceptance and source migration.** PON-C01 through PON-C12: higher-height/lower-work forks, target mutation, lucky output, DAA boundary, equal work, unavailable body, future-time deferral, workload exhaustion and adversarial work reuse. Formal common-prefix/chain-growth model plus real network evidence remain separate. Reuse no-I/O Input/Effect architecture and bounded ownership patterns. Old BFT transitions are retired reference logic, not a second active consensus engine or PoN implementation.

### Legacy source contract and trace — not the selected PoN target

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

**Selected PoN responsibility.** Own the generation-fenced local mining/identity/effect publication boundary and its durable attempt journal. Custody authenticates producer/payout and authorized external use; it never votes, determines target or certifies model usefulness.

**PoN transition and recovery.** Bind template/challenge/input/model/profile/resource budget and worker generation before dispatch. Record physical attempt entry, run bounded work/proving, verify exact output, persist publication intent and retry identical publication only. New parent/template requires new charged work. Stale result remains attributable to its old attempt; it may support a separate model claim but not new chainwork. Use one writer per attempt namespace and independent rollback frontier where required. Recover dispatched unknown work by exact query/readback; do not reset history. Do not copy PoCO one-vote-per-view restrictions into valid PoW fork behavior. Local capability/revocation/effect history never rewinds on chain reorg.

**PoN acceptance and source migration.** Crash before/after dispatch, output, proof, intent and publication; ACK loss; stale parent; changing payout/body; pipe-capacity output; cancellation; host takeover; coherent store rollback; duplicate exact retransmission. Reuse descriptor/nonce/fence/custody and bounded worker mechanisms where matching. Retire SafetyRules vote locks and PoCO double-vote slashing as target requirements; retained signer records stay historical.

### Legacy source contract and trace — not the selected PoN target

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

**Selected PoN responsibility.** Own transport, discovery, bounded dissemination and authenticated resource/session context, not mining eligibility or consensus decisions. Peer identity authenticates a session, not stake, work, personhood or a right to exclude valid miners.

**PoN transition and recovery.** Admit cheap length/version/rate/session checks before proof work. Separate queues for headers/control, transaction data, large parameter chunks and proofs. Fetch competing branches from diverse sources. Return exact request/generation-bound results; a corrupt peer copy does not classify all copies invalid. Gossip verified blocks promptly without waiting for global model adoption. Retain replay/session and download cursors under their declared owner. Restart must not replay an obsolete response into a new attempt. Index parameters by exact content and codec, not mutable URL. Preserve partial-download checks and repair obligations.

**PoN acceptance and source migration.** Independent-host partition/heal, different-work forks, malformed chunks/proofs, stale sessions, adversarial peers, source diversity, author offline, bounded memory/queues and measured propagation/verification tails. Reuse safe framing, request binding, replay protection and bounded I/O. Retired validator mesh/ReadySet certificates are not PoN consensus admission.

### Legacy source contract and trace — not the selected PoN target

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

**Selected PoN responsibility.** Own provisional transaction admission, mempool and branch-aware nonce/reservation handoff. Inclusion, confirmation, model adoption and external execution are different facts. No mempool success or local WAL entry certifies a block.

**PoN transition and recovery.** Validate signatures/scope/nonce and bounded payload against the exact active state. Reserve provisionally without changing canonical balances. On block inclusion index its hash, not height alone. On reorg remove orphan inclusion, release/reconcile provisional state and revalidate transactions against new balances, nonces, grants and generation before requeue. Do not automatically create a new external attempt. Version existing WAL semantics to distinguish local request history from branch-derived reservations. Preserve identity and uncertain handoff across restart. A local operation terminal/effect-entry tombstone cannot disappear just because its chain transaction was detached.

**PoN acceptance and source migration.** Double submit, changed payload at same key, inclusion and depth regression, nonce conflict after reorg, sponsor exhaustion, missing history, signed stale authorization and no-side-effect rejection. Reuse exact request identity and durable handoff/readback patterns. Old Reserved/HandedOff/finalized labels require explicit new semantics; do not mass-rename stored enums.

### Legacy source contract and trace — not the selected PoN target

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

**Selected PoN responsibility.** Own parent-relative deterministic execution, resource metering and ordered reversible application deltas. It validates block roots, not the mining work predicate or preferred branch. Long training/inference stays in bounded workers.

**PoN transition and recovery.** Apply mandatory bounded deadline/refund/retention work first, then canonical transactions. Record actual read/write conflicts including shared sponsor, nonce, grant and budget rows. Produce complete forward/undo effects and state/receipt/model/reward roots. Parallel 1/2/4/8-worker execution must equal serial output. A valid proof cannot excuse unavailable bodies or nondeterministic evaluation. M07 owns commits and undo data; M08 coordinates active-chain changes. Persist source/target block hash/root and exact deltas, with readback. Reexecute only deterministic chain application; external provider effects remain in their independent journal and are never undone by a database rollback.

**PoN acceptance and source migration.** Serial/parallel root equality, reject-no-write, attach/detach replay equality, conflicting sponsor/nonces, rewards/model pointers unwound, deep replay and crashes across durable publication. Reuse deterministic native execution and checked metering. Introduce versioned undo/branch carriers; old P/D/C/K finality assumptions remain legacy until adapted and qualified.

### Legacy source contract and trace — not the selected PoN target

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

The native complete-body implementation now speculates real frozen-v0 runtime
attempts in batches of at most 32 on at most 8 workers, recording actual reads
and validating absence/type/version/full-value dependencies before ordered
reuse or re-execution. PoCO/lifecycle operations remain barriers; mutation
staging, final roots and durable commit remain ordered. This private scheduler
does not import the separate AI-v1 transaction or fee profile. Read/result
retention limits, fallback behavior and exact differential tests are specified
in the implementation guide's M06 native worker boundary. A private proof for
successful transfers permits canonical rebasing of only the checked collector
fee addition/version while all other dependencies remain exact; explicit
collector operations remain barriers. This removes forced collector retries
for independent transfers, without asserting a measured throughput gain.

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

**Selected PoN responsibility.** Own canonical state schemas, branch roots, undo/checkpoint storage and authoritative chain-state writes. It does not select a fork or own local Hepta learning facts. Parameter bytes are M09/Hepta artifacts referenced by authenticated roots.

**PoN transition and recovery.** Check descriptor-bound namespace, schema and current writer generation. Validate source root before staging reversible changes. Retain forward/undo lineage per block hash, then atomically publish the M08-approved active generation only after exact readback. Rebuild derived indexes from authenticated state. Do not use height as unique identity or copy all state per small read. Use PinnedSqliteNamespace-style identity/fence/sidecar protection and explicit new branch schema. Chain balances/nonces/model pointers roll back; independent local effect/revocation anchors do not. Deep reorg beyond retained undo triggers verified rebuild, not permanent rejection of heavier valid work. Crash recovery must recognize only exact old, intermediate intent or exact new states.

**PoN acceptance and source migration.** Fault injection at every stage/detach/attach/head/ack cut; two-writer races; same-height different-root snapshots; old profile replay; prune-depth resync; resource accounting and bounded query/restart tails. Reuse exact schema validation, incremental deltas, descriptor fences and readback. Current append-finalized implementation is not claimed to provide the required PoN undo schema.

### Legacy source contract and trace — not the selected PoN target

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

**Selected PoN responsibility.** Own realization of M02 preferred-branch decisions, consistent confirmation views and recovery publication. It does not invent finality, select a second fork or use a QC to lock PoN history. Local policy confirmations remain reversible.

**PoN transition and recovery.** Accept only a bound M02 branch decision with all dependencies valid. Determine common ancestor and ordered detach/attach, persist intent, apply through M06/M07, verify roots, atomically publish active generation, then send idempotent index/outbox changes. Recompute confirmations and reward maturity. Crossing a local threshold never turns a valid deeper reorg into invalid consensus. One Node Commit Ledger-style owner coordinates the exact reorg. Reopen by matching predecessor, intent, old/new roots and durable readback. Unknown commit/ack remains fenced. M03/Hepta effect and revocation histories are joined for reconciliation, not rolled back. Keep historical model-output identity.

**PoN acceptance and source migration.** Deep reorg after payout/model use, crashes during all stages, index ACK loss, failed replacement, unavailable ancestors, isolated client views, local revoke retained and authoritative query of already executed remote effects. Reuse durable coordinator/intents/readback. Retire three-QC ancestor-finalization and joint epoch handoff for new history; retain their old decoders and storage meaning solely for migration.

### Legacy source contract and trace — not the selected PoN target

**Authority.** M08 owns ordered application finalization, the append-only Node
Commit Ledger, projection coordination, restart convergence, recovery actions,
and publication eligibility. It cannot independently choose a fork or override
M02/M03 authority.

**Primary code.** `trnm-core-restart-v0` and
`trnm-poco-order-application-v1`; it coordinates M03, M06, M07, and M13
contracts.

**Ledger contract.** Candidate PCC1 uses separate domain lifecycles:

```text
signing:  Validated -> IntentDurable -> SignatureRecorded -> VotePublished
finality: FinalityVerified -> CommitIntentDurable -> ApplicationApplied
          -> CommitRecorded -> CheckpointConfirmed -> ReceiptPublished
```

Vote publication does not wait for finality of its own block; it requires the
exact durable Safety/signing authority and required anchor. Receipt publication
requires finality, application/commit durability and checkpoint confirmation.
The old `Prepared → ApplicationSealed → SafetyPersisted → SignIntentPersisted →
SignatureConfirmed → FinalityApplied → CheckpointConfirmed → OutboundPublished`
chain is `legacy-ledger-observation`: retained local stage vocabulary, not a
shared publication rule or proof that domain operations occurred. Stored tags
are not renamed by this documentation change. Unmapped historical records stay
inert until explicit owner/fact/predecessor/recovery mapping is qualified.

The legacy record format binds generation, chain/validator/application identity,
height/view/block/parent, proposal and proof digests, pre/post roots, receipt/event
roots, Safety revision, signer watermark, finality proof, checkpoint predecessor,
prior digest and durable sequence. PCC1 consumers must verify the corresponding
domain facts; a field list or a caller stage is not authority.

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

**Selected PoN responsibility.** Own bounded artifact publication, availability, repair and retention responsibilities. A model root or receipt is not the model bytes, and storage attestations do not choose a ledger branch. Parameters must remain usable without the contributor online.

**PoN transition and recovery.** Validate canonical bounded manifest and permissible data format, reserve storage/repair obligations, receive and verify actual chunks, reconstruct exact bytes and attest only the declared availability statement. Global adoption requires all base/expert/router/calibration dependencies available under the chosen profile. Replicate across declared independent custodians and check retrieval rather than counting URLs or signatures. Retain content-addressed bytes and responsibility records through evaluation/challenge/reward horizons and accepted replay policy. A chain reorg may change entitlement but cannot justify deleting evidence still needed for unresolved disputes or recovery. Reference-aware garbage collection never deletes shared base weights still used by another release.

**PoN acceptance and source migration.** Author-offline retrieval, one/multiple replica failures, malicious manifests/chunks, exact size bounds, repair exhaustion, shared-base GC, reorged release retention and privacy/use-policy rejection. Reuse bounded chunk/retention/repair and durable artifact patterns. Old weighted availability committees are not PoN fork-choice authority; any attested storage profile must disclose its separate trust assumptions.

### Legacy source contract and trace — not the selected PoN target

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

**Selected PoN responsibility.** Own the deterministic chain lifecycle for parameter contributions, evaluation/composition jobs and public release proposals. Hepta remains owner of local training and private task data. M10 cannot self-certify a useful model, mint reward or issue local execution permission.

**PoN transition and recovery.** Admit exact parent model, compatible family/layers/ranks/numeric profile, real parameter bytes and publication/use conditions. Reserve evaluation/retention obligations and lock the evaluation plan before results. Consume M11 typed evidence and whole-model composition outcomes, then propose a reproducible release and M12 allocation. Mining success alone cannot admit a model. Non-miners may contribute useful trained updates. Chain lifecycle and adopted-release pointers are branch-derived; local training/artifact lineage and actual effect records remain with Hepta. Reorg transitions invalidate current adoption/entitlement without rewriting historical model outputs. Every retry binds the same original identity or an explicitly new authorized attempt.

**PoN acceptance and source migration.** Real task to parameter to independent evaluation to composed model to independent free consumer and next contribution. Test incompatible bundles, duplicate attempts, cancel/late receipt, author loss, complementary experts, no improvement and model-release reorg. Reuse task/lease/escrow/attempt/capacity state ownership and bounded worker execution. New contribution/evaluation/release transitions are unimplemented until actual registered consumers execute them.

### Legacy source contract and trace — not the selected PoN target

**Authority.** M10 owns agent identities as application objects, root/session
capability lifecycle, nonce lanes and budgets, task offers, bids, leases, escrow
reservation, deadlines, checkpoint/resume, migration, cancellation, timeout,
and refund state transitions. It cannot order blocks, sign consensus messages,
or treat external compute as deterministic without an M11 profile.

**Primary code.** `trnm-poco-agent-market-v1` and `trnm-worker-agent`. The
candidate archive owner is `archive_store.rs::TaskArchiveStoreV1`; it is a
local durable adapter and does not promote the planned terminal service to
production authority.

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

The candidate archive owner persists a policy-bound live root, legal-hold
snapshot, contiguous seal chain and archived terminal records. Archive/delete
is one immediate SQLite transaction with reopen-time chain/root audit and exact
retry receipts. It still requires an authenticated whole-node terminal/retention
permit, external hold authority and independently accepted multi-host,
power-loss and scale evidence before any production deletion claim.

**Verification.** Capability revocation/delegation, shared-budget concurrency,
all lifecycle terminal paths, crash recovery, conservation, wallet/RPC/SDK, and
Node proof integration are required. SLO profile: `candidate-application-v1`.

---

## M11 — Verification / Challenge

**Selected PoN responsibility.** Own pinned evaluation and challenge semantics for public model benefit, distinct from M01 work-proof cryptography and M02 fork choice. No evaluator majority, model rank, stake or subjective truth assertion creates chainwork.

**PoN transition and recovery.** Lock exact candidate/reference, compatibility, data strata, metrics, uncertainty, resource allowance and composition recipe before testing. Run isolated independent cross-node held-out and future-window evaluations. Test whole composition and old-task regression, not just local training loss. A deterministic public profile verifies reproducible outputs; private/human assessments have explicit attested trust classes. Apply bounded rules to current chain state without retroactively changing valid block work. Store immutable plan/evidence identity, accepted result and challenge responsibility under the existing owner. Reorged acceptance is not current adoption; retain source-bound evidence and failed observations. Evaluator failure or unavailable data is not a fabricated positive or fraud verdict.

**PoN acceptance and source migration.** Candidate/reference/input/profile replacement, repeat benchmark gaming, bad loader/backdoor probes, whole-model degradation despite expert gain, complementary bundles, evaluator conflicts, timeout/Unknown preservation and independent work-primitive shortcut attacks. Reuse context-bound verification/result types and challenge persistence. Current StakeQuorum/business attestation remains legacy evidence semantics, never a substitute for new permissionless neural-work consensus.

### Legacy source contract and trace — not the selected PoN target

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

**Selected PoN responsibility.** Own deterministic asset accounting and three separate economic responsibilities: mining reward maturity, adopted-model gain rewards and actual serving/evaluation/storage payment. Consumption-derived voting power and validator-weight phases are retired from the target.

**PoN transition and recovery.** Apply fixed genesis/profile issuance, fee and maturity rules only for active valid-chain blocks. Unlock a bounded model pool only for credible whole-model improvement under the locked plan; zero gain pays zero. Allocate accepted nonnegative contribution scores using exact floor arithmetic and retain dust. Root work has one budget across parents/experts/cells. Fund and reserve bounded public inference before service, separately accounting tokens and in-kind resources. Account balances, claim nullifiers, subsidy maturity and release entitlement revert with branch state. Actual off-chain delivery/payout observations do not. Reconcile orphaned external effects under a declared policy before reissuing; SQL rollback does not recover money or undo an API call.

**PoN acceptance and source migration.** Conservation through reorg/restart, zero score and no-gain allocation, floor/dust, repeat claims, split contributions, reward maturity crossed by deep fork, insufficient sponsor funds, free-tier Sybil load and non-idempotent external payout recovery. Reuse exact escrow/resource conservation, typed settlement and replay principles. Existing consumption-rollup formulas and bond-weight selection are legacy-only, not adopted PoN reward or work rules.

### Legacy source contract and trace — not the selected PoN target

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

**Selected PoN responsibility.** Own verification of PoN work/header ancestry and application inclusion/snapshot provenance, bounded sync and explicit legacy import. It does not trust peer-supplied chainwork or convert old finality to new work. A light client exposes its availability and full-validation assumptions.

**PoN transition and recovery.** Verify every required target/work/profile/time relation along the relevant branch, accumulate work, compare peers under the accepted light-client model and bind inclusion to an observed best tip. Header-only/SPV verification does not independently establish complete model-data availability or execution validity. Full sync fetches/reexecutes missing bodies/state before service. Export all balances/escrow/nonces/tasks/profiles/retention and classify old proof strength before fresh-namespace import. Persist checkpoint/sync progress with exact chain/root/schema and branch generation; do not infer finality from a cached tip. Deep reorg beyond pruning triggers authenticated reconstruction. Legacy key/WAL state remains read-only; fresh PoN identity never resets the same signing/effect namespace.

**PoN acceptance and source migration.** Independent header/work chain and inclusion parser, competing-work views, missing body/data, deep replay, interrupted import, conserved escrow/retention, separate old/new asset semantics and old proof-class mislabel rejection. Reuse bounded download/staging, exact root reconstruction and classified legacy proof readers. New PoN sync/confirmation proofs need explicit new codecs; WeakSubjectivityAnchorV0 cannot be renamed a PoN work anchor.

### Legacy source contract and trace — not the selected PoN target

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

The v1 finality receipt verifier fixes transaction and object proof tree domains
and checks path length, direction, and duplicate-last padding against the
declared leaf index/count. Equal real leaves and equal subtrees remain valid.
This Merkle format does not independently commit the exact leaf count in its
root: appending a duplicate final leaf can produce the same root. Consumers must
not treat the proof's count as an authenticated total. Removing that ambiguity
requires a separately versioned root/count commitment and producer/consumer
review; the existing receipt schema and root rules remain unchanged.

**Verification.** Arbitrary-length trust paths, skipped views, epoch transitions,
hostile peers/chunks, checkpoint renewal, snapshot restart, independent parser,
and cross-version migration proofs are required. SLO profile:
`bounded-io-runtime-v1` for download and `contract-library-v1` for verification.

---

## M14 — RPC / Indexer / SDK / CLI

**Selected PoN responsibility.** Own non-authoritative RPC/indexer/SDK/CLI and public model-use surfaces. User-visible states are submitted, included, policy-confirmed, reorged and adopted-under-profile, not unconditional finalized. A UI cannot elevate an attestation into a work or local authority proof.

**PoN transition and recovery.** Read the verified active-chain view and index contiguous add/remove events idempotently. Verify confirmations/inclusion through M13, expose reorg and stale observations, and refuse unknown proof classes. Serve reproducible release manifests and parameter bytes through M09. Bind each inference request to a supported deployment profile and reserved free quota; do not hide missing experts or mutable backend switches. Indexer/cache/projection is rebuildable and never authoritative for balances or adoption. Reorg updates remove/add entries atomically by generation. Persist client requests and exact returned model identity when needed; a retry cannot turn a past execution into a fresh free request silently.

**PoN acceptance and source migration.** SDK independently checks new proof classes, reorged rewards/model pointers, incomplete bundles, author offline, reduced deployment profile labeling, stale cache, free-tier overload and exact inference model binding. Reuse safe bounded RPC and source-bound projections. Existing finalized DTOs and legacy client paths stay explicitly historical until actual consumers adopt probabilistic states.

### Legacy source contract and trace — not the selected PoN target

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

**Selected PoN responsibility.** Own composition, startup/shutdown, packaging and activation of one ordinary PoN node with separately owned services. It contains no domain state machine, alternative consensus, model trainer or hidden task store.

**PoN transition and recovery.** Bind exact genesis/profile/work primitive and binaries; acquire writer/authority fences; reopen branch/application/effect journals; reconcile unfinished reorgs and external operations; load bounded networking/verification/mining workers; only then admit work and requests. Hepta startup uses existing model/artifact/operations owners. Shut down with bounded drain and retained unresolved identity; never discard an attempt to regain readiness. Startup joins M03/M07/M08/M13 exact contexts and independent local effect frontiers. Recover one owner per domain, not filesystem-inferred authority. Fresh-genesis migration keeps legacy namespace read-only. Global release inclusion does not force local model activation; use new admitted generations.

**PoN acceptance and source migration.** Exact binary ordinary startup/request/shutdown; real work/fork/reorg; integrated Hepta parameter loop; author/worker failures; multi-host recovery and power cuts; actual Cargo production closure excludes retired active BFT logic; independent accepted deployment. Reuse thin host/port composition, bounded worker/process controls and release provenance. Old PoCO candidate host remains legacy source; new runtime is not claimed implemented by these documents.

### Legacy source contract and trace — not the selected PoN target

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
handoff bindings. `trnm-native-application` is active M06 native product code and
is required by the `node-prod-v0` build closure. The retired `trnm-node` package
is absent from the tracked workspace; its provenance remains in Git history.

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

**Selected PoN responsibility.** The global control plane is advisory. It can propose composition/router/resource choices and summarize measurements; it cannot set chainwork, choose forks, issue capabilities, alter difficulty at runtime or automatically activate code/models.

**PoN transition and recovery.** Read permitted source-bound observations and fixed public evaluation plans. Generate bounded expert/graph/router or distillation candidates within registered interfaces, including reuse/no-change. Submit through M10/M11 for independent evaluation. Hepta retains local NDU objectives and four subject levels; no mandatory global RPC on Cell/reflex paths. Keep proposal lineage and non-authoritative telemetry with exact versions; canonical parameters, release state, budgets and learning facts stay with existing owners. A reorg invalidates chain-derived proposal context, not local history; recompute/revalidate without elevating caches.

**PoN acceptance and source migration.** No-change and abstain paths, compatible/invalid composition proposals, whole-system gains vs local optima, missed windows, failed model proposal, stale/reorged context and continued system safety with this service disabled. Reuse observer/planner/guard separation. Old advisory control does not acquire consensus or production activation through the new PoN name.

### Legacy source contract and trace — not the selected PoN target

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

**Selected PoN responsibility.** Own source-bound observability, conformance/fuzz/formal campaigns and independent evidence intake. A checker cannot certify itself as a cryptographic authority, economics reviewer, model evaluator or release approver.

**PoN transition and recovery.** Resolve exact source/tree/base/binary/profile and changed responsibility. Run read-only document/registry tests, independent codecs/work verifiers, formal consensus/reorg properties, actual multi-host mining and model learning/use experiments. Preserve failures, missing data and censored runs. Explicitly test old model/nonce/proof reuse, work shortcuts, poisoned experts, split rewards and orphaned effects. Immutable evidence references bind raw traces and authoritative producer identities; collector stores are not domain truth. Historical PoCO tests retain their original source/profile and cannot be reused as PoN security. Reorg observations record both branches and local irreversible history.

**PoN acceptance and source migration.** All PON-C/R/M/E/X cases, independent byte/work implementations, crash/power-loss/multihost campaigns, whole-model future-window usefulness, free-tier actual service, conservation and attack-cost experiments. Document/reference tests alone never imply these passed. Reuse exact-source evidence pipeline, failure retention, CI trust separation and source-graph checks. Retire PoCO release milestones as the active work sequence; retain legacy source regressions only for affected compatibility code.

### Legacy source contract and trace — not the selected PoN target

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

A registry row mapping primary source units, references, test roots, SLOs,
maintainers, dependencies, capabilities and evidence proves navigation and
ownership coverage only. Detailed-design acceptance additionally requires the
implementation guide's operation-level version/state/error/vector/symbol traces
and qualified independent semantic review. A file-path or requirement-count pass
does not grant that acceptance.

Implementation completion additionally requires exact-source execution and
authenticated accepted evidence. Maintainer routing is not independent review;
vacant specialist roles and unaccepted vectors remain visible blockers.
Production and activation remain governed solely by machine truth, protected
review, external evidence and signed governance records.

## Cargo graph and module quotient assessment

The existing build-closure command can also consume real locked/offline Cargo
metadata for the host target. It retains normal, dev and build dependencies,
optional declarations, target predicates and resolved feature names separately.
A module quotient contracts multiple crates into one Mxx bucket; a cycle there
is not evidence of a normal Cargo cycle. In particular a pure rule and its
storage adapter may belong to one module but have different dependency roles.
The audit reports exact source/destination crate witnesses for every undeclared
module edge and every quotient edge. No existing edge is silently whitelisted.
`--require-module-architecture` emits its report and fails when actual normal
crate cycles, undeclared normal module edges, unknown/ambiguous module membership
or module quotient cycles violate the declared registry. `--audit-module-graph`
reports those gaps without pretending build-closure qualification is architecture
acceptance. The existing per-product Cargo-tree feature comparisons remain the
authority for production composition; workspace metadata uses unified workspace
features and must not be labeled as an individual binary's feature graph.
Manifest/lock/registry bytes are checked before and after collection. No metadata
result changes a runtime capability, source module ownership or release flag.
