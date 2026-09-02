# TRNM Repository Blocker Cores v0

Status: **repository implementation slice; not production activation**  
Plan: `trnm-chain-development-plan-v2`  
Protocol surface: `poco-bft-v0`  
Integration branch: `work/plan-v2-repository-blockers-closure-20260902`

This document is the implementation contract for the repository-owned slices
introduced to close the structural parts of `NODE-SPLIT-001`, `TX-PROD-001`,
`SYNC-PROD-001`, `MIG-001`, `MIG-014/016`, `CONTROL-001`, and release-bundle
provenance.  It is deliberately narrower than a production-readiness claim.
External hardware, multi-host, campaign, audit, soak, governance, and release
acceptance remain separate evidence gates.

## 1. Global authority model

The new crates obey one direction of authority:

```text
independent trust/governance configuration
              |
              v
versioned pure protocol cores
              |
              v
node-local durable adapters and guards
              |
              v
thin production composition
```

No control-plane, migration, state-sync, release, or composition API may sign,
vote, finalize, manufacture a state root, erase evidence, rewrite history,
bypass admission, import validator signing state, or activate production.
Those operations remain owned by the canonical consensus, SafetyRules,
application/state, signer, governance, and release gates.

All external effects follow intent/receipt discipline.  A production adapter
must durably persist an intent before exposing the effect, and must reject a
receipt whose operation id, sequence, digest, height, block id, state root, or
generation differs from the retained intent.

## 2. `trnm-node-boundary-v0` — explicit node decomposition

### Purpose

Defines versioned contracts between:

- the persistent kernel host;
- the authority coordinator;
- the bounded I/O runtime;
- the thin composition layer;
- the CLI adapter; and
- lab/evidence fixtures.

### Invariants

1. The host performs no work before recovery returns `Ready`.
2. `Quarantined` recovery is sticky at the composition boundary.
3. Every ingress frame is profile-, peer-, nonce-, and payload-bound.
4. Each host step has explicit item and byte budgets.
5. Authority stages advance only to the exact successor:
   `Prepared -> ApplicationSealed -> SafetyPersisted ->
   SignIntentPersisted -> SignatureConfirmed -> FinalityApplied ->
   CheckpointConfirmed -> OutboundPublished`.
6. Operation bindings include identity generation, height, view, block,
   parent, and proposal digest.
7. Composition and CLI roles may not own domain state.
8. Lab/evidence roles are not production-allowed.

### Integration

The existing node host must implement `AuthorityCoordinatorV0` over its durable
Node Commit Ledger and `IoRuntimeV0` over authenticated bounded network queues.
No in-memory reference coordinator is acceptable for production.

### Fault tests

Required adapters must cover process kill at every authority stage, replay of
the same command and receipt, mismatched operation binding, sequence overflow,
queue saturation, aggregate byte-budget overflow, peer/profile substitution,
and quarantine recovery.

## 3. `trnm-tx-lifecycle-v0` — production transaction lifecycle core

### State machine

```text
Admitted -> WalPersisted -> Proposed -> Ordered -> Executed -> Finalized
    |              |                                      |
    +--------------+-------------------------------> Tombstoned -> GC
```

Replacement is allowed only while the retained transaction is `Admitted` or
`WalPersisted`, and only for the same account/nonce with a strictly higher fee.
The replaced record is retained as a tombstone bound to the replacement id.

### Admission and replay rules

- chain id, sender, nonce, validity height, resource limits, payload, fee, and
  authorization are included in the canonical transaction id;
- payload, authorization, resource, and validity bounds are closed;
- authorization is verified through an injected verifier;
- a nonce at or below the finalized replay floor is rejected;
- identical submissions are idempotent;
- same account/nonce substitutions that do not satisfy replacement rules fail
  closed.

### WAL, proposal, execution, finality, and broadcast

- WAL sequence is durable and substitution-resistant;
- proposal id/index and ordered block/height/index are retained;
- execution receipt must match the ordered position and fee ceiling;
- finality witness must match the ordered block and height;
- broadcast uses a durable monotonic intent sequence;
- a transport receipt must exactly match the retained broadcast intent;
- finalized readback returns ordered, execution, finality, and optional
  broadcast facts from one retained record.

### Tombstone and GC

GC requires a non-zero authority digest, the same account, a replay floor
strictly greater than the transaction nonce, and a finalized height at least as
high as the retained finality witness.  Removing a mempool entry alone is never
sufficient authorization for deletion.

### Remaining adapter work

Production wiring must connect the state machine to the canonical WAL,
admission verifier, proposal handoff, executor receipt, finality store,
broadcast transport, read API, and tombstone database.  The pure core does not
claim those adapters are live.

## 4. `trnm-state-sync-v0` — authenticated non-destructive state sync

### Trust path

The trust anchor is independently configured and includes chain, protocol,
epoch, height, checkpoint, and validator-set digests.  Peers cannot select it.
A path may contain up to the closed protocol bound and must satisfy:

- exact chain/protocol binding;
- parent checkpoint continuity;
- strictly increasing height;
- same epoch or the exact next epoch;
- validator-set continuity; and
- injected proof verification for every link.

### Snapshot commitments

The protocol uses a one-way commitment graph with no hash fixed point:

```text
stable snapshot header digest
      -> each indexed chunk digest
      -> chunk Merkle root
      -> final manifest digest
```

The stable header excludes both `chunk_root` and `manifest_digest`.  The final
manifest binds the stable header and chunk root.  Every chunk binds the stable
header and index.  Duplicate identical chunks are idempotent; same-index byte
substitution is rejected.

### State-root verification and install

A canonical application adapter recomputes the target state root from ordered
chunks and the schema digest.  Installation writes only to a staging
generation.  The target may enter service only through
`commit_staging_cas(expected_current_root, ...)`.  Any failure requests staging
abort; it never rewrites the currently serving generation in place.

### Required production evidence

- arbitrary-length epoch/checkpoint path vectors;
- corrupt/missing/duplicated/reordered chunks;
- wrong chain, protocol, schema, state root, chunk root, and checkpoint;
- process kill during each staging phase;
- CAS conflict with a concurrently advanced current root;
- successful restart from the old generation after every failed install; and
- real multi-host catch-up to an independently anchored finalized checkpoint.

## 5. `trnm-migration-v0` — finalized export to fresh genesis

### Source verification

The source header binds chain, protocol, finalized height, source state root,
schema, finality proof, row count, and export root.  Rows are closed-bound,
strictly ordered, unique, and individually hashed.  The export root is
recomputed before projection.  Finality proof verification is injected and
must be independent of the exporting peer.

### Authority-state exclusion

The API refuses namespaces for validator private keys, signer journals,
SafetyRules stores, remote-signer watermarks, Node Commit Ledgers, and operator
recovery keys.  New validators must initialize fresh signing and safety state.
No direct database rewrite or legacy fallback path exists.

### Target projection

Projection is explicit and may omit or transform rows.  Resulting target keys
must be unique.  A target-schema-specific root builder recomputes the complete
root; a zero/placeholder root is invalid.  The plan binds distinct source and
target chain ids, target protocol/schema, fresh genesis id, and mandatory
`no_fallback` plus `downgrade_prohibited` flags.

### Cutover

Each attestation binds plan digest, target root, and fresh genesis id.
Duplicate signers and mismatched attestations are rejected.  An injected
verifier returns signer weight, and cutover requires the configured threshold.
This is a protocol primitive, not evidence that governance approval occurred.

## 6. `trnm-control-plane-v0` — observer-first guarded control plane

### Observer registry

Module descriptors bind contract, implementation, dependency graph,
configuration, capabilities, invariants, and generation.  Same-generation
substitution and generation rollback fail closed.  Measurements bind workload
and validity region and retain goodput, latency distribution, resource use,
queue pressure, errors, drops, recovery cost, and evidence digest.

### Plan classes

- `OperationalLocal`: accepted only from a node-local allowlist and within
  explicit integer bounds.
- `DeterminismCritical`: additionally requires shadow replay, worker-count
  invariance, and equal pre/post roots.
- `ConsensusCritical`: additionally requires an independently verified
  governance authorization bound to the plan and activation window.

The guard requires exact next generation, source graph, contract set, signature,
height window, rollback plan, expected-effect digest, resulting configuration,
and invariant result.  Per-action results are returned in a canonical receipt.
Any forbidden authority action is represented explicitly and rejected.

### Activation rule

A control-plane receipt can never set production, public-testnet, release, or
G5 status.  Those booleans are owned by their independent evidence manifests.

## 7. `trnm-poco-node-production-v0` — wiring-only composition

The production composition owns only three injected objects:

1. `PersistentValidatorHostV0<C, I>`;
2. `TxLifecycleV0<A>`; and
3. `LocalPlanGuardV0<P>`.

State-sync and migration remain session-scoped; there is no hidden global
singleton.  The crate has no signer, storage, network, clock, executor, state
root, governance, or lab implementation.  Its tests prove recovery is required
before polling and that the composition role cannot own domain state.

The next integration slice must adapt existing canonical node components to
these traits and then remove production ownership from the historical monolith.
Until that is complete, `NODE-SPLIT-001` is structurally advanced but not closed.

## 8. `trnm-release-bundle-v0` — exact-source bundle contract

A bundle binds:

- repository, commit, tree, Cargo.lock, toolchain, and production closure;
- clean-source status;
- platform- and source-path-bound artifact hashes and sizes;
- a sorted, unique SBOM with required production-package coverage;
- builder identity, workflow, run, isolated environment, and build inputs;
- artifact-set, SBOM, provenance, previous-bundle, signer, and bundle digests;
  and
- an injected release-signature verifier.

Independent-build comparison ignores builder identity but requires identical
exact source, artifacts, SBOM, and counts.  A match is reproducibility evidence,
not release approval.  A real release still requires two independent builders,
retained logs, publication verification, external review, and governance.

## 9. Repository qualification matrix

The implementation branch is not eligible for integration until all of the
following pass at one exact source head:

```bash
cargo fmt --all -- --check
cargo test -p trnm-node-boundary-v0 --locked
cargo test -p trnm-tx-lifecycle-v0 --locked
cargo test -p trnm-state-sync-v0 --locked
cargo test -p trnm-migration-v0 --locked
cargo test -p trnm-control-plane-v0 --locked
cargo test -p trnm-poco-node-production-v0 --locked
cargo test -p trnm-release-bundle-v0 --locked
cargo check --workspace --all-targets --locked
bash scripts/project-preflight.sh
```

The dependency closure must continue to prove that the default production node
has zero AI-v1 candidate edges and that all candidate crates require the
explicit `ai-v1-candidate` feature.

## 10. Non-claims and honest blocker state

These repository cores do **not** by themselves close:

- persistent authenticated multi-host consensus;
- production adapters over the existing Node Commit Ledger, storage, network,
  executor, signer, finality, read API, state sync target, or release builders;
- HSM/device-backed signing;
- physical power-loss evidence;
- external audit/red-team review;
- wall-clock soak and activation evidence;
- governance approval;
- public-testnet, production, release, or G5 readiness.

No document or unit test may convert queued, skipped, synthetic, simulated,
self-reviewed, or missing external evidence into acceptance.
