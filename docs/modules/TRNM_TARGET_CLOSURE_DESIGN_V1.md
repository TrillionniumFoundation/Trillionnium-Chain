# Target closure design v1: epoch, public transactions, storage and acceptance

Status: **implementation-ready design and evidence map; production disabled**  
Owner: M17 documentation contract; producers/consumers: M02–M15

This document closes the documentation gap between a module being registered
and an engineer having a concrete implementation sequence. The eighteen module
specifications remain the authority for each module's complete contract. This
index fixes the four current cross-module workflows to named inputs, durable
records, error classes, crash cuts and tests. `planned` and `candidate` mean
the design is specific but the implementation or independent acceptance is not
complete.

## Common implementation rule

Every workflow has five separate ownership boundaries:

`P` = authenticated proposal/admission and durable Safety obligation;  
`D` = deterministic application execution and durable artifact;  
`C` = Core application-sealed transition and Safety persistence;  
`K` = application/checkpoint publication with independent readback;  
`R` = recovery, exact retry or fail-closed fence.

The caller never supplies a root, validator set, timestamp, signer watermark,
proof class or replay floor as authority. Each is read from the authenticated
parent or an owner-affine durable record. A failure before a durable boundary
leaves the source; an uncertain boundary accepts only exact source or target
after fresh readback; a third state fences the owner. No workflow below may
create a signer intent unless its row explicitly says `signing=yes` and M03's
persist-before-sign protocol has completed.

## Cross-workflow implementation matrix

| Workflow | P/D/C/K sequence and durable identity | Required negative/crash cases | Current source and status |
|---|---|---|---|
| E1 cross epoch | M02 authenticated C+1/C+2 seals; M07 edge carries application C and consensus C+2; M06 first-new P targets C+3; M08 strict proof commit CASes native head; M15 V1 lineage checkpoint joins Safety/native/old custody/new custody. | swapped edge/root, seal application mutation, old key after retirement, new key before checkpoint, crash at each owner boundary, reordered QC/TC, second crossing. | `M02_CONSENSUS_CORE_TECHNICAL_SPEC_V1.md`, `M03_SAFETY_SIGNER_TECHNICAL_SPEC_V1.md`, `M06_EXECUTION_TECHNICAL_SPEC_V1.md`, `M07_STATE_STORAGE_TECHNICAL_SPEC_V1.md`, `M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md`, `M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md`; the actual candidate executes the native first-new P, confirms its fresh readback, seals Core D and persists the typed Safety NativeValid C transition without signing (`actual_epoch_runtime_executes_native_p_core_d_and_safety_c_without_signing`). `commit_admitted_epoch_finality_v1` now binds a real strict native first-new proof vector to the retained P, commits K, revalidates the progressed cut, and advances the independent application cut only after K readback. `recover_progressed_obligation_readback_v1` verifies the durable pre-K journal9/P/C/custody cut after a process-shaped restart without rebinding Core or signing; vote/finality collection, resumed progressed replay and repeated crossing remain open. |
| T1 public transaction | M05 exact signed bytes → nonce/replay WAL → proposer handoff; M06 authenticated parent execution; M08 finality/commit; M14 query proof; M13 wiped node imports manifest/chunks/deltas before any signing. | duplicate/conflicting nonce, gap, overload, lost response, peer failure, tampered chunk/proof, SIGKILL at WAL/P/K/CURRENT. | `M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md`, `M13_STATE_SYNC_MIGRATION_TECHNICAL_SPEC_V1.md`, `M14_CLIENT_PLATFORM_TECHNICAL_SPEC_V1.md`; committed Transaction/Submit proof readback is now bounded by the two-worker query pool with strict proof verification and explicit backpressure, while the production listener and multi-epoch sync remain open. |
| S1 incremental storage | M07 changed-node/value delta + authenticated version/root metadata; M08 commit ledger and replay suffix; M13 chunk/catalog import; schema6→7 migration is an explicit CAS, never open-time migration. | interrupted migration, third schema state, stale/pruned reference, altered edge/P/proof, rollback anchor mismatch, growing-history byte/time budget. | `M06_EXECUTION_TECHNICAL_SPEC_V1.md`, `M07_STATE_STORAGE_TECHNICAL_SPEC_V1.md`, `M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md`; schema6 preparation and schema7 owner bridge have candidate tests, public transfer/GC/performance acceptance remain open. |
| F1 acceptance | M15 composes real host processes and M17 records source/config/hardware/network; M02–M08/M13 provide protocol evidence; final report includes goodput, p50/p95/p99, queues, bytes and recovery. | RTT/loss/partition matrix, f-tolerance, process crash vs power cut, catch-up under load, epoch boundary under load, disk exhaustion and signer rollback. | `M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md` and `M17_EVIDENCE_SECURITY_TECHNICAL_SPEC_V1.md`; prior clean-source campaign did not pass and no production/performance claim is made. |

## Executable block contracts

The four rows above are implementation blocks, not labels. An engineer must be
able to start from the named input, write the listed durable record, and run the
listed readback before the next owner is touched. The following contracts make
the boundary explicit; an item marked `open` is a required implementation or
independent-evidence task, not an implied success.

### E1: cross epoch

* **Input and admission.** `AuthenticatedEpochApplicationEdgeV1` is the sole
  predecessor authority. `CandidateEpochRuntimeV1::admit_epoch_proposal_v1`
  accepts one signed `EpochHandoff` at `first_application_height`; Core emits
  one `PersistSafetyState` and the journal9 head is compared to the external
  `EpochNodeCheckpointV1` before the validation request is released.
* **P/D/C.** `execute_admitted_epoch_proposal_v1` decodes the bounded payload,
  recomputes payload/state/receipt/evidence roots, calls native schema-4 P,
  confirms P by block id, consumes the Core-issued seal authority for D, and
  persists Safety NativeValid C from the live Core request. The typed
  `NativeValidTransitionV0::from_core_delivery_v0` constructor takes the exact
  non-cloneable Core D carrier, so route, validation identity, Valid checksum,
  completion revision and post-ack action cannot be substituted while the
  canonical one-attempt, 328-byte Safety context is assembled. Its
  `validate_against_core_delivery_v0` readback is run before C. The seven
  host-owned commitments remain a separate P/D manifest: they describe native
  execution and application rows which Core does not own, and must be derived
  from the same P/D readback and reconciled independently. This typed seam
  does not, by itself, authenticate an arbitrary host manifest to Core D; that
  source-binding boundary remains open for a future epoch-specific sealed
  delivery-facts carrier. No signer API is reachable in this block.
* **K and receipt.**
  `commit_admitted_epoch_finality_v1` accepts only a strict CEV0 three-chain
  proof for the retained P, performs the native K CAS, reopens the committed
  row, and advances the independent checkpoint only after the head, P digest,
  artifact, overlay, sequence, owner and activation binding all match.
  Once that checkpoint names the committed first-new application block,
  `admit_epoch_proposal_v1` rejects a second crossing at the persisted
  application cut before consulting Core or any signer; the regression in
  `actual_epoch_runtime_executes_native_p_core_d_and_safety_c_without_signing`
  fixes this one-shot boundary. This is a replay guard, not a second-epoch
  implementation.
* **Crash contract.** Before native P, a restart may call
  `recover_pending_epoch_validation_readback_v1`; it must find the exact
  first-new Proposal validation obligation, old application head, journal9
  revision, retired custody, ordinary signer custody and independent
  checkpoint, then return a read-only receipt. After P/D/C and before K it may
  call `recover_progressed_obligation_readback_v1`, which must find the exact
  pending Vote, journal9 revision, native P, retired custody, ordinary signer
  custody and pre-K application head. Both paths are comparison-only: they do
  not recreate Core, resume the validation callback, or release a signer.
  Authenticated resumed obligation replay, vote/finality collection and a
  second complete epoch remain `open`; the repeated first-new guard only
  closes duplicate admission after the first K checkpoint.
* **Vectors.** The positive vector is
  `actual_epoch_runtime_executes_native_p_core_d_and_safety_c_without_signing`
  followed by strict K and post-K revalidation. The restart vectors are
  `actual_epoch_runtime_pending_validation_recovery_rejoins_without_execution_or_signing`
  at the pre-P cut, followed by
  `actual_epoch_runtime_progressed_obligation_recovery_rejoins_pdc_without_signing`
  at the pre-K cut.
  Negative vectors must cover swapped edge/root, wrong epoch height, proof
  substitution, K replay, old-key use and checkpoint CAS loss.

### T1: public transaction and sync

* **Transaction input.** The canonical signed envelope enters the node-owned
  `TxAdmissionWalV0` namespace. The nonce row is keyed by `(namespace,
  signer, nonce)` and stores the exact transaction digest, state
  `Reserved|HandedOff|Committed|Released`, owner token and replay floor. A
  duplicate with identical bytes is an exact retry; a changed body, nonce gap,
  stale token or retained-row overflow rejects without a new effect.
* **Commit and query.** `commit_candidate_with_native_readback` (or the
  authenticated HandedOff recovery path) must write the final receipt and
  commitment in one SQLite transaction, close/revalidate the namespace, and
  return `StoredNativeCommitReceiptV0` only after the pending row is
  `Committed`. A receipt digest lookup is evidence, not finality. The
  candidate `PocoNodeLabOrdinaryProposalRuntimeV0::read_finalized_transaction_by_digest_v1`
  path now performs a fresh finalized-tip application/proof read, reparses
  every stored canonical envelope, rejects vector cardinality drift or
  duplicate digest matches, and returns the exact outer bytes, transaction
  index, receipt commitment and proof identity. M14 must still independently
  verify retained proof bytes and header/root binding; this carrier is not a
  production listener or historical index.
* **Sync input.** A wiped node first verifies a pinned native trust path, then
  decodes canonical bounded `SnapshotTransferFrameV0` (`TSYN` v0) manifest and
  chunk frames before accepting an exact manifest and bounded indexed chunks.
  It recomputes the chunk root and target state root in staging, imports with
  expected-current-root CAS, and only then joins the node checkpoint. No
  imported bytes can create a signer intent, and a missing, altered, unknown-
  version or trailing-byte frame remains unavailable/error.
* **Open boundary.** The canonical frame boundary is implemented, but the
  production listener, authenticated peer identity/request deadlines, proposer
  handoff, finalized public response, arbitrary-height/multi-epoch transport and
  cross-process replay anchor still need real composition. Candidate proof
  readback, frame round trips and loopback tests do not close those items.
* **Vectors.** Required cases are duplicate/conflicting nonce, gap,
  overload/backpressure, lost response, peer failure, tampered receipt/proof,
  chunk substitution, interrupted import, and SIGKILL at WAL/P/K/CURRENT.

### S1: incremental storage

* **Schema transition.** A schema-6 owner records the authenticated
  `incremental_migration_pin`; `ensure_incremental_epoch_commit_owner_v1`
  performs one explicit schema-6→7 CAS and creates the closed-world commit,
  descendant, replay-node and owner tables. Opening a schema-7 database with a
  missing, extra or altered object is a permanent fence; open-time repair is
  forbidden.
* **Delta and root.** Each prepared block stores changed nodes/values,
  parent/head identity, storage sequence, replay version/root, P digest and
  artifact digest. The commit path recomputes the post-root from the bounded
  delta, records the finality proof and updates the owner head in one
  transaction. Descendant branches retain their own prepared rows until the
  selected proof commits; losing branches are pruned only after the finalized
  prefix pins are released.
* **Recovery and budget.** `reopen_prepared_incremental_epoch_v1` and its
  descendant counterpart must resolve every crash cut to exact source/target or
  fence. Read/write bytes, retained replay depth and reopen time are measured
  against the growing-history budget; a local unit test is not a performance
  claim.
* **Transfer boundary.** `SqliteIncrementalStateStoreV0::export_snapshot_v0`
  and `initialize_from_snapshot_v0` now provide a bounded local snapshot
  handoff with exact rows/root/generation readback and no authority import.
  Public peer export/import still requires a verified checkpoint/export binding,
  interrupted-transfer and disk-full evidence, and transport ownership;
  tombstone GC, arbitrary trust paths and an independently administered
  growing-history campaign remain open.

### F1: multi-host fault and performance acceptance

* **Topology.** M15 starts at least four independently provisioned OS hosts
  with declared CPU/RAM/disk, validator keys and an externally administered
  monotonic signer anchor. M04 carries authenticated frames over persistent
  network links; the run manifest binds source commit/tree, config, binary
  digest, host identity, clock, network profile and workload digest.
* **Fault matrix.** Every run records process crash separately from physical
  power loss, plus RTT/loss/partition, disk exhaustion, signer rollback,
  epoch boundary and catch-up under load. The oracle checks finalized user
  transactions, quorum/f-tolerance, duplicate effects, root equality and
  recovery source/target; a timeout or missing record is failure, never a
  zero-filled metric.
* **Performance output.** The report contains offered and finalized goodput,
  end-to-end finality p50/p95/p99, queue/drop/error rates, CPU/memory/disk and
  network bytes, state growth, catch-up time and recovery time. Fixed workload,
  warm-up, sample count, clock source and raw per-host evidence are mandatory.
  No local loopback, simulated fault or candidate report may be promoted to F1.

## Exact ordinary no-sign sync path now implemented

The ordinary late-proposal route is the first concrete T1 consumer:

1. `receive_unbound_proposal_v1` authenticates the proposal, certified parent,
   epoch/view and route. `IgnoreStale` proposals stop here.
2. `vote_ready_proposal_v1` consumes only `Ready` and invokes
   `sync_late_proposal_v1` after signed-owner admission returns no owner.
3. `drive_one_to_synced_no_sign_v0` executes `Input::SyncedProposal`, persists
   Safety, claims one validation, stores and reads back native P/D, seals the
   Core C transition, and requires an empty final Core ACK.
4. The `SyncedNoSign` Safety-C/K closure and whole-node checkpoint compare
   application/Safety/P/K facts and the external signer watermark. The runtime
   returns to `Ready` and retains the artifact for later finality.

The exact code is
`trnm-poco-lab-validator/src/continuous_runtime.rs`,
`trnm-poco-node/src/lab_authority.rs`,
`trnm-native-application-sqlite/src/store.rs`,
`trnm-poco-node/src/external_node_checkpoint.rs` and
`trnm-poco-node/src/native_proposal_p_host.rs`. Regressions are
`ready_synced_proposal_commits_without_vote_or_watermark_advance_v1`,
`late_network_proposal_after_timeout_preserves_signed_owner_v1`,
`stale_qc_replay_does_not_consume_signed_owner_with_prepared_child`, and
`synced_proposal_commits_without_creating_a_signer_intent`.

This path does not authorize a Vote/Timeout, finality, production state-sync,
epoch activation or a public listener. Those claims require the open tests in
the matrix and the machine flags remain false.

## Documentation completeness gate

For each M00–M17 specification, an implementation review must find all of:

* versioned interface fields and authority owner;
* ordered state transitions, including forbidden transitions;
* exact durable keys/rows, atomicity and restart source/target rules;
* bounded bytes/items/work and explicit reject/unavailable/halt mapping;
* security bindings (domain, role, epoch/height/view/nonce, root/proof);
* positive, negative, crash and deterministic-concurrency vectors;
* implementation symbol, consuming module and evidence status.

The structural module gate verifies navigation only. The current read-only
results are intentionally `semantic_design_acceptance=not-assessed`,
`operation_catalog_complete=false`, and
`independent_golden_vector_count=0`; changing those values requires the actual
vectors and independent review artifacts, not another registry entry.
