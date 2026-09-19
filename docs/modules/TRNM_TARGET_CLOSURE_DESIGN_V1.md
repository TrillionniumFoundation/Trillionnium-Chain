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
| E1 cross epoch | M02 authenticated C+1/C+2 seals; M07 edge carries application C and consensus C+2; M06 first-new P targets C+3; M08 strict proof commit CASes native head; M15 V1 lineage checkpoint joins Safety/native/old custody/new custody. | swapped edge/root, seal application mutation, old key after retirement, new key before checkpoint, crash at each owner boundary, reordered QC/TC, second crossing. | `M02_CONSENSUS_CORE_TECHNICAL_SPEC_V1.md`, `M03_SAFETY_SIGNER_TECHNICAL_SPEC_V1.md`, `M06_EXECUTION_TECHNICAL_SPEC_V1.md`, `M07_STATE_STORAGE_TECHNICAL_SPEC_V1.md`, `M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md`, `M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md`; activation/timeout and a bounded first-proposal P0→durable-validation-obligation seam are candidate evidence, while application D/C/K, vote/finality, crash recovery after a progressed obligation and repeated crossing remain open. |
| T1 public transaction | M05 exact signed bytes → nonce/replay WAL → proposer handoff; M06 authenticated parent execution; M08 finality/commit; M14 query proof; M13 wiped node imports manifest/chunks/deltas before any signing. | duplicate/conflicting nonce, gap, overload, lost response, peer failure, tampered chunk/proof, SIGKILL at WAL/P/K/CURRENT. | `M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md`, `M13_STATE_SYNC_MIGRATION_TECHNICAL_SPEC_V1.md`, `M14_CLIENT_PLATFORM_TECHNICAL_SPEC_V1.md`; WAL and bounded ordinary replay are candidate/feature-gated, production listener and multi-epoch sync are open. |
| S1 incremental storage | M07 changed-node/value delta + authenticated version/root metadata; M08 commit ledger and replay suffix; M13 chunk/catalog import; schema6→7 migration is an explicit CAS, never open-time migration. | interrupted migration, third schema state, stale/pruned reference, altered edge/P/proof, rollback anchor mismatch, growing-history byte/time budget. | `M06_EXECUTION_TECHNICAL_SPEC_V1.md`, `M07_STATE_STORAGE_TECHNICAL_SPEC_V1.md`, `M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md`; schema6 preparation and schema7 owner bridge have candidate tests, public transfer/GC/performance acceptance remain open. |
| F1 acceptance | M15 composes real host processes and M17 records source/config/hardware/network; M02–M08/M13 provide protocol evidence; final report includes goodput, p50/p95/p99, queues, bytes and recovery. | RTT/loss/partition matrix, f-tolerance, process crash vs power cut, catch-up under load, epoch boundary under load, disk exhaustion and signer rollback. | `M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md` and `M17_EVIDENCE_SECURITY_TECHNICAL_SPEC_V1.md`; prior clean-source campaign did not pass and no production/performance claim is made. |

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
