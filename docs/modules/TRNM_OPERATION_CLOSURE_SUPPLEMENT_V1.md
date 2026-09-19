# Supplemental operation closure v1

Status: **candidate implementation design; semantic, independent and production acceptance remain open**.

This supplement closes the documentation identity gap for the three implementation
boundaries delivered after the bounded foundation operation catalogue was frozen:
the repeated epoch context join (E1), the public transaction/state-sync join (T1),
and the incremental native state-sync store (S1).  It does not change the wire
version, create an epoch-activation capability, or turn a local regression into
production evidence.  The machine-readable records are in
`config/documentation-operations-supplement-v1.json` and are checked by
`scripts/ci/check_documentation_operations_supplement_v1.py`.

## E1 — strict repeated-epoch context composition

`StrictEpochRuntimeContextV1::compose_successor_v1` accepts a complete successor
activation authority and retained headers.  It requires the successor old set
and parameters to equal the predecessor new set and parameters, the successor
new epoch to be exactly one greater, and the retained ancestry to begin at the
predecessor terminal old header and end at the successor checkpoint parent.
Every edge is checked for consecutive height, exact parent ID, chain, protocol,
and successor genesis identity.  The result is a verification-only context; it
does not create Safety14, a Core owner, a signer lease, a persistence ACK, or an
application checkpoint transition.

The real repeated-epoch fixture is
`trnm-consensus-crypto/tests/epoch_runtime_successor.rs::strict_runtime_context_accepts_a_real_repeated_epoch_successor`.
`trnm-consensus-crypto/tests/epoch_activation_recovery.rs::successor_context_rejects_same_epoch_or_missing_retained_ancestry`
proves that a same-context substitution is rejected before composition.  Crash
cuts, first-new-block execution and custody remain open requirements.

## T1 — finalized transaction to state-sync binding

`bind_finalized_readback_to_native_state_sync_store_v1` obtains a fresh finalized
transaction readback and a fresh SQLite state-sync binding/readback.  It checks
block ID, height, state root, binding digest and manifest digest before deriving
the domain-separated joined digest.  The joined value carries partial progress;
it is not a finality proof or a complete snapshot.  The adapter method
`apply_finalized_readback_and_bind_native_sync_v1` commits the transaction
readback first and then performs this join, returning typed `Finality` versus
`Sync` errors.  A sync mismatch can therefore follow durable finality and must
be recovered by an exact read-only retry; the two owners are deliberately not
claimed to be one atomic transaction.

The bridge unit tests cover exact identity and block/state-root substitution.
`trnm-durable-file-adapters-v0/tests/production_tx_state_sync_e2e.rs::finalized_readback_survives_sync_mismatch_and_exact_recovery_retry`
adds a candidate-only vertical composition: a real hash-chained transaction
journal records finality, an intentionally mismatched SQLite binding returns a
typed `Sync` error, and a recovered `ProductionTxNodeAdapterV0` retries the
same read-only join against a corrected store. It does not provide a listener,
authenticated network source, physical crash cut or production activation;
those remain open.

## S1 — incremental SQLite state-sync append and crash recovery

`SqliteNativeStateSyncStoreV1::append_chunk_v1` validates the session binding,
manifest and chunk identity, then updates the chunk and metadata rows in one
`BEGIN IMMEDIATE` transaction.  Exact duplicates are idempotent; substitutions,
stale writers and disconnected checkpoint context are rejected.  Fresh metadata
and chunk readback is required before a result escapes the owner.

`native_sqlite_session_survives_cross_process_restart_and_rejects_readback_tamper`
proves reopen and tamper detection.  The process-crash case
`native_sqlite_uncommitted_append_is_rolled_back_after_sigkill_and_can_resume`
holds an uncommitted append in a child process, kills it, observes no row or
progress, and resumes with a valid append.  This is SQLite process-crash evidence;
it does not qualify physical power loss, controller-cache durability, or an
independent host rollback floor.

## Acceptance boundary

The supplement requires a positive and a negative source regression for every
operation and records a recovery case where one exists.  It reports exact source
and test bindings, but deliberately reports `independent_golden_vector_count=0`,
`semantic_acceptance=not-assessed`, and `production_authority=false`.  The
original foundation catalogue remains bounded and remains
`operation_catalog_complete=false`; this supplement closes the new implementation
records without claiming that all future or disabled operations are catalogued.
