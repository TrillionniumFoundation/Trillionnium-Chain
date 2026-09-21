# M00–M17 implementation acceptance matrix v1

Status: **candidate implementation design; semantic acceptance and production
conformance remain not-assessed**. This matrix closes a documentation shape gap:
each registered module has one concrete implementation entry point, one
representative regression, an ordered state transition, and an explicit list of
requirement IDs that still need acceptance. A row is not an acceptance claim.

The companion gate, `scripts/ci/check_module_implementation_contracts_v1.py`,
cross-checks every row against `config/documentation-contracts-v1.json`, opens
the referenced source files, and checks the named function/test symbols. It is
deliberately lexical and source-bound; it cannot promote semantic acceptance,
independent vectors, production authority, or external fault evidence.

The gate requires an ordered transition and a nonempty open-evidence field,
without prescribing a minimum number of intermediate states or an English
sentence ending. A direct two-state transition is valid navigation data. The
technical specification and its behavioral checks determine whether the
transition actually preserves persistence, signing and recovery requirements.

Each transition names the minimum owner-visible ordering. Implementations must
also preserve the module's exact error, persistence, recovery, resource, and
security rules in the linked technical specification. `source-regression-open`
means that the named test is a review input, not independent acceptance.

## Matrix

### M00 — Protocol / Schema / Codec

- **Implementation source:** `trillionnium/crates/trnm-consensus-types/src/cev0_decode.rs::decode_consensus_parameters_v0_exact`
- **Regression source:** `trillionnium/crates/trnm-consensus-types/src/cev0_decode.rs::consensus_parameters_decoder_round_trips_and_exhausts_the_exact_root`
- **State transition:** `AuthenticatedContext -> BoundedDecode -> SemanticValidate -> CanonicalReencode -> AdmittedValue`
- **Acceptance requirements:** `M00-CANON`, `M00-PREFIX`, `M00-BOUND`, `M00-DOMAIN`, `M00-REGISTRY`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** independent vectors for every reachable CEV0/CEV1 object and parser/error review remain required.

### M01 — Cryptography / Identity / Capability

- **Implementation source:** `trillionnium/crates/trnm-consensus-crypto/src/strict_finality.rs::decode_verify_finality_proof_strict_v0`
- **Regression source:** `trillionnium/crates/trnm-consensus-crypto/tests/pcc1_strict_finality.rs::rejects_retargeting_to_newest_qc_or_different_root`
- **State transition:** `UntrustedProof -> StrictDecode -> ContextAndSignatureVerify -> VerifiedCapability`
- **Acceptance requirements:** `M01-KEY`, `M01-SIG`, `M01-TARGET`, `M01-CAP`, `M01-REVOKE`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** independent signature vectors, HSM custody and complete epoch/migration consumer review remain required.

### M02 — Order / Consensus Kernel

- **Implementation source:** `trillionnium/crates/trnm-consensus-core/src/core.rs::step`
- **Regression source:** `trillionnium/crates/trnm-consensus-sim/tests/scenarios.rs::two_plus_two_partition_cannot_finalize_and_heal_restores_progress`
- **State transition:** `InputEvent -> ValidateContext -> DeterministicTransition -> PersistSafetyDecision -> Effect`
- **Acceptance requirements:** `M02-QUORUM`, `M02-THREECHAIN`, `M02-TC`, `M02-LIVE`, `M02-EPOCH`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** live multi-host liveness, Safety14 handoff and independent state-machine vectors remain required.

### M03 — Safety / Signer / Checkpoint

- **Implementation source:** `trillionnium/crates/trnm-consensus-signer-journal/src/sqlite.rs::sign_exact_v0`
- **Regression source:** `trillionnium/crates/trnm-consensus-signer-journal/tests/sqlite_journal.rs::signature_is_persisted_before_return_and_exact_replay_skips_producer`
- **State transition:** `SignIntent -> PreparedAndSynced -> ProduceSignature -> VerifyAndPersist -> WatermarkReadback`
- **Acceptance requirements:** `M03-PERSIST`, `M03-LOSTACK`, `M03-ROLLBACK`, `M03-CAS`, `M03-CUSTODY`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** physical power-loss, external monotonic anchor and role-specific handoff custody remain required.

### M04 — P2P / Session / Dissemination

- **Implementation source:** `trillionnium/crates/trnm-consensus-peer-lease/src/store.rs::apply`
- **Regression source:** `trillionnium/crates/trnm-consensus-peer-lease/src/store.rs::journal_restarts_and_fences_stale_generation`
- **State transition:** `PeerFrame -> AuthenticateAndBind -> PersistPending -> PreparedAck -> ReplayFloor`
- **Acceptance requirements:** `M04-FRAME`, `M04-LEASE`, `M04-REPLAY`, `M04-DOS`, `M04-HANDOFF`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** authenticated production transport, cross-platform persistence and independent LAN/WAN partition evidence remain required.

### M05 — Transaction Admission / Mempool

- **Implementation source:** `trillionnium/crates/trnm-tx-lifecycle-v0/src/lib.rs::collect`
- **Regression source:** `trillionnium/crates/trnm-tx-lifecycle-v0/src/lib.rs::full_lifecycle_is_idempotent_and_gc_is_proof_gated`
- **State transition:** `SubmittedIntent -> CheckTx -> DurableAdmission -> Proposal -> FinalizedReceipt -> GC`
- **Acceptance requirements:** `M05-NONCE`, `M05-REPLACE`, `M05-RESTART`, `M05-GC`, `M05-PARENT`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** production CheckTx/sign/broadcast composition and independent multi-transaction proof vectors remain required.

### M06 — Execution / MVCC / Meter

- **Implementation source:** `trillionnium/crates/trnm-native-execution-v0/src/lib.rs::stage_runtime_mutations_v0`
- **Regression source:** `trillionnium/crates/trnm-native-execution-v0/src/overlay_delta_tests.rs::later_duplicate_rejects_the_entire_transaction`
- **State transition:** `NativeTx -> Validate -> PlanMVCC -> Execute -> CommitRoot`
- **Acceptance requirements:** `M06-WORKERS`, `M06-HOT`, `M06-ATOMIC`, `M06-REEXEC`, `M06-METER`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** production execution wiring, cross-epoch application edge and sustained deterministic concurrency evidence remain required.

### M07 — State / JMT / Storage

- **Implementation source:** `trillionnium/crates/trnm-native-application-sqlite/src/store.rs::open`
- **Regression source:** `trillionnium/crates/trnm-native-application-sqlite/src/tests.rs::schema_or_trigger_drift_is_rejected_on_reopen`
- **State transition:** `StoreOpen -> SchemaAudit -> SnapshotRead -> DeltaCAS -> RootReadback`
- **Acceptance requirements:** `M07-NAMESPACE`, `M07-SCHEMA`, `M07-ROOT`, `M07-PRUNE`, `M07-DURABLE`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** physical durability, scalable authenticated compaction and multi-host rollback authority remain required.

### M08 — Finality / Node Commit / Recovery

- **Implementation source:** `trillionnium/crates/trnm-native-execution-v0/src/pcc1_finality.rs::read_poco_finalized_bytes_v0`
- **Regression source:** `trillionnium/crates/trnm-native-execution-v0/src/pcc1_finality/tests.rs::readback_never_promotes_prepared_state_even_with_a_valid_proof`
- **State transition:** `FinalityProof -> StrictVerify -> PreparedCommit -> DurableCommit -> ReceiptReadback`
- **Acceptance requirements:** `M08-SEPARATE`, `M08-OLDEST`, `M08-PREPARED`, `M08-CUT`, `M08-BUDGET`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** complete second-edge/two-seal bridge, physical crash evidence and independent finality vectors remain required.

### M09 — Data Availability

- **Implementation source:** `trillionnium/crates/trnm-poco-da-v1/src/store.rs::prepare_attestation`
- **Regression source:** `trillionnium/crates/trnm-poco-da-v1/src/tests.rs::durable_before_attest_survives_reopen_and_rejects_bad_signature`
- **State transition:** `Batch -> DurableAttestationIntent -> SignedAttestation -> QuorumCertificate -> RetainedBytes`
- **Acceptance requirements:** `M09-NAMESPACE`, `M09-THRESHOLD`, `M09-RETENTION`, `M09-STORE`, `M09-REPAIR`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** network interoperability, external custody and retention/retrieval campaigns remain required.

### M10 — Agent / Task / Market

- **Implementation source:** `trillionnium/crates/trnm-poco-agent-market-v1/src/store.rs::execute_order_finalized`
- **Regression source:** `trillionnium/crates/trnm-poco-agent-market-v1/src/tests.rs::task_funded_escrow_bid_lease_and_provider_accept_are_atomic`
- **State transition:** `TaskOffer -> EscrowReserved -> LeaseActive -> ProviderResult -> FinalizedSettlement`
- **Acceptance requirements:** `M10-AGGREGATE`, `M10-REVOKE`, `M10-TERMINAL`, `M10-SERVICE`, `M10-HISTORY`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** terminal lifecycle codecs, archive bounds and production settlement composition remain required.

### M11 — Verification / Challenge

- **Implementation source:** `trillionnium/crates/trnm-poco-verify-challenge-v1/src/profile_registry_v1.rs::resolve_exact`
- **Regression source:** `trillionnium/crates/trnm-poco-verify-challenge-v1/tests/profile_registry_v1.rs::disabled_expired_revoked_and_unknown_profiles_do_not_fallback`
- **State transition:** `VerificationClaim -> ProfileResolve -> EvidenceVerify -> ChallengeWindow -> MaturedDecision`
- **Acceptance requirements:** `M11-PIN`, `M11-CLASS`, `M11-STATUS`, `M11-CHALLENGE`, `M11-MATURE`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** real proof backends, challenge economics and multi-challenge maturity evidence remain required.

### M12 — Settlement / Economics

- **Implementation source:** `trillionnium/crates/trnm-poco-consumption-settlement-v1/src/engine.rs::apply_transition`
- **Regression source:** `trillionnium/crates/trnm-poco-consumption-settlement-v1/src/tests.rs::receipt_rollup_and_settlement_are_bilateral_gap_free_and_conserved`
- **State transition:** `Receipt -> BilateralValidate -> RollupConserve -> SettlementCommit -> AuditedReceipt`
- **Acceptance requirements:** `M12-CONSERVE`, `M12-DOUBLE`, `M12-PARTIAL`, `M12-POLICY`, `M12-ECONOMIC`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** multi-asset terminal settlement, authenticated producer composition and independent economics review remain required.

### M13 — State Sync / Light Client / Migration

- **Implementation source:** `trillionnium/crates/trnm-state-sync-v0/src/lib.rs::verify_complete`
- **Regression source:** `trillionnium/crates/trnm-state-sync-v0/tests/verification_seals.rs::recomputed_root_mismatch_cannot_issue_a_verified_snapshot`
- **State transition:** `TrustAnchor -> VerifyPath -> StageChunks -> RecomputeRoot -> InstallCAS`
- **Acceptance requirements:** `M13-ANCHOR`, `M13-CLASS`, `M13-PATH`, `M13-STAGE`, `M13-MIGRATE`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** production transport, multi-epoch installer, external finality source and physical/multi-host storage evidence remain required.

### M14 — RPC / Indexer / SDK / CLI

- **Implementation source:** `trillionnium/crates/trnm-rpc/src/lib.rs::validate_trnm_address`
- **Regression source:** `trillionnium/crates/trnm-rpc/src/lib.rs::query_account_state_invalid_input`
- **State transition:** `RPCRequest -> DecodeValidate -> AuthorizeRead -> StableResponse`
- **Acceptance requirements:** `M14-READONLY`, `M14-FRESH`, `M14-PROOF`, `M14-BOUND`, `M14-E2E`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** live adapter interoperability, SDK/CLI compatibility and non-authoritative cache recovery remain required.

### M15 — Node Composition / Packaging / Release

- **Implementation source:** `trillionnium/crates/trnm-poco-node-production-v0/src/lib.rs::advance_verified`
- **Regression source:** `trillionnium/crates/trnm-poco-node-production-v0/tests/public_authority_surface.rs::production_session_exports_verified_tokens_not_naked_digest_mutators`
- **State transition:** `ProcessStart -> RecoverAuthority -> Readback -> ReadyOrQuarantine`
- **Acceptance requirements:** `M15-CLOSURE`, `M15-WIRING`, `M15-START`, `M15-ARTIFACT`, `M15-NONPROMOTE`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** signed reproducible artifacts, multi-host deployment and external rollback custody remain required.

### M16 — Global Control Plane

- **Implementation source:** `trillionnium/crates/trnm-control-plane-v0/src/lib.rs::evaluate`
- **Regression source:** `trillionnium/crates/trnm-control-plane-v0/src/lib.rs::forbidden_authority_is_rejected_before_evaluation`
- **State transition:** `Observation -> WindowEvaluate -> GuardDecision -> PlanReceipt`
- **Acceptance requirements:** `M16-CLASS`, `M16-GUARD`, `M16-STALE`, `M16-LOSS`, `M16-ROLLBACK`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** independent observer input, rollback drills and proof that control-plane output cannot acquire consensus authority remain required.

### M17 — Evidence / Benchmark / Security

- **Implementation source:** `scripts/ci/check_documentation_contracts_v1.py::validate_structure`
- **Regression source:** `scripts/ci/test_documentation_contracts_v1.py::test_local_accepted_state`
- **State transition:** `EvidenceInput -> ValidateEnvelope -> ExecuteBoundedRun -> SealReport -> IndependentReview`
- **Acceptance requirements:** `M17-SOURCE`, `M17-MUTANT`, `M17-STATUS`, `M17-INDEPENDENCE`, `M17-REPRO`
- **Acceptance status:** `source-regression-open`
- **Open evidence:** independent reviewer signatures, non-self-authored multi-host/fault data and performance acceptance remain required.

The matrix intentionally leaves every status open. A passing matrix gate proves
that each row names a real implementation/test symbol and maps to the existing
requirement inventory; it does not prove that those tests pass or that any
production or external gate has been satisfied.
