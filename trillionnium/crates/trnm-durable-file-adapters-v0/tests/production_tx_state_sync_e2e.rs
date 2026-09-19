//! Candidate-only vertical composition evidence for M05/M13/M15.
//!
//! This test owns a real hash-chained candidate transaction journal and a
//! real SQLite state-sync store. It does not open a listener, authenticate a
//! peer, or alter `NODE_OWNED_TX_PRODUCTION_ACTIVATION_V0` (which remains
//! false). The first sync binding is intentionally wrong: finality must remain
//! durable, and a recovered adapter must retry the read-only join against the
//! corrected store without re-reading or re-writing finality.

use std::{
    convert::Infallible,
    fs, io,
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection};
use trnm_durable_file_adapters_v0::{
    CandidateTxFileJournalV0, CandidateTxJournalIdentityV0, CandidateTxJournalLimitsV0,
};
use trnm_poco_node_production_v0::ProductionTxNodeAdapterV0;
use trnm_state_sync_v0::{
    Digest32V0 as StateDigest32V0, NativeStateSyncBindingV1, SqliteNativeStateSyncStoreV1,
};
use trnm_tx_lifecycle_v0::{
    AccountIdV0, AuthenticatedTxBroadcasterV0, AuthorizationVerifierV0, BroadcastIntentV0,
    BroadcastReceiptV0, CoreSafetyPermitClaimV0, CoreSafetyPermitVerifierV0, ExecutionReceiptV0,
    FinalityWitnessV0, FinalizedTxClaimV0, FinalizedTxReadbackSourceV0, NonExportableTxSignerV0,
    OrderedPositionV0, ProposalHandoffV0, ResourceLimitsV0, SignedTxEnvelopeV0, TxIdV0, TxIntentV0,
    TxSignRequestV0, TxSignatureReceiptV0,
};

fn tx_digest(byte: u8) -> trnm_tx_lifecycle_v0::Digest32V0 {
    trnm_tx_lifecycle_v0::Digest32V0([byte; 32])
}

fn state_digest(byte: u8) -> StateDigest32V0 {
    StateDigest32V0([byte; 32])
}

struct AcceptAuthorization;
impl AuthorizationVerifierV0 for AcceptAuthorization {
    type Error = Infallible;

    fn verify(
        &self,
        _sender: AccountIdV0,
        _digest: trnm_tx_lifecycle_v0::Digest32V0,
        _authorization: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct UnusedPermit;
impl CoreSafetyPermitVerifierV0 for UnusedPermit {
    type Error = io::Error;

    fn verify_core_safety_permit(
        &self,
        _claim: &CoreSafetyPermitClaimV0,
    ) -> Result<(), Self::Error> {
        Err(io::Error::other("signing is not part of this fixture"))
    }
}

struct UnusedSigner;
impl NonExportableTxSignerV0 for UnusedSigner {
    type Error = io::Error;

    fn sign_transaction(
        &mut self,
        _request: &TxSignRequestV0,
    ) -> Result<TxSignatureReceiptV0, Self::Error> {
        Err(io::Error::other("signing is not part of this fixture"))
    }
}

struct UnusedBroadcaster;
impl AuthenticatedTxBroadcasterV0 for UnusedBroadcaster {
    type Error = io::Error;

    fn broadcast_authenticated(
        &mut self,
        _intent: BroadcastIntentV0,
        _envelope: &SignedTxEnvelopeV0,
    ) -> Result<BroadcastReceiptV0, Self::Error> {
        Err(io::Error::other("broadcast is not part of this fixture"))
    }
}

#[derive(Clone, Copy)]
struct FinalitySource {
    claim: FinalizedTxClaimV0,
}
impl FinalizedTxReadbackSourceV0 for FinalitySource {
    type Error = Infallible;

    fn read_finalized_transaction(
        &mut self,
        _tx_id: TxIdV0,
    ) -> Result<FinalizedTxClaimV0, Self::Error> {
        Ok(self.claim)
    }
}

fn intent() -> TxIntentV0 {
    TxIntentV0 {
        chain_id: tx_digest(1),
        sender: tx_digest(2),
        nonce: 3,
        fee_bid: 100,
        valid_until_height: 100,
        resource_limits: ResourceLimitsV0 {
            max_compute: 1_000,
            max_state_reads: 10,
            max_state_writes: 10,
            max_event_bytes: 1_024,
        },
        payload: vec![4, 5],
        authorization: vec![6; 64],
    }
}

fn finalized_claim(tx_id: TxIdV0) -> FinalizedTxClaimV0 {
    let ordered = OrderedPositionV0 {
        block_id: tx_digest(20),
        height: 9,
        transaction_index: 0,
    };
    let execution = ExecutionReceiptV0 {
        tx_id,
        ordered,
        pre_state_root: tx_digest(21),
        post_state_root: tx_digest(22),
        receipt_digest: tx_digest(23),
        event_root: tx_digest(24),
        fee_charged: 10,
        success: true,
    };
    let finality = FinalityWitnessV0 {
        block_id: ordered.block_id,
        height: ordered.height,
        state_root: execution.post_state_root,
        finality_proof_digest: tx_digest(25),
    };
    let mut claim = FinalizedTxClaimV0 {
        tx_id,
        ordered,
        execution,
        finality,
        source_authentication_digest: tx_digest(26),
        claim_digest: tx_digest(0),
    };
    claim.claim_digest = claim.canonical_digest();
    claim
}

fn state_store(path: &Path, state_root: StateDigest32V0) -> SqliteNativeStateSyncStoreV1 {
    let mut binding = NativeStateSyncBindingV1 {
        trust_path_digest: state_digest(1),
        terminal_block_digest: state_digest(20),
        checkpoint_digest: state_digest(3),
        manifest_digest: state_digest(4),
        height: 9,
        epoch: 2,
        state_root,
        schema_digest: state_digest(5),
        application_version: 1,
        binding_digest: state_digest(0),
    };
    binding.binding_digest = binding.canonical_digest();
    let manifest_binding_digest = state_digest(6);
    let progress_digest = StateDigest32V0::hash(
        b"trnm.state-sync.session-progress.v0",
        &[&binding.manifest_digest.0],
    );
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "PRAGMA application_id=0x5453594e;
             PRAGMA user_version=1;
             PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE native_state_sync_meta_v1 (
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               binding_digest BLOB NOT NULL CHECK(length(binding_digest)=32),
               trust_path_digest BLOB NOT NULL CHECK(length(trust_path_digest)=32),
               terminal_block_digest BLOB NOT NULL CHECK(length(terminal_block_digest)=32),
               checkpoint_digest BLOB NOT NULL CHECK(length(checkpoint_digest)=32),
               manifest_digest BLOB NOT NULL CHECK(length(manifest_digest)=32),
               manifest_binding_digest BLOB NOT NULL CHECK(length(manifest_binding_digest)=32),
               height INTEGER NOT NULL CHECK(height>0),
               epoch INTEGER NOT NULL CHECK(epoch>=0),
               state_root BLOB NOT NULL CHECK(length(state_root)=32),
               schema_digest BLOB NOT NULL CHECK(length(schema_digest)=32),
               application_version INTEGER NOT NULL CHECK(application_version>0),
               received_chunk_count INTEGER NOT NULL CHECK(received_chunk_count>=0),
               received_bytes INTEGER NOT NULL CHECK(received_bytes>=0),
               progress_digest BLOB NOT NULL CHECK(length(progress_digest)=32)
             ) STRICT;
             CREATE TABLE native_state_sync_chunks_v1 (
               chunk_index INTEGER PRIMARY KEY CHECK(chunk_index>=0),
               manifest_digest BLOB NOT NULL CHECK(length(manifest_digest)=32),
               bytes BLOB NOT NULL,
               chunk_digest BLOB NOT NULL CHECK(length(chunk_digest)=32)
             ) WITHOUT ROWID;",
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO native_state_sync_meta_v1(singleton,binding_digest,trust_path_digest,terminal_block_digest,checkpoint_digest,manifest_digest,manifest_binding_digest,height,epoch,state_root,schema_digest,application_version,received_chunk_count,received_bytes,progress_digest) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                &binding.binding_digest.0[..],
                &binding.trust_path_digest.0[..],
                &binding.terminal_block_digest.0[..],
                &binding.checkpoint_digest.0[..],
                &binding.manifest_digest.0[..],
                &manifest_binding_digest.0[..],
                binding.height as i64,
                binding.epoch as i64,
                &binding.state_root.0[..],
                &binding.schema_digest.0[..],
                binding.application_version as i64,
                0_i64,
                0_i64,
                &progress_digest.0[..],
            ],
        )
        .unwrap();
    SqliteNativeStateSyncStoreV1::open_existing(path).unwrap()
}

fn journal_directory(label: &str) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "trnm-m05-m13-m15-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let directory = root.join("journal");
    fs::create_dir_all(&directory).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    (root, directory.canonicalize().unwrap())
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn finalized_readback_survives_sync_mismatch_and_exact_recovery_retry() {
    assert!(!trnm_poco_node_production_v0::NODE_OWNED_TX_PRODUCTION_ACTIVATION_V0);
    let chain_id = tx_digest(1);
    let (root, journal_path) = journal_directory("retry");
    let identity = CandidateTxJournalIdentityV0 {
        chain_id,
        journal_id: tx_digest(7),
    };
    let journal = CandidateTxFileJournalV0::open(
        &journal_path,
        identity,
        CandidateTxJournalLimitsV0::default(),
    )
    .unwrap();
    let claim = finalized_claim(intent().tx_id());
    let mut adapter = ProductionTxNodeAdapterV0::new(
        chain_id,
        AcceptAuthorization,
        journal,
        UnusedPermit,
        UnusedSigner,
        UnusedBroadcaster,
        FinalitySource { claim },
    );
    let admission = adapter.admit_and_persist(intent(), 1).unwrap();
    adapter
        .persist_proposal(
            admission.tx_id,
            ProposalHandoffV0 {
                proposal_id: tx_digest(30),
                proposal_index: 0,
            },
        )
        .unwrap();
    let wrong_path = root.join("wrong.sqlite");
    let wrong_store = state_store(&wrong_path, state_digest(99));
    let error = adapter
        .apply_finalized_readback_and_bind_native_sync_v1(admission.tx_id, &wrong_store)
        .unwrap_err();
    assert!(matches!(
        error,
        trnm_poco_node_production_v0::FinalizedTxNativeStateSyncApplyErrorV0::Sync(
            trnm_poco_node_production_v0::FinalizedTxNativeStateSyncBindingErrorV0::StateRootMismatch
        )
    ));
    assert!(!adapter.is_poisoned());
    drop(wrong_store);
    drop(adapter);

    let journal = CandidateTxFileJournalV0::open(
        &journal_path,
        identity,
        CandidateTxJournalLimitsV0::default(),
    )
    .unwrap();
    let correct_path = root.join("correct.sqlite");
    let correct_store = state_store(&correct_path, state_digest(22));
    let mut recovered = ProductionTxNodeAdapterV0::recover(
        chain_id,
        AcceptAuthorization,
        journal,
        UnusedPermit,
        UnusedSigner,
        UnusedBroadcaster,
        FinalitySource { claim },
    )
    .unwrap();
    let joined = recovered
        .apply_finalized_readback_and_bind_native_sync_v1(admission.tx_id, &correct_store)
        .unwrap();
    assert_eq!(joined.finalized.tx_id, admission.tx_id);
    assert_eq!(joined.sync_binding.state_root, tx_digest(22));
    assert_eq!(joined.sync_binding.block_id, tx_digest(20));
    drop(recovered);
    drop(correct_store);
    let _ = fs::remove_dir_all(root);
}
