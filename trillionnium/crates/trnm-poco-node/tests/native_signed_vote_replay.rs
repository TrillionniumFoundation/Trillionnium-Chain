#![cfg(target_os = "linux")]
//! Single-process source regressions with real native execution, SQLite and
//! Ed25519. The retained in-memory watermark and key are test custody only.
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tempfile::TempDir;
use trnm_consensus_core::CoreConfig;
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, PinnedSqliteSignerJournalV0,
    SignatureProducerErrorV0, SignatureProducerV0, SignatureRequestV0, SignerJournalProfileV0,
    SignerWatermarkV0,
};
use trnm_consensus_types::{
    ApplicationPayloadV0, Block, BlockHeader, BlockId, BlockKind, CanonicalSignIntentV0,
    EvidenceRoot, Height, PayloadDigest, ProposalWitnessV0, ReceiptsRoot, SignatureBytes,
    SignedProposalV0, StateRoot, View, Vote,
};
use trnm_native_execution_v0::NativeApplicationConfigV0;
use trnm_poco_node::{
    commission_native_h1_ordinary_lab_test_bundle_v0, open_existing_native_signed_vote_replay_v1,
    PocoNodeNativeSignedVoteReplayErrorV1 as ReplayError,
};

#[derive(Clone, Default)]
struct Watermark(Arc<Mutex<Option<SignerWatermarkV0>>>);
impl ExternalMonotonicWatermarkV0 for Watermark {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        let head = *self.0.lock().unwrap();
        if head.is_some_and(|h| h.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(head)
    }
    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        let mut head = self.0.lock().unwrap();
        if *head != expected {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        match expected {
            None if target.sequence() == 0 => {}
            Some(prior)
                if prior.scope() == target.scope()
                    && prior.journal_id() == target.journal_id()
                    && prior.sequence().checked_add(1) == Some(target.sequence()) => {}
            _ => return Err(ExternalWatermarkErrorV0::InvalidPersistedState),
        }
        *head = Some(target);
        Ok(())
    }
}
struct Producer {
    key: SigningKey,
    calls: Arc<AtomicUsize>,
    unavailable: bool,
}
impl SignatureProducerV0 for Producer {
    fn sign(
        &mut self,
        request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.unavailable {
            return Err(SignatureProducerErrorV0::Unavailable);
        }
        Ok(SignatureBytes::from_array(
            self.key.sign(request.signing_root().as_bytes()).to_bytes(),
        ))
    }
}
struct Fixture {
    root: TempDir,
    config: CoreConfig,
    apps: Vec<NativeApplicationConfigV0>,
    watermark: Watermark,
    calls: Arc<AtomicUsize>,
    vote: Option<Vote>,
    unsigned_checkpoint: Vec<u8>,
    intent: CanonicalSignIntentV0,
}
impl Fixture {
    fn new(unsigned: bool) -> Self {
        let root = TempDir::new().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let watermark = Watermark::default();
        let bundle =
            commission_native_h1_ordinary_lab_test_bundle_v0(root.path(), watermark.clone(), 4, 3)
                .unwrap();
        let apps = (0..8)
            .map(|_| bundle.fresh_reopen_application_config_v0().unwrap())
            .collect();
        let set = bundle.validator_set_v0().clone();
        let parameters = *bundle.consensus_parameters_v0();
        let height = bundle.ordinary_start_height_v0();
        let timestamp = 400;
        let txs = bundle.ordinary_transactions_v0(height, timestamp).unwrap();
        let binding = bundle.runtime_v0().proposal_binding_v0().unwrap();
        let (parent, preview) = bundle
            .runtime_v0()
            .preview_next_nonempty_v0(txs.clone(), timestamp)
            .unwrap();
        let payload = ApplicationPayloadV0::new(txs).unwrap();
        let proposer = bundle.local_validator_v0();
        let header = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            binding.current_view_v0(),
            Height::new(height),
            BlockKind::Regular,
            BlockId::new(*parent.application_head_v0().block_id().as_bytes()),
            proposer,
            set.id(),
            parameters.hash(),
            PayloadDigest::new(*preview.payload_root().as_bytes()),
            StateRoot::new(*preview.post_state_root().as_bytes()),
            ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*preview.evidence_root().as_bytes()),
            timestamp,
            None,
        )
        .unwrap();
        let block = Block::new(header, payload.try_cev0_bytes().unwrap(), Vec::new()).unwrap();
        let root_hash =
            ProposalWitnessV0::signing_root_for(block.header(), binding.high_qc_v0(), None, None)
                .unwrap();
        let witness = ProposalWitnessV0::new(
            block.header(),
            binding.high_qc_v0().clone(),
            None,
            None,
            bundle.sign_consensus_root_v0(proposer, root_hash).unwrap(),
            &set,
            None,
            &parameters,
            parent.authenticated_parent_timestamp_ms_v0(),
        )
        .unwrap();
        let proposal = SignedProposalV0::new(
            block,
            witness,
            &set,
            None,
            &parameters,
            parent.authenticated_parent_timestamp_ms_v0(),
        )
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut producer = Producer {
            key: bundle.signing_key_v0().clone(),
            calls: calls.clone(),
            unavailable: unsigned,
        };
        let (config, _app, runtime) = bundle.into_recovery_test_parts_v0();
        let inert = runtime.drive_one_to_inert_request_v0(proposal).unwrap();
        let facts = inert.facts_v0();
        let intent = CanonicalSignIntentV0::vote(
            &set,
            proposer,
            facts.authorizing_safety_revision(),
            facts.view(),
            Height::new(facts.height()),
            facts.block_id(),
        )
        .unwrap();
        let checkpoint_path = root.path().join("checkpoint/checkpoint.sqlite3");
        // SQLite checkpoint uses a rollback journal; the clean database copy
        // is an actual earlier checkpoint used only for the stale-file test.
        let unsigned_checkpoint = fs::read(&checkpoint_path).unwrap();
        let vote = match inert.sign_exact_vote_v0(&mut producer) {
            Ok(signed) => {
                assert!(!unsigned);
                Some(signed.outbound_v0().vote_v0().clone())
            }
            Err(_) => {
                assert!(unsigned);
                None
            }
        };
        Self {
            root,
            config,
            apps,
            watermark,
            calls,
            vote,
            unsigned_checkpoint,
            intent,
        }
    }
    fn open(
        &mut self,
    ) -> Result<trnm_poco_node::PocoNodeNativeSignedVoteReplayOwnerV1<Watermark>, ReplayError> {
        open_existing_native_signed_vote_replay_v1(
            self.root.path(),
            self.config.clone(),
            self.apps.pop().unwrap(),
            self.watermark.clone(),
        )
    }
}

fn with_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

// Snapshot logical rows, including all revisions, event counts, digests,
// application state and K sequences. SQLite open bookkeeping is excluded.
fn logical_snapshot(root: &Path) -> [u8; 32] {
    let mut hash = Sha256::new();
    for path in [
        "target-safety/safety.sqlite3",
        "signer/signer.sqlite3",
        "application/application.sqlite3",
        "validation/validation.sqlite3",
        "checkpoint/checkpoint.sqlite3",
    ] {
        let conn = if path.starts_with("application/") || path.starts_with("validation/") {
            rusqlite::Connection::open_with_flags(
                format!("file:{}?immutable=1", root.join(path).display()),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
            )
            .unwrap()
        } else {
            rusqlite::Connection::open_with_flags(
                root.join(path),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap()
        };
        let tables=conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap()
            .query_map([],|r|r.get::<_,String>(0)).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
        hash.update(path.as_bytes());
        for table in tables {
            hash.update(table.as_bytes());
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT * FROM \"{}\" ORDER BY 1",
                    table.replace('"', "\"\"")
                ))
                .unwrap();
            let columns = stmt.column_count();
            let mut rows = stmt.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                for i in 0..columns {
                    hash.update(format!("{:?}", row.get_ref(i).unwrap()).as_bytes());
                }
            }
        }
    }
    hash.finalize().into()
}

#[test]
fn live_native_vote_reopens_exactly_without_new_signatures_or_logical_writes() {
    with_stack(|| {
        let mut f = Fixture::new(false);
        let expected = f.vote.clone().unwrap();
        let before = logical_snapshot(f.root.path());
        let watermark = *f.watermark.0.lock().unwrap();
        for _ in 0..2 {
            let mut owner = f.open().unwrap();
            assert_eq!(owner.replay_exact_vote_v1().unwrap().vote_v1(), &expected);
            assert_eq!(owner.replay_exact_vote_v1().unwrap().vote_v1(), &expected);
            drop(owner);
            assert_eq!(logical_snapshot(f.root.path()), before);
            assert_eq!(*f.watermark.0.lock().unwrap(), watermark);
            assert_eq!(f.calls.load(Ordering::SeqCst), 1);
        }
    });
}

#[test]
fn pinned_journal_readback_returns_only_existing_signatures_and_observes_external_changes() {
    with_stack(|| {
        for unsigned in [false, true] {
            let f = Fixture::new(unsigned);
            let scope = f.watermark.0.lock().unwrap().unwrap().scope();
            let profile = SignerJournalProfileV0::new(
                f.config.validator_set().clone(),
                f.config.local_validator(),
                trnm_poco_node::SIGNER_JOURNAL_PROFILE_REF_V0,
                scope,
                4096,
                4096,
                64 * 1024 * 1024,
            )
            .unwrap();
            let before = logical_snapshot(f.root.path());
            let mut journal = PinnedSqliteSignerJournalV0::open_existing_v0(
                f.root.path().join("signer/signer.sqlite3"),
                profile,
                f.watermark.clone(),
            )
            .unwrap();
            let read = journal.read_signed_intent_exact_v1(&f.intent).unwrap();
            assert_eq!(read.is_none(), unsigned);
            if let Some(read) = read {
                assert_eq!(read.intent_v1(), &f.intent);
                assert_eq!(read.signature_v1(), *f.vote.as_ref().unwrap().signature());
            }
            let absent = CanonicalSignIntentV0::vote(
                f.config.validator_set(),
                f.config.local_validator(),
                f.intent.authorizing_safety_revision() + 1,
                View::new(99),
                Height::new(4),
                BlockId::new([0xED; 32]),
            )
            .unwrap();
            assert!(journal
                .read_signed_intent_exact_v1(&absent)
                .unwrap()
                .is_none());
            let original = f.watermark.0.lock().unwrap().unwrap();
            *f.watermark.0.lock().unwrap() = Some(
                SignerWatermarkV0::from_persisted_parts(
                    original.scope(),
                    original.journal_id(),
                    original.sequence() + 1,
                    [0xCD; 32],
                )
                .unwrap(),
            );
            assert!(journal.read_signed_intent_exact_v1(&f.intent).is_err());
            *f.watermark.0.lock().unwrap() = Some(original);
            drop(journal);
            assert_eq!(logical_snapshot(f.root.path()), before);
            assert_eq!(f.calls.load(Ordering::SeqCst), 1);
        }
    });
}

#[test]
fn every_local_store_corruption_rejects_and_live_external_change_fences_replay() {
    with_stack(|| {
        for (path,statement) in [
        ("target-safety/safety.sqlite3","UPDATE safety_store_metadata_v0 SET metadata_checksum=zeroblob(32) WHERE singleton=1"),
        ("signer/signer.sqlite3","UPDATE signer_journal_head_v0 SET head_checksum=zeroblob(32) WHERE singleton=1"),
        ("validation/validation.sqlite3","UPDATE proposal_validation_jobs_v0 SET row_checksum=zeroblob(32)"),
        ("application/application.sqlite3","UPDATE native_durable_execution_p_v0 SET target_snapshot_digest=zeroblob(32)"),
    ] {
        let mut f=Fixture::new(false);
        let conn=rusqlite::Connection::open(f.root.path().join(path)).unwrap();
        assert!(conn.execute(statement,[]).unwrap()>0); drop(conn);
        assert!(f.open().is_err(),"{path}");
        assert_eq!(f.calls.load(Ordering::SeqCst),1);
    }
        let mut f = Fixture::new(false);
        let mut owner = f.open().unwrap();
        let original = f.watermark.0.lock().unwrap().unwrap();
        *f.watermark.0.lock().unwrap() = Some(
            SignerWatermarkV0::from_persisted_parts(
                original.scope(),
                original.journal_id(),
                original.sequence() + 1,
                [0xCE; 32],
            )
            .unwrap(),
        );
        assert!(owner.replay_exact_vote_v1().is_err());
        *f.watermark.0.lock().unwrap() = Some(original);
        assert!(matches!(
            owner.replay_exact_vote_v1(),
            Err(ReplayError::Unavailable {
                stage: "owner_fenced"
            })
        ));
        drop(owner);
        assert!(f.open().is_ok());
    });
}

#[test]
fn unsigned_native_vote_remains_unavailable_and_never_calls_custody() {
    with_stack(|| {
        let mut f = Fixture::new(true);
        let before = logical_snapshot(f.root.path());
        assert!(matches!(
            f.open(),
            Err(ReplayError::Unavailable {
                stage: "unsigned_signer_tail"
            })
        ));
        assert_eq!(logical_snapshot(f.root.path()), before);
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn stale_or_foreign_checkpoint_cannot_release_the_signed_vote() {
    with_stack(|| {
        let mut f = Fixture::new(false);
        let path = f.root.path().join("checkpoint/checkpoint.sqlite3");
        let exact = fs::read(&path).unwrap();
        fs::write(&path, &f.unsigned_checkpoint).unwrap();
        assert!(matches!(
            f.open(),
            Err(ReplayError::Unavailable {
                stage: "checkpoint_owner_join"
            })
        ));
        fs::write(&path, &exact).unwrap();
        let mut owner = f.open().unwrap();
        assert_eq!(
            owner.replay_exact_vote_v1().unwrap().vote_v1(),
            f.vote.as_ref().unwrap()
        );
        drop(owner);
        let foreign = Fixture::new(false);
        fs::write(
            &path,
            fs::read(foreign.root.path().join("checkpoint/checkpoint.sqlite3")).unwrap(),
        )
        .unwrap();
        assert!(f.open().is_err());
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn missing_or_corrupt_native_artifacts_reject_without_initializing_replacements() {
    with_stack(|| {
        let mut f = Fixture::new(false);
        let path = f.root.path().join("validation/validation.sqlite3");
        let original = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(matches!(
            f.open(),
            Err(ReplayError::Unavailable {
                stage: "existing_namespace"
            })
        ));
        assert!(!path.exists());
        fs::write(&path, []).unwrap();
        assert!(f.open().is_err());
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        fs::write(&path, original).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut owner = f.open().unwrap();
        let connection =
            rusqlite::Connection::open(f.root.path().join("application/application.sqlite3"))
                .unwrap();
        connection.execute("UPDATE native_application_metadata_v0 SET head_state_root=zeroblob(32) WHERE singleton=1",[]).unwrap();
        drop(connection);
        assert!(owner.replay_exact_vote_v1().is_err());
        drop(owner);
        assert!(f.open().is_err());
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn foreign_local_validator_profile_is_rejected_before_logical_store_changes() {
    with_stack(|| {
        let mut f = Fixture::new(false);
        let before = logical_snapshot(f.root.path());
        let config = CoreConfig::new(
            f.config.validator_set().validators()[0].id(),
            f.config.validator_set().clone(),
            *f.config.consensus_parameters(),
            0,
            32,
            64,
        )
        .unwrap();
        assert!(open_existing_native_signed_vote_replay_v1(
            f.root.path(),
            config,
            f.apps.pop().unwrap(),
            f.watermark.clone()
        )
        .is_err());
        assert_eq!(logical_snapshot(f.root.path()), before);
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    });
}
