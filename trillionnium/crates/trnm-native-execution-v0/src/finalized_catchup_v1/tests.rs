use super::*;
use crate::durable::{
    arm_sync_store_commit_boundary_fault_v0, SyncStoreCommitBoundaryFaultPointV0,
};
use crate::pcc1_finality::tests::{certified, config, config_for_local, key, qc};
use crate::NativeApplicationExecutionErrorCodeV0;
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;
use trnm_consensus_types::{
    ApplicationPayloadV0, CertifiedHeaderV0, EvidenceRoot, FinalityProofV0, GenesisQcV0,
    PayloadDigest, QcReferenceV0, ReceiptsRoot, StateRoot,
};
use trnm_finality_types::SignedCommandEnvelopeV1;
use trnm_native_application::{NativeApplicationGenesisRequestV0, NativeExecutedBlockV0};
use trnm_protocol::{
    CanonicalCommandV1, CanonicalTxV1, CANONICAL_TX_PAYLOAD_TYPE_V1, CANONICAL_TX_SCHEMA_V1,
};

const T0: u64 = 1_700_000_000_000;
const FINALIZED: usize = 3;

fn budget() -> Cev0AdmissionBudgetV0 {
    Cev0AdmissionBudgetV0::protocol_v0()
}
fn limits() -> NativeCatchupLimitsV1 {
    NativeCatchupLimitsV1::new(64, 64 * 1024 * 1024, 1024).unwrap()
}
fn snapshot_limits() -> NativeSnapshotReadLimitsV1 {
    NativeSnapshotReadLimitsV1::new(64 * 1024 * 1024, 100_000, 1024 * 1024).unwrap()
}
fn open_new(path: &Path) -> DurableNativeApplicationV0 {
    open_with_config(path, config())
}
fn open_with_config(
    path: &Path,
    cfg: crate::NativeApplicationConfigV0,
) -> DurableNativeApplicationV0 {
    let genesis = NativeApplicationGenesisRequestV0::new(
        ChainIdV0::new(cfg.chain_id_v0()).unwrap(),
        GenesisHashV0::new(cfg.genesis_hash_v0()).unwrap(),
        Hash32V0::new(cfg.chain_descriptor_hash_v0()),
        Hash32V0::new(cfg.signer_policy_commitment_v0()),
        StateRootV0::new(cfg.initial_state_root()).unwrap(),
        cfg.initial_validator_set().clone(),
    )
    .unwrap();
    let app = DurableNativeApplicationV0::open(path, cfg).unwrap();
    app.initialize(genesis).unwrap();
    app
}

fn transactions(height: u64, chain: &str) -> Vec<Vec<u8>> {
    if height.is_multiple_of(2) {
        return vec![];
    }
    let nonce = height.div_ceil(2);
    let tx = CanonicalTxV1 {
        schema: CANONICAL_TX_SCHEMA_V1.into(),
        sender: "did:operator:1".into(),
        nonce,
        max_gas: 100_000,
        fee_limit: 100_000,
        command: CanonicalCommandV1::CreditAccount {
            account: "did:client:1".into(),
            amount: 10_000,
        },
    };
    let envelope = SignedCommandEnvelopeV1::sign(
        chain,
        format!("catchup-{height}"),
        "did:operator:1",
        "operator",
        nonce,
        T0,
        T0 + 100_000,
        CANONICAL_TX_PAYLOAD_TYPE_V1,
        &serde_json::to_vec(&tx).unwrap(),
        &key(81),
    )
    .unwrap();
    vec![serde_json::to_vec(&envelope).unwrap()]
}

struct Fixture {
    _directory: TempDir,
    source: DurableNativeApplicationV0,
    headers: Vec<BlockHeader>,
    bodies: Vec<Vec<u8>>,
    executed: Vec<NativeExecutedBlockV0>,
    proofs: Vec<FinalityProofV0>,
    proof_bytes: Vec<Vec<u8>>,
}
impl Fixture {
    fn new() -> Self {
        let directory = TempDir::new().unwrap();
        let source = open_new(&directory.path().join("source.sqlite"));
        let cfg = source.config_v0();
        let set = cfg.validator_set_v0();
        let params = cfg.consensus_parameters_v0();
        let mut parent = source.confirmed_committed_head_v0().unwrap();
        let mut headers = Vec::new();
        let mut bodies = Vec::new();
        let mut executed = Vec::new();
        let mut certified_headers: Vec<CertifiedHeaderV0> = Vec::new();
        let mut justify = QcReferenceV0::genesis_anchor(
            GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set).unwrap(),
        );
        for h in 1..=(FINALIZED as u64 + 3) {
            let txs = transactions(h, cfg.chain_id_v0());
            let preview = source
                .preview_block_v0(
                    &NativeBlockPreviewRequestV0::new(
                        ChainIdV0::new(cfg.chain_id_v0()).unwrap(),
                        GenesisHashV0::new(cfg.genesis_hash_v0()).unwrap(),
                        parent.clone(),
                        HeightV0::new(h),
                        T0 + h * 1000,
                        ValidatorSetIdV0::new(*set.id().as_bytes()).unwrap(),
                        txs.clone(),
                    )
                    .unwrap(),
                )
                .unwrap();
            let proposer = set.validators()[((h - 1) % 4) as usize].id();
            let header = BlockHeader::new(
                set.genesis_hash(),
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                View::new(h),
                Height::new(h),
                BlockKind::Regular,
                BlockId::new(*parent.block_id().as_bytes()),
                proposer,
                set.id(),
                params.hash(),
                PayloadDigest::new(*preview.payload_root().as_bytes()),
                StateRoot::new(*preview.post_state_root().as_bytes()),
                ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
                EvidenceRoot::new(*preview.evidence_root().as_bytes()),
                T0 + h * 1000,
                None,
            )
            .unwrap();
            let request = NativeBlockExecutionRequestV0::new(
                ChainIdV0::new(cfg.chain_id_v0()).unwrap(),
                GenesisHashV0::new(cfg.genesis_hash_v0()).unwrap(),
                parent,
                BlockIdV0::new(*header.id().as_bytes()).unwrap(),
                HeightV0::new(h),
                header.timestamp_ms(),
                ValidatorSetIdV0::new(*set.id().as_bytes()).unwrap(),
                txs.clone(),
                NativeExpectedBlockCommitmentsV0::new(
                    preview.payload_root(),
                    preview.post_state_root(),
                    preview.receipts_root(),
                    preview.evidence_root(),
                )
                .unwrap(),
            )
            .unwrap();
            let block = match source.execute_block(request).unwrap() {
                NativeBlockExecutionResultV0::Valid(v) => *v,
                other => panic!("{other:?}"),
            };
            parent = source
                .confirm_durable_p_v0(&block)
                .unwrap()
                .overlay_parent_head_v0()
                .unwrap();
            let certificate = qc(set, &header);
            certified_headers.push(certified(
                set,
                params,
                header.clone(),
                justify,
                certificate.clone(),
                T0 + (h - 1) * 1000,
            ));
            justify = QcReferenceV0::ordinary(certificate);
            bodies.push(
                ApplicationPayloadV0::new(txs)
                    .unwrap()
                    .try_cev0_bytes()
                    .unwrap(),
            );
            headers.push(header);
            executed.push(block);
        }
        let mut proofs = Vec::new();
        let mut proof_bytes = Vec::new();
        for i in 0..(FINALIZED + 1) {
            let proof = FinalityProofV0::new(
                certified_headers[i].clone(),
                certified_headers[i + 1].clone(),
                certified_headers[i + 2].clone(),
                set,
                None,
                params,
                T0 + i as u64 * 1000,
            )
            .unwrap();
            let bytes = proof.try_cev0_bytes().unwrap();
            if i < FINALIZED {
                source
                    .commit_poco_finality_bytes_v0(
                        POCO_THREE_CHAIN_PROOF_CLASS_V0,
                        &bytes,
                        executed[i].clone(),
                        T0 + i as u64 * 1000,
                        &mut budget(),
                    )
                    .unwrap();
            }
            proofs.push(proof);
            proof_bytes.push(bytes);
        }
        Self {
            _directory: directory,
            source,
            headers,
            bodies,
            executed,
            proofs,
            proof_bytes,
        }
    }
    fn target(&self) -> StrictFinalityProofV0 {
        let i = FINALIZED - 1;
        let h = &self.headers[i];
        let cfg = self.source.config_v0();
        decode_verify_finality_proof_strict_v0(
            POCO_THREE_CHAIN_PROOF_CLASS_V0,
            &self.proof_bytes[i],
            cfg.validator_set_v0(),
            cfg.consensus_parameters_v0(),
            FinalityExpectationV0 {
                block_id: h.id(),
                height: h.height(),
                state_root: h.state_root(),
                receipts_root: h.receipts_root(),
                evidence_root: h.evidence_root(),
                parent_id: h.parent_id(),
                parent_height: Height::new(i as u64),
                parent_timestamp_ms: T0 + i as u64 * 1000,
            },
            &mut budget(),
        )
        .unwrap()
    }
    fn session(
        &self,
        app: DurableNativeApplicationV0,
        current: Option<usize>,
    ) -> NativeFinalizedCatchupV1 {
        NativeFinalizedCatchupV1::recover(
            app,
            self.target(),
            T0,
            current.map(|i| self.proof_bytes[i].as_slice()),
            limits(),
            &mut budget(),
        )
        .unwrap()
    }
    fn apply(
        &self,
        session: &mut NativeFinalizedCatchupV1,
        i: usize,
    ) -> Result<NativeCatchupReceiptV1, NativeCatchupErrorV1> {
        session.apply(
            &self.headers[i],
            &self.bodies[i],
            &self.proof_bytes[i],
            &mut budget(),
        )
    }
    fn finish(&self, session: NativeFinalizedCatchupV1) -> RestoredNativeApplicationV1 {
        let export = self
            .source
            .begin_finalized_snapshot_export_v1(
                POCO_THREE_CHAIN_PROOF_CLASS_V0,
                &self.proof_bytes[FINALIZED - 1],
                HeightV0::new(FINALIZED as u64),
                T0 + (FINALIZED as u64 - 1) * 1000,
                1024,
                &mut budget(),
            )
            .unwrap();
        let chunks = (0..export.manifest().chunks().len()).map(|i| {
            self.source
                .read_snapshot_chunk_v1(&export, i as u32)
                .map_err(io::Error::other)
        });
        session
            .finish_with_snapshot(export.manifest(), chunks, snapshot_limits())
            .unwrap()
    }
}

fn row_count(path: &Path) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT count(*) FROM native_durable_execution_p_v0",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn replay_restore_reconstructs_real_execution_empty_block_and_nonce_floor() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("restore.sqlite");
    let mut session = f.session(open_new(&path), None);
    for i in 0..FINALIZED {
        let receipt = f.apply(&mut session, i).unwrap();
        assert!(!receipt.replayed());
        assert_eq!(receipt.head().height().get(), i as u64 + 1);
        assert_eq!(
            receipt.head().state_root(),
            f.executed[i].request().expected().post_state_root()
        );
    }
    assert!(f.apply(&mut session, FINALIZED - 1).unwrap().replayed());
    let restored = f.finish(session);
    assert_eq!(restored.head().height().get(), FINALIZED as u64);
    let app = restored.into_application();
    let floor = app
        .verify_finalized_signer_replay_floor_v1(
            "did:operator:1",
            2,
            HeightV0::new(FINALIZED as u64),
            &f.proofs[FINALIZED - 1],
            T0 + (FINALIZED as u64 - 1) * 1000,
        )
        .unwrap();
    assert_eq!(floor.reject_nonce_through_v1(), 2);
    assert_eq!(row_count(&path), FINALIZED as i64);
    let final_row = app.read_finalized_by_height_v0(HeightV0::new(2)).unwrap();
    assert!(final_row.executed_v0().request().transactions().is_empty());
}

#[test]
fn replay_resume_requires_real_current_proof_and_uses_local_parent_time() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("restore.sqlite");
    let mut session = f.session(open_new(&path), None);
    f.apply(&mut session, 0).unwrap();
    drop(session);
    let app = DurableNativeApplicationV0::open(&path, config()).unwrap();
    assert!(matches!(
        NativeFinalizedCatchupV1::recover(app, f.target(), T0, None, limits(), &mut budget()),
        Err(NativeCatchupErrorV1::CurrentProofRequired)
    ));
    let app = DurableNativeApplicationV0::open(&path, config()).unwrap();
    let mut session = f.session(app, Some(0));
    assert!(f.apply(&mut session, 0).unwrap().replayed());
    f.apply(&mut session, 1).unwrap();
    f.apply(&mut session, 2).unwrap();
    f.finish(session);
}

#[test]
fn replay_invalid_body_signature_gap_and_budget_leave_database_unchanged() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("restore.sqlite");
    let mut session = f.session(open_new(&path), None);
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        f.apply(&mut session, 1),
        Err(NativeCatchupErrorV1::NonContiguous)
    ));
    let mut body = f.bodies[0].clone();
    *body.last_mut().unwrap() ^= 1;
    assert!(session
        .apply(&f.headers[0], &body, &f.proof_bytes[0], &mut budget())
        .is_err());
    let mut proof = f.proof_bytes[0].clone();
    *proof.last_mut().unwrap() ^= 1;
    assert!(session
        .apply(&f.headers[0], &f.bodies[0], &proof, &mut budget())
        .is_err());
    let tiny = NativeCatchupLimitsV1::new(3, 1, 10).unwrap();
    session.limits = tiny;
    assert!(matches!(
        f.apply(&mut session, 0),
        Err(NativeCatchupErrorV1::Limit)
    ));
    assert_eq!(row_count(&path), 0);
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(!session.recovery_required());
}

#[test]
fn replay_new_epoch_cannot_use_ordinary_catchup_path() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("restore.sqlite");
    let mut session = f.session(open_new(&path), None);
    let before = fs::read(&path).unwrap();
    let h = &f.headers[0];
    let changed = BlockHeader::new(
        h.genesis_hash(),
        h.chain_id(),
        h.protocol_version(),
        trnm_consensus_types::Epoch::new(1),
        h.view(),
        h.height(),
        h.block_kind(),
        h.parent_id(),
        h.proposer_id(),
        h.validator_set_id(),
        h.consensus_parameters_hash(),
        h.payload_digest(),
        h.state_root(),
        h.receipts_root(),
        h.evidence_root(),
        h.timestamp_ms(),
        None,
    )
    .unwrap();
    assert!(matches!(
        session.apply(&changed, &f.bodies[0], &f.proof_bytes[0], &mut budget()),
        Err(NativeCatchupErrorV1::Context)
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn replay_incomplete_cannot_release_owner_via_snapshot_finish() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let session = f.session(open_new(&dir.path().join("restore.sqlite")), None);
    let export = f
        .source
        .begin_finalized_snapshot_export_v1(
            POCO_THREE_CHAIN_PROOF_CLASS_V0,
            &f.proof_bytes[2],
            HeightV0::new(3),
            T0 + 2000,
            1024,
            &mut budget(),
        )
        .unwrap();
    let input = std::iter::from_fn(|| -> Option<io::Result<Vec<u8>>> {
        panic!("incomplete replay must not even request download bytes")
    });
    assert!(matches!(
        session.finish_with_snapshot(export.manifest(), input, snapshot_limits()),
        Err(NativeCatchupErrorV1::Incomplete)
    ));
}

#[test]
fn replay_lost_sync_response_fences_owner_then_exact_recovery_succeeds() {
    for point in [
        SyncStoreCommitBoundaryFaultPointV0::Database,
        SyncStoreCommitBoundaryFaultPointV0::Directory,
    ] {
        let f = Fixture::new();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("restore.sqlite");
        let mut s = f.session(open_new(&path), None);
        let guard = arm_sync_store_commit_boundary_fault_v0(&path, point);
        assert!(matches!(
            f.apply(&mut s, 0),
            Err(NativeCatchupErrorV1::Uncertain(_))
        ));
        assert!(s.recovery_required());
        assert!(matches!(
            f.apply(&mut s, 0),
            Err(NativeCatchupErrorV1::RecoveryRequired)
        ));
        drop(guard);
        drop(s);
        let app = DurableNativeApplicationV0::open(&path, config()).unwrap();
        let head = app.confirmed_committed_head_v0().unwrap();
        let current = (head.height().get() > 0).then_some(0);
        let mut s = f.session(app, current);
        let r = f.apply(&mut s, 0).unwrap();
        assert_eq!(r.replayed(), current.is_some());
        f.apply(&mut s, 1).unwrap();
        f.apply(&mut s, 2).unwrap();
        f.finish(s);
        assert_eq!(row_count(&path), 3);
    }
}

#[test]
fn committed_retry_reestablishes_database_and_directory_sync_without_new_rows() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("restore.sqlite");
    let mut s = f.session(open_new(&path), None);
    f.apply(&mut s, 0).unwrap();
    for point in [
        SyncStoreCommitBoundaryFaultPointV0::Database,
        SyncStoreCommitBoundaryFaultPointV0::Directory,
    ] {
        let before = fs::read(&path).unwrap();
        let guard = arm_sync_store_commit_boundary_fault_v0(&path, point);
        let err = f.apply(&mut s, 0).unwrap_err();
        assert!(
            matches!(err,NativeCatchupErrorV1::Uncertain(ref e) if e.code()==NativeApplicationExecutionErrorCodeV0::CommitUncertain)
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(row_count(&path), 1);
        drop(guard);
        drop(s);
        s = f.session(
            DurableNativeApplicationV0::open(&path, config()).unwrap(),
            Some(0),
        );
    }
    assert!(f.apply(&mut s, 0).unwrap().replayed());
}

#[test]
fn replay_process_child() {
    let Some(root) = std::env::var_os("TRNM_CATCHUP_CHILD_ROOT") else {
        return;
    };
    let f = Fixture::new();
    let path = Path::new(&root).join("restore.sqlite");
    let mut s = f.session(open_new(&path), None);
    f.apply(&mut s, 0).unwrap();
    panic!("expected child to exit at a persistence cut");
}

#[test]
fn replay_real_process_exit_after_prepare_or_commit_recovers_exactly_once() {
    for cut in ["after-prepare", "after-commit"] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("restore.sqlite");
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "finalized_catchup_v1::tests::replay_process_child",
                "--nocapture",
            ])
            .env("TRNM_CATCHUP_CHILD_ROOT", dir.path())
            .env("TRNM_CATCHUP_TEST_PATH", &path)
            .env("TRNM_CATCHUP_TEST_CUT", cut)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73));
        let f = Fixture::new();
        let app = DurableNativeApplicationV0::open(&path, config()).unwrap();
        let head = app.confirmed_committed_head_v0().unwrap();
        let current = (head.height().get() > 0).then_some(0);
        let mut s = f.session(app, current);
        assert_eq!(
            f.apply(&mut s, 0).unwrap().replayed(),
            cut == "after-commit"
        );
        f.apply(&mut s, 1).unwrap();
        f.apply(&mut s, 2).unwrap();
        f.finish(s);
        assert_eq!(row_count(&path), 3);
    }
}

fn begin_export(f: &Fixture) -> crate::NativeSnapshotExportV1 {
    f.source
        .begin_finalized_snapshot_export_v1(
            POCO_THREE_CHAIN_PROOF_CLASS_V0,
            &f.proof_bytes[2],
            HeightV0::new(3),
            T0 + 2000,
            1024,
            &mut budget(),
        )
        .unwrap()
}

#[test]
fn pinned_snapshot_survives_real_source_advance_and_source_close() {
    let f = Fixture::new();
    let target = f.target();
    let pin = f
        .source
        .pin_finalized_snapshot_export_v1(begin_export(&f), 64 * 1024 * 1024)
        .unwrap();
    let live = begin_export(&f);
    f.source
        .commit_poco_finality_bytes_v0(
            POCO_THREE_CHAIN_PROOF_CLASS_V0,
            &f.proof_bytes[3],
            f.executed[3].clone(),
            T0 + 3000,
            &mut budget(),
        )
        .unwrap();
    assert!(f.source.read_snapshot_chunk_v1(&live, 0).is_err());
    let expected = pin.snapshot_digest().to_owned();
    drop(f);
    let cfg = config();
    let chunks =
        (0..pin.manifest().chunks().len()).map(|i| Ok(pin.chunk(i as u32).unwrap().to_vec()));
    let verified =
        verify_native_snapshot_stream_v1(&cfg, &target, pin.manifest(), chunks, snapshot_limits())
            .unwrap();
    assert_eq!(verified.snapshot_digest(), &expected);
    assert_eq!(verified.height(), 3);
}

#[test]
fn pinned_snapshot_rejects_stale_owner_source_and_retention_bounds() {
    let f = Fixture::new();
    for cap in [0, 1, 512 * 1024 * 1024 + 1] {
        assert!(f
            .source
            .pin_finalized_snapshot_export_v1(begin_export(&f), cap)
            .is_err());
    }
    let dir = TempDir::new().unwrap();
    let other = open_new(&dir.path().join("other.sqlite"));
    assert!(other
        .pin_finalized_snapshot_export_v1(begin_export(&f), 64 * 1024 * 1024)
        .is_err());
    let stale = begin_export(&f);
    f.source
        .commit_poco_finality_bytes_v0(
            POCO_THREE_CHAIN_PROOF_CLASS_V0,
            &f.proof_bytes[3],
            f.executed[3].clone(),
            T0 + 3000,
            &mut budget(),
        )
        .unwrap();
    assert!(f
        .source
        .pin_finalized_snapshot_export_v1(stale, 64 * 1024 * 1024)
        .is_err());
}

#[test]
fn pinned_snapshot_bounds_and_concurrent_read_slices_are_exact() {
    let f = Fixture::new();
    let pin = f
        .source
        .pin_finalized_snapshot_export_v1(begin_export(&f), 64 * 1024 * 1024)
        .unwrap();
    assert!(pin.chunk(u32::MAX).is_err());
    assert!(pin.chunk(pin.manifest().chunks().len() as u32).is_err());
    std::thread::scope(|scope| {
        let pin = &pin;
        let handles: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(move || {
                    let mut collected = Vec::new();
                    for i in 0..pin.manifest().chunks().len() {
                        collected.extend_from_slice(pin.chunk(i as u32).unwrap());
                    }
                    use sha2::Digest;
                    <[u8; 32]>::from(sha2::Sha256::digest(&collected))
                })
            })
            .collect();
        for handle in handles {
            assert_eq!(&handle.join().unwrap(), pin.snapshot_digest());
        }
    });
}

#[test]
fn catchup_pinned_snapshot_finishes_real_application_owner_and_continues_execution() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("restore.sqlite");
    let pin = f
        .source
        .pin_finalized_snapshot_export_v1(begin_export(&f), 64 * 1024 * 1024)
        .unwrap();
    let mut s = f.session(open_new(&path), None);
    for i in 0..3 {
        f.apply(&mut s, i).unwrap();
    }
    let chunks =
        (0..pin.manifest().chunks().len()).map(|i| Ok(pin.chunk(i as u32).unwrap().to_vec()));
    let restored = s
        .finish_with_snapshot(pin.manifest(), chunks, snapshot_limits())
        .unwrap();
    let app = restored.into_application();
    let row = app.read_finalized_by_height_v0(HeightV0::new(3)).unwrap();
    assert_eq!(
        row.receipts_root_v0(),
        f.executed[2].request().expected().receipts_root()
    );
    let cfg = app.config_v0();
    let h = &f.headers[3];
    let request = NativeBlockExecutionRequestV0::new(
        ChainIdV0::new(cfg.chain_id_v0()).unwrap(),
        GenesisHashV0::new(cfg.genesis_hash_v0()).unwrap(),
        app.confirmed_committed_head_v0().unwrap(),
        BlockIdV0::new(*h.id().as_bytes()).unwrap(),
        HeightV0::new(4),
        h.timestamp_ms(),
        ValidatorSetIdV0::new(*cfg.validator_set_v0().id().as_bytes()).unwrap(),
        vec![],
        f.executed[3].request().expected(),
    )
    .unwrap();
    let exec = match app.execute_block(request).unwrap() {
        NativeBlockExecutionResultV0::Valid(v) => *v,
        v => panic!("{v:?}"),
    };
    let committed = app
        .commit_poco_finality_bytes_v0(
            POCO_THREE_CHAIN_PROOF_CLASS_V0,
            &f.proof_bytes[3],
            exec,
            T0 + 3000,
            &mut budget(),
        )
        .unwrap();
    assert_eq!(committed.head().height().get(), 4);
}

#[test]
fn catchup_declared_transaction_fanout_rejected_before_payload_decoder() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("restore.sqlite");
    let mut s = f.session(open_new(&path), None);
    let before = fs::read(&path).unwrap();
    for count in [1025, u32::MAX] {
        assert!(matches!(
            s.apply(
                &f.headers[0],
                &count.to_be_bytes(),
                &f.proof_bytes[0],
                &mut budget()
            ),
            Err(NativeCatchupErrorV1::Limit)
        ));
    }
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(row_count(&path), 0);
}

#[test]
fn catchup_snapshot_corruption_or_truncation_cannot_release_owner() {
    for corrupt in [false, true] {
        let f = Fixture::new();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("restore.sqlite");
        let mut s = f.session(open_new(&path), None);
        for i in 0..3 {
            f.apply(&mut s, i).unwrap();
        }
        let pin = f
            .source
            .pin_finalized_snapshot_export_v1(begin_export(&f), 64 * 1024 * 1024)
            .unwrap();
        let before = fs::read(&path).unwrap();
        let mut chunks: Vec<io::Result<Vec<u8>>> = (0..pin.manifest().chunks().len())
            .map(|i| Ok(pin.chunk(i as u32).unwrap().to_vec()))
            .collect();
        if corrupt {
            chunks[0].as_mut().unwrap()[0] ^= 1;
        } else {
            chunks.pop();
        }
        assert!(matches!(
            s.finish_with_snapshot(pin.manifest(), chunks, snapshot_limits()),
            Err(NativeCatchupErrorV1::Snapshot(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        let app = DurableNativeApplicationV0::open(&path, config()).unwrap();
        assert_eq!(app.confirmed_committed_head_v0().unwrap().height().get(), 3);
    }
}

#[test]
fn catchup_other_node_reconstructs_its_own_commit_ids_and_replay_sets() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("restore.sqlite");
    let target = open_with_config(&path, config_for_local(1));
    assert_ne!(
        target.config_v0().store_id(),
        f.source.config_v0().store_id()
    );
    let mut s = f.session(target, None);
    for i in 0..3 {
        f.apply(&mut s, i).unwrap();
    }
    let restored = f.finish(s);
    assert_eq!(
        restored.head().state_root(),
        f.source.confirmed_committed_head_v0().unwrap().state_root()
    );
    assert_ne!(
        restored.head().commit_id(),
        f.source.confirmed_committed_head_v0().unwrap().commit_id()
    );
    let app = restored.into_application();
    let floor = app
        .verify_finalized_signer_replay_floor_v1(
            "did:operator:1",
            2,
            HeightV0::new(3),
            &f.proofs[2],
            T0 + 2000,
        )
        .unwrap();
    assert!(floor.belongs_to_application_v1(&app));
    assert!(!floor.belongs_to_application_v1(&f.source));
}

#[test]
fn catchup_second_verification_pass_is_reserved_before_prepared_row() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("restore.sqlite");
    let mut s = f.session(open_new(&path), None);
    let mut count = budget();
    count.charge_finality_proof(&f.proofs[0]).unwrap();
    let mut insufficient =
        Cev0AdmissionBudgetV0::new(f.proof_bytes[0].len(), count.signature_work());
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        s.apply(
            &f.headers[0],
            &f.bodies[0],
            &f.proof_bytes[0],
            &mut insufficient
        ),
        Err(NativeCatchupErrorV1::Admission(_))
    ));
    assert_eq!(row_count(&path), 0);
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(!s.recovery_required());
    let mut enough = budget();
    s.apply(&f.headers[0], &f.bodies[0], &f.proof_bytes[0], &mut enough)
        .unwrap();
    assert_eq!(enough.signature_work(), 2 * count.signature_work());
}

#[test]
fn catchup_resume_wrong_proof_does_not_mutate_committed_prefix() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("restore.sqlite");
    let mut s = f.session(open_new(&path), None);
    f.apply(&mut s, 0).unwrap();
    drop(s);
    let before = fs::read(&path).unwrap();
    for proof in [&f.proof_bytes[1], &vec![0; 10]] {
        let app = DurableNativeApplicationV0::open(&path, config()).unwrap();
        assert!(NativeFinalizedCatchupV1::recover(
            app,
            f.target(),
            T0,
            Some(proof),
            limits(),
            &mut budget()
        )
        .is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn catchup_signed_wrong_execution_root_is_rejected_before_persistence() {
    // A fully signed hostile claim is still not an application computation.
    // Rebuild every affected certified header with real test-only Ed25519 keys.
    let f = Fixture::new();
    let cfg = config();
    let set = cfg.validator_set_v0();
    let params = cfg.consensus_parameters_v0();
    let mut headers = Vec::new();
    let mut certs = Vec::new();
    let mut parent = set.genesis_hash().into_bytes();
    let mut justify = QcReferenceV0::genesis_anchor(
        GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set).unwrap(),
    );
    for i in 0..3 {
        let h = &f.headers[i];
        let header = BlockHeader::new(
            h.genesis_hash(),
            h.chain_id(),
            h.protocol_version(),
            h.epoch(),
            h.view(),
            h.height(),
            h.block_kind(),
            BlockId::new(parent),
            h.proposer_id(),
            h.validator_set_id(),
            h.consensus_parameters_hash(),
            h.payload_digest(),
            if i == 0 {
                StateRoot::new([0xEE; 32])
            } else {
                h.state_root()
            },
            h.receipts_root(),
            h.evidence_root(),
            h.timestamp_ms(),
            None,
        )
        .unwrap();
        let certificate = qc(set, &header);
        certs.push(certified(
            set,
            params,
            header.clone(),
            justify,
            certificate.clone(),
            T0 + i as u64 * 1000,
        ));
        justify = QcReferenceV0::ordinary(certificate);
        parent = *header.id().as_bytes();
        headers.push(header);
    }
    let proof = FinalityProofV0::new(
        certs[0].clone(),
        certs[1].clone(),
        certs[2].clone(),
        set,
        None,
        params,
        T0,
    )
    .unwrap()
    .try_cev0_bytes()
    .unwrap();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("restore.sqlite");
    let mut s = f.session(open_new(&path), None);
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        s.apply(&headers[0], &f.bodies[0], &proof, &mut budget()),
        Err(NativeCatchupErrorV1::ExecutionMismatch)
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(row_count(&path), 0);
}

#[test]
fn catchup_new_input_authentication_precedes_storage_and_observed_loss_is_sticky() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("restore.sqlite");
    let retained = dir.path().join("retained.sqlite");
    let mut session = f.session(open_new(&path), None);
    let before = fs::read(&path).unwrap();
    fs::rename(&path, &retained).unwrap();
    let mut bad = f.proof_bytes[0].clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(matches!(
        session.apply(&f.headers[0], &f.bodies[0], &bad, &mut budget()),
        Err(NativeCatchupErrorV1::Admission(_))
    ));
    assert!(!session.recovery_required());
    assert!(!path.exists(), "rejected input must not create a new store");
    assert!(matches!(
        f.apply(&mut session, 0),
        Err(NativeCatchupErrorV1::Application(_))
    ));
    assert!(session.recovery_required());
    fs::rename(&retained, &path).unwrap();
    assert!(matches!(
        f.apply(&mut session, 0),
        Err(NativeCatchupErrorV1::RecoveryRequired)
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
    drop(session);
    let mut recovered = f.session(
        DurableNativeApplicationV0::open(&path, config()).unwrap(),
        None,
    );
    assert!(!f.apply(&mut recovered, 0).unwrap().replayed());
}
