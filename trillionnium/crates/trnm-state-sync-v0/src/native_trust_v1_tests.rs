use super::*;
use crate::chunk_merkle_root_v0;
use serde_json::Value;
use trnm_consensus_crypto::recover_epoch_activation_authority_strict_v0;
use trnm_consensus_types::{
    decode_epoch_activation_evidence_v0_exact, EpochActivationEvidenceBytesV0,
};

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

static PAUSE_AFTER_METADATA_READ: AtomicBool = AtomicBool::new(false);
static METADATA_READ_REACHED: AtomicBool = AtomicBool::new(false);
// The failpoint is process-global because it lives in the test module. Keep
// the two interleaving tests mutually exclusive so one test cannot release or
// observe the other test's pause state when libtest runs them in parallel.
static METADATA_INTERLEAVING_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Test-only interleaving point used to prove that a durable read observes one
/// SQLite WAL snapshot even when a writer commits between metadata and chunk
/// queries. It is deliberately unreachable from non-test builds.
pub(crate) fn pause_after_metadata_read_v1() {
    METADATA_READ_REACHED.store(true, Ordering::SeqCst);
    while PAUSE_AFTER_METADATA_READ.load(Ordering::SeqCst) {
        std::thread::yield_now();
    }
}

fn begin_metadata_read_pause_v1() {
    METADATA_READ_REACHED.store(false, Ordering::SeqCst);
    PAUSE_AFTER_METADATA_READ.store(true, Ordering::SeqCst);
}

fn wait_metadata_read_pause_v1() {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if METADATA_READ_REACHED.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    panic!("metadata read did not reach deterministic interleaving point");
}

fn end_metadata_read_pause_v1() {
    PAUSE_AFTER_METADATA_READ.store(false, Ordering::SeqCst);
}

// Real Ed25519 fixture builder shared in form with crypto's epoch boundary tests.
const CORPUS: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json"
);

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect()
}

fn fixture(
    profile: &str,
) -> (
    EpochActivationEvidenceBytesV0,
    ValidatorSet,
    ConsensusParametersV0,
    [u8; 32],
) {
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    let case = &corpus[profile];
    let raw = |section: &str, field: &str| unhex(case[section][field].as_str().unwrap());
    let bytes = EpochActivationEvidenceBytesV0 {
        old_checkpoint_finality: raw("checkpoint_finality", "raw_finality_proof_cev0_hex"),
        next_epoch_commitment: raw("preheader", "commitment_cev0_hex"),
        authorization_kernel: raw("handoff", "raw_anchor_certificate_kernel_cev0_hex"),
        old_validator_set: raw("preheader", "old_validator_set_cev0_hex"),
        old_consensus_parameters: raw("preheader", "old_parameters_cev0_hex"),
        new_validator_set: raw("preheader", "new_validator_set_cev0_hex"),
        new_consensus_parameters: raw("preheader", "new_parameters_cev0_hex"),
        authenticated_checkpoint_parent_header: raw(
            "preheader",
            "checkpoint_parent_header_cev0_hex",
        ),
    };
    let old_set = decode_validator_set_v0_exact(&bytes.old_validator_set).unwrap();
    let old_parameters =
        decode_consensus_parameters_v0_exact(&bytes.old_consensus_parameters).unwrap();
    let binding = unhex(match profile {
        "positive" => "4ba70b831d3bd70a1be8669f654ac42148017fca0b83f84e999ac532b9c70e4f",
        "authenticated_fallback" => {
            "3f719cc7d84539da791a3206d46c4d529f390b2333c35128847f7b62dcd2fc73"
        }
        _ => panic!("unknown frozen fixture"),
    })
    .try_into()
    .unwrap();
    (bytes, old_set, old_parameters, binding)
}

fn first_epoch_finality_bytes(
    activation: &trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0,
) -> (
    Vec<u8>,
    trnm_consensus_crypto::FinalityExpectationV0,
    Vec<usize>,
) {
    first_epoch_finality_with_views(activation, [1, 2, 3], None)
}

fn first_epoch_finality_with_views(
    activation: &trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0,
    views: [u64; 3],
    anchor_context: Option<(
        trnm_consensus_types::QcReferenceV0,
        trnm_consensus_types::EpochAnchorAuthorizationV0,
    )>,
) -> (
    Vec<u8>,
    trnm_consensus_crypto::FinalityExpectationV0,
    Vec<usize>,
) {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use trnm_consensus_types::*;
    let set = activation.new_validator_set();
    let params = activation.new_consensus_parameters();
    let key = |validator: &Validator| {
        let mut h = Sha256::new();
        h.update(b"trnm.poco-bft.checkpoint-finality.private-fixture.v0:");
        h.update(validator.id().as_bytes());
        let key = SigningKey::from_bytes(&h.finalize().into());
        assert_eq!(
            key.verifying_key().to_bytes(),
            validator.consensus_key().into_bytes()
        );
        key
    };
    let common = || {
        let mut bytes = 0u16.to_be_bytes().to_vec();
        bytes.extend(set.genesis_hash().as_bytes());
        bytes.extend((set.chain_id().as_bytes().len() as u16).to_be_bytes());
        bytes.extend(set.chain_id().as_bytes());
        bytes.extend(set.protocol_version().get().to_be_bytes());
        bytes.extend(set.epoch().get().to_be_bytes());
        bytes.extend(set.id().as_bytes());
        bytes
    };
    let mut encoded = common();
    encoded.extend(params.hash().as_bytes());
    let terminal = activation.terminal_old_header();
    let mut anchor = common();
    anchor.extend(0u64.to_be_bytes());
    anchor.extend(terminal.height().get().to_be_bytes());
    anchor.extend(terminal.id().as_bytes());
    anchor.extend(0u32.to_be_bytes());
    let mut parent_id = terminal.id();
    let mut previous_qc = None;
    let mut expected = None;
    let mut signature_offsets = Vec::new();
    for (index, view) in views.into_iter().enumerate() {
        let height_offset = index as u64 + 1;
        let proposer = &set.validators()[(view as usize - 1) % set.validators().len()];
        let header = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(terminal.height().get() + height_offset),
            if index == 0 {
                BlockKind::EpochHandoff
            } else {
                BlockKind::Regular
            },
            parent_id,
            proposer.id(),
            set.id(),
            params.hash(),
            PayloadDigest::new([0x41; 32]),
            StateRoot::new([0x42; 32]),
            ReceiptsRoot::new([0x43; 32]),
            EvidenceRoot::new([0x44; 32]),
            terminal.timestamp_ms() + height_offset,
            None,
        )
        .unwrap();
        let justify_for_timeout = if index == 0 {
            anchor_context.as_ref().map(|(anchor, _)| anchor.clone())
        } else {
            Some(QcReferenceV0::ordinary(previous_qc.clone().unwrap()))
        };
        let timeout = if let Some(justify) = justify_for_timeout {
            if justify.qc_ref().view().get() + 1 < view {
                let entries = set
                    .validators()
                    .iter()
                    .map(|validator| {
                        let root = TimeoutVote::signing_root_for_set(
                            set,
                            View::new(view - 1),
                            justify.qc_ref(),
                        )
                        .unwrap();
                        TimeoutEntryV0::new(
                            validator.id(),
                            justify.qc_ref(),
                            SignatureBytes::from_array(
                                key(validator).sign(root.as_bytes()).to_bytes(),
                            ),
                        )
                        .unwrap()
                    })
                    .collect();
                Some(
                    TimeoutCertificateV0::new(
                        View::new(view - 1),
                        entries,
                        vec![justify.clone()],
                        justify.id(),
                        set,
                    )
                    .unwrap(),
                )
            } else {
                None
            }
        } else {
            None
        };
        let root =
            Vote::signing_root_for_set(set, header.view(), header.height(), header.id()).unwrap();
        let votes = set
            .validators()
            .iter()
            .map(|validator| {
                Vote::new(
                    set.chain_id(),
                    set.protocol_version(),
                    set.epoch(),
                    header.view(),
                    header.height(),
                    header.id(),
                    set.id(),
                    validator.id(),
                    SignatureBytes::from_array(key(validator).sign(root.as_bytes()).to_bytes()),
                    set,
                )
                .unwrap()
            })
            .collect();
        let qc = QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            header.view(),
            header.height(),
            header.id(),
            set.id(),
            votes,
            set,
        )
        .unwrap();
        if index == 0 {
            let root = if let Some((anchor, authorization)) = &anchor_context {
                ProposalWitnessV0::signing_root_for(
                    &header,
                    anchor,
                    timeout.as_ref(),
                    Some(authorization),
                )
                .unwrap()
            } else {
                epoch_first_proposal_signing_root_v0(
                    &header,
                    activation.authorization_kernel(),
                    activation.old_validator_set(),
                    set,
                    params,
                )
                .unwrap()
            };
            let signature = key(proposer).sign(root.as_bytes()).to_bytes();
            encoded.extend(header.try_cev0_bytes().unwrap());
            encoded.extend(&anchor);
            if let Some(tc) = &timeout {
                encoded.push(1);
                encoded.extend(tc.try_cev0_bytes().unwrap());
            } else {
                encoded.push(0);
            }
            encoded.push(1); // exact authorization follows
            encoded.extend(activation.authorization_cev0_bytes().unwrap());
            signature_offsets.push(encoded.len());
            encoded.extend(signature);
            encoded.extend(qc.try_cev0_bytes().unwrap());
            expected = Some(trnm_consensus_crypto::FinalityExpectationV0 {
                block_id: header.id(),
                height: header.height(),
                state_root: header.state_root(),
                receipts_root: header.receipts_root(),
                evidence_root: header.evidence_root(),
                parent_id: terminal.id(),
                parent_height: terminal.height(),
                parent_timestamp_ms: terminal.timestamp_ms(),
            });
        } else {
            let justify = QcReferenceV0::ordinary(previous_qc.take().unwrap());
            let witness = ProposalWitnessV0::new(
                &header,
                justify.clone(),
                timeout.clone(),
                None,
                SignatureBytes::from_array([1; 64]),
                set,
                None,
                params,
                header.timestamp_ms() - 1,
            )
            .unwrap();
            let root = witness.signing_root_for_header(&header).unwrap();
            let signature =
                SignatureBytes::from_array(key(proposer).sign(root.as_bytes()).to_bytes());
            let certified = CertifiedHeaderV0::new(
                header.clone(),
                justify,
                timeout,
                None,
                signature,
                qc.clone(),
                set,
                None,
                params,
                header.timestamp_ms() - 1,
            )
            .unwrap();
            let raw = certified.try_cev0_bytes().unwrap();
            let signature_position = raw
                .windows(64)
                .position(|x| x == signature.as_bytes())
                .unwrap();
            signature_offsets.push(encoded.len() + signature_position);
            encoded.extend(raw);
        }
        parent_id = header.id();
        previous_qc = Some(qc);
    }
    (encoded, expected.unwrap(), signature_offsets)
}

fn pinned(
    header: &BlockHeader,
    set: &ValidatorSet,
    params: &ConsensusParametersV0,
) -> NativeTrustAnchorV1 {
    let h = header.try_cev0_bytes().unwrap();
    let s = set.try_cev0_bytes().unwrap();
    let p = params.canonical_bytes();
    NativeTrustAnchorV1::from_pinned_bytes(
        &h,
        &s,
        &p,
        native_trust_anchor_pin_v1(&h, &s, &p).unwrap(),
    )
    .unwrap()
}
fn expectation(header: &BlockHeader, parent: &BlockHeader) -> FinalityExpectationV0 {
    FinalityExpectationV0 {
        block_id: header.id(),
        height: header.height(),
        state_root: header.state_root(),
        receipts_root: header.receipts_root(),
        evidence_root: header.evidence_root(),
        parent_id: parent.id(),
        parent_height: parent.height(),
        parent_timestamp_ms: parent.timestamp_ms(),
    }
}

#[test]
fn real_ordinary_and_epoch_path_joins_exact_head_and_projects_snapshot_target() {
    for profile in ["positive", "authenticated_fallback"] {
        let (evidence, set, params, binding) = fixture(profile);
        let decoded = decode_epoch_activation_evidence_v0_exact(
            evidence.as_preimages(),
            &set,
            &params,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
        let checkpoint = decoded.old_checkpoint_finality().finalized_block().header();
        let parent = decoded.authenticated_checkpoint_parent_header();
        let anchor = pinned(parent, &set, &params);
        let activation = recover_epoch_activation_authority_strict_v0(
            evidence.as_preimages(),
            &set,
            &params,
            binding,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
        let (new_proof, expected, _) = first_epoch_finality_bytes(&activation);
        let steps = [
            NativeTrustStepV1::Ordinary {
                proof: &evidence.old_checkpoint_finality,
                expected: expectation(checkpoint, parent),
            },
            NativeTrustStepV1::EpochFirst {
                evidence: evidence.as_preimages(),
                proof: &new_proof,
                expected,
            },
        ];
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        let path = verify_native_trust_path_v1(
            &anchor,
            &steps,
            NativeTrustPathLimitsV1::default(),
            &mut budget,
        )
        .unwrap();
        assert_eq!(path.terminal_header().id(), expected.block_id);
        assert_eq!(
            path.terminal_validator_set(),
            activation.new_validator_set()
        );
        assert_eq!(
            path.terminal_parameters(),
            activation.new_consensus_parameters()
        );
        assert_eq!(path.snapshot_trust_path().link_count(), 2);
        assert_eq!(
            path.snapshot_trust_path().terminal().height,
            expected.height.get()
        );
        assert_eq!(
            path.snapshot_trust_path().terminal().state_root.0,
            *expected.state_root.as_bytes()
        );
        assert!(budget.signature_work() > 0);
        let projection = path.snapshot_trust_path().clone();
        let mut manifest = crate::SnapshotManifestV0 {
            chain_id: projection.anchor().chain_id,
            protocol_digest: projection.anchor().protocol_digest,
            height: expected.height.get(),
            epoch: activation.new_validator_set().epoch().get(),
            state_root: projection.terminal().state_root,
            chunk_root: Digest32V0([4; 32]),
            chunk_count: 1,
            maximum_chunk_bytes: 16,
            total_bytes: 16,
            schema_digest: Digest32V0([5; 32]),
            checkpoint_digest: projection.terminal().checkpoint_digest,
            manifest_digest: Digest32V0([0; 32]),
        };
        manifest.manifest_digest = manifest.canonical_digest();
        assert!(manifest.validate(&projection).is_ok());
        let application = NativeApplicationCheckpointV1 {
            schema_digest: manifest.schema_digest,
            application_version: 1,
        };
        let binding = manifest.chunk_binding_digest();
        let retained = SnapshotChunkV0 {
            manifest_digest: binding,
            index: 0,
            bytes: vec![7; 16],
            chunk_digest: SnapshotChunkV0::canonical_digest(binding, 0, &[7; 16]),
        };
        let mut session =
            NativeStateSyncSessionV1::begin(path.clone(), manifest.clone(), application).unwrap();
        session.accept_chunk(retained.clone()).unwrap();
        let readback = session.readback();
        let resumed = NativeStateSyncSessionV1::resume(
            path.clone(),
            manifest.clone(),
            application,
            readback,
            std::slice::from_ref(&retained),
        )
        .unwrap();
        assert_eq!(resumed.readback(), readback);
        let mut substituted = retained.clone();
        substituted.bytes[0] ^= 1;
        assert!(matches!(
            NativeStateSyncSessionV1::resume(
                path.clone(),
                manifest.clone(),
                application,
                readback,
                &[substituted]
            ),
            Err(StateSyncErrorV0::InvalidChunk)
        ));
        let mut wrong_readback = readback;
        wrong_readback.binding_digest = Digest32V0([8; 32]);
        assert!(matches!(
            NativeStateSyncSessionV1::resume(
                path.clone(),
                manifest.clone(),
                application,
                wrong_readback,
                &[retained]
            ),
            Err(StateSyncErrorV0::NativeSessionReadbackMismatch)
        ));
        manifest.height += 1;
        assert!(manifest.validate(&projection).is_err());
        let needed = budget.signature_work();
        let mut short = Cev0AdmissionBudgetV0::new(budget.maximum_root_bytes(), needed - 1);
        assert!(verify_native_trust_path_v1(
            &anchor,
            &steps,
            NativeTrustPathLimitsV1::default(),
            &mut short
        )
        .is_err());
        assert!(short.signature_work() > 0);
        let total = steps.iter().map(|s| step_digest(*s).unwrap().0).sum();
        for limits in [
            NativeTrustPathLimitsV1 {
                maximum_links: 1,
                maximum_total_bytes: total,
            },
            NativeTrustPathLimitsV1 {
                maximum_links: 2,
                maximum_total_bytes: total - 1,
            },
        ] {
            let mut zero_work = Cev0AdmissionBudgetV0::protocol_v0();
            assert!(verify_native_trust_path_v1(&anchor, &steps, limits, &mut zero_work).is_err());
            assert_eq!(zero_work.signature_work(), 0);
        }
    }
}

fn durable_session_fixture() -> (
    VerifiedNativeTrustPathV1,
    SnapshotManifestV0,
    NativeApplicationCheckpointV1,
    Vec<SnapshotChunkV0>,
) {
    let (evidence, set, params, binding) = fixture("positive");
    let decoded = decode_epoch_activation_evidence_v0_exact(
        evidence.as_preimages(),
        &set,
        &params,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let checkpoint = decoded.old_checkpoint_finality().finalized_block().header();
    let parent = decoded.authenticated_checkpoint_parent_header();
    let anchor = pinned(parent, &set, &params);
    let activation = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &set,
        &params,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let (proof, expected, _) = first_epoch_finality_bytes(&activation);
    let path = verify_native_trust_path_v1(
        &anchor,
        &[
            NativeTrustStepV1::Ordinary {
                proof: &evidence.old_checkpoint_finality,
                expected: expectation(checkpoint, parent),
            },
            NativeTrustStepV1::EpochFirst {
                evidence: evidence.as_preimages(),
                proof: &proof,
                expected,
            },
        ],
        NativeTrustPathLimitsV1::default(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let projection = path.snapshot_trust_path();
    let bytes = [vec![7_u8], vec![8_u8]];
    let mut manifest = SnapshotManifestV0 {
        chain_id: projection.anchor().chain_id,
        protocol_digest: projection.anchor().protocol_digest,
        height: expected.height.get(),
        epoch: activation.new_validator_set().epoch().get(),
        state_root: projection.terminal().state_root,
        chunk_root: Digest32V0([0; 32]),
        chunk_count: 2,
        maximum_chunk_bytes: 1,
        total_bytes: 2,
        schema_digest: Digest32V0([5; 32]),
        checkpoint_digest: projection.terminal().checkpoint_digest,
        manifest_digest: Digest32V0([0; 32]),
    };
    let chunk_binding = manifest.chunk_binding_digest();
    let chunks = bytes
        .iter()
        .enumerate()
        .map(|(index, bytes)| SnapshotChunkV0 {
            manifest_digest: chunk_binding,
            index: index as u32,
            bytes: bytes.clone(),
            chunk_digest: SnapshotChunkV0::canonical_digest(chunk_binding, index as u32, bytes),
        })
        .collect::<Vec<_>>();
    manifest.chunk_root = chunk_merkle_root_v0(
        &chunks
            .iter()
            .map(|chunk| chunk.chunk_digest)
            .collect::<Vec<_>>(),
    );
    manifest.manifest_digest = manifest.canonical_digest();
    let application = NativeApplicationCheckpointV1 {
        schema_digest: manifest.schema_digest,
        application_version: 1,
    };
    (path, manifest, application, chunks)
}

#[test]
fn native_application_binding_requires_matching_schema_and_nonzero_version() {
    let (path, manifest, application, _) = durable_session_fixture();
    let session =
        NativeStateSyncSessionV1::begin(path.clone(), manifest.clone(), application).unwrap();
    assert_eq!(session.binding().schema_digest, manifest.schema_digest);
    // M13's general application version is independently supplied; only a
    // concrete native profile may require it to equal the terminal height.
    let other_version = NativeApplicationCheckpointV1 {
        application_version: manifest.height + 1,
        ..application
    };
    let other =
        NativeStateSyncSessionV1::begin(path.clone(), manifest.clone(), other_version).unwrap();
    assert_ne!(
        other.binding().binding_digest,
        session.binding().binding_digest
    );
    assert_eq!(other.binding().application_version, manifest.height + 1);

    for invalid in [
        NativeApplicationCheckpointV1 {
            schema_digest: Digest32V0([6; 32]),
            ..application
        },
        NativeApplicationCheckpointV1 {
            schema_digest: Digest32V0([0; 32]),
            ..application
        },
        NativeApplicationCheckpointV1 {
            application_version: 0,
            ..application
        },
    ] {
        assert!(matches!(
            NativeStateSyncSessionV1::begin(path.clone(), manifest.clone(), invalid),
            Err(StateSyncErrorV0::NativeApplicationBindingMismatch)
        ));
    }
    let mut zero_schema_manifest = manifest;
    zero_schema_manifest.schema_digest = Digest32V0([0; 32]);
    zero_schema_manifest.manifest_digest = zero_schema_manifest.canonical_digest();
    assert!(matches!(
        NativeStateSyncSessionV1::begin(
            path,
            zero_schema_manifest,
            NativeApplicationCheckpointV1 {
                schema_digest: Digest32V0([0; 32]),
                ..application
            }
        ),
        Err(StateSyncErrorV0::InvalidManifest)
    ));
}

#[test]
fn native_sqlite_resume_and_append_screen_exact_manifest_before_materialization() {
    let (path, original_manifest, application, _) = durable_session_fixture();
    for (case, total_bytes, rows) in [
        ("count", 4, vec![(0, vec![7]), (1, vec![8]), (2, vec![9])]),
        ("index", 4, vec![(2, vec![7])]),
        ("chunk", 4, vec![(0, vec![7, 8, 9])]),
        ("total", 3, vec![(0, vec![7, 8]), (1, vec![9, 10])]),
    ] {
        let mut manifest = original_manifest.clone();
        manifest.maximum_chunk_bytes = 2;
        manifest.total_bytes = total_bytes;
        manifest.manifest_digest = manifest.canonical_digest();
        let mut session =
            NativeStateSyncSessionV1::begin(path.clone(), manifest.clone(), application).unwrap();
        let before = session.readback();
        let store_path = std::env::temp_dir().join(format!(
            "trnm-native-sync-manifest-{case}-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = SqliteNativeStateSyncStoreV1::initialize(&store_path, &session).unwrap();
        let binding = manifest.chunk_binding_digest();
        let connection = rusqlite::Connection::open(&store_path).unwrap();
        for (index, bytes) in &rows {
            let digest = SnapshotChunkV0::canonical_digest(binding, *index, bytes);
            connection
                .execute(
                    "INSERT INTO native_state_sync_chunks_v1(chunk_index,manifest_digest,bytes,chunk_digest) VALUES(?1,?2,?3,?4)",
                    params![i64::from(*index), &binding.0[..], bytes, &digest.0[..]],
                )
                .unwrap();
        }
        // Every forged row fits the generic protocol bounds and has a valid
        // digest. The stale empty readback would fail only after loading all
        // bytes; exact error assertions below require the earlier SQL screen.
        assert_eq!(
            read_chunks_v1(&connection, binding).unwrap().len(),
            rows.len()
        );
        drop(connection);
        let next = SnapshotChunkV0 {
            manifest_digest: binding,
            index: 0,
            bytes: vec![7],
            chunk_digest: SnapshotChunkV0::canonical_digest(binding, 0, &[7]),
        };
        for result in [
            store
                .resume_existing_v1(path.clone(), manifest.clone(), application)
                .map(|_| ()),
            SqliteNativeStateSyncStoreV1::resume_from_path_v1(
                &store_path,
                path.clone(),
                manifest.clone(),
                application,
            )
            .map(|_| ()),
            store.append_chunk_v1(&mut session, next),
        ] {
            let error = result.expect_err("manifest bound must reject before readback");
            match case {
                "count" | "total" => assert!(matches!(
                    error,
                    NativeStateSyncStoreErrorV1::Protocol(StateSyncErrorV0::SnapshotTooLarge)
                )),
                "index" => assert!(matches!(
                    error,
                    NativeStateSyncStoreErrorV1::StoreSchemaMismatch
                )),
                "chunk" => assert!(matches!(
                    error,
                    NativeStateSyncStoreErrorV1::Protocol(StateSyncErrorV0::InvalidChunk)
                )),
                _ => unreachable!(),
            }
        }
        assert_eq!(session.readback(), before);

        // Even these invalid chunk rows must not be read when the freshly
        // supplied application version belongs to another durable binding.
        let wrong_application = NativeApplicationCheckpointV1 {
            application_version: application.application_version + 1,
            ..application
        };
        assert!(matches!(
            SqliteNativeStateSyncStoreV1::resume_from_path_v1(
                &store_path,
                path.clone(),
                manifest.clone(),
                wrong_application,
            ),
            Err(NativeStateSyncStoreErrorV1::BindingMismatch)
        ));
        let mut wrong_session =
            NativeStateSyncSessionV1::begin(path.clone(), manifest, wrong_application).unwrap();
        let wrong_next = SnapshotChunkV0 {
            manifest_digest: binding,
            index: 0,
            bytes: vec![7],
            chunk_digest: SnapshotChunkV0::canonical_digest(binding, 0, &[7]),
        };
        assert!(matches!(
            store.append_chunk_v1(&mut wrong_session, wrong_next),
            Err(NativeStateSyncStoreErrorV1::DurableReadbackMismatch)
        ));
        let _ = std::fs::remove_file(&store_path);
        let _ = std::fs::remove_file(store_path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(store_path.with_extension("sqlite-shm"));
    }
}

#[test]
fn native_sqlite_session_survives_cross_process_restart_and_rejects_readback_tamper() {
    let (path, manifest, application, chunks) = durable_session_fixture();
    let store_path = std::env::temp_dir().join(format!(
        "trnm-native-sync-store-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut session =
        NativeStateSyncSessionV1::begin(path.clone(), manifest.clone(), application).unwrap();
    let store = SqliteNativeStateSyncStoreV1::initialize(&store_path, &session).unwrap();
    store
        .append_chunk_v1(&mut session, chunks[0].clone())
        .unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_trust_v1::tests::native_sqlite_session_child_reopen",
            "--nocapture",
        ])
        .env("TRNM_NATIVE_SYNC_CHILD_PATH_V1", &store_path)
        .status()
        .unwrap();
    assert!(child.success(), "cross-process state-sync child failed");
    let reopened = SqliteNativeStateSyncStoreV1::open_existing(&store_path).unwrap();
    let resumed = reopened
        .resume_existing_v1(path, manifest, application)
        .unwrap();
    assert_eq!(resumed.readback().received_chunk_count, 2);
    assert_eq!(resumed.readback().received_bytes, 2);

    let connection = rusqlite::Connection::open(&store_path).unwrap();
    connection
        .execute(
            "UPDATE native_state_sync_meta_v1 SET progress_digest=?1 WHERE singleton=1",
            rusqlite::params![&[9_u8; 32][..]],
        )
        .unwrap();
    assert!(matches!(
        reopened.readback_v1(),
        Err(NativeStateSyncStoreErrorV1::DurableReadbackMismatch)
    ));
    let _ = std::fs::remove_file(&store_path);
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-shm"));
}

#[test]
fn native_sqlite_uncommitted_append_is_rolled_back_after_sigkill_and_can_resume() {
    let (path, manifest, application, chunks) = durable_session_fixture();
    let store_path = std::env::temp_dir().join(format!(
        "trnm-native-sync-sigkill-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let ready_path = store_path.with_extension("ready");
    let base =
        NativeStateSyncSessionV1::begin(path.clone(), manifest.clone(), application).unwrap();
    let store = SqliteNativeStateSyncStoreV1::initialize(&store_path, &base).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_trust_v1::tests::native_sqlite_session_child_hold_uncommitted_append",
            "--nocapture",
        ])
        .env("TRNM_NATIVE_SYNC_SIGKILL_PATH_V1", &store_path)
        .env("TRNM_NATIVE_SYNC_SIGKILL_READY_V1", &ready_path)
        .spawn()
        .unwrap();

    let mut ready = false;
    for _ in 0..250 {
        if ready_path.exists() {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        panic!("state-sync crash child did not reach its uncommitted transaction");
    }
    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert!(
        !status.success(),
        "SIGKILL child unexpectedly exited cleanly"
    );

    let reopened = SqliteNativeStateSyncStoreV1::open_existing(&store_path).unwrap();
    assert_eq!(reopened.readback_v1().unwrap().received_chunk_count, 0);
    assert!(reopened.retained_chunks_v1().unwrap().is_empty());
    let mut resumed = reopened
        .resume_existing_v1(path, manifest, application)
        .unwrap();
    store
        .append_chunk_v1(&mut resumed, chunks[0].clone())
        .unwrap();
    assert_eq!(store.readback_v1().unwrap().received_chunk_count, 1);

    let _ = std::fs::remove_file(&ready_path);
    let _ = std::fs::remove_file(&store_path);
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-shm"));
}

#[test]
fn native_sqlite_append_fails_closed_at_database_page_ceiling() {
    let (path, mut manifest, application, _) = durable_session_fixture();
    // Use a page-sized payload so the bounded SQLite ceiling is exercised
    // deterministically even when the empty store still has free space in its
    // last page.
    let bytes = vec![0xA5; 8 * 1024];
    manifest.chunk_count = 1;
    manifest.maximum_chunk_bytes = bytes.len() as u32;
    manifest.total_bytes = bytes.len() as u64;
    manifest.chunk_root = Digest32V0([0; 32]);
    manifest.manifest_digest = Digest32V0([0; 32]);
    let binding = manifest.chunk_binding_digest();
    let chunk = SnapshotChunkV0 {
        manifest_digest: binding,
        index: 0,
        chunk_digest: SnapshotChunkV0::canonical_digest(binding, 0, &bytes),
        bytes,
    };
    manifest.chunk_root = chunk_merkle_root_v0(&[chunk.chunk_digest]);
    manifest.manifest_digest = manifest.canonical_digest();
    let store_path = std::env::temp_dir().join(format!(
        "trnm-native-sync-full-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut session = NativeStateSyncSessionV1::begin(path, manifest, application).unwrap();
    let store = SqliteNativeStateSyncStoreV1::initialize(&store_path, &session).unwrap();

    // Bound the real SQLite file to its current page count.  The next append
    // therefore reaches SQLITE_FULL after beginning the writer transaction;
    // this is a bounded disk-exhaustion regression, not a simulated error.
    let connection = rusqlite::Connection::open(&store_path).unwrap();
    let pages: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .unwrap();
    assert!(pages > 0);
    drop(connection);

    let before = store.readback_v1().unwrap();
    let limited_store = store.clone().with_test_max_page_count_v1(pages);
    let result = limited_store.append_chunk_v1(&mut session, chunk);
    let error = result.expect_err("page ceiling must reject the append");
    assert!(matches!(error, NativeStateSyncStoreErrorV1::Sqlite(_)));
    assert_eq!(session.readback(), before);
    assert_eq!(store.readback_v1().unwrap(), before);
    assert!(store.retained_chunks_v1().unwrap().is_empty());

    let _ = std::fs::remove_file(&store_path);
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-shm"));
}

#[test]
fn native_sqlite_initialize_persists_prefilled_session_chunks() {
    let (path, manifest, application, chunks) = durable_session_fixture();
    let store_path = std::env::temp_dir().join(format!(
        "trnm-native-sync-prefilled-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut session =
        NativeStateSyncSessionV1::begin(path.clone(), manifest.clone(), application).unwrap();
    session.accept_chunk(chunks[0].clone()).unwrap();
    let store = SqliteNativeStateSyncStoreV1::initialize(&store_path, &session).unwrap();
    assert_eq!(store.readback_v1().unwrap().received_chunk_count, 1);
    assert_eq!(store.retained_chunks_v1().unwrap(), vec![chunks[0].clone()]);
    let (reopened, resumed) =
        SqliteNativeStateSyncStoreV1::resume_from_path_v1(&store_path, path, manifest, application)
            .unwrap();
    assert_eq!(resumed.readback(), session.readback());
    assert_eq!(reopened.readback_v1().unwrap(), session.readback());
    let _ = std::fs::remove_file(&store_path);
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-shm"));
}

#[test]
fn native_sqlite_reopen_rejects_schema_object_drift() {
    let (path, manifest, application, _) = durable_session_fixture();
    let store_path = std::env::temp_dir().join(format!(
        "trnm-native-sync-schema-drift-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let session = NativeStateSyncSessionV1::begin(path, manifest, application).unwrap();
    let _store = SqliteNativeStateSyncStoreV1::initialize(&store_path, &session).unwrap();
    let connection = rusqlite::Connection::open(&store_path).unwrap();
    connection
        .execute(
            "CREATE INDEX native_state_sync_chunk_drift ON native_state_sync_chunks_v1(chunk_index)",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        SqliteNativeStateSyncStoreV1::open_existing(&store_path),
        Err(NativeStateSyncStoreErrorV1::StoreSchemaMismatch)
    ));
    let _ = std::fs::remove_file(&store_path);
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-shm"));
}

#[test]
fn native_sqlite_reopen_rejects_forged_blob_bounds_before_materialization() {
    let (path, manifest, application, chunks) = durable_session_fixture();
    let oversized_path = std::env::temp_dir().join(format!(
        "trnm-native-sync-oversized-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut session =
        NativeStateSyncSessionV1::begin(path.clone(), manifest.clone(), application).unwrap();
    let store = SqliteNativeStateSyncStoreV1::initialize(&oversized_path, &session).unwrap();
    store
        .append_chunk_v1(&mut session, chunks[0].clone())
        .unwrap();
    let connection = rusqlite::Connection::open(&oversized_path).unwrap();
    connection
        .execute(
            "UPDATE native_state_sync_chunks_v1 SET bytes=zeroblob(?1) WHERE chunk_index=0",
            rusqlite::params![i64::try_from(crate::MAX_CHUNK_BYTES_V0 + 1).unwrap()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        SqliteNativeStateSyncStoreV1::open_existing(&oversized_path),
        Err(NativeStateSyncStoreErrorV1::Protocol(
            StateSyncErrorV0::InvalidChunk
        ))
    ));

    let malformed_path = std::env::temp_dir().join(format!(
        "trnm-native-sync-malformed-meta-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let session = NativeStateSyncSessionV1::begin(path, manifest, application).unwrap();
    let _store = SqliteNativeStateSyncStoreV1::initialize(&malformed_path, &session).unwrap();
    let connection = rusqlite::Connection::open(&malformed_path).unwrap();
    connection
        .execute("PRAGMA ignore_check_constraints=ON", [])
        .unwrap();
    connection
        .execute(
            "UPDATE native_state_sync_meta_v1 SET progress_digest=zeroblob(33) WHERE singleton=1",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        SqliteNativeStateSyncStoreV1::open_existing(&malformed_path),
        Err(NativeStateSyncStoreErrorV1::StoreSchemaMismatch)
    ));

    let text_path = std::env::temp_dir().join(format!(
        "trnm-native-sync-text-chunk-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (text_path_input, text_manifest, text_application, text_chunks) = durable_session_fixture();
    let mut text_session =
        NativeStateSyncSessionV1::begin(text_path_input, text_manifest, text_application).unwrap();
    let text_store = SqliteNativeStateSyncStoreV1::initialize(&text_path, &text_session).unwrap();
    text_store
        .append_chunk_v1(&mut text_session, text_chunks[0].clone())
        .unwrap();
    let connection = rusqlite::Connection::open(&text_path).unwrap();
    connection
        .execute(
            "UPDATE native_state_sync_chunks_v1 SET bytes='forged text' WHERE chunk_index=0",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        SqliteNativeStateSyncStoreV1::open_existing(&text_path),
        Err(NativeStateSyncStoreErrorV1::StoreSchemaMismatch)
    ));

    let extra_row_path = std::env::temp_dir().join(format!(
        "trnm-native-sync-extra-meta-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (extra_path_input, extra_manifest, extra_application, _) = durable_session_fixture();
    let extra_session =
        NativeStateSyncSessionV1::begin(extra_path_input, extra_manifest, extra_application)
            .unwrap();
    let _extra_store =
        SqliteNativeStateSyncStoreV1::initialize(&extra_row_path, &extra_session).unwrap();
    let connection = rusqlite::Connection::open(&extra_row_path).unwrap();
    connection
        .execute("PRAGMA ignore_check_constraints=ON", [])
        .unwrap();
    connection
        .execute(
            "INSERT INTO native_state_sync_meta_v1
             SELECT 2,binding_digest,trust_path_digest,terminal_block_digest,
                    checkpoint_digest,manifest_digest,manifest_binding_digest,
                    height,epoch,state_root,schema_digest,application_version,
                    received_chunk_count,received_bytes,progress_digest
                FROM native_state_sync_meta_v1 WHERE singleton=1",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        SqliteNativeStateSyncStoreV1::open_existing(&extra_row_path),
        Err(NativeStateSyncStoreErrorV1::StoreSchemaMismatch)
    ));

    for store_path in [
        &oversized_path,
        &malformed_path,
        &text_path,
        &extra_row_path,
    ] {
        let _ = std::fs::remove_file(store_path);
        let _ = std::fs::remove_file(store_path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(store_path.with_extension("sqlite-shm"));
    }
}

#[test]
fn native_sqlite_session_child_reopen() {
    let Ok(store_path) = std::env::var("TRNM_NATIVE_SYNC_CHILD_PATH_V1") else {
        return;
    };
    let (path, manifest, application, chunks) = durable_session_fixture();
    let store = SqliteNativeStateSyncStoreV1::open_existing(&store_path).unwrap();
    let mut session = store
        .resume_existing_v1(path, manifest, application)
        .unwrap();
    store
        .append_chunk_v1(&mut session, chunks[1].clone())
        .unwrap();
    assert_eq!(store.readback_v1().unwrap().received_chunk_count, 2);
}

#[test]
fn native_sqlite_session_child_hold_uncommitted_append() {
    let Ok(store_path) = std::env::var("TRNM_NATIVE_SYNC_SIGKILL_PATH_V1") else {
        return;
    };
    let Ok(ready_path) = std::env::var("TRNM_NATIVE_SYNC_SIGKILL_READY_V1") else {
        return;
    };
    let (path, manifest, application, chunks) = durable_session_fixture();
    let _store = SqliteNativeStateSyncStoreV1::open_existing(&store_path).unwrap();
    let mut next = NativeStateSyncSessionV1::begin(path, manifest, application).unwrap();
    next.accept_chunk(chunks[0].clone()).unwrap();
    let readback = next.readback();
    let mut connection = rusqlite::Connection::open(&store_path).unwrap();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    transaction
        .execute(
            "INSERT INTO native_state_sync_chunks_v1(chunk_index,manifest_digest,bytes,chunk_digest) VALUES(?1,?2,?3,?4)",
            params![
                i64::from(chunks[0].index),
                &chunks[0].manifest_digest.0[..],
                &chunks[0].bytes,
                &chunks[0].chunk_digest.0[..]
            ],
        )
        .unwrap();
    transaction
        .execute(
            "UPDATE native_state_sync_meta_v1 SET received_chunk_count=?1,received_bytes=?2,progress_digest=?3 WHERE singleton=1",
            params![
                i64::from(readback.received_chunk_count),
                i64::try_from(readback.received_bytes).unwrap(),
                &readback.progress_digest.0[..]
            ],
        )
        .unwrap();
    std::fs::write(ready_path, b"uncommitted").unwrap();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[test]
fn native_sqlite_append_rejects_stale_concurrent_writer_after_durable_cas() {
    let (path, manifest, application, chunks) = durable_session_fixture();
    let store_path = std::env::temp_dir().join(format!(
        "trnm-native-sync-stale-writer-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let base = NativeStateSyncSessionV1::begin(path, manifest, application).unwrap();
    let store = SqliteNativeStateSyncStoreV1::initialize(&store_path, &base).unwrap();
    let gate = std::sync::Arc::new(std::sync::Barrier::new(3));
    let left_gate = gate.clone();
    let left_store = store.clone();
    let left_session = base.clone();
    let left_chunk = chunks[0].clone();
    let left = std::thread::spawn(move || {
        let mut session = left_session;
        left_gate.wait();
        left_store.append_chunk_v1(&mut session, left_chunk)
    });
    let right_gate = gate.clone();
    let right_store = store.clone();
    let right_session = base;
    let right_chunk = chunks[1].clone();
    let right = std::thread::spawn(move || {
        let mut session = right_session;
        right_gate.wait();
        right_store.append_chunk_v1(&mut session, right_chunk)
    });
    gate.wait();
    let left_result = left.join().unwrap();
    let right_result = right.join().unwrap();
    assert_eq!(
        usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()),
        1
    );
    let stale = [left_result, right_result]
        .into_iter()
        .find_map(Result::err)
        .expect("one writer must lose the durable compare-and-swap");
    assert!(matches!(
        stale,
        NativeStateSyncStoreErrorV1::DurableReadbackMismatch
    ));
    assert_eq!(store.readback_v1().unwrap().received_chunk_count, 1);
    let _ = std::fs::remove_file(&store_path);
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-shm"));
}

#[test]
fn native_sqlite_readback_uses_one_snapshot_while_append_commits_between_queries() {
    let _interleaving_guard = METADATA_INTERLEAVING_TEST_LOCK.lock().unwrap();
    let (path, manifest, application, chunks) = durable_session_fixture();
    let store_path = std::env::temp_dir().join(format!(
        "trnm-native-sync-read-snapshot-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut session = NativeStateSyncSessionV1::begin(path, manifest, application).unwrap();
    let store = SqliteNativeStateSyncStoreV1::initialize(&store_path, &session).unwrap();
    begin_metadata_read_pause_v1();
    let reader_store = store.clone();
    let reader = std::thread::spawn(move || reader_store.binding_and_readback_v1());
    wait_metadata_read_pause_v1();

    // This commit lands after the reader's metadata SELECT but before its
    // chunk SELECT. A transaction-pinned reader must continue seeing the
    // pre-append empty snapshot, not combine count=0 with one retained chunk.
    store
        .append_chunk_v1(&mut session, chunks[0].clone())
        .unwrap();
    end_metadata_read_pause_v1();
    let (_, readback) = reader.join().unwrap().unwrap();
    assert_eq!(readback.received_chunk_count, 0);
    assert_eq!(readback.received_bytes, 0);
    assert_eq!(store.readback_v1().unwrap().received_chunk_count, 1);

    let _ = std::fs::remove_file(&store_path);
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-shm"));
}

#[test]
fn native_sqlite_resume_holds_writer_lock_until_authenticated_join_finishes() {
    let _interleaving_guard = METADATA_INTERLEAVING_TEST_LOCK.lock().unwrap();
    let (path, manifest, application, chunks) = durable_session_fixture();
    let store_path = std::env::temp_dir().join(format!(
        "trnm-native-sync-resume-lock-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let base =
        NativeStateSyncSessionV1::begin(path.clone(), manifest.clone(), application).unwrap();
    let store = SqliteNativeStateSyncStoreV1::initialize(&store_path, &base).unwrap();

    // Pause after the resume transaction has read metadata.  A writer that
    // could interleave here would make the returned session describe a stale
    // durable snapshot; BEGIN IMMEDIATE must keep it waiting until resume
    // commits.
    begin_metadata_read_pause_v1();
    let resume_store = store.clone();
    let resume_path = path.clone();
    let resume_manifest = manifest.clone();
    let resume = std::thread::spawn(move || {
        resume_store.resume_existing_v1(resume_path, resume_manifest, application)
    });
    wait_metadata_read_pause_v1();

    let writer_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer_done_clone = writer_done.clone();
    let writer_store = store.clone();
    let writer_base = base.clone();
    let writer_chunk = chunks[0].clone();
    let writer = std::thread::spawn(move || {
        let mut session = writer_base;
        let result = writer_store.append_chunk_v1(&mut session, writer_chunk);
        writer_done_clone.store(true, Ordering::SeqCst);
        result
    });
    // The writer must not complete while the authenticated resume still owns
    // the SQLite writer lock.
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert!(!writer_done.load(Ordering::SeqCst));
    end_metadata_read_pause_v1();

    let resumed = resume.join().unwrap().unwrap();
    assert_eq!(resumed.readback().received_chunk_count, 0);
    writer.join().unwrap().unwrap();
    assert_eq!(store.readback_v1().unwrap().received_chunk_count, 1);

    let _ = std::fs::remove_file(&store_path);
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-shm"));
}

#[test]
fn native_sqlite_initialize_is_single_publisher_under_concurrency() {
    let (path, manifest, application, _) = durable_session_fixture();
    let store_path = std::env::temp_dir().join(format!(
        "trnm-native-sync-init-race-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let session = NativeStateSyncSessionV1::begin(path, manifest, application).unwrap();
    let gate = std::sync::Arc::new(std::sync::Barrier::new(3));
    let left_gate = gate.clone();
    let left_path = store_path.clone();
    let left_session = session.clone();
    let left = std::thread::spawn(move || {
        left_gate.wait();
        SqliteNativeStateSyncStoreV1::initialize(left_path, &left_session)
    });
    let right_gate = gate.clone();
    let right_path = store_path.clone();
    let right_session = session;
    let right = std::thread::spawn(move || {
        right_gate.wait();
        SqliteNativeStateSyncStoreV1::initialize(right_path, &right_session)
    });
    gate.wait();
    let left_result = left.join().unwrap();
    let right_result = right.join().unwrap();
    assert_eq!(
        usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()),
        1
    );
    let loser = [left_result, right_result]
        .into_iter()
        .find_map(Result::err)
        .expect("one initializer must lose the publication race");
    assert!(matches!(
        loser,
        NativeStateSyncStoreErrorV1::StoreAlreadyInitialized
    ));
    let reopened = SqliteNativeStateSyncStoreV1::open_existing(&store_path).unwrap();
    assert_eq!(reopened.readback_v1().unwrap().received_chunk_count, 0);
    let _ = std::fs::remove_file(&store_path);
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(store_path.with_extension("sqlite-shm"));
}

#[cfg(unix)]
#[test]
fn native_sqlite_paths_reject_symlink_aliases_and_dangling_reservations() {
    let (path, manifest, application, _) = durable_session_fixture();
    let root = std::env::temp_dir().join(format!(
        "trnm-native-sync-symlink-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let target = root.join("target.sqlite");
    let alias = root.join("alias.sqlite");
    let dangling = root.join("dangling.sqlite");
    let session = NativeStateSyncSessionV1::begin(path, manifest, application).unwrap();
    let store = SqliteNativeStateSyncStoreV1::initialize(&target, &session).unwrap();
    drop(store);
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    assert!(matches!(
        SqliteNativeStateSyncStoreV1::open_existing(&alias),
        Err(NativeStateSyncStoreErrorV1::Io(_))
    ));
    std::os::unix::fs::symlink(root.join("missing.sqlite"), &dangling).unwrap();
    assert!(matches!(
        SqliteNativeStateSyncStoreV1::initialize(&dangling, &session),
        Err(NativeStateSyncStoreErrorV1::StoreAlreadyInitialized)
    ));
    let _ = std::fs::remove_file(&alias);
    let _ = std::fs::remove_file(&dangling);
    let _ = std::fs::remove_file(&target);
    let _ = std::fs::remove_file(target.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(target.with_extension("sqlite-shm"));
    let _ = std::fs::remove_dir(&root);
}

#[test]
fn native_path_rejects_replay_reordering_disconnected_checkpoint_and_untrusted_set() {
    let (evidence, set, params, binding) = fixture("positive");
    let decoded = decode_epoch_activation_evidence_v0_exact(
        evidence.as_preimages(),
        &set,
        &params,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let checkpoint = decoded.old_checkpoint_finality().finalized_block().header();
    let parent = decoded.authenticated_checkpoint_parent_header();
    let parent_anchor = pinned(parent, &set, &params);
    let checkpoint_anchor = pinned(checkpoint, &set, &params);
    let activation = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &set,
        &params,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let (bytes, expected, signatures) = first_epoch_finality_bytes(&activation);
    let ordinary = NativeTrustStepV1::Ordinary {
        proof: &evidence.old_checkpoint_finality,
        expected: expectation(checkpoint, parent),
    };
    let epoch = NativeTrustStepV1::EpochFirst {
        evidence: evidence.as_preimages(),
        proof: &bytes,
        expected,
    };
    let verify = |anchor: &NativeTrustAnchorV1, steps: &[NativeTrustStepV1<'_>]| {
        verify_native_trust_path_v1(
            anchor,
            steps,
            NativeTrustPathLimitsV1::default(),
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
    };
    assert!(verify(&checkpoint_anchor, &[epoch]).is_ok());
    for steps in [
        vec![],
        vec![epoch, ordinary],
        vec![ordinary, ordinary],
        vec![ordinary, epoch, epoch],
    ] {
        assert!(verify(&parent_anchor, &steps).is_err());
    }
    let mut wrong_expected = expected;
    wrong_expected.parent_timestamp_ms += 1;
    assert!(verify(
        &checkpoint_anchor,
        &[NativeTrustStepV1::EpochFirst {
            evidence: evidence.as_preimages(),
            proof: &bytes,
            expected: wrong_expected
        }]
    )
    .is_err());
    // Equal checkpoint height but another header must fail even if the epoch proof is genuine.
    let wrong = BlockHeader::new(
        checkpoint.genesis_hash(),
        checkpoint.chain_id(),
        checkpoint.protocol_version(),
        checkpoint.epoch(),
        checkpoint.view(),
        checkpoint.height(),
        checkpoint.block_kind(),
        checkpoint.parent_id(),
        checkpoint.proposer_id(),
        checkpoint.validator_set_id(),
        checkpoint.consensus_parameters_hash(),
        checkpoint.payload_root(),
        trnm_consensus_types::StateRoot::new([77; 32]),
        checkpoint.receipts_root(),
        checkpoint.evidence_root(),
        checkpoint.timestamp_ms(),
        checkpoint.next_epoch_commitment_hash(),
    )
    .unwrap();
    assert!(verify(&pinned(&wrong, &set, &params), &[epoch]).is_err());
    let mut swapped = evidence.clone();
    swapped.old_validator_set = evidence.new_validator_set.clone();
    assert!(verify(
        &checkpoint_anchor,
        &[NativeTrustStepV1::EpochFirst {
            evidence: swapped.as_preimages(),
            proof: &bytes,
            expected
        }]
    )
    .is_err());
    for offset in signatures {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        assert!(verify_native_trust_path_v1(
            &checkpoint_anchor,
            &[NativeTrustStepV1::EpochFirst {
                evidence: evidence.as_preimages(),
                proof: &corrupt,
                expected
            }],
            NativeTrustPathLimitsV1::default(),
            &mut budget
        )
        .is_err());
        assert!(budget.signature_work() > 0);
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(verify(
        &checkpoint_anchor,
        &[NativeTrustStepV1::EpochFirst {
            evidence: evidence.as_preimages(),
            proof: &trailing,
            expected
        }]
    )
    .is_err());
    assert!(verify(
        &checkpoint_anchor,
        &[NativeTrustStepV1::Ordinary {
            proof: &bytes,
            expected
        }]
    )
    .is_err());
}

#[test]
fn anchor_pin_covers_every_context_byte_and_generic_epoch_zero_rule_remains() {
    let (evidence, set, params, _) = fixture("positive");
    let header = &evidence.authenticated_checkpoint_parent_header;
    let pin = native_trust_anchor_pin_v1(
        header,
        &evidence.old_validator_set,
        &evidence.old_consensus_parameters,
    )
    .unwrap();
    for index in 0..3 {
        let mut parts = [
            header.clone(),
            evidence.old_validator_set.clone(),
            evidence.old_consensus_parameters.clone(),
        ];
        parts[index][0] ^= 1;
        assert!(
            NativeTrustAnchorV1::from_pinned_bytes(&parts[0], &parts[1], &parts[2], pin).is_err()
        );
    }
    assert!(NativeTrustAnchorV1::from_pinned_bytes(
        header,
        &evidence.old_validator_set,
        &evidence.old_consensus_parameters,
        Digest32V0([0; 32])
    )
    .is_err());
    assert!(NativeTrustAnchorV1::from_pinned_bytes(
        header,
        &evidence.new_validator_set,
        &evidence.old_consensus_parameters,
        native_trust_anchor_pin_v1(
            header,
            &evidence.new_validator_set,
            &evidence.old_consensus_parameters
        )
        .unwrap()
    )
    .is_err());
    let anchor = NativeTrustAnchorV1::from_pinned_bytes(
        header,
        &evidence.old_validator_set,
        &evidence.old_consensus_parameters,
        pin,
    )
    .unwrap();
    assert_eq!(anchor.validator_set(), &set);
    assert_eq!(anchor.parameters(), &params);
    assert!(WeakSubjectivityAnchorV0 {
        chain_id: Digest32V0([1; 32]),
        protocol_digest: Digest32V0([2; 32]),
        epoch: 0,
        height: 10,
        checkpoint_digest: pin,
        validator_set_digest: Digest32V0([3; 32])
    }
    .validate()
    .is_err());
    assert!(native_trust_anchor_pin_v1(&vec![1; MAX_NATIVE_ANCHOR_BYTES_V1], b"x", b"y").is_err());
}

#[test]
fn epoch_path_accepts_strict_timeout_certificate_route() {
    let (evidence, set, params, binding) = fixture("positive");
    let activation = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &set,
        &params,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let (base, expected, _) = first_epoch_finality_bytes(&activation);
    let verified = decode_verify_epoch_first_finality_strict_v1(
        evidence.as_preimages(),
        &base,
        &set,
        &params,
        expected,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let first = verified.proof().finalized_block();
    let anchor_context = (
        first.justify_qc().clone(),
        first.epoch_anchor_authorization().unwrap().clone(),
    );
    let (proof, expected, _) =
        first_epoch_finality_with_views(&activation, [3, 5, 8], Some(anchor_context));
    let anchor = pinned(verified.checkpoint_header(), &set, &params);
    let path = verify_native_trust_path_v1(
        &anchor,
        &[NativeTrustStepV1::EpochFirst {
            evidence: evidence.as_preimages(),
            proof: &proof,
            expected,
        }],
        NativeTrustPathLimitsV1::default(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert_eq!(path.terminal_header().view().get(), 3);
    assert_eq!(
        path.terminal_header().height().get(),
        anchor.header().height().get() + 3
    );
}

#[test]
fn native_positive_height_epoch_zero_anchor_is_explicitly_supported() {
    use trnm_consensus_types::{BlockId, BlockKind, Epoch, Height, View};
    let (evidence, set, params, _) = fixture("positive");
    let old =
        decode_block_header_v0_exact(&evidence.authenticated_checkpoint_parent_header).unwrap();
    let zero = ValidatorSet::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        Epoch::new(0),
        params.hash(),
        set.validators().to_vec(),
    )
    .unwrap();
    let header = BlockHeader::new(
        zero.genesis_hash(),
        zero.chain_id(),
        zero.protocol_version(),
        Epoch::new(0),
        View::new(1),
        Height::new(1),
        BlockKind::Regular,
        BlockId::new(*zero.genesis_hash().as_bytes()),
        zero.validators()[0].id(),
        zero.id(),
        params.hash(),
        old.payload_root(),
        old.state_root(),
        old.receipts_root(),
        old.evidence_root(),
        1000,
        None,
    )
    .unwrap();
    let anchor = pinned(&header, &zero, &params);
    assert_eq!(anchor.header().epoch().get(), 0);
    assert_eq!(anchor.header().height().get(), 1);
}
