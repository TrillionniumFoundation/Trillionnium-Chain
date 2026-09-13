#![cfg(target_os = "linux")]

//! Four validator host instances in one local test process, using real
//! SQLite/Core/signer-journal integration. Keys and the independently
//! retained in-memory watermark below are test fixtures, not custody evidence.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use ed25519_dalek::{Signer, SigningKey};
use tempfile::TempDir;
use trnm_consensus_core::{CoreConfig, OutboundMessage, SafetyStateRecordLimitsV0};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, SignatureProducerErrorV0,
    SignatureProducerV0, SignatureRequestV0, SignerWatermarkV0,
};
use trnm_consensus_types::{
    BlockId, Cev0AdmissionBudgetV0, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch,
    GenesisHash, GenesisQcV0, Height, ProtocolVersion, QcReferenceV0, QuorumCertificate,
    SignatureBytes, TimeoutCertificateV0, TimeoutEntryV0, TimeoutVote, Validator, ValidatorId,
    ValidatorSet, View, Vote, VotingPower,
};
use trnm_poco_node::{
    PocoNodeHostActionV0, PocoNodeHostErrorV0, PocoNodeHostV0, PocoNodeStartConfigV0,
    PocoNodeTimeoutCertificateErrorV0 as TcError,
    PocoNodeTimeoutCertificateUnavailableV0 as TcUnavailable,
};

#[derive(Clone, Default)]
struct FixtureWatermark(Arc<Mutex<Option<SignerWatermarkV0>>>);

impl ExternalMonotonicWatermarkV0 for FixtureWatermark {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        let value = *self.0.lock().unwrap();
        if value.is_some_and(|head| head.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(value)
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

struct FixtureProducer {
    key: SigningKey,
    calls: Arc<AtomicUsize>,
}

impl SignatureProducerV0 for FixtureProducer {
    fn sign(
        &mut self,
        request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(SignatureBytes::from_array(
            self.key.sign(request.signing_root().as_bytes()).to_bytes(),
        ))
    }
}

struct Fixture {
    keys: Vec<SigningKey>,
    set: ValidatorSet,
    parameters: ConsensusParametersV0,
}

impl Fixture {
    fn new() -> Self {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let keys = (41u8..45)
            .map(|key| SigningKey::from_bytes(&[key; 32]))
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Validator::new(
                    ValidatorId::new([index as u8 + 1; 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let set = ValidatorSet::new(
            GenesisHash::new([0xA5; 32]),
            ChainId::from_static("trnm-tc-host-recovery"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        Self {
            keys,
            set,
            parameters,
        }
    }

    fn genesis(&self) -> GenesisQcV0 {
        GenesisQcV0::new(self.set.genesis_hash(), self.set.chain_id(), &self.set).unwrap()
    }

    fn budget(&self) -> Cev0AdmissionBudgetV0 {
        Cev0AdmissionBudgetV0::for_validator_set(&self.parameters, &self.set)
    }

    fn tc(&self, view: u64, reference: QcReferenceV0) -> TimeoutCertificateV0 {
        let root =
            TimeoutVote::signing_root_for_set(&self.set, View::new(view), reference.qc_ref())
                .unwrap();
        let entries = self
            .keys
            .iter()
            .take(3)
            .enumerate()
            .map(|(index, key)| {
                TimeoutEntryV0::new(
                    ValidatorId::new([index as u8 + 1; 32]),
                    reference.qc_ref(),
                    SignatureBytes::from_array(key.sign(root.as_bytes()).to_bytes()),
                )
                .unwrap()
            })
            .collect();
        TimeoutCertificateV0::new(
            View::new(view),
            entries,
            vec![reference.clone()],
            reference.id(),
            &self.set,
        )
        .unwrap()
    }

    fn genesis_tc(&self, view: u64) -> TimeoutCertificateV0 {
        self.tc(view, QcReferenceV0::genesis_anchor(self.genesis()))
    }

    fn missing_ordinary_qc(&self) -> QcReferenceV0 {
        let block = BlockId::new([0xB7; 32]);
        let root =
            Vote::signing_root_for_set(&self.set, View::new(1), Height::new(1), block).unwrap();
        let votes = self
            .keys
            .iter()
            .take(3)
            .enumerate()
            .map(|(index, key)| {
                Vote::new(
                    self.set.chain_id(),
                    ProtocolVersion::V0,
                    Epoch::new(0),
                    View::new(1),
                    Height::new(1),
                    block,
                    self.set.id(),
                    ValidatorId::new([index as u8 + 1; 32]),
                    SignatureBytes::from_array(key.sign(root.as_bytes()).to_bytes()),
                    &self.set,
                )
                .unwrap()
            })
            .collect();
        QcReferenceV0::ordinary(
            QuorumCertificate::new(
                self.set.chain_id(),
                ProtocolVersion::V0,
                Epoch::new(0),
                View::new(1),
                Height::new(1),
                block,
                self.set.id(),
                votes,
                &self.set,
            )
            .unwrap(),
        )
    }
}

type Host = PocoNodeHostV0<FixtureWatermark, FixtureProducer>;

struct Node {
    _root: TempDir,
    config: PocoNodeStartConfigV0,
    watermark: FixtureWatermark,
    key: SigningKey,
    calls: Arc<AtomicUsize>,
}

impl Node {
    fn new(fixture: &Fixture, index: usize) -> (Self, Host) {
        let root = TempDir::new().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["safety", "signer"] {
            let path = root.path().join(name);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let core = CoreConfig::new(
            ValidatorId::new([index as u8 + 1; 32]),
            fixture.set.clone(),
            fixture.parameters,
            17,
            64,
            64,
        )
        .unwrap();
        let config = PocoNodeStartConfigV0::new(
            root.path().join("safety/state.sqlite3"),
            root.path().join("signer/signer.sqlite3"),
            core,
            SafetyStateRecordLimitsV0::new(64 * 1024 * 1024, 16 * 1024 * 1024).unwrap(),
            192 * 1024 * 1024,
            64,
            4096,
            32 * 1024 * 1024,
        )
        .unwrap();
        let node = Self {
            _root: root,
            config,
            watermark: FixtureWatermark::default(),
            key: fixture.keys[index].clone(),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let host = PocoNodeHostV0::initialize_new(
            node.config.clone(),
            fixture.genesis(),
            node.watermark.clone(),
            node.producer(),
        )
        .unwrap();
        (node, host)
    }

    fn producer(&self) -> FixtureProducer {
        FixtureProducer {
            key: self.key.clone(),
            calls: self.calls.clone(),
        }
    }

    fn reopen(&self) -> Host {
        PocoNodeHostV0::open_existing(self.config.clone(), self.watermark.clone(), self.producer())
            .unwrap()
    }

    fn tamper_safety_metadata(&self) {
        let connection =
            rusqlite::Connection::open(self._root.path().join("safety/state.sqlite3")).unwrap();
        assert_eq!(connection.execute(
            "UPDATE safety_store_metadata_v0 SET metadata_checksum=zeroblob(32) WHERE singleton=1",
            [],
        ).unwrap(), 1);
    }

    fn assert_reopen_rejected(&self) {
        assert!(PocoNodeHostV0::open_existing(
            self.config.clone(),
            self.watermark.clone(),
            self.producer()
        )
        .is_err());
    }
}

fn timeout(actions: Vec<PocoNodeHostActionV0>) -> TimeoutVote {
    actions
        .into_iter()
        .find_map(|action| match action {
            PocoNodeHostActionV0::Broadcast(value) => match value.message() {
                OutboundMessage::TimeoutVote(vote) => Some(vote.clone()),
                _ => None,
            },
            _ => None,
        })
        .expect("one actual host-produced timeout")
}

#[test]
fn four_hosts_form_tc_advance_reopen_and_sign_the_next_view() {
    let fixture = Fixture::new();
    let mut fleet = (0..4)
        .map(|index| Node::new(&fixture, index))
        .collect::<Vec<_>>();
    let emitted = fleet
        .iter_mut()
        .map(|(_, host)| timeout(host.on_local_timeout_v0().unwrap()))
        .collect::<Vec<_>>();
    let anchor = QcReferenceV0::genesis_anchor(fixture.genesis());
    let entries = emitted
        .iter()
        .take(3)
        .map(|vote| TimeoutEntryV0::new(vote.author(), vote.high_qc(), *vote.signature()).unwrap())
        .collect();
    let tc = TimeoutCertificateV0::new(
        View::new(1),
        entries,
        vec![anchor.clone()],
        anchor.id(),
        &fixture.set,
    )
    .unwrap();
    let bytes = tc.try_cev0_bytes().unwrap();
    for (node, host) in &mut fleet {
        let mut budget = fixture.budget();
        assert_eq!(
            host.on_timeout_certificate_bytes_v0(&bytes, &mut budget)
                .unwrap(),
            vec![PocoNodeHostActionV0::ArmViewTimer {
                epoch: Epoch::new(0),
                view: View::new(2)
            }]
        );
        assert_eq!(
            budget.signature_work(),
            6,
            "both TC verification passes are charged"
        );
        assert_eq!(
            node.calls.load(Ordering::SeqCst),
            1,
            "TC never invokes custody"
        );
        assert_eq!(
            host.safety_head().unwrap().state().current_view(),
            View::new(2)
        );
        assert!(host.production_activation_check().is_err());
    }
    let (node, host) = fleet.remove(0);
    drop(host); // The caller may have lost every timer action returned above.
    let mut reopened = node.reopen();
    assert_eq!(reopened.safety_state().current_view(), View::new(2));
    let before = reopened.safety_head().unwrap().revision();
    assert!(reopened
        .on_timeout_certificate_bytes_v0(&bytes, &mut fixture.budget())
        .unwrap()
        .is_empty());
    assert_eq!(reopened.safety_head().unwrap().revision(), before);
    let next = timeout(reopened.on_local_timeout_v0().unwrap());
    assert_eq!(next.view(), View::new(2));
    next.verify(&fixture.set, &StrictEd25519Verifier).unwrap();
    assert_eq!(node.calls.load(Ordering::SeqCst), 2);
    drop(reopened);
    let mut recovered_signature = node.reopen();
    let tc2 = fixture.genesis_tc(2).try_cev0_bytes().unwrap();
    assert!(matches!(
        recovered_signature.on_timeout_certificate_bytes_v0(&tc2, &mut fixture.budget()),
        Err(TcError::Unavailable(TcUnavailable::PendingSignature))
    ));
    let replayed = timeout(recovered_signature.resume_v0().unwrap());
    assert_eq!(replayed, next);
    assert_eq!(
        node.calls.load(Ordering::SeqCst),
        2,
        "lost signature reply replays without custody"
    );
    recovered_signature
        .on_timeout_certificate_bytes_v0(&tc2, &mut fixture.budget())
        .unwrap();
    assert_eq!(
        recovered_signature.safety_state().current_view(),
        View::new(3)
    );
}

#[test]
fn malformed_wrong_context_and_bad_signatures_leave_the_host_reusable() {
    let fixture = Fixture::new();
    let (node, mut host) = Node::new(&fixture, 0);
    let valid = fixture.genesis_tc(1).try_cev0_bytes().unwrap();
    // Schema(2), genesis(32), ConsensusString(2+L), protocol(4), epoch(8),
    // validator set digest(32), timed-out view(8).
    let count_at = 88 + fixture.set.chain_id().as_bytes().len();
    assert_eq!(&valid[count_at..count_at + 4], &3u32.to_be_bytes());
    let first = count_at + 4;
    // Exact CEV0: Bytes<validator-id>(4+32), QC summary(32+8+8+8+32), signature(64).
    let entry_bytes = 188;
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut wrong_chain = valid.clone();
    wrong_chain[36] ^= 1;
    let mut bad_signature = valid.clone();
    bad_signature[first + entry_bytes - 1] ^= 1;
    let mut duplicate = valid.clone();
    duplicate.copy_within(first..first + entry_bytes, first + entry_bytes);
    let mut reordered = valid.clone();
    reordered[first..first + entry_bytes]
        .copy_from_slice(&valid[first + entry_bytes..first + 2 * entry_bytes]);
    reordered[first + entry_bytes..first + 2 * entry_bytes]
        .copy_from_slice(&valid[first..first + entry_bytes]);
    let mut insufficient = valid.clone();
    insufficient[count_at..count_at + 4].copy_from_slice(&2u32.to_be_bytes());
    insufficient.drain(first + 2 * entry_bytes..first + 3 * entry_bytes);
    let before = host.safety_head().unwrap().state().clone();
    for bytes in [
        trailing,
        wrong_chain,
        bad_signature,
        duplicate,
        reordered,
        insufficient,
        valid[..8].to_vec(),
    ] {
        assert!(host
            .on_timeout_certificate_bytes_v0(&bytes, &mut fixture.budget())
            .is_err());
        assert_eq!(host.safety_state(), &before);
        assert_eq!(host.safety_head().unwrap().state(), &before);
        assert_eq!(node.calls.load(Ordering::SeqCst), 0);
    }
    host.on_timeout_certificate_bytes_v0(&valid, &mut fixture.budget())
        .unwrap();
    assert_eq!(host.safety_state().current_view(), View::new(2));
}

#[test]
fn local_budget_failure_before_second_crypto_pass_has_no_durable_effect() {
    let fixture = Fixture::new();
    let (node, mut host) = Node::new(&fixture, 0);
    let bytes = fixture.genesis_tc(1).try_cev0_bytes().unwrap();
    let mut budget = Cev0AdmissionBudgetV0::new(bytes.len(), 3);
    assert!(matches!(
        host.on_timeout_certificate_bytes_v0(&bytes, &mut budget),
        Err(TcError::Admission(_))
    ));
    assert_eq!(budget.signature_work(), 3);
    assert_eq!(host.safety_head().unwrap().revision(), 0);
    assert_eq!(node.calls.load(Ordering::SeqCst), 0);
    host.on_timeout_certificate_bytes_v0(&bytes, &mut fixture.budget())
        .unwrap();
}

#[test]
fn certified_missing_ancestry_is_unavailable_and_does_not_poison_the_header() {
    let fixture = Fixture::new();
    let (node, mut host) = Node::new(&fixture, 0);
    let bytes = fixture
        .tc(2, fixture.missing_ordinary_qc())
        .try_cev0_bytes()
        .unwrap();
    assert!(matches!(
        host.on_timeout_certificate_bytes_v0(&bytes, &mut fixture.budget()),
        Err(TcError::Unavailable(
            TcUnavailable::AuthenticatedAncestryRequired
        ))
    ));
    assert_eq!(host.safety_head().unwrap().revision(), 0);
    assert_eq!(host.safety_state().current_view(), View::new(1));
    assert_eq!(node.calls.load(Ordering::SeqCst), 0);
    host.on_timeout_certificate_bytes_v0(
        &fixture.genesis_tc(1).try_cev0_bytes().unwrap(),
        &mut fixture.budget(),
    )
    .unwrap();
}

#[test]
fn narrow_local_aggregate_and_forged_stale_tc_never_mutate_the_owner() {
    let fixture = Fixture::new();
    let (node, mut host) = Node::new(&fixture, 0);
    let ordinary = fixture
        .tc(2, fixture.missing_ordinary_qc())
        .try_cev0_bytes()
        .unwrap();
    let mut narrow = Cev0AdmissionBudgetV0::with_limits(ordinary.len(), 100, 2);
    assert!(matches!(
        host.on_timeout_certificate_bytes_v0(&ordinary, &mut narrow),
        Err(TcError::Admission(_))
    ));
    assert_eq!(
        narrow.signature_work(),
        0,
        "nested cap applies before verification"
    );
    assert_eq!(host.safety_head().unwrap().revision(), 0);

    let valid = fixture.genesis_tc(1).try_cev0_bytes().unwrap();
    host.on_timeout_certificate_bytes_v0(&valid, &mut fixture.budget())
        .unwrap();
    let advanced = host.safety_head().unwrap().state().clone();
    let mut forged = valid.clone();
    let first_signature_last_byte = 88 + fixture.set.chain_id().as_bytes().len() + 4 + 188 - 1;
    forged[first_signature_last_byte] ^= 1;
    assert!(matches!(
        host.on_timeout_certificate_bytes_v0(&forged, &mut fixture.budget()),
        Err(TcError::InvalidCertificate(_))
    ));
    assert_eq!(host.safety_head().unwrap().state(), &advanced);
    assert_eq!(host.safety_state(), &advanced);
    assert_eq!(node.calls.load(Ordering::SeqCst), 0);
    let mut wrong_context = valid.clone();
    wrong_context[36] ^= 1;
    assert!(matches!(
        host.on_timeout_certificate_bytes_v0(&wrong_context, &mut fixture.budget()),
        Err(TcError::Admission(_))
    ));
    assert_eq!(host.safety_head().unwrap().state(), &advanced);
    let mut stale_budget = fixture.budget();
    assert!(host
        .on_timeout_certificate_bytes_v0(&valid, &mut stale_budget)
        .unwrap()
        .is_empty());
    assert_eq!(stale_budget.signature_work(), 3);
    assert_eq!(host.safety_head().unwrap().state(), &advanced);
}

#[test]
fn sqlite_tamper_fences_the_host_before_any_timer_and_rejects_reopen() {
    let fixture = Fixture::new();
    let (node, mut host) = Node::new(&fixture, 0);
    let bytes = fixture.genesis_tc(1).try_cev0_bytes().unwrap();
    node.tamper_safety_metadata();
    assert!(matches!(
        host.on_timeout_certificate_bytes_v0(&bytes, &mut fixture.budget()),
        Err(TcError::Host(_))
    ));
    assert!(matches!(
        host.resume_v0(),
        Err(PocoNodeHostErrorV0::BoundedTimeoutHostFailStopped)
    ));
    assert!(matches!(
        host.on_local_timeout_v0(),
        Err(PocoNodeHostErrorV0::BoundedTimeoutHostFailStopped)
    ));
    assert_eq!(node.calls.load(Ordering::SeqCst), 0);
    drop(host);
    node.assert_reopen_rejected();
}

// These are userspace unwind/drop boundaries around real SQLite commits. They
// exercise source/target reconstruction and lost acknowledgement, not SIGKILL,
// power-loss, or independently administered watermark evidence.
#[cfg(feature = "recovery-process-test-support")]
#[test]
fn each_tc_persistence_cut_reopens_the_exact_source_or_target_and_replays() {
    use trnm_poco_node::PocoNodeTimeoutCertificateProcessCheckpointPhaseV0 as Phase;
    for (phase, expected_revision, expected_view) in [
        (Phase::SignatureReleaseBeforePersistence, 1, 1),
        (Phase::SignatureReleasePersistedBeforeReadback, 2, 1),
        (Phase::SignatureReleaseReadbackBeforeStorageAck, 2, 1),
        (Phase::ViewAdvanceBeforePersistence, 2, 1),
        (Phase::ViewAdvancePersistedBeforeReadback, 3, 2),
        (Phase::ViewAdvanceReadbackBeforeStorageAck, 3, 2),
    ] {
        let fixture = Fixture::new();
        let (node, mut host) = Node::new(&fixture, 0);
        let first_timeout = timeout(host.on_local_timeout_v0().unwrap());
        let bytes = fixture.genesis_tc(1).try_cev0_bytes().unwrap();
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            host.on_timeout_certificate_bytes_with_process_checkpoint_observer_v0(
                &bytes,
                &mut fixture.budget(),
                &mut |current| {
                    if current == phase {
                        panic!("abandon owner at {phase:?}");
                    }
                },
            )
            .unwrap()
        }));
        assert!(interrupted.is_err());
        drop(host);
        assert_eq!(node.calls.load(Ordering::SeqCst), 1);
        let mut recovered = node.reopen();
        assert_eq!(
            recovered.safety_head().unwrap().revision(),
            expected_revision,
            "{phase:?}"
        );
        assert_eq!(
            recovered.safety_state().current_view(),
            View::new(expected_view),
            "{phase:?}"
        );
        let resumed = recovered.resume_v0().unwrap();
        if expected_revision == 1 {
            assert_eq!(timeout(resumed), first_timeout);
        } else {
            assert!(resumed.iter().all(|action| matches!(action,
                PocoNodeHostActionV0::ArmViewTimer { epoch, view }
                    if *epoch == Epoch::new(0) && *view == View::new(expected_view)
            )));
        }
        recovered
            .on_timeout_certificate_bytes_v0(&bytes, &mut fixture.budget())
            .unwrap();
        assert_eq!(recovered.safety_state().current_view(), View::new(2));
        let second = timeout(recovered.on_local_timeout_v0().unwrap());
        assert_eq!(second.view(), View::new(2));
        second.verify(&fixture.set, &StrictEd25519Verifier).unwrap();
        assert_eq!(node.calls.load(Ordering::SeqCst), 2);
    }
}

#[cfg(feature = "recovery-process-test-support")]
#[test]
fn tamper_after_each_tc_write_never_releases_a_timer_or_reuses_the_owner() {
    use trnm_poco_node::PocoNodeTimeoutCertificateProcessCheckpointPhaseV0 as Phase;
    for phase in [
        Phase::SignatureReleasePersistedBeforeReadback,
        Phase::ViewAdvancePersistedBeforeReadback,
    ] {
        let fixture = Fixture::new();
        let (node, mut host) = Node::new(&fixture, 0);
        host.on_local_timeout_v0().unwrap();
        let bytes = fixture.genesis_tc(1).try_cev0_bytes().unwrap();
        let mut injected = false;
        let result = host.on_timeout_certificate_bytes_with_process_checkpoint_observer_v0(
            &bytes,
            &mut fixture.budget(),
            &mut |current| {
                if current == phase {
                    node.tamper_safety_metadata();
                    injected = true;
                }
            },
        );
        assert!(injected);
        assert!(matches!(result, Err(TcError::Host(_))));
        assert!(matches!(
            host.resume_v0(),
            Err(PocoNodeHostErrorV0::BoundedTimeoutHostFailStopped)
        ));
        assert_eq!(node.calls.load(Ordering::SeqCst), 1);
        drop(host);
        node.assert_reopen_rejected();
    }
}
