use super::*;
use crate::ExternalWatermarkErrorV0;
use ed25519_dalek::{Signer, SigningKey};
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    sync::{Arc, Mutex},
};
use trnm_consensus_types::{
    ChainId, ConsensusPublicKey, GenesisHash, ProtocolVersion, Validator, VotingPower,
};

#[derive(Default)]
struct AnchorState {
    head: Option<SignerWatermarkV0>,
    fail: Option<(u64, bool)>,
}
#[derive(Clone, Default)]
struct Anchor(Arc<Mutex<AnchorState>>);
impl ExternalMonotonicWatermarkV0 for Anchor {
    fn load(&mut self, _: [u8; 32]) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        Ok(self.0.lock().unwrap().head)
    }
    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        let mut s = self.0.lock().unwrap();
        if s.head != expected || !successor(expected, target) {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        let fail = s.fail.is_some_and(|f| f.0 == target.sequence());
        if fail && !s.fail.unwrap().1 {
            s.fail = None;
            return Err(ExternalWatermarkErrorV0::Unavailable);
        }
        s.head = Some(target);
        if fail {
            s.fail = None;
            return Err(ExternalWatermarkErrorV0::Unavailable);
        }
        Ok(())
    }
}
fn successor(expected: Option<SignerWatermarkV0>, target: SignerWatermarkV0) -> bool {
    match expected {
        None => target.sequence() == 0,
        Some(old) => {
            old.scope() == target.scope()
                && old.journal_id() == target.journal_id()
                && old.sequence().checked_add(1) == Some(target.sequence())
        }
    }
}
fn fixture(maximum: usize) -> (ProposalJournalProfileV1, SigningKey) {
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let keys: Vec<_> = (1..=4).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
    let validators = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            Validator::new(
                ValidatorId::new([i as u8 + 1; 32]),
                ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                VotingPower::new(1).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let set = ValidatorSet::new(
        GenesisHash::new([0xa1; 32]),
        ChainId::from_static("proposal-journal-test"),
        ProtocolVersion::V0,
        Epoch::new(0),
        parameters.hash(),
        validators,
    )
    .unwrap();
    (
        ProposalJournalProfileV1::new(
            set,
            parameters,
            ValidatorId::new([1; 32]),
            [0xb1; 32],
            [0xc1; 32],
            maximum,
        )
        .unwrap(),
        keys[0].clone(),
    )
}
fn request(profile: &ProposalJournalProfileV1, view: u64, root: u8) -> ProposalSignatureRequestV0 {
    ProposalSignatureRequestV0::new(
        BlockId::new([root; 32]),
        BlockId::new([0x22; 32]),
        profile.set.id(),
        profile.author,
        profile.set.epoch(),
        View::new(view),
        Height::new(view + 3),
        SigningRoot::new([root; 32]),
        profile
            .set
            .validator(profile.author)
            .unwrap()
            .consensus_key()
            .into_bytes(),
        profile.signer_profile,
    )
    .unwrap()
}
fn temp() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temp
}
struct Producer {
    key: SigningKey,
    calls: usize,
    observed: Option<SignatureBytes>,
    fail: bool,
    callback: Option<Box<dyn FnMut()>>,
}
impl Producer {
    fn new(key: SigningKey) -> Self {
        Self {
            key,
            calls: 0,
            observed: None,
            fail: false,
            callback: None,
        }
    }
}
impl ProposalSignatureProducerV0 for Producer {
    fn sign_proposal(
        &mut self,
        request: ProposalSignatureRequestV0,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        self.calls += 1;
        if let Some(callback) = self.callback.as_mut() {
            callback();
        }
        let signature =
            SignatureBytes::from_array(self.key.sign(request.signing_root().as_bytes()).to_bytes());
        self.observed = Some(signature);
        if self.fail {
            return Err(SignatureProducerErrorV0::Unavailable);
        }
        Ok(signature)
    }
}

#[test]
fn proposal_persist_and_anchor_precede_custody_and_exact_replay_never_resigns() {
    let t = temp();
    let path = t.path().join("proposal.log");
    let (profile, key) = fixture(4);
    let anchor = Anchor::default();
    let req = request(&profile, 1, 0x31);
    let mut producer = Producer::new(key);
    let mut journal =
        ProposalJournalV1::create_new(&path, profile.clone(), anchor.clone()).unwrap();
    let observation = anchor.clone();
    let disk = path.clone();
    producer.callback = Some(Box::new(move || {
        assert_eq!(
            fs::metadata(&disk).unwrap().len() as usize,
            HEADER_BYTES + RECORD_BYTES
        );
        assert_eq!(observation.0.lock().unwrap().head.unwrap().sequence(), 1);
        assert_eq!(
            &fs::read(&disk).unwrap()[HEADER_BYTES + 9..HEADER_BYTES + 9 + REQUEST_BYTES],
            &encode_request(req)
        );
    }));
    let sig = journal.sign_exact(req, &mut producer).unwrap();
    let bytes = fs::read(&path).unwrap();
    assert_eq!(producer.calls, 1);
    assert_eq!(anchor.0.lock().unwrap().head.unwrap().sequence(), 2);
    assert_eq!(journal.sign_exact(req, &mut producer).unwrap(), sig);
    drop(journal);
    let mut reopened = ProposalJournalV1::open_existing(&path, profile.clone(), anchor).unwrap();
    assert_eq!(reopened.sign_exact(req, &mut producer).unwrap(), sig);
    assert_eq!(producer.calls, 1);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(matches!(
        reopened.sign_exact(request(&profile, 1, 0x32), &mut producer),
        Err(ProposalJournalErrorV1::Conflict)
    ));
    assert_eq!(fs::read(&path).unwrap(), bytes);
    producer.callback = None;
    reopened
        .sign_exact(request(&profile, 2, 0x33), &mut producer)
        .unwrap();
    assert!(matches!(
        reopened.sign_exact(request(&profile, 1, 0x34), &mut producer),
        Err(ProposalJournalErrorV1::Conflict)
    ));
}

#[test]
fn proposal_lost_custody_reply_requires_reopen_and_observed_signature_recovery() {
    let t = temp();
    let path = t.path().join("proposal.log");
    let (profile, key) = fixture(4);
    let anchor = Anchor::default();
    let req = request(&profile, 1, 0x31);
    let mut producer = Producer::new(key);
    producer.fail = true;
    let mut journal =
        ProposalJournalV1::create_new(&path, profile.clone(), anchor.clone()).unwrap();
    assert!(journal.sign_exact(req, &mut producer).is_err());
    assert!(!journal.is_ready());
    assert!(matches!(
        journal.sign_exact(req, &mut producer),
        Err(ProposalJournalErrorV1::NotReady)
    ));
    assert_eq!(producer.calls, 1);
    drop(journal);
    let mut recovered = ProposalJournalV1::open_existing(&path, profile.clone(), anchor).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        recovered.recover_observed_signature(req, SignatureBytes::from_array([1; 64])),
        Err(ProposalJournalErrorV1::InvalidSignature)
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(matches!(
        recovered.sign_exact(request(&profile, 2, 0x33), &mut producer),
        Err(ProposalJournalErrorV1::Conflict)
    ));
    assert_eq!(
        recovered
            .recover_observed_signature(req, producer.observed.unwrap())
            .unwrap(),
        producer.observed.unwrap()
    );
    assert_eq!(
        recovered.sign_exact(req, &mut producer).unwrap(),
        producer.observed.unwrap()
    );
    assert_eq!(producer.calls, 1);
}

#[test]
fn proposal_all_append_anchor_and_custody_cuts_remain_exact() {
    for cut in [
        (1, "sync"),
        (1, "anchor"),
        (1, "custody"),
        (2, "sync"),
        (2, "anchor"),
    ] {
        let t = temp();
        let path = t.path().join("proposal.log");
        let (profile, key) = fixture(4);
        let anchor = Anchor::default();
        let req = request(&profile, 1, 0x31);
        let mut producer = Producer::new(key);
        let mut journal =
            ProposalJournalV1::create_new(&path, profile.clone(), anchor.clone()).unwrap();
        journal.fault = Some(cut);
        assert!(journal.sign_exact(req, &mut producer).is_err());
        assert!(!journal.is_ready());
        drop(journal);
        let mut journal =
            ProposalJournalV1::open_existing(&path, profile.clone(), anchor.clone()).unwrap();
        let expected =
            SignatureBytes::from_array(producer.key.sign(req.signing_root().as_bytes()).to_bytes());
        assert_eq!(journal.sign_exact(req, &mut producer).unwrap(), expected);
        assert_eq!(anchor.0.lock().unwrap().head.unwrap().sequence(), 2);
        assert_eq!(
            fs::metadata(&path).unwrap().len() as usize,
            HEADER_BYTES + 2 * RECORD_BYTES
        );
        assert!(matches!(
            journal.sign_exact(request(&profile, 1, 0x32), &mut producer),
            Err(ProposalJournalErrorV1::Conflict)
        ));
    }
}

#[test]
fn proposal_anchor_failures_before_or_after_apply_never_release_early_signature() {
    for sequence in [1, 2] {
        for apply in [false, true] {
            let t = temp();
            let path = t.path().join("proposal.log");
            let (profile, key) = fixture(4);
            let anchor = Anchor::default();
            let req = request(&profile, 1, 0x31);
            let mut producer = Producer::new(key);
            let mut journal =
                ProposalJournalV1::create_new(&path, profile.clone(), anchor.clone()).unwrap();
            anchor.0.lock().unwrap().fail = Some((sequence, apply));
            assert!(matches!(
                journal.sign_exact(req, &mut producer),
                Err(ProposalJournalErrorV1::Anchor)
            ));
            assert_eq!(producer.calls, usize::from(sequence == 2));
            drop(journal);
            let mut reopened =
                ProposalJournalV1::open_existing(&path, profile, anchor.clone()).unwrap();
            reopened.sign_exact(req, &mut producer).unwrap();
            assert_eq!(producer.calls, 1);
            assert_eq!(anchor.0.lock().unwrap().head.unwrap().sequence(), 2);
        }
    }
}

#[test]
fn proposal_invalid_signature_or_live_disk_mutation_fences_owner() {
    for corrupt_disk in [false, true] {
        let t = temp();
        let path = t.path().join("proposal.log");
        let (profile, key) = fixture(4);
        let anchor = Anchor::default();
        let req = request(&profile, 1, 0x31);
        let mut producer = Producer::new(if corrupt_disk {
            key
        } else {
            SigningKey::from_bytes(&[9; 32])
        });
        let mut journal = ProposalJournalV1::create_new(&path, profile, anchor.clone()).unwrap();
        if corrupt_disk {
            let path = path.clone();
            producer.callback = Some(Box::new(move || {
                let mut bytes = fs::read(&path).unwrap();
                bytes[HEADER_BYTES + 20] ^= 1;
                fs::write(&path, bytes).unwrap();
            }));
        }
        assert!(journal.sign_exact(req, &mut producer).is_err());
        assert!(!journal.is_ready());
        assert_eq!(anchor.0.lock().unwrap().head.unwrap().sequence(), 1);
        assert_eq!(producer.calls, 1);
    }
}

#[test]
fn proposal_corruption_partial_tail_rollback_and_missing_anchor_are_not_repaired() {
    for mutation in 0..4 {
        let t = temp();
        let path = t.path().join("proposal.log");
        let (profile, key) = fixture(4);
        let anchor = Anchor::default();
        let mut journal =
            ProposalJournalV1::create_new(&path, profile.clone(), anchor.clone()).unwrap();
        let initial = fs::read(&path).unwrap();
        journal
            .sign_exact(request(&profile, 1, 0x31), &mut Producer::new(key))
            .unwrap();
        drop(journal);
        let mut bytes = fs::read(&path).unwrap();
        match mutation {
            0 => bytes[HEADER_BYTES + 20] ^= 1,
            1 => {
                bytes.pop();
            }
            2 => bytes = initial,
            _ => anchor.0.lock().unwrap().head = None,
        }
        fs::write(&path, &bytes).unwrap();
        assert!(ProposalJournalV1::open_existing(&path, profile, anchor).is_err());
        assert_eq!(
            fs::read(&path).unwrap(),
            bytes,
            "recovery must not truncate evidence"
        );
    }
}

#[test]
fn proposal_capacity_and_wrong_context_do_not_consume_request_or_anchor() {
    let t = temp();
    let path = t.path().join("proposal.log");
    let (profile, key) = fixture(1);
    let anchor = Anchor::default();
    let mut journal =
        ProposalJournalV1::create_new(&path, profile.clone(), anchor.clone()).unwrap();
    let mut producer = Producer::new(key);
    let before = fs::read(&path).unwrap();
    let mut foreign = profile.clone();
    foreign.signer_profile = [2; 32];
    assert!(matches!(
        journal.sign_exact(request(&foreign, 1, 0x31), &mut producer),
        Err(ProposalJournalErrorV1::InvalidRequest)
    ));
    assert_eq!(producer.calls, 0);
    assert_eq!(fs::read(&path).unwrap(), before);
    journal
        .sign_exact(request(&profile, 1, 0x31), &mut producer)
        .unwrap();
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        journal.sign_exact(request(&profile, 2, 0x32), &mut producer),
        Err(ProposalJournalErrorV1::Capacity)
    ));
    assert_eq!(producer.calls, 1);
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn proposal_namespace_owner_lock_and_endpoint_replacement_are_enforced() {
    let t = temp();
    let path = t.path().join("proposal.log");
    let (profile, key) = fixture(4);
    let anchor = Anchor::default();
    let mut journal =
        ProposalJournalV1::create_new(&path, profile.clone(), anchor.clone()).unwrap();
    assert!(matches!(
        ProposalJournalV1::open_existing(&path, profile.clone(), anchor.clone()),
        Err(ProposalJournalErrorV1::Locked)
    ));
    let backup = t.path().join("renamed.log");
    fs::rename(&path, &backup).unwrap();
    fs::copy(&backup, &path).unwrap();
    assert!(journal
        .sign_exact(request(&profile, 1, 0x31), &mut Producer::new(key))
        .is_err());
    assert!(!journal.is_ready());
    fs::remove_file(&path).unwrap();
    symlink(&backup, &path).unwrap();
    assert!(ProposalJournalV1::open_existing(&path, profile, anchor).is_err());
}

#[test]
fn proposal_exact_codec_roundtrip_and_closed_shape() {
    let (profile, _) = fixture(4);
    let req = request(&profile, 9, 0x31);
    let encoded = encode_request(req);
    assert_eq!(decode_request(&encoded, &profile).unwrap(), req);
    assert!(decode_request(&encoded[..119], &profile).is_err());
    let mut wrong_epoch = encoded;
    wrong_epoch[71] = 1;
    assert!(decode_request(&wrong_epoch, &profile).is_err());
    let mut zero_view = encoded;
    zero_view[72..80].fill(0);
    assert!(decode_request(&zero_view, &profile).is_err());
}

#[test]
fn proposal_wrapper_uses_existing_signature_port_and_retains_conflict_rejection() {
    let t = temp();
    let (profile, key) = fixture(4);
    let journal = ProposalJournalV1::create_new(
        t.path().join("proposal.log"),
        profile.clone(),
        Anchor::default(),
    )
    .unwrap();
    let mut wrapper = JournaledProposalProducerV1::new(journal, Producer::new(key));
    let req = request(&profile, 1, 0x31);
    let signature = wrapper.sign_proposal(req).unwrap();
    assert!(profile.verify_signature(&req, signature));
    assert_eq!(wrapper.sign_proposal(req).unwrap(), signature);
    assert_eq!(
        wrapper.sign_proposal(request(&profile, 1, 0x32)),
        Err(SignatureProducerErrorV0::Rejected)
    );
    assert_eq!(wrapper.producer.calls, 1);
}

// Single-controller file CAS fixture, in a different directory from the log.
// This verifies process-loss ordering only, not independent hardware custody.
struct FileAnchor(PathBuf);
impl ExternalMonotonicWatermarkV0 for FileAnchor {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        let bytes = match fs::read(&self.0) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ExternalWatermarkErrorV0::Unavailable),
        };
        if bytes.len() != 104 || bytes[..32] != scope {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        SignerWatermarkV0::from_persisted_parts(
            scope,
            bytes[32..64].try_into().unwrap(),
            u64::from_be_bytes(bytes[64..72].try_into().unwrap()),
            bytes[72..104].try_into().unwrap(),
        )
        .map(Some)
    }
    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        if self.load(target.scope())? != expected || !successor(expected, target) {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        let mut bytes = Vec::new();
        bytes.extend(target.scope());
        bytes.extend(target.journal_id());
        bytes.extend(target.sequence().to_be_bytes());
        bytes.extend(target.chain_checksum());
        let temporary = self.0.with_extension("next");
        let mut f = File::create(&temporary).map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        f.write_all(&bytes)
            .and_then(|()| f.sync_all())
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        fs::rename(temporary, &self.0).map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        File::open(self.0.parent().unwrap())
            .and_then(|f| f.sync_all())
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)
    }
}

#[test]
fn proposal_journal_process_cut_child() {
    let Ok(root) = std::env::var("TRNM_PJ_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let (profile, key) = fixture(4);
    let req = request(&profile, 1, 0x31);
    let mut journal = ProposalJournalV1::create_new(
        root.join("local/proposal.log"),
        profile,
        FileAnchor(root.join("external/head")),
    )
    .unwrap();
    let sequence = std::env::var("TRNM_PJ_TEST_SEQUENCE")
        .unwrap()
        .parse()
        .unwrap();
    let stage = match std::env::var("TRNM_PJ_TEST_STAGE").unwrap().as_str() {
        "sync" => "sync",
        "anchor" => "anchor",
        "custody" => "custody",
        _ => panic!("unknown test cut"),
    };
    journal.fault = Some((sequence, stage));
    journal.fault_exit = true;
    let _ = journal.sign_exact(req, &mut Producer::new(key));
    panic!("specified child cut did not terminate");
}

#[test]
fn proposal_five_process_exit_cuts_recover_one_exact_decision() {
    for (sequence, stage) in [
        (1, "sync"),
        (1, "anchor"),
        (1, "custody"),
        (2, "sync"),
        (2, "anchor"),
    ] {
        let t = temp();
        fs::create_dir(t.path().join("local")).unwrap();
        fs::create_dir(t.path().join("external")).unwrap();
        fs::set_permissions(t.path().join("local"), fs::Permissions::from_mode(0o700)).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "proposal_journal_v1::tests::proposal_journal_process_cut_child",
                "--nocapture",
            ])
            .env("TRNM_PJ_TEST_ROOT", t.path())
            .env("TRNM_PJ_TEST_SEQUENCE", sequence.to_string())
            .env("TRNM_PJ_TEST_STAGE", stage)
            .status()
            .unwrap();
        assert_eq!(child.code(), Some(73));
        let (profile, key) = fixture(4);
        let req = request(&profile, 1, 0x31);
        let mut journal = ProposalJournalV1::open_existing(
            t.path().join("local/proposal.log"),
            profile.clone(),
            FileAnchor(t.path().join("external/head")),
        )
        .unwrap();
        let mut producer = Producer::new(key);
        let signature = journal.sign_exact(req, &mut producer).unwrap();
        assert!(profile.verify_signature(&req, signature));
        assert_eq!(journal.sign_exact(req, &mut producer).unwrap(), signature);
        assert_eq!(producer.calls, usize::from(sequence == 1));
        assert!(matches!(
            journal.sign_exact(request(&profile, 1, 0x32), &mut producer),
            Err(ProposalJournalErrorV1::Conflict)
        ));
        assert_eq!(
            fs::metadata(t.path().join("local/proposal.log"))
                .unwrap()
                .len() as usize,
            HEADER_BYTES + 2 * RECORD_BYTES
        );
    }
}

#[test]
fn proposal_journal_does_not_invent_a_cross_view_height_validity_rule() {
    let t = temp();
    let path = t.path().join("proposal.log");
    let (profile, key) = fixture(3);
    let anchor = Anchor::default();
    let mut producer = Producer::new(key);
    let mut journal =
        ProposalJournalV1::create_new(&path, profile.clone(), anchor.clone()).unwrap();
    let first = request(&profile, 10, 0x51);
    journal.sign_exact(first, &mut producer).unwrap();
    let ordinary = request(&profile, 11, 0x52);
    // Fork choice and authenticated parent validity belong to Core. A later
    // view may choose a different-height parent; this journal only binds the
    // complete request and forbids equivocation at the same view.
    let rebased = ProposalSignatureRequestV0::new(
        ordinary.proposal_id(),
        ordinary.parent_id(),
        ordinary.validator_set_id(),
        ordinary.author(),
        ordinary.epoch(),
        ordinary.view(),
        Height::new(4),
        ordinary.signing_root(),
        ordinary.expected_consensus_public_key(),
        ordinary.signer_profile_ref(),
    )
    .unwrap();
    let signature = journal.sign_exact(rebased, &mut producer).unwrap();
    drop(journal);
    let mut reopened = ProposalJournalV1::open_existing(&path, profile, anchor).unwrap();
    assert_eq!(
        reopened.sign_exact(rebased, &mut producer).unwrap(),
        signature
    );
    assert!(matches!(
        reopened.sign_exact(ordinary, &mut producer),
        Err(ProposalJournalErrorV1::Conflict)
    ));
    assert_eq!(producer.calls, 2);
}
