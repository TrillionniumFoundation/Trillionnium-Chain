//! Process-boundary evidence for the durable checkpoint/restart slice.
//!
//! The unit tests exercise the store in one process.  This integration test
//! deliberately commits from a child and aborts that process immediately
//! after `commit` returns.  The parent then reopens the same namespace and
//! re-verifies the retained QC.  It proves the documented durable-boundary
//! contract without claiming Core/SafetyRules or validator activation.

use std::{
    env,
    process::{Command, Stdio},
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use tempfile::tempdir;
use trnm_consensus_types::{
    BlockId, ChainId, ConsensusParametersHash, ConsensusPublicKey, Epoch, Height, ProtocolVersion,
    QuorumCertificate, SignatureBytes, SignatureVerifier, Validator, ValidatorId, ValidatorSet,
    View, Vote, VotingPower,
};
use trnm_core_restart_v0::{
    CheckpointCandidateV0, CheckpointCommitOutcomeV0, CheckpointStoreV0, RestartDispositionV0,
};
use trnm_native_application::{
    ApplicationCommitIdV0, ApplicationHeadV0, BlockIdV0, HeightV0, StateRootV0,
};

const CHILD_ENV: &str = "TRNM_CORE_RESTART_PROCESS_CRASH_CHILD_V0";
const DIRECTORY_ENV: &str = "TRNM_CORE_RESTART_PROCESS_CRASH_DIRECTORY_V0";

struct StrictTestVerifier;

impl SignatureVerifier for StrictTestVerifier {
    fn verify(
        &self,
        validator: &Validator,
        root: &trnm_consensus_types::SigningRoot,
        signature: &SignatureBytes,
    ) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(validator.consensus_key().as_bytes()) else {
            return false;
        };
        key.verify_strict(
            root.as_bytes(),
            &Signature::from_bytes(signature.as_bytes()),
        )
        .is_ok()
    }
}

fn fixture() -> (ValidatorSet, QuorumCertificate, ApplicationHeadV0) {
    let genesis = trnm_consensus_types::GenesisHash::new([7; 32]);
    let chain = ChainId::new("restart-process-test").expect("chain");
    let params_hash = ConsensusParametersHash::new([8; 32]);
    let mut keys = Vec::new();
    let mut validators = Vec::new();
    for index in 0..4u8 {
        let signing = SigningKey::from_bytes(&[index + 1; 32]);
        let key = signing.verifying_key();
        let id = ValidatorId::new([index + 1; 32]);
        keys.push(signing);
        validators.push(
            Validator::new(
                id,
                ConsensusPublicKey::new(key.to_bytes()),
                VotingPower::new(1).expect("power"),
            )
            .expect("validator"),
        );
    }
    validators.sort_by_key(Validator::id);
    let set = ValidatorSet::new(
        genesis,
        chain,
        ProtocolVersion::V0,
        Epoch::new(0),
        params_hash,
        validators,
    )
    .expect("set");
    let block_id = BlockId::new([9; 32]);
    let height = Height::new(4);
    let view = View::new(1);
    let root = Vote::signing_root_for_set(&set, view, height, block_id).expect("root");
    let mut votes = Vec::new();
    for (index, signing) in keys[..3].iter().enumerate() {
        let id = ValidatorId::new([index as u8 + 1; 32]);
        let signature = SignatureBytes::from_array(signing.sign(root.as_bytes()).to_bytes());
        votes.push(
            Vote::new(
                chain,
                ProtocolVersion::V0,
                Epoch::new(0),
                view,
                height,
                block_id,
                set.id(),
                id,
                signature,
                &set,
            )
            .expect("vote"),
        );
    }
    votes.sort_by_key(Vote::author);
    let qc = QuorumCertificate::new(
        chain,
        ProtocolVersion::V0,
        Epoch::new(0),
        view,
        height,
        block_id,
        set.id(),
        votes,
        &set,
    )
    .expect("QC");
    let head = ApplicationHeadV0::new(
        HeightV0::new(4),
        BlockIdV0::new([9; 32]).expect("block"),
        StateRootV0::new([10; 32]).expect("root"),
        ApplicationCommitIdV0::new([11; 32]).expect("commit"),
    );
    (set, qc, head)
}

#[test]
fn checkpoint_commit_survives_child_abort_and_reopen() {
    if env::var_os(CHILD_ENV).is_some() {
        let directory = env::var_os(DIRECTORY_ENV).expect("child directory");
        let (set, qc, head) = fixture();
        let candidate = CheckpointCandidateV0::admit_quorum_certificate(
            &qc,
            &set,
            &StrictTestVerifier,
            &head,
            b"process-crash-state-v0".to_vec(),
        )
        .expect("child admits QC");
        let mut store = CheckpointStoreV0::open(directory).expect("child opens store");
        assert_eq!(
            store
                .commit(&candidate, None)
                .expect("child commits checkpoint"),
            CheckpointCommitOutcomeV0::Committed
        );
        // Simulate kill -9 immediately after the durable boundary.  The
        // parent must recover from the append-only record and synced snapshot.
        std::process::abort();
    }

    let directory = tempdir().expect("directory");
    let status = Command::new(env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("checkpoint_commit_survives_child_abort_and_reopen")
        .arg("--nocapture")
        .env(CHILD_ENV, "1")
        .env(DIRECTORY_ENV, directory.path())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("spawn child checkpoint writer");
    assert!(!status.success(), "child must terminate by abort");

    let (set, qc, _head) = fixture();
    let reopened = CheckpointStoreV0::open(directory.path()).expect("reopen after child abort");
    let RestartDispositionV0::Ready(record) =
        reopened.restart_disposition().expect("restart disposition")
    else {
        panic!("durable child checkpoint was not ready");
    };
    assert_eq!(record.height(), 4);
    assert_eq!(record.epoch(), 0);
    reopened
        .verify_current_quorum_certificate(&qc, &set, &StrictTestVerifier)
        .expect("re-verify retained QC after process crash");
}
