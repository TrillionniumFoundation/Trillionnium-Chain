#![cfg(feature = "external-signer-runtime")]

//! Cross-process composition test for the bounded timeout host.
//!
//! This deliberately uses a shadow four-validator Core and a one-request
//! fixture signer service.  It proves the node's local SafetyStore and
//! journal cross the external Unix watermark and remote signer boundaries;
//! it is not a network, proposal, locked-QC, or production activation test.

use std::{
    fs,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use tempfile::TempDir;
use trnm_consensus_core::CoreConfig;
use trnm_consensus_core::SafetyStateRecordLimitsV0;
use trnm_consensus_external_watermark::UnixWatermarkClient;
use trnm_consensus_remote_signer_protocol::{
    ProcessGenerationV1, RemoteSignerCheckpointWitnessV1, RemoteSignerClientProfileRefV1,
    RemoteSignerLeaseIdV1, RemoteSignerRequestBindingV1, RemoteSignerRoleProfileRefV1,
    RemoteSignerServiceProfileRefV1,
};
use trnm_consensus_remote_signer_service::{
    PurposePolicyV1, RemoteSignerService, RemoteSignerServiceConfig,
};
use trnm_consensus_types::{
    ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, GenesisQcV0,
    ProtocolVersion, Validator, ValidatorId, ValidatorSet, VotingPower,
};
use trnm_poco_node::{
    initialize_unix_external_timeout_host_v0, PocoNodeHostActionV0, PocoNodeStartConfigV0,
    SIGNER_JOURNAL_PROFILE_REF_V0,
};

const RECORD_BYTES: usize = 64 * 1024 * 1024;
const BLOB_BYTES: usize = 16 * 1024 * 1024;
const SAFETY_DATABASE_BYTES: usize = 192 * 1024 * 1024;
const SIGNER_INTENTS: u64 = 64;
const SIGNER_INTENT_BYTES: usize = 4096;
const SIGNER_DATABASE_BYTES: usize = 32 * 1024 * 1024;

struct Fixture {
    keys: Vec<SigningKey>,
    validator_set: ValidatorSet,
    core_config: CoreConfig,
}

impl Fixture {
    fn new() -> Self {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let keys = (1_u8..=4)
            .map(|index| SigningKey::from_bytes(&[index.saturating_add(40); 32]))
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let id = ValidatorId::new([index as u8 + 1; 32]);
                Validator::new(
                    id,
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).expect("positive voting power"),
                )
                .expect("valid fixture validator")
            })
            .collect::<Vec<_>>();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0xa5; 32]),
            ChainId::from_static("trnm-poco-external-runtime"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid fixture validator set");
        let core_config = CoreConfig::new(
            ValidatorId::new([1; 32]),
            validator_set.clone(),
            parameters,
            0,
            32,
            64,
        )
        .expect("valid fixture Core config");
        Self {
            keys,
            validator_set,
            core_config,
        }
    }
}

fn private_child(root: &TempDir, name: &str) -> PathBuf {
    let path = root.path().join(name);
    fs::create_dir(&path).expect("create private namespace");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .expect("protect private namespace");
    path
}

fn wait_for_socket(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.is_socket() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("Unix socket did not become ready: {}", path.display());
}

trait SocketPathExt {
    fn is_socket(&self) -> bool;
}

impl SocketPathExt for Path {
    fn is_socket(&self) -> bool {
        fs::symlink_metadata(self)
            .map(|metadata| metadata.file_type().is_socket())
            .unwrap_or(false)
    }
}

#[test]
fn bounded_timeout_host_crosses_external_watermark_and_remote_signer() {
    let root = TempDir::new().expect("temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("protect temporary root");
    let fixture = Fixture::new();
    let safety_parent = private_child(&root, "safety");
    let signer_parent = private_child(&root, "signer-journal");
    let watermark_parent = private_child(&root, "watermark");
    let watermark_socket = watermark_parent.join("authority.sock");
    let watermark_log = watermark_parent.join("authority.log");
    let remote_parent = private_child(&root, "remote-signer");
    let remote_socket = remote_parent.join("signer.sock");
    let remote_db = remote_parent.join("signer.sqlite3");

    let authority =
        trnm_consensus_external_watermark::ExternalWatermarkAuthority::open(&watermark_log)
            .expect("open external authority");
    let watermark_socket_for_thread = watermark_socket.clone();
    thread::spawn(move || {
        let _ = authority.serve_unix(&watermark_socket_for_thread);
    });
    wait_for_socket(&watermark_socket);

    let local = fixture
        .validator_set
        .validator(ValidatorId::new([1; 32]))
        .unwrap();
    let binding = RemoteSignerRequestBindingV1::new(
        &fixture.validator_set,
        local.id(),
        RemoteSignerRoleProfileRefV1::from_public_descriptor(b"p0-timeout-role")
            .expect("role profile"),
        RemoteSignerServiceProfileRefV1::from_public_descriptor(b"p0-timeout-service")
            .expect("service profile"),
        RemoteSignerClientProfileRefV1::from_public_descriptor(b"p0-timeout-client")
            .expect("client profile"),
        ProcessGenerationV1::new(1).expect("process generation"),
        RemoteSignerLeaseIdV1::from_public_grant_descriptor(b"p0-timeout-lease").expect("lease"),
        RemoteSignerCheckpointWitnessV1::new(1, [0x52; 32]).expect("checkpoint witness"),
    )
    .expect("remote signer binding");
    let service = RemoteSignerService::open(RemoteSignerServiceConfig {
        validator_set: fixture.validator_set.clone(),
        binding,
        signing_key: fixture.keys[0].clone(),
        watermark_path: remote_db,
        purpose_policy: PurposePolicyV1::timeout_vote_only(),
    })
    .expect("open remote signer service");
    let mut service = service;
    let remote_socket_for_thread = remote_socket.clone();
    thread::spawn(move || {
        let _ = service.serve_unix_once(&remote_socket_for_thread);
    });
    wait_for_socket(&remote_socket);

    let node_config = PocoNodeStartConfigV0::new(
        safety_parent.join("safety.sqlite3"),
        signer_parent.join("signer.sqlite3"),
        fixture.core_config.clone(),
        SafetyStateRecordLimitsV0::new(RECORD_BYTES, BLOB_BYTES).expect("record limits"),
        SAFETY_DATABASE_BYTES,
        SIGNER_INTENTS,
        SIGNER_INTENT_BYTES,
        SIGNER_DATABASE_BYTES,
    )
    .expect("node start config");
    let genesis_qc = GenesisQcV0::new(
        fixture.validator_set.genesis_hash(),
        fixture.validator_set.chain_id(),
        &fixture.validator_set,
    )
    .expect("genesis QC");
    let signer = trnm_consensus_unix_remote_signer::UnixRemoteSignerProducer::new(
        trnm_consensus_unix_remote_signer::UnixRemoteSignerProducerConfig {
            socket_path: remote_socket,
            validator_set: fixture.validator_set.clone(),
            author: local.id(),
            signer_profile_ref: SIGNER_JOURNAL_PROFILE_REF_V0,
            role_profile_ref: binding.role_profile_ref(),
            service_profile_ref: binding.service_profile_ref(),
            client_profile_ref: binding.client_profile_ref(),
            process_generation: binding.process_generation(),
            lease_id: binding.lease_id(),
            checkpoint_witness: binding.checkpoint_witness(),
            timeout: Duration::from_secs(2),
        },
    )
    .expect("remote signer client");
    let watermark = UnixWatermarkClient::new(watermark_socket.clone()).expect("watermark client");
    let mut host =
        initialize_unix_external_timeout_host_v0(node_config, genesis_qc, watermark, signer)
            .expect("initialize externally fenced timeout host");

    let actions = host
        .on_local_timeout_v0()
        .expect("remote timeout signature and Core broadcast");
    assert!(actions
        .iter()
        .any(|action| matches!(action, PocoNodeHostActionV0::Broadcast(_))));
    assert!(
        host.signer_journal_head()
            .expect("read external head")
            .sequence()
            > 0
    );
    assert!(host.production_activation_check().is_err());

    // Reopen both durable namespaces through fresh Unix clients.  This is the
    // restart half of the seam: the node must observe the exact external
    // watermark and the service must authenticate its existing SQLite
    // reservation namespace before a second host can be constructed.
    drop(host);
    let service_again = RemoteSignerService::open(RemoteSignerServiceConfig {
        validator_set: fixture.validator_set.clone(),
        binding,
        signing_key: fixture.keys[0].clone(),
        watermark_path: remote_parent.join("signer.sqlite3"),
        purpose_policy: PurposePolicyV1::timeout_vote_only(),
    })
    .expect("reopen remote signer service namespace");
    let mut service_again = service_again;
    let remote_socket_again = remote_parent.join("signer-reopen.sock");
    let remote_socket_again_for_thread = remote_socket_again.clone();
    thread::spawn(move || {
        let _ = service_again.serve_unix_once(&remote_socket_again_for_thread);
    });
    wait_for_socket(&remote_socket_again);
    let node_config_again = PocoNodeStartConfigV0::new(
        safety_parent.join("safety.sqlite3"),
        signer_parent.join("signer.sqlite3"),
        fixture.core_config.clone(),
        SafetyStateRecordLimitsV0::new(RECORD_BYTES, BLOB_BYTES).expect("record limits again"),
        SAFETY_DATABASE_BYTES,
        SIGNER_INTENTS,
        SIGNER_INTENT_BYTES,
        SIGNER_DATABASE_BYTES,
    )
    .expect("reopen node start config");
    let signer_again = trnm_consensus_unix_remote_signer::UnixRemoteSignerProducer::new(
        trnm_consensus_unix_remote_signer::UnixRemoteSignerProducerConfig {
            socket_path: remote_socket_again,
            validator_set: fixture.validator_set.clone(),
            author: local.id(),
            signer_profile_ref: SIGNER_JOURNAL_PROFILE_REF_V0,
            role_profile_ref: binding.role_profile_ref(),
            service_profile_ref: binding.service_profile_ref(),
            client_profile_ref: binding.client_profile_ref(),
            process_generation: binding.process_generation(),
            lease_id: binding.lease_id(),
            checkpoint_witness: binding.checkpoint_witness(),
            timeout: Duration::from_secs(2),
        },
    )
    .expect("reopen remote signer client");
    let watermark_again =
        UnixWatermarkClient::new(watermark_socket).expect("reopen watermark client");
    let mut reopened = trnm_poco_node::open_unix_external_timeout_host_v0(
        node_config_again,
        watermark_again,
        signer_again,
    )
    .expect("reopen externally fenced timeout host");
    assert!(
        reopened
            .signer_journal_head()
            .expect("read reopened external head")
            .sequence()
            > 0
    );
    assert!(reopened.production_activation_check().is_err());

    // Keep this assertion explicit: this composition does not silently turn
    // the bounded timeout seam into a proposal/QC/production runtime.
    assert!(!trnm_poco_node::PRODUCTION_CANDIDATE_V0);
}
