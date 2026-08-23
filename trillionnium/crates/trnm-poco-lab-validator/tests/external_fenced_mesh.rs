//! Cross-process proof that the Unix lease daemon is the authority consumed by
//! the authenticated mesh worker/generation paths.
//!
//! This is transport evidence only.  It does not start Core, a signer, or a
//! validator loop, and therefore cannot be used as a seven-node run claim.

use std::{
    collections::BTreeMap,
    net::{SocketAddr, TcpListener},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use tempfile::TempDir;
use trnm_consensus_types::{
    ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
    Validator, ValidatorId, ValidatorSet, VotingPower,
};
use trnm_poco_lab_validator::{
    consensus_mesh::{MeshFixtureConfigV1, PersistentAuthenticatedPeerMeshV0},
    key_roles::{ValidatorKeyRoleBindingV1, ValidatorKeyRoleRegistryV1},
    p2p_admission::UnixExternalPeerLeaseAuthorityV1,
    transport::RunTransportContext,
};

fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("allocate fixture port");
    listener.local_addr().expect("read fixture port")
}

fn fixture_configs() -> (MeshFixtureConfigV1, MeshFixtureConfigV1) {
    let a_p2p = SigningKey::from_bytes(&[0x61; 32]);
    let b_p2p = SigningKey::from_bytes(&[0x62; 32]);
    let a_consensus = SigningKey::from_bytes(&[0x31; 32]);
    let b_consensus = SigningKey::from_bytes(&[0x32; 32]);
    let a_operator = SigningKey::from_bytes(&[0x41; 32]);
    let b_operator = SigningKey::from_bytes(&[0x42; 32]);
    let a = ValidatorId::new([0x71; 32]);
    let b = ValidatorId::new([0x72; 32]);
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let set = ValidatorSet::new(
        GenesisHash::new([0x73; 32]),
        ChainId::new("trnm-poco-g3-fenced-mesh-test").unwrap(),
        ProtocolVersion::V0,
        Epoch::new(0),
        parameters.hash(),
        vec![
            Validator::new(
                a,
                ConsensusPublicKey::new(a_consensus.verifying_key().to_bytes()),
                VotingPower::new(1).unwrap(),
            )
            .unwrap(),
            Validator::new(
                b,
                ConsensusPublicKey::new(b_consensus.verifying_key().to_bytes()),
                VotingPower::new(1).unwrap(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let roles = ValidatorKeyRoleRegistryV1::new(
        &set,
        vec![
            ValidatorKeyRoleBindingV1::new(
                a,
                a_consensus.verifying_key().to_bytes(),
                a_p2p.verifying_key().to_bytes(),
                a_operator.verifying_key().to_bytes(),
            )
            .unwrap(),
            ValidatorKeyRoleBindingV1::new(
                b,
                b_consensus.verifying_key().to_bytes(),
                b_p2p.verifying_key().to_bytes(),
                b_operator.verifying_key().to_bytes(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let a_addr = free_addr();
    let b_addr = free_addr();
    let context = RunTransportContext::new([0x74; 32], [0x75; 32], [0x76; 32], [0x77; 32])
        .with_validator_set_binding(set.epoch().get(), set.id().into_bytes());
    let mut a_out = BTreeMap::new();
    a_out.insert(b, b_addr);
    let mut a_in = BTreeMap::new();
    a_in.insert(b, b_addr);
    let mut b_out = BTreeMap::new();
    b_out.insert(a, a_addr);
    let mut b_in = BTreeMap::new();
    b_in.insert(a, a_addr);
    (
        MeshFixtureConfigV1::new(
            "poco-g3-2-fenced-mesh-cross-process",
            a,
            a_p2p,
            set.clone(),
            roles.clone(),
            context,
            a_addr,
            a_out,
            a_in,
        )
        .unwrap(),
        MeshFixtureConfigV1::new(
            "poco-g3-2-fenced-mesh-cross-process",
            b,
            b_p2p,
            set,
            roles,
            context,
            b_addr,
            b_out,
            b_in,
        )
        .unwrap(),
    )
}

fn start_daemon(root: &TempDir) -> (Child, std::path::PathBuf) {
    let socket = root.path().join("peer-lease.sock");
    let journal = root.path().join("peer-lease.journal");
    let ready = root.path().join("peer-lease.ready");
    let daemon_binary = std::env::var_os("CARGO_BIN_EXE_trnm_poco_lab_peer_lease_daemon")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let mut path = std::env::current_exe().expect("locate integration test binary");
            path.pop(); // deps/
            path.pop(); // debug/
            path.push("trnm-poco-lab-peer-lease-daemon");
            path
        });
    let child = Command::new(daemon_binary)
        .arg("--socket")
        .arg(&socket)
        .arg("--journal")
        .arg(&journal)
        .arg("--ready-file")
        .arg(&ready)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn external peer-lease daemon");
    let deadline = Instant::now() + Duration::from_secs(3);
    while !ready.exists() {
        assert!(
            Instant::now() < deadline,
            "peer-lease daemon did not become ready"
        );
        thread::sleep(Duration::from_millis(10));
    }
    (child, socket)
}

#[test]
fn unix_daemon_fences_real_mesh_workers_and_frames_across_process_boundary() {
    let root = TempDir::new().unwrap();
    let (mut daemon, socket) = start_daemon(&root);
    let (a_config, b_config) = fixture_configs();
    let a_socket = socket.clone();
    let b_socket = socket.clone();
    let a_thread = thread::spawn(move || {
        PersistentAuthenticatedPeerMeshV0::establish_fixture_with_fence_v1(
            &a_config,
            Duration::from_secs(5),
            Duration::from_millis(500),
            8,
            Arc::new(UnixExternalPeerLeaseAuthorityV1::connect(a_socket)),
        )
        .expect("establish A behind external daemon")
    });
    let b_thread = thread::spawn(move || {
        PersistentAuthenticatedPeerMeshV0::establish_fixture_with_fence_v1(
            &b_config,
            Duration::from_secs(5),
            Duration::from_millis(500),
            8,
            Arc::new(UnixExternalPeerLeaseAuthorityV1::connect(b_socket)),
        )
        .expect("establish B behind external daemon")
    });
    let a_mesh = a_thread.join().unwrap();
    let b_mesh = b_thread.join().unwrap();
    assert_eq!(a_mesh.initial_sessions().len(), 2);
    assert_eq!(b_mesh.initial_sessions().len(), 2);
    a_mesh.ensure_healthy().unwrap();
    b_mesh.ensure_healthy().unwrap();
    a_mesh
        .send_to(
            ValidatorId::new([0x72; 32]),
            trnm_poco_lab_validator::frame::FrameKind::Vote,
            vec![0xa5, 0x5a],
        )
        .unwrap();
    let b_mesh = b_mesh;
    let mut received = false;
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Some(trnm_poco_lab_validator::consensus_mesh::MeshIngressEventV0::Frame(frame)) =
            b_mesh.receive_timeout(Duration::from_millis(100)).unwrap()
        {
            assert_eq!(frame.remote(), ValidatorId::new([0x71; 32]));
            assert_eq!(frame.into_frame().payload, vec![0xa5, 0x5a]);
            received = true;
            break;
        }
    }
    assert!(received, "fenced mesh did not deliver authenticated frame");
    b_mesh.close().unwrap();
    a_mesh.close().unwrap();
    daemon.kill().unwrap();
    daemon.wait().unwrap();
}
