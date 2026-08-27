//! Cross-process proof that the Unix lease daemon is the authority consumed by
//! the authenticated mesh worker/generation paths.
//!
//! This is transport evidence only.  It does not start Core, a signer, or a
//! validator loop, and therefore cannot be used as a seven-node run claim.

use std::{
    collections::BTreeMap,
    net::{SocketAddr, TcpListener},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::{Signer, SigningKey};
use tempfile::TempDir;
use trnm_consensus_types::{
    BlockId, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, Height,
    ProtocolVersion, SignatureBytes, Validator, ValidatorId, ValidatorSet, View, Vote, VotingPower,
};
use trnm_poco_lab_validator::{
    collector::decode_authenticated_consensus_frame_v0,
    consensus_mesh::{MeshFixtureConfigV1, PersistentAuthenticatedPeerMeshV0},
    frame::FrameKind,
    key_roles::{ValidatorKeyRoleBindingV1, ValidatorKeyRoleRegistryV1},
    p2p_admission::{
        ExternalFenceError, ExternalPeerDirectionV1, ExternalPeerLeaseAuthorityV1,
        ExternalPeerLeaseRequestV1, ExternalPeerLeaseScopeV1, UnixExternalPeerLeaseAuthorityV1,
    },
    payload_replay::PayloadReplayStoreV1,
    transport::RunTransportContext,
    wire::encode_vote,
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

fn stop_daemon(child: &mut Child) {
    if child.try_wait().expect("poll peer-lease daemon").is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn establish_pair(
    socket: &Path,
    a_config: MeshFixtureConfigV1,
    b_config: MeshFixtureConfigV1,
    fence_ttl: Duration,
) -> (
    PersistentAuthenticatedPeerMeshV0,
    PersistentAuthenticatedPeerMeshV0,
) {
    let a_socket = socket.to_path_buf();
    let b_socket = socket.to_path_buf();
    let a_thread = thread::spawn(move || {
        PersistentAuthenticatedPeerMeshV0::establish_fixture_with_fence_ttl_v1(
            &a_config,
            Duration::from_secs(5),
            Duration::from_millis(500),
            8,
            fence_ttl,
            Arc::new(UnixExternalPeerLeaseAuthorityV1::connect(a_socket)),
        )
        .expect("establish A behind external daemon")
    });
    let b_thread = thread::spawn(move || {
        PersistentAuthenticatedPeerMeshV0::establish_fixture_with_fence_ttl_v1(
            &b_config,
            Duration::from_secs(5),
            Duration::from_millis(500),
            8,
            fence_ttl,
            Arc::new(UnixExternalPeerLeaseAuthorityV1::connect(b_socket)),
        )
        .expect("establish B behind external daemon")
    });
    (a_thread.join().unwrap(), b_thread.join().unwrap())
}

#[test]
fn unix_daemon_fences_real_mesh_workers_and_frames_across_process_boundary() {
    let root = TempDir::new().unwrap();
    // The replay authority intentionally requires a private parent.  Make
    // the harness root explicit rather than inheriting a platform/umask
    // dependent tempfile mode.
    #[cfg(unix)]
    {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let (mut daemon, socket) = start_daemon(&root);
    let (a_config, b_config) = fixture_configs();
    let replay_namespace = b_config
        .payload_replay_namespace_v1()
        .expect("payload replay namespace");
    let replay = Mutex::new(
        PayloadReplayStoreV1::open(root.path().join("b-payload-replay.wal"), replay_namespace)
            .expect("payload replay WAL"),
    );
    let b_run_id = b_config.run_id_v1().to_owned();
    let transport_validator_set = a_config.validator_set_v1().clone();
    let consensus_parameters = ConsensusParametersV0::reference_shadow_v0();
    let admission_context = a_config.admission_context_v1();
    let (a_mesh, b_mesh) = establish_pair(&socket, a_config, b_config, Duration::from_secs(1));
    assert_eq!(a_mesh.initial_sessions().len(), 2);
    assert_eq!(b_mesh.initial_sessions().len(), 2);
    // No health call or consensus frame occurs during this interval.  The
    // mesh-level supervisor (and idle receive/send polls) must renew every
    // directed lease before the one-second authority TTL expires.
    thread::sleep(Duration::from_millis(1_300));
    a_mesh.ensure_healthy().unwrap();
    b_mesh.ensure_healthy().unwrap();
    // Carry a real, strictly signed PoCO Vote through the authenticated
    // cross-process mesh.  This is deliberately one statement (not a QC and
    // not a validator loop), but it proves the transport does not stop at an
    // arbitrary health/test payload: wire decoding and Ed25519 admission run
    // on the receiving side with the frozen validator-set context.
    let a_consensus = SigningKey::from_bytes(&[0x31; 32]);
    let vote_block = BlockId::new([0x91; 32]);
    let vote_view = View::new(1);
    let vote_height = Height::new(1);
    let vote_root =
        Vote::signing_root_for_set(&transport_validator_set, vote_view, vote_height, vote_block)
            .unwrap();
    let a_id = ValidatorId::new([0x71; 32]);
    let vote = Vote::new(
        transport_validator_set.chain_id(),
        transport_validator_set.protocol_version(),
        transport_validator_set.epoch(),
        vote_view,
        vote_height,
        vote_block,
        transport_validator_set.id(),
        a_id,
        SignatureBytes::from_array(a_consensus.sign(vote_root.as_bytes()).to_bytes()),
        &transport_validator_set,
    )
    .unwrap();
    a_mesh
        .send_to(
            ValidatorId::new([0x72; 32]),
            FrameKind::Vote,
            encode_vote(&vote),
        )
        .unwrap();
    let b_mesh = b_mesh;
    let mut received = false;
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Some(trnm_poco_lab_validator::consensus_mesh::MeshIngressEventV0::Frame(frame)) =
            b_mesh
                .receive_timeout_with_payload_replay_v1(
                    Duration::from_millis(100),
                    &replay,
                    &b_run_id,
                )
                .unwrap()
        {
            assert_eq!(frame.remote(), ValidatorId::new([0x71; 32]));
            let authenticated = frame.into_frame();
            let decoded = decode_authenticated_consensus_frame_v0(
                &authenticated,
                &transport_validator_set,
                &consensus_parameters,
            )
            .unwrap();
            let trnm_poco_lab_validator::collector::AdmittedConsensusMessageV0::Vote(decoded_vote) =
                decoded
            else {
                panic!("mesh delivered a non-Vote consensus message");
            };
            assert_eq!(decoded_vote, vote);
            received = true;
            break;
        }
    }
    assert!(received, "fenced mesh did not deliver authenticated frame");
    assert_eq!(
        replay.lock().unwrap().accepted_frame_count(),
        1,
        "mesh frame must be durably admitted before exposure"
    );
    let outbound_session = a_mesh
        .initial_sessions()
        .iter()
        .find(|facts| {
            facts.direction() == trnm_poco_lab_validator::consensus_mesh::PeerDirectionV0::Outbound
        })
        .expect("outbound session exists")
        .session_id();
    let close_started = Instant::now();
    b_mesh.close().unwrap();
    a_mesh.close().unwrap();
    assert!(
        close_started.elapsed() < Duration::from_millis(750),
        "idle mesh close exceeded bounded shutdown window"
    );
    // The daemon retains the monotonic generation after both mesh workers
    // release their leases.  Replaying generation one with the old session
    // must be rejected across the process boundary.
    let replay_scope = ExternalPeerLeaseScopeV1::new(
        ValidatorId::new([0x71; 32]),
        ValidatorId::new([0x72; 32]),
        ExternalPeerDirectionV1::Outbound,
        admission_context,
        outbound_session,
        1,
    )
    .unwrap();
    let replay_authority = UnixExternalPeerLeaseAuthorityV1::connect(&socket);
    let replay_error = replay_authority
        .acquire(ExternalPeerLeaseRequestV1::new(replay_scope, Duration::from_secs(1)).unwrap())
        .unwrap_err();
    assert_eq!(replay_error, ExternalFenceError::StaleGeneration);
    stop_daemon(&mut daemon);
}

#[test]
fn idle_mesh_shutdown_is_bounded_independently_of_lease_ttl() {
    let root = TempDir::new().unwrap();
    let (mut daemon, socket) = start_daemon(&root);
    let (a_config, b_config) = fixture_configs();
    let (a_mesh, b_mesh) = establish_pair(&socket, a_config, b_config, Duration::from_secs(30));

    // A 30-second lease has a ten-second renewal cadence.  Closing both
    // meshes must still wake the supervisor promptly instead of joining on
    // that sleep interval.
    let started = Instant::now();
    let a_close = thread::spawn(move || a_mesh.close());
    let b_close = thread::spawn(move || b_mesh.close());
    a_close.join().unwrap().unwrap();
    b_close.join().unwrap().unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(750),
        "mesh shutdown waited on the lease renewal interval"
    );
    stop_daemon(&mut daemon);
}

#[test]
fn idle_external_lease_renewal_failure_terminates_mesh() {
    let root = TempDir::new().unwrap();
    let (mut daemon, socket) = start_daemon(&root);
    let (a_config, b_config) = fixture_configs();
    let (a_mesh, b_mesh) = establish_pair(&socket, a_config, b_config, Duration::from_secs(1));

    // No health call or frame is made after the authority disappears.  The
    // supervisor must observe the failed renewal itself and put both meshes
    // into a terminal fail-closed state.
    stop_daemon(&mut daemon);
    thread::sleep(Duration::from_millis(550));
    let a_error = a_mesh.ensure_healthy().unwrap_err().to_string();
    let b_error = b_mesh.ensure_healthy().unwrap_err().to_string();
    assert!(
        a_error.contains("external fence") && b_error.contains("external fence"),
        "idle renewal failure did not terminate either mesh: A={a_error}; B={b_error}"
    );
    drop(a_mesh);
    drop(b_mesh);
}
