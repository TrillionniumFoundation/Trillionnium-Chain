//! Bounded timeout-only bridge evidence.
//!
//! This test deliberately exercises the real external watermark daemon and
//! response hash-chain, but it does not claim Core/SafetyRules authority or a
//! production signer. Vote requests remain fail-closed.

use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::Duration,
};

use tempfile::TempDir;
use trnm_consensus_external_watermark::{
    ExternalWatermarkAuthorityError, ExternalWatermarkSemanticBindingV1, UnixWatermarkClient,
};
use trnm_consensus_remote_signer_protocol::decode_unverified_remote_signer_response_v1_exact;
use trnm_consensus_remote_signer_service::{
    fixture_request, fixture_service_config, ExternalAuthorityAdapterV1, Fixture, PurposePolicyV1,
    RemoteSignerService, UnixExternalTimeoutAuthorityV1,
};

const CAPABILITY: [u8; 32] = [0x33; 32];

struct AuthorityProcess {
    child: Child,
    socket: PathBuf,
    log: PathBuf,
    binding: trnm_consensus_remote_signer_protocol::RemoteSignerRequestBindingV1,
}

impl AuthorityProcess {
    fn binary() -> PathBuf {
        if let Ok(path) = env::var("CARGO_BIN_EXE_trnm-external-watermark-v0") {
            return PathBuf::from(path);
        }
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/trnm-external-watermark-v0")
    }

    fn start(
        root: &Path,
        binding: trnm_consensus_remote_signer_protocol::RemoteSignerRequestBindingV1,
    ) -> Self {
        let socket = root.join("authority.sock");
        let log = root.join("authority.log");
        let scope = UnixExternalTimeoutAuthorityV1::scope_for_binding(binding);
        let journal = UnixExternalTimeoutAuthorityV1::journal_id_for_binding(binding);
        let child = Command::new(Self::binary())
            .args([
                "semantic",
                "--socket",
                socket.to_str().expect("authority socket path"),
                "--log",
                log.to_str().expect("authority log path"),
                "--scope",
                &hex32(scope),
                "--journal-id",
                &hex32(journal),
                "--capability",
                &hex32(CAPABILITY),
            ])
            .spawn()
            .expect("spawn external watermark daemon");
        let process = Self {
            child,
            socket,
            log,
            binding,
        };
        let client = UnixWatermarkClient::new(&process.socket).expect("authority client");
        let semantic_binding = ExternalWatermarkSemanticBindingV1::new(scope, journal, CAPABILITY)
            .expect("semantic authority binding");
        for _ in 0..100 {
            match client.load_semantic_checked(semantic_binding) {
                Err(ExternalWatermarkAuthorityError::Io { .. })
                | Err(ExternalWatermarkAuthorityError::Unavailable) => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) | Ok(Some(_)) => return process,
                other => panic!("authority startup probe unexpected: {other:?}"),
            }
        }
        panic!("timed out waiting for external watermark daemon");
    }

    fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let replacement = Self::start(
            self.socket.parent().expect("authority parent"),
            self.binding,
        );
        self.child = replacement.child;
        self.socket = replacement.socket;
        self.log = replacement.log;
        self.binding = replacement.binding;
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn hex32(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn timeout_bridge_orders_cas_sign_bind_and_replays_after_daemon_restart() {
    let root = TempDir::new().expect("temporary bridge root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = Fixture::new();
    let mut authority = AuthorityProcess::start(root.path(), fixture.binding);
    let local_db = root.path().join("local.sqlite3");
    let mut service = RemoteSignerService::open(fixture_service_config(
        &local_db,
        PurposePolicyV1::timeout_vote_only(),
    ))
    .expect("open fixture service");
    let request_value =
        fixture_request(&fixture, "timeout", 3, b"external-adapter").expect("timeout request");
    let request = request_value.try_exact_bytes().expect("encode request");
    let response_log = root.path().join("responses.log");
    let mut adapter = UnixExternalTimeoutAuthorityV1::from_binding(
        fixture.binding,
        &authority.socket,
        &response_log,
    )
    .expect("open external adapter")
    .with_capability(CAPABILITY);
    let first = service
        .process_request_with_external_authority_v1(&request, &mut adapter)
        .expect("external timeout request");
    decode_unverified_remote_signer_response_v1_exact(&first, &request_value)
        .expect("response envelope binds exact request");
    let replay = service
        .process_request_with_external_authority_v1(&request, &mut adapter)
        .expect("exact response replay");
    assert_eq!(replay, first, "replay must return the exact response bytes");
    let lower_same_process = fixture_request(&fixture, "timeout", 2, b"lower-same-process")
        .unwrap()
        .try_exact_bytes()
        .unwrap();
    assert!(service
        .process_request_with_external_authority_v1(&lower_same_process, &mut adapter)
        .expect_err("semantic rollback must fail closed")
        .is_external_authority_required());
    let client = UnixWatermarkClient::new(&authority.socket).unwrap();
    let semantic_binding =
        ExternalWatermarkSemanticBindingV1::new(adapter.scope(), adapter.journal_id(), CAPABILITY)
            .expect("semantic adapter binding");
    assert!(
        client.load_checked(adapter.scope()).is_err(),
        "semantic authority must reject the opaque load wire path"
    );
    assert_eq!(
        client
            .load_semantic_checked(semantic_binding)
            .unwrap()
            .unwrap()
            .0
            .sequence(),
        0
    );
    drop(adapter);

    let mut wrong_capability = UnixExternalTimeoutAuthorityV1::from_binding(
        fixture.binding,
        &authority.socket,
        &response_log,
    )
    .expect("reopen adapter with wrong capability")
    .with_capability([0x44; 32]);
    assert!(
        service
            .process_request_with_external_authority_v1(&request, &mut wrong_capability)
            .is_err(),
        "exact replay must not bypass immutable capability binding"
    );
    drop(wrong_capability);

    authority.stop();
    authority.restart();
    let mut reopened = UnixExternalTimeoutAuthorityV1::from_binding(
        fixture.binding,
        &authority.socket,
        &response_log,
    )
    .expect("reopen external adapter after daemon restart")
    .with_capability(CAPABILITY);
    let replay_after_restart = service
        .process_request_with_external_authority_v1(&request, &mut reopened)
        .expect("replay after authority restart");
    assert_eq!(replay_after_restart, first);

    let lower = fixture_request(&fixture, "timeout", 2, b"lower-after-restart")
        .unwrap()
        .try_exact_bytes()
        .unwrap();
    assert!(service
        .process_request_with_external_authority_v1(&lower, &mut reopened)
        .expect_err("new semantic request after restart must fail closed")
        .is_external_authority_required());

    let higher_value = fixture_request(&fixture, "timeout", 5, b"higher-after-restart")
        .expect("higher timeout request");
    let higher = higher_value
        .try_exact_bytes()
        .expect("encode higher request");
    let higher_response = service
        .process_request_with_external_authority_v1(&higher, &mut reopened)
        .expect("external authority must enforce semantic order, not local process memory");
    decode_unverified_remote_signer_response_v1_exact(&higher_response, &higher_value)
        .expect("higher response binds exact request");

    // Restoring the external log behind its durable head is a hard startup
    // failure; no adapter may silently reconstruct a watermark from SQLite.
    authority.stop();
    let bytes = fs::read(&authority.log).expect("read authority log");
    fs::write(&authority.log, &bytes[..bytes.len() - 1]).expect("truncate authority log");
    let failed = Command::new(AuthorityProcess::binary())
        .args([
            "semantic",
            "--socket",
            authority.socket.to_str().unwrap(),
            "--log",
            authority.log.to_str().unwrap(),
            "--scope",
            &hex32(UnixExternalTimeoutAuthorityV1::scope_for_binding(
                fixture.binding,
            )),
            "--journal-id",
            &hex32(UnixExternalTimeoutAuthorityV1::journal_id_for_binding(
                fixture.binding,
            )),
            "--capability",
            &hex32(CAPABILITY),
        ])
        .output()
        .expect("spawn tampered authority");
    assert!(!failed.status.success(), "rollback must fail closed");
}

#[test]
fn timeout_bridge_rejects_vote_and_ambiguous_reservation() {
    let root = TempDir::new().expect("temporary bridge root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = Fixture::new();
    let mut authority = AuthorityProcess::start(root.path(), fixture.binding);
    let local_db = root.path().join("local.sqlite3");
    let mut service =
        RemoteSignerService::open(fixture_service_config(&local_db, PurposePolicyV1::both()))
            .expect("open fixture service");
    let socket = authority.socket.clone();
    let response_log = root.path().join("responses.log");
    let mut adapter =
        UnixExternalTimeoutAuthorityV1::from_binding(fixture.binding, &socket, &response_log)
            .unwrap()
            .with_capability(CAPABILITY);
    let vote = fixture_request(&fixture, "vote", 3, b"vote-disabled")
        .unwrap()
        .try_exact_bytes()
        .unwrap();
    let error = service
        .process_request_with_external_authority_v1(&vote, &mut adapter)
        .expect_err("vote path must stay fail closed");
    assert!(error.is_external_authority_required());

    let timeout = fixture_request(&fixture, "timeout", 4, b"crash-before-bind").unwrap();
    let timeout_bytes = timeout.try_exact_bytes().unwrap();
    let facts = service
        .external_authority_request_v1(&timeout_bytes)
        .unwrap();
    let reservation = adapter.reserve_v1(facts).expect("reserve external CAS");
    assert_eq!(reservation.sequence(), 0);
    drop(adapter);
    let mut reopened =
        UnixExternalTimeoutAuthorityV1::from_binding(fixture.binding, &socket, &response_log)
            .expect("reopen adapter before ambiguity check")
            .with_capability(CAPABILITY);
    assert!(
        reopened.reserve_v1(facts).is_err(),
        "unbound external reservation is ambiguous"
    );
    authority.stop();
}
