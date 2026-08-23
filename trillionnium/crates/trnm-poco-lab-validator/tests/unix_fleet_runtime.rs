use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    thread,
    time::Duration,
};

use ed25519_dalek::{Signer, SigningKey};
use tempfile::tempdir;
use trnm_consensus_types::ValidatorId;
use trnm_consensus_unix_fleet_signer::{
    FleetRootPurposeV1, FleetRootRequestV1, FleetRootResponseV1,
};
use trnm_poco_lab_validator::consensus_runtime::{
    FleetSignatureProducerV1, FleetSignaturePurposeV1, FleetSignatureRequestV1,
    UnixFleetSignatureProducerV1,
};

fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .expect("request frame header");
    let length = u32::from_be_bytes(header) as usize;
    assert!(length > 0 && length < 4096, "bounded request frame");
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).expect("request frame body");
    body
}

fn write_frame(stream: &mut UnixStream, body: &[u8]) {
    let length = u32::try_from(body.len()).expect("bounded response frame");
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(body))
        .and_then(|_| stream.flush())
        .expect("response frame");
}

#[test]
fn runtime_unix_fleet_adapter_binds_and_verifies_subprocess_style_response() {
    let directory = tempdir().expect("temporary signer directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private signer directory");
    let socket = directory.path().join("fleet-root.sock");
    let listener = UnixListener::bind(&socket).expect("bind signer socket");
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).expect("private signer socket");

    let origin = ValidatorId::from_bytes(b"runtime-fleet-validator").expect("bounded origin");
    let validator_set_id = [0x51; 32];
    let signing_root = [0x72; 32];
    let signing_key = SigningKey::from_bytes(&[0x44; 32]);
    let verifying_key = signing_key.verifying_key().to_bytes();
    let server_signing_key = signing_key.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept signer client");
        let request = FleetRootRequestV1::decode_exact(&read_frame(&mut stream))
            .expect("decode exact runtime request");
        assert_eq!(request.purpose(), FleetRootPurposeV1::RestartPark);
        assert_eq!(request.origin(), origin);
        assert_eq!(request.validator_set_id(), validator_set_id);
        assert_eq!(request.signing_root(), signing_root);
        assert_ne!(request.nonce(), [0; 32]);
        let signature = server_signing_key.sign(&request.signing_root()).to_bytes();
        let response = FleetRootResponseV1::from_request_signature(&request, signature)
            .expect("bind exact signer response");
        let mut envelope = Vec::with_capacity(1 + response.try_exact_bytes().len());
        envelope.push(0);
        envelope.extend_from_slice(&response.try_exact_bytes());
        write_frame(&mut stream, &envelope);
    });

    let config = trnm_consensus_unix_fleet_signer::UnixFleetRootSignerConfig {
        socket_path: socket,
        origin,
        validator_set_id,
        verifying_key,
        timeout: Duration::from_secs(2),
    };
    let mut producer = UnixFleetSignatureProducerV1::new(config).expect("construct adapter");
    let request = FleetSignatureRequestV1::new(
        FleetSignaturePurposeV1::RestartPark,
        origin,
        validator_set_id,
        signing_root,
    );
    let signature = producer
        .sign_fleet_v1(request)
        .expect("strict Unix fleet response");
    assert_eq!(signature, signing_key.sign(&signing_root).to_bytes());
    server.join().expect("signer server join");
}
