//! Test-only deterministic signer server.
//!
//! This module is compiled only with `--features test-fixture`; it is not a
//! deployment credential source and is intentionally absent from default
//! builds.

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::UnixListener,
    },
    path::Path,
};

use ed25519_dalek::{Signer, SigningKey};
use trnm_consensus_remote_signer_protocol::{
    decode_remote_signer_request_v1_exact, ProcessGenerationV1, RemoteSignerCheckpointWitnessV1,
    RemoteSignerClientProfileRefV1, RemoteSignerLeaseIdV1, RemoteSignerRequestBindingV1,
    RemoteSignerRoleProfileRefV1, RemoteSignerServiceProfileRefV1,
    UnverifiedRemoteSignerResponseV1,
};
use trnm_consensus_types::{
    BlockId, CanonicalSignIntentV0, CertificateId, ChainId, ConsensusParametersHash,
    ConsensusPublicKey, Epoch, GenesisHash, Height, ProtocolVersion, QcRef, SignatureBytes,
    Validator, ValidatorId, ValidatorSet, View, VotingPower,
};

use crate::{write_frame, UnixRemoteSignerProducerConfig};

/// Deterministic test-only seed. It is never accepted by the default build.
const FIXTURE_SEED: [u8; 32] = [0x5a; 32];
const SECOND_SEED: [u8; 32] = [0x6b; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureServerMode {
    Valid,
    ReplayFirst,
    MutatedResponse,
    OversizedResponse,
    TruncatedResponse,
    ZeroLengthResponse,
    InvalidSignature,
}

impl FixtureServerMode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "valid" => Ok(Self::Valid),
            "replay-first" => Ok(Self::ReplayFirst),
            "mutated-response" => Ok(Self::MutatedResponse),
            "oversized-response" => Ok(Self::OversizedResponse),
            "truncated-response" => Ok(Self::TruncatedResponse),
            "zero-length-response" => Ok(Self::ZeroLengthResponse),
            "invalid-signature" => Ok(Self::InvalidSignature),
            _ => Err(format!("unknown fixture mode {value}")),
        }
    }
}

pub fn fixture_validator_set() -> ValidatorSet {
    let first = SigningKey::from_bytes(&FIXTURE_SEED);
    let second = SigningKey::from_bytes(&SECOND_SEED);
    ValidatorSet::new(
        GenesisHash::new([0x31; 32]),
        ChainId::from_static("trnm-unix-remote-signer-test"),
        ProtocolVersion::V0,
        Epoch::new(7),
        ConsensusParametersHash::new([0x42; 32]),
        vec![
            Validator::new(
                ValidatorId::from_bytes(b"fixture-validator-a").expect("fixture author"),
                ConsensusPublicKey::new(first.verifying_key().to_bytes()),
                VotingPower::new(1).expect("fixture power"),
            )
            .expect("fixture validator"),
            Validator::new(
                ValidatorId::from_bytes(b"fixture-validator-b").expect("fixture peer"),
                ConsensusPublicKey::new(second.verifying_key().to_bytes()),
                VotingPower::new(1).expect("fixture power"),
            )
            .expect("fixture validator"),
        ],
    )
    .expect("fixture validator set")
}

pub fn fixture_binding(set: &ValidatorSet) -> RemoteSignerRequestBindingV1 {
    RemoteSignerRequestBindingV1::new(
        set,
        fixture_author(),
        RemoteSignerRoleProfileRefV1::from_public_descriptor(b"unix-test-role")
            .expect("fixture role"),
        RemoteSignerServiceProfileRefV1::from_public_descriptor(b"unix-test-service")
            .expect("fixture service"),
        RemoteSignerClientProfileRefV1::from_public_descriptor(b"unix-test-client")
            .expect("fixture client"),
        ProcessGenerationV1::new(3).expect("fixture generation"),
        RemoteSignerLeaseIdV1::from_public_grant_descriptor(b"unix-test-lease")
            .expect("fixture lease"),
        RemoteSignerCheckpointWitnessV1::new(2, [0x77; 32]).expect("fixture checkpoint"),
    )
    .expect("fixture binding")
}

pub fn fixture_config(socket_path: impl AsRef<Path>) -> UnixRemoteSignerProducerConfig {
    let validator_set = fixture_validator_set();
    UnixRemoteSignerProducerConfig {
        socket_path: socket_path.as_ref().to_path_buf(),
        validator_set: validator_set.clone(),
        author: fixture_author(),
        signer_profile_ref: [0x88; 32],
        role_profile_ref: RemoteSignerRoleProfileRefV1::from_public_descriptor(b"unix-test-role")
            .expect("fixture role"),
        service_profile_ref: RemoteSignerServiceProfileRefV1::from_public_descriptor(
            b"unix-test-service",
        )
        .expect("fixture service"),
        client_profile_ref: RemoteSignerClientProfileRefV1::from_public_descriptor(
            b"unix-test-client",
        )
        .expect("fixture client"),
        process_generation: ProcessGenerationV1::new(3).expect("fixture generation"),
        lease_id: RemoteSignerLeaseIdV1::from_public_grant_descriptor(b"unix-test-lease")
            .expect("fixture lease"),
        checkpoint_witness: RemoteSignerCheckpointWitnessV1::new(2, [0x77; 32])
            .expect("fixture checkpoint"),
        timeout: std::time::Duration::from_secs(2),
    }
}

pub fn fixture_intent(view: u64) -> CanonicalSignIntentV0 {
    let set = fixture_validator_set();
    if view == 0 {
        CanonicalSignIntentV0::vote(
            &set,
            fixture_author(),
            1,
            View::new(0),
            Height::new(1),
            BlockId::new([0x90; 32]),
        )
        .expect("fixture vote intent")
    } else {
        CanonicalSignIntentV0::timeout_vote(
            &set,
            fixture_author(),
            view + 1,
            View::new(view),
            QcRef::new(
                CertificateId::new([0xa0u8.wrapping_add(view as u8); 32]),
                set.epoch(),
                View::new(view - 1),
                Height::new(view),
                BlockId::new([0xb0u8.wrapping_add(view as u8); 32]),
                set.id(),
            ),
        )
        .expect("fixture timeout intent")
    }
}

fn fixture_author() -> ValidatorId {
    ValidatorId::from_bytes(b"fixture-validator-a").expect("fixture author")
}

pub fn serve_fixture(
    socket_path: impl AsRef<Path>,
    mode: FixtureServerMode,
    request_count: usize,
) -> Result<(), String> {
    let requested_socket_path = socket_path.as_ref();
    if request_count == 0 {
        return Err("request count must be positive".to_owned());
    }
    if !requested_socket_path.is_absolute() {
        return Err("fixture socket path must be absolute".to_owned());
    }
    if requested_socket_path.exists() {
        let metadata =
            fs::symlink_metadata(requested_socket_path).map_err(|error| error.to_string())?;
        if !metadata.file_type().is_socket() {
            return Err("fixture socket path is not a socket".to_owned());
        }
        fs::remove_file(requested_socket_path).map_err(|error| error.to_string())?;
    }
    let parent = requested_socket_path
        .parent()
        .ok_or_else(|| "fixture socket has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
    if !parent_metadata.is_dir() || parent_metadata.permissions().mode() & 0o077 != 0 {
        return Err("fixture socket parent is not private".to_owned());
    }
    let normalized_parent = fs::canonicalize(parent).map_err(|error| error.to_string())?;
    let filename = requested_socket_path
        .file_name()
        .ok_or_else(|| "fixture socket has no filename".to_owned())?;
    let socket_path = normalized_parent.join(filename);
    let listener = UnixListener::bind(&socket_path).map_err(|error| error.to_string())?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    let set = fixture_validator_set();
    let binding = fixture_binding(&set);
    let key = SigningKey::from_bytes(&FIXTURE_SEED);
    let wrong_key = SigningKey::from_bytes(&[0x7c; 32]);
    let mut first_response: Option<Vec<u8>> = None;
    for (index, incoming) in listener.incoming().take(request_count).enumerate() {
        let mut stream = incoming.map_err(|error| error.to_string())?;
        let request_bytes = read_fixture_frame(&mut stream).map_err(|error| error.to_string())?;
        let request = decode_remote_signer_request_v1_exact(&request_bytes, &set, binding)
            .map_err(|error| error.to_string())?;
        let signing_key = if mode == FixtureServerMode::InvalidSignature {
            &wrong_key
        } else {
            &key
        };
        let signature = SignatureBytes::from_array(
            signing_key
                .sign(request.command().intent().signing_root().as_bytes())
                .to_bytes(),
        );
        let response =
            UnverifiedRemoteSignerResponseV1::from_unverified_signature_bytes(&request, signature)
                .map_err(|error| error.to_string())?;
        let mut response_bytes = response
            .try_exact_bytes()
            .map_err(|error| error.to_string())?;
        match mode {
            FixtureServerMode::ReplayFirst if index > 0 => {
                response_bytes = first_response
                    .clone()
                    .ok_or_else(|| "missing first response".to_owned())?;
            }
            FixtureServerMode::MutatedResponse => {
                let last = response_bytes
                    .last_mut()
                    .ok_or_else(|| "empty response".to_owned())?;
                *last ^= 1;
            }
            FixtureServerMode::OversizedResponse => {
                let header = (u32::MAX).to_be_bytes().to_vec();
                stream
                    .write_all(&header)
                    .map_err(|error| error.to_string())?;
                stream.flush().map_err(|error| error.to_string())?;
                continue;
            }
            FixtureServerMode::TruncatedResponse => {
                stream
                    .write_all(&64u32.to_be_bytes())
                    .and_then(|_| stream.write_all(&[0u8]))
                    .and_then(|_| stream.flush())
                    .map_err(|error| error.to_string())?;
                continue;
            }
            FixtureServerMode::ZeroLengthResponse => {
                stream
                    .write_all(&0u32.to_be_bytes())
                    .and_then(|_| stream.flush())
                    .map_err(|error| error.to_string())?;
                continue;
            }
            FixtureServerMode::Valid
            | FixtureServerMode::ReplayFirst
            | FixtureServerMode::InvalidSignature => {}
        }
        if first_response.is_none() {
            first_response = Some(response_bytes.clone());
        }
        write_frame(&mut stream, &response_bytes).map_err(|error| error.to_string())?;
    }
    let _ = fs::remove_file(&socket_path);
    Ok(())
}

fn read_fixture_frame(stream: &mut std::os::unix::net::UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture request frame is empty",
        ));
    }
    if length > trnm_consensus_remote_signer_protocol::MAX_REMOTE_SIGNER_REQUEST_BYTES_V1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture frame too large",
        ));
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    Ok(body)
}
