#![cfg(feature = "test-fixture")]

//! Deterministic subprocess signer used only by black-box tests.

use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
};

use ed25519_dalek::{Signer, SigningKey};

use crate::{FleetRootRequestV1, FleetRootResponseV1, MAX_REQUEST_BYTES_V1};

/// Fixture seed is compiled only under `test-fixture` and never enters the
/// default client build.
pub const FIXTURE_SEED_V1: [u8; 32] = [0x4a; 32];
pub fn fixture_public_key_v1() -> [u8; 32] {
    SigningKey::from_bytes(&FIXTURE_SEED_V1)
        .verifying_key()
        .to_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureModeV1 {
    Valid,
    ReplayFirst,
    MutatedResponse,
    InvalidSignature,
    TruncatedResponse,
    OversizedResponse,
    ZeroLengthResponse,
}

impl FixtureModeV1 {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "valid" => Ok(Self::Valid),
            "replay-first" => Ok(Self::ReplayFirst),
            "mutated-response" => Ok(Self::MutatedResponse),
            "invalid-signature" => Ok(Self::InvalidSignature),
            "truncated-response" => Ok(Self::TruncatedResponse),
            "oversized-response" => Ok(Self::OversizedResponse),
            "zero-length-response" => Ok(Self::ZeroLengthResponse),
            _ => Err(format!("unknown fleet signer fixture mode {value}")),
        }
    }
}

/// Runs a bounded one-request-per-connection fixture server. The server keeps
/// exact response bytes by request fingerprint and rejects a nonce reused for
/// a different request, proving the replay/fail-closed seam without claiming
/// durable production authority.
pub fn serve_fixture(
    socket_path: impl AsRef<Path>,
    mode: FixtureModeV1,
    request_count: usize,
) -> Result<(), String> {
    if request_count == 0 {
        return Err("request count must be positive".to_owned());
    }
    let requested = socket_path.as_ref();
    if !requested.is_absolute() {
        return Err("fixture socket path must be absolute".to_owned());
    }
    if requested.exists() {
        let metadata = fs::symlink_metadata(requested).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
            return Err("fixture socket path is not a plain socket".to_owned());
        }
        fs::remove_file(requested).map_err(|e| e.to_string())?;
    }
    let parent = requested
        .parent()
        .ok_or_else(|| "socket has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let parent = fs::canonicalize(parent).map_err(|e| e.to_string())?;
    let filename = requested
        .file_name()
        .ok_or_else(|| "socket has no filename".to_owned())?;
    let socket = parent.join(filename);
    let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;

    let good_key = SigningKey::from_bytes(&FIXTURE_SEED_V1);
    let bad_key = SigningKey::from_bytes(&[0x7c; 32]);
    let mut responses = BTreeMap::<[u8; 32], Vec<u8>>::new();
    let mut nonces = BTreeMap::<[u8; 32], [u8; 32]>::new();
    let mut first_response: Option<Vec<u8>> = None;

    for (index, incoming) in listener.incoming().take(request_count).enumerate() {
        let mut stream = incoming.map_err(|e| e.to_string())?;
        let body = read_frame(&mut stream, MAX_REQUEST_BYTES_V1).map_err(|e| e.to_string())?;
        let request = FleetRootRequestV1::decode_exact(&body).map_err(|e| e.to_string())?;
        let fingerprint = request.fingerprint().map_err(|e| e.to_string())?;
        if let Some(previous) = nonces.get(&request.nonce()) {
            if previous != &fingerprint {
                write_reject(&mut stream, 9).map_err(|e| e.to_string())?;
                continue;
            }
        }
        if mode == FixtureModeV1::ReplayFirst && index > 0 {
            if let Some(first) = &first_response {
                write_ok(&mut stream, first).map_err(|e| e.to_string())?;
                continue;
            }
        }
        if let Some(previous) = responses.get(&fingerprint) {
            let replay = previous.clone();
            write_ok(&mut stream, &replay).map_err(|e| e.to_string())?;
            continue;
        }
        nonces.insert(request.nonce(), fingerprint);
        let signing_key = if mode == FixtureModeV1::InvalidSignature {
            &bad_key
        } else {
            &good_key
        };
        let signature = signing_key.sign(&request.signing_root()).to_bytes();
        let response = FleetRootResponseV1::from_request_signature(&request, signature)
            .map_err(|e| e.to_string())?;
        let mut encoded = response.try_exact_bytes();
        match mode {
            FixtureModeV1::MutatedResponse => {
                if let Some(last) = encoded.last_mut() {
                    *last ^= 1;
                }
            }
            FixtureModeV1::OversizedResponse => {
                stream
                    .write_all(&u32::MAX.to_be_bytes())
                    .and_then(|_| stream.flush())
                    .map_err(|e| e.to_string())?;
                continue;
            }
            FixtureModeV1::TruncatedResponse => {
                stream
                    .write_all(&64u32.to_be_bytes())
                    .map_err(|e| e.to_string())?;
                stream.write_all(&[0]).map_err(|e| e.to_string())?;
                stream.flush().map_err(|e| e.to_string())?;
                continue;
            }
            FixtureModeV1::ZeroLengthResponse => {
                stream
                    .write_all(&0u32.to_be_bytes())
                    .map_err(|e| e.to_string())?;
                stream.flush().map_err(|e| e.to_string())?;
                continue;
            }
            FixtureModeV1::Valid | FixtureModeV1::ReplayFirst | FixtureModeV1::InvalidSignature => {
            }
        }
        if first_response.is_none() {
            first_response = Some(encoded.clone());
        }
        responses.insert(fingerprint, encoded.clone());
        write_ok(&mut stream, &encoded).map_err(|e| e.to_string())?;
    }
    let _ = fs::remove_file(&socket);
    Ok(())
}

fn write_ok(stream: &mut UnixStream, response: &[u8]) -> io::Result<()> {
    let mut body = Vec::with_capacity(response.len() + 1);
    body.push(super::RESPONSE_STATUS_OK_V1);
    body.extend_from_slice(response);
    write_raw_frame(stream, &body)
}

fn write_reject(stream: &mut UnixStream, code: u8) -> io::Result<()> {
    write_raw_frame(stream, &[super::RESPONSE_STATUS_REJECT_V1, code])
}

fn write_raw_frame(stream: &mut UnixStream, body: &[u8]) -> io::Result<()> {
    stream.write_all(&(u32::try_from(body.len()).unwrap_or(u32::MAX)).to_be_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn read_frame(stream: &mut UnixStream, maximum: usize) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid fixture frame",
        ));
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    Ok(body)
}
