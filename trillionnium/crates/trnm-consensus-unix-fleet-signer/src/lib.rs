#![forbid(unsafe_code)]

//! Strict Unix transport seam for fleet-root signatures.
//!
//! This crate is deliberately independent of the validator node.  It carries
//! only a typed `(purpose, origin, validator-set, signing-root, nonce)`
//! request across a private Unix socket and verifies the exact response.  It
//! does not own a Core, SafetyRules, lease, watermark, private key, or runtime
//! activation.  The optional subprocess fixture is the sole place where a
//! deterministic test key exists.

#[cfg(not(unix))]
compile_error!("trnm-consensus-unix-fleet-signer requires a Unix host");

use std::{
    fmt, fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::UnixStream,
    },
    path::PathBuf,
    time::Duration,
};

use sha2::{Digest, Sha256};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    ConsensusPublicKey, SignatureBytes, SignatureVerifier, SigningRoot, Validator, ValidatorId,
    VotingPower,
};

/// Runtime activation is intentionally closed for this transport seam.
pub const UNIX_FLEET_SIGNER_RUNTIME_ACTIVATION_V1: bool = false;
/// No private key is present in the default library build.
pub const UNIX_FLEET_SIGNER_PRIVATE_KEY_HANDLING_V1: bool = false;
/// This crate does not evaluate locked-QC/SafetyRules authorization.
pub const UNIX_FLEET_SIGNER_SAFETY_RULES_AUTHORITY_V1: bool = false;
/// The transport/client slice is not a production candidate.
pub const UNIX_FLEET_SIGNER_PRODUCTION_CANDIDATE_V1: bool = false;

const REQUEST_MAGIC_V1: &[u8; 8] = b"TRNMFQ01";
const RESPONSE_MAGIC_V1: &[u8; 8] = b"TRNMFQ02";
const REQUEST_SCHEMA_V1: u8 = 1;
const RESPONSE_SCHEMA_V1: u8 = 1;
const CHECKSUM_DOMAIN_V1: &[u8] = b"trnm.consensus.unix-fleet-root.checksum.v1\0";
const FINGERPRINT_DOMAIN_V1: &[u8] = b"trnm.consensus.unix-fleet-root.request.v1\0";
const FRAME_HEADER_BYTES: usize = 4;
const RESPONSE_STATUS_OK_V1: u8 = 0;
const RESPONSE_STATUS_REJECT_V1: u8 = 1;
const MAX_ORIGIN_BYTES_V1: usize = 128;
const MAX_REQUEST_BYTES_V1: usize = 8 + 4 + 1 + 2 + MAX_ORIGIN_BYTES_V1 + 32 + 32 + 32 + 32;
const MAX_RESPONSE_BYTES_V1: usize = 8 + 4 + 32 + 64 + 32;
const MAX_FRAME_BYTES_V1: usize = MAX_REQUEST_BYTES_V1 + 2;
const MAX_TIMEOUT_V1: Duration = Duration::from_secs(30);

/// The purpose domain is intentionally closed; arbitrary sign-bytes cannot
/// enter this producer seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FleetRootPurposeV1 {
    Ready = 1,
    Start = 2,
    Relay = 3,
    Restart = 4,
    RestartCut = 5,
    RestartPark = 6,
}

impl FleetRootPurposeV1 {
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    fn from_byte(value: u8) -> Result<Self, FleetSignerProtocolErrorV1> {
        match value {
            1 => Ok(Self::Ready),
            2 => Ok(Self::Start),
            3 => Ok(Self::Relay),
            4 => Ok(Self::Restart),
            5 => Ok(Self::RestartCut),
            6 => Ok(Self::RestartPark),
            _ => Err(FleetSignerProtocolErrorV1::InvalidPurpose(value)),
        }
    }
}

/// A complete, bounded fleet-root signing request.  The nonce is supplied by
/// the caller; this crate does not pretend to provide nonce freshness or a
/// durable replay authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetRootRequestV1 {
    purpose: FleetRootPurposeV1,
    origin: ValidatorId,
    validator_set_id: [u8; 32],
    signing_root: [u8; 32],
    nonce: [u8; 32],
}

impl FleetRootRequestV1 {
    pub fn new(
        purpose: FleetRootPurposeV1,
        origin: ValidatorId,
        validator_set_id: [u8; 32],
        signing_root: [u8; 32],
        nonce: [u8; 32],
    ) -> Result<Self, FleetSignerProtocolErrorV1> {
        let value = Self {
            purpose,
            origin,
            validator_set_id,
            signing_root,
            nonce,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn purpose(self) -> FleetRootPurposeV1 {
        self.purpose
    }

    pub const fn origin(self) -> ValidatorId {
        self.origin
    }

    pub const fn validator_set_id(self) -> [u8; 32] {
        self.validator_set_id
    }

    pub const fn signing_root(self) -> [u8; 32] {
        self.signing_root
    }

    pub const fn nonce(self) -> [u8; 32] {
        self.nonce
    }

    pub fn validate(&self) -> Result<(), FleetSignerProtocolErrorV1> {
        if self.origin.is_zero() || self.origin.as_bytes().len() > MAX_ORIGIN_BYTES_V1 {
            return Err(FleetSignerProtocolErrorV1::InvalidOrigin);
        }
        if self.validator_set_id == [0; 32] {
            return Err(FleetSignerProtocolErrorV1::ZeroField("validator-set-id"));
        }
        if self.signing_root == [0; 32] {
            return Err(FleetSignerProtocolErrorV1::ZeroField("signing-root"));
        }
        if self.nonce == [0; 32] {
            return Err(FleetSignerProtocolErrorV1::ZeroField("nonce"));
        }
        Ok(())
    }

    /// Returns the exact canonical request bytes, including its checksum.
    pub fn try_exact_bytes(&self) -> Result<Vec<u8>, FleetSignerProtocolErrorV1> {
        self.validate()?;
        let origin = self.origin.as_bytes();
        let mut body = Vec::with_capacity(MAX_REQUEST_BYTES_V1);
        body.extend_from_slice(REQUEST_MAGIC_V1);
        body.extend_from_slice(&[REQUEST_SCHEMA_V1, 0, 0, 0]);
        body.push(self.purpose.as_byte());
        put_u16(
            &mut body,
            u16::try_from(origin.len()).map_err(|_| FleetSignerProtocolErrorV1::InvalidOrigin)?,
        );
        body.extend_from_slice(origin);
        body.extend_from_slice(&self.validator_set_id);
        body.extend_from_slice(&self.signing_root);
        body.extend_from_slice(&self.nonce);
        let checksum = checksum_v1(&body);
        body.extend_from_slice(&checksum);
        Ok(body)
    }

    /// Hashes the exact canonical request preimage.  The checksum is not part
    /// of the fingerprint, so a checksum rewrite cannot create a new intent.
    pub fn fingerprint(&self) -> Result<[u8; 32], FleetSignerProtocolErrorV1> {
        let encoded = self.try_exact_bytes()?;
        Ok(fingerprint_for_encoded_v1(&encoded[..encoded.len() - 32]))
    }

    /// Decodes one exact canonical request. Every length and checksum is
    /// checked before any field is projected, and trailing bytes are rejected.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, FleetSignerProtocolErrorV1> {
        const MINIMUM: usize = 8 + 4 + 1 + 2 + 1 + 32 + 32 + 32 + 32;
        if bytes.len() < MINIMUM {
            return Err(FleetSignerProtocolErrorV1::TruncatedOrTrailing);
        }
        if bytes.len() > MAX_REQUEST_BYTES_V1 {
            return Err(FleetSignerProtocolErrorV1::FrameTooLarge {
                actual: bytes.len(),
                maximum: MAX_REQUEST_BYTES_V1,
            });
        }
        if &bytes[..8] != REQUEST_MAGIC_V1 {
            return Err(FleetSignerProtocolErrorV1::InvalidEnvelope);
        }
        if bytes[8] != REQUEST_SCHEMA_V1 {
            return Err(FleetSignerProtocolErrorV1::UnsupportedSchema(bytes[8]));
        }
        if bytes[9..12] != [0, 0, 0] {
            return Err(FleetSignerProtocolErrorV1::InvalidEnvelope);
        }
        let purpose = FleetRootPurposeV1::from_byte(bytes[12])?;
        let origin_length = u16::from_be_bytes([bytes[13], bytes[14]]) as usize;
        if origin_length == 0 || origin_length > MAX_ORIGIN_BYTES_V1 {
            return Err(FleetSignerProtocolErrorV1::InvalidOrigin);
        }
        let origin_start = 15usize;
        let origin_end = origin_start
            .checked_add(origin_length)
            .ok_or(FleetSignerProtocolErrorV1::TruncatedOrTrailing)?;
        let fixed_end = origin_end
            .checked_add(32 + 32 + 32 + 32)
            .ok_or(FleetSignerProtocolErrorV1::TruncatedOrTrailing)?;
        if fixed_end != bytes.len() {
            return Err(FleetSignerProtocolErrorV1::TruncatedOrTrailing);
        }
        let origin = ValidatorId::from_bytes(&bytes[origin_start..origin_end])
            .map_err(|_| FleetSignerProtocolErrorV1::InvalidOrigin)?;
        let mut offset = origin_end;
        let validator_set_id: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| FleetSignerProtocolErrorV1::TruncatedOrTrailing)?;
        offset += 32;
        let signing_root: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| FleetSignerProtocolErrorV1::TruncatedOrTrailing)?;
        offset += 32;
        let nonce: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| FleetSignerProtocolErrorV1::TruncatedOrTrailing)?;
        offset += 32;
        let stored_checksum: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| FleetSignerProtocolErrorV1::TruncatedOrTrailing)?;
        if checksum_v1(&bytes[..offset]) != stored_checksum {
            return Err(FleetSignerProtocolErrorV1::ChecksumMismatch);
        }
        Self::new(purpose, origin, validator_set_id, signing_root, nonce)
    }
}

/// Exact response envelope.  It carries the request fingerprint and signature;
/// the client reconstructs the expected request and rejects any mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetRootResponseV1 {
    request_fingerprint: [u8; 32],
    signature: [u8; 64],
}

impl FleetRootResponseV1 {
    pub fn from_request_signature(
        request: &FleetRootRequestV1,
        signature: [u8; 64],
    ) -> Result<Self, FleetSignerProtocolErrorV1> {
        Ok(Self {
            request_fingerprint: request.fingerprint()?,
            signature,
        })
    }

    pub const fn request_fingerprint(self) -> [u8; 32] {
        self.request_fingerprint
    }

    pub const fn signature(self) -> [u8; 64] {
        self.signature
    }

    pub fn try_exact_bytes(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(MAX_RESPONSE_BYTES_V1);
        body.extend_from_slice(RESPONSE_MAGIC_V1);
        body.extend_from_slice(&[RESPONSE_SCHEMA_V1, 0, 0, 0]);
        body.extend_from_slice(&self.request_fingerprint);
        body.extend_from_slice(&self.signature);
        let checksum = checksum_v1(&body);
        body.extend_from_slice(&checksum);
        body
    }

    pub fn decode_exact(
        bytes: &[u8],
        request: &FleetRootRequestV1,
    ) -> Result<Self, FleetSignerProtocolErrorV1> {
        if bytes.len() > MAX_RESPONSE_BYTES_V1 {
            return Err(FleetSignerProtocolErrorV1::FrameTooLarge {
                actual: bytes.len(),
                maximum: MAX_RESPONSE_BYTES_V1,
            });
        }
        let expected_len = MAX_RESPONSE_BYTES_V1;
        if bytes.len() != expected_len {
            return Err(FleetSignerProtocolErrorV1::TruncatedOrTrailing);
        }
        if &bytes[..8] != RESPONSE_MAGIC_V1
            || bytes[8] != RESPONSE_SCHEMA_V1
            || bytes[9..12] != [0, 0, 0]
        {
            return Err(FleetSignerProtocolErrorV1::InvalidEnvelope);
        }
        let checksum_offset = bytes.len() - 32;
        if checksum_v1(&bytes[..checksum_offset]) != bytes[checksum_offset..] {
            return Err(FleetSignerProtocolErrorV1::ChecksumMismatch);
        }
        let request_fingerprint: [u8; 32] = bytes[12..44]
            .try_into()
            .map_err(|_| FleetSignerProtocolErrorV1::InvalidEnvelope)?;
        let expected_fingerprint = request.fingerprint()?;
        if request_fingerprint != expected_fingerprint {
            return Err(FleetSignerProtocolErrorV1::ResponseBindingMismatch);
        }
        let signature: [u8; 64] = bytes[44..108]
            .try_into()
            .map_err(|_| FleetSignerProtocolErrorV1::InvalidEnvelope)?;
        Ok(Self {
            request_fingerprint,
            signature,
        })
    }
}

/// Stable protocol/transport failures. All malformed, mismatched, replayed,
/// and ambiguous responses map to rejection rather than retrying a different
/// intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetSignerProtocolErrorV1 {
    InvalidEnvelope,
    UnsupportedSchema(u8),
    InvalidPurpose(u8),
    InvalidOrigin,
    ZeroField(&'static str),
    FrameTooLarge { actual: usize, maximum: usize },
    EmptyFrame,
    TruncatedOrTrailing,
    ChecksumMismatch,
    ResponseBindingMismatch,
    InvalidSignature,
    ReplayConflict,
    Rejected(u8),
}

impl fmt::Display for FleetSignerProtocolErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEnvelope => f.write_str("invalid fleet signer envelope"),
            Self::UnsupportedSchema(v) => write!(f, "unsupported fleet signer schema {v}"),
            Self::InvalidPurpose(v) => write!(f, "invalid fleet signer purpose {v}"),
            Self::InvalidOrigin => f.write_str("invalid fleet signer origin"),
            Self::ZeroField(name) => write!(f, "fleet signer {name} is zero"),
            Self::FrameTooLarge { actual, maximum } => {
                write!(f, "fleet signer frame {actual} exceeds {maximum}")
            }
            Self::EmptyFrame => f.write_str("fleet signer frame is empty"),
            Self::TruncatedOrTrailing => f.write_str("fleet signer frame is truncated or trailing"),
            Self::ChecksumMismatch => f.write_str("fleet signer checksum differs"),
            Self::ResponseBindingMismatch => f.write_str("fleet signer response binding differs"),
            Self::InvalidSignature => f.write_str("fleet signer signature is invalid"),
            Self::ReplayConflict => f.write_str("fleet signer replay conflicts"),
            Self::Rejected(code) => write!(f, "fleet signer service rejected request {code}"),
        }
    }
}

impl std::error::Error for FleetSignerProtocolErrorV1 {}

/// Transport/client failures. No variant represents a successful authority
/// grant; callers must treat every error as fail-closed.
#[derive(Debug)]
pub enum UnixFleetSignerErrorV1 {
    InvalidConfig(&'static str),
    SocketMissing,
    SocketNotPrivate,
    Io {
        stage: &'static str,
        source: io::Error,
    },
    Protocol(FleetSignerProtocolErrorV1),
}

impl fmt::Display for UnixFleetSignerErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "invalid Unix fleet signer config: {reason}"),
            Self::SocketMissing => f.write_str("Unix fleet signer socket is missing"),
            Self::SocketNotPrivate => f.write_str("Unix fleet signer socket is not private"),
            Self::Io { stage, source } => write!(f, "Unix fleet signer I/O at {stage}: {source}"),
            Self::Protocol(error) => write!(f, "Unix fleet signer protocol: {error}"),
        }
    }
}

impl std::error::Error for UnixFleetSignerErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FleetSignerProtocolErrorV1> for UnixFleetSignerErrorV1 {
    fn from(value: FleetSignerProtocolErrorV1) -> Self {
        Self::Protocol(value)
    }
}

/// A signer client carrying no private key. The configured public key is used
/// to strictly verify the returned signature over the exact request root.
#[derive(Debug, Clone)]
pub struct UnixFleetRootSignerConfig {
    pub socket_path: PathBuf,
    pub origin: ValidatorId,
    pub validator_set_id: [u8; 32],
    pub verifying_key: [u8; 32],
    pub timeout: Duration,
}

impl UnixFleetRootSignerConfig {
    fn validate(&self) -> Result<(), UnixFleetSignerErrorV1> {
        if self.socket_path.as_os_str().is_empty() || !self.socket_path.is_absolute() {
            return Err(UnixFleetSignerErrorV1::InvalidConfig(
                "socket path must be absolute",
            ));
        }
        if self.origin.is_zero() {
            return Err(UnixFleetSignerErrorV1::InvalidConfig("origin is zero"));
        }
        if self.validator_set_id == [0; 32] {
            return Err(UnixFleetSignerErrorV1::InvalidConfig(
                "validator-set id is zero",
            ));
        }
        if self.verifying_key == [0; 32] {
            return Err(UnixFleetSignerErrorV1::InvalidConfig(
                "verifying key is zero",
            ));
        }
        if self.timeout.is_zero() || self.timeout > MAX_TIMEOUT_V1 {
            return Err(UnixFleetSignerErrorV1::InvalidConfig(
                "timeout must be positive and at most 30 seconds",
            ));
        }
        Ok(())
    }
}

/// Typed Unix producer. A caller must provide a fresh nonce for every new
/// intent. Exact duplicate requests are replayable; a conflicting response or
/// nonce is rejected before signature bytes escape this API.
#[derive(Debug, Clone)]
pub struct UnixFleetRootSignerProducerV1 {
    config: UnixFleetRootSignerConfig,
}

impl UnixFleetRootSignerProducerV1 {
    pub fn new(config: UnixFleetRootSignerConfig) -> Result<Self, UnixFleetSignerErrorV1> {
        config.validate()?;
        Ok(Self { config })
    }

    pub const fn config(&self) -> &UnixFleetRootSignerConfig {
        &self.config
    }

    /// Checks socket and parent ownership shape without connecting.
    pub fn preflight(&self) -> Result<(), UnixFleetSignerErrorV1> {
        let metadata = fs::symlink_metadata(&self.config.socket_path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                UnixFleetSignerErrorV1::SocketMissing
            } else {
                UnixFleetSignerErrorV1::Io {
                    stage: "socket metadata",
                    source: error,
                }
            }
        })?;
        if !metadata.file_type().is_socket() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(UnixFleetSignerErrorV1::SocketNotPrivate);
        }
        let parent =
            self.config
                .socket_path
                .parent()
                .ok_or(UnixFleetSignerErrorV1::InvalidConfig(
                    "socket has no parent",
                ))?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(|source| UnixFleetSignerErrorV1::Io {
                stage: "socket parent metadata",
                source,
            })?;
        if !parent_metadata.is_dir() || parent_metadata.permissions().mode() & 0o077 != 0 {
            return Err(UnixFleetSignerErrorV1::SocketNotPrivate);
        }
        Ok(())
    }

    /// Signs one exact purpose/root/nonce request through the external Unix
    /// process. This method does not retry a rejected or ambiguous response.
    pub fn sign_fleet_root_v1(
        &mut self,
        purpose: FleetRootPurposeV1,
        signing_root: [u8; 32],
        nonce: [u8; 32],
    ) -> Result<[u8; 64], UnixFleetSignerErrorV1> {
        let request = FleetRootRequestV1::new(
            purpose,
            self.config.origin,
            self.config.validator_set_id,
            signing_root,
            nonce,
        )?;
        let request_bytes = request.try_exact_bytes()?;
        let response_bytes = self.call(&request_bytes)?;
        let response = FleetRootResponseV1::decode_exact(&response_bytes, &request)?;
        verify_signature_v1(&self.config, &request, response.signature())?;
        Ok(response.signature())
    }

    fn call(&self, request: &[u8]) -> Result<Vec<u8>, UnixFleetSignerErrorV1> {
        if request.len() > MAX_REQUEST_BYTES_V1 {
            return Err(FleetSignerProtocolErrorV1::FrameTooLarge {
                actual: request.len(),
                maximum: MAX_REQUEST_BYTES_V1,
            }
            .into());
        }
        self.preflight()?;
        let mut stream = UnixStream::connect(&self.config.socket_path).map_err(|source| {
            UnixFleetSignerErrorV1::Io {
                stage: "connect",
                source,
            }
        })?;
        stream
            .set_read_timeout(Some(self.config.timeout))
            .map_err(|source| UnixFleetSignerErrorV1::Io {
                stage: "read timeout",
                source,
            })?;
        stream
            .set_write_timeout(Some(self.config.timeout))
            .map_err(|source| UnixFleetSignerErrorV1::Io {
                stage: "write timeout",
                source,
            })?;
        write_frame_v1(&mut stream, request)?;
        let frame = read_frame_v1(&mut stream, MAX_FRAME_BYTES_V1)?;
        if frame.is_empty() {
            return Err(FleetSignerProtocolErrorV1::EmptyFrame.into());
        }
        match frame[0] {
            RESPONSE_STATUS_OK_V1 if frame.len() > 1 => Ok(frame[1..].to_vec()),
            RESPONSE_STATUS_OK_V1 => Err(FleetSignerProtocolErrorV1::EmptyFrame.into()),
            RESPONSE_STATUS_REJECT_V1 => {
                let code = frame.get(1).copied().unwrap_or_default();
                Err(FleetSignerProtocolErrorV1::Rejected(code).into())
            }
            _ => Err(FleetSignerProtocolErrorV1::InvalidEnvelope.into()),
        }
    }
}

/// Object-safe seam for a later runtime adapter. This trait is intentionally
/// crate-local in meaning and does not imply Core/SafetyRules authority.
pub trait FleetRootSignatureProducerV1: Send {
    fn sign_fleet_root_v1(
        &mut self,
        purpose: FleetRootPurposeV1,
        signing_root: [u8; 32],
        nonce: [u8; 32],
    ) -> Result<[u8; 64], UnixFleetSignerErrorV1>;
}

impl FleetRootSignatureProducerV1 for UnixFleetRootSignerProducerV1 {
    fn sign_fleet_root_v1(
        &mut self,
        purpose: FleetRootPurposeV1,
        signing_root: [u8; 32],
        nonce: [u8; 32],
    ) -> Result<[u8; 64], UnixFleetSignerErrorV1> {
        Self::sign_fleet_root_v1(self, purpose, signing_root, nonce)
    }
}

fn verify_signature_v1(
    config: &UnixFleetRootSignerConfig,
    request: &FleetRootRequestV1,
    signature: [u8; 64],
) -> Result<(), UnixFleetSignerErrorV1> {
    let validator = Validator::new(
        config.origin,
        ConsensusPublicKey::new(config.verifying_key),
        VotingPower::new(1).map_err(|_| UnixFleetSignerErrorV1::InvalidConfig("voting power"))?,
    )
    .map_err(|_| UnixFleetSignerErrorV1::InvalidConfig("verifying key shape"))?;
    let signing_root = SigningRoot::new(request.signing_root());
    let signature = SignatureBytes::from_array(signature);
    if StrictEd25519Verifier.verify(&validator, &signing_root, &signature) {
        Ok(())
    } else {
        Err(FleetSignerProtocolErrorV1::InvalidSignature.into())
    }
}

fn checksum_v1(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CHECKSUM_DOMAIN_V1);
    hash.update(bytes);
    hash.finalize().into()
}

fn fingerprint_for_encoded_v1(bytes_without_checksum: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FINGERPRINT_DOMAIN_V1);
    hash.update(bytes_without_checksum);
    hash.finalize().into()
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_frame_v1(stream: &mut UnixStream, body: &[u8]) -> Result<(), UnixFleetSignerErrorV1> {
    if body.is_empty() {
        return Err(FleetSignerProtocolErrorV1::EmptyFrame.into());
    }
    let length =
        u32::try_from(body.len()).map_err(|_| FleetSignerProtocolErrorV1::FrameTooLarge {
            actual: body.len(),
            maximum: u32::MAX as usize,
        })?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(body))
        .and_then(|_| stream.flush())
        .map_err(|source| UnixFleetSignerErrorV1::Io {
            stage: "write frame",
            source,
        })
}

fn read_frame_v1(
    stream: &mut UnixStream,
    maximum: usize,
) -> Result<Vec<u8>, UnixFleetSignerErrorV1> {
    let mut header = [0u8; FRAME_HEADER_BYTES];
    stream.read_exact(&mut header).map_err(|source| {
        if source.kind() == io::ErrorKind::UnexpectedEof {
            UnixFleetSignerErrorV1::Protocol(FleetSignerProtocolErrorV1::TruncatedOrTrailing)
        } else {
            UnixFleetSignerErrorV1::Io {
                stage: "read frame header",
                source,
            }
        }
    })?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(FleetSignerProtocolErrorV1::EmptyFrame.into());
    }
    if length > maximum {
        return Err(FleetSignerProtocolErrorV1::FrameTooLarge {
            actual: length,
            maximum,
        }
        .into());
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).map_err(|source| {
        if source.kind() == io::ErrorKind::UnexpectedEof {
            UnixFleetSignerErrorV1::Protocol(FleetSignerProtocolErrorV1::TruncatedOrTrailing)
        } else {
            UnixFleetSignerErrorV1::Io {
                stage: "read frame body",
                source,
            }
        }
    })?;
    Ok(body)
}

#[cfg(feature = "test-fixture")]
pub mod test_fixture;

#[cfg(test)]
mod source_contract_tests {
    #[test]
    fn default_build_has_closed_truth_flags_and_no_secret_api() {
        const _: () = {
            assert!(!super::UNIX_FLEET_SIGNER_RUNTIME_ACTIVATION_V1);
            assert!(!super::UNIX_FLEET_SIGNER_PRIVATE_KEY_HANDLING_V1);
            assert!(!super::UNIX_FLEET_SIGNER_SAFETY_RULES_AUTHORITY_V1);
            assert!(!super::UNIX_FLEET_SIGNER_PRODUCTION_CANDIDATE_V1);
        };
        let manifest = include_str!("../Cargo.toml");
        assert!(manifest.contains(concat!("fixture_", "private", "_key = false")));
        assert!(manifest.contains("production_activation = false"));
        assert!(manifest.contains("required-features = [\"test-fixture\"]"));
        let source = include_str!("lib.rs");
        for forbidden in [
            concat!("Signing", "Key"),
            concat!("Secret", "Key"),
            concat!("signing", "_key"),
            concat!("private", "_key"),
        ] {
            assert!(
                !source.contains(forbidden),
                "default source token: {forbidden}"
            );
        }
    }

    #[test]
    fn request_decoder_is_exact_and_binds_all_fields() {
        let origin =
            trnm_consensus_types::ValidatorId::from_bytes(b"fixture-origin").expect("origin");
        let request = super::FleetRootRequestV1::new(
            super::FleetRootPurposeV1::Relay,
            origin,
            [1; 32],
            [2; 32],
            [3; 32],
        )
        .expect("request");
        let encoded = request.try_exact_bytes().expect("encode");
        assert_eq!(
            super::FleetRootRequestV1::decode_exact(&encoded),
            Ok(request)
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            super::FleetRootRequestV1::decode_exact(&trailing),
            Err(super::FleetSignerProtocolErrorV1::TruncatedOrTrailing)
        ));

        let mut checksum = encoded;
        let last = checksum.len() - 1;
        checksum[last] ^= 1;
        assert!(matches!(
            super::FleetRootRequestV1::decode_exact(&checksum),
            Err(super::FleetSignerProtocolErrorV1::ChecksumMismatch)
        ));
    }
}
