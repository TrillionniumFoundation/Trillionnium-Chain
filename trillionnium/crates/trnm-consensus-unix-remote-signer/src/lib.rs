#![forbid(unsafe_code)]

//! Bounded Unix client for the inert remote-signer protocol v1.
//!
//! This crate is intentionally independent of `trnm-poco-node`. It supplies a
//! composable [`SignatureProducerV0`] implementation, but does not itself
//! admit Core/SafetyRules requests or activate a consensus runtime.

#[cfg(not(unix))]
compile_error!("trnm-consensus-unix-remote-signer requires a Unix domain socket host");

use std::{
    fmt, fs,
    io::{self, Read, Write},
    os::unix::{fs::FileTypeExt, fs::PermissionsExt, net::UnixStream},
    path::PathBuf,
    time::Duration,
};

use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_remote_signer_protocol::{
    decode_unverified_remote_proposal_signer_response_v1_exact,
    decode_unverified_remote_signer_response_v1_exact, proposal_purpose_profile_digest_v1,
    RemoteConsensusCommandV1, RemoteProposalSignatureRequestV1, RemoteSignerCheckpointWitnessV1,
    RemoteSignerClientProfileRefV1, RemoteSignerLeaseIdV1, RemoteSignerProtocolErrorV1,
    RemoteSignerRequestBindingV1, RemoteSignerRequestNonceV1, RemoteSignerRequestV1,
    RemoteSignerRoleProfileRefV1, RemoteSignerServiceProfileRefV1,
    MAX_REMOTE_PROPOSAL_SIGNER_REQUEST_BYTES_V1, MAX_REMOTE_PROPOSAL_SIGNER_RESPONSE_BYTES_V1,
    MAX_REMOTE_SIGNER_REQUEST_BYTES_V1, MAX_REMOTE_SIGNER_RESPONSE_BYTES_V1,
};
use trnm_consensus_signer_journal::{
    ProposalSignatureProducerV0, ProposalSignatureRequestV0, SignatureProducerErrorV0,
    SignatureProducerV0, SignatureRequestV0,
};
use trnm_consensus_types::{
    CanonicalSignIntentV0, SignatureBytes, SignatureVerifier, ValidatorId, ValidatorSet,
};

/// Runtime activation is deliberately closed for this adapter slice.
pub const UNIX_REMOTE_SIGNER_RUNTIME_ACTIVATION_V1: bool = false;
/// The adapter has no credential resolver or private-key storage.
pub const UNIX_REMOTE_SIGNER_PRIVATE_KEY_HANDLING_V1: bool = false;
/// The adapter does not evaluate locked-QC/SafetyRules authorization.
pub const UNIX_REMOTE_SIGNER_SAFETY_RULES_AUTHORITY_V1: bool = false;
/// The adapter is not a production candidate by itself.
pub const UNIX_REMOTE_SIGNER_PRODUCTION_CANDIDATE_V1: bool = false;

const FRAME_HEADER_BYTES: usize = 4;
// The standalone service wraps an exact protocol response in one status byte;
// the older fixture server returns the exact response directly. Both forms
// are accepted only because the protocol magic makes the framing unambiguous.
const SERVICE_FRAME_OK: u8 = 0;
const SERVICE_FRAME_REJECT: u8 = 1;
const NONCE_DOMAIN: &[u8] = b"trnm.consensus.unix-remote-signer.request-nonce.v1\0";
const MAX_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for one node-side remote signer client.
#[derive(Debug, Clone)]
pub struct UnixRemoteSignerProducerConfig {
    pub socket_path: PathBuf,
    pub validator_set: ValidatorSet,
    pub author: ValidatorId,
    /// This is the signer-journal profile reference, not a private key.
    pub signer_profile_ref: [u8; 32],
    pub role_profile_ref: RemoteSignerRoleProfileRefV1,
    pub service_profile_ref: RemoteSignerServiceProfileRefV1,
    pub client_profile_ref: RemoteSignerClientProfileRefV1,
    pub process_generation: trnm_consensus_remote_signer_protocol::ProcessGenerationV1,
    pub lease_id: RemoteSignerLeaseIdV1,
    pub checkpoint_witness: RemoteSignerCheckpointWitnessV1,
    pub timeout: Duration,
}

impl UnixRemoteSignerProducerConfig {
    fn validate(&self) -> Result<(), UnixRemoteSignerError> {
        self.validator_set
            .validate_shape()
            .map_err(|_| UnixRemoteSignerError::InvalidConfig("validator set shape"))?;
        if self.validator_set.validator(self.author).is_none() {
            return Err(UnixRemoteSignerError::InvalidConfig(
                "configured author is absent from validator set",
            ));
        }
        if self.signer_profile_ref == [0; 32] {
            return Err(UnixRemoteSignerError::InvalidConfig(
                "signer profile reference is zero",
            ));
        }
        if self.socket_path.as_os_str().is_empty() {
            return Err(UnixRemoteSignerError::InvalidConfig("socket path is empty"));
        }
        if !self.socket_path.is_absolute() {
            return Err(UnixRemoteSignerError::InvalidConfig(
                "socket path must be absolute",
            ));
        }
        if self.timeout.is_zero() || self.timeout > MAX_TIMEOUT {
            return Err(UnixRemoteSignerError::InvalidConfig(
                "timeout must be positive and at most 30 seconds",
            ));
        }
        Ok(())
    }
}

/// Closed, inspectable client failures. The trait implementation maps these
/// to the smaller signer-journal error surface without retrying unsafe input.
#[derive(Debug)]
pub enum UnixRemoteSignerError {
    InvalidConfig(&'static str),
    SocketNotPrivate,
    SocketNotFound,
    Io {
        stage: &'static str,
        source: io::Error,
    },
    FrameTooLarge {
        actual: usize,
        maximum: usize,
    },
    TruncatedFrame,
    EmptyFrame,
    Protocol(RemoteSignerProtocolErrorV1),
    InvalidSignerProfile,
    AuthorMismatch,
    InvalidSignature,
    ServiceRejected(u8),
}

impl fmt::Display for UnixRemoteSignerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => {
                write!(formatter, "invalid remote signer config: {reason}")
            }
            Self::SocketNotPrivate => formatter.write_str("remote signer socket is not private"),
            Self::SocketNotFound => formatter.write_str("remote signer socket is missing"),
            Self::Io { stage, source } => {
                write!(formatter, "remote signer I/O at {stage}: {source}")
            }
            Self::FrameTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "remote signer frame {actual} exceeds bound {maximum}"
                )
            }
            Self::TruncatedFrame => formatter.write_str("remote signer frame is truncated"),
            Self::EmptyFrame => formatter.write_str("remote signer frame is empty"),
            Self::Protocol(source) => write!(
                formatter,
                "remote signer protocol rejected response: {source}"
            ),
            Self::InvalidSignerProfile => {
                formatter.write_str("signer profile differs from client config")
            }
            Self::AuthorMismatch => {
                formatter.write_str("sign request author differs from client config")
            }
            Self::InvalidSignature => {
                formatter.write_str("remote signer signature failed strict verification")
            }
            Self::ServiceRejected(code) => {
                write!(
                    formatter,
                    "remote signer service rejected request with code {code}"
                )
            }
        }
    }
}

impl std::error::Error for UnixRemoteSignerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<RemoteSignerProtocolErrorV1> for UnixRemoteSignerError {
    fn from(value: RemoteSignerProtocolErrorV1) -> Self {
        Self::Protocol(value)
    }
}

/// A stateless, one-request-per-connection Unix signer producer.
#[derive(Debug, Clone)]
pub struct UnixRemoteSignerProducer {
    config: UnixRemoteSignerProducerConfig,
}

impl UnixRemoteSignerProducer {
    pub fn new(config: UnixRemoteSignerProducerConfig) -> Result<Self, UnixRemoteSignerError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn config(&self) -> &UnixRemoteSignerProducerConfig {
        &self.config
    }

    /// Performs local socket shape checks without connecting or granting any
    /// signer authority.
    pub fn preflight(&self) -> Result<(), UnixRemoteSignerError> {
        let metadata = fs::symlink_metadata(&self.config.socket_path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                UnixRemoteSignerError::SocketNotFound
            } else {
                UnixRemoteSignerError::Io {
                    stage: "socket metadata",
                    source: error,
                }
            }
        })?;
        if !metadata.file_type().is_socket() {
            return Err(UnixRemoteSignerError::InvalidConfig(
                "socket path is not a Unix socket",
            ));
        }
        // Refuse group/world access. symlink_metadata also prevents a symlink
        // from being silently followed at the preflight boundary.
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(UnixRemoteSignerError::SocketNotPrivate);
        }
        let parent = self
            .config
            .socket_path
            .parent()
            .ok_or(UnixRemoteSignerError::InvalidConfig("socket has no parent"))?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(|source| UnixRemoteSignerError::Io {
                stage: "socket parent metadata",
                source,
            })?;
        if !parent_metadata.is_dir() || parent_metadata.permissions().mode() & 0o077 != 0 {
            return Err(UnixRemoteSignerError::SocketNotPrivate);
        }
        Ok(())
    }

    /// Public composable entry point for callers that do not yet own a
    /// signer-journal instance. A production caller should normally invoke
    /// this through `SqliteSignerJournalV0::sign_exact_v0` instead.
    pub fn sign_intent_exact(
        &mut self,
        intent: &CanonicalSignIntentV0,
    ) -> Result<SignatureBytes, UnixRemoteSignerError> {
        self.sign_intent_with_profile(intent, self.config.signer_profile_ref)
    }

    fn sign_intent_with_profile(
        &mut self,
        intent: &CanonicalSignIntentV0,
        signer_profile_ref: [u8; 32],
    ) -> Result<SignatureBytes, UnixRemoteSignerError> {
        if intent.author() != self.config.author {
            return Err(UnixRemoteSignerError::AuthorMismatch);
        }
        if signer_profile_ref != self.config.signer_profile_ref {
            return Err(UnixRemoteSignerError::InvalidSignerProfile);
        }
        intent.validate(&self.config.validator_set).map_err(|_| {
            UnixRemoteSignerError::InvalidConfig("sign intent does not match validator set")
        })?;
        let binding = RemoteSignerRequestBindingV1::new(
            &self.config.validator_set,
            self.config.author,
            self.config.role_profile_ref,
            self.config.service_profile_ref,
            self.config.client_profile_ref,
            self.config.process_generation,
            self.config.lease_id,
            self.config.checkpoint_witness,
        )
        .map_err(|_| UnixRemoteSignerError::InvalidConfig("remote signer binding"))?;
        let command = RemoteConsensusCommandV1::from_canonical_intent(
            intent.clone(),
            &self.config.validator_set,
        )
        .map_err(|_| UnixRemoteSignerError::InvalidConfig("remote signer command"))?;
        let nonce = derive_request_nonce(intent, signer_profile_ref, binding);
        let request =
            RemoteSignerRequestV1::new(command, &self.config.validator_set, binding, nonce)?;
        let request_bytes = request.try_exact_bytes()?;
        let response_bytes = self.call(
            &request_bytes,
            MAX_REMOTE_SIGNER_REQUEST_BYTES_V1,
            MAX_REMOTE_SIGNER_RESPONSE_BYTES_V1,
        )?;
        let response =
            decode_unverified_remote_signer_response_v1_exact(&response_bytes, &request)?;
        let signature = response.unverified_signature_bytes();
        let validator = self
            .config
            .validator_set
            .validator(self.config.author)
            .ok_or(UnixRemoteSignerError::InvalidConfig(
                "configured author disappeared",
            ))?;
        if !StrictEd25519Verifier.verify(validator, &intent.signing_root(), &signature) {
            return Err(UnixRemoteSignerError::InvalidSignature);
        }
        Ok(signature)
    }

    /// Sends one exact proposal witness request through the independently
    /// provisioned proposal-purpose wire. This is a separate trait surface
    /// from Vote/Timeout and is disabled by old signer services because the
    /// purpose profile and magic are distinct.
    pub fn sign_proposal_exact(
        &mut self,
        request: ProposalSignatureRequestV0,
    ) -> Result<SignatureBytes, UnixRemoteSignerError> {
        if request.author() != self.config.author {
            return Err(UnixRemoteSignerError::AuthorMismatch);
        }
        if request.signer_profile_ref() != self.config.signer_profile_ref {
            return Err(UnixRemoteSignerError::InvalidSignerProfile);
        }
        if request.validator_set_id() != self.config.validator_set.id() {
            return Err(UnixRemoteSignerError::InvalidConfig(
                "proposal validator-set differs from client config",
            ));
        }
        let validator = self
            .config
            .validator_set
            .validator(self.config.author)
            .ok_or(UnixRemoteSignerError::InvalidConfig(
                "configured author disappeared",
            ))?;
        if request.expected_consensus_public_key() != *validator.consensus_key().as_bytes() {
            return Err(UnixRemoteSignerError::InvalidConfig(
                "proposal public key differs from validator set",
            ));
        }
        let binding = RemoteSignerRequestBindingV1::new_with_purpose_profile_v1(
            &self.config.validator_set,
            self.config.author,
            self.config.role_profile_ref,
            self.config.service_profile_ref,
            self.config.client_profile_ref,
            self.config.process_generation,
            self.config.lease_id,
            self.config.checkpoint_witness,
            proposal_purpose_profile_digest_v1(),
        )
        .map_err(|_| UnixRemoteSignerError::InvalidConfig("proposal signer binding"))?;
        let nonce = derive_proposal_request_nonce(&request, binding);
        let wire_request = RemoteProposalSignatureRequestV1::new(
            binding,
            request.proposal_id(),
            request.parent_id(),
            request.validator_set_id(),
            request.author(),
            request.epoch(),
            request.view(),
            request.height(),
            request.signing_root(),
            request.expected_consensus_public_key(),
            request.signer_profile_ref(),
            nonce,
            &self.config.validator_set,
        )
        .map_err(UnixRemoteSignerError::Protocol)?;
        let request_bytes = wire_request
            .try_exact_bytes()
            .map_err(UnixRemoteSignerError::Protocol)?;
        let response_bytes = self.call(
            &request_bytes,
            MAX_REMOTE_PROPOSAL_SIGNER_REQUEST_BYTES_V1,
            MAX_REMOTE_PROPOSAL_SIGNER_RESPONSE_BYTES_V1,
        )?;
        let response = decode_unverified_remote_proposal_signer_response_v1_exact(
            &response_bytes,
            &wire_request,
        )
        .map_err(UnixRemoteSignerError::Protocol)?;
        let signature = response.unverified_signature_bytes();
        if !StrictEd25519Verifier.verify(validator, &request.signing_root(), &signature) {
            return Err(UnixRemoteSignerError::InvalidSignature);
        }
        Ok(signature)
    }

    fn call(
        &self,
        request_bytes: &[u8],
        maximum_request: usize,
        maximum_response: usize,
    ) -> Result<Vec<u8>, UnixRemoteSignerError> {
        if request_bytes.len() > maximum_request {
            return Err(UnixRemoteSignerError::FrameTooLarge {
                actual: request_bytes.len(),
                maximum: maximum_request,
            });
        }
        self.preflight()?;
        let mut stream = UnixStream::connect(&self.config.socket_path).map_err(|source| {
            UnixRemoteSignerError::Io {
                stage: "connect",
                source,
            }
        })?;
        stream
            .set_read_timeout(Some(self.config.timeout))
            .map_err(|source| UnixRemoteSignerError::Io {
                stage: "read timeout",
                source,
            })?;
        stream
            .set_write_timeout(Some(self.config.timeout))
            .map_err(|source| UnixRemoteSignerError::Io {
                stage: "write timeout",
                source,
            })?;
        write_frame(&mut stream, request_bytes)?;
        let framed = read_frame(
            &mut stream,
            maximum_response
                .checked_add(1)
                .expect("response frame bound does not overflow"),
        )?;
        if framed.first() == Some(&SERVICE_FRAME_OK) {
            if framed.len() == 1 {
                return Err(UnixRemoteSignerError::EmptyFrame);
            }
            return Ok(framed[1..].to_vec());
        }
        if framed.first() == Some(&SERVICE_FRAME_REJECT) {
            let code = framed.get(1).copied().unwrap_or_default();
            return Err(UnixRemoteSignerError::ServiceRejected(code));
        }
        Ok(framed)
    }
}

impl ProposalSignatureProducerV0 for UnixRemoteSignerProducer {
    fn sign_proposal(
        &mut self,
        request: ProposalSignatureRequestV0,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        self.sign_proposal_exact(request)
            .map_err(|error| match error {
                UnixRemoteSignerError::Io { source, .. }
                    if matches!(
                        source.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    SignatureProducerErrorV0::Unavailable
                }
                UnixRemoteSignerError::Io { .. } | UnixRemoteSignerError::SocketNotFound => {
                    SignatureProducerErrorV0::Unavailable
                }
                UnixRemoteSignerError::InvalidConfig(_)
                | UnixRemoteSignerError::SocketNotPrivate
                | UnixRemoteSignerError::FrameTooLarge { .. }
                | UnixRemoteSignerError::TruncatedFrame
                | UnixRemoteSignerError::EmptyFrame
                | UnixRemoteSignerError::Protocol(_)
                | UnixRemoteSignerError::InvalidSignerProfile
                | UnixRemoteSignerError::AuthorMismatch
                | UnixRemoteSignerError::InvalidSignature
                | UnixRemoteSignerError::ServiceRejected(_) => SignatureProducerErrorV0::Rejected,
            })
    }
}

impl SignatureProducerV0 for UnixRemoteSignerProducer {
    fn sign(
        &mut self,
        request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        self.sign_intent_with_profile(request.intent(), request.signer_profile_ref())
            .map_err(|error| match error {
                UnixRemoteSignerError::Io { source, .. }
                    if matches!(
                        source.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    SignatureProducerErrorV0::Unavailable
                }
                UnixRemoteSignerError::Io { .. } | UnixRemoteSignerError::SocketNotFound => {
                    SignatureProducerErrorV0::Unavailable
                }
                UnixRemoteSignerError::InvalidConfig(_)
                | UnixRemoteSignerError::SocketNotPrivate
                | UnixRemoteSignerError::FrameTooLarge { .. }
                | UnixRemoteSignerError::TruncatedFrame
                | UnixRemoteSignerError::EmptyFrame
                | UnixRemoteSignerError::Protocol(_)
                | UnixRemoteSignerError::InvalidSignerProfile
                | UnixRemoteSignerError::AuthorMismatch
                | UnixRemoteSignerError::InvalidSignature
                | UnixRemoteSignerError::ServiceRejected(_) => SignatureProducerErrorV0::Rejected,
            })
    }
}

fn derive_request_nonce(
    intent: &CanonicalSignIntentV0,
    signer_profile_ref: [u8; 32],
    binding: RemoteSignerRequestBindingV1,
) -> RemoteSignerRequestNonceV1 {
    let mut material = Vec::with_capacity(NONCE_DOMAIN.len() + 32 + 32 + 8 + 32);
    material.extend_from_slice(NONCE_DOMAIN);
    material.extend_from_slice(intent.fingerprint().as_bytes());
    material.extend_from_slice(&signer_profile_ref);
    material.extend_from_slice(&binding.process_generation().get().to_be_bytes());
    material.extend_from_slice(binding.lease_id().as_bytes());
    RemoteSignerRequestNonceV1::from_public_nonce_material(&material)
        .expect("bounded deterministic nonce material must be valid")
}

fn derive_proposal_request_nonce(
    request: &ProposalSignatureRequestV0,
    binding: RemoteSignerRequestBindingV1,
) -> RemoteSignerRequestNonceV1 {
    const DOMAIN: &[u8] = b"trnm.consensus.unix-remote-signer.proposal-request-nonce.v1\0";
    let mut material = Vec::with_capacity(DOMAIN.len() + 32 * 8 + 8 * 3);
    material.extend_from_slice(DOMAIN);
    material.extend_from_slice(request.proposal_id().as_bytes());
    material.extend_from_slice(request.parent_id().as_bytes());
    material.extend_from_slice(request.validator_set_id().as_bytes());
    material.extend_from_slice(request.author().as_bytes());
    material.extend_from_slice(&request.epoch().get().to_be_bytes());
    material.extend_from_slice(&request.view().get().to_be_bytes());
    material.extend_from_slice(&request.height().get().to_be_bytes());
    material.extend_from_slice(request.signing_root().as_bytes());
    material.extend_from_slice(&request.expected_consensus_public_key());
    material.extend_from_slice(&request.signer_profile_ref());
    material.extend_from_slice(&binding.process_generation().get().to_be_bytes());
    material.extend_from_slice(binding.lease_id().as_bytes());
    RemoteSignerRequestNonceV1::from_public_nonce_material(&material)
        .expect("bounded deterministic proposal nonce material must be valid")
}

fn write_frame(stream: &mut UnixStream, body: &[u8]) -> Result<(), UnixRemoteSignerError> {
    if body.is_empty() {
        return Err(UnixRemoteSignerError::EmptyFrame);
    }
    let length = u32::try_from(body.len()).map_err(|_| UnixRemoteSignerError::FrameTooLarge {
        actual: body.len(),
        maximum: u32::MAX as usize,
    })?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(body))
        .and_then(|_| stream.flush())
        .map_err(|source| UnixRemoteSignerError::Io {
            stage: "write frame",
            source,
        })
}

fn read_frame(stream: &mut UnixStream, maximum: usize) -> Result<Vec<u8>, UnixRemoteSignerError> {
    let mut header = [0u8; FRAME_HEADER_BYTES];
    stream.read_exact(&mut header).map_err(|source| {
        if source.kind() == io::ErrorKind::UnexpectedEof {
            UnixRemoteSignerError::TruncatedFrame
        } else {
            UnixRemoteSignerError::Io {
                stage: "read frame header",
                source,
            }
        }
    })?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(UnixRemoteSignerError::EmptyFrame);
    }
    if length > maximum {
        return Err(UnixRemoteSignerError::FrameTooLarge {
            actual: length,
            maximum,
        });
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).map_err(|source| {
        if source.kind() == io::ErrorKind::UnexpectedEof {
            UnixRemoteSignerError::TruncatedFrame
        } else {
            UnixRemoteSignerError::Io {
                stage: "read frame body",
                source,
            }
        }
    })?;
    Ok(body)
}

#[cfg(feature = "test-fixture")]
pub mod test_fixture;
#[cfg(feature = "test-fixture")]
pub use test_fixture::FixtureServerMode;

#[cfg(test)]
mod source_contract_tests {
    #[test]
    fn production_flags_and_default_manifest_are_closed() {
        const _: () = {
            assert!(!super::UNIX_REMOTE_SIGNER_RUNTIME_ACTIVATION_V1);
            assert!(!super::UNIX_REMOTE_SIGNER_PRIVATE_KEY_HANDLING_V1);
            assert!(!super::UNIX_REMOTE_SIGNER_SAFETY_RULES_AUTHORITY_V1);
            assert!(!super::UNIX_REMOTE_SIGNER_PRODUCTION_CANDIDATE_V1);
        };
        let manifest = include_str!("../Cargo.toml");
        assert!(manifest.contains("fixture_private_key = false"));
        assert!(manifest.contains("production_activation = false"));
        assert!(manifest.contains("required-features = [\"test-fixture\"]"));
    }
}
