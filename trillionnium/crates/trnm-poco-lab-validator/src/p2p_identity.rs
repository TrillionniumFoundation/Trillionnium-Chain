//! Typed external identity-signature boundary for authenticated P2P.
//!
//! The transport owns the handshake transcript and frame envelope.  A
//! deployed caller may therefore provide only this narrow producer instead of
//! placing a raw consensus/P2P `SigningKey` in the node process.  The request
//! carries the exact transcript context (including the receiver challenge and
//! derived session), while the transport verifies the returned signature
//! against the committed P2P role key before writing anything to the socket.

use std::fmt;

use trnm_consensus_types::ValidatorId;

/// Which authenticated transport record is being signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum P2pIdentitySignaturePurposeV1 {
    Challenge = 1,
    Hello = 2,
    Finished = 3,
    Frame = 4,
}

/// Exact typed request sent to an external P2P identity signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P2pIdentitySignatureRequestV1 {
    purpose: P2pIdentitySignaturePurposeV1,
    signer: ValidatorId,
    peer: Option<ValidatorId>,
    run_id_sha256: [u8; 32],
    network_context_digest: [u8; 32],
    session: [u8; 32],
    /// Receiver challenge nonce for `Challenge`, and the derived
    /// receiver/sender nonce binding for later records.
    nonce_binding: [u8; 32],
    signing_root: [u8; 32],
}

impl P2pIdentitySignatureRequestV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        purpose: P2pIdentitySignaturePurposeV1,
        signer: ValidatorId,
        peer: Option<ValidatorId>,
        run_id_sha256: [u8; 32],
        network_context_digest: [u8; 32],
        session: [u8; 32],
        nonce_binding: [u8; 32],
        signing_root: [u8; 32],
    ) -> Result<Self, P2pIdentityErrorV1> {
        if signer.is_zero() || run_id_sha256 == [0; 32] || signing_root == [0; 32] {
            return Err(P2pIdentityErrorV1::InvalidRequest);
        }
        if peer.is_some_and(|value| value.is_zero()) {
            return Err(P2pIdentityErrorV1::InvalidRequest);
        }
        Ok(Self {
            purpose,
            signer,
            peer,
            run_id_sha256,
            network_context_digest,
            session,
            nonce_binding,
            signing_root,
        })
    }

    pub const fn purpose(self) -> P2pIdentitySignaturePurposeV1 {
        self.purpose
    }

    pub const fn signer(self) -> ValidatorId {
        self.signer
    }

    pub const fn peer(self) -> Option<ValidatorId> {
        self.peer
    }

    pub const fn run_id_sha256(self) -> [u8; 32] {
        self.run_id_sha256
    }

    pub const fn network_context_digest(self) -> [u8; 32] {
        self.network_context_digest
    }

    pub const fn session(self) -> [u8; 32] {
        self.session
    }

    pub const fn nonce_binding(self) -> [u8; 32] {
        self.nonce_binding
    }

    pub const fn signing_root(self) -> [u8; 32] {
        self.signing_root
    }
}

/// Errors returned by an external identity signer.  The transport maps these
/// to a permanent fail-closed connection error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P2pIdentityErrorV1 {
    InvalidRequest,
    Unavailable,
    Rejected,
}

impl fmt::Display for P2pIdentityErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "external P2P identity request is invalid",
            Self::Unavailable => "external P2P identity signer is unavailable",
            Self::Rejected => "external P2P identity signer rejected the request",
        })
    }
}

impl std::error::Error for P2pIdentityErrorV1 {}

/// Producer seam used by the external authenticated transport constructors.
/// It exposes a public role key but never exposes private key bytes.
pub trait P2pIdentitySignatureProducerV1: Send {
    fn public_key_v1(&self) -> [u8; 32];

    fn sign_v1(
        &mut self,
        request: P2pIdentitySignatureRequestV1,
    ) -> Result<[u8; 64], P2pIdentityErrorV1>;
}
