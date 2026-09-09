//! Fail-closed production capability ports for the native validator host.
//!
//! These contracts deliberately provide no software signer, local watermark,
//! host-attestation bypass, wall clock, socket, or activation implementation.
//! A production composition must inject independently administered adapters.

use crate::{Digest32V0, NodeIdentityV0};
use std::{error::Error, fmt};

pub const MAX_HOST_ATTESTATION_BYTES_V0: usize = 64 * 1024;
pub const MAX_REMOTE_SIGNATURE_BYTES_V0: usize = 16 * 1024;
pub const MAX_PACEMAKER_DELAY_MILLIS_V0: u64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostAttestationClaimV0 {
    pub node_identity: NodeIdentityV0,
    pub executable_digest: Digest32V0,
    pub boot_measurement_digest: Digest32V0,
    pub policy_digest: Digest32V0,
    pub issued_generation: u64,
    pub expires_after_height: u64,
    pub evidence: Vec<u8>,
    pub evidence_digest: Digest32V0,
}

impl HostAttestationClaimV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.node.host-attestation-claim.v0",
            &[
                &self.node_identity.digest().0,
                &self.executable_digest.0,
                &self.boot_measurement_digest.0,
                &self.policy_digest.0,
                &self.issued_generation.to_be_bytes(),
                &self.expires_after_height.to_be_bytes(),
                &self.evidence,
            ],
        )
    }

    pub fn validate(
        &self,
        expected_identity: NodeIdentityV0,
        current_height: u64,
    ) -> Result<(), ProductionPortErrorV0> {
        expected_identity
            .validate()
            .map_err(|_| ProductionPortErrorV0::InvalidIdentity)?;
        if self.node_identity != expected_identity
            || self.executable_digest == Digest32V0([0; 32])
            || self.boot_measurement_digest == Digest32V0([0; 32])
            || self.policy_digest == Digest32V0([0; 32])
            || self.issued_generation != expected_identity.generation
            || current_height == 0
            || self.expires_after_height < current_height
            || self.evidence.is_empty()
            || self.evidence.len() > MAX_HOST_ATTESTATION_BYTES_V0
            || self.evidence_digest == Digest32V0([0; 32])
            || self.evidence_digest != self.canonical_digest()
        {
            return Err(ProductionPortErrorV0::InvalidHostAttestation);
        }
        Ok(())
    }
}

pub trait HostAttestationVerifierV0 {
    type Error: Error + Send + Sync + 'static;

    fn verify_host_attestation(
        &self,
        claim: &HostAttestationClaimV0,
    ) -> Result<(), Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedHostAttestationV0 {
    identity_digest: Digest32V0,
    evidence_digest: Digest32V0,
    executable_digest: Digest32V0,
    policy_digest: Digest32V0,
    expires_after_height: u64,
}

impl VerifiedHostAttestationV0 {
    #[must_use]
    pub const fn identity_digest(&self) -> Digest32V0 {
        self.identity_digest
    }

    #[must_use]
    pub const fn evidence_digest(&self) -> Digest32V0 {
        self.evidence_digest
    }

    #[must_use]
    pub const fn executable_digest(&self) -> Digest32V0 {
        self.executable_digest
    }

    #[must_use]
    pub const fn policy_digest(&self) -> Digest32V0 {
        self.policy_digest
    }

    #[must_use]
    pub const fn expires_after_height(&self) -> u64 {
        self.expires_after_height
    }
}

pub fn verify_host_attestation_v0<V>(
    verifier: &V,
    claim: HostAttestationClaimV0,
    expected_identity: NodeIdentityV0,
    current_height: u64,
) -> Result<VerifiedHostAttestationV0, HostAttestationErrorV0<V::Error>>
where
    V: HostAttestationVerifierV0,
{
    claim
        .validate(expected_identity, current_height)
        .map_err(HostAttestationErrorV0::Protocol)?;
    verifier
        .verify_host_attestation(&claim)
        .map_err(HostAttestationErrorV0::Verifier)?;
    Ok(VerifiedHostAttestationV0 {
        identity_digest: expected_identity.digest(),
        evidence_digest: claim.evidence_digest,
        executable_digest: claim.executable_digest,
        policy_digest: claim.policy_digest,
        expires_after_height: claim.expires_after_height,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalAnchorRecordV0 {
    pub identity_digest: Digest32V0,
    pub generation: u64,
    pub sequence: u64,
    pub value_digest: Digest32V0,
    pub previous_record_digest: Digest32V0,
    pub record_digest: Digest32V0,
}

impl ExternalAnchorRecordV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.node.external-anchor-record.v0",
            &[
                &self.identity_digest.0,
                &self.generation.to_be_bytes(),
                &self.sequence.to_be_bytes(),
                &self.value_digest.0,
                &self.previous_record_digest.0,
            ],
        )
    }

    pub fn validate_for(self, identity: NodeIdentityV0) -> Result<Self, ProductionPortErrorV0> {
        identity
            .validate()
            .map_err(|_| ProductionPortErrorV0::InvalidIdentity)?;
        if self.identity_digest != identity.digest()
            || self.generation != identity.generation
            || self.sequence == 0
            || self.value_digest == Digest32V0([0; 32])
            || (self.sequence == 1 && self.previous_record_digest != Digest32V0([0; 32]))
            || (self.sequence > 1 && self.previous_record_digest == Digest32V0([0; 32]))
            || self.record_digest == Digest32V0([0; 32])
            || self.record_digest != self.canonical_digest()
        {
            return Err(ProductionPortErrorV0::InvalidAnchorRecord);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalAnchorReceiptV0 {
    pub identity_digest: Digest32V0,
    pub previous_record_digest: Digest32V0,
    pub next_record_digest: Digest32V0,
    pub durable_receipt_digest: Digest32V0,
}

pub trait ExternalMonotonicAnchorPortV0 {
    type Error: Error + Send + Sync + 'static;

    fn read_current(
        &mut self,
        identity: NodeIdentityV0,
    ) -> Result<Option<ExternalAnchorRecordV0>, Self::Error>;

    fn compare_and_advance(
        &mut self,
        identity: NodeIdentityV0,
        expected: Option<ExternalAnchorRecordV0>,
        next: ExternalAnchorRecordV0,
    ) -> Result<ExternalAnchorReceiptV0, Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedAnchorAdvanceV0 {
    identity_digest: Digest32V0,
    previous_record_digest: Digest32V0,
    next_record_digest: Digest32V0,
    sequence: u64,
    value_digest: Digest32V0,
    durable_receipt_digest: Digest32V0,
}

impl VerifiedAnchorAdvanceV0 {
    #[must_use]
    pub const fn identity_digest(&self) -> Digest32V0 {
        self.identity_digest
    }

    #[must_use]
    pub const fn previous_record_digest(&self) -> Digest32V0 {
        self.previous_record_digest
    }

    #[must_use]
    pub const fn next_record_digest(&self) -> Digest32V0 {
        self.next_record_digest
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn value_digest(&self) -> Digest32V0 {
        self.value_digest
    }

    #[must_use]
    pub const fn durable_receipt_digest(&self) -> Digest32V0 {
        self.durable_receipt_digest
    }
}

pub fn advance_external_anchor_v0<A>(
    anchor: &mut A,
    identity: NodeIdentityV0,
    expected: Option<ExternalAnchorRecordV0>,
    next: ExternalAnchorRecordV0,
) -> Result<VerifiedAnchorAdvanceV0, AnchorAdvanceErrorV0<A::Error>>
where
    A: ExternalMonotonicAnchorPortV0,
{
    let next = next
        .validate_for(identity)
        .map_err(AnchorAdvanceErrorV0::Protocol)?;
    let expected_digest = expected.map_or(Digest32V0([0; 32]), |record| record.record_digest);
    match expected {
        Some(previous) => {
            let previous = previous
                .validate_for(identity)
                .map_err(AnchorAdvanceErrorV0::Protocol)?;
            let expected_sequence = previous.sequence.checked_add(1).ok_or(
                AnchorAdvanceErrorV0::Protocol(ProductionPortErrorV0::AnchorNotExactSuccessor),
            )?;
            if next.sequence != expected_sequence
                || next.previous_record_digest != previous.record_digest
            {
                return Err(AnchorAdvanceErrorV0::Protocol(
                    ProductionPortErrorV0::AnchorNotExactSuccessor,
                ));
            }
        }
        None => {
            if next.sequence != 1 || next.previous_record_digest != Digest32V0([0; 32]) {
                return Err(AnchorAdvanceErrorV0::Protocol(
                    ProductionPortErrorV0::AnchorNotExactSuccessor,
                ));
            }
        }
    }
    let receipt = anchor
        .compare_and_advance(identity, expected, next)
        .map_err(AnchorAdvanceErrorV0::Adapter)?;
    if receipt.identity_digest != identity.digest()
        || receipt.previous_record_digest != expected_digest
        || receipt.next_record_digest != next.record_digest
        || receipt.durable_receipt_digest == Digest32V0([0; 32])
    {
        return Err(AnchorAdvanceErrorV0::Protocol(
            ProductionPortErrorV0::AnchorReceiptMismatch,
        ));
    }
    Ok(VerifiedAnchorAdvanceV0 {
        identity_digest: identity.digest(),
        previous_record_digest: expected_digest,
        next_record_digest: next.record_digest,
        sequence: next.sequence,
        value_digest: next.value_digest,
        durable_receipt_digest: receipt.durable_receipt_digest,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ConsensusSignKindV0 {
    Proposal = 0,
    Vote = 1,
    Timeout = 2,
    EpochHandoff = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteSignRequestV0 {
    pub node_identity: NodeIdentityV0,
    pub epoch: u64,
    pub view: u64,
    pub kind: ConsensusSignKindV0,
    pub message_digest: Digest32V0,
    pub safety_state_digest: Digest32V0,
    pub anchor_record_digest: Digest32V0,
    pub request_digest: Digest32V0,
}

impl RemoteSignRequestV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.node.remote-sign-request.v0",
            &[
                &self.node_identity.digest().0,
                &self.epoch.to_be_bytes(),
                &self.view.to_be_bytes(),
                &[self.kind as u8],
                &self.message_digest.0,
                &self.safety_state_digest.0,
                &self.anchor_record_digest.0,
            ],
        )
    }

    pub fn validate(self) -> Result<Self, ProductionPortErrorV0> {
        self.node_identity
            .validate()
            .map_err(|_| ProductionPortErrorV0::InvalidIdentity)?;
        if self.epoch == 0
            || self.message_digest == Digest32V0([0; 32])
            || self.safety_state_digest == Digest32V0([0; 32])
            || self.anchor_record_digest == Digest32V0([0; 32])
            || self.request_digest == Digest32V0([0; 32])
            || self.request_digest != self.canonical_digest()
        {
            return Err(ProductionPortErrorV0::InvalidSignRequest);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteSignatureReceiptV0 {
    pub request_digest: Digest32V0,
    pub anchor_record_digest: Digest32V0,
    pub signature: Vec<u8>,
    pub signature_digest: Digest32V0,
    pub signer_attestation_digest: Digest32V0,
    pub receipt_digest: Digest32V0,
}

impl RemoteSignatureReceiptV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.node.remote-signature-receipt.v0",
            &[
                &self.request_digest.0,
                &self.anchor_record_digest.0,
                &self.signature,
                &self.signer_attestation_digest.0,
            ],
        )
    }
}

pub trait RemoteConsensusSignerV0 {
    type Error: Error + Send + Sync + 'static;

    fn sign_remote(
        &mut self,
        request: &RemoteSignRequestV0,
    ) -> Result<RemoteSignatureReceiptV0, Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedRemoteSignatureV0 {
    request_digest: Digest32V0,
    anchor_record_digest: Digest32V0,
    signature_digest: Digest32V0,
    signer_attestation_digest: Digest32V0,
    receipt_digest: Digest32V0,
}

impl VerifiedRemoteSignatureV0 {
    #[must_use]
    pub const fn request_digest(&self) -> Digest32V0 {
        self.request_digest
    }

    #[must_use]
    pub const fn anchor_record_digest(&self) -> Digest32V0 {
        self.anchor_record_digest
    }

    #[must_use]
    pub const fn signature_digest(&self) -> Digest32V0 {
        self.signature_digest
    }

    #[must_use]
    pub const fn signer_attestation_digest(&self) -> Digest32V0 {
        self.signer_attestation_digest
    }

    #[must_use]
    pub const fn receipt_digest(&self) -> Digest32V0 {
        self.receipt_digest
    }
}

pub fn sign_with_verified_anchor_v0<S>(
    signer: &mut S,
    request: RemoteSignRequestV0,
    anchor: &VerifiedAnchorAdvanceV0,
) -> Result<VerifiedRemoteSignatureV0, RemoteSigningErrorV0<S::Error>>
where
    S: RemoteConsensusSignerV0,
{
    let request = request
        .validate()
        .map_err(RemoteSigningErrorV0::Protocol)?;
    if request.node_identity.digest() != anchor.identity_digest()
        || request.anchor_record_digest != anchor.next_record_digest()
        || request.message_digest != anchor.value_digest()
    {
        return Err(RemoteSigningErrorV0::Protocol(
            ProductionPortErrorV0::SignRequestAnchorMismatch,
        ));
    }
    let receipt = signer
        .sign_remote(&request)
        .map_err(RemoteSigningErrorV0::Adapter)?;
    if receipt.request_digest != request.request_digest
        || receipt.anchor_record_digest != request.anchor_record_digest
        || receipt.signature.is_empty()
        || receipt.signature.len() > MAX_REMOTE_SIGNATURE_BYTES_V0
        || receipt.signature_digest
            != Digest32V0::hash(b"trnm.node.remote-signature-bytes.v0", &[&receipt.signature])
        || receipt.signer_attestation_digest == Digest32V0([0; 32])
        || receipt.receipt_digest == Digest32V0([0; 32])
        || receipt.receipt_digest != receipt.canonical_digest()
    {
        return Err(RemoteSigningErrorV0::Protocol(
            ProductionPortErrorV0::SignatureReceiptMismatch,
        ));
    }
    Ok(VerifiedRemoteSignatureV0 {
        request_digest: receipt.request_digest,
        anchor_record_digest: receipt.anchor_record_digest,
        signature_digest: receipt.signature_digest,
        signer_attestation_digest: receipt.signer_attestation_digest,
        receipt_digest: receipt.receipt_digest,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacemakerArmV0 {
    pub node_identity_digest: Digest32V0,
    pub epoch: u64,
    pub view: u64,
    pub generation: u64,
    pub absolute_deadline_millis: u64,
    pub arm_digest: Digest32V0,
}

impl PacemakerArmV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.node.persistent-pacemaker-arm.v0",
            &[
                &self.node_identity_digest.0,
                &self.epoch.to_be_bytes(),
                &self.view.to_be_bytes(),
                &self.generation.to_be_bytes(),
                &self.absolute_deadline_millis.to_be_bytes(),
            ],
        )
    }

    pub fn validate(self, identity: NodeIdentityV0) -> Result<Self, ProductionPortErrorV0> {
        if self.node_identity_digest != identity.digest()
            || self.epoch == 0
            || self.generation != identity.generation
            || self.absolute_deadline_millis == 0
            || self.arm_digest == Digest32V0([0; 32])
            || self.arm_digest != self.canonical_digest()
        {
            return Err(ProductionPortErrorV0::InvalidPacemakerArm);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacemakerPollV0 {
    Idle,
    Armed(PacemakerArmV0),
    Fired(PacemakerArmV0),
}

pub trait PersistentPacemakerPortV0 {
    type Error: Error + Send + Sync + 'static;

    fn recover_pacemaker(
        &mut self,
        identity: NodeIdentityV0,
    ) -> Result<Option<PacemakerArmV0>, Self::Error>;
    fn arm_pacemaker(
        &mut self,
        identity: NodeIdentityV0,
        arm: PacemakerArmV0,
    ) -> Result<PacemakerArmV0, Self::Error>;
    fn poll_pacemaker(
        &mut self,
        identity: NodeIdentityV0,
    ) -> Result<PacemakerPollV0, Self::Error>;
    fn acknowledge_pacemaker_fire(
        &mut self,
        identity: NodeIdentityV0,
        arm_digest: Digest32V0,
    ) -> Result<(), Self::Error>;
}

/// Complete repository-side security port set for a production validator.
///
/// The type intentionally implements neither `Default` nor `Clone`. No in-tree
/// software fallback is supplied. Adapters remain externally administered and
/// independently reviewable.
pub struct ProductionSecurityPortsV0<S, A, H, P> {
    signer: S,
    anchor: A,
    host_attestation: H,
    pacemaker: P,
}

impl<S, A, H, P> ProductionSecurityPortsV0<S, A, H, P>
where
    S: RemoteConsensusSignerV0,
    A: ExternalMonotonicAnchorPortV0,
    H: HostAttestationVerifierV0,
    P: PersistentPacemakerPortV0,
{
    #[must_use]
    pub fn new(signer: S, anchor: A, host_attestation: H, pacemaker: P) -> Self {
        Self {
            signer,
            anchor,
            host_attestation,
            pacemaker,
        }
    }

    pub fn verify_startup(
        &mut self,
        identity: NodeIdentityV0,
        claim: HostAttestationClaimV0,
        current_height: u64,
    ) -> Result<VerifiedProductionStartupV0, ProductionStartupErrorV0<H::Error, A::Error>> {
        let attestation = verify_host_attestation_v0(
            &self.host_attestation,
            claim,
            identity,
            current_height,
        )
        .map_err(ProductionStartupErrorV0::Attestation)?;
        let anchor = self
            .anchor
            .read_current(identity)
            .map_err(ProductionStartupErrorV0::Anchor)?
            .ok_or(ProductionStartupErrorV0::Protocol(
                ProductionPortErrorV0::MissingExternalAnchor,
            ))?
            .validate_for(identity)
            .map_err(ProductionStartupErrorV0::Protocol)?;
        Ok(VerifiedProductionStartupV0 {
            identity,
            host_attestation_digest: attestation.evidence_digest(),
            executable_digest: attestation.executable_digest(),
            policy_digest: attestation.policy_digest(),
            anchor,
        })
    }

    pub fn anchor_and_sign(
        &mut self,
        startup: VerifiedProductionStartupV0,
        next_anchor: ExternalAnchorRecordV0,
        request: RemoteSignRequestV0,
    ) -> Result<
        (VerifiedProductionStartupV0, VerifiedRemoteSignatureV0),
        ProductionSignErrorV0<A::Error, S::Error>,
    > {
        let verified_anchor = advance_external_anchor_v0(
            &mut self.anchor,
            startup.identity,
            Some(startup.anchor),
            next_anchor,
        )
        .map_err(ProductionSignErrorV0::Anchor)?;
        let next_startup = VerifiedProductionStartupV0 {
            identity: startup.identity,
            host_attestation_digest: startup.host_attestation_digest,
            executable_digest: startup.executable_digest,
            policy_digest: startup.policy_digest,
            anchor: next_anchor,
        };
        let signature = sign_with_verified_anchor_v0(&mut self.signer, request, &verified_anchor)
            .map_err(ProductionSignErrorV0::Signer)?;
        Ok((next_startup, signature))
    }

    pub fn pacemaker_mut(&mut self) -> &mut P {
        &mut self.pacemaker
    }

    pub fn into_parts(self) -> (S, A, H, P) {
        (self.signer, self.anchor, self.host_attestation, self.pacemaker)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedProductionStartupV0 {
    identity: NodeIdentityV0,
    host_attestation_digest: Digest32V0,
    executable_digest: Digest32V0,
    policy_digest: Digest32V0,
    anchor: ExternalAnchorRecordV0,
}

impl VerifiedProductionStartupV0 {
    #[must_use]
    pub const fn identity(&self) -> NodeIdentityV0 {
        self.identity
    }

    #[must_use]
    pub const fn host_attestation_digest(&self) -> Digest32V0 {
        self.host_attestation_digest
    }

    #[must_use]
    pub const fn executable_digest(&self) -> Digest32V0 {
        self.executable_digest
    }

    #[must_use]
    pub const fn policy_digest(&self) -> Digest32V0 {
        self.policy_digest
    }

    #[must_use]
    pub const fn anchor(&self) -> ExternalAnchorRecordV0 {
        self.anchor
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionPortErrorV0 {
    InvalidIdentity,
    InvalidHostAttestation,
    MissingExternalAnchor,
    InvalidAnchorRecord,
    AnchorNotExactSuccessor,
    AnchorReceiptMismatch,
    InvalidSignRequest,
    SignRequestAnchorMismatch,
    SignatureReceiptMismatch,
    InvalidPacemakerArm,
}

impl fmt::Display for ProductionPortErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidIdentity => "production port identity is invalid",
            Self::InvalidHostAttestation => "host attestation is malformed, stale, or misbound",
            Self::MissingExternalAnchor => "external monotonic anchor is absent",
            Self::InvalidAnchorRecord => "external monotonic anchor record is invalid",
            Self::AnchorNotExactSuccessor => "external anchor is not the exact successor",
            Self::AnchorReceiptMismatch => "external anchor durable receipt is misbound",
            Self::InvalidSignRequest => "remote consensus sign request is invalid",
            Self::SignRequestAnchorMismatch => "remote sign request is not bound to the verified anchor",
            Self::SignatureReceiptMismatch => "remote signature receipt is malformed or substituted",
            Self::InvalidPacemakerArm => "persistent pacemaker arm is invalid",
        })
    }
}

impl Error for ProductionPortErrorV0 {}

#[derive(Debug)]
pub enum HostAttestationErrorV0<E> {
    Protocol(ProductionPortErrorV0),
    Verifier(E),
}

impl<E: fmt::Display> fmt::Display for HostAttestationErrorV0<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "host attestation rejected: {error}"),
            Self::Verifier(error) => write!(f, "host attestation verifier failed: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for HostAttestationErrorV0<E> {}

#[derive(Debug)]
pub enum AnchorAdvanceErrorV0<E> {
    Protocol(ProductionPortErrorV0),
    Adapter(E),
}

impl<E: fmt::Display> fmt::Display for AnchorAdvanceErrorV0<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "external anchor rejected: {error}"),
            Self::Adapter(error) => write!(f, "external anchor adapter failed: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for AnchorAdvanceErrorV0<E> {}

#[derive(Debug)]
pub enum RemoteSigningErrorV0<E> {
    Protocol(ProductionPortErrorV0),
    Adapter(E),
}

impl<E: fmt::Display> fmt::Display for RemoteSigningErrorV0<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "remote signing rejected: {error}"),
            Self::Adapter(error) => write!(f, "remote signer failed: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for RemoteSigningErrorV0<E> {}

#[derive(Debug)]
pub enum ProductionStartupErrorV0<HostError, AnchorError> {
    Protocol(ProductionPortErrorV0),
    Attestation(HostAttestationErrorV0<HostError>),
    Anchor(AnchorError),
}

impl<H: fmt::Display, A: fmt::Display> fmt::Display for ProductionStartupErrorV0<H, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "production startup rejected: {error}"),
            Self::Attestation(error) => write!(f, "production startup attestation failed: {error}"),
            Self::Anchor(error) => write!(f, "production startup anchor read failed: {error}"),
        }
    }
}

impl<H, A> Error for ProductionStartupErrorV0<H, A>
where
    H: Error + 'static,
    A: Error + 'static,
{
}

#[derive(Debug)]
pub enum ProductionSignErrorV0<AnchorError, SignerError> {
    Anchor(AnchorAdvanceErrorV0<AnchorError>),
    Signer(RemoteSigningErrorV0<SignerError>),
}

impl<A: fmt::Display, S: fmt::Display> fmt::Display for ProductionSignErrorV0<A, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anchor(error) => write!(f, "production signing anchor failed: {error}"),
            Self::Signer(error) => write!(f, "production remote signing failed: {error}"),
        }
    }
}

impl<A, S> Error for ProductionSignErrorV0<A, S>
where
    A: Error + 'static,
    S: Error + 'static,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    fn d(byte: u8) -> Digest32V0 {
        Digest32V0([byte; 32])
    }

    fn identity() -> NodeIdentityV0 {
        NodeIdentityV0 {
            chain_id: d(1),
            validator_id: d(2),
            application_id: d(3),
            generation: 7,
        }
    }

    fn anchor_record(
        sequence: u64,
        previous_record_digest: Digest32V0,
        value_digest: Digest32V0,
    ) -> ExternalAnchorRecordV0 {
        let mut record = ExternalAnchorRecordV0 {
            identity_digest: identity().digest(),
            generation: identity().generation,
            sequence,
            value_digest,
            previous_record_digest,
            record_digest: d(0),
        };
        record.record_digest = record.canonical_digest();
        record
    }

    struct AcceptHost;

    impl HostAttestationVerifierV0 for AcceptHost {
        type Error = Infallible;

        fn verify_host_attestation(
            &self,
            _claim: &HostAttestationClaimV0,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct MemoryAnchor {
        current: Option<ExternalAnchorRecordV0>,
    }

    impl ExternalMonotonicAnchorPortV0 for MemoryAnchor {
        type Error = Infallible;

        fn read_current(
            &mut self,
            _identity: NodeIdentityV0,
        ) -> Result<Option<ExternalAnchorRecordV0>, Self::Error> {
            Ok(self.current)
        }

        fn compare_and_advance(
            &mut self,
            identity: NodeIdentityV0,
            expected: Option<ExternalAnchorRecordV0>,
            next: ExternalAnchorRecordV0,
        ) -> Result<ExternalAnchorReceiptV0, Self::Error> {
            assert_eq!(self.current, expected);
            self.current = Some(next);
            Ok(ExternalAnchorReceiptV0 {
                identity_digest: identity.digest(),
                previous_record_digest: expected
                    .map_or(Digest32V0([0; 32]), |record| record.record_digest),
                next_record_digest: next.record_digest,
                durable_receipt_digest: d(90),
            })
        }
    }

    struct MemorySigner;

    impl RemoteConsensusSignerV0 for MemorySigner {
        type Error = Infallible;

        fn sign_remote(
            &mut self,
            request: &RemoteSignRequestV0,
        ) -> Result<RemoteSignatureReceiptV0, Self::Error> {
            let signature = vec![5; 64];
            let mut receipt = RemoteSignatureReceiptV0 {
                request_digest: request.request_digest,
                anchor_record_digest: request.anchor_record_digest,
                signature_digest: Digest32V0::hash(
                    b"trnm.node.remote-signature-bytes.v0",
                    &[&signature],
                ),
                signature,
                signer_attestation_digest: d(91),
                receipt_digest: d(0),
            };
            receipt.receipt_digest = receipt.canonical_digest();
            Ok(receipt)
        }
    }

    struct MemoryPacemaker;

    impl PersistentPacemakerPortV0 for MemoryPacemaker {
        type Error = Infallible;

        fn recover_pacemaker(
            &mut self,
            _identity: NodeIdentityV0,
        ) -> Result<Option<PacemakerArmV0>, Self::Error> {
            Ok(None)
        }

        fn arm_pacemaker(
            &mut self,
            _identity: NodeIdentityV0,
            arm: PacemakerArmV0,
        ) -> Result<PacemakerArmV0, Self::Error> {
            Ok(arm)
        }

        fn poll_pacemaker(
            &mut self,
            _identity: NodeIdentityV0,
        ) -> Result<PacemakerPollV0, Self::Error> {
            Ok(PacemakerPollV0::Idle)
        }

        fn acknowledge_pacemaker_fire(
            &mut self,
            _identity: NodeIdentityV0,
            _arm_digest: Digest32V0,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn startup_requires_external_attestation_and_anchor() {
        let claim_evidence = vec![7, 8, 9];
        let mut claim = HostAttestationClaimV0 {
            node_identity: identity(),
            executable_digest: d(4),
            boot_measurement_digest: d(5),
            policy_digest: d(6),
            issued_generation: identity().generation,
            expires_after_height: 100,
            evidence: claim_evidence,
            evidence_digest: d(0),
        };
        claim.evidence_digest = claim.canonical_digest();
        let first_anchor = anchor_record(1, d(0), d(40));
        let mut ports = ProductionSecurityPortsV0::new(
            MemorySigner,
            MemoryAnchor {
                current: Some(first_anchor),
            },
            AcceptHost,
            MemoryPacemaker,
        );
        let evidence_digest = claim.evidence_digest;
        let startup = ports.verify_startup(identity(), claim, 50).unwrap();
        assert_eq!(startup.anchor(), first_anchor);
        assert_eq!(startup.host_attestation_digest(), evidence_digest);
    }

    #[test]
    fn anchor_must_advance_before_remote_signing() {
        let first_anchor = anchor_record(1, d(0), d(40));
        let next_anchor = anchor_record(2, first_anchor.record_digest, d(41));
        let claim_evidence = vec![7, 8, 9];
        let mut claim = HostAttestationClaimV0 {
            node_identity: identity(),
            executable_digest: d(4),
            boot_measurement_digest: d(5),
            policy_digest: d(6),
            issued_generation: identity().generation,
            expires_after_height: 100,
            evidence: claim_evidence,
            evidence_digest: d(0),
        };
        claim.evidence_digest = claim.canonical_digest();
        let mut ports = ProductionSecurityPortsV0::new(
            MemorySigner,
            MemoryAnchor {
                current: Some(first_anchor),
            },
            AcceptHost,
            MemoryPacemaker,
        );
        let startup = ports.verify_startup(identity(), claim, 50).unwrap();
        let mut request = RemoteSignRequestV0 {
            node_identity: identity(),
            epoch: 2,
            view: 11,
            kind: ConsensusSignKindV0::Vote,
            message_digest: next_anchor.value_digest,
            safety_state_digest: d(42),
            anchor_record_digest: next_anchor.record_digest,
            request_digest: d(0),
        };
        request.request_digest = request.canonical_digest();
        let (startup, signature) = ports
            .anchor_and_sign(startup, next_anchor, request)
            .unwrap();
        assert_eq!(startup.anchor(), next_anchor);
        assert_eq!(signature.request_digest(), request.request_digest);
        assert_eq!(signature.anchor_record_digest(), next_anchor.record_digest);
    }

    #[test]
    fn stale_attestation_and_anchor_substitution_fail_closed() {
        let evidence = vec![1];
        let mut claim = HostAttestationClaimV0 {
            node_identity: identity(),
            executable_digest: d(4),
            boot_measurement_digest: d(5),
            policy_digest: d(6),
            issued_generation: identity().generation,
            expires_after_height: 10,
            evidence,
            evidence_digest: d(0),
        };
        claim.evidence_digest = claim.canonical_digest();
        assert!(matches!(
            verify_host_attestation_v0(&AcceptHost, claim, identity(), 11),
            Err(HostAttestationErrorV0::Protocol(
                ProductionPortErrorV0::InvalidHostAttestation
            ))
        ));

        let first = anchor_record(1, d(0), d(40));
        let skipped = anchor_record(3, first.record_digest, d(41));
        let mut anchor = MemoryAnchor {
            current: Some(first),
        };
        assert!(matches!(
            advance_external_anchor_v0(&mut anchor, identity(), Some(first), skipped),
            Err(AnchorAdvanceErrorV0::Protocol(
                ProductionPortErrorV0::AnchorNotExactSuccessor
            ))
        ));
    }
}
