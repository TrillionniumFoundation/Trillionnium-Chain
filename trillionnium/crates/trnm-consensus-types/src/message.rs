use alloc::{boxed::Box, vec::Vec};

use subtle::ConstantTimeEq;

use crate::{
    canonical::{
        canonical_hash, signing_root, try_canonical_bytes, CanonicalSignable, Encoder,
        DOMAIN_PROPOSAL, DOMAIN_SIGN_INTENT, DOMAIN_TIMEOUT, DOMAIN_VOTE,
    },
    Block, BlockId, CertificateId, ChainId, CommonConsensusContextV0, Epoch, Height, MessageKind,
    ProtocolVersion, QuorumCertificate, Result, SignatureBytes, SignatureVerifier, SigningRoot,
    TimeoutCertificate, ValidationError, ValidatorId, ValidatorSet, ValidatorSetId, View,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct QcRef {
    qc_digest: CertificateId,
    epoch: Epoch,
    view: View,
    height: Height,
    block_id: BlockId,
    validator_set_id: ValidatorSetId,
}

impl QcRef {
    pub const fn new(
        qc_digest: CertificateId,
        epoch: Epoch,
        view: View,
        height: Height,
        block_id: BlockId,
        validator_set_id: ValidatorSetId,
    ) -> Self {
        Self {
            qc_digest,
            epoch,
            view,
            height,
            block_id,
            validator_set_id,
        }
    }

    pub const fn qc_digest(&self) -> CertificateId {
        self.qc_digest
    }

    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub const fn view(&self) -> View {
        self.view
    }

    pub const fn height(&self) -> Height {
        self.height
    }

    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }
}

impl From<&QuorumCertificate> for QcRef {
    fn from(value: &QuorumCertificate) -> Self {
        Self::new(
            value.id(),
            value.epoch(),
            value.view(),
            value.height(),
            value.block_id(),
            value.validator_set_id(),
        )
    }
}

/// Frozen schema version for the Core-to-signer authorization envelope.
pub const CANONICAL_SIGN_INTENT_SCHEMA_VERSION_V0: u16 = 0;

/// Hash of every immutable field in one [`CanonicalSignIntentV0`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignIntentFingerprintV0([u8; 32]);

impl SignIntentFingerprintV0 {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Exact CEV0 bytes hashed by a validator vote signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteSignPreimageV0 {
    context: CommonConsensusContextV0,
    height: Height,
    block_id: BlockId,
}

impl VoteSignPreimageV0 {
    pub fn for_validator_set(
        validator_set: &ValidatorSet,
        view: View,
        height: Height,
        block_id: BlockId,
    ) -> Result<Self> {
        let value = Self {
            context: validator_set.consensus_context(view, MessageKind::Vote)?,
            height,
            block_id,
        };
        value.validate(validator_set)?;
        Ok(value)
    }

    pub const fn context(&self) -> CommonConsensusContextV0 {
        self.context
    }

    pub const fn view(&self) -> View {
        self.context.view()
    }

    pub const fn height(&self) -> Height {
        self.height
    }

    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode(encoder))
    }

    pub fn signing_root(&self) -> SigningRoot {
        signing_root(DOMAIN_VOTE, |encoder| self.encode(encoder))
    }

    pub fn validate(&self, validator_set: &ValidatorSet) -> Result<()> {
        validate_sign_context(self.context, MessageKind::Vote, validator_set)
    }

    fn encode(&self, encoder: &mut Encoder) {
        self.context.encode(encoder);
        encoder.u64(self.height.get());
        encoder.fixed(self.block_id.as_bytes());
    }
}

/// Exact CEV0 bytes hashed by a validator timeout-vote signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutVoteSignPreimageV0 {
    context: CommonConsensusContextV0,
    high_qc: QcRef,
}

impl TimeoutVoteSignPreimageV0 {
    pub fn for_validator_set(
        validator_set: &ValidatorSet,
        view: View,
        high_qc: QcRef,
    ) -> Result<Self> {
        let value = Self {
            context: validator_set.consensus_context(view, MessageKind::Timeout)?,
            high_qc,
        };
        value.validate(validator_set)?;
        Ok(value)
    }

    pub const fn context(&self) -> CommonConsensusContextV0 {
        self.context
    }

    pub const fn view(&self) -> View {
        self.context.view()
    }

    pub const fn high_qc(&self) -> QcRef {
        self.high_qc
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode(encoder))
    }

    pub fn signing_root(&self) -> SigningRoot {
        signing_root(DOMAIN_TIMEOUT, |encoder| self.encode(encoder))
    }

    pub fn validate(&self, validator_set: &ValidatorSet) -> Result<()> {
        validate_sign_context(self.context, MessageKind::Timeout, validator_set)?;
        if self.high_qc.epoch != self.context.epoch()
            || self.high_qc.validator_set_id != self.context.validator_set_hash()
        {
            return Err(ValidationError::CertificateMismatch);
        }
        if self.high_qc.view > self.context.view() {
            return Err(ValidationError::InvalidCertificate(
                "timeout high QC is ahead of timeout view",
            ));
        }
        Ok(())
    }

    fn encode(&self, encoder: &mut Encoder) {
        self.context.encode(encoder);
        encode_qc_ref(encoder, self.high_qc);
    }
}

/// Closed set of signable preimages accepted by the PoCO-BFT v0 signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalSignPreimageV0 {
    Vote(VoteSignPreimageV0),
    TimeoutVote(TimeoutVoteSignPreimageV0),
}

impl CanonicalSignPreimageV0 {
    pub const fn context(&self) -> CommonConsensusContextV0 {
        match self {
            Self::Vote(value) => value.context(),
            Self::TimeoutVote(value) => value.context(),
        }
    }

    pub fn signing_root(&self) -> SigningRoot {
        match self {
            Self::Vote(value) => value.signing_root(),
            Self::TimeoutVote(value) => value.signing_root(),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Vote(value) => value.canonical_bytes(),
            Self::TimeoutVote(value) => value.canonical_bytes(),
        }
    }

    pub fn validate(&self, validator_set: &ValidatorSet) -> Result<()> {
        match self {
            Self::Vote(value) => value.validate(validator_set),
            Self::TimeoutVote(value) => value.validate(validator_set),
        }
    }

    fn tag(&self) -> u8 {
        match self {
            Self::Vote(_) => 0,
            Self::TimeoutVote(_) => 1,
        }
    }

    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(self.tag());
        match self {
            Self::Vote(value) => value.encode(encoder),
            Self::TimeoutVote(value) => value.encode(encoder),
        }
    }
}

/// Complete immutable Core authorization passed to an independent signer.
///
/// The signer must validate this envelope against its configured validator
/// set and monotonic journal before producing or replaying a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalSignIntentV0 {
    schema_version: u16,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_id: ValidatorSetId,
    author: ValidatorId,
    authorizing_safety_revision: u64,
    preimage: CanonicalSignPreimageV0,
    signing_root: SigningRoot,
    fingerprint: SignIntentFingerprintV0,
}

impl CanonicalSignIntentV0 {
    pub fn vote(
        validator_set: &ValidatorSet,
        author: ValidatorId,
        authorizing_safety_revision: u64,
        view: View,
        height: Height,
        block_id: BlockId,
    ) -> Result<Self> {
        Self::new(
            validator_set,
            author,
            authorizing_safety_revision,
            CanonicalSignPreimageV0::Vote(VoteSignPreimageV0::for_validator_set(
                validator_set,
                view,
                height,
                block_id,
            )?),
        )
    }

    pub fn timeout_vote(
        validator_set: &ValidatorSet,
        author: ValidatorId,
        authorizing_safety_revision: u64,
        view: View,
        high_qc: QcRef,
    ) -> Result<Self> {
        Self::new(
            validator_set,
            author,
            authorizing_safety_revision,
            CanonicalSignPreimageV0::TimeoutVote(TimeoutVoteSignPreimageV0::for_validator_set(
                validator_set,
                view,
                high_qc,
            )?),
        )
    }

    fn new(
        validator_set: &ValidatorSet,
        author: ValidatorId,
        authorizing_safety_revision: u64,
        preimage: CanonicalSignPreimageV0,
    ) -> Result<Self> {
        if authorizing_safety_revision == 0 {
            return Err(ValidationError::InvalidSignIntent(
                "authorizing SafetyState revision must be positive",
            ));
        }
        preimage.validate(validator_set)?;
        if validator_set.validator(author).is_none() {
            return Err(ValidationError::UnknownValidator(Box::new(author)));
        }
        let context = preimage.context();
        let mut value = Self {
            schema_version: CANONICAL_SIGN_INTENT_SCHEMA_VERSION_V0,
            chain_id: context.chain_id(),
            protocol_version: context.protocol_version(),
            epoch: context.epoch(),
            validator_set_id: context.validator_set_hash(),
            author,
            authorizing_safety_revision,
            signing_root: preimage.signing_root(),
            preimage,
            fingerprint: SignIntentFingerprintV0::new([0; 32]),
        };
        value.fingerprint = value.recompute_fingerprint();
        value.validate(validator_set)?;
        Ok(value)
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn author(&self) -> ValidatorId {
        self.author
    }

    pub const fn authorizing_safety_revision(&self) -> u64 {
        self.authorizing_safety_revision
    }

    pub const fn preimage(&self) -> &CanonicalSignPreimageV0 {
        &self.preimage
    }

    pub const fn signing_root(&self) -> SigningRoot {
        self.signing_root
    }

    pub const fn fingerprint(&self) -> SignIntentFingerprintV0 {
        self.fingerprint
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| {
            self.encode_fingerprint_preimage(encoder);
            encoder.fixed(self.fingerprint.as_bytes());
        })
    }

    pub fn validate(&self, validator_set: &ValidatorSet) -> Result<()> {
        if self.schema_version != CANONICAL_SIGN_INTENT_SCHEMA_VERSION_V0 {
            return Err(ValidationError::InvalidSchemaVersion {
                actual: self.schema_version,
                expected: CANONICAL_SIGN_INTENT_SCHEMA_VERSION_V0,
            });
        }
        if self.authorizing_safety_revision == 0 {
            return Err(ValidationError::InvalidSignIntent(
                "authorizing SafetyState revision must be positive",
            ));
        }
        self.preimage.validate(validator_set)?;
        let context = self.preimage.context();
        if self.chain_id != context.chain_id()
            || self.protocol_version != context.protocol_version()
            || self.epoch != context.epoch()
            || self.validator_set_id != context.validator_set_hash()
        {
            return Err(ValidationError::ConsensusContextMismatch);
        }
        if validator_set.validator(self.author).is_none() {
            return Err(ValidationError::UnknownValidator(Box::new(self.author)));
        }
        if self
            .signing_root
            .as_bytes()
            .ct_eq(self.preimage.signing_root().as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(ValidationError::InvalidSignIntent(
                "signing root does not match canonical preimage",
            ));
        }
        if self
            .fingerprint
            .as_bytes()
            .ct_eq(self.recompute_fingerprint().as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(ValidationError::InvalidSignIntent(
                "intent fingerprint does not match immutable fields",
            ));
        }
        Ok(())
    }

    fn recompute_fingerprint(&self) -> SignIntentFingerprintV0 {
        SignIntentFingerprintV0::new(canonical_hash(DOMAIN_SIGN_INTENT, |encoder| {
            self.encode_fingerprint_preimage(encoder);
        }))
    }

    fn encode_fingerprint_preimage(&self, encoder: &mut Encoder) {
        encoder.u16(self.schema_version);
        encoder.consensus_string(self.chain_id.as_bytes());
        encoder.u32(self.protocol_version.get());
        encoder.u64(self.epoch.get());
        encoder.fixed(self.validator_set_id.as_bytes());
        encoder.bytes(self.author.as_bytes());
        encoder.u64(self.authorizing_safety_revision);
        self.preimage.encode(encoder);
        encoder.fixed(self.signing_root.as_bytes());
    }
}

fn validate_sign_context(
    context: CommonConsensusContextV0,
    expected_kind: MessageKind,
    validator_set: &ValidatorSet,
) -> Result<()> {
    validate_set_binding(
        context.chain_id(),
        context.protocol_version(),
        context.epoch(),
        context.validator_set_hash(),
        validator_set,
    )?;
    context.require_kind(expected_kind)?;
    if context.genesis_hash() != validator_set.genesis_hash() {
        return Err(ValidationError::GenesisHashMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    context: CommonConsensusContextV0,
    height: Height,
    block_id: BlockId,
    validator_set_id: ValidatorSetId,
    author: ValidatorId,
    signature: SignatureBytes,
}

impl Vote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        view: View,
        height: Height,
        block_id: BlockId,
        validator_set_id: ValidatorSetId,
        author: ValidatorId,
        signature: SignatureBytes,
        validator_set: &ValidatorSet,
    ) -> Result<Self> {
        validate_set_binding(
            chain_id,
            protocol_version,
            epoch,
            validator_set_id,
            validator_set,
        )?;
        let value = Self {
            context: validator_set.consensus_context(view, MessageKind::Vote)?,
            height,
            block_id,
            validator_set_id,
            author,
            signature,
        };
        value.validate_shape(validator_set)?;
        Ok(value)
    }

    pub const fn context(&self) -> &CommonConsensusContextV0 {
        &self.context
    }

    pub const fn chain_id(&self) -> ChainId {
        self.context.chain_id()
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.context.protocol_version()
    }

    pub const fn epoch(&self) -> Epoch {
        self.context.epoch()
    }

    pub const fn view(&self) -> View {
        self.context.view()
    }

    pub const fn height(&self) -> Height {
        self.height
    }

    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn author(&self) -> ValidatorId {
        self.author
    }

    pub const fn signature(&self) -> &SignatureBytes {
        &self.signature
    }

    pub fn signing_root_for(
        context: CommonConsensusContextV0,
        height: Height,
        block_id: BlockId,
    ) -> Result<SigningRoot> {
        context.require_kind(MessageKind::Vote)?;
        Ok(signing_root(DOMAIN_VOTE, |encoder| {
            context.encode(encoder);
            encoder.u64(height.get());
            encoder.fixed(block_id.as_bytes());
        }))
    }

    pub fn signing_root_for_set(
        validator_set: &ValidatorSet,
        view: View,
        height: Height,
        block_id: BlockId,
    ) -> Result<SigningRoot> {
        Self::signing_root_for(
            validator_set.consensus_context(view, MessageKind::Vote)?,
            height,
            block_id,
        )
    }

    pub fn validate_shape(&self, validator_set: &ValidatorSet) -> Result<()> {
        validate_set_binding(
            self.chain_id(),
            self.protocol_version(),
            self.epoch(),
            self.validator_set_id,
            validator_set,
        )?;
        self.context.require_kind(MessageKind::Vote)?;
        if self.context.genesis_hash() != validator_set.genesis_hash() {
            return Err(ValidationError::GenesisHashMismatch);
        }
        self.signature.validate_shape()?;
        if validator_set.validator(self.author).is_none() {
            return Err(ValidationError::UnknownValidator(Box::new(self.author)));
        }
        Ok(())
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<()> {
        self.validate_shape(validator_set)?;
        let validator = validator_set
            .validator(self.author)
            .ok_or_else(|| ValidationError::UnknownValidator(Box::new(self.author)))?;
        if !verifier.verify(validator, &self.signing_root(), &self.signature) {
            return Err(ValidationError::InvalidSignature(Box::new(self.author)));
        }
        Ok(())
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.chain_id() == other.chain_id()
            && self.protocol_version() == other.protocol_version()
            && self.epoch() == other.epoch()
            && self.view() == other.view()
            && self.validator_set_id == other.validator_set_id
            && self.author == other.author
            && (self.height != other.height || self.block_id != other.block_id)
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        context: CommonConsensusContextV0,
        height: Height,
        block_id: BlockId,
        validator_set_id: ValidatorSetId,
        author: ValidatorId,
        signature: SignatureBytes,
    ) -> Result<Self> {
        context.require_kind(MessageKind::Vote)?;
        signature.validate_shape()?;
        Ok(Self {
            context,
            height,
            block_id,
            validator_set_id,
            author,
            signature,
        })
    }
}

impl CanonicalSignable for Vote {
    fn signing_root(&self) -> SigningRoot {
        Self::signing_root_for(self.context, self.height, self.block_id)
            .expect("Vote stores a validated vote context")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutVote {
    context: CommonConsensusContextV0,
    validator_set_id: ValidatorSetId,
    high_qc: QcRef,
    author: ValidatorId,
    signature: SignatureBytes,
}

impl TimeoutVote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        view: View,
        validator_set_id: ValidatorSetId,
        high_qc: QcRef,
        author: ValidatorId,
        signature: SignatureBytes,
        validator_set: &ValidatorSet,
    ) -> Result<Self> {
        validate_set_binding(
            chain_id,
            protocol_version,
            epoch,
            validator_set_id,
            validator_set,
        )?;
        let value = Self {
            context: validator_set.consensus_context(view, MessageKind::Timeout)?,
            validator_set_id,
            high_qc,
            author,
            signature,
        };
        value.validate_shape(validator_set)?;
        Ok(value)
    }

    pub const fn context(&self) -> &CommonConsensusContextV0 {
        &self.context
    }

    pub const fn chain_id(&self) -> ChainId {
        self.context.chain_id()
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.context.protocol_version()
    }

    pub const fn epoch(&self) -> Epoch {
        self.context.epoch()
    }

    pub const fn view(&self) -> View {
        self.context.view()
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn high_qc(&self) -> QcRef {
        self.high_qc
    }

    pub const fn author(&self) -> ValidatorId {
        self.author
    }

    pub const fn signature(&self) -> &SignatureBytes {
        &self.signature
    }

    pub fn signing_root_for(
        context: CommonConsensusContextV0,
        high_qc: QcRef,
    ) -> Result<SigningRoot> {
        context.require_kind(MessageKind::Timeout)?;
        Ok(signing_root(DOMAIN_TIMEOUT, |encoder| {
            context.encode(encoder);
            encode_qc_ref(encoder, high_qc);
        }))
    }

    pub fn signing_root_for_set(
        validator_set: &ValidatorSet,
        view: View,
        high_qc: QcRef,
    ) -> Result<SigningRoot> {
        Self::signing_root_for(
            validator_set.consensus_context(view, MessageKind::Timeout)?,
            high_qc,
        )
    }

    pub fn validate_shape(&self, validator_set: &ValidatorSet) -> Result<()> {
        validate_set_binding(
            self.chain_id(),
            self.protocol_version(),
            self.epoch(),
            self.validator_set_id,
            validator_set,
        )?;
        self.context.require_kind(MessageKind::Timeout)?;
        if self.context.genesis_hash() != validator_set.genesis_hash() {
            return Err(ValidationError::GenesisHashMismatch);
        }
        if self.high_qc.epoch != self.epoch()
            || self.high_qc.validator_set_id != self.validator_set_id
        {
            return Err(ValidationError::CertificateMismatch);
        }
        if self.high_qc.view > self.view() {
            return Err(ValidationError::InvalidCertificate(
                "timeout high QC is ahead of timeout view",
            ));
        }
        self.signature.validate_shape()?;
        if validator_set.validator(self.author).is_none() {
            return Err(ValidationError::UnknownValidator(Box::new(self.author)));
        }
        Ok(())
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<()> {
        self.validate_shape(validator_set)?;
        let validator = validator_set
            .validator(self.author)
            .ok_or_else(|| ValidationError::UnknownValidator(Box::new(self.author)))?;
        if !verifier.verify(validator, &self.signing_root(), &self.signature) {
            return Err(ValidationError::InvalidSignature(Box::new(self.author)));
        }
        Ok(())
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.chain_id() == other.chain_id()
            && self.protocol_version() == other.protocol_version()
            && self.epoch() == other.epoch()
            && self.view() == other.view()
            && self.validator_set_id == other.validator_set_id
            && self.author == other.author
            && self.high_qc != other.high_qc
    }
}

impl CanonicalSignable for TimeoutVote {
    fn signing_root(&self) -> SigningRoot {
        Self::signing_root_for(self.context, self.high_qc)
            .expect("TimeoutVote stores a validated timeout context")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalJustification {
    Quorum(Box<QuorumCertificate>),
    Timeout(Box<TimeoutCertificate>),
}

impl ProposalJustification {
    pub fn quorum(certificate: QuorumCertificate) -> Self {
        Self::Quorum(Box::new(certificate))
    }

    pub fn timeout(certificate: TimeoutCertificate) -> Self {
        Self::Timeout(Box::new(certificate))
    }

    pub fn certificate_id(&self) -> CertificateId {
        match self {
            Self::Quorum(certificate) => certificate.id(),
            Self::Timeout(certificate) => certificate.high_qc().id(),
        }
    }

    pub fn timeout_certificate_id(&self) -> Option<CertificateId> {
        match self {
            Self::Quorum(_) => None,
            Self::Timeout(certificate) => Some(certificate.id()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    context: CommonConsensusContextV0,
    block: Block,
    justification: ProposalJustification,
    handoff_certificate_digest: Option<CertificateId>,
    proposer: ValidatorId,
    signature: SignatureBytes,
}

impl Proposal {
    pub fn new(
        block: Block,
        justification: ProposalJustification,
        proposer: ValidatorId,
        signature: SignatureBytes,
        validator_set: &ValidatorSet,
    ) -> Result<Self> {
        Self::new_with_handoff_digest(
            block,
            justification,
            None,
            proposer,
            signature,
            validator_set,
        )
    }

    pub fn new_with_handoff_digest(
        block: Block,
        justification: ProposalJustification,
        handoff_certificate_digest: Option<CertificateId>,
        proposer: ValidatorId,
        signature: SignatureBytes,
        validator_set: &ValidatorSet,
    ) -> Result<Self> {
        let context =
            validator_set.consensus_context(block.header().view(), MessageKind::Proposal)?;
        let value = Self {
            context,
            block,
            justification,
            handoff_certificate_digest,
            proposer,
            signature,
        };
        value.validate_shape(validator_set)?;
        Ok(value)
    }

    pub const fn context(&self) -> &CommonConsensusContextV0 {
        &self.context
    }

    pub const fn block(&self) -> &Block {
        &self.block
    }

    pub const fn justification(&self) -> &ProposalJustification {
        &self.justification
    }

    pub const fn proposer(&self) -> ValidatorId {
        self.proposer
    }

    pub const fn signature(&self) -> &SignatureBytes {
        &self.signature
    }

    pub const fn handoff_certificate_digest(&self) -> Option<CertificateId> {
        self.handoff_certificate_digest
    }

    pub fn signing_root_for(
        block: &Block,
        justification: &ProposalJustification,
        handoff_certificate_digest: Option<CertificateId>,
        validator_set: &ValidatorSet,
    ) -> Result<SigningRoot> {
        let header = block.header();
        let context = validator_set.consensus_context(header.view(), MessageKind::Proposal)?;
        Ok(proposal_signing_root(
            context,
            header.height(),
            block.id(),
            justification,
            handoff_certificate_digest,
        ))
    }

    pub fn validate_shape(&self, validator_set: &ValidatorSet) -> Result<()> {
        self.block.validate_shape()?;
        let header = self.block.header();
        validate_set_binding(
            header.chain_id(),
            header.protocol_version(),
            header.epoch(),
            header.validator_set_id(),
            validator_set,
        )?;
        self.context.require_kind(MessageKind::Proposal)?;
        if self.context.genesis_hash() != validator_set.genesis_hash()
            || header.genesis_hash() != validator_set.genesis_hash()
            || self.context.chain_id() != header.chain_id()
            || self.context.protocol_version() != header.protocol_version()
            || self.context.epoch() != header.epoch()
            || self.context.validator_set_hash() != header.validator_set_id()
            || self.context.view() != header.view()
            || header.consensus_parameters_hash() != validator_set.consensus_parameters_hash()
            || header.proposer_id() != self.proposer
        {
            return Err(ValidationError::ConsensusContextMismatch);
        }
        self.signature.validate_shape()?;
        if validator_set.validator(self.proposer).is_none() {
            return Err(ValidationError::UnknownValidator(Box::new(self.proposer)));
        }
        match &self.justification {
            ProposalJustification::Quorum(certificate) => {
                certificate.validate_shape(validator_set)?;
                validate_parent(header, QcRef::from(certificate.as_ref()))?;
                if header.view().get() != certificate.view().checked_next()?.get() {
                    return Err(ValidationError::InvalidProposal(
                        "proposal without a TC must immediately follow justify-QC view",
                    ));
                }
            }
            ProposalJustification::Timeout(certificate) => {
                certificate.validate_shape(validator_set)?;
                validate_parent(header, QcRef::from(certificate.high_qc()))?;
                if header.view().get() != certificate.view().checked_next()?.get() {
                    return Err(ValidationError::InvalidProposal(
                        "timeout-justified proposal must be in the next view",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<()> {
        self.validate_shape(validator_set)?;
        match &self.justification {
            ProposalJustification::Quorum(certificate) => {
                certificate.verify(validator_set, verifier)?
            }
            ProposalJustification::Timeout(certificate) => {
                certificate.verify(validator_set, verifier)?
            }
        }
        let validator = validator_set
            .validator(self.proposer)
            .ok_or_else(|| ValidationError::UnknownValidator(Box::new(self.proposer)))?;
        if !verifier.verify(validator, &self.signing_root(), &self.signature) {
            return Err(ValidationError::InvalidSignature(Box::new(self.proposer)));
        }
        Ok(())
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        let left = self.block.header();
        let right = other.block.header();
        self.context == other.context
            && left.chain_id() == right.chain_id()
            && left.protocol_version() == right.protocol_version()
            && left.epoch() == right.epoch()
            && left.view() == right.view()
            && left.validator_set_id() == right.validator_set_id()
            && self.proposer == other.proposer
            && self.signing_root() != other.signing_root()
    }
}

impl CanonicalSignable for Proposal {
    fn signing_root(&self) -> SigningRoot {
        proposal_signing_root(
            self.context,
            self.block.header().height(),
            self.block.id(),
            &self.justification,
            self.handoff_certificate_digest,
        )
    }
}

fn proposal_signing_root(
    context: CommonConsensusContextV0,
    height: Height,
    block_id: BlockId,
    justification: &ProposalJustification,
    handoff_certificate_digest: Option<CertificateId>,
) -> SigningRoot {
    proposal_signing_root_from_digests(
        context,
        height,
        block_id,
        justification.certificate_id(),
        justification.timeout_certificate_id(),
        handoff_certificate_digest,
    )
}

pub(crate) fn proposal_signing_root_from_digests(
    context: CommonConsensusContextV0,
    height: Height,
    block_id: BlockId,
    justify_qc_digest: CertificateId,
    timeout_certificate_digest: Option<CertificateId>,
    handoff_certificate_digest: Option<CertificateId>,
) -> SigningRoot {
    signing_root(DOMAIN_PROPOSAL, |encoder| {
        encode_proposal_sign_from_digests(
            encoder,
            context,
            height,
            block_id,
            justify_qc_digest,
            timeout_certificate_digest,
            handoff_certificate_digest,
        );
    })
}

#[cfg(test)]
pub(crate) fn proposal_signing_bytes_from_digests(
    context: CommonConsensusContextV0,
    height: Height,
    block_id: BlockId,
    justify_qc_digest: CertificateId,
    timeout_certificate_digest: Option<CertificateId>,
    handoff_certificate_digest: Option<CertificateId>,
) -> Result<Vec<u8>> {
    try_canonical_bytes(|encoder| {
        encode_proposal_sign_from_digests(
            encoder,
            context,
            height,
            block_id,
            justify_qc_digest,
            timeout_certificate_digest,
            handoff_certificate_digest,
        );
    })
}

#[allow(clippy::too_many_arguments)]
fn encode_proposal_sign_from_digests(
    encoder: &mut Encoder,
    context: CommonConsensusContextV0,
    height: Height,
    block_id: BlockId,
    justify_qc_digest: CertificateId,
    timeout_certificate_digest: Option<CertificateId>,
    handoff_certificate_digest: Option<CertificateId>,
) {
    context.encode(encoder);
    encoder.u64(height.get());
    encoder.fixed(block_id.as_bytes());
    encoder.fixed(justify_qc_digest.as_bytes());
    encoder.optional_fixed(
        timeout_certificate_digest
            .as_ref()
            .map(CertificateId::as_bytes),
    );
    encoder.optional_fixed(
        handoff_certificate_digest
            .as_ref()
            .map(CertificateId::as_bytes),
    );
}

fn validate_set_binding(
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_id: ValidatorSetId,
    validator_set: &ValidatorSet,
) -> Result<()> {
    validator_set.validate_shape()?;
    if chain_id != validator_set.chain_id() {
        return Err(ValidationError::ChainIdMismatch);
    }
    if protocol_version != validator_set.protocol_version() {
        return Err(ValidationError::ProtocolVersionMismatch);
    }
    if epoch != validator_set.epoch() {
        return Err(ValidationError::EpochMismatch);
    }
    if validator_set_id != validator_set.id() {
        return Err(ValidationError::ValidatorSetMismatch);
    }
    Ok(())
}

fn validate_parent(header: &crate::BlockHeader, parent: QcRef) -> Result<()> {
    if header.epoch() != parent.epoch || header.validator_set_id() != parent.validator_set_id {
        return Err(ValidationError::CertificateMismatch);
    }
    if header.parent_id() != parent.block_id {
        return Err(ValidationError::ParentBlockMismatch);
    }
    if header.height().get() != parent.height.checked_next()?.get() {
        return Err(ValidationError::HeightMismatch);
    }
    Ok(())
}

pub(crate) fn encode_qc_ref(encoder: &mut crate::canonical::Encoder, value: QcRef) {
    encoder.fixed(value.qc_digest.as_bytes());
    encoder.u64(value.epoch.get());
    encoder.u64(value.view.get());
    encoder.u64(value.height.get());
    encoder.fixed(value.block_id.as_bytes());
}
