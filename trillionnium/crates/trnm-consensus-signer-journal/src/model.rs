use trnm_consensus_types::{
    BlockId, CanonicalSignIntentV0, ChainId, Epoch, Height, ProtocolVersion,
    SignIntentFingerprintV0, SignatureBytes, SigningRoot, ValidatorId, ValidatorSet,
    ValidatorSetId, View,
};

use crate::{
    error::{ExternalWatermarkErrorV0, SignatureProducerErrorV0, SignerJournalErrorV0},
    hash::hash_domain,
};

pub(crate) const MAXIMUM_INTENTS_HARD_V0: u64 = 1_000_000;
pub(crate) const MAXIMUM_INTENT_BYTES_HARD_V0: usize = 16 * 1024;
pub(crate) const DATABASE_OVERHEAD_BYTES_V0: usize = 16 * 1024 * 1024;
const PROFILE_DOMAIN_V0: &str = "trnm.consensus-signer-journal.profile.v0";
const LIFECYCLE_NONCE_DOMAIN_V0: &str = "trnm.consensus-signer-journal.lifecycle-nonce.v0";

/// Derives the nonce used for one durable signer-journal lifecycle event.
///
/// A canonical intent has two externally fenced lifecycle heads: the odd
/// `prepared` event and the following even `signed` event.  The nonce must
/// therefore include the target external sequence; reusing the intent
/// checksum for both events would make a semantic authority mistake the
/// legitimate second CAS for a replay.  This helper is public so every
/// external authority implementation uses the same domain-separated
/// derivation rather than inventing a transport-local nonce scheme.
#[must_use]
pub fn signer_journal_lifecycle_nonce_v0(
    epoch: u64,
    view: u64,
    safety_revision: u64,
    request_fingerprint: [u8; 32],
    signing_root: [u8; 32],
    target_sequence: u64,
) -> [u8; 32] {
    hash_domain(
        LIFECYCLE_NONCE_DOMAIN_V0,
        &[
            &epoch.to_be_bytes(),
            &view.to_be_bytes(),
            &safety_revision.to_be_bytes(),
            &request_fingerprint,
            &signing_root,
            &target_sequence.to_be_bytes(),
        ],
    )
}

/// Exact external anti-rollback head corresponding to one local journal head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerWatermarkV0 {
    scope: [u8; 32],
    journal_id: [u8; 32],
    sequence: u64,
    chain_checksum: [u8; 32],
}

/// Immutable namespace binding for a semantic external watermark authority.
///
/// The capability is an admission secret held by the independently
/// provisioned authority client/daemon; it is never a signing key.  The
/// signer-journal crate carries this small protocol type so the journal can
/// opt into semantic CAS without depending on a concrete Unix/HSM transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalWatermarkSemanticBindingV0 {
    pub scope: [u8; 32],
    pub journal_id: [u8; 32],
    pub capability: [u8; 32],
}

impl ExternalWatermarkSemanticBindingV0 {
    pub fn new(scope: [u8; 32], journal_id: [u8; 32], capability: [u8; 32]) -> Option<Self> {
        if scope == [0; 32] || journal_id == [0; 32] || capability == [0; 32] {
            return None;
        }
        Some(Self {
            scope,
            journal_id,
            capability,
        })
    }
}

/// Semantic round facts bound to one external watermark reservation.
///
/// These are intentionally narrower than Core/SafetyRules state.  They bind
/// the signer-journal intent coordinates and request identity so an opted-in
/// external authority cannot be used through the legacy opaque CAS path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalWatermarkSemanticFactsV0 {
    pub epoch: u64,
    pub view: u64,
    pub safety_revision: u64,
    pub request_nonce: [u8; 32],
    pub request_fingerprint: [u8; 32],
    pub signing_root: [u8; 32],
    pub capability: [u8; 32],
}

impl ExternalWatermarkSemanticFactsV0 {
    pub fn new(
        epoch: u64,
        view: u64,
        safety_revision: u64,
        request_nonce: [u8; 32],
        request_fingerprint: [u8; 32],
        signing_root: [u8; 32],
        capability: [u8; 32],
    ) -> Option<Self> {
        if safety_revision == 0
            || request_nonce == [0; 32]
            || request_fingerprint == [0; 32]
            || signing_root == [0; 32]
            || capability == [0; 32]
        {
            return None;
        }
        Some(Self {
            epoch,
            view,
            safety_revision,
            request_nonce,
            request_fingerprint,
            signing_root,
            capability,
        })
    }

    /// Constructs facts from a local journal intent.  The capability is
    /// intentionally left zero: it is private to the semantic authority
    /// adapter and is filled there after the adapter authenticates its bound
    /// namespace.  A nonzero capability supplied by a caller is still
    /// carried and must match that adapter exactly.
    pub fn from_journal_intent(
        epoch: u64,
        view: u64,
        safety_revision: u64,
        request_nonce: [u8; 32],
        request_fingerprint: [u8; 32],
        signing_root: [u8; 32],
    ) -> Option<Self> {
        if safety_revision == 0
            || request_nonce == [0; 32]
            || request_fingerprint == [0; 32]
            || signing_root == [0; 32]
        {
            return None;
        }
        Some(Self {
            epoch,
            view,
            safety_revision,
            request_nonce,
            request_fingerprint,
            signing_root,
            capability: [0; 32],
        })
    }
}

impl SignerWatermarkV0 {
    pub fn from_persisted_parts(
        scope: [u8; 32],
        journal_id: [u8; 32],
        sequence: u64,
        chain_checksum: [u8; 32],
    ) -> Result<Self, ExternalWatermarkErrorV0> {
        if scope == [0; 32] || journal_id == [0; 32] || chain_checksum == [0; 32] {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(Self {
            scope,
            journal_id,
            sequence,
            chain_checksum,
        })
    }

    pub const fn scope(&self) -> [u8; 32] {
        self.scope
    }

    pub const fn journal_id(&self) -> [u8; 32] {
        self.journal_id
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn chain_checksum(&self) -> [u8; 32] {
        self.chain_checksum
    }
}

/// Mandatory external monotonic state boundary.
///
/// Implementations must live outside the SQLite/WAL/sidecar namespace, keep
/// one value per scope, and provide durable compare-and-advance semantics.
/// `compare_and_advance(None, target)` may succeed only when the scope has
/// never been claimed. A non-`None` target must preserve scope/journal ID,
/// advance the sequence by exactly one, and never permit rollback or overwrite.
/// This crate intentionally supplies no filesystem-backed implementation.
pub trait ExternalMonotonicWatermarkV0 {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0>;

    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0>;

    /// Returns whether this authority requires semantic CAS.  Legacy
    /// implementations remain opaque by default; an opted-in implementation
    /// must reject the legacy methods on its own transport.
    fn semantic_mode_v0(&self) -> bool {
        false
    }

    /// Returns whether this semantic authority uses one CAS record for each
    /// complete reservation.  The strict signer-journal-pair lifecycle uses
    /// two records per intent and is not interchangeable with a transition
    /// store that emits one record per SafetyRules transition.  A semantic
    /// adapter must reject an authority that does not explicitly identify the
    /// compatible lifecycle; `false` is deliberately fail-closed/unknown.
    fn semantic_per_reservation_v0(&self) -> bool {
        false
    }

    /// Loads a semantic head after authenticating the exact namespace.  The
    /// default is unreachable for legacy opaque authorities.
    fn load_semantic_v0(
        &mut self,
        _scope: [u8; 32],
        _journal_id: [u8; 32],
    ) -> Result<
        Option<(SignerWatermarkV0, ExternalWatermarkSemanticFactsV0)>,
        ExternalWatermarkErrorV0,
    > {
        Err(ExternalWatermarkErrorV0::Unavailable)
    }

    /// Advances a semantic head using facts from the exact local signer
    /// intent.  The default is unreachable for legacy opaque authorities.
    fn compare_and_advance_semantic_v0(
        &mut self,
        _expected: Option<SignerWatermarkV0>,
        _target: SignerWatermarkV0,
        _facts: ExternalWatermarkSemanticFactsV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        Err(ExternalWatermarkErrorV0::Unavailable)
    }

    /// Claims a sequence-zero semantic namespace.  Genesis has no signer
    /// intent from which to derive facts, so the authority creates and binds
    /// its own deterministic genesis record.  Legacy authorities never call
    /// this method.
    fn compare_and_advance_semantic_genesis_v0(
        &mut self,
        _expected: Option<SignerWatermarkV0>,
        _target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        Err(ExternalWatermarkErrorV0::Unavailable)
    }
}

/// Composition seam for installing an independently administered watermark
/// after a local journal owner has been constructed.
///
/// Implementations must make installation transactional from the caller's
/// point of view: either all subsequent [`ExternalMonotonicWatermarkV0`]
/// operations are fenced by `external`, or the local owner is failed closed.
/// A missing external value may only be claimed for a sequence-zero genesis
/// head; non-genesis local history must already be present and exact in the
/// independently administered authority.
/// The injected object is deliberately trait-based so a Unix client, HSM
/// adapter, TPM bridge, or test register can be supplied without making this
/// crate depend on one transport or device implementation.
pub trait ExternalMonotonicWatermarkInjectionV0 {
    fn install_external_monotonic_watermark_v0(
        &mut self,
        external: Box<dyn ExternalMonotonicWatermarkV0 + Send>,
    ) -> Result<(), ExternalWatermarkErrorV0>;
}

/// Authorized input passed to an external private-key/HSM/KMS adapter.
#[derive(Debug, Clone, Copy)]
pub struct SignatureRequestV0<'a> {
    intent: &'a CanonicalSignIntentV0,
    signer_profile_ref: [u8; 32],
}

impl<'a> SignatureRequestV0<'a> {
    pub(crate) const fn new(
        intent: &'a CanonicalSignIntentV0,
        signer_profile_ref: [u8; 32],
    ) -> Self {
        Self {
            intent,
            signer_profile_ref,
        }
    }

    pub const fn intent(&self) -> &'a CanonicalSignIntentV0 {
        self.intent
    }

    pub const fn author(&self) -> ValidatorId {
        self.intent.author()
    }

    pub const fn signing_root(&self) -> SigningRoot {
        self.intent.signing_root()
    }

    pub const fn fingerprint(&self) -> SignIntentFingerprintV0 {
        self.intent.fingerprint()
    }

    pub const fn signer_profile_ref(&self) -> [u8; 32] {
        self.signer_profile_ref
    }
}

/// Injected signing boundary. No implementation or private-key storage is
/// provided by this crate.
///
/// The adapter contract is exact-idempotent by intent fingerprint. Once a
/// request has reached a producer, every later call for that fingerprint must
/// return the same RFC 8032 Ed25519 signature bytes. A process can crash after
/// the producer signs but before the signature event is appended, so the
/// journal cannot enforce this property on behalf of an HSM/KMS. Adapters that
/// randomize signatures or forget fingerprint replay state are unsupported.
pub trait SignatureProducerV0 {
    fn sign(
        &mut self,
        request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0>;
}

/// Exact, bounded identity of one proposal witness that is eligible for a
/// separately injected proposal signer.
///
/// Proposal signing is intentionally not folded into [`CanonicalSignIntentV0`]
/// or [`SignatureProducerV0`]: the v0 signer journal only journals Vote and
/// TimeoutVote intents.  This request carries the block identity and all
/// consensus coordinates in addition to the proposal signing root, so a
/// producer can bind an external request to the exact proposal rather than
/// accepting caller-selected arbitrary bytes.  Constructing this value is
/// still only protocol data; it does not prove Core/SafetyRules authorization,
/// reserve a nonce, or advance an external watermark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposalSignatureRequestV0 {
    proposal_id: BlockId,
    parent_id: BlockId,
    validator_set_id: ValidatorSetId,
    author: ValidatorId,
    epoch: Epoch,
    view: View,
    height: Height,
    signing_root: SigningRoot,
    expected_consensus_public_key: [u8; 32],
    signer_profile_ref: [u8; 32],
}

impl ProposalSignatureRequestV0 {
    /// Builds a request only when all identity fields are nonzero and the
    /// network coordinates are positive.  This shape check is deliberately
    /// weaker than Core/SafetyRules admission and must not be treated as it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal_id: BlockId,
        parent_id: BlockId,
        validator_set_id: ValidatorSetId,
        author: ValidatorId,
        epoch: Epoch,
        view: View,
        height: Height,
        signing_root: SigningRoot,
        expected_consensus_public_key: [u8; 32],
        signer_profile_ref: [u8; 32],
    ) -> Option<Self> {
        if proposal_id.is_zero()
            || parent_id.is_zero()
            || validator_set_id.is_zero()
            || author.is_zero()
            || view.get() == 0
            || height.get() == 0
            || signing_root.is_zero()
            || expected_consensus_public_key == [0; 32]
            || signer_profile_ref == [0; 32]
        {
            return None;
        }
        Some(Self {
            proposal_id,
            parent_id,
            validator_set_id,
            author,
            epoch,
            view,
            height,
            signing_root,
            expected_consensus_public_key,
            signer_profile_ref,
        })
    }

    pub const fn proposal_id(&self) -> BlockId {
        self.proposal_id
    }

    pub const fn parent_id(&self) -> BlockId {
        self.parent_id
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn author(&self) -> ValidatorId {
        self.author
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

    pub const fn signing_root(&self) -> SigningRoot {
        self.signing_root
    }

    pub const fn expected_consensus_public_key(&self) -> [u8; 32] {
        self.expected_consensus_public_key
    }

    pub const fn signer_profile_ref(&self) -> [u8; 32] {
        self.signer_profile_ref
    }
}

/// Separate proposal-witness signing seam.
///
/// Implementations must deterministically replay the same signature for the
/// same request identity.  The trait is not wired into the normal continuous
/// runtime and does not replace the Vote/TimeoutVote signer journal.
pub trait ProposalSignatureProducerV0 {
    fn sign_proposal(
        &mut self,
        request: ProposalSignatureRequestV0,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0>;
}

#[cfg(test)]
mod proposal_request_tests {
    use super::*;

    fn request() -> ProposalSignatureRequestV0 {
        ProposalSignatureRequestV0::new(
            BlockId::new([1; 32]),
            BlockId::new([2; 32]),
            ValidatorSetId::new([3; 32]),
            ValidatorId::new([4; 32]),
            Epoch::new(7),
            View::new(8),
            Height::new(9),
            SigningRoot::new([5; 32]),
            [6; 32],
            [7; 32],
        )
        .expect("strictly shaped proposal request")
    }

    #[test]
    fn proposal_request_rejects_zero_identity_or_network_coordinates() {
        let valid = request();
        assert_eq!(valid.proposal_id(), BlockId::new([1; 32]));
        assert_eq!(valid.signing_root(), SigningRoot::new([5; 32]));
        assert!(ProposalSignatureRequestV0::new(
            BlockId::ZERO,
            valid.parent_id(),
            valid.validator_set_id(),
            valid.author(),
            valid.epoch(),
            valid.view(),
            valid.height(),
            valid.signing_root(),
            valid.expected_consensus_public_key(),
            valid.signer_profile_ref(),
        )
        .is_none());
        assert!(ProposalSignatureRequestV0::new(
            valid.proposal_id(),
            valid.parent_id(),
            valid.validator_set_id(),
            valid.author(),
            valid.epoch(),
            View::new(0),
            valid.height(),
            valid.signing_root(),
            valid.expected_consensus_public_key(),
            valid.signer_profile_ref(),
        )
        .is_none());
        assert!(ProposalSignatureRequestV0::new(
            valid.proposal_id(),
            valid.parent_id(),
            valid.validator_set_id(),
            valid.author(),
            valid.epoch(),
            valid.view(),
            valid.height(),
            valid.signing_root(),
            valid.expected_consensus_public_key(),
            [0; 32],
        )
        .is_none());
    }
}

/// Immutable profile for one validator and one frozen validator-set epoch.
#[derive(Debug, Clone)]
pub struct SignerJournalProfileV0 {
    validator_set: ValidatorSet,
    author: ValidatorId,
    signer_profile_ref: [u8; 32],
    external_watermark_scope: [u8; 32],
    maximum_intents: u64,
    maximum_intent_bytes: usize,
    maximum_database_bytes: usize,
    profile_checksum: [u8; 32],
}

impl SignerJournalProfileV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        validator_set: ValidatorSet,
        author: ValidatorId,
        signer_profile_ref: [u8; 32],
        external_watermark_scope: [u8; 32],
        maximum_intents: u64,
        maximum_intent_bytes: usize,
        maximum_database_bytes: usize,
    ) -> Result<Self, SignerJournalErrorV0> {
        validator_set
            .validate_shape()
            .map_err(|error| SignerJournalErrorV0::intent("validate validator set", error))?;
        if validator_set.validator(author).is_none() {
            return Err(SignerJournalErrorV0::InvalidProfile(
                "author is absent from validator set",
            ));
        }
        if signer_profile_ref == [0; 32] || external_watermark_scope == [0; 32] {
            return Err(SignerJournalErrorV0::InvalidProfile(
                "signer profile and external watermark scope must be nonzero",
            ));
        }
        if maximum_intents == 0 || maximum_intents > MAXIMUM_INTENTS_HARD_V0 {
            return Err(SignerJournalErrorV0::InvalidProfile("intent count bound"));
        }
        if maximum_intent_bytes == 0 || maximum_intent_bytes > MAXIMUM_INTENT_BYTES_HARD_V0 {
            return Err(SignerJournalErrorV0::InvalidProfile("intent byte bound"));
        }
        let retained_bytes = usize::try_from(maximum_intents)
            .ok()
            .and_then(|count| maximum_intent_bytes.checked_add(1536)?.checked_mul(count))
            .and_then(|bytes| bytes.checked_add(DATABASE_OVERHEAD_BYTES_V0))
            .ok_or(SignerJournalErrorV0::InvalidProfile(
                "database budget calculation overflow",
            ))?;
        if maximum_database_bytes < retained_bytes || maximum_database_bytes > i64::MAX as usize {
            return Err(SignerJournalErrorV0::InvalidProfile(
                "database budget cannot retain declared append-only capacity",
            ));
        }

        let validator_set_bytes = validator_set
            .try_cev0_bytes()
            .map_err(|error| SignerJournalErrorV0::intent("encode validator set", error))?;
        let maximum_intents_be = maximum_intents.to_be_bytes();
        let maximum_intent_bytes_be = (maximum_intent_bytes as u64).to_be_bytes();
        let maximum_database_bytes_be = (maximum_database_bytes as u64).to_be_bytes();
        let profile_checksum = hash_domain(
            PROFILE_DOMAIN_V0,
            &[
                &validator_set_bytes,
                author.as_bytes(),
                &signer_profile_ref,
                &external_watermark_scope,
                &maximum_intents_be,
                &maximum_intent_bytes_be,
                &maximum_database_bytes_be,
            ],
        );
        Ok(Self {
            validator_set,
            author,
            signer_profile_ref,
            external_watermark_scope,
            maximum_intents,
            maximum_intent_bytes,
            maximum_database_bytes,
            profile_checksum,
        })
    }

    pub const fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub const fn author(&self) -> ValidatorId {
        self.author
    }

    pub const fn chain_id(&self) -> ChainId {
        self.validator_set.chain_id()
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.validator_set.protocol_version()
    }

    pub const fn epoch(&self) -> Epoch {
        self.validator_set.epoch()
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set.id()
    }

    pub const fn signer_profile_ref(&self) -> [u8; 32] {
        self.signer_profile_ref
    }

    pub const fn external_watermark_scope(&self) -> [u8; 32] {
        self.external_watermark_scope
    }

    pub const fn maximum_intents(&self) -> u64 {
        self.maximum_intents
    }

    pub const fn maximum_intent_bytes(&self) -> usize {
        self.maximum_intent_bytes
    }

    pub const fn maximum_database_bytes(&self) -> usize {
        self.maximum_database_bytes
    }

    pub const fn profile_checksum(&self) -> [u8; 32] {
        self.profile_checksum
    }
}
