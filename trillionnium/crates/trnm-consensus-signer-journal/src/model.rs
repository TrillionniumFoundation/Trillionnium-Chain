use trnm_consensus_types::{
    CanonicalSignIntentV0, ChainId, Epoch, ProtocolVersion, SignIntentFingerprintV0,
    SignatureBytes, SigningRoot, ValidatorId, ValidatorSet, ValidatorSetId,
};

use crate::{
    error::{ExternalWatermarkErrorV0, SignatureProducerErrorV0, SignerJournalErrorV0},
    hash::hash_domain,
};

pub(crate) const MAXIMUM_INTENTS_HARD_V0: u64 = 1_000_000;
pub(crate) const MAXIMUM_INTENT_BYTES_HARD_V0: usize = 16 * 1024;
pub(crate) const DATABASE_OVERHEAD_BYTES_V0: usize = 16 * 1024 * 1024;
const PROFILE_DOMAIN_V0: &str = "trnm.consensus-signer-journal.profile.v0";

/// Exact external anti-rollback head corresponding to one local journal head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerWatermarkV0 {
    scope: [u8; 32],
    journal_id: [u8; 32],
    sequence: u64,
    chain_checksum: [u8; 32],
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
