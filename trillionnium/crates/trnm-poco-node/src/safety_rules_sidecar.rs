//! Composition-only semantic watermark adapter for the inert SafetyRules
//! authority.
//!
//! This module is intentionally behind `safety-rules-sidecar`.  It does not
//! drive Core, sign a vote, or open a runtime gate.  Its sole job is to make
//! the exact `InertSafetyTransitionV1` tuple visible to an independently
//! administered semantic watermark: authenticated predecessor digest,
//! successor Safety revision, canonical intent fingerprint, signing root, and
//! a deterministic chain checksum.  A caller must supply the freshly
//! authenticated Safety digest at open/reopen; a stale or forked local owner
//! is rejected before the external CAS is attempted.

#![cfg(feature = "safety-rules-sidecar")]

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};
use trnm_consensus_safety_rules::{
    InertSafetyTransitionV1, SafetyRulesDurableTransitionStoreV1, SafetyRulesStateDigestV1,
};
use trnm_consensus_signer_journal::{
    signer_journal_lifecycle_nonce_v0, ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0,
    ExternalWatermarkSemanticFactsV0, SignerWatermarkV0,
};

pub const SAFETY_RULES_SEMANTIC_SIDECAR_RUNTIME_COMPOSITION_V1: bool = true;
pub const SAFETY_RULES_SEMANTIC_SIDECAR_PRODUCTION_ACTIVATION_V1: bool = false;

const TRANSITION_CHAIN_DOMAIN_V1: &[u8] = b"trnm.poco-node.safety-rules-sidecar.transition.v1\0";
const GENESIS_CHAIN_DOMAIN_V1: &[u8] = b"trnm.poco-node.safety-rules-sidecar.genesis.v1\0";

/// Fail-closed errors from the composition adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyRulesSemanticSidecarErrorV1 {
    InvalidConfiguration,
    External(ExternalWatermarkErrorV0),
    Poisoned,
    PredecessorMismatch,
    RevisionMismatch,
    SemanticIntentMismatch,
    ExternalHeadMismatch,
}

impl fmt::Display for SafetyRulesSemanticSidecarErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => {
                formatter.write_str("invalid SafetyRules sidecar configuration")
            }
            Self::External(error) => write!(formatter, "external semantic watermark: {error:?}"),
            Self::Poisoned => formatter.write_str("SafetyRules semantic sidecar is poisoned"),
            Self::PredecessorMismatch => {
                formatter.write_str("SafetyRules predecessor digest mismatch")
            }
            Self::RevisionMismatch => {
                formatter.write_str("SafetyRules revision is not the next external sequence")
            }
            Self::SemanticIntentMismatch => {
                formatter.write_str("canonical intent does not match successor Safety revision")
            }
            Self::ExternalHeadMismatch => formatter
                .write_str("external semantic head does not match the authenticated local state"),
        }
    }
}

impl Error for SafetyRulesSemanticSidecarErrorV1 {}

/// A non-cloneable, composition-only durable transition store.
///
/// `state_digest` is supplied by the caller after validating the authoritative
/// SafetyRules state.  The adapter retains it in memory and checks every
/// transition before touching the external authority.  Reopening therefore
/// requires a fresh authenticated digest rather than trusting a stale local
/// owner.  The external implementation must be in semantic mode; opaque CAS
/// is rejected at construction and can never be selected by fallback.
pub struct SafetyRulesSemanticSidecarV1<W> {
    external: W,
    scope: [u8; 32],
    journal_id: [u8; 32],
    capability: [u8; 32],
    expected: Option<SignerWatermarkV0>,
    state_digest: SafetyRulesStateDigestV1,
    poisoned: bool,
}

impl<W> fmt::Debug for SafetyRulesSemanticSidecarV1<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafetyRulesSemanticSidecarV1")
            .field("scope", &self.scope)
            .field("journal_id", &self.journal_id)
            .field("expected", &self.expected)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl<W> SafetyRulesSemanticSidecarV1<W>
where
    W: ExternalMonotonicWatermarkV0,
{
    /// Opens a semantic sidecar against a freshly validated local state.
    pub fn open(
        mut external: W,
        scope: [u8; 32],
        journal_id: [u8; 32],
        capability: [u8; 32],
        state_digest: SafetyRulesStateDigestV1,
    ) -> Result<Self, SafetyRulesSemanticSidecarErrorV1> {
        if scope == [0; 32] || journal_id == [0; 32] || capability == [0; 32] {
            return Err(SafetyRulesSemanticSidecarErrorV1::InvalidConfiguration);
        }
        if !external.semantic_mode_v0() {
            return Err(SafetyRulesSemanticSidecarErrorV1::InvalidConfiguration);
        }
        // This adapter emits one external reservation per complete
        // SafetyRules transition.  The strict signer-journal-pair lifecycle
        // (odd prepared + even signed) is a different protocol and must not
        // be accepted with a later, surprising failure.
        if !external.semantic_per_reservation_v0() {
            return Err(SafetyRulesSemanticSidecarErrorV1::InvalidConfiguration);
        }
        let head = external
            .load_semantic_v0(scope, journal_id)
            .map_err(SafetyRulesSemanticSidecarErrorV1::External)?;
        let expected = match head {
            None => None,
            Some((watermark, facts)) => {
                let genesis_facts = watermark.sequence() == 0 && facts.safety_revision == 1;
                if watermark.scope() != scope
                    || watermark.journal_id() != journal_id
                    // A head read comes from the external authority, not a
                    // local intent adapter; accepting a zero capability here
                    // would turn namespace authentication into an optional
                    // check on reopen.
                    || facts.capability != capability
                    || (!genesis_facts && facts.safety_revision != watermark.sequence())
                {
                    return Err(SafetyRulesSemanticSidecarErrorV1::ExternalHeadMismatch);
                }
                Some(watermark)
            }
        };
        Ok(Self {
            external,
            scope,
            journal_id,
            capability,
            expected,
            state_digest,
            poisoned: false,
        })
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub const fn expected_watermark(&self) -> Option<SignerWatermarkV0> {
        self.expected
    }

    /// Refreshes the local state binding after an authenticated reopen.  The
    /// next transition still has to carry exactly this digest.
    pub fn rebind_state_digest(&mut self, state_digest: SafetyRulesStateDigestV1) {
        self.state_digest = state_digest;
    }

    fn poison<E>(&mut self, error: SafetyRulesSemanticSidecarErrorV1) -> Result<(), E>
    where
        E: From<SafetyRulesSemanticSidecarErrorV1>,
    {
        self.poisoned = true;
        Err(error.into())
    }
}

impl<W> SafetyRulesDurableTransitionStoreV1 for SafetyRulesSemanticSidecarV1<W>
where
    W: ExternalMonotonicWatermarkV0,
{
    type Error = SafetyRulesSemanticSidecarErrorV1;

    fn persist_transition_v1(
        &mut self,
        predecessor: SafetyRulesStateDigestV1,
        transition: &InertSafetyTransitionV1,
    ) -> Result<(), Self::Error> {
        if self.poisoned {
            return Err(SafetyRulesSemanticSidecarErrorV1::Poisoned);
        }
        if predecessor != self.state_digest || transition.predecessor_state_digest() != predecessor
        {
            return self.poison(SafetyRulesSemanticSidecarErrorV1::PredecessorMismatch);
        }

        let successor = transition.successor_state();
        let sequence = successor.revision();
        let intent = transition.canonical_intent();
        if sequence == 0 || intent.authorizing_safety_revision() != sequence {
            return self.poison(SafetyRulesSemanticSidecarErrorV1::SemanticIntentMismatch);
        }
        let expected_sequence = self.expected.map_or(0, |watermark| watermark.sequence());
        if sequence != expected_sequence.saturating_add(1) {
            return self.poison(SafetyRulesSemanticSidecarErrorV1::RevisionMismatch);
        }

        if self.expected.is_none() {
            let genesis_checksum = digest_parts(
                GENESIS_CHAIN_DOMAIN_V1,
                &[&self.scope, &self.journal_id, &self.capability],
            );
            let genesis = SignerWatermarkV0::from_persisted_parts(
                self.scope,
                self.journal_id,
                0,
                genesis_checksum,
            )
            .map_err(SafetyRulesSemanticSidecarErrorV1::External)?;
            if let Err(error) = self
                .external
                .compare_and_advance_semantic_genesis_v0(None, genesis)
            {
                self.poisoned = true;
                return Err(SafetyRulesSemanticSidecarErrorV1::External(error));
            }
            self.expected = Some(genesis);
        }

        let checksum = transition_checksum_v1(self.scope, self.journal_id, transition);
        let target = SignerWatermarkV0::from_persisted_parts(
            self.scope,
            self.journal_id,
            sequence,
            checksum,
        )
        .map_err(SafetyRulesSemanticSidecarErrorV1::External)?;
        let fingerprint = intent.fingerprint().into_bytes();
        let signing_root = intent.signing_root().into_bytes();
        let nonce = signer_journal_lifecycle_nonce_v0(
            intent.epoch().get(),
            intent.preimage().context().view().get(),
            sequence,
            fingerprint,
            signing_root,
            sequence,
        );
        let facts = ExternalWatermarkSemanticFactsV0::new(
            intent.epoch().get(),
            intent.preimage().context().view().get(),
            sequence,
            nonce,
            fingerprint,
            signing_root,
            self.capability,
        )
        .ok_or(SafetyRulesSemanticSidecarErrorV1::SemanticIntentMismatch)?;
        let expected = self.expected;
        if let Err(error) = self
            .external
            .compare_and_advance_semantic_v0(expected, target, facts)
        {
            self.poisoned = true;
            return Err(SafetyRulesSemanticSidecarErrorV1::External(error));
        }
        self.expected = Some(target);
        self.state_digest = successor.digest();
        Ok(())
    }
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn transition_checksum_v1(
    scope: [u8; 32],
    journal_id: [u8; 32],
    transition: &InertSafetyTransitionV1,
) -> [u8; 32] {
    let predecessor = transition.predecessor_state_digest().into_bytes();
    let successor = transition.successor_state().digest().into_bytes();
    let candidate = transition.candidate_digest().into_bytes();
    let fingerprint = transition.canonical_intent().fingerprint().into_bytes();
    let signing_root = transition.canonical_intent().signing_root().into_bytes();
    let kind = [transition.kind() as u8];
    digest_parts(
        TRANSITION_CHAIN_DOMAIN_V1,
        &[
            &scope,
            &journal_id,
            &predecessor,
            &successor,
            &candidate,
            &fingerprint,
            &signing_root,
            &kind,
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_consensus_safety_rules::{
        PureHotStuffSafetyKernelV1, SafetyRulesContextV1, SafetyRulesStateV1,
    };
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, GenesisQcV0,
        ProtocolVersion, SignatureBytes, SignatureVerifier, SigningRoot, Validator, ValidatorId,
        ValidatorSet, VotingPower,
    };

    #[derive(Debug, Clone, Copy)]
    struct RootSignatures;

    impl SignatureVerifier for RootSignatures {
        fn verify(
            &self,
            _validator: &Validator,
            root: &SigningRoot,
            signature: &SignatureBytes,
        ) -> bool {
            signature.as_bytes()[..32] == root.as_bytes()[..]
                && signature.as_bytes()[32..] == root.as_bytes()[..]
        }
    }

    #[derive(Debug, Default)]
    struct MemorySemanticAuthority {
        head: Option<SignerWatermarkV0>,
        facts: Option<ExternalWatermarkSemanticFactsV0>,
        poisoned: bool,
    }

    impl ExternalMonotonicWatermarkV0 for MemorySemanticAuthority {
        fn load(
            &mut self,
            _scope: [u8; 32],
        ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
            Err(ExternalWatermarkErrorV0::InvalidPersistedState)
        }

        fn compare_and_advance(
            &mut self,
            _expected: Option<SignerWatermarkV0>,
            _target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            Err(ExternalWatermarkErrorV0::InvalidPersistedState)
        }

        fn semantic_mode_v0(&self) -> bool {
            true
        }

        fn semantic_per_reservation_v0(&self) -> bool {
            true
        }

        fn load_semantic_v0(
            &mut self,
            _scope: [u8; 32],
            _journal_id: [u8; 32],
        ) -> Result<
            Option<(SignerWatermarkV0, ExternalWatermarkSemanticFactsV0)>,
            ExternalWatermarkErrorV0,
        > {
            Ok(self.head.zip(self.facts))
        }

        fn compare_and_advance_semantic_genesis_v0(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            if self.head != expected || target.sequence() != 0 {
                self.poisoned = true;
                return Err(ExternalWatermarkErrorV0::CompareFailed);
            }
            let facts = ExternalWatermarkSemanticFactsV0::new(
                0,
                0,
                0 + 1,
                [1; 32],
                [2; 32],
                [3; 32],
                [9; 32],
            )
            .expect("nonzero genesis facts");
            self.head = Some(target);
            self.facts = Some(facts);
            Ok(())
        }

        fn compare_and_advance_semantic_v0(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
            facts: ExternalWatermarkSemanticFactsV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            if self.poisoned || self.head != expected {
                return Err(ExternalWatermarkErrorV0::Unavailable);
            }
            let previous = self.head.expect("genesis installed");
            let previous_facts = self.facts.expect("genesis facts installed");
            let first_after_genesis = previous.sequence() == 0 && target.sequence() == 1;
            if target.sequence() != previous.sequence() + 1
                || (!first_after_genesis && facts.safety_revision <= previous_facts.safety_revision)
                || facts.request_fingerprint == previous_facts.request_fingerprint
                || facts.capability != [9; 32]
            {
                self.poisoned = true;
                return Err(ExternalWatermarkErrorV0::CompareFailed);
            }
            self.head = Some(target);
            self.facts = Some(facts);
            Ok(())
        }
    }

    fn context_and_state() -> (SafetyRulesContextV1, SafetyRulesStateV1) {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = (1u8..=4)
            .map(|index| {
                Validator::new(
                    ValidatorId::new([index; 32]),
                    ConsensusPublicKey::new([index + 100; 32]),
                    VotingPower::new(1).expect("positive power"),
                )
                .expect("valid validator")
            })
            .collect();
        let set = ValidatorSet::new(
            GenesisHash::new([0xA5; 32]),
            ChainId::from_static("trnm-safety-sidecar-test"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid set");
        let context =
            SafetyRulesContextV1::new(set.clone(), parameters, ValidatorId::new([1; 32]), 0, 16)
                .expect("valid context");
        let genesis =
            GenesisQcV0::new(set.genesis_hash(), set.chain_id(), &set).expect("valid genesis");
        let state = SafetyRulesStateV1::from_genesis(&context, genesis, &RootSignatures)
            .expect("valid state");
        (context, state)
    }

    #[test]
    fn semantic_sidecar_binds_transition_and_rejects_replay_or_predecessor_fork() {
        let (context, state) = context_and_state();
        let transition =
            PureHotStuffSafetyKernelV1::prepare_timeout(&context, &state, &RootSignatures)
                .expect("timeout transition");
        let authority = MemorySemanticAuthority::default();
        let mut sidecar = SafetyRulesSemanticSidecarV1::open(
            authority,
            [0x11; 32],
            [0x22; 32],
            [0x09; 32],
            state.digest(),
        )
        .expect("semantic sidecar opens");
        sidecar
            .persist_transition_v1(state.digest(), &transition)
            .expect("first transition persists");
        assert_eq!(
            sidecar.expected_watermark().map(|head| head.sequence()),
            Some(1)
        );
        let replay = sidecar.persist_transition_v1(state.digest(), &transition);
        assert_eq!(
            replay,
            Err(SafetyRulesSemanticSidecarErrorV1::PredecessorMismatch)
        );
        assert!(sidecar.is_poisoned());
    }

    #[test]
    fn semantic_sidecar_rejects_opaque_authority_without_fallback() {
        let (_context, state) = context_and_state();
        let error = SafetyRulesSemanticSidecarV1::open(
            OpaqueAuthority,
            [1; 32],
            [2; 32],
            [3; 32],
            state.digest(),
        )
        .expect_err("opaque authority must fail closed");
        assert_eq!(
            error,
            SafetyRulesSemanticSidecarErrorV1::InvalidConfiguration
        );
    }

    #[test]
    fn semantic_sidecar_rejects_strict_pair_lifecycle_without_fallback() {
        let (_context, state) = context_and_state();
        let error = SafetyRulesSemanticSidecarV1::open(
            StrictSemanticAuthority,
            [1; 32],
            [2; 32],
            [3; 32],
            state.digest(),
        )
        .expect_err("strict pair lifecycle must not be used per transition");
        assert_eq!(
            error,
            SafetyRulesSemanticSidecarErrorV1::InvalidConfiguration
        );
    }

    #[derive(Debug, Default)]
    struct OpaqueAuthority;

    impl ExternalMonotonicWatermarkV0 for OpaqueAuthority {
        fn load(
            &mut self,
            _scope: [u8; 32],
        ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
            Ok(None)
        }
        fn compare_and_advance(
            &mut self,
            _expected: Option<SignerWatermarkV0>,
            _target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct StrictSemanticAuthority;

    impl ExternalMonotonicWatermarkV0 for StrictSemanticAuthority {
        fn load(
            &mut self,
            _scope: [u8; 32],
        ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
            Ok(None)
        }

        fn compare_and_advance(
            &mut self,
            _expected: Option<SignerWatermarkV0>,
            _target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            Ok(())
        }

        fn semantic_mode_v0(&self) -> bool {
            true
        }

        fn load_semantic_v0(
            &mut self,
            _scope: [u8; 32],
            _journal_id: [u8; 32],
        ) -> Result<
            Option<(SignerWatermarkV0, ExternalWatermarkSemanticFactsV0)>,
            ExternalWatermarkErrorV0,
        > {
            Ok(None)
        }
    }
}
