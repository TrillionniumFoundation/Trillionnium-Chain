//! Pure H3b2b0 semantic state-transition rules for PoCO snapshot values.
//!
//! This module deliberately has no production-authority output.  It only
//! constrains create/update/delete operations after the one canonical raw
//! decoder in `poco_transition` has produced an owned semantic fact.

use anyhow::{bail, ensure, Result};

macro_rules! exact_u8_enum {
    ($name:ident { $($variant:ident = $value:literal => $wire_name:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(u8)]
        pub(crate) enum $name {
            $($variant = $value),+
        }

        impl TryFrom<u8> for $name {
            type Error = anyhow::Error;

            fn try_from(value: u8) -> Result<Self> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => bail!(concat!("unknown ", stringify!($name), " discriminant")),
                }
            }
        }

        #[cfg(test)]
        impl $name {
            pub(crate) const fn wire_name(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire_name),+
                }
            }
        }
    };
}

exact_u8_enum!(SettlementStateV0 {
    FinalizedFundedUnused = 1 => "finalized_funded_unused",
    Consumed = 2 => "consumed",
    Released = 3 => "released",
});

exact_u8_enum!(MeasurementStateV0 {
    NotRequired = 1 => "not_required",
    Verified = 2 => "verified",
    Rejected = 3 => "rejected",
});

exact_u8_enum!(RelationshipClassV0 {
    Independent = 1 => "independent",
    Related = 2 => "related",
    Reciprocal = 3 => "reciprocal",
    Unresolved = 4 => "unresolved",
});

exact_u8_enum!(RegistrationStateV0 {
    Active = 1 => "active",
    Revoked = 2 => "revoked",
});

exact_u8_enum!(BondStateV0 {
    ActiveSlashable = 1 => "active_slashable",
    Unbonding = 2 => "unbonding",
});

exact_u8_enum!(JailReasonV0 {
    DoubleVote = 1 => "double_vote",
    Downtime = 2 => "downtime",
    Governance = 3 => "governance",
});

exact_u8_enum!(LifecycleStateV0 {
    Accepted = 1 => "accepted",
    Revoked = 2 => "revoked",
    ChallengePending = 3 => "challenge_pending",
    ChallengeRejected = 4 => "challenge_rejected",
    ChallengeSustained = 5 => "challenge_sustained",
});

exact_u8_enum!(RolloutPhaseV0 {
    Shadow = 0 => "shadow",
    EligibilityOnly = 1 => "eligibility_only",
    CappedWeight = 2 => "capped_weight",
    Full = 3 => "full",
});

exact_u8_enum!(GovernanceApprovalV0 {
    Pending = 0 => "proposed",
    Approved = 1 => "approved",
});

/// Compact, owned semantic projection returned by the sole exact decoder.
///
/// Fixed-size digests stand in for already exact-decoded large imported
/// objects.  This kernel does not authenticate external ledgers, evidence, or
/// governance decisions and cannot authorize candidate selection or epoch
/// transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SemanticFactV0 {
    ConsumptionCertificate,
    ConsumerKeyAuthorization {
        public_key: [u8; 32],
        active_from: u64,
        revoked_at: Option<u64>,
    },
    ConsumerNonce {
        max_accepted_nonce: u64,
    },
    UniqueConsumptionTuple {
        certificate_id: [u8; 32],
        accepted_height: u64,
    },
    MeterDefinition {
        unit_scale: u128,
        active_from: u64,
        retired_at: Option<u64>,
    },
    Settlement {
        commitment: [u8; 32],
        state: SettlementStateV0,
        finalized_height: u64,
    },
    MeasurementEvidence {
        evidence_root: Option<[u8; 32]>,
        state: MeasurementStateV0,
    },
    RelationshipClassification {
        class: RelationshipClassV0,
        expires_at: u64,
    },
    ValidatorRegistration {
        consensus_key: [u8; 32],
        registration_nonce: u64,
        proof_digest: [u8; 32],
        state: RegistrationStateV0,
    },
    ActiveBond {
        amount: u128,
        locked_until: u64,
        state: BondStateV0,
    },
    JailStatus {
        jailed_until: u64,
        reason: JailReasonV0,
    },
    RevocationOrChallenge {
        state: LifecycleStateV0,
        effective_height: u64,
    },
    ValidatorConfiguration,
    ConsensusParameters,
    RolloutOrGovernance {
        target_epoch: u64,
        phase: RolloutPhaseV0,
        parameters_hash: [u8; 32],
        activation_height: u64,
        approval: GovernanceApprovalV0,
    },
    ApplicationAuthorityState {
        state_revision: u64,
        last_target_height: u64,
        nullifier_root: [u8; 32],
        nullifier_count: u64,
    },
}

/// Lower-inclusive, optional-upper-exclusive block-height interval.
#[allow(dead_code)] // Frozen for the next authority join; currently consumed by conformance tests.
pub(crate) const fn block_interval_contains_v0(
    height: u64,
    lower_inclusive: u64,
    upper_exclusive: Option<u64>,
) -> bool {
    height >= lower_inclusive
        && match upper_exclusive {
            Some(upper) => height < upper,
            None => true,
        }
}

/// Relationship records remain usable strictly before their expiry height.
#[allow(dead_code)] // Frozen for the next authority join; currently consumed by conformance tests.
pub(crate) const fn relationship_unexpired_v0(height: u64, expires_at: u64) -> bool {
    height < expires_at
}

/// Finalization, authenticated creation, lifecycle effect, and rollout
/// activation become effective at their boundary height, inclusively.
#[allow(dead_code)] // Frozen for the next authority join; currently consumed by conformance tests.
pub(crate) const fn block_boundary_reached_v0(height: u64, boundary: u64) -> bool {
    height >= boundary
}

/// Bond locks and jail intervals expire at the named target epoch,
/// inclusively.
#[allow(dead_code)] // Frozen for the next authority join; currently consumed by conformance tests.
pub(crate) const fn epoch_boundary_reached_v0(target_epoch: u64, until: u64) -> bool {
    target_epoch >= until
}

/// Applies the conservative H3b2b0 transition graph.
///
/// No v0 semantic value may be deleted.  Facts without an explicitly frozen
/// update rule are create-only.  This is intentionally narrower than a future
/// production business-state machine.
pub(crate) fn validate_semantic_mutation_v0(
    expected: Option<&SemanticFactV0>,
    next: Option<&SemanticFactV0>,
) -> Result<()> {
    match (expected, next) {
        (None, Some(next)) => validate_create(next),
        (Some(_), None) => bail!("PoCO semantic values are non-deletable in v0"),
        (Some(expected), Some(next)) => validate_update(expected, next),
        (None, None) => bail!("empty PoCO semantic mutation"),
    }
}

fn validate_create(next: &SemanticFactV0) -> Result<()> {
    match next {
        SemanticFactV0::ConsumerKeyAuthorization { revoked_at, .. } => {
            ensure!(revoked_at.is_none(), "consumer key must be created active");
        }
        SemanticFactV0::MeterDefinition { retired_at, .. } => {
            ensure!(retired_at.is_none(), "meter must be created active");
        }
        SemanticFactV0::Settlement { state, .. } => {
            ensure!(
                *state == SettlementStateV0::FinalizedFundedUnused,
                "settlement must be created finalized, funded, and unused"
            );
        }
        SemanticFactV0::ValidatorRegistration { state, .. } => {
            ensure!(
                *state == RegistrationStateV0::Active,
                "validator registration must be created active"
            );
        }
        SemanticFactV0::RevocationOrChallenge { state, .. } => {
            ensure!(
                *state == LifecycleStateV0::Accepted,
                "certificate lifecycle must be created accepted"
            );
        }
        SemanticFactV0::RolloutOrGovernance { approval, .. } => {
            ensure!(
                *approval == GovernanceApprovalV0::Pending,
                "rollout governance must be created pending"
            );
        }
        SemanticFactV0::ApplicationAuthorityState {
            state_revision,
            last_target_height,
            nullifier_count,
            ..
        } => {
            ensure!(
                *state_revision == 1,
                "application authority must be created at revision 1"
            );
            ensure!(
                *last_target_height == 0,
                "application authority genesis height must be zero"
            );
            ensure!(
                *nullifier_count == 0,
                "application authority must start with an empty nullifier set"
            );
        }
        _ => {}
    }
    Ok(())
}

fn validate_update(expected: &SemanticFactV0, next: &SemanticFactV0) -> Result<()> {
    match (expected, next) {
        (
            SemanticFactV0::ConsumerKeyAuthorization {
                public_key: old_key,
                active_from: old_active,
                revoked_at: None,
            },
            SemanticFactV0::ConsumerKeyAuthorization {
                public_key: new_key,
                active_from: new_active,
                revoked_at: Some(revoked_at),
            },
        ) => {
            ensure!(old_key == new_key, "consumer public key is immutable");
            ensure!(
                old_active == new_active,
                "consumer key active_from is immutable"
            );
            ensure!(
                *revoked_at > *old_active,
                "consumer key revocation is not monotonic"
            );
            Ok(())
        }
        (
            SemanticFactV0::ConsumerNonce {
                max_accepted_nonce: old,
            },
            SemanticFactV0::ConsumerNonce {
                max_accepted_nonce: new,
            },
        ) => {
            ensure!(new > old, "accepted consumer nonce must strictly increase");
            Ok(())
        }
        (
            SemanticFactV0::MeterDefinition {
                unit_scale: old_scale,
                active_from: old_active,
                retired_at: None,
            },
            SemanticFactV0::MeterDefinition {
                unit_scale: new_scale,
                active_from: new_active,
                retired_at: Some(retired_at),
            },
        ) => {
            ensure!(old_scale == new_scale, "meter unit scale is immutable");
            ensure!(old_active == new_active, "meter active_from is immutable");
            ensure!(
                *retired_at > *old_active,
                "meter retirement is not monotonic"
            );
            Ok(())
        }
        (
            SemanticFactV0::Settlement {
                commitment: old_commitment,
                state: SettlementStateV0::FinalizedFundedUnused,
                finalized_height: old_height,
            },
            SemanticFactV0::Settlement {
                commitment: new_commitment,
                state: new_state,
                finalized_height: new_height,
            },
        ) => {
            ensure!(
                old_commitment == new_commitment,
                "settlement commitment is immutable"
            );
            ensure!(
                old_height == new_height,
                "settlement finalized height is immutable"
            );
            ensure!(
                matches!(
                    new_state,
                    SettlementStateV0::Consumed | SettlementStateV0::Released
                ),
                "invalid settlement transition"
            );
            Ok(())
        }
        (
            SemanticFactV0::ValidatorRegistration {
                consensus_key: old_key,
                registration_nonce: old_nonce,
                proof_digest: old_proof,
                state: RegistrationStateV0::Active,
            },
            SemanticFactV0::ValidatorRegistration {
                consensus_key: new_key,
                registration_nonce: new_nonce,
                proof_digest: new_proof,
                state: RegistrationStateV0::Revoked,
            },
        ) => {
            ensure!(
                old_key == new_key,
                "validator key rotation is unsupported in H3b2b0"
            );
            ensure!(
                old_nonce == new_nonce,
                "validator registration nonce is immutable in H3b2b0"
            );
            ensure!(
                old_proof == new_proof,
                "validator PoP is immutable in H3b2b0"
            );
            Ok(())
        }
        (
            SemanticFactV0::RevocationOrChallenge {
                state: old_state,
                effective_height: old_height,
            },
            SemanticFactV0::RevocationOrChallenge {
                state: new_state,
                effective_height: new_height,
            },
        ) => {
            ensure!(
                new_height > old_height,
                "lifecycle effective height must increase"
            );
            ensure!(
                matches!(
                    (old_state, new_state),
                    (LifecycleStateV0::Accepted, LifecycleStateV0::Revoked)
                        | (
                            LifecycleStateV0::Accepted,
                            LifecycleStateV0::ChallengePending
                        )
                        | (
                            LifecycleStateV0::ChallengePending,
                            LifecycleStateV0::ChallengeRejected
                        )
                        | (
                            LifecycleStateV0::ChallengePending,
                            LifecycleStateV0::ChallengeSustained
                        )
                ),
                "invalid certificate lifecycle transition"
            );
            Ok(())
        }
        (
            SemanticFactV0::RolloutOrGovernance {
                target_epoch: old_epoch,
                phase: old_phase,
                parameters_hash: old_hash,
                activation_height: old_height,
                approval: GovernanceApprovalV0::Pending,
            },
            SemanticFactV0::RolloutOrGovernance {
                target_epoch: new_epoch,
                phase: new_phase,
                parameters_hash: new_hash,
                activation_height: new_height,
                approval: GovernanceApprovalV0::Approved,
            },
        ) => {
            ensure!(old_epoch == new_epoch, "rollout target epoch is immutable");
            ensure!(old_phase == new_phase, "rollout phase is immutable");
            ensure!(old_hash == new_hash, "rollout parameter hash is immutable");
            ensure!(
                old_height == new_height,
                "rollout activation height is immutable"
            );
            Ok(())
        }
        (
            SemanticFactV0::ApplicationAuthorityState {
                state_revision: expected_revision,
                last_target_height: expected_height,
                nullifier_root: expected_root,
                nullifier_count: expected_count,
            },
            SemanticFactV0::ApplicationAuthorityState {
                state_revision: next_revision,
                last_target_height: next_height,
                nullifier_root: next_root,
                nullifier_count: next_count,
            },
        ) => {
            ensure!(
                expected_revision.checked_add(1) == Some(*next_revision),
                "application authority state revision is not exact successor"
            );
            ensure!(
                next_height > expected_height,
                "application authority target height did not advance"
            );
            ensure!(
                next_count >= expected_count,
                "application authority nullifier count decreased"
            );
            ensure!(
                (*next_count == *expected_count) == (*next_root == *expected_root),
                "application authority nullifier root/count transition mismatch"
            );
            Ok(())
        }
        (left, right) if std::mem::discriminant(left) != std::mem::discriminant(right) => {
            bail!("PoCO semantic fact kind changed across update")
        }
        _ => bail!("PoCO semantic value is create-only or already terminal in v0"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const BUSINESS_SEMANTICS_VECTOR: &str = include_str!(
        "../../../../docs/protocol/poco-bft-v0/vectors/poco-business-semantics-v0.json"
    );

    fn vector() -> Value {
        serde_json::from_str(BUSINESS_SEMANTICS_VECTOR).unwrap()
    }

    fn decimal(value: &Value) -> u64 {
        value.as_str().unwrap().parse().unwrap()
    }

    fn optional_decimal(value: &Value) -> Option<u64> {
        value.as_str().map(|value| value.parse().unwrap())
    }

    fn exact_enum_name(name: &str, value: u8) -> Result<&'static str> {
        match name {
            "settlement_state" => Ok(SettlementStateV0::try_from(value)?.wire_name()),
            "measurement_state" => Ok(MeasurementStateV0::try_from(value)?.wire_name()),
            "relationship_class" => Ok(RelationshipClassV0::try_from(value)?.wire_name()),
            "registration_state" => Ok(RegistrationStateV0::try_from(value)?.wire_name()),
            "bond_state" => Ok(BondStateV0::try_from(value)?.wire_name()),
            "jail_reason" => Ok(JailReasonV0::try_from(value)?.wire_name()),
            "lifecycle_state" => Ok(LifecycleStateV0::try_from(value)?.wire_name()),
            "rollout_phase" => Ok(RolloutPhaseV0::try_from(value)?.wire_name()),
            "approval_state" => Ok(GovernanceApprovalV0::try_from(value)?.wire_name()),
            _ => bail!("unknown vector enum"),
        }
    }

    fn transition_fact(field: &str, value: u8, after: bool) -> SemanticFactV0 {
        match field {
            "settlement_state" => SemanticFactV0::Settlement {
                commitment: [1; 32],
                state: SettlementStateV0::try_from(value).unwrap(),
                finalized_height: 50,
            },
            "registration_state" => SemanticFactV0::ValidatorRegistration {
                consensus_key: [2; 32],
                registration_nonce: 7,
                proof_digest: [3; 32],
                state: RegistrationStateV0::try_from(value).unwrap(),
            },
            "lifecycle_state" => SemanticFactV0::RevocationOrChallenge {
                state: LifecycleStateV0::try_from(value).unwrap(),
                effective_height: if after { 81 } else { 80 },
            },
            "approval_state" => SemanticFactV0::RolloutOrGovernance {
                target_epoch: 4,
                phase: RolloutPhaseV0::Shadow,
                parameters_hash: [4; 32],
                activation_height: 90,
                approval: GovernanceApprovalV0::try_from(value).unwrap(),
            },
            _ => panic!("unknown transition field"),
        }
    }

    fn base_fact_for_kind(kind: u8) -> SemanticFactV0 {
        match kind {
            1 => SemanticFactV0::ConsumptionCertificate,
            2 => SemanticFactV0::ConsumerKeyAuthorization {
                public_key: [1; 32],
                active_from: 10,
                revoked_at: None,
            },
            3 => SemanticFactV0::ConsumerNonce {
                max_accepted_nonce: 0,
            },
            4 => SemanticFactV0::UniqueConsumptionTuple {
                certificate_id: [2; 32],
                accepted_height: 6,
            },
            5 => SemanticFactV0::MeterDefinition {
                unit_scale: 1,
                active_from: 30,
                retired_at: None,
            },
            6 => SemanticFactV0::Settlement {
                commitment: [2; 32],
                state: SettlementStateV0::FinalizedFundedUnused,
                finalized_height: 50,
            },
            7 => SemanticFactV0::MeasurementEvidence {
                evidence_root: None,
                state: MeasurementStateV0::NotRequired,
            },
            8 => SemanticFactV0::RelationshipClassification {
                class: RelationshipClassV0::Independent,
                expires_at: 70,
            },
            9 => SemanticFactV0::ValidatorRegistration {
                consensus_key: [3; 32],
                registration_nonce: 1,
                proof_digest: [4; 32],
                state: RegistrationStateV0::Active,
            },
            10 => SemanticFactV0::ActiveBond {
                amount: 1,
                locked_until: 100,
                state: BondStateV0::ActiveSlashable,
            },
            11 => SemanticFactV0::JailStatus {
                jailed_until: 110,
                reason: JailReasonV0::DoubleVote,
            },
            12 => SemanticFactV0::RevocationOrChallenge {
                state: LifecycleStateV0::Accepted,
                effective_height: 80,
            },
            13 => SemanticFactV0::ValidatorConfiguration,
            14 => SemanticFactV0::ConsensusParameters,
            15 => SemanticFactV0::RolloutOrGovernance {
                target_epoch: 4,
                phase: RolloutPhaseV0::Shadow,
                parameters_hash: [5; 32],
                activation_height: 90,
                approval: GovernanceApprovalV0::Pending,
            },
            _ => panic!("unknown semantic kind"),
        }
    }

    #[test]
    fn every_semantic_discriminant_is_exact() {
        for value in 1..=3 {
            SettlementStateV0::try_from(value).unwrap();
            MeasurementStateV0::try_from(value).unwrap();
            JailReasonV0::try_from(value).unwrap();
        }
        for value in 1..=4 {
            RelationshipClassV0::try_from(value).unwrap();
        }
        for value in 1..=2 {
            RegistrationStateV0::try_from(value).unwrap();
            BondStateV0::try_from(value).unwrap();
        }
        for value in 1..=5 {
            LifecycleStateV0::try_from(value).unwrap();
        }
        for value in 0..=3 {
            RolloutPhaseV0::try_from(value).unwrap();
        }
        for value in 0..=1 {
            GovernanceApprovalV0::try_from(value).unwrap();
        }

        assert!(SettlementStateV0::try_from(0).is_err());
        assert!(MeasurementStateV0::try_from(4).is_err());
        assert!(RelationshipClassV0::try_from(5).is_err());
        assert!(RegistrationStateV0::try_from(3).is_err());
        assert!(BondStateV0::try_from(0).is_err());
        assert!(JailReasonV0::try_from(4).is_err());
        assert!(LifecycleStateV0::try_from(6).is_err());
        assert!(RolloutPhaseV0::try_from(4).is_err());
        assert!(GovernanceApprovalV0::try_from(2).is_err());
    }

    #[test]
    fn shared_vector_covers_exact_enums_and_all_transition_pairs() {
        let vector = vector();
        let enum_cases = vector["enum_cases"].as_array().unwrap();
        assert_eq!(enum_cases.len(), 46);
        let mut valid = 0usize;
        let mut unknown = 0usize;
        for case in enum_cases {
            let result = exact_enum_name(
                case["enum"].as_str().unwrap(),
                case["value"].as_u64().unwrap() as u8,
            );
            if case["expected"] == "accept" {
                valid += 1;
                assert_eq!(result.unwrap(), case["name"].as_str().unwrap());
            } else {
                unknown += 1;
                assert!(result.is_err());
            }
        }
        assert_eq!(valid, vector["expected_counts"]["enum_valid"]);
        assert_eq!(unknown, vector["expected_counts"]["enum_unknown"]);

        let transition_cases = vector["transition_cases"].as_array().unwrap();
        let mut allowed = 0usize;
        for case in transition_cases {
            let field = case["field"].as_str().unwrap();
            let before = transition_fact(field, case["from"].as_u64().unwrap() as u8, false);
            let after = transition_fact(field, case["to"].as_u64().unwrap() as u8, true);
            let result = validate_semantic_mutation_v0(Some(&before), Some(&after));
            let expected_accept = case["expected"] == "accept";
            allowed += usize::from(expected_accept);
            assert_eq!(result.is_ok(), expected_accept, "transition case {case}");
        }
        assert_eq!(transition_cases.len(), 42);
        assert_eq!(allowed, vector["expected_counts"]["transition_allowed"]);
    }

    #[test]
    fn shared_vector_freezes_clock_boundaries() {
        let vector = vector();
        let cases = vector["clock_cases"].as_array().unwrap();
        assert_eq!(
            cases.len(),
            usize::try_from(
                vector["expected_counts"]["block_height_cases"]
                    .as_u64()
                    .unwrap()
                    + vector["expected_counts"]["target_epoch_cases"]
                        .as_u64()
                        .unwrap(),
            )
            .unwrap()
        );
        for case in cases {
            let value = decimal(&case["value"]);
            let boundary = &case["boundary"];
            let actual = match case["rule"].as_str().unwrap() {
                "certificate_billing_window" => {
                    let start = decimal(&boundary["billing_start_height"]);
                    let inclusive_end = decimal(&boundary["billing_end_height"]);
                    let upper = inclusive_end.checked_add(1);
                    block_interval_contains_v0(value, start, upper)
                }
                "consumer_key_active" => block_interval_contains_v0(
                    value,
                    decimal(&boundary["active_from"]),
                    optional_decimal(&boundary["revoked_at"]),
                ),
                "meter_active" => block_interval_contains_v0(
                    value,
                    decimal(&boundary["active_from"]),
                    optional_decimal(&boundary["retired_at"]),
                ),
                "relationship_unexpired" => {
                    relationship_unexpired_v0(value, decimal(&boundary["expires_at"]))
                }
                "certificate_acceptance" => {
                    let billing_end = decimal(&boundary["billing_end_height"]);
                    let accepted = decimal(&boundary["accepted_height"]);
                    billing_end < accepted && block_boundary_reached_v0(value, accepted)
                }
                "settlement_finalized" => {
                    block_boundary_reached_v0(value, decimal(&boundary["finalized_height"]))
                }
                "measurement_created" => block_boundary_reached_v0(
                    value,
                    decimal(&boundary["authenticated_creation_height"]),
                ),
                "lifecycle_effective" => {
                    block_boundary_reached_v0(value, decimal(&boundary["effective_height"]))
                }
                "rollout_activation" => {
                    block_boundary_reached_v0(value, decimal(&boundary["activation_height"]))
                }
                "bond_unlocked" => {
                    epoch_boundary_reached_v0(value, decimal(&boundary["locked_until"]))
                }
                "jail_expired" => {
                    epoch_boundary_reached_v0(value, decimal(&boundary["jailed_until"]))
                }
                rule => panic!("unknown clock rule {rule}"),
            };
            assert_eq!(
                actual,
                case["expected"].as_bool().unwrap(),
                "clock case {case}"
            );
        }
        assert_eq!(
            cases
                .iter()
                .filter(|case| case["clock"] == "block_height")
                .count(),
            vector["expected_counts"]["block_height_cases"]
        );
        assert_eq!(
            cases
                .iter()
                .filter(|case| case["clock"] == "target_epoch")
                .count(),
            vector["expected_counts"]["target_epoch_cases"]
        );
        assert!(!block_interval_contains_v0(9, 10, None));
        assert!(block_interval_contains_v0(10, 10, None));
        assert!(block_interval_contains_v0(u64::MAX, 10, None));
    }

    #[test]
    fn shared_vector_freezes_nonce_watermark_and_non_deletion() {
        let vector = vector();
        let cases = vector["nonce_cases"].as_array().unwrap();
        let mut allowed = 0usize;
        for case in cases {
            let previous = optional_decimal(&case["previous"])
                .map(|max_accepted_nonce| SemanticFactV0::ConsumerNonce { max_accepted_nonce });
            let candidate = decimal(&case["candidate"]);
            let next = SemanticFactV0::ConsumerNonce {
                max_accepted_nonce: candidate,
            };
            let result = validate_semantic_mutation_v0(previous.as_ref(), Some(&next));
            let expected_accept = case["expected"] == "accept";
            allowed += usize::from(expected_accept);
            assert_eq!(result.is_ok(), expected_accept, "nonce case {case}");
            if expected_accept {
                assert_eq!(decimal(&case["result"]), candidate);
                assert_eq!(case["exhausted"].as_bool().unwrap(), candidate == u64::MAX);
            }
        }
        assert_eq!(cases.len(), vector["expected_counts"]["nonce_cases"]);
        assert_eq!(allowed, vector["expected_counts"]["nonce_allowed"]);

        let delete_kinds = vector["delete_policy"]["all_kinds"].as_array().unwrap();
        assert_eq!(delete_kinds.len(), 15);
        for kind in delete_kinds {
            let fact = base_fact_for_kind(kind.as_u64().unwrap() as u8);
            assert!(validate_semantic_mutation_v0(Some(&fact), None).is_err());
        }

        for kind in vector["create_only_update_rejections"].as_array().unwrap() {
            let fact = base_fact_for_kind(kind.as_u64().unwrap() as u8);
            assert!(validate_semantic_mutation_v0(Some(&fact), Some(&fact)).is_err());
        }
    }

    #[test]
    fn shared_vector_freezes_immutability_and_terminal_rules() {
        let vector = vector();
        let cases = vector["immutability_campaign"].as_array().unwrap();
        let mut allowed = 0usize;
        for case in cases {
            let (before, after) = match case["record"].as_str().unwrap() {
                "consumer_key" => {
                    let active = decimal(&case["active_from"]);
                    let old_key = [1; 32];
                    let new_key = if case["public_key_equal"].as_bool().unwrap() {
                        old_key
                    } else {
                        [2; 32]
                    };
                    let new_active = if case["active_from_equal"].as_bool().unwrap() {
                        active
                    } else {
                        active + 1
                    };
                    (
                        SemanticFactV0::ConsumerKeyAuthorization {
                            public_key: old_key,
                            active_from: active,
                            revoked_at: optional_decimal(&case["revoked_before"]),
                        },
                        SemanticFactV0::ConsumerKeyAuthorization {
                            public_key: new_key,
                            active_from: new_active,
                            revoked_at: optional_decimal(&case["revoked_after"]),
                        },
                    )
                }
                "meter" => {
                    let active = decimal(&case["active_from"]);
                    let old_scale = 10;
                    let new_scale = if case["unit_scale_equal"].as_bool().unwrap() {
                        old_scale
                    } else {
                        old_scale + 1
                    };
                    let new_active = if case["active_from_equal"].as_bool().unwrap() {
                        active
                    } else {
                        active + 1
                    };
                    (
                        SemanticFactV0::MeterDefinition {
                            unit_scale: old_scale,
                            active_from: active,
                            retired_at: optional_decimal(&case["retired_before"]),
                        },
                        SemanticFactV0::MeterDefinition {
                            unit_scale: new_scale,
                            active_from: new_active,
                            retired_at: optional_decimal(&case["retired_after"]),
                        },
                    )
                }
                "settlement" => (
                    SemanticFactV0::Settlement {
                        commitment: [1; 32],
                        state: SettlementStateV0::try_from(
                            case["state_before"].as_u64().unwrap() as u8
                        )
                        .unwrap(),
                        finalized_height: 50,
                    },
                    SemanticFactV0::Settlement {
                        commitment: if case["commitment_equal"].as_bool().unwrap() {
                            [1; 32]
                        } else {
                            [2; 32]
                        },
                        state: SettlementStateV0::try_from(
                            case["state_after"].as_u64().unwrap() as u8
                        )
                        .unwrap(),
                        finalized_height: if case["finalized_height_equal"].as_bool().unwrap() {
                            50
                        } else {
                            51
                        },
                    },
                ),
                "registration" => (
                    SemanticFactV0::ValidatorRegistration {
                        consensus_key: [1; 32],
                        registration_nonce: 7,
                        proof_digest: [3; 32],
                        state: RegistrationStateV0::try_from(
                            case["state_before"].as_u64().unwrap() as u8,
                        )
                        .unwrap(),
                    },
                    SemanticFactV0::ValidatorRegistration {
                        consensus_key: if case["key_equal"].as_bool().unwrap() {
                            [1; 32]
                        } else {
                            [2; 32]
                        },
                        registration_nonce: if case["nonce_equal"].as_bool().unwrap() {
                            7
                        } else {
                            8
                        },
                        proof_digest: if case["pop_equal"].as_bool().unwrap() {
                            [3; 32]
                        } else {
                            [4; 32]
                        },
                        state: RegistrationStateV0::try_from(
                            case["state_after"].as_u64().unwrap() as u8
                        )
                        .unwrap(),
                    },
                ),
                "lifecycle" => (
                    SemanticFactV0::RevocationOrChallenge {
                        state: LifecycleStateV0::try_from(
                            case["state_before"].as_u64().unwrap() as u8
                        )
                        .unwrap(),
                        effective_height: decimal(&case["effective_before"]),
                    },
                    SemanticFactV0::RevocationOrChallenge {
                        state: LifecycleStateV0::try_from(
                            case["state_after"].as_u64().unwrap() as u8
                        )
                        .unwrap(),
                        effective_height: decimal(&case["effective_after"]),
                    },
                ),
                "rollout" => (
                    SemanticFactV0::RolloutOrGovernance {
                        target_epoch: if case["target_epoch_equal"].as_bool().unwrap() {
                            4
                        } else {
                            5
                        },
                        phase: RolloutPhaseV0::Shadow,
                        parameters_hash: [1; 32],
                        activation_height: 90,
                        approval: GovernanceApprovalV0::try_from(
                            case["approval_before"].as_u64().unwrap() as u8,
                        )
                        .unwrap(),
                    },
                    SemanticFactV0::RolloutOrGovernance {
                        target_epoch: 4,
                        phase: if case["phase_equal"].as_bool().unwrap() {
                            RolloutPhaseV0::Shadow
                        } else {
                            RolloutPhaseV0::EligibilityOnly
                        },
                        parameters_hash: if case["parameters_hash_equal"].as_bool().unwrap() {
                            [1; 32]
                        } else {
                            [2; 32]
                        },
                        activation_height: if case["activation_height_equal"].as_bool().unwrap() {
                            90
                        } else {
                            91
                        },
                        approval: GovernanceApprovalV0::try_from(
                            case["approval_after"].as_u64().unwrap() as u8,
                        )
                        .unwrap(),
                    },
                ),
                record => panic!("unknown immutability record {record}"),
            };
            let result = validate_semantic_mutation_v0(Some(&before), Some(&after));
            let expected_accept = case["expected"] == "accept";
            allowed += usize::from(expected_accept);
            assert_eq!(result.is_ok(), expected_accept, "immutability case {case}");
        }
        assert_eq!(cases.len(), vector["expected_counts"]["immutability_cases"]);
        assert_eq!(allowed, vector["expected_counts"]["immutability_allowed"]);
    }

    #[test]
    fn lifecycle_terminal_states_and_height_replays_are_rejected() {
        let accepted = SemanticFactV0::RevocationOrChallenge {
            state: LifecycleStateV0::Accepted,
            effective_height: 10,
        };
        let pending = SemanticFactV0::RevocationOrChallenge {
            state: LifecycleStateV0::ChallengePending,
            effective_height: 11,
        };
        let sustained = SemanticFactV0::RevocationOrChallenge {
            state: LifecycleStateV0::ChallengeSustained,
            effective_height: 12,
        };
        assert!(validate_semantic_mutation_v0(Some(&accepted), Some(&pending)).is_ok());
        assert!(validate_semantic_mutation_v0(Some(&pending), Some(&sustained)).is_ok());
        assert!(validate_semantic_mutation_v0(Some(&sustained), Some(&accepted)).is_err());
        let same_height = SemanticFactV0::RevocationOrChallenge {
            state: LifecycleStateV0::ChallengeRejected,
            effective_height: 11,
        };
        assert!(validate_semantic_mutation_v0(Some(&pending), Some(&same_height)).is_err());
    }

    #[test]
    fn all_semantic_deletes_and_create_only_updates_are_rejected() {
        let certificate = SemanticFactV0::ConsumptionCertificate;
        assert!(validate_semantic_mutation_v0(Some(&certificate), None).is_err());
        assert!(validate_semantic_mutation_v0(Some(&certificate), Some(&certificate)).is_err());
    }

    #[test]
    fn stateful_records_must_be_created_in_their_initial_state() {
        let vector = vector();
        let cases = vector["create_cases"].as_array().unwrap();
        let mut allowed = 0usize;
        for case in cases {
            let fact = match case["kind"].as_u64().unwrap() {
                2 => SemanticFactV0::ConsumerKeyAuthorization {
                    public_key: [1; 32],
                    active_from: 10,
                    revoked_at: optional_decimal(&case["value"]),
                },
                5 => SemanticFactV0::MeterDefinition {
                    unit_scale: 1,
                    active_from: 30,
                    retired_at: optional_decimal(&case["value"]),
                },
                6 => SemanticFactV0::Settlement {
                    commitment: [2; 32],
                    state: SettlementStateV0::try_from(case["value"].as_u64().unwrap() as u8)
                        .unwrap(),
                    finalized_height: 50,
                },
                9 => SemanticFactV0::ValidatorRegistration {
                    consensus_key: [3; 32],
                    registration_nonce: 1,
                    proof_digest: [4; 32],
                    state: RegistrationStateV0::try_from(case["value"].as_u64().unwrap() as u8)
                        .unwrap(),
                },
                12 => SemanticFactV0::RevocationOrChallenge {
                    state: LifecycleStateV0::try_from(case["value"].as_u64().unwrap() as u8)
                        .unwrap(),
                    effective_height: 80,
                },
                15 => SemanticFactV0::RolloutOrGovernance {
                    target_epoch: 4,
                    phase: RolloutPhaseV0::Shadow,
                    parameters_hash: [5; 32],
                    activation_height: 90,
                    approval: GovernanceApprovalV0::try_from(case["value"].as_u64().unwrap() as u8)
                        .unwrap(),
                },
                kind => panic!("unexpected create-case kind {kind}"),
            };
            let result = validate_semantic_mutation_v0(None, Some(&fact));
            let expected_accept = case["expected"] == "accept";
            allowed += usize::from(expected_accept);
            assert_eq!(result.is_ok(), expected_accept, "create case {case}");
        }
        assert_eq!(cases.len(), vector["expected_counts"]["create_cases"]);
        assert_eq!(allowed, vector["expected_counts"]["create_allowed"]);
    }
}
