//! Phase-bound direct-seven RestartParkedAck ownership.
//!
//! The wire values in `restart_cut` prove signatures and exact Cut/Park
//! relations, but cloneable bytes alone do not prove that a message occupied
//! one fresh `ParkedAck` ingress slot or that the local signer had already
//! crossed its durable `restart_cut -> restart_park` journal boundary.  This
//! module keeps those two authorities non-Clone and forms an N/N barrier only
//! from one local originated slot plus six distinct authenticated slots from
//! the same bounded admission map.
//!
//! This remains an inert barrier.  It grants no RecoveryReady/RecoveryStart,
//! process-control, timer, ordinary-consensus, or activation authority.  The
//! current configuration still retains a raw signing key elsewhere, so this
//! owner graph must not be described as process-wide signer exclusivity.

use std::collections::BTreeMap;

use anyhow::{ensure, Context, Result as AnyResult};
use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use trnm_consensus_types::ValidatorId;

use crate::{
    config::LoadedValidatorConfig,
    continuous_runtime::{
        ContinuousRestartDeclaredParkAuthorityV1, ContinuousRuntimeFactsV0,
        RestartSignatureProducerV1, RestartSignaturePurposeV1,
    },
    process_event::LocalRestartParkJournalCommitV1,
    restart_cut::{
        restart_parked_ack_admission_set_sha256_for_ids_v1, RestartParkRoleV1,
        RestartParkedAckCertificateV1, RestartParkedAckCommonV1, SignedRestartParkedAckV1,
    },
    restart_park_protocol::StoredRestartCutParkCertificatesV1,
    restart_parked_ack_store::{
        persist_restart_parked_ack_certificate_v1, RestartParkedAckLocalWitnessV1,
        StoredRestartParkedAckCertificateV1,
    },
    restart_protocol::{
        restart_protocol_message_id_for_parts_v1, restart_protocol_payload_digest_for_parts_v1,
        AdmittedRestartProtocolMessageV1, RestartProtocolAdmissionInstanceV1,
        RestartProtocolOriginReservationV1, RestartProtocolPhaseV1,
        VerifiedRestartProtocolOriginReservationV1,
    },
};

/// Non-Clone local declaration whose sole signature was issued only after
/// consuming both the retained parked authority and a fresh journal-commit
/// token.  The exact durable Cut/Park pair remains inside this carrier.
#[must_use = "a declared ParkedAck must acquire the sole local originated slot"]
pub(crate) struct DeclaredRestartParkedAckV1 {
    stored: StoredRestartCutParkCertificatesV1,
    declared_park: ContinuousRestartDeclaredParkAuthorityV1,
    journal_commit: LocalRestartParkJournalCommitV1,
    statement: SignedRestartParkedAckV1,
}

impl std::fmt::Debug for DeclaredRestartParkedAckV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeclaredRestartParkedAckV1")
            .field("origin", &self.statement.origin())
            .field("role", &self.statement.role())
            .field("statement_sha256", &self.statement.statement_sha256())
            .field("journal_commit", &self.journal_commit)
            .finish_non_exhaustive()
    }
}

impl DeclaredRestartParkedAckV1 {
    pub(crate) const fn statement_v1(&self) -> &SignedRestartParkedAckV1 {
        &self.statement
    }

    pub(crate) const fn stored_cut_park_v1(&self) -> &StoredRestartCutParkCertificatesV1 {
        &self.stored
    }

    pub(crate) const fn parked_facts_v1(&self) -> ContinuousRuntimeFactsV0 {
        self.declared_park.facts_v1()
    }

    pub(crate) const fn journal_commit_v1(&self) -> &LocalRestartParkJournalCommitV1 {
        &self.journal_commit
    }

    fn revalidate_fresh_v1(&self) -> AnyResult<()> {
        let stored = &self.stored;
        ensure_journal_commit_matches_stored_v1(&self.journal_commit, stored)?;
        ensure_declared_park_matches_stored_v1(&self.declared_park, stored)?;
        self.statement
            .verify(
                stored.fleet_start_certificate_v1(),
                stored.cut_certificate_v1(),
                stored.park_certificate_v1(),
                stored.admission_set_sha256_v1(),
                stored.validator_set_v1(),
            )
            .map_err(|error| anyhow::anyhow!("reverify local ParkedAck declaration: {error}"))?;
        ensure!(
            self.statement.origin() == stored.local_validator_v1()
                && self.statement.role() == stored.local_role_v1()
                && self.statement.local_config_sha256() == stored.local_config_sha256_v1()
                && self.statement.local_park_statement_sha256()
                    == stored.local_park_statement_sha256_v1()
                && self.statement.predecessor_sequence()
                    == self.journal_commit.predecessor_sequence_v1()
                && self.statement.predecessor_sha256()
                    == self.journal_commit.predecessor_sha256_v1()
                && self.statement.restart_cut_event_sequence()
                    == self.journal_commit.restart_cut_event_sequence_v1()
                && self.statement.restart_cut_event_sha256()
                    == self.journal_commit.restart_cut_event_sha256_v1()
                && self.statement.restart_park_event_sequence()
                    == self.journal_commit.restart_park_event_sequence_v1()
                && self.statement.restart_park_event_sha256()
                    == self.journal_commit.restart_park_event_sha256_v1(),
            "local ParkedAck declaration differs from its retained authority or journal commit"
        );
        Ok(())
    }
}

/// Consumes the only durably parked local owner into an Ack-only declaration.
/// Callers cannot pass a raw key or arbitrary signing preimage into this
/// boundary; the exact preimage is derived here from retained typed owners.
pub(crate) fn issue_local_restart_parked_ack_v1(
    stored: StoredRestartCutParkCertificatesV1,
    declared_park: ContinuousRestartDeclaredParkAuthorityV1,
    journal_commit: LocalRestartParkJournalCommitV1,
    config: &LoadedValidatorConfig,
    expected_role: RestartParkRoleV1,
    mut restart_producer: Option<&mut dyn RestartSignatureProducerV1>,
) -> AnyResult<DeclaredRestartParkedAckV1> {
    stored
        .revalidate_fresh_v1()
        .context("fresh-revalidate durable Cut/Park before local ParkedAck issuance")?;
    ensure_journal_commit_matches_stored_v1(&journal_commit, &stored)?;
    ensure_declared_park_matches_stored_v1(&declared_park, &stored)?;
    ensure!(
        config.local_validator() == stored.local_validator_v1()
            && config.config_sha256() == stored.local_config_sha256_v1()
            && config.validator_set() == stored.validator_set_v1()
            && stored.local_role_v1() == expected_role
            && journal_commit.local_validator_v1() == stored.local_validator_v1()
            && journal_commit.role_v1() == expected_role,
        "local ParkedAck issuance differs from config, validator set, or target/peer role"
    );

    let common = RestartParkedAckCommonV1::new(
        stored.fleet_start_certificate_v1(),
        stored.cut_certificate_v1(),
        stored.park_certificate_v1(),
        stored.admission_set_sha256_v1(),
        stored.validator_set_v1(),
    )
    .map_err(|error| anyhow::anyhow!("form exact ParkedAck common facts: {error}"))?;
    let digest = SignedRestartParkedAckV1::signing_digest_for_parts(
        common,
        stored.local_validator_v1(),
        expected_role,
        stored.local_config_sha256_v1(),
        stored.local_park_statement_sha256_v1(),
        journal_commit.predecessor_sequence_v1(),
        journal_commit.predecessor_sha256_v1(),
        journal_commit.restart_cut_event_sequence_v1(),
        journal_commit.restart_cut_event_sha256_v1(),
        journal_commit.restart_park_event_sequence_v1(),
        journal_commit.restart_park_event_sha256_v1(),
        stored.fleet_start_certificate_v1(),
        stored.cut_certificate_v1(),
        stored.park_certificate_v1(),
        stored.admission_set_sha256_v1(),
        stored.validator_set_v1(),
    )
    .map_err(|error| anyhow::anyhow!("form exact ParkedAck signing digest: {error}"))?;
    let signature = if let Some(producer) = restart_producer.as_deref_mut() {
        producer
            .sign_restart_v1(RestartSignaturePurposeV1::Park, digest)
            .context("produce external RestartParkedAck signature")?
    } else {
        config.consensus_signing_key().sign(&digest).to_bytes()
    };
    let statement = SignedRestartParkedAckV1::from_parts(
        common,
        stored.local_validator_v1(),
        expected_role,
        stored.local_config_sha256_v1(),
        stored.local_park_statement_sha256_v1(),
        journal_commit.predecessor_sequence_v1(),
        journal_commit.predecessor_sha256_v1(),
        journal_commit.restart_cut_event_sequence_v1(),
        journal_commit.restart_cut_event_sha256_v1(),
        journal_commit.restart_park_event_sequence_v1(),
        journal_commit.restart_park_event_sha256_v1(),
        signature,
        stored.fleet_start_certificate_v1(),
        stored.cut_certificate_v1(),
        stored.park_certificate_v1(),
        stored.admission_set_sha256_v1(),
        stored.validator_set_v1(),
    )
    .map_err(|error| anyhow::anyhow!("verify exact local ParkedAck signature bytes: {error}"))?;
    let value = DeclaredRestartParkedAckV1 {
        stored,
        declared_park,
        journal_commit,
        statement,
    };
    value.revalidate_fresh_v1()?;
    Ok(value)
}

fn ensure_journal_commit_matches_stored_v1(
    journal_commit: &LocalRestartParkJournalCommitV1,
    stored: &StoredRestartCutParkCertificatesV1,
) -> AnyResult<()> {
    stored
        .revalidate_fresh_v1()
        .context("fresh-revalidate Cut/Park at ParkedAck journal join")?;
    let local_park = stored.local_park_v1();
    let fleet_start_certificate_sha256: [u8; 32] =
        Sha256::digest(stored.fleet_start_certificate_v1().encode()).into();
    ensure!(
        stored.body_v1().process_instance() == 1
            && journal_commit.local_validator_v1() == stored.local_validator_v1()
            && journal_commit.local_config_sha256_v1() == stored.local_config_sha256_v1()
            && journal_commit.target_validator_v1() == stored.body_v1().target_validator()
            && journal_commit.role_v1() == stored.local_role_v1()
            && journal_commit.process_instance_v1() == 1
            && journal_commit.fleet_start_certificate_sha256_v1() == fleet_start_certificate_sha256
            && journal_commit.restart_cut_body_sha256_v1() == stored.body_v1().digest()
            && journal_commit.restart_cut_artifact_sha256_v1() == stored.cut_artifact_sha256_v1()
            && journal_commit.restart_park_artifact_sha256_v1() == stored.park_artifact_sha256_v1()
            && journal_commit.restart_cut_park_admission_set_sha256_v1()
                == stored.admission_set_sha256_v1()
            && journal_commit.local_park_statement_sha256_v1()
                == stored.local_park_statement_sha256_v1()
            && journal_commit.predecessor_sequence_v1()
                == local_park.local_state().runtime_journal_head_sequence
            && journal_commit.predecessor_sha256_v1()
                == local_park.local_state().runtime_journal_head_sha256
            && journal_commit.restart_cut_event_sequence_v1()
                == journal_commit
                    .predecessor_sequence_v1()
                    .checked_add(1)
                    .context("ParkedAck predecessor sequence overflow")?
            && journal_commit.restart_park_event_sequence_v1()
                == journal_commit
                    .restart_cut_event_sequence_v1()
                    .checked_add(1)
                    .context("ParkedAck Cut event sequence overflow")?
            && journal_commit.local_config_sha256_v1() != [0; 32]
            && journal_commit.local_park_statement_sha256_v1() != [0; 32]
            && journal_commit.predecessor_sha256_v1() != [0; 32]
            && journal_commit.restart_cut_event_sha256_v1() != [0; 32]
            && journal_commit.restart_park_event_sha256_v1() != [0; 32],
        "fresh journal commit differs from the exact durable local Cut/Park owner"
    );
    Ok(())
}

fn ensure_declared_park_matches_stored_v1(
    declared: &ContinuousRestartDeclaredParkAuthorityV1,
    stored: &StoredRestartCutParkCertificatesV1,
) -> AnyResult<()> {
    let local_validator = stored.local_validator_v1();
    let declared_statement = declared.statement_v1();
    ensure!(
        declared_statement.origin() == local_validator
            && stored.cut_certificate_v1().statement(local_validator)
                == Some(declared_statement.cut())
            && stored.park_certificate_v1().statement(local_validator)
                == Some(declared_statement.park())
            && declared_statement.park().local_park().role() == stored.local_role_v1()
            && declared_statement.park().local_park().local_config_sha256()
                == stored.local_config_sha256_v1()
            && declared_statement.park().statement_sha256()
                == stored.local_park_statement_sha256_v1(),
        "retained declared park authority differs from the exact durable local certificates"
    );
    Ok(())
}

/// Non-Clone proof that one strictly decoded ParkedAck occupied its author's
/// sole fresh authenticated ParkedAck slot.
#[must_use = "an admitted ParkedAck must remain in its direct-seven barrier"]
pub(crate) struct AdmittedRestartParkedAckV1 {
    admission: AdmittedRestartProtocolMessageV1,
    statement: SignedRestartParkedAckV1,
}

impl std::fmt::Debug for AdmittedRestartParkedAckV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedRestartParkedAckV1")
            .field("origin", &self.statement.origin())
            .field("message_id", &self.admission.message_id_v1())
            .field("statement_sha256", &self.statement.statement_sha256())
            .finish_non_exhaustive()
    }
}

impl AdmittedRestartParkedAckV1 {
    pub(crate) fn new(
        admission: AdmittedRestartProtocolMessageV1,
        stored: &StoredRestartCutParkCertificatesV1,
    ) -> AnyResult<Self> {
        stored
            .revalidate_fresh_v1()
            .context("fresh-revalidate Cut/Park before admitting ParkedAck")?;
        ensure!(
            admission.validator_set_id_v1() == stored.validator_set_v1().id()
                && admission.phase_v1() == RestartProtocolPhaseV1::ParkedAck,
            "ParkedAck occupied the wrong campaign or protocol phase"
        );
        let statement = SignedRestartParkedAckV1::decode(
            admission.payload_v1(),
            stored.fleet_start_certificate_v1(),
            stored.cut_certificate_v1(),
            stored.park_certificate_v1(),
            stored.admission_set_sha256_v1(),
            stored.validator_set_v1(),
        )
        .map_err(|error| anyhow::anyhow!("decode admitted ParkedAck: {error}"))?;
        ensure!(
            statement.encode() == admission.payload_v1()
                && statement.origin() == admission.origin_v1(),
            "ParkedAck differs from its canonical authenticated transport origin"
        );
        let value = Self {
            admission,
            statement,
        };
        value.revalidate_v1(stored)?;
        Ok(value)
    }

    pub(crate) const fn statement_v1(&self) -> &SignedRestartParkedAckV1 {
        &self.statement
    }

    pub(crate) fn message_id_v1(&self) -> [u8; 32] {
        self.admission.message_id_v1()
    }

    const fn admission_instance_v1(&self) -> RestartProtocolAdmissionInstanceV1 {
        self.admission.admission_instance_v1()
    }

    fn revalidate_v1(&self, stored: &StoredRestartCutParkCertificatesV1) -> AnyResult<()> {
        ensure!(
            self.admission.validator_set_id_v1() == stored.validator_set_v1().id()
                && self.admission.phase_v1() == RestartProtocolPhaseV1::ParkedAck
                && self.admission.origin_v1() == self.statement.origin()
                && self.admission.payload_v1() == self.statement.encode(),
            "retained ParkedAck admission differs from its signed statement"
        );
        self.statement
            .verify(
                stored.fleet_start_certificate_v1(),
                stored.cut_certificate_v1(),
                stored.park_certificate_v1(),
                stored.admission_set_sha256_v1(),
                stored.validator_set_v1(),
            )
            .map_err(|error| anyhow::anyhow!("reverify admitted ParkedAck: {error}"))
    }
}

/// Non-Clone proof that the local bounded ingress reserved its sole
/// ParkedAck slot for the exact declaration carrying the consumed local
/// parked authority.
#[must_use = "an originated ParkedAck must remain in its direct-seven barrier"]
pub(crate) struct OriginatedRestartParkedAckV1 {
    reservation: VerifiedRestartProtocolOriginReservationV1,
    declared: DeclaredRestartParkedAckV1,
}

impl std::fmt::Debug for OriginatedRestartParkedAckV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OriginatedRestartParkedAckV1")
            .field("origin", &self.declared.statement_v1().origin())
            .field("message_id", &self.reservation.message_id_v1())
            .field(
                "statement_sha256",
                &self.declared.statement_v1().statement_sha256(),
            )
            .finish_non_exhaustive()
    }
}

impl OriginatedRestartParkedAckV1 {
    pub(crate) fn new(
        reservation: RestartProtocolOriginReservationV1,
        declared: DeclaredRestartParkedAckV1,
    ) -> AnyResult<Self> {
        declared.revalidate_fresh_v1()?;
        let stored = declared.stored_cut_park_v1();
        let statement = declared.statement_v1();
        let payload = statement.encode();
        let reservation = reservation
            .into_verified_for_parts_v1(
                stored.validator_set_v1().id(),
                statement.origin(),
                RestartProtocolPhaseV1::ParkedAck,
                &payload,
            )
            .map_err(|error| anyhow::anyhow!("join local ParkedAck reservation: {error}"))?;
        let value = Self {
            reservation,
            declared,
        };
        value.revalidate_fresh_v1()?;
        Ok(value)
    }

    pub(crate) const fn statement_v1(&self) -> &SignedRestartParkedAckV1 {
        self.declared.statement_v1()
    }

    /// Borrowed durable Cut/Park facts used to strictly decode remote Ack
    /// slots while this originated owner remains in the local collector.
    pub(crate) const fn stored_cut_park_v1(&self) -> &StoredRestartCutParkCertificatesV1 {
        self.declared.stored_cut_park_v1()
    }

    pub(crate) fn message_id_v1(&self) -> [u8; 32] {
        self.reservation.message_id_v1()
    }

    const fn admission_instance_v1(&self) -> RestartProtocolAdmissionInstanceV1 {
        self.reservation.admission_instance_v1()
    }

    fn revalidate_fresh_v1(&self) -> AnyResult<()> {
        self.declared.revalidate_fresh_v1()?;
        let stored = self.declared.stored_cut_park_v1();
        let statement = self.declared.statement_v1();
        let payload = statement.encode();
        ensure!(
            self.reservation.validator_set_id_v1() == stored.validator_set_v1().id()
                && self.reservation.origin_v1() == statement.origin()
                && self.reservation.phase_v1() == RestartProtocolPhaseV1::ParkedAck
                && self.reservation.payload_v1() == payload
                && self.reservation.message_id_v1()
                    == restart_protocol_message_id_for_parts_v1(
                        stored.validator_set_v1().id(),
                        statement.origin(),
                        RestartProtocolPhaseV1::ParkedAck,
                        &payload,
                    )
                && self.reservation.payload_digest_v1()
                    == restart_protocol_payload_digest_for_parts_v1(
                        stored.validator_set_v1().id(),
                        statement.origin(),
                        RestartProtocolPhaseV1::ParkedAck,
                        &payload,
                    ),
            "retained originated ParkedAck differs from its exact reservation"
        );
        Ok(())
    }
}

enum RestartParkedAckSlotV1 {
    Admitted(AdmittedRestartParkedAckV1),
    Originated(OriginatedRestartParkedAckV1),
}

impl RestartParkedAckSlotV1 {
    const fn statement_v1(&self) -> &SignedRestartParkedAckV1 {
        match self {
            Self::Admitted(value) => value.statement_v1(),
            Self::Originated(value) => value.statement_v1(),
        }
    }

    fn message_id_v1(&self) -> [u8; 32] {
        match self {
            Self::Admitted(value) => value.message_id_v1(),
            Self::Originated(value) => value.message_id_v1(),
        }
    }

    const fn admission_instance_v1(&self) -> RestartProtocolAdmissionInstanceV1 {
        match self {
            Self::Admitted(value) => value.admission_instance_v1(),
            Self::Originated(value) => value.admission_instance_v1(),
        }
    }

    const fn is_originated_v1(&self) -> bool {
        matches!(self, Self::Originated(_))
    }
}

/// Non-Clone proof that exactly one local originated ParkedAck plus six
/// distinct authenticated remote ParkedAcks from the same admission map form
/// the exact direct-seven certificate and its phase-admission identity.
#[must_use = "the ParkedAck N/N barrier must cross its durable certificate/journal boundary"]
pub(crate) struct VerifiedRestartParkedAckBarrierV1 {
    statements: Vec<RestartParkedAckSlotV1>,
    certificate: RestartParkedAckCertificateV1,
    artifact_sha256: [u8; 32],
    admission_set_sha256: [u8; 32],
}

impl std::fmt::Debug for VerifiedRestartParkedAckBarrierV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedRestartParkedAckBarrierV1")
            .field(
                "target_validator",
                &self.certificate.common().target_validator(),
            )
            .field("statement_count", &self.statements.len())
            .field("artifact_sha256", &self.artifact_sha256)
            .field("admission_set_sha256", &self.admission_set_sha256)
            .finish_non_exhaustive()
    }
}

impl VerifiedRestartParkedAckBarrierV1 {
    pub(crate) fn new_with_originated_v1(
        admitted: Vec<AdmittedRestartParkedAckV1>,
        originated: OriginatedRestartParkedAckV1,
    ) -> AnyResult<Self> {
        originated.revalidate_fresh_v1()?;
        let local_validator = originated.statement_v1().origin();
        let admission_instance = originated.admission_instance_v1();
        {
            let stored = originated.declared.stored_cut_park_v1();
            ensure!(
                stored.validator_set_v1().validators().len() == 7
                    && admitted.len() == 6
                    && local_validator == stored.local_validator_v1(),
                "ParkedAck barrier is not one local plus six remote direct-seven members"
            );
            for statement in &admitted {
                statement.revalidate_v1(stored)?;
                ensure!(
                    statement.admission_instance_v1() == admission_instance
                        && statement.statement_v1().origin() != local_validator,
                    "ParkedAck statements came from another admission map or repeat local origin"
                );
            }
        }

        let mut canonical = BTreeMap::new();
        canonical.insert(
            local_validator,
            RestartParkedAckSlotV1::Originated(originated),
        );
        for statement in admitted {
            let origin = statement.statement_v1().origin();
            ensure!(
                canonical
                    .insert(origin, RestartParkedAckSlotV1::Admitted(statement))
                    .is_none(),
                "ParkedAck barrier repeats one authenticated origin"
            );
        }
        let validator_ids = match canonical.get(&local_validator) {
            Some(RestartParkedAckSlotV1::Originated(value)) => value
                .declared
                .stored_cut_park_v1()
                .validator_set_v1()
                .validators()
                .iter()
                .map(|validator| validator.id())
                .collect::<Vec<_>>(),
            _ => unreachable!("local ParkedAck slot changed during canonicalization"),
        };
        ensure!(
            canonical.len() == 7
                && validator_ids
                    .iter()
                    .all(|validator| canonical.contains_key(validator)),
            "ParkedAck barrier omits one direct-seven validator"
        );

        let statements = canonical.into_values().collect::<Vec<_>>();
        let stored = statements
            .iter()
            .find_map(|statement| match statement {
                RestartParkedAckSlotV1::Originated(value) => {
                    Some(value.declared.stored_cut_park_v1())
                }
                RestartParkedAckSlotV1::Admitted(_) => None,
            })
            .context("ParkedAck barrier lost its local originated owner")?;
        let common = *statements
            .first()
            .context("ParkedAck barrier unexpectedly empty")?
            .statement_v1()
            .common();
        ensure!(
            statements
                .iter()
                .all(|statement| statement.statement_v1().common() == &common)
                && statements
                    .iter()
                    .filter(|statement| statement.is_originated_v1())
                    .count()
                    == 1,
            "ParkedAck barrier differs in common facts or local provenance"
        );
        let certificate = RestartParkedAckCertificateV1::new(
            common,
            statements
                .iter()
                .map(|statement| statement.statement_v1().clone())
                .collect(),
            stored.fleet_start_certificate_v1(),
            stored.cut_certificate_v1(),
            stored.park_certificate_v1(),
            stored.admission_set_sha256_v1(),
            stored.validator_set_v1(),
        )
        .map_err(|error| anyhow::anyhow!("form exact ParkedAck certificate: {error}"))?;
        let message_ids = statements
            .iter()
            .map(|statement| (statement.statement_v1().origin(), statement.message_id_v1()))
            .collect::<BTreeMap<_, _>>();
        let admission_set_sha256 = restart_parked_ack_admission_set_sha256_for_ids_v1(
            &message_ids,
            stored.validator_set_v1(),
        )
        .map_err(|error| anyhow::anyhow!("form exact ParkedAck admission-set digest: {error}"))?;
        let artifact_sha256 = Sha256::digest(certificate.encode()).into();
        let value = Self {
            statements,
            certificate,
            artifact_sha256,
            admission_set_sha256,
        };
        value.revalidate_fresh_v1()?;
        Ok(value)
    }

    pub(crate) const fn certificate_v1(&self) -> &RestartParkedAckCertificateV1 {
        &self.certificate
    }

    pub(crate) const fn common_v1(&self) -> &RestartParkedAckCommonV1 {
        self.certificate.common()
    }

    pub(crate) const fn artifact_sha256_v1(&self) -> [u8; 32] {
        self.artifact_sha256
    }

    pub(crate) const fn admission_set_sha256_v1(&self) -> [u8; 32] {
        self.admission_set_sha256
    }

    pub(crate) const fn statement_count_v1(&self) -> usize {
        self.statements.len()
    }

    pub(crate) fn statement_message_id_v1(&self, origin: ValidatorId) -> Option<[u8; 32]> {
        self.statements
            .binary_search_by_key(&origin, |statement| statement.statement_v1().origin())
            .ok()
            .and_then(|index| self.statements.get(index))
            .map(RestartParkedAckSlotV1::message_id_v1)
    }

    pub(crate) fn local_statement_v1(&self) -> &SignedRestartParkedAckV1 {
        self.local_originated_v1().statement_v1()
    }

    pub(crate) fn stored_cut_park_v1(&self) -> &StoredRestartCutParkCertificatesV1 {
        self.local_originated_v1().declared.stored_cut_park_v1()
    }

    pub(crate) fn parked_facts_v1(&self) -> ContinuousRuntimeFactsV0 {
        self.local_originated_v1().declared.parked_facts_v1()
    }

    pub(crate) fn journal_commit_v1(&self) -> &LocalRestartParkJournalCommitV1 {
        self.local_originated_v1().declared.journal_commit_v1()
    }

    /// Consumes the complete phase-bound barrier through the hardened Ack
    /// store while retaining the local declared parked authority, exact
    /// Cut/Park stores, and journal-commit witness in the returned composite.
    pub(crate) fn persist_v1(
        self,
        config: &LoadedValidatorConfig,
    ) -> AnyResult<DurablyAcknowledgedRestartParkedBarrierV1> {
        self.revalidate_fresh_v1()?;
        let stored_cut_park = self.stored_cut_park_v1();
        ensure!(
            config.local_validator() == stored_cut_park.local_validator_v1()
                && config.config_sha256() == stored_cut_park.local_config_sha256_v1()
                && config.validator_set() == stored_cut_park.validator_set_v1(),
            "ParkedAck persistence config differs from the retained local barrier"
        );
        let local_witness = ack_store_witness_from_commit_v1(self.journal_commit_v1())?;
        let stored_ack = persist_restart_parked_ack_certificate_v1(
            config.run_root(),
            self.artifact_sha256,
            self.certificate.clone(),
            stored_cut_park.cut_artifact_sha256_v1(),
            stored_cut_park.cut_certificate_v1(),
            stored_cut_park.park_artifact_sha256_v1(),
            stored_cut_park.park_certificate_v1(),
            stored_cut_park.admission_set_sha256_v1(),
            stored_cut_park.local_validator_v1(),
            stored_cut_park.local_config_sha256_v1(),
            local_witness,
            stored_cut_park.fleet_start_certificate_v1(),
            stored_cut_park.validator_set_v1(),
        )
        .context("persist exact phase-bound ParkedAck certificate")?;
        let value = DurablyAcknowledgedRestartParkedBarrierV1 {
            barrier: self,
            stored_ack,
        };
        value.revalidate_fresh_v1()?;
        Ok(value)
    }

    pub(crate) fn revalidate_fresh_v1(&self) -> AnyResult<()> {
        let originated = self.local_originated_v1();
        originated.revalidate_fresh_v1()?;
        let stored = originated.declared.stored_cut_park_v1();
        ensure!(
            stored.validator_set_v1().validators().len() == 7
                && self.statements.len() == 7
                && originated.statement_v1().origin() == stored.local_validator_v1(),
            "retained ParkedAck barrier lost direct-seven local provenance"
        );
        let admission_instance = originated.admission_instance_v1();
        let mut message_ids = BTreeMap::new();
        let mut originated_count = 0usize;
        let mut previous = None;
        for statement in &self.statements {
            ensure!(
                statement.admission_instance_v1() == admission_instance
                    && previous.is_none_or(|origin| origin < statement.statement_v1().origin()),
                "retained ParkedAck barrier changed admission map or canonical order"
            );
            match statement {
                RestartParkedAckSlotV1::Admitted(value) => value.revalidate_v1(stored)?,
                RestartParkedAckSlotV1::Originated(value) => {
                    value.revalidate_fresh_v1()?;
                    originated_count += 1;
                }
            }
            previous = Some(statement.statement_v1().origin());
            ensure!(
                message_ids
                    .insert(statement.statement_v1().origin(), statement.message_id_v1())
                    .is_none(),
                "retained ParkedAck barrier repeats one origin"
            );
        }
        ensure!(
            originated_count == 1
                && stored
                    .validator_set_v1()
                    .validators()
                    .iter()
                    .all(|validator| message_ids.contains_key(&validator.id())),
            "retained ParkedAck barrier lost exact membership"
        );
        self.certificate
            .verify(
                stored.fleet_start_certificate_v1(),
                stored.cut_certificate_v1(),
                stored.park_certificate_v1(),
                stored.admission_set_sha256_v1(),
                stored.validator_set_v1(),
            )
            .map_err(|error| anyhow::anyhow!("reverify retained ParkedAck certificate: {error}"))?;
        let admission_set_sha256 = restart_parked_ack_admission_set_sha256_for_ids_v1(
            &message_ids,
            stored.validator_set_v1(),
        )
        .map_err(|error| anyhow::anyhow!("reverify ParkedAck admission set: {error}"))?;
        let fresh_artifact_sha256: [u8; 32] = Sha256::digest(self.certificate.encode()).into();
        ensure!(
            self.certificate.common() == self.statements[0].statement_v1().common()
                && self.statements.iter().all(|statement| self
                    .certificate
                    .statement(statement.statement_v1().origin())
                    == Some(statement.statement_v1()))
                && fresh_artifact_sha256 == self.artifact_sha256
                && admission_set_sha256 == self.admission_set_sha256,
            "retained ParkedAck certificate or phase identities changed"
        );
        Ok(())
    }

    fn local_originated_v1(&self) -> &OriginatedRestartParkedAckV1 {
        self.statements
            .iter()
            .find_map(|statement| match statement {
                RestartParkedAckSlotV1::Originated(value) => Some(value),
                RestartParkedAckSlotV1::Admitted(_) => None,
            })
            .expect("verified ParkedAck barrier retains one local originated slot")
    }
}

fn ack_store_witness_from_commit_v1(
    commit: &LocalRestartParkJournalCommitV1,
) -> AnyResult<RestartParkedAckLocalWitnessV1> {
    RestartParkedAckLocalWitnessV1::new(
        commit.role_v1(),
        commit.local_park_statement_sha256_v1(),
        commit.predecessor_sequence_v1(),
        commit.predecessor_sha256_v1(),
        commit.restart_cut_event_sequence_v1(),
        commit.restart_cut_event_sha256_v1(),
        commit.restart_park_event_sequence_v1(),
        commit.restart_park_event_sha256_v1(),
    )
}

/// Final same-process ParkedAck durable composite.  The standalone Ack store
/// is inert data; this owner is the boundary that keeps it joined to the exact
/// freshly revalidated Cut/Park stores, local journal commit, fifth-phase
/// admission digest, and consumed continuous parked authority.
#[must_use = "the durable ParkedAck composite must remain joined through its rpa1/P2 gates"]
pub(crate) struct DurablyAcknowledgedRestartParkedBarrierV1 {
    barrier: VerifiedRestartParkedAckBarrierV1,
    stored_ack: StoredRestartParkedAckCertificateV1,
}

impl std::fmt::Debug for DurablyAcknowledgedRestartParkedBarrierV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurablyAcknowledgedRestartParkedBarrierV1")
            .field("local_validator", &self.local_statement_v1().origin())
            .field("role", &self.local_statement_v1().role())
            .field("ack_artifact_sha256", &self.ack_artifact_sha256_v1())
            .field(
                "ack_admission_set_sha256",
                &self.ack_admission_set_sha256_v1(),
            )
            .finish_non_exhaustive()
    }
}

impl DurablyAcknowledgedRestartParkedBarrierV1 {
    pub(crate) fn stored_cut_park_v1(&self) -> &StoredRestartCutParkCertificatesV1 {
        self.barrier.stored_cut_park_v1()
    }

    pub(crate) const fn stored_ack_v1(&self) -> &StoredRestartParkedAckCertificateV1 {
        &self.stored_ack
    }

    pub(crate) const fn ack_certificate_v1(&self) -> &RestartParkedAckCertificateV1 {
        self.barrier.certificate_v1()
    }

    pub(crate) const fn ack_artifact_sha256_v1(&self) -> [u8; 32] {
        self.barrier.artifact_sha256_v1()
    }

    /// Digest of the seven exact fifth-phase transport message IDs. This is
    /// deliberately distinct from the prior Cut/Park admission digest in the
    /// signed Ack common facts.
    pub(crate) const fn ack_admission_set_sha256_v1(&self) -> [u8; 32] {
        self.barrier.admission_set_sha256_v1()
    }

    pub(crate) fn local_statement_v1(&self) -> &SignedRestartParkedAckV1 {
        self.barrier.local_statement_v1()
    }

    pub(crate) fn journal_commit_v1(&self) -> &LocalRestartParkJournalCommitV1 {
        self.barrier.journal_commit_v1()
    }

    pub(crate) fn parked_facts_v1(&self) -> ContinuousRuntimeFactsV0 {
        self.barrier.parked_facts_v1()
    }

    pub(crate) fn revalidate_fresh_v1(&self) -> AnyResult<()> {
        self.barrier.revalidate_fresh_v1()?;
        let stored_cut_park = self.barrier.stored_cut_park_v1();
        let expected_witness = ack_store_witness_from_commit_v1(self.barrier.journal_commit_v1())?;
        self.stored_ack
            .revalidate_fresh_v1(
                stored_cut_park.fleet_start_certificate_v1(),
                stored_cut_park.validator_set_v1(),
            )
            .context("fresh-revalidate stored ParkedAck in durable composite")?;
        ensure!(
            self.stored_ack.value_v1() == self.barrier.certificate_v1()
                && self.stored_ack.artifact_sha256_v1() == self.barrier.artifact_sha256_v1()
                && self.stored_ack.restart_cut_certificate_v1()
                    == stored_cut_park.cut_certificate_v1()
                && self.stored_ack.restart_cut_artifact_sha256_v1()
                    == stored_cut_park.cut_artifact_sha256_v1()
                && self.stored_ack.restart_park_certificate_v1()
                    == stored_cut_park.park_certificate_v1()
                && self.stored_ack.restart_park_artifact_sha256_v1()
                    == stored_cut_park.park_artifact_sha256_v1()
                && self.stored_ack.restart_cut_park_admission_set_sha256_v1()
                    == stored_cut_park.admission_set_sha256_v1()
                && self.stored_ack.local_validator_v1() == stored_cut_park.local_validator_v1()
                && self.stored_ack.local_config_sha256_v1()
                    == stored_cut_park.local_config_sha256_v1()
                && self.stored_ack.local_witness_v1() == expected_witness
                && self.stored_ack.local_statement_v1() == self.barrier.local_statement_v1()
                && self.stored_ack.statement_count_v1() == 7
                && self.barrier.admission_set_sha256_v1() != [0; 32],
            "durable ParkedAck store differs from its retained barrier, journal, or Cut/Park owner"
        );
        Ok(())
    }
}
