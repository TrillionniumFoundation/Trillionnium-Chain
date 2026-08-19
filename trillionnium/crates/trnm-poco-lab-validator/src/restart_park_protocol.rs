//! Phase-bound direct-seven RestartCut/RestartPark barrier ownership.
//!
//! The raw wire values in `restart_cut` are cloneable signed data. They do
//! not prove that the local bounded ingress admitted a distinct target
//! Prepare slot and seven Cut slots. This module consumes the non-Clone `New`
//! admission owner for each slot, performs the phase/origin/canonical wire
//! joins, and retains those owners alongside both exact certificates.
//!
//! This boundary exposes one narrow dual-store persistence/reopen seam but no
//! signing key, journal write, process control, Ready/Start, timer, network,
//! or activation authority.  A process transition must additionally consume
//! the exact signed-journal owner that commits both artifact identities.

use std::collections::BTreeMap;

use anyhow::{ensure, Context, Result as AnyResult};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{ValidatorId, ValidatorSet};

use crate::{
    config::LoadedValidatorConfig,
    continuous_runtime::ContinuousRestartDeclaredParkAuthorityV1,
    fleet_barrier::FleetStartCertificateV1,
    process_event::LocalRestartParkJournalCommitV1,
    restart_cut::{
        RestartCutCertificateV1, RestartCutErrorV1, RestartCutParkStatementV1,
        RestartParkCertificateV1, RestartParkRoleV1, SignedRestartCutV1,
        VerifiedRestartCutCertificateV1, VerifiedRestartPrepareV1,
    },
    restart_cut_store::{
        load_fleet_start_certificate_v1, load_local_restart_cut_certificate_v1,
        persist_local_restart_cut_certificate_v1, StoredRestartCutCertificateV1,
    },
    restart_park_store::{
        load_restart_park_certificate_v1, persist_restart_park_certificate_v1,
        StoredRestartParkCertificateV1,
    },
    restart_parked_ack_protocol::{issue_local_restart_parked_ack_v1, DeclaredRestartParkedAckV1},
    restart_protocol::{
        restart_protocol_message_id_for_parts_v1, restart_protocol_payload_digest_for_parts_v1,
        AdmittedRestartProtocolMessageV1, RestartProtocolAdmissionInstanceV1,
        RestartProtocolOriginReservationV1, RestartProtocolPhaseV1,
        VerifiedRestartProtocolOriginReservationV1,
    },
};

const RESTART_PARK_ADMISSION_SET_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-park-admission-set.v1";
const RESTART_PARK_PREPARE_ID_TAG_V1: &[u8] = b"Prepare";
const RESTART_PARK_CUT_ID_TAG_V1: &[u8] = b"Cut";

/// Non-Clone proof that a target-authored declaration occupied one fresh
/// authenticated Prepare slot and passed the exact FleetStart/set join.
#[must_use = "an admitted target Prepare must remain paired with its Cut barrier"]
pub(crate) struct AdmittedRestartPrepareV1 {
    admission: AdmittedRestartProtocolMessageV1,
    verified: VerifiedRestartPrepareV1,
}

impl std::fmt::Debug for AdmittedRestartPrepareV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedRestartPrepareV1")
            .field("origin", &self.admission.origin_v1())
            .field("message_id", &self.admission.message_id_v1())
            .field("body_digest", &self.verified.body().digest())
            .finish_non_exhaustive()
    }
}

impl AdmittedRestartPrepareV1 {
    pub(crate) fn new(
        admission: AdmittedRestartProtocolMessageV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        if admission.validator_set_id_v1() != validator_set.id() {
            return Err(RestartCutErrorV1::WrongCampaign);
        }
        if admission.phase_v1() != RestartProtocolPhaseV1::Prepare {
            return Err(RestartCutErrorV1::WrongProtocolPhase);
        }
        let declaration = SignedRestartCutV1::decode(admission.payload_v1(), validator_set)?;
        if declaration.encode() != admission.payload_v1() {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        if declaration.origin() != admission.origin_v1() {
            return Err(RestartCutErrorV1::AuthenticatedOriginMismatch);
        }
        let verified =
            declaration.verify_target_prepare_owned(fleet_start_certificate, validator_set)?;
        let value = Self {
            admission,
            verified,
        };
        value.revalidate_v1(fleet_start_certificate, validator_set)?;
        Ok(value)
    }

    pub(crate) const fn declaration_v1(&self) -> &SignedRestartCutV1 {
        self.verified.target_declaration()
    }

    pub(crate) const fn body_v1(&self) -> &crate::restart_cut::RestartCutBodyV1 {
        self.verified.body()
    }

    pub(crate) fn message_id_v1(&self) -> [u8; 32] {
        self.admission.message_id_v1()
    }

    const fn admission_instance_v1(&self) -> RestartProtocolAdmissionInstanceV1 {
        self.admission.admission_instance_v1()
    }

    fn revalidate_v1(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        if self.admission.validator_set_id_v1() != validator_set.id() {
            return Err(RestartCutErrorV1::WrongCampaign);
        }
        if self.admission.phase_v1() != RestartProtocolPhaseV1::Prepare {
            return Err(RestartCutErrorV1::WrongProtocolPhase);
        }
        let declaration = self.verified.target_declaration();
        if self.admission.origin_v1() != declaration.origin() {
            return Err(RestartCutErrorV1::AuthenticatedOriginMismatch);
        }
        if self.admission.payload_v1() != declaration.encode() {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        let freshly_verified = declaration
            .clone()
            .verify_target_prepare_owned(fleet_start_certificate, validator_set)?;
        if freshly_verified.target_declaration() != declaration {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        Ok(())
    }
}

/// Non-Clone proof that the local bounded ingress reserved the sole Prepare
/// slot for this exact target-authored declaration.  The receipt cannot be
/// promoted from a remote payload or reconstructed from scalar identities.
#[must_use = "an originated target Prepare must remain paired with its Cut barrier"]
pub(crate) struct OriginatedRestartPrepareV1 {
    reservation: VerifiedRestartProtocolOriginReservationV1,
    verified: VerifiedRestartPrepareV1,
}

impl OriginatedRestartPrepareV1 {
    pub(crate) fn new(
        reservation: RestartProtocolOriginReservationV1,
        declaration: SignedRestartCutV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        let verified =
            declaration.verify_target_prepare_owned(fleet_start_certificate, validator_set)?;
        let payload = verified.target_declaration().encode();
        let reservation = reservation
            .into_verified_for_parts_v1(
                validator_set.id(),
                verified.target_declaration().origin(),
                RestartProtocolPhaseV1::Prepare,
                &payload,
            )
            .map_err(|_| RestartCutErrorV1::AuthenticatedOriginMismatch)?;
        let value = Self {
            reservation,
            verified,
        };
        value.revalidate_v1(fleet_start_certificate, validator_set)?;
        Ok(value)
    }

    fn revalidate_v1(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        let declaration = self.verified.target_declaration();
        let payload = declaration.encode();
        if self.reservation.validator_set_id_v1() != validator_set.id()
            || self.reservation.origin_v1() != declaration.origin()
            || self.reservation.phase_v1() != RestartProtocolPhaseV1::Prepare
            || self.reservation.payload_v1() != payload
            || self.reservation.message_id_v1()
                != restart_protocol_message_id_for_parts_v1(
                    validator_set.id(),
                    declaration.origin(),
                    RestartProtocolPhaseV1::Prepare,
                    &payload,
                )
            || self.reservation.payload_digest_v1()
                != restart_protocol_payload_digest_for_parts_v1(
                    validator_set.id(),
                    declaration.origin(),
                    RestartProtocolPhaseV1::Prepare,
                    &payload,
                )
        {
            return Err(RestartCutErrorV1::AuthenticatedOriginMismatch);
        }
        let _ = declaration
            .clone()
            .verify_target_prepare_owned(fleet_start_certificate, validator_set)?;
        Ok(())
    }
}

enum RestartPrepareSlotV1 {
    Admitted(AdmittedRestartPrepareV1),
    Originated(OriginatedRestartPrepareV1),
}

impl RestartPrepareSlotV1 {
    const fn declaration_v1(&self) -> &SignedRestartCutV1 {
        match self {
            Self::Admitted(value) => value.declaration_v1(),
            Self::Originated(value) => value.verified.target_declaration(),
        }
    }

    const fn body_v1(&self) -> &crate::restart_cut::RestartCutBodyV1 {
        match self {
            Self::Admitted(value) => value.body_v1(),
            Self::Originated(value) => value.verified.body(),
        }
    }

    fn message_id_v1(&self) -> [u8; 32] {
        match self {
            Self::Admitted(value) => value.message_id_v1(),
            Self::Originated(value) => value.reservation.message_id_v1(),
        }
    }

    const fn admission_instance_v1(&self) -> RestartProtocolAdmissionInstanceV1 {
        match self {
            Self::Admitted(value) => value.admission_instance_v1(),
            Self::Originated(value) => value.reservation.admission_instance_v1(),
        }
    }

    fn revalidate_v1(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        match self {
            Self::Admitted(value) => value.revalidate_v1(fleet_start_certificate, validator_set),
            Self::Originated(value) => value.revalidate_v1(fleet_start_certificate, validator_set),
        }
    }
}

/// Non-Clone proof that one exact dual Cut/Park statement occupied its
/// authenticated origin's sole fresh Cut slot.
#[must_use = "an admitted Cut/Park statement must remain in its seven-way barrier"]
pub(crate) struct AdmittedRestartCutParkV1 {
    admission: AdmittedRestartProtocolMessageV1,
    statement: RestartCutParkStatementV1,
}

impl std::fmt::Debug for AdmittedRestartCutParkV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedRestartCutParkV1")
            .field("origin", &self.statement.origin())
            .field("message_id", &self.admission.message_id_v1())
            .field("statement_sha256", &self.statement.statement_sha256())
            .finish_non_exhaustive()
    }
}

impl AdmittedRestartCutParkV1 {
    pub(crate) fn new(
        admission: AdmittedRestartProtocolMessageV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        if admission.validator_set_id_v1() != validator_set.id() {
            return Err(RestartCutErrorV1::WrongCampaign);
        }
        if admission.phase_v1() != RestartProtocolPhaseV1::Cut {
            return Err(RestartCutErrorV1::WrongProtocolPhase);
        }
        let statement = RestartCutParkStatementV1::decode(
            admission.payload_v1(),
            fleet_start_certificate,
            validator_set,
        )?;
        if statement.encode() != admission.payload_v1() {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        if statement.origin() != admission.origin_v1() {
            return Err(RestartCutErrorV1::AuthenticatedOriginMismatch);
        }
        let value = Self {
            admission,
            statement,
        };
        value.revalidate_v1(fleet_start_certificate, validator_set)?;
        Ok(value)
    }

    pub(crate) const fn statement_v1(&self) -> &RestartCutParkStatementV1 {
        &self.statement
    }

    pub(crate) fn message_id_v1(&self) -> [u8; 32] {
        self.admission.message_id_v1()
    }

    const fn admission_instance_v1(&self) -> RestartProtocolAdmissionInstanceV1 {
        self.admission.admission_instance_v1()
    }

    fn revalidate_v1(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        if self.admission.validator_set_id_v1() != validator_set.id() {
            return Err(RestartCutErrorV1::WrongCampaign);
        }
        if self.admission.phase_v1() != RestartProtocolPhaseV1::Cut {
            return Err(RestartCutErrorV1::WrongProtocolPhase);
        }
        if self.admission.origin_v1() != self.statement.origin() {
            return Err(RestartCutErrorV1::AuthenticatedOriginMismatch);
        }
        if self.admission.payload_v1() != self.statement.encode() {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        self.statement
            .verify(fleet_start_certificate, validator_set)
    }
}

/// Non-Clone proof that the local bounded ingress reserved the sole Cut slot
/// for this exact dual Cut/Park payload.
#[must_use = "an originated Cut/Park statement must remain in its seven-way barrier"]
pub(crate) struct OriginatedRestartCutParkV1 {
    reservation: VerifiedRestartProtocolOriginReservationV1,
    declared: LocalRestartCutParkStatementOwnerV1,
}

impl OriginatedRestartCutParkV1 {
    pub(crate) fn new(
        reservation: RestartProtocolOriginReservationV1,
        declared: ContinuousRestartDeclaredParkAuthorityV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        let statement = declared.statement_v1();
        let payload = statement.encode();
        let reservation = reservation
            .into_verified_for_parts_v1(
                validator_set.id(),
                statement.origin(),
                RestartProtocolPhaseV1::Cut,
                &payload,
            )
            .map_err(|_| RestartCutErrorV1::AuthenticatedOriginMismatch)?;
        let value = Self {
            reservation,
            declared: LocalRestartCutParkStatementOwnerV1::Declared(declared),
        };
        value.revalidate_v1(fleet_start_certificate, validator_set)?;
        Ok(value)
    }

    #[cfg(test)]
    pub(crate) fn new_test_only(
        reservation: RestartProtocolOriginReservationV1,
        statement: RestartCutParkStatementV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        let payload = statement.encode();
        let reservation = reservation
            .into_verified_for_parts_v1(
                validator_set.id(),
                statement.origin(),
                RestartProtocolPhaseV1::Cut,
                &payload,
            )
            .map_err(|_| RestartCutErrorV1::AuthenticatedOriginMismatch)?;
        let value = Self {
            reservation,
            declared: LocalRestartCutParkStatementOwnerV1::TestOnly(statement),
        };
        value.revalidate_v1(fleet_start_certificate, validator_set)?;
        Ok(value)
    }

    const fn statement_v1(&self) -> &RestartCutParkStatementV1 {
        self.declared.statement_v1()
    }

    fn revalidate_v1(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        let payload = self.statement_v1().encode();
        if self.reservation.validator_set_id_v1() != validator_set.id()
            || self.reservation.origin_v1() != self.statement_v1().origin()
            || self.reservation.phase_v1() != RestartProtocolPhaseV1::Cut
            || self.reservation.payload_v1() != payload
            || self.reservation.message_id_v1()
                != restart_protocol_message_id_for_parts_v1(
                    validator_set.id(),
                    self.statement_v1().origin(),
                    RestartProtocolPhaseV1::Cut,
                    &payload,
                )
            || self.reservation.payload_digest_v1()
                != restart_protocol_payload_digest_for_parts_v1(
                    validator_set.id(),
                    self.statement_v1().origin(),
                    RestartProtocolPhaseV1::Cut,
                    &payload,
                )
        {
            return Err(RestartCutErrorV1::AuthenticatedOriginMismatch);
        }
        self.statement_v1()
            .verify(fleet_start_certificate, validator_set)
    }

    fn into_declared_authority_v1(self) -> Option<ContinuousRestartDeclaredParkAuthorityV1> {
        self.declared.into_declared_authority_v1()
    }
}

enum LocalRestartCutParkStatementOwnerV1 {
    Declared(ContinuousRestartDeclaredParkAuthorityV1),
    #[cfg(test)]
    TestOnly(RestartCutParkStatementV1),
}

impl LocalRestartCutParkStatementOwnerV1 {
    const fn statement_v1(&self) -> &RestartCutParkStatementV1 {
        match self {
            Self::Declared(value) => value.statement_v1(),
            #[cfg(test)]
            Self::TestOnly(value) => value,
        }
    }

    fn into_declared_authority_v1(self) -> Option<ContinuousRestartDeclaredParkAuthorityV1> {
        match self {
            Self::Declared(value) => Some(value),
            #[cfg(test)]
            Self::TestOnly(_) => None,
        }
    }
}

enum RestartCutParkSlotV1 {
    Admitted(AdmittedRestartCutParkV1),
    Originated(OriginatedRestartCutParkV1),
}

impl RestartCutParkSlotV1 {
    const fn statement_v1(&self) -> &RestartCutParkStatementV1 {
        match self {
            Self::Admitted(value) => value.statement_v1(),
            Self::Originated(value) => value.statement_v1(),
        }
    }

    fn message_id_v1(&self) -> [u8; 32] {
        match self {
            Self::Admitted(value) => value.message_id_v1(),
            Self::Originated(value) => value.reservation.message_id_v1(),
        }
    }

    const fn admission_instance_v1(&self) -> RestartProtocolAdmissionInstanceV1 {
        match self {
            Self::Admitted(value) => value.admission_instance_v1(),
            Self::Originated(value) => value.reservation.admission_instance_v1(),
        }
    }

    fn revalidate_v1(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        match self {
            Self::Admitted(value) => value.revalidate_v1(fleet_start_certificate, validator_set),
            Self::Originated(value) => value.revalidate_v1(fleet_start_certificate, validator_set),
        }
    }
}

/// Non-Clone proof that one distinct authenticated target Prepare and all
/// seven distinct authenticated Cut slots deterministically form both exact
/// certificates. The phase admissions and certificates cannot be split by
/// this API; a later composite durable boundary must consume the whole owner.
#[must_use = "the phase-bound dual certificate owner must cross one composite durable boundary"]
pub(crate) struct VerifiedRestartCutParkCertificatesV1 {
    target_prepare: RestartPrepareSlotV1,
    statements: Vec<RestartCutParkSlotV1>,
    cut_certificate: VerifiedRestartCutCertificateV1,
    park_certificate: RestartParkCertificateV1,
    park_artifact_sha256: [u8; 32],
    admission_set_sha256: [u8; 32],
}

impl std::fmt::Debug for VerifiedRestartCutParkCertificatesV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedRestartCutParkCertificatesV1")
            .field(
                "target_validator",
                &self.target_prepare.body_v1().target_validator(),
            )
            .field("prepare_message_id", &self.target_prepare.message_id_v1())
            .field("statement_count", &self.statements.len())
            .field(
                "cut_artifact_sha256",
                &self.cut_certificate.artifact_sha256(),
            )
            .field("park_artifact_sha256", &self.park_artifact_sha256)
            .field("admission_set_sha256", &self.admission_set_sha256)
            .finish_non_exhaustive()
    }
}

impl VerifiedRestartCutParkCertificatesV1 {
    pub(crate) fn new(
        target_prepare: AdmittedRestartPrepareV1,
        statements: Vec<AdmittedRestartCutParkV1>,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        Self::new_phase_bound_v1(
            RestartPrepareSlotV1::Admitted(target_prepare),
            statements
                .into_iter()
                .map(RestartCutParkSlotV1::Admitted)
                .collect(),
            fleet_start_certificate,
            validator_set,
        )
    }

    pub(crate) fn new_with_originated_prepare_v1(
        target_prepare: OriginatedRestartPrepareV1,
        statements: Vec<AdmittedRestartCutParkV1>,
        local_statement: OriginatedRestartCutParkV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        let mut statements = statements
            .into_iter()
            .map(RestartCutParkSlotV1::Admitted)
            .collect::<Vec<_>>();
        statements.push(RestartCutParkSlotV1::Originated(local_statement));
        Self::new_phase_bound_v1(
            RestartPrepareSlotV1::Originated(target_prepare),
            statements,
            fleet_start_certificate,
            validator_set,
        )
    }

    pub(crate) fn new_with_originated_cut_v1(
        target_prepare: AdmittedRestartPrepareV1,
        statements: Vec<AdmittedRestartCutParkV1>,
        local_statement: OriginatedRestartCutParkV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        let mut statements = statements
            .into_iter()
            .map(RestartCutParkSlotV1::Admitted)
            .collect::<Vec<_>>();
        statements.push(RestartCutParkSlotV1::Originated(local_statement));
        Self::new_phase_bound_v1(
            RestartPrepareSlotV1::Admitted(target_prepare),
            statements,
            fleet_start_certificate,
            validator_set,
        )
    }

    fn new_phase_bound_v1(
        target_prepare: RestartPrepareSlotV1,
        statements: Vec<RestartCutParkSlotV1>,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCutErrorV1> {
        target_prepare.revalidate_v1(fleet_start_certificate, validator_set)?;
        if validator_set.validators().len() != 7 {
            return Err(RestartCutErrorV1::WrongCampaign);
        }
        let mut canonical = BTreeMap::new();
        for statement in statements {
            statement.revalidate_v1(fleet_start_certificate, validator_set)?;
            if statement.admission_instance_v1() != target_prepare.admission_instance_v1() {
                return Err(RestartCutErrorV1::DifferentAdmissionMap);
            }
            if statement.statement_v1().body() != target_prepare.body_v1() {
                return Err(RestartCutErrorV1::DifferentCut);
            }
            if canonical
                .insert(statement.statement_v1().origin(), statement)
                .is_some()
            {
                return Err(RestartCutErrorV1::DuplicateOrigin);
            }
        }
        if canonical.len() != 7
            || validator_set
                .validators()
                .iter()
                .any(|validator| !canonical.contains_key(&validator.id()))
        {
            return Err(RestartCutErrorV1::Incomplete);
        }
        let target_statement = canonical
            .get(&target_prepare.body_v1().target_validator())
            .ok_or(RestartCutErrorV1::Incomplete)?;
        if target_statement.statement_v1().cut() != target_prepare.declaration_v1() {
            return Err(RestartCutErrorV1::DifferentCut);
        }

        let statements = canonical.into_values().collect::<Vec<_>>();
        let (cut_certificate, park_certificate, park_artifact_sha256) = rebuild_certificates_v1(
            &target_prepare,
            &statements,
            fleet_start_certificate,
            validator_set,
        )?;
        let admission_set_sha256 =
            admission_set_sha256_from_admitted_v1(&target_prepare, &statements, validator_set)?;
        Ok(Self {
            target_prepare,
            statements,
            cut_certificate,
            park_certificate,
            park_artifact_sha256,
            admission_set_sha256,
        })
    }

    pub(crate) const fn body_v1(&self) -> &crate::restart_cut::RestartCutBodyV1 {
        self.target_prepare.body_v1()
    }

    pub(crate) fn prepare_message_id_v1(&self) -> [u8; 32] {
        self.target_prepare.message_id_v1()
    }

    pub(crate) const fn statement_count_v1(&self) -> usize {
        self.statements.len()
    }

    pub(crate) fn statement_message_id_v1(&self, origin: ValidatorId) -> Option<[u8; 32]> {
        self.statements
            .binary_search_by_key(&origin, |statement| statement.statement_v1().origin())
            .ok()
            .and_then(|index| self.statements.get(index))
            .map(RestartCutParkSlotV1::message_id_v1)
    }

    pub(crate) const fn cut_artifact_sha256_v1(&self) -> [u8; 32] {
        self.cut_certificate.artifact_sha256()
    }

    pub(crate) const fn park_artifact_sha256_v1(&self) -> [u8; 32] {
        self.park_artifact_sha256
    }

    pub(crate) const fn admission_set_sha256_v1(&self) -> [u8; 32] {
        self.admission_set_sha256
    }

    pub(crate) fn revalidate_v1(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<(), RestartCutErrorV1> {
        self.target_prepare
            .revalidate_v1(fleet_start_certificate, validator_set)?;
        if validator_set.validators().len() != 7 || self.statements.len() != 7 {
            return Err(RestartCutErrorV1::WrongCampaign);
        }
        let mut previous = None;
        for statement in &self.statements {
            statement.revalidate_v1(fleet_start_certificate, validator_set)?;
            if statement.admission_instance_v1() != self.target_prepare.admission_instance_v1() {
                return Err(RestartCutErrorV1::DifferentAdmissionMap);
            }
            if statement.statement_v1().body() != self.target_prepare.body_v1() {
                return Err(RestartCutErrorV1::DifferentCut);
            }
            if previous.is_some_and(|origin| origin >= statement.statement_v1().origin()) {
                return Err(RestartCutErrorV1::DuplicateOrigin);
            }
            previous = Some(statement.statement_v1().origin());
        }
        if validator_set.validators().iter().any(|validator| {
            self.statements
                .binary_search_by_key(&validator.id(), |statement| {
                    statement.statement_v1().origin()
                })
                .is_err()
        }) {
            return Err(RestartCutErrorV1::Incomplete);
        }
        if self
            .statements
            .binary_search_by_key(
                &self.target_prepare.body_v1().target_validator(),
                |statement| statement.statement_v1().origin(),
            )
            .ok()
            .and_then(|index| self.statements.get(index))
            .is_none_or(|statement| {
                statement.statement_v1().cut() != self.target_prepare.declaration_v1()
            })
        {
            return Err(RestartCutErrorV1::DifferentCut);
        }
        let (cut, park, park_sha256) = rebuild_certificates_v1(
            &self.target_prepare,
            &self.statements,
            fleet_start_certificate,
            validator_set,
        )?;
        if cut.certificate() != self.cut_certificate.certificate()
            || cut.artifact_sha256() != self.cut_certificate.artifact_sha256()
            || park != self.park_certificate
            || park_sha256 != self.park_artifact_sha256
            || admission_set_sha256_from_admitted_v1(
                &self.target_prepare,
                &self.statements,
                validator_set,
            )? != self.admission_set_sha256
        {
            return Err(RestartCutErrorV1::NonCanonical);
        }
        Ok(())
    }

    /// Consumes a target-local phase-bound pair through both create-new
    /// durable stores. Process-2 startup still accepts only this role.
    pub(crate) fn persist_target_v1(
        self,
        config: &LoadedValidatorConfig,
        fleet_start_certificate: &FleetStartCertificateV1,
    ) -> AnyResult<DurablyParkedTargetRestartOwnerV1> {
        let (stored, declared) =
            self.persist_local_role_v1(config, fleet_start_certificate, RestartParkRoleV1::Target)?;
        let declared = declared.context(
            "target Cut/Park persistence lost its consumed continuous restart authority",
        )?;
        Ok(DurablyParkedTargetRestartOwnerV1 { stored, declared })
    }

    /// Consumes a peer-local phase-bound pair through the same two hardened
    /// artifact stores. This grants no process-2 startup authority; the peer
    /// journal must separately consume it into its process-1 parked state.
    pub(crate) fn persist_peer_v1(
        self,
        config: &LoadedValidatorConfig,
        fleet_start_certificate: &FleetStartCertificateV1,
    ) -> AnyResult<DurablyParkedPeerRestartOwnerV1> {
        let (stored, declared) =
            self.persist_local_role_v1(config, fleet_start_certificate, RestartParkRoleV1::Peer)?;
        let declared = declared
            .context("peer Cut/Park persistence lost its consumed continuous restart authority")?;
        Ok(DurablyParkedPeerRestartOwnerV1 { stored, declared })
    }

    fn persist_local_role_v1(
        mut self,
        config: &LoadedValidatorConfig,
        fleet_start_certificate: &FleetStartCertificateV1,
        expected_role: RestartParkRoleV1,
    ) -> AnyResult<(
        StoredRestartCutParkCertificatesV1,
        Option<ContinuousRestartDeclaredParkAuthorityV1>,
    )> {
        self.revalidate_v1(fleet_start_certificate, config.validator_set())
            .map_err(|error| anyhow::anyhow!("revalidate phase-bound Cut/Park pair: {error}"))?;
        let local_validator = config.local_validator();
        let local_config_sha256 = config.config_sha256();
        let prepare_provenance = matches!(
            (&self.target_prepare, expected_role),
            (
                RestartPrepareSlotV1::Originated(_),
                RestartParkRoleV1::Target
            ) | (RestartPrepareSlotV1::Admitted(_), RestartParkRoleV1::Peer)
        );
        let local_cut_index = self.statements.iter().position(|statement| {
            statement.statement_v1().origin() == local_validator
                && matches!(statement, RestartCutParkSlotV1::Originated(_))
        });
        ensure!(
            prepare_provenance
                && local_cut_index.is_some()
                && self.body_v1().process_instance() == 1
                && match expected_role {
                    RestartParkRoleV1::Target => {
                        self.body_v1().target_validator() == local_validator
                            && self.body_v1().target_config_sha256() == local_config_sha256
                    }
                    RestartParkRoleV1::Peer => {
                        self.body_v1().target_validator() != local_validator
                    }
                },
            "phase-bound Cut/Park pair lacks the exact local phase provenance or process-1 role"
        );
        let local_park = self
            .park_certificate
            .statement(local_validator)
            .context("phase-bound park certificate lacks the target statement")?;
        ensure!(
            local_park.local_park().role() == expected_role,
            "phase-bound local park differs from the required role"
        );

        let prepare_message_id = self.prepare_message_id_v1();
        let admission_set_sha256 = self.admission_set_sha256;
        let local_park_statement_sha256 = local_park.statement_sha256();
        let body = self.body_v1().clone();
        let cut_artifact_sha256 = self.cut_artifact_sha256_v1();
        let park_artifact_sha256 = self.park_artifact_sha256;
        let local_declared_authority = match self
            .statements
            .swap_remove(local_cut_index.context("local originated Cut slot disappeared")?)
        {
            RestartCutParkSlotV1::Originated(value) => value.into_declared_authority_v1(),
            RestartCutParkSlotV1::Admitted(_) => None,
        };
        let verified_cut = self.cut_certificate;
        let park_certificate = self.park_certificate;

        let stored_cut = persist_local_restart_cut_certificate_v1(config, verified_cut)
            .context("persist phase-bound RestartCut certificate")?;
        let stored_park = persist_restart_park_certificate_v1(
            config.run_root(),
            park_artifact_sha256,
            park_certificate,
            &body,
            local_validator,
            local_config_sha256,
            fleet_start_certificate,
            config.validator_set(),
        )
        .context("persist phase-bound RestartPark certificate")?;
        let value = StoredRestartCutParkCertificatesV1 {
            stored_cut,
            stored_park,
            fleet_start_certificate: fleet_start_certificate.clone(),
            validator_set: config.validator_set().clone(),
            local_validator,
            local_config_sha256,
            prepare_message_id,
            admission_set_sha256,
            local_park_statement_sha256,
        };
        value.revalidate_fresh_v1()?;
        ensure!(
            value.body_v1() == &body
                && value.cut_artifact_sha256_v1() == cut_artifact_sha256
                && value.park_artifact_sha256_v1() == park_artifact_sha256,
            "stored Cut/Park pair differs from the phase-bound input"
        );
        Ok((value, local_declared_authority))
    }

    #[cfg(test)]
    pub(crate) fn persist_target_at_test_root_v1(
        self,
        root: &std::path::Path,
        local_validator: ValidatorId,
        local_config_sha256: [u8; 32],
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> AnyResult<StoredRestartCutParkCertificatesV1> {
        self.persist_local_at_test_root_v1(
            root,
            local_validator,
            local_config_sha256,
            fleet_start_certificate,
            validator_set,
            RestartParkRoleV1::Target,
        )
    }

    #[cfg(test)]
    pub(crate) fn persist_peer_at_test_root_v1(
        self,
        root: &std::path::Path,
        local_validator: ValidatorId,
        local_config_sha256: [u8; 32],
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> AnyResult<StoredRestartCutParkCertificatesV1> {
        self.persist_local_at_test_root_v1(
            root,
            local_validator,
            local_config_sha256,
            fleet_start_certificate,
            validator_set,
            RestartParkRoleV1::Peer,
        )
    }

    #[cfg(test)]
    fn persist_local_at_test_root_v1(
        self,
        root: &std::path::Path,
        local_validator: ValidatorId,
        local_config_sha256: [u8; 32],
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
        expected_role: RestartParkRoleV1,
    ) -> AnyResult<StoredRestartCutParkCertificatesV1> {
        self.revalidate_v1(fleet_start_certificate, validator_set)
            .map_err(|error| anyhow::anyhow!("revalidate test Cut/Park pair: {error}"))?;
        let prepare_provenance = matches!(
            (&self.target_prepare, expected_role),
            (
                RestartPrepareSlotV1::Originated(_),
                RestartParkRoleV1::Target
            ) | (RestartPrepareSlotV1::Admitted(_), RestartParkRoleV1::Peer)
        );
        let local_cut_originated = self.statements.iter().any(|statement| {
            statement.statement_v1().origin() == local_validator
                && matches!(statement, RestartCutParkSlotV1::Originated(_))
        });
        ensure!(
            prepare_provenance
                && local_cut_originated
                && match expected_role {
                    RestartParkRoleV1::Target => {
                        self.body_v1().target_validator() == local_validator
                            && self.body_v1().target_config_sha256() == local_config_sha256
                    }
                    RestartParkRoleV1::Peer => {
                        self.body_v1().target_validator() != local_validator
                    }
                },
            "test Cut/Park pair lacks the exact local phase provenance or role"
        );
        let local_park = self
            .park_certificate
            .statement(local_validator)
            .context("test park certificate lacks local statement")?;
        ensure!(
            local_park.local_park().role() == expected_role
                && local_park.local_park().local_config_sha256() == local_config_sha256,
            "test park certificate local statement differs from the required role/config"
        );
        let prepare_message_id = self.prepare_message_id_v1();
        let admission_set_sha256 = self.admission_set_sha256;
        let local_park_statement_sha256 = local_park.statement_sha256();
        let body = self.body_v1().clone();
        let park_artifact_sha256 = self.park_artifact_sha256;
        let stored_cut = crate::restart_cut_store::persist_restart_cut_at_test_root_v1(
            root,
            local_validator,
            local_config_sha256,
            validator_set,
            fleet_start_certificate,
            self.cut_certificate,
        )?;
        let stored_park = persist_restart_park_certificate_v1(
            root,
            park_artifact_sha256,
            self.park_certificate,
            &body,
            local_validator,
            local_config_sha256,
            fleet_start_certificate,
            validator_set,
        )?;
        let value = StoredRestartCutParkCertificatesV1 {
            stored_cut,
            stored_park,
            fleet_start_certificate: fleet_start_certificate.clone(),
            validator_set: validator_set.clone(),
            local_validator,
            local_config_sha256,
            prepare_message_id,
            admission_set_sha256,
            local_park_statement_sha256,
        };
        value.revalidate_fresh_v1()?;
        Ok(value)
    }
}

/// Non-Clone target owner that keeps the consumed continuous authority parked
/// after both certificates are durable. A later ParkedAck issuer must consume
/// this whole carrier; merely owning the stored pair cannot acknowledge that
/// the local process reached its durable journal boundary.
#[must_use = "a durably parked target must retain its continuous restart authority"]
pub(crate) struct DurablyParkedTargetRestartOwnerV1 {
    stored: StoredRestartCutParkCertificatesV1,
    declared: ContinuousRestartDeclaredParkAuthorityV1,
}

impl DurablyParkedTargetRestartOwnerV1 {
    pub(crate) const fn stored_v1(&self) -> &StoredRestartCutParkCertificatesV1 {
        &self.stored
    }

    pub(crate) fn revalidate_fresh_v1(&self) -> AnyResult<()> {
        self.stored.revalidate_fresh_v1()
    }

    pub(crate) const fn parked_facts_v1(
        &self,
    ) -> crate::continuous_runtime::ContinuousRuntimeFactsV0 {
        self.declared.facts_v1()
    }

    /// Consumes the complete target parked owner and its unforgeable fresh
    /// journal-commit witness into the one Ack-only declaration. The stored
    /// pair and declared continuous authority remain joined inside the
    /// returned non-Clone owner.
    pub(crate) fn into_parked_ack_declaration_v1(
        self,
        journal_commit: LocalRestartParkJournalCommitV1,
        config: &LoadedValidatorConfig,
    ) -> AnyResult<DeclaredRestartParkedAckV1> {
        issue_local_restart_parked_ack_v1(
            self.stored,
            self.declared,
            journal_commit,
            config,
            RestartParkRoleV1::Target,
        )
    }
}

impl std::fmt::Debug for DurablyParkedTargetRestartOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurablyParkedTargetRestartOwnerV1")
            .field("stored", &self.stored)
            .field("parked_facts", &self.declared.facts_v1())
            .finish_non_exhaustive()
    }
}

/// Non-Clone peer owner that keeps the consumed continuous authority parked
/// after both certificates are durable.  The stored pair is comparison-only;
/// a later typed RecoveryStart transition must consume this whole carrier
/// before ordinary consensus authority can be restored.
#[must_use = "a durably parked peer must retain its continuous restart authority"]
pub(crate) struct DurablyParkedPeerRestartOwnerV1 {
    stored: StoredRestartCutParkCertificatesV1,
    declared: ContinuousRestartDeclaredParkAuthorityV1,
}

impl DurablyParkedPeerRestartOwnerV1 {
    pub(crate) const fn stored_v1(&self) -> &StoredRestartCutParkCertificatesV1 {
        &self.stored
    }

    pub(crate) fn revalidate_fresh_v1(&self) -> AnyResult<()> {
        self.stored.revalidate_fresh_v1()
    }

    pub(crate) const fn parked_facts_v1(
        &self,
    ) -> crate::continuous_runtime::ContinuousRuntimeFactsV0 {
        self.declared.facts_v1()
    }

    /// Peer analogue of the consuming target transition. This issues only a
    /// process-1 ParkedAck and cannot recover or reactivate consensus.
    pub(crate) fn into_parked_ack_declaration_v1(
        self,
        journal_commit: LocalRestartParkJournalCommitV1,
        config: &LoadedValidatorConfig,
    ) -> AnyResult<DeclaredRestartParkedAckV1> {
        issue_local_restart_parked_ack_v1(
            self.stored,
            self.declared,
            journal_commit,
            config,
            RestartParkRoleV1::Peer,
        )
    }
}

impl std::fmt::Debug for DurablyParkedPeerRestartOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurablyParkedPeerRestartOwnerV1")
            .field("stored", &self.stored)
            .field("parked_facts", &self.declared.facts_v1())
            .finish_non_exhaustive()
    }
}

/// Non-Clone durable owner for one exact local RestartCut and RestartPark
/// artifacts plus the phase identities from which they were formed.  Neither
/// stored certificate can be extracted independently.
#[must_use = "the durable Cut/Park pair must remain joined through journal and process-2 gates"]
pub(crate) struct StoredRestartCutParkCertificatesV1 {
    stored_cut: StoredRestartCutCertificateV1,
    stored_park: StoredRestartParkCertificateV1,
    fleet_start_certificate: FleetStartCertificateV1,
    validator_set: ValidatorSet,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    prepare_message_id: [u8; 32],
    admission_set_sha256: [u8; 32],
    local_park_statement_sha256: [u8; 32],
}

impl std::fmt::Debug for StoredRestartCutParkCertificatesV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredRestartCutParkCertificatesV1")
            .field("local_validator", &self.local_validator)
            .field("cut_artifact_sha256", &self.cut_artifact_sha256_v1())
            .field("park_artifact_sha256", &self.park_artifact_sha256_v1())
            .field("admission_set_sha256", &self.admission_set_sha256)
            .finish_non_exhaustive()
    }
}

impl StoredRestartCutParkCertificatesV1 {
    /// Borrows both exact authenticated certificates while retaining the
    /// non-Clone paired durable owner. ParkedAck validation must bind these
    /// exact artifacts rather than only their shared body projection.
    pub(crate) const fn cut_certificate_v1(&self) -> &RestartCutCertificateV1 {
        self.stored_cut.certificate_v1()
    }

    pub(crate) const fn park_certificate_v1(&self) -> &RestartParkCertificateV1 {
        self.stored_park.value_v1()
    }

    pub(crate) const fn fleet_start_certificate_v1(&self) -> &FleetStartCertificateV1 {
        &self.fleet_start_certificate
    }

    pub(crate) const fn validator_set_v1(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub(crate) const fn body_v1(&self) -> &crate::restart_cut::RestartCutBodyV1 {
        self.stored_cut.body_v1()
    }

    pub(crate) const fn cut_artifact_sha256_v1(&self) -> [u8; 32] {
        self.stored_cut.artifact_sha256_v1()
    }

    pub(crate) const fn park_artifact_sha256_v1(&self) -> [u8; 32] {
        self.stored_park.artifact_sha256_v1()
    }

    pub(crate) const fn prepare_message_id_v1(&self) -> [u8; 32] {
        self.prepare_message_id
    }

    pub(crate) const fn admission_set_sha256_v1(&self) -> [u8; 32] {
        self.admission_set_sha256
    }

    pub(crate) const fn local_park_statement_sha256_v1(&self) -> [u8; 32] {
        self.local_park_statement_sha256
    }

    pub(crate) const fn local_validator_v1(&self) -> ValidatorId {
        self.local_validator
    }

    pub(crate) const fn local_config_sha256_v1(&self) -> [u8; 32] {
        self.local_config_sha256
    }

    pub(crate) const fn local_park_v1(&self) -> &crate::restart_cut::LocalRestartParkV1 {
        self.stored_park.local_statement_v1().local_park()
    }

    pub(crate) const fn statement_count_v1(&self) -> usize {
        self.stored_cut.statement_count_v1()
    }

    pub(crate) fn contains_exact_target_prepare_v1(
        &self,
        declaration: &SignedRestartCutV1,
    ) -> bool {
        self.stored_cut
            .contains_exact_target_prepare_v1(declaration)
    }

    pub(crate) const fn local_role_v1(&self) -> RestartParkRoleV1 {
        self.stored_park.local_statement_v1().local_park().role()
    }

    pub(crate) fn cut_path_v1(&self) -> &std::path::Path {
        self.stored_cut.path_v1()
    }

    pub(crate) fn park_path_v1(&self) -> &std::path::Path {
        self.stored_park.path_v1()
    }

    pub(crate) fn revalidate_fresh_v1(&self) -> AnyResult<()> {
        self.stored_cut
            .revalidate_fresh_readback_v1()
            .context("fresh-revalidate paired RestartCut")?;
        self.stored_park
            .revalidate_fresh_v1(&self.fleet_start_certificate, &self.validator_set)
            .context("fresh-revalidate paired RestartPark")?;
        ensure!(
            self.local_validator == self.stored_park.local_validator_v1()
                && self.local_config_sha256 == self.stored_park.local_config_sha256_v1()
                && self.stored_cut.body_v1() == self.stored_park.body_v1()
                && self.stored_cut.artifact_sha256_v1() != [0; 32]
                && self.stored_park.artifact_sha256_v1() != [0; 32]
                && self.stored_park.local_statement_v1().statement_sha256()
                    == self.local_park_statement_sha256
                && match self.stored_park.local_statement_v1().local_park().role() {
                    RestartParkRoleV1::Target => {
                        self.stored_cut.body_v1().target_validator() == self.local_validator
                            && self.stored_cut.body_v1().target_config_sha256()
                                == self.local_config_sha256
                    }
                    RestartParkRoleV1::Peer => {
                        self.stored_cut.body_v1().target_validator() != self.local_validator
                    }
                },
            "fresh Cut/Park pair differs in body, local binding, role, or exact statement"
        );
        let (prepare_message_id, admission_set_sha256) = phase_identity_facts_from_stored_v1(
            &self.stored_cut,
            &self.stored_park,
            &self.fleet_start_certificate,
            &self.validator_set,
        )?;
        ensure!(
            prepare_message_id == self.prepare_message_id
                && admission_set_sha256 == self.admission_set_sha256,
            "fresh Cut/Park pair differs from retained phase identities"
        );
        Ok(())
    }
}

/// Reopens both target artifacts only from identities recovered from the
/// already-verified signed process journal.  The caller must retain this
/// non-Clone owner; scalar inputs are comparison facts and grant no process
/// transition authority on their own.
#[allow(clippy::too_many_arguments)]
pub(crate) fn load_target_restart_cut_park_certificates_v1(
    config: &LoadedValidatorConfig,
    expected_cut_artifact_sha256: [u8; 32],
    expected_park_artifact_sha256: [u8; 32],
    expected_body_sha256: [u8; 32],
    expected_admission_set_sha256: [u8; 32],
    expected_local_park_statement_sha256: [u8; 32],
) -> AnyResult<StoredRestartCutParkCertificatesV1> {
    ensure!(
        expected_cut_artifact_sha256 != [0; 32]
            && expected_park_artifact_sha256 != [0; 32]
            && expected_body_sha256 != [0; 32]
            && expected_admission_set_sha256 != [0; 32]
            && expected_local_park_statement_sha256 != [0; 32],
        "signed journal Cut/Park expectations contain a zero digest"
    );
    let fleet_start_certificate =
        load_fleet_start_certificate_v1(config.run_root(), config.validator_set())
            .context("load target Cut/Park FleetStart certificate")?;
    let stored_cut = load_local_restart_cut_certificate_v1(config)
        .context("load target RestartCut certificate for paired reopen")?;
    ensure!(
        stored_cut.artifact_sha256_v1() == expected_cut_artifact_sha256
            && stored_cut.body_v1().digest() == expected_body_sha256,
        "stored RestartCut differs from signed journal Cut/Park expectations"
    );
    let stored_park = load_restart_park_certificate_v1(
        config.run_root(),
        expected_park_artifact_sha256,
        stored_cut.body_v1(),
        config.local_validator(),
        config.config_sha256(),
        &fleet_start_certificate,
        config.validator_set(),
    )
    .context("load target RestartPark certificate for paired reopen")?;
    let (prepare_message_id, admission_set_sha256) = phase_identity_facts_from_stored_v1(
        &stored_cut,
        &stored_park,
        &fleet_start_certificate,
        config.validator_set(),
    )?;
    ensure!(
        admission_set_sha256 == expected_admission_set_sha256,
        "stored Cut/Park phase identities differ from the signed journal admission set"
    );
    let value = StoredRestartCutParkCertificatesV1 {
        stored_cut,
        stored_park,
        fleet_start_certificate,
        validator_set: config.validator_set().clone(),
        local_validator: config.local_validator(),
        local_config_sha256: config.config_sha256(),
        prepare_message_id,
        admission_set_sha256,
        local_park_statement_sha256: expected_local_park_statement_sha256,
    };
    value.revalidate_fresh_v1()?;
    ensure!(
        value.cut_artifact_sha256_v1() == expected_cut_artifact_sha256
            && value.park_artifact_sha256_v1() == expected_park_artifact_sha256
            && value.body_v1().digest() == expected_body_sha256
            && value.admission_set_sha256_v1() == expected_admission_set_sha256
            && value.local_park_statement_sha256_v1() == expected_local_park_statement_sha256
            && value.local_role_v1() == RestartParkRoleV1::Target
            && value.body_v1().target_validator() == config.local_validator()
            && value.body_v1().target_config_sha256() == config.config_sha256(),
        "fresh target Cut/Park pair differs from signed journal expectations"
    );
    Ok(value)
}

#[cfg(test)]
pub(crate) fn persist_restart_cut_park_at_test_root_v1(
    root: &std::path::Path,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    fleet_start_certificate: &FleetStartCertificateV1,
    validator_set: &ValidatorSet,
    verified_cut: VerifiedRestartCutCertificateV1,
    park_certificate: RestartParkCertificateV1,
) -> AnyResult<StoredRestartCutParkCertificatesV1> {
    ensure!(
        verified_cut.body() == park_certificate.body()
            && verified_cut.body().target_validator() == local_validator,
        "test Cut/Park pair differs in body or local target"
    );
    let local_park = park_certificate
        .statement(local_validator)
        .context("test Cut/Park pair lacks local target park statement")?;
    ensure!(
        local_park.local_park().role() == RestartParkRoleV1::Target,
        "test Cut/Park pair local statement is not target role"
    );
    let body = verified_cut.body().clone();
    let park_artifact_sha256: [u8; 32] = Sha256::digest(park_certificate.encode()).into();
    let local_park_statement_sha256 = local_park.statement_sha256();
    let stored_cut = crate::restart_cut_store::persist_restart_cut_at_test_root_v1(
        root,
        local_validator,
        local_config_sha256,
        validator_set,
        fleet_start_certificate,
        verified_cut,
    )?;
    let stored_park = persist_restart_park_certificate_v1(
        root,
        park_artifact_sha256,
        park_certificate,
        &body,
        local_validator,
        local_config_sha256,
        fleet_start_certificate,
        validator_set,
    )?;
    let (prepare_message_id, admission_set_sha256) = phase_identity_facts_from_stored_v1(
        &stored_cut,
        &stored_park,
        fleet_start_certificate,
        validator_set,
    )?;
    let value = StoredRestartCutParkCertificatesV1 {
        stored_cut,
        stored_park,
        fleet_start_certificate: fleet_start_certificate.clone(),
        validator_set: validator_set.clone(),
        local_validator,
        local_config_sha256,
        prepare_message_id,
        admission_set_sha256,
        local_park_statement_sha256,
    };
    value.revalidate_fresh_v1()?;
    Ok(value)
}

fn admission_set_sha256_from_admitted_v1(
    target_prepare: &RestartPrepareSlotV1,
    statements: &[RestartCutParkSlotV1],
    validator_set: &ValidatorSet,
) -> Result<[u8; 32], RestartCutErrorV1> {
    let mut cut_message_ids = BTreeMap::new();
    for statement in statements {
        if cut_message_ids
            .insert(statement.statement_v1().origin(), statement.message_id_v1())
            .is_some()
        {
            return Err(RestartCutErrorV1::DuplicateOrigin);
        }
    }
    admission_set_sha256_from_ids_v1(
        target_prepare.message_id_v1(),
        &cut_message_ids,
        validator_set,
    )
}

fn admission_set_sha256_from_ids_v1(
    prepare_message_id: [u8; 32],
    cut_message_ids: &BTreeMap<ValidatorId, [u8; 32]>,
    validator_set: &ValidatorSet,
) -> Result<[u8; 32], RestartCutErrorV1> {
    if validator_set.validators().len() != 7
        || cut_message_ids.len() != validator_set.validators().len()
        || prepare_message_id == [0; 32]
    {
        return Err(RestartCutErrorV1::Incomplete);
    }
    let mut hasher = Sha256::new();
    hasher.update(RESTART_PARK_ADMISSION_SET_DOMAIN_V1);
    hasher.update(validator_set.id().as_bytes());
    hasher.update(RESTART_PARK_PREPARE_ID_TAG_V1);
    hasher.update(prepare_message_id);
    hasher.update(
        u32::try_from(cut_message_ids.len())
            .map_err(|_| RestartCutErrorV1::TooLarge)?
            .to_be_bytes(),
    );
    for validator in validator_set.validators() {
        let message_id = cut_message_ids
            .get(&validator.id())
            .ok_or(RestartCutErrorV1::Incomplete)?;
        if *message_id == [0; 32] {
            return Err(RestartCutErrorV1::Incomplete);
        }
        hasher.update(validator.id().as_bytes());
        hasher.update(RESTART_PARK_CUT_ID_TAG_V1);
        hasher.update(message_id);
    }
    Ok(hasher.finalize().into())
}

fn phase_identity_facts_from_stored_v1(
    stored_cut: &StoredRestartCutCertificateV1,
    stored_park: &StoredRestartParkCertificateV1,
    fleet_start_certificate: &FleetStartCertificateV1,
    validator_set: &ValidatorSet,
) -> AnyResult<([u8; 32], [u8; 32])> {
    ensure!(
        stored_cut.body_v1() == stored_park.body_v1(),
        "stored Cut/Park phase identity body differs"
    );
    let target = stored_cut.body_v1().target_validator();
    let target_prepare = stored_cut
        .statement_v1(target)
        .context("stored RestartCut lacks its target Prepare statement")?;
    let prepare_message_id = restart_protocol_message_id_for_parts_v1(
        validator_set.id(),
        target,
        RestartProtocolPhaseV1::Prepare,
        &target_prepare.encode(),
    );
    let mut cut_message_ids = BTreeMap::new();
    for validator in validator_set.validators() {
        let origin = validator.id();
        let cut = stored_cut
            .statement_v1(origin)
            .with_context(|| format!("stored RestartCut lacks origin {origin:?}"))?;
        let park = stored_park
            .value_v1()
            .statement(origin)
            .with_context(|| format!("stored RestartPark lacks origin {origin:?}"))?;
        let dual = RestartCutParkStatementV1::new(
            cut.clone(),
            park.clone(),
            fleet_start_certificate,
            validator_set,
        )
        .map_err(|error| anyhow::anyhow!("rebuild stored dual Cut/Park statement: {error}"))?;
        let message_id = restart_protocol_message_id_for_parts_v1(
            validator_set.id(),
            origin,
            RestartProtocolPhaseV1::Cut,
            &dual.encode(),
        );
        ensure!(
            cut_message_ids.insert(origin, message_id).is_none(),
            "stored Cut/Park pair repeats one origin"
        );
    }
    let admission_set_sha256 =
        admission_set_sha256_from_ids_v1(prepare_message_id, &cut_message_ids, validator_set)
            .map_err(|error| anyhow::anyhow!("rebuild stored admission-set digest: {error}"))?;
    Ok((prepare_message_id, admission_set_sha256))
}

fn rebuild_certificates_v1(
    target_prepare: &RestartPrepareSlotV1,
    statements: &[RestartCutParkSlotV1],
    fleet_start_certificate: &FleetStartCertificateV1,
    validator_set: &ValidatorSet,
) -> Result<
    (
        VerifiedRestartCutCertificateV1,
        RestartParkCertificateV1,
        [u8; 32],
    ),
    RestartCutErrorV1,
> {
    let cut_certificate = RestartCutCertificateV1::new(
        statements
            .iter()
            .map(|statement| statement.statement_v1().cut().clone())
            .collect(),
        fleet_start_certificate,
        validator_set,
    )?
    .verify_owned(fleet_start_certificate, validator_set)?;
    if cut_certificate.body() != target_prepare.body_v1()
        || cut_certificate
            .certificate()
            .statement(target_prepare.declaration_v1().origin())
            != Some(target_prepare.declaration_v1())
    {
        return Err(RestartCutErrorV1::DifferentCut);
    }
    let park_certificate = RestartParkCertificateV1::new(
        target_prepare.body_v1().clone(),
        statements
            .iter()
            .map(|statement| statement.statement_v1().park().clone())
            .collect(),
        fleet_start_certificate,
        validator_set,
    )?;
    let park_artifact_sha256 = Sha256::digest(park_certificate.encode()).into();
    Ok((cut_certificate, park_certificate, park_artifact_sha256))
}
