//! Strict, conditional recovery through a separately pinned surviving witness.
//!
//! V5 adds a second authenticated register to the research owner. Its signed
//! binding covers the complete V3 enrollment, declared common-restore domain,
//! recovery epoch and witness roster. A successful append requires the exact
//! witness CAS acknowledgement before the local pending record is completed.
//! An uncertain acknowledgement leaves pending state for explicit reconciliation.
//!
//! The witness must durably retain its register outside the declared restore
//! domain. Key separation, a new nonce, or this caller-supplied declaration does
//! not establish physical independence. Restoring every authority and its pins
//! remains indistinguishable from an earlier legitimate deployment. This module
//! neither provisions a witness service nor authorizes M15 or external effects.
use super::{
    digest, map_error, rejected, require, CommittedRootOperationV3, CurrentIntentObservationV3,
    JournalEnrollmentV3, JournalHeadV3, OwnerBudgetV3, RecoveryFloorV4, RootAnchorTransportV3,
    RootContextObservationV3, RootOwnerResultV3, RootOwnerV3, RootWriterSignerV3, StoreV3,
};
use std::path::Path;
use trnm_crypto_primitives::pq_root_v3::{DualFamilyRosterV3, RootSignatureV3};
use trnm_release_bundle::root_recovery_v3::{
    DigestV3, ReleaseIntentV3, RootActionV3, RootEnvelopeV3, RootPolicyV3,
};

pub mod durable;
mod provider_readback;

const ENROLLMENT: &[u8] = b"TRNM/RootWitness/Enrollment/v5\0";
const BINDING: &[u8] = b"TRNM/RootWitness/Binding/v5\0";
const REQUEST: &[u8] = b"TRNM/RootWitness/WriterRequest/v5\0";
const REQUEST_DIGEST: &[u8] = b"TRNM/RootWitness/RequestDigest/v5\0";
const RECEIPT: &[u8] = b"TRNM/RootWitness/Receipt/v5\0";

/// Independently provisioned trust inputs. The restore-domain identifier and
/// recovery epoch are declarations, not attestations of a deployment's custody.
/// No database/anchor response can create or change this policy implicitly.
#[derive(Clone)]
pub struct WitnessPolicyV5 {
    enrollment_commitment: DigestV3,
    restore_domain: DigestV3,
    recovery_epoch: u64,
    binding: DigestV3,
    writer: DualFamilyRosterV3,
    witness: DualFamilyRosterV3,
}

impl WitnessPolicyV5 {
    pub fn new(
        enrollment: &JournalEnrollmentV3,
        restore_domain: DigestV3,
        recovery_epoch: u64,
        witness: DualFamilyRosterV3,
    ) -> RootOwnerResultV3<Self> {
        require(
            restore_domain != [0; 64] && recovery_epoch != 0,
            "ROOT_WITNESS_V5_RESTORE_DOMAIN_OR_EPOCH",
        )?;
        let enrollment_bytes = enrollment.encode()?;
        DualFamilyRosterV3::decode(&witness.encode()).map_err(map_error)?;
        let keys = witness.key_ids();
        let services = enrollment.service_ids();
        require(
            keys.len() == 6 && keys.iter().all(|key| !services.contains(key)),
            "ROOT_WITNESS_V5_CROSS_ROLE_SERVICE_KEY",
        )?;
        let value = Self {
            enrollment_commitment: digest(ENROLLMENT, &[&enrollment_bytes]),
            restore_domain,
            recovery_epoch,
            binding: digest(
                BINDING,
                &[
                    &enrollment_bytes,
                    &restore_domain,
                    &recovery_epoch.to_be_bytes(),
                    &witness.encode(),
                ],
            ),
            writer: enrollment.writer.clone(),
            witness,
        };
        value.check_root_policy(&enrollment.policy)?;
        Ok(value)
    }

    pub fn binding(&self) -> DigestV3 {
        self.binding
    }
    pub fn enrollment_commitment(&self) -> DigestV3 {
        self.enrollment_commitment
    }
    pub fn restore_domain(&self) -> DigestV3 {
        self.restore_domain
    }
    pub fn recovery_epoch(&self) -> u64 {
        self.recovery_epoch
    }
    pub fn witness_roster(&self) -> &DualFamilyRosterV3 {
        &self.witness
    }

    fn check_enrollment(&self, enrollment: &JournalEnrollmentV3) -> RootOwnerResultV3<()> {
        require(
            self.enrollment_commitment == digest(ENROLLMENT, &[&enrollment.encode()?]),
            "ROOT_WITNESS_V5_COMPLETE_ENROLLMENT",
        )?;
        self.check_root_policy(&enrollment.policy)
    }

    fn check_root_policy(&self, policy: &RootPolicyV3) -> RootOwnerResultV3<()> {
        let witness_keys = self.witness.key_ids();
        require(
            policy
                .roster
                .key_ids()
                .iter()
                .all(|key| !witness_keys.contains(key)),
            "ROOT_WITNESS_V5_CROSS_ROLE_ROOT_KEY",
        )
    }

    fn check_envelope(&self, envelope: &RootEnvelopeV3) -> RootOwnerResultV3<()> {
        match &envelope.statement.action {
            RootActionV3::Rotate { next }
            | RootActionV3::Recover { next }
            | RootActionV3::PolicyChange { next } => self.check_root_policy(next),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessRequestV5 {
    pub binding: DigestV3,
    pub challenge: [u8; 32],
    pub expected: Option<JournalHeadV3>,
    pub target: Option<JournalHeadV3>,
}

impl WitnessRequestV5 {
    fn fresh(
        binding: DigestV3,
        expected: Option<JournalHeadV3>,
        target: Option<JournalHeadV3>,
        budget: &OwnerBudgetV3,
    ) -> RootOwnerResultV3<Self> {
        let mut challenge = [0; 32];
        let mut filled = 0;
        while filled < challenge.len() {
            budget.check()?;
            let count = rustix::rand::getrandom(
                &mut challenge[filled..],
                rustix::rand::GetRandomFlags::NONBLOCK,
            )?;
            require(count != 0, "ROOT_WITNESS_V5_CHALLENGE_UNAVAILABLE")?;
            filled += count;
        }
        let value = Self {
            binding,
            challenge,
            expected,
            target,
        };
        value.message()?;
        Ok(value)
    }

    pub fn message(&self) -> RootOwnerResultV3<Vec<u8>> {
        require(
            self.binding != [0; 64] && self.challenge != [0; 32],
            "ROOT_WITNESS_V5_REQUEST_IDENTITY",
        )?;
        let mut bytes = REQUEST.to_vec();
        bytes.extend(self.binding);
        bytes.extend(self.challenge);
        match (self.expected, self.target) {
            (None, None) => bytes.push(0),
            (Some(expected), Some(target)) => {
                expected.validate()?;
                target.validate()?;
                require(
                    expected.version.checked_add(1) == Some(target.version),
                    "ROOT_WITNESS_V5_IMMEDIATE_SUCCESSOR",
                )?;
                bytes.push(1);
                bytes.extend(expected.bytes());
                bytes.extend(target.bytes());
            }
            _ => return Err(rejected("ROOT_WITNESS_V5_REQUEST_SHAPE")),
        }
        Ok(bytes)
    }

    pub fn digest(&self) -> RootOwnerResultV3<DigestV3> {
        Ok(digest(REQUEST_DIGEST, &[&self.message()?]))
    }
}

pub struct WitnessEnvelopeV5 {
    pub request: WitnessRequestV5,
    pub writer_approvals: Vec<RootSignatureV3>,
}

impl WitnessEnvelopeV5 {
    /// Server-side authentication against separately provisioned immutable pins.
    /// The server must validate and durably serialize its exact CAS before ACK.
    pub fn verify_writer(
        &self,
        policy: &WitnessPolicyV5,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<()> {
        budget.check()?;
        require(
            self.request.binding == policy.binding,
            "ROOT_WITNESS_V5_REQUEST_BINDING",
        )?;
        policy
            .writer
            .verify_quorum(
                &self.request.message()?,
                &self.writer_approvals,
                budget.verification(),
            )
            .map_err(map_error)?;
        budget.check()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessOutcomeV5 {
    Current,
    Advanced,
    Mismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessReceiptV5 {
    pub binding: DigestV3,
    pub challenge: [u8; 32],
    pub request_digest: DigestV3,
    pub head: JournalHeadV3,
    pub outcome: WitnessOutcomeV5,
}

impl WitnessReceiptV5 {
    pub fn for_request(
        request: &WitnessRequestV5,
        head: JournalHeadV3,
        outcome: WitnessOutcomeV5,
    ) -> RootOwnerResultV3<Self> {
        let value = Self {
            binding: request.binding,
            challenge: request.challenge,
            request_digest: request.digest()?,
            head,
            outcome,
        };
        value.message()?;
        Ok(value)
    }

    pub fn message(&self) -> RootOwnerResultV3<Vec<u8>> {
        self.head.validate()?;
        require(
            self.binding != [0; 64] && self.challenge != [0; 32] && self.request_digest != [0; 64],
            "ROOT_WITNESS_V5_RECEIPT_IDENTITY",
        )?;
        let mut bytes = RECEIPT.to_vec();
        bytes.extend(self.binding);
        bytes.extend(self.challenge);
        bytes.extend(self.request_digest);
        bytes.extend(self.head.bytes());
        bytes.push(match self.outcome {
            WitnessOutcomeV5::Current => 0,
            WitnessOutcomeV5::Advanced => 1,
            WitnessOutcomeV5::Mismatch => 2,
        });
        Ok(bytes)
    }
}

pub struct SignedWitnessReceiptV5 {
    pub receipt: WitnessReceiptV5,
    pub approvals: Vec<RootSignatureV3>,
}

/// A transport supplies declarations; its implementation alone does not prove
/// durable non-rollback storage, honest service behavior or independent custody.
pub trait RootWitnessTransportV5 {
    fn exchange(
        &mut self,
        request: WitnessEnvelopeV5,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<SignedWitnessReceiptV5>;
}

/// Required, non-clonable live client. No cached receipt or static-floor fallback.
pub struct RootWitnessV5 {
    policy: WitnessPolicyV5,
    writer: Box<dyn RootWriterSignerV3>,
    transport: Box<dyn RootWitnessTransportV5>,
    last_head: Option<JournalHeadV3>,
    fenced: bool,
}

impl RootWitnessV5 {
    pub fn new(
        policy: WitnessPolicyV5,
        writer: impl RootWriterSignerV3 + 'static,
        transport: impl RootWitnessTransportV5 + 'static,
    ) -> Self {
        Self {
            policy,
            writer: Box::new(writer),
            transport: Box::new(transport),
            last_head: None,
            fenced: false,
        }
    }

    fn exchange(
        &mut self,
        request: WitnessRequestV5,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<WitnessReceiptV5> {
        budget.check()?;
        require(!self.fenced, "ROOT_WITNESS_V5_SESSION_FENCED")?;
        let original_budget = budget.identity.clone();
        let message = request.message()?;
        let signatures = self.writer.sign(&message, budget);
        budget.check_identity(&original_budget)?;
        let signatures = signatures?;
        self.policy
            .writer
            .verify_quorum(&message, &signatures, budget.verification())
            .map_err(map_error)?;
        budget.check()?;
        let response = self.transport.exchange(
            WitnessEnvelopeV5 {
                request: request.clone(),
                writer_approvals: signatures,
            },
            budget,
        );
        // A callback error cannot renew the budget or clear cancellation either.
        budget.check_identity(&original_budget)?;
        let response = response?;
        require(
            response.receipt.binding == self.policy.binding
                && response.receipt.challenge == request.challenge
                && response.receipt.request_digest == request.digest()?,
            "ROOT_WITNESS_V5_COMPLETE_REQUEST_BINDING",
        )?;
        self.policy
            .witness
            .verify_quorum(
                &response.receipt.message()?,
                &response.approvals,
                budget.verification(),
            )
            .map_err(map_error)?;
        budget.check()?;
        Ok(response.receipt)
    }

    fn remember(&mut self, head: JournalHeadV3) -> RootOwnerResultV3<()> {
        if let Some(previous) = self.last_head {
            require(
                head.version > previous.version || head == previous,
                "ROOT_WITNESS_V5_REGRESSION_OR_EQUIVOCATION",
            )?;
        }
        self.last_head = Some(head);
        Ok(())
    }

    fn current(&mut self, budget: &mut OwnerBudgetV3) -> RootOwnerResultV3<JournalHeadV3> {
        let result = (|| {
            let receipt = self.exchange(
                WitnessRequestV5::fresh(self.policy.binding, None, None, budget)?,
                budget,
            )?;
            require(
                receipt.outcome == WitnessOutcomeV5::Current,
                "ROOT_WITNESS_V5_CURRENT_OUTCOME",
            )?;
            self.remember(receipt.head)?;
            Ok(receipt.head)
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    fn advance(
        &mut self,
        previous: JournalHeadV3,
        target: JournalHeadV3,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<()> {
        let result = (|| {
            let receipt = self.exchange(
                WitnessRequestV5::fresh(self.policy.binding, Some(previous), Some(target), budget)?,
                budget,
            )?;
            require(
                receipt.outcome == WitnessOutcomeV5::Advanced && receipt.head == target,
                "ROOT_WITNESS_V5_CAS_REFUSED",
            )?;
            self.remember(receipt.head)
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    fn complete_pending(
        &mut self,
        observed: JournalHeadV3,
        previous: JournalHeadV3,
        target: JournalHeadV3,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<()> {
        budget.check()?;
        require(
            !self.fenced && self.last_head == Some(observed),
            "ROOT_WITNESS_V5_PENDING_OBSERVATION",
        )?;
        if observed == target {
            return Ok(());
        }
        require(observed == previous, "ROOT_WITNESS_V5_PENDING_CONFLICT")?;
        // The root owner already authenticated the exact pending transition and
        // observed the original anchor at target. Never resubmit that anchor CAS.
        self.advance(previous, target, budget)
    }
}

/// Strict API with no public inner owner, conversion, Deref or optional witness.
/// V3 remains a separately named research path; V5 cannot silently downgrade.
pub struct WitnessedRootOwnerV5 {
    inner: RootOwnerV3,
    witness: RootWitnessV5,
    fenced: bool,
}

/// Head commitments for the exact SQLite snapshot whose complete signatures
/// and historical root roles were checked together. Never supplied by a caller.
#[derive(Clone, Copy)]
struct CheckedHistoryV5 {
    current: JournalHeadV3,
    pending: Option<JournalHeadV3>,
}

/// A fresh point-in-time observation, not an installation/payment capability.
/// It cannot be serialized, cloned, or detached from its borrowed owner.
pub struct WitnessedIntentObservationV5<'owner> {
    inner: CurrentIntentObservationV3<'owner>,
    witness_binding: DigestV3,
}

impl WitnessedIntentObservationV5<'_> {
    pub fn intent(&self) -> &ReleaseIntentV3 {
        self.inner.intent()
    }
    pub fn observed_head(&self) -> JournalHeadV3 {
        self.inner.observed_head()
    }
    pub fn witness_binding(&self) -> DigestV3 {
        self.witness_binding
    }
}

impl WitnessedRootOwnerV5 {
    pub fn create(
        path: &Path,
        enrollment: JournalEnrollmentV3,
        writer: impl RootWriterSignerV3 + 'static,
        anchor: impl RootAnchorTransportV3 + 'static,
        mut witness: RootWitnessV5,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Self> {
        witness.policy.check_enrollment(&enrollment)?;
        require(
            witness.current(budget)? == enrollment.initial_head()?,
            "ROOT_WITNESS_V5_INITIAL_HEAD",
        )?;
        let inner = RootOwnerV3::create(path, enrollment, writer, anchor, budget)?;
        let mut owner = Self {
            inner,
            witness,
            fenced: false,
        };
        owner.context(budget)?;
        Ok(owner)
    }

    pub fn open_existing(
        path: &Path,
        enrollment: JournalEnrollmentV3,
        writer: impl RootWriterSignerV3 + 'static,
        anchor: impl RootAnchorTransportV3 + 'static,
        mut witness: RootWitnessV5,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Self> {
        witness.policy.check_enrollment(&enrollment)?;
        // Only this fresh authenticated response supplies the V4 ancestry pin.
        let head = witness.current(budget)?;
        let floor = RecoveryFloorV4::from_external_pin(&enrollment, head)?;
        let inner = RootOwnerV3::open_existing_with_recovery_floor(
            path, enrollment, writer, anchor, floor, budget,
        )?;
        let owner = Self {
            inner,
            witness,
            fenced: false,
        };
        let checked = owner.checked_history(budget)?;
        if let Some(pending) = checked.pending {
            require(
                head == checked.current || head == pending,
                "ROOT_WITNESS_V5_PENDING_CONFLICT",
            )?;
        } else {
            require(head == checked.current, "ROOT_WITNESS_V5_CURRENT_HEAD")?;
        }
        owner.inner.healthy(budget)?;
        Ok(owner)
    }

    fn healthy(&self, budget: &OwnerBudgetV3) -> RootOwnerResultV3<()> {
        require(!self.fenced, "ROOT_WITNESS_V5_OWNER_FENCED")?;
        self.inner.healthy(budget)
    }

    fn checked_history(&self, budget: &mut OwnerBudgetV3) -> RootOwnerResultV3<CheckedHistoryV5> {
        self.healthy(budget)?;
        self.witness
            .policy
            .check_enrollment(&self.inner.enrollment)?;
        self.inner.store.with_read(budget, |db, budget| {
            let rows = StoreV3::read_bounded(db)?;
            let mut loaded = RootOwnerV3::replay(
                db,
                &self.inner.enrollment,
                self.inner.recovery_floor.as_ref(),
                budget,
            )?;
            let checked = CheckedHistoryV5 {
                current: loaded.head,
                pending: loaded.pending.as_ref().map(|pending| pending.head),
            };
            if let Some(pending) = &loaded.pending {
                RootOwnerV3::replay_event(
                    &self.inner.enrollment,
                    &mut loaded.state,
                    &mut loaded.head,
                    pending,
                    budget,
                )?;
            }
            // Include historical rotations and the staged target. Checking only
            // the current root would miss temporary witness-key reuse. Both
            // reads above and these roles use the same SQLite read transaction;
            // the returned commitments therefore bind authenticated exact bytes.
            for row in rows.events.iter().chain(rows.pending.iter()) {
                budget.check()?;
                let envelope = RootEnvelopeV3::decode(&row.envelope).map_err(map_error)?;
                self.witness.policy.check_envelope(&envelope)?;
            }
            Ok(checked)
        })
    }

    pub fn context(
        &mut self,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<RootContextObservationV3> {
        let result = (|| {
            self.healthy(budget)?;
            let witnessed = self.witness.current(budget)?;
            // The witness callback may yield. Revalidate local identity/history
            // and the original anchor after it, using the same original budget.
            let checked = self.checked_history(budget)?;
            require(checked.pending.is_none(), "ROOT_OWNER_PENDING_FENCED")?;
            let context = self.inner.context(budget)?;
            require(
                context.head == checked.current,
                "ROOT_WITNESS_V5_LOCAL_SNAPSHOT_CHANGED",
            )?;
            require(context.head == witnessed, "ROOT_WITNESS_V5_CURRENT_HEAD")?;
            Ok(context)
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    pub fn apply(
        &mut self,
        envelope: &RootEnvelopeV3,
        now_unix: u64,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<CommittedRootOperationV3> {
        let result = (|| {
            let observed = self.context(budget)?.head;
            self.witness.policy.check_envelope(envelope)?;
            let witness = &mut self.witness;
            self.inner.apply_with_commit_ack(
                envelope,
                now_unix,
                budget,
                |previous, target, budget| {
                    require(previous == observed, "ROOT_WITNESS_V5_PREDECESSOR_CHANGED")?;
                    witness.advance(previous, target, budget)
                },
            )
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    /// Complete the existing authenticated transition only. Lost ACK at target
    /// is read back; a witness still at its exact predecessor may receive the
    /// same CAS. No root-anchor CAS, new statement, nonce, or effect is created.
    pub fn resume_pending(
        &mut self,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<JournalHeadV3> {
        let result = (|| {
            self.healthy(budget)?;
            let checked = self.checked_history(budget)?;
            let target = checked
                .pending
                .ok_or_else(|| rejected("ROOT_OWNER_NO_PENDING"))?;
            // One fresh witness read follows the authenticated role snapshot.
            // The callback may change local state; the ACK hook below binds the
            // later independently replayed pending record to this exact pair.
            let observed = self.witness.current(budget)?;
            require(
                observed == checked.current || observed == target,
                "ROOT_WITNESS_V5_PENDING_CONFLICT",
            )?;
            let witness = &mut self.witness;
            self.inner.resume_pending_with_commit_ack(
                budget,
                |previous, replayed_target, budget| {
                    require(
                        previous == checked.current && replayed_target == target,
                        "ROOT_WITNESS_V5_PENDING_SNAPSHOT_CHANGED",
                    )?;
                    witness.complete_pending(observed, previous, replayed_target, budget)
                },
            )
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    pub fn observe_current_intent<'a>(
        &'a mut self,
        operation: DigestV3,
        now_unix: u64,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<WitnessedIntentObservationV5<'a>> {
        let prepared = (|| {
            self.healthy(budget)?;
            let head = self.witness.current(budget)?;
            let checked = self.checked_history(budget)?;
            require(checked.pending.is_none(), "ROOT_OWNER_PENDING_FENCED")?;
            Ok((head, checked.current, self.witness.policy.binding))
        })();
        let (head, checked, witness_binding) = match prepared {
            Ok(value) => value,
            Err(error) => {
                self.fenced = true;
                return Err(error);
            }
        };
        match self
            .inner
            .observe_current_intent(operation, now_unix, budget)
        {
            Ok(inner) if inner.observed_head() == head && inner.observed_head() == checked => {
                Ok(WitnessedIntentObservationV5 {
                    inner,
                    witness_binding,
                })
            }
            Ok(_) => {
                self.fenced = true;
                Err(rejected("ROOT_WITNESS_V5_CURRENT_HEAD"))
            }
            Err(error) => {
                self.fenced = true;
                Err(error)
            }
        }
    }
}
