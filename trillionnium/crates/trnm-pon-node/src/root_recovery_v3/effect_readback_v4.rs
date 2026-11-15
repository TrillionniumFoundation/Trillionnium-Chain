//! Native provider declarations in a fresh V4 namespace. No effect is dispatched.
//!
//! A signed readback authenticates a provider's declaration, not the external
//! effect. This journal never grants M15 entry, FinalUse, payment, compensation
//! or retry authority. Its private directory requires trusted administration;
//! restoring all retained files and all external currentness owners is outside
//! its guarantee. Root recovery floors are caller pins, not custody evidence.
use super::witnessed_v5::WitnessedRootOwnerV5;
use super::{
    digest, map_error, rejected, require, JournalHeadV3, OwnerBudgetV3, RootOwnerResultV3,
    RootOwnerV3, StoreV3,
};
use fs2::FileExt;
use rustix::fs::{openat, Mode, OFlags};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use trnm_crypto_primitives::pq_root_v3::{DualFamilyRosterV3, RootSignatureV3};
use trnm_release_bundle::root_recovery_v3::{
    DigestV3, ReleaseIntentV3, ReleaseUseV3, RootActionV3, RootEnvelopeV3,
};

const ENROLLMENT: &[u8] = b"TRNM/RootProvider/Enrollment/v4\0";
const INTENT: &[u8] = b"TRNM/RootProvider/Intent/v4\0";
const REQUEST: &[u8] = b"TRNM/RootProvider/ReadbackRequest/v4\0";
const REQUEST_DIGEST: &[u8] = b"TRNM/RootProvider/RequestDigest/v4\0";
const RECEIPT: &[u8] = b"TRNM/RootProvider/ReadbackReceipt/v4\0";
const FILE: &[u8] = b"TRNM/RootProvider/EvidenceJournal/v4\0";
const RECORD: &[u8] = b"TRNM/RootProvider/EvidenceRecord/v4\0";
const HISTORY_FLOOR: &[u8] = b"TRNM/RootProvider/HistoryFloor/v6\0";
const MAX_ENROLLMENT: usize = 64 * 1024;
const MAX_RECORD: usize = 256 * 1024;
const MAX_RECORDS: usize = 128;
const MAX_FILE: u64 = 16 * 1024 * 1024;

/// Actual selected material. Every field, including use kind and attempt, must
/// equal the historical root operation. Supplying it never authorizes a sink.
pub struct ReadbackMaterialV4<'a> {
    pub kind: ReleaseUseV3,
    pub attempt: [u8; 32],
    pub bundle: &'a [u8],
    pub contract: &'a [u8],
    pub artifact: &'a [u8],
}

/// Complete independently retained expectation for this evidence journal.
/// Only a replayed root owner constructs it; it remains a readback identity.
#[derive(Clone)]
pub struct ProviderEnrollmentV4 {
    scope: DigestV3,
    operation: DigestV3,
    initial_head: JournalHeadV3,
    operation_head: JournalHeadV3,
    intent: ReleaseIntentV3,
    provider: [u8; 32],
    roster: DualFamilyRosterV3,
}
impl ProviderEnrollmentV4 {
    pub fn operation_id(&self) -> DigestV3 {
        self.operation
    }
    pub fn intent(&self) -> &ReleaseIntentV3 {
        &self.intent
    }
    pub fn provider(&self) -> [u8; 32] {
        self.provider
    }
    pub fn roster(&self) -> &DualFamilyRosterV3 {
        &self.roster
    }
    pub fn encode(&self) -> RootOwnerResultV3<Vec<u8>> {
        self.initial_head.validate()?;
        self.operation_head.validate()?;
        require(
            self.scope != [0; 64] && self.operation != [0; 64] && self.provider != [0; 32],
            "ROOT_PROVIDER_ENROLLMENT_IDENTITY",
        )?;
        let mut bytes = ENROLLMENT.to_vec();
        bytes.extend(self.scope);
        bytes.extend(self.operation);
        bytes.extend(self.initial_head.bytes());
        bytes.extend(self.operation_head.bytes());
        put_blob(&mut bytes, &self.intent.encode().map_err(map_error)?)?;
        bytes.extend(self.provider);
        put_blob(&mut bytes, &self.roster.encode())?;
        require(
            bytes.len() <= MAX_ENROLLMENT,
            "ROOT_PROVIDER_ENROLLMENT_BOUND",
        )?;
        Ok(bytes)
    }
    pub fn commitment(&self) -> RootOwnerResultV3<DigestV3> {
        Ok(digest(ENROLLMENT, &[&self.encode()?]))
    }
    fn request(&self, orphaned_at: Option<u64>) -> RootOwnerResultV3<ProviderRequestV4> {
        let mut challenge = [0; 32];
        let filled =
            rustix::rand::getrandom(&mut challenge, rustix::rand::GetRandomFlags::NONBLOCK)?;
        require(
            filled == challenge.len(),
            "ROOT_PROVIDER_ENTROPY_UNAVAILABLE",
        )?;
        let request = ProviderRequestV4 {
            scope: self.scope,
            operation_id: self.operation,
            intent_commitment: digest(INTENT, &[&self.intent.encode().map_err(map_error)?]),
            provider: self.provider,
            enrollment_commitment: self.commitment()?,
            challenge,
            orphaned_at,
        };
        request.message()?;
        Ok(request)
    }
    fn check_request(&self, request: &ProviderRequestV4) -> RootOwnerResultV3<()> {
        require(
            request.scope == self.scope
                && request.operation_id == self.operation
                && request.intent_commitment
                    == digest(INTENT, &[&self.intent.encode().map_err(map_error)?])
                && request.provider == self.provider
                && request.enrollment_commitment == self.commitment()?,
            "ROOT_PROVIDER_ORIGINAL_OPERATION_BINDING",
        )?;
        request.message()?;
        Ok(())
    }
}

impl RootOwnerV3 {
    /// Reconstruct an exact *historical readback identity* after signed replay
    /// and a fresh anchor check. Revocation/expiry never grants redispatch; they
    /// also must not prevent learning what an already entered operation did.
    /// A configured recovery floor is mandatory here, without an independence
    /// claim. The full retained root-key history must be disjoint from provider
    /// keys. The V3 journal and all its authority rules remain unchanged.
    pub fn provider_readback_enrollment_v4(
        &mut self,
        operation: DigestV3,
        provider: [u8; 32],
        roster: DualFamilyRosterV3,
        material: ReadbackMaterialV4<'_>,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<ProviderEnrollmentV4> {
        budget.check()?;
        let actual = ReleaseIntentV3::from_bytes(
            material.kind,
            material.bundle,
            material.contract,
            material.artifact,
            material.attempt,
        )
        .map_err(map_error)?;
        budget.check()?;
        self.provider_enrollment_from_retained(operation, provider, roster, &actual, budget)
    }

    fn provider_enrollment_from_retained(
        &mut self,
        operation: DigestV3,
        provider: [u8; 32],
        roster: DualFamilyRosterV3,
        actual: &ReleaseIntentV3,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<ProviderEnrollmentV4> {
        let result = (|| {
            self.healthy(budget)?;
            require(
                self.recovery_floor().is_some(),
                "ROOT_PROVIDER_RECOVERY_FLOOR_REQUIRED",
            )?;
            require(
                provider != [0; 32] && operation != [0; 64],
                "ROOT_PROVIDER_IDENTITY",
            )?;
            DualFamilyRosterV3::decode(&roster.encode()).map_err(map_error)?;
            let store = &self.store;
            let enrollment = &self.enrollment;
            let floor = self.recovery_floor.as_ref();
            let anchor = &mut self.anchor;
            store.with_write(budget, |db, budget| {
                let loaded = Self::replay(db, enrollment, floor, budget)?;
                require(loaded.pending.is_none(), "ROOT_OWNER_PENDING_FENCED")?;
                let observed = anchor.current(budget)?;
                require(
                    observed == loaded.head,
                    "ROOT_OWNER_EXTERNAL_ROLLBACK_OR_CONFLICT",
                )?;
                let rows = StoreV3::read_bounded(db)?;
                let mut root_keys: BTreeSet<_> =
                    enrollment.policy.roster.key_ids().into_iter().collect();
                root_keys.extend(enrollment.service_ids());
                let mut selected = None;
                for event in rows.events {
                    let envelope = RootEnvelopeV3::decode(&event.envelope).map_err(map_error)?;
                    if let Some(next) = envelope.statement.action.successor() {
                        root_keys.extend(next.roster.key_ids());
                    }
                    if envelope.statement.operation_id().map_err(map_error)? == operation {
                        require(selected.is_none(), "ROOT_PROVIDER_DUPLICATE_OPERATION")?;
                        let RootActionV3::Normal { intent } = envelope.statement.action else {
                            return Err(rejected("ROOT_PROVIDER_NOT_RELEASE_OPERATION"));
                        };
                        require(
                            &intent == actual,
                            "ROOT_PROVIDER_COMPLETE_MATERIAL_MISMATCH",
                        )?;
                        selected = Some((intent, event.head));
                    }
                }
                require(
                    roster.key_ids().iter().all(|id| !root_keys.contains(id)),
                    "ROOT_PROVIDER_CROSS_ROLE_KEY",
                )?;
                let (intent, operation_head) =
                    selected.ok_or_else(|| rejected("ROOT_PROVIDER_UNKNOWN_OPERATION"))?;
                budget.check()?;
                let value = ProviderEnrollmentV4 {
                    scope: enrollment.scope,
                    operation,
                    initial_head: enrollment.initial_head()?,
                    operation_head,
                    intent,
                    provider,
                    roster,
                };
                value.encode()?;
                Ok(value)
            })
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    pub(super) fn refresh_provider_enrollment(
        &mut self,
        expected: &ProviderEnrollmentV4,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<()> {
        let current = self.provider_enrollment_from_retained(
            expected.operation,
            expected.provider,
            expected.roster.clone(),
            &expected.intent,
            budget,
        )?;
        require(
            current.encode()? == expected.encode()?,
            "ROOT_PROVIDER_ROOT_ENROLLMENT_CHANGED",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRequestV4 {
    pub scope: DigestV3,
    pub operation_id: DigestV3,
    pub intent_commitment: DigestV3,
    pub provider: [u8; 32],
    pub enrollment_commitment: DigestV3,
    pub challenge: [u8; 32],
    pub orphaned_at: Option<u64>,
}
impl ProviderRequestV4 {
    pub fn message(&self) -> RootOwnerResultV3<Vec<u8>> {
        require(
            self.scope != [0; 64]
                && self.operation_id != [0; 64]
                && self.intent_commitment != [0; 64]
                && self.provider != [0; 32]
                && self.enrollment_commitment != [0; 64]
                && self.challenge != [0; 32],
            "ROOT_PROVIDER_REQUEST_IDENTITY",
        )?;
        let mut bytes = REQUEST.to_vec();
        bytes.extend(self.scope);
        bytes.extend(self.operation_id);
        bytes.extend(self.intent_commitment);
        bytes.extend(self.provider);
        bytes.extend(self.enrollment_commitment);
        bytes.extend(self.challenge);
        put_epoch(&mut bytes, self.orphaned_at)?;
        Ok(bytes)
    }
    pub fn digest(&self) -> RootOwnerResultV3<DigestV3> {
        Ok(digest(REQUEST_DIGEST, &[&self.message()?]))
    }
    fn decode(bytes: &[u8]) -> RootOwnerResultV3<Self> {
        let mut reader = Reader::new(bytes);
        reader.domain(REQUEST)?;
        let value = Self {
            scope: reader.fixed()?,
            operation_id: reader.fixed()?,
            intent_commitment: reader.fixed()?,
            provider: reader.fixed()?,
            enrollment_commitment: reader.fixed()?,
            challenge: reader.fixed()?,
            orphaned_at: reader.epoch()?,
        };
        reader.finish()?;
        require(
            value.message()? == bytes,
            "ROOT_PROVIDER_NONCANONICAL_REQUEST",
        )?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProviderOutcomeV4 {
    Unknown = 0,
    Applied = 1,
    NotApplied = 2,
    Compensated = 3,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProviderReconciliationV4 {
    None = 0,
    LiabilityRetained = 1,
    NotApplied = 2,
    Compensated = 3,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReceiptV4 {
    pub scope: DigestV3,
    pub operation_id: DigestV3,
    pub intent_commitment: DigestV3,
    pub provider: [u8; 32],
    pub enrollment_commitment: DigestV3,
    pub challenge: [u8; 32],
    pub request_digest: DigestV3,
    pub receipt_id: [u8; 32],
    pub outcome: ProviderOutcomeV4,
    pub reconciliation: ProviderReconciliationV4,
    pub reconciled_epoch: Option<u64>,
}
impl ProviderReceiptV4 {
    /// Unsigned complete declaration for the independently pinned provider.
    pub fn for_request(
        request: &ProviderRequestV4,
        receipt_id: [u8; 32],
        outcome: ProviderOutcomeV4,
        reconciliation: ProviderReconciliationV4,
    ) -> RootOwnerResultV3<Self> {
        let value = Self {
            scope: request.scope,
            operation_id: request.operation_id,
            intent_commitment: request.intent_commitment,
            provider: request.provider,
            enrollment_commitment: request.enrollment_commitment,
            challenge: request.challenge,
            request_digest: request.digest()?,
            receipt_id,
            outcome,
            reconciliation,
            reconciled_epoch: if reconciliation == ProviderReconciliationV4::None {
                None
            } else {
                request.orphaned_at
            },
        };
        value.message()?;
        Ok(value)
    }
    pub fn message(&self) -> RootOwnerResultV3<Vec<u8>> {
        require(
            self.scope != [0; 64]
                && self.operation_id != [0; 64]
                && self.intent_commitment != [0; 64]
                && self.provider != [0; 32]
                && self.enrollment_commitment != [0; 64]
                && self.challenge != [0; 32]
                && self.request_digest != [0; 64]
                && self.receipt_id != [0; 32],
            "ROOT_PROVIDER_RECEIPT_IDENTITY",
        )?;
        let expected = match self.reconciliation {
            ProviderReconciliationV4::None => None,
            ProviderReconciliationV4::LiabilityRetained => Some(ProviderOutcomeV4::Applied),
            ProviderReconciliationV4::NotApplied => Some(ProviderOutcomeV4::NotApplied),
            ProviderReconciliationV4::Compensated => Some(ProviderOutcomeV4::Compensated),
        };
        require(
            expected.map_or(self.reconciled_epoch.is_none(), |outcome| {
                self.outcome == outcome && self.reconciled_epoch.is_some_and(|epoch| epoch > 0)
            }),
            "ROOT_PROVIDER_RECONCILIATION_SHAPE",
        )?;
        let mut bytes = RECEIPT.to_vec();
        bytes.extend(self.scope);
        bytes.extend(self.operation_id);
        bytes.extend(self.intent_commitment);
        bytes.extend(self.provider);
        bytes.extend(self.enrollment_commitment);
        bytes.extend(self.challenge);
        bytes.extend(self.request_digest);
        bytes.extend(self.receipt_id);
        bytes.push(self.outcome as u8);
        bytes.push(self.reconciliation as u8);
        put_epoch(&mut bytes, self.reconciled_epoch)?;
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> RootOwnerResultV3<Self> {
        let mut reader = Reader::new(bytes);
        reader.domain(RECEIPT)?;
        let value = Self {
            scope: reader.fixed()?,
            operation_id: reader.fixed()?,
            intent_commitment: reader.fixed()?,
            provider: reader.fixed()?,
            enrollment_commitment: reader.fixed()?,
            challenge: reader.fixed()?,
            request_digest: reader.fixed()?,
            receipt_id: reader.fixed()?,
            outcome: match reader.byte()? {
                0 => ProviderOutcomeV4::Unknown,
                1 => ProviderOutcomeV4::Applied,
                2 => ProviderOutcomeV4::NotApplied,
                3 => ProviderOutcomeV4::Compensated,
                _ => return Err(rejected("ROOT_PROVIDER_OUTCOME")),
            },
            reconciliation: match reader.byte()? {
                0 => ProviderReconciliationV4::None,
                1 => ProviderReconciliationV4::LiabilityRetained,
                2 => ProviderReconciliationV4::NotApplied,
                3 => ProviderReconciliationV4::Compensated,
                _ => return Err(rejected("ROOT_PROVIDER_RECONCILIATION")),
            },
            reconciled_epoch: reader.epoch()?,
        };
        reader.finish()?;
        require(
            value.message()? == bytes,
            "ROOT_PROVIDER_NONCANONICAL_RECEIPT",
        )?;
        Ok(value)
    }
}

pub struct SignedProviderReceiptV4 {
    pub receipt: ProviderReceiptV4,
    pub approvals: Vec<RootSignatureV3>,
}
impl SignedProviderReceiptV4 {
    fn encode(&self) -> RootOwnerResultV3<Vec<u8>> {
        require(self.approvals.len() == 4, "ROOT_PROVIDER_EXACT_QUORUM")?;
        let mut bytes = Vec::new();
        put_blob(&mut bytes, &self.receipt.message()?)?;
        let mut sorted: Vec<_> = self.approvals.iter().collect();
        sorted.sort_unstable_by_key(|value| value.signer);
        for signature in sorted {
            bytes.extend(signature.signer);
            put_blob(&mut bytes, &signature.signature)?;
        }
        require(bytes.len() <= MAX_RECORD, "ROOT_PROVIDER_RECEIPT_BOUND")?;
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> RootOwnerResultV3<Self> {
        let mut reader = Reader::new(bytes);
        let receipt = ProviderReceiptV4::decode(reader.blob()?)?;
        let mut approvals = Vec::with_capacity(4);
        for _ in 0..4 {
            approvals.push(RootSignatureV3 {
                signer: reader.fixed()?,
                signature: reader.blob()?.to_vec(),
            });
        }
        reader.finish()?;
        let value = Self { receipt, approvals };
        require(
            value.encode()? == bytes,
            "ROOT_PROVIDER_NONCANONICAL_APPROVALS",
        )?;
        Ok(value)
    }
    fn verify(
        &self,
        enrollment: &ProviderEnrollmentV4,
        request: &ProviderRequestV4,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<()> {
        budget.check()?;
        enrollment.check_request(request)?;
        let receipt = &self.receipt;
        require(
            receipt.scope == request.scope
                && receipt.operation_id == request.operation_id
                && receipt.intent_commitment == request.intent_commitment
                && receipt.provider == request.provider
                && receipt.enrollment_commitment == request.enrollment_commitment
                && receipt.challenge == request.challenge
                && receipt.request_digest == request.digest()?,
            "ROOT_PROVIDER_COMPLETE_REQUEST_BINDING",
        )?;
        if receipt.reconciliation != ProviderReconciliationV4::None {
            require(
                receipt.reconciled_epoch == request.orphaned_at && request.orphaned_at.is_some(),
                "ROOT_PROVIDER_ORPHAN_EPOCH",
            )?;
        }
        enrollment
            .roster
            .verify_quorum(&receipt.message()?, &self.approvals, budget.verification())
            .map_err(map_error)?;
        budget.check()
    }
}

/// Read-only provider lookup. This interface deliberately has no execute,
/// retry, compensate, install or FinalUse operation.
pub trait RootProviderReadbackTransportV4 {
    fn readback(
        &mut self,
        request: &ProviderRequestV4,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<SignedProviderReceiptV4>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationStateV4 {
    None,
    Required,
    LiabilityRetained,
    NotApplied,
    Compensated,
}
/// Provider declarations only. `last_known` is never erased by an Unknown
/// response; `pending` identifies an unanswered *read*, not effect execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderEvidenceV4 {
    pub operation_id: DigestV3,
    pub readbacks_started: u64,
    pub pending: bool,
    pub last_known: Option<ProviderOutcomeV4>,
    pub orphaned_at: Option<u64>,
    pub reconciliation: ReconciliationStateV4,
    /// Every retained epoch, including older explicitly retained liabilities.
    /// The 128-record bound also bounds this map; no generation erases it.
    pub orphan_history: BTreeMap<u64, ReconciliationStateV4>,
}
impl ProviderEvidenceV4 {
    pub fn authorization_granted(&self) -> bool {
        false
    }
    pub fn redispatch_permitted(&self) -> bool {
        false
    }
    pub fn actual_external_effects_verified(&self) -> bool {
        false
    }
}
struct Replay {
    evidence: ProviderEvidenceV4,
    request: Option<ProviderRequestV4>,
    challenges: BTreeSet<[u8; 32]>,
    receipts: BTreeSet<[u8; 32]>,
    records: usize,
    chain: DigestV3,
}

/// The held session's exact last accepted journal head. This is deliberately
/// volatile: it detects history replacement while this owner remains alive,
/// not a rollback that also restores the process or precedes a cold open.
#[derive(Clone, Copy, Eq, PartialEq)]
struct SessionHeadV4 {
    bytes: u64,
    records: usize,
    chain: DigestV3,
}

/// An exact retained prefix of the original provider journal. This is a caller
/// pin, not a signature, a current-head assertion or proof of independent
/// custody. Authentication and survival outside the restored journal are the
/// caller's obligations. Exporting a restored file and importing that same
/// value cannot establish freshness.
///
/// The new pin namespace does not change V4 records or signed domains. A valid
/// suffix may follow this prefix, including an unanswered read. Only history
/// through this floor is protected against cold rollback relative to the pin;
/// later records need an independently retained newer floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderHistoryFloorV6 {
    enrollment: DigestV3,
    operation: DigestV3,
    bytes: u64,
    records: u64,
    chain: DigestV3,
}
impl ProviderHistoryFloorV6 {
    /// Initial pin for an independently authorized first enrollment. It cannot
    /// justify registering the same historical operation at another empty path
    /// after the caller has retained a later floor.
    pub fn initial(enrollment: &ProviderEnrollmentV4) -> RootOwnerResultV3<Self> {
        let mut header = FILE.to_vec();
        put_blob(&mut header, &enrollment.encode()?)?;
        let value = Self {
            enrollment: enrollment.commitment()?,
            operation: enrollment.operation,
            bytes: header.len() as u64,
            records: 0,
            chain: enrollment.commitment()?,
        };
        value.encode()?;
        Ok(value)
    }
    pub fn encode(&self) -> RootOwnerResultV3<Vec<u8>> {
        require(
            self.enrollment != [0; 64]
                && self.operation != [0; 64]
                && self.chain != [0; 64]
                && self.bytes > FILE.len() as u64
                && self.bytes <= MAX_FILE
                && self.records <= MAX_RECORDS as u64,
            "ROOT_PROVIDER_HISTORY_FLOOR_SHAPE",
        )?;
        let mut bytes = HISTORY_FLOOR.to_vec();
        bytes.extend(self.enrollment);
        bytes.extend(self.operation);
        bytes.extend(self.bytes.to_be_bytes());
        bytes.extend(self.records.to_be_bytes());
        bytes.extend(self.chain);
        Ok(bytes)
    }
    /// Decode an already authenticated, independently retained pin. This checks
    /// the closed encoding only; it cannot authenticate the pin's source.
    pub fn from_external_pin(bytes: &[u8]) -> RootOwnerResultV3<Self> {
        let mut reader = Reader::new(bytes);
        reader.domain(HISTORY_FLOOR)?;
        let value = Self {
            enrollment: reader.fixed()?,
            operation: reader.fixed()?,
            bytes: reader.u64()?,
            records: reader.u64()?,
            chain: reader.fixed()?,
        };
        reader.finish()?;
        require(
            value.encode()? == bytes,
            "ROOT_PROVIDER_HISTORY_FLOOR_ENCODING",
        )?;
        Ok(value)
    }
    pub fn operation_id(&self) -> DigestV3 {
        self.operation
    }
    fn matches(&self, bytes: usize, replay: &Replay) -> bool {
        self.bytes == bytes as u64
            && self.records == replay.records as u64
            && self.chain == replay.chain
    }
}

impl Replay {
    fn initial(enrollment: &ProviderEnrollmentV4) -> RootOwnerResultV3<Self> {
        Ok(Self {
            evidence: ProviderEvidenceV4 {
                operation_id: enrollment.operation,
                readbacks_started: 0,
                pending: false,
                last_known: None,
                orphaned_at: None,
                reconciliation: ReconciliationStateV4::None,
                orphan_history: BTreeMap::new(),
            },
            request: None,
            challenges: BTreeSet::new(),
            receipts: BTreeSet::new(),
            records: 0,
            chain: enrollment.commitment()?,
        })
    }
    fn apply(
        &mut self,
        bytes: &[u8],
        enrollment: &ProviderEnrollmentV4,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<()> {
        budget.check()?;
        require(self.records < MAX_RECORDS, "ROOT_PROVIDER_HISTORY_FULL")?;
        let mut reader = Reader::new(bytes);
        match reader.byte()? {
            1 => {
                let request = ProviderRequestV4::decode(reader.rest())?;
                enrollment.check_request(&request)?;
                require(
                    request.orphaned_at == self.evidence.orphaned_at
                        && self.challenges.insert(request.challenge),
                    "ROOT_PROVIDER_REQUEST_EPOCH_OR_REPLAY",
                )?;
                self.evidence.readbacks_started += 1;
                self.evidence.pending = true;
                self.request = Some(request);
            }
            2 => {
                let signed = SignedProviderReceiptV4::decode(reader.rest())?;
                require(self.evidence.pending, "ROOT_PROVIDER_UNREQUESTED_RECEIPT")?;
                let request = self
                    .request
                    .as_ref()
                    .ok_or_else(|| rejected("ROOT_PROVIDER_MISSING_REQUEST"))?;
                signed.verify(enrollment, request, budget)?;
                require(
                    self.receipts.insert(signed.receipt.receipt_id),
                    "ROOT_PROVIDER_RECEIPT_REPLAY",
                )?;
                let receipt = signed.receipt;
                if receipt.outcome != ProviderOutcomeV4::Unknown {
                    let allowed = match self.evidence.last_known {
                        None => true,
                        Some(ProviderOutcomeV4::Applied) => matches!(
                            receipt.outcome,
                            ProviderOutcomeV4::Applied | ProviderOutcomeV4::Compensated
                        ),
                        Some(known) => receipt.outcome == known,
                    };
                    require(allowed, "ROOT_PROVIDER_CONTRADICTORY_FINAL_DECLARATION")?;
                    self.evidence.last_known = Some(receipt.outcome);
                }
                if receipt.reconciliation != ProviderReconciliationV4::None {
                    require(
                        receipt.reconciled_epoch == self.evidence.orphaned_at,
                        "ROOT_PROVIDER_CURRENT_ORPHAN_EPOCH",
                    )?;
                    self.evidence.reconciliation = match receipt.reconciliation {
                        ProviderReconciliationV4::LiabilityRetained => {
                            ReconciliationStateV4::LiabilityRetained
                        }
                        ProviderReconciliationV4::NotApplied => ReconciliationStateV4::NotApplied,
                        ProviderReconciliationV4::Compensated => ReconciliationStateV4::Compensated,
                        ProviderReconciliationV4::None => unreachable!(),
                    };
                    self.evidence.orphan_history.insert(
                        receipt
                            .reconciled_epoch
                            .ok_or_else(|| rejected("ROOT_PROVIDER_MISSING_ORPHAN_EPOCH"))?,
                        self.evidence.reconciliation,
                    );
                }
                self.evidence.pending = false;
            }
            3 => {
                let epoch = reader.u64()?;
                reader.finish()?;
                require(
                    self.evidence.reconciliation != ReconciliationStateV4::Required,
                    "ROOT_PROVIDER_PRIOR_ORPHAN_UNRESOLVED",
                )?;
                require(
                    epoch > 0
                        && self
                            .evidence
                            .orphaned_at
                            .is_none_or(|previous| epoch > previous),
                    "ROOT_PROVIDER_ORPHAN_EPOCH_REGRESSION",
                )?;
                self.evidence.orphaned_at = Some(epoch);
                self.evidence.reconciliation = ReconciliationStateV4::Required;
                self.evidence
                    .orphan_history
                    .insert(epoch, ReconciliationStateV4::Required);
                // Any prior pending read names an old orphan epoch. It remains
                // in history, but no delayed response can clear this new debt.
                self.evidence.pending = false;
                self.request = None;
            }
            _ => return Err(rejected("ROOT_PROVIDER_RECORD_KIND")),
        }
        self.records += 1;
        self.chain = digest(RECORD, &[&self.chain, bytes]);
        budget.check()
    }
}

/// Descriptor-bound append-only, fsync-before-readback evidence. The caller must
/// retain the expected enrollment separately. No writable SQLite open, automatic
/// enrollment/migration, tail repair, history pruning or allowance reset exists.
/// This is local evidence durability, not independent anti-rollback storage.
pub struct ProviderEvidenceJournalV4 {
    file: File,
    directory: File,
    path: PathBuf,
    parent: PathBuf,
    process: u32,
    enrollment: ProviderEnrollmentV4,
    session_head: Option<SessionHeadV4>,
    history_floor: Option<ProviderHistoryFloorV6>,
    fenced: bool,
}
impl ProviderEvidenceJournalV4 {
    pub fn create(
        path: &Path,
        enrollment: ProviderEnrollmentV4,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Self> {
        let mut value = Self::bind(path, enrollment, true, budget)?;
        let mut header = FILE.to_vec();
        put_blob(&mut header, &value.enrollment.encode()?)?;
        value.file.write_all(&header)?;
        value.file.sync_all()?;
        value.directory.sync_all()?;
        value.session_head = Some(SessionHeadV4 {
            bytes: header.len() as u64,
            records: 0,
            chain: value.enrollment.commitment()?,
        });
        value.replay(budget)?;
        Ok(value)
    }
    pub fn open_existing(
        path: &Path,
        enrollment: ProviderEnrollmentV4,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Self> {
        let mut value = Self::bind(path, enrollment, false, budget)?;
        value.replay(budget)?;
        Ok(value)
    }
    /// Reopen only if complete verified history contains the externally retained
    /// prefix at its exact frame boundary. A witness for the Root journal alone
    /// cannot supply this provider-history pin.
    pub fn open_existing_with_history_floor_v6(
        path: &Path,
        enrollment: ProviderEnrollmentV4,
        floor: ProviderHistoryFloorV6,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Self> {
        let mut value = Self::bind(path, enrollment, false, budget)?;
        value.install_external_history_floor_v6(floor, budget)?;
        Ok(value)
    }
    /// Install or advance a caller-authenticated floor without changing any
    /// journal byte. A floor cannot be cleared or lowered on the live owner.
    /// First creation also requires this explicit step before V5 readback;
    /// creating a new local path is not evidence that an operation is new.
    pub fn install_external_history_floor_v6(
        &mut self,
        floor: ProviderHistoryFloorV6,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<()> {
        let result = (|| {
            self.check(budget)?;
            floor.encode()?;
            require(
                floor.enrollment == self.enrollment.commitment()?
                    && floor.operation == self.enrollment.operation,
                "ROOT_PROVIDER_HISTORY_FLOOR_ENROLLMENT",
            )?;
            if let Some(old) = &self.history_floor {
                require(
                    floor.records > old.records || &floor == old,
                    "ROOT_PROVIDER_HISTORY_FLOOR_REGRESSION",
                )?;
                self.replay(budget)?;
            }
            self.history_floor = Some(floor);
            self.replay(budget)?;
            Ok(())
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
    /// Observe the verified local prefix for separate external retention. This
    /// does not install a floor, certify freshness or authorize any effect.
    pub fn history_checkpoint_v6(
        &mut self,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<ProviderHistoryFloorV6> {
        let result = (|| {
            let state = self.replay(budget)?;
            let head = self
                .session_head
                .ok_or_else(|| rejected("ROOT_PROVIDER_MISSING_HEAD"))?;
            let floor = ProviderHistoryFloorV6 {
                enrollment: self.enrollment.commitment()?,
                operation: self.enrollment.operation,
                bytes: head.bytes,
                records: state.records as u64,
                chain: state.chain,
            };
            floor.encode()?;
            Ok(floor)
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
    fn bind(
        path: &Path,
        enrollment: ProviderEnrollmentV4,
        create: bool,
        budget: &OwnerBudgetV3,
    ) -> RootOwnerResultV3<Self> {
        budget.check()?;
        enrollment.encode()?;
        require(path.is_absolute(), "ROOT_PROVIDER_ABSOLUTE_PATH")?;
        let parent = path
            .parent()
            .ok_or_else(|| rejected("ROOT_PROVIDER_PATH"))?;
        require(
            parent.canonicalize()? == parent,
            "ROOT_PROVIDER_CANONICAL_DIRECTORY",
        )?;
        let name = path
            .file_name()
            .ok_or_else(|| rejected("ROOT_PROVIDER_PATH"))?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)?;
        let meta = directory.metadata()?;
        require(
            meta.is_dir()
                && meta.uid() == rustix::process::geteuid().as_raw()
                && meta.mode() & 0o7777 == 0o700,
            "ROOT_PROVIDER_PRIVATE_DIRECTORY",
        )?;
        let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        if create {
            flags |= OFlags::CREATE | OFlags::EXCL;
        }
        let file = File::from(openat(&directory, name, flags, Mode::RUSR | Mode::WUSR)?);
        file.try_lock_exclusive()
            .map_err(|_| rejected("ROOT_PROVIDER_JOURNAL_BUSY"))?;
        let value = Self {
            file,
            directory,
            path: path.to_path_buf(),
            parent: parent.to_path_buf(),
            process: std::process::id(),
            enrollment,
            session_head: None,
            history_floor: None,
            fenced: false,
        };
        value.check(budget)?;
        Ok(value)
    }
    fn check(&self, budget: &OwnerBudgetV3) -> RootOwnerResultV3<()> {
        budget.check()?;
        require(
            !self.fenced && self.process == std::process::id(),
            "ROOT_PROVIDER_SESSION_FENCED",
        )?;
        let file = self.file.metadata()?;
        let path = fs::symlink_metadata(&self.path)?;
        let directory = self.directory.metadata()?;
        let parent = fs::symlink_metadata(&self.parent)?;
        require(
            file.is_file()
                && file.nlink() == 1
                && file.uid() == rustix::process::geteuid().as_raw()
                && file.mode() & 0o7777 == 0o600
                && file.len() <= MAX_FILE
                && path.is_file()
                && (file.dev(), file.ino()) == (path.dev(), path.ino())
                && directory.is_dir()
                && directory.uid() == rustix::process::geteuid().as_raw()
                && directory.mode() & 0o7777 == 0o700
                && parent.is_dir()
                && (directory.dev(), directory.ino()) == (parent.dev(), parent.ino()),
            "ROOT_PROVIDER_JOURNAL_IDENTITY",
        )?;
        Ok(())
    }
    fn replay(&mut self, budget: &mut OwnerBudgetV3) -> RootOwnerResultV3<Replay> {
        self.check(budget)?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        (&self.file).take(MAX_FILE + 1).read_to_end(&mut bytes)?;
        require(bytes.len() as u64 <= MAX_FILE, "ROOT_PROVIDER_FILE_BOUND")?;
        require(
            self.session_head
                .is_none_or(|head| head.bytes == bytes.len() as u64),
            "ROOT_PROVIDER_SESSION_HISTORY_CHANGED",
        )?;
        let mut reader = Reader::new(&bytes);
        reader.domain(FILE)?;
        require(
            reader.blob()? == self.enrollment.encode()?,
            "ROOT_PROVIDER_PINNED_ENROLLMENT",
        )?;
        let mut state = Replay::initial(&self.enrollment)?;
        let mut floor_seen = self
            .history_floor
            .as_ref()
            .is_none_or(|floor| floor.matches(reader.position, &state));
        while !reader.rest().is_empty() {
            let event = reader.blob()?;
            state.apply(event, &self.enrollment, budget)?;
            require(
                reader.fixed::<64>()? == state.chain,
                "ROOT_PROVIDER_RECORD_CHAIN",
            )?;
            floor_seen |= self
                .history_floor
                .as_ref()
                .is_some_and(|floor| floor.matches(reader.position, &state));
        }
        require(floor_seen, "ROOT_PROVIDER_HISTORY_FLOOR_NOT_IN_HISTORY")?;
        self.check(budget)?;
        let observed = SessionHeadV4 {
            bytes: bytes.len() as u64,
            records: state.records,
            chain: state.chain,
        };
        require(
            self.session_head.is_none_or(|head| head == observed),
            "ROOT_PROVIDER_SESSION_HISTORY_CHANGED",
        )?;
        // Only the first verified replay on a new owner adopts existing bytes.
        // Later advances happen solely after this owner's durable append.
        self.session_head = Some(observed);
        Ok(state)
    }
    fn append(
        &mut self,
        bytes: &[u8],
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<ProviderEvidenceV4> {
        let mut state = self.replay(budget)?;
        state.apply(bytes, &self.enrollment, budget)?;
        let mut frame = Vec::new();
        put_blob(&mut frame, bytes)?;
        frame.extend(state.chain);
        let length = self.file.metadata()?.len();
        require(
            self.session_head.is_some_and(|head| head.bytes == length),
            "ROOT_PROVIDER_SESSION_HISTORY_CHANGED",
        )?;
        require(
            length
                .checked_add(frame.len() as u64)
                .is_some_and(|n| n <= MAX_FILE),
            "ROOT_PROVIDER_FILE_BOUND",
        )?;
        self.check(budget)?;
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&frame)?;
        self.file.sync_all()?;
        self.directory.sync_all()?;
        self.check(budget)?;
        let expected_length = length + frame.len() as u64;
        require(
            self.file.metadata()?.len() == expected_length,
            "ROOT_PROVIDER_SESSION_HISTORY_CHANGED",
        )?;
        self.session_head = Some(SessionHeadV4 {
            bytes: expected_length,
            records: state.records,
            chain: state.chain,
        });
        Ok(state.evidence)
    }
    pub fn evidence(
        &mut self,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<ProviderEvidenceV4> {
        let result = self.replay(budget).map(|state| state.evidence);
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
    /// Record an explicit caller-observed orphan epoch. This is not proof of a
    /// chain reorganization, and never asserts that an external effect reversed.
    pub fn observe_orphan_epoch(
        &mut self,
        epoch: u64,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<ProviderEvidenceV4> {
        let mut event = vec![3];
        event.extend(epoch.to_be_bytes());
        let result = self.append(&event, budget);
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
    /// Read only. A failed/uncertain callback leaves its exact request durable.
    /// A later read uses a fresh challenge for the same enrolled operation.
    pub fn reconcile(
        &mut self,
        root: &mut RootOwnerV3,
        transport: &mut impl RootProviderReadbackTransportV4,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<ProviderEvidenceV4> {
        self.reconcile_checked(transport, budget, |enrollment, budget| {
            root.refresh_provider_enrollment(enrollment, budget)
        })
    }

    /// Read the same original operation through a required live V5 witness.
    /// Both sides of the provider callback revalidate the witnessed Root owner;
    /// no inner V3 owner, static-floor fallback or effect-dispatch API escapes.
    /// The existing V4 journal and signatures remain declarations, not proof
    /// that a real external action occurred or that it may be repeated.
    pub fn reconcile_witnessed_v5(
        &mut self,
        root: &mut WitnessedRootOwnerV5,
        transport: &mut impl RootProviderReadbackTransportV4,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<ProviderEvidenceV4> {
        if self.history_floor.is_none() {
            self.fenced = true;
            return Err(rejected("ROOT_PROVIDER_EXTERNAL_HISTORY_FLOOR_REQUIRED"));
        }
        self.reconcile_checked(transport, budget, |enrollment, budget| {
            root.refresh_provider_enrollment_v4(enrollment, budget)
        })
    }

    fn reconcile_checked(
        &mut self,
        transport: &mut impl RootProviderReadbackTransportV4,
        budget: &mut OwnerBudgetV3,
        mut refresh_root: impl FnMut(&ProviderEnrollmentV4, &mut OwnerBudgetV3) -> RootOwnerResultV3<()>,
    ) -> RootOwnerResultV3<ProviderEvidenceV4> {
        let result = (|| {
            self.check(budget)?;
            let original = budget.identity.clone();
            refresh_root(&self.enrollment, budget)?;
            let state = self.replay(budget)?;
            // Reserve capacity for both request and response before calling out.
            require(
                state.records <= MAX_RECORDS - 2,
                "ROOT_PROVIDER_HISTORY_FULL",
            )?;
            require(
                self.file.metadata()?.len() <= MAX_FILE - (2 * MAX_RECORD + 136) as u64,
                "ROOT_PROVIDER_FILE_BOUND",
            )?;
            let request = self.enrollment.request(state.evidence.orphaned_at)?;
            let mut pending = vec![1];
            pending.extend(request.message()?);
            self.append(&pending, budget)?;
            budget.check_identity(&original)?;
            let response = transport.readback(&request, budget);
            budget.check_identity(&original)?;
            let signed = response?;
            refresh_root(&self.enrollment, budget)?;
            self.check(budget)?;
            signed.verify(&self.enrollment, &request, budget)?;
            let mut event = vec![2];
            event.extend(signed.encode()?);
            let evidence = self.append(&event, budget)?;
            budget.check_identity(&original)?;
            Ok(evidence)
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
}

fn put_blob(out: &mut Vec<u8>, bytes: &[u8]) -> RootOwnerResultV3<()> {
    require(bytes.len() <= MAX_RECORD, "ROOT_PROVIDER_BLOB_BOUND")?;
    out.extend((bytes.len() as u32).to_be_bytes());
    out.extend(bytes);
    Ok(())
}
fn put_epoch(out: &mut Vec<u8>, epoch: Option<u64>) -> RootOwnerResultV3<()> {
    match epoch {
        None => out.push(0),
        Some(value) => {
            require(value > 0, "ROOT_PROVIDER_ZERO_EPOCH")?;
            out.push(1);
            out.extend(value.to_be_bytes());
        }
    }
    Ok(())
}
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, count: usize) -> RootOwnerResultV3<&'a [u8]> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| rejected("ROOT_PROVIDER_DECODE_BOUND"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| rejected("ROOT_PROVIDER_TRUNCATED"))?;
        self.position = end;
        Ok(value)
    }
    fn fixed<const N: usize>(&mut self) -> RootOwnerResultV3<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn byte(&mut self) -> RootOwnerResultV3<u8> {
        Ok(self.fixed::<1>()?[0])
    }
    fn u64(&mut self) -> RootOwnerResultV3<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    fn blob(&mut self) -> RootOwnerResultV3<&'a [u8]> {
        let n = u32::from_be_bytes(self.fixed()?) as usize;
        require(n <= MAX_RECORD, "ROOT_PROVIDER_DECODE_BOUND")?;
        self.take(n)
    }
    fn domain(&mut self, expected: &[u8]) -> RootOwnerResultV3<()> {
        require(
            self.take(expected.len())? == expected,
            "ROOT_PROVIDER_NAMESPACE",
        )
    }
    fn epoch(&mut self) -> RootOwnerResultV3<Option<u64>> {
        match self.byte()? {
            0 => Ok(None),
            1 => {
                let value = self.u64()?;
                require(value > 0, "ROOT_PROVIDER_ZERO_EPOCH")?;
                Ok(Some(value))
            }
            _ => Err(rejected("ROOT_PROVIDER_EPOCH_TAG")),
        }
    }
    fn rest(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }
    fn finish(&self) -> RootOwnerResultV3<()> {
        require(self.rest().is_empty(), "ROOT_PROVIDER_TRAILING_BYTES")
    }
}
