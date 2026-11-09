//! Explicit native root journal; no legacy M15 migration or execution authority.
//!
//! The caller independently pins the complete enrollment, supplies trusted Unix
//! time, and provisions an external anchor before creation. Every operation
//! replays retained signed events and checks that anchor with a fresh challenge.
//! Restoring both this journal and every external freshness owner remains outside
//! its rollback guarantee. The same-host test authority is not independent custody.
//! The private directory's owner UID is trusted not to replace paths concurrently
//! with opening SQLite. This ordinary SQLite adapter is not the M15 custom VFS and
//! does not prove inode continuity against a same-UID swap-and-restore race.
use sha2::{Digest, Sha512};
use std::collections::BTreeSet;
use std::io;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use trnm_crypto_primitives::pq_root_v3::{DualFamilyRosterV3, VerificationBudgetV3};
use trnm_release_bundle::root_recovery_v3::{
    DigestV3, ReleaseIntentV3, RootActionV3, RootEnvelopeV3, RootPolicyV3, RootStateV3,
};

mod anchor;
mod storage;
use anchor::AnchorClientV3;
pub use anchor::{
    AnchorEnvelopeV3, AnchorOutcomeV3, AnchorReceiptV3, AnchorRequestV3, RootAnchorTransportV3,
    RootWriterSignerV3, SignedAnchorReceiptV3,
};
use storage::{RetainedEventV3, StoreV3};

pub type RootOwnerResultV3<T> = io::Result<T>;
pub const MAX_JOURNAL_EVENTS_V3: usize = 128;
const MAX_ENROLLMENT_BYTES: usize = 65_536;
const MAX_ENVELOPE_BYTES: usize = 262_144;
const MAX_STATE_BYTES: usize = 2 * 1024 * 1024;
const MAX_RETAINED_BYTES: usize = 32 * 1024 * 1024;
const SCOPE_DOMAIN: &[u8] = b"TRNM/RootOwner/Scope/v3\0";
const ENROLLMENT_DOMAIN: &[u8] = b"TRNM/RootOwner/Enrollment/v3\0";
const HEAD_DOMAIN: &[u8] = b"TRNM/RootOwner/JournalHead/v3\0";

fn rejected(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn require(condition: bool, message: &'static str) -> RootOwnerResultV3<()> {
    if condition {
        Ok(())
    } else {
        Err(rejected(message))
    }
}
fn map_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}
fn digest(domain: &[u8], parts: &[&[u8]]) -> DigestV3 {
    let mut hash = Sha512::new();
    hash.update(domain);
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

/// One original verification quota, cancellation flag and absolute deadline.
/// Signature verification is in-process and checked before/after each batch;
/// this does not claim preemption inside a single cryptographic primitive.
pub struct OwnerBudgetV3 {
    verification: VerificationBudgetV3,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    identity: Arc<()>,
}
impl OwnerBudgetV3 {
    pub fn new(
        verification: VerificationBudgetV3,
        deadline: Instant,
        cancelled: Arc<AtomicBool>,
    ) -> RootOwnerResultV3<Self> {
        let value = Self {
            verification,
            deadline,
            cancelled,
            identity: Arc::new(()),
        };
        value.check()?;
        Ok(value)
    }
    pub fn check(&self) -> RootOwnerResultV3<()> {
        self.verification.checkpoint().map_err(map_error)?;
        require(
            !self.cancelled.load(Ordering::Acquire) && Instant::now() < self.deadline,
            "ROOT_OWNER_ORIGINAL_BUDGET_EXPIRED_OR_CANCELLED",
        )
    }
    fn verification(&mut self) -> &mut VerificationBudgetV3 {
        &mut self.verification
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn attempts(&self) -> u16 {
        self.verification.attempts()
    }
    pub fn charged_bytes(&self) -> u64 {
        self.verification.charged_bytes()
    }
    /// Cancellation only tightens the original operation budget.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    fn check_identity(&self, expected: &Arc<()>) -> RootOwnerResultV3<()> {
        require(
            Arc::ptr_eq(&self.identity, expected),
            "ROOT_OWNER_CALLBACK_REPLACED_BUDGET",
        )?;
        self.check()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalHeadV3 {
    pub version: u64,
    pub root: DigestV3,
}
impl JournalHeadV3 {
    fn validate(&self) -> RootOwnerResultV3<()> {
        require(
            self.version <= MAX_JOURNAL_EVENTS_V3 as u64 && self.root != [0; 64],
            "ROOT_OWNER_HEAD_SHAPE",
        )
    }
    fn bytes(&self) -> [u8; 72] {
        let mut output = [0; 72];
        output[..8].copy_from_slice(&self.version.to_be_bytes());
        output[8..].copy_from_slice(&self.root);
        output
    }
}

/// Independently pinned identifiers for one deployment and root owner. These
/// retain their existing 32-byte identity meaning; hashing them into a V3 scope
/// does not upgrade the security of any algorithm that originally produced them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalDomainV3 {
    network: [u8; 32],
    genesis: [u8; 32],
    owner: [u8; 32],
}
impl JournalDomainV3 {
    pub fn new(network: [u8; 32], genesis: [u8; 32], owner: [u8; 32]) -> RootOwnerResultV3<Self> {
        let value = Self {
            network,
            genesis,
            owner,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> RootOwnerResultV3<()> {
        require(
            self.network != [0; 32] && self.genesis != [0; 32] && self.owner != [0; 32],
            "ROOT_OWNER_DOMAIN_IDENTIFIERS",
        )
    }
    pub fn network(&self) -> [u8; 32] {
        self.network
    }
    pub fn genesis(&self) -> [u8; 32] {
        self.genesis
    }
    pub fn owner(&self) -> [u8; 32] {
        self.owner
    }
    pub fn scope(&self) -> DigestV3 {
        digest(
            SCOPE_DOMAIN,
            &[
                b"network",
                &self.network,
                b"genesis",
                &self.genesis,
                b"owner",
                &self.owner,
            ],
        )
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = SCOPE_DOMAIN.to_vec();
        bytes.extend(b"network\0");
        bytes.extend(self.network);
        bytes.extend(b"genesis\0");
        bytes.extend(self.genesis);
        bytes.extend(b"owner\0");
        bytes.extend(self.owner);
        bytes
    }
}

/// Independently supplied immutable pins, never inferred from the database or
/// transport response. There is no constructor that adopts an existing journal.
#[derive(Clone)]
pub struct JournalEnrollmentV3 {
    domain: JournalDomainV3,
    scope: DigestV3,
    policy: RootPolicyV3,
    initialized_at_unix: u64,
    writer: DualFamilyRosterV3,
    anchor: DualFamilyRosterV3,
}
impl JournalEnrollmentV3 {
    pub fn new(
        domain: JournalDomainV3,
        policy: RootPolicyV3,
        initialized_at_unix: u64,
        writer: DualFamilyRosterV3,
        anchor: DualFamilyRosterV3,
    ) -> RootOwnerResultV3<Self> {
        let value = Self {
            scope: domain.scope(),
            domain,
            policy,
            initialized_at_unix,
            writer,
            anchor,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn scope(&self) -> DigestV3 {
        self.scope
    }
    pub fn domain(&self) -> JournalDomainV3 {
        self.domain
    }
    pub fn writer_roster(&self) -> &DualFamilyRosterV3 {
        &self.writer
    }
    pub fn anchor_roster(&self) -> &DualFamilyRosterV3 {
        &self.anchor
    }
    fn service_ids(&self) -> BTreeSet<DigestV3> {
        self.writer
            .key_ids()
            .into_iter()
            .chain(self.anchor.key_ids())
            .collect()
    }
    fn check_policy(&self, policy: &RootPolicyV3) -> RootOwnerResultV3<()> {
        let services = self.service_ids();
        require(
            policy
                .roster
                .key_ids()
                .iter()
                .all(|key| !services.contains(key)),
            "ROOT_OWNER_CROSS_ROLE_ROOT_KEY",
        )
    }
    fn check_envelope(&self, envelope: &RootEnvelopeV3) -> RootOwnerResultV3<()> {
        match &envelope.statement.action {
            RootActionV3::Rotate { next }
            | RootActionV3::Recover { next }
            | RootActionV3::PolicyChange { next } => self.check_policy(next),
            _ => Ok(()),
        }
    }
    fn validate(&self) -> RootOwnerResultV3<()> {
        self.domain.validate()?;
        require(
            self.scope != [0; 64] && self.scope == self.domain.scope(),
            "ROOT_OWNER_SCOPE",
        )?;
        let writer = self.writer.key_ids();
        let anchor = self.anchor.key_ids();
        require(
            writer.len() == 6 && anchor.len() == 6 && writer.iter().all(|id| !anchor.contains(id)),
            "ROOT_OWNER_CROSS_ROLE_SERVICE_KEY",
        )?;
        DualFamilyRosterV3::decode(&self.writer.encode()).map_err(map_error)?;
        DualFamilyRosterV3::decode(&self.anchor.encode()).map_err(map_error)?;
        self.check_policy(&self.policy)?;
        self.initial_state()?;
        Ok(())
    }
    fn initial_state(&self) -> RootOwnerResultV3<RootStateV3> {
        RootStateV3::bootstrap(self.scope, self.policy.clone(), self.initialized_at_unix)
            .map_err(map_error)
    }
    pub fn encode(&self) -> RootOwnerResultV3<Vec<u8>> {
        self.validate()?;
        let mut result = ENROLLMENT_DOMAIN.to_vec();
        result.extend(self.domain.encode());
        result.extend(self.scope);
        result.extend(self.initialized_at_unix.to_be_bytes());
        for bytes in [
            self.policy.encode().map_err(map_error)?,
            self.writer.encode(),
            self.anchor.encode(),
        ] {
            require(
                bytes.len() <= MAX_ENROLLMENT_BYTES,
                "ROOT_OWNER_ENROLLMENT_BOUND",
            )?;
            result.extend((bytes.len() as u32).to_be_bytes());
            result.extend(bytes);
        }
        require(
            result.len() <= MAX_ENROLLMENT_BYTES,
            "ROOT_OWNER_ENROLLMENT_BOUND",
        )?;
        Ok(result)
    }
    /// Pure enrollment identity for explicit external registration. Calling
    /// this does not create or overwrite an external anchor or a journal.
    pub fn initial_head(&self) -> RootOwnerResultV3<JournalHeadV3> {
        let enrollment = self.encode()?;
        let state = self.initial_state()?.encode().map_err(map_error)?;
        Ok(JournalHeadV3 {
            version: 0,
            root: digest(HEAD_DOMAIN, &[&enrollment, &state]),
        })
    }
}

/// A point-in-time observation. It is neither serializable nor clonable and
/// cannot be constructed by a caller. It grants no installation or final use.
pub struct CurrentIntentObservationV3<'owner> {
    intent: ReleaseIntentV3,
    head: JournalHeadV3,
    _owner: PhantomData<&'owner mut RootOwnerV3>,
}
impl CurrentIntentObservationV3<'_> {
    pub fn intent(&self) -> &ReleaseIntentV3 {
        &self.intent
    }
    pub fn observed_head(&self) -> JournalHeadV3 {
        self.head
    }
}

pub struct CommittedRootOperationV3 {
    pub operation_id: DigestV3,
    pub head: JournalHeadV3,
}

/// Fresh signing context, not an authorization. A later signed statement must
/// still name this exact predecessor; concurrent changes never rewrite it.
pub struct RootContextObservationV3 {
    pub scope: DigestV3,
    pub generation: u64,
    pub last_sequence: u64,
    pub predecessor: DigestV3,
    pub time_floor_unix: u64,
    pub policy: RootPolicyV3,
    pub revoked: BTreeSet<DigestV3>,
    pub head: JournalHeadV3,
}

/// Standalone native research owner. Existing M15 production command/profile
/// selection is unchanged; no process, payment or application effect is entered.
pub struct RootOwnerV3 {
    store: StoreV3,
    enrollment: JournalEnrollmentV3,
    anchor: AnchorClientV3,
    fenced: bool,
}

struct LoadedV3 {
    head: JournalHeadV3,
    state: RootStateV3,
    pending: Option<RetainedEventV3>,
}

impl RootOwnerV3 {
    pub fn create(
        path: &Path,
        enrollment: JournalEnrollmentV3,
        writer: impl RootWriterSignerV3 + 'static,
        transport: impl RootAnchorTransportV3 + 'static,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Self> {
        budget.check()?;
        let initial = enrollment.initial_head()?;
        let bytes = enrollment.encode()?;
        let state = enrollment.initial_state()?.encode().map_err(map_error)?;
        let store = StoreV3::create(path, &bytes, initial, &state, budget)?;
        let mut owner = Self {
            store,
            anchor: AnchorClientV3::new(&enrollment, writer, transport),
            enrollment,
            fenced: false,
        };
        // Enrollment at the independent service is explicit and precedes this
        // call. Failure leaves the newly created file; it is never overwritten.
        owner.check_anchor(initial, budget)?;
        Ok(owner)
    }

    pub fn open_existing(
        path: &Path,
        enrollment: JournalEnrollmentV3,
        writer: impl RootWriterSignerV3 + 'static,
        transport: impl RootAnchorTransportV3 + 'static,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Self> {
        budget.check()?;
        enrollment.validate()?;
        let store = StoreV3::open(path, budget)?;
        let mut owner = Self {
            store,
            anchor: AnchorClientV3::new(&enrollment, writer, transport),
            enrollment,
            fenced: false,
        };
        let loaded = owner.load(budget)?;
        // A pending predecessor is never silently cleared or resubmitted.
        // Opening is allowed only for explicit completed-only reconciliation.
        let expected = loaded.pending.as_ref().map_or(loaded.head, |row| row.head);
        owner.check_anchor(expected, budget)?;
        Ok(owner)
    }

    fn healthy(&self, budget: &OwnerBudgetV3) -> RootOwnerResultV3<()> {
        budget.check()?;
        require(!self.fenced, "ROOT_OWNER_SESSION_FENCED")?;
        self.store.check_identity()
    }

    fn load(&self, budget: &mut OwnerBudgetV3) -> RootOwnerResultV3<LoadedV3> {
        self.healthy(budget)?;
        self.store.with_read(budget, |db, budget| {
            Self::replay(db, &self.enrollment, budget)
        })
    }

    fn replay(
        db: &rusqlite::Connection,
        enrollment: &JournalEnrollmentV3,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<LoadedV3> {
        budget.check()?;
        let rows = StoreV3::read_bounded(db)?;
        let initial = enrollment.initial_state()?;
        require(
            rows.enrollment == enrollment.encode()?
                && rows.initial_state == initial.encode().map_err(map_error)?
                && rows.initial_head == enrollment.initial_head()?,
            "ROOT_OWNER_PINNED_ENROLLMENT",
        )?;
        let mut state = initial;
        let mut head = rows.initial_head;
        for event in &rows.events {
            Self::replay_event(enrollment, &mut state, &mut head, event, budget)?;
        }
        require(
            rows.current_head == head && rows.current_state == state.encode().map_err(map_error)?,
            "ROOT_OWNER_CURRENT_REPLAY_MISMATCH",
        )?;
        if let Some(pending) = &rows.pending {
            require(pending.previous == head, "ROOT_OWNER_PENDING_PREDECESSOR")?;
        }
        budget.check()?;
        Ok(LoadedV3 {
            head,
            state,
            pending: rows.pending,
        })
    }

    fn replay_event(
        enrollment: &JournalEnrollmentV3,
        state: &mut RootStateV3,
        head: &mut JournalHeadV3,
        event: &RetainedEventV3,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<DigestV3> {
        budget.check()?;
        require(event.previous == *head, "ROOT_OWNER_EVENT_PREDECESSOR")?;
        let envelope = RootEnvelopeV3::decode(&event.envelope).map_err(map_error)?;
        require(
            envelope.encode().map_err(map_error)? == event.envelope,
            "ROOT_OWNER_EVENT_NONCANONICAL",
        )?;
        enrollment.check_envelope(&envelope)?;
        let operation = state
            .apply(&envelope, event.observed_at_unix, budget.verification())
            .map_err(map_error)?;
        budget.check()?;
        let encoded = state.encode().map_err(map_error)?;
        require(encoded == event.state, "ROOT_OWNER_EVENT_STATE_MISMATCH")?;
        let expected = event_head(
            enrollment.scope,
            *head,
            event.observed_at_unix,
            &event.envelope,
            &encoded,
        )?;
        require(expected == event.head, "ROOT_OWNER_EVENT_HEAD_MISMATCH")?;
        *head = expected;
        Ok(operation)
    }

    fn check_anchor(
        &mut self,
        expected: JournalHeadV3,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<()> {
        let observed = self.anchor.current(budget)?;
        self.store.check_identity()?;
        require(
            observed == expected,
            "ROOT_OWNER_EXTERNAL_ROLLBACK_OR_CONFLICT",
        )?;
        budget.check()
    }

    pub fn context(
        &mut self,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<RootContextObservationV3> {
        let result = (|| {
            self.healthy(budget)?;
            let store = &self.store;
            let enrollment = &self.enrollment;
            let anchor = &mut self.anchor;
            store.with_write(budget, |db, budget| {
                let loaded = Self::replay(db, enrollment, budget)?;
                require(loaded.pending.is_none(), "ROOT_OWNER_PENDING_FENCED")?;
                let observed = anchor.current(budget)?;
                store.check_identity()?;
                require(
                    observed == loaded.head,
                    "ROOT_OWNER_EXTERNAL_ROLLBACK_OR_CONFLICT",
                )?;
                budget.check()?;
                Ok(RootContextObservationV3 {
                    scope: loaded.state.scope(),
                    generation: loaded.state.generation(),
                    last_sequence: loaded.state.sequence(),
                    predecessor: loaded.state.checkpoint(),
                    time_floor_unix: loaded.state.time_floor(),
                    policy: loaded.state.policy().clone(),
                    revoked: loaded.state.revoked().clone(),
                    head: loaded.head,
                })
            })
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
        let result = self.apply_inner(envelope, now_unix, budget);
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    fn apply_inner(
        &mut self,
        envelope: &RootEnvelopeV3,
        now_unix: u64,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<CommittedRootOperationV3> {
        self.healthy(budget)?;
        let raw = envelope.encode().map_err(map_error)?;
        require(raw.len() <= MAX_ENVELOPE_BYTES, "ROOT_OWNER_ENVELOPE_BOUND")?;
        let immutable = RootEnvelopeV3::decode(&raw).map_err(map_error)?;
        let (event, operation) = {
            let store = &self.store;
            let enrollment = &self.enrollment;
            let anchor = &mut self.anchor;
            store.with_write(budget, |db, budget| {
                let mut loaded = Self::replay(db, enrollment, budget)?;
                require(loaded.pending.is_none(), "ROOT_OWNER_PENDING_FENCED")?;
                require(
                    loaded.head.version < MAX_JOURNAL_EVENTS_V3 as u64,
                    "ROOT_OWNER_HISTORY_FULL",
                )?;
                let observed = anchor.current(budget)?;
                store.check_identity()?;
                require(
                    observed == loaded.head,
                    "ROOT_OWNER_EXTERNAL_ROLLBACK_OR_CONFLICT",
                )?;
                enrollment.check_envelope(&immutable)?;
                let operation = loaded
                    .state
                    .apply(&immutable, now_unix, budget.verification())
                    .map_err(map_error)?;
                budget.check()?;
                let encoded = loaded.state.encode().map_err(map_error)?;
                require(encoded.len() <= MAX_STATE_BYTES, "ROOT_OWNER_STATE_BOUND")?;
                let head = event_head(enrollment.scope, loaded.head, now_unix, &raw, &encoded)?;
                let event = RetainedEventV3 {
                    previous: loaded.head,
                    head,
                    observed_at_unix: now_unix,
                    envelope: raw,
                    state: encoded,
                };
                StoreV3::stage(db, &event)?;
                Ok((event, operation))
            })?
        };
        // The exact pending bytes are durably committed before any external CAS.
        // No error path deletes this reservation or signs a replacement request.
        self.anchor.advance(event.previous, event.head, budget)?;
        self.store.check_identity()?;
        self.finish(&event, budget)?;
        budget.check()?;
        Ok(CommittedRootOperationV3 {
            operation_id: operation,
            head: event.head,
        })
    }

    fn finish(
        &self,
        expected: &RetainedEventV3,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<()> {
        self.store.with_write(budget, |db, budget| {
            let mut loaded = Self::replay(db, &self.enrollment, budget)?;
            require(
                loaded.pending.as_ref() == Some(expected),
                "ROOT_OWNER_PENDING_CHANGED",
            )?;
            Self::replay_event(
                &self.enrollment,
                &mut loaded.state,
                &mut loaded.head,
                expected,
                budget,
            )?;
            StoreV3::finish(db, expected)?;
            Ok(())
        })
    }

    /// Complete only the exact already externally committed target. A fresh
    /// response showing the predecessor cannot authorize clearing/retrying CAS.
    pub fn resume_pending(
        &mut self,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<JournalHeadV3> {
        let result = (|| {
            let loaded = self.load(budget)?;
            let pending = loaded
                .pending
                .ok_or_else(|| rejected("ROOT_OWNER_NO_PENDING"))?;
            self.check_anchor(pending.head, budget)?;
            self.finish(&pending, budget)?;
            budget.check()?;
            Ok(pending.head)
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    /// Fresh observation only. A future installer/consumer must bind its held
    /// objects, reserve a durable unique entry, and recheck at its actual sink.
    pub fn observe_current_intent<'a>(
        &'a mut self,
        operation: DigestV3,
        now_unix: u64,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<CurrentIntentObservationV3<'a>> {
        let result = (|| {
            self.healthy(budget)?;
            let store = &self.store;
            let enrollment = &self.enrollment;
            let anchor = &mut self.anchor;
            store.with_write(budget, |db, budget| {
                let loaded = Self::replay(db, enrollment, budget)?;
                require(loaded.pending.is_none(), "ROOT_OWNER_PENDING_FENCED")?;
                let observed = anchor.current(budget)?;
                store.check_identity()?;
                require(
                    observed == loaded.head,
                    "ROOT_OWNER_EXTERNAL_ROLLBACK_OR_CONFLICT",
                )?;
                let intent = loaded
                    .state
                    .check_current(operation, now_unix)
                    .map_err(map_error)?
                    .clone();
                budget.check()?;
                Ok(CurrentIntentObservationV3 {
                    intent,
                    head: loaded.head,
                    _owner: PhantomData,
                })
            })
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
}

fn event_head(
    scope: DigestV3,
    previous: JournalHeadV3,
    observed_at_unix: u64,
    envelope: &[u8],
    state: &[u8],
) -> RootOwnerResultV3<JournalHeadV3> {
    previous.validate()?;
    let version = previous
        .version
        .checked_add(1)
        .ok_or_else(|| rejected("ROOT_OWNER_HISTORY_FULL"))?;
    let head = JournalHeadV3 {
        version,
        root: digest(
            HEAD_DOMAIN,
            &[
                &scope,
                &previous.bytes(),
                &version.to_be_bytes(),
                &observed_at_unix.to_be_bytes(),
                envelope,
                state,
            ],
        ),
    };
    head.validate()?;
    Ok(head)
}
