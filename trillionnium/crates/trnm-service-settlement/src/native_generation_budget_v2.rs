//! Dedicated full-W1 generation namespace; V1 bytes are untouched.
//!
//! Narrow M12 adapter: one indivisible native Task, one immutable statement and
//! one physical generation intent. Monetary authority is still NativeFundingOwnerV1.
//! The journal mechanics follow native_budget.rs at b6c730c2; this module neither
//! credits accounts nor manufactures a native refund. Provider ACK is not Positive.
use crate::native_budget::{
    NativeBudgetAnchorV1, NativeBudgetErrorV1, NativeFundingOwnerV1, NativeFundingSourceV1,
    NativePaymentObservationV1, NativePaymentQueryV1,
};
use borsh::{BorshDeserialize, BorshSerialize};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, time::Duration};

pub type Hash = [u8; 32];
pub type Result<T> = std::result::Result<T, NativeBudgetErrorV1>;
pub const NAMESPACE: &str = "pon-native-owner-w1-generation-budget-v2";
pub const PROFILE: &str = "trnm-w1-risc0-3.0.6-poseidon2-join-v2";
mod recovery_checkpoint_v3;
pub use recovery_checkpoint_v3::GenerationRecoveryCheckpointV3;
const APP: i64 = 0x504e_4732;
const MAX_EVENT: usize = 16_384;
const META: &str = "CREATE TABLE native_generation_meta_v2(singleton INTEGER PRIMARY KEY CHECK(singleton=1),configuration BLOB NOT NULL,journal BLOB NOT NULL CHECK(length(journal)=32),sequence INTEGER NOT NULL,root BLOB NOT NULL CHECK(length(root)=32)) STRICT";
const EVENTS: &str = "CREATE TABLE native_generation_events_v2(sequence INTEGER PRIMARY KEY,payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 16384),root BLOB NOT NULL CHECK(length(root)=32)) STRICT";
fn require(ok: bool, code: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(NativeBudgetErrorV1::Invalid(code))
    }
}
fn encode<T: BorshSerialize>(value: &T) -> Result<Vec<u8>> {
    Ok(borsh::to_vec(value)?)
}
pub fn sha256(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}
fn digest<T: BorshSerialize>(domain: &[u8], value: &T) -> Result<Hash> {
    let bytes = encode(value)?;
    let mut h = Sha256::new();
    h.update((domain.len() as u64).to_le_bytes());
    h.update(domain);
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
    Ok(h.finalize().into())
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ConfigurationV2 {
    pub network: Hash,
    pub parameters: Hash,
    pub genesis: Hash,
    pub max_records: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum GenerationLaneV2 {
    FullW1ProofGeneration,
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct GenerationResourcesV2 {
    pub cpu_ns: u64,
    pub gpu_ns: u64,
    pub memory_peak_upper_bound_bytes: u64,
    pub receipt_bytes: u64,
}
impl GenerationResourcesV2 {
    fn vector(&self) -> [u64; 4] {
        [
            self.cpu_ns,
            self.gpu_ns,
            self.memory_peak_upper_bound_bytes,
            self.receipt_bytes,
        ]
    }
    fn within(&self, cap: &Self) -> bool {
        self.vector()
            .iter()
            .zip(cap.vector())
            .all(|(used, cap)| *used <= cap)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct OriginalDeadlineV2 {
    /// Identity of the controller host AND monotonic clock epoch/boot.
    pub clock_domain: Hash,
    pub winner_ns: u64,
    pub deadline_ns: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ClockCheckpointV2 {
    pub clock_domain: Hash,
    pub now_ns: u64,
}
impl OriginalDeadlineV2 {
    pub fn check(&self, now: &ClockCheckpointV2) -> Result<()> {
        require(
            self.clock_domain == now.clock_domain,
            "GENERATION_CLOCK_CONTINUITY_UNKNOWN",
        )?;
        require(
            self.winner_ns <= now.now_ns && now.now_ns < self.deadline_ns,
            "GENERATION_ORIGINAL_DEADLINE",
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct GenerationStatementV2 {
    pub lane: GenerationLaneV2,
    pub task: Hash,
    pub owner: Hash,
    pub provider: Hash,
    pub input_sha256: Hash,
    pub header_sha256: Hash,
    pub expected_artifacts_sha256: Hash,
    pub expected_journal_sha256: Hash,
    pub expected_work_id: Hash,
    pub image_id: [u32; 8],
    pub guest_sha256: Hash,
    pub verifier_binary_sha256: Hash,
    /// Trusted source/run closure pin; not inferred from a receipt or provider ACK.
    pub execution_source_commitment: Hash,
    pub original_deadline: OriginalDeadlineV2,
    /// Original native height deadline, distinct from wall/monotonic time.
    pub chain_deadline: u64,
    pub provider_namespace: Hash,
    pub provider_operation: Hash,
    pub request_digest: Hash,
    pub resource_cap: GenerationResourcesV2,
}
impl GenerationStatementV2 {
    pub fn id(&self) -> Result<Hash> {
        digest(b"native-w1-generation-statement-v2", self)
    }
    fn check(&self) -> Result<()> {
        require(
            self.original_deadline.winner_ns < self.original_deadline.deadline_ns
                && self.original_deadline.clock_domain != [0; 32]
                && self.chain_deadline > 0
                && self.provider_operation != [0; 32]
                && self.request_digest != [0; 32]
                && self.execution_source_commitment != [0; 32]
                && self.resource_cap.vector().iter().any(|v| *v > 0),
            "GENERATION_STATEMENT",
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ProviderJobV2 {
    pub provider_namespace: Hash,
    pub operation: Hash,
    pub request_digest: Hash,
    /// Provider's actual durable identity; never a synthesized retry/attempt ID.
    pub job_id: String,
}
impl ProviderJobV2 {
    fn check(&self, s: &GenerationStatementV2) -> Result<()> {
        require(
            self.provider_namespace == s.provider_namespace
                && self.operation == s.provider_operation
                && self.request_digest == s.request_digest
                && !self.job_id.is_empty()
                && self.job_id.len() <= 512
                && !self.job_id.chars().any(char::is_control),
            "GENERATION_PROVIDER_IDENTITY",
        )
    }
}
pub struct GenerationEvidenceV2<'a> {
    pub receipt: &'a [u8],
    pub header: &'a [u8],
    pub expected_artifacts: &'a [u8],
    /// Locator/digest into the trusted runtime's retained new-execution closure.
    pub owned_execution_evidence: Hash,
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct IndependentFullVerdictV2 {
    pub receipt_sha256: Hash,
    pub header_sha256: Hash,
    pub expected_artifacts_sha256: Hash,
    pub journal_sha256: Hash,
    pub work_id: Hash,
    pub image_id: [u32; 8],
    pub profile_id: String,
    pub sdk: String,
    pub verifier_binary_sha256: Hash,
    pub owned_execution_evidence: Hash,
    pub consumed: GenerationResourcesV2,
}
/// Trusted owner boundary, analogous to NativeFundingOwnerV1, with no defaults.
/// A concrete implementation must run the independent complete verifier, check
/// the actual newly executed pipeline/job closure, and measure owned resources.
/// Implementing this trait is NOT something an untrusted provider may do.
pub trait NativeGenerationOwnerV2: NativeFundingOwnerV1 {
    /// Stable Node-owned task assignment, shared by this service's generation
    /// journals and retained across native branch changes. It issues no funds.
    fn claim_generation_task(
        &mut self,
        statement: &GenerationStatementV2,
        journal_identity: Hash,
    ) -> Result<()>;
    fn clock_checkpoint(&mut self) -> Result<ClockCheckpointV2>;
    fn verify_full_generation(
        &mut self,
        statement: &GenerationStatementV2,
        job: &ProviderJobV2,
        evidence: &GenerationEvidenceV2<'_>,
    ) -> Result<IndependentFullVerdictV2>;
    /// Check an ordinary signed native TaskSettle wire; no submission or payment.
    fn check_settlement_wire(
        &mut self,
        statement: &GenerationStatementV2,
        exact_wire: &[u8],
    ) -> Result<NativePaymentQueryV1>;
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
struct NativeTaskPinV2 {
    owner: Hash,
    provider: Hash,
    whole_obligation: u64,
    deadline: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct SettlementIntentV2 {
    pub operation: Hash,
    pub exact_wire: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum FailureKindV2 {
    InvalidProof,
    Failed,
    Unknown,
    ResourceOverrun,
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct FailureV2 {
    pub kind: FailureKindV2,
    pub evidence_digest: Hash,
    /// Unknown measurement uses None and charges the original full reservation.
    /// Measured overruns are retained exactly, never clipped to the cap.
    pub consumed: Option<GenerationResourcesV2>,
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
struct Record {
    statement: GenerationStatementV2,
    funding: NativeTaskPinV2,
    intent: bool,
    job: Option<ProviderJobV2>,
    verified: Option<IndependentFullVerdictV2>,
    failure: Option<FailureV2>,
    cancel: Option<Hash>,
    settlement: Option<SettlementIntentV2>,
    payment: Option<NativePaymentObservationV1>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationReadbackV2 {
    pub statement: GenerationStatementV2,
    pub dispatch_intent: bool,
    pub job: Option<ProviderJobV2>,
    pub verified: Option<IndependentFullVerdictV2>,
    pub failure: Option<FailureV2>,
    pub cancellation: Option<Hash>,
    pub settlement: Option<SettlementIntentV2>,
    pub historical_payment: Option<NativePaymentObservationV1>,
    pub resource_charge: GenerationResourcesV2,
}
impl Record {
    fn readback(&self) -> GenerationReadbackV2 {
        GenerationReadbackV2 {
            statement: self.statement.clone(),
            dispatch_intent: self.intent,
            job: self.job.clone(),
            verified: self.verified.clone(),
            failure: self.failure.clone(),
            cancellation: self.cancel,
            settlement: self.settlement.clone(),
            historical_payment: self.payment.clone(),
            resource_charge: self
                .verified
                .as_ref()
                .map(|v| v.consumed.clone())
                .or_else(|| self.failure.as_ref().and_then(|v| v.consumed.clone()))
                .unwrap_or_else(|| self.statement.resource_cap.clone()),
        }
    }
}
#[derive(Clone, Default, Eq, PartialEq)]
struct State {
    anchor: Option<NativeBudgetAnchorV1>,
    records: BTreeMap<Hash, Record>,
    tasks: BTreeMap<Hash, Hash>,
    operations: BTreeMap<Hash, Hash>,
}
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
enum Event {
    Prepare {
        anchor: NativeBudgetAnchorV1,
        clock: ClockCheckpointV2,
        statement: Box<GenerationStatementV2>,
        funding: NativeTaskPinV2,
    },
    Intent {
        id: Hash,
        anchor: NativeBudgetAnchorV1,
        clock: ClockCheckpointV2,
    },
    BindJob {
        id: Hash,
        job: ProviderJobV2,
    },
    Verified {
        id: Hash,
        anchor: NativeBudgetAnchorV1,
        clock: ClockCheckpointV2,
        verdict: Box<IndependentFullVerdictV2>,
    },
    Failure {
        id: Hash,
        failure: FailureV2,
    },
    Cancel {
        id: Hash,
        reason: Hash,
    },
    Settlement {
        id: Hash,
        anchor: NativeBudgetAnchorV1,
        clock: ClockCheckpointV2,
        intent: SettlementIntentV2,
    },
    Payment {
        id: Hash,
        observed: NativePaymentObservationV1,
    },
}
impl State {
    fn record(&self, id: Hash) -> Result<&Record> {
        self.records
            .get(&id)
            .ok_or(NativeBudgetErrorV1::Invalid("GENERATION_UNKNOWN"))
    }
    fn anchor(&mut self, a: NativeBudgetAnchorV1, cfg: &ConfigurationV2) -> Result<()> {
        require(
            (a.network, a.parameters, a.genesis) == (cfg.network, cfg.parameters, cfg.genesis),
            "GENERATION_NATIVE_CONTEXT",
        )?;
        require(
            self.anchor
                .is_none_or(|prior| a.generation > prior.generation || a == prior),
            "GENERATION_STALE_OWNER_SNAPSHOT",
        )?;
        self.anchor = Some(a);
        Ok(())
    }
    fn apply(&mut self, e: &Event, cfg: &ConfigurationV2) -> Result<()> {
        match e {
            Event::Prepare {
                anchor,
                clock,
                statement,
                funding,
            } => {
                self.anchor(*anchor, cfg)?;
                statement.check()?;
                statement.original_deadline.check(clock)?;
                let id = statement.id()?;
                require(
                    self.records.len() < cfg.max_records as usize
                        && !self.records.contains_key(&id)
                        && !self.tasks.contains_key(&statement.task),
                    "GENERATION_TASK_REPLAY",
                )?;
                require(
                    funding.owner == statement.owner
                        && funding.provider == statement.provider
                        && funding.deadline == statement.chain_deadline
                        && funding.whole_obligation > 0
                        && anchor.height < funding.deadline,
                    "GENERATION_NATIVE_PIN",
                )?;
                self.tasks.insert(statement.task, id);
                self.records.insert(
                    id,
                    Record {
                        statement: (**statement).clone(),
                        funding: funding.clone(),
                        intent: false,
                        job: None,
                        verified: None,
                        failure: None,
                        cancel: None,
                        settlement: None,
                        payment: None,
                    },
                );
            }
            Event::Intent { id, anchor, clock } => {
                self.anchor(*anchor, cfg)?;
                let r = self.record(*id)?;
                r.statement.original_deadline.check(clock)?;
                require(
                    !r.intent
                        && r.cancel.is_none()
                        && r.failure.is_none()
                        && anchor.height < r.statement.chain_deadline
                        && !self
                            .operations
                            .contains_key(&r.statement.provider_operation),
                    "GENERATION_DISPATCH_FENCE",
                )?;
                self.operations.insert(r.statement.provider_operation, *id);
                self.records.get_mut(id).unwrap().intent = true;
            }
            Event::BindJob { id, job } => {
                let r = self.record(*id)?;
                job.check(&r.statement)?;
                require(r.intent && r.job.is_none(), "GENERATION_JOB_REPLAY")?;
                self.records.get_mut(id).unwrap().job = Some(job.clone());
            }
            Event::Verified {
                id,
                anchor,
                clock,
                verdict,
            } => {
                self.anchor(*anchor, cfg)?;
                let r = self.record(*id)?;
                r.statement.original_deadline.check(clock)?;
                require(
                    r.intent
                        && r.job.is_some()
                        && r.cancel.is_none()
                        && r.failure.is_none()
                        && r.verified.is_none()
                        && anchor.height < r.statement.chain_deadline,
                    "GENERATION_VERIFICATION_FENCE",
                )?;
                check_verdict(&r.statement, verdict)?;
                self.records.get_mut(id).unwrap().verified = Some((**verdict).clone());
            }
            Event::Failure { id, failure } => {
                let r = self.record(*id)?;
                require(
                    r.intent && r.verified.is_none() && r.failure.is_none(),
                    "GENERATION_TERMINAL_REPLAY",
                )?;
                require(
                    !matches!(failure.kind, FailureKindV2::Unknown) || failure.consumed.is_none(),
                    "GENERATION_UNKNOWN_FULL_RESERVATION",
                )?;
                self.records.get_mut(id).unwrap().failure = Some(failure.clone());
            }
            Event::Cancel { id, reason } => {
                let r = self.record(*id)?;
                require(
                    r.cancel.is_none() && r.settlement.is_none(),
                    "GENERATION_CANCEL_TOO_LATE",
                )?;
                self.records.get_mut(id).unwrap().cancel = Some(*reason);
            }
            Event::Settlement {
                id,
                anchor,
                clock,
                intent,
            } => {
                self.anchor(*anchor, cfg)?;
                let r = self.record(*id)?;
                r.statement.original_deadline.check(clock)?;
                require(
                    r.verified.is_some()
                        && r.cancel.is_none()
                        && r.failure.is_none()
                        && r.settlement.is_none()
                        && !self.operations.contains_key(&intent.operation)
                        && anchor.height < r.statement.chain_deadline
                        && !intent.exact_wire.is_empty()
                        && intent.exact_wire.len() <= 4096,
                    "GENERATION_SETTLEMENT_FENCE",
                )?;
                self.operations.insert(intent.operation, *id);
                self.records.get_mut(id).unwrap().settlement = Some(intent.clone());
            }
            Event::Payment { id, observed } => {
                self.anchor(observed.anchor, cfg)?;
                let r = self.record(*id)?;
                require(
                    r.verified.is_some()
                        && r.cancel.is_none()
                        && r.payment.is_none()
                        && r.settlement
                            .as_ref()
                            .is_some_and(|s| s.operation == observed.operation),
                    "GENERATION_PAYMENT_FENCE",
                )?;
                check_payment(r, observed)?;
                self.records.get_mut(id).unwrap().payment = Some(observed.clone());
            }
        }
        Ok(())
    }
}
fn check_verdict(s: &GenerationStatementV2, v: &IndependentFullVerdictV2) -> Result<()> {
    require(
        v.header_sha256 == s.header_sha256
            && v.expected_artifacts_sha256 == s.expected_artifacts_sha256
            && v.journal_sha256 == s.expected_journal_sha256
            && v.work_id == s.expected_work_id
            && v.image_id == s.image_id
            && v.profile_id == PROFILE
            && v.sdk == "3.0.6"
            && v.verifier_binary_sha256 == s.verifier_binary_sha256
            && v.owned_execution_evidence != [0; 32]
            && v.consumed.within(&s.resource_cap),
        "GENERATION_FULL_VERDICT_BINDING",
    )
}
fn check_payment(r: &Record, p: &NativePaymentObservationV1) -> Result<()> {
    require(
        p.source == NativeFundingSourceV1::Task(r.statement.task)
            && p.subject == r.statement.id()?
            && p.beneficiary == r.statement.provider
            && p.gross_escrow_debit == r.funding.whole_obligation
            && p.beneficiary_credit == r.funding.whole_obligation,
        "GENERATION_CANONICAL_PAYMENT_BINDING",
    )
}

fn parse_hash(v: &serde_json::Value, name: &str) -> Result<Hash> {
    let text = v
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or(NativeBudgetErrorV1::Invalid("GENERATION_NATIVE_ROW"))?;
    require(
        text.len() == 64
            && text
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "GENERATION_NATIVE_ROW",
    )?;
    let mut bytes = [0; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)
            .map_err(|_| NativeBudgetErrorV1::Invalid("GENERATION_NATIVE_ROW"))?;
    }
    Ok(bytes)
}
fn observe_task(
    owner: &mut impl NativeGenerationOwnerV2,
    s: &GenerationStatementV2,
    settlement: bool,
) -> Result<(NativeBudgetAnchorV1, ClockCheckpointV2, NativeTaskPinV2)> {
    let clock = owner.clock_checkpoint()?;
    s.original_deadline.check(&clock)?;
    let o = owner.observe_funding(NativeFundingSourceV1::Task(s.task))?;
    require(
        o.source == NativeFundingSourceV1::Task(s.task),
        "GENERATION_NATIVE_SOURCE",
    )?;
    let v = o.row.ok_or(NativeBudgetErrorV1::Invalid(
        "GENERATION_NATIVE_SOURCE_MISSING",
    ))?;
    let status = v
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    require(
        status == "receipt" || (!settlement && status == "reserved"),
        "GENERATION_NATIVE_SOURCE_CLOSED",
    )?;
    if status == "receipt" {
        require(
            parse_hash(&v, "output")? == s.id()?,
            "GENERATION_NATIVE_OUTPUT",
        )?;
    } else {
        require(
            v.get("output") == Some(&serde_json::Value::Null),
            "GENERATION_NATIVE_OUTPUT",
        )?;
    }
    let n = |k| {
        v.get(k)
            .and_then(serde_json::Value::as_u64)
            .ok_or(NativeBudgetErrorV1::Invalid("GENERATION_NATIVE_ROW"))
    };
    let pin = NativeTaskPinV2 {
        owner: parse_hash(&v, "owner")?,
        provider: parse_hash(&v, "provider")?,
        whole_obligation: n("remaining")?,
        deadline: n("deadline")?,
    };
    require(
        pin.owner == s.owner
            && pin.provider == s.provider
            && pin.deadline == s.chain_deadline
            && pin.whole_obligation > 0
            && o.anchor.height < pin.deadline,
        "GENERATION_NATIVE_PIN",
    )?;
    Ok((o.anchor, clock, pin))
}

pub enum DispatchDecisionV2 {
    New,
    Pending,
    Done,
}
enum Update<T> {
    Replay(T),
    Append(Box<Event>, T),
}
impl<T> Update<T> {
    fn append(event: Event, value: T) -> Self {
        Self::Append(Box::new(event), value)
    }
}
pub struct NativeGenerationStoreV2 {
    connection: Connection,
    configuration: ConfigurationV2,
    journal_identity: Hash,
    recovery_expected_v3: Option<GenerationRecoveryCheckpointV3>,
    recovery_committed_v3: Option<GenerationRecoveryCheckpointV3>,
}
fn event_root(journal: Hash, previous: Hash, sequence: u64, payload: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(NAMESPACE.as_bytes());
    h.update(journal);
    h.update(previous);
    h.update(sequence.to_le_bytes());
    h.update((payload.len() as u64).to_le_bytes());
    h.update(payload);
    h.finalize().into()
}
fn schema(c: &Connection) -> Result<()> {
    let app: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    require(app == APP && version == 2, "GENERATION_FOREIGN_DATABASE")?;
    for (name, expected) in [
        ("native_generation_meta_v2", META),
        ("native_generation_events_v2", EVENTS),
    ] {
        let actual: Option<String> = c
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |r| r.get(0),
            )
            .optional()?;
        require(
            actual.as_deref() == Some(expected),
            "GENERATION_STORE_SCHEMA",
        )?;
    }
    let count: u64 = c.query_row(
        "SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'",
        [],
        |r| r.get(0),
    )?;
    require(count == 2, "GENERATION_STORE_SCHEMA")
}
fn journal_id(c: &Connection) -> Result<Hash> {
    // Restored files may have bypassed CHECK constraints. Do not allocate an
    // attacker-sized Vec before validating an ostensibly fixed-size field.
    let bytes: Option<Vec<u8>> = c.query_row(
        "SELECT CASE WHEN typeof(journal)='blob' AND length(journal)=32 THEN journal ELSE NULL END FROM native_generation_meta_v2 WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    bytes
        .ok_or(NativeBudgetErrorV1::Invalid("GENERATION_JOURNAL_IDENTITY"))?
        .try_into()
        .map_err(|_| NativeBudgetErrorV1::Invalid("GENERATION_JOURNAL_IDENTITY"))
}
fn load(
    c: &Connection,
    cfg: &ConfigurationV2,
    journal: Hash,
    expected: Option<(u64, Hash, &State)>,
) -> Result<(State, u64, Hash)> {
    schema(c)?;
    require(journal_id(c)? == journal, "GENERATION_JOURNAL_IDENTITY")?;
    let (config, count, root): (Option<Vec<u8>>, u64, Option<Vec<u8>>) = c.query_row(
        "SELECT CASE WHEN typeof(configuration)='blob' AND length(configuration)<=16384 THEN configuration ELSE NULL END,sequence,CASE WHEN typeof(root)='blob' AND length(root)=32 THEN root ELSE NULL END FROM native_generation_meta_v2 WHERE singleton=1",
        [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    let root = root.ok_or(NativeBudgetErrorV1::Invalid("GENERATION_JOURNAL_ROOT_SIZE"))?;
    require(
        config.as_deref() == Some(encode(cfg)?.as_slice())
            && count <= u64::from(cfg.max_records) * 12,
        "GENERATION_STORE_CONFIGURATION",
    )?;
    let mut state = State::default();
    let mut sequence = 0;
    let mut previous = [0; 32];
    let mut seen = expected.is_none();
    if let Some((0, wanted, original)) = expected {
        require(
            wanted == previous && original == &state,
            "GENERATION_COMMITTED_READBACK",
        )?;
        seen = true;
    }
    let mut q = c.prepare("SELECT sequence,CASE WHEN typeof(payload)='blob' AND length(payload)<=16384 THEN payload ELSE NULL END,CASE WHEN typeof(root)='blob' AND length(root)=32 THEN root ELSE NULL END FROM native_generation_events_v2 ORDER BY sequence")?;
    let mut rows = q.query([])?;
    while let Some(row) = rows.next()? {
        sequence += 1;
        require(
            sequence <= count && row.get::<_, u64>(0)? == sequence,
            "GENERATION_JOURNAL_SEQUENCE",
        )?;
        let bytes: Option<Vec<u8>> = row.get(1)?;
        let bytes = bytes.ok_or(NativeBudgetErrorV1::Invalid("GENERATION_EVENT_SIZE"))?;
        let stored_root: Option<Vec<u8>> = row.get(2)?;
        let stored_root =
            stored_root.ok_or(NativeBudgetErrorV1::Invalid("GENERATION_JOURNAL_ROOT_SIZE"))?;
        let current = event_root(journal, previous, sequence, &bytes);
        require(stored_root.as_slice() == current, "GENERATION_JOURNAL_ROOT")?;
        let e: Event = borsh::from_slice(&bytes)?;
        require(encode(&e)? == bytes, "GENERATION_JOURNAL_ENCODING")?;
        state.apply(&e, cfg)?;
        if let Some((wanted_sequence, wanted_root, original)) = expected {
            if wanted_sequence == sequence {
                require(
                    wanted_root == current && original == &state,
                    "GENERATION_COMMITTED_READBACK",
                )?;
                seen = true;
            }
        }
        previous = current;
    }
    require(
        sequence == count && root.as_slice() == previous && seen,
        "GENERATION_JOURNAL_HEAD",
    )?;
    Ok((state, sequence, previous))
}
impl NativeGenerationStoreV2 {
    pub fn open(path: &Path, configuration: ConfigurationV2) -> Result<Self> {
        require(
            (1..=4096).contains(&configuration.max_records),
            "GENERATION_RECORD_LIMIT",
        )?;
        if let Ok(m) = path.symlink_metadata() {
            require(
                m.is_file() && !m.file_type().is_symlink(),
                "GENERATION_STORE_FILE",
            )?;
        }
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let mut c = Connection::open(path)?;
        c.busy_timeout(Duration::from_secs(5))?;
        c.pragma_update(None, "trusted_schema", false)?;
        c.pragma_update(None, "synchronous", "FULL")?;
        let app: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if app == 0 && version == 0 {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let count: u64 = tx.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'",
                [],
                |r| r.get(0),
            )?;
            require(count == 0, "GENERATION_FOREIGN_DATABASE")?;
            tx.execute_batch(META)?;
            tx.execute_batch(EVENTS)?;
            require(
                tx.execute(
                    "INSERT INTO native_generation_meta_v2 VALUES(1,?1,randomblob(32),0,?2)",
                    params![encode(&configuration)?, [0u8; 32].as_slice()],
                )? == 1,
                "GENERATION_JOURNAL_WRITE",
            )?;
            tx.pragma_update(None, "application_id", APP)?;
            tx.pragma_update(None, "user_version", 2)?;
            load(
                &tx,
                &configuration,
                journal_id(&tx)?,
                Some((0, [0; 32], &State::default())),
            )?;
            tx.commit()?;
        }
        schema(&c)?;
        c.pragma_update(None, "journal_mode", "WAL")?;
        let journal_identity = journal_id(&c)?;
        let store = Self {
            connection: c,
            configuration,
            journal_identity,
            recovery_expected_v3: None,
            recovery_committed_v3: None,
        };
        store.snapshot()?;
        Ok(store)
    }
    fn snapshot(&self) -> Result<State> {
        self.snapshot_with_head().map(|(state, _, _)| state)
    }
    fn snapshot_with_head(&self) -> Result<(State, u64, Hash)> {
        let tx = self.connection.unchecked_transaction()?;
        let (s, sequence, root) = load(&tx, &self.configuration, self.journal_identity, None)?;
        self.check_recovery_expected_v3(sequence, root)?;
        tx.commit()?;
        Ok((s, sequence, root))
    }
    fn update<T>(&mut self, make: impl FnOnce(&State) -> Result<Update<T>>) -> Result<T> {
        let expected = self.recovery_expected_v3;
        let context = expected.map(|_| self.recovery_context_v3()).transpose()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (mut state, mut sequence, mut root) =
            load(&tx, &self.configuration, self.journal_identity, None)?;
        if let (Some(expected), Some(context)) = (expected, context) {
            require(
                expected
                    == recovery_checkpoint_v3::checkpoint_from_parts_v3(context, sequence, root)?,
                "GENERATION_RECOVERY_TRANSACTION_HEAD",
            )?;
        }
        let value = match make(&state)? {
            Update::Replay(v) => v,
            Update::Append(e, v) => {
                state.apply(&e, &self.configuration)?;
                let bytes = encode(&e)?;
                require(bytes.len() <= MAX_EVENT, "GENERATION_EVENT_SIZE")?;
                let old_root = root;
                let old_sequence = sequence;
                sequence = sequence
                    .checked_add(1)
                    .ok_or(NativeBudgetErrorV1::Invalid("GENERATION_ARITHMETIC"))?;
                require(
                    sequence <= u64::from(self.configuration.max_records) * 12,
                    "GENERATION_JOURNAL_LIMIT",
                )?;
                root = event_root(self.journal_identity, root, sequence, &bytes);
                require(
                    tx.execute(
                        "INSERT INTO native_generation_events_v2 VALUES(?1,?2,?3)",
                        params![sequence, bytes, root.as_slice()],
                    )? == 1,
                    "GENERATION_JOURNAL_WRITE",
                )?;
                require(tx.execute("UPDATE native_generation_meta_v2 SET sequence=?1,root=?2 WHERE singleton=1 AND sequence=?3 AND root=?4",
                    params![sequence, root.as_slice(), old_sequence, old_root.as_slice()])? == 1, "GENERATION_JOURNAL_WRITE")?;
                v
            }
        };
        load(
            &tx,
            &self.configuration,
            self.journal_identity,
            Some((sequence, root, &state)),
        )?;
        tx.commit()?;
        if let Some(context) = context {
            self.recovery_committed_v3 = Some(recovery_checkpoint_v3::checkpoint_from_parts_v3(
                context, sequence, root,
            )?);
        }
        // Failure after commit is uncertainty. Retrying finds Pending, never New.
        let read = self.connection.unchecked_transaction()?;
        load(
            &read,
            &self.configuration,
            self.journal_identity,
            Some((sequence, root, &state)),
        )?;
        read.commit()?;
        Ok(value)
    }
    pub fn readback(&self, id: Hash) -> Result<GenerationReadbackV2> {
        Ok(self.snapshot()?.record(id)?.readback())
    }
    pub fn journal_identity(&self) -> Hash {
        self.journal_identity
    }
    pub fn prepare(
        &mut self,
        owner: &mut impl NativeGenerationOwnerV2,
        s: GenerationStatementV2,
    ) -> Result<Hash> {
        s.check()?;
        let id = s.id()?;
        let journal = self.journal_identity;
        self.update(|state| {
            if let Some(r) = state.records.get(&id) {
                require(r.statement == s, "GENERATION_STATEMENT_REPLAY")?;
                owner.claim_generation_task(&s, journal)?;
                return Ok(Update::Replay(id));
            }
            let (anchor, clock, funding) = observe_task(owner, &s, false)?;
            // This durable fence is deliberately committed first. If this
            // journal append fails, only this same retained journal may retry.
            owner.claim_generation_task(&s, journal)?;
            Ok(Update::append(
                Event::Prepare {
                    anchor,
                    clock,
                    statement: Box::new(s),
                    funding,
                },
                id,
            ))
        })
    }
    pub fn begin(
        &mut self,
        owner: &mut impl NativeGenerationOwnerV2,
        id: Hash,
    ) -> Result<DispatchDecisionV2> {
        let journal = self.journal_identity;
        self.update(|state| {
            let r = state.record(id)?;
            // Cancellation is terminal for dispatch even when accounting is
            // unknown. Replaying it neither releases the original resource
            // charge nor consults/repins native funding after a branch change.
            if r.cancel.is_some() || r.verified.is_some() || r.failure.is_some() {
                return Ok(Update::Replay(DispatchDecisionV2::Done));
            }
            if r.intent {
                return Ok(Update::Replay(DispatchDecisionV2::Pending));
            }
            let (anchor, clock, pin) = observe_task(owner, &r.statement, false)?;
            require(pin == r.funding, "GENERATION_NATIVE_REPIN")?;
            owner.claim_generation_task(&r.statement, journal)?;
            Ok(Update::append(
                Event::Intent { id, anchor, clock },
                DispatchDecisionV2::New,
            ))
        })
    }
    pub fn bind_job(&mut self, id: Hash, job: ProviderJobV2) -> Result<()> {
        self.update(|state| {
            if let Some(prior) = &state.record(id)?.job {
                require(prior == &job, "GENERATION_JOB_REPLAY")?;
                return Ok(Update::Replay(()));
            }
            Ok(Update::append(Event::BindJob { id, job }, ()))
        })
    }
    pub fn verify(
        &mut self,
        owner: &mut impl NativeGenerationOwnerV2,
        id: Hash,
        evidence: &GenerationEvidenceV2<'_>,
    ) -> Result<()> {
        let before = self.snapshot()?;
        let r = before.record(id)?;
        require(
            r.cancel.is_none() && r.failure.is_none(),
            "GENERATION_VERIFICATION_FENCE",
        )?;
        require(
            sha256(evidence.header) == r.statement.header_sha256
                && evidence.expected_artifacts.len() == 64
                && sha256(evidence.expected_artifacts) == r.statement.expected_artifacts_sha256
                && evidence.receipt.len() as u64 <= r.statement.resource_cap.receipt_bytes
                && evidence.owned_execution_evidence != [0; 32],
            "GENERATION_EXTERNAL_EXPECTATION",
        )?;
        if let Some(v) = &r.verified {
            require(
                v.receipt_sha256 == sha256(evidence.receipt)
                    && v.owned_execution_evidence == evidence.owned_execution_evidence,
                "GENERATION_VERDICT_REPLAY",
            )?;
            return Ok(());
        }
        let job = r
            .job
            .as_ref()
            .ok_or(NativeBudgetErrorV1::Invalid("GENERATION_JOB_UNKNOWN"))?;
        r.statement
            .original_deadline
            .check(&owner.clock_checkpoint()?)?;
        // Expensive cryptography is outside the write transaction: cancellation
        // may commit meanwhile, and the transaction below then refuses Positive.
        let verdict = owner.verify_full_generation(&r.statement, job, evidence)?;
        require(
            verdict.receipt_sha256 == sha256(evidence.receipt)
                && verdict.consumed.receipt_bytes == evidence.receipt.len() as u64
                && verdict.owned_execution_evidence == evidence.owned_execution_evidence,
            "GENERATION_RECEIPT_BINDING",
        )?;
        self.update(|state| {
            let current = state.record(id)?;
            require(
                current.statement == r.statement && current.job == r.job,
                "GENERATION_VERIFICATION_REPIN",
            )?;
            if let Some(prior) = &current.verified {
                require(prior == &verdict, "GENERATION_VERDICT_REPLAY")?;
                return Ok(Update::Replay(()));
            }
            let (anchor, clock, pin) = observe_task(owner, &current.statement, false)?;
            require(pin == current.funding, "GENERATION_NATIVE_REPIN")?;
            Ok(Update::append(
                Event::Verified {
                    id,
                    anchor,
                    clock,
                    verdict: Box::new(verdict),
                },
                (),
            ))
        })
    }
    pub fn fail(&mut self, id: Hash, failure: FailureV2) -> Result<()> {
        self.update(|state| {
            if let Some(prior) = &state.record(id)?.failure {
                require(prior == &failure, "GENERATION_FAILURE_REPLAY")?;
                return Ok(Update::Replay(()));
            }
            Ok(Update::append(Event::Failure { id, failure }, ()))
        })
    }
    pub fn cancel(&mut self, id: Hash, reason: Hash) -> Result<()> {
        self.update(|state| {
            if state.record(id)?.cancel.is_some() {
                return Ok(Update::Replay(()));
            }
            Ok(Update::append(Event::Cancel { id, reason }, ()))
        })
    }
    /// The successful new intent is the SERVICE cancellation linearization point.
    /// It is not canonical inclusion, and it performs no signing/submission.
    pub fn prepare_settlement(
        &mut self,
        owner: &mut impl NativeGenerationOwnerV2,
        id: Hash,
        exact_wire: Vec<u8>,
    ) -> Result<DispatchDecisionV2> {
        self.update(|state| {
            let r = state.record(id)?;
            if let Some(old) = &r.settlement {
                require(old.exact_wire == exact_wire, "GENERATION_SETTLEMENT_REPLAY")?;
                return Ok(Update::Replay(if r.payment.is_some() {
                    DispatchDecisionV2::Done
                } else {
                    DispatchDecisionV2::Pending
                }));
            }
            require(
                r.verified.is_some() && r.cancel.is_none() && r.failure.is_none(),
                "GENERATION_SETTLEMENT_FENCE",
            )?;
            let (anchor, clock, pin) = observe_task(owner, &r.statement, true)?;
            require(pin == r.funding, "GENERATION_NATIVE_REPIN")?;
            let q = owner.check_settlement_wire(&r.statement, &exact_wire)?;
            require(
                q.source == NativeFundingSourceV1::Task(r.statement.task)
                    && q.subject == id
                    && q.beneficiary == r.statement.provider
                    && q.maximum_gross_units == r.funding.whole_obligation,
                "GENERATION_SETTLEMENT_WIRE",
            )?;
            Ok(Update::append(
                Event::Settlement {
                    id,
                    anchor,
                    clock,
                    intent: SettlementIntentV2 {
                        operation: q.operation,
                        exact_wire,
                    },
                },
                DispatchDecisionV2::New,
            ))
        })
    }
    pub fn record_payment(
        &mut self,
        owner: &mut impl NativeFundingOwnerV1,
        id: Hash,
    ) -> Result<()> {
        self.update(|state| {
            let r = state.record(id)?;
            if r.payment.is_some() {
                return Ok(Update::Replay(()));
            }
            let intent = r.settlement.as_ref().ok_or(NativeBudgetErrorV1::Invalid(
                "GENERATION_SETTLEMENT_UNKNOWN",
            ))?;
            let q = NativePaymentQueryV1 {
                source: NativeFundingSourceV1::Task(r.statement.task),
                subject: id,
                beneficiary: r.statement.provider,
                operation: intent.operation,
                maximum_gross_units: r.funding.whole_obligation,
            };
            let observed = owner.observe_payment(&q)?;
            Ok(Update::append(Event::Payment { id, observed }, ()))
        })
    }
    pub fn reobserve_payment(
        &self,
        owner: &mut impl NativeFundingOwnerV1,
        id: Hash,
    ) -> Result<NativePaymentObservationV1> {
        let (mut state, sequence, root) = self.snapshot_with_head()?;
        let r = state.record(id)?.clone();
        let original = r.payment.as_ref().ok_or(NativeBudgetErrorV1::Invalid(
            "GENERATION_PAYMENT_UNRECORDED",
        ))?;
        let q = NativePaymentQueryV1 {
            source: original.source,
            subject: original.subject,
            beneficiary: original.beneficiary,
            operation: original.operation,
            maximum_gross_units: r.funding.whole_obligation,
        };
        let observed = owner.observe_payment(&q)?;
        state.anchor(observed.anchor, &self.configuration)?;
        check_payment(&r, &observed)?;
        require(
            observed.operation == original.operation,
            "GENERATION_PAYMENT_REOBSERVATION",
        )?;
        // The owner callback may overlap an append through another connection.
        // Read a new SQLite snapshot after leaving the original one: even an
        // append at the same native generation makes this observation stale.
        // This is a readback fence, not a durable anchor update or a new payment.
        let (_, current_sequence, current_root) = self.snapshot_with_head()?;
        require(
            (current_sequence, current_root) == (sequence, root),
            "GENERATION_PAYMENT_JOURNAL_CHANGED",
        )?;
        Ok(observed)
    }
}

#[cfg(test)]
mod tests;
