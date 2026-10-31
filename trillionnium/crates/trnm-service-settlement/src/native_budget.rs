//! Native-owner adapter and monotonic local resource/effect journal.
//!
//! The owner callback is a trusted integration boundary, not a remote funding
//! claim. Only the actual Node implementation authenticates active anchors and
//! native rows. There is no supplied-amount funding API, issuance, account credit
//! or second settlement ledger here. Actual payments must be observed through
//! ordinary native transactions/reward maturation by that same owner.
//!
//! This database is never a branch snapshot. A reorganization may invalidate a
//! funding row or payment's current-chain status, but cannot erase physical cost,
//! pending external effects, exact operation bindings or an observed past payment.
//! A pending effect requires target-side reconciliation; it is never permission
//! to dispatch again. An operator restoring this entire database from an old copy
//! is outside its anti-rollback guarantee; the Node/target must retain their fences.

use borsh::{BorshDeserialize, BorshSerialize};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt, path::Path, time::Duration};

pub type NativeBudgetHashV1 = [u8; 32];
pub type NativeBudgetResultV1<T> = Result<T, NativeBudgetErrorV1>;
pub const NATIVE_BUDGET_NAMESPACE_V1: &str = "pon-native-owner-six-lane-budget-v1";
const APPLICATION_ID: i64 = 0x504e_4231;
const MAX_EVENT_BYTES: usize = 16_384;

#[derive(Debug)]
pub enum NativeBudgetErrorV1 {
    Invalid(&'static str),
    Owner(String),
    Store(rusqlite::Error),
    Io(std::io::Error),
}
impl fmt::Display for NativeBudgetErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(code) => write!(f, "{code}"),
            Self::Owner(cause) => write!(f, "NATIVE_BUDGET_OWNER: {cause}"),
            Self::Store(cause) => write!(f, "NATIVE_BUDGET_STORE: {cause}"),
            Self::Io(cause) => write!(f, "NATIVE_BUDGET_IO: {cause}"),
        }
    }
}
impl std::error::Error for NativeBudgetErrorV1 {}
impl From<rusqlite::Error> for NativeBudgetErrorV1 {
    fn from(value: rusqlite::Error) -> Self {
        Self::Store(value)
    }
}
impl From<std::io::Error> for NativeBudgetErrorV1 {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
fn require(ok: bool, code: &'static str) -> NativeBudgetResultV1<()> {
    if ok {
        Ok(())
    } else {
        Err(NativeBudgetErrorV1::Invalid(code))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NativeBudgetAnchorV1 {
    pub network: NativeBudgetHashV1,
    pub parameters: NativeBudgetHashV1,
    pub genesis: NativeBudgetHashV1,
    pub block: NativeBudgetHashV1,
    pub state_root: NativeBudgetHashV1,
    pub height: u64,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, BorshSerialize, BorshDeserialize)]
pub enum NativeFundingSourceV1 {
    Reward(NativeBudgetHashV1),
    Release(NativeBudgetHashV1),
    Task(NativeBudgetHashV1),
    Quota(NativeBudgetHashV1),
}
impl NativeFundingSourceV1 {
    fn indivisible(self) -> bool {
        matches!(self, Self::Reward(_) | Self::Task(_))
    }
    pub fn key(self) -> String {
        let (prefix, id) = match self {
            Self::Reward(id) => ("reward:", id),
            Self::Release(id) => ("release:", id),
            Self::Task(id) => ("task:", id),
            Self::Quota(id) => ("quota:", id),
        };
        format!("{prefix}{}", hex_string(&id))
    }
}
/// Produced by a single authenticated owner snapshot, including absent rows.
/// The adapter deliberately does not claim that arbitrary instances verify a
/// chain: implementing NativeFundingOwnerV1 is a trusted native-owner boundary.
#[derive(Clone, Debug)]
pub struct NativeFundingObservationV1 {
    pub anchor: NativeBudgetAnchorV1,
    pub source: NativeFundingSourceV1,
    pub row: Option<Value>,
}
#[derive(Clone, Debug)]
pub struct NativePaymentQueryV1 {
    pub source: NativeFundingSourceV1,
    /// Task output, release contribution ID, quota result or original reward ID.
    pub subject: NativeBudgetHashV1,
    pub beneficiary: NativeBudgetHashV1,
    /// Exact ordinary transaction or original reward identity, never an ACK.
    pub operation: NativeBudgetHashV1,
    pub maximum_gross_units: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NativePaymentObservationV1 {
    pub anchor: NativeBudgetAnchorV1,
    pub source: NativeFundingSourceV1,
    pub subject: NativeBudgetHashV1,
    pub beneficiary: NativeBudgetHashV1,
    pub operation: NativeBudgetHashV1,
    pub gross_escrow_debit: u64,
    /// Quota use pays gross minus its actual native fee; never conflate them.
    pub beneficiary_credit: u64,
}
/// Two observations of the same monetary effect, not a new payment or a
/// finality/execution capability. `observed` is current only at the native
/// owner's checked snapshot; the historical journal is not rewritten.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePaymentReadbackV1 {
    pub historical: NativePaymentObservationV1,
    pub observed: NativePaymentObservationV1,
}

pub trait NativeFundingOwnerV1 {
    fn observe_funding(
        &mut self,
        source: NativeFundingSourceV1,
    ) -> NativeBudgetResultV1<NativeFundingObservationV1>;

    /// Verify ordinary M06 execution, branch membership and the exact recipient
    /// and amount. Absence of this bridge is an explicit refusal, not a proof.
    fn observe_payment(
        &mut self,
        _query: &NativePaymentQueryV1,
    ) -> NativeBudgetResultV1<NativePaymentObservationV1> {
        Err(NativeBudgetErrorV1::Invalid(
            "NATIVE_PAYMENT_PROOF_UNAVAILABLE",
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, BorshSerialize, BorshDeserialize)]
pub enum NativeBudgetLaneV1 {
    Mining,
    Contribution,
    Evaluation,
    Storage,
    Repair,
    Serving,
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum NativeBudgetResourcesV1 {
    Mining {
        verified_work_units: u64,
        cpu_ns: u64,
    },
    Contribution {
        training_cpu_ns: u64,
        parameter_bytes: u64,
    },
    Evaluation {
        evaluation_cpu_ns: u64,
        evaluated_examples: u64,
    },
    Storage {
        retained_bytes: u64,
        retained_byte_blocks: u64,
    },
    Repair {
        cpu_ns: u64,
        download_bytes: u64,
        upload_bytes: u64,
        attempts: u64,
    },
    Serving {
        inference_cpu_ns: u64,
        output_tokens: u64,
    },
}
impl NativeBudgetResourcesV1 {
    pub fn lane(&self) -> NativeBudgetLaneV1 {
        match self {
            Self::Mining { .. } => NativeBudgetLaneV1::Mining,
            Self::Contribution { .. } => NativeBudgetLaneV1::Contribution,
            Self::Evaluation { .. } => NativeBudgetLaneV1::Evaluation,
            Self::Storage { .. } => NativeBudgetLaneV1::Storage,
            Self::Repair { .. } => NativeBudgetLaneV1::Repair,
            Self::Serving { .. } => NativeBudgetLaneV1::Serving,
        }
    }
    fn vector(&self) -> [u64; 4] {
        match *self {
            Self::Mining {
                verified_work_units,
                cpu_ns,
            } => [verified_work_units, cpu_ns, 0, 0],
            Self::Contribution {
                training_cpu_ns,
                parameter_bytes,
            } => [training_cpu_ns, parameter_bytes, 0, 0],
            Self::Evaluation {
                evaluation_cpu_ns,
                evaluated_examples,
            } => [evaluation_cpu_ns, evaluated_examples, 0, 0],
            Self::Storage {
                retained_bytes,
                retained_byte_blocks,
            } => [retained_bytes, retained_byte_blocks, 0, 0],
            Self::Repair {
                cpu_ns,
                download_bytes,
                upload_bytes,
                attempts,
            } => [cpu_ns, download_bytes, upload_bytes, attempts],
            Self::Serving {
                inference_cpu_ns,
                output_tokens,
            } => [inference_cpu_ns, output_tokens, 0, 0],
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NativeBudgetConfigV1 {
    pub network: NativeBudgetHashV1,
    pub parameters: NativeBudgetHashV1,
    pub genesis: NativeBudgetHashV1,
    pub max_records: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NativeBudgetPolicyV1 {
    pub budget: NativeBudgetHashV1,
    pub source: NativeFundingSourceV1,
    pub monetary_cap: u64,
    pub deadline: u64,
    pub resource_cap: NativeBudgetResourcesV1,
    pub max_inflight: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NativeBudgetClaimV1 {
    pub claim: NativeBudgetHashV1,
    pub budget: NativeBudgetHashV1,
    pub subject: NativeBudgetHashV1,
    pub beneficiary: NativeBudgetHashV1,
    pub monetary_reservation: u64,
    pub resource_reservation: NativeBudgetResourcesV1,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum NativeResourceOutcomeV1 {
    Positive,
    NoGain,
    Invalid,
    Unknown,
    Cancelled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeBudgetReplayV1 {
    New,
    Pending,
    Done,
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
struct FundingPin {
    source: NativeFundingSourceV1,
    lane: NativeBudgetLaneV1,
    owner: NativeBudgetHashV1,
    beneficiary: Option<NativeBudgetHashV1>,
    consumer: Option<NativeBudgetHashV1>,
    root: Option<NativeBudgetHashV1>,
    maturity: u64,
    deadline: Option<u64>,
}
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
struct Funding {
    pin: FundingPin,
    remaining: u64,
    claimed_subjects: Vec<NativeBudgetHashV1>,
    // Receipt status/output is mutable native state, not an immutable contract
    // pin. It must be checked again before the first physical intent.
    task_output: Option<NativeBudgetHashV1>,
}
impl Funding {
    fn check_subject(&self, claim: &NativeBudgetClaimV1) -> NativeBudgetResultV1<()> {
        require(
            !self.claimed_subjects.contains(&claim.subject)
                && self
                    .pin
                    .beneficiary
                    .is_none_or(|who| who == claim.beneficiary),
            "BUDGET_NATIVE_PAYEE_OR_ALREADY_CLAIMED",
        )?;
        require(
            !matches!(
                self.pin.source,
                NativeFundingSourceV1::Task(_) | NativeFundingSourceV1::Quota(_)
            ) || claim.subject != [0; 32],
            "BUDGET_NATIVE_OUTPUT_REQUIRED",
        )?;
        require(
            self.task_output
                .is_none_or(|output| output == claim.subject),
            "BUDGET_NATIVE_TASK_OUTPUT_BINDING",
        )?;
        if let NativeFundingSourceV1::Reward(id) = self.pin.source {
            require(claim.subject == id, "BUDGET_NATIVE_REWARD_SUBJECT")?;
        }
        Ok(())
    }
}
fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}
fn identity(value: &str) -> NativeBudgetResultV1<NativeBudgetHashV1> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "BUDGET_NATIVE_IDENTITY",
    )?;
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)
            .map_err(|_| NativeBudgetErrorV1::Invalid("BUDGET_NATIVE_IDENTITY"))?;
    }
    Ok(bytes)
}
fn number(row: &Value, key: &str) -> NativeBudgetResultV1<u64> {
    row.get(key)
        .and_then(Value::as_u64)
        .ok_or(NativeBudgetErrorV1::Invalid("BUDGET_NATIVE_NUMBER"))
}
fn text<'a>(row: &'a Value, key: &str) -> NativeBudgetResultV1<&'a str> {
    row.get(key)
        .and_then(Value::as_str)
        .ok_or(NativeBudgetErrorV1::Invalid("BUDGET_NATIVE_FIELD"))
}
fn funding(
    observed: &NativeFundingObservationV1,
    lane: NativeBudgetLaneV1,
) -> NativeBudgetResultV1<Funding> {
    let row = observed
        .row
        .as_ref()
        .ok_or(NativeBudgetErrorV1::Invalid("BUDGET_NATIVE_SOURCE_MISSING"))?;
    let owner = identity(text(row, "owner")?)?;
    let (remaining, beneficiary, root, maturity, deadline, subjects) = match (observed.source, lane)
    {
        (NativeFundingSourceV1::Reward(_), NativeBudgetLaneV1::Mining) => (
            number(row, "amount")?,
            Some(owner),
            None,
            number(row, "maturity")?,
            None,
            Vec::new(),
        ),
        (NativeFundingSourceV1::Release(_), NativeBudgetLaneV1::Contribution) => {
            require(
                text(row, "status")? == "open",
                "BUDGET_NATIVE_SOURCE_CLOSED",
            )?;
            let remaining = number(row, "remaining")?;
            require(
                remaining <= number(row, "budget")? && number(row, "total")? > 0,
                "BUDGET_NATIVE_RELEASE",
            )?;
            let claims = row
                .get("claims")
                .and_then(Value::as_object)
                .ok_or(NativeBudgetErrorV1::Invalid("BUDGET_NATIVE_RELEASE"))?;
            require(claims.len() <= 256, "BUDGET_NATIVE_RELEASE")?;
            let mut subjects = Vec::new();
            for (id, amount) in claims {
                require(amount.as_u64().is_some(), "BUDGET_NATIVE_NUMBER")?;
                subjects.push(identity(id)?);
            }
            (
                remaining,
                None,
                Some(identity(text(row, "root")?)?),
                number(row, "maturity")?,
                Some(number(row, "deadline")?),
                subjects,
            )
        }
        (
            NativeFundingSourceV1::Task(_),
            NativeBudgetLaneV1::Evaluation
            | NativeBudgetLaneV1::Storage
            | NativeBudgetLaneV1::Repair,
        ) => {
            require(
                matches!(text(row, "status")?, "reserved" | "receipt"),
                "BUDGET_NATIVE_SOURCE_CLOSED",
            )?;
            (
                number(row, "remaining")?,
                Some(identity(text(row, "provider")?)?),
                None,
                0,
                Some(number(row, "deadline")?),
                Vec::new(),
            )
        }
        (NativeFundingSourceV1::Quota(_), NativeBudgetLaneV1::Serving) => {
            require(
                text(row, "status")? == "reserved" && number(row, "units")? > 0,
                "BUDGET_NATIVE_SOURCE_CLOSED",
            )?;
            identity(text(row, "consumer")?)?;
            (
                number(row, "remaining")?,
                Some(identity(text(row, "provider")?)?),
                None,
                0,
                Some(number(row, "deadline")?),
                Vec::new(),
            )
        }
        _ => return Err(NativeBudgetErrorV1::Invalid("BUDGET_NATIVE_SOURCE_LANE")),
    };
    require(
        remaining > 0 && deadline.is_none_or(|d| observed.anchor.height < d),
        "BUDGET_NATIVE_SOURCE_CLOSED",
    )?;
    let consumer = if matches!(observed.source, NativeFundingSourceV1::Quota(_)) {
        Some(identity(text(row, "consumer")?)?)
    } else {
        None
    };
    let task_output = if matches!(observed.source, NativeFundingSourceV1::Task(_)) {
        if text(row, "status")? == "receipt" {
            let output = identity(text(row, "output")?)?;
            require(output != [0; 32], "BUDGET_NATIVE_TASK_OUTPUT_BINDING")?;
            Some(output)
        } else {
            require(
                row.get("output") == Some(&Value::Null),
                "BUDGET_NATIVE_TASK_OUTPUT_BINDING",
            )?;
            None
        }
    } else {
        None
    };
    Ok(Funding {
        pin: FundingPin {
            source: observed.source,
            lane,
            owner,
            beneficiary,
            consumer,
            root,
            maturity,
            deadline,
        },
        remaining,
        claimed_subjects: subjects,
        task_output,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
struct Budget {
    policy: NativeBudgetPolicyV1,
    funding: FundingPin,
    closed: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
struct Effect {
    operation: NativeBudgetHashV1,
    effect: NativeBudgetHashV1,
    window: Option<(u64, u64)>,
    receipt: Option<NativeBudgetHashV1>,
}
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
struct Claim {
    specification: NativeBudgetClaimV1,
    outcome: Option<NativeResourceOutcomeV1>,
    consumed: Option<NativeBudgetResourcesV1>,
    effect: Option<Effect>,
    payment: Option<NativePaymentObservationV1>,
}
impl Claim {
    fn monetary_commitment(&self) -> u64 {
        if let Some(payment) = &self.payment {
            payment.gross_escrow_debit
        }
        // A failed/unknown local job is not proof that no native settlement
        // was submitted. Keep its monetary hold until original source expiry;
        // this adapter cannot manufacture a native refund or reuse that hold.
        else {
            self.specification.monetary_reservation
        }
    }
    fn unpaid_commitment(&self) -> u64 {
        if self.payment.is_some() {
            0
        } else {
            self.monetary_commitment()
        }
    }
    fn resource_charge(&self) -> &NativeBudgetResourcesV1 {
        self.consumed
            .as_ref()
            .unwrap_or(&self.specification.resource_reservation)
    }
}

const META_SQL: &str = "CREATE TABLE native_budget_meta_v1(singleton INTEGER PRIMARY KEY CHECK(singleton=1),configuration BLOB NOT NULL,sequence INTEGER NOT NULL,root BLOB NOT NULL CHECK(length(root)=32)) STRICT";
const EVENT_SQL: &str = "CREATE TABLE native_budget_events_v1(sequence INTEGER PRIMARY KEY,payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 16384),root BLOB NOT NULL CHECK(length(root)=32)) STRICT";

/// Local obligations survive branch changes. Open a new path; never repurpose
/// the portable single-rollup database or a Node's native database.
pub struct NativeBudgetStoreV1 {
    connection: Connection,
    configuration: NativeBudgetConfigV1,
}
enum Update<T> {
    Append(Box<Event>, T),
    Replay(T),
}
fn encoded<T: BorshSerialize>(value: &T) -> NativeBudgetResultV1<Vec<u8>> {
    Ok(borsh::to_vec(value)?)
}
fn event_root(previous: NativeBudgetHashV1, sequence: u64, payload: &[u8]) -> NativeBudgetHashV1 {
    let mut h = Sha256::new();
    h.update(NATIVE_BUDGET_NAMESPACE_V1.as_bytes());
    h.update(previous);
    h.update(sequence.to_le_bytes());
    h.update((payload.len() as u64).to_le_bytes());
    h.update(payload);
    h.finalize().into()
}
fn fixed(bytes: Vec<u8>) -> NativeBudgetResultV1<NativeBudgetHashV1> {
    bytes
        .try_into()
        .map_err(|_| NativeBudgetErrorV1::Invalid("BUDGET_JOURNAL_ROOT"))
}
fn check_store_schema(connection: &Connection) -> NativeBudgetResultV1<()> {
    let application: i64 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    require(
        application == APPLICATION_ID && version == 1,
        "BUDGET_FOREIGN_DATABASE",
    )?;
    for (name, expected) in [
        ("native_budget_meta_v1", META_SQL),
        ("native_budget_events_v1", EVENT_SQL),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |r| r.get(0),
            )
            .optional()?;
        require(actual.as_deref() == Some(expected), "BUDGET_STORE_SCHEMA")?;
    }
    let objects: u64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'",
        [],
        |r| r.get(0),
    )?;
    require(objects == 2, "BUDGET_STORE_SCHEMA")
}
/// A caller-local readback expectation, never stored state or a new hash domain.
/// A valid concurrent append may extend it; the exact committed event and the
/// complete state derived at its prefix must still be present in one snapshot.
#[derive(Clone, Copy)]
struct JournalReadback<'a> {
    sequence: u64,
    root: NativeBudgetHashV1,
    payload: Option<&'a [u8]>,
    state: &'a BudgetState,
}
fn load(
    connection: &Connection,
    configuration: &NativeBudgetConfigV1,
) -> NativeBudgetResultV1<(BudgetState, u64, NativeBudgetHashV1)> {
    load_checked(connection, configuration, None)
}
fn load_checked(
    connection: &Connection,
    configuration: &NativeBudgetConfigV1,
    readback: Option<JournalReadback<'_>>,
) -> NativeBudgetResultV1<(BudgetState, u64, NativeBudgetHashV1)> {
    // A live handle must not turn schema/namespace changes made after open into
    // permission to write or an authoritative same-ID replay.
    check_store_schema(connection)?;
    let (bytes, expected_count, expected_root): (Option<Vec<u8>>, u64, Vec<u8>) = connection.query_row(
        "SELECT CASE WHEN length(configuration)<=16384 THEN configuration ELSE NULL END,sequence,root FROM native_budget_meta_v1 WHERE singleton=1", [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    require(
        bytes.as_deref() == Some(encoded(configuration)?.as_slice()),
        "BUDGET_STORE_CONFIGURATION",
    )?;
    require(
        expected_count <= u64::from(configuration.max_records) * 7,
        "BUDGET_JOURNAL_LIMIT",
    )?;
    let mut state = BudgetState::default();
    let mut sequence = 0;
    let mut previous = [0; 32];
    let mut readback_seen = readback.is_none();
    if let Some(expected) = readback.filter(|expected| expected.sequence == 0) {
        require(
            expected.root == previous && expected.payload.is_none() && expected.state == &state,
            "BUDGET_JOURNAL_READBACK",
        )?;
        readback_seen = true;
    }
    let mut query = connection.prepare("SELECT sequence,CASE WHEN length(payload)<=16384 THEN payload ELSE NULL END,root FROM native_budget_events_v1 ORDER BY sequence")?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        sequence += 1;
        require(
            sequence <= expected_count && row.get::<_, u64>(0)? == sequence,
            "BUDGET_JOURNAL_SEQUENCE",
        )?;
        let payload: Option<Vec<u8>> = row.get(1)?;
        let payload = payload.ok_or(NativeBudgetErrorV1::Invalid("BUDGET_JOURNAL_EVENT_LIMIT"))?;
        let root = event_root(previous, sequence, &payload);
        require(fixed(row.get(2)?)? == root, "BUDGET_JOURNAL_ROOT")?;
        let event: Event = borsh::from_slice(&payload)?;
        require(encoded(&event)? == payload, "BUDGET_JOURNAL_ENCODING")?;
        state.apply(&event, configuration)?;
        if let Some(expected) = readback.filter(|expected| expected.sequence == sequence) {
            require(
                root == expected.root
                    && expected.state == &state
                    && expected
                        .payload
                        .is_none_or(|exact| exact == payload.as_slice()),
                "BUDGET_JOURNAL_READBACK",
            )?;
            readback_seen = true;
        }
        previous = root;
    }
    require(
        sequence == expected_count && fixed(expected_root)? == previous,
        "BUDGET_JOURNAL_HEAD",
    )?;
    require(readback_seen, "BUDGET_JOURNAL_READBACK")?;
    Ok((state, sequence, previous))
}
// Standalone readers must pin one SQLite snapshot too: reading the head and
// event stream in separate implicit transactions can mistake a concurrent
// committed append for journal damage.
fn load_snapshot(
    connection: &Connection,
    configuration: &NativeBudgetConfigV1,
) -> NativeBudgetResultV1<(BudgetState, u64, NativeBudgetHashV1)> {
    load_snapshot_checked(connection, configuration, None)
}
fn load_snapshot_checked(
    connection: &Connection,
    configuration: &NativeBudgetConfigV1,
    readback: Option<JournalReadback<'_>>,
) -> NativeBudgetResultV1<(BudgetState, u64, NativeBudgetHashV1)> {
    let transaction = connection.unchecked_transaction()?;
    let state = load_checked(&transaction, configuration, readback)?;
    transaction.commit()?;
    Ok(state)
}
fn check_exact_readback(
    connection: &Connection,
    configuration: &NativeBudgetConfigV1,
    expected: JournalReadback<'_>,
) -> NativeBudgetResultV1<()> {
    let (_, sequence, root) = load_checked(connection, configuration, Some(expected))?;
    require(
        sequence == expected.sequence && root == expected.root,
        "BUDGET_JOURNAL_READBACK",
    )
}
impl NativeBudgetStoreV1 {
    pub fn open(path: &Path, configuration: NativeBudgetConfigV1) -> NativeBudgetResultV1<Self> {
        require(
            (1..=65_536).contains(&configuration.max_records),
            "BUDGET_RECORD_LIMIT",
        )?;
        if let Ok(metadata) = path.symlink_metadata() {
            require(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "BUDGET_STORE_FILE",
            )?;
        }
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "trusted_schema", false)?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let application: i64 =
            connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if application == 0 && version == 0 {
            let count: u64 = connection.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'",
                [],
                |r| r.get(0),
            )?;
            require(count == 0, "BUDGET_FOREIGN_DATABASE")?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(META_SQL)?;
            transaction.execute_batch(EVENT_SQL)?;
            require(
                transaction.execute(
                    "INSERT INTO native_budget_meta_v1 VALUES(1,?1,0,?2)",
                    params![encoded(&configuration)?, [0u8; 32].as_slice()],
                )? == 1,
                "BUDGET_JOURNAL_WRITE",
            )?;
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", 1)?;
            let empty = BudgetState::default();
            check_exact_readback(
                &transaction,
                &configuration,
                JournalReadback {
                    sequence: 0,
                    root: [0; 32],
                    payload: None,
                    state: &empty,
                },
            )?;
            transaction.commit()?;
        } else {
            require(
                application == APPLICATION_ID && version == 1,
                "BUDGET_FOREIGN_DATABASE",
            )?;
        }
        check_store_schema(&connection)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        load_snapshot(&connection, &configuration)?;
        Ok(Self {
            connection,
            configuration,
        })
    }
    fn update<T>(
        &mut self,
        make: impl FnOnce(&BudgetState) -> NativeBudgetResultV1<Update<T>>,
    ) -> NativeBudgetResultV1<T> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (mut state, sequence, previous) = load(&transaction, &self.configuration)?;
        match make(&state)? {
            Update::Replay(value) => {
                let expected = JournalReadback {
                    sequence,
                    root: previous,
                    payload: None,
                    state: &state,
                };
                check_exact_readback(&transaction, &self.configuration, expected)?;
                transaction.commit()?;
                load_snapshot_checked(&self.connection, &self.configuration, Some(expected))?;
                Ok(value)
            }
            Update::Append(event, value) => {
                let event = *event;
                state.apply(&event, &self.configuration)?;
                let payload = encoded(&event)?;
                require(
                    payload.len() <= MAX_EVENT_BYTES,
                    "BUDGET_JOURNAL_EVENT_LIMIT",
                )?;
                let sequence = add(sequence, 1)?;
                require(
                    sequence <= u64::from(self.configuration.max_records) * 7,
                    "BUDGET_JOURNAL_LIMIT",
                )?;
                let root = event_root(previous, sequence, &payload);
                require(
                    transaction.execute(
                        "INSERT INTO native_budget_events_v1 VALUES(?1,?2,?3)",
                        params![sequence, payload, root.as_slice()],
                    )? == 1,
                    "BUDGET_JOURNAL_WRITE",
                )?;
                require(
                    transaction.execute(
                        "UPDATE native_budget_meta_v1 SET sequence=?1,root=?2 WHERE singleton=1 AND sequence=?3 AND root=?4",
                        params![sequence, root.as_slice(), sequence - 1, previous.as_slice()],
                    )? == 1,
                    "BUDGET_JOURNAL_WRITE",
                )?;
                let expected = JournalReadback {
                    sequence,
                    root,
                    payload: Some(&payload),
                    state: &state,
                };
                check_exact_readback(&transaction, &self.configuration, expected)?;
                transaction.commit()?;
                // Only an actual committed readback permits New. If the read
                // fails after a successful commit, return uncertainty; a later
                // retry reloads the real intent and can only reconcile it.
                // No in-memory state is retained or advanced on the error path.
                load_snapshot_checked(&self.connection, &self.configuration, Some(expected))?;
                Ok(value)
            }
        }
    }
    pub fn open_budget(
        &mut self,
        owner: &mut impl NativeFundingOwnerV1,
        policy: NativeBudgetPolicyV1,
    ) -> NativeBudgetResultV1<NativeBudgetReplayV1> {
        self.update(|state| {
            if let Some(previous) = state.budgets.get(&policy.budget) {
                require(previous.policy == policy, "BUDGET_POLICY_REPLAY_MISMATCH")?;
                return Ok(Update::Replay(NativeBudgetReplayV1::Done));
            }
            let observed = owner.observe_funding(policy.source)?;
            require(
                observed.source == policy.source,
                "BUDGET_NATIVE_SOURCE_BINDING",
            )?;
            let funding = funding(&observed, policy.resource_cap.lane())?;
            Ok(Update::Append(
                Box::new(Event::Open {
                    anchor: observed.anchor,
                    funding,
                    policy,
                }),
                NativeBudgetReplayV1::New,
            ))
        })
    }
    pub fn reserve(
        &mut self,
        owner: &mut impl NativeFundingOwnerV1,
        claim: NativeBudgetClaimV1,
    ) -> NativeBudgetResultV1<NativeBudgetReplayV1> {
        self.update(|state| {
            if let Some(previous) = state.claims.get(&claim.claim) {
                require(
                    previous.specification == claim,
                    "BUDGET_CLAIM_REPLAY_MISMATCH",
                )?;
                return Ok(Update::Replay(if previous.outcome.is_some() {
                    NativeBudgetReplayV1::Done
                } else {
                    NativeBudgetReplayV1::Pending
                }));
            }
            let policy = &state.budget(claim.budget)?.policy;
            let observed = owner.observe_funding(policy.source)?;
            require(
                observed.source == policy.source,
                "BUDGET_NATIVE_SOURCE_BINDING",
            )?;
            let funding = funding(&observed, policy.resource_cap.lane())?;
            Ok(Update::Append(
                Box::new(Event::Reserve {
                    anchor: observed.anchor,
                    funding,
                    claim,
                }),
                NativeBudgetReplayV1::New,
            ))
        })
    }
    pub fn begin_effect(
        &mut self,
        owner: &mut impl NativeFundingOwnerV1,
        claim: NativeBudgetHashV1,
        operation: NativeBudgetHashV1,
        effect: NativeBudgetHashV1,
    ) -> NativeBudgetResultV1<NativeBudgetReplayV1> {
        self.begin_effect_window(owner, claim, operation, effect, None)
    }
    /// Funds and the immutable [from, until) service window are checked against
    /// the same owner snapshot before a new durable intent. Exact replay keeps
    /// its original window and grants only target reconciliation.
    pub fn begin_effect_in_window(
        &mut self,
        owner: &mut impl NativeFundingOwnerV1,
        claim: NativeBudgetHashV1,
        operation: NativeBudgetHashV1,
        effect: NativeBudgetHashV1,
        from: u64,
        until: u64,
    ) -> NativeBudgetResultV1<NativeBudgetReplayV1> {
        self.begin_effect_window(owner, claim, operation, effect, Some((from, until)))
    }
    fn begin_effect_window(
        &mut self,
        owner: &mut impl NativeFundingOwnerV1,
        claim: NativeBudgetHashV1,
        operation: NativeBudgetHashV1,
        effect: NativeBudgetHashV1,
        window: Option<(u64, u64)>,
    ) -> NativeBudgetResultV1<NativeBudgetReplayV1> {
        self.update(|state| {
            let record = state.claim(claim)?;
            if let Some(previous) = &record.effect {
                require(
                    previous.operation == operation
                        && previous.effect == effect
                        && previous.window == window
                        && state.operations.get(&operation) == Some(&claim),
                    "BUDGET_EFFECT_REPLAY_MISMATCH",
                )?;
                return Ok(Update::Replay(if previous.receipt.is_some() {
                    NativeBudgetReplayV1::Done
                } else {
                    NativeBudgetReplayV1::Pending
                }));
            }
            let policy = &state.budget(record.specification.budget)?.policy;
            let observed = owner.observe_funding(policy.source)?;
            require(
                observed.source == policy.source,
                "BUDGET_NATIVE_SOURCE_BINDING",
            )?;
            let funding = funding(&observed, policy.resource_cap.lane())?;
            Ok(Update::Append(
                Box::new(Event::Intent {
                    anchor: observed.anchor,
                    funding,
                    claim,
                    operation,
                    effect,
                    window,
                }),
                NativeBudgetReplayV1::New,
            ))
        })
    }
    pub fn complete_effect(
        &mut self,
        claim: NativeBudgetHashV1,
        operation: NativeBudgetHashV1,
        target_receipt: NativeBudgetHashV1,
    ) -> NativeBudgetResultV1<NativeBudgetReplayV1> {
        self.update(|state| {
            let effect = state
                .claim(claim)?
                .effect
                .as_ref()
                .ok_or(NativeBudgetErrorV1::Invalid("BUDGET_EFFECT_NOT_STARTED"))?;
            require(
                effect.operation == operation,
                "BUDGET_EFFECT_REPLAY_MISMATCH",
            )?;
            if let Some(previous) = effect.receipt {
                require(previous == target_receipt, "BUDGET_EFFECT_REPLAY_MISMATCH")?;
                return Ok(Update::Replay(NativeBudgetReplayV1::Done));
            }
            Ok(Update::Append(
                Box::new(Event::Complete {
                    claim,
                    operation,
                    receipt: target_receipt,
                }),
                NativeBudgetReplayV1::New,
            ))
        })
    }
    /// Actual resources come from the worker/storage owner after join/readback.
    /// Unknown measurement consumes the entire original reservation, never zero.
    pub fn record_resources(
        &mut self,
        claim: NativeBudgetHashV1,
        outcome: NativeResourceOutcomeV1,
        consumed: Option<NativeBudgetResourcesV1>,
    ) -> NativeBudgetResultV1<NativeBudgetReplayV1> {
        self.update(|state| {
            require(
                outcome != NativeResourceOutcomeV1::Positive || consumed.is_some(),
                "BUDGET_POSITIVE_RESOURCE_MEASUREMENT_REQUIRED",
            )?;
            require(
                outcome != NativeResourceOutcomeV1::Unknown || consumed.is_none(),
                "BUDGET_UNKNOWN_RESOURCE_FULL_RESERVATION",
            )?;
            let record = state.claim(claim)?;
            let actual =
                consumed.unwrap_or_else(|| record.specification.resource_reservation.clone());
            if let Some(previous) = record.outcome {
                require(
                    previous == outcome && record.consumed.as_ref() == Some(&actual),
                    "BUDGET_RESOURCE_REPLAY_MISMATCH",
                )?;
                return Ok(Update::Replay(NativeBudgetReplayV1::Done));
            }
            Ok(Update::Append(
                Box::new(Event::Resources {
                    claim,
                    outcome,
                    consumed: actual,
                }),
                NativeBudgetReplayV1::New,
            ))
        })
    }
    /// Records an already executed ordinary payment. This method issues nothing.
    pub fn record_native_payment(
        &mut self,
        owner: &mut impl NativeFundingOwnerV1,
        claim: NativeBudgetHashV1,
        operation: NativeBudgetHashV1,
    ) -> NativeBudgetResultV1<NativeBudgetReplayV1> {
        self.update(|state| {
            let record = state.claim(claim)?;
            if let Some(previous) = &record.payment {
                require(
                    previous.operation == operation,
                    "BUDGET_PAYMENT_REPLAY_MISMATCH",
                )?;
                return Ok(Update::Replay(NativeBudgetReplayV1::Done));
            }
            let query = NativePaymentQueryV1 {
                source: state.budget(record.specification.budget)?.policy.source,
                subject: record.specification.subject,
                beneficiary: record.specification.beneficiary,
                operation,
                maximum_gross_units: record.specification.monetary_reservation,
            };
            let observed = owner.observe_payment(&query)?;
            require(
                observed.operation == operation,
                "BUDGET_NATIVE_PAYMENT_BINDING",
            )?;
            Ok(Update::Append(
                Box::new(Event::Payment { claim, observed }),
                NativeBudgetReplayV1::New,
            ))
        })
    }
    /// Recheck one recorded payment against the native owner's current chain.
    /// The exact query comes only from the retained claim/payment. Owner refusal
    /// remains an error, not proof of nonpayment or permission to pay/dispatch
    /// again. Reappearance on another branch may change the observation anchor,
    /// but must preserve the original monetary effect and all local history.
    pub fn reobserve_native_payment(
        &self,
        owner: &mut impl NativeFundingOwnerV1,
        claim: NativeBudgetHashV1,
    ) -> NativeBudgetResultV1<NativePaymentReadbackV1> {
        let (mut state, _, _) = load_snapshot(&self.connection, &self.configuration)?;
        let record = state.claim(claim)?;
        let historical = record.payment.clone().ok_or(NativeBudgetErrorV1::Invalid(
            "BUDGET_NATIVE_PAYMENT_UNRECORDED",
        ))?;
        let query = NativePaymentQueryV1 {
            source: state.budget(record.specification.budget)?.policy.source,
            subject: record.specification.subject,
            beneficiary: record.specification.beneficiary,
            operation: historical.operation,
            maximum_gross_units: record.specification.monetary_reservation,
        };
        let observed = owner.observe_payment(&query)?;
        // Apply the existing context/generation rule to this disposable snapshot,
        // never append an event or change the historical anchor on a readback.
        state.observe_anchor(observed.anchor, &self.configuration)?;
        require(
            observed.source == historical.source
                && observed.subject == historical.subject
                && observed.beneficiary == historical.beneficiary
                && observed.operation == historical.operation
                && observed.gross_escrow_debit == historical.gross_escrow_debit
                && observed.beneficiary_credit == historical.beneficiary_credit,
            "BUDGET_NATIVE_PAYMENT_READBACK_BINDING",
        )?;
        Ok(NativePaymentReadbackV1 {
            historical,
            observed,
        })
    }
    pub fn close_expired(
        &mut self,
        owner: &mut impl NativeFundingOwnerV1,
        budget: NativeBudgetHashV1,
    ) -> NativeBudgetResultV1<NativeBudgetReplayV1> {
        self.update(|state| {
            let record = state.budget(budget)?;
            if record.closed {
                return Ok(Update::Replay(NativeBudgetReplayV1::Done));
            }
            let observed = owner.observe_funding(record.policy.source)?;
            require(
                observed.source == record.policy.source,
                "BUDGET_NATIVE_SOURCE_BINDING",
            )?;
            Ok(Update::Append(
                Box::new(Event::Close {
                    anchor: observed.anchor,
                    budget,
                }),
                NativeBudgetReplayV1::New,
            ))
        })
    }
    pub fn report(&self) -> NativeBudgetResultV1<Value> {
        let (state, sequence, root) = load_snapshot(&self.connection, &self.configuration)?;
        let mut budgets = Vec::new();
        for (id, budget) in &state.budgets {
            let mut resources = [0u64; 4];
            let mut committed = 0;
            let mut paid_gross = 0;
            let mut paid_net = 0;
            let mut pending_effects = 0;
            for record in state
                .claims
                .values()
                .filter(|c| c.specification.budget == *id)
            {
                committed = add(committed, record.monetary_commitment())?;
                for (total, amount) in resources.iter_mut().zip(record.resource_charge().vector()) {
                    *total = add(*total, amount)?;
                }
                if let Some(payment) = &record.payment {
                    paid_gross = add(paid_gross, payment.gross_escrow_debit)?;
                    paid_net = add(paid_net, payment.beneficiary_credit)?;
                }
                pending_effects +=
                    u64::from(record.effect.as_ref().is_some_and(|e| e.receipt.is_none()));
            }
            budgets.push(serde_json::json!({"budget":hex_string(id),"source":budget.policy.source.key(),
                "lane":format!("{:?}",budget.policy.resource_cap.lane()),"cap":budget.policy.monetary_cap,
                "committed_units":committed,"unallocated_units":budget.policy.monetary_cap.checked_sub(committed).ok_or(NativeBudgetErrorV1::Invalid("BUDGET_CONSERVATION"))?,
                "historically_observed_native_gross_debit":paid_gross,"historically_observed_beneficiary_credit":paid_net,
                "resource_charge":resources,"resource_cap":budget.policy.resource_cap.vector(),
                "pending_effects":pending_effects,"closed":budget.closed}));
        }
        Ok(
            serde_json::json!({"schema":NATIVE_BUDGET_NAMESPACE_V1,"sequence":sequence,"journal_root":hex_string(&root),
            "source_count":state.sources.len(),"claim_count":state.claims.len(),"budgets":budgets,
            "authorizes_native_payment":false,"current_branch_payment_finality":false,
            "physical_capacity_verified_by_this_adapter":false,"production_activation":false}),
        )
    }
}

#[cfg(test)]
mod tests;
#[derive(Clone, Default, Eq, PartialEq)]
struct BudgetState {
    anchor: Option<NativeBudgetAnchorV1>,
    sources: BTreeMap<NativeFundingSourceV1, (FundingPin, u64)>,
    budgets: BTreeMap<NativeBudgetHashV1, Budget>,
    claims: BTreeMap<NativeBudgetHashV1, Claim>,
    subjects: BTreeMap<(NativeBudgetLaneV1, NativeBudgetHashV1), NativeBudgetHashV1>,
    operations: BTreeMap<NativeBudgetHashV1, NativeBudgetHashV1>,
}
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
enum Event {
    Open {
        anchor: NativeBudgetAnchorV1,
        funding: Funding,
        policy: NativeBudgetPolicyV1,
    },
    Reserve {
        anchor: NativeBudgetAnchorV1,
        funding: Funding,
        claim: NativeBudgetClaimV1,
    },
    Resources {
        claim: NativeBudgetHashV1,
        outcome: NativeResourceOutcomeV1,
        consumed: NativeBudgetResourcesV1,
    },
    Intent {
        anchor: NativeBudgetAnchorV1,
        funding: Funding,
        claim: NativeBudgetHashV1,
        operation: NativeBudgetHashV1,
        effect: NativeBudgetHashV1,
        window: Option<(u64, u64)>,
    },
    Complete {
        claim: NativeBudgetHashV1,
        operation: NativeBudgetHashV1,
        receipt: NativeBudgetHashV1,
    },
    Payment {
        claim: NativeBudgetHashV1,
        observed: NativePaymentObservationV1,
    },
    Close {
        anchor: NativeBudgetAnchorV1,
        budget: NativeBudgetHashV1,
    },
}
fn add(a: u64, b: u64) -> NativeBudgetResultV1<u64> {
    a.checked_add(b)
        .ok_or(NativeBudgetErrorV1::Invalid("BUDGET_ARITHMETIC"))
}
impl BudgetState {
    fn observe_anchor(
        &mut self,
        anchor: NativeBudgetAnchorV1,
        config: &NativeBudgetConfigV1,
    ) -> NativeBudgetResultV1<()> {
        require(
            anchor.network == config.network
                && anchor.parameters == config.parameters
                && anchor.genesis == config.genesis,
            "BUDGET_NATIVE_CONTEXT",
        )?;
        if let Some(previous) = self.anchor {
            require(
                anchor.generation > previous.generation || anchor == previous,
                "BUDGET_STALE_OWNER_SNAPSHOT",
            )?;
        }
        self.anchor = Some(anchor);
        Ok(())
    }
    fn budget(&self, id: NativeBudgetHashV1) -> NativeBudgetResultV1<&Budget> {
        self.budgets
            .get(&id)
            .ok_or(NativeBudgetErrorV1::Invalid("BUDGET_UNKNOWN"))
    }
    fn claim(&self, id: NativeBudgetHashV1) -> NativeBudgetResultV1<&Claim> {
        self.claims
            .get(&id)
            .ok_or(NativeBudgetErrorV1::Invalid("BUDGET_CLAIM_UNKNOWN"))
    }
    fn check_funding(
        &self,
        budget: &Budget,
        funding: &Funding,
        height: u64,
    ) -> NativeBudgetResultV1<()> {
        require(
            !budget.closed && height < budget.policy.deadline && funding.pin == budget.funding,
            "BUDGET_NATIVE_SOURCE_CHANGED_OR_CLOSED",
        )?;
        // A reward ID binds parent/height/miner, not the sibling block's fees.
        // Reorgs can therefore expose the same ID with a different whole amount.
        require(
            !budget.policy.source.indivisible() || funding.remaining == budget.policy.monetary_cap,
            "BUDGET_NATIVE_SOURCE_ALL_OR_NOTHING",
        )?;
        let pending = self
            .claims
            .values()
            .filter(|claim| {
                self.budgets[&claim.specification.budget].policy.source == budget.policy.source
            })
            .try_fold(0, |sum, claim| add(sum, claim.unpaid_commitment()))?;
        require(pending <= funding.remaining, "BUDGET_NATIVE_FUNDS_SPENT")
    }
    fn apply(&mut self, event: &Event, config: &NativeBudgetConfigV1) -> NativeBudgetResultV1<()> {
        match event {
            Event::Open {
                anchor,
                funding,
                policy,
            } => {
                self.observe_anchor(*anchor, config)?;
                require(
                    self.budgets.len() < config.max_records as usize
                        && !self.budgets.contains_key(&policy.budget),
                    "BUDGET_RECORD_OR_DUPLICATE",
                )?;
                require(
                    policy.source == funding.pin.source
                        && policy.resource_cap.lane() == funding.pin.lane,
                    "BUDGET_NATIVE_SOURCE_LANE",
                )?;
                require(
                    policy.monetary_cap > 0
                        && policy.monetary_cap <= funding.remaining
                        && anchor.height < policy.deadline
                        && funding.pin.maturity < policy.deadline
                        && funding.pin.deadline.is_none_or(|d| policy.deadline <= d)
                        && (1..=64).contains(&policy.max_inflight)
                        && policy.resource_cap.vector().iter().any(|n| *n > 0),
                    "BUDGET_POLICY",
                )?;
                // Native task settlement and reward maturation pay the entire
                // original obligation; neither is a divisible payment primitive.
                require(
                    !policy.source.indivisible() || policy.monetary_cap == funding.remaining,
                    "BUDGET_NATIVE_SOURCE_ALL_OR_NOTHING",
                )?;
                let ceiling = if let Some((pin, initial)) = self.sources.get(&policy.source) {
                    require(pin == &funding.pin, "BUDGET_SOURCE_REPIN")?;
                    *initial
                } else {
                    require(
                        self.sources.len() < config.max_records as usize,
                        "BUDGET_RECORD_LIMIT",
                    )?;
                    funding.remaining
                };
                let allocated = self
                    .budgets
                    .values()
                    .filter(|b| b.policy.source == policy.source)
                    .try_fold(0, |sum, b| add(sum, b.policy.monetary_cap))?;
                require(
                    add(allocated, policy.monetary_cap)? <= ceiling,
                    "BUDGET_SOURCE_OVERBOOKED",
                )?;
                self.sources
                    .entry(policy.source)
                    .or_insert((funding.pin.clone(), ceiling));
                self.budgets.insert(
                    policy.budget,
                    Budget {
                        policy: policy.clone(),
                        funding: funding.pin.clone(),
                        closed: false,
                    },
                );
            }
            Event::Reserve {
                anchor,
                funding,
                claim,
            } => {
                self.observe_anchor(*anchor, config)?;
                require(
                    self.claims.len() < config.max_records as usize
                        && !self.claims.contains_key(&claim.claim),
                    "BUDGET_RECORD_OR_DUPLICATE",
                )?;
                let budget = self.budget(claim.budget)?;
                self.check_funding(budget, funding, anchor.height)?;
                let lane = budget.policy.resource_cap.lane();
                require(
                    claim.resource_reservation.lane() == lane
                        && !self.subjects.contains_key(&(lane, claim.subject)),
                    "BUDGET_RESOURCE_KIND_OR_SUBJECT_REPLAY",
                )?;
                require(
                    claim.resource_reservation.vector().iter().any(|n| *n > 0),
                    "BUDGET_RESOURCES",
                )?;
                funding.check_subject(claim)?;
                require(
                    claim.monetary_reservation > 0
                        && (!budget.policy.source.indivisible()
                            || claim.monetary_reservation == budget.policy.monetary_cap),
                    "BUDGET_NATIVE_SOURCE_ALL_OR_NOTHING",
                )?;
                let mut money = claim.monetary_reservation;
                let mut resources = claim.resource_reservation.vector();
                let mut inflight = 1;
                let mut unpaid = claim.monetary_reservation;
                for prior in self.claims.values() {
                    let prior_budget = self.budget(prior.specification.budget)?;
                    if prior_budget.policy.source == budget.policy.source {
                        unpaid = add(unpaid, prior.unpaid_commitment())?;
                    }
                    if prior.specification.budget != claim.budget {
                        continue;
                    }
                    money = add(money, prior.monetary_commitment())?;
                    for (total, actual) in
                        resources.iter_mut().zip(prior.resource_charge().vector())
                    {
                        *total = add(*total, actual)?;
                    }
                    if prior.outcome.is_none() {
                        inflight += 1;
                    }
                }
                require(
                    money <= budget.policy.monetary_cap && unpaid <= funding.remaining,
                    "BUDGET_FUNDS",
                )?;
                require(
                    inflight <= budget.policy.max_inflight
                        && resources
                            .iter()
                            .zip(budget.policy.resource_cap.vector())
                            .all(|(used, cap)| *used <= cap),
                    "BUDGET_RESOURCES",
                )?;
                self.subjects.insert((lane, claim.subject), claim.claim);
                self.claims.insert(
                    claim.claim,
                    Claim {
                        specification: claim.clone(),
                        outcome: None,
                        consumed: None,
                        effect: None,
                        payment: None,
                    },
                );
            }
            Event::Resources {
                claim,
                outcome,
                consumed,
            } => {
                let record = self.claim(*claim)?;
                require(
                    record.outcome.is_none() && record.consumed.is_none(),
                    "BUDGET_RESOURCE_ALREADY_RESOLVED",
                )?;
                require(
                    consumed.lane() == record.specification.resource_reservation.lane()
                        && consumed
                            .vector()
                            .iter()
                            .zip(record.specification.resource_reservation.vector())
                            .all(|(used, cap)| *used <= cap),
                    "BUDGET_RESOURCE_OVERRUN",
                )?;
                require(
                    *outcome != NativeResourceOutcomeV1::Unknown
                        || consumed == &record.specification.resource_reservation,
                    "BUDGET_UNKNOWN_RESOURCE_FULL_RESERVATION",
                )?;
                let record = self.claims.get_mut(claim).unwrap();
                record.outcome = Some(*outcome);
                record.consumed = Some(consumed.clone());
            }
            Event::Intent {
                anchor,
                funding,
                claim,
                operation,
                effect,
                window,
            } => {
                self.observe_anchor(*anchor, config)?;
                require(
                    window.is_none_or(|(from, until)| {
                        from < until && from <= anchor.height && anchor.height < until
                    }),
                    "BUDGET_NATIVE_EFFECT_WINDOW",
                )?;
                let record = self.claim(*claim)?;
                self.check_funding(
                    self.budget(record.specification.budget)?,
                    funding,
                    anchor.height,
                )?;
                funding.check_subject(&record.specification)?;
                require(
                    record.effect.is_none() && record.outcome.is_none(),
                    "BUDGET_EFFECT_ALREADY_STARTED_OR_RESOLVED",
                )?;
                require(
                    !self.operations.contains_key(operation),
                    "BUDGET_OPERATION_REPLAY",
                )?;
                self.operations.insert(*operation, *claim);
                self.claims.get_mut(claim).unwrap().effect = Some(Effect {
                    operation: *operation,
                    effect: *effect,
                    window: *window,
                    receipt: None,
                });
            }
            Event::Complete {
                claim,
                operation,
                receipt,
            } => {
                let record = self.claim(*claim)?;
                let effect = record
                    .effect
                    .as_ref()
                    .ok_or(NativeBudgetErrorV1::Invalid("BUDGET_EFFECT_NOT_STARTED"))?;
                require(
                    effect.operation == *operation
                        && effect.receipt.is_none()
                        && self.operations.get(operation) == Some(claim),
                    "BUDGET_OPERATION_REPLAY",
                )?;
                self.claims
                    .get_mut(claim)
                    .unwrap()
                    .effect
                    .as_mut()
                    .unwrap()
                    .receipt = Some(*receipt);
            }
            Event::Payment { claim, observed } => {
                self.observe_anchor(observed.anchor, config)?;
                let record = self.claim(*claim)?;
                let budget = self.budget(record.specification.budget)?;
                require(
                    record.payment.is_none()
                        && record.outcome == Some(NativeResourceOutcomeV1::Positive)
                        && observed.source == budget.policy.source
                        && observed.subject == record.specification.subject
                        && observed.beneficiary == record.specification.beneficiary
                        && observed.anchor.height >= budget.funding.maturity
                        && observed.gross_escrow_debit > 0
                        && observed.gross_escrow_debit <= record.specification.monetary_reservation
                        && observed.beneficiary_credit <= observed.gross_escrow_debit,
                    "BUDGET_NATIVE_PAYMENT_BINDING",
                )?;
                if budget.policy.source.indivisible() {
                    require(
                        observed.gross_escrow_debit == record.specification.monetary_reservation,
                        "BUDGET_NATIVE_SOURCE_ALL_OR_NOTHING",
                    )?;
                }
                if let NativeFundingSourceV1::Reward(id) = budget.policy.source {
                    require(observed.operation == id, "BUDGET_NATIVE_REWARD_OPERATION")?;
                }
                if !matches!(budget.policy.source, NativeFundingSourceV1::Quota(_)) {
                    require(
                        observed.beneficiary_credit == observed.gross_escrow_debit,
                        "BUDGET_NATIVE_PAYMENT_BINDING",
                    )?;
                }
                // Payment may be observed after deadline: it is a historical
                // native fact, not permission to issue a late payment here.
                require(
                    !self.operations.contains_key(&observed.operation),
                    "BUDGET_OPERATION_REPLAY",
                )?;
                self.operations.insert(observed.operation, *claim);
                self.claims.get_mut(claim).unwrap().payment = Some(observed.clone());
            }
            Event::Close { anchor, budget } => {
                self.observe_anchor(*anchor, config)?;
                let record = self.budget(*budget)?;
                require(
                    !record.closed && anchor.height >= record.policy.deadline,
                    "BUDGET_NOT_EXPIRED",
                )?;
                self.budgets.get_mut(budget).unwrap().closed = true;
                // Unknown jobs keep their full physical reservation. A pending
                // external intent remains pending even after chain expiry.
                for record in self
                    .claims
                    .values_mut()
                    .filter(|c| c.specification.budget == *budget && c.outcome.is_none())
                {
                    record.outcome = Some(NativeResourceOutcomeV1::Unknown);
                    record.consumed = Some(record.specification.resource_reservation.clone());
                }
            }
        }
        Ok(())
    }
}
