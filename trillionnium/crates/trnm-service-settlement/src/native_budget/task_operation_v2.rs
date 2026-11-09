//! Prospective local Task operations whose output is unknown at reservation.
//!
//! The actual Node owner must pin one budget protocol and one immutable binding
//! per new TSC1 task, and consume its begin gate at most once. This journal is
//! neither a balance ledger nor a physical target grant. A returned New requires
//! both owner and local durable intents; Pending permits reconciliation only.
//! The target must retain its own execution fence, especially if both local
//! databases are restored. Legacy V1 claims are never retyped or migrated here.
use super::{
    encoded, hex_string, require, NativeBudgetAnchorV1, NativeBudgetConfigV1, NativeBudgetErrorV1,
    NativeBudgetHashV1 as Hash, NativeBudgetLaneV1, NativeBudgetReplayV1, NativeBudgetResourcesV1,
    NativeBudgetResultV1 as Result, NativeFundingOwnerV1, NativeFundingSourceV1,
    NativePaymentObservationV1, NativePaymentQueryV1, NativePaymentReadbackV1,
    NativeResourceOutcomeV1,
};
use borsh::{BorshDeserialize, BorshSerialize};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, time::Duration};

pub const NAMESPACE: &str = "pon-native-task-operation-v2";
const APPLICATION_ID: i64 = 0x504e_5432;
const EVENT_LIMIT: usize = 16_384;
const META_SQL: &str = "CREATE TABLE task_operation_meta_v2(singleton INTEGER PRIMARY KEY CHECK(singleton=1),configuration BLOB NOT NULL,sequence INTEGER NOT NULL,root BLOB NOT NULL CHECK(length(root)=32)) STRICT";
const EVENT_SQL: &str = "CREATE TABLE task_operation_events_v2(sequence INTEGER PRIMARY KEY,payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 16384),root BLOB NOT NULL CHECK(length(root)=32)) STRICT";

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NativeTaskOperationBindingV2 {
    pub claim: Hash,
    pub task: Hash,
    pub contract_digest: Hash,
    pub operation: Hash,
    pub beneficiary: Hash,
    /// Commitment to the intended target invocation. This is not itself an
    /// authenticated execution permission from that target.
    pub target_scope: Hash,
    pub resource_cap: NativeBudgetResourcesV1,
}
impl NativeTaskOperationBindingV2 {
    pub fn validate(&self) -> Result<()> {
        require(
            ![
                self.claim,
                self.task,
                self.contract_digest,
                self.operation,
                self.beneficiary,
                self.target_scope,
            ]
            .contains(&[0; 32])
                && matches!(
                    self.resource_cap.lane(),
                    NativeBudgetLaneV1::Contribution | NativeBudgetLaneV1::Evaluation
                )
                && self.resource_cap.vector().iter().any(|value| *value > 0),
            "TASK_OPERATION_BINDING_V2",
        )
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encoded(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        require(bytes.len() <= 512, "TASK_OPERATION_BINDING_V2")?;
        let binding: Self = borsh::from_slice(bytes)?;
        require(binding.encode()? == bytes, "TASK_OPERATION_BINDING_V2")?;
        Ok(binding)
    }
    pub fn id(&self) -> Result<Hash> {
        Ok(digest(b"binding", &[&self.encode()?]))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum NativeTaskStatusV2 {
    Reserved,
    Receipt,
    Settled,
    Refunded,
    Expired,
}

/// Only the trusted native owner authenticates the source and complete contract.
/// Constructing this value or implementing the trait is not a chain proof.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NativeTaskContractObservationV2 {
    pub anchor: NativeBudgetAnchorV1,
    pub task: Hash,
    pub contract_digest: Hash,
    pub payer: Hash,
    pub provider: Hash,
    pub request: Hash,
    pub model: Hash,
    pub input: Hash,
    pub output_spec: Hash,
    pub amount: u64,
    pub delivery_deadline: u64,
    pub dispute_deadline: u64,
    pub remaining: u64,
    pub status: NativeTaskStatusV2,
    pub output: Option<Hash>,
    pub receipt_height: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NativeTaskBeginObservationV2 {
    pub contract: NativeTaskContractObservationV2,
    /// The owner persists consumption before reporting true. A repeated binding
    /// reports false even when a second local journal has no Begin event yet.
    pub new_execution: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NativeTaskDeliveryObservationV2 {
    pub contract: NativeTaskContractObservationV2,
    pub receipt_operation: Hash,
    /// The actual receipt block, distinct from the current contract snapshot.
    pub receipt_anchor: NativeBudgetAnchorV1,
}

pub trait NativeTaskOperationOwnerV2: NativeFundingOwnerV1 {
    /// Must pin V2 and the exact binding durably, rejecting any V1 pin. Old Task
    /// records without the fresh TSC1 contract namespace are not eligible.
    fn reserve_task_operation_v2(
        &mut self,
        binding: &NativeTaskOperationBindingV2,
    ) -> Result<NativeTaskContractObservationV2>;
    /// Must persist a one-time begin fence shared by all local journals using
    /// this owner. Reorg, epoch changes and a different claim cannot clear it.
    fn begin_task_operation_v2(
        &mut self,
        binding: &NativeTaskOperationBindingV2,
    ) -> Result<NativeTaskBeginObservationV2>;
    /// Must replay the actual provider receipt. Caller-supplied result hashes,
    /// current-row differences and terminal payment alone are insufficient.
    fn observe_task_delivery_v2(
        &mut self,
        binding: &NativeTaskOperationBindingV2,
    ) -> Result<NativeTaskDeliveryObservationV2>;
}

/// Complete declared cost categories in one explicitly identified unit. These
/// measurements and their receipt still need their actual metering owner; this
/// journal does not turn caller declarations into verified physical costs.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NativeTaskCostBreakdownV2 {
    pub training_units: u64,
    pub evaluation_units: u64,
    pub storage_units: u64,
    pub serving_units: u64,
    pub unit: Hash,
    pub measurement_receipt: Hash,
}
impl NativeTaskCostBreakdownV2 {
    fn validate(&self) -> Result<()> {
        require(
            self.unit != [0; 32] && self.measurement_receipt != [0; 32],
            "TASK_OPERATION_COSTS_V2",
        )?;
        [
            self.training_units,
            self.evaluation_units,
            self.storage_units,
            self.serving_units,
        ]
        .into_iter()
        .try_fold(0_u64, |sum, value| {
            sum.checked_add(value)
                .ok_or(NativeBudgetErrorV1::Invalid("TASK_OPERATION_COSTS_V2"))
        })?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NativeTaskCostRecordV2 {
    pub outcome: NativeResourceOutcomeV1,
    pub consumed: NativeBudgetResourcesV1,
    pub costs: NativeTaskCostBreakdownV2,
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NativeTaskCompletionV2 {
    pub operation: Hash,
    pub output: Hash,
    pub target_receipt: Hash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeTaskOperationSnapshotV2 {
    pub binding: NativeTaskOperationBindingV2,
    pub reserved: NativeTaskContractObservationV2,
    pub begun: Option<NativeTaskBeginObservationV2>,
    pub costs: Option<NativeTaskCostRecordV2>,
    pub completion: Option<NativeTaskCompletionV2>,
    pub delivery: Option<NativeTaskDeliveryObservationV2>,
    pub payment: Option<NativePaymentObservationV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NativeTaskOperationCheckpointV2 {
    pub configuration: NativeBudgetConfigV1,
    pub sequence: u64,
    pub root: Hash,
}

fn digest(domain: &[u8], parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(NAMESPACE.as_bytes());
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn anchor_context(anchor: NativeBudgetAnchorV1, cfg: &NativeBudgetConfigV1) -> Result<()> {
    require(
        anchor.network == cfg.network
            && anchor.parameters == cfg.parameters
            && anchor.genesis == cfg.genesis
            && anchor.block != [0; 32]
            && anchor.state_root != [0; 32],
        "TASK_OPERATION_ANCHOR_V2",
    )
}

fn validate_contract(
    contract: &NativeTaskContractObservationV2,
    binding: &NativeTaskOperationBindingV2,
    cfg: &NativeBudgetConfigV1,
) -> Result<()> {
    anchor_context(contract.anchor, cfg)?;
    require(
        contract.task == binding.task
            && contract.contract_digest == binding.contract_digest
            && contract.provider == binding.beneficiary
            && ![
                contract.payer,
                contract.request,
                contract.model,
                contract.input,
                contract.output_spec,
            ]
            .contains(&[0; 32])
            && contract.amount > 0
            && contract.delivery_deadline > 0
            && contract.delivery_deadline < contract.dispute_deadline,
        "TASK_OPERATION_CONTRACT_V2",
    )?;
    match (contract.output, contract.receipt_height) {
        (None, None) => {}
        (Some(output), Some(height)) => require(
            output != [0; 32]
                && height <= contract.delivery_deadline
                && height <= contract.anchor.height,
            "TASK_OPERATION_DELIVERY_V2",
        )?,
        _ => return Err(NativeBudgetErrorV1::Invalid("TASK_OPERATION_DELIVERY_V2")),
    }
    require(
        match contract.status {
            NativeTaskStatusV2::Reserved => {
                contract.remaining == contract.amount && contract.output.is_none()
            }
            NativeTaskStatusV2::Receipt => {
                contract.remaining == contract.amount && contract.output.is_some()
            }
            NativeTaskStatusV2::Settled => contract.remaining == 0 && contract.output.is_some(),
            NativeTaskStatusV2::Refunded | NativeTaskStatusV2::Expired => contract.remaining == 0,
        },
        "TASK_OPERATION_NATIVE_STATE_V2",
    )
}

fn same_contract(a: &NativeTaskContractObservationV2, b: &NativeTaskContractObservationV2) -> bool {
    a.task == b.task
        && a.contract_digest == b.contract_digest
        && a.payer == b.payer
        && a.provider == b.provider
        && a.request == b.request
        && a.model == b.model
        && a.input == b.input
        && a.output_spec == b.output_spec
        && a.amount == b.amount
        && a.delivery_deadline == b.delivery_deadline
        && a.dispute_deadline == b.dispute_deadline
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
enum Event {
    Reserve {
        binding: NativeTaskOperationBindingV2,
        observed: NativeTaskContractObservationV2,
    },
    Begin {
        claim: Hash,
        observed: NativeTaskBeginObservationV2,
    },
    Costs {
        claim: Hash,
        record: NativeTaskCostRecordV2,
    },
    Complete {
        claim: Hash,
        completion: NativeTaskCompletionV2,
    },
    Delivery {
        claim: Hash,
        observed: NativeTaskDeliveryObservationV2,
    },
    Payment {
        claim: Hash,
        observed: NativePaymentObservationV1,
    },
}

#[derive(Clone, Default, Eq, PartialEq)]
struct OperationState {
    anchor: Option<NativeBudgetAnchorV1>,
    claims: BTreeMap<Hash, NativeTaskOperationSnapshotV2>,
    tasks: BTreeMap<Hash, Hash>,
    operations: BTreeMap<Hash, Hash>,
}
impl OperationState {
    fn claim(&self, claim: Hash) -> Result<&NativeTaskOperationSnapshotV2> {
        self.claims
            .get(&claim)
            .ok_or(NativeBudgetErrorV1::Invalid("TASK_OPERATION_UNKNOWN_V2"))
    }
    fn observe(&mut self, anchor: NativeBudgetAnchorV1, cfg: &NativeBudgetConfigV1) -> Result<()> {
        anchor_context(anchor, cfg)?;
        if let Some(previous) = self.anchor {
            require(
                anchor.generation > previous.generation
                    || (anchor.generation == previous.generation && anchor == previous),
                "TASK_OPERATION_ANCHOR_ROLLBACK_V2",
            )?;
        }
        self.anchor = Some(anchor);
        Ok(())
    }
    fn apply(&mut self, event: &Event, cfg: &NativeBudgetConfigV1) -> Result<()> {
        match event {
            Event::Reserve { binding, observed } => {
                binding.validate()?;
                validate_contract(observed, binding, cfg)?;
                self.observe(observed.anchor, cfg)?;
                require(
                    self.claims.len() < cfg.max_records as usize
                        && !self.claims.contains_key(&binding.claim)
                        && !self.tasks.contains_key(&binding.task)
                        && !self.operations.contains_key(&binding.operation),
                    "TASK_OPERATION_REPLAY_V2",
                )?;
                require(
                    observed.status == NativeTaskStatusV2::Reserved
                        && observed.anchor.height < observed.delivery_deadline,
                    "TASK_OPERATION_FUNDED_START_V2",
                )?;
                self.tasks.insert(binding.task, binding.claim);
                self.operations.insert(binding.operation, binding.claim);
                self.claims.insert(
                    binding.claim,
                    NativeTaskOperationSnapshotV2 {
                        binding: binding.clone(),
                        reserved: observed.clone(),
                        begun: None,
                        costs: None,
                        completion: None,
                        delivery: None,
                        payment: None,
                    },
                );
            }
            Event::Begin { claim, observed } => {
                self.observe(observed.contract.anchor, cfg)?;
                let prior = self.claim(*claim)?;
                validate_contract(&observed.contract, &prior.binding, cfg)?;
                require(
                    prior.begun.is_none()
                        && same_contract(&prior.reserved, &observed.contract)
                        && (!observed.new_execution
                            || (observed.contract.status == NativeTaskStatusV2::Reserved
                                && observed.contract.anchor.height
                                    < observed.contract.delivery_deadline)),
                    "TASK_OPERATION_BEGIN_V2",
                )?;
                self.claims.get_mut(claim).unwrap().begun = Some(observed.clone());
            }
            Event::Costs { claim, record } => {
                let prior = self.claim(*claim)?;
                record.costs.validate()?;
                require(
                    prior.begun.is_some()
                        && prior.costs.is_none()
                        && record.consumed.lane() == prior.binding.resource_cap.lane()
                        && record
                            .consumed
                            .vector()
                            .iter()
                            .zip(prior.binding.resource_cap.vector())
                            .all(|(used, cap)| *used <= cap)
                        && (record.outcome != NativeResourceOutcomeV1::Unknown
                            || record.consumed == prior.binding.resource_cap),
                    "TASK_OPERATION_RESOURCES_V2",
                )?;
                self.claims.get_mut(claim).unwrap().costs = Some(record.clone());
            }
            Event::Complete { claim, completion } => {
                let prior = self.claim(*claim)?;
                require(
                    prior.begun.is_some()
                        && prior.costs.is_some()
                        && prior.completion.is_none()
                        && completion.operation == prior.binding.operation
                        && completion.output != [0; 32]
                        && completion.target_receipt != [0; 32],
                    "TASK_OPERATION_COMPLETE_V2",
                )?;
                self.claims.get_mut(claim).unwrap().completion = Some(completion.clone());
            }
            Event::Delivery { claim, observed } => {
                self.observe(observed.contract.anchor, cfg)?;
                let prior = self.claim(*claim)?;
                validate_contract(&observed.contract, &prior.binding, cfg)?;
                anchor_context(observed.receipt_anchor, cfg)?;
                let completion = prior
                    .completion
                    .as_ref()
                    .ok_or(NativeBudgetErrorV1::Invalid(
                        "TASK_OPERATION_NOT_COMPLETED_V2",
                    ))?;
                require(
                    prior.delivery.is_none()
                        && same_contract(&prior.reserved, &observed.contract)
                        && observed.receipt_operation != [0; 32]
                        && observed.contract.output == Some(completion.output)
                        && observed.contract.receipt_height == Some(observed.receipt_anchor.height)
                        && observed.receipt_anchor.height <= observed.contract.anchor.height
                        && observed.receipt_anchor.generation
                            <= observed.contract.anchor.generation,
                    "TASK_OPERATION_DELIVERY_V2",
                )?;
                self.claims.get_mut(claim).unwrap().delivery = Some(observed.clone());
            }
            Event::Payment { claim, observed } => {
                self.observe(observed.anchor, cfg)?;
                let prior = self.claim(*claim)?;
                let completion = prior
                    .completion
                    .as_ref()
                    .ok_or(NativeBudgetErrorV1::Invalid(
                        "TASK_OPERATION_NOT_COMPLETED_V2",
                    ))?;
                require(
                    prior.payment.is_none()
                        && prior.delivery.is_some()
                        && prior.costs.as_ref().is_some_and(|record| {
                            matches!(
                                record.outcome,
                                NativeResourceOutcomeV1::Positive | NativeResourceOutcomeV1::NoGain
                            )
                        })
                        && observed.source == NativeFundingSourceV1::Task(prior.binding.task)
                        && observed.subject == completion.output
                        && observed.beneficiary == prior.binding.beneficiary
                        && observed.operation != [0; 32]
                        && observed.gross_escrow_debit == prior.reserved.amount
                        && observed.beneficiary_credit == prior.reserved.amount,
                    "TASK_OPERATION_PAYMENT_V2",
                )?;
                self.claims.get_mut(claim).unwrap().payment = Some(observed.clone());
            }
        }
        Ok(())
    }
}

fn check_schema(connection: &Connection) -> Result<()> {
    let app: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    require(
        app == APPLICATION_ID && version == 2,
        "TASK_OPERATION_STORE_V2",
    )?;
    for (name, expected) in [
        ("task_operation_meta_v2", META_SQL),
        ("task_operation_events_v2", EVENT_SQL),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        require(
            actual.as_deref() == Some(expected),
            "TASK_OPERATION_SCHEMA_V2",
        )?;
    }
    let objects: u64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'",
        [],
        |row| row.get(0),
    )?;
    require(objects == 2, "TASK_OPERATION_SCHEMA_V2")
}

fn load(
    connection: &Connection,
    cfg: &NativeBudgetConfigV1,
) -> Result<(OperationState, u64, Hash)> {
    check_schema(connection)?;
    let (configuration, count, expected_root): (Option<Vec<u8>>, u64, Vec<u8>) = connection.query_row(
        "SELECT CASE WHEN length(configuration)<=16384 THEN configuration ELSE NULL END,sequence,root FROM task_operation_meta_v2 WHERE singleton=1", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    require(
        configuration == Some(encoded(cfg)?),
        "TASK_OPERATION_CONFIGURATION_V2",
    )?;
    require(
        count <= u64::from(cfg.max_records) * 6,
        "TASK_OPERATION_JOURNAL_LIMIT_V2",
    )?;
    let mut state = OperationState::default();
    let mut sequence = 0;
    let mut previous = [0; 32];
    let mut query = connection.prepare("SELECT sequence,CASE WHEN length(payload)<=16384 THEN payload ELSE NULL END,root FROM task_operation_events_v2 ORDER BY sequence")?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        sequence += 1;
        require(
            sequence <= count && row.get::<_, u64>(0)? == sequence,
            "TASK_OPERATION_SEQUENCE_V2",
        )?;
        let payload: Option<Vec<u8>> = row.get(1)?;
        let payload = payload.ok_or(NativeBudgetErrorV1::Invalid(
            "TASK_OPERATION_EVENT_LIMIT_V2",
        ))?;
        let root = digest(b"event", &[&previous, &sequence.to_le_bytes(), &payload]);
        require(row.get::<_, Vec<u8>>(2)? == root, "TASK_OPERATION_ROOT_V2")?;
        let event: Event = borsh::from_slice(&payload)?;
        require(encoded(&event)? == payload, "TASK_OPERATION_ENCODING_V2")?;
        state.apply(&event, cfg)?;
        previous = root;
    }
    require(
        sequence == count && expected_root == previous,
        "TASK_OPERATION_HEAD_V2",
    )?;
    Ok((state, sequence, previous))
}

fn checked_snapshot(
    connection: &Connection,
    cfg: &NativeBudgetConfigV1,
    expected: Option<(u64, Hash)>,
) -> Result<(OperationState, u64, Hash)> {
    let read = connection.unchecked_transaction()?;
    let result = load(&read, cfg)?;
    if let Some((sequence, root)) = expected {
        require(
            sequence <= result.1,
            "TASK_OPERATION_CHECKPOINT_ROLLBACK_V2",
        )?;
        if sequence == 0 {
            require(root == [0; 32], "TASK_OPERATION_CHECKPOINT_V2")?;
        } else {
            let recorded: Vec<u8> = read.query_row(
                "SELECT root FROM task_operation_events_v2 WHERE sequence=?1",
                [sequence],
                |row| row.get(0),
            )?;
            require(recorded == root, "TASK_OPERATION_CHECKPOINT_V2")?;
        }
    }
    read.commit()?;
    Ok(result)
}

enum Update<T> {
    Replay(T),
    Append(Box<Event>, T),
}

pub struct NativeTaskOperationStoreV2 {
    connection: Connection,
    configuration: NativeBudgetConfigV1,
}
impl NativeTaskOperationStoreV2 {
    pub fn open(path: &Path, configuration: NativeBudgetConfigV1) -> Result<Self> {
        require(
            (1..=65_536).contains(&configuration.max_records)
                && ![
                    configuration.network,
                    configuration.parameters,
                    configuration.genesis,
                ]
                .contains(&[0; 32]),
            "TASK_OPERATION_CONFIGURATION_V2",
        )?;
        if let Ok(metadata) = path.symlink_metadata() {
            require(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "TASK_OPERATION_FILE_V2",
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
        let app: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if app == 0 && version == 0 {
            let count: u64 = connection.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'",
                [],
                |row| row.get(0),
            )?;
            require(count == 0, "TASK_OPERATION_STORE_V2")?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(META_SQL)?;
            transaction.execute_batch(EVENT_SQL)?;
            require(
                transaction.execute(
                    "INSERT INTO task_operation_meta_v2 VALUES(1,?1,0,?2)",
                    params![encoded(&configuration)?, [0_u8; 32].as_slice()],
                )? == 1,
                "TASK_OPERATION_WRITE_V2",
            )?;
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", 2)?;
            let (state, sequence, root) = load(&transaction, &configuration)?;
            require(
                state == OperationState::default() && sequence == 0 && root == [0; 32],
                "TASK_OPERATION_READBACK_V2",
            )?;
            transaction.commit()?;
        }
        check_schema(&connection)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        checked_snapshot(&connection, &configuration, None)?;
        Ok(Self {
            connection,
            configuration,
        })
    }

    fn update<T>(&mut self, make: impl FnOnce(&OperationState) -> Result<Update<T>>) -> Result<T> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (mut state, mut sequence, mut root) = load(&transaction, &self.configuration)?;
        let value = match make(&state)? {
            Update::Replay(value) => value,
            Update::Append(event, value) => {
                state.apply(&event, &self.configuration)?;
                let payload = encoded(event.as_ref())?;
                require(
                    payload.len() <= EVENT_LIMIT,
                    "TASK_OPERATION_EVENT_LIMIT_V2",
                )?;
                let previous = root;
                sequence += 1;
                require(
                    sequence <= u64::from(self.configuration.max_records) * 6,
                    "TASK_OPERATION_JOURNAL_LIMIT_V2",
                )?;
                root = digest(b"event", &[&previous, &sequence.to_le_bytes(), &payload]);
                require(
                    transaction.execute(
                        "INSERT INTO task_operation_events_v2 VALUES(?1,?2,?3)",
                        params![sequence, payload, root.as_slice()],
                    )? == 1,
                    "TASK_OPERATION_WRITE_V2",
                )?;
                require(transaction.execute("UPDATE task_operation_meta_v2 SET sequence=?1,root=?2 WHERE singleton=1 AND sequence=?3 AND root=?4", params![sequence, root.as_slice(), sequence - 1, previous.as_slice()])? == 1, "TASK_OPERATION_WRITE_V2")?;
                value
            }
        };
        let observed = load(&transaction, &self.configuration)?;
        require(
            observed == (state, sequence, root),
            "TASK_OPERATION_READBACK_V2",
        )?;
        transaction.commit()?;
        // A concurrent valid append may follow this prefix. A failed readback
        // returns uncertainty, never an extra execution grant on the next call.
        checked_snapshot(
            &self.connection,
            &self.configuration,
            Some((sequence, root)),
        )?;
        Ok(value)
    }

    pub fn reserve(
        &mut self,
        owner: &mut impl NativeTaskOperationOwnerV2,
        binding: NativeTaskOperationBindingV2,
    ) -> Result<NativeBudgetReplayV1> {
        let maximum = self.configuration.max_records as usize;
        self.update(|state| {
            binding.validate()?;
            if let Some(prior) = state.claims.get(&binding.claim) {
                require(prior.binding == binding, "TASK_OPERATION_REPLAY_V2")?;
                return Ok(Update::Replay(if prior.completion.is_some() {
                    NativeBudgetReplayV1::Done
                } else {
                    NativeBudgetReplayV1::Pending
                }));
            }
            require(
                state.claims.len() < maximum
                    && !state.tasks.contains_key(&binding.task)
                    && !state.operations.contains_key(&binding.operation),
                "TASK_OPERATION_REPLAY_V2",
            )?;
            let observed = owner.reserve_task_operation_v2(&binding)?;
            Ok(Update::Append(
                Box::new(Event::Reserve { binding, observed }),
                NativeBudgetReplayV1::New,
            ))
        })
    }

    pub fn begin(
        &mut self,
        owner: &mut impl NativeTaskOperationOwnerV2,
        claim: Hash,
    ) -> Result<NativeBudgetReplayV1> {
        self.update(|state| {
            let prior = state.claim(claim)?;
            if prior.begun.is_some() {
                return Ok(Update::Replay(if prior.completion.is_some() {
                    NativeBudgetReplayV1::Done
                } else {
                    NativeBudgetReplayV1::Pending
                }));
            }
            let observed = owner.begin_task_operation_v2(&prior.binding)?;
            let replay = if observed.new_execution {
                NativeBudgetReplayV1::New
            } else {
                NativeBudgetReplayV1::Pending
            };
            Ok(Update::Append(
                Box::new(Event::Begin { claim, observed }),
                replay,
            ))
        })
    }

    pub fn record_costs(
        &mut self,
        claim: Hash,
        outcome: NativeResourceOutcomeV1,
        consumed: NativeBudgetResourcesV1,
        costs: NativeTaskCostBreakdownV2,
    ) -> Result<NativeBudgetReplayV1> {
        self.update(|state| {
            let record = NativeTaskCostRecordV2 {
                outcome,
                consumed,
                costs,
            };
            if let Some(prior) = &state.claim(claim)?.costs {
                require(prior == &record, "TASK_OPERATION_COST_REPLAY_V2")?;
                return Ok(Update::Replay(NativeBudgetReplayV1::Done));
            }
            Ok(Update::Append(
                Box::new(Event::Costs { claim, record }),
                NativeBudgetReplayV1::New,
            ))
        })
    }

    pub fn complete(
        &mut self,
        claim: Hash,
        operation: Hash,
        output: Hash,
        target_receipt: Hash,
    ) -> Result<NativeBudgetReplayV1> {
        self.update(|state| {
            let completion = NativeTaskCompletionV2 {
                operation,
                output,
                target_receipt,
            };
            if let Some(prior) = &state.claim(claim)?.completion {
                require(prior == &completion, "TASK_OPERATION_COMPLETION_REPLAY_V2")?;
                return Ok(Update::Replay(NativeBudgetReplayV1::Done));
            }
            Ok(Update::Append(
                Box::new(Event::Complete { claim, completion }),
                NativeBudgetReplayV1::New,
            ))
        })
    }

    pub fn bind_delivery(
        &mut self,
        owner: &mut impl NativeTaskOperationOwnerV2,
        claim: Hash,
    ) -> Result<NativeBudgetReplayV1> {
        self.update(|state| {
            let prior = state.claim(claim)?;
            if prior.delivery.is_some() {
                return Ok(Update::Replay(NativeBudgetReplayV1::Done));
            }
            require(
                prior.completion.is_some(),
                "TASK_OPERATION_NOT_COMPLETED_V2",
            )?;
            let observed = owner.observe_task_delivery_v2(&prior.binding)?;
            Ok(Update::Append(
                Box::new(Event::Delivery { claim, observed }),
                NativeBudgetReplayV1::New,
            ))
        })
    }

    pub fn record_native_payment(
        &mut self,
        owner: &mut impl NativeTaskOperationOwnerV2,
        claim: Hash,
        operation: Hash,
    ) -> Result<NativeBudgetReplayV1> {
        self.update(|state| {
            let prior = state.claim(claim)?;
            if let Some(payment) = &prior.payment {
                require(
                    payment.operation == operation,
                    "TASK_OPERATION_PAYMENT_REPLAY_V2",
                )?;
                return Ok(Update::Replay(NativeBudgetReplayV1::Done));
            }
            require(
                prior.delivery.is_some(),
                "TASK_OPERATION_DELIVERY_REQUIRED_V2",
            )?;
            let query = payment_query(prior, operation)?;
            let observed = owner.observe_payment(&query)?;
            require(observed.operation == operation, "TASK_OPERATION_PAYMENT_V2")?;
            Ok(Update::Append(
                Box::new(Event::Payment { claim, observed }),
                NativeBudgetReplayV1::New,
            ))
        })
    }

    /// Read the original payment against the complete journal's persisted anchor
    /// floor. This is an observation, not another payment or an execution grant;
    /// it never rewrites historical payment facts or advances the durable floor.
    pub fn reobserve_native_payment(
        &self,
        owner: &mut impl NativeTaskOperationOwnerV2,
        claim: Hash,
    ) -> Result<NativePaymentReadbackV1> {
        let (mut state, sequence, root) =
            checked_snapshot(&self.connection, &self.configuration, None)?;
        let prior = state.claim(claim)?.clone();
        let historical = prior.payment.as_ref().ok_or(NativeBudgetErrorV1::Invalid(
            "TASK_OPERATION_PAYMENT_REQUIRED_V2",
        ))?;
        let observed = owner.observe_payment(&payment_query(&prior, historical.operation)?)?;
        // Other operations may already have retained a newer native anchor.
        // The existing journal rule also forbids different roots/blocks at one
        // generation. Apply it only to this disposable, consistent snapshot.
        state.observe(observed.anchor, &self.configuration)?;
        require(
            observed.source == historical.source
                && observed.subject == historical.subject
                && observed.beneficiary == historical.beneficiary
                && observed.operation == historical.operation
                && observed.gross_escrow_debit == historical.gross_escrow_debit
                && observed.beneficiary_credit == historical.beneficiary_credit,
            "TASK_OPERATION_PAYMENT_V2",
        )?;
        // A callback may overlap a writer using another SQLite connection.
        // Leave the original read transaction before checking again so a WAL
        // commit cannot remain hidden by that snapshot. Any changed head makes
        // this bounded observation stale, even when its old prefix is valid.
        let (_, current_sequence, current_root) = checked_snapshot(
            &self.connection,
            &self.configuration,
            Some((sequence, root)),
        )?;
        require(
            (current_sequence, current_root) == (sequence, root),
            "TASK_OPERATION_PAYMENT_JOURNAL_CHANGED_V2",
        )?;
        Ok(NativePaymentReadbackV1 {
            historical: historical.clone(),
            observed,
        })
    }

    pub fn snapshot(&self, claim: Hash) -> Result<NativeTaskOperationSnapshotV2> {
        self.snapshot_after_checkpoint(claim, None)
            .map(|(snapshot, _)| snapshot)
    }

    /// Read one verified snapshot and its current checkpoint while enforcing an
    /// independently retained prefix. Never combine a claim from one SQLite
    /// snapshot with a checkpoint from a later read transaction.
    pub fn snapshot_after_checkpoint(
        &self,
        claim: Hash,
        expected: Option<&NativeTaskOperationCheckpointV2>,
    ) -> Result<(
        NativeTaskOperationSnapshotV2,
        NativeTaskOperationCheckpointV2,
    )> {
        if let Some(expected) = expected {
            require(
                expected.configuration == self.configuration,
                "TASK_OPERATION_CHECKPOINT_V2",
            )?;
        }
        let (state, sequence, root) = checked_snapshot(
            &self.connection,
            &self.configuration,
            expected.map(|checkpoint| (checkpoint.sequence, checkpoint.root)),
        )?;
        Ok((
            state.claim(claim)?.clone(),
            NativeTaskOperationCheckpointV2 {
                configuration: self.configuration.clone(),
                sequence,
                root,
            },
        ))
    }

    pub fn checkpoint(&self) -> Result<NativeTaskOperationCheckpointV2> {
        let (_, sequence, root) = checked_snapshot(&self.connection, &self.configuration, None)?;
        Ok(NativeTaskOperationCheckpointV2 {
            configuration: self.configuration.clone(),
            sequence,
            root,
        })
    }

    pub fn verify_checkpoint(
        &self,
        checkpoint: &NativeTaskOperationCheckpointV2,
    ) -> Result<NativeTaskOperationCheckpointV2> {
        require(
            checkpoint.configuration == self.configuration,
            "TASK_OPERATION_CHECKPOINT_V2",
        )?;
        let (_, sequence, root) = checked_snapshot(
            &self.connection,
            &self.configuration,
            Some((checkpoint.sequence, checkpoint.root)),
        )?;
        Ok(NativeTaskOperationCheckpointV2 {
            configuration: self.configuration.clone(),
            sequence,
            root,
        })
    }

    pub fn report(&self) -> Result<Value> {
        let (state, sequence, root) =
            checked_snapshot(&self.connection, &self.configuration, None)?;
        let claims: Vec<_> = state.claims.values().map(|claim| json!({
            "claim":hex_string(&claim.binding.claim),
            "task":hex_string(&claim.binding.task),
            "contract_digest":hex_string(&claim.binding.contract_digest),
            "operation":hex_string(&claim.binding.operation),
            "target_scope":hex_string(&claim.binding.target_scope),
            "original_native_escrow":claim.reserved.amount,
            "resource_cap":claim.binding.resource_cap.vector(),
            "resource_charge":claim.costs.as_ref().map_or_else(||claim.binding.resource_cap.vector(),|costs|costs.consumed.vector()),
            "begun":claim.begun.is_some(),
            "completed":claim.completion.is_some(),
            "actual_output":claim.completion.as_ref().map(|completion|hex_string(&completion.output)),
            "native_delivery_bound":claim.delivery.is_some(),
            "historically_observed_native_payment":claim.payment.as_ref().map(|payment|payment.gross_escrow_debit),
            "declared_costs":claim.costs.as_ref().map(|record|json!({
                "outcome":format!("{:?}",record.outcome),
                "training_units":record.costs.training_units,
                "evaluation_units":record.costs.evaluation_units,
                "storage_units":record.costs.storage_units,
                "serving_units":record.costs.serving_units,
                "unit":hex_string(&record.costs.unit),
                "measurement_receipt":hex_string(&record.costs.measurement_receipt)
            })),
            "learning_improvement_bonus":false
        })).collect();
        Ok(json!({
            "schema":NAMESPACE,"sequence":sequence,"journal_root":hex_string(&root),"claims":claims,
            "authorizes_native_payment":false,"current_branch_payment_finality":false,
            "physical_costs_verified_by_this_journal":false,"independent_actors_attested":false,
            "production_activation":false
        }))
    }
}

fn payment_query(
    prior: &NativeTaskOperationSnapshotV2,
    operation: Hash,
) -> Result<NativePaymentQueryV1> {
    let completion = prior
        .completion
        .as_ref()
        .ok_or(NativeBudgetErrorV1::Invalid(
            "TASK_OPERATION_NOT_COMPLETED_V2",
        ))?;
    require(operation != [0; 32], "TASK_OPERATION_PAYMENT_V2")?;
    Ok(NativePaymentQueryV1 {
        source: NativeFundingSourceV1::Task(prior.binding.task),
        subject: completion.output,
        beneficiary: prior.binding.beneficiary,
        operation,
        maximum_gross_units: prior.reserved.amount,
    })
}

#[cfg(test)]
mod tests;
