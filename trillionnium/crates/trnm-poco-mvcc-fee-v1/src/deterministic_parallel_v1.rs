//! Candidate-only bounded parallel execution and canonical commit model.
//!
//! Workers speculate against one immutable parent snapshot. The commit loop is
//! always transaction-index ordered and re-executes a transaction against the
//! committed prefix whenever any declared read version changed. This module
//! neither writes a global JMT nor moves settlement assets.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
    thread,
};

use sha2::{Digest, Sha256};

pub const MAX_PARALLEL_WORKERS_V1: usize = 64;
pub const PARALLEL_EXECUTION_ECONOMIC_AUTHORITY_V1: bool = false;
pub const PARALLEL_EXECUTION_SETTLEMENT_AUTHORITY_V1: bool = false;
pub const PARALLEL_EXECUTION_GLOBAL_JMT_AUTHORITY_V1: bool = false;

pub type ParallelObjectIdV1 = [u8; 32];
pub type ParallelTransactionIdV1 = [u8; 32];
pub type ParallelAccountIdV1 = [u8; 32];

const STATE_ROOT_DOMAIN_V1: &[u8] = b"trnm.g2d.parallel.state-root.v1\0";
const RECEIPT_ROOT_DOMAIN_V1: &[u8] = b"trnm.g2d.parallel.receipt-root.v1\0";
const WRITE_SET_ROOT_DOMAIN_V1: &[u8] = b"trnm.g2d.parallel.write-set-root.v1\0";
const FEE_ROOT_DOMAIN_V1: &[u8] = b"trnm.g2d.parallel.fee-root.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParallelExecutionErrorV1 {
    EmptyBlock,
    InvalidWorkerCount,
    NonCanonicalTransactionIndex,
    ZeroIdentifier,
    DuplicateTransactionId,
    NonCanonicalAccessSet,
    UndeclaredRead,
    UndeclaredWrite,
    DuplicateInstructionWrite,
    MissingObject,
    ArithmeticOverflow,
    ObjectVersionOverflow,
    FeeLimitExceeded,
    WorkerPanicked,
    MissingWorkerResult,
}

impl fmt::Display for ParallelExecutionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyBlock => "parallel execution block is empty",
            Self::InvalidWorkerCount => "parallel worker count is outside the bound",
            Self::NonCanonicalTransactionIndex => "transaction indices are not canonical",
            Self::ZeroIdentifier => "an execution identifier is zero",
            Self::DuplicateTransactionId => "transaction identifier is duplicated",
            Self::NonCanonicalAccessSet => "declared access set is not sorted and unique",
            Self::UndeclaredRead => "instruction performs an undeclared read",
            Self::UndeclaredWrite => "instruction performs an undeclared write",
            Self::DuplicateInstructionWrite => "multiple instructions write the same object",
            Self::MissingObject => "declared object is absent from the parent state",
            Self::ArithmeticOverflow => "checked execution arithmetic overflowed",
            Self::ObjectVersionOverflow => "object version overflowed",
            Self::FeeLimitExceeded => "computed fee exceeds the transaction maximum",
            Self::WorkerPanicked => "parallel speculation worker panicked",
            Self::MissingWorkerResult => "parallel speculation omitted a transaction result",
        })
    }
}

impl std::error::Error for ParallelExecutionErrorV1 {}

pub type ParallelExecutionResultV1<T> = Result<T, ParallelExecutionErrorV1>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParallelVersionedValueV1 {
    pub version: u64,
    pub value: i128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParallelStateV1 {
    objects: BTreeMap<ParallelObjectIdV1, ParallelVersionedValueV1>,
}

impl ParallelStateV1 {
    pub fn from_objects(
        objects: Vec<(ParallelObjectIdV1, u64, i128)>,
    ) -> ParallelExecutionResultV1<Self> {
        let mut state = BTreeMap::new();
        for (object_id, version, value) in objects {
            require_nonzero(&object_id)?;
            if state
                .insert(object_id, ParallelVersionedValueV1 { version, value })
                .is_some()
            {
                return Err(ParallelExecutionErrorV1::NonCanonicalAccessSet);
            }
        }
        Ok(Self { objects: state })
    }

    pub fn get(&self, object_id: &ParallelObjectIdV1) -> Option<ParallelVersionedValueV1> {
        self.objects.get(object_id).copied()
    }

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParallelInstructionV1 {
    Set {
        target: ParallelObjectIdV1,
        value: i128,
    },
    AddFromRead {
        target: ParallelObjectIdV1,
        source: ParallelObjectIdV1,
        delta: i128,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParallelResourceVectorV1 {
    pub compute_units: u64,
    pub state_read_units: u64,
    pub state_write_units: u64,
    pub artifact_units: u64,
}

impl ParallelResourceVectorV1 {
    fn exceeds(self, limit: Self) -> bool {
        self.compute_units > limit.compute_units
            || self.state_read_units > limit.state_read_units
            || self.state_write_units > limit.state_write_units
            || self.artifact_units > limit.artifact_units
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParallelFeeScheduleV1 {
    pub base_fee: u128,
    pub compute_unit_price: u128,
    pub state_read_unit_price: u128,
    pub state_write_unit_price: u128,
    pub artifact_unit_price: u128,
}

impl ParallelFeeScheduleV1 {
    fn fee_for(self, usage: ParallelResourceVectorV1) -> ParallelExecutionResultV1<u128> {
        let mut total = self.base_fee;
        total = checked_fee_component(total, usage.compute_units, self.compute_unit_price)?;
        total = checked_fee_component(total, usage.state_read_units, self.state_read_unit_price)?;
        total = checked_fee_component(total, usage.state_write_units, self.state_write_unit_price)?;
        checked_fee_component(total, usage.artifact_units, self.artifact_unit_price)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParallelTransactionV1 {
    pub index: u32,
    pub transaction_id: ParallelTransactionIdV1,
    pub payer: ParallelAccountIdV1,
    pub declared_reads: Vec<ParallelObjectIdV1>,
    pub declared_writes: Vec<ParallelObjectIdV1>,
    pub instructions: Vec<ParallelInstructionV1>,
    pub base_compute_units: u64,
    pub artifact_units: u64,
    pub resource_limit: ParallelResourceVectorV1,
    pub max_fee: u128,
    pub force_revert: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParallelReceiptStatusV1 {
    Success,
    Reverted,
    OutOfResource,
}

impl ParallelReceiptStatusV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Reverted => 1,
            Self::OutOfResource => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParallelExecutionReceiptV1 {
    pub index: u32,
    pub transaction_id: ParallelTransactionIdV1,
    pub payer: ParallelAccountIdV1,
    pub status: ParallelReceiptStatusV1,
    pub retry_count: u32,
    pub usage: ParallelResourceVectorV1,
    pub fee_charged: u128,
    pub write_set_root: [u8; 32],
    pub economic_authority: bool,
    pub settlement_authority: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParallelFeeDeltaV1 {
    pub payer: ParallelAccountIdV1,
    pub payer_debit: u128,
    pub fee_sink_credit: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParallelBlockResultV1 {
    pub state: ParallelStateV1,
    pub receipts: Vec<ParallelExecutionReceiptV1>,
    pub fee_deltas: Vec<ParallelFeeDeltaV1>,
    pub state_root: [u8; 32],
    pub receipt_root: [u8; 32],
    pub fee_root: [u8; 32],
    pub worker_count: usize,
    pub economic_authority: bool,
    pub settlement_authority: bool,
    pub global_jmt_authority: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SpeculatedTransactionV1 {
    transaction: ParallelTransactionV1,
    read_versions: BTreeMap<ParallelObjectIdV1, u64>,
    writes: BTreeMap<ParallelObjectIdV1, i128>,
    status: ParallelReceiptStatusV1,
    usage: ParallelResourceVectorV1,
    fee_charged: u128,
}

pub fn execute_parallel_block_v1(
    parent: &ParallelStateV1,
    transactions: &[ParallelTransactionV1],
    worker_count: usize,
    fee_schedule: ParallelFeeScheduleV1,
) -> ParallelExecutionResultV1<ParallelBlockResultV1> {
    validate_block(transactions, worker_count)?;
    let speculative = speculate_parallel(parent, transactions, worker_count, fee_schedule)?;
    let mut state = parent.clone();
    let mut receipts = Vec::with_capacity(speculative.len());
    let mut fees = BTreeMap::<ParallelAccountIdV1, u128>::new();

    for original in speculative {
        let conflicted = original
            .read_versions
            .iter()
            .any(|(id, version)| state.get(id).map(|value| value.version) != Some(*version));
        let (selected, retry_count) = if conflicted {
            (
                execute_transaction(&state, &original.transaction, fee_schedule)?,
                1,
            )
        } else {
            (original, 0)
        };

        if selected.status == ParallelReceiptStatusV1::Success {
            apply_writes(&mut state, &selected.writes)?;
        }
        let write_set_root = write_set_root(&selected.writes);
        receipts.push(ParallelExecutionReceiptV1 {
            index: selected.transaction.index,
            transaction_id: selected.transaction.transaction_id,
            payer: selected.transaction.payer,
            status: selected.status,
            retry_count,
            usage: selected.usage,
            fee_charged: selected.fee_charged,
            write_set_root,
            economic_authority: false,
            settlement_authority: false,
        });
        let accumulated = fees.entry(selected.transaction.payer).or_default();
        *accumulated = accumulated
            .checked_add(selected.fee_charged)
            .ok_or(ParallelExecutionErrorV1::ArithmeticOverflow)?;
    }

    let fee_deltas = fees
        .into_iter()
        .map(|(payer, amount)| ParallelFeeDeltaV1 {
            payer,
            payer_debit: amount,
            fee_sink_credit: amount,
        })
        .collect::<Vec<_>>();
    let state_root = state_root(&state);
    let receipt_root = receipt_root(&receipts);
    let fee_root = fee_root(&fee_deltas);
    Ok(ParallelBlockResultV1 {
        state,
        receipts,
        fee_deltas,
        state_root,
        receipt_root,
        fee_root,
        worker_count,
        economic_authority: false,
        settlement_authority: false,
        global_jmt_authority: false,
    })
}

fn validate_block(
    transactions: &[ParallelTransactionV1],
    worker_count: usize,
) -> ParallelExecutionResultV1<()> {
    if transactions.is_empty() {
        return Err(ParallelExecutionErrorV1::EmptyBlock);
    }
    if worker_count == 0 || worker_count > MAX_PARALLEL_WORKERS_V1 {
        return Err(ParallelExecutionErrorV1::InvalidWorkerCount);
    }
    let mut transaction_ids = BTreeSet::new();
    for (expected_index, transaction) in transactions.iter().enumerate() {
        if transaction.index
            != u32::try_from(expected_index)
                .map_err(|_| ParallelExecutionErrorV1::NonCanonicalTransactionIndex)?
        {
            return Err(ParallelExecutionErrorV1::NonCanonicalTransactionIndex);
        }
        require_nonzero(&transaction.transaction_id)?;
        require_nonzero(&transaction.payer)?;
        if !transaction_ids.insert(transaction.transaction_id) {
            return Err(ParallelExecutionErrorV1::DuplicateTransactionId);
        }
        validate_transaction(transaction)?;
    }
    Ok(())
}

fn validate_transaction(transaction: &ParallelTransactionV1) -> ParallelExecutionResultV1<()> {
    validate_access_set(&transaction.declared_reads)?;
    validate_access_set(&transaction.declared_writes)?;
    let declared_reads = transaction
        .declared_reads
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let declared_writes = transaction
        .declared_writes
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut actual_reads = BTreeSet::new();
    let mut actual_writes = BTreeSet::new();
    for instruction in &transaction.instructions {
        let (target, source) = match instruction {
            ParallelInstructionV1::Set { target, .. } => (*target, None),
            ParallelInstructionV1::AddFromRead { target, source, .. } => (*target, Some(*source)),
        };
        require_nonzero(&target)?;
        if !actual_writes.insert(target) {
            return Err(ParallelExecutionErrorV1::DuplicateInstructionWrite);
        }
        if let Some(source) = source {
            require_nonzero(&source)?;
            actual_reads.insert(source);
        }
    }
    if actual_reads != declared_reads {
        return Err(ParallelExecutionErrorV1::UndeclaredRead);
    }
    if actual_writes != declared_writes {
        return Err(ParallelExecutionErrorV1::UndeclaredWrite);
    }
    Ok(())
}

fn validate_access_set(values: &[ParallelObjectIdV1]) -> ParallelExecutionResultV1<()> {
    let mut previous = None;
    for value in values {
        require_nonzero(value)?;
        if previous.is_some_and(|item| item >= *value) {
            return Err(ParallelExecutionErrorV1::NonCanonicalAccessSet);
        }
        previous = Some(*value);
    }
    Ok(())
}

fn speculate_parallel(
    parent: &ParallelStateV1,
    transactions: &[ParallelTransactionV1],
    worker_count: usize,
    fee_schedule: ParallelFeeScheduleV1,
) -> ParallelExecutionResultV1<Vec<SpeculatedTransactionV1>> {
    let parent = Arc::new(parent.clone());
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for worker in 0..worker_count {
            let parent = Arc::clone(&parent);
            handles.push(scope.spawn(move || {
                let mut rows = Vec::new();
                let mut position = worker;
                while position < transactions.len() {
                    rows.push((
                        position,
                        execute_transaction(parent.as_ref(), &transactions[position], fee_schedule),
                    ));
                    position += worker_count;
                }
                rows
            }));
        }
        let mut slots = (0..transactions.len())
            .map(|_| None)
            .collect::<Vec<Option<SpeculatedTransactionV1>>>();
        for handle in handles {
            let rows = handle
                .join()
                .map_err(|_| ParallelExecutionErrorV1::WorkerPanicked)?;
            for (position, row) in rows {
                slots[position] = Some(row?);
            }
        }
        slots
            .into_iter()
            .map(|row| row.ok_or(ParallelExecutionErrorV1::MissingWorkerResult))
            .collect()
    })
}

fn execute_transaction(
    state: &ParallelStateV1,
    transaction: &ParallelTransactionV1,
    fee_schedule: ParallelFeeScheduleV1,
) -> ParallelExecutionResultV1<SpeculatedTransactionV1> {
    let instruction_units = u64::try_from(transaction.instructions.len())
        .map_err(|_| ParallelExecutionErrorV1::ArithmeticOverflow)?;
    let usage = ParallelResourceVectorV1 {
        compute_units: transaction
            .base_compute_units
            .checked_add(instruction_units)
            .ok_or(ParallelExecutionErrorV1::ArithmeticOverflow)?,
        state_read_units: u64::try_from(transaction.declared_reads.len())
            .map_err(|_| ParallelExecutionErrorV1::ArithmeticOverflow)?,
        state_write_units: u64::try_from(transaction.declared_writes.len())
            .map_err(|_| ParallelExecutionErrorV1::ArithmeticOverflow)?,
        artifact_units: transaction.artifact_units,
    };
    let fee_charged = fee_schedule.fee_for(usage)?;
    if fee_charged > transaction.max_fee {
        return Err(ParallelExecutionErrorV1::FeeLimitExceeded);
    }

    let mut read_versions = BTreeMap::new();
    for object_id in &transaction.declared_reads {
        let value = state
            .get(object_id)
            .ok_or(ParallelExecutionErrorV1::MissingObject)?;
        read_versions.insert(*object_id, value.version);
    }
    for object_id in &transaction.declared_writes {
        if state.get(object_id).is_none() {
            return Err(ParallelExecutionErrorV1::MissingObject);
        }
    }

    let status = if usage.exceeds(transaction.resource_limit) {
        ParallelReceiptStatusV1::OutOfResource
    } else if transaction.force_revert {
        ParallelReceiptStatusV1::Reverted
    } else {
        ParallelReceiptStatusV1::Success
    };
    let mut writes = BTreeMap::new();
    if status == ParallelReceiptStatusV1::Success {
        for instruction in &transaction.instructions {
            let (target, value) = match instruction {
                ParallelInstructionV1::Set { target, value } => (*target, *value),
                ParallelInstructionV1::AddFromRead {
                    target,
                    source,
                    delta,
                } => {
                    let source_value = state
                        .get(source)
                        .ok_or(ParallelExecutionErrorV1::MissingObject)?
                        .value;
                    (
                        *target,
                        source_value
                            .checked_add(*delta)
                            .ok_or(ParallelExecutionErrorV1::ArithmeticOverflow)?,
                    )
                }
            };
            writes.insert(target, value);
        }
    }
    Ok(SpeculatedTransactionV1 {
        transaction: transaction.clone(),
        read_versions,
        writes,
        status,
        usage,
        fee_charged,
    })
}

fn apply_writes(
    state: &mut ParallelStateV1,
    writes: &BTreeMap<ParallelObjectIdV1, i128>,
) -> ParallelExecutionResultV1<()> {
    for object_id in writes.keys() {
        let value = state
            .objects
            .get(object_id)
            .ok_or(ParallelExecutionErrorV1::MissingObject)?;
        value
            .version
            .checked_add(1)
            .ok_or(ParallelExecutionErrorV1::ObjectVersionOverflow)?;
    }
    for (object_id, next_value) in writes {
        let value = state
            .objects
            .get_mut(object_id)
            .ok_or(ParallelExecutionErrorV1::MissingObject)?;
        value.version += 1;
        value.value = *next_value;
    }
    Ok(())
}

fn checked_fee_component(
    current: u128,
    units: u64,
    price: u128,
) -> ParallelExecutionResultV1<u128> {
    let component = u128::from(units)
        .checked_mul(price)
        .ok_or(ParallelExecutionErrorV1::ArithmeticOverflow)?;
    current
        .checked_add(component)
        .ok_or(ParallelExecutionErrorV1::ArithmeticOverflow)
}

fn require_nonzero(value: &[u8; 32]) -> ParallelExecutionResultV1<()> {
    if *value == [0; 32] {
        return Err(ParallelExecutionErrorV1::ZeroIdentifier);
    }
    Ok(())
}

fn hash_frame(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(
        u64::try_from(value.len())
            .expect("hash frame length fits u64")
            .to_be_bytes(),
    );
    hasher.update(value);
}

fn state_root(state: &ParallelStateV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, STATE_ROOT_DOMAIN_V1);
    hash_frame(
        &mut hasher,
        &u64::try_from(state.len())
            .expect("state length fits u64")
            .to_be_bytes(),
    );
    for (object_id, value) in &state.objects {
        hash_frame(&mut hasher, object_id);
        hash_frame(&mut hasher, &value.version.to_be_bytes());
        hash_frame(&mut hasher, &value.value.to_be_bytes());
    }
    hasher.finalize().into()
}

fn write_set_root(writes: &BTreeMap<ParallelObjectIdV1, i128>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, WRITE_SET_ROOT_DOMAIN_V1);
    hash_frame(
        &mut hasher,
        &u64::try_from(writes.len())
            .expect("write length fits u64")
            .to_be_bytes(),
    );
    for (object_id, value) in writes {
        hash_frame(&mut hasher, object_id);
        hash_frame(&mut hasher, &value.to_be_bytes());
    }
    hasher.finalize().into()
}

fn receipt_root(receipts: &[ParallelExecutionReceiptV1]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, RECEIPT_ROOT_DOMAIN_V1);
    hash_frame(
        &mut hasher,
        &u64::try_from(receipts.len())
            .expect("receipt length fits u64")
            .to_be_bytes(),
    );
    for receipt in receipts {
        hash_frame(&mut hasher, &receipt.index.to_be_bytes());
        hash_frame(&mut hasher, &receipt.transaction_id);
        hash_frame(&mut hasher, &receipt.payer);
        hash_frame(&mut hasher, &[receipt.status.tag()]);
        hash_frame(&mut hasher, &receipt.retry_count.to_be_bytes());
        hash_frame(&mut hasher, &receipt.usage.compute_units.to_be_bytes());
        hash_frame(&mut hasher, &receipt.usage.state_read_units.to_be_bytes());
        hash_frame(&mut hasher, &receipt.usage.state_write_units.to_be_bytes());
        hash_frame(&mut hasher, &receipt.usage.artifact_units.to_be_bytes());
        hash_frame(&mut hasher, &receipt.fee_charged.to_be_bytes());
        hash_frame(&mut hasher, &receipt.write_set_root);
    }
    hasher.finalize().into()
}

fn fee_root(deltas: &[ParallelFeeDeltaV1]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, FEE_ROOT_DOMAIN_V1);
    hash_frame(
        &mut hasher,
        &u64::try_from(deltas.len())
            .expect("fee length fits u64")
            .to_be_bytes(),
    );
    for delta in deltas {
        hash_frame(&mut hasher, &delta.payer);
        hash_frame(&mut hasher, &delta.payer_debit.to_be_bytes());
        hash_frame(&mut hasher, &delta.fee_sink_credit.to_be_bytes());
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u8) -> [u8; 32] {
        let mut out = [0; 32];
        out[31] = value;
        out
    }

    fn schedule() -> ParallelFeeScheduleV1 {
        ParallelFeeScheduleV1 {
            base_fee: 1,
            compute_unit_price: 2,
            state_read_unit_price: 3,
            state_write_unit_price: 5,
            artifact_unit_price: 7,
        }
    }

    fn limit() -> ParallelResourceVectorV1 {
        ParallelResourceVectorV1 {
            compute_units: 100,
            state_read_units: 10,
            state_write_units: 10,
            artifact_units: 10,
        }
    }

    fn parent() -> ParallelStateV1 {
        ParallelStateV1::from_objects(vec![(id(1), 0, 10), (id(2), 0, 20), (id(3), 0, 0)])
            .expect("parent state")
    }

    fn transactions() -> Vec<ParallelTransactionV1> {
        vec![
            ParallelTransactionV1 {
                index: 0,
                transaction_id: id(11),
                payer: id(21),
                declared_reads: vec![id(1)],
                declared_writes: vec![id(3)],
                instructions: vec![ParallelInstructionV1::AddFromRead {
                    target: id(3),
                    source: id(1),
                    delta: 1,
                }],
                base_compute_units: 5,
                artifact_units: 1,
                resource_limit: limit(),
                max_fee: 10_000,
                force_revert: false,
            },
            ParallelTransactionV1 {
                index: 1,
                transaction_id: id(12),
                payer: id(22),
                declared_reads: vec![id(3)],
                declared_writes: vec![id(2)],
                instructions: vec![ParallelInstructionV1::AddFromRead {
                    target: id(2),
                    source: id(3),
                    delta: 2,
                }],
                base_compute_units: 5,
                artifact_units: 1,
                resource_limit: limit(),
                max_fee: 10_000,
                force_revert: false,
            },
        ]
    }

    #[test]
    fn worker_count_does_not_change_roots_or_receipts() {
        let baseline = execute_parallel_block_v1(&parent(), &transactions(), 1, schedule())
            .expect("one worker");
        assert_eq!(baseline.state.get(&id(3)).expect("z").value, 11);
        assert_eq!(baseline.state.get(&id(2)).expect("y").value, 13);
        assert_eq!(baseline.receipts[1].retry_count, 1);
        for workers in [2, 4, 8] {
            let candidate =
                execute_parallel_block_v1(&parent(), &transactions(), workers, schedule())
                    .expect("parallel execution");
            assert_eq!(candidate.state, baseline.state);
            assert_eq!(candidate.receipts, baseline.receipts);
            assert_eq!(candidate.fee_deltas, baseline.fee_deltas);
            assert_eq!(candidate.state_root, baseline.state_root);
            assert_eq!(candidate.receipt_root, baseline.receipt_root);
            assert_eq!(candidate.fee_root, baseline.fee_root);
        }
        assert!(!baseline.economic_authority);
        assert!(!baseline.settlement_authority);
        assert!(!baseline.global_jmt_authority);
    }

    #[test]
    fn reverted_and_out_of_resource_never_write() {
        let mut reverted = transactions()[0].clone();
        reverted.force_revert = true;
        let result = execute_parallel_block_v1(&parent(), &[reverted], 2, schedule())
            .expect("reverted execution");
        assert_eq!(result.receipts[0].status, ParallelReceiptStatusV1::Reverted);
        assert_eq!(result.state, parent());

        let mut exhausted = transactions()[0].clone();
        exhausted.resource_limit.compute_units = 0;
        let result = execute_parallel_block_v1(&parent(), &[exhausted], 2, schedule())
            .expect("out of resource execution");
        assert_eq!(
            result.receipts[0].status,
            ParallelReceiptStatusV1::OutOfResource
        );
        assert_eq!(result.state, parent());
    }

    #[test]
    fn undeclared_access_and_noncanonical_sets_fail_closed() {
        let mut transaction = transactions()[0].clone();
        transaction.declared_reads.clear();
        assert_eq!(
            execute_parallel_block_v1(&parent(), &[transaction], 1, schedule()),
            Err(ParallelExecutionErrorV1::UndeclaredRead)
        );

        let mut transaction = transactions()[0].clone();
        transaction.declared_reads = vec![id(1), id(1)];
        assert_eq!(
            execute_parallel_block_v1(&parent(), &[transaction], 1, schedule()),
            Err(ParallelExecutionErrorV1::NonCanonicalAccessSet)
        );
    }

    #[test]
    fn canonical_indices_and_unique_transaction_ids_are_required() {
        let mut gap = transactions();
        gap[1].index = 2;
        assert_eq!(
            execute_parallel_block_v1(&parent(), &gap, 2, schedule()),
            Err(ParallelExecutionErrorV1::NonCanonicalTransactionIndex)
        );

        let mut duplicate = transactions();
        duplicate[1].transaction_id = duplicate[0].transaction_id;
        assert_eq!(
            execute_parallel_block_v1(&parent(), &duplicate, 2, schedule()),
            Err(ParallelExecutionErrorV1::DuplicateTransactionId)
        );
    }

    #[test]
    fn fee_limit_and_worker_bounds_fail_closed() {
        let mut transaction = transactions()[0].clone();
        transaction.max_fee = 0;
        assert_eq!(
            execute_parallel_block_v1(&parent(), &[transaction], 1, schedule()),
            Err(ParallelExecutionErrorV1::FeeLimitExceeded)
        );
        assert_eq!(
            execute_parallel_block_v1(&parent(), &transactions(), 0, schedule()),
            Err(ParallelExecutionErrorV1::InvalidWorkerCount)
        );
        assert_eq!(
            execute_parallel_block_v1(
                &parent(),
                &transactions(),
                MAX_PARALLEL_WORKERS_V1 + 1,
                schedule(),
            ),
            Err(ParallelExecutionErrorV1::InvalidWorkerCount)
        );
    }
}
