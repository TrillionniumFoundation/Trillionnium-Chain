use std::{
    collections::{BTreeMap, BTreeSet},
    thread,
};

use crate::{
    codec::{canonical_bytes, digest_value},
    error::{error, MvccFeeErrorCodeV1, MvccFeeResultV1},
    DestinationFeeCreditV1, FeeDeltaV1, Hash32V1, MvccBlockReceiptV1, MvccBlockV1,
    MvccFeeGenesisV1, MvccTransactionV1, ObjectProgramV1, ObjectStateV1, ReadSetEntryV1,
    ReceiptStatusV1, ResourcePriceV1, ResourceUsageV1, TransactionExecutionReceiptV1,
    TypedObjectIdV1, WriteSetEntryV1, RESOURCE_COMPUTE_UNITS_V1, RESOURCE_ORDERED_BYTES_V1,
    RESOURCE_STATE_READ_BYTES_V1, RESOURCE_STATE_WRITE_BYTES_V1, SCHEMA_VERSION_V1, UNIT_BYTE_V1,
    UNIT_COMPUTE_V1,
};

pub(crate) type ObjectMapV1 = BTreeMap<TypedObjectIdV1, ObjectStateV1>;
type ResourceAggregationKeyV1 = (u16, Vec<u8>, Vec<u8>, u32, u16);

const MAX_TRANSACTIONS_V1: usize = 256;
const MAX_ACCESS_WIDTH_V1: usize = 64;
pub(crate) const MAX_EXECUTION_WORKERS_V1: usize = 64;

pub(crate) fn validate_worker_count_v1(worker_count: usize) -> MvccFeeResultV1<()> {
    if worker_count == 0 || worker_count > MAX_EXECUTION_WORKERS_V1 {
        return Err(error(
            MvccFeeErrorCodeV1::InvalidBounds,
            "execution worker count is outside frozen candidate bounds",
        ));
    }
    Ok(())
}

pub fn derive_transaction_id_v1(transaction: &MvccTransactionV1) -> MvccFeeResultV1<Hash32V1> {
    digest_value(
        "trnm.poco-ai.mvcc-transaction.candidate.v1",
        &(
            transaction.schema_version,
            transaction.transaction_index,
            transaction.fee_payer,
            &transaction.declared_reads,
            &transaction.declared_writes,
            transaction.compute_unit_limit,
            transaction.max_fee,
            &transaction.program,
        ),
    )
}

pub fn derive_block_id_v1(block: &MvccBlockV1) -> MvccFeeResultV1<Hash32V1> {
    digest_value(
        "trnm.poco-ai.mvcc-block.candidate.v1",
        &(
            block.schema_version,
            &block.context,
            block.height,
            block.expected_parent_height,
            block.expected_parent_block_id,
            block.expected_parent_state_root,
            &block.transactions,
        ),
    )
}

pub(crate) fn validate_genesis(genesis: &MvccFeeGenesisV1) -> MvccFeeResultV1<()> {
    if genesis.schema_version != SCHEMA_VERSION_V1
        || genesis.context.chain_id.is_empty()
        || genesis.context.protocol_id != b"trnm-poco-ai-native-v1"
        || genesis.context.protocol_version != 1
        || genesis.context.genesis_hash == Hash32V1([0; 32])
        || genesis.context.profile_hash == Hash32V1([0; 32])
        || genesis.store_id == Hash32V1([0; 32])
        || genesis.initial_block_id == Hash32V1([0; 32])
        || genesis.initial_objects.is_empty()
        || genesis.resource_prices.len() != 4
        || genesis.destination_splits.is_empty()
    {
        return Err(error(
            MvccFeeErrorCodeV1::InvalidBounds,
            "invalid bounded MVCC genesis",
        ));
    }
    require_strict(
        &genesis.initial_objects,
        |value| value.object_id,
        "initial objects",
    )?;
    if genesis
        .initial_objects
        .iter()
        .any(|value| value.schema_version != SCHEMA_VERSION_V1 || value.closed)
    {
        return Err(error(
            MvccFeeErrorCodeV1::InvalidState,
            "invalid initial object",
        ));
    }
    require_strict(
        &genesis.resource_prices,
        |value| (value.resource_class, value.resource_id.clone(), value.unit),
        "resource prices",
    )?;
    let expected_classes = [
        (RESOURCE_ORDERED_BYTES_V1, UNIT_BYTE_V1),
        (RESOURCE_STATE_READ_BYTES_V1, UNIT_BYTE_V1),
        (RESOURCE_STATE_WRITE_BYTES_V1, UNIT_BYTE_V1),
        (RESOURCE_COMPUTE_UNITS_V1, UNIT_COMPUTE_V1),
    ];
    for (price, expected) in genesis.resource_prices.iter().zip(expected_classes) {
        if (price.resource_class, price.unit) != expected
            || !price.resource_id.is_empty()
            || price.price_denominator == 0
            || price.minimum_charge > price.maximum_charge
        {
            return Err(error(
                MvccFeeErrorCodeV1::InvalidBounds,
                "invalid resource price",
            ));
        }
    }
    require_strict(
        &genesis.destination_splits,
        |value| value.destination,
        "fee destinations",
    )?;
    let denominator = genesis.destination_splits[0].denominator;
    if denominator == 0
        || genesis
            .destination_splits
            .iter()
            .any(|value| value.denominator != denominator || value.numerator == 0)
        || !genesis
            .destination_splits
            .iter()
            .any(|value| value.destination == genesis.remainder_destination)
    {
        return Err(error(
            MvccFeeErrorCodeV1::InvalidBounds,
            "invalid destination split",
        ));
    }
    let numerator_sum = genesis
        .destination_splits
        .iter()
        .try_fold(0u128, |sum, value| {
            sum.checked_add(value.numerator).ok_or_else(|| {
                error(
                    MvccFeeErrorCodeV1::ArithmeticOverflow,
                    "destination numerator overflow",
                )
            })
        })?;
    if numerator_sum != denominator {
        return Err(error(
            MvccFeeErrorCodeV1::ConservationViolation,
            "destination splits do not sum to one",
        ));
    }
    let object_ids: BTreeSet<_> = genesis
        .initial_objects
        .iter()
        .map(|value| value.object_id)
        .collect();
    if genesis
        .destination_splits
        .iter()
        .any(|value| !object_ids.contains(&value.destination))
    {
        return Err(error(
            MvccFeeErrorCodeV1::NotFound,
            "fee destination object absent",
        ));
    }
    Ok(())
}

fn require_strict<T, K: Ord>(
    values: &[T],
    key: impl Fn(&T) -> K,
    label: &str,
) -> MvccFeeResultV1<()> {
    if values
        .windows(2)
        .any(|window| key(&window[0]) >= key(&window[1]))
    {
        return Err(error(
            MvccFeeErrorCodeV1::NonCanonical,
            format!("{label} must be strictly sorted and unique"),
        ));
    }
    Ok(())
}

pub(crate) fn state_root(objects: &ObjectMapV1) -> MvccFeeResultV1<Hash32V1> {
    digest_value(
        "trnm.poco-ai.mvcc-object-state-root.candidate.v1",
        &objects.values().cloned().collect::<Vec<_>>(),
    )
}

pub fn derive_state_root_v1(objects: &[ObjectStateV1]) -> MvccFeeResultV1<Hash32V1> {
    require_strict(objects, |value| value.object_id, "state objects")?;
    let map: ObjectMapV1 = objects
        .iter()
        .cloned()
        .map(|value| (value.object_id, value))
        .collect();
    state_root(&map)
}

fn value_hash(value: &ObjectStateV1) -> MvccFeeResultV1<Hash32V1> {
    digest_value("trnm.poco-ai.mvcc-object-value.candidate.v1", value)
}

pub(crate) fn execute_block(
    genesis: &MvccFeeGenesisV1,
    parent: &ObjectMapV1,
    block: &MvccBlockV1,
) -> MvccFeeResultV1<(ObjectMapV1, MvccBlockReceiptV1)> {
    execute_block_with_workers(genesis, parent, block, 1)
}

pub(crate) fn execute_block_with_workers(
    genesis: &MvccFeeGenesisV1,
    parent: &ObjectMapV1,
    block: &MvccBlockV1,
    worker_count: usize,
) -> MvccFeeResultV1<(ObjectMapV1, MvccBlockReceiptV1)> {
    validate_worker_count_v1(worker_count)?;
    validate_block(genesis, parent, block)?;
    let parent_root = state_root(parent)?;
    let speculative_reads =
        parallel_speculative_reads_v1(parent, &block.transactions, worker_count)?;
    let mut current = parent.clone();
    let mut pending_fees: BTreeMap<(TypedObjectIdV1, TypedObjectIdV1), u128> = BTreeMap::new();
    let mut receipts = Vec::with_capacity(block.transactions.len());
    for (transaction, speculative) in block.transactions.iter().zip(speculative_reads) {
        let current_reads = read_set(&current, transaction)?;
        let conflict_set: Vec<_> = speculative
            .iter()
            .zip(&current_reads)
            .filter_map(|(left, right)| {
                (left.observed_version != right.observed_version
                    || left.observed_value_hash != right.observed_value_hash)
                    .then_some(right.object_id)
            })
            .collect();
        let retry_count = u32::from(!conflict_set.is_empty());
        let receipt = execute_transaction(
            genesis,
            &mut current,
            &mut pending_fees,
            transaction,
            current_reads,
            conflict_set,
            retry_count,
        )?;
        receipts.push(receipt);
    }
    let aggregated_fee_deltas = reduce_pending_fees(&pending_fees);
    let destination_credits = reduce_destination_credits(&aggregated_fee_deltas)?;
    apply_destination_credits(&mut current, &destination_credits)?;
    let final_state_root = state_root(&current)?;
    let resource_totals = aggregate_resources(&receipts)?;
    let receipts_root = digest_value("trnm.poco-ai.mvcc-receipts-root.candidate.v1", &receipts)?;
    let resource_totals_root = digest_value(
        "trnm.poco-ai.mvcc-resource-totals-root.candidate.v1",
        &resource_totals,
    )?;
    let fee_deltas_root = digest_value(
        "trnm.poco-ai.mvcc-fee-deltas-root.candidate.v1",
        &(&aggregated_fee_deltas, &destination_credits),
    )?;
    let mvcc_resolution_root = digest_value(
        "trnm.poco-ai.mvcc-resolution-root.candidate.v1",
        &receipts
            .iter()
            .map(|value| {
                (
                    &value.transaction_id,
                    &value.conflict_set,
                    value.retry_count,
                )
            })
            .collect::<Vec<_>>(),
    )?;
    let transaction_count = u32::try_from(receipts.len()).map_err(|_| {
        error(
            MvccFeeErrorCodeV1::ArithmeticOverflow,
            "transaction count overflow",
        )
    })?;
    let receipt = MvccBlockReceiptV1 {
        schema_version: SCHEMA_VERSION_V1,
        store_id: genesis.store_id,
        block_id: block.block_id,
        height: block.height,
        parent_state_root: parent_root,
        final_state_root,
        receipts_root,
        resource_totals_root,
        fee_deltas_root,
        mvcc_resolution_root,
        transaction_count,
        receipts,
        resource_totals,
        aggregated_fee_deltas,
        destination_credits,
    };
    Ok((current, receipt))
}

fn parallel_speculative_reads_v1(
    parent: &ObjectMapV1,
    transactions: &[MvccTransactionV1],
    worker_count: usize,
) -> MvccFeeResultV1<Vec<Vec<ReadSetEntryV1>>> {
    validate_worker_count_v1(worker_count)?;
    let active_workers = worker_count.min(transactions.len().max(1));
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(active_workers);
        for worker_index in 0..active_workers {
            handles.push(scope.spawn(move || {
                let mut rows = Vec::new();
                let mut position = worker_index;
                while position < transactions.len() {
                    rows.push((position, read_set(parent, &transactions[position])));
                    position += active_workers;
                }
                rows
            }));
        }

        let mut ordered: Vec<Option<Vec<ReadSetEntryV1>>> =
            (0..transactions.len()).map(|_| None).collect();
        for handle in handles {
            let rows = handle.join().map_err(|_| {
                error(
                    MvccFeeErrorCodeV1::InvalidState,
                    "parallel speculation worker panicked",
                )
            })?;
            for (position, row) in rows {
                ordered[position] = Some(row?);
            }
        }

        ordered
            .into_iter()
            .map(|row| {
                row.ok_or_else(|| {
                    error(
                        MvccFeeErrorCodeV1::InvalidState,
                        "parallel speculation omitted a canonical transaction",
                    )
                })
            })
            .collect()
    })
}

fn validate_block(
    genesis: &MvccFeeGenesisV1,
    parent: &ObjectMapV1,
    block: &MvccBlockV1,
) -> MvccFeeResultV1<()> {
    if block.schema_version != SCHEMA_VERSION_V1
        || block.context != genesis.context
        || block.block_id == Hash32V1([0; 32])
        || block.transactions.is_empty()
        || block.transactions.len() > MAX_TRANSACTIONS_V1
        || block.expected_parent_state_root != state_root(parent)?
        || block.block_id != derive_block_id_v1(block)?
    {
        return Err(error(
            MvccFeeErrorCodeV1::InvalidContext,
            "invalid block context/id/parent",
        ));
    }
    let destinations: BTreeSet<_> = genesis
        .destination_splits
        .iter()
        .map(|value| value.destination)
        .collect();
    let mut transaction_ids = BTreeSet::new();
    for (index, transaction) in block.transactions.iter().enumerate() {
        let index_u32 = u32::try_from(index)
            .map_err(|_| error(MvccFeeErrorCodeV1::ArithmeticOverflow, "index overflow"))?;
        if transaction.schema_version != SCHEMA_VERSION_V1
            || transaction.transaction_index != index_u32
            || transaction.transaction_id == Hash32V1([0; 32])
            || transaction.transaction_id != derive_transaction_id_v1(transaction)?
            || !transaction_ids.insert(transaction.transaction_id)
            || transaction.compute_unit_limit == 0
            || transaction.max_fee == 0
            || transaction.declared_reads.len() > MAX_ACCESS_WIDTH_V1
            || transaction.declared_writes.len() > MAX_ACCESS_WIDTH_V1
            || destinations.contains(&transaction.fee_payer)
        {
            return Err(error(
                MvccFeeErrorCodeV1::InvalidBounds,
                "invalid transaction identity/bounds",
            ));
        }
        require_strict(
            &transaction.declared_reads,
            |value| *value,
            "declared reads",
        )?;
        require_strict(
            &transaction.declared_writes,
            |value| *value,
            "declared writes",
        )?;
        let (expected_reads, expected_writes) = expected_access(transaction)?;
        if transaction.declared_reads != expected_reads
            || transaction.declared_writes != expected_writes
        {
            return Err(error(
                MvccFeeErrorCodeV1::UndeclaredAccess,
                "declared access does not match program",
            ));
        }
    }
    Ok(())
}

fn expected_access(
    transaction: &MvccTransactionV1,
) -> MvccFeeResultV1<(Vec<TypedObjectIdV1>, Vec<TypedObjectIdV1>)> {
    let mut ids = vec![transaction.fee_payer];
    match transaction.program {
        ObjectProgramV1::Add { target, .. } => {
            if target == transaction.fee_payer {
                return Err(error(
                    MvccFeeErrorCodeV1::DuplicateAccess,
                    "fee payer and target must differ",
                ));
            }
            ids.push(target);
        }
        ObjectProgramV1::Transfer {
            source,
            destination,
            ..
        } => {
            if source == destination
                || source == transaction.fee_payer
                || destination == transaction.fee_payer
            {
                return Err(error(
                    MvccFeeErrorCodeV1::DuplicateAccess,
                    "bounded transfer objects must be distinct",
                ));
            }
            ids.extend([source, destination]);
        }
        ObjectProgramV1::Revert { .. } => {}
    }
    ids.sort_unstable();
    Ok((ids.clone(), ids))
}

fn read_set(
    state: &ObjectMapV1,
    transaction: &MvccTransactionV1,
) -> MvccFeeResultV1<Vec<ReadSetEntryV1>> {
    transaction
        .declared_reads
        .iter()
        .map(|object_id| {
            let value = state
                .get(object_id)
                .ok_or_else(|| error(MvccFeeErrorCodeV1::NotFound, "declared object absent"))?;
            if value.closed {
                return Err(error(
                    MvccFeeErrorCodeV1::InvalidState,
                    "declared object closed",
                ));
            }
            Ok(ReadSetEntryV1 {
                object_id: *object_id,
                observed_version: value.version,
                observed_value_hash: value_hash(value)?,
            })
        })
        .collect()
}

fn execute_transaction(
    genesis: &MvccFeeGenesisV1,
    state: &mut ObjectMapV1,
    pending_fees: &mut BTreeMap<(TypedObjectIdV1, TypedObjectIdV1), u128>,
    transaction: &MvccTransactionV1,
    read_set: Vec<ReadSetEntryV1>,
    conflict_set: Vec<TypedObjectIdV1>,
    retry_count: u32,
) -> MvccFeeResultV1<TransactionExecutionReceiptV1> {
    let required_compute = match transaction.program {
        ObjectProgramV1::Add { .. } => 10,
        ObjectProgramV1::Transfer { .. } => 20,
        ObjectProgramV1::Revert { .. } => 5,
    };
    let (status, error_class, charged_compute) = match transaction.program {
        ObjectProgramV1::Revert { error_class } => (
            ReceiptStatusV1::Reverted,
            Some(error_class),
            required_compute,
        ),
        _ if transaction.compute_unit_limit < required_compute => (
            ReceiptStatusV1::OutOfResource,
            Some(1),
            transaction.compute_unit_limit,
        ),
        _ => (ReceiptStatusV1::Success, None, required_compute),
    };
    let app_write_count: usize = match (&transaction.program, status) {
        (ObjectProgramV1::Add { .. }, ReceiptStatusV1::Success) => 1,
        (ObjectProgramV1::Transfer { .. }, ReceiptStatusV1::Success) => 2,
        _ => 0,
    };
    let read_bytes = read_set.iter().try_fold(0u128, |sum, entry| {
        let object = state
            .get(&entry.object_id)
            .expect("read set was derived from state");
        let len = u128::try_from(canonical_bytes(object)?.len()).map_err(|_| {
            error(
                MvccFeeErrorCodeV1::ArithmeticOverflow,
                "read byte count overflow",
            )
        })?;
        sum.checked_add(len).ok_or_else(|| {
            error(
                MvccFeeErrorCodeV1::ArithmeticOverflow,
                "read bytes overflow",
            )
        })
    })?;
    let object_size = u128::try_from(
        canonical_bytes(
            state
                .get(&transaction.fee_payer)
                .ok_or_else(|| error(MvccFeeErrorCodeV1::NotFound, "fee payer absent"))?,
        )?
        .len(),
    )
    .map_err(|_| {
        error(
            MvccFeeErrorCodeV1::ArithmeticOverflow,
            "write byte count overflow",
        )
    })?;
    let write_count = u128::try_from(app_write_count + 1).map_err(|_| {
        error(
            MvccFeeErrorCodeV1::ArithmeticOverflow,
            "write count overflow",
        )
    })?;
    let write_bytes = object_size.checked_mul(write_count).ok_or_else(|| {
        error(
            MvccFeeErrorCodeV1::ArithmeticOverflow,
            "write bytes overflow",
        )
    })?;
    let ordered_bytes = u128::try_from(canonical_bytes(transaction)?.len()).map_err(|_| {
        error(
            MvccFeeErrorCodeV1::ArithmeticOverflow,
            "ordered bytes overflow",
        )
    })?;
    let usage_values = [
        (RESOURCE_ORDERED_BYTES_V1, UNIT_BYTE_V1, ordered_bytes),
        (RESOURCE_STATE_READ_BYTES_V1, UNIT_BYTE_V1, read_bytes),
        (RESOURCE_STATE_WRITE_BYTES_V1, UNIT_BYTE_V1, write_bytes),
        (RESOURCE_COMPUTE_UNITS_V1, UNIT_COMPUTE_V1, charged_compute),
    ];
    let resource_usage = usage_values
        .into_iter()
        .map(|(resource_class, unit, amount)| {
            Ok(ResourceUsageV1 {
                resource_class,
                resource_id: Vec::new(),
                meter_id: b"trnm-reference-meter".to_vec(),
                meter_version: 1,
                amount,
                unit,
                measurement_commitment: digest_value(
                    "trnm.poco-ai.resource-measurement.candidate.v1",
                    &(
                        transaction.transaction_id,
                        transaction.transaction_index,
                        resource_class,
                        amount,
                        unit,
                    ),
                )?,
            })
        })
        .collect::<MvccFeeResultV1<Vec<_>>>()?;
    let fee_charged = calculate_fee(&genesis.resource_prices, &resource_usage)?;
    if fee_charged > transaction.max_fee {
        return Err(error(
            MvccFeeErrorCodeV1::FeeLimitExceeded,
            "computed fee exceeds transaction ceiling",
        ));
    }
    let payer = state
        .get(&transaction.fee_payer)
        .cloned()
        .ok_or_else(|| error(MvccFeeErrorCodeV1::NotFound, "fee payer absent"))?;
    if payer.value < fee_charged {
        return Err(error(
            MvccFeeErrorCodeV1::InsufficientFunds,
            "fee payer balance insufficient",
        ));
    }
    let mut successors = BTreeMap::new();
    if status == ReceiptStatusV1::Success {
        match transaction.program {
            ObjectProgramV1::Add { target, amount } => {
                let mut object = state
                    .get(&target)
                    .cloned()
                    .ok_or_else(|| error(MvccFeeErrorCodeV1::NotFound, "add target absent"))?;
                object.value = object
                    .value
                    .checked_add(amount)
                    .ok_or_else(|| error(MvccFeeErrorCodeV1::ArithmeticOverflow, "add overflow"))?;
                object.version = object.version.checked_add(1).ok_or_else(|| {
                    error(
                        MvccFeeErrorCodeV1::ArithmeticOverflow,
                        "object version overflow",
                    )
                })?;
                successors.insert(target, object);
            }
            ObjectProgramV1::Transfer {
                source,
                destination,
                amount,
            } => {
                let mut from = state
                    .get(&source)
                    .cloned()
                    .ok_or_else(|| error(MvccFeeErrorCodeV1::NotFound, "transfer source absent"))?;
                let mut to = state.get(&destination).cloned().ok_or_else(|| {
                    error(MvccFeeErrorCodeV1::NotFound, "transfer destination absent")
                })?;
                if from.value < amount {
                    return Err(error(
                        MvccFeeErrorCodeV1::InsufficientFunds,
                        "transfer source insufficient",
                    ));
                }
                from.value = from.value.checked_sub(amount).ok_or_else(|| {
                    error(
                        MvccFeeErrorCodeV1::ArithmeticOverflow,
                        "transfer source underflow",
                    )
                })?;
                to.value = to.value.checked_add(amount).ok_or_else(|| {
                    error(
                        MvccFeeErrorCodeV1::ArithmeticOverflow,
                        "transfer destination overflow",
                    )
                })?;
                from.version = from.version.checked_add(1).ok_or_else(|| {
                    error(
                        MvccFeeErrorCodeV1::ArithmeticOverflow,
                        "source version overflow",
                    )
                })?;
                to.version = to.version.checked_add(1).ok_or_else(|| {
                    error(
                        MvccFeeErrorCodeV1::ArithmeticOverflow,
                        "destination version overflow",
                    )
                })?;
                successors.insert(source, from);
                successors.insert(destination, to);
            }
            ObjectProgramV1::Revert { .. } => unreachable!("revert is not successful"),
        }
    }
    let mut payer_successor = payer.clone();
    payer_successor.value = payer_successor
        .value
        .checked_sub(fee_charged)
        .ok_or_else(|| {
            error(
                MvccFeeErrorCodeV1::ArithmeticOverflow,
                "payer fee underflow",
            )
        })?;
    payer_successor.version = payer_successor.version.checked_add(1).ok_or_else(|| {
        error(
            MvccFeeErrorCodeV1::ArithmeticOverflow,
            "payer version overflow",
        )
    })?;
    successors.insert(transaction.fee_payer, payer_successor);
    let mut write_set = Vec::with_capacity(successors.len());
    for (id, successor) in &successors {
        let prior = state
            .get(id)
            .expect("successor objects were loaded from state");
        write_set.push(WriteSetEntryV1 {
            object_id: *id,
            prior_version: prior.version,
            successor_version: successor.version,
            successor_value_hash: value_hash(successor)?,
        });
    }
    for (id, successor) in successors {
        state.insert(id, successor);
    }
    let fee_deltas = split_fee(genesis, transaction.fee_payer, fee_charged)?;
    for delta in &fee_deltas {
        let slot = pending_fees
            .entry((delta.source, delta.destination))
            .or_default();
        *slot = slot.checked_add(delta.amount).ok_or_else(|| {
            error(
                MvccFeeErrorCodeV1::ArithmeticOverflow,
                "pending fee delta overflow",
            )
        })?;
    }
    let pending = reduce_pending_fees(pending_fees);
    let post_transaction_state_root = digest_value(
        "trnm.poco-ai.mvcc-intermediate-state-root.candidate.v1",
        &(state.values().cloned().collect::<Vec<_>>(), &pending),
    )?;
    let read_set_root = digest_value("trnm.poco-ai.read-set-root.candidate.v1", &read_set)?;
    let write_set_root = digest_value("trnm.poco-ai.write-set-root.candidate.v1", &write_set)?;
    let state_delta_root = digest_value("trnm.poco-ai.state-delta-root.candidate.v1", &write_set)?;
    Ok(TransactionExecutionReceiptV1 {
        schema_version: SCHEMA_VERSION_V1,
        transaction_id: transaction.transaction_id,
        transaction_index: transaction.transaction_index,
        status,
        error_class,
        read_set,
        write_set,
        read_set_root,
        write_set_root,
        state_delta_root,
        post_transaction_state_root,
        resource_usage,
        fee_charged,
        refund_amount: transaction
            .max_fee
            .checked_sub(fee_charged)
            .ok_or_else(|| error(MvccFeeErrorCodeV1::ArithmeticOverflow, "refund underflow"))?,
        fee_deltas,
        conflict_set,
        retry_count,
    })
}

fn calculate_fee(prices: &[ResourcePriceV1], usage: &[ResourceUsageV1]) -> MvccFeeResultV1<u128> {
    prices
        .iter()
        .zip(usage)
        .try_fold(0u128, |sum, (price, item)| {
            if (price.resource_class, &price.resource_id, price.unit)
                != (item.resource_class, &item.resource_id, item.unit)
            {
                return Err(error(
                    MvccFeeErrorCodeV1::InvalidState,
                    "usage has no exact committed price",
                ));
            }
            let numerator = item
                .amount
                .checked_mul(price.price_numerator)
                .ok_or_else(|| {
                    error(
                        MvccFeeErrorCodeV1::ArithmeticOverflow,
                        "resource charge multiply overflow",
                    )
                })?;
            let quotient = numerator / price.price_denominator;
            let rounded = quotient
                .checked_add(u128::from(numerator % price.price_denominator != 0))
                .ok_or_else(|| {
                    error(
                        MvccFeeErrorCodeV1::ArithmeticOverflow,
                        "resource charge rounding overflow",
                    )
                })?;
            let charge = rounded.clamp(price.minimum_charge, price.maximum_charge);
            sum.checked_add(charge)
                .ok_or_else(|| error(MvccFeeErrorCodeV1::ArithmeticOverflow, "fee total overflow"))
        })
}

fn split_fee(
    genesis: &MvccFeeGenesisV1,
    source: TypedObjectIdV1,
    fee: u128,
) -> MvccFeeResultV1<Vec<FeeDeltaV1>> {
    let mut output = Vec::with_capacity(genesis.destination_splits.len());
    let mut assigned = 0u128;
    for split in &genesis.destination_splits {
        let amount = fee.checked_mul(split.numerator).ok_or_else(|| {
            error(
                MvccFeeErrorCodeV1::ArithmeticOverflow,
                "fee split multiply overflow",
            )
        })? / split.denominator;
        assigned = assigned.checked_add(amount).ok_or_else(|| {
            error(
                MvccFeeErrorCodeV1::ArithmeticOverflow,
                "fee split sum overflow",
            )
        })?;
        output.push(FeeDeltaV1 {
            source,
            destination: split.destination,
            amount,
        });
    }
    let remainder = fee.checked_sub(assigned).ok_or_else(|| {
        error(
            MvccFeeErrorCodeV1::ConservationViolation,
            "fee split exceeds fee",
        )
    })?;
    let slot = output
        .iter_mut()
        .find(|value| value.destination == genesis.remainder_destination)
        .ok_or_else(|| {
            error(
                MvccFeeErrorCodeV1::InvalidState,
                "remainder destination absent",
            )
        })?;
    slot.amount = slot
        .amount
        .checked_add(remainder)
        .ok_or_else(|| error(MvccFeeErrorCodeV1::ArithmeticOverflow, "remainder overflow"))?;
    let total = output.iter().try_fold(0u128, |sum, value| {
        sum.checked_add(value.amount).ok_or_else(|| {
            error(
                MvccFeeErrorCodeV1::ArithmeticOverflow,
                "fee delta sum overflow",
            )
        })
    })?;
    if total != fee {
        return Err(error(
            MvccFeeErrorCodeV1::ConservationViolation,
            "fee deltas do not conserve",
        ));
    }
    Ok(output)
}

fn reduce_pending_fees(
    pending: &BTreeMap<(TypedObjectIdV1, TypedObjectIdV1), u128>,
) -> Vec<FeeDeltaV1> {
    pending
        .iter()
        .map(|((source, destination), amount)| FeeDeltaV1 {
            source: *source,
            destination: *destination,
            amount: *amount,
        })
        .collect()
}

fn reduce_destination_credits(
    deltas: &[FeeDeltaV1],
) -> MvccFeeResultV1<Vec<DestinationFeeCreditV1>> {
    let mut credits: BTreeMap<TypedObjectIdV1, u128> = BTreeMap::new();
    for delta in deltas {
        let slot = credits.entry(delta.destination).or_default();
        *slot = slot.checked_add(delta.amount).ok_or_else(|| {
            error(
                MvccFeeErrorCodeV1::ArithmeticOverflow,
                "destination credit overflow",
            )
        })?;
    }
    Ok(credits
        .into_iter()
        .map(|(destination, amount)| DestinationFeeCreditV1 {
            destination,
            amount,
        })
        .collect())
}

fn apply_destination_credits(
    state: &mut ObjectMapV1,
    credits: &[DestinationFeeCreditV1],
) -> MvccFeeResultV1<()> {
    for credit in credits {
        let destination = credit.destination;
        let amount = credit.amount;
        let object = state
            .get_mut(&destination)
            .ok_or_else(|| error(MvccFeeErrorCodeV1::NotFound, "fee destination absent"))?;
        object.value = object.value.checked_add(amount).ok_or_else(|| {
            error(
                MvccFeeErrorCodeV1::ArithmeticOverflow,
                "fee destination value overflow",
            )
        })?;
        object.version = object.version.checked_add(1).ok_or_else(|| {
            error(
                MvccFeeErrorCodeV1::ArithmeticOverflow,
                "fee destination version overflow",
            )
        })?;
    }
    Ok(())
}

fn aggregate_resources(
    receipts: &[TransactionExecutionReceiptV1],
) -> MvccFeeResultV1<Vec<ResourceUsageV1>> {
    let mut totals: BTreeMap<ResourceAggregationKeyV1, u128> = BTreeMap::new();
    for usage in receipts.iter().flat_map(|receipt| &receipt.resource_usage) {
        let key = (
            usage.resource_class,
            usage.resource_id.clone(),
            usage.meter_id.clone(),
            usage.meter_version,
            usage.unit,
        );
        let slot = totals.entry(key).or_default();
        *slot = slot.checked_add(usage.amount).ok_or_else(|| {
            error(
                MvccFeeErrorCodeV1::ArithmeticOverflow,
                "resource total overflow",
            )
        })?;
    }
    totals
        .into_iter()
        .map(
            |((resource_class, resource_id, meter_id, meter_version, unit), amount)| {
                Ok(ResourceUsageV1 {
                    resource_class,
                    resource_id,
                    meter_id,
                    meter_version,
                    amount,
                    unit,
                    measurement_commitment: digest_value(
                        "trnm.poco-ai.block-resource-total.candidate.v1",
                        &(resource_class, amount, unit),
                    )?,
                })
            },
        )
        .collect()
}
