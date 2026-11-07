//! Node-retained V2 journal prefix floors. No monetary ledger is added.
use super::*;
use trnm_service_settlement::native_budget::task_operation_v2::{
    NativeTaskOperationCheckpointV2, NativeTaskOperationSnapshotV2, NativeTaskOperationStoreV2,
};
use trnm_service_settlement::native_budget::{NativeBudgetConfigV1, NativePaymentQueryV1};

const PREFIX: &str = "pon-native-task-operation-reconciliation-v2:event:";
const HEAD: &str = "pon-native-task-operation-reconciliation-v2:head";
const SCHEMA: &str = "pon-native-task-operation-reconciliation-v2";
const MAX_RECORDS: usize = 128;
const MAX_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    max_records: u32,
    sequence: u64,
    root: Hash,
}
impl Checkpoint {
    fn native(&self, anchor: &Anchor) -> NativeTaskOperationCheckpointV2 {
        NativeTaskOperationCheckpointV2 {
            configuration: NativeBudgetConfigV1 {
                network: anchor.network,
                parameters: anchor.parameters,
                genesis: anchor.genesis,
                max_records: self.max_records,
            },
            sequence: self.sequence,
            root: self.root,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    schema: String,
    claim: Hash,
    task: Hash,
    binding: Hash,
    consumer_epoch: u64,
    anchor: Anchor,
    checkpoint: Checkpoint,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    sequence: u64,
    previous: Hash,
    root: Hash,
    observation: Observation,
}
fn root(sequence: u64, previous: Hash, observation: &Observation) -> Result<Hash> {
    Ok(hash(
        b"pon-native-task-operation-reconciliation-record-v2",
        &[
            &sequence.to_le_bytes(),
            &previous,
            &canonical(&serde_json::to_value(observation)?)?,
        ],
    ))
}
fn head(records: &[Record]) -> Result<Option<Vec<u8>>> {
    records
        .last()
        .map(|record| canonical(&json!({"sequence":record.sequence,"root":record.root})))
        .transpose()
}
fn progress(before: &Observation, after: &Observation) -> Result<()> {
    ensure(
        after.consumer_epoch >= before.consumer_epoch
            && after.anchor.generation >= before.anchor.generation
            && (after.anchor.generation != before.anchor.generation
                || after.anchor == before.anchor)
            && after.checkpoint.max_records == before.checkpoint.max_records
            && after.checkpoint.sequence >= before.checkpoint.sequence
            && (after.checkpoint.sequence != before.checkpoint.sequence
                || after.checkpoint.root == before.checkpoint.root),
        "TASK_OPERATION_RECONCILIATION_PROGRESS",
    )
}
fn record_report(record: &Record) -> Value {
    json!({
        "schema":SCHEMA,"sequence":record.sequence,"root":hex::encode(record.root),
        "task":hex::encode(record.observation.task),"claim":hex::encode(record.observation.claim),
        "binding":hex::encode(record.observation.binding),"consumer_epoch":record.observation.consumer_epoch,
        "anchor":record.observation.anchor,"checkpoint":record.observation.checkpoint,
        "physical_costs_verified":false,"independent_evaluation_verified":false,
        "global_execution_authority":false,"production_activation":false,
    })
}

impl Node {
    fn read_task_operation_reconciliations_v2(
        &self,
        pins: &BTreeMap<Hash, Pin>,
    ) -> Result<Vec<Record>> {
        let mut query = self.db.prepare(
            "SELECT typeof(key),length(CAST(key AS BLOB)),substr(CAST(key AS BLOB),1,?3),typeof(value),length(value),substr(value,1,?1) FROM metadata WHERE key GLOB 'pon-native-task-operation-reconciliation-v2:*' ORDER BY key LIMIT ?2",
        )?;
        let rows = query
            .query_map(
                params![MAX_BYTES + 1, MAX_RECORDS + 2, PREFIX.len() + 17],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, usize>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, usize>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure(
            rows.len() <= MAX_RECORDS + 1,
            "TASK_OPERATION_RECONCILIATION_LIMIT",
        )?;
        let mut records: Vec<Record> = Vec::new();
        let mut retained_head = None;
        for (key_kind, key_length, key_raw, kind, length, raw) in rows {
            ensure(
                key_kind == "text"
                    && key_length <= PREFIX.len() + 16
                    && key_raw.len() == key_length
                    && key_raw.is_ascii(),
                "TASK_OPERATION_RECONCILIATION_KEY",
            )?;
            let key =
                String::from_utf8(key_raw).map_err(|_| "TASK_OPERATION_RECONCILIATION_KEY")?;
            ensure(
                kind == "blob" && length <= MAX_BYTES && raw.len() == length,
                "TASK_OPERATION_RECONCILIATION_BYTES",
            )?;
            if key == HEAD {
                retained_head = Some(raw);
                continue;
            }
            let record: Record =
                serde_json::from_slice(&raw).map_err(|_| "TASK_OPERATION_RECONCILIATION_CODEC")?;
            let sequence = records.len() as u64 + 1;
            let previous = records.last().map(|record| record.root).unwrap_or([0; 32]);
            let observed = &record.observation;
            ensure(
                key == format!("{PREFIX}{sequence:016x}")
                    && record.sequence == sequence
                    && record.previous == previous
                    && record.root == root(sequence, previous, observed)?
                    && raw == canonical(&serde_json::to_value(&record)?)?
                    && observed.schema == SCHEMA
                    && observed.checkpoint.sequence > 0
                    && (1..=65_536).contains(&observed.checkpoint.max_records)
                    && observed.checkpoint.sequence
                        <= u64::from(observed.checkpoint.max_records) * 6,
                "TASK_OPERATION_RECONCILIATION_RECORD",
            )?;
            self.check_task_operation_anchor_v1(&observed.anchor)?;
            let pin = pins
                .get(&observed.task)
                .ok_or("TASK_OPERATION_RECONCILIATION_PIN")?;
            let binding = pin.binding()?.ok_or("TASK_OPERATION_RECONCILIATION_PIN")?;
            ensure(
                pin.version == 2
                    && binding.claim == observed.claim
                    && binding.id().map_err(budget_error)? == observed.binding,
                "TASK_OPERATION_RECONCILIATION_PIN",
            )?;
            if let Some(prior) = records.last() {
                progress(&prior.observation, observed)?;
            }
            records.push(record);
        }
        ensure(
            head(&records)? == retained_head,
            "TASK_OPERATION_RECONCILIATION_HEAD",
        )?;
        Ok(records)
    }
    pub(super) fn validate_task_operation_reconciliations_v2(
        &self,
        pins: &BTreeMap<Hash, Pin>,
    ) -> Result<()> {
        self.read_task_operation_reconciliations_v2(pins)
            .map(|_| ())
            .map_err(Error::local_integrity)
    }
    pub fn native_task_operation_reconciliation_history_v2(&self) -> Result<Value> {
        self.ready()?;
        let pins = self.task_operation_pins_v1()?;
        self.validate_task_operation_history_v1(&pins)?;
        let records = self
            .read_task_operation_reconciliations_v2(&pins)
            .map_err(Error::local_integrity)?;
        Ok(json!({
            "schema":"pon-native-task-operation-reconciliation-history-v2",
            "records":records.iter().map(record_report).collect::<Vec<_>>(),
            "live_m12_journal_rechecked":false,"global_execution_authority":false,"production_activation":false,
        }))
    }
    fn verify_operation_snapshot_v2(
        &self,
        snapshot: &NativeTaskOperationSnapshotV2,
        pins: &BTreeMap<Hash, Pin>,
    ) -> Result<()> {
        let binding = &snapshot.binding;
        let pin = pins
            .get(&binding.task)
            .ok_or("TASK_OPERATION_RECONCILIATION_PIN")?;
        ensure(
            pin.version == 2
                && pin.binding.as_ref() == Some(&binding.encode().map_err(budget_error)?),
            "TASK_OPERATION_RECONCILIATION_PIN",
        )?;
        ensure(
            self.historical_contract_operation_v2(binding, snapshot.reserved.anchor)?
                == snapshot.reserved
                && snapshot.reserved.anchor.generation >= pin.source.generation,
            "TASK_OPERATION_RECONCILIATION_SOURCE",
        )?;
        if let Some(begun) = &snapshot.begun {
            ensure(
                pin.started_at.is_some()
                    && (!begun.new_execution
                        || pin.started_at.as_ref() == Some(&begun.contract.anchor.into()))
                    && pin.started_at.as_ref().is_some_and(|started| {
                        begun.contract.anchor.generation >= started.generation
                    })
                    && self.historical_contract_operation_v2(binding, begun.contract.anchor)?
                        == begun.contract,
                "TASK_OPERATION_RECONCILIATION_BEGIN",
            )?;
        }
        if let Some(delivery) = &snapshot.delivery {
            let original = pin
                .delivery
                .as_ref()
                .ok_or("TASK_OPERATION_RECONCILIATION_DELIVERY")?;
            let contract =
                self.historical_contract_operation_v2(binding, delivery.contract.anchor)?;
            ensure(
                contract == delivery.contract,
                "TASK_OPERATION_RECONCILIATION_SOURCE",
            )?;
            let actual = self.read_delivery_for_contract_v2(binding, contract)?;
            ensure(
                actual == *delivery
                    && actual.contract.output == Some(original.output)
                    && actual.receipt_operation == original.receipt_operation,
                "TASK_OPERATION_RECONCILIATION_DELIVERY",
            )?;
        }
        if let Some(payment) = &snapshot.payment {
            let output = snapshot
                .completion
                .as_ref()
                .ok_or("TASK_OPERATION_RECONCILIATION_PAYMENT")?
                .output;
            let query = NativePaymentQueryV1 {
                source: NativeFundingSourceV1::Task(binding.task),
                subject: output,
                beneficiary: binding.beneficiary,
                operation: payment.operation,
                maximum_gross_units: snapshot.reserved.amount,
            };
            let actual = self.native_payment_observation_at_anchor_v1(&query, payment.anchor)?;
            ensure(actual == *payment, "TASK_OPERATION_RECONCILIATION_PAYMENT")?;
        }
        Ok(())
    }

    /// Preserve a checked M12 prefix in this Node before treating later cost or
    /// completion exports as a continuation. This never issues a payment or a
    /// new execution decision. One Node namespace pins one V2 journal history.
    pub fn reconcile_native_task_operation_v2(
        &mut self,
        store: &NativeTaskOperationStoreV2,
        claim: Hash,
        consumer_epoch: u64,
    ) -> Result<Value> {
        self.ready()?;
        let pins = self.task_operation_pins_v1()?;
        self.validate_task_operation_history_v1(&pins)?;
        let records = self
            .read_task_operation_reconciliations_v2(&pins)
            .map_err(Error::local_integrity)?;
        if let Some(last) = records.last() {
            ensure(
                consumer_epoch >= last.observation.consumer_epoch,
                "TASK_OPERATION_RECONCILIATION_EPOCH",
            )?;
        }
        let expected = records
            .last()
            .map(|last| last.observation.checkpoint.native(&last.observation.anchor));
        let (snapshot, checkpoint) = store
            .snapshot_after_checkpoint(claim, expected.as_ref())
            .map_err(budget_error)?;
        ensure(
            checkpoint.configuration.network == self.settings.network()
                && checkpoint.configuration.parameters == self.settings.parameters()
                && checkpoint.configuration.genesis == self.settings.genesis(),
            "TASK_OPERATION_RECONCILIATION_CONTEXT",
        )?;
        self.verify_operation_snapshot_v2(&snapshot, &pins)?;
        let source =
            self.native_funding_observation(NativeFundingSourceV1::Task(snapshot.binding.task))?;
        let observation = Observation {
            schema: SCHEMA.into(),
            claim,
            task: snapshot.binding.task,
            binding: snapshot.binding.id().map_err(budget_error)?,
            consumer_epoch,
            anchor: source.anchor.into(),
            checkpoint: Checkpoint {
                max_records: checkpoint.configuration.max_records,
                sequence: checkpoint.sequence,
                root: checkpoint.root,
            },
        };
        if let Some(last) = records.last() {
            progress(&last.observation, &observation)?;
        }
        store.verify_checkpoint(&checkpoint).map_err(budget_error)?;
        if let Some(prior) = records
            .iter()
            .rev()
            .find(|record| record.observation == observation)
        {
            ensure(
                self.native_funding_observation(NativeFundingSourceV1::Task(
                    snapshot.binding.task,
                ))?
                .anchor
                    == source.anchor,
                "STALE_VIEW",
            )?;
            return Ok(reconciliation_report(prior, &snapshot));
        }
        ensure(
            records.len() < MAX_RECORDS,
            "TASK_OPERATION_RECONCILIATION_LIMIT",
        )?;
        let sequence = records.len() as u64 + 1;
        let previous = records.last().map(|record| record.root).unwrap_or([0; 32]);
        let record = Record {
            sequence,
            previous,
            root: root(sequence, previous, &observation)?,
            observation,
        };
        let raw = canonical(&serde_json::to_value(&record)?)?;
        ensure(
            raw.len() <= MAX_BYTES,
            "TASK_OPERATION_RECONCILIATION_BYTES",
        )?;
        let mut next = records.clone();
        next.push(record.clone());
        let next_head = head(&next)?.ok_or("TASK_OPERATION_RECONCILIATION_HEAD")?;
        self.atomic(|| {
            ensure(
                self.task_operation_pins_v1()? == pins
                    && self.read_task_operation_reconciliations_v2(&pins)? == records,
                "TASK_OPERATION_RECONCILIATION_STALE",
            )?;
            ensure(
                self.active()? == (source.anchor.block, source.anchor.generation),
                "STALE_VIEW",
            )?;
            ensure(
                self.db.execute(
                    "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                    params![format!("{PREFIX}{sequence:016x}"), &raw],
                )? == 1,
                "TASK_OPERATION_RECONCILIATION_WRITE",
            )?;
            let changed = if let Some(prior) = head(&records)? {
                self.db.execute(
                    "UPDATE metadata SET value=?1 WHERE key=?2 AND value=?3",
                    params![&next_head, HEAD, prior],
                )?
            } else {
                self.db.execute(
                    "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                    params![HEAD, &next_head],
                )?
            };
            ensure(
                changed == 1 && self.read_task_operation_reconciliations_v2(&pins)? == next,
                "TASK_OPERATION_RECONCILIATION_WRITE",
            )
            .map_err(Error::local_integrity)
        })?;
        Ok(reconciliation_report(&record, &snapshot))
    }
}
fn reconciliation_report(record: &Record, snapshot: &NativeTaskOperationSnapshotV2) -> Value {
    let mut report = record_report(record);
    report["prospective_native_task_admission"] = json!(true);
    report["native_delivery_verified"] = json!(snapshot.delivery.is_some());
    report["historical_native_payment_verified"] = json!(snapshot.payment.is_some());
    report["current_branch_payment_finality"] = json!(false);
    report["reported_output"] = json!(snapshot
        .completion
        .as_ref()
        .map(|completion| hex::encode(completion.output)));
    report["declared_costs"] = json!(snapshot.costs.as_ref().map(|record| json!({
        "outcome":format!("{:?}",record.outcome),"training_units":record.costs.training_units,
        "evaluation_units":record.costs.evaluation_units,"storage_units":record.costs.storage_units,
        "serving_units":record.costs.serving_units,"unit":hex::encode(record.costs.unit),
        "measurement_receipt":hex::encode(record.costs.measurement_receipt),
    })));
    report
}
