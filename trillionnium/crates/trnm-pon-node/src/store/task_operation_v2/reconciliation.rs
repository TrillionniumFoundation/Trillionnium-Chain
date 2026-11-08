//! Node-retained V2 journal prefix floors. No monetary ledger is added.
use super::*;
use trnm_protocol::funded_service_task_v1::FundedServiceContractV1;
use trnm_service_settlement::native_budget::task_operation_v2::{
    NativeTaskOperationCheckpointV2, NativeTaskOperationSnapshotV2, NativeTaskOperationStoreV2,
};
use trnm_service_settlement::native_budget::{
    NativeBudgetConfigV1, NativePaymentObservationV1, NativePaymentQueryV1,
};

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
    /// Read the original paid Task, provider receipt and monetary transition on
    /// one currently selected native branch. Full expected terms select the
    /// intended work; neither those terms nor this report grant target access.
    ///
    /// This read-only V3 observation requires an already reconciled V2 journal
    /// head and its exact latest declared consumer epoch. It cannot advance a
    /// journal floor, begin gate or epoch. This complete current Task view needs
    /// the original row to remain present. Native mandatory cleanup removes a
    /// zero-remaining Task strictly after its dispute deadline. Its historical
    /// payment can still be a current-branch fact, but an absent, refunded or
    /// expired Task cannot satisfy this deliberately narrower paid-Task view.
    ///
    /// Node and M12 are separate owners. The final checks establish a bounded
    /// observation, not atomic external FinalUse, future freshness, independent
    /// demand, physical metering or consensus weight. Exported JSON has no
    /// authenticated import path and is never an execution/payment capability.
    pub fn observe_current_native_task_operation_v3(
        &self,
        store: &NativeTaskOperationStoreV2,
        expected_binding: &NativeTaskOperationBindingV2,
        expected_contract: &FundedServiceContractV1,
        consumer_epoch: u64,
    ) -> Result<Value> {
        self.ready()?;
        expected_binding.id().map_err(budget_error)?;
        expected_contract
            .validate()
            .map_err(|_| "TASK_OPERATION_CURRENT_EXPECTATION_V3")?;
        let selected = self.active()?;
        let pins = self.task_operation_pins_v1()?;
        self.validate_task_operation_history_v1(&pins)?;
        let records = self
            .read_task_operation_reconciliations_v2(&pins)
            .map_err(Error::local_integrity)?;
        let last = records
            .last()
            .ok_or("TASK_OPERATION_CURRENT_RECONCILIATION_REQUIRED_V3")?;
        ensure(
            consumer_epoch == last.observation.consumer_epoch,
            "TASK_OPERATION_CURRENT_EPOCH_V3",
        )?;
        let binding_id = expected_binding.id().map_err(budget_error)?;
        ensure(
            records.iter().any(|record| {
                record.observation.claim == expected_binding.claim
                    && record.observation.task == expected_binding.task
                    && record.observation.binding == binding_id
            }),
            "TASK_OPERATION_CURRENT_RECONCILIATION_REQUIRED_V3",
        )?;
        let expected_checkpoint = last.observation.checkpoint.native(&last.observation.anchor);
        let (snapshot, checkpoint) = store
            .snapshot_after_checkpoint(expected_binding.claim, Some(&expected_checkpoint))
            .map_err(budget_error)?;
        ensure(
            checkpoint == expected_checkpoint,
            "TASK_OPERATION_CURRENT_UNRECONCILED_HEAD_V3",
        )?;
        ensure(
            snapshot.binding == *expected_binding,
            "TASK_OPERATION_CURRENT_EXPECTATION_V3",
        )?;
        self.verify_operation_snapshot_v2(&snapshot, &pins)?;

        let source =
            self.native_funding_observation(NativeFundingSourceV1::Task(expected_binding.task))?;
        ensure(
            (source.anchor.block, source.anchor.generation) == selected,
            "STALE_VIEW",
        )?;
        let row = source
            .row
            .as_ref()
            .ok_or("TASK_OPERATION_CURRENT_SOURCE_ABSENT_V3")?;
        let contract =
            funded_service_v1::read_contract(expected_binding.task, row, &self.settings.app)?
                .ok_or("TASK_OPERATION_CONTRACT_REQUIRED")?;
        ensure(
            contract.terms == *expected_contract
                && contract.contract_digest == expected_binding.contract_digest,
            "TASK_OPERATION_CURRENT_EXPECTATION_V3",
        )?;
        let current = self.contract_operation_from_native_v2(expected_binding, source)?;
        ensure(
            current.status == NativeTaskStatusV2::Settled && current.remaining == 0,
            "TASK_OPERATION_CURRENT_NOT_PAID_V3",
        )?;
        let completion = snapshot
            .completion
            .as_ref()
            .ok_or("TASK_OPERATION_CURRENT_COMPLETION_REQUIRED_V3")?;
        let historical_delivery = snapshot
            .delivery
            .as_ref()
            .ok_or("TASK_OPERATION_CURRENT_DELIVERY_REQUIRED_V3")?;
        let delivery = self.read_delivery_for_contract_v2(expected_binding, current)?;
        ensure(
            delivery.contract.output == Some(completion.output)
                && delivery.receipt_operation == historical_delivery.receipt_operation,
            "TASK_OPERATION_CURRENT_DELIVERY_IDENTITY_V3",
        )?;
        let historical_payment = snapshot
            .payment
            .as_ref()
            .ok_or("TASK_OPERATION_CURRENT_PAYMENT_REQUIRED_V3")?;
        let payment = self.native_payment_observation_at_anchor_v1(
            &NativePaymentQueryV1 {
                source: NativeFundingSourceV1::Task(expected_binding.task),
                subject: completion.output,
                beneficiary: expected_binding.beneficiary,
                operation: historical_payment.operation,
                maximum_gross_units: snapshot.reserved.amount,
            },
            delivery.contract.anchor,
        )?;
        ensure(
            payment.anchor == delivery.contract.anchor
                && payment.source == historical_payment.source
                && payment.subject == historical_payment.subject
                && payment.beneficiary == historical_payment.beneficiary
                && payment.operation == historical_payment.operation
                && payment.gross_escrow_debit == historical_payment.gross_escrow_debit
                && payment.beneficiary_credit == historical_payment.beneficiary_credit,
            "TASK_OPERATION_CURRENT_PAYMENT_IDENTITY_V3",
        )?;

        let report = json!({
            "schema":"pon-native-task-operation-current-v3",
            "scope":"CURRENT_PAID_NATIVE_TASK_OBSERVATION",
            "claim":hex::encode(expected_binding.claim),
            "task":hex::encode(expected_binding.task),
            "binding":hex::encode(binding_id),
            "operation":hex::encode(expected_binding.operation),
            "target_scope_commitment":hex::encode(expected_binding.target_scope),
            "target_receipt_commitment":hex::encode(completion.target_receipt),
            "declared_reconciliation_epoch":consumer_epoch,
            "retained_reconciliation_sequence":last.sequence,
            "retained_reconciliation_root":hex::encode(last.root),
            "m12_checkpoint":last.observation.checkpoint,
            "observed_anchor":Anchor::from(delivery.contract.anchor),
            "original_full_contract":contract,
            "native_status":"settled",
            "remaining_native_escrow":delivery.contract.remaining,
            "output":hex::encode(completion.output),
            "original_delivery_operation":hex::encode(historical_delivery.receipt_operation),
            "historical_delivery_anchor":Anchor::from(historical_delivery.receipt_anchor),
            "current_delivery_anchor":Anchor::from(delivery.receipt_anchor),
            "historical_payment":current_payment_report_v3(historical_payment),
            "current_payment":current_payment_report_v3(&payment),
            "current_branch_delivery_membership":true,
            "current_branch_payment_membership":true,
            "current_branch_payment_finality":false,
            "declared_costs":reconciliation_report(last, &snapshot)["declared_costs"],
            "physical_costs_verified":false,
            "independent_customer_verified":false,
            "external_budget_origin_verified":false,
            "authenticated_target_authorization":false,
            "authenticated_target_receipt":false,
            "current_consumer_authorization_verified":false,
            "actual_consumer_use_verified":false,
            "atomic_external_final_use":false,
            "learning_improvement_bonus":false,
            "execution_authority":false,
            "authorizes_native_payment":false,
            "consensus_weight_eligible":false,
            "chainwork_awarded":0,
            "production_activation":false,
        });
        ensure(
            canonical(&report)?.len() <= 32_768,
            "TASK_OPERATION_CURRENT_REPORT_BYTES_V3",
        )?;
        // verify_checkpoint accepts retained prefixes. Its returned *current*
        // head must still equal this snapshot, not merely contain it.
        ensure(
            store.verify_checkpoint(&checkpoint).map_err(budget_error)? == checkpoint,
            "TASK_OPERATION_CURRENT_JOURNAL_CHANGED_V3",
        )?;
        self.ready()?;
        ensure(
            self.task_operation_pins_v1()? == pins
                && self.read_task_operation_reconciliations_v2(&pins)? == records,
            "TASK_OPERATION_CURRENT_OWNER_CHANGED_V3",
        )?;
        ensure(self.active()? == selected, "STALE_VIEW")?;
        Ok(report)
    }

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
fn current_payment_report_v3(payment: &NativePaymentObservationV1) -> Value {
    json!({
        "anchor":Anchor::from(payment.anchor),
        "source":payment.source.key(),
        "subject":hex::encode(payment.subject),
        "beneficiary":hex::encode(payment.beneficiary),
        "operation":hex::encode(payment.operation),
        "gross_escrow_debit":payment.gross_escrow_debit,
        "beneficiary_credit":payment.beneficiary_credit,
    })
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
