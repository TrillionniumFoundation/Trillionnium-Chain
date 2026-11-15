//! Native Task evidence and a bounded, monotonic reconciliation history.
//!
//! The only inputs are a checked M12 store and claim/contract locators. Funding,
//! delivery commitments and payments are read from this Node's actual retained
//! state and replayed payment owner. Exported JSON is never an import interface.
//! This metadata pays nothing and grants no dispatch or model-install authority.
//! One Node namespace pins one M12 journal history. Restoring both databases and
//! every external fence together remains outside the local anti-rollback claim.
use super::{canonical, Node, StateBackend};
use crate::{ensure, Error, ErrorCode, Result};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use trnm_mvcc_fee::pon_executor::funded_service_v1;
use trnm_protocol::pon_wire::{hash, Hash};
use trnm_service_settlement::native_budget::evidence::{
    NativeBudgetCheckpointV1, NativeBudgetClaimEvidenceV1,
};
use trnm_service_settlement::native_budget::{
    NativeBudgetAnchorV1, NativeBudgetConfigV1, NativeBudgetStoreV1, NativeFundingObservationV1,
    NativeFundingSourceV1, NativePaymentObservationV1, NativePaymentQueryV1,
};

const SCHEMA: &str = "pon-native-task-evidence-v1";
const PREFIX: &str = "pon-native-demand-evidence-v1:event:";
const HEAD: &str = "pon-native-demand-evidence-v1:head";
const MAX_RECORDS: usize = 128;
const MAX_BYTES: usize = 32_768;
const MAX_KEY_BYTES: usize = PREFIX.len() + 16;

#[derive(Clone, Debug)]
pub struct NativeTaskEvidenceRequestV1 {
    pub claim: Hash,
    /// A consumer-supplied monotonic fence, not a clock or a chain epoch proof.
    pub consumer_epoch: u64,
    /// When present, the real task must bind exactly this complete contract.
    pub expected_contract_digest: Option<Hash>,
}

/// Only the native reconciliation method constructs this observation.
#[derive(Clone, Debug)]
pub struct NativeTaskEvidenceV1 {
    record: Record,
    journal: NativeBudgetClaimEvidenceV1,
}
impl NativeTaskEvidenceV1 {
    pub fn sequence(&self) -> u64 {
        self.record.sequence
    }
    pub fn root(&self) -> Hash {
        self.record.root
    }
    pub fn task(&self) -> Hash {
        self.record.observation.task
    }
    pub fn current_payment_confirmed(&self) -> bool {
        self.record.observation.payment_current
    }
    pub fn report(&self) -> Result<Value> {
        let mut report = observation_report(&self.record);
        report["m12"] = self.journal.report().map_err(budget_error)?;
        Ok(report)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    network: Hash,
    parameters: Hash,
    genesis: Hash,
    block: Hash,
    state_root: Hash,
    height: u64,
    generation: u64,
}
impl From<NativeBudgetAnchorV1> for Anchor {
    fn from(value: NativeBudgetAnchorV1) -> Self {
        Self {
            network: value.network,
            parameters: value.parameters,
            genesis: value.genesis,
            block: value.block,
            state_root: value.state_root,
            height: value.height,
            generation: value.generation,
        }
    }
}
impl Anchor {
    fn native(&self) -> NativeBudgetAnchorV1 {
        NativeBudgetAnchorV1 {
            network: self.network,
            parameters: self.parameters,
            genesis: self.genesis,
            block: self.block,
            state_root: self.state_root,
            height: self.height,
            generation: self.generation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    max_records: u32,
    sequence: u64,
    root: Hash,
}
impl Checkpoint {
    fn native(&self, anchor: &Anchor) -> NativeBudgetCheckpointV1 {
        NativeBudgetCheckpointV1 {
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
struct FundingRecord {
    anchor: Anchor,
    row: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payment {
    anchor: Anchor,
    operation: Hash,
    gross_escrow_debit: u64,
    beneficiary_credit: u64,
}
impl Payment {
    fn from_native(value: &NativePaymentObservationV1) -> Self {
        Self {
            anchor: value.anchor.into(),
            operation: value.operation,
            gross_escrow_debit: value.gross_escrow_debit,
            beneficiary_credit: value.beneficiary_credit,
        }
    }
    fn query(&self, observation: &Observation) -> NativePaymentQueryV1 {
        NativePaymentQueryV1 {
            source: NativeFundingSourceV1::Task(observation.task),
            subject: observation.subject,
            beneficiary: observation.beneficiary,
            operation: self.operation,
            maximum_gross_units: observation.monetary_reservation,
        }
    }
    fn matches(&self, observed: &NativePaymentObservationV1) -> bool {
        self.operation == observed.operation
            && self.gross_escrow_debit == observed.gross_escrow_debit
            && self.beneficiary_credit == observed.beneficiary_credit
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    schema: String,
    task: Hash,
    claim: Hash,
    budget: Hash,
    subject: Hash,
    beneficiary: Hash,
    monetary_reservation: u64,
    binding_digest: Hash,
    evidence_digest: Hash,
    consumer_epoch: u64,
    contract_digest: Option<Hash>,
    anchor: Anchor,
    checkpoint: Checkpoint,
    funding: Vec<FundingRecord>,
    current_row: Option<Value>,
    payment: Option<Payment>,
    payment_current: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    sequence: u64,
    previous: Hash,
    root: Hash,
    observation: Observation,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    sequence: u64,
    root: Hash,
}

fn budget_error(error: impl std::fmt::Display) -> Error {
    Error::from(format!("NATIVE_DEMAND_BUDGET:{error}"))
}
fn record_root(sequence: u64, previous: Hash, observation: &Observation) -> Result<Hash> {
    Ok(hash(
        b"pon-native-demand-evidence-record-v1",
        &[
            &previous,
            &sequence.to_le_bytes(),
            &canonical(&serde_json::to_value(observation)?)?,
        ],
    ))
}
fn head(records: &[Record]) -> Result<Option<Vec<u8>>> {
    records
        .last()
        .map(|record| {
            canonical(&serde_json::to_value(Head {
                sequence: record.sequence,
                root: record.root,
            })?)
        })
        .transpose()
}
fn observation_report(record: &Record) -> Value {
    let observed = &record.observation;
    json!({
        "schema":SCHEMA,
        "sequence":record.sequence,
        "root":hex::encode(record.root),
        "consumer_epoch":observed.consumer_epoch,
        "task":hex::encode(observed.task),
        "contract_digest":observed.contract_digest.map(hex::encode),
        "anchor":observed.anchor,
        "m12_checkpoint":observed.checkpoint,
        "m12_binding_digest":hex::encode(observed.binding_digest),
        "m12_evidence_digest":hex::encode(observed.evidence_digest),
        "funding_observations":observed.funding,
        "current_task":observed.current_row,
        "historical_payment":observed.payment,
        "payment_current_on_observed_branch":observed.payment_current,
        "native_funding_verified":true,
        "complete_contract_bound":observed.contract_digest.is_some(),
        "current_delivery_matches_claim":observed.current_row.as_ref().is_some_and(|row| row["output"] == hex::encode(observed.subject)),
        "historical_payment_verified":observed.payment.is_some(),
        "output_bytes_verified":false,
        "physical_costs_verified":false,
        "independent_customer_verified":false,
        "independent_evaluator_verified":false,
        "external_demand_verified":false,
        "prospective_training_admission":false,
        "learning_bonus_authorized":false,
        "execution_authority":false,
        "production_activation":false,
    })
}

impl Node {
    fn write_demand_metadata_v1(&self, write: impl FnOnce() -> Result<()>) -> Result<()> {
        if self.state_backend != StateBackend::PermanentAccountGrowthV2 {
            return self.atomic(write);
        }
        // Growth has a bounded working state and a separate permanent-account
        // root. The complete-State writer's slot/continuity checker cannot
        // validate this backend. Keep its cold-audited owner, epoch and one
        // Immediate transaction, and rebind the actual Growth root on both
        // sides of the metadata write without enumerating permanent accounts.
        self.growth_observation_epoch()?;
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let before = self.growth_snapshot_in_read()?;
        let slot = self.slot()?;
        write()?;
        let after = self.growth_snapshot_in_read()?;
        ensure(
            before.block == after.block
                && before.generation == after.generation
                && before.height == after.height
                && before.commitment == after.commitment
                && before.working == after.working
                && slot == self.slot()?,
            "NATIVE_DEMAND_GROWTH_WRITE",
        )
        .map_err(Error::local_integrity)?;
        self.continuous_scope_checkpoint()?;
        self.mining_scope_checkpoint()?;
        self.growth_observation_epoch()?;
        transaction.commit()?;
        // A foreign commit becomes visible to data_version after COMMIT.
        self.growth_observation_epoch()
    }

    fn read_native_demand_evidence_v1(&self) -> Result<Vec<Record>> {
        let mut query = self.db.prepare(
            "SELECT typeof(key),length(CAST(key AS BLOB)),substr(CAST(key AS BLOB),1,?3),typeof(value),length(value),substr(value,1,?1) FROM metadata WHERE key GLOB 'pon-native-demand-evidence-v1:*' ORDER BY key LIMIT ?2",
        )?;
        let rows = query
            .query_map(
                params![MAX_BYTES + 1, MAX_RECORDS + 2, MAX_KEY_BYTES + 1],
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
        ensure(rows.len() <= MAX_RECORDS + 1, "NATIVE_DEMAND_RECORD_LIMIT")?;
        let mut records: Vec<Record> = Vec::new();
        let mut retained_head = None;
        let mut bindings: BTreeMap<Hash, &Observation> = BTreeMap::new();
        for (key_kind, key_length, key_raw, kind, length, raw) in rows {
            ensure(
                key_kind == "text"
                    && key_length <= MAX_KEY_BYTES
                    && key_raw.len() == key_length
                    && key_raw.is_ascii(),
                "NATIVE_DEMAND_KEY",
            )?;
            let key = String::from_utf8(key_raw).map_err(|_| "NATIVE_DEMAND_KEY")?;
            ensure(
                kind == "blob" && length <= MAX_BYTES && raw.len() == length,
                "NATIVE_DEMAND_BYTES",
            )?;
            if key == HEAD {
                retained_head = Some(raw);
                continue;
            }
            let record: Record = serde_json::from_slice(&raw).map_err(|_| "NATIVE_DEMAND_CODEC")?;
            let sequence = records.len() as u64 + 1;
            let previous = records.last().map(|prior| prior.root).unwrap_or([0; 32]);
            ensure(
                key == format!("{PREFIX}{sequence:016x}")
                    && record.sequence == sequence
                    && record.previous == previous
                    && record.root == record_root(sequence, previous, &record.observation)?
                    && raw == canonical(&serde_json::to_value(&record)?)?,
                "NATIVE_DEMAND_RECORD_BINDING",
            )?;
            self.validate_demand_observation_v1(&record.observation)?;
            if let Some(prior) = records.last() {
                check_progress(&prior.observation, &record.observation)?;
            }
            records.push(record);
        }
        ensure(retained_head == head(&records)?, "NATIVE_DEMAND_HEAD")?;
        for record in &records {
            let observed = &record.observation;
            if let Some(prior) = bindings.insert(observed.task, observed) {
                check_binding(prior, observed)?;
            }
        }
        Ok(records)
    }

    fn native_demand_records_v1(&self) -> Result<Vec<Record>> {
        self.read_native_demand_evidence_v1()
            .map_err(Error::local_integrity)
    }

    fn validate_demand_anchor_v1(&self, anchor: &Anchor) -> Result<()> {
        self.validate_native_active_anchor_v1(&anchor.native())
    }

    fn demand_task_at_v1(&self, anchor: &Anchor, task: Hash) -> Result<Option<Value>> {
        self.validate_demand_anchor_v1(anchor)?;
        let state = if self.state_backend == StateBackend::PermanentAccountGrowthV2 {
            self.growth_working(anchor.block)?
        } else {
            self.state_at(anchor.block)?
        };
        Ok(state.get(&NativeFundingSourceV1::Task(task).key()).cloned())
    }

    fn demand_contract_v1(&self, task: Hash, row: &Value) -> Result<Option<Hash>> {
        Ok(
            funded_service_v1::read_contract(task, row, &self.settings.app)?
                .map(|contract| contract.contract_digest),
        )
    }

    fn validate_demand_observation_v1(&self, observed: &Observation) -> Result<()> {
        ensure(
            observed.schema == SCHEMA
                && observed.claim != [0; 32]
                && observed.budget != [0; 32]
                && observed.subject != [0; 32]
                && observed.monetary_reservation > 0
                && (2..=3).contains(&observed.funding.len())
                && (1..=65_536).contains(&observed.checkpoint.max_records)
                && (2..=u64::from(observed.checkpoint.max_records) * 7)
                    .contains(&observed.checkpoint.sequence)
                && (!observed.payment_current || observed.payment.is_some()),
            "NATIVE_DEMAND_RECORD",
        )?;
        self.validate_demand_anchor_v1(&observed.anchor)?;
        for funding in &observed.funding {
            self.validate_demand_anchor_v1(&funding.anchor)?;
            ensure(
                self.demand_contract_v1(observed.task, &funding.row)? == observed.contract_digest
                    && funding.row["provider"] == hex::encode(observed.beneficiary),
                "NATIVE_DEMAND_CONTRACT",
            )?;
        }
        if let Some(row) = &observed.current_row {
            ensure(
                self.demand_contract_v1(observed.task, row)? == observed.contract_digest
                    && row["owner"] == observed.funding[0].row["owner"]
                    && row["provider"] == hex::encode(observed.beneficiary),
                "NATIVE_DEMAND_CONTRACT",
            )?;
        }
        if let Some(payment) = &observed.payment {
            self.validate_demand_anchor_v1(&payment.anchor)?;
            ensure(
                payment.operation != [0; 32]
                    && payment.gross_escrow_debit > 0
                    && payment.gross_escrow_debit <= observed.monetary_reservation
                    && payment.beneficiary_credit == payment.gross_escrow_debit,
                "NATIVE_DEMAND_PAYMENT",
            )?;
        }
        Ok(())
    }

    fn validate_demand_native_history_v1(&self, records: &[Record]) -> Result<()> {
        // Exact native state and replay stay authoritative after a restart.
        for record in records {
            let observed = &record.observation;
            for funding in &observed.funding {
                ensure(
                    self.demand_task_at_v1(&funding.anchor, observed.task)?
                        == Some(funding.row.clone()),
                    "NATIVE_DEMAND_FUNDING_HISTORY",
                )?;
            }
            ensure(
                self.demand_task_at_v1(&observed.anchor, observed.task)? == observed.current_row,
                "NATIVE_DEMAND_TASK_HISTORY",
            )?;
            if let Some(payment) = &observed.payment {
                let query = payment.query(observed);
                let historical =
                    self.native_payment_observation_at_anchor_v1(&query, payment.anchor.native())?;
                ensure(
                    payment.matches(&historical),
                    "NATIVE_DEMAND_PAYMENT_HISTORY",
                )?;
                match self.native_payment_observation_at_anchor_v1(&query, observed.anchor.native())
                {
                    Ok(current) => ensure(
                        observed.payment_current && payment.matches(&current),
                        "NATIVE_DEMAND_PAYMENT_HISTORY",
                    )?,
                    Err(error) if error.is(ErrorCode::NativePaymentNotConfirmed) => {
                        ensure(!observed.payment_current, "NATIVE_DEMAND_PAYMENT_HISTORY")?;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    pub(super) fn validate_native_demand_evidence_v1(&self) -> Result<()> {
        self.validate_demand_native_history_v1(&self.native_demand_records_v1()?)
            .map_err(Error::local_integrity)
    }

    /// Retained native observations, not a claim of freshness or a new payment.
    /// The external M12 journal must be supplied to reconciliation before reuse.
    pub fn native_task_evidence_history_v1(&self) -> Result<Value> {
        self.ready()?;
        let records = self.native_demand_records_v1()?;
        self.validate_demand_native_history_v1(&records)?;
        Ok(json!({
            "schema":"pon-native-task-evidence-history-v1",
            "records":records.iter().map(observation_report).collect::<Vec<_>>(),
            "m12_current_journal_rechecked":false,
            "execution_authority":false,
            "production_activation":false,
        }))
    }

    /// Check all real owners and persist one exact observation. A reorg changes
    /// current membership, never the historical payment or operation identity.
    /// Repeated identical observations return the same retained record.
    pub fn reconcile_native_task_evidence_v1(
        &mut self,
        store: &NativeBudgetStoreV1,
        request: NativeTaskEvidenceRequestV1,
    ) -> Result<NativeTaskEvidenceV1> {
        self.ready()?;
        let records = self.native_demand_records_v1()?;
        self.validate_demand_native_history_v1(&records)?;
        if let Some(last) = records.last() {
            ensure(
                request.consumer_epoch >= last.observation.consumer_epoch,
                "NATIVE_DEMAND_EPOCH",
            )?;
        }
        let retained_checkpoint = records
            .last()
            .map(|last| last.observation.checkpoint.native(&last.observation.anchor));
        let journal = store
            .claim_evidence_after_v1(request.claim, retained_checkpoint.as_ref())
            .map_err(budget_error)?;
        let checkpoint = journal.checkpoint();
        ensure(
            checkpoint.configuration.network == self.settings.network()
                && checkpoint.configuration.parameters == self.settings.parameters()
                && checkpoint.configuration.genesis == self.settings.genesis(),
            "NATIVE_DEMAND_CONTEXT",
        )?;
        let NativeFundingSourceV1::Task(task) = journal.policy().source else {
            return Err("NATIVE_DEMAND_TASK_REQUIRED".into());
        };
        let current = self.native_funding_observation(journal.policy().source)?;
        let mut funding_records = Vec::new();
        let mut contract_digest = None;
        for retained in journal.funding_observations() {
            let anchor: Anchor = retained.anchor().into();
            let row = self.demand_task_at_v1(&anchor, task)?;
            retained
                .verify_observation(&NativeFundingObservationV1 {
                    anchor: retained.anchor(),
                    source: retained.source(),
                    row: row.clone(),
                })
                .map_err(budget_error)?;
            let row = row.ok_or("NATIVE_DEMAND_FUNDING_HISTORY")?;
            let actual_contract = self.demand_contract_v1(task, &row)?;
            if funding_records.is_empty() {
                contract_digest = actual_contract;
            } else {
                ensure(actual_contract == contract_digest, "NATIVE_DEMAND_CONTRACT")?;
            }
            funding_records.push(FundingRecord { anchor, row });
        }
        ensure(
            request
                .expected_contract_digest
                .is_none_or(|expected| Some(expected) == contract_digest),
            "NATIVE_DEMAND_CONTRACT",
        )?;
        let mut observation = Observation {
            schema: SCHEMA.into(),
            task,
            claim: request.claim,
            budget: journal.policy().budget,
            subject: journal.claim().subject,
            beneficiary: journal.claim().beneficiary,
            monetary_reservation: journal.claim().monetary_reservation,
            binding_digest: journal.binding_digest().map_err(budget_error)?,
            evidence_digest: journal.evidence_digest().map_err(budget_error)?,
            consumer_epoch: request.consumer_epoch,
            contract_digest,
            anchor: current.anchor.into(),
            checkpoint: Checkpoint {
                max_records: checkpoint.configuration.max_records,
                sequence: checkpoint.sequence,
                root: checkpoint.root,
            },
            funding: funding_records,
            current_row: current.row,
            payment: journal.historical_payment().map(Payment::from_native),
            payment_current: false,
        };
        if let Some(payment) = &observation.payment {
            let query = payment.query(&observation);
            let historical =
                self.native_payment_observation_at_anchor_v1(&query, payment.anchor.native())?;
            ensure(
                payment.matches(&historical),
                "NATIVE_DEMAND_PAYMENT_HISTORY",
            )?;
            match self.native_payment_observation(&query) {
                Ok(actual) => {
                    ensure(
                        actual.anchor == current.anchor && payment.matches(&actual),
                        "NATIVE_DEMAND_PAYMENT_CURRENT",
                    )?;
                    observation.payment_current = true;
                }
                Err(error) if error.is(ErrorCode::NativePaymentNotConfirmed) => {}
                Err(error) => return Err(error),
            }
        }
        if contract_digest.is_some() {
            // A generic M12 owner callback can quote real funding facts without
            // using this Node's authorization path. Native V1 operation evidence
            // for a TSC1 Task additionally requires the actual retained V1 pin.
            self.require_native_task_budget_version_v1(task)?;
        }
        self.validate_demand_observation_v1(&observation)?;
        // This also fences a negative payment lookup, which returns an error
        // instead of an anchor. It must describe the same current generation.
        ensure(
            self.native_funding_observation(journal.policy().source)?
                .anchor
                == current.anchor,
            "STALE_VIEW",
        )?;
        // Replays recheck the live prefix too; they are not cached authority.
        store
            .verify_evidence_checkpoint_v1(checkpoint)
            .map_err(budget_error)?;
        if let Some(last) = records.last() {
            check_progress(&last.observation, &observation)?;
        }
        if let Some(prior) = records
            .iter()
            .rev()
            .find(|record| record.observation.task == task)
        {
            check_binding(&prior.observation, &observation)?;
            if prior.observation == observation {
                return Ok(NativeTaskEvidenceV1 {
                    record: prior.clone(),
                    journal,
                });
            }
        }
        ensure(records.len() < MAX_RECORDS, "NATIVE_DEMAND_RECORD_LIMIT")?;
        let sequence = records.len() as u64 + 1;
        let previous = records.last().map(|record| record.root).unwrap_or([0; 32]);
        let record = Record {
            sequence,
            previous,
            root: record_root(sequence, previous, &observation)?,
            observation,
        };
        let raw = canonical(&serde_json::to_value(&record)?)?;
        ensure(raw.len() <= MAX_BYTES, "NATIVE_DEMAND_BYTES")?;
        let mut next = records.clone();
        next.push(record.clone());
        let next_head = head(&next)?.ok_or("NATIVE_DEMAND_HEAD")?;
        self.write_demand_metadata_v1(|| {
            ensure(
                self.native_demand_records_v1()? == records,
                "NATIVE_DEMAND_STALE_HISTORY",
            )?;
            ensure(
                self.active()? == (current.anchor.block, current.anchor.generation),
                "STALE_VIEW",
            )?;
            ensure(
                self.db.execute(
                    "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                    params![format!("{PREFIX}{sequence:016x}"), &raw],
                )? == 1,
                "NATIVE_DEMAND_WRITE",
            )?;
            let changed = if let Some(prior_head) = head(&records)? {
                self.db.execute(
                    "UPDATE metadata SET value=?1 WHERE key=?2 AND value=?3",
                    params![&next_head, HEAD, prior_head],
                )?
            } else {
                self.db.execute(
                    "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                    params![HEAD, &next_head],
                )?
            };
            ensure(
                changed == 1 && self.native_demand_records_v1()? == next,
                "NATIVE_DEMAND_WRITE",
            )
            .map_err(Error::local_integrity)
        })?;
        Ok(NativeTaskEvidenceV1 { record, journal })
    }
}

fn check_progress(prior: &Observation, next: &Observation) -> Result<()> {
    ensure(
        next.consumer_epoch >= prior.consumer_epoch
            && next.anchor.generation >= prior.anchor.generation
            && (next.anchor.generation != prior.anchor.generation || next.anchor == prior.anchor)
            && next.checkpoint.max_records == prior.checkpoint.max_records
            && next.checkpoint.sequence >= prior.checkpoint.sequence
            && (next.checkpoint.sequence != prior.checkpoint.sequence
                || next.checkpoint.root == prior.checkpoint.root),
        "NATIVE_DEMAND_PROGRESS",
    )
}
fn check_binding(prior: &Observation, next: &Observation) -> Result<()> {
    ensure(
        prior.claim == next.claim
            && prior.budget == next.budget
            && prior.subject == next.subject
            && prior.beneficiary == next.beneficiary
            && prior.monetary_reservation == next.monetary_reservation
            && prior.binding_digest == next.binding_digest
            && prior.contract_digest == next.contract_digest
            && prior
                .payment
                .as_ref()
                .is_none_or(|payment| Some(payment) == next.payment.as_ref()),
        "NATIVE_DEMAND_REBIND",
    )
}
