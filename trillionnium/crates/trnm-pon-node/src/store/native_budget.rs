//! Existing Node writer's durable local obligations, bound to actual M06 funds.
//! These records observe escrow; they neither lock it on chain nor pay/dispatch.
use super::{canonical, Node};
use crate::{ensure, Error, Result};
use rusqlite::params;
use std::collections::BTreeMap;
use trnm_protocol::pon_wire::Hash;

#[path = "native_budget_relation.rs"]
mod relation;
use relation::{funding, head, source_key, validate_record, validate_totals, verify_payee, Record};
pub use relation::{
    NativeBudgetInventoryV1, NativeBudgetLaneV1, NativeBudgetLocalRecordV1,
    NativeBudgetObservationV1, NativeBudgetRequestV1, NativeContributionClaimV1,
};

const SCHEMA: &str = "pon-native-budget-obligation-v1";
const PREFIX: &str = "pon-native-budget-v1:op:";
const HEAD: &str = "pon-native-budget-v1:head";
const MAX_RECORDS: usize = 128;
const MAX_BYTES: usize = 8192;
const MAX_KEY_BYTES: usize = PREFIX.len() + 64;

impl Node {
    fn native_budget_records_v1(&self) -> Result<BTreeMap<String, Record>> {
        self.read_native_budget_records_v1()
            .map_err(Error::local_integrity)
    }

    fn read_native_budget_records_v1(&self) -> Result<BTreeMap<String, Record>> {
        let mut rows = self.db.prepare(
            "SELECT typeof(key),length(CAST(key AS BLOB)),substr(CAST(key AS BLOB),1,?3),typeof(value),length(value),substr(value,1,?1) FROM metadata WHERE key GLOB 'pon-native-budget-v1:*' ORDER BY key LIMIT ?2")?;
        let rows = rows
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
        ensure(rows.len() <= MAX_RECORDS + 1, "BUDGET_RECORD_LIMIT")?;
        let mut records = BTreeMap::new();
        let mut retained_head = None;
        for (key_kind, key_length, key_raw, kind, length, raw) in rows {
            ensure(
                key_kind == "text"
                    && key_length <= MAX_KEY_BYTES
                    && key_raw.len() == key_length
                    && key_raw.is_ascii(),
                "BUDGET_RECORD_KEY",
            )?;
            let key = String::from_utf8(key_raw).map_err(|_| Error::from("BUDGET_RECORD_KEY"))?;
            ensure(
                kind == "blob" && length <= MAX_BYTES && raw.len() == length,
                "BUDGET_RECORD_BYTES",
            )?;
            if key == HEAD {
                retained_head = Some(raw);
                continue;
            }
            let record: Record =
                serde_json::from_slice(&raw).map_err(|_| Error::from("BUDGET_RECORD_CODEC"))?;
            ensure(
                key == format!("{PREFIX}{}", hex::encode(record.request.operation))
                    && raw == canonical(&serde_json::to_value(&record)?)?,
                "BUDGET_RECORD_BINDING",
            )?;
            validate_record(self, &record)?;
            records.insert(key, record);
        }
        ensure(
            (records.is_empty() && retained_head.is_none())
                || retained_head == Some(head(&records)?),
            "BUDGET_RECORD_SET",
        )?;
        validate_totals(&records)?;
        Ok(records)
    }

    pub(super) fn validate_native_budget_records_v1(&self) -> Result<()> {
        self.validate_native_budget_sources_v1(&self.native_budget_records_v1()?)
    }

    fn validate_native_budget_sources_v1(&self, records: &BTreeMap<String, Record>) -> Result<()> {
        (|| {
            for record in records.values() {
                let original = self.state_at(record.source_tip)?;
                let value = original
                    .get(&source_key(&record.request))
                    .ok_or("BUDGET_SOURCE_HISTORY")?;
                verify_payee(value, &record.request)?;
                let actual = funding(value, record.request.lane)?;
                ensure(
                    actual == record.funding
                        && self.record(record.source_tip)?.height == record.source_height,
                    "BUDGET_SOURCE_HISTORY",
                )?;
            }
            Ok(())
        })()
        .map_err(Error::local_integrity)
    }

    /// Read exact retained intents for the existing effect owner's recovery.
    /// No current-funding decision or target-side reconciliation is performed.
    pub fn native_budget_inventory_v1(&self) -> Result<NativeBudgetInventoryV1> {
        self.ready()?;
        let records = self.native_budget_records_v1()?;
        self.validate_native_budget_sources_v1(&records)?;
        Ok(NativeBudgetInventoryV1 {
            schema: "pon-native-budget-local-inventory-v1",
            network: self.settings.network(),
            parameters: self.settings.parameters(),
            genesis: self.settings.genesis(),
            records: records
                .into_values()
                .map(|record| NativeBudgetLocalRecordV1 {
                    request: record.request,
                    source_tip: record.source_tip,
                    source_generation: record.source_generation,
                    source_height: record.source_height,
                    source_funding_digest: record.funding.digest,
                    resources_consumed: record.consumed,
                    effect: record.effect,
                    receipt: record.receipt,
                })
                .collect(),
            chain_funds_locked: false,
            payment_executed: false,
            execution_authority: false,
            production_activation: false,
        })
    }

    /// `None` means local absence only, never proof that a target did no work.
    /// The entire bounded set is checked even when this operation is absent.
    pub fn native_budget_operation_v1(
        &self,
        operation: Hash,
    ) -> Result<Option<NativeBudgetLocalRecordV1>> {
        Ok(self
            .native_budget_inventory_v1()?
            .records
            .into_iter()
            .find(|record| record.request.operation == operation))
    }

    fn native_budget_source_current_v1(
        &self,
        record: &Record,
        records: &BTreeMap<String, Record>,
    ) -> Result<bool> {
        self.ready()?;
        let (tip, generation, state) = self.read_active()?;
        let height = self.record(tip)?.height;
        let canonical_source = crate::ancestry_index::contains(
            &self.db,
            self.ancestry_context()?,
            tip,
            record.source_tip,
            crate::ancestry_index::READ_SQL_BUDGET,
            &mut |_| Ok(()),
        )?;
        let current = state
            .get(&source_key(&record.request))
            .and_then(|row| funding(row, record.request.lane).ok());
        let held = records
            .values()
            .filter(|r| source_key(&r.request) == source_key(&record.request))
            .try_fold(0u64, |sum, row| {
                sum.checked_add(row.request.amount).ok_or("BUDGET_AMOUNT")
            })?;
        ensure(self.active()? == (tip, generation), "STALE_VIEW")?;
        Ok(canonical_source
            && current.as_ref() == Some(&record.funding)
            && held <= record.funding.remaining
            && height >= record.funding.maturity
            && record
                .funding
                .deadline
                .is_none_or(|deadline| height < deadline))
    }

    fn native_budget_observation_v1(
        &self,
        record: &Record,
        records: &BTreeMap<String, Record>,
    ) -> Result<NativeBudgetObservationV1> {
        Ok(NativeBudgetObservationV1 {
            operation: record.request.operation,
            funding_current: self.native_budget_source_current_v1(record, records)?,
            resources_consumed: record.consumed,
            effect_pending: record.effect.is_some() && record.receipt.is_none(),
            effect_completed: record.receipt.is_some(),
            durable_records: records.len(),
            chain_funds_locked: false,
            payment_executed: false,
            execution_authority: false,
            production_activation: false,
        })
    }

    fn write_native_budget_record_v1(
        &self,
        records: &BTreeMap<String, Record>,
        record: &Record,
    ) -> Result<()> {
        let key = format!("{PREFIX}{}", hex::encode(record.request.operation));
        validate_record(self, record)?;
        let raw = canonical(&serde_json::to_value(record)?)?;
        ensure(raw.len() <= MAX_BYTES, "BUDGET_RECORD_BYTES")?;
        let mut next = records.clone();
        next.insert(key.clone(), record.clone());
        ensure(next.len() <= MAX_RECORDS, "BUDGET_RECORD_LIMIT")?;
        validate_record(self, record)?;
        validate_totals(&next)?;
        let next_head = head(&next)?;
        self.atomic(|| {
            let changed = if let Some(prior) = records.get(&key) {
                self.db.execute(
                    "UPDATE metadata SET value=?1 WHERE key=?2 AND value=?3",
                    params![&raw, &key, canonical(&serde_json::to_value(prior)?)?],
                )?
            } else {
                self.db.execute(
                    "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                    params![&key, &raw],
                )?
            };
            ensure(changed == 1, "BUDGET_WRITE").map_err(Error::local_integrity)?;
            let changed = if records.is_empty() {
                self.db.execute(
                    "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                    params![HEAD, &next_head],
                )?
            } else {
                self.db.execute(
                    "UPDATE metadata SET value=?1 WHERE key=?2 AND value=?3",
                    params![&next_head, HEAD, head(records)?],
                )?
            };
            ensure(
                changed == 1 && self.native_budget_records_v1()? == next,
                "BUDGET_WRITE",
            )
            .map_err(Error::local_integrity)
        })
    }

    /// Observe actual native escrow and durably reserve only LOCAL liabilities.
    /// Existing on-chain spend/cancel commands remain authoritative and unlocked.
    pub fn reserve_native_budget_v1(
        &mut self,
        request: NativeBudgetRequestV1,
    ) -> Result<NativeBudgetObservationV1> {
        self.ready()?;
        let mut records = self.native_budget_records_v1()?;
        let key = format!("{PREFIX}{}", hex::encode(request.operation));
        if let Some(record) = records.get(&key) {
            ensure(record.request == request, "BUDGET_OPERATION_REPLAY")?;
            return self.native_budget_observation_v1(record, &records);
        }
        let (tip, generation, state) = self.read_active()?;
        let value = state
            .get(&source_key(&request))
            .ok_or("BUDGET_SOURCE_ABSENT")?;
        verify_payee(value, &request)?;
        let source = funding(value, request.lane)?;
        let record = Record {
            schema: SCHEMA.into(),
            network: self.settings.network(),
            parameters: self.settings.parameters(),
            genesis: self.settings.genesis(),
            request,
            source_tip: tip,
            source_generation: generation,
            source_height: self.record(tip)?.height,
            funding: source,
            consumed: None,
            effect: None,
            receipt: None,
        };
        ensure(
            record
                .funding
                .deadline
                .is_none_or(|deadline| record.source_height < deadline),
            "BUDGET_SOURCE_EXPIRED",
        )?;
        self.write_native_budget_record_v1(&records, &record)?;
        records.insert(key, record.clone());
        self.native_budget_observation_v1(&record, &records)
    }

    /// Resource facts are owner inputs. Unknown work retains its full reserve.
    pub fn settle_native_budget_resources_v1(
        &mut self,
        operation: Hash,
        actual: [u64; 2],
    ) -> Result<NativeBudgetObservationV1> {
        self.ready()?;
        let mut records = self.native_budget_records_v1()?;
        let key = format!("{PREFIX}{}", hex::encode(operation));
        let mut record = records
            .get(&key)
            .cloned()
            .ok_or("BUDGET_OPERATION_ABSENT")?;
        ensure(
            record.consumed.is_none_or(|prior| prior == actual),
            "BUDGET_RESOURCE_REPLAY",
        )?;
        if record.consumed.is_none() {
            record.consumed = Some(actual);
            self.write_native_budget_record_v1(&records, &record)?;
            records.insert(key, record.clone());
        }
        self.native_budget_observation_v1(&record, &records)
    }

    /// Retain intent only; new intent requires funds still canonical/current.
    pub fn prepare_native_budget_effect_v1(
        &mut self,
        operation: Hash,
        effect: Hash,
    ) -> Result<NativeBudgetObservationV1> {
        self.ready()?;
        let mut records = self.native_budget_records_v1()?;
        let key = format!("{PREFIX}{}", hex::encode(operation));
        let mut record = records
            .get(&key)
            .cloned()
            .ok_or("BUDGET_OPERATION_ABSENT")?;
        ensure(
            effect != [0; 32] && record.consumed.is_some(),
            "BUDGET_EFFECT",
        )?;
        ensure(
            record.effect.is_none_or(|prior| prior == effect),
            "BUDGET_EFFECT_REPLAY",
        )?;
        if record.effect.is_none() {
            ensure(
                self.native_budget_source_current_v1(&record, &records)?,
                "BUDGET_FUNDING_NOT_CURRENT",
            )?;
            record.effect = Some(effect);
            self.write_native_budget_record_v1(&records, &record)?;
            records.insert(key, record.clone());
        }
        self.native_budget_observation_v1(&record, &records)
    }

    /// Reconcile a retained target-side receipt even after its funding orphaned.
    /// The receipt is not independently authenticated by this persistence API.
    pub fn finish_native_budget_effect_v1(
        &mut self,
        operation: Hash,
        effect: Hash,
        receipt: Hash,
    ) -> Result<NativeBudgetObservationV1> {
        self.ready()?;
        let mut records = self.native_budget_records_v1()?;
        let key = format!("{PREFIX}{}", hex::encode(operation));
        let mut record = records
            .get(&key)
            .cloned()
            .ok_or("BUDGET_OPERATION_ABSENT")?;
        ensure(
            record.effect == Some(effect)
                && receipt != [0; 32]
                && record.receipt.is_none_or(|prior| prior == receipt),
            "BUDGET_RECEIPT_REPLAY",
        )?;
        if record.receipt.is_none() {
            record.receipt = Some(receipt);
            self.write_native_budget_record_v1(&records, &record)?;
            records.insert(key, record.clone());
        }
        self.native_budget_observation_v1(&record, &records)
    }
}

#[cfg(test)]
#[path = "native_budget_tests.rs"]
mod tests;
