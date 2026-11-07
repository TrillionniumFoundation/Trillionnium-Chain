//! Native owners for unknown-output Task operations and durable version fences.
//!
//! These pins bind one native Task to V1 or one exact V2 operation in this Node.
//! They are not a global dispatch grant. The real external target still owns
//! execution, completion and effect deduplication across all of its callers.
use super::{canonical, Node, StateBackend};
use crate::{consensus, ensure, Error, Result};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Mutex};
use trnm_mvcc_fee::pon_executor::{self, funded_service_v1, CanonicalTransitionObserver, State};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};
use trnm_service_settlement::native_budget::task_operation_v2::{
    NativeTaskBeginObservationV2, NativeTaskContractObservationV2, NativeTaskDeliveryObservationV2,
    NativeTaskOperationBindingV2, NativeTaskOperationOwnerV2, NativeTaskStatusV2,
};
use trnm_service_settlement::native_budget::{
    NativeBudgetAnchorV1, NativeBudgetErrorV1, NativeBudgetResultV1, NativeFundingObservationV1,
    NativeFundingSourceV1,
};

const PREFIX: &str = "pon-native-task-operation-pin-v1:task:";
const HEAD: &str = "pon-native-task-operation-pin-v1:head";
const SCHEMA: &str = "pon-native-task-operation-pin-v1";
const MAX_RECORDS: usize = 128;
const MAX_BYTES: usize = 8192;
const MAX_BINDING_BYTES: usize = 512;
const MAX_ANCESTORS: usize = 4096;

mod reconciliation;

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
struct DeliveryPin {
    output: Hash,
    receipt_operation: Hash,
    receipt_anchor: Anchor,
    observed_anchor: Anchor,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    schema: String,
    task: Hash,
    contract_digest: Hash,
    payer: Hash,
    provider: Hash,
    amount: u64,
    source: Anchor,
    version: u8,
    binding: Option<Vec<u8>>,
    started_at: Option<Anchor>,
    delivery: Option<DeliveryPin>,
}
impl Pin {
    fn binding(&self) -> Result<Option<NativeTaskOperationBindingV2>> {
        self.binding
            .as_deref()
            .map(|bytes| {
                ensure(
                    bytes.len() <= MAX_BINDING_BYTES,
                    "TASK_OPERATION_BINDING_BYTES",
                )?;
                NativeTaskOperationBindingV2::decode(bytes).map_err(budget_error)
            })
            .transpose()
    }
}
fn budget_error(error: impl std::fmt::Display) -> Error {
    Error::from(format!("TASK_OPERATION_BUDGET:{error}"))
}
fn owner_error(error: Error) -> NativeBudgetErrorV1 {
    NativeBudgetErrorV1::Owner(error.to_string())
}
fn pin_head(pins: &BTreeMap<Hash, Pin>) -> Result<Option<Vec<u8>>> {
    if pins.is_empty() {
        return Ok(None);
    }
    let bytes = canonical(&serde_json::to_value(pins.values().collect::<Vec<_>>())?)?;
    Ok(Some(
        hash(b"pon-native-task-operation-pin-set-v1", &[&bytes]).to_vec(),
    ))
}

impl Node {
    fn check_task_operation_anchor_v1(&self, anchor: &Anchor) -> Result<()> {
        self.validate_native_active_anchor_v1(&anchor.native())
    }
    // A receipt block is an ancestor in a checked observation, not necessarily
    // the active tip of the observation's generation.
    fn check_task_operation_block_v1(&self, anchor: &Anchor) -> Result<()> {
        ensure(
            anchor.network == self.settings.network()
                && anchor.parameters == self.settings.parameters()
                && anchor.genesis == self.settings.genesis()
                && anchor.generation <= self.active()?.1,
            "TASK_OPERATION_PIN_CONTEXT",
        )?;
        let record = self.record(anchor.block)?;
        ensure(
            record.height == anchor.height && record.root == anchor.state_root,
            "TASK_OPERATION_PIN_ANCHOR",
        )
    }
    fn read_task_operation_pins_v1(&self) -> Result<BTreeMap<Hash, Pin>> {
        let mut statement = self.db.prepare(
            "SELECT typeof(key),length(CAST(key AS BLOB)),substr(CAST(key AS BLOB),1,?3),typeof(value),length(value),substr(value,1,?1) FROM metadata WHERE key GLOB 'pon-native-task-operation-pin-v1:*' ORDER BY key LIMIT ?2",
        )?;
        let rows = statement
            .query_map(
                params![MAX_BYTES + 1, MAX_RECORDS + 2, PREFIX.len() + 65],
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
        ensure(rows.len() <= MAX_RECORDS + 1, "TASK_OPERATION_PIN_LIMIT")?;
        let mut pins = BTreeMap::new();
        let mut head = None;
        let mut operations = BTreeMap::new();
        for (key_kind, key_length, key_raw, kind, length, raw) in rows {
            ensure(
                key_kind == "text"
                    && key_length <= PREFIX.len() + 64
                    && key_raw.len() == key_length
                    && key_raw.is_ascii(),
                "TASK_OPERATION_PIN_KEY",
            )?;
            let key = String::from_utf8(key_raw).map_err(|_| "TASK_OPERATION_PIN_KEY")?;
            ensure(
                kind == "blob" && length <= MAX_BYTES && raw.len() == length,
                "TASK_OPERATION_PIN_BYTES",
            )?;
            if key == HEAD {
                head = Some(raw);
                continue;
            }
            let pin: Pin = serde_json::from_slice(&raw).map_err(|_| "TASK_OPERATION_PIN_CODEC")?;
            ensure(
                key == format!("{PREFIX}{}", hex::encode(pin.task))
                    && pin.schema == SCHEMA
                    && pin.amount > 0
                    && raw == canonical(&serde_json::to_value(&pin)?)?,
                "TASK_OPERATION_PIN_BINDING",
            )?;
            self.check_task_operation_anchor_v1(&pin.source)?;
            if let Some(anchor) = &pin.started_at {
                self.check_task_operation_anchor_v1(anchor)?;
            }
            match (pin.version, pin.binding()?) {
                (1, None) => ensure(
                    pin.started_at.is_none() && pin.delivery.is_none(),
                    "TASK_OPERATION_PIN_VERSION",
                )?,
                (2, Some(binding)) => {
                    ensure(
                        binding.task == pin.task
                            && binding.contract_digest == pin.contract_digest
                            && binding.beneficiary == pin.provider,
                        "TASK_OPERATION_PIN_BINDING",
                    )?;
                    binding.id().map_err(budget_error)?;
                    if let Some(delivery) = &pin.delivery {
                        ensure(
                            pin.started_at.is_some()
                                && delivery.output != [0; 32]
                                && delivery.receipt_operation != [0; 32],
                            "TASK_OPERATION_DELIVERY_PIN",
                        )?;
                        self.check_task_operation_block_v1(&delivery.receipt_anchor)?;
                        self.check_task_operation_anchor_v1(&delivery.observed_anchor)?;
                    }
                    ensure(
                        operations.insert(binding.operation, pin.task).is_none(),
                        "TASK_OPERATION_PIN_DUPLICATE_OPERATION",
                    )?;
                }
                _ => return Err("TASK_OPERATION_PIN_VERSION".into()),
            }
            ensure(
                pins.insert(pin.task, pin).is_none(),
                "TASK_OPERATION_PIN_BINDING",
            )?;
        }
        ensure(head == pin_head(&pins)?, "TASK_OPERATION_PIN_SET")?;
        Ok(pins)
    }
    fn task_operation_pins_v1(&self) -> Result<BTreeMap<Hash, Pin>> {
        self.read_task_operation_pins_v1()
            .map_err(Error::local_integrity)
    }
    fn validate_task_operation_history_v1(&self, pins: &BTreeMap<Hash, Pin>) -> Result<()> {
        for pin in pins.values() {
            ensure(
                matches!(
                    self.state_backend,
                    StateBackend::Legacy | StateBackend::AuthenticatedV1
                ),
                "TASK_OPERATION_BACKEND",
            )?;
            for anchor in std::iter::once(&pin.source).chain(pin.started_at.iter()) {
                let state = self.state_at(anchor.block)?;
                let row = state
                    .get(&NativeFundingSourceV1::Task(pin.task).key())
                    .ok_or("TASK_OPERATION_PIN_SOURCE")?;
                let contract = funded_service_v1::read_contract(pin.task, row, &self.settings.app)?
                    .ok_or("TASK_OPERATION_CONTRACT_REQUIRED")?;
                ensure(
                    contract.contract_digest == pin.contract_digest
                        && contract.payer == pin.payer
                        && contract.terms.provider == pin.provider
                        && contract.terms.budget == pin.amount
                        && row["remaining"] == pin.amount
                        && (row["status"] == "reserved"
                            || (pin.version == 1 && row["status"] == "receipt")),
                    "TASK_OPERATION_PIN_SOURCE",
                )?;
                if pin.version == 2 {
                    ensure(
                        contract.delivered_output.is_none()
                            && anchor.height < contract.terms.delivery_deadline,
                        "TASK_OPERATION_PIN_SOURCE",
                    )?;
                }
            }
            if let Some(delivery) = &pin.delivery {
                let binding = pin.binding()?.ok_or("TASK_OPERATION_DELIVERY_PIN")?;
                let contract = self.historical_contract_operation_v2(
                    &binding,
                    delivery.observed_anchor.native(),
                )?;
                let actual = self.read_delivery_for_contract_v2(&binding, contract)?;
                ensure(
                    actual.contract.output == Some(delivery.output)
                        && actual.receipt_operation == delivery.receipt_operation
                        && actual.receipt_anchor == delivery.receipt_anchor.native(),
                    "TASK_OPERATION_DELIVERY_PIN_HISTORY",
                )?;
            }
        }
        Ok(())
    }
    pub(super) fn validate_native_task_operation_pins_v1(&self) -> Result<()> {
        (|| {
            let pins = self.task_operation_pins_v1()?;
            self.validate_task_operation_history_v1(&pins)?;
            self.validate_task_operation_reconciliations_v2(&pins)
        })()
        .map_err(Error::local_integrity)
    }
    pub fn native_task_operation_pins_v1(&self) -> Result<Value> {
        self.ready()?;
        let pins = self.task_operation_pins_v1()?;
        self.validate_task_operation_history_v1(&pins)?;
        Ok(json!({
            "schema":"pon-native-task-operation-pin-inventory-v1",
            "records":pins.values().collect::<Vec<_>>(),
            "global_execution_authority":false,"physical_execution_verified":false,
            "production_activation":false,
        }))
    }
    fn write_task_operation_pin_v1(
        &self,
        pins: &BTreeMap<Hash, Pin>,
        pin: &Pin,
        current: NativeBudgetAnchorV1,
    ) -> Result<()> {
        let mut next = pins.clone();
        next.insert(pin.task, pin.clone());
        ensure(next.len() <= MAX_RECORDS, "TASK_OPERATION_PIN_LIMIT")?;
        let raw = canonical(&serde_json::to_value(pin)?)?;
        ensure(raw.len() <= MAX_BYTES, "TASK_OPERATION_PIN_BYTES")?;
        let key = format!("{PREFIX}{}", hex::encode(pin.task));
        let next_head = pin_head(&next)?.ok_or("TASK_OPERATION_PIN_SET")?;
        self.atomic(|| {
            ensure(
                self.task_operation_pins_v1()? == *pins,
                "TASK_OPERATION_PIN_STALE",
            )?;
            ensure(
                self.active()? == (current.block, current.generation),
                "STALE_VIEW",
            )?;
            let changed = if let Some(old) = pins.get(&pin.task) {
                self.db.execute(
                    "UPDATE metadata SET value=?1 WHERE key=?2 AND value=?3",
                    params![&raw, &key, canonical(&serde_json::to_value(old)?)?],
                )?
            } else {
                self.db.execute(
                    "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                    params![&key, &raw],
                )?
            };
            ensure(changed == 1, "TASK_OPERATION_PIN_WRITE")?;
            let changed = if let Some(old) = pin_head(pins)? {
                self.db.execute(
                    "UPDATE metadata SET value=?1 WHERE key=?2 AND value=?3",
                    params![&next_head, HEAD, old],
                )?
            } else {
                self.db.execute(
                    "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                    params![HEAD, &next_head],
                )?
            };
            ensure(
                changed == 1 && self.task_operation_pins_v1()? == next,
                "TASK_OPERATION_PIN_WRITE",
            )
            .map_err(Error::local_integrity)
        })
    }

    /// V1's trusted owner callback uses this path; ordinary funding queries
    /// remain read-only. A selected full-contract Task cannot later switch to V2.
    pub(in crate::store) fn observe_native_budget_funding_v1(
        &mut self,
        source: NativeFundingSourceV1,
    ) -> Result<NativeFundingObservationV1> {
        let observed = self.native_funding_observation(source)?;
        let NativeFundingSourceV1::Task(task) = source else {
            return Ok(observed);
        };
        let pins = self.task_operation_pins_v1()?;
        self.validate_task_operation_history_v1(&pins)?;
        if let Some(pin) = pins.get(&task) {
            ensure(pin.version == 1, "TASK_OPERATION_VERSION_CONFLICT")?;
            return Ok(observed);
        }
        if !funded_service_v1::enabled(&self.settings.app) {
            return Ok(observed);
        }
        let Some(row) = &observed.row else {
            return Ok(observed);
        };
        let contract = funded_service_v1::read_contract(task, row, &self.settings.app)?
            .ok_or("TASK_OPERATION_CONTRACT_REQUIRED")?;
        ensure(
            matches!(
                self.state_backend,
                StateBackend::Legacy | StateBackend::AuthenticatedV1
            ),
            "TASK_OPERATION_BACKEND",
        )?;
        ensure(
            (row["status"] == "reserved" || row["status"] == "receipt")
                && row["remaining"] == contract.terms.budget
                && observed.anchor.height < contract.terms.dispute_deadline,
            "TASK_OPERATION_SOURCE_CLOSED",
        )?;
        let pin = Pin {
            schema: SCHEMA.into(),
            task,
            contract_digest: contract.contract_digest,
            payer: contract.payer,
            provider: contract.terms.provider,
            amount: contract.terms.budget,
            source: observed.anchor.into(),
            version: 1,
            binding: None,
            started_at: None,
            delivery: None,
        };
        self.write_task_operation_pin_v1(&pins, &pin, observed.anchor)?;
        Ok(observed)
    }
    pub(in crate::store) fn require_native_task_budget_version_v1(&self, task: Hash) -> Result<()> {
        ensure(
            self.task_operation_pins_v1()?
                .get(&task)
                .is_some_and(|pin| pin.version == 1),
            "TASK_OPERATION_VERSION_CONFLICT",
        )
    }

    fn observe_contract_operation_v2(
        &self,
        binding: &NativeTaskOperationBindingV2,
    ) -> Result<NativeTaskContractObservationV2> {
        let source = self.native_funding_observation(NativeFundingSourceV1::Task(binding.task))?;
        self.contract_operation_from_native_v2(binding, source)
    }
    fn historical_contract_operation_v2(
        &self,
        binding: &NativeTaskOperationBindingV2,
        anchor: NativeBudgetAnchorV1,
    ) -> Result<NativeTaskContractObservationV2> {
        self.check_task_operation_anchor_v1(&anchor.into())?;
        let source = NativeFundingSourceV1::Task(binding.task);
        let state = self.state_at(anchor.block)?;
        self.contract_operation_from_native_v2(
            binding,
            NativeFundingObservationV1 {
                anchor,
                source,
                row: state.get(&source.key()).cloned(),
            },
        )
    }
    fn contract_operation_from_native_v2(
        &self,
        binding: &NativeTaskOperationBindingV2,
        source: NativeFundingObservationV1,
    ) -> Result<NativeTaskContractObservationV2> {
        binding.id().map_err(budget_error)?;
        ensure(
            funded_service_v1::enabled(&self.settings.app)
                && matches!(
                    self.state_backend,
                    StateBackend::Legacy | StateBackend::AuthenticatedV1
                ),
            "TASK_OPERATION_PROFILE",
        )?;
        ensure(
            source.source == NativeFundingSourceV1::Task(binding.task),
            "TASK_OPERATION_BINDING",
        )?;
        let row = source.row.as_ref().ok_or("TASK_OPERATION_SOURCE_ABSENT")?;
        let contract = funded_service_v1::read_contract(binding.task, row, &self.settings.app)?
            .ok_or("TASK_OPERATION_CONTRACT_REQUIRED")?;
        ensure(
            contract.contract_digest == binding.contract_digest
                && contract.terms.provider == binding.beneficiary,
            "TASK_OPERATION_BINDING",
        )?;
        let status = match row["status"].as_str() {
            Some("reserved") => NativeTaskStatusV2::Reserved,
            Some("receipt") => NativeTaskStatusV2::Receipt,
            Some("settled") => NativeTaskStatusV2::Settled,
            Some("refunded") => NativeTaskStatusV2::Refunded,
            Some("expired") => NativeTaskStatusV2::Expired,
            _ => return Err("TASK_OPERATION_SOURCE_STATUS".into()),
        };
        Ok(NativeTaskContractObservationV2 {
            anchor: source.anchor,
            task: binding.task,
            contract_digest: contract.contract_digest,
            payer: contract.payer,
            provider: contract.terms.provider,
            request: contract.terms.request,
            model: contract.terms.model,
            input: contract.terms.input,
            output_spec: contract.terms.output_spec,
            amount: contract.terms.budget,
            delivery_deadline: contract.terms.delivery_deadline,
            dispute_deadline: contract.terms.dispute_deadline,
            remaining: row["remaining"]
                .as_u64()
                .ok_or("TASK_OPERATION_SOURCE_AMOUNT")?,
            status,
            output: contract.delivered_output,
            receipt_height: contract.receipt_height,
        })
    }
    fn reserve_operation_v2(
        &mut self,
        binding: &NativeTaskOperationBindingV2,
        begin: bool,
    ) -> Result<NativeTaskBeginObservationV2> {
        self.ready()?;
        let pins = self.task_operation_pins_v1()?;
        self.validate_task_operation_history_v1(&pins)?;
        let encoded = binding.encode().map_err(budget_error)?;
        ensure(
            encoded.len() <= MAX_BINDING_BYTES,
            "TASK_OPERATION_BINDING_BYTES",
        )?;
        if let Some(pin) = pins.get(&binding.task) {
            ensure(pin.version == 2, "TASK_OPERATION_VERSION_CONFLICT")?;
            ensure(
                pin.binding.as_deref() == Some(encoded.as_slice()),
                "TASK_OPERATION_REBIND",
            )?;
            if pin.started_at.is_some() {
                // Retained begin never grants another execution. A missing or
                // changed source may also refuse this readback; neither is New.
                return Ok(NativeTaskBeginObservationV2 {
                    contract: self.observe_contract_operation_v2(binding)?,
                    new_execution: false,
                });
            }
        }
        for pin in pins.values() {
            if let Some(prior) = pin.binding()? {
                ensure(
                    prior.operation != binding.operation || pin.task == binding.task,
                    "TASK_OPERATION_DUPLICATE_OPERATION",
                )?;
            }
        }
        let observed = self.observe_contract_operation_v2(binding)?;
        ensure(
            observed.status == NativeTaskStatusV2::Reserved
                && observed.output.is_none()
                && observed.receipt_height.is_none()
                && observed.remaining == observed.amount
                && observed.anchor.height < observed.delivery_deadline,
            "TASK_OPERATION_NOT_PROSPECTIVE",
        )?;
        let mut pin = pins.get(&binding.task).cloned().unwrap_or(Pin {
            schema: SCHEMA.into(),
            task: binding.task,
            contract_digest: binding.contract_digest,
            payer: observed.payer,
            provider: observed.provider,
            amount: observed.amount,
            source: observed.anchor.into(),
            version: 2,
            binding: Some(encoded),
            started_at: None,
            delivery: None,
        });
        if begin {
            pin.started_at = Some(observed.anchor.into());
        }
        if pins.get(&binding.task) != Some(&pin) {
            self.write_task_operation_pin_v1(&pins, &pin, observed.anchor)?;
        }
        Ok(NativeTaskBeginObservationV2 {
            contract: observed,
            new_execution: begin,
        })
    }
    fn delivery_operation_v2(
        &mut self,
        binding: &NativeTaskOperationBindingV2,
    ) -> Result<NativeTaskDeliveryObservationV2> {
        self.ready()?;
        let pins = self.task_operation_pins_v1()?;
        self.validate_task_operation_history_v1(&pins)?;
        let pin = pins.get(&binding.task).ok_or("TASK_OPERATION_PIN_ABSENT")?;
        ensure(
            pin.version == 2
                && pin.binding.as_ref() == Some(&binding.encode().map_err(budget_error)?)
                && pin.started_at.is_some(),
            "TASK_OPERATION_DELIVERY_BINDING",
        )?;
        let contract = self.observe_contract_operation_v2(binding)?;
        let actual = self.read_delivery_for_contract_v2(binding, contract)?;
        ensure(
            self.native_funding_observation(NativeFundingSourceV1::Task(binding.task))?
                .anchor
                == actual.contract.anchor,
            "STALE_VIEW",
        )?;
        if let Some(delivery) = &pin.delivery {
            ensure(
                actual.contract.output == Some(delivery.output),
                "TASK_OPERATION_OUTPUT_REBIND",
            )?;
            ensure(
                actual.receipt_operation == delivery.receipt_operation,
                "TASK_OPERATION_RECEIPT_REBIND",
            )?;
        } else {
            let mut next = pin.clone();
            next.delivery = Some(DeliveryPin {
                output: actual
                    .contract
                    .output
                    .ok_or("TASK_OPERATION_NOT_DELIVERED")?,
                receipt_operation: actual.receipt_operation,
                receipt_anchor: actual.receipt_anchor.into(),
                observed_anchor: actual.contract.anchor.into(),
            });
            self.write_task_operation_pin_v1(&pins, &next, actual.contract.anchor)?;
        }
        Ok(actual)
    }
    fn read_delivery_for_contract_v2(
        &self,
        binding: &NativeTaskOperationBindingV2,
        contract: NativeTaskContractObservationV2,
    ) -> Result<NativeTaskDeliveryObservationV2> {
        let receipt_height = contract
            .receipt_height
            .ok_or("TASK_OPERATION_NOT_DELIVERED")?;
        let output = contract.output.ok_or("TASK_OPERATION_NOT_DELIVERED")?;
        let read = self.db.unchecked_transaction()?;
        self.namespace()?;
        self.storage_context()?;
        let selected = self.active()?;
        self.check_task_operation_anchor_v1(&contract.anchor.into())?;
        let mut cursor = contract.anchor.block;
        let mut delivery = None;
        for _ in 0..MAX_ANCESTORS {
            let record = self.record(cursor)?;
            ensure(
                record.height >= receipt_height,
                "TASK_OPERATION_DELIVERY_ANCESTRY",
            )?;
            let header = self.native_payment_header(cursor)?;
            let parent = self.record(header.parent)?;
            ensure(
                record.parent == Some(header.parent)
                    && record.height == header.height
                    && record.root == header.state
                    && header.network == self.settings.network()
                    && header.parameters == self.settings.parameters()
                    && parent.height.checked_add(1) == Some(record.height)
                    && record.work
                        == parent
                            .work
                            .checked_add(consensus::required_work(header.target)?)?,
                "TASK_OPERATION_DELIVERY_ANCESTRY",
            )?;
            if record.height == receipt_height {
                let observer = DeliveryObserver {
                    binding,
                    output,
                    height: record.height,
                    config: &self.settings.app,
                    result: Mutex::new(None),
                };
                self.check_native_payment_transition(cursor, &observer)?;
                let operation = observer
                    .result
                    .into_inner()
                    .map_err(|_| "TASK_OPERATION_DELIVERY_OBSERVER")?
                    .ok_or("TASK_OPERATION_NOT_DELIVERED")?;
                let mut anchor = contract.anchor;
                anchor.block = cursor;
                anchor.state_root = record.root;
                anchor.height = record.height;
                delivery = Some((operation, anchor));
                break;
            }
            cursor = header.parent;
        }
        let (receipt_operation, receipt_anchor) =
            delivery.ok_or("TASK_OPERATION_DELIVERY_SCAN_LIMIT")?;
        self.namespace()?;
        self.storage_context()?;
        ensure(self.active()? == selected, "STALE_VIEW")?;
        read.rollback()?;
        self.namespace()?;
        ensure(self.active()? == selected, "STALE_VIEW")?;
        Ok(NativeTaskDeliveryObservationV2 {
            contract,
            receipt_operation,
            receipt_anchor,
        })
    }
}

impl NativeTaskOperationOwnerV2 for Node {
    fn reserve_task_operation_v2(
        &mut self,
        binding: &NativeTaskOperationBindingV2,
    ) -> NativeBudgetResultV1<NativeTaskContractObservationV2> {
        self.reserve_operation_v2(binding, false)
            .map(|value| value.contract)
            .map_err(owner_error)
    }
    fn begin_task_operation_v2(
        &mut self,
        binding: &NativeTaskOperationBindingV2,
    ) -> NativeBudgetResultV1<NativeTaskBeginObservationV2> {
        self.reserve_operation_v2(binding, true)
            .map_err(owner_error)
    }
    fn observe_task_delivery_v2(
        &mut self,
        binding: &NativeTaskOperationBindingV2,
    ) -> NativeBudgetResultV1<NativeTaskDeliveryObservationV2> {
        self.delivery_operation_v2(binding).map_err(owner_error)
    }
}

struct DeliveryObserver<'a> {
    binding: &'a NativeTaskOperationBindingV2,
    output: Hash,
    height: u64,
    config: &'a pon_executor::Config,
    result: Mutex<Option<Hash>>,
}
impl CanonicalTransitionObserver for DeliveryObserver<'_> {
    fn transaction(
        &self,
        _index: usize,
        envelope: &Envelope,
        before: &State,
        writes: &State,
        fee: u64,
        receipt: &[u8],
    ) -> pon_executor::Result<()> {
        if envelope.tag != 4
            || envelope.payload.len() != 64
            || envelope.payload[..32] != self.binding.task
        {
            return Ok(());
        }
        let key = NativeFundingSourceV1::Task(self.binding.task).key();
        let old = before.get(&key).ok_or("TASK_OPERATION_DELIVERY_SOURCE")?;
        let new = writes.get(&key).ok_or("TASK_OPERATION_DELIVERY_SOURCE")?;
        let original = funded_service_v1::read_contract(self.binding.task, old, self.config)?
            .ok_or("TASK_OPERATION_DELIVERY_SOURCE")?;
        let delivered = funded_service_v1::read_contract(self.binding.task, new, self.config)?
            .ok_or("TASK_OPERATION_DELIVERY_SOURCE")?;
        let operation = envelope
            .id()
            .map_err(|_| "TASK_OPERATION_DELIVERY_ENVELOPE")?;
        let receipt: Value =
            serde_json::from_slice(receipt).map_err(|_| "TASK_OPERATION_DELIVERY_RECEIPT")?;
        if envelope.sender != self.binding.beneficiary
            || envelope.payload[32..] != self.output
            || original.contract_digest != self.binding.contract_digest
            || original.delivered_output.is_some()
            || delivered.contract_digest != self.binding.contract_digest
            || delivered.delivered_output != Some(self.output)
            || delivered.receipt_height != Some(self.height)
            || old["status"] != "reserved"
            || new["status"] != "receipt"
            || old["remaining"] != new["remaining"]
            || receipt["tx"] != hex::encode(operation)
            || receipt["fee"] != fee
            || receipt["status"] != "applied"
        {
            return Err("TASK_OPERATION_DELIVERY_BINDING");
        }
        let mut retained = self
            .result
            .lock()
            .map_err(|_| "TASK_OPERATION_DELIVERY_OBSERVER")?;
        if retained.is_some() {
            return Err("TASK_OPERATION_DELIVERY_DUPLICATE");
        }
        *retained = Some(operation);
        Ok(())
    }
}
