//! Opt-in classical development contracts using the original native Task escrow.
//! No balance, issuance, payment or refund owner is introduced here. Frozen
//! commitments and distinct keys do not prove real demand or independent control.
use super::{canonical, field, require, text, Config, Result, View};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use trnm_protocol::funded_service_task_v1::{
    FundedServiceContractV1, FundedServiceDecisionV1, FundedServiceReservationV1,
    FundedServiceVerdictV1, DECISION_BYTES, RESERVATION_BYTES,
};
use trnm_protocol::pon_wire::{hash, Hash};

pub const PROFILE: &str = "funded-service-contract-dev-v1";
pub const RECORD_SCHEMA: &str = "funded-service-task-record-v1";
pub const RECORD_FIELD: &str = "service_contract_v1";

fn policy() -> Value {
    json!({
        "schema": "funded-service-contract-policy-v1",
        "profile": PROFILE,
        "record_schema": RECORD_SCHEMA,
        "reservation_bytes": RESERVATION_BYTES,
        "decision_bytes": DECISION_BYTES,
        "delivery_deadline_inclusive": true,
        "dispute_deadline_exclusive": true,
        "partial_settlement": false,
        "arbitrary_recipient": false,
        "post_quantum_authorization": false,
        "production_activation": false,
        "independent_customer_attested": false,
        "independent_arbitrator_attested": false
    })
}

fn parameters(cfg: &Config) -> Result<Hash> {
    let wire: Value =
        serde_json::from_str(include_str!("../../../../../config/pon/ledger-v1.json"))
            .map_err(|_| "CONFIG")?;
    let work: Value = serde_json::from_str(include_str!(
        "../../../../../config/pon/work-profile-v1.json"
    ))
    .map_err(|_| "CONFIG")?;
    Ok(hash(
        b"parameters",
        &[
            &canonical(&cfg.params)?,
            &canonical(&wire)?,
            &canonical(&work)?,
            &canonical(&cfg.model_registry)?,
        ],
    ))
}

/// Select before constructing genesis or task bootstrap records. Reusing this
/// with deployed state is not a migration and the changed context rejects it.
pub fn install(cfg: &mut Config) -> Result<()> {
    require(
        cfg.params["state_profile"].is_null(),
        "SERVICE_CONTRACT_GROWTH_UNSUPPORTED",
    )?;
    require(
        !cfg.is_pq_account_profile() && cfg.params["account_authorization_profile"].is_null(),
        "SERVICE_CONTRACT_PQ_UNSUPPORTED",
    )?;
    require(
        cfg.params["funded_service_contract_profile"].is_null()
            && cfg.params["funded_service_contract_policy"].is_null()
            && cfg.params["production_activation"] == false,
        "SERVICE_CONTRACT_PROFILE",
    )?;
    let label = format!("{}-{PROFILE}", text(&cfg.params, "chain_label")?);
    cfg.params["funded_service_contract_profile"] = json!(PROFILE);
    cfg.params["funded_service_contract_policy"] = policy();
    cfg.params["chain_label"] = json!(label);
    cfg.network = hash(b"network", &[label.as_bytes()]);
    cfg.parameters = parameters(cfg)?;
    check_config(cfg)
}

pub fn enabled(cfg: &Config) -> bool {
    cfg.params["funded_service_contract_profile"] == PROFILE
}

/// Refuse partial selection, changed policy bytes and unauthorized PQ hybrids.
pub fn check_config(cfg: &Config) -> Result<()> {
    if cfg.params["funded_service_contract_profile"].is_null() {
        return require(
            cfg.params["funded_service_contract_policy"].is_null(),
            "SERVICE_CONTRACT_PROFILE",
        );
    }
    require(
        cfg.params["state_profile"].is_null(),
        "SERVICE_CONTRACT_GROWTH_UNSUPPORTED",
    )?;
    require(
        enabled(cfg)
            && !cfg.is_pq_account_profile()
            && cfg.params["account_authorization_profile"].is_null()
            && cfg.params["production_activation"] == false
            && cfg.params["funded_service_contract_policy"] == policy(),
        "SERVICE_CONTRACT_PROFILE",
    )?;
    let label = text(&cfg.params, "chain_label")?;
    require(
        label.ends_with(&format!("-{PROFILE}"))
            && cfg.network == hash(b"network", &[label.as_bytes()])
            && cfg.parameters == parameters(cfg)?,
        "SERVICE_CONTRACT_CONTEXT",
    )
}

/// The universal codec recognizes the extension; only this selected consensus
/// context admits it. Selecting this profile also forbids unbound reservations.
pub fn check_command(cfg: &Config, tag: u8, payload: &[u8]) -> Result<()> {
    if tag == 2 {
        if enabled(cfg) {
            FundedServiceReservationV1::decode(payload)
                .map_err(|_| "SERVICE_CONTRACT_RESERVATION")?;
        } else {
            require(payload.len() == 80, "SERVICE_CONTRACT_PROFILE")?;
        }
    } else if tag == 5 && payload.len() != 64 {
        require(enabled(cfg), "SERVICE_CONTRACT_PROFILE")?;
        FundedServiceDecisionV1::decode(payload).map_err(|_| "SERVICE_CONTRACT_DECISION")?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceResolutionKindV1 {
    CustomerAccepted,
    ArbitratorPaid,
    ArbitratorRefunded,
    NonDeliveryRefund,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceResolutionV1 {
    pub kind: ServiceResolutionKindV1,
    pub actor: Hash,
    pub nonce: u64,
    pub height: u64,
    pub evidence: Option<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceContractRecordV1 {
    pub schema: String,
    pub network: Hash,
    pub parameters: Hash,
    pub payer: Hash,
    pub reservation_nonce: u64,
    pub contract_digest: Hash,
    pub terms: FundedServiceContractV1,
    pub reserved_at: u64,
    pub receipt_height: Option<u64>,
    pub delivered_output: Option<Hash>,
    pub resolution: Option<ServiceResolutionV1>,
}

/// Validate the complete stored relation, including the original native Task
/// monetary fields. A caller-supplied JSON row is not evidence of native origin;
/// consumers must obtain it from the actual canonical state owner.
pub fn read_contract(
    task: Hash,
    row: &Value,
    cfg: &Config,
) -> Result<Option<ServiceContractRecordV1>> {
    let Some(stored) = row.get(RECORD_FIELD) else {
        return Ok(None);
    };
    check_config(cfg)?;
    require(enabled(cfg), "SERVICE_CONTRACT_PROFILE")?;
    let record: ServiceContractRecordV1 =
        serde_json::from_value(stored.clone()).map_err(|_| "SERVICE_CONTRACT_RECORD")?;
    record
        .terms
        .validate()
        .map_err(|_| "SERVICE_CONTRACT_RECORD")?;
    require(
        record.schema == RECORD_SCHEMA
            && record.network == cfg.network
            && record.parameters == cfg.parameters
            && record.payer != [0; 32]
            && record.reservation_nonce > 0
            && record.terms.arbitrator != record.payer
            && record.contract_digest
                == record
                    .terms
                    .digest(cfg.network, cfg.parameters, record.payer)
            && task
                == record.terms.task_id(
                    cfg.network,
                    cfg.parameters,
                    record.payer,
                    record.reservation_nonce,
                )
            && text(row, "owner")? == hex::encode(record.payer)
            && text(row, "provider")? == hex::encode(record.terms.provider)
            && field(row, "deadline")? == record.terms.dispute_deadline
            && record.reserved_at < record.terms.delivery_deadline,
        "SERVICE_CONTRACT_RECORD",
    )?;
    match (record.receipt_height, record.delivered_output) {
        (None, None) => require(
            row.get("output") == Some(&Value::Null),
            "SERVICE_CONTRACT_RECORD",
        )?,
        (Some(height), Some(output)) => require(
            output != [0; 32]
                && record.reserved_at <= height
                && height <= record.terms.delivery_deadline
                && text(row, "output")? == hex::encode(output),
            "SERVICE_CONTRACT_RECORD",
        )?,
        _ => return Err("SERVICE_CONTRACT_RECORD"),
    }
    let remaining = field(row, "remaining")?;
    let delivered = record.delivered_output.is_some();
    match text(row, "status")? {
        "reserved" => require(
            remaining == record.terms.budget && !delivered && record.resolution.is_none(),
            "SERVICE_CONTRACT_RECORD",
        )?,
        "receipt" => require(
            remaining == record.terms.budget && delivered && record.resolution.is_none(),
            "SERVICE_CONTRACT_RECORD",
        )?,
        "expired" => require(
            remaining == 0 && record.resolution.is_none(),
            "SERVICE_CONTRACT_RECORD",
        )?,
        "settled" | "refunded" => {
            let resolution = record
                .resolution
                .as_ref()
                .ok_or("SERVICE_CONTRACT_RECORD")?;
            require(
                remaining == 0
                    && resolution.nonce > 0
                    && resolution.height >= record.reserved_at
                    && resolution.height < record.terms.dispute_deadline
                    && record
                        .receipt_height
                        .is_none_or(|height| height <= resolution.height),
                "SERVICE_CONTRACT_RECORD",
            )?;
            match resolution.kind {
                ServiceResolutionKindV1::CustomerAccepted => require(
                    text(row, "status")? == "settled"
                        && delivered
                        && resolution.actor == record.payer
                        && resolution.evidence.is_none(),
                    "SERVICE_CONTRACT_RECORD",
                )?,
                ServiceResolutionKindV1::ArbitratorPaid => require(
                    text(row, "status")? == "settled"
                        && delivered
                        && resolution.actor == record.terms.arbitrator
                        && resolution.evidence.is_some_and(|value| value != [0; 32]),
                    "SERVICE_CONTRACT_RECORD",
                )?,
                ServiceResolutionKindV1::ArbitratorRefunded => require(
                    text(row, "status")? == "refunded"
                        && (delivered || resolution.height > record.terms.delivery_deadline)
                        && resolution.actor == record.terms.arbitrator
                        && resolution.evidence.is_some_and(|value| value != [0; 32]),
                    "SERVICE_CONTRACT_RECORD",
                )?,
                ServiceResolutionKindV1::NonDeliveryRefund => require(
                    text(row, "status")? == "refunded"
                        && !delivered
                        && resolution.height > record.terms.delivery_deadline
                        && resolution.actor == record.payer
                        && resolution.evidence.is_none(),
                    "SERVICE_CONTRACT_RECORD",
                )?,
            }
        }
        _ => return Err("SERVICE_CONTRACT_RECORD"),
    }
    Ok(Some(record))
}

fn write_record(row: &mut Value, record: &ServiceContractRecordV1) -> Result<()> {
    row[RECORD_FIELD] = serde_json::to_value(record).map_err(|_| "SERVICE_CONTRACT_RECORD")?;
    Ok(())
}

/// Return true only when the selected contract owner actually handles a command.
/// This is a child of the original application executor so escrow and balances
/// remain in its one atomic MVCC patch and canonical replay, including reorgs.
pub(super) fn apply_task_command(
    state: &mut View<'_>,
    sender: Hash,
    nonce: u64,
    tag: u8,
    payload: &[u8],
    height: u64,
    cfg: &Config,
) -> Result<bool> {
    check_command(cfg, tag, payload)?;
    if !enabled(cfg) {
        return Ok(false);
    }
    check_config(cfg)?;
    if tag == 2 {
        let reservation = FundedServiceReservationV1::decode(payload)
            .map_err(|_| "SERVICE_CONTRACT_RESERVATION")?;
        let contract = reservation.contract;
        require(
            sender != [0; 32]
                && nonce > 0
                && contract.arbitrator != sender
                && height < contract.delivery_deadline
                && reservation.task == contract.task_id(cfg.network, cfg.parameters, sender, nonce),
            "SERVICE_CONTRACT_BINDING",
        )?;
        let key = format!("task:{}", hex::encode(reservation.task));
        require(state.get(&key).is_none(), "DUPLICATE")?;
        state.deadline(cfg, contract.dispute_deadline, height)?;
        state.debit(&hex::encode(sender), contract.budget)?;
        let record = ServiceContractRecordV1 {
            schema: RECORD_SCHEMA.into(),
            network: cfg.network,
            parameters: cfg.parameters,
            payer: sender,
            reservation_nonce: nonce,
            contract_digest: contract.digest(cfg.network, cfg.parameters, sender),
            terms: contract,
            reserved_at: height,
            receipt_height: None,
            delivered_output: None,
            resolution: None,
        };
        let mut row = json!({
            "owner":hex::encode(sender),
            "provider":hex::encode(record.terms.provider),
            "remaining":record.terms.budget,
            "deadline":record.terms.dispute_deadline,
            "status":"reserved",
            "output":null
        });
        write_record(&mut row, &record)?;
        state.put(key, row);
        return Ok(true);
    }
    let decision = if tag == 5 && payload.len() == DECISION_BYTES {
        Some(FundedServiceDecisionV1::decode(payload).map_err(|_| "SERVICE_CONTRACT_DECISION")?)
    } else {
        None
    };
    let task = if let Some(decision) = &decision {
        decision.task
    } else {
        require(
            (tag == 3 && payload.len() == 32) || (matches!(tag, 4 | 5) && payload.len() == 64),
            "SERVICE_CONTRACT_COMMAND",
        )?;
        payload[..32]
            .try_into()
            .map_err(|_| "SERVICE_CONTRACT_COMMAND")?
    };
    let (key, mut row) = state.object("task:", task)?;
    let mut record = read_contract(task, &row, cfg)?.ok_or("SERVICE_CONTRACT_REQUIRED")?;
    require(
        record.resolution.is_none()
            && matches!(text(&row, "status")?, "reserved" | "receipt")
            && field(&row, "remaining")? == record.terms.budget
            && height < record.terms.dispute_deadline,
        "SERVICE_CONTRACT_CLOSED",
    )?;
    let resolution = match tag {
        3 => {
            require(
                sender == record.payer
                    && record.delivered_output.is_none()
                    && height > record.terms.delivery_deadline,
                "SERVICE_CONTRACT_CANCELLATION",
            )?;
            state.credit(&hex::encode(record.payer), record.terms.budget)?;
            row["remaining"] = json!(0);
            row["status"] = json!("refunded");
            Some(ServiceResolutionV1 {
                kind: ServiceResolutionKindV1::NonDeliveryRefund,
                actor: sender,
                nonce,
                height,
                evidence: None,
            })
        }
        4 => {
            let output: Hash = payload[32..]
                .try_into()
                .map_err(|_| "SERVICE_CONTRACT_COMMAND")?;
            require(
                sender == record.terms.provider
                    && record.delivered_output.is_none()
                    && height <= record.terms.delivery_deadline
                    && output != [0; 32],
                "SERVICE_CONTRACT_DELIVERY",
            )?;
            record.receipt_height = Some(height);
            record.delivered_output = Some(output);
            row["output"] = json!(hex::encode(output));
            row["status"] = json!("receipt");
            None
        }
        5 => {
            let (kind, recipient, evidence) = if let Some(decision) = decision {
                require(
                    sender == record.terms.arbitrator
                        && decision.contract_digest == record.contract_digest
                        && decision.output == record.delivered_output.unwrap_or([0; 32]),
                    "SERVICE_CONTRACT_ARBITRATOR",
                )?;
                match decision.verdict {
                    FundedServiceVerdictV1::PayProvider => {
                        require(
                            record.delivered_output.is_some(),
                            "SERVICE_CONTRACT_DELIVERY",
                        )?;
                        (
                            ServiceResolutionKindV1::ArbitratorPaid,
                            record.terms.provider,
                            Some(decision.evidence),
                        )
                    }
                    FundedServiceVerdictV1::RefundPayer => {
                        require(
                            record.delivered_output.is_some()
                                || height > record.terms.delivery_deadline,
                            "SERVICE_CONTRACT_DELIVERY",
                        )?;
                        (
                            ServiceResolutionKindV1::ArbitratorRefunded,
                            record.payer,
                            Some(decision.evidence),
                        )
                    }
                }
            } else {
                let output: Hash = payload[32..]
                    .try_into()
                    .map_err(|_| "SERVICE_CONTRACT_COMMAND")?;
                require(
                    sender == record.payer && record.delivered_output == Some(output),
                    "SERVICE_CONTRACT_ACCEPTANCE",
                )?;
                (
                    ServiceResolutionKindV1::CustomerAccepted,
                    record.terms.provider,
                    None,
                )
            };
            state.credit(&hex::encode(recipient), record.terms.budget)?;
            row["remaining"] = json!(0);
            row["status"] = json!(if kind == ServiceResolutionKindV1::ArbitratorRefunded {
                "refunded"
            } else {
                "settled"
            });
            Some(ServiceResolutionV1 {
                kind,
                actor: sender,
                nonce,
                height,
                evidence,
            })
        }
        _ => return Err("SERVICE_CONTRACT_COMMAND"),
    };
    record.resolution = resolution;
    write_record(&mut row, &record)?;
    read_contract(task, &row, cfg)?.ok_or("SERVICE_CONTRACT_RECORD")?;
    state.put(key, row);
    Ok(true)
}

#[cfg(test)]
mod tests;
