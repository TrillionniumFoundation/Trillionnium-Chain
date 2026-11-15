//! Pure relations consumed only by the existing Node durable budget path.
use super::{canonical, Node, SCHEMA};
use crate::{digest, ensure, sequence_root, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use trnm_protocol::pon_wire::{hash, Hash};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeBudgetLaneV1 {
    Mining,
    Contribution,
    Evaluation,
    Storage,
    Serving,
}
impl NativeBudgetLaneV1 {
    fn prefix(self) -> &'static str {
        match self {
            Self::Mining => "reward:",
            Self::Contribution => "release:",
            Self::Evaluation | Self::Storage => "task:",
            Self::Serving => "quota:",
        }
    }
}

/// Protected local owner inputs, not a peer request, signature or capacity proof.
/// Units are lane-specific pairs documented in REWARD_BUDGETS_V1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBudgetRequestV1 {
    pub operation: Hash,
    pub subject: Hash,
    pub beneficiary: Hash,
    pub lane: NativeBudgetLaneV1,
    pub source: Hash,
    pub amount: u64,
    pub source_cap: u64,
    pub resource_cap: [u64; 2],
    pub resource_reservation: [u64; 2],
    pub contribution: Option<NativeContributionClaimV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeContributionClaimV1 {
    pub candidate: Hash,
    pub score: u64,
    pub siblings: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Funding {
    pub(super) owner: Hash,
    pub(super) remaining: u64,
    pub(super) maturity: u64,
    pub(super) deadline: Option<u64>,
    pub(super) digest: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub(super) schema: String,
    pub(super) network: Hash,
    pub(super) parameters: Hash,
    pub(super) genesis: Hash,
    pub(super) request: NativeBudgetRequestV1,
    pub(super) source_tip: Hash,
    pub(super) source_generation: u64,
    pub(super) source_height: u64,
    pub(super) funding: Funding,
    pub(super) consumed: Option<[u64; 2]>,
    pub(super) effect: Option<Hash>,
    pub(super) receipt: Option<Hash>,
}

/// Native durable readback, always without payment or external-effect authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NativeBudgetObservationV1 {
    pub operation: Hash,
    pub funding_current: bool,
    pub resources_consumed: Option<[u64; 2]>,
    pub effect_pending: bool,
    pub effect_completed: bool,
    pub durable_records: usize,
    pub chain_funds_locked: bool,
    pub payment_executed: bool,
    pub execution_authority: bool,
    pub production_activation: bool,
}

/// Exact retained LOCAL obligation, including an unauthenticated receipt hash.
/// The source observation is historical; this record grants no execution right.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NativeBudgetLocalRecordV1 {
    pub request: NativeBudgetRequestV1,
    pub source_tip: Hash,
    pub source_generation: u64,
    pub source_height: u64,
    pub source_funding_digest: Hash,
    pub resources_consumed: Option<[u64; 2]>,
    pub effect: Option<Hash>,
    pub receipt: Option<Hash>,
}

/// Bounded local recovery inventory, not funding, delivery or payment authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NativeBudgetInventoryV1 {
    pub schema: &'static str,
    pub network: Hash,
    pub parameters: Hash,
    pub genesis: Hash,
    pub records: Vec<NativeBudgetLocalRecordV1>,
    pub chain_funds_locked: bool,
    pub payment_executed: bool,
    pub execution_authority: bool,
    pub production_activation: bool,
}

pub(super) fn source_key(request: &NativeBudgetRequestV1) -> String {
    format!("{}{}", request.lane.prefix(), hex::encode(request.source))
}
pub(super) fn funding(value: &Value, lane: NativeBudgetLaneV1) -> Result<Funding> {
    let number = |name: &str| {
        value[name]
            .as_u64()
            .ok_or_else(|| Error::from("BUDGET_SOURCE"))
    };
    let owner = digest(value["owner"].as_str().ok_or("BUDGET_SOURCE")?)?;
    let (remaining, maturity, deadline) = match lane {
        NativeBudgetLaneV1::Mining => (number("amount")?, number("maturity")?, None),
        NativeBudgetLaneV1::Contribution => {
            ensure(value["status"] == "open", "BUDGET_SOURCE")?;
            (
                number("remaining")?,
                number("maturity")?,
                Some(number("deadline")?),
            )
        }
        NativeBudgetLaneV1::Evaluation | NativeBudgetLaneV1::Storage => {
            ensure(
                value["status"] == "reserved" || value["status"] == "receipt",
                "BUDGET_SOURCE",
            )?;
            (number("remaining")?, 0, Some(number("deadline")?))
        }
        NativeBudgetLaneV1::Serving => {
            ensure(value["status"] == "reserved", "BUDGET_SOURCE")?;
            (number("remaining")?, 0, Some(number("deadline")?))
        }
    };
    ensure(remaining > 0, "BUDGET_SOURCE")?;
    Ok(Funding {
        owner,
        remaining,
        maturity,
        deadline,
        digest: hash(b"native-budget-source-v1", &[&canonical(value)?]),
    })
}
pub(super) fn verify_payee(value: &Value, request: &NativeBudgetRequestV1) -> Result<()> {
    if request.lane == NativeBudgetLaneV1::Contribution {
        let claim = request.contribution.as_ref().ok_or("BUDGET_ALLOCATION")?;
        let count = value["leaf_count"].as_u64().ok_or("BUDGET_ALLOCATION")?;
        let total = value["total"].as_u64().ok_or("BUDGET_ALLOCATION")?;
        let budget = value["budget"].as_u64().ok_or("BUDGET_ALLOCATION")?;
        ensure(
            (1..=16).contains(&count)
                && total > 0
                && claim.score > 0
                && request.subject == claim.candidate
                && claim.siblings.len() <= 8
                && claim.siblings.len() == (64 - (count - 1).leading_zeros()) as usize
                && value["claims"].get(hex::encode(claim.candidate)).is_none(),
            "BUDGET_ALLOCATION",
        )?;
        let mut leaf = hash(
            b"allocation-leaf",
            &[
                &claim.candidate,
                &request.beneficiary,
                &claim.score.to_le_bytes(),
            ],
        );
        for sibling in &claim.siblings {
            leaf = if leaf < *sibling {
                hash(b"allocation-node", &[&leaf, sibling])
            } else {
                hash(b"allocation-node", &[sibling, &leaf])
            };
        }
        let amount = (budget as u128) * (claim.score as u128) / (total as u128);
        ensure(
            leaf == digest(value["root"].as_str().ok_or("BUDGET_ALLOCATION")?)?
                && amount == request.amount as u128,
            "BUDGET_ALLOCATION",
        )
    } else {
        let field = if request.lane == NativeBudgetLaneV1::Mining {
            "owner"
        } else {
            "provider"
        };
        ensure(
            request.contribution.is_none()
                && digest(value[field].as_str().ok_or("BUDGET_PAYEE")?)? == request.beneficiary,
            "BUDGET_PAYEE",
        )
    }
}
pub(super) fn validate_record(node: &Node, record: &Record) -> Result<()> {
    let request = &record.request;
    ensure(
        record.schema == SCHEMA
            && record.network == node.settings.network()
            && record.parameters == node.settings.parameters()
            && record.genesis == node.settings.genesis(),
        "BUDGET_CONTEXT",
    )?;
    ensure(
        [
            request.operation,
            request.subject,
            request.beneficiary,
            request.source,
        ]
        .iter()
        .all(|id| *id != [0; 32])
            && request.amount > 0
            && request.amount <= request.source_cap
            && request.source_cap <= record.funding.remaining,
        "BUDGET_AMOUNT",
    )?;
    ensure(
        request.resource_cap.iter().all(|n| *n > 0)
            && request.resource_reservation.iter().any(|n| *n > 0)
            && (0..2).all(|i| request.resource_reservation[i] <= request.resource_cap[i])
            && record
                .consumed
                .is_none_or(|actual| (0..2).all(|i| actual[i] <= request.resource_reservation[i])),
        "BUDGET_RESOURCES",
    )?;
    ensure(
        record.effect != Some([0; 32])
            && record.receipt != Some([0; 32])
            && (record.effect.is_none() || record.consumed.is_some())
            && (record.receipt.is_none() || record.effect.is_some()),
        "BUDGET_EFFECT",
    )
}
pub(super) fn validate_totals(records: &BTreeMap<String, Record>) -> Result<()> {
    let mut subjects = BTreeSet::new();
    for record in records.values() {
        let request = &record.request;
        ensure(
            subjects.insert((request.lane.prefix(), request.subject)),
            "BUDGET_SUBJECT_REPLAY",
        )?;
        let mut amount = 0u64;
        let mut resources = [0u64; 2];
        for same in records
            .values()
            .filter(|r| source_key(&r.request) == source_key(request))
        {
            ensure(
                same.request.lane == request.lane
                    && same.request.source_cap == request.source_cap
                    && same.request.resource_cap == request.resource_cap
                    && same.funding == record.funding,
                "BUDGET_SOURCE_REPLAY",
            )?;
            amount = amount
                .checked_add(same.request.amount)
                .ok_or("BUDGET_AMOUNT")?;
            let debt = same.consumed.unwrap_or(same.request.resource_reservation);
            for i in 0..2 {
                resources[i] = resources[i]
                    .checked_add(debt[i])
                    .ok_or("BUDGET_RESOURCES")?;
            }
        }
        ensure(
            amount <= request.source_cap && (0..2).all(|i| resources[i] <= request.resource_cap[i]),
            "BUDGET_CAPACITY",
        )?;
    }
    Ok(())
}
pub(super) fn head(records: &BTreeMap<String, Record>) -> Result<Vec<u8>> {
    let bytes = records
        .values()
        .map(|record| canonical(&serde_json::to_value(record)?))
        .collect::<Result<Vec<_>>>()?;
    canonical(
        &serde_json::json!({"schema":"pon-native-budget-set-v1", "count":records.len(),
        "root":hex::encode(sequence_root("native-budget-set-v1", &bytes))}),
    )
}
