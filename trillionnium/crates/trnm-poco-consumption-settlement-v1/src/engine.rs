use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};

use crate::{
    codec::digest_value,
    error::{error, ConsumptionSettlementErrorCodeV1, ConsumptionSettlementResultV1},
    *,
};

const MAX_RECEIPTS_V1: usize = 1_024;
const MAX_USAGE_ENTRIES_V1: usize = 32;
const MAX_ID_BYTES_V1: usize = 128;

pub fn consumption_receipt_id_v1(
    body: &ConsumptionReceiptBodyV1,
) -> ConsumptionSettlementResultV1<ConsumptionReceiptIdV1> {
    Ok(digest_value("trnm.poco-ai.consumption-receipt.v1", body)?.into())
}

pub fn consumption_rollup_id_v1(
    body: &ConsumptionRollupBodyV1,
) -> ConsumptionSettlementResultV1<ConsumptionRollupIdV1> {
    Ok(digest_value("trnm.poco-ai.consumption-rollup.v1", body)?.into())
}

pub fn settlement_policy_hash_v1(
    policy: &SettlementPolicyV1,
) -> ConsumptionSettlementResultV1<Hash32V1> {
    digest_value("trnm.poco-ai.settlement-policy.v1", policy)
}

pub(crate) fn operation_id(
    command: &ConsumptionSettlementCommandV1,
) -> ConsumptionSettlementResultV1<ConsumptionOperationIdV1> {
    Ok(digest_value(
        "trnm.poco-ai.consumption-settlement-operation.candidate.v1",
        command,
    )?
    .into())
}

pub(crate) fn state_root(
    state: &ConsumptionSettlementKernelStateV1,
) -> ConsumptionSettlementResultV1<Hash32V1> {
    digest_value(
        "trnm.poco-ai.consumption-settlement-state-root.candidate.v1",
        state,
    )
}

pub(crate) fn initial_state(
    trust: &ConsumptionSettlementFreshGenesisTrustBundleV1,
) -> ConsumptionSettlementKernelStateV1 {
    let mut accounts = vec![
        AccountBalanceStateV1 {
            account_id: trust.provider_account_id,
            version: 0,
            balance: trust.provider_opening_balance,
        },
        AccountBalanceStateV1 {
            account_id: trust.consumer_account_id,
            version: 0,
            balance: trust.consumer_opening_balance,
        },
        AccountBalanceStateV1 {
            account_id: trust.protocol_account_id,
            version: 0,
            balance: trust.protocol_opening_balance,
        },
    ];
    accounts.sort_by_key(|account| account.account_id);
    ConsumptionSettlementKernelStateV1 {
        receipts: Vec::new(),
        rollup: None,
        settlement: None,
        escrow: EscrowBalanceStateV1 {
            escrow_id: trust.escrow_id,
            version: trust.escrow_version,
            balance: trust.escrow_funding,
            closed: false,
            last_settlement_id: None,
        },
        result: ResultSettlementStateV1 {
            result_id: trust.result_id,
            revision: trust.result_revision,
            result_status: trust.result_status,
            settlement_maturity: SETTLEMENT_MATURITY_NOT_STARTED_V1,
            settlement_id: None,
        },
        accounts,
    }
}

pub(crate) fn validate_trust_bundle(
    trust: &ConsumptionSettlementFreshGenesisTrustBundleV1,
) -> ConsumptionSettlementResultV1<()> {
    if trust.schema_version != SCHEMA_VERSION_V1
        || trust.context.protocol_version != 1
        || trust.context.chain_id.is_empty()
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidContext,
            "fresh-genesis trust context is invalid",
        ));
    }
    if trust.provider.agent_id == trust.consumer.agent_id
        || trust.provider.key_id == trust.consumer.key_id
        || trust.provider.public_key == trust.consumer.public_key
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidContext,
            "provider and consumer authorities must be distinct",
        ));
    }
    VerifyingKey::from_bytes(&trust.provider.public_key).map_err(|_| {
        error(
            ConsumptionSettlementErrorCodeV1::InvalidContext,
            "provider public key is invalid",
        )
    })?;
    VerifyingKey::from_bytes(&trust.consumer.public_key).map_err(|_| {
        error(
            ConsumptionSettlementErrorCodeV1::InvalidContext,
            "consumer public key is invalid",
        )
    })?;
    let accounts = [
        trust.provider_account_id,
        trust.consumer_account_id,
        trust.protocol_account_id,
    ];
    if accounts.into_iter().collect::<BTreeSet<_>>().len() != accounts.len() {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidContext,
            "settlement accounts must be distinct",
        ));
    }
    if trust.escrow_funding == 0
        || trust.result_status != RESULT_STATUS_FINAL_VALID_V1
        || trust.settlement_policy.schema_version != SCHEMA_VERSION_V1
        || trust.settlement_policy.maximum_rollups != 1
        || trust.settlement_policy.minimum_rollup_challenge_blocks == 0
        || trust.settlement_policy.protocol_fee_denominator == 0
        || trust.settlement_policy.protocol_fee_numerator
            > trust.settlement_policy.protocol_fee_denominator
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidBounds,
            "bounded settlement policy or funding is invalid",
        ));
    }
    if trust.prices.is_empty() || trust.prices.len() > MAX_USAGE_ENTRIES_V1 {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidBounds,
            "price table size is invalid",
        ));
    }
    require_strictly_sorted(&trust.prices, "price table")?;
    for price in &trust.prices {
        if price.resource_id.is_empty()
            || price.resource_id.len() > MAX_ID_BYTES_V1
            || price.meter_id.is_empty()
            || price.meter_id.len() > MAX_ID_BYTES_V1
            || price.unit_price == 0
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::InvalidBounds,
                "price entry is out of bounds",
            ));
        }
    }
    if trust.accepted_evidence_certificates.is_empty() {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidBounds,
            "at least one evidence certificate is required",
        ));
    }
    require_strictly_sorted(
        &trust.accepted_evidence_certificates,
        "evidence certificates",
    )?;
    Ok(())
}

pub(crate) fn validate_execution_static(
    trust: &ConsumptionSettlementFreshGenesisTrustBundleV1,
    execution: &ConsumptionOrderFinalizedExecutionContextV1,
) -> ConsumptionSettlementResultV1<()> {
    if execution.schema_version != SCHEMA_VERSION_V1 || execution.context != trust.context {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidContext,
            "execution context does not match fresh genesis",
        ));
    }
    if execution.order_height < execution.expected_order_height
        || (execution.order_height == execution.expected_order_height
            && execution.order_block_id != execution.expected_order_block_id)
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::StaleVersion,
            "order-finality input regresses or conflicts at one height",
        ));
    }
    Ok(())
}

pub(crate) fn apply_transition(
    trust: &ConsumptionSettlementFreshGenesisTrustBundleV1,
    state: &ConsumptionSettlementKernelStateV1,
    order_height: u64,
    command: &ConsumptionSettlementCommandV1,
) -> ConsumptionSettlementResultV1<(ConsumptionSettlementKernelStateV1, Option<SettlementIdV1>)> {
    let mut next = state.clone();
    let settlement_id = match command {
        ConsumptionSettlementCommandV1::AdmitReceipt { receipt } => {
            admit_receipt(trust, &mut next, order_height, receipt)?;
            None
        }
        ConsumptionSettlementCommandV1::AdmitRollup { rollup, receipts } => {
            admit_rollup(trust, &mut next, order_height, rollup, receipts)?;
            None
        }
        ConsumptionSettlementCommandV1::Settle { operation } => {
            Some(settle(trust, &mut next, order_height, operation)?)
        }
    };
    Ok((next, settlement_id))
}

fn admit_receipt(
    trust: &ConsumptionSettlementFreshGenesisTrustBundleV1,
    state: &mut ConsumptionSettlementKernelStateV1,
    order_height: u64,
    receipt: &ConsumptionReceiptV1,
) -> ConsumptionSettlementResultV1<()> {
    if state.rollup.is_some() || state.settlement.is_some() {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidTransition,
            "receipt admission is closed after rollup creation",
        ));
    }
    let body = &receipt.body;
    validate_common_body(trust, body)?;
    if body.period_end_height != order_height
        || body.period_start_height == 0
        || body.period_start_height > body.period_end_height
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidBounds,
            "receipt period is not bound to execution height",
        ));
    }
    if !trust
        .accepted_evidence_certificates
        .contains(&body.evidence_certificate_id)
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::Unauthorized,
            "evidence certificate is outside the local trust bundle",
        ));
    }
    validate_usage(&body.usage)?;
    let receipt_id = consumption_receipt_id_v1(body)?;
    verify_bilateral_signatures(
        trust,
        Hash32V1::from(receipt_id),
        body.period_end_height,
        "trnm.poco-ai.consumption-receipt-provider-signature.v1",
        "trnm.poco-ai.consumption-receipt-consumer-signature.v1",
        &receipt.provider_signature,
        &receipt.consumer_signature,
    )?;

    let expected_sequence = u64::try_from(state.receipts.len())
        .map_err(|_| {
            error(
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                "receipt count exceeds u64",
            )
        })?
        .checked_add(1)
        .ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                "receipt sequence overflow",
            )
        })?;
    if body.sequence != expected_sequence || state.receipts.len() >= MAX_RECEIPTS_V1 {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::SequenceGap,
            "receipt sequence is not the exact successor",
        ));
    }

    let prior = state.receipts.last();
    match prior {
        None => {
            if body.prior_receipt_id.is_some() || body.sequence != 1 {
                return Err(error(
                    ConsumptionSettlementErrorCodeV1::SequenceGap,
                    "sequence one must have no prior receipt",
                ));
            }
        }
        Some(prior) => {
            if body.prior_receipt_id != Some(prior.receipt_id)
                || body.period_start_height
                    != prior
                        .receipt
                        .body
                        .period_end_height
                        .checked_add(1)
                        .ok_or_else(|| {
                            error(
                                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                                "period height overflow",
                            )
                        })?
            {
                return Err(error(
                    ConsumptionSettlementErrorCodeV1::SequenceGap,
                    "receipt prior identity or period is not contiguous",
                ));
            }
        }
    }
    let expected_cumulative = derive_cumulative_usage(prior, &body.usage)?;
    if body.cumulative_usage != expected_cumulative
        || body.cumulative_usage_root
            != digest_value(
                "trnm.poco-ai.consumption-cumulative-usage-root.v1",
                &expected_cumulative,
            )?
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::RootMismatch,
            "cumulative usage preimage or root is invalid",
        ));
    }
    let period_charge = price_usage(trust, &body.usage)?;
    let prior_charge = prior
        .map(|entry| entry.receipt.body.cumulative_charge)
        .unwrap_or(0);
    let expected_charge = prior_charge.checked_add(period_charge).ok_or_else(|| {
        error(
            ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
            "cumulative charge overflow",
        )
    })?;
    if body.cumulative_charge != expected_charge || expected_charge > trust.escrow_funding {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InsufficientFunds,
            "receipt cumulative charge is invalid or exceeds escrow",
        ));
    }
    state.receipts.push(ConsumptionReceiptStateV1 {
        receipt: receipt.clone(),
        receipt_id,
        version: 0,
        status: 0,
        assigned_rollup_id: None,
        accepted_height: order_height,
    });
    Ok(())
}

fn admit_rollup(
    trust: &ConsumptionSettlementFreshGenesisTrustBundleV1,
    state: &mut ConsumptionSettlementKernelStateV1,
    order_height: u64,
    rollup: &ConsumptionRollupV1,
    supplied_receipts: &[ConsumptionReceiptV1],
) -> ConsumptionSettlementResultV1<()> {
    if state.rollup.is_some() || state.settlement.is_some() || state.receipts.is_empty() {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidTransition,
            "bounded candidate permits exactly one nonempty rollup",
        ));
    }
    let body = &rollup.body;
    if body.schema_version != SCHEMA_VERSION_V1
        || body.context != trust.context
        || body.provider_id != trust.provider.agent_id
        || body.consumer_id != trust.consumer.agent_id
        || body.task_id != trust.task_id
        || body.lease_id != trust.lease_id
        || body.attempt != trust.attempt
        || body.result_id != trust.result_id
        || body.escrow_id != trust.escrow_id
        || body.related_party_policy_hash != trust.related_party_policy_hash
        || body.settlement_policy_hash != settlement_policy_hash_v1(&trust.settlement_policy)?
        || body.evidence_certificate_id
            != state
                .receipts
                .last()
                .ok_or_else(|| {
                    error(
                        ConsumptionSettlementErrorCodeV1::NotFound,
                        "rollup receipt chain is absent",
                    )
                })?
                .receipt
                .body
                .evidence_certificate_id
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidContext,
            "rollup does not bind the bounded trust context",
        ));
    }
    let count = u32::try_from(state.receipts.len()).map_err(|_| {
        error(
            ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
            "receipt count exceeds u32",
        )
    })?;
    let last_sequence = u64::try_from(state.receipts.len()).map_err(|_| {
        error(
            ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
            "receipt count exceeds u64",
        )
    })?;
    let stored_receipts: Vec<_> = state
        .receipts
        .iter()
        .map(|entry| entry.receipt.clone())
        .collect();
    let receipt_ids: Vec<_> = state
        .receipts
        .iter()
        .map(|entry| entry.receipt_id)
        .collect();
    if supplied_receipts != stored_receipts
        || body.first_sequence != 1
        || body.last_sequence != last_sequence
        || body.receipt_count != count
        || body.receipt_ids != receipt_ids
        || state
            .receipts
            .iter()
            .any(|entry| entry.status != 0 || entry.assigned_rollup_id.is_some())
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::Conflict,
            "rollup interval is incomplete, reordered, or already assigned",
        ));
    }
    let receipt_entries: Vec<_> = receipt_ids
        .iter()
        .enumerate()
        .map(|(index, receipt_id)| {
            let sequence = u64::try_from(index)
                .map_err(|_| {
                    error(
                        ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                        "rollup index exceeds u64",
                    )
                })?
                .checked_add(1)
                .ok_or_else(|| {
                    error(
                        ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                        "rollup sequence overflow",
                    )
                })?;
            Ok((sequence, *receipt_id))
        })
        .collect::<ConsumptionSettlementResultV1<Vec<_>>>()?;
    if body.receipts_root
        != digest_value(
            "trnm.poco-ai.rollup-receipts-root.candidate.v1",
            &receipt_entries,
        )?
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::RootMismatch,
            "rollup receipts root is invalid",
        ));
    }
    let last = &state
        .receipts
        .last()
        .ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::NotFound,
                "rollup receipt chain is absent",
            )
        })?
        .receipt
        .body;
    let expected_totals: Vec<_> = last
        .cumulative_usage
        .iter()
        .map(|entry| ResourceUsageV1 {
            resource_class: entry.resource_class,
            resource_id: entry.resource_id.clone(),
            meter_id: entry.meter_id.clone(),
            meter_version: entry.meter_version,
            amount: entry.total_amount,
            unit: entry.unit,
            measurement_commitment: entry.accumulator_commitment,
        })
        .collect();
    if body.usage_totals != expected_totals || body.total_charge != last.cumulative_charge {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::ConservationViolation,
            "rollup totals do not equal the exact receipt chain",
        ));
    }
    let rollup_id = consumption_rollup_id_v1(body)?;
    verify_bilateral_signatures(
        trust,
        Hash32V1::from(rollup_id),
        order_height,
        "trnm.poco-ai.consumption-rollup-provider-signature.v1",
        "trnm.poco-ai.consumption-rollup-consumer-signature.v1",
        &rollup.provider_signature,
        &rollup.consumer_signature,
    )?;
    let close_height = order_height
        .checked_add(trust.settlement_policy.minimum_rollup_challenge_blocks)
        .ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                "rollup challenge close height overflow",
            )
        })?;
    for receipt_state in &mut state.receipts {
        receipt_state.version = receipt_state.version.checked_add(1).ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                "receipt state version overflow",
            )
        })?;
        receipt_state.status = 1;
        receipt_state.assigned_rollup_id = Some(rollup_id);
    }
    state.rollup = Some(ConsumptionRollupStateV1 {
        rollup: rollup.clone(),
        rollup_id,
        version: 0,
        accepted_height: order_height,
        challenge_close_height: close_height,
        status: 0,
        consumed_by_settlement_id: None,
    });
    Ok(())
}

fn settle(
    trust: &ConsumptionSettlementFreshGenesisTrustBundleV1,
    state: &mut ConsumptionSettlementKernelStateV1,
    order_height: u64,
    operation: &SettlementOperationBodyV1,
) -> ConsumptionSettlementResultV1<SettlementIdV1> {
    if state.settlement.is_some() || state.escrow.closed {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::AlreadyConsumed,
            "settlement is one-shot",
        ));
    }
    let rollup = state.rollup.as_ref().ok_or_else(|| {
        error(
            ConsumptionSettlementErrorCodeV1::NotFound,
            "rollup is absent",
        )
    })?;
    if operation.schema_version != SCHEMA_VERSION_V1
        || operation.context != trust.context
        || operation.task_id != trust.task_id
        || operation.lease_id != trust.lease_id
        || operation.attempt != trust.attempt
        || operation.result_id != trust.result_id
        || operation.expected_result_revision != state.result.revision
        || operation.expected_escrow_version != state.escrow.version
        || operation.expected_rollup_version != rollup.version
        || operation.settlement_policy_hash != settlement_policy_hash_v1(&trust.settlement_policy)?
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::StaleVersion,
            "settlement trigger does not match authenticated state",
        ));
    }
    if state.result.result_status != RESULT_STATUS_FINAL_VALID_V1
        || state.result.settlement_maturity != SETTLEMENT_MATURITY_NOT_STARTED_V1
        || rollup.status != 0
        || rollup.consumed_by_settlement_id.is_some()
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidTransition,
            "result or rollup state cannot settle",
        ));
    }
    if order_height <= rollup.challenge_close_height {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::NotMature,
            "rollup challenge window has not closed",
        ));
    }
    let total_charge = rollup.rollup.body.total_charge;
    if total_charge > state.escrow.balance {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InsufficientFunds,
            "rollup charge exceeds durable escrow",
        ));
    }
    let fee_product = total_charge
        .checked_mul(trust.settlement_policy.protocol_fee_numerator)
        .ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                "protocol fee product overflow",
            )
        })?;
    let protocol_fee = fee_product / trust.settlement_policy.protocol_fee_denominator;
    let provider_payment = total_charge.checked_sub(protocol_fee).ok_or_else(|| {
        error(
            ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
            "provider payment underflow",
        )
    })?;
    let consumer_refund = state
        .escrow
        .balance
        .checked_sub(total_charge)
        .ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                "consumer refund underflow",
            )
        })?;
    let mut deltas = Vec::new();
    if provider_payment > 0 {
        deltas.push(ValueDeltaV1 {
            asset_id: trust.asset_id,
            account_id: trust.provider_account_id,
            reason: 0,
            amount: provider_payment,
        });
    }
    if consumer_refund > 0 {
        deltas.push(ValueDeltaV1 {
            asset_id: trust.asset_id,
            account_id: trust.consumer_account_id,
            reason: 1,
            amount: consumer_refund,
        });
    }
    if protocol_fee > 0 {
        deltas.push(ValueDeltaV1 {
            asset_id: trust.asset_id,
            account_id: trust.protocol_account_id,
            reason: 2,
            amount: protocol_fee,
        });
    }
    deltas.sort();
    let output_total = deltas.iter().try_fold(0_u128, |total, delta| {
        total.checked_add(delta.amount).ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                "settlement output total overflow",
            )
        })
    })?;
    if output_total != state.escrow.balance {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::ConservationViolation,
            "settlement outputs do not conserve escrow input",
        ));
    }
    let inputs = vec![SettlementInputV1 {
        asset_id: trust.asset_id,
        escrow_id: state.escrow.escrow_id,
        escrow_version: state.escrow.version,
        amount: state.escrow.balance,
    }];
    let input_value_root = digest_value("trnm.poco-ai.settlement-input-root.v1", &inputs)?;
    let planned_deltas_root = digest_value("trnm.poco-ai.planned-deltas-root.v1", &deltas)?;
    let conservation = (
        trust.asset_id,
        input_value_root,
        planned_deltas_root,
        state.escrow.balance,
        output_total,
        provider_payment,
        consumer_refund,
        protocol_fee,
    );
    let conservation_root = digest_value("trnm.poco-ai.conservation-root.v1", &conservation)?;
    let intent = SettlementIntentV1 {
        schema_version: SCHEMA_VERSION_V1,
        context: trust.context.clone(),
        task_id: trust.task_id,
        lease_id: trust.lease_id,
        attempt: trust.attempt,
        result_id: trust.result_id,
        result_revision: state.result.revision,
        result_status: state.result.result_status,
        settlement_maturity: 1,
        escrow_id: trust.escrow_id,
        consumption_rollup_ids: vec![rollup.rollup_id],
        fee_schedule_hash: trust.settlement_policy.fee_schedule_hash,
        settlement_policy_hash: settlement_policy_hash_v1(&trust.settlement_policy)?,
        inputs,
        input_value_root,
        planned_deltas: deltas.clone(),
        planned_deltas_root,
        conservation_root,
    };
    let settlement_id: SettlementIdV1 = digest_value("trnm.poco-ai.settlement.v1", &intent)?.into();

    let mut post_versions = Vec::new();
    for delta in &deltas {
        let account = state
            .accounts
            .iter_mut()
            .find(|account| account.account_id == delta.account_id)
            .ok_or_else(|| {
                error(
                    ConsumptionSettlementErrorCodeV1::NotFound,
                    "settlement destination account is absent",
                )
            })?;
        let prior_version = account.version;
        account.balance = account.balance.checked_add(delta.amount).ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                "destination balance overflow",
            )
        })?;
        account.version = account.version.checked_add(1).ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                "account version overflow",
            )
        })?;
        post_versions.push(PostAccountVersionEntryV1 {
            account_id: account.account_id,
            prior_version,
            post_version: account.version,
            post_value_hash: digest_value(
                "trnm.poco-ai.account-value.candidate.v1",
                &(account.account_id, account.version, account.balance),
            )?,
        });
    }
    post_versions.sort_by_key(|entry| entry.account_id);
    let post_account_versions_root =
        digest_value("trnm.poco-ai.post-account-versions-root.v1", &post_versions)?;
    state.escrow.version = state.escrow.version.checked_add(1).ok_or_else(|| {
        error(
            ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
            "escrow version overflow",
        )
    })?;
    state.escrow.balance = 0;
    state.escrow.closed = true;
    state.escrow.last_settlement_id = Some(settlement_id);
    state.result.revision = state.result.revision.checked_add(1).ok_or_else(|| {
        error(
            ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
            "result revision overflow",
        )
    })?;
    state.result.settlement_maturity = SETTLEMENT_MATURITY_FINAL_V1;
    state.result.settlement_id = Some(settlement_id);
    let rollup = state.rollup.as_mut().ok_or_else(|| {
        error(
            ConsumptionSettlementErrorCodeV1::NotFound,
            "rollup disappeared during settlement",
        )
    })?;
    rollup.version = rollup.version.checked_add(1).ok_or_else(|| {
        error(
            ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
            "rollup version overflow",
        )
    })?;
    rollup.status = 1;
    rollup.consumed_by_settlement_id = Some(settlement_id);
    let receipt = SettlementReceiptV1 {
        schema_version: SCHEMA_VERSION_V1,
        context: trust.context.clone(),
        settlement_id,
        task_id: trust.task_id,
        lease_id: trust.lease_id,
        result_id: trust.result_id,
        escrow_id: trust.escrow_id,
        applied_deltas: deltas,
        post_account_versions: post_versions,
        post_account_versions_root,
        post_escrow_version: state.escrow.version,
    };
    state.settlement = Some(SettlementStateV1 {
        settlement_id,
        state_version: 0,
        intent,
        status: 1,
        receipt,
        applied_height: order_height,
    });
    Ok(settlement_id)
}

fn validate_common_body(
    trust: &ConsumptionSettlementFreshGenesisTrustBundleV1,
    body: &ConsumptionReceiptBodyV1,
) -> ConsumptionSettlementResultV1<()> {
    if body.schema_version != SCHEMA_VERSION_V1
        || body.context != trust.context
        || body.provider_id != trust.provider.agent_id
        || body.consumer_id != trust.consumer.agent_id
        || body.task_id != trust.task_id
        || body.lease_id != trust.lease_id
        || body.attempt != trust.attempt
        || body.result_id != trust.result_id
        || body.meter_id.is_empty()
        || body.meter_id.len() > MAX_ID_BYTES_V1
        || body.related_party_policy_hash != trust.related_party_policy_hash
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidContext,
            "receipt does not bind the bounded trust context",
        ));
    }
    Ok(())
}

fn validate_usage(usage: &[ResourceUsageV1]) -> ConsumptionSettlementResultV1<()> {
    if usage.is_empty() || usage.len() > MAX_USAGE_ENTRIES_V1 {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidBounds,
            "usage entry count is invalid",
        ));
    }
    require_strictly_sorted(usage, "resource usage")?;
    for entry in usage {
        if entry.resource_id.is_empty()
            || entry.resource_id.len() > MAX_ID_BYTES_V1
            || entry.meter_id.is_empty()
            || entry.meter_id.len() > MAX_ID_BYTES_V1
            || entry.amount == 0
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::InvalidBounds,
                "resource usage entry is invalid",
            ));
        }
    }
    Ok(())
}

fn derive_cumulative_usage(
    prior: Option<&ConsumptionReceiptStateV1>,
    usage: &[ResourceUsageV1],
) -> ConsumptionSettlementResultV1<Vec<CumulativeResourceUsageV1>> {
    type ResourceKey = (u16, Vec<u8>, Vec<u8>, u32, u16);
    let mut prior_map: BTreeMap<ResourceKey, (u128, Hash32V1)> = BTreeMap::new();
    if let Some(prior) = prior {
        for entry in &prior.receipt.body.cumulative_usage {
            prior_map.insert(
                (
                    entry.resource_class,
                    entry.resource_id.clone(),
                    entry.meter_id.clone(),
                    entry.meter_version,
                    entry.unit,
                ),
                (entry.total_amount, entry.accumulator_commitment),
            );
        }
    }
    let mut output = Vec::new();
    for entry in usage {
        let key = (
            entry.resource_class,
            entry.resource_id.clone(),
            entry.meter_id.clone(),
            entry.meter_version,
            entry.unit,
        );
        let (prior_total, prior_accumulator) = prior_map.remove(&key).unwrap_or_default();
        let total_amount = prior_total.checked_add(entry.amount).ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                "cumulative usage overflow",
            )
        })?;
        let accumulator_commitment = digest_value(
            "trnm.poco-ai.consumption-usage-accumulator.v1",
            &(
                &key,
                prior_total,
                (prior_total > 0).then_some(prior_accumulator),
                entry.amount,
                entry.measurement_commitment,
                total_amount,
            ),
        )?;
        output.push(CumulativeResourceUsageV1 {
            resource_class: entry.resource_class,
            resource_id: entry.resource_id.clone(),
            meter_id: entry.meter_id.clone(),
            meter_version: entry.meter_version,
            total_amount,
            unit: entry.unit,
            accumulator_commitment,
        });
    }
    if !prior_map.is_empty() {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidTransition,
            "bounded receipt must continue every cumulative resource key",
        ));
    }
    output.sort();
    Ok(output)
}

fn price_usage(
    trust: &ConsumptionSettlementFreshGenesisTrustBundleV1,
    usage: &[ResourceUsageV1],
) -> ConsumptionSettlementResultV1<u128> {
    usage.iter().try_fold(0_u128, |total, entry| {
        let price = trust
            .prices
            .iter()
            .find(|price| {
                price.resource_class == entry.resource_class
                    && price.resource_id == entry.resource_id
                    && price.meter_id == entry.meter_id
                    && price.meter_version == entry.meter_version
                    && price.unit == entry.unit
            })
            .ok_or_else(|| {
                error(
                    ConsumptionSettlementErrorCodeV1::Unauthorized,
                    "usage has no committed price",
                )
            })?;
        let charge = entry.amount.checked_mul(price.unit_price).ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                "usage charge overflow",
            )
        })?;
        total.checked_add(charge).ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                "period charge overflow",
            )
        })
    })
}

fn verify_bilateral_signatures(
    trust: &ConsumptionSettlementFreshGenesisTrustBundleV1,
    body_id: Hash32V1,
    authority_height: u64,
    provider_domain: &str,
    consumer_domain: &str,
    provider_entry: &BilateralSignatureEntryV1,
    consumer_entry: &BilateralSignatureEntryV1,
) -> ConsumptionSettlementResultV1<()> {
    verify_signature_entry(
        &trust.provider,
        provider_entry,
        body_id,
        authority_height,
        provider_domain,
    )?;
    verify_signature_entry(
        &trust.consumer,
        consumer_entry,
        body_id,
        authority_height,
        consumer_domain,
    )
}

fn verify_signature_entry(
    registered: &RegisteredBilateralKeyV1,
    entry: &BilateralSignatureEntryV1,
    body_id: Hash32V1,
    authority_height: u64,
    domain: &str,
) -> ConsumptionSettlementResultV1<()> {
    if entry.agent_id != registered.agent_id
        || entry.key_id != registered.key_id
        || entry.key_role != KEY_ROLE_BILATERAL_RECEIPT_V1
        || entry.policy_revision != registered.policy_revision
        || entry.key_generation != registered.key_generation
        || entry.authority_height != authority_height
        || entry.signature_scheme != SIGNATURE_SCHEME_ED25519_V1
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::Unauthorized,
            "bilateral authority statement does not match the current key",
        ));
    }
    let statement = BilateralSignatureStatementV1 {
        schema_version: SCHEMA_VERSION_V1,
        body_id,
        agent_id: entry.agent_id,
        key_id: entry.key_id,
        key_role: entry.key_role,
        policy_revision: entry.policy_revision,
        key_generation: entry.key_generation,
        authority_height: entry.authority_height,
    };
    let digest = digest_value(domain, &statement)?;
    let key = VerifyingKey::from_bytes(&registered.public_key).map_err(|_| {
        error(
            ConsumptionSettlementErrorCodeV1::InvalidSignature,
            "registered Ed25519 key is invalid",
        )
    })?;
    let signature = Signature::from_slice(&entry.signature).map_err(|_| {
        error(
            ConsumptionSettlementErrorCodeV1::InvalidSignature,
            "Ed25519 signature length is invalid",
        )
    })?;
    key.verify_strict(&digest.0, &signature).map_err(|_| {
        error(
            ConsumptionSettlementErrorCodeV1::InvalidSignature,
            "bilateral signature verification failed",
        )
    })
}

fn require_strictly_sorted<T: Ord>(values: &[T], label: &str) -> ConsumptionSettlementResultV1<()> {
    if values.windows(2).any(|window| window[0] >= window[1]) {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::NonCanonical,
            format!("{label} must be strictly sorted and unique"),
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn cumulative_usage_for_test(
    prior: Option<&ConsumptionReceiptStateV1>,
    usage: &[ResourceUsageV1],
) -> ConsumptionSettlementResultV1<Vec<CumulativeResourceUsageV1>> {
    derive_cumulative_usage(prior, usage)
}

#[cfg(test)]
pub(crate) fn cumulative_root_for_test(
    cumulative: &[CumulativeResourceUsageV1],
) -> ConsumptionSettlementResultV1<Hash32V1> {
    digest_value(
        "trnm.poco-ai.consumption-cumulative-usage-root.v1",
        &cumulative,
    )
}

#[cfg(test)]
pub(crate) fn receipts_root_for_test(
    receipt_ids: &[ConsumptionReceiptIdV1],
) -> ConsumptionSettlementResultV1<Hash32V1> {
    let entries: Vec<_> = receipt_ids
        .iter()
        .enumerate()
        .map(|(index, id)| (u64::try_from(index).unwrap_or(u64::MAX) + 1, *id))
        .collect();
    digest_value("trnm.poco-ai.rollup-receipts-root.candidate.v1", &entries)
}

#[cfg(test)]
pub(crate) fn signature_digest_for_test(
    domain: &str,
    statement: &BilateralSignatureStatementV1,
) -> ConsumptionSettlementResultV1<Hash32V1> {
    digest_value(domain, statement)
}

#[cfg(test)]
pub(crate) fn canonical_command_for_test(
    command: &ConsumptionSettlementCommandV1,
) -> ConsumptionSettlementResultV1<Vec<u8>> {
    crate::codec::canonical_bytes(command)
}
