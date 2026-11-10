//! Actual native Task funding for the explicit V3 parent-group research entry.
//!
//! Group amounts are submitted unchanged to the existing signed tag-2 owner.
//! Neither cancellation, Task payment, a supplied funding row nor a new budget
//! primitive is introduced. The append-only receipt is an execution observation,
//! not an independently administered funding or future-custody qualification.

use super::*;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::Instant,
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::continuity_v1;
use trnm_protocol::pon_wire::Envelope;

pub(super) const RETAIN_UNTIL: u64 = 100;
pub(super) const REPAIR_DEADLINE: u64 = 90;
pub(super) const FUNDING_RECEIPT_SCHEMA_V3: &str =
    "trnm.cell-native-shard-group-funding-receipt.v3";

const FUNDING_EXPIRES: u64 = 200;
const ROOT_AMOUNT: u64 = 100;

pub(super) fn open_node(path: &Path) -> Result<Node> {
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )?
    .with_permanent_account_growth_v2("native-cell-shard-research-v2")?;
    Ok(Node::open_with_permanent_account_growth_v2(path, settings)?)
}

pub(super) fn budget_config(node: &Node) -> NativeBudgetConfigV1 {
    NativeBudgetConfigV1 {
        network: node.settings().network(),
        parameters: node.settings().parameters(),
        genesis: node.settings().genesis(),
        max_records: 4_096,
    }
}

fn check_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err("original native funding deadline".into())
    }
}

fn append_receipt(file: &mut File, record: &Value, deadline: Instant) -> Result<()> {
    check_deadline(deadline)?;
    serde_json::to_writer(&mut *file, record)?;
    file.write_all(b"\n")?;
    file.sync_data()?;
    check_deadline(deadline)
}

/// Each (beneficiary, amount) becomes one actual original native Task. A single
/// original absolute deadline covers every signature, block, readback and sync.
/// Failures leave the complete already-written prefix and real native state.
pub(super) fn fund_all(
    node: &mut Node,
    grants: &[(Hash, u64)],
    receipt_path: &Path,
    deadline: Instant,
) -> Result<Vec<NativeFundingSourceV1>> {
    check_deadline(deadline)?;
    check(
        (1..=256).contains(&grants.len())
            && grants
                .iter()
                .all(|(beneficiary, amount)| *beneficiary != [0; 32] && *amount > 0),
        "bounded positive native funding roster",
    )?;
    let total = grants.iter().try_fold(0_u64, |sum, (_, amount)| {
        sum.checked_add(*amount)
            .ok_or("native funding monetary-total overflow")
    })?;
    let started = Instant::now();
    let mut receipt = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(receipt_path)?;
    append_receipt(
        &mut receipt,
        &json!({
            "schema": FUNDING_RECEIPT_SCHEMA_V3,
            "event": "begin",
            "expected_tasks": grants.len(),
            "expected_monetary_total": total,
            "known_development_keys": true,
            "native_ledger_coins_are_development_only": true,
            "independent_real_money_funding": false,
            "cancellations_submitted": false,
            "native_task_payments_submitted": false
        }),
        deadline,
    )?;
    let key = signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()])))
        .map_err(|_| "development signing key")?;
    let sender = development_public(0)?;
    let mut sources = Vec::with_capacity(grants.len());
    for batch in grants.chunks(16) {
        check_deadline(deadline)?;
        let nonce = node
            .next_nonce(sender)
            .map_err(|error| format!("NATIVE_GROUP_FUNDING_NONCE: {error}"))?;
        let first = sources.len();
        let mut transactions = Vec::with_capacity(batch.len());
        for (local, (beneficiary, amount)) in batch.iter().enumerate() {
            check_deadline(deadline)?;
            let index = sources.len();
            let nonce = nonce
                .checked_add(local as u64)
                .ok_or("funding nonce overflow")?;
            let until = FUNDING_EXPIRES
                .checked_add(index as u64 / 16)
                .ok_or("funding deadline overflow")?;
            let task = hash(
                b"task-instance-v3",
                &[
                    &node.settings().network(),
                    &node.settings().parameters(),
                    &sender,
                    &nonce.to_le_bytes(),
                    beneficiary,
                    &amount.to_le_bytes(),
                    &until.to_le_bytes(),
                ],
            );
            let mut payload = task.to_vec();
            payload.extend(beneficiary);
            payload.extend(amount.to_le_bytes());
            payload.extend(until.to_le_bytes());
            let mut transaction = Envelope {
                network: node.settings().network(),
                sender,
                nonce,
                expiry: 1_000,
                fee_limit: 1_000_000,
                tag: 2,
                payload,
                signature: [0; 64],
            };
            transaction.signature = hex::decode(sign_hex(
                &key,
                &transaction
                    .signing_digest()
                    .map_err(|_| "native funding signing digest")?,
            ))?
            .try_into()
            .map_err(|_| "native signature size")?;
            let wire = transaction
                .encode()
                .map_err(|_| "native funding transaction encoding")?;
            let source = NativeFundingSourceV1::Task(task);
            append_receipt(
                &mut receipt,
                &json!({
                    "schema": FUNDING_RECEIPT_SCHEMA_V3,
                    "event": "signed_transaction",
                    "index": index,
                    "source": source.key(),
                    "sender": hex::encode(sender),
                    "nonce": nonce,
                    "provider": hex::encode(beneficiary),
                    "amount": amount,
                    "native_deadline_height": until,
                    "transaction_expiry_height": transaction.expiry,
                    "signed_wire_hex": hex::encode(&wire),
                    "signed_wire_sha256": hex::encode(Sha256::digest(&wire)),
                    "elapsed_ns": started.elapsed().as_nanos() as u64
                }),
                deadline,
            )?;
            transactions.push(wire);
            sources.push(source);
        }
        let (parent, height) = node.active()?;
        let packet = node
            .make_growth_consensus_maintenance(
                parent,
                transactions,
                development_public(3)?,
                1 + 10 * (height + 1),
                4_096,
            )
            .map_err(|error| format!("NATIVE_GROUP_FUNDING_MAKE first={first}: {error}"))?;
        check_deadline(deadline)?;
        let tip = node
            .admit_growth(&packet, 100_000)
            .map_err(|error| format!("NATIVE_GROUP_FUNDING_ADMIT first={first}: {error}"))?;
        node.activate(tip).map_err(|error| {
            format!(
                "NATIVE_GROUP_FUNDING_ACTIVATE first={first} admitted={}: {error}",
                hex::encode(tip)
            )
        })?;
        append_receipt(
            &mut receipt,
            &json!({
                "schema": FUNDING_RECEIPT_SCHEMA_V3,
                "event": "block_admitted",
                "first_index": first,
                "end_index_exclusive": sources.len(),
                "block": hex::encode(tip),
                "parent": hex::encode(parent),
                "height": node.active()?.1,
                "elapsed_ns": started.elapsed().as_nanos() as u64
            }),
            deadline,
        )?;
    }
    for (index, (source, (beneficiary, amount))) in sources.iter().zip(grants).enumerate() {
        check_deadline(deadline)?;
        let observation = node.native_funding_observation(*source)?;
        let anchor = observation.anchor;
        let row = observation.row;
        let matched = observation.source == *source
            && row.as_ref().is_some_and(|row| {
                row["status"].as_str() == Some("reserved")
                    && row.get("output") == Some(&Value::Null)
                    && row["owner"].as_str() == Some(hex::encode(sender).as_str())
                    && row["remaining"].as_u64() == Some(*amount)
                    && row["deadline"].as_u64() == Some(FUNDING_EXPIRES + index as u64 / 16)
                    && row["provider"].as_str() == Some(hex::encode(beneficiary).as_str())
            });
        // Preserve the actual row, including null or a mismatch, before any
        // assertion can abort the run. This event never fabricates a row.
        append_receipt(
            &mut receipt,
            &json!({
                "schema": FUNDING_RECEIPT_SCHEMA_V3,
                "event": "native_funding_readback",
                "index": index,
                "source": source.key(),
                "observed_source": observation.source.key(),
                "expected_owner": hex::encode(sender),
                "expected_provider": hex::encode(beneficiary),
                "expected_amount": amount,
                "expected_native_deadline_height": FUNDING_EXPIRES + index as u64 / 16,
                "matches_expected": matched,
                "row": row,
                "anchor": {
                    "network": hex::encode(anchor.network),
                    "parameters": hex::encode(anchor.parameters),
                    "genesis": hex::encode(anchor.genesis),
                    "block": hex::encode(anchor.block),
                    "state_root": hex::encode(anchor.state_root),
                    "height": anchor.height,
                    "generation": anchor.generation
                },
                "elapsed_ns": started.elapsed().as_nanos() as u64
            }),
            deadline,
        )?;
        check(matched, "actual native task funding readback")?;
    }
    append_receipt(
        &mut receipt,
        &json!({
            "schema": FUNDING_RECEIPT_SCHEMA_V3,
            "event": "complete",
            "observed_tasks": sources.len(),
            "observed_monetary_total": total,
            "elapsed_ns": started.elapsed().as_nanos() as u64
        }),
        deadline,
    )?;
    Ok(sources)
}

/// Existing root/member helper: original single-claim Task amount stays 100.
/// V3 storage/repair parents use their independently checked aggregate sums.
pub(super) fn policy_claim(
    operation: Hash,
    label: &[u8],
    index: usize,
    source: NativeFundingSourceV1,
    binding: (Hash, Hash, Hash),
    resources: NativeBudgetResourcesV1,
) -> (NativeBudgetPolicyV1, NativeBudgetClaimV1) {
    let (claim, subject, beneficiary) = binding;
    let budget = identity(operation, label, index);
    (
        NativeBudgetPolicyV1 {
            budget,
            source,
            monetary_cap: ROOT_AMOUNT,
            deadline: RETAIN_UNTIL,
            resource_cap: resources.clone(),
            max_inflight: 1,
        },
        NativeBudgetClaimV1 {
            claim,
            budget,
            subject,
            beneficiary,
            monetary_reservation: ROOT_AMOUNT,
            resource_reservation: resources,
        },
    )
}
