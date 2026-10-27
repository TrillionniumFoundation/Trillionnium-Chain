//! Fresh-namespace native ML-DSA -> existing M06 transfer arithmetic preview.
//! This is a pure component entry: no installed PNX1 dispatch, block inclusion,
//! mempool admission, SQLite commit, migration, final-use or activation follows.
//! Every call authenticates its exact bytes and checks the supplied parent anew.
use super::{
    canonical, debit_authorized_fee, require, root_for_config, transfer_balances, Config, Result,
    State, View,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use trnm_crypto_primitives::pq_auth::verify_tpq1;
use trnm_protocol::pq_frame::{ml_dsa_65_key_id_from_spki, PqFrameExpectation};
use trnm_protocol::pq_transfer::{decode_unverified, owner_context, statement_identity};

pub const PROFILE: &str = "pq-native-fresh-transfer-preview-v1";

/// Separate identity from every installed classic or imported account network.
/// A future durable owner must persist this exact namespace; no implicit import.
pub fn research_network(config: &Config) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"TRNM/PoN/QTX1NativeTransfer/v1\0");
    digest.update(config.network);
    digest.update(config.parameters);
    digest.finalize().into()
}

#[derive(Debug)]
pub struct PqTransferPreview {
    pub network: [u8; 32],
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub statement_id: [u8; 48],
    pub state: State,
    pub fee: u64,
    pub receipt: Vec<u8>,
}

/// QTX1 expiry is an absolute UTC second. It is never reinterpreted as PNX1's
/// block-height expiry. Generation 1 and key-id-addressed fresh accounts are the
/// only supported ownership relation: migration/key rotation remain unimplemented.
pub fn preview_fresh_transfer(
    parent: &State,
    raw: &[u8],
    pinned_spki: &[u8],
    now: u64,
    config: &Config,
) -> Result<PqTransferPreview> {
    let transfer = decode_unverified(raw).map_err(|_| "PQ_ENCODING")?;
    let network = research_network(config);
    require(transfer.network == network, "PQ_NETWORK")?;
    require(transfer.generation == 1, "PQ_FRESH_ONLY")?;
    require(now <= transfer.expires_at, "PQ_EXPIRED")?;
    require(transfer.max_fee <= config.limit("max_fee_limit")?, "FEE")?;
    let key_id = ml_dsa_65_key_id_from_spki(pinned_spki).map_err(|_| "PQ_KEY")?;
    require(transfer.sender == key_id, "PQ_OWNER")?;
    let expected = PqFrameExpectation {
        purpose: 1,
        network,
        owner_context: owner_context(&network, &transfer.sender),
        signer_key_id: key_id,
        owner_generation: 1,
        operation_sequence: transfer.nonce,
        expires_at: transfer.expires_at,
        now,
        payload: transfer.body(),
    };
    let verified =
        verify_tpq1(transfer.frame(), &expected, pinned_spki).map_err(|_| "PQ_SIGNATURE")?;
    require(verified.signer_key_id() == &transfer.sender, "PQ_OWNER")?;
    // A signature is not a parent/root/nonce verdict. Re-read the actual complete
    // parent and invoke the same private arithmetic as installed M06 PNX1.
    let parent_root = root_for_config(parent, config)?;
    let sender = hex::encode(transfer.sender);
    let mut view = View::new(parent, None);
    let fee = debit_authorized_fee(
        &mut view,
        &sender,
        1,
        transfer.nonce,
        transfer.max_fee,
        raw.len(),
        config,
    )?;
    transfer_balances(
        &mut view,
        &sender,
        &hex::encode(transfer.recipient),
        transfer.amount,
    )?;
    let mut account = view.account(&sender)?;
    account["nonce"] = json!(transfer.nonce);
    view.put(format!("account:{sender}"), account);
    let mut state = parent.clone();
    state.extend(view.writes);
    let state_root = root_for_config(&state, config)?;
    let statement_id = statement_identity(&transfer, &key_id);
    let receipt = canonical(&json!({
        "profile": PROFILE,
        "network": hex::encode(network),
        "statement": hex::encode(statement_id),
        "parent_root": hex::encode(parent_root),
        "state_root": hex::encode(state_root),
        "fee": fee,
        "status": "preview_only",
        "production_activation": false,
        "native_pq_node_integrated": false,
    }))?;
    Ok(PqTransferPreview {
        network,
        parent_root,
        state_root,
        statement_id,
        state,
        fee,
        receipt,
    })
}

#[cfg(test)]
mod tests;
