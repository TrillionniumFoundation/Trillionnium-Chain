//! Explicit fresh native PQ transfer profile, composed by the original executor.
//! No legacy account import, key registration/rotation, transport or activation.
use super::{
    canonical, debit_authorized_fee, hash32, require, transfer_balances, AccountPointAccess,
    Config, Hash, Patch, Result, State, View,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use trnm_crypto_primitives::pq_auth::verify_tpq1;
use trnm_protocol::pon_wire::hash;
use trnm_protocol::pq_frame::{ml_dsa_65_key_id_from_spki, PqFrameExpectation};
use trnm_protocol::pq_native_transfer_v1::{self as wire, ChainContext, UnverifiedEnvelope};

pub use wire::PROFILE;
pub const MAX_GENESIS_ACCOUNTS: usize = 64;
const KEY_PREFIX: &str = "pq-key-v1:";
const AUTH_PREFIX: &str = "pq-auth-v1:";

#[derive(Clone, Debug)]
pub struct GenesisAccount {
    /// Public key only. This constructor never receives or retains a signing key.
    pub spki: Vec<u8>,
    pub balance: u64,
}

#[derive(Clone)]
pub(crate) struct Profile {
    context: ChainContext,
    config_digest: Hash,
    keys: BTreeMap<String, Vec<u8>>,
}

fn config_digest(cfg: &Config) -> Result<Hash> {
    Ok(hash(
        b"native-pq-config-integrity-v1",
        &[
            &cfg.network,
            &cfg.parameters,
            &canonical(&cfg.params)?,
            &canonical(&cfg.model_registry)?,
            &canonical(&json!(cfg.fees))?,
            &cfg.family,
            &cfg.plan,
            &canonical(&json!(cfg.evaluators))?,
        ],
    ))
}
pub fn enabled(cfg: &Config) -> bool {
    cfg.native_pq.is_some() || cfg.params.get("native_pq_profile").is_some()
}
fn policy(cfg: &Config) -> Result<&Profile> {
    let p = cfg.native_pq.as_deref().ok_or("PQ_PROFILE_REQUIRED")?;
    require(
        cfg.params["native_pq_profile"] == PROFILE
            && cfg.network == p.context.network
            && cfg.parameters == p.context.parameters
            && config_digest(cfg)? == p.config_digest,
        "PQ_CONFIG_CHANGED",
    )?;
    Ok(p)
}
pub fn context(cfg: &Config) -> Result<ChainContext> {
    let context = policy(cfg)?.context;
    require(context.genesis != [0; 32], "PQ_GENESIS")?;
    Ok(context)
}
fn authority(key: &str) -> Value {
    json!({"schema":1,"algorithm":101,"key_id":key,"generation":1,"retired":false})
}

/// Construct one new valueless genesis. Complete sorted public keys, allocations,
/// timestamp and fixed caps are bound before any signature can be accepted.
pub fn genesis(accounts: &[GenesisAccount], timestamp: u64) -> Result<(Config, State, Hash)> {
    require(
        (1..=MAX_GENESIS_ACCOUNTS).contains(&accounts.len()) && timestamp > 0,
        "PQ_GENESIS_LIMIT",
    )?;
    let mut keys = BTreeMap::new();
    let mut balances = BTreeMap::new();
    let mut issued = 0_u64;
    for account in accounts {
        let key = ml_dsa_65_key_id_from_spki(&account.spki).map_err(|_| "PQ_KEY")?;
        require(key != [0; 32], "PQ_KEY")?;
        let id = hex::encode(key);
        require(
            keys.insert(id.clone(), account.spki.clone()).is_none(),
            "PQ_DUPLICATE_KEY",
        )?;
        balances.insert(id, account.balance);
        issued = issued.checked_add(account.balance).ok_or("RANGE")?;
    }
    require(issued > 0, "PQ_GENESIS_FUNDS")?;
    let descriptor: Vec<Value> = keys.iter().map(|(id,spki)|
        json!({"account":id,"spki":hex::encode(spki),"balance":balances[id],"generation":1,"retired":false})).collect();
    let descriptor = canonical(
        &json!({"profile":PROFILE,"timestamp":timestamp,"accounts":descriptor,
        "transaction_bytes":wire::MAX_BYTES,"transaction_total":wire::MAX_TRANSACTION_BYTES,
        "transaction_count":wire::MAX_TRANSACTIONS,"packet_bytes":1048576,
        "production_activation":false}),
    )?;
    let mut cfg =
        Config::installed_with_profiles("legacy-first-two-v3", crate::continuity_v1::PROFILE)?;
    let base_network = cfg.network;
    let base_parameters = cfg.parameters;
    cfg.params["native_pq_profile"] = json!(PROFILE);
    cfg.params["genesis_timestamp"] = json!(timestamp);
    cfg.params["genesis_accounts"] = json!(keys.len());
    cfg.params["native_pq_descriptor"] = json!(hex::encode(hash(
        b"native-pq-genesis-descriptor-v1",
        &[&descriptor]
    )));
    cfg.network = hash(b"native-pq-network-v1", &[&base_network, &descriptor]);
    cfg.parameters = hash(
        b"native-pq-parameters-v1",
        &[
            &base_parameters,
            &cfg.network,
            &canonical(&cfg.params)?,
            &descriptor,
        ],
    );
    let profile = Profile {
        context: ChainContext {
            network: cfg.network,
            parameters: cfg.parameters,
            genesis: [0; 32],
        },
        config_digest: config_digest(&cfg)?,
        keys,
    };
    cfg.native_pq = Some(Arc::new(profile));
    let mut state = State::from([
        ("meta:issued".into(), json!(issued)),
        ("model:current".into(), json!(hex::encode([0; 32]))),
    ]);
    state.extend(crate::continuity_v1::bootstrap_state(&cfg)?);
    for (id, spki) in &policy(&cfg)?.keys {
        state.insert(
            format!("account:{id}"),
            json!({"balance":balances[id],"nonce":0}),
        );
        state.insert(format!("{AUTH_PREFIX}{id}"), authority(id));
        state.insert(format!("{KEY_PREFIX}{id}"), json!(hex::encode(spki)));
    }
    validate_state(&state, &cfg)?;
    crate::continuity_v1::check_state(&state, 0, &cfg)?;
    let genesis = hash(
        b"genesis",
        &[
            &cfg.network,
            &cfg.parameters,
            &super::root(&state)?,
            &timestamp.to_le_bytes(),
        ],
    );
    Arc::get_mut(cfg.native_pq.as_mut().ok_or("PQ_PROFILE_REQUIRED")?)
        .ok_or("PQ_CONFIG_SHARED")?
        .context
        .genesis = genesis;
    Ok((cfg, state, genesis))
}

/// Exact grammar and membership for the new State namespaces. Transfers cannot
/// register/retire/rotate keys. All public key bytes participate in the actual root.
pub fn validate_state(state: &State, cfg: &Config) -> Result<()> {
    if !enabled(cfg) {
        return Ok(());
    }
    let p = policy(cfg)?;
    for prefix in [KEY_PREFIX, AUTH_PREFIX, "account:"] {
        let rows: Vec<_> = state
            .keys()
            .filter_map(|k| k.strip_prefix(prefix))
            .collect();
        require(
            rows.len() == p.keys.len() && rows.iter().all(|id| p.keys.contains_key(*id)),
            "PQ_STATE_MEMBERSHIP",
        )?;
    }
    for (id, spki) in &p.keys {
        require(
            state.get(&format!("{AUTH_PREFIX}{id}")) == Some(&authority(id)),
            "PQ_AUTH_STATE",
        )?;
        let value = state
            .get(&format!("{KEY_PREFIX}{id}"))
            .ok_or("PQ_KEY_STATE")?;
        require(
            value.as_str() == Some(hex::encode(spki).as_str()) && canonical(value)?.len() == 3950,
            "PQ_KEY_STATE",
        )?;
        let account = state
            .get(&format!("account:{id}"))
            .and_then(Value::as_object)
            .ok_or("PQ_ACCOUNT_STATE")?;
        require(
            account.len() == 2
                && account.get("balance").is_some_and(Value::is_u64)
                && account.get("nonce").is_some_and(Value::is_u64),
            "PQ_ACCOUNT_STATE",
        )?;
    }
    Ok(())
}

fn authorize(view: &mut View<'_>, id: Hash, cfg: &Config) -> Result<Vec<u8>> {
    let name = hex::encode(id);
    let pinned = policy(cfg)?
        .keys
        .get(&name)
        .ok_or("PQ_UNREGISTERED_ACCOUNT")?;
    // Both are actual MVCC reads, not facts supplied by the signature preparer.
    let auth = view
        .get(&format!("{AUTH_PREFIX}{name}"))
        .ok_or("PQ_AUTH_STATE")?;
    require(auth == authority(&name), "PQ_AUTHORITY")?;
    let key = view
        .get(&format!("{KEY_PREFIX}{name}"))
        .ok_or("PQ_KEY_STATE")?;
    require(
        key.as_str() == Some(hex::encode(pinned).as_str()),
        "PQ_KEY_STATE",
    )?;
    Ok(pinned.clone())
}
pub fn validate_block(
    parent: &State,
    transactions: &[Vec<u8>],
    miner: Hash,
    timestamp: Option<u64>,
    cfg: &Config,
) -> Result<()> {
    if !enabled(cfg) {
        return Ok(());
    }
    context(cfg)?;
    require(timestamp.is_some(), "PQ_HEADER_TIMESTAMP_REQUIRED")?;
    require(
        transactions.len() <= wire::MAX_TRANSACTIONS,
        "PQ_TRANSACTION_LIMIT",
    )?;
    let mut bytes = 0_usize;
    for raw in transactions {
        UnverifiedEnvelope::decode(raw).map_err(|_| "PQ_ENCODING")?;
        bytes = bytes.checked_add(raw.len()).ok_or("PQ_TRANSACTION_LIMIT")?;
        require(bytes <= wire::MAX_TRANSACTION_BYTES, "PQ_TRANSACTION_LIMIT")?;
    }
    validate_state(parent, cfg)?;
    authorize(&mut View::new(parent, None), miner, cfg)?;
    Ok(())
}

/// Actual signature possession only. Private fields prevent external construction;
/// current State authorization, nonce, fee, balance and execution still follow.
pub struct PreparedTransfer {
    raw: Vec<u8>,
    context: ChainContext,
    sender: Hash,
    recipient: Hash,
    nonce: u64,
    expires_at: u64,
    amount: u64,
    max_fee: u64,
    spki: Vec<u8>,
    wire_id: Hash,
    statement_id: [u8; 48],
}
impl PreparedTransfer {
    pub fn sender(&self) -> Hash {
        self.sender
    }
    pub fn nonce(&self) -> u64 {
        self.nonce
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn max_fee(&self) -> u64 {
        self.max_fee
    }
    pub fn wire_id(&self) -> Hash {
        self.wire_id
    }
    pub fn statement_id(&self) -> [u8; 48] {
        self.statement_id
    }
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}
pub fn prepare_signature(raw: &[u8], timestamp: u64, cfg: &Config) -> Result<PreparedTransfer> {
    let context = context(cfg)?;
    let envelope = UnverifiedEnvelope::decode(raw).map_err(|_| "PQ_ENCODING")?;
    let transfer = envelope.transfer();
    require(transfer.network == context.network, "PQ_NETWORK")?;
    require(
        transfer.generation == 1 && transfer.sender == envelope.key_id(),
        "PQ_FRESH_AUTHORITY",
    )?;
    require(transfer.max_fee <= cfg.limit("max_fee_limit")?, "FEE")?;
    let expected = PqFrameExpectation {
        purpose: 1,
        network: context.network,
        owner_context: wire::owner_context(context, transfer.sender).map_err(|_| "PQ_CONTEXT")?,
        signer_key_id: envelope.key_id(),
        owner_generation: 1,
        operation_sequence: transfer.nonce,
        expires_at: transfer.expires_at,
        now: timestamp,
        payload: transfer.body(),
    };
    verify_tpq1(transfer.frame(), &expected, envelope.spki()).map_err(|_| "PQ_SIGNATURE")?;
    Ok(PreparedTransfer {
        raw: raw.to_vec(),
        context,
        sender: transfer.sender,
        recipient: transfer.recipient,
        nonce: transfer.nonce,
        expires_at: transfer.expires_at,
        amount: transfer.amount,
        max_fee: transfer.max_fee,
        spki: envelope.spki().to_vec(),
        wire_id: envelope.wire_id(),
        statement_id: envelope.statement_id(context).map_err(|_| "PQ_CONTEXT")?,
    })
}
pub fn validate_current_authority(parent: &State, raw: &[u8], cfg: &Config) -> Result<()> {
    let envelope = UnverifiedEnvelope::decode(raw).map_err(|_| "PQ_ENCODING")?;
    let mut view = View::new(parent, None);
    require(
        authorize(&mut view, envelope.transfer().sender, cfg)? == envelope.spki(),
        "PQ_KEY_STATE",
    )?;
    authorize(&mut view, envelope.transfer().recipient, cfg)?;
    Ok(())
}
pub(super) fn apply(
    base: &State,
    prepared: &PreparedTransfer,
    cfg: &Config,
    access: Option<&AccountPointAccess<'_>>,
) -> Result<Patch> {
    require(prepared.context == context(cfg)?, "PQ_PREPARED_CONTEXT")?;
    let mut view = View::new(base, access);
    require(
        authorize(&mut view, prepared.sender, cfg)? == prepared.spki,
        "PQ_KEY_STATE",
    )?;
    authorize(&mut view, prepared.recipient, cfg)?;
    let sender = hex::encode(prepared.sender);
    let fee = debit_authorized_fee(
        &mut view,
        &sender,
        1,
        prepared.nonce,
        prepared.max_fee,
        prepared.raw.len(),
        cfg,
    )?;
    transfer_balances(
        &mut view,
        &sender,
        &hex::encode(prepared.recipient),
        prepared.amount,
    )?;
    let mut account = view.account(&sender)?;
    account["nonce"] = json!(prepared.nonce);
    view.put(format!("account:{sender}"), account);
    let receipt = canonical(
        &json!({"profile":PROFILE,"tx":hex::encode(prepared.wire_id),
        "statement":hex::encode(prepared.statement_id),"fee":fee,"status":"applied"}),
    )?;
    Ok(Patch {
        writes: view.writes,
        reads: view.reads,
        scans: view.scans,
        fee,
        receipt,
    })
}

pub fn account_id(spki: &[u8]) -> Result<Hash> {
    let id = ml_dsa_65_key_id_from_spki(spki).map_err(|_| "PQ_KEY")?;
    hash32(&hex::encode(id))
}

#[cfg(test)]
mod tests;
