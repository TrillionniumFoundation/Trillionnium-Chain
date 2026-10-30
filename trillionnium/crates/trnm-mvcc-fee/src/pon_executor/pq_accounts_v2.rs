//! Fresh permissionless-account research profile. Account State, fees and task
//! effects stay inside the original M06 transition and original root owner.
use super::{canonical, field, hash32, require, Config, Hash, Result, State, View};
use serde_json::{json, Value};
use sha2::{Digest, Sha384};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use trnm_crypto_primitives::pq_auth::verify_tpq1;
use trnm_protocol::pon_wire::hash;
use trnm_protocol::pq_frame::{ml_dsa_65_key_id_from_spki, PqFrameExpectation};
use trnm_protocol::pq_native_accounts_v2::{self as wire, ChainContext, UnverifiedEnvelope};

pub mod migration;
pub mod task_migration_v1;
pub mod tasks_v4;
pub mod tasks_v5;
pub use migration::{
    CheckpointMaterial, PrecommittedAccount, TrustedMigrationAnchor, TrustedPqPrecommitments,
};
pub use wire::PROFILE;
pub const MAX_GENESIS_ACCOUNTS: usize = 64;
pub const MAX_GENERATIONS: u64 = 16;
const SELECTOR: &str = "native_pq_accounts_profile";
const AUTH: &str = "pq-auth-v2:";
const KEY: &str = "pq-key-v2:";
const STATUS: &str = "pq-key-status-v2:";

#[derive(Clone, Debug)]
pub struct GenesisAccount {
    pub spki: Vec<u8>,
    pub balance: u64,
}

#[derive(Clone)]
pub(crate) struct Profile {
    wire_profile: wire::AccountProfile,
    context: ChainContext,
    config_digest: Hash,
    anchor: Option<Arc<TrustedMigrationAnchor>>,
}

pub fn enabled(cfg: &Config) -> bool {
    cfg.native_pq_v2.is_some() || cfg.params.get(SELECTOR).is_some()
}
fn config_digest(cfg: &Config) -> Result<Hash> {
    Ok(hash(
        b"native-pq-config-integrity-v2",
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
fn policy(cfg: &Config) -> Result<&Profile> {
    let p = cfg.native_pq_v2.as_deref().ok_or("PQ2_PROFILE_REQUIRED")?;
    require(
        cfg.native_pq.is_none()
            && cfg.params.get("native_pq_profile").is_none()
            && cfg.params[SELECTOR] == p.wire_profile.name()
            && cfg.params["native_pq_v2_anchor"]
                == json!(p.anchor.as_ref().map(|a| hex::encode(a.id)))
            && cfg.network == p.context.network
            && cfg.parameters == p.context.parameters
            && config_digest(cfg)? == p.config_digest,
        "PQ2_CONFIG_CHANGED",
    )?;
    Ok(p)
}
/// Exact configured wire profile; callers never infer it from request bytes.
pub fn account_profile(cfg: &Config) -> Result<wire::AccountProfile> {
    Ok(policy(cfg)?.wire_profile)
}
pub fn quota_v3_enabled(cfg: &Config) -> bool {
    cfg.native_pq_v2
        .as_ref()
        .is_some_and(|p| p.wire_profile == wire::AccountProfile::QuotaV3)
}
fn quota_commands_enabled(cfg: &Config) -> bool {
    quota_v3_enabled(cfg) || tasks_v4_enabled(cfg) || tasks_v5_enabled(cfg)
}
pub fn tasks_v4_enabled(cfg: &Config) -> bool {
    cfg.native_pq_v2
        .as_ref()
        .is_some_and(|p| p.wire_profile == wire::AccountProfile::TasksV4)
}
pub fn tasks_v5_enabled(cfg: &Config) -> bool {
    cfg.native_pq_v2
        .as_ref()
        .is_some_and(|p| p.wire_profile == wire::AccountProfile::TasksV5)
}
pub fn decode_for_config<'a>(raw: &'a [u8], cfg: &Config) -> Result<UnverifiedEnvelope<'a>> {
    UnverifiedEnvelope::decode_for_profile(raw, account_profile(cfg)?).map_err(|_| "PQ2_ENCODING")
}
pub fn context(cfg: &Config) -> Result<ChainContext> {
    let context = policy(cfg)?.context;
    require(context.genesis != [0; 32], "PQ2_GENESIS")?;
    Ok(context)
}
/// Signing input only. Actual prior-key and new-key proofs, current imported
/// lock/nonce/balance, header time and original execution still remain required.
pub fn migration_claim_payload(cfg: &Config, account: Hash) -> Result<Vec<u8>> {
    policy(cfg)?
        .anchor
        .as_ref()
        .ok_or("PQ2_TRUSTED_MIGRATION_REQUIRED")?
        .claim_payload(account)
}

fn auth_key(account: &str) -> String {
    format!("{AUTH}{account}")
}
fn key_key(account: &str, generation: u64) -> String {
    format!("{KEY}{account}:{generation:016x}")
}
fn status_key(account: &str, generation: u64) -> String {
    format!("{STATUS}{account}:{generation:016x}")
}
fn authority(generation: u64, key_id: Hash, retired: bool) -> Value {
    json!({"schema":2,"algorithm":101,"key_id":hex::encode(key_id),"generation":generation,"retired":retired})
}
fn install_key(state: &mut State, account: &str, generation: u64, key_id: Hash, spki: &[u8]) {
    state.insert(auth_key(account), authority(generation, key_id, false));
    state.insert(key_key(account, generation), json!(hex::encode(spki)));
    state.insert(
        status_key(account, generation),
        authority(generation, key_id, false),
    );
}

/// The finite seed list only creates this fresh research genesis. It is not a
/// runtime registry: later positive credits may create any nonzero destination.
pub fn genesis(accounts: &[GenesisAccount], timestamp: u64) -> Result<(Config, State, Hash)> {
    build_genesis(accounts, timestamp, None, wire::AccountProfile::AccountsV2)
}
/// Explicit protected startup constructor for a NEW network, not a wire command
/// or an old-store upgrade. The prior PQ registry/checkpoint trust remains external.
pub fn genesis_with_trusted_migration(
    accounts: &[GenesisAccount],
    timestamp: u64,
    anchor: TrustedMigrationAnchor,
) -> Result<(Config, State, Hash)> {
    build_genesis(
        accounts,
        timestamp,
        Some(Arc::new(anchor)),
        wire::AccountProfile::AccountsV2,
    )
}
/// Fresh valueless successor. Existing NPQ2 contexts/stores never opt in.
pub fn genesis_quota_v3(
    accounts: &[GenesisAccount],
    timestamp: u64,
) -> Result<(Config, State, Hash)> {
    build_genesis(accounts, timestamp, None, wire::AccountProfile::QuotaV3)
}
/// Independently anchored import into the NEW quota network. This preserves
/// the same external source-finality/retirement and prior-PQ trust premises.
pub fn genesis_quota_v3_with_trusted_migration(
    accounts: &[GenesisAccount],
    timestamp: u64,
    anchor: TrustedMigrationAnchor,
) -> Result<(Config, State, Hash)> {
    build_genesis(
        accounts,
        timestamp,
        Some(Arc::new(anchor)),
        wire::AccountProfile::QuotaV3,
    )
}
/// Fresh network only. No legacy task or migration payload opts into NPQ4.
pub fn genesis_tasks_v4(
    accounts: &[GenesisAccount],
    timestamp: u64,
) -> Result<(Config, State, Hash)> {
    build_genesis(accounts, timestamp, None, wire::AccountProfile::TasksV4)
}
/// Fresh network only. No legacy task or migration payload opts into NPQ5.
pub fn genesis_tasks_v5(
    accounts: &[GenesisAccount],
    timestamp: u64,
) -> Result<(Config, State, Hash)> {
    build_genesis(accounts, timestamp, None, wire::AccountProfile::TasksV5)
}

/// The fresh constructors retain their original bytes and domains. Anchored
/// NPQ5 import is selected only by its protected constructor, never a wire bit.
#[derive(Clone, Copy)]
enum GenesisProfile {
    Existing(wire::AccountProfile),
    AnchoredTasksV5,
}

fn build_genesis(
    accounts: &[GenesisAccount],
    timestamp: u64,
    anchor: Option<Arc<TrustedMigrationAnchor>>,
    wire_profile: wire::AccountProfile,
) -> Result<(Config, State, Hash)> {
    build_genesis_profile(
        accounts,
        timestamp,
        anchor,
        GenesisProfile::Existing(wire_profile),
    )
}

fn build_genesis_profile(
    accounts: &[GenesisAccount],
    timestamp: u64,
    anchor: Option<Arc<TrustedMigrationAnchor>>,
    profile: GenesisProfile,
) -> Result<(Config, State, Hash)> {
    let (wire_profile, anchored_tasks) = match profile {
        GenesisProfile::Existing(profile) => (profile, false),
        GenesisProfile::AnchoredTasksV5 => (wire::AccountProfile::TasksV5, true),
    };
    require(
        !anchored_tasks || anchor.is_some(),
        "PQ5_TRUSTED_MIGRATION_REQUIRED",
    )?;
    require(
        accounts.len() <= MAX_GENESIS_ACCOUNTS
            && (!accounts.is_empty() || anchor.is_some())
            && timestamp > 0,
        "PQ2_GENESIS_LIMIT",
    )?;
    let mut sorted = BTreeMap::new();
    let mut issued = 0_u64;
    for account in accounts {
        let id = ml_dsa_65_key_id_from_spki(&account.spki).map_err(|_| "PQ2_KEY")?;
        require(
            id != [0; 32] && sorted.insert(id, account).is_none(),
            "PQ2_DUPLICATE_KEY",
        )?;
        issued = issued.checked_add(account.balance).ok_or("RANGE")?;
    }
    issued = issued
        .checked_add(anchor.as_ref().map_or(0, |a| a.issued))
        .ok_or("RANGE")?;
    require(issued > 0, "PQ2_GENESIS_FUNDS")?;
    let rows: Vec<Value> = sorted.iter().map(|(id, account)|
        json!({"account":hex::encode(id),"spki":hex::encode(&account.spki),"balance":account.balance})).collect();
    let descriptor = canonical(
        &json!({"profile":if anchored_tasks { task_migration_v1::PROFILE } else { wire_profile.name() },"timestamp":timestamp,"accounts":rows,
        "max_generations":MAX_GENERATIONS,"transaction_bytes":wire::MAX_BYTES,
        "transaction_total":wire::MAX_TRANSACTION_BYTES,"transaction_count":wire::MAX_TRANSACTIONS,
        "packet_bytes":1048576,"production_activation":false,"migration_anchor":anchor.as_ref().map(|a| hex::encode(a.id))}),
    )?;
    let mut cfg =
        Config::installed_with_profiles("legacy-first-two-v3", crate::continuity_v1::PROFILE)?;
    let old_network = cfg.network;
    let old_parameters = cfg.parameters;
    cfg.params[SELECTOR] = json!(wire_profile.name());
    if wire_profile == wire::AccountProfile::TasksV4 {
        cfg.params["native_pq_task_contract"] = json!({"profile":tasks_v4::PROFILE,"slots":32,
            "witness_chunks":4,"chunk_raw_bytes":2000,"local_revocation_capacity":1024,
            "commands":[18,20,21],"renewal_supported":false,"migration_supported":false});
    }
    if wire_profile == wire::AccountProfile::TasksV5 {
        require(
            anchored_tasks || anchor.is_none(),
            "PQ5_TASK_MIGRATION_UNSUPPORTED",
        )?;
        cfg.params["native_pq_task_contract"] = json!({"profile":tasks_v5::PROFILE,"slots":32,
            "witness_chunks":5,"chunk_raw_bytes":2000,"local_revocation_capacity":1024,
            "commands":[18,19,20,21,22],"renewal_supported":true,"migration_supported":anchored_tasks,
            "pending_status":"awaiting-source","local_revocation_scope":"stable-lineage-v5"});
    }
    if anchored_tasks {
        cfg.params["native_pq_task_migration_profile"] = json!(task_migration_v1::PROFILE);
    }
    cfg.params["genesis_timestamp"] = json!(timestamp);
    cfg.params["native_pq_v2_anchor"] = json!(anchor.as_ref().map(|a| hex::encode(a.id)));
    cfg.params["native_pq_v2_descriptor"] = json!(hex::encode(hash(
        if anchored_tasks {
            b"native-pq-task-migration-descriptor-v1"
        } else {
            match wire_profile {
                wire::AccountProfile::AccountsV2 => b"native-pq-genesis-descriptor-v2",
                wire::AccountProfile::QuotaV3 => b"native-pq-quota-descriptor-v3",
                wire::AccountProfile::TasksV4 => b"native-pq-task-descriptor-v4",
                wire::AccountProfile::TasksV5 => b"native-pq-task-descriptor-v5",
            }
        },
        &[&descriptor]
    )));
    cfg.params["native_pq_v2_base_fees"] = json!({"128":200,"129":400,"130":400});
    cfg.network = hash(
        if anchored_tasks {
            b"native-pq-task-migration-network-v1"
        } else {
            match wire_profile {
                wire::AccountProfile::AccountsV2 => b"native-pq-network-v2",
                wire::AccountProfile::QuotaV3 => b"native-pq-quota-network-v3",
                wire::AccountProfile::TasksV4 => b"native-pq-task-network-v4",
                wire::AccountProfile::TasksV5 => b"native-pq-task-network-v5",
            }
        },
        &[&old_network, &descriptor],
    );
    cfg.parameters = hash(
        if anchored_tasks {
            b"native-pq-task-migration-parameters-v1"
        } else {
            match wire_profile {
                wire::AccountProfile::AccountsV2 => b"native-pq-parameters-v2",
                wire::AccountProfile::QuotaV3 => b"native-pq-quota-parameters-v3",
                wire::AccountProfile::TasksV4 => b"native-pq-task-parameters-v4",
                wire::AccountProfile::TasksV5 => b"native-pq-task-parameters-v5",
            }
        },
        &[
            &old_parameters,
            &cfg.network,
            &canonical(&cfg.params)?,
            &descriptor,
        ],
    );
    cfg.native_pq_v2 = Some(Arc::new(Profile {
        wire_profile,
        context: ChainContext {
            network: cfg.network,
            parameters: cfg.parameters,
            genesis: [0; 32],
        },
        config_digest: config_digest(&cfg)?,
        anchor: anchor.clone(),
    }));
    let mut state = State::from([
        ("meta:issued".into(), json!(issued)),
        ("model:current".into(), json!(hex::encode([0; 32]))),
    ]);
    state.extend(crate::continuity_v1::bootstrap_state(&cfg)?);
    if wire_profile == wire::AccountProfile::TasksV4 {
        state.insert(tasks_v4::GENERATION_KEY.into(), json!(0));
    }
    if wire_profile == wire::AccountProfile::TasksV5 {
        state.insert(tasks_v5::GENERATION_KEY.into(), json!(0));
    }
    for (id, account) in sorted {
        let name = hex::encode(id);
        state.insert(
            format!("account:{name}"),
            json!({"balance":account.balance,"nonce":0}),
        );
        install_key(&mut state, &name, 1, id, &account.spki);
    }
    if let Some(anchor) = &anchor {
        anchor.import_into(&mut state)?;
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
    Arc::get_mut(cfg.native_pq_v2.as_mut().ok_or("PQ2_PROFILE_REQUIRED")?)
        .ok_or("PQ2_CONFIG_SHARED")?
        .context
        .genesis = genesis;
    Ok((cfg, state, genesis))
}

fn decode_spki(value: &Value) -> Result<(Vec<u8>, Hash)> {
    let raw = value.as_str().ok_or("PQ2_KEY_STATE")?;
    require(
        raw.len() == 3948
            && raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "PQ2_KEY_STATE",
    )?;
    let spki = hex::decode(raw).map_err(|_| "PQ2_KEY_STATE")?;
    let id = ml_dsa_65_key_id_from_spki(&spki).map_err(|_| "PQ2_KEY_STATE")?;
    require(
        id != [0; 32] && canonical(value)?.len() == 3950,
        "PQ2_KEY_STATE",
    )?;
    Ok((spki, id))
}

/// Complete State grammar, including pending accounts and all retained key
/// generations. No unbound key/auth leaf may acquire meaning through a root.
pub fn validate_state(state: &State, cfg: &Config) -> Result<()> {
    if !enabled(cfg) {
        return Ok(());
    }
    let profile = policy(cfg)?;
    require(state.len() <= 65_536, "LIMIT")?;
    let mut expected = BTreeSet::new();
    if let Some(anchor) = &profile.anchor {
        for (key, value) in anchor.immutable_rows() {
            require(state.get(&key) == Some(&value), "PQ2_ANCHOR_STATE")?;
            expected.insert(key);
        }
        for name in anchor.accounts.keys() {
            require(
                state.contains_key(&format!("account:{name}"))
                    && state.contains_key(&format!("{}{name}", migration::ORIGIN)),
                "PQ2_IMPORT_COVERAGE",
            )?;
        }
    }
    for (name, account) in state
        .iter()
        .filter_map(|(k, v)| k.strip_prefix("account:").map(|a| (a, v)))
    {
        let id = hash32(name)?;
        require(id != [0; 32], "PQ2_ACCOUNT_STATE")?;
        let object = account.as_object().ok_or("PQ2_ACCOUNT_STATE")?;
        require(
            object.len() == 2
                && object.get("balance").is_some_and(Value::is_u64)
                && object.get("nonce").is_some_and(Value::is_u64),
            "PQ2_ACCOUNT_STATE",
        )?;
        let imported = profile.anchor.as_ref().and_then(|a| a.accounts.get(name));
        if let Some(imported) = imported {
            let anchor = profile
                .anchor
                .as_ref()
                .ok_or("PQ2_TRUSTED_MIGRATION_REQUIRED")?;
            let key = format!("{}{name}", migration::ORIGIN);
            let value = state.get(&key).ok_or("PQ2_IMPORT_COVERAGE")?;
            let claimed = value
                .get("claimed")
                .and_then(Value::as_bool)
                .ok_or("PQ2_IMPORT_STATE")?;
            require(value == &anchor.origin(name, claimed)?, "PQ2_IMPORT_STATE")?;
            expected.insert(key);
            if !claimed {
                require(
                    state.get(&auth_key(name)).is_none()
                        && field(account, "nonce")? == imported.original_nonce
                        && field(account, "balance")? >= imported.original_balance,
                    "PQ2_IMPORT_LOCKED",
                )?;
                continue;
            }
            require(
                state.contains_key(&auth_key(name)),
                "PQ2_IMPORT_CLAIM_AUTHORITY",
            )?;
            // CLAIM atomically installs authority and consumes the next source
            // nonce. Retained authority cannot coexist with a pre-CLAIM nonce.
            require(
                field(account, "nonce")? > imported.original_nonce,
                "PQ2_IMPORT_CLAIM_NONCE",
            )?;
        }
        let Some(auth) = state.get(&auth_key(name)) else {
            require(
                field(account, "nonce")? == 0 && field(account, "balance")? > 0,
                "PQ2_PENDING_NONCE",
            )?;
            continue;
        };
        let generation = field(auth, "generation")?;
        require(
            (1..=MAX_GENERATIONS).contains(&generation),
            "PQ2_GENERATION",
        )?;
        // Each retained rotation consumed one nonce. Imported generation one
        // additionally consumed the CLAIM nonce above the source checkpoint.
        let minimum_nonce = match imported {
            Some(imported) => imported
                .original_nonce
                .checked_add(generation)
                .ok_or("PQ2_AUTHORITY_NONCE")?,
            None => generation - 1,
        };
        require(
            field(account, "nonce")? >= minimum_nonce,
            "PQ2_AUTHORITY_NONCE",
        )?;
        expected.insert(auth_key(name));
        let mut used = BTreeSet::new();
        for current in 1..=generation {
            let key_name = key_key(name, current);
            let status_name = status_key(name, current);
            let (_, key_id) = decode_spki(state.get(&key_name).ok_or("PQ2_KEY_STATE")?)?;
            require(
                used.insert(key_id) && (current != 1 || key_id == id || imported.is_some()),
                "PQ2_KEY_HISTORY",
            )?;
            require(
                state.get(&status_name) == Some(&authority(current, key_id, current < generation)),
                "PQ2_KEY_STATUS",
            )?;
            if current == generation {
                require(auth == &authority(current, key_id, false), "PQ2_AUTH_STATE")?;
            }
            expected.insert(key_name);
            expected.insert(status_name);
        }
    }
    require(
        state
            .keys()
            .filter(|k| k.starts_with("pq-"))
            .all(|key| expected.contains(key)),
        "PQ2_ORPHAN_AUTHORITY",
    )?;
    if tasks_v4_enabled(cfg) {
        tasks_v4::validate_state(state, cfg)?;
    }
    if tasks_v5_enabled(cfg) {
        tasks_v5::validate_state(state, cfg)?;
    }
    Ok(())
}

struct ResolvedAuthority {
    generation: u64,
    key_id: Hash,
    spki: Vec<u8>,
    digest: [u8; 48],
}
fn authorize(view: &mut View<'_>, account: Hash) -> Result<ResolvedAuthority> {
    let name = hex::encode(account);
    require(
        view.get(&format!("account:{name}")).is_some(),
        "PQ2_ACCOUNT_REQUIRED",
    )?;
    let auth = view.get(&auth_key(&name)).ok_or("PQ2_AUTHORITY_REQUIRED")?;
    let generation = field(&auth, "generation")?;
    require(
        (1..=MAX_GENERATIONS).contains(&generation),
        "PQ2_GENERATION",
    )?;
    let (spki, key_id) = decode_spki(
        &view
            .get(&key_key(&name, generation))
            .ok_or("PQ2_KEY_STATE")?,
    )?;
    require(
        auth == authority(generation, key_id, false)
            && view.get(&status_key(&name, generation))
                == Some(authority(generation, key_id, false)),
        "PQ2_AUTHORITY",
    )?;
    let mut hash = Sha384::new();
    hash.update(b"TRNM/PoN/NativePQAuthorityRecord/v2\0");
    hash.update(account);
    hash.update(canonical(&auth)?);
    Ok(ResolvedAuthority {
        generation,
        key_id,
        spki,
        digest: hash.finalize().into(),
    })
}
pub fn authority_digest(state: &State, account: Hash, cfg: &Config) -> Result<[u8; 48]> {
    validate_state(state, cfg)?;
    Ok(authorize(&mut View::new(state, None), account)?.digest)
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
    require(timestamp.is_some() && miner != [0; 32], "PQ2_BLOCK_CONTEXT")?;
    require(
        transactions.len() <= wire::MAX_TRANSACTIONS,
        "PQ2_TRANSACTION_LIMIT",
    )?;
    let mut total = 0_usize;
    let mut accounts = BTreeMap::<Hash, (usize, bool)>::new();
    let mut task_demands = BTreeSet::new();
    for raw in transactions {
        let tx = decode_for_config(raw, cfg)?;
        total = total
            .checked_add(raw.len())
            .ok_or("PQ2_TRANSACTION_LIMIT")?;
        require(
            total <= wire::MAX_TRANSACTION_BYTES,
            "PQ2_TRANSACTION_LIMIT",
        )?;
        let mut referenced = BTreeSet::from([tx.common.account]);
        if tx.kind == 11 && quota_commands_enabled(cfg) {
            referenced.insert(quota_consumer(&mut View::new(parent, None), tx.payload)?);
        }
        if tasks_v4_enabled(cfg) && matches!(tx.kind, 18 | 20 | 21) {
            let (demand, requester, source) =
                tasks_v4::command_owners(&mut View::new(parent, None), &tx, cfg)?;
            require(task_demands.insert(demand), "PQ4_TASK_BLOCK_MUTEX")?;
            referenced.extend([requester, source]);
        }
        if tasks_v5_enabled(cfg) && matches!(tx.kind, 18..=22) {
            let (demand, requester, source) =
                tasks_v5::command_owners(&mut View::new(parent, None), &tx, cfg)?;
            require(task_demands.insert(demand), "PQ5_TASK_BLOCK_MUTEX")?;
            referenced.extend([requester, source]);
        }
        for account in referenced {
            let entry = accounts.entry(account).or_default();
            entry.0 += 1;
            entry.1 |= account == tx.common.account && wire::changes_authority(tx.kind);
            require(entry.0 == 1 || !entry.1, "PQ2_AUTHORITY_BLOCK_MUTEX")?;
        }
    }
    validate_state(parent, cfg)
}

/// Private fields retain actual signature/key binding. They grant no fee,
/// account nonce, current State permission, block or final-use authority.
pub struct PreparedCommand {
    raw: Vec<u8>,
    common: wire::Common,
    kind: u8,
    payload: Vec<u8>,
    keys: Vec<Vec<u8>>,
    wire_id: Hash,
    statement_id: [u8; 48],
    admitted_at: u64,
}
impl PreparedCommand {
    pub fn sender(&self) -> Hash {
        self.common.account
    }
    pub fn nonce(&self) -> u64 {
        self.common.nonce
    }
    pub fn expires_at(&self) -> u64 {
        self.common.expires_at
    }
    pub fn max_fee(&self) -> u64 {
        self.common.max_fee
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
    pub(super) fn signature_count(&self) -> usize {
        self.keys.len()
    }
}

fn quota_consumer(view: &mut View<'_>, payload: &[u8]) -> Result<Hash> {
    let quota: Hash = payload
        .get(..32)
        .ok_or("PQ3_QUOTA_ENCODING")?
        .try_into()
        .map_err(|_| "PQ3_QUOTA_ENCODING")?;
    let (_, row) = view.object("quota:", quota)?;
    hash32(super::text(&row, "consumer")?)
}

fn resolve(
    view: &mut View<'_>,
    tx: &UnverifiedEnvelope<'_>,
    index: usize,
    cfg: &Config,
) -> Result<Vec<u8>> {
    let witness = &tx.witnesses()[index];
    match witness.role {
        1 | 3 => {
            let current = authorize(view, tx.common.account)?;
            require(
                current.generation == tx.common.generation
                    && current.generation == witness.generation
                    && current.key_id == witness.key_id,
                "PQ2_STALE_AUTHORITY",
            )?;
            Ok(current.spki)
        }
        2 if tx.kind == 21 && tasks_v4_enabled(cfg) => {
            let (_, _, source) = tasks_v4::command_owners(view, tx, cfg)?;
            let current = authorize(view, source)?;
            require(
                current.generation == witness.generation && current.key_id == witness.key_id,
                "PQ4_STALE_SOURCE_AUTHORITY",
            )?;
            Ok(current.spki)
        }
        2 if matches!(tx.kind, 21 | 22) && tasks_v5_enabled(cfg) => {
            let (_, _, source) = tasks_v5::command_owners(view, tx, cfg)?;
            let current = authorize(view, source)?;
            require(
                current.generation == witness.generation && current.key_id == witness.key_id,
                "PQ5_STALE_SOURCE_AUTHORITY",
            )?;
            Ok(current.spki)
        }
        2 if tx.kind == 11 && quota_commands_enabled(cfg) => {
            let consumer = quota_consumer(view, tx.payload)?;
            let current = authorize(view, consumer)?;
            require(
                current.generation == witness.generation && current.key_id == witness.key_id,
                "PQ3_STALE_CONSUMER_AUTHORITY",
            )?;
            Ok(current.spki)
        }
        2 => {
            let name = hex::encode(tx.common.account);
            let account = view
                .get(&format!("account:{name}"))
                .ok_or("PQ2_ACCOUNT_REQUIRED")?;
            require(
                view.get(&auth_key(&name)).is_none()
                    && view.get(&format!("{}{name}", migration::ORIGIN)).is_none()
                    && field(&account, "nonce")? == 0
                    && witness.key_id == tx.common.account,
                "PQ2_PENDING_REQUIRED",
            )?;
            Ok(witness.spki.ok_or("PQ2_KEY")?.to_vec())
        }
        4 | 6 => Ok(witness.spki.ok_or("PQ2_KEY")?.to_vec()),
        5 => migration::resolve_claim(view, tx, cfg),
        _ => Err("PQ2_ROLE"),
    }
}
pub fn prepare_signature(
    parent: &State,
    raw: &[u8],
    timestamp: u64,
    cfg: &Config,
) -> Result<PreparedCommand> {
    let context = context(cfg)?;
    let tx = decode_for_config(raw, cfg)?;
    require(tx.common.context == context, "PQ2_CONTEXT")?;
    require(tx.common.max_fee <= cfg.limit("max_fee_limit")?, "FEE")?;
    let mut view = View::new(parent, None);
    if tasks_v4_enabled(cfg) && matches!(tx.kind, 18 | 20 | 21) {
        tasks_v4::command_owners(&mut view, &tx, cfg)?;
    }
    if tasks_v5_enabled(cfg) && matches!(tx.kind, 18..=22) {
        tasks_v5::command_owners(&mut view, &tx, cfg)?;
    }
    let mut keys = Vec::with_capacity(tx.witnesses().len());
    for (index, witness) in tx.witnesses().iter().enumerate() {
        let spki = resolve(&mut view, &tx, index, cfg)?;
        verify_tpq1(
            witness.frame,
            &PqFrameExpectation {
                purpose: witness.role,
                network: context.network,
                owner_context: wire::owner_context_for_profile(
                    account_profile(cfg)?,
                    &tx.common,
                    tx.kind,
                    witness.role,
                )
                .map_err(|_| "PQ2_CONTEXT")?,
                signer_key_id: witness.key_id,
                owner_generation: witness.generation,
                operation_sequence: tx.common.nonce,
                expires_at: tx.common.expires_at,
                now: timestamp,
                payload: tx.core(),
            },
            &spki,
        )
        .map_err(|_| "PQ2_SIGNATURE")?;
        keys.push(spki);
    }
    Ok(PreparedCommand {
        raw: raw.to_vec(),
        common: tx.common,
        kind: tx.kind,
        payload: tx.payload.to_vec(),
        keys,
        wire_id: tx.wire_id(),
        statement_id: tx.statement_id(),
        admitted_at: timestamp,
    })
}
pub fn validate_current_authority(parent: &State, raw: &[u8], cfg: &Config) -> Result<()> {
    context(cfg)?;
    validate_state(parent, cfg)?;
    let tx = decode_for_config(raw, cfg)?;
    require(tx.common.context == context(cfg)?, "PQ2_CONTEXT")?;
    let mut view = View::new(parent, None);
    if tasks_v4_enabled(cfg) && matches!(tx.kind, 18 | 20 | 21) {
        tasks_v4::command_owners(&mut view, &tx, cfg)?;
    }
    if tasks_v5_enabled(cfg) && matches!(tx.kind, 18..=22) {
        tasks_v5::command_owners(&mut view, &tx, cfg)?;
    }
    for index in 0..tx.witnesses().len() {
        resolve(&mut view, &tx, index, cfg)?;
    }
    Ok(())
}

pub(super) fn apply(
    base: &State,
    prepared: &PreparedCommand,
    height: u64,
    cfg: &Config,
    access: Option<&super::AccountPointAccess<'_>>,
) -> Result<super::Patch> {
    require(
        prepared.common.context == context(cfg)?,
        "PQ2_PREPARED_CONTEXT",
    )?;
    let tx = decode_for_config(&prepared.raw, cfg)?;
    let mut view = View::new(base, access);
    if tasks_v4_enabled(cfg) && matches!(tx.kind, 18 | 20 | 21) {
        tasks_v4::command_owners(&mut view, &tx, cfg)?;
    }
    if tasks_v5_enabled(cfg) && matches!(tx.kind, 18..=22) {
        tasks_v5::command_owners(&mut view, &tx, cfg)?;
    }
    for (index, key) in prepared.keys.iter().enumerate() {
        require(
            resolve(&mut view, &tx, index, cfg)? == *key,
            "PQ2_PREPARED_KEY_CHANGED",
        )?;
    }
    let sender = hex::encode(prepared.common.account);
    let fee = if prepared.kind < wire::REGISTER {
        super::debit_authorized_fee(
            &mut view,
            &sender,
            prepared.kind,
            prepared.common.nonce,
            prepared.common.max_fee,
            prepared.raw.len(),
            cfg,
        )?
    } else {
        let account = view.account(&sender)?;
        require(
            field(&account, "nonce")?.checked_add(1) == Some(prepared.common.nonce),
            "NONCE",
        )?;
        let rate = field(
            &cfg.params["native_pq_v2_base_fees"],
            &prepared.kind.to_string(),
        )?;
        let fee = rate
            .checked_add(
                (prepared.raw.len() as u64)
                    .checked_mul(cfg.limit("byte_fee_units")?)
                    .ok_or("RANGE")?,
            )
            .ok_or("RANGE")?;
        require(prepared.common.max_fee >= fee, "FEE")?;
        view.debit(&sender, fee)?;
        fee
    };
    match prepared.kind {
        1 => {
            let recipient = hex::encode(&prepared.payload[..32]);
            let amount = u64::from_le_bytes(
                prepared.payload[32..40]
                    .try_into()
                    .map_err(|_| "PQ2_ENCODING")?,
            );
            if amount > 0 {
                super::transfer_balances(&mut view, &sender, &recipient, amount)?;
            }
        }
        2..=5 => super::apply_task_command(
            &mut view,
            prepared.common.account,
            prepared.common.nonce,
            prepared.kind,
            &prepared.payload,
            height,
            cfg,
        )?,
        10 if quota_commands_enabled(cfg) => super::reserve_quota(
            &mut view,
            prepared.common.account,
            prepared.common.nonce,
            &prepared.payload,
            height,
            cfg,
        )?,
        11 if quota_commands_enabled(cfg) => {
            let quota: Hash = prepared.payload[..32]
                .try_into()
                .map_err(|_| "PQ3_QUOTA_ENCODING")?;
            let units = u64::from_le_bytes(
                prepared.payload[32..40]
                    .try_into()
                    .map_err(|_| "PQ3_QUOTA_ENCODING")?,
            );
            let result: Hash = prepared.payload[40..72]
                .try_into()
                .map_err(|_| "PQ3_QUOTA_ENCODING")?;
            // Both actual current-State ML-DSA witnesses were verified in prepare,
            // and are resolved again above. This common owner has no fake Ed envelope.
            let (key, row) =
                super::quota_use_context(&mut view, &sender, quota, units, result, height)?;
            super::settle_verified_quota(&mut view, &sender, key, row, units, fee, cfg)?;
        }
        18 | 20 | 21 if tasks_v4_enabled(cfg) => tasks_v4::apply(&mut view, prepared, height, cfg)?,
        18..=22 if tasks_v5_enabled(cfg) => tasks_v5::apply(&mut view, prepared, height, cfg)?,
        wire::REGISTER => {
            let mut writes = State::new();
            install_key(
                &mut writes,
                &sender,
                1,
                prepared.common.account,
                &prepared.keys[0],
            );
            for (key, value) in writes {
                require(view.get(&key).is_none(), "PQ2_DUPLICATE_KEY")?;
                view.put(key, value);
            }
        }
        wire::ROTATE => {
            let current = authorize(&mut view, prepared.common.account)?;
            let next = current.generation.checked_add(1).ok_or("PQ2_GENERATION")?;
            require(
                next <= MAX_GENERATIONS && prepared.payload[8..] == current.digest,
                "PQ2_ROTATION_BINDING",
            )?;
            let new_key = ml_dsa_65_key_id_from_spki(&prepared.keys[1]).map_err(|_| "PQ2_KEY")?;
            for generation in 1..=current.generation {
                let (_, old_key) = decode_spki(
                    &view
                        .get(&key_key(&sender, generation))
                        .ok_or("PQ2_KEY_STATE")?,
                )?;
                require(new_key != old_key, "PQ2_REUSED_KEY")?;
            }
            require(
                view.get(&key_key(&sender, next)).is_none()
                    && view.get(&status_key(&sender, next)).is_none(),
                "PQ2_DUPLICATE_KEY",
            )?;
            view.put(
                status_key(&sender, current.generation),
                authority(current.generation, current.key_id, true),
            );
            let mut writes = State::new();
            install_key(&mut writes, &sender, next, new_key, &prepared.keys[1]);
            for (key, value) in writes {
                view.put(key, value);
            }
        }
        wire::CLAIM => migration::apply_claim(&mut view, prepared, cfg)?,
        _ => return Err("PQ2_COMMAND"),
    }
    let mut account = view.account(&sender)?;
    account["nonce"] = json!(prepared.common.nonce);
    view.put(format!("account:{sender}"), account);
    let receipt = canonical(
        &json!({"profile":account_profile(cfg)?.name(),"kind":prepared.kind,
        "tx":hex::encode(prepared.wire_id),"statement":hex::encode(prepared.statement_id),
        "fee":fee,"status":"applied"}),
    )?;
    Ok(super::Patch {
        writes: view.writes,
        reads: view.reads,
        scans: view.scans,
        fee,
        receipt,
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tasks_v4_tests;

#[cfg(test)]
mod tasks_v5_tests;
