//! Explicit operator-selected checkpoint trust for a NEW research network.
//! No wire decoder, authenticated Boolean, source-chain retirement proof or
//! retroactive recovery of Shor-compromised Ed ownership exists in this module.
use super::*;
use trnm_protocol::pon_wire::Header;

pub const MAX_IMPORT_ACCOUNTS: usize = 64;
pub(super) const ORIGIN: &str = "pq-import-v2:";
pub(super) const ANCHOR_KEY: &str = "pq-import-key-v2:";
pub(super) const ANCHOR_META: &str = "pq-import-anchor-v2";

#[derive(Clone, Debug)]
pub struct PrecommittedAccount {
    pub source_account: Hash,
    pub spki: Vec<u8>,
    pub generation: u64,
}

/// A protected configuration choice, never deserialized from a transaction.
/// The caller must independently trust that this exact registry predated the
/// selected source checkpoint. The type does not prove that historical fact.
#[derive(Clone)]
pub struct TrustedPqPrecommitments {
    network: Hash,
    genesis: Hash,
    entries: BTreeMap<Hash, PrecommittedAccount>,
    digest: [u8; 48],
}

/// Untrusted checkpoint preimage. A claimed trace alone is NOT verified W1.
/// Pinning checks its header ID against the independently selected checkpoint;
/// the actual Node exporter supplies its already admitted header and State.
#[derive(Clone)]
pub struct CheckpointMaterial {
    pub genesis: Hash,
    pub header: Header,
    pub trace: Hash,
    pub state: State,
}

#[derive(Clone)]
pub(super) struct ImportAccount {
    pub(super) spki: Vec<u8>,
    pub(super) key_id: Hash,
    pub(super) generation: u64,
    pub(super) original_balance: u64,
    pub(super) original_nonce: u64,
    permission_digest: [u8; 48],
    account_present: bool,
}

/// Opaque startup configuration for a distinct genesis. No existing Node wire
/// operation can install this value or replace an existing network's anchor.
#[derive(Clone)]
pub struct TrustedMigrationAnchor {
    pub(super) id: [u8; 48],
    checkpoint: Hash,
    source_root: Hash,
    source_height: u64,
    source_timestamp: u64,
    source_network: Hash,
    source_parameters: Hash,
    source_genesis: Hash,
    registry_digest: [u8; 48],
    projection_root: Hash,
    pub(super) issued: u64,
    pub(super) accounts: BTreeMap<String, ImportAccount>,
    projection: State,
}

fn digest(domain: &[u8], value: &Value) -> Result<[u8; 48]> {
    let mut hash = Sha384::new();
    hash.update(domain);
    hash.update(canonical(value)?);
    Ok(hash.finalize().into())
}
fn source_id(value: &Value, field_name: &str) -> Result<Hash> {
    let id = hash32(super::super::text(value, field_name)?)?;
    require(id != [0; 32], "PQ2_SOURCE_ID")?;
    Ok(id)
}

impl TrustedPqPrecommitments {
    /// Explicit independent trust selection. Call before obtaining the source
    /// checkpoint in the research experiment. There is no network/RPC wrapper.
    pub fn pin(network: Hash, genesis: Hash, entries: &[PrecommittedAccount]) -> Result<Self> {
        require(
            network != [0; 32]
                && genesis != [0; 32]
                && (1..=MAX_IMPORT_ACCOUNTS).contains(&entries.len()),
            "PQ2_PRECOMMIT_LIMIT",
        )?;
        let mut selected = BTreeMap::new();
        let mut rows = Vec::new();
        for entry in entries {
            let key = ml_dsa_65_key_id_from_spki(&entry.spki).map_err(|_| "PQ2_KEY")?;
            require(
                entry.source_account != [0; 32]
                    && key != [0; 32]
                    && entry.generation > 0
                    && selected
                        .insert(entry.source_account, entry.clone())
                        .is_none(),
                "PQ2_PRECOMMIT_ENTRY",
            )?;
        }
        for (account, entry) in &selected {
            rows.push(json!({"account":hex::encode(account),"generation":entry.generation,"spki":hex::encode(&entry.spki)}));
        }
        let digest = digest(
            b"TRNM/PoN/PQPrecommitments/v2\0",
            &json!({"network":hex::encode(network),"genesis":hex::encode(genesis),"entries":rows}),
        )?;
        Ok(Self {
            network,
            genesis,
            entries: selected,
            digest,
        })
    }
    pub fn commitment(&self) -> [u8; 48] {
        self.digest
    }

    /// Pin a separately trusted exact source checkpoint for a new genesis.
    /// Header ID binds header root/time/height/network/parameters plus trace;
    /// State is completely rehashed and monetary obligations are all enumerated.
    /// This does not independently prove work validity, source finality, prior
    /// registry timing, or enforce a lock/retirement of the source network.
    pub fn pin_checkpoint(
        self,
        pinned_checkpoint: Hash,
        material: CheckpointMaterial,
        source_cfg: &Config,
    ) -> Result<TrustedMigrationAnchor> {
        require(!source_cfg.is_pq_account_profile(), "PQ2_SOURCE_PROFILE")?;
        require(
            material.state.len() <= 65_536
                && material.genesis == self.genesis
                && source_cfg.network == self.network
                && material.header.network == self.network
                && material.header.parameters == source_cfg.parameters
                && material.header.height > 0
                && material.header.height < u64::MAX
                && material.header.timestamp > 0
                && pinned_checkpoint != [0; 32]
                && material.header.block_id(material.trace) == pinned_checkpoint,
            "PQ2_SOURCE_CHECKPOINT",
        )?;
        require(
            super::super::root_for_config(&material.state, source_cfg)? == material.header.state,
            "PQ2_SOURCE_ROOT",
        )?;
        super::super::check_completed_block_state(
            &material.state,
            material.header.height,
            source_cfg,
        )?;
        let issued = super::super::num(material.state.get("meta:issued").ok_or("STATE")?)?;
        let mut projection = State::new();
        let mut needed = BTreeSet::new();
        let mut permissions = BTreeMap::<Hash, Vec<Value>>::new();
        let mut balances = BTreeMap::new();
        let mut imported_reward_heights = BTreeSet::new();
        for (name, value) in &material.state {
            if let Some(account) = name.strip_prefix("account:") {
                let id = hash32(account)?;
                let object = value.as_object().ok_or("PQ2_SOURCE_ACCOUNT")?;
                require(
                    id != [0; 32]
                        && object.len() == 2
                        && object.get("balance").is_some_and(Value::is_u64)
                        && object.get("nonce").is_some_and(Value::is_u64)
                        && field(value, "nonce")? < u64::MAX,
                    "PQ2_SOURCE_ACCOUNT",
                )?;
                needed.insert(id);
                balances.insert(id, (field(value, "balance")?, field(value, "nonce")?));
                projection.insert(name.clone(), value.clone());
            } else if name.starts_with("task:") {
                hash32(name.strip_prefix("task:").ok_or("STATE")?)?;
                let object = value.as_object().ok_or("PQ2_SOURCE_TASK")?;
                require(
                    object.len() == 6
                        && [
                            "owner",
                            "provider",
                            "remaining",
                            "deadline",
                            "status",
                            "output",
                        ]
                        .iter()
                        .all(|k| object.contains_key(*k)),
                    "PQ2_SOURCE_TASK",
                )?;
                let owner = source_id(value, "owner")?;
                let provider = source_id(value, "provider")?;
                let remaining = field(value, "remaining")?;
                let deadline = field(value, "deadline")?;
                let status = super::super::text(value, "status")?;
                require(
                    matches!(
                        status,
                        "reserved" | "receipt" | "cancelled" | "settled" | "expired"
                    ),
                    "PQ2_SOURCE_TASK",
                )?;
                require(
                    remaining == 0
                        || (matches!(status, "reserved" | "receipt")
                            && deadline > material.header.height),
                    "PQ2_SOURCE_DUE_ESCROW_UNSUPPORTED",
                )?;
                if matches!(status, "receipt" | "settled") {
                    require(source_id(value, "output")? != [0; 32], "PQ2_SOURCE_TASK")?;
                } else if matches!(status, "reserved" | "cancelled") {
                    require(value["output"].is_null(), "PQ2_SOURCE_TASK")?;
                } else {
                    require(
                        value["output"].is_null()
                            || value["output"].as_str().is_some_and(|s| hash32(s).is_ok()),
                        "PQ2_SOURCE_TASK",
                    )?;
                }
                let mut translated = value.clone();
                translated["deadline"] = json!(deadline.saturating_sub(material.header.height));
                projection.insert(name.clone(), translated.clone());
                for id in BTreeSet::from([owner, provider]) {
                    needed.insert(id);
                    permissions
                        .entry(id)
                        .or_default()
                        .push(json!({"key":name,"source":value,"translated":translated}));
                }
            } else if name.starts_with("reward:") {
                hash32(name.strip_prefix("reward:").ok_or("STATE")?)?;
                let object = value.as_object().ok_or("PQ2_SOURCE_REWARD")?;
                require(
                    object.len() == 3
                        && ["owner", "amount", "maturity"]
                            .iter()
                            .all(|k| object.contains_key(*k)),
                    "PQ2_SOURCE_REWARD",
                )?;
                let owner = hash32(super::super::text(value, "owner")?)?;
                let amount = field(value, "amount")?;
                let maturity = field(value, "maturity")?;
                require(maturity > material.header.height, "PQ2_SOURCE_MATURITY")?;
                // The destination retains the original fixed 20-block reward
                // owner. Each imported obligation must fit that exact window;
                // no merging, early payout, extra maturity slot or new grace.
                let translated_height = maturity - material.header.height;
                require(
                    translated_height <= 20 && imported_reward_heights.insert(translated_height),
                    "PQ2_SOURCE_REWARD_WINDOW",
                )?;
                let mut translated = value.clone();
                translated["maturity"] = json!(translated_height);
                projection.insert(name.clone(), translated.clone());
                if amount > 0 {
                    require(owner != [0; 32], "PQ2_SOURCE_ID")?;
                    needed.insert(owner);
                }
                permissions
                    .entry(owner)
                    .or_default()
                    .push(json!({"key":name,"source":value,"translated":translated}));
            } else if name.starts_with("quota:") || name.starts_with("release:") {
                require(
                    field(value, "remaining")? == 0,
                    "PQ2_UNSUPPORTED_SOURCE_LIABILITY",
                )?;
            } else if name.starts_with("pq-") {
                return Err("PQ2_SOURCE_PROFILE");
            }
        }
        require(
            needed == self.entries.keys().copied().collect(),
            "PQ2_PRECOMMIT_COVERAGE",
        )?;
        let mut accounts = BTreeMap::new();
        for id in &needed {
            let precommit = &self.entries[id];
            let (balance, nonce) = balances.get(id).copied().unwrap_or((0, 0));
            let name = hex::encode(id);
            projection
                .entry(format!("account:{name}"))
                .or_insert_with(|| json!({"balance":0,"nonce":0}));
            let permission_digest = digest(
                b"TRNM/PoN/PQSourceAccountPermissions/v2\0",
                &json!({
                    "account":name,"account_present":balances.contains_key(id),"balance":balance,"nonce":nonce,
                    "objects":permissions.get(id).cloned().unwrap_or_default(),
                }),
            )?;
            accounts.insert(
                name,
                ImportAccount {
                    spki: precommit.spki.clone(),
                    key_id: ml_dsa_65_key_id_from_spki(&precommit.spki).map_err(|_| "PQ2_KEY")?,
                    generation: precommit.generation,
                    original_balance: balance,
                    original_nonce: nonce,
                    permission_digest,
                    account_present: balances.contains_key(id),
                },
            );
        }
        // Every source account and task/reward row was copied, including zero
        // values. New zero placeholders only name existing task permissions or
        // positive future liabilities; a zero reward alone creates no account.
        require(
            super::super::funds(&projection)? == issued,
            "PQ2_IMPORT_CONSERVATION",
        )?;
        let projection_root = super::super::root(&projection)?;
        let h = &material.header;
        let mut anchor = TrustedMigrationAnchor {
            id: [0; 48],
            checkpoint: pinned_checkpoint,
            source_root: h.state,
            source_height: h.height,
            source_timestamp: h.timestamp,
            source_network: h.network,
            source_parameters: h.parameters,
            source_genesis: material.genesis,
            registry_digest: self.digest,
            projection_root,
            issued,
            accounts,
            projection,
        };
        anchor.id = digest(b"TRNM/PoN/PQMigrationAnchor/v2\0", &anchor.descriptor())?;
        Ok(anchor)
    }
}

/// Only the private new-profile anchor can introduce pre-genesis obligations.
/// The original reward queue owner calls this against actual monetary rows:
/// each unexpired imported row must be byte-identical, and each matured row
/// must already have been removed by the original mandatory transition.
pub(crate) fn retained_reward_count(state: &State, height: u64, cfg: &Config) -> Result<usize> {
    if !enabled(cfg) {
        return Ok(0);
    }
    let Some(anchor) = &policy(cfg)?.anchor else {
        return Ok(0);
    };
    require(
        cfg.params["reward_maturity_blocks"] == 20,
        "PQ2_IMPORT_REWARD_PROFILE",
    )?;
    let mut count = 0_usize;
    for (key, value) in anchor
        .projection
        .iter()
        .filter(|(key, _)| key.starts_with("reward:"))
    {
        if field(value, "maturity")? > height {
            require(state.get(key) == Some(value), "PQ2_IMPORT_REWARD_BINDING")?;
            count += 1;
        } else {
            require(!state.contains_key(key), "PQ2_IMPORT_REWARD_CONSUMED")?;
        }
    }
    Ok(count)
}

impl TrustedMigrationAnchor {
    pub fn id(&self) -> [u8; 48] {
        self.id
    }
    pub fn checkpoint(&self) -> Hash {
        self.checkpoint
    }
    pub fn source_root(&self) -> Hash {
        self.source_root
    }
    pub(super) fn descriptor(&self) -> Value {
        json!({"schema":2,"source_network":hex::encode(self.source_network),
            "source_parameters":hex::encode(self.source_parameters),"source_genesis":hex::encode(self.source_genesis),
            "checkpoint":hex::encode(self.checkpoint),"source_root":hex::encode(self.source_root),
            "source_height":self.source_height,"source_timestamp":self.source_timestamp,
            "prior_pq_registry":hex::encode(self.registry_digest),"projection_root":hex::encode(self.projection_root),
            "issued":self.issued,"accounts":self.accounts.len()})
    }
    pub(super) fn origin(&self, name: &str, claimed: bool) -> Result<Value> {
        let account = self.accounts.get(name).ok_or("PQ2_IMPORT_ACCOUNT")?;
        Ok(
            json!({"schema":2,"anchor":hex::encode(self.id),"source_account":name,
            "source_balance":account.original_balance,"source_nonce":account.original_nonce,
            "account_present":account.account_present,"permission_digest":hex::encode(account.permission_digest),
            "claimed":claimed}),
        )
    }
    pub(super) fn immutable_rows(&self) -> State {
        let mut state = State::from([(ANCHOR_META.into(), self.descriptor())]);
        for (name, account) in &self.accounts {
            state.insert(
                format!("{ANCHOR_KEY}{name}"),
                json!(hex::encode(&account.spki)),
            );
        }
        state
    }
    pub(super) fn import_into(&self, state: &mut State) -> Result<()> {
        for (key, value) in &self.projection {
            require(!state.contains_key(key), "PQ2_IMPORT_ID_COLLISION")?;
            state.insert(key.clone(), value.clone());
        }
        for (key, value) in self.immutable_rows() {
            require(
                state.insert(key, value).is_none(),
                "PQ2_IMPORT_ID_COLLISION",
            )?;
        }
        for name in self.accounts.keys() {
            require(
                state
                    .insert(format!("{ORIGIN}{name}"), self.origin(name, false)?)
                    .is_none(),
                "PQ2_IMPORT_ID_COLLISION",
            )?;
        }
        Ok(())
    }
    pub(super) fn claim_payload(&self, account: Hash) -> Result<Vec<u8>> {
        let record = self
            .accounts
            .get(&hex::encode(account))
            .ok_or("PQ2_IMPORT_ACCOUNT")?;
        Ok([
            self.id.as_slice(),
            &self.checkpoint,
            &self.source_root,
            &account,
            &record.original_balance.to_be_bytes(),
            &record.original_nonce.to_be_bytes(),
            &record.permission_digest,
            &1_u64.to_be_bytes(),
        ]
        .concat())
    }
}

pub(super) fn resolve_claim(
    view: &mut View<'_>,
    tx: &UnverifiedEnvelope<'_>,
    cfg: &Config,
) -> Result<Vec<u8>> {
    let anchor = policy(cfg)?
        .anchor
        .as_ref()
        .ok_or("PQ2_TRUSTED_MIGRATION_REQUIRED")?;
    let name = hex::encode(tx.common.account);
    let pinned = anchor.accounts.get(&name).ok_or("PQ2_IMPORT_ACCOUNT")?;
    require(
        tx.kind == wire::CLAIM
            && tx.common.generation == 0
            && tx.payload == anchor.claim_payload(tx.common.account)?,
        "PQ2_CLAIM_BINDING",
    )?;
    require(
        view.get(ANCHOR_META) == Some(anchor.descriptor())
            && view.get(&format!("{ORIGIN}{name}")) == Some(anchor.origin(&name, false)?)
            && view.get(&auth_key(&name)).is_none(),
        "PQ2_IMPORT_LOCKED",
    )?;
    let account = view
        .get(&format!("account:{name}"))
        .ok_or("PQ2_IMPORT_ACCOUNT")?;
    require(
        field(&account, "nonce")? == pinned.original_nonce,
        "PQ2_IMPORT_NONCE",
    )?;
    let (spki, key_id) = decode_spki(
        &view
            .get(&format!("{ANCHOR_KEY}{name}"))
            .ok_or("PQ2_ANCHOR_STATE")?,
    )?;
    let witness = &tx.witnesses()[0];
    require(
        spki == pinned.spki
            && key_id == pinned.key_id
            && witness.role == 5
            && witness.key_id == key_id
            && witness.generation == pinned.generation,
        "PQ2_PRECOMMITTED_KEY",
    )?;
    Ok(spki)
}

pub(super) fn apply_claim(
    view: &mut View<'_>,
    prepared: &PreparedCommand,
    cfg: &Config,
) -> Result<()> {
    let anchor = policy(cfg)?
        .anchor
        .as_ref()
        .ok_or("PQ2_TRUSTED_MIGRATION_REQUIRED")?;
    // The trusted import constructor pins the explicit account profile. Reuse
    // that selection here too: an NPQ3 claim must never be reparsed as NPQ2,
    // and the original NPQ2 path must not negotiate a newer input profile.
    let tx = decode_for_config(&prepared.raw, cfg)?;
    require(
        resolve_claim(view, &tx, cfg)? == prepared.keys[0],
        "PQ2_PREPARED_KEY_CHANGED",
    )?;
    let name = hex::encode(prepared.common.account);
    let key_id = ml_dsa_65_key_id_from_spki(&prepared.keys[1]).map_err(|_| "PQ2_KEY")?;
    let mut writes = State::new();
    install_key(&mut writes, &name, 1, key_id, &prepared.keys[1]);
    for (key, value) in writes {
        require(view.get(&key).is_none(), "PQ2_DUPLICATE_KEY")?;
        view.put(key, value);
    }
    view.put(format!("{ORIGIN}{name}"), anchor.origin(&name, true)?);
    Ok(())
}
