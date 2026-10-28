//! Native M06 QTX1 account execution selected by a verified PQG1 import.
//! The existing balance, nonce, fees, rewards and branch State remain the owner.
//! This does not authenticate the external old-chain/export/revocation pins.
use super::{
    add, canonical, field, hash, require, ApplicationCommand, Config, Hash, Prepared, Result, State,
};
use serde_json::json;
use sha2::{Digest, Sha256, Sha384};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use trnm_crypto_primitives::{pq_auth::PqNativeVerifier, verify_hex_strict};
use trnm_protocol::{pq_frame::ml_dsa_65_key_id_from_spki, pq_transaction};

pub const PROFILE: &str = "native-pq-qtx1-account-v1";
const LIABILITY_PREFIX: &str = "pq-import-liability:";
const SOURCE_DOMAIN: &[u8] = b"TRNM/PQ/GenesisSource/v1\0";
const STATE_DOMAIN: &[u8] = b"TRNM/PQ/GenesisState/v1\0";
const GENESIS_DOMAIN: &[u8] = b"TRNM/PQ/GenesisID/v1\0";
const MIGRATION_DOMAIN: &[u8] = b"TRNM/PQ/GenesisMigration/v1\0";

/// These exact independently authenticated expectations are not derived from
/// incoming migration bytes. M13 export and revocation authority is external.
pub struct ImportPins {
    pub source_digest: [u8; 48],
    pub old_network: Hash,
    pub new_network: Hash,
    pub old_head: Hash,
    pub withdrawal_head: Hash,
    pub protocol: Hash,
    pub genesis_timestamp: u64,
    pub issued: u64,
    pub target_state_root: [u8; 48],
    pub target_genesis: [u8; 48],
    pub revoked_old_keys: BTreeSet<Hash>,
    pub now: u64,
}
pub struct MigrationEvidence {
    pub old_public: Hash,
    pub new_spki: Vec<u8>,
    pub expires_at: u64,
    pub old_signature: [u8; 64],
    pub pq_signature: Vec<u8>,
}

struct OldAccount {
    raw: [u8; 56],
    old: Hash,
    balance: u64,
    next_nonce: u64,
    generation: u64,
}
struct Source {
    old_network: Hash,
    new_network: Hash,
    old_head: Hash,
    withdrawal: Hash,
    protocol: Hash,
    issued: u64,
    accounts: Vec<OldAccount>,
    liabilities: Vec<[u8; 81]>,
}
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.position.checked_add(N).ok_or("PQ_IMPORT_LENGTH")?;
        let out = self
            .bytes
            .get(self.position..end)
            .ok_or("PQ_IMPORT_LENGTH")?
            .try_into()
            .map_err(|_| "PQ_IMPORT_LENGTH")?;
        self.position = end;
        Ok(out)
    }
    fn number(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take()?))
    }
}
fn digest(domain: &[u8], raw: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(domain);
    h.update((raw.len() as u64).to_be_bytes());
    h.update(raw);
    h.finalize().into()
}
fn address(domain: &[u8], parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update(domain);
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
fn decode_source(raw: &[u8]) -> Result<Source> {
    require((177..=65536).contains(&raw.len()), "PQ_IMPORT_LENGTH")?;
    let mut r = Reader {
        bytes: raw,
        position: 0,
    };
    require(r.take::<5>()? == *b"PQG1\x01", "PQ_IMPORT_VERSION")?;
    let old_network = r.take()?;
    let new_network = r.take()?;
    let old_head = r.take()?;
    let withdrawal = r.take()?;
    let protocol = r.take()?;
    require(
        [old_network, new_network, old_head, withdrawal, protocol]
            .iter()
            .all(|x| *x != [0; 32])
            && old_network != new_network,
        "PQ_IMPORT_CONTEXT",
    )?;
    let issued = r.number()?;
    let count = u16::from_be_bytes(r.take()?) as usize;
    let liabilities = u16::from_be_bytes(r.take()?) as usize;
    require(
        (1..=128).contains(&count) && liabilities <= 256,
        "PQ_IMPORT_LIMIT",
    )?;
    require(
        raw.len() == 177 + 56 * count + 81 * liabilities,
        "PQ_IMPORT_LENGTH",
    )?;
    let mut accounts = Vec::with_capacity(count);
    let mut previous = None;
    let mut total = 0;
    let mut identities = BTreeSet::new();
    for _ in 0..count {
        let bytes = r.take::<56>()?;
        let mut a = Reader {
            bytes: &bytes,
            position: 0,
        };
        let old: Hash = a.take()?;
        let balance = a.number()?;
        let next_nonce = a.number()?;
        let generation = a.number()?;
        require(
            old != [0; 32]
                && previous.is_none_or(|p| p < old)
                && next_nonce > 0
                && generation > 0
                && generation < u64::MAX,
            "PQ_IMPORT_ACCOUNT",
        )?;
        previous = Some(old);
        identities.insert(old);
        total = add(total, balance)?;
        accounts.push(OldAccount {
            raw: bytes,
            old,
            balance,
            next_nonce,
            generation,
        });
    }
    let mut obligations = Vec::with_capacity(liabilities);
    let mut previous = None;
    for _ in 0..liabilities {
        let bytes = r.take::<81>()?;
        let mut l = Reader {
            bytes: &bytes,
            position: 0,
        };
        let id: Hash = l.take()?;
        let owner: Hash = l.take()?;
        let amount = l.number()?;
        let _due = l.number()?;
        let kind = l.take::<1>()?[0];
        require(
            id != [0; 32]
                && previous.is_none_or(|p| p < id)
                && identities.contains(&owner)
                && amount > 0
                && (1..=4).contains(&kind),
            "PQ_IMPORT_LIABILITY",
        )?;
        previous = Some(id);
        total = add(total, amount)?;
        obligations.push(bytes);
    }
    require(total == issued, "PQ_IMPORT_CONSERVATION")?;
    Ok(Source {
        old_network,
        new_network,
        old_head,
        withdrawal,
        protocol,
        issued,
        accounts,
        liabilities: obligations,
    })
}

struct AccountKey {
    verifier: PqNativeVerifier,
    key_id: Hash,
    generation: u64,
    nonce_floor: u64,
}
pub(crate) struct AccountPolicy {
    network: Hash,
    parameters: Hash,
    keys: BTreeMap<Hash, AccountKey>,
    floors: BTreeMap<Hash, u64>,
    liabilities: State,
    locked: u64,
    config_digest: Hash,
}
fn config_digest(cfg: &Config) -> Result<Hash> {
    require(cfg.task_windows.is_none(), "PQ_ACCOUNT_CONFIG")?;
    Ok(hash(
        b"native-pq-qtx1-config-binding-v1",
        &[
            &cfg.network,
            &cfg.parameters,
            &cfg.family,
            &cfg.plan,
            &canonical(&cfg.params)?,
            &canonical(&cfg.model_registry)?,
            &canonical(&json!(cfg.fees))?,
            &canonical(&json!(cfg.evaluators))?,
        ],
    ))
}
impl AccountPolicy {
    pub(crate) fn check_config(&self, cfg: &Config) -> Result<()> {
        require(
            cfg.network == self.network
                && cfg.parameters == self.parameters
                && cfg.params["account_authorization_profile"] == PROFILE
                && cfg.params["max_transaction_bytes"] == 8192
                && cfg.params["max_transactions"] == 16
                && config_digest(cfg)? == self.config_digest,
            "PQ_ACCOUNT_CONFIG",
        )
    }
    pub(crate) fn check_state(&self, state: &State, cfg: &Config) -> Result<()> {
        self.check_config(cfg)?;
        require(
            state
                .iter()
                .filter(|(k, _)| k.starts_with(LIABILITY_PREFIX))
                .eq(self.liabilities.iter()),
            "PQ_IMPORT_LIABILITY_CHANGED",
        )?;
        for (account, floor) in &self.floors {
            let row = state
                .get(&format!("account:{}", hex::encode(account)))
                .ok_or("PQ_ACCOUNT_MISSING")?;
            require(field(row, "nonce")? >= floor - 1, "PQ_ACCOUNT_NONCE_FLOOR")?;
        }
        Ok(())
    }
    pub(crate) fn locked(&self) -> u64 {
        self.locked
    }
}

/// No public constructor or deserializer: all imported account ownership comes
/// from exact PQG1 pins and both real possession signatures. External source
/// history completeness and a pre-quantum-compromise migration cutoff remain
/// assumptions, not facts created by this value.
pub struct VerifiedPqGenesis {
    config: Config,
    state: State,
    source_digest: [u8; 48],
    target_genesis: [u8; 48],
}
impl VerifiedPqGenesis {
    pub fn into_execution_parts(self) -> (Config, State) {
        (self.config, self.state)
    }
    pub fn source_digest(&self) -> [u8; 48] {
        self.source_digest
    }
    pub fn target_genesis(&self) -> [u8; 48] {
        self.target_genesis
    }
}

/// Static new profile identity includes the original installed fee/work/context
/// parameters. Exact source and imported key/state roots are separately bound
/// into the resulting native parameters. No old context is hot-reinterpreted.
pub fn protocol_id(genesis_timestamp: u64) -> Result<Hash> {
    require(
        genesis_timestamp > 0 && genesis_timestamp <= i64::MAX as u64,
        "PQ_IMPORT_GENESIS_TIME",
    )?;
    let cfg = Config::installed()?;
    Ok(hash(
        b"native-pq-qtx1-account-profile-v1",
        &[
            &cfg.parameters,
            &genesis_timestamp.to_be_bytes(),
            b"QTX1/v1/ML-DSA-65/8192/16/transfer-only/frozen-import-liabilities",
        ],
    ))
}

pub fn import_genesis(
    raw: &[u8],
    pins: &ImportPins,
    evidence: &[MigrationEvidence],
) -> Result<VerifiedPqGenesis> {
    let source = decode_source(raw)?;
    let source_digest = digest(SOURCE_DOMAIN, raw);
    require(
        source_digest == pins.source_digest
            && pins.source_digest != [0; 48]
            && source.old_network == pins.old_network
            && source.new_network == pins.new_network
            && source.old_head == pins.old_head
            && source.withdrawal == pins.withdrawal_head
            && source.protocol == pins.protocol
            && source.protocol == protocol_id(pins.genesis_timestamp)?
            && source.issued == pins.issued,
        "PQ_IMPORT_PINS",
    )?;
    require(evidence.len() <= source.accounts.len(), "PQ_IMPORT_LIMIT")?;
    let old: BTreeSet<_> = source.accounts.iter().map(|a| a.old).collect();
    require(
        pins.revoked_old_keys.is_subset(&old),
        "PQ_IMPORT_REVOCATION",
    )?;
    let mut migrations = BTreeMap::new();
    let mut used = BTreeSet::new();
    for proof in evidence {
        let account = source
            .accounts
            .iter()
            .find(|a| a.old == proof.old_public)
            .ok_or("PQ_IMPORT_OLD_KEY")?;
        require(
            !pins.revoked_old_keys.contains(&account.old)
                && !migrations.contains_key(&account.old)
                && proof.expires_at > 0
                && pins.now <= proof.expires_at,
            "PQ_IMPORT_MIGRATION",
        )?;
        let key_id = ml_dsa_65_key_id_from_spki(&proof.new_spki).map_err(|_| "PQ_IMPORT_KEY")?;
        require(used.insert(key_id), "PQ_IMPORT_DUPLICATE_PQ_KEY")?;
        let verifier = PqNativeVerifier::from_pinned_spki(&proof.new_spki, key_id)
            .map_err(|_| "PQ_IMPORT_KEY")?;
        let mut statement = MIGRATION_DOMAIN.to_vec();
        statement.extend_from_slice(&source_digest);
        for value in [
            source.old_network,
            source.new_network,
            source.old_head,
            source.withdrawal,
            source.protocol,
        ] {
            statement.extend_from_slice(&value);
        }
        statement.extend_from_slice(&account.raw);
        statement.extend_from_slice(&key_id);
        statement.extend_from_slice(&(account.generation + 1).to_be_bytes());
        statement.extend_from_slice(&proof.expires_at.to_be_bytes());
        verify_hex_strict(
            &hex::encode(account.old),
            &statement,
            &hex::encode(proof.old_signature),
        )
        .map_err(|_| "PQ_IMPORT_OLD_SIGNATURE")?;
        verifier
            .verify_exact_message(&statement, &proof.pq_signature)
            .map_err(|_| "PQ_IMPORT_PQ_SIGNATURE")?;
        migrations.insert(account.old, (key_id, verifier, proof.new_spki.as_slice()));
    }
    let mut projected = b"PQS1\x01".to_vec();
    projected.extend_from_slice(&source.new_network);
    projected.extend_from_slice(&source.protocol);
    projected.extend_from_slice(&(source.accounts.len() as u16).to_be_bytes());
    let mut state = State::new();
    state.insert("meta:issued".into(), json!(source.issued));
    state.insert("model:current".into(), json!(hex::encode([0; 32])));
    let mut keys = BTreeMap::new();
    let mut floors = BTreeMap::new();
    let mut key_bindings = Vec::new();
    for account in &source.accounts {
        let migration = migrations.remove(&account.old);
        let (account_id, key_id, status) = match &migration {
            Some((id, _, _)) => (
                address(
                    b"TRNM/PQ/Account/v1\0",
                    &[&source.new_network, &account.old, id],
                ),
                *id,
                1,
            ),
            None => (
                address(
                    b"TRNM/PQ/Quarantine/v1\0",
                    &[&source.new_network, &account.old],
                ),
                [0; 32],
                0,
            ),
        };
        require(
            floors.insert(account_id, account.next_nonce).is_none(),
            "PQ_IMPORT_ID_COLLISION",
        )?;
        state.insert(
            format!("account:{}", hex::encode(account_id)),
            json!({"balance":account.balance,"nonce":account.next_nonce-1}),
        );
        projected.push(status);
        projected.extend_from_slice(&account_id);
        projected.extend_from_slice(&key_id);
        projected.extend_from_slice(&account.raw);
        projected.extend_from_slice(&(account.generation + 1).to_be_bytes());
        if let Some((key_id, verifier, spki)) = migration {
            key_bindings.extend_from_slice(&account_id);
            key_bindings.extend_from_slice(spki);
            keys.insert(
                account_id,
                AccountKey {
                    verifier,
                    key_id,
                    generation: account.generation + 1,
                    nonce_floor: account.next_nonce,
                },
            );
        }
    }
    let mut liabilities = State::new();
    let mut locked = 0;
    projected.extend_from_slice(&(source.liabilities.len() as u16).to_be_bytes());
    for raw in &source.liabilities {
        projected.extend_from_slice(raw);
        let amount = u64::from_be_bytes(raw[64..72].try_into().map_err(|_| "PQ_IMPORT_LENGTH")?);
        locked = add(locked, amount)?;
        liabilities.insert(
            format!("{LIABILITY_PREFIX}{}", hex::encode(&raw[..32])),
            json!({"source_record":hex::encode(raw),"amount":amount,"frozen":true}),
        );
    }
    projected.extend_from_slice(&source.issued.to_be_bytes());
    let state_root = digest(STATE_DOMAIN, &projected);
    let mut genesis_body = Vec::new();
    for part in [
        &source.new_network[..],
        &source.protocol[..],
        &source_digest[..],
        &state_root[..],
    ] {
        genesis_body.extend_from_slice(part);
    }
    let target_genesis = digest(GENESIS_DOMAIN, &genesis_body);
    require(
        state_root == pins.target_state_root && target_genesis == pins.target_genesis,
        "PQ_IMPORT_TARGET_PINS",
    )?;
    state.extend(liabilities.clone());
    let mut cfg = Config::installed()?;
    cfg.network = source.new_network;
    cfg.params["genesis_timestamp"] = json!(pins.genesis_timestamp);
    cfg.params["account_authorization_profile"] = json!(PROFILE);
    cfg.params["max_transaction_bytes"] = json!(8192);
    cfg.params["max_transactions"] = json!(16);
    cfg.parameters = hash(
        b"native-pq-qtx1-parameters-v1",
        &[
            &cfg.parameters,
            &source.protocol,
            &source_digest,
            &target_genesis,
            &key_bindings,
            &canonical(&cfg.params)?,
        ],
    );
    // The migration's declared network is an address/export namespace, not a
    // sufficient QTX1 replay domain. A reused declaration with another source,
    // key projection, protocol or launch time must produce a distinct signed
    // native chain identity. This commitment uses the complete resulting
    // parameter identity and verified import genesis, not a caller verdict.
    cfg.network = hash(
        b"native-pq-qtx1-network-v1",
        &[
            &source.new_network,
            &cfg.parameters,
            &source_digest,
            &target_genesis,
        ],
    );
    let policy = Arc::new(AccountPolicy {
        network: cfg.network,
        parameters: cfg.parameters,
        keys,
        floors,
        liabilities,
        locked,
        config_digest: config_digest(&cfg)?,
    });
    policy.check_state(&state, &cfg)?;
    cfg.pq_accounts = Some(policy);
    super::check_completed_block_state(&state, 0, &cfg)?;
    Ok(VerifiedPqGenesis {
        config: cfg,
        state,
        source_digest,
        target_genesis,
    })
}

pub(super) fn prepare(
    raw: &[u8],
    height: u64,
    cfg: &Config,
    signatures: &AtomicUsize,
    policy: &AccountPolicy,
) -> Result<Prepared> {
    policy.check_config(cfg)?;
    let (transfer, body, frame) =
        pq_transaction::decode_signed(raw).map_err(|_| "PQ_ACCOUNT_ENCODING")?;
    require(transfer.network == cfg.network, "NETWORK")?;
    require(height <= transfer.expires_at, "EXPIRED")?;
    let key = policy
        .keys
        .get(&transfer.sender)
        .ok_or("PQ_ACCOUNT_UNMIGRATED")?;
    require(
        transfer.generation == key.generation && transfer.nonce >= key.nonce_floor,
        "PQ_ACCOUNT_GENERATION_OR_NONCE",
    )?;
    let expected = transfer.expectation(key.key_id, height, body);
    signatures.fetch_add(1, Ordering::Relaxed);
    key.verifier
        .verify(frame, &expected)
        .map_err(|_| "PQ_ACCOUNT_SIGNATURE")?;
    let identity = transfer
        .logical_id(key.key_id)
        .map_err(|_| "PQ_ACCOUNT_ENCODING")?
        .to_vec();
    let mut payload = transfer.recipient.to_vec();
    payload.extend_from_slice(&transfer.amount.to_le_bytes());
    // A private typed command crosses into the original M06 apply owner only
    // after real ML-DSA verification. No synthetic PNX1 signature or externally
    // supplied verification Boolean exists on this path.
    let command = ApplicationCommand {
        sender: transfer.sender,
        nonce: transfer.nonce,
        fee_limit: transfer.max_fee,
        tag: 1,
        payload,
    };
    Ok(Prepared {
        command,
        legacy: None,
        sender: hex::encode(transfer.sender),
        encoded_len: raw.len(),
        transaction_id: identity,
    })
}
