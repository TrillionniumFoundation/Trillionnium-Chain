use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, ensure, Context, Result};
use jmt::{
    storage::{Node, NodeKey, StaleNodeIndex},
    KeyHash, RootHash, Version,
};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::Serialize;

use super::{
    auth_tree::{
        stored_object_key, validator_state_key, AuthenticatedObjectRecord, InMemoryAuthTree,
        PlannedAuthUpdate,
    },
    persist_state_bytes, AppState, PendingBlock, StoredObject, ValidatorLifecycleStateV1,
    APP_VERSION, VALIDATOR_LIFECYCLE_SCHEMA_V1,
};

const STORE_SCHEMA_VERSION: &str = "3";
const STATUS_SCHEMA_V2: &str = "trnm_cometbft_app_status_v2";

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StoreFailpoint {
    BeforeSqlCommit,
    AfterSqlCommitBeforeStatus,
}

#[derive(Debug, Clone)]
pub(super) struct ApplicationStore {
    status_path: PathBuf,
    database_path: PathBuf,
    chain_id: String,
    signer_policy_hash_hex: String,
}

#[derive(Serialize)]
struct PersistedStatusV2 {
    schema: &'static str,
    app_version: u64,
    height: u64,
    app_hash_hex: String,
}

impl ApplicationStore {
    pub(super) fn open(
        status_path: &Path,
        chain_id: &str,
        signer_policy_hash_hex: &str,
    ) -> Result<Self> {
        let extension = status_path
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| format!("{value}.sqlite3"))
            .unwrap_or_else(|| "sqlite3".to_string());
        let store = Self {
            status_path: status_path.to_path_buf(),
            database_path: status_path.with_extension(extension),
            chain_id: chain_id.to_string(),
            signer_policy_hash_hex: signer_policy_hash_hex.to_string(),
        };
        Ok(store)
    }

    pub(super) fn load_or_migrate(&self) -> Result<(AppState, InMemoryAuthTree)> {
        if !self.database_path.exists() && self.status_path.exists() {
            return Err(anyhow!(
                "existing pre-v4 state requires the explicit export/new-genesis migration tool"
            ));
        }
        if self.database_path.exists() {
            self.probe_existing_database()?;
        }
        let connection = self.connect()?;
        if self.has_committed_state(&connection)? {
            let auth_tree = load_auth_tree(&connection)?;
            let state = load_sqlite_state(&connection, &auth_tree)?;
            self.refresh_status_best_effort(&state);
            return Ok((state, auth_tree));
        }
        drop(connection);

        if !self.status_path.exists() {
            return Ok((AppState::default(), InMemoryAuthTree::default()));
        }
        Err(anyhow!(
            "existing pre-v4 state requires the explicit export/new-genesis migration tool"
        ))
    }

    pub(super) fn persist_transition(
        &self,
        current: &AppState,
        pending: &PendingBlock,
    ) -> Result<()> {
        self.persist_transition_inner(current, pending, None)
    }

    #[cfg(test)]
    pub(super) fn persist_transition_with_failpoint(
        &self,
        current: &AppState,
        pending: &PendingBlock,
        failpoint: StoreFailpoint,
    ) -> Result<()> {
        self.persist_transition_inner(current, pending, Some(failpoint))
    }

    fn persist_transition_inner(
        &self,
        current: &AppState,
        pending: &PendingBlock,
        #[cfg_attr(not(test), allow(unused_variables))] failpoint: Option<StoreFailpoint>,
    ) -> Result<()> {
        ensure!(
            pending.height == current.height.saturating_add(1),
            "application store height transition is not contiguous"
        );

        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, current)?;
        for object in pending.delta.objects.values() {
            upsert_object(&transaction, object)?;
        }
        for command_id in &pending.delta.command_ids {
            ensure!(
                !current.command_ids.contains(command_id),
                "pending command ID already exists in committed state"
            );
            transaction.execute(
                "INSERT INTO command_ids(command_id) VALUES (?1)",
                params![command_id],
            )?;
        }
        for (signer_id, nonce) in &pending.delta.signer_nonces {
            ensure!(
                !current.signer_nonces.contains(&(signer_id.clone(), *nonce)),
                "pending signer nonce already exists in committed state"
            );
            transaction.execute(
                "INSERT INTO signer_nonces(signer_id, nonce) VALUES (?1, ?2)",
                params![signer_id, nonce.to_be_bytes().as_slice()],
            )?;
        }
        let lifecycle = pending
            .delta
            .validator_lifecycle
            .as_ref()
            .or(current.validator_lifecycle.as_ref())
            .context("cannot persist state before validator lifecycle initialization")?;
        write_validator_lifecycle(&transaction, lifecycle)?;
        ensure!(
            <[u8; 32]>::from(pending.auth_update.root_hash) == pending.app_hash,
            "pending AppHash differs from authenticated tree root"
        );
        persist_auth_update(&transaction, &pending.auth_update)?;
        write_head_values(&transaction, pending.height, pending.app_hash)?;
        #[cfg(test)]
        if failpoint == Some(StoreFailpoint::BeforeSqlCommit) {
            return Err(anyhow!("injected failure before SQLite COMMIT"));
        }
        transaction.commit()?;
        #[cfg(test)]
        if failpoint == Some(StoreFailpoint::AfterSqlCommitBeforeStatus) {
            return Err(anyhow!(
                "injected failure after SQLite COMMIT before status refresh"
            ));
        }
        self.refresh_status_values_best_effort(pending.height, pending.app_hash);
        Ok(())
    }

    pub(super) fn replace_empty_state(
        &self,
        expected: &AppState,
        state: &AppState,
        auth_update: &PlannedAuthUpdate,
    ) -> Result<()> {
        let mut auth_tree = InMemoryAuthTree::default();
        auth_tree.apply(auth_update.clone())?;
        self.replace_empty_state_from_tree(expected, state, &auth_tree)
    }

    pub(super) fn replace_empty_state_from_tree(
        &self,
        expected: &AppState,
        state: &AppState,
        auth_tree: &InMemoryAuthTree,
    ) -> Result<()> {
        ensure!(
            expected.height == 0 && expected.pending.is_none(),
            "snapshot replacement expected state must be empty"
        );
        ensure!(state.pending.is_none(), "cannot persist pending state");
        ensure!(
            auth_tree.latest_version() == Some(state.height)
                && auth_tree
                    .root_hash(state.height)
                    .map(Into::<[u8; 32]>::into)
                    == Some(state.app_hash),
            "replacement authenticated state does not match app head"
        );
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, expected)?;
        transaction.execute("DELETE FROM objects", [])?;
        transaction.execute("DELETE FROM command_ids", [])?;
        transaction.execute("DELETE FROM signer_nonces", [])?;
        transaction.execute("DELETE FROM validator_lifecycle", [])?;
        clear_auth_tree(&transaction)?;
        for object in state.objects.values() {
            upsert_object(&transaction, object)?;
        }
        for command_id in &state.command_ids {
            transaction.execute(
                "INSERT INTO command_ids(command_id) VALUES (?1)",
                params![command_id],
            )?;
        }
        for (signer_id, nonce) in &state.signer_nonces {
            transaction.execute(
                "INSERT INTO signer_nonces(signer_id, nonce) VALUES (?1, ?2)",
                params![signer_id, nonce.to_be_bytes().as_slice()],
            )?;
        }
        if let Some(lifecycle) = &state.validator_lifecycle {
            write_validator_lifecycle(&transaction, lifecycle)?;
        }
        persist_full_auth_tree(&transaction, auth_tree)?;
        write_head_values(&transaction, state.height, state.app_hash)?;
        transaction.commit()?;
        self.refresh_status_best_effort(state);
        Ok(())
    }

    pub(super) fn replace_auth_tree(
        &self,
        state: &AppState,
        auth_tree: &InMemoryAuthTree,
    ) -> Result<()> {
        ensure!(
            state.pending.is_none(),
            "cannot replace authenticated history while a block is pending"
        );
        ensure!(
            auth_tree.latest_version() == Some(state.height)
                && auth_tree
                    .root_hash(state.height)
                    .map(Into::<[u8; 32]>::into)
                    == Some(state.app_hash),
            "replacement authenticated history does not match app head"
        );
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, state)?;
        clear_auth_tree(&transaction)?;
        persist_full_auth_tree(&transaction, auth_tree)?;
        transaction.commit()?;
        Ok(())
    }

    fn connect(&self) -> Result<Connection> {
        if let Some(parent) = self.database_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("create application store directory {}", parent.display())
            })?;
        }
        let connection = Connection::open(&self.database_path)
            .with_context(|| format!("open application store {}", self.database_path.display()))?;
        connection.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;
            PRAGMA busy_timeout=5000;
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS objects (
                object_key_hex TEXT PRIMARY KEY NOT NULL,
                object_type TEXT NOT NULL,
                version TEXT NOT NULL,
                value_hash_hex TEXT NOT NULL,
                value_bytes BLOB NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS command_ids (
                command_id TEXT PRIMARY KEY NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS signer_nonces (
                signer_id TEXT NOT NULL,
                nonce BLOB NOT NULL CHECK(length(nonce)=8),
                PRIMARY KEY (signer_id, nonce)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS validator_lifecycle (
                singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
                state_json BLOB NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS auth_nodes (
                node_key BLOB PRIMARY KEY NOT NULL,
                node BLOB NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS auth_values (
                key_hash BLOB NOT NULL CHECK(length(key_hash)=32),
                version_be BLOB NOT NULL CHECK(length(version_be)=8),
                value BLOB,
                is_deleted INTEGER NOT NULL CHECK(is_deleted IN (0,1)),
                PRIMARY KEY (key_hash, version_be)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS auth_preimages (
                key_hash BLOB PRIMARY KEY NOT NULL CHECK(length(key_hash)=32),
                key_preimage BLOB NOT NULL CHECK(length(key_preimage)>0)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS auth_stale_nodes (
                stale_since_version_be BLOB NOT NULL CHECK(length(stale_since_version_be)=8),
                node_key BLOB NOT NULL,
                PRIMARY KEY (stale_since_version_be, node_key)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS auth_roots (
                version_be BLOB PRIMARY KEY NOT NULL CHECK(length(version_be)=8),
                root_hash BLOB NOT NULL CHECK(length(root_hash)=32)
            ) STRICT;
            ",
        )?;
        let schema: Option<String> = connection
            .query_row(
                "SELECT value FROM metadata WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match schema {
            Some(schema) => ensure!(
                schema == STORE_SCHEMA_VERSION,
                "unsupported application store schema version"
            ),
            None => {
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES ('schema_version', ?1)",
                    params![STORE_SCHEMA_VERSION],
                )?;
            }
        }
        ensure_metadata_binding(&connection, "chain_id", &self.chain_id)?;
        ensure_metadata_binding(&connection, "app_version", &APP_VERSION.to_string())?;
        ensure_metadata_binding(
            &connection,
            "authorized_signers_hash_hex",
            &self.signer_policy_hash_hex,
        )?;
        ensure_metadata_binding(&connection, "auth_tree", "jmt-sha256-v0.12.0")?;
        ensure_metadata_binding(&connection, "auth_codec", "borsh-v1")?;
        Ok(connection)
    }

    fn probe_existing_database(&self) -> Result<()> {
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| {
            format!(
                "open existing application store read-only {}",
                self.database_path.display()
            )
        })?;
        let app_version = APP_VERSION.to_string();
        let bindings = [
            ("schema_version", STORE_SCHEMA_VERSION),
            ("chain_id", self.chain_id.as_str()),
            ("app_version", app_version.as_str()),
            (
                "authorized_signers_hash_hex",
                self.signer_policy_hash_hex.as_str(),
            ),
            ("auth_tree", "jmt-sha256-v0.12.0"),
            ("auth_codec", "borsh-v1"),
        ];
        for (key, expected) in bindings {
            let actual: String = connection
                .query_row(
                    "SELECT value FROM metadata WHERE key=?1",
                    params![key],
                    |row| row.get(0),
                )
                .with_context(|| {
                    format!("existing application store is missing or cannot read {key}")
                })?;
            ensure!(
                actual == expected,
                "existing application store {key} differs from configured value"
            );
        }
        Ok(())
    }

    fn has_committed_state(&self, connection: &Connection) -> Result<bool> {
        Ok(connection
            .query_row("SELECT value FROM metadata WHERE key='height'", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
            .is_some())
    }

    fn refresh_status_best_effort(&self, state: &AppState) {
        self.refresh_status_values_best_effort(state.height, state.app_hash);
    }

    fn refresh_status_values_best_effort(&self, height: u64, app_hash: [u8; 32]) {
        if let Err(error) = self.write_status_values(height, app_hash) {
            eprintln!(
                "[trnm-cometbft-app] SQLite commit is authoritative; failed to refresh status cache: {error:#}"
            );
        }
    }

    fn write_status_values(&self, height: u64, app_hash: [u8; 32]) -> Result<()> {
        let status = PersistedStatusV2 {
            schema: STATUS_SCHEMA_V2,
            app_version: APP_VERSION,
            height,
            app_hash_hex: hex::encode(app_hash),
        };
        persist_state_bytes(&self.status_path, &serde_json::to_vec(&status)?)
    }
}

fn verify_database_head(transaction: &Transaction<'_>, current: &AppState) -> Result<()> {
    let stored_height: Option<String> = transaction
        .query_row("SELECT value FROM metadata WHERE key='height'", [], |row| {
            row.get(0)
        })
        .optional()?;
    if current.height == 0 && stored_height.is_none() {
        return Ok(());
    }
    let stored_height = stored_height
        .ok_or_else(|| anyhow!("application store is missing committed height"))?
        .parse::<u64>()
        .context("parse application store height")?;
    let stored_hash: String = transaction
        .query_row(
            "SELECT value FROM metadata WHERE key='app_hash_hex'",
            [],
            |row| row.get(0),
        )
        .context("application store is missing committed app hash")?;
    ensure!(
        stored_height == current.height && stored_hash == hex::encode(current.app_hash),
        "application store head differs from in-memory committed state"
    );
    Ok(())
}

fn write_head_values(transaction: &Transaction<'_>, height: u64, app_hash: [u8; 32]) -> Result<()> {
    for (key, value) in [
        ("height", height.to_string()),
        ("app_hash_hex", hex::encode(app_hash)),
    ] {
        transaction.execute(
            "INSERT INTO metadata(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
    }
    Ok(())
}

fn clear_auth_tree(transaction: &Transaction<'_>) -> Result<()> {
    transaction.execute("DELETE FROM auth_nodes", [])?;
    transaction.execute("DELETE FROM auth_values", [])?;
    transaction.execute("DELETE FROM auth_preimages", [])?;
    transaction.execute("DELETE FROM auth_stale_nodes", [])?;
    transaction.execute("DELETE FROM auth_roots", [])?;
    Ok(())
}

fn persist_full_auth_tree(
    transaction: &Transaction<'_>,
    auth_tree: &InMemoryAuthTree,
) -> Result<()> {
    for (node_key, node) in auth_tree.nodes() {
        transaction.execute(
            "INSERT INTO auth_nodes(node_key, node) VALUES (?1, ?2)",
            params![
                borsh::to_vec(node_key).context("encode JMT node key")?,
                borsh::to_vec(node).context("encode JMT node")?,
            ],
        )?;
    }
    for ((key_hash, version), value) in auth_tree.values() {
        transaction.execute(
            "INSERT INTO auth_values(key_hash, version_be, value, is_deleted)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                key_hash.0.as_slice(),
                version.to_be_bytes().as_slice(),
                value.as_deref(),
                i64::from(value.is_none()),
            ],
        )?;
    }
    for (key_hash, preimage) in auth_tree.preimages() {
        transaction.execute(
            "INSERT INTO auth_preimages(key_hash, key_preimage) VALUES (?1, ?2)",
            params![key_hash.0.as_slice(), preimage],
        )?;
    }
    for stale in auth_tree.stale_nodes() {
        transaction.execute(
            "INSERT INTO auth_stale_nodes(stale_since_version_be, node_key)
             VALUES (?1, ?2)",
            params![
                stale.stale_since_version.to_be_bytes().as_slice(),
                borsh::to_vec(&stale.node_key).context("encode stale JMT node key")?,
            ],
        )?;
    }
    for (version, root) in auth_tree.roots() {
        transaction.execute(
            "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
            params![version.to_be_bytes().as_slice(), root.0.as_slice(),],
        )?;
    }
    Ok(())
}

fn persist_auth_update(transaction: &Transaction<'_>, update: &PlannedAuthUpdate) -> Result<()> {
    for (node_key, node) in update.tree_update_batch.node_batch.nodes() {
        transaction.execute(
            "INSERT INTO auth_nodes(node_key, node) VALUES (?1, ?2)",
            params![
                borsh::to_vec(node_key).context("encode JMT node key")?,
                borsh::to_vec(node).context("encode JMT node")?,
            ],
        )?;
    }
    for ((version, key_hash), value) in update.tree_update_batch.node_batch.values() {
        transaction.execute(
            "INSERT INTO auth_values(key_hash, version_be, value, is_deleted)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                key_hash.0.as_slice(),
                version.to_be_bytes().as_slice(),
                value.as_deref(),
                i64::from(value.is_none()),
            ],
        )?;
    }
    for (key_hash, preimage) in update.preimages() {
        transaction.execute(
            "INSERT INTO auth_preimages(key_hash, key_preimage) VALUES (?1, ?2)
             ON CONFLICT(key_hash) DO NOTHING",
            params![key_hash.0.as_slice(), preimage],
        )?;
        let stored: Vec<u8> = transaction.query_row(
            "SELECT key_preimage FROM auth_preimages WHERE key_hash=?1",
            params![key_hash.0.as_slice()],
            |row| row.get(0),
        )?;
        ensure!(
            stored == *preimage,
            "authenticated key hash collision in persistent preimage store"
        );
    }
    for stale in &update.tree_update_batch.stale_node_index_batch {
        transaction.execute(
            "INSERT INTO auth_stale_nodes(stale_since_version_be, node_key)
             VALUES (?1, ?2)",
            params![
                stale.stale_since_version.to_be_bytes().as_slice(),
                borsh::to_vec(&stale.node_key).context("encode stale JMT node key")?,
            ],
        )?;
    }
    transaction.execute(
        "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
        params![
            update.version.to_be_bytes().as_slice(),
            update.root_hash.0.as_slice(),
        ],
    )?;
    Ok(())
}

fn load_auth_tree(connection: &Connection) -> Result<InMemoryAuthTree> {
    let mut nodes = std::collections::BTreeMap::new();
    let mut statement =
        connection.prepare("SELECT node_key, node FROM auth_nodes ORDER BY node_key")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    for row in rows {
        let (node_key, node) = row?;
        let node_key: NodeKey =
            borsh::from_slice(&node_key).context("decode persisted JMT node key")?;
        let node: Node = borsh::from_slice(&node).context("decode persisted JMT node")?;
        ensure!(
            nodes.insert(node_key, node).is_none(),
            "duplicate persisted JMT node"
        );
    }

    let mut values = std::collections::BTreeMap::new();
    let mut statement = connection.prepare(
        "SELECT key_hash, version_be, value, is_deleted
         FROM auth_values ORDER BY key_hash, version_be",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Option<Vec<u8>>>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    for row in rows {
        let (key_hash, version, value, is_deleted) = row?;
        let key_hash = KeyHash(
            <[u8; 32]>::try_from(key_hash.as_slice())
                .map_err(|_| anyhow!("persisted JMT key hash is not 32 bytes"))?,
        );
        let version = decode_version_be(&version)?;
        ensure!(
            matches!((is_deleted, value.is_none()), (0, false) | (1, true)),
            "persisted JMT value tombstone mismatch"
        );
        ensure!(
            values.insert((key_hash, version), value).is_none(),
            "duplicate persisted JMT value"
        );
    }

    let mut preimages = std::collections::BTreeMap::new();
    let mut statement = connection
        .prepare("SELECT key_hash, key_preimage FROM auth_preimages ORDER BY key_hash")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    for row in rows {
        let (key_hash, preimage) = row?;
        let key_hash = KeyHash(
            <[u8; 32]>::try_from(key_hash.as_slice())
                .map_err(|_| anyhow!("persisted JMT preimage hash is not 32 bytes"))?,
        );
        ensure!(
            preimages.insert(key_hash, preimage).is_none(),
            "duplicate persisted JMT preimage"
        );
    }

    let mut stale_nodes = std::collections::BTreeSet::new();
    let mut statement = connection.prepare(
        "SELECT stale_since_version_be, node_key
         FROM auth_stale_nodes ORDER BY stale_since_version_be, node_key",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    for row in rows {
        let (stale_since_version, node_key) = row?;
        let stale = StaleNodeIndex {
            stale_since_version: decode_version_be(&stale_since_version)?,
            node_key: borsh::from_slice(&node_key)
                .context("decode persisted stale JMT node key")?,
        };
        ensure!(
            stale_nodes.insert(stale),
            "duplicate persisted stale JMT node index"
        );
    }

    let mut roots = std::collections::BTreeMap::new();
    let mut statement =
        connection.prepare("SELECT version_be, root_hash FROM auth_roots ORDER BY version_be")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    for row in rows {
        let (version, root_hash) = row?;
        let version = decode_version_be(&version)?;
        let root_hash = RootHash(
            <[u8; 32]>::try_from(root_hash.as_slice())
                .map_err(|_| anyhow!("persisted JMT root hash is not 32 bytes"))?,
        );
        ensure!(
            roots.insert(version, root_hash).is_none(),
            "duplicate persisted JMT root"
        );
    }

    InMemoryAuthTree::from_parts(nodes, values, preimages, stale_nodes, roots)
}

fn decode_version_be(bytes: &[u8]) -> Result<Version> {
    Ok(u64::from_be_bytes(<[u8; 8]>::try_from(bytes).map_err(
        |_| anyhow!("persisted JMT version is not 8 bytes"),
    )?))
}

fn upsert_object(transaction: &Transaction<'_>, object: &StoredObject) -> Result<()> {
    transaction.execute(
        "INSERT INTO objects(
            object_key_hex, object_type, version, value_hash_hex, value_bytes
         ) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(object_key_hex) DO UPDATE SET
            object_type=excluded.object_type,
            version=excluded.version,
            value_hash_hex=excluded.value_hash_hex,
            value_bytes=excluded.value_bytes",
        params![
            object.object_key_hex,
            object.object_type,
            object.version.to_string(),
            object.value_hash_hex,
            object.value_bytes,
        ],
    )?;
    Ok(())
}

fn write_validator_lifecycle(
    transaction: &Transaction<'_>,
    lifecycle: &ValidatorLifecycleStateV1,
) -> Result<()> {
    lifecycle.validate()?;
    transaction.execute(
        "INSERT INTO validator_lifecycle(singleton, state_json) VALUES (1, ?1)
         ON CONFLICT(singleton) DO UPDATE SET state_json=excluded.state_json",
        params![serde_json::to_vec(lifecycle)?],
    )?;
    Ok(())
}

fn load_sqlite_state(connection: &Connection, auth_tree: &InMemoryAuthTree) -> Result<AppState> {
    let height = metadata(connection, "height")?
        .parse::<u64>()
        .context("parse application store height")?;
    let app_hash = trnm_finality_types::decode_hash32(
        "application store app_hash",
        &metadata(connection, "app_hash_hex")?,
    )?;

    let mut objects = std::collections::BTreeMap::new();
    let mut statement = connection.prepare(
        "SELECT object_key_hex, object_type, version, value_hash_hex, value_bytes
         FROM objects ORDER BY object_key_hex",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(StoredObject {
            object_key_hex: row.get(0)?,
            object_type: row.get(1)?,
            version: row.get::<_, String>(2)?.parse::<u64>().map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?,
            value_hash_hex: row.get(3)?,
            value_bytes: row.get(4)?,
        })
    })?;
    for row in rows {
        let object = row?;
        ensure!(
            object.value_hash_hex
                == hex::encode(trnm_finality_types::hash_domain(
                    "trnm.state.object.value.v1",
                    &[&object.value_bytes],
                )),
            "application store object value hash mismatch"
        );
        ensure!(
            objects
                .insert(object.object_key_hex.clone(), object)
                .is_none(),
            "duplicate object in application store"
        );
    }

    let mut command_ids = std::collections::BTreeSet::new();
    let mut statement =
        connection.prepare("SELECT command_id FROM command_ids ORDER BY command_id")?;
    for row in statement.query_map([], |row| row.get::<_, String>(0))? {
        ensure!(
            command_ids.insert(row?),
            "duplicate command ID in application store"
        );
    }

    let mut signer_nonces = std::collections::BTreeSet::new();
    let mut statement = connection
        .prepare("SELECT signer_id, nonce FROM signer_nonces ORDER BY signer_id, nonce")?;
    let rows = statement.query_map([], |row| {
        let signer_id = row.get::<_, String>(0)?;
        let nonce_bytes = row.get::<_, Vec<u8>>(1)?;
        let nonce = <[u8; 8]>::try_from(nonce_bytes.as_slice())
            .map(u64::from_be_bytes)
            .map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Blob,
                    "signer nonce must be an 8-byte big-endian value".into(),
                )
            })?;
        Ok((signer_id, nonce))
    })?;
    for row in rows {
        ensure!(
            signer_nonces.insert(row?),
            "duplicate signer nonce in application store"
        );
    }

    let lifecycle_bytes: Vec<u8> = connection
        .query_row(
            "SELECT state_json FROM validator_lifecycle WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .context("application store is missing committed validator lifecycle")?;
    let validator_lifecycle: ValidatorLifecycleStateV1 =
        serde_json::from_slice(&lifecycle_bytes)
            .context("decode application store validator lifecycle")?;
    validator_lifecycle.validate()?;
    ensure!(
        auth_tree.latest_version() == Some(height),
        "authenticated tree version differs from application height"
    );
    let expected = auth_tree
        .root_hash(height)
        .map(Into::<[u8; 32]>::into)
        .context("application store is missing authenticated root")?;
    ensure!(
        expected == app_hash,
        "application store content does not match committed app hash"
    );
    let mut authenticated = auth_tree.verified_live_values(height)?;
    for object in objects.values() {
        let key = stored_object_key(&object.object_key_hex)?;
        let value = authenticated.remove(&key).with_context(|| {
            format!(
                "application store object {} is absent from authenticated state",
                object.object_key_hex
            )
        })?;
        let expected = AuthenticatedObjectRecord::new(
            object.object_type.clone(),
            object.version,
            object.value_bytes.clone(),
        )?
        .encode()?;
        ensure!(
            value == expected,
            "application store object {} differs from authenticated state",
            object.object_key_hex
        );
    }
    let lifecycle_value = authenticated
        .remove(&validator_state_key()?)
        .context("application store validator lifecycle is absent from authenticated state")?;
    let lifecycle_record = AuthenticatedObjectRecord::decode(&lifecycle_value)?;
    ensure!(
        lifecycle_record.object_type == VALIDATOR_LIFECYCLE_SCHEMA_V1
            && lifecycle_record.object_version <= height
            && lifecycle_record.value == lifecycle_bytes,
        "application store validator lifecycle differs from authenticated state"
    );
    ensure!(
        authenticated.is_empty(),
        "authenticated state contains {} leaves absent from the application store",
        authenticated.len()
    );
    Ok(AppState {
        height,
        app_hash,
        objects,
        command_ids,
        signer_nonces,
        validator_lifecycle: Some(validator_lifecycle),
        pending: None,
    })
}

fn metadata(connection: &Connection, key: &str) -> Result<String> {
    connection
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            params![key],
            |row| row.get(0),
        )
        .with_context(|| format!("application store is missing {key}"))
}

fn ensure_metadata_binding(connection: &Connection, key: &str, expected: &str) -> Result<()> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    match actual {
        Some(actual) => ensure!(
            actual == expected,
            "application store {key} differs from configured value"
        ),
        None => {
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES (?1, ?2)",
                params![key, expected],
            )?;
        }
    }
    Ok(())
}
