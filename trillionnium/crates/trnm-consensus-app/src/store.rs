use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, ensure, Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;

use super::{
    compute_app_hash, empty_app_hash, load_state, persist_state_bytes, AppState, PendingBlock,
    StoredObject, ValidatorLifecycleStateV1, APP_VERSION,
};

const STORE_SCHEMA_VERSION: &str = "2";
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
        store.connect()?;
        Ok(store)
    }

    pub(super) fn load_or_migrate(&self) -> Result<AppState> {
        let connection = self.connect()?;
        if self.has_committed_state(&connection)? {
            let state = load_sqlite_state(&connection)?;
            if self.status_path.exists() {
                let status_bytes = fs::read(&self.status_path).with_context(|| {
                    format!("read application status {}", self.status_path.display())
                })?;
                let schema = serde_json::from_slice::<serde_json::Value>(&status_bytes)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("schema")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string)
                    });
                if schema.as_deref() == Some("trnm_cometbft_app_state_v3") {
                    let legacy = load_state(&self.status_path)?;
                    ensure!(
                        legacy.height == state.height && legacy.app_hash == state.app_hash,
                        "legacy JSON state and SQLite head disagree; manual recovery required"
                    );
                }
            }
            self.refresh_status_best_effort(&state);
            return Ok(state);
        }
        drop(connection);

        if !self.status_path.exists() {
            return Ok(AppState::default());
        }
        let bytes = fs::read(&self.status_path)
            .with_context(|| format!("read legacy app state {}", self.status_path.display()))?;
        let schema = serde_json::from_slice::<serde_json::Value>(&bytes)
            .context("decode existing application state before migration")?
            .get("schema")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        ensure!(
            schema == "trnm_cometbft_app_state_v3",
            "SQLite store is empty but status file is not a migratable v3 state; v2 state predates committed validator lifecycle and must not be upgraded implicitly"
        );
        let state = load_state(&self.status_path)?;
        let backup = self.legacy_backup_path();
        if backup.exists() {
            ensure!(
                fs::read(&backup)
                    .with_context(|| format!("read legacy backup {}", backup.display()))?
                    == bytes,
                "existing legacy state backup differs from migration source"
            );
        } else {
            persist_state_bytes(&backup, &bytes).with_context(|| {
                format!("atomically back up legacy app state {}", backup.display())
            })?;
        }
        self.replace_empty_state(&AppState::default(), &state)?;
        Ok(state)
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

    #[cfg(test)]
    pub(super) fn replace_state(&self, state: &AppState) -> Result<()> {
        self.replace_empty_state(&AppState::default(), state)
    }

    pub(super) fn replace_empty_state(&self, expected: &AppState, state: &AppState) -> Result<()> {
        ensure!(
            expected.height == 0 && expected.pending.is_none(),
            "snapshot replacement expected state must be empty"
        );
        ensure!(state.pending.is_none(), "cannot persist pending state");
        let expected_hash = if state.height == 0
            && state.objects.is_empty()
            && state.command_ids.is_empty()
            && state.signer_nonces.is_empty()
            && state.validator_lifecycle.is_none()
        {
            empty_app_hash()
        } else {
            compute_app_hash(
                state.height,
                &state.objects,
                &state.command_ids,
                &state.signer_nonces,
                state.validator_lifecycle.as_ref(),
            )
        };
        ensure!(
            expected_hash == state.app_hash,
            "replacement state content does not match app hash"
        );
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, expected)?;
        transaction.execute("DELETE FROM objects", [])?;
        transaction.execute("DELETE FROM command_ids", [])?;
        transaction.execute("DELETE FROM signer_nonces", [])?;
        transaction.execute("DELETE FROM validator_lifecycle", [])?;
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
        write_head_values(&transaction, state.height, state.app_hash)?;
        transaction.commit()?;
        self.refresh_status_best_effort(state);
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
        Ok(connection)
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

    fn legacy_backup_path(&self) -> PathBuf {
        let extension = self
            .status_path
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| format!("{value}.legacy-v3"))
            .unwrap_or_else(|| "legacy-v3".to_string());
        self.status_path.with_extension(extension)
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

fn load_sqlite_state(connection: &Connection) -> Result<AppState> {
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
    let expected = compute_app_hash(
        height,
        &objects,
        &command_ids,
        &signer_nonces,
        Some(&validator_lifecycle),
    );
    ensure!(
        expected == app_hash,
        "application store content does not match committed app hash"
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
