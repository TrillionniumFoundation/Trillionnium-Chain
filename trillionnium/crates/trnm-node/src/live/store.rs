use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    sync::{Mutex, MutexGuard},
};

use anyhow::{anyhow, ensure, Context, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{
    crypto::{hash_domain, Hash32},
    protocol::{BlockHeaderV1, FinalityReceiptV1, QuorumCertificateV1, SignedCommandEnvelopeV1},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandStatus {
    Accepted,
    Deferred,
    Rejected,
    Finalized,
}

impl CommandStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
            Self::Finalized => "finalized",
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueuedCommand {
    pub envelope: SignedCommandEnvelopeV1,
    pub fingerprint_hex: String,
    pub transaction_hash_hex: String,
    pub status: CommandStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredObject {
    pub object_key_hex: String,
    pub object_type: String,
    pub version: u64,
    pub value_hash_hex: String,
    pub value_bytes: Vec<u8>,
}

impl StoredObject {
    pub fn leaf_hash(&self) -> Hash32 {
        hash_domain(
            "trnm.state.object.leaf.v1",
            &[
                self.object_key_hex.as_bytes(),
                self.object_type.as_bytes(),
                &self.version.to_be_bytes(),
                self.value_hash_hex.as_bytes(),
            ],
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMutation {
    pub object_key_hex: String,
    pub object_type: String,
    pub expected_version: Option<u64>,
    pub next_version: u64,
    pub value_bytes: Vec<u8>,
}

impl ObjectMutation {
    pub fn into_stored(self) -> StoredObject {
        let value_hash_hex = hex::encode(hash_domain(
            "trnm.state.object.value.v1",
            &[&self.value_bytes],
        ));
        StoredObject {
            object_key_hex: self.object_key_hex,
            object_type: self.object_type,
            version: self.next_version,
            value_hash_hex,
            value_bytes: self.value_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTip {
    pub height: u64,
    pub block_hash_hex: String,
    pub timestamp_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreMetrics {
    pub accepted_commands: u64,
    pub deferred_commands: u64,
    pub rejected_commands: u64,
    pub finalized_commands: u64,
    pub objects: u64,
}

#[derive(Debug, Clone)]
pub struct FinalizedCommand {
    pub command_id: String,
    pub transaction_hash_hex: String,
    pub transaction_index: u64,
    pub mutations: Vec<ObjectMutation>,
    pub receipt: FinalityReceiptV1,
}

#[derive(Debug, Clone)]
pub enum InsertCommandOutcome {
    Inserted,
    ExistingPending,
    ExistingRejected(Option<String>),
    ExistingFinalized(FinalityReceiptV1),
    AlteredReplay,
    NonceConflict,
}

pub struct DurableStore {
    connection: Mutex<Connection>,
}

impl DurableStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create chain database directory {}", parent.display()))?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("open chain database {}", path.display()))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS chain_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS commands (
                command_id TEXT PRIMARY KEY,
                fingerprint_hex TEXT NOT NULL,
                signer_id TEXT NOT NULL,
                nonce INTEGER NOT NULL,
                envelope_json BLOB NOT NULL,
                transaction_hash_hex TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL CHECK (
                    status IN ('accepted', 'deferred', 'rejected', 'finalized')
                ),
                status_reason TEXT,
                block_height INTEGER,
                transaction_index INTEGER,
                receipt_json BLOB,
                UNIQUE(signer_id, nonce)
            );
            CREATE INDEX IF NOT EXISTS commands_pending_idx
                ON commands(status);

            CREATE TABLE IF NOT EXISTS blocks (
                height INTEGER PRIMARY KEY,
                block_hash_hex TEXT NOT NULL UNIQUE,
                previous_block_hash_hex TEXT NOT NULL,
                transaction_root_hex TEXT NOT NULL,
                state_root_hex TEXT NOT NULL,
                validator_set_id TEXT NOT NULL,
                timestamp_unix_ms INTEGER NOT NULL,
                header_json BLOB NOT NULL,
                quorum_certificate_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS objects (
                object_key_hex TEXT PRIMARY KEY,
                object_type TEXT NOT NULL,
                version INTEGER NOT NULL,
                value_hash_hex TEXT NOT NULL,
                value_bytes BLOB NOT NULL,
                updated_at_height INTEGER NOT NULL
            );
            ",
        )?;
        let commands_schema: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'commands'",
            [],
            |row| row.get(0),
        )?;
        if !commands_schema.contains("'accepted'") {
            connection.execute_batch(
                "
                BEGIN IMMEDIATE;
                ALTER TABLE commands RENAME TO commands_legacy;
                CREATE TABLE commands (
                    command_id TEXT PRIMARY KEY,
                    fingerprint_hex TEXT NOT NULL,
                    signer_id TEXT NOT NULL,
                    nonce INTEGER NOT NULL,
                    envelope_json BLOB NOT NULL,
                    transaction_hash_hex TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL CHECK (
                        status IN ('accepted', 'deferred', 'rejected', 'finalized')
                    ),
                    status_reason TEXT,
                    block_height INTEGER,
                    transaction_index INTEGER,
                    receipt_json BLOB,
                    UNIQUE(signer_id, nonce)
                );
                INSERT INTO commands (
                    command_id, fingerprint_hex, signer_id, nonce, envelope_json,
                    transaction_hash_hex, status, block_height, transaction_index,
                    receipt_json
                )
                SELECT
                    command_id, fingerprint_hex, signer_id, nonce, envelope_json,
                    transaction_hash_hex,
                    CASE status WHEN 'pending' THEN 'accepted' ELSE status END,
                    block_height, transaction_index, receipt_json
                FROM commands_legacy;
                DROP TABLE commands_legacy;
                CREATE INDEX commands_pending_idx ON commands(status);
                COMMIT;
                ",
            )?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn bind_chain_metadata(&self, expected: &BTreeMap<String, String>) -> Result<()> {
        ensure!(!expected.is_empty(), "chain metadata must not be empty");
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (key, value) in expected {
            let existing: Option<String> = transaction
                .query_row(
                    "SELECT value FROM chain_metadata WHERE key = ?1",
                    params![key],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(existing) = existing {
                ensure!(
                    existing == *value,
                    "durable chain metadata mismatch for `{key}`"
                );
            } else {
                transaction.execute(
                    "INSERT INTO chain_metadata(key, value) VALUES (?1, ?2)",
                    params![key, value],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow!("chain database lock poisoned"))
    }

    pub fn insert_command(
        &self,
        envelope: &SignedCommandEnvelopeV1,
    ) -> Result<InsertCommandOutcome> {
        ensure!(
            envelope.nonce <= i64::MAX as u64,
            "nonce exceeds durable range"
        );
        let fingerprint_hex = hex::encode(envelope.fingerprint()?);
        let transaction_hash_hex = hex::encode(envelope.tx_hash()?);
        let envelope_json = serde_json::to_vec(envelope)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String, Option<String>, Option<Vec<u8>>)> = transaction
            .query_row(
                "SELECT fingerprint_hex, status, status_reason, receipt_json
                   FROM commands WHERE command_id = ?1",
                params![envelope.command_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if let Some((existing_fingerprint, status, status_reason, receipt_json)) = existing {
            transaction.commit()?;
            if existing_fingerprint != fingerprint_hex {
                return Ok(InsertCommandOutcome::AlteredReplay);
            }
            if status == "finalized" {
                let bytes =
                    receipt_json.ok_or_else(|| anyhow!("finalized command is missing receipt"))?;
                return Ok(InsertCommandOutcome::ExistingFinalized(
                    serde_json::from_slice(&bytes)?,
                ));
            }
            if status == "rejected" {
                return Ok(InsertCommandOutcome::ExistingRejected(status_reason));
            }
            return Ok(InsertCommandOutcome::ExistingPending);
        }

        let nonce_owner: Option<String> = transaction
            .query_row(
                "SELECT command_id FROM commands WHERE signer_id = ?1 AND nonce = ?2",
                params![envelope.signer_id, envelope.nonce as i64],
                |row| row.get(0),
            )
            .optional()?;
        if nonce_owner.is_some() {
            transaction.commit()?;
            return Ok(InsertCommandOutcome::NonceConflict);
        }

        transaction.execute(
            "INSERT INTO commands
             (command_id, fingerprint_hex, signer_id, nonce, envelope_json,
              transaction_hash_hex, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'accepted')",
            params![
                envelope.command_id,
                fingerprint_hex,
                envelope.signer_id,
                envelope.nonce as i64,
                envelope_json,
                transaction_hash_hex
            ],
        )?;
        transaction.commit()?;
        Ok(InsertCommandOutcome::Inserted)
    }

    pub fn queued_commands(&self, limit: usize) -> Result<Vec<QueuedCommand>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT envelope_json, fingerprint_hex, transaction_hash_hex, status
               FROM commands
              WHERE status IN ('accepted', 'deferred')
              ORDER BY CASE status WHEN 'accepted' THEN 0 ELSE 1 END, rowid
              LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit as u64], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut queued = Vec::new();
        for row in rows {
            let (envelope_json, fingerprint_hex, transaction_hash_hex, status) = row?;
            queued.push(QueuedCommand {
                envelope: serde_json::from_slice(&envelope_json)?,
                fingerprint_hex,
                transaction_hash_hex,
                status: match status.as_str() {
                    "accepted" => CommandStatus::Accepted,
                    "deferred" => CommandStatus::Deferred,
                    _ => return Err(anyhow!("queued command has invalid status `{status}`")),
                },
            });
        }
        Ok(queued)
    }

    pub fn set_command_status(
        &self,
        command_id: &str,
        status: CommandStatus,
        reason: Option<&str>,
    ) -> Result<()> {
        ensure!(
            matches!(
                status,
                CommandStatus::Accepted | CommandStatus::Deferred | CommandStatus::Rejected
            ),
            "finalized status may only be set by atomic block commit"
        );
        let connection = self.connection()?;
        let updated = connection.execute(
            "UPDATE commands SET status = ?2, status_reason = ?3
              WHERE command_id = ?1 AND status IN ('accepted', 'deferred')",
            params![command_id, status.as_str(), reason],
        )?;
        ensure!(updated == 1, "queued command status changed concurrently");
        Ok(())
    }

    pub fn command_status(
        &self,
        command_id: &str,
    ) -> Result<Option<(CommandStatus, Option<String>)>> {
        let connection = self.connection()?;
        let row: Option<(String, Option<String>)> = connection
            .query_row(
                "SELECT status, status_reason FROM commands WHERE command_id = ?1",
                params![command_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(status, reason)| {
            let status = match status.as_str() {
                "accepted" => CommandStatus::Accepted,
                "deferred" => CommandStatus::Deferred,
                "rejected" => CommandStatus::Rejected,
                "finalized" => CommandStatus::Finalized,
                _ => return Err(anyhow!("command has invalid status `{status}`")),
            };
            Ok((status, reason))
        })
        .transpose()
    }

    pub fn objects(&self) -> Result<BTreeMap<String, StoredObject>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT object_key_hex, object_type, version, value_hash_hex, value_bytes
               FROM objects ORDER BY object_key_hex",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(StoredObject {
                object_key_hex: row.get(0)?,
                object_type: row.get(1)?,
                version: row.get(2)?,
                value_hash_hex: row.get(3)?,
                value_bytes: row.get(4)?,
            })
        })?;
        let mut objects = BTreeMap::new();
        for row in rows {
            let object = row?;
            objects.insert(object.object_key_hex.clone(), object);
        }
        Ok(objects)
    }

    pub fn tip(&self, genesis_hash_hex: &str) -> Result<ChainTip> {
        let connection = self.connection()?;
        let tip = connection
            .query_row(
                "SELECT height, block_hash_hex, timestamp_unix_ms
                   FROM blocks ORDER BY height DESC LIMIT 1",
                [],
                |row| {
                    Ok(ChainTip {
                        height: row.get(0)?,
                        block_hash_hex: row.get(1)?,
                        timestamp_unix_ms: row.get(2)?,
                    })
                },
            )
            .optional()?;
        Ok(tip.unwrap_or(ChainTip {
            height: 0,
            block_hash_hex: genesis_hash_hex.to_string(),
            timestamp_unix_ms: 0,
        }))
    }

    pub fn metrics(&self) -> Result<StoreMetrics> {
        let connection = self.connection()?;
        let command_count = |status: &str| -> Result<u64> {
            connection
                .query_row(
                    "SELECT COUNT(*) FROM commands WHERE status = ?1",
                    params![status],
                    |row| row.get(0),
                )
                .map_err(Into::into)
        };
        Ok(StoreMetrics {
            accepted_commands: command_count("accepted")?,
            deferred_commands: command_count("deferred")?,
            rejected_commands: command_count("rejected")?,
            finalized_commands: command_count("finalized")?,
            objects: connection.query_row("SELECT COUNT(*) FROM objects", [], |row| row.get(0))?,
        })
    }

    pub fn receipt(&self, command_id: &str) -> Result<Option<FinalityReceiptV1>> {
        let connection = self.connection()?;
        let bytes: Option<Vec<u8>> = connection
            .query_row(
                "SELECT receipt_json FROM commands
                  WHERE command_id = ?1 AND status = 'finalized'",
                params![command_id],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
            .transpose()
    }

    pub fn commit_finalized_block(
        &self,
        expected_tip: &ChainTip,
        header: &BlockHeaderV1,
        quorum_certificate: &QuorumCertificateV1,
        commands: &[FinalizedCommand],
    ) -> Result<()> {
        ensure!(
            !commands.is_empty(),
            "cannot commit an empty finalized block"
        );
        ensure!(
            header.height == expected_tip.height.saturating_add(1),
            "prepared block height does not extend expected tip"
        );
        ensure!(
            header.previous_block_hash_hex == expected_tip.block_hash_hex,
            "prepared block previous hash does not extend expected tip"
        );
        ensure!(
            header.height <= i64::MAX as u64,
            "block height exceeds durable range"
        );
        let block_hash_hex = hex::encode(header.block_hash()?);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let current_tip: Option<(u64, String)> = transaction
            .query_row(
                "SELECT height, block_hash_hex FROM blocks ORDER BY height DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (current_height, current_hash) =
            current_tip.unwrap_or((0, expected_tip.block_hash_hex.clone()));
        ensure!(
            current_height == expected_tip.height && current_hash == expected_tip.block_hash_hex,
            "durable chain tip changed while block was being finalized"
        );

        let mut projected_versions = BTreeMap::<String, Option<u64>>::new();
        for finalized in commands {
            let status: Option<String> = transaction
                .query_row(
                    "SELECT status FROM commands WHERE command_id = ?1",
                    params![finalized.command_id],
                    |row| row.get(0),
                )
                .optional()?;
            ensure!(
                matches!(status.as_deref(), Some("accepted" | "deferred")),
                "finalized command is no longer queued"
            );
            ensure!(
                !finalized.mutations.is_empty(),
                "finalized command must contain at least one object mutation"
            );
            for mutation in &finalized.mutations {
                let current_version = match projected_versions.get(&mutation.object_key_hex) {
                    Some(version) => *version,
                    None => transaction
                        .query_row(
                            "SELECT version FROM objects WHERE object_key_hex = ?1",
                            params![mutation.object_key_hex],
                            |row| row.get(0),
                        )
                        .optional()?,
                };
                ensure!(
                    current_version == mutation.expected_version,
                    "object version changed while block was being finalized"
                );
                projected_versions
                    .insert(mutation.object_key_hex.clone(), Some(mutation.next_version));
            }
        }

        transaction.execute(
            "INSERT INTO blocks
             (height, block_hash_hex, previous_block_hash_hex, transaction_root_hex,
              state_root_hex, validator_set_id, timestamp_unix_ms, header_json,
              quorum_certificate_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                header.height as i64,
                block_hash_hex,
                header.previous_block_hash_hex,
                header.transaction_root_hex,
                header.state_root_hex,
                header.validator_set_id,
                header.timestamp_unix_ms as i64,
                serde_json::to_vec(header)?,
                serde_json::to_vec(quorum_certificate)?
            ],
        )?;

        for finalized in commands {
            for mutation in &finalized.mutations {
                let stored = mutation.clone().into_stored();
                transaction.execute(
                    "INSERT INTO objects
                     (object_key_hex, object_type, version, value_hash_hex, value_bytes,
                      updated_at_height)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(object_key_hex) DO UPDATE SET
                        object_type = excluded.object_type,
                        version = excluded.version,
                        value_hash_hex = excluded.value_hash_hex,
                        value_bytes = excluded.value_bytes,
                        updated_at_height = excluded.updated_at_height",
                    params![
                        stored.object_key_hex,
                        stored.object_type,
                        stored.version,
                        stored.value_hash_hex,
                        stored.value_bytes,
                        header.height as i64
                    ],
                )?;
            }
            transaction.execute(
                "UPDATE commands SET
                    status = 'finalized',
                    block_height = ?2,
                    transaction_index = ?3,
                    receipt_json = ?4
                  WHERE command_id = ?1 AND status IN ('accepted', 'deferred')",
                params![
                    finalized.command_id,
                    header.height as i64,
                    finalized.transaction_index as i64,
                    serde_json::to_vec(&finalized.receipt)?
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_db(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "trnm-live-store-{}-{}-{}.sqlite",
            label,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn envelope(command_id: &str, nonce: u64, payload: &[u8]) -> SignedCommandEnvelopeV1 {
        SignedCommandEnvelopeV1::sign(
            "trnm-devnet-test",
            command_id,
            "did:key:hepta",
            "hepta",
            nonce,
            1_000,
            2_000,
            "evaluation_commitment_v1",
            payload,
            &SigningKey::from_bytes(&[3u8; 32]),
        )
        .unwrap()
    }

    #[test]
    fn command_insert_is_idempotent_and_altered_replay_fails_closed() {
        let path = temp_db("idempotency");
        let store = DurableStore::open(&path).unwrap();
        let first = envelope("command-1", 1, b"payload-a");
        assert!(matches!(
            store.insert_command(&first).unwrap(),
            InsertCommandOutcome::Inserted
        ));
        assert!(matches!(
            store.insert_command(&first).unwrap(),
            InsertCommandOutcome::ExistingPending
        ));

        let altered = envelope("command-1", 1, b"payload-b");
        assert!(matches!(
            store.insert_command(&altered).unwrap(),
            InsertCommandOutcome::AlteredReplay
        ));
        let nonce_reuse = envelope("command-2", 1, b"payload-a");
        assert!(matches!(
            store.insert_command(&nonce_reuse).unwrap(),
            InsertCommandOutcome::NonceConflict
        ));
        drop(store);
        let _ = fs::remove_file(path);
    }
}
