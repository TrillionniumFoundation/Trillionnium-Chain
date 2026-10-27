//! Explicit TPQ1 local authorization owner with durable replay consumption.
//!
//! This separate database/profile is not installed by the legacy Node, changes
//! no PNX1 transaction rules, and grants no model-install or chainwork capability.
//! The caller owns the independently pinned scope, clock and eventual effect.
use std::path::Path;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha384};
use trnm_crypto_primitives::pq_auth::{verify_tpq1, PqAuthError};
use trnm_protocol::pq_frame::{ml_dsa_65_key_id_from_spki, PqFrameExpectation, TPQ1_SIGNED_BYTES};

const APPLICATION_ID: i64 = 0x54505131;
const MAX_PAYLOAD: usize = 1_048_576;

#[derive(Debug)]
pub enum PqOwnerError {
    Scope,
    StoreIdentity,
    Sequence,
    Lifetime,
    Payload,
    Frame,
    Authentication(PqAuthError),
    Storage(rusqlite::Error),
}

impl std::fmt::Display for PqOwnerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "TPQ1 local owner: {self:?}")
    }
}

impl std::error::Error for PqOwnerError {}

impl From<rusqlite::Error> for PqOwnerError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error)
    }
}

/// Independently supplied local authorization policy, never decoded from a request.
pub struct PqAuthorizationScope {
    pub purpose: u8,
    pub network: [u8; 32],
    pub owner_context: [u8; 32],
    pub generation: u64,
    pub max_future_seconds: u64,
    pub public_key_spki: Vec<u8>,
}

/// A local replay-consumption record; not evidence that any external effect ran.
#[derive(Debug, PartialEq, Eq)]
pub struct RecordedPqAuthorization {
    sequence: u64,
    statement_digest: [u8; 48],
}

impl RecordedPqAuthorization {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn statement_digest(&self) -> &[u8; 48] {
        &self.statement_digest
    }
}

pub struct PqAuthorizationOwner {
    database: Connection,
    scope: PqAuthorizationScope,
    key_id: [u8; 32],
}

impl PqAuthorizationOwner {
    /// Open a fresh or identically pinned TPQ1 owner. An existing unrelated SQLite
    /// file and a changed scope are rejected, never silently initialized/reset.
    pub fn open(path: &Path, scope: PqAuthorizationScope) -> Result<Self, PqOwnerError> {
        if !(1..=6).contains(&scope.purpose)
            || scope.network == [0; 32]
            || scope.owner_context == [0; 32]
            || scope.generation == 0
            || !(1..=3600).contains(&scope.max_future_seconds)
        {
            return Err(PqOwnerError::Scope);
        }
        let key_id =
            ml_dsa_65_key_id_from_spki(&scope.public_key_spki).map_err(|_| PqOwnerError::Scope)?;
        let mut commitment = Sha384::new();
        commitment.update(b"TRNM/PoN/TPQ1LocalOwner/v1\0");
        commitment.update([scope.purpose]);
        commitment.update(scope.network);
        commitment.update(scope.owner_context);
        commitment.update(scope.generation.to_be_bytes());
        commitment.update(scope.max_future_seconds.to_be_bytes());
        commitment.update(&scope.public_key_spki);
        let identity: [u8; 48] = commitment.finalize().into();
        let mut database = Connection::open(path)?;
        database.busy_timeout(Duration::from_secs(1))?;
        database.pragma_update(None, "synchronous", "FULL")?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let application: i64 =
            transaction.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let table_count: i64 = transaction.query_row(
            "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        if application == 0 && table_count == 0 {
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.execute_batch(
                "CREATE TABLE pq_owner_v1 (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                 identity BLOB NOT NULL CHECK(length(identity)=48),
                 sequence INTEGER NOT NULL CHECK(sequence>=0));
                 CREATE TABLE pq_authorizations_v1 (sequence INTEGER PRIMARY KEY CHECK(sequence>0),
                 statement BLOB NOT NULL CHECK(length(statement)=176),
                 digest BLOB NOT NULL CHECK(length(digest)=48));",
            )?;
            transaction.execute(
                "INSERT INTO pq_owner_v1 VALUES (1, ?1, 0)",
                [identity.as_slice()],
            )?;
        } else if application != APPLICATION_ID {
            return Err(PqOwnerError::StoreIdentity);
        }
        let pinned: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT identity FROM pq_owner_v1 WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if pinned.as_deref() != Some(identity.as_slice()) {
            return Err(PqOwnerError::StoreIdentity);
        }
        transaction.commit()?;
        Ok(Self {
            database,
            scope,
            key_id,
        })
    }

    /// Verify first, then atomically consume exactly the next operation sequence.
    /// Signature randomness never creates a fresh operation identity. Invalid
    /// messages consume no sequence; a competing successful consume makes a
    /// previously verified request stale. This does not roll back with the chain.
    pub fn record_authorization(
        &mut self,
        frame: &[u8],
        payload: &[u8],
        now: u64,
    ) -> Result<RecordedPqAuthorization, PqOwnerError> {
        if frame.len() != TPQ1_SIGNED_BYTES {
            return Err(PqOwnerError::Frame);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(PqOwnerError::Payload);
        }
        let expires_at = u64::from_be_bytes(frame[120..128].try_into().expect("bounded frame"));
        if expires_at < now || expires_at.saturating_sub(now) > self.scope.max_future_seconds {
            return Err(PqOwnerError::Lifetime);
        }
        let previous: i64 = self.database.query_row(
            "SELECT sequence FROM pq_owner_v1 WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        let next = previous
            .checked_add(1)
            .filter(|value| *value > 0)
            .ok_or(PqOwnerError::Sequence)?;
        let expected = PqFrameExpectation {
            purpose: self.scope.purpose,
            network: self.scope.network,
            owner_context: self.scope.owner_context,
            signer_key_id: self.key_id,
            owner_generation: self.scope.generation,
            operation_sequence: next as u64,
            expires_at,
            now,
            payload,
        };
        let checked = verify_tpq1(frame, &expected, &self.scope.public_key_spki)
            .map_err(PqOwnerError::Authentication)?;
        let mut hash = Sha384::new();
        hash.update(b"TRNM/PoN/TPQ1RecordedStatement/v1\0");
        hash.update(checked.statement());
        let digest: [u8; 48] = hash.finalize().into();
        let transaction = self
            .database
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE pq_owner_v1 SET sequence=?1 WHERE singleton=1 AND sequence=?2",
            params![next, previous],
        )?;
        if changed != 1 {
            return Err(PqOwnerError::Sequence);
        }
        transaction.execute(
            "INSERT INTO pq_authorizations_v1 VALUES (?1, ?2, ?3)",
            params![next, checked.statement(), digest.as_slice()],
        )?;
        transaction.commit()?;
        Ok(RecordedPqAuthorization {
            sequence: next as u64,
            statement_digest: digest,
        })
    }
}

#[cfg(test)]
#[path = "pq_authority_tests.rs"]
mod tests;
