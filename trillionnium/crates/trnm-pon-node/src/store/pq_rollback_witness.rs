//! PNQ2-only rollback guard. The external predecessor, permission reads and
//! local mutations are checked while the same SQLite IMMEDIATE is held.
use super::Node;
use crate::{
    ensure,
    ingress::pq_network::{PqNetworkPolicy, MAX_LEDGER_BYTES, MAX_RECORDS},
    pq_rollback_witness::{
        observe_operation, observe_phase, Checkpoint, WitnessBinding, WitnessClient,
    },
    Result,
};
use rusqlite::{params, types::ValueRef, Connection, Transaction, TransactionBehavior};
use sha2::{Digest, Sha512};
use std::{
    cell::RefMut,
    ops::Deref,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

pub(crate) const KEY: &str = "pq_witness_binding_v1";
pub(crate) const DDL: &str = "CREATE TABLE pq_witness_checkpoint_v1(singleton INTEGER PRIMARY KEY CHECK(singleton=1),sequence INTEGER NOT NULL CHECK(sequence>0),root BLOB NOT NULL CHECK(length(root)=64));";

pub(crate) fn initial_checkpoint(
    policy: &PqNetworkPolicy,
    binding: &WitnessBinding,
) -> Result<Checkpoint> {
    ensure(
        binding.matches_policy(policy.canonical()),
        "PQ_WITNESS_POLICY",
    )?;
    let mut db = Connection::open_in_memory()?;
    db.execute_batch("CREATE TABLE metadata(key TEXT PRIMARY KEY,value BLOB NOT NULL);")?;
    db.execute_batch(super::pq_network::DDL)?;
    db.execute_batch(DDL)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "INSERT INTO metadata VALUES('pq_network_owner_v2',?)",
        [policy.canonical()],
    )?;
    super::pq_network::seed(&tx, policy.canonical())?;
    seed(&tx, binding)?;
    checkpoint(&tx)
}

pub(crate) fn seed(tx: &Transaction<'_>, binding: &WitnessBinding) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata VALUES(?,?)",
        params![KEY, binding.canonical()],
    )?;
    let root = protected_root(tx, binding)?;
    tx.execute(
        "INSERT INTO pq_witness_checkpoint_v1 VALUES(1,1,?)",
        [root.as_slice()],
    )?;
    Ok(())
}

pub(crate) fn checkpoint(db: &Connection) -> Result<Checkpoint> {
    let count: u64 = db.query_row("SELECT COUNT(*) FROM pq_witness_checkpoint_v1", [], |r| {
        r.get(0)
    })?;
    ensure(count == 1, "PQ_WITNESS_LOCAL_CHECKPOINT")?;
    let valid: bool = db.query_row("SELECT typeof(singleton)='integer' AND singleton=1 AND typeof(sequence)='integer' AND sequence>0 AND typeof(root)='blob' AND length(root)=64 FROM pq_witness_checkpoint_v1", [], |r| r.get(0))?;
    ensure(valid, "PQ_WITNESS_LOCAL_WIDTH")?;
    let (sequence, root): (u64, Vec<u8>) = db.query_row(
        "SELECT sequence,root FROM pq_witness_checkpoint_v1 WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Checkpoint::new(
        sequence,
        root.try_into().map_err(|_| "PQ_WITNESS_LOCAL_CHECKPOINT")?,
    )
}

pub(crate) fn protected_root(db: &Connection, binding: &WitnessBinding) -> Result<[u8; 64]> {
    // Widths and storage classes are checked in SQL before any BLOB is copied.
    // DDL CHECKs do not validate an attacker-restored database on their own.
    for (key, expected_len) in [
        (KEY, binding.canonical().len()),
        ("pq_network_owner_v2", binding.policy_length()),
    ] {
        let valid: bool = db.query_row(
            "SELECT typeof(value)='blob' AND length(value)=? FROM metadata WHERE key=?",
            params![expected_len, key],
            |r| r.get(0),
        )?;
        ensure(valid, "PQ_WITNESS_LOCAL_WIDTH")?;
        let value: Vec<u8> =
            db.query_row("SELECT value FROM metadata WHERE key=?", [key], |r| {
                r.get(0)
            })?;
        ensure(
            if key == KEY {
                value == binding.canonical()
            } else {
                binding.matches_policy(&value)
            },
            "PQ_WITNESS_POLICY",
        )?;
    }
    let (records, bytes): (u64, u64) = db.query_row("SELECT COUNT(*),COALESCE(SUM(length(wire)+COALESCE(length(response),0)),0) FROM pq_network_request_v2", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
    ensure(
        records <= MAX_RECORDS && bytes <= MAX_LEDGER_BYTES,
        "PQ_WITNESS_LOCAL_BUDGET",
    )?;
    let peers: u64 = db.query_row("SELECT COUNT(*) FROM pq_network_peer_v2", [], |r| r.get(0))?;
    let resources: u64 = db.query_row("SELECT COUNT(*) FROM pq_network_resource_v2", [], |r| {
        r.get(0)
    })?;
    ensure(peers <= 64 && resources == 1, "PQ_WITNESS_LOCAL_BUDGET")?;
    let bad_requests: u64 = db.query_row("SELECT COUNT(*) FROM pq_network_request_v2 WHERE NOT (typeof(peer)='blob' AND length(peer)=32 AND typeof(sequence)='integer' AND sequence>0 AND typeof(operation)='blob' AND length(operation)=32 AND typeof(wire)='blob' AND length(wire)>=3495 AND length(wire)<=2097152 AND typeof(status)='integer' AND status IN (0,1,2) AND ((status IN (0,2) AND response IS NULL AND response_digest IS NULL) OR (status=1 AND typeof(response)='blob' AND length(response)>=3495 AND length(response)<=2097152 AND typeof(response_digest)='blob' AND length(response_digest)=32)))", [], |r| r.get(0))?;
    let bad_peers: u64 = db.query_row("SELECT COUNT(*) FROM pq_network_peer_v2 WHERE NOT (typeof(peer)='blob' AND length(peer)=32 AND typeof(highest_sequence)='integer' AND highest_sequence>=0 AND typeof(revoked)='integer' AND revoked IN (0,1))", [], |r| r.get(0))?;
    let good_resource: bool = db.query_row("SELECT typeof(singleton)='integer' AND singleton=1 AND typeof(connections)='integer' AND connections BETWEEN 0 AND 64 AND typeof(input_bytes)='integer' AND input_bytes BETWEEN 0 AND 33554432 AND typeof(inbound_verifications)='integer' AND inbound_verifications BETWEEN 0 AND 64 FROM pq_network_resource_v2", [], |r| r.get(0))?;
    ensure(
        bad_requests == 0 && bad_peers == 0 && good_resource,
        "PQ_WITNESS_LOCAL_WIDTH",
    )?;
    let mut hash = Sha512::new();
    hash.update(b"TRNM/PNQ2/protected-owner-tables/v1\0");
    hash.update(binding.id());
    for (table, sql) in [
        ("pq_network_resource_v2", "SELECT singleton,connections,input_bytes,inbound_verifications FROM pq_network_resource_v2 ORDER BY singleton"),
        ("pq_network_peer_v2", "SELECT peer,highest_sequence,revoked FROM pq_network_peer_v2 ORDER BY peer"),
        ("pq_network_request_v2", "SELECT peer,sequence,operation,wire,response,response_digest,status FROM pq_network_request_v2 ORDER BY peer,sequence"),
    ] {
        hash.update((table.len() as u64).to_be_bytes()); hash.update(table.as_bytes());
        let mut statement = db.prepare(sql)?;
        let width = statement.column_count();
        let mut rows = statement.query([])?;
        let mut count = 0_u64;
        while let Some(row) = rows.next()? {
            count += 1; hash.update((width as u64).to_be_bytes());
            for column in 0..width {
                match row.get_ref(column)? {
                    ValueRef::Null => hash.update([0]),
                    ValueRef::Integer(n) => { hash.update([1]); hash.update(n.to_be_bytes()); }
                    ValueRef::Blob(bytes) => { hash.update([2]); hash.update((bytes.len() as u64).to_be_bytes()); hash.update(bytes); }
                    _ => return Err("PQ_WITNESS_LOCAL_WIDTH".into()),
                }
            }
        }
        hash.update(count.to_be_bytes());
    }
    Ok(hash.finalize().into())
}

pub(crate) struct Mutation<'a> {
    tx: Option<Transaction<'a>>,
    client: Option<RefMut<'a, WitnessClient>>,
    previous: Option<Checkpoint>,
    deadline: Option<Instant>,
    epoch: &'a AtomicU64,
}

fn invalidate_failed_client(client: &Option<RefMut<'_, WitnessClient>>, epoch: &AtomicU64) {
    if client
        .as_ref()
        .is_some_and(|client| client.available().is_err())
    {
        // Healthy guarded owners issue only nonzero execution epochs. A failed
        // witness must also cancel work that already obtained Execute, not just
        // refuse its later Finish. Zero avoids wrapping on repeated refusals.
        epoch.store(0, Ordering::Release);
    }
}
impl<'a> Mutation<'a> {
    pub(crate) fn begin(node: &'a Node) -> Result<Self> {
        Self::begin_until(node, None)
    }
    pub(crate) fn begin_until(node: &'a Node, deadline: Option<Instant>) -> Result<Self> {
        observe_operation!(
            observation,
            crate::pq_rollback_witness::test_observation::Kind::MutationBegin,
            {
                let mut client = observe_phase!(
                    observation,
                    MutationBegin,
                    node.pq_witness
                        .as_ref()
                        .map(|client| {
                            client
                                .try_borrow_mut()
                                .map_err(|_| crate::Error::from("PQ_WITNESS_BUSY"))
                        })
                        .transpose()
                )?;
                invalidate_failed_client(&client, &node.pq_network_epoch);
                if let Some(client) = client.as_ref() {
                    client.available()?;
                }
                ensure(node.db.is_autocommit(), "PQ_WITNESS_TRANSACTION")?;
                let tx = observe_phase!(
                    observation,
                    MutationBegin,
                    Transaction::new_unchecked(&node.db, TransactionBehavior::Immediate)
                )?;
                let previous: Result<Option<Checkpoint>> = (|| {
                    let Some(client) = client.as_mut() else {
                        return Ok(None);
                    };
                    // Preserve the client's known-before-send cancellation distinction.
                    let local = match observe_phase!(observation, LocalCheckpoint, checkpoint(&tx))
                    {
                        Ok(local) => local,
                        Err(error) => {
                            client.fail_closed();
                            return Err(error);
                        }
                    };
                    let current =
                        observe_phase!(observation, Current, client.current_until(deadline))?;
                    let verified: Result<Checkpoint> = (|| {
                        ensure(current == local, "PQ_WITNESS_ROLLBACK")?;
                        ensure(
                            observe_phase!(
                                observation,
                                ProtectedRoot,
                                protected_root(&tx, client.binding())
                            )? == local.root,
                            "PQ_WITNESS_LOCAL_ROOT",
                        )?;
                        Ok(local)
                    })();
                    if verified.is_err() {
                        client.fail_closed();
                    }
                    Ok(Some(verified?))
                })();
                // Current or integrity checks may fail before a Mutation is returned.
                invalidate_failed_client(&client, &node.pq_network_epoch);
                let previous = previous?;
                Ok(Self {
                    tx: Some(tx),
                    client,
                    previous,
                    deadline,
                    epoch: &node.pq_network_epoch,
                })
            }
        )
    }
    pub(crate) fn commit(self) -> Result<()> {
        self.commit_with_check(&mut || Ok(()))
    }
    pub(crate) fn commit_with_check(
        mut self,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        observe_operation!(
            observation,
            crate::pq_rollback_witness::test_observation::Kind::MutationCommit,
            {
                #[cfg(test)]
                if let (Some(observation), Some(deadline)) = (observation.as_ref(), self.deadline) {
                    observation.deadlines(Some(deadline), deadline);
                }
                observe_phase!(observation, FinalLiveCheck, check())?;
                if let (Some(client), Some(previous)) = (self.client.as_mut(), self.previous) {
                    let root = observe_phase!(
                        observation,
                        ProtectedRoot,
                        protected_root(
                            self.tx.as_ref().ok_or("PQ_WITNESS_TRANSACTION")?,
                            client.binding(),
                        )
                    )?;
                    if root != previous.root {
                        let next = Checkpoint::new(
                            previous
                                .sequence
                                .checked_add(1)
                                .ok_or("PQ_WITNESS_SEQUENCE")?,
                            root,
                        )?;
                        ensure(self.tx.as_ref().ok_or("PQ_WITNESS_TRANSACTION")?.execute("UPDATE pq_witness_checkpoint_v1 SET sequence=?,root=? WHERE singleton=1 AND sequence=? AND root=?", params![next.sequence, next.root.as_slice(), previous.sequence, previous.root.as_slice()])? == 1, "PQ_WITNESS_LOCAL_CHECKPOINT")?;
                        // Known local cancellation rolls back before sending CAS.
                        observe_phase!(observation, FinalLiveCheck, check())?;
                        observe_phase!(
                            observation,
                            AdvanceCas,
                            client.advance_until(previous, next, self.deadline)
                        )?;
                        // A verified successful external receipt must always be paired
                        // with local commit before reporting any late live-use error.
                        let tx = self.tx.take().ok_or("PQ_WITNESS_TRANSACTION")?;
                        #[cfg(test)]
                        if let Some(observation) = observation.as_ref() {
                            observation.mark(crate::pq_rollback_witness::test_observation::Mark::LocalCommitAttempted);
                        }
                        if let Err(error) = observe_phase!(observation, LocalCommit, tx.commit()) {
                            client.fail_closed();
                            return Err(error.into());
                        }
                        #[cfg(test)]
                        if let Some(observation) = observation.as_ref() {
                            observation.mark(
                                crate::pq_rollback_witness::test_observation::Mark::LocalCommitted,
                            );
                        }
                        return observe_phase!(observation, FinalLiveCheck, check());
                    }
                }
                observe_phase!(observation, FinalLiveCheck, check())?;
                let tx = self.tx.take().ok_or("PQ_WITNESS_TRANSACTION")?;
                #[cfg(test)]
                if let Some(observation) = observation.as_ref() {
                    observation.mark(
                        crate::pq_rollback_witness::test_observation::Mark::LocalCommitAttempted,
                    );
                }
                observe_phase!(observation, LocalCommit, tx.commit())?;
                #[cfg(test)]
                if let Some(observation) = observation.as_ref() {
                    observation
                        .mark(crate::pq_rollback_witness::test_observation::Mark::LocalCommitted);
                }
                observe_phase!(observation, FinalLiveCheck, check())
            }
        )
    }
}
impl Drop for Mutation<'_> {
    fn drop(&mut self) {
        // Covers uncertain CAS and local commit failure on every early return.
        // Known pre-send cancellation leaves the client available and does not
        // invalidate already-authorized work.
        invalidate_failed_client(&self.client, self.epoch);
    }
}
impl Deref for Mutation<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.tx.as_ref().expect("transaction retained until commit")
    }
}

impl Node {
    pub(crate) fn check_pq_witness_open(&self) -> Result<()> {
        if self.pq_witness.is_some() {
            let _guard = Mutation::begin(self)?;
        } else {
            let count: u64 =
                self.db
                    .query_row("SELECT COUNT(*) FROM metadata WHERE key=?", [KEY], |r| {
                        r.get(0)
                    })?;
            ensure(count == 0, "PQ_WITNESS_REQUIRED")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod combined_tests;
