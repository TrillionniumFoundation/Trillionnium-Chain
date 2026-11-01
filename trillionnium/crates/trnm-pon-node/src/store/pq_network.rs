//! Durable local PQ transport policy/replay ownership. These tables are outside
//! the reorg State and use an incompatible fresh schema, never account authority.
use super::{NativeOwners, Node, StateBackend};
use crate::{
    ensure,
    ingress::pq_network::{
        peer_ids_from_policy_record, PqNetworkPolicy, VerifiedRequest, MAX_INBOUND_VERIFICATIONS,
        MAX_INGRESS_BYTES, MAX_INGRESS_CONNECTIONS, MAX_LEDGER_BYTES, MAX_RECORDS, MAX_WIRE,
    },
    Error, Result, Settings,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use trnm_protocol::pon_wire::{hash, Hash};

pub(crate) const DDL: &str = "
CREATE TABLE pq_network_resource_v2(singleton INTEGER PRIMARY KEY CHECK(singleton=1),connections INTEGER NOT NULL CHECK(connections>=0 AND connections<=64),input_bytes INTEGER NOT NULL CHECK(input_bytes>=0 AND input_bytes<=33554432),inbound_verifications INTEGER NOT NULL CHECK(inbound_verifications>=0 AND inbound_verifications<=64));
CREATE TABLE pq_network_peer_v2(peer BLOB PRIMARY KEY CHECK(length(peer)=32),highest_sequence INTEGER NOT NULL CHECK(highest_sequence>=0),revoked INTEGER NOT NULL CHECK(revoked IN (0,1)));
CREATE TABLE pq_network_request_v2(peer BLOB NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>0),operation BLOB NOT NULL CHECK(length(operation)=32),wire BLOB NOT NULL CHECK(length(wire)>=3495 AND length(wire)<=2097152),response BLOB,response_digest BLOB,status INTEGER NOT NULL CHECK(status IN (0,1,2)),PRIMARY KEY(peer,sequence),FOREIGN KEY(peer) REFERENCES pq_network_peer_v2(peer),CHECK((status IN (0,2) AND response IS NULL AND response_digest IS NULL) OR (status=1 AND response IS NOT NULL AND response_digest IS NOT NULL AND length(response)>=3495 AND length(response)<=2097152 AND length(response_digest)=32)));
";

pub(crate) fn seed(tx: &Transaction<'_>, policy: &[u8]) -> Result<()> {
    tx.execute("INSERT INTO pq_network_resource_v2 VALUES(1,0,0,0)", [])?;
    for peer in peer_ids_from_policy_record(policy)? {
        tx.execute(
            "INSERT INTO pq_network_peer_v2 VALUES(?,0,0)",
            [peer.as_slice()],
        )?;
    }
    Ok(())
}

pub(crate) enum PqReplay {
    Execute(Arc<AtomicU64>, u64),
    Cached(Vec<u8>),
}

type AuditRow = (u64, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, u8);
type ReplayRow = (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, u8);

impl Node {
    /// New native database only; existing legacy/authenticated schemas refuse.
    /// Pins come from the operator, never network bytes. No installed account,
    /// task, mining or FinalUse signer is migrated by this constructor.
    pub fn open_with_pq_network(
        path: &Path,
        settings: Settings,
        workers: usize,
        policy: &PqNetworkPolicy,
    ) -> Result<Self> {
        ensure(policy.matches(&settings), "PQ_NETWORK_CONTEXT")?;
        ensure(
            !super::owner_marker_present(path)?,
            "OWNER_TASK_POLICY_REQUIRED",
        )?;
        let node = Self::open_selected(
            path,
            settings,
            workers,
            None,
            NativeOwners {
                policy: None,
                mining: None,
                continuous: None,
                pq_network: Some(policy.canonical().to_vec()),
            },
            StateBackend::PqNetworkV2,
            false,
        )?;
        node.validate_pq_network_ledger(policy)?;
        Ok(node)
    }

    pub(crate) fn check_pq_network_policy(&self, policy: &PqNetworkPolicy) -> Result<()> {
        self.namespace()?;
        self.storage_context()?;
        ensure(
            matches!(
                self.state_backend,
                StateBackend::PqNetworkV2 | StateBackend::PqContinuousV3
            ) && policy.matches(&self.settings),
            "PQ_NETWORK_BACKEND",
        )?;
        let recorded: Vec<u8> = self.db.query_row(
            "SELECT value FROM metadata WHERE key='pq_network_owner_v2'",
            [],
            |row| row.get(0),
        )?;
        ensure(recorded == policy.canonical(), "PQ_NETWORK_POLICY_REQUIRED")
    }

    fn pq_network_usage(&self) -> Result<(u64, u64)> {
        Ok(self.db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(wire)+CASE WHEN status=0 THEN 2097152 ELSE COALESCE(length(response),0) END),0) FROM pq_network_request_v2",
            [], |row| Ok((row.get(0)?, row.get(1)?)))?)
    }

    pub fn pq_network_status(&self, policy: &PqNetworkPolicy) -> Result<serde_json::Value> {
        self.check_pq_network_policy(policy)?;
        let (records, reserved_bytes) = self.pq_network_usage()?;
        let ingress = self.pq_ingress_usage()?;
        let revoked: u64 = self.db.query_row(
            "SELECT COUNT(*) FROM pq_network_peer_v2 WHERE revoked=1",
            [],
            |row| row.get(0),
        )?;
        Ok(
            serde_json::json!({"profile":crate::ingress::pq_network::PROFILE,
            "policy":hex::encode(policy.id()),"records":records,"reserved_bytes":reserved_bytes,
            "revoked_peers":revoked,"record_limit":MAX_RECORDS,"byte_limit":MAX_LEDGER_BYTES,
            "ingress_connections":ingress.0,"ingress_bytes":ingress.1,"inbound_signature_attempts":ingress.2,
            "ingress_connection_limit":MAX_INGRESS_CONNECTIONS,"ingress_byte_limit":MAX_INGRESS_BYTES,
            "inbound_signature_attempt_limit":MAX_INBOUND_VERIFICATIONS,"transport_confidentiality":false,
            "account_migration":false,
            "imported_transfer_accounts":self.settings.app.is_pq_account_profile(),
            "whole_native_authorization_migrated":false,"production_activation":false}),
        )
    }

    fn pq_ingress_usage(&self) -> Result<(u64, u64, u64)> {
        let result = self.db.query_row("SELECT connections,input_bytes,inbound_verifications FROM pq_network_resource_v2 WHERE singleton=1", [],
            |row| Ok((row.get::<_,u64>(0)?,row.get::<_,u64>(1)?,row.get::<_,u64>(2)?)))?;
        ensure(
            result.0 <= MAX_INGRESS_CONNECTIONS
                && result.1 <= MAX_INGRESS_BYTES
                && result.2 <= MAX_INBOUND_VERIFICATIONS,
            "PQ_NETWORK_RESOURCE_STATE",
        )?;
        Ok(result)
    }
    /// A failed network attempt consumes protected local capacity, never fees
    /// from an unauthenticated claimed account. Reorg and reopen do not refund it.
    pub(crate) fn charge_pq_ingress(
        &mut self,
        policy: &PqNetworkPolicy,
        connection: bool,
        bytes: u64,
        verification: bool,
    ) -> Result<()> {
        self.check_pq_network_policy(policy)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute("UPDATE pq_network_resource_v2 SET connections=connections+?,input_bytes=input_bytes+?,inbound_verifications=inbound_verifications+? WHERE singleton=1 AND connections<=?-? AND input_bytes<=?-? AND inbound_verifications<=?-?",
            params![u64::from(connection), bytes, u64::from(verification),
                MAX_INGRESS_CONNECTIONS,u64::from(connection),MAX_INGRESS_BYTES,bytes,
                MAX_INBOUND_VERIFICATIONS,u64::from(verification)])?;
        ensure(changed == 1, "PQ_NETWORK_INGRESS_BUDGET")?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn validate_pq_network_ledger(&self, policy: &PqNetworkPolicy) -> Result<()> {
        self.check_pq_network_policy(policy)?;
        self.pq_ingress_usage()?;
        let mut statement = self.db.prepare(
            "SELECT peer,highest_sequence,revoked FROM pq_network_peer_v2 ORDER BY peer",
        )?;
        let peers = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure(
            peers.iter().map(|row| row.0.as_slice()).eq(policy
                .peer_ids()
                .collect::<Vec<_>>()
                .iter()
                .map(|p| p.as_slice())),
            "PQ_NETWORK_ROSTER_INTEGRITY",
        )?;
        let (records, bytes) = self.pq_network_usage()?;
        ensure(
            records <= MAX_RECORDS && bytes <= MAX_LEDGER_BYTES,
            "PQ_NETWORK_LEDGER_BUDGET",
        )?;
        for (peer, highest, _) in peers {
            let mut statement = self.db.prepare("SELECT sequence,operation,wire,response,response_digest,status FROM pq_network_request_v2 WHERE peer=? ORDER BY sequence")?;
            let rows: Vec<AuditRow> = statement
                .query_map([peer.as_slice()], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                })?
                .collect::<std::result::Result<_, _>>()?;
            ensure(
                rows.len() as u64 == highest || rows.len() as u64 == highest + 1,
                "PQ_NETWORK_SEQUENCE_INTEGRITY",
            )?;
            for (index, (sequence, operation, wire, response, response_digest, status)) in
                rows.into_iter().enumerate()
            {
                ensure(
                    sequence == index as u64 + 1,
                    "PQ_NETWORK_SEQUENCE_INTEGRITY",
                )?;
                let verified = policy.verify_retained_request(&wire)?;
                ensure(
                    verified.peer.as_slice() == peer
                        && verified.sequence == sequence
                        && verified.operation.as_slice() == operation,
                    "PQ_NETWORK_AUDIT_INTEGRITY",
                )?;
                match (response, response_digest, status) {
                    (Some(response), Some(digest), 1) if sequence <= highest => {
                        ensure(
                            hash(b"native-pq-network-response-bytes-v2", &[&response]).as_slice()
                                == digest,
                            "PQ_NETWORK_RESPONSE_INTEGRITY",
                        )?;
                        policy.verify_response(&response, &verified, verified.expiry)?;
                    }
                    (None, None, 0) if sequence == highest + 1 => {}
                    (None, None, 2) if sequence <= highest => {}
                    _ => return Err(Error::from("PQ_NETWORK_AUDIT_INTEGRITY").local_integrity()),
                }
            }
        }
        Ok(())
    }

    pub(crate) fn begin_pq_network_request(
        &mut self,
        policy: &PqNetworkPolicy,
        request: &VerifiedRequest,
    ) -> Result<PqReplay> {
        self.ready()?;
        self.check_pq_network_policy(policy)?;
        ensure(request.policy == policy.id(), "PQ_NETWORK_CONTEXT")?;
        let (mut highest, revoked): (u64, bool) = self.db.query_row(
            "SELECT highest_sequence,revoked FROM pq_network_peer_v2 WHERE peer=?",
            [request.peer.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        ensure(!revoked, "PQ_NETWORK_REVOKED")?;
        if self.retire_expired_pq_pending(policy, request.peer, highest)? {
            highest += 1;
        }
        ensure(
            request.sequence <= highest.saturating_add(1),
            "PQ_NETWORK_SEQUENCE_GAP",
        )?;
        let existing: Option<ReplayRow> = self.db.query_row(
            "SELECT operation,response,response_digest,status FROM pq_network_request_v2 WHERE peer=? AND sequence=?",
            params![request.peer.as_slice(),request.sequence], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional()?;
        if let Some((operation, response, digest, status)) = existing {
            ensure(
                operation == request.operation,
                "PQ_NETWORK_CONFLICTING_REPLAY",
            )?;
            match (response, digest, status) {
                (Some(response), Some(digest), 1) => {
                    ensure(
                        request.sequence <= highest
                            && hash(b"native-pq-network-response-bytes-v2", &[&response])
                                .as_slice()
                                == digest,
                        "PQ_NETWORK_RESPONSE_INTEGRITY",
                    )?;
                    policy.verify_response(&response, request, request.expiry)?;
                    return Ok(PqReplay::Cached(response));
                }
                (None, None, 0) if request.sequence == highest + 1 => {}
                (None, None, 2) => return Err("PQ_NETWORK_EXPIRED_UNCONFIRMED".into()),
                _ => return Err(Error::from("PQ_NETWORK_AUDIT_INTEGRITY").local_integrity()),
            }
        } else {
            ensure(
                request.sequence == highest + 1,
                "PQ_NETWORK_SEQUENCE_INTEGRITY",
            )?;
            let (count, bytes) = self.pq_network_usage()?;
            let reservation = (request.wire.len() + MAX_WIRE) as u64;
            ensure(
                count < MAX_RECORDS
                    && bytes
                        .checked_add(reservation)
                        .is_some_and(|n| n <= MAX_LEDGER_BYTES),
                "PQ_NETWORK_LEDGER_BUDGET",
            )?;
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "INSERT INTO pq_network_request_v2 VALUES(?,?,?,?,NULL,NULL,0)",
                params![
                    request.peer.as_slice(),
                    request.sequence,
                    request.operation.as_slice(),
                    &request.wire
                ],
            )?;
            tx.commit()?;
        }
        Ok(PqReplay::Execute(
            self.pq_network_epoch.clone(),
            self.pq_network_epoch.load(Ordering::Acquire),
        ))
    }

    pub(crate) fn finish_pq_network_request(
        &mut self,
        policy: &PqNetworkPolicy,
        request: &VerifiedRequest,
        response: &[u8],
        expected_epoch: u64,
    ) -> Result<()> {
        self.check_pq_network_policy(policy)?;
        ensure(
            self.pq_network_epoch.load(Ordering::Acquire) == expected_epoch,
            "PQ_NETWORK_REVOKED",
        )?;
        policy.verify_response(response, request, request.expiry)?;
        ensure(response.len() <= MAX_WIRE, "PQ_NETWORK_WIRE_LIMIT")?;
        let digest = hash(b"native-pq-network-response-bytes-v2", &[response]);
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute("UPDATE pq_network_request_v2 SET response=?,response_digest=?,status=1 WHERE peer=? AND sequence=? AND operation=? AND response IS NULL AND status=0",
            params![response,digest.as_slice(),request.peer.as_slice(),request.sequence,request.operation.as_slice()])?;
        ensure(changed == 1, "PQ_NETWORK_AUDIT_INTEGRITY")?;
        let changed = tx.execute("UPDATE pq_network_peer_v2 SET highest_sequence=? WHERE peer=? AND highest_sequence=? AND revoked=0",
            params![request.sequence,request.peer.as_slice(),request.sequence-1])?;
        ensure(changed == 1, "PQ_NETWORK_SEQUENCE_INTEGRITY")?;
        tx.commit()?;
        Ok(())
    }

    fn retire_expired_pq_pending(
        &mut self,
        policy: &PqNetworkPolicy,
        peer: Hash,
        highest: u64,
    ) -> Result<bool> {
        let pending: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT wire FROM pq_network_request_v2 WHERE peer=? AND sequence=? AND status=0",
                params![peer.as_slice(), highest + 1],
                |row| row.get(0),
            )
            .optional()?;
        let Some(wire) = pending else {
            return Ok(false);
        };
        let old = policy.verify_retained_request(&wire)?;
        ensure(
            old.peer == peer && old.sequence == highest + 1,
            "PQ_NETWORK_AUDIT_INTEGRITY",
        )?;
        if crate::ingress::now()? <= old.expiry {
            return Ok(false);
        }
        let next_epoch = self
            .pq_network_epoch
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or("PQ_NETWORK_EPOCH")?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure(tx.execute("UPDATE pq_network_request_v2 SET status=2 WHERE peer=? AND sequence=? AND status=0",
            params![peer.as_slice(), old.sequence])? == 1, "PQ_NETWORK_AUDIT_INTEGRITY")?;
        ensure(tx.execute("UPDATE pq_network_peer_v2 SET highest_sequence=? WHERE peer=? AND highest_sequence=?",
            params![old.sequence, peer.as_slice(), highest])? == 1, "PQ_NETWORK_SEQUENCE_INTEGRITY")?;
        tx.commit()?;
        // Invalidate any still-running phase before it can acquire the owner
        // and commit under an expired authorization. No effect is rolled back;
        // retirement deliberately means UNCONFIRMED, not 'did not execute'.
        self.pq_network_epoch.store(next_epoch, Ordering::Release);
        Ok(true)
    }

    /// Local operator revocation only. There is no remote request or un-revoke
    /// method; the row and replay ledger are never part of reorganization State.
    pub fn revoke_pq_network_peer(&mut self, policy: &PqNetworkPolicy, peer: Hash) -> Result<()> {
        self.check_pq_network_policy(policy)?;
        let revoked: bool = self.db.query_row(
            "SELECT revoked FROM pq_network_peer_v2 WHERE peer=?",
            [peer.as_slice()],
            |row| row.get(0),
        )?;
        if revoked {
            return Ok(());
        }
        let next = self
            .pq_network_epoch
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or("PQ_NETWORK_EPOCH")?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure(
            tx.execute(
                "UPDATE pq_network_peer_v2 SET revoked=1 WHERE peer=? AND revoked=0",
                [peer.as_slice()],
            )? == 1,
            "PQ_NETWORK_REVOKED",
        )?;
        tx.commit()?;
        self.pq_network_epoch.store(next, Ordering::Release);
        Ok(())
    }
}
