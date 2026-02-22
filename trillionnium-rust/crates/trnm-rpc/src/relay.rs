use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use trnm_types::{RelayEnvelope, RelaySession, RelaySessionStatus};

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn hash_envelope(env: &RelayEnvelope) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(env)?;
    Ok(hash_bytes(&bytes))
}

fn merkle_root_and_proofs(leaves: &[[u8; 32]]) -> ([u8; 32], Vec<Vec<RelayProofStep>>) {
    if leaves.is_empty() {
        return (hash_bytes(&[]), vec![]);
    }

    let mut proofs: Vec<Vec<RelayProofStep>> = vec![Vec::new(); leaves.len()];
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut indexes: Vec<Vec<usize>> = (0..leaves.len()).map(|i| vec![i]).collect();

    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
        let mut next_indexes = Vec::with_capacity(indexes.len().div_ceil(2));

        let mut i = 0usize;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { left };

            for &leaf_idx in &indexes[i] {
                proofs[leaf_idx].push(RelayProofStep {
                    sibling_hash_hex: hex::encode(right),
                    sibling_is_left: false,
                });
            }
            if i + 1 < level.len() {
                for &leaf_idx in &indexes[i + 1] {
                    proofs[leaf_idx].push(RelayProofStep {
                        sibling_hash_hex: hex::encode(left),
                        sibling_is_left: true,
                    });
                }
            }

            next_level.push(hash_pair(&left, &right));
            let mut merged = indexes[i].clone();
            if i + 1 < indexes.len() {
                merged.extend(indexes[i + 1].iter().copied());
            }
            next_indexes.push(merged);
            i += 2;
        }

        level = next_level;
        indexes = next_indexes;
    }

    (level[0], proofs)
}

#[derive(Debug, Clone)]
pub struct RelayOpenRequest {
    pub session_id: String,
}

#[derive(Debug, Clone)]
pub struct RelayOpenResponse {
    pub session: RelaySession,
}

#[derive(Debug, Clone)]
pub struct RelaySendRequest {
    pub session_id: String,
    pub route: String,
    pub from: String,
    pub to: Option<String>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RelaySendResponse {
    pub envelope: RelayEnvelope,
}

#[derive(Debug, Clone)]
pub struct RelayPollRequest {
    pub session_id: String,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct RelayPollResponse {
    pub session_id: String,
    pub envelopes: Vec<RelayEnvelope>,
}

#[derive(Debug, Clone)]
pub struct RelayAckRequest {
    pub session_id: String,
    /// Backward-compatible single/batch ack by envelope id.
    pub envelope_ids: Vec<u64>,
    /// Batch ack by sequence upper-bound (inclusive) within the session.
    pub upto_seq: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct RelayAckResponse {
    pub session_id: String,
    pub acked: usize,
}

#[derive(Debug, Clone)]
pub struct RelayCloseRequest {
    pub session_id: String,
}

#[derive(Debug, Clone)]
pub struct RelayCloseResponse {
    pub session: RelaySession,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelaySessionProofQuery {
    pub task_id: u64,
    pub session_id: String,
    pub from_seq: u64,
    pub to_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayProofStep {
    pub sibling_hash_hex: String,
    pub sibling_is_left: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEnvelopeProof {
    pub envelope: RelayEnvelope,
    pub leaf_hash_hex: String,
    pub leaf_index: usize,
    pub proof: Vec<RelayProofStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelaySessionProofResponse {
    pub task_id: u64,
    pub session_id: String,
    pub from_seq: u64,
    pub to_seq: u64,
    pub segment_root_hex: String,
    pub messages: Vec<RelayEnvelope>,
    pub proofs: Vec<RelayEnvelopeProof>,
}

pub trait RelayHandler: Send + Sync {
    fn handle(&self, envelope: &RelayEnvelope) -> Result<Vec<RelayEnvelope>>;
}

#[derive(Default)]
pub struct RelayRouter {
    handlers: HashMap<String, Arc<dyn RelayHandler>>,
}

impl RelayRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<H>(&mut self, route: impl Into<String>, handler: H)
    where
        H: RelayHandler + 'static,
    {
        self.handlers.insert(route.into(), Arc::new(handler));
    }

    pub fn dispatch(&self, envelope: &RelayEnvelope) -> Result<Vec<RelayEnvelope>> {
        let Some(handler) = self.handlers.get(&envelope.route) else {
            return Ok(vec![]);
        };
        handler.handle(envelope)
    }

    pub fn has_route(&self, route: &str) -> bool {
        self.handlers.contains_key(route)
    }
}

#[derive(Debug)]
struct RelaySessionState {
    session: RelaySession,
    next_sequence: u64,
    queue: VecDeque<RelayEnvelope>,
    acked_ids: BTreeSet<u64>,
}

impl RelaySessionState {
    fn new(session_id: String) -> Self {
        Self {
            session: RelaySession {
                session_id,
                status: RelaySessionStatus::Open,
                created_at_unix_ms: now_ms(),
                closed_at_unix_ms: None,
            },
            next_sequence: 1,
            queue: VecDeque::new(),
            acked_ids: BTreeSet::new(),
        }
    }

    fn ensure_open(&self) -> Result<()> {
        if self.session.status == RelaySessionStatus::Closed {
            bail!("relay session closed: {}", self.session.session_id);
        }
        Ok(())
    }
}

pub struct RelayService {
    sessions: Mutex<HashMap<String, RelaySessionState>>,
    router: RelayRouter,
    envelope_id: AtomicU64,
}

impl RelayService {
    pub fn new(router: RelayRouter) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            router,
            envelope_id: AtomicU64::new(1),
        }
    }

    pub fn open(&self, req: RelayOpenRequest) -> Result<RelayOpenResponse> {
        let mut g = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("relay lock poisoned"))?;
        let state = g
            .entry(req.session_id.clone())
            .or_insert_with(|| RelaySessionState::new(req.session_id));
        if state.session.status == RelaySessionStatus::Closed {
            state.session.status = RelaySessionStatus::Open;
            state.session.closed_at_unix_ms = None;
        }
        Ok(RelayOpenResponse {
            session: state.session.clone(),
        })
    }

    pub fn send(&self, req: RelaySendRequest) -> Result<RelaySendResponse> {
        if !self.router.has_route(&req.route) {
            bail!("route not registered: {}", req.route);
        }

        let mut g = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("relay lock poisoned"))?;
        let Some(state) = g.get_mut(&req.session_id) else {
            bail!("relay session not found: {}", req.session_id);
        };
        state.ensure_open()?;

        let envelope = RelayEnvelope {
            envelope_id: self.envelope_id.fetch_add(1, Ordering::Relaxed),
            session_id: req.session_id.clone(),
            sequence: state.next_sequence,
            route: req.route,
            from: req.from,
            to: req.to,
            payload: req.payload,
            created_at_unix_ms: now_ms(),
        };
        state.next_sequence += 1;
        state.queue.push_back(envelope.clone());

        for mut routed in self.router.dispatch(&envelope)? {
            routed.session_id = envelope.session_id.clone();
            routed.sequence = state.next_sequence;
            if routed.envelope_id == 0 {
                routed.envelope_id = self.envelope_id.fetch_add(1, Ordering::Relaxed);
            }
            if routed.created_at_unix_ms == 0 {
                routed.created_at_unix_ms = now_ms();
            }
            state.next_sequence += 1;
            state.queue.push_back(routed);
        }

        Ok(RelaySendResponse { envelope })
    }

    pub fn poll(&self, req: RelayPollRequest) -> Result<RelayPollResponse> {
        let g = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("relay lock poisoned"))?;
        let Some(state) = g.get(&req.session_id) else {
            bail!("relay session not found: {}", req.session_id);
        };

        let limit = req.limit.max(1);
        let envelopes = state
            .queue
            .iter()
            .filter(|e| !state.acked_ids.contains(&e.envelope_id))
            .take(limit)
            .cloned()
            .collect();
        Ok(RelayPollResponse {
            session_id: req.session_id,
            envelopes,
        })
    }

    pub fn ack(&self, req: RelayAckRequest) -> Result<RelayAckResponse> {
        let mut g = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("relay lock poisoned"))?;
        let Some(state) = g.get_mut(&req.session_id) else {
            bail!("relay session not found: {}", req.session_id);
        };

        let before = state.acked_ids.len();

        // Backward-compatible id ack path: only accept ids that exist in this session queue.
        let known_ids: HashSet<u64> = state.queue.iter().map(|e| e.envelope_id).collect();
        for id in req.envelope_ids {
            if known_ids.contains(&id) {
                state.acked_ids.insert(id);
            }
        }

        // New batch ack path: ack all envelopes in this session whose sequence <= upto_seq.
        if let Some(upto_seq) = req.upto_seq {
            for env in &state.queue {
                if env.sequence <= upto_seq {
                    state.acked_ids.insert(env.envelope_id);
                }
            }
        }

        Ok(RelayAckResponse {
            session_id: req.session_id,
            acked: state.acked_ids.len().saturating_sub(before),
        })
    }

    pub fn query_session_proof(
        &self,
        req: RelaySessionProofQuery,
    ) -> Result<RelaySessionProofResponse> {
        if req.from_seq == 0 {
            bail!("from_seq must be >= 1");
        }
        if req.to_seq < req.from_seq {
            bail!("invalid seq range: from_seq={} to_seq={}", req.from_seq, req.to_seq);
        }

        let g = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("relay lock poisoned"))?;
        let Some(state) = g.get(&req.session_id) else {
            bail!("relay session not found: {}", req.session_id);
        };

        let messages: Vec<RelayEnvelope> = state
            .queue
            .iter()
            .filter(|e| e.sequence >= req.from_seq && e.sequence <= req.to_seq)
            .cloned()
            .collect();

        let mut leaf_hashes = Vec::with_capacity(messages.len());
        for msg in &messages {
            leaf_hashes.push(hash_envelope(msg)?);
        }
        let (root, proofs) = merkle_root_and_proofs(&leaf_hashes);

        let proofs = messages
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, env)| RelayEnvelopeProof {
                envelope: env,
                leaf_hash_hex: hex::encode(leaf_hashes[i]),
                leaf_index: i,
                proof: proofs[i].clone(),
            })
            .collect();

        Ok(RelaySessionProofResponse {
            task_id: req.task_id,
            session_id: req.session_id,
            from_seq: req.from_seq,
            to_seq: req.to_seq,
            segment_root_hex: hex::encode(root),
            messages,
            proofs,
        })
    }

    pub fn close(&self, req: RelayCloseRequest) -> Result<RelayCloseResponse> {
        let mut g = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("relay lock poisoned"))?;
        let Some(state) = g.get_mut(&req.session_id) else {
            bail!("relay session not found: {}", req.session_id);
        };
        state.session.status = RelaySessionStatus::Closed;
        state.session.closed_at_unix_ms = Some(now_ms());

        Ok(RelayCloseResponse {
            session: state.session.clone(),
        })
    }
}

pub fn verify_session_proof(resp: &RelaySessionProofResponse) -> Result<()> {
    if resp.messages.is_empty() || resp.proofs.is_empty() {
        bail!("proof/messages must be non-empty");
    }
    if resp.messages.len() != resp.proofs.len() {
        bail!("proof/messages length mismatch");
    }
    if resp.from_seq > resp.to_seq {
        bail!("invalid seq range in proof response");
    }

    let expected_len = (resp.to_seq - resp.from_seq + 1) as usize;
    if expected_len != resp.messages.len() {
        bail!("seq range does not match message count");
    }

    let expected_root = hex::decode(&resp.segment_root_hex)
        .map_err(|e| anyhow!("invalid segment root hex: {e}"))?;
    if expected_root.len() != 32 {
        bail!("segment root must be 32 bytes");
    }

    for (i, (msg, p)) in resp.messages.iter().zip(resp.proofs.iter()).enumerate() {
        let expected_seq = resp.from_seq + i as u64;
        if msg.sequence != expected_seq {
            bail!("message sequence mismatch at index {}: got {}, expected {}", i, msg.sequence, expected_seq);
        }
        if p.envelope != *msg {
            bail!("proof envelope mismatch at index {}", i);
        }
        if p.leaf_index != i {
            bail!("proof leaf index mismatch at index {}: got {}", i, p.leaf_index);
        }

        let leaf_hash = hash_envelope(msg)?;
        if hex::encode(leaf_hash) != p.leaf_hash_hex {
            bail!("leaf hash mismatch at index {}", i);
        }

        let mut cur = leaf_hash;
        for step in &p.proof {
            let sib = hex::decode(&step.sibling_hash_hex)
                .map_err(|e| anyhow!("invalid sibling hash hex at index {}: {e}", i))?;
            if sib.len() != 32 {
                bail!("invalid sibling hash length at index {}", i);
            }
            let mut sib_arr = [0u8; 32];
            sib_arr.copy_from_slice(&sib);
            cur = if step.sibling_is_left {
                hash_pair(&sib_arr, &cur)
            } else {
                hash_pair(&cur, &sib_arr)
            };
        }

        if cur.as_slice() != expected_root.as_slice() {
            bail!("computed root mismatch at index {}", i);
        }
    }

    Ok(())
}


pub struct EchoHandler;

impl RelayHandler for EchoHandler {
    fn handle(&self, envelope: &RelayEnvelope) -> Result<Vec<RelayEnvelope>> {
        Ok(vec![RelayEnvelope {
            envelope_id: 0,
            session_id: envelope.session_id.clone(),
            sequence: 0,
            route: "relay.echo.reply".to_string(),
            from: envelope.to.clone().unwrap_or_else(|| "relay".to_string()),
            to: Some(envelope.from.clone()),
            payload: envelope.payload.clone(),
            created_at_unix_ms: 0,
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_open_send_poll_ack_close_happy_path() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);

        let opened = relay
            .open(RelayOpenRequest {
                session_id: "s1".to_string(),
            })
            .expect("open");
        assert_eq!(opened.session.status, RelaySessionStatus::Open);

        let sent = relay
            .send(RelaySendRequest {
                session_id: "s1".to_string(),
                route: "relay.echo".to_string(),
                from: "alice".to_string(),
                to: Some("bob".to_string()),
                payload: b"ping".to_vec(),
            })
            .expect("send");
        assert_eq!(sent.envelope.sequence, 1);

        let polled = relay
            .poll(RelayPollRequest {
                session_id: "s1".to_string(),
                limit: 10,
            })
            .expect("poll");
        assert_eq!(polled.envelopes.len(), 2);

        let acked = relay
            .ack(RelayAckRequest {
                session_id: "s1".to_string(),
                envelope_ids: polled.envelopes.iter().map(|e| e.envelope_id).collect(),
                upto_seq: None,
            })
            .expect("ack");
        assert_eq!(acked.acked, 2);

        let polled2 = relay
            .poll(RelayPollRequest {
                session_id: "s1".to_string(),
                limit: 10,
            })
            .expect("poll after ack");
        assert!(polled2.envelopes.is_empty());

        let closed = relay
            .close(RelayCloseRequest {
                session_id: "s1".to_string(),
            })
            .expect("close");
        assert_eq!(closed.session.status, RelaySessionStatus::Closed);
    }

    #[test]
    fn relay_ack_upto_seq_batch_and_boundaries() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay.open(RelayOpenRequest { session_id: "s2".into() }).unwrap();

        relay.send(RelaySendRequest {
            session_id: "s2".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m1".to_vec(),
        }).unwrap();
        relay.send(RelaySendRequest {
            session_id: "s2".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m2".to_vec(),
        }).unwrap();

        // 2 sends + echo => 4 envelopes (seq 1..=4)
        let all = relay.poll(RelayPollRequest { session_id: "s2".into(), limit: 10 }).unwrap();
        assert_eq!(all.envelopes.len(), 4);

        let empty_range = relay.ack(RelayAckRequest {
            session_id: "s2".into(),
            envelope_ids: vec![],
            upto_seq: Some(0),
        }).unwrap();
        assert_eq!(empty_range.acked, 0);

        let first_batch = relay.ack(RelayAckRequest {
            session_id: "s2".into(),
            envelope_ids: vec![],
            upto_seq: Some(2),
        }).unwrap();
        assert_eq!(first_batch.acked, 2);

        let repeat = relay.ack(RelayAckRequest {
            session_id: "s2".into(),
            envelope_ids: vec![],
            upto_seq: Some(2),
        }).unwrap();
        assert_eq!(repeat.acked, 0);

        let overflow = relay.ack(RelayAckRequest {
            session_id: "s2".into(),
            envelope_ids: vec![],
            upto_seq: Some(u64::MAX),
        }).unwrap();
        assert_eq!(overflow.acked, 2);

        let none_left = relay.poll(RelayPollRequest { session_id: "s2".into(), limit: 10 }).unwrap();
        assert!(none_left.envelopes.is_empty());
    }

    #[test]
    fn relay_query_session_proof_returns_messages_root_and_proofs() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "sp1".into(),
            })
            .unwrap();

        relay
            .send(RelaySendRequest {
                session_id: "sp1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"p1".to_vec(),
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "sp1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"p2".to_vec(),
            })
            .unwrap();

        let out = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 42,
                session_id: "sp1".into(),
                from_seq: 2,
                to_seq: 4,
            })
            .unwrap();

        assert_eq!(out.task_id, 42);
        assert_eq!(out.session_id, "sp1");
        assert_eq!(out.messages.len(), 3);
        assert_eq!(out.proofs.len(), 3);
        assert_eq!(out.messages[0].sequence, 2);
        assert_eq!(out.messages[2].sequence, 4);

        // Root should match recompute from the returned message segment.
        let mut leaves = Vec::new();
        for m in &out.messages {
            leaves.push(hash_envelope(m).unwrap());
        }
        let (expect_root, _) = merkle_root_and_proofs(&leaves);
        assert_eq!(out.segment_root_hex, hex::encode(expect_root));

        for (i, p) in out.proofs.iter().enumerate() {
            assert_eq!(p.envelope.sequence, out.messages[i].sequence);
            assert_eq!(p.leaf_index, i);
            assert!(!p.leaf_hash_hex.is_empty());
        }
    }

    #[test]
    fn relay_session_proof_smoke_and_tamper_matrix() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "sp2".into(),
            })
            .unwrap();

        relay
            .send(RelaySendRequest {
                session_id: "sp2".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"m1".to_vec(),
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "sp2".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"m2".to_vec(),
            })
            .unwrap();

        let proof = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 7,
                session_id: "sp2".into(),
                from_seq: 1,
                to_seq: 4,
            })
            .unwrap();

        // smoke: baseline proof verifies
        verify_session_proof(&proof).unwrap();

        // tamper-1: 缺片段（删掉一个 message + proof）
        let mut missing_segment = proof.clone();
        missing_segment.messages.remove(1);
        missing_segment.proofs.remove(1);
        assert!(verify_session_proof(&missing_segment).is_err());

        // tamper-2: 顺序错乱（交换消息次序）
        let mut out_of_order = proof.clone();
        out_of_order.messages.swap(1, 2);
        out_of_order.proofs.swap(1, 2);
        assert!(verify_session_proof(&out_of_order).is_err());

        // tamper-3: 内容篡改（payload 改写）
        let mut content_tampered = proof.clone();
        content_tampered.messages[0].payload = b"tampered".to_vec();
        content_tampered.proofs[0].envelope.payload = b"tampered".to_vec();
        assert!(verify_session_proof(&content_tampered).is_err());

        // tamper-4: root 不匹配
        let mut root_mismatch = proof.clone();
        root_mismatch.segment_root_hex = "00".repeat(32);
        assert!(verify_session_proof(&root_mismatch).is_err());
    }

}
