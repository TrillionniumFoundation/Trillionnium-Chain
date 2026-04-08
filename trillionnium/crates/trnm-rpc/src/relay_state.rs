use super::*;

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

#[derive(Debug)]
pub(crate) struct RelaySessionState {
    pub(crate) session: RelaySession,
    pub(crate) next_sequence: u64,
    pub(crate) queue: VecDeque<RelayEnvelope>,
    pub(crate) envelope_hashes: Vec<[u8; 32]>,
    pub(crate) acked_ids: BTreeSet<u64>,
    pub(crate) poll_start_idx: usize,
}

impl RelaySessionState {
    pub(crate) fn new(session_id: String) -> Self {
        Self {
            session: RelaySession {
                session_id,
                status: RelaySessionStatus::Open,
                created_at_unix_ms: now_ms(),
                closed_at_unix_ms: None,
            },
            next_sequence: 1,
            queue: VecDeque::new(),
            envelope_hashes: Vec::new(),
            acked_ids: BTreeSet::new(),
            poll_start_idx: 0,
        }
    }

    pub(crate) fn ensure_open(&self) -> Result<()> {
        if self.session.status == RelaySessionStatus::Closed {
            return Err(bad_request(
                "session_closed",
                format!("relay session closed: {}", self.session.session_id),
            ));
        }
        Ok(())
    }

    pub(crate) fn append_envelope(&mut self, envelope: RelayEnvelope) -> Result<()> {
        let hash = hash_envelope(&envelope)?;
        self.queue.push_back(envelope);
        self.envelope_hashes.push(hash);
        Ok(())
    }

    pub(crate) fn advance_poll_start_idx(&mut self) {
        while let Some(env) = self.queue.get(self.poll_start_idx) {
            if self.acked_ids.contains(&env.envelope_id) {
                self.poll_start_idx += 1;
            } else {
                break;
            }
        }
    }
}

impl RelayService {
    fn consume_risk_quota(
        &self,
        domain: RiskDomain,
        session_id: &str,
        source: Option<&str>,
    ) -> Result<()> {
        let source = canonicalize_risk_source(source);
        let mut q = match self.risk_quota.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        q.consume(
            now_ms(),
            domain,
            session_id,
            source.as_str(),
            &self.risk_quota_cfg,
        )
    }

    pub fn query_session_proof(
        &self,
        req: RelaySessionProofQuery,
    ) -> Result<RelaySessionProofResponse> {
        validate_session_id(&req.session_id, "session_id")?;
        if let Err(err) = validate_proof_query_range(req.from_seq, req.to_seq) {
            if err.to_string().contains("bad_request/range_out_of_bounds") {
                self.proof_query_rejected_range_out_of_bounds_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            return Err(err);
        }
        self.consume_risk_quota(RiskDomain::Proof, &req.session_id, req.source.as_deref())?;

        let g = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("relay lock poisoned"))?;
        let Some(state) = g.get(&req.session_id) else {
            return Err(not_found(
                "session_not_found",
                format!("relay session not found: {}", req.session_id),
            ));
        };

        let max_seq = state.next_sequence.saturating_sub(1);
        if req.to_seq > max_seq {
            self.proof_query_rejected_range_out_of_bounds_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(bad_request(
                "range_out_of_bounds",
                format!("to_seq({}) exceeds max sequence({max_seq})", req.to_seq),
            ));
        }

        let messages: Vec<RelayEnvelope> = state
            .queue
            .iter()
            .filter(|e| e.sequence >= req.from_seq && e.sequence <= req.to_seq)
            .cloned()
            .collect();
        let expected_len = (req.to_seq - req.from_seq + 1) as usize;
        if messages.len() != expected_len {
            return Err(anyhow!(
                "session message gap in requested range: expected={} actual={} from_seq={} to_seq={}",
                expected_len,
                messages.len(),
                req.from_seq,
                req.to_seq
            ));
        }

        let start_idx = (req.from_seq - 1) as usize;
        let end_exclusive = req.to_seq as usize;
        if end_exclusive > state.envelope_hashes.len() {
            bail!(
                "session hash cache missing for requested range: to_seq={} available={}",
                req.to_seq,
                state.envelope_hashes.len()
            );
        }
        let leaf_hashes: Vec<[u8; 32]> = state.envelope_hashes[start_idx..end_exclusive].to_vec();
        let (root, proof_paths) = merkle_root_and_proofs(&leaf_hashes);

        let proofs = messages
            .iter()
            .cloned()
            .zip(leaf_hashes.iter())
            .zip(proof_paths.into_iter())
            .enumerate()
            .map(|(i, ((env, leaf_hash), proof))| RelayEnvelopeProof {
                leaf_sequence: env.sequence,
                envelope: env,
                leaf_hash_hex: hex::encode(leaf_hash),
                leaf_index: i,
                proof,
            })
            .collect();

        Ok(RelaySessionProofResponse {
            task_id: req.task_id,
            session_id: req.session_id,
            from_seq: req.from_seq,
            to_seq: req.to_seq,
            segment_root_hex: hex::encode(root),
            range_len: expected_len as u64,
            message_count: expected_len as u32,
            proof_count: expected_len as u32,
            messages,
            proofs,
        })
    }

    pub fn check_challenge_quota(&self, session_id: &str, source: Option<&str>) -> Result<()> {
        validate_session_id(session_id, "session_id")?;
        self.consume_risk_quota(RiskDomain::Challenge, session_id, source)
    }
}

fn is_hex_wrapper_noise(ch: char) -> bool {
    ch.is_whitespace()
        || ch.is_control()
        || matches!(
            ch,
            '\u{200B}'
                | '\u{200C}'
                | '\u{200D}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{202A}'
                | '\u{202B}'
                | '\u{202C}'
                | '\u{202D}'
                | '\u{202E}'
                | '\u{2060}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
                | '\u{FEFF}'
        )
}

fn decode_hex_32(input: &str, field: &str) -> Result<[u8; 32]> {
    let normalized = input.trim_matches(is_hex_wrapper_noise);
    let canonical = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("0X"))
        .unwrap_or(normalized)
        .trim_matches(is_hex_wrapper_noise);
    let bytes = hex::decode(canonical).map_err(|e| anyhow!("invalid {field} hex: {e}"))?;
    if bytes.len() != 32 {
        bail!("{field} must be 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
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
    if resp.range_len != expected_len as u64 {
        bail!("range_len does not match seq range");
    }
    if resp.message_count != resp.messages.len() as u32 {
        bail!("message_count does not match messages length");
    }
    if resp.proof_count != resp.proofs.len() as u32 {
        bail!("proof_count does not match proofs length");
    }
    let total_proof_steps: u32 = resp.proofs.iter().map(|entry| entry.proof.len() as u32).sum();
    if resp.total_proof_steps != total_proof_steps {
        bail!("total_proof_steps does not match proof payload");
    }
    let max_proof_depth = resp
        .proofs
        .iter()
        .map(|entry| entry.proof.len() as u32)
        .max()
        .unwrap_or(0);
    if resp.max_proof_depth != max_proof_depth {
        bail!("max_proof_depth does not match proof payload");
    }

    let expected_root = decode_hex_32(&resp.segment_root_hex, "segment root")?;

    for (i, (msg, p)) in resp.messages.iter().zip(resp.proofs.iter()).enumerate() {
        if msg.session_id != resp.session_id {
            bail!(
                "message session mismatch at index {}: got {}, expected {}",
                i,
                msg.session_id,
                resp.session_id
            );
        }

        let expected_seq = resp.from_seq + i as u64;
        if msg.sequence != expected_seq {
            bail!(
                "message sequence mismatch at index {}: got {}, expected {}",
                i,
                msg.sequence,
                expected_seq
            );
        }
        if p.envelope != *msg {
            bail!("proof envelope mismatch at index {}", i);
        }
        if p.leaf_index != i {
            bail!(
                "proof leaf index mismatch at index {}: got {}",
                i,
                p.leaf_index
            );
        }
        if p.leaf_sequence != expected_seq {
            bail!(
                "proof leaf sequence mismatch at index {}: got {}, expected {}",
                i,
                p.leaf_sequence,
                expected_seq
            );
        }

        let leaf_hash = hash_envelope(msg)?;
        let proof_leaf_hash = decode_hex_32(&p.leaf_hash_hex, "leaf hash")
            .map_err(|e| anyhow!("{e} at index {i}"))?;
        if proof_leaf_hash.as_slice() != leaf_hash.as_slice() {
            bail!("leaf hash mismatch at index {}", i);
        }

        let mut cur = leaf_hash;
        for step in &p.proof {
            let sib_arr = decode_hex_32(&step.sibling_hash_hex, "sibling hash")
                .map_err(|e| anyhow!("{e} at index {i}"))?;
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
