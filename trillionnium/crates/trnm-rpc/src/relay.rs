use anyhow::{anyhow, bail, Result};

const MAX_RELAY_QUERY_LIMIT: usize = 1_000;
const MAX_PROOF_QUERY_SPAN: u64 = 10_000;

fn bad_request(code: &str, detail: impl Into<String>) -> anyhow::Error {
    anyhow!("bad_request/{code}: {}", detail.into())
}

fn not_found(code: &str, detail: impl Into<String>) -> anyhow::Error {
    anyhow!("not_found/{code}: {}", detail.into())
}

fn too_many_requests(code: &str, detail: impl Into<String>) -> anyhow::Error {
    anyhow!("too_many_requests/{code}: {}", detail.into())
}

fn validate_session_id(session_id: &str, field: &str) -> Result<()> {
    if session_id.trim().is_empty() {
        return Err(bad_request(
            "empty_session",
            format!("{field} must be non-empty"),
        ));
    }
    if session_id.trim() != session_id
        || !session_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(bad_request(
            "invalid_session",
            format!("{field} must be canonical"),
        ));
    }
    Ok(())
}

fn validate_route(route: &str) -> Result<()> {
    if route.trim().is_empty() {
        return Err(bad_request("invalid_route", "route must be non-empty"));
    }
    if !route.starts_with("relay.") {
        return Err(bad_request(
            "invalid_route_type",
            format!("route must start with relay.: {route}"),
        ));
    }
    if !route
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(bad_request(
            "invalid_route",
            format!("route contains unsupported chars: {route}"),
        ));
    }
    Ok(())
}

fn validate_proof_query_range(from_seq: u64, to_seq: u64) -> Result<()> {
    if from_seq == 0 {
        return Err(bad_request("invalid_range", "from_seq must be >= 1"));
    }
    if to_seq < from_seq {
        return Err(bad_request(
            "invalid_range",
            format!("from_seq({from_seq}) must be <= to_seq({to_seq})"),
        ));
    }
    let span = to_seq.saturating_sub(from_seq).saturating_add(1);
    if span > MAX_PROOF_QUERY_SPAN {
        return Err(bad_request(
            "range_out_of_bounds",
            format!("requested span {span} exceeds max {MAX_PROOF_QUERY_SPAN}"),
        ));
    }
    Ok(())
}
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
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };

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
    /// Source identity for risk control (e.g. user_id/ip/device).
    /// Defaults to "anon" when omitted.
    pub source: Option<String>,
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
    /// Source identity for risk control (e.g. user_id/ip/device).
    /// Defaults to "anon" when omitted.
    #[serde(default)]
    pub source: Option<String>,
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
    pub leaf_sequence: u64,
    pub proof: Vec<RelayProofStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelaySessionProofResponse {
    pub task_id: u64,
    pub session_id: String,
    pub from_seq: u64,
    pub to_seq: u64,
    pub segment_root_hex: String,
    pub range_len: u64,
    pub message_count: u32,
    pub proof_count: u32,
    pub total_proof_steps: u32,
    pub max_proof_depth: u32,
    pub messages: Vec<RelayEnvelope>,
    pub proofs: Vec<RelayEnvelopeProof>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RiskDomain {
    Relay,
    Proof,
    Challenge,
}

impl RiskDomain {
    fn as_str(self) -> &'static str {
        match self {
            RiskDomain::Relay => "relay",
            RiskDomain::Proof => "proof",
            RiskDomain::Challenge => "challenge",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RiskQuotaConfig {
    pub window_ms: u128,
    pub per_session_limit: u32,
    pub per_source_limit: u32,
}

impl Default for RiskQuotaConfig {
    fn default() -> Self {
        Self {
            window_ms: 1_000,
            per_session_limit: 64,
            per_source_limit: 64,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct WindowCounter {
    window_start_ms: u128,
    used: u32,
}

#[derive(Debug, Clone, Default)]
struct RiskQuotaState {
    by_session: HashMap<(RiskDomain, String), WindowCounter>,
    by_source: HashMap<(RiskDomain, String), WindowCounter>,
}

const MAX_RISK_BUCKET_KEYS_PER_DOMAIN: usize = 4096;

impl RiskQuotaState {
    fn consume(
        &mut self,
        now_ms: u128,
        domain: RiskDomain,
        session_id: &str,
        source: &str,
        cfg: &RiskQuotaConfig,
    ) -> Result<()> {
        Self::consume_bucket(
            &mut self.by_session,
            now_ms,
            domain,
            session_id,
            cfg.window_ms,
            cfg.per_session_limit,
            "session",
        )?;

        if let Err(e) = Self::consume_bucket(
            &mut self.by_source,
            now_ms,
            domain,
            source,
            cfg.window_ms,
            cfg.per_source_limit,
            "source",
        ) {
            // rollback session consumption so two dimensions stay atomic for one request
            Self::rollback_bucket(&mut self.by_session, domain, session_id);
            return Err(e);
        }

        Ok(())
    }

    fn consume_bucket(
        buckets: &mut HashMap<(RiskDomain, String), WindowCounter>,
        now_ms: u128,
        domain: RiskDomain,
        key: &str,
        window_ms: u128,
        limit: u32,
        dim: &str,
    ) -> Result<()> {
        // Misconfigured zero windows effectively disable quota enforcement by expiring
        // every bucket on each consume. Clamp to 1ms so limits stay meaningful.
        let window_ms = window_ms.max(1);
        // Misconfigured zero limits would reject every request (`used >= 0`) and can
        // create a permanent self-inflicted backpressure hotspot. Clamp to 1 so each
        // key always has at least one slot per window.
        let limit = limit.max(1);
        Self::prune_expired_domain_buckets(buckets, now_ms, domain, window_ms);
        let bucket_key = (domain, key.to_string());
        if !buckets.contains_key(&bucket_key)
            && Self::domain_bucket_count(buckets, domain) >= MAX_RISK_BUCKET_KEYS_PER_DOMAIN
        {
            return Err(too_many_requests(
                "quota_exceeded",
                format!(
                    "domain={} dim={} keyspace_exhausted max_keys={} window_ms={}",
                    domain.as_str(),
                    dim,
                    MAX_RISK_BUCKET_KEYS_PER_DOMAIN,
                    window_ms
                ),
            ));
        }

        let bucket = buckets.entry(bucket_key).or_insert_with(|| WindowCounter {
            window_start_ms: now_ms,
            used: 0,
        });

        if now_ms.saturating_sub(bucket.window_start_ms) >= window_ms {
            bucket.window_start_ms = now_ms;
            bucket.used = 0;
        }

        if bucket.used >= limit {
            return Err(too_many_requests(
                "quota_exceeded",
                format!(
                    "domain={} dim={} key={} limit={} window_ms={}",
                    domain.as_str(),
                    dim,
                    elide_risk_error_key(key),
                    limit,
                    window_ms
                ),
            ));
        }
        bucket.used += 1;
        Ok(())
    }

    fn prune_expired_domain_buckets(
        buckets: &mut HashMap<(RiskDomain, String), WindowCounter>,
        now_ms: u128,
        domain: RiskDomain,
        window_ms: u128,
    ) {
        buckets.retain(|(d, _), bucket| {
            if *d != domain {
                return true;
            }
            now_ms.saturating_sub(bucket.window_start_ms) < window_ms
        });
    }

    fn domain_bucket_count(
        buckets: &HashMap<(RiskDomain, String), WindowCounter>,
        domain: RiskDomain,
    ) -> usize {
        buckets.keys().filter(|(d, _)| *d == domain).count()
    }

    fn rollback_bucket(
        buckets: &mut HashMap<(RiskDomain, String), WindowCounter>,
        domain: RiskDomain,
        key: &str,
    ) {
        let bucket_key = (domain, key.to_string());
        let mut should_remove = false;
        if let Some(bucket) = buckets.get_mut(&bucket_key) {
            if bucket.used > 0 {
                bucket.used -= 1;
            }
            should_remove = bucket.used == 0;
        }
        if should_remove {
            buckets.remove(&bucket_key);
        }
    }
}

const RISK_SOURCE_MAX_CHARS: usize = 64;
const RISK_ERROR_KEY_MAX_CHARS: usize = 96;

fn is_disallowed_risk_source_char(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{00A0}'
                | '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{1680}'
                | '\u{180E}'
                | '\u{3164}'
                | '\u{2000}'
                | '\u{2001}'
                | '\u{2002}'
                | '\u{2003}'
                | '\u{2004}'
                | '\u{2005}'
                | '\u{2006}'
                | '\u{2007}'
                | '\u{2008}'
                | '\u{2009}'
                | '\u{200A}'
                | '\u{200B}'
                | '\u{200C}'
                | '\u{200D}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202A}'
                | '\u{202B}'
                | '\u{202C}'
                | '\u{202D}'
                | '\u{202E}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{2800}'
                | '\u{3000}'
                | '\u{2060}'
                | '\u{2061}'
                | '\u{2062}'
                | '\u{2063}'
                | '\u{2064}'
                | '\u{2065}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
                | '\u{206A}'
                | '\u{206B}'
                | '\u{206C}'
                | '\u{206D}'
                | '\u{206E}'
                | '\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'
                | '\u{FFFA}'
                | '\u{FFFB}'
        )
        || ('\u{FE00}'..='\u{FE0F}').contains(&ch)
        || ('\u{E0000}'..='\u{E007F}').contains(&ch)
        || ('\u{E0100}'..='\u{E01EF}').contains(&ch)
}

fn elide_risk_error_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len().min(RISK_ERROR_KEY_MAX_CHARS));
    for ch in key.chars().take(RISK_ERROR_KEY_MAX_CHARS) {
        out.push(ch);
    }
    if key.chars().count() > RISK_ERROR_KEY_MAX_CHARS {
        out.push('…');
    }
    out
}

fn canonicalize_risk_source(source: Option<&str>) -> String {
    fn quote_wrapper_len(source: &str) -> Option<(usize, usize)> {
        const QUOTE_WRAPPERS: [(&str, &str); 7] = [
            ("\"", "\""),
            ("'", "'"),
            ("`", "`"),
            ("“", "”"),
            ("‘", "’"),
            ("«", "»"),
            ("「", "」"),
        ];

        QUOTE_WRAPPERS.iter().find_map(|(open, close)| {
            source
                .starts_with(open)
                .then_some(())
                .filter(|_| source.ends_with(close))
                .map(|_| (open.len(), close.len()))
        })
    }

    let mut source = source.unwrap_or("anon").trim();
    while let Some((prefix_len, suffix_len)) = quote_wrapper_len(source) {
        source = source[prefix_len..source.len() - suffix_len].trim();
    }
    if source.is_empty() {
        return "anon".to_string();
    }

    // Hot-path shortcut: most ingress already carries stable lowercase aliases
    // without whitespace or invisible controls. Reuse the trimmed string directly
    // to avoid per-char writes/allocation churn on quota accounting.
    if source.len() <= RISK_SOURCE_MAX_CHARS
        && source.chars().all(|ch| {
            !ch.is_whitespace() && !ch.is_uppercase() && !is_disallowed_risk_source_char(ch)
        })
    {
        return source.to_string();
    }

    // Collapse internal whitespace/invisible separators so cosmetic or adversarial
    // attribution variants don't explode quota key-space (e.g. "bot  worker",
    // "bot\u{2060}worker", and "bot\u{200B}worker" should share a bucket).
    // Keep this allocation-light: avoid split+collect+join on the hot ingress path.
    let mut out = String::with_capacity(source.len().min(RISK_SOURCE_MAX_CHARS));
    let mut emitted = 0usize;
    let mut pending_space = false;

    for ch in source.chars() {
        if ch.is_whitespace() || is_disallowed_risk_source_char(ch) {
            if emitted > 0 {
                pending_space = true;
            }
            continue;
        }

        if pending_space {
            if emitted >= RISK_SOURCE_MAX_CHARS {
                break;
            }
            out.push(' ');
            emitted += 1;
            pending_space = false;
        }

        for lower in ch.to_lowercase() {
            if emitted >= RISK_SOURCE_MAX_CHARS {
                break;
            }
            out.push(lower);
            emitted += 1;
        }
    }

    if out.is_empty() {
        return "anon".to_string();
    }

    // Bound source cardinality to reduce key-space/memory pressure from adversarial
    // high-entropy attribution strings while preserving stable aliasing semantics.
    out
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
    /// Cache of envelope hash by sequence index (sequence starts from 1).
    envelope_hashes: Vec<[u8; 32]>,
    acked_ids: BTreeSet<u64>,
    poll_start_idx: usize,
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
            envelope_hashes: Vec::new(),
            acked_ids: BTreeSet::new(),
            poll_start_idx: 0,
        }
    }

    fn ensure_open(&self) -> Result<()> {
        if self.session.status == RelaySessionStatus::Closed {
            return Err(bad_request(
                "session_closed",
                format!("relay session closed: {}", self.session.session_id),
            ));
        }
        Ok(())
    }

    fn append_envelope(&mut self, envelope: RelayEnvelope) -> Result<()> {
        let hash = hash_envelope(&envelope)?;
        self.queue.push_back(envelope);
        self.envelope_hashes.push(hash);
        Ok(())
    }

    fn advance_poll_start_idx(&mut self) {
        while let Some(env) = self.queue.get(self.poll_start_idx) {
            if self.acked_ids.remove(&env.envelope_id) {
                self.poll_start_idx += 1;
            } else {
                break;
            }
        }
    }
}

pub struct RelayService {
    sessions: Mutex<HashMap<String, RelaySessionState>>,
    router: RelayRouter,
    envelope_id: AtomicU64,
    risk_quota: Mutex<RiskQuotaState>,
    risk_quota_cfg: RiskQuotaConfig,
    relay_open_total: AtomicU64,
    relay_poll_total: AtomicU64,
    relay_send_rejected_route_not_registered_total: AtomicU64,
    proof_query_rejected_range_out_of_bounds_total: AtomicU64,
}

impl RelayService {
    pub fn new(router: RelayRouter) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            router,
            envelope_id: AtomicU64::new(1),
            risk_quota: Mutex::new(RiskQuotaState::default()),
            risk_quota_cfg: RiskQuotaConfig::default(),
            relay_open_total: AtomicU64::new(0),
            relay_poll_total: AtomicU64::new(0),
            relay_send_rejected_route_not_registered_total: AtomicU64::new(0),
            proof_query_rejected_range_out_of_bounds_total: AtomicU64::new(0),
        }
    }

    pub fn with_risk_quota_config(router: RelayRouter, risk_quota_cfg: RiskQuotaConfig) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            router,
            envelope_id: AtomicU64::new(1),
            risk_quota: Mutex::new(RiskQuotaState::default()),
            risk_quota_cfg,
            relay_open_total: AtomicU64::new(0),
            relay_poll_total: AtomicU64::new(0),
            relay_send_rejected_route_not_registered_total: AtomicU64::new(0),
            proof_query_rejected_range_out_of_bounds_total: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn relay_open_total(&self) -> u64 {
        self.relay_open_total.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn relay_poll_total(&self) -> u64 {
        self.relay_poll_total.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn relay_send_rejected_route_not_registered_total(&self) -> u64 {
        self.relay_send_rejected_route_not_registered_total
            .load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn proof_query_rejected_range_out_of_bounds_total(&self) -> u64 {
        self.proof_query_rejected_range_out_of_bounds_total
            .load(Ordering::Relaxed)
    }

    fn consume_risk_quota(
        &self,
        domain: RiskDomain,
        session_id: &str,
        source: Option<&str>,
    ) -> Result<()> {
        let source = canonicalize_risk_source(source);
        let mut q = match self.risk_quota.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // Best-effort recovery: keep quota enforcement alive after a panicking caller.
                poisoned.into_inner()
            }
        };
        q.consume(
            now_ms(),
            domain,
            session_id,
            source.as_str(),
            &self.risk_quota_cfg,
        )
    }

    pub fn open(&self, req: RelayOpenRequest) -> Result<RelayOpenResponse> {
        validate_session_id(&req.session_id, "session_id")?;
        self.relay_open_total.fetch_add(1, Ordering::Relaxed);
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
        validate_session_id(&req.session_id, "session_id")?;
        validate_route(&req.route)?;
        if !self.router.has_route(&req.route) {
            self.relay_send_rejected_route_not_registered_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(bad_request(
                "invalid_route",
                format!("route not registered: {}", req.route),
            ));
        }
        self.consume_risk_quota(RiskDomain::Relay, &req.session_id, req.source.as_deref())?;

        let mut g = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("relay lock poisoned"))?;
        let Some(state) = g.get_mut(&req.session_id) else {
            return Err(not_found(
                "session_not_found",
                format!("relay session not found: {}", req.session_id),
            ));
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
        state.append_envelope(envelope.clone())?;

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
            state.append_envelope(routed)?;
        }

        Ok(RelaySendResponse { envelope })
    }

    pub fn poll(&self, req: RelayPollRequest) -> Result<RelayPollResponse> {
        validate_session_id(&req.session_id, "session_id")?;
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

        let limit = req.limit.clamp(1, MAX_RELAY_QUERY_LIMIT);
        self.relay_poll_total.fetch_add(1, Ordering::Relaxed);
        let envelopes = state
            .queue
            .iter()
            .skip(state.poll_start_idx)
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
        validate_session_id(&req.session_id, "session_id")?;
        let mut g = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("relay lock poisoned"))?;
        let Some(state) = g.get_mut(&req.session_id) else {
            return Err(not_found(
                "session_not_found",
                format!("relay session not found: {}", req.session_id),
            ));
        };

        let mut acked = 0usize;

        // Backward-compatible id ack path: only accept ids that exist in this session queue.
        // Avoid rebuilding the known-id set when clients use the newer upto_seq-only path,
        // which is common in high-throughput polling loops.
        if !req.envelope_ids.is_empty() {
            let known_ids: HashSet<u64> = state.queue.iter().map(|e| e.envelope_id).collect();
            for id in req.envelope_ids {
                if known_ids.contains(&id) && state.acked_ids.insert(id) {
                    acked += 1;
                }
            }
        }

        // New batch ack path: ack all envelopes in this session whose sequence <= upto_seq.
        if let Some(upto_seq) = req.upto_seq {
            // Queue order is sequence order and advance_poll_start_idx guarantees the
            // prefix before poll_start_idx is already acked. Start from the live poll
            // cursor and stop once we cross the requested range to avoid rescanning
            // long fully-acked prefixes on hot ack loops.
            for env in state.queue.iter().skip(state.poll_start_idx) {
                if env.sequence > upto_seq {
                    break;
                }
                if state.acked_ids.insert(env.envelope_id) {
                    acked += 1;
                }
            }
        }

        state.advance_poll_start_idx();

        Ok(RelayAckResponse {
            session_id: req.session_id,
            acked,
        })
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

        self.consume_risk_quota(RiskDomain::Proof, &req.session_id, req.source.as_deref())?;

        let expected_len = (req.to_seq - req.from_seq + 1) as usize;
        let start_idx = (req.from_seq - 1) as usize;
        let end_exclusive = req.to_seq as usize;
        if end_exclusive > state.queue.len() {
            bail!(
                "session queue missing for requested range: to_seq={} available={}",
                req.to_seq,
                state.queue.len()
            );
        }
        if end_exclusive > state.envelope_hashes.len() {
            bail!(
                "session hash cache missing for requested range: to_seq={} available={}",
                req.to_seq,
                state.envelope_hashes.len()
            );
        }

        let messages: Vec<RelayEnvelope> = state
            .queue
            .iter()
            .skip(start_idx)
            .take(expected_len)
            .cloned()
            .collect();
        for (offset, env) in messages.iter().enumerate() {
            let expected_seq = req.from_seq + offset as u64;
            if env.sequence != expected_seq {
                return Err(anyhow!(
                    "session message gap in requested range: expected_seq={} actual_seq={} from_seq={} to_seq={}",
                    expected_seq,
                    env.sequence,
                    req.from_seq,
                    req.to_seq
                ));
            }
        }

        let leaf_hashes: Vec<[u8; 32]> = state.envelope_hashes[start_idx..end_exclusive].to_vec();
        let (root, proof_paths) = merkle_root_and_proofs(&leaf_hashes);

        let proofs: Vec<RelayEnvelopeProof> = messages
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
        let total_proof_steps = proofs.iter().map(|entry| entry.proof.len() as u32).sum();
        let max_proof_depth = proofs
            .iter()
            .map(|entry| entry.proof.len() as u32)
            .max()
            .unwrap_or(0);

        Ok(RelaySessionProofResponse {
            task_id: req.task_id,
            session_id: req.session_id,
            from_seq: req.from_seq,
            to_seq: req.to_seq,
            segment_root_hex: hex::encode(root),
            range_len: expected_len as u64,
            message_count: expected_len as u32,
            proof_count: expected_len as u32,
            total_proof_steps,
            max_proof_depth,
            messages,
            proofs,
        })
    }

    pub fn check_challenge_quota(&self, session_id: &str, source: Option<&str>) -> Result<()> {
        validate_session_id(session_id, "session_id")?;
        self.consume_risk_quota(RiskDomain::Challenge, session_id, source)
    }

    pub fn close(&self, req: RelayCloseRequest) -> Result<RelayCloseResponse> {
        validate_session_id(&req.session_id, "session_id")?;
        let mut g = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("relay lock poisoned"))?;
        let Some(state) = g.get_mut(&req.session_id) else {
            return Err(not_found(
                "session_not_found",
                format!("relay session not found: {}", req.session_id),
            ));
        };
        state.session.status = RelaySessionStatus::Closed;
        state.session.closed_at_unix_ms = Some(now_ms());

        Ok(RelayCloseResponse {
            session: state.session.clone(),
        })
    }
}

fn is_hex_wrapper_noise(ch: char) -> bool {
    ch.is_whitespace()
        || ch.is_control()
        || matches!(
            ch,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{180B}'
                | '\u{180C}'
                | '\u{180D}'
                | '\u{180E}'
                | '\u{180F}'
                | '\u{200B}'
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
                | '\u{2061}'
                | '\u{2062}'
                | '\u{2063}'
                | '\u{2064}'
                | '\u{2065}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
                | '\u{206A}'
                | '\u{206B}'
                | '\u{206C}'
                | '\u{206D}'
                | '\u{206E}'
                | '\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'
                | '\u{FFFA}'
                | '\u{FFFB}'
        )
        || ('\u{FE00}'..='\u{FE0F}').contains(&ch)
        || ('\u{E0000}'..='\u{E007F}').contains(&ch)
        || ('\u{E0100}'..='\u{E01EF}').contains(&ch)
}

fn decode_hex_32(input: &str, field: &str) -> Result<[u8; 32]> {
    fn quote_wrapper_len(input: &str) -> Option<(usize, usize)> {
        const QUOTE_WRAPPERS: [(&str, &str); 7] = [
            ("\"", "\""),
            ("'", "'"),
            ("`", "`"),
            ("“", "”"),
            ("‘", "’"),
            ("«", "»"),
            ("「", "」"),
        ];

        QUOTE_WRAPPERS.iter().find_map(|(open, close)| {
            input
                .starts_with(open)
                .then_some(())
                .filter(|_| input.ends_with(close))
                .map(|_| (open.len(), close.len()))
        })
    }

    let mut normalized = input.trim_matches(is_hex_wrapper_noise);
    while let Some((prefix_len, suffix_len)) = quote_wrapper_len(normalized) {
        normalized = normalized[prefix_len..normalized.len() - suffix_len]
            .trim_matches(is_hex_wrapper_noise);
    }
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
    let total_proof_steps: u32 = resp
        .proofs
        .iter()
        .map(|entry| entry.proof.len() as u32)
        .sum();
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
        assert_eq!(relay.relay_open_total(), 1);

        let sent = relay
            .send(RelaySendRequest {
                session_id: "s1".to_string(),
                route: "relay.echo".to_string(),
                from: "alice".to_string(),
                to: Some("bob".to_string()),
                payload: b"ping".to_vec(),
                source: None,
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
        assert_eq!(relay.relay_poll_total(), 1);

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
        assert_eq!(relay.relay_poll_total(), 2);

        let closed = relay
            .close(RelayCloseRequest {
                session_id: "s1".to_string(),
            })
            .expect("close");
        assert_eq!(closed.session.status, RelaySessionStatus::Closed);
    }

    #[test]
    fn relay_reopen_closed_session_clears_closed_at_and_accepts_send() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);

        relay
            .open(RelayOpenRequest {
                session_id: "s1-reopen".to_string(),
            })
            .expect("open");

        let closed = relay
            .close(RelayCloseRequest {
                session_id: "s1-reopen".to_string(),
            })
            .expect("close");
        assert_eq!(closed.session.status, RelaySessionStatus::Closed);
        assert!(closed.session.closed_at_unix_ms.is_some());

        let reopened = relay
            .open(RelayOpenRequest {
                session_id: "s1-reopen".to_string(),
            })
            .expect("reopen");
        assert_eq!(reopened.session.status, RelaySessionStatus::Open);
        assert!(reopened.session.closed_at_unix_ms.is_none());

        let sent = relay
            .send(RelaySendRequest {
                session_id: "s1-reopen".to_string(),
                route: "relay.echo".to_string(),
                from: "alice".to_string(),
                to: Some("bob".to_string()),
                payload: b"ping-reopen".to_vec(),
                source: None,
            })
            .expect("send after reopen");
        assert_eq!(sent.envelope.sequence, 1);
    }

    #[test]
    fn relay_ack_upto_seq_batch_and_boundaries() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "s2".into(),
            })
            .unwrap();

        relay
            .send(RelaySendRequest {
                session_id: "s2".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"m1".to_vec(),
                source: None,
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "s2".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"m2".to_vec(),
                source: None,
            })
            .unwrap();

        // 2 sends + echo => 4 envelopes (seq 1..=4)
        let all = relay
            .poll(RelayPollRequest {
                session_id: "s2".into(),
                limit: 10,
            })
            .unwrap();
        assert_eq!(all.envelopes.len(), 4);

        let empty_range = relay
            .ack(RelayAckRequest {
                session_id: "s2".into(),
                envelope_ids: vec![],
                upto_seq: Some(0),
            })
            .unwrap();
        assert_eq!(empty_range.acked, 0);

        let first_batch = relay
            .ack(RelayAckRequest {
                session_id: "s2".into(),
                envelope_ids: vec![],
                upto_seq: Some(2),
            })
            .unwrap();
        assert_eq!(first_batch.acked, 2);

        let repeat = relay
            .ack(RelayAckRequest {
                session_id: "s2".into(),
                envelope_ids: vec![],
                upto_seq: Some(2),
            })
            .unwrap();
        assert_eq!(repeat.acked, 0);

        let overflow = relay
            .ack(RelayAckRequest {
                session_id: "s2".into(),
                envelope_ids: vec![],
                upto_seq: Some(u64::MAX),
            })
            .unwrap();
        assert_eq!(overflow.acked, 2);

        let none_left = relay
            .poll(RelayPollRequest {
                session_id: "s2".into(),
                limit: 10,
            })
            .unwrap();
        assert!(none_left.envelopes.is_empty());
    }

    #[test]
    fn relay_ack_advances_poll_start_index_for_contiguous_acked_prefix() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "s2-cursor".into(),
            })
            .unwrap();

        relay
            .send(RelaySendRequest {
                session_id: "s2-cursor".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"m1".to_vec(),
                source: None,
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "s2-cursor".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"m2".to_vec(),
                source: None,
            })
            .unwrap();

        let batch = relay
            .ack(RelayAckRequest {
                session_id: "s2-cursor".into(),
                envelope_ids: vec![],
                upto_seq: Some(2),
            })
            .unwrap();
        assert_eq!(batch.acked, 2);

        {
            let g = relay.sessions.lock().unwrap();
            let state = g.get("s2-cursor").unwrap();
            assert_eq!(state.poll_start_idx, 2);
            assert!(state.acked_ids.is_empty());
        }

        let pending = relay
            .poll(RelayPollRequest {
                session_id: "s2-cursor".into(),
                limit: 10,
            })
            .unwrap();
        assert_eq!(pending.envelopes.len(), 2);
        assert!(pending.envelopes.iter().all(|e| e.sequence > 2));
    }

    #[test]
    fn relay_ack_upto_seq_respects_poll_cursor_after_prefix_ack() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "s2-cursor-scan".into(),
            })
            .unwrap();

        for payload in [b"m1".as_slice(), b"m2".as_slice(), b"m3".as_slice()] {
            relay
                .send(RelaySendRequest {
                    session_id: "s2-cursor-scan".into(),
                    route: "relay.echo".into(),
                    from: "alice".into(),
                    to: Some("bob".into()),
                    payload: payload.to_vec(),
                    source: None,
                })
                .unwrap();
        }

        let first_two = relay
            .poll(RelayPollRequest {
                session_id: "s2-cursor-scan".into(),
                limit: 2,
            })
            .unwrap();
        assert_eq!(first_two.envelopes.len(), 2);

        let ack_prefix = relay
            .ack(RelayAckRequest {
                session_id: "s2-cursor-scan".into(),
                envelope_ids: first_two.envelopes.iter().map(|e| e.envelope_id).collect(),
                upto_seq: None,
            })
            .unwrap();
        assert_eq!(ack_prefix.acked, 2);

        {
            let g = relay.sessions.lock().unwrap();
            let state = g.get("s2-cursor-scan").unwrap();
            assert_eq!(state.poll_start_idx, 2);
        }

        let ack_through_four = relay
            .ack(RelayAckRequest {
                session_id: "s2-cursor-scan".into(),
                envelope_ids: vec![],
                upto_seq: Some(4),
            })
            .unwrap();
        assert_eq!(ack_through_four.acked, 2);

        let pending = relay
            .poll(RelayPollRequest {
                session_id: "s2-cursor-scan".into(),
                limit: 10,
            })
            .unwrap();
        let pending_seqs: Vec<u64> = pending.envelopes.iter().map(|e| e.sequence).collect();
        assert_eq!(pending_seqs, vec![5, 6]);
    }

    #[test]
    fn relay_session_hash_cache_matches_queue_hashes() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "sp-cache-check".into(),
            })
            .unwrap();

        relay
            .send(RelaySendRequest {
                session_id: "sp-cache-check".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"p1".to_vec(),
                source: None,
            })
            .unwrap();

        let g = relay.sessions.lock().unwrap();
        let state = g.get("sp-cache-check").unwrap();
        assert_eq!(state.queue.len(), state.envelope_hashes.len());
        for (i, env) in state.queue.iter().enumerate() {
            let h = hash_envelope(env).unwrap();
            assert_eq!(h, state.envelope_hashes[i]);
        }
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
                source: None,
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "sp1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"p2".to_vec(),
                source: None,
            })
            .unwrap();

        let out = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 42,
                session_id: "sp1".into(),
                from_seq: 2,
                to_seq: 4,
                source: None,
            })
            .unwrap();

        assert_eq!(out.task_id, 42);
        assert_eq!(out.session_id, "sp1");
        assert_eq!(out.range_len, 3);
        assert_eq!(out.message_count, 3);
        assert_eq!(out.proof_count, 3);
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
                source: None,
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "sp2".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"m2".to_vec(),
                source: None,
            })
            .unwrap();

        let proof = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 7,
                session_id: "sp2".into(),
                from_seq: 1,
                to_seq: 4,
                source: None,
            })
            .unwrap();

        verify_session_proof(&proof).unwrap();

        let mut missing_segment = proof.clone();
        missing_segment.messages.remove(1);
        missing_segment.proofs.remove(1);
        assert!(verify_session_proof(&missing_segment).is_err());

        let mut out_of_order = proof.clone();
        out_of_order.messages.swap(1, 2);
        out_of_order.proofs.swap(1, 2);
        assert!(verify_session_proof(&out_of_order).is_err());

        let mut content_tampered = proof.clone();
        content_tampered.messages[0].payload = b"tampered".to_vec();
        content_tampered.proofs[0].envelope.payload = b"tampered".to_vec();
        assert!(verify_session_proof(&content_tampered).is_err());

        let mut leaf_hash_tampered = proof.clone();
        leaf_hash_tampered.proofs[0].leaf_hash_hex = "ff".repeat(32);
        assert!(verify_session_proof(&leaf_hash_tampered).is_err());

        let mut root_mismatch = proof.clone();
        root_mismatch.segment_root_hex = "00".repeat(32);
        assert!(verify_session_proof(&root_mismatch).is_err());

        let mut range_len_mismatch = proof.clone();
        range_len_mismatch.range_len += 1;
        assert!(verify_session_proof(&range_len_mismatch).is_err());

        let mut message_count_mismatch = proof.clone();
        message_count_mismatch.message_count += 1;
        assert!(verify_session_proof(&message_count_mismatch).is_err());

        let mut proof_count_mismatch = proof.clone();
        proof_count_mismatch.proof_count += 1;
        assert!(verify_session_proof(&proof_count_mismatch).is_err());

        let mut total_steps_mismatch = proof.clone();
        total_steps_mismatch.total_proof_steps += 1;
        assert!(verify_session_proof(&total_steps_mismatch).is_err());

        let mut max_depth_mismatch = proof.clone();
        max_depth_mismatch.max_proof_depth += 1;
        assert!(verify_session_proof(&max_depth_mismatch).is_err());

        let mut session_mismatch = proof.clone();
        session_mismatch.session_id = "sp2-other".to_string();
        assert!(verify_session_proof(&session_mismatch).is_err());
    }

    #[test]
    fn relay_query_session_proof_rejects_noncontiguous_queue_slice() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "sp-gap".into(),
            })
            .unwrap();

        relay
            .send(RelaySendRequest {
                session_id: "sp-gap".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"m1".to_vec(),
                source: None,
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "sp-gap".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"m2".to_vec(),
                source: None,
            })
            .unwrap();

        {
            let mut sessions = relay.sessions.lock().unwrap();
            let state = sessions.get_mut("sp-gap").unwrap();
            state.queue[2].sequence = 99;
        }

        let err = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 8,
                session_id: "sp-gap".into(),
                from_seq: 1,
                to_seq: 4,
                source: None,
            })
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("session message gap in requested range"));
    }

    #[test]
    fn relay_session_proof_accepts_uppercase_leaf_hash_hex() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "sp3".into(),
            })
            .unwrap();

        relay
            .send(RelaySendRequest {
                session_id: "sp3".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"m1".to_vec(),
                source: None,
            })
            .unwrap();

        let mut proof = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 7,
                session_id: "sp3".into(),
                from_seq: 1,
                to_seq: 2,
                source: None,
            })
            .unwrap();

        for entry in proof.proofs.iter_mut() {
            entry.leaf_hash_hex = entry.leaf_hash_hex.to_uppercase();
        }

        verify_session_proof(&proof).unwrap();
    }

    #[test]
    fn relay_session_proof_accepts_0x_prefixed_hash_hex() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "sp3-prefixed".into(),
            })
            .unwrap();

        relay
            .send(RelaySendRequest {
                session_id: "sp3-prefixed".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"m1".to_vec(),
                source: None,
            })
            .unwrap();

        let mut proof = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 7,
                session_id: "sp3-prefixed".into(),
                from_seq: 1,
                to_seq: 2,
                source: None,
            })
            .unwrap();

        proof.segment_root_hex = format!("0x{}", proof.segment_root_hex);
        for entry in proof.proofs.iter_mut() {
            entry.leaf_hash_hex = format!("0X{}", entry.leaf_hash_hex);
            for step in entry.proof.iter_mut() {
                step.sibling_hash_hex = format!("0x{}", step.sibling_hash_hex);
            }
        }

        verify_session_proof(&proof).unwrap();
    }

    #[test]
    fn relay_session_proof_accepts_0x_uppercase_prefixed_hash_hex() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "sp3-prefixed-uppercase".into(),
            })
            .unwrap();

        relay
            .send(RelaySendRequest {
                session_id: "sp3-prefixed-uppercase".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"m1".to_vec(),
                source: None,
            })
            .unwrap();

        let mut proof = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 7,
                session_id: "sp3-prefixed-uppercase".into(),
                from_seq: 1,
                to_seq: 2,
                source: None,
            })
            .unwrap();

        proof.segment_root_hex = format!("0X{}", proof.segment_root_hex.to_uppercase());
        for entry in proof.proofs.iter_mut() {
            entry.leaf_hash_hex = format!("0X{}", entry.leaf_hash_hex.to_uppercase());
            for step in entry.proof.iter_mut() {
                step.sibling_hash_hex = format!("0X{}", step.sibling_hash_hex.to_uppercase());
            }
        }

        verify_session_proof(&proof).unwrap();
    }

    #[test]
    fn relay_session_proof_accepts_hash_hex_wrapped_in_bom_and_bidi_noise() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "sp3-wrapper-noise".into(),
            })
            .unwrap();

        relay
            .send(RelaySendRequest {
                session_id: "sp3-wrapper-noise".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"m1".to_vec(),
                source: None,
            })
            .unwrap();

        let mut proof = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 7,
                session_id: "sp3-wrapper-noise".into(),
                from_seq: 1,
                to_seq: 2,
                source: None,
            })
            .unwrap();

        proof.segment_root_hex = format!("\u{FEFF} 0x{} \u{202E}", proof.segment_root_hex);
        for entry in proof.proofs.iter_mut() {
            entry.leaf_hash_hex = format!("\u{2066}0x{}\u{2069}", entry.leaf_hash_hex);
            for step in entry.proof.iter_mut() {
                step.sibling_hash_hex = format!("\n\u{200F}{}\u{FEFF}\t", step.sibling_hash_hex);
            }
        }

        verify_session_proof(&proof).unwrap();
    }

    #[test]
    fn relay_session_proof_accepts_hash_hex_wrapped_in_annotation_and_tag_noise() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "sp3-annotation-tag-noise".into(),
            })
            .unwrap();

        relay
            .send(RelaySendRequest {
                session_id: "sp3-annotation-tag-noise".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"m1".to_vec(),
                source: None,
            })
            .unwrap();

        let mut proof = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 7,
                session_id: "sp3-annotation-tag-noise".into(),
                from_seq: 1,
                to_seq: 2,
                source: None,
            })
            .unwrap();

        proof.segment_root_hex = format!(
            "\u{FFF9}\u{E0001}0x{}\u{E007F}\u{FFFB}",
            proof.segment_root_hex
        );
        for entry in proof.proofs.iter_mut() {
            entry.leaf_hash_hex = format!(
                "\u{034F}\u{FE0F}{}\u{E0100}",
                entry.leaf_hash_hex.to_uppercase()
            );
            for step in entry.proof.iter_mut() {
                step.sibling_hash_hex = format!(
                    "\u{061C}\u{2061}0X{}\u{2064}\u{180F}",
                    step.sibling_hash_hex.to_uppercase()
                );
            }
        }

        verify_session_proof(&proof).unwrap();
    }

    #[test]
    fn relay_session_proof_accepts_hash_hex_wrapped_in_quotes() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "sp3-quote-noise".into(),
            })
            .unwrap();

        relay
            .send(RelaySendRequest {
                session_id: "sp3-quote-noise".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"m1".to_vec(),
                source: None,
            })
            .unwrap();

        let mut proof = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 7,
                session_id: "sp3-quote-noise".into(),
                from_seq: 1,
                to_seq: 2,
                source: None,
            })
            .unwrap();

        proof.segment_root_hex = format!(" \"0x{}\" ", proof.segment_root_hex);
        for entry in proof.proofs.iter_mut() {
            entry.leaf_hash_hex = format!("“0X{}”", entry.leaf_hash_hex.to_uppercase());
            for step in entry.proof.iter_mut() {
                step.sibling_hash_hex = format!(" 「{}」 ", step.sibling_hash_hex);
            }
        }

        verify_session_proof(&proof).unwrap();
    }

    #[test]
    fn relay_open_rejects_empty_session() {
        let relay = RelayService::new(RelayRouter::new());
        let err = relay
            .open(RelayOpenRequest {
                session_id: "   ".into(),
            })
            .unwrap_err();
        assert!(err.to_string().contains("bad_request/empty_session"));
    }

    #[test]
    fn relay_open_rejects_non_canonical_session_id() {
        let relay = RelayService::new(RelayRouter::new());
        let err = relay
            .open(RelayOpenRequest {
                session_id: " s1\n".into(),
            })
            .unwrap_err();
        assert!(err.to_string().contains("bad_request/invalid_session"));
    }

    #[test]
    fn relay_send_rejects_invalid_route_type() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "s-route".into(),
            })
            .unwrap();

        let err = relay
            .send(RelaySendRequest {
                session_id: "s-route".into(),
                route: "foo/bar".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("bad_request/invalid_route_type"));
    }

    #[test]
    fn relay_send_rejects_unregistered_route_and_counts_metric() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "s-route-missing".into(),
            })
            .unwrap();

        let err = relay
            .send(RelaySendRequest {
                session_id: "s-route-missing".into(),
                route: "relay.unknown".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("bad_request/invalid_route"));
        assert_eq!(relay.relay_send_rejected_route_not_registered_total(), 1);
    }

    #[test]
    fn relay_unregistered_route_rejection_does_not_consume_quota_budget() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::with_risk_quota_config(
            router,
            RiskQuotaConfig {
                window_ms: 1_000,
                per_session_limit: 2,
                per_source_limit: 2,
            },
        );
        relay
            .open(RelayOpenRequest {
                session_id: "s-route-quota".into(),
            })
            .unwrap();

        for _ in 0..3 {
            let err = relay
                .send(RelaySendRequest {
                    session_id: "s-route-quota".into(),
                    route: "relay.unknown".into(),
                    from: "alice".into(),
                    to: Some("bob".into()),
                    payload: b"noise".to_vec(),
                    source: Some("src-route-noise".into()),
                })
                .unwrap_err();
            assert!(err.to_string().contains("bad_request/invalid_route"));
        }

        relay
            .send(RelaySendRequest {
                session_id: "s-route-quota".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"ok-1".to_vec(),
                source: Some("src-route-noise".into()),
            })
            .expect("invalid-route noise should not burn relay quota");
        relay
            .send(RelaySendRequest {
                session_id: "s-route-quota".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"ok-2".to_vec(),
                source: Some("src-route-noise".into()),
            })
            .expect("registered traffic should still use the full configured budget");

        let err = relay
            .send(RelaySendRequest {
                session_id: "s-route-quota".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"ok-3".to_vec(),
                source: Some("src-route-noise".into()),
            })
            .unwrap_err();
        assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
    }

    #[test]
    fn relay_proof_query_rejects_empty_session() {
        let relay = RelayService::new(RelayRouter::new());
        let err = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "".into(),
                from_seq: 1,
                to_seq: 1,
                source: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("bad_request/empty_session"));
    }

    #[test]
    fn relay_proof_query_rejects_session_with_zero_width_space() {
        let relay = RelayService::new(RelayRouter::new());
        let err = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "sp\u{200B}canonical".into(),
                from_seq: 1,
                to_seq: 1,
                source: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("bad_request/invalid_session"));
    }

    #[test]
    fn relay_proof_query_rejects_session_with_word_joiner() {
        let relay = RelayService::new(RelayRouter::new());
        let err = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "sp\u{2060}canonical".into(),
                from_seq: 1,
                to_seq: 1,
                source: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("bad_request/invalid_session"));
    }

    #[test]
    fn relay_proof_query_rejects_reversed_range() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "sp-range".into(),
            })
            .unwrap();

        let err = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "sp-range".into(),
                from_seq: 4,
                to_seq: 2,
                source: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("bad_request/invalid_range"));
    }

    #[test]
    fn relay_proof_query_accepts_exact_max_span() {
        assert!(validate_proof_query_range(1, MAX_PROOF_QUERY_SPAN).is_ok());
        assert!(validate_proof_query_range(41, 40 + MAX_PROOF_QUERY_SPAN).is_ok());
    }

    #[test]
    fn relay_proof_query_rejects_span_overflow() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "sp-span".into(),
            })
            .unwrap();

        let err = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "sp-span".into(),
                from_seq: 1,
                to_seq: MAX_PROOF_QUERY_SPAN + 1,
                source: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("bad_request/range_out_of_bounds"));
        assert_eq!(relay.proof_query_rejected_range_out_of_bounds_total(), 1);
    }

    #[test]
    fn relay_proof_query_rejects_to_seq_out_of_bounds() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "sp-oob".into(),
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "sp-oob".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: None,
            })
            .unwrap();

        let err = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "sp-oob".into(),
                from_seq: 1,
                to_seq: 9,
                source: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("bad_request/range_out_of_bounds"));
        assert_eq!(relay.proof_query_rejected_range_out_of_bounds_total(), 1);
    }

    #[test]
    fn relay_proof_query_rejects_message_gap_in_requested_range() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "sp-gap".into(),
            })
            .unwrap();

        for payload in [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()] {
            relay
                .send(RelaySendRequest {
                    session_id: "sp-gap".into(),
                    route: "relay.echo".into(),
                    from: "alice".into(),
                    to: Some("bob".into()),
                    payload: payload.to_vec(),
                    source: None,
                })
                .unwrap();
        }

        {
            let mut sessions = relay.sessions.lock().expect("relay lock");
            let state = sessions.get_mut("sp-gap").expect("session exists");
            state.queue.retain(|env| env.sequence != 2);
        }

        let err = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "sp-gap".into(),
                from_seq: 1,
                to_seq: 3,
                source: None,
            })
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("session message gap in requested range"),
            "unexpected err: {err}"
        );
    }

    #[test]
    fn relay_poll_clamps_limit() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::new(router);
        relay
            .open(RelayOpenRequest {
                session_id: "sp-limit".into(),
            })
            .unwrap();
        for _ in 0..3 {
            relay
                .send(RelaySendRequest {
                    session_id: "sp-limit".into(),
                    route: "relay.echo".into(),
                    from: "alice".into(),
                    to: Some("bob".into()),
                    payload: b"x".to_vec(),
                    source: None,
                })
                .unwrap();
        }

        let out = relay
            .poll(RelayPollRequest {
                session_id: "sp-limit".into(),
                limit: usize::MAX,
            })
            .unwrap();
        assert_eq!(out.envelopes.len(), 6);
        assert_eq!(relay.relay_poll_total(), 1);
    }

    fn tiny_quota_relay() -> RelayService {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::with_risk_quota_config(
            router,
            RiskQuotaConfig {
                window_ms: 50,
                per_session_limit: 2,
                per_source_limit: 2,
            },
        );
        relay
            .open(RelayOpenRequest {
                session_id: "rq-s1".into(),
            })
            .unwrap();
        relay
            .open(RelayOpenRequest {
                session_id: "rq-s2".into(),
            })
            .unwrap();
        relay
    }

    #[test]
    fn relay_quota_lock_poisoning_recovers_and_still_enforces_limits() {
        let relay = tiny_quota_relay();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = relay.risk_quota.lock().expect("quota lock");
            panic!("intentional poison for resilience test");
        }));

        relay
            .send(RelaySendRequest {
                session_id: "rq-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: Some("src-poison".into()),
            })
            .expect("first post-poison request should recover");
        relay
            .send(RelaySendRequest {
                session_id: "rq-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: Some("src-poison".into()),
            })
            .expect("second post-poison request should recover");

        let err = relay
            .send(RelaySendRequest {
                session_id: "rq-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: Some("src-poison".into()),
            })
            .unwrap_err();
        assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
    }

    #[test]
    fn relay_quota_exceeded_returns_unified_error_code() {
        let relay = tiny_quota_relay();
        for _ in 0..2 {
            relay
                .send(RelaySendRequest {
                    session_id: "rq-s1".into(),
                    route: "relay.echo".into(),
                    from: "alice".into(),
                    to: Some("bob".into()),
                    payload: b"x".to_vec(),
                    source: Some("src-a".into()),
                })
                .unwrap();
        }
        let err = relay
            .send(RelaySendRequest {
                session_id: "rq-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: Some("src-a".into()),
            })
            .unwrap_err();
        assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
    }

    #[test]
    fn relay_quota_resets_after_window() {
        let relay = tiny_quota_relay();
        for _ in 0..2 {
            relay
                .send(RelaySendRequest {
                    session_id: "rq-s1".into(),
                    route: "relay.echo".into(),
                    from: "alice".into(),
                    to: Some("bob".into()),
                    payload: b"x".to_vec(),
                    source: Some("src-b".into()),
                })
                .unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(60));
        relay
            .send(RelaySendRequest {
                session_id: "rq-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: Some("src-b".into()),
            })
            .unwrap();
    }

    #[test]
    fn zero_window_quota_config_is_clamped_to_preserve_enforcement() {
        let mut state = RiskQuotaState::default();
        let cfg = RiskQuotaConfig {
            window_ms: 0,
            per_session_limit: 2,
            per_source_limit: 2,
        };

        state
            .consume(1_000, RiskDomain::Relay, "zw-session", "zw-src", &cfg)
            .unwrap();
        state
            .consume(1_000, RiskDomain::Relay, "zw-session", "zw-src", &cfg)
            .unwrap();

        let err = state
            .consume(1_000, RiskDomain::Relay, "zw-session", "zw-src", &cfg)
            .unwrap_err();
        assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
    }

    #[test]
    fn zero_limits_are_clamped_to_preserve_forward_progress() {
        let mut state = RiskQuotaState::default();
        let cfg = RiskQuotaConfig {
            window_ms: 1_000,
            per_session_limit: 0,
            per_source_limit: 0,
        };

        state
            .consume(1_000, RiskDomain::Relay, "zl-session", "zl-source", &cfg)
            .expect("first request should pass because zero limits are clamped to one slot");

        let err = state
            .consume(1_000, RiskDomain::Relay, "zl-session", "zl-source", &cfg)
            .expect_err("second request in same window should hit clamped quota");
        assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
    }

    #[test]
    fn source_quota_rejection_rolls_back_session_counter_to_avoid_false_backpressure() {
        let mut state = RiskQuotaState::default();
        let cfg = RiskQuotaConfig {
            window_ms: 1_000,
            per_session_limit: 3,
            per_source_limit: 1,
        };

        state
            .consume(1_000, RiskDomain::Relay, "rb-session", "src-a", &cfg)
            .expect("seed consume");

        let err = state
            .consume(1_000, RiskDomain::Relay, "rb-session", "src-a", &cfg)
            .expect_err("second consume should hit per-source quota");
        assert!(err.to_string().contains("too_many_requests/quota_exceeded"));

        // If session usage isn't rolled back on source-quota rejection, the next two
        // distinct sources would exhaust the session quota early and the final consume
        // below would fail with false backpressure.
        state
            .consume(1_000, RiskDomain::Relay, "rb-session", "src-b", &cfg)
            .expect("source-b should pass after rollback");
        state
            .consume(1_000, RiskDomain::Relay, "rb-session", "src-c", &cfg)
            .expect("source-c should pass after rollback");
    }

    #[test]
    fn quota_keyspace_has_domain_cap_with_expired_bucket_pruning() {
        let mut state = RiskQuotaState::default();
        let cfg = RiskQuotaConfig {
            window_ms: 50,
            per_session_limit: u32::MAX,
            per_source_limit: u32::MAX,
        };

        for i in 0..MAX_RISK_BUCKET_KEYS_PER_DOMAIN {
            state
                .consume(
                    1_000,
                    RiskDomain::Relay,
                    "ks-session",
                    &format!("src-{i}"),
                    &cfg,
                )
                .unwrap();
        }

        let err = state
            .consume(1_000, RiskDomain::Relay, "ks-session", "src-over-cap", &cfg)
            .unwrap_err();
        assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
        assert!(err.to_string().contains("keyspace_exhausted"));

        // Once the window moves forward, expired buckets are pruned and new keys are accepted.
        state
            .consume(
                1_100,
                RiskDomain::Relay,
                "ks-session",
                "src-after-window",
                &cfg,
            )
            .unwrap();
    }

    #[test]
    fn relay_quota_isolated_across_sessions() {
        let relay = tiny_quota_relay();
        for _ in 0..2 {
            relay
                .send(RelaySendRequest {
                    session_id: "rq-s1".into(),
                    route: "relay.echo".into(),
                    from: "alice".into(),
                    to: Some("bob".into()),
                    payload: b"x".to_vec(),
                    source: Some("src-c".into()),
                })
                .unwrap();
        }
        relay
            .send(RelaySendRequest {
                session_id: "rq-s2".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: Some("src-d".into()),
            })
            .unwrap();
    }

    #[test]
    fn relay_quota_isolated_across_sources() {
        let relay = tiny_quota_relay();
        relay
            .send(RelaySendRequest {
                session_id: "rq-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: Some("src-e1".into()),
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "rq-s2".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: Some("src-e2".into()),
            })
            .unwrap();
    }

    #[test]
    fn source_attribution_is_canonicalized_for_quota_boundaries() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::with_risk_quota_config(
            router,
            RiskQuotaConfig {
                window_ms: 1_000,
                per_session_limit: 5,
                per_source_limit: 2,
            },
        );
        relay
            .open(RelayOpenRequest {
                session_id: "mv-src-s1".into(),
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "mv-src-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"a".to_vec(),
                source: Some("mv-src".into()),
            })
            .unwrap();

        // Leading/trailing whitespace must not create a fresh source bucket.
        relay
            .send(RelaySendRequest {
                session_id: "mv-src-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"b".to_vec(),
                source: Some("  mv-src  ".into()),
            })
            .unwrap();
        let trimmed_alias_err = relay
            .send(RelaySendRequest {
                session_id: "mv-src-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"c".to_vec(),
                source: Some("mv-src".into()),
            })
            .unwrap_err();
        assert!(trimmed_alias_err
            .to_string()
            .contains("too_many_requests/quota_exceeded"));

        // Blank/whitespace-only attribution should collapse into anon and share one bucket.
        relay
            .send(RelaySendRequest {
                session_id: "mv-src-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"d".to_vec(),
                source: None,
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "mv-src-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"e".to_vec(),
                source: Some("   \t\n".into()),
            })
            .unwrap();
        let anon_alias_err = relay
            .send(RelaySendRequest {
                session_id: "mv-src-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"f".to_vec(),
                source: Some("".into()),
            })
            .unwrap_err();
        assert!(anon_alias_err
            .to_string()
            .contains("too_many_requests/quota_exceeded"));

        // Internal whitespace variants should collapse into the same quota bucket.
        relay
            .open(RelayOpenRequest {
                session_id: "mv-src-s2".into(),
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "mv-src-s2".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"ws-a".to_vec(),
                source: Some("worker   lane".into()),
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "mv-src-s2".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"ws-b".to_vec(),
                source: Some("worker lane".into()),
            })
            .unwrap();
        let ws_alias_err = relay
            .send(RelaySendRequest {
                session_id: "mv-src-s2".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"ws-c".to_vec(),
                source: Some("worker\t\nlane".into()),
            })
            .unwrap_err();
        assert!(ws_alias_err
            .to_string()
            .contains("too_many_requests/quota_exceeded"));

        // Case-only variants must share the same source quota bucket.
        relay
            .open(RelayOpenRequest {
                session_id: "mv-src-s3".into(),
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "mv-src-s3".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"g".to_vec(),
                source: Some("CaseMixSrc".into()),
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "mv-src-s3".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"h".to_vec(),
                source: Some("casemixsrc".into()),
            })
            .unwrap();
        let case_alias_err = relay
            .send(RelaySendRequest {
                session_id: "mv-src-s3".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"i".to_vec(),
                source: Some("CASEMIXSRC".into()),
            })
            .unwrap_err();
        assert!(case_alias_err
            .to_string()
            .contains("too_many_requests/quota_exceeded"));
    }

    #[test]
    fn risk_quota_error_key_is_elided_for_overlong_session_ids() {
        let overlong = "s".repeat(RISK_ERROR_KEY_MAX_CHARS + 32);
        let msg = too_many_requests(
            "quota_exceeded",
            format!(
                "domain={} dim={} key={} limit={} window_ms={}",
                RiskDomain::Relay.as_str(),
                "session",
                elide_risk_error_key(&overlong),
                1,
                1_000
            ),
        )
        .to_string();

        assert!(msg.contains("too_many_requests/quota_exceeded"));
        assert!(msg.contains("key=ss"));
        assert!(msg.contains('…'));
        assert!(!msg.contains(&overlong));
    }

    #[test]
    fn source_attribution_canonicalization_collapses_whitespace_without_trailing_space() {
        let canonical = canonicalize_risk_source(Some("   Bot\t\n Worker   "));
        assert_eq!(canonical, "bot worker");

        // Quoted wrappers should not create distinct quota buckets for the same source alias.
        let canonical_wrapped = canonicalize_risk_source(Some("  \"Bot Worker\"  "));
        assert_eq!(canonical_wrapped, "bot worker");
        let canonical_nested_wrapped = canonicalize_risk_source(Some("  「 Bot Worker 」  "));
        assert_eq!(canonical_nested_wrapped, "bot worker");

        // Non-ASCII whitespace must still collapse even on the lowercase fast path.
        let canonical_nbsp = canonicalize_risk_source(Some("bot\u{00a0}worker"));
        assert_eq!(canonical_nbsp, "bot worker");

        // Braille pattern blank is visually empty and must not split source buckets.
        let canonical_braille_blank = canonicalize_risk_source(Some("bot\u{2800}worker"));
        assert_eq!(canonical_braille_blank, "bot worker");

        // Invisible bidi/format markers must also collapse so sponsor/free-ingress
        // quota accounting can't be split across visually identical aliases.
        let canonical_bidi = canonicalize_risk_source(Some("relay\u{2060}\u{200d}source"));
        assert_eq!(canonical_bidi, "relay source");

        // Tag/BOM/variation-selector noise must also collapse into the same proof
        // attribution bucket instead of creating visually identical aliases.
        let canonical_tag_noise =
            canonicalize_risk_source(Some("proof\u{FEFF}\u{E0020}\u{FE0F}source"));
        assert_eq!(canonical_tag_noise, "proof source");

        // Lowercase/no-whitespace aliases should keep byte shape for hot-path speed.
        assert_eq!(
            canonicalize_risk_source(Some("relay-source-1")),
            "relay-source-1"
        );

        // Non-ASCII uppercase aliases must canonicalize into the same lowercase bucket.
        let canonical_unicode_case = canonicalize_risk_source(Some("İSTANBUL source"));
        assert_eq!(canonical_unicode_case, "i̇stanbul source");

        let exact = "A".repeat(RISK_SOURCE_MAX_CHARS);
        let with_suffix = format!("{}   z", exact);
        // Truncation should not keep a trailing separator when the next token is cut.
        assert_eq!(
            canonicalize_risk_source(Some(&with_suffix)),
            exact.to_ascii_lowercase()
        );
    }

    #[test]
    fn source_attribution_overlong_values_share_truncated_quota_bucket() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::with_risk_quota_config(
            router,
            RiskQuotaConfig {
                window_ms: 1_000,
                per_session_limit: 5,
                per_source_limit: 2,
            },
        );
        relay
            .open(RelayOpenRequest {
                session_id: "mv-src-s3".into(),
            })
            .unwrap();

        let prefix = "X".repeat(RISK_SOURCE_MAX_CHARS);
        let src_a = format!("{}-A", prefix);
        let src_b = format!("{}-B", prefix);

        relay
            .send(RelaySendRequest {
                session_id: "mv-src-s3".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"a".to_vec(),
                source: Some(src_a),
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "mv-src-s3".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"b".to_vec(),
                source: Some(src_b),
            })
            .unwrap();

        let err = relay
            .send(RelaySendRequest {
                session_id: "mv-src-s3".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"c".to_vec(),
                source: Some(format!("{}-C", prefix)),
            })
            .unwrap_err();
        assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
    }

    #[test]
    fn proof_quota_exceeded_has_same_error_code() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::with_risk_quota_config(
            router,
            RiskQuotaConfig {
                window_ms: 1_000,
                per_session_limit: 2,
                per_source_limit: 2,
            },
        );
        relay
            .open(RelayOpenRequest {
                session_id: "proof-s1".into(),
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "proof-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: Some("proof-src".into()),
            })
            .unwrap();

        for _ in 0..2 {
            relay
                .query_session_proof(RelaySessionProofQuery {
                    task_id: 1,
                    session_id: "proof-s1".into(),
                    from_seq: 1,
                    to_seq: 1,
                    source: Some("proof-src".into()),
                })
                .unwrap();
        }
        let err = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "proof-s1".into(),
                from_seq: 1,
                to_seq: 1,
                source: Some("proof-src".into()),
            })
            .unwrap_err();
        assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
    }

    #[test]
    fn out_of_bounds_proof_query_does_not_consume_quota_budget() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::with_risk_quota_config(
            router,
            RiskQuotaConfig {
                window_ms: 1_000,
                per_session_limit: 2,
                per_source_limit: 2,
            },
        );
        relay
            .open(RelayOpenRequest {
                session_id: "proof-oob-budget".into(),
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "proof-oob-budget".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: Some("proof-src".into()),
            })
            .unwrap();

        for _ in 0..3 {
            let err = relay
                .query_session_proof(RelaySessionProofQuery {
                    task_id: 1,
                    session_id: "proof-oob-budget".into(),
                    from_seq: 1,
                    to_seq: 9,
                    source: Some("proof-src".into()),
                })
                .unwrap_err();
            assert!(err.to_string().contains("bad_request/range_out_of_bounds"));
        }

        relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "proof-oob-budget".into(),
                from_seq: 1,
                to_seq: 1,
                source: Some("proof-src".into()),
            })
            .expect("out-of-bounds requests should not burn proof quota budget");

        relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "proof-oob-budget".into(),
                from_seq: 1,
                to_seq: 1,
                source: Some("proof-src".into()),
            })
            .expect("full proof quota budget should remain available after rejected oob requests");

        let err = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "proof-oob-budget".into(),
                from_seq: 1,
                to_seq: 1,
                source: Some("proof-src".into()),
            })
            .unwrap_err();
        assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
    }

    #[test]
    fn zero_from_seq_proof_query_does_not_consume_quota_budget() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::with_risk_quota_config(
            router,
            RiskQuotaConfig {
                window_ms: 1_000,
                per_session_limit: 2,
                per_source_limit: 2,
            },
        );
        relay
            .open(RelayOpenRequest {
                session_id: "proof-zero-budget".into(),
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "proof-zero-budget".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: Some("proof-src".into()),
            })
            .unwrap();

        for _ in 0..3 {
            let err = relay
                .query_session_proof(RelaySessionProofQuery {
                    task_id: 1,
                    session_id: "proof-zero-budget".into(),
                    from_seq: 0,
                    to_seq: 1,
                    source: Some("proof-src".into()),
                })
                .unwrap_err();
            assert!(err.to_string().contains("bad_request/invalid_range"));
        }

        relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "proof-zero-budget".into(),
                from_seq: 1,
                to_seq: 1,
                source: Some("proof-src".into()),
            })
            .expect("zero from_seq requests should not burn proof quota budget");

        relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "proof-zero-budget".into(),
                from_seq: 1,
                to_seq: 1,
                source: Some("proof-src".into()),
            })
            .expect(
                "full proof quota budget should remain available after rejected zero-from requests",
            );

        let err = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "proof-zero-budget".into(),
                from_seq: 1,
                to_seq: 1,
                source: Some("proof-src".into()),
            })
            .unwrap_err();
        assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
    }

    #[test]
    fn proof_quota_source_attribution_aliases_share_boundary() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::with_risk_quota_config(
            router,
            RiskQuotaConfig {
                window_ms: 1_000,
                per_session_limit: 6,
                per_source_limit: 2,
            },
        );
        relay
            .open(RelayOpenRequest {
                session_id: "proof-src-s1".into(),
            })
            .unwrap();
        relay
            .send(RelaySendRequest {
                session_id: "proof-src-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: Some("seed".into()),
            })
            .unwrap();

        relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "proof-src-s1".into(),
                from_seq: 1,
                to_seq: 1,
                source: Some("proof-src".into()),
            })
            .unwrap();
        relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "proof-src-s1".into(),
                from_seq: 1,
                to_seq: 1,
                source: Some("  proof-src  ".into()),
            })
            .unwrap();
        let trimmed_alias_err = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "proof-src-s1".into(),
                from_seq: 1,
                to_seq: 1,
                source: Some("proof-src".into()),
            })
            .unwrap_err();
        assert!(trimmed_alias_err
            .to_string()
            .contains("too_many_requests/quota_exceeded"));

        relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "proof-src-s1".into(),
                from_seq: 1,
                to_seq: 1,
                source: None,
            })
            .unwrap();
        relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "proof-src-s1".into(),
                from_seq: 1,
                to_seq: 1,
                source: Some("\t \n".into()),
            })
            .unwrap();
        let anon_alias_err = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "proof-src-s1".into(),
                from_seq: 1,
                to_seq: 1,
                source: Some("".into()),
            })
            .unwrap_err();
        assert!(anon_alias_err
            .to_string()
            .contains("too_many_requests/quota_exceeded"));
    }

    #[test]
    fn relay_and_proof_quota_are_isolated_by_domain() {
        let mut router = RelayRouter::new();
        router.register("relay.echo", EchoHandler);
        let relay = RelayService::with_risk_quota_config(
            router,
            RiskQuotaConfig {
                window_ms: 1_000,
                per_session_limit: 2,
                per_source_limit: 2,
            },
        );
        relay
            .open(RelayOpenRequest {
                session_id: "mv-s1".into(),
            })
            .unwrap();

        relay
            .send(RelaySendRequest {
                session_id: "mv-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"lane-mv-a".to_vec(),
                source: Some("mv-src".into()),
            })
            .unwrap();

        // Proof quota and relay quota are tracked independently: proof request succeeds
        // even after relay domain already consumed part of its own budget.
        relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 7,
                session_id: "mv-s1".into(),
                from_seq: 1,
                to_seq: 1,
                source: Some("mv-src".into()),
            })
            .unwrap();

        relay
            .send(RelaySendRequest {
                session_id: "mv-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"lane-mv-b".to_vec(),
                source: Some("mv-src".into()),
            })
            .unwrap();

        relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 7,
                session_id: "mv-s1".into(),
                from_seq: 1,
                to_seq: 2,
                source: Some("mv-src".into()),
            })
            .unwrap();

        let proof_err = relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 7,
                session_id: "mv-s1".into(),
                from_seq: 1,
                to_seq: 2,
                source: Some("mv-src".into()),
            })
            .unwrap_err();
        assert!(proof_err
            .to_string()
            .contains("too_many_requests/quota_exceeded"));

        let relay_err = relay
            .send(RelaySendRequest {
                session_id: "mv-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"lane-mv-c".to_vec(),
                source: Some("mv-src".into()),
            })
            .unwrap_err();
        assert!(relay_err
            .to_string()
            .contains("too_many_requests/quota_exceeded"));
    }

    #[test]
    fn challenge_quota_uses_same_limiter_and_error_code() {
        let relay = RelayService::with_risk_quota_config(
            RelayRouter::new(),
            RiskQuotaConfig {
                window_ms: 1_000,
                per_session_limit: 1,
                per_source_limit: 1,
            },
        );
        relay
            .check_challenge_quota("c-s1", Some("challenger-a"))
            .unwrap();
        let err = relay
            .check_challenge_quota("c-s1", Some("challenger-a"))
            .unwrap_err();
        assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
    }
}
