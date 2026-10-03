//! Local bounded queued facts, under the existing Node SQLite/lock owner. Neither
//! typed admission nor this queue grants block execution, inclusion or confirmation.
use super::{bytes32, ensure, Node};
use crate::Result;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use trnm_mempool::{
    AdmissionReject, CanonicalSignerId, CanonicalTxDigest, IngressClass, ResourceLimits,
    SignedAdmissionHooks, SignedEnvelopeMetadata, SignedEnvelopeView, TypedAdmissionGate,
    TypedAdmitOutcome,
};
use trnm_mvcc_fee::pon_commitment::{
    CacheLimits, CheckedExecutionParent, CommitmentObservation, ExecutionRequest,
};
use trnm_mvcc_fee::pon_executor::{
    self, Config, ExecutionControl, ExecutionError, ExecutionProgress, ExecutionWorkerAccounting,
    State,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

pub const LOCAL_POOL_PROFILE: &str = "native-local-queued-pnx1-v2";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolLimits {
    pub max_records: usize,
    pub max_bytes: usize,
    pub max_group_members: usize,
    pub critical_reserve: usize,
    pub max_removals: usize,
    pub preview_miner: Hash,
}
impl PoolLimits {
    fn validate(&self) -> Result<()> {
        ensure(
            (1..=256).contains(&self.max_records)
                && (1..=524288).contains(&self.max_bytes)
                && (1..=16).contains(&self.max_group_members)
                && self.max_group_members <= self.max_records
                && self.critical_reserve < self.max_records
                && (1..=4096).contains(&self.max_removals)
                && self.preview_miner != [0; 32],
            "POOL_LIMITS",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum PoolState {
    Queued,
    SequenceConsumed,
    Expired,
    Blocked,
}
impl PoolState {
    fn code(&self) -> u8 {
        match self {
            Self::Queued => 0,
            Self::SequenceConsumed => 1,
            Self::Expired => 2,
            Self::Blocked => 3,
        }
    }
    fn decode(code: u8) -> Result<Self> {
        match code {
            0 => Ok(Self::Queued),
            1 => Ok(Self::SequenceConsumed),
            2 => Ok(Self::Expired),
            3 => Ok(Self::Blocked),
            _ => Err("POOL_STATE".into()),
        }
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct PoolGroupStatus {
    pub group: String,
    pub digests: Vec<String>,
    pub state: PoolState,
    pub reason: String,
    pub raw_bytes: usize,
}
/// Fixed-size local diagnostics for cache eviction, never a revocation or finality proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PoolGcSummary {
    pub evicted_groups: u64,
    pub evicted_records: u64,
    pub evicted_raw_bytes: u64,
    pub history_head: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct PoolStatus {
    pub profile: &'static str,
    pub context: String,
    pub parent: String,
    pub generation: u64,
    pub checked_parent: Option<String>,
    pub checked_generation: Option<u64>,
    pub classification_current: bool,
    pub retained_records: usize,
    pub retained_bytes: usize,
    pub local_removals: usize,
    pub gc: PoolGcSummary,
    pub groups: Vec<PoolGroupStatus>,
    pub scope: &'static str,
}
#[derive(Debug, Clone, Serialize)]
pub struct PoolReceipt {
    pub group: String,
    pub duplicate: bool,
    pub state: PoolState,
    /// Total reconstructed pending-prefix admissions, not just submitted members.
    pub typed_gate_admissions: usize,
    /// Total metadata popped from that actual M05 prefix queue.
    pub typed_gate_ready_metadata: usize,
    pub scope: &'static str,
}
#[derive(Debug, Clone)]
pub struct PoolBatch {
    pub parent: Hash,
    pub generation: u64,
    pub context: Hash,
    pub preview_miner: Hash,
    pub transactions: Vec<Vec<u8>>,
    pub groups: Vec<Hash>,
    pub typed_gate_admissions: usize,
}

struct Row {
    digest: Hash,
    sender: Hash,
    nonce: u64,
    expiry: u64,
    raw: Vec<u8>,
}
struct Group {
    id: Hash,
    status: PoolState,
    reason: String,
    rows: Vec<Row>,
}
/// Private immutable adapter: resources are derived from the existing command and
/// byte fee, never a fabricated signed gas field or arbitrary-program cost claim.
struct PnxView {
    raw: Vec<u8>,
    envelope: Envelope,
    digest: CanonicalTxDigest,
    signer: CanonicalSignerId,
    fee: u64,
}
fn minimum_fee(tx: &Envelope, bytes: usize, cfg: &Config) -> Result<u64> {
    let base = *cfg.fees.get(usize::from(tx.tag)).ok_or("POOL_TAG")?;
    let byte = cfg.params["byte_fee_units"].as_u64().ok_or("CONFIG")?;
    base.checked_add((bytes as u64).checked_mul(byte).ok_or("POOL_FEE")?)
        .ok_or_else(|| "POOL_FEE".into())
}
impl PnxView {
    fn new(raw: &[u8], cfg: &Config) -> Result<Self> {
        ensure(!raw.is_empty() && raw.len() <= 2048, "POOL_BODY_LIMIT")?;
        let envelope = Envelope::decode(raw).map_err(|_| "POOL_ENCODING")?;
        let digest = CanonicalTxDigest::from_bytes(envelope.id().map_err(|_| "POOL_ENCODING")?)
            .map_err(|_| "POOL_ENCODING")?;
        let signer = CanonicalSignerId::from_bytes(envelope.sender).map_err(|_| "POOL_SIGNER")?;
        let fee = minimum_fee(&envelope, raw.len(), cfg)?;
        Ok(Self {
            raw: raw.to_vec(),
            envelope,
            digest,
            signer,
            fee,
        })
    }
}
impl SignedEnvelopeView for PnxView {
    fn canonical_digest(&self) -> CanonicalTxDigest {
        self.digest
    }
    fn canonical_signer_id(&self) -> std::result::Result<CanonicalSignerId, AdmissionReject> {
        Ok(self.signer)
    }
    fn canonical_body(&self) -> &[u8] {
        &self.raw
    }
    fn nonce(&self) -> u64 {
        self.envelope.nonce
    }
    fn fee_limit(&self) -> u128 {
        u128::from(self.envelope.fee_limit)
    }
    fn resource_limits(&self) -> ResourceLimits {
        ResourceLimits {
            max_gas: self.fee,
            max_bytes: self.raw.len() as u64,
        }
    }
    fn validate_canonical(&self) -> std::result::Result<(), AdmissionReject> {
        if self.envelope.encode().ok().as_deref() != Some(self.raw.as_slice())
            || self.envelope.id().ok() != Some(self.digest.as_bytes())
            || self.envelope.sender != self.signer.as_bytes()
        {
            return Err(AdmissionReject::CanonicalValidationFailed);
        }
        Ok(())
    }
}
struct Hooks<'a> {
    height: u64,
    cfg: &'a Config,
    expected_nonce: u64,
}
impl SignedAdmissionHooks<PnxView> for Hooks<'_> {
    fn verify_signature(
        &mut self,
        view: &PnxView,
        metadata: &SignedEnvelopeMetadata,
    ) -> std::result::Result<(), AdmissionReject> {
        let checked = pon_executor::validate_main_envelope(&view.raw, self.height, self.cfg)
            .map_err(|_| AdmissionReject::SignatureRejected)?;
        if checked != view.envelope
            || metadata.body() != view.raw
            || metadata.digest() != view.digest
            || metadata.signer_id() != view.signer
        {
            return Err(AdmissionReject::CanonicalValidationFailed);
        }
        Ok(())
    }
    fn check_replay(
        &mut self,
        metadata: &SignedEnvelopeMetadata,
    ) -> std::result::Result<(), AdmissionReject> {
        if metadata.nonce() != self.expected_nonce {
            return Err(AdmissionReject::Replay);
        }
        Ok(())
    }
    fn recheck(
        &mut self,
        metadata: &SignedEnvelopeMetadata,
    ) -> std::result::Result<(), AdmissionReject> {
        if metadata.fee_limit() < u128::from(metadata.resource_limits().max_gas)
            || metadata.resource_limits().max_bytes > 2048
        {
            return Err(AdmissionReject::RecheckFailed);
        }
        Ok(())
    }
}
fn chain_nonce(state: &State, sender: Hash) -> Result<u64> {
    match state.get(&format!("account:{}", hex::encode(sender))) {
        None => Ok(0),
        Some(value) => value["nonce"].as_u64().ok_or_else(|| "STATE_NONCE".into()),
    }
}
/// Invocation-local exact raw bindings. No signature/state result is cached.
/// Duplicate digests refuse before replacement, and ready bodies consume one binding.
struct RawBindings<'a> {
    remaining: BTreeMap<Hash, &'a [u8]>,
    max_records: usize,
}
impl<'a> RawBindings<'a> {
    fn new(max_records: usize) -> Self {
        Self {
            remaining: BTreeMap::new(),
            max_records,
        }
    }
    fn insert(&mut self, digest: Hash, raw: &'a [u8]) -> Result<()> {
        ensure(
            !self.remaining.contains_key(&digest),
            "POOL_DUPLICATE_MEMBER",
        )?;
        ensure(self.remaining.len() < self.max_records, "POOL_RECORD_LIMIT")?;
        self.remaining.insert(digest, raw);
        Ok(())
    }
    fn consume(&mut self, digest: Hash, body: &[u8]) -> Result<()> {
        let raw = self.remaining.remove(&digest).ok_or("POOL_TYPED_BINDING")?;
        ensure(body == raw, "POOL_TYPED_BINDING")
    }
    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}
/// Real M05 metadata and strict M06 whole-prefix execution, all against one parent.
/// M05 lane capacity is reused; the durable owner preserves complete group order
/// instead of pretending its lane pop order can split or reorder control bundles.
fn validate_pending(
    raws: &[Vec<u8>],
    height: u64,
    state: &State,
    parent: Hash,
    cfg: &Config,
    limits: &PoolLimits,
    node: &Node,
) -> Result<usize> {
    PendingPreview {
        height,
        state,
        parent,
        cfg,
        limits,
        node,
        checked: None,
        parent_observation: None,
        control: &ExecutionControl::new(&|_| Ok(()), &()),
    }
    .validate(raws)
    .map_err(PoolPreviewError::into_error)
}

/// This value never escapes one owner operation. No staged successor is reused
/// as a parent: each full prefix starts from the same checked immutable State.
enum PoolPreviewError {
    Native(crate::Error),
    Cancelled(crate::Error),
}
impl From<crate::Error> for PoolPreviewError {
    fn from(error: crate::Error) -> Self {
        Self::Native(error)
    }
}
impl From<&str> for PoolPreviewError {
    fn from(error: &str) -> Self {
        Self::Native(error.into())
    }
}
impl From<String> for PoolPreviewError {
    fn from(error: String) -> Self {
        Self::Native(error.into())
    }
}
impl PoolPreviewError {
    fn into_error(self) -> crate::Error {
        match self {
            Self::Native(error) | Self::Cancelled(error) => error,
        }
    }
}
struct PendingPreview<'state, 'operation> {
    height: u64,
    state: &'state State,
    parent: Hash,
    cfg: &'operation Config,
    limits: &'operation PoolLimits,
    node: &'operation Node,
    checked: Option<CheckedExecutionParent<'state>>,
    parent_observation: Option<CommitmentObservation>,
    control: &'operation ExecutionControl<'operation, crate::Error>,
}
impl PendingPreview<'_, '_> {
    fn validate(&mut self, raws: &[Vec<u8>]) -> std::result::Result<usize, PoolPreviewError> {
        let Self {
            height,
            state,
            parent,
            cfg,
            limits,
            node,
            ..
        } = *self;
        let mut gate = TypedAdmissionGate::new(limits.max_records, limits.critical_reserve, 2048);
        let mut next = BTreeMap::new();
        let mut exhausted = BTreeSet::new();
        let mut bindings = RawBindings::new(limits.max_records);
        for (index, raw) in raws.iter().enumerate() {
            (self.control.progress)(ExecutionProgress::BeforePrepare { index })
                .map_err(PoolPreviewError::Cancelled)?;
            let view = PnxView::new(raw, cfg)?;
            bindings.insert(view.digest.as_bytes(), raw)?;
            ensure(!exhausted.contains(&view.envelope.sender), "NONCE_OVERFLOW")?;
            let expected = match next.get(&view.envelope.sender) {
                Some(value) => *value,
                None => chain_nonce(state, view.envelope.sender)?
                    .checked_add(1)
                    .ok_or("NONCE_OVERFLOW")?,
            };
            let mut hooks = Hooks {
                height,
                cfg,
                expected_nonce: expected,
            };
            let class = if (14..=22).contains(&view.envelope.tag) {
                IngressClass::Critical
            } else {
                IngressClass::Normal
            };
            match gate.admit_signed(&view, class, &mut hooks) {
                TypedAdmitOutcome::Accepted => {}
                TypedAdmitOutcome::Backpressured => return Err("POOL_BACKPRESSURED".into()),
                TypedAdmitOutcome::Duplicate => return Err("POOL_DUPLICATE_MEMBER".into()),
                TypedAdmitOutcome::Rejected(reason) => {
                    return Err(format!("POOL_TYPED:{reason:?}").into())
                }
            }
            if let Some(successor) = expected.checked_add(1) {
                next.insert(view.envelope.sender, successor);
            } else {
                exhausted.insert(view.envelope.sender);
            }
            (self.control.progress)(ExecutionProgress::AfterPrepare { index })
                .map_err(PoolPreviewError::Cancelled)?;
        }
        let mut ready = 0;
        while let Some(metadata) = gate.pop_ready() {
            bindings.consume(metadata.digest().as_bytes(), metadata.body())?;
            ready += 1;
        }
        ensure(
            bindings.is_empty() && ready == raws.len(),
            "POOL_TYPED_BINDING",
        )?;
        // Bind lazily, after the first successful typed gate, preserving typed error
        // precedence. Subsequent prefixes borrow the same immutable actual parent.
        if self.checked.is_none() {
            let prior = node.cached_parent(parent)?;
            let checked =
                node.checked_commitment(state, node.record(parent)?.root, prior.as_ref())?;
            self.parent_observation = Some(checked.observation.clone());
            let binding = CheckedExecutionParent::bind(
                state,
                checked.root,
                checked.snapshot.as_ref(),
                CacheLimits::default(),
            );
            self.checked = Some(match binding {
                Ok(binding) => binding,
                Err("COMMITMENT_PARENT" | "COMMITMENT_ROOT") => {
                    // Match execute_derived's defensive full-root retry, even though
                    // the just-checked snapshot and immutable State normally agree.
                    node.invalidate_commitment();
                    CheckedExecutionParent::bind(
                        state,
                        node.record(parent)?.root,
                        None,
                        CacheLimits::default(),
                    )?
                }
                Err(error) => return Err(error.into()),
            });
        }
        // Preserve the existing diagnostic observation if execution itself fails.
        *node.commitment_observation.borrow_mut() = self.parent_observation.clone();
        let output = self
            .checked
            .as_ref()
            .ok_or("POOL_PARENT_BINDING")?
            .execute_with_control(
                ExecutionRequest {
                    transactions: raws,
                    height,
                    miner: limits.preview_miner,
                    parent_id: parent,
                    workers: 1,
                },
                cfg,
                self.control,
            )
            .map_err(|error| match error {
                ExecutionError::Relation(error) => PoolPreviewError::Native(error.into()),
                ExecutionError::Cancelled(error) => PoolPreviewError::Cancelled(error),
            })?;
        *node.commitment_observation.borrow_mut() = Some(output.commitment.observation);
        Ok(ready)
    }
}

/// Actual parent reconstructed for this one pool owner call. Pool writes do not
/// change this State. A new owner call must reconstruct and verify it again.
struct PoolParent {
    id: Hash,
    generation: u64,
    height: u64,
    root: Hash,
    state: State,
}

struct PreviewBinding<'a> {
    checked: Option<CheckedExecutionParent<'a>>,
    observation: Option<CommitmentObservation>,
}

impl Node {
    /// Explicit opt-in on a fresh DDL identity; no import or migration of older pools.
    pub fn enable_local_mempool(&mut self, limits: PoolLimits) -> Result<Hash> {
        self.namespace()?;
        limits.validate()?;
        let raw = serde_json::to_vec(&limits)?;
        let context = hash(
            b"native-local-queued-pnx1-v2",
            &[
                &self.settings.network(),
                &self.settings.parameters(),
                &self.settings.genesis(),
                &raw,
            ],
        );
        let old: Option<(Vec<u8>, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT context,limits FROM local_pool_metadata WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((saved, policy)) = old {
            ensure(saved == context && policy == raw, "POOL_CONTEXT")?
        } else {
            self.db.execute(
                "INSERT INTO local_pool_metadata(singleton,context,limits) VALUES(1,?,?)",
                params![context.as_slice(), raw],
            )?;
        }
        self.pool_reconcile()?;
        Ok(context)
    }
    fn pool_policy(&self) -> Result<(Hash, PoolLimits)> {
        self.namespace()?;
        let (context, raw): (Vec<u8>, Vec<u8>) = self
            .db
            .query_row(
                "SELECT context,limits FROM local_pool_metadata WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or("POOL_NOT_ENABLED")?;
        let limits: PoolLimits = serde_json::from_slice(&raw)?;
        limits.validate()?;
        ensure(serde_json::to_vec(&limits)? == raw, "POOL_POLICY")?;
        let expected = hash(
            b"native-local-queued-pnx1-v2",
            &[
                &self.settings.network(),
                &self.settings.parameters(),
                &self.settings.genesis(),
                &raw,
            ],
        );
        ensure(context == expected, "POOL_CONTEXT")?;
        Ok((bytes32(context)?, limits))
    }
    fn pool_gc_snapshot(&self) -> Result<PoolGcSummary> {
        let (groups, records, bytes, head): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = self.db.query_row(
            "SELECT gc_groups,gc_records,gc_bytes,gc_head FROM local_pool_metadata WHERE singleton=1",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        )?;
        let decode = |raw: Vec<u8>| -> Result<u64> {
            Ok(u64::from_le_bytes(
                raw.try_into().map_err(|_| "POOL_GC_STATE")?,
            ))
        };
        let summary = PoolGcSummary {
            evicted_groups: decode(groups)?,
            evicted_records: decode(records)?,
            evicted_raw_bytes: decode(bytes)?,
            history_head: hex::encode(bytes32(head)?),
        };
        ensure(
            (summary.evicted_groups == 0
                && summary.evicted_records == 0
                && summary.evicted_raw_bytes == 0)
                == (summary.history_head == hex::encode([0u8; 32])),
            "POOL_GC_STATE",
        )?;
        Ok(summary)
    }
    fn pool_groups(&self, limits: &PoolLimits) -> Result<Vec<Group>> {
        let (total, raw_bytes): (usize, usize) = self.db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(raw)),0) FROM local_pool_rows",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure(
            total <= limits.max_records && raw_bytes <= limits.max_bytes,
            "POOL_STORAGE_LIMIT",
        )?;
        let mut statement = self
            .db
            .prepare("SELECT id,status,reason FROM local_pool_groups ORDER BY ordinal LIMIT ?")?;
        let groups = statement
            .query_map([limits.max_records as u32 + 1], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, u8>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure(groups.len() <= limits.max_records, "POOL_STORAGE_LIMIT")?;
        let mut out = Vec::new();
        let mut count = 0;
        let mut bytes = 0;
        for (id, status, reason) in groups {
            ensure(reason.len() <= 128, "POOL_STATE")?;
            let mut stmt=self.db.prepare("SELECT digest,sender,nonce,expiry,fee_limit,raw,position FROM local_pool_rows WHERE group_id=? ORDER BY position")?;
            let rows = stmt
                .query_map([id.as_slice()], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                        r.get::<_, u32>(6)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            ensure(
                !rows.is_empty() && rows.len() <= limits.max_group_members,
                "POOL_GROUP",
            )?;
            let mut decoded = Vec::new();
            let mut ids = Vec::new();
            for (expected_position, (digest, sender, nonce, expiry, fee_limit, raw, position)) in
                rows.into_iter().enumerate()
            {
                ensure(
                    position as usize == expected_position,
                    "POOL_GROUP_POSITION",
                )?;
                let view = PnxView::new(&raw, &self.settings.app)?;
                ensure(
                    digest == view.digest.as_bytes()
                        && sender == view.envelope.sender
                        && nonce == view.envelope.nonce.to_le_bytes()
                        && expiry == view.envelope.expiry.to_le_bytes()
                        && fee_limit == view.envelope.fee_limit.to_le_bytes(),
                    "POOL_STORAGE_BINDING",
                )?;
                count += 1;
                bytes += raw.len();
                ensure(
                    count <= limits.max_records && bytes <= limits.max_bytes,
                    "POOL_STORAGE_LIMIT",
                )?;
                ids.extend_from_slice(&digest);
                decoded.push(Row {
                    digest: bytes32(digest)?,
                    sender: bytes32(sender)?,
                    nonce: view.envelope.nonce,
                    expiry: view.envelope.expiry,
                    raw,
                });
            }
            ensure(
                hash(b"native-local-pool-group-v2", &[&ids]) == bytes32(id.clone())?,
                "POOL_GROUP_BINDING",
            )?;
            out.push(Group {
                id: bytes32(id)?,
                status: PoolState::decode(status)?,
                reason,
                rows: decoded,
            });
        }
        ensure(count == total && bytes == raw_bytes, "POOL_STORAGE_BINDING")?;
        Ok(out)
    }
    /// Classification is branch-relative. SequenceConsumed does not assert that
    /// this exact transaction was mined or confirmed; use normal chain observation.
    pub fn pool_reconcile(&mut self) -> Result<PoolStatus> {
        self.owner_preview_available()?;
        let (_, limits) = self.pool_policy()?;
        let actual = self.pool_parent()?;
        self.pool_reconcile_parent(&limits, &actual)?;
        self.pool_status_snapshot()
    }
    fn pool_parent(&self) -> Result<PoolParent> {
        let (parent, generation) = self.active()?;
        let height = self.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
        let state = self.state_at(parent)?;
        let root = self.record(parent)?.root;
        Ok(PoolParent {
            id: parent,
            generation,
            height,
            root,
            state,
        })
    }
    fn pool_reconcile_parent<'a>(
        &mut self,
        limits: &PoolLimits,
        actual: &'a PoolParent,
    ) -> Result<PreviewBinding<'a>> {
        self.pool_reconcile_parent_with_control(
            limits,
            actual,
            &ExecutionControl::new(&|_| Ok(()), &()),
        )
    }
    fn pool_reconcile_parent_with_control<'a>(
        &mut self,
        limits: &PoolLimits,
        actual: &'a PoolParent,
        control: &ExecutionControl<'_, crate::Error>,
    ) -> Result<PreviewBinding<'a>> {
        let PoolParent {
            id: parent,
            generation,
            height,
            state,
            ..
        } = actual;
        let (parent, generation, height) = (*parent, *generation, *height);
        let groups = self.pool_groups(limits)?;
        let mut accepted = Vec::new();
        let mut preview = PendingPreview {
            height,
            state,
            parent,
            cfg: &self.settings.app,
            limits,
            node: self,
            checked: None,
            parent_observation: None,
            control,
        };
        let mut updates = Vec::new();
        for group in groups {
            let (status, reason) = if group.rows.iter().any(|row| height > row.expiry) {
                (PoolState::Expired, "EXPIRED".to_owned())
            } else if group
                .rows
                .iter()
                .map(|row| chain_nonce(state, row.sender).map(|n| row.nonce <= n))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .any(|used| used)
            {
                (
                    PoolState::SequenceConsumed,
                    "ACTIVE_CHAIN_SEQUENCE_CONSUMED_NOT_INCLUSION_PROOF".to_owned(),
                )
            } else {
                let previous_len = accepted.len();
                accepted.extend(group.rows.into_iter().map(|row| row.raw));
                match preview.validate(&accepted) {
                    Ok(_) => (
                        PoolState::Queued,
                        "EXACT_PENDING_PREFIX_RECHECKED".to_owned(),
                    ),
                    Err(PoolPreviewError::Cancelled(error)) => return Err(error),
                    Err(PoolPreviewError::Native(error)) => {
                        // Roll back only this group's scratch raws. Later groups
                        // see exactly the same accepted prefix as the old copy path.
                        accepted.truncate(previous_len);
                        (PoolState::Blocked, error.to_string())
                    }
                }
            };
            updates.push((group.id, status, reason));
        }
        // The binding borrows only actual State. Release the Node borrow before
        // the pool SQL transaction; no staged successor or admission is retained.
        let binding = PreviewBinding {
            checked: preview.checked.take(),
            observation: preview.parent_observation.take(),
        };
        drop(preview);
        (control.progress)(ExecutionProgress::BeforePersistence)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        fence(&tx, parent, generation)?;
        for (index, (id, status, reason)) in updates.into_iter().enumerate() {
            (control.progress)(ExecutionProgress::PersistenceDelta { index })?;
            ensure(reason.len() <= 128, "POOL_STATE")?;
            tx.execute(
                "UPDATE local_pool_groups SET status=?,reason=? WHERE id=?",
                params![status.code(), reason, id.as_slice()],
            )?;
        }
        tx.execute("UPDATE local_pool_metadata SET checked_parent=?,checked_generation=? WHERE singleton=1",params![parent.as_slice(),generation])?;
        (control.progress)(ExecutionProgress::BeforeDurableCommit)?;
        tx.commit()?;
        Ok(binding)
    }
    pub fn pool_status(&mut self) -> Result<PoolStatus> {
        self.pool_reconcile()
    }
    /// Bounded read-only snapshot, with an explicit last-reconcile generation.
    /// This never executes M06 and must not promote stale classifications.
    pub fn pool_status_snapshot(&self) -> Result<PoolStatus> {
        let (context, limits) = self.pool_policy()?;
        let (parent, generation) = self.active()?;
        let groups = self.pool_groups(&limits)?;
        let mut count = 0;
        let mut bytes = 0;
        let statuses = groups
            .into_iter()
            .map(|group| {
                count += group.rows.len();
                let size = group.rows.iter().map(|row| row.raw.len()).sum();
                bytes += size;
                PoolGroupStatus {
                    group: hex::encode(group.id),
                    digests: group
                        .rows
                        .iter()
                        .map(|row| hex::encode(row.digest))
                        .collect(),
                    state: group.status,
                    reason: group.reason,
                    raw_bytes: size,
                }
            })
            .collect();
        let removals: usize =
            self.db
                .query_row("SELECT COUNT(*) FROM local_pool_removals", [], |r| r.get(0))?;
        ensure(removals <= limits.max_removals, "POOL_STORAGE_LIMIT")?;
        let (checked, checked_generation): (Option<Vec<u8>>, Option<u64>) = self.db.query_row(
            "SELECT checked_parent,checked_generation FROM local_pool_metadata WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure(
            checked.is_some() == checked_generation.is_some(),
            "POOL_STATE",
        )?;
        let checked_parent = checked.map(bytes32).transpose()?;
        let classification_current =
            checked_parent == Some(parent) && checked_generation == Some(generation);
        Ok(PoolStatus{profile:LOCAL_POOL_PROFILE,context:hex::encode(context),parent:hex::encode(parent),generation,
            checked_parent:checked_parent.map(hex::encode),checked_generation,classification_current,
            retained_records:count,retained_bytes:bytes,local_removals:removals,gc:self.pool_gc_snapshot()?,groups:statuses,
            scope:"bounded local snapshot; classification belongs to checked_parent/generation and can be stale; no exact inclusion, confirmation, work or external effect authority"})
    }
    pub fn pool_submit(&mut self, raw: Vec<u8>) -> Result<PoolReceipt> {
        self.pool_submit_bundle(vec![raw])
    }
    /// Atomic local group reservation. Block producers are not obligated to keep
    /// separate transactions together; consensus atomic renewal uses V3 tag22.
    pub fn pool_submit_bundle(&mut self, raws: Vec<Vec<u8>>) -> Result<PoolReceipt> {
        self.pool_submit_bundle_with_accounting(raws, &())
    }
    pub(crate) fn pool_submit_bundle_with_accounting(
        &mut self,
        raws: Vec<Vec<u8>>,
        worker_accounting: &dyn ExecutionWorkerAccounting,
    ) -> Result<PoolReceipt> {
        self.pool_submit_bundle_with_control(
            raws,
            &ExecutionControl::new(&|_| Ok(()), worker_accounting),
        )
    }
    pub(crate) fn pool_submit_bundle_with_control(
        &mut self,
        raws: Vec<Vec<u8>>,
        control: &ExecutionControl<'_, crate::Error>,
    ) -> Result<PoolReceipt> {
        self.owner_preview_available()?;
        let (context, limits) = self.pool_policy()?;
        ensure(
            !raws.is_empty() && raws.len() <= limits.max_group_members,
            "POOL_GROUP_LIMIT",
        )?;
        ensure(
            raws.iter().all(|raw| !raw.is_empty() && raw.len() <= 2048),
            "POOL_BODY_LIMIT",
        )?;
        let total: usize = raws.iter().map(Vec::len).sum();
        ensure(total <= limits.max_bytes, "POOL_BYTE_LIMIT")?;
        let actual = self.pool_parent()?;
        let binding = self.pool_reconcile_parent_with_control(&limits, &actual, control)?;
        // Preserve the original reconcile snapshot checks and error precedence.
        self.pool_status_snapshot()?;
        let groups = self.pool_groups(&limits)?;
        let views = raws
            .iter()
            .map(|raw| PnxView::new(raw, &self.settings.app))
            .collect::<Result<Vec<_>>>()?;
        let mut ids = Vec::new();
        let mut unique = BTreeSet::new();
        for view in &views {
            ensure(
                unique.insert(view.digest.as_bytes()),
                "POOL_DUPLICATE_MEMBER",
            )?;
            ids.extend_from_slice(&view.digest.as_bytes());
        }
        let id = hash(b"native-local-pool-group-v2", &[&ids]);
        for view in &views {
            let removed: bool = self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM local_pool_removals WHERE id=?)",
                [view.digest.as_bytes().as_slice()],
                |r| r.get(0),
            )?;
            ensure(!removed, "POOL_REMOVED")?;
        }
        if let Some(group) = groups.iter().find(|group| group.id == id) {
            ensure(
                group.rows.iter().map(|row| &row.raw).eq(raws.iter()),
                "POOL_DIGEST_CONFLICT",
            )?;
            return Ok(PoolReceipt{group:hex::encode(id),duplicate:true,state:group.status.clone(),typed_gate_admissions:0,typed_gate_ready_metadata:0,scope:"exact retained duplicate; current local state only, no new admission or inclusion claim"});
        }
        let retained: usize = groups.iter().map(|g| g.rows.len()).sum();
        let bytes: usize = groups
            .iter()
            .flat_map(|g| &g.rows)
            .map(|r| r.raw.len())
            .sum();
        for group in &groups {
            for row in &group.rows {
                ensure(
                    !unique.contains(&row.digest),
                    "POOL_MEMBER_ALREADY_RETAINED",
                )?;
                if group.status == PoolState::Queued {
                    ensure(
                        !views.iter().any(|view| {
                            view.envelope.sender == row.sender && view.envelope.nonce == row.nonce
                        }),
                        "POOL_NONCE_CONFLICT",
                    )?;
                }
            }
        }
        let (parent, generation) = self.active()?;
        let record = self.record(parent)?;
        let height = record.height.checked_add(1).ok_or("HEIGHT")?;
        ensure(
            (parent, generation, height) == (actual.id, actual.generation, actual.height),
            "POOL_PARENT_CHANGED",
        )?;
        self.namespace()?;
        ensure(record.root == actual.root, "ROOT")?;
        let state = &actual.state;
        // Admission-triggered cache GC is branch-relative and never creates an
        // operator removal. A group classification can cover only one consumed
        // member: every original member must independently be terminal here.
        let mut kept_records = retained;
        let mut kept_bytes = bytes;
        let mut evictions = Vec::new();
        for group in &groups {
            if kept_records + raws.len() <= limits.max_records
                && kept_bytes + total <= limits.max_bytes
            {
                break;
            }
            if !matches!(
                group.status,
                PoolState::SequenceConsumed | PoolState::Expired
            ) {
                continue;
            }
            let wholly_terminal = group
                .rows
                .iter()
                .map(|row| Ok(height > row.expiry || row.nonce <= chain_nonce(state, row.sender)?))
                .collect::<Result<Vec<bool>>>()?
                .into_iter()
                .all(|terminal| terminal);
            if wholly_terminal {
                kept_records -= group.rows.len();
                kept_bytes -= group.rows.iter().map(|row| row.raw.len()).sum::<usize>();
                evictions.push(group);
            }
        }
        ensure(
            kept_records + raws.len() <= limits.max_records,
            "POOL_RECORD_LIMIT",
        )?;
        ensure(kept_bytes + total <= limits.max_bytes, "POOL_BYTE_LIMIT")?;
        let mut gc = self.pool_gc_snapshot()?;
        let mut gc_head = bytes32(hex::decode(&gc.history_head).map_err(|_| "POOL_GC_STATE")?)?;
        for group in &evictions {
            let records = group.rows.len() as u64;
            let bytes = group
                .rows
                .iter()
                .map(|row| row.raw.len() as u64)
                .sum::<u64>();
            gc.evicted_groups = gc.evicted_groups.checked_add(1).ok_or("POOL_GC_OVERFLOW")?;
            gc.evicted_records = gc
                .evicted_records
                .checked_add(records)
                .ok_or("POOL_GC_OVERFLOW")?;
            gc.evicted_raw_bytes = gc
                .evicted_raw_bytes
                .checked_add(bytes)
                .ok_or("POOL_GC_OVERFLOW")?;
            let digests: Vec<u8> = group.rows.iter().flat_map(|row| row.digest).collect();
            gc_head = hash(
                b"native-local-pool-terminal-cache-eviction-v2",
                &[
                    &gc_head,
                    &context,
                    &parent,
                    &generation.to_le_bytes(),
                    &group.id,
                    &digests,
                    &records.to_le_bytes(),
                    &bytes.to_le_bytes(),
                ],
            );
        }
        let mut candidate: Vec<_> = groups
            .iter()
            .filter(|g| g.status == PoolState::Queued)
            .flat_map(|g| g.rows.iter().map(|r| r.raw.clone()))
            .collect();
        candidate.extend(raws.clone());
        let admitted = PendingPreview {
            height,
            state,
            parent,
            cfg: &self.settings.app,
            limits: &limits,
            node: self,
            checked: binding.checked,
            parent_observation: binding.observation,
            control,
        }
        .validate(&candidate)
        .map_err(PoolPreviewError::into_error)?;
        (control.progress)(ExecutionProgress::BeforePersistence)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        fence(&tx, parent, generation)?;
        for (index, group) in evictions.into_iter().enumerate() {
            (control.progress)(ExecutionProgress::PersistenceDelta { index })?;
            tx.execute(
                "DELETE FROM local_pool_groups WHERE id=?",
                [group.id.as_slice()],
            )?;
        }
        tx.execute("UPDATE local_pool_metadata SET gc_groups=?,gc_records=?,gc_bytes=?,gc_head=? WHERE singleton=1",
            params![gc.evicted_groups.to_le_bytes().as_slice(),gc.evicted_records.to_le_bytes().as_slice(),
                gc.evicted_raw_bytes.to_le_bytes().as_slice(),gc_head.as_slice()])?;
        tx.execute("INSERT INTO local_pool_groups(id,status,reason) VALUES(?,0,'EXACT_PENDING_PREFIX_RECHECKED')",[id.as_slice()])?;
        for (position, view) in views.iter().enumerate() {
            (control.progress)(ExecutionProgress::PersistenceDelta { index: position })?;
            tx.execute(
                "INSERT INTO local_pool_rows VALUES(?,?,?,?,?,?,?,?)",
                params![
                    id.as_slice(),
                    position as u32,
                    view.digest.as_bytes().as_slice(),
                    view.envelope.sender.as_slice(),
                    view.envelope.nonce.to_le_bytes().as_slice(),
                    view.envelope.expiry.to_le_bytes().as_slice(),
                    view.envelope.fee_limit.to_le_bytes().as_slice(),
                    view.raw
                ],
            )?;
        }
        (control.progress)(ExecutionProgress::BeforeDurableCommit)?;
        tx.commit()?;
        Ok(PoolReceipt{group:hex::encode(id),duplicate:false,state:PoolState::Queued,typed_gate_admissions:admitted,typed_gate_ready_metadata:admitted,scope:"M05 typed queue checks plus M06 local prefix preview, SQLite group commit and admission-triggered terminal cache eviction; no block execution, irreversible cache drop or confirmation authority"})
    }
    pub fn pool_mining_batch(
        &mut self,
        parent: Hash,
        generation: u64,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<PoolBatch> {
        ensure(self.active()? == (parent, generation), "POOL_STALE_PARENT")?;
        let (context, limits) = self.pool_policy()?;
        ensure(
            max_records > 0 && max_records <= 256 && max_bytes > 0 && max_bytes <= 524288,
            "POOL_BATCH_LIMIT",
        )?;
        self.pool_reconcile()?;
        let groups = self.pool_groups(&limits)?;
        let mut raws = Vec::new();
        let mut ids = Vec::new();
        let mut bytes = 0;
        for group in groups.into_iter().filter(|g| g.status == PoolState::Queued) {
            let size: usize = group.rows.iter().map(|r| r.raw.len()).sum();
            if raws.len() + group.rows.len() > max_records || bytes + size > max_bytes {
                break;
            }
            bytes += size;
            ids.push(group.id);
            raws.extend(group.rows.into_iter().map(|r| r.raw));
        }
        let height = self.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
        let typed = validate_pending(
            &raws,
            height,
            &self.state_at(parent)?,
            parent,
            &self.settings.app,
            &limits,
            self,
        )?;
        ensure(self.active()? == (parent, generation), "POOL_STALE_PARENT")?;
        Ok(PoolBatch {
            parent,
            generation,
            context,
            preview_miner: limits.preview_miner,
            transactions: raws,
            groups: ids,
            typed_gate_admissions: typed,
        })
    }
    /// Exact retained group/raw recheck immediately before the mining owner uses
    /// a batch. A fence comparison alone never authenticates mutable batch fields.
    pub fn pool_validate_batch(&mut self, batch: &PoolBatch) -> Result<usize> {
        ensure(self.pool_batch_is_current(batch)?, "POOL_STALE_PARENT")?;
        let (_, limits) = self.pool_policy()?;
        ensure(
            batch.preview_miner == limits.preview_miner,
            "POOL_BATCH_BINDING",
        )?;
        self.pool_reconcile()?;
        let groups = self.pool_groups(&limits)?;
        let queued: Vec<_> = groups
            .iter()
            .filter(|g| g.status == PoolState::Queued)
            .collect();
        ensure(batch.groups.len() <= queued.len(), "POOL_BATCH_BINDING")?;
        let chosen = &queued[..batch.groups.len()];
        ensure(
            chosen.iter().map(|g| g.id).eq(batch.groups.iter().copied()),
            "POOL_BATCH_BINDING",
        )?;
        let raws: Vec<_> = chosen
            .iter()
            .flat_map(|g| g.rows.iter().map(|r| r.raw.clone()))
            .collect();
        ensure(raws == batch.transactions, "POOL_BATCH_BINDING")?;
        let height = self
            .parent_height(batch.parent)?
            .checked_add(1)
            .ok_or("HEIGHT")?;
        let admitted = validate_pending(
            &raws,
            height,
            &self.state_at(batch.parent)?,
            batch.parent,
            &self.settings.app,
            &limits,
            self,
        )?;
        ensure(
            self.active()? == (batch.parent, batch.generation),
            "POOL_STALE_PARENT",
        )?;
        Ok(admitted)
    }
    /// Cheap generation/context fence only; pool_validate_batch performs exact raw
    /// and current M05/M06 checks. Neither method authorizes chain activation.
    pub fn pool_batch_is_current(&self, batch: &PoolBatch) -> Result<bool> {
        let (context, _) = self.pool_policy()?;
        Ok(context == batch.context && self.active()? == (batch.parent, batch.generation))
    }
    /// Explicit terminal pruning is local and monotonic, never a branch rollback.
    /// Removed groups cannot be silently resurrected by resubmission or reorg.
    pub fn pool_prune_terminal(&mut self, id: Hash) -> Result<()> {
        self.pool_reconcile()?;
        let (_, limits) = self.pool_policy()?;
        let groups = self.pool_groups(&limits)?;
        let group = groups.iter().find(|g| g.id == id).ok_or("POOL_GROUP")?;
        ensure(group.status != PoolState::Queued, "POOL_PENDING")?;
        let count: usize =
            self.db
                .query_row("SELECT COUNT(*) FROM local_pool_removals", [], |r| r.get(0))?;
        ensure(
            count + group.rows.len() <= limits.max_removals,
            "POOL_REMOVAL_LIMIT",
        )?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for row in &group.rows {
            tx.execute("INSERT INTO local_pool_removals(id,group_id,reason) VALUES(?,?,'explicit-terminal-prune')",params![row.digest.as_slice(),id.as_slice()])?;
        }
        tx.execute("DELETE FROM local_pool_groups WHERE id=?", [id.as_slice()])?;
        tx.commit()?;
        Ok(())
    }
}
fn fence(db: &rusqlite::Transaction<'_>, parent: Hash, generation: u64) -> Result<()> {
    let (tip, recorded): (Vec<u8>, u64) = db.query_row(
        "SELECT tip,generation FROM active WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure(tip == parent && recorded == generation, "POOL_STALE_PARENT")
}

#[cfg(test)]
mod binding_tests {
    use super::*;

    #[test]
    fn exact_binding_consumes_each_body_once_in_any_ready_order() {
        let mut bindings = RawBindings::new(2);
        bindings.insert([1; 32], b"first exact raw").unwrap();
        bindings.insert([2; 32], b"second exact raw").unwrap();
        bindings.consume([2; 32], b"second exact raw").unwrap();
        assert!(!bindings.is_empty());
        bindings.consume([1; 32], b"first exact raw").unwrap();
        assert!(bindings.is_empty());
        assert!(bindings.consume([1; 32], b"first exact raw").is_err());
    }

    #[test]
    fn duplicate_binding_cannot_replace_original_even_at_capacity() {
        let mut bindings = RawBindings::new(1);
        bindings.insert([1; 32], b"original").unwrap();
        assert_eq!(
            bindings
                .insert([1; 32], b"mutated")
                .unwrap_err()
                .to_string(),
            "POOL_DUPLICATE_MEMBER"
        );
        assert_eq!(bindings.remaining[&[1; 32]], b"original");
        assert!(bindings.insert([2; 32], b"extra").is_err());
        bindings.consume([1; 32], b"original").unwrap();
        assert!(bindings.is_empty());
    }

    #[test]
    fn unknown_digest_or_mutated_ready_body_refuses_without_success() {
        let mut bindings = RawBindings::new(2);
        bindings.insert([1; 32], b"original").unwrap();
        bindings.insert([2; 32], b"remaining").unwrap();
        assert!(bindings.consume([3; 32], b"original").is_err());
        assert_eq!(bindings.remaining.len(), 2);
        assert!(bindings.consume([1; 32], b"mutated").is_err());
        assert!(!bindings.is_empty());
        assert_eq!(bindings.remaining[&[2; 32]], b"remaining");
    }

    #[test]
    #[ignore = "explicit normal component timing, not a service or work-cost qualification"]
    fn normal_256_signed_raw_binding_component_timing() {
        use std::time::Instant;
        use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
        let cfg = Config::installed().unwrap();
        let key = signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()])))
            .unwrap();
        let sender = crate::development_public(0).unwrap();
        let mut raws = Vec::new();
        for nonce in 1..=256 {
            let mut payload = crate::development_public(2).unwrap().to_vec();
            payload.extend(1u64.to_le_bytes());
            let mut envelope = Envelope {
                network: cfg.network,
                sender,
                nonce,
                expiry: 2000,
                fee_limit: 1_000_000,
                tag: 1,
                payload,
                signature: [0; 64],
            };
            envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
                .unwrap()
                .try_into()
                .unwrap();
            let raw = envelope.encode().unwrap();
            pon_executor::validate_main_envelope(&raw, 1, &cfg).unwrap();
            raws.push(raw);
        }
        let mut old_ns = Vec::new();
        let mut indexed_ns = Vec::new();
        for _ in 0..32 {
            let stage = Instant::now();
            let digests = raws
                .iter()
                .map(|raw| PnxView::new(raw, &cfg).unwrap().digest.as_bytes())
                .collect::<Vec<_>>();
            let mut remaining = BTreeSet::new();
            for digest in &digests {
                assert!(remaining.insert(*digest));
            }
            for (digest, body) in digests.iter().zip(&raws) {
                assert!(remaining.remove(digest));
                let raw = raws
                    .iter()
                    .find(|raw| {
                        Envelope::decode(raw).ok().and_then(|tx| tx.id().ok()) == Some(*digest)
                    })
                    .unwrap();
                assert_eq!(std::hint::black_box(body), raw);
            }
            assert!(remaining.is_empty());
            old_ns.push(stage.elapsed().as_nanos());
            let stage = Instant::now();
            let mut bindings = RawBindings::new(256);
            let digests = raws
                .iter()
                .map(|raw| {
                    let view = PnxView::new(raw, &cfg).unwrap();
                    bindings.insert(view.digest.as_bytes(), raw).unwrap();
                    view.digest.as_bytes()
                })
                .collect::<Vec<_>>();
            for (digest, body) in digests.into_iter().zip(&raws) {
                bindings
                    .consume(digest, std::hint::black_box(body))
                    .unwrap();
            }
            assert!(bindings.is_empty());
            indexed_ns.push(stage.elapsed().as_nanos());
        }
        println!(
            "{}",
            serde_json::json!({"schema":"normal-pending-raw-binding-timing-v1","signed_raws":256,"raw_bytes":raws.iter().map(Vec::len).sum::<usize>(),"samples":32,"old_scan_elapsed_ns":old_ns,"indexed_elapsed_ns":indexed_ns,"scope":"one invocation-local metadata binding component; real signatures checked before timing; excludes M05, M06, pool reconciliation, native work, SQLite, Node wait and service concurrency","public_network_ready":false,"production_activation":false})
        );
    }
}
