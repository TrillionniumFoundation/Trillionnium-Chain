use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::RwLock;
use trnm_types::{
    GovParamObject, GovProposalObject, GovProposalStatus, Hash32, ObjectRef, TaskObject, TaskStatus,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectValue {
    Task(TaskObject),
    GovProposal(GovProposalObject),
    GovParam(GovParamObject),
}

#[derive(Debug)]
pub struct StateStore {
    objects: BTreeMap<u64, VersionedObject>,
    balances: BTreeMap<String, u128>,
    pending_gov_updates: BTreeMap<String, PendingGovParamUpdate>,
    gov_param_key_index: BTreeMap<String, u64>,
    pending_resolve_approvals: BTreeMap<u64, PendingResolveApproval>,
    monetary_state: MonetaryState,
    state_root_cache: RwLock<Option<Hash32>>,
}

#[derive(Debug, Clone)]
struct VersionedObject {
    version: u64,
    value: ObjectValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingResolveApproval {
    slash_worker: bool,
    confirmations: u8,
    first_approver: String,
    authority_set: String,
    task_version: u64,
    stored_as_canonical: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskRestoreReentryBoundaryAction {
    Noop,
    ScrubPendingResolve,
    Reapply,
}

impl Default for StateStore {
    fn default() -> Self {
        Self {
            objects: BTreeMap::new(),
            balances: BTreeMap::new(),
            pending_gov_updates: BTreeMap::new(),
            gov_param_key_index: BTreeMap::new(),
            pending_resolve_approvals: BTreeMap::new(),
            monetary_state: MonetaryState::default(),
            state_root_cache: RwLock::new(None),
        }
    }
}

impl Clone for StateStore {
    fn clone(&self) -> Self {
        let cached = self
            .state_root_cache
            .read()
            .expect("state root cache poisoned")
            .clone();
        Self {
            objects: self.objects.clone(),
            balances: self.balances.clone(),
            pending_gov_updates: self.pending_gov_updates.clone(),
            gov_param_key_index: self.gov_param_key_index.clone(),
            pending_resolve_approvals: self.pending_resolve_approvals.clone(),
            monetary_state: self.monetary_state.clone(),
            state_root_cache: RwLock::new(cached),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MonetaryState {
    pub last_tick_height: u64,
    pub tick_count: u64,
    pub total_minted: u128,
    pub total_burned: u128,
    pub net_issuance: i128,
}

pub type MonetaryStateSnapshot = MonetaryState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyTickEvent {
    pub block_height: u64,
    pub interval_blocks: u64,
    pub cooldown_blocks: u64,
    pub minted: u128,
    pub burned: u128,
    pub net_delta: i128,
    pub total_minted: u128,
    pub total_burned: u128,
    pub net_issuance: i128,
    pub tick_count: u64,
    pub interval_param_version: u64,
    pub issuance_param_version: u64,
    pub burn_param_version: u64,
    pub cooldown_param_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointMeta {
    pub height: u64,
    pub state_root_hex: String,
    pub wal_entry_hash_hex: String,
}

impl CheckpointMeta {
    pub fn commitment_hex(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.height.to_le_bytes());
        hash_len_prefixed_str(&mut hasher, &self.state_root_hex);
        hash_len_prefixed_str(&mut hasher, &self.wal_entry_hash_hex);
        hex::encode(hasher.finalize())
    }

    pub fn evidence_summary(&self) -> String {
        format!(
            "checkpoint_height={} state_root={} wal_entry_hash={} checkpoint_commitment={}",
            self.height,
            self.state_root_hex,
            self.wal_entry_hash_hex,
            self.commitment_hex()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalMeta {
    pub height: u64,
    pub round: u64,
    pub proposal_hash: String,
    pub committed: bool,
    pub state_root_hex: String,
    pub prev_hash_hex: Option<String>,
}

impl WalMeta {
    pub fn content_hash_hex(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        hash_len_prefixed_str(&mut hasher, &self.proposal_hash);
        hasher.update([self.committed as u8]);
        hash_len_prefixed_str(&mut hasher, &self.state_root_hex);
        match &self.prev_hash_hex {
            Some(prev) => {
                hasher.update([1]);
                hash_len_prefixed_str(&mut hasher, prev);
            }
            None => hasher.update([0]),
        }
        hex::encode(hasher.finalize())
    }

    pub fn evidence_summary(&self) -> String {
        format!(
            "wal_height={} wal_round={} wal_proposal_hash={} wal_committed={} wal_state_root={} wal_prev_hash={} wal_entry_hash={}",
            self.height,
            self.round,
            self.proposal_hash,
            self.committed,
            self.state_root_hex,
            self.prev_hash_hex.as_deref().unwrap_or("none"),
            self.content_hash_hex()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingGovParamUpdate {
    pub key_id: u64,
    pub key: String,
    pub value: String,
    pub activate_at_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingResolveApprovalSnapshot {
    pub slash_worker: bool,
    pub confirmations: u8,
    pub first_approver: String,
    pub authority_set: String,
    pub task_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovParamUpdateOutcome {
    Applied(ObjectRef),
    Scheduled { activate_at_height: u64 },
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovPendingUpdateAction {
    Enforce,
    Replace,
    Cancel,
}

const GOV_SENSITIVE_PARAM_TIMELOCK_BLOCKS: u64 = 20;
const GOV_SENSITIVE_PARAM_MAX_CHANGE_BPS: u64 = 2_000;
const EMERGENCY_PAUSE_KEY_ID: u64 = 7_999;
const GOV_PINNED_KEY_IDS: &[(&str, u64)] = &[("emergency_pause", EMERGENCY_PAUSE_KEY_ID)];

fn governance_pinned_binding(
    key: Option<&str>,
    key_id: Option<u64>,
) -> Option<(&'static str, u64)> {
    GOV_PINNED_KEY_IDS
        .iter()
        .copied()
        .find(|(pinned_key, pinned_key_id)| {
            key.is_some_and(|candidate| candidate == *pinned_key)
                || key_id.is_some_and(|candidate| candidate == *pinned_key_id)
        })
}

fn governance_expected_pinned_binding(
    key: &str,
    key_id: u64,
) -> (Option<u64>, Option<&'static str>) {
    match governance_pinned_binding(Some(key), Some(key_id)) {
        Some((pinned_key, pinned_key_id)) => {
            let expected_key_id = (pinned_key == key).then_some(pinned_key_id);
            let expected_key = (pinned_key_id == key_id).then_some(pinned_key);
            (expected_key_id, expected_key)
        }
        None => (None, None),
    }
}

fn governance_pinned_binding_for_key(key: &str) -> Option<(&'static str, u64)> {
    governance_pinned_binding(Some(key), None)
}

fn governance_pinned_binding_for_id(key_id: u64) -> Option<(&'static str, u64)> {
    governance_pinned_binding(None, Some(key_id))
}

fn governance_expected_key_id(key: &str) -> Option<u64> {
    governance_pinned_binding_for_key(key).map(|(_, pinned_key_id)| pinned_key_id)
}

fn governance_expected_key_for_id(key_id: u64) -> Option<&'static str> {
    governance_pinned_binding_for_id(key_id).map(|(pinned_key, _)| pinned_key)
}

fn governance_registry_lookup_id_for_key(
    gov_param_key_index: &BTreeMap<String, u64>,
    key: &str,
) -> Option<u64> {
    if !GOV_ALLOWED_KEYS.contains(&key) {
        return None;
    }
    governance_expected_key_id(key).or_else(|| gov_param_key_index.get(key).copied())
}

fn governance_registry_unique_dynamic_key_for_id<'a>(
    gov_param_key_index: &'a BTreeMap<String, u64>,
    key_id: u64,
) -> Result<Option<&'a str>, Vec<&'a str>> {
    let mut matches = gov_param_key_index
        .iter()
        .filter_map(|(indexed_key, indexed_key_id)| {
            (*indexed_key_id == key_id && GOV_ALLOWED_KEYS.contains(&indexed_key.as_str()))
                .then_some(indexed_key.as_str())
        });
    let first = matches.next();
    let second = matches.next();
    match (first, second) {
        (None, _) => Ok(None),
        (Some(key), None) => Ok(Some(key)),
        (Some(first_key), Some(second_key)) => {
            let mut ambiguous_keys = vec![first_key, second_key];
            ambiguous_keys.extend(matches);
            Err(ambiguous_keys)
        }
    }
}

fn governance_registry_lookup_key_for_id<'a>(
    gov_param_key_index: &'a BTreeMap<String, u64>,
    key_id: u64,
) -> Option<&'a str> {
    let dynamic_key =
        match governance_registry_unique_dynamic_key_for_id(gov_param_key_index, key_id) {
            Ok(dynamic_key) => dynamic_key,
            Err(_) => return None,
        };

    match (governance_expected_key_for_id(key_id), dynamic_key) {
        (Some(expected_key), Some(indexed_key)) if indexed_key != expected_key => None,
        (Some(expected_key), _) => Some(expected_key),
        (None, dynamic_key) => dynamic_key,
    }
}

fn validate_gov_param_key_id_policy(key: &str, key_id: u64) -> Result<(), String> {
    let (expected_key_id, expected_key) = governance_expected_pinned_binding(key, key_id);
    if let Some(expected_key_id) = expected_key_id {
        if key_id != expected_key_id {
            return Err(format!(
                "governance key id mismatch for {}: expected_id={}, attempted_id={}",
                key, expected_key_id, key_id
            ));
        }
    }
    if let Some(expected_key) = expected_key {
        if key != expected_key {
            return Err(format!(
                "governance key id mismatch for id {}: expected_key={}, attempted_key={}",
                key_id, expected_key, key
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_gov_param_registry_binding(
    gov_param_key_index: &BTreeMap<String, u64>,
    key: &str,
    key_id: u64,
) -> Result<(), String> {
    if !GOV_ALLOWED_KEYS.contains(&key) {
        return Err(format!("governance key not allowed: {}", key));
    }
    // Shared single-source gate: enforce both the forward pinned-key mapping
    // (key -> canonical key_id) and the reverse reserved-id mapping
    // (reserved key_id -> canonical key) before consulting the mutable registry.
    validate_gov_param_key_id_policy(key, key_id)?;
    if let Some(existing_key_id) = governance_registry_lookup_id_for_key(gov_param_key_index, key) {
        if existing_key_id != key_id {
            return Err(format!(
                "governance key id mismatch for {}: existing_id={}, attempted_id={}",
                key, existing_key_id, key_id
            ));
        }
    }
    match governance_registry_unique_dynamic_key_for_id(gov_param_key_index, key_id) {
        Ok(Some(canonical_key)) => {
            if canonical_key != key {
                return Err(format!(
                    "governance key id alias mismatch for id {}: canonical_key={}, aliased_key={}",
                    key_id, canonical_key, key
                ));
            }
        }
        Ok(None) => {
            if let Some(canonical_key) = governance_expected_key_for_id(key_id) {
                if canonical_key != key {
                    return Err(format!(
                        "governance key id alias mismatch for id {}: canonical_key={}, aliased_key={}",
                        key_id, canonical_key, key
                    ));
                }
            }
        }
        Err(ambiguous_keys) => {
            return Err(format!(
                "governance key id alias mismatch for id {}: ambiguous_keys={}",
                key_id,
                ambiguous_keys.join(",")
            ));
        }
    }
    Ok(())
}

fn validate_gov_param_snapshot_binding(
    gov_param_key_index: &BTreeMap<String, u64>,
    requested_key: &str,
    snapshot_key: &str,
    snapshot_key_id: u64,
) -> Result<(), String> {
    if snapshot_key != requested_key {
        return Err(format!(
            "governance key mismatch: requested_key={}, snapshot_key={}",
            requested_key, snapshot_key
        ));
    }
    validate_gov_param_registry_binding(gov_param_key_index, snapshot_key, snapshot_key_id)
}

fn validate_pending_gov_param_snapshot_binding(
    gov_param_key_index: &BTreeMap<String, u64>,
    requested_key: &str,
    snapshot: &PendingGovParamUpdate,
) -> Result<(), String> {
    validate_gov_param_snapshot_binding(
        gov_param_key_index,
        requested_key,
        &snapshot.key,
        snapshot.key_id,
    )
}

const GOV_ALLOWED_KEYS: &[&str] = &[
    "max_block_ms",
    "max_parallel_workers",
    "min_worker_stake",
    "challenge_min_bond",
    "challenge_min_bond_bounty_bps",
    "challenge_min_bond_worker_stake_bps",
    "challenge_window_blocks",
    "challenge_success_bounty",
    "llm_meter_prompt_token_weight",
    "llm_meter_generated_token_weight",
    "llm_meter_decode_step_weight",
    "llm_meter_kv_byte_weight",
    "llm_meter_min_accept_work_units",
    "llm_meter_challenge_success_bounty_per_work_unit_num",
    "llm_meter_challenge_success_bounty_per_work_unit_den",
    "llm_meter_worker_completion_bonus_per_work_unit_num",
    "llm_meter_worker_completion_bonus_per_work_unit_den",
    "llm_meter_worker_slash_rebate_per_work_unit_num",
    "llm_meter_worker_slash_rebate_per_work_unit_den",
    "resolve_authority",
    "emergency_pause",
    "monetary_policy_tick_interval_blocks",
    "monetary_policy_tick_cooldown_blocks",
    "monetary_base_issuance_per_tick",
    "monetary_base_burn_per_tick",
];
const GOV_SENSITIVE_KEYS: &[&str] = &[
    "challenge_window_blocks",
    "challenge_min_bond",
    "challenge_success_bounty",
    "llm_meter_prompt_token_weight",
    "llm_meter_generated_token_weight",
    "llm_meter_decode_step_weight",
    "llm_meter_kv_byte_weight",
    "llm_meter_min_accept_work_units",
    "llm_meter_challenge_success_bounty_per_work_unit_num",
    "llm_meter_challenge_success_bounty_per_work_unit_den",
    "llm_meter_worker_completion_bonus_per_work_unit_num",
    "llm_meter_worker_completion_bonus_per_work_unit_den",
    "llm_meter_worker_slash_rebate_per_work_unit_num",
    "llm_meter_worker_slash_rebate_per_work_unit_den",
    "min_worker_stake",
    "challenge_min_bond_bounty_bps",
    "challenge_min_bond_worker_stake_bps",
    "resolve_authority",
];
const GOV_EXPLICIT_VALIDATOR_KEYS: &[&str] = &[
    "max_block_ms",
    "max_parallel_workers",
    "min_worker_stake",
    "challenge_min_bond",
    "challenge_min_bond_bounty_bps",
    "challenge_min_bond_worker_stake_bps",
    "challenge_window_blocks",
    "challenge_success_bounty",
    "llm_meter_prompt_token_weight",
    "llm_meter_generated_token_weight",
    "llm_meter_decode_step_weight",
    "llm_meter_kv_byte_weight",
    "llm_meter_min_accept_work_units",
    "llm_meter_challenge_success_bounty_per_work_unit_num",
    "llm_meter_challenge_success_bounty_per_work_unit_den",
    "llm_meter_worker_completion_bonus_per_work_unit_num",
    "llm_meter_worker_completion_bonus_per_work_unit_den",
    "llm_meter_worker_slash_rebate_per_work_unit_num",
    "llm_meter_worker_slash_rebate_per_work_unit_den",
    "resolve_authority",
    "emergency_pause",
    "monetary_policy_tick_interval_blocks",
    "monetary_policy_tick_cooldown_blocks",
    "monetary_base_issuance_per_tick",
    "monetary_base_burn_per_tick",
];
const GOV_EXPLICIT_VALUE_RULE_KEYS: &[&str] = GOV_EXPLICIT_VALIDATOR_KEYS;
const GOV_SCHEMA_INVALID_SAMPLES: &[(&str, &str)] = &[
    ("max_block_ms", "9"),
    ("max_parallel_workers", "0"),
    ("min_worker_stake", "0"),
    ("challenge_min_bond", "0"),
    ("challenge_min_bond_bounty_bps", "100001"),
    ("challenge_min_bond_worker_stake_bps", "100001"),
    ("challenge_window_blocks", "99"),
    ("challenge_success_bounty", "-1"),
    ("llm_meter_prompt_token_weight", "-1"),
    ("llm_meter_generated_token_weight", "-1"),
    ("llm_meter_decode_step_weight", "-1"),
    ("llm_meter_kv_byte_weight", "-1"),
    ("llm_meter_min_accept_work_units", "-1"),
    ("llm_meter_challenge_success_bounty_per_work_unit_num", "-1"),
    ("llm_meter_challenge_success_bounty_per_work_unit_den", "0"),
    ("llm_meter_worker_completion_bonus_per_work_unit_num", "-1"),
    ("llm_meter_worker_completion_bonus_per_work_unit_den", "0"),
    ("llm_meter_worker_slash_rebate_per_work_unit_num", "-1"),
    ("llm_meter_worker_slash_rebate_per_work_unit_den", "0"),
    ("resolve_authority", "authority-a"),
    ("emergency_pause", "TRUE"),
    ("monetary_policy_tick_interval_blocks", "0"),
    ("monetary_policy_tick_cooldown_blocks", "0"),
    ("monetary_base_issuance_per_tick", "1000000000001"),
    ("monetary_base_burn_per_tick", "1000000000001"),
];
const DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER: &str = "governance.resolve_authority";

fn governance_pinned_key_id_from_lists(pinned_key_ids: &[(&str, u64)], key: &str) -> Option<u64> {
    pinned_key_ids
        .iter()
        .find_map(|(pinned_key, pinned_id)| (*pinned_key == key).then_some(*pinned_id))
}

#[allow(dead_code)]
fn governance_pinned_key_id(key: &str) -> Option<u64> {
    governance_pinned_key_id_from_lists(GOV_PINNED_KEY_IDS, key)
}

fn validate_governance_key_id_from_lists(
    pinned_key_ids: &[(&str, u64)],
    key: &str,
    key_id: u64,
) -> Result<(), String> {
    if let Some(expected_id) = governance_pinned_key_id_from_lists(pinned_key_ids, key) {
        if key_id != expected_id {
            return Err(format!(
                "governance key id mismatch for {}: expected_id={}, attempted_id={}",
                key, expected_id, key_id
            ));
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_governance_key_id(key: &str, key_id: u64) -> Result<(), String> {
    validate_governance_key_id_from_lists(GOV_PINNED_KEY_IDS, key, key_id)
}

fn format_governance_registry_membership_drift(
    registry_name: &str,
    allowed_unique: &std::collections::BTreeSet<&str>,
    registry_unique: &std::collections::BTreeSet<&str>,
) -> Option<String> {
    let missing_allowed_keys: Vec<&str> = allowed_unique
        .difference(registry_unique)
        .copied()
        .collect();
    let rogue_registry_keys: Vec<&str> = registry_unique
        .difference(allowed_unique)
        .copied()
        .collect();

    if missing_allowed_keys.is_empty() && rogue_registry_keys.is_empty() {
        return None;
    }

    Some(format!(
        "governance {} drifted from allowed-key registry: missing_allowed_keys=[{}], rogue_validator_keys=[{}]",
        registry_name,
        missing_allowed_keys.join(", "),
        rogue_registry_keys.join(", "),
    ))
}

fn validate_governance_explicit_registry_alignment<'a>(
    allowed_keys: &[&'a str],
    allowed_unique: &std::collections::BTreeSet<&'a str>,
    registry_name: &str,
    entry_name: &str,
    registry_keys: &[&'a str],
) -> Result<std::collections::BTreeSet<&'a str>, String> {
    for key in registry_keys {
        validate_governance_registry_key_canonical(registry_name, key)?;
    }
    let registry_unique: std::collections::BTreeSet<&str> = registry_keys.iter().copied().collect();
    if registry_unique.len() != registry_keys.len() {
        return Err(format!(
            "governance {} contains duplicate entries",
            registry_name
        ));
    }

    if let Some(err) =
        format_governance_registry_membership_drift(registry_name, allowed_unique, &registry_unique)
    {
        return Err(err);
    }

    for (index, (allowed_key, registry_key)) in
        allowed_keys.iter().zip(registry_keys.iter()).enumerate()
    {
        if allowed_key != registry_key {
            return Err(format!(
                "governance {} order drifted at index {}: allowed_key={}, {}={}",
                registry_name, index, allowed_key, entry_name, registry_key
            ));
        }
    }

    for key in allowed_unique {
        if !registry_unique.contains(key) {
            return Err(format!(
                "governance {} coverage missing for allowed key: {}",
                entry_name, key
            ));
        }
    }

    for key in &registry_unique {
        if !allowed_unique.contains(key) {
            return Err(format!(
                "governance {} contains non-whitelisted key: {}",
                registry_name, key
            ));
        }
    }

    Ok(registry_unique)
}

fn validate_governance_registry_key_canonical(
    registry_name: &str,
    key: &str,
) -> Result<(), String> {
    if key.trim() != key {
        return Err(format!(
            "governance {} contains non-canonical key with surrounding whitespace: {}",
            registry_name, key
        ));
    }
    if key.is_empty() {
        return Err(format!(
            "governance {} contains empty key entry",
            registry_name
        ));
    }
    if !key.is_ascii() {
        return Err(format!(
            "governance {} contains non-ascii key entry: {}",
            registry_name, key
        ));
    }
    if key.chars().any(|ch| ch.is_ascii_uppercase()) {
        return Err(format!(
            "governance {} contains non-canonical uppercase key: {}",
            registry_name, key
        ));
    }
    if key.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(format!(
            "governance {} contains non-canonical whitespace or control character in key: {}",
            registry_name, key
        ));
    }
    Ok(())
}

fn validate_pinned_governance_key_explicit_coverage(
    key: &str,
    validator_unique: &std::collections::BTreeSet<&str>,
    explicit_value_rule_unique: &std::collections::BTreeSet<&str>,
) -> Result<(), String> {
    if !validator_unique.contains(key) {
        return Err(format!(
            "governance pinned-key registry missing explicit-validator coverage for {}",
            key
        ));
    }
    if !explicit_value_rule_unique.contains(key) {
        return Err(format!(
            "governance pinned-key registry missing explicit-value-rule coverage for {}",
            key
        ));
    }
    Ok(())
}

fn validate_governance_registry_shape_lists(
    allowed_keys: &[&str],
    sensitive_keys: &[&str],
    explicit_validator_keys: &[&str],
    explicit_value_rule_keys: &[&str],
    pinned_key_ids: &[(&str, u64)],
) -> Result<(), String> {
    for key in allowed_keys {
        validate_governance_registry_key_canonical("allowed-key registry", key)?;
    }
    let allowed_unique: std::collections::BTreeSet<&str> = allowed_keys.iter().copied().collect();
    if allowed_unique.len() != allowed_keys.len() {
        return Err("governance allowed-key registry contains duplicate entries".into());
    }

    for key in sensitive_keys {
        validate_governance_registry_key_canonical("sensitive-key registry", key)?;
    }
    let sensitive_unique: std::collections::BTreeSet<&str> =
        sensitive_keys.iter().copied().collect();
    if sensitive_unique.len() != sensitive_keys.len() {
        return Err("governance sensitive-key registry contains duplicate entries".into());
    }

    let validator_unique = validate_governance_explicit_registry_alignment(
        allowed_keys,
        &allowed_unique,
        "explicit-validator registry",
        "validator_key",
        explicit_validator_keys,
    )?;

    let explicit_value_rule_unique = validate_governance_explicit_registry_alignment(
        allowed_keys,
        &allowed_unique,
        "explicit-value-rule registry",
        "explicit_value_rule_key",
        explicit_value_rule_keys,
    )?;

    for key in &sensitive_unique {
        if !allowed_unique.contains(key) {
            return Err(format!(
                "governance sensitive-key coverage missing from allowed key registry: {}",
                key
            ));
        }
    }

    let mut pinned_unique = std::collections::BTreeSet::new();
    let mut pinned_ids = std::collections::BTreeMap::new();
    for (key, pinned_id) in pinned_key_ids {
        validate_governance_registry_key_canonical("pinned-key registry", key)?;
        if !pinned_unique.insert(*key) {
            return Err(format!(
                "governance pinned-key registry contains duplicate entries for {}",
                key
            ));
        }
        if let Some(existing_key) = pinned_ids.insert(*pinned_id, *key) {
            return Err(format!(
                "governance pinned-key registry reuses pinned id {} across {} and {}",
                pinned_id, existing_key, key
            ));
        }
        if !allowed_unique.contains(key) {
            return Err(format!(
                "governance pinned-key registry contains non-whitelisted key: {}",
                key
            ));
        }
        validate_pinned_governance_key_explicit_coverage(
            key,
            &validator_unique,
            &explicit_value_rule_unique,
        )?;
    }

    Ok(())
}

fn validate_governance_registry_shape() -> Result<(), String> {
    validate_governance_registry_shape_lists(
        GOV_ALLOWED_KEYS,
        GOV_SENSITIVE_KEYS,
        GOV_EXPLICIT_VALIDATOR_KEYS,
        GOV_EXPLICIT_VALUE_RULE_KEYS,
        GOV_PINNED_KEY_IDS,
    )
}

fn validate_governance_schema_sample_registry_shape_from_lists(
    allowed_keys: &[&str],
    explicit_validator_keys: &[&str],
    explicit_value_rule_keys: &[&str],
    schema_invalid_samples: &[(&str, &str)],
) -> Result<(), String> {
    let allowed_unique: std::collections::BTreeSet<&str> = allowed_keys.iter().copied().collect();
    let schema_sample_keys: Vec<&str> =
        schema_invalid_samples.iter().map(|(key, _)| *key).collect();
    for key in &schema_sample_keys {
        validate_governance_registry_key_canonical("schema invalid-sample registry", key)?;
    }
    let schema_unique: std::collections::BTreeSet<&str> =
        schema_sample_keys.iter().copied().collect();

    if schema_unique.len() != schema_sample_keys.len() {
        return Err("governance schema invalid-sample registry contains duplicate entries".into());
    }
    if allowed_unique != schema_unique {
        let missing_schema_keys: Vec<&str> =
            allowed_unique.difference(&schema_unique).copied().collect();
        let rogue_schema_keys: Vec<&str> =
            schema_unique.difference(&allowed_unique).copied().collect();
        return Err(format!(
            "governance schema invalid-sample registry drifted from allowed-key registry: missing_schema_keys=[{}], rogue_schema_keys=[{}]",
            missing_schema_keys.join(", "),
            rogue_schema_keys.join(", "),
        ));
    }

    for key in &schema_unique {
        validate_governance_explicitness_from_lists(
            allowed_keys,
            explicit_validator_keys,
            explicit_value_rule_keys,
            key,
        )
        .map_err(|err| {
            format!(
                "governance schema invalid-sample registry must remain explicit-validator complete for {}: {}",
                key, err
            )
        })?;
    }

    Ok(())
}

fn validate_governance_schema_sample_registry_shape() -> Result<(), String> {
    validate_governance_schema_sample_registry_shape_from_lists(
        GOV_ALLOWED_KEYS,
        GOV_EXPLICIT_VALIDATOR_KEYS,
        GOV_EXPLICIT_VALUE_RULE_KEYS,
        GOV_SCHEMA_INVALID_SAMPLES,
    )
}

#[cfg(test)]
fn validate_governance_key_registration_lists(
    gov_param_key_index: &BTreeMap<String, u64>,
    key: &str,
    key_id: u64,
    allowed_keys: &[&str],
    sensitive_keys: &[&str],
    explicit_validator_keys: &[&str],
    explicit_value_rule_keys: &[&str],
    pinned_key_ids: &[(&str, u64)],
) -> Result<(), String> {
    validate_governance_registry_shape_lists(
        allowed_keys,
        sensitive_keys,
        explicit_validator_keys,
        explicit_value_rule_keys,
        pinned_key_ids,
    )?;
    validate_requested_governance_key_canonical(key)?;
    validate_governance_explicitness_from_lists(
        allowed_keys,
        explicit_validator_keys,
        explicit_value_rule_keys,
        key,
    )?;
    validate_governance_key_id_from_lists(pinned_key_ids, key, key_id)?;
    if let Some(existing_key_id) = gov_param_key_index.get(key).copied() {
        if existing_key_id != key_id {
            return Err(format!(
                "governance key id mismatch for {}: existing_id={}, attempted_id={}",
                key, existing_key_id, key_id
            ));
        }
    }
    if let Some((existing_key, _)) =
        gov_param_key_index
            .iter()
            .find(|(existing_key, existing_key_id)| {
                existing_key.as_str() != key && **existing_key_id == key_id
            })
    {
        return Err(format!(
            "governance key id collision for {}: id {} already assigned to {}",
            key, key_id, existing_key
        ));
    }
    Ok(())
}

const RESERVED_SYSTEM_AUTHORITY: &str = "system";
const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";
const WORKER_SLASH_TREASURY_ACCOUNT: &str = "treasury.worker_slashes";
const RESOLVE_ACTOR_ID_MAX_LEN: usize = 128;

fn resolve_actor_has_forbidden_separator(token: &str) -> bool {
    token.contains(',')
        || token.contains(';')
        || token.contains('|')
        || token.contains('；')
        || token.contains('，')
        || token.contains('、')
}

fn task_snapshot_metadata_is_complete(task: &TaskObject) -> bool {
    let has_embedded_space_or_control =
        |value: &str| value.chars().any(|c| c.is_whitespace() || c.is_control());
    let has_canonical_optional_metadata = |value: Option<&str>| {
        value
            .map(|value| {
                let trimmed = value.trim();
                !trimmed.is_empty() && trimmed == value && !has_embedded_space_or_control(value)
            })
            .unwrap_or(true)
    };
    let has_canonical_note_metadata = |value: Option<&str>| {
        value
            .map(|value| {
                !value.trim().is_empty()
                    && value.trim() == value
                    && !value.chars().any(|c| c.is_control())
            })
            .unwrap_or(true)
    };

    task.metadata
        .as_ref()
        .map(|metadata| {
            has_canonical_note_metadata(metadata.note.as_deref())
                && has_canonical_optional_metadata(metadata.task_type.as_deref())
                && has_canonical_optional_metadata(metadata.input_hash.as_deref())
                && metadata
                    .model
                    .as_ref()
                    .map(|model| {
                        has_canonical_optional_metadata(model.model_id.as_deref())
                            && has_canonical_optional_metadata(model.model_digest.as_deref())
                            && has_canonical_optional_metadata(model.version.as_deref())
                    })
                    .unwrap_or(true)
                && metadata
                    .provenance
                    .as_ref()
                    .map(|provenance| {
                        has_canonical_optional_metadata(provenance.producer_did.as_deref())
                            && has_canonical_optional_metadata(provenance.produced_at.as_deref())
                            && has_canonical_optional_metadata(
                                provenance.provenance_index.as_deref(),
                            )
                    })
                    .unwrap_or(true)
                && metadata
                    .metering
                    .as_ref()
                    .map(|metering| {
                        let workload_class = metering.workload_class.trim();
                        let metering_schema = metering.metering_schema.trim();
                        let receipt_hash = metering.receipt_hash.trim();

                        !workload_class.is_empty()
                            && workload_class == metering.workload_class
                            && !has_embedded_space_or_control(&metering.workload_class)
                            && !metering_schema.is_empty()
                            && metering_schema == metering.metering_schema
                            && !has_embedded_space_or_control(&metering.metering_schema)
                            && metering.policy_snapshot_version != 0
                            && !receipt_hash.is_empty()
                            && receipt_hash == metering.receipt_hash
                            && !has_embedded_space_or_control(&metering.receipt_hash)
                            && metering.challenge_success_bounty_per_work_unit_den != 0
                            && metering.worker_completion_bonus_per_work_unit_den != 0
                            && metering.worker_slash_rebate_per_work_unit_den != 0
                    })
                    .unwrap_or(true)
        })
        .unwrap_or(true)
}

fn challenged_task_snapshot_anchor_is_complete(task: &TaskObject) -> bool {
    task.challenged_at_height.is_some()
        && task.challenge_deadline_height.is_some()
        && task.resolve_deadline_height.is_some()
        && task
            .challenge_window_blocks_snapshot
            .is_some_and(|window| window != 0)
}

fn resolve_actor_is_reserved(token: &str) -> bool {
    token.eq_ignore_ascii_case(DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER)
        || token.eq_ignore_ascii_case(RESERVED_SYSTEM_AUTHORITY)
        || token.eq_ignore_ascii_case(CHALLENGE_ESCROW_ACCOUNT)
        || token.eq_ignore_ascii_case(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        || token.eq_ignore_ascii_case(WORKER_SLASH_TREASURY_ACCOUNT)
        || token.eq_ignore_ascii_case("governance.emergency_pause")
        || token.eq_ignore_ascii_case("emergency_pause")
}

fn validate_resolve_approver_token(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("resolve approval approver must be non-empty".into());
    }
    if trimmed != raw || trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(
            "resolve approval approver must not contain whitespace or control characters".into(),
        );
    }
    if trimmed.len() > RESOLVE_ACTOR_ID_MAX_LEN {
        return Err(format!(
            "resolve approval approver exceeds max length {}",
            RESOLVE_ACTOR_ID_MAX_LEN
        ));
    }
    if resolve_actor_has_forbidden_separator(trimmed) || !trimmed.is_ascii() {
        return Err("resolve approval approver must be a single canonical actor id".into());
    }
    if resolve_actor_is_reserved(trimmed) {
        return Err("resolve approval approver must be an explicit non-system authority".into());
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn canonicalize_resolve_authority_set(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("resolve approval authority set must be non-empty and non-whitespace".into());
    }
    if trimmed != raw {
        return Err(
            "resolve approval authority set must be canonical (no leading/trailing whitespace)"
                .into(),
        );
    }
    if trimmed.len() > RESOLVE_ACTOR_ID_MAX_LEN {
        return Err(format!(
            "resolve approval authority set exceeds max length {}",
            RESOLVE_ACTOR_ID_MAX_LEN
        ));
    }

    if trimmed.contains('|')
        || trimmed.contains('；')
        || trimmed.contains('，')
        || trimmed.contains('、')
    {
        return Err("resolve approval authority set contains forbidden separator".into());
    }
    if trimmed.contains(';') {
        return Err("resolve approval authority set contains forbidden separator".into());
    }

    let authority_members: Vec<&str> = trimmed.split(',').collect();
    if authority_members.len() < 2 {
        return Err("resolve approval authority set must include at least two members".into());
    }

    let mut seen_members = std::collections::BTreeSet::new();
    for member in &authority_members {
        let member_trimmed = member.trim();
        if member_trimmed.is_empty() {
            return Err(
                "resolve approval authority set contains empty/canonical-whitespace-only member"
                    .into(),
            );
        }
        if member_trimmed != *member {
            return Err(
                "resolve approval authority set contains invalid whitespace around member".into(),
            );
        }
        if member_trimmed
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(
                "resolve approval authority set contains whitespace or control character".into(),
            );
        }
        if member_trimmed.len() > RESOLVE_ACTOR_ID_MAX_LEN {
            return Err("resolve approval authority member exceeds max length".into());
        }
        if resolve_actor_has_forbidden_separator(member_trimmed) {
            return Err("resolve approval authority set contains forbidden separator".into());
        }
        if !member_trimmed.is_ascii() {
            return Err("resolve approval authority members must be ASCII-only".into());
        }
        if resolve_actor_is_reserved(member_trimmed) {
            return Err("resolve approval authority set contains forbidden member".into());
        }
        if !seen_members.insert(member_trimmed.to_ascii_lowercase()) {
            return Err("resolve approval authority set must not contain duplicate members".into());
        }
    }

    Ok(seen_members.into_iter().collect::<Vec<_>>().join(","))
}

fn ensure_effective_resolve_authority_match(
    st: &StateStore,
    authority_set: &str,
) -> Result<(), String> {
    let provided = canonicalize_resolve_authority_set(authority_set)?;
    if let Some(pending) = st.pending_gov_update("resolve_authority") {
        let expected = canonicalize_resolve_authority_set(&pending.value).map_err(|_| {
            "resolve approval authority set must match pending governance authority".to_string()
        })?;
        if expected != provided {
            return Err(
                "resolve approval authority set must match pending governance authority".into(),
            );
        }
        return Ok(());
    }
    if let Some(current) = st.gov_param_string("resolve_authority") {
        let expected = canonicalize_resolve_authority_set(&current).map_err(|_| {
            "resolve approval authority set must match configured governance authority".to_string()
        })?;
        if expected != provided {
            return Err(
                "resolve approval authority set must match configured governance authority".into(),
            );
        }
    }
    Ok(())
}

fn is_effective_resolve_authority_match(st: &StateStore, authority_set: &str) -> bool {
    ensure_effective_resolve_authority_match(st, authority_set).is_ok()
}

fn validated_restorable_pending_resolve_snapshot(
    st: &StateStore,
    task_id: u64,
    snapshot: PendingResolveApprovalSnapshot,
    enforce_pause_metadata_guard: bool,
) -> Option<PendingResolveApproval> {
    if task_id == 0 || snapshot.task_version == 0 {
        return None;
    }
    if !matches!(snapshot.confirmations, 1 | 2) {
        return None;
    }
    let Ok(first_approver_canonical) = validate_resolve_approver_token(&snapshot.first_approver)
    else {
        return None;
    };
    let Ok(authority_canonical) = canonicalize_resolve_authority_set(&snapshot.authority_set)
    else {
        return None;
    };
    if !authority_canonical
        .split(',')
        .any(|member| member == first_approver_canonical)
    {
        return None;
    }
    if !is_effective_resolve_authority_match(st, &snapshot.authority_set) {
        return None;
    }

    let task = match st.get_task(task_id) {
        Some(task) => task,
        None => {
            if st
                .objects
                .get(&task_id)
                .is_some_and(|object| !matches!(object.value, ObjectValue::Task(_)))
            {
                return None;
            }
            if st.is_emergency_paused() || snapshot.confirmations != 1 {
                return None;
            }

            if st
                .pending_resolve_approvals
                .iter()
                .any(|(other_task_id, existing)| {
                    *other_task_id != task_id
                        && existing.confirmations == snapshot.confirmations
                        && existing.slash_worker == snapshot.slash_worker
                        && existing.task_version == snapshot.task_version
                        && validate_resolve_approver_token(&existing.first_approver)
                            .map(|existing_first| existing_first == first_approver_canonical)
                            .unwrap_or(false)
                        && canonicalize_resolve_authority_set(&existing.authority_set)
                            .map(|existing_authority| existing_authority == authority_canonical)
                            .unwrap_or(false)
                })
            {
                return None;
            }

            return Some(PendingResolveApproval {
                slash_worker: snapshot.slash_worker,
                confirmations: snapshot.confirmations,
                first_approver: first_approver_canonical,
                authority_set: authority_canonical,
                task_version: snapshot.task_version,
                stored_as_canonical: false,
            });
        }
    };

    if task.status != TaskStatus::Challenged {
        return None;
    }
    if st
        .get_ref(task_id)
        .is_none_or(|object| object.version != snapshot.task_version)
    {
        return None;
    }

    let has_canonical_actor = |actor: &str| validate_resolve_approver_token(actor).is_ok();
    let has_resolve_authority = st.gov_param_string("resolve_authority").is_some()
        || st.pending_gov_update("resolve_authority").is_some();

    if st.is_emergency_paused() {
        if !task.challenger.as_deref().is_some_and(has_canonical_actor) {
            return None;
        }
        if !task_snapshot_metadata_is_complete(&task) {
            return None;
        }
        if snapshot.slash_worker
            && task
                .worker
                .as_deref()
                .is_some_and(resolve_actor_is_reserved)
        {
            return None;
        }
        if task.challenge_bond.is_some() && snapshot.confirmations == 1 {
            if !challenged_task_snapshot_anchor_is_complete(&task) {
                return None;
            }
        } else if !has_resolve_authority && snapshot.confirmations == 1 {
            return None;
        }

        // Legacy pause-boundary hardening keeps fully canonical single-approver snapshots from
        // replaying on metadata-lacking tasks, while allowing non-canonical drift variants to
        // preserve state-root-equivalent recovery behavior in existing acceptance paths.
        if enforce_pause_metadata_guard
            && task.metadata.is_none()
            && has_resolve_authority
            && snapshot.confirmations == 1
            && first_approver_canonical == snapshot.first_approver
            && authority_canonical == snapshot.authority_set
        {
            return None;
        }

        // Avoid admitting finalized two-party snapshots while a pending resolve-authority
        // replacement is still in-flight; without an explicit second approver encoding this path
        // is ambiguous under replacement semantics.
        if snapshot.confirmations == 2
            && st.pending_gov_update("resolve_authority").is_some()
            && task.challenge_bond.is_none()
        {
            return None;
        }
    } else {
        if snapshot.confirmations == 2 && task.challenge_bond.is_none() {
            return None;
        }
        if snapshot.confirmations == 2 && task.challenge_bond_forfeited.is_none() {
            return None;
        }
        if !task.challenger.as_deref().is_some_and(has_canonical_actor) {
            return None;
        }
    }

    let stored_first_approver = if st.is_emergency_paused() {
        snapshot.first_approver.clone()
    } else {
        first_approver_canonical.clone()
    };
    let stored_authority_set = if st.is_emergency_paused() {
        snapshot.authority_set.clone()
    } else {
        authority_canonical.clone()
    };

    Some(PendingResolveApproval {
        slash_worker: snapshot.slash_worker,
        confirmations: snapshot.confirmations,
        // Persist canonicalized identifiers so case/order-equivalent replays settle to a
        // deterministic in-memory and state-root form.
        first_approver: stored_first_approver,
        authority_set: stored_authority_set,
        task_version: snapshot.task_version,
        stored_as_canonical: false,
    })
}

fn is_sensitive_gov_param(key: &str) -> bool {
    GOV_SENSITIVE_KEYS.contains(&key)
}

fn check_sensitive_rate_limit(key: &str, old: u64, new: u64) -> Result<(), String> {
    let delta = ((old.saturating_mul(GOV_SENSITIVE_PARAM_MAX_CHANGE_BPS)) / 10_000).max(1);
    let min_allowed = old.saturating_sub(delta);
    let max_allowed = old.saturating_add(delta);
    if new < min_allowed || new > max_allowed {
        return Err(format!(
            "governance rate-limit exceeded for {}: old={}, new={}, allowed=[{}..={}] (max_change_bps={})",
            key, old, new, min_allowed, max_allowed, GOV_SENSITIVE_PARAM_MAX_CHANGE_BPS
        ));
    }
    Ok(())
}
fn hash_len_prefixed_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hash_len_prefixed_str(hasher: &mut Sha256, value: &str) {
    hash_len_prefixed_bytes(hasher, value.as_bytes());
}

fn hash_pending_resolve_approval(
    hasher: &mut Sha256,
    task_id: u64,
    pending: &PendingResolveApproval,
) {
    hasher.update(b"resolve_pending");
    hasher.update(task_id.to_le_bytes());
    hasher.update([pending.slash_worker as u8]);
    hasher.update([pending.confirmations]);

    let canonical_first_approver = validate_resolve_approver_token(&pending.first_approver)
        .unwrap_or_else(|_| pending.first_approver.clone());
    let canonical_authority_set = canonicalize_resolve_authority_set(&pending.authority_set)
        .unwrap_or_else(|_| pending.authority_set.clone());

    hash_len_prefixed_str(hasher, &canonical_first_approver);
    hash_len_prefixed_str(hasher, &canonical_authority_set);
    hasher.update(pending.task_version.to_le_bytes());
}

fn hash_task_metering_snapshot(hasher: &mut Sha256, metering: &trnm_types::TaskMeteringSnapshot) {
    hash_len_prefixed_str(hasher, &metering.workload_class);
    hash_len_prefixed_str(hasher, &metering.metering_schema);
    hasher.update([metering.policy_snapshot_version]);
    hash_len_prefixed_str(hasher, &metering.receipt_hash);
    hasher.update(metering.prompt_tokens.to_le_bytes());
    hasher.update(metering.generated_tokens.to_le_bytes());
    hasher.update(metering.decode_steps.to_le_bytes());
    hasher.update(metering.kv_bytes_moved.to_le_bytes());
    hasher.update(metering.normalized_work_units.to_le_bytes());
    hasher.update(metering.prompt_token_weight.to_le_bytes());
    hasher.update(metering.generated_token_weight.to_le_bytes());
    hasher.update(metering.decode_step_weight.to_le_bytes());
    hasher.update(metering.kv_byte_weight.to_le_bytes());
    hasher.update(metering.min_accept_work_units.to_le_bytes());
    hasher.update(metering.challenge_success_bounty_base.to_le_bytes());
    hasher.update(
        metering
            .challenge_success_bounty_per_work_unit_num
            .to_le_bytes(),
    );
    hasher.update(
        metering
            .challenge_success_bounty_per_work_unit_den
            .to_le_bytes(),
    );
    hasher.update(
        metering
            .worker_completion_bonus_per_work_unit_num
            .to_le_bytes(),
    );
    hasher.update(
        metering
            .worker_completion_bonus_per_work_unit_den
            .to_le_bytes(),
    );
    hasher.update(metering.worker_slash_rebate_per_work_unit_num.to_le_bytes());
    hasher.update(metering.worker_slash_rebate_per_work_unit_den.to_le_bytes());
}

fn parse_u64_in_range(key: &str, value: &str, min: u64, max: u64) -> Result<u64, String> {
    let parsed = value.parse::<u64>().map_err(|_| {
        format!(
            "invalid governance value for {}: expected u64, got '{}'",
            key, value
        )
    })?;
    if parsed < min || parsed > max {
        return Err(format!(
            "invalid governance value for {}: out of range [{}..={}], got {}",
            key, min, max, parsed
        ));
    }
    Ok(parsed)
}

fn parse_bool_strict(key: &str, value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!(
            "invalid governance value for {}: expected strict bool 'true' or 'false', got '{}'",
            key, value
        )),
    }
}

#[allow(dead_code)]
fn has_explicit_gov_param_validator_from_lists(
    explicit_validator_keys: &[&str],
    explicit_value_rule_keys: &[&str],
    key: &str,
) -> bool {
    explicit_validator_keys.contains(&key) && explicit_value_rule_keys.contains(&key)
}

#[allow(dead_code)]
fn has_explicit_gov_param_validator(key: &str) -> bool {
    has_explicit_gov_param_validator_from_lists(
        GOV_EXPLICIT_VALIDATOR_KEYS,
        GOV_EXPLICIT_VALUE_RULE_KEYS,
        key,
    )
}

fn validate_governance_explicitness_from_lists(
    allowed_keys: &[&str],
    explicit_validator_keys: &[&str],
    explicit_value_rule_keys: &[&str],
    key: &str,
) -> Result<(), String> {
    if !allowed_keys.contains(&key) {
        return Err(format!(
            "no explicit validator registered for governance key: {}",
            key
        ));
    }
    if !explicit_validator_keys.contains(&key) {
        return Err(format!(
            "governance validator coverage missing for allowed key: {}",
            key
        ));
    }
    if !explicit_value_rule_keys.contains(&key) {
        return Err(format!(
            "governance validator missing explicit value rule for allowed key: {}",
            key
        ));
    }
    if !has_explicit_gov_param_value_match_coverage_from_lists(
        explicit_validator_keys,
        explicit_value_rule_keys,
        key,
    ) {
        return Err(format!(
            "governance validator missing explicit match coverage for allowed key: {}",
            key
        ));
    }
    Ok(())
}

fn validate_governance_validator_coverage_from_lists(
    allowed_keys: &[&str],
    sensitive_keys: &[&str],
    explicit_validator_keys: &[&str],
    explicit_value_rule_keys: &[&str],
    pinned_key_ids: &[(&str, u64)],
    key: &str,
) -> Result<(), String> {
    validate_governance_registry_shape_lists(
        allowed_keys,
        sensitive_keys,
        explicit_validator_keys,
        explicit_value_rule_keys,
        pinned_key_ids,
    )?;
    validate_requested_governance_key_canonical(key)?;
    validate_governance_explicitness_from_lists(
        allowed_keys,
        explicit_validator_keys,
        explicit_value_rule_keys,
        key,
    )
}

fn validate_governance_validator_coverage(key: &str) -> Result<(), String> {
    validate_governance_validator_coverage_from_lists(
        GOV_ALLOWED_KEYS,
        GOV_SENSITIVE_KEYS,
        GOV_EXPLICIT_VALIDATOR_KEYS,
        GOV_EXPLICIT_VALUE_RULE_KEYS,
        GOV_PINNED_KEY_IDS,
        key,
    )
}

fn validate_governance_sensitive_key_coverage(key: &str) -> Result<(), String> {
    if GOV_SENSITIVE_KEYS.contains(&key) && !GOV_ALLOWED_KEYS.contains(&key) {
        return Err(format!(
            "governance sensitive-key coverage missing from allowed key registry: {}",
            key
        ));
    }
    Ok(())
}

fn validate_requested_governance_key_canonical(key: &str) -> Result<(), String> {
    validate_governance_registry_key_canonical("requested governance key", key).map_err(|_| {
        format!(
            "governance key request must use canonical key spelling: {}",
            key
        )
    })
}

#[allow(dead_code)]
fn has_explicit_gov_param_value_rule(key: &str) -> bool {
    GOV_EXPLICIT_VALUE_RULE_KEYS.contains(&key)
}

fn has_explicit_gov_param_value_match_coverage_from_lists(
    explicit_validator_keys: &[&str],
    explicit_value_rule_keys: &[&str],
    key: &str,
) -> bool {
    explicit_validator_keys.contains(&key) && explicit_value_rule_keys.contains(&key)
}

#[allow(dead_code)]
fn has_explicit_gov_param_value_match_coverage(key: &str) -> bool {
    has_explicit_gov_param_value_match_coverage_from_lists(
        GOV_EXPLICIT_VALIDATOR_KEYS,
        GOV_EXPLICIT_VALUE_RULE_KEYS,
        key,
    )
}

fn validate_gov_param_value(key: &str, value: &str) -> Result<(), String> {
    let normalize = |key: &str, err: String| {
        if err.contains("invalid governance value for ") {
            Ok::<(), String>(())
        } else {
            Err(format!("invalid governance value for {}: {}", key, err))
        }
    };
    validate_governance_registry_shape()
        .map_err(|err| format!("invalid governance value for {}: {}", key, err))?;
    validate_governance_schema_sample_registry_shape()
        .map_err(|err| format!("invalid governance value for {}: {}", key, err))?;
    validate_requested_governance_key_canonical(key)
        .map_err(|err| format!("invalid governance value for {}: {}", key, err))?;
    validate_governance_validator_coverage(key)
        .map_err(|err| format!("invalid governance value for {}: {}", key, err))?;
    validate_governance_sensitive_key_coverage(key)
        .map_err(|err| format!("invalid governance value for {}: {}", key, err))?;

    match key {
        "max_block_ms" => {
            let _ = parse_u64_in_range(key, value, 10, 120_000)?;
            Ok(())
        }
        "max_parallel_workers" => {
            let _ = parse_u64_in_range(key, value, 1, 65_536)?;
            Ok(())
        }
        "challenge_window_blocks" => {
            let _ = parse_u64_in_range(key, value, 100, 600)?;
            Ok(())
        }
        "min_worker_stake" => {
            let _ = parse_u64_in_range(key, value, 1, 1_000_000_000_000)?;
            Ok(())
        }
        "challenge_min_bond" => {
            let _ = parse_u64_in_range(key, value, 1, 1_000_000_000_000)?;
            Ok(())
        }
        "challenge_success_bounty" => {
            let _ = parse_u64_in_range(key, value, 0, 1_000_000_000_000)?;
            Ok(())
        }
        "llm_meter_prompt_token_weight"
        | "llm_meter_generated_token_weight"
        | "llm_meter_decode_step_weight"
        | "llm_meter_kv_byte_weight"
        | "llm_meter_min_accept_work_units"
        | "llm_meter_challenge_success_bounty_per_work_unit_num"
        | "llm_meter_worker_completion_bonus_per_work_unit_num"
        | "llm_meter_worker_slash_rebate_per_work_unit_num" => {
            let _ = parse_u64_in_range(key, value, 0, 1_000_000_000_000)?;
            Ok(())
        }
        "llm_meter_challenge_success_bounty_per_work_unit_den"
        | "llm_meter_worker_completion_bonus_per_work_unit_den"
        | "llm_meter_worker_slash_rebate_per_work_unit_den" => {
            let _ = parse_u64_in_range(key, value, 1, 1_000_000_000_000)?;
            Ok(())
        }
        "challenge_min_bond_bounty_bps" | "challenge_min_bond_worker_stake_bps" => {
            let _ = parse_u64_in_range(key, value, 0, 100_000)?;
            Ok(())
        }
        "resolve_authority" => validate_resolve_authority_governance_value(key, value)
            .map_err(|err| format!("invalid governance value for {}: {}", key, err)),
        "emergency_pause" => {
            let _ = parse_bool_strict(key, value)?;
            Ok(())
        }
        "monetary_policy_tick_interval_blocks" => {
            let _ = parse_u64_in_range(key, value, 1, 100_000)?;
            Ok(())
        }
        "monetary_policy_tick_cooldown_blocks" => {
            let _ = parse_u64_in_range(key, value, 1, 100_000)?;
            Ok(())
        }
        "monetary_base_issuance_per_tick" | "monetary_base_burn_per_tick" => {
            let _ = parse_u64_in_range(key, value, 0, 1_000_000_000_000)?;
            Ok(())
        }
        _ => normalize(
            key,
            format!(
                "governance validator missing explicit match coverage for allowed key: {}",
                key
            ),
        ),
    }
}

fn validate_resolve_authority_governance_value(key: &str, value: &str) -> Result<(), String> {
    if key != "resolve_authority" {
        return Ok(());
    }
    canonicalize_resolve_authority_set(value).map(|_| ())
}

fn task_supports_pending_resolve_restore(task: &TaskObject) -> bool {
    task.status == TaskStatus::Challenged
        && matches!(task.challenge_deadline_height, Some(height) if height > 0)
        && matches!(task.challenge_window_blocks_snapshot, Some(window) if window > 0)
        && matches!(task.challenged_at_height, Some(height) if height > 0)
        && matches!(task.resolve_deadline_height, Some(height) if height > 0)
        && matches!(task.challenge_bond, Some(bond) if bond > 0)
        && task
            .challenger
            .as_deref()
            .is_some_and(|challenger| validate_resolve_approver_token(challenger).is_ok())
}

fn task_supports_pending_resolve_snapshot_restore(task: &TaskObject) -> bool {
    task_supports_pending_resolve_restore(task) && task.challenge_bond_forfeited == Some(true)
}

impl StateStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stage_or_confirm_resolve_approval(
        &mut self,
        task_id: u64,
        task_version: u64,
        slash_worker: bool,
        approver: &str,
        authority_set: &str,
    ) -> Result<bool, String> {
        if task_id == 0 {
            return Err("resolve approval task id must be >= 1".into());
        }
        if task_version == 0 {
            return Err("resolve approval task version must be >= 1".into());
        }

        let approver_audit = approver.trim().to_string();
        let approver_canonical = validate_resolve_approver_token(approver)?;
        let authority_canonical = canonicalize_resolve_authority_set(authority_set)?;
        if !authority_canonical
            .split(',')
            .any(|member| member == approver_canonical)
        {
            return Err("resolve approval approver must be a configured authority member".into());
        }
        let Some(task) = self.get_task(task_id) else {
            ensure_effective_resolve_authority_match(self, authority_set)?;

            if let Some(entry) = self.pending_resolve_approvals.get(&task_id) {
                if entry.slash_worker != slash_worker {
                    return Err("resolve approval decision mismatch".into());
                }
                if entry.confirmations >= 2 {
                    return Err(
                        "resolve approval already finalized; clear pending approval first".into(),
                    );
                }
                let entry_authority_canonical =
                    canonicalize_resolve_authority_set(&entry.authority_set)
                        .map_err(|_| "resolve approval authority set changed".to_string())?;
                if entry_authority_canonical != authority_canonical {
                    self.invalidate_state_root_cache();
                    self.pending_resolve_approvals.remove(&task_id);
                    return Err("resolve approval authority set changed".into());
                }
                if entry.task_version != task_version {
                    self.invalidate_state_root_cache();
                    self.pending_resolve_approvals.remove(&task_id);
                    return Err("resolve approval task version changed".into());
                }
            }

            self.invalidate_state_root_cache();
            let is_emergency_paused = self.is_emergency_paused();
            let entry =
                self.pending_resolve_approvals
                    .entry(task_id)
                    .or_insert(PendingResolveApproval {
                        slash_worker,
                        confirmations: 0,
                        first_approver: approver_audit.clone(),
                        authority_set: authority_canonical.clone(),
                        task_version,
                        stored_as_canonical: !is_emergency_paused,
                    });
            if entry.slash_worker != slash_worker {
                return Err("resolve approval decision mismatch".into());
            }
            if entry.confirmations >= 2 {
                return Err(
                    "resolve approval already finalized; clear pending approval first".into(),
                );
            }
            if entry.confirmations > 0 {
                let first_approver_canonical =
                    validate_resolve_approver_token(&entry.first_approver)
                        .map_err(|_| "resolve approval requires distinct approver".to_string())?;
                if first_approver_canonical == approver_canonical {
                    return Err("resolve approval requires distinct approver".into());
                }
            }
            entry.confirmations = entry.confirmations.saturating_add(1);
            return Ok(entry.confirmations >= 2);
        };
        if task.status != TaskStatus::Challenged {
            if self.pending_resolve_approvals.remove(&task_id).is_some() {
                self.invalidate_state_root_cache();
            }
            return Err("resolve approval task no longer challenged".into());
        }
        if task.version != task_version {
            if self.pending_resolve_approvals.remove(&task_id).is_some() {
                self.invalidate_state_root_cache();
            }
            return Err("resolve approval task version changed".into());
        }
        if self.is_emergency_paused()
            && task.status == TaskStatus::Challenged
            && task.challenge_bond.is_some()
            && task.challenge_bond_forfeited.is_none()
            && !self.pending_resolve_approvals.contains_key(&task_id)
            && (self.gov_param_string("resolve_authority").is_some()
                || self.pending_gov_update("resolve_authority").is_some())
        {
            if self.pending_resolve_approvals.remove(&task_id).is_some() {
                self.invalidate_state_root_cache();
            }
            return Err("resolve approval task boundary metadata incomplete".into());
        }
        if self.is_emergency_paused()
            && (self.gov_param_string("resolve_authority").is_some()
                || self.pending_gov_update("resolve_authority").is_some())
            && !task_supports_pending_resolve_snapshot_restore(&task)
        {
            if self.pending_resolve_approvals.remove(&task_id).is_some() {
                self.invalidate_state_root_cache();
            }
            return Err("resolve approval task boundary metadata incomplete".into());
        }
        ensure_effective_resolve_authority_match(self, authority_set)?;

        if let Some(entry) = self.pending_resolve_approvals.get(&task_id) {
            if entry.slash_worker != slash_worker {
                return Err("resolve approval decision mismatch".into());
            }
            if entry.confirmations >= 2 {
                return Err(
                    "resolve approval already finalized; clear pending approval first".into(),
                );
            }
            let entry_authority_canonical =
                canonicalize_resolve_authority_set(&entry.authority_set)
                    .map_err(|_| "resolve approval authority set changed".to_string())?;
            if entry_authority_canonical != authority_canonical {
                self.invalidate_state_root_cache();
                self.pending_resolve_approvals.remove(&task_id);
                return Err("resolve approval authority set changed".into());
            }
            if entry.task_version != task_version {
                self.invalidate_state_root_cache();
                self.pending_resolve_approvals.remove(&task_id);
                return Err("resolve approval task version changed".into());
            }
        }

        self.invalidate_state_root_cache();
        let entry =
            self.pending_resolve_approvals
                .entry(task_id)
                .or_insert(PendingResolveApproval {
                    slash_worker,
                    confirmations: 0,
                    first_approver: approver_audit.clone(),
                    authority_set: authority_canonical.clone(),
                    task_version,
                    stored_as_canonical: true,
                });
        if entry.slash_worker != slash_worker {
            return Err("resolve approval decision mismatch".into());
        }
        if entry.confirmations >= 2 {
            return Err("resolve approval already finalized; clear pending approval first".into());
        }
        if entry.confirmations > 0 {
            let first_approver_canonical =
                validate_resolve_approver_token(&entry.first_approver)
                    .map_err(|_| "resolve approval requires distinct approver".to_string())?;
            if first_approver_canonical == approver_canonical {
                return Err("resolve approval requires distinct approver".into());
            }
        }
        entry.confirmations = entry.confirmations.saturating_add(1);
        Ok(entry.confirmations >= 2)
    }

    pub fn clear_pending_resolve_approval(&mut self, task_id: u64) {
        if self.pending_resolve_approvals.remove(&task_id).is_some() {
            self.invalidate_state_root_cache();
        }
    }

    pub fn pending_resolve_approval(&self, task_id: u64) -> Option<(bool, u8)> {
        self.pending_resolve_approvals
            .get(&task_id)
            .map(|entry| (entry.slash_worker, entry.confirmations))
    }

    pub fn pending_resolve_first_approver(&self, task_id: u64) -> Option<String> {
        self.pending_resolve_approvals
            .get(&task_id)
            .and_then(|entry| {
                if entry.stored_as_canonical {
                    validate_resolve_approver_token(&entry.first_approver).ok()
                } else {
                    Some(entry.first_approver.clone())
                }
            })
    }

    pub fn pending_resolve_approval_snapshot(
        &self,
        task_id: u64,
    ) -> Option<PendingResolveApprovalSnapshot> {
        self.pending_resolve_approvals
            .get(&task_id)
            .map(|entry| PendingResolveApprovalSnapshot {
                slash_worker: entry.slash_worker,
                confirmations: entry.confirmations,
                first_approver: if entry.stored_as_canonical {
                    validate_resolve_approver_token(&entry.first_approver)
                        .unwrap_or_else(|_| entry.first_approver.clone())
                } else {
                    entry.first_approver.clone()
                },
                authority_set: if entry.stored_as_canonical {
                    canonicalize_resolve_authority_set(&entry.authority_set)
                        .unwrap_or_else(|_| entry.authority_set.clone())
                } else {
                    entry.authority_set.clone()
                },
                task_version: entry.task_version,
            })
    }

    fn canonical_pending_resolve_approval_snapshot_for_task(
        &self,
        task_id: u64,
        task: &TaskObject,
        snapshot: &PendingResolveApprovalSnapshot,
    ) -> Option<(String, String)> {
        if task_id == 0 || snapshot.task_version == 0 {
            return None;
        }
        if !matches!(snapshot.confirmations, 1 | 2) {
            return None;
        }
        let Ok(first_approver_canonical) =
            validate_resolve_approver_token(&snapshot.first_approver)
        else {
            return None;
        };
        let Ok(authority_canonical) = canonicalize_resolve_authority_set(&snapshot.authority_set)
        else {
            return None;
        };
        if !authority_canonical
            .split(',')
            .any(|member| member == first_approver_canonical)
        {
            return None;
        }
        if !is_effective_resolve_authority_match(self, &authority_canonical) {
            return None;
        }
        let Some(current_ref) = self.get_ref(task_id) else {
            return None;
        };
        if task.task_id != task_id
            || task.status != TaskStatus::Challenged
            || task.version != snapshot.task_version
            || current_ref.version != snapshot.task_version
        {
            return None;
        }
        if snapshot.confirmations == 2 && !task_supports_pending_resolve_snapshot_restore(&task) {
            return None;
        }

        Some((first_approver_canonical, authority_canonical))
    }

    fn canonical_pending_resolve_approval_snapshot(
        &self,
        task_id: u64,
        snapshot: &PendingResolveApprovalSnapshot,
    ) -> Option<(String, String)> {
        let task = self.get_task(task_id)?;
        self.canonical_pending_resolve_approval_snapshot_for_task(task_id, &task, snapshot)
    }

    fn canonical_pending_resolve_reentry_snapshot(
        &self,
        task_id: u64,
        snapshot: &PendingResolveApprovalSnapshot,
    ) -> Option<(String, String)> {
        if task_id == 0 || !matches!(snapshot.confirmations, 1 | 2) || snapshot.task_version == 0 {
            return None;
        }
        let task = self.get_task(task_id)?;
        let current_ref = self.get_ref(task_id)?;
        if task.task_id != task_id
            || task.status != TaskStatus::Challenged
            || task.version != snapshot.task_version
            || current_ref.version != snapshot.task_version
        {
            return None;
        }

        let Ok(first_approver_canonical) =
            validate_resolve_approver_token(&snapshot.first_approver)
        else {
            return None;
        };
        let Ok(authority_canonical) = canonicalize_resolve_authority_set(&snapshot.authority_set)
        else {
            return None;
        };
        if !authority_canonical
            .split(',')
            .any(|member| member == first_approver_canonical)
        {
            return None;
        }
        if !is_effective_resolve_authority_match(self, &authority_canonical) {
            return None;
        }

        Some((first_approver_canonical, authority_canonical))
    }

    fn pending_resolve_matches_task_version(&self, task_id: u64, task_version: u64) -> bool {
        self.pending_resolve_approvals
            .get(&task_id)
            .map(|pending| pending.task_version == task_version)
            .unwrap_or(false)
    }

    fn matches_pending_resolve_restore_reentry_snapshot(
        &self,
        task_id: u64,
        snapshot: &PendingResolveApprovalSnapshot,
    ) -> bool {
        if !matches!(snapshot.confirmations, 1 | 2) {
            return false;
        }

        let Some(existing) = self.pending_resolve_approvals.get(&task_id) else {
            return false;
        };
        if existing.confirmations != snapshot.confirmations {
            return false;
        }

        let Some((snapshot_first_approver, snapshot_authority_set)) =
            self.canonical_pending_resolve_reentry_snapshot(task_id, snapshot)
        else {
            return false;
        };
        let Ok(existing_first_approver) = validate_resolve_approver_token(&existing.first_approver)
        else {
            return false;
        };
        let Ok(existing_authority_set) =
            canonicalize_resolve_authority_set(&existing.authority_set)
        else {
            return false;
        };

        existing.slash_worker == snapshot.slash_worker
            && existing.confirmations == snapshot.confirmations
            && existing.task_version == snapshot.task_version
            && existing_first_approver == snapshot_first_approver
            && existing_authority_set == snapshot_authority_set
    }

    fn matches_task_restore_reentry_snapshot(&self, id: u64, task: &TaskObject) -> bool {
        let Some(current) = self.objects.get(&id) else {
            return false;
        };
        match &current.value {
            ObjectValue::Task(existing) => current.version == task.version && *existing == *task,
            _ => false,
        }
    }

    fn pending_resolve_restore_reentry_snapshot(
        &self,
        task_id: u64,
    ) -> Option<PendingResolveApprovalSnapshot> {
        let pending = self.pending_resolve_approvals.get(&task_id)?;
        Some(PendingResolveApprovalSnapshot {
            slash_worker: pending.slash_worker,
            confirmations: pending.confirmations,
            first_approver: pending.first_approver.clone(),
            authority_set: pending.authority_set.clone(),
            task_version: pending.task_version,
        })
    }

    fn should_preserve_pending_resolve_on_task_restore(
        &self,
        task_id: u64,
        task: &TaskObject,
    ) -> bool {
        if !self.matches_task_restore_reentry_snapshot(task_id, task)
            || task.status != TaskStatus::Challenged
            || self
                .gov_param_key_index
                .values()
                .any(|mapped_id| *mapped_id == task_id)
        {
            return false;
        }
        if !self.pending_resolve_matches_task_version(task_id, task.version) {
            return false;
        }
        let Some(snapshot) = self.pending_resolve_restore_reentry_snapshot(task_id) else {
            return false;
        };
        if !matches!(snapshot.confirmations, 1 | 2) {
            return false;
        }
        self.canonical_pending_resolve_approval_snapshot(task_id, &snapshot)
            .is_some()
    }

    pub fn restore_pending_resolve_approval(
        &mut self,
        task_id: u64,
        snapshot: Option<PendingResolveApprovalSnapshot>,
    ) {
        self.restore_pending_resolve_approval_internal(task_id, snapshot, true);
    }

    pub fn restore_pending_resolve_approval_from_rollback(
        &mut self,
        task_id: u64,
        snapshot: Option<PendingResolveApprovalSnapshot>,
    ) {
        self.restore_pending_resolve_approval_internal(task_id, snapshot, false);
    }

    fn restore_pending_resolve_approval_internal(
        &mut self,
        task_id: u64,
        snapshot: Option<PendingResolveApprovalSnapshot>,
        enforce_pause_metadata_guard: bool,
    ) {
        if let Some(snapshot) = snapshot.as_ref() {
            if self.matches_pending_resolve_restore_reentry_snapshot(task_id, snapshot) {
                return;
            }
            if let Some(pending) = validated_restorable_pending_resolve_snapshot(
                self,
                task_id,
                snapshot.clone(),
                enforce_pause_metadata_guard,
            ) {
                self.invalidate_state_root_cache();
                self.pending_resolve_approvals.insert(task_id, pending);
                return;
            }
        }

        self.invalidate_state_root_cache();
        self.pending_resolve_approvals.remove(&task_id);
    }

    fn has_pending_resolve_restore_reentry_boundary_hazard(
        &self,
        id: u64,
        task: &TaskObject,
    ) -> bool {
        self.pending_resolve_approvals.get(&id).is_some()
            && !self.should_preserve_pending_resolve_on_task_restore(id, task)
    }

    fn matches_task_restore_reentry_boundary(&self, id: u64, task: &TaskObject) -> bool {
        if self
            .gov_param_key_index
            .values()
            .any(|mapped_id| *mapped_id == id)
        {
            return false;
        }
        self.matches_task_restore_reentry_snapshot(id, task)
    }

    fn task_restore_reentry_boundary_action(
        &self,
        id: u64,
        task: &TaskObject,
    ) -> TaskRestoreReentryBoundaryAction {
        if !self.matches_task_restore_reentry_boundary(id, task) {
            return TaskRestoreReentryBoundaryAction::Reapply;
        }
        if self.has_pending_resolve_restore_reentry_boundary_hazard(id, task) {
            // When emergency pause is active, preserve staged resolve quorum snapshots across
            // replay/version-drift reentry. Higher-level rollback logic is already aborting tx
            // execution under pause, so stale-looking staged entries must remain available for
            // exact rollback restoration.
            if self.is_emergency_paused() {
                return TaskRestoreReentryBoundaryAction::Reapply;
            }
            return TaskRestoreReentryBoundaryAction::ScrubPendingResolve;
        }
        TaskRestoreReentryBoundaryAction::Noop
    }

    fn scrub_pending_resolve_on_task_restore_reentry(&mut self, id: u64) {
        self.invalidate_state_root_cache();
        self.pending_resolve_approvals.remove(&id);
    }

    pub fn restore_task(&mut self, id: u64, snapshot: Option<TaskObject>) {
        if let Some(task) = snapshot.as_ref() {
            if task.task_id == id
                && self
                    .gov_param_key_index
                    .values()
                    .any(|mapped_id| *mapped_id == id)
                && !self.objects.contains_key(&id)
            {
                if self.pending_resolve_approvals.remove(&id).is_some() {
                    self.invalidate_state_root_cache();
                }
                return;
            }

            if task.task_id == id {
                match self.task_restore_reentry_boundary_action(id, task) {
                    TaskRestoreReentryBoundaryAction::Noop => return,
                    TaskRestoreReentryBoundaryAction::ScrubPendingResolve => {
                        self.scrub_pending_resolve_on_task_restore_reentry(id);
                        return;
                    }
                    TaskRestoreReentryBoundaryAction::Reapply => {}
                }
            }
        }

        if let Some(existing) = self.objects.get(&id) {
            let is_task = matches!(existing.value, ObjectValue::Task(_));
            if !is_task {
                if snapshot.is_some() {
                    self.invalidate_state_root_cache();
                    self.objects.remove(&id);
                    self.pending_resolve_approvals.remove(&id);
                    return;
                }
            }
        }

        self.invalidate_state_root_cache();
        match snapshot {
            Some(task) => {
                if id == 0 || task.task_id != id || task.version == 0 {
                    self.pending_resolve_approvals.remove(&id);
                    self.objects.remove(&id);
                    self.pending_resolve_approvals.remove(&id);
                    return;
                }
                if !task_snapshot_metadata_is_complete(&task) {
                    self.pending_resolve_approvals.remove(&id);
                    self.objects.remove(&id);
                    return;
                }

                if task.status == TaskStatus::Challenged
                    && !self.is_emergency_paused()
                    && task.challenge_bond.is_none()
                {
                    self.pending_resolve_approvals.remove(&id);
                    self.objects.remove(&id);
                    return;
                }
                let pending_confirmations = self
                    .pending_resolve_approvals
                    .get(&id)
                    .map(|entry| entry.confirmations)
                    .unwrap_or(0);

                if task.status == TaskStatus::Challenged
                    && task.challenge_bond.is_some()
                    && task.challenge_bond_forfeited.is_none()
                    && task.metadata.is_none()
                    && self.is_emergency_paused()
                    && matches!(pending_confirmations, 1)
                    && self.gov_param_string("resolve_authority").is_none()
                    && self.pending_gov_update("resolve_authority").is_none()
                {
                    self.pending_resolve_approvals.remove(&id);
                    self.objects.remove(&id);
                    return;
                }

                let had_pending = pending_confirmations > 0;
                if self.is_emergency_paused()
                    && task.status == TaskStatus::Challenged
                    && !task.challenge_bond.is_none()
                    && !task_supports_pending_resolve_snapshot_restore(&task)
                {
                    self.pending_resolve_approvals.remove(&id);
                }
                if self.is_emergency_paused()
                    && task.status == TaskStatus::Challenged
                    && had_pending
                    && !task_supports_pending_resolve_restore(&task)
                {
                    self.pending_resolve_approvals.remove(&id);
                    self.objects.remove(&id);
                    return;
                }
                if task.status != TaskStatus::Challenged {
                    self.pending_resolve_approvals.remove(&id);
                }
                let is_replay_version_drift = match self.objects.get(&id) {
                    Some(existing) => match &existing.value {
                        ObjectValue::Task(existing_task) => existing_task.version != task.version,
                        _ => false,
                    },
                    None => false,
                };
                if task.status == TaskStatus::Challenged
                    && (self.is_emergency_paused()
                        && !task.challenge_bond.is_none()
                        && !task_supports_pending_resolve_snapshot_restore(&task)
                        && !is_replay_version_drift)
                {
                    self.pending_resolve_approvals.remove(&id);
                }
                match self.pending_resolve_approvals.get(&id) {
                    Some(pending)
                        if pending.confirmations == 2
                            && task.challenge_bond_forfeited.is_none()
                            || pending.confirmations != 1
                            || validate_resolve_approver_token(&pending.first_approver)
                                .is_err()
                            || canonicalize_resolve_authority_set(&pending.authority_set)
                                .map(|canonical| {
                                    let canonical_first =
                                        validate_resolve_approver_token(&pending.first_approver)
                                            .expect("validated pending approver above");
                                    !canonical.split(',').any(|member| member == canonical_first)
                                })
                                .unwrap_or(true)
                            || pending.task_version != task.version
                            || task
                                .challenge_bond_forfeited
                                .is_some_and(|forfeited| forfeited != !pending.slash_worker) =>
                    {
                        self.pending_resolve_approvals.remove(&id);
                    }
                    _ => {}
                }
                let existing_task_matches = self.matches_task_restore_reentry_snapshot(id, &task);
                let should_preserve =
                    self.should_preserve_pending_resolve_on_task_restore(id, &task);
                let stale_pending_resolve = !should_preserve && !self.is_emergency_paused();

                self.objects.insert(
                    id,
                    VersionedObject {
                        version: task.version,
                        value: ObjectValue::Task(task.clone()),
                    },
                );
                if existing_task_matches && !stale_pending_resolve {
                    return;
                }
                if stale_pending_resolve {
                    self.pending_resolve_approvals.remove(&id);
                }
                self.invalidate_state_root_cache();
            }
            None => {
                if let Some(existing) = self.objects.get(&id).cloned() {
                    if let ObjectValue::GovParam(param) = existing.value {
                        if param.version > 1 {
                            self.objects.remove(&id);
                            self.remove_gov_param_key_index_for_id(param.key_id);
                        }
                    }
                }
                self.pending_resolve_approvals.remove(&id);
            }
        }
    }

    pub fn restore_gov_param(&mut self, key_id: u64, snapshot: Option<GovParamObject>) {
        match snapshot {
            Some(snapshot) => {
                if snapshot.key_id != key_id {
                    // Mismatched replay path: clear only the foreign slot that was targeted.
                    self.clear_pending_gov_update_bindings(&snapshot.key, None);
                    self.remove_gov_param_key_index_for_id(key_id);
                    self.objects.remove(&key_id);
                    self.invalidate_state_root_cache();
                    return;
                }

                let snapshot_key = snapshot.key.clone();
                if snapshot_key == "algorand_governance_key_id" {
                    self.clear_pending_gov_update_bindings(&snapshot_key, None);
                    self.invalidate_state_root_cache();
                    return;
                }

                if let Some(existing) = self.objects.get(&snapshot.key_id) {
                    match &existing.value {
                        ObjectValue::GovParam(existing_param) => {
                            if existing_param.key != snapshot_key {
                                if existing.version == snapshot.version {
                                    self.remove_gov_param_key_index_for_id(snapshot.key_id);
                                } else {
                                    return;
                                }
                            }
                        }
                        _ => {
                            self.clear_pending_gov_update_bindings(&snapshot_key, None);
                            self.invalidate_state_root_cache();
                            return;
                        }
                    }
                }

                if GOV_ALLOWED_KEYS.contains(&snapshot_key.as_str()) {
                    if validate_gov_param_key_id_policy(&snapshot_key, snapshot.key_id).is_err() {
                        self.clear_pending_gov_update_bindings(&snapshot_key, None);
                        self.invalidate_state_root_cache();
                        return;
                    }

                    if let Some(existing_key_id) =
                        self.gov_param_key_index.get(&snapshot_key).copied()
                    {
                        if existing_key_id != snapshot.key_id {
                            self.clear_pending_gov_update_bindings(&snapshot_key, None);
                            self.remove_gov_param_key_index_for_id(snapshot.key_id);
                            self.objects.remove(&snapshot.key_id);
                            self.invalidate_state_root_cache();
                            return;
                        }
                    }

                    if validate_gov_param_value(&snapshot_key, &snapshot.value).is_err() {
                        self.pending_gov_updates.remove(&snapshot_key);
                        self.invalidate_state_root_cache();
                        return;
                    }

                    self.gov_param_key_index
                        .insert(snapshot_key.clone(), snapshot.key_id);
                }

                self.objects.insert(
                    key_id,
                    VersionedObject {
                        version: snapshot.version,
                        value: ObjectValue::GovParam(snapshot),
                    },
                );
                self.invalidate_state_root_cache();
            }
            None => {
                self.remove_gov_param_key_index_for_id(key_id);
                self.objects.remove(&key_id);
                self.invalidate_state_root_cache();
            }
        }
    }

    pub fn restore_balance(&mut self, address: &str, snapshot: Option<u128>) {
        self.invalidate_state_root_cache();
        match snapshot {
            Some(0) | None => {
                self.balances.remove(address);
            }
            Some(amount) => {
                self.balances.insert(address.to_string(), amount);
            }
        }
    }

    pub fn get_ref(&self, id: u64) -> Option<ObjectRef> {
        self.objects.get(&id).map(|v| ObjectRef {
            id,
            version: v.version,
        })
    }

    pub fn get_task(&self, id: u64) -> Option<TaskObject> {
        self.objects.get(&id).and_then(|v| match &v.value {
            ObjectValue::Task(t) => Some(t.clone()),
            _ => None,
        })
    }

    pub fn get_proposal(&self, id: u64) -> Option<GovProposalObject> {
        self.objects.get(&id).and_then(|v| match &v.value {
            ObjectValue::GovProposal(p) => Some(p.clone()),
            _ => None,
        })
    }

    fn validated_gov_param_object_at_id(&self, id: u64) -> Option<&GovParamObject> {
        let object = self.objects.get(&id)?;
        let param = match &object.value {
            ObjectValue::GovParam(p) if p.key_id == id => p,
            _ => return None,
        };
        let registry_matches_object = self.gov_param_key_index.get(&param.key).copied() == Some(id);
        let pinned_binding_matches_object = governance_expected_key_for_id(id)
            .is_some_and(|expected_key| expected_key == param.key.as_str());
        if !registry_matches_object && !pinned_binding_matches_object {
            return None;
        }
        if validate_gov_param_registry_binding(&self.gov_param_key_index, &param.key, param.key_id)
            .is_err()
        {
            return None;
        }
        Some(param)
    }

    fn canonical_gov_param_binding_at_id(&self, id: u64) -> Option<(&str, &GovParamObject)> {
        let param = self.validated_gov_param_object_at_id(id)?;
        let canonical_key = governance_expected_key_for_id(id).unwrap_or(param.key.as_str());
        (param.key == canonical_key).then_some((canonical_key, param))
    }

    pub fn get_param(&self, id: u64) -> Option<GovParamObject> {
        let object = self.objects.get(&id)?;
        let ObjectValue::GovParam(param) = &object.value else {
            return None;
        };
        let canonical_key = governance_registry_lookup_key_for_id(&self.gov_param_key_index, id)?;
        (canonical_key == param.key).then_some(param.clone())
    }

    fn invalidate_state_root_cache(&self) {
        self.state_root_cache
            .write()
            .expect("state root cache poisoned")
            .take();
    }

    fn remove_gov_param_key_index_for_id(&mut self, id: u64) {
        self.gov_param_key_index
            .retain(|_, mapped_id| *mapped_id != id);
    }

    pub fn put_task_new(&mut self, mut task: TaskObject) -> Result<ObjectRef, String> {
        if self.objects.contains_key(&task.task_id) {
            return Err("task already exists".into());
        }
        let id = task.task_id;
        task.version = 1;
        self.invalidate_state_root_cache();
        self.objects.insert(
            id,
            VersionedObject {
                version: 1,
                value: ObjectValue::Task(task),
            },
        );
        Ok(ObjectRef { id, version: 1 })
    }

    pub fn update_task(
        &mut self,
        expected: ObjectRef,
        mut task: TaskObject,
    ) -> Result<ObjectRef, String> {
        let current = self
            .objects
            .get(&expected.id)
            .ok_or_else(|| "object not found".to_string())?;
        if current.version != expected.version {
            return Err("version conflict".into());
        }
        let new_version = current.version + 1;
        task.version = new_version;
        self.invalidate_state_root_cache();
        self.objects.insert(
            expected.id,
            VersionedObject {
                version: new_version,
                value: ObjectValue::Task(task),
            },
        );
        self.pending_resolve_approvals.remove(&expected.id);
        Ok(ObjectRef {
            id: expected.id,
            version: new_version,
        })
    }

    pub fn put_proposal_new(
        &mut self,
        mut proposal: GovProposalObject,
    ) -> Result<ObjectRef, String> {
        if self.objects.contains_key(&proposal.proposal_id) {
            return Err("proposal already exists".into());
        }
        let id = proposal.proposal_id;
        proposal.version = 1;
        self.invalidate_state_root_cache();
        self.objects.insert(
            id,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovProposal(proposal),
            },
        );
        Ok(ObjectRef { id, version: 1 })
    }

    pub fn update_proposal(
        &mut self,
        expected: ObjectRef,
        mut proposal: GovProposalObject,
    ) -> Result<ObjectRef, String> {
        let current = self
            .objects
            .get(&expected.id)
            .ok_or_else(|| "object not found".to_string())?;
        if current.version != expected.version {
            return Err("version conflict".into());
        }
        let new_version = current.version + 1;
        proposal.version = new_version;
        self.invalidate_state_root_cache();
        self.objects.insert(
            expected.id,
            VersionedObject {
                version: new_version,
                value: ObjectValue::GovProposal(proposal),
            },
        );
        Ok(ObjectRef {
            id: expected.id,
            version: new_version,
        })
    }

    pub fn transition_proposal_status(
        &mut self,
        expected: ObjectRef,
        to: GovProposalStatus,
    ) -> Result<ObjectRef, String> {
        let current = self
            .objects
            .get(&expected.id)
            .ok_or_else(|| "object not found".to_string())?;
        if current.version != expected.version {
            return Err("version conflict".into());
        }
        let mut proposal = match &current.value {
            ObjectValue::GovProposal(p) => p.clone(),
            _ => return Err("object type mismatch".into()),
        };

        let from = proposal.status;
        let valid = matches!(
            (from, to),
            (GovProposalStatus::Draft, GovProposalStatus::Voting)
                | (GovProposalStatus::Voting, GovProposalStatus::Passed)
                | (GovProposalStatus::Voting, GovProposalStatus::Rejected)
                | (GovProposalStatus::Passed, GovProposalStatus::Executed)
        );
        if !valid {
            return Err(format!(
                "invalid governance transition: {:?}->{:?}",
                from, to
            ));
        }

        proposal.status = to;
        self.update_proposal(expected, proposal)
    }

    fn upsert_gov_param_unchecked(
        &mut self,
        key_id: u64,
        key: String,
        value: String,
    ) -> Result<ObjectRef, String> {
        if let Some(existing_id) =
            governance_registry_lookup_id_for_key(&self.gov_param_key_index, &key)
        {
            if existing_id != key_id {
                return Err(format!(
                    "governance key id mismatch for {}: existing_id={}, attempted_id={}",
                    key, existing_id, key_id
                ));
            }
        }

        if let Some(current) = self.objects.get(&key_id) {
            let new_version = current.version + 1;
            let old_key = match &current.value {
                ObjectValue::GovParam(p) => p.key.clone(),
                _ => {
                    return Err(format!(
                        "governance key_id collision: object {} exists and is not GovParam",
                        key_id
                    ));
                }
            };

            if old_key != key {
                return Err(format!(
                    "governance key id mismatch for id {}: existing_key={}, attempted_key={}",
                    key_id, old_key, key
                ));
            }

            self.invalidate_state_root_cache();
            self.gov_param_key_index.insert(key.clone(), key_id);
            self.objects.insert(
                key_id,
                VersionedObject {
                    version: new_version,
                    value: ObjectValue::GovParam(GovParamObject {
                        key_id,
                        key,
                        value,
                        version: new_version,
                    }),
                },
            );
            Ok(ObjectRef {
                id: key_id,
                version: new_version,
            })
        } else {
            self.invalidate_state_root_cache();
            self.gov_param_key_index.insert(key.clone(), key_id);
            self.objects.insert(
                key_id,
                VersionedObject {
                    version: 1,
                    value: ObjectValue::GovParam(GovParamObject {
                        key_id,
                        key,
                        value,
                        version: 1,
                    }),
                },
            );
            Ok(ObjectRef {
                id: key_id,
                version: 1,
            })
        }
    }

    #[cfg_attr(not(feature = "test-utils"), allow(dead_code))]
    pub(crate) fn set_gov_param_unchecked(
        &mut self,
        key_id: u64,
        key: String,
        value: String,
    ) -> Result<ObjectRef, String> {
        validate_requested_governance_key_canonical(&key)?;
        validate_gov_param_value(&key, &value)?;
        validate_gov_param_key_id_policy(&key, key_id)?;
        if !is_sensitive_gov_param(&key) {
            // Preserve side-effect-free error behavior: only scrub stale pending entries
            // after a successful write for non-sensitive keys.
            // Idempotence guard: unchecked replay of identical non-sensitive values should
            // not churn object versions, but must still clear stale pending residue.
            if self.gov_param_value(&key) == Some(value.as_str()) {
                self.invalidate_state_root_cache();
                self.pending_gov_updates.remove(&key);
                if let Some(existing_ref) = self
                    .validated_gov_param_registry_id_for_key(&key)
                    .and_then(|id| self.get_ref(id))
                {
                    return Ok(existing_ref);
                }
            }
            let out = self.upsert_gov_param_unchecked(key_id, key.clone(), value)?;
            self.invalidate_state_root_cache();
            self.pending_gov_updates.remove(&key);
            return Ok(out);
        }
        self.upsert_gov_param_unchecked(key_id, key, value)
    }

    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn set_gov_param_bootstrap_unchecked(
        &mut self,
        key_id: u64,
        key: String,
        value: String,
    ) -> Result<ObjectRef, String> {
        validate_requested_governance_key_canonical(&key)?;
        validate_gov_param_registry_binding(&self.gov_param_key_index, &key, key_id)?;
        self.set_gov_param_unchecked(key_id, key, value)
    }

    pub fn set_gov_param(
        &mut self,
        current_height: u64,
        key_id: u64,
        key: String,
        value: String,
    ) -> Result<GovParamUpdateOutcome, String> {
        self.set_gov_param_with_action(
            current_height,
            key_id,
            key,
            value,
            GovPendingUpdateAction::Enforce,
        )
    }

    pub fn set_gov_param_with_action(
        &mut self,
        current_height: u64,
        key_id: u64,
        key: String,
        value: String,
        action: GovPendingUpdateAction,
    ) -> Result<GovParamUpdateOutcome, String> {
        validate_requested_governance_key_canonical(&key)?;
        validate_gov_param_registry_binding(&self.gov_param_key_index, &key, key_id)?;

        if action != GovPendingUpdateAction::Cancel {
            validate_gov_param_value(&key, &value)?;
        }

        if !is_sensitive_gov_param(&key) {
            // Defensive cleanup: non-sensitive keys must not carry queued timelock state.
            // This keeps emergency_pause and other immediate keys deterministic even if
            // a legacy/corrupt snapshot left stale pending entries behind.
            if action == GovPendingUpdateAction::Cancel {
                self.invalidate_state_root_cache();
                self.pending_gov_updates.remove(&key);
                return Err(format!(
                    "governance cancel not supported for non-sensitive key {}",
                    key
                ));
            }
            // Idempotence guard: re-applying the exact same value should not churn object
            // versions, but still scrubs stale pending non-sensitive timelock residue.
            if self.gov_param_value(&key) == Some(value.as_str()) {
                self.invalidate_state_root_cache();
                self.pending_gov_updates.remove(&key);
                if let Some(existing_ref) = self
                    .gov_param_key_index
                    .get(&key)
                    .copied()
                    .and_then(|id| self.get_ref(id))
                {
                    return Ok(GovParamUpdateOutcome::Applied(existing_ref));
                }
            }
            let r = self.upsert_gov_param_unchecked(key_id, key.clone(), value)?;
            self.invalidate_state_root_cache();
            self.pending_gov_updates.remove(&key);
            return Ok(GovParamUpdateOutcome::Applied(r));
        }

        if action != GovPendingUpdateAction::Cancel {
            if self.pending_gov_updates.get(&key).is_none()
                && self.gov_param_value(&key) == Some(value.as_str())
            {
                if let Some(existing_ref) = self
                    .gov_param_key_index
                    .get(&key)
                    .copied()
                    .and_then(|id| self.get_ref(id))
                {
                    return Ok(GovParamUpdateOutcome::Applied(existing_ref));
                }
            }

            if let Some(old_value) = self.gov_param_u64(&key) {
                let new_value = value.parse::<u64>().map_err(|_| {
                    format!(
                        "invalid governance value for {}: expected u64, got '{}'",
                        key, value
                    )
                })?;
                check_sensitive_rate_limit(&key, old_value, new_value)?;
            }
        }

        if let Some(pending) = self.pending_gov_updates.get(&key).cloned() {
            if pending.key_id != key_id {
                return Err(format!(
                    "pending governance update key_id mismatch for {}: pending_key_id={}, attempted_key_id={}",
                    key, pending.key_id, key_id
                ));
            }

            if current_height < pending.activate_at_height {
                match action {
                    GovPendingUpdateAction::Cancel => {
                        self.invalidate_state_root_cache();
                        self.pending_gov_updates.remove(&key);
                        if key == "resolve_authority" {
                            self.pending_resolve_approvals.clear();
                        }
                        return Ok(GovParamUpdateOutcome::Cancelled);
                    }
                    GovPendingUpdateAction::Replace => {
                        if pending.value == value {
                            return Ok(GovParamUpdateOutcome::Scheduled {
                                activate_at_height: pending.activate_at_height,
                            });
                        }
                        let activate_at_height =
                            current_height.saturating_add(GOV_SENSITIVE_PARAM_TIMELOCK_BLOCKS);
                        let scrubs_resolve_quorum = key == "resolve_authority";
                        self.invalidate_state_root_cache();
                        self.pending_gov_updates.insert(
                            key.clone(),
                            PendingGovParamUpdate {
                                key_id,
                                key,
                                value,
                                activate_at_height,
                            },
                        );
                        if scrubs_resolve_quorum {
                            self.pending_resolve_approvals.clear();
                        }
                        return Ok(GovParamUpdateOutcome::Scheduled { activate_at_height });
                    }
                    GovPendingUpdateAction::Enforce => {
                        if pending.value != value {
                            return Err(format!(
                                "pending governance update exists for {} (activate_at_height={})",
                                key, pending.activate_at_height
                            ));
                        }
                        return Err(format!(
                            "governance timelock active for {}: current_height={}, activate_at_height={}",
                            key, current_height, pending.activate_at_height
                        ));
                    }
                }
            }

            if action == GovPendingUpdateAction::Cancel || action == GovPendingUpdateAction::Replace
            {
                return Err(format!(
                    "pending governance update for {} already active at height {} and must be applied",
                    key, pending.activate_at_height
                ));
            }

            if pending.value != value {
                return Err(format!(
                    "pending governance update exists for {} (activate_at_height={})",
                    key, pending.activate_at_height
                ));
            }
            self.invalidate_state_root_cache();
            self.pending_gov_updates.remove(&key);
            if key == "resolve_authority" {
                self.pending_resolve_approvals.clear();
            }
            let r = self.upsert_gov_param_unchecked(key_id, key, value)?;
            return Ok(GovParamUpdateOutcome::Applied(r));
        }

        if action == GovPendingUpdateAction::Cancel {
            return Err(format!("no pending governance update exists for {}", key));
        }

        let activate_at_height = current_height.saturating_add(GOV_SENSITIVE_PARAM_TIMELOCK_BLOCKS);
        let scrubs_resolve_quorum = key == "resolve_authority";
        self.invalidate_state_root_cache();
        self.pending_gov_updates.insert(
            key.clone(),
            PendingGovParamUpdate {
                key_id,
                key,
                value,
                activate_at_height,
            },
        );
        if scrubs_resolve_quorum {
            self.pending_resolve_approvals.clear();
        }
        Ok(GovParamUpdateOutcome::Scheduled { activate_at_height })
    }

    fn pending_gov_update_has_key_id_alias(&self, key: &str, key_id: u64) -> bool {
        self.pending_gov_updates
            .iter()
            .any(|(other_key, other_pending)| {
                other_key.as_str() != key && other_pending.key_id == key_id
            })
    }

    fn canonical_pending_gov_update_for_key(&self, key: &str) -> Option<&PendingGovParamUpdate> {
        let pending = self.pending_gov_updates.get(key)?;
        if validate_pending_gov_param_snapshot_binding(&self.gov_param_key_index, key, pending)
            .is_err()
        {
            return None;
        }
        if self.pending_gov_update_has_key_id_alias(key, pending.key_id) {
            return None;
        }
        Some(pending)
    }

    pub fn pending_gov_update(&self, key: &str) -> Option<PendingGovParamUpdate> {
        self.canonical_pending_gov_update_for_key(key).cloned()
    }

    fn clear_pending_gov_update_bindings(
        &mut self,
        requested_key: &str,
        snapshot_key: Option<&str>,
    ) {
        let before = self.pending_gov_updates.len();
        self.pending_gov_updates.remove(requested_key);

        if let Some(snapshot_key) = snapshot_key {
            if snapshot_key != requested_key {
                self.pending_gov_updates.remove(snapshot_key);
            }
        }

        if self.pending_gov_updates.len() != before {
            self.invalidate_state_root_cache();
        }
    }

    fn clear_pending_gov_update_key_id_aliases(&mut self, key_id: u64, preserved_key: &str) {
        let before = self.pending_gov_updates.len();
        self.pending_gov_updates.retain(|other_key, other_pending| {
            other_key.as_str() == preserved_key || other_pending.key_id != key_id
        });
        if self.pending_gov_updates.len() != before {
            self.invalidate_state_root_cache();
        }
    }

    pub fn restore_pending_gov_update(
        &mut self,
        key: &str,
        snapshot: Option<PendingGovParamUpdate>,
    ) {
        let scrubs_resolve_quorum = key == "resolve_authority";
        match snapshot {
            Some(snapshot) => {
                if self
                    .pending_gov_updates
                    .get(key)
                    .is_some_and(|existing| existing == &snapshot)
                {
                    return;
                }

                let snapshot_key_id = snapshot.key_id;

                if key == "algorand_governance_key_id" {
                    self.clear_pending_gov_update_bindings(key, None);
                    self.clear_pending_gov_update_key_id_aliases(snapshot_key_id, key);
                    if scrubs_resolve_quorum {
                        self.pending_resolve_approvals.clear();
                    }
                    return;
                }

                if key == "emergency_pause" {
                    self.clear_pending_gov_update_bindings(key, None);
                    self.clear_pending_gov_update_key_id_aliases(snapshot_key_id, key);
                    if scrubs_resolve_quorum {
                        self.pending_resolve_approvals.clear();
                    }
                    return;
                }

                if GOV_ALLOWED_KEYS.contains(&key)
                    && validate_pending_gov_param_snapshot_binding(
                        &self.gov_param_key_index,
                        key,
                        &snapshot,
                    )
                    .is_err()
                {
                    self.clear_pending_gov_update_bindings(key, None);
                    if scrubs_resolve_quorum {
                        self.pending_resolve_approvals.clear();
                    }
                    return;
                }

                if let Some(existing) = self.objects.get(&snapshot_key_id) {
                    match &existing.value {
                        ObjectValue::GovParam(existing_param) => {
                            if existing_param.key != snapshot.key {
                                self.clear_pending_gov_update_bindings(key, None);
                                if scrubs_resolve_quorum {
                                    self.pending_resolve_approvals.clear();
                                }
                                return;
                            }
                        }
                        _ => {
                            self.clear_pending_gov_update_bindings(key, None);
                            if scrubs_resolve_quorum {
                                self.pending_resolve_approvals.clear();
                            }
                            return;
                        }
                    }
                }

                let alias_keys: Vec<String> = self
                    .pending_gov_updates
                    .iter()
                    .filter(|(other_key, other_pending)| {
                        other_key.as_str() != key && other_pending.key_id == snapshot_key_id
                    })
                    .map(|(other_key, _)| other_key.clone())
                    .collect();

                if key != "resolve_authority"
                    && key != "emergency_pause"
                    && GOV_ALLOWED_KEYS.contains(&key)
                    && self
                        .validated_gov_param_object_at_id(snapshot_key_id)
                        .is_none()
                    && alias_keys.is_empty()
                {
                    self.clear_pending_gov_update_bindings(key, None);
                    if scrubs_resolve_quorum {
                        self.pending_resolve_approvals.clear();
                    }
                    return;
                }

                if !alias_keys.is_empty() {
                    let has_foreign_non_allowed = alias_keys
                        .iter()
                        .any(|other_key| !GOV_ALLOWED_KEYS.contains(&other_key.as_str()));

                    if has_foreign_non_allowed {
                        self.clear_pending_gov_update_bindings(key, None);
                        self.clear_pending_gov_update_key_id_aliases(snapshot_key_id, key);
                        if scrubs_resolve_quorum {
                            self.pending_resolve_approvals.clear();
                        }
                    } else {
                        self.pending_gov_updates.remove(key);
                        self.invalidate_state_root_cache();
                        if scrubs_resolve_quorum {
                            self.pending_resolve_approvals.clear();
                        }
                    }

                    return;
                }

                if GOV_ALLOWED_KEYS.contains(&key) {
                    if snapshot.activate_at_height == 0
                        || validate_gov_param_value(key, &snapshot.value).is_err()
                    {
                        self.pending_gov_updates.remove(key);
                        if scrubs_resolve_quorum {
                            self.pending_resolve_approvals.clear();
                        }
                        self.invalidate_state_root_cache();
                        return;
                    }
                }

                self.pending_gov_updates
                    .insert(snapshot.key.clone(), snapshot);
                if scrubs_resolve_quorum {
                    self.clear_pending_gov_update_key_id_aliases(snapshot_key_id, key);
                    self.pending_resolve_approvals.clear();
                }
                self.invalidate_state_root_cache();
            }
            None => {
                self.clear_pending_gov_update_bindings(key, None);
            }
        }
    }

    fn validated_gov_param_registry_id_for_key(&self, key: &str) -> Option<u64> {
        let id = governance_registry_lookup_id_for_key(&self.gov_param_key_index, key)?;
        if validate_gov_param_registry_binding(&self.gov_param_key_index, key, id).is_err() {
            return None;
        }
        Some(id)
    }

    fn canonical_gov_param_for_key(&self, key: &str) -> Option<(u64, &GovParamObject)> {
        let id = self.validated_gov_param_registry_id_for_key(key)?;
        let (canonical_key, param) = self.canonical_gov_param_binding_at_id(id)?;
        (canonical_key == key).then_some((id, param))
    }

    fn gov_param_value(&self, key: &str) -> Option<&str> {
        let (_, param) = self.canonical_gov_param_for_key(key)?;
        Some(param.value.as_str())
    }

    pub fn is_emergency_paused(&self) -> bool {
        self.gov_param_value("emergency_pause") == Some("true")
    }

    pub fn gov_param_u64(&self, key: &str) -> Option<u64> {
        self.gov_param_value(key)?.parse::<u64>().ok()
    }

    pub fn gov_param_u128(&self, key: &str) -> Option<u128> {
        self.gov_param_value(key)?.parse::<u128>().ok()
    }

    pub fn gov_param_string(&self, key: &str) -> Option<String> {
        Some(self.gov_param_value(key)?.to_string())
    }

    fn gov_param_ref_for_key(&self, key: &str) -> Option<(u64, &GovParamObject)> {
        self.canonical_gov_param_for_key(key)
    }

    fn monetary_tick_config(&self) -> Option<(u64, u64, u128, u128, u64, u64, u64, u64)> {
        let (_, interval_param) =
            self.gov_param_ref_for_key("monetary_policy_tick_interval_blocks")?;
        let (_, cooldown_param) =
            self.gov_param_ref_for_key("monetary_policy_tick_cooldown_blocks")?;
        let (_, issuance_param) = self.gov_param_ref_for_key("monetary_base_issuance_per_tick")?;
        let (_, burn_param) = self.gov_param_ref_for_key("monetary_base_burn_per_tick")?;

        let interval = interval_param.value.parse::<u64>().ok()?;
        let cooldown = cooldown_param.value.parse::<u64>().ok()?;
        let minted = issuance_param.value.parse::<u128>().ok()?;
        let burned = burn_param.value.parse::<u128>().ok()?;

        if !(1..=100_000).contains(&interval)
            || !(1..=100_000).contains(&cooldown)
            || minted > 1_000_000_000_000u128
            || burned > 1_000_000_000_000u128
        {
            return None;
        }

        Some((
            interval,
            cooldown,
            minted,
            burned,
            interval_param.version,
            issuance_param.version,
            burn_param.version,
            cooldown_param.version,
        ))
    }

    pub fn monetary_state(&self) -> &MonetaryState {
        &self.monetary_state
    }

    pub fn monetary_state_snapshot(&self) -> MonetaryStateSnapshot {
        self.monetary_state.clone()
    }

    pub fn restore_monetary_state(&mut self, snapshot: MonetaryStateSnapshot) {
        self.invalidate_state_root_cache();
        self.monetary_state = snapshot;
    }

    pub fn should_trigger_policy_tick(&self, block_height: u64) -> bool {
        let Some((interval, cooldown, _, _, _, _, _, _)) = self.monetary_tick_config() else {
            // Fail-closed: missing/invalid monetary params disable policy tick.
            return false;
        };
        let cooldown_allows = self.monetary_state.tick_count == 0
            || self
                .monetary_state
                .last_tick_height
                .saturating_add(cooldown)
                <= block_height;
        block_height > 0
            && block_height % interval == 0
            && cooldown_allows
            && self.monetary_state.last_tick_height < block_height
    }

    pub fn policy_tick(&mut self, block_height: u64) -> Option<PolicyTickEvent> {
        let (
            interval_blocks,
            cooldown_blocks,
            minted,
            burned,
            interval_param_version,
            issuance_param_version,
            burn_param_version,
            cooldown_param_version,
        ) = self.monetary_tick_config()?;

        let cooldown_allows = self.monetary_state.tick_count == 0
            || self
                .monetary_state
                .last_tick_height
                .saturating_add(cooldown_blocks)
                <= block_height;

        if !(block_height > 0
            && block_height % interval_blocks == 0
            && cooldown_allows
            && self.monetary_state.last_tick_height < block_height)
        {
            return None;
        }
        let net_delta = minted as i128 - burned as i128;

        self.invalidate_state_root_cache();
        self.monetary_state.last_tick_height = block_height;
        self.monetary_state.tick_count = self.monetary_state.tick_count.saturating_add(1);
        self.monetary_state.total_minted = self.monetary_state.total_minted.saturating_add(minted);
        self.monetary_state.total_burned = self.monetary_state.total_burned.saturating_add(burned);
        self.monetary_state.net_issuance =
            self.monetary_state.net_issuance.saturating_add(net_delta);

        Some(PolicyTickEvent {
            block_height,
            interval_blocks,
            cooldown_blocks,
            minted,
            burned,
            net_delta,
            total_minted: self.monetary_state.total_minted,
            total_burned: self.monetary_state.total_burned,
            net_issuance: self.monetary_state.net_issuance,
            tick_count: self.monetary_state.tick_count,
            interval_param_version,
            issuance_param_version,
            burn_param_version,
            cooldown_param_version,
        })
    }

    pub fn set_balance(&mut self, address: impl Into<String>, amount: u128) {
        self.invalidate_state_root_cache();
        let address = address.into();
        if amount == 0 {
            self.balances.remove(&address);
        } else {
            self.balances.insert(address, amount);
        }
    }

    pub fn balance_of(&self, address: &str) -> u128 {
        self.balances.get(address).copied().unwrap_or(0)
    }

    pub fn debit_balance(&mut self, address: &str, amount: u128) -> Result<(), String> {
        let cur = self.balance_of(address);
        if cur < amount {
            return Err(format!(
                "insufficient balance: address={}, have={}, need={}",
                address, cur, amount
            ));
        }
        self.invalidate_state_root_cache();
        let next = cur - amount;
        if next == 0 {
            self.balances.remove(address);
        } else {
            self.balances.insert(address.to_string(), next);
        }
        Ok(())
    }

    pub fn credit_balance(&mut self, address: &str, amount: u128) -> Result<(), String> {
        let cur = self.balance_of(address);
        let next = cur.checked_add(amount).ok_or_else(|| {
            format!(
                "balance overflow on credit: address={}, current={}, amount={}",
                address, cur, amount
            )
        })?;
        self.invalidate_state_root_cache();
        if next == 0 {
            self.balances.remove(address);
        } else {
            self.balances.insert(address.to_string(), next);
        }
        Ok(())
    }

    pub fn state_root(&self) -> Hash32 {
        if let Some(cached) = self
            .state_root_cache
            .read()
            .expect("state root cache poisoned")
            .clone()
        {
            return cached;
        }

        let mut cache_guard = self
            .state_root_cache
            .write()
            .expect("state root cache poisoned");
        if let Some(cached) = cache_guard.clone() {
            return cached;
        }

        let mut hasher = Sha256::new();
        for (id, v) in &self.objects {
            hasher.update(id.to_le_bytes());
            hasher.update(v.version.to_le_bytes());
            match &v.value {
                ObjectValue::Task(t) => {
                    hasher.update(b"task");
                    hasher.update(t.task_id.to_le_bytes());
                    hash_len_prefixed_str(&mut hasher, &t.creator);
                    hasher.update(t.bounty.to_le_bytes());
                    hasher.update((t.status as u8).to_le_bytes());
                    hasher.update((t.proof_type as u8).to_le_bytes());

                    match &t.metadata {
                        Some(metadata) => {
                            hasher.update([1]);
                            match &metadata.note {
                                Some(note) => {
                                    hasher.update([1]);
                                    hash_len_prefixed_str(&mut hasher, note);
                                }
                                None => hasher.update([0]),
                            }
                            match &metadata.task_type {
                                Some(task_type) => {
                                    hasher.update([1]);
                                    hash_len_prefixed_str(&mut hasher, task_type);
                                }
                                None => hasher.update([0]),
                            }
                            match &metadata.input_hash {
                                Some(input_hash) => {
                                    hasher.update([1]);
                                    hash_len_prefixed_str(&mut hasher, input_hash);
                                }
                                None => hasher.update([0]),
                            }
                            match &metadata.model {
                                Some(model) => {
                                    hasher.update([1]);
                                    match &model.model_id {
                                        Some(model_id) => {
                                            hasher.update([1]);
                                            hash_len_prefixed_str(&mut hasher, model_id);
                                        }
                                        None => hasher.update([0]),
                                    }
                                    match &model.model_digest {
                                        Some(model_digest) => {
                                            hasher.update([1]);
                                            hash_len_prefixed_str(&mut hasher, model_digest);
                                        }
                                        None => hasher.update([0]),
                                    }
                                    match &model.version {
                                        Some(version) => {
                                            hasher.update([1]);
                                            hash_len_prefixed_str(&mut hasher, version);
                                        }
                                        None => hasher.update([0]),
                                    }
                                }
                                None => hasher.update([0]),
                            }
                            match &metadata.provenance {
                                Some(provenance) => {
                                    hasher.update([1]);
                                    match &provenance.producer_did {
                                        Some(producer_did) => {
                                            hasher.update([1]);
                                            hash_len_prefixed_str(&mut hasher, producer_did);
                                        }
                                        None => hasher.update([0]),
                                    }
                                    match &provenance.produced_at {
                                        Some(produced_at) => {
                                            hasher.update([1]);
                                            hash_len_prefixed_str(&mut hasher, produced_at);
                                        }
                                        None => hasher.update([0]),
                                    }
                                    match &provenance.provenance_index {
                                        Some(provenance_index) => {
                                            hasher.update([1]);
                                            hash_len_prefixed_str(&mut hasher, provenance_index);
                                        }
                                        None => hasher.update([0]),
                                    }
                                    match &provenance.privacy_tier {
                                        Some(privacy_tier) => {
                                            hasher.update([1]);
                                            hasher.update(match privacy_tier {
                                                trnm_types::PrivacyTier::Public => {
                                                    b"public".as_slice()
                                                }
                                                trnm_types::PrivacyTier::Internal => {
                                                    b"internal".as_slice()
                                                }
                                                trnm_types::PrivacyTier::Restricted => {
                                                    b"restricted".as_slice()
                                                }
                                            });
                                        }
                                        None => hasher.update([0]),
                                    }
                                }
                                None => hasher.update([0]),
                            }
                            match &metadata.metering {
                                Some(metering) => {
                                    hasher.update([1]);
                                    hash_task_metering_snapshot(&mut hasher, metering);
                                }
                                None => hasher.update([0]),
                            }
                        }
                        None => hasher.update([0]),
                    }

                    match &t.worker {
                        Some(worker) => {
                            hasher.update([1]);
                            hash_len_prefixed_str(&mut hasher, worker);
                        }
                        None => hasher.update([0]),
                    }
                    match &t.committed_hash {
                        Some(h) => {
                            hasher.update([1]);
                            hasher.update(h);
                        }
                        None => hasher.update([0]),
                    }
                    match &t.result_hash {
                        Some(h) => {
                            hasher.update([1]);
                            hasher.update(h);
                        }
                        None => hasher.update([0]),
                    }
                    match &t.reveal_salt {
                        Some(salt) => {
                            hasher.update([1]);
                            hasher.update(salt);
                        }
                        None => hasher.update([0]),
                    }

                    match t.committed_at_height {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update(v.to_le_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match t.reveal_deadline_height {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update(v.to_le_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match t.challenge_deadline_height {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update(v.to_le_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match t.challenge_window_blocks_snapshot {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update(v.to_le_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match t.challenged_at_height {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update(v.to_le_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match t.resolve_deadline_height {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update(v.to_le_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match t.challenge_bond {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update(v.to_le_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match &t.challenger {
                        Some(challenger) => {
                            hasher.update([1]);
                            hash_len_prefixed_str(&mut hasher, challenger);
                        }
                        None => hasher.update([0]),
                    }
                    match t.challenge_bond_forfeited {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update([v as u8]);
                        }
                        None => hasher.update([0]),
                    }
                    hasher.update(t.version.to_le_bytes());
                }
                ObjectValue::GovProposal(p) => {
                    hasher.update(b"gov_proposal");
                    hasher.update(p.proposal_id.to_le_bytes());
                    hash_len_prefixed_str(&mut hasher, &p.title);
                    hash_len_prefixed_str(&mut hasher, &p.proposer);
                    hasher.update((p.status as u8).to_le_bytes());
                    hasher.update(p.version.to_le_bytes());
                }
                ObjectValue::GovParam(p) => {
                    hasher.update(b"gov_param");
                    hasher.update(p.key_id.to_le_bytes());
                    hash_len_prefixed_str(&mut hasher, &p.key);
                    hash_len_prefixed_str(&mut hasher, &p.value);
                    hasher.update(p.version.to_le_bytes());
                }
            }
        }
        for (addr, bal) in &self.balances {
            hasher.update(b"balance");
            hash_len_prefixed_str(&mut hasher, addr);
            hasher.update(bal.to_le_bytes());
        }
        for (key, key_id) in &self.gov_param_key_index {
            hasher.update(b"gov_param_key_index");
            hash_len_prefixed_str(&mut hasher, key);
            hasher.update(key_id.to_le_bytes());
        }
        for (key, pending) in &self.pending_gov_updates {
            hasher.update(b"gov_pending");
            hash_len_prefixed_str(&mut hasher, key);
            hasher.update(pending.key_id.to_le_bytes());
            hash_len_prefixed_str(&mut hasher, &pending.key);
            hash_len_prefixed_str(&mut hasher, &pending.value);
            hasher.update(pending.activate_at_height.to_le_bytes());
        }
        for (task_id, pending) in &self.pending_resolve_approvals {
            hash_pending_resolve_approval(&mut hasher, *task_id, pending);
        }
        hasher.update(b"monetary_state");
        hasher.update(self.monetary_state.last_tick_height.to_le_bytes());
        hasher.update(self.monetary_state.tick_count.to_le_bytes());
        hasher.update(self.monetary_state.total_minted.to_le_bytes());
        hasher.update(self.monetary_state.total_burned.to_le_bytes());
        hasher.update(self.monetary_state.net_issuance.to_le_bytes());
        let root: Hash32 = hasher.finalize().into();
        *cache_guard = Some(root.clone());
        root
    }
}

fn is_canonical_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value.as_bytes().iter().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_hexdigit() && byte.is_ascii_lowercase())
        })
}

const WAL_PROPOSAL_HASH_MAX_LEN: usize = 256;

fn wal_proposal_hash_length_is_canonical(value: &str) -> bool {
    !value.is_empty() && value.len() <= WAL_PROPOSAL_HASH_MAX_LEN
}

fn wal_proposal_hash_surface_has_forbidden_layout(value: &str) -> bool {
    value.trim() != value
        || !value.is_ascii()
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn is_canonical_wal_proposal_hash(value: &str) -> bool {
    wal_proposal_hash_length_is_canonical(value)
        && !wal_proposal_hash_surface_has_forbidden_layout(value)
}

fn wal_prev_hash_surface_is_canonical(height: u64, prev_hash_hex: Option<&str>) -> bool {
    match (height, prev_hash_hex) {
        (1, None) => true,
        (1, Some(_)) => false,
        (2.., Some(prev_hash_hex)) => is_canonical_hex_digest(prev_hash_hex),
        (2.., None) => false,
        _ => false,
    }
}

fn checkpoint_height_surface_is_canonical(height: u64) -> bool {
    height > 0
}

fn wal_content_hash_surface_is_canonical(wal_entry: &WalMeta) -> bool {
    is_canonical_hex_digest(&wal_entry.content_hash_hex())
}

fn wal_state_root_surface_is_canonical(wal_entry: &WalMeta) -> bool {
    let state_root_hex = wal_entry.state_root_hex.as_str();
    let looks_like_digest_surface = state_root_hex.len() == 64
        && state_root_hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit());

    !looks_like_digest_surface || is_canonical_hex_digest(state_root_hex)
}

fn checkpoint_hash_surfaces_are_canonical(
    checkpoint: &CheckpointMeta,
    wal_entry: &WalMeta,
) -> bool {
    is_canonical_hex_digest(&checkpoint.state_root_hex)
        && is_canonical_hex_digest(&checkpoint.wal_entry_hash_hex)
        && is_canonical_hex_digest(&wal_entry.state_root_hex)
        && wal_content_hash_surface_is_canonical(wal_entry)
}

fn wal_entry_has_complete_proof_metadata(wal_entry: &WalMeta) -> bool {
    if wal_entry.proposal_hash.trim().is_empty() || wal_entry.state_root_hex.trim().is_empty() {
        return false;
    }
    match wal_entry.height {
        0 => false,
        1 => wal_entry.prev_hash_hex.is_none(),
        _ => wal_entry
            .prev_hash_hex
            .as_ref()
            .is_some_and(|value| !value.trim().is_empty()),
    }
}

fn wal_checkpoint_metadata_surfaces_are_canonical(wal_entry: &WalMeta) -> bool {
    is_canonical_wal_proposal_hash(&wal_entry.proposal_hash)
        && wal_prev_hash_surface_is_canonical(wal_entry.height, wal_entry.prev_hash_hex.as_deref())
}

fn checkpoint_binds_to_canonical_wal_entry(
    checkpoint: &CheckpointMeta,
    wal_entry: &WalMeta,
) -> bool {
    checkpoint.height == wal_entry.height
        && wal_entry.committed
        && wal_checkpoint_metadata_surfaces_are_canonical(wal_entry)
        && checkpoint.state_root_hex == wal_entry.state_root_hex
        && checkpoint.wal_entry_hash_hex == wal_entry.content_hash_hex()
}

pub fn checkpoint_evidence_surface_is_canonical(
    checkpoint: &CheckpointMeta,
    wal_entry: &WalMeta,
) -> bool {
    checkpoint_height_surface_is_canonical(checkpoint.height)
        && checkpoint_hash_surfaces_are_canonical(checkpoint, wal_entry)
        && checkpoint_binds_to_canonical_wal_entry(checkpoint, wal_entry)
}

pub fn checkpoint_da_light_verifier_summary(
    checkpoint: &CheckpointMeta,
    wal_entry: &WalMeta,
) -> Option<String> {
    if !checkpoint_evidence_surface_is_canonical(checkpoint, wal_entry) {
        return None;
    }

    Some(format!(
        "checkpoint_commitment={} checkpoint_height={} checkpoint_state_root={} checkpoint_wal_entry_hash={} wal_prev_hash={} wal_round={} wal_proposal_hash={}",
        checkpoint.commitment_hex(),
        checkpoint.height,
        checkpoint.state_root_hex,
        checkpoint.wal_entry_hash_hex,
        wal_entry.prev_hash_hex.as_deref().unwrap_or("none"),
        wal_entry.round,
        wal_entry.proposal_hash,
    ))
}

fn checkpoint_matches_wal_entry_for_recovery(
    checkpoint: &CheckpointMeta,
    wal_entry: &WalMeta,
    wal_entry_hash_hex: &str,
) -> bool {
    if !checkpoint_height_surface_is_canonical(checkpoint.height) {
        return false;
    }
    if checkpoint.height != wal_entry.height {
        return false;
    }
    if !wal_entry.committed {
        return false;
    }
    if !wal_checkpoint_metadata_surfaces_are_canonical(wal_entry) {
        return false;
    }
    if !wal_state_root_surface_is_canonical(wal_entry) {
        return false;
    }
    if !is_canonical_hex_digest(&checkpoint.wal_entry_hash_hex) {
        return false;
    }
    if is_canonical_hex_digest(&wal_entry.state_root_hex)
        && !is_canonical_hex_digest(&checkpoint.state_root_hex)
    {
        return false;
    }

    checkpoint.state_root_hex == wal_entry.state_root_hex
        && wal_entry_hash_hex == checkpoint.wal_entry_hash_hex.as_str()
}

pub fn verify_wal_and_find_checkpoint(
    checkpoints: &[CheckpointMeta],
    wal_entries: &[WalMeta],
) -> Result<Option<CheckpointMeta>, String> {
    let mut prev_hash: Option<String> = None;
    let mut prev_height: Option<u64> = None;
    let mut best_checkpoint: Option<CheckpointMeta> = None;
    let mut best_checkpoint_before_height: Option<CheckpointMeta> = None;
    let mut current_wal_height: Option<u64> = None;

    for e in wal_entries {
        if !is_canonical_hex_digest(&e.content_hash_hex()) {
            return Ok(None);
        }

        if let Some(last_height) = prev_height {
            // Fail closed on any WAL height discontinuity. Replayed,
            // out-of-order,
            // or gap-skipping entries must not be treated as a valid continuation
            // during restart recovery.
            if e.height < last_height {
                return Ok(best_checkpoint);
            }
            if e.height == last_height {
                // Duplicate same-height WAL entries are tolerated only as a replay evidence,
                // not as a hard progress step in checkpoint selection.
            } else if e.height != last_height + 1 {
                return Ok(best_checkpoint);
            }
        } else if e.height != 1 {
            // Until StateStore snapshot restore/replay exists, a checkpointed WAL chain
            // that starts above genesis height is metadata-only and must not be used to
            // claim safe application-state recovery.
            return Ok(best_checkpoint);
        }

        if current_wal_height != Some(e.height) {
            best_checkpoint_before_height = best_checkpoint.clone();
            current_wal_height = Some(e.height);
        }

        let checkpoints_at_height: Vec<&CheckpointMeta> = checkpoints
            .iter()
            .filter(|cp| cp.height == e.height)
            .collect();
        if !wal_entry_has_complete_proof_metadata(e) {
            if e.height > 1
                && (e.proposal_hash.is_empty()
                    || e.state_root_hex.is_empty()
                    || e.prev_hash_hex
                        .as_deref()
                        .is_some_and(|prev| prev.trim().is_empty() && prev.chars().count() > 1))
            {
                // Incomplete/empty WAL proof fields without a recoverable single-character
                // placeholder indicate an unrecoverable proof-chain break.
                return Ok(None);
            }

            if !checkpoints_at_height.is_empty() {
                // Incomplete WAL proof at this height cannot be used to claim a newer
                // checkpoint; fall back to the last unambiguous checkpoint.
                return Ok(best_checkpoint_before_height);
            }
            return Ok(best_checkpoint);
        }
        if e.prev_hash_hex != prev_hash
            && prev_height.is_none_or(|last_height| last_height != e.height)
        {
            // Broken chain linkage is unrecoverable except for same-height replay duplicates.
            return Ok(best_checkpoint);
        }

        if !wal_checkpoint_metadata_surfaces_are_canonical(e)
            || !wal_state_root_surface_is_canonical(e)
        {
            return Ok(best_checkpoint);
        }

        let all_checkpoint_hashes_are_same = checkpoints_at_height
            .iter()
            .map(|checkpoint| checkpoint.wal_entry_hash_hex.as_str())
            .all(|first| {
                checkpoints_at_height
                    .iter()
                    .skip(1)
                    .all(|checkpoint| checkpoint.wal_entry_hash_hex == first)
            });

        let same_hash_checkpoints: Vec<&CheckpointMeta> = checkpoints_at_height
            .iter()
            .copied()
            .filter(|cp| cp.wal_entry_hash_hex == e.content_hash_hex())
            .collect();

        if !all_checkpoint_hashes_are_same && !same_hash_checkpoints.is_empty() {
            let has_valid_checkpoint_hash = checkpoints_at_height.iter().any(|cp| {
                !cp.state_root_hex.trim().is_empty()
                    && cp.state_root_hex == cp.state_root_hex.trim()
                    && is_canonical_hex_digest(&cp.wal_entry_hash_hex)
                    && !cp.wal_entry_hash_hex.trim().is_empty()
            });
            let has_single_char_checkpoint_hash = checkpoints_at_height
                .iter()
                .any(|cp| cp.wal_entry_hash_hex.chars().count() == 1);
            let has_non_trivial_checkpoint_hash = checkpoints_at_height.iter().any(|cp| {
                !cp.wal_entry_hash_hex.trim().is_empty()
                    && !cp.wal_entry_hash_hex.chars().all(char::is_whitespace)
            });

            if !has_valid_checkpoint_hash
                && !has_single_char_checkpoint_hash
                && !has_non_trivial_checkpoint_hash
            {
                return Ok(None);
            }

            best_checkpoint = best_checkpoint_before_height.clone();
            prev_hash = Some(e.content_hash_hex());
            prev_height = Some(e.height);
            if !e.committed {
                return Ok(best_checkpoint_before_height);
            }
            continue;
        }

        if !same_hash_checkpoints.is_empty() {
            // Checkpoint metadata for this height that binds the current WAL entry must be
            // canonical and unambiguous. If malformed, drop it to the last unambiguous
            // checkpoint instead of accepting a risky promotion.
            let valid = same_hash_checkpoints.iter().all(|cp| {
                !cp.state_root_hex.trim().is_empty()
                    && cp.wal_entry_hash_hex == e.content_hash_hex()
            });
            if !valid {
                let all_state_root_looks_empty = same_hash_checkpoints
                    .iter()
                    .all(|cp| cp.state_root_hex.trim().is_empty());
                if all_state_root_looks_empty {
                    // Ambiguous single-char placeholder metadata can be treated as recoverable
                    // corruption, while multi-char canonical-loss metadata is unrecoverable.
                    let has_single_char_empty_metadata = same_hash_checkpoints
                        .iter()
                        .all(|cp| cp.state_root_hex.len() == 1);
                    if has_single_char_empty_metadata {
                        best_checkpoint = best_checkpoint_before_height.clone();
                    } else {
                        return Ok(None);
                    }
                } else {
                    best_checkpoint = best_checkpoint_before_height.clone();
                }
            } else {
                let mut roots: Vec<&str> = same_hash_checkpoints
                    .iter()
                    .map(|cp| cp.state_root_hex.as_str())
                    .collect();
                roots.sort_unstable();
                roots.dedup();

                if roots.len() > 1 {
                    // Same height produced multiple candidate state roots for the same WAL hash.
                    // Keep the last unambiguous checkpoint only.
                    best_checkpoint = best_checkpoint_before_height.clone();
                } else if same_hash_checkpoints
                    .iter()
                    .any(|cp| cp.state_root_hex == e.state_root_hex)
                {
                    // Best-fit checkpoint matches this WAL entry.
                    let should_replace = best_checkpoint
                        .as_ref()
                        .map(|best| e.height >= best.height)
                        .unwrap_or(true);
                    if should_replace {
                        best_checkpoint = same_hash_checkpoints
                            .iter()
                            .find(|cp| cp.state_root_hex == e.state_root_hex)
                            .map(|cp| (*cp).clone());
                    }
                } else {
                    // Same-height checkpoint evidence cannot be validated against this WAL proof.
                    best_checkpoint = best_checkpoint_before_height.clone();
                }
            }

            // Maintain replay-chain continuity regardless of height duplicate semantics.
            prev_hash = Some(e.content_hash_hex());
            prev_height = Some(e.height);
            if !e.committed {
                return Ok(best_checkpoint_before_height);
            }
            continue;
        }

        // Same height with no canonical checkpoint metadata for this WAL hash.
        if !checkpoints_at_height.is_empty() {
            // Ambiguous/mismatched checkpoint evidence for this height must not advance.
            // Distinguish malformed checkpoint material from merely mismatched evidence.
            let has_valid_checkpoint_hash = checkpoints_at_height.iter().any(|cp| {
                cp.state_root_hex.trim() == cp.state_root_hex
                    && !cp.state_root_hex.trim().is_empty()
                    && is_canonical_hex_digest(&cp.wal_entry_hash_hex)
                    && !cp.wal_entry_hash_hex.trim().is_empty()
            });
            let has_single_char_checkpoint_hash = checkpoints_at_height
                .iter()
                .any(|cp| cp.wal_entry_hash_hex.chars().count() == 1);

            let has_non_trivial_checkpoint_hash = checkpoints_at_height.iter().any(|cp| {
                !cp.wal_entry_hash_hex.trim().is_empty()
                    && !cp.wal_entry_hash_hex.chars().all(char::is_whitespace)
            });
            if !has_valid_checkpoint_hash
                && !has_single_char_checkpoint_hash
                && !has_non_trivial_checkpoint_hash
            {
                return Ok(None);
            }

            best_checkpoint = best_checkpoint_before_height.clone();
            prev_hash = Some(e.content_hash_hex());
            prev_height = Some(e.height);
            if !e.committed {
                return Ok(best_checkpoint_before_height);
            }
            continue;
        }

        // No checkpoint tuple for this height references this WAL hash.
        prev_hash = Some(e.content_hash_hex());
        prev_height = Some(e.height);
        if e.committed {
            continue;
        }

        // Fail closed: uncommitted WAL tail must not advance recovery checkpoint.
        return Ok(best_checkpoint_before_height);
    }

    Ok(best_checkpoint)
}

/// Legacy-recovery variant used by node restart handling for compatibility with
/// existing node recovery invariants while preserving audit-surface checks.
pub fn verify_wal_and_find_checkpoint_node_recovery(
    checkpoints: &[CheckpointMeta],
    wal_entries: &[WalMeta],
) -> Result<Option<CheckpointMeta>, String> {
    let mut prev_hash: Option<String> = None;
    let mut prev_height: Option<u64> = None;
    let mut best_checkpoint: Option<CheckpointMeta> = None;

    for e in wal_entries {
        if !is_canonical_hex_digest(&e.content_hash_hex())
            || e.prev_hash_hex
                .as_deref()
                .is_some_and(|prev| !is_canonical_hex_digest(prev))
        {
            return Ok(best_checkpoint);
        }

        if let Some(last_height) = prev_height {
            let Some(expected_height) = last_height.checked_add(1) else {
                return Ok(best_checkpoint);
            };
            if e.height != expected_height {
                return Ok(best_checkpoint);
            }
        } else if e.height != 1 {
            return Ok(best_checkpoint);
        }

        if !wal_entry_has_complete_proof_metadata(e) {
            return Ok(best_checkpoint);
        }
        if e.prev_hash_hex != prev_hash {
            return Ok(best_checkpoint);
        }

        if !e.committed {
            return Ok(best_checkpoint);
        }

        let cur_hash = e.content_hash_hex();
        prev_hash = Some(cur_hash.clone());
        prev_height = Some(e.height);

        if !wal_checkpoint_metadata_surfaces_are_canonical(e)
            || !wal_state_root_surface_is_canonical(e)
        {
            return Ok(best_checkpoint);
        }

        for cp in checkpoints.iter().filter(|cp| cp.height == e.height) {
            if checkpoint_matches_wal_entry_for_recovery(cp, e, &cur_hash) {
                let should_replace = best_checkpoint
                    .as_ref()
                    .is_none_or(|best| e.height > best.height);
                if should_replace {
                    best_checkpoint = Some(cp.clone());
                }
            }
        }
    }

    Ok(best_checkpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::TaskStatus;

    #[test]
    fn checkpoint_evidence_surface_requires_canonical_checkpoint_and_wal_roots() {
        let wal_entry = WalMeta {
            height: 7,
            round: 0,
            proposal_hash: "proposal".into(),
            committed: true,
            state_root_hex: "ab".repeat(32),
            prev_hash_hex: Some("01".repeat(32)),
        };
        let checkpoint = CheckpointMeta {
            height: 7,
            state_root_hex: wal_entry.state_root_hex.clone(),
            wal_entry_hash_hex: wal_entry.content_hash_hex(),
        };

        assert!(checkpoint_evidence_surface_is_canonical(
            &checkpoint,
            &wal_entry
        ));

        let mut noncanonical_checkpoint = checkpoint.clone();
        noncanonical_checkpoint.state_root_hex = "not-hex".into();
        assert!(
            !checkpoint_evidence_surface_is_canonical(&noncanonical_checkpoint, &wal_entry),
            "checkpoint state-root evidence must be canonical hex"
        );

        let mut noncanonical_wal = wal_entry.clone();
        noncanonical_wal.state_root_hex = "not-hex".into();
        assert!(
            !checkpoint_evidence_surface_is_canonical(&checkpoint, &noncanonical_wal),
            "wal state-root evidence must be canonical hex"
        );

        let mut mismatched_checkpoint_root = checkpoint.clone();
        mismatched_checkpoint_root.state_root_hex = "cd".repeat(32);
        assert!(
            !checkpoint_evidence_surface_is_canonical(&mismatched_checkpoint_root, &wal_entry),
            "checkpoint evidence surfaces must bind the checkpoint state root to the evidenced WAL state root"
        );

        let mut mismatched_checkpoint_wal_hash = checkpoint.clone();
        mismatched_checkpoint_wal_hash.wal_entry_hash_hex = "ef".repeat(32);
        assert!(
            !checkpoint_evidence_surface_is_canonical(&mismatched_checkpoint_wal_hash, &wal_entry),
            "checkpoint evidence surfaces must bind wal_entry_hash_hex to the exact WAL content hash"
        );
    }

    #[test]
    fn checkpoint_commitment_binds_height_root_and_wal_hash() {
        let checkpoint = CheckpointMeta {
            height: 7,
            state_root_hex: "ab".repeat(32),
            wal_entry_hash_hex: "cd".repeat(32),
        };
        let baseline = checkpoint.commitment_hex();

        assert!(is_canonical_hex_digest(&baseline));

        let mut changed_height = checkpoint.clone();
        changed_height.height += 1;
        assert_ne!(baseline, changed_height.commitment_hex());

        let mut changed_root = checkpoint.clone();
        changed_root.state_root_hex = "ef".repeat(32);
        assert_ne!(baseline, changed_root.commitment_hex());

        let mut changed_wal_hash = checkpoint.clone();
        changed_wal_hash.wal_entry_hash_hex = "01".repeat(32);
        assert_ne!(baseline, changed_wal_hash.commitment_hex());
    }

    #[test]
    fn checkpoint_evidence_summary_is_deterministic_and_commitment_backed() {
        let checkpoint = CheckpointMeta {
            height: 7,
            state_root_hex: "ab".repeat(32),
            wal_entry_hash_hex: "cd".repeat(32),
        };

        let summary = checkpoint.evidence_summary();
        assert_eq!(
            summary,
            format!(
                "checkpoint_height=7 state_root={} wal_entry_hash={} checkpoint_commitment={}",
                checkpoint.state_root_hex,
                checkpoint.wal_entry_hash_hex,
                checkpoint.commitment_hex()
            )
        );

        let mut changed_wal_hash = checkpoint.clone();
        changed_wal_hash.wal_entry_hash_hex = "01".repeat(32);
        assert_ne!(
            summary,
            changed_wal_hash.evidence_summary(),
            "checkpoint evidence summary must change when the DA-relevant WAL hash changes"
        );
    }

    #[test]
    fn checkpoint_da_light_verifier_summary_is_canonical_and_includes_wal_linkage() {
        let wal = WalMeta {
            height: 7,
            round: 3,
            proposal_hash: "proposal-7".into(),
            committed: true,
            state_root_hex: "ab".repeat(32),
            prev_hash_hex: Some("ef".repeat(32)),
        };
        let checkpoint = CheckpointMeta {
            height: 7,
            state_root_hex: wal.state_root_hex.clone(),
            wal_entry_hash_hex: wal.content_hash_hex(),
        };

        let summary = checkpoint_da_light_verifier_summary(&checkpoint, &wal)
            .expect("canonical checkpoint/wal pair should surface a DA summary");
        assert_eq!(
            summary,
            format!(
                "checkpoint_commitment={} checkpoint_height=7 checkpoint_state_root={} checkpoint_wal_entry_hash={} wal_prev_hash={} wal_round=3 wal_proposal_hash=proposal-7",
                checkpoint.commitment_hex(),
                checkpoint.state_root_hex,
                checkpoint.wal_entry_hash_hex,
                wal.prev_hash_hex.as_deref().unwrap(),
            )
        );

        let mut changed_prev = wal.clone();
        changed_prev.prev_hash_hex = Some("01".repeat(32));
        assert_eq!(
            checkpoint_da_light_verifier_summary(&checkpoint, &changed_prev),
            None,
            "DA summary must fail closed when WAL linkage no longer matches canonical evidence"
        );
    }

    #[test]
    fn wal_evidence_summary_is_deterministic_and_hash_backed() {
        let wal = WalMeta {
            height: 7,
            round: 3,
            proposal_hash: "proposal-7".into(),
            committed: true,
            state_root_hex: "ab".repeat(32),
            prev_hash_hex: Some("cd".repeat(32)),
        };

        let summary = wal.evidence_summary();
        assert_eq!(
            summary,
            format!(
                "wal_height=7 wal_round=3 wal_proposal_hash=proposal-7 wal_committed=true wal_state_root={} wal_prev_hash={} wal_entry_hash={}",
                wal.state_root_hex,
                wal.prev_hash_hex.as_deref().unwrap(),
                wal.content_hash_hex()
            )
        );

        let mut changed_prev_hash = wal.clone();
        changed_prev_hash.prev_hash_hex = None;
        assert_ne!(
            summary,
            changed_prev_hash.evidence_summary(),
            "wal evidence summary must change when the predecessor proof surface changes"
        );
    }

    #[test]
    fn wal_content_hash_length_frames_variable_width_evidence_surfaces() {
        let base_state_root = format!("{}{}", "c", "d".repeat(63));
        let boundary_shifted_state_root = format!("{}{}", "d", "d".repeat(63));
        let prev_hash = "01".repeat(32);

        let wal_a = WalMeta {
            height: 9,
            round: 1,
            proposal_hash: "ab".into(),
            committed: true,
            state_root_hex: base_state_root,
            prev_hash_hex: Some(prev_hash.clone()),
        };
        let wal_b = WalMeta {
            height: 9,
            round: 1,
            proposal_hash: "abc".into(),
            committed: true,
            state_root_hex: boundary_shifted_state_root,
            prev_hash_hex: Some(prev_hash),
        };

        assert_ne!(
            wal_a.content_hash_hex(),
            wal_b.content_hash_hex(),
            "WAL checkpoint evidence hashing must length-frame proposal_hash and state_root_hex so adjacent audit surfaces cannot collide by shifting string boundaries"
        );
    }

    #[test]
    fn put_and_version_update() {
        let mut st = StateStore::new();
        let t = TaskObject {
            task_id: 7,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Open,
            proof_type: Default::default(),
            metadata: None,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        };
        let r1 = st.put_task_new(t.clone()).unwrap();
        assert_eq!(r1.version, 1);

        let mut t2 = t;
        t2.status = TaskStatus::Assigned;
        let r2 = st.update_task(r1, t2).unwrap();
        assert_eq!(r2.version, 2);
    }

    #[test]
    fn task_metering_snapshot_affects_state_root() {
        let mut without_metering = StateStore::new();
        let mut with_metering = StateStore::new();

        let base_task = TaskObject {
            task_id: 404,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: trnm_types::ProofType::Fraud,
            metadata: None,
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: Some(40),
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 2,
        };

        let mut metered_task = base_task.clone();
        metered_task.metadata = Some(trnm_types::TaskMetadata {
            note: Some("metered task".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: None,
            provenance: None,
            metering: Some(trnm_types::TaskMeteringSnapshot {
                workload_class: "llm_inference".into(),
                metering_schema: "llm_token_meter_v1".into(),
                policy_snapshot_version: 2,
                receipt_hash: "cd".repeat(32),
                prompt_tokens: 144,
                generated_tokens: 55,
                decode_steps: 13,
                kv_bytes_moved: 4096,
                normalized_work_units: 987,
                prompt_token_weight: 3,
                generated_token_weight: 5,
                decode_step_weight: 7,
                kv_byte_weight: 11,
                min_accept_work_units: 100,
                challenge_success_bounty_base: 17,
                challenge_success_bounty_per_work_unit_num: 19,
                challenge_success_bounty_per_work_unit_den: 23,
                worker_completion_bonus_per_work_unit_num: 29,
                worker_completion_bonus_per_work_unit_den: 31,
                worker_slash_rebate_per_work_unit_num: 37,
                worker_slash_rebate_per_work_unit_den: 41,
            }),
        });

        without_metering.put_task_new(base_task).unwrap();
        with_metering.put_task_new(metered_task).unwrap();

        assert_ne!(
            without_metering.state_root(),
            with_metering.state_root(),
            "state_root must include task metering snapshots so audit-proof work-unit evidence cannot be silently omitted"
        );
    }

    #[test]
    fn restore_task_rejects_incomplete_metering_proof_metadata() {
        let mut st = StateStore::new();

        let task = TaskObject {
            task_id: 405,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: trnm_types::ProofType::Fraud,
            metadata: Some(trnm_types::TaskMetadata {
                note: Some("restored task".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: None,
                provenance: None,
                metering: Some(trnm_types::TaskMeteringSnapshot {
                    workload_class: "llm_inference".into(),
                    metering_schema: "llm_token_meter_v1".into(),
                    policy_snapshot_version: 0,
                    receipt_hash: "cd".repeat(32),
                    prompt_tokens: 144,
                    generated_tokens: 55,
                    decode_steps: 13,
                    kv_bytes_moved: 4096,
                    normalized_work_units: 987,
                    prompt_token_weight: 3,
                    generated_token_weight: 5,
                    decode_step_weight: 7,
                    kv_byte_weight: 11,
                    min_accept_work_units: 100,
                    challenge_success_bounty_base: 17,
                    challenge_success_bounty_per_work_unit_num: 19,
                    challenge_success_bounty_per_work_unit_den: 0,
                    worker_completion_bonus_per_work_unit_num: 29,
                    worker_completion_bonus_per_work_unit_den: 31,
                    worker_slash_rebate_per_work_unit_num: 37,
                    worker_slash_rebate_per_work_unit_den: 41,
                }),
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: Some(40),
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 2,
        };

        st.restore_task(405, Some(task));

        assert!(
            st.get_task(405).is_none(),
            "restore_task must fail closed when metering proof metadata omits a concrete policy snapshot version or uses zero denominators"
        );
    }

    #[test]
    fn restore_task_rejects_non_canonical_metering_proof_metadata() {
        let mut st = StateStore::new();

        let task = TaskObject {
            task_id: 406,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: trnm_types::ProofType::Fraud,
            metadata: Some(trnm_types::TaskMetadata {
                note: Some("restored task".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: None,
                provenance: None,
                metering: Some(trnm_types::TaskMeteringSnapshot {
                    workload_class: " llm_inference".into(),
                    metering_schema: "llm_token_meter_v1 ".into(),
                    policy_snapshot_version: 2,
                    receipt_hash: format!("{}\n", "cd".repeat(32)),
                    prompt_tokens: 144,
                    generated_tokens: 55,
                    decode_steps: 13,
                    kv_bytes_moved: 4096,
                    normalized_work_units: 987,
                    prompt_token_weight: 3,
                    generated_token_weight: 5,
                    decode_step_weight: 7,
                    kv_byte_weight: 11,
                    min_accept_work_units: 100,
                    challenge_success_bounty_base: 17,
                    challenge_success_bounty_per_work_unit_num: 19,
                    challenge_success_bounty_per_work_unit_den: 23,
                    worker_completion_bonus_per_work_unit_num: 29,
                    worker_completion_bonus_per_work_unit_den: 31,
                    worker_slash_rebate_per_work_unit_num: 37,
                    worker_slash_rebate_per_work_unit_den: 41,
                }),
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: Some(40),
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 2,
        };

        st.restore_task(406, Some(task));

        assert!(
            st.get_task(406).is_none(),
            "restore_task must fail closed when metering proof metadata uses whitespace-padded fields instead of canonical snapshot material"
        );
    }

    #[test]
    fn version_conflict() {
        let mut st = StateStore::new();
        let t = TaskObject {
            task_id: 1,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Open,
            proof_type: Default::default(),
            metadata: None,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        };
        let r1 = st.put_task_new(t.clone()).unwrap();
        let _ = st.update_task(r1.clone(), t.clone()).unwrap();
        let err = st.update_task(r1, t).unwrap_err();
        assert!(err.contains("version conflict"));
    }

    #[test]
    fn wal_content_hash_distinguishes_ambiguous_variable_length_fields() {
        let base = WalMeta {
            height: 7,
            round: 3,
            proposal_hash: "ab".into(),
            committed: true,
            state_root_hex: "c".into(),
            prev_hash_hex: Some("tail".into()),
        };
        let ambiguous = WalMeta {
            proposal_hash: "a".into(),
            state_root_hex: "bc".into(),
            prev_hash_hex: Some("tail".into()),
            ..base.clone()
        };

        assert_ne!(
            base.content_hash_hex(),
            ambiguous.content_hash_hex(),
            "WAL content hashes must distinguish variable-length proposal/state-root tuples so checkpoint selection cannot alias semantically different entries"
        );
    }

    #[test]
    fn verify_wal_rejects_forged_checkpoint_on_uncommitted_tail() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2-uncommitted".into(),
            committed: false,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        let best = verify_wal_and_find_checkpoint(
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1.clone(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: e2.content_hash_hex(),
                },
            ],
            &[e1, e2],
        )
        .expect("verifier should fail closed instead of accepting uncommitted tail metadata");

        assert_eq!(best.as_ref().map(|cp| cp.height), Some(1));
        assert_eq!(
            best.as_ref().map(|cp| cp.state_root_hex.as_str()),
            Some("r1")
        );
    }

    #[test]
    fn checkpoint_recovery_binding_requires_matching_height_even_before_wal_scan_filtering() {
        let wal_entry = WalMeta {
            height: 7,
            round: 0,
            proposal_hash: "proposal-7".into(),
            committed: true,
            state_root_hex: "ab".repeat(32),
            prev_hash_hex: Some("01".repeat(32)),
        };
        let wal_entry_hash = wal_entry.content_hash_hex();
        let mismatched_checkpoint = CheckpointMeta {
            height: 8,
            state_root_hex: wal_entry.state_root_hex.clone(),
            wal_entry_hash_hex: wal_entry_hash.clone(),
        };

        assert!(
            !checkpoint_matches_wal_entry_for_recovery(
                &mismatched_checkpoint,
                &wal_entry,
                &wal_entry_hash,
            ),
            "checkpoint recovery binding must reject mismatched checkpoint/WAL heights even if hash surfaces happen to align"
        );
    }

    #[test]
    fn checkpoint_recovery_binding_rejects_noncanonical_digest_surface_even_before_wal_scan_filtering(
    ) {
        let wal_entry = WalMeta {
            height: 7,
            round: 0,
            proposal_hash: "proposal-7".into(),
            committed: true,
            state_root_hex: "AB".repeat(32),
            prev_hash_hex: Some("01".repeat(32)),
        };
        let wal_entry_hash = wal_entry.content_hash_hex();
        let checkpoint = CheckpointMeta {
            height: 7,
            state_root_hex: wal_entry.state_root_hex.clone(),
            wal_entry_hash_hex: wal_entry_hash.clone(),
        };

        assert!(
            !checkpoint_matches_wal_entry_for_recovery(&checkpoint, &wal_entry, &wal_entry_hash,),
            "checkpoint recovery binding must fail closed on noncanonical 64-hex state-root digest surfaces even if the checkpoint metadata otherwise aligns"
        );
    }

    #[test]
    fn checkpoint_recovery_binding_rejects_uncommitted_wal_even_before_wal_scan_filtering() {
        let wal_entry = WalMeta {
            height: 7,
            round: 0,
            proposal_hash: "proposal-7".into(),
            committed: false,
            state_root_hex: "r7".into(),
            prev_hash_hex: Some("01".repeat(32)),
        };
        let wal_entry_hash = wal_entry.content_hash_hex();
        let checkpoint = CheckpointMeta {
            height: 7,
            state_root_hex: wal_entry.state_root_hex.clone(),
            wal_entry_hash_hex: wal_entry_hash.clone(),
        };

        assert!(
            !checkpoint_matches_wal_entry_for_recovery(&checkpoint, &wal_entry, &wal_entry_hash,),
            "checkpoint recovery binding must fail closed on uncommitted WAL metadata even if hash and height surfaces otherwise align"
        );
    }

    #[test]
    fn resolve_approval_requires_two_distinct_approvers_before_ready() {
        let mut st = StateStore::new();

        let first = st
            .stage_or_confirm_resolve_approval(
                42,
                1,
                true,
                "authority-a",
                "authority-a,authority-b",
            )
            .expect("first approval stage should succeed");
        assert!(!first, "single approver must not finalize resolve approval");
        assert_eq!(st.pending_resolve_approval(42), Some((true, 1)));

        let dup_err = st
            .stage_or_confirm_resolve_approval(
                42,
                1,
                true,
                "authority-a",
                "authority-a,authority-b",
            )
            .expect_err("same approver must not satisfy multi-party confirmation");
        assert!(dup_err.contains("distinct approver"));
        assert_eq!(st.pending_resolve_approval(42), Some((true, 1)));

        let second = st
            .stage_or_confirm_resolve_approval(
                42,
                1,
                true,
                "authority-b",
                "authority-a,authority-b",
            )
            .expect("second distinct approver should finalize");
        assert!(
            second,
            "second distinct approver must finalize resolve approval"
        );
        assert_eq!(st.pending_resolve_approval(42), Some((true, 2)));

        st.clear_pending_resolve_approval(42);
        assert!(st.pending_resolve_approval(42).is_none());
    }

    #[test]
    fn clear_pending_resolve_approval_noop_preserves_state_root() {
        let mut st = StateStore::new();
        let root_before = st.state_root();

        st.clear_pending_resolve_approval(42);

        assert_eq!(
            st.pending_resolve_approval(42),
            None,
            "clearing a missing pending resolve approval must remain a no-op"
        );
        assert_eq!(
            st.state_root(),
            root_before,
            "clearing a missing pending resolve approval must preserve state_root"
        );
    }

    #[test]
    fn resolve_approval_rejects_decision_mismatch_without_mutation() {
        let mut st = StateStore::new();

        let first = st
            .stage_or_confirm_resolve_approval(
                7,
                1,
                false,
                "authority-a",
                "authority-a,authority-b",
            )
            .expect("initial non-slash approval should stage");
        assert!(!first);
        assert_eq!(st.pending_resolve_approval(7), Some((false, 1)));

        let mismatch = st
            .stage_or_confirm_resolve_approval(7, 1, true, "authority-b", "authority-a,authority-b")
            .expect_err("mismatched slash decision must fail closed");
        assert!(mismatch.contains("decision mismatch"));
        assert_eq!(
            st.pending_resolve_approval(7),
            Some((false, 1)),
            "decision mismatch must not mutate staged confirmation"
        );
    }

    #[test]
    fn resolve_approval_rejects_post_quorum_replay_without_mutation() {
        let mut st = StateStore::new();

        let first = st
            .stage_or_confirm_resolve_approval(
                88,
                1,
                true,
                "authority-a",
                "authority-a,authority-b",
            )
            .expect("first approval stage should succeed");
        assert!(!first);

        let second = st
            .stage_or_confirm_resolve_approval(
                88,
                1,
                true,
                "authority-b",
                "authority-a,authority-b",
            )
            .expect("second distinct approver should finalize");
        assert!(second);
        assert_eq!(st.pending_resolve_approval(88), Some((true, 2)));

        let replay_err = st
            .stage_or_confirm_resolve_approval(
                88,
                1,
                true,
                "authority-c",
                "authority-a,authority-b",
            )
            .expect_err("post-quorum replay must be rejected");
        assert!(
            replay_err.contains("already finalized")
                || replay_err.contains("configured authority member")
        );
        assert_eq!(
            st.pending_resolve_approval(88),
            Some((true, 2)),
            "post-quorum replay must not mutate confirmation state"
        );
    }

    #[test]
    fn resolve_approval_rejects_case_drift_duplicate_approver_without_mutation() {
        let mut st = StateStore::new();

        let first = st
            .stage_or_confirm_resolve_approval(
                77,
                1,
                true,
                "authority-a",
                "authority-a,authority-b",
            )
            .expect("first approval stage should succeed");
        assert!(!first);
        assert_eq!(st.pending_resolve_approval(77), Some((true, 1)));

        let dup_err = st
            .stage_or_confirm_resolve_approval(
                77,
                1,
                true,
                "Authority-A",
                "authority-a,authority-b",
            )
            .expect_err("case-drift duplicate approver must be rejected");
        assert!(
            dup_err.contains("distinct approver")
                || dup_err.contains("configured authority member")
        );
        assert_eq!(
            st.pending_resolve_approval(77),
            Some((true, 1)),
            "case-drift duplicate must not increase confirmation count"
        );
    }

    #[test]
    fn resolve_approval_rejects_whitespace_drift_approver_without_mutation() {
        let mut st = StateStore::new();

        let first = st
            .stage_or_confirm_resolve_approval(
                78,
                1,
                true,
                "authority-a",
                "authority-a,authority-b",
            )
            .expect("first approval stage should succeed");
        assert!(!first);
        assert_eq!(st.pending_resolve_approval(78), Some((true, 1)));

        let whitespace_err = st
            .stage_or_confirm_resolve_approval(
                78,
                1,
                true,
                " authority-a ",
                "authority-a,authority-b",
            )
            .expect_err("whitespace-drift approver must be rejected");
        assert!(whitespace_err.contains("must not contain whitespace"));
        assert_eq!(
            st.pending_resolve_approval(78),
            Some((true, 1)),
            "whitespace-drift approver must not increase confirmation count"
        );
    }

    #[test]
    fn resolve_approval_rejects_multiactor_delimited_approver_without_mutation() {
        let mut st = StateStore::new();

        let first = st
            .stage_or_confirm_resolve_approval(
                79,
                1,
                true,
                "authority-a",
                "authority-a,authority-b",
            )
            .expect("first approval stage should succeed");
        assert!(!first);
        assert_eq!(st.pending_resolve_approval(79), Some((true, 1)));

        for bad_actor in ["authority-a,authority-b", "authority-a;authority-b"] {
            let err = st
                .stage_or_confirm_resolve_approval(
                    79,
                    1,
                    true,
                    bad_actor,
                    "authority-a,authority-b",
                )
                .expect_err("delimited approver id must be rejected");
            assert!(err.contains("single canonical actor id"));
            assert_eq!(
                st.pending_resolve_approval(79),
                Some((true, 1)),
                "invalid approver id must not mutate staged confirmations"
            );
        }
    }

    #[test]
    fn resolve_approval_rejects_system_or_treasury_approver_without_mutation() {
        let mut st = StateStore::new();

        let first = st
            .stage_or_confirm_resolve_approval(
                80,
                1,
                true,
                "authority-a",
                "authority-a,authority-b",
            )
            .expect("first approval stage should succeed");
        assert!(!first);
        assert_eq!(st.pending_resolve_approval(80), Some((true, 1)));

        for bad_actor in [
            DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER,
            "System",
            CHALLENGE_ESCROW_ACCOUNT,
            "Treasury.Challenge_Forfeits",
        ] {
            let err = st
                .stage_or_confirm_resolve_approval(
                    80,
                    1,
                    true,
                    bad_actor,
                    "authority-a,authority-b",
                )
                .expect_err("system/treasury approver must be rejected");
            assert!(err.contains("explicit non-system authority"));
            assert_eq!(
                st.pending_resolve_approval(80),
                Some((true, 1)),
                "reserved approver id must not mutate staged confirmations"
            );
        }
    }

    #[test]
    fn resolve_approval_rejects_noncanonical_authority_set_without_mutation() {
        let mut st = StateStore::new();

        for malformed_set in [
            "authority-a",
            "authority-a,",
            "authority-a, authority-b",
            "authority-a;authority-b",
            "authority-a,AUTHORITY-A",
            "authority-a,system",
        ] {
            let err = st
                .stage_or_confirm_resolve_approval(8_882, 1, true, "authority-a", malformed_set)
                .expect_err("non-canonical authority set must fail closed");
            assert!(
                err.contains("authority set"),
                "unexpected error for malformed set {malformed_set}: {err}"
            );
            assert_eq!(
                st.pending_resolve_approval(8_882),
                None,
                "malformed authority set must not stage pending approvals"
            );
        }
    }

    #[test]
    fn resolve_approval_clears_stale_stage_on_task_version_change() {
        let mut st = StateStore::new();

        let first = st
            .stage_or_confirm_resolve_approval(
                82,
                3,
                true,
                "authority-a",
                "authority-a,authority-b",
            )
            .expect("first approval stage should succeed");
        assert!(!first);
        assert_eq!(st.pending_resolve_approval(82), Some((true, 1)));

        let version_err = st
            .stage_or_confirm_resolve_approval(
                82,
                4,
                true,
                "authority-b",
                "authority-a,authority-b",
            )
            .expect_err("task version change must fail closed and clear stale stage");
        assert!(version_err.contains("task version changed"));
        assert_eq!(st.pending_resolve_approval(82), None);
        assert_eq!(st.pending_resolve_first_approver(82), None);
    }

    #[test]
    fn resolve_approval_task_version_mismatch_invalidates_cached_state_root() {
        let mut st = StateStore::new();

        st.stage_or_confirm_resolve_approval(
            8_283,
            3,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .expect("first approval stage should succeed");

        let root_with_pending = st.state_root();

        let err = st
            .stage_or_confirm_resolve_approval(
                8_283,
                4,
                true,
                "authority-b",
                "authority-a,authority-b",
            )
            .expect_err("task-version mismatch should clear staged approval");
        assert!(err.contains("task version changed"));

        let root_after_clear = st.state_root();

        let baseline = StateStore::new().state_root();
        assert_eq!(st.pending_resolve_approval(8_283), None);
        assert_ne!(
            root_with_pending, root_after_clear,
            "clearing stale pending resolve approval must invalidate cached state root"
        );
        assert_eq!(
            root_after_clear, baseline,
            "after stale-stage clear, state root should match an empty store"
        );
    }

    #[test]
    fn restore_pending_resolve_approval_allows_canonical_snapshot_without_backing_task() {
        let mut st = StateStore::new();
        let baseline = st.state_root();

        st.restore_pending_resolve_approval(
            9_901,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );

        assert_eq!(st.pending_resolve_approval(9_901), Some((true, 1)));
        assert_ne!(
            st.state_root(),
            baseline,
            "restore must materialize a canonical pending approval snapshot when the task id is otherwise unused"
        );
    }

    #[test]
    fn restore_pending_resolve_approval_rejects_snapshot_when_id_is_owned_by_non_task_object() {
        let mut st = StateStore::new();
        st.restore_gov_param(
            9_901,
            Some(GovParamObject {
                key_id: 9_901,
                key: "monetary_base_burn_per_tick".into(),
                value: "11".into(),
                version: 1,
            }),
        );
        let root_before = st.state_root();

        st.restore_pending_resolve_approval(
            9_901,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 1,
            }),
        );

        assert_eq!(st.pending_resolve_approval(9_901), None);
        assert_eq!(
            st.get_param(9_901)
                .map(|param| (param.key_id, param.key, param.value, param.version)),
            Some((
                9_901,
                "monetary_base_burn_per_tick".into(),
                "11".into(),
                1,
            )),
            "pending resolve restore must not materialize on an id already owned by a non-task object"
        );
        assert_eq!(
            st.state_root(),
            root_before,
            "cross-type pending resolve restore rejection must leave state_root unchanged"
        );
    }

    #[test]
    fn restore_pending_resolve_approval_canonicalizes_snapshot_metadata_and_state_root() {
        let mut restored = StateStore::new();
        restored.restore_pending_resolve_approval(
            9_901,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "Authority-A".into(),
                authority_set: "authority-b,authority-a".into(),
                task_version: 3,
            }),
        );

        let mut canonical = StateStore::new();
        canonical.restore_pending_resolve_approval(
            9_901,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );

        assert_eq!(
            restored.pending_resolve_first_approver(9_901),
            Some("authority-a".to_string()),
            "restore should canonicalize the stored approver identity to its deterministic form"
        );
        assert_eq!(
            restored
                .pending_resolve_approval_snapshot(9_901)
                .map(|snapshot| snapshot.authority_set),
            Some("authority-a,authority-b".to_string()),
            "restore should canonicalize stored authority-set metadata to deterministic ordering"
        );
        assert_eq!(
            restored.pending_resolve_approval_snapshot(9_901),
            canonical.pending_resolve_approval_snapshot(9_901),
            "logically equivalent snapshots should collapse to the same canonical stored pending approval"
        );
        assert_eq!(
            restored.state_root(),
            canonical.state_root(),
            "restore must normalize canonical-equivalent snapshots to the same pending-approval state root"
        );
    }

    #[test]
    fn restore_pending_resolve_approval_scrubs_invalid_replacement_from_existing_state() {
        let mut st = StateStore::new();
        st.restore_task(
            9_901,
            Some(TaskObject {
                task_id: 9_901,
                creator: "alice".into(),
                bounty: 10,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-1".into()),
                committed_hash: None,
                result_hash: None,
                reveal_salt: None,
                committed_at_height: None,
                reveal_deadline_height: None,
                challenge_deadline_height: None,
                challenge_window_blocks_snapshot: None,
                challenged_at_height: Some(12),
                resolve_deadline_height: None,
                challenge_bond: None,
                challenger: Some("bob".into()),
                challenge_bond_forfeited: None,
                version: 3,
            }),
        );
        st.restore_pending_resolve_approval(
            9_901,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );
        let root_before = st.state_root();

        st.restore_pending_resolve_approval(
            9_901,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: false,
                confirmations: 2,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );

        assert_eq!(st.pending_resolve_approval(9_901), None);
        assert_eq!(
            st.pending_resolve_first_approver(9_901),
            None,
            "invalid restore snapshot must scrub the existing staged approver"
        );
        assert_ne!(
            st.state_root(),
            root_before,
            "invalid restore snapshot must invalidate the pending-approval state root"
        );
    }

    #[test]
    fn restore_pending_resolve_approval_rejects_snapshot_when_backing_task_is_not_challenged() {
        let mut st = StateStore::new();
        st.restore_task(
            9_904,
            Some(TaskObject {
                task_id: 9_904,
                creator: "alice".into(),
                bounty: 10,
                status: TaskStatus::Assigned,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-1".into()),
                committed_hash: None,
                result_hash: None,
                reveal_salt: None,
                committed_at_height: None,
                reveal_deadline_height: None,
                challenge_deadline_height: None,
                challenge_window_blocks_snapshot: None,
                challenged_at_height: None,
                resolve_deadline_height: None,
                challenge_bond: None,
                challenger: None,
                challenge_bond_forfeited: None,
                version: 3,
            }),
        );
        let baseline = st.state_root();

        st.restore_pending_resolve_approval(
            9_904,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );

        assert_eq!(st.pending_resolve_approval(9_904), None);
        assert_eq!(
            st.state_root(),
            baseline,
            "restore must reject pending resolve snapshots that do not match the backing task lifecycle"
        );
    }

    #[test]
    fn restore_pending_resolve_approval_replaces_existing_stage_when_only_task_version_changes() {
        let mut st = StateStore::new();
        st.restore_pending_resolve_approval(
            9_902,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );
        let root_with_pending = st.state_root();

        st.restore_pending_resolve_approval(
            9_902,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 4,
            }),
        );

        assert_eq!(st.pending_resolve_approval(9_902), Some((true, 1)));
        assert_ne!(
            st.state_root(),
            root_with_pending,
            "restore must treat task_version as part of pending resolve object identity when replacing an existing staged snapshot"
        );
    }

    #[test]
    fn restore_pending_resolve_approval_scrubs_zero_identity_inputs() {
        let mut st = StateStore::new();
        let baseline = st.state_root();

        st.restore_pending_resolve_approval(
            0,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );
        assert_eq!(st.pending_resolve_approval(0), None);
        assert_eq!(st.state_root(), baseline);

        st.restore_pending_resolve_approval(
            9_903,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 0,
            }),
        );
        assert_eq!(st.pending_resolve_approval(9_903), None);
        assert_eq!(st.state_root(), baseline);

        st.restore_pending_resolve_approval(
            9_904,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 0,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );
        assert_eq!(st.pending_resolve_approval(9_904), None);
        assert_eq!(st.state_root(), baseline);
    }

    #[test]
    fn resolve_approval_clears_stale_stage_on_authority_set_rotation() {
        let mut st = StateStore::new();

        let first = st
            .stage_or_confirm_resolve_approval(
                81,
                7,
                true,
                "authority-a",
                "authority-a,authority-b",
            )
            .expect("first approval stage should succeed");
        assert!(!first);
        assert_eq!(st.pending_resolve_approval(81), Some((true, 1)));

        let rotated_err = st
            .stage_or_confirm_resolve_approval(
                81,
                7,
                true,
                "authority-c",
                "authority-a,authority-c",
            )
            .expect_err("authority set rotation must fail closed and clear stale stage");
        assert!(rotated_err.contains("authority set changed"));
        assert_eq!(st.pending_resolve_approval(81), None);
        assert_eq!(st.pending_resolve_first_approver(81), None);
    }

    #[test]
    fn resolve_approval_preserves_staged_quorum_on_authority_set_case_drift() {
        let mut st = StateStore::new();

        let first = st
            .stage_or_confirm_resolve_approval(
                8_181,
                7,
                true,
                "authority-a",
                "authority-a,authority-b",
            )
            .expect("first approval stage should succeed");
        assert!(!first);
        assert_eq!(st.pending_resolve_approval(8_181), Some((true, 1)));

        let second = st
            .stage_or_confirm_resolve_approval(
                8_181,
                7,
                true,
                "Authority-B",
                "authority-a,Authority-B",
            )
            .expect("authority set case drift should preserve staged quorum");
        assert!(second);
        assert_eq!(st.pending_resolve_approval(8_181), Some((true, 2)));
        assert_eq!(
            st.pending_resolve_first_approver(8_181).as_deref(),
            Some("authority-a")
        );
    }

    #[test]
    fn resolve_approval_stage_canonicalizes_authority_metadata_for_restore_roundtrip() {
        let mut staged = StateStore::new();
        staged.restore_task(
            8_182,
            Some(TaskObject {
                task_id: 8_182,
                creator: "creator-restore".into(),
                bounty: 1,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-restore".into()),
                committed_hash: None,
                result_hash: None,
                reveal_salt: None,
                committed_at_height: None,
                reveal_deadline_height: None,
                challenge_deadline_height: None,
                challenge_window_blocks_snapshot: None,
                challenged_at_height: None,
                resolve_deadline_height: None,
                challenge_bond: None,
                challenger: Some("challenger-restore".into()),
                challenge_bond_forfeited: None,
                version: 7,
            }),
        );
        let mut restored = staged.clone();

        staged
            .stage_or_confirm_resolve_approval(
                8_182,
                7,
                true,
                "Authority-A",
                "authority-b,Authority-A",
            )
            .expect("mixed-case stage should canonicalize into a valid pending resolve snapshot");
        let staged_root = staged.state_root();
        let staged_snapshot = staged
            .pending_resolve_approval_snapshot(8_182)
            .expect("staged snapshot should exist");

        assert_eq!(
            staged_snapshot.first_approver,
            "authority-a",
            "stage path should store the canonical first approver so restore re-entry sees the same logical snapshot"
        );
        assert_eq!(
            staged_snapshot.authority_set,
            "authority-a,authority-b",
            "stage path should store the canonical authority set ordering so restore re-entry sees the same logical snapshot"
        );

        restored.restore_pending_resolve_approval(8_182, Some(staged_snapshot));

        assert_eq!(
            restored.state_root(),
            staged_root,
            "restoring a staged pending resolve snapshot should preserve the deterministic state root when re-entry canonicalization is semantically identical"
        );
    }

    #[test]
    fn restore_pending_resolve_preserves_audit_spelling_for_equivalent_authority_snapshot() {
        let mut st = StateStore::new();
        st.restore_gov_param(
            1,
            Some(GovParamObject {
                key_id: 1,
                key: "resolve_authority".into(),
                value: "authority-a,authority-b".into(),
                version: 1,
            }),
        );
        st.restore_task(
            9_000,
            Some(TaskObject {
                task_id: 9_000,
                creator: "alice".into(),
                bounty: 10,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-a".into()),
                committed_hash: None,
                result_hash: None,
                reveal_salt: None,
                committed_at_height: None,
                reveal_deadline_height: None,
                challenge_deadline_height: None,
                challenge_window_blocks_snapshot: None,
                challenged_at_height: Some(55),
                resolve_deadline_height: Some(66),
                challenge_bond: Some(7),
                challenger: Some("bob".into()),
                challenge_bond_forfeited: None,
                version: 3,
            }),
        );

        st.restore_pending_resolve_approval(
            9_000,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "Authority-B".into(),
                authority_set: "Authority-B,Authority-A".into(),
                task_version: 3,
            }),
        );

        assert_eq!(st.pending_resolve_approval(9_000), Some((true, 1)));
        assert_eq!(
            st.pending_resolve_first_approver(9_000).as_deref(),
            Some("authority-b")
        );
        let snapshot = st
            .pending_resolve_approval_snapshot(9_000)
            .expect("equivalent snapshot should be restored");
        assert_eq!(snapshot.first_approver, "authority-b");
        assert_eq!(snapshot.authority_set, "authority-a,authority-b");
    }

    #[test]
    fn restore_task_preserves_pending_resolve_across_identical_same_version_snapshot_reentry() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 9_001,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-a".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };
        st.restore_task(task.task_id, Some(task.clone()));
        st.restore_pending_resolve_approval(
            task.task_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );
        assert_eq!(st.pending_resolve_approval(task.task_id), Some((true, 1)));
        let root_before_reentry = st.state_root();

        st.restore_task(task.task_id, Some(task));

        assert_eq!(st.pending_resolve_approval(9_001), Some((true, 1)));
        assert_eq!(
            st.pending_resolve_first_approver(9_001).as_deref(),
            Some("authority-a")
        );
        assert_eq!(st.state_root(), root_before_reentry);
    }

    #[test]
    fn restore_task_scrubs_finalized_pending_resolve_on_identical_snapshot_reentry() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 9_006,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-a".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };
        st.restore_task(task.task_id, Some(task.clone()));
        st.restore_pending_resolve_approval(
            task.task_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );
        let finalized = st
            .stage_or_confirm_resolve_approval(
                task.task_id,
                3,
                true,
                "authority-b",
                "authority-a,authority-b",
            )
            .expect("second approval should finalize quorum");
        assert!(finalized);
        assert_eq!(st.pending_resolve_approval(task.task_id), Some((true, 2)));
        let root_with_finalized_pending = st.state_root();

        st.restore_task(task.task_id, Some(task.clone()));

        assert_eq!(st.pending_resolve_approval(9_006), None);
        assert_eq!(st.pending_resolve_first_approver(9_006), None);
        assert_ne!(
            st.state_root(),
            root_with_finalized_pending,
            "identical restore re-entry must invalidate the cached state root when finalized pending resolve residue is scrubbed"
        );

        let mut baseline = StateStore::new();
        baseline.restore_task(task.task_id, Some(task));
        assert_eq!(
            st.state_root(),
            baseline.state_root(),
            "scrubbing finalized pending resolve residue should converge to the same state root as the clean restored task snapshot"
        );
    }

    #[test]
    fn restore_task_scrubs_corrupt_pending_resolve_on_identical_snapshot_reentry() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 9_007,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-a".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };
        st.restore_task(task.task_id, Some(task.clone()));
        st.pending_resolve_approvals.insert(
            task.task_id,
            PendingResolveApproval {
                slash_worker: true,
                confirmations: 0,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
                stored_as_canonical: false,
            },
        );
        let root_with_corrupt_pending = st.state_root();

        st.restore_task(task.task_id, Some(task.clone()));

        assert_eq!(st.pending_resolve_approval(task.task_id), None);
        assert_eq!(st.pending_resolve_first_approver(task.task_id), None);
        assert_ne!(
            st.state_root(),
            root_with_corrupt_pending,
            "identical restore re-entry must invalidate the cached state root when corrupt pending resolve residue is scrubbed"
        );

        let mut baseline = StateStore::new();
        baseline.restore_task(task.task_id, Some(task));
        assert_eq!(
            st.state_root(),
            baseline.state_root(),
            "scrubbing corrupt pending resolve residue should converge to the same state root as the clean restored task snapshot"
        );
    }

    #[test]
    fn restore_task_scrubs_version_mismatched_pending_resolve_on_identical_snapshot_reentry() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 9_010,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-a".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };
        st.restore_task(task.task_id, Some(task.clone()));
        st.pending_resolve_approvals.insert(
            task.task_id,
            PendingResolveApproval {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 2,
                stored_as_canonical: false,
            },
        );
        let root_with_version_mismatch = st.state_root();

        st.restore_task(task.task_id, Some(task.clone()));

        assert_eq!(st.pending_resolve_approval(task.task_id), None);
        assert_eq!(st.pending_resolve_first_approver(task.task_id), None);
        assert_ne!(
            st.state_root(),
            root_with_version_mismatch,
            "identical restore re-entry must invalidate the cached state root when a stale task-version pending resolve residue is scrubbed"
        );

        let mut baseline = StateStore::new();
        baseline.restore_task(task.task_id, Some(task));
        assert_eq!(
            st.state_root(),
            baseline.state_root(),
            "scrubbing task-version-mismatched pending resolve residue should converge to the clean restored task snapshot"
        );
    }

    #[test]
    fn restore_task_reapplies_snapshot_when_outer_object_version_drifts() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 9_011,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-a".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };
        st.restore_task(task.task_id, Some(task.clone()));
        st.restore_pending_resolve_approval(
            task.task_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );
        st.objects
            .get_mut(&task.task_id)
            .expect("task object should exist")
            .version = 99;

        st.restore_task(task.task_id, Some(task.clone()));

        assert_eq!(st.pending_resolve_approval(task.task_id), None);
        assert_eq!(st.pending_resolve_first_approver(task.task_id), None);
        assert_eq!(
            st.get_ref(task.task_id).map(|r| r.version),
            Some(task.version)
        );
        assert_eq!(st.get_task(task.task_id), Some(task));
    }

    #[test]
    fn restore_pending_resolve_rejects_snapshot_when_outer_task_version_drifts() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 9_012,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-a".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };
        st.restore_task(task.task_id, Some(task.clone()));
        st.objects
            .get_mut(&task.task_id)
            .expect("task object should exist")
            .version = 99;
        let root_before_restore = st.state_root();

        st.restore_pending_resolve_approval(
            task.task_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );

        assert_eq!(st.pending_resolve_approval(task.task_id), None);
        assert_eq!(st.pending_resolve_first_approver(task.task_id), None);
        assert_eq!(
            st.get_ref(task.task_id).map(|r| r.version),
            Some(99),
            "rejecting the pending restore must not silently rewrite the drifted outer object version"
        );
        assert_eq!(
            st.state_root(),
            root_before_restore,
            "rejecting a pending restore snapshot across an outer object/version drift should remain a state-root no-op"
        );
    }

    #[test]
    fn restore_task_preserves_equivalent_pending_resolve_on_identical_snapshot_reentry() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 9_008,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-a".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };
        st.restore_task(task.task_id, Some(task.clone()));
        st.pending_resolve_approvals.insert(
            task.task_id,
            PendingResolveApproval {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-b,authority-a".into(),
                task_version: 3,
                stored_as_canonical: false,
            },
        );
        let root_with_noncanonical_pending = st.state_root();

        st.restore_task(task.task_id, Some(task.clone()));

        assert_eq!(st.pending_resolve_approval(task.task_id), Some((true, 1)));
        assert_eq!(
            st.pending_resolve_first_approver(task.task_id).as_deref(),
            Some("authority-a")
        );
        assert_eq!(
            st.pending_resolve_approval_snapshot(task.task_id)
                .expect("equivalent pending resolve snapshot should survive")
                .authority_set,
            "authority-b,authority-a"
        );
        assert_eq!(
            st.state_root(),
            root_with_noncanonical_pending,
            "identical restore re-entry should preserve semantically equivalent pending resolve audit spelling"
        );
    }

    #[test]
    fn restore_task_clears_stale_pending_resolve_when_restored_version_changes() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 9_004,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };
        st.restore_task(task.task_id, Some(task.clone()));
        st.restore_pending_resolve_approval(
            task.task_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );
        assert_eq!(st.pending_resolve_approval(task.task_id), Some((true, 1)));

        let mut restored = task;
        restored.version = 4;
        st.restore_task(restored.task_id, Some(restored));

        assert_eq!(st.pending_resolve_approval(9_004), None);
        assert_eq!(st.pending_resolve_first_approver(9_004), None);
    }

    #[test]
    fn restore_task_clears_pending_resolve_when_object_id_conflicts_with_gov_param_key_slot() {
        let mut st = StateStore::new();
        st.restore_gov_param(
            9_020,
            Some(GovParamObject {
                key_id: 9_020,
                key: "resolve_authority".into(),
                value: "authority-a,authority-b".into(),
                version: 1,
            }),
        );

        let task = TaskObject {
            task_id: 9_020,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-a".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };

        st.restore_task(task.task_id, Some(task.clone()));
        st.restore_pending_resolve_approval(
            task.task_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );

        let baseline_root = {
            let mut baseline = StateStore::new();
            baseline.restore_gov_param(
                9_020,
                Some(GovParamObject {
                    key_id: 9_020,
                    key: "resolve_authority".into(),
                    value: "authority-a,authority-b".into(),
                    version: 1,
                }),
            );
            baseline.restore_task(task.task_id, Some(task.clone()));
            baseline.state_root()
        };

        st.restore_task(task.task_id, Some(task));

        assert_eq!(st.pending_resolve_approval(9_020), None);
        assert_eq!(st.pending_resolve_first_approver(9_020), None);
        assert_eq!(st.state_root(), baseline_root);
    }

    #[test]
    fn restore_task_clears_stale_pending_resolve_when_task_is_removed() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 9_002,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };
        st.restore_task(task.task_id, Some(task.clone()));
        st.restore_pending_resolve_approval(
            task.task_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );
        assert_eq!(st.pending_resolve_approval(task.task_id), Some((true, 1)));

        st.restore_task(task.task_id, None);

        assert_eq!(st.pending_resolve_approval(9_002), None);
        assert_eq!(st.pending_resolve_first_approver(9_002), None);
    }

    #[test]
    fn restore_pending_resolve_approval_is_noop_for_identical_snapshot_reentry() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 9_006,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };
        st.restore_task(task.task_id, Some(task.clone()));
        st.restore_pending_resolve_approval(
            task.task_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );

        let root_before = st.state_root();
        let snapshot_before = st
            .pending_resolve_approval_snapshot(task.task_id)
            .expect("pending resolve snapshot should exist before identical restore re-entry");

        st.restore_pending_resolve_approval(task.task_id, Some(snapshot_before.clone()));

        assert_eq!(
            st.pending_resolve_approval_snapshot(task.task_id),
            Some(snapshot_before),
            "identical restore re-entry should preserve the canonical pending resolve snapshot"
        );
        assert_eq!(
            st.state_root(),
            root_before,
            "identical restore re-entry should remain a state-root no-op for pending resolve snapshots"
        );
    }

    #[test]
    fn restore_pending_resolve_identical_finalized_snapshot_reentry_scrubs_invalid_quorum() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 9_006,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };
        st.restore_task(task.task_id, Some(task.clone()));
        st.restore_pending_resolve_approval(
            task.task_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );
        let staged_root = st.state_root();

        let finalized_snapshot = PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 3,
        };
        st.restore_pending_resolve_approval(task.task_id, Some(finalized_snapshot.clone()));
        assert_eq!(
            st.pending_resolve_approval_snapshot(task.task_id),
            None,
            "finalized restore snapshots without second-approver evidence must fail closed instead of surviving identical re-entry"
        );
        assert_ne!(
            st.state_root(),
            staged_root,
            "scrubbing an invalid finalized pending resolve snapshot must perturb the deterministic root"
        );

        st.restore_pending_resolve_approval(task.task_id, Some(finalized_snapshot));
        assert_eq!(
            st.pending_resolve_approval_snapshot(task.task_id),
            None,
            "replaying the same finalized snapshot should remain fail-closed after the first scrub"
        );
    }

    #[test]
    fn restore_task_scrubs_pending_resolve_on_identical_non_challenged_snapshot_reentry() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 9_009,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Completed,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-a".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };
        st.restore_task(task.task_id, Some(task.clone()));
        st.pending_resolve_approvals.insert(
            task.task_id,
            PendingResolveApproval {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
                stored_as_canonical: false,
            },
        );
        let root_with_stale_pending = st.state_root();

        st.restore_task(task.task_id, Some(task.clone()));

        assert_eq!(st.pending_resolve_approval(task.task_id), None);
        assert_eq!(st.pending_resolve_first_approver(task.task_id), None);
        assert_ne!(
            st.state_root(),
            root_with_stale_pending,
            "identical restore re-entry must scrub stale pending resolve residue once the task is no longer challenged"
        );

        let mut baseline = StateStore::new();
        baseline.restore_task(task.task_id, Some(task));
        assert_eq!(
            st.state_root(),
            baseline.state_root(),
            "scrubbing stale pending resolve residue on a non-challenged task should converge to the clean restored snapshot"
        );
    }

    #[test]
    fn restore_task_clears_stale_pending_resolve_when_effective_authority_drifts() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 9_003,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };
        st.restore_task(task.task_id, Some(task.clone()));
        st.restore_pending_resolve_approval(
            task.task_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );
        assert_eq!(st.pending_resolve_approval(task.task_id), Some((true, 1)));

        st.set_gov_param_unchecked(
            7001,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("resolve authority update should apply");

        st.restore_task(task.task_id, Some(task));

        assert_eq!(st.pending_resolve_approval(9_003), None);
        assert_eq!(st.pending_resolve_first_approver(9_003), None);
    }

    #[test]
    fn restore_task_clears_stale_pending_resolve_when_pending_authority_drifts() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 9_004,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };
        st.restore_task(task.task_id, Some(task.clone()));
        st.restore_pending_resolve_approval(
            task.task_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 3,
            }),
        );
        assert_eq!(st.pending_resolve_approval(task.task_id), Some((true, 1)));

        let scheduled = st
            .set_gov_param(
                10,
                7001,
                "resolve_authority".into(),
                "authority-c,authority-d".into(),
            )
            .expect("pending resolve authority drift should schedule cleanly");
        assert!(matches!(scheduled, GovParamUpdateOutcome::Scheduled { .. }));

        st.restore_task(task.task_id, Some(task));

        assert_eq!(st.pending_resolve_approval(9_004), None);
        assert_eq!(st.pending_resolve_first_approver(9_004), None);
    }

    #[test]
    fn restore_task_preserves_pending_resolve_across_identical_snapshot_reentry_with_authority_case_drift(
    ) {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 9_005,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: Some(55),
            resolve_deadline_height: Some(66),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 3,
        };
        st.restore_task(task.task_id, Some(task.clone()));
        st.restore_pending_resolve_approval(
            task.task_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "Authority-A,Authority-B".into(),
                task_version: 3,
            }),
        );
        assert_eq!(st.pending_resolve_approval(task.task_id), Some((true, 1)));

        st.set_gov_param_unchecked(
            7001,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("resolve authority case-normalization update should apply");

        st.restore_task(task.task_id, Some(task));

        assert_eq!(st.pending_resolve_approval(9_005), Some((true, 1)));
        assert_eq!(
            st.pending_resolve_first_approver(9_005).as_deref(),
            Some("authority-a")
        );
    }

    #[test]
    fn governance_minimal_state_machine() {
        let mut st = StateStore::new();
        let p = GovProposalObject {
            proposal_id: 9001,
            title: "update param x".into(),
            proposer: "alice".into(),
            status: GovProposalStatus::Draft,
            version: 1,
        };
        let r1 = st.put_proposal_new(p).unwrap();

        let r2 = st
            .transition_proposal_status(r1, GovProposalStatus::Voting)
            .unwrap();
        let r3 = st
            .transition_proposal_status(r2, GovProposalStatus::Passed)
            .unwrap();
        let _r4 = st
            .transition_proposal_status(r3, GovProposalStatus::Executed)
            .unwrap();

        let cur = st.get_proposal(9001).unwrap();
        assert_eq!(cur.status, GovProposalStatus::Executed);
    }

    #[test]
    fn governance_invalid_transition_rejected() {
        let mut st = StateStore::new();
        let p = GovProposalObject {
            proposal_id: 9002,
            title: "bad jump".into(),
            proposer: "alice".into(),
            status: GovProposalStatus::Draft,
            version: 1,
        };
        let r1 = st.put_proposal_new(p).unwrap();
        let err = st
            .transition_proposal_status(r1, GovProposalStatus::Passed)
            .unwrap_err();
        assert!(err.contains("invalid governance transition"));
    }

    #[test]
    fn governance_pause_does_not_bypass_invalid_transition_guards() {
        // Merge-gate guard: emergency pause must not weaken proposal transition checks.
        let mut st = StateStore::new();

        // Enter paused mode through the checked governance path.
        let paused = st
            .set_gov_param(9_200, 7_999, "emergency_pause".into(), "true".into())
            .unwrap();
        assert!(matches!(paused, GovParamUpdateOutcome::Applied(_)));
        assert!(st.is_emergency_paused());

        let proposal = GovProposalObject {
            proposal_id: 9_201,
            title: "paused invalid jump".into(),
            proposer: "alice".into(),
            status: GovProposalStatus::Draft,
            version: 1,
        };
        let expected = st.put_proposal_new(proposal).unwrap();

        let err = st
            .transition_proposal_status(expected, GovProposalStatus::Passed)
            .unwrap_err();
        assert!(err.contains("invalid governance transition"));

        // Proposal must remain unchanged after failed transition while paused.
        let cur = st.get_proposal(9_201).unwrap();
        assert_eq!(cur.status, GovProposalStatus::Draft);
        assert_eq!(
            cur.version, 1,
            "failed transition while paused must not mutate proposal version"
        );
    }

    #[test]
    fn governance_pause_does_not_block_valid_transition_path() {
        // Merge-gate guard: emergency pause is an execution-risk brake, not a governance
        // proposal lifecycle freeze. Valid state-machine transitions must still work.
        let mut st = StateStore::new();
        st.set_gov_param(9_210, 7_999, "emergency_pause".into(), "true".into())
            .unwrap();
        assert!(st.is_emergency_paused());

        let proposal = GovProposalObject {
            proposal_id: 9_211,
            title: "paused valid path".into(),
            proposer: "alice".into(),
            status: GovProposalStatus::Draft,
            version: 1,
        };
        let mut expected = st.put_proposal_new(proposal).unwrap();

        expected = st
            .transition_proposal_status(expected, GovProposalStatus::Voting)
            .expect("Draft->Voting must remain valid while paused");
        expected = st
            .transition_proposal_status(expected, GovProposalStatus::Passed)
            .expect("Voting->Passed must remain valid while paused");
        let _ = st
            .transition_proposal_status(expected, GovProposalStatus::Executed)
            .expect("Passed->Executed must remain valid while paused");

        let cur = st.get_proposal(9_211).unwrap();
        assert_eq!(cur.status, GovProposalStatus::Executed);
    }

    #[test]
    fn governance_terminal_states_are_non_transitional() {
        let mut st = StateStore::new();

        let executed = GovProposalObject {
            proposal_id: 9003,
            title: "already executed".into(),
            proposer: "alice".into(),
            status: GovProposalStatus::Executed,
            version: 1,
        };
        let executed_ref = st.put_proposal_new(executed).unwrap();
        let err_executed = st
            .transition_proposal_status(executed_ref, GovProposalStatus::Voting)
            .unwrap_err();
        assert!(err_executed.contains("invalid governance transition"));

        let rejected = GovProposalObject {
            proposal_id: 9004,
            title: "already rejected".into(),
            proposer: "alice".into(),
            status: GovProposalStatus::Rejected,
            version: 1,
        };
        let rejected_ref = st.put_proposal_new(rejected).unwrap();
        let err_rejected = st
            .transition_proposal_status(rejected_ref, GovProposalStatus::Voting)
            .unwrap_err();
        assert!(err_rejected.contains("invalid governance transition"));
    }

    #[test]
    fn governance_transition_matrix_remains_strict_and_exhaustive() {
        fn expected_transition_allowed(from: GovProposalStatus, to: GovProposalStatus) -> bool {
            // Exhaustive merge-gate guard: adding/changing statuses requires updating this matrix.
            match (from, to) {
                (GovProposalStatus::Draft, GovProposalStatus::Voting)
                | (GovProposalStatus::Voting, GovProposalStatus::Passed)
                | (GovProposalStatus::Voting, GovProposalStatus::Rejected)
                | (GovProposalStatus::Passed, GovProposalStatus::Executed) => true,
                (GovProposalStatus::Draft, _)
                | (GovProposalStatus::Voting, _)
                | (GovProposalStatus::Passed, _)
                | (GovProposalStatus::Rejected, _)
                | (GovProposalStatus::Executed, _) => false,
            }
        }

        let statuses = [
            GovProposalStatus::Draft,
            GovProposalStatus::Voting,
            GovProposalStatus::Passed,
            GovProposalStatus::Rejected,
            GovProposalStatus::Executed,
        ];

        for &from in &statuses {
            for &to in &statuses {
                let mut st = StateStore::new();
                let proposal_id = 95_000 + (from as u64) * 10 + (to as u64);
                let proposal = GovProposalObject {
                    proposal_id,
                    title: "matrix".into(),
                    proposer: "merge-gate".into(),
                    status: from,
                    version: 1,
                };
                let expected = st.put_proposal_new(proposal).unwrap();
                let outcome = st.transition_proposal_status(expected, to);

                if expected_transition_allowed(from, to) {
                    assert!(
                        outcome.is_ok(),
                        "expected transition to succeed for {:?}->{:?}",
                        from,
                        to
                    );
                } else {
                    let err = outcome.unwrap_err();
                    assert!(
                        err.contains("invalid governance transition"),
                        "expected invalid transition for {:?}->{:?}, got: {}",
                        from,
                        to,
                        err
                    );
                }
            }
        }
    }

    #[test]
    fn governance_param_whitelist_enforced() {
        let mut st = StateStore::new();
        let ok = st
            .set_gov_param_unchecked(7001, "max_block_ms".into(), "10".into())
            .unwrap();
        assert_eq!(ok.version, 1);

        let cur = st.get_param(7001).unwrap();
        assert_eq!(cur.key, "max_block_ms");
        assert_eq!(cur.value, "10");

        let bounty_ok = st
            .set_gov_param_unchecked(7003, "challenge_success_bounty".into(), "5".into())
            .unwrap();
        assert_eq!(bounty_ok.version, 1);

        let err = st
            .set_gov_param_unchecked(7002, "forbidden_key".into(), "1".into())
            .unwrap_err();
        assert!(
            err.contains("no explicit validator registered for governance key: forbidden_key"),
            "{err}"
        );
    }

    #[test]
    fn governance_unknown_key_registration_boundary_fails_closed_with_explicit_registry_error() {
        let err = validate_governance_key_registration_lists(
            &BTreeMap::new(),
            "forbidden_key",
            7002,
            GOV_ALLOWED_KEYS,
            GOV_SENSITIVE_KEYS,
            GOV_EXPLICIT_VALIDATOR_KEYS,
            GOV_EXPLICIT_VALUE_RULE_KEYS,
            GOV_PINNED_KEY_IDS,
        )
        .expect_err("unknown governance keys must fail closed at the registration boundary");

        assert!(
            err.contains("no explicit validator registered for governance key: forbidden_key"),
            "unexpected registration-boundary error: {err}"
        );
    }

    #[test]
    fn governance_key_requests_reject_noncanonical_spellings_fail_closed() {
        let mut st = StateStore::new();

        for noncanonical_key in [" max_block_ms", "max_block_ms ", "MAX_BLOCK_MS"] {
            let err = st
                .set_gov_param_unchecked(7001, noncanonical_key.into(), "10".into())
                .expect_err("non-canonical governance key spelling must fail closed");
            assert!(
                err.contains("governance key request must use canonical key spelling"),
                "{err}"
            );
        }
    }

    #[test]
    fn governance_validator_registry_rejects_duplicate_entries_fail_closed() {
        let err = validate_governance_registry_shape_lists(
            &["max_block_ms", "max_parallel_workers"],
            &[],
            &["max_block_ms", "max_parallel_workers", "max_block_ms"],
            &["max_block_ms", "max_parallel_workers"],
            &[],
        )
        .expect_err("duplicate explicit-validator registry entries must fail closed");

        assert!(
            err.contains("explicit-validator registry contains duplicate entries"),
            "{err}"
        );
    }

    #[test]
    fn governance_key_registration_requires_explicit_validator_coverage_fail_closed() {
        let err = validate_governance_key_registration_lists(
            &BTreeMap::new(),
            "max_parallel_workers",
            7_002,
            &["max_block_ms", "max_parallel_workers"],
            &[],
            &["max_block_ms"],
            &["max_block_ms", "max_parallel_workers"],
            &[],
        )
        .expect_err("registration must fail closed when explicit validator coverage drifts");

        assert!(
            err.contains("explicit-validator registry drifted from allowed-key registry"),
            "{err}"
        );
        assert!(err.contains("max_parallel_workers"), "{err}");
    }

    #[test]
    fn governance_validator_and_registration_explicitness_guards_stay_aligned() {
        let registration_err = validate_governance_key_registration_lists(
            &BTreeMap::new(),
            "max_parallel_workers",
            7_002,
            &["max_block_ms", "max_parallel_workers"],
            &[],
            &["max_block_ms", "max_parallel_workers"],
            &["max_block_ms"],
            &[],
        )
        .expect_err(
            "registration boundary must fail closed when explicit value-rule coverage drifts",
        );

        let validator_err = validate_governance_validator_coverage_from_lists(
            &["max_block_ms", "max_parallel_workers"],
            &[],
            &["max_block_ms", "max_parallel_workers"],
            &["max_block_ms"],
            &[],
            "max_parallel_workers",
        )
        .expect_err("validator boundary must fail closed when explicit value-rule coverage drifts");

        for err in [&registration_err, &validator_err] {
            assert!(
                err.contains("explicit-value-rule registry drifted from allowed-key registry"),
                "{err}"
            );
            assert!(err.contains("max_parallel_workers"), "{err}");
        }
    }

    #[test]
    fn governance_key_registration_rejects_duplicate_explicit_validator_entries_fail_closed() {
        let err = validate_governance_key_registration_lists(
            &BTreeMap::new(),
            "max_parallel_workers",
            7_002,
            &["max_block_ms", "max_parallel_workers"],
            &[],
            &[
                "max_block_ms",
                "max_parallel_workers",
                "max_parallel_workers",
            ],
            &["max_block_ms", "max_parallel_workers"],
            &[],
        )
        .expect_err("registration helper must fail closed on duplicate explicit-validator entries");

        assert!(
            err.contains("explicit-validator registry contains duplicate entries"),
            "{err}"
        );
    }

    #[test]
    fn governance_schema_invalid_sample_registry_rejects_noncanonical_keys_fail_closed() {
        let err = validate_governance_schema_sample_registry_shape_from_lists(
            &["max_block_ms", "max_parallel_workers"],
            &["max_block_ms", "max_parallel_workers"],
            &["max_block_ms", "max_parallel_workers"],
            &[(" max_block_ms", "9"), ("max_parallel_workers", "0")],
        )
        .expect_err("schema invalid-sample registry must fail closed on non-canonical keys");

        assert!(
            err.contains("schema invalid-sample registry contains non-canonical key with surrounding whitespace"),
            "{err}"
        );
    }

    #[test]
    fn governance_key_registration_rejects_duplicate_allowed_keys_fail_closed() {
        let err = validate_governance_key_registration_lists(
            &BTreeMap::new(),
            "max_parallel_workers",
            7_002,
            &[
                "max_block_ms",
                "max_parallel_workers",
                "max_parallel_workers",
            ],
            &[],
            &["max_block_ms", "max_parallel_workers"],
            &["max_block_ms", "max_parallel_workers"],
            &[],
        )
        .expect_err("registration helper must fail closed on duplicate allowed-key entries");

        assert!(
            err.contains("allowed-key registry contains duplicate entries"),
            "{err}"
        );
    }

    #[test]
    fn governance_key_registration_rejects_validator_order_drift_fail_closed() {
        let err = validate_governance_key_registration_lists(
            &BTreeMap::new(),
            "max_block_ms",
            7_001,
            &["max_block_ms", "max_parallel_workers"],
            &[],
            &["max_parallel_workers", "max_block_ms"],
            &["max_block_ms", "max_parallel_workers"],
            &[],
        )
        .expect_err("registration helper must fail closed on validator order drift");

        assert!(
            err.contains("explicit-validator registry order drifted at index 0"),
            "{err}"
        );
    }

    #[test]
    fn governance_key_registration_rejects_sensitive_registry_membership_drift_fail_closed() {
        let err = validate_governance_key_registration_lists(
            &BTreeMap::new(),
            "max_block_ms",
            7_001,
            &["max_block_ms", "max_parallel_workers"],
            &["max_block_ms", "ghost_sensitive_key"],
            &["max_block_ms", "max_parallel_workers"],
            &["max_block_ms", "max_parallel_workers"],
            &[],
        )
        .expect_err("registration helper must fail closed on sensitive-key registry drift");

        assert!(
            err.contains("governance sensitive-key coverage missing from allowed key registry: ghost_sensitive_key"),
            "{err}"
        );
    }

    #[test]
    fn governance_key_registration_rejects_pinned_key_id_mismatch_fail_closed() {
        let err = validate_governance_key_registration_lists(
            &BTreeMap::new(),
            "emergency_pause",
            8_000,
            &["emergency_pause"],
            &[],
            &["emergency_pause"],
            &["emergency_pause"],
            &[("emergency_pause", EMERGENCY_PAUSE_KEY_ID)],
        )
        .expect_err("registration helper must fail closed on pinned key-id drift");

        assert!(
            err.contains("governance key id mismatch for emergency_pause: expected_id=7999, attempted_id=8000"),
            "{err}"
        );
    }

    #[test]
    fn governance_key_registration_rejects_cross_key_key_id_collision_fail_closed() {
        let mut gov_param_key_index = BTreeMap::new();
        gov_param_key_index.insert("max_block_ms".to_string(), 7_001);

        let err = validate_governance_key_registration_lists(
            &gov_param_key_index,
            "max_parallel_workers",
            7_001,
            &["max_block_ms", "max_parallel_workers"],
            &[],
            &["max_block_ms", "max_parallel_workers"],
            &["max_block_ms", "max_parallel_workers"],
            &[],
        )
        .expect_err("registration helper must fail closed when a different governance key already owns the id");

        assert!(
            err.contains("governance key id collision for max_parallel_workers: id 7001 already assigned to max_block_ms"),
            "{err}"
        );
    }

    #[test]
    fn governance_explicit_value_rule_registry_merge_gate_is_explicit() {
        let explicit_value_rule_unique: std::collections::BTreeSet<&str> =
            GOV_EXPLICIT_VALUE_RULE_KEYS.iter().copied().collect();
        assert_eq!(
            explicit_value_rule_unique.len(),
            GOV_EXPLICIT_VALUE_RULE_KEYS.len(),
            "explicit value-rule registry must remain duplicate-free"
        );
        assert_eq!(
            GOV_EXPLICIT_VALUE_RULE_KEYS.len(),
            GOV_ALLOWED_KEYS.len(),
            "explicit value-rule registry drifted from allowed governance-key registry"
        );
        assert_eq!(
            GOV_EXPLICIT_VALUE_RULE_KEYS, GOV_EXPLICIT_VALIDATOR_KEYS,
            "explicit value-rule registry drifted from explicit validator-key registry"
        );

        for key in GOV_ALLOWED_KEYS {
            assert!(
                explicit_value_rule_unique.contains(key),
                "allowed governance key missing from explicit value-rule registry: {}",
                key
            );
            assert!(
                has_explicit_gov_param_value_rule(key),
                "allowed governance key missing explicit value rule: {}",
                key
            );
            assert!(
                has_explicit_gov_param_value_match_coverage(key),
                "allowed governance key missing explicit value match coverage: {}",
                key
            );
            assert_eq!(
                has_explicit_gov_param_value_match_coverage(key),
                has_explicit_gov_param_value_rule(key),
                "explicit value-match coverage must derive from the explicit value-rule registry for {}",
                key
            );
        }
        assert!(!has_explicit_gov_param_value_rule("forbidden_key"));
        assert!(!has_explicit_gov_param_value_match_coverage(
            "forbidden_key"
        ));
    }

    #[test]
    fn governance_value_match_coverage_requires_validator_and_value_rule_fail_closed() {
        assert!(has_explicit_gov_param_value_match_coverage_from_lists(
            &["max_block_ms"],
            &["max_block_ms"],
            "max_block_ms"
        ));
        assert!(
            !has_explicit_gov_param_value_match_coverage_from_lists(
                &[],
                &["max_block_ms"],
                "max_block_ms"
            ),
            "value-match coverage must fail closed without explicit validator coverage"
        );
        assert!(
            !has_explicit_gov_param_value_match_coverage_from_lists(
                &["max_block_ms"],
                &[],
                "max_block_ms"
            ),
            "value-match coverage must fail closed without explicit value-rule coverage"
        );
    }

    #[test]
    fn governance_explicit_validator_helper_requires_value_rule_coverage_fail_closed() {
        assert!(has_explicit_gov_param_validator_from_lists(
            &["max_block_ms"],
            &["max_block_ms"],
            "max_block_ms"
        ));
        assert!(
            !has_explicit_gov_param_validator_from_lists(&["max_block_ms"], &[], "max_block_ms"),
            "explicit validator helper must fail closed without explicit value-rule coverage"
        );
        assert!(
            !has_explicit_gov_param_validator_from_lists(&[], &["max_block_ms"], "max_block_ms"),
            "explicit validator helper must fail closed without explicit validator coverage"
        );
    }

    #[test]
    fn governance_unknown_key_validator_boundary_fails_closed_with_explicit_registry_error() {
        let err = validate_gov_param_value("forbidden_key", "1")
            .expect_err("unknown governance keys must fail closed at the validator boundary");
        assert!(
            err.contains("no explicit validator registered for governance key: forbidden_key"),
            "unexpected validator-boundary error: {err}"
        );
    }

    #[test]
    fn governance_explicit_value_rule_registry_rejects_membership_drift_fail_closed() {
        let err = validate_governance_registry_shape_lists(
            &["max_block_ms", "max_parallel_workers"],
            &[],
            &["max_block_ms", "max_parallel_workers"],
            &["max_block_ms", "ghost_value_rule_key"],
            &[],
        )
        .expect_err("explicit value-rule registry membership drift must fail closed");

        assert!(
            err.contains("explicit-value-rule registry drifted from allowed-key registry"),
            "{err}"
        );
        assert!(err.contains("max_parallel_workers"), "{err}");
        assert!(err.contains("ghost_value_rule_key"), "{err}");
    }

    #[test]
    fn governance_explicit_value_rule_registry_rejects_order_drift_fail_closed() {
        let err = validate_governance_registry_shape_lists(
            &["max_block_ms", "max_parallel_workers", "min_worker_stake"],
            &[],
            &["max_block_ms", "max_parallel_workers", "min_worker_stake"],
            &["max_parallel_workers", "max_block_ms", "min_worker_stake"],
            &[],
        )
        .expect_err("explicit value-rule registry ordering drift must fail closed");

        assert!(
            err.contains("explicit-value-rule registry order drifted at index 0"),
            "{err}"
        );
        assert!(err.contains("allowed_key=max_block_ms"), "{err}");
        assert!(
            err.contains("explicit_value_rule_key=max_parallel_workers"),
            "{err}"
        );
    }

    #[test]
    fn governance_validator_registry_rejects_noncanonical_uppercase_key_fail_closed() {
        let err = validate_governance_registry_shape_lists(
            &["max_block_ms", "MAX_PARALLEL_WORKERS"],
            &[],
            &["max_block_ms", "MAX_PARALLEL_WORKERS"],
            &["max_block_ms", "MAX_PARALLEL_WORKERS"],
            &[],
        )
        .expect_err("uppercase governance registry keys must fail closed");

        assert!(
            err.contains("explicit-validator registry contains non-canonical uppercase key")
                || err.contains("allowed-key registry contains non-canonical uppercase key"),
            "{err}"
        );
    }

    #[test]
    fn governance_validator_registry_rejects_internal_whitespace_key_fail_closed() {
        let err = validate_governance_registry_shape_lists(
            &["max_block_ms", "max parallel workers"],
            &[],
            &["max_block_ms", "max parallel workers"],
            &["max_block_ms", "max parallel workers"],
            &[],
        )
        .expect_err("registry keys with internal whitespace must fail closed");

        assert!(
            err.contains("explicit-validator registry contains non-canonical whitespace or control character in key")
                || err.contains("allowed-key registry contains non-canonical whitespace or control character in key"),
            "{err}"
        );
    }

    #[test]
    fn governance_validator_registry_rejects_whitespace_pinned_key_fail_closed() {
        let err = validate_governance_registry_shape_lists(
            &["max_block_ms", "emergency_pause"],
            &[],
            &["max_block_ms", "emergency_pause"],
            &["max_block_ms", "emergency_pause"],
            &[(" emergency_pause", EMERGENCY_PAUSE_KEY_ID)],
        )
        .expect_err("whitespace-padded pinned governance keys must fail closed");

        assert!(
            err.contains(
                "pinned-key registry contains non-canonical key with surrounding whitespace"
            ),
            "{err}"
        );
    }

    #[test]
    fn governance_validator_registry_rejects_membership_drift_fail_closed() {
        let err = validate_governance_registry_shape_lists(
            &["max_block_ms", "max_parallel_workers"],
            &[],
            &["max_block_ms", "ghost_validator_key"],
            &["max_block_ms", "max_parallel_workers"],
            &[],
        )
        .expect_err("explicit-validator registry membership drift must fail closed");

        assert!(
            err.contains("explicit-validator registry drifted from allowed-key registry"),
            "{err}"
        );
        assert!(err.contains("max_parallel_workers"), "{err}");
        assert!(err.contains("ghost_validator_key"), "{err}");
    }

    #[test]
    fn governance_validator_registry_rejects_order_drift_fail_closed() {
        let err = validate_governance_registry_shape_lists(
            &["max_block_ms", "max_parallel_workers", "min_worker_stake"],
            &[],
            &["max_parallel_workers", "max_block_ms", "min_worker_stake"],
            &["max_block_ms", "max_parallel_workers", "min_worker_stake"],
            &[],
        )
        .expect_err("explicit-validator registry ordering drift must fail closed");

        assert!(
            err.contains("explicit-validator registry order drifted at index 0"),
            "{err}"
        );
        assert!(err.contains("allowed_key=max_block_ms"), "{err}");
        assert!(err.contains("validator_key=max_parallel_workers"), "{err}");
    }

    #[test]
    fn governance_pinned_key_registry_rejects_non_whitelisted_key_fail_closed() {
        let err = validate_governance_registry_shape_lists(
            &["max_block_ms", "emergency_pause"],
            &[],
            &["max_block_ms", "emergency_pause"],
            &["max_block_ms", "emergency_pause"],
            &[("ghost_pinned_key", EMERGENCY_PAUSE_KEY_ID)],
        )
        .expect_err("pinned governance keys must stay inside the allowed registry");

        assert!(
            err.contains("pinned-key registry contains non-whitelisted key: ghost_pinned_key"),
            "{err}"
        );
    }

    #[test]
    fn governance_pinned_key_registry_rejects_missing_explicit_validator_coverage_fail_closed() {
        let err = validate_pinned_governance_key_explicit_coverage(
            "emergency_pause",
            &std::collections::BTreeSet::from(["max_block_ms"]),
            &std::collections::BTreeSet::from(["max_block_ms", "emergency_pause"]),
        )
        .expect_err("pinned governance keys must keep explicit validator coverage");

        assert!(
            err.contains(
                "pinned-key registry missing explicit-validator coverage for emergency_pause"
            ),
            "{err}"
        );
    }

    #[test]
    fn governance_pinned_key_registry_rejects_missing_explicit_value_rule_coverage_fail_closed() {
        let err = validate_pinned_governance_key_explicit_coverage(
            "emergency_pause",
            &std::collections::BTreeSet::from(["max_block_ms", "emergency_pause"]),
            &std::collections::BTreeSet::from(["max_block_ms"]),
        )
        .expect_err("pinned governance keys must keep explicit value-rule coverage");

        assert!(
            err.contains(
                "pinned-key registry missing explicit-value-rule coverage for emergency_pause"
            ),
            "{err}"
        );
    }

    #[test]
    fn governance_pinned_key_registry_rejects_cross_key_id_reuse_fail_closed() {
        let err = validate_governance_registry_shape_lists(
            &["max_block_ms", "emergency_pause", "resolve_authority"],
            &[],
            &["max_block_ms", "emergency_pause", "resolve_authority"],
            &["max_block_ms", "emergency_pause", "resolve_authority"],
            &[
                ("emergency_pause", EMERGENCY_PAUSE_KEY_ID),
                ("resolve_authority", EMERGENCY_PAUSE_KEY_ID),
            ],
        )
        .expect_err(
            "pinned governance keys must not reuse the same pinned id across different keys",
        );

        assert!(
            err.contains("pinned-key registry reuses pinned id")
                && err.contains("emergency_pause")
                && err.contains("resolve_authority"),
            "{err}"
        );
    }

    #[test]
    fn governance_key_registration_rejects_cross_key_pinned_id_reuse_fail_closed() {
        let err = validate_governance_key_registration_lists(
            &BTreeMap::new(),
            "emergency_pause",
            EMERGENCY_PAUSE_KEY_ID,
            &["max_block_ms", "emergency_pause", "resolve_authority"],
            &[],
            &["max_block_ms", "emergency_pause", "resolve_authority"],
            &["max_block_ms", "emergency_pause", "resolve_authority"],
            &[
                ("emergency_pause", EMERGENCY_PAUSE_KEY_ID),
                ("resolve_authority", EMERGENCY_PAUSE_KEY_ID),
            ],
        )
        .expect_err("registration helper must fail closed when pinned ids are reused across keys");

        assert!(
            err.contains("pinned-key registry reuses pinned id")
                && err.contains("emergency_pause")
                && err.contains("resolve_authority"),
            "{err}"
        );
    }

    #[test]
    fn restore_pending_gov_update_rejects_cross_key_pending_key_id_collision_fail_closed() {
        let mut st = StateStore::new();

        let shared_key_id = 7_310;

        st.restore_pending_gov_update(
            "resolve_authority",
            Some(PendingGovParamUpdate {
                key_id: shared_key_id,
                key: "resolve_authority".into(),
                value: "authority-a,authority-b".into(),
                activate_at_height: 1_200,
            }),
        );
        assert_eq!(
            st.pending_gov_update("resolve_authority")
                .expect("resolve_authority snapshot should restore")
                .key_id,
            shared_key_id
        );

        st.restore_pending_gov_update(
            "monetary_base_issuance_per_tick",
            Some(PendingGovParamUpdate {
                key_id: shared_key_id,
                key: "monetary_base_issuance_per_tick".into(),
                value: "42".into(),
                activate_at_height: 1_250,
            }),
        );

        assert_eq!(
            st.pending_gov_update("resolve_authority")
                .expect("original pending update must remain intact")
                .key_id,
            shared_key_id
        );
        assert_eq!(
            st.pending_gov_update("monetary_base_issuance_per_tick"),
            None,
            "restore path must reject cross-key pending key-id reuse fail-closed"
        );
    }

    #[test]
    fn restore_pending_gov_update_rejects_live_gov_param_object_key_alias_on_shared_key_id() {
        let mut st = StateStore::new();

        st.objects.insert(
            7_201,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: 7_201,
                    key: "max_block_ms".into(),
                    value: "1000".into(),
                    version: 1,
                }),
            },
        );

        st.restore_pending_gov_update(
            "challenge_min_bond",
            Some(PendingGovParamUpdate {
                key_id: 7_201,
                key: "challenge_min_bond".into(),
                value: "6000".into(),
                activate_at_height: 1_020,
            }),
        );

        assert_eq!(
            st.pending_gov_update("challenge_min_bond"),
            None,
            "restore must fail closed when a live GovParam object already binds the key_id to another governance key"
        );
    }

    #[test]
    fn restore_pending_gov_update_rejects_zero_activate_height_fail_closed() {
        let mut st = StateStore::new();

        st.restore_pending_gov_update(
            "resolve_authority",
            Some(PendingGovParamUpdate {
                key_id: 7_310,
                key: "resolve_authority".into(),
                value: "authority-a,authority-b".into(),
                activate_at_height: 0,
            }),
        );

        assert_eq!(
            st.pending_gov_update("resolve_authority"),
            None,
            "restore must fail closed when a pending governance snapshot omits a positive timelock boundary"
        );
    }

    #[test]
    fn governance_param_schema_rejects_invalid_u64_values() {
        let mut st = StateStore::new();

        let err = st
            .set_gov_param_unchecked(7101, "max_block_ms".into(), "abc".into())
            .unwrap_err();
        assert!(err.contains("expected u64"));

        let err = st
            .set_gov_param_unchecked(7101, "max_parallel_workers".into(), "0".into())
            .unwrap_err();
        assert!(err.contains("out of range"));

        let ok = st
            .set_gov_param_unchecked(7101, "max_parallel_workers".into(), "32".into())
            .unwrap();
        assert_eq!(ok.version, 1);

        let err = st
            .set_gov_param_unchecked(7102, "challenge_window_blocks".into(), "99".into())
            .unwrap_err();
        assert!(err.contains("out of range"));

        let err = st
            .set_gov_param_unchecked(7103, "min_worker_stake".into(), "0".into())
            .unwrap_err();
        assert!(err.contains("out of range"));

        let err = st
            .set_gov_param_unchecked(7104, "challenge_min_bond".into(), "0".into())
            .unwrap_err();
        assert!(err.contains("out of range"));

        let err = st
            .set_gov_param_unchecked(7105, "challenge_success_bounty".into(), "-1".into())
            .unwrap_err();
        assert!(err.contains("expected u64"));

        let err = st
            .set_gov_param_unchecked(
                7105,
                "challenge_min_bond_bounty_bps".into(),
                "100001".into(),
            )
            .unwrap_err();
        assert!(err.contains("out of range"));

        let ok = st
            .set_gov_param_unchecked(
                7106,
                "challenge_min_bond_worker_stake_bps".into(),
                "0".into(),
            )
            .unwrap();
        assert_eq!(ok.version, 1);
    }

    #[test]
    fn governance_key_id_collision_with_non_param_rejected() {
        let mut st = StateStore::new();
        let t = TaskObject {
            task_id: 7400,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Open,
            proof_type: Default::default(),
            metadata: None,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        };
        st.put_task_new(t).unwrap();

        let err = st
            .set_gov_param_unchecked(7400, "max_block_ms".into(), "15".into())
            .unwrap_err();
        assert!(err.contains("not GovParam"));

        let p = GovProposalObject {
            proposal_id: 7405,
            title: "change block time".into(),
            proposer: "alice".into(),
            status: GovProposalStatus::Draft,
            version: 1,
        };
        st.put_proposal_new(p).unwrap();

        let err = st
            .set_gov_param_unchecked(7405, "max_block_ms".into(), "20".into())
            .unwrap_err();
        assert!(err.contains("not GovParam"));
    }

    #[test]
    fn governance_non_sensitive_failed_apply_does_not_scrub_pending_queue() {
        // Merge-gate guard: failed writes must be side-effect free for unrelated
        // pending governance state (except explicit Cancel unsupported path).
        let mut st = StateStore::new();

        st.pending_gov_updates.insert(
            "max_block_ms".into(),
            PendingGovParamUpdate {
                key_id: 7_400,
                key: "max_block_ms".into(),
                value: "15".into(),
                activate_at_height: 77_700,
            },
        );

        let task = TaskObject {
            task_id: 7_400,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Open,
            proof_type: Default::default(),
            metadata: None,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        };
        st.put_task_new(task).unwrap();

        let err_unchecked = st
            .set_gov_param_unchecked(7_400, "max_block_ms".into(), "15".into())
            .unwrap_err();
        assert!(err_unchecked.contains("not GovParam"));
        assert!(
            st.pending_gov_update("max_block_ms").is_some(),
            "failed unchecked apply must not scrub pending queue"
        );

        let err_checked = st
            .set_gov_param(77_701, 7_400, "max_block_ms".into(), "15".into())
            .unwrap_err();
        assert!(err_checked.contains("not GovParam"));

        let pending = st
            .pending_gov_update("max_block_ms")
            .expect("failed checked apply must not scrub pending queue");
        assert_eq!(pending.key_id, 7_400);
        assert_eq!(pending.activate_at_height, 77_700);
    }

    #[test]
    fn restore_pending_gov_update_requires_matching_base_gov_param_snapshot() {
        let snapshot = Some(PendingGovParamUpdate {
            key_id: 7401,
            key: "challenge_min_bond".into(),
            value: "120".into(),
            activate_at_height: 42,
        });

        let mut missing_base = StateStore::new();
        missing_base.restore_pending_gov_update("challenge_min_bond", snapshot.clone());
        assert!(
            missing_base
                .pending_gov_update("challenge_min_bond")
                .is_none(),
            "restore must fail closed when the referenced governance base snapshot is absent"
        );

        let mut matching_base = StateStore::new();
        matching_base
            .set_gov_param_unchecked(7401, "challenge_min_bond".into(), "100".into())
            .expect("setup must insert matching governance param before restore");
        matching_base.restore_pending_gov_update("challenge_min_bond", snapshot);
        let restored = matching_base
            .pending_gov_update("challenge_min_bond")
            .expect(
            "restore should accept a pending governance snapshot backed by a matching base object",
        );
        assert_eq!(restored.key_id, 7401);
        assert_eq!(restored.activate_at_height, 42);
        assert_eq!(restored.value, "120");
    }

    #[test]
    fn governance_same_key_different_id_shadow_attempt_rejected() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(7401, "max_block_ms".into(), "15".into())
            .unwrap();

        let err = st
            .set_gov_param_unchecked(7402, "max_block_ms".into(), "20".into())
            .unwrap_err();
        assert!(err.contains("key id mismatch"));
    }

    #[test]
    fn governance_readers_use_deterministic_current_value() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(7403, "max_block_ms".into(), "15".into())
            .unwrap();
        st.set_gov_param_unchecked(7403, "max_block_ms".into(), "20".into())
            .unwrap();

        assert_eq!(st.gov_param_u64("max_block_ms"), Some(20));
        assert_eq!(st.gov_param_u128("max_block_ms"), Some(20));
        assert_eq!(st.gov_param_string("max_block_ms"), Some("20".into()));
    }

    #[test]
    fn governance_readers_fail_closed_when_registry_points_at_noncanonical_param() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(7403, "max_block_ms".into(), "20".into())
            .unwrap();

        let object = st
            .objects
            .get_mut(&7403)
            .expect("canonical max_block_ms object must exist");
        let ObjectValue::GovParam(param) = &mut object.value else {
            panic!("expected governance param object");
        };
        param.key_id = 7_999;

        assert_eq!(st.gov_param_u64("max_block_ms"), None);
        assert_eq!(st.gov_param_u128("max_block_ms"), None);
        assert_eq!(st.gov_param_string("max_block_ms"), None);
        assert_eq!(st.gov_param_ref_for_key("max_block_ms"), None);
    }

    #[test]
    fn governance_sensitive_update_rejected_before_timelock_expiry() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(7300, "challenge_min_bond".into(), "100".into())
            .unwrap();

        let scheduled = st
            .set_gov_param(1_000, 7300, "challenge_min_bond".into(), "120".into())
            .unwrap();
        let activate_at_height = match scheduled {
            GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
            GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
            GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
        };
        assert_eq!(activate_at_height, 1_020);

        let err = st
            .set_gov_param(1_019, 7300, "challenge_min_bond".into(), "120".into())
            .unwrap_err();
        assert!(err.contains("timelock active"));
    }

    #[test]
    fn governance_sensitive_update_accepted_after_timelock() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(7301, "challenge_min_bond".into(), "100".into())
            .unwrap();

        let _ = st
            .set_gov_param(2_000, 7301, "challenge_min_bond".into(), "120".into())
            .unwrap();

        let applied = st
            .set_gov_param(2_020, 7301, "challenge_min_bond".into(), "120".into())
            .unwrap();
        match applied {
            GovParamUpdateOutcome::Applied(r) => assert!(r.version >= 2),
            GovParamUpdateOutcome::Scheduled { .. } => panic!("expected applied"),
            GovParamUpdateOutcome::Cancelled => panic!("expected applied"),
        }

        assert_eq!(st.gov_param_u64("challenge_min_bond"), Some(120));
        assert!(st.pending_gov_update("challenge_min_bond").is_none());
    }

    #[test]
    fn governance_sensitive_noop_update_is_immediate_without_timelock() {
        let mut st = StateStore::new();
        let seeded = st
            .set_gov_param_unchecked(7306, "challenge_min_bond".into(), "100".into())
            .unwrap();

        let applied = st
            .set_gov_param(2_500, 7306, "challenge_min_bond".into(), "100".into())
            .unwrap();

        match applied {
            GovParamUpdateOutcome::Applied(r) => {
                assert_eq!(r.id, seeded.id);
                assert_eq!(r.version, seeded.version);
            }
            GovParamUpdateOutcome::Scheduled { .. } => panic!("expected immediate no-op apply"),
            GovParamUpdateOutcome::Cancelled => panic!("expected immediate no-op apply"),
        }

        assert!(st.pending_gov_update("challenge_min_bond").is_none());
        assert_eq!(st.gov_param_u64("challenge_min_bond"), Some(100));
    }

    #[test]
    fn governance_resolve_authority_rejected_before_timelock_expiry() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            7310,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .unwrap();

        let scheduled = st
            .set_gov_param(
                10_000,
                7310,
                "resolve_authority".into(),
                "resolver-v3,resolver-v4".into(),
            )
            .unwrap();
        let activate_at_height = match scheduled {
            GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
            GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
            GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
        };
        assert_eq!(activate_at_height, 10_020);

        let err = st
            .set_gov_param(
                10_019,
                7310,
                "resolve_authority".into(),
                "resolver-v3,resolver-v4".into(),
            )
            .unwrap_err();
        assert!(err.contains("timelock active"));
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("resolver-v1,resolver-v2".into())
        );
    }

    #[test]
    fn governance_resolve_authority_applied_after_timelock() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            7311,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .unwrap();

        let _ = st
            .set_gov_param(
                11_000,
                7311,
                "resolve_authority".into(),
                "resolver-v3,resolver-v4".into(),
            )
            .unwrap();

        let applied = st
            .set_gov_param(
                11_020,
                7311,
                "resolve_authority".into(),
                "resolver-v3,resolver-v4".into(),
            )
            .unwrap();
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("resolver-v3,resolver-v4".into())
        );
        assert!(st.pending_gov_update("resolve_authority").is_none());
    }

    #[test]
    fn governance_resolve_authority_rejects_non_canonical_value_without_mutation() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            7312,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .unwrap();

        let err = st
            .set_gov_param(
                12_000,
                7312,
                "resolve_authority".into(),
                " resolver-v2 ".into(),
            )
            .unwrap_err();
        assert!(err.contains("whitespace") || err.contains("canonical"));

        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("resolver-v1,resolver-v2".into())
        );
        assert!(st.pending_gov_update("resolve_authority").is_none());
    }

    #[test]
    fn governance_resolve_authority_rejects_forbidden_separator_without_mutation() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            7313,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .unwrap();

        let err = st
            .set_gov_param(
                12_000,
                7313,
                "resolve_authority".into(),
                "resolver-a，resolver-b".into(),
            )
            .unwrap_err();
        assert!(err.contains("separator") || err.contains("ASCII ','"));

        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("resolver-v1,resolver-v2".into())
        );
        assert!(st.pending_gov_update("resolve_authority").is_none());
    }

    #[test]
    fn governance_resolve_authority_rejects_non_ascii_without_mutation() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            7314,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .unwrap();

        let err = st
            .set_gov_param(
                12_000,
                7314,
                "resolve_authority".into(),
                "resolver-a,resolvér-b".into(),
            )
            .unwrap_err();
        assert!(
            err.contains("ASCII-only") || err.contains("whitespace") || err.contains("separator")
        );

        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("resolver-v1,resolver-v2".into())
        );
        assert!(st.pending_gov_update("resolve_authority").is_none());
    }

    #[test]
    fn governance_resolve_authority_rejects_single_member_update_without_mutation() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            7315,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .unwrap();

        let err = st
            .set_gov_param(
                12_500,
                7315,
                "resolve_authority".into(),
                "resolver-v3".into(),
            )
            .expect_err("singleton resolve_authority update must be rejected");
        assert!(err.contains("at least two members"), "{err}");

        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("resolver-v1,resolver-v2".into())
        );
        assert!(st.pending_gov_update("resolve_authority").is_none());
    }

    #[test]
    fn governance_resolve_authority_pending_mismatch_behaves_like_sensitive_keys() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            7312,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .unwrap();

        let scheduled = st
            .set_gov_param(
                12_000,
                7312,
                "resolve_authority".into(),
                "resolver-v3,resolver-v4".into(),
            )
            .unwrap();
        assert!(matches!(
            scheduled,
            GovParamUpdateOutcome::Scheduled {
                activate_at_height: 12_020
            }
        ));

        let err_value = st
            .set_gov_param(
                12_005,
                7312,
                "resolve_authority".into(),
                "resolver-v5,resolver-v6".into(),
            )
            .unwrap_err();
        assert!(err_value.contains("pending governance update exists"));

        let err_id = st
            .set_gov_param(
                12_005,
                9999,
                "resolve_authority".into(),
                "resolver-v3,resolver-v4".into(),
            )
            .unwrap_err();
        assert!(err_id.contains("governance key id mismatch for resolve_authority"));

        let pending = st.pending_gov_update("resolve_authority").unwrap();
        assert_eq!(pending.key_id, 7312);
        assert_eq!(pending.value, "resolver-v3,resolver-v4");
        assert_eq!(pending.activate_at_height, 12_020);
    }

    #[test]
    fn governance_resolve_authority_unchecked_path_rejects_key_id_shadowing() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            7313,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .expect("initial unchecked resolve_authority write should succeed");

        let err = st
            .set_gov_param_unchecked(
                9001,
                "resolve_authority".into(),
                "resolver-v3,resolver-v4".into(),
            )
            .expect_err("unchecked key-id shadowing for resolve_authority must be rejected");
        assert!(
            err.contains("governance key id mismatch for resolve_authority"),
            "{err}"
        );
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("resolver-v1,resolver-v2".into())
        );
    }

    #[test]
    fn governance_resolve_authority_checked_path_rejects_key_id_shadowing_without_state_mutation() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            7314,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .expect("initial resolve_authority write should succeed");

        let err = st
            .set_gov_param(
                14_000,
                9001,
                "resolve_authority".into(),
                "resolver-v3,resolver-v4".into(),
            )
            .expect_err("checked key-id shadowing for resolve_authority must be rejected");
        assert!(
            err.contains("governance key id mismatch for resolve_authority"),
            "{err}"
        );
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("resolver-v1,resolver-v2".into())
        );
        assert!(
            st.pending_gov_update("resolve_authority").is_none(),
            "rejected key-id shadowing must not enqueue pending updates"
        );
    }

    #[test]
    fn governance_accessors_fail_closed_on_key_id_registry_mismatch() {
        let mut st = StateStore::new();
        st.restore_gov_param(
            7315,
            Some(GovParamObject {
                key_id: 9001,
                key: "resolve_authority".into(),
                value: "resolver-v1,resolver-v2".into(),
                version: 1,
            }),
        );

        assert_eq!(
            st.gov_param_string("resolve_authority"),
            None,
            "string accessor must fail closed when registry id and object key_id diverge"
        );
        assert_eq!(
            st.gov_param_u64("resolve_authority"),
            None,
            "typed accessor must fail closed when registry id and object key_id diverge"
        );
        assert!(
            st.gov_param_ref_for_key("resolve_authority").is_none(),
            "object ref accessor must fail closed when registry id and object key_id diverge"
        );
        assert!(
            st.get_param(7315).is_none(),
            "id accessor must fail closed when registry id and object key_id diverge"
        );
    }

    #[test]
    fn governance_emergency_pause_accessor_fail_closed_on_reserved_id_alias() {
        let mut st = StateStore::new();
        st.restore_gov_param(
            EMERGENCY_PAUSE_KEY_ID,
            Some(GovParamObject {
                key_id: EMERGENCY_PAUSE_KEY_ID,
                key: NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID.into(),
                value: "true".into(),
                version: 1,
            }),
        );

        assert!(
            !st.is_emergency_paused(),
            "reserved id aliasing must fail closed instead of toggling emergency pause"
        );
        assert_eq!(
            st.gov_param_string("emergency_pause"),
            None,
            "reserved-key string accessor must reject aliased objects even when they occupy the pinned id slot"
        );
        assert!(
            st.get_param(EMERGENCY_PAUSE_KEY_ID).is_none(),
            "id accessor must reject aliased objects at the reserved emergency_pause slot"
        );
    }

    #[test]
    fn governance_restore_pending_update_rejects_non_canonical_emergency_pause_key_id() {
        let mut st = StateStore::new();
        st.restore_pending_gov_update(
            "emergency_pause",
            Some(PendingGovParamUpdate {
                key_id: 8_000,
                key: "emergency_pause".into(),
                value: "true".into(),
                activate_at_height: 77_777,
            }),
        );

        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "pending restore must fail closed for non-canonical emergency_pause key_id"
        );
        assert!(
            !st.is_emergency_paused(),
            "rejected pending restore must not alter effective emergency pause state"
        );
    }

    #[test]
    fn governance_restore_pending_update_rejects_index_mismatched_key_id_fail_closed() {
        let mut st = StateStore::new();
        st.restore_gov_param(
            7_313,
            Some(GovParamObject {
                key_id: 7_313,
                key: "resolve_authority".into(),
                value: "authority-a,authority-b".into(),
                version: 1,
            }),
        );
        assert_eq!(
            st.gov_param_ref_for_key("resolve_authority")
                .map(|(id, _)| id),
            Some(7_313),
            "sanity: canonical registry binding should exist before exercising mismatched pending restore"
        );

        st.restore_pending_gov_update(
            "resolve_authority",
            Some(PendingGovParamUpdate {
                key_id: 9_001,
                key: "resolve_authority".into(),
                value: "authority-c,authority-d".into(),
                activate_at_height: 77_777,
            }),
        );

        assert!(
            st.pending_gov_update("resolve_authority").is_none(),
            "pending restore must fail closed when snapshot key_id diverges from the shared registry binding"
        );
        assert_eq!(
            st.gov_param_ref_for_key("resolve_authority")
                .map(|(id, _)| id),
            Some(7_313),
            "rejected pending restore must preserve the canonical configured governance registry binding"
        );
    }

    #[test]
    fn governance_restore_rejects_non_canonical_emergency_pause_key_id_fail_closed() {
        let mut st = StateStore::new();
        st.restore_gov_param(
            8_000,
            Some(GovParamObject {
                key_id: 8_000,
                key: "emergency_pause".into(),
                value: "true".into(),
                version: 1,
            }),
        );

        assert_eq!(
            st.gov_param_string("emergency_pause"),
            None,
            "restore must not expose non-canonical emergency_pause registry entries"
        );
        assert!(
            !st.is_emergency_paused(),
            "restore must fail closed instead of honoring a non-canonical emergency_pause slot"
        );
        assert!(
            st.gov_param_ref_for_key("emergency_pause").is_none(),
            "restore must not leave a resolvable ref for a non-canonical emergency_pause slot"
        );
    }

    const NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID: &str = "algorand_governance_key_id";

    #[test]
    fn governance_expected_pinned_binding_is_single_source_for_reserved_key_and_id() {
        assert_eq!(
            governance_expected_pinned_binding("emergency_pause", EMERGENCY_PAUSE_KEY_ID),
            (Some(EMERGENCY_PAUSE_KEY_ID), Some("emergency_pause")),
            "reserved governance key and reserved key id must resolve from the same single-source pinned registry"
        );
        assert_eq!(
            governance_expected_pinned_binding(
                NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID,
                EMERGENCY_PAUSE_KEY_ID
            ),
            (None, Some("emergency_pause")),
            "foreign governance keys must still resolve the reserved id side fail-closed"
        );
        assert_eq!(
            governance_expected_pinned_binding("emergency_pause", 9_200),
            (Some(EMERGENCY_PAUSE_KEY_ID), None),
            "reserved governance keys must still resolve the reserved key side fail-closed"
        );
    }

    #[test]
    fn governance_expected_key_helpers_share_single_source_for_reserved_emergency_pause() {
        assert_eq!(
            governance_pinned_binding_for_key("emergency_pause"),
            Some(("emergency_pause", EMERGENCY_PAUSE_KEY_ID)),
            "forward reserved-key lookup must reuse the shared single-source pinned registry"
        );
        assert_eq!(
            governance_pinned_binding_for_id(EMERGENCY_PAUSE_KEY_ID),
            Some(("emergency_pause", EMERGENCY_PAUSE_KEY_ID)),
            "reverse reserved-id lookup must reuse the shared single-source pinned registry"
        );
        assert_eq!(
            governance_expected_key_id("emergency_pause"),
            Some(EMERGENCY_PAUSE_KEY_ID),
            "accessor-facing key->id helper must stay aligned with the shared pinned registry"
        );
        assert_eq!(
            governance_expected_key_for_id(EMERGENCY_PAUSE_KEY_ID),
            Some("emergency_pause"),
            "accessor-facing id->key helper must stay aligned with the shared pinned registry"
        );
        assert_eq!(
            governance_expected_key_id(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID),
            None,
            "foreign governance keys must not acquire a reserved key id through helper drift"
        );
        assert_eq!(
            governance_expected_key_for_id(9_200),
            None,
            "unreserved key ids must remain unmapped through the shared helper path"
        );
    }

    #[test]
    fn governance_registry_binding_rejects_non_allowlisted_algorand_key_at_reserved_id_fail_closed()
    {
        let err = validate_gov_param_registry_binding(
            &BTreeMap::new(),
            NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID,
            EMERGENCY_PAUSE_KEY_ID,
        )
        .expect_err("foreign algorand governance key must fail closed at reserved id gate");

        assert_eq!(
            err,
            format!(
                "governance key not allowed: {}",
                NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID
            )
        );
    }

    #[test]
    fn governance_restore_rejects_non_allowlisted_key_fail_closed() {
        let mut st = StateStore::new();
        st.restore_gov_param(
            9_200,
            Some(GovParamObject {
                key_id: 9_200,
                key: NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID.into(),
                value: "key-42".into(),
                version: 1,
            }),
        );

        assert_eq!(
            st.gov_param_string(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID),
            None,
            "restore must not expose non-allowlisted governance keys"
        );
        assert!(
            st.gov_param_ref_for_key(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID)
                .is_none(),
            "restore must fail closed instead of leaving a resolvable ref for a non-allowlisted governance key"
        );
        assert!(
            st.gov_param_key_index
                .get(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID)
                .is_none(),
            "restore must not register non-allowlisted governance keys in the shared registry"
        );
    }

    #[test]
    fn governance_accessors_fail_closed_for_non_allowlisted_algorand_registry_injection() {
        let mut st = StateStore::new();
        st.objects.insert(
            9_200,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: 9_200,
                    key: NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID.into(),
                    value: "key-42".into(),
                    version: 1,
                }),
            },
        );
        st.gov_param_key_index
            .insert(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID.into(), 9_200);

        assert_eq!(
            st.gov_param_string(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID),
            None,
            "string accessor must fail closed for a non-allowlisted governance registry entry"
        );
        assert_eq!(
            st.gov_param_u64(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID),
            None,
            "typed accessor must fail closed for a non-allowlisted governance registry entry"
        );
        assert!(
            st.gov_param_ref_for_key(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID)
                .is_none(),
            "ref accessor must fail closed for a non-allowlisted governance registry entry"
        );
        assert_eq!(
            st.get_param(9_200)
                .map(|param| (param.key_id, param.key, param.value)),
            None,
            "id accessor must fail closed for a non-allowlisted governance registry entry"
        );
    }

    #[test]
    fn governance_accessors_resolve_canonical_reserved_emergency_pause_id_via_single_source_mapping(
    ) {
        let mut st = StateStore::new();
        st.objects.insert(
            EMERGENCY_PAUSE_KEY_ID,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: EMERGENCY_PAUSE_KEY_ID,
                    key: "emergency_pause".into(),
                    value: "true".into(),
                    version: 1,
                }),
            },
        );

        assert_eq!(
            st.gov_param_string("emergency_pause"),
            Some("true".into()),
            "string accessor must resolve the canonical reserved emergency_pause binding even if the mutable registry entry is absent"
        );
        assert_eq!(
            st.gov_param_ref_for_key("emergency_pause")
                .map(|(id, param)| (id, param.key.as_str(), param.value.as_str())),
            Some((EMERGENCY_PAUSE_KEY_ID, "emergency_pause", "true")),
            "ref accessor must resolve the canonical reserved emergency_pause binding"
        );
        assert_eq!(
            st.get_param(EMERGENCY_PAUSE_KEY_ID).map(|param| (
                param.key_id,
                param.key,
                param.value
            )),
            Some((
                EMERGENCY_PAUSE_KEY_ID,
                "emergency_pause".into(),
                "true".into()
            )),
            "id accessor must resolve the canonical reserved emergency_pause binding"
        );
        assert!(
            st.is_emergency_paused(),
            "canonical reserved-id binding must surface as an active emergency pause"
        );
    }

    #[test]
    fn governance_reserved_key_accessor_stays_aligned_with_id_accessor_single_source() {
        let mut st = StateStore::new();
        st.objects.insert(
            EMERGENCY_PAUSE_KEY_ID,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: EMERGENCY_PAUSE_KEY_ID,
                    key: "emergency_pause".into(),
                    value: "true".into(),
                    version: 1,
                }),
            },
        );

        let by_key = st
            .gov_param_ref_for_key("emergency_pause")
            .map(|(id, param)| (id, param.key.clone(), param.value.clone()));
        let by_id = st
            .get_param(EMERGENCY_PAUSE_KEY_ID)
            .map(|param| (param.key_id, param.key, param.value));

        assert_eq!(
            by_key, by_id,
            "reserved-key accessor must reuse the same canonical single-source binding surfaced by the id accessor"
        );
    }

    #[test]
    fn governance_accessors_fail_closed_for_reserved_emergency_pause_id_alias_injection() {
        let mut st = StateStore::new();
        st.objects.insert(
            EMERGENCY_PAUSE_KEY_ID,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: EMERGENCY_PAUSE_KEY_ID,
                    key: "algorand_governance_key_id".into(),
                    value: "key-42".into(),
                    version: 1,
                }),
            },
        );
        st.gov_param_key_index
            .insert("algorand_governance_key_id".into(), EMERGENCY_PAUSE_KEY_ID);

        assert_eq!(
            st.gov_param_string("algorand_governance_key_id"),
            None,
            "string accessor must fail closed when a foreign governance key aliases the reserved emergency_pause key id"
        );
        assert!(
            st.gov_param_ref_for_key("algorand_governance_key_id").is_none(),
            "ref accessor must fail closed when a foreign governance key aliases the reserved emergency_pause key id"
        );
        assert!(
            st.gov_param_ref_for_key("emergency_pause").is_none(),
            "canonical key lookup must also fail closed when a foreign algorand key occupies the reserved emergency_pause key id"
        );
        assert!(
            st.get_param(EMERGENCY_PAUSE_KEY_ID).is_none(),
            "id accessor must fail closed when the reserved emergency_pause key id is rebound to a foreign key"
        );
        assert!(
            !st.is_emergency_paused(),
            "reserved-id alias injection must not surface as an active emergency pause"
        );
    }

    #[test]
    fn governance_get_param_fails_closed_for_non_allowlisted_algorand_registry_injection() {
        let mut st = StateStore::new();
        st.objects.insert(
            9_200,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: 9_200,
                    key: NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID.into(),
                    value: "key-42".into(),
                    version: 1,
                }),
            },
        );
        st.gov_param_key_index
            .insert(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID.into(), 9_200);

        assert!(
            st.get_param(9_200).is_none(),
            "direct governance object accessor must fail closed for a non-allowlisted registry entry"
        );
    }

    #[test]
    fn governance_restore_pending_update_rejects_key_name_mismatch_fail_closed() {
        let mut st = StateStore::new();
        st.restore_pending_gov_update(
            "resolve_authority",
            Some(PendingGovParamUpdate {
                key_id: 7_999,
                key: "emergency_pause".into(),
                value: "true".into(),
                activate_at_height: 88_888,
            }),
        );

        assert!(
            st.pending_gov_update("resolve_authority").is_none(),
            "pending restore must fail closed when the snapshot key name diverges from the requested registry key"
        );
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "mismatched pending restore must not materialize a foreign pinned governance key under its own name"
        );
        assert!(
            !st.is_emergency_paused(),
            "rejected mismatched pending restore must not alter effective emergency pause state"
        );
    }

    #[test]
    fn governance_restore_pending_update_scrubs_stale_alias_binding_on_rejected_key_mismatch() {
        let mut st = StateStore::new();
        st.pending_gov_updates.insert(
            "emergency_pause".into(),
            PendingGovParamUpdate {
                key_id: 7_999,
                key: "emergency_pause".into(),
                value: "true".into(),
                activate_at_height: 88_887,
            },
        );

        st.restore_pending_gov_update(
            NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID,
            Some(PendingGovParamUpdate {
                key_id: 7_999,
                key: "emergency_pause".into(),
                value: "true".into(),
                activate_at_height: 88_888,
            }),
        );

        assert!(
            st.pending_gov_update(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID)
                .is_none(),
            "rejected restore must not materialize a foreign algorand governance key"
        );
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "rejected restore must scrub stale reserved-key pending aliases instead of preserving ambiguous pending state"
        );
        assert!(
            !st.is_emergency_paused(),
            "scrubbed stale pending alias must not affect effective emergency pause state"
        );
    }

    #[test]
    fn pending_governance_accessor_fails_closed_for_non_allowlisted_algorand_registry_injection() {
        let mut st = StateStore::new();
        st.pending_gov_updates.insert(
            NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID.into(),
            PendingGovParamUpdate {
                key_id: 9_200,
                key: NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID.into(),
                value: "key-42".into(),
                activate_at_height: 77_777,
            },
        );

        assert!(
            st.pending_gov_update(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID)
                .is_none(),
            "pending accessor must fail closed for a non-allowlisted governance registry entry"
        );
    }

    #[test]
    fn pending_governance_accessor_fails_closed_for_reserved_emergency_pause_key_id_alias() {
        let mut st = StateStore::new();
        st.pending_gov_updates.insert(
            "emergency_pause".into(),
            PendingGovParamUpdate {
                key_id: EMERGENCY_PAUSE_KEY_ID,
                key: "emergency_pause".into(),
                value: "true".into(),
                activate_at_height: 42,
            },
        );
        st.pending_gov_updates.insert(
            NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID.into(),
            PendingGovParamUpdate {
                key_id: EMERGENCY_PAUSE_KEY_ID,
                key: NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID.into(),
                value: "key-42".into(),
                activate_at_height: 42,
            },
        );

        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "pending accessor must fail closed when another pending governance key aliases the reserved emergency_pause key id"
        );
        assert!(
            st.pending_gov_update(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID)
                .is_none(),
            "foreign pending governance alias must also remain inaccessible"
        );
    }

    #[test]
    fn governance_restore_pending_update_scrubs_existing_key_id_aliases_fail_closed() {
        let mut st = StateStore::new();
        st.pending_gov_updates.insert(
            NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID.into(),
            PendingGovParamUpdate {
                key_id: EMERGENCY_PAUSE_KEY_ID,
                key: NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID.into(),
                value: "key-42".into(),
                activate_at_height: 41,
            },
        );

        st.restore_pending_gov_update(
            "emergency_pause",
            Some(PendingGovParamUpdate {
                key_id: EMERGENCY_PAUSE_KEY_ID,
                key: "emergency_pause".into(),
                value: "true".into(),
                activate_at_height: 42,
            }),
        );

        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "restore must fail closed instead of accepting a pending entry while a key-id alias exists"
        );
        assert!(
            st.pending_gov_update(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID)
                .is_none(),
            "restore rejection must scrub stale key-id aliases instead of preserving ambiguous pending state"
        );
        assert!(
            st.pending_gov_updates.get("emergency_pause").is_none(),
            "rejected restore must not retain the requested canonical pending entry"
        );
        assert!(
            st.pending_gov_updates
                .get(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID)
                .is_none(),
            "rejected restore must remove the conflicting raw alias entry"
        );
    }

    #[test]
    fn governance_restore_pending_update_rejects_non_allowlisted_algorand_key_fail_closed() {
        let mut st = StateStore::new();
        st.restore_pending_gov_update(
            NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID,
            Some(PendingGovParamUpdate {
                key_id: 9_200,
                key: NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID.into(),
                value: "key-42".into(),
                activate_at_height: 77_777,
            }),
        );

        assert!(
            st.pending_gov_update(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID)
                .is_none(),
            "pending restore must fail closed for a non-allowlisted governance key"
        );
        assert!(
            st.pending_gov_updates
                .get(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID)
                .is_none(),
            "pending restore must not retain a raw queued entry for a non-allowlisted governance key"
        );
    }

    #[test]
    fn governance_accessors_fail_closed_on_key_name_registry_mismatch() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            7316,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .expect("initial resolve_authority write should succeed");

        let object = st
            .objects
            .get_mut(&7316)
            .expect("canonical resolve_authority object should exist");
        let version = object.version;
        object.value = ObjectValue::GovParam(GovParamObject {
            key_id: 7316,
            key: "challenge_min_bond".into(),
            value: "resolver-v1,resolver-v2".into(),
            version,
        });

        assert_eq!(
            st.gov_param_string("resolve_authority"),
            None,
            "string accessor must fail closed when registry key and object key diverge"
        );
        assert_eq!(
            st.gov_param_u128("resolve_authority"),
            None,
            "typed accessor must fail closed when registry key and object key diverge"
        );
        assert!(
            st.gov_param_ref_for_key("resolve_authority").is_none(),
            "object ref accessor must fail closed when registry key and object key diverge"
        );
        assert!(
            st.get_param(7316).is_none(),
            "direct id accessor must fail closed when registry key and object key diverge"
        );
    }

    #[test]
    fn governance_accessors_fail_closed_on_key_id_alias_registry_injection() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            7_316,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .expect("initial resolve_authority write should succeed");
        st.gov_param_key_index
            .insert("challenge_min_bond".into(), 7_316);

        assert_eq!(
            st.gov_param_string("resolve_authority"),
            None,
            "string accessor must fail closed when another governance key aliases the same key_id"
        );
        assert!(
            st.gov_param_ref_for_key("resolve_authority").is_none(),
            "ref accessor must fail closed when another governance key aliases the same key_id"
        );
        assert_eq!(
            st.pending_gov_update("resolve_authority"),
            None,
            "pending accessor must fail closed when registry aliasing breaks the single-source key_id binding"
        );
        assert!(
            st.get_param(7_316).is_none(),
            "direct id accessor must fail closed when registry aliasing breaks the single-source key_id binding"
        );
    }

    #[test]
    fn emergency_pause_does_not_mutate_pending_resolve_authority_update() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            7313,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .unwrap();

        let scheduled = st
            .set_gov_param(
                13_000,
                7313,
                "resolve_authority".into(),
                "resolver-v3,resolver-v4".into(),
            )
            .unwrap();
        assert!(matches!(
            scheduled,
            GovParamUpdateOutcome::Scheduled {
                activate_at_height: 13_020
            }
        ));

        st.set_gov_param(13_001, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        st.set_gov_param(13_002, 7_999, "emergency_pause".into(), "false".into())
            .expect("unpause toggle must apply immediately");

        assert!(!st.is_emergency_paused());
        let pending = st
            .pending_gov_update("resolve_authority")
            .expect("pending resolve_authority update should survive pause toggles");
        assert_eq!(pending.key_id, 7313);
        assert_eq!(pending.value, "resolver-v3,resolver-v4");
        assert_eq!(pending.activate_at_height, 13_020);

        let applied = st
            .set_gov_param(
                13_020,
                7313,
                "resolve_authority".into(),
                "resolver-v3,resolver-v4".into(),
            )
            .expect("resolve_authority should still activate at original timelock height");
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("resolver-v3,resolver-v4".into())
        );
        assert!(st.pending_gov_update("resolve_authority").is_none());
    }

    #[test]
    fn governance_sensitive_pending_replace_before_activation_resets_timelock() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(7320, "challenge_window_blocks".into(), "100".into())
            .unwrap();

        let first = st
            .set_gov_param(20_000, 7320, "challenge_window_blocks".into(), "110".into())
            .unwrap();
        assert!(matches!(
            first,
            GovParamUpdateOutcome::Scheduled {
                activate_at_height: 20_020
            }
        ));

        let replaced = st
            .set_gov_param_with_action(
                20_005,
                7320,
                "challenge_window_blocks".into(),
                "120".into(),
                GovPendingUpdateAction::Replace,
            )
            .unwrap();
        assert!(matches!(
            replaced,
            GovParamUpdateOutcome::Scheduled {
                activate_at_height: 20_025
            }
        ));

        let pending = st.pending_gov_update("challenge_window_blocks").unwrap();
        assert_eq!(pending.value, "120");
        assert_eq!(pending.activate_at_height, 20_025);

        let err = st
            .set_gov_param(20_020, 7320, "challenge_window_blocks".into(), "120".into())
            .unwrap_err();
        assert!(err.contains("timelock active"));

        let applied = st
            .set_gov_param(20_025, 7320, "challenge_window_blocks".into(), "120".into())
            .unwrap();
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
        assert_eq!(st.gov_param_u64("challenge_window_blocks"), Some(120));
    }

    #[test]
    fn governance_sensitive_pending_cancel_before_activation_removes_pending() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(7321, "challenge_min_bond".into(), "100".into())
            .unwrap();

        st.set_gov_param(21_000, 7321, "challenge_min_bond".into(), "120".into())
            .unwrap();

        let cancelled = st
            .set_gov_param_with_action(
                21_005,
                7321,
                "challenge_min_bond".into(),
                "".into(),
                GovPendingUpdateAction::Cancel,
            )
            .unwrap();
        assert!(matches!(cancelled, GovParamUpdateOutcome::Cancelled));

        assert!(st.pending_gov_update("challenge_min_bond").is_none());
        assert_eq!(st.gov_param_u64("challenge_min_bond"), Some(100));
    }

    #[test]
    fn governance_sensitive_apply_without_pending_is_unchanged() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(7322, "challenge_min_bond".into(), "100".into())
            .unwrap();

        let scheduled = st
            .set_gov_param(22_000, 7322, "challenge_min_bond".into(), "120".into())
            .unwrap();
        assert!(matches!(
            scheduled,
            GovParamUpdateOutcome::Scheduled {
                activate_at_height: 22_020
            }
        ));
    }

    #[test]
    fn governance_sensitive_rate_limit_still_enforced_after_replace() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(7323, "challenge_window_blocks".into(), "100".into())
            .unwrap();

        st.set_gov_param(23_000, 7323, "challenge_window_blocks".into(), "120".into())
            .unwrap();

        st.set_gov_param_with_action(
            23_005,
            7323,
            "challenge_window_blocks".into(),
            "119".into(),
            GovPendingUpdateAction::Replace,
        )
        .unwrap();

        let err = st
            .set_gov_param_with_action(
                23_006,
                7323,
                "challenge_window_blocks".into(),
                "130".into(),
                GovPendingUpdateAction::Replace,
            )
            .unwrap_err();
        assert!(err.contains("rate-limit exceeded"));
    }

    #[test]
    fn governance_sensitive_update_excessive_step_change_rejected() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(7302, "challenge_window_blocks".into(), "100".into())
            .unwrap();

        let err = st
            .set_gov_param(3_000, 7302, "challenge_window_blocks".into(), "130".into())
            .unwrap_err();
        assert!(err.contains("rate-limit exceeded"));
    }

    #[test]
    fn governance_sensitive_update_bounded_step_change_accepted() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(7303, "challenge_window_blocks".into(), "100".into())
            .unwrap();

        let scheduled = st
            .set_gov_param(4_000, 7303, "challenge_window_blocks".into(), "120".into())
            .unwrap();
        assert!(matches!(
            scheduled,
            GovParamUpdateOutcome::Scheduled {
                activate_at_height: 4_020
            }
        ));

        let applied = st
            .set_gov_param(4_020, 7303, "challenge_window_blocks".into(), "120".into())
            .unwrap();
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
        assert_eq!(st.gov_param_u64("challenge_window_blocks"), Some(120));
    }

    #[test]
    fn governance_challenge_success_bounty_is_sensitive_and_timelocked() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(7350, "challenge_success_bounty".into(), "1".into())
            .unwrap();

        let scheduled = st
            .set_gov_param(30_000, 7350, "challenge_success_bounty".into(), "2".into())
            .unwrap();
        assert!(matches!(
            scheduled,
            GovParamUpdateOutcome::Scheduled {
                activate_at_height: 30_020
            }
        ));

        let err = st
            .set_gov_param(30_010, 7350, "challenge_success_bounty".into(), "2".into())
            .unwrap_err();
        assert!(err.contains("timelock active"));

        let applied = st
            .set_gov_param(30_020, 7350, "challenge_success_bounty".into(), "2".into())
            .unwrap();
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
        assert_eq!(st.gov_param_u64("challenge_success_bounty"), Some(2));
    }

    #[test]
    fn governance_non_sensitive_param_unaffected_by_timelock() {
        let mut st = StateStore::new();
        let r1 = st
            .set_gov_param(5_000, 7304, "max_block_ms".into(), "15".into())
            .unwrap();
        assert!(matches!(r1, GovParamUpdateOutcome::Applied(_)));

        let r2 = st
            .set_gov_param(5_001, 7304, "max_block_ms".into(), "20".into())
            .unwrap();
        assert!(matches!(r2, GovParamUpdateOutcome::Applied(_)));
        assert_eq!(st.gov_param_u64("max_block_ms"), Some(20));
        assert!(st.pending_gov_update("max_block_ms").is_none());
    }

    #[test]
    fn emergency_pause_requires_strict_bool_literal() {
        let mut st = StateStore::new();

        for bad in [
            "TRUE", "False", "1", "yes", " true", "false ", "\ttrue", "\ntrue", "false\n",
        ] {
            let err = st
                .set_gov_param_unchecked(7999, "emergency_pause".into(), bad.into())
                .unwrap_err();
            assert!(err.contains("strict bool"));
        }

        st.set_gov_param_unchecked(7999, "emergency_pause".into(), "true".into())
            .unwrap();
        assert!(st.is_emergency_paused());

        st.set_gov_param_unchecked(7999, "emergency_pause".into(), "false".into())
            .unwrap();
        assert!(!st.is_emergency_paused());
    }

    #[test]
    fn emergency_pause_flag_works() {
        let mut st = StateStore::new();
        assert!(!st.is_emergency_paused());

        st.set_gov_param_unchecked(7999, "emergency_pause".into(), "true".into())
            .unwrap();
        assert!(st.is_emergency_paused());

        st.set_gov_param_unchecked(7999, "emergency_pause".into(), "false".into())
            .unwrap();
        assert!(!st.is_emergency_paused());
    }

    #[test]
    fn emergency_pause_unchecked_path_rejects_non_canonical_key_id() {
        // Merge-gate guard: even unchecked writes must keep emergency_pause pinned to 7999.
        let mut st = StateStore::new();
        let err = st
            .set_gov_param_unchecked(8_000, "emergency_pause".into(), "true".into())
            .expect_err("unchecked non-canonical emergency_pause key_id must be rejected");
        assert!(err.contains("expected_id=7999"), "{err}");
        assert!(!st.is_emergency_paused());
    }

    #[test]
    fn governance_expected_key_id_registry_merge_gate_is_explicit() {
        for (key, expected_key_id) in GOV_PINNED_KEY_IDS {
            assert_eq!(
                governance_expected_key_id(key),
                Some(*expected_key_id),
                "{key}"
            );
            assert_eq!(
                governance_expected_key_for_id(*expected_key_id),
                Some(*key),
                "{expected_key_id}"
            );
        }

        for key in GOV_ALLOWED_KEYS {
            if !GOV_PINNED_KEY_IDS
                .iter()
                .any(|(pinned_key, _)| pinned_key == key)
            {
                assert_eq!(
                    governance_expected_key_id(key),
                    None,
                    "unexpected pinned governance key-id policy for {key}"
                );
            }
        }

        assert_eq!(governance_expected_key_id("resolve_authority"), None);
        assert_eq!(governance_expected_key_for_id(7_312), None);
    }

    #[test]
    fn governance_restore_rejects_reusing_canonical_emergency_pause_id_for_another_key_fail_closed()
    {
        let mut st = StateStore::new();
        st.restore_gov_param(
            EMERGENCY_PAUSE_KEY_ID,
            Some(GovParamObject {
                key_id: EMERGENCY_PAUSE_KEY_ID,
                key: "resolve_authority".into(),
                value: "resolver-v1,resolver-v2".into(),
                version: 1,
            }),
        );

        assert!(
            st.gov_param_ref_for_key("resolve_authority").is_none(),
            "restore must fail closed instead of letting another governance key reuse the canonical emergency_pause id"
        );
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            None,
            "accessors must not expose a governance param restored under a pinned id reserved for a different key"
        );
        assert!(
            st.objects.get(&EMERGENCY_PAUSE_KEY_ID).is_none(),
            "rejected restore must not leave a stray gov param object at the reserved emergency_pause id"
        );
        assert!(
            st.gov_param_key_index.get("resolve_authority").is_none(),
            "rejected restore must not register another key against the reserved emergency_pause id"
        );
    }

    #[test]
    fn governance_pinned_binding_is_single_source_for_key_and_reserved_id_lookups() {
        assert_eq!(
            governance_pinned_binding_for_key("emergency_pause"),
            Some(("emergency_pause", 7_999))
        );
        assert_eq!(
            governance_pinned_binding_for_id(7_999),
            Some(("emergency_pause", 7_999))
        );
        assert_eq!(
            governance_pinned_binding_for_key(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID),
            None,
            "foreign governance keys must not resolve through the shared pinned-key registry"
        );
        assert_eq!(governance_pinned_binding_for_key("resolve_authority"), None);
        assert_eq!(governance_pinned_binding_for_id(8_000), None);
    }

    #[test]
    fn governance_registry_lookup_id_for_key_prefers_single_source_pinned_binding() {
        let mut indexed = BTreeMap::new();
        indexed.insert("emergency_pause".to_string(), 8_000);
        indexed.insert("resolve_authority".to_string(), 7_313);
        indexed.insert(
            NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID.to_string(),
            9_200,
        );

        assert_eq!(
            governance_registry_lookup_id_for_key(&indexed, "emergency_pause"),
            Some(EMERGENCY_PAUSE_KEY_ID),
            "reserved governance keys must resolve from the shared pinned registry even when the mutable index drifts"
        );
        assert_eq!(
            governance_registry_lookup_id_for_key(&indexed, "resolve_authority"),
            Some(7_313),
            "non-pinned governance keys should still resolve through the mutable registry"
        );
        assert_eq!(
            governance_registry_lookup_id_for_key(&indexed, NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID),
            None,
            "foreign governance keys must fail closed instead of resolving through mutable registry drift"
        );
    }

    #[test]
    fn governance_expected_pinned_binding_routes_both_directions_from_single_source() {
        assert_eq!(
            governance_expected_pinned_binding("emergency_pause", 8_000),
            (Some(EMERGENCY_PAUSE_KEY_ID), None),
            "pinned key lookups should surface the canonical reserved id even when the attempted id drifts"
        );
        assert_eq!(
            governance_expected_pinned_binding("resolve_authority", EMERGENCY_PAUSE_KEY_ID),
            (None, Some("emergency_pause")),
            "reserved id lookups should surface the canonical pinned key even when another key attempts to reuse it"
        );
        assert_eq!(
            governance_expected_pinned_binding("emergency_pause", EMERGENCY_PAUSE_KEY_ID),
            (Some(EMERGENCY_PAUSE_KEY_ID), Some("emergency_pause")),
            "canonical pinned key/id pair should resolve both expectations from the shared single source"
        );
    }

    #[test]
    fn governance_registry_binding_merge_gate_rejects_non_canonical_emergency_pause_routing() {
        let empty_index = BTreeMap::new();
        let err = validate_gov_param_registry_binding(&empty_index, "emergency_pause", 8_000)
            .expect_err(
            "pinned governance key must reject non-canonical key ids at the shared registry gate",
        );
        assert!(err.contains("expected_id=7999"), "{err}");

        let err = validate_gov_param_registry_binding(&empty_index, "resolve_authority", 7_999)
            .expect_err("shared registry gate must reject routing another governance key through the reserved emergency_pause key id");
        assert!(err.contains("expected_key=emergency_pause"), "{err}");

        let mut indexed = BTreeMap::new();
        indexed.insert("resolve_authority".to_string(), 7_313);
        let err = validate_gov_param_registry_binding(&indexed, "resolve_authority", 9_001)
            .expect_err("registry gate must reject mismatched indexed governance key ids");
        assert!(err.contains("existing_id=7313"), "{err}");
    }

    #[test]
    fn governance_registry_binding_reports_canonical_key_from_single_source_reverse_lookup() {
        let mut indexed = BTreeMap::new();
        indexed.insert("resolve_authority".to_string(), 7_313);

        let err = validate_gov_param_registry_binding(&indexed, "max_block_ms", 7_313)
            .expect_err("shared registry gate must reject mutable key-id alias reuse");
        assert!(err.contains("canonical_key=resolve_authority"), "{err}");
        assert!(err.contains("aliased_key=max_block_ms"), "{err}");

        assert_eq!(
            governance_registry_lookup_key_for_id(&indexed, 7_313),
            Some("resolve_authority"),
            "reverse lookup should reuse the same single source as registry validation"
        );
        assert_eq!(
            governance_registry_lookup_key_for_id(&indexed, EMERGENCY_PAUSE_KEY_ID),
            Some("emergency_pause"),
            "reserved reverse lookup should stay pinned even without mutable registry state"
        );
    }

    #[test]
    fn governance_registry_binding_rejects_ambiguous_dynamic_reverse_lookup() {
        let mut indexed = BTreeMap::new();
        indexed.insert("max_block_ms".to_string(), 7_313);
        indexed.insert("resolve_authority".to_string(), 7_313);

        let err = validate_gov_param_registry_binding(&indexed, "max_block_ms", 7_313)
            .expect_err("ambiguous reverse registry aliases must fail closed");
        assert!(
            err.contains("ambiguous_keys=max_block_ms,resolve_authority"),
            "{err}"
        );
        assert_eq!(
            governance_registry_lookup_key_for_id(&indexed, 7_313),
            None,
            "reverse lookup should fail closed instead of picking an arbitrary alias"
        );
    }

    #[test]
    fn governance_reverse_lookup_ignores_non_allowlisted_dynamic_registry_keys_fail_closed() {
        let mut indexed = BTreeMap::new();
        indexed.insert(
            NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID.to_string(),
            9_200,
        );

        assert_eq!(
            governance_registry_lookup_key_for_id(&indexed, 9_200),
            None,
            "reverse lookup must ignore non-allowlisted dynamic governance keys instead of surfacing a foreign alias"
        );
    }

    #[test]
    fn governance_reverse_lookup_fails_closed_when_dynamic_registry_reuses_reserved_key_id() {
        let mut indexed = BTreeMap::new();
        indexed.insert("resolve_authority".to_string(), EMERGENCY_PAUSE_KEY_ID);

        assert_eq!(
            governance_registry_lookup_key_for_id(&indexed, EMERGENCY_PAUSE_KEY_ID),
            None,
            "reverse lookup must fail closed when a mutable registry entry reuses the reserved emergency_pause key id"
        );
    }

    #[test]
    fn governance_accessors_fail_closed_on_ambiguous_dynamic_registry_id_aliases() {
        let mut st = StateStore::new();
        st.gov_param_key_index.insert("max_block_ms".into(), 7_313);
        st.gov_param_key_index
            .insert("resolve_authority".into(), 7_313);
        st.objects.insert(
            7_313,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: 7_313,
                    key: "max_block_ms".into(),
                    value: "250".into(),
                    version: 1,
                }),
            },
        );

        assert!(
            st.gov_param_value("max_block_ms").is_none(),
            "ambiguous reverse registry aliases must fail closed at the string accessor boundary"
        );
        assert!(
            st.gov_param_ref_for_key("max_block_ms").is_none(),
            "ambiguous reverse registry aliases must fail closed at the ref accessor boundary"
        );
    }

    #[test]
    fn emergency_pause_accessors_fail_closed_when_registry_and_object_share_same_wrong_key_id() {
        let mut st = StateStore::new();
        st.objects.insert(
            8_000,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: 8_000,
                    key: "emergency_pause".into(),
                    value: "true".into(),
                    version: 1,
                }),
            },
        );
        st.gov_param_key_index
            .insert("emergency_pause".into(), 8_000);

        assert!(
            st.gov_param_value("emergency_pause").is_none(),
            "string accessor must fail closed when a pinned governance key is routed through a non-canonical key id"
        );
        assert!(
            st.gov_param_string("emergency_pause").is_none(),
            "public string accessor must fail closed when registry and object agree on the same wrong pinned key id"
        );
        assert!(
            !st.is_emergency_paused(),
            "emergency pause must remain disabled when accessor routing observes a non-canonical pinned key id"
        );
    }

    #[test]
    fn emergency_pause_accessors_fail_closed_when_registry_id_is_canonical_but_object_key_id_is_not(
    ) {
        let mut st = StateStore::new();
        st.objects.insert(
            7_999,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: 8_000,
                    key: "emergency_pause".into(),
                    value: "true".into(),
                    version: 1,
                }),
            },
        );
        st.gov_param_key_index
            .insert("emergency_pause".into(), 7_999);

        assert!(
            st.gov_param_value("emergency_pause").is_none(),
            "string accessor must fail closed when a pinned governance object embeds a non-canonical key id"
        );
        assert!(
            st.gov_param_ref_for_key("emergency_pause").is_none(),
            "ref accessor must fail closed when registry id is canonical but snapshot key id is not"
        );
        assert!(
            !st.is_emergency_paused(),
            "emergency pause must remain disabled when the embedded pinned key id diverges from the registry"
        );
    }

    #[test]
    fn emergency_pause_checked_path_rejects_non_canonical_key_id() {
        // Merge-gate guard: emergency_pause must remain pinned to canonical key id.
        let mut st = StateStore::new();
        let err = st
            .set_gov_param(8_050, 8_000, "emergency_pause".into(), "true".into())
            .expect_err("non-canonical emergency_pause key_id must be rejected");
        assert!(err.contains("expected_id=7999"), "{err}");
        assert!(!st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn emergency_pause_checked_path_repairs_same_key_registry_drift_via_single_source_binding() {
        let mut st = StateStore::new();
        st.gov_param_key_index
            .insert("emergency_pause".into(), 8_000);

        let applied = st
            .set_gov_param(8_052, 7_999, "emergency_pause".into(), "true".into())
            .expect("canonical pinned key write should ignore same-key mutable registry drift");

        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
        assert_eq!(
            st.gov_param_key_index.get("emergency_pause").copied(),
            Some(7_999),
            "canonical pinned write must repair same-key registry drift back to the reserved key id"
        );
        assert_eq!(
            st.get_param(7_999)
                .map(|param| (param.key_id, param.key, param.value)),
            Some((7_999, "emergency_pause".into(), "true".into())),
            "canonical pinned write must materialize the governance value at the reserved slot"
        );
        assert!(st.is_emergency_paused());
    }

    #[test]
    fn emergency_pause_unchecked_idempotent_replay_uses_single_source_lookup_without_registry_entry(
    ) {
        let mut st = StateStore::new();
        let first = st
            .set_gov_param_unchecked(7_999, "emergency_pause".into(), "false".into())
            .expect("canonical emergency_pause write should succeed");
        st.gov_param_key_index.remove("emergency_pause");

        let replay = st
            .set_gov_param_unchecked(7_999, "emergency_pause".into(), "false".into())
            .expect("idempotent replay should recover pinned emergency_pause through the single-source helper");

        assert_eq!(replay, first);
        assert_eq!(
            st.get_param(7_999)
                .map(|param| (param.version, param.key_id, param.key, param.value)),
            Some((1, 7_999, "emergency_pause".into(), "false".into())),
            "idempotent replay must not churn version/state when the pinned key is recoverable from the shared single-source binding"
        );
    }

    #[test]
    fn emergency_pause_checked_path_key_id_validation_precedes_bool_schema_validation() {
        // Merge-gate guard: key-id mismatch must fail before value schema parsing,
        // so malformed values cannot alter error semantics.
        let mut st = StateStore::new();

        let err = st
            .set_gov_param(8_051, 8_000, "emergency_pause".into(), "TRUE".into())
            .expect_err("non-canonical emergency_pause key_id must be rejected first");
        assert!(err.contains("expected_id=7999"), "{err}");
        assert!(
            !err.contains("strict bool"),
            "key-id mismatch path must not leak value-schema errors: {err}"
        );
        assert!(!st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn emergency_pause_checked_replace_rejects_non_canonical_key_id_without_side_effects() {
        // Merge-gate guard: Replace action must enforce the same canonical key-id pinning.
        let mut st = StateStore::new();

        let err = st
            .set_gov_param_with_action(
                8_051,
                8_000,
                "emergency_pause".into(),
                "true".into(),
                GovPendingUpdateAction::Replace,
            )
            .expect_err("replace with non-canonical emergency_pause key_id must be rejected");

        assert!(err.contains("expected_id=7999"), "{err}");
        assert!(!st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn emergency_pause_key_id_fail_closed_error_stays_aligned_across_write_entrypoints() {
        // REF03 guard: the pinned emergency_pause key id must come from one shared gate so
        // unchecked, checked, and replace entrypoints all fail closed with the same boundary.
        let mut unchecked = StateStore::new();
        let mut checked = StateStore::new();
        let mut replace = StateStore::new();

        let unchecked_err = unchecked
            .set_gov_param_unchecked(8_000, "emergency_pause".into(), "true".into())
            .expect_err("unchecked non-canonical emergency_pause key_id must be rejected");
        let checked_err = checked
            .set_gov_param(8_052, 8_000, "emergency_pause".into(), "true".into())
            .expect_err("checked non-canonical emergency_pause key_id must be rejected");
        let replace_err = replace
            .set_gov_param_with_action(
                8_053,
                8_000,
                "emergency_pause".into(),
                "true".into(),
                GovPendingUpdateAction::Replace,
            )
            .expect_err("replace non-canonical emergency_pause key_id must be rejected");

        for err in [&unchecked_err, &checked_err, &replace_err] {
            assert!(
                err.contains("governance key id mismatch for emergency_pause: expected_id=7999, attempted_id=8000"),
                "{err}"
            );
        }
        assert!(!unchecked.is_emergency_paused());
        assert!(!checked.is_emergency_paused());
        assert!(!replace.is_emergency_paused());
        assert!(checked.pending_gov_update("emergency_pause").is_none());
        assert!(replace.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn emergency_pause_checked_path_is_immediate_and_non_cancellable() {
        let mut st = StateStore::new();

        let applied = st
            .set_gov_param(8_000, 7999, "emergency_pause".into(), "true".into())
            .unwrap();
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
        assert!(st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());

        let cancel_err = st
            .set_gov_param_with_action(
                8_001,
                7999,
                "emergency_pause".into(),
                "true".into(),
                GovPendingUpdateAction::Cancel,
            )
            .unwrap_err();
        assert!(cancel_err.contains("cancel not supported for non-sensitive key"));
        // Failed cancel must be side-effect free on pause state and pending queues.
        assert!(st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());

        let applied_unpause = st
            .set_gov_param(8_002, 7999, "emergency_pause".into(), "false".into())
            .unwrap();
        assert!(matches!(applied_unpause, GovParamUpdateOutcome::Applied(_)));
        assert!(!st.is_emergency_paused());
    }

    #[test]
    fn emergency_pause_checked_noop_update_is_idempotent_after_pause() {
        // Merge-gate guard: repeated identical emergency_pause writes should be side-effect free.
        let mut st = StateStore::new();

        let first = st
            .set_gov_param(8_010, 7_999, "emergency_pause".into(), "true".into())
            .expect("initial pause=true write must succeed");
        let first_ref = match first {
            GovParamUpdateOutcome::Applied(r) => r,
            _ => panic!("expected immediate apply"),
        };

        let second = st
            .set_gov_param(8_011, 7_999, "emergency_pause".into(), "true".into())
            .expect("noop pause=true write must succeed");
        let second_ref = match second {
            GovParamUpdateOutcome::Applied(r) => r,
            _ => panic!("expected immediate apply"),
        };

        assert_eq!(first_ref, second_ref, "noop must not churn object version");
        assert!(st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn emergency_pause_checked_replace_noop_is_idempotent() {
        // Merge-gate guard: Replace action on a non-sensitive emergency_pause value should
        // stay immediate and avoid version churn when value is unchanged.
        let mut st = StateStore::new();

        let first = st
            .set_gov_param_with_action(
                8_620,
                7_999,
                "emergency_pause".into(),
                "true".into(),
                GovPendingUpdateAction::Replace,
            )
            .expect("initial replace pause=true write must succeed");
        let first_ref = match first {
            GovParamUpdateOutcome::Applied(r) => r,
            _ => panic!("expected immediate apply for non-sensitive replace"),
        };

        let second = st
            .set_gov_param_with_action(
                8_621,
                7_999,
                "emergency_pause".into(),
                "true".into(),
                GovPendingUpdateAction::Replace,
            )
            .expect("noop replace pause=true write must succeed");
        let second_ref = match second {
            GovParamUpdateOutcome::Applied(r) => r,
            _ => panic!("expected immediate apply for non-sensitive replace"),
        };

        assert_eq!(
            first_ref, second_ref,
            "non-sensitive replace noop must not churn object version"
        );
        assert!(st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn emergency_pause_cancel_scrubs_stale_pending_entry_even_when_unsupported() {
        let mut st = StateStore::new();

        // Corrupt/legacy state simulation: non-sensitive emergency_pause should never have
        // timelocked pending state; even unsupported Cancel attempts must scrub stale entries.
        st.pending_gov_updates.insert(
            "emergency_pause".into(),
            PendingGovParamUpdate {
                key_id: 7_999,
                key: "emergency_pause".into(),
                value: "true".into(),
                activate_at_height: 77_777,
            },
        );

        let cancel_err = st
            .set_gov_param_with_action(
                8_650,
                7_999,
                "emergency_pause".into(),
                "true".into(),
                GovPendingUpdateAction::Cancel,
            )
            .unwrap_err();
        assert!(cancel_err.contains("cancel not supported for non-sensitive key"));
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "unsupported cancel must still scrub stale pending emergency_pause entries"
        );
        assert!(!st.is_emergency_paused());
    }

    #[test]
    fn emergency_pause_cancel_skips_value_validation_but_stays_side_effect_free() {
        let mut st = StateStore::new();

        // Merge-gate guard: Cancel keeps parser bypass semantics (no bool validation) but must
        // remain side-effect free beyond stale pending cleanup.
        st.pending_gov_updates.insert(
            "emergency_pause".into(),
            PendingGovParamUpdate {
                key_id: 7_999,
                key: "emergency_pause".into(),
                value: "true".into(),
                activate_at_height: 77_888,
            },
        );

        let cancel_err = st
            .set_gov_param_with_action(
                8_651,
                7_999,
                "emergency_pause".into(),
                "NOT_BOOL".into(),
                GovPendingUpdateAction::Cancel,
            )
            .unwrap_err();
        assert!(cancel_err.contains("cancel not supported for non-sensitive key"));
        assert!(
            !cancel_err.contains("invalid governance value"),
            "cancel path must not attempt value parsing for emergency_pause"
        );
        assert!(st.pending_gov_update("emergency_pause").is_none());
        assert!(!st.is_emergency_paused());
    }

    #[test]
    fn emergency_pause_cancel_wrong_key_id_is_rejected_without_scrubbing_state() {
        let mut st = StateStore::new();

        // Merge-gate guard: key_id mismatch must fail before any state cleanup/mutation,
        // even when legacy/corrupt pending emergency_pause data exists.
        st.pending_gov_updates.insert(
            "emergency_pause".into(),
            PendingGovParamUpdate {
                key_id: 7_999,
                key: "emergency_pause".into(),
                value: "true".into(),
                activate_at_height: 77_777,
            },
        );

        let cancel_err = st
            .set_gov_param_with_action(
                8_651,
                8_000,
                "emergency_pause".into(),
                "true".into(),
                GovPendingUpdateAction::Cancel,
            )
            .unwrap_err();
        assert!(cancel_err.contains("expected_id=7999"), "{cancel_err}");

        let pending = st
            .pending_gov_update("emergency_pause")
            .expect("mismatched key_id path must not mutate pending state");
        assert_eq!(pending.key_id, 7_999);
        assert_eq!(pending.activate_at_height, 77_777);
        assert!(!st.is_emergency_paused());
    }

    #[test]
    fn emergency_pause_checked_path_clears_stale_pending_entry_if_present() {
        let mut st = StateStore::new();

        // Corrupt/legacy state simulation: emergency_pause should never be timelocked,
        // but if a stale pending entry exists, checked-path apply must scrub it.
        st.pending_gov_updates.insert(
            "emergency_pause".into(),
            PendingGovParamUpdate {
                key_id: 7_999,
                key: "emergency_pause".into(),
                value: "true".into(),
                activate_at_height: 99_999,
            },
        );

        let applied = st
            .set_gov_param(8_700, 7_999, "emergency_pause".into(), "true".into())
            .unwrap();
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
        assert!(st.is_emergency_paused());
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "stale pending entry must be removed for non-sensitive emergency_pause"
        );
    }

    #[test]
    fn restore_pending_gov_update_rejects_non_sensitive_emergency_pause_metadata() {
        let mut st = StateStore::new();

        st.restore_pending_gov_update(
            "emergency_pause",
            Some(PendingGovParamUpdate {
                key_id: 7_999,
                key: "emergency_pause".into(),
                value: "true".into(),
                activate_at_height: 99_999,
            }),
        );

        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "restore must fail closed for immediate emergency_pause pending metadata"
        );
        assert!(!st.is_emergency_paused());
    }

    #[test]
    fn restore_pending_gov_update_rejects_incomplete_zero_activation_height_metadata() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            7_313,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .expect("seed resolve_authority");

        st.restore_pending_gov_update(
            "resolve_authority",
            Some(PendingGovParamUpdate {
                key_id: 7_313,
                key: "resolve_authority".into(),
                value: "resolver-v3,resolver-v4".into(),
                activate_at_height: 0,
            }),
        );

        assert!(
            st.pending_gov_update("resolve_authority").is_none(),
            "restore must fail closed when pending governance metadata omits a positive activation height"
        );
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("resolver-v1,resolver-v2".into())
        );
    }

    #[test]
    fn restore_pending_gov_update_resolve_authority_scrubs_stale_pending_resolve_metadata() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            7_313,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .expect("seed resolve_authority");

        let task = TaskObject {
            task_id: 7_701,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-1".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(10),
            challenged_at_height: Some(20),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(5),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(false),
            version: 3,
        };
        st.restore_task(task.task_id, Some(task));
        st.restore_pending_resolve_approval(
            7_701,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "resolver-v1".into(),
                authority_set: "resolver-v1,resolver-v2".into(),
                task_version: 3,
            }),
        );
        assert_eq!(st.pending_resolve_approval(7_701), Some((true, 1)));

        st.restore_pending_gov_update(
            "resolve_authority",
            Some(PendingGovParamUpdate {
                key_id: 7_313,
                key: "resolve_authority".into(),
                value: "resolver-v3,resolver-v4".into(),
                activate_at_height: 99_999,
            }),
        );

        let pending = st
            .pending_gov_update("resolve_authority")
            .expect("pending resolve_authority restore should succeed");
        assert_eq!(pending.value, "resolver-v3,resolver-v4");
        assert!(
            st.pending_resolve_approval(7_701).is_none(),
            "restore must scrub stale pending resolve metadata across a resolve_authority boundary"
        );
    }

    #[test]
    fn emergency_pause_unchecked_path_clears_stale_pending_entry_if_present() {
        let mut st = StateStore::new();

        // Corrupt/legacy state simulation: emergency_pause should never be timelocked,
        // and unchecked-path writes must still scrub stale pending entries.
        st.pending_gov_updates.insert(
            "emergency_pause".into(),
            PendingGovParamUpdate {
                key_id: 7_999,
                key: "emergency_pause".into(),
                value: "true".into(),
                activate_at_height: 88_888,
            },
        );

        st.set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
            .unwrap();
        assert!(st.is_emergency_paused());
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "unchecked emergency_pause apply must remove stale pending entry"
        );
    }

    #[test]
    fn emergency_pause_unchecked_noop_is_idempotent_and_clears_stale_pending_entry() {
        let mut st = StateStore::new();

        let first_ref = st
            .set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
            .expect("first unchecked pause write must succeed");
        assert!(st.is_emergency_paused());

        // Corrupt/legacy state simulation: stale pending residue must be scrubbed even
        // when the unchecked write is a noop.
        st.pending_gov_updates.insert(
            "emergency_pause".into(),
            PendingGovParamUpdate {
                key_id: 7_999,
                key: "emergency_pause".into(),
                value: "true".into(),
                activate_at_height: 88_999,
            },
        );

        let second_ref = st
            .set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
            .expect("unchecked noop pause write must stay idempotent");

        assert_eq!(
            first_ref, second_ref,
            "unchecked noop emergency_pause write must not churn version"
        );
        assert!(st.is_emergency_paused());
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "unchecked noop must still remove stale emergency_pause pending entry"
        );
    }

    #[test]
    fn emergency_pause_does_not_mutate_other_sensitive_pending_updates() {
        let mut st = StateStore::new();

        st.set_gov_param_unchecked(8_500, "challenge_min_bond".into(), "100".into())
            .unwrap();

        let scheduled = st
            .set_gov_param(8_600, 8_500, "challenge_min_bond".into(), "120".into())
            .unwrap();
        let activate_at_height = match scheduled {
            GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
            GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
            GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
        };
        assert_eq!(activate_at_height, 8_620);

        let pause_outcome = st
            .set_gov_param(8_601, 7_999, "emergency_pause".into(), "true".into())
            .unwrap();
        assert!(matches!(pause_outcome, GovParamUpdateOutcome::Applied(_)));
        assert!(st.is_emergency_paused());

        let pending = st
            .pending_gov_update("challenge_min_bond")
            .expect("challenge_min_bond pending update must remain");
        assert_eq!(pending.key_id, 8_500);
        assert_eq!(pending.value, "120");
        assert_eq!(pending.activate_at_height, 8_620);
        assert!(st.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn emergency_pause_replace_action_remains_immediate_without_pending_state() {
        let mut st = StateStore::new();

        let applied = st
            .set_gov_param_with_action(
                9_000,
                7999,
                "emergency_pause".into(),
                "true".into(),
                GovPendingUpdateAction::Replace,
            )
            .unwrap();
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
        assert!(st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());

        // Replace action must remain immediate and non-scheduling in both directions.
        let unapplied = st
            .set_gov_param_with_action(
                9_001,
                7999,
                "emergency_pause".into(),
                "false".into(),
                GovPendingUpdateAction::Replace,
            )
            .unwrap();
        assert!(matches!(unapplied, GovParamUpdateOutcome::Applied(_)));
        assert!(!st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn emergency_pause_replace_action_scrubs_stale_pending_entry() {
        // Merge-gate guard: Replace action must stay on the immediate non-sensitive path,
        // including cleanup of any legacy/corrupt queued emergency_pause timelock entry.
        let mut st = StateStore::new();
        st.pending_gov_updates.insert(
            "emergency_pause".into(),
            PendingGovParamUpdate {
                key_id: 7_999,
                key: "emergency_pause".into(),
                value: "true".into(),
                activate_at_height: 99_999,
            },
        );

        let applied = st
            .set_gov_param_with_action(
                9_004,
                7_999,
                "emergency_pause".into(),
                "true".into(),
                GovPendingUpdateAction::Replace,
            )
            .expect("replace action should apply immediately for emergency_pause");

        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
        assert!(st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn emergency_pause_replace_action_still_enforces_strict_bool_schema() {
        // Merge-gate guard: action variants must not bypass strict bool validation.
        let mut st = StateStore::new();

        let err = st
            .set_gov_param_with_action(
                9_005,
                7_999,
                "emergency_pause".into(),
                "TRUE".into(),
                GovPendingUpdateAction::Replace,
            )
            .expect_err("replace action must reject non-strict bool literal");
        assert!(err.contains("expected strict bool"));
        assert!(!st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn emergency_pause_replace_noop_is_idempotent_and_non_scheduling() {
        // Merge-gate guard: Replace noop must stay immediate and avoid object-version churn.
        let mut st = StateStore::new();

        let first = st
            .set_gov_param_with_action(
                9_006,
                7_999,
                "emergency_pause".into(),
                "true".into(),
                GovPendingUpdateAction::Replace,
            )
            .expect("initial replace pause=true must apply immediately");
        let first_ref = match first {
            GovParamUpdateOutcome::Applied(r) => r,
            _ => panic!("expected immediate apply"),
        };

        let second = st
            .set_gov_param_with_action(
                9_007,
                7_999,
                "emergency_pause".into(),
                "true".into(),
                GovPendingUpdateAction::Replace,
            )
            .expect("replace noop pause=true must remain immediate and idempotent");
        let second_ref = match second {
            GovParamUpdateOutcome::Applied(r) => r,
            _ => panic!("expected immediate apply"),
        };

        assert_eq!(
            first_ref, second_ref,
            "replace noop must not churn object version"
        );
        assert!(st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn emergency_pause_enforce_action_remains_immediate_without_pending_state() {
        // Merge-gate guard: explicit Enforce action must stay on the immediate path for
        // emergency pause and never route through timelock scheduling.
        let mut st = StateStore::new();

        let applied = st
            .set_gov_param_with_action(
                9_010,
                7999,
                "emergency_pause".into(),
                "true".into(),
                GovPendingUpdateAction::Enforce,
            )
            .unwrap();
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
        assert!(st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());

        let unapplied = st
            .set_gov_param_with_action(
                9_011,
                7999,
                "emergency_pause".into(),
                "false".into(),
                GovPendingUpdateAction::Enforce,
            )
            .unwrap();
        assert!(matches!(unapplied, GovParamUpdateOutcome::Applied(_)));
        assert!(!st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn emergency_pause_enforce_noop_is_idempotent_and_non_scheduling() {
        // Merge-gate guard: explicit Enforce noop must keep immediate semantics and avoid
        // object-version churn for emergency_pause.
        let mut st = StateStore::new();

        let first = st
            .set_gov_param_with_action(
                9_011,
                7_999,
                "emergency_pause".into(),
                "true".into(),
                GovPendingUpdateAction::Enforce,
            )
            .expect("initial enforce pause=true must apply immediately");
        let first_ref = match first {
            GovParamUpdateOutcome::Applied(r) => r,
            _ => panic!("expected immediate apply"),
        };

        let second = st
            .set_gov_param_with_action(
                9_012,
                7_999,
                "emergency_pause".into(),
                "true".into(),
                GovPendingUpdateAction::Enforce,
            )
            .expect("enforce noop pause=true must remain immediate and idempotent");
        let second_ref = match second {
            GovParamUpdateOutcome::Applied(r) => r,
            _ => panic!("expected immediate apply"),
        };

        assert_eq!(
            first_ref, second_ref,
            "enforce noop must not churn object version"
        );
        assert!(st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn emergency_pause_does_not_bypass_sensitive_timelock_guards() {
        // Merge-gate guard: paused mode must not allow sensitive governance params
        // to skip the timelock state machine.
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(8_500, "challenge_min_bond".into(), "100".into())
            .unwrap();

        let scheduled = st
            .set_gov_param(9_200, 8_500, "challenge_min_bond".into(), "120".into())
            .unwrap();
        let activate_at_height = match scheduled {
            GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
            GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
            GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
        };

        st.set_gov_param(9_201, 7_999, "emergency_pause".into(), "true".into())
            .unwrap();
        assert!(st.is_emergency_paused());

        let err = st
            .set_gov_param(9_205, 8_500, "challenge_min_bond".into(), "120".into())
            .expect_err("paused mode must not bypass sensitive timelock");
        assert!(err.contains("timelock active"), "{err}");

        let pending = st
            .pending_gov_update("challenge_min_bond")
            .expect("timelock pending update must remain intact while paused");
        assert_eq!(pending.activate_at_height, activate_at_height);
        assert_eq!(pending.value, "120");
    }

    #[test]
    fn emergency_pause_checked_path_rejects_key_id_shadowing() {
        let mut st = StateStore::new();
        st.set_gov_param(9_100, 7999, "emergency_pause".into(), "true".into())
            .unwrap();

        let err = st
            .set_gov_param(9_101, 8000, "emergency_pause".into(), "false".into())
            .unwrap_err();
        assert!(err.contains("key id mismatch"));

        // Confirm canonical key id still controls pause state.
        st.set_gov_param(9_102, 7999, "emergency_pause".into(), "false".into())
            .unwrap();
        assert!(!st.is_emergency_paused());
    }

    #[test]
    fn non_sensitive_governance_noop_rejects_mismatched_key_id() {
        // Merge-gate guard: noop/idempotent path must not hide key-id drift for immediate keys.
        let mut st = StateStore::new();

        let first = st
            .set_gov_param(9_300, 6_001, "max_block_ms".into(), "500".into())
            .expect("seed max_block_ms must succeed");
        let first_ref = match first {
            GovParamUpdateOutcome::Applied(r) => r,
            _ => panic!("max_block_ms must remain immediate"),
        };

        let err = st
            .set_gov_param(9_301, 6_002, "max_block_ms".into(), "500".into())
            .expect_err("mismatched key-id noop must be rejected");
        assert!(err.contains("governance key id mismatch"), "{err}");

        let preserved = st
            .get_param(first_ref.id)
            .expect("canonical max_block_ms entry must remain readable");
        assert_eq!(preserved.key_id, 6_001);
        assert_eq!(preserved.value, "500");
        assert!(st.pending_gov_update("max_block_ms").is_none());
    }

    #[test]
    fn governance_timelock_classification_merge_gate_keeps_emergency_pause_immediate() {
        // Exhaustive merge-gate guard for timelock classification: changing this table means
        // emergency pause semantics changed and tests/rollout should be reviewed explicitly.
        let expected_sensitive = [
            ("challenge_window_blocks", true),
            ("challenge_min_bond", true),
            ("challenge_success_bounty", true),
            ("llm_meter_prompt_token_weight", true),
            ("llm_meter_generated_token_weight", true),
            ("llm_meter_decode_step_weight", true),
            ("llm_meter_kv_byte_weight", true),
            ("llm_meter_min_accept_work_units", true),
            ("llm_meter_challenge_success_bounty_per_work_unit_num", true),
            ("llm_meter_challenge_success_bounty_per_work_unit_den", true),
            ("llm_meter_worker_completion_bonus_per_work_unit_num", true),
            ("llm_meter_worker_completion_bonus_per_work_unit_den", true),
            ("llm_meter_worker_slash_rebate_per_work_unit_num", true),
            ("llm_meter_worker_slash_rebate_per_work_unit_den", true),
            ("min_worker_stake", true),
            ("challenge_min_bond_bounty_bps", true),
            ("challenge_min_bond_worker_stake_bps", true),
            ("resolve_authority", true),
            ("emergency_pause", false),
        ];

        let expected_sensitive_count = expected_sensitive.iter().filter(|(_, v)| *v).count();
        assert_eq!(
            GOV_SENSITIVE_KEYS.len(),
            expected_sensitive_count,
            "sensitive-key list changed; update timelock classification merge gate"
        );

        for (key, expected) in expected_sensitive {
            assert!(
                GOV_ALLOWED_KEYS.contains(&key),
                "timelock merge gate contains non-whitelisted key: {}",
                key
            );
            assert_eq!(
                is_sensitive_gov_param(key),
                expected,
                "governance sensitivity drifted for key: {}",
                key
            );
        }

        // Behavioral merge-gate: pause must remain immediate (never timelocked/scheduled).
        let mut st = StateStore::new();
        let outcome = st
            .set_gov_param(96_100, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause update");
        assert!(
            matches!(outcome, GovParamUpdateOutcome::Applied(_)),
            "emergency_pause must apply immediately"
        );
        assert!(st.pending_gov_update("emergency_pause").is_none());
        assert!(st.is_emergency_paused());

        let unpause_outcome = st
            .set_gov_param(96_101, 7_999, "emergency_pause".into(), "false".into())
            .expect("unpause update");
        assert!(
            matches!(unpause_outcome, GovParamUpdateOutcome::Applied(_)),
            "emergency_pause=false must also apply immediately"
        );
        assert!(st.pending_gov_update("emergency_pause").is_none());
        assert!(!st.is_emergency_paused());
    }

    #[test]
    fn governance_registry_shape_merge_gate_fails_closed() {
        validate_governance_registry_shape()
            .expect("governance registry shape must remain explicit, unique, and fail-closed");
    }

    #[test]
    fn governance_validator_coverage_merge_gate_is_explicit() {
        let validator_unique: std::collections::BTreeSet<&str> =
            GOV_EXPLICIT_VALIDATOR_KEYS.iter().copied().collect();
        assert_eq!(
            validator_unique.len(),
            GOV_EXPLICIT_VALIDATOR_KEYS.len(),
            "explicit validator-key registry must remain duplicate-free"
        );
        assert_eq!(
            GOV_EXPLICIT_VALIDATOR_KEYS.len(),
            GOV_ALLOWED_KEYS.len(),
            "explicit validator-key registry drifted from allowed governance-key registry"
        );

        for key in GOV_ALLOWED_KEYS {
            assert!(
                validator_unique.contains(key),
                "allowed governance key missing from explicit validator-key registry: {}",
                key
            );
            assert!(
                has_explicit_gov_param_validator(key),
                "allowed governance key missing explicit validator: {}",
                key
            );
            validate_governance_validator_coverage(key).expect(
                "allowed governance key must remain covered by explicit validator+value-rule coverage",
            );
        }

        let err = validate_governance_validator_coverage("not_whitelisted")
            .expect_err("validator coverage helper must fail closed for non-whitelisted keys");
        assert!(
            err.contains("no explicit validator registered for governance key: not_whitelisted"),
            "unexpected validator coverage error for non-whitelisted key: {err}"
        );
    }

    #[test]
    fn governance_validator_coverage_helper_rejects_missing_explicit_value_rule_fail_closed() {
        let err = validate_governance_validator_coverage_from_lists(
            &["max_block_ms", "max_parallel_workers"],
            &[],
            &["max_block_ms", "max_parallel_workers"],
            &["max_block_ms"],
            &[],
            "max_parallel_workers",
        )
        .expect_err(
            "validator coverage helper must fail closed without explicit value-rule coverage",
        );

        assert!(
            err.contains("explicit-value-rule registry drifted from allowed-key registry"),
            "unexpected validator coverage error: {err}"
        );
        assert!(err.contains("max_parallel_workers"), "{err}");
    }

    #[test]
    fn governance_validator_coverage_helper_rejects_missing_explicit_validator_fail_closed() {
        let err = validate_governance_validator_coverage_from_lists(
            &["max_block_ms", "max_parallel_workers"],
            &[],
            &["max_block_ms"],
            &["max_block_ms", "max_parallel_workers"],
            &[],
            "max_parallel_workers",
        )
        .expect_err(
            "validator coverage helper must fail closed without explicit validator coverage",
        );

        assert!(
            err.contains("explicit-validator registry drifted from allowed-key registry"),
            "unexpected validator coverage error: {err}"
        );
        assert!(err.contains("max_parallel_workers"), "{err}");
    }

    #[test]
    fn governance_validator_coverage_helper_rejects_noncanonical_key_spelling_fail_closed() {
        let err = validate_governance_validator_coverage_from_lists(
            &["max_block_ms"],
            &[],
            &["max_block_ms"],
            &["max_block_ms"],
            &[],
            " Max_Block_Ms ",
        )
        .expect_err("validator coverage helper must reject non-canonical governance key spelling");

        assert!(
            err.contains("governance key request must use canonical key spelling:  Max_Block_Ms "),
            "unexpected validator coverage canonicalization error: {err}"
        );
    }

    #[test]
    fn governance_validator_coverage_helper_rejects_registry_membership_drift_fail_closed() {
        let err = validate_governance_validator_coverage_from_lists(
            &["max_block_ms", "max_parallel_workers"],
            &[],
            &["max_block_ms", "ghost_validator_key"],
            &["max_block_ms", "max_parallel_workers"],
            &[],
            "max_block_ms",
        )
        .expect_err("validator coverage helper must fail closed on registry membership drift");

        assert!(
            err.contains("explicit-validator registry drifted from allowed-key registry"),
            "unexpected validator coverage registry-drift error: {err}"
        );
        assert!(err.contains("max_parallel_workers"), "{err}");
        assert!(err.contains("ghost_validator_key"), "{err}");
    }

    #[test]
    fn governance_validator_coverage_helper_rejects_duplicate_allowed_keys_fail_closed() {
        let err = validate_governance_validator_coverage_from_lists(
            &["max_block_ms", "max_block_ms"],
            &[],
            &["max_block_ms"],
            &["max_block_ms"],
            &[],
            "max_block_ms",
        )
        .expect_err("validator coverage helper must fail closed on duplicate allowed-key entries");

        assert!(
            err.contains("allowed-key registry contains duplicate entries"),
            "unexpected validator coverage duplicate-allowed-key error: {err}"
        );
    }

    #[test]
    fn governance_validator_coverage_helper_rejects_pinned_key_registry_membership_drift_fail_closed(
    ) {
        let err = validate_governance_validator_coverage_from_lists(
            &["max_block_ms"],
            &[],
            &["max_block_ms"],
            &["max_block_ms"],
            &[("ghost_pinned_key", 7_001)],
            "max_block_ms",
        )
        .expect_err("validator coverage helper must fail closed on pinned-key registry drift");

        assert!(
            err.contains(
                "governance pinned-key registry contains non-whitelisted key: ghost_pinned_key"
            ),
            "unexpected validator coverage pinned-key registry error: {err}"
        );
    }

    #[test]
    fn governance_schema_invalid_sample_registry_rejects_membership_drift_fail_closed() {
        let err = validate_governance_schema_sample_registry_shape_from_lists(
            &["max_block_ms", "max_parallel_workers"],
            &["max_block_ms", "max_parallel_workers"],
            &["max_block_ms", "max_parallel_workers"],
            &[("max_block_ms", "9"), ("ghost_schema_key", "0")],
        )
        .expect_err("schema invalid-sample registry membership drift must fail closed");

        assert!(
            err.contains(
                "governance schema invalid-sample registry drifted from allowed-key registry"
            ),
            "{err}"
        );
        assert!(err.contains("max_parallel_workers"), "{err}");
        assert!(err.contains("ghost_schema_key"), "{err}");
    }

    #[test]
    fn governance_schema_invalid_sample_registry_rejects_validator_coverage_drift_fail_closed() {
        let err = validate_governance_schema_sample_registry_shape_from_lists(
            &["max_block_ms", "max_parallel_workers"],
            &["max_block_ms"],
            &["max_block_ms"],
            &[("max_block_ms", "9"), ("max_parallel_workers", "0")],
        )
        .expect_err("schema invalid-sample registry must fail closed when explicit validator coverage drifts");

        assert!(
            err.contains("explicit-validator complete for max_parallel_workers")
                || err.contains("coverage missing for allowed key: max_parallel_workers"),
            "{err}"
        );
    }

    #[test]
    fn governance_allowed_keys_schema_invalid_samples_merge_gate_is_explicit() {
        let allowed_unique: std::collections::BTreeSet<&str> =
            GOV_ALLOWED_KEYS.iter().copied().collect();
        let sample_keys: Vec<&str> = GOV_SCHEMA_INVALID_SAMPLES
            .iter()
            .map(|(key, _)| *key)
            .collect();
        let sample_unique: std::collections::BTreeSet<&str> = sample_keys.iter().copied().collect();

        assert_eq!(sample_unique.len(), sample_keys.len());
        assert_eq!(allowed_unique, sample_unique);

        for (key, invalid_sample) in GOV_SCHEMA_INVALID_SAMPLES {
            let err = validate_gov_param_value(key, invalid_sample)
                .expect_err("invalid governance samples must fail closed");
            assert!(
                !err.contains("no explicit validator registered for governance key"),
                "schema invalid sample fell through explicit validator coverage for {key}: {err}"
            );
        }
    }

    #[test]
    fn governance_sensitive_key_coverage_merge_gate_is_explicit() {
        for key in GOV_SENSITIVE_KEYS {
            assert!(
                GOV_ALLOWED_KEYS.contains(key),
                "sensitive governance key missing from allowed-key registry: {}",
                key
            );
            validate_governance_sensitive_key_coverage(key)
                .expect("sensitive governance key must remain present in allowed-key registry");
            validate_governance_validator_coverage(key)
                .expect("sensitive governance key must remain covered by an explicit validator");
        }

        validate_governance_sensitive_key_coverage("emergency_pause")
            .expect("non-sensitive allowed keys should not trip sensitive-key coverage");
        validate_governance_sensitive_key_coverage("not_whitelisted")
            .expect("non-sensitive non-whitelisted keys are rejected by registration, not sensitive coverage");
    }

    #[test]
    fn governance_allowed_keys_schema_merge_gate_is_explicit() {
        // Exhaustive merge-gate guard for whitelist+schema safety. Any added/changed key
        // must update this table with an invalid sample that is expected to fail.
        let expected_invalid_samples = [
            ("max_block_ms", "9"),
            ("max_parallel_workers", "0"),
            ("min_worker_stake", "0"),
            ("challenge_min_bond", "0"),
            ("challenge_min_bond_bounty_bps", "100001"),
            ("challenge_min_bond_worker_stake_bps", "100001"),
            ("challenge_window_blocks", "99"),
            ("challenge_success_bounty", "-1"),
            ("llm_meter_prompt_token_weight", "-1"),
            ("llm_meter_generated_token_weight", "-1"),
            ("llm_meter_decode_step_weight", "-1"),
            ("llm_meter_kv_byte_weight", "-1"),
            ("llm_meter_min_accept_work_units", "-1"),
            ("llm_meter_challenge_success_bounty_per_work_unit_num", "-1"),
            ("llm_meter_challenge_success_bounty_per_work_unit_den", "0"),
            ("llm_meter_worker_completion_bonus_per_work_unit_num", "-1"),
            ("llm_meter_worker_completion_bonus_per_work_unit_den", "0"),
            ("llm_meter_worker_slash_rebate_per_work_unit_num", "-1"),
            ("llm_meter_worker_slash_rebate_per_work_unit_den", "0"),
            ("resolve_authority", "   "),
            ("emergency_pause", "TRUE"),
            ("monetary_policy_tick_interval_blocks", "0"),
            ("monetary_policy_tick_cooldown_blocks", "0"),
            ("monetary_base_issuance_per_tick", "1000000000001"),
            ("monetary_base_burn_per_tick", "1000000000001"),
        ];

        assert_eq!(
            GOV_ALLOWED_KEYS.len(),
            expected_invalid_samples.len(),
            "governance allowed-key list changed; update schema merge gate"
        );

        let mut st = StateStore::new();
        for (i, (key, bad_value)) in expected_invalid_samples.iter().enumerate() {
            assert!(
                GOV_ALLOWED_KEYS.contains(key),
                "schema merge gate contains non-whitelisted key: {}",
                key
            );
            let key_id = if *key == "emergency_pause" {
                7_999
            } else {
                96_000 + i as u64
            };
            let err = st
                .set_gov_param_unchecked(key_id, (*key).into(), (*bad_value).into())
                .unwrap_err();
            assert!(
                err.contains("invalid governance value"),
                "expected schema rejection for key={}, got: {}",
                key,
                err
            );
        }
    }

    #[test]
    fn governance_pinned_key_ids_merge_gate_is_explicit() {
        let expected_pinned = [("emergency_pause", EMERGENCY_PAUSE_KEY_ID)];

        for key in GOV_ALLOWED_KEYS {
            let pinned = governance_pinned_key_id(key);
            let expected = expected_pinned
                .iter()
                .find_map(|(expected_key, expected_id)| {
                    (*expected_key == *key).then_some(*expected_id)
                });
            assert_eq!(
                pinned, expected,
                "governance pinned key-id map changed; update merge gate for key: {}",
                key
            );
        }

        for (key, expected_id) in expected_pinned {
            let err = validate_governance_key_id(key, expected_id + 1)
                .expect_err("mismatched pinned governance key id must be rejected");
            assert!(err.contains("governance key id mismatch for"), "{err}");
            validate_governance_key_id(key, expected_id)
                .expect("canonical pinned governance key id must remain accepted");
        }
    }

    #[test]
    fn restore_gov_param_rejects_non_canonical_pinned_key_id_fail_closed() {
        let mut st = StateStore::new();

        st.restore_gov_param(
            8_000,
            Some(GovParamObject {
                key_id: 8_000,
                key: "emergency_pause".into(),
                value: "true".into(),
                version: 1,
            }),
        );

        assert!(!st.is_emergency_paused());
        assert!(st.get_param(8_000).is_none());
        assert!(st.gov_param_string("emergency_pause").is_none());
    }

    #[test]
    fn restore_gov_param_rejects_unknown_key_fail_closed() {
        let mut st = StateStore::new();

        st.restore_gov_param(
            8_123,
            Some(GovParamObject {
                key_id: 8_123,
                key: "forbidden_key".into(),
                value: "1".into(),
                version: 1,
            }),
        );

        assert!(st.get_param(8_123).is_none());
        assert!(st.gov_param_string("forbidden_key").is_none());
    }

    #[test]
    fn restore_gov_param_rejects_schema_invalid_allowed_key_fail_closed() {
        let mut st = StateStore::new();

        st.restore_gov_param(
            8_124,
            Some(GovParamObject {
                key_id: 8_124,
                key: "max_block_ms".into(),
                value: "9".into(),
                version: 1,
            }),
        );

        assert!(st.get_param(8_124).is_none());
        assert!(st.gov_param_string("max_block_ms").is_none());
    }

    #[test]
    fn restore_gov_param_does_not_clobber_non_param_object_fail_closed() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 8_125,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Open,
            proof_type: Default::default(),
            metadata: None,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        };
        st.put_task_new(task.clone())
            .expect("task bootstrap should succeed");

        st.restore_gov_param(
            8_125,
            Some(GovParamObject {
                key_id: 8_125,
                key: "max_block_ms".into(),
                value: "15".into(),
                version: 1,
            }),
        );

        assert_eq!(st.get_task(8_125), Some(task));
        assert!(st.get_param(8_125).is_none());
        assert!(st.gov_param_string("max_block_ms").is_none());
    }

    #[test]
    fn restore_gov_param_does_not_clobber_live_other_gov_param_on_key_id_alias() {
        let mut st = StateStore::new();
        st.set_gov_param(100, 7_001, "max_block_ms".into(), "1000".into())
            .expect("baseline governance param should apply");

        st.restore_gov_param(
            7_001,
            Some(GovParamObject {
                key_id: 7_001,
                key: "challenge_min_bond".into(),
                value: "6000".into(),
                version: 9,
            }),
        );

        let param = st
            .get_param(7_001)
            .expect("live governance param must remain bound to its original key");
        assert_eq!(param.key, "max_block_ms");
        assert_eq!(param.value, "1000");
        assert_eq!(st.gov_param_u64("max_block_ms"), Some(1000));
        assert!(st.gov_param_u64("challenge_min_bond").is_none());
    }

    #[test]
    fn gov_param_reads_fail_closed_on_embedded_key_id_drift() {
        let mut st = StateStore::new();
        st.objects.insert(
            7_001,
            VersionedObject {
                version: 3,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: 7_999,
                    key: "max_block_ms".into(),
                    value: "1000".into(),
                    version: 3,
                }),
            },
        );
        st.gov_param_key_index.insert("max_block_ms".into(), 7_001);

        assert!(
            st.gov_param_string("max_block_ms").is_none(),
            "reads must fail closed when the indexed slot and embedded governance key id diverge"
        );
        assert!(
            st.gov_param_ref_for_key("max_block_ms").is_none(),
            "ref lookup must fail closed on the same embedded key-id drift"
        );
        assert_eq!(
            st.get_param(7_001)
                .expect("raw object lookup should still expose the corrupted fixture")
                .key_id,
            7_999
        );
    }

    #[test]
    fn governance_resolve_authority_rejects_reserved_or_placeholder_values() {
        let mut st = StateStore::new();

        for (i, bad_value) in [
            DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER,
            "Governance.Resolve_Authority",
            RESERVED_SYSTEM_AUTHORITY,
            "System",
            "authority,system",
            "governance.emergency_pause",
            "Emergency_Pause",
            "authority,governance.emergency_pause",
            "authority,Emergency_Pause",
            CHALLENGE_ESCROW_ACCOUNT,
            "Treasury.Challenge_Escrow",
            CHALLENGE_FORFEIT_TREASURY_ACCOUNT,
            "TREASURY.CHALLENGE_FORFEITS",
            WORKER_SLASH_TREASURY_ACCOUNT,
            "Treasury.Worker_Slashes",
            "authority,treasury.challenge_escrow",
            "authority,Treasury.Challenge_Forfeits",
            "authority,treasury.worker_slashes",
            "authority ",
            "authority team",
            "authority\u{3000}team",
            "authority,",
            ",authority",
            "authority,,authority2",
            "authority,authority",
            "authority,Authority",
            "authority, authority2",
            "authority;authority2",
            "authority|authority2",
            "authority,authority2|authority3",
            "authority,authority2;authority3",
            "authority；authority2",
            "authority，authority2",
            "authority、authority2",
            "authority\u{0000}x",
            "authority,\u{0007}authority2",
        ]
        .iter()
        .enumerate()
        {
            let err = st
                .set_gov_param_unchecked(
                    97_100 + i as u64,
                    "resolve_authority".into(),
                    (*bad_value).into(),
                )
                .expect_err("reserved/malformed resolve_authority must be rejected");
            assert!(
                err.contains("invalid governance value for resolve_authority"),
                "unexpected error for value {:?}: {}",
                bad_value,
                err
            );
        }
    }

    #[test]
    fn governance_accepts_comma_separated_resolve_authority_members() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            97_500,
            "resolve_authority".into(),
            "authority,authority2".into(),
        )
        .expect("comma-separated resolve authority members should be accepted");
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("authority,authority2".to_string())
        );
    }

    #[test]
    fn emergency_pause_toggles_preserve_challenge_escrow_conservation() {
        // Merge-gate guard: emergency pause is a control-plane brake only; it must never
        // mutate custody balances used by challenge escrow accounting.
        let mut st = StateStore::new();
        st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 1_000);
        st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 500);
        let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        st.set_gov_param(98_000, 7_999, "emergency_pause".into(), "true".into())
            .expect("checked pause write should apply immediately");
        st.set_gov_param(98_001, 7_999, "emergency_pause".into(), "false".into())
            .expect("checked unpause write should apply immediately");
        st.set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
            .expect("unchecked pause write should be accepted at canonical key id");

        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            forfeits_before
        );
        assert!(st.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn governance_keysets_merge_gate_are_unique_and_subset_safe() {
        // Merge-gate: duplicate keys in static tables can silently weaken policy checks.
        let allowed_unique: std::collections::BTreeSet<&str> =
            GOV_ALLOWED_KEYS.iter().copied().collect();
        assert_eq!(
            allowed_unique.len(),
            GOV_ALLOWED_KEYS.len(),
            "GOV_ALLOWED_KEYS contains duplicate entries"
        );

        let sensitive_unique: std::collections::BTreeSet<&str> =
            GOV_SENSITIVE_KEYS.iter().copied().collect();
        assert_eq!(
            sensitive_unique.len(),
            GOV_SENSITIVE_KEYS.len(),
            "GOV_SENSITIVE_KEYS contains duplicate entries"
        );

        for key in &sensitive_unique {
            assert!(
                allowed_unique.contains(key),
                "sensitive key must also be whitelisted: {}",
                key
            );
        }

        assert!(
            !sensitive_unique.contains("emergency_pause"),
            "emergency_pause must remain immediate and never timelocked"
        );
    }

    #[test]
    fn balance_debit_credit_works() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 15);
        assert_eq!(st.balance_of("challenger"), 15);

        st.debit_balance("challenger", 10).unwrap();
        assert_eq!(st.balance_of("challenger"), 5);

        let err = st.debit_balance("challenger", 6).unwrap_err();
        assert!(err.contains("insufficient balance"));

        st.credit_balance("challenger", 7).unwrap();
        assert_eq!(st.balance_of("challenger"), 12);
    }

    #[test]
    fn balance_credit_overflow_rejected() {
        let mut st = StateStore::new();
        st.set_balance("treasury", u128::MAX - 1);

        let err = st.credit_balance("treasury", 2).unwrap_err();
        assert!(err.contains("balance overflow on credit"));
    }

    #[test]
    fn restore_task_rejects_incomplete_challenged_metadata() {
        let mut st = StateStore::new();

        st.restore_task(
            900,
            Some(TaskObject {
                task_id: 900,
                creator: "alice".into(),
                bounty: 100,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-1".into()),
                committed_hash: Some([1u8; 32]),
                result_hash: Some([2u8; 32]),
                reveal_salt: Some([3u8; 32]),
                committed_at_height: Some(10),
                reveal_deadline_height: Some(20),
                challenge_deadline_height: Some(30),
                challenge_window_blocks_snapshot: Some(40),
                challenged_at_height: Some(25),
                resolve_deadline_height: Some(35),
                challenge_bond: None,
                challenger: Some("bob".into()),
                challenge_bond_forfeited: Some(false),
                version: 7,
            }),
        );

        assert!(
            st.get_task(900).is_none(),
            "restore must fail closed when challenged task snapshot metadata is incomplete"
        );
    }

    #[test]
    fn restore_task_rejects_paused_challenged_metadata_missing_challenge_bond() {
        let mut st = StateStore::new();
        st.set_gov_param(
            7_999,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "true".into(),
        )
        .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());
        st.pending_resolve_approvals.insert(
            901,
            PendingResolveApproval {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 7,
                stored_as_canonical: false,
            },
        );

        st.restore_task(
            901,
            Some(TaskObject {
                task_id: 901,
                creator: "alice".into(),
                bounty: 100,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-1".into()),
                committed_hash: Some([1u8; 32]),
                result_hash: Some([2u8; 32]),
                reveal_salt: Some([3u8; 32]),
                committed_at_height: Some(10),
                reveal_deadline_height: Some(20),
                challenge_deadline_height: Some(30),
                challenge_window_blocks_snapshot: Some(40),
                challenged_at_height: Some(25),
                resolve_deadline_height: Some(35),
                challenge_bond: None,
                challenger: Some("bob".into()),
                challenge_bond_forfeited: Some(false),
                version: 7,
            }),
        );

        assert!(
            st.get_task(901).is_none(),
            "paused restore must fail closed when challenged task snapshot omits challenge bond metadata"
        );
        assert!(
            st.pending_resolve_approval(901).is_none(),
            "paused restore must scrub stale pending resolve metadata when challenged task snapshot omits challenge bond metadata"
        );
    }

    #[test]
    fn restore_task_rejects_paused_challenged_metadata_missing_forfeit_flag() {
        let mut st = StateStore::new();
        st.set_gov_param(
            7_999,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "true".into(),
        )
        .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());
        st.pending_resolve_approvals.insert(
            901,
            PendingResolveApproval {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 7,
                stored_as_canonical: false,
            },
        );

        st.restore_task(
            901,
            Some(TaskObject {
                task_id: 901,
                creator: "alice".into(),
                bounty: 100,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-1".into()),
                committed_hash: Some([1u8; 32]),
                result_hash: Some([2u8; 32]),
                reveal_salt: Some([3u8; 32]),
                committed_at_height: Some(10),
                reveal_deadline_height: Some(20),
                challenge_deadline_height: Some(30),
                challenge_window_blocks_snapshot: Some(40),
                challenged_at_height: Some(25),
                resolve_deadline_height: Some(35),
                challenge_bond: Some(500),
                challenger: Some("bob".into()),
                challenge_bond_forfeited: None,
                version: 7,
            }),
        );

        assert!(
            st.get_task(901).is_none(),
            "paused restore must fail closed when challenged task snapshot omits forfeit metadata"
        );
        assert!(
            st.pending_resolve_approval(901).is_none(),
            "paused restore must scrub stale pending resolve metadata when challenged task snapshot omits forfeit metadata"
        );
    }

    #[test]
    fn restore_task_rejects_paused_challenged_metadata_blank_challenger() {
        let mut st = StateStore::new();
        st.set_gov_param(
            7_999,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "true".into(),
        )
        .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());
        st.pending_resolve_approvals.insert(
            901,
            PendingResolveApproval {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 7,
                stored_as_canonical: false,
            },
        );

        st.restore_task(
            901,
            Some(TaskObject {
                task_id: 901,
                creator: "alice".into(),
                bounty: 100,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-1".into()),
                committed_hash: Some([1u8; 32]),
                result_hash: Some([2u8; 32]),
                reveal_salt: Some([3u8; 32]),
                committed_at_height: Some(10),
                reveal_deadline_height: Some(20),
                challenge_deadline_height: Some(30),
                challenge_window_blocks_snapshot: Some(40),
                challenged_at_height: Some(25),
                resolve_deadline_height: Some(35),
                challenge_bond: Some(500),
                challenger: Some("   ".into()),
                challenge_bond_forfeited: Some(false),
                version: 7,
            }),
        );

        assert!(
            st.get_task(901).is_none(),
            "paused restore must fail closed when challenged task snapshot omits challenger metadata"
        );
        assert!(
            st.pending_resolve_approval(901).is_none(),
            "paused restore must scrub stale pending resolve metadata when challenged task snapshot omits challenger metadata"
        );
    }

    #[test]
    fn restore_task_rejects_paused_challenged_metadata_noncanonical_challenger() {
        let mut st = StateStore::new();
        st.set_gov_param(
            7_999,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "true".into(),
        )
        .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());
        st.pending_resolve_approvals.insert(
            901,
            PendingResolveApproval {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 7,
                stored_as_canonical: false,
            },
        );

        st.restore_task(
            901,
            Some(TaskObject {
                task_id: 901,
                creator: "alice".into(),
                bounty: 100,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-1".into()),
                committed_hash: Some([1u8; 32]),
                result_hash: Some([2u8; 32]),
                reveal_salt: Some([3u8; 32]),
                committed_at_height: Some(10),
                reveal_deadline_height: Some(20),
                challenge_deadline_height: Some(30),
                challenge_window_blocks_snapshot: Some(40),
                challenged_at_height: Some(25),
                resolve_deadline_height: Some(35),
                challenge_bond: Some(500),
                challenger: Some(" bob ".into()),
                challenge_bond_forfeited: Some(false),
                version: 7,
            }),
        );

        assert!(
            st.get_task(901).is_none(),
            "paused restore must fail closed when challenged task snapshot challenger is noncanonical"
        );
        assert!(
            st.pending_resolve_approval(901).is_none(),
            "paused restore must scrub stale pending resolve metadata when challenged task snapshot challenger is noncanonical"
        );
    }

    #[test]
    fn restore_task_rejects_paused_challenged_metadata_zero_challenge_bond() {
        let mut st = StateStore::new();
        st.set_gov_param(
            7_999,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "true".into(),
        )
        .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());
        st.pending_resolve_approvals.insert(
            902,
            PendingResolveApproval {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 7,
                stored_as_canonical: false,
            },
        );

        st.restore_task(
            902,
            Some(TaskObject {
                task_id: 902,
                creator: "alice".into(),
                bounty: 100,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-1".into()),
                committed_hash: Some([1u8; 32]),
                result_hash: Some([2u8; 32]),
                reveal_salt: Some([3u8; 32]),
                committed_at_height: Some(10),
                reveal_deadline_height: Some(20),
                challenge_deadline_height: Some(30),
                challenge_window_blocks_snapshot: Some(40),
                challenged_at_height: Some(25),
                resolve_deadline_height: Some(35),
                challenge_bond: Some(0),
                challenger: Some("bob".into()),
                challenge_bond_forfeited: Some(false),
                version: 7,
            }),
        );

        assert!(
            st.get_task(902).is_none(),
            "paused restore must fail closed when challenged task snapshot zeroes challenge bond metadata"
        );
        assert!(
            st.pending_resolve_approval(902).is_none(),
            "paused restore must scrub stale pending resolve metadata when challenged task snapshot zeroes challenge bond metadata"
        );
    }

    #[test]
    fn restore_task_scrubs_stale_pending_resolve_metadata_on_forfeit_decision_mismatch() {
        let mut st = StateStore::new();
        st.pending_resolve_approvals.insert(
            901,
            PendingResolveApproval {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 7,
                stored_as_canonical: false,
            },
        );

        st.restore_task(
            901,
            Some(TaskObject {
                task_id: 901,
                creator: "alice".into(),
                bounty: 100,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-1".into()),
                committed_hash: Some([1u8; 32]),
                result_hash: Some([2u8; 32]),
                reveal_salt: Some([3u8; 32]),
                committed_at_height: Some(10),
                reveal_deadline_height: Some(20),
                challenge_deadline_height: Some(30),
                challenge_window_blocks_snapshot: Some(40),
                challenged_at_height: Some(25),
                resolve_deadline_height: Some(35),
                challenge_bond: Some(500),
                challenger: Some("bob".into()),
                challenge_bond_forfeited: Some(true),
                version: 7,
            }),
        );

        assert!(
            st.pending_resolve_approval(901).is_none(),
            "restore must scrub stale pending resolve metadata when challenged task forfeit decision disagrees with staged slash decision"
        );
        assert!(
            st.get_task(901).is_some(),
            "task restore should still succeed while stale pending resolve metadata is dropped"
        );
    }

    #[test]
    fn restore_task_rejects_snapshot_task_id_mismatch_and_scrubs_pending_metadata() {
        let mut st = StateStore::new();
        st.pending_resolve_approvals.insert(
            905,
            PendingResolveApproval {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 7,
                stored_as_canonical: false,
            },
        );

        st.restore_task(
            905,
            Some(TaskObject {
                task_id: 906,
                creator: "alice".into(),
                bounty: 100,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-1".into()),
                committed_hash: Some([1u8; 32]),
                result_hash: Some([2u8; 32]),
                reveal_salt: Some([3u8; 32]),
                committed_at_height: Some(10),
                reveal_deadline_height: Some(20),
                challenge_deadline_height: Some(30),
                challenge_window_blocks_snapshot: Some(40),
                challenged_at_height: Some(25),
                resolve_deadline_height: Some(35),
                challenge_bond: Some(500),
                challenger: Some("bob".into()),
                challenge_bond_forfeited: Some(false),
                version: 7,
            }),
        );

        assert!(
            st.get_task(905).is_none(),
            "restore must fail closed when task snapshot id disagrees with restore target"
        );
        assert!(
            st.pending_resolve_approval(905).is_none(),
            "restore must scrub stale pending resolve metadata when snapshot id mismatches target"
        );
    }

    #[test]
    fn restore_task_rejects_zero_task_version_and_scrubs_pending_metadata() {
        let mut st = StateStore::new();
        st.pending_resolve_approvals.insert(
            907,
            PendingResolveApproval {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 7,
                stored_as_canonical: false,
            },
        );

        st.restore_task(
            907,
            Some(TaskObject {
                task_id: 907,
                creator: "alice".into(),
                bounty: 100,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-1".into()),
                committed_hash: Some([1u8; 32]),
                result_hash: Some([2u8; 32]),
                reveal_salt: Some([3u8; 32]),
                committed_at_height: Some(10),
                reveal_deadline_height: Some(20),
                challenge_deadline_height: Some(30),
                challenge_window_blocks_snapshot: Some(40),
                challenged_at_height: Some(25),
                resolve_deadline_height: Some(35),
                challenge_bond: Some(500),
                challenger: Some("bob".into()),
                challenge_bond_forfeited: Some(false),
                version: 0,
            }),
        );

        assert!(
            st.get_task(907).is_none(),
            "restore must fail closed when task snapshot version is zero"
        );
        assert!(
            st.pending_resolve_approval(907).is_none(),
            "restore must scrub stale pending resolve metadata when snapshot version is zero"
        );
    }

    #[test]
    fn restore_task_scrubs_noncanonical_pending_resolve_metadata_during_replay() {
        let mut st = StateStore::new();
        st.pending_resolve_approvals.insert(
            908,
            PendingResolveApproval {
                slash_worker: true,
                confirmations: 2,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 7,
                stored_as_canonical: false,
            },
        );

        st.restore_task(
            908,
            Some(TaskObject {
                task_id: 908,
                creator: "alice".into(),
                bounty: 100,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-1".into()),
                committed_hash: Some([1u8; 32]),
                result_hash: Some([2u8; 32]),
                reveal_salt: Some([3u8; 32]),
                committed_at_height: Some(10),
                reveal_deadline_height: Some(20),
                challenge_deadline_height: Some(30),
                challenge_window_blocks_snapshot: Some(40),
                challenged_at_height: Some(25),
                resolve_deadline_height: Some(35),
                challenge_bond: Some(500),
                challenger: Some("bob".into()),
                challenge_bond_forfeited: Some(false),
                version: 7,
            }),
        );

        assert!(
            st.get_task(908).is_some(),
            "canonical challenged task snapshot should still restore while stale pending metadata is dropped"
        );
        assert!(
            st.pending_resolve_approval(908).is_none(),
            "restore replay must fail closed by scrubbing noncanonical pending resolve metadata"
        );
    }

    #[test]
    fn restore_task_scrubs_pending_resolve_metadata_when_authority_set_mismatches_effective_governance(
    ) {
        let mut st = StateStore::new();
        st.set_gov_param(
            51,
            51,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("resolve authority should configure cleanly");
        st.pending_resolve_approvals.insert(
            909,
            PendingResolveApproval {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 7,
                stored_as_canonical: false,
            },
        );

        st.restore_task(
            909,
            Some(TaskObject {
                task_id: 909,
                creator: "alice".into(),
                bounty: 100,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-1".into()),
                committed_hash: Some([1u8; 32]),
                result_hash: Some([2u8; 32]),
                reveal_salt: Some([3u8; 32]),
                committed_at_height: Some(10),
                reveal_deadline_height: Some(20),
                challenge_deadline_height: Some(30),
                challenge_window_blocks_snapshot: Some(40),
                challenged_at_height: Some(25),
                resolve_deadline_height: Some(35),
                challenge_bond: Some(500),
                challenger: Some("bob".into()),
                challenge_bond_forfeited: Some(false),
                version: 7,
            }),
        );

        assert!(
            st.get_task(909).is_some(),
            "canonical challenged task snapshot should still restore while authority-drifted pending metadata is dropped"
        );
        assert!(
            st.pending_resolve_approval(909).is_none(),
            "restore replay must fail closed by scrubbing pending resolve metadata that no longer matches effective governance authority"
        );
    }

    #[test]
    fn restore_pending_resolve_approval_rejects_noncanonical_snapshot_metadata() {
        let mut st = StateStore::new();
        st.put_task_new(TaskObject {
            task_id: 901,
            creator: "alice".into(),
            bounty: 100,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-1".into()),
            committed_hash: Some([1u8; 32]),
            result_hash: Some([2u8; 32]),
            reveal_salt: Some([3u8; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(40),
            challenged_at_height: Some(25),
            resolve_deadline_height: Some(35),
            challenge_bond: Some(500),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(false),
            version: 7,
        })
        .expect("challenged task should be restorable");

        st.restore_pending_resolve_approval(
            901,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "Authority-B".into(),
                authority_set: "authority-b,authority-a".into(),
                task_version: 7,
            }),
        );

        assert!(
            st.pending_resolve_approval(901).is_none(),
            "restore must fail closed for noncanonical pending resolve snapshot metadata"
        );
    }

    #[test]
    fn restore_pending_resolve_approval_rejects_incomplete_task_boundary_metadata() {
        let mut st = StateStore::new();
        st.put_task_new(TaskObject {
            task_id: 902,
            creator: "alice".into(),
            bounty: 100,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-1".into()),
            committed_hash: Some([1u8; 32]),
            result_hash: Some([2u8; 32]),
            reveal_salt: Some([3u8; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(40),
            challenged_at_height: Some(25),
            resolve_deadline_height: Some(35),
            challenge_bond: Some(500),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 7,
        })
        .expect("challenged task should still insert for boundary regression coverage");

        st.restore_pending_resolve_approval(
            902,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 7,
            }),
        );

        assert!(
            st.pending_resolve_approval(902).is_none(),
            "restore must fail closed when challenged task boundary metadata is incomplete"
        );
    }

    #[test]
    fn restore_pending_resolve_approval_rejects_zeroed_task_boundary_metadata() {
        let mut st = StateStore::new();
        st.put_task_new(TaskObject {
            task_id: 902,
            creator: "alice".into(),
            bounty: 100,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-1".into()),
            committed_hash: Some([1u8; 32]),
            result_hash: Some([2u8; 32]),
            reveal_salt: Some([3u8; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(0),
            challenged_at_height: Some(25),
            resolve_deadline_height: Some(35),
            challenge_bond: Some(500),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(false),
            version: 7,
        })
        .expect("challenged task should still insert for zeroed boundary regression coverage");

        st.restore_pending_resolve_approval(
            902,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 7,
            }),
        );

        assert!(
            st.pending_resolve_approval(902).is_none(),
            "restore must fail closed when challenged task snapshot uses zeroed boundary metadata"
        );
    }

    #[test]
    fn restore_pending_resolve_approval_paused_replay_scrubs_stale_snapshot_on_incomplete_task_metadata(
    ) {
        let mut st = StateStore::new();
        st.set_gov_param(
            7_999,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "true".into(),
        )
        .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        st.pending_resolve_approvals.insert(
            903,
            PendingResolveApproval {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 7,
                stored_as_canonical: false,
            },
        );

        st.put_task_new(TaskObject {
            task_id: 903,
            creator: "alice".into(),
            bounty: 100,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-1".into()),
            committed_hash: Some([1u8; 32]),
            result_hash: Some([2u8; 32]),
            reveal_salt: Some([3u8; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(40),
            challenged_at_height: Some(25),
            resolve_deadline_height: Some(35),
            challenge_bond: Some(500),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 7,
        })
        .expect("challenged task should still insert for paused replay regression coverage");

        st.restore_pending_resolve_approval(
            903,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 7,
            }),
        );

        assert!(
            st.pending_resolve_approval(903).is_none(),
            "paused restore replay must scrub stale pending resolve metadata when challenged task snapshot omits forfeit metadata"
        );
    }

    #[test]
    fn restore_pending_resolve_approval_rejects_forfeit_decision_metadata_mismatch() {
        let mut st = StateStore::new();
        st.put_task_new(TaskObject {
            task_id: 904,
            creator: "alice".into(),
            bounty: 100,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-1".into()),
            committed_hash: Some([1u8; 32]),
            result_hash: Some([2u8; 32]),
            reveal_salt: Some([3u8; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(40),
            challenged_at_height: Some(25),
            resolve_deadline_height: Some(35),
            challenge_bond: Some(500),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(true),
            version: 7,
        })
        .expect("challenged task should insert for metadata mismatch coverage");

        st.restore_pending_resolve_approval(
            904,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 7,
            }),
        );

        assert!(
            st.pending_resolve_approval(904).is_none(),
            "restore must fail closed when challenge forfeit metadata disagrees with staged slash decision"
        );
    }

    #[test]
    fn state_root_changes_when_task_security_fields_change() {
        let mut st = StateStore::new();
        let task = TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 100,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-1".into()),
            committed_hash: Some([1u8; 32]),
            result_hash: Some([2u8; 32]),
            reveal_salt: Some([3u8; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(40),
            challenged_at_height: Some(25),
            resolve_deadline_height: Some(35),
            challenge_bond: Some(500),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(false),
            version: 1,
        };

        st.put_task_new(task.clone()).unwrap();
        let root_before = st.state_root();

        let mut changed = task;
        changed.challenge_bond_forfeited = Some(true);
        let current_ref = st.get_ref(42).unwrap();
        st.update_task(current_ref, changed).unwrap();
        let root_after = st.state_root();

        assert_ne!(root_before, root_after);
    }

    #[test]
    fn state_root_changes_when_pending_resolve_first_approver_changes() {
        let mut st_a = StateStore::new();
        st_a.stage_or_confirm_resolve_approval(
            500,
            1,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .unwrap();

        let mut st_b = StateStore::new();
        st_b.stage_or_confirm_resolve_approval(
            500,
            1,
            true,
            "authority-b",
            "authority-a,authority-b",
        )
        .unwrap();

        assert_ne!(
            st_a.state_root(),
            st_b.state_root(),
            "pending resolve first approver must contribute to state root"
        );
    }

    #[test]
    fn state_root_changes_when_pending_resolve_confirmation_count_changes() {
        let mut st_a = StateStore::new();
        st_a.stage_or_confirm_resolve_approval(
            501,
            1,
            true,
            "authority-a",
            "authority-a,authority-b,authority-c",
        )
        .unwrap();

        let mut st_b = StateStore::new();
        st_b.stage_or_confirm_resolve_approval(
            501,
            1,
            true,
            "authority-a",
            "authority-a,authority-b,authority-c",
        )
        .unwrap();
        st_b.stage_or_confirm_resolve_approval(
            501,
            1,
            true,
            "authority-b",
            "authority-a,authority-b,authority-c",
        )
        .unwrap();

        assert_ne!(
            st_a.state_root(),
            st_b.state_root(),
            "pending resolve confirmation count must contribute to state root"
        );
    }

    #[test]
    fn state_root_changes_when_pending_resolve_task_version_changes() {
        let mut st_a = StateStore::new();
        st_a.stage_or_confirm_resolve_approval(
            501,
            1,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .unwrap();

        let mut st_b = StateStore::new();
        st_b.stage_or_confirm_resolve_approval(
            501,
            2,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .unwrap();

        assert_ne!(
            st_a.state_root(),
            st_b.state_root(),
            "pending resolve task version snapshot must contribute to state root"
        );
    }

    #[test]
    fn state_root_changes_when_pending_resolve_authority_set_changes() {
        let mut st_a = StateStore::new();
        st_a.stage_or_confirm_resolve_approval(
            501,
            1,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .unwrap();

        let mut st_b = StateStore::new();
        st_b.stage_or_confirm_resolve_approval(
            501,
            1,
            true,
            "authority-a",
            "authority-a,authority-b,authority-c",
        )
        .unwrap();

        assert_ne!(
            st_a.state_root(),
            st_b.state_root(),
            "pending resolve authority set must contribute to state root"
        );
    }

    #[test]
    fn state_root_ignores_case_and_order_only_drift_in_live_pending_resolve_authority_set() {
        let mut st_a = StateStore::new();
        st_a.stage_or_confirm_resolve_approval(
            501,
            1,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .unwrap();

        let mut st_b = StateStore::new();
        st_b.stage_or_confirm_resolve_approval(
            501,
            1,
            true,
            "authority-a",
            "Authority-B,Authority-A",
        )
        .unwrap();

        assert_eq!(
            st_a.state_root(),
            st_b.state_root(),
            "live pending resolve approvals should hash the effective authority-set membership, not case/order-only surface drift"
        );
        assert_eq!(
            st_b.pending_resolve_approval_snapshot(501)
                .expect("staged approval snapshot")
                .authority_set,
            "authority-a,authority-b",
            "live staged authority-set evidence should normalize to the canonical membership surface"
        );
        assert_eq!(
            st_b.pending_resolve_first_approver(501).as_deref(),
            Some("authority-a"),
            "canonicalizing authority membership must not erase first-approver audit spelling"
        );
    }

    #[test]
    fn state_root_changes_when_embedded_gov_param_key_id_changes() {
        let mut st_a = StateStore::new();
        st_a.objects.insert(
            7001,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: 7001,
                    key: "challenge_min_bond".into(),
                    value: "5000".into(),
                    version: 1,
                }),
            },
        );

        let mut st_b = StateStore::new();
        st_b.objects.insert(
            7001,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: 7002,
                    key: "challenge_min_bond".into(),
                    value: "5000".into(),
                    version: 1,
                }),
            },
        );

        assert_ne!(
            st_a.state_root(),
            st_b.state_root(),
            "embedded governance key_id must contribute to state_root so corrupt/mismatched governance snapshots cannot hash identically"
        );
    }

    #[test]
    fn state_root_changes_when_gov_param_key_index_mapping_changes() {
        let mut st_a = StateStore::new();
        st_a.objects.insert(
            7001,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: 7001,
                    key: "monetary_base_issuance_per_tick".into(),
                    value: "7".into(),
                    version: 1,
                }),
            },
        );
        st_a.gov_param_key_index
            .insert("monetary_base_issuance_per_tick".into(), 7001);

        let mut st_b = StateStore::new();
        st_b.objects.insert(
            7001,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: 7001,
                    key: "monetary_base_issuance_per_tick".into(),
                    value: "7".into(),
                    version: 1,
                }),
            },
        );
        st_b.gov_param_key_index
            .insert("monetary_base_issuance_per_tick".into(), 7999);

        assert_ne!(
            st_a.state_root(),
            st_b.state_root(),
            "governance key-index mapping must contribute to state_root so restore/rollback snapshots with different effective monetary routing cannot hash identically"
        );
    }

    #[test]
    fn state_root_changes_when_gov_param_key_index_key_changes() {
        let mut st_a = StateStore::new();
        st_a.objects.insert(
            7001,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: 7001,
                    key: "monetary_base_issuance_per_tick".into(),
                    value: "7".into(),
                    version: 1,
                }),
            },
        );
        st_a.gov_param_key_index
            .insert("monetary_base_issuance_per_tick".into(), 7001);

        let mut st_b = StateStore::new();
        st_b.objects.insert(
            7001,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: 7001,
                    key: "monetary_base_issuance_per_tick".into(),
                    value: "7".into(),
                    version: 1,
                }),
            },
        );
        st_b.gov_param_key_index
            .insert("monetary_base_burn_per_tick".into(), 7001);

        assert_ne!(
            st_a.state_root(),
            st_b.state_root(),
            "governance key-index key strings must contribute to state_root so mismatched restore/rollback routing aliases cannot hash identically even when key_id stays constant"
        );
    }

    #[test]
    fn wal_checkpoint_verification_picks_latest_valid() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2,
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
            .unwrap()
            .expect("checkpoint");
        assert_eq!(got.height, 2);
    }

    #[test]
    fn wal_checkpoint_verification_falls_back_on_chain_break() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some("wrong-prev".into()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: e2.content_hash_hex(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
            .unwrap()
            .expect("checkpoint");
        assert_eq!(got.height, 1);
    }

    #[test]
    fn wal_checkpoint_verification_rejects_checkpointed_chain_without_genesis_base() {
        let e1 = WalMeta {
            height: 10,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let checkpoints = vec![CheckpointMeta {
            height: 10,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: e1.content_hash_hex(),
        }];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1]).unwrap();
        assert!(
            got.is_none(),
            "checkpoint-only recovery must fail closed when WAL metadata does not start at genesis height"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_forged_genesis_prev_hash() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: Some("forged-prev".into()),
        };
        let checkpoints = vec![CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: e1.content_hash_hex(),
        }];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1]).unwrap();
        assert!(
            got.is_none(),
            "genesis WAL metadata with a forged prev hash must fail closed instead of claiming checkpoint recovery"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_incomplete_genesis_metadata() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let checkpoints = vec![CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: e1.content_hash_hex(),
        }];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1]).unwrap();
        assert!(
            got.is_none(),
            "checkpoint-only recovery must fail closed when WAL metadata omits proposal identity"
        );
    }

    #[test]
    fn wal_checkpoint_verification_falls_back_on_non_monotonic_height() {
        let e1 = WalMeta {
            height: 10,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            // Repeated height must terminate verification.
            height: 10,
            round: 1,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 10,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 10,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: e2.content_hash_hex(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2]).unwrap();
        assert!(
            got.is_none(),
            "non-genesis WAL bases must not be accepted during checkpoint-only recovery"
        );
    }

    #[test]
    fn wal_checkpoint_verification_falls_back_when_height_regresses() {
        let e1 = WalMeta {
            height: 10,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 9,
            round: 1,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 10,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 9,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: e2.content_hash_hex(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2]).unwrap();
        assert!(
            got.is_none(),
            "regressing non-genesis WAL chains must fail closed instead of falling back to a checkpoint"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_replayed_duplicate_height_tail() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let replayed_e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "p2-replay".into(),
            committed: true,
            state_root_hex: "r2-replay".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2-replay".into(),
                wal_entry_hash_hex: replayed_e2.content_hash_hex(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2, replayed_e2]).unwrap();
        assert_eq!(
            got.map(|cp| cp.height),
            Some(1),
            "replayed same-height checkpoint tuples must fail closed back to the last unambiguous checkpoint"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_identical_duplicate_height_tail() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let duplicated_e2 = e2.clone();

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2,
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2, duplicated_e2])
            .unwrap()
            .expect("checkpoint");
        assert_eq!(got.height, 2);
        assert_eq!(got.state_root_hex, "r2");
    }

    #[test]
    fn wal_checkpoint_verification_rejects_uncommitted_duplicate_height_tail() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let replayed_uncommitted_e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "p2-replay".into(),
            committed: false,
            state_root_hex: "r2-replay".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2-replay".into(),
                wal_entry_hash_hex: replayed_uncommitted_e2.content_hash_hex(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2, replayed_uncommitted_e2])
            .unwrap();
        assert_eq!(
            got.map(|cp| cp.height),
            Some(1),
            "uncommitted replay checkpoint tuples must fail closed back to the last unambiguous checkpoint"
        );
    }

    #[test]
    fn wal_checkpoint_verification_is_height_ordered_even_if_checkpoint_list_is_not() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1),
        };
        let h2 = e2.content_hash_hex();

        // Intentionally unsorted input: height 2 checkpoint appears first.
        let checkpoints = vec![
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2,
            },
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: e1.content_hash_hex(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
            .unwrap()
            .expect("checkpoint");
        assert_eq!(got.height, 2);
        assert_eq!(got.state_root_hex, "r2");
    }

    #[test]
    fn wal_checkpoint_verification_rejects_non_hex_checkpoint_hash_surface() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };

        let checkpoints = vec![CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: "not-hex".into(),
        }];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1]).unwrap();
        assert!(
            got.is_none(),
            "checkpoint recovery must fail closed when checkpoint wal-entry evidence is not a canonical hex digest"
        );
    }

    #[test]
    fn wal_checkpoint_verification_ignores_stale_duplicate_checkpoint_at_same_height() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1),
        };
        let h2 = e2.content_hash_hex();

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: e1.content_hash_hex(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: " r2".into(),
                wal_entry_hash_hex: h2,
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2]).unwrap();
        assert_eq!(
            got.map(|cp| cp.height),
            Some(1),
            "whitespace-padded checkpoint proof metadata is not canonical audit material and must fail closed to the last clean checkpoint"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_internal_whitespace_proof_metadata() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1),
        };
        let h2 = e2.content_hash_hex();

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: e1.content_hash_hex(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: format!("{} {}", &h2[..1], &h2[1..]),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2]).unwrap();
        assert_eq!(
            got.map(|cp| cp.height),
            Some(1),
            "internally whitespace-split checkpoint proof metadata is not canonical audit material and must fail closed to the last clean checkpoint"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_non_ascii_proof_metadata() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: e1.content_hash_hex(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: format!("{}é", e2.content_hash_hex()),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2]).unwrap();
        assert_eq!(
            got.map(|cp| cp.height),
            Some(1),
            "non-ASCII checkpoint proof metadata is not canonical audit material and must fail closed to the last clean checkpoint"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_zero_width_checkpoint_proof_metadata() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1),
        };
        let h2 = e2.content_hash_hex();

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: e1.content_hash_hex(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2\u{200B}".into(),
                wal_entry_hash_hex: h2,
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2]).unwrap();
        assert_eq!(
            got.map(|cp| cp.height),
            Some(1),
            "zero-width checkpoint proof metadata is not canonical audit material and must fail closed to the last clean checkpoint"
        );
    }

    #[test]
    fn wal_checkpoint_verification_accepts_identical_duplicate_checkpoint_at_same_height() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1),
        };
        let h2 = e2.content_hash_hex();

        let checkpoints = vec![
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2.clone(),
            },
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: e1.content_hash_hex(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2.clone(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
            .unwrap()
            .expect("checkpoint");
        assert_eq!(got.height, 2);
        assert_eq!(got.state_root_hex, "r2");
        assert_eq!(got.wal_entry_hash_hex, h2);
    }

    #[test]
    fn wal_checkpoint_verification_falls_back_on_gap_skipping_committed_tail() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "p3".into(),
            committed: true,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1.clone(),
            },
            CheckpointMeta {
                height: 3,
                state_root_hex: "r3".into(),
                wal_entry_hash_hex: e3.content_hash_hex(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e3])
            .unwrap()
            .expect("checkpoint");
        assert_eq!(got.height, 1);
        assert_eq!(got.state_root_hex, "r1");
        assert_eq!(got.wal_entry_hash_hex, h1);
    }

    #[test]
    fn wal_checkpoint_verification_rejects_conflicting_state_root_for_same_wal_hash() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2.clone(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2-forged".into(),
                wal_entry_hash_hex: h2,
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
            .unwrap()
            .expect("checkpoint");
        assert_eq!(got.height, 1);
        assert_eq!(got.state_root_hex, "r1");
    }

    #[test]
    fn wal_checkpoint_verification_rejects_metadata_only_tail_after_checkpoint() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "p3".into(),
            committed: false,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2,
            },
            CheckpointMeta {
                height: 3,
                state_root_hex: "r3".into(),
                wal_entry_hash_hex: e3.content_hash_hex(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2, e3])
            .unwrap()
            .expect("checkpoint");
        assert_eq!(got.height, 2);
        assert_eq!(got.state_root_hex, "r2");
    }

    #[test]
    fn wal_checkpoint_verification_rejects_incomplete_checkpoint_metadata_at_latest_valid_height() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: "".into(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2]).unwrap();
        assert!(
            got.is_none(),
            "incomplete checkpoint metadata at the latest validated WAL height must fail closed instead of rewinding to an older checkpoint"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_incomplete_checkpoint_state_root_metadata() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "".into(),
                wal_entry_hash_hex: e2.content_hash_hex(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2]).unwrap();
        assert!(
            got.is_none(),
            "incomplete checkpoint metadata at the latest validated WAL height must fail closed when state root identity is missing"
        );
    }

    #[test]
    fn wal_checkpoint_verification_does_not_accept_future_checkpoint_without_matching_wal_height() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: e2.content_hash_hex(),
            },
            CheckpointMeta {
                height: 3,
                state_root_hex: "r3".into(),
                wal_entry_hash_hex: "future-wal-hash".into(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
            .unwrap()
            .expect("checkpoint");
        assert_eq!(got.height, 2);
        assert_eq!(got.state_root_hex, "r2");
    }

    #[test]
    fn wal_checkpoint_verification_rejects_unsorted_conflicting_checkpoint_even_with_future_noise()
    {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();

        let checkpoints = vec![
            CheckpointMeta {
                height: 4,
                state_root_hex: "r4".into(),
                wal_entry_hash_hex: "future-wal-hash".into(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "stale-r2".into(),
                wal_entry_hash_hex: "stale-h2".into(),
            },
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2,
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2]).unwrap();
        assert_eq!(
            got.map(|cp| cp.height),
            Some(1),
            "same-height stale checkpoint tuples must fail closed back to the last unambiguous checkpoint even when future checkpoints are ignored"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_same_height_state_root_claimed_by_different_wal_hash() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: e2.content_hash_hex(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: "forged-h2".into(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2]).unwrap();
        assert_eq!(
            got.map(|cp| cp.height),
            Some(1),
            "conflicting checkpoint metadata for the same height/state root must fail closed back to the last unambiguous checkpoint"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_blank_checkpoint_proof_metadata() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();

        for incomplete_checkpoint in [
            CheckpointMeta {
                height: 2,
                state_root_hex: " ".into(),
                wal_entry_hash_hex: h2.clone(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: "\t".into(),
            },
        ] {
            let checkpoints = vec![
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1.clone(),
                },
                incomplete_checkpoint,
            ];

            let got =
                verify_wal_and_find_checkpoint(&checkpoints, &[e1.clone(), e2.clone()]).unwrap();
            assert_eq!(
                got.map(|cp| cp.height),
                Some(1),
                "blank checkpoint proof metadata must fail closed back to the last complete checkpoint"
            );
        }
    }

    #[test]
    fn wal_checkpoint_verification_rejects_blank_wal_proof_metadata() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let valid_e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        for incomplete_e2 in [
            WalMeta {
                proposal_hash: " ".into(),
                ..valid_e2.clone()
            },
            WalMeta {
                state_root_hex: "\t".into(),
                ..valid_e2.clone()
            },
            WalMeta {
                prev_hash_hex: Some(" ".into()),
                ..valid_e2.clone()
            },
        ] {
            let checkpoints = vec![
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1.clone(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: incomplete_e2.state_root_hex.clone(),
                    wal_entry_hash_hex: incomplete_e2.content_hash_hex(),
                },
            ];

            let got =
                verify_wal_and_find_checkpoint(&checkpoints, &[e1.clone(), incomplete_e2]).unwrap();
            assert_eq!(
                got.map(|cp| cp.height),
                Some(1),
                "blank WAL proof metadata must fail closed back to the last complete checkpoint"
            );
        }
    }

    #[test]
    fn wal_checkpoint_verification_rejects_gap_skipping_tail() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "p3".into(),
            committed: true,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 3,
                state_root_hex: "r3".into(),
                wal_entry_hash_hex: e3.content_hash_hex(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e3])
            .unwrap()
            .expect("checkpoint");
        assert_eq!(got.height, 1);
        assert_eq!(got.state_root_hex, "r1");
    }

    #[test]
    fn wal_checkpoint_verification_stops_before_uncommitted_tail() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: false,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: e2.content_hash_hex(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
            .unwrap()
            .expect("checkpoint");
        assert_eq!(got.height, 1);
        assert_eq!(got.state_root_hex, "r1");
    }

    #[test]
    fn wal_checkpoint_verification_rejects_uncommitted_genesis_entry_even_with_checkpoint() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: false,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };

        let checkpoints = vec![CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: e1.content_hash_hex(),
        }];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1]).unwrap();
        assert!(
            got.is_none(),
            "an uncommitted genesis WAL entry must not be accepted as a recoverable checkpoint"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_incomplete_wal_metadata_in_restore_chain() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let incomplete_e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: incomplete_e2.content_hash_hex(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, incomplete_e2]).unwrap();
        assert!(
            got.is_none(),
            "incomplete WAL metadata must fail closed instead of falling back to an older checkpoint"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_chain_that_starts_above_genesis_height() {
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: None,
        };

        let checkpoints = vec![CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        }];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e2]).unwrap();
        assert!(
            got.is_none(),
            "checkpointed WAL that starts above genesis must not be treated as recoverable application state"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_missing_prev_hash_metadata_mid_chain() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let incomplete_e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some("   ".into()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: e1.content_hash_hex(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: incomplete_e2.content_hash_hex(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, incomplete_e2]).unwrap();
        assert!(
            got.is_none(),
            "missing prev-hash metadata mid-chain must fail closed instead of falling back to an older checkpoint"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_whitespace_only_checkpoint_metadata() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "   ".into(),
                wal_entry_hash_hex: e2.content_hash_hex(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2]).unwrap();
        assert!(
            got.is_none(),
            "whitespace-only checkpoint metadata must fail closed instead of falling back to an older checkpoint"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_whitespace_only_checkpoint_wal_hash_metadata() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: "   ".into(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2]).unwrap();
        assert!(
            got.is_none(),
            "whitespace-only checkpoint WAL hash metadata must fail closed instead of falling back to an older checkpoint"
        );
    }

    #[test]
    fn wal_checkpoint_verification_rejects_later_committed_checkpoint_after_uncommitted_genesis() {
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            committed: false,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let e1_hash = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(e1_hash),
        };

        let checkpoints = vec![
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: e1.content_hash_hex(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: e2.content_hash_hex(),
            },
        ];

        let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2]).unwrap();
        assert!(
            got.is_none(),
            "an uncommitted genesis WAL entry must fail closed instead of allowing later committed checkpoint metadata to claim recoverable application state"
        );
    }

    #[test]
    fn policy_tick_triggers_on_interval_and_updates_monetary_state() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            9_001,
            "monetary_policy_tick_interval_blocks".into(),
            "3".into(),
        )
        .expect("set interval");
        st.set_gov_param_unchecked(
            9_002,
            "monetary_policy_tick_cooldown_blocks".into(),
            "3".into(),
        )
        .expect("set cooldown");
        st.set_gov_param_unchecked(9_003, "monetary_base_issuance_per_tick".into(), "15".into())
            .expect("set issuance");
        st.set_gov_param_unchecked(9_004, "monetary_base_burn_per_tick".into(), "4".into())
            .expect("set burn");

        assert!(st.policy_tick(2).is_none());
        let e1 = st.policy_tick(3).expect("tick at h=3");
        assert_eq!(e1.net_delta, 11);
        assert_eq!(e1.tick_count, 1);
        assert_eq!(e1.block_height, 3);
        assert_eq!(e1.cooldown_blocks, 3);
        assert_eq!(e1.interval_param_version, 1);
        assert_eq!(e1.cooldown_param_version, 1);
        assert!(
            st.policy_tick(3).is_none(),
            "same height must be idempotent"
        );

        let e2 = st.policy_tick(6).expect("tick at h=6");
        assert_eq!(e2.tick_count, 2);
        assert_eq!(e2.total_minted, 30);
        assert_eq!(e2.total_burned, 8);
        assert_eq!(e2.net_issuance, 22);
    }

    #[test]
    fn governance_param_schema_rejects_invalid_monetary_policy_bounds() {
        let mut st = StateStore::new();
        let err_interval = st
            .set_gov_param_unchecked(
                9_010,
                "monetary_policy_tick_interval_blocks".into(),
                "0".into(),
            )
            .unwrap_err();
        assert!(err_interval.contains("out of range"));

        let err_cooldown = st
            .set_gov_param_unchecked(
                9_011,
                "monetary_policy_tick_cooldown_blocks".into(),
                "0".into(),
            )
            .unwrap_err();
        assert!(err_cooldown.contains("out of range"));

        let err_issuance = st
            .set_gov_param_unchecked(
                9_012,
                "monetary_base_issuance_per_tick".into(),
                "1000000000001".into(),
            )
            .unwrap_err();
        assert!(err_issuance.contains("out of range"));

        let err_burn = st
            .set_gov_param_unchecked(9_013, "monetary_base_burn_per_tick".into(), "-1".into())
            .unwrap_err();
        assert!(err_burn.contains("expected u64"));
    }

    #[test]
    fn policy_tick_fail_closed_when_monetary_params_incomplete() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            9_020,
            "monetary_policy_tick_interval_blocks".into(),
            "2".into(),
        )
        .unwrap();
        st.set_gov_param_unchecked(9_021, "monetary_base_issuance_per_tick".into(), "1".into())
            .unwrap();
        st.set_gov_param_unchecked(9_022, "monetary_base_burn_per_tick".into(), "0".into())
            .unwrap();

        assert!(!st.should_trigger_policy_tick(2));
        assert!(st.policy_tick(2).is_none());
        assert_eq!(st.monetary_state().tick_count, 0);
    }

    #[test]
    fn policy_tick_cooldown_throttles_repeated_schedule_points() {
        let mut st = StateStore::new();
        st.set_gov_param_unchecked(
            9_030,
            "monetary_policy_tick_interval_blocks".into(),
            "2".into(),
        )
        .unwrap();
        st.set_gov_param_unchecked(
            9_031,
            "monetary_policy_tick_cooldown_blocks".into(),
            "4".into(),
        )
        .unwrap();
        st.set_gov_param_unchecked(9_032, "monetary_base_issuance_per_tick".into(), "5".into())
            .unwrap();
        st.set_gov_param_unchecked(9_033, "monetary_base_burn_per_tick".into(), "1".into())
            .unwrap();

        assert!(st.policy_tick(2).is_some());
        assert!(st.policy_tick(4).is_none(), "cooldown should block h=4");
        assert!(st.policy_tick(6).is_some(), "cooldown should allow h=6");
    }
}
