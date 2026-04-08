use trnm_types::{GovParamKey, GovParamObject, ObjectRef, EMERGENCY_PAUSE_KEY_ID};

use crate::{
    validate_gov_param_registry_binding, ObjectValue, StateStore, VersionedObject,
    NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingGovParamUpdate {
    pub key_id: u64,
    pub key: String,
    pub value: String,
    pub activate_at_height: u64,
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
pub(crate) const GOV_ALLOWED_KEYS: &[&str] = &[
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
pub(crate) const GOV_SENSITIVE_KEYS: &[&str] = &[
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
];
pub(crate) const GOV_KEYS_WITH_EXPLICIT_VALIDATORS: &[&str] = &[
    "max_block_ms",
    "max_parallel_workers",
    "challenge_window_blocks",
    "min_worker_stake",
    "challenge_min_bond",
    "challenge_success_bounty",
    "challenge_min_bond_bounty_bps",
    "challenge_min_bond_worker_stake_bps",
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
pub(crate) const GOV_SCHEMA_INVALID_SAMPLES: &[(&str, &str)] = &[
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
pub(crate) const DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER: &str = "governance.resolve_authority";
pub(crate) const RESERVED_SYSTEM_AUTHORITY: &str = "system";
pub(crate) const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
pub(crate) const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";
pub(crate) const WORKER_SLASH_TREASURY_ACCOUNT: &str = "treasury.worker_slashes";

pub(crate) fn is_sensitive_gov_param(key: &str) -> bool {
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

fn has_explicit_gov_param_validator(key: &str) -> bool {
    GOV_KEYS_WITH_EXPLICIT_VALIDATORS.contains(&key)
}

fn governance_pinned_key_id(key: &str) -> Option<u64> {
    GovParamKey::from_str(key).and_then(GovParamKey::canonical_key_id)
}

fn validate_governance_key_id(key: &str, key_id: u64) -> Result<(), String> {
    if let Some(typed_key) = GovParamKey::from_str(key) {
        return typed_key.validate_key_id(key_id);
    }
    Ok(())
}

fn validate_governance_validator_registry_shape() -> Result<(), String> {
    let allowed_unique: std::collections::BTreeSet<&str> =
        GOV_ALLOWED_KEYS.iter().copied().collect();
    let validator_unique: std::collections::BTreeSet<&str> =
        GOV_KEYS_WITH_EXPLICIT_VALIDATORS.iter().copied().collect();

    if allowed_unique.len() != GOV_ALLOWED_KEYS.len() {
        return Err("governance allowed-key registry contains duplicate entries".into());
    }
    if validator_unique.len() != GOV_KEYS_WITH_EXPLICIT_VALIDATORS.len() {
        return Err("governance explicit-validator registry contains duplicate entries".into());
    }
    if allowed_unique != validator_unique {
        let missing_allowed_keys: Vec<&str> = allowed_unique
            .difference(&validator_unique)
            .copied()
            .collect();
        let rogue_validator_keys: Vec<&str> = validator_unique
            .difference(&allowed_unique)
            .copied()
            .collect();
        return Err(format!(
            "governance explicit-validator registry drifted from allowed-key registry: missing_allowed_keys=[{}], rogue_validator_keys=[{}]",
            missing_allowed_keys.join(", "),
            rogue_validator_keys.join(", "),
        ));
    }

    Ok(())
}

fn validate_governance_schema_sample_registry_shape() -> Result<(), String> {
    let allowed_unique: std::collections::BTreeSet<&str> =
        GOV_ALLOWED_KEYS.iter().copied().collect();
    let schema_sample_keys: Vec<&str> = GOV_SCHEMA_INVALID_SAMPLES
        .iter()
        .map(|(key, _)| *key)
        .collect();
    let schema_unique: std::collections::BTreeSet<&str> =
        schema_sample_keys.iter().copied().collect();

    if schema_unique.len() != schema_sample_keys.len() {
        return Err("governance schema invalid-sample registry contains duplicate entries".into());
    }
    if allowed_unique != schema_unique {
        let missing_schema_keys: Vec<&str> = allowed_unique
            .difference(&schema_unique)
            .copied()
            .collect();
        let rogue_schema_keys: Vec<&str> = schema_unique
            .difference(&allowed_unique)
            .copied()
            .collect();
        return Err(format!(
            "governance schema invalid-sample registry drifted from allowed-key registry: missing_schema_keys=[{}], rogue_schema_keys=[{}]",
            missing_schema_keys.join(", "),
            rogue_schema_keys.join(", "),
        ));
    }

    Ok(())
}

fn ensure_allowed_key_has_explicit_validator(key: &str) -> Result<(), String> {
    validate_governance_validator_registry_shape()?;
    validate_governance_schema_sample_registry_shape()?;
    if GOV_ALLOWED_KEYS.contains(&key) && !has_explicit_gov_param_validator(key) {
        return Err(format!(
            "governance key {} is allowed but missing explicit validator registration",
            key
        ));
    }
    Ok(())
}

fn validate_gov_param_value(key: &str, value: &str) -> Result<(), String> {
    ensure_allowed_key_has_explicit_validator(key)?;

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
        "challenge_min_bond_bounty_bps" | "challenge_min_bond_worker_stake_bps" => {
            let _ = parse_u64_in_range(key, value, 0, 100_000)?;
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
        "resolve_authority" => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(format!(
                    "invalid governance value for {}: must be non-empty",
                    key
                ));
            }
            if trimmed != value {
                return Err(format!(
                    "invalid governance value for {}: must not contain surrounding whitespace",
                    key
                ));
            }
            if trimmed.len() > 128 {
                return Err(format!(
                    "invalid governance value for {}: exceeds max length 128",
                    key
                ));
            }
            if trimmed.chars().any(|c| c.is_whitespace()) {
                return Err(format!(
                    "invalid governance value for {}: must not contain whitespace",
                    key
                ));
            }
            if trimmed.contains('，') || trimmed.contains('、') || trimmed.contains('；') {
                return Err(format!(
                    "invalid governance value for {}: only ASCII ',' is allowed as member separator",
                    key
                ));
            }

            let members: Vec<&str> = trimmed.split(',').collect();
            if members.len() < 2 {
                return Err(format!(
                    "invalid governance value for {}: resolve authority set must include at least two members",
                    key
                ));
            }

            let mut seen_lower = std::collections::BTreeSet::new();
            for member in members {
                if member.is_empty() {
                    return Err(format!(
                        "invalid governance value for {}: empty authority member is not allowed",
                        key
                    ));
                }
                let member_lower = member.to_ascii_lowercase();
                if !seen_lower.insert(member_lower.clone()) {
                    return Err(format!(
                        "invalid governance value for {}: duplicate authority member '{}' is not allowed",
                        key, member
                    ));
                }
                if member.contains(';') || member.contains('|') {
                    return Err(format!(
                        "invalid governance value for {}: forbidden separator ';' or '|' in authority member",
                        key
                    ));
                }
                if member.chars().any(|c| c.is_control()) {
                    return Err(format!(
                        "invalid governance value for {}: control characters are not allowed",
                        key
                    ));
                }
                if !member.is_ascii() {
                    return Err(format!(
                        "invalid governance value for {}: must contain ASCII-only account ids",
                        key
                    ));
                }
                if member.eq_ignore_ascii_case(DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER) {
                    return Err(format!(
                        "invalid governance value for {}: placeholder authority is not allowed",
                        key
                    ));
                }
                if member.eq_ignore_ascii_case(RESERVED_SYSTEM_AUTHORITY) {
                    return Err(format!(
                        "invalid governance value for {}: reserved system authority is not allowed",
                        key
                    ));
                }
                if member.eq_ignore_ascii_case(CHALLENGE_ESCROW_ACCOUNT)
                    || member.eq_ignore_ascii_case(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
                    || member.eq_ignore_ascii_case(WORKER_SLASH_TREASURY_ACCOUNT)
                {
                    return Err(format!(
                        "invalid governance value for {}: treasury custody accounts are not allowed",
                        key
                    ));
                }
            }
            Ok(())
        }
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
        _ => Err(format!(
            "invalid governance value for {}: no explicit validator registered",
            key
        )),
    }
}

impl StateStore {
    fn upsert_gov_param_unchecked(
        &mut self,
        key_id: u64,
        key: String,
        value: String,
    ) -> Result<ObjectRef, String> {
        if let Some(existing_id) = self.gov_param_key_index.get(&key).copied() {
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
        validate_gov_param_registry_binding(&self.gov_param_key_index, &key, key_id)?;
        validate_gov_param_value(&key, &value)?;
        if !is_sensitive_gov_param(&key) {
            // Preserve side-effect-free error behavior: only scrub stale pending entries
            // after a successful write for non-sensitive keys.
            // Idempotence guard: unchecked replay of identical non-sensitive values should
            // not churn object versions, but must still clear stale pending residue.
            if self.gov_param_value(&key) == Some(value.as_str()) {
                self.invalidate_state_root_cache();
                self.pending_gov_updates.remove(&key);
                if let Some(existing_ref) = self
                    .gov_param_key_index
                    .get(&key)
                    .copied()
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
                        return Ok(GovParamUpdateOutcome::Cancelled);
                    }
                    GovPendingUpdateAction::Replace => {
                        let activate_at_height =
                            current_height.saturating_add(GOV_SENSITIVE_PARAM_TIMELOCK_BLOCKS);
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
            let r = self.upsert_gov_param_unchecked(key_id, key, value)?;
            return Ok(GovParamUpdateOutcome::Applied(r));
        }

        if action == GovPendingUpdateAction::Cancel {
            return Err(format!("no pending governance update exists for {}", key));
        }

        let activate_at_height = current_height.saturating_add(GOV_SENSITIVE_PARAM_TIMELOCK_BLOCKS);
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
        Ok(GovParamUpdateOutcome::Scheduled { activate_at_height })
    }

    pub fn pending_gov_update(&self, key: &str) -> Option<PendingGovParamUpdate> {
        self.pending_gov_updates.get(key).cloned()
    }

    fn gov_param_value(&self, key: &str) -> Option<&str> {
        let id = self.gov_param_key_index.get(key)?;
        let object = self.objects.get(id)?;
        match &object.value {
            ObjectValue::GovParam(p) if p.key == key && p.key_id == *id => Some(p.value.as_str()),
            _ => None,
        }
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

    pub(crate) fn gov_param_ref_for_key(&self, key: &str) -> Option<(u64, &GovParamObject)> {
        let id = self.gov_param_key_index.get(key).copied()?;
        let object = self.objects.get(&id)?;
        match &object.value {
            ObjectValue::GovParam(p) if p.key == key && p.key_id == id => Some((id, p)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_allowed_key_has_explicit_validator, governance_pinned_key_id,
        has_explicit_gov_param_validator, validate_gov_param_value,
        validate_governance_key_id, GOV_ALLOWED_KEYS, GOV_SCHEMA_INVALID_SAMPLES,
        GOV_SENSITIVE_KEYS,
    };
    use crate::governance_ops::{
        gov_invalid_merge_gate_samples, gov_pinned_key_ids, GovParamKind, GOV_PARAM_SCHEMA,
    };

    #[test]
    fn governance_allowed_keys_have_explicit_value_validators() {
        for key in GOV_ALLOWED_KEYS {
            assert!(
                has_explicit_gov_param_validator(key),
                "allowed governance key missing explicit validator: {}",
                key
            );
            ensure_allowed_key_has_explicit_validator(key)
                .expect("allowed governance key should have a runtime explicitness guard");

            let err = validate_gov_param_value(key, "__merge_gate_invalid_sample__")
                .expect_err("invalid sample should be rejected fail-closed");
            assert!(
                !err.contains("no explicit validator registered"),
                "allowed governance key fell through explicit validator registry: {} => {}",
                key,
                err
            );
            assert!(
                !err.contains("missing explicit validator registration"),
                "allowed governance key tripped runtime explicitness guard unexpectedly: {} => {}",
                key,
                err
            );
        }
    }

    #[test]
    fn governance_pinned_key_id_guard_is_single_source_and_fail_closed() {
        assert_eq!(governance_pinned_key_id("emergency_pause"), Some(7_999));
        assert_eq!(governance_pinned_key_id("max_block_ms"), None);

        let err = validate_governance_key_id("emergency_pause", 8_000)
            .expect_err("pinned governance key ids must fail closed on mismatch");
        assert!(err.contains("expected_id=7999"), "{err}");

        validate_governance_key_id("emergency_pause", 7_999)
            .expect("canonical pinned governance key id should be accepted");
        validate_governance_key_id("max_block_ms", 9_601)
            .expect("unpinned governance keys should stay free of accidental pinning");
    }

    #[test]
    fn foreign_algorand_governance_key_stays_outside_explicit_registry() {
        assert!(
            !GOV_ALLOWED_KEYS.contains(&NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID),
            "foreign algorand governance key must stay outside the allowlist"
        );
        assert!(
            !has_explicit_gov_param_validator(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID),
            "foreign algorand governance key must not gain an explicit validator"
        );
        assert_eq!(
            governance_pinned_key_id(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID),
            None,
            "foreign algorand governance key must not acquire a reserved pinned id"
        );

        let err = validate_gov_param_value(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID, "7999")
            .expect_err("foreign algorand governance key must fail closed at validator boundary");
        assert!(err.contains("no explicit validator registered"), "{err}");
    }

    #[test]
    fn governance_schema_invalid_samples_cover_allowed_keys_once() {
        let allowed_unique: std::collections::BTreeSet<&str> =
            GOV_ALLOWED_KEYS.iter().copied().collect();
        let sample_keys: Vec<&str> = GOV_SCHEMA_INVALID_SAMPLES
            .iter()
            .map(|(key, _)| *key)
            .collect();
        let sample_unique: std::collections::BTreeSet<&str> =
            sample_keys.iter().copied().collect();

        assert_eq!(sample_unique.len(), sample_keys.len());
        assert_eq!(allowed_unique, sample_unique);
    }

    #[test]
    fn governance_legacy_registry_views_match_typed_schema_single_source() {
        let schema_keys: Vec<&str> = GOV_PARAM_SCHEMA.iter().map(|entry| entry.key).collect();
        assert_eq!(GOV_ALLOWED_KEYS, schema_keys.as_slice());

        let legacy_samples: std::collections::BTreeMap<&str, &str> =
            GOV_SCHEMA_INVALID_SAMPLES.iter().copied().collect();
        let schema_samples: std::collections::BTreeMap<&str, &str> = GOV_PARAM_SCHEMA
            .iter()
            .map(|entry| (entry.key, entry.invalid_merge_gate_sample))
            .collect();
        assert_eq!(legacy_samples, schema_samples);
    }

    #[test]
    fn governance_legacy_sensitive_registry_matches_typed_schema_single_source() {
        let schema_sensitive_keys: Vec<&str> = GOV_PARAM_SCHEMA
            .iter()
            .filter(|entry| matches!(entry.kind, GovParamKind::Timelocked))
            .map(|entry| entry.key)
            .collect();
        assert_eq!(GOV_SENSITIVE_KEYS, schema_sensitive_keys.as_slice());
    }

    #[test]
    fn governance_typed_schema_entries_remain_canonical_and_samples_fail_closed() {
        for entry in GOV_PARAM_SCHEMA {
            assert_eq!(entry.key.trim(), entry.key, "schema key must not carry surrounding whitespace: {}", entry.key);
            assert!(entry.key.is_ascii(), "schema key must stay ASCII: {}", entry.key);
            assert!(
                !entry
                    .key
                    .chars()
                    .any(|ch| ch.is_ascii_uppercase() || ch.is_whitespace() || ch.is_control()),
                "schema key must stay canonical lowercase/no-whitespace: {}",
                entry.key
            );

            let err = validate_gov_param_value(entry.key, entry.invalid_merge_gate_sample)
                .expect_err("typed invalid sample must fail closed for every governance schema entry");
            assert!(
                err.contains(entry.key),
                "typed invalid sample rejection should mention the canonical key: {} => {}",
                entry.key,
                err
            );
        }

        let typed_samples: Vec<(&str, &str)> = gov_invalid_merge_gate_samples().collect();
        assert_eq!(typed_samples.as_slice(), GOV_SCHEMA_INVALID_SAMPLES);
    }

    #[test]
    fn governance_legacy_pinned_key_registry_matches_typed_schema_single_source() {
        let schema_pinned: std::collections::BTreeMap<&str, u64> =
            gov_pinned_key_ids().collect();
        let legacy_pinned: std::collections::BTreeMap<&str, u64> =
            GOV_ALLOWED_KEYS
                .iter()
                .filter_map(|key| governance_pinned_key_id(key).map(|key_id| (*key, key_id)))
                .collect();

        assert_eq!(legacy_pinned, schema_pinned);
        assert_eq!(schema_pinned.get("emergency_pause"), Some(&7_999));
        assert!(
            !schema_pinned.contains_key(NON_ALLOWLISTED_ALGORAND_GOVERNANCE_KEY_ID),
            "foreign algorand governance key must stay outside the typed pinned-key registry"
        );
    }

    #[test]
    fn governance_typed_pinned_key_entries_round_trip_through_legacy_guard() {
        for entry in GOV_PARAM_SCHEMA {
            match entry.pinned_key_id {
                Some(expected_id) => {
                    assert_eq!(governance_pinned_key_id(entry.key), Some(expected_id));
                    validate_governance_key_id(entry.key, expected_id)
                        .expect("typed pinned key id should satisfy the legacy guard");

                    let err = validate_governance_key_id(entry.key, expected_id + 1)
                        .expect_err("typed pinned key ids must fail closed on mismatch");
                    assert!(err.contains(entry.key), "{err}");
                    assert!(err.contains(&expected_id.to_string()), "{err}");
                }
                None => {
                    assert_eq!(governance_pinned_key_id(entry.key), None);
                }
            }
        }
    }
}
