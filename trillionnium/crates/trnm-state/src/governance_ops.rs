use crate::StateStore;

pub(crate) const GOV_SENSITIVE_PARAM_TIMELOCK_BLOCKS: u64 = 20;
pub(crate) const GOV_SENSITIVE_PARAM_MAX_CHANGE_BPS: u64 = 2_000;
pub(crate) const EMERGENCY_PAUSE_KEY_ID: u64 = 7_999;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GovParamKind {
    Immediate,
    Timelocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GovParamValueValidator {
    U64Range { min: u64, max: u64 },
    StrictBool,
    ResolveAuthoritySet,
}

impl GovParamValueValidator {
    pub fn validate(self, key: &str, value: &str) -> Result<(), String> {
        match self {
            Self::U64Range { min, max } => {
                let _ = parse_u64_in_range(key, value, min, max)?;
                Ok(())
            }
            Self::StrictBool => {
                let _ = parse_bool_strict(key, value)?;
                Ok(())
            }
            Self::ResolveAuthoritySet => validate_resolve_authority_value(key, value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GovParamSchemaEntry {
    pub key: &'static str,
    pub kind: GovParamKind,
    pub validator: GovParamValueValidator,
    pub invalid_merge_gate_sample: &'static str,
    pub pinned_key_id: Option<u64>,
}

impl GovParamSchemaEntry {
    pub const fn is_sensitive(self) -> bool {
        matches!(self.kind, GovParamKind::Timelocked)
    }
}

pub(crate) const GOV_PARAM_SCHEMA: &[GovParamSchemaEntry] = &[
    GovParamSchemaEntry {
        key: "max_block_ms",
        kind: GovParamKind::Immediate,
        validator: GovParamValueValidator::U64Range {
            min: 10,
            max: 120_000,
        },
        invalid_merge_gate_sample: "9",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "max_parallel_workers",
        kind: GovParamKind::Immediate,
        validator: GovParamValueValidator::U64Range {
            min: 1,
            max: 65_536,
        },
        invalid_merge_gate_sample: "0",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "min_worker_stake",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 1,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "0",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "challenge_min_bond",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 1,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "0",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "challenge_min_bond_bounty_bps",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 0,
            max: 100_000,
        },
        invalid_merge_gate_sample: "100001",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "challenge_min_bond_worker_stake_bps",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 0,
            max: 100_000,
        },
        invalid_merge_gate_sample: "100001",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "challenge_window_blocks",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range { min: 100, max: 600 },
        invalid_merge_gate_sample: "99",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "challenge_success_bounty",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 0,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "-1",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "llm_meter_prompt_token_weight",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 0,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "1000000000001",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "llm_meter_generated_token_weight",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 0,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "1000000000001",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "llm_meter_decode_step_weight",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 0,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "1000000000001",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "llm_meter_kv_byte_weight",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 0,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "1000000000001",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "llm_meter_min_accept_work_units",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 0,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "1000000000001",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "llm_meter_challenge_success_bounty_per_work_unit_num",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 0,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "1000000000001",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "llm_meter_challenge_success_bounty_per_work_unit_den",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 1,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "0",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "llm_meter_worker_completion_bonus_per_work_unit_num",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 0,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "1000000000001",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "llm_meter_worker_completion_bonus_per_work_unit_den",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 1,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "0",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "llm_meter_worker_slash_rebate_per_work_unit_num",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 0,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "1000000000001",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "llm_meter_worker_slash_rebate_per_work_unit_den",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::U64Range {
            min: 1,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "0",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "resolve_authority",
        kind: GovParamKind::Timelocked,
        validator: GovParamValueValidator::ResolveAuthoritySet,
        invalid_merge_gate_sample: "   ",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "emergency_pause",
        kind: GovParamKind::Immediate,
        validator: GovParamValueValidator::StrictBool,
        invalid_merge_gate_sample: "TRUE",
        pinned_key_id: Some(EMERGENCY_PAUSE_KEY_ID),
    },
    GovParamSchemaEntry {
        key: "monetary_policy_tick_interval_blocks",
        kind: GovParamKind::Immediate,
        validator: GovParamValueValidator::U64Range {
            min: 1,
            max: 100_000,
        },
        invalid_merge_gate_sample: "0",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "monetary_policy_tick_cooldown_blocks",
        kind: GovParamKind::Immediate,
        validator: GovParamValueValidator::U64Range {
            min: 1,
            max: 100_000,
        },
        invalid_merge_gate_sample: "0",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "monetary_base_issuance_per_tick",
        kind: GovParamKind::Immediate,
        validator: GovParamValueValidator::U64Range {
            min: 0,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "1000000000001",
        pinned_key_id: None,
    },
    GovParamSchemaEntry {
        key: "monetary_base_burn_per_tick",
        kind: GovParamKind::Immediate,
        validator: GovParamValueValidator::U64Range {
            min: 0,
            max: 1_000_000_000_000,
        },
        invalid_merge_gate_sample: "1000000000001",
        pinned_key_id: None,
    },
];

pub(crate) fn gov_allowed_keys() -> impl Iterator<Item = &'static str> {
    GOV_PARAM_SCHEMA.iter().map(|entry| entry.key)
}

pub(crate) fn gov_sensitive_keys() -> impl Iterator<Item = &'static str> {
    GOV_PARAM_SCHEMA
        .iter()
        .filter(|entry| entry.is_sensitive())
        .map(|entry| entry.key)
}

pub(crate) fn gov_param_registry_entry(key: &str) -> Option<&'static GovParamSchemaEntry> {
    GOV_PARAM_SCHEMA.iter().find(|entry| entry.key == key)
}

pub(crate) fn gov_pinned_key_id(key: &str) -> Option<u64> {
    gov_param_registry_entry(key).and_then(|entry| entry.pinned_key_id)
}

pub(crate) fn gov_pinned_key_ids() -> impl Iterator<Item = (&'static str, u64)> {
    GOV_PARAM_SCHEMA
        .iter()
        .filter_map(|entry| entry.pinned_key_id.map(|key_id| (entry.key, key_id)))
}

pub(crate) fn gov_invalid_merge_gate_samples() -> impl Iterator<Item = (&'static str, &'static str)> {
    GOV_PARAM_SCHEMA
        .iter()
        .map(|entry| (entry.key, entry.invalid_merge_gate_sample))
}

pub(crate) fn is_allowed_gov_param(key: &str) -> bool {
    gov_allowed_keys().any(|allowed_key| allowed_key == key)
}

pub(crate) const DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER: &str = "governance.resolve_authority";
pub(crate) const RESERVED_SYSTEM_AUTHORITY: &str = "system";
pub(crate) const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
pub(crate) const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";
pub(crate) const WORKER_SLASH_TREASURY_ACCOUNT: &str = "treasury.worker_slashes";
pub(crate) const RESOLVE_ACTOR_ID_MAX_LEN: usize = 128;

pub(crate) fn resolve_actor_has_forbidden_separator(token: &str) -> bool {
    token.contains(',')
        || token.contains(';')
        || token.contains('|')
        || token.contains('；')
        || token.contains('，')
        || token.contains('、')
}

pub(crate) fn resolve_actor_is_reserved(token: &str) -> bool {
    token.eq_ignore_ascii_case(DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER)
        || token.eq_ignore_ascii_case(RESERVED_SYSTEM_AUTHORITY)
        || token.eq_ignore_ascii_case(CHALLENGE_ESCROW_ACCOUNT)
        || token.eq_ignore_ascii_case(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        || token.eq_ignore_ascii_case(WORKER_SLASH_TREASURY_ACCOUNT)
        || token.eq_ignore_ascii_case("governance.emergency_pause")
        || token.eq_ignore_ascii_case("emergency_pause")
}

pub(crate) fn validate_resolve_approver_token(raw: &str) -> Result<String, String> {
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

pub(crate) fn canonicalize_resolve_authority_set(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed != raw {
        return Err(
            "resolve approval authority set must be a canonical comma-delimited actor list".into(),
        );
    }
    if trimmed.len() > RESOLVE_ACTOR_ID_MAX_LEN {
        return Err(format!(
            "resolve approval authority set exceeds max length {}",
            RESOLVE_ACTOR_ID_MAX_LEN
        ));
    }

    let authority_members: Vec<&str> = trimmed.split(',').collect();
    if authority_members.len() < 2 {
        return Err("resolve approval authority set must include at least two members".into());
    }

    let mut seen_members = std::collections::BTreeSet::new();
    for member in &authority_members {
        let member_trimmed = member.trim();
        if member_trimmed.is_empty()
            || member_trimmed != *member
            || member_trimmed
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || member_trimmed.len() > RESOLVE_ACTOR_ID_MAX_LEN
            || resolve_actor_has_forbidden_separator(member_trimmed)
            || !member_trimmed.is_ascii()
            || resolve_actor_is_reserved(member_trimmed)
        {
            return Err(
                "resolve approval authority set contains non-canonical or forbidden member".into(),
            );
        }
        if !seen_members.insert(member_trimmed.to_ascii_lowercase()) {
            return Err("resolve approval authority set must not contain duplicate members".into());
        }
    }

    Ok(seen_members.into_iter().collect::<Vec<_>>().join(","))
}

pub(crate) fn ensure_effective_resolve_authority_match(
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

pub(crate) fn is_effective_resolve_authority_match(st: &StateStore, authority_set: &str) -> bool {
    ensure_effective_resolve_authority_match(st, authority_set).is_ok()
}

pub(crate) fn is_sensitive_gov_param(key: &str) -> bool {
    gov_sensitive_keys().any(|sensitive_key| sensitive_key == key)
}

pub(crate) fn check_sensitive_rate_limit(key: &str, old: u64, new: u64) -> Result<(), String> {
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

pub(crate) fn parse_u64_in_range(
    key: &str,
    value: &str,
    min: u64,
    max: u64,
) -> Result<u64, String> {
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

pub(crate) fn parse_bool_strict(key: &str, value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!(
            "invalid governance value for {}: expected strict bool 'true' or 'false', got '{}'",
            key, value
        )),
    }
}

fn validate_resolve_authority_value(key: &str, value: &str) -> Result<(), String> {
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
    if trimmed.len() > RESOLVE_ACTOR_ID_MAX_LEN {
        return Err(format!(
            "invalid governance value for {}: exceeds max length {}",
            key, RESOLVE_ACTOR_ID_MAX_LEN
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
        if member.eq_ignore_ascii_case(RESERVED_SYSTEM_AUTHORITY)
            || member.eq_ignore_ascii_case("governance.emergency_pause")
            || member.eq_ignore_ascii_case("emergency_pause")
        {
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

pub(crate) fn validate_gov_param_value(key: &str, value: &str) -> Result<(), String> {
    let entry = gov_param_registry_entry(key)
        .ok_or_else(|| format!("governance key not allowed: {}", key))?;
    entry.validator.validate(key, value)
}
