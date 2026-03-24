use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LlmTokenMeterPolicy {
    pub(super) coefficients: LlmTokenMeterV1WorkUnitCoefficients,
    pub(super) min_accept_work_units: u128,
    pub(super) challenge_success_bounty_base: u128,
    pub(super) challenge_success_bounty_per_work_unit_num: u128,
    pub(super) challenge_success_bounty_per_work_unit_den: u128,
    pub(super) worker_completion_bonus_per_work_unit_num: u128,
    pub(super) worker_completion_bonus_per_work_unit_den: u128,
    pub(super) worker_slash_rebate_per_work_unit_num: u128,
    pub(super) worker_slash_rebate_per_work_unit_den: u128,
}

impl LlmTokenMeterPolicy {
    fn from_state(st: &StateStore) -> Result<Self, PouwError> {
        let policy = Self {
            coefficients: LlmTokenMeterV1WorkUnitCoefficients {
                prompt_tokens: st
                    .gov_param_u128("llm_meter_prompt_token_weight")
                    .unwrap_or(DEFAULT_LLM_METER_PROMPT_TOKEN_WEIGHT),
                generated_tokens: st
                    .gov_param_u128("llm_meter_generated_token_weight")
                    .unwrap_or(DEFAULT_LLM_METER_GENERATED_TOKEN_WEIGHT),
                decode_steps: st
                    .gov_param_u128("llm_meter_decode_step_weight")
                    .unwrap_or(DEFAULT_LLM_METER_DECODE_STEP_WEIGHT),
                kv_bytes_moved: st
                    .gov_param_u128("llm_meter_kv_byte_weight")
                    .unwrap_or(DEFAULT_LLM_METER_KV_BYTE_WEIGHT),
            },
            min_accept_work_units: st
                .gov_param_u128("llm_meter_min_accept_work_units")
                .unwrap_or(DEFAULT_LLM_METER_MIN_ACCEPT_WORK_UNITS),
            challenge_success_bounty_base: st
                .gov_param_u128("challenge_success_bounty")
                .unwrap_or(DEFAULT_CHALLENGE_SUCCESS_BOUNTY),
            challenge_success_bounty_per_work_unit_num: st
                .gov_param_u128("llm_meter_challenge_success_bounty_per_work_unit_num")
                .unwrap_or(DEFAULT_LLM_METER_CHALLENGE_SUCCESS_BOUNTY_PER_WORK_UNIT_NUM),
            challenge_success_bounty_per_work_unit_den: st
                .gov_param_u128("llm_meter_challenge_success_bounty_per_work_unit_den")
                .unwrap_or(DEFAULT_LLM_METER_CHALLENGE_SUCCESS_BOUNTY_PER_WORK_UNIT_DEN),
            worker_completion_bonus_per_work_unit_num: st
                .gov_param_u128("llm_meter_worker_completion_bonus_per_work_unit_num")
                .unwrap_or(DEFAULT_LLM_METER_WORKER_COMPLETION_BONUS_PER_WORK_UNIT_NUM),
            worker_completion_bonus_per_work_unit_den: st
                .gov_param_u128("llm_meter_worker_completion_bonus_per_work_unit_den")
                .unwrap_or(DEFAULT_LLM_METER_WORKER_COMPLETION_BONUS_PER_WORK_UNIT_DEN),
            worker_slash_rebate_per_work_unit_num: st
                .gov_param_u128("llm_meter_worker_slash_rebate_per_work_unit_num")
                .unwrap_or(DEFAULT_LLM_METER_WORKER_SLASH_REBATE_PER_WORK_UNIT_NUM),
            worker_slash_rebate_per_work_unit_den: st
                .gov_param_u128("llm_meter_worker_slash_rebate_per_work_unit_den")
                .unwrap_or(DEFAULT_LLM_METER_WORKER_SLASH_REBATE_PER_WORK_UNIT_DEN),
        };
        policy.validate()?;
        Ok(policy)
    }

    fn from_snapshot(snapshot: &TaskMeteringSnapshot) -> Result<Self, PouwError> {
        let policy = Self {
            coefficients: LlmTokenMeterV1WorkUnitCoefficients {
                prompt_tokens: snapshot.prompt_token_weight,
                generated_tokens: snapshot.generated_token_weight,
                decode_steps: snapshot.decode_step_weight,
                kv_bytes_moved: snapshot.kv_byte_weight,
            },
            min_accept_work_units: snapshot.min_accept_work_units,
            challenge_success_bounty_base: snapshot.challenge_success_bounty_base,
            challenge_success_bounty_per_work_unit_num: snapshot
                .challenge_success_bounty_per_work_unit_num,
            challenge_success_bounty_per_work_unit_den: snapshot
                .challenge_success_bounty_per_work_unit_den,
            worker_completion_bonus_per_work_unit_num: snapshot
                .worker_completion_bonus_per_work_unit_num,
            worker_completion_bonus_per_work_unit_den: snapshot
                .worker_completion_bonus_per_work_unit_den,
            worker_slash_rebate_per_work_unit_num: snapshot.worker_slash_rebate_per_work_unit_num,
            worker_slash_rebate_per_work_unit_den: snapshot.worker_slash_rebate_per_work_unit_den,
        };
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), PouwError> {
        if self.challenge_success_bounty_per_work_unit_den == 0 {
            return Err(PouwError::State(
                "llm meter challenge success bounty denominator cannot be zero".into(),
            ));
        }
        if self.worker_completion_bonus_per_work_unit_den == 0 {
            return Err(PouwError::State(
                "llm meter worker completion bonus denominator cannot be zero".into(),
            ));
        }
        if self.worker_slash_rebate_per_work_unit_den == 0 {
            return Err(PouwError::State(
                "llm meter worker slash rebate denominator cannot be zero".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn normalized_work_units_for_receipt(&self, receipt: &LlmTokenMeterV1Receipt) -> u128 {
        receipt.normalized_work_units(&self.coefficients)
    }

    pub(super) fn normalized_work_units_for_snapshot(&self, snapshot: &TaskMeteringSnapshot) -> u128 {
        self.coefficients
            .prompt_tokens
            .saturating_mul(snapshot.prompt_tokens as u128)
            .saturating_add(
                self.coefficients
                    .generated_tokens
                    .saturating_mul(snapshot.generated_tokens as u128),
            )
            .saturating_add(
                self.coefficients
                    .decode_steps
                    .saturating_mul(snapshot.decode_steps as u128),
            )
            .saturating_add(
                self.coefficients
                    .kv_bytes_moved
                    .saturating_mul(snapshot.kv_bytes_moved as u128),
            )
    }

    fn challenge_success_bounty_bonus(&self, normalized_work_units: u128) -> u128 {
        ceil_mul_div(
            normalized_work_units,
            self.challenge_success_bounty_per_work_unit_num,
            self.challenge_success_bounty_per_work_unit_den,
        )
    }

    pub(crate) fn effective_challenge_success_bounty(&self, normalized_work_units: u128) -> u128 {
        self.challenge_success_bounty_base
            .saturating_add(self.challenge_success_bounty_bonus(normalized_work_units))
    }

    pub(crate) fn worker_completion_bonus(&self, normalized_work_units: u128) -> u128 {
        ceil_mul_div(
            normalized_work_units,
            self.worker_completion_bonus_per_work_unit_num,
            self.worker_completion_bonus_per_work_unit_den,
        )
    }

    pub(crate) fn worker_slash_rebate(&self, normalized_work_units: u128, locked: u128) -> u128 {
        ceil_mul_div(
            normalized_work_units,
            self.worker_slash_rebate_per_work_unit_num,
            self.worker_slash_rebate_per_work_unit_den,
        )
        .min(locked)
    }
}

pub(crate) fn effective_llm_token_meter_policy(
    st: &StateStore,
) -> Result<LlmTokenMeterPolicy, PouwError> {
    LlmTokenMeterPolicy::from_state(st)
}

pub(crate) fn llm_token_meter_policy_from_snapshot(
    snapshot: &TaskMeteringSnapshot,
) -> Result<Option<LlmTokenMeterPolicy>, PouwError> {
    match snapshot.policy_snapshot_version {
        0 => Ok(None),
        CURRENT_LLM_METER_POLICY_SNAPSHOT_VERSION => {
            Ok(Some(LlmTokenMeterPolicy::from_snapshot(snapshot)?))
        }
        other => Err(PouwError::State(format!(
            "unsupported llm meter policy snapshot version: {}",
            other
        ))),
    }
}

pub(crate) fn llm_token_meter_policy_for_snapshot_or_state(
    st: &StateStore,
    snapshot: Option<&TaskMeteringSnapshot>,
) -> Result<Option<LlmTokenMeterPolicy>, PouwError> {
    let Some(snapshot) = snapshot else {
        return Ok(None);
    };
    if let Some(policy) = llm_token_meter_policy_from_snapshot(snapshot)? {
        Ok(Some(policy))
    } else {
        Ok(Some(effective_llm_token_meter_policy(st)?))
    }
}
