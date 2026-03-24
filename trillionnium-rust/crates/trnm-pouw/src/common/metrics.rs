use sha2::{Digest, Sha256};
use trnm_state::StateStore;
use trnm_types::{Hash32, ObjectRef, ProofType, TaskMeteringSnapshot, TaskObject, TaskStatus};

use crate::metering::{
    parse_and_validate_llm_token_meter_v1_receipt_json, LlmTokenMeterV1Receipt,
    LlmTokenMeterV1WorkUnitCoefficients, DEFAULT_LLM_TOKEN_METER_JITTER_BUDGET_MS,
    LLM_INFERENCE_WORKLOAD_CLASS, LLM_TOKEN_METER_V1_SCHEMA,
};

use super::apply_path::{
    maybe_pay_challenge_success_bounty, settle_worker_stake_for_terminal_state,
};
use super::state::*;

#[path = "metrics/challenge.rs"]
mod challenge;
#[path = "metrics/labels.rs"]
mod labels;
#[path = "metrics/parsing.rs"]
mod parsing;
#[path = "metrics/policy.rs"]
mod policy;
#[path = "metrics/settlement.rs"]
mod settlement;
#[path = "metrics/snapshots.rs"]
mod snapshots;

pub(crate) use challenge::*;
pub(crate) use labels::*;
pub(crate) use parsing::*;
pub(crate) use policy::*;
pub(crate) use settlement::*;
pub(crate) use snapshots::*;
