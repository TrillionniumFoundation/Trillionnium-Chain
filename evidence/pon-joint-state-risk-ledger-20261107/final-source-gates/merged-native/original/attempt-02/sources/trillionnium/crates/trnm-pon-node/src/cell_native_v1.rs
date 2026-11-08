//! Native, fully replayed bounded Cell candidate; no Python runtime is used.
//!
//! This new namespace consumes owner-retained UTF-8 snippets, not V2's complete
//! Git corpus. The owner authenticates snippet origin and task demand. Rust
//! executes preprocessing, every W1 tile, routing, state, sampling and training.
//! A successful check is repeatable computation evidence. It is neither a
//! consensus Packet, an operation consumption, a checkpoint commit nor FinalUse.

mod execution;
mod source;
mod work;

use crate::{digest, ensure, Error, Node, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use trnm_protocol::pon_wire::{hash, Hash};

pub const PROFILE: &str = "pon-cell-stateful-native-int257-v1";
pub const MODEL_SCHEMA: &str = "pon-cell-stateful-native-int257-v1/model";
pub const STATE_SCHEMA: &str = "pon-cell-stateful-native-int257-v1/state";
pub const ADMISSION_SCHEMA: &str = "pon-cell-stateful-native-int257-v1/owner-admission";
pub const CLAIM_SCHEMA: &str = "pon-cell-stateful-native-int257-v1/claim";
pub const OPTIMIZER_SCHEMA: &str = "pon-cell-stateful-native-int257-v1/momentum";
pub const INPUT_PROFILE: &str = "owner-utf8-ascii-token-snippet-v1";
pub const ADMISSION_LIMIT: usize = 1 << 20;
pub const CLAIM_LIMIT: usize = 4 << 20;
pub const DIM: usize = 257;
pub const CLASSES: [&str; 3] = ["M00", "M04", "M10"];
pub const MAX_BATCH: usize = 64;
pub const PRODUCT_BOUND: i64 = 257 * 8 * 32_767;
pub const LOGIT_BOUND: i64 = 2 * PRODUCT_BOUND + 8192;
type Matrix = Vec<Vec<i64>>;
type BoolMatrix = Vec<Vec<bool>>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Model {
    pub schema: String,
    pub base: Matrix,
    pub router: Matrix,
    pub deltas: Vec<Matrix>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Optimizer {
    pub schema: String,
    pub step: u64,
    pub base: Matrix,
    pub deltas: Vec<Matrix>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CellState {
    pub schema: String,
    pub cell_id: String,
    pub generation: u64,
    pub scope: String,
    pub model_artifact: String,
    pub memory: Vec<i64>,
    pub rng_seed: String,
    pub rng_counter: u64,
    pub remaining_steps: u64,
    pub sequence: u64,
    pub optimizer: Option<Optimizer>,
}

/// Origin and labels are independently retained owner inputs, not a Git proof
/// or independently administered ground truth. All UTF-8 bytes are replayed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceSnippet {
    pub id: String,
    pub origin: String,
    pub content_hex: String,
    pub label: u8,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Emit,
    Stop,
    Abstain,
    ProposeTool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Sampler {
    #[serde(rename = "argmax-lowest")]
    ArgmaxLowest,
    #[serde(rename = "sha256-positive-shift-v1")]
    Sha256PositiveShift,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrainableMask {
    pub base: BoolMatrix,
    pub deltas: Vec<BoolMatrix>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Training {
    pub learning_rate_num: u64,
    pub learning_rate_den: u64,
    pub momentum_num: u64,
    pub momentum_den: u64,
    pub clip_abs: u64,
    pub trainable_mask: TrainableMask,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub feature_mask: Vec<bool>,
    pub expert_mask: Vec<Vec<bool>>,
    pub allowed_actions: Vec<Action>,
    pub sampler: Sampler,
    pub abstain_margin: u64,
    pub tool_names: Vec<Option<String>>,
    pub training: Option<Training>,
}

/// This request is read from the consumer's retained owner channel. It has no
/// producer-chosen parent fields and no `relation_valid` or permission flags.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerAdmission {
    pub schema: String,
    pub input_profile: String,
    pub consumer: String,
    pub allowed_use: String,
    pub request_id: String,
    pub issued_at_unix_seconds: u64,
    pub deadline_unix_seconds: u64,
    pub work_target: String,
    pub model: Model,
    pub inputs: Vec<SourceSnippet>,
    pub before: CellState,
    pub policy: Policy,
}

/// Constructed only from the Node's actually verified parent state. There is no
/// deserializer or public constructor that can promote producer JSON to this.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ParentContext {
    network: String,
    parameters: String,
    parent_id: String,
    parent_state_root: String,
    parent_height: u64,
    task_height: u64,
    consensus_time_unix_seconds: u64,
}

/// The only constructor is `Node::cell_expected_from_owner`. In particular a
/// claim or its advertised contract cannot be turned into expected context.
#[derive(Clone, Debug)]
pub struct ExpectedCellTask {
    admission: OwnerAdmission,
    owner_admission_sha256: Hash,
    parent: ParentContext,
    contract_id: Hash,
}

impl ExpectedCellTask {
    pub fn contract_id(&self) -> Hash {
        self.contract_id
    }
    pub fn parent_context(&self) -> &ParentContext {
        &self.parent
    }
    pub fn owner_admission_sha256(&self) -> Hash {
        self.owner_admission_sha256
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TileProof {
    index: usize,
    nonce: u64,
    proof_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Segment {
    contract_id: String,
    ordinal: usize,
    predecessor: String,
    stage: String,
    inputs: Value,
    outputs: Value,
    segment_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Claim {
    schema: String,
    contract_id: String,
    tiles: Vec<TileProof>,
    segments: Vec<Segment>,
    output: Value,
    after_state: CellState,
    after_model: Model,
}

#[derive(Debug)]
struct Stage {
    stage: String,
    inputs: Value,
    outputs: Value,
}

#[derive(Debug)]
struct Execution {
    output: Value,
    after_state: CellState,
    after_model: Model,
    stages: Vec<Stage>,
}

/// Private construction prevents unchecked JSON from becoming a verified Cell.
/// This object carries no owner consumption, checkpoint or use capability.
#[derive(Debug)]
pub struct VerifiedCell {
    contract_id: Hash,
    parent: ParentContext,
    output: Value,
    after_state: CellState,
    after_model: Model,
    segment_root: String,
    live_window: Option<(u64, u64)>,
}

impl VerifiedCell {
    pub fn output(&self) -> &Value {
        &self.output
    }
    pub fn after_state(&self) -> &CellState {
        &self.after_state
    }
    pub fn after_model(&self) -> &Model {
        &self.after_model
    }
    pub fn observation(&self) -> Value {
        json!({
            "schema":format!("{PROFILE}/verification"),
            "profile":PROFILE,"contract_id":hex::encode(self.contract_id),
            "parent_context":self.parent,"segment_root":self.segment_root,
            "live_window_unix_seconds":self.live_window,
            "computed_historical":true,"computed_live":self.live_window.is_some(),
            "full_w1_proofs_verified":5,"full_cell_replay":true,
            "native_node_verifier_invoked":true,
            "source_profile":INPUT_PROFILE,
            "git_source_provenance_verified":false,
            "current_owner_authorization_checked":false,
            "operation_consumed":false,"checkpoint_committed":false,
            "final_use_granted":false,"model_later_used":false,
            "tools_executed":false,"external_delivery_verified":false,
            "consensus_work_admitted":false,"quality_qualified":false,
            "work_cost_qualified":false,"production_activation":false,
            "output":self.output,"after_state":self.after_state,
            "after_model_artifact":model_artifact(&self.after_model).expect("verified model"),
        })
    }
}

fn check_json(value: &Value, depth: usize) -> Result<()> {
    ensure(depth <= 32, "CELL_JSON_DEPTH")?;
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::String(text) => ensure(text.is_ascii(), "CELL_JSON_ASCII"),
        Value::Number(number) => ensure(number.is_i64() || number.is_u64(), "CELL_JSON_INTEGER"),
        Value::Array(values) => {
            for value in values {
                check_json(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (name, value) in values {
                ensure(name.is_ascii(), "CELL_JSON_ASCII")?;
                check_json(value, depth + 1)?;
            }
            Ok(())
        }
    }
}

/// Fixed sorted-key ASCII JSON with exact signed/unsigned integers. Non-ASCII
/// source data travels as raw UTF-8 hex, avoiding language-dependent escaping.
pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    check_json(&value, 0)?;
    Ok(serde_json::to_vec(&value)?)
}

fn decode<T: DeserializeOwned + Serialize>(raw: &[u8], limit: usize) -> Result<T> {
    ensure(!raw.is_empty() && raw.len() <= limit, "CELL_INPUT_LIMIT")?;
    let value: T = serde_json::from_slice(raw).map_err(|_| Error::from("CELL_INPUT_SCHEMA"))?;
    // Also refuses duplicate fields, alternate escapes, whitespace and floats.
    ensure(canonical(&value)? == raw, "CELL_CANONICAL_BYTES")?;
    Ok(value)
}

fn identity(text: &str, maximum: usize) -> Result<()> {
    ensure(
        !text.is_empty()
            && text.len() <= maximum
            && text.as_bytes()[0].is_ascii_alphanumeric()
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte)),
        "CELL_IDENTITY",
    )
}

fn matrix(matrix: &Matrix, bound: i64) -> Result<()> {
    ensure(
        matrix.len() == 3
            && matrix.iter().all(|row| {
                row.len() == DIM && row.iter().all(|&value| (-bound..=bound).contains(&value))
            }),
        "CELL_MATRIX_SHAPE_OR_RANGE",
    )
}

fn mask(matrix: &BoolMatrix) -> bool {
    matrix.len() == 3 && matrix.iter().all(|row| row.len() == DIM)
}

fn validate_model(model: &Model) -> Result<()> {
    ensure(model.schema == MODEL_SCHEMA, "CELL_MODEL_SCHEMA")?;
    matrix(&model.base, 32_767)?;
    matrix(&model.router, 32_767)?;
    ensure(model.deltas.len() == 3, "CELL_MODEL_DELTAS")?;
    for delta in &model.deltas {
        matrix(delta, 32_767)?;
    }
    Ok(())
}

pub fn model_artifact(model: &Model) -> Result<String> {
    validate_model(model)?;
    Ok(hex::encode(hash(
        b"pon-cell-stateful-native-int257-v1/model",
        &[&canonical(model)?],
    )))
}

fn validate_state(state: &CellState, model: &Model) -> Result<()> {
    ensure(state.schema == STATE_SCHEMA, "CELL_STATE_SCHEMA")?;
    for text in [&state.cell_id, &state.model_artifact, &state.rng_seed] {
        digest(text)?;
    }
    identity(&state.scope, 256)?;
    ensure(
        state.memory.len() == 3
            && state
                .memory
                .iter()
                .all(|value| (-8192..=8192).contains(value)),
        "CELL_STATE_MEMORY",
    )?;
    ensure(
        state.model_artifact == model_artifact(model)?,
        "CELL_STATE_MODEL_ARTIFACT",
    )?;
    if let Some(optimizer) = &state.optimizer {
        ensure(
            optimizer.schema == OPTIMIZER_SCHEMA,
            "CELL_OPTIMIZER_SCHEMA",
        )?;
        matrix(&optimizer.base, i64::MAX)?;
        ensure(optimizer.deltas.len() == 3, "CELL_OPTIMIZER_DELTAS")?;
        for delta in &optimizer.deltas {
            matrix(delta, i64::MAX)?;
        }
    }
    Ok(())
}

fn validate_admission(admission: &OwnerAdmission) -> Result<()> {
    ensure(
        admission.schema == ADMISSION_SCHEMA && admission.input_profile == INPUT_PROFILE,
        "CELL_ADMISSION_PROFILE",
    )?;
    identity(&admission.consumer, 128)?;
    identity(&admission.allowed_use, 128)?;
    digest(&admission.request_id)?;
    ensure(
        digest(&admission.work_target)? != [0; 32],
        "CELL_WORK_TARGET",
    )?;
    ensure(
        admission.issued_at_unix_seconds <= admission.deadline_unix_seconds,
        "CELL_TASK_WINDOW",
    )?;
    validate_model(&admission.model)?;
    validate_state(&admission.before, &admission.model)?;
    ensure(
        (1..=MAX_BATCH).contains(&admission.inputs.len()),
        "CELL_BATCH",
    )?;
    let mut ids = BTreeSet::new();
    for input in &admission.inputs {
        digest(&input.id)?;
        ensure(ids.insert(&input.id), "CELL_DUPLICATE_INPUT")?;
        identity(&input.origin, 1024)?;
        ensure(input.label < 3, "CELL_INPUT_LABEL")?;
        source::decode_input(input)?;
    }
    let policy = &admission.policy;
    ensure(
        policy.feature_mask.len() == DIM && policy.feature_mask[DIM - 1],
        "CELL_FEATURE_MASK",
    )?;
    ensure(
        policy.expert_mask.len() == admission.inputs.len()
            && policy
                .expert_mask
                .iter()
                .all(|row| row.len() == 3 && row.iter().any(|v| *v)),
        "CELL_EXPERT_MASK",
    )?;
    ensure(
        !policy.allowed_actions.is_empty()
            && policy.allowed_actions.len() <= 4
            && policy
                .allowed_actions
                .iter()
                .enumerate()
                .all(|(i, action)| !policy.allowed_actions[..i].contains(action)),
        "CELL_ALLOWED_ACTIONS",
    )?;
    ensure(
        policy.abstain_margin <= (2 * LOGIT_BOUND) as u64,
        "CELL_ABSTAIN_MARGIN",
    )?;
    ensure(policy.tool_names.len() == 3, "CELL_TOOL_NAMES")?;
    for name in policy.tool_names.iter().flatten() {
        identity(name, 128)?;
    }
    if let Some(training) = &policy.training {
        ensure(
            training.learning_rate_num <= 1 << 20
                && (1..=1 << 32).contains(&training.learning_rate_den)
                && training.momentum_num < training.momentum_den
                && training.momentum_den <= 1 << 16
                && (1..=1 << 40).contains(&training.clip_abs)
                && mask(&training.trainable_mask.base)
                && training.trainable_mask.deltas.len() == 3
                && training.trainable_mask.deltas.iter().all(mask),
            "CELL_TRAINING_POLICY",
        )?;
    }
    Ok(())
}

impl Node {
    fn cell_verified_parent(&self, parent: Hash) -> Result<ParentContext> {
        // state_at replays/validates native history, rather than trusting a
        // producer's parent hash or the unverified stored header alone.
        let state = self.state_at(parent)?;
        let root = self.settings().state_root(&state)?;
        let height = self.parent_height(parent)?;
        let time = if parent == self.settings().genesis() {
            ensure(height == 0, "CELL_GENESIS_HEIGHT")?;
            self.settings().genesis_time()
        } else {
            let packet = self.packet(parent)?;
            ensure(
                packet.header.network == self.settings().network()
                    && packet.header.parameters == self.settings().parameters()
                    && packet.header.state == root
                    && packet.header.height == height,
                "CELL_PARENT_STATE",
            )?;
            packet.header.timestamp
        };
        Ok(ParentContext {
            network: hex::encode(self.settings().network()),
            parameters: hex::encode(self.settings().parameters()),
            parent_id: hex::encode(parent),
            parent_state_root: hex::encode(root),
            parent_height: height,
            task_height: height.checked_add(1).ok_or("CELL_HEIGHT_OVERFLOW")?,
            // Native Header timestamps are UNIX seconds. No ms or monotonic
            // clock value is silently converted into this new profile.
            consensus_time_unix_seconds: time,
        })
    }

    /// Load the owner's independently retained exact admission and pin it to
    /// real Node parent state. `owner_sha256` must come from that owner channel,
    /// never from the claim under verification. It is a byte pin, not a signer.
    pub fn cell_expected_from_owner(
        &self,
        parent: Hash,
        owner_raw: &[u8],
        owner_sha256: Hash,
    ) -> Result<ExpectedCellTask> {
        ensure(
            owner_raw.len() <= ADMISSION_LIMIT
                && <[u8; 32]>::from(Sha256::digest(owner_raw)) == owner_sha256,
            "CELL_OWNER_ADMISSION_SHA256",
        )?;
        let admission: OwnerAdmission = decode(owner_raw, ADMISSION_LIMIT)?;
        validate_admission(&admission)?;
        let parent = self.cell_verified_parent(parent)?;
        ensure(
            admission.issued_at_unix_seconds <= parent.consensus_time_unix_seconds
                && parent.consensus_time_unix_seconds <= admission.deadline_unix_seconds,
            "CELL_HISTORICAL_WINDOW",
        )?;
        let contract_id = hash(
            b"pon-cell-stateful-native-int257-v1/contract",
            &[&canonical(&json!({"admission":admission,"parent":parent}))?],
        );
        Ok(ExpectedCellTask {
            admission,
            owner_admission_sha256: owner_sha256,
            parent,
            contract_id,
        })
    }

    /// Current-use computation check. Owner revocation, CURRENT, one-use
    /// operation consumption and FinalUse remain the real external owner's job.
    /// Recheck the active parent after work. Historical replay below has no such
    /// dependency, so a reorg or later wall time cannot rewrite historical truth.
    pub fn verify_cell_live(
        &self,
        expected: &ExpectedCellTask,
        claim_raw: &[u8],
        mut clock_unix_seconds: impl FnMut() -> Result<u64>,
    ) -> Result<VerifiedCell> {
        let start = clock_unix_seconds()?;
        let owner = &expected.admission;
        ensure(
            owner.issued_at_unix_seconds <= start && start <= owner.deadline_unix_seconds,
            "CELL_LIVE_START_WINDOW",
        )?;
        let active_before = self.active()?;
        ensure(
            hex::encode(active_before.0) == expected.parent.parent_id
                && self.cell_verified_parent(active_before.0)? == expected.parent,
            "CELL_LIVE_PARENT",
        )?;
        let mut verified = verify_historical(expected, claim_raw)?;
        ensure(
            self.active()? == active_before
                && self.cell_verified_parent(active_before.0)? == expected.parent,
            "CELL_LIVE_PARENT_CHANGED",
        )?;
        let finish = clock_unix_seconds()?;
        ensure(
            start <= finish && finish <= owner.deadline_unix_seconds,
            "CELL_LIVE_FINISH_WINDOW",
        )?;
        verified.live_window = Some((start, finish));
        Ok(verified)
    }
}

fn segments(expected: &ExpectedCellTask, stages: Vec<Stage>) -> Result<Vec<Segment>> {
    let cid = hex::encode(expected.contract_id);
    let mut predecessor = hex::encode(hash(
        b"pon-cell-stateful-native-int257-v1/segment-start",
        &[&expected.contract_id],
    ));
    let mut result = Vec::with_capacity(stages.len());
    for (ordinal, stage) in stages.into_iter().enumerate() {
        let body = json!({"contract_id":cid,"ordinal":ordinal,"predecessor":predecessor,
            "stage":stage.stage,"inputs":stage.inputs,"outputs":stage.outputs});
        let segment_id = hex::encode(hash(
            b"pon-cell-stateful-native-int257-v1/segment",
            &[&canonical(&body)?],
        ));
        result.push(Segment {
            contract_id: cid.clone(),
            ordinal,
            predecessor,
            stage: stage.stage,
            inputs: stage.inputs,
            outputs: stage.outputs,
            segment_id: segment_id.clone(),
        });
        predecessor = segment_id;
    }
    Ok(result)
}

/// Native producer for bounded development fixtures. It performs real W1 work;
/// an exhausted nonce budget fails. It never submits or installs the result.
pub fn prove_reference(expected: &ExpectedCellTask, attempts_per_tile: u64) -> Result<Vec<u8>> {
    ensure(
        (1..=4096).contains(&attempts_per_tile),
        "CELL_SEARCH_BUDGET",
    )?;
    let prepared = source::prepare(&expected.admission)?;
    let tiles = work::prove(expected, &prepared.features, attempts_per_tile)?;
    let products = work::verify(expected, &prepared.features, &tiles)?;
    let executed = execution::execute(&expected.admission, prepared, products)?;
    let claim = Claim {
        schema: CLAIM_SCHEMA.into(),
        contract_id: hex::encode(expected.contract_id),
        tiles,
        segments: segments(expected, executed.stages)?,
        output: executed.output,
        after_state: executed.after_state,
        after_model: executed.after_model,
    };
    let raw = canonical(&claim)?;
    ensure(raw.len() <= CLAIM_LIMIT, "CELL_CLAIM_LIMIT")?;
    Ok(raw)
}

/// Pure historical computation: no wall clock, current revocation or live
/// active-tip input is accepted. The parent/time were obtained from native state
/// when the owner context was frozen. Repeated verification is intentionally OK.
pub fn verify_historical(expected: &ExpectedCellTask, claim_raw: &[u8]) -> Result<VerifiedCell> {
    let claim: Claim = decode(claim_raw, CLAIM_LIMIT)?;
    ensure(claim.schema == CLAIM_SCHEMA, "CELL_CLAIM_PROFILE")?;
    ensure(
        claim.contract_id == hex::encode(expected.contract_id),
        "CELL_EXPECTED_CONTRACT",
    )?;
    let prepared = source::prepare(&expected.admission)?;
    let products = work::verify(expected, &prepared.features, &claim.tiles)?;
    let executed = execution::execute(&expected.admission, prepared, products)?;
    ensure(
        claim.after_state == executed.after_state,
        "CELL_AFTER_STATE_RELATION",
    )?;
    ensure(
        claim.after_model == executed.after_model,
        "CELL_AFTER_MODEL_RELATION",
    )?;
    ensure(claim.output == executed.output, "CELL_OUTPUT_RELATION")?;
    let computed_segments = segments(expected, executed.stages)?;
    ensure(
        claim.segments == computed_segments,
        "CELL_SEGMENT_DATAFLOW_RELATION",
    )?;
    let segment_root = computed_segments
        .last()
        .ok_or("CELL_EMPTY_TRACE")?
        .segment_id
        .clone();
    Ok(VerifiedCell {
        contract_id: expected.contract_id,
        parent: expected.parent.clone(),
        output: executed.output,
        after_state: executed.after_state,
        after_model: executed.after_model,
        segment_root,
        live_window: None,
    })
}
