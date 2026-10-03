//! Bounded native evaluation round observations under one active branch generation.
//! No caller-supplied height, score or confirmation Boolean becomes authority.
use super::{evaluation_observation::EvaluationPhase, Node};
use crate::ancestry_index;
use crate::{consensus, digest, ensure, sequence_root, Error, Result};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use trnm_mvcc_fee::{pon_executor::State, public_evaluation as evaluation};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

pub const MAX_EVALUATION_ROUND_BLOCKS: u64 = 4096;

/// Actual predecessor of the checked round window. It is not confirmed or
/// clock-audited by this observation, even when it happens to be genesis.
#[derive(Clone, Debug, Serialize)]
pub struct EvaluationRoundBaseAnchor {
    block: String,
    height: u64,
    clock_checked: bool,
    confirmation_evaluated: bool,
    confirmed: bool,
}

/// An actual active-chain block observed with the installed confirmation policy.
/// Private fields and no Deserialize prevent unverified construction.
#[derive(Clone, Debug, Serialize)]
pub struct EvaluationRoundAnchor {
    block: String,
    height: u64,
    transaction: Option<String>,
    transaction_membership_verified: bool,
    depth: u64,
    work_delta: String,
    required_work_delta: String,
    confirmed: bool,
}
impl EvaluationRoundAnchor {
    pub fn confirmed(&self) -> bool {
        self.confirmed
    }
    pub fn height(&self) -> u64 {
        self.height
    }
}

/// A local observation, never adoption, reward, execution or finality authority.
/// A later reorg or new active generation invalidates its current-view use.
#[derive(Clone, Debug, Serialize)]
pub struct EvaluationRoundObservation {
    schema: &'static str,
    network: String,
    parameters: String,
    genesis: String,
    candidate: String,
    round: String,
    frozen_plan: Value,
    closed_result: Option<Value>,
    closed_result_digest: Option<String>,
    observed_tip: String,
    active_generation: u64,
    observed_height: u64,
    observed_now: u64,
    round_start: u64,
    round_blocks_checked: u64,
    base_anchor: EvaluationRoundBaseAnchor,
    ancestry_index_sql_lookups: u64,
    historical_states_root_checked: u64,
    global_confirmed_prefix: bool,
    global_clock_history_checked: bool,
    confirmation_policy: &'static str,
    confirmed_round_prefix_block: Option<String>,
    confirmed_round_prefix_height: Option<u64>,
    admitted_phase: EvaluationPhase,
    confirmed_phase: Option<EvaluationPhase>,
    candidate_anchor: EvaluationRoundAnchor,
    closure_anchor: Option<EvaluationRoundAnchor>,
    current_conflict_count: usize,
    finalized: bool,
    adoption_authority: bool,
    reward_authority: bool,
    execution_authority: bool,
    independent_governance_accepted: bool,
    objective_model_quality: bool,
    public_ready: bool,
}
impl EvaluationRoundObservation {
    pub fn admitted_phase(&self) -> EvaluationPhase {
        self.admitted_phase
    }
    pub fn confirmed_phase(&self) -> Option<EvaluationPhase> {
        self.confirmed_phase
    }
    pub fn confirmed_round_prefix_height(&self) -> Option<u64> {
        self.confirmed_round_prefix_height
    }
    pub fn round_blocks_checked(&self) -> u64 {
        self.round_blocks_checked
    }
    pub fn candidate_anchor(&self) -> &EvaluationRoundAnchor {
        &self.candidate_anchor
    }
    pub fn closure_anchor(&self) -> Option<&EvaluationRoundAnchor> {
        self.closure_anchor.as_ref()
    }
    pub fn closed_result(&self) -> Option<&Value> {
        self.closed_result.as_ref()
    }
    pub fn active_generation(&self) -> u64 {
        self.active_generation
    }
}

fn number(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| Error::from("EVALUATION_OBSERVATION_STATE"))
}
fn phase(plan: &Value, width: u64, height: u64) -> Result<EvaluationPhase> {
    let start = number(plan, "start")?;
    Ok(if height < start {
        EvaluationPhase::BeforeRound
    } else if height >= start.checked_add(width).ok_or("HEIGHT")? {
        EvaluationPhase::RoundEnded
    } else if height <= number(plan, "candidate_end")? {
        EvaluationPhase::Candidate
    } else if height <= number(plan, "commit_end")? {
        EvaluationPhase::Commit
    } else if height <= number(plan, "reveal_end")? {
        EvaluationPhase::Reveal
    } else if height < number(plan, "adoption_start")? {
        EvaluationPhase::Dispute
    } else {
        EvaluationPhase::AdoptionWindow
    })
}
fn confirmed_phase(
    plan: &Value,
    width: u64,
    frontier: Option<u64>,
    candidate: &EvaluationRoundAnchor,
) -> Result<Option<EvaluationPhase>> {
    match frontier {
        Some(height) if candidate.confirmed && candidate.height <= height => {
            Ok(Some(phase(plan, width, height)?))
        }
        _ => Ok(None),
    }
}
fn confirmation(
    tip_height: u64,
    tip_work: consensus::Work,
    height: u64,
    work: consensus::Work,
    target: Hash,
    depth_required: u64,
    multiplier: u64,
) -> Result<(u64, consensus::Work, consensus::Work, bool)> {
    let depth = tip_height.checked_sub(height).ok_or("HEIGHT")?;
    let delta = tip_work.checked_sub(work)?;
    let required = consensus::required_work(target)?.mul_small(multiplier)?;
    Ok((
        depth,
        delta,
        required,
        depth >= depth_required && delta >= required,
    ))
}

impl Node {
    /// This v2 observes a complete local round window, never a global prefix.
    /// Bounds limit software work; they do not preempt SQLite or native execution.
    pub fn evaluation_round_observation(
        &self,
        candidate: Hash,
        observed_now: u64,
        max_round_blocks: u64,
    ) -> Result<EvaluationRoundObservation> {
        ensure(
            (1..=MAX_EVALUATION_ROUND_BLOCKS).contains(&max_round_blocks),
            "EVALUATION_OBSERVATION_LIMIT",
        )?;
        self.ready()?;
        let cfg = &self.settings.app;
        ensure(evaluation::enabled(cfg), "PUBLIC_EVAL_PROFILE")?;
        let (tip, generation) = self.active()?;
        let observed = self.record(tip)?;
        let (state_tip, state_generation, state) = self.read_active()?;
        ensure(
            (tip, generation) == (state_tip, state_generation),
            "STALE_VIEW",
        )?;
        let key = format!("contribution:{}", hex::encode(candidate));
        let archive = format!("evaluation-archive:{}", hex::encode(candidate));
        let contribution = state
            .get(&key)
            .or_else(|| state.get(&archive))
            .ok_or("STATE")?;
        let current = evaluation::read_evaluation(&state, candidate)?;
        let plan = &current["plan"];
        let submitted = number(contribution, "submitted_height")?;
        let width = number(&cfg.params, "candidate_round_blocks")?;
        ensure(width > evaluation::ADOPTION_START, "PUBLIC_EVAL_STATE")?;
        let start = submitted / width * width;
        ensure(
            plan["network"] == hex::encode(cfg.network)
                && plan["parameters"] == hex::encode(cfg.parameters)
                && plan["candidate"] == hex::encode(candidate)
                && plan["family"] == hex::encode(cfg.family)
                && plan["model_and_task_contract"] == hex::encode(cfg.plan)
                && plan["max_score"] == cfg.params["max_evidence_score"]
                && plan["artifact"] == contribution["artifact"]
                && plan["components_root"] == contribution["components_root"]
                && plan["parent"] == contribution["parent"]
                && number(plan, "start")? == start
                && number(plan, "candidate_end")?
                    == start
                        .checked_add(evaluation::CANDIDATE_END)
                        .ok_or("HEIGHT")?
                && number(plan, "commit_end")?
                    == start.checked_add(evaluation::COMMIT_END).ok_or("HEIGHT")?
                && number(plan, "reveal_end")?
                    == start.checked_add(evaluation::REVEAL_END).ok_or("HEIGHT")?
                && number(plan, "adoption_start")?
                    == start
                        .checked_add(evaluation::ADOPTION_START)
                        .ok_or("HEIGHT")?,
            "EVALUATION_OBSERVATION_CONTEXT",
        )?;
        let round = evaluation::round(&current)?;
        ensure(
            hash(
                b"native-public-evaluation-round-v1",
                &[&serde_json::to_vec(plan)?],
            ) == round,
            "PUBLIC_EVAL_ROUND",
        )?;
        let depth_required = self.settings.limit("confirmation_depth")?;
        let multiplier = self.settings.limit("confirmation_work_multiplier")?;
        let time_bound = observed_now as u128 + self.settings.limit("future_skew_seconds")? as u128;
        // Never truncate an older retained round into a successful observation.
        let base_height = start.saturating_sub(1);
        let checked_count = observed.height.checked_sub(base_height).ok_or("HEIGHT")?;
        ensure(
            checked_count <= max_round_blocks,
            "EVALUATION_OBSERVATION_LIMIT",
        )?;
        let mut blocks = BTreeMap::new();
        let mut current_block = tip;
        while self.record(current_block)?.height > base_height {
            ensure(
                (blocks.len() as u64) < max_round_blocks,
                "EVALUATION_OBSERVATION_LIMIT",
            )?;
            let record = self.record(current_block)?;
            let header = self.stored_header(current_block)?;
            ensure(header.timestamp as u128 <= time_bound, "TIME_DEFERRED")?;
            let parent = record.parent.ok_or("UNKNOWN_PARENT")?;
            let parent_record = self.record(parent)?;
            ensure(
                parent_record.height.checked_add(1) == Some(record.height)
                    && header.parent == parent,
                "ANCESTRY_HEIGHT",
            )?;
            ensure(
                record.work
                    == parent_record
                        .work
                        .checked_add(consensus::required_work(header.target)?)?,
                "CHAINWORK",
            )?;
            ensure(
                blocks
                    .insert(record.height, (current_block, record, header))
                    .is_none(),
                "ANCESTRY_HEIGHT",
            )?;
            current_block = parent;
        }
        let base_record = self.record(current_block)?;
        ensure(
            blocks.len() as u64 == checked_count && base_record.height == base_height,
            "ANCESTRY_HEIGHT",
        )?;
        if base_height == 0 {
            ensure(
                current_block == self.settings.genesis() && base_record.parent.is_none(),
                "ANCESTRY_HEIGHT",
            )?;
        } else {
            // Check identity/context and stored parent, without claiming a fresh
            // clock or confirmation assessment for the predecessor.
            self.stored_header(current_block)?;
        }
        let lookup = ancestry_index::next(
            &self.db,
            self.ancestry_context(),
            tip,
            current_block,
            ancestry_index::READ_SQL_BUDGET,
            &mut |_| Ok(()),
        )?;
        ensure(
            lookup.next == blocks.first_key_value().map(|(_, (id, _, _))| *id)
                && lookup.height == base_height + 1,
            "EVALUATION_OBSERVATION_ANCESTOR",
        )?;
        // Only this round's complete consecutive path is assessed. No earlier
        // global confirmation or clock-history verdict is inferred.
        let mut frontier = None;
        for (&height, (block, record, header)) in &blocks {
            if !confirmation(
                observed.height,
                observed.work,
                height,
                record.work,
                header.target,
                depth_required,
                multiplier,
            )?
            .3
            {
                break;
            }
            frontier = Some((*block, height));
        }
        let closed = (!current["closed"].is_null()).then(|| current["closed"].clone());
        let closure_height = closed
            .as_ref()
            .map(|v| number(v, "closed_height"))
            .transpose()?;
        let (historical, historical_states_root_checked) =
            self.round_historical_states(&state, &blocks, submitted, closure_height)?;
        let candidate_block = blocks
            .get(&submitted)
            .ok_or("EVALUATION_OBSERVATION_CANDIDATE")?;
        let packet = self.packet(candidate_block.0)?;
        ensure(
            packet.header.transactions == sequence_root("transactions", &packet.transactions),
            "ROOT",
        )?;
        let owner = digest(contribution["owner"].as_str().ok_or("PUBLIC_EVAL_STATE")?)?;
        let mut transaction = None;
        for raw in &packet.transactions {
            let tx = Envelope::decode(raw).map_err(|_| Error::from("TRANSACTION_CODEC"))?;
            if tx.tag == 6 && tx.payload.get(..32) == Some(candidate.as_slice()) {
                ensure(
                    tx.sender == owner && transaction.is_none(),
                    "EVALUATION_OBSERVATION_CANDIDATE",
                )?;
                transaction = Some(hex::encode(hash(b"tx-id", &[raw])));
            }
        }
        ensure(transaction.is_some(), "MEMBERSHIP")?;
        let submitted_state = historical
            .get(&submitted)
            .ok_or("EVALUATION_OBSERVATION_CANDIDATE")?;
        let original = evaluation::read_evaluation(submitted_state, candidate)?;
        ensure(
            original["plan"] == *plan && original["round"] == current["round"],
            "EVALUATION_OBSERVATION_CONTEXT",
        )?;
        let anchor = |height: u64, transaction: Option<String>| -> Result<EvaluationRoundAnchor> {
            let (id, record, header) = blocks
                .get(&height)
                .ok_or("EVALUATION_OBSERVATION_ANCESTOR")?;
            let (depth, delta, required, confirmed) = confirmation(
                observed.height,
                observed.work,
                height,
                record.work,
                header.target,
                depth_required,
                multiplier,
            )?;
            Ok(EvaluationRoundAnchor {
                block: hex::encode(id),
                height,
                transaction_membership_verified: transaction.is_some(),
                transaction,
                depth,
                work_delta: hex::encode(delta.bytes()),
                required_work_delta: hex::encode(required.bytes()),
                confirmed,
            })
        };
        let candidate_anchor = anchor(submitted, transaction)?;
        let (closed_result_digest, closure_anchor) = if let Some(result) = &closed {
            let height = number(result, "closed_height")?;
            let closure = anchor(height, None)?;
            let closure_state = historical
                .get(&height)
                .ok_or("EVALUATION_OBSERVATION_CLOSURE")?;
            ensure(
                evaluation::read_evaluation(closure_state, candidate)?["closed"] == *result,
                "EVALUATION_OBSERVATION_CLOSURE",
            )?;
            (
                Some(hex::encode(evaluation::closed_digest(&current)?)),
                Some(closure),
            )
        } else {
            (None, None)
        };
        let observation = EvaluationRoundObservation {
            schema: "native-evaluation-confirmed-round-observation-v2",
            network: hex::encode(cfg.network),
            parameters: hex::encode(cfg.parameters),
            genesis: hex::encode(self.settings.genesis()),
            candidate: hex::encode(candidate),
            round: hex::encode(round),
            frozen_plan: plan.clone(),
            closed_result: closed,
            closed_result_digest,
            observed_tip: hex::encode(tip),
            active_generation: generation,
            observed_height: observed.height,
            observed_now,
            round_start: start,
            round_blocks_checked: blocks.len() as u64,
            base_anchor: EvaluationRoundBaseAnchor {
                block: hex::encode(current_block),
                height: base_height,
                clock_checked: false,
                confirmation_evaluated: false,
                confirmed: false,
            },
            ancestry_index_sql_lookups: lookup.sql_lookups,
            historical_states_root_checked,
            global_confirmed_prefix: false,
            global_clock_history_checked: false,
            confirmation_policy:
                "installed-depth-and-required-work/continuous-confirmed-round-prefix",
            confirmed_round_prefix_block: frontier.map(|(id, _)| hex::encode(id)),
            confirmed_round_prefix_height: frontier.map(|(_, height)| height),
            admitted_phase: phase(plan, width, observed.height)?,
            confirmed_phase: confirmed_phase(
                plan,
                width,
                frontier.map(|(_, height)| height),
                &candidate_anchor,
            )?,
            candidate_anchor,
            closure_anchor,
            current_conflict_count: current["conflicts"]
                .as_object()
                .ok_or("PUBLIC_EVAL_STATE")?
                .len(),
            finalized: false,
            adoption_authority: false,
            reward_authority: false,
            execution_authority: false,
            independent_governance_accepted: false,
            objective_model_quality: false,
            public_ready: false,
        };
        self.ready()?;
        ensure(self.active()? == (tip, generation), "STALE_VIEW")?;
        Ok(observation)
    }

    /// Re-observe the native branch and clock before reusing a local observation.
    /// This validates freshness only; it grants no phase/adoption/reward authority.
    pub fn check_evaluation_round_observation(
        &self,
        prior: &EvaluationRoundObservation,
        observed_now: u64,
        max_round_blocks: u64,
    ) -> Result<()> {
        self.ready()?;
        ensure(
            prior.network == hex::encode(self.settings.network())
                && prior.parameters == hex::encode(self.settings.parameters())
                && prior.genesis == hex::encode(self.settings.genesis()),
            "EVALUATION_OBSERVATION_CONTEXT",
        )?;
        ensure(
            self.active()? == (digest(&prior.observed_tip)?, prior.active_generation),
            "STALE_VIEW",
        )?;
        let actual = self.evaluation_round_observation(
            digest(&prior.candidate)?,
            observed_now,
            max_round_blocks,
        )?;
        ensure(
            actual.round == prior.round
                && actual.closed_result_digest == prior.closed_result_digest,
            "STALE_VIEW",
        )
    }
}

impl Node {
    fn round_historical_states(
        &self,
        active: &State,
        blocks: &BTreeMap<u64, (Hash, super::Record, trnm_protocol::pon_wire::Header)>,
        submitted: u64,
        closure: Option<u64>,
    ) -> Result<(BTreeMap<u64, State>, u64)> {
        ensure(
            blocks.contains_key(&submitted),
            "EVALUATION_OBSERVATION_CANDIDATE",
        )?;
        if let Some(height) = closure {
            ensure(
                height >= submitted && blocks.contains_key(&height),
                "EVALUATION_OBSERVATION_CLOSURE",
            )?;
        }
        let mut state = active.clone();
        let mut retained = BTreeMap::new();
        let mut commitment = None;
        let mut checked = 0_u64;
        for (&height, (id, record, _)) in blocks.iter().rev() {
            // The initial state is independently root-checked by read_active.
            // Each prior state below is checked against its actual parent root.
            if height == submitted || closure == Some(height) {
                retained.insert(height, state.clone());
            }
            if height == submitted {
                break;
            }
            for (key, before, after) in self.delta_rows(*id)? {
                ensure(
                    state.get(&key).map(super::canonical).transpose()? == after,
                    "UNDO_ROOT",
                )?;
                if let Some(bytes) = before {
                    state.insert(key, serde_json::from_slice(&bytes)?);
                } else {
                    state.remove(&key);
                }
            }
            let parent = record.parent.ok_or("UNKNOWN_PARENT")?;
            let prepared =
                self.checked_commitment(&state, self.record(parent)?.root, commitment.as_ref())?;
            commitment = prepared.snapshot;
            checked = checked.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
        }
        Ok((retained, checked))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{development_public, Settings};
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};

    #[test]
    fn candidate_cannot_skip_an_unconfirmed_round_predecessor() {
        let plan = serde_json::json!({"start":4096,"candidate_end":4111,
            "commit_end":4127,"reveal_end":4143,"adoption_start":4152});
        let candidate = EvaluationRoundAnchor {
            block: "00".repeat(32),
            height: 4097,
            transaction: None,
            transaction_membership_verified: false,
            depth: 6,
            work_delta: "00".repeat(64),
            required_work_delta: "00".repeat(64),
            confirmed: true,
        };
        assert_eq!(confirmed_phase(&plan, 128, None, &candidate).unwrap(), None);
        assert_eq!(
            confirmed_phase(&plan, 128, Some(4096), &candidate).unwrap(),
            None
        );
        assert_eq!(
            confirmed_phase(&plan, 128, Some(4097), &candidate).unwrap(),
            Some(EvaluationPhase::Candidate)
        );
    }

    #[test]
    fn actual_delta_root_and_derived_index_corruption_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let settings =
            Settings::development_with_evaluation_policy(None, evaluation::PROFILE).unwrap();
        let cfg = settings.app.clone();
        let mut node = Node::open(directory.path(), settings, 2).unwrap();
        let owner = development_public(3).unwrap();
        let cid = hash(
            b"contribution-v3",
            &[
                &owner,
                &cfg.family,
                &[0; 32],
                &[7; 32],
                &[8; 32],
                &0_u64.to_le_bytes(),
            ],
        );
        let mut payload = Vec::new();
        for h in [cid, cfg.family, [0; 32], [7; 32]] {
            payload.extend(h);
        }
        payload.extend(1024_u64.to_le_bytes());
        payload.extend([8; 32]);
        payload.extend(0_u64.to_le_bytes());
        let mut tx = Envelope {
            network: cfg.network,
            sender: owner,
            nonce: 1,
            expiry: 100,
            fee_limit: 1_000_000,
            tag: 6,
            payload,
            signature: [0; 64],
        };
        let key =
            signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&3_u64.to_le_bytes()])))
                .unwrap();
        tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
            .unwrap()
            .try_into()
            .unwrap();
        let mut id = [0; 32];
        for height in 1..=4 {
            let raws = if height == 1 {
                vec![tx.encode().unwrap()]
            } else {
                vec![]
            };
            let packet = node
                .make(
                    node.active().unwrap().0,
                    raws,
                    owner,
                    1_800_000_000 + height * 10,
                    4096,
                )
                .unwrap();
            id = node.admit(&packet, 1_800_010_000).unwrap();
            node.activate_observed(id, 1_800_010_000).unwrap();
        }
        let observe = |node: &Node| node.evaluation_round_observation(cid, 1_800_010_000, 4);
        observe(&node).unwrap();
        let (delta_key, after): (String, Option<Vec<u8>>) = node
            .db
            .query_row(
                "SELECT key,after FROM deltas WHERE block=? ORDER BY key LIMIT 1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        node.db
            .execute(
                "UPDATE deltas SET after=? WHERE block=? AND key=?",
                rusqlite::params![b"{}".as_slice(), id.as_slice(), delta_key],
            )
            .unwrap();
        assert_eq!(observe(&node).unwrap_err().to_string(), "UNDO_ROOT");
        node.db
            .execute(
                "UPDATE deltas SET after=? WHERE block=? AND key=?",
                rusqlite::params![after, id.as_slice(), delta_key],
            )
            .unwrap();
        observe(&node).unwrap();
        let seal: Vec<u8> = node
            .db
            .query_row(
                "SELECT seal FROM ancestry_jump WHERE block=? AND level=1",
                [id.as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        node.db
            .execute(
                "UPDATE ancestry_jump SET seal=? WHERE block=? AND level=1",
                rusqlite::params![[0_u8; 32].as_slice(), id.as_slice()],
            )
            .unwrap();
        assert_eq!(
            observe(&node).unwrap_err().to_string(),
            "ANCESTRY_INDEX_SEAL"
        );
        node.db
            .execute(
                "UPDATE ancestry_jump SET seal=? WHERE block=? AND level=1",
                rusqlite::params![seal, id.as_slice()],
            )
            .unwrap();
        observe(&node).unwrap();
        let root: Vec<u8> = node
            .db
            .query_row("SELECT state_root FROM blocks WHERE height=2", [], |r| {
                r.get(0)
            })
            .unwrap();
        node.db
            .execute(
                "UPDATE blocks SET state_root=? WHERE height=2",
                [[0_u8; 32].as_slice()],
            )
            .unwrap();
        // Header/root consistency rejects before inverse deltas are consulted.
        assert_eq!(observe(&node).unwrap_err().to_string(), "STORAGE_PACKET");
        node.db
            .execute("UPDATE blocks SET state_root=? WHERE height=2", [root])
            .unwrap();
        observe(&node).unwrap();
    }
}
