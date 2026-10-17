//! Read-only native evaluation observations under one active branch generation.
//! No caller-supplied height, score or confirmation Boolean becomes authority.
use super::Node;
use crate::{consensus, digest, ensure, sequence_root, Error, Result};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use trnm_mvcc_fee::public_evaluation as evaluation;
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

pub const MAX_EVALUATION_ANCESTRY_BLOCKS: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvaluationPhase {
    BeforeRound,
    Candidate,
    Commit,
    Reveal,
    Dispute,
    AdoptionWindow,
    RoundEnded,
}

/// An actual active-chain block observed with the installed confirmation policy.
/// Private fields and no Deserialize prevent unverified construction.
#[derive(Clone, Debug, Serialize)]
pub struct EvaluationAnchor {
    block: String,
    height: u64,
    transaction: Option<String>,
    transaction_membership_verified: bool,
    depth: u64,
    work_delta: String,
    required_work_delta: String,
    confirmed: bool,
}
impl EvaluationAnchor {
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
pub struct EvaluationObservation {
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
    ancestry_checked: u64,
    confirmation_policy: &'static str,
    confirmed_prefix_block: String,
    confirmed_prefix_height: u64,
    admitted_phase: EvaluationPhase,
    confirmed_phase: Option<EvaluationPhase>,
    candidate_anchor: EvaluationAnchor,
    closure_anchor: Option<EvaluationAnchor>,
    current_conflict_count: usize,
    finalized: bool,
    adoption_authority: bool,
    reward_authority: bool,
    execution_authority: bool,
    independent_governance_accepted: bool,
    objective_model_quality: bool,
    public_ready: bool,
}
impl EvaluationObservation {
    pub fn admitted_phase(&self) -> EvaluationPhase {
        self.admitted_phase
    }
    pub fn confirmed_phase(&self) -> Option<EvaluationPhase> {
        self.confirmed_phase
    }
    pub fn confirmed_prefix_height(&self) -> u64 {
        self.confirmed_prefix_height
    }
    pub fn candidate_anchor(&self) -> &EvaluationAnchor {
        &self.candidate_anchor
    }
    pub fn closure_anchor(&self) -> Option<&EvaluationAnchor> {
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
    frontier: u64,
    candidate: &EvaluationAnchor,
) -> Result<Option<EvaluationPhase>> {
    if candidate.confirmed && candidate.height <= frontier {
        Ok(Some(phase(plan, width, frontier)?))
    } else {
        Ok(None)
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
    /// Traversal bound is a software-work limit, not preemption of SQLite or native
    /// work. No partial frontier is returned if the complete ancestry exceeds it.
    pub fn evaluation_observation(
        &self,
        candidate: Hash,
        observed_now: u64,
        max_ancestry_blocks: u64,
    ) -> Result<EvaluationObservation> {
        ensure(
            (1..=MAX_EVALUATION_ANCESTRY_BLOCKS).contains(&max_ancestry_blocks),
            "EVALUATION_OBSERVATION_LIMIT",
        )?;
        self.ready()?;
        let cfg = &self.settings.app;
        ensure(evaluation::enabled(cfg), "PUBLIC_EVAL_PROFILE")?;
        let (tip, generation) = self.active()?;
        let observed = self.record(tip)?;
        ensure(
            observed.height <= max_ancestry_blocks,
            "EVALUATION_OBSERVATION_LIMIT",
        )?;
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
        let mut blocks = BTreeMap::new();
        let mut current_block = tip;
        while current_block != self.settings.genesis() {
            ensure(
                (blocks.len() as u64) < max_ancestry_blocks,
                "EVALUATION_OBSERVATION_LIMIT",
            )?;
            let link = self.stored_header_link(current_block)?;
            let record = link.record;
            let header = link.header;
            ensure(header.timestamp as u128 <= time_bound, "TIME_DEFERRED")?;
            let parent = header.parent;
            ensure(
                record.work
                    == link
                        .parent_work
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
        ensure(blocks.len() as u64 == observed.height, "ANCESTRY_HEIGHT")?;
        let genesis = self.record(current_block)?;
        ensure(
            genesis.height == 0 && genesis.parent.is_none(),
            "ANCESTRY_HEIGHT",
        )?;
        // A target change can make individual confirmation thresholds nonmonotone.
        // Stop at the first unconfirmed block; never manufacture height from depth.
        let mut frontier = (current_block, 0_u64);
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
            frontier = (*block, height);
        }
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
        let submitted_state = self.state_at(candidate_block.0)?;
        let original = evaluation::read_evaluation(&submitted_state, candidate)?;
        ensure(
            original["plan"] == *plan && original["round"] == current["round"],
            "EVALUATION_OBSERVATION_CONTEXT",
        )?;
        let anchor = |height: u64, transaction: Option<String>| -> Result<EvaluationAnchor> {
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
            Ok(EvaluationAnchor {
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
        let closed = (!current["closed"].is_null()).then(|| current["closed"].clone());
        let (closed_result_digest, closure_anchor) = if let Some(result) = &closed {
            let height = number(result, "closed_height")?;
            let closure = anchor(height, None)?;
            let closure_id = blocks[&height].0;
            let closure_state = self.state_at(closure_id)?;
            ensure(
                evaluation::read_evaluation(&closure_state, candidate)?["closed"] == *result,
                "EVALUATION_OBSERVATION_CLOSURE",
            )?;
            (
                Some(hex::encode(evaluation::closed_digest(&current)?)),
                Some(closure),
            )
        } else {
            (None, None)
        };
        let observation = EvaluationObservation {
            schema: "native-evaluation-confirmed-observation-v1",
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
            ancestry_checked: blocks.len() as u64,
            confirmation_policy: "installed-depth-and-required-work/continuous-confirmed-prefix",
            confirmed_prefix_block: hex::encode(frontier.0),
            confirmed_prefix_height: frontier.1,
            admitted_phase: phase(plan, width, observed.height)?,
            confirmed_phase: confirmed_phase(plan, width, frontier.1, &candidate_anchor)?,
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
    pub fn check_evaluation_observation(
        &self,
        prior: &EvaluationObservation,
        observed_now: u64,
        max_ancestry_blocks: u64,
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
        let actual = self.evaluation_observation(
            digest(&prior.candidate)?,
            observed_now,
            max_ancestry_blocks,
        )?;
        ensure(
            actual.round == prior.round
                && actual.closed_result_digest == prior.closed_result_digest,
            "STALE_VIEW",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{development_public, Settings};
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};

    #[test]
    fn actual_native_observer_refuses_corrupt_kv_root_header_and_parent_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let settings =
            Settings::development_with_evaluation_policy(None, evaluation::PROFILE).unwrap();
        let mut node = Node::open(directory.path(), settings, 1).unwrap();
        let owner = development_public(3).unwrap();
        let cfg = &node.settings.app;
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
        for value in [cid, cfg.family, [0; 32], [7; 32]] {
            payload.extend(value);
        }
        payload.extend(1024_u64.to_le_bytes());
        payload.extend([8; 32]);
        payload.extend(0_u64.to_le_bytes());
        let mut tx = Envelope {
            network: cfg.network,
            sender: owner,
            nonce: 1,
            expiry: 128,
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
        let packet = node
            .make(
                node.settings.genesis(),
                vec![tx.encode().unwrap()],
                owner,
                1_800_000_010,
                4096,
            )
            .unwrap();
        let id = node.admit(&packet, 1_800_010_000).unwrap();
        node.activate(id).unwrap();
        let observe = |node: &Node| node.evaluation_observation(cid, 1_800_010_000, 32);
        observe(&node).unwrap(); // Warm the existing derived cache before actual KV corruption.
        let slot = node.slot().unwrap();
        let account = format!("account:{}", hex::encode(owner));
        let original: Vec<u8> = node
            .db
            .query_row(
                "SELECT value FROM kv WHERE slot=? AND key=?",
                rusqlite::params![slot, account],
                |row| row.get(0),
            )
            .unwrap();
        let mut changed: Value = serde_json::from_slice(&original).unwrap();
        changed["balance"] = serde_json::json!(changed["balance"].as_u64().unwrap() + 1);
        node.db
            .execute(
                "UPDATE kv SET value=? WHERE slot=? AND key=?",
                rusqlite::params![serde_json::to_vec(&changed).unwrap(), slot, account],
            )
            .unwrap();
        assert_eq!(observe(&node).unwrap_err().to_string(), "ROOT");
        node.db
            .execute(
                "UPDATE kv SET value=? WHERE slot=? AND key=?",
                rusqlite::params![original, slot, account],
            )
            .unwrap();
        observe(&node).unwrap();
        node.db
            .execute(
                "UPDATE blocks SET state_root=? WHERE id=?",
                rusqlite::params![[9_u8; 32].as_slice(), id.as_slice()],
            )
            .unwrap();
        assert_eq!(observe(&node).unwrap_err().to_string(), "ROOT");
        node.db
            .execute(
                "UPDATE blocks SET state_root=? WHERE id=?",
                rusqlite::params![packet.header.state.as_slice(), id.as_slice()],
            )
            .unwrap();
        let mut changed = packet.clone();
        changed.header.timestamp += 1;
        node.db
            .execute(
                "UPDATE blocks SET packet=? WHERE id=?",
                rusqlite::params![changed.encode().unwrap(), id.as_slice()],
            )
            .unwrap();
        assert_eq!(observe(&node).unwrap_err().to_string(), "STORAGE_PACKET");
        node.db
            .execute(
                "UPDATE blocks SET packet=? WHERE id=?",
                rusqlite::params![packet.encode().unwrap(), id.as_slice()],
            )
            .unwrap();
        node.db
            .execute(
                "UPDATE blocks SET parent=? WHERE id=?",
                rusqlite::params![[9_u8; 32].as_slice(), id.as_slice()],
            )
            .unwrap();
        assert_eq!(observe(&node).unwrap_err().to_string(), "STORAGE_PACKET");
        node.db
            .execute(
                "UPDATE blocks SET parent=? WHERE id=?",
                rusqlite::params![packet.header.parent.as_slice(), id.as_slice()],
            )
            .unwrap();
        node.db
            .execute("UPDATE blocks SET height=2 WHERE id=?", [id.as_slice()])
            .unwrap();
        assert_eq!(observe(&node).unwrap_err().to_string(), "STORAGE_PACKET");
        node.db
            .execute("UPDATE blocks SET height=1 WHERE id=?", [id.as_slice()])
            .unwrap();
        observe(&node).unwrap();
    }

    #[test]
    fn individually_confirmed_candidate_outside_prefix_has_no_confirmed_phase() {
        let plan = serde_json::json!({"start":0,"candidate_end":15,"commit_end":31,"reveal_end":47,"adoption_start":56});
        let candidate = EvaluationAnchor {
            block: hex::encode([1; 32]),
            height: 15,
            transaction: None,
            transaction_membership_verified: true,
            depth: 6,
            work_delta: hex::encode([1; 64]),
            required_work_delta: hex::encode([1; 64]),
            confirmed: true,
        };
        assert_eq!(confirmed_phase(&plan, 128, 14, &candidate).unwrap(), None);
        assert_eq!(
            confirmed_phase(&plan, 128, 15, &candidate).unwrap(),
            Some(EvaluationPhase::Candidate)
        );
    }

    #[test]
    fn confirmation_uses_actual_target_work_not_just_height_difference() {
        let mut hard = [0; 32];
        hard[31] = 1;
        let easy = [255; 32];
        let tip_work = consensus::Work::default()
            .checked_add(
                consensus::required_work(easy)
                    .unwrap()
                    .mul_small(10)
                    .unwrap(),
            )
            .unwrap();
        assert!(
            confirmation(10, tip_work, 1, consensus::Work::default(), easy, 6, 6)
                .unwrap()
                .3
        );
        assert!(
            !confirmation(10, tip_work, 1, consensus::Work::default(), hard, 6, 6)
                .unwrap()
                .3
        );
    }
}
