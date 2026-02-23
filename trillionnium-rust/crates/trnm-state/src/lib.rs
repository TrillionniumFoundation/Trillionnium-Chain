use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use trnm_types::{
    GovParamObject, GovProposalObject, GovProposalStatus, Hash32, ObjectRef, TaskObject,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectValue {
    Task(TaskObject),
    GovProposal(GovProposalObject),
    GovParam(GovParamObject),
}

#[derive(Debug, Default, Clone)]
pub struct StateStore {
    objects: BTreeMap<u64, VersionedObject>,
}

#[derive(Debug, Clone)]
struct VersionedObject {
    version: u64,
    value: ObjectValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointMeta {
    pub height: u64,
    pub state_root_hex: String,
    pub wal_entry_hash_hex: String,
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
        hasher.update(self.proposal_hash.as_bytes());
        hasher.update([self.committed as u8]);
        hasher.update(self.state_root_hex.as_bytes());
        if let Some(prev) = &self.prev_hash_hex {
            hasher.update(prev.as_bytes());
        } else {
            hasher.update(b"genesis");
        }
        hex::encode(hasher.finalize())
    }
}

fn parse_u64_in_range(key: &str, value: &str, min: u64, max: u64) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("invalid governance value for {}: expected u64, got '{}'", key, value))?;
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

fn validate_gov_param_value(key: &str, value: &str) -> Result<(), String> {
    match key {
        "max_block_ms" => {
            let _ = parse_u64_in_range(key, value, 10, 120_000)?;
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
        "emergency_pause" => {
            let _ = parse_bool_strict(key, value)?;
            Ok(())
        }
        _ => Ok(()),
    }
}

impl StateStore {
    pub fn new() -> Self {
        Self::default()
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

    pub fn get_param(&self, id: u64) -> Option<GovParamObject> {
        self.objects.get(&id).and_then(|v| match &v.value {
            ObjectValue::GovParam(p) => Some(p.clone()),
            _ => None,
        })
    }

    pub fn put_task_new(&mut self, task: TaskObject) -> Result<ObjectRef, String> {
        if self.objects.contains_key(&task.task_id) {
            return Err("task already exists".into());
        }
        let id = task.task_id;
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
        self.objects.insert(
            expected.id,
            VersionedObject {
                version: new_version,
                value: ObjectValue::Task(task),
            },
        );
        Ok(ObjectRef {
            id: expected.id,
            version: new_version,
        })
    }

    pub fn put_proposal_new(&mut self, proposal: GovProposalObject) -> Result<ObjectRef, String> {
        if self.objects.contains_key(&proposal.proposal_id) {
            return Err("proposal already exists".into());
        }
        let id = proposal.proposal_id;
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

    pub fn set_gov_param(
        &mut self,
        key_id: u64,
        key: String,
        value: String,
    ) -> Result<ObjectRef, String> {
        // Governance MVP whitelist.
        const ALLOWED_KEYS: &[&str] = &[
            "max_block_ms",
            "max_parallel_workers",
            "min_worker_stake",
            "challenge_min_bond",
            "challenge_window_blocks",
            "emergency_pause",
        ];
        if !ALLOWED_KEYS.contains(&key.as_str()) {
            return Err(format!("governance key not allowed: {}", key));
        }

        validate_gov_param_value(&key, &value)?;

        if let Some(current) = self.objects.get(&key_id) {
            let new_version = current.version + 1;
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

    pub fn is_emergency_paused(&self) -> bool {
        self.objects.values().any(|v| match &v.value {
            ObjectValue::GovParam(p) => p.key == "emergency_pause" && p.value == "true",
            _ => false,
        })
    }

    pub fn gov_param_u64(&self, key: &str) -> Option<u64> {
        self.objects.values().find_map(|v| match &v.value {
            ObjectValue::GovParam(p) if p.key == key => p.value.parse::<u64>().ok(),
            _ => None,
        })
    }

    pub fn gov_param_u128(&self, key: &str) -> Option<u128> {
        self.objects.values().find_map(|v| match &v.value {
            ObjectValue::GovParam(p) if p.key == key => p.value.parse::<u128>().ok(),
            _ => None,
        })
    }

    pub fn state_root(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        for (id, v) in &self.objects {
            hasher.update(id.to_le_bytes());
            hasher.update(v.version.to_le_bytes());
            match &v.value {
                ObjectValue::Task(t) => {
                    hasher.update(b"task");
                    hasher.update(t.creator.as_bytes());
                    hasher.update(t.bounty.to_le_bytes());
                    hasher.update((t.status as u8).to_le_bytes());
                }
                ObjectValue::GovProposal(p) => {
                    hasher.update(b"gov_proposal");
                    hasher.update(p.title.as_bytes());
                    hasher.update(p.proposer.as_bytes());
                    hasher.update((p.status as u8).to_le_bytes());
                }
                ObjectValue::GovParam(p) => {
                    hasher.update(b"gov_param");
                    hasher.update(p.key.as_bytes());
                    hasher.update(p.value.as_bytes());
                }
            }
        }
        hasher.finalize().into()
    }
}

pub fn verify_wal_and_find_checkpoint(
    checkpoints: &[CheckpointMeta],
    wal_entries: &[WalMeta],
) -> Result<Option<CheckpointMeta>, String> {
    let mut prev_hash: Option<String> = None;
    let mut valid_checkpoints: Vec<CheckpointMeta> = Vec::new();

    for e in wal_entries {
        if e.prev_hash_hex != prev_hash {
            return Ok(valid_checkpoints.pop());
        }
        let cur_hash = e.content_hash_hex();
        prev_hash = Some(cur_hash.clone());

        for cp in checkpoints.iter().filter(|cp| cp.height == e.height) {
            if cp.state_root_hex == e.state_root_hex
                && cur_hash.as_str() == cp.wal_entry_hash_hex.as_str()
            {
                valid_checkpoints.push(cp.clone());
            }
        }
    }

    Ok(valid_checkpoints.pop())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::TaskStatus;

    #[test]
    fn put_and_version_update() {
        let mut st = StateStore::new();
        let t = TaskObject {
            task_id: 7,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Open,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
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
    fn version_conflict() {
        let mut st = StateStore::new();
        let t = TaskObject {
            task_id: 1,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Open,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenge_bond_forfeited: None,
            version: 1,
        };
        let r1 = st.put_task_new(t.clone()).unwrap();
        let _ = st.update_task(r1.clone(), t.clone()).unwrap();
        let err = st.update_task(r1, t).unwrap_err();
        assert!(err.contains("version conflict"));
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
    fn governance_param_whitelist_enforced() {
        let mut st = StateStore::new();
        let ok = st
            .set_gov_param(7001, "max_block_ms".into(), "10".into())
            .unwrap();
        assert_eq!(ok.version, 1);

        let cur = st.get_param(7001).unwrap();
        assert_eq!(cur.key, "max_block_ms");
        assert_eq!(cur.value, "10");

        let err = st
            .set_gov_param(7002, "forbidden_key".into(), "1".into())
            .unwrap_err();
        assert!(err.contains("not allowed"));
    }

    #[test]
    fn governance_param_schema_rejects_invalid_u64_values() {
        let mut st = StateStore::new();

        let err = st
            .set_gov_param(7101, "max_block_ms".into(), "abc".into())
            .unwrap_err();
        assert!(err.contains("expected u64"));

        let err = st
            .set_gov_param(7102, "challenge_window_blocks".into(), "99".into())
            .unwrap_err();
        assert!(err.contains("out of range"));

        let err = st
            .set_gov_param(7103, "min_worker_stake".into(), "0".into())
            .unwrap_err();
        assert!(err.contains("out of range"));

        let err = st
            .set_gov_param(7104, "challenge_min_bond".into(), "0".into())
            .unwrap_err();
        assert!(err.contains("out of range"));
    }

    #[test]
    fn emergency_pause_requires_strict_bool_literal() {
        let mut st = StateStore::new();

        for bad in ["TRUE", "False", "1", "yes"] {
            let err = st
                .set_gov_param(7200, "emergency_pause".into(), bad.into())
                .unwrap_err();
            assert!(err.contains("strict bool"));
        }

        st.set_gov_param(7200, "emergency_pause".into(), "true".into())
            .unwrap();
        assert!(st.is_emergency_paused());

        st.set_gov_param(7200, "emergency_pause".into(), "false".into())
            .unwrap();
        assert!(!st.is_emergency_paused());
    }

    #[test]
    fn emergency_pause_flag_works() {
        let mut st = StateStore::new();
        assert!(!st.is_emergency_paused());

        st.set_gov_param(7999, "emergency_pause".into(), "true".into())
            .unwrap();
        assert!(st.is_emergency_paused());

        st.set_gov_param(7999, "emergency_pause".into(), "false".into())
            .unwrap();
        assert!(!st.is_emergency_paused());
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
}
