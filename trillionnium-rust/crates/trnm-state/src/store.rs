use std::collections::BTreeMap;
use std::sync::RwLock;

use crate::{MonetaryState, PendingGovParamUpdate};
use trnm_types::{
    GovParamObject, GovProposalObject, GovProposalStatus, Hash32, ObjectRef, TaskObject,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectValue {
    Task(TaskObject),
    GovProposal(GovProposalObject),
    GovParam(GovParamObject),
}

#[derive(Debug)]
pub struct StateStore {
    pub(crate) objects: BTreeMap<u64, VersionedObject>,
    pub(crate) balances: BTreeMap<String, u128>,
    pub(crate) pending_gov_updates: BTreeMap<String, PendingGovParamUpdate>,
    pub(crate) gov_param_key_index: BTreeMap<String, u64>,
    pub(crate) pending_resolve_approvals: BTreeMap<u64, PendingResolveApproval>,
    pub(crate) monetary_state: MonetaryState,
    pub(crate) state_root_cache: RwLock<Option<Hash32>>,
}

#[derive(Debug, Clone)]
pub(crate) struct VersionedObject {
    pub(crate) version: u64,
    pub(crate) value: ObjectValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingResolveApproval {
    pub(crate) slash_worker: bool,
    pub(crate) confirmations: u8,
    pub(crate) first_approver: String,
    pub(crate) authority_set: String,
    pub(crate) task_version: u64,
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

    pub(crate) fn invalidate_state_root_cache(&self) {
        self.state_root_cache
            .write()
            .expect("state root cache poisoned")
            .take();
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
        if !matches!(current.value, ObjectValue::Task(_)) {
            return Err("object type mismatch".into());
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
        if !matches!(current.value, ObjectValue::GovProposal(_)) {
            return Err("object type mismatch".into());
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
}
