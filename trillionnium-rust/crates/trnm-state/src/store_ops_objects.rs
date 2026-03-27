use crate::*;
use trnm_types::{GovProposalObject, TaskObject};

impl StateStore {
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

    pub(crate) fn remove_gov_param_key_index_for_id(&mut self, id: u64) {
        self.gov_param_key_index
            .retain(|_, mapped_id| *mapped_id != id);
    }

    pub fn put_task_new(&mut self, mut task: TaskObject) -> Result<ObjectRef, String> {
        if task.task_id == 0 {
            return Err("task id must be non-zero".into());
        }
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
        if !matches!(current.value, ObjectValue::Task(_)) {
            return Err("object type mismatch".into());
        }
        if task.task_id != expected.id {
            return Err("task id mismatch".into());
        }
        if current.version != expected.version {
            return Err("version conflict".into());
        }
        if !matches!(current.value, ObjectValue::Task(_)) {
            return Err("object type mismatch".into());
        }
        if task.version != expected.version {
            return Err("payload version mismatch".into());
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
        if proposal.proposal_id == 0 {
            return Err("proposal id must be non-zero".into());
        }
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
        if !matches!(current.value, ObjectValue::GovProposal(_)) {
            return Err("object type mismatch".into());
        }
        if proposal.proposal_id != expected.id {
            return Err("proposal id mismatch".into());
        }
        if current.version != expected.version {
            return Err("version conflict".into());
        }
        if !matches!(current.value, ObjectValue::GovProposal(_)) {
            return Err("object type mismatch".into());
        }
        if proposal.version != expected.version {
            return Err("payload version mismatch".into());
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
