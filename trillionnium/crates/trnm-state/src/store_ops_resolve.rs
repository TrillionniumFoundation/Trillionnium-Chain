use crate::*;

impl StateStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stage_or_confirm_resolve_approval(
        &mut self,
        task_id: u64,
        task_version: u64,
        slash_worker: bool,
        approver: &str,
        authority_set: &str,
    ) -> Result<bool, String> {
        if task_id == 0 {
            return Err("resolve approval task id must be >= 1".into());
        }
        if task_version == 0 {
            return Err("resolve approval task version must be >= 1".into());
        }

        let approver_canonical = validate_resolve_approver_token(approver)?;
        let authority_canonical = canonicalize_resolve_authority_set(authority_set)?;
        if !authority_canonical
            .split(',')
            .any(|member| member == approver_canonical)
        {
            return Err("resolve approval approver must be a configured authority member".into());
        }
        if let Some(task) = self.get_task(task_id) {
            if task.status != TaskStatus::Challenged {
                if self.pending_resolve_approvals.remove(&task_id).is_some() {
                    self.invalidate_state_root_cache();
                }
                return Err("resolve approval task no longer challenged".into());
            }
            if task.version != task_version {
                if self.pending_resolve_approvals.remove(&task_id).is_some() {
                    self.invalidate_state_root_cache();
                }
                return Err("resolve approval task version changed".into());
            }
        }
        ensure_effective_resolve_authority_match(self, authority_set)?;

        if let Some(entry) = self.pending_resolve_approvals.get(&task_id) {
            if entry.confirmations >= 2 {
                return Err(
                    "resolve approval already finalized; clear pending approval first".into(),
                );
            }
            let entry_authority_canonical =
                canonicalize_resolve_authority_set(&entry.authority_set)
                    .map_err(|_| "resolve approval authority set changed".to_string())?;
            if entry_authority_canonical != authority_canonical {
                self.invalidate_state_root_cache();
                self.pending_resolve_approvals.remove(&task_id);
                return Err("resolve approval authority set changed".into());
            }
            if entry.task_version != task_version {
                self.invalidate_state_root_cache();
                self.pending_resolve_approvals.remove(&task_id);
                return Err("resolve approval task version changed".into());
            }
        }

        self.invalidate_state_root_cache();
        let entry =
            self.pending_resolve_approvals
                .entry(task_id)
                .or_insert(PendingResolveApproval {
                    slash_worker,
                    confirmations: 0,
                    first_approver: approver.trim().to_string(),
                    authority_set: authority_set.to_string(),
                    task_version,
                });
        if entry.slash_worker != slash_worker {
            return Err("resolve approval decision mismatch".into());
        }
        if entry.confirmations >= 2 {
            return Err("resolve approval already finalized; clear pending approval first".into());
        }
        if entry.confirmations > 0 {
            let first_approver_canonical =
                validate_resolve_approver_token(&entry.first_approver)
                    .map_err(|_| "resolve approval requires distinct approver".to_string())?;
            if first_approver_canonical == approver_canonical {
                return Err("resolve approval requires distinct approver".into());
            }
        }
        entry.confirmations = entry.confirmations.saturating_add(1);
        Ok(entry.confirmations >= 2)
    }

    pub fn clear_pending_resolve_approval(&mut self, task_id: u64) {
        self.invalidate_state_root_cache();
        self.pending_resolve_approvals.remove(&task_id);
    }

    pub fn pending_resolve_approval(&self, task_id: u64) -> Option<(bool, u8)> {
        self.pending_resolve_approvals
            .get(&task_id)
            .map(|entry| (entry.slash_worker, entry.confirmations))
    }

    pub fn pending_resolve_first_approver(&self, task_id: u64) -> Option<String> {
        self.pending_resolve_approvals
            .get(&task_id)
            .map(|entry| entry.first_approver.clone())
    }

    pub fn pending_resolve_approval_snapshot(
        &self,
        task_id: u64,
    ) -> Option<PendingResolveApprovalSnapshot> {
        self.pending_resolve_approvals
            .get(&task_id)
            .map(|entry| PendingResolveApprovalSnapshot {
                slash_worker: entry.slash_worker,
                confirmations: entry.confirmations,
                first_approver: entry.first_approver.clone(),
                authority_set: entry.authority_set.clone(),
                task_version: entry.task_version,
            })
    }

    pub fn restore_pending_resolve_approval(
        &mut self,
        task_id: u64,
        snapshot: Option<PendingResolveApprovalSnapshot>,
    ) {
        self.invalidate_state_root_cache();
        self.pending_resolve_approvals.remove(&task_id);

        let Some(snapshot) = snapshot else {
            return;
        };
        if task_id == 0 || snapshot.task_version == 0 {
            return;
        }
        if snapshot.confirmations != 1 {
            return;
        }
        let Ok(first_approver_canonical) =
            validate_resolve_approver_token(&snapshot.first_approver)
        else {
            return;
        };
        let Ok(authority_canonical) = canonicalize_resolve_authority_set(&snapshot.authority_set)
        else {
            return;
        };
        if !authority_canonical
            .split(',')
            .any(|member| member == first_approver_canonical)
        {
            return;
        }
        if !is_effective_resolve_authority_match(self, &snapshot.authority_set) {
            return;
        }
        let Some(task) = self.get_task(task_id) else {
            return;
        };
        if task.status != TaskStatus::Challenged || task.version != snapshot.task_version {
            return;
        }
        if snapshot.slash_worker
            && task
                .worker
                .as_deref()
                .is_some_and(resolve_actor_is_reserved)
        {
            return;
        }

        self.pending_resolve_approvals.insert(
            task_id,
            PendingResolveApproval {
                slash_worker: snapshot.slash_worker,
                confirmations: snapshot.confirmations,
                first_approver: snapshot.first_approver,
                authority_set: snapshot.authority_set,
                task_version: snapshot.task_version,
            },
        );
    }
}
