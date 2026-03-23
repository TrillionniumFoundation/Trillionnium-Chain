use crate::{
    store::PendingResolveApproval, validated_restorable_pending_resolve_snapshot, StateStore,
    CHALLENGE_ESCROW_ACCOUNT, CHALLENGE_FORFEIT_TREASURY_ACCOUNT,
    DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER, RESERVED_SYSTEM_AUTHORITY,
    WORKER_SLASH_TREASURY_ACCOUNT,
};
use trnm_types::TaskStatus;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingResolveApprovalSnapshot {
    pub slash_worker: bool,
    pub confirmations: u8,
    pub first_approver: String,
    pub authority_set: String,
    pub task_version: u64,
}

fn validate_resolve_approval_approver(approver: &str) -> Result<String, String> {
    let approver_trimmed = approver.trim();
    if approver_trimmed.is_empty() {
        return Err("resolve approval approver must be non-empty".into());
    }
    if approver_trimmed != approver || approver_trimmed.chars().any(|c| c.is_whitespace()) {
        return Err("resolve approval approver must not contain whitespace".into());
    }
    if approver_trimmed.contains(',') || approver_trimmed.contains(';') {
        return Err("resolve approval approver must be a single canonical actor id".into());
    }
    if approver_trimmed.eq_ignore_ascii_case(DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER)
        || approver_trimmed.eq_ignore_ascii_case(RESERVED_SYSTEM_AUTHORITY)
        || approver_trimmed.eq_ignore_ascii_case(CHALLENGE_ESCROW_ACCOUNT)
        || approver_trimmed.eq_ignore_ascii_case(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        || approver_trimmed.eq_ignore_ascii_case(WORKER_SLASH_TREASURY_ACCOUNT)
    {
        return Err("resolve approval approver must be an explicit non-system authority".into());
    }
    Ok(approver_trimmed.to_ascii_lowercase())
}

fn validate_resolve_approval_authority_set(authority_set: &str) -> Result<Vec<String>, String> {
    let authority_trimmed = authority_set.trim();
    if authority_trimmed.is_empty() || authority_trimmed != authority_set {
        return Err(
            "resolve approval authority set must be a canonical comma-delimited actor list".into(),
        );
    }
    let authority_members: Vec<&str> = authority_trimmed.split(',').collect();
    if authority_members.len() < 2 {
        return Err("resolve approval authority set must include at least two members".into());
    }
    let has_forbidden_separator = |token: &str| {
        token.contains(';')
            || token.contains('|')
            || token.contains('；')
            || token.contains('，')
            || token.contains('、')
    };
    let mut seen_members = std::collections::BTreeSet::new();
    let mut canonical_members = Vec::with_capacity(authority_members.len());
    for member in &authority_members {
        let member_trimmed = member.trim();
        if member_trimmed.is_empty()
            || member_trimmed != *member
            || member_trimmed.chars().any(|c| c.is_whitespace())
            || has_forbidden_separator(member_trimmed)
            || !member_trimmed.is_ascii()
            || member_trimmed.eq_ignore_ascii_case(DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER)
            || member_trimmed.eq_ignore_ascii_case(RESERVED_SYSTEM_AUTHORITY)
            || member_trimmed.eq_ignore_ascii_case(CHALLENGE_ESCROW_ACCOUNT)
            || member_trimmed.eq_ignore_ascii_case(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
            || member_trimmed.eq_ignore_ascii_case(WORKER_SLASH_TREASURY_ACCOUNT)
        {
            return Err(
                "resolve approval authority set contains non-canonical or forbidden member".into(),
            );
        }
        let canonical_member = member_trimmed.to_ascii_lowercase();
        if !seen_members.insert(canonical_member.clone()) {
            return Err("resolve approval authority set must not contain duplicate members".into());
        }
        canonical_members.push(canonical_member);
    }
    Ok(canonical_members)
}

fn validate_pending_resolve_snapshot(snapshot: &PendingResolveApprovalSnapshot) -> Result<(), String> {
    if !(1..=2).contains(&snapshot.confirmations) {
        return Err("resolve approval snapshot confirmations must be between 1 and 2".into());
    }
    let approver = validate_resolve_approval_approver(&snapshot.first_approver)?;
    let authority_members = validate_resolve_approval_authority_set(&snapshot.authority_set)?;
    if !authority_members.iter().any(|member| member == &approver) {
        return Err("resolve approval approver must be a configured authority member".into());
    }
    Ok(())
}

impl StateStore {
    pub fn stage_or_confirm_resolve_approval(
        &mut self,
        task_id: u64,
        task_version: u64,
        slash_worker: bool,
        approver: &str,
        authority_set: &str,
    ) -> Result<bool, String> {
        let approver_trimmed = validate_resolve_approval_approver(approver)?;
        let authority_members = validate_resolve_approval_authority_set(authority_set)?;
        if !authority_members.iter().any(|member| member == &approver_trimmed) {
            return Err("resolve approval approver must be a configured authority member".into());
        }

        if let Some(entry) = self.pending_resolve_approvals.get(&task_id) {
            if entry.authority_set != authority_set {
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
                    first_approver: approver_trimmed.to_string(),
                    authority_set: authority_set.to_string(),
                    task_version,
                });
        if entry.slash_worker != slash_worker {
            return Err("resolve approval decision mismatch".into());
        }
        if entry.confirmations >= 2 {
            return Err("resolve approval already finalized; clear pending approval first".into());
        }
        if entry.confirmations > 0 && entry.first_approver.eq_ignore_ascii_case(approver_trimmed) {
            return Err("resolve approval requires distinct approver".into());
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
        match snapshot {
            Some(snapshot) => {
                if validate_pending_resolve_snapshot(&snapshot).is_ok() {
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
                } else {
                    self.pending_resolve_approvals.remove(&task_id);
                }
            }
            None => {
                self.pending_resolve_approvals.remove(&task_id);
            }
        }
    }
}
