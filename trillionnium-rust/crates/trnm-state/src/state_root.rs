use sha2::{Digest, Sha256};

use crate::{
    canonicalize_resolve_authority_set, validate_resolve_approver_token, ObjectValue, StateStore,
};
use trnm_types::Hash32;

impl StateStore {
    pub fn state_root(&self) -> Hash32 {
        if let Some(cached) = self
            .state_root_cache
            .read()
            .expect("state root cache poisoned")
            .clone()
        {
            return cached;
        }

        let mut cache_guard = self
            .state_root_cache
            .write()
            .expect("state root cache poisoned");
        if let Some(cached) = cache_guard.clone() {
            return cached;
        }

        let mut hasher = Sha256::new();
        for (id, v) in &self.objects {
            hasher.update(id.to_le_bytes());
            hasher.update(v.version.to_le_bytes());
            match &v.value {
                ObjectValue::Task(t) => {
                    hasher.update(b"task");
                    hasher.update(t.task_id.to_le_bytes());
                    hasher.update(t.creator.as_bytes());
                    hasher.update(t.bounty.to_le_bytes());
                    hasher.update((t.status as u8).to_le_bytes());

                    match &t.worker {
                        Some(worker) => {
                            hasher.update([1]);
                            hasher.update(worker.as_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match &t.committed_hash {
                        Some(h) => {
                            hasher.update([1]);
                            hasher.update(h);
                        }
                        None => hasher.update([0]),
                    }
                    match &t.result_hash {
                        Some(h) => {
                            hasher.update([1]);
                            hasher.update(h);
                        }
                        None => hasher.update([0]),
                    }
                    match &t.reveal_salt {
                        Some(salt) => {
                            hasher.update([1]);
                            hasher.update(salt);
                        }
                        None => hasher.update([0]),
                    }

                    match t.committed_at_height {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update(v.to_le_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match t.reveal_deadline_height {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update(v.to_le_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match t.challenge_deadline_height {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update(v.to_le_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match t.challenge_window_blocks_snapshot {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update(v.to_le_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match t.challenged_at_height {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update(v.to_le_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match t.resolve_deadline_height {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update(v.to_le_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match t.challenge_bond {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update(v.to_le_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match &t.challenger {
                        Some(challenger) => {
                            hasher.update([1]);
                            hasher.update(challenger.as_bytes());
                        }
                        None => hasher.update([0]),
                    }
                    match t.challenge_bond_forfeited {
                        Some(v) => {
                            hasher.update([1]);
                            hasher.update([v as u8]);
                        }
                        None => hasher.update([0]),
                    }
                    hasher.update(t.version.to_le_bytes());
                }
                ObjectValue::GovProposal(p) => {
                    hasher.update(b"gov_proposal");
                    hasher.update(p.proposal_id.to_le_bytes());
                    hasher.update(p.title.as_bytes());
                    hasher.update(p.proposer.as_bytes());
                    hasher.update((p.status as u8).to_le_bytes());
                    hasher.update(p.version.to_le_bytes());
                }
                ObjectValue::GovParam(p) => {
                    hasher.update(b"gov_param");
                    hasher.update(p.key.as_bytes());
                    hasher.update(p.value.as_bytes());
                    hasher.update(p.version.to_le_bytes());
                }
            }
        }
        for (addr, bal) in &self.balances {
            hasher.update(b"balance");
            hasher.update(addr.as_bytes());
            hasher.update(bal.to_le_bytes());
        }
        for (key, pending) in &self.pending_gov_updates {
            hasher.update(b"gov_pending");
            hasher.update(key.as_bytes());
            hasher.update(pending.key_id.to_le_bytes());
            hasher.update(pending.value.as_bytes());
            hasher.update(pending.activate_at_height.to_le_bytes());
        }
        for (task_id, pending) in &self.pending_resolve_approvals {
            hasher.update(b"resolve_pending");
            hasher.update(task_id.to_le_bytes());
            hasher.update([pending.slash_worker as u8]);
            hasher.update([pending.confirmations]);

            let hashed_first_approver = validate_resolve_approver_token(&pending.first_approver)
                .unwrap_or_else(|_| pending.first_approver.clone());
            let hashed_authority_set = canonicalize_resolve_authority_set(&pending.authority_set)
                .unwrap_or_else(|_| pending.authority_set.clone());

            hasher.update(hashed_first_approver.as_bytes());
            hasher.update(hashed_authority_set.as_bytes());
            hasher.update(pending.task_version.to_le_bytes());
        }
        hasher.update(b"monetary_state");
        hasher.update(self.monetary_state.last_tick_height.to_le_bytes());
        hasher.update(self.monetary_state.tick_count.to_le_bytes());
        hasher.update(self.monetary_state.total_minted.to_le_bytes());
        hasher.update(self.monetary_state.total_burned.to_le_bytes());
        hasher.update(self.monetary_state.net_issuance.to_le_bytes());
        let root: Hash32 = hasher.finalize().into();
        *cache_guard = Some(root.clone());
        root
    }
}
