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
                    hash_u64(&mut hasher, t.task_id);
                    hash_str(&mut hasher, &t.creator);
                    hash_u128(&mut hasher, t.bounty);
                    hash_u8(&mut hasher, t.status as u8);
                    hash_u8(&mut hasher, t.proof_type as u8);
                    hash_task_metadata(&mut hasher, t.metadata.as_ref());
                    hash_optional_str(&mut hasher, t.worker.as_deref());
                    hash_optional_bytes(&mut hasher, t.committed_hash.as_ref());
                    hash_optional_bytes(&mut hasher, t.result_hash.as_ref());
                    hash_optional_bytes(&mut hasher, t.reveal_salt.as_ref());
                    hash_optional_u64(&mut hasher, t.committed_at_height);
                    hash_optional_u64(&mut hasher, t.reveal_deadline_height);
                    hash_optional_u64(&mut hasher, t.challenge_deadline_height);
                    hash_optional_u64(&mut hasher, t.challenge_window_blocks_snapshot);
                    hash_optional_u64(&mut hasher, t.challenged_at_height);
                    hash_optional_u64(&mut hasher, t.resolve_deadline_height);
                    hash_optional_u128(&mut hasher, t.challenge_bond);
                    hash_optional_str(&mut hasher, t.challenger.as_deref());
                    hash_optional_bool(&mut hasher, t.challenge_bond_forfeited);
                    hash_u64(&mut hasher, t.version);
                }
                ObjectValue::GovProposal(p) => {
                    hasher.update(b"gov_proposal");
                    hash_u64(&mut hasher, p.proposal_id);
                    hash_str(&mut hasher, &p.title);
                    hash_str(&mut hasher, &p.proposer);
                    hash_u8(&mut hasher, p.status as u8);
                    hash_u64(&mut hasher, p.version);
                }
                ObjectValue::GovParam(p) => {
                    hasher.update(b"gov_param");
                    hash_u64(&mut hasher, p.key_id);
                    hash_str(&mut hasher, &p.key);
                    hash_str(&mut hasher, &p.value);
                    hash_u64(&mut hasher, p.version);
                }
            }
        }
        for (addr, bal) in &self.balances {
            hasher.update(b"balance");
            hash_str(&mut hasher, addr);
            hash_u128(&mut hasher, *bal);
        }
        for (key, pending) in &self.pending_gov_updates {
            hasher.update(b"gov_pending");
            hash_str(&mut hasher, key);
            hash_u64(&mut hasher, pending.key_id);
            hash_str(&mut hasher, &pending.key);
            hash_str(&mut hasher, &pending.value);
            hash_u64(&mut hasher, pending.activate_at_height);
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
