use sha2::{Digest, Sha256};

use crate::{ObjectValue, StateStore};
use trnm_types::{Hash32, PrivacyTier, TaskMetadata, TaskMeteringSnapshot, TaskModelMetadata, TaskProvenanceMetadata};

fn hash_u8(hasher: &mut Sha256, value: u8) {
    hasher.update([value]);
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn hash_u128(hasher: &mut Sha256, value: u128) {
    hasher.update(value.to_le_bytes());
}

fn hash_i128(hasher: &mut Sha256, value: i128) {
    hasher.update(value.to_le_bytes());
}

fn hash_str(hasher: &mut Sha256, value: &str) {
    hash_u64(hasher, value.len() as u64);
    hasher.update(value.as_bytes());
}

fn hash_optional_str(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hash_u8(hasher, 1);
            hash_str(hasher, value);
        }
        None => hash_u8(hasher, 0),
    }
}

fn hash_optional_u64(hasher: &mut Sha256, value: Option<u64>) {
    match value {
        Some(value) => {
            hash_u8(hasher, 1);
            hash_u64(hasher, value);
        }
        None => hash_u8(hasher, 0),
    }
}

fn hash_optional_u128(hasher: &mut Sha256, value: Option<u128>) {
    match value {
        Some(value) => {
            hash_u8(hasher, 1);
            hash_u128(hasher, value);
        }
        None => hash_u8(hasher, 0),
    }
}

fn hash_optional_bool(hasher: &mut Sha256, value: Option<bool>) {
    match value {
        Some(value) => {
            hash_u8(hasher, 1);
            hash_u8(hasher, value as u8);
        }
        None => hash_u8(hasher, 0),
    }
}

fn hash_optional_bytes<const N: usize>(hasher: &mut Sha256, value: Option<&[u8; N]>) {
    match value {
        Some(value) => {
            hash_u8(hasher, 1);
            hasher.update(value);
        }
        None => hash_u8(hasher, 0),
    }
}

fn hash_privacy_tier(hasher: &mut Sha256, value: Option<&PrivacyTier>) {
    match value {
        Some(PrivacyTier::Public) => {
            hash_u8(hasher, 1);
            hash_u8(hasher, 0);
        }
        Some(PrivacyTier::Internal) => {
            hash_u8(hasher, 1);
            hash_u8(hasher, 1);
        }
        Some(PrivacyTier::Restricted) => {
            hash_u8(hasher, 1);
            hash_u8(hasher, 2);
        }
        None => hash_u8(hasher, 0),
    }
}

fn hash_task_model_metadata(hasher: &mut Sha256, model: Option<&TaskModelMetadata>) {
    match model {
        Some(model) => {
            hash_u8(hasher, 1);
            hash_optional_str(hasher, model.model_id.as_deref());
            hash_optional_str(hasher, model.model_digest.as_deref());
            hash_optional_str(hasher, model.version.as_deref());
        }
        None => hash_u8(hasher, 0),
    }
}

fn hash_task_provenance_metadata(hasher: &mut Sha256, provenance: Option<&TaskProvenanceMetadata>) {
    match provenance {
        Some(provenance) => {
            hash_u8(hasher, 1);
            hash_optional_str(hasher, provenance.producer_did.as_deref());
            hash_optional_str(hasher, provenance.produced_at.as_deref());
            hash_optional_str(hasher, provenance.provenance_index.as_deref());
            hash_privacy_tier(hasher, provenance.privacy_tier.as_ref());
        }
        None => hash_u8(hasher, 0),
    }
}

fn hash_task_metering_snapshot(hasher: &mut Sha256, metering: Option<&TaskMeteringSnapshot>) {
    match metering {
        Some(metering) => {
            hash_u8(hasher, 1);
            hash_str(hasher, &metering.workload_class);
            hash_str(hasher, &metering.metering_schema);
            hash_u8(hasher, metering.policy_snapshot_version);
            hash_str(hasher, &metering.receipt_hash);
            hash_u64(hasher, metering.prompt_tokens);
            hash_u64(hasher, metering.generated_tokens);
            hash_u64(hasher, metering.decode_steps);
            hash_u64(hasher, metering.kv_bytes_moved);
            hash_u128(hasher, metering.normalized_work_units);
            hash_u128(hasher, metering.prompt_token_weight);
            hash_u128(hasher, metering.generated_token_weight);
            hash_u128(hasher, metering.decode_step_weight);
            hash_u128(hasher, metering.kv_byte_weight);
            hash_u128(hasher, metering.min_accept_work_units);
            hash_u128(hasher, metering.challenge_success_bounty_base);
            hash_u128(hasher, metering.challenge_success_bounty_per_work_unit_num);
            hash_u128(hasher, metering.challenge_success_bounty_per_work_unit_den);
            hash_u128(hasher, metering.worker_completion_bonus_per_work_unit_num);
            hash_u128(hasher, metering.worker_completion_bonus_per_work_unit_den);
            hash_u128(hasher, metering.worker_slash_rebate_per_work_unit_num);
            hash_u128(hasher, metering.worker_slash_rebate_per_work_unit_den);
        }
        None => hash_u8(hasher, 0),
    }
}

fn hash_task_metadata(hasher: &mut Sha256, metadata: Option<&TaskMetadata>) {
    match metadata {
        Some(metadata) => {
            hash_u8(hasher, 1);
            hash_optional_str(hasher, metadata.note.as_deref());
            hash_optional_str(hasher, metadata.task_type.as_deref());
            hash_optional_str(hasher, metadata.input_hash.as_deref());
            hash_task_model_metadata(hasher, metadata.model.as_ref());
            hash_task_provenance_metadata(hasher, metadata.provenance.as_ref());
            hash_task_metering_snapshot(hasher, metadata.metering.as_ref());
        }
        None => hash_u8(hasher, 0),
    }
}

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
            hash_u64(&mut hasher, *task_id);
            hash_u8(&mut hasher, pending.slash_worker as u8);
            hash_u8(&mut hasher, pending.confirmations);
            hash_str(&mut hasher, &pending.first_approver);
            hash_str(&mut hasher, &pending.authority_set);
            hash_u64(&mut hasher, pending.task_version);
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
