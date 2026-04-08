use sha2::{Digest, Sha256};

use crate::{ObjectValue, StateStore};
use trnm_types::{Hash32, PrivacyTier, TaskMetadata, TaskMeteringSnapshot, TaskModelMetadata, TaskProvenanceMetadata};

fn hash_bytes_with_len(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hash_str_with_len(hasher: &mut Sha256, value: &str) {
    hash_bytes_with_len(hasher, value.as_bytes());
}

fn hash_optional_str(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_str_with_len(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn hash_task_model_metadata(hasher: &mut Sha256, model: Option<&TaskModelMetadata>) {
    match model {
        Some(model) => {
            hasher.update([1]);
            hash_optional_str(hasher, model.model_id.as_deref());
            hash_optional_str(hasher, model.model_digest.as_deref());
            hash_optional_str(hasher, model.version.as_deref());
        }
        None => hasher.update([0]),
    }
}

fn hash_privacy_tier(hasher: &mut Sha256, tier: Option<&PrivacyTier>) {
    match tier {
        Some(PrivacyTier::Public) => hasher.update([1, 0]),
        Some(PrivacyTier::Internal) => hasher.update([1, 1]),
        Some(PrivacyTier::Restricted) => hasher.update([1, 2]),
        None => hasher.update([0]),
    }
}

fn hash_task_provenance_metadata(hasher: &mut Sha256, provenance: Option<&TaskProvenanceMetadata>) {
    match provenance {
        Some(provenance) => {
            hasher.update([1]);
            hash_optional_str(hasher, provenance.producer_did.as_deref());
            hash_optional_str(hasher, provenance.produced_at.as_deref());
            hash_optional_str(hasher, provenance.provenance_index.as_deref());
            hash_privacy_tier(hasher, provenance.privacy_tier.as_ref());
        }
        None => hasher.update([0]),
    }
}

fn hash_task_metering_snapshot(hasher: &mut Sha256, metering: Option<&TaskMeteringSnapshot>) {
    match metering {
        Some(metering) => {
            hasher.update([1]);
            hash_str_with_len(hasher, &metering.workload_class);
            hash_str_with_len(hasher, &metering.metering_schema);
            hasher.update([metering.policy_snapshot_version]);
            hash_str_with_len(hasher, &metering.receipt_hash);
            hasher.update(metering.prompt_tokens.to_le_bytes());
            hasher.update(metering.generated_tokens.to_le_bytes());
            hasher.update(metering.decode_steps.to_le_bytes());
            hasher.update(metering.kv_bytes_moved.to_le_bytes());
            hasher.update(metering.normalized_work_units.to_le_bytes());
            hasher.update(metering.prompt_token_weight.to_le_bytes());
            hasher.update(metering.generated_token_weight.to_le_bytes());
            hasher.update(metering.decode_step_weight.to_le_bytes());
            hasher.update(metering.kv_byte_weight.to_le_bytes());
            hasher.update(metering.min_accept_work_units.to_le_bytes());
            hasher.update(metering.challenge_success_bounty_base.to_le_bytes());
            hasher.update(metering.challenge_success_bounty_per_work_unit_num.to_le_bytes());
            hasher.update(metering.challenge_success_bounty_per_work_unit_den.to_le_bytes());
            hasher.update(metering.worker_completion_bonus_per_work_unit_num.to_le_bytes());
            hasher.update(metering.worker_completion_bonus_per_work_unit_den.to_le_bytes());
            hasher.update(metering.worker_slash_rebate_per_work_unit_num.to_le_bytes());
            hasher.update(metering.worker_slash_rebate_per_work_unit_den.to_le_bytes());
        }
        None => hasher.update([0]),
    }
}

fn hash_task_metadata(hasher: &mut Sha256, metadata: Option<&TaskMetadata>) {
    match metadata {
        Some(metadata) => {
            hasher.update([1]);
            hash_optional_str(hasher, metadata.note.as_deref());
            hash_optional_str(hasher, metadata.task_type.as_deref());
            hash_optional_str(hasher, metadata.input_hash.as_deref());
            hash_task_model_metadata(hasher, metadata.model.as_ref());
            hash_task_provenance_metadata(hasher, metadata.provenance.as_ref());
            hash_task_metering_snapshot(hasher, metadata.metering.as_ref());
        }
        None => hasher.update([0]),
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
                    hasher.update(t.task_id.to_le_bytes());
                    hash_str_with_len(&mut hasher, &t.creator);
                    hasher.update(t.bounty.to_le_bytes());
                    hasher.update((t.status as u8).to_le_bytes());
                    hasher.update((t.proof_type as u8).to_le_bytes());
                    hash_task_metadata(&mut hasher, t.metadata.as_ref());

                    match &t.worker {
                        Some(worker) => {
                            hasher.update([1]);
                            hash_str_with_len(&mut hasher, worker);
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
                            hash_str_with_len(&mut hasher, challenger);
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
                    hash_str_with_len(&mut hasher, &p.title);
                    hash_str_with_len(&mut hasher, &p.proposer);
                    hasher.update((p.status as u8).to_le_bytes());
                    hasher.update(p.version.to_le_bytes());
                }
                ObjectValue::GovParam(p) => {
                    hasher.update(b"gov_param");
                    hash_str_with_len(&mut hasher, &p.key);
                    hash_str_with_len(&mut hasher, &p.value);
                    hasher.update(p.version.to_le_bytes());
                }
            }
        }
        for (addr, bal) in &self.balances {
            hasher.update(b"balance");
            hash_str_with_len(&mut hasher, addr);
            hasher.update(bal.to_le_bytes());
        }
        for (key, pending) in &self.pending_gov_updates {
            hasher.update(b"gov_pending");
            hash_str_with_len(&mut hasher, key);
            hasher.update(pending.key_id.to_le_bytes());
            hash_str_with_len(&mut hasher, &pending.value);
            hasher.update(pending.activate_at_height.to_le_bytes());
        }
        for (task_id, pending) in &self.pending_resolve_approvals {
            hasher.update(b"resolve_pending");
            hasher.update(task_id.to_le_bytes());
            hasher.update([pending.slash_worker as u8]);
            hasher.update([pending.confirmations]);
            hash_str_with_len(&mut hasher, &pending.first_approver);
            hash_str_with_len(&mut hasher, &pending.authority_set);
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
