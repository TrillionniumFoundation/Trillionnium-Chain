use sha2::{Digest, Sha256};

use crate::{ObjectValue, StateStore};
use trnm_types::Hash32;

fn hash_len_prefixed_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hash_len_prefixed_str(hasher: &mut Sha256, value: &str) {
    hash_len_prefixed_bytes(hasher, value.as_bytes());
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
                    hash_len_prefixed_str(&mut hasher, &t.creator);
                    hasher.update(t.bounty.to_le_bytes());
                    hasher.update((t.status as u8).to_le_bytes());
                    hasher.update((t.proof_type as u8).to_le_bytes());

                    match &t.metadata {
                        Some(metadata) => {
                            hasher.update([1]);
                            match &metadata.note {
                                Some(note) => {
                                    hasher.update([1]);
                                    hash_len_prefixed_str(&mut hasher, note);
                                }
                                None => hasher.update([0]),
                            }
                            match &metadata.task_type {
                                Some(task_type) => {
                                    hasher.update([1]);
                                    hash_len_prefixed_str(&mut hasher, task_type);
                                }
                                None => hasher.update([0]),
                            }
                            match &metadata.input_hash {
                                Some(input_hash) => {
                                    hasher.update([1]);
                                    hash_len_prefixed_str(&mut hasher, input_hash);
                                }
                                None => hasher.update([0]),
                            }
                            match &metadata.model {
                                Some(model) => {
                                    hasher.update([1]);
                                    match &model.model_id {
                                        Some(model_id) => {
                                            hasher.update([1]);
                                            hash_len_prefixed_str(&mut hasher, model_id);
                                        }
                                        None => hasher.update([0]),
                                    }
                                    match &model.model_digest {
                                        Some(model_digest) => {
                                            hasher.update([1]);
                                            hash_len_prefixed_str(&mut hasher, model_digest);
                                        }
                                        None => hasher.update([0]),
                                    }
                                    match &model.version {
                                        Some(version) => {
                                            hasher.update([1]);
                                            hash_len_prefixed_str(&mut hasher, version);
                                        }
                                        None => hasher.update([0]),
                                    }
                                }
                                None => hasher.update([0]),
                            }
                            match &metadata.provenance {
                                Some(provenance) => {
                                    hasher.update([1]);
                                    match &provenance.producer_did {
                                        Some(producer_did) => {
                                            hasher.update([1]);
                                            hash_len_prefixed_str(&mut hasher, producer_did);
                                        }
                                        None => hasher.update([0]),
                                    }
                                    match &provenance.produced_at {
                                        Some(produced_at) => {
                                            hasher.update([1]);
                                            hash_len_prefixed_str(&mut hasher, produced_at);
                                        }
                                        None => hasher.update([0]),
                                    }
                                    match &provenance.provenance_index {
                                        Some(provenance_index) => {
                                            hasher.update([1]);
                                            hash_len_prefixed_str(&mut hasher, provenance_index);
                                        }
                                        None => hasher.update([0]),
                                    }
                                    match &provenance.privacy_tier {
                                        Some(privacy_tier) => {
                                            hasher.update([1]);
                                            hasher.update(match privacy_tier {
                                                trnm_types::PrivacyTier::Public => {
                                                    b"public".as_slice()
                                                }
                                                trnm_types::PrivacyTier::Internal => {
                                                    b"internal".as_slice()
                                                }
                                                trnm_types::PrivacyTier::Restricted => {
                                                    b"restricted".as_slice()
                                                }
                                            });
                                        }
                                        None => hasher.update([0]),
                                    }
                                }
                                None => hasher.update([0]),
                            }
                        }
                        None => hasher.update([0]),
                    }

                    match &t.worker {
                        Some(worker) => {
                            hasher.update([1]);
                            hash_len_prefixed_str(&mut hasher, worker);
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
                            hash_len_prefixed_str(&mut hasher, challenger);
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
                    hash_len_prefixed_str(&mut hasher, &p.title);
                    hash_len_prefixed_str(&mut hasher, &p.proposer);
                    hasher.update((p.status as u8).to_le_bytes());
                    hasher.update(p.version.to_le_bytes());
                }
                ObjectValue::GovParam(p) => {
                    hasher.update(b"gov_param");
                    hasher.update(p.key_id.to_le_bytes());
                    hash_len_prefixed_str(&mut hasher, &p.key);
                    hash_len_prefixed_str(&mut hasher, &p.value);
                    hasher.update(p.version.to_le_bytes());
                }
            }
        }
        for (addr, bal) in &self.balances {
            hasher.update(b"balance");
            hash_len_prefixed_str(&mut hasher, addr);
            hasher.update(bal.to_le_bytes());
        }
        for (key, key_id) in &self.gov_param_key_index {
            hasher.update(b"gov_param_key_index");
            hash_len_prefixed_str(&mut hasher, key);
            hasher.update(key_id.to_le_bytes());
        }
        for (key, pending) in &self.pending_gov_updates {
            hasher.update(b"gov_pending");
            hash_len_prefixed_str(&mut hasher, key);
            hasher.update(pending.key_id.to_le_bytes());
            hash_len_prefixed_str(&mut hasher, &pending.key);
            hash_len_prefixed_str(&mut hasher, &pending.value);
            hasher.update(pending.activate_at_height.to_le_bytes());
        }
        for (task_id, pending) in &self.pending_resolve_approvals {
            hasher.update(b"resolve_pending");
            hasher.update(task_id.to_le_bytes());
            hasher.update([pending.slash_worker as u8]);
            hasher.update([pending.confirmations]);
            hash_len_prefixed_str(&mut hasher, &pending.first_approver);
            hash_len_prefixed_str(&mut hasher, &pending.authority_set);
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
