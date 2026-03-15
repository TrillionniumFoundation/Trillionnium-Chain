use sha2::{Digest as Sha256Digest, Sha256};
use sha3::Keccak256;

const ADMIN_UNSET: [u8; 32] = [0u8; 32];
use std::collections::HashSet;

const VALIDATOR_SIGNATURE_LEN: usize = 64;

pub fn action_settlement_finalize() -> [u8; 32] {
    Keccak256::digest(b"SETTLEMENT_FINALIZE").into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeSettlementMessage {
    pub source_chain_id: u64,
    pub source_bridge_id: [u8; 32],
    pub source_tx_hash: [u8; 32],
    pub source_log_index: u64,
    pub target_chain_id: u64,
    pub target_bridge: [u8; 20],
    pub receiver: [u8; 20],
    pub asset: [u8; 20],
    pub amount: u128,
    pub nonce: u64,
    pub deadline: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeRelayError {
    ProofExpired { now_ts: u64, deadline: u64 },
    ProofAlreadyUsed { proof_digest: [u8; 32] },
    NonceAlreadyUsed { nonce_key: [u8; 32] },
    SettlementAlreadyFinalized { settlement_id: [u8; 32] },
    InvalidTargetChain { expected: u64, got: u64 },
    InvalidTargetBridge { expected: [u8; 20], got: [u8; 20] },
    InvalidValidatorSignatureLength { got: usize },
    Unauthorized,
    UnknownValidator { validator: [u8; 32] },
    DuplicateValidatorSignature { validator: [u8; 32] },
    InvalidValidatorSignature { validator: [u8; 32], expected: [u8; 32], got: [u8; 32] },
    NotEnoughValidatorSignatures { required: usize, got: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeRelayEvent {
    ProofSubmitted { proof_digest: [u8; 32], validator_count: usize },
    ProofSubmittedAndStored { proof_digest: [u8; 32] },
    SettlementFinalized { settlement_id: [u8; 32], proof_digest: [u8; 32] },
    NonceConsumed { nonce_key: [u8; 32] },
    AdminUpdated { old_admin: [u8; 32], new_admin: [u8; 32] },
    MinSignaturesUpdated {
        old_min: usize,
        new_min: usize,
    },
    ValidatorsUpdated { previous_count: usize, new_count: usize },
}

#[derive(Debug, Default)]
pub struct BridgeRelay {
    proof_used: HashSet<[u8; 32]>,
    nonce_used: HashSet<[u8; 32]>,
    settlement_finalized: HashSet<[u8; 32]>,
    validators: HashSet<[u8; 32]>,
    min_validator_signatures: usize,
    admin: [u8; 32],
    audit_log: Vec<BridgeRelayEvent>,
}

impl BridgeRelay {
    pub fn new(
        min_validator_signatures: usize,
        validators: impl IntoIterator<Item = [u8; 32]>,
    ) -> Self {
        Self::with_admin(min_validator_signatures, validators, ADMIN_UNSET)
    }

    pub fn with_admin(
        min_validator_signatures: usize,
        validators: impl IntoIterator<Item = [u8; 32]>,
        admin: [u8; 32],
    ) -> Self {
        Self {
            validators: validators.into_iter().collect(),
            min_validator_signatures,
            admin,
            ..Self::default()
        }
    }

    pub fn submit_proof(
        &mut self,
        message: &BridgeSettlementMessage,
        signatures: &[Vec<u8>],
        deadline: u64,
        now_ts: u64,
        current_chain_id: u64,
        self_bridge: [u8; 20],
    ) -> Result<[u8; 32], BridgeRelayError> {
        if now_ts > deadline {
            return Err(BridgeRelayError::ProofExpired { now_ts, deadline });
        }

        self.validate_message_domain(message, now_ts, current_chain_id, self_bridge)?;

        let proof_digest = hash_message(message);
        if self.proof_used.contains(&proof_digest) {
            return Err(BridgeRelayError::ProofAlreadyUsed { proof_digest });
        }

        let valid_count = self.validate_validator_signatures(message, signatures)?;
        if valid_count < self.min_validator_signatures {
            return Err(BridgeRelayError::NotEnoughValidatorSignatures {
                required: self.min_validator_signatures,
                got: valid_count,
            });
        }

        self.audit_log.push(BridgeRelayEvent::ProofSubmitted {
            proof_digest,
            validator_count: valid_count,
        });
        self.audit_log
            .push(BridgeRelayEvent::ProofSubmittedAndStored { proof_digest });
        self.proof_used.insert(proof_digest);
        Ok(proof_digest)
    }

    pub fn consume_nonce(
        &mut self,
        source_chain_id: u64,
        source_bridge_id: [u8; 32],
        target_chain_id: u64,
        target_bridge: [u8; 20],
        action: [u8; 32],
        nonce: u64,
    ) -> Result<[u8; 32], BridgeRelayError> {
        let nonce_key = nonce_key(
            source_chain_id,
            source_bridge_id,
            target_chain_id,
            target_bridge,
            action,
            nonce,
        );

        if self.nonce_used.contains(&nonce_key) {
            return Err(BridgeRelayError::NonceAlreadyUsed { nonce_key });
        }

        self.nonce_used.insert(nonce_key);
        self.audit_log.push(BridgeRelayEvent::NonceConsumed { nonce_key });
        Ok(nonce_key)
    }

    pub fn set_admin(&mut self, caller: &[u8; 32], new_admin: [u8; 32]) -> Result<(), BridgeRelayError> {
        self.require_admin(caller)?;
        let old_admin = self.admin;
        self.admin = new_admin;
        self.audit_log.push(BridgeRelayEvent::AdminUpdated {
            old_admin,
            new_admin,
        });
        Ok(())
    }

    pub fn set_min_validator_signatures(&mut self, caller: &[u8; 32], min: usize) -> Result<(), BridgeRelayError> {
        self.require_admin(caller)?;
        let old_min = self.min_validator_signatures;
        self.min_validator_signatures = min;
        self.audit_log.push(BridgeRelayEvent::MinSignaturesUpdated { old_min, new_min: min });
        Ok(())
    }

    pub fn set_validators(&mut self, caller: &[u8; 32], validators: impl IntoIterator<Item = [u8; 32]>) -> Result<(), BridgeRelayError> {
        self.require_admin(caller)?;
        let previous_count = self.validators.len();
        self.validators = validators.into_iter().collect();
        self.audit_log.push(BridgeRelayEvent::ValidatorsUpdated {
            previous_count,
            new_count: self.validators.len(),
        });
        Ok(())
    }

    pub fn finalize_settlement(
        &mut self,
        message: &BridgeSettlementMessage,
        signatures: &[Vec<u8>],
        deadline: u64,
        now_ts: u64,
        current_chain_id: u64,
        self_bridge: [u8; 20],
    ) -> Result<[u8; 32], BridgeRelayError> {
        let _ = self.submit_proof(
            message,
            signatures,
            deadline,
            now_ts,
            current_chain_id,
            self_bridge,
        )?;

        let settlement_id = settlement_id(message);
        let proof_digest = hash_message(message);
        if self.settlement_finalized.contains(&settlement_id) {
            return Err(BridgeRelayError::SettlementAlreadyFinalized { settlement_id });
        }

        let _ = self.consume_nonce(
            message.source_chain_id,
            message.source_bridge_id,
            message.target_chain_id,
            message.target_bridge,
            action_settlement_finalize(),
            message.nonce,
        )?;

        self.settlement_finalized.insert(settlement_id);
        self.audit_log.push(BridgeRelayEvent::SettlementFinalized {
            settlement_id,
            proof_digest: proof_digest,
        });
        Ok(settlement_id)
    }

    pub fn audit_log(&self) -> &[BridgeRelayEvent] {
        &self.audit_log
    }

    pub fn consume_audit_log(&mut self) -> Vec<BridgeRelayEvent> {
        std::mem::take(&mut self.audit_log)
    }

    fn require_admin(&self, caller: &[u8; 32]) -> Result<(), BridgeRelayError> {
        if self.admin == ADMIN_UNSET || self.admin == *caller {
            Ok(())
        } else {
            Err(BridgeRelayError::Unauthorized)
        }
    }

    fn validate_message_domain(
        &self,
        message: &BridgeSettlementMessage,
        now_ts: u64,
        current_chain_id: u64,
        self_bridge: [u8; 20],
    ) -> Result<(), BridgeRelayError> {
        if message.target_chain_id != current_chain_id {
            return Err(BridgeRelayError::InvalidTargetChain {
                expected: current_chain_id,
                got: message.target_chain_id,
            });
        }

        if message.target_bridge != self_bridge {
            return Err(BridgeRelayError::InvalidTargetBridge {
                expected: self_bridge,
                got: message.target_bridge,
            });
        }

        if now_ts > message.deadline {
            return Err(BridgeRelayError::ProofExpired {
                now_ts,
                deadline: message.deadline,
            });
        }

        Ok(())
    }

    fn validate_validator_signatures(
        &self,
        message: &BridgeSettlementMessage,
        signatures: &[Vec<u8>],
    ) -> Result<usize, BridgeRelayError> {
        let message_digest = hash_message(message);
        let mut seen = HashSet::new();

        for signature in signatures {
            let (validator, provided_tag) = parse_validator_signature(signature)?;

            if !self.validators.contains(&validator) {
                return Err(BridgeRelayError::UnknownValidator { validator });
            }
            if !seen.insert(validator) {
                return Err(BridgeRelayError::DuplicateValidatorSignature { validator });
            }

            let expected_tag = validator_signature_tag(&validator, &message_digest);
            if expected_tag != provided_tag {
                return Err(BridgeRelayError::InvalidValidatorSignature {
                    validator,
                    expected: expected_tag,
                    got: provided_tag,
                });
            }
        }

        Ok(seen.len())
    }
}

fn parse_validator_signature(signature: &[u8]) -> Result<([u8; 32], [u8; 32]), BridgeRelayError> {
    if signature.len() != VALIDATOR_SIGNATURE_LEN {
        return Err(BridgeRelayError::InvalidValidatorSignatureLength {
            got: signature.len(),
        });
    }

    let mut validator = [0u8; 32];
    let mut tag = [0u8; 32];

    validator.copy_from_slice(&signature[..32]);
    tag.copy_from_slice(&signature[32..]);

    Ok((validator, tag))
}

pub fn validator_signature_tag(validator: &[u8; 32], message_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message_digest);
    hasher.update(validator);
    hasher.finalize().into()
}

pub fn nonce_key(
    source_chain_id: u64,
    source_bridge_id: [u8; 32],
    target_chain_id: u64,
    target_bridge: [u8; 20],
    action: [u8; 32],
    nonce: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(source_chain_id.to_be_bytes());
    hasher.update(source_bridge_id);
    hasher.update(target_chain_id.to_be_bytes());
    hasher.update(target_bridge);
    hasher.update(action);
    hasher.update(nonce.to_be_bytes());
    hasher.finalize().into()
}

pub fn settlement_id(message: &BridgeSettlementMessage) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message.source_chain_id.to_be_bytes());
    hasher.update(message.source_tx_hash);
    hasher.update(message.source_log_index.to_be_bytes());
    hasher.update(message.receiver);
    hasher.update(message.asset);
    hasher.update(message.amount.to_be_bytes());
    hasher.finalize().into()
}

pub fn hash_message(message: &BridgeSettlementMessage) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message.source_chain_id.to_be_bytes());
    hasher.update(message.source_bridge_id);
    hasher.update(message.source_tx_hash);
    hasher.update(message.source_log_index.to_be_bytes());
    hasher.update(message.target_chain_id.to_be_bytes());
    hasher.update(message.target_bridge);
    hasher.update(message.receiver);
    hasher.update(message.asset);
    hasher.update(message.amount.to_be_bytes());
    hasher.update(message.nonce.to_be_bytes());
    hasher.update(message.deadline.to_be_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> [u8; 20] {
        [b; 20]
    }

    fn b32(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn sig_for(message: &BridgeSettlementMessage, validator: u8) -> Vec<u8> {
        let validator_id = b32(validator);
        let digest = hash_message(message);
        let tag = validator_signature_tag(&validator_id, &digest);

        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&validator_id);
        out[32..].copy_from_slice(&tag);
        out.to_vec()
    }

    fn relay(min_validator_signatures: usize, validators: &[u8]) -> BridgeRelay {
        BridgeRelay::new(min_validator_signatures, validators.iter().copied().map(b32))
    }

    fn sample_msg() -> BridgeSettlementMessage {
        BridgeSettlementMessage {
            source_chain_id: 1,
            source_bridge_id: b32(1),
            source_tx_hash: b32(2),
            source_log_index: 7,
            target_chain_id: 31337,
            target_bridge: addr(9),
            receiver: addr(3),
            asset: addr(4),
            amount: 42,
            nonce: 99,
            deadline: 1_000,
        }
    }

    #[test]
    fn nonce_domain_isolation_and_replay_protection() {
        let mut relay = relay(1, &[7]);

        let n1 = relay
            .consume_nonce(1, b32(1), 31337, addr(9), action_settlement_finalize(), 10)
            .unwrap();

        let n2 = relay
            .consume_nonce(1, b32(1), 31337, addr(9), b32(55), 10)
            .unwrap();

        assert_ne!(n1, n2, "different action should isolate nonce domains");

        let err = relay
            .consume_nonce(1, b32(1), 31337, addr(9), action_settlement_finalize(), 10)
            .unwrap_err();
        assert!(matches!(err, BridgeRelayError::NonceAlreadyUsed { .. }));
    }

    #[test]
    fn fail_closed_on_expired_proof() {
        let mut relay = relay(1, &[1]);
        let msg = sample_msg();
        let err = relay
            .submit_proof(&msg, &[sig_for(&msg, 1)], 900, 901, 31337, addr(9))
            .unwrap_err();
        assert!(matches!(err, BridgeRelayError::ProofExpired { .. }));
    }

    #[test]
    fn fail_closed_on_duplicate_finalize() {
        let mut relay = relay(1, &[7]);
        let msg = sample_msg();

        relay
            .finalize_settlement(&msg, &[sig_for(&msg, 7)], 1_000, 999, 31337, addr(9))
            .unwrap();

        let err = relay
            .finalize_settlement(&msg, &[sig_for(&msg, 7)], 1_000, 999, 31337, addr(9))
            .unwrap_err();

        assert!(matches!(
            err,
            BridgeRelayError::ProofAlreadyUsed { .. } | BridgeRelayError::SettlementAlreadyFinalized { .. }
        ));
    }

    #[test]
    fn fail_closed_on_chain_domain_mismatch() {
        let mut relay = relay(1, &[7]);
        let mut msg = sample_msg();
        msg.target_chain_id = 10;

        let err = relay
            .finalize_settlement(&msg, &[sig_for(&msg, 7)], 1_000, 999, 31337, addr(9))
            .unwrap_err();

        assert!(matches!(err, BridgeRelayError::InvalidTargetChain { .. }));
    }

    #[test]
    fn duplicate_validator_signatures_do_not_count_twice() {
        let mut relay = relay(2, &[7]);
        let msg = sample_msg();

        let err = relay
            .submit_proof(
                &msg,
                &[sig_for(&msg, 7), sig_for(&msg, 7)],
                1_000,
                999,
                31337,
                addr(9),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            BridgeRelayError::DuplicateValidatorSignature { validator } if validator == b32(7)
        ));
    }

    #[test]
    fn governance_like_admin_can_rotate_validator_set_and_threshold() {
        let mut relay = BridgeRelay::with_admin(1, vec![b32(7)], b32(9));

        relay
            .set_min_validator_signatures(&b32(9), 2)
            .unwrap();
        relay
            .set_validators(&b32(9), vec![b32(7), b32(8)])
            .unwrap();

        let msg = sample_msg();
        let sigs = vec![sig_for(&msg, 7), sig_for(&msg, 8)];

        relay
            .submit_proof(&msg, &sigs, 1_000, 999, 31337, addr(9))
            .unwrap();

        let mut fallback = sample_msg();
        fallback.nonce = 100;
        let err = relay
            .submit_proof(&fallback, &[sig_for(&fallback, 7)], 1_000, 999, 31337, addr(9))
            .unwrap_err();

        assert!(matches!(
            err,
            BridgeRelayError::NotEnoughValidatorSignatures {
                required,
                ..
            } if required == 2
        ));
    }

    #[test]
    fn governance_like_admin_restrains_configuration_changes() {
        let mut relay = BridgeRelay::with_admin(1, vec![b32(7)], b32(9));

        let err = relay
            .set_min_validator_signatures(&b32(8), 2)
            .unwrap_err();
        assert!(matches!(err, BridgeRelayError::Unauthorized));
    }

    #[test]
    fn unknown_validator_signature_fails_closed() {
        let mut relay = relay(1, &[7]);
        let msg = sample_msg();

        let err = relay
            .submit_proof(&msg, &[sig_for(&msg, 8)], 1_000, 999, 31337, addr(9))
            .unwrap_err();

        assert!(matches!(
            err,
            BridgeRelayError::UnknownValidator { validator } if validator == b32(8)
        ));
    }

    #[test]
    fn malformed_signature_length_is_rejected() {
        let mut relay = relay(1, &[9]);
        let msg = sample_msg();
        let short = vec![9u8; 63];

        let err = relay
            .submit_proof(&msg, &[short], 1_000, 999, 31337, addr(9))
            .unwrap_err();

        assert!(matches!(
            err,
            BridgeRelayError::InvalidValidatorSignatureLength { got } if got == 63
        ));
    }

    #[test]
    fn invalid_signature_binding_is_rejected() {
        let mut relay = relay(1, &[7]);
        let msg = sample_msg();
        let mut modified = sample_msg();
        modified.amount = 999;

        let bad_sig = sig_for(&msg, 7);
        let err = relay
            .submit_proof(&modified, &[bad_sig], 1_000, 999, 31337, addr(9))
            .unwrap_err();

        assert!(matches!(
            err,
            BridgeRelayError::InvalidValidatorSignature { validator, .. } if validator == b32(7)
        ));
    }

    #[test]
    fn audit_log_records_admin_and_settlement_flow() {
        let mut relay = BridgeRelay::with_admin(2, vec![b32(7)], b32(9));

        relay.set_validators(&b32(9), vec![b32(7), b32(8)]).unwrap();
        relay
            .set_min_validator_signatures(&b32(9), 2)
            .unwrap();

        let msg = sample_msg();
        let sigs = vec![sig_for(&msg, 7), sig_for(&msg, 8)];

        let proof_digest = relay
            .submit_proof(&msg, &sigs, 1_000, 999, 31337, addr(9))
            .unwrap();
        let mut replay_msg = sample_msg();
        replay_msg.nonce += 1;
        let replay_sig = sig_for(&replay_msg, 7);
        let replay_sig2 = sig_for(&replay_msg, 8);
        let mut relay2 = BridgeRelay::with_admin(2, vec![b32(7), b32(8)], b32(9));
        relay2
            .finalize_settlement(&replay_msg, &[replay_sig, replay_sig2], 1_000, 999, 31337, addr(9))
            .unwrap();

        let logs = relay.audit_log();
        assert!(logs.iter().any(|e| matches!(e, BridgeRelayEvent::ValidatorsUpdated { .. })));
        assert!(logs.iter().any(|e| matches!(e, BridgeRelayEvent::MinSignaturesUpdated { .. })));
        assert!(logs.iter().any(|e| matches!(e, BridgeRelayEvent::ProofSubmitted { .. })));
        assert!(logs.iter().any(|e| matches!(e, BridgeRelayEvent::ProofSubmittedAndStored { proof_digest: d } if *d == proof_digest)));

        relay
            .consume_audit_log()
            .into_iter()
            .for_each(|event| {
                if let BridgeRelayEvent::ProofSubmittedAndStored { proof_digest: stored_digest } = event {
                    assert_eq!(stored_digest, proof_digest);
                }
            });

        assert!(relay.audit_log().is_empty());
    }
}
