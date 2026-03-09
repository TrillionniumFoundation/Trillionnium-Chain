use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const ACTION_SETTLEMENT_FINALIZE: [u8; 32] = keccak_placeholder(b"SETTLEMENT_FINALIZE");

const fn keccak_placeholder(input: &[u8]) -> [u8; 32] {
    // Deterministic placeholder constant builder for MVP skeleton.
    // Not cryptographic keccak. Used only for fixed action domain value.
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < input.len() && i < 32 {
        out[i] = input[i];
        i += 1;
    }
    out
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
    NotEnoughValidatorSignatures { required: usize, got: usize },
}

#[derive(Debug, Default)]
pub struct BridgeRelay {
    proof_used: HashSet<[u8; 32]>,
    nonce_used: HashSet<[u8; 32]>,
    settlement_finalized: HashSet<[u8; 32]>,
    min_validator_signatures: usize,
}

impl BridgeRelay {
    pub fn new(min_validator_signatures: usize) -> Self {
        Self {
            min_validator_signatures,
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

        let valid_count = signatures.len();
        if valid_count < self.min_validator_signatures {
            return Err(BridgeRelayError::NotEnoughValidatorSignatures {
                required: self.min_validator_signatures,
                got: valid_count,
            });
        }

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
        Ok(nonce_key)
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
        if self.settlement_finalized.contains(&settlement_id) {
            return Err(BridgeRelayError::SettlementAlreadyFinalized { settlement_id });
        }

        let _ = self.consume_nonce(
            message.source_chain_id,
            message.source_bridge_id,
            message.target_chain_id,
            message.target_bridge,
            ACTION_SETTLEMENT_FINALIZE,
            message.nonce,
        )?;

        self.settlement_finalized.insert(settlement_id);
        Ok(settlement_id)
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
        let mut relay = BridgeRelay::new(1);

        let n1 = relay
            .consume_nonce(1, b32(1), 31337, addr(9), ACTION_SETTLEMENT_FINALIZE, 10)
            .unwrap();

        let n2 = relay
            .consume_nonce(1, b32(1), 31337, addr(9), b32(55), 10)
            .unwrap();

        assert_ne!(n1, n2, "different action should isolate nonce domains");

        let err = relay
            .consume_nonce(1, b32(1), 31337, addr(9), ACTION_SETTLEMENT_FINALIZE, 10)
            .unwrap_err();
        assert!(matches!(err, BridgeRelayError::NonceAlreadyUsed { .. }));
    }

    #[test]
    fn fail_closed_on_expired_proof() {
        let mut relay = BridgeRelay::new(1);
        let msg = sample_msg();
        let err = relay
            .submit_proof(&msg, &[vec![1]], 900, 901, 31337, addr(9))
            .unwrap_err();
        assert!(matches!(err, BridgeRelayError::ProofExpired { .. }));
    }

    #[test]
    fn fail_closed_on_duplicate_finalize() {
        let mut relay = BridgeRelay::new(1);
        let msg = sample_msg();

        relay
            .finalize_settlement(&msg, &[vec![7]], 1_000, 999, 31337, addr(9))
            .unwrap();

        let err = relay
            .finalize_settlement(&msg, &[vec![7]], 1_000, 999, 31337, addr(9))
            .unwrap_err();

        assert!(matches!(
            err,
            BridgeRelayError::ProofAlreadyUsed { .. } | BridgeRelayError::SettlementAlreadyFinalized { .. }
        ));
    }

    #[test]
    fn fail_closed_on_chain_domain_mismatch() {
        let mut relay = BridgeRelay::new(1);
        let mut msg = sample_msg();
        msg.target_chain_id = 10;

        let err = relay
            .finalize_settlement(&msg, &[vec![7]], 1_000, 999, 31337, addr(9))
            .unwrap_err();

        assert!(matches!(err, BridgeRelayError::InvalidTargetChain { .. }));
    }
}
