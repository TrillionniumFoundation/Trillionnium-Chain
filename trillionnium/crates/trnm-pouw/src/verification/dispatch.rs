use trnm_types::ProofType;

/// Returns the canonical key used across verification routing and receipt persistence.
pub fn proof_type_key(proof_type: ProofType) -> &'static str {
    match proof_type {
        ProofType::Fraud => "fraud",
        ProofType::Tee => "tee",
        ProofType::Zk => "zk",
    }
}
