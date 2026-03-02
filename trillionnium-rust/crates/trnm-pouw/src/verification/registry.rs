use std::collections::HashMap;
use std::sync::Arc;

use trnm_types::{ProofType, TaskObject};

use super::{proof_type_key, verifiers, ProofVerifier, VerificationResult};

pub struct VerifierRegistry {
    verifiers: HashMap<String, Arc<dyn ProofVerifier + Send + Sync>>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
        }
    }

    /// Initializes a registry with built-in verifiers for Fraud/TEE/ZK proof types.
    pub fn with_builtin_verifiers() -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(verifiers::FraudVerifier));
        registry.register(Arc::new(verifiers::TeeVerifier));
        registry.register(Arc::new(verifiers::ZkVerifier));
        registry
    }

    fn normalize_key(raw: &str) -> Option<String> {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return None;
        }

        let delimiter_normalized = normalized
            .chars()
            .map(|ch| {
                if ch == '_'
                    || ch == '＿'
                    || ch == '-'
                    || ch == '－'
                    || ch == '–'
                    || ch == '—'
                    || ch == '/'
                    || ch == '／'
                    || ch == '.'
                    || ch == ':'
                    || ch == '：'
                    || ch == '+'
                    || ch == '|'
                    || ch == '\\'
                    || ch == ','
                    || ch == '，'
                    || ch == ';'
                    || ch == '；'
                    || ch == '='
                    || ch == '@'
                    || ch == '#'
                    || ch == '`'
                    || ch == '%'
                    || ch == '$'
                    || ch == '&'
                    || ch == '('
                    || ch == ')'
                    || ch == '['
                    || ch == ']'
                    || ch == '{'
                    || ch == '}'
                    || ch == '<'
                    || ch == '>'
                    || ch == '"'
                    || ch == '\''
                    || ch == '!'
                    || ch == '?'
                    || ch == '*'
                    || ch == '~'
                    || ch == '^'
                {
                    ' '
                } else {
                    ch
                }
            })
            .collect::<String>();
        let collapsed = delimiter_normalized
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        let canonical = match collapsed.as_str() {
            // Backward-compatible aliases from early V1/V2 proof/receipt naming.
            "fraud proof" | "fraudproof" => "fraud",
            "fraud receipt" | "fraudreceipt" => "fraud",
            "tee proof" | "teeproof" => "tee",
            "tee receipt" | "teereceipt" => "tee",
            "tee attestation" | "teeattestation" => "tee",
            "remote attestation" | "remoteattestation" => "tee",
            "attestation report" | "attestationreport" => "tee",
            "ra report" | "rareport" => "tee",
            "ra quote" | "raquote" => "tee",
            "tee quote" | "teequote" => "tee",
            "sgx quote" | "sgxquote" => "tee",
            "sgx report" | "sgxreport" => "tee",
            "dcap quote" | "dcapquote" => "tee",
            "intel dcap quote" | "inteldcapquote" => "tee",
            "tdx quote" | "tdxquote" => "tee",
            "tdx report" | "tdxreport" => "tee",
            "intel tdx quote" | "inteltdxquote" => "tee",
            "tee report" | "teereport" => "tee",
            "tee evidence" | "teeevidence" => "tee",
            "tee cert" | "teecert" => "tee",
            "tee certificate" | "teecertificate" => "tee",
            "zk proof" | "zkproof" => "zk",
            "zk receipt" | "zkreceipt" => "zk",
            "zk attestation" | "zkattestation" => "zk",
            "zk evidence" | "zkevidence" => "zk",
            "zk snark" | "zksnark" => "zk",
            "zkp" | "zk p" => "zk",
            "zero knowledge" | "zeroknowledge" => "zk",
            "zero knowledge snark" | "zeroknowledgesnark" => "zk",
            "zero knowledge proof" | "zeroknowledgeproof" => "zk",
            "zero knowledge receipt" | "zeroknowledgereceipt" => "zk",
            "zk cert" | "zkcert" => "zk",
            "zero knowledge certificate" | "zeroknowledgecertificate" => "zk",
            "zero knowledge attestation" | "zeroknowledgeattestation" => "zk",
            "zero knowledge evidence" | "zeroknowledgeevidence" => "zk",
            // Keep custom plugin keys delimiter-stable for deterministic re-registration
            // and observability output (e.g., MY__PROOF == "my proof").
            _ => collapsed.as_str(),
        };

        Some(canonical.to_string())
    }

    pub fn register(&mut self, verifier: Arc<dyn ProofVerifier + Send + Sync>) {
        if let Some(key) = Self::normalize_key(verifier.proof_type()) {
            self.verifiers.insert(key, verifier);
        }
    }

    /// Returns normalized proof-type keys currently registered in lexical order.
    ///
    /// This supports V1 plugin observability/debugging without exposing verifier internals.
    pub fn registered_proof_types(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.verifiers.keys().cloned().collect();
        keys.sort();
        keys
    }

    /// Returns whether a verifier is currently registered for a concrete ProofType.
    ///
    /// This gives V1 callers a low-cost readiness probe before dispatching work.
    pub fn is_registered_for(&self, proof_type: ProofType) -> bool {
        self.verifiers.contains_key(proof_type_key(proof_type))
    }

    /// Returns whether a verifier is registered for a raw plugin/alias key after normalization.
    ///
    /// This is useful for V1 plugin diagnostics where callers only have user-provided
    /// proof/receipt labels (e.g. `TEE_RECEIPT`) and need a readiness check before submit.
    pub fn is_registered_kind(&self, raw_kind: &str) -> bool {
        Self::normalize_key(raw_kind)
            .map(|key| self.verifiers.contains_key(&key))
            .unwrap_or(false)
    }

    pub fn verify(&self, task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        let key = proof_type_key(task.proof_type);

        match self.verifiers.get(key) {
            Some(verifier) => verifier.verify_proof(task, proof_data),
            None => VerificationResult::Indeterminate(format!(
                "no verifier registered for proof type: {}",
                key
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use trnm_types::{TaskObject, TaskStatus};

    struct AlwaysValidVerifier {
        kind: &'static str,
    }

    impl ProofVerifier for AlwaysValidVerifier {
        fn proof_type(&self) -> &str {
            self.kind
        }

        fn verify_proof(&self, _task: &TaskObject, _proof_data: &[u8]) -> VerificationResult {
            VerificationResult::Valid
        }
    }

    struct TaggedVerifier {
        kind: &'static str,
        tag: &'static str,
    }

    impl ProofVerifier for TaggedVerifier {
        fn proof_type(&self) -> &str {
            self.kind
        }

        fn verify_proof(&self, _task: &TaskObject, _proof_data: &[u8]) -> VerificationResult {
            VerificationResult::Invalid(self.tag.to_string())
        }
    }

    fn task_with_proof_type(proof_type: ProofType) -> TaskObject {
        TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 100,
            status: TaskStatus::Open,
            proof_type,
            metadata: None,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        }
    }

    #[test]
    fn registry_register_is_case_insensitive_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: "TEE" }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_trims_verifier_key_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: " tee " }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE_RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_hyphenated_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " tee-receipt ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_ra_quote_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: " RA_QUOTE " }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_unicode_dash_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " tee—receipt ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_punctuated_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE?!RECEIPT!! ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_slash_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE/RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_dotted_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE.RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_backslash_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE\\RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_colon_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE:RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_plus_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE+RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_pipe_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE|RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_comma_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE,RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_semicolon_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE;RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_equals_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE=RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_at_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE@RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_hash_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE#RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_percent_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE%RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_dollar_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE$RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_asterisk_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE*RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_tilde_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE~RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_caret_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE^RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_ampersand_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE&RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_parenthesized_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE(RECEIPT) ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_bracketed_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE[RECEIPT] ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_braced_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE{RECEIPT} ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_angle_bracketed_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE<RECEIPT> ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_double_quoted_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " \"TEE\"\"RECEIPT\" ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_single_quoted_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " 'TEE''RECEIPT' ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_compact_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TeEReCeIpT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_space_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " Tee Receipt ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_multiline_whitespace_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: "\n\tTEE\n\tRECEIPT\t\n",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_fraud_receipt_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " FRAUD-RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Fraud);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_fraud_proof_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " fraud-proof ",
        }));

        let task = task_with_proof_type(ProofType::Fraud);
        assert_eq!(registry.verify(&task, b"proof"), VerificationResult::Valid);
    }

    #[test]
    fn registry_register_collapses_tee_proof_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE_PROOF ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"proof"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_zk_proof_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " ZK-PROOF ",
        }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(
            registry.verify(&task, b"proof"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_zero_knowledge_proof_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " Zero-Knowledge Proof ",
        }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(
            registry.verify(&task, b"proof"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_zero_knowledge_receipt_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " Zero Knowledge Receipt ",
        }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_hyphenated_zk_receipt_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " ZK-RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_space_delimited_zk_receipt_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " zk receipt ",
        }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_tee_attestation_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " tee-attestation ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"attestation"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_remote_attestation_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " remote-attestation ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"attestation"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_tee_quote_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " tee-quote ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"attestation"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_sgx_quote_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " SGX_QUOTE ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"attestation"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_dcap_quote_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " dcap-quote ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"attestation"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_intel_dcap_quote_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " Intel DCAP Quote ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"attestation"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_intel_tdx_quote_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " Intel TDX Quote ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"attestation"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_tee_report_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " tee_report ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(registry.verify(&task, b"report"), VerificationResult::Valid);
    }

    #[test]
    fn registry_register_collapses_sgx_report_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " SGX report ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(registry.verify(&task, b"report"), VerificationResult::Valid);
    }

    #[test]
    fn registry_register_collapses_tdx_report_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " tdx-report ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(registry.verify(&task, b"report"), VerificationResult::Valid);
    }

    #[test]
    fn registry_register_collapses_tee_evidence_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE evidence ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"evidence"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_zk_attestation_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " zk_attestation ",
        }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(
            registry.verify(&task, b"attestation"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_zk_evidence_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " ZK-EVIDENCE ",
        }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(
            registry.verify(&task, b"evidence"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_zk_snark_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " ZK-SNARK ",
        }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(registry.verify(&task, b"proof"), VerificationResult::Valid);
    }

    #[test]
    fn registry_register_collapses_zero_knowledge_snark_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " zero knowledge snark ",
        }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(registry.verify(&task, b"proof"), VerificationResult::Valid);
    }

    #[test]
    fn registry_register_collapses_zero_knowledge_evidence_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " zero knowledge evidence ",
        }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(registry.verify(&task, b"evidence"), VerificationResult::Valid);
    }

    #[test]
    fn registry_register_collapses_mixed_delimiter_legacy_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: "  TEE__-__RECEIPT  ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_punctuation_wrapped_legacy_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: "?!TEE?!RECEIPT!?",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_backtick_delimited_legacy_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: "TEE`RECEIPT",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_ignores_empty_verifier_key_after_normalization() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: "   " }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Indeterminate("no verifier registered for proof type: tee".into())
        );
    }

    #[test]
    fn registry_re_register_replaces_verifier_for_normalized_key() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(TaggedVerifier {
            kind: "TEE",
            tag: "old",
        }));
        registry.register(Arc::new(TaggedVerifier {
            kind: " tee ",
            tag: "new",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Invalid("new".to_string())
        );
    }

    #[test]
    fn registry_re_register_replaces_custom_verifier_for_delimiter_equivalent_key() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(TaggedVerifier {
            kind: "MY__CUSTOM--PROOF",
            tag: "old",
        }));
        registry.register(Arc::new(TaggedVerifier {
            kind: "my custom proof",
            tag: "new",
        }));

        assert_eq!(
            registry.registered_proof_types(),
            vec!["my custom proof".to_string()]
        );
    }

    #[test]
    fn registry_registered_proof_types_are_normalized_and_sorted() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: " ZK " }));
        registry.register(Arc::new(AlwaysValidVerifier { kind: "fraud" }));
        registry.register(Arc::new(AlwaysValidVerifier { kind: "TEE" }));
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " tee_receipt ",
        }));

        assert_eq!(
            registry.registered_proof_types(),
            vec!["fraud".to_string(), "tee".to_string(), "zk".to_string()]
        );
    }

    #[test]
    fn registry_returns_indeterminate_when_verifier_is_missing() {
        let registry = VerifierRegistry::new();
        let task = task_with_proof_type(ProofType::Zk);

        assert_eq!(
            registry.verify(&task, b"proof"),
            VerificationResult::Indeterminate("no verifier registered for proof type: zk".into())
        );
    }

    #[test]
    fn registry_is_registered_for_reports_false_when_key_is_missing() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: "fraud" }));

        assert!(registry.is_registered_for(ProofType::Fraud));
        assert!(!registry.is_registered_for(ProofType::Tee));
        assert!(!registry.is_registered_for(ProofType::Zk));
    }

    #[test]
    fn registry_is_registered_for_reports_true_for_builtin_stack() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        assert!(registry.is_registered_for(ProofType::Fraud));
        assert!(registry.is_registered_for(ProofType::Tee));
        assert!(registry.is_registered_for(ProofType::Zk));
    }

    #[test]
    fn registry_is_registered_kind_normalizes_aliases_for_lookup() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        assert!(registry.is_registered_kind("TEE_RECEIPT"));
        assert!(registry.is_registered_kind("TEE_CERTIFICATE"));
        assert!(registry.is_registered_kind("tee cert"));
        assert!(registry.is_registered_kind(" zero-knowledge proof "));
        assert!(registry.is_registered_kind("ZKP"));
        assert!(registry.is_registered_kind("zk-p"));
        assert!(registry.is_registered_kind("zk cert"));
        assert!(registry.is_registered_kind("Zero Knowledge Certificate"));
        assert!(registry.is_registered_kind("Zero Knowledge Attestation"));
        assert!(registry.is_registered_kind("zero knowledge"));
        assert!(registry.is_registered_kind("fraud"));
        assert!(!registry.is_registered_kind("custom-proof"));
        assert!(!registry.is_registered_kind("   "));
    }

    #[test]
    fn registry_is_registered_kind_accepts_punctuated_legacy_receipt_aliases() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        assert!(registry.is_registered_kind("TEE:RECEIPT"));
        assert!(registry.is_registered_kind("?!tee?!receipt!?"));
        assert!(registry.is_registered_kind("\"TEE\"\"RECEIPT\""));
    }

    #[test]
    fn registry_is_registered_kind_accepts_dcap_quote_aliases() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        assert!(registry.is_registered_kind("dcap_quote"));
        assert!(registry.is_registered_kind("Intel DCAP Quote"));
        assert!(registry.is_registered_kind("sgx-quote"));
        assert!(registry.is_registered_kind("intel_tdx_quote"));
        assert!(registry.is_registered_kind("attestation_report"));
        assert!(registry.is_registered_kind("RA report"));
    }

    #[test]
    fn registry_is_registered_kind_accepts_fullwidth_punctuation_aliases() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        assert!(registry.is_registered_kind("TEE：RECEIPT"));
        assert!(registry.is_registered_kind("TEE／QUOTE"));
        assert!(registry.is_registered_kind("TEE－ATTESTATION"));
        assert!(registry.is_registered_kind("TEE，RECEIPT"));
        assert!(registry.is_registered_kind("TEE；RECEIPT"));
        assert!(registry.is_registered_kind("ZK＿PROOF"));
    }

    #[test]
    fn registry_with_builtin_verifiers_registers_v1_stack() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        assert_eq!(
            registry.registered_proof_types(),
            vec!["fraud".to_string(), "tee".to_string(), "zk".to_string()]
        );

        let fraud_task = task_with_proof_type(ProofType::Fraud);
        let tee_task = task_with_proof_type(ProofType::Tee);
        let zk_task = task_with_proof_type(ProofType::Zk);

        assert_eq!(
            registry.verify(&fraud_task, b"FRAUD:challenge"),
            VerificationResult::Valid
        );
        assert_eq!(
            registry.verify(&tee_task, b"TEE:quote"),
            VerificationResult::Valid
        );
        assert_eq!(
            registry.verify(&zk_task, b"ZK:payload!"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_with_builtin_verifiers_surfaces_envelope_validation_failures() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        let fraud_task = task_with_proof_type(ProofType::Fraud);
        let tee_task = task_with_proof_type(ProofType::Tee);
        let zk_task = task_with_proof_type(ProofType::Zk);

        assert!(matches!(
            registry.verify(&fraud_task, b"FRAUD:   \n\t"),
            VerificationResult::Invalid(msg) if msg.contains("Invalid fraud proof envelope")
        ));
        assert!(matches!(
            registry.verify(&tee_task, b"TEE:   \n\t"),
            VerificationResult::Invalid(msg) if msg.contains("Invalid TEE receipt envelope")
        ));
        assert!(matches!(
            registry.verify(&zk_task, b"ZK:       "),
            VerificationResult::Invalid(msg) if msg.contains("Invalid ZK proof envelope")
        ));
    }
}
