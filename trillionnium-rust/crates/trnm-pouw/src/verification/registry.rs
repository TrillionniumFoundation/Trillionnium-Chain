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
                    || ch == '―'
                    || ch == '‒'
                    || ch == '−'
                    || ch == '‐'
                    || ch == '‑'
                    || ch == '-'
                    || ch == '-'
                    || ch == '﹣'
                    || ch == '﹘'
                    || ch == '\u{00a0}'
                    || ch == '\u{3000}'
                    || ch == '\u{200b}'
                    || ch == '\u{200c}'
                    || ch == '\u{200d}'
                    || ch == '\u{2060}'
                    || ch == '\u{2061}'
                    || ch == '\u{2062}'
                    || ch == '\u{2063}'
                    || ch == '\u{feff}'
                    || ch == '/'
                    || ch == '／'
                    || ch == '.'
                    || ch == '．'
                    || ch == ':'
                    || ch == '：'
                    || ch == '+'
                    || ch == '＋'
                    || ch == '|'
                    || ch == '｜'
                    || ch == '\\'
                    || ch == '＼'
                    || ch == ','
                    || ch == '，'
                    || ch == '、'
                    || ch == ';'
                    || ch == '；'
                    || ch == '。'
                    || ch == '．'
                    || ch == '·'
                    || ch == '・'
                    || ch == '∙'
                    || ch == '⋅'
                    || ch == '='
                    || ch == '@'
                    || ch == '#'
                    || ch == '`'
                    || ch == '%'
                    || ch == '$'
                    || ch == '&'
                    || ch == '('
                    || ch == ')'
                    || ch == '（'
                    || ch == '）'
                    || ch == '['
                    || ch == ']'
                    || ch == '［'
                    || ch == '］'
                    || ch == '{'
                    || ch == '}'
                    || ch == '｛'
                    || ch == '｝'
                    || ch == '<'
                    || ch == '>'
                    || ch == '"'
                    || ch == '\''
                    || ch == '“'
                    || ch == '”'
                    || ch == '‘'
                    || ch == '’'
                    || ch == '!'
                    || ch == '！'
                    || ch == '?'
                    || ch == '？'
                    || ch == '*'
                    || ch == '~'
                    || ch == '～'
                    || ch == '〜'
                    || ch == '^'
                    || ch == '®'
                    || ch == '™'
                {
                    ' '
                } else {
                    match ch {
                        '０' => '0',
                        '１' => '1',
                        '２' => '2',
                        '３' => '3',
                        '４' => '4',
                        '５' => '5',
                        '６' => '6',
                        '７' => '7',
                        '８' => '8',
                        '９' => '9',
                        _ => ch,
                    }
                }
            })
            .collect::<String>();
        let collapsed = delimiter_normalized
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if collapsed.is_empty() {
            return None;
        }

        let canonical = match collapsed.as_str() {
            // Backward-compatible aliases from early V1/V2 proof/receipt naming.
            "fraud proof" | "fraudproof" => "fraud",
            "fraud proof v1" | "fraudproofv1" | "fraud proof v 1" => "fraud",
            "fraud proof v2" | "fraudproofv2" | "fraud proof v 2" => "fraud",
            "fraud proof v3" | "fraudproofv3" | "fraud proof v 3" => "fraud",
            "fraud receipt" | "fraudreceipt" => "fraud",
            "fraud receipt v1" | "fraudreceiptv1" | "fraud receipt v 1" | "fraud receiptv1" => "fraud",
            "fraud receipt v2" | "fraudreceiptv2" | "fraud receipt v 2" | "fraud receiptv2" => "fraud",
            "fraud receipt v3" | "fraudreceiptv3" | "fraud receipt v 3" | "fraud receiptv3" => "fraud",
            "fraud challenge" | "fraudchallenge" => "fraud",
            "fraud challenge v1" | "fraudchallengev1" | "fraud challenge v 1" => "fraud",
            "fraud challenge v2" | "fraudchallengev2" | "fraud challenge v 2" => "fraud",
            "fraud challenge v3" | "fraudchallengev3" | "fraud challenge v 3" => "fraud",
            "tee proof" | "teeproof" => "tee",
            "tee proof v1" | "teeproofv1" | "tee proof v 1" => "tee",
            "tee proof v2" | "teeproofv2" | "tee proof v 2" => "tee",
            "tee proof v3" | "teeproofv3" | "tee proof v 3" => "tee",
            "tee receipt" | "teereceipt" => "tee",
            "tee receipt v1" | "teereceiptv1" | "tee receipt v 1" | "tee receiptv1" => "tee",
            "tee receipt v2" | "teereceiptv2" | "tee receipt v 2" | "tee receiptv2" => "tee",
            "tee receipt v3" | "teereceiptv3" | "tee receipt v 3" | "tee receiptv3" => "tee",
            "tee attestation" | "teeattestation" => "tee",
            "tee attestation v1" | "teeattestationv1" | "tee attestation v 1" => "tee",
            "tee attestation v2" | "teeattestationv2" | "tee attestation v 2" => "tee",
            "tee attestation v3" | "teeattestationv3" | "tee attestation v 3" => "tee",
            "remote attestation" | "remoteattestation" => "tee",
            "attestation report" | "attestationreport" => "tee",
            "attestation report v1" | "attestationreportv1" | "attestation report v 1" => "tee",
            "attestation report v2" | "attestationreportv2" | "attestation report v 2" => "tee",
            "attestation report v3" | "attestationreportv3" | "attestation report v 3" => "tee",
            "tee attestation report" | "teeattestationreport" => "tee",
            "tee attestation report v1"
            | "teeattestationreportv1"
            | "tee attestation report v 1" => "tee",
            "tee attestation report v2"
            | "teeattestationreportv2"
            | "tee attestation report v 2" => "tee",
            "tee attestation report v3"
            | "teeattestationreportv3"
            | "tee attestation report v 3" => "tee",
            "ra report" | "rareport" => "tee",
            "ra report v1" | "rareportv1" | "ra report v 1" => "tee",
            "ra report v2" | "rareportv2" | "ra report v 2" => "tee",
            "ra report v3" | "rareportv3" | "ra report v 3" => "tee",
            "tee ra report" | "teerareport" => "tee",
            "tee ra report v1" | "teerareportv1" | "tee ra report v 1" => "tee",
            "tee ra report v2" | "teerareportv2" | "tee ra report v 2" => "tee",
            "tee ra report v3" | "teerareportv3" | "tee ra report v 3" => "tee",
            "ra quote" | "raquote" => "tee",
            "ra quote v1" | "raquotev1" | "ra quote v 1" => "tee",
            "ra quote v2" | "raquotev2" | "ra quote v 2" => "tee",
            "ra quote v3" | "raquotev3" | "ra quote v 3" => "tee",
            "tee ra quote" | "teeraquote" => "tee",
            "tee ra quote v1" | "teeraquotev1" | "tee ra quote v 1" => "tee",
            "tee ra quote v2" | "teeraquotev2" | "tee ra quote v 2" => "tee",
            "tee ra quote v3" | "teeraquotev3" | "tee ra quote v 3" => "tee",
            "tee quote" | "teequote" => "tee",
            "tee quote v1" | "teequotev1" | "tee quote v 1" => "tee",
            "tee quote v2" | "teequotev2" | "tee quote v 2" => "tee",
            "tee quote v3" | "teequotev3" | "tee quote v 3" => "tee",
            "sgx quote" | "sgxquote" => "tee",
            "enclave quote" | "enclavequote" => "tee",
            "sgx report" | "sgxreport" => "tee",
            "dcap quote" | "dcapquote" => "tee",
            "intel dcap quote" | "inteldcapquote" => "tee",
            "sgx dcap quote" | "sgxdcapquote" => "tee",
            "intel sgx dcap quote" | "intelsgxdcapquote" => "tee",
            "tdx quote" | "tdxquote" => "tee",
            "td quote" | "tdquote" => "tee",
            "tdx report" | "tdxreport" => "tee",
            "td report" | "tdreport" => "tee",
            "snp report" | "snpreport" => "tee",
            "snp quote" | "snpquote" => "tee",
            "sev snp report" | "sevsnpreport" => "tee",
            "sev snp quote" | "sevsnpquote" => "tee",
            "amd sev snp report" | "amdsevsnpreport" => "tee",
            "amd sev snp quote" | "amdsevsnpquote" => "tee",
            "intel tdx quote" | "inteltdxquote" => "tee",
            "tee report" | "teereport" => "tee",
            "tee evidence" | "teeevidence" => "tee",
            "tee cert" | "teecert" => "tee",
            "tee certificate" | "teecertificate" => "tee",
            "zk proof" | "zkproof" => "zk",
            "zk proof v1" | "zkproofv1" | "zk proof v 1" => "zk",
            "zk proof v2" | "zkproofv2" | "zk proof v 2" => "zk",
            "zk proof v3" | "zkproofv3" | "zk proof v 3" => "zk",
            "zk receipt" | "zkreceipt" => "zk",
            "zk receipt v1" | "zkreceiptv1" | "zk receipt v 1" | "zk receiptv1" => "zk",
            "zk receipt v2" | "zkreceiptv2" | "zk receipt v 2" | "zk receiptv2" => "zk",
            "zk receipt v3" | "zkreceiptv3" | "zk receipt v 3" | "zk receiptv3" => "zk",
            "zk attestation" | "zkattestation" => "zk",
            "zk evidence" | "zkevidence" => "zk",
            "zk snark" | "zksnark" => "zk",
            "snark" => "zk",
            "zkp" | "zk p" => "zk",
            "zero knowledge" | "zeroknowledge" => "zk",
            "zero knowledge snark" | "zeroknowledgesnark" => "zk",
            "zero knowledge proof" | "zeroknowledgeproof" => "zk",
            "zero knowledge proof v1" | "zeroknowledgeproofv1" | "zero knowledge proof v 1" => "zk",
            "zero knowledge proof v2" | "zeroknowledgeproofv2" | "zero knowledge proof v 2" => "zk",
            "zero knowledge proof v3" | "zeroknowledgeproofv3" | "zero knowledge proof v 3" => "zk",
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
    use crate::verification::normalize_receipt_proof_type;
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
    fn registry_register_collapses_non_breaking_hyphen_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " tee‑receipt ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_figure_dash_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " tee‒receipt ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_small_em_dash_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " tee﹘receipt ",
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
    fn registry_register_collapses_fullwidth_backslash_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE＼RECEIPT ",
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
    fn registry_register_collapses_fullwidth_punctuation_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE：RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );

        let mut slash_registry = VerifierRegistry::new();
        slash_registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE／RECEIPT ",
        }));
        assert_eq!(
            slash_registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );

        let mut dot_registry = VerifierRegistry::new();
        dot_registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE．RECEIPT ",
        }));
        assert_eq!(
            dot_registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_middle_dot_delimited_legacy_receipt_aliases_for_lookup() {
        let mut centered_dot_registry = VerifierRegistry::new();
        centered_dot_registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE·RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            centered_dot_registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );

        let mut katakana_dot_registry = VerifierRegistry::new();
        katakana_dot_registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE・RECEIPT ",
        }));
        assert_eq!(
            katakana_dot_registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );

        let mut bullet_operator_registry = VerifierRegistry::new();
        bullet_operator_registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE∙RECEIPT ",
        }));
        assert_eq!(
            bullet_operator_registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );

        let mut dot_operator_registry = VerifierRegistry::new();
        dot_operator_registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE⋅RECEIPT ",
        }));
        assert_eq!(
            dot_operator_registry.verify(&task, b"receipt"),
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
    fn registry_register_collapses_fullwidth_pipe_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE｜RECEIPT ",
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
    fn registry_register_collapses_fullwidth_tilde_delimited_legacy_receipt_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE～RECEIPT ",
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
    fn registry_register_collapses_fraud_challenge_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " FRAUD_CHALLENGE ",
        }));

        let task = task_with_proof_type(ProofType::Fraud);
        assert_eq!(
            registry.verify(&task, b"challenge"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_tee_proof_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE_PROOF ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(registry.verify(&task, b"proof"), VerificationResult::Valid);
    }

    #[test]
    fn registry_register_collapses_zk_proof_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: " ZK-PROOF " }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(registry.verify(&task, b"proof"), VerificationResult::Valid);
    }

    #[test]
    fn registry_register_collapses_zero_knowledge_proof_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " Zero-Knowledge Proof ",
        }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(registry.verify(&task, b"proof"), VerificationResult::Valid);
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
    fn registry_register_collapses_non_breaking_hyphen_zk_receipt_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " ZK‑RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_figure_dash_zk_receipt_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " ZK‒RECEIPT ",
        }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_collapses_em_dash_zk_receipt_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " ZK—RECEIPT ",
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
    fn registry_register_collapses_tee_certificate_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE_CERTIFICATE ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"certificate"),
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
    fn registry_register_collapses_versioned_tee_quote_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " TEE_QUOTE_v1 ",
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
    fn registry_register_collapses_enclave_quote_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " Enclave-Quote ",
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
    fn registry_register_collapses_intel_sgx_dcap_quote_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " Intel SGX DCAP Quote ",
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
    fn registry_register_collapses_amd_sev_snp_report_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " AMD_SEV-SNP_report ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(registry.verify(&task, b"report"), VerificationResult::Valid);
    }

    #[test]
    fn registry_register_collapses_sev_snp_quote_alias_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: " SEV-SNP quote ",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(registry.verify(&task, b"quote"), VerificationResult::Valid);
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
        registry.register(Arc::new(AlwaysValidVerifier { kind: " ZK-SNARK " }));

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
        assert_eq!(
            registry.verify(&task, b"evidence"),
            VerificationResult::Valid
        );
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
    fn registry_register_collapses_fullwidth_punctuation_wrapped_legacy_aliases_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier {
            kind: "？！TEE？！RECEIPT！？",
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
    fn registry_ignores_punctuation_only_verifier_key_after_normalization() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: "___---///" }));

        assert!(registry.registered_proof_types().is_empty());
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
        assert!(registry.is_registered_kind("SNARK"));
        assert!(registry.is_registered_kind("zk cert"));
        assert!(registry.is_registered_kind("Zero Knowledge Certificate"));
        assert!(registry.is_registered_kind("Zero Knowledge Attestation"));
        assert!(registry.is_registered_kind("zero knowledge"));
        assert!(registry.is_registered_kind("fraud"));
        assert!(registry.is_registered_kind("fraud_challenge"));
        assert!(!registry.is_registered_kind("custom-proof"));
        assert!(!registry.is_registered_kind("   "));
        assert!(!registry.is_registered_kind("___---///"));
    }

    #[test]
    fn registry_is_registered_kind_accepts_punctuated_legacy_receipt_aliases() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        assert!(registry.is_registered_kind("TEE:RECEIPT"));
        assert!(registry.is_registered_kind("?!tee?!receipt!?"));
        assert!(registry.is_registered_kind("\"TEE\"\"RECEIPT\""));
        assert!(registry.is_registered_kind("`TEE``RECEIPT`"));
    }

    #[test]
    fn registry_is_registered_kind_accepts_version_suffixed_legacy_aliases() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        assert!(registry.is_registered_kind("TEE_RECEIPT_V1"));
        assert!(registry.is_registered_kind("tee-proof-v2"));
        assert!(registry.is_registered_kind("TEE_RECEIPT_V_2"));
        assert!(registry.is_registered_kind("TEE_RECEIPTV2"));
        assert!(registry.is_registered_kind("TEE_ATTESTATION_V2"));
        assert!(registry.is_registered_kind("tee-attestation-v3"));
        assert!(registry.is_registered_kind("TEE_ATTESTATION_REPORT_V2"));
        assert!(registry.is_registered_kind("fraud receipt v2"));
        assert!(registry.is_registered_kind("fraud_receipt_v_1"));
        assert!(registry.is_registered_kind("fraud challenge v1"));
        assert!(registry.is_registered_kind("FRAUD_CHALLENGE_V_2"));
        assert!(registry.is_registered_kind("fraud-challenge-v3"));
        assert!(registry.is_registered_kind("fraud-proof-v3"));
        assert!(registry.is_registered_kind("FRAUD_PROOF_V_2"));
        assert!(registry.is_registered_kind("zk receipt v1"));
        assert!(registry.is_registered_kind("zk-receipt-v-2"));
        assert!(registry.is_registered_kind("fraud_receipt_v3"));
        assert!(registry.is_registered_kind("fraud receiptv1"));
        assert!(registry.is_registered_kind("fraud receiptv2"));
        assert!(registry.is_registered_kind("TEE_RECEIPT_V_3"));
        assert!(registry.is_registered_kind("zk receipt v3"));
        assert!(registry.is_registered_kind("zk receiptv1"));
        assert!(registry.is_registered_kind("zk receiptv3"));
        assert!(registry.is_registered_kind("tee proof v3"));
        assert!(registry.is_registered_kind("ZK_PROOF_V2"));
        assert!(registry.is_registered_kind("ZK_PROOF_V3"));
        assert!(registry.is_registered_kind("TEE_RECEIPT_V２"));
        assert!(registry.is_registered_kind("tee-proof-v３"));
        assert!(registry.is_registered_kind("ZK_PROOF_V１"));
    }

    #[test]
    fn registry_aliases_stay_aligned_with_receipt_normalization_contract() {
        let aliases = [
            "TEE_RECEIPT_V1",
            "Intel® SGX™ DCAP Quote",
            "AMD SEV-SNP report",
            "tee‑proof‑v2",
            "RA_QUOTE_V2",
            "TEE～RECEIPT",
            "TEEATTESTATIONV1",
            "zk-receipt-v-2",
            "zero knowledge proof v2",
            "zero knowledge certificate",
            "fraud_receipt_v_1",
            "TEE_RECEIPT_V２",
            "tee﹣receipt",
        ];

        for alias in aliases {
            assert_eq!(
                VerifierRegistry::normalize_key(alias),
                Some(normalize_receipt_proof_type(alias)),
                "alias normalization drifted for {alias}"
            );
        }
    }

    #[test]
    fn registry_is_registered_kind_accepts_dcap_quote_aliases() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        assert!(registry.is_registered_kind("dcap_quote"));
        assert!(registry.is_registered_kind("Intel DCAP Quote"));
        assert!(registry.is_registered_kind("SGX DCAP Quote"));
        assert!(registry.is_registered_kind("Intel SGX DCAP Quote"));
        assert!(registry.is_registered_kind("Intel® SGX™ DCAP Quote"));
        assert!(registry.is_registered_kind("sgx-quote"));
        assert!(registry.is_registered_kind("intel_tdx_quote"));
        assert!(registry.is_registered_kind("td_quote"));
        assert!(registry.is_registered_kind("TD report"));
        assert!(registry.is_registered_kind("attestation_report"));
        assert!(registry.is_registered_kind("TEE attestation report"));
        assert!(registry.is_registered_kind("RA report"));
        assert!(registry.is_registered_kind("RA_QUOTE_V2"));
        assert!(registry.is_registered_kind("TEE_RA_REPORT"));
        assert!(registry.is_registered_kind("tee-ra-quote-v2"));
    }

    #[test]
    fn registry_is_registered_kind_accepts_tdx_and_sev_snp_aliases() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        assert!(registry.is_registered_kind("tdx_quote"));
        assert!(registry.is_registered_kind("TDX report"));
        assert!(registry.is_registered_kind("snp_report"));
        assert!(registry.is_registered_kind("snp_quote"));
        assert!(registry.is_registered_kind("SEV-SNP report"));
        assert!(registry.is_registered_kind("SEV-SNP quote"));
        assert!(registry.is_registered_kind("AMD SEV-SNP report"));
        assert!(registry.is_registered_kind("AMD SEV-SNP quote"));
    }

    #[test]
    fn registry_is_registered_kind_accepts_fullwidth_punctuation_aliases() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        assert!(registry.is_registered_kind("TEE：RECEIPT"));
        assert!(registry.is_registered_kind("TEE／QUOTE"));
        assert!(registry.is_registered_kind("TEE＼QUOTE"));
        assert!(registry.is_registered_kind("TEE＋RECEIPT"));
        assert!(registry.is_registered_kind("TEE－ATTESTATION"));
        assert!(registry.is_registered_kind("TEE﹣RECEIPT"));
        assert!(registry.is_registered_kind("TEE-RECEIPT"));
        assert!(registry.is_registered_kind("TEE，RECEIPT"));
        assert!(registry.is_registered_kind("TEE、RECEIPT"));
        assert!(registry.is_registered_kind("TEE。RECEIPT"));
        assert!(registry.is_registered_kind("TEE．RECEIPT"));
        assert!(registry.is_registered_kind("TEE；RECEIPT"));
        assert!(registry.is_registered_kind("TEE（RECEIPT）"));
        assert!(registry.is_registered_kind("TEE［RECEIPT］"));
        assert!(registry.is_registered_kind("TEE｛RECEIPT｝"));
        assert!(registry.is_registered_kind("“TEE RECEIPT”"));
        assert!(registry.is_registered_kind("'ZK PROOF'"));
        assert!(registry.is_registered_kind("ZK＿PROOF"));
    }

    #[test]
    fn registry_is_registered_kind_accepts_horizontal_bar_delimited_aliases() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        assert!(registry.is_registered_kind("TEE―RECEIPT"));
        assert!(registry.is_registered_kind("ZK―PROOF"));
    }

    #[test]
    fn registry_is_registered_kind_accepts_zero_width_separated_aliases() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        assert!(registry.is_registered_kind("TEE\u{200B}RECEIPT"));
        assert!(registry.is_registered_kind("TEE\u{200D}QUOTE"));
        assert!(registry.is_registered_kind("ZK\u{2060}PROOF"));
        assert!(registry.is_registered_kind("ZK\u{2061}PROOF"));
        assert!(registry.is_registered_kind("ZK\u{2062}PROOF"));
        assert!(registry.is_registered_kind("TEE\u{2063}RECEIPT"));
        assert!(registry.is_registered_kind("zero\u{FEFF}knowledge\u{200C}proof"));
    }

    #[test]
    fn registry_is_registered_kind_accepts_non_breaking_space_separated_aliases() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        assert!(registry.is_registered_kind("TEE\u{00A0}RECEIPT"));
        assert!(registry.is_registered_kind("zero\u{00A0}knowledge\u{00A0}proof"));
    }

    #[test]
    fn registry_is_registered_kind_accepts_ideographic_space_separated_aliases() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        assert!(registry.is_registered_kind("TEE\u{3000}RECEIPT"));
        assert!(registry.is_registered_kind("zero\u{3000}knowledge\u{3000}proof"));
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
