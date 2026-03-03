pub mod registry;
pub mod verifiers;

use serde::{Deserialize, Serialize};
use trnm_types::{ProofType, TaskObject};

/// Result of a verification attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationResult {
    /// The proof is valid and the task result is accepted.
    Valid,
    /// The proof is invalid (e.g., bad signature, bad zk-snark).
    Invalid(String),
    /// The verification could not be completed (e.g., network error, resource exhaustion).
    /// This might warrant a retry or a specific error state.
    Indeterminate(String),
}

/// A standardized receipt for verifiable execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReceipt {
    pub task_id: u64,
    pub proof_type: String,
    pub result: VerificationResult,
    pub verifier_id: String,
    pub timestamp_ms: u64,
}

impl VerificationReceipt {
    /// Creates a canonical receipt shape for persistence and downstream analytics.
    ///
    /// - `proof_type` is normalized to lowercase + trimmed.
    /// - legacy receipt aliases (`fraud_proof|tee_receipt|zk_receipt`) collapse to canonical router keys.
    /// - `verifier_id` is trimmed and falls back to `unknown-verifier` when empty.
    pub fn new(
        task_id: u64,
        proof_type: impl AsRef<str>,
        result: VerificationResult,
        verifier_id: impl AsRef<str>,
        timestamp_ms: u64,
    ) -> Self {
        let normalized_proof_type = normalize_receipt_proof_type(proof_type.as_ref());
        let verifier = verifier_id.as_ref().trim();
        Self {
            task_id,
            proof_type: if normalized_proof_type.is_empty() {
                "unknown".to_string()
            } else {
                normalized_proof_type
            },
            result,
            verifier_id: if verifier.is_empty() {
                "unknown-verifier".to_string()
            } else {
                verifier.to_string()
            },
            timestamp_ms,
        }
    }

    /// Builds a canonical receipt directly from task metadata.
    ///
    /// This avoids proof-type string drift between V1 adapter routing and persisted V2 receipts.
    pub fn from_task(
        task: &TaskObject,
        result: VerificationResult,
        verifier_id: impl AsRef<str>,
        timestamp_ms: u64,
    ) -> Self {
        Self::new(
            task.task_id,
            proof_type_key(task.proof_type),
            result,
            verifier_id,
            timestamp_ms,
        )
    }
}

fn normalize_receipt_proof_type(raw: &str) -> String {
    let lowered = raw.trim().to_ascii_lowercase();
    let ascii_compat = lowered
        .chars()
        .map(|ch| match ch {
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
        })
        .collect::<String>();
    let collapsed_tokens = ascii_compat
        .split(|ch: char| {
            ch == '_'
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
                || ch == '﹣'
                || ch == '﹘'
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
                || ch.is_whitespace()
        })
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    match collapsed_tokens.as_str() {
        "fraud proof" | "fraud receipt" | "fraud proof v1" | "fraud proof v2"
        | "fraud proof v3" | "fraud proof v 1" | "fraud proof v 2" | "fraud proof v 3"
        | "fraud receipt v1" | "fraud receipt v2" | "fraud receipt v 1"
        | "fraud receipt v 2" | "fraud receipt v3" | "fraud receipt v 3"
        | "fraud receiptv1" | "fraud receiptv2" | "fraud receiptv3" | "fraudproof"
        | "fraudproofv1" | "fraudproofv2" | "fraudproofv3" | "fraudreceipt"
        | "fraudreceiptv1" | "fraudreceiptv2" | "fraudreceiptv3" => {
            "fraud".to_string()
        }
        "tee proof"
        | "tee receipt"
        | "tee proof v1"
        | "tee proof v2"
        | "tee proof v3"
        | "tee proof v 1"
        | "tee proof v 2"
        | "tee proof v 3"
        | "tee receipt v1"
        | "tee receipt v2"
        | "tee receipt v3"
        | "tee receiptv1"
        | "tee receiptv2"
        | "tee receiptv3"
        | "tee receipt v 1"
        | "tee receipt v 2"
        | "tee receipt v 3"
        | "tee attestation"
        | "tee attestation v1"
        | "tee attestation v2"
        | "tee attestation v3"
        | "tee attestation v 1"
        | "tee attestation v 2"
        | "tee attestation v 3"
        | "tee quote"
        | "tee report"
        | "sgx quote"
        | "enclave quote"
        | "sgx report"
        | "tee evidence"
        | "remote attestation"
        | "attestation report"
        | "attestation report v1"
        | "attestation report v2"
        | "attestation report v3"
        | "attestation report v 1"
        | "attestation report v 2"
        | "attestation report v 3"
        | "tee attestation report"
        | "tee attestation report v1"
        | "tee attestation report v2"
        | "tee attestation report v3"
        | "tee attestation report v 1"
        | "tee attestation report v 2"
        | "tee attestation report v 3"
        | "ra report"
        | "ra report v1"
        | "ra report v2"
        | "ra report v3"
        | "ra report v 1"
        | "ra report v 2"
        | "ra report v 3"
        | "ra quote"
        | "ra quote v1"
        | "ra quote v2"
        | "ra quote v3"
        | "ra quote v 1"
        | "ra quote v 2"
        | "ra quote v 3"
        | "dcap quote"
        | "intel dcap quote"
        | "sgx dcap quote"
        | "intel sgx dcap quote"
        | "tdx quote"
        | "td quote"
        | "tdx report"
        | "td report"
        | "snp report"
        | "snp quote"
        | "sev snp report"
        | "sev snp quote"
        | "amd sev snp report"
        | "amd sev snp quote"
        | "intel tdx quote"
        | "tee cert"
        | "tee certificate"
        | "teeproof"
        | "teeproofv1"
        | "teeproofv2"
        | "teeproofv3"
        | "teereceipt"
        | "teereceiptv1"
        | "teereceiptv2"
        | "teereceiptv3"
        | "teeattestation"
        | "teeattestationv1"
        | "teeattestationv2"
        | "teeattestationv3"
        | "teequote"
        | "teereport"
        | "sgxquote"
        | "enclavequote"
        | "sgxreport"
        | "teeevidence"
        | "remoteattestation"
        | "attestationreport"
        | "attestationreportv1"
        | "attestationreportv2"
        | "attestationreportv3"
        | "teeattestationreport"
        | "teeattestationreportv1"
        | "teeattestationreportv2"
        | "teeattestationreportv3"
        | "rareport"
        | "rareportv1"
        | "rareportv2"
        | "rareportv3"
        | "raquote"
        | "raquotev1"
        | "raquotev2"
        | "raquotev3"
        | "dcapquote"
        | "inteldcapquote"
        | "sgxdcapquote"
        | "intelsgxdcapquote"
        | "tdxquote"
        | "tdquote"
        | "tdxreport"
        | "tdreport"
        | "snpreport"
        | "snpquote"
        | "sevsnpreport"
        | "sevsnpquote"
        | "amdsevsnpreport"
        | "amdsevsnpquote"
        | "inteltdxquote"
        | "teecert"
        | "teecertificate" => "tee".to_string(),
        "zk proof"
        | "zk receipt"
        | "zk proof v1"
        | "zk proof v2"
        | "zk proof v3"
        | "zk proof v 1"
        | "zk proof v 2"
        | "zk proof v 3"
        | "zk receipt v1"
        | "zk receipt v2"
        | "zk receipt v3"
        | "zk receiptv1"
        | "zk receiptv2"
        | "zk receiptv3"
        | "zk receipt v 1"
        | "zk receipt v 2"
        | "zk receipt v 3"
        | "zk attestation"
        | "zk evidence"
        | "zk snark"
        | "snark"
        | "zero knowledge"
        | "zero knowledge proof"
        | "zero knowledge proof v1"
        | "zero knowledge proof v2"
        | "zero knowledge proof v3"
        | "zero knowledge proof v 1"
        | "zero knowledge proof v 2"
        | "zero knowledge proof v 3"
        | "zero knowledge receipt"
        | "zero knowledge certificate"
        | "zero knowledge attestation"
        | "zero knowledge evidence"
        | "zero knowledge snark"
        | "zkproof"
        | "zkproofv1"
        | "zkproofv2"
        | "zkproofv3"
        | "zkreceipt"
        | "zkreceiptv1"
        | "zkreceiptv2"
        | "zkreceiptv3"
        | "zkattestation"
        | "zkevidence"
        | "zksnark"
        | "zkp"
        | "zk p"
        | "zeroknowledge"
        | "zeroknowledgesnark"
        | "zeroknowledgeproof"
        | "zeroknowledgeproofv1"
        | "zeroknowledgeproofv2"
        | "zeroknowledgeproofv3"
        | "zeroknowledgereceipt"
        | "zeroknowledgecertificate"
        | "zeroknowledgeattestation"
        | "zeroknowledgeevidence"
        | "zk cert"
        | "zkcert" => "zk".to_string(),
        // Keep custom plugin keys delimiter-stable so receipt persistence aligns
        // with registry normalization/observability (e.g., MY__PROOF -> "my proof").
        _ => collapsed_tokens,
    }
}

/// Returns the canonical key used across verification routing and receipt persistence.
pub fn proof_type_key(proof_type: ProofType) -> &'static str {
    match proof_type {
        ProofType::Fraud => "fraud",
        ProofType::Tee => "tee",
        ProofType::Zk => "zk",
    }
}

/// A trait for pluggable verification logic (Fraud Proof, TEE, ZK).
///
/// This allows the market to be agnostic to *how* the work is verified.
pub trait ProofVerifier {
    /// Returns the type of proof this verifier handles.
    fn proof_type(&self) -> &str;

    /// Verifies a proof for a given task.
    ///
    /// # Arguments
    /// * `task` - The task object being verified.
    /// * `proof_data` - The proof payload (e.g., TEE quote, ZK proof bytes, fraud challenge data).
    fn verify_proof(&self, task: &TaskObject, proof_data: &[u8]) -> VerificationResult;
}

/// A mock verifier for testing purposes.
pub struct MockVerifier {
    pub name: String,
    pub should_succeed: bool,
}

impl MockVerifier {
    pub fn new(name: &str, should_succeed: bool) -> Self {
        Self {
            name: name.to_string(),
            should_succeed,
        }
    }
}

impl ProofVerifier for MockVerifier {
    fn proof_type(&self) -> &str {
        &self.name
    }

    fn verify_proof(&self, _task: &TaskObject, _proof_data: &[u8]) -> VerificationResult {
        if self.should_succeed {
            VerificationResult::Valid
        } else {
            VerificationResult::Invalid(format!("Mock verification ({}) failed", self.name))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::{ProofType, TaskStatus};

    fn mock_task() -> TaskObject {
        TaskObject {
            task_id: 1,
            creator: "alice".into(),
            bounty: 100,
            status: TaskStatus::Open,
            proof_type: ProofType::Fraud,
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
    fn test_mock_verifier_success() {
        let verifier = MockVerifier::new("fraud", true);
        let task = mock_task();
        let result = verifier.verify_proof(&task, &[]);
        assert_eq!(result, VerificationResult::Valid);
        assert_eq!(verifier.proof_type(), "fraud");
    }

    #[test]
    fn test_mock_verifier_failure() {
        let verifier = MockVerifier::new("zk", false);
        let task = mock_task();
        let result = verifier.verify_proof(&task, &[]);
        assert!(matches!(result, VerificationResult::Invalid(msg) if msg.contains("zk")));
    }

    #[test]
    fn verification_receipt_json_roundtrip_preserves_fields() {
        let receipt = VerificationReceipt::new(
            42,
            "tee",
            VerificationResult::Valid,
            "tee-sgx-sim",
            1_706_000_000_000,
        );

        let encoded = serde_json::to_string(&receipt).expect("serialize receipt");
        let decoded: VerificationReceipt =
            serde_json::from_str(&encoded).expect("deserialize receipt");

        assert_eq!(decoded, receipt);
    }

    #[test]
    fn verification_receipt_new_normalizes_fields() {
        let receipt = VerificationReceipt::new(7, " TEE ", VerificationResult::Valid, "   ", 123);

        assert_eq!(receipt.task_id, 7);
        assert_eq!(receipt.proof_type, "tee");
        assert_eq!(receipt.verifier_id, "unknown-verifier");
        assert_eq!(receipt.timestamp_ms, 123);
    }

    #[test]
    fn verification_receipt_new_defaults_unknown_proof_type_when_blank() {
        let receipt = VerificationReceipt::new(
            9,
            " \n\t ",
            VerificationResult::Indeterminate("deferred".into()),
            "tee-verifier-1",
            456,
        );

        assert_eq!(receipt.proof_type, "unknown");
        assert_eq!(receipt.verifier_id, "tee-verifier-1");
        assert!(matches!(
            receipt.result,
            VerificationResult::Indeterminate(msg) if msg == "deferred"
        ));
    }

    #[test]
    fn proof_type_key_returns_canonical_router_keys() {
        assert_eq!(proof_type_key(ProofType::Fraud), "fraud");
        assert_eq!(proof_type_key(ProofType::Tee), "tee");
        assert_eq!(proof_type_key(ProofType::Zk), "zk");
    }

    #[test]
    fn verification_receipt_from_task_uses_canonical_proof_key_and_task_id() {
        let mut task = mock_task();
        task.task_id = 77;
        task.proof_type = ProofType::Tee;

        let receipt =
            VerificationReceipt::from_task(&task, VerificationResult::Valid, " tee-verifier ", 789);

        assert_eq!(receipt.task_id, 77);
        assert_eq!(receipt.proof_type, "tee");
        assert_eq!(receipt.verifier_id, "tee-verifier");
        assert_eq!(receipt.timestamp_ms, 789);
        assert_eq!(receipt.result, VerificationResult::Valid);
    }

    #[test]
    fn verification_receipt_new_collapses_legacy_receipt_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "Fraud_Proof", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, " tee_receipt ", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "ZK_RECEIPT", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_hyphenated_legacy_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraud-proof", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, " tee-receipt ", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "ZK-RECEIPT", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_unicode_dash_legacy_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraud—proof", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, " tee–receipt ", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "ZK—RECEIPT", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_horizontal_bar_legacy_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraud―proof", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "tee―receipt", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "zk―proof", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_unicode_minus_legacy_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraud−proof", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "tee−receipt", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "zk−proof", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_unicode_hyphen_legacy_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraud‐proof", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "tee‑receipt", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "zk‐proof", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_space_delimited_legacy_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "Fraud Proof", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, " tee receipt ", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "ZK RECEIPT", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_unicode_whitespace_delimited_aliases_to_router_keys() {
        let tee =
            VerificationReceipt::new(1, "TEE\u{3000}RECEIPT", VerificationResult::Valid, "v", 1);
        let zk = VerificationReceipt::new(2, "ZK\u{00A0}PROOF", VerificationResult::Valid, "v", 2);

        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_zero_width_delimited_aliases_to_router_keys() {
        let tee =
            VerificationReceipt::new(1, "TEE\u{200B}RECEIPT", VerificationResult::Valid, "v", 1);
        let zk = VerificationReceipt::new(
            2,
            "zero\u{FEFF}knowledge\u{200C}proof",
            VerificationResult::Valid,
            "v",
            2,
        );
        let zk_invisible_separator =
            VerificationReceipt::new(3, "ZK\u{2061}PROOF", VerificationResult::Valid, "v", 3);
        let zk_invisible_times =
            VerificationReceipt::new(4, "ZK\u{2062}PROOF", VerificationResult::Valid, "v", 4);
        let tee_invisible_separator =
            VerificationReceipt::new(5, "TEE\u{2063}RECEIPT", VerificationResult::Valid, "v", 5);

        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
        assert_eq!(zk_invisible_separator.proof_type, "zk");
        assert_eq!(zk_invisible_times.proof_type, "zk");
        assert_eq!(tee_invisible_separator.proof_type, "tee");
    }

    #[test]
    fn verification_receipt_new_collapses_legacy_fraud_receipt_aliases_to_router_key() {
        let snake = VerificationReceipt::new(1, "Fraud_Receipt", VerificationResult::Valid, "v", 1);
        let hyphen =
            VerificationReceipt::new(2, " fraud-receipt ", VerificationResult::Valid, "v", 2);
        let space = VerificationReceipt::new(3, "FRAUD RECEIPT", VerificationResult::Valid, "v", 3);

        assert_eq!(snake.proof_type, "fraud");
        assert_eq!(hyphen.proof_type, "fraud");
        assert_eq!(space.proof_type, "fraud");
    }

    #[test]
    fn verification_receipt_new_collapses_legacy_tee_zk_proof_aliases_to_router_keys() {
        let tee_snake = VerificationReceipt::new(1, "TEE_PROOF", VerificationResult::Valid, "v", 1);
        let tee_hyphen =
            VerificationReceipt::new(2, " tee-proof ", VerificationResult::Valid, "v", 2);
        let tee_space = VerificationReceipt::new(3, "tee proof", VerificationResult::Valid, "v", 3);

        let zk_snake = VerificationReceipt::new(4, "ZK_PROOF", VerificationResult::Valid, "v", 4);
        let zk_hyphen =
            VerificationReceipt::new(5, " zk-proof ", VerificationResult::Valid, "v", 5);
        let zk_space = VerificationReceipt::new(6, "zk proof", VerificationResult::Valid, "v", 6);

        assert_eq!(tee_snake.proof_type, "tee");
        assert_eq!(tee_hyphen.proof_type, "tee");
        assert_eq!(tee_space.proof_type, "tee");

        assert_eq!(zk_snake.proof_type, "zk");
        assert_eq!(zk_hyphen.proof_type, "zk");
        assert_eq!(zk_space.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_version_suffixed_legacy_aliases_to_router_keys() {
        let fraud =
            VerificationReceipt::new(1, "fraud_receipt_v3", VerificationResult::Valid, "v", 1);
        let fraud_proof_v3 =
            VerificationReceipt::new(2, "Fraud-Proof-V_3", VerificationResult::Valid, "v", 2);
        let tee = VerificationReceipt::new(3, "TEE-PROOF-V1", VerificationResult::Valid, "v", 2);
        let tee_v3 =
            VerificationReceipt::new(3, "tee receipt v 3", VerificationResult::Valid, "v", 3);
        let tee_proof_v3 =
            VerificationReceipt::new(4, "TEE_PROOF_V_3", VerificationResult::Valid, "v", 4);
        let zk = VerificationReceipt::new(5, "zk receipt v3", VerificationResult::Valid, "v", 5);
        let zk_proof_v3 =
            VerificationReceipt::new(6, "zk-proof-v-3", VerificationResult::Valid, "v", 6);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(fraud_proof_v3.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(tee_v3.proof_type, "tee");
        assert_eq!(tee_proof_v3.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
        assert_eq!(zk_proof_v3.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_repeated_separator_aliases_to_router_keys() {
        let fraud =
            VerificationReceipt::new(1, "FRAUD__RECEIPT", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "tee---proof", VerificationResult::Valid, "v", 2);
        let zk =
            VerificationReceipt::new(3, "zk\t\n  __--receipt", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_slash_dot_colon_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraud/receipt", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "TEE:PROOF", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "zk.receipt", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_plus_delimited_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraud+proof", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "TEE+RECEIPT", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "zk+receipt", VerificationResult::Valid, "v", 3);
        let tee_fullwidth =
            VerificationReceipt::new(4, "TEE＋RECEIPT", VerificationResult::Valid, "v", 4);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
        assert_eq!(tee_fullwidth.proof_type, "tee");
    }

    #[test]
    fn verification_receipt_new_collapses_extended_registry_delimiters_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraud|receipt", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "TEE\\PROOF", VerificationResult::Valid, "v", 2);
        let tee_fullwidth =
            VerificationReceipt::new(3, "TEE＼PROOF", VerificationResult::Valid, "v", 3);
        let zk = VerificationReceipt::new(4, "zk@receipt", VerificationResult::Valid, "v", 4);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(tee_fullwidth.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_fullwidth_pipe_aliases_to_router_keys() {
        let fraud =
            VerificationReceipt::new(1, "fraud｜receipt", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "TEE｜PROOF", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "zk｜attestation", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_fullwidth_comma_and_semicolon_aliases() {
        let tee = VerificationReceipt::new(1, "TEE，RECEIPT", VerificationResult::Valid, "v", 1);
        let zk = VerificationReceipt::new(2, "ZK；PROOF", VerificationResult::Valid, "v", 2);
        let fraud =
            VerificationReceipt::new(3, "FRAUD、RECEIPT", VerificationResult::Valid, "v", 3);

        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
        assert_eq!(fraud.proof_type, "fraud");
    }

    #[test]
    fn verification_receipt_new_collapses_cjk_full_stop_aliases_to_router_keys() {
        let fraud =
            VerificationReceipt::new(1, "FRAUD。RECEIPT", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "TEE。PROOF", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "ZK。RECEIPT", VerificationResult::Valid, "v", 3);
        let tee_fullwidth_dot =
            VerificationReceipt::new(4, "TEE．RECEIPT", VerificationResult::Valid, "v", 4);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
        assert_eq!(tee_fullwidth_dot.proof_type, "tee");
    }

    #[test]
    fn verification_receipt_new_collapses_middle_dot_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraud·receipt", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "TEE・PROOF", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "zk∙attestation", VerificationResult::Valid, "v", 3);
        let zk_dot_operator =
            VerificationReceipt::new(4, "zk⋅proof", VerificationResult::Valid, "v", 4);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
        assert_eq!(zk_dot_operator.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_ampersand_delimited_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraud&proof", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "TEE&RECEIPT", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "zk&attestation", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_punctuation_wrapped_aliases_to_router_keys() {
        let fraud =
            VerificationReceipt::new(1, "?!fraud?!receipt!?", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "!!TEE??PROOF!!", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "??zk!!receipt??", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_fullwidth_punctuation_wrapped_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(
            1,
            "？！fraud？！receipt！？",
            VerificationResult::Valid,
            "v",
            1,
        );
        let tee = VerificationReceipt::new(2, "！！TEE？？PROOF！！", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "？？zk！！receipt？？", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_registry_parenthesis_quote_aliases_to_router_keys() {
        let fraud =
            VerificationReceipt::new(1, "(FRAUD'RECEIPT')", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "\"TEE\"[QUOTE]", VerificationResult::Valid, "v", 2);
        let zk =
            VerificationReceipt::new(3, "<zk>{attestation}", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_compact_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraudproof", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "teereceipt", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "zkattestation", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_glued_tee_receipt_version_aliases_to_router_key() {
        let v1 = VerificationReceipt::new(1, "TEE_RECEIPTV1", VerificationResult::Valid, "v", 1);
        let v2 = VerificationReceipt::new(2, "tee receiptv2", VerificationResult::Valid, "v", 2);
        let v3 = VerificationReceipt::new(3, "tee-receiptv3", VerificationResult::Valid, "v", 3);

        assert_eq!(v1.proof_type, "tee");
        assert_eq!(v2.proof_type, "tee");
        assert_eq!(v3.proof_type, "tee");
    }

    #[test]
    fn verification_receipt_new_collapses_glued_fraud_and_zk_receipt_version_aliases_to_router_keys() {
        let fraud_v1 =
            VerificationReceipt::new(1, "fraud receiptv1", VerificationResult::Valid, "v", 1);
        let fraud_v2 =
            VerificationReceipt::new(2, "fraud-receiptv2", VerificationResult::Valid, "v", 2);
        let zk_v1 = VerificationReceipt::new(3, "zk receiptv1", VerificationResult::Valid, "v", 3);
        let zk_v3 = VerificationReceipt::new(4, "zk-receiptv3", VerificationResult::Valid, "v", 4);

        assert_eq!(fraud_v1.proof_type, "fraud");
        assert_eq!(fraud_v2.proof_type, "fraud");
        assert_eq!(zk_v1.proof_type, "zk");
        assert_eq!(zk_v3.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_zero_knowledge_aliases_to_zk_router_key() {
        let spaced = VerificationReceipt::new(
            1,
            "zero knowledge receipt",
            VerificationResult::Valid,
            "v",
            1,
        );
        let underscored =
            VerificationReceipt::new(2, "ZERO_KNOWLEDGE_PROOF", VerificationResult::Valid, "v", 2);
        let compact = VerificationReceipt::new(
            3,
            "ZeroKnowledgeAttestation",
            VerificationResult::Valid,
            "v",
            3,
        );
        let snark_spaced =
            VerificationReceipt::new(4, "zero knowledge snark", VerificationResult::Valid, "v", 4);
        let snark_compact =
            VerificationReceipt::new(5, "ZeroKnowledgeSnark", VerificationResult::Valid, "v", 5);
        let versioned =
            VerificationReceipt::new(6, "zero-knowledge-proof-v2", VerificationResult::Valid, "v", 6);

        assert_eq!(spaced.proof_type, "zk");
        assert_eq!(underscored.proof_type, "zk");
        assert_eq!(compact.proof_type, "zk");
        assert_eq!(snark_spaced.proof_type, "zk");
        assert_eq!(snark_compact.proof_type, "zk");
        assert_eq!(versioned.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_registry_aliases_for_tee_report_and_zk_snark() {
        let tee_report =
            VerificationReceipt::new(1, "TEE_REPORT", VerificationResult::Valid, "v", 1);
        let zk_snark = VerificationReceipt::new(2, "zk-snark", VerificationResult::Valid, "v", 2);

        assert_eq!(tee_report.proof_type, "tee");
        assert_eq!(zk_snark.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_registry_aliases_for_tee_sgx_and_zk_evidence() {
        let tee_sgx = VerificationReceipt::new(1, "SGX_QUOTE", VerificationResult::Valid, "v", 1);
        let tee_evidence =
            VerificationReceipt::new(2, "tee-evidence", VerificationResult::Valid, "v", 2);
        let zk_evidence = VerificationReceipt::new(
            3,
            "zero knowledge evidence",
            VerificationResult::Valid,
            "v",
            3,
        );

        assert_eq!(tee_sgx.proof_type, "tee");
        assert_eq!(tee_evidence.proof_type, "tee");
        assert_eq!(zk_evidence.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_registry_aliases_for_sgx_tdx_and_short_cert_labels() {
        let tee_sgx_report =
            VerificationReceipt::new(1, "SGX_REPORT", VerificationResult::Valid, "v", 1);
        let tee_tdx_report =
            VerificationReceipt::new(2, "tdx-report", VerificationResult::Valid, "v", 2);
        let tee_short_cert =
            VerificationReceipt::new(3, "tee cert", VerificationResult::Valid, "v", 3);
        let zk_short_cert =
            VerificationReceipt::new(4, "zk cert", VerificationResult::Valid, "v", 4);

        assert_eq!(tee_sgx_report.proof_type, "tee");
        assert_eq!(tee_tdx_report.proof_type, "tee");
        assert_eq!(tee_short_cert.proof_type, "tee");
        assert_eq!(zk_short_cert.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_registry_aliases_for_td_snp_and_enclave_quotes() {
        let tee_enclave_quote =
            VerificationReceipt::new(1, "enclave quote", VerificationResult::Valid, "v", 1);
        let tee_td_report =
            VerificationReceipt::new(2, "td_report", VerificationResult::Valid, "v", 2);
        let tee_snp_report =
            VerificationReceipt::new(3, "AMD-SEV-SNP report", VerificationResult::Valid, "v", 3);

        assert_eq!(tee_enclave_quote.proof_type, "tee");
        assert_eq!(tee_td_report.proof_type, "tee");
        assert_eq!(tee_snp_report.proof_type, "tee");
    }

    #[test]
    fn verification_receipt_new_collapses_snp_quote_aliases_to_tee_router_key() {
        let snp_quote = VerificationReceipt::new(1, "SNP_QUOTE", VerificationResult::Valid, "v", 1);
        let sev_snp_quote =
            VerificationReceipt::new(2, "SEV-SNP quote", VerificationResult::Valid, "v", 2);
        let amd_sev_snp_quote =
            VerificationReceipt::new(3, "AMD SEV SNP QUOTE", VerificationResult::Valid, "v", 3);

        assert_eq!(snp_quote.proof_type, "tee");
        assert_eq!(sev_snp_quote.proof_type, "tee");
        assert_eq!(amd_sev_snp_quote.proof_type, "tee");
    }

    #[test]
    fn verification_receipt_new_collapses_remote_attestation_and_zero_knowledge_aliases() {
        let tee_remote =
            VerificationReceipt::new(1, "remote attestation", VerificationResult::Valid, "v", 1);
        let tee_attestation_report = VerificationReceipt::new(
            2,
            "TEE attestation report",
            VerificationResult::Valid,
            "v",
            2,
        );
        let tee_attestation_report_v2 = VerificationReceipt::new(
            3,
            "TEE attestation report v2",
            VerificationResult::Valid,
            "v",
            3,
        );
        let tee_attestation_v2 =
            VerificationReceipt::new(4, "TEE_ATTESTATION_V2", VerificationResult::Valid, "v", 4);
        let zk_bare =
            VerificationReceipt::new(5, "zero knowledge", VerificationResult::Valid, "v", 5);

        assert_eq!(tee_remote.proof_type, "tee");
        assert_eq!(tee_attestation_report.proof_type, "tee");
        assert_eq!(tee_attestation_report_v2.proof_type, "tee");
        assert_eq!(tee_attestation_v2.proof_type, "tee");
        assert_eq!(zk_bare.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_percent_star_tilde_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraud%receipt", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "TEE*PROOF", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "zk~attestation", VerificationResult::Valid, "v", 3);
        let tee_fullwidth =
            VerificationReceipt::new(4, "TEE～RECEIPT", VerificationResult::Valid, "v", 4);
        let zk_wave_dash =
            VerificationReceipt::new(5, "zk〜proof", VerificationResult::Valid, "v", 5);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
        assert_eq!(tee_fullwidth.proof_type, "tee");
        assert_eq!(zk_wave_dash.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_caret_delimited_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraud^receipt", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "TEE^PROOF", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "zk^attestation", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_dollar_delimited_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraud$receipt", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "tee$proof", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "zk$attestation", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_backtick_delimited_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraud`receipt", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, "TEE`PROOF", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "zk`attestation", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_normalizes_custom_plugin_keys_like_registry() {
        let receipt = VerificationReceipt::new(
            11,
            "  MY__CUSTOM--PROOF  ",
            VerificationResult::Valid,
            "v",
            11,
        );

        assert_eq!(receipt.proof_type, "my custom proof");
    }

    #[test]
    fn verification_receipt_new_supports_registry_parity_aliases_and_fullwidth_delimiters() {
        let tee_fullwidth =
            VerificationReceipt::new(1, "RA：QUOTE", VerificationResult::Valid, "v", 1);
        let tee_certificate =
            VerificationReceipt::new(2, "tee-certificate", VerificationResult::Valid, "v", 2);
        let zk_short = VerificationReceipt::new(3, "zkp", VerificationResult::Valid, "v", 3);
        let zk_certificate = VerificationReceipt::new(
            4,
            "zero knowledge certificate",
            VerificationResult::Valid,
            "v",
            4,
        );
        let tee_intel_sgx_dcap =
            VerificationReceipt::new(5, "Intel SGX DCAP Quote", VerificationResult::Valid, "v", 5);
        let tee_intel_sgx_dcap_marked = VerificationReceipt::new(
            6,
            "Intel® SGX™ DCAP Quote",
            VerificationResult::Valid,
            "v",
            6,
        );
        let tee_sgx_dcap =
            VerificationReceipt::new(7, "SGX DCAP Quote", VerificationResult::Valid, "v", 7);

        assert_eq!(tee_fullwidth.proof_type, "tee");
        assert_eq!(tee_certificate.proof_type, "tee");
        assert_eq!(zk_short.proof_type, "zk");
        assert_eq!(zk_certificate.proof_type, "zk");
        assert_eq!(tee_intel_sgx_dcap.proof_type, "tee");
        assert_eq!(tee_intel_sgx_dcap_marked.proof_type, "tee");
        assert_eq!(tee_sgx_dcap.proof_type, "tee");
    }

    #[test]
    fn verification_receipt_new_collapses_snark_alias_to_zk_router_key() {
        let zk = VerificationReceipt::new(5, "snark", VerificationResult::Valid, "v", 5);

        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_fullwidth_brackets_and_smart_quotes_aliases() {
        let tee =
            VerificationReceipt::new(1, "“TEE（RECEIPT）”", VerificationResult::Valid, "v", 1);
        let zk = VerificationReceipt::new(2, "‘ZK｛PROOF｝’", VerificationResult::Valid, "v", 2);

        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_registry_dash_variants_to_router_keys() {
        let figure_dash =
            VerificationReceipt::new(1, "TEE‒RECEIPT", VerificationResult::Valid, "v", 1);
        let small_em_dash =
            VerificationReceipt::new(2, "TEE﹘RECEIPT", VerificationResult::Valid, "v", 2);

        assert_eq!(figure_dash.proof_type, "tee");
        assert_eq!(small_em_dash.proof_type, "tee");
    }
}
