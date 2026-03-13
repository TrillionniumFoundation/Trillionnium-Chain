use std::collections::HashMap;
use std::sync::Arc;

use trnm_types::TaskObject;

#[cfg(feature = "real-zk-backend")]
use super::real_zk_backend;
use super::{
    backend::{TeeBackendRegistry, VerificationBackendConfig},
    proof_type_key, verifiers, ProofVerifier, VerificationResult,
};

pub struct VerifierRegistry {
    verifiers: HashMap<String, Arc<dyn ProofVerifier + Send + Sync>>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
        }
    }

    /// Initializes a registry with the built-in verification platform stack.
    ///
    /// Routing contract:
    /// - Fraud is a backendless semantic verifier (fail-closed envelope/binding checks only).
    /// - TEE and ZK are semantic verifiers plus configurable backend families.
    /// - Backend selection is family-scoped (`tee` vs `zk`) so config hooks and
    ///   error surfaces stay aligned even when different proof systems share the
    ///   same platform registry implementation.
    pub fn with_builtin_verifiers() -> Self {
        Self::with_backend_config(VerificationBackendConfig::default())
    }

    pub fn with_backend_config(config: VerificationBackendConfig) -> Self {
        // The underlying platform registry is shared, but TEE wiring should
        // speak in family-scoped terms so attestation call sites do not look
        // like they are configured through a ZK-only contract.
        let backend_registry = Arc::new(TeeBackendRegistry::new());
        Self::with_backends(config, backend_registry)
    }

    pub fn with_backends(
        config: VerificationBackendConfig,
        backends: Arc<TeeBackendRegistry>,
    ) -> Self {
        let mut registry = Self::new();

        // Fraud is intentionally kept as the platform's built-in semantic verifier.
        // Only TEE/ZK consume configurable backend families today.
        registry.register(Arc::new(verifiers::FraudVerifier));
        registry.register(Arc::new(verifiers::TeeVerifier::from_config(
            &config,
            Arc::clone(&backends),
        )));
        registry.register(Arc::new(verifiers::ZkVerifier::from_config(
            &config, backends,
        )));
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
                    || ch == '﹣'
                    || ch == '﹘'
                    || ch == '\u{00a0}'
                    || ch == '\u{00ad}'
                    || ch == '\u{3000}'
                    || ch == '\u{200b}'
                    || ch == '\u{200c}'
                    || ch == '\u{200d}'
                    || ch == '\u{2060}'
                    || ch == '\u{2061}'
                    || ch == '\u{2062}'
                    || ch == '\u{2063}'
                    || ch == '\u{180e}'
                    || ch == '\u{feff}'
                    || ch == '/'
                    || ch == '／'
                    || ch == '⁄'
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
                    || ch == '＝'
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
            "fraud receipt v1" | "fraudreceiptv1" | "fraud receipt v 1" | "fraud receiptv1" => {
                "fraud"
            }
            "fraud receipt v2" | "fraudreceiptv2" | "fraud receipt v 2" | "fraud receiptv2" => {
                "fraud"
            }
            "fraud receipt v3" | "fraudreceiptv3" | "fraud receipt v 3" | "fraud receiptv3" => {
                "fraud"
            }
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
            "attestation receipt" | "attestationreceipt" => "tee",
            "attestation receipt v1" | "attestationreceiptv1" | "attestation receipt v 1" => "tee",
            "attestation receipt v2" | "attestationreceiptv2" | "attestation receipt v 2" => "tee",
            "attestation receipt v3" | "attestationreceiptv3" | "attestation receipt v 3" => "tee",
            "tee attestation receipt" | "teeattestationreceipt" => "tee",
            "tee attestation receipt v1"
            | "teeattestationreceiptv1"
            | "tee attestation receipt v 1" => "tee",
            "tee attestation receipt v2"
            | "teeattestationreceiptv2"
            | "tee attestation receipt v 2" => "tee",
            "tee attestation receipt v3"
            | "teeattestationreceiptv3"
            | "tee attestation receipt v 3" => "tee",
            "tee quote" | "teequote" => "tee",
            "tee quote v1" | "teequotev1" | "tee quote v 1" => "tee",
            "tee quote v2" | "teequotev2" | "tee quote v 2" => "tee",
            "tee quote v3" | "teequotev3" | "tee quote v 3" => "tee",
            "tee report" | "teereport" => "tee",
            "tee report v1" | "teereportv1" | "tee report v 1" => "tee",
            "tee report v2" | "teereportv2" | "tee report v 2" => "tee",
            "tee report v3" | "teereportv3" | "tee report v 3" => "tee",
            "sgx quote" | "sgxquote" => "tee",
            "sgx quote v1" | "sgxquotev1" | "sgx quote v 1" => "tee",
            "sgx quote v2" | "sgxquotev2" | "sgx quote v 2" => "tee",
            "sgx quote v3" | "sgxquotev3" | "sgx quote v 3" => "tee",
            "enclave quote" | "enclavequote" => "tee",
            "sgx report" | "sgxreport" => "tee",
            "sgx report v1" | "sgxreportv1" | "sgx report v 1" => "tee",
            "sgx report v2" | "sgxreportv2" | "sgx report v 2" => "tee",
            "sgx report v3" | "sgxreportv3" | "sgx report v 3" => "tee",
            "tee evidence" | "teeevidence" => "tee",
            "attestation evidence" | "attestationevidence" => "tee",
            "tee attestation evidence" | "teeattestationevidence" => "tee",
            "attestation cert" | "attestationcert" => "tee",
            "attestation certs" | "attestationcerts" => "tee",
            "attestation cert v1" | "attestationcertv1" | "attestation cert v 1" => "tee",
            "attestation cert v2" | "attestationcertv2" | "attestation cert v 2" => "tee",
            "attestation cert v3" | "attestationcertv3" | "attestation cert v 3" => "tee",
            "attestation certificate" | "attestationcertificate" => "tee",
            "attestation certificates" | "attestationcertificates" => "tee",
            "attestation certificate v1"
            | "attestationcertificatev1"
            | "attestation certificate v 1" => "tee",
            "attestation certificate v2"
            | "attestationcertificatev2"
            | "attestation certificate v 2" => "tee",
            "attestation certificate v3"
            | "attestationcertificatev3"
            | "attestation certificate v 3" => "tee",
            "tee attestation cert" | "teeattestationcert" => "tee",
            "tee attestation certs" | "teeattestationcerts" => "tee",
            "tee attestation cert v1"
            | "teeattestationcertv1"
            | "tee attestation cert v 1" => "tee",
            "tee attestation cert v2"
            | "teeattestationcertv2"
            | "tee attestation cert v 2" => "tee",
            "tee attestation cert v3"
            | "teeattestationcertv3"
            | "tee attestation cert v 3" => "tee",
            "tee attestation certificate" | "teeattestationcertificate" => "tee",
            "tee attestation certificates" | "teeattestationcertificates" => "tee",
            "tee attestation certificate v1"
            | "teeattestationcertificatev1"
            | "tee attestation certificate v 1" => "tee",
            "tee attestation certificate v2"
            | "teeattestationcertificatev2"
            | "tee attestation certificate v 2" => "tee",
            "tee attestation certificate v3"
            | "teeattestationcertificatev3"
            | "tee attestation certificate v 3" => "tee",
            "enclave report" | "enclavereport" => "tee",
            "enclave evidence" | "enclaveevidence" => "tee",
            "remote attestation" | "remoteattestation" => "tee",
            "remote attestation v1" | "remoteattestationv1" | "remote attestation v 1" => "tee",
            "remote attestation v2" | "remoteattestationv2" | "remote attestation v 2" => "tee",
            "remote attestation v3" | "remoteattestationv3" | "remote attestation v 3" => "tee",
            "remote attestation quote" | "remoteattestationquote" => "tee",
            "tee remote attestation quote" | "teeremoteattestationquote" => "tee",
            "remote attestation report" | "remoteattestationreport" => "tee",
            "tee remote attestation report" | "teeremoteattestationreport" => "tee",
            "remote attestation receipt" | "remoteattestationreceipt" => "tee",
            "tee remote attestation receipt" | "teeremoteattestationreceipt" => "tee",
            "remote attestation evidence" | "remoteattestationevidence" => "tee",
            "tee remote attestation evidence" | "teeremoteattestationevidence" => "tee",
            "remote attestation cert" | "remoteattestationcert" => "tee",
            "remote attestation certs" | "remoteattestationcerts" => "tee",
            "remote attestation cert v1"
            | "remoteattestationcertv1"
            | "remote attestation cert v 1" => "tee",
            "remote attestation cert v2"
            | "remoteattestationcertv2"
            | "remote attestation cert v 2" => "tee",
            "remote attestation cert v3"
            | "remoteattestationcertv3"
            | "remote attestation cert v 3" => "tee",
            "remote attestation certificate" | "remoteattestationcertificate" => "tee",
            "remote attestation certificates" | "remoteattestationcertificates" => "tee",
            "remote attestation certificate v1"
            | "remoteattestationcertificatev1"
            | "remote attestation certificate v 1" => "tee",
            "remote attestation certificate v2"
            | "remoteattestationcertificatev2"
            | "remote attestation certificate v 2" => "tee",
            "remote attestation certificate v3"
            | "remoteattestationcertificatev3"
            | "remote attestation certificate v 3" => "tee",
            "tee remote attestation cert" | "teeremoteattestationcert" => "tee",
            "tee remote attestation certs" | "teeremoteattestationcerts" => "tee",
            "tee remote attestation cert v1"
            | "teeremoteattestationcertv1"
            | "tee remote attestation cert v 1" => "tee",
            "tee remote attestation cert v2"
            | "teeremoteattestationcertv2"
            | "tee remote attestation cert v 2" => "tee",
            "tee remote attestation cert v3"
            | "teeremoteattestationcertv3"
            | "tee remote attestation cert v 3" => "tee",
            "tee remote attestation certificate" | "teeremoteattestationcertificate" => "tee",
            "tee remote attestation certificates" | "teeremoteattestationcertificates" => "tee",
            "tee remote attestation certificate v1"
            | "teeremoteattestationcertificatev1"
            | "tee remote attestation certificate v 1" => "tee",
            "tee remote attestation certificate v2"
            | "teeremoteattestationcertificatev2"
            | "tee remote attestation certificate v 2" => "tee",
            "tee remote attestation certificate v3"
            | "teeremoteattestationcertificatev3"
            | "tee remote attestation certificate v 3" => "tee",
            "attestation report" | "attestationreport" => "tee",
            "attestation report v1" | "attestationreportv1" | "attestation report v 1" => "tee",
            "attestation report v2" | "attestationreportv2" | "attestation report v 2" => "tee",
            "attestation report v3" | "attestationreportv3" | "attestation report v 3" => "tee",
            "attestation quote" | "attestationquote" => "tee",
            "attestation quote v1" | "attestationquotev1" | "attestation quote v 1" => "tee",
            "attestation quote v2" | "attestationquotev2" | "attestation quote v 2" => "tee",
            "attestation quote v3" | "attestationquotev3" | "attestation quote v 3" => "tee",
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
            "tee attestation quote" | "teeattestationquote" => "tee",
            "tee attestation quote v1" | "teeattestationquotev1" | "tee attestation quote v 1" => {
                "tee"
            }
            "tee attestation quote v2" | "teeattestationquotev2" | "tee attestation quote v 2" => {
                "tee"
            }
            "tee attestation quote v3" | "teeattestationquotev3" | "tee attestation quote v 3" => {
                "tee"
            }
            "tee claims" | "teeclaims" => "tee",
            "tee claims v1" | "teeclaimsv1" | "tee claims v 1" => "tee",
            "tee claims v2" | "teeclaimsv2" | "tee claims v 2" => "tee",
            "tee claims v3" | "teeclaimsv3" | "tee claims v 3" => "tee",
            "attestation claims" | "attestationclaims" => "tee",
            "attestation claims v1" | "attestationclaimsv1" | "attestation claims v 1" => {
                "tee"
            }
            "attestation claims v2" | "attestationclaimsv2" | "attestation claims v 2" => {
                "tee"
            }
            "attestation claims v3" | "attestationclaimsv3" | "attestation claims v 3" => {
                "tee"
            }
            "tee attestation claims" | "teeattestationclaims" => "tee",
            "tee attestation claims v1"
            | "teeattestationclaimsv1"
            | "tee attestation claims v 1" => "tee",
            "tee attestation claims v2"
            | "teeattestationclaimsv2"
            | "tee attestation claims v 2" => "tee",
            "tee attestation claims v3"
            | "teeattestationclaimsv3"
            | "tee attestation claims v 3" => "tee",
            "remote attestation claims" | "remoteattestationclaims" => "tee",
            "remote attestation claims v1"
            | "remoteattestationclaimsv1"
            | "remote attestation claims v 1" => "tee",
            "remote attestation claims v2"
            | "remoteattestationclaimsv2"
            | "remote attestation claims v 2" => "tee",
            "remote attestation claims v3"
            | "remoteattestationclaimsv3"
            | "remote attestation claims v 3" => "tee",
            "tee remote attestation claims" | "teeremoteattestationclaims" => "tee",
            "tee remote attestation claims v1"
            | "teeremoteattestationclaimsv1"
            | "tee remote attestation claims v 1" => "tee",
            "tee remote attestation claims v2"
            | "teeremoteattestationclaimsv2"
            | "tee remote attestation claims v 2" => "tee",
            "tee remote attestation claims v3"
            | "teeremoteattestationclaimsv3"
            | "tee remote attestation claims v 3" => "tee",
            "ra claims" | "raclaims" => "tee",
            "ra claims v1" | "raclaimsv1" | "ra claims v 1" => "tee",
            "ra claims v2" | "raclaimsv2" | "ra claims v 2" => "tee",
            "ra claims v3" | "raclaimsv3" | "ra claims v 3" => "tee",
            "dcap claims" | "dcapclaims" => "tee",
            "tee dcap claims" | "teedcapclaims" => "tee",
            "tdx claims" | "tdxclaims" => "tee",
            "tee tdx claims" | "teetdxclaims" => "tee",
            "snp claims" | "snpclaims" => "tee",
            "tee snp claims" | "teesnpclaims" => "tee",
            "sev snp claims" | "sevsnpclaims" => "tee",
            "amd sev snp claims" | "amdsevsnpclaims" => "tee",
            "intel sgx claims" | "intelsgxclaims" => "tee",
            "intel tdx claims" | "inteltdxclaims" => "tee",
            "ra report" | "rareport" => "tee",
            "ra report v1" | "rareportv1" | "ra report v 1" => "tee",
            "ra report v2" | "rareportv2" | "ra report v 2" => "tee",
            "ra report v3" | "rareportv3" | "ra report v 3" => "tee",
            "ra quote" | "raquote" => "tee",
            "ra quote v1" | "raquotev1" | "ra quote v 1" => "tee",
            "ra quote v2" | "raquotev2" | "ra quote v 2" => "tee",
            "ra quote v3" | "raquotev3" | "ra quote v 3" => "tee",
            "dcap quote" | "dcapquote" => "tee",
            "tee dcap quote" | "teedcapquote" => "tee",
            "intel dcap quote" | "inteldcapquote" => "tee",
            "sgx dcap quote" | "sgxdcapquote" => "tee",
            "intel sgx dcap quote" | "intelsgxdcapquote" => "tee",
            "intel sgx report" | "intelsgxreport" => "tee",
            "tdx quote" | "tdxquote" => "tee",
            "tee tdx quote" | "teetdxquote" => "tee",
            "td quote" | "tdquote" => "tee",
            "tdx report" | "tdxreport" => "tee",
            "tee tdx report" | "teetdxreport" => "tee",
            "td report" | "tdreport" => "tee",
            "snp report" | "snpreport" => "tee",
            "tee snp report" | "teesnpreport" => "tee",
            "snp quote" | "snpquote" => "tee",
            "tee snp quote" | "teesnpquote" => "tee",
            "sev snp report" | "sevsnpreport" => "tee",
            "sev snp quote" | "sevsnpquote" => "tee",
            "amd sev snp report" | "amdsevsnpreport" => "tee",
            "amd sev snp quote" | "amdsevsnpquote" => "tee",
            "intel tdx quote" | "inteltdxquote" => "tee",
            "intel tdx report" | "inteltdxreport" => "tee",
            "tee cert" | "teecert" => "tee",
            "tee certs" | "teecerts" => "tee",
            "tee cert v1" | "teecertv1" | "tee cert v 1" => "tee",
            "tee cert v2" | "teecertv2" | "tee cert v 2" => "tee",
            "tee cert v3" | "teecertv3" | "tee cert v 3" => "tee",
            "tee certificate" | "teecertificate" => "tee",
            "tee certificates" | "teecertificates" => "tee",
            "tee certificate v1" | "teecertificatev1" | "tee certificate v 1" => "tee",
            "tee certificate v2" | "teecertificatev2" | "tee certificate v 2" => "tee",
            "tee certificate v3" | "teecertificatev3" | "tee certificate v 3" => "tee",
            "zk proof" | "zkproof" => "zk",
            "zk proof v1" | "zkproofv1" | "zk proof v 1" => "zk",
            "zk proof v2" | "zkproofv2" | "zk proof v 2" => "zk",
            "zk proof v3" | "zkproofv3" | "zk proof v 3" => "zk",
            "zk receipt" | "zkreceipt" => "zk",
            "zk receipt v1" | "zkreceiptv1" | "zk receipt v 1" | "zk receiptv1" => "zk",
            "zk receipt v2" | "zkreceiptv2" | "zk receipt v 2" | "zk receiptv2" => "zk",
            "zk receipt v3" | "zkreceiptv3" | "zk receipt v 3" | "zk receiptv3" => "zk",
            "zero knowledge" | "zeroknowledge" => "zk",
            "zero knowledge proof" | "zeroknowledgeproof" => "zk",
            "zero knowledge receipt" | "zeroknowledgereceipt" => "zk",
            _ => collapsed.as_str(),
        };

        Some(canonical.to_string())
    }

    pub fn register(&mut self, verifier: Arc<dyn ProofVerifier + Send + Sync>) {
        let key = Self::normalize_key(verifier.proof_type())
            .expect("proof verifier key must contain visible characters");
        self.verifiers.insert(key, verifier);
    }

    fn verifier_key_for_task(task: &TaskObject) -> String {
        proof_type_key(task.proof_type).to_string()
    }

    pub fn verify(&self, task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        let key = Self::verifier_key_for_task(task);
        if let Some(verifier) = self.verifiers.get(&key) {
            verifier.verify_proof(task, proof_data)
        } else {
            VerificationResult::Indeterminate(format!(
                "No verifier available for proof_type '{}'",
                key
            ))
        }
    }
}

impl Default for VerifierRegistry {
    fn default() -> Self {
        Self::with_builtin_verifiers()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::backend::{
        BackendExecutionError, BackendVerificationRequest, BackendVerificationSuccess,
        ZkBackendKind, ZkBackendRegistry,
    };
    use std::sync::Arc;
    use trnm_types::{ProofType, TaskObject, TaskStatus};

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

    fn task_with_proof_type(proof_type: ProofType) -> TaskObject {
        TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Completed,
            proof_type,
            metadata: None,
            worker: Some("worker1".into()),
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

    struct MockVectorBackend;
    impl crate::verification::backend::ZkBackend for MockVectorBackend {
        fn backend_id(&self) -> &str {
            "mock-zk-vectors"
        }

        fn verify(
            &self,
            request: BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            assert_eq!(request.task.task_id, 42);
            let payload =
                request
                    .zk_payload
                    .ok_or_else(|| BackendExecutionError::MalformedProof {
                        backend: request.backend_label(self.backend_id()),
                        reason: "missing parsed payload".to_string(),
                    })?;
            match payload.vk_ref.as_str() {
                "vk://trnm/dev/mock-groth16/valid" => Ok(BackendVerificationSuccess {
                    backend_id: self.backend_id().into(),
                }),
                "vk://trnm/dev/mock-groth16/invalid" => Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(self.backend_id()),
                    reason: "mock vector rejected by backend".to_string(),
                }),
                other => Err(BackendExecutionError::MalformedProof {
                    backend: request.backend_label(self.backend_id()),
                    reason: format!("unexpected vk_ref '{other}'"),
                }),
            }
        }
    }

    fn registry_with_mock_zk_backend() -> VerifierRegistry {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockVectorBackend));
        VerifierRegistry::with_backends(
            VerificationBackendConfig {
                tee_backend: ZkBackendKind::Noop,
                zk_backend: ZkBackendKind::Custom("mock-zk-vectors".into()),
                zk_features: Default::default(),
            },
            Arc::new(backends),
        )
    }

    #[test]
    fn registry_zk_vector_valid_payload_reaches_backend_path() {
        let registry = registry_with_mock_zk_backend();
        let mut task = task_with_proof_type(ProofType::Zk);
        task.status = TaskStatus::Committed;
        task.worker = Some("worker-zk".into());
        task.result_hash = Some([0x11; 32]);

        let payload = br#"ZK:{"task_id":42,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/valid","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["42","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert_eq!(registry.verify(&task, payload), VerificationResult::Valid);
    }

    #[test]
    fn registry_zk_vector_invalid_payload_reaches_backend_rejection_path() {
        let registry = registry_with_mock_zk_backend();
        let mut task = task_with_proof_type(ProofType::Zk);
        task.status = TaskStatus::Committed;
        task.worker = Some("worker-zk".into());
        task.result_hash = Some([0x11; 32]);

        let payload = br#"ZK:{"task_id":42,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/invalid","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["42","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            registry.verify(&task, payload),
            VerificationResult::Invalid(msg) if msg.contains("mock vector rejected by backend")
        ));
    }

    #[test]
    fn registry_zk_vector_malformed_envelope_fails_closed_before_crypto() {
        let registry = registry_with_mock_zk_backend();
        let mut task = task_with_proof_type(ProofType::Zk);
        task.status = TaskStatus::Committed;
        task.worker = Some("worker-zk".into());
        task.result_hash = Some([0x11; 32]);

        assert!(matches!(
            registry.verify(&task, b"ZK:   \n\t"),
            VerificationResult::Invalid(msg) if msg.contains("Invalid ZK proof envelope")
        ));
    }

    #[test]
    fn registry_zk_vector_proof_type_mismatch_fails_closed_before_crypto() {
        let registry = registry_with_mock_zk_backend();
        let mut task = task_with_proof_type(ProofType::Zk);
        task.status = TaskStatus::Committed;
        task.worker = Some("worker-zk".into());
        task.result_hash = Some([0x11; 32]);

        let payload = br#"ZK:{"task_id":42,"worker":"worker-zk","proof_type":"tee","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/valid","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["42","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            registry.verify(&task, payload),
            VerificationResult::Invalid(msg) if msg.contains("proof_type mismatch")
        ));
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
        registry.register(Arc::new(AlwaysValidVerifier { kind: "  zk  " }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_supports_known_v1_v2_aliases() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: "fraud" }));
        registry.register(Arc::new(AlwaysValidVerifier { kind: "tee" }));
        registry.register(Arc::new(AlwaysValidVerifier { kind: "zk" }));

        for proof_type in [ProofType::Fraud, ProofType::Tee, ProofType::Zk] {
            let task = task_with_proof_type(proof_type);
            assert_eq!(
                registry.verify(&task, b"receipt"),
                VerificationResult::Valid
            );
        }
    }

    #[test]
    fn registry_normalize_key_maps_extended_tee_attestation_aliases_to_tee() {
        for alias in [
            "tee quote",
            "tee report v2",
            "sgx quote v3",
            "sgx report",
            "tee evidence",
            "attestation evidence",
            "tee attestation evidence",
            "attestation cert",
            "attestation certs",
            "attestation cert v2",
            "attestation certificate",
            "attestation certificates",
            "attestation certificate v3",
            "tee attestation cert",
            "tee attestation certs",
            "tee attestation cert v1",
            "tee attestation certificate",
            "tee attestation certificates",
            "tee attestation certificate v2",
            "enclave report",
            "enclave evidence",
            "tee attestation report",
            "attestation receipt",
            "attestation receipt v3",
            "tee attestation receipt",
            "tee attestation receipt v2",
            "attestation claims",
            "attestation claims v3",
            "tee claims",
            "tee claims v2",
            "tee attestation claims",
            "tee attestation claims v2",
            "attestation quote",
            "attestation quote v3",
            "tee attestation quote",
            "tee attestation quote v2",
            "remote attestation quote",
            "tee remote attestation quote",
            "remote attestation report",
            "tee remote attestation report",
            "remote attestation receipt",
            "tee remote attestation receipt",
            "remote attestation evidence",
            "tee remote attestation evidence",
            "remote attestation claims",
            "tee remote attestation claims",
            "remote attestation cert",
            "remote attestation certs",
            "remote attestation certificate",
            "remote attestation certificates",
            "tee remote attestation cert",
            "tee remote attestation certs",
            "tee remote attestation cert v2",
            "remote attestation certificate v3",
            "tee remote attestation certificate",
            "tee remote attestation certificates",
            "tee remote attestation certificate v1",
            "ra quote",
            "ra report v2",
            "ra claims",
            "dcap quote",
            "dcap claims",
            "intel dcap quote",
            "sgx dcap quote",
            "intel sgx dcap quote",
            "tdx quote",
            "td report",
            "tdx claims",
            "tee tdx claims",
            "snp report",
            "snp claims",
            "tee snp claims",
            "amd sev snp quote",
            "amd sev snp claims",
            "intel sgx report",
            "intel sgx claims",
            "tee dcap quote",
            "tee dcap claims",
            "intel tdx quote",
            "intel tdx report",
            "intel tdx claims",
            "tee tdx quote",
            "tee tdx report",
            "tee snp report",
            "tee snp quote",
            "tee certificate",
            "tee certificates",
            "tee certs",
            "tee cert v2",
            "tee certificate v3",
            "teecertv1",
            "teecertificatev2",
            "teereportv3",
            "sgxquotev2",
            "sevsnpreport",
            "teecert",
        ] {
            assert_eq!(
                VerifierRegistry::normalize_key(alias).as_deref(),
                Some("tee")
            );
        }
    }

    #[test]
    fn registry_normalize_key_maps_separator_heavy_tee_attestation_aliases_to_tee() {
        for alias in [
            "TEE／attestation－receipt＋v２",
            "remote\u{200b}attestation\u{3000}certificate",
            "tee:remote_attestation/report",
            "TEE（attestation）quote",
            "attestation
report",
            "tee:remote_attestation/claims",
            "TEE（attestation）claims",
            "TEE＝remote attestation quote",
        ] {
            assert_eq!(
                VerifierRegistry::normalize_key(alias).as_deref(),
                Some("tee"),
                "alias={alias:?}"
            );
        }
    }
}
