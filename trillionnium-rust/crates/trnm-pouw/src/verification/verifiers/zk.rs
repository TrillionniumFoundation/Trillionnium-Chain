use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::{ProofType, TaskObject};

pub struct ZkVerifier;

fn parse_binding_envelope<'a>(raw: &'a str, expected_prefix: &str) -> Result<Vec<(&'a str, &'a str)>, String> {
    let mut parts = raw.split('|');
    let Some(prefix) = parts.next() else {
        return Err("empty proof envelope".to_string());
    };
    if prefix != expected_prefix {
        return Err(format!("invalid {} proof envelope prefix", expected_prefix));
    }

    let mut kvs = Vec::new();
    for part in parts {
        let Some((k, v)) = part.split_once('=') else {
            return Err(format!("malformed envelope segment: {}", part));
        };
        kvs.push((k, v));
    }
    Ok(kvs)
}

fn lookup<'a>(kvs: &'a [(&'a str, &'a str)], key: &str) -> Option<&'a str> {
    kvs.iter().find_map(|(k, v)| if *k == key { Some(*v) } else { None })
}

impl ProofVerifier for ZkVerifier {
    fn proof_type(&self) -> &str {
        "zk"
    }

    fn verify_proof(&self, task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        let payload = match std::str::from_utf8(proof_data) {
            Ok(v) => v,
            Err(_) => return VerificationResult::Invalid("ZK envelope must be valid UTF-8".to_string()),
        };

        let kvs = match parse_binding_envelope(payload, "ZK") {
            Ok(v) => v,
            Err(e) => return VerificationResult::Invalid(e),
        };

        if !matches!(task.proof_type, ProofType::Zk) {
            return VerificationResult::Invalid("task proof_type is not zk".to_string());
        }

        let task_id = match lookup(&kvs, "task_id").and_then(|v| v.parse::<u64>().ok()) {
            Some(v) => v,
            None => return VerificationResult::Invalid("missing/invalid task_id binding".to_string()),
        };
        if task_id != task.task_id {
            return VerificationResult::Invalid("task_id binding mismatch".to_string());
        }

        let worker = match lookup(&kvs, "worker") {
            Some(v) => v,
            None => return VerificationResult::Invalid("missing worker binding".to_string()),
        };
        if task.worker.as_deref() != Some(worker) {
            return VerificationResult::Invalid("worker binding mismatch".to_string());
        }

        let proof_type = match lookup(&kvs, "proof_type") {
            Some(v) => v,
            None => return VerificationResult::Invalid("missing proof_type binding".to_string()),
        };
        if !proof_type.eq_ignore_ascii_case("zk") {
            return VerificationResult::Invalid("proof_type binding mismatch".to_string());
        }

        let result_hash = match lookup(&kvs, "result_hash") {
            Some(v) => v,
            None => return VerificationResult::Invalid("missing result_hash binding".to_string()),
        };
        let expected_result_hash = match task.result_hash {
            Some(hash) => hex::encode(hash),
            None => return VerificationResult::Invalid("task missing result_hash for envelope binding".to_string()),
        };
        if !result_hash.eq_ignore_ascii_case(&expected_result_hash) {
            return VerificationResult::Invalid("result_hash binding mismatch".to_string());
        }

        VerificationResult::Valid
    }
}
