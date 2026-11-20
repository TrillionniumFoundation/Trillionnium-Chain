//! Observation of the actual retained public Research crate. No payload rules
//! or canonical encoders are reproduced here; flat bytes only marshal the ABI.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use trnm_research_protocol::*;

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

pub(crate) fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn uint(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn key(out: &mut Vec<u8>, value: ExternalKey) {
    out.extend_from_slice(value.as_bytes());
}
fn reference(out: &mut Vec<u8>, value: &ObjectRefV1) {
    uint(out, value.kind as u64);
    key(out, value.key);
    uint(out, value.object_version);
}
fn option(out: &mut Vec<u8>, value: &Option<Digest32>) {
    uint(out, u64::from(value.is_some()));
    if let Some(v) = value {
        out.extend_from_slice(v);
    }
}
fn shares(out: &mut Vec<u8>, values: &[ClaimShareV1]) {
    uint(out, values.len() as u64);
    for v in values {
        key(out, v.contributor);
        uint(out, u64::from(v.share_bps));
    }
}

pub(crate) fn flat(command: &ResearchCommandV1) -> Vec<u8> {
    let mut out = Vec::new();
    match command {
        ResearchCommandV1::MatchEvidenceCommitment(v) => {
            key(&mut out, v.commitment_id);
            key(&mut out, v.match_id);
            key(&mut out, v.challenge_id);
            for digest in [
                v.event_root,
                v.roster_root,
                v.ruleset_hash,
                v.dataset_hash,
                v.archive_hash,
            ] {
                out.extend_from_slice(&digest);
            }
            uint(&mut out, v.event_count);
            uint(&mut out, v.completed_at_unix_s);
        }
        ResearchCommandV1::EvaluationCommitment(v) => {
            key(&mut out, v.evaluation_id);
            reference(&mut out, &v.match_evidence_ref);
            for digest in [v.submission_hash, v.rubric_hash, v.evaluation_hash] {
                out.extend_from_slice(&digest);
            }
            option(&mut out, &v.reproduction_hash);
            uint(&mut out, u64::from(v.score_bps));
            uint(&mut out, u64::from(v.accepted));
            uint(&mut out, v.completed_at_unix_s);
        }
        ResearchCommandV1::IssueWorkloadReceipt(v) => {
            key(&mut out, v.receipt_id);
            reference(&mut out, &v.evaluation_ref);
            uint(&mut out, v.contributors.len() as u64);
            for c in &v.contributors {
                key(&mut out, c.contributor);
                uint(&mut out, c.role as u64);
                uint(&mut out, c.accepted_work_units);
                out.extend_from_slice(&c.contribution_hash);
            }
            uint(&mut out, v.total_accepted_work_units);
            out.extend_from_slice(&v.policy_hash);
            uint(&mut out, v.issued_at_unix_s);
        }
        ResearchCommandV1::CreateResearchClaim(v) => {
            key(&mut out, v.claim_id);
            reference(&mut out, &v.workload_receipt_ref);
            uint(&mut out, v.evidence_refs.len() as u64);
            for r in &v.evidence_refs {
                reference(&mut out, r);
            }
            out.extend_from_slice(&v.artifact_hash);
            out.extend_from_slice(&v.claim_scope_hash);
            shares(&mut out, &v.claimants);
            uint(&mut out, v.created_at_unix_s);
        }
        ResearchCommandV1::DeclareLicense(v) => {
            key(&mut out, v.declaration_id);
            reference(&mut out, &v.claim_ref);
            key(&mut out, v.licensor);
            uint(&mut out, v.scope as u64);
            uint(&mut out, v.spdx_expression.len() as u64);
            out.extend_from_slice(v.spdx_expression.as_bytes());
            option(&mut out, &v.additional_terms_hash);
            uint(&mut out, v.effective_at_unix_s);
        }
        ResearchCommandV1::ChallengeResearchClaim(v) => {
            key(&mut out, v.challenge_id);
            reference(&mut out, &v.claim_ref);
            key(&mut out, v.challenger);
            uint(&mut out, v.reason as u64);
            out.extend_from_slice(&v.evidence_hash);
            uint(&mut out, v.opened_at_unix_s);
        }
        ResearchCommandV1::ResolveResearchClaim(v) => {
            key(&mut out, v.resolution_id);
            reference(&mut out, &v.challenge_ref);
            uint(&mut out, v.decision as u64);
            out.extend_from_slice(&v.resolution_hash);
            shares(&mut out, &v.amended_claimants);
            uint(&mut out, v.decided_at_unix_s);
        }
    }
    out
}

pub(crate) fn validation(e: &ResearchPayloadValidationError) -> (u64, &'static str, u64, u64) {
    use ResearchPayloadValidationError::*;
    match e {
        ZeroExternalKey(name) => (101, name, 0, 0),
        ZeroObjectVersion(name) => (102, name, 0, 0),
        WrongReferenceKind {
            field,
            expected,
            got,
        } => (103, field, *expected as u64, *got as u64),
        ZeroDigest(name) => (104, name, 0, 0),
        ZeroValue(name) => (105, name, 0, 0),
        ZeroTimestamp => (106, "", 0, 0),
        InvalidCollectionSize(name) => (107, name, 0, 0),
        NonCanonicalOrdering(name) => (108, name, 0, 0),
        BasisPointsOutOfRange(name) => (109, name, 0, 0),
        ClaimShareTotalMismatch(total) => (110, "", u64::from(*total), 0),
        WorkUnitTotalMismatch { declared, computed } => (111, "", *declared, *computed),
        WorkUnitOverflow => (112, "", 0, 0),
        InconsistentEvaluation => (113, "", 0, 0),
        InvalidSpdxExpression => (114, "", 0, 0),
        UnexpectedAmendedClaimants => (115, "", 0, 0),
    }
}

pub(crate) fn canonical(e: &CanonicalDecodeError) -> (u64, &'static str, u64, u64) {
    use CanonicalDecodeError::*;
    match e {
        UnexpectedEof => (1, "", 0, 0),
        UnexpectedType => (2, "", 0, 0),
        ForbiddenAdditionalInfo => (3, "", 0, 0),
        NonMinimalEncoding => (4, "", 0, 0),
        InvalidUtf8 => (5, "", 0, 0),
        ArrayLengthMismatch { expected, got } => (6, "", *expected as u64, *got as u64),
        ByteLengthMismatch { expected, got } => (7, "", *expected as u64, *got as u64),
        UnsupportedVersion(v) => (8, "", *v, 0),
        UnknownDiscriminant { name, value } => (9, name, *value, 0),
        TrailingBytes => (10, "", 0, 0),
        NonCanonicalRoundTrip => (11, "", 0, 0),
    }
}

fn observe(input: Value) -> Value {
    let op = input["op"].as_u64().unwrap();
    let command: ResearchCommandV1 = if op == 3 {
        match ResearchCommandV1::from_canonical_bytes(&unhex(input["cbor"].as_str().unwrap())) {
            Ok(v) => v,
            Err(e) => {
                let fields = match &e {
                    ResearchCommandDecodeError::Canonical(v) => canonical(v),
                    ResearchCommandDecodeError::InvalidPayload(v) => validation(v),
                };
                return json!({"code":fields.0,"name":fields.1,"detail1":fields.2,"detail2":fields.3,"error":e.to_string()});
            }
        }
    } else {
        serde_json::from_value(input["command"].clone()).unwrap()
    };
    let flattened = flat(&command);
    if op != 1 {
        if let Err(e) = command.validate() {
            let fields = validation(&e);
            return json!({"code":fields.0,"name":fields.1,"detail1":fields.2,"detail2":fields.3,"error":e.to_string(),"flat_input":hex(&flattened)});
        }
    }
    let primary = command.primary_object_ref();
    let payload = match &command {
        ResearchCommandV1::MatchEvidenceCommitment(v) => v.canonical_bytes(),
        ResearchCommandV1::EvaluationCommitment(v) => v.canonical_bytes(),
        ResearchCommandV1::IssueWorkloadReceipt(v) => v.canonical_bytes(),
        ResearchCommandV1::CreateResearchClaim(v) => v.canonical_bytes(),
        ResearchCommandV1::DeclareLicense(v) => v.canonical_bytes(),
        ResearchCommandV1::ChallengeResearchClaim(v) => v.canonical_bytes(),
        ResearchCommandV1::ResolveResearchClaim(v) => v.canonical_bytes(),
    };
    json!({"code":0,"name":"","detail1":0,"detail2":0,"flat_input":hex(&flattened),"flat":hex(&flattened),
           "canonical":hex(&command.canonical_bytes()),"payload":hex(&payload),"command_type":command.command_type(),
           "kind":primary.kind as u64,"key":hex(primary.key.as_bytes()),"object_version":primary.object_version,
           "object_ref":hex(&primary.canonical_bytes())})
}

fn main() {
    for line in io::stdin().lock().lines() {
        let value: Value = serde_json::from_str(&line.unwrap()).unwrap();
        println!("{}", observe(value));
    }
}
