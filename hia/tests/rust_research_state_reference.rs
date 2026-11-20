//! Observe the retained public state API; JSON only transports typed values.
#[allow(dead_code)]
#[path = "rust_research_payload_reference.rs"]
mod payload;
use ed25519_dalek::SigningKey;
use payload::{hex, unhex, validation};
use serde_json::{json, Value};
use std::io::{self, BufRead};
use trnm_research_protocol::*;

fn identity(v: &Value) -> AuthorityIdentityV1 {
    AuthorityIdentityV1 {
        signer_did: v["signer_did"].as_str().unwrap().into(),
        public_key: serde_json::from_value(v["public_key"].clone()).unwrap(),
    }
}
fn authorities(v: &Value) -> AuthoritySetV1 {
    AuthoritySetV1 {
        nakama_authorities: v["nakama_authorities"].as_array().unwrap().iter().map(identity).collect(),
        hepta_authorities: v["hepta_authorities"].as_array().unwrap().iter().map(identity).collect(),
    }
}
fn snapshot(v: &Value) -> ResearchProtocolSnapshotV1 {
    ResearchProtocolSnapshotV1 {
        protocol_version: serde_json::from_value(v["protocol_version"].clone()).unwrap(),
        authorities: authorities(&v["authorities"]),
        matches: serde_json::from_value(v["matches"].clone()).unwrap(),
        evaluations: serde_json::from_value(v["evaluations"].clone()).unwrap(),
        workload_receipts: serde_json::from_value(v["workload_receipts"].clone()).unwrap(),
        claims: serde_json::from_value(v["claims"].clone()).unwrap(),
        licenses: serde_json::from_value(v["licenses"].clone()).unwrap(),
        challenges: serde_json::from_value(v["challenges"].clone()).unwrap(),
        resolutions: serde_json::from_value(v["resolutions"].clone()).unwrap(),
        applied_commands: serde_json::from_value(v["applied_commands"].clone()).unwrap(),
    }
}
fn failure(e: &ProtocolStateError) -> Value {
    use ProtocolStateError::*;
    let (code, details) = match e {
        InvalidCommand(v) => (401, json!({"error": v.to_string()})),
        InvalidPayload(v) => { let (code, name, a, b) = validation(v); (402, json!({"code": code, "name": name, "a": a, "b": b})) },
        AlteredReplay { command_id } => (403, json!({"command_id": command_id})),
        ChainIdMismatch { expected, actual } => (404, json!({"expected": expected, "actual": actual})),
        SignerNonceReplay { chain_id, signer_did, nonce, last_nonce } => (405, json!({"chain_id": chain_id, "signer_did": signer_did, "nonce": nonce, "last_nonce": last_nonce})),
        InvalidAuthoritySet => (301, json!({})),
        InvalidChainBinding => (406, json!({})),
        MissingChainBinding => (407, json!({})),
        ChainMismatch { expected, got } => (408, json!({"expected": expected, "actual": got})),
        UnauthorizedAuthority { signer_did, role, public_key } => (409, json!({"signer_did": signer_did, "role": role, "public_key": public_key})),
        DuplicateObject { kind, key } => (410, json!({"kind": *kind as u64, "key": key})),
        MissingReferencedObject(object_ref) => (411, json!({"object_ref": object_ref})),
        ObjectVersionMismatch { object_ref, actual } => (412, json!({"object_ref": object_ref, "actual": actual})),
        ObjectVersionExhausted(object_ref) => (413, json!({"object_ref": object_ref})),
        RejectedEvaluationCannotIssueWorkload => (414, json!({})),
        ClaimantWithoutAcceptedWork => (415, json!({})),
        ClaimMissingWorkloadEvaluation => (416, json!({})),
        LicensorIsNotClaimant => (417, json!({})),
        ClaimNotLicensable(status) => (418, json!({"status": *status as u64})),
        ClaimNotChallengeable(status) => (419, json!({"status": *status as u64})),
        ChallengeAlreadyResolved => (420, json!({})),
        ChallengeClaimStateMismatch => (421, json!({})),
        TimestampRegression => (422, json!({})),
        UnsupportedSnapshotVersion(version) => (423, json!({"version": version})),
        InvalidSnapshotGraph => (424, json!({})),
    };
    json!({"code": code, "details": details, "error": e.to_string()})
}
fn state_observation(state: &ResearchProtocolState) -> Value {
    let refs = state.current_object_refs();
    let objects: Vec<_> = refs.iter().map(|r| {
        let value = match r.kind {
            ResearchObjectKind::MatchEvidence => json!(state.get_match(r.key)),
            ResearchObjectKind::EvaluationCommitment => json!(state.get_evaluation(r.key)),
            ResearchObjectKind::WorkloadReceipt => json!(state.get_workload_receipt(r.key)),
            ResearchObjectKind::ResearchClaim => json!(state.get_claim(r.key)),
            ResearchObjectKind::LicenseDeclaration => json!(state.get_license(r.key)),
            ResearchObjectKind::ClaimChallenge => json!(state.get_challenge(r.key)),
            ResearchObjectKind::ClaimResolution => json!(state.get_resolution(r.key)),
        };
        json!({"object_ref": r, "value": value,
               "canonical": hex(&state.object_canonical_bytes(*r).unwrap()),
               "leaf_hash": hex(&state.object_leaf_hash(*r).unwrap())})
    }).collect();
    json!({"code": 0, "details": {}, "chain_id": state.chain_id(),
           "authorities": state.authorities(), "snapshot": state.export_snapshot(),
           "canonical": hex(&state.canonical_snapshot_bytes()),
           "hash": hex(&state.canonical_snapshot_hash()), "refs": refs, "objects": objects,
           "clone_equal": state.clone() == *state})
}
fn signed(v: &Value) -> Result<SignedResearchCommandV1, SignedResearchCommandValidationError> {
    let v = v.get("signed").unwrap_or(v);
    let role = serde_json::from_value(v["signer_role"].clone()).unwrap();
    let command = serde_json::from_value(v["command"].clone()).unwrap();
    let command_id = serde_json::from_value(v["command_id"].clone()).unwrap();
    if let Some(seed) = v.get("seed").and_then(Value::as_str) {
        let seed: [u8; 32] = unhex(seed).try_into().unwrap();
        SignedResearchCommandV1::sign(v["chain_id"].as_str().unwrap().into(), command_id,
            v["signer_did"].as_str().unwrap().into(), role, v["nonce"].as_u64().unwrap(),
            command, &SigningKey::from_bytes(&seed))
    } else {
        Ok(SignedResearchCommandV1 {
            chain_id: v["chain_id"].as_str().unwrap().into(), command_id,
            signer_did: v["signer_did"].as_str().unwrap().into(), signer_role: role,
            nonce: v["nonce"].as_u64().unwrap(), command,
            public_key: serde_json::from_value(v["public_key"].clone()).unwrap(),
            signature: serde_json::from_value(v["signature"].clone()).unwrap(),
        })
    }
}
fn signed_flat(v: &SignedResearchCommandV1) -> Vec<u8> {
    fn number(out: &mut Vec<u8>, n: u64) { out.extend_from_slice(&n.to_le_bytes()); }
    fn text(out: &mut Vec<u8>, s: &str) { number(out, s.len() as u64); out.extend_from_slice(s.as_bytes()); }
    let mut out = Vec::new();
    text(&mut out, &v.chain_id); out.extend_from_slice(v.command_id.as_bytes());
    text(&mut out, &v.signer_did); number(&mut out, v.signer_role as u64);
    number(&mut out, v.nonce); out.extend_from_slice(&v.public_key);
    number(&mut out, v.command.primary_object_ref().kind as u64);
    out.extend(payload::flat(&v.command)); number(&mut out, v.signature.len() as u64);
    out.extend_from_slice(&v.signature); out
}
fn apply_observation(mut state: ResearchProtocolState, v: &Value) -> Value {
    let initial = state_observation(&state);
    let mut steps = Vec::new();
    for request in v["commands"].as_array().unwrap() {
        let command = match signed(request) {
            Ok(command) => command,
            Err(error) => { steps.push(json!({"construction_error": failure(&ProtocolStateError::InvalidCommand(error)), "state": state_observation(&state)})); continue; }
        };
        let validation = match command.validate() {
            Ok(()) => json!({"code": 0}),
            Err(error) => failure(&ProtocolStateError::InvalidCommand(error)),
        };
        let outcome = match state.apply(&command) {
            Ok(ApplyOutcome::Applied { primary_object_ref, changed_object_refs }) => json!({"code": 0, "kind": "applied", "primary_object_ref": primary_object_ref, "changed_object_refs": changed_object_refs}),
            Ok(ApplyOutcome::Idempotent { primary_object_ref, changed_object_refs }) => json!({"code": 0, "kind": "idempotent", "primary_object_ref": primary_object_ref, "changed_object_refs": changed_object_refs}),
            Err(error) => failure(&error),
        };
        steps.push(json!({"signed": command, "flat": hex(&signed_flat(&command)),
            "fingerprint": hex(&command.command_fingerprint()), "validation": validation,
            "outcome": outcome, "state": state_observation(&state)}));
    }
    json!({"code": 0, "initial": initial, "steps": steps})
}
fn get_observation(state: &ResearchProtocolState, kind: u64, key: ExternalKey) -> Value {
    macro_rules! get {
        ($method:ident) => {
            match state.$method(key) {
                Some(value) => json!({"code": 0, "found": true, "object": value,
                    "canonical": hex(&value.canonical_bytes()),
                    "hash": hex(&state.object_leaf_hash(value.object_ref).unwrap())}),
                None => json!({"code": 0, "found": false, "object": null}),
            }
        };
    }
    match kind {
        1 => get!(get_match), 2 => get!(get_evaluation), 3 => get!(get_workload_receipt),
        4 => get!(get_claim), 5 => get!(get_license), 6 => get!(get_challenge),
        7 => get!(get_resolution), _ => panic!("unknown typed getter"),
    }
}
fn query_observation(state: ResearchProtocolState, v: &Value) -> Value {
    let mut values = Vec::new();
    for query in v["queries"].as_array().unwrap() {
        let result = match query["operation"].as_u64().unwrap() {
            3 => get_observation(&state, query["kind"].as_u64().unwrap(),
                serde_json::from_value(query["key"].clone()).unwrap()),
            4 => {
                let reference: ObjectRefV1 = serde_json::from_value(query["object_ref"].clone()).unwrap();
                match state.object_canonical_bytes(reference) {
                    Err(error) => failure(&error),
                    Ok(canonical) => {
                        let mut value = get_observation(&state, reference.kind as u64, reference.key);
                        value["canonical"] = json!(hex(&canonical));
                        value["hash"] = json!(hex(&state.object_leaf_hash(reference).unwrap()));
                        value
                    }
                }
            }
            _ => panic!("unknown typed state query"),
        };
        values.push(result);
    }
    json!({"code": 0, "state": state_observation(&state), "queries": values})
}
fn observe(v: Value) -> Value {
    let state = match v["op"].as_str().unwrap() {
        "restore" | "apply" | "query" => {
            let snapshot = snapshot(&v["snapshot"]);
            if let Some(chain) = v.get("chain").and_then(Value::as_str) {
                ResearchProtocolState::from_snapshot_for_chain(chain, snapshot)
            } else {
                ResearchProtocolState::from_snapshot(snapshot)
            }
        }
        "create" => {
            let authorities = authorities(&v["authorities"]);
            if let Some(chain) = v.get("chain").and_then(Value::as_str) {
                ResearchProtocolState::with_chain_id(chain, authorities)
            } else {
                ResearchProtocolState::with_authorities(authorities)
            }
        }
        "default" => Ok(ResearchProtocolState::default()),
        _ => panic!("unknown state observation"),
    };
    match state {
        Ok(state) if v["op"] == "apply" => apply_observation(state, &v),
        Ok(state) if v["op"] == "query" => query_observation(state, &v),
        Ok(state) => state_observation(&state), Err(e) => failure(&e),
    }
}
fn main() {
    for line in io::stdin().lock().lines() {
        let v: Value = serde_json::from_str(&line.unwrap()).unwrap();
        println!("{}", observe(v));
    }
}
