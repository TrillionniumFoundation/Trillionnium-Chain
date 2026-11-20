use serde_json::{json, Value};
use std::io::{self, BufRead};
use trnm_crypto_primitives::pq_candidate::{
    CandidateAlgorithm, CandidateError, CandidateSigningKey,
};
use trnm_crypto_primitives::pq_profile_auth::{
    CandidateProfileVerifier, ProfileAuthenticationError,
};
use trnm_protocol::crypto_profile::{
    native_work_configuration_digest, BoundCryptoProfile, CandidateEnvelope,
    CandidateVerificationBudget, CryptoProfile, CryptoProfileId, CryptoPurpose, HashPurpose,
    ProfileBinding, ProfileError, ProfileScope,
};
use zeroize::Zeroizing;

fn bytes(v: &Value, field: &str) -> Vec<u8> {
    hex::decode(v[field].as_str().expect("fixture hex")).expect("fixture bytes")
}

fn fixed<const N: usize>(v: &Value, field: &str) -> [u8; N] {
    bytes(v, field).try_into().expect("fixture fixed width")
}

fn number(v: &Value, field: &str) -> u64 {
    v[field].as_u64().expect("fixture integer")
}

fn profile(v: &Value) -> Result<BoundCryptoProfile, ProfileError> {
    let p = match number(v, "profile") {
        1 => CryptoProfile::LegacyMlDsa65V1,
        2 => CryptoProfile::CandidateMlDsa65V1,
        3 => CryptoProfile::CandidateMlDsa87V1,
        _ => panic!("fixture typed profile"),
    };
    let b = &v["binding"];
    p.bind(ProfileBinding {
        network: fixed(b, "network"),
        parameters: fixed(b, "parameters"),
        genesis: fixed(b, "genesis"),
        protocol_version: u32::try_from(number(b, "version")).expect("fixture u32"),
        scope: match number(b, "scope") {
            1 => ProfileScope::NativeAccounts,
            2 => ProfileScope::NativePeer,
            3 => ProfileScope::Operator,
            4 => ProfileScope::WholeSystemCandidate,
            _ => panic!("fixture typed scope"),
        },
        activation_height: number(b, "activation"),
        retirement_height: b["retirement"].as_u64(),
    })
}

fn purpose(value: u64) -> CryptoPurpose {
    match value {
        1 => CryptoPurpose::Account,
        2 => CryptoPurpose::Migration,
        3 => CryptoPurpose::Task,
        4 => CryptoPurpose::Operator,
        5 => CryptoPurpose::Peer,
        6 => CryptoPurpose::Governance,
        7 => CryptoPurpose::Release,
        8 => CryptoPurpose::Current,
        9 => CryptoPurpose::FinalUse,
        10 => CryptoPurpose::Recovery,
        _ => panic!("fixture typed purpose"),
    }
}

fn hash_purpose(value: u64) -> HashPurpose {
    match value {
        1 => HashPurpose::KeyIdentity,
        2 => HashPurpose::Payload,
        3 => HashPurpose::StateCommitment,
        4 => HashPurpose::ReleaseCommitment,
        5 => HashPurpose::ProofCommitment,
        6 => HashPurpose::Address,
        7 => HashPurpose::MerkleNode,
        8 => HashPurpose::ProofTranscript,
        9 => HashPurpose::WorkChallenge,
        10 => HashPurpose::WorkTicket,
        _ => panic!("fixture typed hash purpose"),
    }
}

fn policy(code: u64) -> ProfileError {
    match code {
        1 => ProfileError::Encoding,
        2 => ProfileError::UnknownProfile,
        3 => ProfileError::ProfileMismatch,
        4 => ProfileError::InvalidBinding,
        5 => ProfileError::Inactive,
        6 => ProfileError::CandidateOnly,
        7 => ProfileError::UnsupportedPurpose,
        8 => ProfileError::HistoricalOnly,
        9 => ProfileError::StaleState,
        10 => ProfileError::WorkProfileBoundary,
        11 => ProfileError::Size,
        12 => ProfileError::SignerSet,
        13 => ProfileError::Budget,
        _ => panic!("fixture policy error"),
    }
}

fn error(error: ProfileAuthenticationError) -> Value {
    match error {
        ProfileAuthenticationError::Policy(error) => {
            let detail = match error {
                ProfileError::Encoding => 1,
                ProfileError::UnknownProfile => 2,
                ProfileError::ProfileMismatch => 3,
                ProfileError::InvalidBinding => 4,
                ProfileError::Inactive => 5,
                ProfileError::CandidateOnly => 6,
                ProfileError::UnsupportedPurpose => 7,
                ProfileError::HistoricalOnly => 8,
                ProfileError::StaleState => 9,
                ProfileError::WorkProfileBoundary => 10,
                ProfileError::Size => 11,
                ProfileError::SignerSet => 12,
                ProfileError::Budget => 13,
            };
            json!({"code": 1, "detail": detail})
        }
        ProfileAuthenticationError::Signature(error) => {
            let detail = match error {
                CandidateError::PublicKeyLength { .. } => 3,
                CandidateError::SignatureLength { .. } => 5,
                CandidateError::MessageTooLarge { .. } => 4,
                CandidateError::KeyEncoding => 2,
                CandidateError::SignatureEncoding => 6,
                CandidateError::SignatureRejected => 7,
                CandidateError::SigningFailed => 8,
            };
            json!({"code": 2, "detail": detail})
        }
    }
}

fn keys(v: &Value) -> Vec<Vec<u8>> {
    v["keys"]
        .as_array()
        .expect("fixture keys")
        .iter()
        .map(|key| hex::decode(key.as_str().expect("fixture key hex")).expect("fixture key"))
        .collect()
}

fn verifier(v: &Value) -> Result<CandidateProfileVerifier, ProfileAuthenticationError> {
    let profile = profile(v)?;
    let keys = keys(v);
    let refs: Vec<_> = keys.iter().map(Vec::as_slice).collect();
    CandidateProfileVerifier::from_pinned_keys(profile, &refs)
}

fn ids(v: &Value) -> Vec<[u8; 64]> {
    v["signer_ids"]
        .as_array()
        .expect("fixture ids")
        .iter()
        .map(|id| {
            hex::decode(id.as_str().expect("fixture id hex"))
                .expect("fixture id")
                .try_into()
                .expect("fixture id width")
        })
        .collect()
}

fn envelope<'a>(v: &Value, ids: &'a [[u8; 64]], payload: &'a [u8]) -> CandidateEnvelope<'a> {
    CandidateEnvelope {
        purpose: purpose(number(v, "purpose")),
        owner_generation: number(v, "generation"),
        key_epoch: number(v, "epoch"),
        sequence: number(v, "sequence"),
        valid_from_height: number(v, "valid_from"),
        valid_until_height: number(v, "valid_until"),
        signer_ids: ids,
        payload,
    }
}

fn profile_row(p: &BoundCryptoProfile) -> Value {
    let b = p.binding();
    let mut binding = Vec::new();
    binding.extend_from_slice(&b.network);
    binding.extend_from_slice(&b.parameters);
    binding.extend_from_slice(&b.genesis);
    binding.extend_from_slice(&b.protocol_version.to_le_bytes());
    binding.extend_from_slice(&[b.scope as u8, u8::from(b.retirement_height.is_some()), 0, 0]);
    binding.extend_from_slice(&b.activation_height.to_le_bytes());
    binding.extend_from_slice(&b.retirement_height.unwrap_or(0).to_le_bytes());
    binding.extend_from_slice(&0u64.to_le_bytes());
    json!({"code": 0, "profile": match p.profile() {
        CryptoProfile::LegacyMlDsa65V1 => 1,
        CryptoProfile::CandidateMlDsa65V1 => 2,
        CryptoProfile::CandidateMlDsa87V1 => 3,
    }, "id": p.id().to_hex(), "work": hex::encode(native_work_configuration_digest()),
        "config": hex::encode(p.canonical_configuration()), "binding": hex::encode(binding)})
}

fn dispatch(v: &Value) -> Value {
    match v["op"].as_str().expect("fixture operation") {
        "display" => {
            let e: ProfileAuthenticationError = if number(v, "category") == 1 {
                policy(number(v, "detail")).into()
            } else {
                let expected = number(v, "expected") as usize;
                let actual = number(v, "actual") as usize;
                let e = match number(v, "detail") {
                    2 => CandidateError::KeyEncoding,
                    3 => CandidateError::PublicKeyLength { expected, actual },
                    4 => CandidateError::MessageTooLarge { actual },
                    5 => CandidateError::SignatureLength { expected, actual },
                    6 => CandidateError::SignatureEncoding,
                    7 => CandidateError::SignatureRejected,
                    8 => CandidateError::SigningFailed,
                    _ => panic!("fixture candidate error"),
                };
                e.into()
            };
            json!({"code": 0, "display": e.to_string()})
        }
        "sequence" => {
            let mut owners = Vec::new();
            for owner in v["owners"].as_array().expect("fixture owners") {
                match verifier(owner) {
                    Ok(owner) => owners.push(owner),
                    Err(e) => return error(e),
                }
            }
            let mut budget = if v["default"].as_bool().unwrap_or(false) {
                CandidateVerificationBudget::default()
            } else {
                CandidateVerificationBudget::new()
            };
            let mut results = Vec::new();
            for step in v["steps"].as_array().expect("fixture steps") {
                let mut result = match step["op"].as_str().expect("fixture sequence op") {
                    "reserve" => match budget.reserve(
                        number(step, "bytes") as usize,
                        number(step, "attempts") as usize,
                    ) {
                        Ok(()) => json!({"code": 0}),
                        Err(e) => error(e.into()),
                    },
                    "budget" => json!({"code": 0}),
                    "verify" => {
                        let owner = &owners[number(step, "owner") as usize];
                        let wire = bytes(step, "wire");
                        let raw = &step["expected"];
                        let ids = ids(raw);
                        let payload = bytes(raw, "payload");
                        let expected = envelope(raw, &ids, &payload);
                        match owner.verify(&mut budget, &wire, &expected) {
                            Ok(observation) => {
                                json!({"code": 0, "message": hex::encode(observation.message()),
                                "id": observation.crypto_profile_id().to_hex(), "signers": observation.signer_count()})
                            }
                            Err(e) => error(e),
                        }
                    }
                    _ => panic!("fixture sequence operation"),
                };
                result["attempts"] = json!(budget.attempts());
                result["bytes"] = json!(budget.charged_bytes());
                results.push(result);
            }
            json!({"code": 0, "results": results})
        }
        "init" => match verifier(v) {
            Ok(owner) => {
                let mut row = profile_row(owner.profile());
                row["signer_ids"] = json!(owner
                    .signer_ids()
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>());
                row["keys"] = json!(owner
                    .pinned_keys()
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>());
                row
            }
            Err(e) => error(e),
        },
        "fixture" => {
            let p = profile(v).expect("valid fixture profile");
            let algorithm = if p.profile() == CryptoProfile::CandidateMlDsa65V1 {
                CandidateAlgorithm::MlDsa65
            } else {
                CandidateAlgorithm::MlDsa87
            };
            let signers: Vec<_> = v["seeds"]
                .as_array()
                .expect("fixture seeds")
                .iter()
                .map(|seed| {
                    CandidateSigningKey::from_owned_seed(
                        algorithm,
                        Zeroizing::new(
                            hex::decode(seed.as_str().expect("fixture seed hex"))
                                .expect("fixture seed")
                                .try_into()
                                .expect("seed width"),
                        ),
                    )
                    .expect("fixture signing key")
                })
                .collect();
            let raw_keys: Vec<_> = signers
                .iter()
                .map(CandidateSigningKey::public_key)
                .collect();
            let owner = CandidateProfileVerifier::from_pinned_keys(p.clone(), &raw_keys)
                .expect("fixture verifier");
            let payload = bytes(&v["expected"], "payload");
            let expected = envelope(&v["expected"], owner.signer_ids(), &payload);
            let message = p.candidate_message(&expected).expect("fixture message");
            let keys = owner.pinned_keys();
            let signatures: Vec<_> = keys
                .iter()
                .map(|key| {
                    signers
                        .iter()
                        .find(|signer| signer.public_key() == *key)
                        .expect("fixture pinned signer")
                        .sign(&message)
                        .expect("fixture signature")
                })
                .collect();
            let signature_refs: Vec<_> = signatures.iter().map(Vec::as_slice).collect();
            let wire = p
                .candidate_wire(&expected, &keys, &signature_refs)
                .expect("fixture wire");
            let mut budget = CandidateVerificationBudget::new();
            let observed = owner
                .verify(&mut budget, &wire, &expected)
                .expect("fixture authenticates");
            assert_eq!(observed.message(), message);
            let mut row = profile_row(&p);
            row["signer_ids"] = json!(owner
                .signer_ids()
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>());
            row["keys"] = json!(raw_keys.iter().map(hex::encode).collect::<Vec<_>>());
            row["pinned_keys"] = json!(keys.iter().map(hex::encode).collect::<Vec<_>>());
            row["message"] = json!(hex::encode(message));
            row["wire"] = json!(hex::encode(wire));
            row["signatures"] = json!(signatures.iter().map(hex::encode).collect::<Vec<_>>());
            row
        }
        op => {
            let p = match profile(v) {
                Ok(p) => p,
                Err(e) => return error(e.into()),
            };
            match op {
                "profile" => profile_row(&p),
                "active" => json!({"code": 0, "active": p.active_at(number(v, "height"))}),
                "claim" => match p.require_claim(
                    CryptoProfileId::from_hex(v["claim"].as_str().expect("fixture claim"))
                        .expect("fixture typed claim"),
                ) {
                    Ok(()) => json!({"code": 0}),
                    Err(e) => error(e.into()),
                },
                "commitment" => {
                    match p.commitment(hash_purpose(number(v, "purpose")), &bytes(v, "bytes")) {
                        Ok(digest) => json!({"code": 0, "digest": hex::encode(digest)}),
                        Err(e) => error(e.into()),
                    }
                }
                "message" => {
                    let raw = &v["expected"];
                    let ids = ids(raw);
                    let payload = bytes(raw, "payload");
                    match p.candidate_message(&envelope(raw, &ids, &payload)) {
                        Ok(message) => json!({"code": 0, "message": hex::encode(message)}),
                        Err(e) => error(e.into()),
                    }
                }
                _ => panic!("fixture operation"),
            }
        }
    }
}

fn main() {
    for line in io::stdin().lock().lines() {
        let v: Value = serde_json::from_str(&line.expect("fixture input")).expect("fixture JSON");
        println!("{}", dispatch(&v));
    }
}
