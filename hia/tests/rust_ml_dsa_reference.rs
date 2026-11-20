//! Test-only adapter to the unchanged original crate and exact ml-dsa 0.1.1.
use ml_dsa::{
    ExpandedSigningKey, KeyInit, Keypair, MlDsa65, MlDsa87, Signature, SigningKey, VerifyingKey,
};
use serde_json::{json, Value};
use std::io::{self, BufRead};
use trnm_crypto_primitives::pq_candidate::{
    CandidateAlgorithm, CandidateError, CandidateSigningKey, CandidateVerifier,
};
use zeroize::Zeroizing;

fn bytes(value: &Value, field: &str) -> Vec<u8> {
    hex::decode(value.get(field).and_then(Value::as_str).unwrap_or("")).unwrap()
}

fn error(value: CandidateError) -> Value {
    let text = value.to_string();
    let (code, expected, actual) = match value {
        CandidateError::PublicKeyLength { expected, actual } => (3, expected, actual),
        CandidateError::SignatureLength { expected, actual } => (5, expected, actual),
        CandidateError::MessageTooLarge { actual } => (4, 65536, actual),
        CandidateError::KeyEncoding => (2, 0, 0),
        CandidateError::SignatureEncoding => (6, 0, 0),
        CandidateError::SignatureRejected => (7, 0, 0),
        CandidateError::SigningFailed => (8, 0, 0),
    };
    json!({"code": code, "expected": expected, "actual": actual, "display": text})
}

macro_rules! mathematical {
    ($parameter:ty, $value:expr) => {{
        let value = $value;
        let op = value["op"].as_str().unwrap();
        let message = bytes(value, "message");
        let context = bytes(value, "context");
        let profile = value["profile"].as_u64().unwrap_or(1);
        match op {
            "verify_math" => {
                let public_key = bytes(value, "pk");
                let signature = bytes(value, "signature");
                let key = VerifyingKey::<$parameter>::new_from_slice(&public_key).unwrap();
                match Signature::<$parameter>::try_from(signature.as_slice()) {
                    Err(_) => json!({"code": 6, "expected": 0, "actual": 0}),
                    Ok(signature) => {
                        let valid = match profile {
                            1 => key.verify_with_context(&message, &context, &signature),
                            2 => key.verify_internal(&message, &signature),
                            3 => key.verify_mu(&message.as_slice().try_into().unwrap(), &signature),
                            _ => panic!("unsupported diagnostic profile"),
                        };
                        json!({"code": if valid { 0 } else { 7 }, "expected": 0, "actual": 0})
                    }
                }
            }
            "keygen_math" => {
                let seed = bytes(value, "seed");
                let key = SigningKey::<$parameter>::new_from_slice(&seed).unwrap();
                #[allow(deprecated)]
                let expanded = key.expanded_key().to_expanded();
                json!({"code": 0, "pk": hex::encode(key.verifying_key().encode()), "sk": hex::encode(expanded)})
            }
            "sign_math" => {
                let encoded = bytes(value, "sk");
                #[allow(deprecated)]
                let key = ExpandedSigningKey::<$parameter>::from_expanded(&encoded.as_slice().try_into().unwrap());
                let random = bytes(value, "rnd");
                let random: ml_dsa::B32 = random.as_slice().try_into().unwrap();
                let signature = match profile {
                    1 => {
                        assert!(context.len() <= 255);
                        let prefix = [0, context.len() as u8];
                        key.sign_internal(&[&prefix, &context, &message], &random)
                    }
                    2 => key.sign_internal(&[&message], &random),
                    3 => {
                        assert!(random.iter().all(|byte| *byte == 0));
                        key.sign_mu_deterministic(&message.as_slice().try_into().unwrap())
                    }
                    _ => panic!("unsupported diagnostic profile"),
                };
                json!({"code": 0, "signature": hex::encode(signature.encode())})
            }
            _ => panic!("unsupported mathematical operation"),
        }
    }};
}

fn run(value: &Value) -> Value {
    if value["op"] == "error_display" {
        let expected = value["expected"].as_u64().unwrap() as usize;
        let actual = value["actual"].as_u64().unwrap() as usize;
        return error(match value["code"].as_u64().unwrap() {
            2 => CandidateError::KeyEncoding,
            3 => CandidateError::PublicKeyLength { expected, actual },
            4 => CandidateError::MessageTooLarge { actual },
            5 => CandidateError::SignatureLength { expected, actual },
            6 => CandidateError::SignatureEncoding,
            7 => CandidateError::SignatureRejected,
            8 => CandidateError::SigningFailed,
            _ => panic!("not an original candidate error"),
        });
    }
    let algorithm = match value["parameter"].as_u64().unwrap() {
        65 => CandidateAlgorithm::MlDsa65,
        87 => CandidateAlgorithm::MlDsa87,
        _ => panic!("not an original candidate parameter"),
    };
    match value["op"].as_str().unwrap() {
        "verify" => {
            let public_key = bytes(value, "pk");
            let message = bytes(value, "message");
            let signature = bytes(value, "signature");
            match CandidateVerifier::from_pinned_raw(algorithm, &public_key) {
                Err(value) => error(value),
                Ok(key) => match key.verify(&message, &signature) {
                    Err(value) => error(value),
                    Ok(()) => {
                        json!({"code": 0, "expected": 0, "actual": 0, "name": key.algorithm().name(), "pk": hex::encode(key.public_key())})
                    }
                },
            }
        }
        "keygen" | "sign" => {
            let seed = bytes(value, "seed");
            let seed: [u8; 32] = seed.try_into().unwrap();
            match CandidateSigningKey::from_owned_seed(algorithm, Zeroizing::new(seed)) {
                Err(value) => error(value),
                Ok(key) => {
                    if value["op"] == "keygen" {
                        json!({"code": 0, "name": key.algorithm().name(), "pk": hex::encode(key.public_key())})
                    } else {
                        match key.sign(&bytes(value, "message")) {
                            Err(value) => error(value),
                            Ok(signature) => {
                                json!({"code": 0, "name": key.algorithm().name(), "pk": hex::encode(key.public_key()), "signature": hex::encode(signature)})
                            }
                        }
                    }
                }
            }
        }
        "info" => {
            json!({"name": algorithm.name(), "public_key_bytes": algorithm.public_key_bytes(), "signature_bytes": algorithm.signature_bytes(), "nist_category": algorithm.nist_category(), "all": CandidateAlgorithm::ALL.map(CandidateAlgorithm::name)})
        }
        _ => match algorithm {
            CandidateAlgorithm::MlDsa65 => mathematical!(MlDsa65, value),
            CandidateAlgorithm::MlDsa87 => mathematical!(MlDsa87, value),
        },
    }
}

fn main() {
    for line in io::stdin().lock().lines() {
        let value: Value = serde_json::from_str(&line.unwrap()).unwrap();
        println!("{}", run(&value));
    }
}
