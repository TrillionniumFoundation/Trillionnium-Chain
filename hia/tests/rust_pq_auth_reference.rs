use serde_json::{json, Value};
use std::io::{self, BufRead};
use trnm_crypto_primitives::pq_auth::{
    verify_ml_dsa_65, verify_tpq1, PqAuthError, PqNativeError, PqNativeSigningKey, PqNativeVerifier,
};
use trnm_protocol::pq_frame::{
    ml_dsa_65_key_id_from_spki, payload_commitment, preflight_unverified,
    preflight_unverified_with_spki, PqFrameError, PqFrameExpectation,
};
use zeroize::Zeroizing;

fn bytes(v: &Value, field: &str) -> Vec<u8> {
    hex::decode(v.get(field).and_then(Value::as_str).unwrap_or("")).expect("fixture hex")
}

fn fixed<const N: usize>(v: &Value, field: &str) -> [u8; N] {
    bytes(v, field).try_into().expect("fixture fixed width")
}

fn payload(v: &Value) -> Vec<u8> {
    if let Some(count) = v.get("generated_payload_bytes").and_then(Value::as_u64) {
        let count = usize::try_from(count).expect("fixture count");
        assert!(count <= 67_108_865);
        let width = v["generated_chunk_bytes"].as_u64().expect("fixture chunk") as usize;
        assert!((1..=1_048_512).contains(&width));
        return (0..count).map(|i| ((i % width) % 251) as u8).collect();
    }
    bytes(v, "payload")
}

fn expected<'a>(v: &Value, payload: &'a [u8]) -> PqFrameExpectation<'a> {
    PqFrameExpectation {
        purpose: v["purpose"].as_u64().expect("fixture purpose") as u8,
        network: fixed(v, "network"),
        owner_context: fixed(v, "owner_context"),
        signer_key_id: fixed(v, "signer_key_id"),
        owner_generation: v["owner_generation"].as_u64().expect("fixture generation"),
        operation_sequence: v["operation_sequence"].as_u64().expect("fixture sequence"),
        expires_at: v["expires_at"].as_u64().expect("fixture expiry"),
        now: v["now"].as_u64().expect("fixture now"),
        payload,
    }
}

fn frame_error(error: PqFrameError) -> Value {
    let code = match error {
        PqFrameError::FrameLength => 1,
        PqFrameError::HeaderVersionAlgorithm => 2,
        PqFrameError::PurposeOrReserved => 3,
        PqFrameError::ContextOrIdentity => 4,
        PqFrameError::LifetimeOrSequence => 5,
        PqFrameError::Expired => 6,
        PqFrameError::PayloadSize => 7,
        PqFrameError::PayloadDigest => 8,
        PqFrameError::SignatureLength => 9,
        PqFrameError::PublicKeyDer => 10,
    };
    json!({"code": code, "error": format!("{error:?}")})
}

fn auth_error(error: PqAuthError) -> Value {
    let code = match error {
        PqAuthError::PublicKeyLength => 1,
        PqAuthError::SignatureEncoding => 2,
        PqAuthError::ContextLength => 3,
        PqAuthError::MessageLength => 4,
        PqAuthError::Signature => 5,
        PqAuthError::Frame(error) => return json!({"code": 6, "frame": frame_error(error)}),
    };
    json!({"code": code, "error": format!("{error:?}")})
}

fn native_error(error: PqNativeError) -> Value {
    let code = match &error {
        PqNativeError::Frame(frame) => {
            return json!({"code": 1, "frame": frame_error(*frame), "display": error.to_string()})
        }
        PqNativeError::KeyAlgorithm => 2,
        PqNativeError::KeyPin => 3,
        PqNativeError::SignatureRejected => 4,
        PqNativeError::Backend(_) => 5,
        PqNativeError::OpenSslVersion => 6,
    };
    json!({"code": code, "display": error.to_string()})
}

fn main() {
    for line in io::stdin().lock().lines() {
        let v: Value = serde_json::from_str(&line.expect("fixture input")).expect("fixture JSON");
        let op = v["op"].as_str().expect("fixture operation");
        let result = match op {
            "key_id" => match ml_dsa_65_key_id_from_spki(&bytes(&v, "spki")) {
                Ok(id) => json!({"code": 0, "key_id": hex::encode(id)}),
                Err(error) => frame_error(error),
            },
            "native_error_display" => {
                let error = match v["code"].as_u64().expect("fixture error code") {
                    1 => PqNativeError::Frame(
                        match v["detail"].as_u64().expect("fixture frame error") {
                            1 => PqFrameError::FrameLength,
                            2 => PqFrameError::HeaderVersionAlgorithm,
                            3 => PqFrameError::PurposeOrReserved,
                            4 => PqFrameError::ContextOrIdentity,
                            5 => PqFrameError::LifetimeOrSequence,
                            6 => PqFrameError::Expired,
                            7 => PqFrameError::PayloadSize,
                            8 => PqFrameError::PayloadDigest,
                            9 => PqFrameError::SignatureLength,
                            10 => PqFrameError::PublicKeyDer,
                            _ => panic!("fixture frame error code"),
                        },
                    ),
                    2 => PqNativeError::KeyAlgorithm,
                    3 => PqNativeError::KeyPin,
                    4 => PqNativeError::SignatureRejected,
                    6 => PqNativeError::OpenSslVersion,
                    _ => panic!("fixture native error code"),
                };
                json!({"code": 0, "display": error.to_string()})
            }
            "payload" => match payload_commitment(&payload(&v)) {
                Ok(digest) => json!({"code": 0, "digest": hex::encode(digest)}),
                Err(error) => frame_error(error),
            },
            "frame" | "frame_with_spki" => {
                let payload = payload(&v);
                let expectation = expected(&v["expected"], &payload);
                let frame = bytes(&v, "frame");
                let value = if op == "frame" {
                    preflight_unverified(&frame, &expectation)
                } else {
                    preflight_unverified_with_spki(&frame, &expectation, &bytes(&v, "spki"))
                };
                match value {
                    Ok(observation) => {
                        json!({"code": 0, "statement": hex::encode(observation.unsigned_statement()), "signature": hex::encode(observation.unverified_signature())})
                    }
                    Err(error) => frame_error(error),
                }
            }
            "verify" => match verify_ml_dsa_65(
                &bytes(&v, "pk"),
                &bytes(&v, "message"),
                &bytes(&v, "context"),
                &bytes(&v, "signature"),
            ) {
                Ok(()) => json!({"code": 0}),
                Err(error) => auth_error(error),
            },
            "verify_tpq1" => {
                let payload = payload(&v);
                let expectation = expected(&v["expected"], &payload);
                let frame = bytes(&v, "frame");
                match verify_tpq1(&frame, &expectation, &bytes(&v, "spki")) {
                    Ok(observation) => {
                        json!({"code": 0, "statement": hex::encode(observation.authenticated_statement()), "statement_alias": hex::encode(observation.statement()), "key_id": hex::encode(observation.signer_key_id())})
                    }
                    Err(error) => auth_error(error),
                }
            }
            "seed" | "seed_public" => {
                let seed = Zeroizing::new(fixed::<32>(&v, "seed"));
                let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
                let id = ml_dsa_65_key_id_from_spki(&spki).expect("derived strict SPKI");
                let pin = if v.get("pin").is_some() {
                    fixed(&v, "pin")
                } else {
                    id
                };
                match PqNativeSigningKey::from_owned_seed(seed, pin) {
                    Ok(key) if op == "seed_public" => {
                        json!({"code": 0, "spki": hex::encode(key.public_spki()), "derived_spki": hex::encode(spki), "key_id": hex::encode(key.public_key_id())})
                    }
                    Ok(key) => match key.sign_exact_message(&bytes(&v, "message")) {
                        Ok(signature) => {
                            json!({"code": 0, "spki": hex::encode(key.public_spki()), "derived_spki": hex::encode(spki), "key_id": hex::encode(key.public_key_id()), "signature": hex::encode(signature)})
                        }
                        Err(error) => native_error(error),
                    },
                    Err(error) => native_error(error),
                }
            }
            "seed_statement" => {
                let seed = Zeroizing::new(fixed::<32>(&v, "seed"));
                let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
                let id = ml_dsa_65_key_id_from_spki(&spki).expect("derived strict SPKI");
                let pin = if v.get("pin").is_some() {
                    fixed(&v, "pin")
                } else {
                    id
                };
                match PqNativeSigningKey::from_owned_seed(seed, pin) {
                    Err(error) => native_error(error),
                    Ok(key) => {
                        let payload = payload(&v);
                        let expectation = expected(&v["expected"], &payload);
                        match key.sign_statement(&bytes(&v, "statement"), &expectation) {
                            Ok(frame) => {
                                json!({"code": 0, "frame": hex::encode(frame), "spki": hex::encode(key.public_spki()), "key_id": hex::encode(key.public_key_id())})
                            }
                            Err(error) => native_error(error),
                        }
                    }
                }
            }
            "native_verify" | "native_frame" | "native_public" => {
                match PqNativeVerifier::from_pinned_spki(&bytes(&v, "spki"), fixed(&v, "pin")) {
                    Err(error) => native_error(error),
                    Ok(key) => {
                        if op == "native_public" {
                            json!({"code": 0, "key_id": hex::encode(key.public_key_id()), "spki": hex::encode(key.public_spki())})
                        } else if op == "native_verify" {
                            let message = bytes(&v, "message");
                            match key.verify_exact_message(&message, &bytes(&v, "signature")) {
                                Ok(observation) => {
                                    json!({"code": 0, "message": hex::encode(observation.authenticated_message()), "key_id": hex::encode(observation.signer_key_id()), "public_key_id": hex::encode(key.public_key_id()), "spki": hex::encode(key.public_spki())})
                                }
                                Err(error) => native_error(error),
                            }
                        } else {
                            let payload = payload(&v);
                            let expectation = expected(&v["expected"], &payload);
                            let frame = bytes(&v, "frame");
                            match key.verify(&frame, &expectation) {
                                Ok(observation) => {
                                    json!({"code": 0, "statement": hex::encode(observation.authenticated_statement()), "statement_alias": hex::encode(observation.statement()), "key_id": hex::encode(observation.signer_key_id())})
                                }
                                Err(error) => native_error(error),
                            }
                        }
                    }
                }
            }
            _ => panic!("unrecognized fixture operation"),
        };
        println!("{result}");
    }
}
