use super::pq_identity::ServerPin;
use super::{
    digest, hash, request_op, response, DevelopmentIdentity, Hello, PublicPolicy, PublicServer,
    Request, Response, Result, Settings, MAX_PACKET,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha384};
use std::cell::Cell;

// Keep the original owned Response derive as the independent serialization
// oracle. Do not reproduce the new borrowed signing view here.
fn original_signing_bytes_clone_oracle(response: &Response) -> Result<Vec<u8>> {
    let mut original = Response {
        schema: response.schema.clone(),
        profile: response.profile.clone(),
        network: response.network.clone(),
        parameters: response.parameters.clone(),
        genesis: response.genesis.clone(),
        server: response.server.clone(),
        cookie_digest: response.cookie_digest.clone(),
        request_digest: response.request_digest.clone(),
        ok: response.ok,
        value: response.value.clone(),
        signature: String::new(),
    };
    original.signature.clear();
    Ok(serde_json::to_vec(&original)?)
}

fn original_message_clone_oracle(response: &Response) -> Result<Vec<u8>> {
    let raw = original_signing_bytes_clone_oracle(response)?;
    if response.schema == "public-protected-response-pq-v4" {
        let mut message = b"TRNM/PoN/PaidHistory/Response/PQ/v4\0".to_vec();
        message.extend_from_slice(&Sha384::digest(&raw));
        Ok(message)
    } else {
        Ok(hash(b"public-response-sign-v3", &[&raw]).to_vec())
    }
}

fn response_fixture() -> Response {
    Response {
        schema: "schema-value".to_owned(),
        profile: "profile-value".to_owned(),
        network: "network-value".to_owned(),
        parameters: "parameters-value".to_owned(),
        genesis: "genesis-value".to_owned(),
        server: "server-value".to_owned(),
        cookie_digest: "cookie-digest-value".to_owned(),
        request_digest: "request-digest-value".to_owned(),
        ok: true,
        value: json!({"body": "body-value"}),
        signature: "nonempty-signature".to_owned(),
    }
}

fn assert_original_bytes_and_message(response: &Response) -> Vec<u8> {
    let before = serde_json::to_vec(response).unwrap();
    let expected = original_signing_bytes_clone_oracle(response).unwrap();
    let actual = response.signing_bytes().unwrap();
    assert_eq!(actual, expected);
    assert_eq!(
        response.message().unwrap(),
        original_message_clone_oracle(response).unwrap()
    );
    assert_eq!(serde_json::to_vec(response).unwrap(), before);
    actual
}

#[test]
fn borrowed_response_signing_matches_original_bytes_and_field_order() {
    let response = response_fixture();
    let expected = concat!(
        "{\"schema\":\"schema-value\",\"profile\":\"profile-value\",",
        "\"network\":\"network-value\",\"parameters\":\"parameters-value\",",
        "\"genesis\":\"genesis-value\",\"server\":\"server-value\",",
        "\"cookie_digest\":\"cookie-digest-value\",",
        "\"request_digest\":\"request-digest-value\",\"ok\":true,",
        "\"value\":{\"body\":\"body-value\"},\"signature\":\"\"}"
    );
    let actual = assert_original_bytes_and_message(&response);
    assert_eq!(actual.as_slice(), expected.as_bytes());
}

#[test]
fn borrowed_response_signing_preserves_every_field_except_signature() {
    let response = response_fixture();
    let baseline = assert_original_bytes_and_message(&response);
    let original = serde_json::to_value(&response).unwrap();
    let fields = original.as_object().unwrap();
    assert_eq!(fields.len(), 11);
    for (name, value) in fields {
        let replacements = match name.as_str() {
            "ok" => vec![json!(false)],
            "value" => vec![
                Value::Null,
                json!([false, 0, "", {"nested": [u64::MAX, i64::MIN]}]),
            ],
            _ if value.is_string() => vec![
                json!(""),
                json!("\"\\/\n\r\t\u{0}\u{8}\u{c}\u{e9}\u{6f22}\u{1f642}"),
                json!("a different nonempty value"),
            ],
            _ => panic!("unreviewed Response field: {name}"),
        };
        for replacement in replacements {
            assert_ne!(&replacement, value, "{name}: control must change the field");
            let mut changed = original.clone();
            changed[name.as_str()] = replacement;
            let changed: Response = serde_json::from_value(changed).unwrap();
            let actual = assert_original_bytes_and_message(&changed);
            if name == "signature" {
                assert_eq!(actual, baseline, "only the signature is omitted");
            } else {
                assert_ne!(actual, baseline, "{name}: field must remain committed");
            }
        }
    }
}

#[test]
fn borrowed_response_signing_matches_original_domain_preimages_for_bounded_values() {
    // Serialization controls only: these synthetic values do not claim a
    // valid native packet, a real History replay, or a PQ signature proof.
    let values = [
        Value::Null,
        json!([
            true,
            false,
            0,
            u64::MAX,
            i64::MIN,
            1.5,
            "\"\\\n\u{0}\u{6f22}"
        ]),
        json!({"nested": {"empty": {}, "array": [[], null, {"k": "v"}]}}),
        json!({"packets": ["ab".repeat(MAX_PACKET)]}),
    ];
    for schema in [
        "public-protected-response-v3",
        "public-protected-response-pq-v4",
        "unrecognized-schema-retains-original-fallback",
    ] {
        for value in &values {
            let mut response = response_fixture();
            response.schema = schema.to_owned();
            response.value = value.clone();
            assert_original_bytes_and_message(&response);
        }
    }
}

#[test]
fn borrowed_response_signing_uses_original_signer_verifier_and_progress_fences() {
    let identity = DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap();
    let server_key = identity.public_key().to_owned();
    let server = PublicServer::new(identity, PublicPolicy::development()).unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let request = Request::Head;
    let raw = serde_json::to_vec(&request).unwrap();
    let cookie = server
        .cookie(
            &settings,
            Hello {
                op: request_op(&request).unwrap(),
                len: raw.len(),
                caller: digest(&server_key).unwrap(),
                digest: hash(b"public-request-body-v3", &[&raw]),
                client_nonce: [4; 32],
            },
            "127.0.0.1:19999".parse().unwrap(),
        )
        .unwrap();
    let pin = ServerPin::Classical(&server_key);
    for success in [true, false] {
        let progress_calls = Cell::new(0);
        let outcome: Result<Value> = if success {
            Ok(json!({"height": 0}))
        } else {
            Err("RESPONSE_SIGNING_CONTROL_REFUSAL".into())
        };
        let frame = response(&server, &settings, &cookie, outcome, &|| {
            progress_calls.set(progress_calls.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(progress_calls.get(), 4);
        let declared = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(declared, frame.len() - 4);
        let mut reply: Response = serde_json::from_slice(&frame[4..]).unwrap();
        assert_eq!(serde_json::to_vec(&reply).unwrap(), frame[4..]);
        assert_eq!(reply.ok, success);
        assert_eq!(
            reply.value,
            if success {
                json!({"height": 0})
            } else {
                json!({"error": "RESPONSE_SIGNING_CONTROL_REFUSAL"})
            }
        );
        assert_eq!(reply.schema, "public-protected-response-v3");
        assert_eq!(reply.profile, hex::encode(server.resource_profile()));
        assert_eq!(reply.network, hex::encode(settings.network()));
        assert_eq!(reply.parameters, hex::encode(settings.parameters()));
        assert_eq!(reply.genesis, hex::encode(settings.genesis()));
        assert_eq!(reply.server, server_key);
        assert_eq!(reply.cookie_digest, hex::encode(cookie.id().unwrap()));
        assert_eq!(reply.request_digest, cookie.body_digest);
        pin.verify(&reply.message().unwrap(), &reply.signature)
            .unwrap();
        pin.verify(
            &original_message_clone_oracle(&reply).unwrap(),
            &reply.signature,
        )
        .unwrap();
        reply.value = json!({"tampered": true});
        assert!(pin
            .verify(&reply.message().unwrap(), &reply.signature)
            .is_err());
    }
    for fail_at in 1..=4 {
        let progress_calls = Cell::new(0);
        let error = response(
            &server,
            &settings,
            &cookie,
            Ok(json!({"height": 0})),
            &|| {
                let reached = progress_calls.get() + 1;
                progress_calls.set(reached);
                if reached == fail_at {
                    Err("RESPONSE_SIGNING_CONTROL_CANCELLED".into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert_eq!(progress_calls.get(), fail_at);
        assert_eq!(error.to_string(), "RESPONSE_SIGNING_CONTROL_CANCELLED");
    }
}
