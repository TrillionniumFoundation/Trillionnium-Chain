use serde_json::{json, Value};
use trnm_crypto_primitives::pq_auth::{
    tuf::{
        sign_tuf_mldsa65_v1, verify_tuf_mldsa65_v1, TufMldsa65ErrorV1, TUF_MAX_CANONICAL_BYTES_V1,
        TUF_MAX_DEPTH_V1, TUF_MAX_VALUES_V1, TUF_ML_DSA_65_V1_SCHEME,
    },
    PqNativeSigningKey, PqNativeVerifier,
};
use zeroize::Zeroizing;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/pq/tuf_tap21_mldsa65_v1.json")).unwrap()
}
fn bytes(fixture: &Value, key: &str) -> Vec<u8> {
    hex::decode(fixture[key].as_str().unwrap()).unwrap()
}
fn verifier(fixture: &Value) -> PqNativeVerifier {
    PqNativeVerifier::from_pinned_spki(
        &bytes(fixture, "public_spki_hex"),
        bytes(fixture, "key_id_hex").try_into().unwrap(),
    )
    .unwrap()
}
fn signing_key(fixture: &Value) -> PqNativeSigningKey {
    PqNativeSigningKey::from_owned_seed(
        Zeroizing::new([177; 32]),
        bytes(fixture, "key_id_hex").try_into().unwrap(),
    )
    .unwrap()
}

#[test]
fn independent_sdk_canonicalization_and_openssl_signature_are_accepted() {
    let f = fixture();
    let signature = bytes(&f, "signature_hex");
    let v = verifier(&f);
    let observation =
        verify_tuf_mldsa65_v1(&v, TUF_ML_DSA_65_V1_SCHEME, &f["signed"], &signature).unwrap();
    assert_eq!(observation.signed_value(), &f["signed"]);
    assert_eq!(observation.signer_key_id(), v.public_key_id());
    // A second check binds the fixture to the exact upstream TAP 21 payload,
    // independently of this adapter's canonicalization implementation.
    v.verify_exact_message(&bytes(&f, "presigning_hex"), &signature)
        .unwrap();
}

#[test]
fn rust_signing_uses_exact_independent_presigning_bytes() {
    let f = fixture();
    let signature =
        sign_tuf_mldsa65_v1(&signing_key(&f), TUF_ML_DSA_65_V1_SCHEME, &f["signed"]).unwrap();
    verifier(&f)
        .verify_exact_message(&bytes(&f, "presigning_hex"), &signature)
        .unwrap();
}

#[test]
fn trusted_scheme_is_exact_and_never_inferred_from_signature() {
    let f = fixture();
    let v = verifier(&f);
    let key = signing_key(&f);
    for scheme in [
        "ml-dsa",
        "ml-dsa-65",
        "ml-dsa-65/0",
        "ml-dsa-65/01",
        "ml-dsa-65/2",
        "ml-dsa-44/1",
        "ml-dsa-87/1",
        "ML-DSA-65/1",
        "ml-dsa-65/1 ",
    ] {
        assert!(matches!(
            verify_tuf_mldsa65_v1(&v, scheme, &f["signed"], &bytes(&f, "signature_hex")),
            Err(TufMldsa65ErrorV1::Scheme)
        ));
        assert!(matches!(
            sign_tuf_mldsa65_v1(&key, scheme, &f["signed"]),
            Err(TufMldsa65ErrorV1::Scheme)
        ));
    }
}

#[test]
fn altered_role_or_content_cannot_reuse_a_signature() {
    let f = fixture();
    let v = verifier(&f);
    let signature = bytes(&f, "signature_hex");
    for (key, value) in [
        ("_type", json!("root")),
        ("version", json!(16)),
        ("expires", json!("2099-01-01T00:00:00Z")),
        ("targets", json!({})),
    ] {
        let mut changed = f["signed"].clone();
        changed[key] = value;
        assert!(verify_tuf_mldsa65_v1(&v, TUF_ML_DSA_65_V1_SCHEME, &changed, &signature).is_err());
    }
}

#[test]
fn context_raw_metadata_digest_and_other_version_have_no_fallback() {
    let f = fixture();
    let v = verifier(&f);
    let key = signing_key(&f);
    assert!(verify_tuf_mldsa65_v1(
        &v,
        TUF_ML_DSA_65_V1_SCHEME,
        &f["signed"],
        &bytes(&f, "wrong_context_signature_hex")
    )
    .is_err());
    let message = bytes(&f, "presigning_hex");
    let mut version2 = message.clone();
    version2[3] = 2;
    let mut other_domain = message.clone();
    other_domain[0] ^= 1;
    for wrong in [
        bytes(&f, "canonical_hex"),
        message[4..].to_vec(),
        version2,
        other_domain,
    ] {
        let sig = key.sign_exact_message(&wrong).unwrap();
        assert!(verify_tuf_mldsa65_v1(&v, TUF_ML_DSA_65_V1_SCHEME, &f["signed"], &sig).is_err());
    }
}

#[test]
fn canonical_integer_domain_and_resource_budgets_are_checked_before_crypto() {
    let f = fixture();
    let v = verifier(&f);
    for input in [json!({"n":1.0}), json!({"n":-0.0}), json!({"n":1.2})] {
        assert!(matches!(
            verify_tuf_mldsa65_v1(&v, TUF_ML_DSA_65_V1_SCHEME, &input, &[]),
            Err(TufMldsa65ErrorV1::Integer)
        ));
    }
    let mut deep = Value::Null;
    for _ in 0..TUF_MAX_DEPTH_V1 {
        deep = Value::Array(vec![deep]);
    }
    for input in [
        json!({"big":"a".repeat(TUF_MAX_CANONICAL_BYTES_V1)}),
        json!({"many":vec![Value::Null;TUF_MAX_VALUES_V1]}),
        json!({"deep":deep}),
    ] {
        assert!(matches!(
            verify_tuf_mldsa65_v1(&v, TUF_ML_DSA_65_V1_SCHEME, &input, &[]),
            Err(TufMldsa65ErrorV1::Limit)
        ));
    }
    for input in [Value::Null, json!([]), json!("prefix"), json!(123)] {
        assert!(matches!(
            verify_tuf_mldsa65_v1(&v, TUF_ML_DSA_65_V1_SCHEME, &input, &[]),
            Err(TufMldsa65ErrorV1::MetadataObject)
        ));
    }
}

#[test]
fn reordered_object_fields_and_integer_extremes_have_unique_canonical_meaning() {
    let f = fixture();
    let key = signing_key(&f);
    let v = verifier(&f);
    let a = json!({"z":u64::MAX,"a":i64::MIN,"q":"\\\"\n\u{0000}é"});
    let b: Value = serde_json::from_str(&format!(
        "{{\"q\":\"\\\\\\\"\\n\\u0000é\",\"a\":{},\"z\":{}}}",
        i64::MIN,
        u64::MAX
    ))
    .unwrap();
    let sig = sign_tuf_mldsa65_v1(&key, TUF_ML_DSA_65_V1_SCHEME, &a).unwrap();
    verify_tuf_mldsa65_v1(&v, TUF_ML_DSA_65_V1_SCHEME, &b, &sig).unwrap();
}

#[test]
fn malformed_signature_and_untrusted_key_pin_are_rejected() {
    let f = fixture();
    let v = verifier(&f);
    let signature = bytes(&f, "signature_hex");
    for length in [0, 3308, 3310] {
        let mut bad = signature.clone();
        bad.resize(length, 0);
        assert!(verify_tuf_mldsa65_v1(&v, TUF_ML_DSA_65_V1_SCHEME, &f["signed"], &bad).is_err());
    }
    assert!(PqNativeVerifier::from_pinned_spki(&bytes(&f, "public_spki_hex"), [0; 32]).is_err());
}
