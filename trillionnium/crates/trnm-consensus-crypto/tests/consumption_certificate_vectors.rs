use serde_json::Value;
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_consumption_certificate_v0_exact, ChainId, ConsensusParametersV0, ConsensusPublicKey,
    ConsumptionCertificateDecodeErrorCode, GenesisHash, Height,
};

const VECTOR: &str =
    include_str!("../../../../docs/protocol/poco-bft-v0/vectors/consumption-certificate-v0.json");

#[test]
fn exact_certificate_vector_round_trips_and_strictly_verifies() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid vector JSON");
    let fixture = root
        .get("fixture")
        .and_then(Value::as_object)
        .expect("fixture");
    let raw = hex_vec(string(fixture, "certificate_cev0_hex"));
    let certificate = decode_consumption_certificate_v0_exact(&raw).expect("exact certificate");
    assert_eq!(certificate.try_cev0_bytes().expect("bounded object"), raw);
    assert_eq!(
        certificate.body().try_cev0_bytes().expect("bounded body"),
        hex_vec(string(fixture, "body_cev0_hex"))
    );
    assert_eq!(
        certificate.body().digest().as_bytes(),
        &hex_array::<32>(string(fixture, "body_digest_hex"))
    );
    assert_eq!(
        certificate.certificate_id().as_bytes(),
        &hex_array::<32>(string(fixture, "certificate_id_hex"))
    );
    certificate
        .verify(
            GenesisHash::new(hex_array(string(fixture, "genesis_hash_hex"))),
            ChainId::from_bytes(string(fixture, "chain_id_ascii").as_bytes()).expect("chain"),
            &ConsensusParametersV0::reference_shadow_v0(),
            Height::new(21),
            ConsensusPublicKey::new(hex_array(string(fixture, "consumer_public_key_hex"))),
            &StrictEd25519Verifier,
        )
        .expect("strict Ed25519 admission");

    for length in 0..raw.len() {
        let error = decode_consumption_certificate_v0_exact(&raw[..length])
            .expect_err("every non-complete prefix must fail");
        assert_eq!(
            error.code(),
            ConsumptionCertificateDecodeErrorCode::UnexpectedEnd,
            "prefix {length}"
        );
    }
    let mut wrong_id = raw;
    *wrong_id.last_mut().expect("nonempty fixture") ^= 1;
    assert_eq!(
        decode_consumption_certificate_v0_exact(&wrong_id)
            .expect_err("wrong ID")
            .code(),
        ConsumptionCertificateDecodeErrorCode::CertificateIdMismatch
    );
}

#[test]
fn wrong_key_and_acceptance_boundary_fail_closed() {
    let root: Value = serde_json::from_str(VECTOR).expect("valid vector JSON");
    let fixture = root
        .get("fixture")
        .and_then(Value::as_object)
        .expect("fixture");
    let certificate =
        decode_consumption_certificate_v0_exact(&hex_vec(string(fixture, "certificate_cev0_hex")))
            .expect("exact certificate");
    let genesis = GenesisHash::new(hex_array(string(fixture, "genesis_hash_hex")));
    let chain = ChainId::from_bytes(string(fixture, "chain_id_ascii").as_bytes()).expect("chain");
    assert!(certificate
        .verify(
            genesis,
            chain,
            &ConsensusParametersV0::reference_shadow_v0(),
            Height::new(20),
            ConsensusPublicKey::new(hex_array(string(fixture, "consumer_public_key_hex"))),
            &StrictEd25519Verifier,
        )
        .is_err());
    assert!(certificate
        .verify(
            genesis,
            chain,
            &ConsensusParametersV0::reference_shadow_v0(),
            Height::new(21),
            ConsensusPublicKey::new([9; 32]),
            &StrictEd25519Verifier,
        )
        .is_err());
}

fn string<'a>(object: &'a serde_json::Map<String, Value>, key: &str) -> &'a str {
    object
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing {key}"))
}

fn hex_vec(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex"))
        .collect()
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex_vec(value)
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N} bytes"))
}
