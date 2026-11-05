use super::super::digest_hex;
use super::*;

#[test]
fn signed_development_profile_has_an_independent_exact_encoding_vector() {
    // Independently generated with Python cryptography Ed25519, not by calling
    // the Rust encoder under test to obtain its expected values.
    let context = CellContextV1 {
        family: "discovery-native-test-v1".into(),
        base: [5; 32],
        parent: [6; 32],
        tokenizer: [7; 32],
        layout: [8; 32],
        runtime: [9; 32],
    };
    let cell_context = cell_discovery_context_digest(&context).unwrap();
    assert_eq!(
        digest_hex(cell_context),
        "0a2bd87029f1dd37c8f69a9aed65a1b382bb457f36805c60066258a9ee87b95a"
    );
    let request = CellDiscoveryRequestV1 {
        context: CellDiscoveryContextV1 {
            namespace: [1; 32],
            network: [2; 32],
            parameters: [3; 32],
            genesis: [4; 32],
        },
        cell_context,
        manifest: [11; 32],
    };
    let seed: [u8; 32] = Sha256::digest(11_u64.to_be_bytes()).into();
    let key = SigningKey::from_bytes(&seed);
    assert_eq!(
        digest_hex(key.verifying_key().to_bytes()),
        "bcb4616555ed466a40fdf677ae4a2e579fcf8de8f3f4662cbdcb7d375a72c987"
    );
    let value = CellProviderRecordV1::sign(
        CellProviderStatementV1 {
            request,
            owner: key.verifying_key().to_bytes(),
            endpoint: "127.0.0.1:31234".parse().unwrap(),
            sequence: 1,
            issued_unix_seconds: 1_700_000_000,
            expires_unix_seconds: 1_700_000_300,
        },
        &key,
    )
    .unwrap();
    assert_eq!(value.encode().len(), 335);
    assert_eq!(
        digest_hex(value.message()),
        "16a7b983b0f20db7bab3dae980d08bbbcdc957d7bac25499158145273f177f28"
    );
    assert_eq!(
        digest_hex(value.digest()),
        "8a896269c1962c5b59b4c8c30d21909ed81454d20ba7921932a566e71a697ba6"
    );
    CellProviderRecordV1::decode(&value.encode())
        .unwrap()
        .verify_at(
            request,
            1_700_000_000,
            &CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![31234] },
        )
        .unwrap();
}
