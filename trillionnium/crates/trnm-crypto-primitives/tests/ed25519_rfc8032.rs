//! Fixed RFC 8032 section 7.1 vectors retain the existing Ed25519 wire result
//! across dependency updates. These public example seeds are not credentials.
//! Source: https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
use trnm_crypto_primitives::{
    owned_ed25519::OwnedEd25519Key, public_key_hex, sign_hex, signing_key_from_hex, verify_hex,
    verify_hex_strict,
};

fn check_vector(seed: &str, public: &str, message: &[u8], signature: &str) {
    let key = signing_key_from_hex(seed).unwrap();
    assert_eq!(public_key_hex(&key), public);
    assert_eq!(sign_hex(&key, message), signature);
    verify_hex(public, message, signature).unwrap();
    verify_hex_strict(public, message, signature).unwrap();

    let owned = OwnedEd25519Key::from_canonical_hex(seed).unwrap();
    assert_eq!(owned.public_key_hex(), public);
    assert_eq!(owned.sign_hex(message), signature);
}

#[test]
fn rfc8032_empty_message_exact_signature() {
    check_vector(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        b"",
        concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
    );
}

#[test]
fn rfc8032_one_byte_message_exact_signature() {
    check_vector(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        &[0x72],
        concat!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
    );
}
