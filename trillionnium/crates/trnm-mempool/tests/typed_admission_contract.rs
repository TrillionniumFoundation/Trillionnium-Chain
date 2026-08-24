//! Source-contract checks for the typed ingress boundary.
//!
//! These checks intentionally pin the negative contract: the mempool adapter may
//! not grow a private-key dependency or present its in-memory queue as durable
//! consensus integration while the canonical node owner is still separate.

use std::fs;

#[test]
fn typed_admission_stays_key_free_and_explicitly_non_durable() {
    let path = format!("{}/src/typed_admission.rs", env!("CARGO_MANIFEST_DIR"));
    let source = fs::read_to_string(path).expect("read typed admission source");

    for forbidden in ["SigningKey", "SecretKey", "private_key", "PrivateKey"] {
        assert!(
            !source.contains(forbidden),
            "typed mempool boundary must not contain {forbidden}"
        );
    }
    for required in [
        "trait SignedEnvelopeView",
        "trait SignedAdmissionHooks",
        "CanonicalTxDigest",
        "validate_canonical",
        "ReplayCheckUnavailable",
        "RecheckUnavailable",
        "not a WAL",
        "consensus executor",
    ] {
        assert!(
            source.contains(required),
            "typed admission source lost required boundary marker {required}"
        );
    }
}
