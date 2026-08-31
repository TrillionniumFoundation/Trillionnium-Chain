use crate::{SignatureBytes, SigningRoot, Validator};

/// Pure verification boundary used by the deterministic consensus core.
///
/// Implementations must be deterministic and side-effect free. Private keys
/// and signing operations intentionally do not belong in this crate.
pub trait SignatureVerifier {
    fn verify(
        &self,
        validator: &Validator,
        signing_root: &SigningRoot,
        signature: &SignatureBytes,
    ) -> bool;
}
