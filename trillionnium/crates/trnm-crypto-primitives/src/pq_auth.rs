//! Native ML-DSA-65 verification for the separately namespaced TPQ1 envelope.
//!
//! A checked signature establishes only possession of the independently pinned
//! key for this exact statement. It grants no chainwork, model qualification,
//! replay exemption, installation permission or legacy-wire compatibility.
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use trnm_protocol::pq_frame::{
    preflight_unverified_with_spki, PqFrameError, PqFrameExpectation, ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqAuthError {
    Frame(PqFrameError),
    PublicKeyLength,
    SignatureEncoding,
    ContextLength,
    Signature,
}

/// A signature-checked statement, deliberately not a release/work capability.
/// Private fields prevent unverified bytes or an external Boolean constructing it.
#[derive(Debug)]
pub struct SignatureCheckedPqFrame<'a> {
    statement: &'a [u8],
    signer_key_id: [u8; 32],
}

impl SignatureCheckedPqFrame<'_> {
    pub fn statement(&self) -> &[u8] {
        self.statement
    }

    pub fn signer_key_id(&self) -> &[u8; 32] {
        &self.signer_key_id
    }
}

/// Exact FIPS 204 pure ML-DSA verification, with an explicit context.
///
/// This low-level operation does not establish that an arbitrary supplied public
/// key is an authorized identity. In particular, callers must not use a key read
/// from the same untrusted request as their trust anchor.
pub fn verify_ml_dsa_65(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<(), PqAuthError> {
    if public_key.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(PqAuthError::PublicKeyLength);
    }
    if context.len() > 255 {
        return Err(PqAuthError::ContextLength);
    }
    if signature.len() != ML_DSA_65_SIGNATURE_BYTES {
        return Err(PqAuthError::SignatureEncoding);
    }
    // Decode the signature before expanding the public matrix. The pinned
    // dependency rejects non-increasing/duplicate hints and norm violations.
    let signature =
        Signature::<MlDsa65>::try_from(signature).map_err(|_| PqAuthError::SignatureEncoding)?;
    let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(public_key)
        .map_err(|_| PqAuthError::PublicKeyLength)?;
    let key = VerifyingKey::<MlDsa65>::decode(&encoded);
    if !key.verify_with_context(message, context, &signature) {
        return Err(PqAuthError::Signature);
    }
    Ok(())
}

/// Verify syntax, exact caller-pinned identity/context and a real ML-DSA-65
/// signature, with no Ed25519, external-process, Boolean or permissive fallback.
///
/// TPQ1 v1 signs its canonical 176-byte statement in pure ML-DSA mode with an
/// empty FIPS context, matching the independent OpenSSL research oracle. The
/// statement's magic/version/purpose/network/owner and payload commitment carry
/// its protocol domain. Replay consumption remains the state owner's job.
pub fn verify_tpq1<'a>(
    frame: &'a [u8],
    expected: &PqFrameExpectation<'_>,
    pinned_spki: &[u8],
) -> Result<SignatureCheckedPqFrame<'a>, PqAuthError> {
    let unverified =
        preflight_unverified_with_spki(frame, expected, pinned_spki).map_err(PqAuthError::Frame)?;
    // The preflight has checked the exact 22-byte DER prefix and total length.
    verify_ml_dsa_65(
        &pinned_spki[22..],
        unverified.unsigned_statement(),
        &[],
        unverified.unverified_signature(),
    )?;
    Ok(SignatureCheckedPqFrame {
        statement: unverified.unsigned_statement(),
        signer_key_id: expected.signer_key_id,
    })
}

#[cfg(test)]
#[path = "pq_auth_tests.rs"]
mod tests;
