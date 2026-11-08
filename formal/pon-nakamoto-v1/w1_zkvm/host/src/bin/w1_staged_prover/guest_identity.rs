//! Validate the actual embedded program independently of generated constants.
use super::*;

const RETAINED_BYTES: usize = 375_928;
const RETAINED_SHA256: &str = "25718312ec3c6f5219d832e3516adfb5f82983156f669c5e7daa15bd22d1798f";
const RETAINED_IMAGE: [u32; 8] = [
    1958252411, 3287394615, 1805488136, 1516578702, 78549041, 790278610, 301018785, 4279049364,
];

fn validate(bytes: &[u8], declared_image: [u32; 8], retained: bool) -> Result<()> {
    ensure!(!bytes.is_empty(), "empty embedded guest is forbidden");
    if retained {
        ensure!(
            bytes.len() == RETAINED_BYTES && sha(bytes) == RETAINED_SHA256,
            "retained original v2 guest bytes changed"
        );
        ensure!(
            declared_image == RETAINED_IMAGE,
            "retained fixed v2 image changed"
        );
    }
    let actual =
        risc0_zkvm::compute_image_id(bytes).context("compute actual embedded SDK image")?;
    ensure!(
        actual == Digest::from(declared_image),
        "embedded bytes and declared SDK image disagree"
    );
    Ok(())
}

pub(super) fn verify_selected() -> Result<serde_json::Value> {
    #[cfg(feature = "statement-v2")]
    let mode = trnm_w1_zk_methods::TRNM_W1_GUEST_BUILD_MODE;
    #[cfg(not(feature = "statement-v2"))]
    let mode = "sdk-embed-methods";
    ensure!(
        matches!(mode, "retained-v2-guest" | "sdk-embed-methods"),
        "unknown embedded guest build mode"
    );
    let retained = mode == "retained-v2-guest";
    validate(TRNM_W1_FULL_GUEST_ELF, TRNM_W1_FULL_GUEST_ID, retained)?;
    Ok(json!({
        "schema":"TRNM-W1-GUEST-RUNTIME1","mode":mode,
        "guest_bytes":TRNM_W1_FULL_GUEST_ELF.len(),
        "guest_sha256":sha(TRNM_W1_FULL_GUEST_ELF),"image_id":TRNM_W1_FULL_GUEST_ID,
        "sdk_image_checked":true,"uses_retained_original_guest":retained,
        "fresh_guest_compilation_claimed":false,"cryptographic_proof_complete":false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    const ORIGINAL: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../evidence/pon-w1-full-v2-20261105/guest.bin"
    ));

    #[test]
    fn original_complete_guest_matches_its_exact_bytes_and_real_sdk_image() {
        validate(ORIGINAL, RETAINED_IMAGE, true).unwrap();
        verify_selected().unwrap();
    }

    #[test]
    fn empty_changed_or_relabelled_retained_guests_are_rejected() {
        assert!(validate(&[], RETAINED_IMAGE, true).is_err());
        let mut changed = ORIGINAL.to_vec();
        let middle = changed.len() / 2;
        changed[middle] ^= 1;
        assert!(validate(&changed, RETAINED_IMAGE, true).is_err());
        let mut wrong_image = RETAINED_IMAGE;
        wrong_image[0] ^= 1;
        let error = validate(ORIGINAL, wrong_image, true).unwrap_err();
        assert!(format!("{error:#}").contains("retained fixed v2 image changed"));
        assert!(validate(ORIGINAL, wrong_image, false).is_err());
    }
}
