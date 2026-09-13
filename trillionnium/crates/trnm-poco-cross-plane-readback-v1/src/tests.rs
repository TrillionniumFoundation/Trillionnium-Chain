#[test]
fn projection_hash_is_domain_separated() {
    assert_ne!(
        crate::codec::digest_value("trnm.poco-ai.cross-plane-readback.test.v1", &1u16)
            .expect("digest"),
        crate::codec::digest_value("trnm.poco-ai.cross-plane-readback.test.v1", &2u16)
            .expect("digest")
    );
}
