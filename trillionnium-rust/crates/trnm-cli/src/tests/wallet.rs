use super::*;

#[test]
fn wallet_import_hex_check() {
    let ok =
        ensure_hex_32_bytes("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
    assert_eq!(ok.len(), 64);
    assert!(ensure_hex_32_bytes("0x1234").is_err());
}
