use super::*;

#[test]
fn parse_tx_hash_accepts_unicode_dash_receipt_keys() {
    let non_breaking_shell = parse_tx_hash("[adapter] commit accepted tx‑hash=0xDEADBEEF")
        .expect("non-breaking hyphen shell receipt key should parse");
    assert_eq!(non_breaking_shell, "deadbeef");

    let em_dash_json = parse_tx_hash("adapter stdout: {\"transaction—hash\": \"0xFACECAFE\"}")
        .expect("em dash json receipt key should parse");
    assert_eq!(em_dash_json, "facecafe");

    let fullwidth_shell = parse_tx_hash("[adapter] commit accepted transaction－hash:0xBADDCAFE")
        .expect("fullwidth hyphen shell receipt key should parse");
    assert_eq!(fullwidth_shell, "baddcafe");
}
