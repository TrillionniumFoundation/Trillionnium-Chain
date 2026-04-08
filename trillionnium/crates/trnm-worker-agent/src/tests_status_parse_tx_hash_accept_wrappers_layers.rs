use super::*;

#[test]
fn parse_tx_hash_accepts_angle_bracket_wrapped_receipts() {
    let shell = parse_tx_hash(
        "[adapter] commit accepted tx_hash=<0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd>",
    )
    .expect("angle-bracket shell receipt hash should parse");
    assert_eq!(
        shell,
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    );

    let json = parse_tx_hash(
        "adapter stdout: {\"tx_hash\": \"<0xFACEfaceFACEfaceFACEfaceFACEfaceFACEfaceFACEfaceFACEfaceFACEface>\"}",
    )
    .expect("angle-bracket json receipt hash should parse");
    assert_eq!(
        json,
        "facefacefacefacefacefacefacefacefacefacefacefacefacefacefaceface"
    );
}
