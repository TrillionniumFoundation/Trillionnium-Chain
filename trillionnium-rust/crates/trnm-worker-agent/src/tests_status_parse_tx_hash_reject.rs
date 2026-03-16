use super::*;

#[test]
fn parse_tx_hash_rejects_receipts_over_128_chars() {
    let too_long_hash = format!("0x{}", "AB".repeat(65));
    assert!(parse_tx_hash(&format!("tx_hash={too_long_hash}")).is_none());
}

#[test]
fn parse_tx_hash_rejects_malformed_or_partial_values() {
    assert!(parse_tx_hash("tx_hash=0xdeadbee-").is_none());
    assert!(parse_tx_hash("tx_hash=not-a-hash").is_none());
    assert!(parse_tx_hash(
        "tx_hash=0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
    )
    .is_none());
    assert!(parse_tx_hash("tx_hash=1234567").is_none());
    let overflow_hash = format!("tx_hash=0x{}", "ab".repeat(65));
    assert!(parse_tx_hash(&overflow_hash).is_none());
}
