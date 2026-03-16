use super::*;

#[test]
fn parse_tx_hash_accepts_quoted_and_trailing_punctuated_tokens() {
    let mixed_case =
        "tx_hash=\"0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd\",";
    let parsed = parse_tx_hash(mixed_case).expect("hash should parse");
    assert_eq!(
        parsed,
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    );

    let sentence_tail = "submitted tx_hash=0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd. next";
    let parsed_tail =
        parse_tx_hash(sentence_tail).expect("hash with sentence punctuation should parse");
    assert_eq!(
        parsed_tail,
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    );

    let backtick_wrapped =
        "adapter stdout: tx_hash=`0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd`";
    let parsed_backtick =
        parse_tx_hash(backtick_wrapped).expect("backtick-wrapped hash should parse");
    assert_eq!(
        parsed_backtick,
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    );
}
