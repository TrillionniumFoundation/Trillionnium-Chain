use super::super::*;

#[test]
fn tx_query_parse_kv_is_tolerant_to_case_and_separator() {
    let kv = "TXHASH: 0x777\nSTATUS: committed\nERROR: null\n";
    let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0x777");
    assert_eq!(parsed.status, "committed");
    assert_eq!(parsed.error, None);
}

#[test]
fn tx_query_parse_kv_treats_nullish_error_variants_as_empty() {
    let kv = "tx_hash=0x777\nstatus=committed\nerror='NULL,'\n";
    let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0x777");
    assert_eq!(parsed.status, "committed");
    assert_eq!(parsed.error, None);

    let backtick_kv = "tx_hash=0x778\nstatus=`COMMITTED`\nerror=`null`,\n";
    let parsed_backtick = parse_tx_query_response(backtick_kv, "0xfallback").unwrap();
    assert_eq!(parsed_backtick.tx_hash, "0x778");
    assert_eq!(parsed_backtick.status, "committed");
    assert_eq!(parsed_backtick.error, None);
}

#[test]
fn tx_query_parse_kv_unwraps_single_and_backtick_quoted_error_values() {
    let single = "tx_hash=0x781\nstatus=fail\nerror='nonce mismatch'\n";
    let parsed_single = parse_tx_query_response(single, "0xfallback").unwrap();
    assert_eq!(parsed_single.error.as_deref(), Some("nonce mismatch"));

    let backtick = "tx_hash=0x782\nstatus=fail\nerror=`signature invalid`\n";
    let parsed_backtick = parse_tx_query_response(backtick, "0xfallback").unwrap();
    assert_eq!(parsed_backtick.error.as_deref(), Some("signature invalid"));
}

#[test]
fn tx_query_parse_kv_accepts_noisy_single_line_inline_tokens() {
    let noisy = "[adapter] ts=1700000000 status=committed tx_hash=0x8badf00d, error=null";
    let parsed = parse_tx_query_response(noisy, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0x8badf00d");
    assert_eq!(parsed.status, "committed");
    assert_eq!(parsed.error, None);
}

#[test]
fn tx_query_parse_normalizes_status_aliases_and_punctuation() {
    let kv = "txhash=0xabc\nstatus=FAILED,\n";
    let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0xabc");
    assert_eq!(parsed.status, "fail");

    let json = "{\"tx_hash\":\"0xdef\",\"status\":\"ok\"}";
    let parsed_json = parse_tx_query_response(json, "0xfallback").unwrap();
    assert_eq!(parsed_json.status, "committed");

    let noisy_punct = "tx_hash=0xeee\nstatus=success!?\n";
    let parsed_noisy = parse_tx_query_response(noisy_punct, "0xfallback").unwrap();
    assert_eq!(parsed_noisy.status, "committed");

    let succeeded_alias = "tx_hash=0xeee1\nstatus=succeeded\n";
    let parsed_succeeded = parse_tx_query_response(succeeded_alias, "0xfallback").unwrap();
    assert_eq!(parsed_succeeded.status, "committed");

    let confirmed_alias = "tx_hash=0xeee2\nstatus=confirmed\n";
    let parsed_confirmed = parse_tx_query_response(confirmed_alias, "0xfallback").unwrap();
    assert_eq!(parsed_confirmed.status, "committed");

    let single_quoted = "tx_hash=0xeff\nstatus='committed'\n";
    let parsed_single_quoted = parse_tx_query_response(single_quoted, "0xfallback").unwrap();
    assert_eq!(parsed_single_quoted.status, "committed");

    let rejected_alias = "tx_hash=0xef0\nstatus=REJECTED\n";
    let parsed_rejected = parse_tx_query_response(rejected_alias, "0xfallback").unwrap();
    assert_eq!(parsed_rejected.status, "fail");

    let timed_out_alias = "tx_hash=0xef1\nstatus=timed_out\n";
    let parsed_timed_out = parse_tx_query_response(timed_out_alias, "0xfallback").unwrap();
    assert_eq!(parsed_timed_out.status, "fail");

    let timed_out_hyphen_alias = "tx_hash=0xef2\nstatus=timed-out\n";
    let parsed_timed_out_hyphen =
        parse_tx_query_response(timed_out_hyphen_alias, "0xfallback").unwrap();
    assert_eq!(parsed_timed_out_hyphen.status, "fail");
}

#[test]
fn tx_query_parse_kv_ignores_noisy_lines_and_uses_valid_status() {
    let noisy = "[rpc] connecting...\nrandom line without kv\ntx_hash=0x999\nINFO: still processing\nstatus=committed\n";
    let parsed = parse_tx_query_response(noisy, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0x999");
    assert_eq!(parsed.status, "committed");
    assert_eq!(parsed.error, None);
}

#[test]
fn tx_query_parse_normalizes_quoted_or_punctuated_tx_hash() {
    let kv = "tx_hash='0xABCD1234',\nstatus=committed\n";
    let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0xabcd1234");

    let json = "{\"tx_hash\":\"0xDEADbeef,\",\"status\":\"committed\"}";
    let parsed_json = parse_tx_query_response(json, "0xfallback").unwrap();
    assert_eq!(parsed_json.tx_hash, "0xdeadbeef");

    let nested_wrappers = "tx_hash=(`\"0xBEEF42\"`,)\nstatus=committed\n";
    let parsed_nested = parse_tx_query_response(nested_wrappers, "0xfallback").unwrap();
    assert_eq!(parsed_nested.tx_hash, "0xbeef42");

    let sentence_noise = "tx_hash=0xC0FFEE42?!\nstatus=committed\n";
    let parsed_sentence_noise = parse_tx_query_response(sentence_noise, "0xfallback").unwrap();
    assert_eq!(parsed_sentence_noise.tx_hash, "0xc0ffee42");

    let cjk_sentence_noise = "tx_hash=0xC0FFEE43。\nstatus=committed\n";
    let parsed_cjk_sentence_noise =
        parse_tx_query_response(cjk_sentence_noise, "0xfallback").unwrap();
    assert_eq!(parsed_cjk_sentence_noise.tx_hash, "0xc0ffee43");

    let fullwidth_dot_noise = "tx_hash=0xC0FFEE44．\nstatus=committed\n";
    let parsed_fullwidth_dot_noise =
        parse_tx_query_response(fullwidth_dot_noise, "0xfallback").unwrap();
    assert_eq!(parsed_fullwidth_dot_noise.tx_hash, "0xc0ffee44");
}

#[test]
fn tx_query_parse_kv_accepts_transaction_hash_aliases() {
    let snake = "transaction_hash=0xabc123\nstatus=committed\n";
    let parsed_snake = parse_tx_query_response(snake, "0xfallback").unwrap();
    assert_eq!(parsed_snake.tx_hash, "0xabc123");

    let compact = "transactionHash=0xdef456\nstatus=committed\n";
    let parsed_compact = parse_tx_query_response(compact, "0xfallback").unwrap();
    assert_eq!(parsed_compact.tx_hash, "0xdef456");

    let hyphen = "tx-hash=0xface789\nstatus=committed\n";
    let parsed_hyphen = parse_tx_query_response(hyphen, "0xfallback").unwrap();
    assert_eq!(parsed_hyphen.tx_hash, "0xface789");

    let transaction_hyphen = "transaction-hash: 0xdecafbad\nstatus=committed\n";
    let parsed_transaction_hyphen =
        parse_tx_query_response(transaction_hyphen, "0xfallback").unwrap();
    assert_eq!(parsed_transaction_hyphen.tx_hash, "0xdecafbad");

    let spaced = "tx hash = 0xabc123\ntransaction status = success\n";
    let parsed_spaced = parse_tx_query_response(spaced, "0xfallback").unwrap();
    assert_eq!(parsed_spaced.tx_hash, "0xabc123");
    assert_eq!(parsed_spaced.status, "committed");

    let mixed = "transaction hash：0xdef456\ncheck tx code：0\n";
    let parsed_mixed = parse_tx_query_response(mixed, "0xfallback").unwrap();
    assert_eq!(parsed_mixed.tx_hash, "0xdef456");
    assert_eq!(parsed_mixed.status, "committed");
}

#[test]
fn tx_query_parse_kv_accepts_fullwidth_separators() {
    let fullwidth_equals = "tx_hash＝0xabc987\nstatus＝committed\nerror＝null\n";
    let parsed_fullwidth_equals = parse_tx_query_response(fullwidth_equals, "0xfallback").unwrap();
    assert_eq!(parsed_fullwidth_equals.tx_hash, "0xabc987");
    assert_eq!(parsed_fullwidth_equals.status, "committed");
    assert_eq!(parsed_fullwidth_equals.error, None);

    let fullwidth_colon = "transactionHash：0xdef654\nstatus：COMMITTED\n";
    let parsed_fullwidth_colon = parse_tx_query_response(fullwidth_colon, "0xfallback").unwrap();
    assert_eq!(parsed_fullwidth_colon.tx_hash, "0xdef654");
    assert_eq!(parsed_fullwidth_colon.status, "committed");
}

#[test]
fn tx_query_parse_kv_accepts_angle_bracket_wrapped_inline_tokens() {
    let noisy = "[rpc] <transactionHash:0xCAFE99> <status:COMMITTED> <error:null>";
    let parsed = parse_tx_query_response(noisy, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0xcafe99");
    assert_eq!(parsed.status, "committed");
    assert_eq!(parsed.error, None);
}

#[test]
fn tx_query_parse_kv_accepts_quoted_and_unicode_wrapped_keys() {
    let quoted = "\"tx_hash\"=0xCAFE77\n'status'=COMMITTED\n`error`=null\n";
    let parsed_quoted = parse_tx_query_response(quoted, "0xfallback").unwrap();
    assert_eq!(parsed_quoted.tx_hash, "0xcafe77");
    assert_eq!(parsed_quoted.status, "committed");
    assert_eq!(parsed_quoted.error, None);

    let unicode_wrapped = "《transactionHash》：0xCAFE78\n【status】：SUCCESS\n『error』：NULL\n";
    let parsed_unicode = parse_tx_query_response(unicode_wrapped, "0xfallback").unwrap();
    assert_eq!(parsed_unicode.tx_hash, "0xcafe78");
    assert_eq!(parsed_unicode.status, "committed");
    assert_eq!(parsed_unicode.error, None);

    let vertical_wrapped = "〝transactionHash〞：0xCAFE79\n〟status〟：SUCCESS\n〝error〞：NULL\n";
    let parsed_vertical = parse_tx_query_response(vertical_wrapped, "0xfallback").unwrap();
    assert_eq!(parsed_vertical.tx_hash, "0xcafe79");
    assert_eq!(parsed_vertical.status, "committed");
    assert_eq!(parsed_vertical.error, None);
}

#[test]
fn tx_query_parse_kv_accepts_fullwidth_wrapped_inline_tokens() {
    let noisy = "【rpc】 《transactionHash：0xCAFE98》 《status：COMMITTED》 《error：NULL》";
    let parsed = parse_tx_query_response(noisy, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0xcafe98");
    assert_eq!(parsed.status, "committed");
    assert_eq!(parsed.error, None);
}

#[test]
fn tx_query_parse_kv_accepts_quote_wrapped_inline_tokens() {
    let noisy = "[rpc] \"transactionHash\"=0xCAFE97 'status'=COMMITTED `error`=NULL";
    let parsed = parse_tx_query_response(noisy, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0xcafe97");
    assert_eq!(parsed.status, "committed");
    assert_eq!(parsed.error, None);
}

#[test]
fn tx_query_parse_kv_tolerates_unicode_wrapped_status_and_null_error() {
    let kv = "transactionHash：0xBEEF42\nstatus=\u{2068}“SUCCESS！”\u{2069}\nerror=『NULL？』\n";
    let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0xbeef42");
    assert_eq!(parsed.status, "committed");
    assert_eq!(parsed.error, None);
}

#[test]
fn tx_query_parse_kv_tolerates_bidi_wrapped_tx_hash() {
    let kv = "transactionHash=\u{200e}0xBEEF44\u{200f}\nstatus=\u{061c}committed\u{200f}\nerror=null\n";
    let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0xbeef44");
    assert_eq!(parsed.status, "committed");
    assert_eq!(parsed.error, None);
}

#[test]
fn tx_query_parse_kv_tolerates_guillemet_and_lenticular_wrapped_status() {
    let kv = "transactionHash=0xBEEF43\nstatus=«confirmed»\nerror=【null】\n";
    let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0xbeef43");
    assert_eq!(parsed.status, "committed");
    assert_eq!(parsed.error, None);
}

#[test]
fn tx_query_parse_kv_infers_status_from_hyphenated_code_aliases() {
    let tx_code = "tx_hash=0x704\ntx-code=0\n";
    let parsed_tx_code = parse_tx_query_response(tx_code, "0xfallback").unwrap();
    assert_eq!(parsed_tx_code.tx_hash, "0x704");
    assert_eq!(parsed_tx_code.status, "committed");

    let deliver = "tx_hash=0x705\ndeliver-tx-code=19\n";
    let parsed_deliver = parse_tx_query_response(deliver, "0xfallback").unwrap();
    assert_eq!(parsed_deliver.tx_hash, "0x705");
    assert_eq!(parsed_deliver.status, "fail");

    let check = "transaction-hash: 0x706\ncheck-tx-code: \"0\"\n";
    let parsed_check = parse_tx_query_response(check, "0xfallback").unwrap();
    assert_eq!(parsed_check.tx_hash, "0x706");
    assert_eq!(parsed_check.status, "committed");
}
