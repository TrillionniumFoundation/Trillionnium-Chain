use super::*;

#[test]
fn verification_receipt_new_collapses_legacy_receipt_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "Fraud_Proof", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, " tee_receipt ", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "ZK_RECEIPT", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_hyphenated_legacy_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "fraud-proof", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, " tee-receipt ", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "ZK-RECEIPT", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_unicode_dash_legacy_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "fraud—proof", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, " tee–receipt ", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "ZK—RECEIPT", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_horizontal_bar_legacy_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "fraud―proof", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "tee―receipt", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "zk―proof", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_unicode_minus_legacy_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "fraud−proof", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "tee−receipt", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "zk−proof", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_unicode_hyphen_legacy_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "fraud‐proof", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "tee‑receipt", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "zk‐proof", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_space_delimited_legacy_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "Fraud Proof", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, " tee receipt ", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "ZK RECEIPT", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_unicode_whitespace_delimited_aliases_to_router_keys() {
    let tee =
        VerificationReceipt::new(1, "TEE\u{3000}RECEIPT", VerificationResult::Valid, "v", 1);
    let zk = VerificationReceipt::new(2, "ZK\u{00A0}PROOF", VerificationResult::Valid, "v", 2);

    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_zero_width_delimited_aliases_to_router_keys() {
    let tee =
        VerificationReceipt::new(1, "TEE\u{200B}RECEIPT", VerificationResult::Valid, "v", 1);
    let zk = VerificationReceipt::new(
        2,
        "zero\u{FEFF}knowledge\u{200C}proof",
        VerificationResult::Valid,
        "v",
        2,
    );
    let zk_invisible_separator =
        VerificationReceipt::new(3, "ZK\u{2061}PROOF", VerificationResult::Valid, "v", 3);
    let zk_invisible_times =
        VerificationReceipt::new(4, "ZK\u{2062}PROOF", VerificationResult::Valid, "v", 4);
    let tee_invisible_separator =
        VerificationReceipt::new(5, "TEE\u{2063}RECEIPT", VerificationResult::Valid, "v", 5);

    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
    assert_eq!(zk_invisible_separator.proof_type, "zk");
    assert_eq!(zk_invisible_times.proof_type, "zk");
    assert_eq!(tee_invisible_separator.proof_type, "tee");
}

#[test]
fn verification_receipt_new_collapses_legacy_fraud_receipt_aliases_to_router_key() {
    let snake = VerificationReceipt::new(1, "Fraud_Receipt", VerificationResult::Valid, "v", 1);
    let hyphen =
        VerificationReceipt::new(2, " fraud-receipt ", VerificationResult::Valid, "v", 2);
    let space = VerificationReceipt::new(3, "FRAUD RECEIPT", VerificationResult::Valid, "v", 3);

    assert_eq!(snake.proof_type, "fraud");
    assert_eq!(hyphen.proof_type, "fraud");
    assert_eq!(space.proof_type, "fraud");
}

#[test]
fn verification_receipt_new_collapses_fraud_challenge_aliases_to_router_key() {
    let bare =
        VerificationReceipt::new(1, "Fraud Challenge", VerificationResult::Valid, "v", 1);
    let snake =
        VerificationReceipt::new(2, "fraud_challenge_v2", VerificationResult::Valid, "v", 2);
    let compact =
        VerificationReceipt::new(3, "fraudchallengev3", VerificationResult::Valid, "v", 3);

    assert_eq!(bare.proof_type, "fraud");
    assert_eq!(snake.proof_type, "fraud");
    assert_eq!(compact.proof_type, "fraud");
}

#[test]
fn verification_receipt_new_collapses_legacy_tee_zk_proof_aliases_to_router_keys() {
    let tee_snake = VerificationReceipt::new(1, "TEE_PROOF", VerificationResult::Valid, "v", 1);
    let tee_hyphen =
        VerificationReceipt::new(2, " tee-proof ", VerificationResult::Valid, "v", 2);
    let tee_space = VerificationReceipt::new(3, "tee proof", VerificationResult::Valid, "v", 3);

    let zk_snake = VerificationReceipt::new(4, "ZK_PROOF", VerificationResult::Valid, "v", 4);
    let zk_hyphen =
        VerificationReceipt::new(5, " zk-proof ", VerificationResult::Valid, "v", 5);
    let zk_space = VerificationReceipt::new(6, "zk proof", VerificationResult::Valid, "v", 6);

    assert_eq!(tee_snake.proof_type, "tee");
    assert_eq!(tee_hyphen.proof_type, "tee");
    assert_eq!(tee_space.proof_type, "tee");

    assert_eq!(zk_snake.proof_type, "zk");
    assert_eq!(zk_hyphen.proof_type, "zk");
    assert_eq!(zk_space.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_version_suffixed_legacy_aliases_to_router_keys() {
    let fraud =
        VerificationReceipt::new(1, "fraud_receipt_v3", VerificationResult::Valid, "v", 1);
    let fraud_proof_v3 =
        VerificationReceipt::new(2, "Fraud-Proof-V_3", VerificationResult::Valid, "v", 2);
    let tee = VerificationReceipt::new(3, "TEE-PROOF-V1", VerificationResult::Valid, "v", 2);
    let tee_v3 =
        VerificationReceipt::new(3, "tee receipt v 3", VerificationResult::Valid, "v", 3);
    let tee_proof_v3 =
        VerificationReceipt::new(4, "TEE_PROOF_V_3", VerificationResult::Valid, "v", 4);
    let zk = VerificationReceipt::new(5, "zk receipt v3", VerificationResult::Valid, "v", 5);
    let zk_proof_v3 =
        VerificationReceipt::new(6, "zk-proof-v-3", VerificationResult::Valid, "v", 6);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(fraud_proof_v3.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(tee_v3.proof_type, "tee");
    assert_eq!(tee_proof_v3.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
    assert_eq!(zk_proof_v3.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_repeated_separator_aliases_to_router_keys() {
    let fraud =
        VerificationReceipt::new(1, "FRAUD__RECEIPT", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "tee---proof", VerificationResult::Valid, "v", 2);
    let zk =
        VerificationReceipt::new(3, "zk\t\n  __--receipt", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_slash_dot_colon_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "fraud/receipt", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "TEE:PROOF", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "zk.receipt", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_plus_delimited_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "fraud+proof", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "TEE+RECEIPT", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "zk+receipt", VerificationResult::Valid, "v", 3);
    let tee_fullwidth =
        VerificationReceipt::new(4, "TEE＋RECEIPT", VerificationResult::Valid, "v", 4);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
    assert_eq!(tee_fullwidth.proof_type, "tee");
}

#[test]
fn verification_receipt_new_collapses_extended_registry_delimiters_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "fraud|receipt", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "TEE\\PROOF", VerificationResult::Valid, "v", 2);
    let tee_fullwidth =
        VerificationReceipt::new(3, "TEE＼PROOF", VerificationResult::Valid, "v", 3);
    let zk = VerificationReceipt::new(4, "zk@receipt", VerificationResult::Valid, "v", 4);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(tee_fullwidth.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_fullwidth_pipe_aliases_to_router_keys() {
    let fraud =
        VerificationReceipt::new(1, "fraud｜receipt", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "TEE｜PROOF", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "zk｜attestation", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_fullwidth_comma_and_semicolon_aliases() {
    let tee = VerificationReceipt::new(1, "TEE，RECEIPT", VerificationResult::Valid, "v", 1);
    let zk = VerificationReceipt::new(2, "ZK；PROOF", VerificationResult::Valid, "v", 2);
    let fraud =
        VerificationReceipt::new(3, "FRAUD、RECEIPT", VerificationResult::Valid, "v", 3);

    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
    assert_eq!(fraud.proof_type, "fraud");
}

#[test]
fn verification_receipt_new_collapses_cjk_full_stop_aliases_to_router_keys() {
    let fraud =
        VerificationReceipt::new(1, "FRAUD。RECEIPT", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "TEE。PROOF", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "ZK。RECEIPT", VerificationResult::Valid, "v", 3);
    let tee_fullwidth_dot =
        VerificationReceipt::new(4, "TEE．RECEIPT", VerificationResult::Valid, "v", 4);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
    assert_eq!(tee_fullwidth_dot.proof_type, "tee");
}

#[test]
fn verification_receipt_new_collapses_middle_dot_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "fraud·receipt", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "TEE・PROOF", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "zk∙attestation", VerificationResult::Valid, "v", 3);
    let zk_dot_operator =
        VerificationReceipt::new(4, "zk⋅proof", VerificationResult::Valid, "v", 4);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
    assert_eq!(zk_dot_operator.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_ampersand_delimited_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "fraud&proof", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "TEE&RECEIPT", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "zk&attestation", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_punctuation_wrapped_aliases_to_router_keys() {
    let fraud =
        VerificationReceipt::new(1, "?!fraud?!receipt!?", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "!!TEE??PROOF!!", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "??zk!!receipt??", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_fullwidth_punctuation_wrapped_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(
        1,
        "？！fraud？！receipt！？",
        VerificationResult::Valid,
        "v",
        1,
    );
    let tee =
        VerificationReceipt::new(2, "！！TEE？？PROOF！！", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(
        3,
        "？？zk！！receipt？？",
        VerificationResult::Valid,
        "v",
        3,
    );

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_registry_parenthesis_quote_aliases_to_router_keys() {
    let fraud =
        VerificationReceipt::new(1, "(FRAUD'RECEIPT')", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "\"TEE\"[QUOTE]", VerificationResult::Valid, "v", 2);
    let zk =
        VerificationReceipt::new(3, "<zk>{attestation}", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_compact_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "fraudproof", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "teereceipt", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "zkattestation", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_glued_tee_receipt_version_aliases_to_router_key() {
    let v1 = VerificationReceipt::new(1, "TEE_RECEIPTV1", VerificationResult::Valid, "v", 1);
    let v2 = VerificationReceipt::new(2, "tee receiptv2", VerificationResult::Valid, "v", 2);
    let v3 = VerificationReceipt::new(3, "tee-receiptv3", VerificationResult::Valid, "v", 3);

    assert_eq!(v1.proof_type, "tee");
    assert_eq!(v2.proof_type, "tee");
    assert_eq!(v3.proof_type, "tee");
}

#[test]
fn verification_receipt_new_collapses_glued_fraud_and_zk_receipt_version_aliases_to_router_keys() {
    let fraud_v1 =
        VerificationReceipt::new(1, "fraud receiptv1", VerificationResult::Valid, "v", 1);
    let fraud_v2 =
        VerificationReceipt::new(2, "fraud-receiptv2", VerificationResult::Valid, "v", 2);
    let zk_v1 = VerificationReceipt::new(3, "zk receiptv1", VerificationResult::Valid, "v", 3);
    let zk_v3 = VerificationReceipt::new(4, "zk-receiptv3", VerificationResult::Valid, "v", 4);

    assert_eq!(fraud_v1.proof_type, "fraud");
    assert_eq!(fraud_v2.proof_type, "fraud");
    assert_eq!(zk_v1.proof_type, "zk");
    assert_eq!(zk_v3.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_percent_star_tilde_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "fraud%receipt", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "TEE*PROOF", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "zk~attestation", VerificationResult::Valid, "v", 3);
    let tee_fullwidth =
        VerificationReceipt::new(4, "TEE～RECEIPT", VerificationResult::Valid, "v", 4);
    let zk_wave_dash =
        VerificationReceipt::new(5, "zk〜proof", VerificationResult::Valid, "v", 5);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
    assert_eq!(tee_fullwidth.proof_type, "tee");
    assert_eq!(zk_wave_dash.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_caret_delimited_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "fraud^receipt", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "TEE^PROOF", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "zk^attestation", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_dollar_delimited_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "fraud$receipt", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "tee$proof", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "zk$attestation", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_backtick_delimited_aliases_to_router_keys() {
    let fraud = VerificationReceipt::new(1, "fraud`receipt", VerificationResult::Valid, "v", 1);
    let tee = VerificationReceipt::new(2, "TEE`PROOF", VerificationResult::Valid, "v", 2);
    let zk = VerificationReceipt::new(3, "zk`attestation", VerificationResult::Valid, "v", 3);

    assert_eq!(fraud.proof_type, "fraud");
    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_normalizes_custom_plugin_keys_like_registry() {
    let receipt = VerificationReceipt::new(
        11,
        "  MY__CUSTOM--PROOF  ",
        VerificationResult::Valid,
        "v",
        11,
    );

    assert_eq!(receipt.proof_type, "my custom proof");
}

#[test]
fn verification_receipt_new_collapses_fraction_slash_aliases_to_router_keys() {
    let tee = VerificationReceipt::new(1, "TEE⁄QUOTE", VerificationResult::Valid, "v", 1);
    let zk = VerificationReceipt::new(2, "zk⁄receipt", VerificationResult::Valid, "v", 2);

    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_snark_alias_to_zk_router_key() {
    let zk = VerificationReceipt::new(5, "snark", VerificationResult::Valid, "v", 5);

    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_fullwidth_brackets_and_smart_quotes_aliases() {
    let tee =
        VerificationReceipt::new(1, "“TEE（RECEIPT）”", VerificationResult::Valid, "v", 1);
    let zk = VerificationReceipt::new(2, "‘ZK｛PROOF｝’", VerificationResult::Valid, "v", 2);

    assert_eq!(tee.proof_type, "tee");
    assert_eq!(zk.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_registry_dash_variants_to_router_keys() {
    let figure_dash =
        VerificationReceipt::new(1, "TEE‒RECEIPT", VerificationResult::Valid, "v", 1);
    let small_em_dash =
        VerificationReceipt::new(2, "TEE﹘RECEIPT", VerificationResult::Valid, "v", 2);

    assert_eq!(figure_dash.proof_type, "tee");
    assert_eq!(small_em_dash.proof_type, "tee");
}
