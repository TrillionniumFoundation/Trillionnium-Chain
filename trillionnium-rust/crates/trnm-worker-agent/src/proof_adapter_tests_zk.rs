use crate::proof_adapter::proof_adapter_core::ProofAdapter;
use crate::proof_adapter::ZkReceiptProofAdapter;

#[test]
fn zk_receipt_adapter_parse_response_requires_auditable_fields() {
    let adapter = ZkReceiptProofAdapter;

    let ok = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-1\",\"adapter\":\"zk-receipt\"}",
            )
            .expect("zk receipt payload should parse");
    assert_eq!(ok.provider_request_id.as_deref(), Some("pr-zk-1"));

    let zk_proof_alias = adapter
        .parse_response(
            "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2\",\"adapter\":\"zk-proof\"}",
        )
        .expect("zk proof alias should parse");
    assert_eq!(
        zk_proof_alias.provider_request_id.as_deref(),
        Some("pr-zk-2")
    );

    let zk_proof_underscore_alias = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2b\",\"adapter\":\"ZK_PROOF\"}",
            )
            .expect("zk proof underscore alias should parse");
    assert_eq!(
        zk_proof_underscore_alias.provider_request_id.as_deref(),
        Some("pr-zk-2b")
    );

    let zk_proof_v1_alias = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2ba\",\"adapter\":\"ZK_PROOF_V1\"}",
            )
            .expect("zk proof v1 underscore alias should parse");
    assert_eq!(
        zk_proof_v1_alias.provider_request_id.as_deref(),
        Some("pr-zk-2ba")
    );

    let zk_compact_alias = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2bb\",\"adapter\":\"zkproof\"}",
            )
            .expect("zk compact alias should parse");
    assert_eq!(
        zk_compact_alias.provider_request_id.as_deref(),
        Some("pr-zk-2bb")
    );

    let zk_compact_v1_alias = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2bc\",\"adapter\":\"zkproofv1\"}",
            )
            .expect("zk compact v1 alias should parse");
    assert_eq!(
        zk_compact_v1_alias.provider_request_id.as_deref(),
        Some("pr-zk-2bc")
    );

    let zk_with_bom_and_whitespace = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2c\",\"adapter\":\"  \\uFEFFZK_RECEIPT  \"}",
            )
            .expect("zk receipt label with bom+whitespace should parse");
    assert_eq!(
        zk_with_bom_and_whitespace.provider_request_id.as_deref(),
        Some("pr-zk-2c")
    );

    let zk_with_non_breaking_hyphen = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2d\",\"adapter\":\"ZK‑RECEIPT\"}",
            )
            .expect("zk receipt label with non-breaking hyphen should parse");
    assert_eq!(
        zk_with_non_breaking_hyphen.provider_request_id.as_deref(),
        Some("pr-zk-2d")
    );

    let zk_with_combining_grapheme_joiner = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2d0\",\"adapter\":\"ZK\u{034F}_RECEIPT\"}",
            )
            .expect("zk receipt label with combining grapheme joiner should parse");
    assert_eq!(
        zk_with_combining_grapheme_joiner
            .provider_request_id
            .as_deref(),
        Some("pr-zk-2d0")
    );

    let zk_with_zero_width_joiner = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2e\",\"adapter\":\"ZK\u{200d}_RECEIPT\"}",
            )
            .expect("zk receipt label with zero-width joiner should parse");
    assert_eq!(
        zk_with_zero_width_joiner.provider_request_id.as_deref(),
        Some("pr-zk-2e")
    );

    let zk_with_directional_isolates = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2e0\",\"adapter\":\"ZK\u{2066}_RECEIPT\u{2069}\"}",
            )
            .expect("zk receipt label with directional isolates should parse");
    assert_eq!(
        zk_with_directional_isolates.provider_request_id.as_deref(),
        Some("pr-zk-2e0")
    );

    let zk_with_invisible_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2eaa\",\"adapter\":\"ZK\u{2063}_RECEIPT\"}",
            )
            .expect("zk receipt label with invisible separator should parse");
    assert_eq!(
        zk_with_invisible_separator.provider_request_id.as_deref(),
        Some("pr-zk-2eaa")
    );

    let zk_with_bidi_embedding = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2eab\",\"adapter\":\"ZK\u{202A}_RECEIPT\"}",
            )
            .expect("zk receipt label with bidi embedding should parse");
    assert_eq!(
        zk_with_bidi_embedding.provider_request_id.as_deref(),
        Some("pr-zk-2eab")
    );

    let zk_with_word_joiner = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2ea\",\"adapter\":\"ZK\u{2060}_RECEIPT\"}",
            )
            .expect("zk receipt label with word joiner should parse");
    assert_eq!(
        zk_with_word_joiner.provider_request_id.as_deref(),
        Some("pr-zk-2ea")
    );

    let zk_with_invisible_plus = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2eb\",\"adapter\":\"ZK\u{2064}_RECEIPT\"}",
            )
            .expect("zk receipt label with invisible plus should parse");
    assert_eq!(
        zk_with_invisible_plus.provider_request_id.as_deref(),
        Some("pr-zk-2eb")
    );

    let zk_with_arabic_letter_mark = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2ec\",\"adapter\":\"ZK\u{061C}_RECEIPT\"}",
            )
            .expect("zk receipt label with arabic letter mark should parse");
    assert_eq!(
        zk_with_arabic_letter_mark.provider_request_id.as_deref(),
        Some("pr-zk-2ec")
    );

    let zk_with_embedded_bom = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2f\",\"adapter\":\"ZK\u{feff}_RECEIPT\"}",
            )
            .expect("zk receipt label with embedded bom should parse");
    assert_eq!(
        zk_with_embedded_bom.provider_request_id.as_deref(),
        Some("pr-zk-2f")
    );

    let zk_with_space_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2g\",\"adapter\":\"ZK RECEIPT\"}",
            )
            .expect("zk receipt label with space separator should parse");
    assert_eq!(
        zk_with_space_separator.provider_request_id.as_deref(),
        Some("pr-zk-2g")
    );

    let zk_with_slash_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2h\",\"adapter\":\"ZK/RECEIPT\"}",
            )
            .expect("zk receipt label with slash separator should parse");
    assert_eq!(
        zk_with_slash_separator.provider_request_id.as_deref(),
        Some("pr-zk-2h")
    );

    let zk_with_colon_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2i\",\"adapter\":\"ZK:RECEIPT\"}",
            )
            .expect("zk receipt label with colon separator should parse");
    assert_eq!(
        zk_with_colon_separator.provider_request_id.as_deref(),
        Some("pr-zk-2i")
    );

    let zk_with_backslash_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2ib\",\"adapter\":\"ZK\\\\RECEIPT\"}",
            )
            .expect("zk receipt label with backslash separator should parse");
    assert_eq!(
        zk_with_backslash_separator.provider_request_id.as_deref(),
        Some("pr-zk-2ib")
    );

    let zk_with_spaced_separators = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2j\",\"adapter\":\" ZK - RECEIPT \"}",
            )
            .expect("zk receipt label with spaced separators should parse");
    assert_eq!(
        zk_with_spaced_separators.provider_request_id.as_deref(),
        Some("pr-zk-2j")
    );

    let zk_with_nested_quote_wrappers = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2ic\",\"adapter\":\" '\\\"ZK_RECEIPT\\\"' \"}",
            )
            .expect("zk receipt label with nested quote wrappers should parse");
    assert_eq!(
        zk_with_nested_quote_wrappers.provider_request_id.as_deref(),
        Some("pr-zk-2ic")
    );

    let missing_request_id = adapter
        .parse_response("{\"output_text\":\"ok\",\"adapter\":\"zk-receipt\"}")
        .expect_err("provider_request_id is required");
    assert_eq!(missing_request_id, "zk-receipt-missing-provider-request-id");

    let bom_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"\\uFEFF\",\"adapter\":\"zk-receipt\"}",
            )
            .expect_err("bom-only provider_request_id must fail closed");
    assert_eq!(
        bom_only_request_id,
        "zk-receipt-missing-provider-request-id"
    );

    let zero_width_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"\\u200B\\u200D\\u2060\",\"adapter\":\"zk-receipt\"}",
            )
            .expect_err("zero-width-only provider_request_id must fail closed");
    assert_eq!(
        zero_width_only_request_id,
        "zk-receipt-missing-provider-request-id"
    );

    let directional_isolate_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"\\u2066\\u2069\\u180E\",\"adapter\":\"zk-receipt\"}",
            )
            .expect_err("directional-isolate-only provider_request_id must fail closed");
    assert_eq!(
        directional_isolate_only_request_id,
        "zk-receipt-missing-provider-request-id"
    );

    let whitespace_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"   \\n\\t  \",\"adapter\":\"zk-receipt\"}",
            )
            .expect_err("whitespace-only provider_request_id must fail closed");
    assert_eq!(
        whitespace_only_request_id,
        "zk-receipt-missing-provider-request-id"
    );

    let quote_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\" '\\\"\\\"' \",\"adapter\":\"zk-receipt\"}",
            )
            .expect_err("quote-only provider_request_id must fail closed");
    assert_eq!(
        quote_only_request_id,
        "zk-receipt-missing-provider-request-id"
    );

    let missing_adapter = adapter
        .parse_response("{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-3\"}")
        .expect_err("adapter label is required");
    assert_eq!(missing_adapter, "zk-receipt-missing-adapter-label");

    let bom_only_adapter = adapter
        .parse_response(
            "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-3x\",\"adapter\":\"\\uFEFF\"}",
        )
        .expect_err("bom-only adapter label must fail closed");
    assert_eq!(bom_only_adapter, "zk-receipt-missing-adapter-label");

    let mismatched_adapter = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-4\",\"adapter\":\"tee-receipt\"}",
            )
            .expect_err("mismatched adapter label must fail closed");
    assert_eq!(mismatched_adapter, "zk-receipt-missing-adapter-label");
}
