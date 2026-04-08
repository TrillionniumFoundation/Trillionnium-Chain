use crate::proof_adapter::proof_adapter_core::ProofAdapter;
use crate::proof_adapter::TeeReceiptProofAdapter;

#[test]
fn tee_receipt_adapter_parse_response_requires_auditable_fields() {
    let adapter = TeeReceiptProofAdapter;

    let ok = adapter
        .parse_response(
            "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-1\",\"adapter\":\"tee-receipt\"}",
        )
        .expect("tee receipt payload should parse");
    assert_eq!(ok.provider_request_id.as_deref(), Some("pr-1"));

    let tee_attestation = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2\",\"adapter\":\"tee-attestation\"}",
            )
            .expect("tee attestation alias should parse");
    assert_eq!(tee_attestation.provider_request_id.as_deref(), Some("pr-2"));

    let tee_attestation_underscore = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2b\",\"adapter\":\"TEE_ATTESTATION\"}",
            )
            .expect("tee attestation underscore alias should parse");
    assert_eq!(
        tee_attestation_underscore.provider_request_id.as_deref(),
        Some("pr-2b")
    );

    let tee_compact_alias = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2bb\",\"adapter\":\"teeattestation\"}",
            )
            .expect("tee compact alias should parse");
    assert_eq!(
        tee_compact_alias.provider_request_id.as_deref(),
        Some("pr-2bb")
    );

    let tee_attestation_v1 = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2bc\",\"adapter\":\"TEE_ATTESTATION_V1\"}",
            )
            .expect("tee attestation v1 alias should parse");
    assert_eq!(
        tee_attestation_v1.provider_request_id.as_deref(),
        Some("pr-2bc")
    );

    let tee_with_bom_and_whitespace = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2c\",\"adapter\":\"  \\uFEFFTEE_RECEIPT  \"}",
            )
            .expect("tee receipt label with bom+whitespace should parse");
    assert_eq!(
        tee_with_bom_and_whitespace.provider_request_id.as_deref(),
        Some("pr-2c")
    );

    let tee_with_non_breaking_hyphen = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2d\",\"adapter\":\"TEE‑RECEIPT\"}",
            )
            .expect("tee receipt label with non-breaking hyphen should parse");
    assert_eq!(
        tee_with_non_breaking_hyphen.provider_request_id.as_deref(),
        Some("pr-2d")
    );

    let tee_with_soft_hyphen = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2d0\",\"adapter\":\"TEE\u{00AD}_RECEIPT\"}",
            )
            .expect("tee receipt label with soft hyphen should parse");
    assert_eq!(
        tee_with_soft_hyphen.provider_request_id.as_deref(),
        Some("pr-2d0")
    );

    let tee_with_zero_width_joiner = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2e\",\"adapter\":\"TEE\u{200d}_RECEIPT\"}",
            )
            .expect("tee receipt label with zero-width joiner should parse");
    assert_eq!(
        tee_with_zero_width_joiner.provider_request_id.as_deref(),
        Some("pr-2e")
    );

    let tee_with_directional_isolates = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2e0\",\"adapter\":\"TEE\u{2066}_RECEIPT\u{2069}\"}",
            )
            .expect("tee receipt label with directional isolates should parse");
    assert_eq!(
        tee_with_directional_isolates.provider_request_id.as_deref(),
        Some("pr-2e0")
    );

    let tee_with_left_to_right_mark = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2eaa\",\"adapter\":\"TEE\u{200E}_RECEIPT\"}",
            )
            .expect("tee receipt label with left-to-right mark should parse");
    assert_eq!(
        tee_with_left_to_right_mark.provider_request_id.as_deref(),
        Some("pr-2eaa")
    );

    let tee_with_bidi_override = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2eab\",\"adapter\":\"TEE\u{202E}_RECEIPT\"}",
            )
            .expect("tee receipt label with bidi override should parse");
    assert_eq!(
        tee_with_bidi_override.provider_request_id.as_deref(),
        Some("pr-2eab")
    );

    let tee_with_word_joiner = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2ea\",\"adapter\":\"TEE\u{2060}_RECEIPT\"}",
            )
            .expect("tee receipt label with word joiner should parse");
    assert_eq!(
        tee_with_word_joiner.provider_request_id.as_deref(),
        Some("pr-2ea")
    );

    let tee_with_invisible_times = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2eb\",\"adapter\":\"TEE\u{2062}_RECEIPT\"}",
            )
            .expect("tee receipt label with invisible times should parse");
    assert_eq!(
        tee_with_invisible_times.provider_request_id.as_deref(),
        Some("pr-2eb")
    );

    let tee_with_rtl_mark = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2ec\",\"adapter\":\"TEE\u{200F}_RECEIPT\"}",
            )
            .expect("tee receipt label with rtl mark should parse");
    assert_eq!(
        tee_with_rtl_mark.provider_request_id.as_deref(),
        Some("pr-2ec")
    );

    let tee_with_embedded_bom = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2f\",\"adapter\":\"TEE\u{feff}_RECEIPT\"}",
            )
            .expect("tee receipt label with embedded bom should parse");
    assert_eq!(
        tee_with_embedded_bom.provider_request_id.as_deref(),
        Some("pr-2f")
    );

    let tee_with_space_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2g\",\"adapter\":\"TEE RECEIPT\"}",
            )
            .expect("tee receipt label with space separator should parse");
    assert_eq!(
        tee_with_space_separator.provider_request_id.as_deref(),
        Some("pr-2g")
    );

    let tee_with_colon_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2h\",\"adapter\":\"TEE:RECEIPT\"}",
            )
            .expect("tee receipt label with colon separator should parse");
    assert_eq!(
        tee_with_colon_separator.provider_request_id.as_deref(),
        Some("pr-2h")
    );

    let tee_with_slash_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2i\",\"adapter\":\"TEE/RECEIPT\"}",
            )
            .expect("tee receipt label with slash separator should parse");
    assert_eq!(
        tee_with_slash_separator.provider_request_id.as_deref(),
        Some("pr-2i")
    );

    let tee_with_backslash_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2ib\",\"adapter\":\"TEE\\\\RECEIPT\"}",
            )
            .expect("tee receipt label with backslash separator should parse");
    assert_eq!(
        tee_with_backslash_separator.provider_request_id.as_deref(),
        Some("pr-2ib")
    );

    let tee_with_spaced_separators = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2j\",\"adapter\":\" TEE / RECEIPT \"}",
            )
            .expect("tee receipt label with spaced separators should parse");
    assert_eq!(
        tee_with_spaced_separators.provider_request_id.as_deref(),
        Some("pr-2j")
    );

    let tee_with_nested_quote_wrappers = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2k\",\"adapter\":\" '\\\"TEE_RECEIPT\\\"' \"}",
            )
            .expect("tee receipt label with nested quote wrappers should parse");
    assert_eq!(
        tee_with_nested_quote_wrappers
            .provider_request_id
            .as_deref(),
        Some("pr-2k")
    );

    let missing_request_id = adapter
        .parse_response("{\"output_text\":\"ok\",\"adapter\":\"tee-receipt\"}")
        .expect_err("provider_request_id is required");
    assert_eq!(
        missing_request_id,
        "tee-receipt-missing-provider-request-id"
    );

    let bom_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"\\uFEFF\",\"adapter\":\"tee-receipt\"}",
            )
            .expect_err("bom-only provider_request_id must fail closed");
    assert_eq!(
        bom_only_request_id,
        "tee-receipt-missing-provider-request-id"
    );

    let zero_width_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"\\u200B\\u200D\\u2060\",\"adapter\":\"tee-receipt\"}",
            )
            .expect_err("zero-width-only provider_request_id must fail closed");
    assert_eq!(
        zero_width_only_request_id,
        "tee-receipt-missing-provider-request-id"
    );

    let directional_isolate_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"\\u2066\\u2069\\u180E\",\"adapter\":\"tee-receipt\"}",
            )
            .expect_err("directional-isolate-only provider_request_id must fail closed");
    assert_eq!(
        directional_isolate_only_request_id,
        "tee-receipt-missing-provider-request-id"
    );

    let whitespace_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"   \\n\\t  \",\"adapter\":\"tee-receipt\"}",
            )
            .expect_err("whitespace-only provider_request_id must fail closed");
    assert_eq!(
        whitespace_only_request_id,
        "tee-receipt-missing-provider-request-id"
    );

    let quote_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\" '\\\"\\\"' \",\"adapter\":\"tee-receipt\"}",
            )
            .expect_err("quote-only provider_request_id must fail closed");
    assert_eq!(
        quote_only_request_id,
        "tee-receipt-missing-provider-request-id"
    );

    let missing_adapter = adapter
        .parse_response("{\"output_text\":\"ok\",\"provider_request_id\":\"pr-1\"}")
        .expect_err("adapter label is required");
    assert_eq!(missing_adapter, "tee-receipt-missing-adapter-label");

    let bom_only_adapter = adapter
        .parse_response(
            "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-1x\",\"adapter\":\"\\uFEFF\"}",
        )
        .expect_err("bom-only adapter label must fail closed");
    assert_eq!(bom_only_adapter, "tee-receipt-missing-adapter-label");

    let mismatched_adapter = adapter
        .parse_response(
            "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-1\",\"adapter\":\"zk-receipt\"}",
        )
        .expect_err("mismatched adapter label must fail closed");
    assert_eq!(mismatched_adapter, "tee-receipt-missing-adapter-label");
}
