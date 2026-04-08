use super::*;
#[test]
fn verify_model_output_enforces_trimmed_empty_and_char_limit_boundaries() {
    assert_eq!(
        verify_model_output("   \n\t", 8),
        ("rejected", "empty_output")
    );

    // Zero-width/invisible fillers should not pass verifier checks as meaningful output.
    assert_eq!(
        verify_model_output("\u{200B}\u{200C}\u{FEFF}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{2060}\u{00AD}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{2061}\u{2062}\u{2063}\u{2064}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{2066}\u{2067}\u{2068}\u{2069}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{034F}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{180E}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{200E}\u{200F}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{061C}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{FE0E}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{FE0F}", 8),
        ("rejected", "empty_output")
    );

    // Whitespace + zero-width-only payloads must also be rejected deterministically.
    assert_eq!(
        verify_model_output("\n\u{200B} \t\u{200D}\r\n", 8),
        ("rejected", "empty_output")
    );

    // Control-only payloads should not pass market verification as meaningful content.
    assert_eq!(
        verify_model_output("\u{0007}\u{001B}", 8),
        ("rejected", "empty_output")
    );

    // Control bytes mixed around visible content should be ignored for length accounting.
    assert_eq!(
        verify_model_output("\u{0007}ok\u{001B}", 2),
        ("accepted", "ok")
    );

    // Limit is measured in characters (not bytes) to keep verifier behavior predictable.
    let within = "helloab"; // 4 chars
    assert_eq!(verify_model_output(within, 4), ("accepted", "ok"));

    let over = "helloabc"; // 5 chars
    assert_eq!(
        verify_model_output(over, 4),
        ("rejected", "output_too_long")
    );

    // Leading/trailing transport whitespace should not cause false rejections.
    assert_eq!(verify_model_output(" helloab \n", 4), ("accepted", "ok"));

    // Mixed visible + zero-width should still count as meaningful content.
    assert_eq!(
        verify_model_output("\u{200B}ok\u{200D}", 4),
        ("accepted", "ok")
    );

    // Invisible fillers should not inflate length checks for market verification.
    assert_eq!(
        verify_model_output("\u{200B}ok\u{200D}", 2),
        ("accepted", "ok")
    );
    assert_eq!(verify_model_output("o\u{034F}k", 2), ("accepted", "ok"));

    // Direction/isolation wrappers should not alter verifiable length accounting.
    assert_eq!(
        verify_model_output("\u{2066}ok\u{2069}", 2),
        ("accepted", "ok")
    );
    assert_eq!(
        verify_model_output("\u{2066}ok\u{2069}", 1),
        ("rejected", "output_too_long")
    );

    // ARABIC LETTER MARK wrappers should be treated as invisible fillers as well.
    assert_eq!(
        verify_model_output("\u{061C}ok\u{061C}", 2),
        ("accepted", "ok")
    );
    assert_eq!(
        verify_model_output("\u{061C}ok\u{061C}", 1),
        ("rejected", "output_too_long")
    );

    // ZWJ inside visible emoji sequences should stay deterministic for verifier limits.
    assert_eq!(verify_model_output("👩\u{200D}💻", 2), ("accepted", "ok"));
    assert_eq!(
        verify_model_output("👩\u{200D}💻", 1),
        ("rejected", "output_too_long")
    );
}
