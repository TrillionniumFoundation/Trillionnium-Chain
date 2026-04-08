use super::*;

#[test]
fn normalize_market_status_key_collapses_hidden_and_control_separators() {
    assert_eq!(normalize_market_status_key(" matched\u{200b}"), "matched");
    assert_eq!(normalize_market_status_key("mat\u{00ad}ched"), "matched");
    assert_eq!(normalize_market_status_key("open\u{0007}"), "open");
    assert_eq!(
        normalize_market_status_key("\u{feff} matched \u{2060}"),
        "matched"
    );
}
