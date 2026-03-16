use super::*;

#[test]
fn market_match_falls_back_to_zero_reputation_when_reputation_file_is_malformed_json() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    assert_match_falls_back_to_price_order_with_invalid_reputation_fixture(
        "{not valid json",
        "m2 malformed reputation fallback",
    );
}

#[test]
fn market_match_falls_back_to_zero_reputation_when_reputation_file_is_valid_json_but_wrong_shape() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    assert_match_falls_back_to_price_order_with_invalid_reputation_fixture(
        "[{\"worker\":\"worker-high\",\"reputation\":900}]",
        "m2 wrong-shape reputation fallback",
    );
}
