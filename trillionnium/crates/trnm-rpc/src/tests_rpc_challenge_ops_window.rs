use super::*;

#[test]
fn resolve_ops_window_custom_validation() {
    assert!(resolve_ops_window(Some(OpsWindowArg::Custom), None, Some(1), 10).is_err());
    assert!(resolve_ops_window(Some(OpsWindowArg::Custom), Some(2), Some(1), 10).is_err());
    assert!(resolve_ops_window(
        Some(OpsWindowArg::Custom),
        Some(0),
        Some(OPS_WINDOW_CUSTOM_MAX_MS + 1),
        10
    )
    .is_err());

    let got = resolve_ops_window(Some(OpsWindowArg::H24), None, None, 1_000).unwrap();
    let (from, to, mode) = got.expect("window expected");
    assert_eq!(to, 1_000);
    assert_eq!(mode, "24h");
    assert!(from <= to);
}
