use super::*;

#[test]
fn backoff_is_capped() {
    assert_eq!(round_change_backoff_ms(0, 5, 40), 0);
    assert_eq!(round_change_backoff_ms(1, 5, 40), 5);
    assert_eq!(round_change_backoff_ms(2, 5, 40), 10);
    assert_eq!(round_change_backoff_ms(3, 5, 40), 20);
    assert_eq!(round_change_backoff_ms(4, 5, 40), 40);
    assert_eq!(round_change_backoff_ms(10, 5, 40), 40);
}
