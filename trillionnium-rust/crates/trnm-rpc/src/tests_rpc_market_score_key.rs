use super::*;

#[test]
fn market_worker_tie_break_key_normalizes_case_and_whitespace() {
    assert_eq!(market_worker_tie_break_key(" Worker-A "), "worker-a");
    assert_eq!(market_worker_tie_break_key("worker-Z"), "worker-z");
}
