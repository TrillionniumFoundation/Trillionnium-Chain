use super::*;

#[test]
fn aggressive_scan_window_is_clamped_to_prevent_misconfigured_probe_blowups() {
    let _env = env_lock();
    let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "999999");

    assert_eq!(aggr_scan_window(), 4096);
}

#[test]
fn aggressive_scan_window_parses_trimmed_numeric_env_values() {
    let _env = env_lock();
    let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", " 128 ");

    assert_eq!(aggr_scan_window(), 128);
}

#[test]
fn aggressive_scan_window_ignores_zero_and_separator_only_values() {
    let _env = env_lock();

    let _zero = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "0");
    assert_eq!(aggr_scan_window(), 0);
    drop(_zero);

    let _underscores = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "__,,__");
    assert_eq!(aggr_scan_window(), 0);
}

#[test]
fn aggressive_round_robin_seed_parses_trimmed_numeric_env_values() {
    let _env = env_lock();
    let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", " 7 ");

    assert_eq!(aggr_scan_round_robin_seed(), 7);
}

#[test]
fn integer_env_parsers_accept_underscored_numeric_values() {
    let _env = env_lock();
    let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "1_024");
    let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "9_001");
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "3_2");

    assert_eq!(aggr_scan_window(), 1024);
    assert_eq!(aggr_scan_round_robin_seed(), 9001);
    assert_eq!(hot_bucket_count(), 32);
}

#[test]
fn aggressive_scan_window_accepts_comma_grouped_values() {
    let _env = env_lock();
    let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "1,024");

    assert_eq!(aggr_scan_window(), 1024);
}

#[test]
fn aggressive_scan_window_rejects_ambiguous_comma_decimal_values() {
    let _env = env_lock();
    let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "1,5");

    assert_eq!(aggr_scan_window(), 0);
}

#[test]
fn aggressive_round_robin_seed_rejects_ambiguous_comma_decimal_values() {
    let _env = env_lock();
    let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "1,5");

    assert_eq!(aggr_scan_round_robin_seed(), 0);
}

#[test]
fn integer_env_parsers_accept_plus_prefixed_grouped_values() {
    let _env = env_lock();
    let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", " '+1_536' ");
    let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", " '+1_024' ");
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", " '+3_2' ");

    assert_eq!(aggr_scan_window(), 1536);
    assert_eq!(aggr_scan_round_robin_seed(), 1024);
    assert_eq!(hot_bucket_count(), 32);
}

#[test]
fn aggressive_integer_env_parsers_accept_quoted_plus_prefixed_comma_grouped_values() {
    let _env = env_lock();
    let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", " \"+1,024\" ");
    let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", " '+9,001' ");
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", " \"+1,6\" ");

    assert_eq!(aggr_scan_window(), 1024);
    assert_eq!(aggr_scan_round_robin_seed(), 9001);
    assert_eq!(hot_bucket_count(), 16);
}

#[test]
fn aggressive_unsigned_env_knobs_fail_closed_on_negative_values() {
    let _env = env_lock();
    let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "-128");
    let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "'-7'");
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "-32");

    assert_eq!(aggr_scan_window(), 0);
    assert_eq!(aggr_scan_round_robin_seed(), 0);
    assert_eq!(hot_bucket_count(), 8);
}

#[test]
fn aggressive_round_robin_toggle_parser_handles_trimmed_false_and_true_tokens() {
    let _env = env_lock();

    let _off = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " OFF ");
    assert!(!aggr_scan_round_robin_enabled());
    drop(_off);

    let _yes = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " yes ");
    assert!(aggr_scan_round_robin_enabled());
}

#[test]
fn aggressive_round_robin_toggle_parser_accepts_quoted_tokens() {
    let _env = env_lock();

    let _off = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " \"off\" ");
    assert!(!aggr_scan_round_robin_enabled());
    drop(_off);

    let _on = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " \"on\" ");
    assert!(aggr_scan_round_robin_enabled());
}

#[test]
fn aggressive_round_robin_toggle_parser_accepts_single_quoted_tokens() {
    let _env = env_lock();

    let _off = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " 'off' ");
    assert!(!aggr_scan_round_robin_enabled());
    drop(_off);

    let _on = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " 'on' ");
    assert!(aggr_scan_round_robin_enabled());
}

#[test]
fn aggressive_toggle_parsers_accept_quoted_tokens_for_skip_empty_and_deep_scan() {
    let _env = env_lock();

    let _skip_off = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", " \"off\" ");
    assert!(!aggr_skip_empty_stage_checks());
    drop(_skip_off);

    let _skip_on = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", " 'on' ");
    assert!(aggr_skip_empty_stage_checks());
    drop(_skip_on);

    let _deep_off = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", " 'off' ");
    assert!(!aggr_deep_scan_enabled());
    drop(_deep_off);

    let _deep_on = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", " \"on\" ");
    assert!(aggr_deep_scan_enabled());
}

#[test]
fn aggressive_toggle_parsers_accept_quoted_no_tokens() {
    let _env = env_lock();

    let _rr_no = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " \"no\" ");
    assert!(!aggr_scan_round_robin_enabled());
    drop(_rr_no);

    let _deep_no = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", " 'no' ");
    assert!(!aggr_deep_scan_enabled());
    drop(_deep_no);

    let _skip_no = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", " \"no\" ");
    assert!(!aggr_skip_empty_stage_checks());
}

#[test]
fn aggressive_toggle_parsers_fall_back_to_defaults_on_empty_or_separator_only_values() {
    let _env = env_lock();

    let _rr_empty = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", "  ''  ");
    assert!(aggr_scan_round_robin_enabled());
    drop(_rr_empty);

    let _rr_separators = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " __,,__ ");
    assert!(aggr_scan_round_robin_enabled());
    drop(_rr_separators);

    let _deep_empty = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "  \"\"  ");
    assert!(!aggr_deep_scan_enabled());
    drop(_deep_empty);

    let _skip_separators = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", " _,,_ ");
    assert!(aggr_skip_empty_stage_checks());
}
