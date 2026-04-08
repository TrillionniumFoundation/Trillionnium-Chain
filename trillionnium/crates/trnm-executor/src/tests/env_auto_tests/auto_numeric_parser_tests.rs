use super::*;

#[test]
fn auto_threshold_env_parsers_accept_trimmed_numeric_values() {
    let _env = env_lock();
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", " 0.35 ");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " 0.12 ");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", " 0.018 ");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " 0.03 ");

    assert!((auto_hot_streak_threshold() - 0.35).abs() < f64::EPSILON);
    assert!((auto_reorder_min_margin() - 0.12).abs() < f64::EPSILON);
    assert!((auto_reorder_min_hot_key_share() - 0.018).abs() < f64::EPSILON);
    assert!((auto_min_expected_gain_score() - 0.03).abs() < f64::EPSILON);
}

#[test]
fn auto_threshold_env_parsers_accept_grouped_numeric_values() {
    let _env = env_lock();
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.2_5");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0,1");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0_125");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0,0_5");

    assert!((auto_hot_streak_threshold() - 0.25).abs() < f64::EPSILON);
    assert!((auto_reorder_min_margin() - 0.1).abs() < f64::EPSILON);
    assert!((auto_reorder_min_hot_key_share() - 0.0125).abs() < f64::EPSILON);
    assert!((auto_min_expected_gain_score() - 0.05).abs() < f64::EPSILON);
}

#[test]
fn hot_bucket_count_parser_accepts_trimmed_numeric_values() {
    let _env = env_lock();
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", " 16 ");

    assert_eq!(hot_bucket_count(), 16);
}

#[test]
fn hot_bucket_count_parser_accepts_grouped_numeric_values() {
    let _env = env_lock();
    let _underscored = EnvGuard::set("TRNM_HOT_BUCKETS", " 6_4 ");
    assert_eq!(hot_bucket_count(), 64);
    drop(_underscored);

    let _comma_grouped = EnvGuard::set("TRNM_HOT_BUCKETS", " 1,6 ");
    assert_eq!(hot_bucket_count(), 16);
}

#[test]
fn hot_bucket_count_is_clamped_to_safe_bounds() {
    let _env = env_lock();

    let _low = EnvGuard::set("TRNM_HOT_BUCKETS", "0");
    assert_eq!(hot_bucket_count(), 4);
    drop(_low);

    let _high = EnvGuard::set("TRNM_HOT_BUCKETS", "999");
    assert_eq!(hot_bucket_count(), 64);
}

#[test]
fn auto_adaptive_numeric_env_parser_accepts_quoted_values() {
    let _env = env_lock();

    let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "\"1_024\"");
    let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "'9_001'");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "\"0.2_5\"");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "'0.1'");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "\"0.0_125\"");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "'0.05'");
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "\"1,6\"");
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "'2_048'");
    let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "\"1_024\"");

    assert_eq!(aggr_scan_window(), 1024);
    assert_eq!(aggr_scan_round_robin_seed(), 9001);
    assert_eq!(auto_hot_streak_threshold(), 0.25);
    assert_eq!(auto_reorder_min_margin(), 0.1);
    assert_eq!(auto_reorder_min_hot_key_share(), 0.0125);
    assert_eq!(auto_min_expected_gain_score(), 0.05);
    assert_eq!(hot_bucket_count(), 16);
    assert_eq!(auto_adaptive_min_batch_len(), 2048);
    assert_eq!(auto_adaptive_sample_len(5000), 1024);
}

#[test]
fn auto_adaptive_numeric_env_parser_accepts_plus_prefixed_values() {
    let _env = env_lock();

    let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", " +1_024 ");
    let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", " '+9_001' ");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", " +0.2_5 ");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " '+0.1' ");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", " +0.0_125 ");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " '+0.05' ");
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", " '+1,6' ");
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", " '+1_024' ");
    let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " '+0' ");

    assert_eq!(aggr_scan_window(), 1024);
    assert_eq!(aggr_scan_round_robin_seed(), 9001);
    assert_eq!(auto_hot_streak_threshold(), 0.25);
    assert_eq!(auto_reorder_min_margin(), 0.1);
    assert_eq!(auto_reorder_min_hot_key_share(), 0.0125);
    assert_eq!(auto_min_expected_gain_score(), 0.05);
    assert_eq!(hot_bucket_count(), 16);
    assert_eq!(auto_adaptive_min_batch_len(), 1024);
    assert_eq!(auto_adaptive_sample_len(5000), 64);
}

#[test]
fn grouped_integer_env_parsers_accept_quoted_comma_grouped_values() {
    let _env = env_lock();

    let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", " \"1,024\" ");
    let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", " '9,001' ");
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", " \"1,6\" ");
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", " '2,048' ");
    let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " \"1,536\" ");

    assert_eq!(aggr_scan_window(), 1024);
    assert_eq!(aggr_scan_round_robin_seed(), 9001);
    assert_eq!(hot_bucket_count(), 16);
    assert_eq!(auto_adaptive_min_batch_len(), 2048);
    assert_eq!(auto_adaptive_sample_len(5000), 1536);
    assert_eq!(auto_adaptive_sample_len(1400), 1400);
}

#[test]
fn auto_adaptive_numeric_env_parser_accepts_percent_suffix_for_ratio_knobs() {
    let _env = env_lock();

    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "25%");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " 10% ");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "'1.25%' ");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " \"5%\" ");

    assert_eq!(auto_hot_streak_threshold(), 0.25);
    assert_eq!(auto_reorder_min_margin(), 0.1);
    assert_eq!(auto_reorder_min_hot_key_share(), 0.0125);
    assert_eq!(auto_min_expected_gain_score(), 0.05);
}

#[test]
fn auto_adaptive_numeric_env_parser_accepts_comma_decimal_percent_values() {
    let _env = env_lock();

    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "25,5%");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " '10,5%' ");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "\"1,25%\"");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " 0,5% ");

    assert_eq!(auto_hot_streak_threshold(), 0.255);
    assert_eq!(auto_reorder_min_margin(), 0.105);
    assert_eq!(auto_reorder_min_hot_key_share(), 0.0125);
    assert_eq!(auto_min_expected_gain_score(), 0.005);
}

#[test]
fn auto_adaptive_numeric_env_parser_accepts_quoted_plus_prefixed_comma_decimal_percent_values() {
    let _env = env_lock();

    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", " '+25,5%' ");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " \"+10,5%\" ");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", " '+1,25%' ");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " \"+0,5%\" ");

    assert_eq!(auto_hot_streak_threshold(), 0.255);
    assert_eq!(auto_reorder_min_margin(), 0.105);
    assert_eq!(auto_reorder_min_hot_key_share(), 0.0125);
    assert_eq!(auto_min_expected_gain_score(), 0.005);
}

#[test]
fn auto_adaptive_numeric_env_parser_accepts_grouped_comma_decimal_percent_values() {
    let _env = env_lock();

    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", " '+2_5,5%' ");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " \"+1_0,5%\" ");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", " '+1,2_5%' ");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " \"+0,5_0%\" ");

    assert_eq!(auto_hot_streak_threshold(), 0.255);
    assert_eq!(auto_reorder_min_margin(), 0.105);
    assert_eq!(auto_reorder_min_hot_key_share(), 0.0125);
    assert_eq!(auto_min_expected_gain_score(), 0.005);
}

#[test]
fn auto_adaptive_numeric_env_parser_treats_zero_whole_comma_values_as_decimals() {
    let _env = env_lock();

    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0,250");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " '+0,125' ");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "\"0,375\"");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " '0,050' ");

    assert_eq!(auto_hot_streak_threshold(), 0.25);
    assert_eq!(auto_reorder_min_margin(), 0.125);
    assert_eq!(auto_reorder_min_hot_key_share(), 0.375);
    assert_eq!(auto_min_expected_gain_score(), 0.05);
}

#[test]
fn auto_adaptive_numeric_env_parser_treats_all_zero_whole_comma_values_as_decimals() {
    let _env = env_lock();

    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "000,250");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " '+000,125' ");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "\"000,375\"");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " '000,050' ");

    assert_eq!(auto_hot_streak_threshold(), 0.25);
    assert_eq!(auto_reorder_min_margin(), 0.125);
    assert_eq!(auto_reorder_min_hot_key_share(), 0.375);
    assert_eq!(auto_min_expected_gain_score(), 0.05);
}

#[test]
fn auto_adaptive_numeric_env_parser_treats_leading_comma_values_as_decimals() {
    let _env = env_lock();

    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", ",250");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " '+,125' ");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "\",375\"");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " '-,050' ");

    assert_eq!(auto_hot_streak_threshold(), 0.25);
    assert_eq!(auto_reorder_min_margin(), 0.125);
    assert_eq!(auto_reorder_min_hot_key_share(), 0.375);
    assert_eq!(auto_min_expected_gain_score(), 0.0);
}

#[test]
fn auto_adaptive_numeric_env_parser_treats_leading_comma_percent_values_as_decimals() {
    let _env = env_lock();

    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", ",25%");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " '+,5%' ");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "\",75%\"");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " '-,5%' ");

    assert_eq!(auto_hot_streak_threshold(), 0.0025);
    assert_eq!(auto_reorder_min_margin(), 0.005);
    assert_eq!(auto_reorder_min_hot_key_share(), 0.0075);
    assert_eq!(auto_min_expected_gain_score(), 0.0);
}

#[test]
fn auto_adaptive_numeric_env_parser_accepts_quoted_plus_prefixed_leading_comma_percent_values_with_grouping() {
    let _env = env_lock();

    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", " '+,2_5%' ");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " \"+,5_0%\" ");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", " '+,7_5%' ");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " \"+,2_5%\" ");

    assert_eq!(auto_hot_streak_threshold(), 0.0025);
    assert_eq!(auto_reorder_min_margin(), 0.005);
    assert_eq!(auto_reorder_min_hot_key_share(), 0.0075);
    assert_eq!(auto_min_expected_gain_score(), 0.0025);
}

#[test]
fn auto_adaptive_numeric_env_parser_falls_back_to_defaults_on_invalid_values() {
    let _env = env_lock();

    let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "not-a-number");
    let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "seed??");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "NaN%");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "margin");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "share");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "gain");
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "bucket-count");
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "batch??");

    assert_eq!(aggr_scan_window(), 0);
    assert_eq!(aggr_scan_round_robin_seed(), 0);
    assert_eq!(auto_hot_streak_threshold(), 0.22);
    assert_eq!(auto_reorder_min_margin(), 0.04);
    assert_eq!(auto_reorder_min_hot_key_share(), 0.0075);
    assert_eq!(auto_min_expected_gain_score(), 0.01);
    assert_eq!(hot_bucket_count(), 8);
    assert_eq!(auto_adaptive_min_batch_len(), 512);
}

#[test]
fn auto_adaptive_numeric_env_parser_rejects_ambiguous_multi_comma_ratio_values() {
    let _env = env_lock();

    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0,2,5");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "'+0,1,0'");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "1,2,5%");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "\"0,0,5\"");

    assert_eq!(auto_hot_streak_threshold(), 0.22);
    assert_eq!(auto_reorder_min_margin(), 0.04);
    assert_eq!(auto_reorder_min_hot_key_share(), 0.0075);
    assert_eq!(auto_min_expected_gain_score(), 0.01);
}

#[test]
fn auto_adaptive_min_batch_len_rejects_ambiguous_grouped_comma_values() {
    let _env = env_lock();

    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "'+5,1,2'");

    assert_eq!(auto_adaptive_min_batch_len(), 512);
}

#[test]
fn auto_adaptive_sample_len_rejects_ambiguous_grouped_comma_values() {
    let _env = env_lock();

    let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "'+1,5,3,6'");

    assert_eq!(auto_adaptive_sample_len(5000), 2048);
    assert_eq!(auto_adaptive_sample_len(128), 128);
}

#[test]
fn auto_adaptive_numeric_env_parser_ignores_empty_or_separator_only_values() {
    let _env = env_lock();

    let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "   ");
    let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "__,,__");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", " '' ");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " \"\" ");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", " _,_ ");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " '__,,__' ");
    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", " \"_,,\" ");
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", " '__,,__' ");

    assert_eq!(aggr_scan_window(), 0);
    assert_eq!(aggr_scan_round_robin_seed(), 0);
    assert_eq!(auto_hot_streak_threshold(), 0.22);
    assert_eq!(auto_reorder_min_margin(), 0.04);
    assert_eq!(auto_reorder_min_hot_key_share(), 0.0075);
    assert_eq!(auto_min_expected_gain_score(), 0.01);
    assert_eq!(hot_bucket_count(), 8);
    assert_eq!(auto_adaptive_min_batch_len(), 512);
}

#[test]
fn auto_adaptive_ratio_knobs_are_clamped_to_safe_bounds() {
    let _env = env_lock();

    let _streak_low = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "-25%");
    let _margin_low = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "-0.5");
    let _share_low = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "-1");
    let _gain_low = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "-2%");

    assert_eq!(auto_hot_streak_threshold(), 0.0);
    assert_eq!(auto_reorder_min_margin(), 0.0);
    assert_eq!(auto_reorder_min_hot_key_share(), 0.0);
    assert_eq!(auto_min_expected_gain_score(), 0.0);

    drop(_streak_low);
    drop(_margin_low);
    drop(_share_low);
    drop(_gain_low);

    let _streak_high = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "250%");
    let _margin_high = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "5");
    let _share_high = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "125%");
    let _gain_high = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "3.5");

    assert_eq!(auto_hot_streak_threshold(), 1.0);
    assert_eq!(auto_reorder_min_margin(), 1.0);
    assert_eq!(auto_reorder_min_hot_key_share(), 1.0);
    assert_eq!(auto_min_expected_gain_score(), 1.0);
}

#[test]
fn auto_adaptive_min_batch_len_is_clamped_to_safe_bounds() {
    let _env = env_lock();

    let _low = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "8");
    assert_eq!(auto_adaptive_min_batch_len(), 64);
    drop(_low);

    let _high = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "99999");
    assert_eq!(auto_adaptive_min_batch_len(), 4096);
}

#[test]
fn auto_adaptive_sample_len_is_env_tunable_and_clamped() {
    let _env = env_lock();

    let _default = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "batch??");
    assert_eq!(auto_adaptive_sample_len(5000), 2048);
    drop(_default);

    let _ambiguous = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "1,5");
    assert_eq!(auto_adaptive_sample_len(5000), 2048);
    assert_eq!(auto_adaptive_sample_len(128), 128);
    drop(_ambiguous);

    let _zero = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "0");
    assert_eq!(auto_adaptive_sample_len(5000), 64);
    drop(_zero);

    let _low = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "8");
    assert_eq!(auto_adaptive_sample_len(5000), 64);
    drop(_low);

    let _high = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "99999");
    assert_eq!(auto_adaptive_sample_len(5000), 2048);
    drop(_high);

    let _trimmed = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " '1_024' ");
    assert_eq!(auto_adaptive_sample_len(5000), 1024);
    assert_eq!(auto_adaptive_sample_len(256), 256);
    drop(_trimmed);

    let _comma_grouped = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " '1,0_2_4' ");
    assert_eq!(auto_adaptive_sample_len(5000), 1024);
    assert_eq!(auto_adaptive_sample_len(768), 768);
    drop(_comma_grouped);

    let _plus_grouped = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " '+1,5_3_6' ");
    assert_eq!(auto_adaptive_sample_len(5000), 1536);
    assert_eq!(auto_adaptive_sample_len(1400), 1400);
    drop(_plus_grouped);

    let _separator_only = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " '__,,__' ");
    assert_eq!(auto_adaptive_sample_len(5000), 2048);
    assert_eq!(auto_adaptive_sample_len(128), 128);
    drop(_separator_only);

    let _plus = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " '+1_536' ");
    assert_eq!(auto_adaptive_sample_len(5000), 1536);
    assert_eq!(auto_adaptive_sample_len(1024), 1024);
}

#[test]
fn auto_adaptive_sample_len_preserves_zero_for_empty_batches_even_with_env_floor() {
    let _env = env_lock();
    let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "8");

    // The experimental sample-size floor must not manufacture probe work
    // for empty batches. Keep the helper fail-closed at zero so later
    // callers cannot accidentally treat an empty batch as sampled.
    assert_eq!(auto_adaptive_sample_len(0), 0);
}

#[test]
fn auto_adaptive_unsigned_env_knobs_fail_closed_on_negative_values() {
    let _env = env_lock();

    let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "-16");
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", " '-512' ");
    let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "-1_024");

    assert_eq!(hot_bucket_count(), 8);
    assert_eq!(auto_adaptive_min_batch_len(), 512);
    assert_eq!(auto_adaptive_sample_len(5000), 2048);
    assert_eq!(auto_adaptive_sample_len(128), 128);
}
