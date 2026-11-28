//! Read-only observations from the unchanged executor source used by Bench.
//! Transport sets actual OS environment bytes; the included original functions
//! perform every trim, numeric parse, default, clamp, and effective selection.
use std::ffi::OsString;
use std::io::{self, BufRead};
use std::os::unix::ffi::OsStringExt;

const NAMES: [&str; 12] = [
    "TRNM_AGGR_DEEP_SCAN",
    "TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS",
    "TRNM_AGGR_SCAN_ROUND_ROBIN",
    "TRNM_AGGR_SCAN_WINDOW",
    "TRNM_AGGR_SCAN_RR_SEED",
    "TRNM_HOT_BUCKETS",
    "TRNM_AUTO_MIN_BATCH_LEN",
    "TRNM_AUTO_SAMPLE_LEN",
    "TRNM_AUTO_HOT_STREAK_RATIO",
    "TRNM_AUTO_REORDER_MIN_MARGIN",
    "TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE",
    "TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE",
];

#[allow(dead_code)]
mod original {
    include!(env!("TRNM_EXECUTOR_SOURCE"));

    pub fn effective() -> [u64; 10] {
        [
            u64::from(aggr_deep_scan_enabled())
                | (u64::from(aggr_skip_empty_stage_checks()) << 1)
                | (u64::from(aggr_scan_round_robin_enabled()) << 2),
            hot_bucket_count() as u64,
            auto_adaptive_min_batch_len() as u64,
            auto_adaptive_sample_len(usize::MAX) as u64,
            aggr_scan_window() as u64,
            aggr_scan_round_robin_seed() as u64,
            auto_hot_streak_threshold().to_bits(),
            auto_reorder_min_margin().to_bits(),
            auto_reorder_min_hot_key_share().to_bits(),
            auto_min_expected_gain_score().to_bits(),
        ]
    }
}

fn bytes(token: &str) -> Vec<u8> {
    if token == "=" {
        return Vec::new();
    }
    assert_eq!(token.len() % 2, 0);
    (0..token.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&token[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let words = line.split_whitespace().collect::<Vec<_>>();
        match words[0] {
            "F" => {
                assert_eq!(words.len(), 2);
                let bits = u64::from_str_radix(words[1], 16).unwrap();
                let value = f64::from_bits(bits);
                assert!(value.is_finite());
                println!("{value:.4}");
            }
            "D" => {
                assert_eq!(words.len(), 2);
                let raw = bytes(words[1]);
                let value = std::str::from_utf8(&raw)
                    .ok()
                    .and_then(|text| text.parse::<f64>().ok())
                    .filter(|value| value.is_finite());
                match value {
                    Some(value) => println!("ok {:016x}", value.to_bits()),
                    None => println!("invalid"),
                }
            }
            "E" => {
                assert_eq!(words.len(), NAMES.len() + 1);
                for (name, token) in NAMES.iter().zip(&words[1..]) {
                    if *token == "-" {
                        std::env::remove_var(name);
                    } else {
                        std::env::set_var(name, OsString::from_vec(bytes(token)));
                    }
                }
                let words = original::effective();
                println!(
                    "{}",
                    words
                        .iter()
                        .flat_map(|value| value.to_le_bytes())
                        .map(|value| format!("{value:02x}"))
                        .collect::<String>()
                );
            }
            _ => panic!("unknown observation command"),
        }
    }
}
