use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;

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

fn launch() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();
    let mut entries = Vec::new();
    if !input.is_empty() {
        assert_eq!(input.pop(), Some(0));
        for entry in input.split(|octet| *octet == 0) {
            entries.push(CString::new(entry).unwrap());
        }
    }
    let mut envp: Vec<_> = entries.iter().map(|entry| entry.as_ptr()).collect();
    envp.push(std::ptr::null());
    let exe = CString::new(std::env::current_exe().unwrap().as_os_str().as_bytes()).unwrap();
    let argv = [exe.as_ptr(), std::ptr::null()];
    unsafe extern "C" {
        fn execve(
            path: *const std::ffi::c_char,
            argv: *const *const std::ffi::c_char,
            envp: *const *const std::ffi::c_char,
        ) -> std::ffi::c_int;
    }
    // This adapter receives only synthetic corpus fixtures, never the host's
    // environment. Passing this explicit envp avoids Command/HashMap deduplication.
    unsafe { execve(exe.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    panic!("synthetic execve failed: {}", io::Error::last_os_error());
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("exec") {
        launch();
        return;
    }
    let selected: Vec<_> = NAMES.into_iter().map(std::env::var_os).collect();
    let mut frame = b"BENV0001".to_vec();
    for value in &selected {
        let width = value
            .as_ref()
            .map_or(u64::MAX, |bytes| bytes.as_os_str().as_bytes().len() as u64);
        frame.extend(width.to_le_bytes());
    }
    for value in selected.into_iter().flatten() {
        frame.extend(value.as_os_str().as_bytes());
    }
    let flags = u64::from(aggr_deep_scan_enabled())
        | (u64::from(aggr_skip_empty_stage_checks()) << 1)
        | (u64::from(aggr_scan_round_robin_enabled()) << 2);
    let effective = [
        flags,
        hot_bucket_count() as u64,
        auto_adaptive_min_batch_len() as u64,
        auto_adaptive_sample_len(usize::MAX) as u64,
        aggr_scan_window() as u64,
        aggr_scan_round_robin_seed() as u64,
        auto_hot_streak_threshold().to_bits(),
        auto_reorder_min_margin().to_bits(),
        auto_reorder_min_hot_key_share().to_bits(),
        auto_min_expected_gain_score().to_bits(),
    ];
    let mut stdout = io::stdout().lock();
    stdout.write_all(&frame).unwrap();
    for word in effective {
        stdout.write_all(&word.to_le_bytes()).unwrap();
    }
}
