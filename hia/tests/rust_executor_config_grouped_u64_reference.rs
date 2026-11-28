mod original {
    include!(env!("TRNM_ORIGINAL_EXECUTOR_ENV_CONFIG"));
}

mod active {
    include!(env!("TRNM_ACTIVE_EXECUTOR_GROUPED_FUNCTION"));

    pub(super) fn evaluate(name: &str) -> Option<usize> {
        parse_grouped_env_usize(name)
    }
}

use std::io::{self, BufRead};
use std::os::unix::ffi::OsStringExt;

const KEY: &str = "TRNM_HIA_GROUPED_USIZE_PARITY_INPUT";

fn main() {
    assert_eq!(usize::BITS, 64);
    std::env::remove_var(KEY);
    assert_eq!(original::parse_grouped_env_usize(KEY), None);
    assert_eq!(active::evaluate(KEY), None);

    // This single-threaded reference process uses a private test key only.
    // stdin is hex so malformed UTF-8 remains representable as OsString.
    for line in io::stdin().lock().lines() {
        let line = line.expect("input line");
        assert_eq!(line.len() % 2, 0);
        let bytes: Vec<u8> = line
            .as_bytes()
            .chunks_exact(2)
            .map(|part| {
                let digits = std::str::from_utf8(part).expect("hex ASCII");
                u8::from_str_radix(digits, 16).expect("two hex digits")
            })
            .collect();
        std::env::set_var(KEY, std::ffi::OsString::from_vec(bytes));
        let value = active::evaluate(KEY);
        assert_eq!(
            value,
            original::parse_grouped_env_usize(KEY),
            "hex input: {line}"
        );
        match value {
            Some(value) => println!("{value}"),
            None => println!("-"),
        }
    }
}
