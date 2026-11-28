// This fixture calls the four exact active definitions and the complete retained
// configuration module; it does not implement toggle parsing.
#![allow(dead_code)]

mod active {
    include!(env!("TRNM_EXECUTOR_ACTIVE_TOGGLE_SOURCE"));

    pub(super) fn observe(default: bool) -> [bool; 4] {
        [
            env_toggle_enabled("TRNM_AGGR_DEEP_SCAN", default),
            aggr_skip_empty_stage_checks(),
            aggr_deep_scan_enabled(),
            aggr_scan_round_robin_enabled(),
        ]
    }
}

mod retained {
    include!(env!("TRNM_EXECUTOR_RETAINED_CONFIGURATION_SOURCE"));
}

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;

const KEYS: [&str; 3] = [
    "TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS",
    "TRNM_AGGR_DEEP_SCAN",
    "TRNM_AGGR_SCAN_ROUND_ROBIN",
];

fn main() -> io::Result<()> {
    let mut encoded = Vec::new();
    io::stdin().read_to_end(&mut encoded)?;
    let mut bytes = encoded.as_slice();
    let mut stdout = io::stdout().lock();
    while !bytes.is_empty() {
        let (len, body) = bytes.split_at(4);
        let len = u32::from_le_bytes(len.try_into().unwrap()) as usize;
        let (request, rest) = body.split_at(len);
        let (present, default, value) = match request {
            [0, d @ 0..=1] => (false, *d == 1, &[][..]),
            [1, d @ 0..=1, payload @ ..] => (true, *d == 1, payload),
            _ => panic!("invalid oracle frame"),
        };
        for name in KEYS {
            if present {
                std::env::set_var(name, OsStr::from_bytes(value));
            } else {
                std::env::remove_var(name);
            }
        }
        let retained = [
            retained::env_toggle_enabled("TRNM_AGGR_DEEP_SCAN", default),
            retained::aggr_skip_empty_stage_checks(),
            retained::aggr_deep_scan_enabled(),
            retained::aggr_scan_round_robin_enabled(),
        ];
        let active = active::observe(default);
        stdout.write_all(&active.map(u8::from))?;
        stdout.write_all(&retained.map(u8::from))?;
        bytes = rest;
    }
    stdout.flush()
}
