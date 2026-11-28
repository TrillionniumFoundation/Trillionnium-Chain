use std::io::{self, Read, Write};

// The parent test should prepend the five unchanged constant declarations
// exported by the pinned original lib.rs: DOMAIN, RESERVATION_DOMAIN_V2,
// GROWTH_QUANTUM_BYTES_V2, OBJECTS_PER_ROOT, FILE_BYTES.
mod original {
    include!(env!("TRNM_M15_LEDGER_ORIGINAL"));
}

use original::{GrowthPolicy, Identity, Ledger};
use rusqlite::ffi;

fn reason(ledger: &Ledger) -> u64 {
    match ledger.failed.as_deref() {
        None => 0,
        Some("bounded lifecycle evidence capacity") => 1,
        Some("pre-growth inode length cap") => 2,
        Some(other) => panic!("unmodeled original first failure: {other}"),
    }
}

fn snapshot(ledger: &Ledger, slot: usize) -> [u64; 5] {
    [
        ledger.slots[slot].as_ref().unwrap().receipt.high_water_bytes,
        ledger.lifecycle.len() as u64,
        ledger.operations,
        ledger.denied,
        reason(ledger),
    ]
}

fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn push(out: &mut impl Write, words: &[u64]) {
    for w in words {
        out.write_all(&w.to_le_bytes()).unwrap();
    }
}

fn bind(ledger: &mut Ledger, name: &str, ino: u64, main: bool) -> usize {
    let slot = ledger.reserve_open(name, main).unwrap();
    ledger
        .bind(slot, Identity { dev: 7, ino }, 0, 0, true)
        .unwrap();
    slot
}

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();
    let mut wire = input.as_slice();
    let mut output = io::stdout().lock();
    // Scenario wire: mode (one byte, 0=V1, 1=V2, 2=V2 margin), count LE u64,
    // then count LE u64 endpoints. Each output is 15 LE u64 words:
    // exact seven-word native request, original status, and seven observations.
    while !wire.is_empty() {
        let mode = wire[0];
        let count = usize::try_from(word(&wire[1..9])).unwrap();
        let (endpoints, next) = wire[9..].split_at(count * 8);
        wire = next;
        let policy = match mode {
            0 => GrowthPolicy::ExactV1,
            1 | 2 => GrowthPolicy::Reserve64KiBV2,
            _ => panic!("unexpected test scenario"),
        };
        let mut ledger = Ledger::with_policy(policy);
        let chosen = bind(&mut ledger, "native.sqlite", 1, true);
        if mode == 2 {
            let other = bind(&mut ledger, "native.sqlite-wal", 2, false);
            let third = bind(&mut ledger, "native.sqlite-shm", 3, false);
            for slot in [chosen, other, third] {
                let end = if slot == chosen { FILE_BYTES - GROWTH_QUANTUM_BYTES_V2 } else { FILE_BYTES };
                for endpoint in (GROWTH_QUANTUM_BYTES_V2..=end).step_by(GROWTH_QUANTUM_BYTES_V2 as usize) {
                    ledger.reserve_growth(slot, endpoint).unwrap();
                }
            }
            // Reach the exact documented evidence margin using genuine Rust
            // ledger operations and ordinary retained receipts, never by
            // assigning synthetic lifecycle length or rewriting owner state.
            ledger.add_shm(third).unwrap();
            while ledger.lifecycle.len() < 1016 {
                ledger.reserve_handle(other).unwrap();
                ledger.opened(other).unwrap();
                ledger.close_handle(other);
            }
            assert_eq!(ledger.lifecycle.len(), 1016);
        }
        for e in endpoints.chunks_exact(8) {
            let endpoint = word(e);
            let [water, events, ops, denied, sticky] = snapshot(&ledger, chosen);
            push(&mut output, &[u64::from(mode != 0), water, events, ops, denied, sticky, endpoint]);
            let first = ledger.first_failure_code;
            let status = match ledger.reserve_growth(chosen, endpoint) {
                Ok(()) => ffi::SQLITE_OK,
                Err(code) => code,
            };
            let now = snapshot(&ledger, chosen);
            assert_eq!(ledger.first_failure_code, first.or((status == ffi::SQLITE_FULL).then_some(ffi::SQLITE_FULL)));
            let (flags, requested) = if now[1] != events {
                assert_eq!(now[1], events + 1);
                let event = ledger.lifecycle.last().unwrap();
                assert_eq!(event.action, "reserve-growth");
                assert_eq!(event.high_water_bytes, now[0]);
                (if event.requested_endpoint.is_some() { 3 } else { 1 },
                 event.requested_endpoint.unwrap_or(0))
            } else {
                (0, 0)
            };
            push(&mut output, &[u64::try_from(status).unwrap()]);
            push(&mut output, &now);
            push(&mut output, &[flags, requested]);
        }
    }
}
