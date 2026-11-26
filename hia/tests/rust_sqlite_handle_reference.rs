use std::io::{self, Write};

// Use the same five unchanged pinned constants and artifact linkage as the
// previously published reservation/observed-bind witnesses.
mod original {
    include!(env!("TRNM_M15_LEDGER_ORIGINAL"));
}
use original::{GrowthPolicy, Identity, Ledger};

fn words(out: &mut impl Write, values: &[u64]) {
    for v in values { out.write_all(&v.to_le_bytes()).unwrap(); }
}

fn reason(l: &Ledger) -> u64 {
    match l.failed.as_deref() {
        None => 0,
        Some("bounded lifecycle evidence capacity") => 1,
        Some("per-inode actual+pending handle cap") => 2,
        Some("missing reserved handle") => 3,
        Some("pre-growth inode length cap") => 4,
        Some(other) => panic!("unexpected original sticky reason: {other}"),
    }
}

fn observation(l: &Ledger, slot: usize) -> [u64; 8] {
    let r = &l.slots[slot].as_ref().unwrap().receipt;
    [
        u64::from(r.handles), u64::from(r.pending_opens),
        u64::from(l.active_main_handles), l.lifecycle.len() as u64,
        l.operations, l.denied, reason(l),
        u64::try_from(l.first_failure_code.unwrap_or(0)).unwrap(),
    ]
}

fn replay(out: &mut impl Write, l: &mut Ledger, slot: usize, opened: bool) {
    assert!(l.lifecycle_complete && l.lifecycle.len() <= 1017);
    let main = l.slots[slot].as_ref().unwrap().main;
    let before = observation(l, slot);
    // Input: 10 LE u64 words; action (0 reserve, 1 opened), main, eight
    // words in observation order.
    words(out, &[u64::from(opened), u64::from(main)]);
    words(out, &before);
    let result = if opened { l.opened(slot) } else { l.reserve_handle(slot) };
    let status = result.map(|_| 0).unwrap_or_else(|e| e);
    let after = observation(l, slot);
    let event = if after[3] != before[3] {
        assert_eq!(after[3], before[3] + 1);
        let e = l.lifecycle.last().unwrap();
        assert_eq!(e.requested_endpoint, None);
        assert_eq!((u64::from(e.handles), u64::from(e.pending_opens)), (after[0], after[1]));
        match e.action {
            "reserve-handle" => 1,
            "opened" => 2,
            other => panic!("unexpected original event: {other}"),
        }
    } else { 0 };
    // Response record: exact SQLite status then nine output words.
    words(out, &[u64::try_from(status).unwrap()]);
    words(out, &after);
    words(out, &[event]);
}

fn bind(l: &mut Ledger, name: &str, ino: u64, main: bool) -> usize {
    let c = l.reserve_open(name, main).unwrap();
    l.bind(c, Identity { dev: 7, ino }, 0, 0, true).unwrap();
    c
}

fn margin(cap: bool) -> (Ledger, usize, usize) {
    let mut l = Ledger::with_policy(GrowthPolicy::Reserve64KiBV2);
    let chosen = bind(&mut l, "native.sqlite", 1, true);
    let other = bind(&mut l, "native.sqlite-wal", 2, false);
    let third = bind(&mut l, "native.sqlite-shm", 3, false);
    for slot in [chosen, other, third] {
        for end in (GROWTH_QUANTUM_BYTES_V2..=FILE_BYTES).step_by(GROWTH_QUANTUM_BYTES_V2 as usize) {
            l.reserve_growth(slot, end).unwrap();
        }
    }
    if cap {
        for _ in 0..32 { l.reserve_handle(chosen).unwrap(); }
    } else {
        // Leave one real open reservation for a later opened replay, making
        // the count even without assigning any ledger state.
        l.reserve_handle(chosen).unwrap();
        l.add_shm(third).unwrap();
    }
    while l.lifecycle.len() < 1016 {
        l.reserve_handle(other).unwrap();
        l.opened(other).unwrap();
        l.close_handle(other);
    }
    assert_eq!(l.lifecycle.len(), 1016);
    (l, chosen, third)
}

fn main() {
    let mut out = io::stdout().lock();
    for p in [GrowthPolicy::ExactV1, GrowthPolicy::Reserve64KiBV2] {
        let mut l = Ledger::with_policy(p);
        let a = bind(&mut l, "native.sqlite", 1, true);
        let other = bind(&mut l, "native.sqlite-wal", 2, false);
        replay(&mut out, &mut l, a, false);
        replay(&mut out, &mut l, other, false);
        replay(&mut out, &mut l, a, true);
        replay(&mut out, &mut l, other, true);
        // One actual main and 30 pending: next reservation makes 32.
        for _ in 0..30 { l.reserve_handle(a).unwrap(); }
        replay(&mut out, &mut l, a, false);
        replay(&mut out, &mut l, a, false);
        replay(&mut out, &mut l, a, true);  // opened after sticky FULL
        replay(&mut out, &mut l, a, false); // same sticky, no denied increment
        replay(&mut out, &mut l, other, true); // distinct current IOERR, preserves first FULL

        let mut l = Ledger::with_policy(p);
        let a = bind(&mut l, "native.sqlite", 3, true);
        replay(&mut out, &mut l, a, true); // missing pending is first IOERR
        replay(&mut out, &mut l, a, false); // sticky admission before event/handle caps
    }
    let (mut l, a, _) = margin(false);
    replay(&mut out, &mut l, a, false); // at 1016 accepted and reserves
    replay(&mut out, &mut l, a, false); // at 1017 evidence FULL
    replay(&mut out, &mut l, a, true);  // opened despite sticky/1017

    let (mut l, a, third) = margin(true);
    l.add_shm(third).unwrap();
    assert_eq!(l.lifecycle.len(), 1017);
    replay(&mut out, &mut l, a, false); // evidence FULL wins over handle FULL
    replay(&mut out, &mut l, a, true);  // same full count, admitted earlier pending is consumed

    let mut l = Ledger::with_policy(GrowthPolicy::Reserve64KiBV2);
    let a = bind(&mut l, "native.sqlite", 4, true);
    l.reserve_handle(a).unwrap();
    assert_eq!(l.reserve_growth(a, FILE_BYTES + 1), Err(rusqlite::ffi::SQLITE_FULL));
    replay(&mut out, &mut l, a, true); // original other first-failure class preserved
}
