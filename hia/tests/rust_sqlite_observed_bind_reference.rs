use std::io::{self, Write};

// Prepend the five unchanged constants from original lib.rs, then compile
// with the locked rusqlite/serde/serde_json externs as in reservation replay.
mod original {
    include!(env!("TRNM_M15_LEDGER_ORIGINAL"));
}
use original::{GrowthPolicy, Identity, Ledger};

fn id(dev: u64, ino: u64) -> Identity { Identity { dev, ino } }

fn reason(l: &Ledger) -> u64 {
    match l.failed.as_deref() {
        None => 0,
        Some("named pre-I/O observation must be linked") => 1,
        Some("existing object exceeds per-inode cap") => 2,
        Some("inode aliased across retained slots") => 3,
        Some("named inode replaced") => 4,
        Some("actual inode length exceeds prior reservation") => 5,
        Some("bounded lifecycle evidence capacity") => 6,
        Some("pre-growth inode length cap") => 7,
        Some(other) => panic!("unexpected original first failure: {other}"),
    }
}
fn receipt(l: &Ledger, c: usize) -> [u64; 6] {
    let o = l.slots[c].as_ref().unwrap();
    let r = &o.receipt;
    let bits = u64::from(o.identity.is_some()) | (u64::from(r.linked) << 1)
        | (u64::from(r.reserved_pending_open) << 2);
    [bits, r.device.unwrap_or(0), r.inode.unwrap_or(0), r.high_water_bytes,
     r.actual_last_bytes, r.actual_last_allocated_blocks_512]
}
fn evidence(l: &Ledger) -> [u64; 5] {
    [l.lifecycle.len() as u64, l.operations, l.denied, reason(l),
     u64::try_from(l.first_failure_code.unwrap_or(0)).unwrap()]
}
fn words(out: &mut impl Write, values: &[u64]) {
    for v in values { out.write_all(&v.to_le_bytes()).unwrap(); }
}
fn replay(out: &mut impl Write, l: &mut Ledger, chosen: usize, before: bool,
          who: Identity, length: u64, blocks: u64, linked: bool) {
    let old = receipt(l, chosen);
    let counters = evidence(l);
    let others: Vec<_> = l.slots.iter().enumerate().filter(|(i, _)| *i != chosen)
        .map(|(_, o)| o.as_ref().and_then(|v| v.identity)).collect();
    let p = l.policy() == GrowthPolicy::Reserve64KiBV2;
    let bitmap = u64::from(others[0].is_some()) | (u64::from(others[1].is_some()) << 1);
    let a = others[0].unwrap_or(id(0, 0));
    let b = others[1].unwrap_or(id(0, 0));
    let current_sum: u64 = l.slots.iter().flatten().map(|o| o.receipt.high_water_bytes).sum();
    // Native input: 25 u64 words.
    words(out, &[u64::from(p), u64::from(before)]);
    words(out, &old);
    words(out, &[bitmap, a.dev, a.ino, b.dev, b.ino]);
    words(out, &counters);
    words(out, &[current_sum, l.retained_logical_bytes_peak, u64::from(linked),
                 who.dev, who.ino, length, blocks]);
    let result = if before {
        l.observe_existing_before_io(chosen, who, length, blocks, linked)
    } else {
        l.bind(chosen, who, length, blocks, linked)
    };
    let status = result.map(|_| 0).unwrap_or_else(|code| code);
    let event = if l.lifecycle.len() as u64 != counters[0] {
        assert_eq!(l.lifecycle.len() as u64, counters[0] + 1);
        let r = l.lifecycle.last().unwrap();
        match r.action {
            "bind-real-inode" => { assert_eq!(r.requested_endpoint, None); (1, 0) }
            "bind-existing-before-io-v2" => (2, r.requested_endpoint.unwrap()),
            other => panic!("unexpected original event: {other}"),
        }
    } else { (0, 0) };
    // One return-status word, then 14 u64 output words.
    words(out, &[u64::try_from(status).unwrap()]);
    words(out, &receipt(l, chosen));
    words(out, &evidence(l));
    words(out, &[l.retained_logical_bytes_peak, event.0, event.1]);
}
fn new(policy: GrowthPolicy) -> (Ledger, usize) {
    let mut l = Ledger::with_policy(policy);
    let chosen = l.reserve_open("native.sqlite", true).unwrap();
    (l, chosen)
}
fn prepare_margin() -> (Ledger, usize, usize) {
    let (mut l, chosen) = new(GrowthPolicy::Reserve64KiBV2);
    let other = l.reserve_open("native.sqlite-wal", false).unwrap();
    let third = l.reserve_open("native.sqlite-shm", false).unwrap();
    l.bind(other, id(7, 2), 0, 0, true).unwrap();
    l.bind(third, id(7, 3), 0, 0, true).unwrap();
    for slot in [chosen, other, third] {
        for end in (GROWTH_QUANTUM_BYTES_V2..=FILE_BYTES).step_by(GROWTH_QUANTUM_BYTES_V2 as usize) {
            l.reserve_growth(slot, end).unwrap();
        }
    }
    l.add_shm(third).unwrap();
    while l.lifecycle.len() < 1016 {
        l.reserve_handle(other).unwrap();
        l.opened(other).unwrap();
        l.close_handle(other);
    }
    assert_eq!(l.lifecycle.len(), 1016);
    assert!(l.slots[chosen].as_ref().unwrap().identity.is_none());
    (l, chosen, third)
}
fn main() {
    use GrowthPolicy::{ExactV1 as V1, Reserve64KiBV2 as V2};
    let mut out = io::stdout().lock();

    let (mut l, c) = new(V1);
    replay(&mut out, &mut l, c, true, id(7, 1), 63, 8, false);
    replay(&mut out, &mut l, c, false, id(7, 1), 1, 2, true);
    replay(&mut out, &mut l, c, true, id(7, 1), 65537, 16, true);

    let (mut l, c) = new(V2);
    replay(&mut out, &mut l, c, false, id(7, 1), 1, 1, true);
    // Already failed: only before-I/O first admission consumes another op.
    replay(&mut out, &mut l, c, true, id(7, 1), 1, 9, true);
    replay(&mut out, &mut l, c, false, id(7, 1), 0, 0, true);

    let (mut l, c) = new(V2);
    l.reserve_growth(c, 2).unwrap();
    replay(&mut out, &mut l, c, false, id(7, 1), 3, 5, true);
    replay(&mut out, &mut l, c, true, id(7, 1), 0, 0, true);
    replay(&mut out, &mut l, c, true, id(7, 1), 65537, 7, true);
    replay(&mut out, &mut l, c, false, id(7, 1), 10, 6, false);

    for n in [0, 1, 65535, 65536, 65537, FILE_BYTES] {
        let (mut l, c) = new(V2);
        replay(&mut out, &mut l, c, true, id(7, 1), n, 13, true);
    }

    let (mut l, c) = new(V2);
    let other = l.reserve_open("native.sqlite-wal", false).unwrap();
    l.bind(other, id(7, 2), 0, 0, true).unwrap();
    replay(&mut out, &mut l, c, false, id(8, 2), 0, 0, true);
    // Precedence: unlinked vs all, cap vs alias+replacement, alias vs replacement.
    replay(&mut out, &mut l, c, true, id(7, 2), FILE_BYTES + 1, 99, false);
    replay(&mut out, &mut l, c, false, id(7, 2), FILE_BYTES + 1, 99, true);
    replay(&mut out, &mut l, c, true, id(7, 2), 0, 99, true);
    replay(&mut out, &mut l, c, true, id(8, 3), 0, 99, true);

    let (mut l, c, _) = prepare_margin();
    replay(&mut out, &mut l, c, true, id(7, 1), 1, 0, true);

    let (mut l, c, other) = prepare_margin();
    l.add_shm(other).unwrap();
    assert_eq!(l.lifecycle.len(), 1017);
    replay(&mut out, &mut l, c, true, id(7, 1), 1, 0, true);
    replay(&mut out, &mut l, c, false, id(7, 1), 1, 0, true);
}
