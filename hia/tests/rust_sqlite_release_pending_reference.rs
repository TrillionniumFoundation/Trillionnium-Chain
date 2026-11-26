use std::io::{self, Write};

// Same original locked lib.rs constants/artifact glue as close_collect.
mod original {
    include!(env!("TRNM_M15_LEDGER_ORIGINAL"));
}
use original::{GrowthPolicy, Identity, Ledger};
use rusqlite::ffi;

fn words(out: &mut impl Write, values: &[u64]) {
    for v in values { out.write_all(&v.to_le_bytes()).unwrap(); }
}
fn flags(main: bool, linked: bool, reserved: bool) -> u64 {
    1 | (u64::from(main) << 1) | (u64::from(linked) << 2) | (u64::from(reserved) << 3)
}
fn row(l: &Ledger, slot: usize) -> [u64; 9] {
    l.slots[slot].as_ref().map_or([0; 9], |o| {
        let r = &o.receipt;
        [flags(o.main, r.linked, r.reserved_pending_open),
         u64::from(r.handles), u64::from(r.pending_opens), u64::from(r.shm_references),
         r.high_water_bytes, r.actual_last_bytes, r.generation,
         r.device.unwrap_or(0), r.inode.unwrap_or(0)]
    })
}
fn observe(out: &mut impl Write, l: &mut Ledger, slot: usize, action: u64) {
    let label = match action {
        1 => "unpublished-actual-close",
        2 => "failed-open-no-methods",
        _ => panic!("invalid authored test action"),
    };
    let old = row(l, slot);
    let cleanup = l.cleanup.len();
    let sticky = l.failed.clone();
    let original_code = l.first_failure_code;
    let counters = (l.operations, l.denied, l.lifecycle.len(), l.retained_logical_bytes_peak);
    assert!(old[2] > 0 && cleanup < 256 && l.lifecycle_complete);
    // 31 words: prior close/collect packet followed by typed original action.
    words(out, &[slot as u64, u64::from(l.active_main_handles), cleanup as u64]);
    for i in 0..3 { words(out, &row(l, i)); }
    words(out, &[action]);
    l.release_pending(slot, label);
    assert_eq!((l.failed.clone(), l.first_failure_code), (sticky, original_code));
    assert_eq!((l.operations, l.denied, l.lifecycle.len(), l.retained_logical_bytes_peak), counters);
    assert!(l.lifecycle_complete);
    assert_eq!(l.cleanup.len(), cleanup + 1);
    let event = &l.cleanup[cleanup];
    assert_eq!(event.action, label);
    assert_eq!(event.requested_endpoint, None);
    assert_eq!(u64::from(event.handles), old[1]);
    assert_eq!(u64::from(event.pending_opens) + 1, old[2]);
    let retained = l.slots.iter().enumerate()
        .fold(0, |mask, (i, v)| mask | (u64::from(v.is_some()) << i));
    let charge = l.slots.iter().flatten().map(|v| v.receipt.high_water_bytes).sum();
    // 14 words: same close/collect summary fields with pending decreased
    // instead of actual handles, then exactly observed action discriminator.
    words(out, &[u64::from(l.active_main_handles), l.cleanup.len() as u64, retained, charge]);
    words(out, &[
        flags(old[0] & 2 != 0, event.linked, old[0] & 8 != 0),
        u64::from(event.handles), u64::from(event.pending_opens), u64::from(event.shm_references),
        event.high_water_bytes, event.actual_last_bytes, event.generation,
        event.device.unwrap_or(0), event.inode.unwrap_or(0), action,
    ]);
}
fn pending(l: &mut Ledger, name: &str, number: u64, main: bool, endpoint: u64) -> usize {
    let i = l.reserve_open(name, main).unwrap();
    let who = Identity { dev: 7, ino: number };
    l.bind(i, who, 0, 0, true).unwrap();
    l.reserve_growth(i, endpoint).unwrap();
    l.bind(i, who, endpoint, 1, true).unwrap();
    l.reserve_handle(i).unwrap();
    i
}
fn failed_open(l: &mut Ledger) {
    // Reproduce the original *ledger* call made before release_pending; no
    // SQLite callback / open is run and no failure is injected physically.
    assert_eq!(l.fail::<()>("base xOpen failed; pending reservation retained", ffi::SQLITE_CANTOPEN),
               Err(ffi::SQLITE_CANTOPEN));
}
fn main() {
    let mut out = io::stdout().lock();
    for policy in [GrowthPolicy::ExactV1, GrowthPolicy::Reserve64KiBV2] {
        let mut l = Ledger::with_policy(policy);
        let old = pending(&mut l, "native.sqlite", 1, true, 4097);
        l.unlinked(old);
        let new = pending(&mut l, "native.sqlite", 2, true, 65537);
        observe(&mut out, &mut l, old, 1);
        assert!(l.slots[old].is_some());
        observe(&mut out, &mut l, new, 1);
        assert!(l.slots[old].is_none() && l.slots[new].is_some());

        let mut l = Ledger::with_policy(policy);
        let a = pending(&mut l, "native.sqlite-journal", 4, false, 43);
        l.opened(a).unwrap();
        l.reserve_handle(a).unwrap();
        l.unlinked(a);
        failed_open(&mut l);
        observe(&mut out, &mut l, a, 2);
        assert!(l.slots[a].is_some());
        assert_eq!(l.slots[a].as_ref().unwrap().receipt.handles, 1);
        l.close_handle(a);
        assert!(l.slots[a].is_none());

        let mut l = Ledger::with_policy(policy);
        let a = pending(&mut l, "native.sqlite-shm", 5, false, 73);
        l.add_shm(a).unwrap();
        l.unlinked(a);
        observe(&mut out, &mut l, a, 1);
        assert!(l.slots[a].is_some());
        l.close_shm(a);
        assert!(l.slots[a].is_none());

        let mut l = Ledger::with_policy(policy);
        let a = l.reserve_open("native.sqlite-journal", false).unwrap();
        l.reserve_growth(a, 33).unwrap();
        l.reserve_handle(a).unwrap();
        l.unlinked(a);
        failed_open(&mut l);
        observe(&mut out, &mut l, a, 2);
        assert!(l.slots[a].is_some());
        assert!(l.slots[a].as_ref().unwrap().receipt.reserved_pending_open);

        let mut l = Ledger::with_policy(policy);
        let a = pending(&mut l, "native.sqlite-journal", 6, false, 193);
        l.unlinked(a);
        failed_open(&mut l);
        observe(&mut out, &mut l, a, 2);
        assert!(l.slots[a].is_none());
    }
}
