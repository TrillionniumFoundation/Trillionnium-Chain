use std::io::{self, Write};

// Prefix the five unchanged lib.rs constants and use the pinned original
// Cargo extern artifacts, as for the published reservation/bind witnesses.
mod original {
    include!(env!("TRNM_M15_LEDGER_ORIGINAL"));
}
use original::{GrowthPolicy, Identity, Ledger};

fn write_words(out: &mut impl Write, v: &[u64]) {
    for x in v { out.write_all(&x.to_le_bytes()).unwrap(); }
}

fn flags(main: bool, linked: bool, reserved: bool) -> u64 {
    1 | (u64::from(main) << 1) | (u64::from(linked) << 2) | (u64::from(reserved) << 3)
}

fn row(l: &Ledger, at: usize) -> [u64; 9] {
    l.slots[at].as_ref().map_or([0; 9], |o| {
        let r = &o.receipt;
        [
            flags(o.main, r.linked, r.reserved_pending_open),
            u64::from(r.handles), u64::from(r.pending_opens), u64::from(r.shm_references),
            r.high_water_bytes, r.actual_last_bytes, r.generation,
            r.device.unwrap_or(0), r.inode.unwrap_or(0),
        ]
    })
}

fn observe(out: &mut impl Write, l: &mut Ledger, slot: usize) {
    // Request: 30 LE u64 words; selected index, active-main count, cleanup
    // count, then three nine-word rows in original slot-index order.
    let active = l.active_main_handles;
    let prior_cleanup = l.cleanup.len();
    let old = row(l, slot);
    assert_ne!(old[0], 0);
    assert!(prior_cleanup < 256 && l.lifecycle_complete && l.failed.is_none());
    write_words(out, &[slot as u64, u64::from(active), prior_cleanup as u64]);
    for x in 0..3 { write_words(out, &row(l,x)); }
    l.close_handle(slot);
    assert_eq!(l.cleanup.len(), prior_cleanup + 1);
    assert!(l.lifecycle_complete && l.failed.is_none());
    let e = &l.cleanup[prior_cleanup];
    assert_eq!(e.action, "underlying-close");
    assert_eq!(e.requested_endpoint, None);
    // Result: 13 LE u64 words; active-main count, cleanup count, retained
    // slot mask, retained logical charge, then the nine-word close event.
    // Reserved bit is inherited from the chosen slot; the original event
    // itself does not serialize that bit. Publication is diagnostic only.
    let kept = l.slots.iter().enumerate().fold(0, |mask, (i, v)| mask | (u64::from(v.is_some()) << i));
    let charge = l.slots.iter().flatten().map(|v| v.receipt.high_water_bytes).sum();
    write_words(out, &[u64::from(l.active_main_handles), l.cleanup.len() as u64, kept, charge]);
    write_words(out, &[
        flags(old[0] & 2 != 0, e.linked, old[0] & 8 != 0),
        u64::from(e.handles), u64::from(e.pending_opens), u64::from(e.shm_references),
        e.high_water_bytes, e.actual_last_bytes, e.generation,
        e.device.unwrap_or(0), e.inode.unwrap_or(0),
    ]);
}

fn create(l: &mut Ledger, name: &str, inode: u64, main: bool, end: u64) -> usize {
    let slot = l.reserve_open(name, main).unwrap();
    // This is deterministic original ledger replay, not a real descriptor.
    l.bind(slot, Identity { dev: 7, ino: inode }, 0, 0, true).unwrap();
    l.reserve_growth(slot, end).unwrap();
    l.bind(slot, Identity { dev: 7, ino: inode }, end, 1, true).unwrap();
    l.reserve_handle(slot).unwrap();
    l.opened(slot).unwrap();
    slot
}

fn main() {
    let mut out = io::stdout().lock();
    for p in [GrowthPolicy::ExactV1, GrowthPolicy::Reserve64KiBV2] {
        let mut l = Ledger::with_policy(p);
        let a = create(&mut l, "native.sqlite", 1, true, 4097);
        l.unlinked(a);
        let b = create(&mut l, "native.sqlite", 2, true, 65537);
        assert_ne!(a, b);
        observe(&mut out, &mut l, a);
        assert!(l.slots[a].is_some());
        observe(&mut out, &mut l, b);
        assert!(l.slots[a].is_none());
        assert!(l.slots[b].is_some());

        let mut l = Ledger::with_policy(p);
        let a = create(&mut l, "native.sqlite-shm", 4, false, 33);
        let b = create(&mut l, "native.sqlite-journal", 5, false, 113);
        l.add_shm(a).unwrap();
        l.unlinked(a);
        l.unlinked(b);
        observe(&mut out, &mut l, a);
        assert!(l.slots[a].is_some());
        observe(&mut out, &mut l, b);
        assert!(l.slots[b].is_none());
        l.close_shm(a);
        assert!(l.slots[a].is_none());

        let mut l = Ledger::with_policy(p);
        let raw = l.reserve_open("native.sqlite-shm", false).unwrap();
        l.reserve_growth(raw, 17).unwrap();
        l.unlinked(raw);
        let c = create(&mut l, "native.sqlite-journal", 9, false, 55);
        observe(&mut out, &mut l, c);
        assert!(l.slots[raw].is_some());
        assert!(l.slots[raw].as_ref().unwrap().receipt.reserved_pending_open);

        let mut l = Ledger::with_policy(p);
        let c = create(&mut l, "native.sqlite-journal", 12, false, 91);
        l.reserve_handle(c).unwrap();
        l.unlinked(c);
        observe(&mut out, &mut l, c);
        assert!(l.slots[c].is_some());
        l.release_pending(c, "fixture-cancel");
        assert!(l.slots[c].is_none());

        let mut l = Ledger::with_policy(p);
        let c = create(&mut l, "native.sqlite", 15, true, 1);
        for _ in 0..255 {
            l.close_handle(c);
            l.reserve_handle(c).unwrap();
            l.opened(c).unwrap();
        }
        assert_eq!(l.cleanup.len(), 255);
        observe(&mut out, &mut l, c);
        assert_eq!(l.cleanup.len(), 256);

        let mut l = Ledger::with_policy(p);
        let main = create(&mut l, "native.sqlite", 17, true, 4096);
        let journal = create(&mut l, "native.sqlite-journal", 18, false, 512);
        let shm = create(&mut l, "native.sqlite-shm", 19, false, 96);
        assert_eq!((main, journal, shm), (0, 1, 2));
        l.unlinked(shm);
        observe(&mut out, &mut l, shm);
        assert!(l.slots[shm].is_none());
        assert_eq!(l.active_main_handles, 1);
    }
}
