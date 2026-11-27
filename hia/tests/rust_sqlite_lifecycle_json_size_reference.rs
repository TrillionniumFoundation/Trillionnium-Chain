use std::io::{self, Write};

mod original {
    include!(env!("TRNM_M15_LEDGER_ORIGINAL"));

    pub fn pending_close_probe(basename: &str) -> (LifecycleReceipt, bool) {
        let mut l = Ledger::new();
        let i = l.reserve_open(basename, false).unwrap();
        let r = &l.slots[i].as_ref().unwrap().receipt;
        let event = LifecycleReceipt {
            sequence: l.next_event, action: "underlying-shm-unmap",
            generation: r.generation, basename: r.basename.clone(),
            device: r.device, inode: r.inode, linked: r.linked,
            handles: r.handles, pending_opens: r.pending_opens, shm_references: r.shm_references,
            high_water_bytes: r.high_water_bytes, actual_last_bytes: r.actual_last_bytes,
            requested_endpoint: None,
        };
        l.close_shm(i);
        if let Some(exact) = l.cleanup.first() {
            assert_eq!(serde_json::to_vec(exact).unwrap(), serde_json::to_vec(&event).unwrap());
        }
        (event, l.lifecycle_complete)
    }
}
use original::{GrowthPolicy, Identity, Ledger, LifecycleReceipt};

const ACTIONS: [&str; 12] = [
    "reserve-open", "bind-existing-before-io-v2", "bind-real-inode", "reserve-growth",
    "reserve-handle", "opened", "unpublished-actual-close", "failed-open-no-methods",
    "shm-reference", "underlying-close", "underlying-shm-unmap", "unlinked",
];

fn emit(out: &mut impl Write, family: u64, e: &LifecycleReceipt) {
    let action = ACTIONS.iter().position(|&a| a == e.action).unwrap() as u64 + 1;
    let flags = u64::from(e.device.is_some()) | (u64::from(e.inode.is_some()) << 1)
        | (u64::from(e.requested_endpoint.is_some()) << 2);
    let eq = serde_json::to_vec(e).unwrap();
    let fields = [action, e.sequence, e.generation, e.device.unwrap_or(0),
        e.inode.unwrap_or(0), u64::from(e.linked), e.handles.into(), e.pending_opens.into(),
        e.shm_references.into(), e.high_water_bytes, e.actual_last_bytes,
        e.requested_endpoint.unwrap_or(0), flags];
    for x in [family, e.basename.len() as u64, eq.len() as u64].into_iter().chain(fields) {
        out.write_all(&x.to_le_bytes()).unwrap();
    }
    out.write_all(e.basename.as_bytes()).unwrap();
}

fn main() {
    let mut out = io::stdout().lock();
    for policy in [GrowthPolicy::ExactV1, GrowthPolicy::Reserve64KiBV2] {
        let mut l = Ledger::with_policy(policy);
        let slot = l.reserve_open("native-雪.sqlite", true).unwrap();
        l.observe_existing_before_io(slot, Identity {dev: 3, ino: 42}, 7, 1, true).unwrap();
        l.reserve_growth(slot, 65537).unwrap();
        l.reserve_handle(slot).unwrap(); l.opened(slot).unwrap();
        l.reserve_handle(slot).unwrap(); l.release_pending(slot, "unpublished-actual-close");
        l.reserve_handle(slot).unwrap(); l.release_pending(slot, "failed-open-no-methods");
        l.add_shm(slot).unwrap(); l.close_shm(slot);
        l.unlinked(slot); l.close_handle(slot);
        for e in l.lifecycle.iter().chain(&l.cleanup) { emit(&mut out, 0, e); }
    }
    let controls: String = (0u8..32).map(char::from).collect();
    let unicode = "\u{007f}é中😀\u{2028}\u{2029}e\u{0301}";
    for bits in 0..8u8 {
        let e = LifecycleReceipt {
            sequence: u64::MAX, action: "reserve-growth", generation: 0,
            basename: format!("{controls}{unicode}/\"\\"),
            device: (bits & 1 != 0).then_some(u64::MAX),
            inode: (bits & 2 != 0).then_some(0), linked: bits & 1 != 0,
            handles: u32::MAX, pending_opens: 9, shm_references: 10,
            high_water_bytes: 99999, actual_last_bytes: 100000,
            requested_endpoint: (bits & 4 != 0).then_some(0),
        };
        emit(&mut out, 1, &e);
    }
    let (base, _) = original::pending_close_probe("");
    let base_len = serde_json::to_vec(&base).unwrap().len();
    for width in [511, 512, 513] {
        let (e, kept) = original::pending_close_probe(&"q".repeat(width - base_len));
        assert_eq!(serde_json::to_vec(&e).unwrap().len(), width);
        assert_eq!(kept, width <= 512);
        emit(&mut out, 2, &e);
    }
    let (empty, _) = original::pending_close_probe("");
    emit(&mut out, 3, &empty);
    let mut wide = empty;
    wide.basename = "\u{0003}".repeat(512); // typed serde fixture, not a ledger filename
    emit(&mut out, 3, &wide);
}
