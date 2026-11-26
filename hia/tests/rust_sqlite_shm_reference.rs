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

fn failure(l: &Ledger) -> (u64,u64) {
    match (l.failed.as_deref(), l.first_failure_code) {
        (None,None) => (0,0),
        (Some("fixture-prior"),Some(14)) => (1,14),
        (Some("SHM reference cap"),Some(13)) => (2,13),
        other => panic!("unexpected original failure: {other:?}"),
    }
}

fn observe(out: &mut impl Write, l: &mut Ledger, slot: usize, action: u64, want: u64) {
    let active = l.active_main_handles;
    let old = row(l,slot);
    let ordinary = l.lifecycle.len();
    let cleanup = l.cleanup.len();
    let op = l.operations;
    let denied = l.denied;
    let (tag,code) = failure(l);
    assert!(old[0] != 0 && l.lifecycle_complete);
    write_words(out,&[slot as u64,active.into(),cleanup as u64]);
    for i in 0..3 {write_words(out,&row(l,i));}
    write_words(out,&[action,ordinary as u64,denied as u64,tag,code]);
    let status = match action {
        1 => l.add_shm(slot).err().unwrap_or(0) as u64,
        2 => {l.close_shm(slot); 0},
        _ => unreachable!(),
    };
    assert_eq!(status,want);
    assert!(l.lifecycle_complete);
    assert_eq!(l.operations,op);
    assert_eq!(l.active_main_handles,active);
    let (new_tag,new_code) = failure(l);
    if tag != 0 {assert_eq!((new_tag,new_code),(tag,code));}
    assert_eq!(l.denied,denied.saturating_add(if status != 0 { 1 } else { 0 }));
    let (e, event_tag) = match (action,status) {
        (1,0) => {
            assert_eq!(l.cleanup.len(),cleanup);
            assert_eq!(l.lifecycle.len(),ordinary + 1);
            let e = &l.lifecycle[ordinary];
            assert_eq!(e.action,"shm-reference");
            (Some(e),1)
        },
        (2,0) => {
            assert_eq!(l.cleanup.len(),cleanup + 1);
            assert_eq!(l.lifecycle.len(),ordinary);
            let e = &l.cleanup[cleanup];
            assert_eq!(e.action,"underlying-shm-unmap");
            (Some(e),2)
        },
        (1,13) => {
            assert_eq!(l.lifecycle.len(),ordinary);
            assert_eq!(l.cleanup.len(),cleanup);
            assert_eq!(row(l,slot),old);
            assert_eq!((new_tag,new_code), if tag == 0 {(2,13)} else {(tag,code)});
            (None,0)
        },
        _ => unreachable!(),
    };
    let post = if let Some(e) = e {
        assert_eq!(e.requested_endpoint,None);
        let got = [
            flags(old[0] & 2 != 0,e.linked,old[0] & 8 != 0),
            u64::from(e.handles),u64::from(e.pending_opens),u64::from(e.shm_references),
            e.high_water_bytes,e.actual_last_bytes,e.generation,e.device.unwrap_or(0),e.inode.unwrap_or(0),
        ];
        let mut expected = old;
        expected[3] = if action == 1 {old[3]+1} else {old[3].saturating_sub(1)};
        assert_eq!(got,expected);
        got
    } else {old};
    let mask = l.slots.iter().enumerate().fold(0,|m,(i,x)|m|(u64::from(x.is_some())<<i));
    let charge = l.slots.iter().flatten().map(|x|x.receipt.high_water_bytes).sum();
    // One u64 return-code envelope, followed by the native 18-word diagnostic.
    write_words(out,&[status,l.active_main_handles.into(),l.cleanup.len() as u64,mask,charge]);
    write_words(out,&post);
    write_words(out,&[l.lifecycle.len() as u64,l.denied as u64,new_tag,new_code,event_tag]);
}

fn main() {
    let mut out=io::stdout().lock();
    for p in [GrowthPolicy::ExactV1,GrowthPolicy::Reserve64KiBV2] {
        let mut l=Ledger::with_policy(p);
        let a=create(&mut l,"native.sqlite-shm",1,false,4097);
        for _ in 0..31 {l.add_shm(a).unwrap();}
        observe(&mut out,&mut l,a,1,0); // 31 -> 32
        observe(&mut out,&mut l,a,1,13); // 32 -> FULL (earliest)
        observe(&mut out,&mut l,a,2,0); // 32 -> 31
        let mut l=Ledger::with_policy(p);
        let a=create(&mut l,"native.sqlite-shm",2,false,65537);
        for _ in 0..31 {l.add_shm(a).unwrap();}
        assert_eq!(l.fail::<()>("fixture-prior",14),Err(14));
        observe(&mut out,&mut l,a,1,0); // no admission even after earlier sticky failure
        observe(&mut out,&mut l,a,1,13); // retains original CANTOPEN
        let mut l=Ledger::with_policy(p);
        let a=create(&mut l,"native.sqlite-shm",3,false,65537);
        observe(&mut out,&mut l,a,2,0); // zero -> zero, real event
        l.add_shm(a).unwrap();
        l.unlinked(a);
        l.close_handle(a);
        observe(&mut out,&mut l,a,2,0); // exact high-water refund
        assert!(l.slots[a].is_none());
        let mut l=Ledger::with_policy(p);
        let a=create(&mut l,"native.sqlite",4,true,4097);
        l.add_shm(a).unwrap();
        l.unlinked(a);
        l.close_handle(a);
        let b=create(&mut l,"native.sqlite",5,true,65537);
        assert_ne!(a,b);
        observe(&mut out,&mut l,a,2,0); // old generation retained while main active
        assert!(l.slots[a].is_some());
        l.close_handle(b);
        assert!(l.slots[a].is_none());
        let mut l=Ledger::with_policy(p);
        let a=create(&mut l,"native.sqlite-shm",6,false,65537);
        l.add_shm(a).unwrap();
        l.reserve_handle(a).unwrap();
        l.unlinked(a);
        l.close_handle(a);
        observe(&mut out,&mut l,a,2,0); // pending retains independently
        assert!(l.slots[a].is_some());
        let mut l=Ledger::with_policy(p);
        let a=create(&mut l,"native.sqlite-shm",7,false,65537);
        for _ in 0..255 {l.close_shm(a);}
        l.add_shm(a).unwrap();
        observe(&mut out,&mut l,a,2,0); // 255 -> 256
        observe(&mut out,&mut l,a,1,0); // cleanup-full has no bearing on ordinary add
        let mut l = Ledger::with_policy(p);
        let mut final_slot = None;
        for ino in 100..=104 {
            let a = create(&mut l, "native.sqlite-shm", ino, false, 0);
            for n in 1..=256u64 {
                if l.lifecycle.len() == 992 { break; }
                l.reserve_growth(a, n * 65_536).unwrap();
            }
            if l.lifecycle.len() == 992 {
                final_slot = Some(a);
                break;
            }
            l.unlinked(a);
            l.close_handle(a);
            assert!(l.slots[a].is_none());
        }
        let a = final_slot.expect("exact ordinary evidence prefill");
        assert_eq!(l.lifecycle.len(), 992);
        for _ in 0..31 { l.add_shm(a).unwrap(); }
        observe(&mut out, &mut l, a, 1, 0); // ordinary 1023 -> 1024; SHM 31 -> 32
        assert_eq!(l.lifecycle.len(), 1024);
        observe(&mut out, &mut l, a, 1, 13); // both full; original SHM cap wins, no mutation
        observe(&mut out, &mut l, a, 2, 0); // ordinary full does not prevent cleanup
    }
}
