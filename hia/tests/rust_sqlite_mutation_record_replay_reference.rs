use std::io::{self, Write};

mod original {
    include!(env!("TRNM_M15_LEDGER_ORIGINAL"));

    fn words(out: &mut impl std::io::Write, values: &[u64]) {
        for n in values { out.write_all(&n.to_le_bytes()).unwrap(); }
    }

    fn before(l: &Ledger) -> [u64; 7] {
        let why = match l.failed.as_deref() {
            None => 0,
            Some("bounded lifecycle record cannot be retained") => 1,
            Some("base xOpen failed; pending reservation retained") => 2,
            x => panic!("unrecognized first failure {x:?}"),
        };
        [l.lifecycle.len() as u64, l.cleanup.len() as u64, l.lifecycle_bytes as u64,
         l.lifecycle_complete.into(), l.denied, why, l.first_failure_code.unwrap_or(0) as u64]
    }

    fn row(object: Option<&Object>) -> [u64; 9] {
        object.map_or([0; 9], |o| {
            let r = &o.receipt;
            let flags = 1 | (u64::from(o.main) << 1) | (u64::from(r.linked) << 2)
                | (u64::from(r.reserved_pending_open) << 3);
            [flags, r.handles.into(), r.pending_opens.into(), r.shm_references.into(),
             r.high_water_bytes, r.actual_last_bytes, r.generation, r.device.unwrap_or(0), r.inode.unwrap_or(0)]
        })
    }

    fn observe(out: &mut impl std::io::Write, l: &mut Ledger, slot: usize,
               action: u64, expected_code: u64, chosen_kept: bool, family: u64) {
        let r = &l.slots[slot].as_ref().unwrap().receipt;
        let (label, cleanup, handles, pending, shm, linked) = match action {
            6 => ("opened", false, r.handles + 1, r.pending_opens - 1, r.shm_references, r.linked),
            7 => ("unpublished-actual-close", true, r.handles, r.pending_opens - 1, r.shm_references, r.linked),
            8 => ("failed-open-no-methods", true, r.handles, r.pending_opens - 1, r.shm_references, r.linked),
            9 => ("shm-reference", false, r.handles, r.pending_opens, r.shm_references + 1, r.linked),
            10 => ("underlying-close", true, r.handles - 1, r.pending_opens, r.shm_references, r.linked),
            11 => ("underlying-shm-unmap", true, r.handles, r.pending_opens, r.shm_references.saturating_sub(1), r.linked),
            12 => ("unlinked", true, r.handles, r.pending_opens, r.shm_references, false),
            _ => unreachable!(),
        };
        let proposed = LifecycleReceipt {
            sequence: l.next_event, action: label, generation: r.generation, basename: r.basename.clone(),
            device: r.device, inode: r.inode, linked, handles, pending_opens: pending, shm_references: shm,
            high_water_bytes: r.high_water_bytes, actual_last_bytes: r.actual_last_bytes,
            requested_endpoint: None,
        };
        let opts = u64::from(proposed.device.is_some()) | (u64::from(proposed.inode.is_some()) << 1);
        let prior = before(l);
        let active = l.active_main_handles;
        let main = l.slots[slot].as_ref().unwrap().main;
        let operations = l.operations;
        let peak = l.retained_logical_bytes_peak;
        words(out, &[family, 392 + proposed.basename.len() as u64,
            action, proposed.sequence, proposed.generation,
            proposed.device.unwrap_or(0), proposed.inode.unwrap_or(0), proposed.linked.into(),
            proposed.handles.into(), proposed.pending_opens.into(), proposed.shm_references.into(),
            proposed.high_water_bytes, proposed.actual_last_bytes, 0, opts]);
        words(out, &prior);
        words(out, &[slot as u64, active.into()]);
        for i in 0..OBJECTS_PER_ROOT { words(out, &row(l.slots[i].as_ref())); }
        out.write_all(proposed.basename.as_bytes()).unwrap();
        let status = match action {
            6 => l.opened(slot).err().unwrap_or(0),
            7 | 8 => { l.release_pending(slot, label); 0 },
            9 => l.add_shm(slot).err().unwrap_or(0),
            10 => { l.close_handle(slot); 0 },
            11 => { l.close_shm(slot); 0 },
            12 => { l.unlinked(slot); 0 },
            _ => unreachable!(),
        };
        let outer = status as u64;
        assert_eq!(outer, if cleanup { 0 } else { expected_code });
        assert_eq!(l.operations,operations);
        assert_eq!(l.retained_logical_bytes_peak,peak);
        assert_eq!(l.active_main_handles, active - u32::from(matches!(action, 7 | 8 | 10) && main));
        assert_eq!(l.slots[slot].is_some(),chosen_kept);
        if let Some(o) = &l.slots[slot] {
            assert_eq!((o.receipt.handles,o.receipt.pending_opens,o.receipt.shm_references),
                       (proposed.handles,proposed.pending_opens,proposed.shm_references));
        }
        let after = before(l);
        let code = if l.next_event == proposed.sequence { 13 } else { 0 };
        assert_eq!(code, expected_code);
        let bytes = if code == 0 {
            let event = if cleanup {l.cleanup.last()} else {l.lifecycle.last()}.unwrap();
            let actual = serde_json::to_vec(event).unwrap();
            assert_eq!(actual,serde_json::to_vec(&proposed).unwrap());
            assert_eq!(l.next_event,proposed.sequence+1);
            assert_eq!(after[2]-prior[2],actual.len() as u64);
            actual
        } else {
            assert_eq!(after[..3],prior[..3]);
            assert_eq!(after[3],0);
            assert_eq!(after[4],prior[4]+1);
            assert_eq!(after[5..],if prior[5] == 0 { [1,13] } else { [prior[5],prior[6]] });
            Vec::new()
        };
        let mask = l.slots.iter().enumerate().fold(0, |m,(i,o)|m|(u64::from(o.is_some())<<i));
        let charge = l.slots.iter().flatten().map(|o|o.receipt.high_water_bytes).sum();
        words(out,&[outer,after[0],after[1],l.next_event,after[2],after[3],after[4],after[5],after[6],
            u64::from(code == 0),proposed.handles.into(),proposed.pending_opens.into(),
            proposed.shm_references.into(),mask,charge,code,l.active_main_handles.into()]);
        if !bytes.is_empty() { words(out,&[bytes.len() as u64]); out.write_all(&bytes).unwrap(); }
    }

    fn create(l: &mut Ledger, name: &str, ino: u64, main: bool, end: u64) -> usize {
        let i = l.reserve_open(name,main).unwrap();
        l.bind(i,Identity {dev:7,ino},0,0,true).unwrap();
        l.reserve_growth(i,end).unwrap();
        l.bind(i,Identity {dev:7,ino},end,1,true).unwrap();
        l.reserve_handle(i).unwrap();
        l.opened(i).unwrap();
        i
    }

    fn ordinary_full(p: GrowthPolicy) -> (Ledger,usize) {
        let mut l = Ledger::with_policy(p);
        for ino in 10..=14 {
            let s = create(&mut l,"fixture-open",ino,false,0);
            l.reserve_handle(s).unwrap();
            for n in 1..=256u64 {
                if l.lifecycle.len() == 992 { break; }
                l.reserve_growth(s,n*65_536).unwrap();
            }
            if l.lifecycle.len() == 992 {
                for _ in 0..32 {l.add_shm(s).unwrap();}
                assert_eq!(l.lifecycle.len(),1024);
                assert_eq!(l.slots[s].as_ref().unwrap().receipt.pending_opens,1);
                return (l,s);
            }
            l.unlinked(s);
            l.release_pending(s, "failed-open-no-methods");
            l.close_handle(s);
            assert!(l.slots[s].is_none());
        }
        unreachable!("exact lifecycle prefill")
    }

    fn cleanup_full(p: GrowthPolicy, main: bool) -> (Ledger,usize) {
        let mut l = Ledger::with_policy(p);
        let s = create(&mut l,"fixture-old",31,main,65537);
        let peer = create(&mut l,"fixture-peer",32,main,4097);
        while l.cleanup.len()<255 {l.close_shm(peer);}
        l.unlinked(s);
        assert_eq!(l.cleanup.len(),256);
        (l,s)
    }

    pub fn run(out: &mut impl std::io::Write) {
        for p in [GrowthPolicy::ExactV1, GrowthPolicy::Reserve64KiBV2] {
            let (mut l,i)=ordinary_full(p);
            observe(out,&mut l,i,6,13,true,0);
            let (mut l,i)=ordinary_full(p);
            l.close_shm(i);
            assert_eq!(l.fail::<()>("base xOpen failed; pending reservation retained",ffi::SQLITE_CANTOPEN),
                       Err(ffi::SQLITE_CANTOPEN));
            observe(out,&mut l,i,9,13,true,1);
            let (mut l,i)=cleanup_full(p,false);
            observe(out,&mut l,i,10,13,false,2);
            let (mut l,i)=cleanup_full(p,true);
            observe(out,&mut l,i,10,13,true,3);
            let mut l=Ledger::with_policy(p);
            let i=create(&mut l,"fixture-é_\"_normal",70,false,4097);
            l.reserve_handle(i).unwrap();
            observe(out,&mut l,i,6,0,true,4);
            observe(out,&mut l,i,9,0,true,5);
            observe(out,&mut l,i,11,0,true,6);
            l.reserve_handle(i).unwrap();
            observe(out,&mut l,i,7,0,true,7);
            l.reserve_handle(i).unwrap();
            observe(out,&mut l,i,8,0,true,8);
            observe(out,&mut l,i,10,0,true,9);
            observe(out,&mut l,i,10,0,true,10);
            observe(out,&mut l,i,12,0,false,11);

            let mut l=Ledger::with_policy(p);
            let i=create(&mut l,"fixture-cancel",71,true,4097);
            l.reserve_handle(i).unwrap();
            l.close_handle(i);
            let peer=create(&mut l,"fixture-peer",72,false,65537);
            while l.cleanup.len()<255 {l.close_shm(peer);}
            l.unlinked(i); // full and retained by pending MAIN claim
            observe(out,&mut l,i,7,13,false,12);

            let mut l=Ledger::with_policy(p);
            let i=create(&mut l,"fixture-unlink",73,false,4097);
            l.close_handle(i);
            let peer=create(&mut l,"fixture-peer",74,false,65537);
            while l.cleanup.len()<256 {l.close_shm(peer);}
            observe(out,&mut l,i,12,13,false,13);

            let mut l=Ledger::with_policy(p);
            let i=create(&mut l,"fixture-unmap",75,false,4097);
            l.add_shm(i).unwrap();
            l.close_handle(i);
            let peer=create(&mut l,"fixture-peer",76,false,65537);
            while l.cleanup.len()<255 {l.close_shm(peer);}
            l.unlinked(i);
            observe(out,&mut l,i,11,13,false,14);
        }
    }
}

fn main() {
    original::run(&mut io::stdout().lock());
}
