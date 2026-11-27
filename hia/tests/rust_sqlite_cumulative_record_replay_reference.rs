use std::io::{self, Write};

mod original {
    include!(env!("TRNM_M15_LEDGER_ORIGINAL"));

    fn event(l: &Ledger, slot: usize, action: &'static str, request: Option<u64>) -> LifecycleReceipt {
        let r = &l.slots[slot].as_ref().unwrap().receipt;
        LifecycleReceipt {
            sequence: l.next_event, action, generation: r.generation,
            basename: r.basename.clone(), device: r.device, inode: r.inode,
            linked: r.linked, handles: r.handles, pending_opens: r.pending_opens,
            shm_references: r.shm_references, high_water_bytes: r.high_water_bytes,
            actual_last_bytes: r.actual_last_bytes, requested_endpoint: request,
        }
    }

    fn typed_words(out: &mut impl std::io::Write, e: &LifecycleReceipt, before: [u64; 8], cleanup: bool) {
        let action = match e.action {
            "reserve-open" => 1, "bind-existing-before-io-v2" => 2, "bind-real-inode" => 3,
            "reserve-growth" => 4, "reserve-handle" => 5, "opened" => 6,
            "unpublished-actual-close" => 7, "failed-open-no-methods" => 8, "shm-reference" => 9,
            "underlying-close" => 10, "underlying-shm-unmap" => 11, "unlinked" => 12,
            other => panic!("unrecognized original event {other:?}"),
        };
        assert_eq!(cleanup, matches!(action, 7 | 8 | 10 | 11 | 12));
        assert_eq!(e.sequence, before[2]);
        let option = u64::from(e.device.is_some()) | (u64::from(e.inode.is_some()) << 1)
            | (u64::from(e.requested_endpoint.is_some()) << 2);
        words(out, &[160 + e.basename.len() as u64, action, e.sequence, e.generation,
            e.device.unwrap_or(0), e.inode.unwrap_or(0), u64::from(e.linked),
            e.handles.into(), e.pending_opens.into(), e.shm_references.into(),
            e.high_water_bytes, e.actual_last_bytes, e.requested_endpoint.unwrap_or(0),
            option, before[0], before[1], before[3], before[4], before[5], before[6], before[7]]);
        out.write_all(e.basename.as_bytes()).unwrap();
    }

    fn words(out: &mut impl std::io::Write, fields: &[u64]) {
        for field in fields { out.write_all(&field.to_le_bytes()).unwrap(); }
    }

    fn counters(l: &Ledger) -> [u64; 8] {
        let tag = match l.failed.as_deref() {
            None => 0,
            Some("bounded lifecycle record cannot be retained") => 1,
            Some("base xOpen failed; pending reservation retained") => 2,
            other => panic!("unexpected retained diagnostic {other:?}"),
        };
        [
            l.lifecycle.len() as u64, l.cleanup.len() as u64, l.next_event,
            l.lifecycle_bytes as u64, u64::from(l.lifecycle_complete),
            l.denied, tag, u64::try_from(l.first_failure_code.unwrap_or(0)).unwrap(),
        ]
    }

    fn witness(out: &mut impl std::io::Write, family: u64, l: &mut Ledger, i: usize,
               action: &'static str, cleanup: bool, request: Option<u64>, expected: [u64; 2]) {
        let first = event(l, i, action, request);
        words(out, &[family]);
        typed_words(out, &first, counters(l), cleanup);
        for code in expected {
            let proposed = event(l, i, action, request);
            let prior = counters(l);
            let result = l.record_with_request(i, action, cleanup, request).err().unwrap_or(0) as u64;
            assert_eq!(result, code);
            let after = counters(l);
            words(out, &[code]);
            words(out, &after);
            words(out, &[u64::from(code == 0)]);
            if code == 0 {
                let observed = (if cleanup { l.cleanup.last() } else { l.lifecycle.last() }).unwrap();
                let bytes = serde_json::to_vec(observed).unwrap();
                assert_eq!(bytes, serde_json::to_vec(&proposed).unwrap());
                assert_eq!(after[3]-prior[3],bytes.len() as u64);
                assert_eq!(after[2],prior[2]+1);
                words(out,&[bytes.len() as u64]);
                out.write_all(&bytes).unwrap();
            } else {
                assert_eq!(after[..4],prior[..4]);
                assert_eq!(after[4],0);
                assert_eq!(after[5],prior[5]+1);
            }
        }
    }

    fn find_width(p: GrowthPolicy, width: usize) -> (Ledger, usize) {
        let mut simple = Ledger::with_policy(p);
        let i = simple.reserve_open("é_\"_/", false).unwrap();
        while simple.next_event < 9 { simple.record(i,"opened",false).unwrap(); }
        let base = serde_json::to_vec(&event(&simple,i,"underlying-shm-unmap",None)).unwrap().len();
        let name = format!("é_\"_/{}", "x".repeat(width-base));
        let mut ledger = Ledger::with_policy(p);
        let i = ledger.reserve_open(&name,false).unwrap();
        while ledger.next_event < 9 {ledger.record(i,"opened",false).unwrap();}
        assert_eq!(serde_json::to_vec(&event(&ledger,i,"underlying-shm-unmap",None)).unwrap().len(),width);
        (ledger,i)
    }
    pub fn run(out: &mut impl std::io::Write) {
        for p in [GrowthPolicy::ExactV1, GrowthPolicy::Reserve64KiBV2] {
            let request = (p == GrowthPolicy::Reserve64KiBV2).then_some(65537);
            let mut l=Ledger::with_policy(p);
            let i=l.reserve_open("fixture-é_\"_passes",false).unwrap();
            while l.next_event<9 {l.record(i,"opened",false).unwrap();}
            witness(out,0,&mut l,i,"reserve-growth",false,request,[0,0]);
            let mut l=Ledger::with_policy(p);
            let i=l.reserve_open("fixture-ordinary",false).unwrap();
            while l.lifecycle.len()<1023 {l.record(i,"opened",false).unwrap();}
            witness(out,1,&mut l,i,"opened",false,None,[0,13]);
            witness(out,2,&mut l,i,"opened",false,None,[13,13]);

            let mut l=Ledger::with_policy(p);
            let i=l.reserve_open("fixture-cleanup",false).unwrap();
            while l.cleanup.len()<255 {l.close_shm(i);}
            assert_eq!(l.cleanup.len(),255);
            witness(out,3,&mut l,i,"underlying-shm-unmap",true,None,[0,13]);
            witness(out,4,&mut l,i,"underlying-shm-unmap",true,None,[13,13]);

            let (mut l,i)=find_width(p,512);
            witness(out,5,&mut l,i,"underlying-shm-unmap",true,None,[0,13]);
            let (mut l,i)=find_width(p,513);
            assert_eq!(l.fail::<()>("base xOpen failed; pending reservation retained",ffi::SQLITE_CANTOPEN),
                       Err(ffi::SQLITE_CANTOPEN));
            witness(out,6,&mut l,i,"underlying-shm-unmap",true,None,[13,13]);
        }
    }
}

fn main() {
    original::run(&mut io::stdout().lock());
}
