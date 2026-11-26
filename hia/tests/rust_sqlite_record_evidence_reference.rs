use std::io::{self, Write};

mod original {
    include!(env!("TRNM_M15_LEDGER_ORIGINAL"));

    fn bytes(l: &Ledger, slot: usize, action: &'static str, request: Option<u64>) -> Vec<u8> {
        let r = &l.slots[slot].as_ref().unwrap().receipt;
        serde_json::to_vec(&LifecycleReceipt {
            sequence: l.next_event, action, generation: r.generation,
            basename: r.basename.clone(), device: r.device, inode: r.inode,
            linked: r.linked, handles: r.handles, pending_opens: r.pending_opens,
            shm_references: r.shm_references, high_water_bytes: r.high_water_bytes,
            actual_last_bytes: r.actual_last_bytes, requested_endpoint: request,
        }).unwrap()
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

    fn witness(out: &mut impl std::io::Write, l: &mut Ledger, slot: usize, action: &'static str,
               cleanup: bool, request: Option<u64>) {
        let encoded = bytes(l, slot, action, request);
        let before = counters(l);
        assert_eq!(before[2], before[0] + before[1]);
        words(out, &[if cleanup { 2 } else { 1 }, encoded.len() as u64]);
        words(out, &before);
        let status = l.record_with_request(slot, action, cleanup, request).err().unwrap_or(0);
        let after = counters(l);
        if status == 0 {
            let actual = if cleanup { l.cleanup.last() } else { l.lifecycle.last() }.unwrap();
            assert_eq!(serde_json::to_vec(actual).unwrap(), encoded);
            assert_eq!(after[3] - before[3], encoded.len() as u64);
            assert_eq!(after[2], before[2] + 1);
        } else {
            assert_eq!(status, ffi::SQLITE_FULL);
            assert_eq!(after[..4], before[..4]);
            assert_eq!(after[4], 0);
        }
        words(out, &[status as u64]);
        words(out, &after);
        words(out, &[u64::from(status == 0)]);
    }

    fn exact_name(policy: GrowthPolicy, target: usize, action: &'static str, request: Option<u64>) -> (Ledger, usize) {
        for n in 1..512 {
            let name = format!("fixture-é_\\\"_{}", "x".repeat(n));
            let mut l = Ledger::with_policy(policy);
            if let Ok(slot) = l.reserve_open(&name, false) {
                if bytes(&l, slot, action, request).len() == target {
                    return (l, slot);
                }
            }
        }
        panic!("no reachable exact JSON width {target}");
    }

    pub fn replay_cases(out: &mut impl std::io::Write) {
        for policy in [GrowthPolicy::ExactV1, GrowthPolicy::Reserve64KiBV2] {
            let request = if policy == GrowthPolicy::ExactV1 { None } else { Some(65537) };
            for width in [511, 512, 513] {
                for cleanup in [false, true] {
                    let (action, bound) = if cleanup {
                        ("underlying-shm-unmap", None)
                    } else {
                        ("reserve-growth", request)
                    };
                    let (mut l, slot) = exact_name(policy, width, action, bound);
                    witness(out, &mut l, slot, action, cleanup, bound);
                }
            }

            let mut ordinary = Ledger::with_policy(policy);
            let o = ordinary.reserve_open("ordinary", false).unwrap();
            while ordinary.lifecycle.len() < LIFECYCLE_EVENTS - 1 {
                ordinary.record(o, "shm-reference", false).unwrap();
            }
            witness(out, &mut ordinary, o, "shm-reference", false, None);
            witness(out, &mut ordinary, o, "shm-reference", false, None);
            witness(out, &mut ordinary, o, "underlying-shm-unmap", true, None);
            let mut cleanup = Ledger::with_policy(policy);
            let c = cleanup.reserve_open("cleanup", false).unwrap();
            for _ in 0..CLEANUP_EVENTS - 1 {
                cleanup.close_shm(c);
            }
            witness(out, &mut cleanup, c, "underlying-shm-unmap", true, None);
            witness(out, &mut cleanup, c, "underlying-shm-unmap", true, None);
            witness(out, &mut cleanup, c, "shm-reference", false, None);

            let (mut failed, n) = exact_name(policy, 513, "underlying-shm-unmap", None);
            assert_eq!(failed.fail::<()>("base xOpen failed; pending reservation retained",
                                         ffi::SQLITE_CANTOPEN), Err(ffi::SQLITE_CANTOPEN));
            witness(out, &mut failed, n, "underlying-shm-unmap", true, None);
            // Shorter original event still succeeds despite prior failure.
            witness(out, &mut failed, n, "opened", false, None);
        }
    }
}

fn main() {
    original::replay_cases(&mut io::stdout().lock());
}
