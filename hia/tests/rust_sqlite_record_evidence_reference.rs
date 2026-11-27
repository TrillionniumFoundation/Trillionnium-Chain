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

    fn bytes(l: &Ledger, slot: usize, action: &'static str, request: Option<u64>) -> Vec<u8> {
        serde_json::to_vec(&event(l, slot, action, request)).unwrap()
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

    fn witness(out: &mut impl std::io::Write, l: &mut Ledger, slot: usize, action: &'static str,
               cleanup: bool, request: Option<u64>, typed: bool, include_json: bool) {
        let proposed = event(l, slot, action, request);
        let encoded = serde_json::to_vec(&proposed).unwrap();
        let before = counters(l);
        assert_eq!(before[2], before[0] + before[1]);
        if typed {
            typed_words(out, &proposed, before, cleanup);
        } else {
            words(out, &[if cleanup { 2 } else { 1 }, encoded.len() as u64]);
            words(out, &before);
        }
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
        if include_json && status == 0 {
            let actual = if cleanup { l.cleanup.last() } else { l.lifecycle.last() }.unwrap();
            let retained = serde_json::to_vec(actual).unwrap();
            words(out, &[retained.len() as u64]);
            out.write_all(&retained).unwrap();
        }
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

    pub fn replay_cases(out: &mut impl std::io::Write, typed: bool, include_json: bool) {
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
                    witness(out, &mut l, slot, action, cleanup, bound, typed, include_json);
                }
            }

            let mut ordinary = Ledger::with_policy(policy);
            let o = ordinary.reserve_open("ordinary", false).unwrap();
            while ordinary.lifecycle.len() < LIFECYCLE_EVENTS - 1 {
                ordinary.record(o, "shm-reference", false).unwrap();
            }
            witness(out, &mut ordinary, o, "shm-reference", false, None, typed, include_json);
            witness(out, &mut ordinary, o, "shm-reference", false, None, typed, include_json);
            witness(out, &mut ordinary, o, "underlying-shm-unmap", true, None, typed, include_json);
            let mut cleanup = Ledger::with_policy(policy);
            let c = cleanup.reserve_open("cleanup", false).unwrap();
            for _ in 0..CLEANUP_EVENTS - 1 {
                cleanup.close_shm(c);
            }
            witness(out, &mut cleanup, c, "underlying-shm-unmap", true, None, typed, include_json);
            witness(out, &mut cleanup, c, "underlying-shm-unmap", true, None, typed, include_json);
            witness(out, &mut cleanup, c, "shm-reference", false, None, typed, include_json);

            let (mut failed, n) = exact_name(policy, 513, "underlying-shm-unmap", None);
            assert_eq!(failed.fail::<()>("base xOpen failed; pending reservation retained",
                                         ffi::SQLITE_CANTOPEN), Err(ffi::SQLITE_CANTOPEN));
            witness(out, &mut failed, n, "underlying-shm-unmap", true, None, typed, include_json);
            // Shorter original event still succeeds despite prior failure.
            witness(out, &mut failed, n, "opened", false, None, typed, include_json);
            if typed {
                let mut all = Ledger::with_policy(policy);
                let slot = all.reserve_open(r#"all-é_"_routes"#, true).unwrap();
                all.observe_existing_before_io(slot, Identity { dev: 9, ino: 10 }, 17, 1, true).unwrap();
                all.reserve_handle(slot).unwrap();
                for (action, cleanup, request) in [
                    ("reserve-open", false, None), ("bind-existing-before-io-v2", false, Some(17)),
                    ("bind-real-inode", false, None), ("reserve-handle", false, None),
                    ("unpublished-actual-close", true, None), ("failed-open-no-methods", true, None),
                    ("underlying-close", true, None), ("unlinked", true, None),
                ] {
                    witness(out, &mut all, slot, action, cleanup, request, typed, include_json);
                }
            }
        }
    }
}

fn main() {
    let mode = std::env::args().nth(1);
    let include_json = mode.as_deref() == Some("--retained-json");
    let typed = include_json || mode.as_deref() == Some("--typed");
    original::replay_cases(&mut io::stdout().lock(), typed, include_json);
}
