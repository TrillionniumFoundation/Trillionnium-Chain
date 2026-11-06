//! Real retained headers compare the original two-walk check with one local
//! window. The fixture still mines, verifies, commits and reopens native PNP2.
use super::*;
use std::sync::Mutex;

#[test]
fn native_growth_v2_header_program_reuse_rebinds_each_block_and_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone()).unwrap();
    let first = make(&node, settings.genesis(), vec![]);
    let first_id = admit(&mut node, &first);
    let second = make(&node, first_id, vec![]);
    let second_id = admit(&mut node, &second);
    let before = rows(&node.db);
    node.db.flush_prepared_statement_cache();
    for (id, expected) in [
        (first_id, &first.header),
        (second_id, &second.header),
        (first_id, &first.header),
    ] {
        assert_eq!(&node.growth_header(id).unwrap(), expected);
    }
    // Observe the real retained SQLite VM. A freshly prepared SQL program has
    // zero runs; this proves repeated callers actually reused the cached one.
    {
        let statement = node.db.prepare_cached(GROWTH_HEADER_SQL).unwrap();
        assert_eq!(statement.reset_status(rusqlite::StatementStatus::Run), 3);
        assert_eq!(
            statement.reset_status(rusqlite::StatementStatus::RePrepare),
            0
        );
    }
    assert!(node.growth_header([0; 32]).is_err());
    assert_eq!(node.growth_header(second_id).unwrap(), second.header);
    assert_eq!(rows(&node.db), before);
    drop(node);
    let node = Node::open_with_permanent_account_growth_v2(directory.path(), settings).unwrap();
    assert_eq!(node.growth_header(first_id).unwrap(), first.header);
    assert_eq!(node.growth_header(second_id).unwrap(), second.header);
    assert_eq!(rows(&node.db), before);
}

#[test]
fn native_growth_v2_warm_header_program_reads_changed_prefix_trace_and_length() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone()).unwrap();
    let first = make(&node, settings.genesis(), vec![]);
    let id = admit(&mut node, &first);
    let raw = first.encode().unwrap();
    let before = rows(&node.db);
    for fault in 0..6 {
        assert_eq!(node.growth_header(id).unwrap(), first.header);
        let mut changed = raw.clone();
        let expected = match fault {
            0 => {
                changed[0] ^= 1;
                "GROWTH_PACKET_LENGTH"
            }
            1 => {
                changed[4] ^= 1;
                "HEADER_CODEC"
            }
            2 => {
                let last = changed.len() - 1;
                changed[last] ^= 1;
                "GROWTH_PACKET_ID"
            }
            3 => {
                changed.truncate(4 + trnm_protocol::pon_growth::GROWTH_HEADER_BYTES);
                "GROWTH_PACKET_LENGTH"
            }
            4 => {
                changed.resize(limits::MAX_PACKET_BYTES + 1, 0);
                "GROWTH_PACKET_LENGTH"
            }
            5 => {
                let mut header = first.header.clone();
                header.ledger.timestamp += 1;
                let encoded = header.encode();
                changed[4..4 + encoded.len()].copy_from_slice(&encoded);
                "GROWTH_PACKET_ID"
            }
            _ => unreachable!(),
        };
        let transaction = node.db.unchecked_transaction().unwrap();
        assert_eq!(
            transaction
                .execute(
                    "UPDATE blocks SET packet=? WHERE id=?",
                    params![changed, id.as_slice()],
                )
                .unwrap(),
            1
        );
        assert_eq!(node.growth_header(id).unwrap_err().to_string(), expected);
        transaction.rollback().unwrap();
        assert_eq!(node.growth_header(id).unwrap(), first.header);
        assert_eq!(rows(&node.db), before);
        assert!(node.db.is_autocommit());
    }
}

// The original check is deliberately retained as a test-only oracle. It obtains
// target and median-time inputs through separate native reads, as before.
fn original_check(node: &Node, packet: &GrowthPacket, now: u64) -> Result<()> {
    original_check_with_progress(node, packet, now, &|_| Ok(()))
}

fn original_check_with_progress(
    node: &Node,
    packet: &GrowthPacket,
    now: u64,
    progress: &(impl Fn(GrowthProgress) -> Result<()> + Sync),
) -> Result<()> {
    let h = &packet.header.ledger;
    ensure(
        h.network == node.settings.network() && h.parameters == node.settings.parameters(),
        "NETWORK",
    )?;
    ensure(
        node.record(h.parent)?.height.checked_add(1) == Some(h.height)
            && h.height <= i64::MAX as u64,
        "HEIGHT",
    )?;
    let height = consensus::BranchTargetHeight::after(node.record(h.parent)?.height)?;
    let recent = node.growth_recent_with_progress(h.parent, progress)?;
    let interval = node.settings.limit("retarget_interval")?;
    let target = match height.window(&recent, interval)? {
        consensus::TargetWindow::Parent(target) => target,
        consensus::TargetWindow::Retarget {
            target,
            first,
            last,
        } => consensus::retarget(
            target,
            first,
            last,
            interval,
            node.settings.limit("target_spacing_seconds")?,
            node.settings.target("pow_limit_hex")?,
        )?,
    };
    ensure(h.target == target, "TARGET")?;
    ensure(
        h.transactions == sequence_root("transactions", &packet.transactions),
        "ROOT",
    )?;
    ensure(
        h.work_task == continuity_v1::maintenance_task()?,
        "CONTINUITY_MAINTENANCE",
    )?;
    let times: Vec<_> = node
        .growth_recent_with_progress(h.parent, progress)?
        .iter()
        .take(11)
        .map(|item| item.0)
        .collect();
    consensus::check_time(
        h.timestamp,
        &times,
        now,
        node.settings.limit("future_skew_seconds")?,
    )
}

fn outcome(result: Result<()>) -> std::result::Result<(), String> {
    result.map_err(|error| error.to_string())
}

fn differential(node: &Node, packet: &GrowthPacket, now: u64) {
    assert_eq!(
        outcome(node.check_growth_header(packet, now)),
        outcome(original_check(node, packet, now)),
        "height={}, timestamp={}, now={now}",
        packet.header.ledger.height,
        packet.header.ledger.timestamp,
    );
}

#[test]
fn native_growth_v2_single_header_window_preserves_retarget_time_and_error_order() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone()).unwrap();
    let mut parent = settings.genesis();
    let mut parents = vec![parent];
    for _ in 0..20 {
        let packet = make(&node, parent, vec![]);
        differential(&node, &packet, 100_000);
        for timestamp in [0, 1, 40, 110, packet.header.ledger.timestamp, 200_001] {
            for now in [0, 1, 100_000] {
                let mut candidate = packet.clone();
                candidate.header.ledger.timestamp = timestamp;
                differential(&node, &candidate, now);
            }
        }
        // Doubly-invalid inputs preserve the original refusal precedence.
        for fault in 0..7 {
            let mut candidate = packet.clone();
            candidate.header.ledger.timestamp = 0;
            match fault {
                0 => candidate.header.ledger.network[0] ^= 1,
                1 => candidate.header.ledger.parameters[0] ^= 1,
                2 => candidate.header.ledger.height = 0,
                3 => candidate.header.ledger.parent = [0; 32],
                4 => candidate.header.ledger.target = [0; 32],
                5 => candidate.header.ledger.transactions[0] ^= 1,
                6 => candidate.header.ledger.work_task[0] ^= 1,
                _ => unreachable!(),
            }
            differential(&node, &candidate, 100_000);
        }
        parent = admit(&mut node, &packet);
        parents.push(parent);
    }
    // A retained fork uses its own parent window; the active tip is no input.
    let mut fork = parents[4];
    for height in 5..=16 {
        let txs = if height == 5 {
            vec![transfer(&settings, 0, 1, public(88), 1000)]
        } else {
            vec![]
        };
        let packet = make(&node, fork, txs);
        differential(&node, &packet, 100_000);
        fork = node.admit_growth(&packet, 100_000).unwrap();
    }
    let retained = make(&node, fork, vec![]);
    differential(&node, &retained, 100_000);
    let active = node.active().unwrap();
    drop(node);
    let node = Node::open_with_permanent_account_growth_v2(directory.path(), settings).unwrap();
    assert_eq!(node.active().unwrap(), active);
    differential(&node, &retained, 100_000);
}

#[test]
fn native_growth_v2_single_header_window_reloads_each_admission_context() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone()).unwrap();
    let mut parent = settings.genesis();
    for _ in 0..3 {
        let packet = make(&node, parent, vec![]);
        parent = admit(&mut node, &packet);
    }
    let packet = make(
        &node,
        parent,
        vec![transfer(&settings, 0, 1, public(89), 1000)],
    );
    let before = rows(&node.db);
    let active = node.active().unwrap();
    // All three current context checks remain cancellable: initial precheck,
    // after full W1/owner reacquisition, and inside the write transaction.
    for cut in 0..9 {
        let calls = AtomicUsize::new(0);
        let error = node
            .admit_growth_with_progress(&packet, 100_000, &|point| {
                if matches!(point, GrowthProgress::HeaderAncestor { .. })
                    && calls.fetch_add(1, Ordering::Relaxed) == cut
                {
                    return Err("HEADER_WINDOW_CANCELLED".into());
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "HEADER_WINDOW_CANCELLED");
        assert_eq!(calls.load(Ordering::Relaxed), cut + 1);
        assert_eq!(node.active().unwrap(), active);
        assert_eq!(rows(&node.db), before);
        assert!(node.db.is_autocommit());
    }
    let calls = Mutex::new(Vec::new());
    let id = node
        .admit_growth_with_progress(&packet, 100_000, &|point| {
            if let GrowthProgress::HeaderAncestor { index } = point {
                calls.lock().unwrap().push(index);
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(*calls.lock().unwrap(), vec![0, 1, 2, 0, 1, 2, 0, 1, 2]);
    assert_eq!(node.active().unwrap(), active);
    node.activate(id).unwrap();
    assert_eq!(
        node.growth_account(id, public(89))
            .unwrap()
            .unwrap()
            .balance,
        1000
    );
    assert_eq!(
        node.growth_account(id, public(0)).unwrap().unwrap().nonce,
        1
    );
    let after = rows(&node.db);
    drop(node);
    let node = Node::open_with_permanent_account_growth_v2(directory.path(), settings).unwrap();
    assert_eq!(node.active().unwrap().0, id);
    assert_eq!(rows(&node.db), after);
}

#[test]
fn native_growth_v2_single_header_window_still_rejects_changed_retained_headers() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone()).unwrap();
    let first = make(&node, settings.genesis(), vec![]);
    let parent = admit(&mut node, &first);
    let packet = make(&node, parent, vec![]);
    let active = node.active().unwrap();
    let before = rows(&node.db);
    for sql in [
        "UPDATE blocks SET state_root=zeroblob(32) WHERE height=1",
        "UPDATE blocks SET parent=zeroblob(32) WHERE height=1",
        "UPDATE blocks SET packet=zeroblob(length(packet)) WHERE height=1",
    ] {
        let transaction = node.db.unchecked_transaction().unwrap();
        transaction.execute(sql, []).unwrap();
        let old = outcome(original_check(&node, &packet, 100_000));
        assert!(old.is_err());
        assert_eq!(outcome(node.check_growth_header(&packet, 100_000)), old);
        transaction.rollback().unwrap();
        assert_eq!(node.active().unwrap(), active);
        assert_eq!(rows(&node.db), before);
    }
}

// The owner lock cannot prevent another SQLite connection from committing.
// An audited epoch must be checked after an operation-local header window,
// including the exact-duplicate fast return. A second full walk happened to
// detect this cut in the original algorithm, but was not an epoch fence.
#[test]
fn native_growth_v2_single_header_window_foreign_write_refuses_before_work_or_duplicate_return() {
    for original in [true, false] {
        for existing in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let settings = settings();
            let mut node =
                Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone())
                    .unwrap();
            let first = make(&node, settings.genesis(), vec![]);
            let first_id = admit(&mut node, &first);
            let second = make(&node, first_id, vec![]);
            let parent = admit(&mut node, &second);
            let packet = make(
                &node,
                parent,
                vec![transfer(&settings, 0, 1, public(90), 1000)],
            );
            if existing {
                admit(&mut node, &packet);
            }
            let active = node.active().unwrap();
            let own_changes = node.db.total_changes();
            let path = directory.path().join("native.sqlite");
            let changed = AtomicBool::new(false);
            let work = AtomicUsize::new(0);
            let foreign_rows = Mutex::new(None);
            let progress = |point| {
                if point == (GrowthProgress::HeaderAncestor { index: 1 })
                    && !changed.swap(true, Ordering::Relaxed)
                {
                    // Header index 0's parent record has already been read.
                    // Use a real separate committed writer, not owner.db.
                    let foreign = Connection::open(&path)?;
                    ensure(
                        foreign.execute(
                            "UPDATE blocks SET state_root=zeroblob(32) WHERE id=?",
                            [parent.as_slice()],
                        )? == 1,
                        "TEST_FOREIGN_WRITE",
                    )?;
                    *foreign_rows.lock().unwrap() = Some(rows(&foreign));
                }
                if matches!(point, GrowthProgress::Work(_)) {
                    work.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            };
            let result = if original {
                original_check_with_progress(&node, &packet, 100_000, &progress)
            } else {
                node.admit_growth_with_progress(&packet, 100_000, &progress)
                    .map(|_| ())
            };
            assert!(changed.load(Ordering::Relaxed));
            assert_eq!(
                outcome(result),
                Err(if original {
                    "GROWTH_HEADER_RECORD"
                } else {
                    "GROWTH_STORAGE_EPOCH_CHANGED"
                }
                .into()),
                "original={original}, existing={existing}"
            );
            assert_eq!(work.load(Ordering::Relaxed), 0);
            assert_eq!(node.active().unwrap(), active);
            assert_eq!(node.db.total_changes(), own_changes);
            assert!(node.db.is_autocommit());
            assert_eq!(rows(&node.db), foreign_rows.into_inner().unwrap().unwrap());
        }
    }
}

#[test]
fn native_growth_v2_single_header_window_keeps_epoch_fences_before_and_after_precheck() {
    for after_precheck in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = settings();
        let mut node =
            Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone())
                .unwrap();
        let first = make(&node, settings.genesis(), vec![]);
        let parent = admit(&mut node, &first);
        let packet = make(
            &node,
            parent,
            vec![transfer(&settings, 0, 1, public(91), 1000)],
        );
        let active = node.active().unwrap();
        let own_changes = node.db.total_changes();
        let path = directory.path().join("native.sqlite");
        let changed = AtomicBool::new(false);
        let work = AtomicUsize::new(0);
        let foreign_rows = Mutex::new(None);
        let cut = if after_precheck {
            GrowthProgress::BeforeWork
        } else {
            GrowthProgress::BeforeContext
        };
        let error = node
            .admit_growth_with_progress(&packet, 100_000, &|point| {
                if point == cut && !changed.swap(true, Ordering::Relaxed) {
                    let foreign = Connection::open(&path)?;
                    ensure(
                        foreign.execute(
                            "UPDATE blocks SET state_root=zeroblob(32) WHERE id=?",
                            [parent.as_slice()],
                        )? == 1,
                        "TEST_FOREIGN_WRITE",
                    )?;
                    *foreign_rows.lock().unwrap() = Some(rows(&foreign));
                }
                if matches!(point, GrowthProgress::Work(_)) {
                    work.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "GROWTH_STORAGE_EPOCH_CHANGED");
        assert!(changed.load(Ordering::Relaxed));
        // W1 owns only an immutable packet and no Node lock. A write after
        // precheck is detected when the original owner is reacquired; no
        // context or authorization is cached from before that work.
        assert_eq!(work.load(Ordering::Relaxed) > 0, after_precheck);
        assert_eq!(node.active().unwrap(), active);
        assert_eq!(node.db.total_changes(), own_changes);
        assert!(node.db.is_autocommit());
        assert_eq!(rows(&node.db), foreign_rows.into_inner().unwrap().unwrap());
    }
}
