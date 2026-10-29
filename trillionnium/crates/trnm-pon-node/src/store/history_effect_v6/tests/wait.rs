//! Failures before the original CPU begin retain the original nonrefundable
//! reservation. They are NotStarted facts, never measured-zero settlements.
use super::*;
use std::cell::Cell;

fn cold_not_started(a: &TestAuthority, expected: &str) -> (Anchor, Value) {
    let mut records: Vec<_> = fs::read_dir(&a.journal)
        .unwrap()
        .map(|row| row.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "json"))
        .collect();
    records.sort();
    let mut outside = Anchor::empty();
    let mut intents = 0;
    let mut refused = 0;
    for path in records {
        let raw = fs::read(path).unwrap();
        let frame: journal::Frame = serde_json::from_slice(&raw).unwrap();
        outside = Anchor {
            sequence: frame.sequence,
            digest: policy::digest(&raw),
        };
        match frame.event {
            journal::Event::Budget { .. } => {}
            journal::Event::Intent { .. } => intents += 1,
            journal::Event::NotStarted {
                operation,
                original_error,
            } => {
                refused += 1;
                assert_eq!(operation, a.id(1));
                assert_eq!(original_error, expected);
            }
            _ => panic!("wait created a CPU settlement, effect or epoch-close event"),
        }
    }
    assert_eq!((intents, refused), (1, 1));
    let journal = journal::Journal::open_existing(
        &a.journal,
        rustix::process::geteuid().as_raw(),
        &a.identity,
        &outside,
    )
    .unwrap();
    let observed = journal.observation();
    assert_eq!(observed["pending"], Value::Null);
    assert_eq!(observed["epoch"], Value::Null);
    assert_eq!(observed["known_settlements"], 0);
    assert_eq!(observed["used_operations"], 1);
    assert_eq!(observed["request_nonce"], 1);
    assert_eq!(observed["spent"]["cpu_ns"], 4_000_000_000u64);
    assert_eq!(observed["spent"]["operations"], 1);
    assert!(!a.store.exists(), "wait entered Native initialization");
    (outside, observed)
}

#[test]
fn zero_credit_wait_interruptions_record_not_started_without_refund() {
    for mode in [
        "cancel",
        "deadline",
        "operation-expiry",
        "budget-expiry",
        "boundary-error",
    ] {
        let a = if mode == "budget-expiry" {
            TestAuthority::with_budget_lifetime(2_000_000_000)
        } else {
            TestAuthority::new()
        };
        let _retain = process::retain_fixture(a.f.dir.path(), &format!("startup-wait-{mode}"));
        let (path, sha) = a.launch(mode, 1, 1, a.genesis(), a.installed.clone());
        let (path, sha) = if mode == "operation-expiry" {
            let mut config = read(&path);
            let raw: Vec<u8> = serde_json::from_value(config["signed_startup"].clone()).unwrap();
            let mut envelope: policy::Envelope<Operation> = serde_json::from_slice(&raw).unwrap();
            envelope.body.expires_ns = policy::now().unwrap() + 2_000_000_000;
            config["signed_startup"] = json!(signed(b'O', &envelope.body));
            let revised = a.f.dir.path().join("wait-expiring-operation.json");
            let sha = write_value(&revised, &config);
            (revised, sha)
        } else {
            (path, sha)
        };
        let cancellation = HistoryEffectV6StartupCancellation::for_operation(&a.id(1)).unwrap();
        let (signal, receive) = std::sync::mpsc::sync_channel(1);
        let cancel_worker = if mode == "cancel" {
            let request = cancellation.clone();
            Some(std::thread::spawn(move || {
                receive.recv_timeout(Duration::from_secs(2)).unwrap();
                request.cancel();
            }))
        } else {
            None
        };
        let polls = Cell::new(0u64);
        let until = if mode == "deadline" {
            Instant::now() + Duration::from_millis(500)
        } else {
            deadline()
        };
        let started = Instant::now();
        let error = HistoryEffectV6::open_with_startup_progress(
            &a.store,
            ProtectedHistoryV6Input::load(&path, rustix::process::geteuid().as_raw(), &sha)
                .unwrap(),
            2,
            until,
            Some(&cancellation),
            &|event| {
                assert_eq!(event, StartupProgress::WaitingForCredit);
                polls.set(polls.get() + 1);
                if mode == "cancel" && polls.get() == 1 {
                    signal.send(()).unwrap();
                }
                if mode == "boundary-error" {
                    return Err("HISTORY_TEST_WAIT_BOUNDARY".into());
                }
                Ok(())
            },
        )
        .err()
        .expect("interrupted credit wait returned a Native owner");
        if let Some(worker) = cancel_worker {
            worker.join().unwrap();
        }
        let expected = match mode {
            "cancel" => "HISTORY_V6_CANCELLED",
            "deadline" => "OWNER_CONTINUOUS_STARTUP_DEADLINE",
            "boundary-error" => "HISTORY_TEST_WAIT_BOUNDARY",
            _ => "HISTORY_V6_OPERATION_EXPIRED",
        };
        assert_eq!(error.to_string(), expected);
        assert!(polls.get() > 0, "failed before the actual interior wait");
        assert!(started.elapsed() < Duration::from_secs(4));
        let (outside, cold) = cold_not_started(&a, expected);
        write_value(
            &a.f.dir.path().join("wait-result.json"),
            &json!({"error":expected,"wait_polls":polls.get(),"cold_journal":cold,
                "elapsed_ns":started.elapsed().as_nanos(),"native_entered":false,
                "cpu_receipt_created":false,"original_predebit_preserved":true}),
        );
        if mode == "cancel" {
            let (old, digest) = a.launch("reused-nonce", 1, 2, a.genesis(), outside.clone());
            let error = HistoryEffectV6::open(
                &a.store,
                ProtectedHistoryV6Input::load(&old, rustix::process::geteuid().as_raw(), &digest)
                    .unwrap(),
                2,
                deadline(),
            )
            .err()
            .expect("NotStarted reused its original operation/nonce");
            assert!(error.to_string().contains("REPLAY"));
            // The retained epoch/nonce cannot be reused after NotStarted. An
            // independently authorized NEW epoch can earn credit and open.
            let (old, digest) = a.launch("reused-epoch", 2, 1, a.genesis(), outside.clone());
            let error = HistoryEffectV6::open(
                &a.store,
                ProtectedHistoryV6Input::load(&old, rustix::process::geteuid().as_raw(), &digest)
                    .unwrap(),
                2,
                deadline(),
            )
            .err()
            .expect("NotStarted reused its original epoch");
            assert!(error.to_string().contains("UNCLOSED_EPOCH"));
            let mut owner = a.open("fresh-after-wait", 2, 2, a.genesis(), outside);
            assert_eq!(owner.initial_cpu.stored_credit_ns, 0);
            let close = a.grant(Grant {
                purpose: Purpose::Close,
                nonce: 3,
                epoch: 2,
                frontier: actual(&owner),
                anchor: anchor(&owner),
                packet: None,
                pair: None,
            });
            let closed = owner.close(&close, deadline()).unwrap();
            assert_eq!(closed["journal"]["used_operations"], 3);
            assert_eq!(closed["journal"]["known_settlements"], 2);
            assert_eq!(closed["journal"]["spent"]["cpu_ns"], 12_000_000_000u64);
            assert_eq!(closed["journal"]["epoch"], Value::Null);
            write_value(
                &a.f.dir.path().join("fresh-after-wait-result.json"),
                &closed,
            );
            let terminal = serde_json::from_value(closed["journal"]["anchor"].clone()).unwrap();
            drop(owner);
            let reopened = journal::Journal::open_existing(
                &a.journal,
                rustix::process::geteuid().as_raw(),
                &a.identity,
                &terminal,
            )
            .unwrap();
            assert_eq!(reopened.observation(), closed["journal"]);
        }
    }
}
