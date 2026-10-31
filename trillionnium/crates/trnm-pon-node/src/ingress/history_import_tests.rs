use super::*;
use std::{
    cell::RefCell,
    fs,
    os::unix::process::ExitStatusExt,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Barrier,
    },
};

type Observer = Box<dyn Fn(&str)>;
thread_local! {
    static OBSERVER: RefCell<Option<Observer>> = RefCell::new(None);
}

pub(super) fn cut(stage: &str) {
    OBSERVER.with(|observer| {
        if let Some(observe) = observer.borrow().as_ref() {
            observe(stage);
        }
    });
    if std::env::var("TRNM_HISTORY_KILL_STAGE").ok().as_deref() == Some(stage) {
        let root = std::env::var("TRNM_HISTORY_KILL_DIRECTORY").unwrap();
        fs::write(std::path::Path::new(&root).join("ready"), stage).unwrap();
        // Only this isolated test child pauses. The parent issues SIGKILL;
        // no destructor, normal error return or clean epoch close can run.
        loop {
            thread::park();
        }
    }
}

fn page(settings: &Settings, packet: &Packet) -> Page {
    let id = packet.id().unwrap();
    Page {
        schema: "pon-native-history-v1".into(),
        network: hex::encode(settings.network()),
        parameters: hex::encode(settings.parameters()),
        genesis: hex::encode(settings.genesis()),
        tip: hex::encode(id),
        after: hex::encode(packet.header.parent),
        packets: vec![hex::encode(packet.encode().unwrap())],
        next: hex::encode(id),
        complete: true,
    }
}

fn fixture() -> (tempfile::TempDir, Settings, Node, Packet, u64) {
    let clock = now().unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open(directory.path(), settings.clone(), 2).unwrap();
    let packet = node
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    (directory, settings, node, packet, clock)
}

#[test]
fn pinned_completion_requires_existing_owner_and_expired_completion_cannot_mint_one() {
    let (_directory, settings, node, packet, _clock) = fixture();
    let owner = Mutex::new(node);
    let error = admit_shared_packet(
        &owner,
        packet,
        Instant::now() + Duration::from_secs(10),
        &|| Ok(()),
        Some(settings.genesis()),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "PAGE_COMPLETE");
    assert!(owner.lock().unwrap().public_service_cpu_domain().is_err());
    let error = complete_shared(
        &owner,
        settings.genesis(),
        Instant::now() + Duration::from_secs(10),
        &|| Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "OWNER_PUBLIC_SERVICE_DOMAIN_UNBOUND");
    assert!(owner.lock().unwrap().public_service_cpu_domain().is_err());
    let error =
        complete_shared(&owner, settings.genesis(), Instant::now(), &|| Ok(())).unwrap_err();
    assert!(error.is(crate::ErrorCode::PublicRequestDeadline));
    assert!(owner.lock().unwrap().public_service_cpu_domain().is_err());
    assert_eq!(
        owner.lock().unwrap().read_active().unwrap().0,
        settings.genesis()
    );
}

#[test]
fn pinned_final_packet_and_known_completion_keep_one_owner_without_repeating_w1() {
    let (_directory, settings, mut node, packet, _clock) = fixture();
    let original = public_v3::ServiceMutationCpuDomain::standalone();
    node.bind_public_service_cpu_domain(&original).unwrap();
    let owner = Mutex::new(node);
    let w1 = Arc::new(AtomicUsize::new(0));
    let activations = Arc::new(AtomicUsize::new(0));
    let observed_w1 = w1.clone();
    let observed_activations = activations.clone();
    let observed_cpu = original.clone();
    OBSERVER.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |stage| {
            if stage == "w1" {
                observed_w1.fetch_add(1, Ordering::SeqCst);
            }
            if stage == "activation_progress" {
                observed_activations.fetch_add(1, Ordering::SeqCst);
                assert_eq!(observed_cpu.observe().unwrap().in_flight, 1);
            }
        }))
    });
    let id = packet.id().unwrap();
    let end = Instant::now() + Duration::from_secs(10);
    let admitted = admit_shared_packet(&owner, packet.clone(), end, &|| Ok(()), Some(id));
    assert_eq!(admitted.unwrap(), (true, Some(id)));
    let verified = w1.load(Ordering::SeqCst);
    assert!(verified > 0);
    assert!(activations.load(Ordering::SeqCst) > 0);
    assert_eq!(
        original
            .observe_completion_work()
            .unwrap()
            .retained_identities,
        1
    );
    assert_eq!(complete_shared(&owner, id, end, &|| Ok(())).unwrap(), id);
    assert_eq!(
        admit_shared_packet(&owner, packet, end, &|| Ok(()), Some(id)).unwrap(),
        (false, Some(id))
    );
    OBSERVER.with(|hook| *hook.borrow_mut() = None);
    assert_eq!(w1.load(Ordering::SeqCst), verified);
    assert_eq!(
        original
            .observe_completion_work()
            .unwrap()
            .retained_identities,
        1
    );
    assert_eq!(original.observe().unwrap().in_flight, 0);
    assert!(!original.observe().unwrap().accounting_unavailable);
    let node = owner.lock().unwrap();
    assert!(node
        .public_service_cpu_domain()
        .unwrap()
        .shares_domain_with(&original));
    assert_eq!(node.active().unwrap().0, id);
    assert_ne!(id, settings.genesis());
}

#[test]
fn pinned_activation_failure_keeps_committed_packet_and_retry_does_not_repeat_w1() {
    let (_directory, settings, mut node, packet, _clock) = fixture();
    let original = public_v3::ServiceMutationCpuDomain::standalone();
    node.bind_public_service_cpu_domain(&original).unwrap();
    let owner = Mutex::new(node);
    let fail_activation = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let w1 = Arc::new(AtomicUsize::new(0));
    let observed_failure = fail_activation.clone();
    let observed_w1 = w1.clone();
    OBSERVER.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |stage| {
            if stage == "w1" {
                observed_w1.fetch_add(1, Ordering::SeqCst);
            }
            if stage == "admitted" {
                observed_failure.store(true, Ordering::SeqCst);
            }
        }))
    });
    let id = packet.id().unwrap();
    let end = Instant::now() + Duration::from_secs(10);
    let refused = admit_shared_packet(
        &owner,
        packet.clone(),
        end,
        &|| {
            ensure(
                !fail_activation.load(Ordering::SeqCst),
                "PUBLIC_REQUEST_DEADLINE",
            )
        },
        Some(id),
    );
    assert!(refused
        .unwrap_err()
        .is(crate::ErrorCode::PublicRequestDeadline));
    assert_eq!(owner.lock().unwrap().packet(id).unwrap().id().unwrap(), id);
    assert_eq!(
        owner.lock().unwrap().active().unwrap().0,
        settings.genesis()
    );
    let verified = w1.load(Ordering::SeqCst);
    assert!(verified > 0);
    fail_activation.store(false, Ordering::SeqCst);
    let retried = admit_shared_packet(&owner, packet, end, &|| Ok(()), Some(id));
    OBSERVER.with(|hook| *hook.borrow_mut() = None);
    assert_eq!(retried.unwrap(), (false, Some(id)));
    assert_eq!(w1.load(Ordering::SeqCst), verified);
    assert_eq!(
        original
            .observe_completion_work()
            .unwrap()
            .retained_identities,
        1
    );
    assert_eq!(original.observe().unwrap().in_flight, 0);
    assert_eq!(owner.lock().unwrap().active().unwrap().0, id);
}

#[test]
fn expired_history_never_starts_an_epoch_or_a_cpu_account() {
    let (_directory, settings, node, packet, clock) = fixture();
    let owner = Mutex::new(node);
    let result = receive(
        Owner::Shared(&owner),
        page(&settings, &packet),
        packet.id().unwrap(),
        settings.genesis(),
        clock,
        Control {
            deadline: Instant::now(),
            resource: &|| Ok(()),
        },
    );
    assert!(result
        .unwrap_err()
        .is(crate::ErrorCode::PublicRequestDeadline));
    let node = owner.lock().unwrap();
    assert!(node.public_service_cpu_domain().is_err());
    assert_eq!(node.read_active().unwrap().0, settings.genesis());
}

#[test]
fn shared_history_refill_full_w1_and_actual_m06_release_the_original_writer() {
    let (_directory, settings, node, packet, clock) = fixture();
    let owner = Arc::new(Mutex::new(node));
    let original = owner.lock().unwrap().remote_history_cpu_domain().unwrap();
    assert_eq!(original.observe().unwrap().stored_credit_ns, 0);
    let unlocked_waits = Arc::new(AtomicUsize::new(0));
    let unlocked_w1 = Arc::new(AtomicUsize::new(0));
    let unlocked_m06 = Arc::new(AtomicUsize::new(0));
    let observed_owner = owner.clone();
    let waits = unlocked_waits.clone();
    let works = unlocked_w1.clone();
    let executions = unlocked_m06.clone();
    OBSERVER.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |stage| {
            if stage == "cpu_wait" || stage == "w1" || stage == "m06" {
                let node = observed_owner
                    .try_lock()
                    .expect("History held writer across refill/W1/M06");
                node.active().unwrap();
                if stage == "cpu_wait" {
                    waits.fetch_add(1, Ordering::SeqCst);
                } else if stage == "w1" {
                    works.fetch_add(1, Ordering::SeqCst);
                } else {
                    executions.fetch_add(1, Ordering::SeqCst);
                }
            }
        }))
    });
    let id = packet.id().unwrap();
    let result = receive(
        Owner::Shared(&owner),
        page(&settings, &packet),
        id,
        settings.genesis(),
        clock,
        Control {
            deadline: Instant::now() + Duration::from_secs(10),
            resource: &|| Ok(()),
        },
    );
    OBSERVER.with(|hook| *hook.borrow_mut() = None);
    assert_eq!(result.unwrap(), id);
    assert!(unlocked_waits.load(Ordering::SeqCst) > 0);
    assert!(unlocked_w1.load(Ordering::SeqCst) > 0);
    assert!(unlocked_m06.load(Ordering::SeqCst) > 0);
    let node = owner.lock().unwrap();
    assert!(node
        .public_service_cpu_domain()
        .unwrap()
        .shares_domain_with(&original));
    assert_eq!(node.read_active().unwrap().0, id);
    assert_eq!(original.observe().unwrap().in_flight, 0);
}

#[test]
fn history_decode_cannot_renew_the_original_w1_deadline() {
    let (_directory, settings, node, packet, clock) = fixture();
    let owner = Mutex::new(node);
    let end = Instant::now() + Duration::from_millis(700);
    let work = Arc::new(AtomicUsize::new(0));
    let observed_work = work.clone();
    OBSERVER.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |stage| {
            if stage == "decoded" {
                thread::sleep(
                    end.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
                );
            }
            if stage == "w1" {
                observed_work.fetch_add(1, Ordering::SeqCst);
            }
        }))
    });
    let result = receive(
        Owner::Shared(&owner),
        page(&settings, &packet),
        packet.id().unwrap(),
        settings.genesis(),
        clock,
        Control {
            deadline: end,
            resource: &|| Ok(()),
        },
    );
    OBSERVER.with(|hook| *hook.borrow_mut() = None);
    assert!(result
        .unwrap_err()
        .is(crate::ErrorCode::PublicRequestDeadline));
    assert_eq!(work.load(Ordering::SeqCst), 0);
    let node = owner.lock().unwrap();
    assert_eq!(node.read_active().unwrap().0, settings.genesis());
    assert!(node.packet(packet.id().unwrap()).is_err());
    assert_eq!(
        node.public_service_cpu_domain()
            .unwrap()
            .observe()
            .unwrap()
            .in_flight,
        0
    );
}

#[test]
fn actual_detached_m06_cannot_continue_after_original_cpu_account_is_fenced() {
    let (directory, settings, node, packet, clock) = fixture();
    let owner = Mutex::new(node);
    let original = owner.lock().unwrap().remote_history_cpu_domain().unwrap();
    let observed = original.clone();
    let stages = Arc::new(AtomicUsize::new(0));
    let seen = stages.clone();
    OBSERVER.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |stage| {
            if stage == "m06" {
                seen.fetch_add(1, Ordering::SeqCst);
                observed.abandon_history_epoch();
            }
        }))
    });
    let result = receive(
        Owner::Shared(&owner),
        page(&settings, &packet),
        packet.id().unwrap(),
        settings.genesis(),
        clock,
        Control {
            deadline: Instant::now() + Duration::from_secs(10),
            resource: &|| Ok(()),
        },
    );
    OBSERVER.with(|hook| *hook.borrow_mut() = None);
    assert!(result
        .unwrap_err()
        .is(crate::ErrorCode::PublicMutationCpuUnavailable));
    assert_eq!(stages.load(Ordering::SeqCst), 1);
    assert!(original.observe().unwrap().accounting_unavailable);
    assert!(original
        .begin()
        .err()
        .unwrap()
        .is(crate::ErrorCode::PublicMutationCpuUnavailable));
    {
        let node = owner.lock().unwrap();
        assert!(node
            .public_service_cpu_domain()
            .unwrap()
            .shares_domain_with(&original));
        assert!(node.packet(packet.id().unwrap()).is_err());
        assert_eq!(node.read_active().unwrap().0, settings.genesis());
    }
    drop(owner);
    let mut reopened = Node::open(directory.path(), settings, 2).unwrap();
    assert!(reopened
        .remote_history_cpu_domain()
        .err()
        .unwrap()
        .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
}

#[test]
fn committed_history_keeps_original_deadline_inside_native_activation() {
    let (_directory, settings, node, packet, clock) = fixture();
    let owner = Mutex::new(node);
    let end = Instant::now() + Duration::from_secs(1);
    let activations = Arc::new(AtomicUsize::new(0));
    let observed = activations.clone();
    OBSERVER.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |stage| {
            if stage == "activation_progress" && observed.fetch_add(1, Ordering::SeqCst) == 0 {
                // Enter the actual native activation API after block admission
                // committed, then exceed the SAME business deadline.
                thread::sleep(
                    end.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
                );
            }
        }))
    });
    let result = receive(
        Owner::Shared(&owner),
        page(&settings, &packet),
        packet.id().unwrap(),
        settings.genesis(),
        clock,
        Control {
            deadline: end,
            resource: &|| Ok(()),
        },
    );
    OBSERVER.with(|hook| *hook.borrow_mut() = None);
    assert!(result
        .unwrap_err()
        .is(crate::ErrorCode::PublicRequestDeadline));
    assert_eq!(activations.load(Ordering::SeqCst), 1);
    let node = owner.lock().unwrap();
    assert_eq!(
        node.packet(packet.id().unwrap()).unwrap().encode().unwrap(),
        packet.encode().unwrap()
    );
    // Inspect this same owner before cold recovery may activate committed work.
    assert_eq!(node.read_active().unwrap().0, settings.genesis());
    let original = node.public_service_cpu_domain().unwrap().observe().unwrap();
    assert_eq!(original.in_flight, 0);
    assert!(!original.accounting_unavailable);
}

#[test]
fn shared_admission_owner_wait_observes_control_deadline_and_original_two_second_limit() {
    for (business_limit, expected) in [
        (
            Duration::from_millis(20),
            crate::ErrorCode::PublicRequestDeadline,
        ),
        (Duration::from_secs(4), crate::ErrorCode::PublicQueueBusy),
    ] {
        let (_directory, _settings, node, packet, clock) = fixture();
        let checked = WorkCheckedPacket::verify(packet).unwrap();
        let owner = Arc::new(Mutex::new(node));
        let held = owner.lock().unwrap();
        let request_owner = owner.clone();
        let request = thread::spawn(move || {
            let end = Instant::now() + business_limit;
            let check = |_| ensure(Instant::now() < end, "PUBLIC_REQUEST_DEADLINE");
            crate::ingress::admit_shared_checked(
                &request_owner,
                checked,
                None,
                &mut |_| Ok(()),
                &trnm_mvcc_fee::pon_executor::ExecutionControl::new(&check, &()),
                || Ok(clock),
                None,
            )
            .err()
            .unwrap()
        });
        // Hold the actual Node mutex until the caller refuses; there is no
        // scheduler release that could accidentally pass this deadline check.
        let error = request.join().unwrap();
        drop(held);
        assert!(error.is(expected), "unexpected owner-wait result: {error}");
    }
}

#[test]
fn one_history_close_cannot_clear_another_imports_live_epoch() {
    let (_directory, _settings, mut node, _packet, _clock) = fixture();
    let cpu = public_v3::ServiceMutationCpuDomain::standalone();
    node.bind_public_service_cpu_domain(&cpu).unwrap();
    assert!(node.begin_remote_history_cpu_epoch().unwrap());
    assert!(node.begin_remote_history_cpu_epoch().unwrap());
    let operation = cpu.begin().unwrap();
    // The first import finished its own work. A second import is still live.
    node.finish_remote_history_cpu_epoch(&cpu).unwrap();
    assert_eq!(cpu.observe().unwrap().in_flight, 1);
    assert!(node.begin_remote_history_cpu_epoch().unwrap());
    node.finish_remote_history_cpu_epoch(&cpu).unwrap();
    assert!(!operation.finish().accounting_unavailable);
    node.finish_remote_history_cpu_epoch(&cpu).unwrap();
    assert!(cpu.accounting_available());
}

#[test]
fn concurrent_false_product_wrong_root_and_honest_history_share_one_account() {
    let (_directory, settings, node, honest, clock) = fixture();
    let owner = Arc::new(Mutex::new(node));
    let cpu = owner.lock().unwrap().remote_history_cpu_domain().unwrap();
    let gate = Arc::new(Barrier::new(4));
    let end = Instant::now() + Duration::from_secs(15);
    let mut tasks = Vec::new();
    for index in 0..3 {
        let mut packet = honest.clone();
        if index == 0 {
            let offset = 4 + 2 * trnm_crypto_primitives::pon_work::CELLS * 4;
            let value = u32::from_le_bytes(packet.proof[offset..offset + 4].try_into().unwrap());
            let changed = ((u128::from(value) + index as u128 + 1)
                % trnm_crypto_primitives::pon_work::Q) as u32;
            packet.proof[offset..offset + 4].copy_from_slice(&changed.to_le_bytes());
        }
        if index == 1 {
            use trnm_crypto_primitives::pon_work;
            let words = |range: std::ops::Range<usize>| {
                packet.proof[range]
                    .chunks_exact(4)
                    .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
                    .collect::<Vec<_>>()
            };
            let a = words(4..4 + 4 * pon_work::CELLS);
            let b = words(4 + 4 * pon_work::CELLS..4 + 8 * pon_work::CELLS);
            let prepared = pon_work::PreparedTask::new(&a, &b).unwrap();
            packet.header.state[0] ^= 1;
            for nonce in 0..4096 {
                packet.header.nonce = nonce;
                packet.proof = prepared.prove(packet.header.challenge()).unwrap();
                if pon_work::precheck_proof_statement(
                    packet.header.challenge(),
                    packet.header.work_task,
                    packet.header.target,
                    &packet.proof,
                )
                .is_ok()
                {
                    break;
                }
            }
            // It must reach actual M06 ROOT refusal, never merely fail W1.
            WorkCheckedPacket::verify(packet.clone()).unwrap();
        }
        let owner = owner.clone();
        let settings = settings.clone();
        let gate = gate.clone();
        tasks.push(thread::spawn(move || {
            gate.wait();
            receive(
                Owner::Shared(&owner),
                page(&settings, &packet),
                packet.id().unwrap(),
                settings.genesis(),
                clock,
                Control {
                    deadline: end,
                    resource: &|| Ok(()),
                },
            )
        }));
    }
    gate.wait();
    for (index, task) in tasks.into_iter().enumerate() {
        let outcome = task.join().unwrap();
        if index == 2 {
            assert_eq!(outcome.unwrap(), honest.id().unwrap());
        } else if index == 0 {
            let error = outcome.unwrap_err();
            assert!(
                error.to_string() == "WORK:Product" || error.is(crate::ErrorCode::DuplicateContent),
                "unexpected hostile outcome: {error}"
            );
        } else {
            assert_eq!(outcome.unwrap_err().to_string(), "ROOT");
        }
    }
    let node = owner.lock().unwrap();
    assert!(node
        .public_service_cpu_domain()
        .unwrap()
        .shares_domain_with(&cpu));
    assert_eq!(
        node.packet(honest.id().unwrap()).unwrap().encode().unwrap(),
        honest.encode().unwrap()
    );
    assert_eq!(node.read_active().unwrap().0, honest.id().unwrap());
    let measured = cpu.observe().unwrap();
    assert_eq!(measured.in_flight, 0);
    assert!(!measured.accounting_unavailable);
    assert!(cpu.observe_actual_flow().unwrap().is_some());
}

#[test]
#[ignore = "subprocess fixture: parent selects a real SIGKILL cut"]
fn history_kill_cut_child() {
    let root = std::path::PathBuf::from(std::env::var("TRNM_HISTORY_KILL_DIRECTORY").unwrap());
    let clock: u64 = std::env::var("TRNM_HISTORY_KILL_CLOCK")
        .unwrap()
        .parse()
        .unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let node = Node::open(&root.join("node"), settings.clone(), 2).unwrap();
    let packet = node
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let id = packet.id().unwrap();
    fs::write(root.join("block"), hex::encode(id)).unwrap();
    let owner = Mutex::new(node);
    receive(
        Owner::Shared(&owner),
        page(&settings, &packet),
        id,
        settings.genesis(),
        clock,
        Control {
            deadline: Instant::now() + Duration::from_secs(20),
            resource: &|| Ok(()),
        },
    )
    .unwrap();
    panic!("requested native kill cut was not reached");
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn real_sigkill_history_cuts_preserve_debt_fence_and_committed_blocks() {
    for stage in ["epoch", "w1", "m06", "admitted", "activated"] {
        let directory = tempfile::tempdir().unwrap();
        let clock = now().unwrap();
        let mut child = KillOnDrop(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "ingress::history_import::tests::history_kill_cut_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TRNM_HISTORY_KILL_DIRECTORY", directory.path())
                .env("TRNM_HISTORY_KILL_CLOCK", clock.to_string())
                .env("TRNM_HISTORY_KILL_STAGE", stage)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let end = Instant::now() + Duration::from_secs(30);
        while !directory.path().join("ready").exists() {
            assert!(
                Instant::now() < end,
                "child failed to reach {stage} in time"
            );
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "child exited before {stage}"
            );
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            fs::read_to_string(directory.path().join("ready")).unwrap(),
            stage
        );
        child.0.kill().unwrap();
        assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
        let settings = Settings::development(Some(clock - 100)).unwrap();
        let id =
            crate::digest(&fs::read_to_string(directory.path().join("block")).unwrap()).unwrap();
        // Observe the actual cut BEFORE Node::open invokes ordinary heaviest-
        // work recovery. An admission-gap reopen intentionally activates a
        // fully committed best block; that is not an uncommitted acceptance.
        let db = rusqlite::Connection::open_with_flags(
            directory.path().join("node/native.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let cut_tip: Vec<u8> = db
            .query_row("SELECT tip FROM active WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .unwrap();
        let expected_cut_tip = if stage == "activated" {
            id
        } else {
            settings.genesis()
        };
        assert_eq!(
            cut_tip.as_slice(),
            expected_cut_tip.as_slice(),
            "active publication at cut {stage}"
        );
        let marker: Vec<u8> = db
            .query_row(
                "SELECT value FROM metadata WHERE key='ordinary-public-v3-epoch-v1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(marker, b"active-v1");
        drop(db);
        let mut reopened = Node::open(&directory.path().join("node"), settings.clone(), 2).unwrap();
        let committed = stage == "admitted" || stage == "activated";
        assert_eq!(
            reopened.packet(id).is_ok(),
            committed,
            "native commit mismatch at {stage}"
        );
        assert_eq!(
            reopened.read_active().unwrap().0,
            if committed { id } else { settings.genesis() },
            "ordinary recovery at cut {stage}"
        );
        assert!(reopened
            .remote_history_cpu_domain()
            .err()
            .unwrap()
            .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
        assert!(reopened
            .begin_remote_history_cpu_epoch()
            .unwrap_err()
            .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
        assert!(reopened.public_service_cpu_domain().is_err());
        println!(
            "{}",
            serde_json::json!({"schema":"native-history-real-kill-cut-v1", "cut":stage,
            "observed_signal":libc::SIGKILL, "cut_active_tip":hex::encode(cut_tip),
            "durable_epoch_marker":String::from_utf8(marker).unwrap(),
            "stored_block_after_reopen":reopened.packet(id).is_ok(),
            "reopened_active_tip":hex::encode(reopened.read_active().unwrap().0),
            "new_cpu_account_available":reopened.public_service_cpu_domain().is_ok(),
            "physical_power_loss":false, "debt_reconciliation_complete":false})
        );
    }
}

// Fault injection through the real History resource boundary. These controls
// execute native W1, M06, SQL publication and CPU settlement; they do not claim
// that this test process provisioned or revoked a real fixed Host cgroup.
#[test]
fn first_history_resource_failure_preserves_cold_account_and_clean_restart() {
    for shared in [false, true] {
        let (directory, settings, mut node, packet, clock) = fixture();
        let original = node.remote_history_cpu_domain().unwrap();
        let before = node.read_active().unwrap();
        let calls = AtomicUsize::new(0);
        let resource = || {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(crate::Error::from("PUBLIC_HOST_KERNEL_LIMITS_CHANGED"))
        };
        let owner = Mutex::new(node);
        let control = Control {
            deadline: Instant::now() + Duration::from_secs(10),
            resource: &resource,
        };
        let result = if shared {
            receive(
                Owner::Shared(&owner),
                page(&settings, &packet),
                packet.id().unwrap(),
                settings.genesis(),
                clock,
                control,
            )
        } else {
            receive(
                Owner::Exclusive(&mut owner.lock().unwrap()),
                page(&settings, &packet),
                packet.id().unwrap(),
                settings.genesis(),
                clock,
                control,
            )
        };
        assert_eq!(
            result.unwrap_err().to_string(),
            "PUBLIC_HOST_KERNEL_LIMITS_CHANGED"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
        let observed = original.observe().unwrap();
        assert_eq!(observed.in_flight, 0);
        assert_eq!(observed.stored_credit_ns, 0);
        assert!(!observed.accounting_unavailable);
        let flow = original.observe_actual_flow().unwrap().unwrap();
        assert_eq!(flow.paid_cpu_debit_ns, 0);
        assert_eq!(flow.booked_reservation_ns, 0);
        assert!(flow.balance_identity_verified);
        drop(owner);
        let mut reopened = Node::open(directory.path(), settings, 2).unwrap();
        let cold = reopened
            .remote_history_cpu_domain()
            .unwrap()
            .observe()
            .unwrap();
        assert_eq!(cold.stored_credit_ns, 0);
        assert!(!cold.accounting_unavailable);
        assert_eq!(reopened.read_active().unwrap(), before);
    }
}

fn history_checkpoint_transfer(settings: &Settings) -> Vec<u8> {
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
    use trnm_protocol::pon_wire::{hash, Envelope};
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    let mut payload = crate::development_public(1).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut envelope = Envelope {
        network: settings.network(),
        sender: crate::development_public(0).unwrap(),
        nonce: 1,
        expiry: 10_000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    envelope.encode().unwrap()
}

#[test]
fn history_host_rejection_keeps_native_boundaries_nonce_and_original_paid_account() {
    use std::sync::atomic::AtomicBool;
    for shared in [false, true] {
        for stage in ["w1", "m06", "admitted", "activation_progress"] {
            let clock = now().unwrap();
            let settings = Settings::development(Some(clock - 100)).unwrap();
            let directory = tempfile::tempdir().unwrap();
            let mut node =
                Node::open_with_authenticated_state(directory.path(), settings.clone(), 1).unwrap();
            let before = node.read_active().unwrap();
            let original = node.remote_history_cpu_domain().unwrap();
            let packet = node
                .make(
                    settings.genesis(),
                    vec![history_checkpoint_transfer(&settings)],
                    crate::development_public(0).unwrap(),
                    settings.genesis_time() + 10,
                    4096,
                )
                .unwrap();
            let id = packet.id().unwrap();
            let revoked = Arc::new(AtomicBool::new(false));
            let observed = revoked.clone();
            OBSERVER.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |point| {
                    if point == stage {
                        observed.store(true, Ordering::SeqCst);
                    }
                }));
            });
            let resource = || {
                ensure(
                    !revoked.load(Ordering::SeqCst),
                    "PUBLIC_HOST_KERNEL_LIMITS_CHANGED",
                )
            };
            let owner = Mutex::new(node);
            let control = Control {
                deadline: Instant::now() + Duration::from_secs(10),
                resource: &resource,
            };
            let outcome = if shared {
                receive(
                    Owner::Shared(&owner),
                    page(&settings, &packet),
                    id,
                    settings.genesis(),
                    clock,
                    control,
                )
            } else {
                receive(
                    Owner::Exclusive(&mut owner.lock().unwrap()),
                    page(&settings, &packet),
                    id,
                    settings.genesis(),
                    clock,
                    control,
                )
            };
            OBSERVER.with(|hook| *hook.borrow_mut() = None);
            assert!(
                revoked.load(Ordering::SeqCst),
                "unreached original cut {stage}"
            );
            assert_eq!(
                outcome.unwrap_err().to_string(),
                "PUBLIC_HOST_KERNEL_LIMITS_CHANGED"
            );
            let committed = matches!(stage, "admitted" | "activation_progress");
            {
                let node = owner.lock().unwrap();
                assert_eq!(node.packet(id).is_ok(), committed, "{shared}/{stage}");
                assert_eq!(node.read_active().unwrap(), before, "{shared}/{stage}");
                assert!(node
                    .public_service_cpu_domain()
                    .unwrap()
                    .shares_domain_with(&original));
            }
            let observation = original.observe().unwrap();
            assert_eq!(observation.in_flight, 0);
            assert!(!observation.accounting_unavailable);
            let flow = original.observe_actual_flow().unwrap().unwrap();
            assert!(flow.paid_cpu_debit_ns > 0);
            assert_eq!(flow.paid_cpu_debit_ns, flow.settled_full_cpu_ns);
            assert_eq!(flow.unsettled_known_live_cpu_ns, 0);
            assert_eq!(flow.booked_reservation_ns, 0);
            assert_eq!(flow.initial_credit_ns, 0);
            assert!(flow.balance_identity_verified);
            println!(
                "{}",
                serde_json::json!({"schema":"history-native-resource-failure-v1",
                "shared":shared,"cut":stage,"committed":committed,"flow":flow,
                "real_host_revocation":false})
            );
            // A separate request may retry after the resource owner is restored;
            // the same Node and original CPU domain retain all already paid work.
            let control = Control {
                deadline: Instant::now() + Duration::from_secs(10),
                resource: &|| Ok(()),
            };
            let outcome = if shared {
                receive(
                    Owner::Shared(&owner),
                    page(&settings, &packet),
                    id,
                    settings.genesis(),
                    clock,
                    control,
                )
            } else {
                receive(
                    Owner::Exclusive(&mut owner.lock().unwrap()),
                    page(&settings, &packet),
                    id,
                    settings.genesis(),
                    clock,
                    control,
                )
            };
            assert_eq!(outcome.unwrap(), id);
            let active = owner.lock().unwrap().read_active().unwrap();
            assert_eq!(active.0, id);
            let sender = format!(
                "account:{}",
                hex::encode(crate::development_public(0).unwrap())
            );
            assert_eq!(before.2[&sender]["nonce"], 0);
            assert_eq!(active.2[&sender]["nonce"], 1);
            assert_eq!(original.observe().unwrap().in_flight, 0);
            drop(owner);
            let mut reopened =
                Node::open_with_authenticated_state(directory.path(), settings, 1).unwrap();
            assert_eq!(reopened.read_active().unwrap(), active);
            let cold = reopened
                .remote_history_cpu_domain()
                .unwrap()
                .observe()
                .unwrap();
            assert_eq!(cold.stored_credit_ns, 0);
            assert!(!cold.accounting_unavailable);
        }
    }
}

#[test]
fn shared_history_paid_deficit_refuses_without_waiting_under_original_writer() {
    let (directory, settings, mut node, packet, _clock) = fixture();
    let domain = node.remote_history_cpu_domain().unwrap();
    let before = node.read_active().unwrap();
    let writer = Mutex::new(node);
    let control = Control {
        deadline: Instant::now() + Duration::from_secs(5),
        resource: &|| Ok(()),
    };
    let observed = Mutex::new(None);
    // Use the same epoch guard and close path as a real import. A last scope
    // with actual remaining debt must retain its marker, even with known CPU.
    let close = scoped(&mut Owner::Shared(&writer), &control, |_owner, cpu| {
        assert!(cpu.shares_domain_with(&domain));
        let operation = begin_cpu(cpu, &control)?;
        operation.bind_history_request(control.deadline)?;
        let checked = WorkCheckedPacket::verify_with_progress(packet.clone(), &mut |_| {
            operation.history_checkpoint(false, &|| control.check())
        })?;
        operation.history_work_verified(&checked)?;
        let held = writer.lock().unwrap();
        let mut boundaries = 0;
        // Real W1 CPU depletes the original cold account; no synthetic meter
        // debit or new account replaces the original writer's checkpoints.
        loop {
            let result = WorkCheckedPacket::verify_with_progress(packet.clone(), &mut |_| {
                boundaries += 1;
                assert!(matches!(writer.try_lock(), Err(TryLockError::WouldBlock)));
                operation.history_checkpoint(true, &|| control.check())
            });
            match result {
                Ok(_) => assert!(Instant::now() < control.deadline),
                Err(error) => {
                    assert!(
                        error.is(crate::ErrorCode::PublicMutationCpuBudget),
                        "{error}"
                    );
                    break;
                }
            }
        }
        assert!(boundaries > 0);
        assert!(cpu.observe()?.stored_credit_ns < 0);
        drop(held);
        let receipt = operation.finish();
        assert!(!receipt.accounting_unavailable);
        let flow = cpu.observe_actual_flow()?.unwrap();
        assert_eq!(flow.initial_credit_ns, 0);
        assert_eq!(flow.booked_reservation_ns, 0);
        assert_eq!(flow.paid_cpu_debit_ns, receipt.total_cpu_ns.unwrap());
        assert_eq!(flow.live_owners, 0);
        assert!(flow.balance_identity_verified);
        *observed.lock().unwrap() = Some((boundaries, receipt, flow));
        Ok(())
    });
    let (boundaries, receipt, flow) = observed.into_inner().unwrap().unwrap();
    // Settlement uses actual elapsed refill. Whether that final refill has
    // covered the small measured overshoot is observed, never manufactured.
    let debt_remains = flow.stored_credit_ns < 0;
    if debt_remains {
        assert!(close
            .unwrap_err()
            .is(crate::ErrorCode::PublicMutationCpuUnavailable));
        assert!(!domain.accounting_available());
        assert!(writer
            .lock()
            .unwrap()
            .remote_history_cpu_domain()
            .err()
            .unwrap()
            .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
    } else {
        close.unwrap();
        assert!(domain.accounting_available());
    }
    assert_eq!(writer.lock().unwrap().read_active().unwrap(), before);
    drop(writer);
    let mut reopened = Node::open(directory.path(), settings, 2).unwrap();
    assert_eq!(reopened.read_active().unwrap(), before);
    if debt_remains {
        assert!(reopened
            .remote_history_cpu_domain()
            .err()
            .unwrap()
            .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
    } else {
        assert_eq!(
            reopened
                .remote_history_cpu_domain()
                .unwrap()
                .observe()
                .unwrap()
                .stored_credit_ns,
            0
        );
    }
    println!(
        "{}",
        serde_json::json!({"schema":"history-shared-real-paid-deficit-v1",
        "boundaries":boundaries,"receipt":receipt,"flow":flow,"debt_remains":debt_remains,
        "scope":"bounded full native W1 CPU control, not a network saturation attack"})
    );
}
