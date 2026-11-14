use super::*;
use crate::{development_public, ingress, Node, Packet, Settings};
use trnm_crypto_primitives::{pon_work::facts::WorkFactCache, sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::{hash, Envelope};
fn fixture(workers: usize) -> (tempfile::TempDir, Mutex<Node>, Packet) {
    let dir = tempfile::tempdir().unwrap();
    let clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let s = Settings::development(Some(clock - 100)).unwrap();
    let n = Node::open(dir.path(), s.clone(), workers).unwrap();
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&1u64.to_le_bytes()]))).unwrap();
    let transactions = (1..=8)
        .map(|nonce| {
            let mut payload = development_public(21).unwrap().to_vec();
            payload.extend(1u64.to_le_bytes());
            let mut e = Envelope {
                network: s.network(),
                sender: development_public(1).unwrap(),
                nonce,
                expiry: 10000,
                fee_limit: 1_000_000,
                tag: 1,
                payload,
                signature: [0; 64],
            };
            e.signature = hex::decode(sign_hex(&key, &e.signing_digest().unwrap()))
                .unwrap()
                .try_into()
                .unwrap();
            e.encode().unwrap()
        })
        .collect();
    let packet = n
        .make(
            s.genesis(),
            transactions,
            development_public(0).unwrap(),
            clock - 90,
            4096,
        )
        .unwrap();
    (dir, Mutex::new(n), packet)
}
fn request(p: &Packet) -> ingress::Request {
    ingress::Request::Submit {
        packet: hex::encode(p.encode().unwrap()),
    }
}
#[test]
fn paid_cached_native_execution_registers_all_real_m06_workers() {
    let (_dir, node, p) = fixture(2);
    let facts = WorkFactCache::new(4).unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    let out = ingress::dispatch_shared_with_metered_work_facts(
        &node,
        request(&p),
        &facts,
        &domain,
        &|| Ok(()),
    )
    .unwrap();
    let (result, receipt) = (out.native, out.cpu);
    assert!(
        result.is_ok(),
        "a shared CPU checkpoint must include M06 worker registration"
    );
    assert!(!receipt.accounting_unavailable);
    assert!(receipt.spawned_workers > 0);
    assert_eq!(receipt.spawned_workers, receipt.known_workers);
    println!("METERED_FACT_BOUNDARY worker accounting assertions complete");
}

fn freeze(domain: &ServiceMutationCpuDomain, credit: i128) {
    let mut budget = domain.budget.lock().unwrap();
    assert_eq!(budget.in_flight, 0);
    budget.credit_ns = credit;
    budget.updated = Instant::now() + std::time::Duration::from_secs(60);
    budget.flow = Some(CpuFlow::new(credit));
}
fn assert_paid(domain: &ServiceMutationCpuDomain, receipt: &ServiceMutationCpuSettlement) {
    assert!(!receipt.accounting_unavailable, "{receipt:?}");
    assert!(receipt.total_cpu_ns.unwrap() > 0);
    assert_eq!(
        receipt.total_cpu_ns.unwrap(),
        receipt.owner_cpu_ns.unwrap() + receipt.scoped_worker_cpu_ns.unwrap()
    );
    assert_eq!(
        receipt.total_cpu_ns.unwrap(),
        receipt.live_paid_cpu_ns.unwrap() + receipt.residual_cpu_ns.unwrap()
    );
    assert_eq!(receipt.spawned_workers, receipt.started_workers);
    assert_eq!(receipt.spawned_workers, receipt.finished_workers);
    assert_eq!(receipt.spawned_workers, receipt.known_workers);
    let b = domain.budget.lock().unwrap();
    assert_eq!(b.in_flight, 0);
    let flow = b
        .flow
        .as_ref()
        .unwrap()
        .snapshot(b.credit_ns, b.in_flight, b.termination_reserved_ns)
        .unwrap();
    assert!(flow.balance_identity_verified);
}
#[test]
fn exhausted_domain_refuses_before_cold_or_warm_math_and_state() {
    let (_dir, node, p) = fixture(2);
    let facts = WorkFactCache::new(2).unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    let before = node.lock().unwrap().read_active().unwrap();
    for warm in [false, true] {
        if warm {
            facts
                .verify(
                    p.header.challenge(),
                    p.header.work_task,
                    p.header.target,
                    &p.proof,
                )
                .unwrap();
        }
        let previous = facts.counters();
        freeze(&domain, 0);
        let error = ingress::dispatch_shared_with_metered_work_facts(
            &node,
            request(&p),
            &facts,
            &domain,
            &|| Ok(()),
        )
        .err()
        .unwrap();
        assert_eq!(error.to_string(), "PUBLIC_MUTATION_CPU_BUDGET");
        assert_eq!(facts.counters(), previous);
        assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
        assert_eq!(domain.budget.lock().unwrap().in_flight, 0);
    }
}
#[test]
fn failed_product_and_warm_retry_each_pay_exact_cpu_without_poisoning() {
    let (_dir, node, p) = fixture(2);
    let facts = WorkFactCache::new(2).unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    freeze(&domain, i128::from(MUTATION_CPU_BURST_NS));
    facts
        .verify(
            p.header.challenge(),
            p.header.work_task,
            p.header.target,
            &p.proof,
        )
        .unwrap();
    let before = node.lock().unwrap().read_active().unwrap();
    let mut bad = p.clone();
    bad.proof[4 + 8 * 4096] ^= 1;
    let fail = ingress::dispatch_shared_with_metered_work_facts(
        &node,
        request(&bad),
        &facts,
        &domain,
        &|| Ok(()),
    )
    .unwrap();
    assert_eq!(fail.native.err().unwrap().to_string(), "WORK:Product");
    assert_paid(&domain, &fail.cpu);
    assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
    let success = ingress::dispatch_shared_with_metered_work_facts(
        &node,
        request(&p),
        &facts,
        &domain,
        &|| Ok(()),
    )
    .unwrap();
    assert!(success.native.is_ok());
    assert_paid(&domain, &success.cpu);
    assert_eq!(facts.counters().full_replays, 1);
    assert_eq!(
        domain.budget.lock().unwrap().credit_ns,
        i128::from(MUTATION_CPU_BURST_NS)
            - i128::from(fail.cpu.total_cpu_ns.unwrap())
            - i128::from(success.cpu.total_cpu_ns.unwrap())
    );
}
#[test]
fn cancellation_keeps_spent_cpu_and_retry_does_not_reset_domain() {
    let (_dir, node, p) = fixture(2);
    let facts = WorkFactCache::new(2).unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    freeze(&domain, i128::from(MUTATION_CPU_BURST_NS));
    let before = node.lock().unwrap().read_active().unwrap();
    let cancelled = ingress::dispatch_shared_with_metered_work_facts(
        &node,
        request(&p),
        &facts,
        &domain,
        &|| {
            if facts.counters().full_replays > 0 {
                Err("METERED_TEST_CANCEL".into())
            } else {
                Ok(())
            }
        },
    )
    .unwrap();
    assert_eq!(
        cancelled.native.err().unwrap().to_string(),
        "METERED_TEST_CANCEL"
    );
    assert_paid(&domain, &cancelled.cpu);
    assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
    let paid = cancelled.cpu.total_cpu_ns.unwrap();
    assert_eq!(
        domain.budget.lock().unwrap().credit_ns,
        i128::from(MUTATION_CPU_BURST_NS) - i128::from(paid)
    );
    let retry = ingress::dispatch_shared_with_metered_work_facts(
        &node,
        request(&p),
        &facts,
        &domain,
        &|| Ok(()),
    )
    .unwrap();
    assert!(retry.native.is_ok());
    assert_paid(&domain, &retry.cpu);
    assert_eq!(
        domain.budget.lock().unwrap().credit_ns,
        i128::from(MUTATION_CPU_BURST_NS)
            - i128::from(paid)
            - i128::from(retry.cpu.total_cpu_ns.unwrap())
    );
}
#[test]
fn read_request_cannot_consume_the_mutation_budget_via_this_entry() {
    let (_dir, node, _) = fixture(1);
    let facts = WorkFactCache::new(1).unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    freeze(&domain, 0);
    let before = domain.observe().unwrap();
    let error = ingress::dispatch_shared_with_metered_work_facts(
        &node,
        ingress::Request::Head,
        &facts,
        &domain,
        &|| Ok(()),
    )
    .err()
    .unwrap();
    assert_eq!(error.to_string(), "WORK_FACT_SUBMIT_ONLY");
    assert_eq!(
        domain.observe().unwrap().stored_credit_ns,
        before.stored_credit_ns
    );
    assert_eq!(facts.counters().full_replays, 0);
}
#[test]
fn shared_listener_reconstruction_never_refills_debt_or_replaces_domain() {
    use crate::ingress::{
        public_v3::{PublicPolicy, PublicServer},
        DevelopmentIdentity,
    };
    let (_dir, node, p) = fixture(1);
    let facts = WorkFactCache::new(1).unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    freeze(&domain, -123456789);
    for seed in 70..78 {
        let identity = DevelopmentIdentity::from_secret_hex(&hex::encode([seed; 32])).unwrap();
        let server =
            PublicServer::with_continuous_domain(identity, PublicPolicy::development(), &domain)
                .unwrap();
        let cloned = server.mutation_cpu_domain();
        assert!(cloned.shares_domain_with(&domain));
        assert_eq!(cloned.observe().unwrap().stored_credit_ns, -123456789);
        let error = ingress::dispatch_shared_with_metered_work_facts(
            &node,
            request(&p),
            &facts,
            &cloned,
            &|| Ok(()),
        )
        .err()
        .unwrap();
        assert_eq!(error.to_string(), "PUBLIC_MUTATION_CPU_BUDGET");
        drop(server);
    }
    assert_eq!(domain.observe().unwrap().stored_credit_ns, -123456789);
    assert_eq!(facts.counters().full_replays, 0);
}
#[test]
fn two_reserved_real_owners_block_a_third_cache_entry_then_release_normally() {
    let (_dir, node, p) = fixture(1);
    let facts = WorkFactCache::new(1).unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    let rendezvous = std::sync::Barrier::new(3);
    thread::scope(|scope| {
        let owners: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    let op = domain.begin().unwrap();
                    rendezvous.wait();
                    rendezvous.wait();
                    op.finish()
                })
            })
            .collect();
        rendezvous.wait();
        let error = ingress::dispatch_shared_with_metered_work_facts(
            &node,
            request(&p),
            &facts,
            &domain,
            &|| Ok(()),
        )
        .err()
        .unwrap();
        assert_eq!(error.to_string(), "PUBLIC_MUTATION_CPU_BUDGET");
        assert_eq!(facts.counters().full_replays, 0);
        rendezvous.wait();
        for owner in owners {
            assert!(!owner.join().unwrap().accounting_unavailable);
        }
    });
    let out = ingress::dispatch_shared_with_metered_work_facts(
        &node,
        request(&p),
        &facts,
        &domain,
        &|| Ok(()),
    )
    .unwrap();
    assert!(out.native.is_ok());
    assert_paid(&domain, &out.cpu);
}
#[test]
fn panic_fences_shared_budget_without_rewriting_native_history() {
    let (_dir, node, p) = fixture(1);
    let facts = WorkFactCache::new(1).unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    let before = node.lock().unwrap().read_active().unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = ingress::dispatch_shared_with_metered_work_facts(
            &node,
            request(&p),
            &facts,
            &domain,
            &|| {
                assert_eq!(
                    facts.counters().full_replays,
                    0,
                    "injected W1 callback unwind"
                );
                Ok(())
            },
        );
    }));
    assert!(result.is_err());
    assert!(!domain.accounting_available());
    assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
    assert_eq!(
        domain.begin().err().unwrap().to_string(),
        "PUBLIC_MUTATION_CPU_UNAVAILABLE"
    );
}

#[test]
fn a_foreign_cpu_domain_is_refused_before_m05_work_and_any_reservation() {
    let (_dir, node, packet) = fixture(2);
    let facts = WorkFactCache::new(1).unwrap();
    let owner_domain = ServiceMutationCpuDomain::standalone();
    let foreign = ServiceMutationCpuDomain::standalone();
    node.lock()
        .unwrap()
        .bind_public_service_cpu_domain(&owner_domain)
        .unwrap();
    let before = node.lock().unwrap().read_active().unwrap();
    let foreign_before = foreign.observe().unwrap();
    let reject = ingress::dispatch_shared_with_metered_work_facts(
        &node,
        request(&packet),
        &facts,
        &foreign,
        &|| Ok(()),
    )
    .err()
    .unwrap();
    assert!(reject.is(crate::error::ErrorCode::OwnerPublicServiceCpuDomain));
    assert!(reject.requires_owner_stop());
    assert_eq!(reject.to_string(), "OWNER_PUBLIC_SERVICE_CPU_DOMAIN");
    assert_eq!(
        foreign.observe().unwrap().stored_credit_ns,
        foreign_before.stored_credit_ns
    );
    assert_eq!(foreign.observe().unwrap().in_flight, 0);
    assert_eq!(facts.counters().full_replays, 0);
    assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
    let real = ingress::dispatch_shared_with_metered_work_facts(
        &node,
        request(&packet),
        &facts,
        &owner_domain,
        &|| Ok(()),
    )
    .unwrap();
    assert!(real.native.is_ok());
    assert_paid(&owner_domain, &real.cpu);
    println!("METERED_NODE_BIND rejected_foreign=true foreign_cpu_reservations=0 valid_paid=true");
}

#[test]
fn continuously_distinct_bad_products_exhaust_one_original_prepaid_domain() {
    let (_dir, node, packet) = fixture(2);
    let facts = WorkFactCache::new(2).unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    let original = i128::from(MUTATION_CPU_START_RESERVE_NS) * 4;
    // Freeze only refill, not the measured owner/scoped-worker CPU clock. Every
    // verifier and failure below executes the real native admission path.
    freeze(&domain, original);
    let before = node.lock().unwrap().read_active().unwrap();
    let mut identities = std::collections::BTreeSet::new();
    let mut paid = 0_u64;
    let mut attempted = 0_u64;
    let mut exhausted = false;
    for index in 0..512 {
        let mut bad = packet.clone();
        let offset = 4 + 8 * 4096 + index * 4;
        let old = u32::from_le_bytes(bad.proof[offset..offset + 4].try_into().unwrap());
        // Different canonical C cell on every attempt. Valid A/B, the real
        // trace and its ticket stay intact: refusal requires the full original
        // replay/product check, unless original CPU accounting stops it first.
        let changed = if old == 4_294_967_290 { 0 } else { old + 1 };
        bad.proof[offset..offset + 4].copy_from_slice(&changed.to_le_bytes());
        assert!(identities.insert(hash(b"distinct-invalid-regression-v1", &[&bad.proof])));
        let cloned = domain.clone();
        match ingress::dispatch_shared_with_metered_work_facts(
            &node,
            request(&bad),
            &facts,
            &cloned,
            &|| Ok(()),
        ) {
            Err(error) => {
                assert_eq!(error.to_string(), "PUBLIC_MUTATION_CPU_BUDGET");
                exhausted = true;
                break;
            }
            Ok(outcome) => {
                let error = outcome.native.unwrap_err().to_string();
                assert!(
                    matches!(
                        error.as_str(),
                        "WORK:Product" | "PUBLIC_MUTATION_CPU_BUDGET"
                    ),
                    "{error}"
                );
                assert_paid(&domain, &outcome.cpu);
                paid = paid.checked_add(outcome.cpu.total_cpu_ns.unwrap()).unwrap();
                attempted += 1;
                let budget = domain.budget.lock().unwrap();
                assert_eq!(budget.credit_ns, original - i128::from(paid));
                assert_eq!(budget.verified_completions, 0);
                assert_eq!(budget.completion_work_len, 0);
            }
        }
    }
    assert!(
        exhausted && attempted > 0,
        "paid={paid} attempted={attempted}"
    );
    assert_eq!(facts.counters().hits, 0);
    assert!(facts.counters().full_replays > 0);
    let replays = facts.counters().full_replays;
    let flow = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(flow.paid_cpu_debit_ns, paid);
    assert_eq!(flow.live_owners, 0);
    for index in 1000..1008 {
        let mut bad = packet.clone();
        bad.proof[index] ^= 1;
        assert_eq!(
            ingress::dispatch_shared_with_metered_work_facts(
                &node,
                request(&bad),
                &facts,
                &domain.clone(),
                &|| Ok(()),
            )
            .err()
            .unwrap()
            .to_string(),
            "PUBLIC_MUTATION_CPU_BUDGET"
        );
    }
    assert_eq!(facts.counters().full_replays, replays);
    assert_eq!(
        domain
            .observe_actual_flow()
            .unwrap()
            .unwrap()
            .paid_cpu_debit_ns,
        paid
    );
    assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
    println!("DISTINCT_W1_REFUSALS attempts={attempted} actual_cpu_ns={paid} hits=0 retained_state_unchanged=true exhausted_before_next_replay=true");
}

#[test]
fn fixed_structural_refusals_pay_one_owner_without_touching_warm_work_facts() {
    use trnm_crypto_primitives::pon_work;

    let (_dir, node, packet) = fixture(2);
    let facts = WorkFactCache::new(2).unwrap();
    // The existing genuine fixture supplies one mathematical fact. The fixed
    // bad-version/noncanonical-word controls must fail before consulting it.
    facts
        .verify(
            packet.header.challenge(),
            packet.header.work_task,
            packet.header.target,
            &packet.proof,
        )
        .unwrap();
    let cached = facts.counters();
    let domain = ServiceMutationCpuDomain::standalone();
    let original = i128::from(MUTATION_CPU_BURST_NS);
    freeze(&domain, original);
    let before = node.lock().unwrap().read_active().unwrap();
    let before_stats = node.lock().unwrap().stats().unwrap();
    let mut bad_version = packet.clone();
    bad_version.proof[0] ^= 1;
    let mut cases = vec![(bad_version, "WORK:Version")];
    // Reuse the three fixed encoding-boundary fixtures from the ordinary
    // ingress precheck test. This is a bounded local accounting regression.
    for offset in [4, 4 + pon_work::CELLS * 4, 4 + pon_work::CELLS * 8] {
        let mut bad_field = packet.clone();
        bad_field.proof[offset..offset + 4].copy_from_slice(&(pon_work::Q as u32).to_le_bytes());
        cases.push((bad_field, "WORK:Field"));
    }
    let mut paid = 0_u64;
    for (malformed, expected) in cases {
        let same_owner = domain.clone();
        assert!(same_owner.shares_domain_with(&domain));
        let outcome = ingress::dispatch_shared_with_metered_work_facts(
            &node,
            request(&malformed),
            &facts,
            &same_owner,
            &|| Ok(()),
        )
        .unwrap();
        let error = outcome.native.unwrap_err();
        assert_eq!(error.to_string(), expected);
        assert!(!error.requires_owner_stop());
        assert_paid(&domain, &outcome.cpu);
        assert_eq!(outcome.cpu.spawned_workers, 0);
        paid = paid.checked_add(outcome.cpu.total_cpu_ns.unwrap()).unwrap();
        let flow = domain.observe_actual_flow().unwrap().unwrap();
        assert_eq!(flow.paid_cpu_debit_ns, paid);
        assert_eq!(flow.stored_credit_ns, original - i128::from(paid));
        assert_eq!(flow.booked_reservation_ns, 0);
        assert_eq!(flow.termination_reserved_ns, 0);
        assert_eq!(flow.unsettled_known_live_cpu_ns, 0);
        assert_eq!(flow.credited_refill_ns, 0);
        assert_eq!(facts.counters(), cached);
        assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
        assert_eq!(node.lock().unwrap().stats().unwrap(), before_stats);
    }
    // Returning an unused start reservation does not refund the parse/check
    // CPU already paid, and a grammar failure does not promote completion.
    let budget = domain.budget.lock().unwrap();
    assert_eq!(budget.verified_completions, 0);
    assert_eq!(budget.completion_work_len, 0);
}

#[test]
fn fixed_refusal_releases_only_its_own_reserve_while_cleanup_remains_owned() {
    use std::sync::mpsc;

    let (_dir, node, mut packet) = fixture(1);
    packet.proof[0] ^= 1;
    let facts = WorkFactCache::new(1).unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    let original = i128::from(MUTATION_CPU_BURST_NS);
    freeze(&domain, original);
    let before = node.lock().unwrap().read_active().unwrap();
    let before_stats = node.lock().unwrap().stats().unwrap();
    let same_owner = domain.clone();
    let (ready, ready_rx) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let (ready_result, reserved, rejected, retained, held_result) = thread::scope(|scope| {
        // A separate actual thread avoids nested owner CPU measurements.
        // It owns the original start and cleanup reservations until released.
        let held = scope.spawn(move || {
            let operation = same_owner.begin().unwrap();
            let cleanup = operation
                .checkpoint_handle()
                .reserve_reorg_termination()
                .unwrap();
            ready.send(()).unwrap();
            let released = release_rx.recv_timeout(Duration::from_secs(10));
            drop(cleanup);
            let receipt = operation.finish();
            (released, receipt)
        });
        let ready_result = ready_rx.recv_timeout(Duration::from_secs(10));
        let reserved = domain.observe_actual_flow();
        let rejected = ingress::dispatch_shared_with_metered_work_facts(
            &node,
            request(&packet),
            &facts,
            &domain,
            &|| Ok(()),
        );
        let retained = domain.observe_actual_flow();
        // Release and join before assertions, so a failed control cannot leave
        // the other owner waiting indefinitely or invent stopped-worker proof.
        let _ = release.send(());
        (ready_result, reserved, rejected, retained, held.join())
    });
    ready_result.unwrap();
    let reserved = reserved.unwrap().unwrap();
    let rejected = rejected.unwrap();
    assert_eq!(rejected.native.unwrap_err().to_string(), "WORK:Version");
    let retained = retained.unwrap().unwrap();
    let (released, held_receipt) = held_result.unwrap();
    released.unwrap();
    assert!(retained.balance_identity_verified);
    assert_eq!(retained.live_owners, 1);
    assert_eq!(
        retained.booked_reservation_ns,
        MUTATION_CPU_START_RESERVE_NS
    );
    assert_eq!(
        retained.termination_reserved_ns,
        REORG_TERMINATION_RESERVE_NS
    );
    assert_eq!(
        retained.paid_cpu_debit_ns,
        reserved
            .paid_cpu_debit_ns
            .checked_add(rejected.cpu.total_cpu_ns.unwrap())
            .unwrap()
    );
    assert_eq!(
        retained.stored_credit_ns,
        original
            - i128::from(retained.paid_cpu_debit_ns)
            - i128::from(MUTATION_CPU_START_RESERVE_NS)
            - i128::from(REORG_TERMINATION_RESERVE_NS)
    );
    assert_paid(&domain, &rejected.cpu);
    assert_paid(&domain, &held_receipt);
    let paid = rejected
        .cpu
        .total_cpu_ns
        .unwrap()
        .checked_add(held_receipt.total_cpu_ns.unwrap())
        .unwrap();
    let flow = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(flow.paid_cpu_debit_ns, paid);
    assert_eq!(flow.stored_credit_ns, original - i128::from(paid));
    assert_eq!(flow.booked_reservation_ns, 0);
    assert_eq!(flow.termination_reserved_ns, 0);
    assert_eq!(flow.unsettled_known_live_cpu_ns, 0);
    assert_eq!(flow.credited_refill_ns, 0);
    assert_eq!(facts.counters().full_replays, 0);
    assert_eq!(facts.counters().hits, 0);
    assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
    assert_eq!(node.lock().unwrap().stats().unwrap(), before_stats);
}

#[test]
fn cancelled_fixed_product_refusal_and_retry_keep_actual_debit_and_cleanup() {
    let (_dir, node, packet) = fixture(2);
    let facts = WorkFactCache::new(2).unwrap();
    facts
        .verify(
            packet.header.challenge(),
            packet.header.work_task,
            packet.header.target,
            &packet.proof,
        )
        .unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    let original = i128::from(MUTATION_CPU_BURST_NS);
    freeze(&domain, original);
    let before = node.lock().unwrap().read_active().unwrap();
    let before_stats = node.lock().unwrap().stats().unwrap();
    // Same fixed local product fixture as the retained warm-retry test above.
    let mut malformed = packet;
    malformed.proof[4 + 8 * 4096] ^= 1;
    let cancelled = ingress::dispatch_shared_with_metered_work_facts(
        &node,
        request(&malformed),
        &facts,
        &domain,
        &|| {
            if facts.counters().hits > 0 {
                Err("METERED_FIXED_REFUSAL_CANCEL".into())
            } else {
                Ok(())
            }
        },
    )
    .unwrap();
    assert_eq!(
        cancelled.native.unwrap_err().to_string(),
        "METERED_FIXED_REFUSAL_CANCEL"
    );
    assert_paid(&domain, &cancelled.cpu);
    assert_eq!(cancelled.cpu.spawned_workers, 0);
    assert_eq!(facts.counters().hits, 1);
    let paid_cancel = cancelled.cpu.total_cpu_ns.unwrap();
    let after_cancel = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(after_cancel.paid_cpu_debit_ns, paid_cancel);
    assert_eq!(
        after_cancel.stored_credit_ns,
        original - i128::from(paid_cancel)
    );
    assert_eq!(after_cancel.booked_reservation_ns, 0);
    assert_eq!(after_cancel.termination_reserved_ns, 0);
    assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
    let same_owner = domain.clone();
    let refused = ingress::dispatch_shared_with_metered_work_facts(
        &node,
        request(&malformed),
        &facts,
        &same_owner,
        &|| Ok(()),
    )
    .unwrap();
    assert_eq!(refused.native.unwrap_err().to_string(), "WORK:Product");
    assert_paid(&domain, &refused.cpu);
    assert_eq!(refused.cpu.spawned_workers, 0);
    let paid = paid_cancel
        .checked_add(refused.cpu.total_cpu_ns.unwrap())
        .unwrap();
    let flow = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(flow.paid_cpu_debit_ns, paid);
    assert_eq!(flow.stored_credit_ns, original - i128::from(paid));
    assert_eq!(flow.booked_reservation_ns, 0);
    assert_eq!(flow.termination_reserved_ns, 0);
    assert_eq!(flow.unsettled_known_live_cpu_ns, 0);
    assert_eq!(flow.credited_refill_ns, 0);
    assert_eq!(facts.counters().full_replays, 1);
    assert_eq!(facts.counters().hits, 2);
    assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
    assert_eq!(node.lock().unwrap().stats().unwrap(), before_stats);
    let budget = domain.budget.lock().unwrap();
    assert_eq!(budget.verified_completions, 0);
    assert_eq!(budget.completion_work_len, 0);
}
