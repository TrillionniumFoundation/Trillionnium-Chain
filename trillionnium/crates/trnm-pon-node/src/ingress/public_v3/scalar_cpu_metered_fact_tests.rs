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
        .snapshot(b.credit_ns, b.in_flight)
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
    assert!(!reject.requires_owner_stop());
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
fn a_foreign_cpu_domain_cannot_mask_unavailable_bound_owner_accounting() {
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
    // An actual abandoned original operation makes accounting unavailable;
    // a caller with another domain must not downgrade that fatal condition.
    drop(owner_domain.begin().unwrap());
    assert!(!owner_domain.accounting_available());
    let error = ingress::dispatch_shared_with_metered_work_facts(
        &node,
        request(&packet),
        &facts,
        &foreign,
        &|| Ok(()),
    )
    .err()
    .unwrap();
    assert!(error.is(crate::error::ErrorCode::PublicMutationCpuUnavailable));
    assert!(error.requires_owner_stop());
    assert_eq!(
        foreign.observe().unwrap().stored_credit_ns,
        foreign_before.stored_credit_ns
    );
    assert_eq!(foreign.observe().unwrap().in_flight, 0);
    assert_eq!(facts.counters().full_replays, 0);
    assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
    assert!(node
        .lock()
        .unwrap()
        .continuous_domain_matches(&owner_domain));
    assert!(!owner_domain.accounting_available());
}
