//! Real loopback Cookie/TCP admission of distinct false W1 transcripts.
//!
//! This closes the component-to-listener observation gap without changing any
//! verifier, resource limit, absolute timeout, or production qualification.
//! Sequential requests with rotating development identities are not a saturated
//! Sybil/WAN campaign or evidence of an adversary's minimum construction cost.
#![cfg(target_os = "linux")]

use std::{
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use trnm_crypto_primitives::pon_work;
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v3::{
            self, PublicMetrics, PublicPolicy, PublicReply, PublicRequestObserver, PublicServer,
            Request, ServiceMutationCpuDomain,
        },
        DevelopmentIdentity,
    },
    ErrorCode, Node, Packet, PoolLimits, Settings,
};

fn identity(seed: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([seed; 32])).unwrap()
}

struct Service {
    address: SocketAddr,
    server_seed: u8,
    stop: Arc<AtomicBool>,
    observer: PublicRequestObserver,
    worker: Option<thread::JoinHandle<trnm_pon_node::Result<PublicMetrics>>>,
}

impl Service {
    fn start(owner: Arc<Mutex<Node>>, server: PublicServer, server_seed: u8) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let observer = PublicRequestObserver::new(16).unwrap();
        let observed = observer.clone();
        let worker = thread::spawn(move || {
            public_v3::serve_public_protected_v3_with_request_observer(
                listener,
                owner,
                Duration::from_secs(30),
                signal,
                server,
                Arc::new(Mutex::new(PublicMetrics::default())),
                observed,
            )
        });
        Self {
            address,
            server_seed,
            stop,
            observer,
            worker: Some(worker),
        }
    }

    fn call(
        &self,
        request: &Request,
        settings: &Settings,
        caller_seed: u8,
        policy: PublicPolicy,
    ) -> PublicReply {
        let (reply, actual) = public_v3::call_public_protected_v3_with_metrics(
            self.address,
            request,
            settings,
            identity(self.server_seed).public_key(),
            &identity(caller_seed),
            policy,
        );
        let reply = reply.unwrap();
        assert!(
            actual.solution_found,
            "real Cookie work must precede the body"
        );
        reply
    }

    fn finish(&mut self) -> PublicMetrics {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap().unwrap()
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        // A failed assertion still stops and joins the real listener workers.
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn distinct_false_traces(valid: &Packet) -> (Vec<Packet>, u64) {
    let mut packets = Vec::new();
    let challenge = valid.header.challenge();
    let trace_offset = pon_work::PROOF_BYTES - 32;
    let mut attempts = 0u64;
    for nonce in 0u64..65_536 {
        attempts += 1;
        let trace = pon_work::hash(
            b"public-v3-distinct-invalid-wire-v1",
            &[&challenge, &nonce.to_le_bytes()],
        );
        if trace.as_slice() == &valid.proof[trace_offset..]
            || pon_work::hash(b"ticket", &[&challenge, &trace]) > valid.header.target
        {
            continue;
        }
        let mut packet = valid.clone();
        packet.proof[trace_offset..].copy_from_slice(&trace);
        pon_work::precheck_proof_statement(
            packet.header.challenge(),
            packet.header.work_task,
            packet.header.target,
            &packet.proof,
        )
        .unwrap();
        assert_eq!(
            pon_work::verify(
                packet.header.challenge(),
                packet.header.work_task,
                packet.header.target,
                &packet.proof,
            )
            .unwrap_err(),
            pon_work::WorkError::Transcript,
        );
        assert!(packets
            .iter()
            .all(|prior: &Packet| prior.proof != packet.proof));
        packets.push(packet);
        if packets.len() == 4 {
            return (packets, attempts);
        }
    }
    panic!("bounded fixture search did not produce four distinct passing prechecks");
}

#[test]
fn distinct_false_traces_and_cross_listener_retry_pay_one_shared_domain_without_effects() {
    let now = ingress::now().unwrap();
    let settings = Settings::development(Some(now - 100)).unwrap();
    let oracle_dir = tempfile::tempdir().unwrap();
    let oracle = Node::open(oracle_dir.path(), settings.clone(), 1).unwrap();
    let valid = oracle
        .make(
            settings.genesis(),
            vec![],
            development_public(3).unwrap(),
            now - 90,
            4096,
        )
        .unwrap();
    let (invalid, search_attempts) = distinct_false_traces(&valid);
    let receiver_dir = tempfile::tempdir().unwrap();
    let mut receiver = Node::open(receiver_dir.path(), settings.clone(), 1).unwrap();
    receiver
        .enable_local_mempool(PoolLimits {
            max_records: 8,
            max_bytes: 32768,
            max_group_members: 4,
            critical_reserve: 0,
            max_removals: 16,
            preview_miner: development_public(3).unwrap(),
        })
        .unwrap();
    let initial_state = receiver.read_active().unwrap();
    let owner = Arc::new(Mutex::new(receiver));
    // The existing 8-bit development fixture profile is explicit. The original
    // public default, 30-second campaign and policy constants are not modified.
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let first = PublicServer::new_process_cold(identity(71), policy).unwrap();
    let domain: ServiceMutationCpuDomain = first.mutation_cpu_domain();
    let initial_cpu = domain.observe().unwrap();
    assert_eq!(initial_cpu.stored_credit_ns, 0);
    let second = PublicServer::with_continuous_domain(identity(72), policy, &domain).unwrap();
    assert!(second.mutation_cpu_domain().shares_domain_with(&domain));
    let mut services = [
        Service::start(owner.clone(), first, 71),
        Service::start(owner.clone(), second, 72),
    ];
    let mut last_debit = 0u64;
    // Four distinct proofs, then the first exact proof over the other listener
    // and another authenticated identity. No rejection/arithmetic cache is enabled.
    for (request_index, proof_index) in [0usize, 1, 2, 3, 0].into_iter().enumerate() {
        let listener_index = if request_index == 4 {
            1
        } else {
            request_index % 2
        };
        let rejected = services[listener_index].call(
            &Request::Submit {
                packet: hex::encode(invalid[proof_index].encode().unwrap()),
            },
            &settings,
            80 + request_index as u8,
            policy,
        );
        assert!(!rejected.ok);
        assert_eq!(rejected.value["error"], "WORK:Transcript");
        assert_eq!(owner.lock().unwrap().read_active().unwrap(), initial_state);
        assert_eq!(
            owner.lock().unwrap().active().unwrap().0,
            settings.genesis()
        );
        assert!(owner.lock().unwrap().packet(valid.id().unwrap()).is_err());
        assert_eq!(
            owner
                .lock()
                .unwrap()
                .packet(invalid[proof_index].id().unwrap())
                .unwrap_err()
                .code(),
            Some(ErrorCode::UnknownParent),
        );
        let flow = domain.observe_actual_flow().unwrap().unwrap();
        assert!(flow.balance_identity_verified);
        assert_eq!(flow.initial_credit_ns, 0);
        assert_eq!(flow.live_owners, 0);
        assert!(flow.settled_full_cpu_ns > last_debit);
        last_debit = flow.settled_full_cpu_ns;
        let completion = domain.observe_completion_work().unwrap();
        assert_eq!(completion.retained_identities, 0);
        assert_eq!(completion.live_completions, 0);
    }
    for service in &services {
        let head = service.call(&Request::Head, &settings, 90, policy);
        assert!(head.ok);
        assert_eq!(head.value["height"], 0);
    }
    let accepted = services[0].call(
        &Request::Submit {
            packet: hex::encode(valid.encode().unwrap()),
        },
        &settings,
        91,
        policy,
    );
    assert!(accepted.ok, "{}", accepted.value);
    assert_eq!(
        owner.lock().unwrap().active().unwrap().0,
        valid.id().unwrap()
    );
    let metrics: Vec<_> = services.iter_mut().map(Service::finish).collect();
    let sum = |f: fn(&PublicMetrics) -> u64| metrics.iter().map(f).sum::<u64>();
    assert_eq!(sum(|m| m.accepted_connections), 8);
    assert_eq!(sum(|m| m.delivered_response_frames), 8);
    assert_eq!(sum(|m| m.work_started), 6);
    assert_eq!(sum(|m| m.work_finished), 6);
    assert_eq!(sum(|m| m.work_failed), 5);
    assert_eq!(sum(|m| m.executor_refusals), 5);
    assert_eq!(sum(|m| m.completed_submit), 1);
    assert_eq!(sum(|m| m.completed_read), 2);
    assert_eq!(sum(|m| m.mutation_cpu_reservations), 6);
    assert_eq!(sum(|m| m.mutation_cpu_clock_failures), 0);
    assert_eq!(sum(|m| m.unknown_caller_durable_rows), 0);
    assert!(sum(|m| m.mutation_full_work_cpu_ns) > 0);
    assert_eq!(
        sum(|m| m.mutation_full_work_cpu_ns + m.mutation_dispatch_excluding_work_cpu_ns),
        sum(|m| m.mutation_cpu_charged_ns),
    );
    for m in &metrics {
        assert_eq!(m.mutation_cpu_in_flight_after_shutdown, 0);
        assert!(!m.mutation_cpu_unavailable_after_shutdown);
        assert_eq!(m.paid_body_reserved_bytes_after_shutdown, 0);
        assert_eq!(m.output_reserved_bytes_after_shutdown, 0);
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.read_grants_after_shutdown, 0);
    }
    let flow = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(flow.live_owners, 0);
    assert_eq!(flow.settled_full_cpu_ns, sum(|m| m.mutation_cpu_charged_ns));
    assert_eq!(flow.paid_cpu_debit_ns, flow.settled_full_cpu_ns);
    assert!(flow.balance_identity_verified);
    let completion = domain.observe_completion_work().unwrap();
    assert_eq!(completion.retained_identities, 1);
    assert_eq!(completion.live_completions, 0);
    let mut full_work_records = 0usize;
    let mut failed_work_records = 0usize;
    for service in &services {
        let snapshot = service.observer.snapshot();
        assert!(snapshot.coverage_complete());
        assert_eq!(snapshot.measurement_failures, 0);
        for row in snapshot.records {
            if row.full_work_started {
                full_work_records += 1;
                failed_work_records += usize::from(row.full_work_accepted == Some(false));
                assert!(row.full_work_thread_cpu_ns.unwrap() > 0);
                let settled = row.cpu_settlement.unwrap();
                assert!(settled.budget_settled);
                assert!(settled.total_cpu_ns.unwrap() > 0);
                assert_eq!(
                    settled.total_cpu_ns.unwrap(),
                    settled.live_paid_cpu_ns.unwrap() + settled.residual_cpu_ns.unwrap(),
                );
            }
        }
    }
    assert_eq!((full_work_records, failed_work_records), (6, 5));
    let final_state = owner.lock().unwrap().read_active().unwrap();
    let independent_dir = tempfile::tempdir().unwrap();
    let mut independent = Node::open(independent_dir.path(), settings.clone(), 1).unwrap();
    let independent_id = independent.admit(&valid, now).unwrap();
    independent.activate(independent_id).unwrap();
    assert_eq!(final_state, independent.read_active().unwrap());
    drop(owner);
    let reopened = Node::open(receiver_dir.path(), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), final_state);
    for rejected in &invalid {
        assert_eq!(
            reopened.packet(rejected.id().unwrap()).unwrap_err().code(),
            Some(ErrorCode::UnknownParent),
        );
    }
    println!(
        "{}",
        serde_json::json!({
            "schema": "public-v3-distinct-invalid-wire-lab-v1",
            "distinct_false_transcripts": 4,
            "fixture_false_trace_search_attempts": search_attempts,
            "passing_statement_prechecks": 4,
            "native_cookie_tcp_transcript_refusals": 5,
            "authenticated_invalid_caller_identities": 5,
            "listeners": 2,
            "shared_cpu_domains": 1,
            "initial_cpu_credit_ns": 0,
            "paid_mutation_reservations": 6,
            "paid_mutation_cpu_ns": flow.settled_full_cpu_ns,
            "false_work_priority_grants": 0,
            "false_work_ledger_effects": 0,
            "honest_reads_after_rejection": 2,
            "honest_native_submits_after_rejection": 1,
            "independent_state_verification": true,
            "receiver_cold_reopen_matches": true,
            "fixture_cookie_bits": 8,
            "saturation_claim": false,
            "cross_process_budget_claim": false,
            "wan_and_sybil_qualified": false,
            "production_activation": false,
        })
    );
}
