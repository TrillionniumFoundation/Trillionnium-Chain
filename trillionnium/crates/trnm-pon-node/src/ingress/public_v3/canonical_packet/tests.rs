//! Same-binary transport/codec controls. These are not the original service gate.
//! The owned oracle is the retained d26 implementation, independent of this
//! module's witness constructor; native dispatch still performs real PNW1 work.
use super::super::*;
use super::{CanonicalPacketText, DecodedTaskBody};
use trnm_crypto_primitives::pon_work;

fn server() -> PublicServer {
    PublicServer::new(
        DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap(),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
    )
    .unwrap()
}

fn fixture() -> (tempfile::TempDir, Settings, crate::Packet) {
    let directory = tempfile::tempdir().unwrap();
    let clock = crate::ingress::now().unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let source = Node::open(directory.path(), settings.clone(), 1).unwrap();
    let packet = source
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            clock - 50,
            4096,
        )
        .unwrap();
    (directory, settings, packet)
}

fn body(raw: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&Request::Submit {
        packet: hex::encode(raw),
    })
    .unwrap()
}

fn owned_packet_oracle(raw_body: &[u8]) -> Result<crate::Packet> {
    let Request::Submit { packet } = canonical_request(raw_body, 1)? else {
        unreachable!("owned Submit oracle")
    };
    super::super::super::hex_packet(&packet)
}

fn round_trip(packet: Result<crate::Packet>) -> std::result::Result<Vec<u8>, String> {
    packet
        .and_then(|packet| packet.encode())
        .map_err(|e| e.to_string())
}

#[test]
fn borrowed_complete_packet_codec_matches_owned_for_valid_and_malformed_boundaries() {
    let (_directory, settings, packet) = fixture();
    let raw = packet.encode().unwrap();
    assert_eq!(raw.len(), crate::HEADER_BYTES + 2 + pon_work::PROOF_BYTES);
    let full_body = body(&raw);
    let witness = CanonicalPacketText::from_body(&full_body).unwrap();
    let prefix = br#"{"op":"submit","packet":""#;
    assert_eq!(witness.text.as_ptr(), full_body[prefix.len()..].as_ptr());
    assert_eq!(witness.text.len(), 2 * raw.len());
    assert_eq!(witness.decode().unwrap().proof, packet.proof);
    assert_eq!(round_trip(witness.decode()).unwrap(), raw);

    let envelope = crate::Envelope {
        network: settings.network(),
        sender: crate::development_public(0).unwrap(),
        nonce: 1,
        expiry: 0,
        fee_limit: 0,
        tag: 1,
        payload: vec![0; 40],
        signature: [0; 64],
    }
    .encode()
    .unwrap();
    // Envelope signatures and header commitments are intentionally not verdicts
    // of Packet::decode. The complete codec must copy their actual bytes and the
    // actual complete proof; native authorization is exercised separately below.
    let mut with_transactions = packet.clone();
    with_transactions.transactions = vec![envelope; 256];
    let transaction_wire = with_transactions.encode().unwrap();
    let mut cases = vec![
        ("complete-proof".to_owned(), raw.clone()),
        (
            "maximum-transaction-count".to_owned(),
            transaction_wire.clone(),
        ),
        ("maximum-packet-bytes".to_owned(), vec![0; MAX_PACKET]),
    ];
    for length in [
        0,
        1,
        crate::HEADER_BYTES - 1,
        crate::HEADER_BYTES,
        crate::HEADER_BYTES + 1,
        raw.len() - 1,
    ] {
        cases.push((format!("truncated-{length}"), raw[..length].to_vec()));
    }
    for position in [0, 1, crate::HEADER_BYTES - 1, raw.len() - 33, raw.len() - 1] {
        let mut changed = raw.clone();
        changed[position] ^= 0xff;
        cases.push((format!("changed-{position}"), changed));
    }
    let mut count_overflow = raw.clone();
    count_overflow[crate::HEADER_BYTES..crate::HEADER_BYTES + 2]
        .copy_from_slice(&257u16.to_le_bytes());
    cases.push(("count-overflow".to_owned(), count_overflow));
    let mut trailing = raw.clone();
    trailing.push(0);
    cases.push(("trailing-byte".to_owned(), trailing));
    for length in [0u16, 158, 159, 2048, 2049, u16::MAX] {
        let mut changed = transaction_wire.clone();
        changed[crate::HEADER_BYTES + 2..crate::HEADER_BYTES + 4]
            .copy_from_slice(&length.to_le_bytes());
        cases.push((format!("transaction-length-{length}"), changed));
    }
    for (label, raw) in cases {
        let raw_body = body(&raw);
        let witness = CanonicalPacketText::from_body(&raw_body).unwrap();
        assert_eq!(
            round_trip(witness.decode()),
            round_trip(owned_packet_oracle(&raw_body)),
            "{label}"
        );
    }
}

fn paid_task(raw_body: Vec<u8>, op: u8, server: &PublicServer, settings: &Settings) -> Task {
    let cookie = server
        .cookie(
            settings,
            Hello {
                op,
                len: raw_body.len(),
                caller: [3; 32],
                digest: hash(b"public-request-body-v3", &[&raw_body]),
                client_nonce: [4; 32],
            },
            "127.0.0.1:1".parse().unwrap(),
        )
        .unwrap();
    let body_bytes = raw_body.len() * 3;
    Task {
        id: 1,
        cookie,
        raw_body,
        ready_at: Instant::now(),
        backpressure_seen: false,
        deadline: Instant::now() + Duration::from_secs(2),
        cancelled: Arc::new(AtomicBool::new(false)),
        _permit: BufferPermit::acquire(Arc::new(Mutex::new(0)), body_bytes, MAX_PAID_BODY_BYTES)
            .unwrap(),
        _lane_permit: Arc::new(
            BufferPermit::acquire(Arc::new(Mutex::new(0)), 1, MAX_MUTATING_GRANTS).unwrap(),
        ),
        observation: None,
    }
}

// Retained original order, without calling the new witness constructor. The
// independent serde oracle in input_decode_tests also checks the JSON grammar.
fn owned_task_body_oracle(
    task: &Task,
    server: &PublicServer,
    settings: &Settings,
) -> Result<Request> {
    ensure(
        task.raw_body.len() == task.cookie.body_len as usize,
        "PUBLIC_BODY_LIMIT",
    )?;
    ensure(
        task.cookie.body_digest == hex::encode(hash(b"public-request-body-v3", &[&task.raw_body])),
        "PUBLIC_BODY_DIGEST",
    )?;
    let request = canonical_request(&task.raw_body, task.cookie.op)?;
    server.validate(&task.cookie, settings, false)?;
    Ok(request)
}

#[test]
fn borrowed_body_keeps_original_error_order_and_same_task_permit_lifetime() {
    let server = server();
    let settings = Settings::development(Some(1_700_000_000)).unwrap();
    for (case, raw_body, fault, expected) in [
        (
            "length-first",
            br#"{"op":"submit","packet":"g"}"#.as_slice(),
            1,
            "PUBLIC_BODY_LIMIT",
        ),
        (
            "digest-before-grammar",
            br#"{"op":"submit","packet":"g"}"#.as_slice(),
            2,
            "PUBLIC_BODY_DIGEST",
        ),
        (
            "envelope-before-cookie",
            br#"{"packet":"00","op":"submit"}"#.as_slice(),
            3,
            "PUBLIC_REQUEST_CANONICAL",
        ),
        (
            "hex-before-cookie",
            br#"{"op":"submit","packet":"g0"}"#.as_slice(),
            3,
            "PUBLIC_PACKET_TEXT",
        ),
        (
            "cookie-before-codec",
            br#"{"op":"submit","packet":"00"}"#.as_slice(),
            3,
            "PUBLIC_COOKIE_MAC",
        ),
    ] {
        let mut task = paid_task(raw_body.to_vec(), 1, &server, &settings);
        match fault {
            1 => task.cookie.body_len += 1,
            2 => task.cookie.body_digest = hex::encode([0; 32]),
            3 => task.cookie.mac = hex::encode([0; 32]),
            _ => unreachable!(),
        }
        let original = owned_task_body_oracle(&task, &server, &settings)
            .map(|_| ())
            .map_err(|e| e.to_string());
        let borrowed = decode_task_body(&task, &server, &settings, None)
            .map(|_| ())
            .map_err(|e| e.to_string());
        assert_eq!(borrowed, original, "{case}");
        assert_eq!(borrowed.unwrap_err(), expected, "{case}");
    }

    let mut task = paid_task(body(&[0]), 1, &server, &settings);
    let body_pool = task._permit.pool.clone();
    let lane_pool = task._lane_permit.pool.clone();
    let reserved = task.raw_body.len() * 3;
    {
        let DecodedTaskBody::CanonicalSubmit(packet) =
            decode_task_body(&task, &server, &settings, None).unwrap()
        else {
            panic!("ordinary paid Submit must use borrowed transport grammar")
        };
        assert_eq!(*body_pool.lock().unwrap(), reserved);
        assert_eq!(*lane_pool.lock().unwrap(), 1);
        assert_eq!(packet.decode().err().unwrap().to_string(), "PACKET_LIMIT");
    }
    // The production worker retains the original raw allocation through
    // dispatch, then drops it before response construction/CPU settlement.
    drop(std::mem::take(&mut task.raw_body));
    assert_eq!(*body_pool.lock().unwrap(), reserved);
    assert_eq!(*lane_pool.lock().unwrap(), 1);
    drop(task);
    assert_eq!(*body_pool.lock().unwrap(), 0);
    assert_eq!(*lane_pool.lock().unwrap(), 0);

    let head = paid_task(br#"{"op":"head"}"#.to_vec(), 2, &server, &settings);
    assert!(matches!(
        decode_task_body(&head, &server, &settings, None).unwrap(),
        DecodedTaskBody::Owned(Request::Head)
    ));
}

fn dispatch_case(
    directory: &std::path::Path,
    settings: &Settings,
    raw_body: &[u8],
    borrowed: bool,
    cancel: bool,
) -> Value {
    let node = Mutex::new(Node::open(directory, settings.clone(), 1).unwrap());
    let server = server();
    let metrics = Mutex::new(PublicMetrics::default());
    let permit = PaidMutationCpuPermit::acquire(&server, &metrics).unwrap();
    let measurement = MutationCpuMeasurement::for_permit(Some(&permit));
    let stop = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + Duration::from_secs(2);
    permit
        .live
        .bind_public_request(deadline, stop.clone(), cancelled.clone())
        .unwrap();
    let record = TaskObservation::local(Instant::now());
    let task = paid_task(raw_body.to_vec(), 1, &server, settings);
    let decoded =
        super::super::super::observe_submit_phase(Some(&record), SubmitPhase::BodyDecode, || {
            if borrowed {
                decode_task_body(&task, &server, settings, Some(&measurement))
            } else {
                let stamp = ThreadCpuStamp::start().unwrap();
                let decoded = owned_task_body_oracle(&task, &server, settings);
                measurement.record_phase(&measurement.body_decode_ns, stamp.finish());
                decoded.map(DecodedTaskBody::Owned)
            }
        })
        .unwrap();
    cancelled.store(cancel, Ordering::Release);
    let result = public_dispatch(
        &node,
        decoded,
        deadline,
        &stop,
        &cancelled,
        &metrics,
        PublicDispatchObservation {
            observation: Some(&record),
            mutation_cpu: Some(&measurement),
            arithmetic_facts: None,
            w1_rejection_cache: None,
        },
    )
    .map_err(|e| e.to_string());
    drop(task);
    assert!(permit
        .finish_observed(&measurement, &server, &metrics, Some(&record))
        .is_some());
    let (phases, failures) = record.phase_snapshot();
    assert_eq!(failures, 0);
    let phases: Vec<_> = phases
        .into_iter()
        .map(|phase| {
            serde_json::json!({
                "phase": phase.phase,
                "started": phase.started,
                "completed": phase.completed,
                "accepted": phase.accepted,
                "error_code": phase.error_code,
                "parent_phase": phase.parent_phase,
            })
        })
        .collect();
    let observed = metrics.lock().unwrap();
    assert_eq!(observed.mutation_cpu_clock_failures, 0);
    assert_eq!(observed.mutation_cpu_reservations, 1);
    assert_eq!(
        observed.mutation_cpu_charged_ns,
        observed.mutation_full_work_cpu_ns + observed.mutation_dispatch_excluding_work_cpu_ns
    );
    assert!(observed.mutation_cpu_charged_ns > 0);
    serde_json::json!({
        "result": result,
        "active": node.lock().unwrap().read_active().unwrap(),
        "phases": phases,
        "work_started": observed.work_started,
        "work_finished": observed.work_finished,
        "work_failed": observed.work_failed,
    })
}

#[test]
fn borrowed_submit_matches_owned_native_work_context_cancellation_and_phase_outcomes() {
    let (directory, settings, packet) = fixture();
    let mut product = packet.clone();
    let offset = 4 + 2 * pon_work::CELLS * 4;
    let word = u32::from_le_bytes(product.proof[offset..offset + 4].try_into().unwrap());
    product.proof[offset..offset + 4].copy_from_slice(&u32::from(word == 0).to_le_bytes());
    let mut foreign = packet.clone();
    foreign.header.network[0] ^= 1;
    let cases = [
        ("valid", body(&packet.encode().unwrap()), false, 1),
        (
            "full-work-product",
            body(&product.encode().unwrap()),
            false,
            1,
        ),
        (
            "current-context",
            body(&foreign.encode().unwrap()),
            false,
            0,
        ),
        ("cancelled", body(&packet.encode().unwrap()), true, 0),
        ("packet-codec", body(&[0]), false, 0),
    ];
    for (label, raw_body, cancelled, started) in cases {
        let original = dispatch_case(
            &directory.path().join(format!("{label}-owned")),
            &settings,
            &raw_body,
            false,
            cancelled,
        );
        let borrowed = dispatch_case(
            &directory.path().join(format!("{label}-borrowed")),
            &settings,
            &raw_body,
            true,
            cancelled,
        );
        assert_eq!(borrowed, original, "{label}");
        assert_eq!(borrowed["work_started"], started, "{label}");
        if label == "valid" {
            assert!(borrowed["result"].get("Ok").is_some());
        } else if label == "full-work-product" {
            assert_eq!(borrowed["result"]["Err"], "WORK:Product");
        }
    }
}

/// Explicit component experiment. New allocations are not an OS-cache flush.
/// Setup, admission qualification and the original 4s service gate are outside
/// this body-authentication plus complete Packet-decoding measurement.
#[test]
#[ignore = "explicit same-binary body/Packet component ABBA; requires an idle host"]
fn body_packet_decode_component_abba_retains_every_trial() {
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};

    const BLOCKS: usize = 16;
    let (directory, settings, empty) = fixture();
    let clock = crate::ingress::now().unwrap();
    let source = Node::open(
        &directory.path().join("component-source"),
        settings.clone(),
        1,
    )
    .unwrap();
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    let transfer = |nonce: u64| {
        let mut payload = crate::development_public(1).unwrap().to_vec();
        payload.extend(1u64.to_le_bytes());
        let mut transaction = crate::Envelope {
            network: settings.network(),
            sender: crate::development_public(0).unwrap(),
            nonce,
            expiry: clock + 1000,
            fee_limit: 1_000_000,
            tag: 1,
            payload,
            signature: [0; 64],
        };
        transaction.signature = hex::decode(sign_hex(&key, &transaction.signing_digest().unwrap()))
            .unwrap()
            .try_into()
            .unwrap();
        transaction.encode().unwrap()
    };
    let mut fixtures = vec![("native-empty".to_owned(), empty.encode().unwrap())];
    for count in [1u64, 64] {
        let packet = source
            .make(
                settings.genesis(),
                (1..=count).map(transfer).collect(),
                crate::development_public(0).unwrap(),
                clock - 50,
                4096,
            )
            .unwrap();
        // Make performs actual native preparation and full proof generation.
        // Keep all packet bytes and the complete proof in every decode trial.
        fixtures.push((
            format!("native-transfers-{count}"),
            packet.encode().unwrap(),
        ));
    }
    let raw = empty.encode().unwrap();
    let mut bad_header = raw.clone();
    bad_header[0] ^= 0xff;
    fixtures.push(("malformed-header".to_owned(), bad_header));
    let mut bad_count = raw.clone();
    bad_count[crate::HEADER_BYTES..crate::HEADER_BYTES + 2].copy_from_slice(&257u16.to_le_bytes());
    fixtures.push(("malformed-count".to_owned(), bad_count));
    fixtures.push(("truncated-proof".to_owned(), raw[..raw.len() - 1].to_vec()));

    let server = server();
    let mut actual_trials = 0usize;
    let mut mismatches = 0usize;
    let mut missing_cpu = 0usize;
    let mut decoder_errors = 0usize;
    let expected_trials = fixtures.len() * 2 * BLOCKS * 4;
    println!(
        "{}",
        serde_json::json!({
            "schema": "public-v3-body-packet-component-abba-v1",
            "kind": "plan",
            "fixtures": fixtures.len(),
            "blocks_per_fixture_exposure": BLOCKS,
            "slots": ["owned", "borrowed", "borrowed", "owned"],
            "exposures": ["new-body-allocation", "reused-body-allocation"],
            "expected_trials": expected_trials,
            "scope": "body digest/canonical grammar/cookie plus complete Packet codec",
            "hardware_cache_flushed": false,
            "service_gate": false,
        })
    );
    for (fixture, raw) in fixtures {
        let raw_body = body(&raw);
        let expected = round_trip(owned_packet_oracle(&raw_body));
        let reused = paid_task(raw_body.clone(), 1, &server, &settings);
        for fresh_allocation in [true, false] {
            for block in 0..BLOCKS {
                for (slot, borrowed) in [false, true, true, false].into_iter().enumerate() {
                    // Socket ingress already owns this bounded allocation before
                    // the original worker Decode interval, on both paths.
                    let fresh = fresh_allocation
                        .then(|| paid_task(raw_body.clone(), 1, &server, &settings));
                    let task = fresh.as_ref().unwrap_or(&reused);
                    let wall = Instant::now();
                    let cpu = ThreadCpuStamp::start();
                    let decoded = if borrowed {
                        decode_task_body(std::hint::black_box(task), &server, &settings, None)
                    } else {
                        owned_task_body_oracle(std::hint::black_box(task), &server, &settings)
                            .map(DecodedTaskBody::Owned)
                    };
                    let result = match &decoded {
                        Ok(DecodedTaskBody::CanonicalSubmit(packet)) => packet.decode(),
                        Ok(DecodedTaskBody::Owned(Request::Submit { packet })) => {
                            super::super::super::hex_packet(packet)
                        }
                        Ok(_) => Err("COMPONENT_UNEXPECTED_OPERATION".into()),
                        Err(error) => Err(error.to_string().into()),
                    };
                    std::hint::black_box(&result);
                    let cpu_ns = cpu.and_then(ThreadCpuStamp::finish);
                    let wall_ns = wall.elapsed().as_nanos();
                    // Keep the owned Request and owned Packet alive through the
                    // measured boundary, as the original dispatcher does. Output
                    // checks, formatting and destruction occur after the clocks.
                    let accepted = result.is_ok();
                    let error = result.as_ref().err().map(ToString::to_string);
                    let transactions = result.as_ref().ok().map(|p| p.transactions.len());
                    let proof_bytes = result.as_ref().ok().map(|p| p.proof.len());
                    let matched = round_trip(result) == expected;
                    actual_trials += 1;
                    mismatches += usize::from(!matched);
                    missing_cpu += usize::from(cpu_ns.is_none());
                    decoder_errors += usize::from(!accepted);
                    println!(
                        "{}",
                        serde_json::json!({
                            "schema": "public-v3-body-packet-component-abba-v1",
                            "kind": "trial",
                            "trial": actual_trials,
                            "fixture": fixture,
                            "exposure": if fresh_allocation {
                                "new-body-allocation"
                            } else {
                                "reused-body-allocation"
                            },
                            "block": block,
                            "slot": slot,
                            "method": if borrowed { "borrowed" } else { "owned" },
                            "body_bytes": raw_body.len(),
                            "packet_bytes": raw.len(),
                            "transactions": transactions,
                            "proof_bytes": proof_bytes,
                            "wall_ns": wall_ns,
                            "thread_cpu_ns": cpu_ns,
                            "accepted": accepted,
                            "error": error,
                            "matched_original_oracle": matched,
                        })
                    );
                }
            }
        }
    }
    println!(
        "{}",
        serde_json::json!({
            "schema": "public-v3-body-packet-component-abba-v1",
            "kind": "summary",
            "expected_trials": expected_trials,
            "actual_trials": actual_trials,
            "decoder_errors_retained": decoder_errors,
            "mismatches": mismatches,
            "missing_cpu": missing_cpu,
            "service_gate": false,
        })
    );
    assert_eq!(actual_trials, expected_trials);
    assert_eq!(mismatches, 0);
    assert_eq!(missing_cpu, 0);
    assert_eq!(decoder_errors, 3 * 2 * BLOCKS * 4);
}
