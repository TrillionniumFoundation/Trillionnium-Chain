//! Real signed Clock UDS + Service::answer + durable files. This suite does not
//! run the frontier listener's cross-UID peer path or prove /etc provisioning.
use super::frontier::{Frontier, Validity};
use super::frontier_service::Service;
use super::service_faults::{self as faults, Point};
use super::service_test_fixture::{write, Fixture, NAMESPACE};
use super::trust_wire as wire;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn proposal() -> Frontier {
    Frontier::successor(NAMESPACE, None, b"actual-index").unwrap()
}
fn window(f: &Fixture, seconds: u64) -> Validity {
    Validity {
        not_before: 0,
        expires_at: f.time.now() + seconds,
    }
}
fn row_frontier(f: &Fixture) -> Option<Frontier> {
    let row: serde_json::Value = serde_json::from_slice(&f.row()).unwrap();
    serde_json::from_value(row["frontier"].clone()).unwrap()
}
fn row_floor(f: &Fixture) -> u64 {
    serde_json::from_slice::<serde_json::Value>(&f.row()).unwrap()["time_floor"]
        .as_u64()
        .unwrap()
}

#[test]
fn signed_cas_uses_exact_old_once_and_returns_only_the_observed_lower_floor() {
    let mut f = Fixture::new();
    let mut service = f.initialized();
    f.scope(|| {
        let next = proposal();
        let raw = f.request(None, Some(next.clone()), Some(window(&f, 30)));
        let answer = service.answer(&raw, deadline()).unwrap();
        let reply = f.reply(&raw, &answer);
        assert!(reply.accepted);
        assert_eq!(reply.operation, wire::Operation::CompareAndSet);
        assert_eq!(reply.frontier, Some(next.clone()));
        assert_eq!(row_floor(&f), reply.now_seconds);
        assert_eq!(reply.now_seconds, f.time.last_signed());
        assert!(reply.now_seconds <= f.time.now());
        assert_eq!(faults::admissions(), 1);
        let replay = f.reply(&raw, &service.answer(&raw, deadline()).unwrap());
        assert!(!replay.accepted);
        assert_eq!(replay.frontier, Some(next));
        assert_eq!(row_floor(&f), replay.now_seconds);
        assert_eq!(replay.now_seconds, f.time.last_signed());
        assert_eq!(faults::admissions(), 1);
    });
}

fn pause_before_admission(point: Point) {
    let mut f = Fixture::new();
    let mut service = f.initialized();
    let validity = window(&f, 2);
    let raw = f.request(None, Some(proposal()), Some(validity));
    let original = f.row();
    let reached = Arc::new(AtomicBool::new(false));
    let marker = reached.clone();
    let time = f.time.clone();
    f.scope(|| {
        faults::once(point, move || {
            marker.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(1100));
            assert!(time.now() >= validity.expires_at);
            Ok(())
        });
        let error = service.answer(&raw, deadline()).unwrap_err();
        assert!(reached.load(Ordering::SeqCst));
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            error.to_string(),
            "M15 conservative trusted time interval is outside the exact window"
        );
        assert_eq!(faults::admissions(), 0);
        assert_eq!(f.row(), original);
        assert_eq!(row_frontier(&f), None);
        assert_eq!(
            service.answer(&raw, deadline()).unwrap_err().to_string(),
            "M15 service is fenced"
        );
    });
}

#[test]
fn clock_reply_then_real_elapsed_expiry_refuses_without_cas() {
    pause_before_admission(Point::Clock);
}

#[test]
fn durable_preparation_then_real_elapsed_expiry_refuses_without_cas() {
    pause_before_admission(Point::Prepared);
}

#[test]
fn admitted_completion_after_expiry_lost_reply_is_exact_and_cold_does_not_redispatch() {
    let mut f = Fixture::new();
    let mut service = f.initialized();
    let next = proposal();
    let validity = window(&f, 2);
    let raw = f.request(None, Some(next.clone()), Some(validity));
    let time = f.time.clone();
    f.scope(|| {
        faults::once(Point::Admitted, move || {
            // This is deliberately after the real interval check/decision.
            std::thread::sleep(Duration::from_millis(1100));
            assert!(time.now() >= validity.expires_at);
            faults::once(Point::Published, || {
                Err(std::io::Error::other("lost after durable completion"))
            });
            Ok(())
        });
        assert_eq!(
            service.answer(&raw, deadline()).unwrap_err().to_string(),
            "lost after durable completion"
        );
        assert_eq!(faults::admissions(), 1);
        assert_eq!(row_frontier(&f), Some(next.clone()));
        assert!(row_floor(&f) < validity.expires_at);
        assert_eq!(row_floor(&f), f.time.last_signed());
        assert_eq!(
            service.answer(&raw, deadline()).unwrap_err().to_string(),
            "M15 service is fenced"
        );
        drop(service);
        assert!(Service::open(false).is_err()); // Independent old head/floor cannot adopt the DB.
    });
    f.pin_retained_row(); // Only an equality fixture, not independent custody evidence.
    f.scope(|| {
        let mut cold = Service::open(false).unwrap();
        let retained = f.row();
        assert_eq!(
            cold.initialization().unwrap()["frontier"],
            serde_json::to_value(&next).unwrap()
        );
        let error = cold.answer(&raw, deadline()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(faults::admissions(), 0);
        assert_eq!(f.row(), retained);
    });
}

#[test]
fn prepared_failure_keeps_canonical_row_and_temp_is_not_admission() {
    let mut f = Fixture::new();
    let mut service = f.initialized();
    let raw = f.request(None, Some(proposal()), Some(window(&f, 30)));
    f.scope(|| {
        let original = f.row();
        faults::once(Point::Prepared, || {
            Err(std::io::Error::other("prepared before decision"))
        });
        assert_eq!(
            service.answer(&raw, deadline()).unwrap_err().to_string(),
            "prepared before decision"
        );
        assert_eq!(faults::admissions(), 0);
        assert_eq!(f.row(), original);
        let prepared: Vec<_> = std::fs::read_dir(&f.configuration.directory)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .contains(".prepared-")
            })
            .collect();
        assert_eq!(prepared.len(), 1);
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&prepared[0]).unwrap()).unwrap();
        assert_eq!(raw["frontier"], serde_json::to_value(proposal()).unwrap());
        drop(service);
        let cold = Service::open(false).unwrap();
        assert!(cold.initialization().unwrap()["frontier"].is_null());
        assert_eq!(faults::admissions(), 0);
        assert_eq!(f.row(), original);
    });
}

#[test]
fn wrong_signature_domain_binding_namespace_and_nonce_cannot_mutate_or_fence() {
    let mut f = Fixture::new();
    let mut service = f.initialized();
    let valid = f.request(None, Some(proposal()), Some(window(&f, 30)));
    let wrong_key = super::proof_test_keys::key(93);
    f.scope(|| {
        let original = f.row();
        for fault in 0..7 {
            let mut signed: wire::Signed<wire::Request> = wire::decode(&valid).unwrap();
            let bad = match fault {
                0 => {
                    signed.body.binding[0] ^= 1;
                    wire::sign(wire::REQUEST, signed.body, &f.owner_key).unwrap()
                }
                1 => {
                    signed.body.namespace[0] ^= 1;
                    wire::sign(wire::REQUEST, signed.body, &f.owner_key).unwrap()
                }
                2 => {
                    signed.body.challenge = [0; 32];
                    wire::sign(wire::REQUEST, signed.body, &f.owner_key).unwrap()
                }
                3 => {
                    signed.body.operation = wire::Operation::Clock;
                    wire::sign(wire::REQUEST, signed.body, &f.owner_key).unwrap()
                }
                4 => wire::sign(wire::REQUEST, signed.body, &wrong_key).unwrap(),
                5 => {
                    signed.signature[0] ^= 1;
                    wire::canonical(&signed).unwrap()
                }
                _ => wire::sign(wire::CLOCK_REPLY, signed.body, &f.owner_key).unwrap(),
            };
            assert!(service.answer(&bad, deadline()).is_err());
            assert_eq!(f.row(), original);
            assert_eq!(faults::admissions(), 0);
        }
        let load = f.request(None, None, None);
        let reply = f.reply(&load, &service.answer(&load, deadline()).unwrap());
        assert!(reply.accepted && reply.frontier.is_none());
        assert_eq!(faults::admissions(), 0);
    });
}

#[test]
fn actual_signed_clock_wrong_request_nonce_namespace_or_backward_floor_fences() {
    for fault in 1..=4 {
        let mut f = Fixture::new();
        let mut service = f.initialized();
        let raw = f.request(None, Some(proposal()), Some(window(&f, 30)));
        f.time.mode.store(fault, Ordering::SeqCst);
        f.scope(|| {
            let original = f.row();
            assert_eq!(
                service.answer(&raw, deadline()).unwrap_err().to_string(),
                "M15 independent signed clock binding/floor"
            );
            assert_eq!(f.row(), original);
            assert_eq!(faults::admissions(), 0);
            f.time.mode.store(0, Ordering::SeqCst);
            assert_eq!(
                service.answer(&raw, deadline()).unwrap_err().to_string(),
                "M15 service is fenced"
            );
        });
    }
}

#[test]
fn last_clock_callback_lock_row_or_provisioning_drift_refuses_and_retains_fault() {
    for fault in 0..3 {
        let mut f = Fixture::new();
        let mut service = f.initialized();
        let raw = f.request(None, Some(proposal()), Some(window(&f, 30)));
        let original = f.row();
        let root = f.root_file.clone();
        let directory = f.configuration.directory.clone();
        let mut changed = f.configuration.clone();
        changed.clock.binding[0] ^= 1;
        let reached = Arc::new(AtomicBool::new(false));
        let marker = reached.clone();
        f.scope(|| {
            faults::once(Point::Clock, move || {
                marker.store(true, Ordering::SeqCst);
                match fault {
                    0 => {
                        std::fs::rename(
                            directory.join("owner.lock"),
                            directory.join("original-owner.lock"),
                        )?;
                        write(&directory.join("owner.lock"), b"replacement");
                    }
                    1 => write(
                        &directory.join("independent-frontier.json"),
                        b"retained foreign proposal",
                    ),
                    _ => write(&root, &super::codec::encode(&changed, 65536)?),
                }
                Ok(())
            });
            assert!(service.answer(&raw, deadline()).is_err());
            assert!(reached.load(Ordering::SeqCst));
            assert_eq!(faults::admissions(), 0);
            if fault == 1 {
                assert_eq!(f.row().as_slice(), b"retained foreign proposal");
            } else {
                assert_eq!(f.row(), original);
            }
            assert_eq!(
                service.answer(&raw, deadline()).unwrap_err().to_string(),
                "M15 service is fenced"
            );
        });
    }
}
