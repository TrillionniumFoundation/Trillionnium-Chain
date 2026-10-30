//! These regressions use an already admitted, inactive branch so every
//! injected resource failure belongs to History completion/activation, not
//! to W1 verification. They do not authorize continuous History import.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn complete_page(settings: &crate::Settings, tip: Hash) -> Page {
    Page {
        schema: "pon-native-history-v1".into(),
        network: hex::encode(settings.network()),
        parameters: hex::encode(settings.parameters()),
        genesis: hex::encode(settings.genesis()),
        tip: hex::encode(tip),
        after: hex::encode(tip),
        packets: vec![],
        next: hex::encode(tip),
        complete: true,
    }
}

#[test]
fn history_last_close_refuses_intervening_clone_owner_and_preserves_cold_crash_fence() {
    let observed = now().unwrap();
    let settings = crate::Settings::development(Some(observed - 100)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
    let domain = public_v3::ServiceMutationCpuDomain::standalone();
    node.bind_public_service_cpu_domain(&domain).unwrap();
    assert!(node.begin_remote_history_cpu_epoch().unwrap());
    // The caller's earlier clean observation cannot authorize deletion after
    // a clone has acquired another original reserve in that observation gap.
    assert_eq!(domain.observe().unwrap().in_flight, 0);
    let operation = domain.clone().begin().unwrap();
    let error = node
        .finish_remote_history_cpu_epoch(&domain, true)
        .unwrap_err();
    assert!(error.is(crate::ErrorCode::PublicMutationCpuBudget));
    assert!(!operation.finish().accounting_unavailable);
    assert!(node.begin_remote_history_cpu_epoch().is_err());
    drop(node);
    let mut reopened = Node::open(dir.path(), settings, 2).unwrap();
    assert_eq!(
        reopened
            .remote_history_cpu_domain()
            .err()
            .unwrap()
            .to_string(),
        "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH"
    );
    assert!(reopened.public_service_cpu_domain().is_err());
}

#[test]
fn history_expired_cold_start_does_not_run_an_unpaid_resource_probe() {
    let settings = crate::Settings::development(Some(now().unwrap() - 100)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), settings, 2).unwrap();
    let domain = public_v3::ServiceMutationCpuDomain::cold_remote_history_epoch();
    let resource_calls = AtomicUsize::new(0);
    let native_calls = AtomicUsize::new(0);
    let error = metered_history_operation(
        &mut node,
        &domain,
        Instant::now(),
        &|| {
            resource_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        |_, _| {
            native_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.is(crate::ErrorCode::PublicRequestDeadline));
    assert_eq!(resource_calls.load(Ordering::SeqCst), 0);
    assert_eq!(native_calls.load(Ordering::SeqCst), 0);
    let state = domain.observe().unwrap();
    assert_eq!(state.in_flight, 0);
    assert_eq!(state.stored_credit_ns, 0);
    let flow = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(flow.booked_reservation_ns, 0);
    assert_eq!(flow.paid_cpu_debit_ns, 0);
    assert_eq!(flow.credited_refill_ns, 0);
}

#[test]
fn history_paid_start_cancellation_finishes_original_reserve_before_native_work() {
    let settings = crate::Settings::development(Some(now().unwrap() - 100)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), settings, 2).unwrap();
    let domain = public_v3::ServiceMutationCpuDomain::standalone();
    node.bind_public_service_cpu_domain(&domain).unwrap();
    assert!(node.begin_remote_history_cpu_epoch().unwrap());
    let resource_calls = AtomicUsize::new(0);
    let native_calls = AtomicUsize::new(0);
    let error = metered_history_operation(
        &mut node,
        &domain,
        Instant::now() + Duration::from_secs(2),
        &|| {
            assert_eq!(domain.observe()?.in_flight, 1);
            resource_calls.fetch_add(1, Ordering::SeqCst);
            Err("TEST_HISTORY_PAID_START_CANCELLED".into())
        },
        |_, _| {
            native_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "TEST_HISTORY_PAID_START_CANCELLED");
    assert!(resource_calls.load(Ordering::SeqCst) > 0);
    assert_eq!(native_calls.load(Ordering::SeqCst), 0);
    let state = domain.observe().unwrap();
    assert_eq!(state.in_flight, 0);
    assert!(!state.accounting_unavailable);
    let flow = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(flow.booked_reservation_ns, 0);
    assert!(flow.paid_cpu_debit_ns > 0);
    assert_eq!(flow.paid_cpu_debit_ns, flow.settled_full_cpu_ns);
    node.finish_remote_history_cpu_epoch(&domain, true).unwrap();
    let next = domain.begin().unwrap();
    assert!(!next.finish().accounting_unavailable);
}

#[test]
fn complete_history_checks_resources_inside_activation_and_can_retry() {
    let observed = now().unwrap();
    let settings = crate::Settings::development(Some(observed - 100)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
    let mut tip = settings.genesis();
    for height in 1..=3 {
        let packet = node
            .make(
                tip,
                vec![],
                crate::development_public(0).unwrap(),
                settings.genesis_time() + 10 * height,
                4096,
            )
            .unwrap();
        tip = node.admit(&packet, observed).unwrap();
    }
    assert_eq!(node.read_active().unwrap().0, settings.genesis());
    let before = node.stats().unwrap();
    let domain = node.remote_history_cpu_domain().unwrap();
    let checkpoints = AtomicUsize::new(0);
    let error = receive_page(
        &mut node,
        &domain,
        complete_page(&settings, tip),
        tip,
        tip,
        observed,
        || {
            // Decode must have actually finished its paid interval before
            // this injection can fire. Cancellation stays asserted during
            // settlement; repeated checks do not turn it back into permission.
            if checkpoints.load(Ordering::SeqCst) == 7 {
                return Err("TEST_HISTORY_ACTIVATION_CANCELLED".into());
            }
            let flow = domain
                .observe_actual_flow()?
                .ok_or("TEST_HISTORY_CPU_FLOW")?;
            if flow.live_owners != 0
                && flow.settled_full_cpu_ns != 0
                && checkpoints.fetch_add(1, Ordering::SeqCst) + 1 == 7
            {
                return Err("TEST_HISTORY_ACTIVATION_CANCELLED".into());
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "TEST_HISTORY_ACTIVATION_CANCELLED");
    assert_eq!(checkpoints.load(Ordering::SeqCst), 7);
    assert_eq!(node.stats().unwrap(), before);
    assert_eq!(node.read_active().unwrap().0, settings.genesis());
    let settled = domain.observe().unwrap();
    assert_eq!(settled.in_flight, 0);
    assert!(!settled.accounting_unavailable);
    assert!(node
        .public_service_cpu_domain()
        .unwrap()
        .shares_domain_with(&domain));

    // A known cancellation closes its epoch and leaves the original owner
    // usable. A successful retry must actually activate the stored branch.
    let successful_checks = AtomicUsize::new(0);
    assert_eq!(
        receive_page(
            &mut node,
            &domain,
            complete_page(&settings, tip),
            tip,
            tip,
            observed,
            || {
                successful_checks.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap(),
        tip
    );
    assert!(successful_checks.load(Ordering::SeqCst) > 7);
    assert_eq!(node.read_active().unwrap().0, tip);
    assert_eq!(domain.observe().unwrap().in_flight, 0);
    drop(node);
    let mut reopened = Node::open(dir.path(), settings, 2).unwrap();
    assert_eq!(reopened.read_active().unwrap().0, tip);
    assert!(reopened.remote_history_cpu_domain().is_ok());
}
