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
            // The old outer-only path has four Host checks and would
            // activate successfully. Check seven is inside the observed
            // ancestor traversal on the corrected path, before mutation.
            if checkpoints.fetch_add(1, Ordering::SeqCst) + 1 == 7 {
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
