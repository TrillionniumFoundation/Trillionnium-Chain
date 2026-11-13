//! Direct control for the existing single-use prepared-held continuation.
//! This small fixture exercises its CPU-token forwarding; it does not claim
//! to cross the large-State capacity threshold or qualify that path's latency.
use super::*;

#[test]
fn native_completion_priority_prepared_held_requires_complete_output() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(directory.path(), &settings, authenticated);
        let candidate = packet(&node, settings.genesis(), 1, 1, 1001, 0);
        let invalid = wrong_root(candidate.clone());
        let original = crate::ingress::public_v3::ServiceMutationCpuDomain::standalone();
        let mut promotions = Vec::new();
        for (index, packet) in [invalid, candidate.clone(), candidate.clone()]
            .into_iter()
            .enumerate()
        {
            let operation = original.begin().unwrap();
            operation
                .bind_history_request(Instant::now() + std::time::Duration::from_secs(2))
                .unwrap();
            // W1 and parent checks run in this same measured operation. The
            // private fixture retains the actual same owner and parent epoch.
            let prepared = held_parent_fixture(&node, &packet);
            let progress = |_| operation.checkpoint();
            let control = ExecutionControl::new(&progress, operation.worker_accounting());
            let checkpoint = operation.checkpoint_handle();
            let result = node.admit_held_prepared(prepared, 1000, &control, Some(&checkpoint));
            promotions.push(original.observe_completion_work().unwrap().live_completions);
            let receipt = operation.finish();
            assert!(!receipt.accounting_unavailable);
            assert!(receipt.total_cpu_ns.unwrap() > 0);
            assert_eq!(receipt.started_workers, receipt.finished_workers);
            assert_eq!(receipt.started_workers, receipt.known_workers);
            if index == 0 {
                assert!(
                    matches!(&result, Err(error) if error.to_string() == "ROOT"
                        && !error.requires_owner_stop()),
                    "prepared-held native output rejection changed: {result:?}"
                );
                assert!(node.packet(packet.id().unwrap()).is_err());
            } else {
                assert_eq!(result.unwrap(), candidate.id().unwrap());
            }
        }
        assert_eq!(promotions, vec![0, 1, 0]);
        let observed = original.observe_completion_work().unwrap();
        assert_eq!(
            (observed.retained_identities, observed.live_completions),
            (1, 0)
        );
        let flow = original.observe_actual_flow().unwrap().unwrap();
        assert!(flow.balance_identity_verified);
        assert_eq!(flow.booked_reservation_ns, 0);
    }
}
