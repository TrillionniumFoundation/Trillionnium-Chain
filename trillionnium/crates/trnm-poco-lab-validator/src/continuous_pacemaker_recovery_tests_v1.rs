// Real Core/Safety/signer decisions and strict four-validator TC producers.
// Timer replacement below is not an OS restart or physical durability test.
#[test]
fn fresh_timer_owner_recovers_backoff_from_durable_timeout_inventory() {
    on_bounded_takeover_owner_stack_v0(|| {
        use crate::pacemaker::GenerationAwarePacemakerV0;
        use std::time::{Duration, Instant};
        let lifetime =
            ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(1, 4, 5, 4).unwrap();
        let mut harness = takeover_phase_harness_with_signer_lifetime_v0(4, lifetime);
        let initial_qc = harness.authorities[0].justify_v0().clone();
        let base = Duration::from_secs(2);
        let maximum = Duration::from_secs(30);
        let now = Instant::now();
        let facts = harness.authorities[0].facts_v0().unwrap();
        let mut timer = GenerationAwarePacemakerV0::from_recovered_authority_v1(
            base,
            maximum,
            harness.validator_set.epoch(),
            facts,
        )
        .unwrap();
        timer
            .arm(harness.validator_set.epoch(), facts.current_view_v0(), now)
            .unwrap();
        let mut at = now;
        for expected_ms in [2000, 3000, 4500, 6750] {
            assert!(timer
                .poll(at + Duration::from_millis(expected_ms - 1))
                .is_none());
            at += Duration::from_millis(expected_ms);
            let expired = timer.poll(at).unwrap();
            let mut collector = ConsensusCertificateCollectorV0::new(
                harness.validator_set.clone(),
                MAXIMUM_COLLECTOR_COORDINATES_V0,
            )
            .unwrap();
            collector.register_qc_reference(initial_qc.clone()).unwrap();
            for authority in &mut harness.authorities {
                collector
                    .admit_timeout_vote(authority.begin_local_timeout_v0().unwrap())
                    .unwrap();
            }
            timer.confirm_timeout_emitted(expired).unwrap();
            let tc = collector
                .try_timeout_certificate(expired.view())
                .unwrap()
                .unwrap();
            for authority in &mut harness.authorities {
                authority
                    .advance_timeout_certificate_v0(tc.clone())
                    .unwrap();
            }
            // facts_v0 rechecks the actual authority-owned persisted state.
            let recovered = harness.authorities[0].facts_v0().unwrap();
            let next = GenerationAwarePacemakerV0::from_recovered_authority_v1(
                base,
                maximum,
                harness.validator_set.epoch(),
                recovered,
            )
            .unwrap();
            assert!(next.consecutive_timeouts() >= timer.consecutive_timeouts());
            timer = next;
            let generation = timer
                .arm(
                    harness.validator_set.epoch(),
                    recovered.current_view_v0(),
                    at,
                )
                .unwrap();
            assert_ne!(generation, expired.generation());
            assert!(!timer.validate_generation(
                expired.epoch(),
                expired.view(),
                expired.generation()
            ));
        }
        // Only actual live progress permits the ordinary runtime reset path.
        timer.observe_progress();
        assert_eq!(timer.consecutive_timeouts(), 0);
    });
}

#[test]
fn recovered_timer_rejects_foreign_epoch_without_consuming_authority() {
    on_bounded_takeover_owner_stack_v0(|| {
        use crate::pacemaker::GenerationAwarePacemakerV0;
        use std::time::Duration;
        let harness = takeover_phase_harness_v0(4);
        let before = harness.authorities[0].facts_v0().unwrap();
        assert!(GenerationAwarePacemakerV0::from_recovered_authority_v1(
            Duration::from_secs(2),
            Duration::from_secs(30),
            Epoch::new(1),
            before
        )
        .is_err());
        assert_eq!(harness.authorities[0].facts_v0().unwrap(), before);
    });
}
