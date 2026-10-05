//! Component-level scan/provenance tests. These do not replace the retained
//! full-chain capacity, mandatory-execution, reorganization and recovery tests.
use serde_json::json;
use trnm_mvcc_fee::{
    continuity_v1::{self, CapacityScanError, CAPACITY_PROGRESS_INTERVAL, PROFILE},
    pon_executor::{Config, State},
};

fn config() -> Config {
    Config::installed_with_profiles("native-public-evaluation-dev-v1", PROFILE).unwrap()
}

fn accounts(count: usize) -> State {
    (0..count)
        .map(|index| {
            (
                format!("account:{index:064x}"),
                json!({"balance":0,"nonce":17}),
            )
        })
        .collect()
}

#[test]
fn complete_scan_matches_legacy_at_batch_and_capacity_boundaries() {
    let cfg = config();
    for count in [0, 1, 255, 256, 257, 511, 512, 513, 65_516, 65_536] {
        let state = accounts(count);
        let before = state.clone();
        let mut checks = 0;
        let actual = continuity_v1::capacity_with_progress(&state, 0, &cfg, &mut || {
            checks += 1;
            Ok::<(), usize>(())
        })
        .unwrap();
        assert_eq!(actual, continuity_v1::capacity(&state, 0, &cfg).unwrap());
        assert_eq!(checks, count.div_ceil(CAPACITY_PROGRESS_INTERVAL) + 1);
        assert_eq!(state, before);
    }
}

#[test]
fn every_interruption_cut_stops_without_publishing_or_mutating_and_can_retry() {
    let cfg = config();
    let state = accounts(1025);
    let before = state.clone();
    let expected = continuity_v1::capacity(&state, 0, &cfg).unwrap();
    let checks = state.len().div_ceil(CAPACITY_PROGRESS_INTERVAL) + 1;
    for cut in 0..checks {
        let mut seen = 0;
        let result = continuity_v1::capacity_with_progress(&state, 0, &cfg, &mut || {
            let current = seen;
            seen += 1;
            if current == cut {
                Err(cut)
            } else {
                Ok(())
            }
        });
        assert_eq!(result, Err(CapacityScanError::Cancelled(cut)));
        assert_eq!(seen, cut + 1);
        assert_eq!(state, before);
        assert_eq!(continuity_v1::capacity(&state, 0, &cfg).unwrap(), expected);
    }
}

#[test]
fn cancellation_payload_cannot_be_reinterpreted_as_invalid_state() {
    let cfg = config();
    let state = accounts(1);
    let result = continuity_v1::capacity_with_progress(&state, 0, &cfg, &mut || {
        Err("CONTINUITY_REWARD_QUEUE")
    });
    assert_eq!(
        result,
        Err(CapacityScanError::Cancelled("CONTINUITY_REWARD_QUEUE"))
    );
}

#[test]
fn non_clone_cancellation_payload_keeps_its_identity() {
    #[derive(Debug, PartialEq)]
    struct Stop(Box<u64>);
    let cfg = config();
    let mut payload = Some(Stop(Box::new(71)));
    let address = &*payload.as_ref().unwrap().0 as *const u64;
    let result = continuity_v1::capacity_with_progress(&accounts(1), 0, &cfg, &mut || {
        Err(payload.take().expect("no callbacks after cancellation"))
    });
    match result {
        Err(CapacityScanError::Cancelled(stop)) => {
            assert_eq!(&*stop.0 as *const u64, address);
        }
        other => panic!("unexpected scan result: {other:?}"),
    }
}

#[test]
fn complete_scan_preserves_shared_zero_reward_and_archive_reservations() {
    let cfg = config();
    let owner = format!("{:064x}", 999);
    let mut state = accounts(300);
    state.insert(
        "reward:shared".into(),
        json!({"owner":owner,"amount":0,"maturity":21}),
    );
    for prefix in ["task", "quota", "release"] {
        state.insert(
            format!("{prefix}:shared"),
            json!({"owner":owner,"remaining":1}),
        );
    }
    state.insert("contribution:missing".into(), json!({}));
    state.insert("contribution:retained".into(), json!({}));
    state.insert("evaluation-archive:retained".into(), json!({}));
    let actual =
        continuity_v1::capacity_with_progress(&state, 1, &cfg, &mut || Ok::<(), ()>(())).unwrap();
    assert_eq!(actual, continuity_v1::capacity(&state, 1, &cfg).unwrap());
    assert_eq!(actual.credit_account_reserve, 1);
    assert_eq!(actual.archive_reserve, 1);
    assert_eq!(actual.reward_queue_reserve, 19);
}

#[test]
fn malformed_state_keeps_original_error_and_cannot_publish_partial_capacity() {
    let cfg = config();
    let mut malformed = accounts(300);
    malformed.insert(
        "reward:bad".into(),
        json!({"owner":"bad","amount":0,"maturity":21}),
    );
    let legacy = continuity_v1::capacity(&malformed, 1, &cfg).unwrap_err();
    let mut checks = 0;
    let observed = continuity_v1::capacity_with_progress(&malformed, 1, &cfg, &mut || {
        checks += 1;
        Ok::<(), ()>(())
    });
    assert_eq!(observed, Err(CapacityScanError::State(legacy)));
    assert_eq!(legacy, "CONTINUITY_STATE");
    assert_eq!(checks, 2); // before rows 0 and 256, never a publication callback
}

#[test]
fn wrong_profile_rejects_before_progress_without_upgrading_old_context() {
    let cfg = Config::installed_with_profiles(
        "native-public-evaluation-dev-v1",
        "signed-task-lifecycle-dev-v4",
    )
    .unwrap();
    let mut checks = 0;
    let observed = continuity_v1::capacity_with_progress(&State::new(), 0, &cfg, &mut || {
        checks += 1;
        Ok::<(), ()>(())
    });
    assert_eq!(
        observed,
        Err(CapacityScanError::State("CONTINUITY_PROFILE"))
    );
    assert_eq!(checks, 0);
}
