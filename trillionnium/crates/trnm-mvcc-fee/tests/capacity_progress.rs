//! Component-level scan/provenance tests. These do not replace the retained
//! full-chain capacity, mandatory-execution, reorganization and recovery tests.
use serde_json::json;
use std::collections::BTreeSet;
use trnm_mvcc_fee::{
    continuity_v1::{self, Capacity, CapacityScanError, CAPACITY_PROGRESS_INTERVAL, PROFILE},
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

// Independent retained full-map algorithm for the classic profile used below.
// This deliberately does not call the optimized scanner or its range helper.
fn full_scan_reference(state: &State, height: u64, cfg: &Config) -> Result<Capacity, &'static str> {
    assert!(!cfg.is_pq_account_profile());
    let number = |value: &serde_json::Value, field: &str| {
        value
            .get(field)
            .and_then(serde_json::Value::as_u64)
            .ok_or("CONTINUITY_STATE")
    };
    let maturity = cfg.params["reward_maturity_blocks"]
        .as_u64()
        .ok_or("CONFIG")?;
    let evaluation = trnm_mvcc_fee::public_evaluation::enabled(cfg);
    let mut recipients = BTreeSet::new();
    let mut rewards = BTreeSet::new();
    let mut archives = 0usize;
    for (key, value) in state {
        let reserve = if key.starts_with("reward:") {
            let due = number(value, "maturity")?;
            if due <= height
                || due > height.checked_add(maturity).ok_or("RANGE")?
                || !rewards.insert(due)
            {
                return Err("CONTINUITY_REWARD_QUEUE");
            }
            number(value, "amount")?;
            true
        } else if key.starts_with("task:")
            || key.starts_with("quota:")
            || key.starts_with("release:")
        {
            number(value, "remaining")? > 0
        } else {
            if evaluation && key.starts_with("contribution:") {
                let candidate = key.strip_prefix("contribution:").unwrap();
                if !state.contains_key(&format!("evaluation-archive:{candidate}")) {
                    archives += 1;
                }
            }
            false
        };
        if reserve {
            let owner = value
                .get("owner")
                .and_then(serde_json::Value::as_str)
                .ok_or("CONTINUITY_STATE")?;
            if owner.len() != 64
                || !owner
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("CONTINUITY_STATE");
            }
            let key = format!("account:{owner}");
            if !state.contains_key(&key) {
                recipients.insert(key);
            }
        }
    }
    let expected = height.min(maturity) as usize;
    if rewards.len() != expected {
        return Err("CONTINUITY_REWARD_QUEUE");
    }
    for offset in 0..expected {
        let due = height
            .checked_add(maturity)
            .and_then(|n| n.checked_sub(offset as u64))
            .ok_or("RANGE")?;
        if !rewards.contains(&due) {
            return Err("CONTINUITY_REWARD_QUEUE");
        }
    }
    let queue = (maturity as usize)
        .checked_sub(expected)
        .ok_or("CONTINUITY_REWARD_QUEUE")?;
    Ok(Capacity {
        actual_keys: state.len(),
        credit_account_reserve: recipients.len(),
        archive_reserve: archives,
        reward_queue_reserve: queue,
        required_keys: state.len() + recipients.len() + archives + queue,
    })
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
        assert_eq!(actual, full_scan_reference(&state, 0, &cfg).unwrap());
        // The public progress API retains each original complete-row batch
        // check and its final publication check. Ordinary native capacity can
        // seek liability ranges without changing this cancellation schedule.
        assert_eq!(checks, count.div_ceil(CAPACITY_PROGRESS_INTERVAL) + 1);
        assert_eq!(state, before);
    }
}

#[test]
fn every_interruption_cut_stops_without_publishing_or_mutating_and_can_retry() {
    let cfg = config();
    let mut state = accounts(4096);
    let liabilities = 1025usize;
    for index in 0..liabilities {
        state.insert(
            format!("quota:{index:08x}"),
            json!({"owner":format!("{:064x}", 9999),"remaining":1}),
        );
    }
    let before = state.clone();
    let expected = full_scan_reference(&state, 0, &cfg).unwrap();
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
        _ => panic!("unexpected capacity scan outcome (details redacted)"),
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

#[test]
fn complete_namespace_ranges_preserve_full_map_results_with_future_and_boundary_rows() {
    for policy in ["legacy-first-two-v3", "native-public-evaluation-dev-v1"] {
        let cfg = Config::installed_with_profiles(policy, PROFILE).unwrap();
        for count in [0, 1, 256, 4096] {
            let mut state = accounts(count);
            for due in 21..=40 {
                state.insert(
                    format!("reward:{due:03}"),
                    json!({"maturity":due,"amount":0,"owner":format!("{:064x}", due % 3)}),
                );
            }
            for prefix in ["quota:", "release:", "task:"] {
                state.insert(prefix.into(), json!({"remaining":0,"owner":null}));
                state.insert(
                    format!("{prefix}future"),
                    json!({"remaining":1,"deadline":u64::MAX,"owner":format!("{:064x}", 9000)}),
                );
                state.insert(
                    format!("{prefix}\u{10ffff}"),
                    json!({"remaining":1,"owner":format!("{:064x}", 9001)}),
                );
            }
            for candidate in ["", "kept", "future", "\0", "\u{10ffff}"] {
                state.insert(format!("contribution:{candidate}"), json!(null));
            }
            state.insert("evaluation-archive:kept".into(), json!(null));
            // Neighbouring and unrelated rows still count, but their opaque
            // values must never be parsed as monetary obligations.
            for key in [
                "",
                "account:",
                "account:invalid",
                "contribution",
                "contribution;",
                "quota",
                "quota;",
                "release;",
                "reward;",
                "task;",
                "模型:未知",
            ] {
                state.insert(key.into(), json!(null));
            }
            let before = state.clone();
            let expected = full_scan_reference(&state, 20, &cfg).unwrap();
            assert_eq!(continuity_v1::capacity(&state, 20, &cfg).unwrap(), expected);
            assert_eq!(
                continuity_v1::capacity_with_progress(&state, 20, &cfg, &mut || Ok::<(), ()>(()))
                    .unwrap(),
                expected
            );
            assert_eq!(state, before);
        }
    }
}

#[test]
fn namespace_seeks_keep_lexical_rejection_precedence_and_original_queue_checks() {
    let cfg = config();
    let owner = format!("{:064x}", 42);
    for (rows, expected) in [
        (
            vec![
                ("quota:bad", json!({"remaining":1,"owner":"bad"})),
                ("reward:bad", json!({"maturity":0})),
            ],
            "CONTINUITY_STATE",
        ),
        (
            vec![
                ("release:", json!({"remaining":null})),
                ("reward:bad", json!({"maturity":0})),
            ],
            "CONTINUITY_STATE",
        ),
        (
            vec![
                ("reward:bad", json!({"maturity":0})),
                ("task:bad", json!({"remaining":null})),
            ],
            "CONTINUITY_REWARD_QUEUE",
        ),
        (
            vec![
                (
                    "reward:first",
                    json!({"maturity":21,"amount":0,"owner":owner}),
                ),
                (
                    "reward:duplicate",
                    json!({"maturity":21,"amount":0,"owner":owner}),
                ),
            ],
            "CONTINUITY_REWARD_QUEUE",
        ),
        (
            vec![(
                "reward:far",
                json!({"maturity":22,"amount":0,"owner":owner}),
            )],
            "CONTINUITY_REWARD_QUEUE",
        ),
        (
            vec![(
                "reward:first",
                json!({"maturity":21,"amount":null,"owner":owner}),
            )],
            "CONTINUITY_STATE",
        ),
    ] {
        let mut state = accounts(4096);
        state.extend(rows.into_iter().map(|(key, value)| (key.into(), value)));
        let before = state.clone();
        assert_eq!(full_scan_reference(&state, 1, &cfg), Err(expected));
        assert_eq!(continuity_v1::capacity(&state, 1, &cfg), Err(expected));
        assert_eq!(
            continuity_v1::capacity_with_progress(&state, 1, &cfg, &mut || Ok::<(), ()>(())),
            Err(CapacityScanError::State(expected))
        );
        assert_eq!(state, before);
    }
}
