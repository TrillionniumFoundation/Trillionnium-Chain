//! Account-prefix traversal against the previous complete-State scan. The
//! selected parser keeps its original grammar; no State validity is cached.
use super::*;
use serde_json::{json, Value};
use std::hint::black_box;
use std::io::Write;
use std::time::Instant;

// Exact pre-range parser, including its test-only observation guard. Keep its
// full traversal independent of the candidate's range bounds. Both timed arms
// have the same test observer; these are not ordinary-binary service timings.
fn full_scan(state: &State) -> Result<BTreeMap<Hash, Account>> {
    let mut observation = AccountParseObservation::default();
    let mut out = BTreeMap::new();
    for (key, value) in state {
        observation.rows += 1;
        let Some(owner) = key.strip_prefix("account:") else {
            continue;
        };
        if owner.len() != 64
            || !owner
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ArchiveError::InvalidState);
        }
        let mut address = [0; 32];
        hex::decode_to_slice(owner, &mut address).map_err(|_| ArchiveError::InvalidState)?;
        let account = Account::deserialize(value).map_err(|_| ArchiveError::InvalidState)?;
        if out.insert(address, account).is_some() {
            return Err(ArchiveError::InvalidState);
        }
    }
    Ok(out)
}

fn fixture(account_rows: usize, working_rows: usize) -> State {
    let mut state = State::new();
    for index in 0..account_rows {
        state.insert(
            format!("account:{index:064x}"),
            json!({"balance": index as u64, "nonce": u64::MAX - index as u64}),
        );
    }
    for index in 0..working_rows {
        let prefix = if index.is_multiple_of(2) { "a:" } else { "z:" };
        state.insert(format!("{prefix}{index:08}"), Value::Null);
    }
    state
}

#[test]
fn prefix_range_preserves_all_account_suffixes_and_neighboring_keys() {
    let valid = json!({"balance": 7, "nonce": 9});
    let mut keys = vec![
        "".to_owned(),
        "account".to_owned(),
        "account9".to_owned(),
        "account:".to_owned(),
        "account;".to_owned(),
        "account;tail".to_owned(),
        "account\u{ff1a}".to_owned(),
        "accounts:".to_owned(),
        "Account:".to_owned(),
        "account:\0".to_owned(),
        "account:é".to_owned(),
        "account:账户".to_owned(),
        "account:\u{10ffff}".to_owned(),
        format!("account:{}", "a".repeat(63)),
        format!("account:{}", "a".repeat(64)),
        format!("account:{}", "A".repeat(64)),
        format!("account:{}", "f".repeat(65)),
        format!("account:{}", "é".repeat(32)),
        format!("account:{}\0", "0".repeat(63)),
    ];
    for code in 0u8..=127 {
        let ch = char::from(code);
        keys.push(format!("account{ch}suffix"));
        keys.push(format!("account:{ch}{}", "0".repeat(63)));
    }
    for key in keys {
        let mut state = fixture(3, 16);
        state.insert(key.clone(), valid.clone());
        let expected = full_scan(&state);
        take_account_parse_observation();
        let observed = accounts(&state);
        let (calls, visited) = take_account_parse_observation();
        assert_eq!(observed, expected, "key={key:?}");
        assert_eq!(calls, 1);
        let expected_visited = state
            .iter()
            .filter(|(name, _)| name.starts_with("account:"))
            .position(|(name, _)| name == &key)
            .filter(|_| observed.is_err())
            .map_or_else(
                || {
                    state
                        .keys()
                        .filter(|name| name.starts_with("account:"))
                        .count()
                },
                |index| index + 1,
            );
        assert_eq!(visited, expected_visited, "key={key:?}");
    }
}

#[test]
fn prefix_range_preserves_account_value_grammar_and_first_error_order() {
    let mut cases = vec![
        (Value::Null, false),
        (json!(false), false),
        (json!(0), false),
        (json!("account"), false),
        (json!([]), false),
        (json!({}), false),
        (json!({"balance": 0}), false),
        (json!({"nonce": 0}), false),
        (json!({"balance": 0, "nonce": 0, "extra": true}), false),
        (json!({"balance": 0.0, "nonce": 0}), false),
        (json!({"balance": 0, "nonce": 0.0}), false),
        (json!({"balance": -1, "nonce": 0}), false),
        (json!({"balance": 0, "nonce": -1}), false),
        (json!({"balance": "1", "nonce": 0}), false),
        (json!({"balance": 0, "nonce": null}), false),
    ];
    for balance in [0, 1, u64::MAX] {
        for nonce in [0, 1, u64::MAX] {
            cases.push((json!({"balance": balance, "nonce": nonce}), true));
        }
    }
    for (value, valid) in cases {
        let mut state = fixture(4, 32);
        state.insert(format!("account:{:064x}", 1), value.clone());
        let expected = full_scan(&state);
        assert_eq!(expected.is_ok(), valid, "value={value:?}");
        take_account_parse_observation();
        assert_eq!(accounts(&state), expected, "value={value:?}");
        assert_eq!(
            take_account_parse_observation(),
            (1, if valid { 4 } else { 2 })
        );
    }
    // The first malformed account remains first even with a later malformed
    // key and arbitrary non-account data on both sides of the prefix.
    let mut state = fixture(4, 32);
    state.insert(format!("account:{:064x}", 1), Value::Null);
    state.insert("account:zz".into(), json!({"balance": 0, "nonce": 0}));
    take_account_parse_observation();
    assert_eq!(accounts(&state), Err(ArchiveError::InvalidState));
    assert_eq!(take_account_parse_observation(), (1, 2));
}

#[test]
fn prefix_range_visits_fixed_account_rows_when_working_state_grows() {
    for account_rows in [0, 8] {
        let expected = full_scan(&fixture(account_rows, 0)).unwrap();
        for working_rows in [0, 64, 4_096, 65_528] {
            let state = fixture(account_rows, working_rows);
            take_account_parse_observation();
            assert_eq!(accounts(&state).unwrap(), expected);
            assert_eq!(take_account_parse_observation(), (1, account_rows));
            assert_eq!(full_scan(&state).unwrap(), expected);
            assert_eq!(take_account_parse_observation(), (1, state.len()));
        }
    }
}

#[test]
#[ignore = "explicit paired parser wall observation; no Node/service performance gate"]
fn prefix_range_component_cost_abba() {
    const ROUNDS: usize = 16;
    const ITERATIONS: usize = 8;
    let cohorts = [(8, 0), (8, 64), (8, 4_096), (8, 65_528), (4_096, 64)];
    println!(
        "{}",
        json!({
            "schema": "account-prefix-parser-cost-v1", "event": "campaign_started",
            "rounds": ROUNDS, "iterations_per_sample": ITERATIONS, "order": "ABBA",
            "cohorts": cohorts, "scope": "complete parser and returned-map drop; both arms contain the same test-only observation guard",
            "excludes": "Node, proof work, state roots, SQLite, network, confirmation, RSS and ordinary-binary timing",
            "public_service_qualified": false
        })
    );
    std::io::stdout().flush().unwrap();
    for (account_rows, working_rows) in cohorts {
        let state = fixture(account_rows, working_rows);
        let expected = full_scan(&state).unwrap();
        assert_eq!(accounts(&state).unwrap(), expected);
        let input_digest = hash(
            b"account-prefix-cost-input-v1",
            &[&serde_json::to_vec(&state).unwrap()],
        );
        for round in 0..ROUNDS {
            for (position, range) in [false, true, true, false].into_iter().enumerate() {
                let arm = if range {
                    "account_prefix_range"
                } else {
                    "original_full_scan"
                };
                println!(
                    "{}",
                    json!({
                        "schema": "account-prefix-parser-cost-v1", "event": "sample_started",
                        "account_rows": account_rows, "working_rows": working_rows,
                        "input_digest": hex::encode(input_digest), "round": round, "position": position, "arm": arm
                    })
                );
                std::io::stdout().flush().unwrap();
                take_account_parse_observation();
                let started = Instant::now();
                for _ in 0..ITERATIONS {
                    let parsed = if range {
                        accounts(black_box(&state))
                    } else {
                        full_scan(black_box(&state))
                    };
                    drop(black_box(parsed.unwrap()));
                }
                let elapsed_ns = started.elapsed().as_nanos();
                let observation = take_account_parse_observation();
                assert_eq!(
                    observation,
                    (
                        ITERATIONS,
                        ITERATIONS * if range { account_rows } else { state.len() }
                    )
                );
                println!(
                    "{}",
                    json!({
                        "schema": "account-prefix-parser-cost-v1", "event": "sample_completed",
                        "account_rows": account_rows, "working_rows": working_rows,
                        "input_digest": hex::encode(input_digest), "round": round, "position": position, "arm": arm,
                        "iterations": ITERATIONS, "elapsed_ns": elapsed_ns,
                        "parser_calls": observation.0, "visited_rows": observation.1
                    })
                );
                std::io::stdout().flush().unwrap();
            }
        }
    }
}
