//! Differential controls for the growth profile's existing delta encoding.
//! These comparisons are arithmetic observations, not admission or state authority.
use super::*;
use serde_json::{json, Value};
use std::hint::black_box;
use std::time::Instant;

// Keep the original key-union/look-up implementation independent of the new
// traversal. In particular, preserve its Value comparison before encoding.
fn original(before: &State, after: &State) -> Result<Vec<Delta>> {
    let keys: BTreeSet<_> = before.keys().chain(after.keys()).collect();
    keys.into_iter()
        .filter(|key| before.get(*key) != after.get(*key))
        .map(|key| {
            Ok((
                key.clone(),
                before.get(key).map(canonical).transpose()?,
                after.get(key).map(canonical).transpose()?,
            ))
        })
        .collect()
}

fn compare(before: &State, after: &State) {
    let inputs = (canonical(before).unwrap(), canonical(after).unwrap());
    for (prior, next) in [(before, after), (after, before)] {
        let expected = original(prior, next).unwrap();
        let observed = difference(prior, next).unwrap();
        assert_eq!(observed, expected);
        assert_eq!(canonical(&observed).unwrap(), canonical(&expected).unwrap());
        assert_eq!(
            delta_hash(&observed).unwrap(),
            delta_hash(&expected).unwrap()
        );
        assert!(observed.windows(2).all(|pair| pair[0].0 < pair[1].0));
    }
    assert_eq!(
        inputs,
        (canonical(before).unwrap(), canonical(after).unwrap())
    );
}

#[test]
fn ordered_growth_differences_preserve_value_equality_absence_and_byte_encoding() {
    let values = [
        Value::Null,
        json!(false),
        json!(0),
        json!(0.0),
        json!(-0.0),
        json!(u64::MAX),
        json!("\"\\\n\u{0000}é😀"),
        json!([null, 1, "x", {"a": true}]),
        json!({"balance": 0, "nonce": u64::MAX}),
    ];
    for key in ["", "a", "aa", "\u{0000}", "é", "😀"] {
        for value in &values {
            let before = State::from([(key.to_owned(), value.clone())]);
            compare(&before, &State::new());
            compare(&before, &before);
            for next in &values {
                compare(&before, &State::from([(key.to_owned(), next.clone())]));
            }
        }
    }
    compare(&State::new(), &State::new());
}

#[test]
fn ordered_growth_differences_match_independent_dense_and_sparse_key_unions() {
    for seed in 0..32usize {
        let mut before = State::new();
        let mut after = State::new();
        for index in 0..128usize {
            let key = format!("row:{index:04}:{}", ["a", "é", "😀"][index % 3]);
            if (index + seed) % 5 != 0 {
                before.insert(key.clone(), json!([index, {"v": seed % 7}]));
            }
            if (index * 3 + seed) % 7 != 0 {
                let value = if (index + seed).is_multiple_of(11) {
                    json!({"changed": index})
                } else {
                    json!([index, {"v": seed % 7}])
                };
                after.insert(key, value);
            }
        }
        compare(&before, &after);
    }
}

#[test]
fn ordered_growth_differences_keep_nonce_liability_supply_and_generation_deltas() {
    // This helper must neither authorize nor suppress a state transition. Even
    // an inadmissible nonce rewind is represented identically; M06 and the
    // original admission/reorg owners retain responsibility for rejecting it.
    let before = State::from([
        ("account:sender".into(), json!({"balance": 80, "nonce": 9})),
        (
            "task:pending".into(),
            json!({"remaining": 10, "owner": "sender"}),
        ),
        (
            "reward:maturing".into(),
            json!({"amount": 10, "owner": "sender"}),
        ),
        ("meta:issued".into(), json!(100)),
        ("generation".into(), json!(7)),
    ]);
    let mut after = before.clone();
    after.insert("account:sender".into(), json!({"balance": 75, "nonce": 10}));
    after.insert("account:new".into(), json!({"balance": 5, "nonce": 0}));
    after.insert(
        "quota:remaining".into(),
        json!({"remaining": 10, "owner": "sender"}),
    );
    after.remove("task:pending");
    after.insert("generation".into(), json!(8));
    compare(&before, &after);
    for (prior, next) in [(&before, &after), (&after, &before)] {
        let mut restored = prior.clone();
        for (key, old, new) in difference(prior, next).unwrap() {
            assert_eq!(restored.get(&key).map(canonical).transpose().unwrap(), old);
            match new {
                Some(bytes) => {
                    restored.insert(key, serde_json::from_slice(&bytes).unwrap());
                }
                None => {
                    restored.remove(&key);
                }
            }
        }
        assert_eq!(canonical(&restored).unwrap(), canonical(next).unwrap());
    }
}

#[test]
fn ordered_growth_difference_fixed_changes_retains_stage_cost_samples() {
    for keys in [64, 512, 4096] {
        let before: State = (0..keys)
            .map(|index| (format!("working:{index:05}"), Value::Null))
            .collect();
        let mut after = before.clone();
        after.insert("working:00000".into(), json!(1));
        after.insert(format!("working:{:05}", keys - 1), json!(2));
        after.remove("working:00001");
        for index in 0..3 {
            after.insert(format!("new:{index}"), json!(index));
        }
        let expected = original(&before, &after).unwrap();
        assert_eq!(expected.len(), 6);
        compare(&before, &after);
        let mut old_ns = Vec::new();
        let mut new_ns = Vec::new();
        let mut samples = Vec::new();
        let mut all_equal = true;
        // The preregistered component order is ABBA after untimed equality
        // controls: 16 complete rounds, all 64 outcomes retained per size.
        // Times remain observations, never flaky speed assertions or node TPS.
        for round in 0..16usize {
            for (slot, candidate) in [false, true, true, false].into_iter().enumerate() {
                let started = Instant::now();
                let result = if candidate {
                    difference(black_box(&before), black_box(&after))
                } else {
                    original(black_box(&before), black_box(&after))
                };
                let elapsed = started.elapsed().as_nanos();
                black_box(&result);
                let equal = result.as_ref().is_ok_and(|value| value == &expected);
                all_equal &= equal;
                samples.push(json!({
                    "round": round,
                    "slot": slot,
                    "implementation": if candidate { "candidate" } else { "reference" },
                    "wall_ns": elapsed,
                    "expected_difference_equal": equal,
                    "error": result.err().map(|error| error.to_string()),
                }));
                if candidate {
                    new_ns.push(elapsed);
                } else {
                    old_ns.push(elapsed);
                }
            }
        }
        eprintln!(
            "{}",
            json!({
                "schema": "growth-ordered-difference-stage-observation-v1",
                "compared_working_keys": keys,
                "changed_keys": 6,
                "input_canonical_bytes": canonical(&before).unwrap().len() + canonical(&after).unwrap().len(),
                "comparison_order": ["reference", "candidate", "candidate", "reference"],
                "rounds": 16,
                "samples": samples,
                "reference_wall_ns": old_ns,
                "candidate_wall_ns": new_ns,
                "scope": "one local delta traversal; no account/archive/history/SQL/confirmation qualification",
                "production_qualified": false
            })
        );
        assert!(
            all_equal,
            "every ABBA outcome must match the original difference"
        );
    }
}
