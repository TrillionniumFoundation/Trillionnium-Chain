//! Ordered, borrowed state union for the existing persistence delta walk.
//!
//! Both complete input States remain owned by the admission. This removes the
//! temporary union tree and its per-key lookups, not any visited key, control
//! checkpoint, canonical encoding check or transactional readback.

use super::State;
use serde_json::Value;
use std::cmp::Ordering;

pub(super) struct Entry<'a> {
    pub(super) key: &'a String,
    pub(super) before: Option<&'a Value>,
    pub(super) after: Option<&'a Value>,
}

pub(super) fn entries<'a>(before: &'a State, after: &'a State) -> impl Iterator<Item = Entry<'a>> {
    let mut left = before.iter().peekable();
    let mut right = after.iter().peekable();
    std::iter::from_fn(move || {
        let order = match (left.peek(), right.peek()) {
            (None, None) => return None,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some((a, _)), Some((b, _))) => a.cmp(b),
        };
        match order {
            Ordering::Less => left.next().map(|(key, value)| Entry {
                key,
                before: Some(value),
                after: None,
            }),
            Ordering::Greater => right.next().map(|(key, value)| Entry {
                key,
                before: None,
                after: Some(value),
            }),
            Ordering::Equal => {
                let (key, before) = left.next()?;
                let (_, after) = right.next()?;
                Some(Entry {
                    key,
                    before: Some(before),
                    after: Some(after),
                })
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    type OwnedEntry = (String, Option<Value>, Option<Value>);

    fn original(before: &State, after: &State) -> Vec<OwnedEntry> {
        let mut keys: BTreeSet<_> = before.keys().collect();
        keys.extend(after.keys());
        keys.into_iter()
            .map(|key| {
                (
                    key.clone(),
                    before.get(key).cloned(),
                    after.get(key).cloned(),
                )
            })
            .collect()
    }

    fn candidate(before: &State, after: &State) -> Vec<OwnedEntry> {
        entries(before, after)
            .map(|entry| {
                (
                    entry.key.clone(),
                    entry.before.cloned(),
                    entry.after.cloned(),
                )
            })
            .collect()
    }

    fn state(mut choices: usize) -> State {
        let mut state = State::new();
        for key in ["", "account:alpha", "z"] {
            let value = match choices % 4 {
                0 => None,
                1 => Some(Value::Null),
                2 => Some(serde_json::json!(7)),
                _ => Some(serde_json::json!({"nested": [false, "value", 9]})),
            };
            if let Some(value) = value {
                state.insert(key.to_owned(), value);
            }
            choices /= 4;
        }
        state
    }

    #[test]
    fn ordered_union_matches_original_insert_remove_equal_and_changed_values() {
        // Independent original union is the oracle. Cover absence vs JSON null,
        // equal keys/values, replacements, both one-sided tails and empty maps.
        for before in 0..64 {
            for after in 0..64 {
                let before = state(before);
                let after = state(after);
                assert_eq!(candidate(&before, &after), original(&before, &after));
            }
        }
    }

    #[test]
    fn large_unchanged_prefix_keeps_every_original_checkpoint_position() {
        let before: State = (0..65_536)
            .map(|index| (format!("key:{index:05}"), serde_json::json!(index)))
            .collect();
        let mut after = before.clone();
        after.remove("key:00000");
        after.insert("key:32768".to_owned(), serde_json::json!(true));
        after.insert("key:65536".to_owned(), Value::Null);
        let mut visited = 0;
        let mut changed = Vec::new();
        for (index, entry) in entries(&before, &after).enumerate() {
            assert_eq!(entry.key, &format!("key:{index:05}"));
            if entry.before != entry.after {
                changed.push(index);
            }
            visited += 1;
        }
        assert_eq!(visited, 65_537);
        assert_eq!(changed, vec![0, 32_768, 65_536]);
        // An interrupted caller can drop the borrowed walk; a later call starts
        // from the same complete inputs and cannot resume after skipped keys.
        assert_eq!(entries(&before, &after).take(17).count(), 17);
        assert_eq!(entries(&before, &after).count(), visited);
    }

    #[test]
    fn ordered_union_preserves_exact_unicode_and_numeric_serialization() {
        let before = State::from([
            ("a\\u0000".to_owned(), serde_json::json!(1)),
            ("é".to_owned(), serde_json::json!({"a": [1, 2]})),
            ("λ".to_owned(), Value::Null),
        ]);
        let after = State::from([
            ("a\\u0000".to_owned(), serde_json::json!(1.0)),
            ("é".to_owned(), serde_json::json!({"a": [1, 2]})),
            ("λ".to_owned(), Value::Null),
        ]);
        let actual = candidate(&before, &after);
        let expected = original(&before, &after);
        assert_eq!(actual, expected);
        assert_eq!(
            serde_json::to_vec(&actual).unwrap(),
            serde_json::to_vec(&expected).unwrap()
        );
    }
    fn canonical_deltas(before: &State, after: &State, merged: bool) -> Vec<super::super::Delta> {
        let mut result = Vec::new();
        let mut emit = |key: &String, before: Option<&Value>, after: Option<&Value>| {
            if before != after {
                let before = before.map(serde_json::to_vec).transpose().unwrap();
                let after = after.map(serde_json::to_vec).transpose().unwrap();
                if before != after {
                    result.push((key.clone(), before, after));
                }
            }
        };
        if merged {
            for entry in entries(before, after) {
                emit(entry.key, entry.before, entry.after);
            }
        } else {
            let mut keys: BTreeSet<_> = before.keys().collect();
            keys.extend(after.keys());
            for key in keys {
                emit(key, before.get(key), after.get(key));
            }
        }
        result
    }

    #[test]
    fn paired_full_delta_walk_observes_growth_without_a_timing_gate() {
        for size in [1_024, 16_384, 65_536] {
            let before: State = (0..size)
                .map(|index| (format!("account:{index:05}"), serde_json::json!(index)))
                .collect();
            let mut after = before.clone();
            after.insert("account:00000".to_owned(), serde_json::json!(u64::MAX));
            after.insert("account:00001".to_owned(), Value::Null);
            let expected = canonical_deltas(&before, &after, false);
            assert_eq!(expected.len(), 2);
            let mut samples = Vec::new();
            // ABBA ordering, with the exact old union/get/encoding path as the
            // reference. No machine-dependent speed threshold grants acceptance.
            for round in 0..3 {
                for merged in [false, true, true, false] {
                    let start = std::time::Instant::now();
                    let actual = canonical_deltas(
                        std::hint::black_box(&before),
                        std::hint::black_box(&after),
                        merged,
                    );
                    std::hint::black_box(&actual);
                    let wall_ns = start.elapsed().as_nanos();
                    assert_eq!(actual, expected);
                    samples.push(serde_json::json!({
                        "round": round,
                        "merged": merged,
                        "wall_ns": wall_ns,
                    }));
                }
            }
            println!(
                "{}",
                serde_json::json!({
                    "schema": "trnm-state-delta-walk-observation-v1",
                    "state_keys": size,
                    "changed_keys": 2,
                    "samples": samples,
                    "scope": "complete in-memory delta discovery and changed-value encoding; excludes callbacks, SQLite, snapshots, full-state validation and client confirmation",
                    "public_service_qualified": false,
                })
            );
        }
    }
}
