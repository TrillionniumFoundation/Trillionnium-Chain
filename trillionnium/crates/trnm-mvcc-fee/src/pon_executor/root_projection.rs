//! Operation-local root arithmetic over one immutable complete State.
//! The subset is compared against complete current canonical bytes before a
//! private leaf projection is consumed. No SQL observation or verdict is kept.
use super::{canonical_after_validation, root_with_arithmetic, validate_canonical, Result, State};
use trnm_protocol::pon_wire::{
    Hash, StateRootArithmetic, StateRootInputError, StateRootProjection,
};

/// Created only after the complete actual input has passed its original root
/// grammar. The immutable borrow prevents changes to that source until this
/// one-use projection is consumed or dropped. It is not admission authority.
pub struct NonAccountRootProjection<'a> {
    source: &'a State,
    leaves: StateRootProjection,
}

/// Complete grammar and wire checks remain at the original full-root point.
/// Projection retention uses the same arithmetic object's existing byte cap;
/// refusal still returns the original complete root without a projection.
pub fn root_with_non_account_projection<'a>(
    state: &'a State,
    arithmetic: &mut StateRootArithmetic,
) -> Result<(Hash, Option<NonAccountRootProjection<'a>>)> {
    for value in state.values() {
        validate_canonical(value)?;
    }
    if state.len() > 65_536 {
        return Err("LIMIT");
    }
    let (root, projection) = arithmetic
        .root_from_entries_with_projection(
            state.iter().map(|(key, value)| {
                canonical_after_validation(value).map(|bytes| (key.as_bytes(), bytes))
            }),
            |key| !key.starts_with(b"account:"),
        )
        .map_err(|error| match error {
            StateRootInputError::Input(error) => error,
            StateRootInputError::Wire(_) => "LIMIT",
        })?;
    Ok((
        root,
        projection.map(|leaves| NonAccountRootProjection {
            source: state,
            leaves,
        }),
    ))
}

impl NonAccountRootProjection<'_> {
    /// Run the complete current-partition grammar before any wire or matching
    /// decision. Only exact keys and serialized bytes can consume this source's
    /// leaves. A mismatch or arithmetic failure keeps the original full path.
    /// The boolean reports arithmetic reuse only, never a validity verdict.
    pub fn root(
        self,
        actual: &State,
        arithmetic: &mut StateRootArithmetic,
    ) -> Result<(Hash, bool)> {
        for value in actual.values() {
            validate_canonical(value)?;
        }
        if actual.len() > 65_536 {
            return Err("LIMIT");
        }
        if exact_non_account_input(actual, self.source) {
            if let Ok(root) = arithmetic.root_from_projection(self.leaves) {
                return Ok((root, true));
            }
        }
        root_with_arithmetic(actual, arithmetic).map(|root| (root, false))
    }
}

fn exact_non_account_input(actual: &State, source: &State) -> bool {
    let mut expected = source
        .iter()
        .filter(|(key, _)| !key.starts_with("account:"));
    for (key, value) in actual {
        let Some((prior_key, prior_value)) = expected.next() else {
            return false;
        };
        if key != prior_key {
            return false;
        }
        // Both States already passed their complete grammar: source at token
        // creation and actual above. Keep exact serde bytes, never Value==.
        let (Ok(actual_bytes), Ok(prior_bytes)) = (
            canonical_after_validation(value),
            canonical_after_validation(prior_value),
        ) else {
            return false;
        };
        if actual_bytes != prior_bytes {
            return false;
        }
    }
    expected.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_executor::root;
    use serde_json::json;

    fn partition(source: &State) -> State {
        source
            .iter()
            .filter(|(key, _)| !key.starts_with("account:"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    #[test]
    fn complete_projection_empty_and_all_account_states_keep_original_roots() {
        for source in [
            State::new(),
            State::from([
                ("account:a".into(), json!({"balance":0,"nonce":1})),
                ("account:z".into(), json!("quote\"slash\\newline\n")),
            ]),
        ] {
            let mut arithmetic = StateRootArithmetic::new(0);
            let (full, projection) =
                root_with_non_account_projection(&source, &mut arithmetic).unwrap();
            assert_eq!(full, root(&source).unwrap());
            let projection = projection.unwrap();
            assert_eq!(projection.leaves.payload_bytes(), 0);
            assert_eq!(
                projection.root(&State::new(), &mut arithmetic),
                Ok((root(&State::new()).unwrap(), true))
            );
        }
    }

    #[test]
    fn complete_projection_large_current_input_keeps_exact_roots_and_hash_only_bound() {
        let mut source: State = (0..2100)
            .map(|i| (format!("large-current:{i:04}"), json!("x".repeat(4080))))
            .collect();
        source.insert(
            "account:kept-in-full-root".into(),
            json!({"balance":7,"nonce":1}),
        );
        source.insert("meta:issued".into(), json!(7));
        let mut arithmetic = StateRootArithmetic::new(2 * 1024 * 1024);
        for replacement in ["x", "y"] {
            source.insert("large-current:2099".into(), json!(replacement.repeat(4080)));
            let actual = partition(&source);
            let payload: usize = actual
                .iter()
                .map(|(key, value)| key.len() + serde_json::to_vec(value).unwrap().len())
                .sum();
            assert!(payload > 8 * 1024 * 1024);
            let expected_full = root(&source).unwrap();
            let expected_subset = root(&actual).unwrap();
            for _ in 0..2 {
                let (full, projection) =
                    root_with_non_account_projection(&source, &mut arithmetic).unwrap();
                assert_eq!(full, expected_full);
                let projection = projection.expect("large bodies still fit the hash-only bound");
                assert_eq!(projection.leaves.payload_bytes(), actual.len() * 64);
                assert!(projection.leaves.payload_bytes() < 2 * 1024 * 1024);
                assert_eq!(
                    projection.root(&actual, &mut arithmetic),
                    Ok((expected_subset, true))
                );
            }
        }
    }

    #[test]
    fn non_account_projection_requires_exact_current_bytes_and_key_set() {
        let source = State::from([
            ("account:excluded".into(), json!(7)),
            ("accounts:retained".into(), json!(null)),
            (
                "future:retained".into(),
                json!({"a":[true, "quote\"", "slash\\", "\n"],"z":u64::MAX}),
            ),
            ("plain".into(), json!("x")),
        ]);
        let original = partition(&source);
        let mut changed = original.clone();
        changed.insert("plain".into(), json!("y"));
        let mut removed = original.clone();
        removed.remove("accounts:retained");
        let mut inserted = original.clone();
        inserted.insert("absent-versus-null".into(), json!(null));
        let mut account = original.clone();
        account.insert("account:unexpected".into(), json!(0));
        let mut arithmetic = StateRootArithmetic::new(2 * 1024 * 1024);
        for (actual, reusable) in [
            (&original, true),
            (&changed, false),
            (&removed, false),
            (&inserted, false),
            (&account, false),
            (&State::new(), false),
        ] {
            let (_, projection) =
                root_with_non_account_projection(&source, &mut arithmetic).unwrap();
            let actual_root = projection.unwrap().root(actual, &mut arithmetic).unwrap();
            assert_eq!(actual_root, (root(actual).unwrap(), reusable));
        }
        assert_eq!(source["plain"], json!("x"));
    }

    #[test]
    fn projection_keeps_complete_grammar_before_wire_limits_and_refuses_retention_only() {
        let source = State::from([("normal".into(), json!(1))]);
        let mut arithmetic = StateRootArithmetic::new(2 * 1024 * 1024);
        for invalid in [json!(-0.0), json!(0.5), json!("λ"), json!({"λ":0})] {
            let actual = State::from([
                ("a".repeat(161), json!("x".repeat(4095))),
                ("zz-late".into(), invalid),
            ]);
            let expected = root(&actual);
            assert!(expected.is_err());
            assert_ne!(expected, Err("LIMIT"));
            assert_eq!(
                root_with_non_account_projection(&actual, &mut arithmetic).map(|v| v.0),
                expected
            );
            let (_, projection) =
                root_with_non_account_projection(&source, &mut arithmetic).unwrap();
            assert_eq!(
                projection
                    .unwrap()
                    .root(&actual, &mut arithmetic)
                    .map(|v| v.0),
                expected
            );
        }
        let mut oversized: State = (0..65_537)
            .map(|i| (format!("count:{i:05}"), json!(null)))
            .collect();
        for invalid in [None, Some(json!(-0.0))] {
            if let Some(value) = invalid {
                oversized.insert("zz-late".into(), value);
            }
            let expected = root(&oversized);
            assert!(expected.is_err());
            assert_eq!(
                root_with_non_account_projection(&oversized, &mut arithmetic).map(|v| v.0),
                expected
            );
            let (_, projection) =
                root_with_non_account_projection(&source, &mut arithmetic).unwrap();
            assert_eq!(
                projection
                    .unwrap()
                    .root(&oversized, &mut arithmetic)
                    .map(|v| v.0),
                expected
            );
        }
        for cap in [0, 63, 64] {
            let mut refused = StateRootArithmetic::new(cap);
            let (full, projection) =
                root_with_non_account_projection(&source, &mut refused).unwrap();
            assert_eq!(full, root(&source).unwrap());
            assert_eq!(projection.is_some(), cap >= 64);
            if let Some(projection) = projection {
                assert_eq!(projection.root(&source, &mut refused), Ok((full, true)));
            }
        }
    }
}
