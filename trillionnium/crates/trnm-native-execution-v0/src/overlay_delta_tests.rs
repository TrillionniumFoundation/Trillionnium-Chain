//! Transaction-local staging regressions. These test the real staging function;
//! the clone-based oracle below is test-only and is not production authority.

use std::cell::Cell;

use super::*;

#[derive(Default)]
struct MemoryView {
    objects: BTreeMap<String, StateObject>,
    reads: Cell<usize>,
    unavailable_key: Option<String>,
}

impl TryStateViewV0 for MemoryView {
    type Error = &'static str;

    fn try_get(&self, key: &str) -> std::result::Result<Option<StateObject>, Self::Error> {
        self.reads.set(self.reads.get() + 1);
        if self.unavailable_key.as_deref() == Some(key) {
            return Err("injected authenticated parent read failure");
        }
        Ok(self.objects.get(key).cloned())
    }
}

fn account_mutation(account: &str, expected: Option<u64>, balance: u128) -> RuntimeMutation {
    RuntimeMutation {
        object_key_hex: account_key(account),
        object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
        expected_version: expected,
        next_version: expected.map_or(1, |version| version.checked_add(1).unwrap()),
        value_bytes: serde_json::to_vec(&AccountV1 {
            account: account.to_string(),
            balance,
            nonce: 0,
        })
        .unwrap(),
    }
}

fn state_object(mutation: &RuntimeMutation) -> StateObject {
    StateObject {
        object_type: mutation.object_type.clone(),
        version: mutation.next_version,
        value_bytes: mutation.value_bytes.clone(),
    }
}

fn prior_overlay(count: usize) -> BTreeMap<String, StateObject> {
    (0..count)
        .map(|index| {
            let mutation = account_mutation(&format!("did:delta:{index}"), Some(6), 10);
            (mutation.object_key_hex.clone(), state_object(&mutation))
        })
        .collect()
}

#[test]
fn empty_transaction_stages_no_prior_writes() {
    let view = MemoryView::default();
    let prior = prior_overlay(256);
    let original = prior.clone();
    let delta = stage_runtime_mutations_v0(&view, 2, &prior, &[]).unwrap();
    assert!(delta.is_empty());
    assert_eq!(prior, original);
    assert_eq!(view.reads.get(), 0);
}

#[test]
fn one_touched_object_does_not_copy_the_block_overlay() {
    let view = MemoryView::default();
    let mut prior = prior_overlay(256);
    let untouched_key = account_key("did:delta:0");
    let untouched_allocation = prior[&untouched_key].value_bytes.as_ptr();
    let mutation = account_mutation("did:delta:127", Some(7), 99);
    let delta = stage_runtime_mutations_v0(&view, 2, &prior, &[mutation]).unwrap();
    assert_eq!(delta.len(), 1);
    assert!(!delta.contains_key(&untouched_key));
    assert_eq!(prior[&account_key("did:delta:127")].version, 7);
    assert_eq!(view.reads.get(), 0);
    prior.extend(delta);
    assert_eq!(prior.len(), 256);
    assert_eq!(prior[&account_key("did:delta:127")].version, 8);
    assert_eq!(
        prior[&untouched_key].value_bytes.as_ptr(),
        untouched_allocation
    );
}

#[test]
fn in_block_overlay_takes_precedence_over_parent_state() {
    let prior = prior_overlay(1);
    let mut view = MemoryView::default();
    let parent = account_mutation("did:delta:0", None, 1);
    view.objects
        .insert(parent.object_key_hex.clone(), state_object(&parent));
    let mutation = account_mutation("did:delta:0", Some(7), 20);
    let delta = stage_runtime_mutations_v0(&view, 2, &prior, &[mutation]).unwrap();
    assert_eq!(delta[&account_key("did:delta:0")].version, 8);
    assert_eq!(view.reads.get(), 0);
}

#[test]
fn untouched_key_is_loaded_from_authenticated_parent() {
    let prior = prior_overlay(2);
    let mut view = MemoryView::default();
    let parent = account_mutation("did:parent:1", Some(2), 10);
    view.objects
        .insert(parent.object_key_hex.clone(), state_object(&parent));
    let mutation = account_mutation("did:parent:1", Some(3), 11);
    let delta = stage_runtime_mutations_v0(&view, 2, &prior, &[mutation]).unwrap();
    assert_eq!(delta.len(), 1);
    assert_eq!(delta[&account_key("did:parent:1")].version, 4);
    assert_eq!(view.reads.get(), 1);
    assert_eq!(view.objects[&account_key("did:parent:1")].version, 3);
}

fn assert_rejected_without_overlay_change(
    view: &MemoryView,
    prior: &BTreeMap<String, StateObject>,
    mutations: &[RuntimeMutation],
    expected_error: &str,
) {
    let original = prior.clone();
    let parent = view.objects.clone();
    let error = stage_runtime_mutations_v0(view, 2, prior, mutations).unwrap_err();
    assert!(error.to_string().contains(expected_error), "{error:#}");
    assert_eq!(prior, &original);
    assert_eq!(view.objects, parent);
}

#[test]
fn later_duplicate_rejects_the_entire_transaction() {
    let view = MemoryView::default();
    let prior = prior_overlay(2);
    let first = account_mutation("did:new:1", None, 12);
    assert_rejected_without_overlay_change(
        &view,
        &prior,
        &[first.clone(), first],
        "duplicate runtime mutation key",
    );
}

#[test]
fn later_stale_version_rejects_without_partial_apply() {
    let view = MemoryView::default();
    let prior = prior_overlay(2);
    assert_rejected_without_overlay_change(
        &view,
        &prior,
        &[
            account_mutation("did:new:1", None, 12),
            account_mutation("did:delta:1", Some(6), 12),
        ],
        "expected-version mismatch",
    );
}

#[test]
fn later_parent_read_failure_is_not_treated_as_absence() {
    let view = MemoryView {
        unavailable_key: Some(account_key("did:unavailable:1")),
        ..MemoryView::default()
    };
    let prior = prior_overlay(2);
    assert_rejected_without_overlay_change(
        &view,
        &prior,
        &[
            account_mutation("did:new:1", None, 12),
            account_mutation("did:unavailable:1", None, 12),
        ],
        "authenticated mutation read failed",
    );
    assert_eq!(view.reads.get(), 2);
}

#[test]
fn malformed_later_value_and_key_alias_cannot_publish_earlier_delta() {
    let view = MemoryView::default();
    let prior = prior_overlay(2);
    let first = account_mutation("did:new:1", None, 12);
    let mut malformed = account_mutation("did:new:2", None, 12);
    malformed.value_bytes = b"not-json".to_vec();
    assert_rejected_without_overlay_change(
        &view,
        &prior,
        &[first.clone(), malformed],
        "decode runtime mutation value",
    );
    let mut aliased = account_mutation("did:new:2", None, 12);
    aliased.object_key_hex = account_key("did:other:2");
    assert_rejected_without_overlay_change(
        &view,
        &prior,
        &[first, aliased],
        "canonical key mismatch",
    );
}

#[test]
fn existing_type_and_unknown_new_type_still_reject() {
    let view = MemoryView::default();
    let prior = prior_overlay(2);
    let mut changed_type = account_mutation("did:delta:0", Some(7), 12);
    changed_type.object_type = "unrecognized".to_string();
    assert_rejected_without_overlay_change(&view, &prior, &[changed_type], "changes object type");
    let mut unknown = account_mutation("did:new:1", None, 12);
    unknown.object_type = "unrecognized".to_string();
    assert_rejected_without_overlay_change(&view, &prior, &[unknown], "unsupported object type");
}

#[test]
fn exhausted_and_skipped_versions_still_reject() {
    let view = MemoryView::default();
    let mut prior = prior_overlay(2);
    let mut mutation = account_mutation("did:delta:0", Some(7), 12);
    mutation.next_version = 9;
    assert_rejected_without_overlay_change(
        &view,
        &prior,
        &[mutation.clone()],
        "next-version mismatch",
    );
    prior.get_mut(&mutation.object_key_hex).unwrap().version = u64::MAX;
    mutation.expected_version = Some(u64::MAX);
    mutation.next_version = 0;
    assert_rejected_without_overlay_change(&view, &prior, &[mutation], "object version exhausted");
}

/// Preserve the previous overlay-assembly algorithm as a differential oracle.
/// This deliberately shares the unchanged domain validator: it is not an
/// independent protocol implementation or cryptographic acceptance test.
fn clone_overlay_oracle(
    view: &MemoryView,
    prior: &BTreeMap<String, StateObject>,
    mutations: &[RuntimeMutation],
) -> Result<BTreeMap<String, StateObject>> {
    let mut staged = prior.clone();
    let mut seen = BTreeSet::new();
    for mutation in mutations {
        ensure!(
            seen.insert(mutation.object_key_hex.clone()),
            "duplicate key"
        );
        let current = match staged.get(&mutation.object_key_hex) {
            Some(object) => Some(object.clone()),
            None => view
                .try_get(&mutation.object_key_hex)
                .map_err(|error| anyhow!(error))?,
        };
        ensure!(
            current.as_ref().map(|object| object.version) == mutation.expected_version,
            "stale version"
        );
        if let Some(object) = &current {
            ensure!(object.object_type == mutation.object_type, "changed type");
        }
        let next = current.as_ref().map_or(Ok(1), |object| {
            object.version.checked_add(1).context("version exhausted")
        })?;
        ensure!(next == mutation.next_version, "skipped version");
        validate_runtime_mutation_v0(2, mutation)?;
        staged.insert(mutation.object_key_hex.clone(), state_object(mutation));
    }
    Ok(staged)
}

#[test]
fn mixed_creates_and_hot_updates_match_clone_based_serial_oracle() {
    let view = MemoryView::default();
    let mut actual = prior_overlay(8);
    let mut expected = actual.clone();
    for index in 0..128 {
        let account = if index % 2 == 0 {
            format!("did:delta:{}", index % 8)
        } else {
            format!("did:new:{index}")
        };
        let key = account_key(&account);
        let version = expected.get(&key).map(|object| object.version);
        let mutations = [account_mutation(&account, version, index as u128)];
        expected = clone_overlay_oracle(&view, &expected, &mutations).unwrap();
        let delta = stage_runtime_mutations_v0(&view, 2, &actual, &mutations).unwrap();
        assert_eq!(delta.len(), 1);
        actual.extend(delta);
        assert_eq!(actual, expected);
    }
}

#[test]
fn independent_writes_stage_linear_item_count_not_accumulated_prefixes() {
    for count in [1, 2, 4, 8, 64, 256] {
        let view = MemoryView::default();
        let mut prior = BTreeMap::new();
        let mut staged_items = 0;
        for index in 0..count {
            let mutation = account_mutation(&format!("did:scale:{index}"), None, 1);
            let delta = stage_runtime_mutations_v0(&view, 2, &prior, &[mutation]).unwrap();
            assert_eq!(delta.len(), 1);
            staged_items += delta.len();
            prior.extend(delta);
        }
        assert_eq!(staged_items, count);
        assert_eq!(prior.len(), count);
        assert_eq!(view.reads.get(), count);
    }
}
