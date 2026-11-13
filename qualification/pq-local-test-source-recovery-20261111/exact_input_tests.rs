use super::super::state_root;
use super::*;
use std::collections::BTreeMap;

fn checked(arithmetic: &mut StateRootArithmetic, values: &BTreeMap<Vec<u8>, Vec<u8>>) -> Hash {
    let observed = arithmetic
        .root_from_entries(values.iter().map(|(k, v)| Ok::<_, ()>((k, v))))
        .unwrap();
    assert_eq!(observed, state_root(values).unwrap());
    let observation = arithmetic.observation();
    assert_eq!(observation.input_keys, values.len());
    assert_eq!(
        observation.computed_leaf_hashes + observation.reused_leaf_hashes,
        values.len()
    );
    assert_eq!(
        observation.retained_payload_bytes,
        arithmetic.retained_payload_bytes()
    );
    assert!(observation.exact_input_bytes <= exact_inputs::MAX_BYTES);
    assert!(arithmetic.retained_payload_bytes() <= 2 * 1024 * 1024);
    observed
}

#[test]
fn exact_input_dictionary_reuses_full_bytes_inside_original_large_input_bound() {
    let mut arithmetic = StateRootArithmetic::new(2 * 1024 * 1024);
    let values = (0..2100)
        .map(|i| {
            (
                format!("fixture-large-parent:{i:04}").into_bytes(),
                vec![b'x'; 4082],
            )
        })
        .collect();
    let original = checked(&mut arithmetic, &values);
    assert_eq!(arithmetic.observation().reused_leaf_hashes, 0);
    assert!(arithmetic.observation().exact_input_bytes > 0);
    assert_eq!(checked(&mut arithmetic, &values), original);
    assert_eq!(arithmetic.observation().reused_leaf_hashes, values.len());
    assert_eq!(arithmetic.observation().computed_leaf_hashes, 0);
    // This is the pre-existing large-input test bound, not a larger cache cap.
    assert!(arithmetic.retained_payload_bytes() < 300_000);
}

#[test]
fn exact_input_dictionary_rechecks_values_keys_and_complete_reordered_sources() {
    let mut arithmetic = StateRootArithmetic::new(2 * 1024 * 1024);
    let mut values: BTreeMap<_, _> = (0..80)
        .map(|i| (format!("actual:{i:03}").into_bytes(), vec![b'a'; 4096]))
        .collect();
    let original = checked(&mut arithmetic, &values);
    values.get_mut(b"actual:039".as_slice()).unwrap()[4095] = b'b';
    assert_ne!(checked(&mut arithmetic, &values), original);
    assert_eq!(arithmetic.observation().computed_leaf_hashes, 1);
    assert_eq!(
        arithmetic.observation().reused_leaf_hashes,
        values.len() - 1
    );
    let value = values.remove(b"actual:040".as_slice()).unwrap();
    values.insert(b"changed:040".to_vec(), value);
    checked(&mut arithmetic, &values);
    assert_eq!(arithmetic.observation().computed_leaf_hashes, 1);
    values.remove(b"actual:020".as_slice());
    values.insert(b"new:claimed-root".to_vec(), original.to_vec());
    let expected = checked(&mut arithmetic, &values);
    assert_eq!(
        arithmetic
            .root_from_entries(values.iter().rev().map(|(k, v)| Ok::<_, ()>((k, v))))
            .unwrap(),
        expected
    );
    assert_eq!(arithmetic.observation().computed_leaf_hashes, 0);
    assert_eq!(arithmetic.observation().reused_leaf_hashes, values.len());
}

#[test]
fn exact_input_dictionary_refusal_keeps_original_root_and_leaf_work() {
    let mut arithmetic = StateRootArithmetic::new(2 * 1024 * 1024);
    let values = (0..32u8).map(|i| (vec![i], vec![i; 4096])).collect();
    let original = checked(&mut arithmetic, &values);
    assert_eq!(arithmetic.observation().exact_input_bytes, 0);
    assert_eq!(checked(&mut arithmetic, &values), original);
    assert_eq!(arithmetic.observation().computed_leaf_hashes, 32);
    assert_eq!(arithmetic.observation().reused_leaf_hashes, 0);
}

#[test]
fn exact_input_dictionary_compares_whole_keys_across_ambiguous_prefixes() {
    let mut arithmetic = StateRootArithmetic::new(2 * 1024 * 1024);
    let values = [
        vec![],
        b":".to_vec(),
        b"prefix:".to_vec(),
        b"prefix:key".to_vec(),
        b"prefix::key".to_vec(),
        b"prefix:key:".to_vec(),
        vec![0xff, b':', 0],
    ]
    .into_iter()
    .map(|key| (key, b"same bytes".to_vec()))
    .collect();
    let original = checked(&mut arithmetic, &values);
    assert_eq!(checked(&mut arithmetic, &values), original);
    assert_eq!(arithmetic.observation().reused_leaf_hashes, values.len());
    let material = arithmetic.material.as_ref().unwrap();
    let inputs = material.inputs.as_ref().unwrap();
    for (key, value) in &values {
        let path = hash(b"state-key", &[key]);
        let index = material
            .leaves
            .binary_search_by_key(&path, |row| row.0)
            .unwrap();
        assert!(inputs.matches(index, key, value));
        let mut changed_key = key.clone();
        changed_key.push(0);
        assert!(!inputs.matches(index, &changed_key, value));
        let mut changed_value = value.clone();
        changed_value.push(0);
        assert!(!inputs.matches(index, key, &changed_value));
    }
}
