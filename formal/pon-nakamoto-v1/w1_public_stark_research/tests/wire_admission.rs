//! Mutations of the actual retained complete proofs. No synthetic acceptance
//! fixture stands in for their real bincode/P3 encoding.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use bincode::Options;
use p3_field::PrimeCharacteristicRing;
use w1_full_public_stark_research::proof_config::{Challenge, Val, W1Proof};
use w1_full_public_stark_research::proof_wire::{Component, limits, scan_proof};

struct ObservedAllocator;
thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// The observation covers allocation requests made by the calling test thread
// during scan_proof, not process memory, other threads, decode or verification.
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACK.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if TRACK.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        }
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if TRACK.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

fn fixture(component: Component) -> &'static [u8] {
    match component {
        Component::Sha => include_bytes!("../results/retained-native-02/sha.proof.bin"),
        Component::Arithmetic => include_bytes!("../results/retained-native-02/arith.proof.bin"),
        Component::Carry => {
            include_bytes!("../results/round3-carry-wire-fixtures/carry.arith.proof.bin")
        }
        Component::PackedCarry => {
            include_bytes!("../results/round3-carry-wire-fixtures/packed.arith.proof.bin")
        }
        Component::ScheduledSha => {
            include_bytes!("../results/round4-schedule-wire-fixture/sha.proof.bin")
        }
    }
}

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

fn zero_allocation_scan(bytes: &[u8], component: Component) -> bool {
    ALLOCATIONS.with(|n| n.set(0));
    TRACK.with(|flag| flag.set(true));
    let result = scan_proof(bytes, component);
    TRACK.with(|flag| flag.set(false));
    assert_eq!(ALLOCATIONS.with(Cell::get), 0, "wire scan allocated");
    result.is_ok()
}

fn typed_mutation(component: Component, mutate: impl FnOnce(&mut W1Proof)) {
    let original = fixture(component);
    let mut proof: W1Proof = codec().deserialize(&original[8..]).unwrap();
    mutate(&mut proof);
    let mut wire = original[..8].to_vec();
    wire.extend(codec().serialize(&proof).unwrap());
    assert!(!zero_allocation_scan(&wire, component));
}

#[test]
fn actual_complete_proofs_match_the_frozen_codec_and_scan_without_allocations() {
    for component in [
        Component::Sha,
        Component::Arithmetic,
        Component::Carry,
        Component::PackedCarry,
        Component::ScheduledSha,
    ] {
        let bytes = fixture(component);
        assert!(zero_allocation_scan(bytes, component));
        let proof: W1Proof = codec().deserialize(&bytes[8..]).unwrap();
        assert_eq!(codec().serialize(&proof).unwrap(), bytes[8..]);
        let count = scan_proof(bytes, component).unwrap();
        let limit = limits(component);
        assert_eq!(count.vector_headers, limit.vector_headers);
        assert!(count.field_elements <= limit.maximum_field_elements);
        assert!(count.merkle_siblings <= limit.maximum_merkle_siblings);
        assert!(limit.maximum_bytes < 8 * 1024 * 1024);
    }
}

#[test]
fn huge_cap_and_trace_length_words_reject_before_any_allocation() {
    for component in [
        Component::Sha,
        Component::Arithmetic,
        Component::Carry,
        Component::PackedCarry,
        Component::ScheduledSha,
    ] {
        for offset in [8, 48, 89] {
            let mut bytes = fixture(component).to_vec();
            bytes[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(!zero_allocation_scan(&bytes, component));
        }
    }
}

#[test]
fn noncanonical_field_and_option_tags_are_rejected() {
    for component in [
        Component::Sha,
        Component::Arithmetic,
        Component::Carry,
        Component::PackedCarry,
        Component::ScheduledSha,
    ] {
        let mut bytes = fixture(component).to_vec();
        bytes[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(!zero_allocation_scan(&bytes, component));
        for tag in [1, 2, 255] {
            let mut bytes = fixture(component).to_vec();
            bytes[88] = tag;
            assert!(!zero_allocation_scan(&bytes, component));
        }
    }
}

#[test]
fn component_confusion_truncation_and_trailing_data_are_rejected() {
    for component in [
        Component::Sha,
        Component::Arithmetic,
        Component::Carry,
        Component::PackedCarry,
        Component::ScheduledSha,
    ] {
        let original = fixture(component);
        let mut bytes = original.to_vec();
        bytes[0] ^= 1;
        assert!(!zero_allocation_scan(&bytes, component));
        for amount in [1, 8, 32, original.len() - 8] {
            assert!(!zero_allocation_scan(
                &original[..original.len() - amount],
                component
            ));
        }
        let mut bytes = original.to_vec();
        bytes.push(0);
        assert!(!zero_allocation_scan(&bytes, component));
    }
    assert!(!zero_allocation_scan(
        fixture(Component::Sha),
        Component::Arithmetic
    ));
}

#[test]
fn oversized_component_envelope_rejects_without_scanning_payload() {
    let component = Component::Arithmetic;
    let bytes = vec![0; limits(component).maximum_bytes + 1];
    let error = scan_proof(&bytes, component).unwrap_err();
    assert_eq!(error.offset, 0);
    assert!(!zero_allocation_scan(&bytes, component));
}

#[test]
fn incorrect_ood_openings_reject_before_preprocessing() {
    typed_mutation(Component::Sha, |p| {
        p.opened_values.trace_next = None;
    });
    typed_mutation(Component::Arithmetic, |p| {
        p.opened_values.trace_local.pop();
    });
    typed_mutation(Component::Arithmetic, |p| {
        p.opened_values.preprocessed.as_mut().unwrap().next = Some(vec![Challenge::ZERO; 18]);
    });
    typed_mutation(Component::Sha, |p| {
        p.opened_values.quotient_chunks[0].pop();
    });
    typed_mutation(Component::Arithmetic, |p| {
        p.opened_values.random = Some(vec![Challenge::ZERO]);
    });
}

#[test]
fn wrong_fri_commitment_and_pow_counts_reject_before_preprocessing() {
    typed_mutation(Component::Arithmetic, |p| {
        p.opening_proof.commit_phase_commits.pop();
    });
    typed_mutation(Component::Arithmetic, |p| {
        p.opening_proof.commit_pow_witnesses.pop();
    });
    typed_mutation(Component::Arithmetic, |p| {
        p.opening_proof.input_openings.pop();
    });
}

#[test]
fn input_opening_query_matrix_and_width_counts_are_fixed() {
    typed_mutation(Component::Arithmetic, |p| {
        p.opening_proof.input_openings[0].opened_values.pop();
    });
    typed_mutation(Component::Arithmetic, |p| {
        p.opening_proof.input_openings[1].opened_values[0].pop();
    });
    typed_mutation(Component::Arithmetic, |p| {
        p.opening_proof.input_openings[2].opened_values[63][0].pop();
    });
}

#[test]
fn input_merkle_frontier_cannot_exceed_all_full_paths() {
    typed_mutation(Component::Arithmetic, |p| {
        p.opening_proof.input_openings[2]
            .opening_proof
            .sibling_hashes = vec![[Val::ZERO; 4]; 64 * 19 + 1];
    });
}

#[test]
fn fold_round_query_and_sibling_counts_are_fixed() {
    typed_mutation(Component::Arithmetic, |p| {
        p.opening_proof.commit_phase_openings.pop();
    });
    typed_mutation(Component::Arithmetic, |p| {
        p.opening_proof.commit_phase_openings[0]
            .sibling_values
            .pop();
    });
    typed_mutation(Component::Arithmetic, |p| {
        p.opening_proof.commit_phase_openings[16].sibling_values[63].push(Challenge::ZERO);
    });
}

#[test]
fn fold_merkle_frontier_uses_its_own_reduced_height() {
    typed_mutation(Component::Arithmetic, |p| {
        p.opening_proof.commit_phase_openings[16]
            .opening_proof
            .sibling_hashes = vec![[Val::ZERO; 4]; 64 * 2 + 1];
    });
}

#[test]
fn final_polynomial_and_trace_degree_are_fixed() {
    typed_mutation(Component::Arithmetic, |p| {
        p.opening_proof.final_poly.push(Challenge::ZERO);
    });
    typed_mutation(Component::Arithmetic, |p| {
        p.degree_bits = usize::MAX;
    });
}

#[test]
fn valid_shape_with_changed_canonical_value_is_not_misclassified_as_a_proof() {
    // It must reach the real verifier: the scanner only admits syntax.
    let component = Component::Arithmetic;
    let mut bytes = fixture(component).to_vec();
    bytes[16..24].copy_from_slice(&0u64.to_le_bytes());
    assert!(zero_allocation_scan(&bytes, component));
}

#[test]
fn carry_profiles_have_separate_envelopes_and_fixed_bounds() {
    let profiles = [
        Component::Sha,
        Component::Arithmetic,
        Component::Carry,
        Component::PackedCarry,
        Component::ScheduledSha,
    ];
    for source in profiles {
        for target in profiles {
            assert_eq!(
                zero_allocation_scan(fixture(source), target),
                source == target
            );
        }
    }
    let a = limits(Component::Carry);
    assert_eq!(
        (
            a.minimum_bytes,
            a.maximum_bytes,
            a.maximum_field_elements,
            a.vector_headers,
            a.maximum_merkle_siblings
        ),
        (89669, 554565, 67778, 1540, 14528)
    );
    let b = limits(Component::PackedCarry);
    assert_eq!(
        (
            b.minimum_bytes,
            b.maximum_bytes,
            b.maximum_field_elements,
            b.vector_headers,
            b.maximum_merkle_siblings
        ),
        (317189, 659205, 81059, 1339, 10688)
    );
}

#[test]
fn carry_profile_opening_shapes_are_checked_before_decode() {
    for component in [Component::Carry, Component::PackedCarry] {
        typed_mutation(component, |p| {
            p.opened_values.trace_local.pop();
        });
        typed_mutation(component, |p| {
            p.opened_values.preprocessed.as_mut().unwrap().local.pop();
        });
        typed_mutation(component, |p| {
            p.opened_values.trace_next = Some(vec![]);
        });
        typed_mutation(component, |p| {
            p.opening_proof.input_openings[0].opened_values[63][0].pop();
        });
        typed_mutation(component, |p| {
            p.opening_proof
                .commit_phase_openings
                .last_mut()
                .unwrap()
                .sibling_values
                .pop();
        });
        typed_mutation(component, |p| {
            p.opening_proof.final_poly.push(Challenge::ZERO);
        });
        typed_mutation(component, |p| {
            p.degree_bits = 13;
        });
        let mut canonical_wrong_value = fixture(component).to_vec();
        canonical_wrong_value[16..24].copy_from_slice(&0u64.to_le_bytes());
        assert!(zero_allocation_scan(&canonical_wrong_value, component));
    }
}

#[test]
fn scheduled_sha_profile_bounds_and_openings_are_fixed() {
    let component = Component::ScheduledSha;
    let bound = limits(component);
    assert_eq!(
        (
            bound.minimum_bytes,
            bound.maximum_bytes,
            bound.maximum_field_elements,
            bound.vector_headers,
            bound.maximum_merkle_siblings
        ),
        (3033413, 3338565, 415980, 1338, 9536)
    );
    typed_mutation(component, |p| {
        p.opened_values.trace_next = None;
    });
    typed_mutation(component, |p| {
        p.opened_values.trace_local.pop();
    });
    typed_mutation(component, |p| {
        p.opened_values.preprocessed.as_mut().unwrap().local.pop();
    });
    typed_mutation(component, |p| {
        p.opening_proof.input_openings[2].opened_values[63][0].pop();
    });
    typed_mutation(component, |p| {
        p.opening_proof.final_poly.push(Challenge::ZERO);
    });
    typed_mutation(component, |p| {
        p.degree_bits = 14;
    });
}
