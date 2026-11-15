//! Structural admission controls using four actual full W1 proof files.
//! This scanner harness does not replace the independent cryptographic verifier.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use bincode::Options;
use p3_field::PrimeCharacteristicRing;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use w1_full_public_stark_research::proof_wire as legacy;
use w1_full_public_stark_research::tagged_sha3::{
    Challenge, GOLDILOCKS_ORDER, LOG_BLOWUP, NUM_QUERIES, W1Proof,
};
use w1_full_public_stark_research::tagged_sha3_wire::{Component, WireScan, limits, scan_proof};

struct ObservedAllocator;
thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// Observation covers only allocation calls on this thread during scan_proof.
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

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024)
        .reject_trailing_bytes()
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > 16 * 1024 * 1024 {
        return Err("control input exceeds 16 MiB".into());
    }
    let mut bytes = Vec::new();
    file.take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("control input changed length".into());
    }
    Ok(bytes)
}

fn observed_scan(bytes: &[u8], component: Component) -> Result<WireScan, String> {
    ALLOCATIONS.with(|n| n.set(0));
    TRACK.with(|n| n.set(true));
    let result = scan_proof(bytes, component);
    TRACK.with(|n| n.set(false));
    let count = ALLOCATIONS.with(Cell::get);
    assert_eq!(count, 0, "scanner allocated");
    result.map_err(|e| e.to_string())
}

fn negative(rows: &mut Vec<Value>, name: &str, bytes: &[u8], component: Component) {
    let error = observed_scan(bytes, component).expect_err("malformed shape admitted");
    rows.push(json!({"name":name,"component":component as u32,"rejected":true,"error":error,"observed_scanner_allocations":0}));
}

fn typed(
    rows: &mut Vec<Value>,
    name: &str,
    original: &[u8],
    component: Component,
    mutate: impl FnOnce(&mut W1Proof),
) {
    let mut proof: W1Proof = codec().deserialize(&original[8..]).unwrap();
    mutate(&mut proof);
    let mut bytes = component.magic().to_vec();
    bytes.extend(codec().serialize(&proof).unwrap());
    negative(rows, name, &bytes, component);
}

fn run(paths: &[String]) -> Result<Value, String> {
    if paths.len() != 4 {
        return Err("tagged_sha3_wire_controls NEW_SHA NEW_CARRY LEGACY_SHA LEGACY_CARRY".into());
    }
    let files: Vec<Vec<u8>> = paths
        .iter()
        .map(|p| read(Path::new(p)))
        .collect::<Result<_, _>>()?;
    let mut rows = Vec::new();
    let mut positive = Vec::new();
    for (i, component, old_component) in [
        (0, Component::Sha, legacy::Component::Sha),
        (1, Component::PackedCarry, legacy::Component::PackedCarry),
    ] {
        let original = &files[i];
        let scan = observed_scan(original, component)?;
        let proof: W1Proof = codec()
            .deserialize(&original[8..])
            .map_err(|e| e.to_string())?;
        assert_eq!(codec().serialize(&proof).unwrap(), original[8..]);
        assert_eq!(scan.vector_headers, limits(component).vector_headers);
        positive.push(json!({"component":component as u32,"bytes":scan.bytes,"field_elements":scan.field_elements,"vector_headers":scan.vector_headers,"merkle_siblings":scan.merkle_siblings,"observed_scanner_allocations":0}));
        assert!(
            legacy::scan_proof(&files[i + 2], old_component).is_ok(),
            "original legacy fixture rejected"
        );
        assert!(
            legacy::scan_proof(original, old_component).is_err(),
            "legacy scanner accepted new envelope"
        );
        negative(
            &mut rows,
            "new_rejects_legacy_envelope",
            &files[i + 2],
            component,
        );
        rows.push(json!({"name":"legacy_rejects_new_envelope","component":component as u32,"rejected":true}));
        for offset in [8usize, 80, 153] {
            let mut bytes = original.clone();
            bytes[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            negative(
                &mut rows,
                &format!("huge_length_at_{offset}"),
                &bytes,
                component,
            );
        }
        for tag in [1, 2, 255] {
            let mut bytes = original.clone();
            bytes[152] = tag;
            negative(
                &mut rows,
                &format!("random_option_{tag}"),
                &bytes,
                component,
            );
        }
        let mut bytes = original.clone();
        bytes[161..169].copy_from_slice(&GOLDILOCKS_ORDER.to_le_bytes());
        negative(&mut rows, "noncanonical_field", &bytes, component);
        for amount in [1usize, 8, 64, original.len() - 8] {
            negative(
                &mut rows,
                &format!("truncate_{amount}"),
                &original[..original.len() - amount],
                component,
            );
        }
        let mut bytes = original.clone();
        bytes.push(0);
        negative(&mut rows, "trailing_byte", &bytes, component);
        let mut bytes = original.clone();
        bytes[0] ^= 1;
        negative(&mut rows, "magic_bit", &bytes, component);
        negative(
            &mut rows,
            "oversize_envelope",
            &vec![0; limits(component).maximum_bytes + 1],
            component,
        );
        let mut bytes = original.clone();
        bytes[16..80].fill(255);
        assert!(
            observed_scan(&bytes, component).is_ok(),
            "raw digest words must not be field-reduced"
        );
        rows.push(json!({"name":"raw_all_ff_digest_structurally_admitted","component":component as u32,"structural_admission":true,"cryptographic_verification_not_performed_by_scanner":true,"observed_scanner_allocations":0}));
        typed(&mut rows, "short_trace_opening", original, component, |p| {
            p.opened_values.trace_local.pop();
        });
        typed(
            &mut rows,
            "unexpected_preprocessed_next",
            original,
            component,
            |p| {
                p.opened_values.preprocessed.as_mut().unwrap().next = Some(vec![Challenge::ZERO]);
            },
        );
        typed(
            &mut rows,
            "short_quotient_opening",
            original,
            component,
            |p| {
                p.opened_values.quotient_chunks[0].pop();
            },
        );
        typed(
            &mut rows,
            "unexpected_random_opening",
            original,
            component,
            |p| {
                p.opened_values.random = Some(vec![Challenge::ZERO]);
            },
        );
        typed(
            &mut rows,
            "short_fri_commitments",
            original,
            component,
            |p| {
                p.opening_proof.commit_phase_commits.pop();
            },
        );
        typed(
            &mut rows,
            "short_fri_commit_pow",
            original,
            component,
            |p| {
                p.opening_proof.commit_pow_witnesses.pop();
            },
        );
        typed(
            &mut rows,
            "short_input_batch_count",
            original,
            component,
            |p| {
                p.opening_proof.input_openings.pop();
            },
        );
        typed(&mut rows, "short_query_count", original, component, |p| {
            p.opening_proof.input_openings[0].opened_values.pop();
        });
        typed(&mut rows, "short_matrix_count", original, component, |p| {
            p.opening_proof.input_openings[0].opened_values[0].pop();
        });
        typed(&mut rows, "short_row_width", original, component, |p| {
            p.opening_proof.input_openings[0].opened_values[0][0].pop();
        });
        typed(
            &mut rows,
            "oversize_input_frontier",
            original,
            component,
            |p| {
                p.opening_proof.input_openings[0]
                    .opening_proof
                    .sibling_hashes =
                    vec![[0u64; 8]; NUM_QUERIES * (component.degree_bits() + LOG_BLOWUP) + 1];
            },
        );
        typed(
            &mut rows,
            "short_fold_round_count",
            original,
            component,
            |p| {
                p.opening_proof.commit_phase_openings.pop();
            },
        );
        typed(
            &mut rows,
            "short_fold_query_count",
            original,
            component,
            |p| {
                p.opening_proof.commit_phase_openings[0]
                    .sibling_values
                    .pop();
            },
        );
        typed(
            &mut rows,
            "oversize_fold_sibling_count",
            original,
            component,
            |p| {
                p.opening_proof.commit_phase_openings[0].sibling_values[0].push(Challenge::ZERO);
            },
        );
        typed(
            &mut rows,
            "oversize_final_fold_frontier",
            original,
            component,
            |p| {
                p.opening_proof.commit_phase_openings[component.degree_bits() - 1]
                    .opening_proof
                    .sibling_hashes = vec![[0u64; 8]; NUM_QUERIES * LOG_BLOWUP + 1];
            },
        );
        typed(
            &mut rows,
            "oversize_final_polynomial",
            original,
            component,
            |p| {
                p.opening_proof.final_poly.push(Challenge::ZERO);
            },
        );
        typed(&mut rows, "wrong_degree", original, component, |p| {
            p.degree_bits ^= 1;
        });
    }
    negative(
        &mut rows,
        "new_component_confusion",
        &files[0],
        Component::PackedCarry,
    );
    typed(
        &mut rows,
        "missing_sha_next",
        &files[0],
        Component::Sha,
        |p| {
            p.opened_values.trace_next = None;
        },
    );
    typed(
        &mut rows,
        "unexpected_carry_next",
        &files[1],
        Component::PackedCarry,
        |p| {
            p.opened_values.trace_next = Some(vec![Challenge::ZERO]);
        },
    );
    let identities:Vec<_>=paths.iter().zip(&files).map(|(path,bytes)|json!({"path":path,"bytes":bytes.len(),"sha256":hex::encode(Sha256::digest(bytes))})).collect();
    Ok(
        json!({"schema":"w1-tagged-sha3-wire-controls-v1","result":"PASS","qualification":"HOLD_NO_GO","inputs":identities,"positive":positive,"control_count":rows.len(),"controls":rows,"cryptographic_verification_performed_by_this_harness":false,"global_rejection_cost_bound":false}),
    )
}

fn main() {
    match run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
