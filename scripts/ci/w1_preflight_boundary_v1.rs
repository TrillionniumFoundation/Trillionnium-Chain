//! Synthetic grammar only: exercise the exact pinned Composite preflight.
//! No SDK, cryptographic verification, W1 execution, proof generation or network.
//! Construction and parser allocation counts are separate. Counters describe
//! Rust global allocator calls, not RSS or foreign allocator activity.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
compile_error!("this bounded measurement uses the Linux 64-bit clock ABI");

#[allow(dead_code)]
#[path = "../../trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/host/src/receipt_bounds.rs"]
mod bounds;

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
use std::time::Instant;

const REPEATS: usize = 11;
const CPU_BATCH_CALLS: usize = 4096;
const MIN_WORDS: usize = 92; // Pinned RV32IM v2: version + 90 outputs + po2.
static TRACKING: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static REALLOCS: AtomicU64 = AtomicU64::new(0);
static DEALLOCS: AtomicU64 = AtomicU64::new(0);
static REQUESTED: AtomicU64 = AtomicU64::new(0);

struct Counted;
unsafe impl GlobalAlloc for Counted {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACKING.load(SeqCst) {
            ALLOCS.fetch_add(1, SeqCst);
            REQUESTED.fetch_add(layout.size() as u64, SeqCst);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if TRACKING.load(SeqCst) {
            ALLOCS.fetch_add(1, SeqCst);
            REQUESTED.fetch_add(layout.size() as u64, SeqCst);
        }
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, old: Layout, new_size: usize) -> *mut u8 {
        if TRACKING.load(SeqCst) {
            REALLOCS.fetch_add(1, SeqCst);
            REQUESTED.fetch_add(new_size as u64, SeqCst);
        }
        unsafe { System.realloc(ptr, old, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if TRACKING.load(SeqCst) {
            DEALLOCS.fetch_add(1, SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Counted = Counted;

#[derive(Clone, Copy)]
struct Counts {
    allocations: u64,
    reallocations: u64,
    deallocations: u64,
    requested_bytes: u64,
}
fn begin_counts() {
    ALLOCS.store(0, SeqCst);
    REALLOCS.store(0, SeqCst);
    DEALLOCS.store(0, SeqCst);
    REQUESTED.store(0, SeqCst);
    TRACKING.store(true, SeqCst);
}
fn end_counts() -> Counts {
    TRACKING.store(false, SeqCst);
    Counts {
        allocations: ALLOCS.load(SeqCst),
        reallocations: REALLOCS.load(SeqCst),
        deallocations: DEALLOCS.load(SeqCst),
        requested_bytes: REQUESTED.load(SeqCst),
    }
}

#[repr(C)]
struct Timespec {
    seconds: i64,
    nanoseconds: i64,
}
unsafe extern "C" {
    fn clock_gettime(clock: i32, time: *mut Timespec) -> i32;
    fn fsync(fd: i32) -> i32;
}
fn cpu_ns() -> u128 {
    let mut time = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    // Linux CLOCK_PROCESS_CPUTIME_ID. Clock calls are outside allocator counting.
    assert_eq!(unsafe { clock_gettime(2, &mut time) }, 0);
    assert!(time.seconds >= 0 && (0..1_000_000_000).contains(&time.nanoseconds));
    time.seconds as u128 * 1_000_000_000 + time.nanoseconds as u128
}
fn quoted(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ch if ch <= '\u{1f}' => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}
fn emit(line: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{line}")?;
    out.flush()?;
    // The Python owner gives each case an exclusive regular stdout file.
    if unsafe { fsync(1) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn put32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_le_bytes());
}
fn put64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_le_bytes());
}
fn set32(out: &mut [u8], offset: usize, n: u32) {
    out[offset..offset + 4].copy_from_slice(&n.to_le_bytes());
}
fn set64(out: &mut [u8], offset: usize, n: u64) {
    out[offset..offset + 8].copy_from_slice(&n.to_le_bytes());
}
fn zeros(out: &mut Vec<u8>, n: usize) {
    out.resize(out.len() + n, 0);
}

#[derive(Clone, Copy)]
enum Expected {
    Shape(usize, u64, u32),
    Refused(&'static str),
    Malformed(&'static str),
}
struct Fixture {
    bytes: Vec<u8>,
    expected: Expected,
    last_index: usize,
    last_hash: usize,
    last_po2: usize,
    last_seal_length: usize,
    last_output_option: usize,
    outer_assumptions: usize,
    outer_journal_length: usize,
}
fn skeleton(segments: usize, po2: u32, target_bytes: usize) -> Fixture {
    // Independent fixed bincode grammar. None of these zero-filled seals is a
    // cryptographic proof. 238 bytes accompany each seal; outer framing is 320.
    let minimum_bytes = 320 + segments * (MIN_WORDS * 4 + 238);
    assert!(target_bytes >= minimum_bytes && (target_bytes - minimum_bytes) % 4 == 0);
    assert!(target_bytes <= bounds::MAX_RECEIPT_BYTES);
    let mut extra_words = (target_bytes - minimum_bytes) / 4;
    let mut f = Fixture {
        bytes: Vec::with_capacity(target_bytes + 1),
        expected: Expected::Shape(segments, (segments as u64) << po2, po2),
        last_index: 0,
        last_hash: 0,
        last_po2: 0,
        last_seal_length: 0,
        last_output_option: 0,
        outer_assumptions: 0,
        outer_journal_length: 0,
    };
    put32(&mut f.bytes, 0); // Composite variant.
    put64(&mut f.bytes, segments as u64);
    for index in 0..segments {
        let extra = extra_words.min(bounds::MAX_SEAL_WORDS - MIN_WORDS);
        extra_words -= extra;
        let words = MIN_WORDS + extra;
        f.last_seal_length = f.bytes.len();
        put64(&mut f.bytes, words as u64);
        let seal_start = f.bytes.len();
        zeros(&mut f.bytes, words * 4);
        set32(&mut f.bytes, seal_start, 2);
        f.last_po2 = seal_start + 91 * 4;
        set32(&mut f.bytes, f.last_po2, po2);
        f.last_index = f.bytes.len();
        put32(&mut f.bytes, index as u32);
        put64(&mut f.bytes, 9);
        f.last_hash = f.bytes.len();
        f.bytes.extend_from_slice(b"poseidon2");
        zeros(&mut f.bytes, 32); // Verifier digest: not authenticated here.
        for _ in 0..2 {
            put32(&mut f.bytes, 0); // Opened SystemState.
            zeros(&mut f.bytes, 36);
        }
        put32(&mut f.bytes, 0); // Halted(0).
        put32(&mut f.bytes, 0);
        put32(&mut f.bytes, 1); // Pruned claim input.
        zeros(&mut f.bytes, 32);
        put32(&mut f.bytes, 0); // Opened Some(Output).
        f.last_output_option = f.bytes.len();
        f.bytes.push(1);
        put32(&mut f.bytes, 1); // Pruned journal.
        zeros(&mut f.bytes, 32);
        put32(&mut f.bytes, 0); // Opened empty assumptions.
        put64(&mut f.bytes, 0);
    }
    assert_eq!(extra_words, 0);
    f.outer_assumptions = f.bytes.len();
    put64(&mut f.bytes, 0);
    zeros(&mut f.bytes, 32);
    f.outer_journal_length = f.bytes.len();
    put64(&mut f.bytes, bounds::JOURNAL_BYTES as u64);
    zeros(&mut f.bytes, bounds::JOURNAL_BYTES + 32);
    assert_eq!(f.bytes.len(), target_bytes);
    f
}
fn fixture(case: &str) -> Fixture {
    let (segments, po2, target) = match case {
        "small_control" => (1, 13, 320 + MIN_WORDS * 4 + 238),
        "largest_seal_control" => (1, 20, 320 + bounds::MAX_SEAL_WORDS * 4 + 238),
        "max_segments_cycles_control" => (
            bounds::MAX_SEGMENTS,
            17,
            320 + bounds::MAX_SEGMENTS * (MIN_WORDS * 4 + 238),
        ),
        "near_total_bytes_control" | "late_trailing_byte" => {
            (bounds::MAX_SEGMENTS, 17, bounds::MAX_RECEIPT_BYTES - 4)
        }
        _ => (bounds::MAX_SEGMENTS, 17, bounds::MAX_RECEIPT_BYTES),
    };
    let mut f = skeleton(segments, po2, target);
    f.expected = match case {
        "small_control"
        | "largest_seal_control"
        | "max_segments_cycles_control"
        | "near_total_bytes_control"
        | "exact_total_bytes_control" => f.expected,
        "late_last_segment_index" => {
            set32(&mut f.bytes, f.last_index, segments as u32);
            Expected::Malformed("noncanonical segment index")
        }
        "late_last_segment_hash" => {
            f.bytes[f.last_hash + 8] = b'3';
            Expected::Refused("unsupported commitment hash")
        }
        "late_last_segment_cycle" => {
            set32(&mut f.bytes, f.last_po2, 18);
            Expected::Refused("total padded proof-cycle budget")
        }
        "late_last_claim_option" => {
            f.bytes[f.last_output_option] = 2;
            Expected::Malformed("invalid output option")
        }
        "late_outer_assumptions" => {
            set64(&mut f.bytes, f.outer_assumptions, 1);
            Expected::Refused("nested assumption receipts are unsupported")
        }
        "late_outer_journal_length" => {
            set64(&mut f.bytes, f.outer_journal_length, 229);
            Expected::Refused("journal byte budget")
        }
        "late_truncated_metadata" => {
            f.bytes.pop();
            Expected::Malformed("truncated field")
        }
        "late_trailing_byte" => {
            f.bytes.push(0);
            Expected::Malformed("trailing certificate bytes")
        }
        "over_total_bytes" => {
            f.bytes.push(0);
            Expected::Refused("total certificate byte budget")
        }
        "over_segment_count" => {
            set64(&mut f.bytes, 4, bounds::MAX_SEGMENTS as u64 + 1);
            Expected::Refused("segment count budget")
        }
        "over_seal_words" => {
            set64(&mut f.bytes, 12, bounds::MAX_SEAL_WORDS as u64 + 1);
            Expected::Refused("segment seal word budget")
        }
        "over_seal_length_u64max" => {
            set64(&mut f.bytes, 12, u64::MAX);
            Expected::Refused("segment seal word budget")
        }
        "short_last_seal" => {
            set64(&mut f.bytes, f.last_seal_length, (MIN_WORDS - 1) as u64);
            Expected::Malformed("empty or incomplete seal header")
        }
        _ => panic!("unknown fixed case"),
    };
    f
}

#[inline(never)]
fn invoke(bytes: &[u8]) -> Result<bounds::BoundedShape, bounds::BoundaryError> {
    black_box(bounds::preflight(black_box(bytes)))
}
#[inline(never)]
fn empty_control(bytes: &[u8]) -> usize {
    black_box(black_box(bytes).len())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 2, "one fixed case argument required");
    let case = &args[1];
    let construction_start = Instant::now();
    let construction_cpu = cpu_ns();
    begin_counts();
    let f = fixture(case);
    let construction_allocations = end_counts();
    let construction_cpu = cpu_ns() - construction_cpu;
    let construction_wall = construction_start.elapsed().as_nanos();
    emit(&format!(
        "{{\"schema\":\"pon-w1-preflight-boundary-measurement-v1\",\"record\":\"construction\",\"case\":{},\"synthetic_grammar\":true,\"preflight_only\":true,\"sdk_called\":false,\"cryptographic_proof\":false,\"input_bytes\":{},\"input_capacity_bytes\":{},\"wall_ns\":{},\"process_cpu_ns\":{},\"rust_allocations\":{},\"rust_reallocations\":{},\"rust_deallocations\":{},\"requested_allocation_bytes\":{}}}",
        quoted(case),
        f.bytes.len(),
        f.bytes.capacity(),
        construction_wall,
        construction_cpu,
        construction_allocations.allocations,
        construction_allocations.reallocations,
        construction_allocations.deallocations,
        construction_allocations.requested_bytes
    ))?;
    let mut all_passed = true;
    for trial in 0..REPEATS {
        let started = Instant::now();
        let cpu = cpu_ns();
        begin_counts();
        let result = invoke(&f.bytes);
        let counts = end_counts();
        let cpu = cpu_ns() - cpu;
        let wall = started.elapsed().as_nanos();
        let (class, reason, shape) = match &result {
            Ok(shape) => ("shape_admitted_not_verified", "", Some(*shape)),
            Err(bounds::BoundaryError::Refused(reason)) => ("refused_not_evaluated", *reason, None),
            Err(bounds::BoundaryError::Malformed(reason)) => ("malformed_encoding", *reason, None),
        };
        let outcome_matches = match (f.expected, &result) {
            (Expected::Shape(n, cycles, po2), Ok(s)) => {
                (s.segments, s.padded_cycles, s.maximum_po2) == (n, cycles, po2)
            }
            (Expected::Refused(a), Err(bounds::BoundaryError::Refused(b)))
            | (Expected::Malformed(a), Err(bounds::BoundaryError::Malformed(b))) => a == *b,
            _ => false,
        };
        let zero_parser_allocation = counts.allocations == 0
            && counts.reallocations == 0
            && counts.deallocations == 0
            && counts.requested_bytes == 0;
        let passed = outcome_matches && zero_parser_allocation;
        all_passed &= passed;
        let shape = shape.map_or("null".to_owned(), |s| {
            format!(
                "{{\"segments\":{},\"padded_cycles\":{},\"maximum_po2\":{}}}",
                s.segments, s.padded_cycles, s.maximum_po2
            )
        });
        emit(&format!(
            "{{\"schema\":\"pon-w1-preflight-boundary-measurement-v1\",\"record\":\"trial\",\"case\":{},\"trial\":{},\"class\":{},\"reason\":{},\"shape\":{},\"wall_ns\":{},\"process_cpu_ns\":{},\"rust_allocations\":{},\"rust_reallocations\":{},\"rust_deallocations\":{},\"requested_allocation_bytes\":{},\"expected_outcome_matches\":{},\"zero_parser_allocation\":{},\"passed\":{}}}",
            quoted(case),
            trial,
            quoted(class),
            quoted(reason),
            shape,
            wall,
            cpu,
            counts.allocations,
            counts.reallocations,
            counts.deallocations,
            counts.requested_bytes,
            outcome_matches,
            zero_parser_allocation,
            passed
        ))?;
    }
    // Empty-loop reference: keep its raw measurements; never subtract them.
    let empty_start = Instant::now();
    let empty_cpu = cpu_ns();
    begin_counts();
    let mut empty_last = 0;
    for _ in 0..CPU_BATCH_CALLS {
        empty_last = empty_control(&f.bytes);
    }
    let empty_counts = end_counts();
    let empty_cpu = cpu_ns() - empty_cpu;
    let empty_wall = empty_start.elapsed().as_nanos();
    let empty_passed = empty_last == f.bytes.len()
        && empty_counts.allocations == 0
        && empty_counts.reallocations == 0
        && empty_counts.deallocations == 0
        && empty_counts.requested_bytes == 0;
    all_passed &= empty_passed;
    emit(&format!(
        "{{\"schema\":\"pon-w1-preflight-boundary-measurement-v1\",\"record\":\"empty_loop_reference\",\"case\":{},\"calls\":{},\"wall_ns\":{},\"process_cpu_ns\":{},\"rust_allocations\":{},\"rust_reallocations\":{},\"rust_deallocations\":{},\"requested_allocation_bytes\":{},\"passed\":{},\"subtracted_from_parser\":false}}",
        quoted(case),
        CPU_BATCH_CALLS,
        empty_wall,
        empty_cpu,
        empty_counts.allocations,
        empty_counts.reallocations,
        empty_counts.deallocations,
        empty_counts.requested_bytes,
        empty_passed
    ))?;
    // A bounded batch helps expose process-CPU cost when single-call clock
    // deltas quantize to zero. It is not a cold-cache or isolated parser bound.
    let started = Instant::now();
    let cpu = cpu_ns();
    begin_counts();
    let mut last = None;
    for _ in 0..CPU_BATCH_CALLS {
        last = Some(invoke(&f.bytes));
    }
    let counts = end_counts();
    let cpu = cpu_ns() - cpu;
    let wall = started.elapsed().as_nanos();
    let outcome_matches = match (f.expected, last.as_ref().unwrap()) {
        (Expected::Shape(n, cycles, po2), Ok(s)) => {
            (s.segments, s.padded_cycles, s.maximum_po2) == (n, cycles, po2)
        }
        (Expected::Refused(a), Err(bounds::BoundaryError::Refused(b)))
        | (Expected::Malformed(a), Err(bounds::BoundaryError::Malformed(b))) => a == *b,
        _ => false,
    };
    let passed = outcome_matches
        && counts.allocations == 0
        && counts.reallocations == 0
        && counts.deallocations == 0
        && counts.requested_bytes == 0;
    all_passed &= passed;
    emit(&format!(
        "{{\"schema\":\"pon-w1-preflight-boundary-measurement-v1\",\"record\":\"cpu_batch\",\"case\":{},\"calls\":{},\"wall_ns\":{},\"process_cpu_ns\":{},\"rust_allocations\":{},\"rust_reallocations\":{},\"rust_deallocations\":{},\"requested_allocation_bytes\":{},\"expected_outcome_matches\":{},\"passed\":{}}}",
        quoted(case),
        CPU_BATCH_CALLS,
        wall,
        cpu,
        counts.allocations,
        counts.reallocations,
        counts.deallocations,
        counts.requested_bytes,
        outcome_matches,
        passed
    ))?;
    if !all_passed {
        std::process::exit(1);
    }
    Ok(())
}
