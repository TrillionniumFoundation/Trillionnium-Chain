#!/usr/bin/env python3
"""Build a finite scan-only observation from exact old/current Rust functions.

This is not Node admission, resource-fairness or end-to-end confirmation evidence.
This script does not execute the Node call graph; that validation requires a
separate native test run. Two binaries keep the counting allocator out of timing
observations. All paired samples are retained; no favorable-sample selection or
threshold change is performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def section(text, start, end):
    assert text.count(start) == 1, start
    return text.split(start, 1)[1].split(end, 1)[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--native-dir", type=Path, action="append", default=[])
    parser.add_argument("--base", default="d0737cf5434894ce47fad8082376fc417313c2cb")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    relative = "trillionnium/crates/trnm-pon-node/src/store/detached_admission.rs"
    current = (args.repo / relative).read_text()
    old = subprocess.check_output(["git", "show", f"{args.base}:{relative}"], cwd=args.repo, text=True)
    function_start = "fn payload_bytes("
    original = function_start + section(old, function_start, "\nimpl Node {")
    original = original.replace("fn payload_bytes(", "fn buffered_payload_bytes(", 1)
    current_start = "/// Count the original serde_json wire"
    selected = current_start + section(current, current_start, "\nimpl Node {")
    enum_start = "#[derive(Debug, PartialEq, Eq)]\nenum SnapshotPayload {"
    enum = enum_start + section(current, enum_start, "\n\n/// No Clone")
    store = (args.repo / "trillionnium/crates/trnm-pon-node/src/store.rs").read_text()
    canonical_start = "fn canonical<T: Serialize>("
    canonical = canonical_start + section(store, canonical_start, "\npub(crate) type Delta")
    error_path = args.repo / "trillionnium/crates/trnm-pon-node/src/error.rs"
    header = "\n".join([
        "#![allow(dead_code)]",
        f"#[path = {json.dumps(str(error_path))}] mod error;",
        "use error::Error;",
        "use serde::Serialize;",
        "use serde_json::json;",
        "use trnm_mvcc_fee::pon_executor::{State, ExecutionControl, ExecutionProgress};",
        "use std::sync::atomic::{AtomicU64, Ordering};",
        "use std::time::Instant;",
        "type Result<T> = std::result::Result<T, Error>;",
        "const MAX_SNAPSHOT_PAYLOAD: usize = trnm_mvcc_fee::pon_commitment::MAX_CACHE_PAYLOAD_BYTES;",
    ])
    harness = header + "\n" + enum + "\n" + canonical + "\n" + selected + "\n" + original + r'''

#[cfg(allocation_observer)]
mod allocation {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    struct Meter;
    static ENABLED: AtomicBool = AtomicBool::new(false);
    static ALLOCS: AtomicU64 = AtomicU64::new(0);
    static REALLOCS: AtomicU64 = AtomicU64::new(0);
    static DEALLOCS: AtomicU64 = AtomicU64::new(0);
    static REQUESTED: AtomicU64 = AtomicU64::new(0);
    static REALLOC_REQUESTED: AtomicU64 = AtomicU64::new(0);
    // Forward every pointer and exact Layout to System. Atomic observations
    // allocate nothing. The finite scanner starts no additional threads.
    unsafe impl GlobalAlloc for Meter {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if ENABLED.load(Ordering::Relaxed) {
                ALLOCS.fetch_add(1, Ordering::Relaxed);
                REQUESTED.fetch_add(layout.size() as u64, Ordering::Relaxed);
            }
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            if ENABLED.load(Ordering::Relaxed) {
                ALLOCS.fetch_add(1, Ordering::Relaxed);
                REQUESTED.fetch_add(layout.size() as u64, Ordering::Relaxed);
            }
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            if ENABLED.load(Ordering::Relaxed) {
                DEALLOCS.fetch_add(1, Ordering::Relaxed);
            }
            unsafe { System.dealloc(pointer, layout) }
        }
        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            if ENABLED.load(Ordering::Relaxed) {
                REALLOCS.fetch_add(1, Ordering::Relaxed);
                REALLOC_REQUESTED.fetch_add(size as u64, Ordering::Relaxed);
            }
            unsafe { System.realloc(pointer, layout, size) }
        }
    }
    #[global_allocator]
    static ALLOCATOR: Meter = Meter;
    pub fn begin() {
        for count in [&ALLOCS, &REALLOCS, &DEALLOCS, &REQUESTED, &REALLOC_REQUESTED] {
            count.store(0, Ordering::Relaxed);
        }
        ENABLED.store(true, Ordering::Relaxed);
    }
    pub fn end() -> Option<[u64; 5]> {
        ENABLED.store(false, Ordering::Relaxed);
        Some([&ALLOCS, &REALLOCS, &DEALLOCS, &REQUESTED, &REALLOC_REQUESTED]
            .map(|count| count.load(Ordering::Relaxed)))
    }
}
#[cfg(not(allocation_observer))]
mod allocation {
    pub fn begin() {}
    pub fn end() -> Option<[u64; 5]> { None }
}

type Scan = fn(&State, &ExecutionControl<'_, Error>) -> Result<SnapshotPayload>;
fn sample(scan: Scan, state: &State, repeats: u64, expected: &SnapshotPayload) -> serde_json::Value {
    let calls = AtomicU64::new(0);
    let progress = |_| { calls.fetch_add(1, Ordering::Relaxed); Ok(()) };
    let control = ExecutionControl::new(&progress, &());
    let started = Instant::now();
    allocation::begin();
    for _ in 0..repeats {
        let result = scan(std::hint::black_box(state), &control).unwrap();
        assert_eq!(std::hint::black_box(&result), expected);
    }
    let allocations = allocation::end();
    let elapsed = started.elapsed().as_nanos();
    json!({
        "schema":"detached-payload-scan-sample-v1",
        "repeats":repeats,
        "wall_ns": if cfg!(allocation_observer) { None } else { Some(elapsed) },
        "allocator_calls":allocations,
        "allocator_columns":["alloc_calls","realloc_calls","dealloc_calls","alloc_requested_bytes","realloc_requested_bytes"],
        "progress_callbacks":calls.load(Ordering::Relaxed),
        "original_classification_and_count_equal":true,
    })
}

fn main() {
    println!("{}", json!({
        "schema":"detached-payload-scan-scope-v1",
        "scope":"exact production scan function and original buffered function, using actual M06 State/ExecutionControl and Node Error types; generated account-like Values, no Node/SQL/Host/native ingress execution",
        "allocator_observer":cfg!(allocation_observer),
        "timing_binary_has_custom_allocator":false,
        "warmup_scans_per_arm":4,"paired_rounds":32,
        "order":"alternate buffered/counted within every pair",
        "memory_scope":"requested allocator traffic within scan, not live heap/physical copies/RSS",
        "threshold_bytes":MAX_SNAPSHOT_PAYLOAD,"callbacks":"same original every-256 entries",
        "source_functions":"mechanically extracted and digest bound in manifest.json",
        "four_second_gate_qualified":false,"asymptotic_gate_qualified":false,"production_activation":false,
    }));
    let cases = [
        ("account64",64,64,"account"),
        ("account1024",1024,32,"account"),
        ("escaped1024",1024,16,"escaped"),
        ("large2048",2048,4,"large"),
    ];
    for (case, size, repeats, kind) in cases {
        let mut state = State::new();
        for index in 0..size {
            let key = if kind == "account" { format!("account:{index:064x}") }
                else { format!("data:{index:06}") };
            let value = match kind {
                "account" => json!({"nonce":index,"balance":123456789_u64}),
                "escaped" => json!({"z": [true, null, index], "a": "\"\\\n\t\u{0000}日本語é🦀".repeat(32)}),
                "large" => json!("x".repeat(4094)),
                _ => unreachable!(),
            };
            state.insert(key, value);
        }
        let control = ExecutionControl::new(&|_| Ok(()), &());
        let expected = buffered_payload_bytes(&state, &control).unwrap();
        assert_eq!(payload_bytes(&state, &control).unwrap(), expected);
        for _ in 0..4 {
            std::hint::black_box(buffered_payload_bytes(&state, &control).unwrap());
            std::hint::black_box(payload_bytes(&state, &control).unwrap());
        }
        for pair in 0..32 {
            let arms = if pair % 2 == 0 { [("buffered", buffered_payload_bytes as Scan), ("counted", payload_bytes as Scan)] }
                else { [("counted", payload_bytes as Scan), ("buffered", buffered_payload_bytes as Scan)] };
            for (arm, scan) in arms {
                let mut row = sample(scan, &state, repeats, &expected);
                row["case"] = json!(case);
                row["keys"] = json!(state.len());
                row["pair"] = json!(pair);
                row["arm"] = json!(arm);
                row["first_arm"] = json!(if pair % 2 == 0 {"buffered"} else {"counted"});
                row["classification"] = json!(match expected {SnapshotPayload::Fits(_) => "fits", SnapshotPayload::HeldRequired {..} => "held-required"});
                row["observed_payload_bytes"] = json!(match expected {SnapshotPayload::Fits(n) => n, SnapshotPayload::HeldRequired { observed_bytes } => observed_bytes});
                println!("{row}");
            }
        }
    }
}
'''
    source = args.output / "snapshot_payload_scan.rs"
    source.write_text(harness)
    deps = args.target / "debug/deps"
    libraries = {}
    for name in ("serde", "serde_json", "trnm_mvcc_fee", "trnm_transport", "rusqlite"):
        candidates = list(deps.glob(f"lib{name}-*.rlib"))
        if len(candidates) != 1:
            raise RuntimeError(f"Expected one exact {name} dependency, found {candidates}")
        libraries[name] = candidates[0]
    manifest = {
        "schema":"detached-payload-scan-manifest-v1", "base":args.base,
        "current_source_sha256":hashlib.sha256(current.encode()).hexdigest(),
        "selected_function_sha256":hashlib.sha256(selected.encode()).hexdigest(),
        "original_buffered_function_sha256":hashlib.sha256(original.encode()).hexdigest(),
        "harness_sha256":hashlib.sha256(harness.encode()).hexdigest(),
        "original_node_error_sha256":hashlib.sha256(error_path.read_bytes()).hexdigest(),
        "rustc":subprocess.check_output([str(args.rustc),"--version","--verbose"],text=True),
        "dependencies":{name:{"path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()} for name,path in libraries.items()},
        "runs":[],
    }
    common = [str(args.rustc),"--edition=2021","-Copt-level=3","-Cdebug-assertions=yes","-Coverflow-checks=yes","-L",f"dependency={deps}"]
    for name,path in libraries.items():
        common += ["--extern",f"{name}={path}"]
    for native in sorted((args.target / "debug/build").glob("*/out")):
        common += ["-L",f"native={native}"]
    for native in args.native_dir:
        common += ["-L",f"native={native}"]
    (args.output / "manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    for kind in ("allocation", "timing"):
        binary = args.output / f"snapshot-payload-{kind}"
        command = common + (["--cfg","allocation_observer"] if kind == "allocation" else []) + [str(source),"-o",str(binary)]
        compiled = subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        (args.output / f"{kind}-compile.log").write_text(compiled.stdout)
        run = {"kind":kind,"command":command,"compile_exit":compiled.returncode}
        manifest["runs"].append(run)
        (args.output / "manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
        compiled.check_returncode()
        run["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        with (args.output / f"{kind}-samples.jsonl").open("w") as out:
            executed = subprocess.run([str(binary)],stdout=out,stderr=subprocess.PIPE,text=True)
        (args.output / f"{kind}-run.stderr").write_text(executed.stderr)
        run["run_exit"] = executed.returncode
        (args.output / "manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
        executed.check_returncode()
    print(json.dumps({"result":"completed","manifest":str(args.output / "manifest.json")}))


if __name__ == "__main__":
    main()
