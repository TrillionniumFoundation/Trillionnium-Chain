//! Identical temporary component driver for the preregistered source pair.
//! Actual M06 calls run in the original Cargo test profile. No Node admission,
//! Host policy, fixture gate, cache budget or production API is changed here.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{thread, time::Instant};
use trnm_mvcc_fee::{pon_commitment as commitment, pon_executor as executor};
use trnm_protocol::pon_wire::{Hash, StateRootArithmetic, StateRootArithmeticObservation};

const ROWS: usize = 2100;
const WIDTH: usize = 4080;
const ROOT_BUDGET: usize = 2 * 1024 * 1024;
const WARM_CALLS: usize = 8;

struct Stamp {
    thread: thread::ThreadId,
    ns: u64,
}
impl Stamp {
    fn start() -> Option<Self> {
        Some(Self {
            thread: thread::current().id(),
            ns: thread_cpu_ns()?,
        })
    }
    fn finish(self) -> Option<u64> {
        (self.thread == thread::current().id()).then_some(())?;
        thread_cpu_ns()?.checked_sub(self.ns)
    }
}
fn thread_cpu_ns() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let stamp = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let sec = u64::try_from(stamp.tv_sec).ok()?;
    let ns = u64::try_from(stamp.tv_nsec).ok()?;
    if ns >= 1_000_000_000 {
        return None;
    }
    sec.checked_mul(1_000_000_000)?.checked_add(ns)
}
fn timed<T>(action: impl FnOnce() -> T) -> (T, Option<u64>, Option<u64>) {
    let wall = Instant::now();
    let cpu = Stamp::start();
    let actual = action();
    let cpu = cpu.and_then(Stamp::finish);
    let wall = u64::try_from(wall.elapsed().as_nanos()).ok();
    (actual, cpu, wall)
}
fn root_observation(o: StateRootArithmeticObservation) -> Value {
    json!({
        "input_keys": o.input_keys, "leaf_hashes_computed": o.leaf_hashes_computed,
        "exact_string_hits": o.exact_string_hits, "string_encodings_reused": o.string_encodings_reused,
        "reused_partitions": o.reused_partitions, "computed_partitions": o.computed_partitions,
        "retained_payload_bytes": o.retained_payload_bytes,
        "retained_string_entries": o.retained_string_entries,
        "retained_string_charge_bytes": o.retained_string_charge_bytes,
        "retention_refused": o.retention_refused,
    })
}
#[derive(Debug, PartialEq, Eq)]
struct CommitmentSummary {
    root: Hash,
    observation: commitment::CommitmentObservation,
    snapshot: Option<(Hash, usize, usize, usize)>,
    changes: usize,
}
fn commitment_summary(value: &commitment::PreparedCommitment) -> CommitmentSummary {
    CommitmentSummary {
        root: value.root,
        observation: value.observation.clone(),
        snapshot: value.snapshot.as_ref().map(|snapshot| {
            (
                snapshot.root(),
                snapshot.keys(),
                snapshot.payload_bytes(),
                snapshot.retained_charge_bytes(),
            )
        }),
        changes: value.changes.len(),
    }
}
fn commitment_observation(o: &CommitmentSummary) -> Value {
    json!({
        "root": hex::encode(o.root), "method": format!("{:?}", o.observation.method),
        "actual_keys": o.observation.actual_keys,
        "actual_payload_bytes": o.observation.actual_payload_bytes,
        "changed_keys": o.observation.changed_keys,
        "changed_payload_bytes": o.observation.changed_payload_bytes,
        "compressed_nodes": o.observation.compressed_nodes,
        "workspace_charge_bytes": o.observation.workspace_charge_bytes,
        "snapshot_present": o.snapshot.is_some(), "changes": o.changes,
        "arithmetic_retained_charge_bytes": null,
        "arithmetic_charge_reason": "FullRootArithmetic exposes no charge getter; its fixed 2 MiB bound remains unchanged",
    })
}
struct Input {
    state: executor::State,
    digest: String,
    json_bytes: usize,
    root: Result<Hash, &'static str>,
    commitment: Result<CommitmentSummary, &'static str>,
}
fn input(state: executor::State) -> Input {
    let bytes = serde_json::to_vec(&state).unwrap();
    let digest = hex::encode(Sha256::digest(&bytes));
    let root = executor::root(&state);
    let commitment = commitment::derive_snapshot(&state, None, commitment::CacheLimits::default())
        .map(|prepared| commitment_summary(&prepared));
    Input {
        state,
        digest,
        json_bytes: bytes.len(),
        root,
        commitment,
    }
}
fn inputs(case: &str) -> Vec<Input> {
    // Exact count/width/key grammar of the retained M06 large-parent fixture.
    let mut state = executor::State::new();
    for index in 0..ROWS {
        let mut value = "x".repeat(WIDTH);
        match case {
            "repeated" => {}
            "unique" => {
                let marker = format!("{index:08x}");
                value.replace_range(..8, &marker);
                value.replace_range(WIDTH - 8.., &marker);
            }
            "collision" => value.replace_range(WIDTH / 2..WIDTH / 2 + 8, &format!("{index:08x}")),
            _ => panic!("unregistered case"),
        }
        state.insert(format!("root-fallback:{index:05}"), Value::String(value));
    }
    let mut changed = state.clone();
    let mut changed_value = changed["root-fallback:01000"].as_str().unwrap().to_owned();
    changed_value.replace_range(2000..2001, "y");
    changed.insert("root-fallback:01000".into(), Value::String(changed_value));
    let mut values = vec![input(state.clone()), input(changed)];
    if case == "repeated" {
        let mut grammar = state.clone();
        grammar.insert("a".repeat(161), json!("x".repeat(4095)));
        grammar.insert("zz-invalid".into(), json!(-0.0));
        values.push(input(grammar));
        let mut wire = state;
        wire.insert(format!("zz{}", "w".repeat(159)), Value::Null);
        values.push(input(wire));
        assert_eq!(values[2].root, Err("RANGE"));
        assert_eq!(values[3].root, Err("LIMIT"));
    }
    for value in &values[..2] {
        let expected = value.commitment.as_ref().unwrap();
        assert_eq!(
            expected.observation.method,
            commitment::CommitmentMethod::FullRoot(commitment::FullRootReason::PayloadBudget)
        );
        assert!(expected.observation.actual_payload_bytes > 8 * 1024 * 1024);
        assert!(expected.snapshot.is_none());
        assert_eq!(Some(expected.root), value.root.ok());
    }
    assert_ne!(values[0].root, values[1].root);
    values
}
fn calls(case: &str) -> Vec<(&'static str, usize, usize)> {
    let mut calls = vec![("cold", 0, 0)];
    calls.extend((0..WARM_CALLS).map(|index| ("warm", index, 0)));
    calls.extend([("changed", 0, 1), ("restored", 0, 0)]);
    if case == "repeated" {
        calls.extend([("late_grammar", 0, 2), ("late_wire", 0, 3)]);
    }
    calls
}
fn emit(kind: &str, row: Value) {
    println!("VALUE_POOL_{kind} {}", serde_json::to_string(&row).unwrap());
}

#[test]
#[ignore = "fixed five-pair component campaign; invoked only by the frozen runner"]
fn value_pool_component_registered() {
    let pair: usize = std::env::var("TRNM_VALUE_POOL_PAIR")
        .unwrap()
        .parse()
        .unwrap();
    let variant = std::env::var("TRNM_VALUE_POOL_VARIANT").unwrap();
    assert!(pair < 5 && matches!(variant.as_str(), "baseline" | "candidate"));
    let mut valid = true;
    let mut rows = 0;
    emit(
        "BEGIN",
        json!({"pair":pair,"variant":variant,"rows":ROWS,"width":WIDTH,
        "root_budget":ROOT_BUDGET,"warm_calls":WARM_CALLS,"planned_samples":70,
        "clock":"actual Linux calling thread; unknown remains null",
        "cold":"empty arithmetic owner after common input/reference/empty-hash-table setup; not an OS cold start",
        "timer":"actual complete API call; original encoder/hash/fallback inside; validation, returned-value destruction and logging outside",
        "scope":"component only; no CPU gate, service, SQL, Host check or confirmation claim"}),
    );
    for case in ["repeated", "unique", "collision"] {
        let (inputs, cpu, wall) = timed(|| inputs(case));
        valid &= cpu.is_some() && wall.is_some();
        emit(
            "SETUP",
            json!({"pair":pair,"variant":variant,"case":case,"cpu_ns":cpu,"wall_ns":wall,
            "inputs":inputs.iter().map(|value| json!({"digest":value.digest,"json_bytes":value.json_bytes,
                "expected_root":value.root.ok().map(hex::encode),"expected_error":value.root.err()})).collect::<Vec<_>>(),
            "scope":"input construction and independent original root/derive references; outside all operation samples"}),
        );
        let mut arithmetic = StateRootArithmetic::new(ROOT_BUDGET);
        for (phase, index, which) in calls(case) {
            let input = &inputs[which];
            let before = arithmetic.observation();
            let (actual, cpu, wall) =
                timed(|| executor::root_with_arithmetic(&input.state, &mut arithmetic));
            let after = arithmetic.observation();
            let unchanged_on_error = actual.is_ok() || before == after;
            let matches_reference = actual == input.root;
            let budget_ok = after.retained_payload_bytes <= ROOT_BUDGET;
            valid &= matches_reference
                && budget_ok
                && unchanged_on_error
                && cpu.is_some()
                && wall.is_some();
            rows += 1;
            emit(
                "SAMPLE",
                json!({"pair":pair,"variant":variant,"case":case,"api":"root","phase":phase,"index":index,
                "input_digest":input.digest,"cpu_ns":cpu,"wall_ns":wall,
                "root":actual.ok().map(hex::encode),"error":actual.err(),"matches_reference":matches_reference,
                "budget_ok":budget_ok,"unchanged_on_error":unchanged_on_error,
                "before":root_observation(before),"after":root_observation(after)}),
            );
        }
        let arithmetic = commitment::FullRootArithmetic::default();
        for (phase, index, which) in calls(case) {
            let input = &inputs[which];
            let (actual, cpu, wall) = timed(|| {
                commitment::derive_snapshot_with_arithmetic(
                    &input.state,
                    None,
                    commitment::CacheLimits::default(),
                    &arithmetic,
                )
            });
            let summary = actual
                .as_ref()
                .map(commitment_summary)
                .map_err(|error| *error);
            let matches_reference = summary == input.commitment;
            valid &= matches_reference && cpu.is_some() && wall.is_some();
            rows += 1;
            emit(
                "SAMPLE",
                json!({"pair":pair,"variant":variant,"case":case,"api":"commitment","phase":phase,"index":index,
                "input_digest":input.digest,"cpu_ns":cpu,"wall_ns":wall,"matches_reference":matches_reference,
                "root":summary.as_ref().ok().map(|value| hex::encode(value.root)),"error":summary.as_ref().err(),
                "commitment":summary.as_ref().ok().map(commitment_observation),
                "before":null,"after":null,"unchanged_on_error":null,
                "private_observation_reason":"public FullRootArithmetic exposes no material observer; existing semantic controls test this boundary"}),
            );
        }
    }
    let memory = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmHWM:"))
                .map(str::to_owned)
        });
    emit(
        "END",
        json!({"pair":pair,"variant":variant,"samples":rows,"valid":valid,
        "process_peak_rss":memory,"rss_scope":"whole test process, includes common setup/reference, allocator and temporary workspace; not retained charge"}),
    );
    assert_eq!(rows, 70);
    assert!(
        valid,
        "all failed/unknown observations were emitted; no retry or sample exclusion"
    );
}
