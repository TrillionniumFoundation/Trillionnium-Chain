//! Bounded persistent canonical-JSON transport for the grouped research relation.
//! No sockets, mining, model training, demand authentication or runtime activation.
#![recursion_limit = "256"]
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    hint::black_box,
    io::{self, BufRead, Write},
    time::Instant,
};
use trnm_crypto_primitives::{
    decode_hash32,
    pon_routed_int257_grouped::{
        Context, Matrix, Model, PreparedBatch, PreparedModel, Request, CLASSES, DIM, EXPERTS,
        MAX_BATCH, PROFILE,
    },
};
const SCHEMA: &str = "pon-routed-int257-grouped-session-v0";
const MAX_LINE_BYTES: usize = 256 * 1024;
const MAX_BATCH_COMMANDS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KernelArm {
    Ordinary,
    Selected,
    Packed,
}
impl KernelArm {
    fn label(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Selected => "selected",
            Self::Packed => "packed",
        }
    }
}
// A=ordinary, B=direct selected Product, C=packed grouped Product. Every
// complete six-sample cycle visits all permutations. A partial cycle is exposed
// in the response; it is not described as exactly balanced.
const KERNEL_SAMPLE_ORDERS: [[KernelArm; 3]; 6] = {
    use KernelArm::{Ordinary as A, Packed as C, Selected as B};
    [
        [A, B, C],
        [C, B, A],
        [B, C, A],
        [A, C, B],
        [C, A, B],
        [B, A, C],
    ]
};
type Result<T> = std::result::Result<T, String>;
fn elapsed(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).expect("bounded elapsed ns")
}
#[cfg(target_os = "linux")]
fn cpu_ns() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let t = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    u64::try_from(t.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(t.tv_nsec).ok()?)
}
#[cfg(not(target_os = "linux"))]
fn cpu_ns() -> Option<u64> {
    None
}
fn fields<'a>(value: &'a Value, expected: &[&str]) -> Result<&'a Map<String, Value>> {
    let map = value.as_object().ok_or("OBJECT_REQUIRED")?;
    if map.len() != expected.len() || expected.iter().any(|name| !map.contains_key(*name)) {
        return Err("EXACT_FIELDS".into());
    }
    Ok(map)
}
fn hash(value: &Value) -> Result<[u8; 32]> {
    decode_hash32("hash", value.as_str().ok_or("HASH_STRING")?).map_err(|e| e.to_string())
}
fn uint(value: &Value) -> Result<u64> {
    value.as_u64().ok_or_else(|| "UNSIGNED_INTEGER".into())
}
fn array(value: &Value, length: usize) -> Result<&Vec<Value>> {
    let values = value.as_array().ok_or("ARRAY_REQUIRED")?;
    if values.len() != length {
        return Err("ARRAY_LENGTH".into());
    }
    Ok(values)
}
fn vector(value: &Value) -> Result<[i32; DIM]> {
    let values = array(value, DIM)?;
    let mut output = [0; DIM];
    for (out, value) in output.iter_mut().zip(values) {
        *out = i32::try_from(value.as_i64().ok_or("SIGNED_INTEGER")?).map_err(|_| "SIGNED_I32")?;
    }
    Ok(output)
}
fn matrix(value: &Value) -> Result<Matrix> {
    let values = array(value, CLASSES)?;
    let mut output = [[0; DIM]; CLASSES];
    for (out, row) in output.iter_mut().zip(values) {
        *out = vector(row)?;
    }
    Ok(output)
}
fn model(value: &Value) -> Result<Model> {
    let m = fields(
        value,
        &["type", "model_version", "base", "router", "deltas"],
    )?;
    if m["type"] != "init" {
        return Err("INIT_REQUIRED".into());
    }
    let deltas = array(&m["deltas"], EXPERTS)?;
    let mut ds = [[[0; DIM]; CLASSES]; EXPERTS];
    for (out, delta) in ds.iter_mut().zip(deltas) {
        *out = matrix(delta)?;
    }
    Ok(Model {
        version: hash(&m["model_version"])?,
        base: matrix(&m["base"])?,
        router: matrix(&m["router"])?,
        deltas: ds,
    })
}
struct Batch {
    context: Context,
    requests: Vec<Request>,
    now_ns: u64,
    samples: usize,
    warmup: usize,
}
fn batch(value: &Value) -> Result<Batch> {
    let b = fields(
        value,
        &["type", "context", "requests", "now_ns", "samples", "warmup"],
    )?;
    if b["type"] != "batch" {
        return Err("BATCH_REQUIRED".into());
    }
    let c = fields(&b["context"], &["chain", "parent", "challenge", "batch_id"])?;
    let context = Context {
        chain: hash(&c["chain"])?,
        parent: hash(&c["parent"])?,
        challenge: hash(&c["challenge"])?,
        batch_id: hash(&c["batch_id"])?,
    };
    let rs = b["requests"].as_array().ok_or("REQUEST_ARRAY")?;
    if rs.is_empty() || rs.len() > MAX_BATCH {
        return Err("BATCH_SIZE".into());
    }
    let mut requests = Vec::with_capacity(rs.len());
    for r in rs {
        let r = fields(r, &["id", "scope", "arrival_ns", "deadline_ns", "x"])?;
        requests.push(Request {
            id: hash(&r["id"])?,
            scope: hash(&r["scope"])?,
            arrival_ns: uint(&r["arrival_ns"])?,
            deadline_ns: uint(&r["deadline_ns"])?,
            x: vector(&r["x"])?,
        });
    }
    let samples = uint(&b["samples"])?;
    let warmup = uint(&b["warmup"])?;
    if samples == 0 || samples > 10_000 || warmup > 1000 {
        return Err("SAMPLE_BOUND".into());
    }
    Ok(Batch {
        context,
        requests,
        now_ns: uint(&b["now_ns"])?,
        samples: samples as usize,
        warmup: warmup as usize,
    })
}
/// Read at most the fixed line allowance; read_until without take would allocate
/// an attacker-controlled line before this check. EOF mid-frame is rejected.
fn read_frame(input: &mut impl BufRead) -> Result<Option<Value>> {
    let mut line = Vec::new();
    loop {
        let available = input.fill_buf().map_err(|e| e.to_string())?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Err("UNTERMINATED_FRAME".into());
        }
        let chunk = available
            .iter()
            .position(|&b| b == b'\n')
            .map_or(available.len(), |n| n + 1);
        if line.len() + chunk > MAX_LINE_BYTES {
            return Err("FRAME_BYTE_BOUND".into());
        }
        let done = available[chunk - 1] == b'\n';
        line.extend_from_slice(&available[..chunk]);
        input.consume(chunk);
        if done {
            break;
        }
    }
    line.pop();
    let value: Value = serde_json::from_slice(&line).map_err(|e| e.to_string())?;
    if serde_json::to_vec(&value).map_err(|e| e.to_string())? != line {
        return Err("CANONICAL_JSON_REQUIRED".into());
    }
    Ok(Some(value))
}
fn output(out: &mut impl Write, value: &Value) -> Result<()> {
    serde_json::to_writer(&mut *out, value).map_err(|e| e.to_string())?;
    out.write_all(b"\n")
        .and_then(|_| out.flush())
        .map_err(|e| e.to_string())
}
fn measure<T>(
    operation: impl FnOnce() -> std::result::Result<T, &'static str>,
) -> Result<(T, u64)> {
    let start = Instant::now();
    let value = black_box(operation().map_err(str::to_owned)?);
    Ok((value, elapsed(start)))
}
fn measure_kernels(
    prepared: &PreparedModel,
    batch: &PreparedBatch,
    sample_index: usize,
) -> Result<[u64; 3]> {
    let mut durations = [0; 3];
    for arm in KERNEL_SAMPLE_ORDERS[sample_index % KERNEL_SAMPLE_ORDERS.len()] {
        durations[arm as usize] = match arm {
            KernelArm::Ordinary => measure(|| prepared.ordinary(batch))?.1,
            KernelArm::Selected => measure(|| prepared.direct(batch))?.1,
            KernelArm::Packed => measure(|| prepared.grouped(batch))?.1,
        };
    }
    Ok(durations)
}
fn completion_clock(batch: &Batch, elapsed_ns: u64, deadline_error: &str) -> Result<u64> {
    let now = batch
        .now_ns
        .checked_add(elapsed_ns)
        .ok_or("CLOCK_OVERFLOW")?;
    if batch.requests.iter().any(|r| now >= r.deadline_ns) {
        return Err(deadline_error.into());
    }
    Ok(now)
}
fn run_batch(
    prepared: &PreparedModel,
    value: &Value,
    handler: Instant,
    cpu_start: Option<u64>,
) -> Result<Value> {
    let batch = batch(value)?;
    let (prepared_batch, preparation) = prepared
        .prepare_batch(&batch.context, &batch.requests, batch.now_ns)
        .map_err(str::to_owned)?;
    // First calls in one prepared process, before explicit warmup. They share
    // caches and run ordinary -> packed -> selected, not isolated cold starts.
    let (ordinary, cold_baseline_ns) = measure(|| prepared.ordinary(&prepared_batch))?;
    let ((claim, phase), cold_grouped_ns) = measure(|| prepared.observe(&prepared_batch))?;
    let verify_start = Instant::now();
    let verification_now = batch
        .now_ns
        .checked_add(elapsed(handler))
        .ok_or("CLOCK_OVERFLOW")?;
    let verified = prepared
        .verify(&batch.context, &batch.requests, verification_now, &claim)
        .map_err(str::to_owned)?;
    let verify_ns = elapsed(verify_start);
    let verified_product_ready_now_ns =
        completion_clock(&batch, elapsed(handler), "COMPLETION_DEADLINE")?;
    let product = verified.product();
    if ordinary.routes != product.routes
        || ordinary.logits != product.logits
        || ordinary.predictions != product.predictions
    {
        return Err("ORDINARY_DIFFERENTIAL".into());
    }

    // Measure one complete direct relation from fresh batch preparation. This
    // includes input validation/commitment/copy, execution, output commitment
    // and independent verification. Model preparation remains a separate cost.
    let selected_start = Instant::now();
    let selected_cpu_start = cpu_ns();
    let selected_preparation_now =
        completion_clock(&batch, elapsed(handler), "SELECTED_INPUT_DEADLINE")?;
    let (selected_batch, selected_preparation) = prepared
        .prepare_batch(&batch.context, &batch.requests, selected_preparation_now)
        .map_err(str::to_owned)?;
    let ((selected_claim, selected_phase), cold_selected_with_statement_ns) =
        measure(|| prepared.observe_direct(&selected_batch))?;
    let selected_verify_start = Instant::now();
    let selected_verification_now =
        completion_clock(&batch, elapsed(handler), "SELECTED_VERIFY_DEADLINE")?;
    let selected_verified = prepared
        .verify(
            &batch.context,
            &batch.requests,
            selected_verification_now,
            &selected_claim,
        )
        .map_err(str::to_owned)?;
    let selected_verify_ns = elapsed(selected_verify_start);
    let selected_verified_product_ready_now_ns =
        completion_clock(&batch, elapsed(handler), "SELECTED_COMPLETION_DEADLINE")?;
    let selected_producer_with_verify_cpu_ns =
        selected_cpu_start.and_then(|start| cpu_ns()?.checked_sub(start));
    let selected_producer_with_verify_wall_ns = elapsed(selected_start);
    if selected_claim != claim
        || selected_verified.statement_commitment() != verified.statement_commitment()
        || selected_verified.product() != product
    {
        return Err("PRODUCER_DIFFERENTIAL".into());
    }

    for index in 0..batch.warmup {
        black_box(measure_kernels(prepared, &prepared_batch, index)?);
    }
    let mut baseline_ns = Vec::with_capacity(batch.samples);
    let mut selected_ns = Vec::with_capacity(batch.samples);
    let mut grouped_ns = Vec::with_capacity(batch.samples);
    // Actual execution follows the disclosed six-permutation cycle, including
    // the final incomplete cycle when samples is not divisible by six.
    for index in 0..batch.samples {
        let [baseline, selected, grouped] = measure_kernels(prepared, &prepared_batch, index)?;
        baseline_ns.push(baseline);
        selected_ns.push(selected);
        grouped_ns.push(grouped);
    }
    // The diagnostic repetitions are still charged to response readiness.
    // A timely early kernel cannot hide a late eventual response.
    let completion_now_ns = completion_clock(&batch, elapsed(handler), "RESPONSE_READY_DEADLINE")?;
    let handler_cpu_ns = cpu_start.and_then(|start| cpu_ns()?.checked_sub(start));
    Ok(json!({"type":"batch","schema":SCHEMA,"profile":PROFILE,
        "model_commitment":hex::encode(claim.model_commitment),"input_commitment":hex::encode(claim.input_commitment),
        "statement_commitment":hex::encode(verified.statement_commitment()),"router_outputs":product.router_outputs,
        "routes":product.routes,"groups":product.groups,"logits":product.logits,"predictions":product.predictions,
        "useful_dense_macs":product.useful_dense_macs,"padded_macs":product.padded_macs,"nonempty_expert_groups":product.nonempty_expert_groups,
        "phase_ns":{"validation":preparation.validation,"input_commitment":preparation.input_commitment,"router":phase.router,
            "gather":phase.gather,"expert":phase.expert,"statement_commitment":phase.statement_commitment,"verify":verify_ns},
        "selected_phase_ns":{"validation":selected_preparation.validation,"input_commitment":selected_preparation.input_commitment,
            "execution":selected_phase.execution,"statement_commitment":selected_phase.statement_commitment,"verify":selected_verify_ns},
        "selected_statement_commitment":hex::encode(selected_verified.statement_commitment()),
        "selected_statement_matches_packed":true,"selected_semantic_verified":true,
        "selected_producer_with_verify_wall_ns":selected_producer_with_verify_wall_ns,
        "selected_producer_with_verify_cpu_ns":selected_producer_with_verify_cpu_ns,
        "selected_producer_with_verify_scope":"prepared_model_fresh_batch_input_commit_selected_statement_full_verify",
        "cold_baseline_ns":cold_baseline_ns,"cold_grouped_ns":cold_grouped_ns,
        "cold_selected_with_statement_ns":cold_selected_with_statement_ns,
        "first_call_scope":"ordinary, packed, then selected in one prepared process sharing caches; not isolated cold starts",
        "baseline_ns":baseline_ns,"selected_ns":selected_ns,"grouped_ns":grouped_ns,
        "kernel_sample_order_cycle":KERNEL_SAMPLE_ORDERS.map(|order| order.map(KernelArm::label)),
        "kernel_sample_complete_cycles":batch.samples / KERNEL_SAMPLE_ORDERS.len(),
        "kernel_sample_partial_cycle_samples":batch.samples % KERNEL_SAMPLE_ORDERS.len(),
        "handler_wall_ns":elapsed(handler),"handler_cpu_ns":handler_cpu_ns,"completion_now_ns":completion_now_ns,"verified_product_ready_now_ns":verified_product_ready_now_ns,
        "selected_verified_product_ready_now_ns":selected_verified_product_ready_now_ns,
        "timing_scope":"wall kernel samples: ordinary outputs only, selected direct relation Product, packed gathered relation Product; packed includes three internal Instant phase probes for router/gather/expert, ordinary and selected have no internal phase probes; ratios compare current implementations, not pure packing overhead; hot kernels exclude commitments and full verification; handler includes both fresh batch preparations, both producers and verifiers, typed parsing, identity checks and all repeated work, excludes JSON frame parsing and response serialization",
        "deadline_scope":"caller logical clock plus actual handler elapsed through benchmark and verification, checked again after serialization immediately before write; source timestamps unauthenticated; pipe delivery requires supervisor clock",
        "response_deadline_checked_before_write":true,"distinct_application_batches":null,"benchmark_only":true,"business_credit":0,"semantic_verified":true,"pow_qualified":false,"production_activation":false,
        "public_reward_eligible":false,"model_reward":0,"real_demand_verified":false}))
}
fn run(input: &mut impl BufRead, out: &mut impl Write) -> Result<()> {
    let init = read_frame(input)?.ok_or("INIT_REQUIRED")?;
    let start = Instant::now();
    let prepared = PreparedModel::new(model(&init)?).map_err(str::to_owned)?;
    output(
        out,
        &json!({"type":"prepared","schema":SCHEMA,"profile":PROFILE,"model_commitment":hex::encode(prepared.commitment()),
        "preparation_ns":elapsed(start),"production_activation":false,"pow_qualified":false}),
    )?;
    let mut batches = 0;
    let mut ids = BTreeSet::new();
    let mut requests_seen = BTreeMap::new();
    while let Some(value) = read_frame(input)? {
        batches += 1;
        if batches > MAX_BATCH_COMMANDS {
            return Err("SESSION_BATCH_BOUND".into());
        }
        let handler = Instant::now();
        let cpu_start = cpu_ns();
        let parsed = batch(&value)?;
        if !ids.insert(parsed.context.batch_id) {
            return Err("DUPLICATE_BATCH_ID".into());
        }
        let mut new_request_ids = 0;
        for request in &parsed.requests {
            match requests_seen.get(&request.id) {
                Some(previous) if previous != request => return Err("REQUEST_ID_REBOUND".into()),
                Some(_) => (),
                None => {
                    new_request_ids += 1;
                }
            }
        }
        let mut result = run_batch(&prepared, &value, handler, cpu_start)?;
        for request in &parsed.requests {
            requests_seen.insert(request.id, request.clone());
        }
        result["new_request_ids_in_session"] = json!(new_request_ids);
        result["unique_request_ids_in_session"] = json!(requests_seen.len());
        // Unique opaque IDs are observable, but do not authenticate demand.
        // Charge serialization and session bookkeeping before the final native
        // handoff. The supervisor must still time pipe transit and consumption.
        let mut response = serde_json::to_vec(&result).map_err(|e| e.to_string())?;
        response.push(b'\n');
        completion_clock(&parsed, elapsed(handler), "BEFORE_WRITE_DEADLINE")?;
        out.write_all(&response)
            .and_then(|_| out.flush())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn main() {
    if std::env::args().collect::<Vec<_>>().get(1..) != Some(&["--grouped-research-v0".to_string()])
    {
        eprintln!("GROUPED_RESEARCH_SELECTOR");
        std::process::exit(2);
    }
    if let Err(error) = run(&mut io::stdin().lock(), &mut io::stdout().lock()) {
        eprintln!("grouped research refused: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(v: Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&v).unwrap();
        bytes.push(b'\n');
        bytes
    }
    #[test]
    fn transport_rejects_duplicate_keys_noncanonical_and_truncation() {
        for bytes in [
            b"{\"x\":1,\"x\":2}\n".as_slice(),
            b"{ \"x\":1}\n",
            b"{\"x\":1}",
            b"{\"x\":1.0}\n",
        ] {
            // Floating-point spelling is rejected by integer extraction below,
            // canonical JSON itself may retain a canonical float spelling.
            let result = read_frame(&mut io::Cursor::new(bytes));
            if bytes == b"{\"x\":1.0}\n" {
                assert!(uint(&result.unwrap().unwrap()["x"]).is_err());
            } else {
                assert!(result.is_err());
            }
        }
        assert!(read_frame(&mut io::Cursor::new(vec![b' '; MAX_LINE_BYTES + 1])).is_err());
    }
    #[test]
    fn typed_fields_refuse_bool_overflow_extra_and_bad_hash() {
        assert!(uint(&json!(true)).is_err());
        assert!(uint(&json!(-1)).is_err());
        assert!(hash(&json!("AA".repeat(32))).is_err());
        assert!(fields(&json!({"x":1,"y":2}), &["x"]).is_err());
        let mut vector_value = vec![json!(0); DIM];
        vector_value[0] = json!(i64::MAX);
        assert!(vector(&json!(vector_value)).is_err());
    }
    fn init() -> Value {
        let m = vec![vec![0_i32; DIM]; CLASSES];
        json!({"type":"init","model_version":"11".repeat(32),
            "base":m,"router":m,"deltas":[m,m,m]})
    }
    fn command(batch_id: usize) -> Value {
        let mut x = vec![0_i32; DIM];
        x[DIM - 1] = 8;
        json!({"type":"batch","context":{"chain":"22".repeat(32),
            "parent":"33".repeat(32),"challenge":"44".repeat(32),
            "batch_id":format!("{batch_id:064x}")},"requests":[{
                "id":"55".repeat(32),"scope":"66".repeat(32),"arrival_ns":0,
                "deadline_ns":u64::MAX / 2,"x":x}],"now_ns":0,"samples":1,"warmup":0})
    }
    fn session(commands: Vec<Value>) -> (Result<()>, Vec<Value>) {
        let input: Vec<u8> = commands.into_iter().flat_map(frame).collect();
        let mut output = Vec::new();
        let result = run(&mut io::Cursor::new(input), &mut output);
        let records = output
            .split(|&b| b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        (result, records)
    }
    #[test]
    fn persistent_replay_keeps_one_model_and_zero_business_credit() {
        let (status, records) = session(vec![init(), command(1), command(2)]);
        status.unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["type"], "prepared");
        for record in &records[1..] {
            assert_eq!(record["model_commitment"], records[0]["model_commitment"]);
            assert_eq!(record["semantic_verified"], true);
            assert_eq!(record["production_activation"], false);
            assert_eq!(record["pow_qualified"], false);
            assert_eq!(record["public_reward_eligible"], false);
            assert_eq!(record["business_credit"], 0);
            assert!(record["distinct_application_batches"].is_null());
            assert_eq!(record["useful_dense_macs"], 1542);
            assert_eq!(record["padded_macs"], 0);
            assert_eq!(record["nonempty_expert_groups"], 1);
            assert_eq!(record["unique_request_ids_in_session"], 1);
            assert_eq!(record["response_deadline_checked_before_write"], true);
            assert!(
                record["completion_now_ns"].as_u64().unwrap()
                    >= record["verified_product_ready_now_ns"].as_u64().unwrap()
            );
        }
        assert_eq!(records[1]["new_request_ids_in_session"], 1);
        assert_eq!(records[2]["new_request_ids_in_session"], 0);
        assert_ne!(
            records[1]["input_commitment"],
            records[2]["input_commitment"]
        );
    }
    #[test]
    fn selected_complete_relation_and_three_arm_measurement_are_disclosed() {
        let mut request = command(1);
        request["samples"] = json!(7);
        request["warmup"] = json!(2);
        let (status, records) = session(vec![init(), request]);
        status.unwrap();
        let record = &records[1];
        assert_eq!(record["selected_semantic_verified"], true);
        assert_eq!(record["selected_statement_matches_packed"], true);
        assert_eq!(
            record["selected_statement_commitment"],
            record["statement_commitment"]
        );
        assert_eq!(
            record["selected_producer_with_verify_scope"],
            "prepared_model_fresh_batch_input_commit_selected_statement_full_verify"
        );
        let full_wall = record["selected_producer_with_verify_wall_ns"]
            .as_u64()
            .unwrap();
        let phases = record["selected_phase_ns"].as_object().unwrap();
        assert_eq!(phases.len(), 5);
        let phase_total: u64 = [
            "validation",
            "input_commitment",
            "execution",
            "statement_commitment",
            "verify",
        ]
        .iter()
        .map(|name| phases[*name].as_u64().unwrap())
        .sum();
        assert!(phase_total <= full_wall);
        assert!(full_wall <= record["handler_wall_ns"].as_u64().unwrap());
        assert!(
            record["cold_selected_with_statement_ns"].as_u64().unwrap()
                >= phases["execution"].as_u64().unwrap()
                    + phases["statement_commitment"].as_u64().unwrap()
        );
        let cpu = &record["selected_producer_with_verify_cpu_ns"];
        assert!(cpu.is_null() || cpu.as_u64().is_some());
        for field in ["baseline_ns", "selected_ns", "grouped_ns"] {
            let samples = record[field].as_array().unwrap();
            assert_eq!(samples.len(), 7);
            assert!(samples.iter().all(|sample| sample.as_u64().is_some()));
        }
        let orders = record["kernel_sample_order_cycle"].as_array().unwrap();
        assert_eq!(orders.len(), 6);
        for (i, order) in orders.iter().enumerate() {
            assert_eq!(order.as_array().unwrap().len(), 3);
            assert!(!orders[..i].contains(order));
            for arm in ["ordinary", "selected", "packed"] {
                assert_eq!(
                    order
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|label| *label == arm)
                        .count(),
                    1
                );
            }
        }
        for position in 0..3 {
            for arm in ["ordinary", "selected", "packed"] {
                assert_eq!(
                    orders.iter().filter(|order| order[position] == arm).count(),
                    2
                );
            }
        }
        assert_eq!(record["kernel_sample_complete_cycles"], 1);
        assert_eq!(record["kernel_sample_partial_cycle_samples"], 1);
        assert!(
            record["selected_verified_product_ready_now_ns"]
                .as_u64()
                .unwrap()
                >= record["verified_product_ready_now_ns"].as_u64().unwrap()
        );
        assert!(
            record["completion_now_ns"].as_u64().unwrap()
                >= record["selected_verified_product_ready_now_ns"]
                    .as_u64()
                    .unwrap()
        );
    }
    #[test]
    fn batch_reuse_and_request_identity_rebinding_refuse_without_another_product() {
        let (status, records) = session(vec![init(), command(1), command(1)]);
        assert_eq!(status.unwrap_err(), "DUPLICATE_BATCH_ID");
        assert_eq!(records.len(), 2);
        for key in ["x", "scope", "arrival_ns", "deadline_ns"] {
            let mut rebound = command(2);
            rebound["requests"][0][key] = match key {
                "x" => {
                    let mut x = vec![0_i32; DIM];
                    x[0] = 1;
                    x[DIM - 1] = 8;
                    json!(x)
                }
                "scope" => json!("77".repeat(32)),
                "arrival_ns" => json!(1),
                _ => json!(u64::MAX / 2 - 1),
            };
            let (status, records) = session(vec![init(), command(1), rebound]);
            assert_eq!(status.unwrap_err(), "REQUEST_ID_REBOUND");
            assert_eq!(records.len(), 2);
        }
    }
    #[test]
    fn session_and_benchmark_bounds_fail_closed() {
        let mut commands = vec![init()];
        commands.extend((1..=MAX_BATCH_COMMANDS + 1).map(command));
        let (status, records) = session(commands);
        assert_eq!(status.unwrap_err(), "SESSION_BATCH_BOUND");
        assert_eq!(records.len(), MAX_BATCH_COMMANDS + 1);
        for (field, value) in [("samples", 0), ("samples", 10_001), ("warmup", 1001)] {
            let mut invalid = command(1);
            invalid[field] = json!(value);
            assert_eq!(batch(&invalid).err().unwrap(), "SAMPLE_BOUND");
        }
        let mut duplicate = command(1);
        duplicate["requests"] = json!([duplicate["requests"][0], duplicate["requests"][0]]);
        let (status, records) = session(vec![init(), duplicate]);
        assert_eq!(status.unwrap_err(), "DUPLICATE_REQUEST");
        assert_eq!(records.len(), 1);
    }
    #[test]
    fn completion_clock_refuses_boundary_and_overflow() {
        let mut parsed = batch(&command(1)).unwrap();
        parsed.now_ns = 100;
        parsed.requests[0].deadline_ns = 200;
        assert_eq!(completion_clock(&parsed, 99, "LATE").unwrap(), 199);
        assert_eq!(completion_clock(&parsed, 100, "LATE").unwrap_err(), "LATE");
        parsed.now_ns = u64::MAX - 1;
        parsed.requests[0].deadline_ns = u64::MAX;
        assert_eq!(
            completion_clock(&parsed, 2, "LATE").unwrap_err(),
            "CLOCK_OVERFLOW"
        );
    }
    #[test]
    fn frame_bound_holds_with_small_reader_chunks() {
        let bytes = frame(json!({"x":1}));
        let mut input = io::BufReader::with_capacity(2, io::Cursor::new(bytes));
        assert_eq!(read_frame(&mut input).unwrap().unwrap(), json!({"x":1}));
        let mut input =
            io::BufReader::with_capacity(7, io::Cursor::new(vec![b' '; MAX_LINE_BYTES + 1]));
        assert_eq!(read_frame(&mut input).unwrap_err(), "FRAME_BYTE_BOUND");
    }
    #[test]
    fn missing_init_and_unbounded_arrays_refuse() {
        assert!(run(&mut io::Cursor::new(Vec::new()), &mut Vec::new()).is_err());
        assert!(model(&json!({"type":"init"})).is_err());
        assert!(array(&json!([]), DIM).is_err());
        assert!(read_frame(&mut io::Cursor::new(frame(json!({"x":1}))))
            .unwrap()
            .is_some());
    }
}
