// Private cfg(test) child of the unchanged original Node store module.
// This adapter obtains every parent, State, root and Config from real Node methods.
use super::*;
use serde_json::json;
use std::io::BufRead;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;
use trnm_mvcc_fee::pon_commitment::{
    CacheLimits, CheckedExecutionParent, CheckedTransactionPrefix, StagedOutput, PreparedCommitment,
};
use trnm_mvcc_fee::pon_executor::{
    ExecutionControl, ExecutionError, ExecutionProgress, PrefixContext,
};
use trnm_protocol::pon_wire::{hash, Envelope};

fn seed(index: u64) -> [u8; 32] {
    hash(b"DEV-ONLY-KEY", &[&index.to_le_bytes()])
}
fn public(index: u64) -> [u8; 32] {
    let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(seed(index))).unwrap();
    hex::decode(trnm_crypto_primitives::public_key_hex(&key))
        .unwrap()
        .try_into()
        .unwrap()
}
fn fixture_transaction(kind: &str, network: [u8; 32]) -> Vec<u8> {
    if kind == "short" {
        return b"PN".to_vec();
    }
    if kind == "oversize" {
        return vec![b'x'; 2049];
    }
    let index = if kind == "unfunded" { 99 } else { 0 };
    let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(seed(index))).unwrap();
    let mut actual_network = network;
    if kind == "network" {
        actual_network[0] ^= 1;
    }
    let mut payload = public(1).to_vec();
    payload.extend_from_slice(&7u64.to_le_bytes());
    let mut tx = Envelope {
        network: actual_network,
        sender: public(index),
        nonce: match kind {
            "valid2" => 2,
            "valid3" => 3,
            _ => 1,
        },
        expiry: if kind == "expired" { 0 } else { u64::MAX },
        fee_limit: if kind == "fee-zero" { 0 } else { 10_000_000 },
        tag: 1,
        payload,
        signature: [0; 64],
    };
    tx.signature = hex::decode(trnm_crypto_primitives::sign_hex(
        &key,
        &tx.signing_digest().unwrap(),
    ))
    .unwrap()
    .try_into()
    .unwrap();
    let mut raw = tx.encode().unwrap();
    if kind == "nonce-zero" {
        raw[68..76].fill(0);
        let n = raw.len() - 64;
        let d = hash(b"tx-sign", &[&raw[..n]]);
        let sig = hex::decode(trnm_crypto_primitives::sign_hex(&key, &d)).unwrap();
        raw[n..].copy_from_slice(&sig);
    }
    if kind == "signature" {
        let last = raw.len() - 1;
        raw[last] ^= 1;
    }
    if kind == "unknown-tag" {
        raw[92] = 255;
    }
    raw
}
fn optional_u64(value: &Value) -> Option<u64> {
    if value.is_null() {
        None
    } else {
        Some(value.as_u64().expect("source-bound u64"))
    }
}
fn settings_observation(settings: &Settings) -> Value {
    json!({
        "timestamp":settings.app.params["genesis_timestamp"].as_u64().unwrap(),
        "network_hex":hex::encode(settings.network()),"parameters_hex":hex::encode(settings.parameters()),
        "genesis_hex":hex::encode(settings.genesis()),"initial_root_hex":hex::encode(settings.state_root(&settings.initial).unwrap()),
        "family_hex":hex::encode(settings.app.family),"plan_hex":hex::encode(settings.app.plan),
        "fees":settings.app.fees.to_vec(),"evaluators":settings.app.evaluators.iter().cloned().collect::<Vec<_>>(),
        "params_canonical_hex":hex::encode(canonical(&settings.app.params).unwrap()),
        "model_registry_canonical_hex":hex::encode(canonical(&settings.app.model_registry).unwrap()),
    })
}
fn parent_observation(node: &Node, tip: [u8; 32], generation: u64) -> Value {
    let record = node.record(tip).unwrap();
    json!({"tip_hex":hex::encode(tip),"generation":generation,"slot":node.slot().unwrap(),
           "height":record.height,"parent_hex":record.parent.map(hex::encode),"work_hex":hex::encode(record.work.bytes()),"root_hex":hex::encode(record.root)})
}
fn metric_observation(value: &trnm_mvcc_fee::pon_executor::Output) -> Value {
    json!({"workers":value.metrics.workers,"workers_spawned":value.metrics.workers_spawned,
      "peak_inflight":value.metrics.peak_inflight,"committed_without_replay":value.metrics.committed_without_replay,
      "speculative":value.metrics.speculative,"reexecuted":value.metrics.reexecuted,
      "serial_conflict_batches":value.metrics.serial_conflict_batches,"signature_verifications":value.metrics.signature_verifications})
}
fn commitment_observation(value: &PreparedCommitment, before: &State, after: &State) -> Value {
    let snapshot = value.snapshot.as_ref().map(|s| json!({
        "keys":s.keys(),"payload_bytes":s.payload_bytes(),
        "retained_charge_bytes":s.retained_charge_bytes(),"root_hex":hex::encode(s.root())
    }));
    let changes: Vec<_> = value.changes.iter().map(|c| json!({
        "key_hex":hex::encode(&c.key),"before_hex":c.before.as_ref().map(hex::encode),
        "after_hex":c.after.as_ref().map(hex::encode)
    })).collect();
    let rows = |state: &State| -> Vec<[String;2]> {
        state.iter().map(|(key,value)| [hex::encode(key.as_bytes()),
            hex::encode(canonical(value).unwrap())]).collect()
    };
    json!({"root_hex":hex::encode(value.root),"changes":changes,
        "observation":{"method":format!("{:?}",value.observation.method),
            "actual_keys":value.observation.actual_keys,
            "actual_payload_bytes":value.observation.actual_payload_bytes,
            "changed_keys":value.observation.changed_keys,
            "changed_payload_bytes":value.observation.changed_payload_bytes,
            "compressed_nodes":value.observation.compressed_nodes,
            "workspace_charge_bytes":value.observation.workspace_charge_bytes},
        "snapshot":snapshot,"before":rows(before),"after":rows(after)})
}
fn invoke(index: usize, item: &Value, artifact_root: &Path) {
    let name = item["name"].as_str().unwrap();
    let settings =
        Settings::development(optional_u64(&item["timestamp"])).expect("real Settings constructor");
    let context = settings_observation(&settings);
    assert!(!settings.is_permanent_account_growth_v2());
    assert!(!trnm_mvcc_fee::pon_executor::pq_accounts_v2::enabled(
        &settings.app
    ));
    let workers = usize::try_from(item["workers"].as_u64().unwrap()).unwrap();
    let directory = artifact_root.join(format!("case-{index:04}"));
    std::fs::create_dir(&directory).unwrap();
    let node = Node::open(&directory, settings.clone(), workers).expect("real original Node open");
    assert!(node.state_backend == StateBackend::Legacy);
    let (tip, generation, base) = node.read_active().expect("actual Node parent State");
    let parent = parent_observation(&node, tip, generation);
    let record = node.record(tip).unwrap();
    let base_bytes = encode_state(&base);
    let mut prefix: Option<CheckedTransactionPrefix<'_>> = None;
    let mut actions = Vec::new();
    let mut retained_staged: Option<StagedOutput> = None;
    for (action_index, action) in item["actions"].as_array().unwrap().iter().enumerate() {
        let op = action["op"].as_str().unwrap();
        let transactions: Vec<Vec<u8>> = action
            .get("transactions")
            .map(|rows| {
                rows.as_array()
                    .unwrap()
                    .iter()
                    .map(|kind| fixture_transaction(kind.as_str().unwrap(), settings.network()))
                    .collect()
            })
            .unwrap_or_default();
        let progress = Mutex::new(Vec::<String>::new());
        let checkpoint = |event: ExecutionProgress| -> std::result::Result<(), u64> {
            progress.lock().unwrap().push(format!("{event:?}"));
            Ok(())
        };
        let accounting = ();
        let control = ExecutionControl::new(&checkpoint, &accounting);
        let before_len = prefix.as_ref().map(CheckedTransactionPrefix::len);
        let result = catch_unwind(AssertUnwindSafe(
            || -> std::result::Result<Option<StagedOutput>, ExecutionError<u64>> {
                match op {
                    "new" => {
                        drop(retained_staged.take());
                        drop(prefix.take());
                        let prior = node.cached_parent(tip).expect("actual Node cache lookup");
                        assert!(prior.is_some(), "read_active must retain its actual Snapshot");
                        let checked = node.checked_commitment(&base, record.root, prior.as_ref())
                            .expect("actual Node checked commitment");
                        let binding = CheckedExecutionParent::bind(
                            &base,
                            checked.root,
                            checked.snapshot.as_ref(),
                            CacheLimits::default(),
                        );
                        let bound = match binding {
                            Ok(bound) => bound,
                            Err("COMMITMENT_PARENT" | "COMMITMENT_ROOT") => {
                                node.invalidate_commitment();
                                CheckedExecutionParent::bind(&base, record.root, None, CacheLimits::default())?
                            }
                            Err(error) => return Err(error.into()),
                        };
                        drop(checked);
                        drop(prior);
                        let miner: [u8; 32] = hex::decode(action["miner_hex"].as_str().unwrap())
                            .unwrap()
                            .try_into()
                            .unwrap();
                        let actual_context = PrefixContext {
                            timestamp: optional_u64(&action["timestamp"]),
                            height: record.height.checked_add(1).unwrap(),
                            miner,
                            parent_id: tip,
                        };
                        prefix = Some(bound.into_prefix_with_control(
                            actual_context,
                            &node.settings.app,
                            &control,
                        )?);
                        Ok(None)
                    }
                    "execute" => Ok(Some(
                        prefix
                            .as_mut()
                            .expect("actual living checked Prefix")
                            .execute_with_control(&transactions, &control)?,
                    )),
                    "drop" => {
                        drop(retained_staged.take());
                        drop(prefix.take());
                        Ok(None)
                    }
                    _ => panic!("unknown bound input method"),
                }
            },
        ));
        let mut row = json!({"index":action_index,"op":op,"transactions":transactions.iter().map(hex::encode).collect::<Vec<_>>(),
              "outcome":null,"error":null,"state_hex":null,"root_hex":null,"receipts":null,"metrics":null,
              "timings":null,"commitment_debug":null,"panic_message":null,
              "ready":prefix.is_some(),"length":prefix.as_ref().map(CheckedTransactionPrefix::len).unwrap_or(0),
              "base_unchanged":null,"progress":progress.into_inner().unwrap()});
        match result {
            Ok(Ok(value)) => {
                row["outcome"] = json!("ok");
                if let Some(staged) = value {
                    assert_eq!(
                        staged.output.root, staged.commitment.root,
                        "real checked commitment root"
                    );
                    row["state_hex"] = json!(hex::encode(encode_state(&staged.output.state)));
                    row["root_hex"] = json!(hex::encode(staged.output.root));
                    row["receipts"] = json!(staged
                        .output
                        .receipts
                        .iter()
                        .map(hex::encode)
                        .collect::<Vec<_>>());
                    row["metrics"] = metric_observation(&staged.output);
                    row["timings"] = json!({"state_transition_ns":staged.output.metrics.state_transition_ns,"state_root_ns":staged.output.metrics.state_root_ns});
                    row["commitment_debug"] = json!(format!("{:?}", staged.commitment));
                    retained_staged = Some(staged);
                }
            }
            Ok(Err(ExecutionError::Relation(error))) => {
                row["outcome"] = json!("error");
                row["error"] = json!(error);
            }
            Ok(Err(ExecutionError::Cancelled(token))) => {
                row["outcome"] = json!("cancelled");
                row["token"] = json!(token);
            }
            Err(payload) => {
                row["outcome"] = json!("panic");
                row["panic_message"] = json!(payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                    .unwrap_or_else(|| "non-string panic".into()));
            }
        }
        row["prepared"] = retained_staged.as_ref().map(|s| commitment_observation(&s.commitment, &base, &s.output.state)).unwrap_or(Value::Null);
        if op == "execute" && row["outcome"] != "ok" {
            assert_eq!(
                prefix.as_ref().map(CheckedTransactionPrefix::len),
                before_len,
                "original retained length on failure"
            );
        }
        let (after_tip, after_generation, after) =
            node.read_active().expect("real actual source reread");
        assert_eq!((after_tip, after_generation), (tip, generation));
        assert_eq!(
            encode_state(&after),
            base_bytes,
            "operation changed durable parent"
        );
        assert_eq!(
            parent_observation(&node, after_tip, after_generation),
            parent
        );
        row["base_unchanged"] = json!(true);
        actions.push(row);
    }
    drop(retained_staged);
    drop(prefix);
    let (after_tip, after_generation, after) = node.read_active().unwrap();
    assert_eq!((after_tip, after_generation), (tip, generation));
    assert_eq!(encode_state(&after), base_bytes);
    drop(node);
    let cold = Node::open(&directory, settings, workers).expect("real cold reopen");
    let (cold_tip, cold_generation, cold_base) = cold.read_active().unwrap();
    assert_eq!((cold_tip, cold_generation), (tip, generation));
    assert_eq!(encode_state(&cold_base), base_bytes);
    assert_eq!(parent_observation(&cold, cold_tip, cold_generation), parent);
    drop(cold);
    println!(
        "NPNODE_ORIGINAL:{}",
        json!({"name":name,"context":context,"base_hex":hex::encode(base_bytes),"parent":parent,
        "actions":actions,"base_unchanged":true,"cold_source_equal":true,
        "actual_original_settings":true,"actual_original_node":true,"actual_checked_parent":true,"actual_checked_prefix":true,"actual_prepared_observation":true,
        "external_state_config_root_or_verdict":false,"node_commit":false})
    );
}
#[test]
fn evaluate() {
    let source = std::env::var_os("TRNM_HIA_NODE_PREFIX_CORPUS").expect("actual input");
    let artifacts = PathBuf::from(
        std::env::var_os("TRNM_HIA_NODE_PREFIX_ARTIFACTS").expect("private fixture root"),
    );
    std::fs::create_dir(&artifacts).expect("fresh original fixtures");
    let file = std::fs::File::open(source).unwrap();
    let mut count = 0;
    for (index, line) in std::io::BufReader::new(file).lines().enumerate() {
        let item: Value = serde_json::from_str(&line.unwrap()).unwrap();
        assert_eq!(item["schema"], "trnm.node-checked-prefix-source-history.v1");
        invoke(index, &item, &artifacts);
        count += 1;
    }
    assert_eq!(count, 4, "complete fixed history corpus");
}
// The following functions only encode actual observed serde values as JVT1.
fn encode_node(value: &Value, output: &mut Vec<u8>) {
    let start = output.len();
    output.extend_from_slice(&[0; 5]);
    let tag = match value {
        Value::Null => 0,
        Value::Bool(v) => {
            if *v {
                2
            } else {
                1
            }
        }
        Value::Number(n) => {
            if n.is_u64() {
                output.extend_from_slice(&n.as_u64().unwrap().to_le_bytes());
                3
            } else if n.is_i64() {
                output.extend_from_slice(&n.as_i64().unwrap().to_le_bytes());
                4
            } else {
                output.extend_from_slice(&n.as_f64().unwrap().to_le_bytes());
                5
            }
        }
        Value::String(s) => {
            output.extend_from_slice(s.as_bytes());
            6
        }
        Value::Array(rows) => {
            output.extend_from_slice(&u32::try_from(rows.len()).unwrap().to_le_bytes());
            for v in rows {
                encode_node(v, output);
            }
            7
        }
        Value::Object(rows) => {
            output.extend_from_slice(&u32::try_from(rows.len()).unwrap().to_le_bytes());
            for (key, v) in rows {
                output.extend_from_slice(&u32::try_from(key.len()).unwrap().to_le_bytes());
                output.extend_from_slice(key.as_bytes());
                encode_node(v, output);
            }
            8
        }
    };
    output[start] = tag;
    let n = u32::try_from(output.len() - start - 5).unwrap();
    output[start + 1..start + 5].copy_from_slice(&n.to_le_bytes());
}
fn encode_value(value: &Value) -> Vec<u8> {
    let mut out = b"JVT1".to_vec();
    encode_node(value, &mut out);
    out
}
fn push_u64(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&u64::try_from(value).unwrap().to_le_bytes());
}
fn encode_rows<'a>(
    rows: impl ExactSizeIterator<Item = (&'a String, Option<&'a Value>)>,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_u64(&mut out, rows.len());
    for (key, value) in rows {
        let bytes = value.map(encode_value).unwrap_or_default();
        push_u64(&mut out, key.len());
        push_u64(&mut out, bytes.len());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&bytes);
    }
    out
}
fn encode_state(state: &State) -> Vec<u8> {
    encode_rows(state.iter().map(|(k, v)| (k, Some(v))))
}
