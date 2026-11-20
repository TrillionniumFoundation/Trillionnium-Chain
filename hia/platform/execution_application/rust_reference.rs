// Test-only child of the unchanged production pon_executor module.
// Signature preparation, application, conflict revalidation and consumption
// below call the actual original owners. The byte helpers only transport Value.
use super::*;
use std::io::{BufRead, Write};
use std::sync::Mutex;

fn input_rows(rows: &Value) -> State {
    let mut state = State::new();
    for row in rows.as_array().unwrap() {
        let key = String::from_utf8(hex::decode(row["key_hex"].as_str().unwrap()).unwrap()).unwrap();
        let value = decode_value(&hex::decode(row["value_hex"].as_str().unwrap()).unwrap());
        assert!(state.insert(key, value).is_none(), "duplicate input State key");
    }
    state
}

fn application_history(case: &Value, cfg: &Config) -> Value {
    assert_eq!(case["schema"], "trnm.execution-application-history.v1");
    let mut state = input_rows(&case["base"]);
    let before = hex::encode(encode_state(&state));
    let mut observations = Vec::new();
    let mut actual_calls = BTreeMap::<String, u64>::new();
    let mut panic_messages = Vec::<Option<String>>::new();
    let mut attempt_counts = Vec::new();
    for transaction in case["transactions"].as_array().unwrap() {
        let raw = hex::decode(transaction["wire_hex"].as_str().unwrap()).unwrap();
        let height = transaction["height"].as_u64().unwrap();
        let signatures = AtomicUsize::new(0);
        let base_before = encode_state(&state);
        let callbacks = Mutex::new(Vec::<String>::new());
        let cancel = transaction["cancel_at"].as_u64();
        let callback = |who: &str| -> Result<()> {
            let mut rows = callbacks.lock().unwrap();
            rows.push(hex::encode(who.as_bytes()));
            if cancel == Some(rows.len() as u64) { Err("ACCOUNT_ACCESS") } else { Ok(()) }
        };
        let access: Option<&AccountPointAccess<'_>> = if transaction["callback"].as_bool().unwrap() { Some(&callback) } else { None };
        *actual_calls.entry("prepare".to_owned()).or_default() += 1;
        let prepared = prepare(&raw, height, None, cfg, &signatures, None);
        attempt_counts.push(signatures.load(Ordering::Relaxed));
        let mut patch = None;
        let mut panic_message = None;
        let (kind, outcome, error) = match prepared {
            Err(error) => ("preparation", "error", Some(error)),
            Ok(prepared) => {
                assert!(prepared.native_pq.is_none());
                *actual_calls.entry("apply_authenticated_application".to_owned()).or_default() += 1;
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
                    apply_authenticated_application(&state, &prepared, height, cfg, access, None))) {
                    Ok(Ok(value)) => { patch = Some(value); ("application", "ok", None) },
                    Ok(Err(error)) => ("application", if error == "ACCOUNT_ACCESS" { "cancelled" } else { "error" }, Some(error)),
                    Err(payload) => {
                        panic_message = Some(payload.downcast_ref::<String>().cloned()
                            .or_else(|| payload.downcast_ref::<&str>().map(|text| (*text).to_owned()))
                            .unwrap_or_else(|| "non-string original panic payload".to_owned()));
                        ("application", "panic", Some("PANIC"))
                    },
                }
            },
        };
        let unchanged = encode_state(&state) == base_before;
        assert!(unchanged, "Original application mutated borrowed base");
        let mut result = json!({"kind":kind,"outcome":outcome,"error":error,
            "callbacks":callbacks.lock().unwrap().clone(),"patch_hex":null,"fee":null,"receipt_hex":null,
            "current_before":null,"current_after":null,"base_unchanged":unchanged});
        if let Some(patch) = patch {
            result["patch_hex"] = json!(hex::encode(encode_patch(&patch)));
            result["fee"] = json!(patch.fee);
            result["receipt_hex"] = json!(hex::encode(&patch.receipt));
            *actual_calls.entry("Patch::current".to_owned()).or_default() += 1;
            result["current_before"] = json!(patch.current(&state));
            for mutation in transaction["current_mutations"].as_array().unwrap() {
                let key = String::from_utf8(hex::decode(mutation["key_hex"].as_str().unwrap()).unwrap()).unwrap();
                if mutation["value_hex"].is_null() { state.remove(&key); }
                else { state.insert(key, decode_value(&hex::decode(mutation["value_hex"].as_str().unwrap()).unwrap())); }
            }
            *actual_calls.entry("Patch::current".to_owned()).or_default() += 1;
            result["current_after"] = json!(patch.current(&state));
            if transaction["commit"].as_bool().unwrap() {
                *actual_calls.entry("Patch::apply".to_owned()).or_default() += 1;
                patch.apply(&mut state);
            } else {
                *actual_calls.entry("drop(Patch)".to_owned()).or_default() += 1;
                drop(patch);
            }
        }
        result["after_hex"] = json!(hex::encode(encode_state(&state)));
        result["root"] = Value::Null;
        if transaction["root"].as_bool().unwrap() {
            *actual_calls.entry("pon_executor::root".to_owned()).or_default() += 1;
            result["root"] = match root(&state) {
                Ok(value) => json!({"hash_hex":hex::encode(value),"error":null}),
                Err(error) => json!({"hash_hex":null,"error":error}),
            };
        }
        panic_messages.push(panic_message);
        observations.push(result);
    }
    json!({"name":case["name"],"before_hex":before,"observations":observations,
       "actual_method_calls":actual_calls,"actual_signature_attempts":attempt_counts,
       "actual_panic_messages":panic_messages,"actual_private_preparation":true,
       "actual_original_application":true,"native_runtime_host_proxy":false})
}

#[test]
fn evaluate() {
    let cfg = Config::installed().expect("original default Config");
    assert!(!pq_accounts_v2::enabled(&cfg));
    assert_eq!(cfg.task_profile(), LEGACY_TASK_PROFILE);
    assert!(!public_evaluation::enabled(&cfg));
    let context = json!({"network":hex::encode(cfg.network),"parameters":hex::encode(cfg.parameters),
        "family":hex::encode(cfg.family),"plan":hex::encode(cfg.plan),"params":cfg.params,
        "fees":cfg.fees.to_vec(),"evaluators":cfg.evaluators});
    println!("APCONTEXT:{}",serde_json::to_string(&context).unwrap());
    let path = std::env::var("TRNM_HIA_EXECUTION_APPLICATION_CORPUS").expect("required exact corpus");
    let input = std::io::BufReader::new(std::fs::File::open(path).unwrap());
    let mut total = 0;
    for line in input.lines() {
        let case: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let actual = application_history(&case,&cfg);
        println!("AP_ORIGINAL:{}",serde_json::to_string(&actual).unwrap());
        std::io::stdout().flush().unwrap();total += 1;
    }
    assert!(total>0,"Empty corpus is not a differential");
}

// Test-only byte adapter copied unchanged from the frozen State oracle.
fn take<'a>(input: &'a [u8], cursor: &mut usize, n: usize) -> &'a [u8] {
    let end = cursor.checked_add(n).unwrap();
    let value = input.get(*cursor..end).expect("truncated JVT1 fixture");
    *cursor=end; value
}
fn u32_at(input: &[u8], cursor: &mut usize) -> usize {
    u32::from_le_bytes(take(input,cursor,4).try_into().unwrap()) as usize
}
fn decode_node(input: &[u8], cursor: &mut usize) -> Value {
    let tag=take(input,cursor,1)[0];
    let n=u32_at(input,cursor);let end=cursor.checked_add(n).unwrap();
    let value=match tag {
        0 => { assert_eq!(n,0); Value::Null },
        1|2 => { assert_eq!(n,0); Value::Bool(tag==2) },
        3 => { assert_eq!(n,8); Value::from(u64::from_le_bytes(take(input,cursor,8).try_into().unwrap())) },
        4 => { assert_eq!(n,8); Value::from(i64::from_le_bytes(take(input,cursor,8).try_into().unwrap())) },
        5 => { assert_eq!(n,8); let number=f64::from_le_bytes(take(input,cursor,8).try_into().unwrap()); Value::Number(serde_json::Number::from_f64(number).expect("nonfinite fixture")) },
        6 => Value::String(std::str::from_utf8(take(input,cursor,n)).unwrap().to_owned()),
        7 => { let count=u32_at(input,cursor); let mut rows=Vec::with_capacity(count); for _ in 0..count { rows.push(decode_node(input,cursor)); } Value::Array(rows) },
        8 => { let count=u32_at(input,cursor); let mut rows=serde_json::Map::new(); for _ in 0..count {
            let n=u32_at(input,cursor); let key=std::str::from_utf8(take(input,cursor,n)).unwrap().to_owned(); let value=decode_node(input,cursor); rows.insert(key,value);
        } Value::Object(rows) },
        _ => panic!("invalid fixture tag"),
    };
    assert_eq!(*cursor,end,"JVT1 node extent"); value
}
fn decode_value(input: &[u8]) -> Value {
    assert_eq!(input.get(..4),Some(b"JVT1".as_slice()));let mut cursor=4;let value=decode_node(input,&mut cursor);assert_eq!(cursor,input.len());value
}
fn encode_node(value: &Value, output: &mut Vec<u8>) {
    let start=output.len();output.extend_from_slice(&[0;5]);
    let tag=match value {
        Value::Null => 0,
        Value::Bool(v) => if *v {2} else {1},
        Value::Number(n) => {
            if n.is_u64() { output.extend_from_slice(&n.as_u64().unwrap().to_le_bytes());3 }
            else if n.is_i64() { output.extend_from_slice(&n.as_i64().unwrap().to_le_bytes());4 }
            else { output.extend_from_slice(&n.as_f64().unwrap().to_le_bytes());5 }
        },
        Value::String(s) => { output.extend_from_slice(s.as_bytes());6 },
        Value::Array(rows) => { output.extend_from_slice(&u32::try_from(rows.len()).unwrap().to_le_bytes());for v in rows { encode_node(v,output); }7 },
        Value::Object(rows) => { output.extend_from_slice(&u32::try_from(rows.len()).unwrap().to_le_bytes());for (key,v) in rows { output.extend_from_slice(&u32::try_from(key.len()).unwrap().to_le_bytes());output.extend_from_slice(key.as_bytes());encode_node(v,output); }8 },
    };
    output[start]=tag;let n=u32::try_from(output.len()-start-5).unwrap();output[start+1..start+5].copy_from_slice(&n.to_le_bytes());
}
fn encode_value(value: &Value) -> Vec<u8> {
    let mut out=b"JVT1".to_vec();encode_node(value,&mut out);out
}
fn push_u64(out: &mut Vec<u8>, value: usize) { out.extend_from_slice(&u64::try_from(value).unwrap().to_le_bytes()); }
fn encode_rows<'a>(rows: impl ExactSizeIterator<Item=(&'a String,Option<&'a Value>)>) -> Vec<u8> {
    let mut out=Vec::new();push_u64(&mut out,rows.len());
    for (key,value) in rows { let bytes=value.map(encode_value).unwrap_or_default();push_u64(&mut out,key.len());push_u64(&mut out,bytes.len());out.extend_from_slice(key.as_bytes());out.extend_from_slice(&bytes); }
    out
}
fn encode_state(state: &State) -> Vec<u8> { encode_rows(state.iter().map(|(k,v)| (k,Some(v)))) }
fn encode_patch(patch: &Patch) -> Vec<u8> {
    let mut out=patch.fee.to_le_bytes().to_vec();push_u64(&mut out,patch.receipt.len());out.extend_from_slice(&patch.receipt);
    out.extend_from_slice(&encode_state(&patch.writes));out.extend_from_slice(&encode_rows(patch.reads.iter().map(|(k,v)| (k,v.as_ref()))));push_u64(&mut out,patch.scans.len());
    for (prefix,rows) in &patch.scans { push_u64(&mut out,prefix.len());out.extend_from_slice(prefix.as_bytes());out.extend_from_slice(&encode_state(rows)); }
    out
}
