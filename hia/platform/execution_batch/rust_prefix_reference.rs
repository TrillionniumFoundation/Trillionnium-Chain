// Private cfg(test) child. Original TransactionPrefix and commitment code are unchanged.
use super::*;
use std::io::{BufRead, Write};
use std::sync::Mutex;
fn input_state(input: &[u8]) -> State {
    let mut at = 0;
    let mut word = || {
        let end = at + 8;
        let value = u64::from_le_bytes(input.get(at..end).unwrap().try_into().unwrap());
        at = end;
        value as usize
    };
    let count = word();
    let mut state = State::new();
    for _ in 0..count {
        let key_len = u64::from_le_bytes(input.get(at..at+8).unwrap().try_into().unwrap()) as usize;
        let value_len = u64::from_le_bytes(input.get(at+8..at+16).unwrap().try_into().unwrap()) as usize;
        at += 16;
        let key = std::str::from_utf8(input.get(at..at+key_len).unwrap()).unwrap().to_owned();
        at += key_len;
        let value = decode_value(input.get(at..at+value_len).unwrap());
        at += value_len;
        assert!(state.insert(key,value).is_none(),"duplicate transport State key");
    }
    assert_eq!(at,input.len(),"trailing transport State bytes");
    state
}

struct PrefixAccounting;
impl ExecutionWorkerAccounting for PrefixAccounting {
    fn worker_started(&self) -> Option<Box<dyn ExecutionWorkerInterval + '_>> {
        panic!("ordinary original TransactionPrefix unexpectedly started a worker");
    }
    fn worker_spawn_succeeded(&self) {
        panic!("ordinary original TransactionPrefix unexpectedly spawned a worker");
    }
}
fn private_snapshot(prefix: Option<&TransactionPrefix>) -> Value {
    match prefix {
        None => json!({"ready":false,"length":0,"fees":0,"held_state_hex":"","receipts":[],"transactions":[]}),
        Some(value) => json!({"ready":true,"length":value.len(),"fees":value.fees,
            "held_state_hex":hex::encode(encode_state(&value.state)),
            "receipts":value.receipts.iter().map(hex::encode).collect::<Vec<_>>(),
            "transactions":value.transactions.iter().map(hex::encode).collect::<Vec<_>>()}),
    }
}
enum Succeeded {
    Created(TransactionPrefix),
    Executed(Output),
    Observed,
    Closed,
}
fn observe_command(index:usize,sequence:usize,command:&Value,prefix:&mut Option<TransactionPrefix>,cfg:&Config)->Value {
    let opcode=command["op"].as_u64().unwrap();
    let parent=if opcode==1 {Some(input_state(&hex::decode(command["state_hex"].as_str().unwrap()).unwrap()))} else {None};
    let parent_before=parent.as_ref().map(encode_state);
    let previous=private_snapshot(prefix.as_ref());
    let events=Mutex::new(Vec::<Value>::new());
    let counter=AtomicUsize::new(0);
    let height=if opcode==1 {command["height"].as_u64().unwrap()}
        else {prefix.as_ref().map(|value|value.context.height).unwrap_or(0)};
    let progress=|point:ExecutionProgress|->std::result::Result<(),u64> {
        let (kind,position)=match point {
            ExecutionProgress::BeforePrepare{index}=>(1,index),
            ExecutionProgress::AfterPrepare{index}=>(2,index),
            ExecutionProgress::BeforeStateClone=>(10,0),
            ExecutionProgress::AfterMandatory=>(11,0),
            ExecutionProgress::BeforeApply{index}=>(12,index),
            ExecutionProgress::AfterApply{index}=>(13,index),
            ExecutionProgress::BeforeReward=>(14,0),
            ExecutionProgress::BeforeCommitment=>(15,0),
            ExecutionProgress::AfterCommitment=>(16,0),
            ExecutionProgress::BeforeOutput=>(17,0),
            _=>panic!("unanticipated original Prefix callback {:?}",point),
        };
        let event=counter.fetch_add(1,Ordering::SeqCst)+1;
        events.lock().unwrap().push(json!({"sequence":event,"kind":kind,"index":position,"height":height}));
        if let Some(actions)=command.get("actions") {
            for action in actions.as_array().unwrap() {
                if action["sequence"].as_u64()==Some(event as u64) {
                    match action["class"].as_u64().unwrap() {
                        1=>return Err(action["token"].as_u64().unwrap()),
                        2=>panic!("original Prefix callback panic token {}",action["token"].as_u64().unwrap()),
                        _=>panic!("invalid corpus action"),
                    }
                }
            }
        }
        Ok(())
    };
    let accounting=PrefixAccounting;
    let control=ExecutionControl::new(&progress,&accounting);
    let transactions=command.get("transactions").map(|values|values.as_array().unwrap().iter()
        .map(|value|hex::decode(value.as_str().unwrap()).unwrap()).collect::<Vec<_>>()).unwrap_or_default();
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||->ControlledResult<Succeeded,u64>{
        match opcode {
            1=>{
                assert!(prefix.is_none(),"constructor cannot replace an existing private object");
                let context=PrefixContext {timestamp:command["timestamp"].as_u64(),
                    height:command["height"].as_u64().unwrap(),
                    miner:hex::decode(command["miner_hex"].as_str().unwrap()).unwrap().try_into().unwrap(),
                    parent_id:hex::decode(command["parent_id_hex"].as_str().unwrap()).unwrap().try_into().unwrap()};
                TransactionPrefix::new(parent.as_ref().unwrap(),context,cfg,&control).map(Succeeded::Created)
            },
            2=>prefix.as_mut().expect("original owner required")
                .execute_with_commitment_and_control(&transactions,|state|root_for_config(state,cfg),&control)
                .map(Succeeded::Executed),
            3=>{assert!(prefix.is_some());Ok(Succeeded::Observed)},
            4=>{drop(prefix.take());Ok(Succeeded::Closed)},
            _=>panic!("invalid corpus opcode"),
        }
    }));
    let mut observation=json!({"index":index,"sequence":sequence,"opcode":opcode,"outcome":null,
        "state_hex":null,"root_hex":null,"receipts":null,"metrics":null,"timings":null,
        "error":null,"token":null,"panic_message":null,"rollback_exact":null,"parent_unchanged":null});
    let mut closed=false;
    match result {
        Ok(Ok(value))=>{
            observation["outcome"]=json!("ok");
            match value {
                Succeeded::Created(value)=>{*prefix=Some(value);},
                Succeeded::Executed(value)=>{
                    observation["state_hex"]=json!(hex::encode(encode_state(&value.state)));
                    observation["root_hex"]=json!(hex::encode(value.root));
                    observation["receipts"]=json!(value.receipts.iter().map(hex::encode).collect::<Vec<_>>());
                    observation["metrics"]=json!({"workers":value.metrics.workers,"workers_spawned":value.metrics.workers_spawned,
                        "peak_inflight":value.metrics.peak_inflight,"committed_without_replay":value.metrics.committed_without_replay,
                        "speculative":value.metrics.speculative,"reexecuted":value.metrics.reexecuted,
                        "serial_conflict_batches":value.metrics.serial_conflict_batches,"signature_verifications":value.metrics.signature_verifications});
                    observation["timings"]=json!({"state_transition_ns":value.metrics.state_transition_ns,"state_root_ns":value.metrics.state_root_ns});
                },
                Succeeded::Observed=>{},
                Succeeded::Closed=>{closed=true;},
            }
        },
        Ok(Err(ExecutionError::Relation(error)))=>{observation["outcome"]=json!("error");observation["error"]=json!(error);},
        Ok(Err(ExecutionError::Cancelled(token)))=>{observation["outcome"]=json!("cancelled");observation["token"]=json!(token);},
        Err(payload)=>{
            observation["outcome"]=json!("panic");
            observation["panic_message"]=json!(payload.downcast_ref::<String>().cloned()
                .or_else(||payload.downcast_ref::<&str>().map(|text|(*text).to_owned()))
                .unwrap_or_else(||"non-string original panic".to_owned()));
        },
    }
    if opcode==1 {
        let unchanged=parent_before==parent.as_ref().map(encode_state);
        assert!(unchanged,"original prefix constructor changed parent");observation["parent_unchanged"]=json!(unchanged);
    }
    let mut private=private_snapshot(prefix.as_ref());
    if opcode==2 && observation["outcome"]!="ok" {
        let unchanged=private==previous;assert!(unchanged,"original prefix rejection failed exact rollback");
        observation["rollback_exact"]=json!(unchanged);
    }
    if closed {
        // These diagnostic metadata were read while the real object was alive;
        // a close exposes no live State and confers no surviving capability.
        private=previous;private["ready"]=json!(false);private["held_state_hex"]=json!("");
        observation["private_origin"]=json!("last_actual_snapshot_before_drop");
    } else {observation["private_origin"]=json!("actual_live_original_object");}
    observation["private"]=private;
    observation["progress"]=json!(events.into_inner().unwrap());
    observation
}
fn observe_history(case:&Value,cfg:&Config)->Value {
    assert_eq!(case["schema"],"trnm.transaction-prefix-history.v1");
    let mut prefix=None;let mut commands=Vec::new();let mut skipped=Vec::new();
    for (index,command) in case["commands"].as_array().unwrap().iter().enumerate() {
        if command.get("requires_ready").and_then(Value::as_bool)==Some(true) && prefix.is_none() {
            skipped.push(index);continue;
        }
        commands.push(observe_command(index,commands.len()+1,command,&mut prefix,cfg));
    }
    assert!(prefix.is_none(),"original prefix not retired");
    json!({"name":case["name"],"commands":commands,"skipped":skipped,
        "actual_original_transaction_prefix":true,"external_admission_or_root":false})
}
#[test]
fn evaluate() {
    let cfg=Config::installed().expect("actual original default Config");
    assert!(!pq_accounts_v2::enabled(&cfg));
    assert_eq!(cfg.task_profile(),LEGACY_TASK_PROFILE);
    assert!(!public_evaluation::enabled(&cfg));
    println!("PXCONTEXT:{}",serde_json::to_string(&json!({"network":hex::encode(cfg.network),
        "parameters":hex::encode(cfg.parameters),"family":hex::encode(cfg.family),"plan":hex::encode(cfg.plan),
        "params":cfg.params,"fees":cfg.fees.to_vec(),"evaluators":cfg.evaluators})).unwrap());
    let path=std::env::var("TRNM_HIA_TRANSACTION_PREFIX_CORPUS").expect("bound history corpus");
    let input=std::io::BufReader::new(std::fs::File::open(path).unwrap());
    let mut count=0;
    for line in input.lines() {
        let case:Value=serde_json::from_str(&line.unwrap()).unwrap();
        let observed=observe_history(&case,&cfg);
        println!("PX_ORIGINAL:{}",serde_json::to_string(&observed).unwrap());
        std::io::stdout().flush().unwrap();count+=1;
    }
    assert!(count>0,"empty original history corpus");
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
