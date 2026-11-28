// Private cfg(test) child of the unchanged production pon_executor module.
// All ledger work, prediction, replay, reward, root and worker joins are original calls.
use super::*;
use std::io::{BufRead, Write};
use std::sync::{Barrier, Mutex};

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

struct BatchAccounting {
    started: AtomicUsize,
    stopped: AtomicUsize,
    spawned: AtomicUsize,
    active: AtomicUsize,
    events: Mutex<Vec<Value>>,
}
struct BatchInterval<'a>(&'a BatchAccounting);
impl ExecutionWorkerInterval for BatchInterval<'_> {}
impl Drop for BatchInterval<'_> {
    fn drop(&mut self) {
        self.0.events.lock().unwrap().push(json!({"event":"stopped","thread":format!("{:?}",std::thread::current().id())}));
        self.0.active.fetch_sub(1,Ordering::SeqCst);
        self.0.stopped.fetch_add(1,Ordering::SeqCst);
    }
}
impl ExecutionWorkerAccounting for BatchAccounting {
    fn worker_started(&self) -> Option<Box<dyn ExecutionWorkerInterval + '_>> {
        self.active.fetch_add(1,Ordering::SeqCst);
        self.started.fetch_add(1,Ordering::SeqCst);
        self.events.lock().unwrap().push(json!({"event":"started","thread":format!("{:?}",std::thread::current().id()),"name":std::thread::current().name()}));
        Some(Box::new(BatchInterval(self)))
    }
    fn worker_spawn_succeeded(&self) { self.spawned.fetch_add(1,Ordering::SeqCst); }
}

fn observe_case(case:&Value,cfg:&Config)->Value {
    assert_eq!(case["schema"],"trnm.execution-batch-original-input.v1");
    let parent=input_state(&hex::decode(case["state_hex"].as_str().unwrap()).unwrap());
    let before=encode_state(&parent);
    let transactions=case["transactions"].as_array().unwrap().iter()
        .map(|value|hex::decode(value.as_str().unwrap()).unwrap()).collect::<Vec<_>>();
    let height=case["height"].as_u64().unwrap();
    let workers=usize::try_from(case["workers"].as_u64().unwrap()).unwrap();
    let miner=hex::decode(case["miner_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    let parent_id=hex::decode(case["parent_id_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    let count=workers.min(transactions.len());
    let barrier=if case["barrier"].as_bool().unwrap() && count>1 {Some(Barrier::new(count))} else {None};
    let events=Mutex::new(Vec::<Value>::new());
    let sequences=Mutex::new(BTreeMap::<usize,usize>::new());
    let accounting=BatchAccounting {started:AtomicUsize::new(0),stopped:AtomicUsize::new(0),spawned:AtomicUsize::new(0),
        active:AtomicUsize::new(0),events:Mutex::new(Vec::new())};
    let progress=|point:ExecutionProgress|->std::result::Result<(),u64> {
        let (kind,index,worker)=match point {
            ExecutionProgress::BeforePrepare{index}=>(1,index,index%count),
            ExecutionProgress::AfterPrepare{index}=>(2,index,index%count),
            ExecutionProgress::BeforeStateClone=>(10,0,8),
            ExecutionProgress::AfterMandatory=>(11,0,8),
            ExecutionProgress::BeforeApply{index}=>(12,index,8),
            ExecutionProgress::AfterApply{index}=>(13,index,8),
            ExecutionProgress::BeforeReward=>(14,0,8),
            ExecutionProgress::BeforeCommitment=>(15,0,8),
            ExecutionProgress::AfterCommitment=>(16,0,8),
            ExecutionProgress::BeforeOutput=>(17,0,8),
            _=>panic!("unanticipated original batch progress {:?}",point),
        };
        let sequence={let mut map=sequences.lock().unwrap();let value=map.entry(worker).or_default();*value+=1;*value};
        let thread=std::thread::current();
        events.lock().unwrap().push(json!({"worker":worker,"sequence":sequence,"kind":kind,"index":index,
            "thread":format!("{:?}",thread.id()),"thread_name":thread.name()}));
        if worker!=8 && sequence==1 {if let Some(barrier)=&barrier {barrier.wait();}}
        for action in case["actions"].as_array().unwrap() {
            if action["worker"].as_u64()==Some(worker as u64) && action["sequence"].as_u64()==Some(sequence as u64) {
                match action["class"].as_u64().unwrap() {
                    1=>return Err(action["token"].as_u64().unwrap()),
                    2=>panic!("test-observer callback panic token {}",action["token"].as_u64().unwrap()),
                    _=>panic!("unsupported observer action"),
                }
            }
        }
        Ok(())
    };
    let block=BlockExecution{timestamp:None,transactions:&transactions,height,miner,parent_id,workers};
    let control=ExecutionControl::new(&progress,&accounting);
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||execute_with_control(&parent,block,cfg,&control)));
    let mut observation=json!({"name":case["name"],"parent_hex":hex::encode(encode_state(&parent)),
        "parent_unchanged":encode_state(&parent)==before,"state_hex":null,"receipts":null,"root_hex":null,
        "metrics":null,"error":null,"token":null,"panic_message":null,
        "actual_original_execute_with_control":true,"external_admission_or_root":false});
    match result {
        Ok(Ok(value))=>{
            observation["outcome"]=json!("ok");
            observation["state_hex"]=json!(hex::encode(encode_state(&value.state)));
            observation["receipts"]=json!(value.receipts.iter().map(hex::encode).collect::<Vec<_>>());
            observation["root_hex"]=json!(hex::encode(value.root));
            observation["metrics"]=json!({"workers":value.metrics.workers,"workers_spawned":value.metrics.workers_spawned,
                "peak_inflight":value.metrics.peak_inflight,"committed_without_replay":value.metrics.committed_without_replay,
                "speculative":value.metrics.speculative,"reexecuted":value.metrics.reexecuted,
                "serial_conflict_batches":value.metrics.serial_conflict_batches,"signature_verifications":value.metrics.signature_verifications});
            observation["timings"]=json!({"state_transition_ns":value.metrics.state_transition_ns,"state_root_ns":value.metrics.state_root_ns});
        },
        Ok(Err(ExecutionError::Relation(error)))=>{observation["outcome"]=json!("error");observation["error"]=json!(error);},
        Ok(Err(ExecutionError::Cancelled(token)))=>{observation["outcome"]=json!("cancelled");observation["token"]=json!(token);},
        Err(payload)=>{
            observation["outcome"]=json!("panic");
            observation["panic_message"]=json!(payload.downcast_ref::<String>().cloned()
                .or_else(||payload.downcast_ref::<&str>().map(|text|(*text).to_owned()))
                .unwrap_or_else(||"non-string original panic payload".to_owned()));
        },
    }
    assert!(observation["parent_unchanged"].as_bool().unwrap(),"original parent mutated");
    assert_eq!(accounting.active.load(Ordering::SeqCst),0,"original worker interval leaked");
    assert_eq!(accounting.started.load(Ordering::SeqCst),accounting.stopped.load(Ordering::SeqCst),"original joins did not retire all guards");
    observation["worker_accounting"]=json!({"started":accounting.started.load(Ordering::SeqCst),"stopped":accounting.stopped.load(Ordering::SeqCst),
        "spawned":accounting.spawned.load(Ordering::SeqCst),"active":accounting.active.load(Ordering::SeqCst),"events":accounting.events.into_inner().unwrap()});
    observation["progress"]=json!(events.into_inner().unwrap());
    observation
}

#[test]
fn evaluate() {
    let cfg=Config::installed().expect("actual original default Config");
    assert!(!pq_accounts_v2::enabled(&cfg));assert_eq!(cfg.task_profile(),LEGACY_TASK_PROFILE);
    assert!(!public_evaluation::enabled(&cfg));
    println!("BPCONTEXT:{}",serde_json::to_string(&json!({"network":hex::encode(cfg.network),
        "parameters":hex::encode(cfg.parameters),"family":hex::encode(cfg.family),"plan":hex::encode(cfg.plan),
        "params":cfg.params,"fees":cfg.fees.to_vec(),"evaluators":cfg.evaluators})).unwrap());
    let path=std::env::var("TRNM_HIA_EXECUTION_BATCH_CORPUS").expect("exact actual batch corpus");
    let input=std::io::BufReader::new(std::fs::File::open(path).unwrap());let mut count=0;
    for line in input.lines() {
        let case:Value=serde_json::from_str(&line.unwrap()).unwrap();let observation=observe_case(&case,&cfg);
        println!("BP_ORIGINAL:{}",serde_json::to_string(&observation).unwrap());std::io::stdout().flush().unwrap();count+=1;
    }
    assert!(count>0,"empty original differential");
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
