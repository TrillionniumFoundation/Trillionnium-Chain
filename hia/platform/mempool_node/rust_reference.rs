// Private cfg(test) child of the unchanged original Node store::mempool.
use super::*;
use crate::Settings;
use super::super::canonical;
use serde_json::{json,Value};
use std::io::BufRead;
use std::path::{Path,PathBuf};
use std::panic::{catch_unwind,AssertUnwindSafe};
use std::sync::Mutex;

fn optional_u64(v:&Value)->Option<u64> { if v.is_null(){None}else{Some(v.as_u64().expect("bound optional u64"))} }
fn error_observation(error:&crate::Error)->Value {
 let mut sources=Vec::new();let mut source=std::error::Error::source(error);
 while let Some(e)=source{sources.push(e.to_string());source=e.source();}
 json!({"display":error.to_string(),"code":error.code().map(|v|v.as_str()),"kind":format!("{:?}",error.kind()),
 "requires_owner_stop":error.requires_owner_stop(),"source_displays":sources})
}
fn settings_observation(settings:&Settings)->Value {
 json!({"timestamp":settings.app.params["genesis_timestamp"].as_u64().unwrap(),
 "network_hex":hex::encode(settings.network()),"parameters_hex":hex::encode(settings.parameters()),
 "genesis_hex":hex::encode(settings.genesis()),"initial_root_hex":hex::encode(settings.state_root(&settings.initial).unwrap()),
 "family_hex":hex::encode(settings.app.family),"plan_hex":hex::encode(settings.app.plan),
 "fees":settings.app.fees.to_vec(),"evaluators":settings.app.evaluators.iter().cloned().collect::<Vec<_>>(),
 "params_canonical_hex":hex::encode(canonical(&settings.app.params).unwrap()),
 "model_registry_canonical_hex":hex::encode(canonical(&settings.app.model_registry).unwrap())})
}
fn event(point:ExecutionProgress)->(u64,usize) {
 match point {
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
  ExecutionProgress::BeforeParentBinding=>(18,0),
  ExecutionProgress::BeforeHeaderContext=>(0,0),
  ExecutionProgress::BeforePersistence=>(19,0),
  ExecutionProgress::PersistenceDelta{index}=>(20,index),
  ExecutionProgress::BeforeDurableCommit=>(21,0),
 }
}
fn facts(preview:&PendingPreview<'_,'_>)->Value {
 json!(preview.signatures.iter().map(|fact|json!({"raw_hex":hex::encode(&fact.raw),
  "height":fact.context.height,"parent_hex":hex::encode(fact.context.parent),
  "same_state":std::ptr::eq(fact.context.state,preview.state),
  "same_config":std::ptr::eq(fact.context.cfg,preview.cfg)})).collect::<Vec<_>>())
}
fn actual_base(node:&Node,expected:&(Hash,u64,State))->bool {
 let value=node.read_active().expect("actual held Node reread");
 assert_eq!(&value,expected,"ordinary PendingPreview changed actual durable parent");true
}
fn limits(item:&Value)->PoolLimits {
 let p=&item["policy"];
 PoolLimits{max_records:usize::try_from(p["max_records"].as_u64().unwrap()).unwrap(),
  max_bytes:usize::try_from(p["max_bytes"].as_u64().unwrap()).unwrap(),
  max_group_members:usize::try_from(p["max_group_members"].as_u64().unwrap()).unwrap(),
  critical_reserve:usize::try_from(p["critical_reserve"].as_u64().unwrap()).unwrap(),
  max_removals:usize::try_from(p["max_removals"].as_u64().unwrap()).unwrap(),
  preview_miner:hex::decode(p["preview_miner_hex"].as_str().unwrap()).unwrap().try_into().unwrap()}
}
fn observe_lease(node:&Node,actual:&PoolParent,limits:&PoolLimits,commands:&[Value],base:&(Hash,u64,State))->Vec<Value> {
 node.owner_preview_available().expect("actual ordinary owner availability");
 let owner_permit=node.continuous_pool_validation_permit().expect("actual owner permit selection");
 assert!(owner_permit.is_none(),"finite ordinary profile has no continuous permit");
 let events=Mutex::new(Vec::<Value>::new());
 let target=Mutex::new(None::<Value>);
 let progress=|point:ExecutionProgress|->crate::Result<()> {
  let (kind,index)=event(point);
  let ordinal={let mut rows=events.lock().unwrap();let n=rows.len();rows.push(json!({"kind":kind,"index":index}));n};
  let requested=target.lock().unwrap().clone();
  if let Some(action)=requested {
   if action["ordinal"].as_u64().unwrap()==ordinal as u64 {
    assert_eq!(action["kind"].as_u64(),Some(kind),"actual callback kind at cancellation");
    assert_eq!(action["index"].as_u64(),Some(index as u64),"actual callback index at cancellation");
    let token=action["token"].as_u64().unwrap();
    if action["class"].as_u64().unwrap()==2 {panic!("M05_CALLBACK_PANIC:{token}");}
    return Err(crate::Error::from(format!("M05_CALLBACK_TOKEN:{token}")));
   }
  }
  owner_permit.as_ref().map_or(Ok(()),|permit|permit.progress())
 };
 let control=ExecutionControl::new(&progress,&());
 let mut preview=PendingPreview{height:actual.height,state:&actual.state,parent:actual.id,cfg:&actual.cfg,
  limits,node,checked:None,prefix:None,signatures:Vec::new(),parent_observation:None,control:&control,owner_permit:owner_permit.as_ref()};
 let mut out=Vec::new();
 for item in commands {
  let op=item["op"].as_str().unwrap();let index=item["index"].as_u64().unwrap();
  if op=="read" {out.push(json!({"index":index,"op":op,"outcome":"ok","error":null,"base_unchanged":actual_base(node,base),"progress":[]}));continue;}
  assert_eq!(op,"validate","lease only read or actual validation");
  let raws:Vec<Vec<u8>>=item["transactions"].as_array().unwrap().iter().map(|r|hex::decode(r.as_str().unwrap()).unwrap()).collect();
  let context=SignatureContext{height:actual.height,parent:actual.id,state:&actual.state,cfg:&actual.cfg};
  let reuse=if preview.signatures.len()<=raws.len()&&preview.signatures.iter().zip(&raws).all(|(checked,raw)|checked.matches(context,raw)){preview.signatures.len()}else{0};
  let before_facts=facts(&preview);let before_len=preview.prefix.as_ref().map(CheckedTransactionPrefix::len);
  events.lock().unwrap().clear();
  *target.lock().unwrap()=if item["cancel"].is_null(){None}else{Some(item["cancel"].clone())};
  M05_MAIN_VALIDATIONS.with(|count|count.set(0));
  let result=catch_unwind(AssertUnwindSafe(||preview.validate(&raws)));
  let calls=M05_MAIN_VALIDATIONS.with(std::cell::Cell::get);
  let observed=events.lock().unwrap().clone();
  let mut row=json!({"index":index,"op":op,"outcome":null,"error":null,"error_full":null,
   "ready_count":null,"main_validations":calls,"reused":reuse,"progress":observed,
   "signature_facts":facts(&preview),"prefix_length":preview.prefix.as_ref().map(CheckedTransactionPrefix::len),
   "checked_parent_present":preview.checked.is_some(),"parent_observation_debug":format!("{:?}",preview.parent_observation),
   "base_unchanged":actual_base(node,base),"rollback_length_and_facts":null,"panic_message":null});
  match result {
   Ok(Ok(ready))=>{row["outcome"]=json!("ok");row["ready_count"]=json!(ready);}
   Ok(Err(PoolPreviewError::Native(error)))=>{
    row["outcome"]=json!("error");row["error"]=json!(error.to_string());row["error_full"]=error_observation(&error);
   }
   Ok(Err(PoolPreviewError::Cancelled(error)))=>{
    row["outcome"]=json!("cancelled");row["error_full"]=error_observation(&error);
   }
   Err(payload)=>{
    row["outcome"]=json!("panic");
    row["panic_message"]=json!(payload.downcast_ref::<String>().cloned().or_else(||payload.downcast_ref::<&str>().map(|v|(*v).to_owned())).unwrap_or_else(||"non-string panic".into()));
   }
  }
  if row["outcome"]!="ok"{
   assert_eq!(facts(&preview),before_facts,"failed whole preview published signature facts");
   assert_eq!(preview.prefix.as_ref().map(CheckedTransactionPrefix::len).unwrap_or(0),before_len.unwrap_or(0),"failed whole preview changed retained transaction length");
   row["rollback_length_and_facts"]=json!(true);
  }
  out.push(row);
 }
 drop(preview);assert!(actual_base(node,base));out
}
fn invoke(index:usize,item:&Value,artifacts:&Path) {
 let name=item["name"].as_str().unwrap();
 let settings=Settings::development(optional_u64(&item["timestamp"])).expect("actual Settings");
 assert!(!settings.is_permanent_account_growth_v2());
 assert!(!trnm_mvcc_fee::pon_executor::pq_accounts_v2::enabled(&settings.app));
 let context=settings_observation(&settings);let workers=usize::try_from(item["workers"].as_u64().unwrap()).unwrap();
 let directory=artifacts.join(format!("case-{index:04}"));std::fs::create_dir(&directory).unwrap();
 let node=Node::open(&directory,settings.clone(),workers).expect("actual Node open");
 let base=node.read_active().expect("actual Node parent");let base_bytes=encode_state(&base.2);
 let commands=item["actions"].as_array().unwrap();let mut rows=Vec::new();let mut i=0;let mut closed=false;
 while i<commands.len(){
  let action=&commands[i];let op=action["op"].as_str().unwrap();assert_eq!(action["index"].as_u64(),Some(i as u64));
  match op {
   "open"=>{
    let policy=limits(action);
    match policy.validate(){
     Err(error)=>{rows.push(json!({"index":i,"op":op,"outcome":"error","error":error.to_string(),"error_full":error_observation(&error),"active":false,"progress":[]}));i+=1;}
     Ok(())=>{
      node.owner_preview_available().unwrap();
      let actual=node.pool_parent().expect("actual original pool parent reconstruction");
      assert_eq!((actual.id,actual.generation), (base.0,base.1));assert_eq!(actual.state,base.2);
      rows.push(json!({"index":i,"op":op,"outcome":"ok","error":null,"active":true,"progress":[],
       "parent_height":actual.height,"parent_root_hex":hex::encode(actual.root),"actual_pool_parent":true}));
      let end=(i+1..commands.len()).find(|j|matches!(commands[*j]["op"].as_str().unwrap(),"drop"|"close")).expect("explicit lease retirement");
      rows.extend(observe_lease(&node,&actual,&policy,&commands[i+1..end],&base));
      drop(actual);
      let endop=commands[end]["op"].as_str().unwrap();
      rows.push(json!({"index":end,"op":endop,"outcome":"ok","error":null,"active":false,"progress":[],"actual_scope_dropped":true}));
      i=end+1;
      if endop=="close"{closed=true;assert_eq!(i,commands.len());}
     }
    }
   }
   "read"=>{rows.push(json!({"index":i,"op":op,"outcome":"ok","error":null,"base_unchanged":actual_base(&node,&base),"progress":[]}));i+=1;}
   "close"=>{rows.push(json!({"index":i,"op":op,"outcome":"ok","error":null,"active":false,"progress":[]}));closed=true;i+=1;assert_eq!(i,commands.len());}
   _=>panic!("bound command outside a real owner lease"),
  }
 }
 assert!(closed&&actual_base(&node,&base));drop(node);
 let cold=Node::open(&directory,settings,workers).expect("actual cold reopen");assert_eq!(cold.read_active().unwrap(),base);drop(cold);
 println!("M05NODE_ORIGINAL:{}",json!({"name":name,"context":context,"base_hex":hex::encode(base_bytes),"actions":rows,
  "base_unchanged":true,"cold_source_equal":true,"actual_original_settings":true,"actual_original_node":true,
  "actual_original_pool_parent":true,"actual_original_pending_preview":true,"actual_typed_gate_and_ready":true,
  "external_state_nonce_signature_or_verdict":false,"continuous_permit":false,"durable_local_pool":false,"node_commit":false}));
}
#[test]
fn evaluate(){
 let path=std::env::var_os("TRNM_HIA_M05_NODE_CORPUS").expect("bound input");
 let artifacts=PathBuf::from(std::env::var_os("TRNM_HIA_M05_NODE_ARTIFACTS").expect("fresh artifacts"));
 std::fs::create_dir(&artifacts).unwrap();
 let file=std::fs::File::open(path).unwrap();let mut count=0;
 for (i,line) in std::io::BufReader::new(file).lines().enumerate(){
  let item:Value=serde_json::from_str(&line.unwrap()).unwrap();
  assert_eq!(item["schema"],"trnm.production-m05-original-history.v1");
  invoke(i,&item,&artifacts);count+=1;
 }
 assert_eq!(count,std::env::var("TRNM_HIA_M05_NODE_HISTORY_COUNT").unwrap().parse::<usize>().unwrap());
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

// Additional private observer: actual joint lifecycle on one original Node.

use trnm_mvcc_fee::pon_commitment::{
 CacheLimits as CrossCacheLimits, CheckedExecutionParent as CrossCheckedParent,
 StagedOutput as CrossStagedOutput,
};
use trnm_mvcc_fee::pon_executor::PrefixContext as CrossPrefixContext;
fn cross_parent(node:&Node,tip:Hash,generation:u64)->Value {
 let record=node.record(tip).unwrap();
 json!({"tip_hex":hex::encode(tip),"generation":generation,"slot":node.slot().unwrap(),
 "height":record.height,"parent_hex":record.parent.map(hex::encode),
 "work_hex":hex::encode(record.work.bytes()),"root_hex":hex::encode(record.root)})
}
fn cross_invoke(item:&Value,artifacts:&Path) {
 let settings=Settings::development(optional_u64(&item["timestamp"])).unwrap();
 assert!(item["timestamp"].is_null());assert_eq!(item["workers"].as_u64(),Some(1));
 let context=settings_observation(&settings);
 let directory=artifacts.join("single-owner-cross-lifecycle");
 std::fs::create_dir(&directory).unwrap();
 let node=Node::open(&directory,settings.clone(),1).unwrap();
 let base=node.read_active().unwrap();let base_hex=hex::encode(encode_state(&base.2));
 let parent=cross_parent(&node,base.0,base.1);
 let record=node.record(base.0).unwrap();
 let mut prefix:Option<CheckedTransactionPrefix<'_>>=None;
 let mut staged:Option<CrossStagedOutput>=None;
 let commands=item["actions"].as_array().unwrap();assert_eq!(commands.len(),24);
 let mut rows=Vec::new();let mut index=0usize;let mut closed=false;
 while index<commands.len() {
  let item=&commands[index];assert_eq!(item["index"].as_u64(),Some(index as u64));
  let op=item["op"].as_str().unwrap();
  match op {
   "read"=>{assert!(actual_base(&node,&base));rows.push(json!({"index":index,"op":op,"outcome":"ok","error":null,"base_unchanged":true}));index+=1;}
   "record"=>{let observed=cross_parent(&node,base.0,base.1);assert_eq!(observed,parent);rows.push(json!({"index":index,"op":op,"outcome":"ok","error":null,"parent":observed}));index+=1;}
   "canonical_parent"=>{
    assert!(prefix.is_some());
    let values:Vec<[String;2]>=base.2.iter().map(|(k,v)|[hex::encode(k.as_bytes()),hex::encode(canonical(v).unwrap())]).collect();
    rows.push(json!({"index":index,"op":op,"outcome":"ok","error":null,"rows":values,"root_hex":hex::encode(record.root)}));index+=1;
   }
   "prepared"=>{
    let value=staged.as_ref().expect("actual retained StagedOutput");
    rows.push(json!({"index":index,"op":op,"outcome":"ok","error":null,
     "prepared":cross_commitment_observation(&value.commitment,&base.2,&value.output.state)}));index+=1;
   }
   "node_new"|"node_execute"|"node_drop"=>{
    let events=Mutex::new(Vec::<Value>::new());
    let progress=|point:ExecutionProgress|->crate::Result<()> {
     let (kind,at)=event(point);events.lock().unwrap().push(json!({"kind":kind,"index":at}));Ok(())
    };
    let control=ExecutionControl::new(&progress,&());
    let mut row=json!({"index":index,"op":op,"outcome":"ok","error":null,
      "state_hex":null,"root_hex":null,"receipts":null,"metrics":null});
    if op=="node_new" {
     drop(staged.take());drop(prefix.take());
     let prior=node.cached_parent(base.0).expect("actual Node cache lookup");
     assert!(prior.is_some(),"actual read_active Snapshot");
     let checked=node.checked_commitment(&base.2,record.root,prior.as_ref()).expect("actual checked Node commitment");
     let actual=match CrossCheckedParent::bind(&base.2,checked.root,checked.snapshot.as_ref(),CrossCacheLimits::default()) {
      Ok(bound)=>bound,
      Err("COMMITMENT_PARENT"|"COMMITMENT_ROOT")=>{node.invalidate_commitment();CrossCheckedParent::bind(&base.2,record.root,None,CrossCacheLimits::default()).unwrap()},
      Err(error)=>panic!("actual Some binding failed: {error}"),
     };
     drop(checked);drop(prior);
     let miner:[u8;32]=hex::decode(item["miner_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
     let ctx=CrossPrefixContext{timestamp:optional_u64(&item["timestamp"]),height:record.height.checked_add(1).unwrap(),miner,parent_id:base.0};
     prefix=Some(actual.into_prefix_with_control(ctx,&node.settings.app,&control).unwrap());
    } else if op=="node_execute" {
     let wires:Vec<Vec<u8>>=item["transactions"].as_array().unwrap().iter().map(|x|hex::decode(x.as_str().unwrap()).unwrap()).collect();
     let actual=prefix.as_mut().unwrap().execute_with_control(&wires,&control).unwrap();
     assert_eq!(actual.output.root,actual.commitment.root);
     row["state_hex"]=json!(hex::encode(encode_state(&actual.output.state)));
     row["root_hex"]=json!(hex::encode(actual.output.root));
     row["receipts"]=json!(actual.output.receipts.iter().map(hex::encode).collect::<Vec<_>>());
     row["metrics"]=cross_metric_observation(&actual.output);
     staged=Some(actual);
    } else {drop(staged.take());drop(prefix.take());}
    row["ready"]=json!(prefix.is_some());
    row["length"]=json!(prefix.as_ref().map(CheckedTransactionPrefix::len).unwrap_or(0));
    row["actual_original_progress"]=json!(events.into_inner().unwrap());
    assert!(actual_base(&node,&base));rows.push(row);index+=1;
   }
   "open"=>{
    assert!(prefix.is_none()&&staged.is_none(),"real Node Prefix must retire before pool lease");
    let policy=limits(item);policy.validate().unwrap();node.owner_preview_available().unwrap();
    let actual=node.pool_parent().unwrap();assert_eq!((actual.id,actual.generation),(base.0,base.1));assert_eq!(actual.state,base.2);
    rows.push(json!({"index":index,"op":op,"outcome":"ok","error":null,"active":true,"progress":[]}));
    let end=(index+1..commands.len()).find(|j|commands[*j]["op"]=="drop").unwrap();
    assert!(commands[index+1..end].iter().all(|x|x["op"]=="validate"));
    rows.extend(observe_lease(&node,&actual,&policy,&commands[index+1..end],&base));
    drop(actual);assert!(actual_base(&node,&base));
    rows.push(json!({"index":end,"op":"drop","outcome":"ok","error":null,"active":false,"progress":[],"actual_pool_scope_dropped":true}));
    index=end+1;
   }
   "close"=>{
    assert!(prefix.is_none()&&staged.is_none());assert_eq!(index+1,commands.len());
    assert!(actual_base(&node,&base));closed=true;
    rows.push(json!({"index":index,"op":op,"outcome":"ok","error":null}));index+=1;
   }
   _=>panic!("source-bound cross method outside actual lease"),
  }
 }
 assert!(closed);assert_eq!(rows.len(),24);
 assert!(actual_base(&node,&base));assert_eq!(cross_parent(&node,base.0,base.1),parent);
 drop(staged);drop(prefix);drop(node);
 let cold=Node::open(&directory,settings,1).unwrap();
 assert_eq!(cold.read_active().unwrap(),base);assert_eq!(cross_parent(&cold,base.0,base.1),parent);drop(cold);
 println!("M05CROSS_ORIGINAL:{}",json!({"name":"single-owner-cross-lifecycle","context":context,
  "base_hex":base_hex,"parent":parent,"actions":rows,"same_actual_node_instance":true,
  "actual_original_pending_preview":true,"actual_original_checked_prefix":true,
  "base_unchanged":true,"cold_source_equal":true,"caller_state_root_nonce_or_signature_verdict":false,
  "continuous_permit":false,"node_commit":false}));
}
#[test]
fn evaluate_cross() {
 let path=std::env::var_os("TRNM_HIA_M05_CROSS_CORPUS").expect("source-bound cross input");
 let artifacts=PathBuf::from(std::env::var_os("TRNM_HIA_M05_CROSS_ARTIFACTS").expect("fresh artifacts"));
 std::fs::create_dir(&artifacts).unwrap();
 let file=std::fs::File::open(path).unwrap();let mut count=0;
 for line in std::io::BufReader::new(file).lines() {
  let item:Value=serde_json::from_str(&line.unwrap()).unwrap();
  assert_eq!(item["schema"],"trnm.single-node-m05-C-cross-history.v1");
  cross_invoke(&item,&artifacts);count+=1;
 }
 assert_eq!(count,1);
}

fn cross_metric_observation(value: &trnm_mvcc_fee::pon_executor::Output) -> Value {
    json!({"workers":value.metrics.workers,"workers_spawned":value.metrics.workers_spawned,
      "peak_inflight":value.metrics.peak_inflight,"committed_without_replay":value.metrics.committed_without_replay,
      "speculative":value.metrics.speculative,"reexecuted":value.metrics.reexecuted,
      "serial_conflict_batches":value.metrics.serial_conflict_batches,"signature_verifications":value.metrics.signature_verifications})
}
fn cross_commitment_observation(value: &trnm_mvcc_fee::pon_commitment::PreparedCommitment, before: &State, after: &State) -> Value {
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
