// Private cfg(test) checked-snapshot-history child of the unchanged original pon_commitment module.
// Fixture decoding constructs serde Values; all commitment, tree, capacities,
// allocation markers, clone and query results are produced by original Rust.
use super::*;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
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

fn actual_state(rows: &Value) -> State {
    let mut state = State::new();
    for row in rows.as_array().unwrap() {
        let key = String::from_utf8(hex::decode(row["key_hex"].as_str().unwrap()).unwrap()).unwrap();
        let value = decode_value(&hex::decode(row["value_tape_hex"].as_str().unwrap()).unwrap());
        assert!(state.insert(key, value).is_none(), "duplicate top-level fixture key");
    }
    state
}
fn rows(values: &CanonicalValues) -> Vec<[String; 2]> {
    values.iter().map(|(k,v)| [hex::encode(k),hex::encode(v)]).collect()
}
fn capacities(values: &CanonicalValues) -> Vec<Value> {
    values.iter().map(|(k,v)| json!([hex::encode(k),v.capacity()])).collect()
}
fn snapshot_value(snapshot: Option<&CheckedCommitment>) -> Value {
    snapshot.map_or(Value::Null, |s| json!({
        "keys":s.keys(),"payload_bytes":s.payload_bytes(),
        "retained_charge_bytes":s.retained_charge_bytes(),
        "canonical_values":rows(&s.values),"root_hex":hex::encode(s.root()),
        "allocated_nodes":s.tree.allocated_nodes()
    }))
}

fn observed(prepared: &PreparedCommitment) -> Value {
 let changes:Vec<_>=prepared.changes.iter().map(|c|json!({
  "key_hex":hex::encode(&c.key),"before_hex":c.before.as_ref().map(hex::encode),
  "after_hex":c.after.as_ref().map(hex::encode)})).collect();
 json!({"root_hex":hex::encode(prepared.root),"changes":changes,
 "observation":{"method":format!("{:?}",prepared.observation.method),
 "actual_keys":prepared.observation.actual_keys,
 "actual_payload_bytes":prepared.observation.actual_payload_bytes,
 "changed_keys":prepared.observation.changed_keys,
 "changed_payload_bytes":prepared.observation.changed_payload_bytes,
 "compressed_nodes":prepared.observation.compressed_nodes,
 "workspace_charge_bytes":prepared.observation.workspace_charge_bytes},
 "snapshot":snapshot_value(prepared.snapshot.as_ref())})
}

fn snapshot_observed(s: &CheckedCommitment) -> Value {
 let mut value=snapshot_value(Some(s));
 value["map_refs"]=json!(Arc::strong_count(&s.values));
 for (key,expected) in s.values.iter(){ assert_eq!(s.tree.get(key).unwrap(),Some(expected.as_slice())); }
 assert_eq!(s.tree.root(),s.root());
 value
}
fn parent_observed(p: &CheckedExecutionParent<'_>) -> Value {
 let s=p.predecessor.as_ref().expect("actual Some predecessor");
 assert!(Arc::ptr_eq(&p.actual,&s.values));
 assert_eq!(rows(p.actual.as_ref()),rows(s.values.as_ref()));
 snapshot_observed(s)
}
fn commitment_observed(o: &CommitmentObservation) -> Value {
 json!({"method":format!("{:?}",o.method),"actual_keys":o.actual_keys,
 "actual_payload_bytes":o.actual_payload_bytes,"changed_keys":o.changed_keys,
 "changed_payload_bytes":o.changed_payload_bytes,"compressed_nodes":o.compressed_nodes,
 "workspace_charge_bytes":o.workspace_charge_bytes})
}
fn checked_parent_observed(p: &CheckedExecutionParent<'_>) -> Value {
 let root=state_root(p.actual.as_ref()).unwrap();
 if let Some(snapshot)=&p.predecessor {
  assert!(Arc::ptr_eq(&p.actual,&snapshot.values));
  assert_eq!(snapshot.root,root);
 }
 json!({"root_hex":hex::encode(root),"canonical_values":rows(p.actual.as_ref()),
 "map_refs":Arc::strong_count(&p.actual),"predecessor_present":p.predecessor.is_some(),
 "snapshot":p.predecessor.as_ref().map(snapshot_observed)})
}
fn error_value<T>(value: Result<T>, index: usize) -> Value {
 match value {
  Ok(_) => json!({"status":0}),
  Err(error) => {
   let code=match error {
    "LIMIT"=>69,"RANGE"=>70,"NONCANONICAL"=>71,
    "COMMITMENT_CHARGE"=>72,"COMMITMENT_CACHE_LIMIT"=>74,
    "COMMITMENT_ROOT"=>76,"COMMITMENT_PARENT"=>79,
    _=>panic!("unmapped actual original error: {error}"),
   };
   println!("NDCHECKED_ORIGINAL_ERROR:{}",json!({"index":index,"error":error,"status":code}));
   json!({"status":code})
  }
 }
}
fn emit(index: usize, input: &Value, observation: Value) {
 println!("NDCHECKED_ORIGINAL:{}",json!({"index":index,"op":input["op"],"observation":observation}));
 std::io::stdout().flush().unwrap();
}
#[test]
fn evaluate() {
 let path=std::env::var("TRNM_HIA_CHECKED_CORPUS").expect("source-bound Some corpus");
 let input:Vec<Value>=std::io::BufReader::new(std::fs::File::open(path).unwrap()).lines()
   .map(|line|serde_json::from_str(&line.unwrap()).unwrap()).collect();
 assert_eq!(input.len(),94);
 let mut retained_maps:Vec<std::sync::Weak<CanonicalValues>>=Vec::new();
 let state_empty=actual_state(&input[0]["rows"]);
 emit(0, &input[0], Value::Null);
 let state_base=actual_state(&input[1]["rows"]);
 emit(1, &input[1], Value::Null);
 let limits_2=CacheLimits{max_keys:input[2]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[2]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[2]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_2=pon_executor::root(&state_base).unwrap();
 let mut prepared_fresh=checked_snapshot(&state_base,expected_2,None,limits_2).unwrap();assert_eq!(prepared_fresh.root,pon_executor::root(&state_base).unwrap());
 if let Some(snapshot)=&prepared_fresh.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_2=observed(&prepared_fresh);observed_2["status"]=json!(0);
 emit(2, &input[2], observed_2);
 let mut snapshot_initial=prepared_fresh.snapshot.take().unwrap();drop(prepared_fresh);
 emit(3, &input[3], snapshot_observed(&snapshot_initial));
 let limits_4=CacheLimits{max_keys:input[4]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[4]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[4]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_4=pon_executor::root(&state_base).unwrap();
 let mut prepared_same=checked_snapshot(&state_base,expected_4,Some(&snapshot_initial),limits_4).unwrap();assert_eq!(prepared_same.root,pon_executor::root(&state_base).unwrap());
 if let Some(snapshot)=&prepared_same.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_4=observed(&prepared_same);observed_4["status"]=json!(0);
 emit(4, &input[4], observed_4);
 let mut prepared_same_copy=prepared_same.clone();
 if let (Some(a),Some(b))=(prepared_same.snapshot.as_ref(),prepared_same_copy.snapshot.as_ref()){assert!(Arc::ptr_eq(&a.values,&b.values));}
 emit(5, &input[5], Value::Null);
 let mut snapshot_same_snapshot=prepared_same.snapshot.take().unwrap();drop(prepared_same);
 emit(6, &input[6], snapshot_observed(&snapshot_same_snapshot));
 emit(7, &input[7], snapshot_observed(&snapshot_same_snapshot));
 drop(prepared_same_copy);
 emit(8, &input[8], Value::Null);
 drop(snapshot_same_snapshot);
 emit(9, &input[9], Value::Null);
 let state_changed=actual_state(&input[10]["rows"]);
 emit(10, &input[10], Value::Null);
 let limits_11=CacheLimits{max_keys:input[11]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[11]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[11]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_11=pon_executor::root(&state_changed).unwrap();
 let mut prepared_next_result=checked_snapshot(&state_changed,expected_11,Some(&snapshot_initial),limits_11).unwrap();assert_eq!(prepared_next_result.root,pon_executor::root(&state_changed).unwrap());
 if let Some(snapshot)=&prepared_next_result.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_11=observed(&prepared_next_result);observed_11["status"]=json!(0);
 emit(11, &input[11], observed_11);
 let mut snapshot_next=prepared_next_result.snapshot.take().unwrap();drop(prepared_next_result);
 emit(12, &input[12], snapshot_observed(&snapshot_next));
 let limits_13=CacheLimits{max_keys:input[13]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[13]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[13]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_13=pon_executor::root(&state_changed).unwrap();
 expected_13[0]^=1;
 emit(13, &input[13], error_value(checked_snapshot(&state_changed,expected_13,Some(&snapshot_initial),limits_13),13));
 let limits_14=CacheLimits{max_keys:input[14]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[14]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[14]["limits"][2].as_u64().unwrap() as usize};
 let expected_14=snapshot_initial.root();
 emit(14, &input[14], error_value(checked_snapshot(&state_changed,expected_14,Some(&snapshot_initial),limits_14),14));
 let limits_15=CacheLimits{max_keys:input[15]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[15]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[15]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_15=pon_executor::root(&state_base).unwrap();
 expected_15[0]^=1;
 emit(15, &input[15], error_value(checked_snapshot(&state_base,expected_15,None,limits_15),15));
 let state_same_count_changed=actual_state(&input[16]["rows"]);
 emit(16, &input[16], Value::Null);
 let limits_17=CacheLimits{max_keys:input[17]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[17]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[17]["limits"][2].as_u64().unwrap() as usize};
 let expected_17=snapshot_initial.root();
 emit(17, &input[17], error_value(checked_snapshot(&state_same_count_changed,expected_17,Some(&snapshot_initial),limits_17),17));
 let state_late_range=actual_state(&input[18]["rows"]);
 emit(18, &input[18], Value::Null);
 let state_late_key=actual_state(&input[19]["rows"]);
 emit(19, &input[19], Value::Null);
 let state_late_unicode=actual_state(&input[20]["rows"]);
 emit(20, &input[20], Value::Null);
 let limits_21=CacheLimits{max_keys:input[21]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[21]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[21]["limits"][2].as_u64().unwrap() as usize};
 let expected_21=snapshot_initial.root();
 emit(21, &input[21], error_value(checked_snapshot(&state_late_range,expected_21,Some(&snapshot_initial),limits_21),21));
 let limits_22=CacheLimits{max_keys:input[22]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[22]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[22]["limits"][2].as_u64().unwrap() as usize};
 let expected_22=[0u8;32];
 emit(22, &input[22], error_value(checked_snapshot(&state_late_range,expected_22,None,limits_22),22));
 let limits_23=CacheLimits{max_keys:input[23]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[23]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[23]["limits"][2].as_u64().unwrap() as usize};
 let expected_23=snapshot_initial.root();
 emit(23, &input[23], error_value(checked_snapshot(&state_late_key,expected_23,Some(&snapshot_initial),limits_23),23));
 let limits_24=CacheLimits{max_keys:input[24]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[24]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[24]["limits"][2].as_u64().unwrap() as usize};
 let expected_24=[0u8;32];
 emit(24, &input[24], error_value(checked_snapshot(&state_late_key,expected_24,None,limits_24),24));
 let limits_25=CacheLimits{max_keys:input[25]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[25]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[25]["limits"][2].as_u64().unwrap() as usize};
 let expected_25=snapshot_initial.root();
 emit(25, &input[25], error_value(checked_snapshot(&state_late_unicode,expected_25,Some(&snapshot_initial),limits_25),25));
 let limits_26=CacheLimits{max_keys:input[26]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[26]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[26]["limits"][2].as_u64().unwrap() as usize};
 let expected_26=[0u8;32];
 emit(26, &input[26], error_value(checked_snapshot(&state_late_unicode,expected_26,None,limits_26),26));
 let limits_27=CacheLimits{max_keys:input[27]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[27]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[27]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_27=pon_executor::root(&state_base).unwrap();
 expected_27[0]^=1;
 emit(27, &input[27], error_value(checked_snapshot(&state_base,expected_27,Some(&snapshot_initial),limits_27),27));
 let limits_28=CacheLimits{max_keys:input[28]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[28]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[28]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_28=pon_executor::root(&state_base).unwrap();
 let mut prepared_fallback_key=checked_snapshot(&state_base,expected_28,Some(&snapshot_initial),limits_28).unwrap();assert_eq!(prepared_fallback_key.root,pon_executor::root(&state_base).unwrap());
 if let Some(snapshot)=&prepared_fallback_key.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_28=observed(&prepared_fallback_key);observed_28["status"]=json!(0);
 emit(28, &input[28], observed_28);
 let missing_29=prepared_fallback_key.snapshot.take();
 emit(29, &input[29], json!({"status":if missing_29.is_none(){73}else{0}}));
 drop(prepared_fallback_key);
 emit(30, &input[30], Value::Null);
 let limits_31=CacheLimits{max_keys:input[31]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[31]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[31]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_31=pon_executor::root(&state_base).unwrap();
 let (mut parent_fallback_parent_key,observation_31)=CheckedExecutionParent::check_and_bind(&state_base,expected_31,Some(&snapshot_initial),limits_31).unwrap();
 assert!(std::ptr::eq(parent_fallback_parent_key.state,&state_base));retained_maps.push(Arc::downgrade(&parent_fallback_parent_key.actual));
 emit(31, &input[31], json!({"status":0,"parent":checked_parent_observed(&parent_fallback_parent_key),"preparation":commitment_observed(&observation_31)}));
 let mut prepared_fallback_prepare_key=prepare_state_with_arithmetic(&state_changed,parent_fallback_parent_key.predecessor.as_ref(),Some(parent_fallback_parent_key.actual.as_ref()),parent_fallback_parent_key.limits,None).unwrap();
 assert_eq!(prepared_fallback_prepare_key.root,pon_executor::root(&state_changed).unwrap());
 if let Some(snapshot)=&prepared_fallback_prepare_key.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_32=observed(&prepared_fallback_prepare_key); observed_32["status"]=json!(0);
 emit(32, &input[32], observed_32);
 drop(prepared_fallback_prepare_key);
 emit(33, &input[33], Value::Null);
 drop(parent_fallback_parent_key);
 emit(34, &input[34], Value::Null);
 let limits_35=CacheLimits{max_keys:input[35]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[35]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[35]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_35=pon_executor::root(&state_base).unwrap();
 let mut prepared_fallback_payload=checked_snapshot(&state_base,expected_35,Some(&snapshot_initial),limits_35).unwrap();assert_eq!(prepared_fallback_payload.root,pon_executor::root(&state_base).unwrap());
 if let Some(snapshot)=&prepared_fallback_payload.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_35=observed(&prepared_fallback_payload);observed_35["status"]=json!(0);
 emit(35, &input[35], observed_35);
 let missing_36=prepared_fallback_payload.snapshot.take();
 emit(36, &input[36], json!({"status":if missing_36.is_none(){73}else{0}}));
 drop(prepared_fallback_payload);
 emit(37, &input[37], Value::Null);
 let limits_38=CacheLimits{max_keys:input[38]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[38]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[38]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_38=pon_executor::root(&state_base).unwrap();
 let (mut parent_fallback_parent_payload,observation_38)=CheckedExecutionParent::check_and_bind(&state_base,expected_38,Some(&snapshot_initial),limits_38).unwrap();
 assert!(std::ptr::eq(parent_fallback_parent_payload.state,&state_base));retained_maps.push(Arc::downgrade(&parent_fallback_parent_payload.actual));
 emit(38, &input[38], json!({"status":0,"parent":checked_parent_observed(&parent_fallback_parent_payload),"preparation":commitment_observed(&observation_38)}));
 let mut prepared_fallback_prepare_payload=prepare_state_with_arithmetic(&state_changed,parent_fallback_parent_payload.predecessor.as_ref(),Some(parent_fallback_parent_payload.actual.as_ref()),parent_fallback_parent_payload.limits,None).unwrap();
 assert_eq!(prepared_fallback_prepare_payload.root,pon_executor::root(&state_changed).unwrap());
 if let Some(snapshot)=&prepared_fallback_prepare_payload.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_39=observed(&prepared_fallback_prepare_payload); observed_39["status"]=json!(0);
 emit(39, &input[39], observed_39);
 drop(prepared_fallback_prepare_payload);
 emit(40, &input[40], Value::Null);
 drop(parent_fallback_parent_payload);
 emit(41, &input[41], Value::Null);
 let limits_42=CacheLimits{max_keys:input[42]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[42]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[42]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_42=pon_executor::root(&state_base).unwrap();
 let mut prepared_fallback_workspace=checked_snapshot(&state_base,expected_42,Some(&snapshot_initial),limits_42).unwrap();assert_eq!(prepared_fallback_workspace.root,pon_executor::root(&state_base).unwrap());
 if let Some(snapshot)=&prepared_fallback_workspace.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_42=observed(&prepared_fallback_workspace);observed_42["status"]=json!(0);
 emit(42, &input[42], observed_42);
 let missing_43=prepared_fallback_workspace.snapshot.take();
 emit(43, &input[43], json!({"status":if missing_43.is_none(){73}else{0}}));
 drop(prepared_fallback_workspace);
 emit(44, &input[44], Value::Null);
 let limits_45=CacheLimits{max_keys:input[45]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[45]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[45]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_45=pon_executor::root(&state_base).unwrap();
 let (mut parent_fallback_parent_workspace,observation_45)=CheckedExecutionParent::check_and_bind(&state_base,expected_45,Some(&snapshot_initial),limits_45).unwrap();
 assert!(std::ptr::eq(parent_fallback_parent_workspace.state,&state_base));retained_maps.push(Arc::downgrade(&parent_fallback_parent_workspace.actual));
 emit(45, &input[45], json!({"status":0,"parent":checked_parent_observed(&parent_fallback_parent_workspace),"preparation":commitment_observed(&observation_45)}));
 let mut prepared_fallback_prepare_workspace=prepare_state_with_arithmetic(&state_changed,parent_fallback_parent_workspace.predecessor.as_ref(),Some(parent_fallback_parent_workspace.actual.as_ref()),parent_fallback_parent_workspace.limits,None).unwrap();
 assert_eq!(prepared_fallback_prepare_workspace.root,pon_executor::root(&state_changed).unwrap());
 if let Some(snapshot)=&prepared_fallback_prepare_workspace.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_46=observed(&prepared_fallback_prepare_workspace); observed_46["status"]=json!(0);
 emit(46, &input[46], observed_46);
 drop(prepared_fallback_prepare_workspace);
 emit(47, &input[47], Value::Null);
 drop(parent_fallback_parent_workspace);
 emit(48, &input[48], Value::Null);
 let limits_49=CacheLimits{max_keys:input[49]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[49]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[49]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_49=pon_executor::root(&state_base).unwrap();
 expected_49[0]^=1;
 emit(49, &input[49], error_value(checked_snapshot(&state_base,expected_49,Some(&snapshot_initial),limits_49),49));
 let limits_50=CacheLimits{max_keys:input[50]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[50]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[50]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_50=pon_executor::root(&state_base).unwrap();
 expected_50[0]^=1;
 emit(50, &input[50], error_value(CheckedExecutionParent::check_and_bind(&state_base,expected_50,Some(&snapshot_initial),limits_50),50));
 let limits_51=CacheLimits{max_keys:input[51]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[51]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[51]["limits"][2].as_u64().unwrap() as usize};
 let expected_51=[0u8;32];
 emit(51, &input[51], error_value(CheckedExecutionParent::check_and_bind(&state_late_range,expected_51,Some(&snapshot_initial),limits_51),51));
 let limits_52=CacheLimits{max_keys:input[52]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[52]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[52]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_52=pon_executor::root(&state_base).unwrap();
 let (mut parent_parent_none,observation_52)=CheckedExecutionParent::check_and_bind(&state_base,expected_52,None,limits_52).unwrap();
 assert!(std::ptr::eq(parent_parent_none.state,&state_base));retained_maps.push(Arc::downgrade(&parent_parent_none.actual));
 emit(52, &input[52], json!({"status":0,"parent":checked_parent_observed(&parent_parent_none),"preparation":commitment_observed(&observation_52)}));
 let mut prepared_none_parent_next=prepare_state_with_arithmetic(&state_changed,parent_parent_none.predecessor.as_ref(),Some(parent_parent_none.actual.as_ref()),parent_parent_none.limits,None).unwrap();
 assert_eq!(prepared_none_parent_next.root,pon_executor::root(&state_changed).unwrap());
 if let Some(snapshot)=&prepared_none_parent_next.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_53=observed(&prepared_none_parent_next); observed_53["status"]=json!(0);
 emit(53, &input[53], observed_53);
 let mut snapshot_bound_next=prepared_none_parent_next.snapshot.take().unwrap();drop(prepared_none_parent_next);
 emit(54, &input[54], snapshot_observed(&snapshot_bound_next));
 drop(parent_parent_none);
 emit(55, &input[55], Value::Null);
 let limits_56=CacheLimits{max_keys:input[56]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[56]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[56]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_56=pon_executor::root(&state_base).unwrap();
 let (mut parent_parent_some,observation_56)=CheckedExecutionParent::check_and_bind(&state_base,expected_56,Some(&snapshot_initial),limits_56).unwrap();
 assert!(std::ptr::eq(parent_parent_some.state,&state_base));retained_maps.push(Arc::downgrade(&parent_parent_some.actual));
 emit(56, &input[56], json!({"status":0,"parent":checked_parent_observed(&parent_parent_some),"preparation":commitment_observed(&observation_56)}));
 let mut prepared_parent_result_one=prepare_state_with_arithmetic(&state_changed,parent_parent_some.predecessor.as_ref(),Some(parent_parent_some.actual.as_ref()),parent_parent_some.limits,None).unwrap();
 assert_eq!(prepared_parent_result_one.root,pon_executor::root(&state_changed).unwrap());
 if let Some(snapshot)=&prepared_parent_result_one.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_57=observed(&prepared_parent_result_one); observed_57["status"]=json!(0);
 emit(57, &input[57], observed_57);
 let mut prepared_parent_result_two=prepare_state_with_arithmetic(&state_base,parent_parent_some.predecessor.as_ref(),Some(parent_parent_some.actual.as_ref()),parent_parent_some.limits,None).unwrap();
 assert_eq!(prepared_parent_result_two.root,pon_executor::root(&state_base).unwrap());
 if let Some(snapshot)=&prepared_parent_result_two.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_58=observed(&prepared_parent_result_two); observed_58["status"]=json!(0);
 emit(58, &input[58], observed_58);
 let limits_59=CacheLimits{max_keys:input[59]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[59]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[59]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_59=pon_executor::root(&state_empty).unwrap();
 let mut prepared_empty_result=checked_snapshot(&state_empty,expected_59,None,limits_59).unwrap();assert_eq!(prepared_empty_result.root,pon_executor::root(&state_empty).unwrap());
 if let Some(snapshot)=&prepared_empty_result.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_59=observed(&prepared_empty_result);observed_59["status"]=json!(0);
 emit(59, &input[59], observed_59);
 let mut snapshot_empty_snapshot=prepared_empty_result.snapshot.take().unwrap();drop(prepared_empty_result);
 emit(60, &input[60], snapshot_observed(&snapshot_empty_snapshot));
 let limits_61=CacheLimits{max_keys:input[61]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[61]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[61]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_61=pon_executor::root(&state_empty).unwrap();
 let mut prepared_empty_same=checked_snapshot(&state_empty,expected_61,Some(&snapshot_empty_snapshot),limits_61).unwrap();assert_eq!(prepared_empty_same.root,pon_executor::root(&state_empty).unwrap());
 if let Some(snapshot)=&prepared_empty_same.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_61=observed(&prepared_empty_same);observed_61["status"]=json!(0);
 emit(61, &input[61], observed_61);
 drop(prepared_empty_same);
 emit(62, &input[62], Value::Null);
 let limits_63=CacheLimits{max_keys:input[63]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[63]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[63]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_63=pon_executor::root(&state_empty).unwrap();
 let mut prepared_empty_budget=checked_snapshot(&state_empty,expected_63,Some(&snapshot_empty_snapshot),limits_63).unwrap();assert_eq!(prepared_empty_budget.root,pon_executor::root(&state_empty).unwrap());
 if let Some(snapshot)=&prepared_empty_budget.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_63=observed(&prepared_empty_budget);observed_63["status"]=json!(0);
 emit(63, &input[63], observed_63);
 drop(prepared_empty_budget);
 emit(64, &input[64], Value::Null);
 let limits_65=CacheLimits{max_keys:input[65]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[65]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[65]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_65=pon_executor::root(&state_base).unwrap();
 let mut prepared_exact_budget=checked_snapshot(&state_base,expected_65,Some(&snapshot_initial),limits_65).unwrap();assert_eq!(prepared_exact_budget.root,pon_executor::root(&state_base).unwrap());
 if let Some(snapshot)=&prepared_exact_budget.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_65=observed(&prepared_exact_budget);observed_65["status"]=json!(0);
 emit(65, &input[65], observed_65);
 drop(prepared_exact_budget);
 emit(66, &input[66], Value::Null);
 let limits_67=CacheLimits{max_keys:input[67]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[67]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[67]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_67=pon_executor::root(&state_base).unwrap();
 let mut prepared_under_budget=checked_snapshot(&state_base,expected_67,Some(&snapshot_initial),limits_67).unwrap();assert_eq!(prepared_under_budget.root,pon_executor::root(&state_base).unwrap());
 if let Some(snapshot)=&prepared_under_budget.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_67=observed(&prepared_under_budget);observed_67["status"]=json!(0);
 emit(67, &input[67], observed_67);
 drop(prepared_under_budget);
 emit(68, &input[68], Value::Null);
 let limits_69=CacheLimits{max_keys:input[69]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[69]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[69]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_69=pon_executor::root(&state_changed).unwrap();
 let saved_root_69=snapshot_initial.root;snapshot_initial.root[0]^=1;
 let evaluated_69=checked_snapshot(&state_changed,expected_69,Some(&snapshot_initial),limits_69);snapshot_initial.root=saved_root_69;
 let mut prepared_internal_fallback=evaluated_69.unwrap();assert_eq!(prepared_internal_fallback.root,pon_executor::root(&state_changed).unwrap());
 if let Some(snapshot)=&prepared_internal_fallback.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_69=observed(&prepared_internal_fallback);observed_69["status"]=json!(0);
 emit(69, &input[69], observed_69);
 let missing_70=prepared_internal_fallback.snapshot.take();
 emit(70, &input[70], json!({"status":if missing_70.is_none(){73}else{0}}));
 drop(prepared_internal_fallback);
 emit(71, &input[71], Value::Null);
 let limits_72=CacheLimits{max_keys:input[72]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[72]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[72]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_72=pon_executor::root(&state_base).unwrap();
 let mut prepared_hidden_gate=checked_snapshot(&state_base,expected_72,Some(&snapshot_initial),limits_72).unwrap();assert_eq!(prepared_hidden_gate.root,pon_executor::root(&state_base).unwrap());
 if let Some(snapshot)=&prepared_hidden_gate.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_72=observed(&prepared_hidden_gate);observed_72["status"]=json!(0);
 emit(72, &input[72], observed_72);
 drop(prepared_hidden_gate);
 emit(73, &input[73], Value::Null);
 drop(parent_parent_some);
 emit(74, &input[74], Value::Null);
 drop(state_empty);
 emit(75, &input[75], Value::Null);
 drop(state_base);
 emit(76, &input[76], Value::Null);
 drop(state_changed);
 emit(77, &input[77], Value::Null);
 drop(state_same_count_changed);
 emit(78, &input[78], Value::Null);
 drop(state_late_range);
 emit(79, &input[79], Value::Null);
 drop(state_late_key);
 emit(80, &input[80], Value::Null);
 drop(state_late_unicode);
 emit(81, &input[81], Value::Null);
 emit(82, &input[82], observed(&prepared_parent_result_one));
 emit(83, &input[83], observed(&prepared_parent_result_two));
 emit(84, &input[84], snapshot_observed(&snapshot_initial));
 emit(85, &input[85], snapshot_observed(&snapshot_next));
 emit(86, &input[86], snapshot_observed(&snapshot_bound_next));
 emit(87, &input[87], snapshot_observed(&snapshot_empty_snapshot));
 drop(prepared_parent_result_one);
 emit(88, &input[88], Value::Null);
 drop(prepared_parent_result_two);
 emit(89, &input[89], Value::Null);
 drop(snapshot_initial);
 emit(90, &input[90], Value::Null);
 drop(snapshot_next);
 emit(91, &input[91], Value::Null);
 drop(snapshot_bound_next);
 emit(92, &input[92], Value::Null);
 drop(snapshot_empty_snapshot);
 emit(93, &input[93], Value::Null);
 assert!(retained_maps.iter().all(|weak|weak.upgrade().is_none()),"real canonical maps retained after all owners dropped");
 println!("NDCHECKED_FINAL:{}",json!({"steps":94,"live_logical_owners":0,"retired_map_observations":retained_maps.len()}));
}
