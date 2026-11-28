// Private cfg(test) Some-history child of the unchanged original pon_commitment module.
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
   println!("NDSOME_ORIGINAL_ERROR:{}",json!({"index":index,"error":error,"status":code}));
   json!({"status":code})
  }
 }
}
fn emit(index: usize, input: &Value, observation: Value) {
 println!("NDSOME_ORIGINAL:{}",json!({"index":index,"op":input["op"],"observation":observation}));
 std::io::stdout().flush().unwrap();
}
#[test]
fn evaluate() {
 let path=std::env::var("TRNM_HIA_SOME_CORPUS").expect("source-bound Some corpus");
 let input:Vec<Value>=std::io::BufReader::new(std::fs::File::open(path).unwrap()).lines()
   .map(|line|serde_json::from_str(&line.unwrap()).unwrap()).collect();
 assert_eq!(input.len(),82);
 let mut retained_maps:Vec<std::sync::Weak<CanonicalValues>>=Vec::new();
 let state_empty=actual_state(&input[0]["rows"]);
 emit(0, &input[0], Value::Null);
 let state_original_invalid_seed=actual_state(&input[1]["rows"]);
 emit(1, &input[1], Value::Null);
 { let before=encode(&state_empty).unwrap(); let r=prepare_state_with_arithmetic(&state_original_invalid_seed,None,Some(&before),CacheLimits::default(),None);
 emit(2, &input[2], error_value(r,2));
 }
 let state_non_ascii_seed=actual_state(&input[3]["rows"]);
 emit(3, &input[3], Value::Null);
 { let before=encode(&state_empty).unwrap(); let r=prepare_state_with_arithmetic(&state_non_ascii_seed,None,Some(&before),CacheLimits::default(),None);
 emit(4, &input[4], error_value(r,4));
 }
 let state_base=actual_state(&input[5]["rows"]);
 emit(5, &input[5], Value::Null);
 let mut temporary_6=derive_snapshot(&state_base,None,CacheLimits::default()).unwrap();
 let snapshot_initial=temporary_6.snapshot.take().expect("actual complete snapshot"); drop(temporary_6);
 retained_maps.push(Arc::downgrade(&snapshot_initial.values));
 emit(6, &input[6], snapshot_observed(&snapshot_initial));
 let snapshot_initial_copy=snapshot_initial.clone();
 emit(7, &input[7], Value::Null);
 emit(8, &input[8], snapshot_observed(&snapshot_initial));
 emit(9, &input[9], snapshot_observed(&snapshot_initial_copy));
 let limits_10=CacheLimits{max_keys:input[10]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[10]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[10]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_10=snapshot_initial.root();
 let mut parent_parent=CheckedExecutionParent::bind(&state_base,expected_10,Some(&snapshot_initial),limits_10).unwrap();
 assert!(std::ptr::eq(parent_parent.state,&state_base)); assert!(Arc::ptr_eq(&parent_parent.actual,&snapshot_initial.values));
 emit(10, &input[10], json!({"status":0}));
 emit(11, &input[11], parent_observed(&parent_parent));
 let state_after_one=actual_state(&input[12]["rows"]);
 emit(12, &input[12], Value::Null);
 let limits_13=CacheLimits{max_keys:input[13]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[13]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[13]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_13=snapshot_initial.root();
 expected_13[0]^=1;
 emit(13, &input[13], error_value(CheckedExecutionParent::bind(&state_after_one,expected_13,Some(&snapshot_initial),limits_13),13));
 let limits_14=CacheLimits{max_keys:input[14]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[14]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[14]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_14=snapshot_initial.root();
 expected_14[0]^=1;
 emit(14, &input[14], error_value(CheckedExecutionParent::bind(&state_base,expected_14,Some(&snapshot_initial),limits_14),14));
 let state_late_limit=actual_state(&input[15]["rows"]);
 emit(15, &input[15], Value::Null);
 let limits_16=CacheLimits{max_keys:input[16]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[16]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[16]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_16=snapshot_initial.root();
 emit(16, &input[16], error_value(CheckedExecutionParent::bind(&state_late_limit,expected_16,Some(&snapshot_initial),limits_16),16));
 let limits_17=CacheLimits{max_keys:input[17]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[17]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[17]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_17=snapshot_initial.root();
 expected_17[0]^=1;
 emit(17, &input[17], error_value(CheckedExecutionParent::bind(&state_late_limit,expected_17,Some(&snapshot_initial),limits_17),17));
 let mut prepared_result_one=prepare_state_with_arithmetic(&state_after_one,parent_parent.predecessor.as_ref(),Some(parent_parent.actual.as_ref()),parent_parent.limits,None).unwrap();
 assert_eq!(prepared_result_one.root,pon_executor::root(&state_after_one).unwrap());
 if let Some(snapshot)=&prepared_result_one.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_18=observed(&prepared_result_one); observed_18["status"]=json!(0);
 emit(18, &input[18], observed_18);
 let mut prepared_result_one_copy=prepared_result_one.clone();
 if let (Some(a),Some(b))=(prepared_result_one.snapshot.as_ref(),prepared_result_one_copy.snapshot.as_ref()){assert!(Arc::ptr_eq(&a.values,&b.values));}
 emit(19, &input[19], Value::Null);
 emit(20, &input[20], observed(&prepared_result_one));
 emit(21, &input[21], observed(&prepared_result_one_copy));
 {let key=hex::decode(input[22]["key_hex"].as_str().unwrap()).unwrap();let value=prepared_result_one.snapshot.as_ref().unwrap().tree.get(&key).unwrap();
 emit(22, &input[22], json!({"found":if value.is_some(){1u64}else{0u64},"value_hex":value.map(hex::encode).unwrap_or_default()}));
 }
 {let key=hex::decode(input[23]["key_hex"].as_str().unwrap()).unwrap();let value=prepared_result_one.snapshot.as_ref().unwrap().tree.get(&key).unwrap();
 emit(23, &input[23], json!({"found":if value.is_some(){1u64}else{0u64},"value_hex":value.map(hex::encode).unwrap_or_default()}));
 }
 {let key=hex::decode(input[24]["key_hex"].as_str().unwrap()).unwrap();let value=prepared_result_one.snapshot.as_ref().unwrap().tree.get(&key).unwrap();
 emit(24, &input[24], json!({"found":if value.is_some(){1u64}else{0u64},"value_hex":value.map(hex::encode).unwrap_or_default()}));
 }
 {let key=hex::decode(input[25]["key_hex"].as_str().unwrap()).unwrap();let value=prepared_result_one.snapshot.as_ref().unwrap().tree.get(&key).unwrap();
 emit(25, &input[25], json!({"found":if value.is_some(){1u64}else{0u64},"value_hex":value.map(hex::encode).unwrap_or_default()}));
 }
 {let key=hex::decode(input[26]["key_hex"].as_str().unwrap()).unwrap();let value=prepared_result_one.snapshot.as_ref().unwrap().tree.get(&key).unwrap();
 emit(26, &input[26], json!({"found":if value.is_some(){1u64}else{0u64},"value_hex":value.map(hex::encode).unwrap_or_default()}));
 }
 let snapshot_next=prepared_result_one.snapshot.take().unwrap();drop(prepared_result_one);
 emit(27, &input[27], snapshot_observed(&snapshot_next));
 emit(28, &input[28], snapshot_observed(&snapshot_next));
 drop(prepared_result_one_copy);
 emit(29, &input[29], Value::Null);
 let state_after_two=actual_state(&input[30]["rows"]);
 emit(30, &input[30], Value::Null);
 let mut prepared_result_two=prepare_state_with_arithmetic(&state_after_two,parent_parent.predecessor.as_ref(),Some(parent_parent.actual.as_ref()),parent_parent.limits,None).unwrap();
 assert_eq!(prepared_result_two.root,pon_executor::root(&state_after_two).unwrap());
 if let Some(snapshot)=&prepared_result_two.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_31=observed(&prepared_result_two); observed_31["status"]=json!(0);
 emit(31, &input[31], observed_31);
 let mut prepared_same_parent=prepare_state_with_arithmetic(&state_base,parent_parent.predecessor.as_ref(),Some(parent_parent.actual.as_ref()),parent_parent.limits,None).unwrap();
 assert_eq!(prepared_same_parent.root,pon_executor::root(&state_base).unwrap());
 if let Some(snapshot)=&prepared_same_parent.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_32=observed(&prepared_same_parent); observed_32["status"]=json!(0);
 emit(32, &input[32], observed_32);
 let limits_33=CacheLimits{max_keys:input[33]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[33]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[33]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_33=snapshot_next.root();
 let mut parent_parent_next=CheckedExecutionParent::bind(&state_after_one,expected_33,Some(&snapshot_next),limits_33).unwrap();
 assert!(std::ptr::eq(parent_parent_next.state,&state_after_one)); assert!(Arc::ptr_eq(&parent_parent_next.actual,&snapshot_next.values));
 emit(33, &input[33], json!({"status":0}));
 let mut prepared_second_generation=prepare_state_with_arithmetic(&state_after_two,parent_parent_next.predecessor.as_ref(),Some(parent_parent_next.actual.as_ref()),parent_parent_next.limits,None).unwrap();
 assert_eq!(prepared_second_generation.root,pon_executor::root(&state_after_two).unwrap());
 if let Some(snapshot)=&prepared_second_generation.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_34=observed(&prepared_second_generation); observed_34["status"]=json!(0);
 emit(34, &input[34], observed_34);
 emit(35, &input[35], error_value(prepare_state_with_arithmetic(&state_late_limit,parent_parent.predecessor.as_ref(),Some(parent_parent.actual.as_ref()),parent_parent.limits,None),35));
 emit(36, &input[36], error_value(prepare_state_with_arithmetic(&state_original_invalid_seed,parent_parent.predecessor.as_ref(),Some(parent_parent.actual.as_ref()),parent_parent.limits,None),36));
 emit(37, &input[37], error_value(prepare_state_with_arithmetic(&state_non_ascii_seed,parent_parent.predecessor.as_ref(),Some(parent_parent.actual.as_ref()),parent_parent.limits,None),37));
 let limits_38=CacheLimits{max_keys:input[38]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[38]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[38]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_38=snapshot_initial.root();
 let mut parent_fallback_key=CheckedExecutionParent::bind(&state_base,expected_38,Some(&snapshot_initial),limits_38).unwrap();
 assert!(std::ptr::eq(parent_fallback_key.state,&state_base)); assert!(Arc::ptr_eq(&parent_fallback_key.actual,&snapshot_initial.values));
 emit(38, &input[38], json!({"status":0}));
 let mut prepared_fallback_result_key=prepare_state_with_arithmetic(&state_after_one,parent_fallback_key.predecessor.as_ref(),Some(parent_fallback_key.actual.as_ref()),parent_fallback_key.limits,None).unwrap();
 assert_eq!(prepared_fallback_result_key.root,pon_executor::root(&state_after_one).unwrap());
 if let Some(snapshot)=&prepared_fallback_result_key.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_39=observed(&prepared_fallback_result_key); observed_39["status"]=json!(0);
 emit(39, &input[39], observed_39);
 let missing_40=prepared_fallback_result_key.snapshot.take();
 emit(40, &input[40], json!({"status":if missing_40.is_none(){73}else{0}}));
 emit(41, &input[41], observed(&prepared_fallback_result_key));
 drop(parent_fallback_key);
 emit(42, &input[42], Value::Null);
 drop(prepared_fallback_result_key);
 emit(43, &input[43], Value::Null);
 let limits_44=CacheLimits{max_keys:input[44]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[44]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[44]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_44=snapshot_initial.root();
 let mut parent_fallback_payload=CheckedExecutionParent::bind(&state_base,expected_44,Some(&snapshot_initial),limits_44).unwrap();
 assert!(std::ptr::eq(parent_fallback_payload.state,&state_base)); assert!(Arc::ptr_eq(&parent_fallback_payload.actual,&snapshot_initial.values));
 emit(44, &input[44], json!({"status":0}));
 let mut prepared_fallback_result_payload=prepare_state_with_arithmetic(&state_after_one,parent_fallback_payload.predecessor.as_ref(),Some(parent_fallback_payload.actual.as_ref()),parent_fallback_payload.limits,None).unwrap();
 assert_eq!(prepared_fallback_result_payload.root,pon_executor::root(&state_after_one).unwrap());
 if let Some(snapshot)=&prepared_fallback_result_payload.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_45=observed(&prepared_fallback_result_payload); observed_45["status"]=json!(0);
 emit(45, &input[45], observed_45);
 let missing_46=prepared_fallback_result_payload.snapshot.take();
 emit(46, &input[46], json!({"status":if missing_46.is_none(){73}else{0}}));
 emit(47, &input[47], observed(&prepared_fallback_result_payload));
 drop(parent_fallback_payload);
 emit(48, &input[48], Value::Null);
 drop(prepared_fallback_result_payload);
 emit(49, &input[49], Value::Null);
 let limits_50=CacheLimits{max_keys:input[50]["limits"][0].as_u64().unwrap() as usize,max_payload_bytes:input[50]["limits"][1].as_u64().unwrap() as usize,max_workspace_charge_bytes:input[50]["limits"][2].as_u64().unwrap() as usize};
 let mut expected_50=snapshot_initial.root();
 let mut parent_fallback_workspace=CheckedExecutionParent::bind(&state_base,expected_50,Some(&snapshot_initial),limits_50).unwrap();
 assert!(std::ptr::eq(parent_fallback_workspace.state,&state_base)); assert!(Arc::ptr_eq(&parent_fallback_workspace.actual,&snapshot_initial.values));
 emit(50, &input[50], json!({"status":0}));
 let mut prepared_fallback_result_workspace=prepare_state_with_arithmetic(&state_after_one,parent_fallback_workspace.predecessor.as_ref(),Some(parent_fallback_workspace.actual.as_ref()),parent_fallback_workspace.limits,None).unwrap();
 assert_eq!(prepared_fallback_result_workspace.root,pon_executor::root(&state_after_one).unwrap());
 if let Some(snapshot)=&prepared_fallback_result_workspace.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_51=observed(&prepared_fallback_result_workspace); observed_51["status"]=json!(0);
 emit(51, &input[51], observed_51);
 let missing_52=prepared_fallback_result_workspace.snapshot.take();
 emit(52, &input[52], json!({"status":if missing_52.is_none(){73}else{0}}));
 emit(53, &input[53], observed(&prepared_fallback_result_workspace));
 drop(parent_fallback_workspace);
 emit(54, &input[54], Value::Null);
 drop(prepared_fallback_result_workspace);
 emit(55, &input[55], Value::Null);
 let saved_root_56=parent_parent.predecessor.as_ref().unwrap().root;
 parent_parent.predecessor.as_mut().unwrap().root[0]^=1;
 let evaluated_56=prepare_state_with_arithmetic(&state_after_one,parent_parent.predecessor.as_ref(),Some(parent_parent.actual.as_ref()),parent_parent.limits,None);
 parent_parent.predecessor.as_mut().unwrap().root=saved_root_56;
 let mut prepared_internal_fallback=evaluated_56.unwrap();
 assert_eq!(prepared_internal_fallback.root,pon_executor::root(&state_after_one).unwrap());
 if let Some(snapshot)=&prepared_internal_fallback.snapshot{retained_maps.push(Arc::downgrade(&snapshot.values));}
 let mut observed_56=observed(&prepared_internal_fallback); observed_56["status"]=json!(0);
 emit(56, &input[56], observed_56);
 drop(prepared_internal_fallback);
 emit(57, &input[57], Value::Null);
 drop(parent_parent);
 emit(58, &input[58], Value::Null);
 drop(parent_parent_next);
 emit(59, &input[59], Value::Null);
 drop(state_empty);
 emit(60, &input[60], Value::Null);
 drop(state_original_invalid_seed);
 emit(61, &input[61], Value::Null);
 drop(state_non_ascii_seed);
 emit(62, &input[62], Value::Null);
 drop(state_base);
 emit(63, &input[63], Value::Null);
 drop(state_after_one);
 emit(64, &input[64], Value::Null);
 drop(state_late_limit);
 emit(65, &input[65], Value::Null);
 drop(state_after_two);
 emit(66, &input[66], Value::Null);
 emit(67, &input[67], snapshot_observed(&snapshot_initial));
 emit(68, &input[68], snapshot_observed(&snapshot_initial_copy));
 emit(69, &input[69], snapshot_observed(&snapshot_next));
 emit(70, &input[70], observed(&prepared_result_two));
 {let key=hex::decode(input[71]["key_hex"].as_str().unwrap()).unwrap();let value=prepared_result_two.snapshot.as_ref().unwrap().tree.get(&key).unwrap();
 emit(71, &input[71], json!({"found":if value.is_some(){1u64}else{0u64},"value_hex":value.map(hex::encode).unwrap_or_default()}));
 }
 emit(72, &input[72], observed(&prepared_same_parent));
 {let key=hex::decode(input[73]["key_hex"].as_str().unwrap()).unwrap();let value=prepared_same_parent.snapshot.as_ref().unwrap().tree.get(&key).unwrap();
 emit(73, &input[73], json!({"found":if value.is_some(){1u64}else{0u64},"value_hex":value.map(hex::encode).unwrap_or_default()}));
 }
 emit(74, &input[74], observed(&prepared_second_generation));
 {let key=hex::decode(input[75]["key_hex"].as_str().unwrap()).unwrap();let value=prepared_second_generation.snapshot.as_ref().unwrap().tree.get(&key).unwrap();
 emit(75, &input[75], json!({"found":if value.is_some(){1u64}else{0u64},"value_hex":value.map(hex::encode).unwrap_or_default()}));
 }
 drop(prepared_result_two);
 emit(76, &input[76], Value::Null);
 drop(prepared_same_parent);
 emit(77, &input[77], Value::Null);
 drop(prepared_second_generation);
 emit(78, &input[78], Value::Null);
 drop(snapshot_initial);
 emit(79, &input[79], Value::Null);
 drop(snapshot_initial_copy);
 emit(80, &input[80], Value::Null);
 drop(snapshot_next);
 emit(81, &input[81], Value::Null);
 assert!(retained_maps.iter().all(|weak|weak.upgrade().is_none()),"real canonical maps retained after all owners dropped");
 println!("NDSOME_FINAL:{}",json!({"steps":82,"live_logical_owners":0,"retired_map_observations":retained_maps.len()}));
}
