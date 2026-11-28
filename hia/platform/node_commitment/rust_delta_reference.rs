// Private cfg(test) child of the unchanged original pon_commitment module.
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

fn boundary_state(prefix:u8,count:usize)->State {
 let mut state=State::new();
 for i in 0..count {
  let key=format!("{}{:08x}",char::from(prefix),i);
  assert!(state.insert(key,Value::from(7u64)).is_none());
 }
 state
}
#[test]
fn evaluate() {
 let path=std::env::var("TRNM_HIA_DELTA_CORPUS").expect("source-bound actual Delta cases");
 let input:Vec<Value>=std::io::BufReader::new(std::fs::File::open(path).unwrap()).lines()
  .map(|line|serde_json::from_str(&line.unwrap()).unwrap()).collect();
 assert_eq!(input.len(),2);
 let mut retired_maps=Vec::new();
 for (index,row) in input.iter().enumerate() {
  let count=row["after_keys"].as_u64().unwrap() as usize;
  assert_eq!(row["before_keys"].as_u64(),Some(1));
  assert_eq!(count,if index==0 {65535} else {65536});
  assert_eq!(row["before_prefix"].as_str(),Some("a"));
  assert_eq!(row["after_prefix"].as_str(),Some("b"));
  assert_eq!(row["value"].as_u64(),Some(7));
  let before=boundary_state(b'a',1);
  let after=boundary_state(b'b',count);
  let mut seed=derive_snapshot(&before,None,CacheLimits::default()).unwrap();
  let snapshot=seed.snapshot.take().expect("actual complete prior snapshot");
  drop(seed);
  retired_maps.push(Arc::downgrade(&snapshot.values));
  let parent=CheckedExecutionParent::bind(&before,snapshot.root(),Some(&snapshot),CacheLimits::default()).unwrap();
  assert!(std::ptr::eq(parent.state,&before));
  assert!(Arc::ptr_eq(&parent.actual,&snapshot.values));
  let prepared=prepare_state_with_arithmetic(&after,parent.predecessor.as_ref(),Some(parent.actual.as_ref()),parent.limits,None).unwrap();
  assert_eq!(prepared.root,pon_executor::root(&after).unwrap());
  assert_eq!(prepared.changes.len(),count+1);
  if let Some(current)=prepared.snapshot.as_ref() {
   retired_maps.push(Arc::downgrade(&current.values));
   assert_eq!(index,0);
   assert_eq!(current.values.len(),count);
   assert_eq!(current.tree.allocated_nodes(),count*2-1);
   for (key,value) in current.values.iter() {assert_eq!(current.tree.get(key).unwrap(),Some(value.as_slice()));}
   assert_eq!(current.tree.root(),prepared.root);
  } else {assert_eq!(index,1);}
  println!("NDDELTA_ORIGINAL:{}",json!({"index":index,"after_keys":count,"before_keys":1,"observation":observed(&prepared)}));
  std::io::stdout().flush().unwrap();
  drop(prepared);drop(parent);drop(snapshot);drop(after);drop(before);
  assert!(retired_maps.iter().all(|weak|weak.upgrade().is_none()));
 }
 println!("NDDELTA_FINAL:{}",json!({"cases":2,"live_logical_owners":0,"retired_map_observations":retired_maps.len()}));
}
