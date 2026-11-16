// Test-only adapter appended below the unchanged pon_executor module.
// Every View and Patch operation calls the original method. Safe leaked,
// immutable base clones retain actual View<'static> values across JSON steps;
// their backing allocation is reclaimed by process exit, not claimed as an
// original allocation/lifetime differential. Native owns/reclaims its objects.
use super::*;
use std::io::{BufRead, Write};

struct BorrowedView {
    value: View<'static>,
    _base_id: u64,
}
enum Item {
    Value(Value),
    State(State),
    View(BorrowedView),
    Patch(Patch),
}
struct Registry {
    next: u64,
    objects: BTreeMap<u64, Item>,
    labels: BTreeMap<String, u64>,
    calls: BTreeMap<String, u64>,
    borrowed_base_materializations: u64,
}
impl Registry {
    fn new() -> Self {
        Self { next: 1, objects: BTreeMap::new(), labels: BTreeMap::new(),
            calls: BTreeMap::new(), borrowed_base_materializations: 0 }
    }
    fn called(&mut self, name: &str) {
        *self.calls.entry(name.to_owned()).or_default() += 1;
    }
    fn put(&mut self, item: Item) -> u64 {
        let id = self.next;
        self.next = self.next.checked_add(1).expect("oracle serial exhaustion");
        assert!(self.objects.insert(id, item).is_none());
        id
    }
    fn label(&self, step: &Value, field: &str) -> u64 {
        step.get(field).map_or(0, |v| self.labels[v.as_str().unwrap()])
    }
    fn state(&self, id: u64) -> &State {
        match &self.objects[&id] { Item::State(s) => s, _ => panic!("not a State") }
    }
    fn state_mut(&mut self, id: u64) -> &mut State {
        match self.objects.get_mut(&id).unwrap() { Item::State(s) => s, _ => panic!("not a State") }
    }
    fn value(&self, id: u64) -> &Value {
        match &self.objects[&id] { Item::Value(v) => v, _ => panic!("not a Value") }
    }
    fn take_value(&mut self, id: u64) -> Value {
        match self.objects.remove(&id).unwrap() { Item::Value(v) => v, _ => panic!("not a Value") }
    }
    fn view(&mut self, id: u64) -> &mut View<'static> {
        match self.objects.get_mut(&id).unwrap() { Item::View(v) => &mut v.value, _ => panic!("not a View") }
    }
    fn patch(&self, id: u64) -> &Patch {
        match &self.objects[&id] { Item::Patch(p) => p, _ => panic!("not a Patch") }
    }
    fn optional_value(&mut self, value: Option<Value>) -> u64 {
        value.map_or(0, |v| self.put(Item::Value(v)))
    }
    fn step(&mut self, step: &Value, sequence: u64) -> Value {
        let name = step["op"].as_str().unwrap();
        let a = self.label(step, "a");
        let b = self.label(step, "b");
        let key = String::from_utf8(hex::decode(step.get("key_hex").and_then(Value::as_str).unwrap_or("")).unwrap()).unwrap();
        let data = hex::decode(step.get("data_hex").and_then(Value::as_str).unwrap_or("")).unwrap();
        let mut result = 0_u64;
        let mut output = Vec::new();
        let mut status = 0_u64;
        let mut original_error: Option<&str> = None;
        let op = match name {
            "value.new" => {
                self.called("serde_json::Value construction");
                result = self.put(Item::Value(decode_value(&data)));
                1
            }
            "value.clone" => {
                self.called("Value::clone");
                result = self.put(Item::Value(self.value(a).clone()));
                2
            }
            "value.export" => {
                output = encode_value(self.value(a));
                3
            }
            "value.drop" => {
                self.called("drop(Value)");
                drop(self.take_value(a));
                4
            }
            "state.new" => {
                self.called("State::new");
                result = self.put(Item::State(State::new()));
                5
            }
            "state.clone" => {
                self.called("State::clone");
                result = self.put(Item::State(self.state(a).clone()));
                6
            }
            "state.drop" => {
                self.called("drop(State)");
                match self.objects.remove(&a).unwrap() { Item::State(s) => drop(s), _ => panic!("not a State") }
                7
            }
            "state.put" => {
                self.called("State::insert");
                let value = self.take_value(b);
                let old = self.state_mut(a).insert(key, value);
                result = self.optional_value(old);
                8
            }
            "state.get" => {
                self.called("State::get.cloned");
                let value = self.state(a).get(&key).cloned();
                result = self.optional_value(value);
                9
            }
            "state.remove" => {
                self.called("State::remove");
                let old = self.state_mut(a).remove(&key);
                result = self.optional_value(old);
                10
            }
            "state.export" => {
                output = encode_state(self.state(a));
                11
            }
            "state.clear" => {
                self.called("State::clear");
                self.state_mut(a).clear();
                12
            }
            "view.new" => {
                self.called("View::new");
                let base = Box::leak(Box::new(self.state(a).clone()));
                let value = View::new(base, None);
                self.borrowed_base_materializations += 1;
                result = self.put(Item::View(BorrowedView { value, _base_id: a }));
                13
            }
            "view.get" => {
                self.called("View::get");
                let value = self.view(a).get(&key);
                result = self.optional_value(value);
                14
            }
            "view.put" => {
                self.called("View::put");
                let value = self.take_value(b);
                self.view(a).put(key, value);
                15
            }
            "view.scan" => {
                self.called("View::scan");
                let state = self.view(a).scan(&key);
                result = self.put(Item::State(state));
                16
            }
            "view.drop" => {
                self.called("drop(View)");
                match self.objects.remove(&a).unwrap() { Item::View(v) => drop(v), _ => panic!("not a View") }
                17
            }
            "patch.take" => {
                self.called("Patch field move from original View");
                let view = match self.objects.remove(&a).unwrap() { Item::View(v) => v.value, _ => panic!("not a View") };
                let patch = Patch { writes: view.writes, reads: view.reads, scans: view.scans,
                    fee: step.get("arg").and_then(Value::as_u64).unwrap_or(0), receipt: data };
                result = self.put(Item::Patch(patch));
                18
            }
            "patch.clone" => {
                self.called("Patch::clone");
                result = self.put(Item::Patch(self.patch(a).clone()));
                19
            }
            "patch.current" => {
                self.called("Patch::current");
                result = u64::from(self.patch(a).current(self.state(b)));
                20
            }
            "patch.apply" => {
                self.called("Patch::apply");
                let patch = match self.objects.remove(&a).unwrap() { Item::Patch(p) => p, _ => panic!("not a Patch") };
                patch.apply(self.state_mut(b));
                21
            }
            "patch.drop" => {
                self.called("drop(Patch)");
                match self.objects.remove(&a).unwrap() { Item::Patch(p) => drop(p), _ => panic!("not a Patch") }
                22
            }
            "patch.export" => {
                output = encode_patch(self.patch(a));
                23
            }
            "state.root" => {
                self.called("pon_executor::root");
                match root(self.state(a)) {
                    Ok(value) => output.extend_from_slice(&value),
                    Err(error) => { original_error = Some(error); status = match error {
                        "LIMIT" => 69, "RANGE" => 70, "NONCANONICAL" => 71,
                        other => panic!("unmapped original root error: {other}"),
                    }; }
                }
                24
            }
            "state.prefix" => {
                self.called("prefix_rows.cloned.collect");
                let state = prefix_rows(self.state(a), &key).map(|(k,v)| (k.clone(),v.clone())).collect();
                result = self.put(Item::State(state));
                25
            }
            "close" => {
                self.called("drop(all original owner values)");
                self.objects.clear();
                26
            }
            "value.eq" => {
                self.called("Value::eq");
                result = u64::from(self.value(a) == self.value(b));
                27
            }
            other => panic!("unknown operation {other}"),
        };
        if let Some(label) = step.get("as") { self.labels.insert(label.as_str().unwrap().to_owned(), result); }
        json!({"observation":{"op":op,"sequence":sequence,"status":status,"result":result,
            "data_hex":hex::encode(output),"live_objects":self.objects.len()},"original_error":original_error})
    }
}

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

#[test]
fn evaluate() {
    let path=std::env::var("TRNM_HIA_EXECUTION_STATE_CORPUS").expect("required exact corpus");
    let file=std::fs::File::open(path).unwrap();let reader=std::io::BufReader::new(file);let mut count=0;
    for line in reader.lines() {
        let line=line.unwrap();let case:Value=serde_json::from_str(&line).unwrap();assert_eq!(case["schema"],"trnm.execution-state-history.v1");
        let mut registry=Registry::new();let mut observations=Vec::new();let mut original_errors=Vec::new();
        for (index,step) in case["commands"].as_array().unwrap().iter().enumerate() {
            let row=registry.step(step,(index+1) as u64);observations.push(row["observation"].clone());original_errors.push(row["original_error"].clone());
        }
        assert!(registry.objects.is_empty(),"history must close all owner values");
        let record=json!({"name":case["name"],"observations":observations,"original_errors":original_errors,"actual_method_calls":registry.calls,"borrowed_base_materializations":registry.borrowed_base_materializations,"safe_test_base_clone":true,"native_runtime_host_proxy":false});
        println!("SVP_ORIGINAL:{}",serde_json::to_string(&record).unwrap());std::io::stdout().flush().unwrap();count+=1;
    }
    assert!(count>0,"empty corpus is not a differential");
}
