//! Test-only oracle: every JSON parse/serialization and M06 verdict comes from
//! the retained crates. This file does not reproduce their canonical grammar.
//!
//! First compile the actual locked crate into a fresh target directory:
//! cargo build --locked --manifest-path trillionnium/Cargo.toml \
//!   -p trnm-mvcc-fee --target-dir /absolute/fresh/reference-target
//! Then rustc --edition=2021 -O this_file.rs \
//!   --extern trnm_mvcc_fee=.../debug/libtrnm_mvcc_fee.rlib \
//!   --extern serde_json=.../debug/deps/libserde_json-EXACT.rlib \
//!   -L dependency=.../debug/deps -o /absolute/reference
//! Require exactly one serde_json rlib in that fresh target; never choose an
//! arbitrary stale feature variant.
//!
//! Lines: `string HEX`, `json HEX`, `state HEX`, or `tape HEX`;
//! '-' denotes empty bytes. Tape decoding only constructs original Value/Map
//! objects; its object insertion invokes the actual Map last-wins semantics.
//! Results are one JSON object per input. Root LIMIT for a singleton value
//! means M06's grammar passed before its wire value limit; this is not an
//! alternate grammar checker or a waiver of the State limit.

use std::io::{self, BufRead, Write};
use serde_json::{json, Value};
use trnm_mvcc_fee::pon_executor::{root, State};

fn unhex(text: &str) -> Result<Vec<u8>, &'static str> {
    if text == "-" { return Ok(Vec::new()); }
    if text.len() % 2 != 0 { return Err("odd hex"); }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let digit = |b: u8| -> Option<u8> {
            match b { b'0'..=b'9' => Some(b-b'0'), b'a'..=b'f' => Some(b-b'a'+10),
                      b'A'..=b'F' => Some(b-b'A'+10), _ => None }
        };
        out.push((digit(pair[0]).ok_or("hex")? << 4) | digit(pair[1]).ok_or("hex")?);
    }
    Ok(out)
}

fn hex(raw: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(raw.len()*2);
    for byte in raw { out.push(DIGITS[(byte >> 4) as usize] as char); out.push(DIGITS[(byte & 15) as usize] as char); }
    out
}

fn value_result(value: Value) -> Value {
    let state = State::from([(String::new(), value)]);
    // Original root performs its complete grammar pass before serialization
    // and wire limits. Do not serialize an already rejected Value first.
    let (grammar, result) = match root(&state) {
        Ok(hash) => ("OK", hex(&hash)),
        Err("LIMIT") => ("OK", "LIMIT".to_owned()),
        Err(error) => (error, error.to_owned()),
    };
    let canonical = if grammar == "OK" {
        Some(hex(&serde_json::to_vec(state.get("").expect("singleton")).expect("accepted Value serializes")))
    } else { None };
    let singleton = state.get("").expect("singleton");
    let string_bytes = singleton.as_str().map(|text| hex(text.as_bytes()));
    json!({"parse":"OK","grammar":grammar,"root":result,"canonical":canonical,
           "string":singleton.is_string(),"string_bytes":string_bytes})
}

struct Tape<'a> { raw: &'a [u8], position: usize, nodes: usize }
impl<'a> Tape<'a> {
    fn bytes(&mut self, count: usize, end: usize) -> Result<&'a [u8], &'static str> {
        let next = self.position.checked_add(count).ok_or("FRAME")?;
        if next > end { return Err("FRAME"); }
        let result = self.raw.get(self.position..next).ok_or("FRAME")?;
        self.position = next;
        Ok(result)
    }
    fn u32(&mut self, end: usize) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(self.bytes(4,end)?.try_into().map_err(|_| "FRAME")?))
    }
    fn node(&mut self, enclosing: usize) -> Result<Value, &'static str> {
        let tag = self.bytes(1,enclosing)?[0];
        let count = self.u32(enclosing)? as usize;
        let end = self.position.checked_add(count).ok_or("FRAME")?;
        if end > enclosing || tag > 8 { return Err("FRAME"); }
        // Local node shape precedes the explicit constructor-node capacity,
        // matching the JVT1 admission contract, not a new M06 semantic limit.
        match tag {
            0..=2 if count != 0 => return Err("FRAME"),
            3..=5 if count != 8 => return Err("FRAME"),
            5 => {
                let bytes: [u8; 8] = self.raw[self.position..end].try_into().map_err(|_| "FRAME")?;
                if serde_json::Number::from_f64(f64::from_le_bytes(bytes)).is_none() { return Err("FRAME"); }
            },
            6 => { std::str::from_utf8(&self.raw[self.position..end]).map_err(|_| "FRAME")?; },
            7..=8 if count < 4 => return Err("FRAME"),
            _ => (),
        }
        if self.nodes >= 8192 { return Err("CAPACITY"); }
        self.nodes += 1;
        let value = match tag {
            0 if count == 0 => Value::Null,
            1 if count == 0 => Value::Bool(false),
            2 if count == 0 => Value::Bool(true),
            3 if count == 8 => Value::from(u64::from_le_bytes(self.bytes(8,end)?.try_into().map_err(|_| "FRAME")?)),
            4 if count == 8 => Value::from(i64::from_le_bytes(self.bytes(8,end)?.try_into().map_err(|_| "FRAME")?)),
            5 if count == 8 => Value::Number(serde_json::Number::from_f64(f64::from_le_bytes(
                self.bytes(8,end)?.try_into().map_err(|_| "FRAME")?)).ok_or("FRAME")?),
            6 => Value::String(String::from_utf8(self.bytes(count,end)?.to_vec()).map_err(|_| "FRAME")?),
            7 => {
                let entries = self.u32(end)?;
                let mut values = Vec::new();
                for _ in 0..entries { values.push(self.node(end)?); }
                Value::Array(values)
            },
            8 => {
                let entries = self.u32(end)?;
                let mut values = serde_json::Map::new();
                for _ in 0..entries {
                    let length = self.u32(end)? as usize;
                    let key = String::from_utf8(self.bytes(length,end)?.to_vec()).map_err(|_| "FRAME")?;
                    let value = self.node(end)?;
                    values.insert(key,value);
                }
                Value::Object(values)
            },
            _ => return Err("FRAME"),
        };
        if self.position != end { return Err("FRAME"); }
        Ok(value)
    }
}

fn tape_value(raw: &[u8]) -> Result<Value, &'static str> {
    if !raw.starts_with(b"JVT1") { return Err("FRAME"); }
    if raw.len() > 65536 { return Err("CAPACITY"); }
    let mut decoder = Tape { raw, position: 4, nodes: 0 };
    let value = decoder.node(raw.len())?;
    if decoder.position != raw.len() { return Err("FRAME"); }
    Ok(value)
}

fn run(line: &str) -> Value {
    let mut fields = line.split_whitespace();
    let Some(operation) = fields.next() else { return json!({"parse":"FRAME"}); };
    let Some(encoded) = fields.next() else { return json!({"parse":"FRAME"}); };
    if fields.next().is_some() { return json!({"parse":"FRAME"}); }
    let raw = match unhex(encoded) { Ok(raw) => raw, Err(error) => return json!({"parse":"FRAME","error":error}) };
    match operation {
        "string" => match String::from_utf8(raw) {
            Ok(text) => value_result(Value::String(text)),
            Err(error) => json!({"parse":"UTF8","error":error.to_string()}),
        },
        "json" => match serde_json::from_slice::<Value>(&raw) {
            Ok(value) => value_result(value),
            Err(error) => json!({"parse":"JSON","error":error.to_string()}),
        },
        "tape" => match tape_value(&raw) {
            Ok(value) => value_result(value),
            Err(error) => json!({"parse":"TAPE","error":error}),
        },
        "state" => match serde_json::from_slice::<State>(&raw) {
            Ok(state) => {
                let result = root(&state).map(|hash| hex(&hash)).unwrap_or_else(|error| error.to_owned());
                let canonical = if result == "LIMIT" || result.len() == 64 {
                    Some(hex(&serde_json::to_vec(&state).expect("accepted State serializes")))
                } else { None };
                json!({"parse":"OK","root":result,"canonical":canonical})
            },
            Err(error) => json!({"parse":"JSON","error":error.to_string()}),
        },
        _ => json!({"parse":"FRAME"}),
    }
}

fn evaluate_input() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        serde_json::to_writer(&mut out, &run(&line)).expect("stdout");
        out.write_all(b"\n").expect("newline");
        out.flush().expect("flush");
    }
}

fn main() {
    // Test resource profile only. The new tape can construct values deeper
    // than serde's text-parser recursion profile. Preserve those original
    // Value/root/serialization/drop calls without restricting the HIA domain
    // to the executable's default thread stack. Any panic/abort still fails.
    std::thread::Builder::new()
        .name("trnm-hia-state-reference".to_owned())
        .stack_size(64 * 1024 * 1024)
        .spawn(evaluate_input)
        .expect("reference thread")
        .join()
        .expect("reference evaluation");
}
