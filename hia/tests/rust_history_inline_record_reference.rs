//! Only held ValueRef observations from local in-memory constant SELECTs.
use std::error::Error as _;
use std::io::{self, Write};
use rusqlite::{types::{Value, ValueRef}, Connection, params_from_iter};
use trnm_pon_node::{Error, Result, consensus::Work};
type Hash = [u8; 32];
include!("frozen_inline_record.rs");

fn frame(row: &rusqlite::Row<'_>) -> Vec<u8> {
    let mut result = b"HIR1\0\0\0\0".to_vec();
    let mut bytes = Vec::new();
    for col in 0..4 {
        let (tag, raw) = match row.get_ref(col).unwrap() {
            ValueRef::Null => (0u64, vec![]),
            ValueRef::Integer(v) => (1, v.to_le_bytes().to_vec()),
            ValueRef::Real(v) => (2, v.to_le_bytes().to_vec()),
            ValueRef::Text(v) => (3, v.to_vec()),
            ValueRef::Blob(v) => (4, v.to_vec()),
        };
        result.extend_from_slice(&tag.to_le_bytes());
        result.extend_from_slice(&(raw.len() as u64).to_le_bytes());
        bytes.extend(raw);
    }
    result.extend(bytes);
    result
}

fn main() {
    use Value::{Blob, Integer, Null, Real, Text};
    let db = Connection::open_in_memory().unwrap();
    let mut statement = db.prepare("SELECT ?1 AS parent, ?2 AS height, ?3 AS work, ?4 AS root").unwrap();
    let p = Blob((0..32).map(|i| i + 0x20).collect());
    let w = Blob((0..64).map(|i| i + 0x50).collect());
    let r = Blob((0..32).map(|i| i + 0x90).collect());
    let baseline = [p.clone(), Integer(7), w.clone(), r.clone()];
    let mut panel = vec![(0u32,baseline.clone())];
    let mut add = |status, changes: Vec<(usize,Value)>| {
        let mut values = baseline.clone();
        for (i,v) in changes { values[i]=v; }
        panel.push((status,values));
    };
    add(0,vec![(0,Null),(1,Integer(0))]);
    add(0,vec![(1,Integer(i64::MAX))]);
    for (idx,status) in [(0,10),(1,11),(2,12),(3,13)] {
        for invalid in [Real(1.0),Text("7".into())] { add(status,vec![(idx,invalid)]); }
    }
    add(11,vec![(1,Null)]);
    add(11,vec![(1,Blob(vec![7;8]))]);
    add(12,vec![(2,Null)]);
    add(13,vec![(3,Null)]);
    add(14,vec![(1,Integer(-1))]);
    add(14,vec![(1,Integer(i64::MIN)),(3,Text("late".into()))]);
    for n in [0,31,33,4096] { add(30,vec![(0,Blob(vec![2;n]))]); }
    for n in [0,63,65,4096] { add(31,vec![(2,Blob(vec![3;n]))]); }
    for n in [0,31,33,4096] { add(30,vec![(3,Blob(vec![4;n]))]); }
    add(12,vec![(0,Blob(vec![0;33])),(2,Text("earlier shape".into()))]);
    add(13,vec![(0,Blob(vec![0;31])),(2,Blob(vec![0;63])),(3,Integer(1))]);
    add(10,vec![(0,Integer(0)),(1,Integer(-1)),(2,Text("type".into()))]);
    add(30,vec![(0,Blob(vec![0;31])),(2,Blob(vec![0;63]))]);
    add(31,vec![(2,Blob(vec![0;63])),(3,Blob(vec![0;31]))]);

    let mut out = io::stdout().lock();
    for (expected,values) in panel {
        let mut rows=statement.query(params_from_iter(&values)).unwrap();
        let row=rows.next().unwrap().unwrap();
        let input=frame(row);
        let mut output=Vec::new();
        let code=match inline_record(row,0) {
            Ok(record) => {
                output.extend_from_slice(&u64::from(record.parent.is_some()).to_le_bytes());
                output.extend_from_slice(&record.parent.unwrap_or([0;32]));
                output.extend_from_slice(&record.height.to_le_bytes());
                output.extend_from_slice(&record.work.bytes());
                output.extend_from_slice(&record.root);
                0
            }
            Err(err) => match err.source().and_then(|source| source.downcast_ref::<rusqlite::Error>()) {
                Some(rusqlite::Error::InvalidColumnType(n,_,_)) => 10+*n as u32,
                Some(rusqlite::Error::IntegralValueOutOfRange(1,_)) => 14,
                Some(other) => panic!("Unexpected locked rusqlite status {other:?}"),
                None => match err.to_string().as_str() {
                    "STORAGE_HASH" => 30,
                    "STORAGE_WORK" => 31,
                    other => panic!("Unexpected original refusal {other}"),
                },
            },
        };
        assert_eq!(code,expected);
        assert!(rows.next().unwrap().is_none());
        out.write_all(&(input.len() as u32).to_le_bytes()).unwrap();
        out.write_all(&code.to_le_bytes()).unwrap();
        out.write_all(&(output.len() as u32).to_le_bytes()).unwrap();
        out.write_all(&input).unwrap();
        out.write_all(&output).unwrap();
    }
}
