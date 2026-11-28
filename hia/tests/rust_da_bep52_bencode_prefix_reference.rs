// Exact private original parser; inclusion is only in this offline witness.
use std::io::{self, Read, Write};
use trnm_data_availability::cell::{CellErrorV1, CellResultV1};

include!(env!("HIA_BENCODE_ORIGINAL_REQUIRE"));

#[allow(dead_code)]
#[path = "../../trillionnium/crates/trnm-data-availability/src/cell/bep52_peer/bencode.rs"]
mod bencode;

fn project(value: &bencode::Value<'_>) -> (u64, u64) {
    match value {
        bencode::Value::Bytes(_) => (1, 1),
        bencode::Value::Integer(_) => (2, 1),
        bencode::Value::List(values) => (3, 1 + values.iter().map(|x| project(x).1).sum::<u64>()),
        bencode::Value::Dictionary(values) => {
            (4, 1 + values.iter().map(|(_, x)| project(x).1).sum::<u64>())
        }
    }
}

fn status(message: &'static str) -> u8 {
    match message {
        "BEP52 bencode complexity" => 20,
        "BEP52 bencode value" => 21,
        "BEP52 bencode string bound" => 22,
        "BEP52 bencode string length" => 23,
        "BEP52 bencode string canonical" => 24,
        "BEP52 bencode string truncated" => 25,
        "BEP52 bencode integer bound" => 26,
        "BEP52 bencode integer end" => 27,
        "BEP52 bencode integer empty" => 28,
        "BEP52 bencode integer digits" => 29,
        "BEP52 bencode integer canonical" => 30,
        "BEP52 bencode negative zero" => 31,
        "BEP52 bencode key order/duplicate" => 32,
        "BEP52 bencode integer overflow" => 33,
        _ => panic!("unexpected frozen error category: {message}"),
    }
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let mut out = io::BufWriter::new(io::stdout().lock());
    let mut remaining = input.as_slice();
    while !remaining.is_empty() {
        let (len, body) = remaining.split_at(4);
        let n = u32::from_le_bytes(len.try_into().expect("witness frame length")) as usize;
        let (row, rest) = body.split_at(n);
        remaining = rest;
        match bencode::decode(row) {
            Ok((value, count)) => {
                let (kind, items) = project(&value);
                out.write_all(&[0])?;
                for word in [kind, count as u64, items] {
                    out.write_all(&word.to_be_bytes())?;
                }
            }
            Err(CellErrorV1::Invalid(message)) => out.write_all(&[status(message)])?,
            Err(other) => panic!("unexpected frozen result: {other:?}"),
        }
    }
    out.flush()
}
