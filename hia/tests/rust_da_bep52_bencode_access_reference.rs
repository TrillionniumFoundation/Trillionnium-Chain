// Test-only projection of the unchanged original borrowed offline accessors.
use std::io::{self, Read, Write};
use trnm_data_availability::cell::{CellErrorV1, CellResultV1};

include!(env!("HIA_BENCODE_ORIGINAL_REQUIRE"));

#[path = "../../trillionnium/crates/trnm-data-availability/src/cell/bep52_peer/bencode.rs"]
mod bencode;
use bencode::Value;

fn bytes(raw: &[u8], out: &mut Vec<u8>) {
    out.extend(raw.len().to_string().bytes());
    out.push(b':');
    out.extend_from_slice(raw);
}

fn encode(v: &Value<'_>, out: &mut Vec<u8>) {
    match v {
        Value::Bytes(raw) => bytes(raw, out),
        Value::Integer(n) => {
            out.push(b'i');
            out.extend(n.to_string().bytes());
            out.push(b'e');
        }
        Value::List(xs) => {
            out.push(b'l');
            for x in xs {
                encode(x, out);
            }
            out.push(b'e');
        }
        Value::Dictionary(xs) => {
            out.push(b'd');
            for (k, x) in xs {
                bytes(k, out);
                encode(x, out);
            }
            out.push(b'e');
        }
    }
}

fn kind(v: &Value<'_>) -> u64 {
    match v {
        Value::Bytes(_) => 1,
        Value::Integer(_) => 2,
        Value::List(_) => 3,
        Value::Dictionary(_) => 4,
    }
}

// Recover a selected decoded object's encoded range by reencoding the actual
// original dictionary in its frozen order. The complete reencoding is compared
// to the original consumed bytes before this projection is admitted.
fn span(root: &Value<'_>, selected: &Value<'_>) -> CellResultV1<(u64, u64)> {
    let mut prefix = vec![b'd'];
    for (key, value) in root.dictionary()? {
        bytes(key, &mut prefix);
        let start = prefix.len() as u64;
        encode(value, &mut prefix);
        if std::ptr::eq(value, selected) {
            return Ok((start, prefix.len() as u64));
        }
    }
    panic!("frozen accessor failed to point inside original decoded dictionary");
}

fn observe(raw: &[u8], key: &[u8], mode: u8) -> CellResultV1<[u64; 4]> {
    let (value, consumed) = bencode::decode(raw)?;
    let root = &value;
    let mut canonical = Vec::new();
    encode(root, &mut canonical);
    assert_eq!(canonical, raw[..consumed]);
    let end = consumed as u64;
    Ok(match mode {
        0 => [4, 0, end, root.dictionary()?.len() as u64],
        1 | 2 => {
            let got = if mode == 1 { root.optional(key)? } else { Some(root.field(key)?) };
            if let Some(value) = got {
                let (start, stop) = span(root, value)?;
                [kind(value), start, stop, 0]
            } else {
                [0, 0, 0, 0]
            }
        }
        3 => {
            let number = root.number(key)?;
            let (start, stop) = span(root, root.field(key)?)?;
            [2, start, stop, number]
        }
        4 => [2, 0, end, root.integer()?],
        5 => {
            let data = root.bytes()?;
            assert_eq!(data.as_ptr(), raw[consumed - data.len()..].as_ptr());
            [1, end - data.len() as u64, end, 0]
        }
        6 => [3, 0, end, root.list()?.len() as u64],
        _ => panic!("unknown fixture mode"),
    })
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
        "BEP52 bencode dictionary" => 40,
        "BEP52 bencode unsigned integer" => 41,
        "BEP52 bencode bytes" => 42,
        "BEP52 bencode list" => 43,
        "BEP52 bencode required field" => 44,
        _ => panic!("unexpected frozen error category: {message}"),
    }
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let mut out = io::BufWriter::new(io::stdout().lock());
    let mut remain = input.as_slice();
    while !remain.is_empty() {
        let (len, data) = remain.split_at(4);
        let n = u32::from_le_bytes(len.try_into().unwrap()) as usize;
        let (batch, rest) = data.split_at(n);
        remain = rest;
        let footer = batch.len() - 5;
        let n = u32::from_be_bytes(batch[footer..footer + 4].try_into().unwrap()) as usize;
        match observe(&batch[..n], &batch[n..footer], batch[footer + 4]) {
            Ok(record) => {
                out.write_all(&[0])?;
                for value in record {
                    out.write_all(&value.to_be_bytes())?;
                }
            }
            Err(CellErrorV1::Invalid(message)) => out.write_all(&[status(message)])?,
            Err(other) => panic!("unexpected frozen result: {other:?}"),
        }
    }
    out.flush()
}
