// The test driver puts the exact, source-hashed original functions/types here.
// Only the fixture projection below is new. It does not translate parsing.
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use std::collections::{BTreeMap, BTreeSet};
use std::{fmt, io::{self, Read, Write}};
include!("original_tensor_header.rs");

fn write_text(out: &mut impl Write, value: &str) -> io::Result<()> {
    out.write_all(&(value.len() as u64).to_le_bytes())?;
    out.write_all(value.as_bytes())
}

fn main() -> io::Result<()> {
    let mut fixtures = Vec::new();
    io::stdin().read_to_end(&mut fixtures)?;
    let mut fixtures = fixtures.as_slice();
    let mut out = io::BufWriter::new(io::stdout().lock());
    while !fixtures.is_empty() {
        let size = u32::from_le_bytes(fixtures[..4].try_into().unwrap()) as usize;
        let (bytes, rest) = fixtures[4..].split_at(size);
        fixtures = rest;
        match serde_json::from_slice::<TensorHeader>(bytes) {
            Ok(value) => {
                let mut projection = Vec::new();
                projection.extend((value.tensors.len() as u64).to_le_bytes());
                for (name, item) in value.tensors {
                    write_text(&mut projection, &name)?;
                    write_text(&mut projection, &item.dtype)?;
                    projection.extend((item.shape.len() as u64).to_le_bytes());
                    for component in item.shape.into_iter().chain(item.data_offsets) {
                        projection.extend(component.to_le_bytes());
                    }
                }
                out.write_all(&[0])?;
                out.write_all(&(projection.len() as u32).to_le_bytes())?;
                out.write_all(&projection)?;
            }
            Err(_) => out.write_all(&[217, 0, 0, 0, 0])?,
        }
    }
    out.flush()
}
