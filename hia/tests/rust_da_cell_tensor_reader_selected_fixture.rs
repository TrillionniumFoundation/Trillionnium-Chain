// Test-only child of the exact unchanged tensor.rs copy. No loader or resident
// handles: project a checked canonical range from its same inert Cursor bytes.
use crate::cell::{CellErrorV1, CellModelReleaseRootV1, CellTensorContractV1};
use std::fs::OpenOptions;
use std::io::{self, Cursor, Read, Write};
use std::time::{Duration, Instant};

const MARKER: &[u8] = b"TRNM_DA_TENSOR_SELECTED_EXACT_V1";
const OUTPUT_CAP: usize = (1 << 20) - 8;

fn split(input: &[u8], at: usize) -> (&[u8], &[u8]) {
    let size = u32::from_be_bytes(input[at..at + 4].try_into().unwrap()) as usize;
    input[at + 4..].split_at(size)
}

fn observe(input: &[u8], mut out: impl Write) -> io::Result<()> {
    let qn = u16::from_le_bytes(input[..2].try_into().unwrap()) as usize;
    let (query, frame) = input[2..].split_at(qn);
    let expected_pin = frame[..32].try_into().unwrap();
    let file_index = u16::from_be_bytes(frame[32..34].try_into().unwrap());
    let (contract, remainder) = split(frame, 34);
    let (root, payload) = split(remainder, 0);
    let result = (|| {
        let contract = CellTensorContractV1::decode(contract)?;
        let root = CellModelReleaseRootV1::decode(root)?;
        let mut reader = Cursor::new(payload);
        let layout = contract.verify_reader_layout(
            &root,
            expected_pin,
            file_index,
            &mut reader,
            Instant::now() + Duration::from_secs(60),
        )?;
        assert_eq!(reader.position(), payload.len() as u64);
        let declared = &contract.files()[contract
            .files()
            .binary_search_by_key(&file_index, |file| file.file_index)
            .unwrap()];
        assert_eq!(declared.tensors.len(), layout.ranges.len());
        // Exact bytewise lookup/order as the original declared tensor lookup.
        let picked = std::str::from_utf8(query).ok().and_then(|name| {
            declared
                .tensors
                .binary_search_by(|spec| spec.name.as_str().cmp(name))
                .ok()
        });
        Ok(picked.map(|j| {
            let (start, length) = layout.ranges[j];
            &payload[start as usize..(start + length) as usize]
        }))
    })();
    match result {
        Ok(Some(bytes)) => {
            out.write_all(&0u16.to_le_bytes())?;
            out.write_all(&(bytes.len() as u64).to_le_bytes())?;
            if bytes.len() <= OUTPUT_CAP {
                out.write_all(bytes)?;
            }
        }
        Ok(None) => {
            let missing = b"selected tensor missing";
            out.write_all(&(missing.len() as u16).to_le_bytes())?;
            out.write_all(missing)?;
        }
        Err(CellErrorV1::Invalid(reason)) => {
            out.write_all(&(reason.len() as u16).to_le_bytes())?;
            out.write_all(reason.as_bytes())?;
        }
        Err(other) => panic!("Unexpected original selected tensor result: {other:?}"),
    }
    Ok(())
}

#[test]
fn original_private_layout_observe() -> io::Result<()> {
    let path = std::env::var_os("TRNM_DA_TENSOR_LAYOUT_CAPTURE").expect("private capture path");
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let mut out = io::BufWriter::new(file);
    out.write_all(MARKER)?;
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut input = raw.as_slice();
    while !input.is_empty() {
        let n = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
        let (frame, rest) = input[4..].split_at(n);
        observe(frame, &mut out)?;
        input = rest;
    }
    out.flush()
}
