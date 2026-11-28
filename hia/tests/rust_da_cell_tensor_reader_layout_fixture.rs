// A test-only child of an exact tracked tensor.rs copy. No production source
// changes, file reader, owner handle or provider access.
use crate::cell::{CellErrorV1, CellModelReleaseRootV1, CellTensorContractV1};
use std::fs::OpenOptions;
use std::io::{self, Cursor, Read, Write};
use std::time::{Duration, Instant};

const MARKER: &[u8] = b"TRNM_DA_TENSOR_LAYOUT_EXACT_V1";

fn split(input: &[u8], at: usize) -> (&[u8], &[u8]) {
    let size = u32::from_be_bytes(input[at..at + 4].try_into().unwrap()) as usize;
    input[at + 4..].split_at(size)
}

fn observe(frame: &[u8], mut out: impl Write) -> io::Result<()> {
    let expected_pin = frame[..32].try_into().unwrap();
    let requested_file = u16::from_be_bytes(frame[32..34].try_into().unwrap());
    let (contract, remainder) = split(frame, 34);
    let (root, payload) = split(remainder, 0);
    let result = (|| {
        let contract = CellTensorContractV1::decode(contract)?;
        let root = CellModelReleaseRootV1::decode(root)?;
        let mut reader = Cursor::new(payload);
        let layout = contract.verify_reader_layout(
            &root,
            expected_pin,
            requested_file,
            &mut reader,
            Instant::now() + Duration::from_secs(60),
        )?;
        assert_eq!(reader.position(), payload.len() as u64);
        Ok(layout)
    })();
    match result {
        Ok(layout) => {
            let v = layout.readback;
            assert_eq!(layout.ranges.len(), v.tensor_count);
            out.write_all(&0u16.to_le_bytes())?;
            out.write_all(&v.contract_id)?;
            out.write_all(&v.model_root)?;
            out.write_all(&v.file_index.to_le_bytes())?;
            out.write_all(&(v.tensor_count as u64).to_le_bytes())?;
            out.write_all(&v.payload_bytes.to_le_bytes())?;
            out.write_all(&v.payload_sha256)?;
            for (offset, length) in layout.ranges {
                out.write_all(&offset.to_le_bytes())?;
                out.write_all(&length.to_le_bytes())?;
            }
        }
        Err(CellErrorV1::Invalid(reason)) => {
            out.write_all(&(reason.len() as u16).to_le_bytes())?;
            out.write_all(reason.as_bytes())?;
        }
        Err(other) => panic!("Unexpected original tensor layout result: {other:?}"),
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
