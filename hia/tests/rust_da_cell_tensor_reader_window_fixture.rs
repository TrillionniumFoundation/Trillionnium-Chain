// Test-only child of exact frozen residency/tensor.rs. The original complete
// layout is computed on inert synthetic bytes before any borrowed byte view.
use super::{CellResidentFileV1, CellResidentTensorFileV1};
use crate::cell::{CellErrorV1, CellModelReleaseRootV1, CellTensorContractV1};
use std::fs::OpenOptions;
use std::io::{self, Cursor, Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MARKER: &[u8] = b"TRNM_DA_TENSOR_WINDOW_EXACT_V1";
const OUTPUT_CAP: usize = (1 << 20) - 8;
const FIXTURE_CAP: usize = 3 << 20;
const CHUNK: usize = 16_384;

fn split(input: &[u8], at: usize) -> (&[u8], &[u8]) {
    let size = u32::from_be_bytes(input[at..at + 4].try_into().unwrap()) as usize;
    input[at + 4..].split_at(size)
}

fn observe(input: &[u8], mut out: impl Write) -> io::Result<()> {
    let qn = u16::from_le_bytes(input[..2].try_into().unwrap()) as usize;
    let (query, frame) = input[2..].split_at(qn);
    let offset = u64::from_le_bytes(query[..8].try_into().unwrap());
    let amount = u64::from_le_bytes(query[8..16].try_into().unwrap()) as usize;
    assert!(amount <= FIXTURE_CAP);
    let expected_pin = frame[..32].try_into().unwrap();
    let file_index = u16::from_be_bytes(frame[32..34].try_into().unwrap());
    let (contract, remainder) = split(frame, 34);
    let (root, payload) = split(remainder, 0);
    let result: Result<Option<Vec<u8>>, CellErrorV1> = (|| {
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
        let spec = &contract.files()[contract
            .files()
            .binary_search_by_key(&file_index, |file| file.file_index)
            .unwrap()];
        let exact = &root.closure().files()[usize::from(file_index)];
        // The local backing file has no resident manager or authorization.
        // Its ordered Arc slices are precisely the same already checked bytes.
        let file = CellResidentFileV1 {
            path: exact.path.clone(),
            role: exact.role,
            manifest_id: exact.manifest,
            payload_sha256: layout.readback.payload_sha256,
            chunks: payload.chunks(CHUNK).map(Arc::from).collect(),
        };
        let stored = CellResidentTensorFileV1 {
            file: &file,
            spec,
            ranges: layout.ranges,
            readback: layout.readback,
        };
        let Some(view) = std::str::from_utf8(&query[16..])
            .ok()
            .and_then(|name| stored.tensor(name))
        else {
            return Ok(None);
        };
        let mut copied = vec![0xa5; amount];
        let actual = view.copy_bytes(offset, &mut copied);
        if actual.is_err() {
            assert!(copied.iter().all(|&byte| byte == 0xa5));
        }
        actual?;
        Ok(Some(copied))
    })();
    match result {
        Ok(Some(bytes)) => {
            out.write_all(&0u16.to_le_bytes())?;
            out.write_all(&(bytes.len() as u64).to_le_bytes())?;
            if bytes.len() <= OUTPUT_CAP {
                out.write_all(&bytes)?;
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
        Err(other) => panic!("Unexpected original tensor window result: {other:?}"),
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
