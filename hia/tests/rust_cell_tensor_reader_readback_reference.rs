use std::io::{self, Cursor, Read, Write};
use std::time::{Duration, Instant};
use trnm_data_availability::cell::{CellErrorV1, CellModelReleaseRootV1, CellTensorContractV1};

fn split(input: &[u8], at: usize) -> (&[u8], &[u8]) {
    let size = u32::from_be_bytes(input[at..at + 4].try_into().unwrap()) as usize;
    input[at + 4..].split_at(size)
}

fn observe(frame: &[u8], mut out: impl Write) -> io::Result<()> {
    let expected_pin = frame[..32].try_into().unwrap();
    let requested_file = u16::from_be_bytes(frame[32..34].try_into().unwrap());
    let (contract, remainder) = split(frame, 34);
    let (root, payload) = split(remainder, 0);
    let observation = (|| {
        let contract = CellTensorContractV1::decode(contract)?;
        let root = CellModelReleaseRootV1::decode(root)?;
        let mut reader = Cursor::new(payload);
        let value = contract.verify_reader(
            &root,
            expected_pin,
            requested_file,
            &mut reader,
            Instant::now() + Duration::from_secs(60),
        )?;
        assert_eq!(reader.position(), payload.len() as u64);
        Ok(value)
    })();
    match observation {
        Ok(value) => {
            out.write_all(&0u16.to_le_bytes())?;
            out.write_all(&value.contract_id)?;
            out.write_all(&value.model_root)?;
            out.write_all(&value.file_index.to_le_bytes())?;
            out.write_all(&(value.tensor_count as u64).to_le_bytes())?;
            out.write_all(&value.payload_bytes.to_le_bytes())?;
            out.write_all(&value.payload_sha256)?;
        }
        Err(CellErrorV1::Invalid(reason)) => {
            out.write_all(&(reason.len() as u16).to_le_bytes())?;
            out.write_all(reason.as_bytes())?;
        }
        Err(other) => panic!("Unexpected original reader result: {other:?}"),
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut input = raw.as_slice();
    let mut out = io::BufWriter::new(io::stdout().lock());
    while !input.is_empty() {
        let n = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
        let (frame, rest) = input[4..].split_at(n);
        observe(frame, &mut out)?;
        input = rest;
    }
    out.flush()
}
