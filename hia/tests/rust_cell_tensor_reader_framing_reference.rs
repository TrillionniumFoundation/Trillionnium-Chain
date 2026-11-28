use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};
use trnm_data_availability::cell::{
    CellErrorV1, CellModelReleaseRootV1, CellTensorContractV1, CellTensorReadbackV1,
};

#[derive(Default)]
struct Trace<'a> {
    cursor: Cursor<&'a [u8]>,
    reads: Vec<(u64, u64)>,
    seeks: u64,
}

impl Read for Trace<'_> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        let before = self.cursor.position();
        let length = self.cursor.read(dst)?;
        self.reads.push((before, length as u64));
        Ok(length)
    }
}

impl Seek for Trace<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.seeks += 1;
        self.cursor.seek(from)
    }
}

fn split(input: &[u8], at: usize) -> (&[u8], &[u8]) {
    let size = u32::from_be_bytes(input[at..at + 4].try_into().unwrap()) as usize;
    input[at + 4..].split_at(size)
}

fn observe<W: Write>(frame: &[u8], mut out: W) -> io::Result<()> {
    let pin = frame[..32].try_into().unwrap();
    let index = u16::from_be_bytes(frame[32..34].try_into().unwrap());
    let (contract, remainder) = split(frame, 34);
    let (root, file) = split(remainder, 0);
    let mut trace = Trace {
        cursor: Cursor::new(file),
        ..Trace::default()
    };
    let observed: Result<CellTensorReadbackV1, CellErrorV1> = (|| {
        let contract = CellTensorContractV1::decode(contract)?;
        let root = CellModelReleaseRootV1::decode(root)?;
        contract.verify_reader(
            &root,
            pin,
            index,
            &mut trace,
            Instant::now() + Duration::from_secs(60),
        )
    })();
    let message = match &observed {
        Ok(readback) => {
            assert_eq!(readback.file_index, index);
            assert_eq!(readback.contract_id, pin);
            assert_eq!(readback.payload_bytes, file.len() as u64);
            assert_eq!(readback.payload_sha256, <[u8; 32]>::from(Sha256::digest(file)));
            "ok"
        }
        Err(CellErrorV1::Invalid(message)) => *message,
        Err(other) => panic!("unexpected original result {other:?}"),
    };
    out.write_all(&(message.len() as u16).to_le_bytes())?;
    out.write_all(message.as_bytes())?;
    out.write_all(&trace.seeks.to_le_bytes())?;
    out.write_all(&(trace.reads.len() as u64).to_le_bytes())?;
    for (start, len) in trace.reads.iter().copied() {
        out.write_all(&start.to_le_bytes())?;
        out.write_all(&len.to_le_bytes())?;
    }
    if observed.is_ok()
        || matches!(
            message,
            "tensor header JSON"
                | "tensor roster coverage"
                | "tensor roster metadata"
                | "tensor data range"
                | "tensor overlap or hole"
                | "tensor trailing data"
                | "tensor payload digest"
        )
    {
        let (0, 8) = trace.reads[0] else {
            panic!("original did not read the exact LE64 prefix");
        };
        let (8, hlen) = trace.reads[1] else {
            panic!("original did not read the exact declared header");
        };
        let blen = file.len() as u64 - 8 - hlen;
        out.write_all(&hlen.to_le_bytes())?;
        out.write_all(&blen.to_le_bytes())?;
        if let Ok(readback) = observed {
            out.write_all(&readback.payload_sha256)?;
        } else {
            // Only a raw-byte observation; the original did not issue readback.
            out.write_all(&Sha256::digest(file))?;
        }
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
        let (frame, left) = input[4..].split_at(n);
        observe(frame, &mut out)?;
        input = left;
    }
    out.flush()
}
