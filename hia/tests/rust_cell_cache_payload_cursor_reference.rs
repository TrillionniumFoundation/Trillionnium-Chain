// Test-only pure facade over exact CachePayloadReader arithmetic fragments.
// No deadline is mocked; no store, fetched bytes, cursor handle or read occurs.
use std::io::{self, Read, SeekFrom, Write};
use trnm_data_availability::cell::{CellErrorV1, CellManifestV1};

struct CursorArithmetic {
    manifest: CellManifestV1,
    position: u64,
}

struct OutputExtent(usize);

impl OutputExtent {
    fn is_empty(&self) -> bool {
        self.0 == 0
    }
    fn len(&self) -> usize {
        self.0
    }
}

impl CursorArithmetic {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
// EXACT_SEEK
    }

    fn read_arithmetic(&mut self, output: OutputExtent, span: &mut [usize; 2]) -> io::Result<usize> {
// EXACT_READ_FIRST
// EXACT_READ_LAST
        *span = [index, offset];
// EXACT_ADVANCE
    }
}

fn manifest_status(error: CellErrorV1) -> u8 {
    match error {
        CellErrorV1::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof => 2,
        CellErrorV1::Invalid(reason) => match reason {
            "manifest length" => 1,
            "manifest version" => 3,
            "family length" => 4,
            "family encoding" => 5,
            "chunk count" => 6,
            "manifest coverage" => 7,
            "model family" => 8,
            "chunk size" => 9,
            "cell size" => 10,
            "chunk coverage" => 11,
            "chunk length" => 12,
            _ => panic!("Unexpected manifest error {reason}"),
        },
        other => panic!("Unexpected manifest result {other:?}"),
    }
}

fn observe(wire: &[u8], mut out: impl Write) -> io::Result<()> {
    let op = wire[0];
    let position = u64::from_le_bytes(wire[1..9].try_into().unwrap());
    let request = u64::from_le_bytes(wire[9..17].try_into().unwrap());
    let manifest = match CellManifestV1::decode(&wire[17..]) {
        Ok(m) => m,
        Err(e) => return out.write_all(&[manifest_status(e)]),
    };
    assert_eq!(manifest.encode(), &wire[17..]);
    let mut cursor = CursorArithmetic { manifest, position };
    if op == 3 {
        let mut span = [0usize; 2];
        let counted = cursor.read_arithmetic(OutputExtent(usize::try_from(request).unwrap()), &mut span)?;
        out.write_all(&[0])?;
        for n in [span[0] as u64, span[1] as u64, counted as u64, cursor.position] {
            out.write_all(&n.to_le_bytes())?;
        }
        return Ok(());
    }
    let from = match op {
        0 => SeekFrom::Start(request),
        1 => SeekFrom::End(request as i64),
        2 => SeekFrom::Current(request as i64),
        _ => panic!("Unknown synthetic fixture operation"),
    };
    match cursor.seek(from) {
        Ok(next) => {
            assert_eq!(cursor.position, next);
            out.write_all(&[0])?;
            out.write_all(&next.to_le_bytes())
        }
        Err(e) => {
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(e.to_string(), "tensor seek range");
            assert_eq!(cursor.position, position);
            out.write_all(&[246])
        }
    }
}

fn main() -> io::Result<()> {
    let mut b = Vec::new();
    io::stdin().read_to_end(&mut b)?;
    let mut remaining = b.as_slice();
    let mut out = io::BufWriter::new(io::stdout().lock());
    while !remaining.is_empty() {
        let n = u32::from_le_bytes(remaining[..4].try_into().unwrap()) as usize;
        let (request, rest) = remaining[4..].split_at(n);
        observe(request, &mut out)?;
        remaining = rest;
    }
    out.flush()
}
