// Test-only oracle: frozen TCM1 decode, original raw SHA and exact read arithmetic.
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use trnm_data_availability::cell::CellManifestV1;

struct CursorArithmetic {
    manifest: CellManifestV1,
    position: u64,
}
struct OutputExtent(usize);
impl OutputExtent {
    fn is_empty(&self) -> bool { self.0 == 0 }
    fn len(&self) -> usize { self.0 }
}

fn digest_equal(bytes: &[u8], hash: [u8; 32]) -> bool {
// EXACT_HASH
    false
}

impl CursorArithmetic {
    fn held(&mut self, output: OutputExtent, bytes: &[u8]) -> io::Result<Option<Vec<u8>>> {
// EXACT_READ_FIRST
        if bytes.is_empty() || !digest_equal(bytes, expected.sha256) {
            return Ok(None);
        }
// EXACT_LENGTH
// EXACT_COPY
        Ok(Some(output))
    }
}

fn observe(frame: &[u8], mut out: impl Write) -> io::Result<()> {
    let start = u64::from_le_bytes(frame[..8].try_into().unwrap());
    let want = u64::from_le_bytes(frame[8..16].try_into().unwrap());
    let n = u32::from_le_bytes(frame[16..20].try_into().unwrap()) as usize;
    let (wire, bytes) = frame[20..].split_at(n);
    let manifest = CellManifestV1::decode(wire).unwrap();
    assert_eq!(manifest.encode(), wire);
    let mut cursor = CursorArithmetic { manifest, position: start };
    let extent = OutputExtent(usize::try_from(want).unwrap());
    match cursor.held(extent, bytes) {
        Ok(Some(value)) => {
            assert_eq!(cursor.position, start + value.len() as u64);
            out.write_all(&[0])?;
            out.write_all(&cursor.position.to_le_bytes())?;
            out.write_all(&(value.len() as u64).to_le_bytes())?;
            out.write_all(&value)
        }
        Ok(None) => {
            assert_eq!(cursor.position, start);
            out.write_all(&[247])
        }
        Err(e) => {
            assert_eq!(cursor.position, start);
            assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            assert_eq!(e.to_string(), "tensor chunk length");
            out.write_all(&[248])
        }
    }
}

fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut remaining = raw.as_slice();
    let mut o = io::BufWriter::new(io::stdout().lock());
    while !remaining.is_empty() {
        let n = u32::from_le_bytes(remaining[..4].try_into().unwrap()) as usize;
        let (item, rest) = remaining[4..].split_at(n);
        observe(item, &mut o)?;
        remaining = rest;
    }
    o.flush()
}
