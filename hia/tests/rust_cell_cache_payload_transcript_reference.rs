// Harness binds original cursor/slot code to two inert, caller-owned byte spans.
use sha2::{Digest, Sha256};
use std::io::{self, Read, SeekFrom, Write};
use trnm_data_availability::cell::CellManifestV1;

struct Reader<'a> {
    manifest: CellManifestV1,
    position: u64,
    cached_index: Option<usize>,
    cached_bytes: Vec<u8>,
    held: [&'a [u8]; 2],
}

// EXACT_DIGEST

impl Reader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
// EXACT_READ
    }

    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
// EXACT_SEEK
    }
}

fn le32(p: &[u8]) -> usize {
    u32::from_le_bytes(p[..4].try_into().unwrap()) as usize
}

fn observe(frame: &[u8], out: &mut impl Write) -> io::Result<()> {
    let ml = le32(frame);
    let left = le32(&frame[4..]);
    let count = le32(&frame[8..]);
    let (ops, rest) = frame[12..].split_at(9 * count);
    let (wire, body) = rest.split_at(ml);
    let (a, b) = body.split_at(left);
    let manifest = CellManifestV1::decode(wire).unwrap();
    assert_eq!(manifest.encode(), wire);
    assert_eq!(manifest.chunks().len(), 2);
    let mut reader = Reader {
        manifest, position: 0, cached_index: None, cached_bytes: Vec::new(), held: [a,b],
    };
    for op in ops.chunks_exact(9) {
        let arg = u64::from_le_bytes(op[1..].try_into().unwrap());
        let mut body = [0u8; 64];
        let (code, n): (u64, usize) = match op[0] {
            0 => { assert_eq!(reader.seek(SeekFrom::Start(arg))?, arg); (0,0) }
            1 => match reader.read(&mut body[..arg as usize]) {
                Ok(n) => (0,n),
                Err(e) if e.kind()==io::ErrorKind::NotFound => (247,0),
                Err(e) if e.kind()==io::ErrorKind::InvalidData && e.to_string()=="tensor chunk length" => (248,0),
                Err(e) => return Err(e),
            },
            _ => unreachable!(),
        };
        assert_eq!(reader.cached_index.is_none(),reader.cached_bytes.is_empty());
        for x in [code,reader.position,reader.cached_index.map_or(0,|v|1+v as u64),n as u64] {
            out.write_all(&x.to_le_bytes())?;
        }
        out.write_all(&body)?;
    }
    Ok(())
}

fn main() -> Result<(),io::Error> {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)?;
    let mut stream = buf.as_slice();
    let mut out = io::BufWriter::new(io::stdout().lock());
    while !stream.is_empty() {
        let len = le32(stream);
        let (frame, rest) = stream[4..].split_at(len);
        observe(frame, &mut out)?;
        stream = rest;
    }
    out.flush()
}
