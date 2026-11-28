//! Observe the locked public TCM1 and BEP52 in-memory value APIs.
use std::io::{self, ErrorKind, Read, Write};
use trnm_data_availability::cell::{
    CellBep52BindingV1, CellContextV1, CellErrorV1, CellManifestV1,
};

fn observe(raw: &[u8]) -> Result<Vec<u8>, CellErrorV1> {
    assert_eq!(&raw[..4], b"BPB1");
    let family = usize::from(raw[36]);
    let at = 37 + family;
    let digest = |index: usize| raw[at + index * 32..at + (index + 1) * 32].try_into().unwrap();
    let expected = CellContextV1 {
        family: std::str::from_utf8(&raw[37..at]).unwrap().into(),
        base: digest(0),
        parent: digest(1),
        tokenizer: digest(2),
        layout: digest(3),
        runtime: digest(4),
    };
    let declared = &raw[at + 160..];
    let manifest = CellManifestV1::decode(declared)?;
    assert_eq!(manifest.encode(), declared);
    let pinned = CellBep52BindingV1::from_pinned_manifest(
        &manifest, raw[4..36].try_into().unwrap(), &expected,
    )?;
    let canonical = pinned.info_bytes();
    pinned.verify_info_bytes(&canonical)?;
    assert_eq!(pinned.manifest_id(), raw[4..36]);
    let mut out = Vec::new();
    out.extend(pinned.pieces_root());
    out.extend(pinned.info_hash());
    out.extend((canonical.len() as u16).to_be_bytes());
    out.extend(canonical);
    Ok(out)
}

fn main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut out = io::stdout().lock();
    loop {
        let mut n = [0; 4];
        match input.read(&mut n[..1]) {
            Ok(0) => return Ok(()),
            Ok(1) => input.read_exact(&mut n[1..])?,
            Ok(_) => unreachable!(),
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
        let n = u32::from_le_bytes(n) as usize;
        assert!((197..=1_048_576).contains(&n));
        let mut raw = vec![0; n];
        input.read_exact(&mut raw)?;
        match observe(&raw) {
            Ok(answer) => {
                out.write_all(&[0])?;
                out.write_all(&answer)?;
            }
            Err(CellErrorV1::Io(err)) if err.kind() == ErrorKind::UnexpectedEof => {
                out.write_all(&[2])?;
            }
            Err(CellErrorV1::Invalid(reason)) => {
                let code = match reason {
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
                    "BEP52 context pin" => 14,
                    "BEP52 manifest pin" => 15,
                    "BEP52 requires 16 KiB TCM1 chunks" => 16,
                    "BEP52 leaf count" => 17,
                    _ => panic!("unexpected original BEP52 reason: {reason}"),
                };
                out.write_all(&[code])?;
            }
            Err(other) => panic!("unexpected original BEP52 result: {other:?}"),
        }
    }
}
