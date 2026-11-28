//! Observe the locked public TCM1 and BEP52 in-memory value APIs.
use std::io::{self, ErrorKind, Read, Write};
use trnm_data_availability::cell::{
    CellBep52BindingV1, CellBep52ChunkProofV1, CellContextV1, CellErrorV1, CellManifestV1,
};

fn observe(raw: &[u8]) -> Result<Vec<u8>, CellErrorV1> {
    let (mode, request) = raw.split_last().unwrap();
    if *mode == 0 {
        let proof = CellBep52ChunkProofV1::decode(request)?;
        assert_eq!(proof.encode(), request);
        assert_eq!(proof.index(), u32::from_be_bytes(request[68..72].try_into().unwrap()));
        assert_eq!(proof.leaf_count(), u32::from_be_bytes(request[72..76].try_into().unwrap()));
        return Ok(proof.encode());
    }
    assert_eq!(*mode, 1);
    let (raw, selected) = request.split_at(request.len()-4);
    let selected = u32::from_be_bytes(selected.try_into().unwrap());
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
    let proof = pinned.chunk_proof(selected)?;
    assert_eq!(proof.index(), selected);
    let bytes = proof.encode();
    assert_eq!(CellBep52ChunkProofV1::decode(&bytes)?, proof);
    Ok(bytes)
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
        assert!((1..=1_048_581).contains(&n));
        let mut raw = vec![0; n];
        input.read_exact(&mut raw)?;
        match observe(&raw) {
            Ok(answer) => {
                out.write_all(&[0])?;
                out.write_all(&(answer.len() as u16).to_be_bytes())?;
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
                    "BEP52 proof size" => 31,
                    "BEP52 proof version" => 32,
                    "BEP52 leaf count" => 33,
                    "BEP52 chunk index" => 34,
                    "BEP52 proof depth" => 35,
                    "BEP52 padding subtree" => 36,
                    _ => panic!("unexpected original CBP1 reason: {reason}"),
                };
                out.write_all(&[code])?;
            }
            Err(other) => panic!("unexpected original CBP1 result: {other:?}"),
        }
    }
}
