//! Observe the locked public TCM1 and BEP52 in-memory value APIs.
use std::io::{self, ErrorKind, Read, Write};
use trnm_data_availability::cell::{
    CellBep52BindingV1, CellContextV1, CellErrorV1, CellManifestV1,
};

fn binding(raw: &[u8]) -> Result<CellBep52BindingV1, CellErrorV1> {
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
    CellBep52BindingV1::from_pinned_manifest(&manifest, raw[4..36].try_into().unwrap(), &expected)
}

fn observe(raw: &[u8]) -> Result<Vec<u8>, CellErrorV1> {
    let (body, trailer) = raw.split_at(raw.len()-5);
    let at = u32::from_be_bytes(trailer[..4].try_into().unwrap()) as usize;
    let (frame, supplied) = body.split_at(at);
    let v = binding(frame)?;
    match trailer[4] {
        0 => {
            assert!(supplied.is_empty());
            let info = v.info_bytes();
            let data = v.metainfo_bytes();
            v.verify_info_bytes(&info)?;
            v.verify_metainfo_bytes(&data)?;
            let mut out = Vec::new();
            out.extend((info.len() as u16).to_be_bytes());
            out.extend((data.len() as u32).to_be_bytes());
            out.extend(data);
            Ok(out)
        }
        1 => { v.verify_info_bytes(supplied)?; Ok(Vec::new()) }
        2 => { v.verify_metainfo_bytes(supplied)?; Ok(Vec::new()) }
        _ => unreachable!(),
    }
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
        assert!((5..=1_573_893).contains(&n));
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
                    "BEP52 info size" => 30,
                    "BEP52 canonical info binding" => 31,
                    "BEP52 metainfo size" => 32,
                    "BEP52 canonical metainfo binding" => 33,
                    _ => panic!("unexpected original BEP52 metainfo reason: {reason}"),
                };
                out.write_all(&[code])?;
            }
            Err(other) => panic!("unexpected original BEP52 metainfo result: {other:?}"),
        }
    }
}
