//! Observe the locked public TCM1 and BEP52 in-memory value APIs.
use std::io::{self, ErrorKind, Read, Write};
use trnm_data_availability::cell::{
    CellBep52BindingV1, CellBep52MagnetV1, CellContextV1, CellErrorV1, CellManifestV1,
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

fn project(m: &CellBep52MagnetV1) -> Vec<u8> {
    let mut result = m.info_hash().to_vec();
    result.extend(m.encode().as_bytes());
    assert_eq!(result.len(), 120);
    result
}

fn observe(raw: &[u8]) -> Result<Vec<u8>, CellErrorV1> {
    let (mode, body) = raw.split_last().unwrap();
    if *mode == 0 {
        let text = std::str::from_utf8(body).expect("actual Rust &str fixture");
        let value = CellBep52MagnetV1::parse(text)?;
        assert_eq!(value.encode().as_bytes(), body);
        return Ok(project(&value));
    }

    let (body, trailer) = body.split_at(body.len()-4);
    let at = u32::from_be_bytes(trailer.try_into().unwrap()) as usize;
    let (frame, supplied) = body.split_at(at);
    let value = binding(frame)?;
    match *mode {
        1 => {
            let text = std::str::from_utf8(supplied).expect("actual Rust &str fixture");
            value.verify_magnet(text)?;
            Ok(Vec::new())
        }
        2 => {
            assert!(supplied.is_empty());
            let descriptor = value.magnet();
            assert_eq!(descriptor.info_hash(), value.info_hash());
            value.verify_magnet(&descriptor.encode())?;
            Ok(project(&descriptor))
        }
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
        assert!((1..=1_048_576).contains(&n));
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
                    "BEP52 magnet profile" => 30,
                    "canonical digest" => 31,
                    "BEP52 infohash pin" => 32,
                    _ => panic!("unexpected original BEP52 descriptor reason: {reason}"),
                };
                out.write_all(&[code])?;
            }
            Err(other) => panic!("unexpected original BEP52 descriptor result: {other:?}"),
        }
    }
}
