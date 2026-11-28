//! Ordinary owned in-memory fixtures, observed through the exact private custody.rs verifier.
use super::{CellRs46ChunkBindingV1, CellRs46CodewordV1, CellRs46ShardInputV1};
use crate::cell::{CellChunkV1, CellContextV1, CellDigestV1, CellErrorV1, CellManifestV1};
use sha2::{Digest, Sha256};
use std::io::Write;

const MARKER: &[u8] = b"TRNM_DA_RS46_COMMITTED_SLOT_COMPARATOR_V1";

fn context(seed: u8) -> CellContextV1 {
    CellContextV1 {
        family: "rs46-observation".into(),
        base: [seed; 32],
        parent: [seed + 1; 32],
        tokenizer: [seed + 2; 32],
        layout: [seed + 3; 32],
        runtime: [seed + 4; 32],
    }
}

fn make(data: &[u8], seed: u8, prefix: bool) -> (CellManifestV1, u32) {
    let chunk_bytes: u32 = if data.len() > 16_384 { 4_194_304 } else { 16_384 };
    let digest = |x: &[u8]| -> CellDigestV1 { Sha256::digest(x).into() };
    let row = CellChunkV1 { size: data.len().try_into().unwrap(), sha256: digest(data) };
    let (index, data_digest, rows) = if prefix {
        let first = vec![31; chunk_bytes as usize];
        let mut payload = Sha256::new();
        payload.update(&first);
        payload.update(data);
        (1, payload.finalize().into(),
         vec![CellChunkV1{ size: chunk_bytes, sha256: digest(&first) }, row])
    } else { (0, digest(data), vec![row]) };
    let size = u64::from(index)*u64::from(chunk_bytes) + data.len() as u64;
    (CellManifestV1::new(context(seed), size, data_digest, chunk_bytes, rows).unwrap(), index)
}

fn frame(manifest: &CellManifestV1, index: u32, crc: &[u8], expected: CellDigestV1) -> Vec<u8> {
    let mut wire = b"RCB1".to_vec();
    wire.extend(index.to_be_bytes());
    wire.extend(manifest.id());
    wire.extend(expected);
    let encoded = manifest.encode();
    let n = usize::from(encoded[4]);
    wire.extend(&encoded[4..165+n]);
    wire.extend((encoded.len() as u32).to_be_bytes());
    wire.extend(&encoded);
    wire.extend(crc);
    wire
}

fn observed(w: &mut impl Write, rcb: &[u8], owner_slot: u8, wire: &[u8]) -> u8 {
    assert_eq!(&rcb[..4], b"RCB1");
    let n = usize::from(rcb[72]);
    let at = 233 + n;
    let size = u32::from_be_bytes(rcb[at..at+4].try_into().unwrap()) as usize;
    let start = at+4;
    let orig = CellManifestV1::decode(&rcb[start..start+size]).unwrap();
    let pin = |i| rcb[73 + n + 32*i..73 + n + 32*(i+1)].try_into().unwrap();
    let context = CellContextV1 {
        family: String::from_utf8(rcb[73..73+n].to_vec()).unwrap(),
        base: pin(0usize), parent: pin(1), tokenizer: pin(2), layout: pin(3), runtime: pin(4),
    };
    let answer = CellRs46ChunkBindingV1::from_pinned_manifest(
        &orig, rcb[8..40].try_into().unwrap(), &context,
        u32::from_be_bytes(rcb[4..8].try_into().unwrap()),
    ).and_then(|binding| CellRs46CodewordV1::decode_pinned(
        &rcb[start+size..], &binding, rcb[40..72].try_into().unwrap(),
    )).and_then(|crc| crc.verify_input(&CellRs46ShardInputV1 { index: owner_slot, wire }));
    let status = match &answer {
        Ok(_) => 0,
        Err(CellErrorV1::Invalid(reason)) => match *reason {
            "RS46 chunk index" => 13,
            "RS46 context pin" => 14,
            "RS46 manifest pin" => 15,
            "RS46 codeword pin" => 22,
            "RS46 shard wire size" => 31,
            "RS46 shard version" => 32,
            "RS46 source size" => 33,
            "RS46 shard index" => 34,
            "RS46 shard coverage" => 35,
            "RS46 committed shard readback" => 36,
            _ => panic!("Unexpected ordinary fixture result: {reason}"),
        },
        Err(other) => panic!("Unexpected ordinary fixture error: {other:?}"),
    };
    w.write_all(&[status, owner_slot]).unwrap();
    w.write_all(&(rcb.len() as u32).to_le_bytes()).unwrap();
    w.write_all(&(wire.len() as u32).to_le_bytes()).unwrap();
    w.write_all(rcb).unwrap();
    w.write_all(wire).unwrap();
    if let Ok(shard) = answer {
        assert_eq!(shard.encode(), wire);
        w.write_all(&shard.id()).unwrap();
        w.write_all(&shard.encode()[..81]).unwrap();
    }
    status
}

#[test]
fn observe_exact_committed_slot() {
    let path = std::env::var_os("TRNM_DA_PRIVATE_PATH_FIXTURE").unwrap();
    let mut f = std::fs::File::options().write(true).create_new(true).open(path).unwrap();
    f.write_all(MARKER).unwrap();
    for (n, seed, prefix) in [(1usize, 4u8, false), (17, 10, true), (4097, 21, false)] {
        let data: Vec<u8> = (0..n).map(|i| ((i * 37 + usize::from(seed)) % 251) as u8).collect();
        let (m, i) = make(&data, seed, prefix);
        let b = CellRs46ChunkBindingV1::from_pinned_manifest(&m, m.id(), m.context(), i).unwrap();
        let (c, six) = CellRs46CodewordV1::from_verified_chunk_with_shards(&b, &data).unwrap();
        let frame_wire = frame(&m, i, &c.encode(), c.id());
        for s in 0..6 {
            let shard = six[s].encode();
            assert_eq!(observed(&mut f, &frame_wire, s as u8, &shard), 0);
            assert_eq!(observed(&mut f, &frame_wire, ((s+1)%6) as u8, &shard), 36);
        }
        let first = six[0].encode();
        let changed = |at: usize, value: u8, code| {
            let mut j = first.clone(); j[at] = value; (j, code)
        };
        let ordinary_cases = [
            changed(0, b'X', 32), changed(40, 0xff, 33), changed(76, 6, 34),
            changed(80, first[80] ^ 1, 35), changed(4, first[4] ^ 1, 36),
            changed(39, first[39] ^ 1, 36), changed(43, first[43] + 1, 36),
            changed(44, first[44] ^ 1, 36), changed(81, first[81] ^ 1, 36),
        ];
        for (wire, code) in ordinary_cases { assert_eq!(observed(&mut f, &frame_wire, 0, &wire), code); }
        assert_eq!(observed(&mut f, &frame_wire, 0, &first[..81]), 31);
        assert_eq!(observed(&mut f, &frame_wire, 7, &first), 36);
        for (offset, code) in [(4, 13), (73 + usize::from(frame_wire[72]), 14), (8, 15), (40, 22)] {
            let mut wrong_pin = frame_wire.clone();
            wrong_pin[offset] ^= 1;
            assert_eq!(observed(&mut f, &wrong_pin, 0, &first), code);
        }
    }
    let data: Vec<u8> = (0..4_194_304).map(|i| (i % 239) as u8).collect();
    let (m, i) = make(&data, 42, false);
    let b = CellRs46ChunkBindingV1::from_pinned_manifest(&m, m.id(), m.context(), i).unwrap();
    let (c, shards) = CellRs46CodewordV1::from_verified_chunk_with_shards(&b, &data).unwrap();
    let largest_frame = frame(&m, i, &c.encode(), c.id());
    assert_eq!(observed(&mut f, &largest_frame, 5, &shards[5].encode()), 0);

    let shared_extent = 1_048_576usize;
    let len = (shared_extent - largest_frame.len() - 81 - 5) * 4;
    let (bare, index) = make(&data[..len], 42, false);
    let binding = CellRs46ChunkBindingV1::from_pinned_manifest(
        &bare, bare.id(), bare.context(), index,
    ).unwrap();
    let (codeword, six) =
        CellRs46CodewordV1::from_verified_chunk_with_shards(&binding, &data[..len]).unwrap();
    let boxed = frame(&bare, index, &codeword.encode(), codeword.id());
    let shard = six[2].encode();
    assert_eq!(boxed.len() + shard.len() + 5, shared_extent);
    assert_eq!(observed(&mut f, &boxed, 2, &shard), 0);
}
