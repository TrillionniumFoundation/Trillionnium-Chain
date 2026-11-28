use std::io::{self, Write};
use trnm_data_availability::{
    DaAuthorAuthorityV1, DaBatchAuthorV1, DaBatchEnvelopeV1, DaCommitteeDescriptorV1, DaErrorCodeV1,
    DaMemberV1, DaPolicyV1, Hash32V1, ProtocolContextV1, UnsignedTransactionBatchV1,
};

// Public-only RFC 8032 vector; this boundary cannot create an author signature.
const KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
fn digest(x: u8) -> Hash32V1 {
    Hash32V1::new([x; 32])
}

fn generated(chain: &str, author: Vec<u8>, sequence: u64, marker: u8) -> Vec<u8> {
    let context = ProtocolContextV1::new(digest(1), chain, digest(2)).unwrap();
    let member = DaMemberV1::new(KEY, 1, None, digest(3), digest(4)).unwrap();
    let committee =
        DaCommitteeDescriptorV1::new_transaction_batch(context, 7, vec![member], 2, 8192, 4096, 32, 4)
            .unwrap();
    let authority = DaAuthorAuthorityV1::new(author.clone(), KEY, 1, u64::MAX, 8192, 4)
        .unwrap();
    let policy = DaPolicyV1::new_transaction_batch(&committee, vec![authority], 32, 256, 4, 16384, 50, 20)
        .unwrap();
    let transactions = vec![vec![marker, 0, 1, 2], vec![marker; 65], vec![marker, 0, 0, 1]];
    let built = UnsignedTransactionBatchV1::build(&committee, &policy, author, sequence, transactions)
        .expect("original public-only synthetic transaction envelope");
    let wire = borsh::to_vec(built.envelope()).unwrap();
    assert_eq!(wire.len(), 283 + chain.len() + built.envelope().author_id().len());
    wire
}
fn u32_at(bytes: &[u8], p: usize) -> usize {
    u32::from_le_bytes(bytes[p..p+4].try_into().unwrap()) as usize
}
fn replace_field(bytes: &[u8], position: usize, raw: &[u8]) -> Vec<u8> {
    let n = u32_at(bytes, position);
    let mut out = Vec::with_capacity(bytes.len() - n + raw.len());
    out.extend(&bytes[..position]);
    out.extend((raw.len() as u32).to_le_bytes());
    out.extend(raw);
    out.extend(&bytes[position+4+n..]);
    out
}
fn change(bytes: &[u8], p: usize, val: &[u8]) -> Vec<u8> {
    let mut new = bytes.to_vec();
    new[p..p+val.len()].copy_from_slice(val);
    new
}

fn report(out: &mut impl Write, wire: &[u8], expect: u8) -> io::Result<()> {
    let mut result = Vec::new();
    let decoded = borsh::from_slice::<DaBatchEnvelopeV1>(wire);
    let code = match decoded {
        Err(_) => 100,
        Ok(envelope) => {
            assert_eq!(borsh::to_vec(&envelope).unwrap(), wire);
            match (envelope.batch_id(), DaBatchAuthorV1::signing_root(&envelope)) {
                (Ok(batch), Ok(root)) => {
                    result.extend(batch.as_bytes());
                    result.extend(root.as_bytes());
                    0
                }
                (Err(batch), Err(root)) => {
                    assert_eq!(batch, root);
                    match (root.code(), root.message()) {
                        (DaErrorCodeV1::InvalidContext,"unsupported context version") => 2,
                        (DaErrorCodeV1::InvalidContext,"chain ID must be bounded nonempty ASCII") => 3,
                        (DaErrorCodeV1::UnsupportedNamespace,"ArtifactEvidence is outside this candidate tranche") => 4,
                        (DaErrorCodeV1::UnsupportedNamespace,"unknown DA namespace") => 5,
                        (DaErrorCodeV1::InvalidBounds,"invalid transaction-batch envelope") => 6,
                        unexpected => panic!("Unexpected original refusal {unexpected:?}"),
                    }
                }
                unexpected => panic!("Inconsistent batch and author roots {unexpected:?}"),
            }
        }
    };
    assert_eq!(code, expect);
    out.write_all(&[code])?;
    out.write_all(&(wire.len() as u32).to_le_bytes())?;
    out.write_all(wire)?;
    out.write_all(&result)?;
    Ok(())
}

fn main() -> io::Result<()> {
    let mut out = io::stdout().lock();
    let canonical = generated("x", vec![0xfe, 0, 1], 1, 7);
    let c = u32_at(&canonical, 36);
    let a = u32_at(&canonical, 117+c);
    let seq = 121 + c + a;
    for (wire, expect) in [
        (canonical.clone(), 0),
        (generated("x", vec![0xfe, 0, 1], 1, 8), 0),
        (generated("x", vec![0xfe, 0, 1], 2, 7), 0),
        (generated(&"A".repeat(128), (0..=255).collect(), u64::MAX, 9), 0),
        (generated("\0\t\n\r", b"\0a\xff".to_vec(), 256, 10), 0),
        (change(&canonical, 4, &[0; 32]), 0),
        (change(&canonical, seq+10, &[0; 32]), 0),
        (change(&canonical, seq+54, &[0; 32]), 0),
        (change(&canonical, seq+122, &[0; 32]), 0),
        (change(&canonical, 2, &[0,0]), 2),
        (change(&canonical, 40+c, &[2,0,0,0]), 2),
        (replace_field(&canonical, 36, b""), 3),
        (replace_field(&canonical, 36, &[b'a';129]), 3),
        (replace_field(&canonical, 36, "é".as_bytes()), 3),
        (replace_field(&canonical, 36, "😀".as_bytes()), 3),
        (replace_field(&canonical, 36, b"\xff"), 100),
        (replace_field(&canonical, 36, b"\xed\xa0\x80"), 100),
        (replace_field(&canonical, 36, b"\xc0\x80"), 100),
        (change(&canonical, 76+c, &[1]), 4),
        (change(&canonical, 76+c, &[0xff]), 5),
        (change(&canonical, 0, &[0,0]), 6),
        (replace_field(&canonical, 117+c, b""), 6),
        (change(&canonical, seq, &[0;8]), 6),
        (change(&canonical, seq+8, &[1,0]), 6),
        (change(&canonical, seq+42, &[0;4]), 6),
        (change(&canonical, seq+46, &[0;8]), 6),
        (change(&canonical, seq+118, &[0;4]), 6),
        (change(&canonical, seq+154, &7_u64.to_le_bytes()), 6),
        (change(&change(&canonical, 76+c, &[1]), 0, &[0,0]), 4),
        (change(&change(&canonical, 76+c, &[1]), 2, &[0,0]), 2),
        (replace_field(&change(&canonical, 76+c, &[1]), 36, "é".as_bytes()), 3),
        (replace_field(&change(&canonical, 2, &[0,0]), 36, b"\xff"), 100),
        (canonical[..canonical.len()-1].to_vec(), 100),
        ([canonical.as_slice(), b"x"].concat(), 100),
        (replace_field(&canonical, 117+c, &[0x5a;257]), 0),
        (replace_field(&canonical, 117+c, &vec![0x5a; 1_048_576-283-c]), 0),
        (replace_field(&canonical, 117+c, &vec![0x5a; 1_048_577-283-c]), 0),
    ] {
        report(&mut out, &wire, expect)?;
    }
    Ok(())
}
