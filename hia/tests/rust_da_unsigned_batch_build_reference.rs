use std::io::{self, Read, Write};
use trnm_data_availability::{
    DaAuthorAuthorityV1, DaCommitteeDescriptorV1, DaErrorCodeV1, DaMemberV1, DaPolicyV1,
    Hash32V1, ProtocolContextV1, UnsignedTransactionBatchV1,
};
const KEY: [u8; 32] = [
    0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
    0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a,
];
const KEY_B: [u8; 32] = [
    0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,
    0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c,
];

fn observe(raw: &[u8]) -> (Vec<u8>, u8, Vec<u8>) {
    let variant = raw[0];
    let sequence = u64::from_le_bytes(raw[2..10].try_into().unwrap());
    let step = u32::from_le_bytes(raw[10..14].try_into().unwrap());
    let chunks = u32::from_le_bytes(raw[14..18].try_into().unwrap());
    let max_bytes = u64::from_le_bytes(raw[18..26].try_into().unwrap());
    let max_items = u32::from_le_bytes(raw[26..30].try_into().unwrap());
    let (chain, len) = if variant == 3 { ("x".repeat(128), 256) } else { ("x".into(), 1) };
    let a = vec![0; len];
    let mut b = vec![0; len];
    b[0] = 255;
    let chosen = match raw[1] {
        0 => a.clone(), 1 => b.clone(), 2 => vec![0x7f], 3 => Vec::new(),
        _ => panic!("unexpected synthetic selector"),
    };
    let word = |n| Hash32V1::new([n; 32]);
    let context = ProtocolContextV1::new(word(1), &chain, word(2)).unwrap();
    let member = DaMemberV1::new(KEY, 1, None, word(3), word(4)).unwrap();
    let epoch = if variant == 4 { u64::MAX } else { 8 };
    let committee = DaCommitteeDescriptorV1::new_transaction_batch(
        context, epoch, vec![member], 2, max_bytes, max_bytes, max_items, 4,
    ).unwrap();
    let authors = vec![
        DaAuthorAuthorityV1::new(a, KEY, 1, 10, max_bytes, 4).unwrap(),
        DaAuthorAuthorityV1::new(b, KEY_B, 3, 3, max_bytes, 4).unwrap(),
    ];
    let policy = DaPolicyV1::new_transaction_batch(
        &committee, authors, step, chunks, 2, max_bytes, 5, 4,
    ).unwrap();
    let mut c = borsh::to_vec(&committee).unwrap();
    let mut p = borsh::to_vec(&policy).unwrap();
    let v = 2 + 74 + chain.len() + 8 + 32;
    let sz = p.len();
    let first_key = v + 4 + 4 + 1;
    let first = first_key + 32;
    match variant {
        0 | 3 | 4 | 14 | 15 => (),
        1 => p[4] ^= 1,
        2 => p[v-32] ^= 1,
        5 => p[sz-36..sz-32].fill(0),
        6 => p[sz-36..sz-32].copy_from_slice(&(max_bytes as u32 + 1).to_le_bytes()),
        7 => { p[v..v+4].fill(0); p.drain(v+4..sz-48); }
        8 => p[first..first+8].fill(0),
        9 => p[first+16..first+24].copy_from_slice(&(max_bytes+1).to_le_bytes()),
        10 => c[0] = 2,
        11 => { p[sz-48] ^= 1; p[first..first+8].fill(0); }
        12 => { let e = c.len()-44; c[e..e+16].fill(0); p[4] ^= 1; }
        13 => { p[first_key..first].fill(0); p[first_key] = 1; }
        16 => p[first+65..first+73].fill(0),
        17 => p[first_key+65..first+65].copy_from_slice(&KEY),
        _ => panic!("unexpected test variant"),
    }
    let special;
    let content = if matches!(variant, 14 | 15) {
        let extent = 262_144 + (variant-14) as usize;
        let framing = c.len()+p.len()+chosen.len()+24;
        special = borsh::to_vec(&vec![vec![0x4d_u8;extent-framing-8]]).unwrap();
        special.as_slice()
    } else {
        &raw[30..]
    };
    let original_committee = borsh::from_slice::<DaCommitteeDescriptorV1>(&c).unwrap();
    let original_policy = borsh::from_slice::<DaPolicyV1>(&p).unwrap();
    assert_eq!(borsh::to_vec(&original_committee).unwrap(), c);
    assert_eq!(borsh::to_vec(&original_policy).unwrap(), p);
    let mut q = c.clone();
    q.extend_from_slice(&p);
    q.extend_from_slice(&borsh::to_vec(&chosen).unwrap());
    q.extend_from_slice(&sequence.to_le_bytes());
    q.extend_from_slice(content);
    for size in [c.len(), p.len(), content.len()] {
        q.extend_from_slice(&(size as u32).to_le_bytes());
    }
    let rows = match borsh::from_slice::<Vec<Vec<u8>>>(content) {
        Ok(x) => x, Err(_) => return (q,100,Vec::new()),
    };
    assert_eq!(borsh::to_vec(&rows).unwrap(), content);
    let batch = match UnsignedTransactionBatchV1::build(
        &original_committee, &original_policy, chosen, sequence, rows,
    ) {
        Ok(x) => x,
        Err(err) => {
            use DaErrorCodeV1::*;
            let tag = match (err.code(),err.message()) {
                (InvalidCommittee,"invalid committee bounds") => 210,
                (InvalidCommittee,"committee threshold is not floor(2W/3)+1") => 212,
                (InvalidBounds,"invalid transaction-batch DA policy") => 215,
                (InvalidBounds,"chunk bound exceeds batch bound") => 216,
                (InvalidBounds,"authorities must be canonical and within committee limits") => 217,
                (InvalidBounds,"DA policy requires an author authority") => 218,
                (InvalidBounds,"invalid DA author authority") => 3,
                (InvalidSignature,"weak author key is forbidden") => 7,
                (UnauthorizedAuthor,"author is not in the committed DA policy") => 219,
                (SequenceConflict,"author sequence is outside authority range") => 220,
                (InvalidBounds,"invalid transaction item count") => 40,
                (NonCanonical,"transaction entries must be nonempty and duplicate-free") => 41,
                (InvalidBounds,"transaction batch chunk count exceeds policy") => 42,
                (InvalidBounds,"transaction batch exceeds max_batch_bytes") => 43,
                (ArithmeticOverflow,"retention end overflow") => 44,
                unexpected => panic!("Unexpected actual original result: {unexpected:?}"),
            };
            return (q,tag,Vec::new());
        }
    };
    assert_eq!(batch.batch_id(),batch.envelope().batch_id().unwrap());
    assert_eq!(batch.content_bytes(),content);
    let envelope = borsh::to_vec(batch.envelope()).unwrap();
    let mut result = borsh::to_vec(&envelope).unwrap();
    result.extend_from_slice(batch.batch_id().as_bytes());
    result.extend_from_slice(&borsh::to_vec(&batch.content_bytes()).unwrap());
    result.extend_from_slice(&borsh::to_vec(batch.chunks()).unwrap());
    (q,0,result)
}

fn main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut n = [0; 4];
        if input.read(&mut n[..1])? == 0 { return Ok(()); }
        input.read_exact(&mut n[1..])?;
        let size = u32::from_le_bytes(n) as usize;
        assert!((30..=262_160).contains(&size));
        let mut data = vec![0; size];
        input.read_exact(&mut data)?;
        let (wire,status,result) = observe(&data);
        output.write_all(&[status])?;
        output.write_all(&(wire.len() as u32).to_le_bytes())?;
        output.write_all(&(result.len() as u32).to_le_bytes())?;
        output.write_all(&wire)?;
        output.write_all(&result)?;
    }
}
