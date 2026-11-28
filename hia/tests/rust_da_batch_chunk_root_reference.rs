use std::io::{self, Read, Write};
use trnm_data_availability::{
    DaAuthorAuthorityV1, DaCommitteeDescriptorV1, DaErrorCodeV1, DaMemberV1, DaPolicyV1,
    Hash32V1, ProtocolContextV1, UnsignedTransactionBatchV1,
};

const PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
    0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
    0xf7, 0x07, 0x51, 0x1a,
];
const CAP: u64 = 2 * 1024 * 1024;

struct Fixture {
    committee: DaCommitteeDescriptorV1,
    authority: DaAuthorAuthorityV1,
    author: Vec<u8>,
    sequence: u64,
    prefix: Vec<u8>,
}

impl Fixture {
    fn policy(&self, step: u32, chunks: u32) -> DaPolicyV1 {
        DaPolicyV1::new_transaction_batch(
            &self.committee, vec![self.authority.clone()], step, chunks, 2, CAP, 5, 4,
        ).unwrap()
    }

    fn new(chain: &str, author: Vec<u8>, epoch: u64, sequence: u64, discriminator: u8) -> Self {
        let digest = |n| Hash32V1::new([n + discriminator; 32]);
        let context = ProtocolContextV1::new(digest(1), chain, digest(2)).unwrap();
        let member = DaMemberV1::new(PUBLIC, 1, None, digest(3), digest(4)).unwrap();
        let committee = DaCommitteeDescriptorV1::new_transaction_batch(
            context, epoch, vec![member], 2, CAP, CAP, 64, 4,
        ).unwrap();
        let authority = DaAuthorAuthorityV1::new(author.clone(), PUBLIC, 1, u64::MAX, CAP, 4)
            .unwrap();
        let mut f = Self { committee, author, authority, sequence, prefix: Vec::new() };
        let sample = UnsignedTransactionBatchV1::build(
            &f.committee, &f.policy(32, 64), f.author.clone(), f.sequence, vec![vec![0]],
        ).unwrap();
        let first = borsh::to_vec(&sample.chunks()[0]).unwrap();
        let width = 129 + chain.len() + f.author.len();
        f.prefix = first[..width].to_vec();
        f
    }

    fn run(&self, content: &[u8], step: u32, limit: u32) -> (u8, Vec<u8>) {
        let rows = match borsh::from_slice::<Vec<Vec<u8>>>(content) {
            Ok(items) => items,
            Err(_) => return (100, Vec::new()),
        };
        assert_eq!(borsh::to_vec(&rows).unwrap(), content);
        let batch = match UnsignedTransactionBatchV1::build(
            &self.committee, &self.policy(step, limit), self.author.clone(), self.sequence, rows,
        ) {
            Ok(value) => value,
            Err(err) => return (match (err.code(), err.message()) {
                (DaErrorCodeV1::InvalidBounds, "invalid transaction item count") => 40,
                (DaErrorCodeV1::NonCanonical, "transaction entries must be nonempty and duplicate-free") => 41,
                (DaErrorCodeV1::InvalidBounds, "transaction batch chunk count exceeds policy") => 42,
                unknown => panic!("Unexpected original DA chunk stage result: {unknown:?}"),
            }, Vec::new()),
        };
        let envelope = batch.envelope();
        assert_eq!(batch.content_bytes(), content);
        assert_eq!(batch.chunks().len(), envelope.chunk_count() as usize);
        let mut profile = None;
        for (i, (original, expected)) in batch.chunks().iter().zip(content.chunks(step as usize)).enumerate() {
            assert_eq!(original.index() as usize, i);
            assert_eq!(original.bytes(), expected);
            let wire = borsh::to_vec(original).unwrap();
            assert_eq!(&wire[..self.prefix.len()], self.prefix);
            let p = self.prefix.len();
            let here: [u8; 32] = wire[p..p+32].try_into().unwrap();
            assert_eq!(*profile.get_or_insert(here), here);
            assert_eq!(u32::from_le_bytes(wire[p+32..p+36].try_into().unwrap()), original.index());
            assert_eq!(u64::from_le_bytes(wire[p+36..p+44].try_into().unwrap()), original.bytes().len() as u64);
        }
        assert_eq!(content.chunks(step as usize).count(), batch.chunks().len());
        let mut result = profile.unwrap().to_vec();
        result.extend_from_slice(envelope.chunk_root().as_bytes());
        result.extend_from_slice(&envelope.chunk_count().to_le_bytes());
        (0, result)
    }
}

fn main() -> io::Result<()> {
    let fixtures = [
        Fixture::new("x", vec![0xff], 1, 1, 0),
        Fixture::new(&"b".repeat(128), (0..=255).collect(), 9, u64::MAX, 12),
        Fixture::new("x", vec![0xff], 1, 2, 0),
    ];
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut width = [0; 4];
        if input.read(&mut width[..1])? == 0 {
            return Ok(());
        }
        input.read_exact(&mut width[1..])?;
        let size = u32::from_le_bytes(width) as usize;
        assert!((9..=1_048_577).contains(&size));
        let mut raw = vec![0; size];
        input.read_exact(&mut raw)?;
        let step = u32::from_le_bytes(raw[..4].try_into().unwrap());
        let limit = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        let f = &fixtures[raw[8] as usize];
        let (code, result) = f.run(&raw[9..], step, limit);
        assert_eq!(result.len(), if code == 0 {68} else {0});
        output.write_all(&[code])?;
        output.write_all(&(f.prefix.len() as u32).to_le_bytes())?;
        output.write_all(&f.prefix)?;
        output.write_all(&result)?;
    }
}
