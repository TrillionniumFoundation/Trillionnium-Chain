use std::io::{self, Write};
use trnm_data_availability::{
    DaAuthorAuthorityV1, DaCommitteeDescriptorV1, DaMemberV1, DaPolicyV1, Hash32V1,
    ProtocolContextV1, UnsignedTransactionBatchV1,
};

const PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
fn digest(byte: u8) -> Hash32V1 {
    Hash32V1::new([byte; 32])
}

fn fixture(
    tag: u32, chain: &str, author: Vec<u8>, sequence: u64, item: Vec<u8>, max_chunk: u32,
    out: &mut impl Write,
) -> io::Result<()> {
    let context = ProtocolContextV1::new(digest(1), chain, digest(2)).unwrap();
    let member = DaMemberV1::new(PUBLIC, 1, None, digest(3), digest(4)).unwrap();
    let cap = 2_097_152;
    let committee = DaCommitteeDescriptorV1::new_transaction_batch(
        context, 7, vec![member], 2, cap, cap, 64, 4,
    ).unwrap();
    let authority = DaAuthorAuthorityV1::new(author.clone(), PUBLIC, 1, u64::MAX, cap, 4).unwrap();
    let policy = DaPolicyV1::new_transaction_batch(
        &committee, vec![authority], max_chunk, 512, 4, cap, 50, 20,
    ).unwrap();
    let batch = UnsignedTransactionBatchV1::build(&committee, &policy, author.clone(), sequence, vec![item])
        .expect("the original batch owns construction of all chunks");
    assert_eq!(batch.content_bytes(), batch.chunks().iter().flat_map(|chunk| chunk.bytes().iter().copied()).collect::<Vec<_>>());
    let coord_len = 173 + chain.len() + author.len();
    for (i, chunk) in batch.chunks().iter().enumerate() {
        assert_eq!(chunk.index() as usize, i);
        let canonical = borsh::to_vec(chunk).expect("original complete chunk serialization");
        let coordinate = &canonical[..coord_len];
        let committed_id = &canonical[coord_len..coord_len+32];
        let bytes_vector = &canonical[coord_len+32..canonical.len()-32];
        let committed_content = &canonical[canonical.len()-32..];
        assert_eq!(u64::from_le_bytes(coordinate[coord_len-8..].try_into().unwrap()), chunk.bytes().len() as u64);
        assert_eq!(u32::from_le_bytes(coordinate[coord_len-12..coord_len-8].try_into().unwrap()), chunk.index());
        assert_eq!(committed_id, chunk.chunk_id().as_bytes());
        assert_eq!(&bytes_vector[4..], chunk.bytes());
        assert_eq!(u32::from_le_bytes(bytes_vector[..4].try_into().unwrap()) as usize, chunk.bytes().len());
        for v in [tag, chunk.index(), coord_len as u32, (coordinate.len()+bytes_vector.len()) as u32] {
            out.write_all(&v.to_le_bytes())?;
        }
        out.write_all(coordinate)?;
        out.write_all(bytes_vector)?;
        out.write_all(committed_id)?;
        out.write_all(committed_content)?;
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let out = &mut io::stdout().lock();
    fixture(1, "x", b"a".to_vec(), 1, vec![8; 25], 32, out)?;
    fixture(2, "x", b"a".to_vec(), 1, vec![9; 25], 32, out)?;
    fixture(3, "x", b"a".to_vec(), 2, vec![8; 25], 32, out)?;
    fixture(4, "\0\t\n\r", b"\0\xff".to_vec(), 1, vec![3; 27], 32, out)?;
    fixture(5, "y", b"s".to_vec(), 1, vec![1; 26], 32, out)?;
    fixture(6, "x", b"a".to_vec(), 1, vec![8; 80], 16, out)?;
    fixture(7, &"x".repeat(128), (0..=255).collect(), u64::MAX, vec![3; 129], 32, out)?;
    for n in 0..2 {
        let width = 1_048_576 + n;
        let bytes = width - 179;
        fixture(8+n as u32, "x", b"a".to_vec(), 1, vec![7; bytes-8], bytes as u32, out)?;
    }
    Ok(())
}
