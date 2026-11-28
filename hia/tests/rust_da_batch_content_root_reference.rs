use std::io::{self, Read, Write};
use trnm_data_availability::{
    DaAuthorAuthorityV1, DaCommitteeDescriptorV1, DaErrorCodeV1, DaMemberV1, DaPolicyV1,
    Hash32V1, ProtocolContextV1, UnsignedTransactionBatchV1,
};

// Public RFC 8032 fixture bytes. The original unsigned API does not sign.
const KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
    0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
    0xf7, 0x07, 0x51, 0x1a,
];
const MAX_BYTES: u64 = 2 * 1024 * 1024;

fn main() -> io::Result<()> {
    let word = |x| Hash32V1::new([x; 32]);
    let context = ProtocolContextV1::new(word(3), "hia-content-reference", word(4)).unwrap();
    let member = DaMemberV1::new(KEY, 1, None, word(5), word(6)).unwrap();
    let committee = DaCommitteeDescriptorV1::new_transaction_batch(
        context, 1, vec![member], 2, MAX_BYTES, MAX_BYTES, 64, 4,
    ).unwrap();
    let author = b"local unsigned fixture".to_vec();
    let authority = DaAuthorAuthorityV1::new(author.clone(), KEY, 1, 9, MAX_BYTES, 4).unwrap();
    let policy = DaPolicyV1::new_transaction_batch(
        &committee, vec![authority], MAX_BYTES as u32, 4, 2, MAX_BYTES, 5, 4,
    ).unwrap();

    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut len = [0; 4];
        if input.read(&mut len[..1])? == 0 {
            return Ok(());
        }
        input.read_exact(&mut len[1..])?;
        let extent = u32::from_le_bytes(len) as usize;
        assert!(extent <= 1_048_577);
        let mut frame = vec![0; extent];
        input.read_exact(&mut frame)?;
        let mut result = Vec::new();
        let code = match borsh::from_slice::<Vec<Vec<u8>>>(&frame) {
            Err(_) => 100u8,
            Ok(rows) => {
                assert_eq!(borsh::to_vec(&rows).unwrap(), frame);
                match UnsignedTransactionBatchV1::build(
                    &committee, &policy, author.clone(), 1, rows,
                ) {
                    Ok(batch) => {
                        assert_eq!(batch.content_bytes(), frame);
                        let envelope = batch.envelope();
                        result.extend_from_slice(envelope.content_root().as_bytes());
                        result.extend_from_slice(&envelope.item_count().to_le_bytes());
                        result.extend_from_slice(&envelope.uncompressed_bytes().to_le_bytes());
                        0u8
                    }
                    Err(err) => match (err.code(), err.message()) {
                        (DaErrorCodeV1::InvalidBounds, "invalid transaction item count") => 40,
                        (DaErrorCodeV1::NonCanonical, "transaction entries must be nonempty and duplicate-free") => 41,
                        unexpected => panic!("Unexpected original unsigned content result: {unexpected:?}"),
                    },
                }
            }
        };
        assert_eq!(result.len(), if code == 0 {44} else {0});
        output.write_all(&[code])?;
        output.write_all(&result)?;
    }
}
