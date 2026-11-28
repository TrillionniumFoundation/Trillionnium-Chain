use borsh::{from_slice, to_vec};
use ed25519_dalek::{Signer, SigningKey};
use std::io::{self, Write};
use trnm_data_availability::{
    DaAuthorAuthorityV1, DaBatchAuthorV1, DaBatchEnvelopeV1, DaCommitteeDescriptorV1,
    DaErrorCodeV1, DaMemberV1, DaPolicyV1, Hash32V1, ProtocolContextV1,
    UnsignedTransactionBatchV1,
};

fn hash(byte: u8) -> Hash32V1 {
    Hash32V1::new([byte; 32])
}

fn envelope(
    chain: &str,
    author: Vec<u8>,
    key: [u8; 32],
    sequence: u64,
    marker: u8,
) -> DaBatchEnvelopeV1 {
    let context = ProtocolContextV1::new(hash(1), chain, hash(2)).unwrap();
    let member = DaMemberV1::new(key, 7, None, hash(3), hash(4)).unwrap();
    let committee =
        DaCommitteeDescriptorV1::new_transaction_batch(context, 7, vec![member], 2, 8192, 4096, 32, 4)
            .unwrap();
    let authority = DaAuthorAuthorityV1::new(author.clone(), key, 1, u64::MAX, 8192, 4).unwrap();
    let policy =
        DaPolicyV1::new_transaction_batch(&committee, vec![authority], 32, 256, 4, 16384, 50, 20)
            .unwrap();
    let transactions = vec![vec![marker, 0, 1], vec![marker; 65]];
    UnsignedTransactionBatchV1::build(&committee, &policy, author, sequence, transactions)
        .unwrap()
        .envelope()
        .clone()
}

fn report(
    out: &mut impl Write,
    env: &DaBatchEnvelopeV1,
    statement: &[u8],
    key: [u8; 32],
    signature: Vec<u8>,
    expected: u8,
) -> io::Result<()> {
    let seen = DaBatchAuthorV1::from_signature(env, key, signature.clone());
    let standard = match seen {
        Ok(author) => {
            assert_eq!(expected, 0);
            Some(to_vec(&author).unwrap())
        }
        Err(error) => {
            assert_eq!(expected, 201);
            assert_eq!(error.code(), DaErrorCodeV1::InvalidSignature);
            None
        }
    };
    let mut role = statement.to_vec();
    role.extend_from_slice(&0_u16.to_le_bytes());
    role.extend_from_slice(&key);
    role.extend(to_vec(&signature).unwrap());
    if let Some(canonical) = standard {
        assert_eq!(role, canonical);
    }
    let decoded = from_slice::<DaBatchAuthorV1>(&role).unwrap();
    assert_eq!(to_vec(&decoded).unwrap(), role);
    let env = to_vec(env).unwrap();
    let extent = env.len() as u32;
    out.write_all(&[expected])?;
    out.write_all(&(extent + role.len() as u32 + 4).to_le_bytes())?;
    out.write_all(&env)?;
    out.write_all(&role)?;
    out.write_all(&extent.to_le_bytes())
}

fn main() -> io::Result<()> {
    // These local fixture identities are deliberately detached from any
    // account, service, deployment, policy authority, or external key source.
    let normal = SigningKey::from_bytes(&[23; 32]);
    let different = SigningKey::from_bytes(&[51; 32]);
    let key = normal.verifying_key().to_bytes();
    let other_key = different.verifying_key().to_bytes();
    let mut out = io::stdout().lock();
    for (chain, author, sequence) in [
        ("standard-fixture".to_string(), b"native-test-author".to_vec(), 7),
        ("a".repeat(128), (0..=255).collect(), u64::MAX),
    ] {
        let env = envelope(&chain, author.clone(), key, sequence, 8);
        let other = envelope(&chain, author, key, sequence, 9);
        let root = DaBatchAuthorV1::signing_root(&env).unwrap();
        let other_root = DaBatchAuthorV1::signing_root(&other).unwrap();
        assert_ne!(root, other_root);
        let valid = normal.sign(root.as_bytes()).to_bytes();
        let wrong_message = normal.sign(other_root.as_bytes()).to_bytes();
        let signed = DaBatchAuthorV1::from_signature(&env, key, valid.to_vec()).unwrap();
        let signed_wire = to_vec(&signed).unwrap();
        let statement = &signed_wire[..signed_wire.len() - 102];
        assert_eq!(&statement[..2], &[1, 0]);
        assert_eq!(&statement[statement.len()-32..], env.batch_id().unwrap().as_bytes());
        for (pk, sig, result) in [
            (key, valid.to_vec(), 0),
            (other_key, valid.to_vec(), 201),
            (key, valid[..63].to_vec(), 201),
            (key, vec![], 201),
            (key, [valid.as_slice(), &[0]].concat(), 201),
            (key, wrong_message.to_vec(), 201),
        ] {
            report(&mut out, &env, statement, pk, sig, result)?;
        }
    }
    Ok(())
}
