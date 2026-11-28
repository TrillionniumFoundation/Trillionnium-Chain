use borsh::{from_slice, to_vec};
use ed25519_dalek::{Signer, SigningKey};
use std::io::{self, Write};
use trnm_data_availability::{
    AvailabilityCertificateV1, DaAttestationBodyV1, DaAttestationV1, DaAuthorAuthorityV1,
    DaBatchAuthorV1, DaBatchEnvelopeV1, DaCommitteeDescriptorV1, DaErrorCodeV1, DaMemberV1,
    DaPolicyV1, Hash32V1, ProtocolContextV1, UnsignedTransactionBatchV1,
};

fn hash(b: u8) -> Hash32V1 {
    Hash32V1::new([b; 32])
}

fn batch(
    c: &DaCommitteeDescriptorV1,
    p: &DaPolicyV1,
    a: &[u8],
    k: &SigningKey,
    marker: u8,
) -> (DaBatchEnvelopeV1, DaBatchAuthorV1) {
    let source = UnsignedTransactionBatchV1::build(
        c, p, a.to_vec(), 7, vec![vec![marker, 1], vec![marker; 65]],
    ).unwrap();
    let e = source.envelope().clone();
    let root = DaBatchAuthorV1::signing_root(&e).unwrap();
    let verified = DaBatchAuthorV1::from_signature(
        &e, k.verifying_key().to_bytes(), k.sign(root.as_bytes()).to_bytes().to_vec(),
    ).unwrap();
    (e, verified)
}

fn attestation(
    c: &DaCommitteeDescriptorV1,
    envelope: &DaBatchEnvelopeV1,
    member: &DaMemberV1,
    signer: &SigningKey,
) -> DaAttestationV1 {
    let mut raw = 1_u16.to_le_bytes().to_vec();
    raw.extend(to_vec(envelope.context()).unwrap());
    raw.push(envelope.namespace().tag());
    raw.extend(envelope.epoch().to_le_bytes());
    raw.extend(envelope.committee_id().as_bytes());
    raw.extend(envelope.batch_id().unwrap().as_bytes());
    raw.extend(envelope.content_root().as_bytes());
    raw.extend(envelope.chunk_root().as_bytes());
    raw.extend(envelope.retention_end_epoch().to_le_bytes());
    raw.extend(member.definition_hash().as_bytes());
    raw.extend(to_vec(&envelope.author_id().to_vec()).unwrap());
    raw.extend(envelope.author_sequence().to_le_bytes());
    raw.extend(1_u64.to_le_bytes());
    raw.extend(hash(37).as_bytes());
    let body: DaAttestationBodyV1 = from_slice(&raw).unwrap();
    assert_eq!(to_vec(&body).unwrap(), raw);
    let root = DaAttestationV1::signing_root(&body).unwrap();
    let att = DaAttestationV1::from_signature(
        c, body, signer.sign(root.as_bytes()).to_bytes().to_vec(),
    ).unwrap();
    att.verify(c).unwrap();
    att
}

fn report(
    out: &mut impl Write,
    c: &DaCommitteeDescriptorV1,
    cert: &[u8],
    want: u8,
) -> io::Result<()> {
    let obj = from_slice::<AvailabilityCertificateV1>(cert).unwrap();
    assert_eq!(to_vec(&obj).unwrap(), cert);
    let seen = match obj.verify(c) {
        Ok(()) => 0,
        Err(error) => match (error.code(), error.message()) {
            (DaErrorCodeV1::InsufficientWeight, _) => 231,
            (DaErrorCodeV1::Conflict, _) => 232,
            (DaErrorCodeV1::IdentifierMismatch, _) => 222,
            (DaErrorCodeV1::InvalidSignature, "invalid Ed25519 signature length") => 224,
            other => panic!("unexpected original verify result {other:?}"),
        },
    };
    assert_eq!(seen, want);
    let committee = to_vec(c).unwrap();
    let cut = committee.len() as u32;
    let len = cut + cert.len() as u32 + 4;
    out.write_all(&[seen])?;
    out.write_all(&len.to_le_bytes())?;
    out.write_all(&committee)?;
    out.write_all(cert)?;
    out.write_all(&cut.to_le_bytes())
}

fn main() -> io::Result<()> {
    let mut out = io::stdout().lock();
    // Private isolated fixture identities only; no external key can enter.
    let author_key = SigningKey::from_bytes(&[81; 32]);
    let attestor_keys = [21, 42, 63].map(|b| SigningKey::from_bytes(&[b; 32]));
    let unit = (1_u128 << 64) - 2;
    let weights = [unit + 1, unit, unit];
    let mut roster = attestor_keys.iter().zip(weights).map(|(key, weight)| {
        let member = DaMemberV1::new(
            key.verifying_key().to_bytes(), weight, None, hash(3), hash(4),
        ).unwrap();
        (member, key)
    }).collect::<Vec<_>>();
    roster.sort_by_key(|(member, _)| member.definition_hash());
    let ctx = ProtocolContextV1::new(hash(1), "standard-certificate-fixture", hash(2)).unwrap();
    let c = DaCommitteeDescriptorV1::new_transaction_batch(
        ctx, 90, roster.iter().map(|(member, _)| member.clone()).collect(),
        13, 8192, 8192, 32, 4,
    ).unwrap();
    assert_eq!(c.threshold_weight(), 2 * unit + 1);
    let a = b"disposable-author";
    let authority = DaAuthorAuthorityV1::new(
        a.to_vec(), author_key.verifying_key().to_bytes(), 1, 30, 8192, 4,
    ).unwrap();
    let p = DaPolicyV1::new_transaction_batch(&c, vec![authority], 32, 256, 4, 16384, 50, 20)
        .unwrap();
    let (e, author) = batch(&c, &p, a, &author_key, 5);
    let (other, _) = batch(&c, &p, a, &author_key, 6);
    let rows = roster.iter().map(|(m, key)| attestation(&c, &e, m, key))
        .collect::<Vec<_>>();
    let light = roster.iter().position(|(m, _)| m.weight() == unit).unwrap();
    let heavy = roster.iter().position(|(m, _)| m.weight() == unit + 1).unwrap();
    let exact = rows.iter().enumerate().filter_map(|(i, x)| {
        (i == heavy || i == light).then_some(x.clone())
    }).collect::<Vec<_>>();
    let below = rows.iter().enumerate().filter_map(|(i, x)| {
        (i != heavy).then_some(x.clone())
    }).collect::<Vec<_>>();
    let full = AvailabilityCertificateV1::build(&c, e.clone(), author.clone(), rows.clone())
        .unwrap();
    let threshold = AvailabilityCertificateV1::build(&c, e.clone(), author, exact.clone()).unwrap();
    let wire = to_vec(&full).unwrap();
    report(&mut out, &c, &wire, 0)?;
    report(&mut out, &c, &to_vec(&threshold).unwrap(), 0)?;
    let complete_rows = to_vec(&rows).unwrap();
    let endpoint = wire.len() - 32;
    let at = endpoint - complete_rows.len();
    assert_eq!(&wire[at..endpoint], complete_rows);
    let replace = |list: Vec<DaAttestationV1>| {
        [&wire[..at], &to_vec(&list).unwrap(), &wire[endpoint..]].concat()
    };
    report(&mut out, &c, &replace(below), 231)?;
    report(&mut out, &c, &replace(vec![]), 231)?;
    report(&mut out, &c, &replace(exact.iter().cloned().rev().collect()), 232)?;
    report(&mut out, &c, &replace(vec![rows[0].clone(), rows[0].clone()]), 232)?;
    let other_row = attestation(&c, &other, &roster[0].0, roster[0].1);
    report(&mut out, &c, &replace(vec![other_row, rows[1].clone(), rows[2].clone()]), 232)?;
    let mut short = to_vec(&rows[0]).unwrap();
    let signature_len = short.len() - 68;
    short[signature_len..signature_len+4].copy_from_slice(&63_u32.to_le_bytes());
    short.pop();
    let short = from_slice::<DaAttestationV1>(&short).unwrap();
    report(&mut out, &c, &replace(vec![short, rows[1].clone(), rows[2].clone()]), 224)?;
    let mut wrong_id = wire;
    wrong_id[endpoint] ^= 1;
    report(&mut out, &c, &wrong_id, 222)?;
    Ok(())
}
