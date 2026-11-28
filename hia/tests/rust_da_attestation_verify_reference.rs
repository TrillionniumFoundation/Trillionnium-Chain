use borsh::{from_slice, to_vec};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use trnm_data_availability::{
    DaAttestationBodyV1, DaAttestationV1, DaCommitteeDescriptorV1, DaErrorCodeV1,
    DaMemberV1, Hash32V1, ProtocolContextV1,
};

fn sha_domain(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update((domain.len() as u32).to_le_bytes());
    s.update(domain);
    s.update(value);
    s.finalize().into()
}
fn packet(
    committee: &[u8],
    body: &[u8],
    sig: &[u8],
    scheme: u16,
    wrong_id: bool,
    expected: u8,
    out: &mut impl Write,
) -> io::Result<()> {
    let mut id = sha_domain(b"trnm.portable.v2.da-attestation.v1", body);
    if wrong_id { id[0] ^= 1; }
    let mut raw_att = body.to_owned();
    raw_att.extend(id);
    raw_att.extend(scheme.to_le_bytes());
    raw_att.extend(to_vec(&sig.to_vec()).unwrap());
    let att = from_slice::<DaAttestationV1>(&raw_att).unwrap();
    assert_eq!(to_vec(&att).unwrap(), raw_att);
    let comm = from_slice::<DaCommitteeDescriptorV1>(committee).unwrap();
    assert_eq!(to_vec(&comm).unwrap(), committee);
    let seen = match att.verify(&comm) {
        Ok(()) => 0,
        Err(e) => {
            use DaErrorCodeV1::*;
            let (kind, tag) = match e.message() {
                "attestation ID or scheme mismatch" => (IdentifierMismatch, 222),
                "attestor is not a committee member" => (InvalidCommittee, 223),
                "invalid Ed25519 signature length" => (InvalidSignature, 224),
                "strict Ed25519 verification failed" => (InvalidSignature, 225),
                "attestation does not bind the exact committed DA context" => (InvalidContext, 221),
                "committee threshold is not floor(2W/3)+1" => (InvalidCommittee, 212),
                "unknown DA namespace" => (UnsupportedNamespace, 214),
                other => panic!("unobserved original outcome: {other}"),
            };
            assert_eq!(kind, e.code());
            tag
        }
    };
    assert_eq!(seen, expected);
    let length = committee.len() + raw_att.len() + 4;
    out.write_all(&[seen])?;
    out.write_all(&(length as u32).to_le_bytes())?;
    out.write_all(committee)?;
    out.write_all(&raw_att)?;
    out.write_all(&(committee.len() as u32).to_le_bytes())
}

fn signed_fixture(out: &mut impl Write, label: String, index: u8) -> io::Result<()> {
    // Isolated deterministic test keys. No account, production identity, or
    // key provided by a caller participates in this source oracle.
    let keys = [7, 19, 231].map(|b| SigningKey::from_bytes(&[b ^ index; 32]));
    let mut paired = keys.iter().enumerate().map(|(i, key)| {
        (DaMemberV1::new(key.verifying_key().to_bytes(), (i+1) as u128, None,
            Hash32V1::new([3;32]), Hash32V1::new([4;32])).unwrap(), key)
    }).collect::<Vec<_>>();
    paired.sort_by_key(|(m, _)| m.definition_hash());
    let (member, signer) = paired.last().unwrap();
    let context = ProtocolContextV1::new(Hash32V1::new([1;32]), label.clone(),
                                        Hash32V1::new([2;32])).unwrap();
    let committee = DaCommitteeDescriptorV1::new_transaction_batch(
        context.clone(), 29, paired.iter().map(|(m,_)| m.clone()).collect(),
        1, 2, 3, 4, 5).unwrap();
    let cb = to_vec(&committee).unwrap();
    let ctx = to_vec(&context).unwrap();
    let body_n = 76 + label.len();
    let base_author = b"toy-da-signer".to_vec();
    let mkbody = |author: Vec<u8>| {
        let mut b = 1_u16.to_le_bytes().to_vec();
        b.extend(&ctx);
        b.push(0);
        b.extend(29_u64.to_le_bytes());
        b.extend(committee.committee_id().unwrap().as_bytes());
        for v in [60, 61, 62] { b.extend([v;32]); }
        b.extend(71_u64.to_le_bytes());
        b.extend(member.definition_hash().as_bytes());
        b.extend(to_vec(&author).unwrap());
        b.extend(19_u64.to_le_bytes());
        b.extend(33_u64.to_le_bytes());
        b.extend([90;32]);
        b
    };
    let original_sign = |body: &[u8]| {
        let body = from_slice::<DaAttestationBodyV1>(body).unwrap();
        let root = DaAttestationV1::signing_root(&body).unwrap();
        signer.sign(root.as_bytes()).to_bytes()
    };
    let raw = mkbody(base_author.clone());
    let sig = original_sign(&raw);
    let actual = DaAttestationV1::from_signature(
        &committee, from_slice(&raw).unwrap(), sig.to_vec()).unwrap();
    actual.verify(&committee).unwrap();
    packet(&cb, &raw, &sig, 0, false, 0, out)?;
    packet(&cb, &raw, &sig, 0, true, 222, out)?;
    packet(&cb, &raw, &[], 7, true, 222, out)?;
    packet(&cb, &raw, &sig[..63], 0, false, 224, out)?;
    packet(&cb, &raw, &[0;64], 0, false, 225, out)?;
    let mut s_bad = sig; s_bad[63] ^= 1;
    packet(&cb, &raw, &s_bad, 0, false, 225, out)?;
    let mut non_member = raw.clone();
    non_member[body_n+145..body_n+177].fill(0);
    assert!(committee.member(Hash32V1::new([0;32])).is_none());
    packet(&cb, &non_member, &[], 0, false, 223, out)?;
    packet(&cb, &non_member, &[], 0, true, 222, out)?;
    non_member[body_n] = 255;
    packet(&cb, &non_member, &[], 7, true, 214, out)?;
    let mut phase = raw.clone();
    phase[0] = 2;
    packet(&cb, &phase, &[], 7, true, 221, out)?;
    let mut bad_committee = cb.clone();
    let threshold = bad_committee.len() - 44;
    bad_committee[threshold..threshold+16].fill(0);
    packet(&bad_committee, &raw, &[], 7, true, 212, out)?;
    if index == 0 {
        let max_author = (1<<20) - (cb.len() + raw.len() - base_author.len() + 38 + 64 + 4);
        for length in [max_author, max_author+1] {
            let very_large = mkbody(vec![b'a'; length]);
            let very_sig = original_sign(&very_large);
            packet(&cb, &very_large, &very_sig, 0, false, 0, out)?;
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let mut out = io::stdout().lock();
    signed_fixture(&mut out, "native-da-verify".into(), 0)?;
    signed_fixture(&mut out, "z".repeat(128), 1)?;
    out.flush()
}
