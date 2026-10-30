//! Deliberately public deterministic research keys. Never deploy these seeds.
use ml_dsa::{Keypair, MlDsa65, Signature, SignatureEncoding, Signer, SigningKey};
use trnm_protocol::pq_frame::{ml_dsa_65_key_id_from_spki, ML_DSA_65_SIGNATURE_BYTES};
use trnm_protocol::pq_native_accounts_v2::{self as wire, Common, WitnessKey};

pub struct Key {
    signing: SigningKey<MlDsa65>,
    pub spki: Vec<u8>,
    pub id: [u8; 32],
}
impl Key {
    pub fn public_test_seed(value: u8) -> Self {
        let signing = SigningKey::<MlDsa65>::from_seed(&[value; 32].into());
        let mut spki = include_bytes!("../fixtures/pq_transfer/public.der")[..22].to_vec();
        spki.extend(signing.verifying_key().encode().as_slice());
        let id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
        Self { signing, spki, id }
    }
}

pub struct Witness<'a> {
    pub key: &'a Key,
    pub role: u8,
    pub generation: u64,
    pub carried: bool,
}

pub fn signed(
    common: &Common,
    kind: u8,
    payload: &[u8],
    witnesses: &[Witness<'_>],
    randomness: Option<[u8; 32]>,
) -> Vec<u8> {
    let descriptors: Vec<_> = witnesses
        .iter()
        .map(|w| WitnessKey {
            role: w.role,
            generation: w.generation,
            key_id: w.key.id,
            spki: w.carried.then(|| w.key.spki.clone()),
        })
        .collect();
    let frames: Vec<_> = witnesses
        .iter()
        .enumerate()
        .map(|(index, witness)| {
            let statement =
                wire::signing_statement(common, kind, payload, &descriptors, index).unwrap();
            let signature: Signature<MlDsa65> = match randomness {
                Some(rnd) => witness
                    .key
                    .signing
                    .expanded_key()
                    .sign_internal(&[&[0, 0], &statement], &rnd.into()),
                None => witness.key.signing.sign(&statement),
            };
            let mut frame = statement.to_vec();
            frame.extend((ML_DSA_65_SIGNATURE_BYTES as u16).to_be_bytes());
            frame.extend(signature.to_bytes().as_slice());
            frame
        })
        .collect();
    wire::encode(common, kind, payload, &descriptors, &frames).unwrap()
}
