//! Public deterministic test keys only. Never use these seeds for any authority.
use ml_dsa::{Keypair, MlDsa65, Signature, SignatureEncoding, Signer, SigningKey};
use trnm_protocol::pq_frame::{ML_DSA_65_SIGNATURE_BYTES, TPQ1_SIGNED_BYTES};
use trnm_protocol::pq_native_transfer_v1::{self as wire, ChainContext};

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
        let id = trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki(&spki).unwrap();
        Self { signing, spki, id }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn transfer(
        &self,
        context: ChainContext,
        recipient: [u8; 32],
        nonce: u64,
        expiry: u64,
        amount: u64,
        fee: u64,
        memo: &[u8],
        randomness: Option<[u8; 32]>,
    ) -> Vec<u8> {
        assert!(memo.len() <= 512);
        let body_len = 144 + memo.len();
        let mut raw = vec![0_u8; body_len + TPQ1_SIGNED_BYTES];
        raw[..6].copy_from_slice(b"QTX1\x01\x01");
        raw[6..38].copy_from_slice(&context.network);
        raw[38..70].copy_from_slice(&self.id);
        raw[70..102].copy_from_slice(&recipient);
        for (at, n) in [
            (102, 1_u64),
            (110, nonce),
            (118, expiry),
            (126, amount),
            (134, fee),
        ] {
            raw[at..at + 8].copy_from_slice(&n.to_be_bytes());
        }
        raw[142..144].copy_from_slice(&(memo.len() as u16).to_be_bytes());
        raw[144..body_len].copy_from_slice(memo);
        let statement = wire::signing_statement(&raw, &self.spki, context).unwrap();
        let signature: Signature<MlDsa65> = match randomness {
            Some(rnd) => self
                .signing
                .expanded_key()
                .sign_internal(&[&[0, 0], &statement], &rnd.into()),
            None => self.signing.sign(&statement),
        };
        raw[body_len..body_len + 176].copy_from_slice(&statement);
        raw[body_len + 176..body_len + 178]
            .copy_from_slice(&(ML_DSA_65_SIGNATURE_BYTES as u16).to_be_bytes());
        raw[body_len + 178..].copy_from_slice(signature.to_bytes().as_slice());
        wire::encode(&raw, &self.spki).unwrap()
    }
}
