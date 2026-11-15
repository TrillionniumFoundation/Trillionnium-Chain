//! Separate research profile using framed SHA3-512 for MMCS and transcript hashing.
//!
//! Every role uses the same concrete SHA3-512 implementation. Distinct byte
//! encodings are not a claim of independent random oracles or quantum security.
//! This module adds no recursive SHA3 AIR and changes no legacy configuration.

use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::PrimeField64;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use p3_uni_stark::{Proof, StarkConfig};
use serde_json::{Value, json};
use sha3::{Digest, Sha3_512};

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 2>;
pub const GOLDILOCKS_ORDER: u64 = 18_446_744_069_414_584_321;
pub const LOG_BLOWUP: usize = 2;
pub const LOG_FINAL_POLY_LEN: usize = 0;
pub const MAX_LOG_ARITY: usize = 1;
pub const NUM_QUERIES: usize = 64;
pub const SHA_DEGREE_BITS: usize = 13;
pub const PACKED_CARRY_DEGREE_BITS: usize = 14;
pub const SHA_WIDTH: usize = 7728;
pub const SHA_PRE_WIDTH: usize = 27;
pub const PACKED_CARRY_WIDTH: usize = 370;
pub const PACKED_CARRY_PRE_WIDTH: usize = 180;

const _: () = {
    assert!(Val::ORDER_U64 == GOLDILOCKS_ORDER);
    assert!(p3_sha256_air::NUM_SHA256_COLS == SHA_WIDTH);
    assert!(crate::sha_air::PREPROCESSED_WIDTH == SHA_PRE_WIDTH);
    assert!(5 * crate::arith_carry_air::CARRY_WIDTH == PACKED_CARRY_WIDTH);
    assert!(5 * crate::arith_carry_air::CARRY_PREPROCESSED_WIDTH == PACKED_CARRY_PRE_WIDTH);
};

pub const PROFILE_ID: &[u8] = b"TRNM-W1-P3-SHA3-512-TAGGED-R1";
pub const FRAME_MAGIC: &[u8] = b"TRNM-W1-SHARED-HASH\0";
/// Frozen parameters are included in every application hash frame.
pub const DESCRIPTOR: &[u8] = b"p3=0.8.0;sha3=512;r=576;c=1024;F=18446744069414584321;E=X^2-7;binary;cap=0;log_blowup=2;log_final_poly=0;max_log_arity=1;queries=64;pow=0;zk=0;sha=d13,w7728,p27,q2,next1;carry=d14,w370,p180,q1,next0";
pub const DIGEST_BYTES: usize = 64;
pub type Context = [u8; DIGEST_BYTES];
/// Eight raw little-endian words preserve every SHA3 output bit. They are not
/// Goldilocks elements, and must never be reduced modulo the field order.
pub type MerkleDigest = [u64; 8];

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component {
    Sha = 1,
    PackedCarry = 4,
}

impl TryFrom<u32> for Component {
    type Error = &'static str;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Sha),
            4 => Ok(Self::PackedCarry),
            _ => Err("unsupported SHA3 profile component"),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Leaf = 1,
    Branch = 2,
    Transcript = 3,
    StatementContext = 4,
}

/// All variable byte strings in this header have explicit little-endian lengths.
/// The payload follows the header; its byte count is a fixed-width suffix, which
/// permits streaming without collecting unknown-length iterators.
pub fn frame_header(component: u32, role: Role, context: &Context) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(FRAME_MAGIC);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&(PROFILE_ID.len() as u16).to_le_bytes());
    bytes.extend_from_slice(PROFILE_ID);
    bytes.extend_from_slice(&(DESCRIPTOR.len() as u16).to_le_bytes());
    bytes.extend_from_slice(DESCRIPTOR);
    bytes.extend_from_slice(&component.to_le_bytes());
    bytes.push(role as u8);
    bytes.extend_from_slice(context);
    bytes
}

fn hash_frame(component: u32, role: Role, context: &Context, bytes: &[u8]) -> Context {
    let mut hash = Sha3_512::new();
    hash.update(frame_header(component, role, context));
    hash.update(bytes);
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.finalize().into()
}

pub fn digest_words(bytes: Context) -> MerkleDigest {
    core::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()))
}

pub fn digest_bytes(words: MerkleDigest) -> Context {
    let mut bytes = [0u8; DIGEST_BYTES];
    for (chunk, word) in bytes.chunks_exact_mut(8).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// A typed, length-bound digest of the canonical public statement and the two
/// independent expected inputs. Call only after the application validates the
/// statement encoding and plans against those expectations.
pub fn statement_context(
    public: &[u8],
    expected_header: &[u8],
    expected_artifacts: &[u8],
) -> Context {
    let mut payload = Vec::new();
    payload.extend_from_slice(&3u32.to_le_bytes());
    for (tag, bytes) in [(1u8, public), (2, expected_header), (3, expected_artifacts)] {
        payload.push(tag);
        payload.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        payload.extend_from_slice(bytes);
    }
    hash_frame(0, Role::StatementContext, &[0u8; DIGEST_BYTES], &payload)
}

#[derive(Clone, Debug)]
pub struct LeafHasher {
    prefix: Sha3_512,
}

impl LeafHasher {
    pub fn new(component: Component, context: Context) -> Self {
        let mut prefix = Sha3_512::new();
        prefix.update(frame_header(component as u32, Role::Leaf, &context));
        Self { prefix }
    }
}

impl CryptographicHasher<Val, MerkleDigest> for LeafHasher {
    fn hash_iter<I>(&self, input: I) -> MerkleDigest
    where
        I: IntoIterator<Item = Val>,
    {
        let mut hash = self.prefix.clone();
        let mut length = 0u64;
        for value in input {
            hash.update(value.to_unique_u64().to_le_bytes());
            length = length.checked_add(8).expect("leaf byte length overflow");
        }
        hash.update(length.to_le_bytes());
        digest_words(hash.finalize().into())
    }
}

#[derive(Clone, Debug)]
pub struct BranchCompressor {
    prefix: Sha3_512,
}

impl BranchCompressor {
    pub fn new(component: Component, context: Context) -> Self {
        let mut prefix = Sha3_512::new();
        prefix.update(frame_header(component as u32, Role::Branch, &context));
        Self { prefix }
    }
}

impl PseudoCompressionFunction<MerkleDigest, 2> for BranchCompressor {
    fn compress(&self, input: [MerkleDigest; 2]) -> MerkleDigest {
        let mut hash = self.prefix.clone();
        for digest in input {
            for word in digest {
                hash.update(word.to_le_bytes());
            }
        }
        hash.update(128u64.to_le_bytes());
        digest_words(hash.finalize().into())
    }
}

#[derive(Clone, Debug)]
pub struct TranscriptHasher {
    prefix: Sha3_512,
}

impl TranscriptHasher {
    pub fn new(component: Component, context: Context) -> Self {
        let mut prefix = Sha3_512::new();
        prefix.update(frame_header(component as u32, Role::Transcript, &context));
        Self { prefix }
    }
}

impl CryptographicHasher<u8, Context> for TranscriptHasher {
    fn hash_iter<I>(&self, input: I) -> Context
    where
        I: IntoIterator<Item = u8>,
    {
        let mut hash = self.prefix.clone();
        let mut length = 0u64;
        // Buffer only one SHA3-512 rate block, including for non-sized iterators.
        let mut block = [0u8; 72];
        let mut used = 0;
        for byte in input {
            block[used] = byte;
            used += 1;
            length = length
                .checked_add(1)
                .expect("transcript byte length overflow");
            if used == block.len() {
                hash.update(block);
                used = 0;
            }
        }
        hash.update(&block[..used]);
        hash.update(length.to_le_bytes());
        hash.finalize().into()
    }
}

pub type ValMmcs = MerkleTreeMmcs<Val, u64, LeafHasher, BranchCompressor, 2, 8>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Challenger = SerializingChallenger64<Val, HashChallenger<u8, TranscriptHasher, 64>>;
pub type Dft = Radix2DitParallel<Val>;
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
pub type W1Proof = Proof<Config>;

/// New profile only. Callers select a closed component enum and a 64-byte
/// statement context; they cannot select weaker FRI or hashing parameters.
pub fn config(component: Component, context: Context) -> Config {
    let mmcs = ValMmcs::new(
        LeafHasher::new(component, context),
        BranchCompressor::new(component, context),
        0,
    );
    let fri_params = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: LOG_FINAL_POLY_LEN,
        max_log_arity: MAX_LOG_ARITY,
        num_queries: NUM_QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ChallengeMmcs::new(mmcs.clone()),
    };
    let pcs = Pcs::new(Dft::default(), mmcs, fri_params);
    let challenger = Challenger::new(HashChallenger::new(
        Vec::new(),
        TranscriptHasher::new(component, context),
    ));
    Config::new(pcs, challenger)
        .with_ood_proof_of_work_bits(0)
        .with_lookup_proof_of_work_bits(0)
}

pub fn profile_metadata(context: &Context) -> Value {
    json!({
        "schema":"w1-p3-tagged-sha3-512-research-profile-v1",
        "qualification":"HOLD_NO_GO", "profile_id":String::from_utf8_lossy(PROFILE_ID),
        "descriptor":String::from_utf8_lossy(DESCRIPTOR), "statement_context_hex":hex::encode(context),
        "shared_primitive":"one concrete FIPS 202 SHA3-512 implementation for leaf, branch, transcript, and statement context",
        "sha3":{"rate_bits":576,"capacity_bits":1024,"digest_bytes":64},
        "mmcs":{"arity":2,"cap_height":0,"digest_encoding":"8 raw little-endian u64 words, no field reduction","leaf_encoding":"canonical Goldilocks u64le stream with byte-length suffix","branch_payload_bytes":128,"position_tagged":false,"matrix_boundary_tagged":false},
        "transcript":{"adapter":"P3 0.8.0 HashChallenger<u8, TranscriptHasher,64> with SerializingChallenger64","field_sampling":"8-byte little-endian candidates; reject candidates >= Goldilocks modulus; extension coefficients sampled separately","query_sampling":"mask 8-byte samples as required by P3","byte_order":"HashChallenger pops output bytes in reverse digest order","application_context":"typed length-framed canonical public statement + independent expected header + independent expected artifacts","p3_message_schedule":"unchanged frozen P3 transcript order; no new per-message semantic tags", "inherited_state_alias":"HashChallenger does not encode observe-call boundaries or count of bytes already popped within an output block before a new observation; generic transcript-history injectivity is not claimed"},
        "fri":{"log_blowup":LOG_BLOWUP,"log_final_poly_len":LOG_FINAL_POLY_LEN,"max_log_arity":MAX_LOG_ARITY,"num_queries":NUM_QUERIES,"all_grinding_bits":0},
        "unchanged_w1_relation":"existing W1 SHA-256 AIR plus five-lane packed carry AIR",
        "new_recursive_sha3_air":false,"independent_role_oracle_claim":false,
        "concrete_binding_bits":Value::Null,"complete_noninteractive_security_bits":Value::Null,
        "quantum_security_bits":Value::Null,"lifecycle_security_bits":Value::Null,
        "open_obligations":["joint concrete shared-hash binding and Fiat-Shamir analysis","actual MMCS opening geometry including adversarial sibling digests","quantum and preprocessing-advice composition","recursive AIR and in-circuit verification cost"]
    })
}
