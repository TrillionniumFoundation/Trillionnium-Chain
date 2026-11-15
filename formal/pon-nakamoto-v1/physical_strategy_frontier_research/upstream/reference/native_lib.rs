//! Exact native implementation of the research-only selected-event v1 relation.
//!
//! This is not W1, a STARK, a proof of minimum work, a consensus adapter, or an
//! effect-authorizing verifier. The caller retains Expected independently.
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const Q: u64 = 4_294_967_291;
pub const SIDE: usize = 8;
pub const BLOCK_WORDS: usize = 64;
pub const EXPECTED_BYTES: usize = 192;
pub const WITNESS_BYTES: usize = 1419;
pub const DOMAIN: &[u8] = b"TRNM-PON-SELECTED-EVENT-RESEARCH-R1\0";
pub const PROFILE: &[u8] = b"local-product8-fq4294967291-n64-r8-selected-v1";
pub type Hash = [u8; 32];
pub type Block = [u32; BLOCK_WORDS];
pub type MatrixBlocks = [Block; 64];
pub type Refusal = &'static str;

pub trait Meter {
    fn hash(&mut self, _bytes: usize) {}
    fn multiplications(&mut self, _n: u64) {}
    fn additions(&mut self, _n: u64) {}
}

#[derive(Default)]
pub struct NoMeter;
impl Meter for NoMeter {}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Counts {
    pub sha256_calls: u64,
    pub sha256_input_bytes: u64,
    pub sha256_compression_blocks: u64,
    pub scalar_multiplications: u64,
    pub scalar_additions: u64,
}
impl Meter for Counts {
    fn hash(&mut self, bytes: usize) {
        self.sha256_calls += 1;
        self.sha256_input_bytes += bytes as u64;
        self.sha256_compression_blocks += (bytes + 9).div_ceil(64) as u64;
    }
    fn multiplications(&mut self, n: u64) {
        self.scalar_multiplications += n;
    }
    fn additions(&mut self, n: u64) {
        self.scalar_additions += n;
    }
}

// Tags and part lengths are internal, fixed protocol values, not wire inputs.
fn h<M: Meter>(tag: &[u8], parts: &[&[u8]], meter: &mut M) -> Hash {
    assert!(tag.len() < 256);
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update([tag.len() as u8]);
    digest.update(tag);
    let mut length = DOMAIN.len() + 1 + tag.len();
    for part in parts {
        let n: u32 = part.len().try_into().expect("fixed internal hash part");
        digest.update(n.to_le_bytes());
        digest.update(part);
        length += 4 + part.len();
    }
    meter.hash(length);
    digest.finalize().into()
}

fn validate_block(block: &Block) -> Result<(), Refusal> {
    if block.iter().any(|&x| u64::from(x) >= Q) {
        return Err("FIELD");
    }
    Ok(())
}

fn words(block: &Block) -> [u8; 256] {
    let mut encoded = [0; 256];
    for (dst, word) in encoded.chunks_exact_mut(4).zip(block) {
        dst.copy_from_slice(&word.to_le_bytes());
    }
    encoded
}

/// Accumulation uses u128: eight canonical 32-bit products do not fit u64.
pub fn block_mul<M: Meter>(a: &Block, b: &Block, meter: &mut M) -> Block {
    let mut result = [0; BLOCK_WORDS];
    for row in 0..SIDE {
        for column in 0..SIDE {
            let mut sum = 0_u128;
            for inner in 0..SIDE {
                sum += u128::from(a[row * SIDE + inner]) * u128::from(b[inner * SIDE + column]);
            }
            result[row * SIDE + column] = (sum % u128::from(Q)) as u32;
        }
    }
    meter.multiplications(512);
    // Seven additions per eight-term dot product, excluding zero initialization.
    meter.additions(448);
    result
}

fn block_add<M: Meter>(a: &Block, b: &Block, meter: &mut M) -> Block {
    let result = std::array::from_fn(|i| ((u64::from(a[i]) + u64::from(b[i])) % Q) as u32);
    meter.additions(64);
    result
}

fn leaf<M: Meter>(label: u8, index: u8, block: &Block, meter: &mut M) -> Hash {
    h(
        b"leaf",
        &[PROFILE, &[label], &[index], &words(block)],
        meter,
    )
}

#[derive(Clone)]
pub struct Tree {
    levels: Vec<Vec<Hash>>,
}
impl Tree {
    pub fn build<M: Meter>(
        label: u8,
        blocks: &MatrixBlocks,
        meter: &mut M,
    ) -> Result<Self, Refusal> {
        if label != b'A' && label != b'B' {
            return Err("LEAF_ID");
        }
        for block in blocks {
            validate_block(block)?;
        }
        let mut levels = vec![blocks
            .iter()
            .enumerate()
            .map(|(i, block)| leaf(label, i as u8, block, meter))
            .collect::<Vec<_>>()];
        for level in 0..6 {
            let parent = levels[level]
                .chunks_exact(2)
                .map(|pair| {
                    h(
                        b"node",
                        &[PROFILE, &[label], &[level as u8], &pair[0], &pair[1]],
                        meter,
                    )
                })
                .collect();
            levels.push(parent);
        }
        Ok(Self { levels })
    }
    pub fn root(&self) -> Hash {
        self.levels[6][0]
    }
    pub fn opening(&self, mut index: usize) -> [Hash; 6] {
        std::array::from_fn(|level| {
            let sibling = self.levels[level][index ^ 1];
            index /= 2;
            sibling
        })
    }
}

fn check_opening<M: Meter>(
    root: &Hash,
    label: u8,
    mut index: u8,
    block: &Block,
    path: &[Hash; 6],
    meter: &mut M,
) -> Result<(), Refusal> {
    let mut digest = leaf(label, index, block, meter);
    for (level, sibling) in path.iter().enumerate() {
        let (left, right) = if index.is_multiple_of(2) {
            (&digest, sibling)
        } else {
            (sibling, &digest)
        };
        digest = h(
            b"node",
            &[PROFILE, &[label], &[level as u8], left, right],
            meter,
        );
        index /= 2;
    }
    if &digest != root {
        return Err("MERKLE");
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected {
    pub chain: Hash,
    pub parent: Hash,
    pub header_without_work: Hash,
    pub root_a: Hash,
    pub root_b: Hash,
    pub target: Hash,
}
impl Expected {
    pub fn validate(&self) -> Result<(), Refusal> {
        if self.target == [0; 32] {
            return Err("TARGET_ZERO");
        }
        Ok(())
    }
    pub fn commitment<M: Meter>(&self, meter: &mut M) -> Result<Hash, Refusal> {
        self.validate()?;
        let task = h(b"task", &[PROFILE, &self.root_a, &self.root_b], meter);
        Ok(h(
            b"context",
            &[
                PROFILE,
                &self.chain,
                &self.parent,
                &self.header_without_work,
                &task,
                &self.target,
            ],
            meter,
        ))
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() != EXPECTED_BYTES {
            return Err("EXPECTED_LENGTH");
        }
        let part = |index: usize| {
            bytes[index * 32..(index + 1) * 32]
                .try_into()
                .expect("exact slice")
        };
        Ok(Self {
            chain: part(0),
            parent: part(1),
            header_without_work: part(2),
            root_a: part(3),
            root_b: part(4),
            target: part(5),
        })
    }
    pub fn encode(&self) -> [u8; EXPECTED_BYTES] {
        let mut result = [0; EXPECTED_BYTES];
        for (chunk, value) in result.chunks_exact_mut(32).zip([
            &self.chain,
            &self.parent,
            &self.header_without_work,
            &self.root_a,
            &self.root_b,
            &self.target,
        ]) {
            chunk.copy_from_slice(value);
        }
        result
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub nonce: u64,
    pub coordinates: [u8; 3],
    pub a: Block,
    pub b: Block,
    pub path_a: [Hash; 6],
    pub path_b: [Hash; 6],
    pub noisy_product: Block,
    pub useful_product: Block,
}
impl Witness {
    // The transport is a research harness only, with exact length and no extensions.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() != WITNESS_BYTES {
            return Err("WITNESS_LENGTH");
        }
        let mut offset = 11;
        let mut read_block = || {
            let value = std::array::from_fn(|i| {
                u32::from_le_bytes(
                    bytes[offset + i * 4..offset + i * 4 + 4]
                        .try_into()
                        .expect("exact slice"),
                )
            });
            offset += 256;
            value
        };
        let a = read_block();
        let b = read_block();
        let path_a = std::array::from_fn(|i| {
            bytes[523 + i * 32..523 + (i + 1) * 32]
                .try_into()
                .expect("exact slice")
        });
        let path_b = std::array::from_fn(|i| {
            bytes[715 + i * 32..715 + (i + 1) * 32]
                .try_into()
                .expect("exact slice")
        });
        let noisy_product = std::array::from_fn(|i| {
            u32::from_le_bytes(
                bytes[907 + i * 4..911 + i * 4]
                    .try_into()
                    .expect("exact slice"),
            )
        });
        let useful_product = std::array::from_fn(|i| {
            u32::from_le_bytes(
                bytes[1163 + i * 4..1167 + i * 4]
                    .try_into()
                    .expect("exact slice"),
            )
        });
        Ok(Self {
            nonce: u64::from_le_bytes(bytes[..8].try_into().expect("exact slice")),
            coordinates: bytes[8..11].try_into().expect("exact slice"),
            a,
            b,
            path_a,
            path_b,
            noisy_product,
            useful_product,
        })
    }
    pub fn encode(&self) -> [u8; WITNESS_BYTES] {
        let mut result = [0; WITNESS_BYTES];
        result[..8].copy_from_slice(&self.nonce.to_le_bytes());
        result[8..11].copy_from_slice(&self.coordinates);
        result[11..267].copy_from_slice(&words(&self.a));
        result[267..523].copy_from_slice(&words(&self.b));
        for (i, value) in self.path_a.iter().enumerate() {
            result[523 + i * 32..555 + i * 32].copy_from_slice(value);
        }
        for (i, value) in self.path_b.iter().enumerate() {
            result[715 + i * 32..747 + i * 32].copy_from_slice(value);
        }
        result[907..1163].copy_from_slice(&words(&self.noisy_product));
        result[1163..1419].copy_from_slice(&words(&self.useful_product));
        result
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSelectedEvent {
    pub context: Hash,
    pub event_id: Hash,
    pub ticket: Hash,
    pub useful_product: Block,
}

pub fn seed<M: Meter>(ctx: &Expected, nonce: u64, meter: &mut M) -> Result<Hash, Refusal> {
    Ok(h(
        b"noise-seed",
        &[&ctx.commitment(meter)?, &nonce.to_le_bytes()],
        meter,
    ))
}
pub fn selected_coordinates<M: Meter>(seed: &Hash, meter: &mut M) -> [u8; 3] {
    let selector = h(b"selected-coordinate", &[seed], meter);
    [selector[0] & 7, selector[1] & 7, selector[2] & 7]
}

fn sample_eight(mut draw: impl FnMut(u32) -> Hash) -> Result<[u32; 8], Refusal> {
    let mut result = [0; 8];
    let mut count = 0;
    for counter in 0..128 {
        for bytes in draw(counter).chunks_exact(4) {
            let value = u32::from_le_bytes(bytes.try_into().expect("exact word"));
            if u64::from(value) < Q {
                result[count] = value;
                count += 1;
                if count == 8 {
                    return Ok(result);
                }
            }
        }
    }
    Err("NOISE_BUDGET")
}

pub fn noise_eight<M: Meter>(
    s: &Hash,
    label: u8,
    index: u8,
    meter: &mut M,
) -> Result<[u32; 8], Refusal> {
    if label >= 4 || index >= 64 {
        return Err("NOISE_COORD");
    }
    sample_eight(|counter| {
        h(
            b"noise-eight",
            &[s, &[label, index], &counter.to_le_bytes()],
            meter,
        )
    })
}

pub fn noise_blocks<M: Meter>(
    s: &Hash,
    coordinates: [u8; 3],
    meter: &mut M,
) -> Result<(Block, Block), Refusal> {
    let [bi, bk, bj] = coordinates;
    if coordinates.iter().any(|&i| i >= 8) {
        return Err("TILE_COORD");
    }
    let mut factors = [[0; 64]; 4];
    for label in 0..4 {
        for i in 0..8 {
            let index = match label {
                0 => bi * 8 + i,
                1 => i * 8 + bk,
                2 => bk * 8 + i,
                _ => i * 8 + bj,
            };
            factors[usize::from(label)][usize::from(i) * 8..usize::from(i + 1) * 8]
                .copy_from_slice(&noise_eight(s, label, index, meter)?);
        }
    }
    Ok((
        block_mul(&factors[0], &factors[1], meter),
        block_mul(&factors[2], &factors[3], meter),
    ))
}

pub fn statement<M: Meter>(ctx: &Expected, w: &Witness, meter: &mut M) -> Result<Hash, Refusal> {
    Ok(h(
        b"event",
        &[
            &ctx.commitment(meter)?,
            &w.nonce.to_le_bytes(),
            &w.coordinates,
            &words(&w.noisy_product),
            &words(&w.useful_product),
        ],
        meter,
    ))
}
pub fn ticket<M: Meter>(event: &Hash, meter: &mut M) -> Hash {
    h(b"ticket", &[event], meter)
}

pub fn verify<M: Meter>(
    ctx: &Expected,
    w: &Witness,
    meter: &mut M,
) -> Result<VerifiedSelectedEvent, Refusal> {
    ctx.validate()?;
    if w.coordinates.iter().any(|&i| i >= 8) {
        return Err("TILE_COORD");
    }
    let s = seed(ctx, w.nonce, meter)?;
    if selected_coordinates(&s, meter) != w.coordinates {
        return Err("SELECTED_COORD");
    }
    for block in [&w.a, &w.b, &w.noisy_product, &w.useful_product] {
        validate_block(block)?;
    }
    check_opening(
        &ctx.root_a,
        b'A',
        w.coordinates[0] * 8 + w.coordinates[1],
        &w.a,
        &w.path_a,
        meter,
    )?;
    check_opening(
        &ctx.root_b,
        b'B',
        w.coordinates[1] * 8 + w.coordinates[2],
        &w.b,
        &w.path_b,
        meter,
    )?;
    let event_id = statement(ctx, w, meter)?;
    let ticket = ticket(&event_id, meter);
    // Rust array ordering is the same lexicographic byte ordering as Python bytes.
    if ticket > ctx.target {
        return Err("TARGET");
    }
    let (e, f) = noise_blocks(&s, w.coordinates, meter)?;
    let a_plus_e = block_add(&w.a, &e, meter);
    let b_plus_f = block_add(&w.b, &f, meter);
    if block_mul(&a_plus_e, &b_plus_f, meter) != w.noisy_product {
        return Err("NOISY_PRODUCT");
    }
    if block_mul(&w.a, &w.b, meter) != w.useful_product {
        return Err("USEFUL_PRODUCT");
    }
    Ok(VerifiedSelectedEvent {
        context: ctx.commitment(meter)?,
        event_id,
        ticket,
        useful_product: w.useful_product,
    })
}

pub fn verify_bytes<M: Meter>(
    expected: &[u8],
    witness: &[u8],
    meter: &mut M,
) -> Result<VerifiedSelectedEvent, Refusal> {
    let ctx = Expected::decode(expected)?;
    let w = Witness::decode(witness)?;
    verify(&ctx, &w, meter)
}

pub struct PreparedTask {
    pub a: MatrixBlocks,
    pub b: MatrixBlocks,
    tree_a: Tree,
    tree_b: Tree,
    cached_products: Option<Box<[Block; 512]>>,
}
impl PreparedTask {
    pub fn new<M: Meter>(
        a: MatrixBlocks,
        b: MatrixBlocks,
        cache_products: bool,
        meter: &mut M,
    ) -> Result<Self, Refusal> {
        let tree_a = Tree::build(b'A', &a, meter)?;
        let tree_b = Tree::build(b'B', &b, meter)?;
        let cached_products = cache_products.then(|| {
            Box::new(std::array::from_fn(|index| {
                let bi = index / 64;
                let bk = (index / 8) % 8;
                let bj = index % 8;
                block_mul(&a[bi * 8 + bk], &b[bk * 8 + bj], meter)
            }))
        });
        Ok(Self {
            a,
            b,
            tree_a,
            tree_b,
            cached_products,
        })
    }
    pub fn roots(&self) -> (Hash, Hash) {
        (self.tree_a.root(), self.tree_b.root())
    }
    pub fn produce<M: Meter>(
        &self,
        ctx: &Expected,
        nonce: u64,
        meter: &mut M,
    ) -> Result<Witness, Refusal> {
        let s = seed(ctx, nonce, meter)?;
        let coordinates = selected_coordinates(&s, meter);
        if self.roots() != (ctx.root_a, ctx.root_b) {
            return Err("TASK_ROOT");
        }
        let [bi, bk, bj] = coordinates.map(usize::from);
        let a = self.a[bi * 8 + bk];
        let b = self.b[bk * 8 + bj];
        let (e, f) = noise_blocks(&s, coordinates, meter)?;
        let a_plus_e = block_add(&a, &e, meter);
        let b_plus_f = block_add(&b, &f, meter);
        let noisy_product = block_mul(&a_plus_e, &b_plus_f, meter);
        let useful_product = self.cached_products.as_ref().map_or_else(
            || block_mul(&a, &b, meter),
            |products| products[bi * 64 + bk * 8 + bj],
        );
        Ok(Witness {
            nonce,
            coordinates,
            a,
            b,
            path_a: self.tree_a.opening(bi * 8 + bk),
            path_b: self.tree_b.opening(bk * 8 + bj),
            noisy_product,
            useful_product,
        })
    }
}

pub fn deterministic_task() -> (MatrixBlocks, MatrixBlocks) {
    let a = std::array::from_fn(|i| std::array::from_fn(|j| ((i * 17 + j * 13) as u64 % Q) as u32));
    let b = std::array::from_fn(|i| std::array::from_fn(|j| ((i * 11 + j * 7) as u64 % Q) as u32));
    (a, b)
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut result, "{b:02x}").expect("String write");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multiplication_does_not_overflow_u64_accumulator() {
        let high = [(Q - 1) as u32; 64];
        assert_eq!(block_mul(&high, &high, &mut NoMeter), [8; 64]);
    }
    #[test]
    fn noncanonical_last_four_u32_values_and_q_are_rejected() {
        for bad in Q..=u64::from(u32::MAX) {
            let mut words = [0; 64];
            words[63] = bad as u32;
            assert_eq!(validate_block(&words), Err("FIELD"));
        }
    }
    #[test]
    fn sampler_stops_after_exactly_128_digest_draws() {
        let mut calls = 0;
        assert_eq!(
            sample_eight(|counter| {
                assert_eq!(counter, calls);
                calls += 1;
                [255; 32]
            }),
            Err("NOISE_BUDGET")
        );
        assert_eq!(calls, 128);
    }
    #[test]
    fn sampler_accepts_eight_valid_words_on_final_allowed_draw() {
        let mut calls = 0;
        let result = sample_eight(|counter| {
            calls += 1;
            if counter == 127 {
                [0; 32]
            } else {
                [255; 32]
            }
        })
        .unwrap();
        assert_eq!(calls, 128);
        assert_eq!(result, [0; 8]);
    }
    #[test]
    fn sampler_rejects_values_instead_of_modulo_mapping() {
        let mut calls = 0;
        let result = sample_eight(|_| {
            calls += 1;
            let values: [u32; 8] = if calls == 1 {
                [Q as u32, 1, u32::MAX, 2, 3, 4, 5, 6]
            } else {
                [7, 8, 9, 10, 11, 12, 13, 14]
            };
            let mut bytes = [0; 32];
            for (part, value) in bytes.chunks_exact_mut(4).zip(values) {
                part.copy_from_slice(&value.to_le_bytes());
            }
            bytes
        })
        .unwrap();
        assert_eq!(result, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(calls, 2);
    }
    #[test]
    fn oversized_and_truncated_frames_reject_before_hashes() {
        for size in [0, EXPECTED_BYTES - 1, EXPECTED_BYTES + 1, 1_000_000] {
            let mut counts = Counts::default();
            assert_eq!(
                verify_bytes(&vec![0; size], &[0; WITNESS_BYTES], &mut counts),
                Err("EXPECTED_LENGTH")
            );
            assert_eq!(counts, Counts::default());
        }
        for size in [0, WITNESS_BYTES - 1, WITNESS_BYTES + 1, 1_000_000] {
            let mut counts = Counts::default();
            assert_eq!(
                verify_bytes(&[0; EXPECTED_BYTES], &vec![0; size], &mut counts),
                Err("WITNESS_LENGTH")
            );
            assert_eq!(counts, Counts::default());
        }
    }
    #[test]
    fn target_comparison_is_big_endian_lexicographic_not_little_endian() {
        let mut left = [0; 32];
        let mut right = [0; 32];
        left[0] = 1;
        right[31] = 255;
        assert!(left > right);
    }
    #[test]
    fn typed_frame_roundtrip_and_cached_producer_equivalence() {
        let (a, b) = deterministic_task();
        let plain = PreparedTask::new(a, b, false, &mut NoMeter).unwrap();
        let cached = PreparedTask::new(a, b, true, &mut NoMeter).unwrap();
        let (root_a, root_b) = plain.roots();
        let ctx = Expected {
            chain: [b'C'; 32],
            parent: [b'P'; 32],
            header_without_work: [b'H'; 32],
            root_a,
            root_b,
            target: [255; 32],
        };
        assert_eq!(Expected::decode(&ctx.encode()).unwrap(), ctx);
        for nonce in [0, 9, u64::MAX] {
            let w = plain.produce(&ctx, nonce, &mut NoMeter).unwrap();
            assert_eq!(cached.produce(&ctx, nonce, &mut NoMeter).unwrap(), w);
            assert_eq!(Witness::decode(&w.encode()).unwrap(), w);
            assert!(verify(&ctx, &w, &mut NoMeter).is_ok());
        }
    }
}
