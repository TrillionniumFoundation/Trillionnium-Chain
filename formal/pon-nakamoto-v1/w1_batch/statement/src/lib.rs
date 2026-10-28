#![no_std]
#![forbid(unsafe_code)]
//! Public byte bindings for a NEW research-only batch statement.
//!
//! This crate does NOT prove W1. Each included journal must separately be
//! authenticated by a receipt for FROZEN_LEAF_IMAGE_ID. The guest unconditionally
//! calls env::verify for every leaf; host verification requires an unconditional
//! successful receipt for the exact compiled batch image. Nothing here grants
//! node admission, validates parent/task-window/M06/authorization, or adds weight.

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

pub const FROZEN_LEAF_IMAGE_ID: [u32; 8] = [
    4203990569, 1706128024, 889896351, 2751765305, 3434005897, 1411617246, 870515685, 3215144349,
];
pub const LEAF_DOMAIN: &[u8] = b"TRNM-W1-ZK-JOURNAL1\0";
pub const INPUT_DOMAIN: &[u8] = b"TRNM-W1-BATCH-INPUT1\0";
pub const BATCH_DOMAIN: &[u8] = b"TRNM-W1-BATCH-JOURNAL1\0";
pub const HEADER_BYTES: usize = 318;
pub const LEAF_JOURNAL_BYTES: usize = 16818;
pub const LEAF_ENTRY_BYTES: usize = HEADER_BYTES + LEAF_JOURNAL_BYTES;
pub const MAX_LEAVES: usize = 64;
pub const INPUT_PREFIX_BYTES: usize = INPUT_DOMAIN.len() + 4;
pub const BATCH_PREFIX_BYTES: usize = BATCH_DOMAIN.len() + 32 + 4;
pub const MAX_INPUT_BYTES: usize = INPUT_PREFIX_BYTES + MAX_LEAVES * LEAF_ENTRY_BYTES;
pub const MAX_BATCH_JOURNAL_BYTES: usize = BATCH_PREFIX_BYTES + MAX_LEAVES * LEAF_JOURNAL_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Count,
    Length,
    Domain,
    LeafImage,
    Header,
    Target,
    Ticket,
    WorkIdentity,
    ProductRange,
    DuplicateWork,
}

#[derive(Clone, Copy)]
pub struct Leaf<'a> {
    pub header: &'a [u8],
    pub journal: &'a [u8],
}

fn count(value: u32) -> Result<usize, Error> {
    let value = value as usize;
    if (1..=MAX_LEAVES).contains(&value) {
        Ok(value)
    } else {
        Err(Error::Count)
    }
}

/// Parse a fixed-size prefix before allocating space for entries.
pub fn input_count(prefix: &[u8]) -> Result<usize, Error> {
    if prefix.len() != INPUT_PREFIX_BYTES {
        return Err(Error::Length);
    }
    if !prefix.starts_with(INPUT_DOMAIN) {
        return Err(Error::Domain);
    }
    count(u32::from_le_bytes(
        prefix[INPUT_DOMAIN.len()..].try_into().unwrap(),
    ))
}

fn pon_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"TRNM-PON1\0");
    hash.update((tag.len() as u16).to_le_bytes());
    hash.update(tag);
    for part in parts {
        hash.update((part.len() as u32).to_le_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

/// Independently derive the original identity from the proven header and trace.
/// Caller-provided work IDs, proof randomness and batch position have no role.
/// These public checks alone are NOT proof verification or a W1 fallback.
pub fn leaf_identity(header: &[u8], journal: &[u8]) -> Result<[u8; 32], Error> {
    if header.len() != HEADER_BYTES || &header[..4] != b"PNH1" || header[4..6] != 1u16.to_le_bytes()
    {
        return Err(Error::Header);
    }
    if journal.len() != LEAF_JOURNAL_BYTES {
        return Err(Error::Length);
    }
    if !journal.starts_with(LEAF_DOMAIN) {
        return Err(Error::Domain);
    }
    let fields = LEAF_DOMAIN.len() + HEADER_BYTES;
    if &journal[LEAF_DOMAIN.len()..fields] != header {
        return Err(Error::Header);
    }
    let trace: [u8; 32] = journal[fields..fields + 32].try_into().unwrap();
    let ticket: [u8; 32] = journal[fields + 32..fields + 64].try_into().unwrap();
    let carried_identity: [u8; 32] = journal[fields + 64..fields + 96].try_into().unwrap();
    let target: [u8; 32] = header[118..150].try_into().unwrap();
    if target == [0; 32] || ticket > target {
        return Err(Error::Target);
    }
    let challenge = pon_hash(b"challenge", &[header]);
    if ticket != pon_hash(b"ticket", &[&challenge, &trace]) {
        return Err(Error::Ticket);
    }
    let identity = pon_hash(b"block", &[header, &trace]);
    if carried_identity != identity {
        return Err(Error::WorkIdentity);
    }
    for word in journal[fields + 96..].chunks_exact(4) {
        if u32::from_le_bytes(word.try_into().unwrap()) >= 4294967291 {
            return Err(Error::ProductRange);
        }
    }
    Ok(identity)
}

fn append_unique(ids: &mut Vec<[u8; 32]>, identity: [u8; 32]) -> Result<(), Error> {
    // At most 64 IDs: bounded linear comparison also works inside the guest.
    if ids.contains(&identity) {
        return Err(Error::DuplicateWork);
    }
    ids.push(identity);
    Ok(())
}

pub struct Builder {
    expected: usize,
    ids: Vec<[u8; 32]>,
    journal: Vec<u8>,
}

impl Builder {
    pub fn new(expected: usize) -> Result<Self, Error> {
        if !(1..=MAX_LEAVES).contains(&expected) {
            return Err(Error::Count);
        }
        let mut journal = Vec::with_capacity(BATCH_PREFIX_BYTES + expected * LEAF_JOURNAL_BYTES);
        journal.extend_from_slice(BATCH_DOMAIN);
        for word in FROZEN_LEAF_IMAGE_ID {
            journal.extend_from_slice(&word.to_le_bytes());
        }
        journal.extend_from_slice(&(expected as u32).to_le_bytes());
        Ok(Self {
            expected,
            ids: Vec::with_capacity(expected),
            journal,
        })
    }

    /// A caller must authenticate this exact journal against the frozen image.
    pub fn push(&mut self, leaf: Leaf<'_>) -> Result<(), Error> {
        if self.ids.len() >= self.expected {
            return Err(Error::Count);
        }
        append_unique(&mut self.ids, leaf_identity(leaf.header, leaf.journal)?)?;
        // Keep ALL 16,818 bytes, including the complete product. No prefixes,
        // ranges, noise checks, transcript pieces or cell words are omitted.
        self.journal.extend_from_slice(leaf.journal);
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<u8>, Error> {
        if self.ids.len() != self.expected {
            return Err(Error::Count);
        }
        Ok(self.journal)
    }
}

pub fn build_journal(leaves: &[Leaf<'_>]) -> Result<Vec<u8>, Error> {
    let mut builder = Builder::new(leaves.len())?;
    for leaf in leaves {
        builder.push(*leaf)?;
    }
    builder.finish()
}

pub fn encode_input(leaves: &[Leaf<'_>]) -> Result<Vec<u8>, Error> {
    // Validate the public bindings and uniqueness before encoding.
    build_journal(leaves)?;
    let mut input = Vec::with_capacity(INPUT_PREFIX_BYTES + leaves.len() * LEAF_ENTRY_BYTES);
    input.extend_from_slice(INPUT_DOMAIN);
    input.extend_from_slice(&(leaves.len() as u32).to_le_bytes());
    for leaf in leaves {
        input.extend_from_slice(leaf.header);
        input.extend_from_slice(leaf.journal);
    }
    Ok(input)
}

/// Exact-length decoder used for controls. The guest uses the same prefix and
/// entry format with bounded reads and an explicit EOF check.
pub fn decode_input(input: &[u8]) -> Result<Vec<Leaf<'_>>, Error> {
    if input.len() < INPUT_PREFIX_BYTES || input.len() > MAX_INPUT_BYTES {
        return Err(Error::Length);
    }
    let expected = input_count(&input[..INPUT_PREFIX_BYTES])?;
    if input.len() != INPUT_PREFIX_BYTES + expected * LEAF_ENTRY_BYTES {
        return Err(Error::Length);
    }
    let leaves: Vec<_> = input[INPUT_PREFIX_BYTES..]
        .chunks_exact(LEAF_ENTRY_BYTES)
        .map(|entry| Leaf {
            header: &entry[..HEADER_BYTES],
            journal: &entry[HEADER_BYTES..],
        })
        .collect();
    build_journal(&leaves)?;
    Ok(leaves)
}

/// Call ONLY after verifying an unconditional receipt for the exact batch image.
/// The expected ordered headers come from the caller's requested statement.
pub fn check_batch_journal(
    expected_headers: &[&[u8]],
    journal: &[u8],
) -> Result<Vec<[u8; 32]>, Error> {
    if journal.len() < BATCH_PREFIX_BYTES || journal.len() > MAX_BATCH_JOURNAL_BYTES {
        return Err(Error::Length);
    }
    if !journal.starts_with(BATCH_DOMAIN) {
        return Err(Error::Domain);
    }
    let image = &journal[BATCH_DOMAIN.len()..BATCH_DOMAIN.len() + 32];
    for (bytes, word) in image.chunks_exact(4).zip(FROZEN_LEAF_IMAGE_ID) {
        if bytes != word.to_le_bytes() {
            return Err(Error::LeafImage);
        }
    }
    let expected = count(u32::from_le_bytes(
        journal[BATCH_PREFIX_BYTES - 4..BATCH_PREFIX_BYTES]
            .try_into()
            .unwrap(),
    ))?;
    if expected != expected_headers.len()
        || journal.len() != BATCH_PREFIX_BYTES + expected * LEAF_JOURNAL_BYTES
    {
        return Err(Error::Length);
    }
    let mut ids = Vec::with_capacity(expected);
    for (header, leaf) in expected_headers
        .iter()
        .zip(journal[BATCH_PREFIX_BYTES..].chunks_exact(LEAF_JOURNAL_BYTES))
    {
        append_unique(&mut ids, leaf_identity(header, leaf)?)?;
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    const HEADER: &[u8] = include_bytes!(
        "../../../../../evidence/pon-w1-complete-succinct-20261028/full-proof/header.bin"
    );
    const JOURNAL: &[u8] = include_bytes!(
        "../../../../../evidence/pon-w1-complete-succinct-20261028/full-proof/expected-journal.bin"
    );

    fn leaf() -> Leaf<'static> {
        Leaf {
            header: HEADER,
            journal: JOURNAL,
        }
    }

    #[test]
    fn frozen_leaf_roundtrip_retains_every_public_byte() {
        let leaves = [leaf()];
        let input = encode_input(&leaves).unwrap();
        assert_eq!(decode_input(&input).unwrap()[0].journal, JOURNAL);
        let batch = build_journal(&leaves).unwrap();
        assert_eq!(&batch[BATCH_PREFIX_BYTES..], JOURNAL);
        assert_eq!(
            check_batch_journal(&[HEADER], &batch).unwrap(),
            [leaf_identity(HEADER, JOURNAL).unwrap()]
        );
    }

    #[test]
    fn repeated_valid_work_is_not_multiple_work() {
        assert_eq!(build_journal(&[leaf(), leaf()]), Err(Error::DuplicateWork));
        let mut changed_product = JOURNAL.to_vec();
        changed_product[LEAF_JOURNAL_BYTES - 1] ^= 1;
        // Even a different public product (without any proof) cannot turn the
        // same original header/trace identity into an additional ticket.
        assert_eq!(
            build_journal(&[
                leaf(),
                Leaf {
                    header: HEADER,
                    journal: &changed_product
                }
            ]),
            Err(Error::DuplicateWork)
        );
    }

    #[test]
    fn exact_counts_bounds_domains_and_no_omitted_leaf() {
        assert!(Builder::new(0).is_err());
        assert!(Builder::new(MAX_LEAVES + 1).is_err());
        assert_eq!(Builder::new(1).unwrap().finish(), Err(Error::Count));
        let input = encode_input(&[leaf()]).unwrap();
        for length in [0, INPUT_PREFIX_BYTES - 1, input.len() - 1] {
            assert!(decode_input(&input[..length]).is_err());
        }
        let mut extra = input.clone();
        extra.push(0);
        assert!(decode_input(&extra).is_err());
        for value in [0u32, 2, u32::MAX] {
            let mut bad = input.clone();
            bad[INPUT_DOMAIN.len()..INPUT_PREFIX_BYTES].copy_from_slice(&value.to_le_bytes());
            assert!(decode_input(&bad).is_err());
        }
        let mut bad = input;
        bad[0] ^= 1;
        assert!(decode_input(&bad).is_err());
    }

    #[test]
    fn header_trace_ticket_identity_and_product_range_are_bound() {
        let fields = LEAF_DOMAIN.len() + HEADER_BYTES;
        for offset in [0, LEAF_DOMAIN.len(), fields, fields + 32, fields + 64] {
            let mut bad = JOURNAL.to_vec();
            bad[offset] ^= 1;
            assert!(leaf_identity(HEADER, &bad).is_err());
        }
        let mut bad = JOURNAL.to_vec();
        bad[fields + 96..fields + 100].copy_from_slice(&4294967291u32.to_le_bytes());
        assert_eq!(leaf_identity(HEADER, &bad), Err(Error::ProductRange));
        let mut wrong_header = HEADER.to_vec();
        wrong_header[310] ^= 1;
        assert_eq!(leaf_identity(&wrong_header, JOURNAL), Err(Error::Header));
    }

    #[test]
    fn batch_domain_leaf_image_and_count_are_bound() {
        let original = build_journal(&[leaf()]).unwrap();
        for offset in [0, BATCH_DOMAIN.len(), BATCH_PREFIX_BYTES - 4] {
            let mut bad = original.clone();
            bad[offset] ^= 1;
            assert!(check_batch_journal(&[HEADER], &bad).is_err());
        }
        assert!(check_batch_journal(&[], &original).is_err());
        let mut bad = original;
        bad.push(0);
        assert!(check_batch_journal(&[HEADER], &bad).is_err());
    }
}
