//! Flat, bounded preparation provenance. All evidence remains inert until an
//! explicitly versioned consumer joins its independent durable owner barriers.
use alloc::{boxed::Box, vec::Vec};
use core::fmt;
use sha2::{Digest, Sha256};
use trnm_consensus_crypto::{
    recover_epoch_activation_authority_strict_v0,
    recover_successor_epoch_activation_authority_strict_v1, EpochActivationRecoveryErrorV0,
    StrictSameVersionEpochActivationAuthorityV0, StrictSuccessorEpochActivationErrorV1,
};
use trnm_consensus_types::{
    decode_block_header_v0_exact, Cev0AdmissionBudgetV0, ConsensusParametersV0, DecodeError,
    EpochActivationEvidencePreimagesV0, ValidatorSet, MAX_CEV0_ROOT_BYTES_V0,
};

pub const EPOCH_PREPARATION_RECORD_SCHEMA_V2: u16 = 2;
pub const EPOCH_PREPARATION_RECORD_MAGIC_V2: &[u8; 8] = b"TRNMEP02";
pub const MAX_EPOCH_PREPARATION_ENTRIES_V2: usize = 32;
pub const MAX_EPOCH_PREPARATION_RECORD_BYTES_V2: usize = 64 * 1024 * 1024;
pub const MAX_EPOCH_PREPARATION_HEADERS_V2: usize = 256;
pub const MAX_EPOCH_PREPARATION_HEADER_BYTES_V2: usize = 4096;
pub const MAX_EPOCH_PREPARATION_INTERVAL_BYTES_V2: usize = 1024 * 1024;
const PREFIX_BYTES: usize = 8 + 2 + 1 + 32 + 32 + 4;
const DIGEST_DOMAIN: &[u8] = b"trnm.consensus-core.epoch-preparation-provenance.v2";

#[derive(Debug)]
pub enum EpochPreparationErrorV2 {
    Invalid(&'static str),
    LengthLimit,
    BindingMismatch,
    DigestMismatch,
    Root(EpochActivationRecoveryErrorV0),
    Successor(StrictSuccessorEpochActivationErrorV1),
    Header(DecodeError),
}
impl fmt::Display for EpochPreparationErrorV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "epoch preparation v2: {reason}"),
            Self::LengthLimit => f.write_str("epoch preparation v2 length bound"),
            Self::BindingMismatch => f.write_str("epoch preparation v2 binding mismatch"),
            Self::DigestMismatch => f.write_str("epoch preparation v2 digest mismatch"),
            Self::Root(error) => write!(f, "epoch preparation root: {error}"),
            Self::Successor(error) => write!(f, "epoch preparation successor: {error}"),
            Self::Header(error) => write!(f, "epoch preparation header: {error}"),
        }
    }
}
impl core::error::Error for EpochPreparationErrorV2 {}
type Result<T> = core::result::Result<T, EpochPreparationErrorV2>;

/// Borrowed untrusted input; neither decoded flags nor caller-selected roots
/// are verification authority. The first ancestry interval is empty.
#[derive(Debug, Clone, Copy)]
pub struct EpochPreparationEntryV2<'a> {
    pub binding_ref: [u8; 32],
    pub retained_ancestry: &'a [&'a [u8]],
    pub evidence: EpochActivationEvidencePreimagesV0<'a>,
}

/// Exact canonical persistence bytes. Cloning this inert record copies no live
/// owner and cannot reconstruct authority without independently pinned recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochPreparationRecordV2 {
    bytes: Vec<u8>,
    digest: [u8; 32],
    root_binding: [u8; 32],
    terminal_binding: [u8; 32],
    entry_count: usize,
}
impl EpochPreparationRecordV2 {
    pub const fn root_binding_v2(&self) -> [u8; 32] {
        self.root_binding
    }
    pub const fn terminal_binding_v2(&self) -> [u8; 32] {
        self.terminal_binding
    }
    pub const fn entry_count_v2(&self) -> usize {
        self.entry_count
    }
    pub const fn digest_v2(&self) -> [u8; 32] {
        self.digest
    }
    pub fn as_bytes_v2(&self) -> &[u8] {
        &self.bytes
    }
    pub fn encode_v2(&self) -> Result<Vec<u8>> {
        Ok(self.bytes.clone())
    }
}

/// Complete cryptographic preparation only: no step, timer, storage ACK,
/// signing or implicit conversion to the eight-root Core persistence profile.
/// ```compile_fail
/// use trnm_consensus_core::EpochPreparationV2;
/// fn copy(owner: EpochPreparationV2) { let _ = owner.clone(); }
/// ```
/// ```compile_fail
/// use trnm_consensus_core::EpochPreparationV2;
/// fn fabricate() { let _ = EpochPreparationV2 {}; }
/// ```
#[derive(Debug)]
#[must_use = "retain the complete provenance durably or discard this inert owner"]
pub struct EpochPreparationV2 {
    authority: Box<StrictSameVersionEpochActivationAuthorityV0>,
    record: EpochPreparationRecordV2,
    root_set: ValidatorSet,
    root_parameters: ConsensusParametersV0,
}
impl EpochPreparationV2 {
    pub fn authority_v2(&self) -> &StrictSameVersionEpochActivationAuthorityV0 {
        &self.authority
    }
    pub const fn record_v2(&self) -> &EpochPreparationRecordV2 {
        &self.record
    }
    /// Independently supplied root trust retained after the whole strict fold.
    pub const fn root_validator_set_v2(&self) -> &ValidatorSet {
        &self.root_set
    }
    pub const fn root_parameters_v2(&self) -> &ConsensusParametersV0 {
        &self.root_parameters
    }
}

pub fn prepare_epoch_handoff_evidence_v2(
    entries: &[EpochPreparationEntryV2<'_>],
    trusted_old_set: &ValidatorSet,
    trusted_old_parameters: &ConsensusParametersV0,
    root_binding: [u8; 32],
    terminal_binding: [u8; 32],
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<EpochPreparationV2> {
    let size = preflight(
        entries.iter().copied(),
        entries.len(),
        root_binding,
        terminal_binding,
        budget,
    )?;
    let authority = verify_entries(
        entries.iter().copied(),
        trusted_old_set,
        trusted_old_parameters,
        budget,
    )?;
    // Record retention begins only after every strict edge passes. In particular
    // a bad late edge never allocates a 64 MiB aggregate preparation record.
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(EPOCH_PREPARATION_RECORD_MAGIC_V2);
    bytes.extend_from_slice(&EPOCH_PREPARATION_RECORD_SCHEMA_V2.to_be_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&root_binding);
    bytes.extend_from_slice(&terminal_binding);
    put_u32(&mut bytes, entries.len());
    for entry in entries {
        bytes.extend_from_slice(&entry.binding_ref);
        put_u32(&mut bytes, entry.retained_ancestry.len());
        for header in entry.retained_ancestry {
            put_blob(&mut bytes, header);
        }
        for root in roots(entry.evidence) {
            put_blob(&mut bytes, root);
        }
    }
    debug_assert_eq!(bytes.len(), size);
    Ok(owned_preparation(
        authority,
        bytes,
        root_binding,
        terminal_binding,
        entries.len(),
        trusted_old_set,
        trusted_old_parameters,
    ))
}

/// Reopen with independently expected root, terminal and whole-record identity.
/// No public digest-free recovery overload exists. Framing/pin failures precede
/// signature work; charges for a later cryptographic failure are never refunded.
pub fn recover_epoch_preparation_v2(
    bytes: &[u8],
    trusted_old_set: &ValidatorSet,
    trusted_old_parameters: &ConsensusParametersV0,
    expected_root_binding: [u8; 32],
    expected_terminal_binding: [u8; 32],
    expected_record_digest: [u8; 32],
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<EpochPreparationV2> {
    if bytes.len() > MAX_EPOCH_PREPARATION_RECORD_BYTES_V2 {
        return Err(EpochPreparationErrorV2::LengthLimit);
    }
    let mut cursor = Cursor { bytes, offset: 0 };
    if cursor.take(8)? != EPOCH_PREPARATION_RECORD_MAGIC_V2
        || cursor.take(2)? != EPOCH_PREPARATION_RECORD_SCHEMA_V2.to_be_bytes()
        || cursor.take(1)? != [0]
    {
        return Err(EpochPreparationErrorV2::Invalid("magic/schema/phase"));
    }
    if cursor.array32()? != expected_root_binding || cursor.array32()? != expected_terminal_binding
    {
        return Err(EpochPreparationErrorV2::BindingMismatch);
    }
    let count = cursor.u32()?;
    check_count(count)?;
    // Only bounded slice descriptors are allocated during framing, never roots.
    let mut raw = Vec::with_capacity(count);
    for index in 0..count {
        let binding_ref = cursor.array32()?;
        let header_count = cursor.u32()?;
        check_header_count(index, header_count)?;
        let mut headers = Vec::with_capacity(header_count);
        for _ in 0..header_count {
            headers.push(cursor.blob(MAX_EPOCH_PREPARATION_HEADER_BYTES_V2)?);
        }
        let mut fields = [&[][..]; 8];
        for field in &mut fields {
            *field = cursor.blob(MAX_CEV0_ROOT_BYTES_V0)?;
        }
        raw.push(RawEntry {
            binding_ref,
            headers,
            evidence: preimages(fields),
        });
    }
    if cursor.offset != bytes.len() {
        return Err(EpochPreparationErrorV2::Invalid("trailing bytes"));
    }
    let size = preflight(
        raw.iter().map(RawEntry::borrowed),
        count,
        expected_root_binding,
        expected_terminal_binding,
        budget,
    )?;
    if size != bytes.len() {
        return Err(EpochPreparationErrorV2::Invalid("noncanonical framing"));
    }
    if record_digest(bytes) != expected_record_digest {
        return Err(EpochPreparationErrorV2::DigestMismatch);
    }
    let authority = verify_entries(
        raw.iter().map(RawEntry::borrowed),
        trusted_old_set,
        trusted_old_parameters,
        budget,
    )?;
    Ok(owned_preparation(
        authority,
        bytes.to_vec(),
        expected_root_binding,
        expected_terminal_binding,
        count,
        trusted_old_set,
        trusted_old_parameters,
    ))
}

fn check_count(count: usize) -> Result<()> {
    if !(1..=MAX_EPOCH_PREPARATION_ENTRIES_V2).contains(&count) {
        return Err(EpochPreparationErrorV2::Invalid("entry count"));
    }
    Ok(())
}
fn check_header_count(index: usize, count: usize) -> Result<()> {
    if (index == 0 && count != 0)
        || (index != 0 && !(2..=MAX_EPOCH_PREPARATION_HEADERS_V2).contains(&count))
    {
        return Err(EpochPreparationErrorV2::Invalid("ancestry count"));
    }
    Ok(())
}
fn add(total: &mut usize, amount: usize) -> Result<()> {
    *total = total
        .checked_add(amount)
        .ok_or(EpochPreparationErrorV2::LengthLimit)?;
    if *total > MAX_EPOCH_PREPARATION_RECORD_BYTES_V2 {
        return Err(EpochPreparationErrorV2::LengthLimit);
    }
    Ok(())
}
fn preflight<'a>(
    entries: impl Iterator<Item = EpochPreparationEntryV2<'a>>,
    count: usize,
    root_binding: [u8; 32],
    terminal_binding: [u8; 32],
    budget: &Cev0AdmissionBudgetV0,
) -> Result<usize> {
    check_count(count)?;
    if root_binding == [0; 32] || terminal_binding == [0; 32] {
        return Err(EpochPreparationErrorV2::BindingMismatch);
    }
    let mut total = PREFIX_BYTES;
    let mut seen = Vec::with_capacity(count);
    for (index, entry) in entries.enumerate() {
        if index >= count || entry.binding_ref == [0; 32] || seen.contains(&entry.binding_ref) {
            return Err(EpochPreparationErrorV2::Invalid(
                "entry count or duplicate/zero binding",
            ));
        }
        if (index == 0 && entry.binding_ref != root_binding)
            || (index + 1 == count && entry.binding_ref != terminal_binding)
        {
            return Err(EpochPreparationErrorV2::BindingMismatch);
        }
        seen.push(entry.binding_ref);
        check_header_count(index, entry.retained_ancestry.len())?;
        add(&mut total, 32 + 4)?;
        let mut interval = 0usize;
        for header in entry.retained_ancestry {
            if header.is_empty() || header.len() > MAX_EPOCH_PREPARATION_HEADER_BYTES_V2 {
                return Err(EpochPreparationErrorV2::LengthLimit);
            }
            interval = interval
                .checked_add(header.len())
                .ok_or(EpochPreparationErrorV2::LengthLimit)?;
            if interval > MAX_EPOCH_PREPARATION_INTERVAL_BYTES_V2 {
                return Err(EpochPreparationErrorV2::LengthLimit);
            }
            add(&mut total, 4)?;
            add(&mut total, header.len())?;
        }
        let mut root_size = 0usize;
        for root in roots(entry.evidence) {
            if root.is_empty() {
                return Err(EpochPreparationErrorV2::Invalid("empty evidence root"));
            }
            root_size = root_size
                .checked_add(root.len())
                .ok_or(EpochPreparationErrorV2::LengthLimit)?;
            if root_size > MAX_CEV0_ROOT_BYTES_V0 || root_size > budget.maximum_root_bytes() {
                return Err(EpochPreparationErrorV2::LengthLimit);
            }
            add(&mut total, 4)?;
            add(&mut total, root.len())?;
        }
    }
    if seen.len() != count {
        return Err(EpochPreparationErrorV2::Invalid("entry count"));
    }
    Ok(total)
}

// One strict fold shared by fresh preparation and recovery. Never reset, clone
// or refund the caller's budget between edges. Only one predecessor is retained.
#[inline(never)]
fn verify_entries<'a>(
    entries: impl Iterator<Item = EpochPreparationEntryV2<'a>>,
    root_set: &ValidatorSet,
    root_parameters: &ConsensusParametersV0,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<Box<StrictSameVersionEpochActivationAuthorityV0>> {
    let mut previous: Option<Box<StrictSameVersionEpochActivationAuthorityV0>> = None;
    for entry in entries {
        let outgoing_parameters = previous.as_ref().map_or(root_parameters, |predecessor| {
            predecessor.new_consensus_parameters()
        });
        let configured_limit =
            Cev0AdmissionBudgetV0::for_parameters(outgoing_parameters).maximum_root_bytes();
        // Configuration is independently trusted for the first edge and comes
        // from the already verified predecessor for later edges. This separate
        // byte screen never substitutes or resets the caller's work meter.
        let root_bytes = roots(entry.evidence)
            .iter()
            .try_fold(0usize, |total, root| {
                total
                    .checked_add(root.len())
                    .ok_or(EpochPreparationErrorV2::LengthLimit)
            })?;
        if root_bytes > configured_limit {
            return Err(EpochPreparationErrorV2::LengthLimit);
        }
        let mut headers = Vec::with_capacity(entry.retained_ancestry.len());
        for bytes in entry.retained_ancestry {
            headers.push(
                decode_block_header_v0_exact(bytes).map_err(EpochPreparationErrorV2::Header)?,
            );
        }
        let authority = if let Some(predecessor) = &previous {
            recover_successor_epoch_activation_authority_strict_v1(
                predecessor,
                &headers,
                entry.evidence,
                entry.binding_ref,
                budget,
            )
            .map_err(EpochPreparationErrorV2::Successor)?
        } else {
            recover_epoch_activation_authority_strict_v0(
                entry.evidence,
                root_set,
                root_parameters,
                entry.binding_ref,
                budget,
            )
            .map_err(EpochPreparationErrorV2::Root)?
        };
        previous = Some(Box::new(authority));
    }
    previous.ok_or(EpochPreparationErrorV2::Invalid("empty strict fold"))
}

fn record_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DIGEST_DOMAIN);
    hash.update([0]);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}
fn owned_preparation(
    authority: Box<StrictSameVersionEpochActivationAuthorityV0>,
    bytes: Vec<u8>,
    root_binding: [u8; 32],
    terminal_binding: [u8; 32],
    entry_count: usize,
    root_set: &ValidatorSet,
    root_parameters: &ConsensusParametersV0,
) -> EpochPreparationV2 {
    let digest = record_digest(&bytes);
    EpochPreparationV2 {
        authority,
        root_set: root_set.clone(),
        root_parameters: *root_parameters,
        record: EpochPreparationRecordV2 {
            bytes,
            digest,
            root_binding,
            terminal_binding,
            entry_count,
        },
    }
}
struct RawEntry<'a> {
    binding_ref: [u8; 32],
    headers: Vec<&'a [u8]>,
    evidence: EpochActivationEvidencePreimagesV0<'a>,
}
impl RawEntry<'_> {
    fn borrowed(&self) -> EpochPreparationEntryV2<'_> {
        EpochPreparationEntryV2 {
            binding_ref: self.binding_ref,
            retained_ancestry: &self.headers,
            evidence: self.evidence,
        }
    }
}
fn roots(fields: EpochActivationEvidencePreimagesV0<'_>) -> [&[u8]; 8] {
    [
        fields.old_checkpoint_finality,
        fields.next_epoch_commitment,
        fields.authorization_kernel,
        fields.old_validator_set,
        fields.old_consensus_parameters,
        fields.new_validator_set,
        fields.new_consensus_parameters,
        fields.authenticated_checkpoint_parent_header,
    ]
}
fn preimages(fields: [&[u8]; 8]) -> EpochActivationEvidencePreimagesV0<'_> {
    EpochActivationEvidencePreimagesV0 {
        old_checkpoint_finality: fields[0],
        next_epoch_commitment: fields[1],
        authorization_kernel: fields[2],
        old_validator_set: fields[3],
        old_consensus_parameters: fields[4],
        new_validator_set: fields[5],
        new_consensus_parameters: fields[6],
        authenticated_checkpoint_parent_header: fields[7],
    }
}
fn put_u32(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend_from_slice(&(value as u32).to_be_bytes());
}
fn put_blob(bytes: &mut Vec<u8>, value: &[u8]) {
    put_u32(bytes, value.len());
    bytes.extend_from_slice(value);
}
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(size)
            .ok_or(EpochPreparationErrorV2::LengthLimit)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(EpochPreparationErrorV2::Invalid("truncated record"))?;
        self.offset = end;
        Ok(value)
    }
    fn u32(&mut self) -> Result<usize> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("four bytes")) as usize)
    }
    fn array32(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }
    fn blob(&mut self, limit: usize) -> Result<&'a [u8]> {
        let size = self.u32()?;
        if size == 0 || size > limit {
            return Err(EpochPreparationErrorV2::LengthLimit);
        }
        self.take(size)
    }
}
