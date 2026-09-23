//! Canonical comparison data for the independent epoch node lineage.
//! Decoding or constructing a record grants no Core ACK, custody lease or key access.
use crate::ExternalNodeCheckpointV0;
use sha2::{Digest, Sha256};
use trnm_consensus_types::{ChainId, ValidatorId};

type Hash32 = [u8; 32];
pub const EPOCH_NODE_CHECKPOINT_MAX_BYTES_V1: usize = 8192;
const MAGIC: &[u8; 8] = b"TRNMNC01";
const CHECKSUM_DOMAIN: &[u8] = b"trnm.node.epoch-lineage-checkpoint.v1";
const ORIGIN_DOMAIN: &[u8] = b"trnm.node.epoch-lineage-origin.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochNodeCheckpointErrorV1 {
    Length,
    Magic,
    Version,
    Tag,
    Checksum,
    Invalid(&'static str),
    Successor,
}
impl std::fmt::Display for EpochNodeCheckpointErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "epoch node checkpoint: {self:?}")
    }
}
impl std::error::Error for EpochNodeCheckpointErrorV1 {}
type Result<T> = std::result::Result<T, EpochNodeCheckpointErrorV1>;
fn invalid<T>(why: &'static str) -> Result<T> {
    Err(EpochNodeCheckpointErrorV1::Invalid(why))
}
fn nonzero(hash: Hash32) -> Result<()> {
    if hash == [0; 32] {
        invalid("zero hash")
    } else {
        Ok(())
    }
}
pub(crate) fn epoch_origin_checksum_v1(bytes: &[u8]) -> Hash32 {
    hash(ORIGIN_DOMAIN, bytes)
}
fn hash(domain: &[u8], bytes: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(b"trnm.domain.hash.v1");
    h.update((domain.len() as u64).to_be_bytes());
    h.update(domain);
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    h.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EpochCheckpointPhaseV1 {
    ActivationCommitted = 0,
    Ordinary = 1,
    EpochRetired = 2,
    /// Outgoing native13 receipt; deliberately no activation successor yet.
    EpochRetiredNative13 = 3,
    /// Strict native attachment only; deliberately no activation successor.
    EpochHandoffAttachedNative13 = 4,
    /// Explicit native13 / physical Journal12 successor activation.
    SuccessorActivationNative13Journal12 = 5,
}
impl EpochCheckpointPhaseV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        match r.byte()? {
            0 => Ok(Self::ActivationCommitted),
            1 => Ok(Self::Ordinary),
            2 => Ok(Self::EpochRetired),
            3 => Ok(Self::EpochRetiredNative13),
            4 => Ok(Self::EpochHandoffAttachedNative13),
            5 => Ok(Self::SuccessorActivationNative13Journal12),
            _ => Err(EpochNodeCheckpointErrorV1::Tag),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EpochCheckpointRoleV1 {
    Continuing = 0,
    VirginNew = 1,
    Removed = 2,
}
impl EpochCheckpointRoleV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        match r.byte()? {
            0 => Ok(Self::Continuing),
            1 => Ok(Self::VirginNew),
            2 => Ok(Self::Removed),
            _ => Err(EpochNodeCheckpointErrorV1::Tag),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EpochCheckpointPredecessorV1 {
    TerminalV0 = 0,
    V1 = 1,
    VirginCommission = 2,
}
impl EpochCheckpointPredecessorV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        match r.byte()? {
            0 => Ok(Self::TerminalV0),
            1 => Ok(Self::V1),
            2 => Ok(Self::VirginCommission),
            _ => Err(EpochNodeCheckpointErrorV1::Tag),
        }
    }
}

/// Inert comparison fields; actual owner validation is a separate operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSafetyCutV1 {
    pub journal_id: Hash32,
    pub context_ref: Hash32,
    pub revision: u64,
    pub record_checksum: Hash32,
    pub chain_checksum: Hash32,
}
impl EpochSafetyCutV1 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.journal_id);
        out.extend_from_slice(&self.context_ref);
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.extend_from_slice(&self.record_checksum);
        out.extend_from_slice(&self.chain_checksum);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            journal_id: r.array()?,
            context_ref: r.array()?,
            revision: u64::from_be_bytes(r.array()?),
            record_checksum: r.array()?,
            chain_checksum: r.array()?,
        })
    }
    fn validate_hashes(&self) -> Result<()> {
        nonzero(self.journal_id)?;
        nonzero(self.context_ref)?;
        nonzero(self.record_checksum)?;
        nonzero(self.chain_checksum)?;
        Ok(())
    }
}

/// Inert comparison fields; actual owner validation is a separate operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochApplicationEdgeCutV1 {
    pub checkpoint_block_id: Hash32,
    pub checkpoint_height: u64,
    pub checkpoint_state_root: Hash32,
    pub terminal_old_block_id: Hash32,
    pub terminal_old_height: u64,
    pub terminal_old_view: u64,
    pub terminal_old_qc_id: Hash32,
    pub native_authorization_id: Hash32,
}
impl EpochApplicationEdgeCutV1 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.checkpoint_block_id);
        out.extend_from_slice(&self.checkpoint_height.to_be_bytes());
        out.extend_from_slice(&self.checkpoint_state_root);
        out.extend_from_slice(&self.terminal_old_block_id);
        out.extend_from_slice(&self.terminal_old_height.to_be_bytes());
        out.extend_from_slice(&self.terminal_old_view.to_be_bytes());
        out.extend_from_slice(&self.terminal_old_qc_id);
        out.extend_from_slice(&self.native_authorization_id);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            checkpoint_block_id: r.array()?,
            checkpoint_height: u64::from_be_bytes(r.array()?),
            checkpoint_state_root: r.array()?,
            terminal_old_block_id: r.array()?,
            terminal_old_height: u64::from_be_bytes(r.array()?),
            terminal_old_view: u64::from_be_bytes(r.array()?),
            terminal_old_qc_id: r.array()?,
            native_authorization_id: r.array()?,
        })
    }
    fn validate_hashes(&self) -> Result<()> {
        nonzero(self.checkpoint_block_id)?;
        nonzero(self.checkpoint_state_root)?;
        nonzero(self.terminal_old_block_id)?;
        nonzero(self.terminal_old_qc_id)?;
        nonzero(self.native_authorization_id)?;
        Ok(())
    }
}

/// Inert comparison fields; actual owner validation is a separate operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochApplicationCutV1 {
    pub block_id: Hash32,
    pub height: u64,
    pub epoch: u64,
    pub view: u64,
    pub timestamp_ms: u64,
    pub state_root: Hash32,
    pub native_store_id: Hash32,
    pub native_commit_id: Hash32,
    pub p_sequence: u64,
    pub p_digest: Hash32,
    pub artifact_digest: Hash32,
    pub overlay_digest: Hash32,
    pub commit_sequence: u64,
}
impl EpochApplicationCutV1 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.block_id);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.view.to_be_bytes());
        out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.native_store_id);
        out.extend_from_slice(&self.native_commit_id);
        out.extend_from_slice(&self.p_sequence.to_be_bytes());
        out.extend_from_slice(&self.p_digest);
        out.extend_from_slice(&self.artifact_digest);
        out.extend_from_slice(&self.overlay_digest);
        out.extend_from_slice(&self.commit_sequence.to_be_bytes());
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            block_id: r.array()?,
            height: u64::from_be_bytes(r.array()?),
            epoch: u64::from_be_bytes(r.array()?),
            view: u64::from_be_bytes(r.array()?),
            timestamp_ms: u64::from_be_bytes(r.array()?),
            state_root: r.array()?,
            native_store_id: r.array()?,
            native_commit_id: r.array()?,
            p_sequence: u64::from_be_bytes(r.array()?),
            p_digest: r.array()?,
            artifact_digest: r.array()?,
            overlay_digest: r.array()?,
            commit_sequence: u64::from_be_bytes(r.array()?),
        })
    }
    fn validate_hashes(&self) -> Result<()> {
        nonzero(self.block_id)?;
        nonzero(self.state_root)?;
        nonzero(self.native_store_id)?;
        nonzero(self.native_commit_id)?;
        nonzero(self.p_digest)?;
        nonzero(self.artifact_digest)?;
        nonzero(self.overlay_digest)?;
        Ok(())
    }
}

/// Inert comparison fields; actual owner validation is a separate operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochRetiredCustodyCutV1 {
    pub epoch: u64,
    pub author: ValidatorId,
    pub validator_set_id: Hash32,
    pub parameters_hash: Hash32,
    pub scope: Hash32,
    pub journal_id: Hash32,
    pub profile_checksum: Hash32,
    pub source_sequence: u64,
    pub source_chain_checksum: Hash32,
    pub terminal_sequence: u64,
    pub terminal_chain_checksum: Hash32,
    pub retirement_record_checksum: Hash32,
}
impl EpochRetiredCustodyCutV1 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.epoch.to_be_bytes());
        put_bytes(out, self.author.as_bytes());
        out.extend_from_slice(&self.validator_set_id);
        out.extend_from_slice(&self.parameters_hash);
        out.extend_from_slice(&self.scope);
        out.extend_from_slice(&self.journal_id);
        out.extend_from_slice(&self.profile_checksum);
        out.extend_from_slice(&self.source_sequence.to_be_bytes());
        out.extend_from_slice(&self.source_chain_checksum);
        out.extend_from_slice(&self.terminal_sequence.to_be_bytes());
        out.extend_from_slice(&self.terminal_chain_checksum);
        out.extend_from_slice(&self.retirement_record_checksum);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            epoch: u64::from_be_bytes(r.array()?),
            author: ValidatorId::from_bytes(r.identity()?)
                .map_err(|_| EpochNodeCheckpointErrorV1::Invalid("author"))?,
            validator_set_id: r.array()?,
            parameters_hash: r.array()?,
            scope: r.array()?,
            journal_id: r.array()?,
            profile_checksum: r.array()?,
            source_sequence: u64::from_be_bytes(r.array()?),
            source_chain_checksum: r.array()?,
            terminal_sequence: u64::from_be_bytes(r.array()?),
            terminal_chain_checksum: r.array()?,
            retirement_record_checksum: r.array()?,
        })
    }
    fn validate_hashes(&self) -> Result<()> {
        nonzero(self.validator_set_id)?;
        nonzero(self.parameters_hash)?;
        nonzero(self.scope)?;
        nonzero(self.journal_id)?;
        nonzero(self.profile_checksum)?;
        nonzero(self.source_chain_checksum)?;
        nonzero(self.terminal_chain_checksum)?;
        nonzero(self.retirement_record_checksum)?;
        Ok(())
    }
}

/// Inert comparison fields; actual owner validation is a separate operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochOrdinaryCustodyCutV1 {
    pub scope: Hash32,
    pub journal_id: Hash32,
    pub profile_checksum: Hash32,
    pub sequence: u64,
    pub chain_checksum: Hash32,
}
impl EpochOrdinaryCustodyCutV1 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.scope);
        out.extend_from_slice(&self.journal_id);
        out.extend_from_slice(&self.profile_checksum);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.chain_checksum);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            scope: r.array()?,
            journal_id: r.array()?,
            profile_checksum: r.array()?,
            sequence: u64::from_be_bytes(r.array()?),
            chain_checksum: r.array()?,
        })
    }
    fn validate_hashes(&self) -> Result<()> {
        nonzero(self.scope)?;
        nonzero(self.journal_id)?;
        nonzero(self.profile_checksum)?;
        nonzero(self.chain_checksum)?;
        Ok(())
    }
}

/// Inert comparison fields; actual owner validation is a separate operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochNodeCheckpointFieldsV1 {
    pub phase: EpochCheckpointPhaseV1,
    pub role: EpochCheckpointRoleV1,
    pub predecessor_kind: EpochCheckpointPredecessorV1,
    pub lineage_id: Hash32,
    pub origin_checksum: Hash32,
    pub generation: u64,
    pub predecessor_checksum: Hash32,
    pub genesis_hash: Hash32,
    pub chain_id: ChainId,
    pub protocol_version: u32,
    pub epoch: u64,
    pub author: ValidatorId,
    pub validator_set_id: Hash32,
    pub parameters_hash: Hash32,
    pub owner_generation: u64,
    pub phase_authority_binding: Hash32,
    pub source_safety: Option<EpochSafetyCutV1>,
    pub target_safety: EpochSafetyCutV1,
    pub edge: EpochApplicationEdgeCutV1,
    pub application: EpochApplicationCutV1,
    pub retired: Option<EpochRetiredCustodyCutV1>,
    pub ordinary: Option<EpochOrdinaryCustodyCutV1>,
}
impl EpochNodeCheckpointFieldsV1 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.phase as u8);
        out.push(self.role as u8);
        out.push(self.predecessor_kind as u8);
        out.extend_from_slice(&self.lineage_id);
        out.extend_from_slice(&self.origin_checksum);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.predecessor_checksum);
        out.extend_from_slice(&self.genesis_hash);
        put_bytes(out, self.chain_id.as_bytes());
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        put_bytes(out, self.author.as_bytes());
        out.extend_from_slice(&self.validator_set_id);
        out.extend_from_slice(&self.parameters_hash);
        out.extend_from_slice(&self.owner_generation.to_be_bytes());
        out.extend_from_slice(&self.phase_authority_binding);
        match &self.source_safety {
            None => out.push(0),
            Some(v) => {
                out.push(1);
                v.encode(out);
            }
        }
        self.target_safety.encode(out);
        self.edge.encode(out);
        self.application.encode(out);
        match &self.retired {
            None => out.push(0),
            Some(v) => {
                out.push(1);
                v.encode(out);
            }
        }
        match &self.ordinary {
            None => out.push(0),
            Some(v) => {
                out.push(1);
                v.encode(out);
            }
        }
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            phase: EpochCheckpointPhaseV1::decode(r)?,
            role: EpochCheckpointRoleV1::decode(r)?,
            predecessor_kind: EpochCheckpointPredecessorV1::decode(r)?,
            lineage_id: r.array()?,
            origin_checksum: r.array()?,
            generation: u64::from_be_bytes(r.array()?),
            predecessor_checksum: r.array()?,
            genesis_hash: r.array()?,
            chain_id: ChainId::from_bytes(r.identity()?)
                .map_err(|_| EpochNodeCheckpointErrorV1::Invalid("chain_id"))?,
            protocol_version: u32::from_be_bytes(r.array()?),
            epoch: u64::from_be_bytes(r.array()?),
            author: ValidatorId::from_bytes(r.identity()?)
                .map_err(|_| EpochNodeCheckpointErrorV1::Invalid("author"))?,
            validator_set_id: r.array()?,
            parameters_hash: r.array()?,
            owner_generation: u64::from_be_bytes(r.array()?),
            phase_authority_binding: r.array()?,
            source_safety: match r.byte()? {
                0 => None,
                1 => Some(EpochSafetyCutV1::decode(r)?),
                _ => return Err(EpochNodeCheckpointErrorV1::Tag),
            },
            target_safety: EpochSafetyCutV1::decode(r)?,
            edge: EpochApplicationEdgeCutV1::decode(r)?,
            application: EpochApplicationCutV1::decode(r)?,
            retired: match r.byte()? {
                0 => None,
                1 => Some(EpochRetiredCustodyCutV1::decode(r)?),
                _ => return Err(EpochNodeCheckpointErrorV1::Tag),
            },
            ordinary: match r.byte()? {
                0 => None,
                1 => Some(EpochOrdinaryCustodyCutV1::decode(r)?),
                _ => return Err(EpochNodeCheckpointErrorV1::Tag),
            },
        })
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(EpochNodeCheckpointErrorV1::Length)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(EpochNodeCheckpointErrorV1::Length)?;
        self.offset = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| EpochNodeCheckpointErrorV1::Length)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    fn identity(&mut self) -> Result<&'a [u8]> {
        let n = u16::from_be_bytes(self.array()?) as usize;
        if !(1..=128).contains(&n) {
            return Err(EpochNodeCheckpointErrorV1::Length);
        }
        self.take(n)
    }
}

/// Checksummed, comparison-only local node record. This is not an activation receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochNodeCheckpointV1 {
    fields: EpochNodeCheckpointFieldsV1,
    checksum: Hash32,
}
impl EpochNodeCheckpointV1 {
    pub fn new(fields: EpochNodeCheckpointFieldsV1) -> Result<Self> {
        validate(&fields)?;
        let prefix = encode_prefix(&fields);
        if prefix.len() + 32 > EPOCH_NODE_CHECKPOINT_MAX_BYTES_V1 {
            return Err(EpochNodeCheckpointErrorV1::Length);
        }
        Ok(Self {
            fields,
            checksum: hash(CHECKSUM_DOMAIN, &prefix),
        })
    }
    pub const fn fields(&self) -> &EpochNodeCheckpointFieldsV1 {
        &self.fields
    }
    pub const fn checksum(&self) -> Hash32 {
        self.checksum
    }
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut out = encode_prefix(&self.fields);
        out.extend_from_slice(&self.checksum);
        out
    }
    pub fn decode_canonical_exact(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > EPOCH_NODE_CHECKPOINT_MAX_BYTES_V1 || bytes.len() < 42 {
            return Err(EpochNodeCheckpointErrorV1::Length);
        }
        let mut r = Reader { bytes, offset: 0 };
        if r.take(8)? != MAGIC {
            return Err(EpochNodeCheckpointErrorV1::Magic);
        }
        if u16::from_be_bytes(r.array()?) != 1 {
            return Err(EpochNodeCheckpointErrorV1::Version);
        }
        let fields = EpochNodeCheckpointFieldsV1::decode(&mut r)?;
        let checksum = r.array()?;
        if r.offset != bytes.len() {
            return Err(EpochNodeCheckpointErrorV1::Length);
        }
        let value = Self::new(fields)?;
        if value.checksum != checksum {
            return Err(EpochNodeCheckpointErrorV1::Checksum);
        }
        Ok(value)
    }

    /// Compare the exact original V0 cut. Actual native/Safety/custody joins are
    /// still mandatory before a private store may migrate or a driver may ACK.
    pub fn validate_first_continuing_v0(&self, old: &ExternalNodeCheckpointV0) -> Result<()> {
        let f = &self.fields;
        let p = old.fields();
        let source = EpochSafetyCutV1 {
            journal_id: p.safety_journal_id,
            context_ref: p.safety_verifier_profile_ref,
            revision: p.safety_revision,
            record_checksum: p.safety_state_record_checksum,
            chain_checksum: p.safety_record_chain_checksum,
        };
        let retired = f.retired.ok_or(EpochNodeCheckpointErrorV1::Successor)?;
        if f.phase != EpochCheckpointPhaseV1::ActivationCommitted
            || f.role != EpochCheckpointRoleV1::Continuing
            || f.predecessor_kind != EpochCheckpointPredecessorV1::TerminalV0
            || f.lineage_id != p.scope
            || f.origin_checksum != epoch_origin_checksum_v1(&old.encode_canonical())
            || Some(f.generation) != p.generation.checked_add(1)
            || f.predecessor_checksum != old.checkpoint_checksum()
            || f.source_safety != Some(source)
            || Some(f.target_safety.revision) != source.revision.checked_add(1)
            || f.application.block_id != p.application_block_id.into_bytes()
            || f.application.height != p.application_height
            || f.application.state_root != p.application_state_root.into_bytes()
            || f.application.view != p.application_view
            || f.application.timestamp_ms != p.application_timestamp_ms
            || retired.scope != p.scope
            || retired.journal_id != p.signer_journal_id
            || retired.profile_checksum != p.signer_profile_checksum
            || retired.terminal_sequence != p.signer_exact_watermark.sequence()
            || retired.terminal_chain_checksum != p.signer_exact_watermark.chain_checksum()
        {
            return Err(EpochNodeCheckpointErrorV1::Successor);
        }
        Ok(())
    }

    /// Closed scalar succession checks; no owner freshness or signature authority.
    pub fn validate_successor_of(&self, old: &Self) -> Result<()> {
        let f = &self.fields;
        let p = &old.fields;
        let fail = || Err(EpochNodeCheckpointErrorV1::Successor);
        if f.lineage_id != p.lineage_id
            || f.origin_checksum != p.origin_checksum
            || f.predecessor_kind != EpochCheckpointPredecessorV1::V1
            || Some(f.generation) != p.generation.checked_add(1)
            || f.predecessor_checksum != old.checksum
            || f.genesis_hash != p.genesis_hash
            || f.chain_id != p.chain_id
            || f.protocol_version != p.protocol_version
            || f.author != p.author
            || (!matches!(
                f.phase,
                EpochCheckpointPhaseV1::ActivationCommitted
                    | EpochCheckpointPhaseV1::SuccessorActivationNative13Journal12
            ) && f.owner_generation != p.owner_generation)
        {
            return fail();
        }
        match (p.phase, f.phase) {
            (
                EpochCheckpointPhaseV1::ActivationCommitted
                | EpochCheckpointPhaseV1::Ordinary
                | EpochCheckpointPhaseV1::SuccessorActivationNative13Journal12,
                EpochCheckpointPhaseV1::Ordinary,
            ) => {
                let a = f.ordinary.ok_or(EpochNodeCheckpointErrorV1::Successor)?;
                let b = p.ordinary.ok_or(EpochNodeCheckpointErrorV1::Successor)?;
                if f.epoch != p.epoch
                    || f.role != p.role
                    || f.validator_set_id != p.validator_set_id
                    || f.parameters_hash != p.parameters_hash
                    || f.phase_authority_binding != p.phase_authority_binding
                    || f.edge != p.edge
                    || f.retired != p.retired
                    || f.source_safety != p.source_safety
                    || a.scope != b.scope
                    || a.journal_id != b.journal_id
                    || a.profile_checksum != b.profile_checksum
                    || a.sequence < b.sequence
                    || (a.sequence == b.sequence && a.chain_checksum != b.chain_checksum)
                    || !safety_advances(&p.target_safety, &f.target_safety)
                    || !application_advances(&p.application, &f.application)
                {
                    return fail();
                }
            }
            (
                EpochCheckpointPhaseV1::ActivationCommitted | EpochCheckpointPhaseV1::Ordinary,
                EpochCheckpointPhaseV1::EpochRetired,
            ) => {
                let b = p.ordinary.ok_or(EpochNodeCheckpointErrorV1::Successor)?;
                let retired = f.retired.ok_or(EpochNodeCheckpointErrorV1::Successor)?;
                if f.epoch != p.epoch
                    || f.validator_set_id != p.validator_set_id
                    || f.parameters_hash != p.parameters_hash
                    || f.source_safety != Some(p.target_safety)
                    || !safety_advances(&p.target_safety, &f.target_safety)
                    || !application_advances(&p.application, &f.application)
                    || retired.scope != b.scope
                    || retired.journal_id != b.journal_id
                    || retired.profile_checksum != b.profile_checksum
                    || retired.source_sequence < b.sequence
                    || (retired.source_sequence == b.sequence
                        && retired.source_chain_checksum != b.chain_checksum)
                {
                    return fail();
                }
            }
            (EpochCheckpointPhaseV1::Ordinary, EpochCheckpointPhaseV1::EpochRetiredNative13) => {
                let b = p.ordinary.ok_or(EpochNodeCheckpointErrorV1::Successor)?;
                let retired = f.retired.ok_or(EpochNodeCheckpointErrorV1::Successor)?;
                if f.epoch != p.epoch
                    || f.validator_set_id != p.validator_set_id
                    || f.parameters_hash != p.parameters_hash
                    || f.source_safety != Some(p.target_safety)
                    || f.target_safety != p.target_safety
                    || f.application != p.application
                    || retired.scope != b.scope
                    || retired.journal_id != b.journal_id
                    || retired.profile_checksum != b.profile_checksum
                    || retired.source_sequence != b.sequence
                    || retired.source_chain_checksum != b.chain_checksum
                {
                    return fail();
                }
            }
            (
                EpochCheckpointPhaseV1::EpochRetiredNative13,
                EpochCheckpointPhaseV1::EpochHandoffAttachedNative13,
            ) => {
                let mut prior_edge = p.edge;
                prior_edge.native_authorization_id = f.edge.native_authorization_id;
                if f.epoch != p.epoch
                    || f.role != p.role
                    || f.validator_set_id != p.validator_set_id
                    || f.parameters_hash != p.parameters_hash
                    || f.source_safety != p.source_safety
                    || f.target_safety != p.target_safety
                    || f.application != p.application
                    || f.retired != p.retired
                    || f.ordinary != p.ordinary
                    || f.edge != prior_edge
                {
                    return fail();
                }
            }
            (
                EpochCheckpointPhaseV1::EpochHandoffAttachedNative13,
                EpochCheckpointPhaseV1::SuccessorActivationNative13Journal12,
            ) => {
                let a = f.ordinary.ok_or(EpochNodeCheckpointErrorV1::Successor)?;
                let retired = p.retired.ok_or(EpochNodeCheckpointErrorV1::Successor)?;
                if Some(f.owner_generation) != p.owner_generation.checked_add(1)
                    || p.role != EpochCheckpointRoleV1::Continuing
                    || f.role != EpochCheckpointRoleV1::Continuing
                    || Some(f.epoch) != p.epoch.checked_add(1)
                    || f.source_safety != Some(p.target_safety)
                    || Some(f.target_safety.revision) != p.target_safety.revision.checked_add(1)
                    || f.target_safety.journal_id == p.target_safety.journal_id
                    || f.application != p.application
                    || f.retired != p.retired
                    || f.edge != p.edge
                    || a.sequence != 0
                    || a.scope == retired.scope
                    || a.journal_id == retired.journal_id
                {
                    return fail();
                }
            }
            (EpochCheckpointPhaseV1::EpochRetired, EpochCheckpointPhaseV1::ActivationCommitted) => {
                let a = f.ordinary.ok_or(EpochNodeCheckpointErrorV1::Successor)?;
                let retired = p.retired.ok_or(EpochNodeCheckpointErrorV1::Successor)?;
                if Some(f.owner_generation) != p.owner_generation.checked_add(1)
                    || p.role != EpochCheckpointRoleV1::Continuing
                    || f.role != EpochCheckpointRoleV1::Continuing
                    || Some(f.epoch) != p.epoch.checked_add(1)
                    || f.source_safety != Some(p.target_safety)
                    || Some(f.target_safety.revision) != p.target_safety.revision.checked_add(1)
                    || f.application != p.application
                    || f.retired != p.retired
                    || f.edge.checkpoint_block_id != p.edge.checkpoint_block_id
                    || f.edge.checkpoint_height != p.edge.checkpoint_height
                    || f.edge.checkpoint_state_root != p.edge.checkpoint_state_root
                    || f.edge.terminal_old_block_id != p.edge.terminal_old_block_id
                    || f.edge.terminal_old_height != p.edge.terminal_old_height
                    || f.edge.terminal_old_view != p.edge.terminal_old_view
                    || f.edge.terminal_old_qc_id != p.edge.terminal_old_qc_id
                    || a.scope == retired.scope
                    || a.journal_id == retired.journal_id
                {
                    return fail();
                }
            }
            _ => return fail(),
        }
        Ok(())
    }
}
fn encode_prefix(fields: &EpochNodeCheckpointFieldsV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(2048);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&1u16.to_be_bytes());
    fields.encode(&mut out);
    out
}
fn safety_advances(old: &EpochSafetyCutV1, new: &EpochSafetyCutV1) -> bool {
    old.journal_id == new.journal_id
        && old.context_ref == new.context_ref
        && new.revision >= old.revision
        && (new.revision != old.revision || old == new)
}
fn application_advances(old: &EpochApplicationCutV1, new: &EpochApplicationCutV1) -> bool {
    old.native_store_id == new.native_store_id
        && new.height >= old.height
        && new.epoch >= old.epoch
        && (new.height == old.height
            || (new.commit_sequence > old.commit_sequence && new.p_sequence > old.p_sequence))
        && (new.epoch != old.epoch || new.view >= old.view)
        && new.timestamp_ms >= old.timestamp_ms
        && (new.height != old.height || old == new)
}
fn validate(f: &EpochNodeCheckpointFieldsV1) -> Result<()> {
    for h in [
        f.lineage_id,
        f.origin_checksum,
        f.predecessor_checksum,
        f.genesis_hash,
        f.validator_set_id,
        f.parameters_hash,
        f.phase_authority_binding,
    ] {
        nonzero(h)?;
    }
    f.target_safety.validate_hashes()?;
    f.edge.validate_hashes()?;
    f.application.validate_hashes()?;
    if f.generation == 0
        || f.owner_generation == 0
        || f.author.is_zero()
        || f.author.as_bytes().len() > 128
        || f.chain_id.as_bytes().len() > 128
    {
        return invalid("generation or author");
    }
    if let Some(s) = &f.source_safety {
        s.validate_hashes()?;
    }
    if let Some(o) = &f.ordinary {
        o.validate_hashes()?;
    }
    if let Some(r) = &f.retired {
        r.validate_hashes()?;
        if r.author.is_zero()
            || r.author.as_bytes().len() > 128
            || Some(r.terminal_sequence) != r.source_sequence.checked_add(1)
        {
            return invalid("retirement sequence or author");
        }
    }
    if Some(f.edge.terminal_old_height) != f.edge.checkpoint_height.checked_add(2)
        || f.edge.checkpoint_height == 0
        || f.edge.terminal_old_view == 0
        || f.application.p_sequence == 0
        || f.application.commit_sequence == 0
        || f.application.height < f.edge.checkpoint_height
        || f.application.epoch > f.epoch
    {
        return invalid("application edge");
    }
    if f.phase == EpochCheckpointPhaseV1::SuccessorActivationNative13Journal12
        && (f.role != EpochCheckpointRoleV1::Continuing
            || f.predecessor_kind != EpochCheckpointPredecessorV1::V1)
    {
        return invalid("native13 Journal12 activation role");
    }
    match (f.predecessor_kind, f.phase, f.role) {
        (
            EpochCheckpointPredecessorV1::TerminalV0,
            EpochCheckpointPhaseV1::ActivationCommitted,
            EpochCheckpointRoleV1::Continuing,
        )
        | (
            EpochCheckpointPredecessorV1::VirginCommission,
            EpochCheckpointPhaseV1::ActivationCommitted,
            EpochCheckpointRoleV1::VirginNew,
        )
        | (EpochCheckpointPredecessorV1::V1, _, _) => {}
        _ => return invalid("predecessor phase role"),
    }
    match f.phase {
        EpochCheckpointPhaseV1::ActivationCommitted
        | EpochCheckpointPhaseV1::Ordinary
        | EpochCheckpointPhaseV1::SuccessorActivationNative13Journal12 => {
            let ordinary = f.ordinary.ok_or(EpochNodeCheckpointErrorV1::Invalid(
                "missing ordinary custody",
            ))?;
            match f.role {
                EpochCheckpointRoleV1::Continuing => {
                    let retired = f.retired.ok_or(EpochNodeCheckpointErrorV1::Invalid(
                        "missing retired custody",
                    ))?;
                    let source = f
                        .source_safety
                        .ok_or(EpochNodeCheckpointErrorV1::Invalid("missing source Safety"))?;
                    if Some(f.epoch) != retired.epoch.checked_add(1)
                        || retired.author != f.author
                        || source.journal_id == f.target_safety.journal_id
                        || ordinary.scope == retired.scope
                        || ordinary.journal_id == retired.journal_id
                    {
                        return invalid("incoming epoch identity");
                    }
                }
                EpochCheckpointRoleV1::VirginNew
                    if f.source_safety.is_none() && f.retired.is_none() => {}
                _ => return invalid("phase role"),
            }
            if matches!(
                f.phase,
                EpochCheckpointPhaseV1::ActivationCommitted
                    | EpochCheckpointPhaseV1::SuccessorActivationNative13Journal12
            ) {
                if ordinary.sequence != 0
                    || f.application.height != f.edge.checkpoint_height
                    || f.application.block_id != f.edge.checkpoint_block_id
                    || f.application.state_root != f.edge.checkpoint_state_root
                    || Some(f.epoch) != f.application.epoch.checked_add(1)
                {
                    return invalid("activation cut");
                }
            } else if f.application.height == f.edge.checkpoint_height {
                if f.application.block_id != f.edge.checkpoint_block_id
                    || f.application.state_root != f.edge.checkpoint_state_root
                    || Some(f.epoch) != f.application.epoch.checked_add(1)
                {
                    return invalid("ordinary checkpoint C");
                }
            } else if f.application.height != f.edge.checkpoint_height
                && (f.application.height <= f.edge.terminal_old_height
                    || f.application.epoch != f.epoch)
            {
                return invalid("ordinary application includes virtual seals");
            }
        }
        EpochCheckpointPhaseV1::EpochRetired
        | EpochCheckpointPhaseV1::EpochRetiredNative13
        | EpochCheckpointPhaseV1::EpochHandoffAttachedNative13 => {
            let retired = f.retired.ok_or(EpochNodeCheckpointErrorV1::Invalid(
                "missing current retirement",
            ))?;
            if f.role == EpochCheckpointRoleV1::VirginNew
                || f.source_safety.is_none()
                || f.ordinary.is_some()
                || retired.epoch != f.epoch
                || retired.author != f.author
                || retired.validator_set_id != f.validator_set_id
                || retired.parameters_hash != f.parameters_hash
                || f.application.epoch != f.epoch
                || f.application.height != f.edge.checkpoint_height
                || f.application.block_id != f.edge.checkpoint_block_id
                || f.application.state_root != f.edge.checkpoint_state_root
            {
                return invalid("retired phase cut");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "epoch_node_checkpoint_v1_tests.rs"]
pub(crate) mod tests;
