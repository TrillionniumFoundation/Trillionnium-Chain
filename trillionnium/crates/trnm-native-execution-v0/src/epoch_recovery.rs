//! Local retained handoff evidence. Decoding bytes never creates the public
//! application edge; the live owner must still reconstruct checkpoint state.
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    Cev0AdmissionBudgetV0, ConsensusParametersV0, EpochActivationEvidencePreimagesV0, ValidatorSet,
};

pub(crate) const MAX_EPOCH_EVIDENCE_BYTES_V1: usize = 64 * 1024 * 1024;
const DOMAIN: &[u8] = b"TRNMEVD1";

#[derive(Debug)]
pub(crate) struct EpochRecoveryEvidenceV1 {
    pub(crate) checkpoint_artifact: Vec<u8>,
    pub(crate) cutoff_finality: Vec<u8>,
    pub(crate) cutoff_parent: Vec<u8>,
    pub(crate) checkpoint_parent: Vec<u8>,
    pub(crate) checkpoint_header: Vec<u8>,
    pub(crate) checkpoint_finality: Vec<u8>,
    pub(crate) anchor: Vec<u8>,
    pub(crate) preparation_id: [u8; 32],
    pub(crate) old_set: Vec<u8>,
    pub(crate) old_parameters: Vec<u8>,
    pub(crate) new_set: Vec<u8>,
    pub(crate) new_parameters: Vec<u8>,
    pub(crate) next_commitment: Vec<u8>,
}

impl EpochRecoveryEvidenceV1 {
    pub(crate) fn proof_preimages(&self) -> EpochActivationEvidencePreimagesV0<'_> {
        EpochActivationEvidencePreimagesV0 {
            old_checkpoint_finality: &self.checkpoint_finality,
            next_epoch_commitment: &self.next_commitment,
            authorization_kernel: &self.anchor,
            old_validator_set: &self.old_set,
            old_consensus_parameters: &self.old_parameters,
            new_validator_set: &self.new_set,
            new_consensus_parameters: &self.new_parameters,
            authenticated_checkpoint_parent_header: &self.checkpoint_parent,
        }
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let parts = [
            &self.checkpoint_artifact,
            &self.cutoff_finality,
            &self.cutoff_parent,
            &self.checkpoint_parent,
            &self.checkpoint_header,
            &self.checkpoint_finality,
            &self.anchor,
            &self.old_set,
            &self.old_parameters,
            &self.new_set,
            &self.new_parameters,
            &self.next_commitment,
        ];
        let size = parts
            .iter()
            .try_fold(DOMAIN.len() + 2 + 32 + 32, |n, p| {
                n.checked_add(4)?.checked_add(p.len())
            })
            .context("epoch evidence length overflow")?;
        ensure!(
            size <= MAX_EPOCH_EVIDENCE_BYTES_V1,
            "epoch evidence exceeds local budget"
        );
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        for part in parts {
            bytes.extend_from_slice(&u32::try_from(part.len())?.to_be_bytes());
            bytes.extend_from_slice(part);
        }
        bytes.extend_from_slice(&self.preparation_id);
        let checksum = Sha256::digest(&bytes);
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_EPOCH_EVIDENCE_BYTES_V1 && bytes.len() >= DOMAIN.len() + 2 + 64,
            "epoch evidence size invalid"
        );
        let (body, checksum) = bytes.split_at(bytes.len() - 32);
        ensure!(
            Sha256::digest(body).as_slice() == checksum,
            "epoch evidence checksum mismatch"
        );
        let mut reader = EvidenceReader {
            bytes: body,
            offset: 0,
        };
        ensure!(
            reader.take(DOMAIN.len())? == DOMAIN && reader.take(2)? == 1u16.to_be_bytes(),
            "epoch evidence domain/version mismatch"
        );
        let result = Self {
            checkpoint_artifact: reader.part()?,
            cutoff_finality: reader.part()?,
            cutoff_parent: reader.part()?,
            checkpoint_parent: reader.part()?,
            checkpoint_header: reader.part()?,
            checkpoint_finality: reader.part()?,
            anchor: reader.part()?,
            old_set: reader.part()?,
            old_parameters: reader.part()?,
            new_set: reader.part()?,
            new_parameters: reader.part()?,
            next_commitment: reader.part()?,
            preparation_id: reader.take(32)?.try_into()?,
        };
        ensure!(reader.offset == body.len(), "epoch evidence trailing bytes");
        ensure!(result.encode()? == bytes, "noncanonical epoch evidence");
        Ok(result)
    }

    /// Lower storage audit only: this authenticates consensus geometry and
    /// configurations. It is not the full native cutoff/preparation receipt.
    pub(crate) fn audit_strict(
        &self,
        trusted_old_set: &ValidatorSet,
        trusted_old_parameters: &ConsensusParametersV0,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<AuditedEpochEvidenceV1> {
        let decoded = trnm_consensus_types::decode_epoch_activation_evidence_v0_exact(
            self.proof_preimages(),
            trusted_old_set,
            trusted_old_parameters,
            budget,
        )
        .map_err(|e| anyhow::anyhow!("epoch evidence exact decode: {e:?}"))?;
        let activation =
            trnm_consensus_crypto::verify_same_version_epoch_activation_authority_strict_v0(
                decoded.old_checkpoint_finality(),
                decoded.next_epoch_commitment(),
                decoded.authorization_kernel(),
                decoded.old_validator_set(),
                decoded.old_consensus_parameters(),
                decoded.new_validator_set(),
                decoded.new_consensus_parameters(),
                decoded.authenticated_checkpoint_parent_header(),
            )
            .map_err(|e| anyhow::anyhow!("epoch evidence strict verification: {e:?}"))?;
        let checkpoint = decoded.old_checkpoint_finality().finalized_block().header();
        ensure!(
            checkpoint
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("checkpoint encoding: {e:?}"))?
                == self.checkpoint_header,
            "epoch evidence checkpoint splice"
        );
        let executed = trnm_native_application::decode_native_executed_block_artifact_v0(
            &self.checkpoint_artifact,
        )?;
        let request = executed.request();
        ensure!(
            request.block_id().as_bytes() == checkpoint.id().as_bytes()
                && request.height().get() == checkpoint.height().get()
                && request.parent().block_id().as_bytes() == checkpoint.parent_id().as_bytes()
                && request.timestamp_ms() == checkpoint.timestamp_ms()
                && request.expected().post_state_root().as_bytes()
                    == checkpoint.state_root().as_bytes()
                && request.expected().payload_root().as_bytes()
                    == checkpoint.payload_root().as_bytes()
                && request.expected().receipts_root().as_bytes()
                    == checkpoint.receipts_root().as_bytes()
                && request.expected().evidence_root().as_bytes()
                    == checkpoint.evidence_root().as_bytes(),
            "epoch retained artifact differs from strict checkpoint"
        );
        Ok(AuditedEpochEvidenceV1 { activation })
    }
}

pub(crate) struct AuditedEpochEvidenceV1 {
    pub(crate) activation: trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0,
}
impl AuditedEpochEvidenceV1 {
    pub(crate) fn coordinates(
        &self,
        binding: [u8; 32],
    ) -> Result<crate::epoch_edge::EpochApplicationCoordinatesV1> {
        let checkpoint = self
            .activation
            .old_checkpoint_finality()
            .finalized_block()
            .header();
        let terminal = self.activation.authorization_kernel().terminal_old_header();
        let value = crate::epoch_edge::EpochApplicationCoordinatesV1 {
            checkpoint_version: checkpoint.height().get(),
            checkpoint_root: *checkpoint.state_root().as_bytes(),
            terminal_version: terminal.height().get(),
            first_version: terminal
                .height()
                .get()
                .checked_add(1)
                .context("epoch height overflow")?,
            authorization_id: binding,
        };
        value.validate()?;
        Ok(value)
    }
}

struct EvidenceReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> EvidenceReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(n)
            .context("evidence offset overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .context("truncated epoch evidence")?;
        self.offset = end;
        Ok(value)
    }
    fn part(&mut self) -> Result<Vec<u8>> {
        let len = u32::from_be_bytes(self.take(4)?.try_into()?) as usize;
        Ok(self.take(len)?.to_vec())
    }
}
