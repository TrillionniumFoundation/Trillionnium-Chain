//! Recovery-specific payload observations without weakening the original read API.

use super::*;
use crate::cell::retention::{CellRetentionPayloadFaultStageV2, CellRetentionPayloadObservationV2};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CellRs46ProviderPayloadFaultStageV2 {
    Seek,
    Read,
    ChunkDigest,
    PayloadDigest,
}

/// A rejected, bounded payload read from one previously pinned provider duty.
/// This is not an authenticated accusation against a remote operator.
#[derive(Debug)]
pub struct CellRs46ProviderPayloadFaultV2 {
    operation: CellDigestV1,
    provider_store: CellDigestV1,
    stage: CellRs46ProviderPayloadFaultStageV2,
    expected_bytes: u64,
    read_bytes_lower_bound: u64,
    read_bytes_upper_bound: u64,
    original: CellErrorV1,
}

impl CellRs46ProviderPayloadFaultV2 {
    pub fn operation(&self) -> CellDigestV1 {
        self.operation
    }
    pub fn provider_store(&self) -> CellDigestV1 {
        self.provider_store
    }
    pub fn stage(&self) -> CellRs46ProviderPayloadFaultStageV2 {
        self.stage
    }
    pub fn expected_bytes(&self) -> u64 {
        self.expected_bytes
    }
    pub fn read_bytes_bounds(&self) -> (u64, u64) {
        (self.read_bytes_lower_bound, self.read_bytes_upper_bound)
    }
    pub fn original_error(&self) -> &CellErrorV1 {
        &self.original
    }
}

#[derive(Debug)]
pub enum CellRs46ProviderReadObservationV2 {
    Verified(CellRs46StoredShardV1),
    Rejected(CellRs46ProviderPayloadFaultV2),
}

impl CellRs46ShardProviderV1 {
    /// Observe an independently pinned CSP1 duty. Only physical payload seek,
    /// read, chunk-hash or full-payload-hash failure is returned as Rejected.
    /// The caller may then count this provider as an erasure, retaining the
    /// observation and the original complete-attempt budget. No retry is free.
    ///
    /// Metadata/descriptor/owner/scope/allocation errors, cancellation and the
    /// original absolute deadline remain fatal outer errors. All identity and
    /// control fences run before a rejected observation can escape. The legacy
    /// read method and its fail-fast behavior remain unchanged.
    pub fn read_observed_v2(
        &mut self,
        contract: &CellRs46ShardContractV1,
        expected_operation: CellDigestV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellRs46ProviderReadObservationV2> {
        controlled(deadline, checkpoint)?;
        self.check_contract(contract, expected_operation)?;
        require(
            self.descriptor(contract.binding(), expected_operation, deadline)? == *contract,
            "RS46 observed provider independent descriptor pin",
        )?;
        self.check_reserved_contract(contract)?;
        controlled(deadline, checkpoint)?;
        let observation = self.arena.observe_payload_controlled_v2(
            expected_operation,
            contract.manifest().size(),
            deadline,
            checkpoint,
        )?;
        controlled(deadline, checkpoint)?;
        self.check_reserved_contract(contract)?;
        require(
            self.descriptor(contract.binding(), expected_operation, deadline)? == *contract,
            "RS46 provider descriptor changed",
        )?;
        controlled(deadline, checkpoint)?;
        match observation {
            CellRetentionPayloadObservationV2::Verified(bytes) => {
                // A malformed committed CSP1/CRS1 relation is a contract error,
                // not a provider-local erasure, even if a payload hash matches.
                let shard = contract.verify_wire(&bytes)?;
                controlled(deadline, checkpoint)?;
                Ok(CellRs46ProviderReadObservationV2::Verified(
                    CellRs46StoredShardV1 {
                        operation: expected_operation,
                        provider_store: self.arena.store_id(),
                        codeword: contract.owner().codeword,
                        placement: contract.owner().placement,
                        shard,
                    },
                ))
            }
            CellRetentionPayloadObservationV2::Rejected(fault) => {
                let stage = match fault.stage {
                    CellRetentionPayloadFaultStageV2::Seek => {
                        CellRs46ProviderPayloadFaultStageV2::Seek
                    }
                    CellRetentionPayloadFaultStageV2::Read => {
                        CellRs46ProviderPayloadFaultStageV2::Read
                    }
                    CellRetentionPayloadFaultStageV2::ChunkDigest => {
                        CellRs46ProviderPayloadFaultStageV2::ChunkDigest
                    }
                    CellRetentionPayloadFaultStageV2::PayloadDigest => {
                        CellRs46ProviderPayloadFaultStageV2::PayloadDigest
                    }
                };
                Ok(CellRs46ProviderReadObservationV2::Rejected(
                    CellRs46ProviderPayloadFaultV2 {
                        operation: expected_operation,
                        provider_store: self.arena.store_id(),
                        stage,
                        expected_bytes: fault.expected_bytes,
                        read_bytes_lower_bound: fault.read_bytes_lower_bound,
                        read_bytes_upper_bound: fault.read_bytes_upper_bound,
                        original: fault.original,
                    },
                ))
            }
        }
    }
}
