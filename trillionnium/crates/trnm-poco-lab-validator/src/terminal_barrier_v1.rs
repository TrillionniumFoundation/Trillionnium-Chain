//! Direct-seven, process-local controlled-campaign termination. Transport
//! owners are the only remote admission entry; these bytes are not proofs.
use crate::{
    consensus_mesh::{MeshInboundFrameV0, PeerDirectionV0, PeerSessionFactsV0},
    frame::FrameKind,
};
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use trnm_consensus_types::ValidatorId;

const MAGIC: &[u8; 8] = b"TRNMTB01";
const PREFIX: usize = 8 + 1 + 32 + 32;
const PREPARE_BYTES: usize = PREFIX + 8 + 5 * 32;
const PARK_BYTES: usize = PREFIX + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalCommonCutV1 {
    pub height: u64,
    pub block: [u8; 32],
    pub state: [u8; 32],
    pub chain: [u8; 32],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalPrepareV1 {
    pub common: TerminalCommonCutV1,
    pub checkpoint: [u8; 32],
    pub local_cut: [u8; 32],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyV1 {
    Prepare(TerminalPrepareV1),
    Park([u8; 32]),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MessageV1 {
    start: [u8; 32],
    origin: ValidatorId,
    body: BodyV1,
}
impl MessageV1 {
    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PREPARE_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.push(match self.body {
            BodyV1::Prepare(_) => 1,
            BodyV1::Park(_) => 2,
        });
        bytes.extend_from_slice(&self.start);
        bytes.extend_from_slice(self.origin.as_bytes());
        match self.body {
            BodyV1::Prepare(p) => {
                bytes.extend_from_slice(&p.common.height.to_le_bytes());
                for digest in [
                    p.common.block,
                    p.common.state,
                    p.common.chain,
                    p.checkpoint,
                    p.local_cut,
                ] {
                    bytes.extend_from_slice(&digest);
                }
            }
            BodyV1::Park(set) => bytes.extend_from_slice(&set),
        }
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            matches!(bytes.len(), PREPARE_BYTES | PARK_BYTES),
            "terminal payload length"
        );
        ensure!(&bytes[..8] == MAGIC, "terminal payload domain");
        let digest = |offset: usize| -> [u8; 32] {
            bytes[offset..offset + 32]
                .try_into()
                .expect("fixed terminal length")
        };
        let start = digest(9);
        let origin = ValidatorId::new(digest(41));
        ensure!(
            start != [0; 32] && origin.as_bytes() != [0; 32],
            "zero terminal context"
        );
        let body = match bytes[8] {
            1 if bytes.len() == PREPARE_BYTES => {
                let height =
                    u64::from_le_bytes(bytes[PREFIX..PREFIX + 8].try_into().expect("fixed height"));
                let p = TerminalPrepareV1 {
                    common: TerminalCommonCutV1 {
                        height,
                        block: digest(PREFIX + 8),
                        state: digest(PREFIX + 40),
                        chain: digest(PREFIX + 72),
                    },
                    checkpoint: digest(PREFIX + 104),
                    local_cut: digest(PREFIX + 136),
                };
                ensure!(
                    height > 0
                        && [
                            p.common.block,
                            p.common.state,
                            p.common.chain,
                            p.checkpoint,
                            p.local_cut
                        ]
                        .iter()
                        .all(|h| *h != [0; 32]),
                    "zero terminal Prepare cut"
                );
                BodyV1::Prepare(p)
            }
            2 if bytes.len() == PARK_BYTES => {
                let set = digest(PREFIX);
                ensure!(set != [0; 32], "zero terminal Park set");
                BodyV1::Park(set)
            }
            _ => anyhow::bail!("terminal phase/length mismatch"),
        };
        Ok(Self {
            start,
            origin,
            body,
        })
    }
}

/// At most seven immutable payloads per phase and twelve current sessions.
/// No detached signature or caller-selected remote identity can enter this map.
pub(crate) struct TerminalBarrierV1 {
    start: [u8; 32],
    local: ValidatorId,
    members: BTreeSet<ValidatorId>,
    prepares: BTreeMap<ValidatorId, TerminalPrepareV1>,
    parks: BTreeMap<ValidatorId, [u8; 32]>,
    sessions: BTreeMap<(PeerDirectionV0, ValidatorId), (u64, [u8; 32])>,
    unavailable: BTreeSet<(PeerDirectionV0, ValidatorId)>,
}
impl TerminalBarrierV1 {
    pub fn new(
        start: [u8; 32],
        local: ValidatorId,
        members: BTreeSet<ValidatorId>,
        sessions: &[PeerSessionFactsV0],
    ) -> Result<Self> {
        ensure!(
            start != [0; 32] && members.len() == 7 && members.contains(&local),
            "terminal barrier requires exact direct seven"
        );
        let mut this = Self {
            start,
            local,
            members,
            prepares: BTreeMap::new(),
            parks: BTreeMap::new(),
            sessions: BTreeMap::new(),
            unavailable: BTreeSet::new(),
        };
        for session in sessions {
            this.observe_session(*session)?;
        }
        ensure!(
            this.sessions.len() == 12,
            "terminal barrier requires both directions for six peers"
        );
        Ok(this)
    }
    pub fn observe_session(&mut self, session: PeerSessionFactsV0) -> Result<()> {
        let remote = session.remote();
        ensure!(
            remote != self.local
                && self.members.contains(&remote)
                && session.generation() > 0
                && session.session_id() != [0; 32],
            "invalid terminal session owner"
        );
        let key = (session.direction(), remote);
        let current = (session.generation(), session.session_id());
        if let Some(prior) = self.sessions.get(&key) {
            if *prior == current {
                return Ok(());
            }
            // Delayed lifecycle observations cannot replace a current owner.
            if current.0 < prior.0 {
                return Ok(());
            }
            ensure!(
                !self.local_prepared()
                    && !self.prepares.contains_key(&remote)
                    && !self.parks.contains_key(&remote),
                "terminal session changed after Prepare"
            );
            ensure!(current.0 > prior.0, "terminal session generation reused");
        }
        self.sessions.insert(key, current);
        Ok(())
    }
    pub fn local_prepared(&self) -> bool {
        self.prepares.contains_key(&self.local)
    }
    pub fn local_prepare(&self) -> Option<TerminalPrepareV1> {
        self.prepares.get(&self.local).copied()
    }
    pub fn prepare_local(&mut self, prepare: TerminalPrepareV1) -> Result<Vec<u8>> {
        let message = MessageV1 {
            start: self.start,
            origin: self.local,
            body: BodyV1::Prepare(prepare),
        };
        // Apply the same closed format constraints to the originating cut.
        MessageV1::decode(&message.encode())?;
        self.insert(message)?;
        Ok(message.encode())
    }
    pub fn admit(&mut self, inbound: &MeshInboundFrameV0) -> Result<()> {
        ensure!(
            inbound.direction() == PeerDirectionV0::Inbound
                && inbound.frame().kind == FrameKind::TerminalBarrier,
            "terminal ingress requires direct inbound owner"
        );
        ensure!(
            inbound.frame().sender == inbound.remote()
                && inbound.frame().session == inbound.session_id(),
            "terminal frame differs from mesh owner"
        );
        ensure!(
            self.sessions
                .get(&(PeerDirectionV0::Inbound, inbound.remote()))
                == Some(&(inbound.session_generation(), inbound.session_id())),
            "terminal frame uses noncurrent session"
        );
        let message = MessageV1::decode(&inbound.frame().payload)?;
        ensure!(
            message.origin == inbound.remote()
                && message.origin != self.local
                && message.start == self.start,
            "terminal origin or fleet Start mismatch"
        );
        self.insert(message)
    }
    fn insert(&mut self, message: MessageV1) -> Result<()> {
        ensure!(
            message.start == self.start && self.members.contains(&message.origin),
            "terminal member/context mismatch"
        );
        match message.body {
            BodyV1::Prepare(prepare) => {
                if let Some(previous) = self.prepares.get(&message.origin) {
                    ensure!(*previous == prepare, "conflicting terminal Prepare");
                    return Ok(());
                }
                ensure!(
                    self.prepares.values().all(|p| p.common == prepare.common),
                    "terminal final roots differ"
                );
                self.prepares.insert(message.origin, prepare);
            }
            BodyV1::Park(set) => {
                ensure!(
                    self.local_prepared(),
                    "terminal Park arrived before local Prepare"
                );
                if let Some(previous) = self.parks.get(&message.origin) {
                    ensure!(*previous == set, "conflicting terminal Park");
                    return Ok(());
                }
                if let Some(expected) = self.prepare_set()? {
                    ensure!(
                        set == expected,
                        "terminal Park differs from full Prepare set"
                    );
                }
                self.parks.insert(message.origin, set);
            }
        }
        // Early Park is inert until the complete, identically sorted set exists.
        if let Some(set) = self.prepare_set()? {
            ensure!(
                self.parks.values().all(|park| *park == set),
                "early terminal Park differs from full Prepare set"
            );
        }
        Ok(())
    }
    pub fn prepare_set(&self) -> Result<Option<[u8; 32]>> {
        if self.prepares.len() != 7 {
            return Ok(None);
        }
        let mut hash = Sha256::new();
        hash.update(b"TRNM/DirectSevenTerminalPrepareSet/V1\0");
        hash.update(7_u32.to_le_bytes());
        for (origin, prepare) in &self.prepares {
            // Outer session/sequence/signature is peer-specific and must never
            // enter this common digest.
            hash.update(
                MessageV1 {
                    start: self.start,
                    origin: *origin,
                    body: BodyV1::Prepare(*prepare),
                }
                .encode(),
            );
        }
        Ok(Some(hash.finalize().into()))
    }
    /// No Park bytes can be originated from detached facts or a live runtime.
    pub fn park_local(
        &mut self,
        terminal: &mut crate::continuous_runtime::ContinuousValidatorTerminalOwnerV0,
    ) -> Result<Vec<u8>> {
        let set = self
            .prepare_set()?
            .context("terminal Park lacks all seven Prepare records")?;
        let facts = *terminal.confirm_terminal_cut_v1()?;
        let node = facts.node_v0();
        let prepare = self
            .local_prepare()
            .context("terminal Park lacks local Prepare")?;
        ensure!(
            facts.local_validator_v0() == self.local
                && facts.validator_count_v0() == 7
                && node.checkpoint_canonical_sha256_v0() == prepare.checkpoint
                && (TerminalCommonCutV1 {
                    height: node.finalized_height_v0(),
                    block: *node.finalized_block_id_v0().as_bytes(),
                    state: node.application_state_root_v0(),
                    chain: node.finalized_chain_root_v0()
                }) == prepare.common,
            "consumed terminal owner differs from original Prepare"
        );
        let message = MessageV1 {
            start: self.start,
            origin: self.local,
            body: BodyV1::Park(set),
        };
        self.insert(message)?;
        Ok(message.encode())
    }
    pub fn complete(&self) -> Result<bool> {
        Ok(self.prepare_set()?.is_some_and(|set| {
            self.parks.len() == 7
                && self.parks.values().all(|p| *p == set)
                && self
                    .unavailable
                    .iter()
                    .all(|(_, peer)| self.parks.get(peer) == Some(&set))
        }))
    }
    pub fn observe_unavailable(&mut self, session: PeerSessionFactsV0) -> Result<()> {
        ensure!(
            self.parks.contains_key(&self.local),
            "disconnect before local terminal Park"
        );
        ensure!(
            self.sessions.get(&(session.direction(), session.remote()))
                == Some(&(session.generation(), session.session_id())),
            "terminal disconnect differs from current session"
        );
        // Outbound lifecycle can overtake the peer's inbound Park on another
        // worker. Retain at most twelve exact obligations until N/N Park;
        // none authorizes successful exit or clears a prior ordinary fault.
        self.unavailable
            .insert((session.direction(), session.remote()));
        Ok(())
    }
    pub fn explains_unavailable(&self, session: PeerSessionFactsV0) -> Result<bool> {
        let Some(set) = self.prepare_set()? else {
            return Ok(false);
        };
        Ok(self.parks.contains_key(&self.local)
            && self.parks.get(&session.remote()) == Some(&set)
            && self.sessions.get(&(session.direction(), session.remote()))
                == Some(&(session.generation(), session.session_id())))
    }
    pub fn validate_residual(
        &self,
        event: crate::consensus_mesh::MeshIngressEventV0,
    ) -> Result<()> {
        ensure!(
            self.complete()?,
            "terminal shutdown lacks all seven Park records"
        );
        match event {
            crate::consensus_mesh::MeshIngressEventV0::Frame(inbound) => {
                ensure!(
                    inbound.direction() == PeerDirectionV0::Inbound
                        && inbound.frame().kind == FrameKind::TerminalBarrier
                        && inbound.frame().sender == inbound.remote()
                        && inbound.frame().session == inbound.session_id(),
                    "ordinary or unowned ingress behind terminal barrier"
                );
                ensure!(
                    self.sessions
                        .get(&(PeerDirectionV0::Inbound, inbound.remote()))
                        == Some(&(inbound.session_generation(), inbound.session_id())),
                    "residual terminal session differs"
                );
                let message = MessageV1::decode(&inbound.frame().payload)?;
                ensure!(
                    message.start == self.start && message.origin == inbound.remote(),
                    "residual terminal context differs"
                );
                let exact = match message.body {
                    BodyV1::Prepare(p) => self.prepares.get(&message.origin) == Some(&p),
                    BodyV1::Park(p) => self.parks.get(&message.origin) == Some(&p),
                };
                ensure!(
                    exact,
                    "residual terminal frame is not exact observed replay"
                );
            }
            crate::consensus_mesh::MeshIngressEventV0::SessionUnavailable(session) => ensure!(
                self.explains_unavailable(session)?,
                "unexplained residual terminal disconnect"
            ),
            crate::consensus_mesh::MeshIngressEventV0::SessionReestablished(_) => {
                anyhow::bail!("reconnect queued at terminal shutdown")
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("terminal_barrier_tests_v1.inc");
}
