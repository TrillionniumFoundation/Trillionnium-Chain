use sha2::{Digest, Sha512};

use crate::cell::{
    adoption_boundary::CellModelUpdateBoundaryV1, require, CellDigestV1, CellErrorV1, CellResultV1,
    CellVersionCommitmentV1,
};

pub const MAX_CELL_ADOPTION_CANDIDATES_V1: u32 = 16;
pub const MAX_CELL_ADOPTION_DECISIONS_V1: u32 = 1024;

/// Independently supplied immutable local configuration, never a peer-decoded
/// policy. A changed identity, scope, boundary or capacity needs a fresh owner
/// namespace and an explicit migration; reopening cannot silently replace it.
#[derive(Clone, Debug)]
pub struct CellAdoptionPolicyV1 {
    pub(super) node: CellDigestV1,
    pub(super) policy: CellDigestV1,
    pub(super) scope: CellDigestV1,
    pub(super) boundary: CellModelUpdateBoundaryV1,
    pub(super) candidates: u32,
    pub(super) decisions: u32,
}

impl CellAdoptionPolicyV1 {
    pub fn new(
        node: CellDigestV1,
        policy: CellDigestV1,
        scope: CellDigestV1,
        boundary: CellModelUpdateBoundaryV1,
    ) -> CellResultV1<Self> {
        require(
            [node, policy, scope].iter().all(|value| *value != [0; 32]),
            "adoption local policy identity",
        )?;
        Ok(Self {
            node,
            policy,
            scope,
            boundary,
            candidates: MAX_CELL_ADOPTION_CANDIDATES_V1,
            decisions: MAX_CELL_ADOPTION_DECISIONS_V1,
        })
    }

    /// Tighten the finite local journal before creating it. No eviction or
    /// automatic history reset is performed when either capacity is exhausted.
    pub fn with_limits(mut self, candidates: u32, decisions: u32) -> CellResultV1<Self> {
        require(
            (1..=MAX_CELL_ADOPTION_CANDIDATES_V1).contains(&candidates)
                && (1..=MAX_CELL_ADOPTION_DECISIONS_V1).contains(&decisions),
            "adoption local policy limits",
        )?;
        self.candidates = candidates;
        self.decisions = decisions;
        Ok(self)
    }

    pub fn digest(&self) -> CellVersionCommitmentV1 {
        hash(b"TRNM/Cell/LocalAdoptionPolicy/v1\0", &self.encode())
    }

    pub fn node_id(&self) -> CellDigestV1 {
        self.node
    }

    pub fn boundary(&self) -> &CellModelUpdateBoundaryV1 {
        &self.boundary
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = b"TAP1".to_vec();
        bytes.extend(self.node);
        bytes.extend(self.policy);
        bytes.extend(self.scope);
        bytes.extend(self.boundary.digest());
        bytes.extend(self.candidates.to_be_bytes());
        bytes.extend(self.decisions.to_be_bytes());
        bytes
    }

    pub(super) fn initial(&self) -> CellAdoptionSnapshotV1 {
        let policy = self.digest();
        CellAdoptionSnapshotV1 {
            policy,
            revision: 0,
            selected: None,
            history: hash(b"TRNM/Cell/LocalAdoptionInitial/v1\0", &policy),
        }
    }
}

/// Commitments to external evidence bytes only. None means no such evidence
/// was supplied. This type contains no signature/quorum/quality acceptance bit.
/// The local reviewer authenticates and evaluates the underlying material.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CellCandidateEvidenceV1 {
    pub evaluation: Option<CellVersionCommitmentV1>,
    pub reproduction: Option<CellVersionCommitmentV1>,
    pub chain_observation: Option<CellVersionCommitmentV1>,
    pub settlement: Option<CellVersionCommitmentV1>,
}

impl CellCandidateEvidenceV1 {
    pub fn commitment(&self) -> CellVersionCommitmentV1 {
        hash(
            b"TRNM/Cell/CandidateEvidenceReferences/v1\0",
            &self.encode(),
        )
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = b"TCE1".to_vec();
        for value in [
            self.evaluation,
            self.reproduction,
            self.chain_observation,
            self.settlement,
        ] {
            put_optional(&mut bytes, value);
        }
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        let mut input = Input(bytes);
        require(input.take::<4>()? == *b"TCE1", "adoption evidence schema")?;
        let value = Self {
            evaluation: input.optional()?,
            reproduction: input.optional()?,
            chain_observation: input.optional()?,
            settlement: input.optional()?,
        };
        input.end()?;
        value.validate()?;
        Ok(value)
    }

    pub(super) fn validate(&self) -> CellResultV1<()> {
        require(
            [
                self.evaluation,
                self.reproduction,
                self.chain_observation,
                self.settlement,
            ]
            .into_iter()
            .flatten()
            .all(|value| value != [0; 64]),
            "adoption zero evidence reference",
        )
    }
}

/// A local observation of metadata and references. It grants no adoption,
/// publication, settlement, storage promise, execution, or independent review.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellCandidateObservationV1 {
    pub candidate: CellVersionCommitmentV1,
    pub parent: Option<CellVersionCommitmentV1>,
    pub evidence: CellVersionCommitmentV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CellAdoptionActionV1 {
    Adopt = 1,
    Defer = 2,
    Retain = 3,
    Rollback = 4,
}

impl CellAdoptionActionV1 {
    fn decode(value: u8) -> CellResultV1<Self> {
        match value {
            1 => Ok(Self::Adopt),
            2 => Ok(Self::Defer),
            3 => Ok(Self::Retain),
            4 => Ok(Self::Rollback),
            _ => Err(CellErrorV1::Invalid("adoption decision action")),
        }
    }
}

/// A local journal observation, not an authorization. Decode is for a trusted
/// owner's persisted recovery floor; parsing peer bytes does not trust them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellAdoptionSnapshotV1 {
    pub(super) policy: CellVersionCommitmentV1,
    pub(super) revision: u64,
    pub(super) selected: Option<CellVersionCommitmentV1>,
    pub(super) history: CellVersionCommitmentV1,
}

impl CellAdoptionSnapshotV1 {
    pub fn policy_digest(&self) -> CellVersionCommitmentV1 {
        self.policy
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn selected(&self) -> Option<CellVersionCommitmentV1> {
        self.selected
    }
    pub fn history_digest(&self) -> CellVersionCommitmentV1 {
        self.history
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = b"TAS1".to_vec();
        bytes.extend(self.policy);
        bytes.extend(self.revision.to_be_bytes());
        put_optional(&mut bytes, self.selected);
        bytes.extend(self.history);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        let mut input = Input(bytes);
        require(input.take::<4>()? == *b"TAS1", "adoption snapshot schema")?;
        let value = Self {
            policy: input.take()?,
            revision: u64::from_be_bytes(input.take()?),
            selected: input.optional()?,
            history: input.take()?,
        };
        input.end()?;
        require(
            value.policy != [0; 64]
                && value.history != [0; 64]
                && value.selected != Some([0; 64])
                && value.revision <= u64::from(MAX_CELL_ADOPTION_DECISIONS_V1),
            "adoption snapshot fields",
        )?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Decision {
    pub request: CellDigestV1,
    pub before: CellAdoptionSnapshotV1,
    pub action: CellAdoptionActionV1,
    pub candidate: CellVersionCommitmentV1,
    pub review: CellVersionCommitmentV1,
}

impl Decision {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = b"TAD1".to_vec();
        bytes.extend(self.request);
        let before = self.before.encode();
        bytes.extend((before.len() as u16).to_be_bytes());
        bytes.extend(before);
        bytes.push(self.action as u8);
        bytes.extend(self.candidate);
        bytes.extend(self.review);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        let mut input = Input(bytes);
        require(input.take::<4>()? == *b"TAD1", "adoption request schema")?;
        let request = input.take()?;
        let length = u16::from_be_bytes(input.take()?) as usize;
        let before = CellAdoptionSnapshotV1::decode(input.bytes(length)?)?;
        let value = Self {
            request,
            before,
            action: CellAdoptionActionV1::decode(input.take::<1>()?[0])?,
            candidate: input.take()?,
            review: input.take()?,
        };
        input.end()?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> CellResultV1<()> {
        require(
            self.request != [0; 32] && self.candidate != [0; 64] && self.review != [0; 64],
            "adoption local decision identity/review",
        )
    }
}

/// The exact committed local decision. Replaying an old receipt only reports
/// that old event; callers must use a fresh snapshot before actual model use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellAdoptionReceiptV1 {
    pub(super) decision: Decision,
    pub(super) after: CellAdoptionSnapshotV1,
    pub(super) evidence_set: CellVersionCommitmentV1,
}

impl CellAdoptionReceiptV1 {
    pub fn request_id(&self) -> CellDigestV1 {
        self.decision.request
    }
    pub fn action(&self) -> CellAdoptionActionV1 {
        self.decision.action
    }
    pub fn candidate(&self) -> CellVersionCommitmentV1 {
        self.decision.candidate
    }
    pub fn before(&self) -> &CellAdoptionSnapshotV1 {
        &self.decision.before
    }
    pub fn after(&self) -> &CellAdoptionSnapshotV1 {
        &self.after
    }
    pub fn review_commitment(&self) -> CellVersionCommitmentV1 {
        self.decision.review
    }
    pub fn evidence_set_commitment(&self) -> CellVersionCommitmentV1 {
        self.evidence_set
    }
    pub(super) fn new(
        decision: Decision,
        selected: Option<CellVersionCommitmentV1>,
        evidence_set: CellVersionCommitmentV1,
    ) -> CellResultV1<Self> {
        let mut material = decision.encode();
        material.extend(evidence_set);
        put_optional(&mut material, selected);
        let after = CellAdoptionSnapshotV1 {
            policy: decision.before.policy,
            revision: decision
                .before
                .revision
                .checked_add(1)
                .ok_or(CellErrorV1::Invalid("adoption revision overflow"))?,
            selected,
            history: hash(b"TRNM/Cell/LocalAdoptionDecision/v1\0", &material),
        };
        Ok(Self {
            decision,
            after,
            evidence_set,
        })
    }
}

pub(super) fn hash(domain: &[u8], bytes: &[u8]) -> CellVersionCommitmentV1 {
    let mut state = Sha512::new();
    state.update(domain);
    state.update(bytes);
    state.finalize().into()
}

fn put_optional(bytes: &mut Vec<u8>, value: Option<CellVersionCommitmentV1>) {
    bytes.push(u8::from(value.is_some()));
    if let Some(value) = value {
        bytes.extend(value);
    }
}

struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn bytes(&mut self, count: usize) -> CellResultV1<&'a [u8]> {
        require(count <= self.0.len(), "adoption truncated encoding")?;
        let (head, tail) = self.0.split_at(count);
        self.0 = tail;
        Ok(head)
    }
    fn take<const N: usize>(&mut self) -> CellResultV1<[u8; N]> {
        Ok(self.bytes(N)?.try_into().unwrap())
    }
    fn optional(&mut self) -> CellResultV1<Option<CellVersionCommitmentV1>> {
        match self.take::<1>()?[0] {
            0 => Ok(None),
            1 => Ok(Some(self.take()?)),
            _ => Err(CellErrorV1::Invalid("adoption optional encoding")),
        }
    }
    fn end(self) -> CellResultV1<()> {
        require(self.0.is_empty(), "adoption trailing encoding")
    }
}
