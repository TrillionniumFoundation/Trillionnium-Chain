//! Bounded consensus ingress and certificate collectors for the G3 LAN lane.
//!
//! This module is deliberately below a validator event loop. It consumes
//! authenticated transport frames, reconstructs exact frozen-v0 values, and
//! can aggregate strictly verified Vote and TimeoutVote statements into QC/TC
//! values. It owns no Core, SafetyStore, signer, application, pacemaker, or
//! network socket and therefore cannot be mistaken for consensus authority.

use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    fmt,
};

use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    BlockId, CertificateId, ConsensusParametersV0, ContextAuthorizedQcV0, Height, QcRef,
    QcReferenceV0, QuorumCertificate, TimeoutCertificateV0, TimeoutEntryV0, TimeoutVote,
    ValidatorId, ValidatorSet, View, Vote,
};

use crate::{
    frame::{AuthenticatedFrame, FrameKind},
    wire::{
        admission_budget_for_context, decode_quorum_certificate_with_budget,
        decode_timeout_certificate_with_budget, decode_timeout_vote_with_budget,
        decode_vote_with_budget, ConsensusWireError, UnboundProposalV0,
    },
};

pub const MAX_PENDING_COORDINATES_V0: usize = 4_096;

type QuorumCoordinateV0 = (View, Height, BlockId);

/// Semantic identity of a QC carrier inside a timeout certificate.
///
/// The certificate digest is intentionally omitted: signer-subset variants
/// may have different bytes while certifying the same logical target.  The
/// synthetic/ordinary discriminator remains part of the identity because an
/// authenticated anchor is not interchangeable with an ordinary QC whose
/// summary happens to match.
type TimeoutQcTargetV0 = (bool, u64, u64, u64, [u8; 32], [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmittedConsensusMessageV0 {
    Proposal(Box<UnboundProposalV0>),
    Vote(Vote),
    TimeoutVote(TimeoutVote),
    QuorumCertificate(QuorumCertificate),
    TimeoutCertificate(TimeoutCertificateV0),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorAdmissionV0 {
    Inserted,
    ExactReplay,
}

#[derive(Debug)]
pub enum ConsensusIngressErrorV0 {
    Wire(ConsensusWireError),
    UnknownSender,
    SenderStatementMismatch,
    UnsupportedFrameKind,
    StaleView,
    Capacity,
    VoteEquivocation,
    TimeoutEquivocation,
    MissingQcReference(CertificateId),
    ConflictingQcReference(CertificateId),
    ConflictingQcCoordinate {
        view: View,
        height: Height,
        block_id: BlockId,
    },
    ConflictingTimeoutCoordinate(View),
    InvalidCertificate(String),
}

impl fmt::Display for ConsensusIngressErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "consensus wire: {error}"),
            Self::UnknownSender => formatter.write_str("frame sender is absent from validator set"),
            Self::SenderStatementMismatch => {
                formatter.write_str("authenticated sender differs from statement author")
            }
            Self::UnsupportedFrameKind => {
                formatter.write_str("frame kind is outside consensus ingress")
            }
            Self::StaleView => formatter.write_str("consensus statement view was pruned"),
            Self::Capacity => formatter.write_str("bounded collector capacity exhausted"),
            Self::VoteEquivocation => formatter.write_str("validator sent conflicting votes"),
            Self::TimeoutEquivocation => {
                formatter.write_str("validator sent conflicting timeout votes")
            }
            Self::MissingQcReference(id) => {
                write!(
                    formatter,
                    "missing exact timeout QC reference {}",
                    hex::encode(id.as_bytes())
                )
            }
            Self::ConflictingQcReference(id) => {
                write!(
                    formatter,
                    "conflicting QC reference {}",
                    hex::encode(id.as_bytes())
                )
            }
            Self::ConflictingQcCoordinate {
                view,
                height,
                block_id,
            } => write!(
                formatter,
                "conflicting QC coordinate view={} height={} block={}",
                view.get(),
                height.get(),
                hex::encode(block_id.as_bytes())
            ),
            Self::ConflictingTimeoutCoordinate(view) => {
                write!(
                    formatter,
                    "conflicting timeout coordinate view={}",
                    view.get()
                )
            }
            Self::InvalidCertificate(reason) => write!(formatter, "invalid certificate: {reason}"),
        }
    }
}

impl std::error::Error for ConsensusIngressErrorV0 {}

impl From<ConsensusWireError> for ConsensusIngressErrorV0 {
    fn from(value: ConsensusWireError) -> Self {
        Self::Wire(value)
    }
}

/// Decodes one already authenticated transport frame and checks that any
/// author carried inside the statement is exactly the authenticated sender.
/// QC/TC frames may be relayed by any member of the same configured set.
pub fn decode_authenticated_consensus_frame_v0(
    frame: &AuthenticatedFrame,
    validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
) -> Result<AdmittedConsensusMessageV0, ConsensusIngressErrorV0> {
    if validator_set.validator(frame.sender).is_none() {
        return Err(ConsensusIngressErrorV0::UnknownSender);
    }
    // One shared meter covers the complete logical statement.  The strict
    // verifier is reached only after the selected decoder has charged its
    // root bytes and signature work.
    let mut budget = admission_budget_for_context(consensus_parameters, validator_set)?;
    match frame.kind {
        FrameKind::Proposal => {
            let proposal = UnboundProposalV0::decode_with_budget(
                &frame.payload,
                validator_set,
                consensus_parameters,
                &mut budget,
            )?;
            if proposal.block().header().proposer_id() != frame.sender {
                return Err(ConsensusIngressErrorV0::SenderStatementMismatch);
            }
            Ok(AdmittedConsensusMessageV0::Proposal(Box::new(proposal)))
        }
        FrameKind::Vote => {
            let vote = decode_vote_with_budget(&frame.payload, validator_set, &mut budget)?;
            if vote.author() != frame.sender {
                return Err(ConsensusIngressErrorV0::SenderStatementMismatch);
            }
            Ok(AdmittedConsensusMessageV0::Vote(vote))
        }
        FrameKind::TimeoutVote => {
            let vote = decode_timeout_vote_with_budget(&frame.payload, validator_set, &mut budget)?;
            if vote.author() != frame.sender {
                return Err(ConsensusIngressErrorV0::SenderStatementMismatch);
            }
            Ok(AdmittedConsensusMessageV0::TimeoutVote(vote))
        }
        FrameKind::QuorumCertificate => Ok(AdmittedConsensusMessageV0::QuorumCertificate(
            decode_quorum_certificate_with_budget(&frame.payload, validator_set, &mut budget)?,
        )),
        FrameKind::TimeoutCertificate => Ok(AdmittedConsensusMessageV0::TimeoutCertificate(
            decode_timeout_certificate_with_budget(&frame.payload, validator_set, &mut budget)?,
        )),
        FrameKind::SubmitBatch | FrameKind::Health | FrameKind::ConsensusRelay => {
            Err(ConsensusIngressErrorV0::UnsupportedFrameKind)
        }
        // Barrier statements have their own independent signature and strict
        // 2N admission map. They must never enter the ordinary collector.
        FrameKind::FleetReady | FrameKind::FleetStart => {
            Err(ConsensusIngressErrorV0::UnsupportedFrameKind)
        }
        // Restart protocol messages have a separate fixed 5N admission map
        // and never enter the view-indexed QC/TC collector.
        FrameKind::RestartPrepare
        | FrameKind::RestartCut
        | FrameKind::RestartParkedAck
        | FrameKind::RestartRecoveryReady
        | FrameKind::RestartRecoveryStart => Err(ConsensusIngressErrorV0::UnsupportedFrameKind),
        // Dedicated catch-up wire has its own strict subtype verifier and
        // non-evicting admission. It is not a fifth restart phase and cannot
        // enter Proposal/QC/TC collection.
        FrameKind::RestartCatchup => Err(ConsensusIngressErrorV0::UnsupportedFrameKind),
    }
}

/// Bounded, deterministic QC/TC aggregation state.
///
/// Exact replays are idempotent. Conflicting statements by one author are
/// rejected and retained as a safety signal; this collector does not attempt
/// to manufacture an evidence object or mutate Core state.
#[derive(Clone)]
pub struct ConsensusCertificateCollectorV0 {
    validator_set: ValidatorSet,
    max_pending_coordinates: usize,
    minimum_retained_view: View,
    votes: BTreeMap<(View, Height, BlockId), BTreeMap<ValidatorId, Vote>>,
    vote_choices: BTreeMap<(View, Height, ValidatorId), BlockId>,
    timeouts: BTreeMap<View, BTreeMap<ValidatorId, TimeoutVote>>,
    timeout_choices: BTreeMap<(View, ValidatorId), QcRef>,
    qc_references: BTreeMap<CertificateId, QcReferenceV0>,
    /// First verified QC observed for each semantic coordinate.
    ///
    /// A later vote can enlarge the collector's vote set after quorum has
    /// already been reached. Rebuilding a certificate from that enlarged set
    /// would produce a second valid QC with different bytes for the same
    /// `(view, height, block_id)`, which is not a new consensus event and
    /// conflicts with the content-addressed replay archive. Freeze the first
    /// verified certificate so retries and relays remain byte-identical.
    formed_qcs: BTreeMap<QuorumCoordinateV0, QuorumCertificate>,
    /// First verified TC observed for each timed-out view.  As with QCs,
    /// additional timeout votes can otherwise rebuild a byte-different
    /// certificate for an already completed semantic view.
    formed_tcs: BTreeMap<View, TimeoutCertificateV0>,
}

impl ConsensusCertificateCollectorV0 {
    pub fn new(
        validator_set: ValidatorSet,
        max_pending_coordinates: usize,
    ) -> Result<Self, ConsensusIngressErrorV0> {
        validator_set
            .validate_shape()
            .map_err(invalid_certificate)?;
        if max_pending_coordinates == 0 || max_pending_coordinates > MAX_PENDING_COORDINATES_V0 {
            return Err(ConsensusIngressErrorV0::Capacity);
        }
        Ok(Self {
            validator_set,
            max_pending_coordinates,
            minimum_retained_view: View::new(0),
            votes: BTreeMap::new(),
            vote_choices: BTreeMap::new(),
            timeouts: BTreeMap::new(),
            timeout_choices: BTreeMap::new(),
            qc_references: BTreeMap::new(),
            formed_qcs: BTreeMap::new(),
            formed_tcs: BTreeMap::new(),
        })
    }

    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub const fn minimum_retained_view(&self) -> View {
        self.minimum_retained_view
    }

    /// Drops consensus coordinates that can no longer affect the live Core
    /// tail. The caller must retain every QC reference still reachable from
    /// its authoritative high-QC/pending-TC state. Remaining timeout votes add
    /// their own referenced QCs automatically.
    ///
    /// This watermark is monotonic. Once a view is pruned, an authenticated
    /// replay for that view is rejected instead of consuming fresh capacity.
    pub fn prune_before_view(
        &mut self,
        minimum_retained_view: View,
        retain_qc_references: impl IntoIterator<Item = CertificateId>,
    ) -> Result<(), ConsensusIngressErrorV0> {
        if minimum_retained_view < self.minimum_retained_view {
            return Err(ConsensusIngressErrorV0::StaleView);
        }
        self.votes
            .retain(|(view, _, _), _| *view >= minimum_retained_view);
        self.vote_choices
            .retain(|(view, _, _), _| *view >= minimum_retained_view);
        self.timeouts
            .retain(|view, _| *view >= minimum_retained_view);
        self.timeout_choices
            .retain(|(view, _), _| *view >= minimum_retained_view);

        let mut retained_qcs = retain_qc_references.into_iter().collect::<BTreeSet<_>>();
        // A live canonical QC is itself an authoritative carrier.  Keep its
        // exact reference together with the frozen certificate even when the
        // caller did not repeat the ID in the explicit retention set; this
        // prevents a post-prune canonical getter from exposing an orphan that
        // TC formation can no longer resolve.
        retained_qcs.extend(
            self.formed_qcs
                .iter()
                .filter(|(coordinate, _)| coordinate.0 >= minimum_retained_view)
                .map(|(_, certificate)| certificate.id()),
        );
        for votes in self.timeouts.values() {
            retained_qcs.extend(votes.values().map(|vote| vote.high_qc().qc_digest()));
        }
        self.qc_references
            .retain(|certificate_id, _| retained_qcs.contains(certificate_id));
        self.formed_qcs.retain(|coordinate, certificate| {
            coordinate.0 >= minimum_retained_view || retained_qcs.contains(&certificate.id())
        });
        self.formed_tcs
            .retain(|timed_out_view, _| *timed_out_view >= minimum_retained_view);
        self.minimum_retained_view = minimum_retained_view;
        Ok(())
    }

    pub fn admit_vote(
        &mut self,
        vote: Vote,
    ) -> Result<CollectorAdmissionV0, ConsensusIngressErrorV0> {
        if vote.view() < self.minimum_retained_view {
            return Err(ConsensusIngressErrorV0::StaleView);
        }
        vote.verify(&self.validator_set, &StrictEd25519Verifier)
            .map_err(invalid_certificate)?;
        let author_coordinate = (vote.view(), vote.height(), vote.author());
        let mut inserted_choice = false;
        match self.vote_choices.entry(author_coordinate) {
            Entry::Occupied(entry) if *entry.get() != vote.block_id() => {
                return Err(ConsensusIngressErrorV0::VoteEquivocation);
            }
            Entry::Vacant(entry) => {
                entry.insert(vote.block_id());
                inserted_choice = true;
            }
            Entry::Occupied(_) => {}
        }
        let coordinate = (vote.view(), vote.height(), vote.block_id());
        if !self.votes.contains_key(&coordinate) && self.votes.len() >= self.max_pending_coordinates
        {
            if inserted_choice {
                self.vote_choices.remove(&author_coordinate);
            }
            return Err(ConsensusIngressErrorV0::Capacity);
        }
        match self
            .votes
            .entry(coordinate)
            .or_default()
            .entry(vote.author())
        {
            Entry::Occupied(entry) if entry.get() == &vote => Ok(CollectorAdmissionV0::ExactReplay),
            Entry::Occupied(_) => Err(ConsensusIngressErrorV0::VoteEquivocation),
            Entry::Vacant(entry) => {
                entry.insert(vote);
                Ok(CollectorAdmissionV0::Inserted)
            }
        }
    }

    pub fn try_quorum_certificate(
        &mut self,
        view: View,
        height: Height,
        block_id: BlockId,
    ) -> Result<Option<QuorumCertificate>, ConsensusIngressErrorV0> {
        if view < self.minimum_retained_view {
            return Err(ConsensusIngressErrorV0::StaleView);
        }
        let coordinate = (view, height, block_id);
        if let Some(certificate) = self.formed_qcs.get(&coordinate) {
            return Ok(Some(certificate.clone()));
        }
        let Some(votes) = self.votes.get(&(view, height, block_id)) else {
            return Ok(None);
        };
        if signed_power(&self.validator_set, votes.keys().copied())?
            < self.validator_set.quorum_power()
        {
            return Ok(None);
        }
        let certificate = QuorumCertificate::new(
            self.validator_set.chain_id(),
            self.validator_set.protocol_version(),
            self.validator_set.epoch(),
            view,
            height,
            block_id,
            self.validator_set.id(),
            votes.values().cloned().collect(),
            &self.validator_set,
        )
        .map_err(invalid_certificate)?;
        certificate
            .verify(&self.validator_set, &StrictEd25519Verifier)
            .map_err(invalid_certificate)?;
        self.register_qc_reference(QcReferenceV0::ordinary(certificate))?;
        // `register_qc_reference` may have observed a different valid QC for
        // this coordinate first.  Always return the frozen entry, never the
        // newly rebuilt candidate.
        Ok(self.formed_qcs.get(&coordinate).cloned())
    }

    /// Returns the first verified QC for one semantic coordinate, if any.
    pub fn canonical_quorum_certificate(
        &self,
        view: View,
        height: Height,
        block_id: BlockId,
    ) -> Option<&QuorumCertificate> {
        self.formed_qcs
            .get(&(view, height, block_id))
            .filter(|certificate| {
                view >= self.minimum_retained_view
                    || self.qc_references.contains_key(&certificate.id())
            })
    }

    pub fn register_qc_reference(
        &mut self,
        reference: QcReferenceV0,
    ) -> Result<CollectorAdmissionV0, ConsensusIngressErrorV0> {
        verify_qc_reference(&reference, &self.validator_set)?;
        let id = reference.id();
        if let Some(existing) = self.qc_references.get(&id) {
            if existing != &reference {
                return Err(ConsensusIngressErrorV0::ConflictingQcReference(id));
            }
            // An exact replay is inert.  If a retained reference lost its
            // auxiliary canonical entry due to an interrupted prune, restore
            // that entry only when capacity still permits it.
            if let QcReferenceV0::Ordinary(certificate) = &reference {
                let coordinate = (
                    certificate.view(),
                    certificate.height(),
                    certificate.block_id(),
                );
                if !self.formed_qcs.contains_key(&coordinate) {
                    if self.formed_qcs.len() >= self.max_pending_coordinates {
                        return Err(ConsensusIngressErrorV0::Capacity);
                    }
                    self.formed_qcs.insert(coordinate, (**certificate).clone());
                }
            }
            return Ok(CollectorAdmissionV0::ExactReplay);
        }
        let mut canonical_candidate = match &reference {
            QcReferenceV0::Ordinary(certificate) => Some((
                (
                    certificate.view(),
                    certificate.height(),
                    certificate.block_id(),
                ),
                (**certificate).clone(),
            )),
            QcReferenceV0::Synthetic(_) => None,
        };
        if let Some(((view, height, block_id), certificate)) = &canonical_candidate {
            let exact_retained = self
                .qc_references
                .get(&certificate.id())
                .is_some_and(|existing| existing.as_ordinary() == Some(certificate));
            if *view < self.minimum_retained_view && !exact_retained {
                return Err(ConsensusIngressErrorV0::StaleView);
            }
            if let Some(existing) = self.formed_qcs.get(&(*view, *height, *block_id)) {
                if existing.id() != certificate.id() {
                    // Same-coordinate QC variants are valid consensus
                    // evidence.  Keep the exact reference for decoding and
                    // audit, but do not let it replace the already frozen
                    // authority value or enter the canonical route.
                    canonical_candidate = None;
                }
            }
        }
        if let Some(((view, height, block_id), _)) = &canonical_candidate {
            if !self.formed_qcs.contains_key(&(*view, *height, *block_id))
                && self.formed_qcs.len() >= self.max_pending_coordinates
            {
                return Err(ConsensusIngressErrorV0::Capacity);
            }
        }
        let reference_bound = self
            .max_pending_coordinates
            .checked_add(1)
            .ok_or(ConsensusIngressErrorV0::Capacity)?;
        if self.qc_references.len() >= reference_bound {
            return Err(ConsensusIngressErrorV0::Capacity);
        }
        self.qc_references.insert(id, reference);
        if let Some((coordinate, certificate)) = canonical_candidate {
            self.formed_qcs.entry(coordinate).or_insert(certificate);
        }
        Ok(CollectorAdmissionV0::Inserted)
    }

    pub fn admit_timeout_vote(
        &mut self,
        vote: TimeoutVote,
    ) -> Result<CollectorAdmissionV0, ConsensusIngressErrorV0> {
        if vote.view() < self.minimum_retained_view {
            return Err(ConsensusIngressErrorV0::StaleView);
        }
        vote.verify(&self.validator_set, &StrictEd25519Verifier)
            .map_err(invalid_certificate)?;
        if let Some(reference) = self.qc_references.get(&vote.high_qc().qc_digest()) {
            if reference.qc_ref() != vote.high_qc() {
                return Err(ConsensusIngressErrorV0::ConflictingQcReference(
                    vote.high_qc().qc_digest(),
                ));
            }
            // A timeout vote may use an old high-QC only when that exact
            // reference is still retained across the watermark.  Same-view
            // alternate signer subsets remain valid protocol evidence and are
            // intentionally not rejected here; Core applies its own
            // coordinate/digest ordering rules.
            self.ensure_canonical_qc_reference(reference)?;
        }
        let author_coordinate = (vote.view(), vote.author());
        let mut inserted_choice = false;
        match self.timeout_choices.entry(author_coordinate) {
            Entry::Occupied(entry) if *entry.get() != vote.high_qc() => {
                return Err(ConsensusIngressErrorV0::TimeoutEquivocation);
            }
            Entry::Vacant(entry) => {
                entry.insert(vote.high_qc());
                inserted_choice = true;
            }
            Entry::Occupied(_) => {}
        }
        if !self.timeouts.contains_key(&vote.view())
            && self.timeouts.len() >= self.max_pending_coordinates
        {
            if inserted_choice {
                self.timeout_choices.remove(&author_coordinate);
            }
            return Err(ConsensusIngressErrorV0::Capacity);
        }
        match self
            .timeouts
            .entry(vote.view())
            .or_default()
            .entry(vote.author())
        {
            Entry::Occupied(entry) if entry.get() == &vote => Ok(CollectorAdmissionV0::ExactReplay),
            Entry::Occupied(_) => Err(ConsensusIngressErrorV0::TimeoutEquivocation),
            Entry::Vacant(entry) => {
                entry.insert(vote);
                Ok(CollectorAdmissionV0::Inserted)
            }
        }
    }

    pub fn try_timeout_certificate(
        &mut self,
        timed_out_view: View,
    ) -> Result<Option<TimeoutCertificateV0>, ConsensusIngressErrorV0> {
        if timed_out_view < self.minimum_retained_view {
            return Err(ConsensusIngressErrorV0::StaleView);
        }
        if let Some(certificate) = self.formed_tcs.get(&timed_out_view) {
            return Ok(Some(certificate.clone()));
        }
        let Some(votes) = self.timeouts.get(&timed_out_view) else {
            return Ok(None);
        };
        if signed_power(&self.validator_set, votes.keys().copied())?
            < self.validator_set.quorum_power()
        {
            return Ok(None);
        }
        let mut maximum: Option<QcRef> = None;
        let mut referenced = BTreeMap::new();
        let mut entries = Vec::with_capacity(votes.len());
        for vote in votes.values() {
            let high_qc = vote.high_qc();
            let reference = self.qc_references.get(&high_qc.qc_digest()).ok_or(
                ConsensusIngressErrorV0::MissingQcReference(high_qc.qc_digest()),
            )?;
            if reference.qc_ref() != high_qc {
                return Err(ConsensusIngressErrorV0::ConflictingQcReference(
                    high_qc.qc_digest(),
                ));
            }
            self.ensure_canonical_qc_reference(reference)?;
            referenced.insert(reference.id(), reference.clone());
            maximum = match maximum {
                Some(current)
                    if (current.view(), current.block_id(), current.qc_digest())
                        >= (high_qc.view(), high_qc.block_id(), high_qc.qc_digest()) =>
                {
                    Some(current)
                }
                _ => Some(high_qc),
            };
            entries.push(
                TimeoutEntryV0::new(vote.author(), high_qc, *vote.signature())
                    .map_err(invalid_certificate)?,
            );
        }
        let selected = maximum.ok_or_else(|| {
            ConsensusIngressErrorV0::InvalidCertificate("empty timeout quorum".to_owned())
        })?;
        let certificate = TimeoutCertificateV0::new(
            timed_out_view,
            entries,
            referenced.into_values().collect(),
            selected.qc_digest(),
            &self.validator_set,
        )
        .map_err(invalid_certificate)?;
        certificate
            .verify(&self.validator_set, None, &StrictEd25519Verifier)
            .map_err(invalid_certificate)?;
        if self.formed_tcs.len() >= self.max_pending_coordinates {
            return Err(ConsensusIngressErrorV0::Capacity);
        }
        self.formed_tcs.insert(timed_out_view, certificate);
        Ok(self.formed_tcs.get(&timed_out_view).cloned())
    }

    /// Attempts timeout-certificate formation for a live ingress path where
    /// authenticated TimeoutVotes may arrive before their complete QC
    /// carrier.  The strict [`Self::try_timeout_certificate`] API remains
    /// fail-closed for callers that need to distinguish a permanently
    /// missing reference; the event loop treats that one dependency as
    /// transient and retries after the QC frame is admitted.
    pub(crate) fn try_timeout_certificate_if_ready(
        &mut self,
        timed_out_view: View,
    ) -> Result<Option<TimeoutCertificateV0>, ConsensusIngressErrorV0> {
        match self.try_timeout_certificate(timed_out_view) {
            Err(ConsensusIngressErrorV0::MissingQcReference(_)) => Ok(None),
            result => result,
        }
    }

    /// Returns every timeout view currently retained by the collector.  The
    /// caller snapshots the keys before attempting formation so a late QC can
    /// be registered and retried without borrowing the map across mutation.
    pub(crate) fn pending_timeout_views(&self) -> Vec<View> {
        self.timeouts.keys().copied().collect()
    }

    /// Returns the first verified TC for one timed-out view, if any.
    pub fn canonical_timeout_certificate(
        &self,
        timed_out_view: View,
    ) -> Option<&TimeoutCertificateV0> {
        self.formed_tcs
            .get(&timed_out_view)
            .filter(|_| timed_out_view >= self.minimum_retained_view)
    }

    /// Registers a complete remote TC and freezes the first verified bytes for
    /// its timed-out view.  Later valid variants remain available through the
    /// ordinary QC-reference map for strict decoding, but are not routed as a
    /// second authority event.
    pub fn register_timeout_certificate(
        &mut self,
        certificate: TimeoutCertificateV0,
    ) -> Result<TimeoutCertificateV0, ConsensusIngressErrorV0> {
        // Exact replay and a previously frozen conflicting view are handled
        // before clone-on-write.  This keeps a replay storm from repeatedly
        // copying the bounded collector maps.
        let timed_out_view = certificate.timed_out_view();
        if timed_out_view < self.minimum_retained_view {
            return Err(ConsensusIngressErrorV0::StaleView);
        }
        if self
            .formed_tcs
            .get(&timed_out_view)
            .is_some_and(|existing| existing == &certificate)
        {
            return Ok(self
                .formed_tcs
                .get(&timed_out_view)
                .expect("checked frozen timeout certificate")
                .clone());
        }
        let mut staged = self.clone();
        let canonical = staged.register_timeout_certificate_inner(certificate)?;
        *self = staged;
        Ok(canonical)
    }

    fn register_timeout_certificate_inner(
        &mut self,
        certificate: TimeoutCertificateV0,
    ) -> Result<TimeoutCertificateV0, ConsensusIngressErrorV0> {
        let timed_out_view = certificate.timed_out_view();
        if timed_out_view < self.minimum_retained_view {
            return Err(ConsensusIngressErrorV0::StaleView);
        }
        let had_frozen_tc = self.formed_tcs.contains_key(&timed_out_view);
        certificate
            .verify(&self.validator_set, None, &StrictEd25519Verifier)
            .map_err(invalid_certificate)?;
        // A signer-subset/digest alternate for the same logical target is
        // harmless and is routed through the first frozen bytes.  A
        // certificate that changes the timeout context or any referenced-QC
        // target is a safety conflict, even when its signatures are valid.
        // Check this before mutating the staged reference maps so the
        // clone-on-write admission remains fail-closed and atomic.
        if let Some(existing) = self.formed_tcs.get(&timed_out_view) {
            if !timeout_certificates_same_semantic_target_v0(existing, &certificate)? {
                return Err(ConsensusIngressErrorV0::ConflictingTimeoutCoordinate(
                    timed_out_view,
                ));
            }
        }
        for reference in certificate.referenced_qcs() {
            self.ensure_canonical_qc_reference(reference)?;
            self.register_qc_reference(reference.clone())?;
        }
        if !had_frozen_tc && self.formed_tcs.len() >= self.max_pending_coordinates {
            return Err(ConsensusIngressErrorV0::Capacity);
        }
        if !had_frozen_tc {
            self.formed_tcs.insert(timed_out_view, certificate.clone());
        }
        // A remote alternate can still be a valid certificate for the same
        // timed-out view.  It is retained only through its exact QC
        // references for audit/decoding; the route must carry the first
        // verified bytes that were frozen for this semantic coordinate.
        Ok(self
            .formed_tcs
            .get(&timed_out_view)
            .expect("timeout certificate is frozen after admission")
            .clone())
    }

    fn ensure_canonical_qc_reference(
        &self,
        reference: &QcReferenceV0,
    ) -> Result<(), ConsensusIngressErrorV0> {
        let QcReferenceV0::Ordinary(certificate) = reference else {
            return Ok(());
        };
        let exact_retained = self
            .qc_references
            .get(&certificate.id())
            .is_some_and(|existing| existing.as_ordinary() == Some(certificate));
        if certificate.view() < self.minimum_retained_view && !exact_retained {
            return Err(ConsensusIngressErrorV0::StaleView);
        }
        Ok(())
    }
}

/// Conservative coordinate budget for a retained view window. In one view,
/// independently authenticated validators can split their one vote each
/// across at most `validator_count` block coordinates, plus one timeout
/// coordinate. The runtime should prune by its authoritative Core watermark
/// before this sliding window is crossed.
pub fn required_pending_coordinate_capacity_v0(
    validator_count: usize,
    retained_views: usize,
) -> Result<usize, ConsensusIngressErrorV0> {
    if validator_count == 0 || retained_views == 0 {
        return Err(ConsensusIngressErrorV0::Capacity);
    }
    validator_count
        .checked_add(1)
        .and_then(|per_view| per_view.checked_mul(retained_views))
        .filter(|capacity| *capacity <= MAX_PENDING_COORDINATES_V0)
        .ok_or(ConsensusIngressErrorV0::Capacity)
}

fn timeout_qc_target_v0(reference: &QcReferenceV0) -> TimeoutQcTargetV0 {
    let summary = reference.qc_ref();
    (
        reference.as_synthetic().is_some(),
        summary.epoch().get(),
        summary.view().get(),
        summary.height().get(),
        *summary.block_id().as_bytes(),
        *summary.validator_set_id().as_bytes(),
    )
}

fn timeout_qc_targets_v0(certificate: &TimeoutCertificateV0) -> Vec<TimeoutQcTargetV0> {
    let mut targets = certificate
        .referenced_qcs()
        .iter()
        .map(timeout_qc_target_v0)
        .collect::<Vec<_>>();
    targets.sort_unstable();
    targets
}

fn selected_timeout_qc_target_v0(
    certificate: &TimeoutCertificateV0,
) -> Result<TimeoutQcTargetV0, ConsensusIngressErrorV0> {
    let selected_id = certificate.selected_high_qc_digest();
    let selected = certificate
        .referenced_qcs()
        .iter()
        .find(|reference| reference.id() == selected_id)
        .ok_or_else(|| {
            ConsensusIngressErrorV0::InvalidCertificate(
                "timeout certificate selected high-QC digest is absent from referenced QCs"
                    .to_owned(),
            )
        })?;
    Ok(timeout_qc_target_v0(selected))
}

/// Compares authenticated TCs while ignoring only signer-subset/digest
/// variation.  A different context, referenced-QC target, or selected target
/// must fail closed at the collector boundary.
fn timeout_certificates_same_semantic_target_v0(
    accepted: &TimeoutCertificateV0,
    candidate: &TimeoutCertificateV0,
) -> Result<bool, ConsensusIngressErrorV0> {
    if accepted.genesis_hash() != candidate.genesis_hash()
        || accepted.chain_id() != candidate.chain_id()
        || accepted.protocol_version() != candidate.protocol_version()
        || accepted.epoch() != candidate.epoch()
        || accepted.validator_set_hash() != candidate.validator_set_hash()
        || accepted.timed_out_view() != candidate.timed_out_view()
    {
        return Ok(false);
    }
    Ok(
        timeout_qc_targets_v0(accepted) == timeout_qc_targets_v0(candidate)
            && selected_timeout_qc_target_v0(accepted)?
                == selected_timeout_qc_target_v0(candidate)?,
    )
}

fn signed_power(
    validator_set: &ValidatorSet,
    validators: impl Iterator<Item = ValidatorId>,
) -> Result<u128, ConsensusIngressErrorV0> {
    let mut power = 0u128;
    for validator in validators {
        power = power
            .checked_add(
                validator_set
                    .power_of(validator)
                    .ok_or(ConsensusIngressErrorV0::UnknownSender)?,
            )
            .ok_or_else(|| {
                ConsensusIngressErrorV0::InvalidCertificate(
                    "signed voting-power overflow".to_owned(),
                )
            })?;
    }
    Ok(power)
}

fn verify_qc_reference(
    reference: &QcReferenceV0,
    validator_set: &ValidatorSet,
) -> Result<(), ConsensusIngressErrorV0> {
    match reference {
        QcReferenceV0::Ordinary(certificate) => certificate
            .verify(validator_set, &StrictEd25519Verifier)
            .map_err(invalid_certificate),
        QcReferenceV0::Synthetic(value) => match value.as_ref() {
            ContextAuthorizedQcV0::Genesis(anchor) => anchor
                .matches_trusted_set(validator_set)
                .map_err(invalid_certificate),
            ContextAuthorizedQcV0::Epoch(_) => Err(ConsensusIngressErrorV0::InvalidCertificate(
                "epoch anchors are outside the G3 epoch-zero collector".to_owned(),
            )),
        },
    }
}

fn invalid_certificate(error: impl fmt::Debug) -> ConsensusIngressErrorV0 {
    ConsensusIngressErrorV0::InvalidCertificate(format!("{error:?}"))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use trnm_consensus_types::{
        ChainId, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion, SignatureBytes,
        Validator, VotingPower,
    };

    use super::*;
    use crate::{frame::FrameKind, wire::encode_vote};

    fn fixture() -> (Vec<SigningKey>, ValidatorSet) {
        let keys: Vec<_> = (1u8..=7)
            .map(|seed| SigningKey::from_bytes(&[seed; 32]))
            .collect();
        let powers = [4u64, 3, 3, 2, 2, 1, 1];
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Validator::new(
                    ValidatorId::new([u8::try_from(index + 1).unwrap(); 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(powers[index]).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = ValidatorSet::new(
            GenesisHash::new([0xa1; 32]),
            ChainId::new("trnm-g3-collector-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        (keys, set)
    }

    #[test]
    fn restart_frames_never_enter_the_qc_tc_collector() {
        let (_, set) = fixture();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        for kind in [
            FrameKind::RestartPrepare,
            FrameKind::RestartCut,
            FrameKind::RestartParkedAck,
            FrameKind::RestartRecoveryReady,
            FrameKind::RestartRecoveryStart,
            FrameKind::RestartCatchup,
        ] {
            let frame = AuthenticatedFrame {
                sender: set.validators()[0].id(),
                session: [0x55; 32],
                sequence: 0,
                kind,
                payload: vec![1],
            };
            assert!(matches!(
                decode_authenticated_consensus_frame_v0(&frame, &set, &parameters),
                Err(ConsensusIngressErrorV0::UnsupportedFrameKind)
            ));
        }
    }

    #[test]
    fn authenticated_ingress_rejects_unbound_parameter_profile() {
        let (_, set) = fixture();
        let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
        fields.max_block_bytes = 1;
        fields.max_consensus_message_bytes = 1;
        let unbound = ConsensusParametersV0::new(fields).unwrap();
        let frame = AuthenticatedFrame {
            sender: set.validators()[0].id(),
            session: [0x56; 32],
            sequence: 0,
            kind: FrameKind::Vote,
            payload: Vec::new(),
        };
        assert!(matches!(
            decode_authenticated_consensus_frame_v0(&frame, &set, &unbound),
            Err(ConsensusIngressErrorV0::Wire(
                ConsensusWireError::Malformed(
                    "consensus parameters differ from validator-set context"
                )
            ))
        ));
    }

    fn vote(
        keys: &[SigningKey],
        set: &ValidatorSet,
        index: usize,
        view: u64,
        height: u64,
        block_id: BlockId,
    ) -> Vote {
        let root = Vote::signing_root_for_set(set, View::new(view), Height::new(height), block_id)
            .unwrap();
        Vote::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(height),
            block_id,
            set.id(),
            set.validators()[index].id(),
            SignatureBytes::from_array(keys[index].sign(root.as_bytes()).to_bytes()),
            set,
        )
        .unwrap()
    }

    fn timeout_vote(
        keys: &[SigningKey],
        set: &ValidatorSet,
        index: usize,
        view: u64,
        high_qc: QcRef,
    ) -> TimeoutVote {
        let root = TimeoutVote::signing_root_for_set(set, View::new(view), high_qc).unwrap();
        TimeoutVote::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            set.id(),
            high_qc,
            set.validators()[index].id(),
            SignatureBytes::from_array(keys[index].sign(root.as_bytes()).to_bytes()),
            set,
        )
        .unwrap()
    }

    #[test]
    fn weighted_vote_collection_forms_only_a_real_quorum() {
        let (keys, set) = fixture();
        assert_eq!(set.total_power(), 16);
        assert_eq!(set.quorum_power(), 11);
        let block = BlockId::new([0xb2; 32]);
        let mut collector = ConsensusCertificateCollectorV0::new(set.clone(), 8).unwrap();
        for index in 0..3 {
            collector
                .admit_vote(vote(&keys, &set, index, 4, 2, block))
                .unwrap();
        }
        assert!(collector
            .try_quorum_certificate(View::new(4), Height::new(2), block)
            .unwrap()
            .is_none());
        let fourth = vote(&keys, &set, 3, 4, 2, block);
        assert_eq!(
            collector.admit_vote(fourth.clone()).unwrap(),
            CollectorAdmissionV0::Inserted
        );
        assert_eq!(
            collector.admit_vote(fourth).unwrap(),
            CollectorAdmissionV0::ExactReplay
        );
        let certificate = collector
            .try_quorum_certificate(View::new(4), Height::new(2), block)
            .unwrap()
            .unwrap();
        assert_eq!(certificate.votes().len(), 4);
        certificate.verify(&set, &StrictEd25519Verifier).unwrap();
    }

    #[test]
    fn quorum_certificate_is_frozen_at_first_verified_coordinate() {
        let (keys, set) = fixture();
        let block = BlockId::new([0xb3; 32]);
        let mut collector = ConsensusCertificateCollectorV0::new(set.clone(), 8).unwrap();
        for index in 0..4 {
            collector
                .admit_vote(vote(&keys, &set, index, 4, 2, block))
                .unwrap();
        }
        let first = collector
            .try_quorum_certificate(View::new(4), Height::new(2), block)
            .unwrap()
            .expect("first quorum certificate");
        assert_eq!(first.votes().len(), 4);

        // A later vote would previously rebuild a larger, byte-different QC
        // for the same semantic coordinate.  The first verified certificate
        // remains the canonical replay/archive value.
        collector
            .admit_vote(vote(&keys, &set, 4, 4, 2, block))
            .unwrap();
        let retry = collector
            .try_quorum_certificate(View::new(4), Height::new(2), block)
            .unwrap()
            .expect("frozen quorum certificate retry");
        assert_eq!(retry, first);
        assert_eq!(
            collector
                .canonical_quorum_certificate(View::new(4), Height::new(2), block)
                .expect("canonical quorum certificate"),
            &first
        );

        // A separately received valid alternate is retained as a verified
        // reference for timeout-vote decoding, but cannot replace the frozen
        // canonical certificate used by the runtime.
        let alternate = QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(4),
            Height::new(2),
            block,
            set.id(),
            (0..5)
                .map(|index| vote(&keys, &set, index, 4, 2, block))
                .collect(),
            &set,
        )
        .unwrap();
        assert_ne!(alternate.id(), first.id());
        collector
            .register_qc_reference(QcReferenceV0::ordinary(alternate))
            .unwrap();
        assert_eq!(
            collector
                .canonical_quorum_certificate(View::new(4), Height::new(2), block)
                .expect("canonical quorum certificate after alternate"),
            &first
        );
    }

    #[test]
    fn timeout_collection_requires_exact_qc_carrier() {
        let (keys, set) = fixture();
        let block = BlockId::new([0xc3; 32]);
        let mut collector = ConsensusCertificateCollectorV0::new(set.clone(), 8).unwrap();
        for index in 0..4 {
            collector
                .admit_vote(vote(&keys, &set, index, 5, 3, block))
                .unwrap();
        }
        let qc = collector
            .try_quorum_certificate(View::new(5), Height::new(3), block)
            .unwrap()
            .unwrap();
        let high_qc = QcRef::from(&qc);
        let mut missing = ConsensusCertificateCollectorV0::new(set.clone(), 8).unwrap();
        for index in 0..4 {
            let timeout = timeout_vote(&keys, &set, index, 6, high_qc);
            collector.admit_timeout_vote(timeout.clone()).unwrap();
            missing.admit_timeout_vote(timeout).unwrap();
        }
        assert!(matches!(
            missing.try_timeout_certificate(View::new(6)),
            Err(ConsensusIngressErrorV0::MissingQcReference(_))
        ));
        let tc = collector
            .try_timeout_certificate(View::new(6))
            .unwrap()
            .unwrap();
        assert_eq!(tc.entries().len(), 4);
        assert_eq!(tc.referenced_qcs().len(), 1);
        assert_eq!(tc.selected_high_qc_digest(), qc.id());
        tc.verify(&set, None, &StrictEd25519Verifier).unwrap();
    }

    #[test]
    fn timeout_certificate_is_frozen_at_first_verified_view() {
        let (keys, set) = fixture();
        let block = BlockId::new([0xc4; 32]);
        let mut collector = ConsensusCertificateCollectorV0::new(set.clone(), 8).unwrap();
        for index in 0..4 {
            collector
                .admit_vote(vote(&keys, &set, index, 5, 3, block))
                .unwrap();
        }
        let qc = collector
            .try_quorum_certificate(View::new(5), Height::new(3), block)
            .unwrap()
            .expect("quorum carrier for timeout votes");
        let high_qc = QcRef::from(&qc);
        for index in 0..4 {
            collector
                .admit_timeout_vote(timeout_vote(&keys, &set, index, 6, high_qc))
                .unwrap();
        }
        let first = collector
            .try_timeout_certificate(View::new(6))
            .unwrap()
            .expect("first timeout certificate");
        collector
            .admit_timeout_vote(timeout_vote(&keys, &set, 4, 6, high_qc))
            .unwrap();
        let retry = collector
            .try_timeout_certificate(View::new(6))
            .unwrap()
            .expect("frozen timeout certificate retry");
        assert_eq!(retry, first);
        assert_eq!(
            collector
                .canonical_timeout_certificate(View::new(6))
                .expect("canonical timeout certificate"),
            &first
        );
    }

    #[test]
    fn remote_timeout_registration_routes_the_frozen_canonical() {
        let (keys, set) = fixture();
        let block = BlockId::new([0xc5; 32]);
        let mut collector = ConsensusCertificateCollectorV0::new(set.clone(), 8).unwrap();
        for index in 0..4 {
            collector
                .admit_vote(vote(&keys, &set, index, 5, 3, block))
                .unwrap();
        }
        let qc = collector
            .try_quorum_certificate(View::new(5), Height::new(3), block)
            .unwrap()
            .expect("quorum carrier for timeout votes");
        let high_qc = QcRef::from(&qc);
        for index in 0..4 {
            collector
                .admit_timeout_vote(timeout_vote(&keys, &set, index, 6, high_qc))
                .unwrap();
        }
        let first = collector
            .try_timeout_certificate(View::new(6))
            .unwrap()
            .expect("first timeout certificate");

        // Build a separately received, valid alternate with a larger signer
        // set.  It has the same semantic timed-out view but different bytes.
        let mut remote = ConsensusCertificateCollectorV0::new(set.clone(), 8).unwrap();
        remote
            .register_qc_reference(QcReferenceV0::ordinary(qc.clone()))
            .unwrap();
        for index in 0..5 {
            remote
                .admit_timeout_vote(timeout_vote(&keys, &set, index, 6, high_qc))
                .unwrap();
        }
        let alternate = remote
            .try_timeout_certificate(View::new(6))
            .unwrap()
            .expect("alternate timeout certificate");
        assert_ne!(alternate, first);

        let routed = collector.register_timeout_certificate(alternate).unwrap();
        assert_eq!(routed, first);
        assert_eq!(
            collector
                .canonical_timeout_certificate(View::new(6))
                .expect("frozen canonical timeout certificate"),
            &first
        );

        // A valid TC for the same timed-out view but a different high-QC
        // target is not an alternate signer subset; it is a conflicting
        // consensus coordinate and must be rejected atomically.
        let conflict_block = BlockId::new([0xc6; 32]);
        let mut conflicting_collector =
            ConsensusCertificateCollectorV0::new(set.clone(), 8).unwrap();
        for index in 0..4 {
            conflicting_collector
                .admit_vote(vote(&keys, &set, index, 5, 3, conflict_block))
                .unwrap();
        }
        let conflict_qc = conflicting_collector
            .try_quorum_certificate(View::new(5), Height::new(3), conflict_block)
            .unwrap()
            .expect("conflicting quorum carrier");
        let conflict_high_qc = QcRef::from(&conflict_qc);
        for index in 0..4 {
            conflicting_collector
                .admit_timeout_vote(timeout_vote(&keys, &set, index, 6, conflict_high_qc))
                .unwrap();
        }
        let conflicting_tc = conflicting_collector
            .try_timeout_certificate(View::new(6))
            .unwrap()
            .expect("conflicting timeout certificate");
        assert!(matches!(
            collector.register_timeout_certificate(conflicting_tc),
            Err(ConsensusIngressErrorV0::ConflictingTimeoutCoordinate(view))
                if view == View::new(6)
        ));
        // Clone-on-write admission must leave the conflicting QC out of the
        // live canonical map as well as preserving the accepted TC.
        assert!(collector
            .canonical_quorum_certificate(View::new(5), Height::new(3), conflict_block)
            .is_none());
        assert_eq!(
            collector
                .canonical_timeout_certificate(View::new(6))
                .expect("canonical timeout certificate after conflict"),
            &first
        );
    }

    #[test]
    fn authenticated_sender_and_equivocation_are_fail_closed() {
        let (keys, set) = fixture();
        let block_a = BlockId::new([0xd4; 32]);
        let block_b = BlockId::new([0xe5; 32]);
        let first = vote(&keys, &set, 0, 7, 4, block_a);
        let frame = AuthenticatedFrame {
            sender: set.validators()[1].id(),
            session: [7; 32],
            sequence: 0,
            kind: FrameKind::Vote,
            payload: encode_vote(&first),
        };
        assert!(matches!(
            decode_authenticated_consensus_frame_v0(
                &frame,
                &set,
                &ConsensusParametersV0::reference_shadow_v0()
            ),
            Err(ConsensusIngressErrorV0::SenderStatementMismatch)
        ));

        let mut collector = ConsensusCertificateCollectorV0::new(set.clone(), 8).unwrap();
        collector.admit_vote(first).unwrap();
        assert!(matches!(
            collector.admit_vote(vote(&keys, &set, 0, 7, 4, block_b)),
            Err(ConsensusIngressErrorV0::VoteEquivocation)
        ));
    }

    #[test]
    fn pruning_is_monotonic_rejects_old_replay_and_retains_live_timeout_qc() {
        let (keys, set) = fixture();
        let block = BlockId::new([0xf6; 32]);
        let mut collector = ConsensusCertificateCollectorV0::new(set.clone(), 8).unwrap();
        for index in 0..4 {
            collector
                .admit_vote(vote(&keys, &set, index, 5, 3, block))
                .unwrap();
        }
        let qc = collector
            .try_quorum_certificate(View::new(5), Height::new(3), block)
            .unwrap()
            .unwrap();
        let high_qc = QcRef::from(&qc);
        for index in 0..4 {
            collector
                .admit_timeout_vote(timeout_vote(&keys, &set, index, 6, high_qc))
                .unwrap();
        }

        collector
            .prune_before_view(View::new(6), std::iter::empty())
            .unwrap();
        assert_eq!(collector.minimum_retained_view(), View::new(6));
        assert!(collector
            .try_timeout_certificate(View::new(6))
            .unwrap()
            .is_some());
        assert!(matches!(
            collector.admit_vote(vote(&keys, &set, 4, 5, 3, block)),
            Err(ConsensusIngressErrorV0::StaleView)
        ));
        assert!(matches!(
            collector.prune_before_view(View::new(5), [qc.id()]),
            Err(ConsensusIngressErrorV0::StaleView)
        ));

        collector
            .prune_before_view(View::new(7), [qc.id()])
            .unwrap();
        assert!(collector.votes.is_empty());
        assert!(collector.timeouts.is_empty());
        assert!(collector.qc_references.contains_key(&qc.id()));
    }

    #[test]
    fn retained_view_capacity_is_topology_derived_and_bounded() {
        assert_eq!(required_pending_coordinate_capacity_v0(7, 6).unwrap(), 48);
        assert_eq!(
            required_pending_coordinate_capacity_v0(100, 6).unwrap(),
            606
        );
        assert!(required_pending_coordinate_capacity_v0(0, 6).is_err());
        assert!(required_pending_coordinate_capacity_v0(100, 41).is_err());
    }
}
