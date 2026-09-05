module anchor_view_change {
  // Bounded first-block/view-change and candidate-validation model. Both
  // GenesisQC and EpochAnchorQC are exact context-authorized, empty-signature
  // view-0 anchors. They may initialize safe-vote/high-QC state and be selected
  // by a TC, but the same explicit acceptance relations used for ordinary QCs
  // and finality reject them as certifying or finality QCs.

  type TcCandidate = {
    present: bool,
    timedOutView: int,
    referencedAnchorId: int,
    selectedAnchorId: int,
    signerCount: int,
  }

  type QcCandidate = {
    present: bool,
    qcId: int,
    view: int,
  }

  type FinalityCandidate = {
    present: bool,
    directChain: bool,
    q0: QcCandidate,
    q1: QcCandidate,
    q2: QcCandidate,
  }

  pure val VALIDATORS = 0.to(3)
  pure val QUORUM = 3

  pure val TRUSTED_GENESIS = 1
  pure val AUTHORIZED_EPOCH = 2
  pure val EPOCH_MISSING_NEW_QUORUM = 3
  pure val UNTRUSTED_GENESIS = 4
  pure val MODES = Set(
    TRUSTED_GENESIS,
    AUTHORIZED_EPOCH,
    EPOCH_MISSING_NEW_QUORUM,
    UNTRUSTED_GENESIS)

  pure val GENESIS_ANCHOR_ID = 10
  pure val EPOCH_ANCHOR_ID = 20
  pure val ORDINARY_FIRST_QC_ID = 30
  pure val ORDINARY_CHILD_QC_ID = 31
  pure val ORDINARY_GRANDCHILD_QC_ID = 32
  pure val WRONG_EMPTY_QC_ID = 99
  pure val GENESIS_FIRST_HEIGHT = 1
  pure val EPOCH_ACTIVATION_HEIGHT = 100

  pure val REJECT_UNAUTHORIZED_EMPTY_QC = 1
  pure val REJECT_MISSING_HANDOFF = 2
  pure val REJECT_WRONG_TC_ANCHOR = 3
  pure val REJECT_ANCHOR_CERTIFICATION = 4
  pure val REJECT_ANCHOR_FINALITY = 5

  pure val EMPTY_QC_CANDIDATE = {
    present: false,
    qcId: 0,
    view: 0,
  }

  pure val EMPTY_TC_CANDIDATE = {
    present: false,
    timedOutView: 0,
    referencedAnchorId: 0,
    selectedAnchorId: 0,
    signerCount: 0,
  }

  pure val EMPTY_FINALITY_CANDIDATE = {
    present: false,
    directChain: false,
    q0: EMPTY_QC_CANDIDATE,
    q1: EMPTY_QC_CANDIDATE,
    q2: EMPTY_QC_CANDIDATE,
  }

  pure def isGenesisMode(mode) =
    mode == TRUSTED_GENESIS or mode == UNTRUSTED_GENESIS

  pure def exactAnchorId(mode) =
    if (isGenesisMode(mode)) GENESIS_ANCHOR_ID else EPOCH_ANCHOR_ID

  pure def firstBlockHeight(mode) =
    if (isGenesisMode(mode)) GENESIS_FIRST_HEIGHT
    else EPOCH_ACTIVATION_HEIGHT

  pure def anchorView(_mode) = 0
  pure def anchorHeight(mode) = firstBlockHeight(mode) - 1
  pure def anchorSignatureCount(_mode) = 0

  pure def terminalOldFinal(mode) = not(isGenesisMode(mode))
  pure def oldHandoffQuorum(mode) = not(isGenesisMode(mode))
  pure def newHandoffQuorum(mode) = mode == AUTHORIZED_EPOCH

  pure def contextAuthorized(mode) =
    mode == TRUSTED_GENESIS or all {
      mode == AUTHORIZED_EPOCH,
      terminalOldFinal(mode),
      oldHandoffQuorum(mode),
      newHandoffQuorum(mode),
    }

  pure def ordinaryQcId(qcId) = Set(
    ORDINARY_FIRST_QC_ID,
    ORDINARY_CHILD_QC_ID,
    ORDINARY_GRANDCHILD_QC_ID).contains(qcId)

  pure def qcSignatureCount(mode, qcId) =
    if (qcId == exactAnchorId(mode) or qcId == WRONG_EMPTY_QC_ID) 0
    else if (ordinaryQcId(qcId)) QUORUM
    else 0

  // Both positive and negative TC actions use this exact predicate. A
  // rejection witness therefore has to present a concrete malformed candidate.
  pure def tcAcceptance(mode, candidate) = all {
    contextAuthorized(mode),
    candidate.present,
    candidate.timedOutView == 1,
    candidate.referencedAnchorId == exactAnchorId(mode),
    candidate.selectedAnchorId == exactAnchorId(mode),
    candidate.signerCount >= QUORUM,
  }

  // The boolean is the retained mutation point. Production actions always pass
  // false. The mutation lane passes true, changing this same relation so that a
  // context anchor is incorrectly granted certification power.
  pure def certifyingQcAcceptance(mode, candidate, syntheticAnchorHasPower) = all {
    contextAuthorized(mode),
    candidate.present,
    any {
      all {
        ordinaryQcId(candidate.qcId),
        candidate.view >= 1,
        qcSignatureCount(mode, candidate.qcId) >= QUORUM,
      },
      all {
        syntheticAnchorHasPower,
        candidate.qcId == exactAnchorId(mode),
        candidate.view == anchorView(mode),
      },
    },
  }

  // Finality validation calls the same certifying-QC relation for every link.
  // q0 may be an anchor only in the deliberately broken mutation lane.
  pure def finalityAcceptance(mode, candidate, syntheticAnchorHasPower) = all {
    contextAuthorized(mode),
    candidate.present,
    candidate.directChain,
    certifyingQcAcceptance(mode, candidate.q0, syntheticAnchorHasPower),
    certifyingQcAcceptance(mode, candidate.q1, syntheticAnchorHasPower),
    certifyingQcAcceptance(mode, candidate.q2, syntheticAnchorHasPower),
    any {
      candidate.q0.qcId == ORDINARY_FIRST_QC_ID,
      all {
        syntheticAnchorHasPower,
        candidate.q0.qcId == exactAnchorId(mode),
      },
    },
    candidate.q1.qcId == ORDINARY_CHILD_QC_ID,
    candidate.q2.qcId == ORDINARY_GRANDCHILD_QC_ID,
    candidate.q0.view < candidate.q1.view,
    candidate.q1.view < candidate.q2.view,
  }

  var mode: int
  var stage: int
  var currentView: int
  var initialLeaderFailed: bool
  var timeouts: Set[int]
  var timeoutAnchorId: int
  var tcSelectedAnchorId: int
  var proposalView: int
  var proposalHeight: int
  var proposalLeader: int
  var votes: Set[int]
  var ordinaryQcFormed: bool
  var finalized: bool
  var rejections: Set[int]

  var tcCandidate: TcCandidate
  var certifyingQcCandidate: QcCandidate
  var finalityCandidate: FinalityCandidate
  var acceptedCertifyingQc: QcCandidate
  var acceptedFinalityCandidate: FinalityCandidate

  action keepProtocolState = all {
    mode' = mode,
    stage' = stage,
    currentView' = currentView,
    initialLeaderFailed' = initialLeaderFailed,
    timeouts' = timeouts,
    timeoutAnchorId' = timeoutAnchorId,
    tcSelectedAnchorId' = tcSelectedAnchorId,
    proposalView' = proposalView,
    proposalHeight' = proposalHeight,
    proposalLeader' = proposalLeader,
    votes' = votes,
    ordinaryQcFormed' = ordinaryQcFormed,
    finalized' = finalized,
    rejections' = rejections,
  }

  action keepCandidateValidationState = all {
    tcCandidate' = tcCandidate,
    certifyingQcCandidate' = certifyingQcCandidate,
    finalityCandidate' = finalityCandidate,
    acceptedCertifyingQc' = acceptedCertifyingQc,
    acceptedFinalityCandidate' = acceptedFinalityCandidate,
  }

  action initMode(chosenMode) = all {
    MODES.contains(chosenMode),
    mode' = chosenMode,
    stage' = 0,
    currentView' = 1,
    initialLeaderFailed' = false,
    timeouts' = Set(),
    timeoutAnchorId' = 0,
    tcSelectedAnchorId' = 0,
    proposalView' = 0,
    proposalHeight' = 0,
    proposalLeader' = -1,
    votes' = Set(),
    ordinaryQcFormed' = false,
    finalized' = false,
    rejections' = Set(),
    tcCandidate' = EMPTY_TC_CANDIDATE,
    certifyingQcCandidate' = EMPTY_QC_CANDIDATE,
    finalityCandidate' = EMPTY_FINALITY_CANDIDATE,
    acceptedCertifyingQc' = EMPTY_QC_CANDIDATE,
    acceptedFinalityCandidate' = EMPTY_FINALITY_CANDIDATE,
  }

  action initGenesisAuthorized = initMode(TRUSTED_GENESIS)
  action initEpochAuthorized = initMode(AUTHORIZED_EPOCH)
  action initEpochMissingHandoff = initMode(EPOCH_MISSING_NEW_QUORUM)
  action initGenesisUntrusted = initMode(UNTRUSTED_GENESIS)

  action init = any {
    initGenesisAuthorized,
    initEpochAuthorized,
    initEpochMissingHandoff,
    initGenesisUntrusted,
  }

  action failInitialLeader = all {
    contextAuthorized(mode),
    stage == 0,
    currentView == 1,
    mode' = mode,
    stage' = 1,
    currentView' = currentView,
    initialLeaderFailed' = true,
    timeouts' = timeouts,
    timeoutAnchorId' = timeoutAnchorId,
    tcSelectedAnchorId' = tcSelectedAnchorId,
    proposalView' = proposalView,
    proposalHeight' = proposalHeight,
    proposalLeader' = proposalLeader,
    votes' = votes,
    ordinaryQcFormed' = ordinaryQcFormed,
    finalized' = finalized,
    rejections' = rejections,
    keepCandidateValidationState,
  }

  action collectTimeoutQuorum = all {
    contextAuthorized(mode),
    stage == 1,
    initialLeaderFailed,
    mode' = mode,
    stage' = 2,
    currentView' = currentView,
    initialLeaderFailed' = initialLeaderFailed,
    timeouts' = Set(0, 1, 2),
    timeoutAnchorId' = exactAnchorId(mode),
    tcSelectedAnchorId' = tcSelectedAnchorId,
    proposalView' = proposalView,
    proposalHeight' = proposalHeight,
    proposalLeader' = proposalLeader,
    votes' = votes,
    ordinaryQcFormed' = ordinaryQcFormed,
    finalized' = finalized,
    rejections' = rejections,
    keepCandidateValidationState,
  }

  action presentTcCandidate(selectedAnchorId) = all {
    not(tcCandidate.present),
    keepProtocolState,
    tcCandidate' = {
      present: true,
      timedOutView: 1,
      referencedAnchorId: exactAnchorId(mode),
      selectedAnchorId: selectedAnchorId,
      signerCount: timeouts.size(),
    },
    certifyingQcCandidate' = certifyingQcCandidate,
    finalityCandidate' = finalityCandidate,
    acceptedCertifyingQc' = acceptedCertifyingQc,
    acceptedFinalityCandidate' = acceptedFinalityCandidate,
  }

  action presentExactAnchorTc = all {
    contextAuthorized(mode),
    stage == 2,
    timeouts.size() >= QUORUM,
    timeoutAnchorId == exactAnchorId(mode),
    presentTcCandidate(exactAnchorId(mode)),
  }

  action presentWrongAnchorTc = all {
    contextAuthorized(mode),
    stage == 2,
    timeouts.size() >= QUORUM,
    timeoutAnchorId == exactAnchorId(mode),
    presentTcCandidate(WRONG_EMPTY_QC_ID),
  }

  action presentMissingHandoffTc = all {
    mode == EPOCH_MISSING_NEW_QUORUM,
    stage == 0,
    presentTcCandidate(exactAnchorId(mode)),
  }

  action presentUnauthorizedGenesisTc = all {
    mode == UNTRUSTED_GENESIS,
    stage == 0,
    presentTcCandidate(exactAnchorId(mode)),
  }

  action acceptAnchorTc = all {
    stage == 2,
    tcAcceptance(mode, tcCandidate),
    mode' = mode,
    stage' = 3,
    currentView' = 2,
    initialLeaderFailed' = initialLeaderFailed,
    timeouts' = timeouts,
    timeoutAnchorId' = timeoutAnchorId,
    tcSelectedAnchorId' = tcCandidate.selectedAnchorId,
    proposalView' = proposalView,
    proposalHeight' = proposalHeight,
    proposalLeader' = proposalLeader,
    votes' = votes,
    ordinaryQcFormed' = ordinaryQcFormed,
    finalized' = finalized,
    rejections' = rejections,
    keepCandidateValidationState,
  }

  // View 2's scheduled leader is validator 1. View advancement does not alter
  // the epoch's first-block/activation height.
  action acceptFirstProposalAfterTc = all {
    contextAuthorized(mode),
    stage == 3,
    currentView == 2,
    tcSelectedAnchorId == exactAnchorId(mode),
    mode' = mode,
    stage' = 4,
    currentView' = currentView,
    initialLeaderFailed' = initialLeaderFailed,
    timeouts' = timeouts,
    timeoutAnchorId' = timeoutAnchorId,
    tcSelectedAnchorId' = tcSelectedAnchorId,
    proposalView' = currentView,
    proposalHeight' = firstBlockHeight(mode),
    proposalLeader' = 1,
    votes' = votes,
    ordinaryQcFormed' = ordinaryQcFormed,
    finalized' = finalized,
    rejections' = rejections,
    keepCandidateValidationState,
  }

  // The non-faulty fast path remains valid: view 1 leader 0 may propose with
  // the exact authorized anchor and no TC.
  action acceptFirstProposalAtView1 = all {
    contextAuthorized(mode),
    stage == 0,
    currentView == 1,
    not(initialLeaderFailed),
    mode' = mode,
    stage' = 4,
    currentView' = currentView,
    initialLeaderFailed' = initialLeaderFailed,
    timeouts' = timeouts,
    timeoutAnchorId' = timeoutAnchorId,
    tcSelectedAnchorId' = tcSelectedAnchorId,
    proposalView' = 1,
    proposalHeight' = firstBlockHeight(mode),
    proposalLeader' = 0,
    votes' = votes,
    ordinaryQcFormed' = ordinaryQcFormed,
    finalized' = finalized,
    rejections' = rejections,
    keepCandidateValidationState,
  }

  action collectOrdinaryVoteQuorum = all {
    stage == 4,
    proposalView >= 1,
    mode' = mode,
    stage' = 5,
    currentView' = currentView,
    initialLeaderFailed' = initialLeaderFailed,
    timeouts' = timeouts,
    timeoutAnchorId' = timeoutAnchorId,
    tcSelectedAnchorId' = tcSelectedAnchorId,
    proposalView' = proposalView,
    proposalHeight' = proposalHeight,
    proposalLeader' = proposalLeader,
    votes' = Set(0, 1, 2),
    ordinaryQcFormed' = ordinaryQcFormed,
    finalized' = finalized,
    rejections' = rejections,
    keepCandidateValidationState,
  }

  action formOrdinaryFirstBlockQc = {
    val candidate = {
      present: true,
      qcId: ORDINARY_FIRST_QC_ID,
      view: proposalView,
    }
    all {
      stage == 5,
      votes.size() >= QUORUM,
      certifyingQcAcceptance(mode, candidate, false),
      mode' = mode,
      stage' = 6,
      currentView' = currentView,
      initialLeaderFailed' = initialLeaderFailed,
      timeouts' = timeouts,
      timeoutAnchorId' = timeoutAnchorId,
      tcSelectedAnchorId' = tcSelectedAnchorId,
      proposalView' = proposalView,
      proposalHeight' = proposalHeight,
      proposalLeader' = proposalLeader,
      votes' = votes,
      ordinaryQcFormed' = true,
      finalized' = finalized,
      rejections' = rejections,
      tcCandidate' = tcCandidate,
      certifyingQcCandidate' = candidate,
      finalityCandidate' = finalityCandidate,
      acceptedCertifyingQc' = candidate,
      acceptedFinalityCandidate' = acceptedFinalityCandidate,
    }
  }

  action presentCertifyingQcCandidate(qcId, view) = all {
    not(certifyingQcCandidate.present),
    keepProtocolState,
    tcCandidate' = tcCandidate,
    certifyingQcCandidate' = { present: true, qcId: qcId, view: view },
    finalityCandidate' = finalityCandidate,
    acceptedCertifyingQc' = acceptedCertifyingQc,
    acceptedFinalityCandidate' = acceptedFinalityCandidate,
  }

  action presentValidCertifyingQc = all {
    contextAuthorized(mode),
    presentCertifyingQcCandidate(ORDINARY_FIRST_QC_ID, 1),
  }

  action presentWrongEmptyCertifyingQc =
    presentCertifyingQcCandidate(WRONG_EMPTY_QC_ID, 0)

  action presentAnchorCertifyingQc =
    presentCertifyingQcCandidate(exactAnchorId(mode), anchorView(mode))

  action acceptCertifyingQcCandidate = all {
    certifyingQcAcceptance(mode, certifyingQcCandidate, false),
    keepProtocolState,
    tcCandidate' = tcCandidate,
    certifyingQcCandidate' = certifyingQcCandidate,
    finalityCandidate' = finalityCandidate,
    acceptedCertifyingQc' = certifyingQcCandidate,
    acceptedFinalityCandidate' = acceptedFinalityCandidate,
  }

  action presentFinalityCandidate(candidate) = all {
    not(finalityCandidate.present),
    keepProtocolState,
    tcCandidate' = tcCandidate,
    certifyingQcCandidate' = certifyingQcCandidate,
    finalityCandidate' = candidate,
    acceptedCertifyingQc' = acceptedCertifyingQc,
    acceptedFinalityCandidate' = acceptedFinalityCandidate,
  }

  action presentValidFinality =
    presentFinalityCandidate({
      present: true,
      directChain: true,
      q0: { present: true, qcId: ORDINARY_FIRST_QC_ID, view: 1 },
      q1: { present: true, qcId: ORDINARY_CHILD_QC_ID, view: 2 },
      q2: { present: true, qcId: ORDINARY_GRANDCHILD_QC_ID, view: 3 },
    })

  action presentAnchorFinality =
    presentFinalityCandidate({
      present: true,
      directChain: true,
      q0: {
        present: true,
        qcId: exactAnchorId(mode),
        view: anchorView(mode),
      },
      q1: { present: true, qcId: ORDINARY_CHILD_QC_ID, view: 2 },
      q2: { present: true, qcId: ORDINARY_GRANDCHILD_QC_ID, view: 3 },
    })

  action acceptFinalityCandidate = all {
    finalityAcceptance(mode, finalityCandidate, false),
    mode' = mode,
    stage' = stage,
    currentView' = currentView,
    initialLeaderFailed' = initialLeaderFailed,
    timeouts' = timeouts,
    timeoutAnchorId' = timeoutAnchorId,
    tcSelectedAnchorId' = tcSelectedAnchorId,
    proposalView' = proposalView,
    proposalHeight' = proposalHeight,
    proposalLeader' = proposalLeader,
    votes' = votes,
    ordinaryQcFormed' = ordinaryQcFormed,
    finalized' = true,
    rejections' = rejections,
    tcCandidate' = tcCandidate,
    certifyingQcCandidate' = certifyingQcCandidate,
    finalityCandidate' = finalityCandidate,
    acceptedCertifyingQc' = acceptedCertifyingQc,
    acceptedFinalityCandidate' = finalityCandidate,
  }

  action recordRejection(reason) = all {
    mode' = mode,
    stage' = stage,
    currentView' = currentView,
    initialLeaderFailed' = initialLeaderFailed,
    timeouts' = timeouts,
    timeoutAnchorId' = timeoutAnchorId,
    tcSelectedAnchorId' = tcSelectedAnchorId,
    proposalView' = proposalView,
    proposalHeight' = proposalHeight,
    proposalLeader' = proposalLeader,
    votes' = votes,
    ordinaryQcFormed' = ordinaryQcFormed,
    finalized' = finalized,
    rejections' = rejections.union(Set(reason)),
    keepCandidateValidationState,
  }

  action rejectWrongAnchorTc = all {
    tcCandidate.present,
    tcCandidate.selectedAnchorId == WRONG_EMPTY_QC_ID,
    not(tcAcceptance(mode, tcCandidate)),
    recordRejection(REJECT_WRONG_TC_ANCHOR),
  }

  action rejectMissingHandoffAnchor = all {
    mode == EPOCH_MISSING_NEW_QUORUM,
    tcCandidate.present,
    not(tcAcceptance(mode, tcCandidate)),
    recordRejection(REJECT_MISSING_HANDOFF),
  }

  action rejectUnauthorizedContextAnchor = all {
    mode == UNTRUSTED_GENESIS,
    tcCandidate.present,
    not(tcAcceptance(mode, tcCandidate)),
    recordRejection(REJECT_UNAUTHORIZED_EMPTY_QC),
  }

  action rejectUnauthorizedEmptyQc = all {
    certifyingQcCandidate.present,
    certifyingQcCandidate.qcId == WRONG_EMPTY_QC_ID,
    not(certifyingQcAcceptance(mode, certifyingQcCandidate, false)),
    recordRejection(REJECT_UNAUTHORIZED_EMPTY_QC),
  }

  action rejectAnchorAsCertifyingQc = all {
    certifyingQcCandidate.present,
    certifyingQcCandidate.qcId == exactAnchorId(mode),
    not(certifyingQcAcceptance(mode, certifyingQcCandidate, false)),
    recordRejection(REJECT_ANCHOR_CERTIFICATION),
  }

  action rejectAnchorInFinalityProof = all {
    finalityCandidate.present,
    finalityCandidate.q0.qcId == exactAnchorId(mode),
    not(finalityAcceptance(mode, finalityCandidate, false)),
    recordRejection(REJECT_ANCHOR_FINALITY),
  }

  // These mutation actions deliberately enable the one mutation switch in the
  // same relations used above. They are excluded from the production step.
  action acceptCertifyingQcCandidateMutant = all {
    certifyingQcAcceptance(mode, certifyingQcCandidate, true), // MUTANT
    keepProtocolState,
    tcCandidate' = tcCandidate,
    certifyingQcCandidate' = certifyingQcCandidate,
    finalityCandidate' = finalityCandidate,
    acceptedCertifyingQc' = certifyingQcCandidate,
    acceptedFinalityCandidate' = acceptedFinalityCandidate,
  }

  action acceptFinalityCandidateMutant = all {
    finalityAcceptance(mode, finalityCandidate, true), // MUTANT
    mode' = mode,
    stage' = stage,
    currentView' = currentView,
    initialLeaderFailed' = initialLeaderFailed,
    timeouts' = timeouts,
    timeoutAnchorId' = timeoutAnchorId,
    tcSelectedAnchorId' = tcSelectedAnchorId,
    proposalView' = proposalView,
    proposalHeight' = proposalHeight,
    proposalLeader' = proposalLeader,
    votes' = votes,
    ordinaryQcFormed' = ordinaryQcFormed,
    finalized' = true,
    rejections' = rejections,
    tcCandidate' = tcCandidate,
    certifyingQcCandidate' = certifyingQcCandidate,
    finalityCandidate' = finalityCandidate,
    acceptedCertifyingQc' = acceptedCertifyingQc,
    acceptedFinalityCandidate' = finalityCandidate,
  }

  action authorizedViewChangeStep = any {
    failInitialLeader,
    collectTimeoutQuorum,
    presentExactAnchorTc,
    acceptAnchorTc,
    acceptFirstProposalAfterTc,
    collectOrdinaryVoteQuorum,
    formOrdinaryFirstBlockQc,
  }

  action wrongTcRejectionStep = any {
    failInitialLeader,
    collectTimeoutQuorum,
    presentWrongAnchorTc,
    rejectWrongAnchorTc,
  }

  action missingHandoffRejectionStep = any {
    presentMissingHandoffTc,
    rejectMissingHandoffAnchor,
  }

  action unauthorizedContextRejectionStep = any {
    presentUnauthorizedGenesisTc,
    rejectUnauthorizedContextAnchor,
  }

  action wrongEmptyQcRejectionStep = any {
    presentWrongEmptyCertifyingQc,
    rejectUnauthorizedEmptyQc,
  }

  action anchorCertificationRejectionStep = any {
    presentAnchorCertifyingQc,
    rejectAnchorAsCertifyingQc,
  }

  action anchorFinalityRejectionStep = any {
    presentAnchorFinality,
    rejectAnchorInFinalityProof,
  }

  action certifyingQcAcceptanceStep = any {
    presentValidCertifyingQc,
    acceptCertifyingQcCandidate,
  }

  action finalityAcceptanceStep = any {
    presentValidFinality,
    acceptFinalityCandidate,
  }

  action anchorCertificationMutantStep = any {
    presentAnchorCertifyingQc,
    acceptCertifyingQcCandidateMutant,
  }

  action anchorFinalityMutantStep = any {
    presentAnchorFinality,
    acceptFinalityCandidateMutant,
  }

  action step = any {
    authorizedViewChangeStep,
    acceptFirstProposalAtView1,
    presentWrongAnchorTc,
    rejectWrongAnchorTc,
    presentMissingHandoffTc,
    rejectMissingHandoffAnchor,
    presentUnauthorizedGenesisTc,
    rejectUnauthorizedContextAnchor,
    presentWrongEmptyCertifyingQc,
    rejectUnauthorizedEmptyQc,
    presentAnchorCertifyingQc,
    rejectAnchorAsCertifyingQc,
    presentAnchorFinality,
    rejectAnchorInFinalityProof,
    presentValidCertifyingQc,
    acceptCertifyingQcCandidate,
    presentValidFinality,
    acceptFinalityCandidate,
  }

  val anchorsAreViewZeroAndUnsigned =
    MODES.forall(candidateMode => all {
      anchorView(candidateMode) == 0,
      anchorHeight(candidateMode) + 1 == firstBlockHeight(candidateMode),
      anchorSignatureCount(candidateMode) == 0,
    })

  val onlyContextAuthorizedAnchorsCanProgress =
    stage == 0 or contextAuthorized(mode)

  val timeoutQuorumReferencesExactAnchor =
    timeouts.size() < QUORUM or timeoutAnchorId == exactAnchorId(mode)

  val tcRequiresQuorumAndExactAnchor =
    tcSelectedAnchorId == 0 or all {
      tcAcceptance(mode, tcCandidate),
      tcSelectedAnchorId == tcCandidate.selectedAnchorId,
      currentView == 2,
    }

  val firstProposalKeepsActivationHeight =
    proposalView == 0 or proposalHeight == firstBlockHeight(mode)

  val skippedViewProposalRequiresExactTc =
    proposalView <= 1 or all {
      proposalView == 2,
      tcSelectedAnchorId == exactAnchorId(mode),
      timeouts.size() >= QUORUM,
      tcAcceptance(mode, tcCandidate),
    }

  val proposalUsesCorrectLeaderForActualView =
    proposalView == 0
      or (proposalView == 1 and proposalLeader == 0)
      or (proposalView == 2 and proposalLeader == 1)

  val ordinaryQcRequiresOrdinaryVoteQuorum =
    not(ordinaryQcFormed) or all {
      proposalView >= 1,
      votes.size() >= QUORUM,
      proposalHeight == firstBlockHeight(mode),
      acceptedCertifyingQc.qcId == ORDINARY_FIRST_QC_ID,
      certifyingQcAcceptance(mode, acceptedCertifyingQc, false),
    }

  val candidateValidationFailsClosed = all {
    not(acceptedCertifyingQc.present)
      or certifyingQcAcceptance(mode, acceptedCertifyingQc, false),
    not(acceptedFinalityCandidate.present)
      or finalityAcceptance(mode, acceptedFinalityCandidate, false),
    not(finalized) or acceptedFinalityCandidate.present,
  }

  val anchorHasNoCertificationOrFinalityPower = all {
    not(acceptedCertifyingQc.present)
      or acceptedCertifyingQc.qcId != exactAnchorId(mode),
    not(acceptedFinalityCandidate.present) or all {
      acceptedFinalityCandidate.q0.qcId != exactAnchorId(mode),
      acceptedFinalityCandidate.q1.qcId != exactAnchorId(mode),
      acceptedFinalityCandidate.q2.qcId != exactAnchorId(mode),
    },
    candidateValidationFailsClosed,
  }

  val missingHandoffAuthorizationCannotProgress =
    mode != EPOCH_MISSING_NEW_QUORUM or all {
      not(contextAuthorized(mode)),
      stage == 0,
      tcSelectedAnchorId == 0,
      proposalView == 0,
      not(ordinaryQcFormed),
      not(finalized),
      not(acceptedCertifyingQc.present),
      not(acceptedFinalityCandidate.present),
    }

  val untrustedGenesisCannotProgress =
    mode != UNTRUSTED_GENESIS or all {
      not(contextAuthorized(mode)),
      stage == 0,
      proposalView == 0,
      not(ordinaryQcFormed),
      not(finalized),
      not(acceptedCertifyingQc.present),
      not(acceptedFinalityCandidate.present),
    }

  val anchorViewChangeSafety = all {
    anchorsAreViewZeroAndUnsigned,
    onlyContextAuthorizedAnchorsCanProgress,
    timeoutQuorumReferencesExactAnchor,
    tcRequiresQuorumAndExactAnchor,
    firstProposalKeepsActivationHeight,
    skippedViewProposalRequiresExactTc,
    proposalUsesCorrectLeaderForActualView,
    ordinaryQcRequiresOrdinaryVoteQuorum,
    candidateValidationFailsClosed,
    anchorHasNoCertificationOrFinalityPower,
    missingHandoffAuthorizationCannotProgress,
    untrustedGenesisCannotProgress,
  }

  // Bounded reachability targets used by CI.
  val authorizedViewChangeNotReached =
    not(all {
      ordinaryQcFormed,
      proposalView == 2,
      currentView == 2,
      proposalHeight == firstBlockHeight(mode),
      tcSelectedAnchorId == exactAnchorId(mode),
      votes.size() >= QUORUM,
      not(finalized),
    })

  val validCertifyingQcAcceptanceNotReached =
    not(all {
      acceptedCertifyingQc.present,
      certifyingQcAcceptance(mode, acceptedCertifyingQc, false),
    })

  val validFinalityAcceptanceNotReached =
    not(all {
      finalized,
      acceptedFinalityCandidate.present,
      finalityAcceptance(mode, acceptedFinalityCandidate, false),
    })

  val wrongTcRejectionNotReached =
    not(rejections.contains(REJECT_WRONG_TC_ANCHOR))

  val missingHandoffRejectionNotReached =
    not(rejections.contains(REJECT_MISSING_HANDOFF))

  val unauthorizedEmptyRejectionNotReached =
    not(rejections.contains(REJECT_UNAUTHORIZED_EMPTY_QC))

  val anchorCertificationRejectionNotReached =
    not(rejections.contains(REJECT_ANCHOR_CERTIFICATION))

  val anchorFinalityRejectionNotReached =
    not(rejections.contains(REJECT_ANCHOR_FINALITY))
}
