module light_client_handoff {
  // Bounded light-client model for one authenticated epoch transition. The
  // client starts at epoch 1 with a trusting period of two epochs. Epoch 3 is
  // exactly on the inclusive boundary; epoch 4 is the first rejected epoch.
  //
  // Set 2 is the honest candidate set and set 3 represents an attacker-owned
  // set that may produce a perfectly valid self-signed chain. A self-signed
  // chain is evidence of finality only after the old finalized checkpoint
  // committed the set and both old/new handoff quorums authorized the same
  // (target epoch, set id) link.

  type EpochLink = { targetEpoch: int, setId: int }
  type HandoffVote = { validator: int, targetEpoch: int, setId: int }

  pure val VALIDATORS = 0.to(11)
  pure val OLD_SET = Set(0, 1, 2, 3)
  pure val NEW_SET_2 = Set(4, 5, 6, 7)
  pure val NEW_SET_3 = Set(8, 9, 10, 11)
  pure val TARGET_EPOCHS = Set(2, 3, 4)
  pure val SET_IDS = Set(2, 3)
  pure val TRUSTED_EPOCH = 1
  pure val TRUSTING_PERIOD_EPOCHS = 2
  pure val QUORUM = 3
  pure val BOUNDARY_LINK = { targetEpoch: 3, setId: 2 }

  pure def validatorsFor(setId) =
    if (setId == 2) NEW_SET_2 else NEW_SET_3

  pure def isCandidate(link) =
    TARGET_EPOCHS.contains(link.targetEpoch) and SET_IDS.contains(link.setId)

  pure def withinTrustingPeriod(targetEpoch) =
    targetEpoch >= TRUSTED_EPOCH
      and targetEpoch - TRUSTED_EPOCH <= TRUSTING_PERIOD_EPOCHS

  var finalizedOldCheckpoints: Set[int]
  var nextSetCommitments: Set[EpochLink]
  var oldHandoffVotes: Set[HandoffVote]
  var newHandoffVotes: Set[HandoffVote]
  var finalizedNewEpochChains: Set[EpochLink]
  var freshnessKnown: bool
  var acceptedLinks: Set[EpochLink]

  def oldVoters(link) =
    oldHandoffVotes
      .filter(vote =>
        vote.targetEpoch == link.targetEpoch and vote.setId == link.setId)
      .map(vote => vote.validator)

  def newVoters(link) =
    newHandoffVotes
      .filter(vote =>
        vote.targetEpoch == link.targetEpoch and vote.setId == link.setId)
      .map(vote => vote.validator)

  def hasOldQuorum(link) = oldVoters(link).size() >= QUORUM
  def hasNewQuorum(link) = newVoters(link).size() >= QUORUM

  def checkpointCommitted(link) =
    finalizedOldCheckpoints.contains(link.targetEpoch - 1)
      and nextSetCommitments.contains(link)

  def hasAuthorizedProof(link) = all {
    checkpointCommitted(link),
    hasOldQuorum(link),
    hasNewQuorum(link),
    finalizedNewEpochChains.contains(link),
  }

  action init = all {
    finalizedOldCheckpoints' = Set(),
    nextSetCommitments' = Set(),
    oldHandoffVotes' = Set(),
    newHandoffVotes' = Set(),
    finalizedNewEpochChains' = Set(),
    freshnessKnown' = true,
    acceptedLinks' = Set(),
  }

  // The next-set commitment is part of the finalized old checkpoint. Exactly
  // one set id may be committed for a target epoch in this bounded model.
  action finalizeCheckpoint(targetEpoch, setId) = {
    val link = { targetEpoch: targetEpoch, setId: setId }
    all {
      acceptedLinks.size() == 0,
      isCandidate(link),
      not(nextSetCommitments.exists(existing =>
        existing.targetEpoch == targetEpoch)),
      finalizedOldCheckpoints' =
        finalizedOldCheckpoints.union(Set(targetEpoch - 1)),
      nextSetCommitments' = nextSetCommitments.union(Set(link)),
      oldHandoffVotes' = oldHandoffVotes,
      newHandoffVotes' = newHandoffVotes,
      finalizedNewEpochChains' = finalizedNewEpochChains,
      freshnessKnown' = freshnessKnown,
      acceptedLinks' = acceptedLinks,
    }
  }

  action signOld(validator, targetEpoch, setId) = {
    val link = { targetEpoch: targetEpoch, setId: setId }
    all {
      acceptedLinks.size() == 0,
      OLD_SET.contains(validator),
      isCandidate(link),
      checkpointCommitted(link),
      finalizedOldCheckpoints' = finalizedOldCheckpoints,
      nextSetCommitments' = nextSetCommitments,
      oldHandoffVotes' = oldHandoffVotes.union(Set({
        validator: validator,
        targetEpoch: targetEpoch,
        setId: setId,
      })),
      newHandoffVotes' = newHandoffVotes,
      finalizedNewEpochChains' = finalizedNewEpochChains,
      freshnessKnown' = freshnessKnown,
      acceptedLinks' = acceptedLinks,
    }
  }

  // A candidate set can sign itself even when it was never committed. This is
  // deliberately allowed in the environment: the verifier, not the network,
  // must reject that otherwise valid-looking long-range history.
  action signNew(validator, targetEpoch, setId) = {
    val link = { targetEpoch: targetEpoch, setId: setId }
    all {
      acceptedLinks.size() == 0,
      isCandidate(link),
      validatorsFor(setId).contains(validator),
      finalizedOldCheckpoints' = finalizedOldCheckpoints,
      nextSetCommitments' = nextSetCommitments,
      oldHandoffVotes' = oldHandoffVotes,
      newHandoffVotes' = newHandoffVotes.union(Set({
        validator: validator,
        targetEpoch: targetEpoch,
        setId: setId,
      })),
      finalizedNewEpochChains' = finalizedNewEpochChains,
      freshnessKnown' = freshnessKnown,
      acceptedLinks' = acceptedLinks,
    }
  }

  // This abstracts a valid epoch-local three-chain under the candidate set.
  // It is useful evidence, but is not authority to select that set.
  action finalizeCandidateChain(targetEpoch, setId) = {
    val link = { targetEpoch: targetEpoch, setId: setId }
    all {
      acceptedLinks.size() == 0,
      isCandidate(link),
      hasNewQuorum(link),
      finalizedOldCheckpoints' = finalizedOldCheckpoints,
      nextSetCommitments' = nextSetCommitments,
      oldHandoffVotes' = oldHandoffVotes,
      newHandoffVotes' = newHandoffVotes,
      finalizedNewEpochChains' = finalizedNewEpochChains.union(Set(link)),
      freshnessKnown' = freshnessKnown,
      acceptedLinks' = acceptedLinks,
    }
  }

  action markFreshnessUncertain = all {
    acceptedLinks.size() == 0,
    finalizedOldCheckpoints' = finalizedOldCheckpoints,
    nextSetCommitments' = nextSetCommitments,
    oldHandoffVotes' = oldHandoffVotes,
    newHandoffVotes' = newHandoffVotes,
    finalizedNewEpochChains' = finalizedNewEpochChains,
    freshnessKnown' = false,
    acceptedLinks' = acceptedLinks,
  }

  action accept(targetEpoch, setId) = {
    val link = { targetEpoch: targetEpoch, setId: setId }
    all {
      acceptedLinks.size() == 0,
      isCandidate(link),
      freshnessKnown,
      withinTrustingPeriod(targetEpoch),
      hasAuthorizedProof(link),
      finalizedOldCheckpoints' = finalizedOldCheckpoints,
      nextSetCommitments' = nextSetCommitments,
      oldHandoffVotes' = oldHandoffVotes,
      newHandoffVotes' = newHandoffVotes,
      finalizedNewEpochChains' = finalizedNewEpochChains,
      freshnessKnown' = freshnessKnown,
      acceptedLinks' = Set(link),
    }
  }

  // A coverage macro for a complete, valid proof at the exact inclusive
  // trusting-period boundary. Keeping this transition explicit prevents the
  // safety runs from passing only because the granular random scheduler did
  // not happen to assemble all seven signatures and finality evidence.
  action acceptCompleteBoundaryProof = all {
    acceptedLinks.size() == 0,
    freshnessKnown,
    not(nextSetCommitments.exists(existing =>
      existing.targetEpoch == BOUNDARY_LINK.targetEpoch)),
    withinTrustingPeriod(BOUNDARY_LINK.targetEpoch),
    finalizedOldCheckpoints' =
      finalizedOldCheckpoints.union(Set(BOUNDARY_LINK.targetEpoch - 1)),
    nextSetCommitments' = nextSetCommitments.union(Set(BOUNDARY_LINK)),
    oldHandoffVotes' = oldHandoffVotes.union(Set(
      { validator: 0, targetEpoch: 3, setId: 2 },
      { validator: 1, targetEpoch: 3, setId: 2 },
      { validator: 2, targetEpoch: 3, setId: 2 })),
    newHandoffVotes' = newHandoffVotes.union(Set(
      { validator: 4, targetEpoch: 3, setId: 2 },
      { validator: 5, targetEpoch: 3, setId: 2 },
      { validator: 6, targetEpoch: 3, setId: 2 })),
    finalizedNewEpochChains' =
      finalizedNewEpochChains.union(Set(BOUNDARY_LINK)),
    freshnessKnown' = freshnessKnown,
    acceptedLinks' = Set(BOUNDARY_LINK),
  }

  action step = {
    nondet validator = VALIDATORS.oneOf()
    nondet targetEpoch = TARGET_EPOCHS.oneOf()
    nondet setId = SET_IDS.oneOf()
    any {
      finalizeCheckpoint(targetEpoch, setId),
      signOld(validator, targetEpoch, setId),
      signNew(validator, targetEpoch, setId),
      finalizeCandidateChain(targetEpoch, setId),
      markFreshnessUncertain,
      accept(targetEpoch, setId),
      acceptCompleteBoundaryProof,
    }
  }

  /// Accepted sets are descendants of a finalized old checkpoint commitment
  /// and carry independent old/new handoff quorums over the same link.
  val acceptedOnlyCommittedJointTransition =
    acceptedLinks.forall(link => hasAuthorizedProof(link))

  /// Checked epoch distance is inclusive at the configured boundary.
  val acceptedWithinTrustingPeriod =
    acceptedLinks.forall(link => withinTrustingPeriod(link.targetEpoch))

  /// If freshness is uncertain, ordinary peer updates fail closed.
  val uncertainFreshnessFailsClosed =
    freshnessKnown or acceptedLinks.size() == 0

  /// Epoch 3 is exactly allowed (3 - 1 == 2); epoch 4 is rejected.
  val trustingPeriodBoundary = all {
    withinTrustingPeriod(3),
    not(withinTrustingPeriod(4)),
  }

  val atMostOneAcceptedLink = acceptedLinks.size() <= 1
}
