module upgrade_atomicity {
  // Bounded atomic-upgrade model. Plans 1 and 2 are supported but conflict at
  // the same activation height by carrying different parameter hashes. Plan 3
  // targets an unsupported protocol version. Old and new validator sets are
  // disjoint here so their quorum obligations remain independently visible.

  type HandoffVote = { validator: int, plan: int }
  type ActiveConfiguration = {
    height: int,
    protocolVersion: int,
    parameterHash: int,
  }

  pure val VALIDATORS = 0.to(7)
  pure val OLD_SET = Set(0, 1, 2, 3)
  pure val NEW_SET = Set(4, 5, 6, 7)
  pure val OLD_BYZANTINE = Set(0)
  pure val NEW_BYZANTINE = Set(4)
  pure val OLD_HONEST = Set(1, 2, 3)
  pure val NEW_HONEST = Set(5, 6, 7)
  pure val PLANS = Set(1, 2, 3)
  pure val QUORUM = 3
  pure val PRE_NOTICE_HEIGHT = 8
  pure val NOTICE_HEIGHT = 9
  pure val CHECKPOINT_HEIGHT = 10
  pure val SEAL_1_HEIGHT = 11
  pure val SEAL_2_HEIGHT = 12
  pure val ACTIVATION_HEIGHT = 13
  pure val LOCAL_SUPPORTED_VERSIONS = Set(1, 2)

  pure def targetProtocolVersion(plan) = if (plan == 3) 3 else 2

  pure def targetParameterHash(plan) =
    if (plan == 1) 101 else if (plan == 2) 202 else 303

  pure def planActivationHeight(_plan) = ACTIVATION_HEIGHT

  // Honest validators support the current version and the frozen v2 upgrade.
  // The two Byzantine validators may sign arbitrary versions, but their one
  // vote per set is insufficient to form either quorum for unsupported v3.
  pure def supportedVersions(validator) =
    if (OLD_HONEST.contains(validator) or NEW_HONEST.contains(validator))
    Set(1, 2)
    else Set(1)

  pure def activeConfigurationFor(plan) = {
    height: planActivationHeight(plan),
    protocolVersion: targetProtocolVersion(plan),
    parameterHash: targetParameterHash(plan),
  }

  var finalizedHeight: int
  var finalizedNotices: Set[int]
  var selectedPlan: int
  var checkpointFinalPlan: int
  var seal1FinalPlan: int
  var seal2FinalPlan: int
  var oldVotes: Set[HandoffVote]
  var newVotes: Set[HandoffVote]
  var activePlan: int
  var activeConfigurations: Set[ActiveConfiguration]
  var firstNewBlockPlan: int
  var halted: bool

  def oldVoters(plan) =
    oldVotes
      .filter(vote => vote.plan == plan)
      .map(vote => vote.validator)

  def newVoters(plan) =
    newVotes
      .filter(vote => vote.plan == plan)
      .map(vote => vote.validator)

  def hasOldQuorum(plan) = oldVoters(plan).size() >= QUORUM
  def hasNewQuorum(plan) = newVoters(plan).size() >= QUORUM

  def activationEvidence(plan) = all {
    finalizedNotices == Set(plan),
    selectedPlan == plan,
    checkpointFinalPlan == plan,
    seal1FinalPlan == plan,
    seal2FinalPlan == plan,
    hasOldQuorum(plan),
    hasNewQuorum(plan),
    LOCAL_SUPPORTED_VERSIONS.contains(targetProtocolVersion(plan)),
    finalizedHeight == planActivationHeight(plan),
    firstNewBlockPlan == plan,
    activeConfigurations.contains(activeConfigurationFor(plan)),
  }

  action init = all {
    finalizedHeight' = PRE_NOTICE_HEIGHT,
    finalizedNotices' = Set(),
    selectedPlan' = 0,
    checkpointFinalPlan' = 0,
    seal1FinalPlan' = 0,
    seal2FinalPlan' = 0,
    oldVotes' = Set(),
    newVotes' = Set(),
    activePlan' = 0,
    activeConfigurations' = Set(),
    firstNewBlockPlan' = 0,
    halted' = false,
  }

  action finalizeUpgradePlanNotice(plan) = all {
    not(halted),
    activePlan == 0,
    PLANS.contains(plan),
    finalizedHeight == PRE_NOTICE_HEIGHT,
    finalizedNotices.size() == 0,
    finalizedHeight' = NOTICE_HEIGHT,
    finalizedNotices' = Set(plan),
    selectedPlan' = plan,
    checkpointFinalPlan' = checkpointFinalPlan,
    seal1FinalPlan' = seal1FinalPlan,
    seal2FinalPlan' = seal2FinalPlan,
    oldVotes' = oldVotes,
    newVotes' = newVotes,
    activePlan' = activePlan,
    activeConfigurations' = activeConfigurations,
    firstNewBlockPlan' = firstNewBlockPlan,
    halted' = halted,
  }

  // A second finalized plan for the same bounded activation height is treated
  // as conflicting safety evidence. It is retained and the receiver halts
  // before any further milestone or activation can occur.
  action observeConflictingFinalizedPlan(plan) = all {
    not(halted),
    activePlan == 0,
    PLANS.contains(plan),
    selectedPlan != 0,
    plan != selectedPlan,
    planActivationHeight(plan) == planActivationHeight(selectedPlan),
    finalizedHeight' = finalizedHeight,
    finalizedNotices' = finalizedNotices.union(Set(plan)),
    selectedPlan' = selectedPlan,
    checkpointFinalPlan' = checkpointFinalPlan,
    seal1FinalPlan' = seal1FinalPlan,
    seal2FinalPlan' = seal2FinalPlan,
    oldVotes' = oldVotes,
    newVotes' = newVotes,
    activePlan' = activePlan,
    activeConfigurations' = activeConfigurations,
    firstNewBlockPlan' = firstNewBlockPlan,
    halted' = true,
  }

  action finalizeCheckpoint(plan) = all {
    not(halted),
    activePlan == 0,
    selectedPlan == plan,
    finalizedNotices == Set(plan),
    finalizedHeight == NOTICE_HEIGHT,
    checkpointFinalPlan == 0,
    finalizedHeight' = CHECKPOINT_HEIGHT,
    finalizedNotices' = finalizedNotices,
    selectedPlan' = selectedPlan,
    checkpointFinalPlan' = plan,
    seal1FinalPlan' = seal1FinalPlan,
    seal2FinalPlan' = seal2FinalPlan,
    oldVotes' = oldVotes,
    newVotes' = newVotes,
    activePlan' = activePlan,
    activeConfigurations' = activeConfigurations,
    firstNewBlockPlan' = firstNewBlockPlan,
    halted' = halted,
  }

  action finalizeSeal1(plan) = all {
    not(halted),
    activePlan == 0,
    selectedPlan == plan,
    checkpointFinalPlan == plan,
    finalizedHeight == CHECKPOINT_HEIGHT,
    seal1FinalPlan == 0,
    finalizedHeight' = SEAL_1_HEIGHT,
    finalizedNotices' = finalizedNotices,
    selectedPlan' = selectedPlan,
    checkpointFinalPlan' = checkpointFinalPlan,
    seal1FinalPlan' = plan,
    seal2FinalPlan' = seal2FinalPlan,
    oldVotes' = oldVotes,
    newVotes' = newVotes,
    activePlan' = activePlan,
    activeConfigurations' = activeConfigurations,
    firstNewBlockPlan' = firstNewBlockPlan,
    halted' = halted,
  }

  action finalizeSeal2(plan) = all {
    not(halted),
    activePlan == 0,
    selectedPlan == plan,
    seal1FinalPlan == plan,
    finalizedHeight == SEAL_1_HEIGHT,
    seal2FinalPlan == 0,
    finalizedHeight' = SEAL_2_HEIGHT,
    finalizedNotices' = finalizedNotices,
    selectedPlan' = selectedPlan,
    checkpointFinalPlan' = checkpointFinalPlan,
    seal1FinalPlan' = seal1FinalPlan,
    seal2FinalPlan' = plan,
    oldVotes' = oldVotes,
    newVotes' = newVotes,
    activePlan' = activePlan,
    activeConfigurations' = activeConfigurations,
    firstNewBlockPlan' = firstNewBlockPlan,
    halted' = halted,
  }

  action signOldHandoff(validator, plan) = all {
    not(halted),
    activePlan == 0,
    selectedPlan == plan,
    seal2FinalPlan == plan,
    finalizedHeight == SEAL_2_HEIGHT,
    OLD_SET.contains(validator),
    OLD_BYZANTINE.contains(validator)
      or supportedVersions(validator).contains(targetProtocolVersion(plan)),
    OLD_BYZANTINE.contains(validator)
      or not(oldVotes.exists(vote =>
        vote.validator == validator and vote.plan != plan)),
    finalizedHeight' = finalizedHeight,
    finalizedNotices' = finalizedNotices,
    selectedPlan' = selectedPlan,
    checkpointFinalPlan' = checkpointFinalPlan,
    seal1FinalPlan' = seal1FinalPlan,
    seal2FinalPlan' = seal2FinalPlan,
    oldVotes' = oldVotes.union(Set({ validator: validator, plan: plan })),
    newVotes' = newVotes,
    activePlan' = activePlan,
    activeConfigurations' = activeConfigurations,
    firstNewBlockPlan' = firstNewBlockPlan,
    halted' = halted,
  }

  action signNewHandoff(validator, plan) = all {
    not(halted),
    activePlan == 0,
    selectedPlan == plan,
    seal2FinalPlan == plan,
    finalizedHeight == SEAL_2_HEIGHT,
    NEW_SET.contains(validator),
    NEW_BYZANTINE.contains(validator)
      or supportedVersions(validator).contains(targetProtocolVersion(plan)),
    NEW_BYZANTINE.contains(validator)
      or not(newVotes.exists(vote =>
        vote.validator == validator and vote.plan != plan)),
    finalizedHeight' = finalizedHeight,
    finalizedNotices' = finalizedNotices,
    selectedPlan' = selectedPlan,
    checkpointFinalPlan' = checkpointFinalPlan,
    seal1FinalPlan' = seal1FinalPlan,
    seal2FinalPlan' = seal2FinalPlan,
    oldVotes' = oldVotes,
    newVotes' = newVotes.union(Set({ validator: validator, plan: plan })),
    activePlan' = activePlan,
    activeConfigurations' = activeConfigurations,
    firstNewBlockPlan' = firstNewBlockPlan,
    halted' = halted,
  }

  // Activation and the first new-protocol block are one state transition. No
  // intermediate state exposes the new protocol or parameter hash before its
  // declared height and complete authorization proof.
  action activateAndFinalizeFirstNewBlock(plan) = all {
    not(halted),
    activePlan == 0,
    activeConfigurations.size() == 0,
    firstNewBlockPlan == 0,
    selectedPlan == plan,
    finalizedNotices == Set(plan),
    checkpointFinalPlan == plan,
    seal1FinalPlan == plan,
    seal2FinalPlan == plan,
    finalizedHeight == planActivationHeight(plan) - 1,
    hasOldQuorum(plan),
    hasNewQuorum(plan),
    LOCAL_SUPPORTED_VERSIONS.contains(targetProtocolVersion(plan)),
    finalizedHeight' = planActivationHeight(plan),
    finalizedNotices' = finalizedNotices,
    selectedPlan' = selectedPlan,
    checkpointFinalPlan' = checkpointFinalPlan,
    seal1FinalPlan' = seal1FinalPlan,
    seal2FinalPlan' = seal2FinalPlan,
    oldVotes' = oldVotes,
    newVotes' = newVotes,
    activePlan' = plan,
    activeConfigurations' =
      activeConfigurations.union(Set(activeConfigurationFor(plan))),
    firstNewBlockPlan' = plan,
    halted' = halted,
  }

  // Two deterministic quorum macros retain a short valid-upgrade witness.
  // Every vote in this witness is from an honest validator that advertises v2.
  action witnessOldQuorum = all {
    not(halted),
    selectedPlan == 1,
    seal2FinalPlan == 1,
    finalizedHeight == SEAL_2_HEIGHT,
    oldVotes.size() == 0,
    finalizedHeight' = finalizedHeight,
    finalizedNotices' = finalizedNotices,
    selectedPlan' = selectedPlan,
    checkpointFinalPlan' = checkpointFinalPlan,
    seal1FinalPlan' = seal1FinalPlan,
    seal2FinalPlan' = seal2FinalPlan,
    oldVotes' = Set(
      { validator: 1, plan: 1 },
      { validator: 2, plan: 1 },
      { validator: 3, plan: 1 }),
    newVotes' = newVotes,
    activePlan' = activePlan,
    activeConfigurations' = activeConfigurations,
    firstNewBlockPlan' = firstNewBlockPlan,
    halted' = halted,
  }

  action witnessNewQuorum = all {
    not(halted),
    selectedPlan == 1,
    seal2FinalPlan == 1,
    finalizedHeight == SEAL_2_HEIGHT,
    hasOldQuorum(1),
    newVotes.size() == 0,
    finalizedHeight' = finalizedHeight,
    finalizedNotices' = finalizedNotices,
    selectedPlan' = selectedPlan,
    checkpointFinalPlan' = checkpointFinalPlan,
    seal1FinalPlan' = seal1FinalPlan,
    seal2FinalPlan' = seal2FinalPlan,
    oldVotes' = oldVotes,
    newVotes' = Set(
      { validator: 5, plan: 1 },
      { validator: 6, plan: 1 },
      { validator: 7, plan: 1 }),
    activePlan' = activePlan,
    activeConfigurations' = activeConfigurations,
    firstNewBlockPlan' = firstNewBlockPlan,
    halted' = halted,
  }

  action legalUpgradeStep = any {
    finalizeUpgradePlanNotice(1),
    finalizeCheckpoint(1),
    finalizeSeal1(1),
    finalizeSeal2(1),
    witnessOldQuorum,
    witnessNewQuorum,
    activateAndFinalizeFirstNewBlock(1),
  }

  action step = {
    nondet validator = VALIDATORS.oneOf()
    nondet plan = PLANS.oneOf()
    any {
      finalizeUpgradePlanNotice(plan),
      observeConflictingFinalizedPlan(plan),
      finalizeCheckpoint(plan),
      finalizeSeal1(plan),
      finalizeSeal2(plan),
      signOldHandoff(validator, plan),
      signNewHandoff(validator, plan),
      activateAndFinalizeFirstNewBlock(plan),
      witnessOldQuorum,
      witnessNewQuorum,
    }
  }

  val milestoneFinalityIsOrdered = all {
    checkpointFinalPlan == 0 or all {
      finalizedNotices.contains(checkpointFinalPlan),
      selectedPlan == checkpointFinalPlan,
      finalizedHeight >= CHECKPOINT_HEIGHT,
    },
    seal1FinalPlan == 0 or all {
      checkpointFinalPlan == seal1FinalPlan,
      finalizedHeight >= SEAL_1_HEIGHT,
    },
    seal2FinalPlan == 0 or all {
      seal1FinalPlan == seal2FinalPlan,
      finalizedHeight >= SEAL_2_HEIGHT,
    },
  }

  val activationRequiresAllPrerequisites =
    activePlan == 0 or activationEvidence(activePlan)

  val activationRequiresFinalizedUpgradePath =
    activePlan == 0 or all {
      finalizedNotices == Set(activePlan),
      selectedPlan == activePlan,
      checkpointFinalPlan == activePlan,
      seal1FinalPlan == activePlan,
      seal2FinalPlan == activePlan,
    }

  val activationRequiresBothHandoffQuorums =
    activePlan == 0 or all {
      hasOldQuorum(activePlan),
      hasNewQuorum(activePlan),
    }

  val activationRequiresSupportedProtocolVersion =
    activePlan == 0
      or LOCAL_SUPPORTED_VERSIONS.contains(targetProtocolVersion(activePlan))

  val activationAtDeclaredHeightAndFirstBlock =
    activePlan == 0 or all {
      finalizedHeight == planActivationHeight(activePlan),
      firstNewBlockPlan == activePlan,
      activeConfigurations.contains(activeConfigurationFor(activePlan)),
    }

  val unsupportedPlanCannotActivate = activePlan != 3

  val conflictingFinalizedPlansFailClosed =
    finalizedNotices.size() <= 1 or all {
      halted,
      activePlan == 0,
      firstNewBlockPlan == 0,
      activeConfigurations.size() == 0,
    }

  val oneConfigurationPerHeight =
    activeConfigurations.forall(left =>
      activeConfigurations.forall(right =>
        left.height != right.height or all {
          left.protocolVersion == right.protocolVersion,
          left.parameterHash == right.parameterHash,
        }))

  val firstNewBlockMatchesActiveConfiguration =
    if (firstNewBlockPlan == 0) activePlan == 0
    else all {
      firstNewBlockPlan == activePlan,
      activeConfigurations.contains(activeConfigurationFor(activePlan)),
      finalizedHeight == planActivationHeight(activePlan),
    }

  val handoffVotesRespectSupportedVersionSets = all {
    oldVotes.forall(vote =>
      OLD_BYZANTINE.contains(vote.validator)
        or supportedVersions(vote.validator)
          .contains(targetProtocolVersion(vote.plan))),
    newVotes.forall(vote =>
      NEW_BYZANTINE.contains(vote.validator)
        or supportedVersions(vote.validator)
          .contains(targetProtocolVersion(vote.plan))),
  }

  val honestHandoffNonEquivocation = all {
    OLD_HONEST.forall(validator =>
      oldVotes
        .filter(vote => vote.validator == validator)
        .map(vote => vote.plan)
        .size() <= 1),
    NEW_HONEST.forall(validator =>
      newVotes
        .filter(vote => vote.validator == validator)
        .map(vote => vote.plan)
        .size() <= 1),
  }

  val haltedUpgradeCannotActivate = not(halted) or activePlan == 0

  val upgradeAtomicitySafety = all {
    milestoneFinalityIsOrdered,
    activationRequiresAllPrerequisites,
    activationRequiresFinalizedUpgradePath,
    activationRequiresBothHandoffQuorums,
    activationRequiresSupportedProtocolVersion,
    activationAtDeclaredHeightAndFirstBlock,
    unsupportedPlanCannotActivate,
    conflictingFinalizedPlansFailClosed,
    oneConfigurationPerHeight,
    firstNewBlockMatchesActiveConfiguration,
    handoffVotesRespectSupportedVersionSets,
    honestHandoffNonEquivocation,
    haltedUpgradeCannotActivate,
  }

  // CI deliberately falsifies this predicate under `legalUpgradeStep` to
  // retain a seven-transition valid-upgrade reachability trace.
  val legalUpgradeNotReached = activePlan != 1
}
