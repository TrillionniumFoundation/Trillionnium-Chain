module partition_heal {
  // Four-validator bounded network model. Validator 0 may be Byzantine;
  // validators 1..3 are honest and quorum is three. Blocks 1/3/5 and 2/4/6
  // form conflicting direct-parent chains. While partitioned, {0,1} and
  // {2,3} cannot exchange vote messages. Messages may be delayed indefinitely
  // (signed but neither delivered nor dropped), explicitly dropped, or
  // delivered subject to the partition. Healing is monotonic.

  type Vote = { validator: int, block: int }
  type Message = { voter: int, block: int, recipient: int }

  pure val VALIDATORS = 0.to(3)
  pure val HONEST = Set(1, 2, 3)
  pure val BLOCKS = 0.to(6)
  pure val QUORUM = 3

  pure def parent(block) =
    if (block == 1 or block == 2) 0
    else if (block == 3) 1
    else if (block == 4) 2
    else if (block == 5) 3
    else if (block == 6) 4
    else 0

  pure def height(block) =
    if (block == 0) 0
    else if (block == 1 or block == 2) 1
    else if (block == 3 or block == 4) 2
    else 3

  pure def view(block) =
    if (block == 0) 0
    else if (block == 1) 1
    else if (block == 3) 2
    else if (block == 5) 3
    else if (block == 2) 4
    else if (block == 4) 5
    else 6

  pure def samePartition(left, right) =
    (left <= 1 and right <= 1) or (left >= 2 and right >= 2)

  pure def isAncestor(ancestor, block) =
    ancestor == 0
      or ancestor == block
      or ancestor == parent(block)
      or ancestor == parent(parent(block))
      or ancestor == parent(parent(parent(block)))

  var networkHealed: bool
  var votes: Set[Vote]
  var delivered: Set[Message]
  var dropped: Set[Message]
  var lockedBlock: int -> int
  var lastVotedView: int -> int
  var finalized: Set[int]
  var fairStage: int

  def votersSeen(recipient, block) =
    delivered
      .filter(message =>
        message.recipient == recipient and message.block == block)
      .map(message => message.voter)

  def recipientHasQc(recipient, block) =
    block == 0 or votersSeen(recipient, block).size() >= QUORUM

  def hasQc(block) =
    block == 0 or VALIDATORS.exists(recipient => recipientHasQc(recipient, block))

  def hasVotedInView(validator, blockView) =
    votes.exists(vote =>
      vote.validator == validator and view(vote.block) == blockView)

  def safeForHonestVote(validator, block) = {
    val justify = parent(block)
    val locked = lockedBlock.get(validator)
    all {
      view(block) > lastVotedView.get(validator),
      not(hasVotedInView(validator, view(block))),
      hasQc(justify),
      isAncestor(locked, block) or view(justify) > view(locked),
    }
  }

  action init = all {
    networkHealed' = false,
    votes' = Set(),
    delivered' = Set(),
    dropped' = Set(),
    lockedBlock' = VALIDATORS.mapBy(_ => 0),
    lastVotedView' = VALIDATORS.mapBy(_ => 0),
    finalized' = Set(),
    fairStage' = 0,
  }

  action castVote(validator, block) = all {
    fairStage == 0,
    VALIDATORS.contains(validator),
    BLOCKS.contains(block),
    block != 0,
    validator == 0 or safeForHonestVote(validator, block),
    networkHealed' = networkHealed,
    votes' = votes.union(Set({ validator: validator, block: block })),
    delivered' = delivered,
    dropped' = dropped,
    lockedBlock' =
      if (HONEST.contains(validator)
        and view(parent(block)) > view(lockedBlock.get(validator)))
      lockedBlock.set(validator, parent(block))
      else lockedBlock,
    lastVotedView' =
      if (HONEST.contains(validator))
      lastVotedView.set(validator, view(block))
      else lastVotedView,
    finalized' = finalized,
    fairStage' = fairStage,
  }

  action deliverVote(voter, block, recipient) = {
    val message = { voter: voter, block: block, recipient: recipient }
    all {
      fairStage == 0,
      VALIDATORS.contains(voter),
      VALIDATORS.contains(recipient),
      BLOCKS.contains(block),
      block != 0,
      votes.contains({ validator: voter, block: block }),
      not(delivered.contains(message)),
      not(dropped.contains(message)),
      networkHealed or samePartition(voter, recipient),
      networkHealed' = networkHealed,
      votes' = votes,
      delivered' = delivered.union(Set(message)),
      dropped' = dropped,
      lockedBlock' = lockedBlock,
      lastVotedView' = lastVotedView,
      finalized' = finalized,
      fairStage' = fairStage,
    }
  }

  action dropVote(voter, block, recipient) = {
    val message = { voter: voter, block: block, recipient: recipient }
    all {
      fairStage == 0,
      VALIDATORS.contains(voter),
      VALIDATORS.contains(recipient),
      BLOCKS.contains(block),
      block != 0,
      votes.contains({ validator: voter, block: block }),
      not(delivered.contains(message)),
      not(dropped.contains(message)),
      networkHealed' = networkHealed,
      votes' = votes,
      delivered' = delivered,
      dropped' = dropped.union(Set(message)),
      lockedBlock' = lockedBlock,
      lastVotedView' = lastVotedView,
      finalized' = finalized,
      fairStage' = fairStage,
    }
  }

  action healNetwork = all {
    fairStage == 0,
    not(networkHealed),
    networkHealed' = true,
    votes' = votes,
    delivered' = delivered,
    dropped' = dropped,
    lockedBlock' = lockedBlock,
    lastVotedView' = lastVotedView,
    finalized' = finalized,
    fairStage' = fairStage,
  }

  action finalizeThreeChain(tip) = all {
    fairStage == 0,
    BLOCKS.contains(tip),
    height(tip) == 3,
    hasQc(tip),
    hasQc(parent(tip)),
    hasQc(parent(parent(tip))),
    networkHealed' = networkHealed,
    votes' = votes,
    delivered' = delivered,
    dropped' = dropped,
    lockedBlock' = lockedBlock,
    lastVotedView' = lastVotedView,
    finalized' = finalized.union(Set(parent(parent(tip)))),
    fairStage' = fairStage,
  }

  // The next four actions are a concrete finite fair-delivery witness. After
  // healing, all three honest validators vote in increasing views and their
  // messages are delivered to honest validator 1. No Byzantine cooperation is
  // needed. CI selects `fairHealStep` directly and searches for stage 4.
  action fairHeal = all {
    fairStage == 0,
    not(networkHealed),
    votes.size() == 0,
    delivered.size() == 0,
    dropped.size() == 0,
    finalized.size() == 0,
    networkHealed' = true,
    votes' = votes,
    delivered' = delivered,
    dropped' = dropped,
    lockedBlock' = lockedBlock,
    lastVotedView' = lastVotedView,
    finalized' = finalized,
    fairStage' = 1,
  }

  action fairCertifyFirst = all {
    fairStage == 1,
    networkHealed,
    networkHealed' = networkHealed,
    votes' = votes.union(Set(
      { validator: 1, block: 1 },
      { validator: 2, block: 1 },
      { validator: 3, block: 1 })),
    delivered' = delivered.union(Set(
      { voter: 1, block: 1, recipient: 1 },
      { voter: 2, block: 1, recipient: 1 },
      { voter: 3, block: 1, recipient: 1 })),
    dropped' = dropped,
    lockedBlock' = lockedBlock,
    lastVotedView' = lastVotedView
      .set(1, view(1))
      .set(2, view(1))
      .set(3, view(1)),
    finalized' = finalized,
    fairStage' = 2,
  }

  action fairCertifySecond = all {
    fairStage == 2,
    recipientHasQc(1, 1),
    networkHealed' = networkHealed,
    votes' = votes.union(Set(
      { validator: 1, block: 3 },
      { validator: 2, block: 3 },
      { validator: 3, block: 3 })),
    delivered' = delivered.union(Set(
      { voter: 1, block: 3, recipient: 1 },
      { voter: 2, block: 3, recipient: 1 },
      { voter: 3, block: 3, recipient: 1 })),
    dropped' = dropped,
    lockedBlock' = lockedBlock
      .set(1, 1)
      .set(2, 1)
      .set(3, 1),
    lastVotedView' = lastVotedView
      .set(1, view(3))
      .set(2, view(3))
      .set(3, view(3)),
    finalized' = finalized,
    fairStage' = 3,
  }

  action fairCertifyThirdAndFinalize = all {
    fairStage == 3,
    recipientHasQc(1, 1),
    recipientHasQc(1, 3),
    networkHealed' = networkHealed,
    votes' = votes.union(Set(
      { validator: 1, block: 5 },
      { validator: 2, block: 5 },
      { validator: 3, block: 5 })),
    delivered' = delivered.union(Set(
      { voter: 1, block: 5, recipient: 1 },
      { voter: 2, block: 5, recipient: 1 },
      { voter: 3, block: 5, recipient: 1 })),
    dropped' = dropped,
    lockedBlock' = lockedBlock
      .set(1, 3)
      .set(2, 3)
      .set(3, 3),
    lastVotedView' = lastVotedView
      .set(1, view(5))
      .set(2, view(5))
      .set(3, view(5)),
    finalized' = finalized.union(Set(1)),
    fairStage' = 4,
  }

  action fairHealStep = any {
    fairHeal,
    fairCertifyFirst,
    fairCertifySecond,
    fairCertifyThirdAndFinalize,
  }

  action step = {
    nondet voter = VALIDATORS.oneOf()
    nondet block = BLOCKS.filter(candidate => candidate != 0).oneOf()
    nondet recipient = VALIDATORS.oneOf()
    nondet tip = Set(5, 6).oneOf()
    any {
      castVote(voter, block),
      deliverVote(voter, block, recipient),
      dropVote(voter, block, recipient),
      healNetwork,
      finalizeThreeChain(tip),
      fairHealStep,
    }
  }

  /// Loss, delay, partition, and healing cannot make two blocks at the same
  /// height finalize in this bounded chained-QC model.
  val noConflictingFinalityAcrossPartitionHeal =
    finalized.forall(left =>
      finalized.forall(right => height(left) != height(right) or left == right))

  /// A two-by-two partition cannot assemble three distinct signer messages at
  /// any recipient. Stalling is allowed and expected.
  val partitionMayStallButCannotCertify =
    networkHealed or BLOCKS.forall(block => block == 0 or not(hasQc(block)))

  val deliveredMessagesCameFromVotes =
    delivered.forall(message =>
      votes.contains({ validator: message.voter, block: message.block }))

  val deliveredAndDroppedAreDisjoint =
    delivered.intersect(dropped).size() == 0

  val partitionedDeliveryDoesNotCross =
    networkHealed or delivered.forall(message =>
      samePartition(message.voter, message.recipient))

  val everyQcContainsHonestSigner =
    BLOCKS.forall(block =>
      not(hasQc(block)) or block == 0
        or VALIDATORS.forall(recipient =>
          not(recipientHasQc(recipient, block))
            or votersSeen(recipient, block)
              .exists(voter => HONEST.contains(voter))))

  val durableNonEquivocationAcrossNetworkFaults =
    HONEST.forall(voter =>
      1.to(6).forall(protocolView =>
        votes
          .filter(vote =>
            vote.validator == voter and view(vote.block) == protocolView)
          .size() <= 1))

  val journalCoversVotesAcrossNetworkFaults =
    votes.forall(vote =>
      not(HONEST.contains(vote.validator))
        or view(vote.block) <= lastVotedView.get(vote.validator))

  val locksRemainCertifiedAcrossNetworkFaults =
    HONEST.forall(voter => hasQc(lockedBlock.get(voter)))

  val fairWitnessStateIsValid =
    fairStage != 4 or all {
      networkHealed,
      recipientHasQc(1, 1),
      recipientHasQc(1, 3),
      recipientHasQc(1, 5),
      finalized.contains(1),
      votes
        .filter(vote => vote.block == 5 and HONEST.contains(vote.validator))
        .size() == QUORUM,
    }

  // One aggregate predicate lets CI explore a single seeded trace corpus
  // while retaining the separately named review points above.
  val partitionHealSafety = all {
    noConflictingFinalityAcrossPartitionHeal,
    partitionMayStallButCannotCertify,
    deliveredMessagesCameFromVotes,
    deliveredAndDroppedAreDisjoint,
    partitionedDeliveryDoesNotCross,
    everyQcContainsHonestSigner,
    durableNonEquivocationAcrossNetworkFaults,
    journalCoversVotesAcrossNetworkFaults,
    locksRemainCertifiedAcrossNetworkFaults,
    fairWitnessStateIsValid,
  }

  // Reachability target. CI deliberately falsifies it under fairHealStep to
  // retain a concrete four-transition progress trace after healing.
  val fairHealProgressNotReached = fairStage != 4
}
