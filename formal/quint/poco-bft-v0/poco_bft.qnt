module poco_bft_v0 {
  // A bounded safety model for the v0 chained-QC lock and direct three-chain
  // rule. Validator 0 is Byzantine; validators 1..3 are honest. Blocks
  // 1/3/5 and 2/4/6 form two conflicting direct-parent branches.
  //
  // One transition admits any nonempty batch of votes evaluated from the same
  // pre-state, including every singleton batch and every exact 3-of-4 quorum.
  // Thus no individual-vote path is deleted, while a legal three-chain remains
  // reachable in four transitions and a deliberately unsafe
  // conflicting-finality mutation in eight. A symbolic depth-10 result cannot
  // pass merely because the bad state needs >10 vote/finalize transitions.

  type Vote = { validator: int, block: int }

  pure val VALIDATORS = 0.to(3)
  pure val HONEST = Set(1, 2, 3)
  pure val BLOCKS = 0.to(6)
  pure val QUORUM = 3
  pure val QUORUMS = Set(
    Set(0, 1, 2),
    Set(0, 1, 3),
    Set(0, 2, 3),
    Set(1, 2, 3)
  )
  pure val SIGNER_BATCHES = Set(
    Set(0), Set(1), Set(2), Set(3),
    Set(0, 1), Set(0, 2), Set(0, 3),
    Set(1, 2), Set(1, 3), Set(2, 3),
    Set(0, 1, 2), Set(0, 1, 3), Set(0, 2, 3), Set(1, 2, 3),
    Set(0, 1, 2, 3)
  )

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

  // The conflicting branch begins only after the first branch can complete a
  // three-chain. This is the higher-view fork that the lock rule must reject.
  pure def view(block) =
    if (block == 0) 0
    else if (block == 1) 1
    else if (block == 3) 2
    else if (block == 5) 3
    else if (block == 2) 4
    else if (block == 4) 5
    else 6

  pure def isAncestor(ancestor, block) =
    ancestor == 0
      or ancestor == block
      or ancestor == parent(block)
      or ancestor == parent(parent(block))
      or ancestor == parent(parent(parent(block)))

  var votes: Set[Vote]
  var qcs: Set[int]
  var lockedBlock: int -> int
  var lastVotedView: int -> int
  var finalized: Set[int]

  def votersFor(block) =
    votes
      .filter(vote => vote.block == block)
      .map(vote => vote.validator)

  def hasQc(block) = qcs.contains(block)

  def hasVotedInView(validator, blockView) =
    votes.exists(vote => vote.validator == validator and view(vote.block) == blockView)

  // A voter processing proposal B first learns B.justify_qc, which certifies
  // parent(B). Per the normative QC-processing rule that can advance its lock
  // to parent(B).justify_qc, i.e. grandparent(B), but never lowers the lock.
  def lockAfterLearningJustify(validator, block) = {
    val current = lockedBlock.get(validator)
    val learned = parent(parent(block))
    if (view(learned) > view(current)) learned else current
  }

  def safeForHonestVote(validator, block) = {
    val justify = parent(block)
    val effectiveLock = lockAfterLearningJustify(validator, block)
    all {
      view(block) > lastVotedView.get(validator),
      not(hasVotedInView(validator, view(block))),
      hasQc(justify),
      // A TC/view advance is deliberately insufficient: only extending the
      // lock or carrying a strictly higher justify QC makes the vote safe.
      isAncestor(effectiveLock, block) or view(justify) > view(effectiveLock),
    }
  }

  action init = all {
    votes' = Set(),
    qcs' = Set(0),
    lockedBlock' = VALIDATORS.mapBy(_ => 0),
    lastVotedView' = VALIDATORS.mapBy(_ => 0),
    finalized' = Set(),
  }

  action castVoteBatch(block, signers) = all {
    BLOCKS.contains(block),
    block != 0,
    SIGNER_BATCHES.contains(signers),
    not(hasQc(block)),
    hasQc(parent(block)),
    signers.forall(validator =>
      not(votes.contains({ validator: validator, block: block }))),
    signers.forall(validator =>
      not(HONEST.contains(validator)) or safeForHonestVote(validator, block)),
    votes' = votes.union(
      signers.map(validator => { validator: validator, block: block })),
    qcs' =
      if (votersFor(block).union(signers).size() >= QUORUM)
      qcs.union(Set(block))
      else qcs,
    lockedBlock' = VALIDATORS.mapBy(validator =>
      if (HONEST.contains(validator) and signers.contains(validator))
      lockAfterLearningJustify(validator, block)
      else lockedBlock.get(validator)),
    // This is the durable monotonic vote watermark. The transition models
    // decision+journal persistence before any vote becomes part of the QC.
    lastVotedView' = VALIDATORS.mapBy(validator =>
      if (HONEST.contains(validator) and signers.contains(validator))
      view(block)
      else lastVotedView.get(validator)),
    finalized' = finalized,
  }

  action finalizeThreeChain(tip) = all {
    BLOCKS.contains(tip),
    height(tip) == 3,
    hasQc(tip),
    hasQc(parent(tip)),
    hasQc(parent(parent(tip))),
    votes' = votes,
    qcs' = qcs,
    lockedBlock' = lockedBlock,
    lastVotedView' = lastVotedView,
    finalized' = finalized.union(Set(parent(parent(tip)))),
  }

  action step = {
    nondet block = BLOCKS.filter(candidate => candidate != 0).oneOf()
    nondet signers = SIGNER_BATCHES.oneOf()
    nondet tip = Set(5, 6).oneOf()
    any {
      castVoteBatch(block, signers),
      finalizeThreeChain(tip),
    }
  }

  // Deterministic positive witness: one legal direct three-chain finalizes
  // block 1 in four transitions.
  action legalFinalityStep =
    if (not(hasQc(1))) castVoteBatch(1, Set(0, 1, 2))
    else if (not(hasQc(3))) castVoteBatch(3, Set(0, 1, 2))
    else if (not(hasQc(5))) castVoteBatch(5, Set(0, 1, 2))
    else finalizeThreeChain(5)

  // Retained in-model mutation: remove the safe-vote/lock gate while keeping
  // exact quorums, parent QCs, durable watermarks, and the same finality rule.
  action unsafeFormQc(block, signers) = all {
    BLOCKS.contains(block),
    block != 0,
    QUORUMS.contains(signers),
    not(hasQc(block)),
    hasQc(parent(block)),
    votes' = votes.union(
      signers.map(validator => { validator: validator, block: block })),
    qcs' = qcs.union(Set(block)),
    lockedBlock' = lockedBlock,
    lastVotedView' = VALIDATORS.mapBy(validator =>
      if (HONEST.contains(validator) and signers.contains(validator))
      view(block)
      else lastVotedView.get(validator)),
    finalized' = finalized,
  }

  action unsafeForkStep =
    if (not(hasQc(1))) unsafeFormQc(1, Set(0, 1, 2))
    else if (not(hasQc(3))) unsafeFormQc(3, Set(0, 1, 2))
    else if (not(hasQc(5))) unsafeFormQc(5, Set(0, 1, 2))
    else if (not(finalized.contains(1))) finalizeThreeChain(5)
    else if (not(hasQc(2))) unsafeFormQc(2, Set(0, 1, 2))
    else if (not(hasQc(4))) unsafeFormQc(4, Set(0, 1, 2))
    else if (not(hasQc(6))) unsafeFormQc(6, Set(0, 1, 2))
    else finalizeThreeChain(6)

  /// Every pair of finalized blocks is prefix-comparable, including pairs at
  /// different heights. Same-height equality is only a corollary.
  val noConflictingFinality =
    finalized.forall(left =>
      finalized.forall(right => isAncestor(left, right) or isAncestor(right, left)))

  /// Every non-genesis QC in this bounded model contains an honest signer.
  val quorumContainsHonest =
    qcs.forall(block =>
      block == 0 or votersFor(block).exists(v => HONEST.contains(v)))

  /// Honest validators never produce two votes in one protocol view.
  val durableNonEquivocation =
    HONEST.forall(voter =>
      1.to(6).forall(protocolView =>
        votes
          .filter(vote => vote.validator == voter and view(vote.block) == protocolView)
          .size() <= 1))

  /// The durable view watermark covers every honest vote already emitted.
  val journalCoversVotes =
    votes.forall(vote =>
      not(HONEST.contains(vote.validator))
        or view(vote.block) <= lastVotedView.get(vote.validator))

  /// Locks only name genesis or a block with a QC.
  val certifiedLocks =
    HONEST.forall(voter => hasQc(lockedBlock.get(voter)))

  val legalFinalityNotReached = not(finalized.contains(1))
}
