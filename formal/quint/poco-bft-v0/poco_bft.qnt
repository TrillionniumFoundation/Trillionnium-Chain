module poco_bft_v0 {
  // A bounded safety model for the v0 chained-QC lock and three-chain commit
  // rule. Validator 0 is Byzantine; validators 1..3 are honest. Blocks 1/3/5
  // and 2/4/6 form two conflicting, direct-parent branches.

  type Vote = { validator: int, block: int }

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

  // The conflicting branch begins only after the first branch could have
  // completed a three-chain. This is the adversarial higher-view fork that
  // the lock rule must reject.
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
  var lockedBlock: int -> int
  var lastVotedView: int -> int
  var finalized: Set[int]

  def votersFor(block) =
    votes
      .filter(vote => vote.block == block)
      .map(vote => vote.validator)

  def hasQc(block) = block == 0 or votersFor(block).size() >= QUORUM

  def hasVotedInView(validator, blockView) =
    votes.exists(vote => vote.validator == validator and view(vote.block) == blockView)

  def safeForHonestVote(validator, block) = {
    val justify = parent(block)
    val locked = lockedBlock.get(validator)
    all {
      view(block) > lastVotedView.get(validator),
      not(hasVotedInView(validator, view(block))),
      hasQc(justify),
      // TC/view advancement is deliberately absent here: only certified
      // ancestry or a strictly higher QC can unlock an honest validator.
      isAncestor(locked, block) or view(justify) > view(locked),
    }
  }

  action init = all {
    votes' = Set(),
    lockedBlock' = VALIDATORS.mapBy(_ => 0),
    lastVotedView' = VALIDATORS.mapBy(_ => 0),
    finalized' = Set(),
  }

  action castVote(validator, block) = all {
    VALIDATORS.contains(validator),
    BLOCKS.contains(block),
    block != 0,
    validator == 0 or safeForHonestVote(validator, block),
    votes' = votes.union(Set({ validator: validator, block: block })),
    lockedBlock' =
      if (HONEST.contains(validator) and view(parent(block)) > view(lockedBlock.get(validator)))
      lockedBlock.set(validator, parent(block))
      else lockedBlock,
    lastVotedView' =
      if (HONEST.contains(validator)) lastVotedView.set(validator, view(block))
      else lastVotedView,
    finalized' = finalized,
  }

  action finalizeThreeChain(tip) = all {
    BLOCKS.contains(tip),
    height(tip) == 3,
    hasQc(tip),
    hasQc(parent(tip)),
    hasQc(parent(parent(tip))),
    votes' = votes,
    lockedBlock' = lockedBlock,
    lastVotedView' = lastVotedView,
    finalized' = finalized.union(Set(parent(parent(tip)))),
  }

  action step = {
    nondet validator = VALIDATORS.oneOf()
    nondet block = BLOCKS.filter(candidate => candidate != 0).oneOf()
    nondet tip = Set(5, 6).oneOf()
    any {
      castVote(validator, block),
      finalizeThreeChain(tip),
    }
  }

  /// No two conflicting blocks at the same height can both be finalized.
  val noConflictingFinality =
    finalized.forall(left =>
      finalized.forall(right => height(left) != height(right) or left == right))

  /// Every QC in this bounded model contains at least one honest signer.
  val quorumContainsHonest =
    BLOCKS.forall(block =>
      not(hasQc(block)) or block == 0 or votersFor(block).exists(v => HONEST.contains(v)))

  /// Honest validators never produce two votes in one protocol view.
  val durableNonEquivocation =
    HONEST.forall(voter =>
      1.to(6).forall(protocolView =>
        votes
          .filter(vote => vote.validator == voter and view(vote.block) == protocolView)
          .size() <= 1))

  /// The durable journal covers every honest vote already emitted.
  val journalCoversVotes =
    votes.forall(vote =>
      not(HONEST.contains(vote.validator))
        or view(vote.block) <= lastVotedView.get(vote.validator))

  /// Locks only name genesis or a block with a QC.
  val certifiedLocks =
    HONEST.forall(voter => hasQc(lockedBlock.get(voter)))
}
