module poco_ai_v1_weighted_order_kernel {
  // Candidate-only bounded model for the fields carried by
  // ValidatorSetDefinitionV1, VoteStatementBodyV1, QuorumCertificateV1, and
  // BlockHeaderV1. Integer block IDs abstract typed BlockIdV1 values; parent,
  // height, and view are the authenticated header fields for the fixed corpus.

  type VoteStatementV1 = {
    validator_id: int,
    block_id: int,
    epoch: int,
    view: int,
  }

  pure val VALIDATORS = 0.to(3)
  pure val HONEST = Set(1, 2, 3)
  pure val BLOCKS = 0.to(6)
  pure val SIGNER_BATCHES = Set(
    Set(0), Set(1), Set(2), Set(3),
    Set(0, 1), Set(0, 2), Set(0, 3),
    Set(1, 2), Set(1, 3), Set(2, 3),
    Set(0, 1, 2), Set(0, 1, 3), Set(0, 2, 3), Set(1, 2, 3),
    Set(0, 1, 2, 3)
  )

  // Blocks 1/3/5 and 2/4/6 are conflicting direct-parent chains. The second
  // chain starts at higher views so a lock-bypass mutation is reachable.
  pure def parent(block_id) =
    if (block_id == 1 or block_id == 2) 0
    else if (block_id == 3) 1
    else if (block_id == 4) 2
    else if (block_id == 5) 3
    else if (block_id == 6) 4
    else 0

  pure def height(block_id) =
    if (block_id == 0) 0
    else if (block_id == 1 or block_id == 2) 1
    else if (block_id == 3 or block_id == 4) 2
    else 3

  pure def view(block_id) =
    if (block_id == 0) 0
    else if (block_id == 1) 1
    else if (block_id == 3) 2
    else if (block_id == 5) 3
    else if (block_id == 2) 4
    else if (block_id == 4) 5
    else 6

  pure def extends(candidate, ancestor) =
    ancestor == 0
      or candidate == ancestor
      or parent(candidate) == ancestor
      or parent(parent(candidate)) == ancestor
      or parent(parent(parent(candidate))) == ancestor

  var validator_set_mode: int
  var voting_weight: int -> int
  var total_weight: int
  var quorum_threshold: int
  var vote_statements: Set[VoteStatementV1]
  var certified_blocks: Set[int]
  var locked_block: int -> int
  var last_voted_view: int -> int
  var finalized_blocks: Set[int]
  var finality_witness_tips: Set[int]

  def votersFor(block_id) =
    vote_statements
      .filter(statement => statement.block_id == block_id)
      .map(statement => statement.validator_id)

  def signedWeight(block_id) = {
    val voters = votersFor(block_id)
    (if (voters.contains(0)) voting_weight.get(0) else 0)
      + (if (voters.contains(1)) voting_weight.get(1) else 0)
      + (if (voters.contains(2)) voting_weight.get(2) else 0)
      + (if (voters.contains(3)) voting_weight.get(3) else 0)
  }

  def hasQc(block_id) = certified_blocks.contains(block_id)

  def alreadyVotedInView(validator_id, proposal_view) =
    vote_statements.exists(statement =>
      statement.validator_id == validator_id and statement.view == proposal_view)

  // Processing P.justify_qc first may advance the lock to the QC named by the
  // parent's justify, i.e. the proposal grandparent. It can never lower it.
  def lockAfterJustification(validator_id, block_id) = {
    val current = locked_block.get(validator_id)
    val learned = parent(parent(block_id))
    if (view(learned) > view(current)) learned else current
  }

  def safeVote(validator_id, block_id) = {
    val effective_lock = lockAfterJustification(validator_id, block_id)
    all {
      view(block_id) > last_voted_view.get(validator_id),
      not(alreadyVotedInView(validator_id, view(block_id))),
      hasQc(parent(block_id)),
      extends(block_id, effective_lock)
        or view(parent(block_id)) > view(effective_lock),
    }
  }

  action initVectorFixture = all {
    validator_set_mode' = 0,
    // The current CEV1 candidate vector has four weight-1 members, W=4 and
    // quorum_threshold=floor(2W/3)+1=3.
    voting_weight' = VALIDATORS.mapBy(_ => 1),
    total_weight' = 4,
    quorum_threshold' = 3,
    vote_statements' = Set(),
    certified_blocks' = Set(0),
    locked_block' = VALIDATORS.mapBy(_ => 0),
    last_voted_view' = VALIDATORS.mapBy(_ => 0),
    finalized_blocks' = Set(),
    finality_witness_tips' = Set(),
  }

  action initNonEqualWeights = all {
    validator_set_mode' = 1,
    // A second bounded legal definition checks that the model sums weights,
    // rather than signer cardinality: W=10, threshold=7, Byzantine weight=3.
    voting_weight' = VALIDATORS.mapBy(validator_id =>
      if (validator_id == 0 or validator_id == 1) 3 else 2),
    total_weight' = 10,
    quorum_threshold' = 7,
    vote_statements' = Set(),
    certified_blocks' = Set(0),
    locked_block' = VALIDATORS.mapBy(_ => 0),
    last_voted_view' = VALIDATORS.mapBy(_ => 0),
    finalized_blocks' = Set(),
    finality_witness_tips' = Set(),
  }

  action init = any {
    initVectorFixture,
    initNonEqualWeights,
  }

  action castVoteBatch(block_id, signers) = all {
    BLOCKS.contains(block_id),
    block_id != 0,
    SIGNER_BATCHES.contains(signers),
    not(hasQc(block_id)),
    hasQc(parent(block_id)),
    signers.forall(validator_id =>
      not(vote_statements.contains({
        validator_id: validator_id,
        block_id: block_id,
        epoch: 7,
        view: view(block_id),
      }))),
    signers.forall(validator_id =>
      not(HONEST.contains(validator_id)) or safeVote(validator_id, block_id)),
    validator_set_mode' = validator_set_mode,
    voting_weight' = voting_weight,
    total_weight' = total_weight,
    quorum_threshold' = quorum_threshold,
    vote_statements' = vote_statements.union(signers.map(validator_id => {
      validator_id: validator_id,
      block_id: block_id,
      epoch: 7,
      view: view(block_id),
    })),
    certified_blocks' =
      if (signedWeight(block_id)
          + signers
              .filter(validator_id => not(votersFor(block_id).contains(validator_id)))
              .fold(0, (weight, validator_id) =>
                weight + voting_weight.get(validator_id))
          >= quorum_threshold)
      certified_blocks.union(Set(block_id))
      else certified_blocks,
    locked_block' = VALIDATORS.mapBy(validator_id =>
      if (HONEST.contains(validator_id) and signers.contains(validator_id))
      lockAfterJustification(validator_id, block_id)
      else locked_block.get(validator_id)),
    last_voted_view' = VALIDATORS.mapBy(validator_id =>
      if (HONEST.contains(validator_id) and signers.contains(validator_id))
      view(block_id)
      else last_voted_view.get(validator_id)),
    finalized_blocks' = finalized_blocks,
    finality_witness_tips' = finality_witness_tips,
  }

  action finalizeDirectThreeChain(tip) = all {
    BLOCKS.contains(tip),
    height(tip) == 3,
    hasQc(tip),
    hasQc(parent(tip)),
    hasQc(parent(parent(tip))),
    height(parent(tip)) == height(tip) - 1,
    height(parent(parent(tip))) == height(tip) - 2,
    view(parent(parent(tip))) < view(parent(tip)),
    view(parent(tip)) < view(tip),
    validator_set_mode' = validator_set_mode,
    voting_weight' = voting_weight,
    total_weight' = total_weight,
    quorum_threshold' = quorum_threshold,
    vote_statements' = vote_statements,
    certified_blocks' = certified_blocks,
    locked_block' = locked_block,
    last_voted_view' = last_voted_view,
    finalized_blocks' = finalized_blocks.union(Set(parent(parent(tip)))),
    finality_witness_tips' = finality_witness_tips.union(Set(tip)),
  }

  action step = {
    nondet block_id = BLOCKS.filter(candidate => candidate != 0).oneOf()
    nondet signers = SIGNER_BATCHES.oneOf()
    nondet tip = Set(5, 6).oneOf()
    any {
      castVoteBatch(block_id, signers),
      finalizeDirectThreeChain(tip),
    }
  }

  action legalFinalityStep =
    if (not(hasQc(1))) castVoteBatch(1, Set(0, 1, 2))
    else if (not(hasQc(3))) castVoteBatch(3, Set(0, 1, 2))
    else if (not(hasQc(5))) castVoteBatch(5, Set(0, 1, 2))
    else finalizeDirectThreeChain(5)

  val thresholdMatchesCommittedWeights =
    if (validator_set_mode == 0)
    total_weight == 4 and quorum_threshold == 3
    else total_weight == 10 and quorum_threshold == 7

  val everyQcHasUniqueWeightedQuorum =
    certified_blocks.forall(block_id =>
      block_id == 0
        or all {
          signedWeight(block_id) >= quorum_threshold,
          votersFor(block_id).size()
            == vote_statements
              .filter(statement => statement.block_id == block_id)
              .size(),
        })

  val honestVoteNonEquivocation =
    HONEST.forall(validator_id =>
      1.to(6).forall(proposal_view =>
        vote_statements
          .filter(statement =>
            statement.validator_id == validator_id
              and statement.epoch == 7
              and statement.view == proposal_view)
          .size() <= 1))

  val certifiedLocks =
    HONEST.forall(validator_id => hasQc(locked_block.get(validator_id)))

  val finalityRequiresDirectThreeChain =
    finalized_blocks.forall(finalized_block =>
      finality_witness_tips.exists(tip => all {
        parent(parent(tip)) == finalized_block,
        hasQc(tip),
        hasQc(parent(tip)),
        hasQc(parent(parent(tip))),
        height(parent(tip)) == height(tip) - 1,
        height(parent(parent(tip))) == height(tip) - 2,
        view(parent(parent(tip))) < view(parent(tip)),
        view(parent(tip)) < view(tip),
      }))

  val noConflictingOrderFinality =
    finalized_blocks.forall(left =>
      finalized_blocks.forall(right => extends(left, right) or extends(right, left)))

  val legalFinalityNotReached = not(finalized_blocks.contains(1))
}
