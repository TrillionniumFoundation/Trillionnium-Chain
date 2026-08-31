module poco_ai_v1_mutant_unsafe_lock_vote {
  // MUTANT: after a direct three-chain finalizes branch 1 and durably locks it,
  // the same honest quorum is permitted to vote the conflicting higher-view
  // branch 2 without extends(lock) or higher-justify evidence.

  type VoteStatementV1 = { validator_id: int, block_id: int, view: int }

  pure val QUORUM = Set(0, 1, 2)

  var phase: int
  var votes: Set[VoteStatementV1]
  var certified_blocks: Set[int]
  var locked_branch: int
  var finalized_branches: Set[int]

  action init = all {
    phase' = 0,
    votes' = Set(),
    certified_blocks' = Set(0),
    locked_branch' = 0,
    finalized_branches' = Set(),
  }

  action certify(block_id, proposal_view) = all {
    votes' = votes.union(QUORUM.map(validator_id => {
      validator_id: validator_id,
      block_id: block_id,
      view: proposal_view,
    })),
    certified_blocks' = certified_blocks.union(Set(block_id)),
    phase' = phase + 1,
    locked_branch' =
      if (block_id == 5) 1
      else if (block_id == 6) 2
      else locked_branch,
    finalized_branches' =
      if (block_id == 5) finalized_branches.union(Set(1))
      else if (block_id == 6) finalized_branches.union(Set(2))
      else finalized_branches,
  }

  action step =
    if (phase == 0) certify(1, 1)
    else if (phase == 1) certify(3, 2)
    else if (phase == 2) certify(5, 3)
    // MUTANT begins: blocks 2/4/6 do not extend locked branch 1.
    else if (phase == 3) certify(2, 4)
    else if (phase == 4) certify(4, 5)
    else certify(6, 6)

  val noConflictingOrderFinality = finalized_branches.size() <= 1
}
