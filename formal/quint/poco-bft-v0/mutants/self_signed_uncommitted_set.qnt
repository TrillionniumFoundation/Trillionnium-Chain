module self_signed_uncommitted_set {
  // Deliberately broken light client. The old finalized checkpoint commits
  // set 2, while attacker-controlled set 3 supplies a self-signed finalized
  // chain. The mutant accepts set 3 without the checkpoint commitment or old
  // handoff quorum.

  type EpochLink = { targetEpoch: int, setId: int }
  type HandoffVote = { validator: int, targetEpoch: int, setId: int }

  pure val COMMITTED_LINK = { targetEpoch: 2, setId: 2 }
  pure val ATTACKER_LINK = { targetEpoch: 2, setId: 3 }
  pure val QUORUM = 3

  var finalizedOldCheckpoints: Set[int]
  var nextSetCommitments: Set[EpochLink]
  var oldHandoffVotes: Set[HandoffVote]
  var newHandoffVotes: Set[HandoffVote]
  var finalizedNewEpochChains: Set[EpochLink]
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

  action init = all {
    finalizedOldCheckpoints' = Set(1),
    nextSetCommitments' = Set(COMMITTED_LINK),
    oldHandoffVotes' = Set(),
    newHandoffVotes' = Set(
      { validator: 8, targetEpoch: 2, setId: 3 },
      { validator: 9, targetEpoch: 2, setId: 3 },
      { validator: 10, targetEpoch: 2, setId: 3 }),
    finalizedNewEpochChains' = Set(ATTACKER_LINK),
    acceptedLinks' = Set(),
  }

  action acceptSelfSignedSet = all {
    hasNewQuorum(ATTACKER_LINK),
    finalizedNewEpochChains.contains(ATTACKER_LINK),
    // MUTANT: no commitment match and no old-set handoff quorum are checked.
    finalizedOldCheckpoints' = finalizedOldCheckpoints,
    nextSetCommitments' = nextSetCommitments,
    oldHandoffVotes' = oldHandoffVotes,
    newHandoffVotes' = newHandoffVotes,
    finalizedNewEpochChains' = finalizedNewEpochChains,
    acceptedLinks' = Set(ATTACKER_LINK),
  }

  action step = acceptSelfSignedSet

  val acceptedOnlyCommittedJointTransition =
    acceptedLinks.forall(link => all {
      finalizedOldCheckpoints.contains(link.targetEpoch - 1),
      nextSetCommitments.contains(link),
      hasOldQuorum(link),
      hasNewQuorum(link),
      finalizedNewEpochChains.contains(link),
    })
}
