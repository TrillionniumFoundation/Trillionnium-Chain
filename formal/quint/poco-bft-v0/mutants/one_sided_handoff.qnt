module one_sided_handoff {
  // Deliberately broken epoch activation: an old-set quorum activates without
  // the independently required new-set quorum.

  type HandoffVote = { validator: int, descriptor: int }

  pure val VALIDATORS = 0.to(5)
  pure val OLD_SET = Set(0, 1, 2, 3)
  pure val NEW_SET = Set(2, 3, 4, 5)
  pure val DESCRIPTORS = Set(1, 2)
  pure val QUORUM = 3

  var checkpointFinal: bool
  var oldVotes: Set[HandoffVote]
  var newVotes: Set[HandoffVote]
  var activatedDescriptor: int

  def oldVoters(descriptor) =
    oldVotes
      .filter(vote => vote.descriptor == descriptor)
      .map(vote => vote.validator)

  def newVoters(descriptor) =
    newVotes
      .filter(vote => vote.descriptor == descriptor)
      .map(vote => vote.validator)

  def hasOldQuorum(descriptor) = oldVoters(descriptor).size() >= QUORUM
  def hasNewQuorum(descriptor) = newVoters(descriptor).size() >= QUORUM

  action init = all {
    checkpointFinal' = false,
    oldVotes' = Set(),
    newVotes' = Set(),
    activatedDescriptor' = 0,
  }

  action finalizeCheckpoint = all {
    checkpointFinal' = true,
    oldVotes' = oldVotes,
    newVotes' = newVotes,
    activatedDescriptor' = activatedDescriptor,
  }

  action signOld(validator, descriptor) = all {
    OLD_SET.contains(validator),
    DESCRIPTORS.contains(descriptor),
    checkpointFinal,
    checkpointFinal' = checkpointFinal,
    oldVotes' = oldVotes.union(Set({ validator: validator, descriptor: descriptor })),
    newVotes' = newVotes,
    activatedDescriptor' = activatedDescriptor,
  }

  action signNew(validator, descriptor) = all {
    NEW_SET.contains(validator),
    DESCRIPTORS.contains(descriptor),
    checkpointFinal,
    checkpointFinal' = checkpointFinal,
    oldVotes' = oldVotes,
    newVotes' = newVotes.union(Set({ validator: validator, descriptor: descriptor })),
    activatedDescriptor' = activatedDescriptor,
  }

  action activate(descriptor) = all {
    DESCRIPTORS.contains(descriptor),
    activatedDescriptor == 0,
    checkpointFinal,
    hasOldQuorum(descriptor),
    // MUTANT: hasNewQuorum(descriptor) is missing.
    checkpointFinal' = checkpointFinal,
    oldVotes' = oldVotes,
    newVotes' = newVotes,
    activatedDescriptor' = descriptor,
  }

  action step = {
    nondet validator = VALIDATORS.oneOf()
    nondet descriptor = DESCRIPTORS.oneOf()
    any {
      finalizeCheckpoint,
      signOld(validator, descriptor),
      signNew(validator, descriptor),
      activate(descriptor),
    }
  }

  val activationRequiresBothQuorums =
    activatedDescriptor == 0
      or all {
        hasOldQuorum(activatedDescriptor),
        hasNewQuorum(activatedDescriptor),
      }
}
