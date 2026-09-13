module duplicate_signer_weight {
  // Deliberately broken weighted-QC model. Validator 0's power is counted a
  // second time whenever it appears, representing duplicate signer entries.

  type Vote = { validator: int, branch: int }

  pure val VALIDATORS = 0.to(6)
  pure val BRANCHES = Set(1, 2)

  var mode: int
  var active: Set[int]
  var byzantine: Set[int]
  var power: int -> int
  var quorum: int
  var votes: Set[Vote]

  def votersFor(branch) =
    votes
      .filter(vote => vote.branch == branch)
      .map(vote => vote.validator)

  def signedPowerWithDuplicate(branch) = {
    val voters = votersFor(branch)
    (if (voters.contains(0)) power.get(0) else 0)
      + (if (voters.contains(0)) power.get(0) else 0) // MUTANT
      + (if (voters.contains(1)) power.get(1) else 0)
      + (if (voters.contains(2)) power.get(2) else 0)
      + (if (voters.contains(3)) power.get(3) else 0)
      + (if (voters.contains(4)) power.get(4) else 0)
      + (if (voters.contains(5)) power.get(5) else 0)
      + (if (voters.contains(6)) power.get(6) else 0)
  }

  def hasQc(branch) = signedPowerWithDuplicate(branch) >= quorum

  action initFourWeighted = all {
    mode' = 4,
    active' = Set(0, 1, 2, 3),
    byzantine' = Set(0),
    power' = VALIDATORS.mapBy(v =>
      if (v == 0 or v == 1) 3
      else if (v == 2 or v == 3) 2
      else 0),
    quorum' = 7,
    votes' = Set(),
  }

  action initSevenEqual = all {
    mode' = 7,
    active' = VALIDATORS,
    byzantine' = Set(0, 1),
    power' = VALIDATORS.mapBy(_ => 1),
    quorum' = 5,
    votes' = Set(),
  }

  action init = any {
    initFourWeighted,
    initSevenEqual,
  }

  action castVote(validator, branch) = all {
    active.contains(validator),
    BRANCHES.contains(branch),
    byzantine.contains(validator)
      or not(votes.exists(vote =>
        vote.validator == validator and vote.branch != branch)),
    mode' = mode,
    active' = active,
    byzantine' = byzantine,
    power' = power,
    quorum' = quorum,
    votes' = votes.union(Set({ validator: validator, branch: branch })),
  }

  action step = {
    nondet validator = VALIDATORS.oneOf()
    nondet branch = BRANCHES.oneOf()
    castVote(validator, branch)
  }

  val noConflictingWeightedQcs = not(hasQc(1) and hasQc(2))
}
