module weighted_quorum {
  // Bounded weighted-intersection model. Initialization nondeterministically
  // selects either four non-equal-weight validators or seven equal-weight
  // validators. Byzantine weight is strictly below one third in both modes.

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

  def signedPower(branch) = {
    val voters = votersFor(branch)
    (if (voters.contains(0)) power.get(0) else 0)
      + (if (voters.contains(1)) power.get(1) else 0)
      + (if (voters.contains(2)) power.get(2) else 0)
      + (if (voters.contains(3)) power.get(3) else 0)
      + (if (voters.contains(4)) power.get(4) else 0)
      + (if (voters.contains(5)) power.get(5) else 0)
      + (if (voters.contains(6)) power.get(6) else 0)
  }

  def hasQc(branch) = signedPower(branch) >= quorum

  action initFourWeighted = all {
    mode' = 4,
    active' = Set(0, 1, 2, 3),
    byzantine' = Set(0),
    // Total W=10, Byzantine weight=3, quorum=floor(20/3)+1=7.
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
    // Total W=7, Byzantine weight=2, quorum=floor(14/3)+1=5.
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

  /// Correct unique-signer weighted quorums cannot certify both branches.
  val noConflictingWeightedQcs = not(hasQc(1) and hasQc(2))

  /// Every accepted QC contains an honest validator in both configurations.
  val weightedQcContainsHonest =
    BRANCHES.forall(branch =>
      not(hasQc(branch))
        or votersFor(branch).exists(validator => not(byzantine.contains(validator))))

  /// Vote storage is a set, so one validator contributes at most once per QC.
  val uniqueSignerAccounting =
    BRANCHES.forall(branch =>
      votersFor(branch).size()
        == votes.filter(vote => vote.branch == branch).size())
}
