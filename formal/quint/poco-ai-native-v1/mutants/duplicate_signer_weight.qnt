module poco_ai_v1_mutant_duplicate_signer_weight {
  // MUTANT: validator 0's weight is counted twice in each certificate. In the
  // non-equal bounded definition, two disjoint honest signer subsets can then
  // form conflicting same-view QCs around the one Byzantine validator.

  type VoteSignatureEntryV1 = { validator_id: int, branch: int }

  var signatures: Set[VoteSignatureEntryV1]

  def votersFor(branch) =
    signatures
      .filter(entry => entry.branch == branch)
      .map(entry => entry.validator_id)

  def mutatedSignedWeight(branch) = {
    val voters = votersFor(branch)
    (if (voters.contains(0)) 3 else 0)
      + (if (voters.contains(0)) 3 else 0) // MUTANT: duplicate identity
      + (if (voters.contains(1)) 3 else 0)
      + (if (voters.contains(2)) 2 else 0)
      + (if (voters.contains(3)) 2 else 0)
  }

  def hasQc(branch) = mutatedSignedWeight(branch) >= 7

  action init = signatures' = Set()

  action step =
    if (not(hasQc(1)))
    signatures' = signatures.union(Set(
      { validator_id: 0, branch: 1 },
      { validator_id: 1, branch: 1 }
    ))
    else signatures' = signatures.union(Set(
      { validator_id: 0, branch: 2 },
      { validator_id: 2, branch: 2 }
    ))

  val noConflictingWeightedQcs = not(hasQc(1) and hasQc(2))
}
