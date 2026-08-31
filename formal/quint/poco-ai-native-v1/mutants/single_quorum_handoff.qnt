module poco_ai_v1_mutant_single_quorum_handoff {
  // MUTANT: the successor epoch activates after only the OldSet role reaches
  // the candidate fixture's threshold 3; NewSet signatures are absent.

  var old_set_signers: Set[int]
  var new_set_signers: Set[int]
  var activated_epoch: int

  action init = all {
    old_set_signers' = Set(),
    new_set_signers' = Set(),
    activated_epoch' = 0,
  }

  action step =
    if (old_set_signers.size() < 3) all {
      old_set_signers' = Set(0, 1, 2),
      new_set_signers' = new_set_signers,
      activated_epoch' = activated_epoch,
    }
    else all {
      old_set_signers' = old_set_signers,
      new_set_signers' = new_set_signers,
      activated_epoch' = 8, // MUTANT
    }

  val activationRequiresDualWeightedQuorum =
    activated_epoch == 0
      or all { old_set_signers.size() >= 3, new_set_signers.size() >= 3 }
}
