module poco_ai_v1_mutant_wrong_activation_anchor {
  // MUTANT: both role quorums exist, but the installed EpochStartJustification
  // names a different handoff ID than the jointly signed EpochHandoffV1.

  pure val HANDOFF_ID = 1

  var phase: int
  var checkpoint_finalized: bool
  var old_set_signers: Set[int]
  var new_set_signers: Set[int]
  var activated_epoch: int
  var activation_anchor_handoff_id: int

  action init = all {
    phase' = 0,
    checkpoint_finalized' = false,
    old_set_signers' = Set(),
    new_set_signers' = Set(),
    activated_epoch' = 0,
    activation_anchor_handoff_id' = 0,
  }

  action step =
    if (phase == 0) all {
      phase' = 1,
      checkpoint_finalized' = true,
      old_set_signers' = old_set_signers,
      new_set_signers' = new_set_signers,
      activated_epoch' = activated_epoch,
      activation_anchor_handoff_id' = activation_anchor_handoff_id,
    }
    else if (phase == 1) all {
      phase' = 2,
      checkpoint_finalized' = checkpoint_finalized,
      old_set_signers' = Set(0, 1, 2),
      new_set_signers' = new_set_signers,
      activated_epoch' = activated_epoch,
      activation_anchor_handoff_id' = activation_anchor_handoff_id,
    }
    else if (phase == 2) all {
      phase' = 3,
      checkpoint_finalized' = checkpoint_finalized,
      old_set_signers' = old_set_signers,
      new_set_signers' = Set(1, 2, 3),
      activated_epoch' = activated_epoch,
      activation_anchor_handoff_id' = activation_anchor_handoff_id,
    }
    else all {
      phase' = 4,
      checkpoint_finalized' = checkpoint_finalized,
      old_set_signers' = old_set_signers,
      new_set_signers' = new_set_signers,
      activated_epoch' = 8,
      activation_anchor_handoff_id' = 2, // MUTANT
    }

  val activationAnchorIsExact =
    activated_epoch == 0 or activation_anchor_handoff_id == HANDOFF_ID
}
