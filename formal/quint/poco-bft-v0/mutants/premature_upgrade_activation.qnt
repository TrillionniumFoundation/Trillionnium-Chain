module premature_upgrade_activation {
  // Deliberately broken upgrade transition. It finalizes an UpgradePlan notice
  // and immediately activates at height 9, before checkpoint/seal finality,
  // either handoff quorum, the declared height, or the first new block.

  pure val DECLARED_ACTIVATION_HEIGHT = 13

  var noticeFinal: bool
  var checkpointFinal: bool
  var seal1Final: bool
  var seal2Final: bool
  var oldQuorum: bool
  var newQuorum: bool
  var finalizedHeight: int
  var activePlan: int
  var firstNewBlockFinal: bool

  action init = all {
    noticeFinal' = false,
    checkpointFinal' = false,
    seal1Final' = false,
    seal2Final' = false,
    oldQuorum' = false,
    newQuorum' = false,
    finalizedHeight' = 8,
    activePlan' = 0,
    firstNewBlockFinal' = false,
  }

  action activateAfterNoticeOnly = all {
    noticeFinal' = true,
    checkpointFinal' = false,
    seal1Final' = false,
    seal2Final' = false,
    oldQuorum' = false,
    newQuorum' = false,
    finalizedHeight' = 9,
    activePlan' = 1, // MUTANT: activation ignores every remaining guard.
    firstNewBlockFinal' = false,
  }

  action step = activateAfterNoticeOnly

  val activationRequiresAllPrerequisites =
    activePlan == 0 or all {
      noticeFinal,
      checkpointFinal,
      seal1Final,
      seal2Final,
      oldQuorum,
      newQuorum,
      finalizedHeight == DECLARED_ACTIVATION_HEIGHT,
      firstNewBlockFinal,
    }
}
