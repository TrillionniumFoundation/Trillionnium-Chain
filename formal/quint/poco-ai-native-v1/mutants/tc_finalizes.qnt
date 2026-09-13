module poco_ai_v1_mutant_tc_finalizes {
  // MUTANT: a TC advances view and incorrectly advances order finality despite
  // carrying no VoteStatementBodyV1 quorum certificate or three-chain.

  var current_view: int
  var finalized_height: int

  action init = all {
    current_view' = 4,
    finalized_height' = 7,
  }

  action step = all {
    current_view' = 5,
    finalized_height' = 8, // MUTANT
  }

  val tcNeverFinalizes = finalized_height == 7
}
