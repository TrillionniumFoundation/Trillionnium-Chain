module poco_ai_v1_mutant_two_chain_finality {
  // MUTANT: B0 is finalized once B0 and its direct child B1 have QCs, without
  // the required certified grandchild B2 and its third Vote statement/QC.

  var phase: int
  var certified_blocks: Set[int]
  var finalized_blocks: Set[int]

  action init = all {
    phase' = 0,
    certified_blocks' = Set(0),
    finalized_blocks' = Set(),
  }

  action step =
    if (phase == 0) all {
      phase' = 1,
      certified_blocks' = certified_blocks.union(Set(1)),
      finalized_blocks' = finalized_blocks,
    }
    else all {
      phase' = 2,
      certified_blocks' = certified_blocks.union(Set(3)),
      finalized_blocks' = finalized_blocks.union(Set(1)), // MUTANT
    }

  val finalityRequiresThreeChain =
    finalized_blocks.size() == 0 or certified_blocks.contains(5)
}
