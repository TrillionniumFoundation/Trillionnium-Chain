module tc_omits_referenced_qc {
  // Deliberately broken TC builder. Three timeout entries bind three exact QC
  // digests, but digest 22 is omitted from the de-duplicated reference table.

  type TimeoutEntry = { validator: int, qcDigest: int }

  pure val QC_DIGESTS = Set(11, 22, 34)

  var entries: Set[TimeoutEntry]
  var referencedQcs: Set[int]
  var accepted: bool

  def entryQcDigests = entries.map(entry => entry.qcDigest)

  action init = all {
    entries' = Set(),
    referencedQcs' = Set(),
    accepted' = false,
  }

  action buildAndAcceptBrokenTc = all {
    entries' = Set(
      { validator: 0, qcDigest: 11 },
      { validator: 1, qcDigest: 22 },
      { validator: 2, qcDigest: 34 }),
    referencedQcs' = Set(11, 34), // MUTANT: exact QC digest 22 is omitted.
    accepted' = true,
  }

  action step = buildAndAcceptBrokenTc

  val completeUniqueQcReferences = all {
    referencedQcs == entryQcDigests,
    referencedQcs.forall(digest => QC_DIGESTS.contains(digest)),
  }
}
