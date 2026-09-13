module sign_before_persist {
  // Deliberately broken model retained as mutation evidence. `sign` accepts a
  // volatile request before it reaches the journal, so a crash can erase the
  // only decision record after a signature has escaped.

  type Decision = { validator: int, view: int, block: int }

  pure val VALIDATORS = 0.to(3)
  pure val HONEST = Set(1, 2, 3)
  pure val VIEWS = 1.to(2)
  pure val BLOCKS = 1.to(2)

  var pending: Set[Decision]
  var journal: Set[Decision]
  var signatures: Set[Decision]

  action init = all {
    pending' = Set(),
    journal' = Set(),
    signatures' = Set(),
  }

  action request(decision) = all {
    VALIDATORS.contains(decision.validator),
    VIEWS.contains(decision.view),
    BLOCKS.contains(decision.block),
    pending' = pending.union(Set(decision)),
    journal' = journal,
    signatures' = signatures,
  }

  action persist(decision) = all {
    pending.contains(decision),
    pending' = pending,
    journal' = journal.union(Set(decision)),
    signatures' = signatures,
  }

  action sign(decision) = all {
    // MUTANT: this must be journal.contains(decision).
    pending.contains(decision),
    pending' = pending.filter(other => other != decision),
    journal' = journal,
    signatures' = signatures.union(Set(decision)),
  }

  action crash(validator) = all {
    VALIDATORS.contains(validator),
    pending' = pending.filter(decision => decision.validator != validator),
    journal' = journal,
    signatures' = signatures,
  }

  action step = {
    nondet validator = HONEST.oneOf()
    nondet protocolView = VIEWS.oneOf()
    nondet block = BLOCKS.oneOf()
    val decision = { validator: validator, view: protocolView, block: block }
    any {
      request(decision),
      persist(decision),
      sign(decision),
      crash(validator),
    }
  }

  val signatureCoveredByJournal =
    signatures.forall(decision => journal.contains(decision))
}
