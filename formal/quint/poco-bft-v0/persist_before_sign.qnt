module persist_before_sign {
  // Explicit crash-boundary model for the v0 persist-before-sign contract.
  // Validator 0 is Byzantine. The invariant is scoped to validators 1..3.

  type Decision = { validator: int, view: int, block: int }

  pure val VALIDATORS = 0.to(3)
  pure val HONEST = Set(1, 2, 3)
  pure val VIEWS = 1.to(4)
  pure val BLOCKS = 1.to(2)

  var pending: Set[Decision]
  var journal: Set[Decision]
  var signatures: Set[Decision]
  var lastVotedView: int -> int

  pure def sameSlot(left, right) =
    left.validator == right.validator and left.view == right.view

  pure def conflicts(left, right) =
    sameSlot(left, right) and left.block != right.block

  action init = all {
    pending' = Set(),
    journal' = Set(),
    signatures' = Set(),
    lastVotedView' = VALIDATORS.mapBy(_ => 0),
  }

  action request(decision) = all {
    VALIDATORS.contains(decision.validator),
    VIEWS.contains(decision.view),
    BLOCKS.contains(decision.block),
    decision.validator == 0 or all {
      decision.view > lastVotedView.get(decision.validator),
      not(pending.exists(other => other.validator == decision.validator)),
      not(journal.exists(other => conflicts(other, decision))),
    },
    pending' = pending.union(Set(decision)),
    journal' = journal,
    signatures' = signatures,
    lastVotedView' = lastVotedView,
  }

  action persist(decision) = all {
    pending.contains(decision),
    decision.validator == 0 or all {
      decision.view > lastVotedView.get(decision.validator),
      not(journal.exists(other => conflicts(other, decision))),
    },
    pending' = pending,
    journal' = journal.union(Set(decision)),
    signatures' = signatures,
    lastVotedView' =
      if (HONEST.contains(decision.validator))
      lastVotedView.set(decision.validator, decision.view)
      else lastVotedView,
  }

  action sign(decision) = all {
    // This guard is the durability boundary: volatile intent is insufficient.
    journal.contains(decision),
    pending' = pending.filter(other => other != decision),
    journal' = journal,
    signatures' = signatures.union(Set(decision)),
    lastVotedView' = lastVotedView,
  }

  action crash(validator) = all {
    VALIDATORS.contains(validator),
    // A crash destroys only volatile requests. Durable decisions, monotonic
    // views, and already released signatures survive recovery unchanged.
    pending' = pending.filter(decision => decision.validator != validator),
    journal' = journal,
    signatures' = signatures,
    lastVotedView' = lastVotedView,
  }

  action step = {
    nondet validator = VALIDATORS.oneOf()
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

  /// Every honest released signature is covered by the durable journal.
  val signatureCoveredByJournal =
    signatures.forall(decision =>
      not(HONEST.contains(decision.validator)) or journal.contains(decision))

  /// Honest validators never durably authorize two blocks in one view.
  val durableNonEquivocationAcrossCrash =
    journal.forall(left =>
      journal.forall(right =>
        not(HONEST.contains(left.validator)) or not(conflicts(left, right))))

  /// Recovery cannot lower the durable monotonic view watermark.
  val journalCoveredByViewWatermark =
    journal.forall(decision =>
      not(HONEST.contains(decision.validator))
        or decision.view <= lastVotedView.get(decision.validator))
}
