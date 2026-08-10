module tc_high_qc_selection {
  // Bounded validation model for a timeout certificate whose timeout entries
  // carry heterogeneous high-QC references. A timeout entry binds the exact
  // digest of one QC. The transport-level reference table is a set, so each
  // referenced QC is present exactly once even when several entries point to
  // it.

  type TimeoutEntry = { validator: int, qcDigest: int }

  pure val VALIDATORS = 0.to(3)
  pure val QC_DIGESTS = Set(11, 22, 23, 24, 34)
  pure val QUORUM = 3
  pure val TIMED_OUT_VIEW = 5

  // The digest is an opaque identifier. These two projections abstract the
  // fields obtained after validating and decoding the exact referenced QC.
  pure def qcView(digest) =
    if (digest == 11) 1
    else if (digest == 22 or digest == 23 or digest == 24) 2
    else 3

  pure def qcBlock(digest) =
    if (digest == 11) 10
    else if (digest == 22 or digest == 24) 20
    else if (digest == 23) 21
    else 30

  pure def outranks(leftDigest, rightDigest) =
    qcView(leftDigest) > qcView(rightDigest)
      or all {
        qcView(leftDigest) == qcView(rightDigest),
        any {
          qcBlock(leftDigest) > qcBlock(rightDigest),
          all {
            qcBlock(leftDigest) == qcBlock(rightDigest),
            leftDigest > rightDigest,
          },
        },
      }

  var entries: Set[TimeoutEntry]
  var referencedQcs: Set[int]
  var currentView: int
  var selectedQcDigest: int
  var accepted: bool
  var halted: bool
  var validated: bool

  def entryValidators = entries.map(entry => entry.validator)
  def entryQcDigests = entries.map(entry => entry.qcDigest)

  def hasTimeoutQuorum = entryValidators.size() >= QUORUM

  def hasSameViewConflict =
    referencedQcs.exists(left =>
      referencedQcs.exists(right => all {
        left != right,
        qcView(left) == qcView(right),
        qcBlock(left) != qcBlock(right),
      }))

  def isCanonicalSelection(digest) = all {
    referencedQcs.contains(digest),
    referencedQcs.forall(other => not(outranks(other, digest))),
  }

  def canonicalDigest =
    if (referencedQcs.contains(34)) 34
    else if (referencedQcs.contains(23)) 23
    else if (referencedQcs.contains(24)) 24
    else if (referencedQcs.contains(22)) 22
    else 11

  action init = all {
    entries' = Set(),
    referencedQcs' = Set(),
    currentView' = TIMED_OUT_VIEW,
    selectedQcDigest' = 0,
    accepted' = false,
    halted' = false,
    validated' = false,
  }

  // A complete non-conflicting TC used by the bounded reachability gate.
  // Its entries carry three different high QCs; digest 34 wins by (view,
  // block id, QC digest).
  action initHeterogeneous = all {
    entries' = Set(
      { validator: 0, qcDigest: 11 },
      { validator: 1, qcDigest: 22 },
      { validator: 2, qcDigest: 34 }),
    referencedQcs' = Set(11, 22, 34),
    currentView' = TIMED_OUT_VIEW,
    selectedQcDigest' = 0,
    accepted' = false,
    halted' = false,
    validated' = false,
  }

  // A complete but internally conflicting TC used to exercise the fail-closed
  // branch: digests 22 and 23 certify different blocks in the same view.
  action initConflicting = all {
    entries' = Set(
      { validator: 0, qcDigest: 11 },
      { validator: 1, qcDigest: 22 },
      { validator: 2, qcDigest: 23 }),
    referencedQcs' = Set(11, 22, 23),
    currentView' = TIMED_OUT_VIEW,
    selectedQcDigest' = 0,
    accepted' = false,
    halted' = false,
    validated' = false,
  }

  // Digests 22 and 24 certify the same block in the same view, as can happen
  // when different signer subsets produce different QC encodings. This is not
  // a safety conflict. Lexicographic digest order makes 24 the unique choice.
  action initSameViewBlockDifferentDigests = all {
    entries' = Set(
      { validator: 0, qcDigest: 11 },
      { validator: 1, qcDigest: 22 },
      { validator: 2, qcDigest: 24 }),
    referencedQcs' = Set(11, 22, 24),
    currentView' = TIMED_OUT_VIEW,
    selectedQcDigest' = 0,
    accepted' = false,
    halted' = false,
    validated' = false,
  }

  action addTimeoutEntry(validator, qcDigest) = all {
    not(accepted),
    not(halted),
    VALIDATORS.contains(validator),
    QC_DIGESTS.contains(qcDigest),
    qcView(qcDigest) < TIMED_OUT_VIEW,
    not(entries.exists(entry => entry.validator == validator)),
    entries' = entries.union(Set({
      validator: validator,
      qcDigest: qcDigest,
    })),
    referencedQcs' = referencedQcs.union(Set(qcDigest)),
    currentView' = currentView,
    selectedQcDigest' = selectedQcDigest,
    accepted' = accepted,
    halted' = halted,
    validated' = validated,
  }

  // Validation first checks the exact, complete reference table. A same-view,
  // different-block conflict is retained as safety evidence and halts this
  // bounded receiver; it is never accepted and never advances operational
  // view.
  action validateTc = all {
    not(accepted),
    not(halted),
    hasTimeoutQuorum,
    referencedQcs == entryQcDigests,
    referencedQcs.forall(digest => QC_DIGESTS.contains(digest)),
    entries' = entries,
    referencedQcs' = referencedQcs,
    currentView' =
      if (hasSameViewConflict) currentView else TIMED_OUT_VIEW + 1,
    selectedQcDigest' =
      if (hasSameViewConflict) 0 else canonicalDigest,
    accepted' = not(hasSameViewConflict),
    halted' = hasSameViewConflict,
    validated' = true,
  }

  action step = {
    nondet validator = VALIDATORS.oneOf()
    nondet qcDigest = QC_DIGESTS.oneOf()
    any {
      addTimeoutEntry(validator, qcDigest),
      validateTc,
    }
  }

  /// Every entry's exact digest is present and the reference table has no
  /// omitted or unreferenced QCs. Set representation supplies de-duplication.
  val completeUniqueQcReferences = all {
    referencedQcs == entryQcDigests,
    referencedQcs.forall(digest => QC_DIGESTS.contains(digest)),
  }

  /// An accepted TC selects the unique maximum by
  /// (QC view, block id, canonical QC digest bytes). Integers stand in for
  /// lexicographically compared digest bytes in this bounded model.
  val acceptedSelectsCanonicalHighQc =
    not(accepted) or isCanonicalSelection(selectedQcDigest)

  /// QCs for different blocks in one view are evidence of a safety violation.
  /// This receiver preserves the conflict as a halt and rejects the TC.
  val sameViewConflictFailsClosed =
    not(validated) or not(hasSameViewConflict) or all {
      halted,
      not(accepted),
      selectedQcDigest == 0,
      currentView == TIMED_OUT_VIEW,
    }

  val acceptedOnlyWithTimeoutQuorum = not(accepted) or hasTimeoutQuorum

  val haltedReceiverCannotAccept = not(halted) or all {
    not(accepted),
    selectedQcDigest == 0,
  }

  val qcDigestBreaksEqualViewBlockTie = all {
    qcView(22) == qcView(24),
    qcBlock(22) == qcBlock(24),
    outranks(24, 22),
    not(outranks(22, 24)),
  }

  // Reachability targets. CI deliberately falsifies these predicates under
  // the dedicated initializers; they are witnesses, not protocol invariants.
  val heterogeneousSelectionNotReached =
    not(all {
      accepted,
      referencedQcs == Set(11, 22, 34),
      selectedQcDigest == 34,
    })

  val conflictingQcHaltNotReached =
    not(all { halted, hasSameViewConflict })

  val sameViewBlockDigestSelectionNotReached =
    not(all {
      accepted,
      referencedQcs == Set(11, 22, 24),
      selectedQcDigest == 24,
      not(hasSameViewConflict),
    })
}
