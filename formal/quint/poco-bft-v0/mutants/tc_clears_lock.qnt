module tc_clears_lock {
  // Deliberately broken TC transition: accepting a TC clears honest locks.

  pure val VALIDATORS = 0.to(3)
  pure val HONEST = Set(1, 2, 3)
  pure val TIMEOUT_VIEWS = 2.to(6)
  pure val QC_VIEWS = 0.to(5)

  var currentView: int
  var highQcView: int
  var lockedView: int -> int

  action init = all {
    currentView' = 2,
    highQcView' = 1,
    lockedView' = VALIDATORS.mapBy(v => if (HONEST.contains(v)) 2 else 0),
  }

  action receiveTc(timedOutView, selectedHighQcView) = all {
    TIMEOUT_VIEWS.contains(timedOutView),
    QC_VIEWS.contains(selectedHighQcView),
    timedOutView >= currentView,
    selectedHighQcView < timedOutView,
    currentView' = timedOutView + 1,
    highQcView' =
      if (selectedHighQcView > highQcView) selectedHighQcView else highQcView,
    lockedView' = VALIDATORS.mapBy(_ => 0), // MUTANT
  }

  action step = {
    nondet timedOutView = TIMEOUT_VIEWS.oneOf()
    nondet selectedHighQcView = QC_VIEWS.oneOf()
    receiveTc(timedOutView, selectedHighQcView)
  }

  val tcDoesNotUnlock =
    HONEST.forall(validator => lockedView.get(validator) >= 2)
}
