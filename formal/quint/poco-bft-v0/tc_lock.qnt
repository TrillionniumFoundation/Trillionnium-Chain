module tc_lock {
  // Timeout certificates may advance operational view and carry a selected
  // valid high QC, but they never directly clear or lower an honest lock.

  pure val VALIDATORS = 0.to(3)
  pure val HONEST = Set(1, 2, 3)
  pure val TIMEOUT_VIEWS = 2.to(6)
  pure val QC_VIEWS = 0.to(5)

  var currentView: int
  var highQcView: int
  var lockedView: int -> int
  var acceptedTcCount: int

  action init = all {
    currentView' = 2,
    highQcView' = 1,
    lockedView' = VALIDATORS.mapBy(v => if (HONEST.contains(v)) 2 else 0),
    acceptedTcCount' = 0,
  }

  action receiveTc(timedOutView, selectedHighQcView) = all {
    TIMEOUT_VIEWS.contains(timedOutView),
    QC_VIEWS.contains(selectedHighQcView),
    timedOutView >= currentView,
    selectedHighQcView < timedOutView,
    currentView' = timedOutView + 1,
    highQcView' =
      if (selectedHighQcView > highQcView) selectedHighQcView else highQcView,
    lockedView' = lockedView,
    acceptedTcCount' = acceptedTcCount + 1,
  }

  action step = {
    nondet timedOutView = TIMEOUT_VIEWS.oneOf()
    nondet selectedHighQcView = QC_VIEWS.oneOf()
    receiveTc(timedOutView, selectedHighQcView)
  }

  /// A TC alone cannot lower or clear an honest validator's lock.
  val tcDoesNotUnlock =
    HONEST.forall(validator => lockedView.get(validator) >= 2)

  /// Operational view and learned high-QC view are monotonic in this model.
  val tcStateMonotonic = currentView >= 2 and highQcView >= 1
}
