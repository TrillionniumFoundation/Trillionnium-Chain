module poco_ai_v1_timeout_lock {
  // Bounded transition model for TimeoutCertificateBodyV1. A valid TC binds
  // target_view=timed_out_view+1 and a selected verified safe parent. It may
  // advance current_view/high_qc_view, but has no QC, lock, or finality power.

  pure val TIMED_OUT_VIEWS = 4.to(8)
  pure val SAFE_PARENT_QC_VIEWS = 0.to(7)

  var current_view: int
  var high_qc_view: int
  var locked_qc_view: int
  var finalized_height: int
  var certified_block_count: int
  var accepted_tc_count: int
  var last_timed_out_view: int
  var last_target_view: int

  action init = all {
    current_view' = 4,
    high_qc_view' = 3,
    locked_qc_view' = 2,
    finalized_height' = 7,
    certified_block_count' = 3,
    accepted_tc_count' = 0,
    last_timed_out_view' = 0,
    last_target_view' = 0,
  }

  action acceptTimeoutCertificate(
    timed_out_view,
    target_view,
    selected_safe_parent_qc_view,
  ) = all {
    TIMED_OUT_VIEWS.contains(timed_out_view),
    SAFE_PARENT_QC_VIEWS.contains(selected_safe_parent_qc_view),
    target_view == timed_out_view + 1,
    timed_out_view >= current_view,
    selected_safe_parent_qc_view < target_view,
    current_view' = target_view,
    high_qc_view' =
      if (selected_safe_parent_qc_view > high_qc_view)
      selected_safe_parent_qc_view
      else high_qc_view,
    locked_qc_view' = locked_qc_view,
    finalized_height' = finalized_height,
    certified_block_count' = certified_block_count,
    accepted_tc_count' = accepted_tc_count + 1,
    last_timed_out_view' = timed_out_view,
    last_target_view' = target_view,
  }

  action step = {
    nondet timed_out_view = TIMED_OUT_VIEWS.oneOf()
    nondet selected_safe_parent_qc_view = SAFE_PARENT_QC_VIEWS.oneOf()
    acceptTimeoutCertificate(
      timed_out_view,
      timed_out_view + 1,
      selected_safe_parent_qc_view,
    )
  }

  action legalTimeoutStep =
    acceptTimeoutCertificate(4, 5, 3)

  val tcTargetIsImmediateSuccessor =
    accepted_tc_count == 0 or last_target_view == last_timed_out_view + 1

  val tcNeverUnlocks = locked_qc_view == 2

  val tcNeverCertifiesOrFinalizes =
    certified_block_count == 3 and finalized_height == 7

  val tcViewStateIsMonotonic = current_view >= 4 and high_qc_view >= 3

  val legalTimeoutNotReached = accepted_tc_count == 0
}
