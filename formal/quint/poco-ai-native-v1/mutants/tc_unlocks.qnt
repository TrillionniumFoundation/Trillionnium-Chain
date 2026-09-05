module poco_ai_v1_mutant_tc_unlocks {
  // MUTANT: accepting TimeoutCertificateBodyV1 clears the durable locked QC.

  var current_view: int
  var locked_qc_view: int

  action init = all {
    current_view' = 4,
    locked_qc_view' = 2,
  }

  action step = all {
    current_view' = 5,
    locked_qc_view' = 0, // MUTANT
  }

  val tcNeverUnlocks = locked_qc_view == 2
}
