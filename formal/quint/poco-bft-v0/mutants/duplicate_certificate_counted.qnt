module duplicate_certificate_counted {
  // Deliberately broken snapshot builder. Two input slots carry the same
  // certificate ID, but the builder sums both instead of invalidating the
  // complete candidate and falling back atomically.

  type CertificateSlot = { slot: int, certificateId: int, units: int }

  pure val INPUT = Set(
    { slot: 0, certificateId: 77, units: 1000000 },
    { slot: 1, certificateId: 77, units: 1000000 })

  var computed: bool
  var candidateUnits: int
  var fallback: bool

  def uniqueCertificateIds = INPUT.map(entry => entry.certificateId)

  action init = all {
    computed' = false,
    candidateUnits' = 0,
    fallback' = false,
  }

  action computeBrokenSnapshot = all {
    computed' = true,
    candidateUnits' = 2000000, // MUTANT: duplicate ID contributes twice.
    fallback' = false,
  }

  action step = computeBrokenSnapshot

  val duplicateCertificateFailsClosed =
    not(computed) or INPUT.size() == uniqueCertificateIds.size() or all {
      fallback,
      candidateUnits == 0,
    }
}
