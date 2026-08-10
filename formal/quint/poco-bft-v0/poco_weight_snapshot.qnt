module poco_weight_snapshot {
  // Bounded deterministic weight-snapshot model using the exact P0 reference
  // parameters. A regular certificate family is represented by cardinalities
  // rather than 2,904 materialized records: four providers, eleven tasks per
  // provider, six consumers per task, and eleven distinct certificates per
  // (provider, task, consumer) group. This is enough to hit every hierarchical
  // unit cap while keeping the state space reviewable.

  pure val PROVIDERS = 0.to(3)
  pure val VALID_SCENARIO = 1
  pure val DUPLICATE_ID_SCENARIO = 2
  pure val OVERFLOW_SCENARIO = 3
  pure val MALFORMED_SCENARIO = 4
  pure val SCENARIOS = Set(
    VALID_SCENARIO,
    DUPLICATE_ID_SCENARIO,
    OVERFLOW_SCENARIO,
    MALFORMED_SCENARIO)

  // Exact frozen `parameters.toml` values.
  pure val SCALE_PPM = 1000000
  pure val MATURITY_EPOCHS = 2
  pure val MAX_CERTIFICATE_AGE_EPOCHS = 20
  pure val DECAY_STEP_PPM_PER_EPOCH = 50000
  pure val PER_CERTIFICATE_UNIT_CAP = 1000000
  pure val PER_CONSUMER_PROVIDER_EPOCH_UNIT_CAP = 10000000
  pure val PER_TASK_PROVIDER_EPOCH_UNIT_CAP = 50000000
  pure val PER_PROVIDER_EPOCH_UNIT_CAP = 500000000
  pure val UNITS_PER_POWER = 1000000
  pure val BOND_ATOMIC_UNITS_PER_POWER = 1000000000
  pure val MIN_VALIDATOR_POWER = 1
  pure val MAX_VALIDATOR_POWER = 1000000
  pure val MAX_VALIDATOR_SHARE_PPM = 250000
  pure val MAX_TOTAL_VOTING_POWER = 1152921504606846975
  pure val MIN_VALIDATORS = 4
  pure val MAX_VALIDATORS = 100

  pure val SNAPSHOT_EPOCH = 30
  pure val RAW_CERTIFICATE_UNITS = 2000000
  pure val CERTIFICATES_PER_CONSUMER_GROUP = 11
  pure val CONSUMERS_PER_TASK = 6
  pure val TASKS_PER_PROVIDER = 11
  pure val ACTIVE_SLASHABLE_BOND = 400000000000
  pure val CURRENT_POWER = 10

  // Quint 0.32's Rust evaluator accepts only i64 literals, so it cannot hold
  // u128::MAX. This bounded model uses the exact frozen maximum total voting
  // power as a conservative checked-arithmetic sentinel. Every valid fixture
  // intermediate is far below it; a value beyond it fails closed. Full-u128
  // arithmetic still requires implementation vectors outside this model.
  pure val CHECKED_ARITHMETIC_SENTINEL = MAX_TOTAL_VOTING_POWER

  pure def min2(left, right) = if (left < right) left else right
  pure def min3(first, second, third) = min2(min2(first, second), third)

  pure def validModelUnsigned(value) =
    value >= 0 and value <= CHECKED_ARITHMETIC_SENTINEL

  pure def checkedAddValid(left, right) = all {
    validModelUnsigned(left),
    validModelUnsigned(right),
    left <= CHECKED_ARITHMETIC_SENTINEL - right,
  }

  pure def checkedMultiplyValid(left, right) = all {
    validModelUnsigned(left),
    validModelUnsigned(right),
    right == 0 or left <= CHECKED_ARITHMETIC_SENTINEL / right,
  }

  pure def certificateContribution(finalizedEpoch, consumedUnits) =
    if (not(validModelUnsigned(consumedUnits))) 0
    else if (SNAPSHOT_EPOCH < finalizedEpoch + MATURITY_EPOCHS) 0
    else {
      val age = SNAPSHOT_EPOCH - finalizedEpoch - MATURITY_EPOCHS
      if (age >= MAX_CERTIFICATE_AGE_EPOCHS) 0
      else {
        val decayProduct = age * DECAY_STEP_PPM_PER_EPOCH
        val decay =
          if (decayProduct >= SCALE_PPM) 0 else SCALE_PPM - decayProduct
        min2(consumedUnits, PER_CERTIFICATE_UNIT_CAP)
          * decay / SCALE_PPM
      }
    }

  // The same mathematical groups are deliberately partitioned in opposite
  // orders. Checked addition plus caps must produce identical results.
  pure def perCertificateUnits =
    certificateContribution(SNAPSHOT_EPOCH - MATURITY_EPOCHS,
      RAW_CERTIFICATE_UNITS)

  pure def consumerRawForward =
    5 * perCertificateUnits
      + (CERTIFICATES_PER_CONSUMER_GROUP - 5) * perCertificateUnits

  pure def consumerRawReverse =
    (CERTIFICATES_PER_CONSUMER_GROUP - 5) * perCertificateUnits
      + 5 * perCertificateUnits

  pure def consumerCappedForward =
    min2(consumerRawForward, PER_CONSUMER_PROVIDER_EPOCH_UNIT_CAP)

  pure def consumerCappedReverse =
    min2(consumerRawReverse, PER_CONSUMER_PROVIDER_EPOCH_UNIT_CAP)

  pure def taskRawForward =
    2 * consumerCappedForward
      + (CONSUMERS_PER_TASK - 2) * consumerCappedForward

  pure def taskRawReverse =
    (CONSUMERS_PER_TASK - 2) * consumerCappedReverse
      + 2 * consumerCappedReverse

  pure def taskCappedForward =
    min2(taskRawForward, PER_TASK_PROVIDER_EPOCH_UNIT_CAP)

  pure def taskCappedReverse =
    min2(taskRawReverse, PER_TASK_PROVIDER_EPOCH_UNIT_CAP)

  pure def providerRawForward =
    5 * taskCappedForward
      + (TASKS_PER_PROVIDER - 5) * taskCappedForward

  pure def providerRawReverse =
    (TASKS_PER_PROVIDER - 5) * taskCappedReverse
      + 5 * taskCappedReverse

  pure def providerCappedForward =
    min2(providerRawForward, PER_PROVIDER_EPOCH_UNIT_CAP)

  pure def providerCappedReverse =
    min2(providerRawReverse, PER_PROVIDER_EPOCH_UNIT_CAP)

  pure def bondCapacity =
    ACTIVE_SLASHABLE_BOND / BOND_ATOMIC_UNITS_PER_POWER

  pure def rawPowerFrom(providerUnits) = min3(
    providerUnits / UNITS_PER_POWER,
    bondCapacity,
    MAX_VALIDATOR_POWER)

  pure def zeroPowers = PROVIDERS.mapBy(_ => 0)
  pure def currentPowers = PROVIDERS.mapBy(_ => CURRENT_POWER)
  pure def canonicalProviderOrder = PROVIDERS.mapBy(position => position)

  pure def powersFromForwardAggregation =
    PROVIDERS.mapBy(_ => rawPowerFrom(providerCappedForward))

  pure def powersFromReverseAggregation =
    PROVIDERS.mapBy(_ => rawPowerFrom(providerCappedReverse))

  // A separate bounded selection fixture exercises descending raw power and
  // ascending validator ID as the deterministic tie-break. After selection,
  // snapshot encoding returns to canonical ascending provider ID order.
  pure def sortFixturePower(provider) =
    if (provider == 0) 300
    else if (provider == 1 or provider == 2) 400
    else 350

  pure def selectionOrder = PROVIDERS.mapBy(position =>
    if (position == 0) 1
    else if (position == 1) 2
    else if (position == 2) 3
    else 0)

  pure def candidateOutranks(left, right) =
    sortFixturePower(left) > sortFixturePower(right)
      or all {
        sortFixturePower(left) == sortFixturePower(right),
        left < right,
      }

  pure def totalPower(powers) =
    powers.get(0) + powers.get(1) + powers.get(2) + powers.get(3)

  pure def max4(first, second, third, fourth) =
    if (first >= second and first >= third and first >= fourth) first
    else if (second >= third and second >= fourth) second
    else if (third >= fourth) third
    else fourth

  pure def maximumPower(powers) =
    max4(powers.get(0), powers.get(1), powers.get(2), powers.get(3))

  pure def structuralPowerBounds(powers) = {
    val total = totalPower(powers)
    val maximum = maximumPower(powers)
    all {
      PROVIDERS.size() >= MIN_VALIDATORS,
      PROVIDERS.size() <= MAX_VALIDATORS,
      PROVIDERS.forall(provider => all {
        powers.get(provider) >= MIN_VALIDATOR_POWER,
        powers.get(provider) <= bondCapacity,
        powers.get(provider) <= MAX_VALIDATOR_POWER,
        checkedMultiplyValid(
          powers.get(provider), BOND_ATOMIC_UNITS_PER_POWER),
        powers.get(provider) * BOND_ATOMIC_UNITS_PER_POWER
          <= ACTIVE_SLASHABLE_BOND,
      }),
      total > 0,
      total <= MAX_TOTAL_VOTING_POWER,
      checkedMultiplyValid(3, maximum),
      3 * maximum < total,
      checkedMultiplyValid(maximum, SCALE_PPM),
      checkedMultiplyValid(MAX_VALIDATOR_SHARE_PPM, total),
      maximum * SCALE_PPM <= MAX_VALIDATOR_SHARE_PPM * total,
    }
  }

  var scenario: int
  var forwardComputed: bool
  var reverseComputed: bool
  var forwardCandidatePowers: int -> int
  var reverseCandidatePowers: int -> int
  var forwardCommittedPowers: int -> int
  var reverseCommittedPowers: int -> int
  var forwardOrder: int -> int
  var reverseOrder: int -> int
  var forwardFallback: bool
  var reverseFallback: bool
  var forwardError: bool
  var reverseError: bool

  def scenarioHasError =
    scenario == DUPLICATE_ID_SCENARIO
      or scenario == OVERFLOW_SCENARIO
      or scenario == MALFORMED_SCENARIO

  action initScenario(chosenScenario) = all {
    SCENARIOS.contains(chosenScenario),
    scenario' = chosenScenario,
    forwardComputed' = false,
    reverseComputed' = false,
    forwardCandidatePowers' = zeroPowers,
    reverseCandidatePowers' = zeroPowers,
    forwardCommittedPowers' = currentPowers,
    reverseCommittedPowers' = currentPowers,
    forwardOrder' = canonicalProviderOrder,
    reverseOrder' = canonicalProviderOrder,
    forwardFallback' = false,
    reverseFallback' = false,
    forwardError' = false,
    reverseError' = false,
  }

  action initValid = initScenario(VALID_SCENARIO)
  action initDuplicate = initScenario(DUPLICATE_ID_SCENARIO)
  action initOverflow = initScenario(OVERFLOW_SCENARIO)
  action initMalformed = initScenario(MALFORMED_SCENARIO)

  action init = any {
    initValid,
    initDuplicate,
    initOverflow,
    initMalformed,
  }

  // In shadow, valid candidate powers are committed only as diagnostics. The
  // effective next set remains the canonical current set. Any duplicate,
  // arithmetic overflow, or malformed-state error atomically invalidates the
  // entire candidate and uses the same current-set fallback.
  action computeForward = all {
    not(forwardComputed),
    scenario' = scenario,
    forwardComputed' = true,
    reverseComputed' = reverseComputed,
    forwardCandidatePowers' =
      if (scenarioHasError) zeroPowers else powersFromForwardAggregation,
    reverseCandidatePowers' = reverseCandidatePowers,
    forwardCommittedPowers' = currentPowers,
    reverseCommittedPowers' = reverseCommittedPowers,
    forwardOrder' = canonicalProviderOrder,
    reverseOrder' = reverseOrder,
    forwardFallback' = scenarioHasError,
    reverseFallback' = reverseFallback,
    forwardError' = scenarioHasError,
    reverseError' = reverseError,
  }

  action computeReverse = all {
    not(reverseComputed),
    scenario' = scenario,
    forwardComputed' = forwardComputed,
    reverseComputed' = true,
    forwardCandidatePowers' = forwardCandidatePowers,
    reverseCandidatePowers' =
      if (scenarioHasError) zeroPowers else powersFromReverseAggregation,
    forwardCommittedPowers' = forwardCommittedPowers,
    reverseCommittedPowers' = currentPowers,
    forwardOrder' = forwardOrder,
    reverseOrder' = canonicalProviderOrder,
    forwardFallback' = forwardFallback,
    reverseFallback' = scenarioHasError,
    forwardError' = forwardError,
    reverseError' = scenarioHasError,
  }

  action step = any {
    computeForward,
    computeReverse,
  }

  /// Exact maturity and age boundaries use floor-decayed, per-cert-capped
  /// units. Immature and expired certificates contribute zero.
  val maturityAgeDecayAndPerCertificateCap = all {
    perCertificateUnits == PER_CERTIFICATE_UNIT_CAP,
    certificateContribution(29, RAW_CERTIFICATE_UNITS) == 0,
    certificateContribution(28, RAW_CERTIFICATE_UNITS)
      == PER_CERTIFICATE_UNIT_CAP,
    certificateContribution(18, RAW_CERTIFICATE_UNITS) == 500000,
    certificateContribution(8, RAW_CERTIFICATE_UNITS) == 0,
  }

  /// All frozen hierarchy caps are exercised, not merely asserted as loose
  /// upper bounds.
  val hierarchicalCapsHitInFrozenOrder = all {
    PROVIDERS.size() * TASKS_PER_PROVIDER * CONSUMERS_PER_TASK
      * CERTIFICATES_PER_CONSUMER_GROUP == 2904,
    consumerRawForward == 11000000,
    consumerCappedForward == PER_CONSUMER_PROVIDER_EPOCH_UNIT_CAP,
    taskRawForward == 60000000,
    taskCappedForward == PER_TASK_PROVIDER_EPOCH_UNIT_CAP,
    providerRawForward == 550000000,
    providerCappedForward == PER_PROVIDER_EPOCH_UNIT_CAP,
    providerCappedReverse == providerCappedForward,
  }

  /// Opposite enumeration orders give byte-structurally identical bounded
  /// outputs: candidate powers, shadow committed powers, fallback/error bits,
  /// and canonical validator ordering.
  val identicalInputProducesUniqueSnapshot =
    not(forwardComputed and reverseComputed) or all {
      forwardCandidatePowers == reverseCandidatePowers,
      forwardCommittedPowers == reverseCommittedPowers,
      forwardOrder == reverseOrder,
      forwardFallback == reverseFallback,
      forwardError == reverseError,
    }

  val canonicalAggregationIsOrderIndependent = all {
    consumerRawForward == consumerRawReverse,
    consumerCappedForward == consumerCappedReverse,
    taskRawForward == taskRawReverse,
    taskCappedForward == taskCappedReverse,
    providerRawForward == providerRawReverse,
    providerCappedForward == providerCappedReverse,
  }

  val deterministicRawThenIdSelectionOrder = all {
    PROVIDERS.map(position => selectionOrder.get(position)).size()
      == PROVIDERS.size(),
    PROVIDERS.forall(leftPosition =>
      PROVIDERS.forall(rightPosition =>
        leftPosition >= rightPosition
          or candidateOutranks(
            selectionOrder.get(leftPosition),
            selectionOrder.get(rightPosition)))),
    canonicalProviderOrder == PROVIDERS.mapBy(position => position),
  }

  val duplicateCertificateFailsClosed =
    scenario != DUPLICATE_ID_SCENARIO or all {
      not(forwardComputed) or all {
        forwardError,
        forwardFallback,
        forwardCandidatePowers == zeroPowers,
        forwardCommittedPowers == currentPowers,
      },
      not(reverseComputed) or all {
        reverseError,
        reverseFallback,
        reverseCandidatePowers == zeroPowers,
        reverseCommittedPowers == currentPowers,
      },
    }

  val errorAndOverflowFailClosed = all {
    not(checkedAddValid(CHECKED_ARITHMETIC_SENTINEL, 1)),
    not(checkedMultiplyValid(CHECKED_ARITHMETIC_SENTINEL, 2)),
    not(validModelUnsigned(-1)),
    not(scenarioHasError) or all {
      not(forwardComputed) or all {
        forwardFallback,
        forwardCandidatePowers == zeroPowers,
        forwardCommittedPowers == currentPowers,
      },
      not(reverseComputed) or all {
        reverseFallback,
        reverseCandidatePowers == zeroPowers,
        reverseCommittedPowers == currentPowers,
      },
    },
  }

  val candidateAndCommittedPowerBounds = all {
    not(forwardComputed) or all {
      forwardFallback or all {
        structuralPowerBounds(forwardCandidatePowers),
        PROVIDERS.forall(provider =>
          forwardCandidatePowers.get(provider)
            <= providerCappedForward / UNITS_PER_POWER),
      },
      structuralPowerBounds(forwardCommittedPowers),
    },
    not(reverseComputed) or all {
      reverseFallback or all {
        structuralPowerBounds(reverseCandidatePowers),
        PROVIDERS.forall(provider =>
          reverseCandidatePowers.get(provider)
            <= providerCappedReverse / UNITS_PER_POWER),
      },
      structuralPowerBounds(reverseCommittedPowers),
    },
  }

  val shadowAlwaysCarriesCanonicalCurrentSet = all {
    not(forwardComputed) or all {
      forwardCommittedPowers == currentPowers,
      forwardOrder == canonicalProviderOrder,
    },
    not(reverseComputed) or all {
      reverseCommittedPowers == currentPowers,
      reverseOrder == canonicalProviderOrder,
    },
  }

  val pocoWeightSnapshotSafety = all {
    maturityAgeDecayAndPerCertificateCap,
    hierarchicalCapsHitInFrozenOrder,
    identicalInputProducesUniqueSnapshot,
    canonicalAggregationIsOrderIndependent,
    deterministicRawThenIdSelectionOrder,
    duplicateCertificateFailsClosed,
    errorAndOverflowFailClosed,
    candidateAndCommittedPowerBounds,
    shadowAlwaysCarriesCanonicalCurrentSet,
  }

  // Reachability targets. CI falsifies them with explicit initializers; these
  // are bounded coverage evidence rather than safety invariants.
  val legalSnapshotNotReached =
    not(all {
      forwardComputed,
      reverseComputed,
      not(forwardFallback),
      forwardCandidatePowers == PROVIDERS.mapBy(_ => 400),
      forwardCommittedPowers == currentPowers,
    })

  val duplicateFallbackNotReached =
    not(all {
      forwardComputed,
      reverseComputed,
      forwardFallback,
      reverseFallback,
      forwardCandidatePowers == zeroPowers,
      reverseCandidatePowers == zeroPowers,
    })

  val overflowFallbackNotReached = duplicateFallbackNotReached
}
