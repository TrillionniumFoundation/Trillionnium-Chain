module poco_application_atomicity {
  // Bounded H3b2b1 application-authority kernel. Each operation observes one
  // authenticated source head and either publishes every required
  // cross-entry/JMT/nullifier write at the next committed height or publishes
  // none. Integer identifiers stand for exact, domain-separated wire IDs.

  type CommitRecord = {
    operation: int,
    succeeded: bool,
    requiredWrites: int,
    appliedWrites: int,
    sourceHead: int,
    targetHead: int,
    sourceManifest: int,
    targetManifest: int,
    sourceAuthority: int,
    targetAuthority: int,
  }

  type TargetBoundField = {
    operation: int,
    fieldKind: int,
    fieldHeight: int,
    committedHeight: int,
  }

  type AcceptedCertificate = {
    certificate: int,
    targetHeight: int,
    keyAuthority: bool,
    meterAuthority: bool,
    settlementAuthority: bool,
    measurementAuthority: bool,
    relationshipAuthority: bool,
    lifecycleAuthority: bool,
    replayAuthority: bool,
  }

  type MonotonicAdvance = {
    identity: int,
    sequence: int,
    previous: int,
    current: int,
  }

  type UniqueClaim = { identifier: int, application: int }

  type PruneRecord = {
    operation: int,
    subject: int,
    deleted: bool,
    nullifierInserted: bool,
    countBefore: int,
    countAfter: int,
  }

  type ReplayAttempt = {
    subject: int,
    accepted: bool,
    sourceHead: int,
    targetHead: int,
  }

  type ApplicationState = {
    mode: int,
    stage: int,
    committedHeight: int,
    stateHead: int,
    manifestRevision: int,
    authorityRevision: int,
    sparseNullifierCount: int,
    acceptedCertificates: Set[AcceptedCertificate],
    targetBoundFields: Set[TargetBoundField],
    nonceHistory: Set[MonotonicAdvance],
    registrationHistory: Set[MonotonicAdvance],
    decisionClaims: Set[UniqueClaim],
    nullifierClaims: Set[UniqueClaim],
    pruneRecords: Set[PruneRecord],
    replayAttempts: Set[ReplayAttempt],
    commitRecords: Set[CommitRecord],
    richEntries: Set[int],
    challengeState: int,
    governanceState: int,
    currentRegistrationNonce: int,
  }

  pure val MODE_ACCEPTANCE = 1
  pure val MODE_CHALLENGE = 2
  pure val MODE_GOVERNANCE = 3
  pure val MODE_ROTATION = 4
  pure val MODE_PRUNE = 5
  pure val MODE_FAILURE = 6

  pure val CERTIFICATE = 101
  pure val CHALLENGE = 201
  pure val GOVERNANCE = 301
  pure val VALIDATOR = 401

  pure val OP_ACCEPT = 1001
  pure val OP_OPEN_CHALLENGE = 1002
  pure val OP_RESOLVE_CHALLENGE = 1003
  pure val OP_PROPOSE_GOVERNANCE = 1004
  pure val OP_APPROVE_GOVERNANCE = 1005
  pure val OP_ROTATE_REGISTRATION = 1006
  pure val OP_PRUNE = 1007
  pure val OP_REPLAY = 1008
  pure val OP_REJECT = 1009

  pure val CHALLENGE_NONE = 0
  pure val CHALLENGE_ACCEPTED = 1
  pure val CHALLENGE_PENDING = 2
  pure val CHALLENGE_REJECTED = 3
  pure val GOVERNANCE_NONE = 0
  pure val GOVERNANCE_PROPOSED = 1
  pure val GOVERNANCE_APPROVED = 2

  var app: ApplicationState

  pure def emptyState(mode, height, headValue, manifest, authority) = {
    mode: mode,
    stage: 0,
    committedHeight: height,
    stateHead: headValue,
    manifestRevision: manifest,
    authorityRevision: authority,
    sparseNullifierCount: 0,
    acceptedCertificates: Set(),
    targetBoundFields: Set(),
    nonceHistory: Set(),
    registrationHistory: Set(),
    decisionClaims: Set(),
    nullifierClaims: Set(),
    pruneRecords: Set(),
    replayAttempts: Set(),
    commitRecords: Set(),
    richEntries: Set(),
    challengeState: CHALLENGE_NONE,
    governanceState: GOVERNANCE_NONE,
    currentRegistrationNonce: 0,
  }

  pure def historicalAcceptedCertificate(height) = {
    certificate: CERTIFICATE,
    targetHeight: height,
    keyAuthority: true,
    meterAuthority: true,
    settlementAuthority: true,
    measurementAuthority: true,
    relationshipAuthority: true,
    lifecycleAuthority: true,
    replayAuthority: true,
  }

  pure def successfulCommit(operation, writes, sourceHead, sourceManifest,
      sourceAuthority) = {
    operation: operation,
    succeeded: true,
    requiredWrites: writes,
    appliedWrites: writes,
    sourceHead: sourceHead,
    targetHead: sourceHead + 1,
    sourceManifest: sourceManifest,
    targetManifest: sourceManifest + 1,
    sourceAuthority: sourceAuthority,
    targetAuthority: sourceAuthority + 1,
  }

  pure def failedCommit(operation, sourceHead, sourceManifest,
      sourceAuthority) = {
    operation: operation,
    succeeded: false,
    requiredWrites: 8,
    appliedWrites: 0,
    sourceHead: sourceHead,
    targetHead: sourceHead,
    sourceManifest: sourceManifest,
    targetManifest: sourceManifest,
    sourceAuthority: sourceAuthority,
    targetAuthority: sourceAuthority,
  }

  action initAcceptance =
    app' = emptyState(MODE_ACCEPTANCE, 10, 100, 20, 30)

  action initChallenge =
    app' = {
      mode: MODE_CHALLENGE,
      stage: 0,
      committedHeight: 20,
      stateHead: 200,
      manifestRevision: 40,
      authorityRevision: 50,
      sparseNullifierCount: 1,
      acceptedCertificates: Set(historicalAcceptedCertificate(19)),
      targetBoundFields: Set({
        operation: OP_ACCEPT,
        fieldKind: 1,
        fieldHeight: 19,
        committedHeight: 19,
      }),
      nonceHistory: Set({ identity: 1, sequence: 1, previous: 4, current: 5 }),
      registrationHistory: Set(),
      decisionClaims: Set({ identifier: 701, application: OP_ACCEPT }),
      nullifierClaims: Set({ identifier: 701, application: OP_ACCEPT }),
      pruneRecords: Set(),
      replayAttempts: Set(),
      commitRecords: Set(),
      richEntries: Set(CERTIFICATE),
      challengeState: CHALLENGE_ACCEPTED,
      governanceState: GOVERNANCE_NONE,
      currentRegistrationNonce: 0,
    }

  action initGovernance =
    app' = emptyState(MODE_GOVERNANCE, 30, 300, 60, 70)

  action initRotation =
    app' = {
      mode: MODE_ROTATION,
      stage: 0,
      committedHeight: 40,
      stateHead: 400,
      manifestRevision: 80,
      authorityRevision: 90,
      sparseNullifierCount: 0,
      acceptedCertificates: Set(),
      targetBoundFields: Set({
        operation: 900,
        fieldKind: 7,
        fieldHeight: 39,
        committedHeight: 39,
      }),
      nonceHistory: Set(),
      registrationHistory: Set({
        identity: VALIDATOR,
        sequence: 0,
        previous: 0,
        current: 1,
      }),
      decisionClaims: Set({ identifier: 901, application: 900 }),
      nullifierClaims: Set(),
      pruneRecords: Set(),
      replayAttempts: Set(),
      commitRecords: Set(),
      richEntries: Set(VALIDATOR),
      challengeState: CHALLENGE_NONE,
      governanceState: GOVERNANCE_NONE,
      currentRegistrationNonce: 1,
    }

  action initPrune =
    app' = {
      mode: MODE_PRUNE,
      stage: 0,
      committedHeight: 50,
      stateHead: 500,
      manifestRevision: 100,
      authorityRevision: 110,
      sparseNullifierCount: 0,
      acceptedCertificates: Set(historicalAcceptedCertificate(20)),
      targetBoundFields: Set({
        operation: OP_ACCEPT,
        fieldKind: 1,
        fieldHeight: 20,
        committedHeight: 20,
      }),
      nonceHistory: Set({ identity: 1, sequence: 1, previous: 8, current: 9 }),
      registrationHistory: Set(),
      decisionClaims: Set({ identifier: 702, application: OP_ACCEPT }),
      nullifierClaims: Set(),
      pruneRecords: Set(),
      replayAttempts: Set(),
      commitRecords: Set(),
      richEntries: Set(CERTIFICATE),
      challengeState: CHALLENGE_REJECTED,
      governanceState: GOVERNANCE_NONE,
      currentRegistrationNonce: 0,
    }

  action initFailure =
    app' = emptyState(MODE_FAILURE, 60, 600, 120, 130)

  action init = any {
    initAcceptance,
    initChallenge,
    initGovernance,
    initRotation,
    initPrune,
    initFailure,
  }

  action acceptCertificate = all {
    app.mode == MODE_ACCEPTANCE,
    app.stage == 0,
    not(app.richEntries.contains(CERTIFICATE)),
    app' = {
      mode: app.mode,
      stage: 1,
      committedHeight: 11,
      stateHead: 101,
      manifestRevision: 21,
      authorityRevision: 31,
      sparseNullifierCount: 1,
      acceptedCertificates: Set({
        certificate: CERTIFICATE,
        targetHeight: 11,
        keyAuthority: true,
        meterAuthority: true,
        settlementAuthority: true,
        measurementAuthority: true,
        relationshipAuthority: true,
        lifecycleAuthority: true,
        replayAuthority: true,
      }),
      targetBoundFields: Set(
        { operation: OP_ACCEPT, fieldKind: 1, fieldHeight: 11, committedHeight: 11 },
        { operation: OP_ACCEPT, fieldKind: 2, fieldHeight: 11, committedHeight: 11 },
        { operation: OP_ACCEPT, fieldKind: 3, fieldHeight: 11, committedHeight: 11 },
        { operation: OP_ACCEPT, fieldKind: 4, fieldHeight: 11, committedHeight: 11 }),
      nonceHistory: Set({ identity: 1, sequence: 1, previous: 5, current: 6 }),
      registrationHistory: app.registrationHistory,
      decisionClaims: Set({ identifier: 703, application: OP_ACCEPT }),
      nullifierClaims: Set({ identifier: 703, application: OP_ACCEPT }),
      pruneRecords: app.pruneRecords,
      replayAttempts: app.replayAttempts,
      commitRecords: Set(successfulCommit(OP_ACCEPT, 8, 100, 20, 30)),
      richEntries: Set(CERTIFICATE),
      challengeState: CHALLENGE_ACCEPTED,
      governanceState: app.governanceState,
      currentRegistrationNonce: app.currentRegistrationNonce,
    },
  }

  action openChallenge = all {
    app.mode == MODE_CHALLENGE,
    app.stage == 0,
    app.challengeState == CHALLENGE_ACCEPTED,
    app.richEntries.contains(CERTIFICATE),
    app' = {
      mode: app.mode,
      stage: 1,
      committedHeight: 21,
      stateHead: 201,
      manifestRevision: 41,
      authorityRevision: 51,
      sparseNullifierCount: 2,
      acceptedCertificates: app.acceptedCertificates,
      targetBoundFields: app.targetBoundFields.union(Set({
        operation: OP_OPEN_CHALLENGE,
        fieldKind: 5,
        fieldHeight: 21,
        committedHeight: 21,
      })),
      nonceHistory: app.nonceHistory,
      registrationHistory: app.registrationHistory,
      decisionClaims: app.decisionClaims.union(Set({
        identifier: 704,
        application: OP_OPEN_CHALLENGE,
      })),
      nullifierClaims: app.nullifierClaims.union(Set({
        identifier: 704,
        application: OP_OPEN_CHALLENGE,
      })),
      pruneRecords: app.pruneRecords,
      replayAttempts: app.replayAttempts,
      commitRecords: app.commitRecords.union(Set(
        successfulCommit(OP_OPEN_CHALLENGE, 3, 200, 40, 50))),
      richEntries: app.richEntries,
      challengeState: CHALLENGE_PENDING,
      governanceState: app.governanceState,
      currentRegistrationNonce: app.currentRegistrationNonce,
    },
  }

  action resolveChallenge = all {
    app.mode == MODE_CHALLENGE,
    app.stage == 1,
    app.challengeState == CHALLENGE_PENDING,
    app' = {
      mode: app.mode,
      stage: 2,
      committedHeight: 22,
      stateHead: 202,
      manifestRevision: 42,
      authorityRevision: 52,
      sparseNullifierCount: 3,
      acceptedCertificates: app.acceptedCertificates,
      targetBoundFields: app.targetBoundFields.union(Set({
        operation: OP_RESOLVE_CHALLENGE,
        fieldKind: 6,
        fieldHeight: 22,
        committedHeight: 22,
      })),
      nonceHistory: app.nonceHistory,
      registrationHistory: app.registrationHistory,
      decisionClaims: app.decisionClaims.union(Set({
        identifier: 705,
        application: OP_RESOLVE_CHALLENGE,
      })),
      nullifierClaims: app.nullifierClaims.union(Set({
        identifier: 705,
        application: OP_RESOLVE_CHALLENGE,
      })),
      pruneRecords: app.pruneRecords,
      replayAttempts: app.replayAttempts,
      commitRecords: app.commitRecords.union(Set(
        successfulCommit(OP_RESOLVE_CHALLENGE, 3, 201, 41, 51))),
      richEntries: app.richEntries,
      challengeState: CHALLENGE_REJECTED,
      governanceState: app.governanceState,
      currentRegistrationNonce: app.currentRegistrationNonce,
    },
  }

  action proposeGovernance = all {
    app.mode == MODE_GOVERNANCE,
    app.stage == 0,
    app.governanceState == GOVERNANCE_NONE,
    app' = {
      mode: app.mode,
      stage: 1,
      committedHeight: 31,
      stateHead: 301,
      manifestRevision: 61,
      authorityRevision: 71,
      sparseNullifierCount: 1,
      acceptedCertificates: app.acceptedCertificates,
      targetBoundFields: Set({
        operation: OP_PROPOSE_GOVERNANCE,
        fieldKind: 8,
        fieldHeight: 31,
        committedHeight: 31,
      }),
      nonceHistory: app.nonceHistory,
      registrationHistory: app.registrationHistory,
      decisionClaims: Set({ identifier: 706, application: OP_PROPOSE_GOVERNANCE }),
      nullifierClaims: Set({ identifier: 706, application: OP_PROPOSE_GOVERNANCE }),
      pruneRecords: app.pruneRecords,
      replayAttempts: app.replayAttempts,
      commitRecords: Set(successfulCommit(OP_PROPOSE_GOVERNANCE, 3, 300, 60, 70)),
      richEntries: Set(GOVERNANCE),
      challengeState: app.challengeState,
      governanceState: GOVERNANCE_PROPOSED,
      currentRegistrationNonce: app.currentRegistrationNonce,
    },
  }

  action approveGovernance = all {
    app.mode == MODE_GOVERNANCE,
    app.stage == 1,
    app.governanceState == GOVERNANCE_PROPOSED,
    app' = {
      mode: app.mode,
      stage: 2,
      committedHeight: 32,
      stateHead: 302,
      manifestRevision: 62,
      authorityRevision: 72,
      sparseNullifierCount: 2,
      acceptedCertificates: app.acceptedCertificates,
      targetBoundFields: app.targetBoundFields.union(Set({
        operation: OP_APPROVE_GOVERNANCE,
        fieldKind: 9,
        fieldHeight: 32,
        committedHeight: 32,
      })),
      nonceHistory: app.nonceHistory,
      registrationHistory: app.registrationHistory,
      decisionClaims: app.decisionClaims.union(Set({
        identifier: 707,
        application: OP_APPROVE_GOVERNANCE,
      })),
      nullifierClaims: app.nullifierClaims.union(Set({
        identifier: 707,
        application: OP_APPROVE_GOVERNANCE,
      })),
      pruneRecords: app.pruneRecords,
      replayAttempts: app.replayAttempts,
      commitRecords: app.commitRecords.union(Set(
        successfulCommit(OP_APPROVE_GOVERNANCE, 3, 301, 61, 71))),
      richEntries: app.richEntries,
      challengeState: app.challengeState,
      governanceState: GOVERNANCE_APPROVED,
      currentRegistrationNonce: app.currentRegistrationNonce,
    },
  }

  action rotateRegistration = all {
    app.mode == MODE_ROTATION,
    app.stage == 0,
    app.currentRegistrationNonce == 1,
    app' = {
      mode: app.mode,
      stage: 1,
      committedHeight: 41,
      stateHead: 401,
      manifestRevision: 81,
      authorityRevision: 91,
      sparseNullifierCount: app.sparseNullifierCount,
      acceptedCertificates: app.acceptedCertificates,
      targetBoundFields: app.targetBoundFields.union(Set({
        operation: OP_ROTATE_REGISTRATION,
        fieldKind: 10,
        fieldHeight: 41,
        committedHeight: 41,
      })),
      nonceHistory: app.nonceHistory,
      registrationHistory: app.registrationHistory.union(Set({
        identity: VALIDATOR,
        sequence: 1,
        previous: 1,
        current: 2,
      })),
      decisionClaims: app.decisionClaims.union(Set({
        identifier: 708,
        application: OP_ROTATE_REGISTRATION,
      })),
      nullifierClaims: app.nullifierClaims,
      pruneRecords: app.pruneRecords,
      replayAttempts: app.replayAttempts,
      commitRecords: app.commitRecords.union(Set(
        successfulCommit(OP_ROTATE_REGISTRATION, 3, 400, 80, 90))),
      richEntries: app.richEntries,
      challengeState: app.challengeState,
      governanceState: app.governanceState,
      currentRegistrationNonce: 2,
    },
  }

  action pruneCertificate = all {
    app.mode == MODE_PRUNE,
    app.stage == 0,
    app.richEntries.contains(CERTIFICATE),
    app.challengeState == CHALLENGE_REJECTED,
    app' = {
      mode: app.mode,
      stage: 1,
      committedHeight: 51,
      stateHead: 501,
      manifestRevision: 101,
      authorityRevision: 111,
      sparseNullifierCount: 1,
      acceptedCertificates: app.acceptedCertificates,
      targetBoundFields: app.targetBoundFields.union(Set({
        operation: OP_PRUNE,
        fieldKind: 11,
        fieldHeight: 51,
        committedHeight: 51,
      })),
      nonceHistory: app.nonceHistory,
      registrationHistory: app.registrationHistory,
      decisionClaims: app.decisionClaims,
      nullifierClaims: app.nullifierClaims.union(Set({
        identifier: CERTIFICATE,
        application: OP_PRUNE,
      })),
      pruneRecords: Set({
        operation: OP_PRUNE,
        subject: CERTIFICATE,
        deleted: true,
        nullifierInserted: true,
        countBefore: 0,
        countAfter: 1,
      }),
      replayAttempts: app.replayAttempts,
      commitRecords: Set(successfulCommit(OP_PRUNE, 4, 500, 100, 110)),
      richEntries: Set(),
      challengeState: app.challengeState,
      governanceState: app.governanceState,
      currentRegistrationNonce: app.currentRegistrationNonce,
    },
  }

  action rejectReplayAfterPrune = all {
    app.mode == MODE_PRUNE,
    app.stage == 1,
    not(app.richEntries.contains(CERTIFICATE)),
    app.nullifierClaims.exists(claim => claim.identifier == CERTIFICATE),
    app' = {
      mode: app.mode,
      stage: 2,
      committedHeight: app.committedHeight,
      stateHead: app.stateHead,
      manifestRevision: app.manifestRevision,
      authorityRevision: app.authorityRevision,
      sparseNullifierCount: app.sparseNullifierCount,
      acceptedCertificates: app.acceptedCertificates,
      targetBoundFields: app.targetBoundFields,
      nonceHistory: app.nonceHistory,
      registrationHistory: app.registrationHistory,
      decisionClaims: app.decisionClaims,
      nullifierClaims: app.nullifierClaims,
      pruneRecords: app.pruneRecords,
      replayAttempts: Set({
        subject: CERTIFICATE,
        accepted: false,
        sourceHead: app.stateHead,
        targetHead: app.stateHead,
      }),
      commitRecords: app.commitRecords.union(Set(
        failedCommit(OP_REPLAY, app.stateHead, app.manifestRevision,
          app.authorityRevision))),
      richEntries: app.richEntries,
      challengeState: app.challengeState,
      governanceState: app.governanceState,
      currentRegistrationNonce: app.currentRegistrationNonce,
    },
  }

  action rejectInvalidOperation = all {
    app.mode == MODE_FAILURE,
    app.stage == 0,
    app' = {
      mode: app.mode,
      stage: 1,
      committedHeight: app.committedHeight,
      stateHead: app.stateHead,
      manifestRevision: app.manifestRevision,
      authorityRevision: app.authorityRevision,
      sparseNullifierCount: app.sparseNullifierCount,
      acceptedCertificates: app.acceptedCertificates,
      targetBoundFields: app.targetBoundFields,
      nonceHistory: app.nonceHistory,
      registrationHistory: app.registrationHistory,
      decisionClaims: app.decisionClaims,
      nullifierClaims: app.nullifierClaims,
      pruneRecords: app.pruneRecords,
      replayAttempts: app.replayAttempts,
      commitRecords: Set(failedCommit(
        OP_REJECT, app.stateHead, app.manifestRevision, app.authorityRevision)),
      richEntries: app.richEntries,
      challengeState: app.challengeState,
      governanceState: app.governanceState,
      currentRegistrationNonce: app.currentRegistrationNonce,
    },
  }

  // Retained negative control: a cross-entry operation advances the roots but
  // publishes only seven of its eight required writes.
  action partial_cross_entry_commit = all {
    app.mode == MODE_ACCEPTANCE,
    app.stage == 0,
    app' = {
      mode: app.mode,
      stage: 1,
      committedHeight: 11,
      stateHead: 101,
      manifestRevision: 21,
      authorityRevision: 31,
      sparseNullifierCount: app.sparseNullifierCount,
      acceptedCertificates: app.acceptedCertificates,
      targetBoundFields: app.targetBoundFields,
      nonceHistory: app.nonceHistory,
      registrationHistory: app.registrationHistory,
      decisionClaims: app.decisionClaims,
      nullifierClaims: app.nullifierClaims,
      pruneRecords: app.pruneRecords,
      replayAttempts: app.replayAttempts,
      commitRecords: Set({
        operation: OP_ACCEPT,
        succeeded: true,
        requiredWrites: 8,
        appliedWrites: 7,
        sourceHead: 100,
        targetHead: 101,
        sourceManifest: 20,
        targetManifest: 21,
        sourceAuthority: 30,
        targetAuthority: 31,
      }),
      richEntries: app.richEntries,
      challengeState: app.challengeState,
      governanceState: app.governanceState,
      currentRegistrationNonce: app.currentRegistrationNonce,
    },
  }

  // Retained negative control: pruning deletes the rich group without the
  // required domain-separated sparse-nullifier insertion.
  action prune_without_nullifier = all {
    app.mode == MODE_PRUNE,
    app.stage == 0,
    app.richEntries.contains(CERTIFICATE),
    app' = {
      mode: app.mode,
      stage: 1,
      committedHeight: 51,
      stateHead: 501,
      manifestRevision: 101,
      authorityRevision: 111,
      sparseNullifierCount: 0,
      acceptedCertificates: app.acceptedCertificates,
      targetBoundFields: app.targetBoundFields,
      nonceHistory: app.nonceHistory,
      registrationHistory: app.registrationHistory,
      decisionClaims: app.decisionClaims,
      nullifierClaims: app.nullifierClaims,
      pruneRecords: Set({
        operation: OP_PRUNE,
        subject: CERTIFICATE,
        deleted: true,
        nullifierInserted: false,
        countBefore: 0,
        countAfter: 0,
      }),
      replayAttempts: app.replayAttempts,
      commitRecords: Set(successfulCommit(OP_PRUNE, 3, 500, 100, 110)),
      richEntries: Set(),
      challengeState: app.challengeState,
      governanceState: app.governanceState,
      currentRegistrationNonce: app.currentRegistrationNonce,
    },
  }

  action acceptanceWitnessStep = any { acceptCertificate }
  action challengeWitnessStep = any { openChallenge, resolveChallenge }
  action governanceWitnessStep = any { proposeGovernance, approveGovernance }
  action rotationWitnessStep = any { rotateRegistration }
  action pruneReplayWitnessStep = any { pruneCertificate, rejectReplayAfterPrune }
  action failureRollbackWitnessStep = any { rejectInvalidOperation }
  action partialCrossEntryCommitMutantStep = any { partial_cross_entry_commit }
  action pruneWithoutNullifierMutantStep = any { prune_without_nullifier }

  action step = any {
    acceptCertificate,
    openChallenge,
    resolveChallenge,
    proposeGovernance,
    approveGovernance,
    rotateRegistration,
    pruneCertificate,
    rejectReplayAfterPrune,
    rejectInvalidOperation,
  }

  val allOrNothingCommit =
    app.commitRecords.forall(commit =>
      if (commit.succeeded) all {
        commit.appliedWrites == commit.requiredWrites,
        commit.targetHead == commit.sourceHead + 1,
        commit.targetManifest == commit.sourceManifest + 1,
        commit.targetAuthority == commit.sourceAuthority + 1,
      }
      else all {
        commit.appliedWrites == 0,
        commit.targetHead == commit.sourceHead,
        commit.targetManifest == commit.sourceManifest,
        commit.targetAuthority == commit.sourceAuthority,
      })

  val targetBoundFieldsEqualCommittedHeight =
    app.targetBoundFields.forall(bound =>
      bound.fieldHeight == bound.committedHeight)

  val acceptedCertificateHasAllAuthorities =
    app.acceptedCertificates.forall(certificate => all {
      certificate.keyAuthority,
      certificate.meterAuthority,
      certificate.settlementAuthority,
      certificate.measurementAuthority,
      certificate.relationshipAuthority,
      certificate.lifecycleAuthority,
      certificate.replayAuthority,
      app.targetBoundFields.exists(bound => all {
        bound.fieldKind == 1,
        bound.fieldHeight == certificate.targetHeight,
        bound.committedHeight == certificate.targetHeight,
      }),
    })

  val nonceAndRegistrationHistoryMonotonic = all {
    app.nonceHistory.forall(advance => advance.current > advance.previous),
    app.registrationHistory.forall(advance =>
      advance.current > advance.previous),
    app.registrationHistory.forall(left =>
      app.registrationHistory.forall(right =>
        left.identity != right.identity
          or right.sequence != left.sequence + 1
          or right.previous == left.current)),
    app.registrationHistory.forall(advance =>
      advance.identity != VALIDATOR
        or advance.current <= app.currentRegistrationNonce),
  }

  val decisionAndNullifierAtMostOnce = all {
    app.decisionClaims.forall(claim =>
      app.decisionClaims
        .filter(other => other.identifier == claim.identifier)
        .size() <= 1),
    app.nullifierClaims.forall(claim =>
      app.nullifierClaims
        .filter(other => other.identifier == claim.identifier)
        .size() <= 1),
    app.sparseNullifierCount == app.nullifierClaims.size(),
  }

  val pruneRequiresAtomicSparseNullifierInsertion =
    app.pruneRecords.forall(prune =>
      not(prune.deleted) or all {
        prune.nullifierInserted,
        prune.countAfter == prune.countBefore + 1,
        app.nullifierClaims.exists(claim => all {
          claim.identifier == prune.subject,
          claim.application == prune.operation,
        }),
        not(app.richEntries.contains(prune.subject)),
      })

  val replayRejectedAfterPrune =
    app.replayAttempts.forall(attempt =>
      not(app.pruneRecords.exists(prune => all {
        prune.subject == attempt.subject,
        prune.deleted,
      })) or all {
        not(attempt.accepted),
        attempt.targetHead == attempt.sourceHead,
      })

  val failedOperationLeavesHeadUnchanged =
    app.commitRecords.forall(commit =>
      commit.succeeded or all {
        commit.targetHead == commit.sourceHead,
        commit.targetManifest == commit.sourceManifest,
        commit.targetAuthority == commit.sourceAuthority,
      })

  val pocoApplicationAtomicitySafety = all {
    allOrNothingCommit,
    targetBoundFieldsEqualCommittedHeight,
    acceptedCertificateHasAllAuthorities,
    nonceAndRegistrationHistoryMonotonic,
    decisionAndNullifierAtMostOnce,
    pruneRequiresAtomicSparseNullifierInsertion,
    replayRejectedAfterPrune,
    failedOperationLeavesHeadUnchanged,
  }

  val acceptanceNotReached =
    not(app.acceptedCertificates.exists(certificate =>
      certificate.certificate == CERTIFICATE and certificate.targetHeight == 11))

  val challengeNotReached = app.challengeState != CHALLENGE_REJECTED
  val governanceNotReached = app.governanceState != GOVERNANCE_APPROVED
  val rotationNotReached = app.currentRegistrationNonce != 2

  val pruneReplayRejectNotReached =
    not(all {
      app.pruneRecords.exists(prune => prune.subject == CERTIFICATE),
      app.replayAttempts.exists(attempt => all {
        attempt.subject == CERTIFICATE,
        not(attempt.accepted),
        attempt.sourceHead == attempt.targetHead,
      }),
    })

  val failureRollbackNotReached =
    not(app.commitRecords.exists(commit => all {
      not(commit.succeeded),
      commit.operation == OP_REJECT,
      commit.sourceHead == commit.targetHead,
    }))
}
