module poco_ai_v1_epoch_handoff_activation {
  // Bounded model for the current CEV1 EpochHandoffBodyV1 fixture and its
  // role-separated EpochHandoffSignatureEntryV1 lists. The source and target
  // sets intentionally overlap completely; role weight is never reused.

  type EpochHandoffSignatureEntryV1 = {
    signer_id: int,
    role: int,
    handoff_id: int,
  }

  pure val VALIDATORS = 0.to(3)
  pure val SIGNER_BATCHES = Set(
    Set(0), Set(1), Set(2), Set(3),
    Set(0, 1), Set(0, 2), Set(0, 3),
    Set(1, 2), Set(1, 3), Set(2, 3),
    Set(0, 1, 2), Set(0, 1, 3), Set(0, 2, 3), Set(1, 2, 3),
    Set(0, 1, 2, 3)
  )
  pure val HANDOFF_ID = 1
  pure val OLD_EPOCH = 7
  pure val NEW_EPOCH = 8
  pure val TERMINAL_HEIGHT = 99
  pure val ACTIVATION_HEIGHT = 100
  pure val INITIAL_NEW_VIEW = 1
  pure val QUORUM_THRESHOLD = 3

  var checkpoint_finalized: bool
  var old_set_signatures: Set[EpochHandoffSignatureEntryV1]
  var new_set_signatures: Set[EpochHandoffSignatureEntryV1]
  var activated_epoch: int
  var activated_height: int
  var activation_anchor_handoff_id: int
  var initial_new_view: int

  def oldSigners(handoff_id) =
    old_set_signatures
      .filter(entry => entry.handoff_id == handoff_id and entry.role == 0)
      .map(entry => entry.signer_id)

  def newSigners(handoff_id) =
    new_set_signatures
      .filter(entry => entry.handoff_id == handoff_id and entry.role == 1)
      .map(entry => entry.signer_id)

  // All weights are 1 in the candidate vector; these are role-specific
  // weighted sums, not a union of overlapping identities.
  def oldSignedWeight(handoff_id) = oldSigners(handoff_id).size()
  def newSignedWeight(handoff_id) = newSigners(handoff_id).size()
  def hasOldQuorum(handoff_id) =
    oldSignedWeight(handoff_id) >= QUORUM_THRESHOLD
  def hasNewQuorum(handoff_id) =
    newSignedWeight(handoff_id) >= QUORUM_THRESHOLD

  action init = all {
    checkpoint_finalized' = false,
    old_set_signatures' = Set(),
    new_set_signatures' = Set(),
    activated_epoch' = 0,
    activated_height' = 0,
    activation_anchor_handoff_id' = 0,
    initial_new_view' = 0,
  }

  action finalizeOldEpochCheckpoint = all {
    checkpoint_finalized' = true,
    old_set_signatures' = old_set_signatures,
    new_set_signatures' = new_set_signatures,
    activated_epoch' = activated_epoch,
    activated_height' = activated_height,
    activation_anchor_handoff_id' = activation_anchor_handoff_id,
    initial_new_view' = initial_new_view,
  }

  action signOldRole(signers) = all {
    checkpoint_finalized,
    SIGNER_BATCHES.contains(signers),
    signers.forall(signer_id => not(old_set_signatures.contains({
      signer_id: signer_id,
      role: 0,
      handoff_id: HANDOFF_ID,
    }))),
    checkpoint_finalized' = checkpoint_finalized,
    old_set_signatures' = old_set_signatures.union(signers.map(signer_id => {
      signer_id: signer_id,
      role: 0,
      handoff_id: HANDOFF_ID,
    })),
    new_set_signatures' = new_set_signatures,
    activated_epoch' = activated_epoch,
    activated_height' = activated_height,
    activation_anchor_handoff_id' = activation_anchor_handoff_id,
    initial_new_view' = initial_new_view,
  }

  action signNewRole(signers) = all {
    checkpoint_finalized,
    SIGNER_BATCHES.contains(signers),
    signers.forall(signer_id => not(new_set_signatures.contains({
      signer_id: signer_id,
      role: 1,
      handoff_id: HANDOFF_ID,
    }))),
    checkpoint_finalized' = checkpoint_finalized,
    old_set_signatures' = old_set_signatures,
    new_set_signatures' = new_set_signatures.union(signers.map(signer_id => {
      signer_id: signer_id,
      role: 1,
      handoff_id: HANDOFF_ID,
    })),
    activated_epoch' = activated_epoch,
    activated_height' = activated_height,
    activation_anchor_handoff_id' = activation_anchor_handoff_id,
    initial_new_view' = initial_new_view,
  }

  action activateSuccessorEpoch = all {
    activated_epoch == 0,
    checkpoint_finalized,
    hasOldQuorum(HANDOFF_ID),
    hasNewQuorum(HANDOFF_ID),
    checkpoint_finalized' = checkpoint_finalized,
    old_set_signatures' = old_set_signatures,
    new_set_signatures' = new_set_signatures,
    activated_epoch' = NEW_EPOCH,
    activated_height' = ACTIVATION_HEIGHT,
    activation_anchor_handoff_id' = HANDOFF_ID,
    initial_new_view' = INITIAL_NEW_VIEW,
  }

  action step = {
    nondet signers = SIGNER_BATCHES.oneOf()
    any {
      finalizeOldEpochCheckpoint,
      signOldRole(signers),
      signNewRole(signers),
      activateSuccessorEpoch,
    }
  }

  action legalActivationStep =
    if (not(checkpoint_finalized)) finalizeOldEpochCheckpoint
    else if (not(hasOldQuorum(HANDOFF_ID))) signOldRole(Set(0, 1, 2))
    else if (not(hasNewQuorum(HANDOFF_ID))) signNewRole(Set(1, 2, 3))
    else activateSuccessorEpoch

  val handoffRolesAreSeparated = all {
    old_set_signatures.forall(entry => entry.role == 0),
    new_set_signatures.forall(entry => entry.role == 1),
  }

  val activationRequiresFinalizedCheckpoint =
    activated_epoch == 0 or checkpoint_finalized

  val activationRequiresDualWeightedQuorum =
    activated_epoch == 0 or all {
      hasOldQuorum(activation_anchor_handoff_id),
      hasNewQuorum(activation_anchor_handoff_id),
    }

  val activationAnchorIsExact =
    activated_epoch == 0 or activation_anchor_handoff_id == HANDOFF_ID

  val activationCoordinatesAreMonotonic =
    activated_epoch == 0 or all {
      activated_epoch == OLD_EPOCH + 1,
      activated_epoch == NEW_EPOCH,
      activated_height == TERMINAL_HEIGHT + 1,
      activated_height == ACTIVATION_HEIGHT,
      initial_new_view == INITIAL_NEW_VIEW,
    }

  val legalActivationNotReached = activated_epoch == 0
}
