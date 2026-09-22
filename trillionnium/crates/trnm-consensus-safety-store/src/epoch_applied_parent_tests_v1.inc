use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::os::unix::fs::PermissionsExt;
use trnm_consensus_core::*;
use trnm_consensus_crypto::*;
use trnm_consensus_types::*;

// Obtain the epoch state from the actual old native/Core/journal terminal
// fixture and its strictly verified activation. No persisted state is edited.
#[inline(never)]
fn genuine_epoch_state() -> Box<SafetyState> {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = SigningKey::from_bytes(&[20; 32]);
    let fixture = Box::new(
        crate::test_fixtures::build_native_old_epoch_terminal_v1(directory.path(), |intent| {
            Ok(SignatureBytes::from_array(
                key.sign(intent.signing_root().as_bytes()).to_bytes(),
            ))
        })
        .unwrap(),
    );
    let prepared = fixture
        .application
        .confirm_prepared_checkpoint_execution_v1(
            &fixture.checkpoint,
            &fixture.checkpoint_execution,
        )
        .unwrap();
    let proof = decode_finality_proof_v0_exact(
        &fixture.checkpoint_finality_bytes,
        prepared.old_validator_set(),
        prepared.old_parameters(),
        7000,
    )
    .unwrap();
    let anchor = decode_epoch_anchor_authorization_kernel_v0_exact(
        &fixture.handoff_anchor_bytes,
        prepared.old_validator_set(),
        prepared.new_validator_set(),
    )
    .unwrap();
    let strict = verify_same_version_epoch_activation_authority_strict_v0(
        &proof,
        &prepared.next_epoch_commitment(),
        &anchor,
        prepared.old_validator_set(),
        prepared.old_parameters(),
        prepared.new_validator_set(),
        prepared.new_parameters(),
        &fixture.checkpoint_parent_header,
    )
    .unwrap();
    let runtime = StrictEpochRuntimeContextV1::from_activation_v1(strict).unwrap();
    let config = CoreConfig::new(
        prepared.new_validator_set().validators()[0].id(),
        prepared.new_validator_set().clone(),
        *prepared.new_parameters(),
        0,
        32,
        64,
    )
    .unwrap();
    let row = fixture
        .application
        .confirm_durable_execution_history_row_v0(&fixture.checkpoint_execution)
        .unwrap();
    let header = fixture.checkpoint.header();
    let artifact = ValidatedPayloadArtifactRefV0::new(
        BlockIdOverlayRefV0::new(header.id(), header.parent_id(), row.overlay_digest_v0()),
        row.artifact_digest_v0(),
    );
    let limits = minimum_epoch_safety_record_limits_v1(&config, &runtime).unwrap();
    let context =
        EpochSafetyStateRecordContextV1::new(&config, runtime, artifact, 2, limits).unwrap();
    let (_, recovered) = fixture
        .journal
        .prepare_terminal_recovery_v1(fixture.pin)
        .unwrap();
    let activation = Box::new(recovered.prepare_epoch_activation_v1(&context).unwrap());
    Box::new(activation.state().clone())
}

#[test]
fn epoch_applied_step_requires_exact_checkpoint_and_both_bound_parents() {
    let state = genuine_epoch_state();
    let epoch = state.epoch_state_v1().unwrap();
    let checkpoint = epoch.checkpoint_header();
    let terminal = epoch.terminal_old_header();
    let predecessor = FinalizedTip::new(
        checkpoint.height(),
        checkpoint.view(),
        checkpoint.id(),
        checkpoint.timestamp_ms(),
    );
    let target = BlockId::new([0xab; 32]);
    let successor = FinalizedTip::new(
        terminal.height().checked_next().unwrap(),
        View::new(91),
        target,
        9001,
    );
    let overlay = BlockIdOverlayRefV0::for_epoch_application_v1(
        target,
        checkpoint.id(),
        terminal.id(),
        epoch.activation_binding(),
        [0xad; 32],
    )
    .unwrap();
    assert!(exact_epoch_first_application_step_v1(
        &state,
        predecessor,
        successor,
        overlay
    ));

    // These are inert comparison mutants, not fabricated Core requests or ACKs.
    for wrong in [
        FinalizedTip::new(
            predecessor.height().checked_next().unwrap(),
            predecessor.view(),
            predecessor.block_id(),
            predecessor.timestamp_ms(),
        ),
        FinalizedTip::new(
            predecessor.height(),
            View::new(predecessor.view().get() + 1),
            predecessor.block_id(),
            predecessor.timestamp_ms(),
        ),
        FinalizedTip::new(
            predecessor.height(),
            predecessor.view(),
            BlockId::new([0xee; 32]),
            predecessor.timestamp_ms(),
        ),
        FinalizedTip::new(
            predecessor.height(),
            predecessor.view(),
            predecessor.block_id(),
            predecessor.timestamp_ms() + 1,
        ),
    ] {
        assert!(!exact_epoch_first_application_step_v1(
            &state, wrong, successor, overlay
        ));
    }
    for wrong in [
        BlockIdOverlayRefV0::new(target, checkpoint.id(), [0xad; 32]),
        BlockIdOverlayRefV0::for_epoch_application_v1(
            target,
            BlockId::new([0xef; 32]),
            terminal.id(),
            epoch.activation_binding(),
            [0xad; 32],
        )
        .unwrap(),
        BlockIdOverlayRefV0::for_epoch_application_v1(
            target,
            checkpoint.id(),
            BlockId::new([0xef; 32]),
            epoch.activation_binding(),
            [0xad; 32],
        )
        .unwrap(),
        BlockIdOverlayRefV0::for_epoch_application_v1(
            target,
            checkpoint.id(),
            terminal.id(),
            [0xee; 32],
            [0xad; 32],
        )
        .unwrap(),
        BlockIdOverlayRefV0::for_epoch_application_v1(
            BlockId::new([0xee; 32]),
            checkpoint.id(),
            terminal.id(),
            epoch.activation_binding(),
            [0xad; 32],
        )
        .unwrap(),
    ] {
        assert!(!exact_epoch_first_application_step_v1(
            &state,
            predecessor,
            successor,
            wrong
        ));
    }
    for wrong_height in [
        predecessor.height().checked_next().unwrap(),
        terminal.height(),
        successor.height().checked_next().unwrap(),
    ] {
        let wrong = FinalizedTip::new(
            wrong_height,
            successor.view(),
            successor.block_id(),
            successor.timestamp_ms(),
        );
        assert!(!exact_epoch_first_application_step_v1(
            &state,
            predecessor,
            wrong,
            overlay
        ));
    }
    let no_epoch = native_finalization_applied_pair_tests::genesis_state();
    assert!(!exact_epoch_first_application_step_v1(
        &no_epoch,
        predecessor,
        successor,
        overlay
    ));
}
