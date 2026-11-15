use std::{fs, os::unix::fs::PermissionsExt};

use tempfile::TempDir;
use trnm_checkpoint_store::ExternalCheckpointAuthorityV2;
use trnm_checkpoint_types::{
    BlockId, EffectWatermarkV2, ExternalCheckpointFieldsV2, ExternalCheckpointV2, StateRoot,
};

fn checkpoint(generation: u64, predecessor_checksum: [u8; 32]) -> ExternalCheckpointV2 {
    ExternalCheckpointV2::new(ExternalCheckpointFieldsV2 {
        scope: [1; 32],
        generation,
        predecessor_checksum,
        authority_journal_id: [2; 32],
        authority_verifier_profile_ref: [3; 32],
        authority_revision: generation + 1,
        authority_state_record_checksum: [4; 32],
        authority_record_chain_checksum: [5; 32],
        application_host_config_ref: [6; 32],
        application_projection_profile_ref: [7; 32],
        application_authority_binding_manifest_checksum: [8; 32],
        application_committed_head_row_checksum: [9; 32],
        application_recovery_closure_checksum: [10; 32],
        application_block_id: BlockId::new([11; 32]),
        application_height: generation + 1,
        application_state_root: StateRoot::new([12; 32]),
        application_generation: generation + 1,
        application_timestamp_ms: 100 + generation,
        effect_journal_id: [13; 32],
        effect_profile_checksum: [14; 32],
        effect_exact_watermark: EffectWatermarkV2::from_persisted_parts(
            [1; 32], [13; 32], generation, [15; 32],
        )
        .unwrap(),
    })
    .unwrap()
}

fn private_tempdir() -> TempDir {
    let directory = TempDir::new().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn cold_recovery_rejects_self_consistent_old_complete_image() {
    let directory = private_tempdir();
    let log = directory.path().join("checkpoint.log");
    let anchor = directory.path().join(".checkpoint.log.head-v2");
    let first = checkpoint(0, [0; 32]);
    let second = checkpoint(1, first.checkpoint_checksum());
    let mut authority = ExternalCheckpointAuthorityV2::open(&log).unwrap();
    authority.compare_and_advance_checked(None, first).unwrap();
    let old_log = fs::read(&log).unwrap();
    let old_anchor = fs::read(&anchor).unwrap();
    authority
        .compare_and_advance_checked(Some(first), second)
        .unwrap();
    assert_eq!(authority.load_checked([1; 32]).unwrap(), Some(second));
    drop(authority);

    fs::write(&log, &old_log).unwrap();
    fs::write(&anchor, &old_anchor).unwrap();
    let restored = ExternalCheckpointAuthorityV2::open(&log);
    assert!(
        restored.is_err(),
        "self-consistent old journal plus anchor restored consumed history"
    );
}
