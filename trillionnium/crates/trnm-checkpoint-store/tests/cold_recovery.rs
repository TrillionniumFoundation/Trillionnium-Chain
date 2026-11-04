use std::{fs, os::unix::fs::PermissionsExt};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use trnm_checkpoint_store::{
    read_external_journal_checkpoint_v1, write_new_external_journal_checkpoint_v1,
    ExternalCheckpointAuthorityErrorV2, ExternalCheckpointAuthorityV2, ExternalJournalCheckpointV1,
};
use trnm_checkpoint_types::{
    BlockId, EffectWatermarkV2, ExternalCheckpointFieldsV2, ExternalCheckpointV2, StateRoot,
};

fn checkpoint(generation: u64, predecessor_checksum: [u8; 32]) -> ExternalCheckpointV2 {
    checkpoint_in_scope(generation, predecessor_checksum, [1; 32], [12; 32])
}

fn checkpoint_in_scope(
    generation: u64,
    predecessor_checksum: [u8; 32],
    scope: [u8; 32],
    state_root: [u8; 32],
) -> ExternalCheckpointV2 {
    ExternalCheckpointV2::new(ExternalCheckpointFieldsV2 {
        scope,
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
        application_state_root: StateRoot::new(state_root),
        application_generation: generation + 1,
        application_timestamp_ms: 100 + generation,
        effect_journal_id: [13; 32],
        effect_profile_checksum: [14; 32],
        effect_exact_watermark: EffectWatermarkV2::from_persisted_parts(
            scope, [13; 32], generation, [15; 32],
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
    let mut authority = ExternalCheckpointAuthorityV2::register_new(&log).unwrap();
    authority.compare_and_advance_checked(None, first).unwrap();
    let old_log = fs::read(&log).unwrap();
    let old_anchor = fs::read(&anchor).unwrap();
    authority
        .compare_and_advance_checked(Some(first), second)
        .unwrap();
    assert_eq!(authority.load_checked([1; 32]).unwrap(), Some(second));
    let independently_retained = authority.journal_checkpoint_v1().unwrap();
    drop(authority);

    fs::write(&log, &old_log).unwrap();
    fs::write(&anchor, &old_anchor).unwrap();
    let restored = ExternalCheckpointAuthorityV2::reopen_with_external_checkpoint(
        &log,
        independently_retained,
    );
    assert!(
        matches!(
            restored,
            Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "external journal checkpoint mismatch"
            ))
        ),
        "self-consistent old journal plus anchor restored consumed history"
    );
    assert_eq!(fs::read(log).unwrap(), old_log);
    assert_eq!(fs::read(anchor).unwrap(), old_anchor);
}

#[test]
fn healthy_existing_journal_reopens_with_exact_external_checkpoint() {
    let directory = private_tempdir();
    let log = directory.path().join("checkpoint.log");
    let first = checkpoint(0, [0; 32]);
    let second = checkpoint(1, first.checkpoint_checksum());
    let mut authority = ExternalCheckpointAuthorityV2::register_new(&log).unwrap();
    authority.compare_and_advance_checked(None, first).unwrap();
    authority
        .compare_and_advance_checked(Some(first), second)
        .unwrap();
    let expected = authority.journal_checkpoint_v1().unwrap();
    assert_eq!(expected.record_count(), 2);
    assert_eq!(
        ExternalJournalCheckpointV1::decode_canonical_exact(&expected.encode_canonical()).unwrap(),
        expected
    );
    drop(authority);
    let reopened = ExternalCheckpointAuthorityV2::reopen_with_external_checkpoint(&log, expected)
        .expect("exact independently retained count and root");
    assert_eq!(reopened.load_checked([1; 32]).unwrap(), Some(second));
    assert_eq!(reopened.journal_checkpoint_v1().unwrap(), expected);
}

#[test]
fn same_count_different_root_is_not_a_fresh_recovery() {
    let original = private_tempdir();
    let fork = private_tempdir();
    let original_log = original.path().join("checkpoint.log");
    let original_head = original.path().join(".checkpoint.log.head-v2");
    let fork_log = fork.path().join("checkpoint.log");
    let fork_head = fork.path().join(".checkpoint.log.head-v2");
    let first = checkpoint(0, [0; 32]);
    let alternate = checkpoint_in_scope(0, [0; 32], [1; 32], [99; 32]);
    let mut authority = ExternalCheckpointAuthorityV2::register_new(&original_log).unwrap();
    authority.compare_and_advance_checked(None, first).unwrap();
    let expected = authority.journal_checkpoint_v1().unwrap();
    drop(authority);
    let mut alternative = ExternalCheckpointAuthorityV2::register_new(&fork_log).unwrap();
    alternative
        .compare_and_advance_checked(None, alternate)
        .unwrap();
    let alternative_head = alternative.journal_checkpoint_v1().unwrap();
    assert_eq!(expected.record_count(), alternative_head.record_count());
    assert_ne!(expected.root(), alternative_head.root());
    drop(alternative);
    let fork_bytes = fs::read(fork_log).unwrap();
    assert_eq!(fs::read(&original_log).unwrap().len(), fork_bytes.len());
    fs::write(&original_log, fork_bytes).unwrap();
    fs::write(original_head, fs::read(fork_head).unwrap()).unwrap();
    assert!(matches!(
        ExternalCheckpointAuthorityV2::reopen_with_external_checkpoint(original_log, expected),
        Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
            "external journal checkpoint mismatch"
        ))
    ));
}

#[test]
fn full_journal_pin_covers_removal_of_another_scope() {
    let directory = private_tempdir();
    let log = directory.path().join("checkpoint.log");
    let anchor = directory.path().join(".checkpoint.log.head-v2");
    let first = checkpoint(0, [0; 32]);
    let other_scope = checkpoint_in_scope(0, [0; 32], [42; 32], [12; 32]);
    let mut authority = ExternalCheckpointAuthorityV2::register_new(&log).unwrap();
    authority.compare_and_advance_checked(None, first).unwrap();
    let old_log = fs::read(&log).unwrap();
    let old_anchor = fs::read(&anchor).unwrap();
    authority
        .compare_and_advance_checked(None, other_scope)
        .unwrap();
    let expected = authority.journal_checkpoint_v1().unwrap();
    assert_eq!(expected.record_count(), 2);
    assert_eq!(authority.load_checked([1; 32]).unwrap(), Some(first));
    drop(authority);
    fs::write(&log, old_log).unwrap();
    fs::write(&anchor, old_anchor).unwrap();
    assert!(ExternalCheckpointAuthorityV2::reopen_with_external_checkpoint(log, expected).is_err());
}

#[test]
fn external_mismatch_is_rejected_before_stale_local_head_repair() {
    let directory = private_tempdir();
    let log = directory.path().join("checkpoint.log");
    let anchor = directory.path().join(".checkpoint.log.head-v2");
    let first = checkpoint(0, [0; 32]);
    let second = checkpoint(1, first.checkpoint_checksum());
    let mut authority = ExternalCheckpointAuthorityV2::register_new(&log).unwrap();
    authority.compare_and_advance_checked(None, first).unwrap();
    let old_pin = authority.journal_checkpoint_v1().unwrap();
    let old_anchor = fs::read(&anchor).unwrap();
    authority
        .compare_and_advance_checked(Some(first), second)
        .unwrap();
    let new_pin = authority.journal_checkpoint_v1().unwrap();
    let new_anchor = fs::read(&anchor).unwrap();
    let full_log = fs::read(&log).unwrap();
    drop(authority);
    fs::write(&anchor, &old_anchor).unwrap();
    assert!(ExternalCheckpointAuthorityV2::reopen_with_external_checkpoint(&log, old_pin).is_err());
    assert_eq!(fs::read(&anchor).unwrap(), old_anchor);
    assert_eq!(fs::read(&log).unwrap(), full_log);

    let recovered =
        ExternalCheckpointAuthorityV2::reopen_with_external_checkpoint(&log, new_pin).unwrap();
    assert_eq!(recovered.load_checked([1; 32]).unwrap(), Some(second));
    assert_eq!(fs::read(&anchor).unwrap(), new_anchor);
}

#[test]
fn pinned_reopen_never_reseeds_missing_existing_files() {
    for missing_name in [
        "checkpoint.log",
        ".checkpoint.log.lock-v2",
        ".checkpoint.log.head-v2",
    ] {
        let directory = private_tempdir();
        let log = directory.path().join("checkpoint.log");
        let authority = ExternalCheckpointAuthorityV2::register_new(&log).unwrap();
        let expected = authority.journal_checkpoint_v1().unwrap();
        drop(authority);
        let missing_path = directory.path().join(missing_name);
        fs::remove_file(&missing_path).unwrap();
        assert!(
            ExternalCheckpointAuthorityV2::reopen_with_external_checkpoint(&log, expected).is_err()
        );
        assert!(
            !missing_path.exists(),
            "reopen must not reseed {missing_name}"
        );
    }
}

#[test]
fn register_new_rejects_existing_even_empty_namespaces() {
    for existing_name in [
        "checkpoint.log",
        ".checkpoint.log.lock-v2",
        ".checkpoint.log.head-v2",
    ] {
        let directory = private_tempdir();
        let log = directory.path().join("checkpoint.log");
        let existing_path = directory.path().join(existing_name);
        fs::write(&existing_path, b"old registration evidence").unwrap();
        assert!(ExternalCheckpointAuthorityV2::register_new(&log).is_err());
        assert_eq!(
            fs::read(&existing_path).unwrap(),
            b"old registration evidence"
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
    let directory = private_tempdir();
    let log = directory.path().join("checkpoint.log");
    let authority = ExternalCheckpointAuthorityV2::register_new(&log).unwrap();
    drop(authority);
    assert!(ExternalCheckpointAuthorityV2::register_new(&log).is_err());
}

#[test]
fn structural_open_cannot_serve_or_export_a_freshness_claim() {
    let directory = private_tempdir();
    let log = directory.path().join("checkpoint.log");
    let socket = directory.path().join("checkpoint.sock");
    let authority = ExternalCheckpointAuthorityV2::open(&log).unwrap();
    assert!(authority.journal_checkpoint_v1().is_err());
    assert!(authority.serve_unix(&socket).is_err());
    assert!(!socket.exists());
}

#[test]
fn export_is_exact_new_domain_and_cannot_overwrite_an_external_pin() {
    let directory = private_tempdir();
    let retained = private_tempdir();
    let log = directory.path().join("checkpoint.log");
    let anchor = directory.path().join(".checkpoint.log.head-v2");
    let export = retained.path().join("independent-checkpoint.bin");
    let authority = ExternalCheckpointAuthorityV2::register_new(&log).unwrap();
    let expected = authority.journal_checkpoint_v1().unwrap();
    write_new_external_journal_checkpoint_v1(&export, expected).unwrap();
    assert_eq!(
        read_external_journal_checkpoint_v1(&export).unwrap(),
        expected
    );
    assert!(write_new_external_journal_checkpoint_v1(&export, expected).is_err());
    assert_eq!(
        read_external_journal_checkpoint_v1(&export).unwrap(),
        expected
    );
    // A same-directory crash-recovery head is a different namespace and
    // cannot be supplied directly as the independent recovery expectation.
    assert!(read_external_journal_checkpoint_v1(anchor).is_err());
    let mut trailing = expected.encode_canonical().to_vec();
    trailing.push(0);
    assert!(ExternalJournalCheckpointV1::decode_canonical_exact(&trailing).is_err());
    fs::write(&export, &trailing).unwrap();
    assert!(read_external_journal_checkpoint_v1(&export).is_err());
    let mut bad_version = expected.encode_canonical();
    bad_version[8] = 2;
    assert!(ExternalJournalCheckpointV1::decode_canonical_exact(&bad_version).is_err());
    let mut corrupt = expected.encode_canonical();
    corrupt[20] ^= 1;
    assert!(ExternalJournalCheckpointV1::decode_canonical_exact(&corrupt).is_err());
    assert!(ExternalJournalCheckpointV1::decode_canonical_exact(&corrupt[..83]).is_err());
}

#[test]
fn impossible_external_count_is_rejected_without_replay_or_repair() {
    let directory = private_tempdir();
    let log = directory.path().join("checkpoint.log");
    let anchor = directory.path().join(".checkpoint.log.head-v2");
    let mut authority = ExternalCheckpointAuthorityV2::register_new(&log).unwrap();
    authority
        .compare_and_advance_checked(None, checkpoint(0, [0; 32]))
        .unwrap();
    let mut bytes = authority
        .journal_checkpoint_v1()
        .unwrap()
        .encode_canonical();
    drop(authority);
    // Canonical but impossible external input: the checksum is not a signature
    // or a resource-admission decision. Reopen must check integer arithmetic.
    bytes[12..20].copy_from_slice(&u64::MAX.to_be_bytes());
    let mut hash = Sha256::new();
    hash.update(b"trnm.external-node-checkpoint.journal-export.v1\0");
    hash.update(52_u64.to_be_bytes());
    hash.update(&bytes[..52]);
    bytes[52..].copy_from_slice(&hash.finalize());
    let oversized = ExternalJournalCheckpointV1::decode_canonical_exact(&bytes).unwrap();
    let before_log = fs::read(&log).unwrap();
    let before_anchor = fs::read(&anchor).unwrap();
    assert!(matches!(
        ExternalCheckpointAuthorityV2::reopen_with_external_checkpoint(&log, oversized),
        Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
            "external journal checkpoint length overflow"
        ))
    ));
    assert_eq!(fs::read(log).unwrap(), before_log);
    assert_eq!(fs::read(anchor).unwrap(), before_anchor);
}

#[test]
fn extra_record_is_rejected_before_hash_replay() {
    let directory = private_tempdir();
    let log = directory.path().join("checkpoint.log");
    let anchor = directory.path().join(".checkpoint.log.head-v2");
    let mut authority = ExternalCheckpointAuthorityV2::register_new(&log).unwrap();
    authority
        .compare_and_advance_checked(None, checkpoint(0, [0; 32]))
        .unwrap();
    let expected = authority.journal_checkpoint_v1().unwrap();
    drop(authority);
    let original = fs::read(&log).unwrap();
    let mut doubled = original.clone();
    doubled.extend(original);
    fs::write(&log, &doubled).unwrap();
    let before_anchor = fs::read(&anchor).unwrap();
    assert!(matches!(
        ExternalCheckpointAuthorityV2::reopen_with_external_checkpoint(&log, expected),
        Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
            "external journal checkpoint mismatch"
        ))
    ));
    assert_eq!(fs::read(log).unwrap(), doubled);
    assert_eq!(fs::read(anchor).unwrap(), before_anchor);
}
