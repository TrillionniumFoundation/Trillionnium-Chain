#![cfg(target_os = "linux")]
use serde_json::Value;
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
use tempfile::TempDir;
use trnm_consensus_core::{recover_epoch_preparation_v1, EpochPreparationV1};
use trnm_consensus_safety_store::{
    EpochPreparationCreateCutV1, EpochPreparationStoreErrorV1, SqliteEpochPreparationStoreV1,
};
use trnm_consensus_types::{
    decode_consensus_parameters_v0_exact, decode_validator_set_v0_exact, Cev0AdmissionBudgetV0,
    ConsensusParametersV0, ValidatorSet,
};
// A spawned process briefly inherits other test threads' flock descriptors
// before exec applies CLOEXEC. Serialize this file's process/namespace tests
// instead of weakening the production exclusive-owner check or retrying it.
static PROCESS_NAMESPACE_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

const CORPUS: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json"
);
fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn fixture(profile: &str) -> (Vec<u8>, ValidatorSet, ConsensusParametersV0, [u8; 32]) {
    let value: Value = serde_json::from_str(CORPUS).unwrap();
    let case = &value[profile];
    let raw = |section: &str, field: &str| unhex(case[section][field].as_str().unwrap());
    let fields = [
        raw("checkpoint_finality", "raw_finality_proof_cev0_hex"),
        raw("preheader", "commitment_cev0_hex"),
        raw("handoff", "raw_anchor_certificate_kernel_cev0_hex"),
        raw("preheader", "old_validator_set_cev0_hex"),
        raw("preheader", "old_parameters_cev0_hex"),
        raw("preheader", "new_validator_set_cev0_hex"),
        raw("preheader", "new_parameters_cev0_hex"),
        raw("preheader", "checkpoint_parent_header_cev0_hex"),
    ];
    let old_set = decode_validator_set_v0_exact(&fields[3]).unwrap();
    let parameters = decode_consensus_parameters_v0_exact(&fields[4]).unwrap();
    let binding: [u8; 32] = unhex(if profile == "positive" {
        "4ba70b831d3bd70a1be8669f654ac42148017fca0b83f84e999ac532b9c70e4f"
    } else {
        "3f719cc7d84539da791a3206d46c4d529f390b2333c35128847f7b62dcd2fc73"
    })
    .try_into()
    .unwrap();
    // Construct only untrusted persistence bytes; recovery below must rebuild
    // cryptographic authority from the complete frozen proof, never from tags.
    let mut record = b"TRNMEP01".to_vec();
    record.extend_from_slice(&1u16.to_be_bytes());
    record.push(0);
    record.extend_from_slice(&binding);
    for field in fields {
        record.extend_from_slice(&(field.len() as u32).to_be_bytes());
        record.extend_from_slice(&field);
    }
    (record, old_set, parameters, binding)
}
fn prepare(
    record: &[u8],
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    binding: [u8; 32],
) -> EpochPreparationV1 {
    recover_epoch_preparation_v1(
        record,
        set,
        parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap()
}
fn directory() -> TempDir {
    let directory = TempDir::new().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
fn open(
    path: &Path,
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    binding: [u8; 32],
) -> SqliteEpochPreparationStoreV1 {
    SqliteEpochPreparationStoreV1::open_existing(
        path,
        set,
        parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap()
}

#[test]
fn exact_preparation_is_durable_reopenable_and_idempotent() {
    let _process_namespace = PROCESS_NAMESPACE_TEST
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (record, set, parameters, binding) = fixture("positive");
    let directory = directory();
    let path = directory.path().join("epoch.sqlite");
    let mut store = SqliteEpochPreparationStoreV1::create_new(
        &path,
        prepare(&record, &set, &parameters, binding),
        &set,
        &parameters,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let retained = store
        .retain_exact_v1(
            prepare(&record, &set, &parameters, binding),
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(retained.record_v1().encode_v1().unwrap(), record);
    drop(store);
    for _ in 0..2 {
        let mut reopened = open(&path, &set, &parameters, binding);
        let recovered = reopened
            .recover_fresh_v1(&mut Cev0AdmissionBudgetV0::protocol_v0())
            .unwrap();
        assert_eq!(recovered.record_v1().encode_v1().unwrap(), record);
        assert_eq!(recovered.authority_v1().binding_ref().as_bytes(), &binding);
    }
}

#[test]
fn valid_different_evidence_and_wrong_trust_never_replace_the_pinned_record() {
    let _process_namespace = PROCESS_NAMESPACE_TEST
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (record, set, parameters, binding) = fixture("positive");
    let (other, other_set, other_parameters, other_binding) = fixture("authenticated_fallback");
    let directory = directory();
    let path = directory.path().join("epoch.sqlite");
    let mut store = SqliteEpochPreparationStoreV1::create_new(
        &path,
        prepare(&record, &set, &parameters, binding),
        &set,
        &parameters,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert!(store
        .retain_exact_v1(
            prepare(&other, &other_set, &other_parameters, other_binding),
            &mut Cev0AdmissionBudgetV0::protocol_v0()
        )
        .is_err());
    assert_eq!(
        store
            .recover_fresh_v1(&mut Cev0AdmissionBudgetV0::protocol_v0())
            .unwrap()
            .record_v1()
            .encode_v1()
            .unwrap(),
        record
    );
    drop(store);
    assert!(SqliteEpochPreparationStoreV1::open_existing(
        &path,
        &set,
        &parameters,
        other_binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0()
    )
    .is_err());
    open(&path, &set, &parameters, binding);
}

#[test]
fn malformed_record_and_narrow_budget_do_not_rebuild_authority_or_change_budget() {
    let _process_namespace = PROCESS_NAMESPACE_TEST
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (record, set, parameters, binding) = fixture("positive");
    let mut cases = vec![];
    let mut schema = record.clone();
    schema[9] = 2;
    cases.push(schema);
    let mut phase = record.clone();
    phase[10] = 1;
    cases.push(phase);
    let mut trailing = record.clone();
    trailing.push(0);
    cases.push(trailing);
    let mut oversized = record.clone();
    oversized[43..47].copy_from_slice(&u32::MAX.to_be_bytes());
    cases.push(oversized);
    let mut truncated = record.clone();
    truncated.pop();
    cases.push(truncated);
    for changed in cases {
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        let before = budget;
        assert!(
            recover_epoch_preparation_v1(&changed, &set, &parameters, binding, &mut budget)
                .is_err()
        );
        assert_eq!(budget, before);
    }
    let mut budget = Cev0AdmissionBudgetV0::new(0, 0);
    let before = budget;
    assert!(
        recover_epoch_preparation_v1(&record, &set, &parameters, binding, &mut budget).is_err()
    );
    assert_eq!(budget, before);
}

#[test]
fn corrupt_or_incomplete_namespace_is_rejected_without_initialization() {
    let _process_namespace = PROCESS_NAMESPACE_TEST
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (record, set, parameters, binding) = fixture("positive");
    let directory = directory();
    let missing = directory.path().join("absent.sqlite");
    assert!(SqliteEpochPreparationStoreV1::open_existing(
        &missing,
        &set,
        &parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0()
    )
    .is_err());
    assert!(!missing.exists());
    let path = directory.path().join("epoch.sqlite");
    let mut store = SqliteEpochPreparationStoreV1::create_new(
        &path,
        prepare(&record, &set, &parameters, binding),
        &set,
        &parameters,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store
        .recover_fresh_v1(&mut Cev0AdmissionBudgetV0::protocol_v0())
        .is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE epoch_preparation_v1 SET record_checksum=zeroblob(32)",
            [],
        )
        .unwrap();
    // Keep all real sidecars, so this case reaches checksum verification rather
    // than passing solely because the test connection removed its WAL on close.
    let mut persistent_wal = 1i32;
    // SAFETY: the live SQLite connection owns the handle; the file-control
    // opcode borrows this integer only for the duration of this call.
    assert_eq!(
        unsafe {
            rusqlite::ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
                (&mut persistent_wal as *mut i32).cast(),
            )
        },
        rusqlite::ffi::SQLITE_OK
    );
    drop(connection);
    let error = SqliteEpochPreparationStoreV1::open_existing(
        &path,
        &set,
        &parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            EpochPreparationStoreErrorV1::InvalidRecord("binding or record checksum mismatch")
        ),
        "{error}"
    );
}

#[test]
fn second_owner_and_every_pinned_file_replacement_are_rejected() {
    let _process_namespace = PROCESS_NAMESPACE_TEST
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (record, set, parameters, binding) = fixture("positive");
    for suffix in ["", ".epoch.lock", "-wal", "-shm"] {
        let directory = directory();
        let path = directory.path().join("epoch.sqlite");
        let mut store = SqliteEpochPreparationStoreV1::create_new(
            &path,
            prepare(&record, &set, &parameters, binding),
            &set,
            &parameters,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
        let second = SqliteEpochPreparationStoreV1::open_existing(
            &path,
            &set,
            &parameters,
            binding,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap_err();
        assert!(
            matches!(second, EpochPreparationStoreErrorV1::Locked),
            "{second}"
        );
        let replaced = directory.path().join(format!("epoch.sqlite{suffix}"));
        let saved = directory.path().join("pinned-original");
        fs::rename(&replaced, &saved).unwrap();
        fs::copy(&saved, &replaced).unwrap();
        fs::set_permissions(&replaced, fs::Permissions::from_mode(0o600)).unwrap();
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        let before = budget;
        let error = store.recover_fresh_v1(&mut budget).unwrap_err();
        assert!(
            matches!(error, EpochPreparationStoreErrorV1::FileIdentityChanged),
            "{suffix}: {error}"
        );
        assert_eq!(budget, before);
        // Restore the original before SQLite closes; otherwise the test itself
        // would ask SQLite to close under a replaced namespace.
        fs::remove_file(&replaced).unwrap();
        fs::rename(&saved, &replaced).unwrap();
        drop(store.recover_fresh_v1(&mut budget).unwrap());
    }
}

#[test]
fn unsafe_parent_symlink_and_hard_link_never_create_an_owner() {
    let _process_namespace = PROCESS_NAMESPACE_TEST
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    use std::os::unix::fs::symlink;
    let (record, set, parameters, binding) = fixture("positive");
    let directory = directory();
    let path = directory.path().join("epoch.sqlite");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let result = SqliteEpochPreparationStoreV1::create_new(
        &path,
        prepare(&record, &set, &parameters, binding),
        &set,
        &parameters,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    );
    assert!(matches!(
        result,
        Err(EpochPreparationStoreErrorV1::InvalidNamespace(_))
    ));
    assert!(!path.exists());
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store = SqliteEpochPreparationStoreV1::create_new(
        &path,
        prepare(&record, &set, &parameters, binding),
        &set,
        &parameters,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    drop(store);
    let original = directory.path().join("saved.sqlite");
    fs::rename(&path, &original).unwrap();
    symlink(&original, &path).unwrap();
    assert!(SqliteEpochPreparationStoreV1::open_existing(
        &path,
        &set,
        &parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .is_err());
    fs::remove_file(&path).unwrap();
    fs::rename(&original, &path).unwrap();
    fs::hard_link(&path, &original).unwrap();
    let error = SqliteEpochPreparationStoreV1::open_existing(
        &path,
        &set,
        &parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap_err();
    assert!(
        matches!(error, EpochPreparationStoreErrorV1::InvalidNamespace(_)),
        "{error}"
    );
    fs::remove_file(&original).unwrap();
    open(&path, &set, &parameters, binding);
}

fn corrupt_persisted_preparation_bytes(path: &Path) {
    use std::os::unix::fs::{FileExt, MetadataExt};
    let mut changed = 0;
    // A clean connection close may checkpoint the record from WAL into DB.
    // Corrupt every persisted copy, keeping identity, length and permissions.
    for candidate in [path.to_path_buf(), path.with_file_name("epoch.sqlite-wal")] {
        let bytes = fs::read(&candidate).unwrap();
        let offsets: Vec<_> = bytes
            .windows(8)
            .enumerate()
            .filter_map(|(offset, value)| (value == b"TRNMEP01").then_some(offset))
            .collect();
        if offsets.is_empty() {
            continue;
        }
        let before = fs::metadata(&candidate).unwrap();
        let file = fs::OpenOptions::new().write(true).open(&candidate).unwrap();
        for offset in offsets {
            file.write_all_at(b"X", offset as u64).unwrap();
            changed += 1;
        }
        file.sync_all().unwrap();
        let after = fs::metadata(&candidate).unwrap();
        assert_eq!(before.ino(), after.ino());
        assert_eq!(before.len(), after.len());
        assert_eq!(before.mode(), after.mode());
    }
    assert!(changed > 0, "test must damage real persisted evidence");
}

#[test]
fn same_inode_persisted_corruption_cannot_return_cached_authority() {
    let _process_namespace = PROCESS_NAMESPACE_TEST
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (record, set, parameters, binding) = fixture("positive");
    let directory = directory();
    let path = directory.path().join("epoch.sqlite");
    let mut store = SqliteEpochPreparationStoreV1::create_new(
        &path,
        prepare(&record, &set, &parameters, binding),
        &set,
        &parameters,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    corrupt_persisted_preparation_bytes(&path);
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    let before = budget;
    assert!(
        store.recover_fresh_v1(&mut budget).is_err(),
        "a new read transaction on the same cached connection is insufficient"
    );
    assert_eq!(budget, before);
}

#[test]
fn create_ack_reads_synchronized_files_through_a_fresh_connection() {
    let _process_namespace = PROCESS_NAMESPACE_TEST
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (record, set, parameters, binding) = fixture("positive");
    let directory = directory();
    let path = directory.path().join("epoch.sqlite");
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    let before = budget;
    let outcome = SqliteEpochPreparationStoreV1::create_new_with_observer_v1(
        &path,
        prepare(&record, &set, &parameters, binding),
        &set,
        &parameters,
        &mut budget,
        |cut| {
            if cut == EpochPreparationCreateCutV1::AfterSyncBeforeReadback {
                corrupt_persisted_preparation_bytes(&path);
            }
            Ok(())
        },
    );
    assert!(
        outcome.is_err(),
        "cached pre-sync bytes cannot establish a durable ACK"
    );
    assert!(
        budget.signature_work() > before.signature_work(),
        "failed durable ACK does not refund the strict pre-creation verification"
    );
}

#[test]
fn every_initialization_cut_rejects_replaced_wal_and_shm_inodes() {
    let _process_namespace = PROCESS_NAMESPACE_TEST
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (record, set, parameters, binding) = fixture("positive");
    for cut in [
        EpochPreparationCreateCutV1::AfterSchemaBeforeRecord,
        EpochPreparationCreateCutV1::AfterRecordBeforeCommit,
        EpochPreparationCreateCutV1::AfterCommitBeforeSync,
        EpochPreparationCreateCutV1::AfterSyncBeforeReadback,
    ] {
        for suffix in ["-wal", "-shm"] {
            let directory = directory();
            let path = directory.path().join("epoch.sqlite");
            let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
            let before = budget;
            let outcome = SqliteEpochPreparationStoreV1::create_new_with_observer_v1(
                &path,
                prepare(&record, &set, &parameters, binding),
                &set,
                &parameters,
                &mut budget,
                |actual| {
                    if actual == cut {
                        let sidecar = directory.path().join(format!("epoch.sqlite{suffix}"));
                        let displaced = directory.path().join("displaced-sidecar");
                        fs::rename(&sidecar, &displaced).unwrap();
                        fs::copy(&displaced, &sidecar).unwrap();
                        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600)).unwrap();
                    }
                    Ok(())
                },
            );
            assert!(
                outcome.is_err(),
                "{cut:?}/{suffix}: cached old handle must not authorize a new inode"
            );
            assert!(
                budget.signature_work() > before.signature_work(),
                "namespace failure does not refund the strict pre-creation verification"
            );
        }
    }
}

#[test]
fn core_and_store_keep_work_charged_when_strict_recovery_fails() {
    let _process_namespace = PROCESS_NAMESPACE_TEST
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    use sha2::{Digest, Sha256};
    let (record, set, parameters, binding) = fixture("positive");
    let mut measured = Cev0AdmissionBudgetV0::protocol_v0();
    drop(recover_epoch_preparation_v1(&record, &set, &parameters, binding, &mut measured).unwrap());
    let mut invalid = record.clone();
    let mut offset = 43;
    for index in 0..=2 {
        let length = u32::from_be_bytes(invalid[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if index == 2 {
            invalid[offset + length - 1] ^= 1; // Shape-valid kernel signature.
        }
        offset += length;
    }
    let mut budget =
        Cev0AdmissionBudgetV0::new(measured.maximum_root_bytes(), measured.signature_work());
    assert!(
        recover_epoch_preparation_v1(&invalid, &set, &parameters, binding, &mut budget).is_err()
    );
    assert_eq!(budget.signature_work(), measured.signature_work());
    let charged = budget;
    assert!(
        recover_epoch_preparation_v1(&invalid, &set, &parameters, binding, &mut budget).is_err()
    );
    assert_eq!(budget, charged);

    let directory = directory();
    let path = directory.path().join("epoch.sqlite");
    drop(
        SqliteEpochPreparationStoreV1::create_new(
            &path,
            prepare(&record, &set, &parameters, binding),
            &set,
            &parameters,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap(),
    );
    let connection = rusqlite::Connection::open(&path).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.local.epoch-preparation-record-checksum.v1");
    hasher.update((invalid.len() as u64).to_be_bytes());
    hasher.update(&invalid);
    let checksum: [u8; 32] = hasher.finalize().into();
    connection
        .execute(
            "UPDATE epoch_preparation_v1 SET record=?1, record_checksum=?2",
            rusqlite::params![invalid, checksum.as_slice()],
        )
        .unwrap();
    let mut persistent_wal = 1i32;
    // SAFETY: the live connection owns the handle and SQLite retains no pointer.
    assert_eq!(
        unsafe {
            rusqlite::ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
                (&mut persistent_wal as *mut i32).cast(),
            )
        },
        rusqlite::ffi::SQLITE_OK
    );
    drop(connection);
    let mut budget =
        Cev0AdmissionBudgetV0::new(measured.maximum_root_bytes(), measured.signature_work());
    let failure = SqliteEpochPreparationStoreV1::open_existing(
        &path,
        &set,
        &parameters,
        binding,
        &mut budget,
    )
    .unwrap_err();
    assert!(
        matches!(failure, EpochPreparationStoreErrorV1::Preparation(_)),
        "{failure}"
    );
    assert_eq!(
        budget.signature_work(),
        measured.signature_work(),
        "a checksum-consistent invalid proof cannot get free strict verification from Store"
    );
    let charged = budget;
    assert!(SqliteEpochPreparationStoreV1::open_existing(
        &path,
        &set,
        &parameters,
        binding,
        &mut budget,
    )
    .is_err());
    assert_eq!(budget, charged);
}

#[test]
fn epoch_preparation_process_crash_child() {
    let _process_namespace = PROCESS_NAMESPACE_TEST
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let Some(path) = std::env::var_os("TRNM_EPOCH_PREPARATION_CRASH_PATH") else {
        return;
    };
    let stage = std::env::var("TRNM_EPOCH_PREPARATION_CRASH_STAGE").unwrap();
    let (record, set, parameters, binding) = fixture("positive");
    SqliteEpochPreparationStoreV1::create_new_with_observer_v1(
        Path::new(&path),
        prepare(&record, &set, &parameters, binding),
        &set,
        &parameters,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
        |cut| {
            if format!("{cut:?}") == stage {
                std::process::exit(73);
            }
            Ok(())
        },
    )
    .unwrap();
    panic!("requested crash cut was not reached");
}

#[test]
fn actual_sqlite_commit_cuts_reopen_only_the_exact_committed_preparation() {
    let _process_namespace = PROCESS_NAMESPACE_TEST
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (record, set, parameters, binding) = fixture("positive");
    for (cut, committed) in [
        (EpochPreparationCreateCutV1::AfterSchemaBeforeRecord, false),
        (EpochPreparationCreateCutV1::AfterRecordBeforeCommit, false),
        (EpochPreparationCreateCutV1::AfterCommitBeforeSync, true),
        (EpochPreparationCreateCutV1::AfterSyncBeforeReadback, true),
    ] {
        let directory = directory();
        let path = directory.path().join("epoch.sqlite");
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "epoch_preparation_process_crash_child",
                "--nocapture",
            ])
            .env("TRNM_EPOCH_PREPARATION_CRASH_PATH", &path)
            .env("TRNM_EPOCH_PREPARATION_CRASH_STAGE", format!("{cut:?}"))
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73), "{cut:?}");
        let reopened = SqliteEpochPreparationStoreV1::open_existing(
            &path,
            &set,
            &parameters,
            binding,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        );
        assert_eq!(reopened.is_ok(), committed, "{cut:?}: {reopened:?}");
        if let Ok(mut store) = reopened {
            let recovered = store
                .recover_fresh_v1(&mut Cev0AdmissionBudgetV0::protocol_v0())
                .unwrap();
            assert_eq!(
                recovered.record_v1().encode_v1().unwrap(),
                record,
                "{cut:?}"
            );
        }
    }
}
