//! Narrow retained-reader controls. No Seek/Read fault is simulated here.

use super::*;

fn acknowledged_corrupt(path: &Path) -> (CellRetentionStoreV1, CellRetentionContractV1, Vec<u8>) {
    let (mut arena, cache, contract, bytes) = fixture(path);
    arena
        .acknowledge(contract.operation, &cache, deadline())
        .unwrap();
    arena.arena.seek(SeekFrom::Start(0)).unwrap();
    arena.arena.write_all(&[bytes[0] ^ 1]).unwrap();
    arena.arena.sync_all().unwrap();
    (arena, contract, bytes)
}

fn record(case: &str, result: &CellResultV1<CellRetentionPayloadObservationV2>) {
    println!(
        "SP27_BOUNDARY_JSON {}",
        serde_json::json!({
            "schema":"sp27-05.native-observation-boundary-control.v1",
            "case":case,
            "actual_payload_corruption":true,
            "outer_error":result.as_ref().err().map(|error|format!("{error:?}")),
            "returned_observation":result.as_ref().ok().map(|value|match value {
                CellRetentionPayloadObservationV2::Verified(_) => "Verified",
                CellRetentionPayloadObservationV2::Rejected(_) => "Rejected",
            }),
            "scope":"native single-host retained-reader fixture; no model forward"
        })
    );
}

#[test]
fn sp27_observation_allocation_limit_is_fatal_before_corrupt_payload() {
    let dir = tempfile::tempdir().unwrap();
    let (mut arena, contract, bytes) = acknowledged_corrupt(dir.path());
    let before = row_checksum(&arena.required_row(contract.operation).unwrap());
    let result = arena.observe_payload_controlled_v2(
        contract.operation,
        bytes.len() as u64 - 1,
        deadline(),
        &mut || Ok(()),
    );
    record("caller_allocation_limit_with_corrupt_payload", &result);
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("retention read allocation limit"))
    ));
    assert_eq!(
        row_checksum(&arena.required_row(contract.operation).unwrap()),
        before
    );
}

#[test]
fn sp27_observation_schema_error_is_fatal_with_corrupt_payload() {
    let dir = tempfile::tempdir().unwrap();
    let (mut arena, contract, bytes) = acknowledged_corrupt(dir.path());
    arena
        .connection
        .execute("CREATE TABLE unadmitted (value INTEGER)", [])
        .unwrap();
    let result = arena.observe_payload_controlled_v2(
        contract.operation,
        bytes.len() as u64,
        deadline(),
        &mut || Ok(()),
    );
    record("schema_change_with_corrupt_payload", &result);
    assert!(result.is_err());
}

#[test]
fn sp27_observation_physical_capacity_failure_is_fatal_with_corrupt_payload() {
    let dir = tempfile::tempdir().unwrap();
    let (mut arena, contract, bytes) = acknowledged_corrupt(dir.path());
    arena.arena.set_len(bytes.len() as u64 - 1).unwrap();
    let result = arena.observe_payload_controlled_v2(
        contract.operation,
        bytes.len() as u64,
        deadline(),
        &mut || Ok(()),
    );
    record("physical_truncation_with_corrupt_payload", &result);
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("retention physical capacity"))
    ));
}

#[test]
fn sp27_observation_retained_final_callback_metadata_change_is_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let (mut arena, contract, bytes) = acknowledged_corrupt(dir.path());
    let mut total = 0;
    assert!(matches!(
        arena
            .observe_payload_controlled_v2(
                contract.operation,
                bytes.len() as u64,
                deadline(),
                &mut || {
                    total += 1;
                    Ok(())
                }
            )
            .unwrap(),
        CellRetentionPayloadObservationV2::Rejected(_)
    ));
    let path = dir.path().join("retained/retention.sqlite");
    let mut calls = 0;
    let result = arena.observe_payload_controlled_v2(
        contract.operation,
        bytes.len() as u64,
        deadline(),
        &mut || {
            calls += 1;
            if calls == total {
                Connection::open(&path)
                    .unwrap()
                    .execute(
                        "UPDATE obligations SET checksum=zeroblob(32) WHERE operation=?1",
                        [contract.operation.as_slice()],
                    )
                    .unwrap();
            }
            Ok(())
        },
    );
    assert_eq!(calls, total);
    record("retained_final_callback_metadata_change", &result);
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("retention row integrity"))
    ));
}
