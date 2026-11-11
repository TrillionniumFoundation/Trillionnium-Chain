//! Targeted SP27-05 return-boundary controls. These are local native fixtures,
//! not independent-provider, remote-attestation, authorization or effect tests.

use super::*;

fn prepared(
    corrupt: bool,
) -> (
    tempfile::TempDir,
    Fixture,
    CellRs46ShardContractV1,
    CellRs46ShardProviderV1,
) {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let contract = fixture.contract(0, 1);
    let source = cache(&dir.path().join("source.sqlite"));
    fixture.stage(&contract, &source);
    let path = dir.path().join("provider");
    let mut provider = CellRs46ShardProviderV1::create(&path, fixture.config(0, 16)).unwrap();
    provider
        .publish(&contract, contract.operation(), &source, deadline())
        .unwrap();
    if corrupt {
        damage(&path);
    }
    (dir, fixture, contract, provider)
}

fn count_callbacks(
    provider: &mut CellRs46ShardProviderV1,
    contract: &CellRs46ShardContractV1,
    corrupt: bool,
) -> usize {
    let mut calls = 0;
    let result = provider
        .read_observed_v2(contract, contract.operation(), deadline(), &mut || {
            calls += 1;
            Ok(())
        })
        .unwrap();
    match (corrupt, result) {
        (false, CellRs46ProviderReadObservationV2::Verified(_)) => (),
        (true, CellRs46ProviderReadObservationV2::Rejected(fault)) => {
            assert_eq!(
                fault.stage(),
                CellRs46ProviderPayloadFaultStageV2::ChunkDigest
            );
            assert_eq!(
                fault.read_bytes_bounds(),
                (fault.expected_bytes(), fault.expected_bytes())
            );
        }
        _ => panic!("fixture must reach its declared payload branch"),
    }
    calls
}

fn record(
    case: &str,
    corrupt: bool,
    calls: usize,
    result: &CellResultV1<CellRs46ProviderReadObservationV2>,
) {
    println!(
        "SP27_BOUNDARY_JSON {}",
        serde_json::json!({
            "schema": "sp27-05.native-observation-boundary-control.v1",
            "case": case,
            "actual_payload_corruption": corrupt,
            "callback_count": calls,
            "outer_error": result.as_ref().err().map(|e| format!("{e:?}")),
            "returned_observation": result.as_ref().ok().map(|value| match value {
                CellRs46ProviderReadObservationV2::Verified(_) => "Verified",
                CellRs46ProviderReadObservationV2::Rejected(_) => "Rejected",
            }),
            "scope": "native single-host fixture; explicit local callback mutation; no model forward"
        })
    );
}

#[test]
fn sp27_observation_final_callback_descriptor_change_is_fatal() {
    let mut outer_errors = 0;
    for corrupt in [false, true] {
        let (dir, _fixture, contract, mut provider) = prepared(corrupt);
        let total = count_callbacks(&mut provider, &contract, corrupt);
        let path = dir
            .path()
            .join("provider")
            .join(DESCRIPTORS)
            .join(hex::encode(contract.operation()));
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        let before = ledger(&dir.path().join("provider"), contract.operation());
        let mut calls = 0;
        let result =
            provider.read_observed_v2(&contract, contract.operation(), deadline(), &mut || {
                calls += 1;
                if calls == total {
                    fs::write(&path, &bytes).unwrap();
                }
                Ok(())
            });
        assert_eq!(calls, total);
        assert_eq!(
            ledger(&dir.path().join("provider"), contract.operation()),
            before
        );
        record("final_callback_descriptor_change", corrupt, calls, &result);
        outer_errors += usize::from(matches!(
            result,
            Err(CellErrorV1::Invalid("RS46 provider operation pin"))
        ));
    }
    assert_eq!(
        outer_errors, 2,
        "neither completed bytes nor a payload rejection may hide a changed descriptor"
    );
}

#[test]
fn sp27_observation_final_callback_metadata_change_is_fatal() {
    let mut outer_errors = 0;
    for corrupt in [false, true] {
        let (dir, _fixture, contract, mut provider) = prepared(corrupt);
        let total = count_callbacks(&mut provider, &contract, corrupt);
        let path = dir.path().join("provider/retention.sqlite");
        let mut calls = 0;
        let result =
            provider.read_observed_v2(&contract, contract.operation(), deadline(), &mut || {
                calls += 1;
                if calls == total {
                    Connection::open(&path)
                        .unwrap()
                        .execute(
                            "UPDATE obligations SET checksum=zeroblob(32) WHERE operation=?1",
                            [contract.operation().as_slice()],
                        )
                        .unwrap();
                }
                Ok(())
            });
        assert_eq!(calls, total);
        record("final_callback_metadata_change", corrupt, calls, &result);
        outer_errors += usize::from(matches!(
            result,
            Err(CellErrorV1::Invalid("retention row integrity"))
        ));
    }
    assert_eq!(
        outer_errors, 2,
        "metadata failure must remain an outer error after the last callback"
    );
}

#[test]
fn sp27_observation_owner_scope_and_operation_errors_are_not_erasures() {
    let (dir, fixture, contract, mut provider) = prepared(true);
    let before = ledger(&dir.path().join("provider"), contract.operation());
    let wrong_operation =
        provider.read_observed_v2(&contract, [99; 32], deadline(), &mut || Ok(()));
    record("wrong_operation", true, 1, &wrong_operation);
    assert!(matches!(
        wrong_operation,
        Err(CellErrorV1::Invalid("RS46 provider operation pin"))
    ));
    for (name, field) in [
        ("owner_generation", 0),
        ("provider_store", 1),
        ("original_operation_scope", 2),
        ("context_scope", 3),
    ] {
        let mut owner = contract.owner().clone();
        match field {
            0 => owner.owner_generation += 1,
            1 => owner.provider_store = [199; 32],
            2 => owner.original_operation = [199; 32],
            3 => owner.context.runtime = [199; 32],
            _ => unreachable!(),
        }
        let changed = CellRs46ShardContractV1::from_verified_shard(
            owner,
            &fixture.binding,
            &fixture.codeword,
            &fixture.placement,
            &fixture.wires[0],
        )
        .unwrap();
        let mut calls = 0;
        let result =
            provider.read_observed_v2(&changed, changed.operation(), deadline(), &mut || {
                calls += 1;
                Ok(())
            });
        record(name, true, calls, &result);
        assert!(
            result.is_err(),
            "{name} cannot be a rejected payload observation"
        );
    }
    assert_eq!(
        ledger(&dir.path().join("provider"), contract.operation()),
        before
    );
}

#[test]
fn sp27_observation_cancel_and_original_deadline_dominate_completed_fault() {
    for corrupt in [false, true] {
        let (_dir, _fixture, contract, mut provider) = prepared(corrupt);
        let total = count_callbacks(&mut provider, &contract, corrupt);
        let mut calls = 0;
        let cancelled =
            provider.read_observed_v2(&contract, contract.operation(), deadline(), &mut || {
                calls += 1;
                if calls == total {
                    Err(CellErrorV1::Invalid("SP27 final owner cancellation"))
                } else {
                    Ok(())
                }
            });
        record("final_callback_cancellation", corrupt, calls, &cancelled);
        assert_eq!(calls, total);
        assert!(matches!(
            cancelled,
            Err(CellErrorV1::Invalid("SP27 final owner cancellation"))
        ));
        let end = Instant::now() + Duration::from_secs(1);
        calls = 0;
        let expired = provider.read_observed_v2(&contract, contract.operation(), end, &mut || {
            calls += 1;
            if calls == total {
                std::thread::sleep(
                    end.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
                );
            }
            Ok(())
        });
        record(
            "original_deadline_at_final_callback",
            corrupt,
            calls,
            &expired,
        );
        assert_eq!(
            calls, total,
            "setup must reach the intended final boundary before the original deadline"
        );
        assert!(matches!(
            expired,
            Err(CellErrorV1::Invalid("RS46 provider deadline"))
        ));
    }
}

#[test]
fn sp27_observation_payload_digest_mismatch_is_not_an_admissible_csp1() {
    let fixture = Fixture::new();
    let contract = fixture.contract(0, 1);
    let original = contract.manifest().encode();
    let malformed = CellManifestV1::new(
        contract.manifest().context().clone(),
        contract.manifest().size(),
        [201; 32],
        MAX_CHUNK_BYTES,
        contract.manifest().chunks().to_vec(),
    )
    .unwrap();
    let mut wire = contract.encode();
    assert!(wire.ends_with(&original));
    wire.truncate(wire.len() - original.len() - 4);
    wire.extend_from_slice(&(malformed.encode().len() as u32).to_be_bytes());
    wire.extend_from_slice(&malformed.encode());
    let mut hash = Sha256::new();
    hash.update(b"trnm.cell-rs46-provider-slot.v1\0");
    hash.update(&wire);
    let repinned = hash.finalize().into();
    let result = CellRs46ShardContractV1::decode_pinned(&wire, &fixture.binding, repinned);
    println!(
        "SP27_BOUNDARY_JSON {}",
        serde_json::json!({
            "schema":"sp27-05.native-observation-boundary-control.v1",
            "case":"repinned_csp1_single_chunk_payload_digest_disagreement",
            "outer_error":result.as_ref().err().map(|error|format!("{error:?}")),
            "physical_payload_read_performed":false,
            "scope":"malformed metadata decoder control; not a PayloadDigest I/O observation"
        })
    );
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("RS46 provider manifest binding"))
    ));
}
