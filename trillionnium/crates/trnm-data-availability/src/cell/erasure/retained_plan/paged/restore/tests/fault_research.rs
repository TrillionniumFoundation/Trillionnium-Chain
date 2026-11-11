//! Fixed-source SP27-05 functional counterexamples. Single-host local providers.
//! These timings are diagnostics, not independent-domain or speedup evidence.

use super::*;
use std::io::{Read, Seek, SeekFrom, Write};

mod matrix;
mod process_restart;

fn corrupt_first_payload(fixture: &Fixture, slot: usize) {
    let path = fixture
        .directory
        .path()
        .join(format!("provider-{slot}/payload.arena"));
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut value = [0];
    file.read_exact(&mut value).unwrap();
    value[0] ^= 1;
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&value).unwrap();
    file.sync_all().unwrap();
}

fn observed_read(
    fixture: &Fixture,
    contract: &CellRs46ShardContractV1,
    end: Instant,
    available: &[usize],
    faults: &mut Vec<serde_json::Value>,
    delivered: &mut u64,
) -> CellResultV1<Option<Vec<u8>>> {
    let slot = fixture.slots[&contract.operation()];
    if !available.contains(&slot) {
        return Ok(None);
    }
    match fixture.providers.borrow_mut()[slot].read_observed_v2(
        contract,
        contract.operation(),
        end,
        &mut || Ok(()),
    )? {
        CellRs46ProviderReadObservationV2::Verified(actual) => {
            let wire = actual.shard().encode();
            *delivered += wire.len() as u64;
            Ok(Some(wire))
        }
        CellRs46ProviderReadObservationV2::Rejected(fault) => {
            faults.push(serde_json::json!({
                "slot": slot,
                "stage": format!("{:?}", fault.stage()),
                "operation": hex::encode(fault.operation()),
                "provider_store": hex::encode(fault.provider_store()),
                "original_error": format!("{:?}", fault.original_error()),
                "expected_bytes": fault.expected_bytes(),
                "provider_payload_read_byte_bounds": fault.read_bytes_bounds(),
            }));
            Ok(None)
        }
    }
}

#[test]
fn sp27_payload_fault_with_five_healthy_providers_reproduces_wrapper_failure() {
    let fixture = Fixture::new(2, 2);
    corrupt_first_payload(&fixture, 0);
    let baseline = cache(&fixture.directory.path().join("baseline.sqlite"));
    let mut baseline_budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(1)).unwrap();
    let mut baseline_delivered = 0_u64;
    let begin = Instant::now();
    let result = fixture.restore(&baseline, &mut baseline_budget, |contract, end| {
        let wire = fixture.read_subset(contract, end, &[0, 1, 2, 3, 4, 5])?;
        baseline_delivered += wire.as_ref().map_or(0, |wire| wire.len() as u64);
        Ok(wire)
    });
    let baseline_ns = begin.elapsed().as_nanos();
    assert!(result.is_err());
    let baseline_error = format!("{:?}", result.unwrap_err());
    let target = cache(&fixture.directory.path().join("observed.sqlite"));
    let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(1)).unwrap();
    let mut faults = Vec::new();
    let mut delivered = 0;
    let begin = Instant::now();
    let actual = fixture
        .restore(&target, &mut budget, |contract, end| {
            observed_read(
                &fixture,
                contract,
                end,
                &[0, 1, 2, 3, 4, 5],
                &mut faults,
                &mut delivered,
            )
        })
        .unwrap();
    let observed_ns = begin.elapsed().as_nanos();
    assert_eq!(faults.len(), 1);
    assert_eq!(actual.content, fixture.content.commitment());
    assert_eq!(actual.version, fixture.contract.version.commitment());
    assert_eq!(actual.chunks, 3);
    assert_eq!(actual.usage, baseline_budget.usage());
    println!(
        "SP27_JSON {}",
        serde_json::json!({
            "schema": "sp27-05-functional-native-v1",
            "case": "one_actual_arena_byte_corrupt_five_healthy",
            "source_base": "8dee97636e2b6932fb7a22b1b54f2cab09ae8406",
            "baseline": {"success": false, "error": baseline_error, "elapsed_ns": baseline_ns, "delivered_wire_bytes": baseline_delivered},
            "typed": {"success": true, "elapsed_ns": observed_ns, "delivered_wire_bytes": delivered, "faults": faults},
            "payload_bytes": actual.payload_bytes,
            "chunks": actual.chunks,
            "verified_shards": actual.verified_shards,
            "missing_shards": actual.missing_shards,
            "reserved_input_bytes_each": actual.usage.input_bytes_committed,
            "reserved_provider_reads_each": actual.usage.provider_reads_committed,
            "scope": "single-host; sequential order; diagnostic only; no actual model forward in this fixture"
        })
    );
}

#[test]
fn sp27_typed_payload_faults_preserve_cancellation_and_contract_errors() {
    let fixture = Fixture::new(2, 2);
    let page = fixture.plan.read_page(0, deadline()).unwrap();
    let contract = page.chunks()[0].slots()[0].clone();
    corrupt_first_payload(&fixture, 0);
    let mut callbacks = 0;
    let observed = fixture.providers.borrow_mut()[0]
        .read_observed_v2(&contract, contract.operation(), deadline(), &mut || {
            callbacks += 1;
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        observed,
        CellRs46ProviderReadObservationV2::Rejected(_)
    ));
    for stop_at in 1..=callbacks {
        let mut count = 0;
        let stopped = fixture.providers.borrow_mut()[0].read_observed_v2(
            &contract,
            contract.operation(),
            deadline(),
            &mut || {
                count += 1;
                if count == stop_at {
                    Err(CellErrorV1::Invalid("SP27 original cancellation"))
                } else {
                    Ok(())
                }
            },
        );
        assert!(
            matches!(
                stopped,
                Err(CellErrorV1::Invalid("SP27 original cancellation"))
            ),
            "checkpoint {stop_at}/{callbacks}"
        );
    }
    assert!(fixture.providers.borrow_mut()[0]
        .read_observed_v2(&contract, [0; 32], deadline(), &mut || Ok(()),)
        .is_err());
    assert!(fixture.providers.borrow_mut()[1]
        .read_observed_v2(&contract, contract.operation(), deadline(), &mut || Ok(()),)
        .is_err());
    assert!(fixture.providers.borrow_mut()[0]
        .read_observed_v2(&contract, contract.operation(), Instant::now(), &mut || Ok(
            ()
        ),)
        .is_err());
    println!(
        "SP27_JSON {}",
        serde_json::json!({"schema":"sp27-05-functional-native-v1", "case":"all_cancel_checkpoints_and_wrong_operation_owner_deadline", "cancel_checkpoints": callbacks, "success":true})
    );
}

#[test]
fn sp27_typed_payload_faults_do_not_hide_descriptor_substitution() {
    let fixture = Fixture::new(2, 2);
    let page = fixture.plan.read_page(0, deadline()).unwrap();
    let contract = page.chunks()[0].slots()[0].clone();
    corrupt_first_payload(&fixture, 0);
    let path = fixture
        .directory
        .path()
        .join("provider-0/slot-descriptors-v1")
        .join(hex::encode(contract.operation()));
    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(path, bytes).unwrap();
    let result = fixture.providers.borrow_mut()[0].read_observed_v2(
        &contract,
        contract.operation(),
        deadline(),
        &mut || Ok(()),
    );
    assert!(result.is_err());
    println!(
        "SP27_JSON {}",
        serde_json::json!({"schema":"sp27-05-functional-native-v1", "case":"payload_fault_and_descriptor_change_remain_fatal", "error":format!("{:?}",result.unwrap_err()), "success":true})
    );
}
