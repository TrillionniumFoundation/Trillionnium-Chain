//! Persist with one process; exit; reopen and fully recover with fresh processes.
//! These are orderly local process exits, not host crashes or power-loss tests.

use super::*;
use serde_json::{json, Value};
use std::{path::Path, process::Command};

const NAME: &str = "cell::erasure::retained_plan::paged::restore::tests::fault_research::process_restart::sp27_provider_process_restart_clean_and_payload_fault";

fn config() -> CellVersionRetentionConfigV3 {
    CellVersionRetentionConfigV3 {
        retention: CellRetentionConfigV1 {
            store_id: [73; 32],
            capacity_bytes: 8 << 20,
            maximum_obligations: 64,
        },
        maximum_versions: 16,
        maximum_metadata_bytes: 16 << 20,
    }
}

fn provider_config(slot: u64) -> CellRs46ShardProviderConfigV1 {
    CellRs46ShardProviderConfigV1 {
        placement: CellRs46ShardPlacementV1 {
            provider_id: identity(30, slot),
            responsible_owner: identity(31, slot),
            administrator: identity(32, slot),
            failure_domain: identity(33, slot),
            domain_evidence: identity(34, slot),
            repair_owner: identity(35, slot),
        },
        owner_generation: 1,
        capacity_bytes: 4 << 20,
        maximum_obligations: 256,
    }
}

fn write_json(path: &Path, value: &Value) {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .unwrap();
    file.write_all(&serde_json::to_vec_pretty(value).unwrap())
        .unwrap();
    file.sync_all().unwrap();
}

fn writer(output: &Path, corrupt: bool) {
    let fixture = Fixture::new(2, 2);
    if corrupt {
        corrupt_first_payload(&fixture, 0);
    }
    let contract = fixture.contract.encode(&config()).unwrap();
    let content = fixture.content.encode();
    fs::write(output.join("contract.tca3"), &contract).unwrap();
    fs::write(output.join("content.tcv2"), &content).unwrap();
    let receipt = json!({
        "writer_pid":std::process::id(),"root":fixture.directory.path(),"corrupt_slot":if corrupt {Some(0)} else {None},
        "plan":hex::encode(fixture.plan.commitment()),"anchor":hex::encode(fixture.catalog.anchor(deadline()).unwrap().encode()),
        "content":hex::encode(fixture.content.commitment()),"version":hex::encode(fixture.contract.version.commitment()),
        "contract_sha256":hex::encode(Sha256::digest(&contract)),"content_sha256":hex::encode(Sha256::digest(&content)),
        "publisher_and_staging_caches_deleted":!fixture.directory.path().join("publisher.sqlite").exists()&&!fixture.directory.path().join("delivery.sqlite").exists(),
        "source_catalog_payload_zeroed":true,"payload_bytes":32788,
    });
    // Close every handle before returning; the parent waits for process exit.
    let Fixture {
        directory,
        catalog,
        plan,
        contract: _,
        content: _,
        providers,
        slots: _,
    } = fixture;
    drop(providers);
    drop(plan);
    drop(catalog);
    let persisted = directory.keep();
    assert_eq!(persisted, Path::new(receipt["root"].as_str().unwrap()));
    write_json(&output.join("writer.json"), &receipt);
}

fn reader(output: &Path, typed: bool) {
    let record: Value =
        serde_json::from_slice(&fs::read(output.join("writer.json")).unwrap()).unwrap();
    assert_ne!(
        record["writer_pid"].as_u64().unwrap(),
        u64::from(std::process::id())
    );
    let root = Path::new(record["root"].as_str().unwrap());
    let contract_bytes = fs::read(output.join("contract.tca3")).unwrap();
    let content_bytes = fs::read(output.join("content.tcv2")).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&contract_bytes)),
        record["contract_sha256"]
    );
    assert_eq!(
        hex::encode(Sha256::digest(&content_bytes)),
        record["content_sha256"]
    );
    let contract = CellVersionRetentionContractV3::decode(&contract_bytes, &config()).unwrap();
    let content = CellVersionContentV2::decode(&content_bytes).unwrap();
    assert_eq!(hex::encode(content.commitment()), record["content"]);
    assert_eq!(
        hex::encode(contract.version.commitment()),
        record["version"]
    );
    let anchor = CellVersionCatalogAnchorV3::decode(
        &hex::decode(record["anchor"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let catalog =
        CellVersionRetentionStoreV3::open(&root.join("catalog"), config(), anchor).unwrap();
    let plan = CellPagedRetainedShardPlanFileV2::open(
        &root.join("plan"),
        hex::decode(record["plan"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        deadline(),
    )
    .unwrap();
    let mut providers = (0..6)
        .map(|slot| {
            CellRs46ShardProviderV1::open(
                &root.join(format!("provider-{slot}")),
                provider_config(slot),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let target = cache(&root.join(if typed {
        "new-process-typed.sqlite"
    } else {
        "new-process-legacy.sqlite"
    }));
    assert_eq!(target.cache_usage().unwrap().chunk_rows, 0);
    let mut budget = CellPagedShardRestoreBudgetV2::new(CellPagedShardRestoreLimitsV2 {
        deadline: deadline(),
        maximum_attempts: 1,
        maximum_chunks: 4096,
        maximum_provider_reads: 6 * 4096,
        maximum_input_bytes: 32 << 20,
        maximum_reconstruction_bytes: 32 << 20,
        maximum_cache_bytes: 32 << 20,
        maximum_readback_payload_bytes: 32 << 20,
        maximum_readback_chunks: 4096,
    })
    .unwrap();
    let model = contract.model.loader_context();
    let environment = contract.environment.loader_context();
    let mut faults = Vec::new();
    let mut delivered = 0_u64;
    let result = restore_cell_paged_version_to_cache_v2(
        CellPagedShardRestoreRequestV2 {
            plan_file: &plan,
            catalog: &catalog,
            current_height: 11,
            original_root_operation: contract.operation,
            content: &content,
            expected: &CellVersionLoaderContextV1 {
                commitment: contract.version.commitment(),
                model: &model,
                environment: &environment,
            },
            content_pin: content.commitment(),
            target: &target,
        },
        &mut budget,
        |duty, end| {
            let slot = usize::from(duty.owner().slot);
            let wire = if typed {
                match providers[slot]
                    .read_observed_v2(duty, duty.operation(), end, &mut || Ok(()))?
                {
                    CellRs46ProviderReadObservationV2::Verified(stored) => stored.shard().encode(),
                    CellRs46ProviderReadObservationV2::Rejected(fault) => {
                        faults.push(json!({"slot":slot,"stage":format!("{:?}",fault.stage()),"original_error":format!("{:?}",fault.original_error()),"read_byte_bounds":fault.read_bytes_bounds()}));
                        return Ok(None);
                    }
                }
            } else {
                providers[slot]
                    .read(duty.binding(), duty.operation(), end, &mut || Ok(()))?
                    .shard()
                    .encode()
            };
            delivered += wire.len() as u64;
            Ok(Some(wire))
        },
    );
    let success = result.is_ok();
    if let Ok(readback) = &result {
        assert_eq!(readback.content, content.commitment());
        assert_eq!(readback.version, contract.version.commitment());
        assert_eq!(readback.payload_bytes, 32788);
    }
    let value = json!({"reader_pid":std::process::id(),"writer_pid":record["writer_pid"],"typed":typed,
        "success":success,"error":result.err().map(|e|format!("{e:?}")),"typed_faults":faults,
        "delivered_wire_bytes":delivered,"content":record["content"],"version":record["version"],
        "reserved_reads":budget.usage().provider_reads_committed,"source_and_staging_absent":!root.join("publisher.sqlite").exists()&&!root.join("delivery.sqlite").exists(),
        "catalog_payload_still_zero":fs::read(root.join("catalog/objects/payload.arena")).unwrap().iter().all(|b|*b==0),
    });
    write_json(
        &output.join(if typed {
            "reader-typed.json"
        } else {
            "reader-legacy.json"
        }),
        &value,
    );
    assert_eq!(success, typed || record["corrupt_slot"].is_null());
}

#[test]
fn sp27_provider_process_restart_clean_and_payload_fault() {
    if let Ok(phase) = std::env::var("SP27_PROVIDER_PHASE") {
        let output = std::env::var("SP27_PROVIDER_CASE_DIR").unwrap();
        let output = Path::new(&output);
        match phase.as_str() {
            "writer" => writer(
                output,
                std::env::var("SP27_PROVIDER_CORRUPT").unwrap() == "1",
            ),
            "reader-legacy" => reader(output, false),
            "reader-typed" => reader(output, true),
            _ => panic!("unknown SP27 process stage"),
        }
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let output = std::env::var("SP27_PROVIDER_PROCESS_OUTPUT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| temporary.path().join("observations"));
    fs::create_dir(&output).unwrap();
    for corrupt in [false, true] {
        let case = output.join(if corrupt { "one-corrupt" } else { "clean" });
        fs::create_dir(&case).unwrap();
        let mut phases = Vec::new();
        for phase in ["writer", "reader-legacy", "reader-typed"] {
            let child = Command::new(std::env::current_exe().unwrap())
                .args([NAME, "--exact", "--nocapture", "--test-threads=1"])
                .env("SP27_PROVIDER_PHASE", phase)
                .env("SP27_PROVIDER_CASE_DIR", &case)
                .env("SP27_PROVIDER_CORRUPT", if corrupt { "1" } else { "0" })
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let pid = child.id();
            let observed = child.wait_with_output().unwrap();
            fs::write(case.join(format!("{phase}.stdout.log")), &observed.stdout).unwrap();
            fs::write(case.join(format!("{phase}.stderr.log")), &observed.stderr).unwrap();
            phases.push(json!({"phase":phase,"pid":pid,"exit_code":observed.status.code(),"waited_for_exit_before_next_phase":true}));
            assert!(
                observed.status.success(),
                "{phase} {:?}",
                String::from_utf8_lossy(&observed.stdout)
            );
        }
        let writer: Value =
            serde_json::from_slice(&fs::read(case.join("writer.json")).unwrap()).unwrap();
        let legacy: Value =
            serde_json::from_slice(&fs::read(case.join("reader-legacy.json")).unwrap()).unwrap();
        let typed: Value =
            serde_json::from_slice(&fs::read(case.join("reader-typed.json")).unwrap()).unwrap();
        let record = json!({"schema":"sp27-05-provider-process-restart.v1","case":if corrupt {"one_corrupt"} else {"clean"},
            "parent_pid":std::process::id(),"phases":phases,"writer":writer,"legacy":legacy,"typed":typed,
            "scope":"single-host orderly provider-owner process exit and recreation; no power loss, OS restart or independent domain"});
        write_json(&case.join("result.json"), &record);
        println!("SP27_JSON {record}");
        fs::remove_dir_all(Path::new(writer["root"].as_str().unwrap())).unwrap();
    }
}
