//! Four explicit recovery arms. Results must retain scheme and fault semantics.

use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
struct Scenario {
    name: &'static str,
    missing: &'static [usize],
    corrupt: &'static [usize],
    mix: &'static [usize],
    reopen: bool,
    interrupt: bool,
    wrong_content: bool,
}

fn scenarios() -> Vec<Scenario> {
    let base = Scenario {
        name: "clean",
        missing: &[],
        corrupt: &[],
        mix: &[],
        reopen: false,
        interrupt: false,
        wrong_content: false,
    };
    vec![
        base,
        Scenario {
            name: "missing_1",
            missing: &[5],
            ..base
        },
        Scenario {
            name: "missing_2",
            missing: &[4, 5],
            ..base
        },
        Scenario {
            name: "missing_3",
            missing: &[3, 4, 5],
            ..base
        },
        Scenario {
            name: "corrupt_1",
            corrupt: &[0],
            ..base
        },
        Scenario {
            name: "corrupt_2",
            corrupt: &[0, 1],
            ..base
        },
        Scenario {
            name: "corrupt_3",
            corrupt: &[0, 1, 2],
            ..base
        },
        Scenario {
            name: "corrupt_1_missing_1",
            corrupt: &[0],
            missing: &[5],
            ..base
        },
        Scenario {
            name: "corrupt_1_missing_2",
            corrupt: &[0],
            missing: &[4, 5],
            ..base
        },
        Scenario {
            name: "mixed_version_1",
            mix: &[0],
            ..base
        },
        Scenario {
            name: "mixed_version_2",
            mix: &[0, 1],
            ..base
        },
        Scenario {
            name: "mixed_version_3",
            mix: &[0, 1, 2],
            ..base
        },
        Scenario {
            name: "providers_reopened",
            reopen: true,
            ..base
        },
        Scenario {
            name: "providers_reopened_corrupt_1",
            reopen: true,
            corrupt: &[0],
            ..base
        },
        Scenario {
            name: "cooperative_interruption_then_retry",
            interrupt: true,
            ..base
        },
        Scenario {
            name: "expected_content_changed",
            wrong_content: true,
            ..base
        },
    ]
}

fn positions(fixture: &Fixture) -> BTreeMap<CellDigestV1, u64> {
    let mut out = BTreeMap::new();
    for slot in 0..6 {
        let db = rusqlite::Connection::open_with_flags(
            fixture
                .directory
                .path()
                .join(format!("provider-{slot}/retention.sqlite")),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let mut query = db
            .prepare("SELECT operation, position FROM obligations")
            .unwrap();
        for row in query
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, u64>(1)?))
            })
            .unwrap()
        {
            let (operation, position) = row.unwrap();
            out.insert(operation.try_into().unwrap(), position);
        }
    }
    out
}

fn raw_read(
    fixture: &Fixture,
    contract: &CellRs46ShardContractV1,
    offsets: &BTreeMap<CellDigestV1, u64>,
) -> CellResultV1<Vec<u8>> {
    let slot = fixture.slots[&contract.operation()];
    let mut file = fs::File::open(
        fixture
            .directory
            .path()
            .join(format!("provider-{slot}/payload.arena")),
    )?;
    file.seek(SeekFrom::Start(offsets[&contract.operation()]))?;
    let mut wire = vec![0; contract.manifest().size() as usize];
    file.read_exact(&mut wire)?;
    Ok(wire)
}

fn copy_material(fixture: &Fixture) -> (Vec<(CellManifestV1, Vec<u8>)>, u64) {
    let path = fixture.directory.path().join("setup-copy-source.sqlite");
    let target = cache(&path);
    let mut budget = CellPagedShardRestoreBudgetV2::new(fixture.limits(1)).unwrap();
    let readback = fixture
        .restore(&target, &mut budget, |contract, end| {
            fixture.read_subset(contract, end, &[0, 1, 2, 3, 4, 5])
        })
        .unwrap();
    let mut objects = Vec::new();
    for manifest in fixture.contract.version.manifests() {
        let mut bytes = Vec::new();
        for chunk in manifest.chunks() {
            bytes.extend_from_slice(&target.chunk(chunk.sha256).unwrap().unwrap());
        }
        assert_eq!(bytes.len() as u64, manifest.size());
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&bytes)),
            manifest.payload_sha256()
        );
        for slot in 0..6 {
            let dir = fixture.directory.path().join(format!("full-copy-{slot}"));
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(hex::encode(manifest.id())), &bytes).unwrap();
        }
        objects.push((manifest.clone(), bytes));
    }
    drop(target);
    fs::remove_file(path).unwrap();
    (objects, readback.payload_bytes)
}

fn reopen_providers(fixture: &Fixture) {
    fixture.providers.borrow_mut().clear();
    for slot in 0..6 {
        let config = CellRs46ShardProviderConfigV1 {
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
        };
        fixture.providers.borrow_mut().push(
            CellRs46ShardProviderV1::open(
                &fixture.directory.path().join(format!("provider-{slot}")),
                config,
            )
            .unwrap(),
        );
    }
}

fn apply_faults(
    fixture: &Fixture,
    scenario: Scenario,
    objects: &[(CellManifestV1, Vec<u8>)],
    offsets: &BTreeMap<CellDigestV1, u64>,
) {
    let page = fixture.plan.read_page(0, deadline()).unwrap();
    let chunk = &page.chunks()[0];
    let (manifest, original) = objects
        .iter()
        .find(|(m, _)| m.id() == chunk.manifest())
        .unwrap();
    let original_chunk = &original[..chunk.binding().source_bytes() as usize];
    let mut other = original_chunk.to_vec();
    other[0] ^= 1;
    let mut context = manifest.context().clone();
    context.base[0] ^= 1;
    let digest: CellDigestV1 = Sha256::digest(&other).into();
    let other_manifest = CellManifestV1::new(
        context.clone(),
        other.len() as u64,
        digest,
        16_384,
        vec![CellChunkV1 {
            size: other.len() as u32,
            sha256: digest,
        }],
    )
    .unwrap();
    let other_binding = CellRs46ChunkBindingV1::from_pinned_manifest(
        &other_manifest,
        other_manifest.id(),
        &context,
        0,
    )
    .unwrap();
    let alternate = other_binding.encode_chunk(&other).unwrap();
    for slot in scenario.corrupt {
        corrupt_first_payload(fixture, *slot);
    }
    for slot in scenario.mix {
        let contract = &chunk.slots()[*slot];
        let mut arena = fs::OpenOptions::new()
            .write(true)
            .open(
                fixture
                    .directory
                    .path()
                    .join(format!("provider-{slot}/payload.arena")),
            )
            .unwrap();
        let wire = alternate[*slot].encode();
        assert_eq!(wire.len() as u64, contract.manifest().size());
        arena
            .seek(SeekFrom::Start(offsets[&contract.operation()]))
            .unwrap();
        arena.write_all(&wire).unwrap();
        arena.sync_all().unwrap();
    }
    for slot in scenario.corrupt.iter().chain(scenario.mix) {
        let path = fixture
            .directory
            .path()
            .join(format!("full-copy-{slot}"))
            .join(hex::encode(manifest.id()));
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let mut byte = [0];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 1;
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
    }
    if scenario.reopen {
        reopen_providers(fixture);
    }
}

struct CopyAttempt {
    interrupt_after_copy: bool,
    original_deadline: Instant,
}

fn full_copy_restore(
    fixture: &Fixture,
    scenario: Scenario,
    target: &CellStoreV1,
    bytes: &mut u64,
    provider_reads: &mut u64,
    errors: &mut Vec<serde_json::Value>,
    attempt: CopyAttempt,
) -> CellResultV1<()> {
    let CopyAttempt {
        interrupt_after_copy,
        original_deadline,
    } = attempt;
    require(
        Instant::now() < original_deadline,
        "SP27 full copy original deadline",
    )?;
    let model = fixture.contract.model.loader_context();
    let environment = fixture.contract.environment.loader_context();
    let expected = CellVersionLoaderContextV1 {
        commitment: fixture.contract.version.commitment(),
        model: &model,
        environment: &environment,
    };
    let mut pin = fixture.content.commitment();
    if scenario.wrong_content {
        pin[0] ^= 1;
    }
    fixture.content.pin_for_owner(&expected, pin)?;
    for manifest in fixture.contract.version.manifests() {
        let mut found = false;
        for slot in 0..6 {
            require(
                Instant::now() < original_deadline,
                "SP27 full copy original deadline",
            )?;
            if scenario.missing.contains(&slot) {
                continue;
            }
            *provider_reads += 1;
            let path = fixture
                .directory
                .path()
                .join(format!("full-copy-{slot}"))
                .join(hex::encode(manifest.id()));
            let actual = fs::read(path)?;
            require(
                Instant::now() < original_deadline,
                "SP27 full copy original deadline",
            )?;
            *bytes += actual.len() as u64;
            if actual.len() as u64 != manifest.size()
                || <[u8; 32]>::from(Sha256::digest(&actual)) != manifest.payload_sha256()
            {
                errors.push(serde_json::json!({"slot":slot,"stage":"full_copy_payload_digest"}));
                continue;
            }
            for (chunk, raw) in manifest.chunks().iter().zip(actual.chunks(16_384)) {
                target.put_chunk(chunk, raw)?;
            }
            target.put_manifest(manifest.id(), &manifest.encode())?;
            if interrupt_after_copy {
                return Err(CellErrorV1::Invalid(
                    "SP27 full copy cooperative interruption",
                ));
            }
            found = true;
            break;
        }
        require(found, "SP27 full copy no valid replica")?;
    }
    let mut readback = CellContentReadSessionV2::new(
        CellReleaseLimitsV1 {
            max_payload_bytes: 32 << 20,
            max_chunks: 4096,
            deadline: original_deadline,
        },
        1,
    )?;
    fixture
        .content
        .verify_cached(target, &expected, pin, &mut readback)?;
    Ok(())
}

fn process_usage() -> Option<(u64, u64)> {
    // Linux procfs observations avoid introducing unsafe code into this crate.
    // The scheduler value belongs to the calling test thread, not all children.
    let scheduler = fs::read_to_string("/proc/thread-self/schedstat").ok()?;
    let thread_cpu_ns = scheduler.split_whitespace().next()?.parse().ok()?;
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let peak_kib: u64 = status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((thread_cpu_ns, peak_kib * 1024))
}

#[test]
#[ignore = "explicit single-host research matrix; run with --nocapture --test-threads=1"]
fn sp27_storage_fault_matrix() {
    let repetitions = std::env::var("SP27_STORAGE_REPETITIONS")
        .ok()
        .map(|x| x.parse::<usize>().unwrap())
        .unwrap_or(2);
    assert!((1..=8).contains(&repetitions));
    let mut output = std::env::var("SP27_STORAGE_OUTPUT").ok().map(|path| {
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .unwrap()
    });
    let schemes = [
        "full_copy_6",
        "standard_rs_raw_wire",
        "paged_fail_fast",
        "typed_payload_observation",
    ];
    let mut rows = 0;
    for chunks in [1, 8] {
        for (scenario_index, scenario) in scenarios().into_iter().enumerate() {
            for repeat in 0..repetitions {
                for position in 0..schemes.len() {
                    let scheme = schemes[(position + repeat + scenario_index) % schemes.len()];
                    // Each arm gets a separately created deterministic fixture.
                    // Full replicas are physically absent during every RS arm.
                    let fixture = Fixture::new(chunks, 2);
                    let offsets = positions(&fixture);
                    let (objects, payload_bytes) = copy_material(&fixture);
                    apply_faults(&fixture, scenario, &objects, &offsets);
                    drop(objects);
                    if scheme != "full_copy_6" {
                        for slot in 0..6 {
                            fs::remove_dir_all(
                                fixture.directory.path().join(format!("full-copy-{slot}")),
                            )
                            .unwrap();
                        }
                    }
                    assert!(!fixture.directory.path().join("publisher.sqlite").exists());
                    assert!(!fixture.directory.path().join("delivery.sqlite").exists());
                    assert!(!fixture
                        .directory
                        .path()
                        .join("setup-copy-source.sqlite")
                        .exists());
                    let target = cache(
                        &fixture
                            .directory
                            .path()
                            .join(format!("target-{scheme}.sqlite")),
                    );
                    let mut delivered = 0_u64;
                    let mut reads = 0_u64;
                    let mut faults = Vec::new();
                    let usage_before = process_usage();
                    let begin = Instant::now();
                    let limits = fixture.limits(if scenario.interrupt { 2 } else { 1 });
                    let original_deadline = limits.deadline;
                    let mut budget = CellPagedShardRestoreBudgetV2::new(limits).unwrap();
                    let mut interruptions = Vec::new();
                    let result: CellResultV1<()> = if scheme == "full_copy_6" {
                        if scenario.interrupt {
                            let stopped = full_copy_restore(
                                &fixture,
                                scenario,
                                &target,
                                &mut delivered,
                                &mut reads,
                                &mut faults,
                                CopyAttempt {
                                    interrupt_after_copy: true,
                                    original_deadline,
                                },
                            );
                            assert!(stopped.is_err());
                            interruptions.push(serde_json::json!({"error":format!("{:?}",stopped.unwrap_err()),"scope":"one copied manifest then cooperative stop; no shared paged attempt budget"}));
                        }
                        full_copy_restore(
                            &fixture,
                            scenario,
                            &target,
                            &mut delivered,
                            &mut reads,
                            &mut faults,
                            CopyAttempt {
                                interrupt_after_copy: false,
                                original_deadline,
                            },
                        )
                    } else {
                        if scenario.interrupt {
                            let mut callbacks = 0;
                            let stopped = fixture.restore(&target, &mut budget, |contract, end| {
                                callbacks += 1;
                                if callbacks == 2 {
                                    return Err(CellErrorV1::Invalid(
                                        "SP27 cooperative interruption",
                                    ));
                                }
                                let wire =
                                    fixture.read_subset(contract, end, &[0, 1, 2, 3, 4, 5])?;
                                delivered += wire.as_ref().map_or(0, |wire| wire.len() as u64);
                                reads += 1;
                                Ok(wire)
                            });
                            assert!(stopped.is_err());
                            interruptions.push(serde_json::json!({"error":format!("{:?}",stopped.unwrap_err()),"attempts_reserved":budget.usage().attempts_committed,"callback_count":callbacks}));
                        }
                        let model = fixture.contract.model.loader_context();
                        let environment = fixture.contract.environment.loader_context();
                        let expected = CellVersionLoaderContextV1 {
                            commitment: fixture.contract.version.commitment(),
                            model: &model,
                            environment: &environment,
                        };
                        let mut pin = fixture.content.commitment();
                        if scenario.wrong_content {
                            pin[0] ^= 1;
                        }
                        let request = CellPagedShardRestoreRequestV2 {
                            plan_file: &fixture.plan,
                            catalog: &fixture.catalog,
                            current_height: 11,
                            original_root_operation: fixture.contract.operation,
                            content: &fixture.content,
                            expected: &expected,
                            content_pin: pin,
                            target: &target,
                        };
                        restore_cell_paged_version_to_cache_v2(
                            request,
                            &mut budget,
                            |contract, end| {
                                reads += 1;
                                let slot = fixture.slots[&contract.operation()];
                                if scenario.missing.contains(&slot) {
                                    return Ok(None);
                                }
                                if scheme == "typed_payload_observation" {
                                    observed_read(
                                        &fixture,
                                        contract,
                                        end,
                                        &[0, 1, 2, 3, 4, 5],
                                        &mut faults,
                                        &mut delivered,
                                    )
                                } else {
                                    let wire = if scheme == "standard_rs_raw_wire" {
                                        raw_read(&fixture, contract, &offsets)?
                                    } else {
                                        fixture
                                            .read_subset(contract, end, &[0, 1, 2, 3, 4, 5])?
                                            .unwrap()
                                    };
                                    delivered += wire.len() as u64;
                                    Ok(Some(wire))
                                }
                            },
                        )
                        .map(|_| ())
                    };
                    let elapsed_ns = begin.elapsed().as_nanos();
                    let usage_after = process_usage();
                    let resource=usage_before.zip(usage_after).map(|(before,after)|serde_json::json!({"calling_thread_cpu_ns":after.0-before.0,"process_cumulative_peak_rss_bytes":after.1,"scope":"calling-thread scheduler CPU delta; process lifetime high-water RSS, not per-case allocation peak; no host isolation claim"}));
                    let effective_bad = (0..6)
                        .filter(|slot| {
                            scenario.missing.contains(slot)
                                || scenario.corrupt.contains(slot)
                                || scenario.mix.contains(slot)
                        })
                        .count();
                    let expected_success = if scenario.wrong_content {
                        false
                    } else if scheme == "full_copy_6" {
                        effective_bad < 6
                    } else if scheme == "paged_fail_fast"
                        && (!scenario.corrupt.is_empty() || !scenario.mix.is_empty())
                    {
                        false
                    } else {
                        effective_bad <= 2
                    };
                    let recoverable_by_content_threshold = !scenario.wrong_content
                        && if scheme == "full_copy_6" {
                            effective_bad < 6
                        } else {
                            effective_bad <= 2
                        };
                    let success = result.is_ok();
                    let error = result.err().map(|e| format!("{e:?}"));
                    let record = serde_json::json!({
                        "schema":"sp27-05-matrix-native-v1","case":scenario.name,"scheme":scheme,"repetition":repeat,"arm_position":position,
                        "payload_bytes":payload_bytes,"model_chunks":chunks,"success":success,"expected_success_for_declared_scheme":expected_success,
                        "recoverable_by_content_threshold":recoverable_by_content_threshold,
                        "wrong_accept":success&&!recoverable_by_content_threshold,"wrong_reject":!success&&recoverable_by_content_threshold,"error":error,
                        "elapsed_ns":elapsed_ns,"delivered_wire_bytes":delivered,"callback_or_replica_reads":reads,"payload_faults":faults,"resource":resource,
                        "content_tcv2":hex::encode(fixture.content.commitment()),"version_tcv1":hex::encode(fixture.contract.version.commitment()),
                        "reserved_attempts":budget.usage().attempts_committed,"reserved_input_bytes":budget.usage().input_bytes_committed,
                        "reserved_reads":budget.usage().provider_reads_committed,"partial_cache_chunk_rows":target.cache_usage().unwrap().chunk_rows,
                        "interruption_observations":interruptions,"publisher_and_staging_caches_deleted":true,"full_copies_present_during_run":scheme=="full_copy_6","per_arm_fixture_isolated":true,
                        "original_deadline_shared_across_retries":true,
                        "mixed_version_fault_semantics":if scheme=="full_copy_6"{"one byte altered in selected complete-replica payload; no alternate replica manifest"}else{"valid raw RS wire from alternate content and context; original provider contract unchanged"},
                        "bytes_scope":"returned bytes only; excludes rejected provider arena bytes except separately recorded typed fault bounds; not disk or network total",
                        "storage_payload_bytes":if scheme=="full_copy_6"{6*payload_bytes}else{payload_bytes.div_ceil(4)*6+81*6*(chunks as u64+1)},
                        "scope":"single-host synthetic native fixture; no independent custody, no model forward; timing diagnostic only"
                    });
                    if let Some(file) = &mut output {
                        writeln!(file, "{record}").unwrap();
                        file.flush().unwrap();
                    }
                    println!("SP27_JSON {record}");
                    rows += 1;
                    assert_eq!(success, expected_success, "{} {}", scenario.name, scheme);
                }
            }
        }
    }
    println!("SP27_MATRIX_ROWS {rows}");
}
