//! Real native funding, M12 journal and complete model/environment target owner.

#[path = "version_shard_plan_tests.rs"]
mod shard_plan;
#[test]
fn native_version_reorg_keeps_custody_but_cannot_grant_new_funding_or_foreign_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open_node(
        &directory.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let genesis = node.settings.genesis();
    let (cache, contract) = version_material(directory.path());
    let path = directory.path().join("archive");
    let mut archive = CellVersionRetentionStoreV3::create(&path, version_config()).unwrap();
    let request = funded_version(&mut node, &archive, contract);
    let mut budgets =
        NativeBudgetStoreV1::open(&directory.path().join("budgets.sqlite"), config(&node)).unwrap();
    let first = node
        .retain_native_cell_version(
            &mut budgets,
            &mut archive,
            &cache,
            request.clone(),
            deadline(),
        )
        .unwrap();
    let original = physical_rows(&path);
    let charged = budgets.report().unwrap();
    // Four real funding transactions produced four blocks. The replacement
    // branch must carry strictly more verified work before activation.
    let mut fork = genesis;
    for _ in 0..5 {
        fork = mine(&mut node, fork, vec![]);
    }
    assert!(node
        .native_funding_observation(request.policy.source)
        .unwrap()
        .row
        .is_none());
    let empty = CellStoreV1::open(&directory.path().join("empty.sqlite"), cache_config()).unwrap();
    let replay = node
        .retain_native_cell_version(
            &mut budgets,
            &mut archive,
            &empty,
            request.clone(),
            deadline(),
        )
        .unwrap();
    assert_eq!(replay.replay, NativeBudgetReplayV1::Done);
    assert_eq!(replay.target, first.target);
    assert_eq!(physical_rows(&path), original);
    assert_eq!(budgets.report().unwrap(), charged);
    let mut fresh = request.clone();
    fresh.contract.operation = [74; 32];
    fresh.contract.funding_operation = [75; 32];
    fresh.policy.budget = [76; 32];
    fresh.claim.claim = fresh.contract.funding_operation;
    fresh.claim.budget = fresh.policy.budget;
    fresh.claim.subject = archive.contract_commitment(&fresh.contract).unwrap();
    assert!(node
        .retain_native_cell_version(&mut budgets, &mut archive, &cache, fresh, deadline(),)
        .is_err());
    assert_eq!(root_count(&path), 1);
    assert_eq!(budgets.report().unwrap(), charged);
    let settings = crate::Settings::development_with_profiles(
        Some(2),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let mut foreign = Node::open(&directory.path().join("foreign"), settings, 1).unwrap();
    let error = foreign
        .retire_native_cell_version(
            &budgets,
            &mut archive,
            request.contract.operation,
            deadline(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("BUDGET_NATIVE_CONTEXT"));
    assert_eq!(physical_rows(&path), original);
    advance_to(&mut node, 12);
    node.retire_native_cell_version(
        &budgets,
        &mut archive,
        request.contract.operation,
        deadline(),
    )
    .unwrap();
    assert!(node
        .retire_native_cell_version_member(
            &budgets,
            &mut archive,
            request.contract.operation,
            request.contract.objects[0].operation,
            None,
            deadline(),
        )
        .is_err());
    advance_to(&mut node, 16);
    assert!(
        node.retire_native_cell_version_member(
            &budgets,
            &mut archive,
            request.contract.operation,
            request.contract.objects[0].operation,
            None,
            deadline(),
        )
        .unwrap()
        .retired
    );
    assert_eq!(budgets.report().unwrap(), charged);
}

#[test]
fn native_version_scheduler_pending_metadata_accepts_only_new_funded_copy_then_reopens_done() {
    for backend in [
        StateBackend::AuthenticatedV1,
        StateBackend::PermanentAccountGrowthV2,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut node = open_node(&dir.path().join("node"), backend);
        let (cache, contract) = version_material(dir.path());
        let path = dir.path().join("owner");
        let mut owner = CellVersionRetentionStoreV3::create(&path, version_config()).unwrap();
        let request = funded_version(&mut node, &owner, contract);
        // Scheduler metadata is already Pending. No physical initial byte has
        // been copied and no M12 effect exists until the actual funded adapter.
        owner
            .reserve_version(
                request.contract.clone(),
                request.expected_catalog,
                deadline(),
            )
            .unwrap();
        assert!(physical_rows(&path).iter().all(|row| row.2 == 0));
        let journal = dir.path().join("budgets.sqlite");
        let mut budgets = NativeBudgetStoreV1::open(&journal, config(&node)).unwrap();
        let first = node
            .retain_native_cell_version(
                &mut budgets,
                &mut owner,
                &cache,
                request.clone(),
                deadline(),
            )
            .unwrap();
        assert_eq!(first.replay, NativeBudgetReplayV1::New);
        assert_eq!(first.target.version, request.contract.version.commitment());
        assert_eq!(first.target.objects.len(), 3);
        let physical = physical_rows(&path);
        assert_eq!(physical.iter().map(|row| row.2).sum::<u64>(), 651);
        let charged = budgets.report().unwrap();
        assert_eq!(charged["budgets"].as_array().unwrap().len(), 4);
        let anchor = owner.anchor(deadline()).unwrap();
        drop(owner);
        drop(budgets);
        drop(cache);
        for name in [
            "runtime.bin",
            "base.bin",
            "tokenizer.json",
            "version-cache.sqlite",
        ] {
            fs::remove_file(dir.path().join(name)).unwrap();
        }
        let empty = CellStoreV1::open(&dir.path().join("empty.sqlite"), cache_config()).unwrap();
        let mut owner = CellVersionRetentionStoreV3::open(&path, version_config(), anchor).unwrap();
        let mut budgets = NativeBudgetStoreV1::open(&journal, config(&node)).unwrap();
        let repeated = node
            .retain_native_cell_version(
                &mut budgets,
                &mut owner,
                &empty,
                request.clone(),
                deadline(),
            )
            .unwrap();
        assert_eq!(repeated.replay, NativeBudgetReplayV1::Done);
        assert_eq!(repeated.target, first.target);
        assert_eq!(physical_rows(&path), physical);
        assert_eq!(budgets.report().unwrap(), charged);
        assert!(node
            .retire_native_cell_version(
                &budgets,
                &mut owner,
                request.contract.operation,
                deadline()
            )
            .is_err());
        advance_to(&mut node, 16);
        node.retire_native_cell_version(
            &budgets,
            &mut owner,
            request.contract.operation,
            deadline(),
        )
        .unwrap();
        for object in &request.contract.objects {
            assert!(
                node.retire_native_cell_version_member(
                    &budgets,
                    &mut owner,
                    request.contract.operation,
                    object.operation,
                    None,
                    deadline()
                )
                .unwrap()
                .retired
            );
        }
        assert_eq!(budgets.report().unwrap(), charged);
    }
}

#[test]
fn native_version_pending_monetary_effect_cannot_retry_copy_with_a_new_source() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = open_node(
        &dir.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let (cache, contract) = version_material(dir.path());
    let path = dir.path().join("owner");
    let mut owner = CellVersionRetentionStoreV3::create(&path, version_config()).unwrap();
    let request = funded_version(&mut node, &owner, contract);
    let journal = dir.path().join("budgets.sqlite");
    let mut budgets = NativeBudgetStoreV1::open(&journal, config(&node)).unwrap();
    let empty = CellStoreV1::open(&dir.path().join("empty.sqlite"), cache_config()).unwrap();
    assert!(node
        .retain_native_cell_version(
            &mut budgets,
            &mut owner,
            &empty,
            request.clone(),
            deadline()
        )
        .is_err());
    let physical = physical_rows(&path);
    let charged = budgets.report().unwrap();
    assert!(physical.iter().any(|row| row.2 > 0));
    let bytes = fs::read(path.join("objects/payload.arena")).unwrap();
    let anchor = owner.anchor(deadline()).unwrap();
    drop(owner);
    drop(budgets);
    let mut owner = CellVersionRetentionStoreV3::open(&path, version_config(), anchor).unwrap();
    let mut budgets = NativeBudgetStoreV1::open(&journal, config(&node)).unwrap();
    assert!(node
        .retain_native_cell_version(&mut budgets, &mut owner, &cache, request, deadline())
        .is_err());
    assert_eq!(physical_rows(&path), physical);
    assert_eq!(fs::read(path.join("objects/payload.arena")).unwrap(), bytes);
    assert_eq!(budgets.report().unwrap(), charged);
}
#[test]
fn native_version_scope_alias_and_late_funding_errors_precede_every_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open_node(
        &directory.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let (cache, contract) = version_material(directory.path());
    let path = directory.path().join("archive");
    let mut archive = CellVersionRetentionStoreV3::create(&path, version_config()).unwrap();
    let request = funded_version(&mut node, &archive, contract);
    let mut budgets =
        NativeBudgetStoreV1::open(&directory.path().join("budgets.sqlite"), config(&node)).unwrap();
    let before = budgets.report().unwrap();
    for case in 0..11 {
        let mut wrong = request.clone();
        match case {
            0 => {
                wrong.members.pop();
            }
            1 => wrong.members.swap(0, 1),
            2 => wrong.claim.subject = [99; 32],
            3 => wrong.members[1].claim.subject = [99; 32],
            4 => wrong.policy.deadline = wrong.contract.retain_until_height - 1,
            5 => {
                wrong.members[1].policy.deadline = wrong.members[1].contract.retain_until_height - 1
            }
            6 => {
                wrong.members[1].claim.resource_reservation = NativeBudgetResourcesV1::Storage {
                    retained_bytes: wrong.members[1].contract.manifest.size(),
                    retained_byte_blocks: 1,
                }
            }
            7 => wrong.members[1].policy.source = wrong.policy.source,
            8 => wrong.members[1].claim.beneficiary = public(2),
            9 => wrong.policy.source = NativeFundingSourceV1::Task([99; 32]),
            10 => wrong.members[2].policy.source = NativeFundingSourceV1::Task([99; 32]),
            _ => unreachable!(),
        }
        assert!(
            node.retain_native_cell_version(&mut budgets, &mut archive, &cache, wrong, deadline(),)
                .is_err(),
            "case {case}"
        );
        assert_eq!(budgets.report().unwrap(), before, "case {case}");
        assert_eq!(root_count(&path), 0, "case {case}");
        assert!(physical_rows(&path).is_empty(), "case {case}");
    }
    assert!(node
        .retain_native_cell_version(
            &mut budgets,
            &mut archive,
            &cache,
            request,
            Instant::now() - Duration::from_secs(1),
        )
        .is_err());
    assert_eq!(budgets.report().unwrap(), before);
    assert_eq!(root_count(&path), 0);
}

#[test]
fn native_version_outer_history_cannot_invent_missing_member_intents() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open_node(
        &directory.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let (cache, contract) = version_material(directory.path());
    let path = directory.path().join("archive");
    let mut archive = CellVersionRetentionStoreV3::create(&path, version_config()).unwrap();
    let request = funded_version(&mut node, &archive, contract);
    let mut budgets =
        NativeBudgetStoreV1::open(&directory.path().join("budgets.sqlite"), config(&node)).unwrap();
    // This is valid generic M12 history, but not a valid completed Node release
    // composition. Use the original public owner calls; do not forge its rows.
    budgets
        .open_budget(&mut node, request.policy.clone())
        .unwrap();
    budgets.reserve(&mut node, request.claim.clone()).unwrap();
    budgets
        .begin_effect_in_window(
            &mut node,
            request.claim.claim,
            request.contract.operation,
            request.claim.subject,
            request.contract.retain_from_height,
            request.contract.retain_until_height,
        )
        .unwrap();
    for done in [false, true] {
        if done {
            let receipt = hash(
                b"trnm.native-cell-version-initial-readback.v3\0",
                &[&request.claim.subject],
            );
            budgets
                .complete_effect(request.claim.claim, request.contract.operation, receipt)
                .unwrap();
        }
        let before = budgets.report().unwrap();
        let error = node
            .retain_native_cell_version(
                &mut budgets,
                &mut archive,
                &cache,
                request.clone(),
                deadline(),
            )
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("NATIVE_CELL_VERSION_MEMBER_INTENT_MISSING"));
        assert_eq!(budgets.report().unwrap(), before);
        assert_eq!(root_count(&path), 0);
        assert!(physical_rows(&path).is_empty());
    }
}

use super::*;
use trnm_data_availability::cell::{
    CellClosureFileV1, CellFileRoleV1, CellModelReleaseRootV1, CellReleaseClosureV1,
    CellVersionLoaderPinV3, CellVersionManifestV1, CellVersionRetentionConfigV3,
    CellVersionRetentionContractV3, CellVersionRetentionStoreV3,
};

fn version_config() -> CellVersionRetentionConfigV3 {
    CellVersionRetentionConfigV3 {
        retention: CellRetentionConfigV1 {
            store_id: [91; 32],
            capacity_bytes: 65_536,
            maximum_obligations: 32,
        },
        maximum_versions: 8,
        maximum_metadata_bytes: 64 << 20,
    }
}

fn version_material(directory: &Path) -> (CellStoreV1, CellVersionRetentionContractV3) {
    let cache = CellStoreV1::open(&directory.join("version-cache.sqlite"), cache_config()).unwrap();
    let context = |runtime| CellContextV1 {
        family: "native-funded-version-v3".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime,
    };
    let make = |name: &str, index: u8, ctx: CellContextV1| {
        let path = directory.join(name);
        fs::write(&path, vec![17 + index; 200 + 17 * usize::from(index)]).unwrap();
        cache.pack_file(&path, ctx, 16_384).unwrap()
    };
    let file = |manifest: &trnm_data_availability::cell::CellManifestV1,
                name: &str,
                role,
                dependencies| CellClosureFileV1 {
        path: name.into(),
        role,
        manifest: manifest.id(),
        payload_sha256: manifest.payload_sha256(),
        payload_bytes: manifest.size(),
        dependencies,
    };
    let env = make("runtime.bin", 0, context([5; 32]));
    let environment = CellReleaseClosureV1::new(
        env.context().clone(),
        1,
        [11; 32],
        vec![0],
        vec![file(
            &env,
            "runtime.bin",
            CellFileRoleV1::Configuration,
            vec![],
        )],
    )
    .unwrap();
    let base = make("base.bin", 1, context(environment.id()));
    let tokenizer = make("tokenizer.json", 2, context(environment.id()));
    let model = CellReleaseClosureV1::new(
        base.context().clone(),
        2,
        [12; 32],
        vec![0],
        vec![
            file(&base, "base.bin", CellFileRoleV1::Base, vec![1]),
            file(
                &tokenizer,
                "tokenizer.json",
                CellFileRoleV1::Tokenizer,
                vec![],
            ),
        ],
    )
    .unwrap();
    let pin = |closure: &CellReleaseClosureV1, role| CellVersionLoaderPinV3 {
        closure_id: closure.id(),
        context: closure.release().context().clone(),
        selected_generation: closure.selected_generation(),
        loader_profile: closure.loader_profile(),
        required_roles: vec![role],
        max_payload_bytes: 65_536,
        max_chunks: 16,
    };
    let model_pin = pin(&model, CellFileRoleV1::Base);
    let environment_pin = pin(&environment, CellFileRoleV1::Configuration);
    let mut objects = vec![env, base, tokenizer]
        .into_iter()
        .enumerate()
        .map(|(index, manifest)| CellRetentionContractV1 {
            operation: [31 + index as u8; 32],
            funding_operation: [41 + index as u8; 32],
            retain_from_height: 1,
            retain_until_height: 16,
            maximum_repair_bytes: manifest.size() * 3,
            manifest,
            successor: None,
        })
        .collect::<Vec<_>>();
    objects.sort_by_key(|object| object.manifest.id());
    let version = CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(model, vec![]).unwrap(),
        environment,
        objects
            .iter()
            .map(|object| object.manifest.clone())
            .collect(),
    )
    .unwrap();
    (
        cache,
        CellVersionRetentionContractV3 {
            operation: [71; 32],
            funding_operation: [72; 32],
            responsible_owner: public(1),
            failure_domain: [81; 32],
            replica_index: 0,
            required_replicas: 2,
            retain_from_height: 1,
            retain_until_height: 12,
            repair_deadline_height: 11,
            version,
            model: model_pin,
            environment: environment_pin,
            tensor_model: None,
            snapshot: None,
            objects,
        },
    )
}

fn funded_version(
    node: &mut Node,
    retention: &CellVersionRetentionStoreV3,
    contract: CellVersionRetentionContractV3,
) -> NativeCellVersionRetentionRequestV3 {
    let mut members = Vec::new();
    for (index, object) in contract.objects.iter().enumerate() {
        let resources = NativeBudgetResourcesV1::Storage {
            retained_bytes: object.manifest.size(),
            retained_byte_blocks: object.manifest.size()
                * (object.retain_until_height - object.retain_from_height),
        };
        let budget = [51 + index as u8; 32];
        members.push(NativeCellRetentionRequestV1 {
            policy: NativeBudgetPolicyV1 {
                budget,
                source: fund(node, 200),
                monetary_cap: 200,
                deadline: 40,
                resource_cap: resources.clone(),
                max_inflight: 1,
            },
            claim: NativeBudgetClaimV1 {
                claim: object.funding_operation,
                budget,
                subject: object.commitment(retention.store_id()),
                beneficiary: public(1),
                monetary_reservation: 200,
                resource_reservation: resources,
            },
            contract: object.clone(),
        });
    }
    let bytes: u64 = contract
        .objects
        .iter()
        .map(|object| object.manifest.size())
        .sum();
    let resources = NativeBudgetResourcesV1::Storage {
        retained_bytes: bytes,
        retained_byte_blocks: bytes * (contract.retain_until_height - contract.retain_from_height),
    };
    NativeCellVersionRetentionRequestV3 {
        policy: NativeBudgetPolicyV1 {
            budget: [73; 32],
            source: fund(node, 400),
            monetary_cap: 400,
            deadline: 40,
            resource_cap: resources.clone(),
            max_inflight: 1,
        },
        claim: NativeBudgetClaimV1 {
            claim: contract.funding_operation,
            budget: [73; 32],
            subject: retention.contract_commitment(&contract).unwrap(),
            beneficiary: public(1),
            monetary_reservation: 400,
            resource_reservation: resources,
        },
        expected_catalog: retention.anchor(deadline()).unwrap(),
        contract,
        members,
    }
}

fn physical_rows(path: &Path) -> Vec<(Vec<u8>, u8, u64, u64)> {
    let connection = rusqlite::Connection::open(path.join("objects/retention.sqlite")).unwrap();
    let mut statement = connection.prepare(
        "SELECT operation,status,initial_bytes,repair_bytes FROM obligations ORDER BY operation",
    ).unwrap();
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap()
}

fn root_count(path: &Path) -> u64 {
    rusqlite::Connection::open(path.join("versions.sqlite"))
        .unwrap()
        .query_row("SELECT count(*) FROM version_duties", [], |row| row.get(0))
        .unwrap()
}

fn advance_to(node: &mut Node, height: u64) {
    while node.record(node.active().unwrap().0).unwrap().height < height {
        let parent = node.active().unwrap().0;
        mine(node, parent, vec![]);
    }
}

#[test]
fn native_version_member_gc_requires_successor_native_effect() {
    for backend in [
        StateBackend::AuthenticatedV1,
        StateBackend::PermanentAccountGrowthV2,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut node = open_node(&directory.path().join("node"), backend);
        let path = directory.path().join("archive");
        let next_path = directory.path().join("successor-archive");
        let mut retained = CellVersionRetentionStoreV3::create(&path, version_config()).unwrap();
        let mut next_config = version_config();
        next_config.retention.store_id = [191; 32];
        let mut next = CellVersionRetentionStoreV3::create(&next_path, next_config).unwrap();
        let (cache, mut original) = version_material(directory.path());
        let mut next_contract = original.clone();
        next_contract.operation = [171; 32];
        next_contract.funding_operation = [172; 32];
        next_contract.retain_until_height = 24;
        next_contract.repair_deadline_height = 23;
        for (index, (old, new)) in original
            .objects
            .iter_mut()
            .zip(&mut next_contract.objects)
            .enumerate()
        {
            new.operation = [131 + index as u8; 32];
            new.funding_operation = [141 + index as u8; 32];
            new.retain_until_height = 30;
            old.successor = Some((next.store_id(), new.operation));
        }
        let original_request = funded_version(&mut node, &retained, original.clone());
        let mut next_request = funded_version(&mut node, &next, next_contract.clone());
        next_request.policy.budget = [173; 32];
        next_request.claim.budget = next_request.policy.budget;
        for (index, member) in next_request.members.iter_mut().enumerate() {
            member.policy.budget = [151 + index as u8; 32];
            member.claim.budget = member.policy.budget;
        }
        let mut budgets =
            NativeBudgetStoreV1::open(&directory.path().join("budgets.sqlite"), config(&node))
                .unwrap();
        node.retain_native_cell_version(
            &mut budgets,
            &mut retained,
            &cache,
            original_request,
            deadline(),
        )
        .unwrap();
        next.reserve_version(
            next_contract.clone(),
            next_request.expected_catalog,
            deadline(),
        )
        .unwrap();
        next.acknowledge_version(next_contract.operation, &cache, deadline())
            .unwrap();
        while node
            .native_funding_observation(next_request.policy.source)
            .unwrap()
            .anchor
            .height
            < 16
        {
            let parent = node.active().unwrap().0;
            mine(&mut node, parent, vec![]);
        }
        node.retire_native_cell_version(&budgets, &mut retained, original.operation, deadline())
            .unwrap();
        let object = original.objects[0].operation;
        let rows = physical_rows(&path);
        let charged = budgets.report().unwrap();
        let error = node
            .retire_native_cell_version_member(
                &budgets,
                &mut retained,
                original.operation,
                object,
                Some(&mut next),
                deadline(),
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("BUDGET_CLAIM_UNKNOWN"),
            "{error}"
        );
        assert_eq!(physical_rows(&path), rows);
        assert_eq!(budgets.report().unwrap(), charged);
        next_request.expected_catalog = next.anchor(deadline()).unwrap();
        node.retain_native_cell_version(&mut budgets, &mut next, &cache, next_request, deadline())
            .unwrap();
        let charged = budgets.report().unwrap();
        let retired = node
            .retire_native_cell_version_member(
                &budgets,
                &mut retained,
                original.operation,
                object,
                Some(&mut next),
                deadline(),
            )
            .unwrap();
        assert!(retired.retired);
        let replay = node
            .retire_native_cell_version_member(
                &budgets,
                &mut retained,
                original.operation,
                object,
                None,
                deadline(),
            )
            .unwrap();
        assert_eq!(replay, retired);
        assert_eq!(budgets.report().unwrap(), charged);
    }
}
