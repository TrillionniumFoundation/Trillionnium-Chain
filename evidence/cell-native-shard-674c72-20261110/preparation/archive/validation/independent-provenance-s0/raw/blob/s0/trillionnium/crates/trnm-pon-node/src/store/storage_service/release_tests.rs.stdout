//! Actual native task transactions, M12 history and complete TCA2 targets.
//! These finite local controls do not establish paid custody or WAN replicas.

use super::*;
use trnm_data_availability::cell::{
    CellClosureFileV1, CellFileRoleV1, CellModelReleaseRootV1, CellReleaseClosureV1,
    CellReleaseRetentionConfigV2, CellReleaseRetentionContractV2, CellReleaseRetentionStoreV2,
};

fn archive_config() -> CellReleaseRetentionConfigV2 {
    CellReleaseRetentionConfigV2 {
        retention: CellRetentionConfigV1 {
            store_id: [91; 32],
            capacity_bytes: 65_536,
            maximum_obligations: 32,
        },
        maximum_releases: 8,
    }
}

fn release_material(directory: &Path) -> (CellStoreV1, CellReleaseRetentionContractV2) {
    let cache = CellStoreV1::open(&directory.join("release-cache.sqlite"), cache_config()).unwrap();
    let context = CellContextV1 {
        family: "native-funded-release-v2".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    };
    let mut files = Vec::new();
    let mut objects = Vec::new();
    for (index, (name, role)) in [
        ("base.bin", CellFileRoleV1::Base),
        ("router.bin", CellFileRoleV1::Router),
        ("tokenizer.json", CellFileRoleV1::Tokenizer),
    ]
    .into_iter()
    .enumerate()
    {
        let path = directory.join(name);
        fs::write(&path, vec![17 + index as u8; 200 + 17 * index]).unwrap();
        let manifest = cache.pack_file(&path, context.clone(), 16_384).unwrap();
        files.push(CellClosureFileV1 {
            path: name.into(),
            role,
            manifest: manifest.id(),
            payload_sha256: manifest.payload_sha256(),
            payload_bytes: manifest.size(),
            dependencies: if index == 1 { vec![0, 2] } else { vec![] },
        });
        objects.push(CellRetentionContractV1 {
            operation: [31 + index as u8; 32],
            funding_operation: [41 + index as u8; 32],
            retain_from_height: 1,
            retain_until_height: 16,
            maximum_repair_bytes: manifest.size() * 3,
            manifest,
            successor: None,
        });
    }
    objects.sort_by_key(|object| object.manifest.id());
    let closure = CellReleaseClosureV1::new(context, 1, [11; 32], vec![1], files).unwrap();
    let contract = CellReleaseRetentionContractV2 {
        operation: [71; 32],
        funding_operation: [72; 32],
        responsible_owner: public(1),
        failure_domain: [81; 32],
        replica_index: 0,
        required_replicas: 2,
        retain_from_height: 1,
        retain_until_height: 12,
        repair_deadline_height: 11,
        root: CellModelReleaseRootV1::new(closure, vec![]).unwrap(),
        tensor_model: None,
        objects,
    };
    (cache, contract)
}

fn funded_release(
    node: &mut Node,
    retention: &CellReleaseRetentionStoreV2,
    contract: CellReleaseRetentionContractV2,
) -> NativeCellReleaseRetentionRequestV2 {
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
    NativeCellReleaseRetentionRequestV2 {
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
    rusqlite::Connection::open(path.join("archive.sqlite"))
        .unwrap()
        .query_row("SELECT count(*) FROM release_duties", [], |row| row.get(0))
        .unwrap()
}

fn advance_to(node: &mut Node, height: u64) {
    while node.record(node.active().unwrap().0).unwrap().height < height {
        let parent = node.active().unwrap().0;
        mine(node, parent, vec![]);
    }
}

#[test]
fn native_release_complete_tasks_reopen_and_shared_members_keep_original_effects() {
    for backend in [
        StateBackend::AuthenticatedV1,
        StateBackend::PermanentAccountGrowthV2,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut node = open_node(&directory.path().join("node"), backend);
        let (cache, contract) = release_material(directory.path());
        let path = directory.path().join("archive");
        let mut archive = CellReleaseRetentionStoreV2::create(&path, archive_config()).unwrap();
        let request = funded_release(&mut node, &archive, contract);
        let journal = directory.path().join("budgets.sqlite");
        let mut budgets = NativeBudgetStoreV1::open(&journal, config(&node)).unwrap();
        let first = node
            .retain_native_cell_release(
                &mut budgets,
                &mut archive,
                &cache,
                request.clone(),
                deadline(),
            )
            .unwrap();
        assert_eq!(first.replay, NativeBudgetReplayV1::New);
        assert!(first.target.acknowledged);
        assert!(first
            .members
            .iter()
            .all(|member| member.replay == NativeBudgetReplayV1::New));
        let physical = physical_rows(&path);
        assert_eq!(physical.len(), 3);
        assert_eq!(physical.iter().map(|row| row.2).sum::<u64>(), 651);
        let charged = budgets.report().unwrap();
        assert_eq!(charged["budgets"].as_array().unwrap().len(), 4);
        // Two separately admitted levels are not six payloads or any payment.
        assert_eq!(first.target.objects.len(), 3);
        drop(archive);
        drop(budgets);
        drop(cache);
        for name in ["base.bin", "router.bin", "tokenizer.json"] {
            fs::remove_file(directory.path().join(name)).unwrap();
        }
        let empty =
            CellStoreV1::open(&directory.path().join("empty.sqlite"), cache_config()).unwrap();
        let mut archive = CellReleaseRetentionStoreV2::open(&path, archive_config()).unwrap();
        let mut budgets = NativeBudgetStoreV1::open(&journal, config(&node)).unwrap();
        let repeat = node
            .retain_native_cell_release(
                &mut budgets,
                &mut archive,
                &empty,
                request.clone(),
                deadline(),
            )
            .unwrap();
        assert_eq!(repeat.replay, NativeBudgetReplayV1::Done);
        assert_eq!(repeat.target, first.target);
        assert_eq!(budgets.report().unwrap(), charged);
        assert_eq!(physical_rows(&path), physical);

        let mut next = request.clone();
        next.contract.operation = [74; 32];
        next.contract.funding_operation = [75; 32];
        next.contract.retain_until_height = 14;
        next.contract.repair_deadline_height = 13;
        let closure = request.contract.root.closure();
        next.contract.root = CellModelReleaseRootV1::new(
            CellReleaseClosureV1::new(
                closure.release().context().clone(),
                2,
                closure.loader_profile(),
                closure.roots().to_vec(),
                closure.files().to_vec(),
            )
            .unwrap(),
            vec![request.contract.root.id()],
        )
        .unwrap();
        next.policy.budget = [76; 32];
        next.policy.source = fund(&mut node, 400);
        next.policy.resource_cap = NativeBudgetResourcesV1::Storage {
            retained_bytes: 651,
            retained_byte_blocks: 651 * 13,
        };
        next.claim.claim = next.contract.funding_operation;
        next.claim.budget = next.policy.budget;
        next.claim.subject = archive.contract_commitment(&next.contract).unwrap();
        next.claim.resource_reservation = next.policy.resource_cap.clone();
        let shared = node
            .retain_native_cell_release(
                &mut budgets,
                &mut archive,
                &empty,
                next.clone(),
                deadline(),
            )
            .unwrap();
        assert_eq!(shared.replay, NativeBudgetReplayV1::New);
        assert!(shared
            .members
            .iter()
            .all(|member| member.replay == NativeBudgetReplayV1::Done));
        assert_eq!(physical_rows(&path), physical);
        assert_eq!(root_count(&path), 2);
        advance_to(&mut node, 16);
        node.retire_native_cell_release(
            &budgets,
            &mut archive,
            request.contract.operation,
            deadline(),
        )
        .unwrap();
        assert!(node
            .retire_native_cell_release_member(
                &budgets,
                &mut archive,
                request.contract.operation,
                request.contract.objects[0].operation,
                None,
                deadline(),
            )
            .is_err());
        assert_eq!(physical_rows(&path), physical);
        node.retire_native_cell_release(
            &budgets,
            &mut archive,
            next.contract.operation,
            deadline(),
        )
        .unwrap();
        assert!(
            node.retire_native_cell_release_member(
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
    }
}

#[test]
fn native_release_scope_alias_and_late_funding_errors_precede_every_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open_node(
        &directory.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let (cache, contract) = release_material(directory.path());
    let path = directory.path().join("archive");
    let mut archive = CellReleaseRetentionStoreV2::create(&path, archive_config()).unwrap();
    let request = funded_release(&mut node, &archive, contract);
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
            node.retain_native_cell_release(&mut budgets, &mut archive, &cache, wrong, deadline(),)
                .is_err(),
            "case {case}"
        );
        assert_eq!(budgets.report().unwrap(), before, "case {case}");
        assert_eq!(root_count(&path), 0, "case {case}");
        assert!(physical_rows(&path).is_empty(), "case {case}");
    }
    assert!(node
        .retain_native_cell_release(
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
fn native_release_outer_history_cannot_invent_missing_member_intents() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open_node(
        &directory.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let (cache, contract) = release_material(directory.path());
    let path = directory.path().join("archive");
    let mut archive = CellReleaseRetentionStoreV2::create(&path, archive_config()).unwrap();
    let request = funded_release(&mut node, &archive, contract);
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
                b"trnm.native-cell-release-initial-readback.v2\0",
                &[&request.claim.subject],
            );
            budgets
                .complete_effect(request.claim.claim, request.contract.operation, receipt)
                .unwrap();
        }
        let before = budgets.report().unwrap();
        let error = node
            .retain_native_cell_release(
                &mut budgets,
                &mut archive,
                &cache,
                request.clone(),
                deadline(),
            )
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("NATIVE_CELL_RELEASE_MEMBER_INTENT_MISSING"));
        assert_eq!(budgets.report().unwrap(), before);
        assert_eq!(root_count(&path), 0);
        assert!(physical_rows(&path).is_empty());
    }
}

fn repair_request(
    node: &mut Node,
    archive: &CellReleaseRetentionStoreV2,
    contract: &CellReleaseRetentionContractV2,
    object: &CellRetentionContractV1,
    seed: u8,
) -> NativeCellReleaseRepairRequestV2 {
    let resources = NativeBudgetResourcesV1::Repair {
        cpu_ns: 1_000_000_000,
        download_bytes: object.manifest.size(),
        upload_bytes: 0,
        attempts: 1,
    };
    let claim = [seed + 1; 32];
    let operation = [seed + 2; 32];
    NativeCellReleaseRepairRequestV2 {
        policy: NativeBudgetPolicyV1 {
            budget: [seed; 32],
            source: fund(node, 100),
            monetary_cap: 100,
            deadline: 40,
            resource_cap: resources.clone(),
            max_inflight: 1,
        },
        claim: NativeBudgetClaimV1 {
            claim,
            budget: [seed; 32],
            subject: native_cell_release_repair_subject_v2(
                archive,
                contract,
                object.operation,
                operation,
                claim,
            )
            .unwrap(),
            beneficiary: public(1),
            monetary_reservation: 100,
            resource_reservation: resources,
        },
        release_operation: contract.operation,
        object_operation: object.operation,
        repair_operation: operation,
    }
}

#[test]
#[cfg(target_os = "linux")]
fn native_release_interrupted_members_need_distinct_repairs_without_redispatch() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open_node(
        &directory.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let (cache, contract) = release_material(directory.path());
    let path = directory.path().join("archive");
    let mut archive = CellReleaseRetentionStoreV2::create(&path, archive_config()).unwrap();
    let request = funded_release(&mut node, &archive, contract);
    let mut budgets =
        NativeBudgetStoreV1::open(&directory.path().join("budgets.sqlite"), config(&node)).unwrap();
    let partial =
        CellStoreV1::open(&directory.path().join("partial.sqlite"), cache_config()).unwrap();
    let first = &request.contract.objects[0].manifest;
    for chunk in first.chunks() {
        partial
            .put_chunk(chunk, &cache.chunk(chunk.sha256).unwrap().unwrap())
            .unwrap();
    }
    assert!(node
        .retain_native_cell_release(
            &mut budgets,
            &mut archive,
            &partial,
            request.clone(),
            deadline(),
        )
        .is_err());
    let original = physical_rows(&path);
    let charged = budgets.report().unwrap();
    let payload = fs::read(path.join("objects/payload.arena")).unwrap();
    assert_eq!(root_count(&path), 1);
    assert!(original.iter().any(|row| row.1 == 1 && row.2 > 0));
    assert!(original.iter().any(|row| row.1 == 0 && row.2 > 0));
    assert!(original.iter().any(|row| row.1 == 0 && row.2 == 0));
    // The now-complete cache cannot convert any old pending effect into a new
    // copy, including the third member whose first copy was never reached.
    assert!(node
        .retain_native_cell_release(
            &mut budgets,
            &mut archive,
            &cache,
            request.clone(),
            deadline(),
        )
        .is_err());
    assert_eq!(budgets.report().unwrap(), charged);
    assert_eq!(physical_rows(&path), original);
    assert_eq!(
        fs::read(path.join("objects/payload.arena")).unwrap(),
        payload
    );
    assert!(node
        .retire_native_cell_release(
            &budgets,
            &mut archive,
            request.contract.operation,
            deadline(),
        )
        .is_err());
    for (index, object) in request.contract.objects.iter().enumerate().skip(1) {
        let repair = repair_request(
            &mut node,
            &archive,
            &request.contract,
            object,
            100 + 4 * index as u8,
        );
        let repaired = node
            .repair_native_cell_release_member(
                &mut budgets,
                &mut archive,
                &cache,
                repair,
                deadline(),
            )
            .unwrap();
        assert_eq!(repaired.replay, NativeBudgetReplayV1::New);
        assert_eq!(
            repaired.target.repair_bytes_committed,
            object.manifest.size()
        );
    }
    let recovered = node
        .retain_native_cell_release(
            &mut budgets,
            &mut archive,
            &partial,
            request.clone(),
            deadline(),
        )
        .unwrap();
    assert_eq!(recovered.replay, NativeBudgetReplayV1::Pending);
    assert!(recovered.target.acknowledged);
    assert_eq!(
        recovered.target.objects[0].initial_copy_bytes_committed,
        first.size()
    );
    assert_eq!(recovered.target.objects[2].initial_copy_bytes_committed, 0);
    let recovered_charge = budgets.report().unwrap();
    assert_eq!(
        node.retain_native_cell_release(&mut budgets, &mut archive, &partial, request, deadline(),)
            .unwrap()
            .replay,
        NativeBudgetReplayV1::Done
    );
    assert_eq!(budgets.report().unwrap(), recovered_charge);
}

#[test]
fn native_release_reorg_keeps_custody_but_cannot_grant_new_funding_or_foreign_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open_node(
        &directory.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let genesis = node.settings.genesis();
    let (cache, contract) = release_material(directory.path());
    let path = directory.path().join("archive");
    let mut archive = CellReleaseRetentionStoreV2::create(&path, archive_config()).unwrap();
    let request = funded_release(&mut node, &archive, contract);
    let mut budgets =
        NativeBudgetStoreV1::open(&directory.path().join("budgets.sqlite"), config(&node)).unwrap();
    let first = node
        .retain_native_cell_release(
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
        .retain_native_cell_release(
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
        .retain_native_cell_release(&mut budgets, &mut archive, &cache, fresh, deadline(),)
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
        .retire_native_cell_release(
            &budgets,
            &mut archive,
            request.contract.operation,
            deadline(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("BUDGET_NATIVE_CONTEXT"));
    assert_eq!(physical_rows(&path), original);
    advance_to(&mut node, 12);
    node.retire_native_cell_release(
        &budgets,
        &mut archive,
        request.contract.operation,
        deadline(),
    )
    .unwrap();
    assert!(node
        .retire_native_cell_release_member(
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
        node.retire_native_cell_release_member(
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
#[cfg(target_os = "linux")]
fn native_release_repair_scope_deadline_and_exact_old_reconciliation_remain_distinct() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open_node(
        &directory.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let (cache, mut contract) = release_material(directory.path());
    contract.repair_deadline_height = 6;
    let path = directory.path().join("archive");
    let mut archive = CellReleaseRetentionStoreV2::create(&path, archive_config()).unwrap();
    let request = funded_release(&mut node, &archive, contract);
    let mut budgets =
        NativeBudgetStoreV1::open(&directory.path().join("budgets.sqlite"), config(&node)).unwrap();
    node.retain_native_cell_release(
        &mut budgets,
        &mut archive,
        &cache,
        request.clone(),
        deadline(),
    )
    .unwrap();
    damage(&path.join("objects"));
    let object = &request.contract.objects[0];
    let repair = repair_request(&mut node, &archive, &request.contract, object, 100);
    let before = budgets.report().unwrap();
    for case in 0..4 {
        let mut wrong = repair.clone();
        match case {
            0 => wrong.claim.subject = [99; 32],
            1 => wrong.object_operation = request.contract.objects[1].operation,
            2 => wrong.claim.beneficiary = public(2),
            3 => wrong.policy.deadline = 6,
            _ => unreachable!(),
        }
        assert!(node
            .repair_native_cell_release_member(
                &mut budgets,
                &mut archive,
                &cache,
                wrong,
                deadline(),
            )
            .is_err());
        assert_eq!(budgets.report().unwrap(), before);
    }
    let repaired = node
        .repair_native_cell_release_member(
            &mut budgets,
            &mut archive,
            &cache,
            repair.clone(),
            deadline(),
        )
        .unwrap();
    assert_eq!(
        repaired.target.repair_bytes_committed,
        object.manifest.size()
    );
    let charged = budgets.report().unwrap();
    advance_to(&mut node, 7);
    let empty = CellStoreV1::open(&directory.path().join("empty.sqlite"), cache_config()).unwrap();
    let repeated = node
        .repair_native_cell_release_member(
            &mut budgets,
            &mut archive,
            &empty,
            repair.clone(),
            deadline(),
        )
        .unwrap();
    assert_eq!(repeated.replay, NativeBudgetReplayV1::Done);
    assert_eq!(repeated.target, repaired.target);
    assert_eq!(budgets.report().unwrap(), charged);
    let late = repair_request(&mut node, &archive, &request.contract, object, 104);
    assert!(node
        .repair_native_cell_release_member(&mut budgets, &mut archive, &cache, late, deadline(),)
        .is_err());
    assert_eq!(budgets.report().unwrap(), charged);
    damage(&path.join("objects"));
    let damaged = fs::read(path.join("objects/payload.arena")).unwrap();
    assert!(node
        .repair_native_cell_release_member(&mut budgets, &mut archive, &cache, repair, deadline(),)
        .is_err());
    assert_eq!(
        fs::read(path.join("objects/payload.arena")).unwrap(),
        damaged
    );
    assert_eq!(budgets.report().unwrap(), charged);
}
