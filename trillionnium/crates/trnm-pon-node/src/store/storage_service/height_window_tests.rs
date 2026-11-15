use super::*;

#[test]
fn native_cell_storage_height_window_refuses_before_reservation_and_recovers_original_effect() {
    for backend in [
        StateBackend::Legacy,
        StateBackend::AuthenticatedV1,
        StateBackend::PermanentAccountGrowthV2,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut node = open_node(&dir.path().join("node"), backend);
        let source = fund(&mut node, 1000);
        let (cache, manifest, _) = material(dir.path());
        let mut request = request(source, &manifest);
        let mut budgets =
            NativeBudgetStoreV1::open(&dir.path().join("budgets.sqlite"), config(&node)).unwrap();
        let path = dir.path().join("retention");
        let mut retained = CellRetentionStoreV1::create(&path, retention_config()).unwrap();
        let before = budgets.report().unwrap();
        let arena = fs::read(path.join("payload.arena")).unwrap();
        // Real task funding is current at height 1. Neither an expired nor a
        // future service window may strand a new local budget or arena hold.
        for (from, until) in [(0, 1), (2, 3)] {
            request.contract.retain_from_height = from;
            request.contract.retain_until_height = until;
            request.claim.subject = request.contract.commitment(retained.store_id());
            let error = node
                .retain_native_cell(
                    &mut budgets,
                    &mut retained,
                    &cache,
                    request.clone(),
                    deadline(),
                )
                .unwrap_err();
            assert!(
                error.to_string().contains("BUDGET_NATIVE_EFFECT_WINDOW"),
                "{error}"
            );
            assert_eq!(budgets.report().unwrap(), before);
            assert!(retained.contract(request.contract.operation).is_err());
            assert_eq!(fs::read(path.join("payload.arena")).unwrap(), arena);
        }

        let parent = node.active().unwrap().0;
        mine(&mut node, parent, vec![]);
        let first = node
            .retain_native_cell(
                &mut budgets,
                &mut retained,
                &cache,
                request.clone(),
                deadline(),
            )
            .unwrap();
        assert_eq!(first.replay, NativeBudgetReplayV1::New);
        assert_eq!(first.target.initial_copy_bytes_committed, manifest.size());
        let charged = budgets.report().unwrap();
        let parent = node.active().unwrap().0;
        mine(&mut node, parent, vec![]);
        // Crossing the end height only excludes new dispatch. Recovery must
        // retain the original funding, effect identity and charged resources.
        let recovered = node
            .retain_native_cell(&mut budgets, &mut retained, &cache, request, deadline())
            .unwrap();
        assert_eq!(recovered.replay, NativeBudgetReplayV1::Done);
        assert_eq!(recovered.target, first.target);
        assert_eq!(recovered.target_receipt, first.target_receipt);
        assert_eq!(budgets.report().unwrap(), charged);
    }
}

fn repair_request(
    source: NativeFundingSourceV1,
    retained: &CellRetentionStoreV1,
    contract: &CellRetentionContractV1,
    identities: [u8; 3],
) -> NativeCellRepairRequestV1 {
    let [budget, claim, operation] = identities.map(|byte| [byte; 32]);
    let resources = NativeBudgetResourcesV1::Repair {
        cpu_ns: 1_000_000_000,
        download_bytes: contract.manifest.size(),
        upload_bytes: 0,
        attempts: 1,
    };
    NativeCellRepairRequestV1 {
        policy: NativeBudgetPolicyV1 {
            budget,
            source,
            monetary_cap: 200,
            deadline: 40,
            resource_cap: resources.clone(),
            max_inflight: 1,
        },
        claim: NativeBudgetClaimV1 {
            claim,
            budget,
            subject: native_cell_repair_subject_v1(retained, contract, operation, claim),
            beneficiary: public(1),
            monetary_reservation: 200,
            resource_reservation: resources,
        },
        obligation: contract.operation,
        repair_operation: operation,
    }
}

#[test]
fn native_cell_repair_height_window_preserves_recovery_without_reserving_new_work() {
    for backend in [
        StateBackend::Legacy,
        StateBackend::AuthenticatedV1,
        StateBackend::PermanentAccountGrowthV2,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut node = open_node(&dir.path().join("node"), backend);
        let storage_source = fund(&mut node, 1000);
        let repair_source = fund(&mut node, 200);
        let later_source = fund(&mut node, 200);
        let (cache, manifest, _) = material(dir.path());
        let mut storage = request(storage_source, &manifest);
        storage.contract.retain_until_height = 4;
        storage.claim.subject = storage.contract.commitment(retention_config().store_id);
        let mut budgets =
            NativeBudgetStoreV1::open(&dir.path().join("budgets.sqlite"), config(&node)).unwrap();
        let path = dir.path().join("retention");
        let mut retained = CellRetentionStoreV1::create(&path, retention_config()).unwrap();
        node.retain_native_cell(
            &mut budgets,
            &mut retained,
            &cache,
            storage.clone(),
            deadline(),
        )
        .unwrap();
        let repair = repair_request(repair_source, &retained, &storage.contract, [81, 82, 83]);
        let later = repair_request(later_source, &retained, &storage.contract, [84, 85, 86]);
        damage(&path);
        let repaired = node
            .repair_native_cell(
                &mut budgets,
                &mut retained,
                &cache,
                repair.clone(),
                deadline(),
            )
            .unwrap();
        assert_eq!(repaired.replay, NativeBudgetReplayV1::New);
        assert_eq!(repaired.target.repair_bytes_committed, manifest.size());
        let charged = budgets.report().unwrap();
        let arena = fs::read(path.join("payload.arena")).unwrap();
        let parent = node.active().unwrap().0;
        mine(&mut node, parent, vec![]);
        let recovered = node
            .repair_native_cell(&mut budgets, &mut retained, &cache, repair, deadline())
            .unwrap();
        assert_eq!(recovered.replay, NativeBudgetReplayV1::Done);
        assert_eq!(recovered.target, repaired.target);
        assert_eq!(recovered.target_receipt, repaired.target_receipt);
        assert!(!recovered.repair_cpu_observation.unwrap().original_attempt);
        assert_eq!(budgets.report().unwrap(), charged);

        // The second task still has genuine native funding, but the original
        // storage window has ended. Its failed admission cannot consume a new
        // budget or repair attempt, nor refund/change the earlier work.
        let error = node
            .repair_native_cell(&mut budgets, &mut retained, &cache, later, deadline())
            .unwrap_err();
        assert!(
            error.to_string().contains("BUDGET_NATIVE_EFFECT_WINDOW"),
            "{error}"
        );
        assert_eq!(budgets.report().unwrap(), charged);
        assert_eq!(
            retained
                .verify(storage.contract.operation, deadline())
                .unwrap(),
            repaired.target
        );
        assert_eq!(fs::read(path.join("payload.arena")).unwrap(), arena);
    }
}
