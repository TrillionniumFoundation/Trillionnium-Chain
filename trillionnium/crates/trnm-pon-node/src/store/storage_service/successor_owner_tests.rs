//! A local successor ACK cannot replace the original native effect owner.
//! These controls establish neither live coin locking nor independent custody.
use super::*;

#[test]
fn native_cell_successor_requires_completed_journal_effect_and_gc_replay_survives_reuse() {
    for backend in [
        StateBackend::Legacy,
        StateBackend::AuthenticatedV1,
        StateBackend::PermanentAccountGrowthV2,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let node_path = directory.path().join("node");
        let mut node = open_node(&node_path, backend);
        let source = fund(&mut node, 1000);
        let next_source = fund(&mut node, 1000);
        let (cache, manifest, _) = material(directory.path());
        let conf = config(&node);
        let journal = directory.path().join("budgets.sqlite");
        let mut budgets = NativeBudgetStoreV1::open(&journal, conf.clone()).unwrap();
        let path = directory.path().join("retention");
        let next_path = directory.path().join("successor");
        let mut retained = CellRetentionStoreV1::create(&path, retention_config()).unwrap();
        let mut next_config = retention_config();
        next_config.store_id = [79; 32];
        let mut next = CellRetentionStoreV1::create(&next_path, next_config).unwrap();
        let mut next_request = request(next_source, &manifest);
        next_request.contract.operation = [80; 32];
        next_request.contract.funding_operation = [81; 32];
        next_request.policy.budget = [82; 32];
        next_request.claim.claim = next_request.contract.funding_operation;
        next_request.claim.budget = next_request.policy.budget;
        next_request.claim.subject = next_request.contract.commitment(next.store_id());
        let mut original = request(source, &manifest);
        original.contract.retain_until_height = 3;
        original.contract.successor = Some((next.store_id(), next_request.contract.operation));
        original.claim.subject = original.contract.commitment(retained.store_id());
        let initial = node
            .retain_native_cell(
                &mut budgets,
                &mut retained,
                &cache,
                original.clone(),
                deadline(),
            )
            .unwrap();
        // M09 has no monetary authority. Produce genuine successor bytes with
        // no successor M12 claim, then ask the higher-level native owner for GC.
        next.reserve(next_request.contract.clone()).unwrap();
        let successor_bytes = next
            .acknowledge(next_request.contract.operation, &cache, deadline())
            .unwrap();
        let parent = node.active().unwrap().0;
        mine(&mut node, parent, vec![]);
        let before = budgets.report().unwrap();
        let error = node
            .retire_native_cell(
                &budgets,
                &mut retained,
                original.contract.operation,
                Some(&mut next),
                deadline(),
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("BUDGET_CLAIM_UNKNOWN"),
            "{error}"
        );
        assert_eq!(budgets.report().unwrap(), before);
        assert_eq!(
            retained
                .verify(original.contract.operation, deadline())
                .unwrap(),
            initial.target
        );

        // A pending M12 intent still cannot grant reclamation, even when its
        // target completed before the native completion receipt was persisted.
        budgets
            .open_budget(&mut node, next_request.policy.clone())
            .unwrap();
        budgets
            .reserve(&mut node, next_request.claim.clone())
            .unwrap();
        budgets
            .begin_effect_in_window(
                &mut node,
                next_request.claim.claim,
                next_request.contract.operation,
                next_request.claim.subject,
                next_request.contract.retain_from_height,
                next_request.contract.retain_until_height,
            )
            .unwrap();
        let pending = budgets.report().unwrap();
        let error = node
            .retire_native_cell(
                &budgets,
                &mut retained,
                original.contract.operation,
                Some(&mut next),
                deadline(),
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("BUDGET_COMPLETED_EFFECT_BINDING"),
            "{error}"
        );
        assert_eq!(budgets.report().unwrap(), pending);
        assert_eq!(
            retained
                .verify(original.contract.operation, deadline())
                .unwrap(),
            initial.target
        );
        let completed = node
            .retain_native_cell(
                &mut budgets,
                &mut next,
                &cache,
                next_request.clone(),
                deadline(),
            )
            .unwrap();
        assert_eq!(completed.replay, NativeBudgetReplayV1::Pending);
        assert_eq!(completed.target, successor_bytes);
        let charged = budgets.report().unwrap();
        let retired = node
            .retire_native_cell(
                &budgets,
                &mut retained,
                original.contract.operation,
                Some(&mut next),
                deadline(),
            )
            .unwrap();
        assert!(retired.retired);
        assert_eq!(budgets.report().unwrap(), charged);

        // Rehydrate solely from the successor after the publisher disappears.
        drop(cache);
        fs::remove_file(directory.path().join("source.cell")).unwrap();
        fs::remove_file(directory.path().join("cache.sqlite")).unwrap();
        let recovered =
            CellStoreV1::open(&directory.path().join("recovered.sqlite"), cache_config()).unwrap();
        next.populate_cache(next_request.contract.operation, &recovered, deadline())
            .unwrap();
        let replacement_source = fund(&mut node, 1000);
        let mut replacement = request(replacement_source, &manifest);
        replacement.contract.operation = [86; 32];
        replacement.contract.funding_operation = [87; 32];
        replacement.policy.budget = [88; 32];
        replacement.claim.claim = replacement.contract.funding_operation;
        replacement.claim.budget = replacement.policy.budget;
        replacement.claim.subject = replacement.contract.commitment(retained.store_id());
        // One aligned payload fills the arena: this succeeds only after actual
        // reclamation, while the original operation record remains terminal.
        node.retain_native_cell(
            &mut budgets,
            &mut retained,
            &recovered,
            replacement,
            deadline(),
        )
        .unwrap();
        let charged = budgets.report().unwrap();
        drop(retained);
        drop(next);
        drop(budgets);
        drop(node);
        fs::remove_dir_all(&next_path).unwrap();
        let mut node = open_node(&node_path, backend);
        let budgets = NativeBudgetStoreV1::open(&journal, conf).unwrap();
        let mut retained = CellRetentionStoreV1::open(&path, retention_config()).unwrap();
        let replay = node
            .retire_native_cell(
                &budgets,
                &mut retained,
                original.contract.operation,
                None,
                deadline(),
            )
            .unwrap();
        assert_eq!(replay, retired);
        assert_eq!(budgets.report().unwrap(), charged);
    }
}
