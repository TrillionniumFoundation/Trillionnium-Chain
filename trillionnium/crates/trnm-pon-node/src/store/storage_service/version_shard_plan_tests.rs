//! Child of the complete-version native tests: one actual owner chain across
//! TCA3, immutable CRP1, distinct native tasks and six local provider arenas.

use super::*;
use trnm_data_availability::cell::{
    CellRetainedShardPlanFileV1, CellRetainedShardPlanRequestV1, CellRs46ShardPlacementV1,
    CellRs46ShardProviderConfigV1, CellRs46ShardProviderV1,
};

fn fund_provider(
    node: &mut Node,
    provider: Hash,
    amount: u64,
    until: u64,
) -> NativeFundingSourceV1 {
    let nonce = node.next_nonce(public(0)).unwrap();
    let network = node.settings.network();
    let task = hash(
        b"task-instance-v3",
        &[
            &network,
            &node.settings.parameters(),
            &public(0),
            &nonce.to_le_bytes(),
            &provider,
            &amount.to_le_bytes(),
            &until.to_le_bytes(),
        ],
    );
    let mut payload = task.to_vec();
    payload.extend(provider);
    payload.extend(amount.to_le_bytes());
    payload.extend(until.to_le_bytes());
    let mut transaction = Envelope {
        network,
        sender: public(0),
        nonce,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag: 2,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    transaction.signature = hex::decode(sign_hex(&key, &transaction.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    let parent = node.active().unwrap().0;
    mine(node, parent, vec![transaction.encode().unwrap()]);
    let source = NativeFundingSourceV1::Task(task);
    let row = node
        .native_funding_observation(source)
        .unwrap()
        .row
        .unwrap();
    assert_eq!(row["deadline"].as_u64(), Some(until));
    assert_eq!(row["remaining"].as_u64(), Some(amount));
    assert_eq!(
        row["provider"].as_str(),
        Some(hex::encode(provider).as_str())
    );
    source
}

fn provider_configs() -> [CellRs46ShardProviderConfigV1; 6] {
    std::array::from_fn(|slot| CellRs46ShardProviderConfigV1 {
        placement: CellRs46ShardPlacementV1 {
            provider_id: [101 + slot as u8; 32],
            responsible_owner: public(slot as u64 + 1),
            administrator: [121 + slot as u8; 32],
            failure_domain: [131 + slot as u8; 32],
            domain_evidence: [141 + slot as u8; 32],
            repair_owner: public(slot as u64 + 1),
        },
        owner_generation: 7,
        capacity_bytes: 64 * 4096,
        maximum_obligations: 64,
    })
}

fn physical_debits(path: &Path) -> Vec<(Vec<u8>, u8, u64, u64)> {
    let connection = rusqlite::Connection::open(path.join("retention.sqlite")).unwrap();
    let mut query = connection.prepare("SELECT operation,status,initial_bytes,repair_bytes FROM obligations ORDER BY operation").unwrap();
    query
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap()
}

#[test]
fn native_complete_version_to_complete_local_shard_plan_reopens_without_sources_or_new_debits() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = open_node(
        &dir.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let (source, mut contract) = version_material(dir.path());
    contract.retain_until_height = 40;
    contract.repair_deadline_height = 35;
    for object in &mut contract.objects {
        object.retain_until_height = 40;
    }
    let catalog_path = dir.path().join("catalog");
    let mut catalog = CellVersionRetentionStoreV3::create(&catalog_path, version_config()).unwrap();
    let native_root = funded_version(&mut node, &catalog, contract.clone());
    let journal = dir.path().join("budgets.sqlite");
    let mut budgets = NativeBudgetStoreV1::open(&journal, config(&node)).unwrap();
    node.retain_native_cell_version(
        &mut budgets,
        &mut catalog,
        &source,
        native_root.clone(),
        deadline(),
    )
    .unwrap();
    let plan_path = dir.path().join("complete.crp1");
    let request = CellRetainedShardPlanRequestV1 {
        operation: [189; 32],
        expected_catalog: catalog.anchor(deadline()).unwrap(),
        current_height: node
            .native_funding_observation(native_root.policy.source)
            .unwrap()
            .anchor
            .height,
        required_until_height: 35,
        providers: provider_configs(),
        maximum_repairs_per_slot: 2,
        funding_operations: (0..3)
            .map(|chunk| std::array::from_fn(|slot| [191 + chunk as u8 * 6 + slot as u8; 32]))
            .collect(),
    };
    let file =
        CellRetainedShardPlanFileV1::create(&plan_path, &mut catalog, &source, request, deadline())
            .unwrap();
    assert_eq!(file.plan().roots().len(), 1);
    assert_eq!(file.plan().chunks().len(), 3);
    let mut providers: [CellRs46ShardProviderV1; 6] = provider_configs()
        .into_iter()
        .enumerate()
        .map(|(slot, config)| {
            CellRs46ShardProviderV1::create(&dir.path().join(format!("provider-{slot}")), config)
                .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    let mut requests = Vec::new();
    for (index, slot) in file
        .plan()
        .chunks()
        .iter()
        .flat_map(|chunk| chunk.slots())
        .enumerate()
    {
        let bytes = slot.manifest().size();
        let owner = slot.owner();
        let resources = NativeBudgetResourcesV1::Storage {
            retained_bytes: bytes,
            retained_byte_blocks: bytes * (owner.retain_until_height - owner.retain_from_height),
        };
        let budget = [220 + index as u8; 32];
        let beneficiary = slot.placement().placements[usize::from(owner.slot)].responsible_owner;
        requests.push(NativeCellShardRetentionRequestV1 {
            policy: NativeBudgetPolicyV1 {
                budget,
                // M06 permits at most sixteen monetary expirations per height.
                // Keep all original policy/retention deadlines, and spread the
                // real provider funding expirations over earlier heights 41..46
                // (three per height), leaving the four original TCA3 jobs at 50.
                source: fund_provider(&mut node, beneficiary, 100, 41 + u64::from(owner.slot)),
                monetary_cap: 100,
                deadline: 40,
                resource_cap: resources.clone(),
                max_inflight: 1,
            },
            claim: NativeBudgetClaimV1 {
                claim: owner.funding_operation,
                budget,
                subject: slot.retention_contract().commitment(owner.provider_store),
                beneficiary,
                monetary_reservation: 100,
                resource_reservation: resources,
            },
            contract: slot.clone(),
        });
    }
    let mut due = std::collections::BTreeMap::new();
    for source in native_root
        .members
        .iter()
        .map(|entry| entry.policy.source)
        .chain(std::iter::once(native_root.policy.source))
        .chain(requests.iter().map(|entry| entry.policy.source))
    {
        let row = node
            .native_funding_observation(source)
            .unwrap()
            .row
            .unwrap();
        *due.entry(row["deadline"].as_u64().unwrap())
            .or_insert(0_u64) += 1;
    }
    assert_eq!(
        due,
        std::collections::BTreeMap::from([
            (41, 3),
            (42, 3),
            (43, 3),
            (44, 3),
            (45, 3),
            (46, 3),
            (50, 4),
        ])
    );
    let input_bytes: u64 = requests
        .iter()
        .map(|entry| entry.contract.manifest().size())
        .sum();
    let reconstruction_bytes = input_bytes
        + file
            .plan()
            .chunks()
            .iter()
            .map(|chunk| u64::from(chunk.binding().source_bytes()))
            .sum::<u64>();
    let mut verification = NativeCellRetainedShardVerificationBudgetV1::new(
        Instant::now() + Duration::from_secs(30),
        6,
        2 * input_bytes,
        2 * reconstruction_bytes,
    );
    let before = budgets.report().unwrap();
    let mut omitted = requests.clone();
    omitted.pop();
    let mut aliased = requests.clone();
    aliased[17].policy.source = aliased[0].policy.source;
    let mut unfunded = requests.clone();
    unfunded[17].policy.source = NativeFundingSourceV1::Task([9; 32]);
    let mut wrong_owner = requests.clone();
    wrong_owner[17].claim.beneficiary = public(0);
    for refused in [omitted, aliased, unfunded, wrong_owner] {
        assert!(node
            .retain_native_cell_shard_plan(
                &mut budgets,
                NativeCellRetainedShardPlanTargetsV1 {
                    catalog: &catalog,
                    plan_file: &file,
                    providers: &mut providers,
                    cache: &source
                },
                NativeCellRetainedShardPlanRequestV1 { slots: refused },
                &mut verification
            )
            .is_err());
        assert_eq!(budgets.report().unwrap(), before);
        for slot in 0..6 {
            assert!(physical_debits(&dir.path().join(format!("provider-{slot}"))).is_empty());
        }
        assert_eq!(verification.usage().attempts_committed, 0);
    }
    let request = NativeCellRetainedShardPlanRequestV1 { slots: requests };
    let first = node
        .retain_native_cell_shard_plan(
            &mut budgets,
            NativeCellRetainedShardPlanTargetsV1 {
                catalog: &catalog,
                plan_file: &file,
                providers: &mut providers,
                cache: &source,
            },
            request.clone(),
            &mut verification,
        )
        .unwrap();
    assert_eq!(first.slots.len(), 18);
    assert!(first
        .slots
        .iter()
        .all(|slot| slot.native.replay == NativeBudgetReplayV1::New));
    assert_eq!(first.verification_usage.attempts_committed, 3);
    let physical: Vec<_> = (0..6)
        .map(|slot| physical_debits(&dir.path().join(format!("provider-{slot}"))))
        .collect();
    assert!(physical.iter().all(
        |rows| rows.len() == 3 && rows.iter().all(|row| row.1 == 1 && row.2 > 0 && row.3 == 0)
    ));
    let charged = budgets.report().unwrap();
    assert_eq!(charged["budgets"].as_array().unwrap().len(), 22);
    let anchor = catalog.anchor(deadline()).unwrap();
    let pin = file.commitment();
    drop(source);
    drop(catalog);
    drop(providers);
    drop(file);
    drop(budgets);
    for name in [
        "runtime.bin",
        "base.bin",
        "tokenizer.json",
        "version-cache.sqlite",
    ] {
        fs::remove_file(dir.path().join(name)).unwrap();
    }
    let mut catalog =
        CellVersionRetentionStoreV3::open(&catalog_path, version_config(), anchor).unwrap();
    let file = CellRetainedShardPlanFileV1::open(&plan_path, pin, deadline()).unwrap();
    let mut providers: [CellRs46ShardProviderV1; 6] = provider_configs()
        .into_iter()
        .enumerate()
        .map(|(slot, config)| {
            CellRs46ShardProviderV1::open(&dir.path().join(format!("provider-{slot}")), config)
                .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    let mut budgets = NativeBudgetStoreV1::open(&journal, config(&node)).unwrap();
    let empty = CellStoreV1::open(&dir.path().join("empty.sqlite"), cache_config()).unwrap();
    let repeat = node
        .retain_native_cell_shard_plan(
            &mut budgets,
            NativeCellRetainedShardPlanTargetsV1 {
                catalog: &catalog,
                plan_file: &file,
                providers: &mut providers,
                cache: &empty,
            },
            request.clone(),
            &mut verification,
        )
        .unwrap();
    assert_eq!(repeat.plan, first.plan);
    assert_eq!(repeat.slots.len(), 18);
    assert!(repeat
        .slots
        .iter()
        .all(|slot| slot.native.replay == NativeBudgetReplayV1::Done));
    assert_eq!(repeat.verification_usage.attempts_committed, 6);
    assert_eq!(budgets.report().unwrap(), charged);
    for (slot, expected) in physical.iter().enumerate() {
        assert_eq!(
            &physical_debits(&dir.path().join(format!("provider-{slot}"))),
            expected
        );
    }
    // The same explicit verification allowance cannot be silently refreshed.
    let error = node
        .retain_native_cell_shard_plan(
            &mut budgets,
            NativeCellRetainedShardPlanTargetsV1 {
                catalog: &catalog,
                plan_file: &file,
                providers: &mut providers,
                cache: &empty,
            },
            request.clone(),
            &mut verification,
        )
        .unwrap_err();
    assert!(error.to_string().contains("VERIFICATION_RESERVATION"));
    assert_eq!(budgets.report().unwrap(), charged);
    // The first five original targets remain healthy; the sixth first chunk
    // fails during actual readback, before any codec call for that chunk. The
    // whole admitted plan still consumes its explicit original allowance.
    damage(&dir.path().join("provider-5"));
    let mut failed_observation = NativeCellRetainedShardVerificationBudgetV1::new(
        Instant::now() + Duration::from_secs(30),
        3,
        input_bytes,
        reconstruction_bytes,
    );
    let error = node
        .retain_native_cell_shard_plan(
            &mut budgets,
            NativeCellRetainedShardPlanTargetsV1 {
                catalog: &catalog,
                plan_file: &file,
                providers: &mut providers,
                cache: &empty,
            },
            request.clone(),
            &mut failed_observation,
        )
        .unwrap_err();
    assert!(error.to_string().contains("chunk digest"));
    assert_eq!(failed_observation.usage().attempts_committed, 3);
    assert_eq!(
        failed_observation.usage().input_bytes_committed,
        input_bytes
    );
    assert_eq!(failed_observation.codec_usage().attempts_committed, 0);
    let error = node
        .retain_native_cell_shard_plan(
            &mut budgets,
            NativeCellRetainedShardPlanTargetsV1 {
                catalog: &catalog,
                plan_file: &file,
                providers: &mut providers,
                cache: &empty,
            },
            request.clone(),
            &mut failed_observation,
        )
        .unwrap_err();
    assert!(error.to_string().contains("VERIFICATION_RESERVATION"));
    assert_eq!(budgets.report().unwrap(), charged);
    for (slot, expected) in physical.iter().enumerate() {
        assert_eq!(
            &physical_debits(&dir.path().join(format!("provider-{slot}"))),
            expected
        );
    }
    // A newly protected root invalidates this complete-set assertion even if it
    // references the same version and all old target bytes still exist.
    contract.operation = [175; 32];
    contract.funding_operation = [176; 32];
    catalog
        .reserve_version(contract, catalog.anchor(deadline()).unwrap(), deadline())
        .unwrap();
    let mut next_observation = NativeCellRetainedShardVerificationBudgetV1::new(
        deadline(),
        3,
        input_bytes,
        reconstruction_bytes,
    );
    let error = node
        .retain_native_cell_shard_plan(
            &mut budgets,
            NativeCellRetainedShardPlanTargetsV1 {
                catalog: &catalog,
                plan_file: &file,
                providers: &mut providers,
                cache: &empty,
            },
            request,
            &mut next_observation,
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("retained shard plan")
            || error.to_string().contains("complete service")
    );
    assert_eq!(next_observation.usage().attempts_committed, 0);
    assert_eq!(budgets.report().unwrap(), charged);
}

#[path = "version_shard_recovery_tests.rs"]
mod recovery;
