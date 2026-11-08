use std::{
    fs::{self, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use tempfile::TempDir;

use super::*;
use crate::cell::{
    CellCacheConfigV4, CellChunkV1, CellClosureFileV1, CellContextV1, CellFileRoleV1,
    CellManifestV1, CellReleaseClosureV1, CellReleaseRetentionConfigV2, CellRetentionConfigV1,
    CellRetentionContractV1, CellStoreV1,
};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

fn configuration(slot: usize) -> CellReleaseRetentionConfigV2 {
    CellReleaseRetentionConfigV2 {
        retention: CellRetentionConfigV1 {
            store_id: [21 + slot as u8; 32],
            capacity_bytes: 32_768,
            maximum_obligations: 32,
        },
        maximum_releases: 16,
    }
}

struct Fixture {
    directory: TempDir,
    cache: Option<CellStoreV1>,
    stores: Vec<CellReleaseRetentionStoreV2>,
    contracts: Vec<CellReleaseRetentionContractV2>,
    policy: CellReleaseCustodyPolicyV1,
}

impl Fixture {
    fn new(acknowledge: bool) -> Self {
        Self::with_runtime(acknowledge, [5; 32])
    }

    fn with_runtime(acknowledge: bool, runtime: CellDigestV1) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let inputs = directory.path().join("inputs");
        fs::create_dir(&inputs).unwrap();
        let cache = CellStoreV1::open(
            &directory.path().join("source.sqlite"),
            CellCacheConfigV4 {
                max_database_bytes: 4 * 1024 * 1024,
                max_logical_bytes: 2 * 1024 * 1024,
                max_chunk_rows: 256,
                max_manifest_rows: 64,
            },
        )
        .unwrap();
        let context = CellContextV1 {
            family: "custody-observation-test-v1".into(),
            base: [1; 32],
            parent: [2; 32],
            tokenizer: [3; 32],
            layout: [4; 32],
            runtime,
        };
        let mut files = Vec::new();
        let mut manifests = Vec::new();
        for (index, (name, role)) in [
            ("base.bin", CellFileRoleV1::Base),
            ("router.bin", CellFileRoleV1::Router),
            ("tokenizer.json", CellFileRoleV1::Tokenizer),
        ]
        .into_iter()
        .enumerate()
        {
            let input = inputs.join(name);
            fs::write(&input, vec![17 + index as u8; 200 + index * 17]).unwrap();
            let manifest = cache.pack_file(&input, context.clone(), 16_384).unwrap();
            files.push(CellClosureFileV1 {
                path: name.into(),
                role,
                manifest: manifest.id(),
                payload_sha256: manifest.payload_sha256(),
                payload_bytes: manifest.size(),
                dependencies: if index == 1 { vec![0, 2] } else { vec![] },
            });
            manifests.push(manifest);
        }
        let closure = CellReleaseClosureV1::new(context, 1, [11; 32], vec![1], files).unwrap();
        let root = CellModelReleaseRootV1::new(closure, vec![]).unwrap();
        let mut stores = Vec::new();
        let mut contracts = Vec::new();
        let mut replicas = Vec::new();
        for slot in 0..3 {
            let mut objects: Vec<_> = manifests
                .iter()
                .enumerate()
                .map(|(index, manifest)| CellRetentionContractV1 {
                    operation: [51 + (slot * 10 + index) as u8; 32],
                    funding_operation: [91 + (slot * 10 + index) as u8; 32],
                    manifest: manifest.clone(),
                    retain_from_height: 0,
                    retain_until_height: 100,
                    maximum_repair_bytes: 8192,
                    successor: None,
                })
                .collect();
            objects.sort_by_key(|object| object.manifest.id());
            let contract = CellReleaseRetentionContractV2 {
                operation: [31 + slot as u8; 32],
                funding_operation: [41 + slot as u8; 32],
                responsible_owner: [131 + slot as u8; 32],
                failure_domain: [141 + slot as u8; 32],
                replica_index: slot as u16,
                required_replicas: 3,
                retain_from_height: 10,
                retain_until_height: 50,
                repair_deadline_height: 40,
                root: root.clone(),
                tensor_model: None,
                objects,
            };
            let mut store = CellReleaseRetentionStoreV2::create(
                &directory.path().join(format!("archive-{slot}")),
                configuration(slot),
            )
            .unwrap();
            store.reserve_release(contract.clone(), deadline()).unwrap();
            if acknowledge {
                store
                    .acknowledge_release(contract.operation, &cache, deadline())
                    .unwrap();
            }
            replicas.push(
                CellCustodyReplicaPinV1::from_contract(
                    &store,
                    &contract,
                    [161 + slot as u8; 32],
                    [181 + slot as u8; 32],
                    [201; 32],
                    [211 + slot as u8; 32],
                )
                .unwrap(),
            );
            stores.push(store);
            contracts.push(contract);
        }
        Self {
            directory,
            cache: Some(cache),
            stores,
            contracts,
            policy: CellReleaseCustodyPolicyV1 {
                root,
                required_replicas: 3,
                renewal_lead_blocks: 8,
                replicas,
            },
        }
    }

    fn probe_budget(&self) -> CellCustodyProbeBudgetV1 {
        CellCustodyProbeBudgetV1::new(deadline(), 3, 3 * self.policy.payload_bytes().unwrap())
    }

    fn observe(
        &mut self,
        height: u64,
        budget: &mut CellCustodyProbeBudgetV1,
    ) -> CellReleaseCustodyReportV1 {
        observe_release_custody(
            &self.policy,
            self.policy.id().unwrap(),
            &mut self.stores.iter_mut().collect::<Vec<_>>(),
            height,
            budget,
        )
        .unwrap()
    }

    fn archive_path(&self, slot: usize) -> PathBuf {
        self.directory.path().join(format!("archive-{slot}"))
    }

    fn remove_source(&mut self) {
        drop(self.cache.take());
        fs::remove_dir_all(self.directory.path().join("inputs")).unwrap();
        for name in ["source.sqlite", "source.sqlite-wal", "source.sqlite-shm"] {
            let path = self.directory.path().join(name);
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
    }

    fn corrupt(&self, slot: usize) {
        let mut arena = OpenOptions::new()
            .write(true)
            .open(self.archive_path(slot).join("objects/payload.arena"))
            .unwrap();
        arena.seek(SeekFrom::Start(0)).unwrap();
        arena.write_all(&[255]).unwrap();
        arena.sync_all().unwrap();
    }
}

fn bytes(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap()
}

#[test]
fn three_complete_target_readbacks_survive_source_and_cache_loss() {
    let mut fixture = Fixture::new(true);
    fixture.remove_source();
    let mut budget = fixture.probe_budget();
    let report = fixture.observe(20, &mut budget);
    assert_eq!(report.release_root, fixture.policy.root.id());
    assert_eq!(report.complete_replicas_observed, 3);
    assert!(report.complete_byte_coverage_observed());
    assert_eq!(report.payload_bytes_per_complete_replica, 200 + 217 + 234);
    assert_eq!(report.usage_before.store_probes_committed, 0);
    assert_eq!(report.usage_after.store_probes_committed, 3);
    assert_eq!(
        report.usage_after.payload_bytes_committed,
        3 * (200 + 217 + 234)
    );
    assert!(report
        .replicas
        .iter()
        .all(|entry| entry.state == CellCustodyReplicaStateV1::Observed));
    assert!(report.plan_continuation(&[]).unwrap().iter().all(|entry| {
        entry.renewal == CellCustodyRenewalActionV1::NotDue
            && entry.recovery == CellCustodyRecoveryActionV1::None
    }));
}

#[test]
fn origin_and_one_missing_provider_leave_one_debt_without_counting_a_cache() {
    let mut fixture = Fixture::new(true);
    fixture.remove_source();
    let policy_id = fixture.policy.id().unwrap();
    let mut budget = fixture.probe_budget();
    let report = observe_release_custody(
        &fixture.policy,
        policy_id,
        &mut fixture.stores[..2].iter_mut().collect::<Vec<_>>(),
        20,
        &mut budget,
    )
    .unwrap();
    assert_eq!(report.complete_replicas_observed, 2);
    assert!(!report.complete_byte_coverage_observed());
    assert_eq!(
        report.replicas[2].state,
        CellCustodyReplicaStateV1::StoreUnavailable
    );
    assert_eq!(report.usage_after.store_probes_committed, 2);
    let plan = report.plan_continuation(&[]).unwrap();
    assert_eq!(
        plan[2].recovery,
        CellCustodyRecoveryActionV1::ReconcileThenRestore
    );
    assert_eq!(plan[2].last_new_repair_height, 40);
    assert_eq!(plan[2].complete_version_payload_bytes, 651);
}

#[test]
fn complementary_partial_archives_never_count_as_a_complete_replica() {
    let mut fixture = Fixture::new(false);
    for slot in 0..3 {
        fixture.stores[slot]
            .acknowledge_member(
                fixture.contracts[slot].operation,
                fixture.contracts[slot].objects[slot].operation,
                fixture.cache.as_ref().unwrap(),
                deadline(),
            )
            .unwrap();
    }
    let mut budget = fixture.probe_budget();
    let report = fixture.observe(20, &mut budget);
    assert_eq!(report.complete_replicas_observed, 0);
    assert!(!report.complete_byte_coverage_observed());
    assert!(report
        .replicas
        .iter()
        .all(|entry| matches!(entry.state, CellCustodyReplicaStateV1::ReadbackRefused(_))));
    assert_eq!(budget.usage().payload_bytes_committed, 3 * 651);
}

#[test]
fn historical_ack_cannot_hide_corruption_and_failed_probes_are_not_refunded() {
    let mut fixture = Fixture::new(true);
    fixture.corrupt(1);
    let corrupt_bytes = bytes(&fixture.archive_path(1).join("objects/payload.arena"));
    let mut budget = fixture.probe_budget();
    let report = fixture.observe(20, &mut budget);
    assert_eq!(report.complete_replicas_observed, 2);
    assert!(matches!(
        report.replicas[1].state,
        CellCustodyReplicaStateV1::ReadbackRefused(_)
    ));
    assert_eq!(budget.usage().payload_bytes_committed, 3 * 651);
    let retry = fixture.observe(20, &mut budget);
    assert_eq!(retry.complete_replicas_observed, 0);
    assert!(retry
        .replicas
        .iter()
        .all(|entry| matches!(entry.state, CellCustodyReplicaStateV1::ProbeRefused(_))));
    assert_eq!(budget.usage(), report.usage_after);
    assert_eq!(
        bytes(&fixture.archive_path(1).join("objects/payload.arena")),
        corrupt_bytes
    );
    assert_eq!(
        fixture.stores[1]
            .contract(fixture.contracts[1].operation, deadline())
            .unwrap(),
        fixture.contracts[1]
    );
}

#[test]
fn policy_pin_rejects_changed_domain_and_continuation_owners_before_probe() {
    let mut fixture = Fixture::new(true);
    let original = fixture.policy.id().unwrap();
    let mut changed = Vec::new();
    let mut policy = fixture.policy.clone();
    policy.replicas[0].administrator[0] ^= 1;
    changed.push(policy);
    let mut policy = fixture.policy.clone();
    policy.replicas[0].domain_evidence[0] ^= 1;
    changed.push(policy);
    let mut policy = fixture.policy.clone();
    policy.replicas[0].renewal_owner[0] ^= 1;
    changed.push(policy);
    let mut policy = fixture.policy.clone();
    policy.replicas[0].repair_owner[0] ^= 1;
    changed.push(policy);
    let mut policy = fixture.policy.clone();
    policy.renewal_lead_blocks += 1;
    changed.push(policy);
    for policy in changed {
        assert_ne!(policy.id().unwrap(), original);
        let mut budget = fixture.probe_budget();
        assert!(matches!(
            observe_release_custody(
                &policy,
                original,
                &mut fixture.stores.iter_mut().collect::<Vec<_>>(),
                20,
                &mut budget
            ),
            Err(CellErrorV1::Invalid("custody policy pin"))
        ));
        assert_eq!(budget.usage().store_probes_committed, 0);
    }
}

#[test]
fn declared_domain_and_owner_aliases_and_absent_evidence_fail_closed() {
    let fixture = Fixture::new(true);
    for cause in [
        "store",
        "owner",
        "administrator",
        "domain",
        "slot",
        "evidence",
        "count",
    ] {
        let mut policy = fixture.policy.clone();
        match cause {
            "store" => policy.replicas[1].store_id = policy.replicas[0].store_id,
            "owner" => policy.replicas[1].responsible_owner = policy.replicas[0].responsible_owner,
            "administrator" => policy.replicas[1].administrator = policy.replicas[0].administrator,
            "domain" => policy.replicas[1].failure_domain = policy.replicas[0].failure_domain,
            "slot" => policy.replicas[1].replica_index = 0,
            "evidence" => policy.replicas[1].domain_evidence = [0; 32],
            "count" => policy.required_replicas = 2,
            _ => unreachable!(),
        }
        assert!(policy.id().is_err(), "{cause}");
    }
}

#[test]
fn expected_store_identifier_cannot_be_counted_twice_from_two_local_directories() {
    let mut fixture = Fixture::new(true);
    let mut duplicate = CellReleaseRetentionStoreV2::create(
        &fixture.directory.path().join("duplicate-store-id"),
        configuration(0),
    )
    .unwrap();
    let mut budget = fixture.probe_budget();
    assert!(matches!(
        observe_release_custody(
            &fixture.policy,
            fixture.policy.id().unwrap(),
            &mut [&mut fixture.stores[0], &mut duplicate],
            20,
            &mut budget
        ),
        Err(CellErrorV1::Invalid(
            "custody unexpected or duplicate store"
        ))
    ));
    assert_eq!(budget.usage().store_probes_committed, 0);
}

#[test]
fn same_payload_under_another_version_is_not_the_pinned_whole_release() {
    let mut fixture = Fixture::new(true);
    let original = fixture.policy.root.closure();
    let closure = CellReleaseClosureV1::new(
        original.release().context().clone(),
        2,
        original.loader_profile(),
        original.roots().to_vec(),
        original.files().to_vec(),
    )
    .unwrap();
    fixture.policy.root =
        CellModelReleaseRootV1::new(closure, vec![fixture.policy.root.id()]).unwrap();
    let mut budget = fixture.probe_budget();
    let report = fixture.observe(20, &mut budget);
    assert_eq!(report.complete_replicas_observed, 0);
    assert!(report
        .replicas
        .iter()
        .all(|entry| entry.state == CellCustodyReplicaStateV1::ContractMismatch));
    assert_eq!(budget.usage().payload_bytes_committed, 3 * 651);
}

#[test]
fn complete_payload_budget_is_reserved_before_any_partial_scan() {
    let mut fixture = Fixture::new(true);
    let mut budget = CellCustodyProbeBudgetV1::new(deadline(), 3, 2 * 651);
    let report = fixture.observe(20, &mut budget);
    assert_eq!(report.complete_replicas_observed, 2);
    assert!(matches!(
        report.replicas[2].state,
        CellCustodyReplicaStateV1::ProbeRefused(_)
    ));
    assert_eq!(report.usage_after.store_probes_committed, 2);
    assert_eq!(report.usage_after.payload_bytes_committed, 2 * 651);
    let plan = report.plan_continuation(&[]).unwrap();
    assert_eq!(
        plan[2].recovery,
        CellCustodyRecoveryActionV1::ObservationRequired
    );
}

#[test]
fn expired_original_observation_deadline_is_not_refreshed() {
    let mut fixture = Fixture::new(true);
    let mut budget = CellCustodyProbeBudgetV1::new(Instant::now(), 30, u64::MAX);
    assert!(matches!(
        observe_release_custody(
            &fixture.policy,
            fixture.policy.id().unwrap(),
            &mut fixture.stores.iter_mut().collect::<Vec<_>>(),
            20,
            &mut budget
        ),
        Err(CellErrorV1::Invalid("custody original deadline"))
    ));
    assert_eq!(budget.usage().store_probes_committed, 0);
}

#[test]
fn future_and_expired_promises_never_count_even_when_all_bytes_remain() {
    let mut fixture = Fixture::new(true);
    for (height, expected) in [
        (9, CellCustodyReplicaStateV1::NotStarted),
        (50, CellCustodyReplicaStateV1::Expired),
    ] {
        let before = bytes(&fixture.archive_path(0).join("objects/payload.arena"));
        let mut budget = fixture.probe_budget();
        let report = fixture.observe(height, &mut budget);
        assert_eq!(report.complete_replicas_observed, 0);
        assert!(report.replicas.iter().all(|entry| entry.state == expected));
        assert_eq!(report.usage_after.store_probes_committed, 0);
        assert_eq!(
            bytes(&fixture.archive_path(0).join("objects/payload.arena")),
            before
        );
        if height == 50 {
            let plan = report.plan_continuation(&[]).unwrap();
            assert!(plan.iter().all(|entry| entry.renewal
                == CellCustodyRenewalActionV1::PromiseExpired
                && entry.recovery == CellCustodyRecoveryActionV1::PromiseExpired));
        }
    }
    assert!(
        fixture.stores[0]
            .verify_release(fixture.contracts[0].operation, deadline())
            .unwrap()
            .acknowledged
    );
}

#[test]
fn sponsor_disappearance_keeps_original_deadline_duty_and_full_coverage_target() {
    let mut fixture = Fixture::new(true);
    let original_contracts = fixture.contracts.clone();
    let mut budget = fixture.probe_budget();
    let report = fixture.observe(42, &mut budget);
    assert!(report.complete_byte_coverage_observed());
    let sponsors = [CellCustodySponsorObservationV1 {
        owner: [201; 32],
        state: CellCustodySponsorStateV1::Unavailable,
    }];
    let plan = report.plan_continuation(&sponsors).unwrap();
    assert!(plan.iter().all(|entry| {
        entry.renewal == CellCustodyRenewalActionV1::ReplacementSponsorRequired
            && entry.successor_required_before_height == 50
            && entry.last_new_repair_height == 40
    }));
    assert_eq!(report.required_replicas, 3);
    for (slot, expected) in original_contracts.iter().enumerate() {
        assert_eq!(
            fixture.stores[slot]
                .contract(expected.operation, deadline())
                .unwrap(),
            *expected
        );
    }
    let mut next_budget = fixture.probe_budget();
    let later = fixture
        .observe(49, &mut next_budget)
        .plan_continuation(&sponsors)
        .unwrap();
    assert!(later
        .iter()
        .all(|entry| entry.successor_required_before_height == 50));
}

#[test]
fn reachable_sponsor_is_never_treated_as_available_funds_or_paid_renewal() {
    let mut fixture = Fixture::new(true);
    let mut budget = fixture.probe_budget();
    let report = fixture.observe(42, &mut budget);
    let unknown = report.plan_continuation(&[]).unwrap();
    assert!(unknown
        .iter()
        .all(|entry| entry.renewal == CellCustodyRenewalActionV1::SponsorUnconfirmed));
    let plan = report
        .plan_continuation(&[CellCustodySponsorObservationV1 {
            owner: [201; 32],
            state: CellCustodySponsorStateV1::Contactable,
        }])
        .unwrap();
    assert!(plan
        .iter()
        .all(|entry| entry.renewal == CellCustodyRenewalActionV1::FundingRequired));
    let sponsor = CellCustodySponsorObservationV1 {
        owner: [201; 32],
        state: CellCustodySponsorStateV1::Unavailable,
    };
    assert!(report.plan_continuation(&[sponsor, sponsor]).is_err());
    assert!(report
        .plan_continuation(&[CellCustodySponsorObservationV1 {
            owner: [202; 32],
            state: CellCustodySponsorStateV1::Contactable
        }])
        .is_err());
}

#[test]
fn missed_fixed_repair_window_requires_replacement_without_extending_paid_terms() {
    let mut fixture = Fixture::new(true);
    fixture.corrupt(0);
    let mut budget = fixture.probe_budget();
    let report = fixture.observe(40, &mut budget);
    assert_eq!(
        report.plan_continuation(&[]).unwrap()[0].recovery,
        CellCustodyRecoveryActionV1::ReconcileThenRestore
    );
    let mut next_budget = fixture.probe_budget();
    let later = fixture.observe(41, &mut next_budget);
    assert_eq!(
        later.plan_continuation(&[]).unwrap()[0].recovery,
        CellCustodyRecoveryActionV1::RepairWindowClosed
    );
    assert_eq!(
        fixture.stores[0]
            .contract(fixture.contracts[0].operation, deadline())
            .unwrap(),
        fixture.contracts[0]
    );
    assert_eq!(later.complete_replicas_observed, 2);
}

#[test]
fn cold_reopen_reobserves_bytes_and_does_not_accept_only_the_prior_report() {
    let mut fixture = Fixture::new(true);
    let mut budget = fixture.probe_budget();
    assert!(fixture
        .observe(20, &mut budget)
        .complete_byte_coverage_observed());
    fixture.stores.clear();
    fixture.corrupt(2);
    for slot in 0..3 {
        fixture.stores.push(
            CellReleaseRetentionStoreV2::open(&fixture.archive_path(slot), configuration(slot))
                .unwrap(),
        );
    }
    let mut new_budget = fixture.probe_budget();
    let reopened = fixture.observe(20, &mut new_budget);
    assert_eq!(reopened.complete_replicas_observed, 2);
    assert!(!reopened.complete_byte_coverage_observed());
    assert!(matches!(
        reopened.replicas[2].state,
        CellCustodyReplicaStateV1::ReadbackRefused(_)
    ));
}

fn version_fixture(
    acknowledge_environment: bool,
) -> (Fixture, CellVersionManifestV1, CellReleaseCustodyPolicyV1) {
    let environment_context = CellContextV1 {
        family: "custody-observation-test-v1".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    };
    let mut files = Vec::new();
    let mut material = Vec::new();
    for (index, name) in ["abi.json", "runtime.bin"].into_iter().enumerate() {
        let payload = vec![91 + index as u8; 100 + index * 17];
        let digest: CellDigestV1 = Sha256::digest(&payload).into();
        let manifest = CellManifestV1::new(
            environment_context.clone(),
            payload.len() as u64,
            digest,
            16_384,
            vec![CellChunkV1 {
                size: payload.len() as u32,
                sha256: digest,
            }],
        )
        .unwrap();
        files.push(CellClosureFileV1 {
            path: name.into(),
            role: CellFileRoleV1::Configuration,
            manifest: manifest.id(),
            payload_sha256: digest,
            payload_bytes: payload.len() as u64,
            dependencies: if index == 1 { vec![0] } else { vec![] },
        });
        material.push((name, payload, manifest));
    }
    let environment =
        CellReleaseClosureV1::new(environment_context.clone(), 1, [12; 32], vec![1], files)
            .unwrap();
    let mut fixture = Fixture::with_runtime(true, environment.id());
    for (name, payload, expected) in &material {
        let input = fixture.directory.path().join("inputs").join(name);
        fs::write(&input, payload).unwrap();
        let actual = fixture
            .cache
            .as_ref()
            .unwrap()
            .pack_file(&input, environment_context.clone(), 16_384)
            .unwrap();
        assert_eq!(&actual, expected);
    }
    let environment_root = CellModelReleaseRootV1::new(environment.clone(), vec![]).unwrap();
    let mut environment_pins = Vec::new();
    for slot in 0..3 {
        let mut objects: Vec<_> = material
            .iter()
            .enumerate()
            .map(|(index, (_, _, manifest))| CellRetentionContractV1 {
                operation: [56 + (slot * 10 + index) as u8; 32],
                funding_operation: [96 + (slot * 10 + index) as u8; 32],
                manifest: manifest.clone(),
                retain_from_height: 0,
                retain_until_height: 100,
                maximum_repair_bytes: 8192,
                successor: None,
            })
            .collect();
        objects.sort_by_key(|object| object.manifest.id());
        let contract = CellReleaseRetentionContractV2 {
            operation: [34 + slot as u8; 32],
            funding_operation: [44 + slot as u8; 32],
            root: environment_root.clone(),
            objects,
            ..fixture.contracts[slot].clone()
        };
        fixture.stores[slot]
            .reserve_release(contract.clone(), deadline())
            .unwrap();
        if acknowledge_environment {
            fixture.stores[slot]
                .acknowledge_release(
                    contract.operation,
                    fixture.cache.as_ref().unwrap(),
                    deadline(),
                )
                .unwrap();
        }
        let model_pin = &fixture.policy.replicas[slot];
        environment_pins.push(
            CellCustodyReplicaPinV1::from_contract(
                &fixture.stores[slot],
                &contract,
                model_pin.administrator,
                model_pin.domain_evidence,
                model_pin.renewal_owner,
                model_pin.repair_owner,
            )
            .unwrap(),
        );
    }
    let environment_policy = CellReleaseCustodyPolicyV1 {
        root: environment_root,
        required_replicas: 3,
        renewal_lead_blocks: 8,
        replicas: environment_pins,
    };
    let mut manifests: Vec<_> = fixture.contracts[0]
        .objects
        .iter()
        .map(|object| object.manifest.clone())
        .collect();
    manifests.extend(material.into_iter().map(|(_, _, manifest)| manifest));
    manifests.sort_by_key(CellManifestV1::id);
    let version =
        CellVersionManifestV1::new(fixture.policy.root.clone(), environment, manifests).unwrap();
    (fixture, version, environment_policy)
}

fn policy_pin(policy: &CellReleaseCustodyPolicyV1) -> CellCustodyPolicyPinV1<'_> {
    CellCustodyPolicyPinV1 {
        policy,
        expected: policy.id().unwrap(),
    }
}

#[test]
fn complete_version_counts_real_model_and_environment_on_the_same_archives() {
    let (mut fixture, version, environment) = version_fixture(true);
    fixture.remove_source();
    let mut budget = CellCustodyProbeBudgetV1::new(deadline(), 6, 3 * (651 + 217));
    let mut changed = version.commitment();
    changed[0] ^= 1;
    assert!(matches!(
        observe_version_custody(
            &version,
            changed,
            policy_pin(&fixture.policy),
            policy_pin(&environment),
            &mut fixture.stores.iter_mut().collect::<Vec<_>>(),
            20,
            &mut budget,
        ),
        Err(CellErrorV1::Invalid("custody complete version pin"))
    ));
    assert_eq!(budget.usage().store_probes_committed, 0);
    let report = observe_version_custody(
        &version,
        version.commitment(),
        policy_pin(&fixture.policy),
        policy_pin(&environment),
        &mut fixture.stores.iter_mut().collect::<Vec<_>>(),
        20,
        &mut budget,
    )
    .unwrap();
    assert!(report.complete_byte_coverage_observed());
    assert_eq!(report.version(), version.commitment());
    assert_eq!(report.complete_replica_slots(), [0, 1, 2]);
    assert_eq!(report.payload_bytes_per_complete_replica(), 651 + 217);
    assert_eq!(report.usage_after().store_probes_committed, 6);
    assert_eq!(
        report.usage_after().payload_bytes_committed,
        3 * (651 + 217)
    );
    assert!(report.model().unwrap().complete_byte_coverage_observed());
    assert!(report
        .environment()
        .unwrap()
        .complete_byte_coverage_observed());
}

#[test]
fn complete_models_with_one_partial_environment_leave_the_whole_version_incomplete() {
    let (mut fixture, version, environment) = version_fixture(false);
    for slot in 0..2 {
        fixture.stores[slot]
            .acknowledge_release(
                environment.replicas[slot].operation,
                fixture.cache.as_ref().unwrap(),
                deadline(),
            )
            .unwrap();
    }
    let last = fixture.stores[2]
        .contract(environment.replicas[2].operation, deadline())
        .unwrap();
    fixture.stores[2]
        .acknowledge_member(
            last.operation,
            last.objects[0].operation,
            fixture.cache.as_ref().unwrap(),
            deadline(),
        )
        .unwrap();
    let mut budget = CellCustodyProbeBudgetV1::new(deadline(), 6, 3 * (651 + 217));
    let report = observe_version_custody(
        &version,
        version.commitment(),
        policy_pin(&fixture.policy),
        policy_pin(&environment),
        &mut fixture.stores.iter_mut().collect::<Vec<_>>(),
        20,
        &mut budget,
    )
    .unwrap();
    assert_eq!(report.model().unwrap().complete_replicas_observed(), 3);
    assert_eq!(
        report.environment().unwrap().complete_replicas_observed(),
        2
    );
    assert_eq!(report.complete_replica_slots(), [0, 1]);
    assert!(!report.complete_byte_coverage_observed());
    assert_eq!(
        report.usage_after().payload_bytes_committed,
        3 * (651 + 217)
    );
    let retry = observe_version_custody(
        &version,
        version.commitment(),
        policy_pin(&fixture.policy),
        policy_pin(&environment),
        &mut fixture.stores.iter_mut().collect::<Vec<_>>(),
        20,
        &mut budget,
    )
    .unwrap();
    assert_eq!(retry.complete_replicas_observed(), 0);
    for component in [retry.model().unwrap(), retry.environment().unwrap()] {
        assert!(component
            .replicas()
            .iter()
            .all(|entry| matches!(entry.state, CellCustodyReplicaStateV1::ProbeRefused(_))));
    }
    assert_eq!(retry.usage_after(), report.usage_after());
}

#[test]
fn complete_version_refuses_to_splice_a_valid_environment_from_another_physical_store() {
    let (mut fixture, version, mut environment) = version_fixture(true);
    let contract = fixture.stores[0]
        .contract(environment.replicas[0].operation, deadline())
        .unwrap();
    let mut replacement = CellReleaseRetentionStoreV2::create(
        &fixture.directory.path().join("other-environment-store"),
        configuration(3),
    )
    .unwrap();
    replacement
        .reserve_release(contract.clone(), deadline())
        .unwrap();
    replacement
        .acknowledge_release(
            contract.operation,
            fixture.cache.as_ref().unwrap(),
            deadline(),
        )
        .unwrap();
    let old = environment.replicas[0].clone();
    environment.replicas[0] = CellCustodyReplicaPinV1::from_contract(
        &replacement,
        &contract,
        old.administrator,
        old.domain_evidence,
        old.renewal_owner,
        old.repair_owner,
    )
    .unwrap();
    assert!(
        replacement
            .verify_release(contract.operation, deadline())
            .unwrap()
            .acknowledged
    );
    let mut budget = CellCustodyProbeBudgetV1::new(deadline(), 6, 3 * (651 + 217));
    let mut stores: Vec<_> = fixture.stores.iter_mut().collect();
    stores.push(&mut replacement);
    assert!(matches!(
        observe_version_custody(
            &version,
            version.commitment(),
            policy_pin(&fixture.policy),
            policy_pin(&environment),
            &mut stores,
            20,
            &mut budget,
        ),
        Err(CellErrorV1::Invalid("custody complete version topology"))
    ));
    assert_eq!(budget.usage().store_probes_committed, 0);
}

#[test]
fn complete_version_environment_cannot_obtain_a_fresh_budget_after_model_scans() {
    let (mut fixture, version, environment) = version_fixture(true);
    let mut budget = CellCustodyProbeBudgetV1::new(deadline(), 3, 3 * 651);
    let report = observe_version_custody(
        &version,
        version.commitment(),
        policy_pin(&fixture.policy),
        policy_pin(&environment),
        &mut fixture.stores.iter_mut().collect::<Vec<_>>(),
        20,
        &mut budget,
    )
    .unwrap();
    assert_eq!(report.model().unwrap().complete_replicas_observed(), 3);
    assert_eq!(
        report.environment().unwrap().complete_replicas_observed(),
        0
    );
    assert_eq!(report.complete_replicas_observed(), 0);
    assert!(!report.complete_byte_coverage_observed());
    assert_eq!(report.usage_after().payload_bytes_committed, 3 * 651);
    assert_eq!(report.usage_after().store_probes_committed, 3);
    assert!(report
        .environment()
        .unwrap()
        .replicas()
        .iter()
        .all(|entry| matches!(entry.state, CellCustodyReplicaStateV1::ProbeRefused(_))));
}
