use std::time::Duration;

use super::*;
use crate::cell::{
    version::tests::{fixture as version_fixture, owner as loader_owner},
    CellChunkV1, CellFileRoleV1, CellLoaderContextV1, CellManifestV1, CellModelReleaseRootV1,
    CellReleaseClosureV1, CellRetainedVersionEntryV1, CellRs46ChunkBindingV1,
    CellRs46ManifestBindingV1, CellStoreV1, CellVersionLoaderContextV1, CellVersionManifestV1,
};

const ALL_SIX: [(usize, u8); 6] = [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4), (5, 5)];
const FOUR_SURVIVORS: [(usize, u8); 4] = [(2, 2), (3, 3), (4, 4), (5, 5)];
const ORIGINAL_BYTES: u64 = 4 * 32_769;
const ORIGINAL_CHUNKS: u64 = 12;
// Six distinct identities on each of three axes: 18 events, 172 scenarios.
const ORIGINAL_EVALUATION_STEPS: u64 = ORIGINAL_CHUNKS * (18 * 6 + 172 * 7);

struct Fixture {
    _directory: tempfile::TempDir,
    store: CellStoreV1,
    retained: CellRetainedVersionSetV1,
    model_owners: Vec<CellLoaderContextV1>,
    environment_owners: Vec<CellLoaderContextV1>,
    policy: CellRecoveryPlacementPolicyV1,
}

impl Fixture {
    fn new(two_compositions: bool) -> Self {
        let (directory, store, version) = version_fixture();
        let mut versions = vec![version];
        if two_compositions {
            let original = &versions[0];
            let closure = original.model().closure();
            let next_closure = CellReleaseClosureV1::new(
                closure.release().context().clone(),
                closure.selected_generation() + 1,
                [78; 32],
                closure.roots().to_vec(),
                closure.files().to_vec(),
            )
            .unwrap();
            let next = CellVersionManifestV1::new(
                CellModelReleaseRootV1::new(next_closure, vec![original.model().id()]).unwrap(),
                original.environment().clone(),
                original.manifests().to_vec(),
            )
            .unwrap();
            assert_ne!(original.commitment(), next.commitment());
            versions.push(next);
        }
        Self::from_versions(directory, store, versions)
    }

    fn from_versions(
        directory: tempfile::TempDir,
        store: CellStoreV1,
        mut versions: Vec<CellVersionManifestV1>,
    ) -> Self {
        versions.sort_by_key(CellVersionManifestV1::commitment);
        let model_owners = versions
            .iter()
            .map(|v| loader_owner(v.model().closure(), CellFileRoleV1::Base))
            .collect();
        let environment_owners = versions
            .iter()
            .map(|v| loader_owner(v.environment(), CellFileRoleV1::Configuration))
            .collect();
        let retained = CellRetainedVersionSetV1::new(
            7,
            versions
                .into_iter()
                .map(|version| CellRetainedVersionEntryV1 {
                    version,
                    retain_from_height: 10,
                    retain_until_height: 100,
                })
                .collect(),
        )
        .unwrap();
        let providers = (0..6_u8)
            .map(|index| CellRecoveryProviderPinV1 {
                provider_id: [index + 1; 32],
                operator: [index + 40; 32],
                administrator: [index + 80; 32],
                failure_domain: [index + 120; 32],
                domain_evidence: [index + 180; 32],
            })
            .collect();
        let policy = CellRecoveryPlacementPolicyV1::new(
            providers,
            CellRecoveryFaultPolicyV1 {
                axes: vec![
                    CellRecoveryFaultAxisV1::Operator,
                    CellRecoveryFaultAxisV1::Administrator,
                    CellRecoveryFaultAxisV1::FailureDomain,
                ],
                maximum_lost_events: 2,
            },
        )
        .unwrap();
        Self {
            _directory: directory,
            store,
            retained,
            model_owners,
            environment_owners,
            policy,
        }
    }

    fn contexts(&self) -> Vec<CellVersionLoaderContextV1<'_>> {
        self.retained
            .entries()
            .iter()
            .enumerate()
            .map(|(index, entry)| CellVersionLoaderContextV1 {
                commitment: entry.version.commitment(),
                model: &self.model_owners[index],
                environment: &self.environment_owners[index],
            })
            .collect()
    }

    fn owner<'a>(
        &'a self,
        contexts: &'a [CellVersionLoaderContextV1<'a>],
    ) -> CellRetainedSetOwnerV1<'a> {
        CellRetainedSetOwnerV1 {
            commitment: self.retained.commitment(),
            epoch: 7,
            current_height: 20,
            required_until_height: 80,
            versions: contexts,
        }
    }

    fn manifest(&self, key: CellRecoveryChunkKeyV1) -> &CellManifestV1 {
        self.retained
            .entries()
            .iter()
            .flat_map(|entry| entry.version.manifests())
            .find(|manifest| manifest.id() == key.manifest)
            .unwrap()
    }

    fn original(&self, key: CellRecoveryChunkKeyV1) -> Vec<u8> {
        self.store
            .chunk(self.manifest(key).chunks()[key.chunk_index as usize].sha256)
            .unwrap()
            .unwrap()
    }

    fn shares(
        &self,
        key: CellRecoveryChunkKeyV1,
        assignments: &[(usize, u8)],
    ) -> Vec<CellRs46ProviderShardV1> {
        let manifest = self.manifest(key);
        let binding = CellRs46ChunkBindingV1::from_pinned_manifest(
            manifest,
            key.manifest,
            manifest.context(),
            key.chunk_index,
        )
        .unwrap();
        let encoded = binding.encode_chunk(&self.original(key)).unwrap();
        assignments
            .iter()
            .map(|(provider, shard)| CellRs46ProviderShardV1 {
                provider_id: self.policy.providers()[*provider].provider_id,
                shard: encoded[usize::from(*shard)].clone(),
            })
            .collect()
    }

    fn complete(
        &self,
        session: &mut CellRetainedRs46RecoveryV1<'_, '_>,
        assignments: &[(usize, u8)],
    ) -> u64 {
        let mut count = 0;
        while let Some(key) = session.next_chunk() {
            let restored = session
                .recover_next(&self.shares(key, assignments))
                .unwrap();
            assert_eq!(restored, self.original(key));
            count += 1;
        }
        count
    }
}

fn budget() -> CellRs46RecoveryBudgetV1 {
    CellRs46RecoveryBudgetV1::new(
        Instant::now() + Duration::from_secs(30),
        8,
        128,
        2_000_000,
        10_000_000,
        4_000_000,
    )
}

fn error<T>(result: CellResultV1<T>) -> CellErrorV1 {
    match result {
        Err(error) => error,
        Ok(_) => panic!("expected refusal"),
    }
}

fn wire_bytes(shares: &[CellRs46ProviderShardV1]) -> u64 {
    shares
        .iter()
        .map(|share| share.shard.encode().len() as u64)
        .sum()
}

fn corrupt_payload(shard: &CellRs46ShardV1) -> CellRs46ShardV1 {
    let mut wire = shard.encode();
    *wire.last_mut().unwrap() ^= 1;
    // Parsing alone intentionally does not authenticate the payload.
    CellRs46ShardV1::decode(&wire).unwrap()
}

#[test]
fn actual_complete_retained_union_recovers_all_bytes_and_shared_compositions_once() {
    let fixture = Fixture::new(true);
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    let mut budget = budget();
    let mut session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .unwrap();
    assert_eq!(fixture.retained.entries().len(), 2);
    assert_eq!(fixture.complete(&mut session, &ALL_SIX), ORIGINAL_CHUNKS);
    let report = session.finish().unwrap();
    assert_eq!(report.retained_set(), fixture.retained.commitment());
    assert_eq!(report.placement_policy(), fixture.policy.commitment());
    assert_eq!(
        (report.manifests(), report.chunks(), report.source_bytes()),
        (4, ORIGINAL_CHUNKS, ORIGINAL_BYTES)
    );
    assert!(report.survives_declared_faults());
    assert!(report.deficits().is_empty());
    let (started, finished) = report.observation_window();
    assert!(started <= finished);
    assert_eq!(budget.usage().attempts_committed, 1);
    assert_eq!(budget.usage().chunks_committed, ORIGINAL_CHUNKS);
    assert_eq!(budget.usage().source_bytes_committed, ORIGINAL_BYTES);
    assert_eq!(
        budget.usage().evaluation_steps_committed,
        ORIGINAL_EVALUATION_STEPS
    );
    assert!(budget.usage().shard_wire_bytes_committed > ORIGINAL_BYTES);
}

#[test]
fn four_correct_survivors_restore_bytes_without_claiming_two_more_losses() {
    let fixture = Fixture::new(false);
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    let mut budget = budget();
    let mut session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .unwrap();
    assert_eq!(
        fixture.complete(&mut session, &FOUR_SURVIVORS),
        ORIGINAL_CHUNKS
    );
    let report = session.finish().unwrap();
    assert!(!report.survives_declared_faults());
    assert_eq!(report.deficits().len() as u64, ORIGINAL_CHUNKS);
    assert!(report
        .deficits()
        .iter()
        .all(|deficit| deficit.placement.recoverable_now()
            && deficit.placement.minimum_distinct_shards() == 2));
}

#[test]
fn actual_valid_bytes_in_one_shared_domain_keep_every_deficit() {
    let fixture = Fixture::new(false);
    let mut pins = fixture.policy.providers().to_vec();
    for pin in &mut pins {
        pin.failure_domain = [17; 32];
    }
    let policy = CellRecoveryPlacementPolicyV1::new(pins, fixture.policy.faults().clone()).unwrap();
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    let mut budget = budget();
    let mut session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &policy,
        policy.commitment(),
        &mut budget,
    )
    .unwrap();
    fixture.complete(&mut session, &ALL_SIX);
    let report = session.finish().unwrap();
    assert_eq!(report.source_bytes(), ORIGINAL_BYTES);
    assert!(!report.survives_declared_faults());
    assert_eq!(report.deficits().len() as u64, ORIGINAL_CHUNKS);
    for deficit in report.deficits() {
        assert!(deficit.placement.recoverable_now());
        assert_eq!(deficit.placement.minimum_distinct_shards(), 0);
        assert_eq!(
            deficit.placement.worst_case_events(),
            &[super::super::CellRecoveryFaultEventV1 {
                axis: CellRecoveryFaultAxisV1::FailureDomain,
                identity: [17; 32],
            }]
        );
    }
}

#[test]
fn missing_final_model_or_environment_chunk_cannot_finish() {
    for environment in [false, true] {
        let fixture = Fixture::new(false);
        let version = &fixture.retained.entries()[0].version;
        let files = if environment {
            version.environment().files()
        } else {
            version.model().closure().files()
        };
        let target_manifest = files.last().unwrap().manifest;
        let target = CellRecoveryChunkKeyV1 {
            manifest: target_manifest,
            chunk_index: 2,
        };
        let contexts = fixture.contexts();
        let owner = fixture.owner(&contexts);
        let mut budget = budget();
        let mut session = CellRetainedRs46RecoveryV1::new(
            &fixture.retained,
            &owner,
            &fixture.policy,
            fixture.policy.commitment(),
            &mut budget,
        )
        .unwrap();
        while session.next_chunk() != Some(target) {
            let key = session
                .next_chunk()
                .expect("target chunk is in the exact roster");
            session
                .recover_next(&fixture.shares(key, &ALL_SIX))
                .unwrap();
        }
        assert!(error(session.finish())
            .to_string()
            .contains("complete retained closure not recovered"));
        assert_eq!(budget.usage().chunks_committed, ORIGINAL_CHUNKS);
    }
}

#[test]
fn empty_session_and_unexpected_extra_chunk_cannot_finish() {
    let fixture = Fixture::new(false);
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    let mut budget = budget();
    let session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .unwrap();
    assert!(session.finish().is_err());
    let mut session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .unwrap();
    let first = session.next_chunk().unwrap();
    let replay = fixture.shares(first, &ALL_SIX);
    fixture.complete(&mut session, &ALL_SIX);
    assert!(session.next_chunk().is_none());
    assert!(error(session.recover_next(&replay))
        .to_string()
        .contains("unexpected extra chunk"));
    assert!(session.finish().is_err());
}

#[test]
fn wrong_chunk_index_is_refused_and_correct_retry_cannot_clear_failure() {
    let fixture = Fixture::new(false);
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    let mut budget = budget();
    let mut session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .unwrap();
    let expected = session.next_chunk().unwrap();
    let later = CellRecoveryChunkKeyV1 {
        chunk_index: expected.chunk_index + 1,
        ..expected
    };
    let wrong = fixture.shares(later, &ALL_SIX);
    assert!(error(session.recover_next(&wrong))
        .to_string()
        .contains("original chunk pin"));
    assert!(
        error(session.recover_next(&fixture.shares(expected, &ALL_SIX)))
            .to_string()
            .contains("already refused")
    );
    assert!(session.finish().is_err());
    assert_eq!(
        budget.usage().shard_wire_bytes_committed,
        wire_bytes(&wrong)
    );
}

#[test]
fn shards_from_another_manifest_cannot_complete_the_next_selected_chunk() {
    let fixture = Fixture::new(false);
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    let mut budget = budget();
    let mut session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .unwrap();
    let expected = session.next_chunk().unwrap();
    let other = fixture.retained.entries()[0]
        .version
        .manifests()
        .iter()
        .find(|m| m.id() != expected.manifest)
        .unwrap();
    let wrong = fixture.shares(
        CellRecoveryChunkKeyV1 {
            manifest: other.id(),
            chunk_index: 0,
        },
        &ALL_SIX,
    );
    assert!(error(session.recover_next(&wrong))
        .to_string()
        .contains("original chunk pin"));
    assert!(session.finish().is_err());
}

#[test]
fn original_chunk_binding_refuses_foreign_context_even_for_identical_source_bytes() {
    let fixture = Fixture::new(false);
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    let mut budget = budget();
    let mut session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .unwrap();
    let key = session.next_chunk().unwrap();
    let expected = fixture.manifest(key);
    let mut context = expected.context().clone();
    context.runtime = [51; 32];
    let foreign = CellManifestV1::new(
        context,
        expected.size(),
        expected.payload_sha256(),
        expected.chunk_bytes(),
        expected.chunks().to_vec(),
    )
    .unwrap();
    let binding =
        CellRs46ChunkBindingV1::from_pinned_manifest(&foreign, foreign.id(), foreign.context(), 0)
            .unwrap();
    let shards = binding.encode_chunk(&fixture.original(key)).unwrap();
    let shares: Vec<_> = shards
        .into_iter()
        .enumerate()
        .map(|(index, shard)| CellRs46ProviderShardV1 {
            provider_id: fixture.policy.providers()[index].provider_id,
            shard,
        })
        .collect();
    assert!(error(session.recover_next(&shares))
        .to_string()
        .contains("original chunk pin"));
    assert!(session.finish().is_err());
}

#[test]
fn corrupt_extra_shard_is_refused_after_four_correct_data_rows() {
    let fixture = Fixture::new(false);
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    let mut budget = budget();
    let mut session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .unwrap();
    let key = session.next_chunk().unwrap();
    let mut shares = fixture.shares(key, &ALL_SIX);
    shares[5].shard = corrupt_payload(&shares[5].shard);
    assert!(error(session.recover_next(&shares))
        .to_string()
        .contains("inconsistent extra shard"));
    assert!(session.finish().is_err());
    assert_eq!(
        budget.usage().shard_wire_bytes_committed,
        wire_bytes(&shares)
    );
}

#[test]
fn identical_indices_on_different_providers_do_not_create_four_rows() {
    let fixture = Fixture::new(false);
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    let mut budget = budget();
    let mut session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .unwrap();
    let key = session.next_chunk().unwrap();
    let shares = fixture.shares(key, &[(0, 0), (1, 0), (2, 1), (3, 1), (4, 2), (5, 2)]);
    assert!(error(session.recover_next(&shares))
        .to_string()
        .contains("requires four to six shards"));
    assert!(session.finish().is_err());
    assert_eq!(
        budget.usage().shard_wire_bytes_committed,
        wire_bytes(&shares)
    );
}

#[test]
fn replicated_valid_index_counts_once_and_every_replica_must_match() {
    let fixture = Fixture::new(false);
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    let mut budget = budget();
    let assignments = [(0, 0), (1, 0), (2, 1), (3, 2), (4, 3)];
    let mut session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .unwrap();
    let key = session.next_chunk().unwrap();
    let shares = fixture.shares(key, &assignments);
    assert_eq!(
        session.recover_next(&shares).unwrap(),
        fixture.original(key)
    );
    drop(session);
    let mut session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .unwrap();
    let mut conflict = fixture.shares(key, &assignments);
    conflict[1].shard = corrupt_payload(&conflict[1].shard);
    assert!(error(session.recover_next(&conflict))
        .to_string()
        .contains("conflicting copies of one shard"));
    assert!(session.finish().is_err());
    assert_eq!(
        budget.usage().shard_wire_bytes_committed,
        wire_bytes(&shares) + wire_bytes(&conflict)
    );
}

#[test]
fn duplicate_provider_index_unknown_provider_and_noncanonical_input_are_refused() {
    let fixture = Fixture::new(false);
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    for mutation in 0..3 {
        let mut budget = budget();
        let mut session = CellRetainedRs46RecoveryV1::new(
            &fixture.retained,
            &owner,
            &fixture.policy,
            fixture.policy.commitment(),
            &mut budget,
        )
        .unwrap();
        let mut shares = fixture.shares(session.next_chunk().unwrap(), &ALL_SIX);
        match mutation {
            0 => shares.insert(0, shares[0].clone()),
            1 => shares[5].provider_id = [250; 32],
            _ => shares.swap(0, 1),
        }
        assert!(session.recover_next(&shares).is_err());
        assert!(session.finish().is_err());
        assert_eq!(
            budget.usage().shard_wire_bytes_committed,
            wire_bytes(&shares)
        );
    }
}

#[test]
fn whole_payload_hash_is_checked_even_when_every_chunk_is_originally_pinned() {
    let (directory, store, original) = version_fixture();
    let closure = original.model().closure();
    let original_id = closure.files()[0].manifest;
    let manifest = original
        .manifests()
        .iter()
        .find(|m| m.id() == original_id)
        .unwrap();
    let wrong_payload = Sha256::digest(b"not the original concatenated payload").into();
    let dishonest = CellManifestV1::new(
        manifest.context().clone(),
        manifest.size(),
        wrong_payload,
        manifest.chunk_bytes(),
        manifest.chunks().to_vec(),
    )
    .unwrap();
    let dishonest_id = dishonest.id();
    let mut files = closure.files().to_vec();
    files[0].manifest = dishonest_id;
    files[0].payload_sha256 = wrong_payload;
    let changed_closure = CellReleaseClosureV1::new(
        closure.release().context().clone(),
        closure.selected_generation(),
        closure.loader_profile(),
        closure.roots().to_vec(),
        files,
    )
    .unwrap();
    let mut manifests = original.manifests().to_vec();
    *manifests
        .iter_mut()
        .find(|m| m.id() == original_id)
        .unwrap() = dishonest;
    manifests.sort_by_key(CellManifestV1::id);
    let changed_version = CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(changed_closure, vec![]).unwrap(),
        original.environment().clone(),
        manifests,
    )
    .unwrap();
    let fixture = Fixture::from_versions(directory, store, vec![changed_version]);
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    let mut budget = budget();
    let mut session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .unwrap();
    loop {
        let key = session.next_chunk().unwrap();
        let result = session.recover_next(&fixture.shares(key, &ALL_SIX));
        if key.manifest == dishonest_id && key.chunk_index == 2 {
            assert!(error(result)
                .to_string()
                .contains("recovered whole payload"));
            break;
        }
        result.unwrap();
    }
    assert!(session.finish().is_err());
}

#[test]
fn owner_set_epoch_version_and_placement_pins_refuse_before_reservation() {
    let fixture = Fixture::new(true);
    let contexts = fixture.contexts();
    for field in 0..3 {
        let mut owner = fixture.owner(&contexts);
        match field {
            0 => owner.commitment[0] ^= 1,
            1 => owner.epoch += 1,
            _ => owner.required_until_height = 101,
        }
        let mut budget = budget();
        assert!(CellRetainedRs46RecoveryV1::new(
            &fixture.retained,
            &owner,
            &fixture.policy,
            fixture.policy.commitment(),
            &mut budget,
        )
        .is_err());
        assert_eq!(budget.usage(), CellRs46RecoveryUsageV1::default());
    }
    let owner = fixture.owner(&contexts);
    let mut changed_pins = fixture.policy.providers().to_vec();
    changed_pins[0].domain_evidence = [99; 32];
    let changed_policy =
        CellRecoveryPlacementPolicyV1::new(changed_pins, fixture.policy.faults().clone()).unwrap();
    assert_ne!(changed_policy.commitment(), fixture.policy.commitment());
    let mut budget = budget();
    assert!(CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &changed_policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .is_err());
    assert_eq!(budget.usage(), CellRs46RecoveryUsageV1::default());
    let omitted =
        CellRetainedVersionSetV1::new(7, fixture.retained.entries()[..1].to_vec()).unwrap();
    assert!(CellRetainedRs46RecoveryV1::new(
        &omitted,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .is_err());
    assert_eq!(budget.usage(), CellRs46RecoveryUsageV1::default());
    let mut changed_contexts = fixture.contexts();
    changed_contexts[0].commitment[0] ^= 1;
    let wrong_version = fixture.owner(&changed_contexts);
    assert!(CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &wrong_version,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .is_err());
    assert_eq!(budget.usage(), CellRs46RecoveryUsageV1::default());
}

#[test]
fn whole_plan_limits_refuse_upfront_without_a_partial_admission() {
    let fixture = Fixture::new(false);
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    for (attempts, chunks, bytes, steps) in [
        (
            0,
            ORIGINAL_CHUNKS,
            ORIGINAL_BYTES,
            ORIGINAL_EVALUATION_STEPS,
        ),
        (
            1,
            ORIGINAL_CHUNKS - 1,
            ORIGINAL_BYTES,
            ORIGINAL_EVALUATION_STEPS,
        ),
        (
            1,
            ORIGINAL_CHUNKS,
            ORIGINAL_BYTES - 1,
            ORIGINAL_EVALUATION_STEPS,
        ),
        (
            1,
            ORIGINAL_CHUNKS,
            ORIGINAL_BYTES,
            ORIGINAL_EVALUATION_STEPS - 1,
        ),
    ] {
        let mut budget = CellRs46RecoveryBudgetV1::new(
            Instant::now() + Duration::from_secs(30),
            attempts,
            chunks,
            bytes,
            steps,
            1_000_000,
        );
        assert!(error(CellRetainedRs46RecoveryV1::new(
            &fixture.retained,
            &owner,
            &fixture.policy,
            fixture.policy.commitment(),
            &mut budget,
        ))
        .to_string()
        .contains("complete-set reservation exhausted"));
        assert_eq!(budget.usage(), CellRs46RecoveryUsageV1::default());
    }
    let mut exact = CellRs46RecoveryBudgetV1::new(
        Instant::now() + Duration::from_secs(30),
        1,
        ORIGINAL_CHUNKS,
        ORIGINAL_BYTES,
        ORIGINAL_EVALUATION_STEPS,
        1_000_000,
    );
    let session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut exact,
    )
    .unwrap();
    drop(session);
    assert_eq!(
        exact.usage().evaluation_steps_committed,
        ORIGINAL_EVALUATION_STEPS
    );
}

#[test]
fn corrupt_attempt_keeps_complete_plan_and_wire_debits_across_new_sessions() {
    let fixture = Fixture::new(false);
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    // Two attempt slots exist, but only the original whole-plan work allowance.
    let mut budget = CellRs46RecoveryBudgetV1::new(
        Instant::now() + Duration::from_secs(30),
        2,
        2 * ORIGINAL_CHUNKS,
        2 * ORIGINAL_BYTES,
        ORIGINAL_EVALUATION_STEPS,
        1_000_000,
    );
    let mut session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .unwrap();
    let key = session.next_chunk().unwrap();
    let mut shares = fixture.shares(key, &ALL_SIX);
    shares[5].shard = corrupt_payload(&shares[5].shard);
    assert!(session.recover_next(&shares).is_err());
    assert!(session
        .recover_next(&fixture.shares(key, &ALL_SIX))
        .is_err());
    assert!(session.finish().is_err());
    let original_usage = budget.usage();
    assert_eq!(original_usage.attempts_committed, 1);
    assert_eq!(original_usage.chunks_committed, ORIGINAL_CHUNKS);
    assert_eq!(original_usage.source_bytes_committed, ORIGINAL_BYTES);
    assert_eq!(
        original_usage.evaluation_steps_committed,
        ORIGINAL_EVALUATION_STEPS
    );
    assert_eq!(
        original_usage.shard_wire_bytes_committed,
        wire_bytes(&shares)
    );
    assert!(CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .is_err());
    assert_eq!(budget.usage(), original_usage);
}

#[test]
fn original_attempt_and_wire_limits_do_not_reset_after_refusal() {
    let fixture = Fixture::new(false);
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    let mut budget = CellRs46RecoveryBudgetV1::new(
        Instant::now() + Duration::from_secs(30),
        1,
        100,
        1_000_000,
        1_000_000,
        0,
    );
    let mut session = CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .unwrap();
    let key = session.next_chunk().unwrap();
    assert!(error(session.recover_next(&fixture.shares(key, &ALL_SIX)))
        .to_string()
        .contains("original wire reservation"));
    assert!(session.finish().is_err());
    assert_eq!(budget.usage().attempts_committed, 1);
    assert_eq!(budget.usage().shard_wire_bytes_committed, 0);
    assert!(CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    )
    .is_err());
    assert_eq!(budget.usage().attempts_committed, 1);
}

#[test]
fn expired_original_deadline_refuses_before_any_reservation() {
    let fixture = Fixture::new(false);
    let contexts = fixture.contexts();
    let owner = fixture.owner(&contexts);
    let mut budget =
        CellRs46RecoveryBudgetV1::new(Instant::now(), 1, 100, 1_000_000, 1_000_000, 1_000_000);
    assert!(error(CellRetainedRs46RecoveryV1::new(
        &fixture.retained,
        &owner,
        &fixture.policy,
        fixture.policy.commitment(),
        &mut budget,
    ))
    .to_string()
    .contains("original deadline"));
    assert_eq!(budget.usage(), CellRs46RecoveryUsageV1::default());
}

#[test]
fn cached_manifest_binding_checks_independent_pins_and_chunk_bounds() {
    let fixture = Fixture::new(false);
    let manifest = &fixture.retained.entries()[0].version.manifests()[0];
    let id = manifest.id();
    let pinned = CellRs46ManifestBindingV1::new(manifest, id, manifest.context()).unwrap();
    assert_eq!(pinned.manifest_id(), id);
    assert!(std::ptr::eq(pinned.manifest(), manifest));
    let mut wrong_id = id;
    wrong_id[0] ^= 1;
    assert!(CellRs46ManifestBindingV1::new(manifest, wrong_id, manifest.context()).is_err());
    let mut wrong_context = manifest.context().clone();
    wrong_context.tokenizer[0] ^= 1;
    assert!(CellRs46ManifestBindingV1::new(manifest, id, &wrong_context).is_err());
    assert!(pinned.chunk(manifest.chunks().len() as u32).is_err());
    assert!(pinned.chunk(u32::MAX).is_err());
}

#[test]
fn cached_chunk_bindings_preserve_every_original_crs1_wire_and_recovery() {
    let fixture = Fixture::new(false);
    for manifest in fixture.retained.entries()[0].version.manifests() {
        let pinned =
            CellRs46ManifestBindingV1::new(manifest, manifest.id(), manifest.context()).unwrap();
        for (index, original_chunk) in manifest.chunks().iter().enumerate() {
            let cached = pinned.chunk(index as u32).unwrap();
            let legacy = CellRs46ChunkBindingV1::from_pinned_manifest(
                manifest,
                manifest.id(),
                manifest.context(),
                index as u32,
            )
            .unwrap();
            assert_eq!(cached, legacy);
            let source = fixture.store.chunk(original_chunk.sha256).unwrap().unwrap();
            let encoded = cached.encode_chunk(&source).unwrap();
            assert_eq!(encoded, legacy.encode_chunk(&source).unwrap());
            for shard in &encoded {
                let wire = shard.encode();
                assert_eq!(&wire[..4], b"CRS1");
                assert_eq!(&wire[4..36], &manifest.id());
                assert_eq!(&wire[36..40], &(index as u32).to_be_bytes());
                assert_eq!(&wire[40..44], &original_chunk.size.to_be_bytes());
                assert_eq!(&wire[44..76], &original_chunk.sha256);
                assert_eq!(wire.len(), 81 + source.len().div_ceil(4));
            }
            assert_eq!(cached.recover_chunk(&encoded[2..]).unwrap(), source);
        }
    }
}

#[test]
fn cached_binding_accepts_maximum_manifest_and_last_legal_chunk_index() {
    let source = vec![0x35; 16_384];
    let chunk = CellChunkV1 {
        size: source.len() as u32,
        sha256: Sha256::digest(&source).into(),
    };
    // This test checks metadata binding and one chunk only. Its declared whole
    // payload hash is not presented as a completed 256 MiB recovery observation.
    let manifest = CellManifestV1::new(
        crate::cell::version::tests::context([9; 32]),
        16_384 * 16_384,
        [12; 32],
        16_384,
        vec![chunk; 16_384],
    )
    .unwrap();
    let pinned =
        CellRs46ManifestBindingV1::new(&manifest, manifest.id(), manifest.context()).unwrap();
    let first = pinned.chunk(0).unwrap();
    let last = pinned.chunk(16_383).unwrap();
    assert_eq!(first.manifest_id(), last.manifest_id());
    assert_eq!(last.chunk_index(), 16_383);
    assert_ne!(first, last);
    assert!(pinned.chunk(16_384).is_err());
    let codeword = last.encode_chunk(&source).unwrap();
    assert_eq!(last.recover_chunk(&codeword[2..]).unwrap(), source);
}
