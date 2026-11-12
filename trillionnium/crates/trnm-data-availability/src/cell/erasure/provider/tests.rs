use std::{
    io::{Seek, SeekFrom},
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, OptionalExtension};

use super::*;
use crate::cell::{
    CellCacheConfigV4, CellChunkV1, CellContextV1, CellManifestV1, CellRs46RepairBudgetV1,
    CellRs46ShardInputV1, MAX_CHUNK_BYTES,
};

mod observation;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

fn context() -> CellContextV1 {
    CellContextV1 {
        family: "provider-native-v1".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    }
}

fn cache(path: &Path) -> CellStoreV1 {
    CellStoreV1::open(
        path,
        CellCacheConfigV4 {
            max_database_bytes: 64 * 1024 * 1024,
            max_logical_bytes: 16 * 1024 * 1024,
            max_chunk_rows: 128,
            max_manifest_rows: 128,
        },
    )
    .unwrap()
}

struct Fixture {
    bytes: Vec<u8>,
    binding: CellRs46ChunkBindingV1,
    codeword: CellRs46CodewordV1,
    placement: CellRs46PlacementPolicyV1,
    wires: [Vec<u8>; 6],
}

impl Fixture {
    fn new() -> Self {
        let bytes = (0..200_003)
            .map(|n| ((n * 37 + 19) % 251) as u8)
            .collect::<Vec<_>>();
        let digest = Sha256::digest(&bytes).into();
        let manifest = CellManifestV1::new(
            context(),
            bytes.len() as u64,
            digest,
            MAX_CHUNK_BYTES,
            vec![CellChunkV1 {
                size: bytes.len() as u32,
                sha256: digest,
            }],
        )
        .unwrap();
        let binding =
            CellRs46ChunkBindingV1::from_pinned_manifest(&manifest, manifest.id(), &context(), 0)
                .unwrap();
        let codeword = CellRs46CodewordV1::from_verified_chunk(&binding, &bytes).unwrap();
        let wires = binding
            .encode_chunk(&bytes)
            .unwrap()
            .map(|shard| shard.encode());
        let placement = CellRs46PlacementPolicyV1 {
            codeword: codeword.id(),
            placements: std::array::from_fn(|slot| CellRs46ShardPlacementV1 {
                provider_id: [10 + slot as u8; 32],
                responsible_owner: [20 + slot as u8; 32],
                administrator: [30 + slot as u8; 32],
                failure_domain: [40 + slot as u8; 32],
                domain_evidence: [50 + slot as u8; 32],
                repair_owner: [60 + slot as u8; 32],
            }),
        };
        Self {
            bytes,
            binding,
            codeword,
            placement,
            wires,
        }
    }

    fn config(&self, slot: usize, maximum_obligations: u32) -> CellRs46ShardProviderConfigV1 {
        CellRs46ShardProviderConfigV1 {
            placement: self.placement.placements[slot].clone(),
            owner_generation: 7,
            capacity_bytes: 1024 * 1024,
            maximum_obligations,
        }
    }

    fn contract(&self, slot: usize, original: u8) -> CellRs46ShardContractV1 {
        let config = self.config(slot, 16);
        CellRs46ShardContractV1::from_verified_shard(
            CellRs46ShardOwnerV1 {
                original_operation: [original; 32],
                provider_store: config.store_id().unwrap(),
                owner_generation: config.owner_generation,
                funding_operation: [100 + slot as u8 + original; 32],
                codeword: self.codeword.id(),
                placement: self.placement.id().unwrap(),
                slot: slot as u8,
                context: context(),
                retain_from_height: 10,
                retain_until_height: 20,
                maximum_repair_bytes: self.wires[slot].len() as u64 * 2,
            },
            &self.binding,
            &self.codeword,
            &self.placement,
            &self.wires[slot],
        )
        .unwrap()
    }

    fn stage(&self, contract: &CellRs46ShardContractV1, target: &CellStoreV1) {
        CellRs46ShardProviderV1::cache_shard(
            contract,
            contract.operation(),
            &self.wires[usize::from(contract.owner().slot)],
            target,
            deadline(),
        )
        .unwrap();
    }
}

fn ledger(path: &Path, operation: CellDigestV1) -> Option<(u64, u64, u8)> {
    Connection::open_with_flags(
        path.join("retention.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
    .query_row(
        "SELECT initial_bytes,repair_bytes,status FROM obligations WHERE operation=?1",
        [operation.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .optional()
    .unwrap()
}

fn repair_row(path: &Path, operation: CellDigestV1) -> Option<(u64, bool)> {
    Connection::open_with_flags(
        path.join("retention.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
    .query_row(
        "SELECT amount,complete FROM repairs WHERE operation=?1",
        [operation.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .unwrap()
}

fn damage(path: &Path) {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path.join("payload.arena"))
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&[0xff]).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn csp1_roundtrip_keeps_independent_source_operation_context_and_slot_pins() {
    let fixture = Fixture::new();
    let contract = fixture.contract(0, 1);
    let wire = contract.encode();
    // Independent Python struct/hashlib/GF(256) reference, not Rust-generated.
    assert_eq!(wire.len(), 1824);
    assert_eq!(hex::encode(sha2::Sha512::digest(&wire)), "065ff6725e176fcee3018d53025f3a8a29fe3a13aba4cc3ac19d74693a6d385b29deec7d493a6995518a584ca838afa607eb0fb08f9c5a2c09b4984d87569792");
    assert_eq!(
        hex::encode(contract.operation()),
        "ef8a594dc368f319e3b840e399608efe9cbc29f91f5fb61f1ec95e7e83009ba8"
    );
    assert!(wire.len() <= MAX_CELL_RS46_PROVIDER_DESCRIPTOR_BYTES_V1);
    assert_eq!(
        CellRs46ShardContractV1::decode_pinned(&wire, &fixture.binding, contract.operation())
            .unwrap(),
        contract
    );
    assert!(CellRs46ShardContractV1::decode_pinned(&wire, &fixture.binding, [8; 32]).is_err());
    let mut tampered = wire.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(CellRs46ShardContractV1::decode_pinned(
        &tampered,
        &fixture.binding,
        contract.operation()
    )
    .is_err());
    let mut different = fixture.binding.clone();
    different.manifest[0] ^= 1;
    assert!(
        CellRs46ShardContractV1::decode_pinned(&wire, &different, contract.operation()).is_err()
    );
    assert!(CellRs46ShardContractV1::from_verified_shard(
        contract.owner().clone(),
        &fixture.binding,
        &fixture.codeword,
        &fixture.placement,
        &fixture.wires[1]
    )
    .is_err());
    let mut changed = contract.owner().clone();
    changed.context.runtime = [99; 32];
    let changed = CellRs46ShardContractV1::from_verified_shard(
        changed,
        &fixture.binding,
        &fixture.codeword,
        &fixture.placement,
        &fixture.wires[0],
    )
    .unwrap();
    assert_ne!(changed.operation(), contract.operation());
    assert!(changed.verify_pin(contract.operation()).is_err());
    assert_eq!(contract.manifest().context().runtime, context().runtime);
}

#[test]
fn provider_reopens_full_descriptor_and_reads_actual_bytes_without_cache() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let contract = fixture.contract(0, 1);
    let source = cache(&dir.path().join("source.sqlite"));
    fixture.stage(&contract, &source);
    let path = dir.path().join("provider");
    let config = fixture.config(0, 16);
    let mut provider = CellRs46ShardProviderV1::create(&path, config.clone()).unwrap();
    let (ack, observed) = provider
        .publish(&contract, contract.operation(), &source, deadline())
        .unwrap();
    assert_eq!(
        ack.initial_copy_bytes_committed,
        fixture.wires[0].len() as u64
    );
    assert_eq!(observed.shard().encode(), fixture.wires[0]);
    drop(provider);
    drop(source);
    fs::remove_file(dir.path().join("source.sqlite")).unwrap();
    let mut provider = CellRs46ShardProviderV1::open(&path, config.clone()).unwrap();
    assert_eq!(
        provider
            .descriptor(&fixture.binding, contract.operation(), deadline())
            .unwrap(),
        contract
    );
    let actual = provider
        .read(
            &fixture.binding,
            contract.operation(),
            deadline(),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(actual, observed);
    assert_eq!(actual.provider_store(), config.store_id().unwrap());
    assert_eq!(actual.codeword(), fixture.codeword.id());
    assert_eq!(actual.placement(), fixture.placement.id().unwrap());
    assert_eq!(
        ledger(&path, contract.operation()),
        Some((fixture.wires[0].len() as u64, 0, 1))
    );
    drop(provider);
    let mut changed = config;
    changed.owner_generation += 1;
    assert!(CellRs46ShardProviderV1::open(&path, changed).is_err());
}

#[test]
fn provider_lost_publish_result_reconciles_without_source_or_second_charge() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let contract = fixture.contract(0, 1);
    let source = cache(&dir.path().join("source.sqlite"));
    fixture.stage(&contract, &source);
    let path = dir.path().join("provider");
    let config = fixture.config(0, 16);
    let mut provider = CellRs46ShardProviderV1::create(&path, config.clone()).unwrap();
    let mut lost = false;
    let result = provider.publish_controlled(
        &contract,
        contract.operation(),
        &source,
        deadline(),
        &mut || {
            if ledger(&path, contract.operation()).is_some_and(|(_, _, status)| status == 1) {
                lost = true;
                return Err(CellErrorV1::Invalid("injected lost provider result"));
            }
            Ok(())
        },
    );
    assert!(result.is_err() && lost);
    let original = ledger(&path, contract.operation()).unwrap();
    drop(provider);
    drop(source);
    fs::remove_file(dir.path().join("source.sqlite")).unwrap();
    let mut provider = CellRs46ShardProviderV1::open(&path, config).unwrap();
    let (ack, actual) = provider
        .reconcile_acknowledgement(
            &fixture.binding,
            contract.operation(),
            deadline(),
            &mut || Ok(()),
        )
        .unwrap();
    assert!(ack.acknowledged);
    assert_eq!(actual.shard().encode(), fixture.wires[0]);
    assert_eq!(ledger(&path, contract.operation()), Some(original));
}

#[test]
fn provider_initial_unknown_never_redispatches_after_source_returns() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let contract = fixture.contract(0, 1);
    let cache_path = dir.path().join("source.sqlite");
    let source = cache(&cache_path);
    fixture.stage(&contract, &source);
    let path = dir.path().join("provider");
    let mut provider = CellRs46ShardProviderV1::create(&path, fixture.config(0, 16)).unwrap();
    let mut removed = false;
    let result = provider.publish_controlled(
        &contract,
        contract.operation(),
        &source,
        deadline(),
        &mut || {
            if !removed && ledger(&path, contract.operation()).is_some() {
                Connection::open(&cache_path)
                    .unwrap()
                    .execute("DELETE FROM cell_chunks_v1", [])
                    .unwrap();
                removed = true;
            }
            Ok(())
        },
    );
    assert!(result.is_err() && removed);
    let charged = (fixture.wires[0].len() as u64, 0, 0);
    assert_eq!(ledger(&path, contract.operation()), Some(charged));
    fixture.stage(&contract, &source);
    assert!(provider
        .publish(&contract, contract.operation(), &source, deadline())
        .is_err());
    assert!(provider
        .reconcile_acknowledgement(
            &fixture.binding,
            contract.operation(),
            deadline(),
            &mut || Ok(())
        )
        .is_err());
    assert_eq!(ledger(&path, contract.operation()), Some(charged));
    // An explicit different repair operation spends the original repair budget.
    let (ack, actual) = provider
        .repair(
            CellRs46ShardRepairRequestV1 {
                binding: &fixture.binding,
                operation: contract.operation(),
                repair_operation: [201; 32],
                cache: &source,
                deadline: deadline(),
            },
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(ack.repair_bytes_committed, fixture.wires[0].len() as u64);
    assert_eq!(actual.shard().encode(), fixture.wires[0]);
    assert_eq!(
        ledger(&path, contract.operation()),
        Some((charged.0, charged.0, 1))
    );
}

#[test]
fn provider_unknown_repair_keeps_debit_across_reopen_and_budget_exhaustion() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let contract = fixture.contract(0, 1);
    let source = cache(&dir.path().join("source.sqlite"));
    fixture.stage(&contract, &source);
    let path = dir.path().join("provider");
    let config = fixture.config(0, 16);
    let mut provider = CellRs46ShardProviderV1::create(&path, config.clone()).unwrap();
    provider
        .publish(&contract, contract.operation(), &source, deadline())
        .unwrap();
    damage(&path);
    let mut cancelled = false;
    let result = provider.repair(
        CellRs46ShardRepairRequestV1 {
            binding: &fixture.binding,
            operation: contract.operation(),
            repair_operation: [201; 32],
            cache: &source,
            deadline: deadline(),
        },
        &mut || {
            if repair_row(&path, [201; 32]).is_some() {
                cancelled = true;
                return Err(CellErrorV1::Invalid(
                    "injected repair cancellation after durable intent",
                ));
            }
            Ok(())
        },
    );
    assert!(result.is_err() && cancelled);
    let size = fixture.wires[0].len() as u64;
    assert_eq!(repair_row(&path, [201; 32]), Some((size, false)));
    assert_eq!(ledger(&path, contract.operation()), Some((size, size, 1)));
    drop(provider);
    let mut provider = CellRs46ShardProviderV1::open(&path, config).unwrap();
    assert!(provider
        .reconcile_repair(
            &fixture.binding,
            contract.operation(),
            [201; 32],
            deadline(),
            &mut || Ok(())
        )
        .is_err());
    assert!(provider
        .repair(
            CellRs46ShardRepairRequestV1 {
                binding: &fixture.binding,
                operation: contract.operation(),
                repair_operation: [201; 32],
                cache: &source,
                deadline: deadline(),
            },
            &mut || Ok(())
        )
        .is_err());
    assert_eq!(ledger(&path, contract.operation()), Some((size, size, 1)));
    let (ack, actual) = provider
        .repair(
            CellRs46ShardRepairRequestV1 {
                binding: &fixture.binding,
                operation: contract.operation(),
                repair_operation: [202; 32],
                cache: &source,
                deadline: deadline(),
            },
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(ack.repair_bytes_committed, 2 * size);
    assert_eq!(actual.shard().encode(), fixture.wires[0]);
    // Reconcile the older unknown intent against the repaired target, without
    // redoing either repair or subtracting the first operation's debit.
    provider
        .reconcile_repair(
            &fixture.binding,
            contract.operation(),
            [201; 32],
            deadline(),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(repair_row(&path, [201; 32]), Some((size, true)));
    damage(&path);
    assert!(provider
        .repair(
            CellRs46ShardRepairRequestV1 {
                binding: &fixture.binding,
                operation: contract.operation(),
                repair_operation: [203; 32],
                cache: &source,
                deadline: deadline(),
            },
            &mut || Ok(())
        )
        .is_err());
    assert_eq!(
        ledger(&path, contract.operation()),
        Some((size, 2 * size, 1))
    );
    assert!(provider
        .read(
            &fixture.binding,
            contract.operation(),
            deadline(),
            &mut || Ok(())
        )
        .is_err());
}

#[test]
fn provider_reconstructs_from_actual_four_arenas_and_repairs_actual_fifth_slot() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let source = cache(&dir.path().join("source.sqlite"));
    let contracts: Vec<_> = (0..6).map(|slot| fixture.contract(slot, 1)).collect();
    let mut providers = Vec::new();
    for (slot, contract) in contracts.iter().enumerate() {
        fixture.stage(contract, &source);
        let path = dir.path().join(format!("provider-{slot}"));
        let mut provider =
            CellRs46ShardProviderV1::create(&path, fixture.config(slot, 16)).unwrap();
        provider
            .publish(contract, contract.operation(), &source, deadline())
            .unwrap();
        providers.push(provider);
    }
    drop(source);
    fs::remove_file(dir.path().join("source.sqlite")).unwrap();
    damage(&dir.path().join("provider-4"));
    assert!(providers[4]
        .read(
            &fixture.binding,
            contracts[4].operation(),
            deadline(),
            &mut || Ok(())
        )
        .is_err());
    let wires: Vec<_> = (0..4)
        .map(|slot| {
            providers[slot]
                .read(
                    &fixture.binding,
                    contracts[slot].operation(),
                    deadline(),
                    &mut || Ok(()),
                )
                .unwrap()
                .shard()
                .encode()
        })
        .collect();
    let inputs: Vec<_> = wires
        .iter()
        .enumerate()
        .map(|(slot, wire)| CellRs46ShardInputV1 {
            index: slot as u8,
            wire,
        })
        .collect();
    let end = deadline();
    let mut budget = CellRs46RepairBudgetV1::new(
        end,
        1,
        wires.iter().map(|wire| wire.len() as u64).sum(),
        fixture.bytes.len() as u64
            + fixture
                .wires
                .iter()
                .map(|wire| wire.len() as u64)
                .sum::<u64>(),
    );
    let recovered = fixture
        .codeword
        .repair_chunk(
            &fixture.binding,
            fixture.codeword.id(),
            &inputs,
            &mut budget,
        )
        .unwrap();
    assert_eq!(recovered.source(), fixture.bytes);
    let repaired = recovered
        .repaired_shards()
        .iter()
        .find(|shard| shard.index() == 4)
        .unwrap()
        .encode();
    assert_eq!(repaired, fixture.wires[4]);
    let repair_cache = cache(&dir.path().join("repair.sqlite"));
    CellRs46ShardProviderV1::cache_shard(
        &contracts[4],
        contracts[4].operation(),
        &repaired,
        &repair_cache,
        end,
    )
    .unwrap();
    let (ack, observed) = providers[4]
        .repair(
            CellRs46ShardRepairRequestV1 {
                binding: &fixture.binding,
                operation: contracts[4].operation(),
                repair_operation: [201; 32],
                cache: &repair_cache,
                deadline: end,
            },
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(ack.repair_bytes_committed, repaired.len() as u64);
    assert_eq!(observed.shard().encode(), repaired);
    assert_eq!(budget.usage().attempts_committed, 1);
    // These six local namespaces establish byte operations only, not six
    // independent machines or an authenticated WAN placement observation.
}

#[test]
fn provider_metadata_limit_rejects_before_creating_new_file_and_keeps_terminal_history() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let first = fixture.contract(0, 1);
    let second = fixture.contract(0, 2);
    let source = cache(&dir.path().join("source.sqlite"));
    fixture.stage(&first, &source);
    fixture.stage(&second, &source);
    let path = dir.path().join("provider");
    let mut provider = CellRs46ShardProviderV1::create(&path, fixture.config(0, 1)).unwrap();
    provider
        .publish(&first, first.operation(), &source, deadline())
        .unwrap();
    assert!(provider
        .publish(&second, second.operation(), &source, deadline())
        .is_err());
    assert_eq!(fs::read_dir(path.join(DESCRIPTORS)).unwrap().count(), 1);
    assert!(ledger(&path, second.operation()).is_none());
    assert!(provider
        .retire(
            &fixture.binding,
            first.operation(),
            19,
            deadline(),
            &mut || Ok(())
        )
        .is_err());
    // Expired damaged payload must not require a successful repair before
    // retirement; immutable metadata and the original height still bind it.
    damage(&path);
    assert!(provider
        .read(&fixture.binding, first.operation(), deadline(), &mut || Ok(
            ()
        ))
        .is_err());
    assert!(
        provider
            .retire(
                &fixture.binding,
                first.operation(),
                20,
                deadline(),
                &mut || Ok(())
            )
            .unwrap()
            .retired
    );
    assert!(provider
        .read(&fixture.binding, first.operation(), deadline(), &mut || Ok(
            ()
        ))
        .is_err());
    assert!(provider
        .publish(&second, second.operation(), &source, deadline())
        .is_err());
    assert_eq!(fs::read_dir(path.join(DESCRIPTORS)).unwrap().count(), 1);
    assert_eq!(ledger(&path, first.operation()).unwrap().2, 2);
}

#[test]
fn provider_descriptor_fault_or_wrong_owner_never_returns_existing_arena_success() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let contract = fixture.contract(0, 1);
    let source = cache(&dir.path().join("source.sqlite"));
    fixture.stage(&contract, &source);
    let path = dir.path().join("provider");
    let mut provider = CellRs46ShardProviderV1::create(&path, fixture.config(0, 16)).unwrap();
    let mut owner = contract.owner().clone();
    owner.owner_generation += 1;
    let wrong = CellRs46ShardContractV1::from_verified_shard(
        owner,
        &fixture.binding,
        &fixture.codeword,
        &fixture.placement,
        &fixture.wires[0],
    )
    .unwrap();
    assert!(provider
        .publish(&wrong, wrong.operation(), &source, deadline())
        .is_err());
    assert_eq!(fs::read_dir(path.join(DESCRIPTORS)).unwrap().count(), 0);
    provider
        .publish(&contract, contract.operation(), &source, deadline())
        .unwrap();
    let descriptor = path
        .join(DESCRIPTORS)
        .join(hex::encode(contract.operation()));
    let before = ledger(&path, contract.operation());
    fs::write(&descriptor, b"CSP1 partial interrupted metadata").unwrap();
    assert!(provider
        .read(
            &fixture.binding,
            contract.operation(),
            deadline(),
            &mut || Ok(())
        )
        .is_err());
    assert!(provider
        .publish(&contract, contract.operation(), &source, deadline())
        .is_err());
    assert_eq!(
        fs::read(&descriptor).unwrap(),
        b"CSP1 partial interrupted metadata"
    );
    assert_eq!(ledger(&path, contract.operation()), before);
}

#[test]
fn provider_expired_deadline_and_immediate_cancel_create_no_slot() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let contract = fixture.contract(0, 1);
    let source = cache(&dir.path().join("source.sqlite"));
    fixture.stage(&contract, &source);
    let path = dir.path().join("provider");
    let mut provider = CellRs46ShardProviderV1::create(&path, fixture.config(0, 16)).unwrap();
    assert!(provider
        .publish(
            &contract,
            contract.operation(),
            &source,
            Instant::now() - Duration::from_secs(1)
        )
        .is_err());
    assert!(provider
        .publish_controlled(
            &contract,
            contract.operation(),
            &source,
            deadline(),
            &mut || Err(CellErrorV1::Invalid("cancelled before provider admission"))
        )
        .is_err());
    assert_eq!(fs::read_dir(path.join(DESCRIPTORS)).unwrap().count(), 0);
    assert!(ledger(&path, contract.operation()).is_none());
}
