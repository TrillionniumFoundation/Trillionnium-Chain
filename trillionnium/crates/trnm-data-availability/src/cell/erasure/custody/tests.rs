use std::time::Duration;

use super::*;
use crate::cell::{
    digest_hex, version::tests::owner, version_content::tests::captured, CellCacheConfigV4,
    CellChunkV1, CellContextV1, CellFileRoleV1, CellManifestV1, CellVersionContentV2,
    CellVersionLoaderContextV1, MAX_CHUNK_BYTES,
};

fn context() -> CellContextV1 {
    CellContextV1 {
        family: "rs46-test-v1".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    }
}

fn binding(bytes: &[u8], context: CellContextV1) -> CellRs46ChunkBindingV1 {
    let digest = Sha256::digest(bytes).into();
    let manifest = CellManifestV1::new(
        context.clone(),
        bytes.len() as u64,
        digest,
        MAX_CHUNK_BYTES,
        vec![CellChunkV1 {
            size: bytes.len() as u32,
            sha256: digest,
        }],
    )
    .unwrap();
    CellRs46ChunkBindingV1::from_pinned_manifest(&manifest, manifest.id(), &context, 0).unwrap()
}

struct Fixture {
    source: Vec<u8>,
    binding: CellRs46ChunkBindingV1,
    codeword: CellRs46CodewordV1,
    wires: [Vec<u8>; 6],
}

impl Fixture {
    fn new(source: &[u8]) -> Self {
        let binding = binding(source, context());
        Self::with_binding(source, binding)
    }

    fn with_binding(source: &[u8], binding: CellRs46ChunkBindingV1) -> Self {
        let codeword = CellRs46CodewordV1::from_verified_chunk(&binding, source).unwrap();
        let wires = binding
            .encode_chunk(source)
            .unwrap()
            .map(|shard| shard.encode());
        Self {
            source: source.to_vec(),
            binding,
            codeword,
            wires,
        }
    }

    fn costs(&self) -> (u64, u64) {
        let input = self.wires.iter().map(|wire| wire.len() as u64).sum();
        (input, input + self.source.len() as u64)
    }

    fn budget(&self) -> CellRs46RepairBudgetV1 {
        let (input, output) = self.costs();
        CellRs46RepairBudgetV1::new(Instant::now() + Duration::from_secs(20), 1, input, output)
    }

    fn repair(
        &self,
        inputs: &[CellRs46ShardInputV1<'_>],
        budget: &mut CellRs46RepairBudgetV1,
    ) -> CellResultV1<CellRs46RepairV1> {
        self.codeword
            .repair_chunk(&self.binding, self.codeword.id(), inputs, budget)
    }

    fn assert_repaired(&self, repair: &CellRs46RepairV1, slots: &[u8]) {
        assert_eq!(repair.codeword(), self.codeword.id());
        assert_eq!(repair.source(), self.source);
        assert_eq!(
            repair
                .repaired_shards()
                .iter()
                .map(CellRs46ShardV1::index)
                .collect::<Vec<_>>(),
            slots,
        );
        for shard in repair.repaired_shards() {
            assert_eq!(shard.encode(), self.wires[usize::from(shard.index())]);
            assert_eq!(
                shard.id(),
                self.codeword.shard_ids()[usize::from(shard.index())]
            );
        }
    }
}

fn inputs(wires: &[Vec<u8>; 6]) -> [CellRs46ShardInputV1<'_>; 6] {
    std::array::from_fn(|index| CellRs46ShardInputV1 {
        index: index as u8,
        wire: &wires[index],
    })
}

fn placement(codeword: CellDigestV1) -> CellRs46PlacementPolicyV1 {
    CellRs46PlacementPolicyV1 {
        codeword,
        placements: std::array::from_fn(|index| CellRs46ShardPlacementV1 {
            provider_id: [10 + index as u8; 32],
            responsible_owner: [20 + index as u8; 32],
            administrator: [30 + index as u8; 32],
            failure_domain: [40 + index as u8; 32],
            domain_evidence: [50 + index as u8; 32],
            repair_owner: [60 + index as u8; 32],
        }),
    }
}

#[test]
fn crc1_codeword_and_placement_match_independent_exact_vectors() {
    // Python struct/hashlib construction using the independent RS46 vector.
    let fixture = Fixture::new(&[1, 2, 3, 4]);
    assert_eq!(
        hex::encode(fixture.codeword.encode()),
        concat!(
            "43524331a58a797159f1411bd6b08afd69729812647137897c0ae9aaf30c7c773d5c8496",
            "00000000000000049f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
            "c72deb567b2524276ff931312d41f45c742515156615f10ba08a3c303969e543a",
            "2c2e41cdd95e7fac18b338ccd929516afb7f7e3558e022db491f315541d17ea83",
            "066e2c4c13051515d275fee65b0f5c528fb90e3d24bcf4650b0e18157c3491f4",
            "ec978d9234e1086043cc1e14b201b4c1c347270b741fffb41b7b1c4fc9f455",
            "0524d4b2be21cb4fb0fc6b7355da7aaabca5cb55b97e66ec91c6226ed1707970",
            "6e41bdf16cd70d39c849ba22ed26150f99e565a53dbe74d0280530e1aaf3c29f",
        ),
    );
    assert_eq!(
        digest_hex(fixture.codeword.id()),
        "52c0442b51c9405c9f151218d7c17bd4c71ba78cc8d8ce19d8158c98cf15b4f0",
    );
    assert_eq!(
        CellRs46CodewordV1::decode_pinned(
            &fixture.codeword.encode(),
            &fixture.binding,
            fixture.codeword.id(),
        )
        .unwrap(),
        fixture.codeword,
    );
    let policy = placement(fixture.codeword.id());
    assert_eq!(
        digest_hex(policy.id().unwrap()),
        "6b1b65757883bdf00357cc4d4cc5a22f32b3889624526af4dc46eeac0b341ce9",
    );
    policy
        .verify_pin(policy.id().unwrap(), fixture.codeword.id())
        .unwrap();
}

#[test]
fn codeword_creation_requires_original_verified_payload() {
    let fixture = Fixture::new(b"exact source bytes");
    let mut damaged = fixture.source.clone();
    damaged[0] ^= 1;
    assert!(CellRs46CodewordV1::from_verified_chunk(&fixture.binding, &damaged).is_err());
    assert!(CellRs46CodewordV1::from_verified_chunk(&fixture.binding, &[]).is_err());
    for (index, shard) in fixture
        .binding
        .encode_chunk(&fixture.source)
        .unwrap()
        .iter()
        .enumerate()
    {
        assert_eq!(fixture.codeword.shard_ids()[index], shard.id());
    }
}

#[test]
fn cold_codeword_decode_requires_exact_wire_and_both_independent_pins() {
    let fixture = Fixture::new(b"pinned cold recovery");
    let wire = fixture.codeword.encode();
    for end in 0..wire.len() {
        assert!(CellRs46CodewordV1::decode_pinned(
            &wire[..end],
            &fixture.binding,
            fixture.codeword.id(),
        )
        .is_err());
    }
    let mut extended = wire.to_vec();
    extended.push(0);
    assert!(
        CellRs46CodewordV1::decode_pinned(&extended, &fixture.binding, fixture.codeword.id(),)
            .is_err()
    );
    for offset in 0..wire.len() {
        let mut changed = wire;
        changed[offset] ^= 1;
        assert!(
            CellRs46CodewordV1::decode_pinned(&changed, &fixture.binding, fixture.codeword.id(),)
                .is_err(),
            "offset {offset}"
        );
        if offset < 76 {
            // A peer's replacement descriptor digest is no source authority.
            assert!(
                CellRs46CodewordV1::decode_pinned(
                    &changed,
                    &fixture.binding,
                    codeword_id(&changed),
                )
                .is_err(),
                "self-hashed source change at {offset}"
            );
        }
    }
    let mut changed_context = context();
    changed_context.runtime = [99; 32];
    let foreign = binding(&fixture.source, changed_context);
    assert!(CellRs46CodewordV1::decode_pinned(&wire, &foreign, fixture.codeword.id(),).is_err());
    let mut zero_id = wire;
    zero_id[76..108].fill(0);
    assert!(
        CellRs46CodewordV1::decode_pinned(&zero_id, &fixture.binding, codeword_id(&zero_id),)
            .is_err()
    );
    let mut duplicate_id = wire;
    duplicate_id[108..140].copy_from_slice(&wire[76..108]);
    assert!(CellRs46CodewordV1::decode_pinned(
        &duplicate_id,
        &fixture.binding,
        codeword_id(&duplicate_id),
    )
    .is_err());
}

#[test]
fn every_two_damaged_shards_are_screened_and_rebuilt_from_four_committed_shards() {
    let source: Vec<_> = (0..16_401).map(|i| (i % 251) as u8).collect();
    let fixture = Fixture::new(&source);
    let mut combinations = 0;
    for first in 0..5 {
        for second in first + 1..6 {
            let mut wires = fixture.wires.clone();
            wires[first][SHARD_HEADER_BYTES] ^= 1;
            wires[second][SHARD_HEADER_BYTES] ^= 2;
            let mut budget = fixture.budget();
            let repair = fixture.repair(&inputs(&wires), &mut budget).unwrap();
            let bad = [first as u8, second as u8];
            fixture.assert_repaired(&repair, &bad);
            assert_eq!(repair.rejected_slots(), bad);
            assert!(repair.missing_slots().is_empty());
            assert_eq!(repair.verified_slots().len(), 4);
            assert_eq!(repair.usage_before(), CellRs46RepairUsageV1::default());
            assert_eq!(repair.usage_after(), budget.usage());
            assert_eq!(budget.usage().attempts_committed, 1);
            assert_eq!(budget.usage().input_bytes_committed, fixture.costs().0);
            assert_eq!(
                budget.usage().reconstruction_bytes_committed,
                fixture.costs().1
            );
            combinations += 1;
        }
    }
    assert_eq!(combinations, 15);
}

#[test]
fn every_four_committed_shard_subset_rebuilds_only_the_missing_slots() {
    let fixture = Fixture::new(b"cold repair with a partial final data shard");
    let all = inputs(&fixture.wires);
    let mut combinations = 0;
    for first in 0..5 {
        for second in first + 1..6 {
            let missing = [first as u8, second as u8];
            let subset: Vec<_> = all
                .iter()
                .filter(|input| !missing.contains(&input.index))
                .copied()
                .collect();
            let mut budget = fixture.budget();
            let repair = fixture.repair(&subset, &mut budget).unwrap();
            fixture.assert_repaired(&repair, &missing);
            assert_eq!(repair.missing_slots(), missing);
            assert!(repair.rejected_slots().is_empty());
            assert_eq!(
                repair.verified_slots(),
                subset.iter().map(|input| input.index).collect::<Vec<_>>()
            );
            assert_eq!(
                budget.usage().input_bytes_committed,
                4 * fixture.wires[0].len() as u64
            );
            combinations += 1;
        }
    }
    assert_eq!(combinations, 15);
}

#[test]
fn a_corrupt_extra_shard_is_replaced_and_is_never_reported_as_verified() {
    let fixture = Fixture::new(b"the old codec still rejects unfiltered extra corruption");
    let mut wires = fixture.wires.clone();
    wires[5][SHARD_HEADER_BYTES] ^= 1;
    let decoded: Vec<_> = wires
        .iter()
        .map(|wire| CellRs46ShardV1::decode(wire).unwrap())
        .collect();
    assert!(fixture.binding.recover_chunk(&decoded).is_err());
    let repair = fixture
        .repair(&inputs(&wires), &mut fixture.budget())
        .unwrap();
    fixture.assert_repaired(&repair, &[5]);
    assert!(!repair.cache_readback_observed());
    assert_eq!(repair.verified_slots(), &[0, 1, 2, 3, 4]);
    assert_eq!(repair.rejected_slots(), &[5]);
    let healthy = fixture
        .repair(&inputs(&fixture.wires), &mut fixture.budget())
        .unwrap();
    fixture.assert_repaired(&healthy, &[]);
    assert_eq!(healthy.verified_slots(), &[0, 1, 2, 3, 4, 5]);
}

#[test]
fn malformed_headers_and_wrong_slot_readbacks_never_count_as_committed_shards() {
    let fixture = Fixture::new(b"request slots do not come from an untrusted peer header");
    for case in 0..5 {
        let mut wires = fixture.wires.clone();
        match case {
            0 => wires[0].clear(),
            1 => {
                wires[0].pop();
            }
            2 => wires[0][0] ^= 1,
            3 => wires[0][76] = 5,
            _ => wires[0][40..44].fill(0),
        }
        // A valid shard from another slot is still a rejected response here.
        wires[5] = fixture.wires[0].clone();
        let repair = fixture
            .repair(&inputs(&wires), &mut fixture.budget())
            .unwrap();
        fixture.assert_repaired(&repair, &[0, 5]);
        assert_eq!(repair.rejected_slots(), &[0, 5]);
        assert_eq!(repair.verified_slots(), &[1, 2, 3, 4]);
    }
}

#[test]
fn three_damaged_shards_refuse_and_keep_the_original_attempt_debit() {
    let fixture = Fixture::new(b"three losses exceed RS46 repair capacity");
    let mut wires = fixture.wires.clone();
    for wire in &mut wires[..3] {
        wire[SHARD_HEADER_BYTES] ^= 1;
    }
    let mut budget = fixture.budget();
    assert!(matches!(
        fixture.repair(&inputs(&wires), &mut budget),
        Err(CellErrorV1::Invalid(
            "RS46 repair requires four committed shards"
        )),
    ));
    let spent = budget.usage();
    assert_eq!(spent.attempts_committed, 1);
    assert_eq!(spent.input_bytes_committed, fixture.costs().0);
    assert_eq!(spent.reconstruction_bytes_committed, fixture.costs().1);
    assert!(matches!(
        fixture.repair(&inputs(&fixture.wires), &mut budget),
        Err(CellErrorV1::Invalid("RS46 repair budget exhausted")),
    ));
    assert_eq!(budget.usage(), spent);
}

#[test]
fn repair_refuses_noncanonical_slots_wrong_pins_and_unbounded_wire_before_admission() {
    let fixture = Fixture::new(b"bounded admission");
    let all = inputs(&fixture.wires);
    let mut budget = fixture.budget();
    for count in 0..4 {
        assert!(fixture.repair(&all[..count], &mut budget).is_err());
    }
    for bad in [
        vec![all[0], all[1], all[2], all[2]],
        vec![all[3], all[2], all[1], all[0]],
        vec![all[0]; 7],
        vec![
            all[0],
            all[1],
            all[2],
            CellRs46ShardInputV1 {
                index: 6,
                wire: all[3].wire,
            },
        ],
    ] {
        assert!(fixture.repair(&bad, &mut budget).is_err());
    }
    let oversized = vec![0; MAX_CELL_RS46_SHARD_WIRE_BYTES_V1 + 1];
    let mut too_large = all;
    too_large[0].wire = &oversized;
    assert!(fixture.repair(&too_large, &mut budget).is_err());
    assert!(fixture
        .codeword
        .repair_chunk(&fixture.binding, [99; 32], &all, &mut budget)
        .is_err());
    let mut foreign_context = context();
    foreign_context.parent = [99; 32];
    let foreign = binding(&fixture.source, foreign_context);
    assert!(fixture
        .codeword
        .repair_chunk(&foreign, fixture.codeword.id(), &all, &mut budget)
        .is_err());
    assert_eq!(budget.usage(), CellRs46RepairUsageV1::default());
}

#[test]
fn repaired_codeword_checks_even_the_two_commitments_not_used_for_decoding() {
    let fixture = Fixture::new(b"four correct shards cannot endorse two false replacement IDs");
    let mut wire = fixture.codeword.encode();
    wire[76 + 4 * 32] ^= 1;
    let changed_id = codeword_id(&wire);
    // Even an independently pinned malformed catalogue cannot fabricate repair.
    let changed = CellRs46CodewordV1::decode_pinned(&wire, &fixture.binding, changed_id).unwrap();
    let mut budget = fixture.budget();
    assert!(matches!(
        changed.repair_chunk(
            &fixture.binding,
            changed_id,
            &inputs(&fixture.wires)[..4],
            &mut budget
        ),
        Err(CellErrorV1::Invalid("RS46 repaired codeword pin")),
    ));
    assert_eq!(budget.usage().attempts_committed, 1);
}

#[test]
fn a_rebound_bad_shard_digest_still_cannot_replace_original_chunk_verification() {
    let fixture = Fixture::new(b"the original TCM1 source digest remains authoritative");
    let mut wires = fixture.wires.clone();
    wires[0][SHARD_HEADER_BYTES] ^= 1;
    let bad = CellRs46ShardV1::decode(&wires[0]).unwrap();
    let mut descriptor = fixture.codeword.encode();
    descriptor[76..108].copy_from_slice(&bad.id());
    let changed_id = codeword_id(&descriptor);
    let changed =
        CellRs46CodewordV1::decode_pinned(&descriptor, &fixture.binding, changed_id).unwrap();
    let mut budget = fixture.budget();
    assert!(changed
        .repair_chunk(
            &fixture.binding,
            changed_id,
            &inputs(&wires)[..4],
            &mut budget
        )
        .is_err());
    assert_eq!(budget.usage().attempts_committed, 1);
}

#[test]
fn exact_attempt_input_and_reconstruction_caps_apply_without_partial_reservation() {
    let fixture = Fixture::new(b"exact full potential work reservation");
    let (input, output) = fixture.costs();
    for (attempts, input_limit, output_limit) in [
        (0, input, output),
        (1, input - 1, output),
        (1, input, output - 1),
    ] {
        let mut budget = CellRs46RepairBudgetV1::new(
            Instant::now() + Duration::from_secs(20),
            attempts,
            input_limit,
            output_limit,
        );
        assert!(matches!(
            fixture.repair(&inputs(&fixture.wires), &mut budget),
            Err(CellErrorV1::Invalid("RS46 repair budget exhausted")),
        ));
        assert_eq!(budget.usage(), CellRs46RepairUsageV1::default());
    }
    let mut budget = fixture.budget();
    let repair = fixture
        .repair(&inputs(&fixture.wires), &mut budget)
        .unwrap();
    assert_eq!(
        repair.usage_after(),
        CellRs46RepairUsageV1 {
            attempts_committed: 1,
            input_bytes_committed: input,
            reconstruction_bytes_committed: output,
            cache_bytes_committed: 0,
        }
    );
}

#[test]
fn retry_preserves_failure_debits_and_original_deadline() {
    let fixture = Fixture::new(b"a retry reuses the original reservation");
    let (input, output) = fixture.costs();
    let mut budget = CellRs46RepairBudgetV1::new(
        Instant::now() + Duration::from_secs(20),
        3,
        3 * input,
        3 * output,
    );
    let mut damaged = fixture.wires.clone();
    for wire in &mut damaged[..3] {
        wire[SHARD_HEADER_BYTES] ^= 1;
    }
    assert!(fixture.repair(&inputs(&damaged), &mut budget).is_err());
    let first = budget.usage();
    let repaired = fixture
        .repair(&inputs(&fixture.wires), &mut budget)
        .unwrap();
    assert_eq!(repaired.usage_before(), first);
    assert_eq!(repaired.usage_after().attempts_committed, 2);
    assert_eq!(repaired.usage_after().input_bytes_committed, 2 * input);
    assert_eq!(
        repaired.usage_after().reconstruction_bytes_committed,
        2 * output
    );
    // Deterministic expired-deadline control; no wall-clock performance claim.
    budget.deadline = Instant::now();
    assert!(matches!(
        fixture.repair(&inputs(&fixture.wires), &mut budget),
        Err(CellErrorV1::Invalid("RS46 repair original deadline")),
    ));
    assert_eq!(budget.usage(), repaired.usage_after());
    let mut expired = CellRs46RepairBudgetV1::new(Instant::now(), 1, input, output);
    assert!(fixture
        .repair(&inputs(&fixture.wires), &mut expired)
        .is_err());
    assert_eq!(expired.usage(), CellRs46RepairUsageV1::default());
}

#[test]
fn maximum_chunk_repairs_two_losses_with_exact_header_inclusive_byte_debits() {
    let source: Vec<_> = (0..MAX_CHUNK_BYTES).map(|i| (i % 251) as u8).collect();
    let fixture = Fixture::new(&source);
    let mut wires = fixture.wires.clone();
    wires[0][SHARD_HEADER_BYTES] ^= 1;
    wires[4][SHARD_HEADER_BYTES] ^= 1;
    let mut budget = fixture.budget();
    let repair = fixture.repair(&inputs(&wires), &mut budget).unwrap();
    fixture.assert_repaired(&repair, &[0, 4]);
    assert_eq!(repair.rejected_slots(), &[0, 4]);
    assert_eq!(
        budget.usage().input_bytes_committed,
        6 * MAX_CELL_RS46_SHARD_WIRE_BYTES_V1 as u64
    );
    assert_eq!(
        budget.usage().reconstruction_bytes_committed,
        fixture.costs().1
    );
}

#[test]
fn placement_rejects_repeated_provider_owner_administrator_or_failure_domain() {
    let fixture = Fixture::new(b"six declared domains");
    let policy = placement(fixture.codeword.id());
    for field in 0..4 {
        let mut repeated = policy.clone();
        let first = repeated.placements[0].clone();
        match field {
            0 => repeated.placements[1].provider_id = first.provider_id,
            1 => repeated.placements[1].responsible_owner = first.responsible_owner,
            2 => repeated.placements[1].administrator = first.administrator,
            _ => repeated.placements[1].failure_domain = first.failure_domain,
        }
        assert!(matches!(
            repeated.id(),
            Err(CellErrorV1::Invalid(
                "RS46 placement duplicate provider/owner/domain"
            ))
        ));
    }
    for field in 0..6 {
        let mut zero = policy.clone();
        let first = &mut zero.placements[0];
        match field {
            0 => first.provider_id = [0; 32],
            1 => first.responsible_owner = [0; 32],
            2 => first.administrator = [0; 32],
            3 => first.failure_domain = [0; 32],
            4 => first.domain_evidence = [0; 32],
            _ => first.repair_owner = [0; 32],
        }
        assert!(matches!(
            zero.id(),
            Err(CellErrorV1::Invalid("RS46 placement identity"))
        ));
    }
    let mut zero = policy;
    zero.codeword = [0; 32];
    assert!(zero.id().is_err());
}

#[test]
fn placement_pin_commits_every_slot_identity_evidence_and_repair_owner() {
    let fixture = Fixture::new(b"a changed target requires an independently approved policy");
    let policy = placement(fixture.codeword.id());
    let original = policy.id().unwrap();
    for index in 0..6 {
        for field in 0..6 {
            let mut changed = policy.clone();
            let entry = &mut changed.placements[index];
            match field {
                0 => entry.provider_id[0] ^= 0x80,
                1 => entry.responsible_owner[0] ^= 0x80,
                2 => entry.administrator[0] ^= 0x80,
                3 => entry.failure_domain[0] ^= 0x80,
                4 => entry.domain_evidence[0] ^= 0x80,
                _ => entry.repair_owner[0] ^= 0x80,
            }
            assert_ne!(changed.id().unwrap(), original);
            assert!(changed.verify_pin(original, fixture.codeword.id()).is_err());
        }
    }
    let mut reordered = policy.clone();
    reordered.placements.swap(0, 1);
    assert!(reordered
        .verify_pin(original, fixture.codeword.id())
        .is_err());
    let mut foreign = policy;
    foreign.codeword[0] ^= 1;
    assert!(foreign
        .verify_pin(foreign.id().unwrap(), fixture.codeword.id())
        .is_err());
}

fn cache_fixture() -> (CellVersionContentV2, Fixture) {
    let (_directory, source_store, content) = captured();
    let manifest = &content.version().manifests()[0];
    let binding = CellRs46ChunkBindingV1::from_pinned_manifest(
        manifest,
        manifest.id(),
        manifest.context(),
        0,
    )
    .unwrap();
    let source = source_store
        .chunk(manifest.chunks()[0].sha256)
        .unwrap()
        .unwrap();
    let fixture = Fixture::with_binding(&source, binding);
    // The original database and its directory are dropped before repair.
    (content, fixture)
}

fn pinned_content(content: &CellVersionContentV2) -> PinnedCellVersionContentV2<'_> {
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    content
        .pin_for_owner(
            &CellVersionLoaderContextV1 {
                commitment: content.version().commitment(),
                model: &model,
                environment: &environment,
            },
            content.commitment(),
        )
        .unwrap()
}

fn cache_config(max_logical_bytes: u64) -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 4 * 1024 * 1024,
        max_logical_bytes,
        max_chunk_rows: 8,
        max_manifest_rows: 8,
    }
}

fn cache_budget(fixture: &Fixture, attempts: u32, cache_bytes: u64) -> CellRs46RepairBudgetV1 {
    let (input, reconstruction) = fixture.costs();
    CellRs46RepairBudgetV1::new_with_cache(
        Instant::now() + Duration::from_secs(20),
        attempts,
        u64::from(attempts) * input,
        u64::from(attempts) * reconstruction,
        cache_bytes,
    )
}

#[test]
fn two_bad_shards_commit_strongly_verified_chunk_and_survive_cache_reopen() {
    let (content, fixture) = cache_fixture();
    let pinned = pinned_content(&content);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("repaired.sqlite");
    let store = CellStoreV1::open(&path, cache_config(1024 * 1024)).unwrap();
    let mut wires = fixture.wires.clone();
    wires[0][SHARD_HEADER_BYTES] ^= 1;
    wires[5][SHARD_HEADER_BYTES] ^= 1;
    let cache_bytes = 2 * fixture.source.len() as u64;
    let mut budget = cache_budget(&fixture, 1, cache_bytes);
    let repair = fixture
        .codeword
        .repair_chunk_to_cache(
            &fixture.binding,
            fixture.codeword.id(),
            &inputs(&wires),
            CellRs46CacheTargetV1 {
                store: &store,
                content: &pinned,
            },
            &mut budget,
        )
        .unwrap();
    fixture.assert_repaired(&repair, &[0, 5]);
    assert!(repair.cache_readback_observed());
    assert_eq!(repair.usage_after(), budget.usage());
    assert_eq!(budget.usage().cache_bytes_committed, cache_bytes);
    assert_eq!(store.cache_usage().unwrap().chunk_rows, 1);
    assert_eq!(
        store.cache_usage().unwrap().logical_bytes,
        fixture.source.len() as u64 + 32
    );
    drop(store);
    let reopened = CellStoreV1::open_read_only(&path).unwrap();
    let actual = reopened
        .chunk(fixture.binding.chunk.sha256)
        .unwrap()
        .unwrap();
    assert_eq!(actual, fixture.source);
    pinned
        .verify_chunk(fixture.binding.manifest_id(), 0, &actual)
        .unwrap();
}

#[test]
fn strong_content_mismatch_refuses_repair_cache_write_before_any_row() {
    let (content, fixture) = cache_fixture();
    let mut wire = content.encode();
    let metadata_bytes = u32::from_be_bytes(wire[4..8].try_into().unwrap()) as usize;
    // Keep every legacy manifest/chunk ID but change the first SHA-512 chunk pin.
    let first_chunk_digest = 8 + metadata_bytes + 2 + 32 + 64 + 4;
    wire[first_chunk_digest] ^= 1;
    let changed = CellVersionContentV2::decode(&wire).unwrap();
    assert_eq!(changed.version(), content.version());
    let pinned = pinned_content(&changed);
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(
        &directory.path().join("target.sqlite"),
        cache_config(1024 * 1024),
    )
    .unwrap();
    let before = store.cache_usage().unwrap();
    let cache_bytes = 2 * fixture.source.len() as u64;
    let mut budget = cache_budget(&fixture, 1, cache_bytes);
    assert!(matches!(
        fixture.codeword.repair_chunk_to_cache(
            &fixture.binding,
            fixture.codeword.id(),
            &inputs(&fixture.wires),
            CellRs46CacheTargetV1 {
                store: &store,
                content: &pinned
            },
            &mut budget,
        ),
        Err(CellErrorV1::Invalid("content SHA512 chunk")),
    ));
    assert_eq!(store.cache_usage().unwrap(), before);
    assert!(store.chunk(fixture.binding.chunk.sha256).unwrap().is_none());
    assert_eq!(budget.usage().attempts_committed, 1);
    assert_eq!(
        budget.usage().reconstruction_bytes_committed,
        fixture.costs().1
    );
    assert_eq!(budget.usage().cache_bytes_committed, cache_bytes);
}

#[test]
fn cache_quota_refusal_keeps_repair_and_write_read_reservations_spent() {
    let (content, fixture) = cache_fixture();
    let pinned = pinned_content(&content);
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("tiny.sqlite"), cache_config(1)).unwrap();
    let before = store.cache_usage().unwrap();
    let cache_bytes = 2 * fixture.source.len() as u64;
    let mut budget = cache_budget(&fixture, 2, 2 * cache_bytes);
    for attempt in 1..=2 {
        assert!(matches!(
            fixture.codeword.repair_chunk_to_cache(
                &fixture.binding,
                fixture.codeword.id(),
                &inputs(&fixture.wires),
                CellRs46CacheTargetV1 {
                    store: &store,
                    content: &pinned
                },
                &mut budget,
            ),
            Err(CellErrorV1::CacheQuotaExceeded),
        ));
        assert_eq!(budget.usage().attempts_committed, attempt);
        assert_eq!(
            budget.usage().input_bytes_committed,
            u64::from(attempt) * fixture.costs().0
        );
        assert_eq!(
            budget.usage().reconstruction_bytes_committed,
            u64::from(attempt) * fixture.costs().1
        );
        assert_eq!(
            budget.usage().cache_bytes_committed,
            u64::from(attempt) * cache_bytes
        );
        assert_eq!(store.cache_usage().unwrap(), before);
    }
    let spent = budget.usage();
    assert!(matches!(
        fixture.codeword.repair_chunk_to_cache(
            &fixture.binding,
            fixture.codeword.id(),
            &inputs(&fixture.wires),
            CellRs46CacheTargetV1 {
                store: &store,
                content: &pinned
            },
            &mut budget,
        ),
        Err(CellErrorV1::Invalid("RS46 repair budget exhausted")),
    ));
    assert_eq!(budget.usage(), spent);
    assert!(store.chunk(fixture.binding.chunk.sha256).unwrap().is_none());
}

#[test]
fn cache_commit_requires_full_write_read_budget_and_never_refreshes_repair_deadline() {
    let (content, fixture) = cache_fixture();
    let pinned = pinned_content(&content);
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(
        &directory.path().join("target.sqlite"),
        cache_config(1024 * 1024),
    )
    .unwrap();
    let cache_bytes = 2 * fixture.source.len() as u64;
    // Pure repair's constructor grants no implicit cache allowance.
    for mut budget in [fixture.budget(), cache_budget(&fixture, 1, cache_bytes - 1)] {
        assert!(matches!(
            fixture.codeword.repair_chunk_to_cache(
                &fixture.binding,
                fixture.codeword.id(),
                &inputs(&fixture.wires),
                CellRs46CacheTargetV1 {
                    store: &store,
                    content: &pinned
                },
                &mut budget,
            ),
            Err(CellErrorV1::Invalid("RS46 repair cache budget exhausted")),
        ));
        assert_eq!(budget.usage().attempts_committed, 1);
        assert_eq!(budget.usage().cache_bytes_committed, 0);
        assert_eq!(store.cache_usage().unwrap().chunk_rows, 0);
    }
    let mut expired = cache_budget(&fixture, 1, cache_bytes);
    expired.deadline = Instant::now();
    assert!(matches!(
        fixture.codeword.repair_chunk_to_cache(
            &fixture.binding,
            fixture.codeword.id(),
            &inputs(&fixture.wires),
            CellRs46CacheTargetV1 {
                store: &store,
                content: &pinned
            },
            &mut expired,
        ),
        Err(CellErrorV1::Invalid("RS46 repair original deadline")),
    ));
    assert_eq!(expired.usage(), CellRs46RepairUsageV1::default());
    assert_eq!(store.cache_usage().unwrap().chunk_rows, 0);
}

#[test]
fn verified_chunk_pair_preserves_all_shard_wires_padding_and_bounds() {
    for length in [
        1_usize,
        2,
        3,
        4,
        5,
        17,
        16_383,
        16_384,
        16_385,
        MAX_CHUNK_BYTES as usize,
    ] {
        let source: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
        let pin = binding(&source, context());
        let expected = pin.encode_chunk(&source).unwrap();
        let (codeword, actual) =
            CellRs46CodewordV1::from_verified_chunk_with_shards(&pin, &source).unwrap();
        for (slot, (actual, expected)) in actual.iter().zip(&expected).enumerate() {
            assert_eq!(actual.index() as usize, slot);
            assert_eq!(
                actual.encode(),
                expected.encode(),
                "source length {length}, slot {slot}"
            );
            assert_eq!(actual.id(), expected.id());
            assert_eq!(actual.id(), codeword.shard_ids()[slot]);
        }
        assert_eq!(
            CellRs46CodewordV1::decode_pinned(&codeword.encode(), &pin, codeword.id(),).unwrap(),
            codeword
        );
    }
}

#[test]
fn verified_chunk_pair_rejects_wrong_length_and_same_length_wrong_hash() {
    let source: Vec<u8> = (0..257).map(|index| (index % 251) as u8).collect();
    let pin = binding(&source, context());
    let mut extended = source.clone();
    extended.push(0);
    let mut damaged = source.clone();
    damaged[128] ^= 1;
    assert_eq!(damaged.len(), source.len());
    for (label, bad) in [
        ("empty", Vec::new()),
        ("short", source[..source.len() - 1].to_vec()),
        ("long", extended),
        ("wrong hash", damaged),
    ] {
        assert!(
            CellRs46CodewordV1::from_verified_chunk_with_shards(&pin, &bad).is_err(),
            "{label}"
        );
    }
}
