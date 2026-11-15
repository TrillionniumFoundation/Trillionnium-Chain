//! Research schedule arithmetic and real complete-W1 controls. The original
//! Node admits only its original policy; none of these checks activates ASERT.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::research_work_schedule::{
    asert_target, inspect_retained_branch, AsertInputs, CheckedBranchSchedule, ClockEligibility,
    FullWorkCheck, HistoryHeader, IncrementalWorkSchedule, NativeWire, Policy, Profile,
    ProfileInputs, MAX_RESEARCH_HEIGHT,
};
use trnm_pon_node::{consensus, development_public, GrowthPacket, Node, Packet, Settings};
use trnm_protocol::pon_wire::{hash, Hash, Header};

const GENESIS_TIME: u64 = 1_750_000_000;

fn target(text: &str) -> Hash {
    hex::decode(text).unwrap().try_into().unwrap()
}

fn limit() -> Hash {
    let mut value = [255; 32];
    value[0] = 127;
    value
}

fn fixture(policy: Policy) -> Profile {
    Profile::new(ProfileInputs {
        network: [1; 32],
        parameters: [2; 32],
        genesis: [3; 32],
        genesis_time: 1000,
        initial_target: limit(),
        pow_limit: limit(),
        legacy_interval: 16,
        spacing_seconds: 10,
        future_skew_seconds: 120,
        wire: NativeWire::Pnh1,
        policy,
    })
    .unwrap()
}

fn context(profile: &Profile, chronological: &[HistoryHeader]) -> CheckedBranchSchedule {
    let parent = chronological
        .last()
        .map_or(profile.inputs().genesis, |row| row.block);
    let history: Vec<_> = chronological.iter().rev().cloned().collect();
    CheckedBranchSchedule::from_parent_first(profile, parent, &history).unwrap()
}

fn candidate(profile: &Profile, history: &[HistoryHeader], timestamp: u64) -> Header {
    let checked = context(profile, history);
    Header {
        network: profile.inputs().network,
        parameters: profile.inputs().parameters,
        parent: checked.parent(),
        height: history.len() as u64 + 1,
        timestamp,
        target: checked.required_target(),
        miner: [4; 32],
        transactions: [5; 32],
        state: [6; 32],
        receipts: [7; 32],
        work_task: [8; 32],
        nonce: 0,
    }
}

fn append(profile: &Profile, history: &mut Vec<HistoryHeader>, timestamp: u64) {
    let header = candidate(profile, history, timestamp);
    context(profile, history)
        .check_historical_header(&header)
        .unwrap();
    let block = hash(b"synthetic-research-schedule-test", &[&header.encode()]);
    history.push(HistoryHeader { block, header });
}

#[test]
fn native_asert_matches_all_18_pinned_bchn_raw_target_vectors() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../formal/pon-nakamoto-v1/vectors/quantum-daa-asert-bchn-v1.json"
    ))
    .unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 18);
    assert_eq!(
        fixture["source_commit"],
        "07576013c91ff4a3a74acd85f189c69121cdad1b"
    );
    for vector in vectors {
        let actual = asert_target(AsertInputs {
            anchor_target: target(vector["anchor_target_hex"].as_str().unwrap()),
            time_delta: i128::from(vector["time_delta"].as_i64().unwrap()),
            intervals: vector["intervals"].as_u64().unwrap(),
            spacing_seconds: fixture["spacing"].as_u64().unwrap(),
            half_life_seconds: fixture["half_life"].as_u64().unwrap(),
            pow_limit: target(fixture["pow_limit_hex"].as_str().unwrap()),
        })
        .unwrap();
        assert_eq!(
            hex::encode(actual),
            vector["expected_target_hex"].as_str().unwrap()
        );
    }
}

#[test]
fn native_asert_fractional_i128_and_full_u256_boundaries() {
    // Expected integers were independently computed with the already-retained
    // Python big-integer oracle, not native Work shifts or division.
    let anchor = target("000100000000000000000000000000000000000000000000ab54a98ceb1f0ad2");
    let vectors = [
        (
            0,
            1,
            10,
            160,
            "0000f52a8000000000000000000000000000000000000000a41477d202e9be02",
        ),
        (
            9,
            1,
            10,
            160,
            "0000fee60000000000000000000000000000000000000000aa97ee4a25e40aa0",
        ),
        (
            10,
            1,
            10,
            160,
            "000100000000000000000000000000000000000000000000ab54a98ceb1f0ad2",
        ),
        (
            11,
            1,
            10,
            160,
            "0001011d0000000000000000000000000000000000000000ac1366cdad00cc61",
        ),
        (
            169,
            1,
            10,
            160,
            "0001fdca0000000000000000000000000000000000000001552e85eaf8ae3f02",
        ),
        (
            170,
            1,
            10,
            160,
            "00020000000000000000000000000000000000000000000156a95319d63e15a4",
        ),
        (
            -1,
            1,
            10,
            160,
            "0000f41c0000000000000000000000000000000000000000a35f6edcdb834db5",
        ),
        (
            -1000,
            11,
            10,
            173,
            "000002ff5a0000000000000000000000000000000000000002018ee3c0cffcaa",
        ),
        (
            159,
            16,
            10,
            65536,
            "0000ffff8000000000000000000000000000000000000000ab5453e296589542",
        ),
        (
            159,
            16,
            10,
            65537,
            "000100000000000000000000000000000000000000000000ab54a98ceb1f0ad2",
        ),
        (
            161,
            16,
            10,
            65537,
            "000100000000000000000000000000000000000000000000ab54a98ceb1f0ad2",
        ),
    ];
    for (time_delta, intervals, spacing_seconds, half_life_seconds, expected) in vectors {
        assert_eq!(
            asert_target(AsertInputs {
                anchor_target: anchor,
                time_delta,
                intervals,
                spacing_seconds,
                half_life_seconds,
                pow_limit: [255; 32],
            })
            .unwrap(),
            target(expected)
        );
    }
    for (time_delta, expected) in [
        (i128::from(u64::MAX), [255; 32]),
        (-i128::from(u64::MAX), target(&format!("{:064x}", 1))),
    ] {
        assert_eq!(
            asert_target(AsertInputs {
                anchor_target: anchor,
                time_delta,
                intervals: 1,
                spacing_seconds: 1,
                half_life_seconds: 1,
                pow_limit: [255; 32],
            })
            .unwrap(),
            expected
        );
    }
    // Full-width target multiplication cannot use BCH's leading-zero shortcut.
    assert_eq!(
        asert_target(AsertInputs {
            anchor_target: [255; 32],
            time_delta: 11,
            intervals: 1,
            spacing_seconds: 10,
            half_life_seconds: 160,
            pow_limit: [255; 32],
        })
        .unwrap(),
        [255; 32]
    );
}

#[test]
fn native_asert_rejects_invalid_parameters_and_signed_intermediate_overflow() {
    let valid = AsertInputs {
        anchor_target: limit(),
        time_delta: 10,
        intervals: 1,
        spacing_seconds: 10,
        half_life_seconds: 160,
        pow_limit: limit(),
    };
    for input in [
        AsertInputs {
            anchor_target: [0; 32],
            ..valid
        },
        AsertInputs {
            pow_limit: [0; 32],
            ..valid
        },
        AsertInputs {
            intervals: 0,
            ..valid
        },
        AsertInputs {
            spacing_seconds: 0,
            ..valid
        },
        AsertInputs {
            half_life_seconds: 0,
            ..valid
        },
        AsertInputs {
            time_delta: i128::from(u64::MAX) + 1,
            ..valid
        },
    ] {
        assert_eq!(
            asert_target(input).unwrap_err().to_string(),
            "SCHEDULE_ASERT_PARAMETERS"
        );
    }
    for (intervals, spacing_seconds) in [(u64::MAX, u64::MAX), (u64::MAX, 1 << 48)] {
        assert_eq!(
            asert_target(AsertInputs {
                intervals,
                spacing_seconds,
                ..valid
            })
            .unwrap_err()
            .to_string(),
            "SCHEDULE_ASERT_I128_RANGE"
        );
    }
}

#[test]
fn c0_keeps_target_over_multiple_legacy_boundaries_and_counts_exact_work() {
    let profile = fixture(Policy::FixedTarget);
    let mut history = Vec::new();
    for height in 1..=64 {
        append(&profile, &mut history, 1000 + height);
        assert_eq!(history.last().unwrap().header.target, limit());
        assert_eq!(context(&profile, &history).required_target(), limit());
    }
    assert_eq!(context(&profile, &history).anchor(), None);
    let mut expected = [0; 64];
    expected[63] = 128;
    assert_eq!(
        context(&profile, &history).cumulative_work().bytes(),
        expected
    );
    assert_ne!(
        consensus::retarget(limit(), 1000, 1015, 16, 10, limit()).unwrap(),
        limit()
    );
}

#[test]
fn c1_activation_block_keeps_legacy_credit_then_uses_anchor_parent_time() {
    let profile = fixture(Policy::AnchoredAsert {
        activation_height: 16,
        half_life_seconds: 160,
    });
    let mut history = Vec::new();
    for height in 1..=16 {
        append(&profile, &mut history, 1000 + height);
    }
    let expected_anchor =
        target("206d3a06d3a06d3a06d3a06d3a06d3a06d3a06d3a06d3a06d3a06d3a06d3a06c");
    assert_eq!(history[15].header.target, expected_anchor);
    let checked = context(&profile, &history);
    let anchor = checked.anchor().unwrap();
    assert_eq!(anchor.height(), 16);
    assert_eq!(anchor.parent_time(), 1015);
    assert_eq!(anchor.target(), expected_anchor);
    assert_eq!(anchor.key().block, history[15].block);
    assert_eq!(anchor.key().profile, profile.id());
    assert_eq!(
        checked.required_target(),
        target("1f306eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeed")
    );
    let summed = history
        .iter()
        .fold(consensus::Work::default(), |total, row| {
            total
                .checked_add(consensus::required_work(row.header.target).unwrap())
                .unwrap()
        });
    assert_eq!(checked.cumulative_work(), summed);
}

#[test]
fn anchors_and_profile_hints_are_bound_to_the_actual_parent_fork() {
    let policy = Policy::AnchoredAsert {
        activation_height: 2,
        half_life_seconds: 160,
    };
    let profile = fixture(policy);
    let mut common = Vec::new();
    append(&profile, &mut common, 1010);
    let mut left = common.clone();
    let mut right = common;
    append(&profile, &mut left, 1011);
    append(&profile, &mut right, 1100);
    let a = context(&profile, &left);
    let b = context(&profile, &right);
    assert_ne!(a.anchor().unwrap().key(), b.anchor().unwrap().key());
    assert_ne!(a.required_target(), b.required_target());
    a.check_anchor_hint(a.anchor().unwrap()).unwrap();
    assert_eq!(
        a.check_anchor_hint(b.anchor().unwrap())
            .unwrap_err()
            .to_string(),
        "SCHEDULE_ANCHOR_MISMATCH"
    );
    let mut other_inputs = profile.inputs().clone();
    other_inputs.policy = Policy::AnchoredAsert {
        activation_height: 2,
        half_life_seconds: 320,
    };
    let other_profile = Profile::new(other_inputs).unwrap();
    let other = context(&other_profile, &left);
    assert_eq!(
        other.anchor().unwrap().key().block,
        a.anchor().unwrap().key().block
    );
    assert_ne!(other.profile_id(), a.profile_id());
    assert_eq!(
        a.check_anchor_hint(other.anchor().unwrap())
            .unwrap_err()
            .to_string(),
        "SCHEDULE_ANCHOR_MISMATCH"
    );
    let rebuilt = context(&profile, &left);
    assert_eq!(a, rebuilt);
}

#[test]
fn complete_path_namespace_links_heights_and_duplicate_ids_are_checked() {
    let profile = fixture(Policy::FixedTarget);
    let mut history = Vec::new();
    for height in 1..=3 {
        append(&profile, &mut history, 1000 + height * 10);
    }
    let parent = history.last().unwrap().block;
    let rows: Vec<_> = history.iter().rev().cloned().collect();
    let mut changed = rows.clone();
    changed[0].header.network = [99; 32];
    assert_eq!(
        CheckedBranchSchedule::from_parent_first(&profile, parent, &changed)
            .unwrap_err()
            .to_string(),
        "SCHEDULE_NAMESPACE"
    );
    let mut changed = rows.clone();
    changed[0].header.height += 1;
    assert_eq!(
        CheckedBranchSchedule::from_parent_first(&profile, parent, &changed)
            .unwrap_err()
            .to_string(),
        "SCHEDULE_HEIGHT"
    );
    let mut changed = rows.clone();
    changed[0].header.parent = [99; 32];
    assert_eq!(
        CheckedBranchSchedule::from_parent_first(&profile, parent, &changed)
            .unwrap_err()
            .to_string(),
        "SCHEDULE_PARENT"
    );
    let mut changed = rows.clone();
    changed[0].block = changed[1].block;
    assert_eq!(
        CheckedBranchSchedule::from_parent_first(&profile, parent, &changed)
            .unwrap_err()
            .to_string(),
        "SCHEDULE_DUPLICATE_BLOCK"
    );
    assert_eq!(
        CheckedBranchSchedule::from_parent_first(&profile, [99; 32], &rows)
            .unwrap_err()
            .to_string(),
        "SCHEDULE_EXPECTED_PARENT"
    );
    assert_eq!(
        CheckedBranchSchedule::from_parent_first(&profile, parent, &rows[..2])
            .unwrap_err()
            .to_string(),
        "SCHEDULE_PARENT"
    );
    let too_long = vec![rows[0].clone(); MAX_RESEARCH_HEIGHT as usize];
    assert_eq!(
        CheckedBranchSchedule::from_parent_first(&profile, parent, &too_long)
            .unwrap_err()
            .to_string(),
        "SCHEDULE_HORIZON"
    );
}

#[test]
fn new_time_rules_allow_equal_parent_only_when_strictly_above_mtp() {
    let profile = fixture(Policy::FixedTarget);
    let mut history = Vec::new();
    for timestamp in [1010, 1020, 1030, 1040, 1100] {
        append(&profile, &mut history, timestamp);
    }
    let checked = context(&profile, &history);
    checked
        .check_historical_header(&candidate(&profile, &history, 1100))
        .unwrap();
    assert_eq!(
        checked
            .check_historical_header(&candidate(&profile, &history, 1041))
            .unwrap_err()
            .to_string(),
        "SCHEDULE_TIME_NONDECREASING"
    );
    let short = &history[..1];
    assert_eq!(
        context(&profile, short)
            .check_historical_header(&candidate(&profile, short, 1010))
            .unwrap_err()
            .to_string(),
        "SCHEDULE_TIME_MTP"
    );
}

#[test]
fn legacy_nonmonotone_history_is_not_reinterpreted_after_activation() {
    let profile = fixture(Policy::AnchoredAsert {
        activation_height: 5,
        half_life_seconds: 160,
    });
    let mut history = Vec::new();
    for timestamp in [1010, 1020, 1100, 1021, 1022] {
        append(&profile, &mut history, timestamp);
    }
    let checked = context(&profile, &history);
    assert_eq!(checked.anchor().unwrap().parent_time(), 1021);
    assert_eq!(
        checked
            .check_historical_header(&candidate(&profile, &history, 1021))
            .unwrap_err()
            .to_string(),
        "SCHEDULE_TIME_NONDECREASING"
    );
    checked
        .check_historical_header(&candidate(&profile, &history, 1023))
        .unwrap();
}

#[test]
fn local_clock_rollback_only_changes_defer_status_not_history_or_target() {
    let profile = fixture(Policy::FixedTarget);
    let mut history = Vec::new();
    append(&profile, &mut history, 1010);
    let checked = context(&profile, &history);
    let historical = checked
        .check_historical_header(&candidate(&profile, &history, 2000))
        .unwrap();
    let original = historical.clone();
    for (now, expected) in [
        (1879, ClockEligibility::DeferredUntil(1880)),
        (1880, ClockEligibility::Eligible),
        (1881, ClockEligibility::Eligible),
        (0, ClockEligibility::DeferredUntil(1880)),
        (u64::MAX, ClockEligibility::Eligible),
    ] {
        assert_eq!(historical.clock_eligibility(now), expected);
        assert_eq!(historical, original);
        assert_eq!(checked.required_target(), limit());
    }
    assert_eq!(
        historical.block_work(),
        consensus::required_work(limit()).unwrap()
    );
    let overflowing = consensus::Work::from_bytes([255; 64]);
    assert_eq!(
        overflowing
            .checked_add(historical.block_work())
            .unwrap_err()
            .to_string(),
        "CHAINWORK_OVERFLOW"
    );
}

#[test]
fn branch_clock_retains_the_maximum_of_nonmonotone_legacy_history() {
    let profile = fixture(Policy::AnchoredAsert {
        activation_height: 5,
        half_life_seconds: 160,
    });
    let mut history = Vec::new();
    for timestamp in [1010, 1020, 1100, 1021, 1022] {
        append(&profile, &mut history, timestamp);
    }
    let checked = context(&profile, &history);
    let historical = checked
        .check_historical_header(&candidate(&profile, &history, 1023))
        .unwrap();
    assert_eq!(checked.max_ancestor_time(), 1100);
    assert_eq!(
        historical.clock_eligibility(903),
        ClockEligibility::Eligible
    );
    assert_eq!(
        historical.branch_clock_eligibility(903),
        ClockEligibility::DeferredUntil(980)
    );
    let original = historical.clone();
    for now in [980, 981, 903, 0, u64::MAX] {
        let expected = if now < 980 {
            ClockEligibility::DeferredUntil(980)
        } else {
            ClockEligibility::Eligible
        };
        assert_eq!(historical.branch_clock_eligibility(now), expected);
        assert_eq!(checked.branch_clock_eligibility(now), expected);
        assert_eq!(historical, original);
    }

    // Keep the high legacy ancestor after it leaves the eleven-point MTP.
    for timestamp in 1023..=1035 {
        append(&profile, &mut history, timestamp);
    }
    assert!(history
        .iter()
        .rev()
        .take(11)
        .all(|row| row.header.timestamp < 1100));
    let extended = context(&profile, &history);
    let later = extended
        .check_historical_header(&candidate(&profile, &history, 1036))
        .unwrap();
    assert_eq!(extended.max_ancestor_time(), 1100);
    assert_eq!(later.clock_eligibility(916), ClockEligibility::Eligible);
    assert_eq!(
        later.branch_clock_eligibility(979),
        ClockEligibility::DeferredUntil(980)
    );
}

#[test]
fn incremental_genesis_has_no_imported_credit_or_anchor() {
    for policy in [
        Policy::FixedTarget,
        Policy::AnchoredAsert {
            activation_height: 1,
            half_life_seconds: 160,
        },
    ] {
        let profile = fixture(policy);
        let prefix = IncrementalWorkSchedule::new(&profile);
        assert_eq!(prefix.profile_id(), profile.id());
        assert_eq!(prefix.tip(), profile.inputs().genesis);
        assert_eq!(prefix.height(), 0);
        assert_eq!(prefix.anchor(), None);
        assert_eq!(prefix.cumulative_work(), consensus::Work::default());
        assert_eq!(prefix.max_ancestor_time(), profile.inputs().genesis_time);
        assert_eq!(prefix.next_context().unwrap(), context(&profile, &[]));
        assert_eq!(
            prefix.branch_clock_eligibility(879),
            ClockEligibility::DeferredUntil(880)
        );
    }
}

#[derive(Clone, Copy)]
enum Backend {
    Pnh1,
    Pgh2,
}

#[derive(Clone)]
enum NativePacket {
    Pnh1(Packet),
    Pgh2(GrowthPacket),
}

impl NativePacket {
    fn id(&self) -> Hash {
        match self {
            Self::Pnh1(p) => p.id().unwrap(),
            Self::Pgh2(p) => p.id().unwrap(),
        }
    }
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Pnh1(p) => p.encode().unwrap(),
            Self::Pgh2(p) => p.encode().unwrap(),
        }
    }
    fn header_bytes(&self) -> Vec<u8> {
        match self {
            Self::Pnh1(p) => p.header.encode(),
            Self::Pgh2(p) => p.header.encode(),
        }
    }
    fn header(&self) -> &Header {
        match self {
            Self::Pnh1(p) => &p.header,
            Self::Pgh2(p) => &p.header.ledger,
        }
    }
    fn header_mut(&mut self) -> &mut Header {
        match self {
            Self::Pnh1(p) => &mut p.header,
            Self::Pgh2(p) => &mut p.header.ledger,
        }
    }
    fn challenge(&self) -> Hash {
        match self {
            Self::Pnh1(p) => p.header.challenge(),
            Self::Pgh2(p) => p.header.challenge(),
        }
    }
    fn proof(&self) -> &[u8] {
        match self {
            Self::Pnh1(p) => &p.proof,
            Self::Pgh2(p) => &p.proof,
        }
    }
    fn proof_mut(&mut self) -> &mut Vec<u8> {
        match self {
            Self::Pnh1(p) => &mut p.proof,
            Self::Pgh2(p) => &mut p.proof,
        }
    }
    fn full_verify(&self) {
        pon_work::verify(
            self.challenge(),
            self.header().work_task,
            self.header().target,
            self.proof(),
        )
        .unwrap();
    }
    fn check(&self, checked: &CheckedBranchSchedule) -> trnm_pon_node::Result<FullWorkCheck> {
        self.check_with_progress(checked, &mut || Ok(()))
    }
    fn check_with_progress(
        &self,
        checked: &CheckedBranchSchedule,
        progress: &mut impl FnMut() -> trnm_pon_node::Result<()>,
    ) -> trnm_pon_node::Result<FullWorkCheck> {
        match self {
            Self::Pnh1(p) => checked.check_pnh1_packet(p, progress),
            Self::Pgh2(p) => checked.check_pgh2_packet(p, progress),
        }
    }
    fn advance(
        &self,
        prefix: &mut IncrementalWorkSchedule,
        progress: &mut impl FnMut() -> trnm_pon_node::Result<()>,
    ) -> trnm_pon_node::Result<FullWorkCheck> {
        match self {
            Self::Pnh1(p) => prefix.append_pnh1_packet(p, progress),
            Self::Pgh2(p) => prefix.append_pgh2_packet(p, progress),
        }
    }
    fn reprove(&mut self, required: Hash) {
        let (a, b) = match self {
            Self::Pnh1(_) => trnm_pon_node::maintenance(),
            Self::Pgh2(_) => continuity_v1::maintenance_matrices(),
        };
        self.header_mut().target = required;
        for nonce in 0..4096 {
            self.header_mut().nonce = nonce;
            let proof = pon_work::prove(self.challenge(), &a, &b).unwrap();
            *self.proof_mut() = proof;
            match pon_work::verify(
                self.challenge(),
                self.header().work_task,
                required,
                self.proof(),
            ) {
                Ok(_) => return,
                Err(pon_work::WorkError::Target) => {}
                Err(error) => panic!("fresh native work failed: {error:?}"),
            }
        }
        panic!("fresh native work search exhausted");
    }
}

impl Backend {
    fn name(self) -> &'static str {
        match self {
            Self::Pnh1 => "pnh1-authenticated",
            Self::Pgh2 => "pgh2-growth",
        }
    }
    fn settings(self) -> Settings {
        match self {
            Self::Pnh1 => Settings::development(Some(GENESIS_TIME)).unwrap(),
            Self::Pgh2 => Settings::development_with_profiles(
                Some(GENESIS_TIME),
                "native-public-evaluation-dev-v1",
                continuity_v1::PROFILE,
            )
            .unwrap()
            .with_permanent_account_growth_v2("branch-work-schedule-research-v1-tests")
            .unwrap(),
        }
    }
    fn open(self, path: &Path, settings: Settings) -> Node {
        match self {
            Self::Pnh1 => Node::open_with_authenticated_state(path, settings, 1).unwrap(),
            Self::Pgh2 => Node::open_with_permanent_account_growth_v2(path, settings).unwrap(),
        }
    }
    fn make(self, node: &Node, parent: Hash, timestamp: u64, miner: u64) -> NativePacket {
        let miner = development_public(miner).unwrap();
        match self {
            Self::Pnh1 => {
                NativePacket::Pnh1(node.make(parent, vec![], miner, timestamp, 4096).unwrap())
            }
            Self::Pgh2 => NativePacket::Pgh2(
                node.make_growth_consensus_maintenance(parent, vec![], miner, timestamp, 4096)
                    .unwrap(),
            ),
        }
    }
    fn admit(self, node: &mut Node, packet: &NativePacket) -> trnm_pon_node::Result<Hash> {
        match (self, packet) {
            (Self::Pnh1, NativePacket::Pnh1(p)) => node.admit(p, GENESIS_TIME + 10000),
            (Self::Pgh2, NativePacket::Pgh2(p)) => node.admit_growth(p, GENESIS_TIME + 10000),
            _ => panic!("native wire mismatch"),
        }
    }
    fn retained(self, node: &Node, id: Hash) -> NativePacket {
        match self {
            Self::Pnh1 => NativePacket::Pnh1(node.packet(id).unwrap()),
            Self::Pgh2 => NativePacket::Pgh2(node.growth_packet(id).unwrap()),
        }
    }
    fn activate(self, node: &mut Node, id: Hash) {
        match self {
            Self::Pnh1 => {
                node.activate_observed(id, GENESIS_TIME + 10000).unwrap();
            }
            Self::Pgh2 => {
                node.activate(id).unwrap();
            }
        }
    }
}

// Evidence retention only. This helper neither selects nor installs a policy.
// Each backend directory is new; stale evidence is an error, never overwritten.
fn export_research_evidence(
    root: &Path,
    backend: Backend,
    profile: &Profile,
    reopened: &Node,
    packets: &[(&str, &NativePacket)],
    observations: Value,
) {
    assert_eq!(packets.len(), 7);
    std::fs::create_dir_all(root).unwrap();
    let directory = root.join(backend.name());
    std::fs::create_dir(&directory).expect("research evidence backend directory must not exist");
    std::fs::create_dir(directory.join("packets")).unwrap();
    let config = profile.inputs();
    let mut records = Vec::new();
    for (label, packet) in packets {
        let mut parent = packet.header().parent;
        let mut branch = Vec::new();
        while parent != config.genesis {
            assert!(branch.len() < packets.len());
            let ancestor = packets
                .iter()
                .find(|(_, candidate)| candidate.id() == parent)
                .unwrap()
                .1;
            branch.push(HistoryHeader {
                block: parent,
                header: ancestor.header().clone(),
            });
            parent = ancestor.header().parent;
        }
        let checked =
            CheckedBranchSchedule::from_parent_first(profile, packet.header().parent, &branch)
                .unwrap();
        let mut times: Vec<_> = branch
            .iter()
            .map(|row| row.header.timestamp)
            .chain(std::iter::once(config.genesis_time))
            .take(11)
            .collect();
        times.sort_unstable();
        packet.full_verify();
        let outcome = packet.check(&checked);
        let observed = outcome
            .as_ref()
            .map_or_else(|error| error.to_string(), |_| "PASS".to_string());
        let expected = if *label == "backwards" {
            "SCHEDULE_TIME_NONDECREASING"
        } else {
            "PASS"
        };
        assert_eq!(observed, expected);
        let raw = packet.encode();
        let storage = if *label == "fresh_adjusted" {
            assert!(reopened.parent_height(packet.id()).is_err());
            "not-retained"
        } else {
            let retained = match backend {
                Backend::Pnh1 => reopened.packet(packet.id()).unwrap().encode().unwrap(),
                Backend::Pgh2 => reopened
                    .growth_packet(packet.id())
                    .unwrap()
                    .encode()
                    .unwrap(),
            };
            assert_eq!(retained, raw);
            "retained-byte-identical"
        };
        let filename = format!("packets/{label}.pnk");
        std::fs::write(directory.join(&filename), &raw).unwrap();
        let anchor = checked.anchor().map(|value| json!({
            "profile": hex::encode(value.key().profile), "block": hex::encode(value.key().block),
            "height": value.height(), "target": hex::encode(value.target()), "parent_time": value.parent_time(),
        }));
        records.push(json!({
            "label": label, "packet_file": filename, "packet_bytes": raw.len(),
            "packet_sha256": hex::encode(Sha256::digest(&raw)), "id": hex::encode(packet.id()),
            "header_hex": hex::encode(packet.header_bytes()), "challenge": hex::encode(packet.challenge()),
            "proof_bytes": packet.proof().len(), "proof_sha256": hex::encode(Sha256::digest(packet.proof())),
            "trace": hex::encode(&packet.proof()[packet.proof().len() - 32..]),
            "parent": hex::encode(packet.header().parent), "height": packet.header().height,
            "timestamp": packet.header().timestamp, "actual_target": hex::encode(packet.header().target),
            "required_target": hex::encode(checked.required_target()),
            "parent_branch": branch.iter().map(|row| hex::encode(row.block)).collect::<Vec<_>>(),
            "anchor": anchor, "median_time_past": times[times.len() / 2],
            "parent_cumulative_work_hex": hex::encode(checked.cumulative_work().bytes()),
            "block_work_hex": hex::encode(consensus::required_work(checked.required_target()).unwrap().bytes()),
            "candidate_cumulative_work_hex": outcome.as_ref().ok().map(|result| hex::encode(result.historical().cumulative_work().bytes())),
            "expected_research_verdict": expected, "observed_research_verdict": observed,
            "complete_native_work_verification": true,
            "native_admission_observed": if *label == "fresh_adjusted" { "TARGET" } else { "admitted" },
            "cold_storage_observation": storage,
        }));
    }
    let Policy::AnchoredAsert {
        activation_height,
        half_life_seconds,
    } = config.policy
    else {
        panic!("ASERT evidence profile required")
    };
    let report = json!({
        "schema": "pon-native-branch-work-schedule-v1", "backend": backend.name(),
        "header_profile": match backend { Backend::Pnh1 => "PNH1", Backend::Pgh2 => "PGH2" },
        "settings_scope": "actual-schedule-inputs-and-task-profile-only",
        "task_profile": reopened.settings().task_profile(),
        "profile": {
            "schema": trnm_pon_node::research_work_schedule::SCHEMA, "id": hex::encode(profile.id()),
            "network": hex::encode(config.network), "parameters": hex::encode(config.parameters),
            "genesis": hex::encode(config.genesis), "genesis_timestamp": config.genesis_time,
            "initial_target": hex::encode(config.initial_target), "pow_limit": hex::encode(config.pow_limit),
            "legacy_interval": config.legacy_interval, "spacing_seconds": config.spacing_seconds,
            "future_skew_seconds": config.future_skew_seconds, "median_window": 11,
            "max_research_height": MAX_RESEARCH_HEIGHT, "activation_height": activation_height,
            "half_life_seconds": half_life_seconds,
        },
        "records": records, "native_observations": observations,
        "native_new_profile_installed": false, "default_consensus_rules_changed": false,
        "production_activation": false, "minimum_cost_qualified": false,
        "quantum_cost_qualified": false, "joint_consensus_security_proven": false,
        "full_execution_identity_verified": false,
    });
    let raw = serde_json::to_vec_pretty(&report).unwrap();
    let digest = hex::encode(Sha256::digest(&raw));
    std::fs::write(directory.join("report.json"), &raw).unwrap();
    std::fs::write(directory.join("report.sha256"), format!("{digest}\n")).unwrap();
    println!(
        "RESEARCH_EVIDENCE {} {} {digest}",
        backend.name(),
        directory.display()
    );
}

fn native_complete_proof_campaign(backend: Backend) {
    let directory = tempfile::tempdir().unwrap();
    let settings = backend.settings();
    let genesis = settings.genesis();
    let profile = Profile::for_node(
        &settings,
        Policy::AnchoredAsert {
            activation_height: 1,
            half_life_seconds: 160,
        },
    )
    .unwrap();
    let mut node = backend.open(directory.path(), settings.clone());
    let first = backend.make(&node, genesis, GENESIS_TIME + 10, 0);
    let first_id = backend.admit(&mut node, &first).unwrap();

    // Opaque incremental state has no arithmetic-history or peer-work import.
    let mut incremental = IncrementalWorkSchedule::new(&profile);
    assert_eq!(
        incremental.next_context().unwrap(),
        inspect_retained_branch(&node, &profile, genesis, &mut || Ok(())).unwrap()
    );
    let mut other_wire = profile.inputs().clone();
    other_wire.wire = match other_wire.wire {
        NativeWire::Pnh1 => NativeWire::Pgh2,
        NativeWire::Pgh2 => NativeWire::Pnh1,
    };
    let mut other_namespace = profile.inputs().clone();
    other_namespace.parameters[0] ^= 1;
    for (inputs, error) in [
        (other_wire, "SCHEDULE_WIRE"),
        (other_namespace, "SCHEDULE_NAMESPACE"),
    ] {
        let wrong_profile = Profile::new(inputs).unwrap();
        let mut refused = IncrementalWorkSchedule::new(&wrong_profile);
        let before = refused.clone();
        let mut callbacks = 0;
        assert_eq!(
            first
                .advance(&mut refused, &mut || {
                    callbacks += 1;
                    Ok(())
                })
                .unwrap_err()
                .to_string(),
            error
        );
        assert_eq!(callbacks, 0);
        assert_eq!(refused, before);
    }
    let first_receipt = first.advance(&mut incremental, &mut || Ok(())).unwrap();
    assert_eq!(first_receipt.block(), first_id);
    assert_eq!(incremental.tip(), first_id);
    assert_eq!(incremental.anchor().unwrap().key().block, first_id);
    let first_prefix = incremental.clone();
    assert_eq!(
        incremental.next_context().unwrap(),
        inspect_retained_branch(&node, &profile, first_id, &mut || Ok(())).unwrap()
    );

    let fast = backend.make(&node, first_id, GENESIS_TIME + 11, 0);
    let fast_id = backend.admit(&mut node, &fast).unwrap();
    backend.activate(&mut node, fast_id);
    let fast_context = inspect_retained_branch(&node, &profile, fast_id, &mut || Ok(())).unwrap();
    let mut direct_callbacks = 0;
    let direct = fast
        .check_with_progress(&incremental.next_context().unwrap(), &mut || {
            direct_callbacks += 1;
            Ok(())
        })
        .unwrap();
    let mut incremental_callbacks = 0;
    let advanced = fast
        .advance(&mut incremental, &mut || {
            incremental_callbacks += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(advanced, direct);
    // The same candidate's single complete replay plus one final publish
    // checkpoint; adding a parent did not cause another parent-proof replay.
    assert!(direct_callbacks > 1);
    assert_eq!(incremental_callbacks, direct_callbacks + 1);
    assert_eq!(incremental.next_context().unwrap(), fast_context);
    let fast_prefix = incremental.clone();
    assert!(fast_context.required_target() < fast.header().target);
    let mut fresh = backend.make(&node, fast_id, GENESIS_TIME + 12, 0);
    fresh.reprove(fast_context.required_target());
    fresh.full_verify();
    let result = fresh.check(&fast_context).unwrap();
    assert_eq!(
        result.historical().required_target(),
        fast_context.required_target()
    );
    assert_eq!(
        result.historical().cumulative_work(),
        fast_context
            .cumulative_work()
            .checked_add(consensus::required_work(fast_context.required_target()).unwrap())
            .unwrap()
    );
    assert_eq!(
        result.historical().clock_eligibility(0),
        ClockEligibility::DeferredUntil(GENESIS_TIME + 12 - 120)
    );
    assert_eq!(
        result.historical().clock_eligibility(GENESIS_TIME + 12),
        ClockEligibility::Eligible
    );

    // This is a policy-isolation control, NOT evidence of a timestamp fix.
    // The original Node keeps its original target; the new target-bound full
    // proof has just passed the separate research verifier above.
    let original_fresh_refusal = backend.admit(&mut node, &fresh).unwrap_err().to_string();
    assert_eq!(original_fresh_refusal, "TARGET");
    assert!(node.parent_height(result.block()).is_err());

    let mut corrupt = fresh.clone();
    let index = 4 + 2 * pon_work::CELLS * 4;
    let old = u32::from_le_bytes(corrupt.proof()[index..index + 4].try_into().unwrap());
    corrupt.proof_mut()[index..index + 4].copy_from_slice(&(old ^ 1).to_le_bytes());
    let wrong_product_refusal = corrupt.check(&fast_context).unwrap_err().to_string();
    assert_eq!(wrong_product_refusal, "WORK:Product");
    let unchanged = incremental.clone();
    assert_eq!(
        corrupt
            .advance(&mut incremental, &mut || Ok(()))
            .unwrap_err()
            .to_string(),
        "WORK:Product"
    );
    assert_eq!(incremental, unchanged);
    assert_eq!(
        fresh
            .advance(
                &mut incremental,
                &mut || Err("INCREMENTAL_CANCELLED".into())
            )
            .unwrap_err()
            .to_string(),
        "INCREMENTAL_CANCELLED"
    );
    assert_eq!(incremental, unchanged);
    let mut wrong_parent = fresh.clone();
    wrong_parent.header_mut().parent = genesis;
    let mut preflight_callbacks = 0;
    assert_eq!(
        wrong_parent
            .advance(&mut incremental, &mut || {
                preflight_callbacks += 1;
                Ok(())
            })
            .unwrap_err()
            .to_string(),
        "SCHEDULE_PARENT"
    );
    assert_eq!(preflight_callbacks, 0);
    assert_eq!(incremental, unchanged);

    let mut candidate_callbacks = 0;
    fresh
        .check_with_progress(&fast_context, &mut || {
            candidate_callbacks += 1;
            Ok(())
        })
        .unwrap();
    let mut late_callbacks = 0;
    assert_eq!(
        fresh
            .advance(&mut incremental, &mut || {
                late_callbacks += 1;
                if late_callbacks > candidate_callbacks {
                    Err("INCREMENTAL_FINAL_CANCELLED".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err()
            .to_string(),
        "INCREMENTAL_FINAL_CANCELLED"
    );
    assert_eq!(late_callbacks, candidate_callbacks + 1);
    assert_eq!(incremental, unchanged);

    // The cancelled candidate can be retried; only the successful publication
    // adds its exact work. Re-delivery then adds no credit and enters no replay.
    assert_eq!(
        fresh.advance(&mut incremental, &mut || Ok(())).unwrap(),
        result
    );
    let after_fresh = incremental.clone();
    let mut duplicate_callbacks = 0;
    assert_eq!(
        fresh
            .advance(&mut incremental, &mut || {
                duplicate_callbacks += 1;
                Ok(())
            })
            .unwrap_err()
            .to_string(),
        "SCHEDULE_DUPLICATE_BLOCK"
    );
    assert_eq!(duplicate_callbacks, 0);
    assert_eq!(incremental, after_fresh);
    assert_eq!(incremental.height(), 3);
    assert_eq!(
        incremental.cumulative_work(),
        result.historical().cumulative_work()
    );

    let cancellation = match &fresh {
        NativePacket::Pnh1(p) => {
            fast_context.check_pnh1_packet(p, &mut || Err("SCHEDULE_TEST_CANCELLED".into()))
        }
        NativePacket::Pgh2(p) => {
            fast_context.check_pgh2_packet(p, &mut || Err("SCHEDULE_TEST_CANCELLED".into()))
        }
    };
    let cancellation_refusal = cancellation.unwrap_err().to_string();
    assert_eq!(cancellation_refusal, "SCHEDULE_TEST_CANCELLED");

    let high = backend.make(&node, first_id, GENESIS_TIME + 100, 1);
    let high_id = backend.admit(&mut node, &high).unwrap();
    let high_context = inspect_retained_branch(&node, &profile, high_id, &mut || Ok(())).unwrap();
    let mut high_prefix = first_prefix.clone();
    high.advance(&mut high_prefix, &mut || Ok(())).unwrap();
    assert_eq!(high_prefix.next_context().unwrap(), high_context);
    assert_eq!(incremental, after_fresh);
    // Freshly computed full W1 at the *correct candidate target*, above MTP,
    // below its parent's timestamp. It fails the intended new time rule.
    let backwards = backend.make(&node, high_id, GENESIS_TIME + 11, 1);
    assert_eq!(backwards.header().target, high_context.required_target());
    backwards.full_verify();
    let backwards_research_refusal = backwards.check(&high_context).unwrap_err().to_string();
    assert_eq!(backwards_research_refusal, "SCHEDULE_TIME_NONDECREASING");
    let before_backwards = high_prefix.clone();
    assert_eq!(
        backwards
            .advance(&mut high_prefix, &mut || Ok(()))
            .unwrap_err()
            .to_string(),
        "SCHEDULE_TIME_NONDECREASING"
    );
    assert_eq!(high_prefix, before_backwards);
    let old_rule_id = backend.admit(&mut node, &backwards).unwrap();
    assert_eq!(node.parent_height(old_rule_id).unwrap(), 3);

    let equal = backend.make(&node, high_id, GENESIS_TIME + 100, 1);
    equal.full_verify();
    let equal_check = equal.check(&high_context).unwrap();
    assert_eq!(
        equal.advance(&mut high_prefix, &mut || Ok(())).unwrap(),
        equal_check
    );
    assert_eq!(incremental, after_fresh);
    assert_eq!(first_prefix.height(), 1);
    let equal_id = backend.admit(&mut node, &equal).unwrap();
    assert_eq!(node.parent_height(equal_id).unwrap(), 3);

    let other_anchor = backend.make(&node, genesis, GENESIS_TIME + 20, 2);
    let other_anchor_id = backend.admit(&mut node, &other_anchor).unwrap();
    let other_context =
        inspect_retained_branch(&node, &profile, other_anchor_id, &mut || Ok(())).unwrap();
    let cross_fork_anchor_refusal = fast_context
        .check_anchor_hint(other_context.anchor().unwrap())
        .unwrap_err()
        .to_string();
    assert_eq!(cross_fork_anchor_refusal, "SCHEDULE_ANCHOR_MISMATCH");
    let mut alternate = IncrementalWorkSchedule::new(&profile);
    other_anchor
        .advance(&mut alternate, &mut || Ok(()))
        .unwrap();
    assert_eq!(alternate.next_context().unwrap(), other_context);
    assert_ne!(alternate.anchor(), first_prefix.anchor());
    assert_eq!(incremental, after_fresh);

    // A real old-policy nonmonotone prefix retains its greatest timestamp.
    // The candidate-only clock may pass while an earlier ancestor is deferred.
    let late_activation = Profile::for_node(
        &settings,
        Policy::AnchoredAsert {
            activation_height: 3,
            half_life_seconds: 160,
        },
    )
    .unwrap();
    let mut legacy_prefix = IncrementalWorkSchedule::new(&late_activation);
    first.advance(&mut legacy_prefix, &mut || Ok(())).unwrap();
    high.advance(&mut legacy_prefix, &mut || Ok(())).unwrap();
    let legacy_receipt = backwards
        .advance(&mut legacy_prefix, &mut || Ok(()))
        .unwrap();
    let skew = profile.inputs().future_skew_seconds;
    let candidate_now = backwards.header().timestamp.saturating_sub(skew);
    let branch_ready = high.header().timestamp.saturating_sub(skew);
    assert_eq!(
        legacy_receipt.historical().clock_eligibility(candidate_now),
        ClockEligibility::Eligible
    );
    assert_eq!(
        legacy_receipt
            .historical()
            .branch_clock_eligibility(candidate_now),
        ClockEligibility::DeferredUntil(branch_ready)
    );
    assert_eq!(legacy_prefix.max_ancestor_time(), high.header().timestamp);
    let legacy_before = legacy_prefix.clone();
    for now in [branch_ready, candidate_now, 0, u64::MAX] {
        let expected = if now < branch_ready {
            ClockEligibility::DeferredUntil(branch_ready)
        } else {
            ClockEligibility::Eligible
        };
        assert_eq!(legacy_prefix.branch_clock_eligibility(now), expected);
        assert_eq!(
            legacy_receipt.historical().branch_clock_eligibility(now),
            expected
        );
        assert_eq!(legacy_prefix, legacy_before);
    }
    let c0 = Profile::for_node(&settings, Policy::FixedTarget).unwrap();
    let c0_context = inspect_retained_branch(&node, &c0, fast_id, &mut || Ok(())).unwrap();
    assert_eq!(c0_context.required_target(), fast.header().target);
    drop(node);
    let reopened = backend.open(directory.path(), settings);
    let cold = inspect_retained_branch(&reopened, &profile, fast_id, &mut || Ok(())).unwrap();
    assert_eq!(cold, fast_context);
    let mut cold_incremental = IncrementalWorkSchedule::new(&profile);
    for id in [first_id, fast_id] {
        backend
            .retained(&reopened, id)
            .advance(&mut cold_incremental, &mut || Ok(()))
            .unwrap();
    }
    assert_eq!(cold_incremental, fast_prefix);
    assert_eq!(cold_incremental.next_context().unwrap(), cold);
    let cold_nonmonotone_refusal =
        inspect_retained_branch(&reopened, &profile, old_rule_id, &mut || Ok(()))
            .unwrap_err()
            .to_string();
    assert_eq!(cold_nonmonotone_refusal, "SCHEDULE_TIME_NONDECREASING");
    let cold_c0 = inspect_retained_branch(&reopened, &c0, fast_id, &mut || Ok(())).unwrap();
    assert_eq!(cold_c0, c0_context);
    let mut c0_incremental = IncrementalWorkSchedule::new(&c0);
    for packet in [&first, &fast] {
        packet.advance(&mut c0_incremental, &mut || Ok(())).unwrap();
    }
    assert_eq!(c0_incremental.next_context().unwrap(), cold_c0);
    assert_eq!(c0_incremental.anchor(), None);
    if let Some(root) = std::env::var_os("TRNM_WORK_SCHEDULE_RESEARCH_DIR") {
        export_research_evidence(
            Path::new(&root),
            backend,
            &profile,
            &reopened,
            &[
                ("first", &first),
                ("fast", &fast),
                ("high", &high),
                ("other_anchor", &other_anchor),
                ("fresh_adjusted", &fresh),
                ("backwards", &backwards),
                ("equal", &equal),
            ],
            json!({
                "original_fresh_refusal": original_fresh_refusal, "wrong_product_refusal": wrong_product_refusal,
                "cancellation_refusal": cancellation_refusal, "backwards_research_refusal": backwards_research_refusal,
                "cross_fork_anchor_refusal": cross_fork_anchor_refusal, "cold_nonmonotone_refusal": cold_nonmonotone_refusal,
                "cold_fast_context_equal": cold == fast_context, "cold_c0_context_equal": cold_c0 == c0_context,
                "c0_profile_id": hex::encode(c0.id()), "c0_parent": hex::encode(fast_id),
                "c0_required_target": hex::encode(c0_context.required_target()),
                "c0_parent_cumulative_work_hex": hex::encode(c0_context.cumulative_work().bytes()),
            }),
        );
    }
}

#[test]
fn pnh1_fresh_complete_work_time_refusal_and_native_cold_readback() {
    native_complete_proof_campaign(Backend::Pnh1);
}

#[test]
fn pgh2_fresh_complete_work_time_refusal_and_native_cold_readback() {
    native_complete_proof_campaign(Backend::Pgh2);
}

#[test]
fn incremental_normal_complete_packets_match_retained_context_for_both_wires() {
    for backend in [Backend::Pnh1, Backend::Pgh2] {
        let directory = tempfile::tempdir().unwrap();
        let settings = backend.settings();
        let genesis = settings.genesis();
        let profile = Profile::for_node(&settings, Policy::FixedTarget).unwrap();
        let mut node = backend.open(directory.path(), settings);
        let packet = backend.make(&node, genesis, GENESIS_TIME + 10, 0);
        let block = backend.admit(&mut node, &packet).unwrap();
        let mut prefix = IncrementalWorkSchedule::new(&profile);
        let mut direct_callbacks = 0;
        let direct = packet
            .check_with_progress(&prefix.next_context().unwrap(), &mut || {
                direct_callbacks += 1;
                Ok(())
            })
            .unwrap();
        let mut append_callbacks = 0;
        let appended = packet
            .advance(&mut prefix, &mut || {
                append_callbacks += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(appended, direct);
        assert_eq!(prefix.tip(), block);
        assert_eq!(prefix.height(), 1);
        assert_eq!(prefix.max_ancestor_time(), GENESIS_TIME + 10);
        assert_eq!(append_callbacks, direct_callbacks + 1);
        assert_eq!(
            prefix.branch_clock_eligibility(GENESIS_TIME + 20),
            ClockEligibility::Eligible
        );
        assert_eq!(
            prefix.next_context().unwrap(),
            inspect_retained_branch(&node, &profile, block, &mut || Ok(())).unwrap()
        );
        assert_eq!(
            node.activate_observed(block, GENESIS_TIME + 20).unwrap(),
            block
        );
        assert_eq!(backend.retained(&node, block).encode(), packet.encode());
    }
}
