
/// M06 lower-layer transition test: an expired ACTIVE record is retained until
/// its available_until height, then open is permitted without a synthetic
/// terminal status write. The outer native executor owns actual signatures,
/// nonces and fees; this test does not claim to exercise that outer boundary.
#[test]
fn all_32_q4_slots_reject_early_reopen_and_allow_only_retention_safe_generation() {
    use trnm_protocol::qualified_work_task::lifecycle_v2::{DemandRevocationV2, DEMAND_SLOTS};

    let cfg = Config::installed_with_profiles("native-public-evaluation-dev-v1", PROFILE).unwrap();
    let model: Vec<u8> = (0..4096_u32).flat_map(|i| (i % 97).to_le_bytes()).collect();
    let input: Vec<u8> = (0..4096_u32).flat_map(|i| (i % 101).to_le_bytes()).collect();
    let boot = qualified_task_lifecycle::bootstrap_state(&cfg, &model, &input).unwrap();
    let envelope = |nonce: u64, tag: u8, payload: Vec<u8>| {
        let mut tx = Envelope {
            network: cfg.network,
            sender: boot.lease.requester,
            nonce,
            expiry: 3000,
            fee_limit: 100_000,
            tag,
            payload,
            signature: [0; 64],
        };
        tx.signature = sign(1, &tx.signing_digest().unwrap());
        tx
    };
    let mut state = Spy { state: boot.state.clone(), writes: 0 };
    for slot in 1..DEMAND_SLOTS {
        let mut fresh = boot.lease.clone();
        fresh.slot = slot;
        fresh.generation = u64::from(slot) + 1;
        fresh.revision = 1;
        fresh.not_before = 1;
        fresh.expires = 1001;
        fresh.available_until = 1101;
        fresh.demand_id = fresh.derived_demand_id();
        qualified_task_lifecycle::apply_verified_command(
            &mut state, &envelope(u64::from(slot), 18, fresh.encode().unwrap()), 1, &cfg,
        ).unwrap();
    }
    assert_eq!(
        state.state.keys().filter(|key| key.starts_with("qualified-demand-slot-v2:")).count(),
        usize::from(DEMAND_SLOTS),
    );
    assert_eq!(state.state[qualified_task_lifecycle::GENERATION_KEY], 32);

    // A 33rd distinct slot cannot be encoded as a legal QDL2 lease.
    let mut nonexistent = boot.lease.clone();
    nonexistent.slot = DEMAND_SLOTS;
    nonexistent.generation = 33;
    nonexistent.demand_id = nonexistent.derived_demand_id();
    assert!(nonexistent.encode().is_err());

    let mut replacement = boot.lease.clone();
    replacement.generation = 33;
    replacement.revision = 1;
    replacement.not_before = 1101;
    replacement.expires = 2101;
    replacement.available_until = 2201;
    replacement.demand_id = replacement.derived_demand_id();
    let open = envelope(32, 18, replacement.encode().unwrap());

    for revoked in [false, true] {
        let mut branch = Spy { state: state.state.clone(), writes: 0 };
        if revoked {
            let request = DemandRevocationV2 {
                network: cfg.network,
                parameters: cfg.parameters,
                slot: 0,
                demand_id: boot.lease.demand_id,
                requester: boot.lease.requester,
                expected_revision: boot.lease.revision,
            };
            qualified_task_lifecycle::apply_verified_command(
                &mut branch, &envelope(33, 20, request.encode().unwrap()), 2, &cfg,
            ).unwrap();
            assert_eq!(branch.state[&slot_key(0).unwrap()]["status"], "revoked");
        } else {
            assert_eq!(branch.state[&slot_key(0).unwrap()]["status"], "active");
        }
        let retained = branch.state.clone();
        branch.writes = 0;
        for height in [1000, 1100] {
            let error = qualified_task_lifecycle::apply_verified_command(
                &mut branch, &open, height, &cfg,
            ).unwrap_err();
            assert_eq!(error.to_string(), "TASK_RETAINED");
            assert_eq!(branch.state, retained);
            assert_eq!(branch.writes, 0);
        }
        qualified_task_lifecycle::apply_verified_command(
            &mut branch, &open, 1101, &cfg,
        ).unwrap();
        assert_eq!(branch.writes, 2); // exactly slot + generation key
        assert_eq!(branch.state[qualified_task_lifecycle::GENERATION_KEY], 33);
        assert_eq!(branch.state[&slot_key(0).unwrap()]["status"], "active");
        assert_eq!(branch.state[&slot_key(0).unwrap()]["opened_height"], 1101);
        assert_eq!(
            branch.state.keys().filter(|key| key.starts_with("qualified-demand-slot-v2:")).count(),
            usize::from(DEMAND_SLOTS),
        );
        // Simulated branch rollback to before the open, followed by exact replay.
        // This is not a real Node fork/reorg; separate native tests own that.
        let committed = branch.state.clone();
        let mut replay = Spy { state: retained, writes: 0 };
        qualified_task_lifecycle::apply_verified_command(&mut replay, &open, 1101, &cfg).unwrap();
        assert_eq!(replay.state, committed);
        assert_eq!(replay.writes, 2);
    }
}
