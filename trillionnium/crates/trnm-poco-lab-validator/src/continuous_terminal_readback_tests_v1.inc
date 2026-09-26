// The genuine live construction uses the existing deployed-owner harness.
// The new terminal readback calls below execute on the default test thread.
#[inline(never)]
fn terminal_readback_fixture_v1() -> Box<TakeoverPhaseHarnessV0> {
    on_bounded_takeover_owner_stack_v0(|| {
        let lifetime =
            ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(3, 0, 3, 0).unwrap();
        let mut harness = takeover_phase_harness_with_profile_v0(4, lifetime, 3);
        for _ in 0..3 {
            let proposal = proposal_for_takeover_v0(&harness);
            drive_parallel_deployed_authority_round_v0(&mut harness.authorities, proposal).unwrap();
        }
        Box::new(harness)
    })
}

#[test]
fn consumed_terminal_fresh_readback_rejects_replaced_namespaces_and_latches_v1() {
    let mut harness = terminal_readback_fixture_v1();
    let targets = [
        "application/application.sqlite3",
        "validation/validation.sqlite3",
        "target-safety/safety.sqlite3",
        "checkpoint/checkpoint.sqlite3",
    ];
    for (index, authority) in harness.authorities.drain(..).enumerate() {
        let root = harness
            ._temp
            .path()
            .join(format!("takeover-authority-{index:03}"));
        let before = targets
            .iter()
            .map(|path| fs::read(root.join(path)).unwrap())
            .collect::<Vec<_>>();
        let mut terminal = authority.into_terminal_owner_v0().unwrap();
        let expected = *terminal.facts_v0();
        assert_eq!(
            expected.node_v0().finalized_height_v0(),
            harness.ordinary_start_height
        );
        assert_eq!(terminal.confirm_terminal_cut_v1().unwrap(), &expected);
        assert_eq!(terminal.confirm_terminal_cut_v1().unwrap(), &expected);
        for (path, bytes) in targets.iter().zip(before) {
            assert_eq!(
                fs::read(root.join(path)).unwrap(),
                bytes,
                "readback must not write {path}"
            );
        }
        let path = root.join(targets[index]);
        let original = path.with_extension("original");
        fs::rename(&path, &original).unwrap();
        fs::copy(&original, &path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            terminal.confirm_terminal_cut_v1().is_err(),
            "replacement must reject {}",
            targets[index]
        );
        fs::remove_file(&path).unwrap();
        fs::rename(&original, &path).unwrap();
        let error = terminal.confirm_terminal_cut_v1().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("terminal owner readback is fenced"),
            "{error}"
        );
        assert_eq!(
            terminal.facts_v0(),
            &expected,
            "failure cannot adopt replacement facts"
        );
    }
}
