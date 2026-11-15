//! The native owner uses the same account-scope decision as the M06 executor.
//! These tests do not qualify a production profile or change a stored namespace.
use super::*;
use serde_json::json;

fn invalid_settings(baseline: &Settings) -> Vec<(String, Settings, &'static str)> {
    let mut cases = Vec::new();
    for field in ["production_activation", "not_mainnet", "coin_atomic_unit"] {
        let wrong = match field {
            "production_activation" => json!(true),
            "not_mainnet" => json!(false),
            "coin_atomic_unit" => json!("market-value"),
            _ => unreachable!(),
        };
        for (label, value) in [
            ("wrong", Some(wrong)),
            ("null", Some(Value::Null)),
            ("missing", None),
        ] {
            let mut settings = baseline.clone();
            let params = settings.app.params.as_object_mut().unwrap();
            if let Some(value) = value {
                params.insert(field.into(), value);
            } else {
                params.remove(field);
            }
            cases.push((
                format!("{field}-{label}"),
                settings,
                "ACCOUNT_DEVELOPMENT_SCOPE_REQUIRED",
            ));
        }
    }
    for field in ["account_authorization_profile", "native_pq_profile"] {
        for (label, value) in [
            ("null", Value::Null),
            ("unknown", json!("unavailable-pq-profile")),
        ] {
            let mut settings = baseline.clone();
            settings.app.params[field] = value;
            cases.push((
                format!("{field}-{label}"),
                settings,
                "PQ_ACCOUNT_PROFILE_UNAVAILABLE",
            ));
        }
    }
    cases
}

fn expect_open_refusal(result: Result<Node>, expected: &str) {
    let error = result.err().expect("invalid Settings opened a Node");
    assert_eq!(error.to_string(), expected);
    // Invalid startup input does not establish damage to an existing owner.
    assert!(!error.requires_owner_stop());
}

fn namespace_bytes(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            (
                PathBuf::from(entry.file_name()),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

#[test]
fn invalid_account_scope_never_creates_legacy_or_authenticated_namespace() {
    let root = tempfile::tempdir().unwrap();
    let baseline = Settings::development(None).unwrap();
    for (label, settings, expected) in invalid_settings(&baseline) {
        for authenticated in [false, true] {
            let path = root.path().join(format!("{label}-{authenticated}"));
            let result = if authenticated {
                Node::open_with_authenticated_state(&path, settings.clone(), 1)
            } else {
                Node::open(&path, settings.clone(), 1)
            };
            expect_open_refusal(result, expected);
            assert!(!path.exists(), "invalid {label} created a namespace");
        }
    }
}

#[test]
fn cold_open_rechecks_account_scope_without_rewriting_existing_storage() {
    let root = tempfile::tempdir().unwrap();
    for authenticated in [false, true] {
        let path = root.path().join(format!("existing-{authenticated}"));
        let baseline = Settings::development(None).unwrap();
        let node = if authenticated {
            Node::open_with_authenticated_state(&path, baseline.clone(), 1).unwrap()
        } else {
            Node::open(&path, baseline.clone(), 1).unwrap()
        };
        let initial = node.read_active().unwrap();
        drop(node);
        let original_bytes = namespace_bytes(&path);
        for (label, settings, expected) in invalid_settings(&baseline) {
            // A caller cannot keep the old DB identity and merely relabel its
            // mutable configuration as production or an unavailable PQ profile.
            assert_eq!(settings.network(), baseline.network());
            assert_eq!(settings.parameters(), baseline.parameters());
            assert_eq!(settings.genesis(), baseline.genesis());
            let result = if authenticated {
                Node::open_with_authenticated_state(&path, settings, 1)
            } else {
                Node::open(&path, settings, 1)
            };
            expect_open_refusal(result, expected);
            assert_eq!(namespace_bytes(&path), original_bytes, "{label}");
        }
        let node = if authenticated {
            Node::open_with_authenticated_state(&path, baseline, 1).unwrap()
        } else {
            Node::open(&path, baseline, 1).unwrap()
        };
        assert_eq!(node.read_active().unwrap(), initial);
    }
}

#[test]
fn warm_owner_rechecks_current_account_scope_before_reads_recovery_and_activation() {
    let root = tempfile::tempdir().unwrap();
    for authenticated in [false, true] {
        let path = root.path().join(format!("warm-{authenticated}"));
        let baseline = Settings::development(None).unwrap();
        let mut node = if authenticated {
            Node::open_with_authenticated_state(&path, baseline.clone(), 1).unwrap()
        } else {
            Node::open(&path, baseline.clone(), 1).unwrap()
        };
        let initial = node.read_active().unwrap();
        let initial_pair = node.active().unwrap();
        let changes = node.db.total_changes();
        for (label, settings, expected) in invalid_settings(&baseline) {
            // Test-only access simulates an in-process configuration mistake;
            // public callers cannot mutate the Node's private Settings.
            node.settings = settings;
            for error in [
                node.read_active().unwrap_err(),
                node.recover().unwrap_err(),
                node.activate(initial_pair.0).unwrap_err(),
            ] {
                assert_eq!(error.to_string(), expected, "{label}");
                assert_eq!(error.kind(), crate::ErrorKind::LocalStructure, "{label}");
                assert!(error.requires_owner_stop(), "{label}");
            }
            // A matching diagnostic string, including one from an authenticated
            // peer, cannot manufacture this local owner-stop classification.
            assert!(!Error::from(expected).requires_owner_stop(), "{label}");
            assert!(!Error::remote(expected).requires_owner_stop(), "{label}");
            assert_eq!(node.active().unwrap(), initial_pair, "{label}");
            assert_eq!(node.db.total_changes(), changes, "{label}");
            node.settings = baseline.clone();
            assert_eq!(node.read_active().unwrap(), initial, "{label}");
        }
    }
}

#[test]
fn growth_owner_rechecks_scope_before_open_recovery_and_noop_activation() {
    // Use the same real continuity/growth genesis as the existing growth tests;
    // no packet mining or complete-state adapter is needed for this boundary.
    let baseline = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap()
    .with_permanent_account_growth_v2("account-profile-scope-test")
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("existing-growth");
    let mut node = Node::open_with_permanent_account_growth_v2(&path, baseline.clone()).unwrap();
    let initial_pair = node.active().unwrap();
    let initial = node.growth_observe(initial_pair.0).unwrap().commitment;
    let changes = node.db.total_changes();

    for (label, settings, expected) in invalid_settings(&baseline) {
        let fresh = root.path().join(format!("fresh-{label}"));
        expect_open_refusal(
            Node::open_with_permanent_account_growth_v2(&fresh, settings.clone()),
            expected,
        );
        assert!(
            !fresh.exists(),
            "invalid {label} created a growth namespace"
        );

        node.settings = settings;
        for error in [
            node.growth_observe(initial_pair.0).unwrap_err(),
            node.recover().unwrap_err(),
            // This public entry selects the separate growth_activate branch.
            // Even the already-active target must recheck the current owner.
            node.activate(initial_pair.0).unwrap_err(),
            node.activate_with_fault(initial_pair.0, None).unwrap_err(),
            node.growth_activate_with_progress(initial_pair.0, &|_| Ok(()))
                .unwrap_err(),
        ] {
            assert_eq!(error.to_string(), expected, "{label}");
            assert_eq!(error.kind(), crate::ErrorKind::LocalStructure, "{label}");
            assert!(error.requires_owner_stop(), "{label}");
        }
        assert_eq!(node.active().unwrap(), initial_pair, "{label}");
        assert_eq!(node.db.total_changes(), changes, "{label}");
        node.settings = baseline.clone();
        assert_eq!(
            node.growth_observe(initial_pair.0).unwrap().commitment,
            initial,
            "{label}",
        );
    }

    drop(node);
    let original_bytes = namespace_bytes(&path);
    for (label, settings, expected) in invalid_settings(&baseline) {
        assert_eq!(settings.network(), baseline.network());
        assert_eq!(settings.parameters(), baseline.parameters());
        assert_eq!(settings.genesis(), baseline.genesis());
        expect_open_refusal(
            Node::open_with_permanent_account_growth_v2(&path, settings),
            expected,
        );
        assert_eq!(namespace_bytes(&path), original_bytes, "{label}");
    }
    let node = Node::open_with_permanent_account_growth_v2(&path, baseline).unwrap();
    assert_eq!(node.active().unwrap(), initial_pair);
    assert_eq!(
        node.growth_observe(initial_pair.0).unwrap().commitment,
        initial
    );
}
