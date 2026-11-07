//! Real SQLite owner controls; no authorization stub or native qualification.
use super::*;
use crate::ingress::pq_network::{PqNetworkPolicy, PqTlsPins};
use openssl::pkey::{KeyType, PKey};

fn material(generation: u64) -> (Settings, PqNetworkPolicy) {
    let settings = Settings::development(Some(1_700_000_000)).unwrap();
    let spki = |seed| {
        PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32])
            .unwrap()
            .public_key_to_der()
            .unwrap()
    };
    let policy = PqNetworkPolicy::new_tls13(
        &settings,
        &spki(71),
        generation,
        [spki(72), spki(73)],
        PqTlsPins::new([91; 32], "localhost".into()).unwrap(),
    )
    .unwrap();
    (settings, policy)
}
fn provision(path: &Path, settings: &Settings, policy: &PqNetworkPolicy) {
    drop(Node::open_with_pq_network(path, settings.clone(), 1, policy).unwrap());
}
fn with_hook(
    path: &Path,
    settings: Settings,
    policy: &PqNetworkPolicy,
    existing: bool,
    hook: &mut Hook<'_>,
) -> Result<Node> {
    Node::open_selected_mode(
        path,
        settings,
        1,
        Some(hook),
        NativeOwners {
            policy: None,
            mining: None,
            continuous: None,
            pq_network: Some(policy.canonical().to_vec()),
            pq_witness: None,
        },
        StateBackend::PqNetworkV2,
        if existing {
            SelectedOpen::ExistingPqOwner
        } else {
            SelectedOpen::InitializeOrRecover {
                growth_observation_only: false,
            }
        },
    )
}
fn durable_files(path: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter_map(|entry| {
            let name = entry.file_name().into_string().unwrap();
            // A connection can transiently open SQLite's original WAL/SHM handles.
            // These controls compare initialized database/owner/intent bytes.
            if matches!(name.as_str(), "native.sqlite-wal" | "native.sqlite-shm") {
                return None;
            }
            Some((name, fs::read(entry.path()).unwrap()))
        })
        .collect()
}

#[test]
fn existing_pq_owner_reopens_the_actual_initialized_connection() {
    let root = tempfile::tempdir().unwrap();
    let (settings, policy) = material(1);
    provision(root.path(), &settings, &policy);
    let prior = durable_files(root.path());
    let node =
        Node::open_existing_with_pq_network(root.path(), settings.clone(), 1, &policy).unwrap();
    node.check_pq_network_policy(&policy).unwrap();
    assert_eq!(node.settings().genesis(), settings.genesis());
    assert_eq!(node.active().unwrap().0, settings.genesis());
    drop(node);
    assert_eq!(durable_files(root.path()), prior);
    assert!(!root.path().join("initializing.json").exists());
    drop(Node::open_with_pq_network(root.path(), settings, 1, &policy).unwrap());
}

#[test]
fn existing_pq_owner_never_creates_missing_root_lock_or_empty_schema() {
    let outer = tempfile::tempdir().unwrap();
    let (settings, policy) = material(1);
    let missing = outer.path().join("absent");
    assert!(Node::open_existing_with_pq_network(&missing, settings.clone(), 1, &policy).is_err());
    assert!(!missing.exists());
    let store = outer.path().join("store");
    provision(&store, &settings, &policy);
    fs::remove_file(store.join("owner.lock")).unwrap();
    let prior = durable_files(&store);
    assert!(Node::open_existing_with_pq_network(&store, settings.clone(), 1, &policy).is_err());
    assert_eq!(durable_files(&store), prior);
    let empty = outer.path().join("empty");
    fs::create_dir(&empty).unwrap();
    fs::write(empty.join("owner.lock"), []).unwrap();
    fs::write(empty.join("native.sqlite"), []).unwrap();
    let prior = durable_files(&empty);
    let error = Node::open_existing_with_pq_network(&empty, settings, 1, &policy)
        .err()
        .unwrap();
    assert!(error.to_string().contains("PQ_EXISTING_OWNER_INITIALIZED"));
    assert_eq!(durable_files(&empty), prior);
}

#[test]
fn existing_pq_owner_refuses_matching_initialization_but_original_api_can_recover() {
    let root = tempfile::tempdir().unwrap();
    let (settings, policy) = material(1);
    let mut cut = |name: &str| -> Result<()> {
        if name == "init-intent" {
            Err("EXPECTED_INITIALIZATION_CUT".into())
        } else {
            Ok(())
        }
    };
    let error = with_hook(root.path(), settings.clone(), &policy, false, &mut cut)
        .err()
        .unwrap();
    assert!(error.to_string().contains("EXPECTED_INITIALIZATION_CUT"));
    assert!(root.path().join("initializing.json").is_file());
    fs::write(root.path().join("native.sqlite"), []).unwrap();
    let prior = durable_files(root.path());
    let error = Node::open_existing_with_pq_network(root.path(), settings.clone(), 1, &policy)
        .err()
        .unwrap();
    assert!(error
        .to_string()
        .contains("PQ_EXISTING_OWNER_INITIALIZATION"));
    assert_eq!(durable_files(root.path()), prior);
    // The unchanged old public API still completes its exact retained intent.
    provision(root.path(), &settings, &policy);
    assert!(!root.path().join("initializing.json").exists());
    drop(Node::open_existing_with_pq_network(root.path(), settings, 1, &policy).unwrap());
}

#[test]
fn existing_pq_owner_refuses_database_loss_or_replacement_before_open() {
    for replace in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (settings, policy) = material(1);
        provision(root.path(), &settings, &policy);
        let path = root.path().join("native.sqlite");
        let bytes = fs::read(&path).unwrap();
        let mut reached = false;
        let mut cut = |name: &str| -> Result<()> {
            if name == "existing-owner-before-open" {
                reached = true;
                fs::rename(&path, root.path().join("held-old.sqlite"))?;
                if replace {
                    fs::write(&path, &bytes)?;
                }
            }
            Ok(())
        };
        let result = with_hook(root.path(), settings, &policy, true, &mut cut);
        assert!(reached && result.is_err());
        if replace {
            assert!(result
                .err()
                .unwrap()
                .to_string()
                .contains("NAMESPACE_CHANGED"));
            assert_eq!(fs::read(&path).unwrap(), bytes);
        } else {
            assert!(
                !path.exists(),
                "no CREATE after the original existence check"
            );
        }
        assert_eq!(
            fs::read(root.path().join("held-old.sqlite")).unwrap(),
            bytes
        );
        assert!(!root.path().join("initializing.json").exists());
    }
}

#[test]
fn existing_pq_owner_refuses_changed_bindings_after_connection_validation() {
    for fault in 0..4 {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("store");
        let (settings, policy) = material(1);
        provision(&directory, &settings, &policy);
        let bytes = fs::read(directory.join("native.sqlite")).unwrap();
        let mut reached = false;
        let mut cut = |name: &str| -> Result<()> {
            if name == "existing-owner-validated" {
                reached = true;
                match fault {
                    0 => {
                        fs::rename(
                            directory.join("native.sqlite"),
                            directory.join("old.sqlite"),
                        )?;
                        fs::write(directory.join("native.sqlite"), &bytes)?;
                    }
                    1 => fs::write(directory.join("initializing.json"), b"external fault")?,
                    2 => {
                        fs::rename(directory.join("owner.lock"), directory.join("old.lock"))?;
                        fs::write(directory.join("owner.lock"), b"replacement")?;
                    }
                    3 => {
                        fs::rename(&directory, root.path().join("held-old-root"))?;
                        fs::create_dir(&directory)?;
                        fs::write(directory.join("sentinel"), b"replacement root")?;
                    }
                    _ => unreachable!(),
                }
            }
            Ok(())
        };
        let error = with_hook(&directory, settings, &policy, true, &mut cut)
            .err()
            .unwrap();
        assert!(reached);
        let expected = match fault {
            0 | 3 => "NAMESPACE_CHANGED",
            1 => "PQ_EXISTING_OWNER_INITIALIZATION",
            2 => "OWNER_REPLACED",
            _ => unreachable!(),
        };
        assert!(error.to_string().contains(expected), "{error}");
        if fault == 3 {
            assert_eq!(
                fs::read(directory.join("sentinel")).unwrap(),
                b"replacement root"
            );
            assert!(!directory.join("native.sqlite").exists());
            assert!(!directory.join("owner.lock").exists());
        } else {
            assert_eq!(fs::read(directory.join("native.sqlite")).unwrap(), bytes);
            if fault == 1 {
                assert_eq!(
                    fs::read(directory.join("initializing.json")).unwrap(),
                    b"external fault"
                );
            } else {
                assert!(!directory.join("initializing.json").exists());
            }
            if fault == 2 {
                assert_eq!(
                    fs::read(directory.join("owner.lock")).unwrap(),
                    b"replacement"
                );
            }
        }
    }
}

#[test]
fn existing_pq_owner_rejects_link_special_file_and_incompatible_owner_without_repair() {
    let (settings, policy) = material(1);
    for fault in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("store");
        provision(&directory, &settings, &policy);
        let path = directory.join("native.sqlite");
        let saved = root.path().join("saved.sqlite");
        fs::rename(&path, &saved).unwrap();
        let socket = match fault {
            0 => {
                std::os::unix::fs::symlink(&saved, &path).unwrap();
                None
            }
            1 => {
                fs::hard_link(&saved, &path).unwrap();
                None
            }
            2 => Some(std::os::unix::net::UnixListener::bind(&path).unwrap()),
            _ => unreachable!(),
        };
        let bytes = fs::read(&saved).unwrap();
        assert!(
            Node::open_existing_with_pq_network(&directory, settings.clone(), 1, &policy).is_err()
        );
        assert_eq!(fs::read(&saved).unwrap(), bytes);
        assert!(!directory.join("initializing.json").exists());
        drop(socket);
    }
    let root = tempfile::tempdir().unwrap();
    provision(root.path(), &settings, &policy);
    let prior = durable_files(root.path());
    let (_, different) = material(2);
    let error = Node::open_existing_with_pq_network(root.path(), settings, 1, &different)
        .err()
        .unwrap();
    assert!(error.to_string().contains("PQ_NETWORK_POLICY_REQUIRED"));
    assert_eq!(durable_files(root.path()), prior);
}
