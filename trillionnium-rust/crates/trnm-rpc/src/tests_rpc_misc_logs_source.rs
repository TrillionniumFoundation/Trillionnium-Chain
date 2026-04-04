use super::*;

#[test]
fn discover_default_node_event_log_sources_includes_dynamic_node4_and_nightly_logs() {
    let root = unique_tmp_path("trnm-rpc-log-root", "dir");
    let run_dir = root.join("run");
    fs::create_dir_all(&run_dir).expect("create run dir");
    fs::write(run_dir.join("node1.log"), "").expect("write node1");
    fs::write(run_dir.join("node4.log"), "").expect("write node4");
    fs::write(run_dir.join("nightly-bft.log"), "").expect("write nightly");
    fs::write(run_dir.join("notes.txt"), "").expect("write txt");

    let got = discover_default_node_event_log_sources(&root);

    assert!(got.contains(&run_dir.join("node1.log")));
    assert!(got.contains(&run_dir.join("node4.log")));
    assert!(got.contains(&run_dir.join("nightly-bft.log")));
    assert!(!got.contains(&run_dir.join("notes.txt")));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_prefers_manifest_and_env_over_fixed_defaults() {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources", "dir");
    let run_dir = root.join("run");
    let manifest_dir = root.join("cfg");
    fs::create_dir_all(&run_dir).expect("create run dir");
    fs::create_dir_all(&manifest_dir).expect("create manifest dir");

    let env_log = root.join("env-node4.log");
    let manifest_log = manifest_dir.join("nightly.log");
    let manifest = manifest_dir.join("sources.txt");
    fs::write(&env_log, "").expect("write env log");
    fs::write(&manifest_log, "").expect("write manifest log");
    fs::write(&manifest, "# comment\nnightly.log\n").expect("write manifest");

    let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
    let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
    unsafe {
        std::env::set_var(
            NODE_EVENT_LOG_SOURCES_ENV,
            env_log.to_string_lossy().to_string(),
        );
        std::env::set_var(
            NODE_EVENT_LOG_MANIFEST_ENV,
            manifest.to_string_lossy().to_string(),
        );
    }

    let got = load_node_event_log_sources(&root);

    match prev_sources {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
    }
    match prev_manifest {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
    }

    assert!(got.contains(&env_log));
    assert!(got.contains(&manifest_log));
    assert_eq!(got.len(), 2, "custom sources should replace defaults");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_deduplicates_overlapping_manifest_and_relative_env_entries() {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources-dedupe", "dir");
    let manifest_dir = root.join("cfg");
    fs::create_dir_all(&manifest_dir).expect("create manifest dir");

    let shared_log = root.join("shared.log");
    let manifest = manifest_dir.join("sources.txt");
    fs::write(&shared_log, "").expect("write shared log");
    fs::write(&manifest, format!("{}\n", shared_log.display())).expect("write manifest");

    let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
    let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
    unsafe {
        std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, "shared.log");
        std::env::set_var(
            NODE_EVENT_LOG_MANIFEST_ENV,
            manifest.to_string_lossy().to_string(),
        );
    }

    let got = load_node_event_log_sources(&root);

    match prev_sources {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
    }
    match prev_manifest {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
    }

    assert_eq!(got, vec![shared_log], "overlapping sources should collapse to one path");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_accepts_comma_and_semicolon_separated_manifest_entries() {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources-manifest-delimiters", "dir");
    let archive_dir = root.join("archive");
    let manifest_dir = root.join("cfg/history");
    fs::create_dir_all(&archive_dir).expect("create archive dir");
    fs::create_dir_all(&manifest_dir).expect("create manifest dir");

    let first_log = archive_dir.join("node4.log");
    let second_log = archive_dir.join("node5.log");
    let manifest = manifest_dir.join("sources.txt");
    fs::write(&first_log, "").expect("write first archived log");
    fs::write(&second_log, "").expect("write second archived log");
    fs::write(
        &manifest,
        "\"../../archive/node4.log\", '../../archive/node5.log'; `../../archive/node4.log`\n",
    )
    .expect("write manifest");

    let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
    let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
    unsafe {
        std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV);
        std::env::set_var(
            NODE_EVENT_LOG_MANIFEST_ENV,
            manifest.to_string_lossy().to_string(),
        );
    }

    let got = load_node_event_log_sources(&root);

    match prev_sources {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
    }
    match prev_manifest {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
    }

    assert_eq!(
        got,
        vec![archive_dir.join("node4.log"), archive_dir.join("node5.log")],
        "historical replay manifests should accept comma/semicolon-separated path aliases and dedupe them"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_resolves_parent_relative_manifest_entries_from_manifest_dir() {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources-parent-relative", "dir");
    let archive_dir = root.join("archive");
    let manifest_dir = root.join("cfg/history");
    fs::create_dir_all(&archive_dir).expect("create archive dir");
    fs::create_dir_all(&manifest_dir).expect("create manifest dir");

    let archived_log = archive_dir.join("node4.log");
    let manifest = manifest_dir.join("sources.txt");
    fs::write(&archived_log, "").expect("write archived log");
    fs::write(&manifest, "../../archive/node4.log\n").expect("write manifest");

    let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
    let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
    unsafe {
        std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV);
        std::env::set_var(
            NODE_EVENT_LOG_MANIFEST_ENV,
            manifest.to_string_lossy().to_string(),
        );
    }

    let got = load_node_event_log_sources(&root);

    match prev_sources {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
    }
    match prev_manifest {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
    }

    assert_eq!(
        got,
        vec![archive_dir.join("node4.log")],
        "historical replay manifests must resolve relative entries from the manifest directory"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_deduplicates_lexically_equivalent_manifest_relative_entries() {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources-manifest-relative-dedupe", "dir");
    let archive_dir = root.join("archive");
    let manifest_dir = root.join("cfg/history");
    fs::create_dir_all(&archive_dir).expect("create archive dir");
    fs::create_dir_all(&manifest_dir).expect("create manifest dir");

    let archived_log = archive_dir.join("node4.log");
    let manifest = manifest_dir.join("sources.txt");
    fs::write(&archived_log, "").expect("write archived log");
    fs::write(
        &manifest,
        "../../archive/./node4.log\n../../archive/history/../node4.log\n",
    )
    .expect("write manifest");

    let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
    let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
    unsafe {
        std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV);
        std::env::set_var(
            NODE_EVENT_LOG_MANIFEST_ENV,
            manifest.to_string_lossy().to_string(),
        );
    }

    let got = load_node_event_log_sources(&root);

    match prev_sources {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
    }
    match prev_manifest {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
    }

    assert_eq!(
        got,
        vec![archive_dir.join("node4.log")],
        "historical replay manifests should dedupe lexically equivalent relative aliases before read-model expansion"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_resolves_relative_manifest_env_from_root_before_replay_expansion() {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources-relative-manifest-env", "dir");
    let archive_dir = root.join("archive");
    let manifest_dir = root.join("cfg/history");
    fs::create_dir_all(&archive_dir).expect("create archive dir");
    fs::create_dir_all(&manifest_dir).expect("create manifest dir");

    let archived_log = archive_dir.join("node4.log");
    let manifest = manifest_dir.join("sources.txt");
    fs::write(&archived_log, "").expect("write archived log");
    fs::write(&manifest, "../../archive/node4.log\n").expect("write manifest");

    let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
    let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
    unsafe {
        std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV);
        std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, "cfg/history/sources.txt");
    }

    let got = load_node_event_log_sources(&root);

    match prev_sources {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
    }
    match prev_manifest {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
    }

    assert_eq!(
        got,
        vec![archive_dir.join("node4.log")],
        "relative historical replay manifest env paths must resolve from the RPC root before manifest entries are expanded"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_accepts_bom_wrapped_manifest_env_with_comment_suffix() {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources-wrapped-manifest-env", "dir");
    let archive_dir = root.join("archive");
    let manifest_dir = root.join("cfg/history");
    fs::create_dir_all(&archive_dir).expect("create archive dir");
    fs::create_dir_all(&manifest_dir).expect("create manifest dir");

    let archived_log = archive_dir.join("node4.log");
    let manifest = manifest_dir.join("sources.txt");
    fs::write(&archived_log, "").expect("write archived log");
    fs::write(&manifest, "../../archive/node4.log\n").expect("write manifest");

    let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
    let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
    unsafe {
        std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV);
        std::env::set_var(
            NODE_EVENT_LOG_MANIFEST_ENV,
            "\u{feff}  \"cfg/history/sources.txt\"# archived replay note ",
        );
    }

    let got = load_node_event_log_sources(&root);

    match prev_sources {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
    }
    match prev_manifest {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
    }

    assert_eq!(
        got,
        vec![archive_dir.join("node4.log")],
        "wrapped historical replay manifest env paths should normalize before manifest expansion"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_deduplicates_lexically_equivalent_relative_env_entries() {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources-env-relative", "dir");
    let history_dir = root.join("history");
    fs::create_dir_all(&history_dir).expect("create history dir");

    let shared_log = root.join("shared.log");
    fs::write(&shared_log, "").expect("write shared log");

    let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
    let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
    unsafe {
        std::env::set_var(
            NODE_EVENT_LOG_SOURCES_ENV,
            "history/../shared.log,shared.log",
        );
        std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV);
    }

    let got = load_node_event_log_sources(&root);

    match prev_sources {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
    }
    match prev_manifest {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
    }

    assert_eq!(
        got,
        vec![shared_log],
        "historical replay env entries should dedupe after lexical normalization"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_falls_back_to_default_logs_when_manifest_and_env_only_contain_comments(
) {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources-comment-only-fallback", "dir");
    let run_dir = root.join("run");
    let manifest_dir = root.join("cfg/history");
    fs::create_dir_all(&run_dir).expect("create run dir");
    fs::create_dir_all(&manifest_dir).expect("create manifest dir");

    let default_log = run_dir.join("event-field-check.log");
    let manifest = manifest_dir.join("sources.txt");
    fs::write(&default_log, "").expect("write default log");
    fs::write(&manifest, "# archived replay note only\n\n").expect("write manifest");

    let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
    let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
    unsafe {
        std::env::set_var(
            NODE_EVENT_LOG_SOURCES_ENV,
            "  # operator replay note only ;   # another note ",
        );
        std::env::set_var(
            NODE_EVENT_LOG_MANIFEST_ENV,
            manifest.to_string_lossy().to_string(),
        );
    }

    let got = load_node_event_log_sources(&root);

    match prev_sources {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
    }
    match prev_manifest {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
    }

    assert_eq!(
        got,
        vec![default_log],
        "comment-only historical replay manifest/env inputs should fall back to durable default log discovery"
    );

    let _ = fs::remove_dir_all(root);
}
