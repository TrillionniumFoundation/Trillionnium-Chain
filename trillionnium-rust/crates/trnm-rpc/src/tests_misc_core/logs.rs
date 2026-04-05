pub(crate) use super::*;

#[test]
fn read_log_tail_returns_recent_lines() {
    let tmp = unique_tmp_path("trnm-rpc-tail-test", "log");
    fs::write(
        &tmp,
        "line1
line2
[event] event_type=commit task_id=1 tx_id=1 block_height=1
",
    )
    .expect("write temp log");
    let tail = read_log_tail(&tmp, 80).expect("tail text");
    assert!(tail.contains("[event] event_type=commit"));
    let _ = fs::remove_file(tmp);
}

#[test]
fn read_log_tail_keeps_first_line_when_tail_starts_on_newline_boundary() {
    let tmp = unique_tmp_path("trnm-rpc-tail-boundary", "log");
    let content = "line1\n[event] event_type=commit task_id=7 tx_id=11 block_height=3\n";
    fs::write(&tmp, content).expect("write temp log");

    let start = "line1\n".len() as u64;
    let tail_bytes = content.len() as u64 - start;
    let tail = read_log_tail(&tmp, tail_bytes).expect("tail text");

    assert!(tail.starts_with("[event] event_type=commit"));
    let _ = fs::remove_file(tmp);
}

#[test]
fn read_log_tail_tolerates_non_utf8_bytes() {
    let tmp = unique_tmp_path("trnm-rpc-tail-binary", "log");
    let mut bytes = vec![0xff, 0xfe, b'\n'];
    bytes.extend_from_slice(b"[event] event_type=commit task_id=9 tx_id=1 block_height=1\n");
    fs::write(&tmp, bytes).expect("write temp binary log");

    let tail = read_log_tail(&tmp, 1024).expect("tail text");
    assert!(tail.contains("[event] event_type=commit task_id=9"));
    let _ = fs::remove_file(tmp);
}

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
fn load_node_event_log_sources_deduplicates_lexically_equivalent_absolute_entries() {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources-absolute-dedupe", "dir");
    let cfg_dir = root.join("cfg");
    fs::create_dir_all(&cfg_dir).expect("create cfg dir");

    let shared_log = root.join("shared.log");
    let manifest = cfg_dir.join("sources.txt");
    fs::write(&shared_log, "").expect("write shared log");
    fs::write(
        &manifest,
        format!("{}\n", root.join("history/../shared.log").display()),
    )
    .expect("write manifest");

    let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
    let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
    unsafe {
        std::env::set_var(
            NODE_EVENT_LOG_SOURCES_ENV,
            root.join("./shared.log").to_string_lossy().to_string(),
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
        vec![shared_log],
        "lexically equivalent absolute historical log sources should dedupe to one path"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_resolves_wrapped_relative_manifest_env_from_root() {
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
        std::env::set_var(
            NODE_EVENT_LOG_MANIFEST_ENV,
            "  \"cfg/history/sources.txt\"   # operator replay note ",
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
        vec![archived_log],
        "wrapped relative manifest env paths with inline comments should still resolve from the RPC root"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_unwraps_quoted_manifest_entries_for_historical_replay() {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources-manifest-quoted", "dir");
    let archive_dir = root.join("archive");
    let manifest_dir = root.join("cfg/history");
    fs::create_dir_all(&archive_dir).expect("create archive dir");
    fs::create_dir_all(&manifest_dir).expect("create manifest dir");

    let archived_log = archive_dir.join("node4.log");
    let second_archived_log = archive_dir.join("node5.log");
    let manifest = manifest_dir.join("sources.txt");
    fs::write(&archived_log, "").expect("write archived log");
    fs::write(&second_archived_log, "").expect("write second archived log");
    fs::write(
        &manifest,
        "\"../../archive/node4.log\"\n'../../archive/node5.log'\n`../../archive/node4.log`\n",
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
        "historical replay manifest entries should unwrap quote-like wrappers and dedupe to canonical log sources"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_accepts_carriage_return_manifest_entries_for_historical_replay() {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources-manifest-crlf", "dir");
    let archive_dir = root.join("archive");
    let manifest_dir = root.join("cfg/history");
    fs::create_dir_all(&archive_dir).expect("create archive dir");
    fs::create_dir_all(&manifest_dir).expect("create manifest dir");

    let archived_log = archive_dir.join("node4.log");
    let second_archived_log = archive_dir.join("node5.log");
    let manifest = manifest_dir.join("sources.txt");
    fs::write(&archived_log, "").expect("write archived log");
    fs::write(&second_archived_log, "").expect("write second archived log");
    fs::write(
        &manifest,
        "\"../../archive/node4.log\"# replay note\r`../../archive/node5.log`# archived replay note\r",
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
        "historical replay manifests should keep carriage-return-separated wrapped entries while dropping attached comments"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_tolerates_bom_wrapped_manifest_env_for_historical_replay() {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources-manifest-env-bom", "dir");
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
            "\u{feff}  \"cfg/history/sources.txt\"   # archived replay note ",
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
        vec![archived_log],
        "historical replay manifest env values should tolerate UTF-8 BOM wrappers before resolving from the RPC root"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_unwraps_quoted_env_entries_for_historical_replay() {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources-quoted-env", "dir");
    fs::create_dir_all(&root).expect("create root dir");

    let shared_log = root.join("shared.log");
    fs::write(&shared_log, "").expect("write shared log");

    let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
    let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
    unsafe {
        std::env::set_var(
            NODE_EVENT_LOG_SOURCES_ENV,
            "  \"shared.log\" ; `./shared.log` ; \"# ignored wrapped comment\" ; `# ignored too`  ",
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
        "quoted historical replay env entries should resolve to canonical log sources"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_accepts_carriage_return_env_entries_with_bom_wrapped_comments() {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources-env-crlf-bom-comments", "dir");
    fs::create_dir_all(&root).expect("create root dir");

    let node4_log = root.join("node4.log");
    let node5_log = root.join("node5.log");
    fs::write(&node4_log, "").expect("write node4 log");
    fs::write(&node5_log, "").expect("write node5 log");

    let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
    let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
    unsafe {
        std::env::set_var(
            NODE_EVENT_LOG_SOURCES_ENV,
            "\"node4.log\"  \u{feff}# replay note\r`./node5.log`  \u{feff}# archived replay note\r",
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
        vec![node4_log, node5_log],
        "carriage-return-separated historical replay env aliases should keep wrapped paths while dropping BOM-spaced attached comments"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_latest_node_events_reads_events_from_configured_node4_source() {
    let _guard = lock_env();
    let path = unique_tmp_path("trnm-rpc-node4", "log");
    fs::write(
            &path,
            "[event] event_type=commit task_id=44 tx_id=7 block_height=9 actor=node4 from_status=ASSIGNED to_status=COMPLETED state_root=abc signer=node4\n",
        )
        .expect("write node4 log");

    let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
    let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
    unsafe {
        std::env::set_var(
            NODE_EVENT_LOG_SOURCES_ENV,
            path.to_string_lossy().to_string(),
        );
        std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV);
    }

    let got = load_latest_node_events();

    match prev_sources {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
    }
    match prev_manifest {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
    }

    assert!(got.iter().any(|evt| {
        evt.task_id == 44
            && evt.tx_id == 7
            && evt.block_height == 9
            && evt.actor == "node4"
            && evt.signer.as_deref() == Some("node4")
    }));

    let _ = fs::remove_file(path);
}
