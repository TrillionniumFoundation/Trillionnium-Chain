use super::*;

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
