use super::*;

fn arguments() -> BTreeMap<String, String> {
    [
        ("--development", "true"),
        ("--native-peer", "127.0.0.1:20001"),
        ("--history-peer", "127.0.0.1:20002"),
        ("--initial-sequence", "1"),
        ("--campaign", "/not-opened-campaign"),
        ("--store", "/not-opened-node"),
        ("--packet", "/not-opened-packet"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .collect()
}

#[test]
fn create_epoch_includes_preparse_time_and_serve_resume_have_no_fresh_epoch() {
    let started = Instant::now().checked_sub(Duration::from_secs(61)).unwrap();
    let plan = capture_create("pq-parent-create", started)
        .unwrap()
        .unwrap();
    assert_eq!(plan.started, started);
    assert_eq!(plan.deadline, started + Duration::from_secs(60));
    assert_eq!(plan.max_submit_attempts, 3);
    assert_eq!(plan.max_calls, 16);
    assert_eq!(plan.max_parent_packets, 1);
    for command in [
        "pq-parent-resume",
        "pq-parent-tls-serve",
        "pq-tls-serve",
        "serve",
    ] {
        assert!(capture_create(command, started).unwrap().is_none());
    }
}

#[test]
fn expired_preparse_create_epoch_refuses_before_any_protected_input_or_owner() {
    let started = Instant::now().checked_sub(Duration::from_secs(61)).unwrap();
    let plan = capture_create("pq-parent-create", started).unwrap();
    let error = run("pq-parent-create", &arguments(), plan).unwrap_err();
    assert_eq!(error.to_string(), "SUBMIT_RECOVERY_DEADLINE");
}

#[test]
fn resume_rejects_each_new_epoch_or_capacity_override_before_paths() {
    for key in [
        "--submit-deadline-ms",
        "--submit-attempts",
        "--submit-call-cap",
        "--submit-parent-depth",
    ] {
        let mut args = arguments();
        args.insert(key.to_owned(), "1".to_owned());
        let error = run("pq-parent-resume", &args, None).unwrap_err();
        assert_eq!(error.to_string(), "PQ_PARENT_OPTION");
    }
}
