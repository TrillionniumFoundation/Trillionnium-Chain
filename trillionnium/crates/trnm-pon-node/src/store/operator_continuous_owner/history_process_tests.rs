// Real independently terminated native process, original known-prefix residual
// settlement, and a fresh native process. No physical-power-loss claim.
use super::*;
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildConfiguration {
    schema: String,
    store: PathBuf,
    inputs: policy::Inputs,
    page: Vec<u8>,
    tip: String,
    after: String,
    validation_operation_id: String,
    activation_operation_id: String,
    selection: Option<HistoryRecoverySelection>,
    prior_validation: Option<Value>,
    prior_activation: Option<Value>,
}

fn sha(raw: &[u8]) -> String {
    crate::operator_task_policy::digest_bytes(raw)
}
fn emit(path: &Path, value: &Value) {
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = path.with_extension("pending");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .unwrap();
    file.write_all(&serde_json::to_vec(value).unwrap()).unwrap();
    file.sync_all().unwrap();
    drop(file);
    fs::rename(&temporary, path).unwrap();
    fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}
fn checked_child_config() -> (ChildConfiguration, PathBuf) {
    let path = PathBuf::from(
        std::env::var("TRNM_HISTORY_PROCESS_CONFIG")
            .expect("explicit child configuration required"),
    );
    assert!(path.is_absolute());
    let raw = fs::read(&path).unwrap();
    assert_eq!(
        sha(&raw),
        std::env::var("TRNM_HISTORY_PROCESS_CONFIG_SHA256").unwrap()
    );
    let config: ChildConfiguration = serde_json::from_slice(&raw).unwrap();
    assert_eq!(config.schema, "actual-history-native-process-fixture-v1");
    let output = PathBuf::from(std::env::var("TRNM_HISTORY_PROCESS_OUTPUT").unwrap());
    assert!(output.is_absolute() && !output.exists());
    (config, output)
}

pub(super) fn child() {
    let (config, output) = checked_child_config();
    match std::env::var("TRNM_HISTORY_PROCESS_MODE").unwrap().as_str() {
        "crash" => {
            assert!(config.selection.is_none());
            let mut node = Node::open_operator_continuous_checkpoint_with_workers(
                &config.store,
                config.inputs,
                Instant::now() + Duration::from_secs(30),
                2,
            )
            .unwrap()
            .0;
            let cancel = node.continuous_cancellation_handle().unwrap();
            let calls = AtomicU64::new(0);
            let result = node
                .receive_owned_history_operation(
                    OwnedHistoryRequest {
                        raw_page: &config.page,
                        tip: crate::digest(&config.tip).unwrap(),
                        after: crate::digest(&config.after).unwrap(),
                        validation_operation_id: &config.validation_operation_id,
                        activation_operation_id: &config.activation_operation_id,
                        observed_now: fixture::CLOCK,
                    },
                    &|point| {
                        if point == OwnedHistoryProgress::Activation
                            && calls.fetch_add(1, Ordering::AcqRel) == 11
                        {
                            assert!(cancel.cancel().unwrap());
                        }
                        Ok(())
                    },
                )
                .unwrap();
            assert!(
                !result.completed
                    && result.validation.native_id == Some(crate::digest(&config.tip).unwrap())
            );
            checked(&result.validation, 2);
            checked(result.activation.as_ref().unwrap(), 0);
            assert!(result
                .activation
                .as_ref()
                .unwrap()
                .native_error
                .as_deref()
                .unwrap()
                .contains("CpuUnknown"));
            assert_eq!(
                node.active().unwrap(),
                (crate::digest(&config.after).unwrap(), 0)
            );
            let snapshot = node.continuous_process_cpu_snapshot().unwrap();
            assert_eq!(snapshot["pending_scopes"], 0);
            assert_eq!(snapshot["claims"], 4);
            assert_eq!(snapshot["started_operations"], 4);
            emit(
                &output,
                &json!({"schema":"actual-history-known-prefix-barrier-v1","pid":std::process::id(),
                "result":result,"process_snapshot":snapshot,"active":config.after,"generation":0,
                "validation_receipt":node.continuous_scope_receipt(&config.validation_operation_id).unwrap(),
                "activation_receipt":node.continuous_scope_receipt(&config.activation_operation_id).unwrap(),
                "clean_close_created":false,"scoped_workers_joined":true,"receiver_listener_started":false}),
            );
            // No drop or CleanClose: the bounded external guardian kills this
            // exact process after verifying the durable known-prefix barrier.
            loop {
                std::thread::park();
            }
        }
        "resume" => {
            let selection = config
                .selection
                .expect("exact local recovery selector required");
            let old_validation = config.prior_validation.unwrap();
            let old_activation = config.prior_activation.unwrap();
            let mut held = Node::open_operator_continuous_history_recovery(
                &config.store,
                config.inputs,
                Instant::now() + Duration::from_secs(30),
                2,
                selection,
            )
            .unwrap();
            assert_eq!(
                held.active().unwrap(),
                (crate::digest(&config.after).unwrap(), 0)
            );
            let flow = held
                .node
                .continuous_cpu_domain()
                .unwrap()
                .observe_actual_flow()
                .unwrap()
                .unwrap();
            assert_eq!(flow.initial_credit_ns, 0);
            same_receipt(
                &old_validation,
                &held
                    .scope_receipt(old_validation["linked_operations"][0].as_str().unwrap())
                    .unwrap(),
            );
            same_receipt(
                &old_activation,
                &held
                    .scope_receipt(old_activation["linked_operations"][0].as_str().unwrap())
                    .unwrap(),
            );
            let result = held
                .resume_native_fixture(&config.page, fixture::CLOCK, &|_| Ok(()))
                .unwrap();
            assert!(
                result.completed,
                "{}",
                serde_json::to_string(result).unwrap()
            );
            checked(&result.validation, 0); // identical admitted bytes: no second M06 execution
            checked(result.activation.as_ref().unwrap(), 0);
            let result = serde_json::to_value(result).unwrap();
            let (node, _, _) = held.into_ready().unwrap();
            assert_eq!(
                node.active().unwrap(),
                (crate::digest(&config.tip).unwrap(), 1)
            );
            let snapshot = node.continuous_process_cpu_snapshot().unwrap();
            assert_eq!(snapshot["claims"], 8);
            assert_eq!(snapshot["started_operations"], 8);
            assert_eq!(snapshot["pending_scopes"], 0);
            same_receipt(
                &old_validation,
                &node
                    .continuous_scope_receipt(
                        old_validation["linked_operations"][0].as_str().unwrap(),
                    )
                    .unwrap(),
            );
            same_receipt(
                &old_activation,
                &node
                    .continuous_scope_receipt(
                        old_activation["linked_operations"][0].as_str().unwrap(),
                    )
                    .unwrap(),
            );
            let closed = node.close_continuous_checkpoint().unwrap();
            emit(
                &output,
                &json!({"schema":"actual-history-fresh-process-resume-v1","pid":std::process::id(),
                "result":result,"active":config.tip,"generation":1,"process_snapshot":snapshot,
                "initial_credit_ns":flow.initial_credit_ns,"closed":closed,"prior_receipts_unchanged":true,
                "new_budget_installed":false,"refund":false,"public_host_path_executed":false}),
            );
        }
        other => panic!("unknown explicit process fixture mode {other}"),
    }
}

fn inputs_value(input: &policy::Inputs) -> Value {
    assert!(input.lease_transition.is_none());
    let view = &input.view_authority;
    let budget=input.budget_authority.as_ref().map(|a|json!({"identity":a.identity,"expected":a.expected,
        "envelope_sha256":a.envelope_sha256,"latest_sequence":a.latest_sequence,"latest_digest":a.latest_digest}));
    let allocations:Vec<_>=input.allocations.iter().map(|a|json!({"raw":a.raw,"authority":{
        "identity":a.authority.identity,"expected":a.authority.expected,"expected_envelope_sha256":a.authority.expected_envelope_sha256,
        "latest_allocator_sequence":a.authority.latest_allocator_sequence,"latest_allocator_digest":a.authority.latest_allocator_digest}})).collect();
    let materials: Vec<_> = input
        .materials
        .iter()
        .map(|m| json!({"role":m.role,"path":m.path,"bytes":m.bytes,"sha256":m.sha256}))
        .collect();
    let recovery=input.known_unclean_restart.as_ref().map(|r|json!({"raw":r.raw,"authority":{
        "identity":r.authority.identity,"expected":r.authority.expected,"envelope_sha256":r.authority.envelope_sha256,
        "body_digest":r.authority.body_digest}}));
    json!({"raw_view":input.raw_view,"view_authority":{"identity":view.identity,"expected":view.expected,
        "envelope_sha256":view.envelope_sha256,"latest_sequence":view.latest_sequence,"latest_digest":view.latest_digest},
        "raw_budget":input.raw_budget,"budget_authority":budget,"allocations":allocations,"journal_path":input.journal_path,
        "expected_uid":input.expected_uid,"expected_journal":input.expected_journal,"materials":materials,
        "lease_transition":null,"known_unclean_restart":recovery})
}
fn configuration(f: &Fixture, v: &ViewInput) -> Value {
    json!({"schema":"actual-history-native-process-fixture-v1","store":f.store(),"inputs":inputs_value(v.inputs.as_ref().unwrap()),
        "page":f.page,"tip":hex::encode(f.packet.id().unwrap()),"after":hex::encode(f.settings.genesis()),
        "validation_operation_id":v.validation,"activation_operation_id":v.activation,"selection":null,
        "prior_validation":null,"prior_activation":null})
}
fn outside<'a>(
    f: &'a Fixture,
    path: &'a Path,
    digest: &'a str,
) -> crate::operator_continuous_controller::OutsideLaunch<'a> {
    crate::operator_continuous_controller::OutsideLaunch {
        path,
        sha256: digest,
        registry_key: &f.identity.registry_key,
        task_key: &f.identity.task_key,
        source_commit: &f.identity.source_commit,
        node_policy_source: &f.identity.node_policy_source,
        registry2_package: &f.identity.registry2_package,
    }
}
fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::create_dir(to)?;
    for item in fs::read_dir(from)? {
        let item = item?;
        let target = to.join(item.file_name());
        if item.file_type()?.is_dir() {
            copy_tree(&item.path(), &target)?;
        } else if item.file_type()?.is_file() {
            fs::copy(item.path(), target)?;
        } else {
            return Err(std::io::Error::other("unexpected fixture symlink"));
        }
    }
    Ok(())
}
struct ExportOnExit {
    from: PathBuf,
    to: Option<PathBuf>,
}
impl Drop for ExportOnExit {
    fn drop(&mut self) {
        if let Some(to) = &self.to {
            if let Some(parent) = to.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Err(error) = copy_tree(&self.from, to) {
                eprintln!("HISTORY_PROCESS_ARTIFACT_EXPORT_ERROR {error}");
                if !std::thread::panicking() {
                    panic!("required native process artifact export failed: {error}");
                }
            }
        }
    }
}

pub(super) fn run() {
    let f = Fixture::new();
    let _export = ExportOnExit {
        from: f.dir.path().to_path_buf(),
        to: std::env::var_os("TRNM_HISTORY_NATIVE_ARTIFACT_DIR")
            .map(|p| PathBuf::from(p).join("real-process-sigkill")),
    };
    let first = first(&f);
    let initial_path = f.dir.path().join("crash-process.json");
    emit(&initial_path, &configuration(&f, &first));
    let binary = std::env::current_exe().unwrap();
    let binary_sha = sha(&fs::read(&binary).unwrap());
    let configuration_sha = sha(&fs::read(&initial_path).unwrap());
    let guardian = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../scripts/ci/history_native_process_guard.py");
    assert_eq!(
        sha(&fs::read(&guardian).unwrap()),
        sha(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../scripts/ci/history_native_process_guard.py"
        )))
    );
    let killed = f.dir.path().join("actual-sigkill");
    let output = Command::new("python3")
        .arg(guardian)
        .arg("--binary")
        .arg(&binary)
        .args(["--binary-sha256", &binary_sha])
        .arg("--configuration")
        .arg(&initial_path)
        .args(["--configuration-sha256", &configuration_sha])
        .arg("--directory")
        .arg(&killed)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    fs::write(f.dir.path().join("guardian.stdout.log"), &output.stdout).unwrap();
    fs::write(f.dir.path().join("guardian.stderr.log"), &output.stderr).unwrap();
    assert!(
        output.status.success(),
        "guardian failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let wait_raw = fs::read(killed.join("actual-wait4.json")).unwrap();
    let wait: Value = serde_json::from_slice(&wait_raw).unwrap();
    assert_eq!(wait["passed"], true);
    assert_eq!(wait["actual_wait4"], true);
    assert_eq!(wait["signal"], 9);
    let prefix_raw = fs::read(killed.join("known-prefix-ready.json")).unwrap();
    let prefix: Value = serde_json::from_slice(&prefix_raw).unwrap();
    assert_eq!(wait["known_prefix_sha256"], sha(&prefix_raw));
    assert_eq!(wait["owned_child_pid"], prefix["pid"]);
    let snapshot = &prefix["process_snapshot"];
    let anchor: history::Anchor = serde_json::from_value(snapshot["journal_head"].clone()).unwrap();
    let now = crate::operator_task_policy::now_ns().unwrap();
    let body = crate::operator_continuous_recovery::RecoveryBody {
        schema: "restricted-continuous-known-unclean-restart-v1".into(),
        identity: f.identity.clone(),
        prior_journal: anchor.clone(),
        exact_usage_digest: snapshot["exact_usage_digest"].as_str().unwrap().into(),
        actual_parent: hex::encode(f.settings.genesis()),
        actual_generation: 0,
        closed_process_receipt_sha256: sha(&wait_raw),
        process_start_scope: snapshot["process_start_scope"].as_str().unwrap().into(),
        native_task: f.binding.task.native_task.clone(),
        instance_class: f.binding.instance_class.clone(),
        known_scope_total_cpu_ns: wait["known_scope_total_cpu_ns"].as_u64().unwrap(),
        closed_process_total_cpu_ns: wait["closed_process_total_cpu_ns"].as_u64().unwrap(),
        residual_cpu_ns: wait["residual_cpu_ns"].as_u64().unwrap(),
        actual_wait4: wait["actual_wait4"].as_bool().unwrap(),
        signal: wait["signal"].as_i64().unwrap().try_into().unwrap(),
        all_owned_children_reaped: wait["all_owned_children_reaped"].as_bool().unwrap(),
        adopted_descendants: serde_json::from_value(wait["adopted_descendants"].clone()).unwrap(),
        issued_ns: now,
        expires_ns: now + 300_000_000_000,
    };
    let (raw, digest) = crate::operator_continuous_test_support::signed(
        b"TRNM-RESTRICTED-CONTINUOUS-KNOWN-UNCLEAN-RESTART1",
        &body,
    );
    let recovery = json!({"raw":raw,"authority":{"identity":f.identity,"expected":body,
        "envelope_sha256":sha(&raw),"body_digest":digest}});
    let launch = json!({"schema":"restricted-continuous-known-unclean-recovery-launch-v1","source_commit":f.identity.source_commit,
        "node_policy_source":f.identity.node_policy_source,"registry2_package":f.identity.registry2_package,
        "journal_path":f.dir.path().join("journal"),"expected_uid":rustix::process::geteuid().as_raw(),
        "expected_journal":anchor,"input":recovery});
    let launch_path = f.dir.path().join("original-known-unclean-launch.json");
    emit(&launch_path, &launch);
    let launch_sha = sha(&fs::read(&launch_path).unwrap());
    let settled = crate::operator_continuous_controller::prepare_known_unclean_restart(outside(
        &f,
        &launch_path,
        &launch_sha,
    ))
    .unwrap();
    assert_eq!(settled["native_opened"], false);
    assert_eq!(settled["clean_close_created"], false);
    assert_eq!(settled["credit_granted_ns"], 0);
    assert_eq!(settled["residual_cpu_ns"], wait["residual_cpu_ns"]);
    emit(
        &f.dir
            .path()
            .join("actual-original-residual-settlement.json"),
        &settled,
    );
    // Exactly the same original signed close cannot settle again.
    assert!(
        crate::operator_continuous_controller::prepare_known_unclean_restart(outside(
            &f,
            &launch_path,
            &launch_sha
        ))
        .is_err()
    );
    let next_anchor: history::Anchor =
        serde_json::from_value(settled["journal_head"].clone()).unwrap();
    let journal = history::Journal::open(
        &f.dir.path().join("journal"),
        rustix::process::geteuid().as_raw(),
        &f.identity,
        &next_anchor,
    )
    .unwrap();
    assert_eq!(
        journal.usage_digest().unwrap(),
        settled["exact_usage_digest"].as_str().unwrap()
    );
    same_receipt(
        &prefix["validation_receipt"],
        &serde_json::to_value(journal.scope_receipt(&scope_id(&first.validation)).unwrap())
            .unwrap(),
    );
    drop(journal);
    let mut fresh = f.view(
        2,
        Some(first.view_digest.clone()),
        next_anchor,
        (f.settings.genesis(), 0),
        5,
        true,
    );
    fresh.inputs.as_mut().unwrap().known_unclean_restart =
        Some(serde_json::from_value(recovery).unwrap());
    let selection = json!({"schema":"restricted-continuous-single-successor-recovery-v1","target":hex::encode(f.packet.id().unwrap()),
        "prior_validation_operation_id":first.validation,
        "prior_validation_settled_record_sha256":prefix["validation_receipt"]["settled_record_sha256"],
        "validation_operation_id":fresh.validation,"activation_operation_id":fresh.activation});
    let mut resume = configuration(&f, &fresh);
    resume["selection"] = selection;
    resume["prior_validation"] = prefix["validation_receipt"].clone();
    resume["prior_activation"] = prefix["activation_receipt"].clone();
    let resume_path = f.dir.path().join("fresh-process.json");
    emit(&resume_path, &resume);
    let resume_sha = sha(&fs::read(&resume_path).unwrap());
    let resumed_path = f.dir.path().join("fresh-process-result.json");
    let stdout_path = f.dir.path().join("fresh-process.stdout.log");
    let stderr_path = f.dir.path().join("fresh-process.stderr.log");
    let mut child = Command::new(&binary)
        .args([
            "store::operator_continuous_owner::history_import::tests::history_process_child_helper",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("TRNM_HISTORY_PROCESS_MODE", "resume")
        .env("TRNM_HISTORY_PROCESS_CONFIG", &resume_path)
        .env("TRNM_HISTORY_PROCESS_CONFIG_SHA256", &resume_sha)
        .env("TRNM_HISTORY_PROCESS_OUTPUT", &resumed_path)
        .stdin(Stdio::null())
        .stdout(fs::File::create(&stdout_path).unwrap())
        .stderr(fs::File::create(&stderr_path).unwrap())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(50);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _actual = child.wait().unwrap();
            panic!("fresh native process exceeded 50 seconds; owned child killed and reaped");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = fs::read_to_string(&stdout_path).unwrap();
    let stderr = fs::read_to_string(&stderr_path).unwrap();
    assert!(
        status.success(),
        "fresh native process failed: {} {}",
        stdout,
        stderr
    );
    assert!(stdout.contains("1 passed; 0 failed;"));
    let resumed: Value = serde_json::from_slice(&fs::read(resumed_path).unwrap()).unwrap();
    assert_ne!(resumed["pid"], prefix["pid"]);
    assert_ne!(resumed["pid"], std::process::id());
    assert_eq!(resumed["result"]["completed"], true);
    assert_eq!(resumed["initial_credit_ns"], 0);
    assert_eq!(resumed["process_snapshot"]["claims"], 8);
    let final_head: history::Anchor =
        serde_json::from_value(resumed["closed"]["journal_head"].clone()).unwrap();
    let mut journal = history::Journal::open(
        &f.dir.path().join("journal"),
        rustix::process::geteuid().as_raw(),
        &f.identity,
        &final_head,
    )
    .unwrap();
    same_receipt(
        &prefix["validation_receipt"],
        &serde_json::to_value(journal.scope_receipt(&scope_id(&first.validation)).unwrap())
            .unwrap(),
    );
    same_receipt(
        &prefix["activation_receipt"],
        &serde_json::to_value(journal.scope_receipt(&scope_id(&first.activation)).unwrap())
            .unwrap(),
    );
    let old = recipient::authenticate(
        &first.signed_validation,
        &first.validation_authority,
        crate::operator_task_policy::now_ns().unwrap(),
    )
    .unwrap();
    let usage = journal.usage_digest().unwrap();
    assert_eq!(
        journal.reserve_allocation(&old),
        Err(crate::operator_task_policy::PolicyError::Replay)
    );
    assert_eq!(journal.anchor(), final_head);
    assert_eq!(journal.usage_digest().unwrap(), usage);
    eprintln!(
        "HISTORY_NATIVE_ACTUAL_SIGKILL {}",
        json!({"wait4":wait,"residual_settlement":settled,
        "fresh_native_process":resumed,"original_receipts_unchanged":true,"duplicate_residual_refused":true,
        "physical_power_loss_qualified":false,"pending_scope_crash_qualified":false,"public_network_ready":false})
    );
}
