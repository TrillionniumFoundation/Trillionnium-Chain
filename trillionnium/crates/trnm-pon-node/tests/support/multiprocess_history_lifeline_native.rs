//! Actual systemd/Node controller-death controls, separate from the unchanged
//! three original campaigns. The checkpoints name boundaries after real calls;
//! they do not claim a kill inside an arithmetic instruction or an atomic stop.
use super::{
    membership, parent_observation, publish, read, sha, support, StateBackendChoice, Verifier,
    PARENT,
};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use trnm_pon_node::{development_public, ingress};

const STAGES: [&str; 3] = [
    "after-node-open-before-seed",
    "after-public-import-before-response",
    "after-node-close-before-report",
];
const OBSERVE: Duration = Duration::from_secs(180);
const DEATH: Duration = Duration::from_secs(5);

pub(super) fn boundary(job: &Value, path: &Path, stage: &str, facts: impl FnOnce() -> Value) {
    let Some(selected) = job["owner_death_control"].as_str() else {
        return;
    };
    assert!(
        STAGES.contains(&selected),
        "explicit finite native control stage"
    );
    if selected != stage {
        return;
    }
    let facts = facts();
    publish(
        &path.join("owner-death-boundary.json"),
        &json!({
            "schema":"native-history-owner-death-boundary-v1", "stage":stage,
            "pid":std::process::id(), "cgroup":membership(std::process::id()),
            "binary_sha256":sha(&std::env::current_exe().unwrap()),
            "job_sha256":sha(&path.join("job.json")),
            "controller_observation":job["controller_observation"],
            "parent":parent_observation(), "facts":facts,
            "scope":"after the named actual native call; awaiting owned controller death, never a substitute successful completion",
        }),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        thread::park_timeout(Duration::from_millis(10));
    }
    panic!("actual controller-death observer did not terminate the armed helper");
}

#[test]
#[ignore = "owned native controller helper; only the exact parent controls provide its immutable job"]
fn controller_entry() {
    let root = PathBuf::from(std::env::var_os("TRNM_HISTORY_VERIFIER_LIFELINE_CASE").unwrap());
    let control = read(&root.join("control.json"));
    let stage = control["stage"].as_str().unwrap();
    assert!(STAGES.contains(&stage));
    assert_eq!(
        control["binary_sha256"],
        sha(&std::env::current_exe().unwrap())
    );
    let settings = support::settings();
    assert_eq!(control["genesis"], hex::encode(settings.genesis()));
    assert_eq!(control["network"], hex::encode(settings.network()));
    assert_eq!(control["parameters"], hex::encode(settings.parameters()));
    let backend = StateBackendChoice::AuthenticatedV1;
    // This separate death control uses one actual legal empty maintenance
    // packet. It cannot qualify the original four-block/1024-transfer campaign.
    let packet = if stage == "after-public-import-before-response" {
        let producer = backend.open(&root.join("producer"), settings.clone());
        Some(
            producer
                .make_consensus_maintenance(
                    settings.genesis(),
                    vec![],
                    development_public(0).unwrap(),
                    settings.genesis_time() + 10,
                    4096,
                )
                .unwrap(),
        )
    } else {
        None
    };
    if let Some(packet) = &packet {
        publish(
            &root.join("original-packet.json"),
            &json!({
                "id":hex::encode(packet.id().unwrap()),
                "wire":hex::encode(packet.encode().unwrap()),
                "after":hex::encode(settings.genesis()),
            }),
        );
    }
    let mut verifier = Verifier::start_inner(&root.join("verifier"), backend, &[], Some(stage));
    if let Some(packet) = packet {
        let id = packet.id().unwrap();
        let page = ingress::Page {
            schema: "pon-native-history-v1".into(),
            network: hex::encode(settings.network()),
            parameters: hex::encode(settings.parameters()),
            genesis: hex::encode(settings.genesis()),
            tip: hex::encode(id),
            after: hex::encode(settings.genesis()),
            packets: vec![hex::encode(packet.encode().unwrap())],
            next: hex::encode(id),
            complete: true,
        };
        // The actual source-bound actor still calls receive_public_page_from;
        // no loopback or development importer bypass is used by this control.
        let _ = verifier.import(
            "127.0.0.1:1".parse().unwrap(),
            serde_json::to_value(page).unwrap(),
            id,
            settings.genesis(),
            support::now(),
            support::monotonic(),
        );
    } else {
        let _ = verifier.finish();
    }
    panic!("controller unexpectedly reached completion beyond its death boundary");
}

fn systemd_state(unit: &str) -> Value {
    let output = Command::new("systemctl")
        .args([
            "show",
            unit,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=ExecMainCode",
            "--property=ExecMainStatus",
            "--property=MainPID",
            "--property=ControlGroup",
            "--property=CPUUsageNSec",
            "--property=MemoryPeak",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "actual unit observation failed");
    let mut state = serde_json::Map::new();
    for line in String::from_utf8(output.stdout).unwrap().lines() {
        let (key, value) = line.split_once('=').unwrap();
        assert!(state.insert(key.to_owned(), json!(value)).is_none());
    }
    Value::Object(state)
}

struct Controller {
    child: Child,
    unit: Option<String>,
    root: PathBuf,
    assertions_completed: bool,
}
impl Drop for Controller {
    fn drop(&mut self) {
        let mut killed_owned_child = false;
        if matches!(self.child.try_wait(), Ok(None)) {
            killed_owned_child = self.child.kill().is_ok();
            let _ = self.child.wait();
        }
        let mut commands = Vec::new();
        if let Some(unit) = &self.unit {
            let actions: &[&str] = if self.assertions_completed {
                &["reset-failed"]
            } else {
                &["stop", "reset-failed"]
            };
            for action in actions {
                let outcome = Command::new("sudo")
                    .args(["-n", "systemctl", action, unit])
                    .output();
                commands.push(match outcome {
                    Ok(outcome) => json!({"action":action,"exit_success":outcome.status.success(),
                        "stdout":String::from_utf8_lossy(&outcome.stdout),
                        "stderr":String::from_utf8_lossy(&outcome.stderr)}),
                    Err(error) => json!({"action":action,"error":error.to_string()}),
                });
            }
        }
        let record = json!({"schema":"native-history-owner-death-cleanup-v1",
            "unit":self.unit,"assertions_completed_before_cleanup":self.assertions_completed,
            "killed_owned_controller_during_cleanup":killed_owned_child,"commands":commands,
            "scope":"only this case's recorded transient unit; cleanup never creates successful native evidence"});
        let _ = fs::write(
            self.root.join("cleanup.json"),
            serde_json::to_vec(&record).unwrap(),
        );
    }
}

fn wait_file(controller: &mut Controller, path: &Path, deadline: Instant) -> Value {
    loop {
        if path.is_file() {
            return read(path);
        }
        assert!(
            controller.child.try_wait().unwrap().is_none(),
            "owned controller exited before native boundary"
        );
        assert!(
            Instant::now() < deadline,
            "bounded actual native boundary wait"
        );
        thread::sleep(Duration::from_millis(2));
    }
}

fn one_case(stage: &str) {
    assert!(STAGES.contains(&stage));
    let root = PathBuf::from(std::env::var_os("TRNM_HISTORY_VERIFIER_LIFELINE_OUTPUT").unwrap());
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let binary_sha256 = sha(&executable);
    publish(
        &root.join("control.json"),
        &json!({"schema":"native-history-owner-death-control-v1",
        "stage":stage,"binary_sha256":binary_sha256,"state_backend":"authenticated-v1",
        "genesis":hex::encode(support::settings().genesis()),
        "network":hex::encode(support::settings().network()),
        "parameters":hex::encode(support::settings().parameters())}),
    );
    let selector = format!(
        "{}::controller_entry",
        module_path!().split_once("::").unwrap().1
    );
    let log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("controller.log"))
        .unwrap();
    let mut controller = Controller {
        child: Command::new(&executable)
            .args([
                selector.as_str(),
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TRNM_HISTORY_VERIFIER_LIFELINE_CASE", &root)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
        unit: None,
        root: root.clone(),
        assertions_completed: false,
    };
    let controller_pid = controller.child.id();
    let deadline = Instant::now() + OBSERVE;
    let verifier = root.join("verifier");
    let launch = wait_file(&mut controller, &verifier.join("launch.json"), deadline);
    assert_eq!(launch["controller_pid"], controller_pid);
    assert_eq!(launch["parent"], PARENT);
    assert_eq!(
        launch["original_outer_cgroup"],
        membership(std::process::id())
    );
    assert_eq!(membership(controller_pid), membership(std::process::id()));
    assert_eq!(
        sha(&PathBuf::from(format!("/proc/{controller_pid}/exe"))),
        binary_sha256
    );
    assert_eq!(launch["parent_before_spawn"]["pids.current"], 0);
    assert_eq!(launch["binary_sha256"], binary_sha256);
    assert_eq!(launch["controller_capability_prequeued"], true);
    assert_eq!(launch["owner_death_control"], stage);
    assert_eq!(launch["collect_on_exit"], false);
    let unit = launch["unit"].as_str().unwrap().to_owned();
    let suffix = unit
        .strip_prefix(&format!("trnm-campaign-verifier-{controller_pid}-"))
        .unwrap()
        .strip_suffix(".service")
        .unwrap();
    assert!(!suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()));
    controller.unit = Some(unit.clone());
    let boundary = wait_file(
        &mut controller,
        &verifier.join("owner-death-boundary.json"),
        deadline,
    );
    assert_eq!(boundary["stage"], stage);
    assert_eq!(boundary["binary_sha256"], binary_sha256);
    assert_eq!(boundary["job_sha256"], launch["job_sha256"]);
    assert_eq!(boundary["controller_observation"]["pid"], controller_pid);
    let actor_pid = u32::try_from(boundary["pid"].as_u64().unwrap()).unwrap();
    assert_ne!(actor_pid, controller_pid);
    assert_eq!(
        sha(&PathBuf::from(format!("/proc/{actor_pid}/exe"))),
        binary_sha256
    );
    assert_eq!(
        membership(actor_pid),
        format!("/trnmponpublic.slice/{unit}")
    );
    let parent_before_death = parent_observation();
    assert!(parent_before_death["pids.current"].as_u64().unwrap() >= 2);
    let before = systemd_state(&unit);
    assert_eq!(before["MainPID"], actor_pid.to_string());
    assert_eq!(before["ActiveState"], "active");
    assert_eq!(
        before["ControlGroup"],
        format!("/trnmponpublic.slice/{unit}")
    );
    assert!(controller.child.try_wait().unwrap().is_none());
    assert!(!verifier.join("report.json").exists());
    let facts = &boundary["facts"];
    match stage {
        "after-node-open-before-seed" => {
            assert_eq!(facts["actual_native_open_returned"], true);
            assert_eq!(facts["active"][0], json!(support::settings().genesis()));
            assert!(!verifier.join("ready.json").exists());
        }
        "after-public-import-before-response" => {
            assert_eq!(facts["actual_strict_public_import_returned"], true);
            let original = read(&root.join("original-packet.json"));
            let expected: Vec<u8> = hex::decode(original["id"].as_str().unwrap()).unwrap();
            assert_eq!(facts["returned_value"], json!(expected));
            assert_eq!(facts["active"][0], facts["returned_value"]);
            assert_eq!(facts["sequence"], 0);
            assert_eq!(
                facts["request_sha256"],
                sha(&verifier.join("request-000.json"))
            );
            assert!(!verifier.join("response-000.json").exists());
        }
        "after-node-close-before-report" => {
            assert_eq!(facts["actual_node_close_returned"], true);
            assert_eq!(facts["actual_runner_returned"], true);
            assert_eq!(facts["clean_node_close"], true);
            assert_eq!(
                facts["entry_schema"],
                "native-public-history-verifier-entry-v2"
            );
            let finish = read(&verifier.join("response-000.json"));
            assert!(finish["error"].is_null());
            assert_eq!(finish["value"]["closing_original_node"], true);
        }
        _ => unreachable!(),
    }
    publish(
        &root.join("before-owner-death.json"),
        &json!({"launch":launch,"boundary":boundary,
        "actual_systemd_unit":before,"parent":parent_before_death,"controller_pid":controller_pid,
        "actor_pid":actor_pid,"binary_sha256":binary_sha256}),
    );
    let death = Instant::now();
    // Only the still-owned unreaped Child is killed. No caller-supplied PID,
    // service PID, UID scan, process group or unrelated process is signalled.
    controller.child.kill().unwrap();
    let killed = controller.child.wait().unwrap();
    assert_eq!(killed.signal(), Some(libc::SIGKILL));
    let (after, parent_after) = loop {
        let state = systemd_state(&unit);
        let parent = parent_observation();
        if state["MainPID"] == "0" && parent["pids.current"] == 0 {
            break (state, parent);
        }
        assert!(
            death.elapsed() < DEATH,
            "armed verifier must terminate before any administrative cleanup or 240s fallback"
        );
        thread::sleep(Duration::from_millis(2));
    };
    let death_to_empty_ns = death.elapsed().as_nanos();
    assert!(death.elapsed() < DEATH);
    assert_eq!(after["ExecMainCode"], "1", "actual CLD_EXITED required");
    assert_eq!(
        after["ExecMainStatus"], "137",
        "the real self-exit status required, not cleanup SIGKILL or panic"
    );
    assert_eq!(after["ActiveState"], "failed");
    assert!(
        !verifier.join("report.json").exists(),
        "no synthetic clean completion after owner death"
    );
    publish(
        &root.join("result.json"),
        &json!({
            "schema":"native-history-owner-death-result-v1","stage":stage,
            "binary_sha256":binary_sha256,"controller_pid":controller_pid,"actor_pid":actor_pid,
            "controller_signal":killed.signal(),"unit":unit,
            "before":before,"after":after,"parent_before_death":parent_before_death,
            "parent_after_death":parent_after,"death_to_empty_ns":death_to_empty_ns,
            "maximum_death_to_empty_ns":DEATH.as_nanos(),"actual_boundary":boundary,
            "administrative_stop_before_observation":false,"clean_completion_report_exists":false,
            "completed_control":true,"original_campaign_qualified":false,
            "scope":"actual exact-source systemd service and Node call boundaries; asynchronous owner-death self exit and empty original fixed parent before cleanup, not zero-latency cancellation or a successful History settlement",
        }),
    );
    controller.assertions_completed = true;
}

#[test]
#[ignore = "requires the original administrator-provisioned fixed History parent; mandatory dedicated CI lane"]
fn controller_death_after_actual_node_open_removes_verifier() {
    one_case(STAGES[0]);
}

#[test]
#[ignore = "requires the original administrator-provisioned fixed History parent; mandatory dedicated CI lane"]
fn controller_death_after_actual_public_import_removes_verifier() {
    one_case(STAGES[1]);
}

#[test]
#[ignore = "requires the original administrator-provisioned fixed History parent; mandatory dedicated CI lane"]
fn controller_death_after_run_return_before_report_removes_verifier() {
    one_case(STAGES[2]);
}
