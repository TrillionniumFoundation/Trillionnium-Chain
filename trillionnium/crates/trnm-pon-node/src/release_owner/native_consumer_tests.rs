//! Real ignored native gate: one static Node binary, production fixed /etc,
//! two independent UIDs, signed services and the existing NPQ6 owner fixture.
//! A pass is isolated execution evidence, never independent deployment custody.
use super::execution_wire::{ConfigurationPolicy, Contract, LaunchAttempt};
use super::frontier::{invalid, Digest32, Result};
use super::native_build_fixture as build;
use super::native_isolation_fixture::{
    self as isolation, Process, HELPER, RUNTIME_UID, SERVICE_UID,
};
use super::native_observation_fixture as observed;
use super::native_provision_fixture::{Fixture, NODE, WORKING};
use super::records::Record;
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

fn successful_frame(
    child: &mut Process,
    request: &Value,
    step: u64,
    until: Instant,
) -> Result<Value> {
    child.send(request)?;
    let value = child.json(None, until)?;
    assert_eq!(
        value["schema"],
        "restricted-owner-continuous-step-result-v2"
    );
    assert_eq!(value["step"], step);
    assert_eq!(value["control_frame_recorded"], true);
    assert_eq!(value["metadata_errors"], json!([]));
    assert!(value["native_error"].is_null(), "{value}");
    assert_eq!(value["public_network_ready"], false);
    Ok(value)
}
fn rejected(name: &str, uid: u32, args: &[String], expected: &str, until: Instant) -> Result<()> {
    let mut child = Process::spawn(name, uid, Path::new(NODE), args, &[])?;
    child.close_input();
    assert!(!child.wait(until)?.success());
    let stdout = fs::read(&child.stdout)?;
    let stderr = fs::read_to_string(&child.stderr)?;
    assert!(
        stdout.is_empty(),
        "{name} returned a purported successful result"
    );
    assert!(stderr.contains(expected), "{name}: {stderr}");
    Ok(())
}
fn publish_configuration(
    f: &mut Fixture,
    contract: &Contract,
    inputs: &Value,
    version: u64,
    previous: Option<Digest32>,
) -> Result<ConfigurationPolicy> {
    let policy = ConfigurationPolicy {
        schema_version: 1,
        contract: contract.clone(),
        inputs_digest: super::consumer::inputs_digest(inputs)?,
    };
    let publication = build::publication(
        &f.root,
        &f.index()?,
        &f.release_keys[2],
        build::ReleaseInput {
            role: 2,
            version,
            previous,
            content: policy.digest()?,
            bundle: None,
            configuration: Some(policy.clone()),
        },
    )?;
    f.publish(&publication)?;
    Ok(policy)
}
fn attempt_and_claim(pid: u32) -> Result<(Digest32, LaunchAttempt)> {
    let records = observed::records()?;
    let attempts: Vec<_> = records
        .iter()
        .filter_map(|(id, record)| match record {
            Record::LaunchAttempt(value) => Some((*id, value.as_ref().clone())),
            _ => None,
        })
        .collect();
    let claims: Vec<_> = records
        .iter()
        .filter_map(|(_, record)| match record {
            Record::Claim(value) => Some(value),
            _ => None,
        })
        .collect();
    assert_eq!(attempts.len(), 1);
    assert_eq!(claims.len(), 1);
    let (id, attempt) = &attempts[0];
    assert_eq!(attempt.process.pid, pid);
    assert_eq!(attempt.process.uid, RUNTIME_UID);
    assert_eq!(claims[0].attempt, *id);
    assert_eq!(claims[0].process, attempt.process);
    Ok((*id, attempt.clone()))
}
fn journal_frames(path: &Path) -> Result<Vec<String>> {
    let mut names = fs::read_dir(path)?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    if names.len() > crate::operator_continuous_history::MAX_ROWS + 3 {
        return Err(invalid("native original journal row bound"));
    }
    names.sort();
    let mut frames = Vec::new();
    for name in names {
        let name = name
            .to_str()
            .ok_or_else(|| invalid("native journal name"))?;
        if !name.starts_with("entry-") {
            continue;
        }
        let raw = build::bounded(&path.join(name), 65536)?; // Original MAX_ROW_BYTES.
        let row: Value = serde_json::from_slice(&raw).map_err(std::io::Error::other)?;
        assert_eq!(row["schema"], "restricted-continuous-journal-row-pq-v3");
        if row["event"]["kind"] == "control-frame" {
            frames.push(hex::encode(build::sha(&raw)));
        }
    }
    Ok(frames)
}
fn inherited_fixture_data(bytes: &[u8]) -> Result<File> {
    // Anyone can fabricate sealed transport. This negative control deliberately
    // supplies it without granting a second M15 process claim.
    use rustix::fs::{MemfdFlags, Mode, SealFlags};
    let mut file = File::from(rustix::fs::memfd_create(
        "m15-copied-claim-fixture",
        MemfdFlags::ALLOW_SEALING | MemfdFlags::NOEXEC_SEAL,
    )?);
    file.write_all(bytes)?;
    rustix::fs::fchmod(&file, Mode::RUSR)?;
    rustix::fs::fchown(
        &file,
        Some(rustix::process::Uid::from_raw(RUNTIME_UID)),
        Some(rustix::process::Gid::from_raw(RUNTIME_UID)),
    )?;
    rustix::fs::fcntl_add_seals(
        &file,
        SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL | SealFlags::EXEC,
    )?;
    Ok(file)
}

#[ignore = "requires reviewed static Node/test artifacts and a fresh rootless user/mount/PID namespace"]
#[test]
fn isolated_fixed_root_static_node_claim_refresh_and_revocation() -> Result<()> {
    assert_eq!(
        std::env::var("TRNM_M15_ISOLATED_SUITE").unwrap(),
        "isolated-native-v1"
    );
    let until = Instant::now() + Duration::from_secs(180);
    let mut f = Fixture::provision()?;
    let service = f.start_service()?;
    let mut helper = Process::spawn(
        "original-npq6-fixture",
        RUNTIME_UID,
        Path::new("/m15/bin/tests"),
        &[
            "--exact".into(),
            HELPER.into(),
            "--ignored".into(),
            "--nocapture".into(),
            "--test-threads=1".into(),
        ],
        &[("TRNM_M15_FIXTURE_HELPER", "isolated-native-v1")],
    )?;
    let exported = helper.json(Some(b"M15_FIXTURE:"), until)?;
    assert_eq!(exported["schema"], "trnm-m15-existing-npq6-fixture-v1");
    assert_eq!(exported["qualification"], false);
    assert_eq!(exported["launch"]["maximum_steps"], 32);
    assert_eq!(exported["launch"]["wall_seconds"], 180);
    assert!(exported["launch"]["receiver_service"].is_null());
    let initialized = f.admin(RUNTIME_UID, "m15-release-owner-initialize-v1", &[])?;
    assert_eq!(initialized["schema"], "trnm-m15-owner-initialized-v1");
    assert_eq!(initialized["production_qualified"], false);
    let node = f.build.bundle(&f.release_keys[1], "1", None)?;
    let node_digest = node.bundle_digest;
    let publication = build::publication(
        &f.root,
        &f.index()?,
        &f.release_keys[1],
        build::ReleaseInput {
            role: 1,
            version: 1,
            previous: None,
            content: node_digest,
            bundle: Some(node),
            configuration: None,
        },
    )?;
    f.publish(&publication)?;
    let contract = build::contract(
        &f.build,
        node_digest,
        f.namespace,
        f.trust_pin,
        &exported,
        Path::new(WORKING),
    )?;
    let policy = publish_configuration(&mut f, &contract, &exported["launch"]["inputs"], 1, None)?;
    let installed = f.admin(
        RUNTIME_UID,
        "m15-release-owner-install-v1",
        &[
            "--artifact".into(),
            NODE.into(),
            "--artifact-name".into(),
            "trnm-pon-node".into(),
        ],
    )?;
    assert_eq!(installed["schema"], "trnm-m15-installation-v1");
    assert_eq!(installed["execution_authorized"], false);
    let before = f.index()?.encode()?;
    rejected(
        "wrong-runtime-uid",
        SERVICE_UID,
        &["m15-release-owner-status-v1".into()],
        "M15 complete deployment binding",
        until,
    )?;
    assert_eq!(f.index()?.encode()?, before);

    f.clock
        .catalog_fault
        .arm(f.build.program_sha256, f.build.program_bytes)?;
    let mut child = Process::spawn(
        "actual-static-node",
        RUNTIME_UID,
        Path::new(NODE),
        &["m15-release-owner-launch-v1".into()],
        &[
            ("LD_PRELOAD", "/nonexistent/m15-injection.so"),
            ("LD_LIBRARY_PATH", "/nonexistent/m15-libs"),
        ],
    )?;
    let pid = child.id();
    let startup = child.json(None, until)?;
    assert_eq!(startup["schema"], "m15-owner-continuous-startup-v1");
    assert_eq!(startup["public_network_ready"], false);
    assert_eq!(startup["original8193_qualification"], false);
    observed::image(pid, f.build.program_sha256, f.build.program_bytes)?;
    let environment = fs::read(format!("/proc/{pid}/environ"))?;
    let mut actual_environment: Vec<_> = environment
        .split(|b| *b == 0)
        .filter(|v| !v.is_empty())
        .map(Vec::from)
        .collect();
    actual_environment.sort();
    assert_eq!(
        actual_environment,
        vec![b"LANG=C".to_vec(), b"LC_ALL=C".to_vec(), b"TZ=UTC".to_vec()]
    );
    let (attempt_id, attempt) = attempt_and_claim(pid)?;
    f.clock.catalog_fault.require_fired()?;
    f.clock.catalog_fault.retain_witness()?;

    // A copied receipt and arbitrary sealed files do not confer a new launch.
    let before = f.index()?.encode()?;
    {
        let handoff = inherited_fixture_data(&super::codec::encode(
            &super::launch::Handoff {
                schema_version: 1,
                namespace: f.namespace,
                attempt: attempt_id,
            },
            4096,
        )?)?;
        let launch = inherited_fixture_data(&build::bounded(
            &contract.outside.path,
            super::launch::MAX_CONFIGURATION as u64,
        )?)?;
        let mut args = contract.arguments[1..].to_vec();
        args.extend([
            "--m15-launch-fd".into(),
            launch.as_raw_fd().to_string(),
            "--m15-handoff-fd".into(),
            handoff.as_raw_fd().to_string(),
        ]);
        rejected(
            "copied-consumed-claim",
            RUNTIME_UID,
            &args,
            "M15 launch attempt epoch/expiry/consumption changed",
            until,
        )?;
    }
    assert_eq!(f.index()?.encode()?, before);
    rejected(
        "changed-catalog-next-launch",
        RUNTIME_UID,
        &["m15-release-owner-launch-v1".into()],
        "M15 catalog exact size",
        until,
    )?;
    assert_eq!(f.index()?.encode()?, before);
    assert_eq!(attempt.actual_arguments[0], "trnm-pon-node");
    let first = successful_frame(&mut child, &json!({"purpose":"read-head"}), 1, until)?;
    assert_eq!(first["parent"], exported["parent"]);
    assert_eq!(first["generation"], exported["generation"]);
    helper.send(
        &json!({"schema":"trnm-m15-existing-npq6-fixture-command-v1","action":"refresh",
        "head":first["journal_head"],"parent":first["parent"],"generation":first["generation"]}),
    )?;
    let refreshed = helper.json(Some(b"M15_FIXTURE:"), until)?;
    assert_eq!(refreshed["launch"]["maximum_steps"], 32);
    assert_eq!(refreshed["launch"]["wall_seconds"], 180);
    let _next_policy = publish_configuration(
        &mut f,
        &contract,
        &refreshed["launch"]["inputs"],
        2,
        Some(policy.digest()?),
    )?;
    let refresh = successful_frame(
        &mut child,
        &json!({"purpose":"refresh","inputs":refreshed["launch"]["inputs"]}),
        2,
        until,
    )?;
    assert_eq!(refresh["result"]["refreshed"], true);
    assert_eq!(refresh["result"]["work_capability_issued"], false);
    let _second = successful_frame(&mut child, &json!({"purpose":"read-head"}), 3, until)?;
    let journal = Path::new(
        exported["launch"]["inputs"]["journal_path"]
            .as_str()
            .unwrap(),
    );
    let frames = journal_frames(journal)?;
    assert_eq!(frames.len(), 3);

    // Publish a real signed successor: the still-running old claim must not
    // authorize even CancelEpoch or another controller frame under the old role.
    let next_node = f.build.bundle(&f.release_keys[1], "2", Some(node_digest))?;
    let next = build::publication(
        &f.root,
        &f.index()?,
        &f.release_keys[1],
        build::ReleaseInput {
            role: 1,
            version: 2,
            previous: Some(node_digest),
            content: next_node.bundle_digest,
            bundle: Some(next_node),
            configuration: None,
        },
    )?;
    f.publish(&next)?;
    let before = f.index()?.encode()?;
    child.send(&json!({"purpose":"cancel-epoch"}))?;
    child.close_input();
    assert!(!child.wait(until)?.success());
    assert!(fs::read_to_string(&child.stderr)?
        .contains("M15 bundle/artifact/platform/configuration cross-binding"));
    assert_eq!(journal_frames(journal)?, frames);
    assert_eq!(f.index()?.encode()?, before);
    attempt_and_claim(pid)?;
    helper.send(
        &json!({"schema":"trnm-m15-existing-npq6-fixture-command-v1","action":"stop",
        "head":null,"parent":null,"generation":null}),
    )?;
    helper.close_input();
    assert!(helper.wait(until)?.success());
    drop(service);
    f.clock.finish()?;
    isolation::write(Path::new("/m15/evidence/consumer-result.json"),&serde_json::to_vec(&json!({
        "schema":"trnm-m15-real-isolated-consumer-result-v1","actual_pid":pid,
        "node_program_sha256":hex::encode(f.build.program_sha256),"attempt":hex::encode(attempt_id),
        "observed_controller_frames":3,"original_maximum_steps":32,"original_wall_seconds":180,
        "service_rpc_seconds":2,"fixture_principals":[RUNTIME_UID,SERVICE_UID],
        "same_fd_static_exec":true,"single_claim":true,"actual_refresh":true,
        "copied_claim_refused":true,"catalog_next_launch_refused":true,
        "revoked_frame_not_recorded":true,"production_qualified":false,
        "independent_deployment_qualified":false
    })).map_err(std::io::Error::other)?,0,0o600)?;
    Ok(())
}
