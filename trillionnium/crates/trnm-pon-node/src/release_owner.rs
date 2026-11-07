//! Explicit M15 operator profile. Never upgrades legacy research entry points.
//! All executable production paths require the independently provisioned root.
#[cfg(target_os = "linux")]
mod bundle_wire;
#[cfg(target_os = "linux")]
mod catalog;
#[cfg(target_os = "linux")]
mod codec;
#[cfg(target_os = "linux")]
mod consumer;
#[cfg(target_os = "linux")]
mod deployment;
#[cfg(target_os = "linux")]
mod elf;
#[cfg(target_os = "linux")]
mod execution_wire;
#[cfg(target_os = "linux")]
mod files;
#[cfg(all(test, target_os = "linux"))]
mod files_faults;
#[cfg(all(test, target_os = "linux"))]
mod files_tests;
#[cfg(target_os = "linux")]
mod frontier;
#[cfg(target_os = "linux")]
mod launch;
#[cfg(target_os = "linux")]
mod owner;
#[cfg(target_os = "linux")]
mod process_identity;
#[cfg(target_os = "linux")]
mod proof_state;
#[cfg(target_os = "linux")]
mod proof_wire;
#[cfg(target_os = "linux")]
mod protected;
#[cfg(target_os = "linux")]
mod records;
#[cfg(target_os = "linux")]
mod sealed;
#[cfg(target_os = "linux")]
mod transaction;
#[cfg(all(test, target_os = "linux"))]
mod transaction_faults;
#[cfg(all(test, target_os = "linux"))]
mod transaction_tests;
#[cfg(target_os = "linux")]
mod trust_client;
#[cfg(target_os = "linux")]
mod trust_wire;
#[cfg(target_os = "linux")]
mod unix_transport;

#[cfg(target_os = "linux")]
pub(crate) use consumer::{inputs_digest, Session};

#[cfg(target_os = "linux")]
pub fn open_controller(
    outside: crate::operator_continuous_controller::OutsideLaunch<'_>,
    launch_fd: u32,
    handoff_fd: u32,
    started: std::time::Instant,
) -> crate::Result<crate::operator_continuous_controller::Controller> {
    let session = consumer::Session::consume(
        crate::operator_continuous_controller::OutsideLaunch {
            path: outside.path,
            sha256: outside.sha256,
            registry_key: outside.registry_key,
            task_key: outside.task_key,
            source_commit: outside.source_commit,
            node_policy_source: outside.node_policy_source,
            registry2_package: outside.registry2_package,
        },
        launch_fd,
        handoff_fd,
    )?;
    crate::operator_continuous_controller::Controller::open_m15(outside, started, session)
}

#[cfg(target_os = "linux")]
fn publication(path: &std::path::Path) -> frontier::Result<proof_wire::Publication> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = sealed::identity(&file)?;
    if !path.is_absolute()
        || !file.metadata()?.is_file()
        || file.metadata()?.nlink() != 1
        || before.size == 0
        || before.size > records::MAX_RECORD_BYTES as u64
    {
        return Err(frontier::invalid("M15 publication input bound/type/path"));
    }
    let mut raw = Vec::new();
    Read::by_ref(&mut file)
        .take(records::MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut raw)?;
    let named = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if raw.len() as u64 != before.size
        || before != sealed::identity(&file)?
        || before != sealed::identity(&named)?
    {
        return Err(frontier::invalid("M15 publication source changed"));
    }
    codec::decode(&raw, records::MAX_RECORD_BYTES)
}

pub fn run_admin(
    command: &str,
    args: &std::collections::BTreeMap<String, String>,
) -> crate::Result<serde_json::Value> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (command, args);
        Err("M15_SEALED_LINUX_PROFILE_UNSUPPORTED".into())
    }
    #[cfg(target_os = "linux")]
    {
        use serde_json::json;
        let expected: &[&str] = match command {
            "m15-release-owner-initialize-v1"
            | "m15-release-owner-status-v1"
            | "m15-release-owner-launch-v1"
            | "m15-release-owner-frontier-initialize-v1"
            | "m15-release-owner-frontier-serve-v1" => &[],
            "m15-release-owner-publish-v1" => &["--publication"],
            "m15-release-owner-install-v1" => &["--artifact", "--artifact-name"],
            _ => return Err("M15_EXPLICIT_VERSIONED_COMMAND_REQUIRED".into()),
        };
        crate::ensure(
            args.len() == expected.len() && args.keys().all(|key| expected.contains(&key.as_str())),
            "M15_EXACT_COMMAND_ARGUMENTS",
        )?;
        match command {
            "m15-release-owner-frontier-initialize-v1" => frontier_service::Service::open(true)?
                .initialization()
                .map_err(Into::into),
            "m15-release-owner-frontier-serve-v1" => {
                frontier_service::Service::open(false)?.serve()?;
                Err("M15_FRONTIER_SERVICE_STOPPED".into())
            }
            "m15-release-owner-initialize-v1" => {
                let owner = owner::Owner::initialize()?;
                Ok(
                    json!({"schema":"trnm-m15-owner-initialized-v1","frontier":owner.frontier()?,
                    "production_qualified":false,"execution_authorized":false}),
                )
            }
            "m15-release-owner-status-v1" => {
                let mut owner = owner::Owner::open()?;
                let state = owner.reload()?;
                Ok(
                    json!({"schema":"trnm-m15-owner-status-v1","frontier":owner.frontier()?,
                    "records":state.index.records.len(),"production_qualified":false,"execution_authorized":false}),
                )
            }
            "m15-release-owner-publish-v1" => {
                let value = publication(std::path::Path::new(&args["--publication"]))?;
                let digest = owner::Owner::open()?.publish(value)?;
                Ok(
                    json!({"schema":"trnm-m15-publication-v1","record":hex::encode(digest),"execution_authorized":false}),
                )
            }
            "m15-release-owner-install-v1" => {
                let digest = catalog::install(
                    std::path::Path::new(&args["--artifact"]),
                    &args["--artifact-name"],
                )?;
                Ok(
                    json!({"schema":"trnm-m15-installation-v1","record":hex::encode(digest),"execution_authorized":false}),
                )
            }
            "m15-release-owner-launch-v1" => {
                launch::execute()?;
                Err("M15_EXEC_RETURNED_WITHOUT_REPLACEMENT".into())
            }
            _ => Err("M15_EXPLICIT_VERSIONED_COMMAND_REQUIRED".into()),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod sealed_faults;
#[cfg(all(test, target_os = "linux"))]
mod sealed_tests;

#[cfg(all(test, target_os = "linux"))]
mod proof_test_keys;
#[cfg(target_os = "linux")]
mod root_separation;
#[cfg(all(test, target_os = "linux"))]
mod root_separation_tests;

#[cfg(target_os = "linux")]
mod frontier_service;
#[cfg(target_os = "linux")]
mod service_clock;
#[cfg(target_os = "linux")]
mod service_configuration;
#[cfg(target_os = "linux")]
mod service_socket;
#[cfg(target_os = "linux")]
mod service_store;
#[cfg(target_os = "linux")]
mod system_root;

#[cfg(target_os = "linux")]
mod clock_contract;

#[cfg(all(test, target_os = "linux"))]
mod service_faults;

#[cfg(all(test, target_os = "linux"))]
mod service_test_fixture;
#[cfg(all(test, target_os = "linux"))]
mod service_tests;

#[cfg(all(test, target_os = "linux"))]
mod native_build_fixture;

#[cfg(all(test, target_os = "linux"))]
mod native_isolation_fixture;

#[cfg(all(test, target_os = "linux"))]
mod native_provision_fixture;

#[cfg(all(test, target_os = "linux"))]
mod native_observation_fixture;

#[cfg(all(test, target_os = "linux"))]
mod native_consumer_tests;
