//! Exact current-ELF CI fixture setup; native Host checks remain authoritative.
use std::path::{Path, PathBuf};
use trnm_pon_node::host_kernel_parent::{require_host_kernel_budget, FIXED_PUBLIC_KERNEL_PARENT};

/// A successful parent delegates one complete named test. The verified child
/// returns false and executes every original statement in that same test body.
pub fn execute_in_fixed_host(target: &str, selector: &str, cli_binary: Option<&str>) -> bool {
    let budget = require_host_kernel_budget(
        "127.0.0.1:0".parse().unwrap(),
        Some(FIXED_PUBLIC_KERNEL_PARENT),
    );
    let in_original_host = matches!(&budget, Ok(Some(actual)) if actual.verify().is_ok());
    let child = std::env::var_os("TRNM_PUBLIC_FIXTURE_HOST_CHILD");
    if let Some(value) = &child {
        assert_eq!(
            value,
            &std::ffi::OsString::from(format!("{target}::{selector}")),
            "wrong public fixture child identity"
        );
        assert!(
            in_original_host,
            "public fixture child must satisfy the actual original kernel checks"
        );
        assert_eq!(
            cli_binary.map(|path| Path::new(path).canonicalize().unwrap()),
            std::env::var_os("TRNM_PUBLIC_FIXTURE_CLI_BINARY").map(PathBuf::from),
            "public fixture must bind the CLI path compiled into this exact test"
        );
    }
    if in_original_host
        || std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("CI").as_deref() != Ok("true")
    {
        // Local callers retain the original refusal. No marker creates a Host.
        return false;
    }
    assert!(child.is_none(), "public fixture Host recursion refused");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap()
        .canonicalize()
        .unwrap();
    let receipts = PathBuf::from(
        std::env::var_os("TRNM_CI_RECEIPT_DIR").expect("current CI receipt directory required"),
    );
    let output = receipts.join("public-fixtures").join(target).join(selector);
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let mut command = std::process::Command::new("python3");
    command
        .current_dir(root)
        .arg("scripts/ci/run_public_fixture_native.py")
        .arg("--launch")
        .arg("--target")
        .arg(target)
        .arg("--selector")
        .arg(selector)
        .arg("--binary")
        .arg(executable)
        .arg("--parent-pid")
        .arg(std::process::id().to_string())
        .arg("--out")
        .arg(&output);
    if let Some(binary) = cli_binary {
        command
            .arg("--cli-binary")
            .arg(Path::new(binary).canonicalize().unwrap());
    }
    let status = command.status().expect("public Host fixture must execute");
    assert!(
        status.success(),
        "source-bound public Host fixture failed; retained receipts: {}",
        output.display()
    );
    true
}
