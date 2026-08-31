use std::process::Command;

use tempfile::TempDir;

fn rpc_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_trnm-rpc"))
}

#[test]
fn help_is_truthful_without_enabling_the_local_harness() {
    let output = rpc_command()
        .arg("--help")
        .env_remove("TRNM_RPC_DEVELOPMENT_ONLY")
        .output()
        .expect("run trnm-rpc --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(
        "Trillionnium development-only local-file RPC harness (not a production node RPC)"
    ));
    assert!(stdout.contains("TRNM_RPC_DEVELOPMENT_ONLY=1"));
    assert!(stdout.contains("no production node backend"));
}

#[test]
fn execution_without_exact_development_only_opt_in_fails_before_creating_local_state() {
    let address = format!("trnm1{}", "a".repeat(40));

    for opt_in in [None, Some("true"), Some(" 1 ")] {
        let temp = TempDir::new().expect("create isolated working directory");
        let mut command = rpc_command();
        command
            .current_dir(temp.path())
            .args(["query-balance", &address])
            .env_remove("TRNM_RPC_DEVELOPMENT_ONLY")
            .env_remove("TRNM_RPC_ACCOUNTS_FILE")
            .env_remove("TRNM_RPC_TX_FILE");
        if let Some(value) = opt_in {
            command.env("TRNM_RPC_DEVELOPMENT_ONLY", value);
        }

        let output = command.output().expect("run guarded trnm-rpc command");
        assert!(
            !output.status.success(),
            "missing or malformed development-only opt-in must fail closed"
        );
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("no production node backend"), "{stderr}");
        assert!(
            stderr.contains("local-file/model surrogate is disabled by default"),
            "{stderr}"
        );
        assert!(stderr.contains("TRNM_RPC_DEVELOPMENT_ONLY=1"), "{stderr}");
        assert!(
            std::fs::read_dir(temp.path())
                .expect("read isolated working directory")
                .next()
                .is_none(),
            "fail-closed guard must run before any implicit local-state creation"
        );
    }
}
