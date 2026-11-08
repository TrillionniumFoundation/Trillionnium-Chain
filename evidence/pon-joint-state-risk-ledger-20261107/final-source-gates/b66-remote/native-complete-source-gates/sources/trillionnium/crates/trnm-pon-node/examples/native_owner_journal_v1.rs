//! Actual native persistent journal experiment; all output paths must be new.
#[path = "support/native_journal_scenario.rs"]
mod native_journal_scenario;

use std::path::Path;
use std::process::Command;
use trnm_pon_node::Result;

fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() == 2 && arguments[0] == "--crash-child" {
        return native_journal_scenario::crash_child(Path::new(&arguments[1]));
    }
    if arguments.len() != 1 {
        return Err("USAGE: native_owner_journal_v1 NEW_OUTPUT_DIRECTORY".into());
    }
    let executable = std::env::current_exe()?;
    let report = native_journal_scenario::run(Path::new(&arguments[0]), |plan| {
        Ok(Command::new(&executable)
            .arg("--crash-child")
            .arg(plan)
            .output()?)
    })?;
    println!(
        "{}",
        serde_json::json!({"recorded":Path::new(&arguments[0]).join("run.json"),
        "native_execution_exercised":true,"journals":report["journals"].as_array().map(Vec::len),
        "actual_child_exit":report["crash_child"]["exit_code"],"six_successor_risk_qualified":false})
    );
    Ok(())
}
