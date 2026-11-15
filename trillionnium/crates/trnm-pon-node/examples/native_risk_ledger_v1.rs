//! Real native PNRL1 registration experiment; the output directory must be new.
#[path = "support/native_risk_scenario.rs"]
mod scenario;
use std::path::Path;
use std::process::Command;
use trnm_pon_node::Result;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 2 && args[0] == "--crash-child" {
        return scenario::crash_child(Path::new(&args[1]));
    }
    if args.len() != 1 {
        return Err("USAGE: native_risk_ledger_v1 NEW_OUTPUT_DIRECTORY".into());
    }
    let executable = std::env::current_exe()?;
    let report = scenario::run(Path::new(&args[0]), |plan| {
        Ok(Command::new(&executable)
            .arg("--crash-child")
            .arg(plan)
            .output()?)
    })?;
    println!(
        "{}",
        serde_json::json!({"recorded":Path::new(&args[0]).join("run.json"),
        "starts":report["final_status"]["starts_registered"],"spent_units":report["final_status"]["spent_units"],
        "actual_probability_law_authenticated":false,"global_failure_probability":null})
    );
    Ok(())
}
