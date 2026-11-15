//! Record actual native owner observations; never a network risk simulator.
#[path = "support/native_owner_scenario.rs"]
mod scenario;

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let output = PathBuf::from(arguments.next().ok_or("provide NEW_OUTPUT_JSON")?);
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let parent = output.parent().ok_or("output needs parent directory")?;
    std::fs::create_dir_all(parent)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)?;
    let run = scenario::run()?;
    let artifacts = run.report["packet_artifacts"]
        .as_array()
        .ok_or("artifact manifest")?;
    std::fs::create_dir(parent.join("packets"))?;
    for (row, artifact) in artifacts.iter().zip(&run.artifacts) {
        let path = parent.join(row["path"].as_str().ok_or("artifact path")?);
        let mut packet = OpenOptions::new().write(true).create_new(true).open(path)?;
        packet.write_all(&artifact.bytes)?;
    }
    serde_json::to_writer_pretty(&mut file, &run.report)?;
    file.write_all(b"\n")?;
    println!(
        "{}",
        serde_json::json!({"recorded":output,"native_execution_exercised":true,
        "snapshots":run.report["snapshots"].as_array().map(Vec::len),
        "native_runtime_attested":false,"six_successor_risk_qualified":false})
    );
    Ok(())
}
