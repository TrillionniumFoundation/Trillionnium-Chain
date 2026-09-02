#![forbid(unsafe_code)]
#![cfg(not(feature = "ai-v1-candidate"))]

use std::process::Command;

const NODE: &str = env!("CARGO_BIN_EXE_trnm-poco-node");

#[test]
fn default_binary_refuses_ai_v1_candidate_commands() {
    for command in [
        "prepare-g2-manifest-bound-candidate-v2",
        "run-g2-manifest-bound-candidate-v2",
    ] {
        let output = Command::new(NODE)
            .arg(command)
            .output()
            .expect("run default trnm-poco-node binary");
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).expect("node stderr is UTF-8");
        assert!(stderr.contains("ai_v1_candidate_feature=false"));
        assert!(stderr.contains("--features ai-v1-candidate"));
        assert!(!stderr.contains("PREPARED candidate_only=true"));
    }
}
