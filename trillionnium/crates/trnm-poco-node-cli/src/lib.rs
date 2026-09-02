#![forbid(unsafe_code)]
//! Non-authoritative CLI boundary for the production-shaped PoCO node.

use std::ffi::OsString;

use trnm_poco_node_host::{NodeHostStatusV0, PocoNodeHostV0};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeCliCommandV0 {
    Status,
    Start,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCliOutcomeV0 {
    exit_code: u8,
    stdout: String,
    stderr: String,
}

impl NodeCliOutcomeV0 {
    pub fn exit_code(&self) -> u8 {
        self.exit_code
    }

    pub fn stdout(&self) -> &str {
        &self.stdout
    }

    pub fn stderr(&self) -> &str {
        &self.stderr
    }
}

fn render_status_v0(status: NodeHostStatusV0) -> String {
    format!(
        "{{\"schema\":\"trnm-poco-node-status-v0\",\"production_candidate\":{},\"host_complete\":{},\"unwired_contract_count\":{},\"authority_gate_open\":{},\"required_io_surface_count\":{},\"enabled_io_surface_count\":{},\"production_activation\":{},\"start_permitted\":{}}}\n",
        status.authority().production_candidate(),
        status.authority().host_implementation_complete(),
        status.authority().unwired_contract_count(),
        status.authority_gate_open(),
        status.required_io_surface_count(),
        status.enabled_io_surface_count(),
        status.production_activation(),
        status.start_permitted(),
    )
}

pub fn parse_command_v0(arguments: &[OsString]) -> Result<NodeCliCommandV0, &'static str> {
    match arguments {
        [command] if command.to_str() == Some("status") => Ok(NodeCliCommandV0::Status),
        [command] if command.to_str() == Some("start") => Ok(NodeCliCommandV0::Start),
        [] => Err("missing command; allowed commands: status, start"),
        _ => Err("unknown command; allowed commands: status, start"),
    }
}

pub fn run_v0(arguments: &[OsString]) -> NodeCliOutcomeV0 {
    let host = PocoNodeHostV0::inert();
    match parse_command_v0(arguments) {
        Ok(NodeCliCommandV0::Status) => NodeCliOutcomeV0 {
            exit_code: 0,
            stdout: render_status_v0(host.status()),
            stderr: String::new(),
        },
        Ok(NodeCliCommandV0::Start) => {
            let blocked = host
                .start()
                .expect_err("the production-shaped host must remain fail-closed");
            NodeCliOutcomeV0 {
                exit_code: 1,
                stdout: String::new(),
                stderr: format!("{blocked}\n"),
            }
        }
        Err(cause) => NodeCliOutcomeV0 {
            exit_code: 2,
            stdout: String::new(),
            stderr: format!("node CLI refused: {cause}\n"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(|value| OsString::from(*value)).collect()
    }

    #[test]
    fn status_is_sanitized_and_non_authoritative() {
        let outcome = run_v0(&args(&["status"]));
        assert_eq!(outcome.exit_code(), 0);
        assert!(outcome.stdout().contains("\"production_candidate\":false"));
        assert!(outcome.stdout().contains("\"authority_gate_open\":false"));
        assert!(outcome.stdout().contains("\"production_activation\":false"));
        assert!(outcome.stdout().contains("\"start_permitted\":false"));
        assert!(outcome.stderr().is_empty());
    }

    #[test]
    fn start_and_unknown_commands_fail_closed() {
        let start = run_v0(&args(&["start"]));
        assert_eq!(start.exit_code(), 1);
        assert!(start.stderr().contains("node host start blocked"));

        let unknown = run_v0(&args(&["serve"]));
        assert_eq!(unknown.exit_code(), 2);
        assert!(unknown.stderr().contains("node CLI refused"));
    }
}
