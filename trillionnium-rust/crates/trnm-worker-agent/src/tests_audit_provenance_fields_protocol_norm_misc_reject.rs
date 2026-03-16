use super::*;

#[test]
fn normalized_agent_protocol_rejects_oversized_alias_input() {
    let oversized = format!("MCP over HTTP v2 {}", "x".repeat(200));
    assert_eq!(normalized_agent_protocol(Some(&oversized)), None);
}
