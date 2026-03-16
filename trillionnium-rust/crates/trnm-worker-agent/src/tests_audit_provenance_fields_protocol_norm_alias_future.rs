use super::*;
#[test]
fn normalized_agent_protocol_accepts_future_version_suffixes() {
    assert_eq!(
        normalized_agent_protocol(Some("MCP over HTTP v9")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A Streamable HTTP v12")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent Protocol v27")).as_deref(),
        Some("a2a")
    );
}
