use super::*;

#[test]
fn normalized_agent_protocol_accepts_websocket_aliases() {
    assert_eq!(
        normalized_agent_protocol(Some("MCP over WebSocket v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP over WS v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP over WebSockets v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI MCP WebSocket v3")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI MCP WebSockets v3")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic MCP over WebSocket v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic MCP over WebSockets v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over WebSocket v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over WS v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over WebSockets v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent WebSocket v4")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent WebSockets v4")).as_deref(),
        Some("a2a")
    );
}
