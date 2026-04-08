use super::*;
#[test]
fn normalized_agent_protocol_accepts_punctuation_variants_for_aliases() {
    assert_eq!(
        normalized_agent_protocol(Some("Model.Context.Protocol")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol 2.0")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol JSON-RPC v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent:To:Agent")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent-To-Agent Protocol v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A 2.0")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent-to-Agent JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent-2-Agent Protocol JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol STDIO v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP over JSON-RPC v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP over STDIO v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP over SSE v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP Streamable HTTP v1")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP HTTP v1")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol over HTTP v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol over Streamable HTTP v2"))
            .as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol SSE v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent-to-Agent Protocol STDIO v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over SSE v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over STDIO v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A Streamable HTTP v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A HTTP v1")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent-to-Agent Streamable HTTP v1")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent HTTP v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent over HTTP v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI MCP")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI Model Context Protocol v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI MCP over HTTP v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI MCP over Streamable HTTP v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic MCP Protocol")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic Model Context Protocol v1")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic MCP over Streamable HTTP v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic Model Context Protocol over HTTP v2")).as_deref(),
        Some("mcp")
    );
}
